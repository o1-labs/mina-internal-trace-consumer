use anyhow::Result;
use mina_graphql_client::{
    GatingUpdate, MinaClientConfig, MinaGraphQLClient, NetworkPeer, PaymentsDetails,
    ZkappCommandsDetails,
};
use structopt::StructOpt;
use url::Url;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "mina-graphql-client",
    about = "Debug utility for mina internal qraphql interface."
)]
struct Cli {
    #[structopt(name = "secret-key", env = "KEY")]
    /// The secret key used to sign the request in base64 format.
    secret_key: String,

    #[structopt(name = "address", env = "ADDRESS")]
    /// Address in format `host:port` of the graphql server.
    address: String,

    #[structopt(subcommand, about = "The command to run.")]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
struct InputZkappCommandsDetails {
    #[structopt(long, default_value = "2")]
    max_account_updates: i64,

    #[structopt(long)]
    max_cost: bool,

    #[structopt(long, default_value = "0")]
    account_queue_size: i64,

    #[structopt(long, default_value = "1000000000")]
    deployment_fee: i64,

    #[structopt(long, default_value = "2000000000")]
    max_fee: i64,

    #[structopt(long, default_value = "1000000000")]
    min_fee: i64,
    #[structopt(long, default_value = "6000360000")]
    init_balance: i64,
    #[structopt(long, default_value = "3000180000")]
    max_new_zkapp_balance: i64,
    #[structopt(long, default_value = "1000060000")]
    min_new_zkapp_balance: i64,
    #[structopt(long, default_value = "1000")]
    max_balance_change: i64,
    #[structopt(long, default_value = "0")]
    min_balance_change: i64,
    #[structopt(long)]
    no_precondition: bool,
    #[structopt(long, default_value = "test")]
    memo_prefix: String,
    #[structopt(long, default_value = "30")]
    duration_min: i64,
    #[structopt(long, default_value = "0.25")]
    tps: f64,
    #[structopt(long, default_value = "0")]
    num_new_accounts: i64,
    #[structopt(long, default_value = "8")]
    num_zkapps_to_deploy: i64,
    #[structopt(long, default_value = "Vec::new()")]
    fee_payers: Vec<String>,
}

impl From<InputZkappCommandsDetails> for ZkappCommandsDetails {
    fn from(val: InputZkappCommandsDetails) -> Self {
        ZkappCommandsDetails {
            max_account_updates: val.max_account_updates,
            max_cost: val.max_cost,
            account_queue_size: val.account_queue_size,
            deployment_fee: val.deployment_fee,
            max_fee: val.max_fee,
            min_fee: val.min_fee,
            init_balance: val.init_balance,
            max_new_zkapp_balance: val.max_new_zkapp_balance,
            min_new_zkapp_balance: val.min_new_zkapp_balance,
            max_balance_change: val.max_balance_change,
            min_balance_change: val.min_balance_change,
            no_precondition: val.no_precondition,
            memo_prefix: val.memo_prefix,
            duration_min: val.duration_min,
            tps: val.tps,
            num_new_accounts: val.num_new_accounts,
            num_zkapps_to_deploy: val.num_zkapps_to_deploy,
            fee_payers: val.fee_payers,
        }
    }
}

#[derive(Debug, StructOpt)]
struct InputPaymentsDetails {
    #[structopt(long, default_value = "30")]
    duration_min: i64,

    #[structopt(long, default_value = "0.25")]
    tps: f64,

    #[structopt(long, default_value = "test")]
    memo: String,

    #[structopt(long, default_value = "2000000000")]
    fee_max: String,

    #[structopt(long, default_value = "1000000000")]
    fee_min: String,

    #[structopt(long, default_value = "1000000000")]
    amount: String,

    #[structopt(long)]
    receiver: String,

    #[structopt(long, default_value = "Vec::new()")]
    senders: Vec<String>,
}

impl From<InputPaymentsDetails> for PaymentsDetails {
    fn from(val: InputPaymentsDetails) -> Self {
        PaymentsDetails {
            duration_in_minutes: val.duration_min,
            transactions_per_second: val.tps,
            memo: val.memo,
            fee_max: val.fee_max,
            fee_min: val.fee_min,
            amount: val.amount,
            receiver: val.receiver,
            senders: val.senders,
        }
    }
}

#[derive(Debug, StructOpt)]
struct InputNetworkPeer {
    #[structopt(long)]
    host: String,

    #[structopt(long)]
    libp2p_port: i64,

    #[structopt(long)]
    peer_id: String,
}

impl From<InputNetworkPeer> for NetworkPeer {
    fn from(val: InputNetworkPeer) -> Self {
        NetworkPeer {
            host: val.host,
            libp2p_port: val.libp2p_port,
            peer_id: val.peer_id,
        }
    }
}

#[derive(Debug, StructOpt)]
struct InputGatingUpdate {
    #[structopt(long)]
    clean_added_peers: bool,

    #[structopt(long)]
    isolate: bool,

    #[structopt(long)]
    added_peers: Vec<String>,

    #[structopt(long)]
    banned_peers: Vec<String>,

    #[structopt(long)]
    trusted_peers: Vec<String>,
}

fn parse_network_peer(s: &str) -> Result<NetworkPeer> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!(
            "Invalid network peer format. Expected: host,libp2p_port,peer_id"
        ));
    }
    Ok(NetworkPeer {
        host: parts[0].to_string(),
        libp2p_port: parts[1].parse()?,
        peer_id: parts[2].to_string(),
    })
}

impl InputGatingUpdate {
    fn into_gating_update(self) -> Result<GatingUpdate> {
        let added_peers: Result<Vec<NetworkPeer>> = self
            .added_peers
            .iter()
            .map(|s| parse_network_peer(s))
            .collect();
        let banned_peers: Result<Vec<NetworkPeer>> = self
            .banned_peers
            .iter()
            .map(|s| parse_network_peer(s))
            .collect();
        let trusted_peers: Result<Vec<NetworkPeer>> = self
            .trusted_peers
            .iter()
            .map(|s| parse_network_peer(s))
            .collect();

        Ok(GatingUpdate {
            clean_added_peers: self.clean_added_peers,
            isolate: self.isolate,
            added_peers: added_peers?,
            banned_peers: banned_peers?,
            trusted_peers: trusted_peers?,
        })
    }
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Authenticate with the server only.
    Auth,
    /// Fetch logs from the server.
    FetchMoreLogs,
    /// Flush logs from the server.
    FlushLogs,
    /// Reset zkapp soft limit.
    ResetZkappSoftLimit,
    /// Schedule zkapp payments.
    ScheduleZkappPayments(InputZkappCommandsDetails),
    /// Schedule regular payments.
    SchedulePayments(InputPaymentsDetails),
    /// Stop scheduled transactions.
    StopPayments {
        #[structopt(long)]
        handle: String,
    },
    /// Update gating configuration.
    UpdateGating(InputGatingUpdate),
    /// Get slots won by block producer.
    SlotsWon,
    /// Stop the Mina daemon.
    StopDaemon {
        #[structopt(long)]
        delay_seconds: Option<i64>,
        #[structopt(long)]
        clean_config: bool,
    },
    /// Get connection gating configuration (trusted peers, banned peers, isolate mode).
    ConnectionGatingConfig,
    /// Get list of currently connected peers.
    GetPeers,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let opt = Cli::from_args();

    let error_msg = "Invalid address format, expected http(s)://host:port";
    let url = Url::parse(&opt.address).expect(error_msg);

    let config = MinaClientConfig {
        address: url.host_str().expect(error_msg).to_string(),
        graphql_port: url
            .port_or_known_default()
            .expect("Missing or invalid port in the address"),
        use_https: url.scheme() == "https",
        secret_key_base64: opt.secret_key,
    };

    let mut client = MinaGraphQLClient::from(config);

    match opt.cmd {
        Command::Auth => {
            client.authorize().await?;
            println!("authorized");
        }
        Command::FetchMoreLogs => {
            client.authorize().await?;
            println!("authorized");
            let (last_log_id, logs) = client.fetch_more_logs().await?;
            println!("last log id: {}", last_log_id);
            println!("logs: {:#?}", logs);
        }
        Command::FlushLogs => {
            client.authorize().await?;
            println!("authorized");
            client.flush_logs().await?;
            println!("flushed logs");
        }
        Command::ResetZkappSoftLimit => {
            client.authorize().await?;
            println!("authorized");
            client.reset_zkapp_soft_limit_query().await?;
        }
        Command::ScheduleZkappPayments(cmd) => {
            client.authorize().await?;
            println!("authorized");
            client.schedule_zkapp_payments(cmd.into()).await?;
        }
        Command::SchedulePayments(cmd) => {
            client.authorize().await?;
            println!("authorized");
            let handle = client.schedule_payments(cmd.into()).await?;
            println!("Scheduled payments with handle: {}", handle);
        }
        Command::StopPayments { handle } => {
            client.authorize().await?;
            println!("authorized");
            let result = client.stop_payments(handle).await?;
            println!("Stop payments result: {}", result);
        }
        Command::UpdateGating(cmd) => {
            client.authorize().await?;
            println!("authorized");
            let gating_update = cmd.into_gating_update()?;
            let result = client.update_gating(gating_update).await?;
            println!("Update gating result: {}", result);
        }
        Command::SlotsWon => {
            client.authorize().await?;
            println!("authorized");
            let slots = client.slots_won().await?;
            println!("Slots won: {:?}", slots);
        }
        Command::StopDaemon {
            delay_seconds,
            clean_config,
        } => {
            client.authorize().await?;
            println!("authorized");
            let clean_config_opt = if clean_config { Some(true) } else { None };
            let result = client.stop_daemon(delay_seconds, clean_config_opt).await?;
            println!("Stop daemon result: {}", result);
        }
        Command::ConnectionGatingConfig => {
            let config = client.connection_gating_config().await?;
            println!("\nConnection Gating Configuration:");
            println!("================================");
            println!("Isolate mode: {}", config.isolate);
            println!("\nTrusted Peers ({}):", config.trusted_peers.len());
            for peer in &config.trusted_peers {
                println!("  - {} ({}:{})", peer.peer_id, peer.host, peer.libp2p_port);
            }
            println!("\nBanned Peers ({}):", config.banned_peers.len());
            for peer in &config.banned_peers {
                println!("  - {} ({}:{})", peer.peer_id, peer.host, peer.libp2p_port);
            }
        }
        Command::GetPeers => {
            let peers = client.get_peers().await?;
            println!("\nConnected Peers ({}):", peers.len());
            println!("===================");
            for peer in &peers {
                println!("Peer ID:      {}", peer.peer_id);
                println!("Host:         {}", peer.host);
                println!("Libp2p Port:  {}", peer.libp2p_port);
                println!("---");
            }
        }
    };

    Ok(())
}
