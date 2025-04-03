use anyhow::Result;
use mina_graphql_client::{MinaClientConfig, MinaGraphQLClient, ZkappCommandsDetails};
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

impl Into<ZkappCommandsDetails> for InputZkappCommandsDetails {
    fn into(self) -> ZkappCommandsDetails {
        ZkappCommandsDetails {
            max_account_updates: self.max_account_updates,
            max_cost: self.max_cost,
            account_queue_size: self.account_queue_size,
            deployment_fee: self.deployment_fee,
            max_fee: self.max_fee,
            min_fee: self.min_fee,
            init_balance: self.init_balance,
            max_new_zkapp_balance: self.max_new_zkapp_balance,
            min_new_zkapp_balance: self.min_new_zkapp_balance,
            max_balance_change: self.max_balance_change,
            min_balance_change: self.min_balance_change,
            no_precondition: self.no_precondition,
            memo_prefix: self.memo_prefix,
            duration_min: self.duration_min,
            tps: self.tps,
            num_new_accounts: self.num_new_accounts,
            num_zkapps_to_deploy: self.num_zkapps_to_deploy,
            fee_payers: self.fee_payers,
        }
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Cli::from_args();

    let error_msg = "Invalid address format, expected http(s)://host:port";
    let url = Url::parse(&opt.address).expect("error_msg");

    let config = MinaClientConfig {
        address: url.host_str().expect(error_msg).to_string(),
        graphql_port: url.port_or_known_default().expect("port"),
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
    };

    Ok(())
}
