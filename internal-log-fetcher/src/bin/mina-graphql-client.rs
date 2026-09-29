// SPDX-License-Identifier: Apache-2.0

//! Debug utility for a daemon's ITN GraphQL server, built on `mina-sdk`.
//!
//! The ITN commands sign their requests with the ed25519 key `KEY`; the
//! daemon must list its public key in `--itn-keys`. `get-peers` and
//! `connection-gating-config` are not ITN operations: they send an unsigned
//! request, so `ADDRESS` must then be the daemon's public GraphQL port.

use anyhow::{anyhow, Result};
use mina_sdk::itn::{
    GatingUpdate, ItnClient, ItnKey, NetworkPeer, PaymentsDetails, ZkappCommandsDetails,
};
use mina_sdk::{Currency, MinaClient};
use serde::Serialize;
use serde_json::Value;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "mina-graphql-client",
    about = "Debug utility for the mina internal (ITN) graphql interface."
)]
struct Cli {
    #[structopt(name = "secret-key", env = "KEY")]
    /// The secret key used to sign the request, as a base64 ed25519 seed.
    secret_key: String,

    #[structopt(name = "address", env = "ADDRESS")]
    /// Address of the graphql server: `http(s)://host:port`; `/graphql` is added.
    address: String,

    #[structopt(long, short = "j")]
    /// Output results in JSON format for programmatic use
    json: bool,

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
    /// In nanomina, as are all fees and balances below.
    #[structopt(long, default_value = "1000000000")]
    deployment_fee: u64,
    #[structopt(long, default_value = "2000000000")]
    max_fee: u64,
    #[structopt(long, default_value = "1000000000")]
    min_fee: u64,
    #[structopt(long, default_value = "6000360000")]
    init_balance: u64,
    #[structopt(long, default_value = "3000180000")]
    max_new_zkapp_balance: u64,
    #[structopt(long, default_value = "1000060000")]
    min_new_zkapp_balance: u64,
    #[structopt(long, default_value = "1000")]
    max_balance_change: u64,
    #[structopt(long, default_value = "0")]
    min_balance_change: u64,
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
    /// Base58 private keys of the fee payers.
    #[structopt(long)]
    fee_payers: Vec<String>,
}

impl From<InputZkappCommandsDetails> for ZkappCommandsDetails {
    fn from(val: InputZkappCommandsDetails) -> Self {
        ZkappCommandsDetails {
            max_account_updates: Some(val.max_account_updates),
            max_cost: val.max_cost,
            account_queue_size: val.account_queue_size,
            deployment_fee: Currency::from_nanomina(val.deployment_fee),
            max_fee: Currency::from_nanomina(val.max_fee),
            min_fee: Currency::from_nanomina(val.min_fee),
            init_balance: Currency::from_nanomina(val.init_balance),
            max_new_zkapp_balance: Currency::from_nanomina(val.max_new_zkapp_balance),
            min_new_zkapp_balance: Currency::from_nanomina(val.min_new_zkapp_balance),
            max_balance_change: Currency::from_nanomina(val.max_balance_change),
            min_balance_change: Currency::from_nanomina(val.min_balance_change),
            no_precondition: val.no_precondition,
            memo_prefix: val.memo_prefix,
            duration_min: val.duration_min,
            tps: val.tps,
            num_new_accounts: val.num_new_accounts,
            num_zkapps_to_deploy: val.num_zkapps_to_deploy,
            fee_payers: val.fee_payers,
            non_default_token: None,
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
    /// In nanomina, as are `fee-min` and `amount`.
    #[structopt(long, default_value = "2000000000")]
    fee_max: u64,
    #[structopt(long, default_value = "1000000000")]
    fee_min: u64,
    #[structopt(long, default_value = "1000000000")]
    amount: u64,
    #[structopt(long)]
    receiver: String,
    /// Base58 private keys of the senders.
    #[structopt(long)]
    senders: Vec<String>,
}

impl From<InputPaymentsDetails> for PaymentsDetails {
    fn from(val: InputPaymentsDetails) -> Self {
        PaymentsDetails {
            duration_min: val.duration_min,
            tps: val.tps,
            memo_prefix: val.memo,
            max_fee: Currency::from_nanomina(val.fee_max),
            min_fee: Currency::from_nanomina(val.fee_min),
            amount: Currency::from_nanomina(val.amount),
            receiver: val.receiver,
            senders: val.senders,
        }
    }
}

#[derive(Debug, StructOpt)]
struct InputGatingUpdate {
    #[structopt(long)]
    clean_added_peers: bool,
    #[structopt(long)]
    isolate: bool,
    /// `host,libp2p_port,peer_id`; can be repeated, as can the lists below.
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
        return Err(anyhow!(
            "Invalid network peer format. Expected: host,libp2p_port,peer_id"
        ));
    }
    Ok(NetworkPeer {
        host: parts[0].to_string(),
        libp2p_port: parts[1].parse()?,
        peer_id: parts[2].to_string(),
    })
}

impl TryFrom<InputGatingUpdate> for GatingUpdate {
    type Error = anyhow::Error;

    fn try_from(value: InputGatingUpdate) -> Result<Self, Self::Error> {
        let peers = |list: &[String]| -> Result<Vec<NetworkPeer>> {
            list.iter().map(|s| parse_network_peer(s)).collect()
        };
        Ok(GatingUpdate {
            clean_added_peers: value.clean_added_peers,
            isolate: value.isolate,
            added_peers: peers(&value.added_peers)?,
            banned_peers: peers(&value.banned_peers)?,
            trusted_peers: peers(&value.trusted_peers)?,
        })
    }
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Authenticate with the server only.
    Auth,
    /// Fetch logs from the server.
    FetchMoreLogs,
    /// Flush logs from the server: those up to `end-log-id`, or all the
    /// logs present now if it is not given.
    FlushLogs {
        #[structopt(long)]
        end_log_id: Option<i64>,
    },
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
    /// Get connection gating configuration (trusted peers, banned peers,
    /// isolate mode). Public GraphQL: ADDRESS must be the public port.
    ConnectionGatingConfig,
    /// Get list of currently connected peers. Public GraphQL: ADDRESS must
    /// be the public port.
    GetPeers,
}

/// Output structures for JSON serialization
#[derive(Debug, Serialize)]
struct PeerOutput {
    peer_id: String,
    host: String,
    libp2p_port: i64,
}

#[derive(Debug, Serialize)]
struct ConnectionGatingOutput {
    isolate: bool,
    trusted_peers: Vec<PeerOutput>,
    banned_peers: Vec<PeerOutput>,
}

#[derive(Debug, Serialize)]
struct FetchLogsOutput {
    new_logs_available: bool,
    logs_count: usize,
    logs: String,
}

#[derive(Debug, Serialize)]
struct GenericOutput {
    result: String,
}

#[derive(Debug, Serialize)]
struct SlotsWonOutput {
    slots: Vec<u64>,
}

/// Print `data` as JSON with `--json`, or `human` otherwise.
fn output<T: Serialize>(json: bool, data: &T, human: impl FnOnce()) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(data)?);
    } else {
        human();
    }
    Ok(())
}

const CONNECTION_GATING_CONFIG: &str = r#"query {
  connectionGatingConfig {
    isolate
    trustedPeers { peerId host libp2pPort }
    bannedPeers { peerId host libp2pPort }
  }
}"#;

fn peers_of(v: &Value) -> Vec<PeerOutput> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|p| PeerOutput {
                    peer_id: p["peerId"].as_str().unwrap_or_default().to_string(),
                    host: p["host"].as_str().unwrap_or_default().to_string(),
                    libp2p_port: p["libp2pPort"].as_i64().unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let opt = Cli::from_args();
    let uri = format!("{}/graphql", opt.address.trim_end_matches('/'));
    let itn =
        || -> Result<ItnClient> { Ok(ItnClient::new(&uri, ItnKey::from_base64(&opt.secret_key)?)) };
    let json = opt.json;

    match opt.cmd {
        Command::Auth => {
            let auth = itn()?.auth().await?;
            println!(
                "authorized: server {}, sequence number {}",
                auth.server_uuid, auth.signer_sequence_number
            );
        }
        Command::FetchMoreLogs => {
            let logs = itn()?.internal_logs(0).await?;
            output(
                json,
                &FetchLogsOutput {
                    new_logs_available: !logs.is_empty(),
                    logs_count: logs.len(),
                    logs: format!("{:#?}", logs),
                },
                || {
                    println!("new logs available: {}", !logs.is_empty());
                    println!("logs: {:#?}", logs);
                },
            )?;
        }
        Command::FlushLogs { end_log_id } => {
            let client = itn()?;
            let end = match end_log_id {
                Some(id) => Some(id),
                None => client.internal_logs(0).await?.last().map(|l| l.id),
            };
            let result = match end {
                Some(end) => client.flush_internal_logs(end).await?,
                None => "0".to_string(),
            };
            output(
                json,
                &GenericOutput {
                    result: result.clone(),
                },
                || println!("Flushed logs: {result}"),
            )?;
        }
        Command::ResetZkappSoftLimit => {
            itn()?.set_zkapp_command_limit(None).await?;
            println!("reset zkapp soft limit");
        }
        Command::ScheduleZkappPayments(cmd) => {
            let handle = itn()?.schedule_zkapp_commands(&cmd.into()).await?;
            output(
                json,
                &GenericOutput {
                    result: handle.clone(),
                },
                || println!("Scheduled zkapp commands with handle: {handle}"),
            )?;
        }
        Command::SchedulePayments(cmd) => {
            let handle = itn()?.schedule_payments(&cmd.into()).await?;
            output(
                json,
                &GenericOutput {
                    result: handle.clone(),
                },
                || println!("Scheduled payments with handle: {handle}"),
            )?;
        }
        Command::StopPayments { handle } => {
            let result = itn()?.stop_scheduled_transactions(&handle).await?;
            output(
                json,
                &GenericOutput {
                    result: result.clone(),
                },
                || println!("Stop payments result: {result}"),
            )?;
        }
        Command::UpdateGating(cmd) => {
            let result = itn()?.update_gating(&cmd.try_into()?).await?;
            output(
                json,
                &GenericOutput {
                    result: result.clone(),
                },
                || println!("Update gating result: {result}"),
            )?;
        }
        Command::SlotsWon => {
            let slots = itn()?.slots_won().await?;
            output(
                json,
                &SlotsWonOutput {
                    slots: slots.clone(),
                },
                || println!("Slots won: {:?}", slots),
            )?;
        }
        Command::StopDaemon {
            delay_seconds,
            clean_config,
        } => {
            let clean_config = if clean_config { Some(true) } else { None };
            let result = itn()?.stop_daemon(delay_seconds, clean_config).await?;
            output(
                json,
                &GenericOutput {
                    result: result.clone(),
                },
                || println!("Stop daemon result: {result}"),
            )?;
        }
        Command::ConnectionGatingConfig => {
            let data = MinaClient::new(&uri)
                .execute_query(CONNECTION_GATING_CONFIG, None, "connection_gating_config")
                .await?;
            let c = &data["connectionGatingConfig"];
            let config = ConnectionGatingOutput {
                isolate: c["isolate"].as_bool().unwrap_or_default(),
                trusted_peers: peers_of(&c["trustedPeers"]),
                banned_peers: peers_of(&c["bannedPeers"]),
            };
            output(json, &config, || {
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
            })?;
        }
        Command::GetPeers => {
            let peers: Vec<PeerOutput> = MinaClient::new(&uri)
                .get_peers()
                .await?
                .into_iter()
                .map(|p| PeerOutput {
                    peer_id: p.peer_id,
                    host: p.host,
                    libp2p_port: p.port,
                })
                .collect();
            output(json, &peers, || {
                println!("\nConnected Peers ({}):", peers.len());
                println!("===================");
                for peer in &peers {
                    println!("Peer ID:      {}", peer.peer_id);
                    println!("Host:         {}", peer.host);
                    println!("Libp2p Port:  {}", peer.libp2p_port);
                    println!("---");
                }
            })?;
        }
    };

    Ok(())
}
