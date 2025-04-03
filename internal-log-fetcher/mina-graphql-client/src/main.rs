use structopt::StructOpt;
use mina_graphql_client::{MinaClientConfig, MinaGraphQLClient};
use anyhow::Result;
use url::Url;

#[derive(Debug, StructOpt)]
#[structopt(name = "mina-graphql-client", about = "Debug utility for mina internal qraphql interface.")]
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



#[derive(Debug,StructOpt)]
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
    ScheduleZkappPayments,
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
            let (last_log_id,logs) = client.fetch_more_logs().await?;
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
        Command::ScheduleZkappPayments => {
            client.authorize().await?;
            println!("authorized");
            client.schedule_zkapp_payments().await?;
        }
    };

    Ok(())
}

