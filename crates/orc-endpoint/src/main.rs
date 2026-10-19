use clap::Parser;
use std::{path::PathBuf, sync::Arc};
#[derive(Parser)]
#[command(
    version,
    about = "ORC endpoint: local authorization and supervised execution"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
}
#[tokio::main]
async fn main() -> Result<(), orc_transport::AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = orc_protocol::strict_decode(&std::fs::read(Args::parse().config)?)?;
    let endpoint = Arc::new(orc_endpoint::Endpoint::open(config).await?);
    tokio::select! {
        r=endpoint.clone().connect()=>r?,
        r=endpoint.clone().supervise()=>r?,
        r=orc_admin::serve(&endpoint.config.admin_socket,orc_admin::current_uid(),endpoint.clone())=>r?,
        _=shutdown_signal()=>endpoint.shutdown().await?,
    }
    Ok(())
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM registration");
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
}
