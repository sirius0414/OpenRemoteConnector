//! MCP 进程入口：分别启动 Agent HTTP、设备 mTLS 和所有者管理 socket。
//!
//! HTTP 监听仅用于回环/反向代理入口，设备 TLS 在服务内终止；本进程不执行用户命令。

use clap::Parser;
use std::{path::PathBuf, sync::Arc};
#[derive(Parser)]
#[command(
    version,
    about = "Independent ORC MCP service; never executes host commands"
)]
struct Args {
    #[arg(
        long,
        required_unless_present = "print_tool_schemas",
        conflicts_with = "print_tool_schemas"
    )]
    config: Option<PathBuf>,
    /// Print the actual MCP tool definitions and JSON schemas without opening state.
    #[arg(long)]
    print_tool_schemas: bool,
}
#[tokio::main]
async fn main() -> Result<(), orc_transport::AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    if args.print_tool_schemas {
        println!(
            "{}",
            serde_json::to_string_pretty(&orc_mcp::tool_definitions())?
        );
        return Ok(());
    }
    let config =
        orc_protocol::strict_decode(&std::fs::read(args.config.ok_or("config required")?)?)?;
    let state = Arc::new(orc_mcp::Mcp::open(config).await?);
    let http = tokio::net::TcpListener::bind(state.config.http_bind).await?;
    tokio::select! {
        r=axum::serve(http,orc_mcp::router(state.clone()))=>r?,
        r=state.clone().serve_devices()=>r?,
        r=orc_admin::serve(&state.config.admin_socket,orc_admin::current_uid(),state.clone())=>r?,
        _=tokio::signal::ctrl_c()=>{},
    }
    Ok(())
}
