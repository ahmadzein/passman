use anyhow::Result;
use passman_mcp::PassmanServer;
use passman_vault::{watcher, Vault};
use rmcp::{transport::stdio, ServiceExt};
use tracing_subscriber::{self, EnvFilter};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    // Handle --version / --help
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("passman-mcp-server {VERSION}");
        return Ok(());
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("passman-mcp-server {VERSION}");
        println!("Secure credential proxy MCP server\n");
        println!("USAGE: passman-mcp-server [OPTIONS]\n");
        println!("OPTIONS:");
        println!("  -h, --help       Print help");
        println!("  -V, --version    Print version");
        println!("\nCommunicates via JSON-RPC over stdio (MCP transport).");
        println!("Configure in your MCP client as:");
        println!("  {{ \"command\": \"passman-mcp-server\", \"args\": [] }}");
        return Ok(());
    }

    // All logging goes to stderr (stdout is the MCP JSON-RPC transport)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Passman MCP server v{VERSION} starting");

    let vault = Vault::with_defaults();

    // Start file watcher for cross-process vault sync
    let vault_path = vault.vault_path().await;
    let _watch_handle = watcher::watch_vault(vault.clone(), vault_path);

    let server = PassmanServer::new(vault);

    let service = server
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("Failed to start MCP service: {:?}", e);
        })?;

    tracing::info!("Passman MCP server running on stdio");

    service.waiting().await?;

    tracing::info!("Passman MCP server shutting down");
    Ok(())
}
