#![recursion_limit = "512"]
//! memoric - A red team memory weapon MCP Server for Windows
//!
//! Supports three modes:
//! - STDIO mode (default): Direct MCP over stdin/stdout, no elevation
//! - Proxy mode (--proxy): Normal privileges, handles STDIO with Claude Desktop + UAC elevation
//! - Worker mode (--worker): Elevated privileges, executes privileged operations via Named Pipe

// MCP tools are dispatched dynamically via string matching in call_tool()
// so the compiler can't trace usage of pub functions across module boundaries
#![allow(dead_code, unused_variables)]

mod bruteforce;
mod byovd;
mod bypass_db;
mod crypto;
mod driver;
mod elevation;
mod error;
mod evasion;
mod info;
mod inject;
mod ipc;
mod kernel;
mod mcp;
mod memory;
mod opsec_cleanup;
mod orchestration;
mod privilege;
mod proxy;
mod redteam;
mod safe_handle;
mod state;
mod stdio_server;
mod util;
mod worker;

use anyhow::Result;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() -> Result<()> {
    // Initialize logging - output to stderr only (MCP compliant)
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .init();

    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let is_worker = args.iter().any(|a| a == "--worker");
    let is_proxy = args.iter().any(|a| a == "--proxy");

    if is_worker {
        // Worker mode: elevated privileges, connects to Proxy via Named Pipe
        worker::run_worker()?;
    } else if is_proxy {
        // Proxy mode: normal privileges, STDIO + UAC elevation + Named Pipe
        proxy::run_proxy()?;
    } else {
        // STDIO mode (default): direct MCP server over stdin/stdout
        stdio_server::run_stdio()?;
    }

    Ok(())
}
