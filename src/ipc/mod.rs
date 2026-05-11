//! IPC module for Named Pipe communication
//!
//! Architecture (Reverse Connection):
//! - Proxy (Medium IL) creates Named Pipe Server
//! - Worker (High IL) connects as Client
//! - This avoids MIC No-Write-Up issues

pub mod client;
pub mod server;

pub use client::PipeClient;
pub use server::PipeServer;
