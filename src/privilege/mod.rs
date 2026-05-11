//! Privilege escalation module

pub mod abuse;
pub mod auto;
pub mod debug;
pub mod potato;
pub mod service;
pub mod symlink;
pub mod system;
pub mod token;
pub mod uac;

pub use debug::*;
