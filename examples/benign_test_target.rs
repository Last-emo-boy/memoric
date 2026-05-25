//! Opt-in benign target process for deterministic memory scanning tests.
//!
//! Run with:
//!
//! cargo run --example benign_test_target -- --seconds 120

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static MARKER_BYTES: &[u8] = b"MEMORIC_BENIGN_TEST_TARGET_V1";
static MUTABLE_COUNTER: AtomicU64 = AtomicU64::new(0x4D45_4D4F_5249_4301);

fn main() {
    let config = Config::from_args(std::env::args().skip(1).collect());
    let mut owned_marker = config.marker.unwrap_or_else(|| MARKER_BYTES.to_vec());
    owned_marker.shrink_to_fit();

    let marker_ptr = owned_marker.as_ptr() as usize;
    let counter_ptr = &MUTABLE_COUNTER as *const AtomicU64 as usize;
    println!("memoric benign test target");
    println!("pid={}", std::process::id());
    println!("marker_ascii={}", String::from_utf8_lossy(&owned_marker));
    println!("marker_address=0x{:016X}", marker_ptr);
    println!("marker_len={}", owned_marker.len());
    println!("counter_address=0x{:016X}", counter_ptr);
    println!("counter_type=u64");
    println!("seconds={}", config.seconds);
    println!("ready=true");

    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(config.seconds) {
        MUTABLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(config.tick_ms));
    }
}

#[derive(Debug)]
struct Config {
    seconds: u64,
    tick_ms: u64,
    marker: Option<Vec<u8>>,
}

impl Config {
    fn from_args(args: Vec<String>) -> Self {
        let mut config = Self {
            seconds: 300,
            tick_ms: 250,
            marker: None,
        };

        let mut idx = 0;
        while idx < args.len() {
            match args[idx].as_str() {
                "--seconds" => {
                    if let Some(value) = args.get(idx + 1).and_then(|v| v.parse::<u64>().ok()) {
                        config.seconds = value.clamp(1, 3600);
                        idx += 1;
                    }
                }
                "--tick-ms" => {
                    if let Some(value) = args.get(idx + 1).and_then(|v| v.parse::<u64>().ok()) {
                        config.tick_ms = value.clamp(10, 10_000);
                        idx += 1;
                    }
                }
                "--marker" => {
                    if let Some(value) = args.get(idx + 1) {
                        let bytes = value.as_bytes().to_vec();
                        if !bytes.is_empty() && bytes.len() <= 256 {
                            config.marker = Some(bytes);
                        }
                        idx += 1;
                    }
                }
                "--help" | "-h" => {
                    print_help_and_exit();
                }
                _ => {}
            }
            idx += 1;
        }

        config
    }
}

fn print_help_and_exit() -> ! {
    println!("Usage: cargo run --example benign_test_target -- [--seconds N] [--tick-ms N] [--marker TEXT]");
    println!("Defaults: --seconds 300 --tick-ms 250 --marker MEMORIC_BENIGN_TEST_TARGET_V1");
    std::process::exit(0);
}
