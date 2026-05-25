use serde_json::{json, Value};
use std::io::Read;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[test]
fn stdio_subprocess_replays_mixed_jsonrpc_stream() {
    let input_lines = [
        json!({
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {}
        })
        .to_string(),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        .to_string(),
        "{not-json".to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": "ping",
            "method": "ping"
        })
        .to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "method": "tools/list",
            "params": { "limit": 3 }
        })
        .to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": "unknown",
            "method": "not/a_method"
        })
        .to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": "overlong",
            "method": "unknown/overlong",
            "params": {
                "blob": "x".repeat(8192)
            }
        })
        .to_string(),
    ];

    let output = run_stdio_subprocess(&input_lines, Duration::from_secs(15));
    assert!(
        output.status.success(),
        "stdio subprocess failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let responses = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("stdout line should be JSON"))
        .collect::<Vec<_>>();

    assert_eq!(
        responses.len(),
        6,
        "notification should not produce a response; stdout={stdout:?}"
    );

    assert_eq!(responses[0]["id"], "init");
    assert_eq!(responses[0]["result"]["protocolVersion"], "2025-11-25");

    assert_eq!(responses[1]["id"], Value::Null);
    assert_eq!(responses[1]["error"]["code"], -32700);

    assert_eq!(responses[2]["id"], "ping");
    assert_eq!(responses[2]["result"], Value::Null);

    assert_eq!(responses[3]["id"], "tools");
    let tools = responses[3]["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    assert_eq!(tools.len(), 3);

    assert_eq!(responses[4]["id"], "unknown");
    assert_eq!(responses[4]["error"]["code"], -32601);

    assert_eq!(responses[5]["id"], "overlong");
    assert_eq!(responses[5]["error"]["code"], -32601);
}

fn run_stdio_subprocess(input_lines: &[String], timeout: Duration) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_memoric"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("MEMORIC_TASKS_PATH")
        .env_remove("MEMORIC_AUDIT_PATH")
        .env_remove("MEMORIC_POLICY_PROFILE_PATH")
        .spawn()
        .expect("spawn memoric stdio subprocess");

    let mut stdout = child.stdout.take().expect("child stdout should be piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .read_to_end(&mut bytes)
            .expect("read child stdout to end");
        bytes
    });
    let mut stderr = child.stderr.take().expect("child stderr should be piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .read_to_end(&mut bytes)
            .expect("read child stderr to end");
        bytes
    });

    {
        let stdin = child.stdin.as_mut().expect("child stdin should be piped");
        for line in input_lines {
            writeln!(stdin, "{line}").expect("write request line");
        }
    }
    drop(child.stdin.take());

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("poll stdio subprocess") {
            Some(status) => {
                let stdout = stdout_reader.join().expect("stdout reader should join");
                let stderr = stderr_reader.join().expect("stderr reader should join");
                return Output {
                    status,
                    stdout,
                    stderr,
                };
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let status = child.wait().expect("collect timed-out subprocess status");
                let stdout = stdout_reader.join().expect("stdout reader should join");
                let stderr = stderr_reader.join().expect("stderr reader should join");
                let output = Output {
                    status,
                    stdout,
                    stderr,
                };
                panic!(
                    "stdio subprocess timed out after {:?}; stdout={} stderr={}",
                    timeout,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}
