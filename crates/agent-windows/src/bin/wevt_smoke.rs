//! wevt_smoke - Minimal WEVTAPI test binary
//! Reads events from System channel and prints details
//! Used to isolate wevt_reader crashes from capture logic

#![cfg(target_os = "windows")]

use std::io::Write;

fn main() {
    // Install panic hook
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("\n========== PANIC ==========");
        eprintln!("{}", panic_info);
        if let Some(location) = panic_info.location() {
            eprintln!("Location: {}:{}:{}", location.file(), location.line(), location.column());
        }
        eprintln!("Backtrace:\n{:?}", std::backtrace::Backtrace::capture());
        eprintln!("============================\n");
        let _ = std::io::stderr().flush();
    }));

    eprintln!("wevt_smoke: Testing WEVTAPI event reading");
    eprintln!("=========================================");
    let _ = std::io::stderr().flush();

    // Create reader with only System channel enabled
    let mut reader = agent_windows::wevt_reader::WevtReader::new();
    
    eprintln!("[smoke] Created WevtReader, calling poll()...");
    let _ = std::io::stderr().flush();

    match reader.poll() {
        Ok(records) => {
            eprintln!("[smoke] poll() returned {} records", records.len());
            let _ = std::io::stderr().flush();
            
            for (i, record) in records.iter().enumerate().take(20) {
                eprintln!(
                    "[smoke] Event {}: record_id={:?}, provider={}, event_id={}, xml_len={}",
                    i + 1,
                    record.source_record_id,
                    record.provider,
                    record.event_id,
                    record.xml.len()
                );
                let _ = std::io::stderr().flush();
            }
            
            eprintln!("[smoke] Successfully processed {} events", records.len().min(20));
            eprintln!("[smoke] TEST PASSED");
        }
        Err(e) => {
            eprintln!("[smoke] poll() FAILED: {}", e);
            eprintln!("[smoke] TEST FAILED");
            std::process::exit(1);
        }
    }
    
    let _ = std::io::stderr().flush();
    eprintln!("[smoke] Exiting cleanly");
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("wevt_smoke requires Windows");
    std::process::exit(1);
}
