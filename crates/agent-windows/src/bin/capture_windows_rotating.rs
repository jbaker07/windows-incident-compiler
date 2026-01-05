//! capture_windows_rotating binary entry point
//! Windows Event Log capture with rotating segments

use std::path::PathBuf;
use std::time::Duration;
use std::io::Write;

fn main() {
    // Install panic hook for better diagnostics
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("\n========== PANIC ==========");
        eprintln!("{}", panic_info);
        if let Some(location) = panic_info.location() {
            eprintln!("Location: {}:{}:{}", location.file(), location.line(), location.column());
        }
        // Print backtrace if available
        eprintln!("Backtrace:\n{:?}", std::backtrace::Backtrace::capture());
        eprintln!("============================\n");
        let _ = std::io::stderr().flush();
    }));
    
    eprintln!("capture_windows_rotating: Windows Event Log pipeline");
    let _ = std::io::stderr().flush();
    
    // Get telemetry root from env or default
    let telemetry_root = std::env::var("EDR_TELEMETRY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            #[cfg(target_os = "windows")]
            { PathBuf::from(r"C:\ProgramData\edr") }
            #[cfg(not(target_os = "windows"))]
            { PathBuf::from("/var/lib/edr") }
        });
    
    let segments_dir = telemetry_root.join("segments");
    
    // Create directories
    if let Err(e) = std::fs::create_dir_all(&segments_dir) {
        eprintln!("ERROR: Failed to create segments directory: {}", e);
        std::process::exit(1);
    }
    
    eprintln!("EDR_TELEMETRY_ROOT: {}", telemetry_root.display());
    eprintln!("Segments directory: {}", segments_dir.display());
    
    #[cfg(target_os = "windows")]
    {
        // Initialize capture
        let mut capture = agent_windows::capture_windows_rotating::WindowsEventCapture::new(segments_dir.clone());
        
        // Setup shutdown handler
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        ctrlc::set_handler(move || {
            eprintln!("\n[capture_windows_rotating] Shutdown signal received");
            shutdown_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        }).expect("Failed to set Ctrl-C handler");
        
        eprintln!("Beginning Windows Event Log capture loop (Ctrl-C to stop)...");
        let _ = std::io::stderr().flush();
        
        // Main capture loop
        while !shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                capture.poll_and_write()
            })) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    eprintln!("[capture] poll_and_write error: {:?}", e);
                }
                Err(panic_payload) => {
                    eprintln!("[capture] poll_and_write PANICKED: {:?}", panic_payload);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        
        eprintln!("[capture_windows_rotating] Capture stopped");
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("ERROR: capture_windows_rotating requires Windows");
        eprintln!("On non-Windows platforms, use capture_linux_rotating or capture_macos_rotating");
        std::process::exit(1);
    }
}
