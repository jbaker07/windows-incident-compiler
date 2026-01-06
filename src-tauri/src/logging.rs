//! Logging setup for EDR Desktop
//! 
//! Logs to a file in the app data directory

use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize logging with file output
/// 
/// Returns a guard that must be held for the lifetime of the application
/// to ensure logs are flushed.
pub fn init_logging() -> WorkerGuard {
    let log_dir = get_log_dir();
    
    // Ensure log directory exists
    std::fs::create_dir_all(&log_dir).ok();

    // Create file appender with daily rotation
    let file_appender = tracing_appender::rolling::daily(&log_dir, "edr-desktop.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Build subscriber with both stdout and file output
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,edr_desktop=debug"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
        )
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(true)
        )
        .init();

    tracing::info!("Logging initialized, log directory: {:?}", log_dir);
    
    guard
}

/// Get the log directory path
pub fn get_log_dir() -> PathBuf {
    // Use platform-appropriate app data directory
    if let Some(data_dir) = dirs::data_local_dir() {
        return data_dir.join("EDR Desktop").join("logs");
    }

    // Fallback to home directory
    if let Some(home) = dirs::home_dir() {
        return home.join(".edr-desktop").join("logs");
    }

    // Last resort
    PathBuf::from("./edr_logs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_dir_is_deterministic() {
        let dir1 = get_log_dir();
        let dir2 = get_log_dir();
        assert_eq!(dir1, dir2, "Log directory should be deterministic");
    }

    #[test]
    fn test_log_dir_is_local() {
        let dir = get_log_dir();
        let path_str = dir.display().to_string();
        
        // Should not point to any cloud locations
        assert!(!path_str.contains("iCloud"), "Should not use iCloud");
        assert!(!path_str.contains("Dropbox"), "Should not use Dropbox");
        assert!(!path_str.contains("OneDrive"), "Should not use OneDrive");
    }
}
