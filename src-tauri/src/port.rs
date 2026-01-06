//! Port selection logic - deterministic port with fallback

// Used by Tauri supervisor, not CLI binaries
#![allow(dead_code)]

use std::net::TcpListener;

/// Find an available port in the given range
/// 
/// Starts with `default_port` and increments up to `max_port` until
/// an available port is found.
/// 
/// # Arguments
/// * `default_port` - The preferred port to use
/// * `max_port` - The maximum port to try (inclusive)
/// 
/// # Returns
/// The first available port in the range, or None if all are busy
pub async fn find_available_port(default_port: u16, max_port: u16) -> Option<u16> {
    for port in default_port..=max_port {
        if is_port_available(port) {
            return Some(port);
        }
    }
    None
}

/// Check if a port is available for binding
fn is_port_available(port: u16) -> bool {
    TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok()
}

/// Synchronous version of port availability check (for use from supervisor)
pub fn is_port_available_sync(port: u16) -> bool {
    is_port_available(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_find_available_port_returns_first_available() {
        // In a clean test environment, port 3000 should be available
        let port = find_available_port(3000, 3010).await;
        assert!(port.is_some(), "Should find an available port");
        
        let port = port.unwrap();
        assert!(port >= 3000 && port <= 3010, "Port should be in range");
    }

    #[tokio::test]
    async fn test_find_available_port_skips_busy_ports() {
        // Bind to a test port to force fallback
        let _listener = std::net::TcpListener::bind("127.0.0.1:18765").ok();
        
        // Should still find a port
        let port = find_available_port(18765, 18775).await;
        assert!(port.is_some(), "Should find an available port even with busy default");
    }

    #[test]
    fn test_is_port_available_returns_true_for_free_port() {
        // Use a high port unlikely to be in use
        assert!(is_port_available(59999), "High port should be available");
    }

    #[test]
    fn test_is_port_available_returns_false_for_bound_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_port = listener.local_addr().unwrap().port();
        
        assert!(!is_port_available(bound_port), "Bound port should not be available");
    }
}
