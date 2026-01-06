fn main() {
    // Skip Windows resource file generation for development
    // The icon.ico is optional for basic functionality
    #[cfg(windows)]
    {
        // Set env to skip winres if icon.ico is problematic
        if std::path::Path::new("icons/icon.ico").exists() {
            let metadata = std::fs::metadata("icons/icon.ico").ok();
            if metadata.map(|m| m.len() < 100).unwrap_or(true) {
                // Skip winres for invalid/tiny icon files
                println!("cargo:warning=Skipping winres due to potentially invalid icon.ico");
            }
        }
    }
    tauri_build::build()
}
