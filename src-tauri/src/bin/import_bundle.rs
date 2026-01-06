//! import_bundle CLI - Development/CI entry point for testing the import pipeline
//!
//! Usage:
//!   cargo run --bin import_bundle -- --input <path> [--out <imports_dir>]
//!
//! This is a thin CLI wrapper around SafeImporter for dev/CI workflows.
//! It mirrors what the Tauri UI does but runs headless.

use edr_desktop_lib::{SafeImporter, ImportLimits};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    let mut input_path: Option<String> = None;
    let mut out_dir: Option<PathBuf> = None;
    
    // Simple arg parsing (no external deps)
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" => {
                i += 1;
                if i < args.len() {
                    input_path = Some(args[i].clone());
                }
            }
            "--out" | "-o" => {
                i += 1;
                if i < args.len() {
                    out_dir = Some(PathBuf::from(&args[i]));
                }
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }
    
    let input = match input_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --input <path> is required");
            print_usage();
            std::process::exit(1);
        }
    };
    
    // Default output to ./imports if not specified
    let run_dir = out_dir.unwrap_or_else(|| PathBuf::from("."));
    let run_id = generate_run_id();
    
    println!("import_bundle CLI");
    println!("  input:  {}", input);
    println!("  out:    {}", run_dir.display());
    println!("  run_id: {}", run_id);
    println!();
    
    // Create importer with default limits
    let importer = SafeImporter::new(run_id.clone(), run_dir.clone(), Some(ImportLimits::default()));
    
    match importer.import(&input) {
        Ok(result) => {
            println!("✓ Import successful!");
            println!("  bundle_id:     {}", result.bundle_id);
            println!("  manifest:      {}", result.manifest_path);
            println!("  files_dir:     {}", result.files_dir);
            println!("  total_files:   {}", result.summary.total_files);
            println!("  parsed_files:  {}", result.summary.parsed_files);
            println!("  events_extracted: {}", result.summary.events_extracted);
            println!("  total_bytes:   {}", result.summary.total_bytes);
            
            if result.summary.rejected_files > 0 {
                println!();
                println!("Rejected files: {}", result.summary.rejected_files);
            }
            
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("✗ Import failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Usage: import_bundle --input <path> [--out <dir>]");
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  --input, -i <path>   Path to folder or zip to import (required)");
    eprintln!("  --out, -o <dir>      Output directory for imports/ (default: .)");
    eprintln!("  --help, -h           Show this help");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  import_bundle --input ./testdata/sample_bundle");
    eprintln!("  import_bundle --input evidence.zip --out ./telemetry");
}

fn generate_run_id() -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("cli_{}", ts)
}
