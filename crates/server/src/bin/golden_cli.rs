//! Golden Bundle CLI - Verify and Generate Golden Bundles
//!
//! Usage:
//!   golden-cli verify [OPTIONS] <BUNDLE_DIR>
//!   golden-cli generate [OPTIONS] <OUTPUT_DIR>
//!
//! Acceptance Gates:
//! 1. Verifier runs fully in-process (no HTTP, no server)
//! 2. Verdict semantics: PASS/PARTIAL/FAIL
//! 3. Golden bundles are generated, not hand-edited
//! 4. Produces JSON artifact for CI
//! 5. Hard edges covered

use edr_server::{
    generate_all_golden_bundles, verify_all_bundles, verify_bundle_in_process, VerificationReport,
    VerifyMode,
};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return ExitCode::from(1);
    }

    match args[1].as_str() {
        "verify" => run_verify(&args[2..]),
        "generate" | "gen" => run_generate(&args[2..]),
        "help" | "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            ExitCode::from(1)
        }
    }
}

fn print_usage() {
    eprintln!(
        r#"Golden Bundle CLI - Verify and Generate Golden Bundles

USAGE:
    golden-cli verify [OPTIONS] <BUNDLE_DIR>
    golden-cli generate [OPTIONS] <OUTPUT_DIR>

COMMANDS:
    verify      Verify golden bundles (in-process, no HTTP)
    generate    Generate golden bundles from predefined scenarios

VERIFY OPTIONS:
    --strict              Strict mode (version/playbook mismatch => FAIL)
    --json <FILE>         Output JSON report to file
    --families <LIST>     Comma-separated family filter (e.g., credential_access,persistence)
    --limit <N>           Max bundles to verify (for quick iteration)

GENERATE OPTIONS:
    --regenerate          Regenerate all bundles (overwrite existing)

EXAMPLES:
    # Verify all golden bundles (strict mode)
    golden-cli verify --strict bundles/golden

    # Verify specific families
    golden-cli verify --families credential_access,edge_cases bundles/golden

    # Verify with JSON output for CI
    golden-cli verify --strict --json results.json bundles/golden

    # Generate all golden bundles
    golden-cli generate bundles/golden

    # Verify single bundle
    golden-cli verify bundles/golden/credential_access/mimikatz_lsass_001

VERDICTS:
    PASS    - Replay == recompute across all dimensions
    PARTIAL - Recompute ran but with warnings (best_effort mode only)
    FAIL    - Checksum invalid, ordering violation, or determinism failure
"#
    );
}

fn run_verify(args: &[String]) -> ExitCode {
    let mut strict = false;
    let mut json_output: Option<PathBuf> = None;
    let mut families: Option<Vec<String>> = None;
    let mut limit: Option<usize> = None;
    let mut bundle_dir: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--strict" => strict = true,
            "--json" => {
                i += 1;
                if i < args.len() {
                    json_output = Some(PathBuf::from(&args[i]));
                }
            }
            "--families" => {
                i += 1;
                if i < args.len() {
                    families = Some(args[i].split(',').map(|s| s.trim().to_string()).collect());
                }
            }
            "--limit" => {
                i += 1;
                if i < args.len() {
                    limit = args[i].parse().ok();
                }
            }
            arg if !arg.starts_with('-') => {
                bundle_dir = Some(PathBuf::from(arg));
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
            }
        }
        i += 1;
    }

    let bundle_dir = match bundle_dir {
        Some(d) => d,
        None => {
            eprintln!("Error: BUNDLE_DIR required");
            return ExitCode::from(1);
        }
    };

    let mode = if strict {
        VerifyMode::Strict
    } else {
        VerifyMode::BestEffort
    };

    // Check if it's a single bundle or directory of bundles
    let report = if bundle_dir.join("manifest.json").exists() {
        // Single bundle
        match verify_bundle_in_process(&bundle_dir, mode) {
            Ok(result) => {
                let verdict = result.verdict.clone();
                VerificationReport {
                    timestamp: chrono::Utc::now(),
                    mode: if strict { "strict" } else { "best_effort" }.to_string(),
                    total_bundles: 1,
                    passed: if verdict == "PASS" { 1 } else { 0 },
                    partial: if verdict == "PARTIAL" { 1 } else { 0 },
                    failed: if verdict == "FAIL" { 1 } else { 0 },
                    results: vec![result],
                    overall_verdict: verdict,
                }
            }
            Err(e) => {
                eprintln!("Error verifying bundle: {}", e);
                return ExitCode::from(1);
            }
        }
    } else {
        // Directory of bundles
        match verify_all_bundles(&bundle_dir, mode, families.as_deref(), limit) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error verifying bundles: {}", e);
                return ExitCode::from(1);
            }
        }
    };

    // Print summary
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║           GOLDEN BUNDLE VERIFICATION REPORT                  ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Mode: {:55} ║", report.mode);
    println!("║  Total: {:54} ║", report.total_bundles);
    println!("║  Passed: {:53} ║", report.passed);
    println!("║  Partial: {:52} ║", report.partial);
    println!("║  Failed: {:53} ║", report.failed);
    println!("╠══════════════════════════════════════════════════════════════╣");

    let verdict_display = match report.overall_verdict.as_str() {
        "PASS" => "✓ PASS",
        "PARTIAL" => "⚠ PARTIAL",
        "FAIL" => "✗ FAIL",
        _ => &report.overall_verdict,
    };
    println!("║  Overall Verdict: {:44} ║", verdict_display);
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Print per-bundle details
    for result in &report.results {
        let icon = match result.verdict.as_str() {
            "PASS" => "✓",
            "PARTIAL" => "⚠",
            "FAIL" => "✗",
            _ => "?",
        };

        println!(
            "{} {}/{} [{}]",
            icon, result.family, result.bundle_name, result.verdict
        );

        if result.verdict != "PASS" {
            for reason in &result.reasons {
                println!("    └─ {}", reason);
            }
        }
    }

    // Write JSON output if requested
    if let Some(json_path) = json_output {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&json_path, json) {
                    eprintln!("Error writing JSON output: {}", e);
                } else {
                    println!("\nJSON report written to: {}", json_path.display());
                }
            }
            Err(e) => eprintln!("Error serializing report: {}", e),
        }
    }

    // Exit code based on verdict
    match report.overall_verdict.as_str() {
        "PASS" => ExitCode::SUCCESS,
        "PARTIAL" => ExitCode::from(0), // PARTIAL is acceptable in CI
        "FAIL" => ExitCode::from(1),    // FAIL breaks CI
        _ => ExitCode::from(1),
    }
}

fn run_generate(args: &[String]) -> ExitCode {
    let mut output_dir: Option<PathBuf> = None;
    let mut regenerate = false;

    for arg in args {
        match arg.as_str() {
            "--regenerate" => regenerate = true,
            a if !a.starts_with('-') => {
                output_dir = Some(PathBuf::from(a));
            }
            _ => {}
        }
    }

    let output_dir = match output_dir {
        Some(d) => d,
        None => {
            eprintln!("Error: OUTPUT_DIR required");
            return ExitCode::from(1);
        }
    };

    // Check if bundles already exist
    if output_dir.exists() && !regenerate {
        let has_bundles = std::fs::read_dir(&output_dir)
            .map(|entries| entries.filter_map(|e| e.ok()).any(|e| e.path().is_dir()))
            .unwrap_or(false);

        if has_bundles {
            eprintln!("Warning: Output directory already contains bundles.");
            eprintln!("Use --regenerate to overwrite.");
            return ExitCode::from(1);
        }
    }

    println!("Generating golden bundles...\n");

    match generate_all_golden_bundles(&output_dir) {
        Ok(paths) => {
            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║           GOLDEN BUNDLE GENERATION COMPLETE                  ║");
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!("║  Generated: {:50} ║", paths.len());
            println!("║  Output: {:53} ║", output_dir.display());
            println!("╚══════════════════════════════════════════════════════════════╝\n");

            for path in &paths {
                let family = path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("?");
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                println!("  ✓ {}/{}", family, name);
            }

            println!(
                "\nVerify with: golden-cli verify --strict {}",
                output_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error generating bundles: {}", e);
            ExitCode::from(1)
        }
    }
}
