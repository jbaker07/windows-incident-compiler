//! Explainability Test Harness
//!
//! Validates that every Signal has a verifiable explanation bundle:
//! 1. Query /api/signals to get all signals
//! 2. For each signal, query /api/signals/{id}/explain
//! 3. Assert that explanation contains required fields
//! 4. Optionally replay segments to trigger fresh signals
//!
//! Usage:
//!   explain_harness --server http://127.0.0.1:3000
//!   explain_harness --server http://127.0.0.1:3000 --require-evidence

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Explainability Test Harness - validates ExplanationBundles for all signals
#[derive(Parser, Debug)]
#[command(name = "explain_harness")]
#[command(about = "Test harness for explainability verification")]
struct Args {
    /// Server base URL (e.g., http://127.0.0.1:3000)
    #[arg(long, default_value = "http://127.0.0.1:3000")]
    server: String,

    /// Minimum number of signals expected (fails if fewer)
    #[arg(long, default_value = "0")]
    min_signals: usize,

    /// Require at least one filled slot per signal
    #[arg(long)]
    require_filled_slot: bool,

    /// Require at least one evidence excerpt per signal
    #[arg(long)]
    require_evidence: bool,

    /// Timeout in seconds for HTTP requests
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Signal {
    signal_id: String,
    signal_type: String,
    severity: String,
    host: String,
    ts: String,
    evidence_ptrs: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ExplanationBundle {
    signal_id: String,
    playbook_id: String,
    playbook_title: Option<String>,
    family: String,
    slots: Vec<SlotExplanation>,
    entities: Option<EntityBundle>,
    evidence: Option<Vec<EvidenceExcerpt>>,
    counters: Option<ExplanationCounters>,
    limitations: Option<Vec<String>>,
    summary: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SlotExplanation {
    name: String,
    required: bool,
    status: String,
    predicate_desc: String,
    matched_facts: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EntityBundle {
    proc_keys: Option<Vec<String>>,
    file_keys: Option<Vec<String>>,
    identity_keys: Option<Vec<String>>,
    net_keys: Option<Vec<String>>,
    registry_keys: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EvidenceExcerpt {
    ptr: EvidencePtr,
    source: String,
    ts_ms: i64,
    excerpt: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EvidencePtr {
    stream_id: String,
    segment_id: u32,
    record_index: usize,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ExplanationCounters {
    required_slots_filled: u32,
    required_slots_total: u32,
    optional_slots_filled: u32,
    optional_slots_total: u32,
    facts_emitted: u32,
}

#[derive(Debug, Serialize)]
struct HarnessReport {
    passed: bool,
    signals_checked: usize,
    explanations_valid: usize,
    explanations_invalid: usize,
    errors: Vec<String>,
    warnings: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║      EXPLAINABILITY TEST HARNESS                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Server:           {}", args.server);
    println!("Min signals:      {}", args.min_signals);
    println!("Require filled:   {}", args.require_filled_slot);
    println!("Require evidence: {}", args.require_evidence);
    println!();

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .build()?;

    let mut report = HarnessReport {
        passed: true,
        signals_checked: 0,
        explanations_valid: 0,
        explanations_invalid: 0,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Step 1: Fetch all signals
    println!("─── Fetching signals from /api/signals ───");
    let signals_url = format!("{}/api/signals?limit=100", args.server);
    let signals_resp: ApiResponse<Vec<Signal>> = client.get(&signals_url).send()?.json()?;

    if !signals_resp.success {
        let err = format!("Failed to fetch signals: {:?}", signals_resp.error);
        report.errors.push(err.clone());
        report.passed = false;
        eprintln!("❌ {}", err);
        print_report(&report);
        return Ok(());
    }

    let signals = signals_resp.data.unwrap_or_default();
    println!("✓ Found {} signals", signals.len());

    if signals.len() < args.min_signals {
        let err = format!(
            "Insufficient signals: found {}, expected at least {}",
            signals.len(),
            args.min_signals
        );
        report.errors.push(err.clone());
        report.passed = false;
        eprintln!("❌ {}", err);
    }

    if signals.is_empty() {
        println!("⚠ No signals to validate. Pass --min-signals=1 to require signals.");
        print_report(&report);
        return Ok(());
    }

    // Step 2: For each signal, fetch and validate explanation
    println!();
    println!("─── Validating explanations ───");

    for sig in &signals {
        report.signals_checked += 1;

        if args.verbose {
            println!();
            println!(
                "  Signal: {} ({}, {})",
                sig.signal_id, sig.signal_type, sig.severity
            );
        }

        let explain_url = format!("{}/api/signals/{}/explain", args.server, sig.signal_id);
        let explain_resp: Result<ApiResponse<ExplanationBundle>, _> =
            client.get(&explain_url).send().and_then(|r| r.json());

        match explain_resp {
            Ok(resp) => {
                if !resp.success {
                    let err = format!(
                        "Signal {} has no explanation: {:?}",
                        sig.signal_id, resp.error
                    );
                    report.errors.push(err.clone());
                    report.explanations_invalid += 1;
                    report.passed = false;
                    eprintln!("  ❌ {}", err);
                    continue;
                }

                if let Some(exp) = resp.data {
                    let validation = validate_explanation(&exp, &args);

                    if validation.is_valid {
                        report.explanations_valid += 1;
                        if args.verbose {
                            println!(
                                "  ✓ Valid: playbook={}, slots={}, evidence={}",
                                exp.playbook_id,
                                exp.slots.len(),
                                exp.evidence.as_ref().map(|e| e.len()).unwrap_or(0)
                            );
                        }
                    } else {
                        report.explanations_invalid += 1;
                        report.passed = false;
                        for err in validation.errors {
                            let msg = format!("Signal {}: {}", sig.signal_id, err);
                            report.errors.push(msg.clone());
                            eprintln!("  ❌ {}", msg);
                        }
                    }

                    for warn in validation.warnings {
                        report
                            .warnings
                            .push(format!("Signal {}: {}", sig.signal_id, warn));
                    }
                } else {
                    let err = format!("Signal {} explanation data is null", sig.signal_id);
                    report.errors.push(err.clone());
                    report.explanations_invalid += 1;
                    report.passed = false;
                    eprintln!("  ❌ {}", err);
                }
            }
            Err(e) => {
                let err = format!("Failed to fetch explanation for {}: {}", sig.signal_id, e);
                report.errors.push(err.clone());
                report.explanations_invalid += 1;
                report.passed = false;
                eprintln!("  ❌ {}", err);
            }
        }
    }

    println!();
    print_report(&report);

    if report.passed {
        println!("═══════════════════════════════════════════════════════════════");
        println!("  ✓ ALL CHECKS PASSED");
        println!("═══════════════════════════════════════════════════════════════");
        Ok(())
    } else {
        println!("═══════════════════════════════════════════════════════════════");
        println!("  ✗ SOME CHECKS FAILED");
        println!("═══════════════════════════════════════════════════════════════");
        std::process::exit(1);
    }
}

struct ValidationResult {
    is_valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

fn validate_explanation(exp: &ExplanationBundle, args: &Args) -> ValidationResult {
    let mut result = ValidationResult {
        is_valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Required: playbook_id must be non-empty
    if exp.playbook_id.is_empty() {
        result.is_valid = false;
        result.errors.push("playbook_id is empty".into());
    }

    // Required: family must be non-empty
    if exp.family.is_empty() {
        result.is_valid = false;
        result.errors.push("family is empty".into());
    }

    // Required: must have at least one slot
    if exp.slots.is_empty() {
        result.is_valid = false;
        result.errors.push("no slots defined".into());
    }

    // Validate slots have required fields
    for slot in &exp.slots {
        if slot.name.is_empty() {
            result.is_valid = false;
            result.errors.push("slot has empty name".to_string());
        }
        if slot.predicate_desc.is_empty() {
            result
                .warnings
                .push(format!("slot '{}' has empty predicate_desc", slot.name));
        }
    }

    // Optional: require at least one filled slot
    if args.require_filled_slot {
        let filled = exp.slots.iter().filter(|s| s.status == "filled").count();
        if filled == 0 {
            result.is_valid = false;
            result
                .errors
                .push("no filled slots (--require-filled-slot)".into());
        }
    }

    // Optional: require evidence
    if args.require_evidence {
        let evidence_count = exp.evidence.as_ref().map(|e| e.len()).unwrap_or(0);
        if evidence_count == 0 {
            result.is_valid = false;
            result
                .errors
                .push("no evidence excerpts (--require-evidence)".into());
        }
    }

    // Validate counters consistency
    if let Some(counters) = &exp.counters {
        let required_slots = exp.slots.iter().filter(|s| s.required).count() as u32;
        if counters.required_slots_total != required_slots {
            result.warnings.push(format!(
                "counters.required_slots_total ({}) != actual required slots ({})",
                counters.required_slots_total, required_slots
            ));
        }
    }

    // Validate evidence pointers
    if let Some(evidence) = &exp.evidence {
        for ev in evidence {
            if ev.ptr.stream_id.is_empty() {
                result.warnings.push("evidence has empty stream_id".into());
            }
        }
    }

    result
}

fn print_report(report: &HarnessReport) {
    println!("─── REPORT ───");
    println!("Signals checked:       {}", report.signals_checked);
    println!("Explanations valid:    {}", report.explanations_valid);
    println!("Explanations invalid:  {}", report.explanations_invalid);

    if !report.warnings.is_empty() {
        println!();
        println!("Warnings ({}):", report.warnings.len());
        for w in &report.warnings {
            println!("  ⚠ {}", w);
        }
    }

    if !report.errors.is_empty() {
        println!();
        println!("Errors ({}):", report.errors.len());
        for e in &report.errors {
            println!("  ✗ {}", e);
        }
    }
    println!();
}
