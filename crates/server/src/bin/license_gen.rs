//! License Generator Tool (Vendor/Admin Only)
//!
//! This tool generates signed license files for customers.
//! It is NOT included in the distributed product - only used by the vendor.
//!
//! Usage:
//!   # Generate a new keypair (do this once, save the private key securely)
//!   cargo run --bin license_gen -- --generate-keypair
//!
//!   # Generate a license for a customer
//!   cargo run --bin license_gen -- \
//!     --install-id <uuid> \
//!     --entitlements diff_mode,pro_reports \
//!     --customer "Acme Corp" \
//!     --expires-at 1735689600
//!
//! The private key should be set in the EDR_LICENSE_PRIVATE_KEY_B64 environment variable.

use std::env;
use std::fs;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use edr_core::license::{base64_encode, LicensePayload, SignedLicense};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--generate-keypair") {
        generate_keypair();
        return;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return;
    }

    // Parse arguments
    let install_id = get_arg(&args, "--install-id").expect("--install-id is required");
    let entitlements_str =
        get_arg(&args, "--entitlements").expect("--entitlements is required (comma-separated)");
    let customer = get_arg(&args, "--customer");
    let edition = get_arg(&args, "--edition").unwrap_or_else(|| "pro".to_string());
    let expires_at = get_arg(&args, "--expires-at")
        .map(|s| s.parse::<i64>().expect("Invalid expires-at timestamp"));
    let output = get_arg(&args, "--output").unwrap_or_else(|| "license.json".to_string());

    // Parse entitlements
    let entitlements: Vec<String> = entitlements_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if entitlements.is_empty() {
        eprintln!("Error: At least one entitlement is required");
        std::process::exit(1);
    }

    // Get private key from environment
    let private_key_b64 = env::var("EDR_LICENSE_PRIVATE_KEY_B64")
        .expect("EDR_LICENSE_PRIVATE_KEY_B64 environment variable must be set");

    let private_key_bytes =
        base64_decode(&private_key_b64).expect("Invalid base64 in EDR_LICENSE_PRIVATE_KEY_B64");

    if private_key_bytes.len() != 32 {
        eprintln!("Error: Private key must be 32 bytes (Ed25519)");
        std::process::exit(1);
    }

    let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into().unwrap());

    // Generate license ID
    let uuid_str = uuid::Uuid::new_v4().simple().to_string();
    let license_id = format!("lic_{}", &uuid_str[..16]);

    // Current timestamp
    let issued_at = chrono::Utc::now().timestamp_millis();

    // Convert expires_at to milliseconds if provided as seconds
    let expires_at = expires_at.map(|ts| {
        if ts < 10_000_000_000 {
            // Assume seconds, convert to milliseconds
            ts * 1000
        } else {
            ts
        }
    });

    // Optional machine fingerprint (for enhanced binding)
    let machine_fingerprint = get_arg(&args, "--machine-fingerprint");

    // Build payload
    let payload = LicensePayload {
        license_id: license_id.clone(),
        customer,
        edition,
        entitlements,
        issued_at,
        expires_at,
        bound_install_id: install_id.clone(),
        bound_machine_fingerprint: machine_fingerprint,
    };

    // Sign the canonical payload
    let canonical = payload.to_canonical_bytes();
    let signature = signing_key.sign(&canonical);
    let signature_b64 = base64_encode(signature.to_bytes().as_ref());

    // Create signed license
    let signed_license = SignedLicense {
        payload,
        signature: signature_b64,
    };

    // Serialize to pretty JSON
    let json = serde_json::to_string_pretty(&signed_license).expect("Failed to serialize license");

    // Write to file
    fs::write(&output, &json).expect("Failed to write license file");

    println!("✅ License generated successfully!");
    println!();
    println!("License ID:    {}", license_id);
    println!("Install ID:    {}", install_id);
    println!("Entitlements:  {:?}", signed_license.payload.entitlements);
    println!("Edition:       {}", signed_license.payload.edition);
    println!(
        "Expires:       {}",
        expires_at
            .map(|ts| format!(
                "{} ({}ms)",
                chrono::DateTime::from_timestamp_millis(ts)
                    .map(|d| d.to_string())
                    .unwrap_or_default(),
                ts
            ))
            .unwrap_or_else(|| "Never (perpetual)".to_string())
    );
    println!();
    println!("Output:        {}", output);
}

fn generate_keypair() {
    use rand::rngs::OsRng;
    use rand::RngCore;

    // Generate random 32 bytes for private key
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);

    // Create signing key from random bytes
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key: VerifyingKey = (&signing_key).into();

    let private_key_b64 = base64_encode(signing_key.as_bytes());
    let public_key_b64 = base64_encode(verifying_key.as_bytes());

    println!("🔑 Generated new Ed25519 keypair");
    println!();
    println!("=== PRIVATE KEY (keep secret!) ===");
    println!("Set this in your environment:");
    println!();
    println!(
        "  export EDR_LICENSE_PRIVATE_KEY_B64=\"{}\"",
        private_key_b64
    );
    println!();
    println!("=== PUBLIC KEY (embed in application) ===");
    println!("Replace LICENSE_PUBLIC_KEY_B64 in crates/core/src/license.rs:");
    println!();
    println!(
        "  pub const LICENSE_PUBLIC_KEY_B64: &str = \"{}\";",
        public_key_b64
    );
    println!();
    println!(
        "⚠️  WARNING: Store the private key securely. If lost, you cannot generate new licenses."
    );
    println!("⚠️  WARNING: Do not commit the private key to version control!");
}

fn get_arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn print_usage() {
    println!("EDR License Generator Tool");
    println!();
    println!("USAGE:");
    println!("  license_gen --generate-keypair");
    println!("  license_gen --install-id <ID> --entitlements <LIST> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("  --generate-keypair    Generate a new Ed25519 keypair");
    println!();
    println!("OPTIONS:");
    println!("  --install-id <ID>       Installation ID to bind the license to (required)");
    println!("  --entitlements <LIST>   Comma-separated list of entitlements (required)");
    println!("                          Available: diff_mode, pro_reports, team_features");
    println!("  --customer <NAME>       Customer name (optional)");
    println!("  --edition <EDITION>     License edition: pro, team (default: pro)");
    println!("  --expires-at <TS>       Unix timestamp when license expires (optional)");
    println!("                          Omit for perpetual license");
    println!("  --output <FILE>         Output file path (default: license.json)");
    println!();
    println!("ENVIRONMENT:");
    println!("  EDR_LICENSE_PRIVATE_KEY_B64    Base64-encoded Ed25519 private key");
    println!();
    println!("EXAMPLES:");
    println!("  # Generate keypair (do once)");
    println!("  license_gen --generate-keypair");
    println!();
    println!("  # Generate perpetual Pro license");
    println!("  license_gen --install-id abc-123 --entitlements diff_mode,pro_reports \\");
    println!("              --customer \"Acme Corp\"");
    println!();
    println!("  # Generate time-limited license (expires Jan 1, 2026)");
    println!("  license_gen --install-id abc-123 --entitlements diff_mode \\");
    println!("              --expires-at 1767225600");
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim().replace(['\n', '\r', ' '], "");
    let input = input.trim_end_matches('=');

    if input.is_empty() {
        return Some(Vec::new());
    }

    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;

    for c in input.bytes() {
        let value = ALPHABET.iter().position(|&x| x == c)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(result)
}
