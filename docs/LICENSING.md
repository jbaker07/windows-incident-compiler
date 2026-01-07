# EDR Pro Licensing System

This document describes the local-first licensing system for EDR Pro features.

## Overview

The EDR Pro licensing system uses Ed25519 digital signatures to verify license authenticity offline. Licenses are bound to a specific installation ID and can grant various entitlements.

### Key Features

- **Local-first**: License verification happens entirely offline
- **Cryptographically signed**: Ed25519 signatures prevent tampering
- **Installation binding**: Licenses are tied to a unique install ID
- **Expiration support**: Licenses can have optional expiration dates
- **Multiple entitlements**: Single license can grant multiple features

## Architecture

```
┌─────────────────────┐         ┌──────────────────────┐
│   license_gen CLI   │         │   EDR Server/UI      │
│  (vendor machine)   │         │  (customer machine)  │
├─────────────────────┤         ├──────────────────────┤
│ - Generate keypairs │         │ - Read install_id    │
│ - Sign licenses     │ ──────► │ - Verify signatures  │
│ - Set expiration    │  JSON   │ - Check entitlements │
│ - Set entitlements  │ license │ - Gate Pro features  │
└─────────────────────┘  file   └──────────────────────┘
```

## Installation ID

Each EDR installation has a unique UUID v4 identifier stored at:

- **Windows**: `%PROGRAMDATA%\edr\install_id`
- **Linux**: `/var/lib/edr/install_id`  
- **macOS**: `/Library/Application Support/edr/install_id`

The install ID is generated on first use and persists across updates.

### Retrieving Install ID

**Via UI**: Navigate to the **License** tab to see the install ID with a copy button.

**Via API**:
```bash
curl http://localhost:8080/api/license/status
```

Response:
```json
{
  "status": "not_installed",
  "install_id": "550e8400-e29b-41d4-a716-446655440000",
  "entitlements": []
}
```

## Generating Licenses (Vendor)

The `license_gen` tool is used by vendors to generate keypairs and sign licenses.

### Initial Setup: Generate Keypair

```bash
cargo run --bin license_gen -- --generate-keypair
```

Output:
```
🔑 Generated new Ed25519 keypair

=== PRIVATE KEY (keep secret!) ===
Set this in your environment:

  export EDR_LICENSE_PRIVATE_KEY_B64="<base64-private-key>"

=== PUBLIC KEY (embed in application) ===
Replace LICENSE_PUBLIC_KEY_B64 in crates/core/src/license.rs:

  pub const LICENSE_PUBLIC_KEY_B64: &str = "<base64-public-key>";

⚠️  WARNING: Store the private key securely. If lost, you cannot generate new licenses.
⚠️  WARNING: Do not commit the private key to version control!
```

**Important**: 
1. Store the private key securely (e.g., hardware security module, secure vault)
2. Update `crates/core/src/license.rs` with the public key before shipping

### Generate a License

```bash
# Set the private key (do this once per session)
export EDR_LICENSE_PRIVATE_KEY_B64="<your-private-key>"

# Generate license for a customer
cargo run --bin license_gen -- \
  --install-id "550e8400-e29b-41d4-a716-446655440000" \
  --customer "Acme Corp" \
  --edition "pro" \
  --entitlements "diff_mode,pro_reports" \
  --output "acme_license.json"
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--install-id` | Yes | Customer's install_id (UUID) |
| `--customer` | Yes | Customer name for the license |
| `--edition` | No | Edition string (default: "pro") |
| `--entitlements` | No | Comma-separated list (default: "diff_mode") |
| `--expires-at` | No | Unix timestamp in ms (omit for perpetual) |
| `--output` | No | Output file path (default: "license.json") |

### Available Entitlements

| Entitlement | Description |
|-------------|-------------|
| `diff_mode` | Enable Diff Mode comparison features |
| `pro_reports` | Enable advanced PDF reports |
| `team_features` | Enable team collaboration features |

## License File Format

Licenses are JSON files with the following structure:

```json
{
  "payload": {
    "customer": "Acme Corp",
    "install_id": "550e8400-e29b-41d4-a716-446655440000",
    "entitlements": ["diff_mode", "pro_reports"],
    "edition": "pro",
    "issued_at_ms": 1704067200000,
    "expires_at_ms": null
  },
  "signature_b64": "base64-encoded-ed25519-signature"
}
```

The signature is computed over the canonical JSON serialization of the payload (keys sorted alphabetically, no whitespace).

## Installing a License

### Via UI

1. Navigate to the **License** tab
2. Either:
   - Click "Choose File" and select the license JSON file
   - Drag and drop the license file onto the drop zone
   - Paste the JSON content directly
3. Click "Import License"
4. The page will refresh showing the new license status

### Via API

```bash
# Read license file and POST to install endpoint
curl -X POST http://localhost:8080/api/license/install \
  -H "Content-Type: application/json" \
  -d @license.json
```

Response on success:
```json
{
  "success": true,
  "message": "License installed successfully"
}
```

## License Status

### Status Values

| Status | Description |
|--------|-------------|
| `valid` | License is valid and active |
| `not_installed` | No license file found |
| `expired` | License has passed expiration date |
| `install_id_mismatch` | License is for a different installation |
| `invalid_signature` | License signature verification failed |
| `malformed` | License file could not be parsed |

### Checking Status

**Via API**:
```bash
curl http://localhost:8080/api/license/status
```

**Via UI**: The License tab shows current status, entitlements, and expiration.

## Runtime Gating

Pro features check entitlements at runtime:

```rust
use edr_core::{diff_mode_enabled, license_manager::global_license_manager};

// Check if diff mode is available
if diff_mode_enabled() {
    // Pro feature code
}

// Or check specific entitlement
let mgr = global_license_manager();
if mgr.has_entitlement("pro_reports") {
    // Generate pro report
}
```

When a Pro feature is accessed without a valid license, the API returns:

```json
HTTP/1.1 402 Payment Required
{
  "error": "pro_license_required",
  "message": "This feature requires an active EDR Pro license.",
  "install_id": "550e8400-e29b-41d4-a716-446655440000",
  "required_entitlement": "diff_mode"
}
```

## Security Considerations

### Key Security

1. **Private Key Security**: The Ed25519 private key must be kept secret. Store it in a secure vault or HSM, never in source control.

2. **Public Key Embedding**: The public key is embedded in the binary. Changing it requires rebuilding the application.

3. **Key Rotation**: Multiple public keys can be configured for rotation. Old licenses signed with rotated keys continue to work.

### Verification Security

4. **Offline Verification**: All verification happens locally. No network calls are made to validate licenses.

5. **Signature Verification**: Licenses are verified using Ed25519 signatures, which are secure against forgery.

### Binding Security (Anti-Copy Protection)

6. **Install ID Binding**: Licenses are bound to a unique installation ID and cannot be shared.

7. **Machine Fingerprint Binding** (Optional): Licenses can be bound to machine hardware characteristics (CPU, machine GUID, OS build). This prevents simple "copy license.json to another machine" attacks.

8. **DPAPI Protection** (Windows): On Windows, license files can be encrypted at rest using Windows Data Protection API. This ties the license to the Windows user profile.

9. **Clock Tamper Detection**: The system tracks last-seen timestamps. Large backward clock jumps are detected and flagged as suspicious, preventing expiry bypass through clock manipulation.

### Privacy

10. **Privacy-Preserving Fingerprint**: Machine fingerprints are derived from stable hardware characteristics but truncated and hashed to avoid identifying specific machines. No PII is collected or transmitted.

11. **Local-First**: All licensing logic runs locally. No telemetry, no phone-home, no SaaS dependency.

### Graceful Degradation

12. **VM-Friendly**: If machine fingerprint cannot be generated (common in some VMs), the license still works with install_id binding only.

13. **DPAPI Optional**: If DPAPI protection fails, the license is stored as plaintext JSON (still signature-protected).

## License Binding Details

### What a License is Bound To

| Binding | Required | Purpose |
|---------|----------|---------|
| `bound_install_id` | Yes | UUID generated on first run |
| `bound_machine_fingerprint` | Optional | SHA256 hash of machine characteristics |

### Machine Fingerprint Components (Windows)

The fingerprint is derived from:
- Windows Machine GUID (from registry)
- CPU model name
- Windows build number

These are hashed together and truncated to 16 hex characters.

### Special Fingerprint Values

- `"PORTABLE"`: Special value that matches any machine (for dev/testing licenses)
- `null`/absent: No fingerprint binding (install_id only)

### Example: Generate Fingerprint-Bound License

```bash
export EDR_LICENSE_PRIVATE_KEY_B64="<your-private-key>"

# Generate with machine fingerprint binding
cargo run --bin license_gen -- \
  --install-id "550e8400-e29b-41d4-a716-446655440000" \
  --machine-fingerprint "abc123def456" \
  --customer "Acme Corp" \
  --edition "pro" \
  --entitlements "diff_mode,pro_reports" \
  --output "acme_license.json"
```

## Troubleshooting

### "install_id_mismatch" Error

The license was generated for a different installation. Request a new license with the correct install_id.

### "wrong_machine" Error

The license was bound to a different machine's fingerprint. Either:
- Request a new license with the current machine's fingerprint
- Request a portable license (fingerprint = "PORTABLE")

### "invalid_signature" Error

The license file may have been modified, or the public key in the application doesn't match the private key used to sign the license.

### License Not Detected After Install

Try reloading the license:
```bash
curl -X POST http://localhost:8080/api/license/reload
```

### Clock Tamper Warning

If you see clock-related warnings, ensure your system time is accurate. The system detects large backward clock jumps.

### Finding the Install ID

Check the License tab in the UI, or:
```bash
# Windows
type "%PROGRAMDATA%\edr\install_id"

# Linux/macOS
cat /var/lib/edr/install_id  # or /Library/Application Support/edr/install_id
```
