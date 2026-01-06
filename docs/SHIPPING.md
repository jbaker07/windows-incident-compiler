# EDR Shipping & Packaging Notes

## Distribution Contents

The customer distribution package includes:

```
edr-windows-v0.3.0/
├── edr-server.exe              # Main server binary (includes runtime-gated Pro features)
├── edr-locald.exe              # Local detection daemon
├── capture_windows_rotating.exe # Windows event capture agent
├── ui/                          # Web interface assets
│   ├── index.html
│   ├── app.js
│   └── ...
├── LICENSING.md                 # License documentation
├── README.md                    # Getting started guide
└── SHA256SUMS.txt               # Integrity checksums
```

## What is NOT Shipped

The following are **vendor-only** tools and should **NEVER** be included in customer distributions:

- `license_gen.exe` - License generation tool (requires private signing key)
- `EDR_LICENSE_PRIVATE_KEY_B64` - Private signing key (environment variable, never stored in code)

## License Storage Locations

### License File
- **Path**: `%PROGRAMDATA%\edr\license.json`
- **Created by**: User via UI import or API POST
- **Format**: JSON with Ed25519 signature

### Install ID
- **Path**: `%PROGRAMDATA%\edr\install_id`
- **Created by**: First run of edr-server.exe
- **Format**: UUID v4 string

## Activation Workflow

### For Customers

1. **Start the server**: Run `edr-server.exe`
2. **Get Install ID**: Open http://localhost:3000 → License tab → Copy Install ID
3. **Send to vendor**: Provide install ID when purchasing license
4. **Receive license file**: Vendor sends `license.json`
5. **Import license**: License tab → Import → Select file or paste JSON
6. **Verify**: Status should show "License Valid" with entitlements

### For Vendors

1. **Generate keypair** (one-time): `cargo run --bin license_gen -- --generate-keypair`
2. **Store private key securely**: Save `EDR_LICENSE_PRIVATE_KEY_B64` in secure vault
3. **Embed public key**: Update `LICENSE_PUBLIC_KEY_B64` in `crates/core/src/license.rs` before building
4. **Generate license**:
   ```bash
   export EDR_LICENSE_PRIVATE_KEY_B64="<private-key>"
   cargo run --bin license_gen -- \
     --install-id "<customer-install-id>" \
     --customer "Customer Name" \
     --entitlements "diff_mode,pro_reports" \
     --output customer_license.json
   ```
5. **Send to customer**: Deliver `customer_license.json` securely

## Runtime Gating Behavior

### Without License (402 Response)
```json
{
  "error": "pro_required",
  "feature": "diff_mode",
  "install_id": "550e8400-e29b-41d4-a716-446655440000",
  "upgrade": true,
  "reason": "No license installed"
}
```

### With Valid License (200 Response)
```json
{
  "success": true,
  "data": { ... }  // Feature data
}
```

## UI Behavior

### License Tab
- Shows current status (Valid/Not Installed/Expired/Invalid)
- Displays install ID with copy button
- Import options: File picker, drag-drop, paste JSON
- Shows entitlements when valid

### Pro Feature Tabs (e.g., Compare/Diff)
- Without license: Shows upgrade banner with install ID
- With license: Full functionality

## Reproducible Builds

All release artifacts are built via GitHub Actions:

1. **Trigger**: Push tag matching `v*`
2. **Build**: `cargo build --release`
3. **Checksums**: SHA256 for all executables
4. **Artifacts**: Uploaded to GitHub Releases

To verify a release:
```powershell
# Download SHA256SUMS.txt and binaries
Get-FileHash edr-server.exe -Algorithm SHA256
# Compare with SHA256SUMS.txt
```

## Security Checklist

- [ ] Private key NOT in source control
- [ ] Private key NOT in distributed binaries
- [ ] Public key embedded in binary at compile time
- [ ] `license_gen` binary NOT included in customer package
- [ ] License verification works offline
- [ ] Tampered licenses rejected with clear error
