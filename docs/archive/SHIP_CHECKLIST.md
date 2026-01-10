# Ship Checklist for v0.3.5

This document is a pre-release security and quality audit checklist.
All items must pass before tagging a release.

## 🔐 Security Audit

### Private Key Material
- [x] **PASS**: `SigningKey` only appears in `license_gen.rs` (vendor-only tool)
- [x] **PASS**: No hardcoded private keys found in codebase
- [x] **PASS**: CI scans shipping binaries for forbidden patterns:
  - `SigningKey`
  - `PRIVATE_KEY`
  - `EDR_LICENSE_PRIVATE_KEY`
  - `-----BEGIN PRIVATE KEY-----`
  - `ed25519_secret`

### Forbidden Binaries
- [x] **PASS**: `license_gen.exe` in forbidden_binaries list (`packaging/allowlist.json`)
- [x] **PASS**: `golden-cli.exe` in forbidden_binaries list
- [x] **PASS**: Other internal/dev tools excluded:
  - `proof_run.exe`
  - `metrics_run.exe`
  - `explain_harness.exe`
  - `wevt_smoke.exe`
  - `agent-windows.exe`

### Fingerprint Privacy
- [x] **PASS**: Fingerprint is SHA256 hash, not raw machine data
- [x] **PASS**: Only 16 hex chars (64 bits) stored - not reversible
- [x] **PASS**: Components: machine_guid + CPU name + OS build (no PII)
- [x] **PASS**: Documentation states "not personally identifiable"

### License Security
- [x] **PASS**: Ed25519 signature verification with public key only
- [x] **PASS**: Key rotation support via `LICENSE_PUBLIC_KEYS_ROTATED`
- [x] **PASS**: Machine binding prevents simple license copying
- [x] **PASS**: DPAPI protection for at-rest license storage (Windows)
- [x] **PASS**: Clock tamper detection implemented

## 📦 Packaging Audit

### Artifact Validation
- [x] **PASS**: Single source of truth: `packaging/allowlist.json`
- [x] **PASS**: CI validates artifacts against allowlist
- [x] **PASS**: Release workflow validates artifacts against allowlist
- [x] **PASS**: JSON schema provided for allowlist validation

### Required Binaries
- [x] `edr-server.exe` - Web UI and API server
- [x] `edr-locald.exe` - Local daemon for event processing
- [x] `capture_windows_rotating.exe` - Windows event log capture

### Required Assets
- [x] `ui/` directory with all frontend files
- [x] `README.md` documentation
- [x] `MANIFEST.txt` with SHA256 checksums

## 🎨 UX Audit

### License Panel
- [x] **PASS**: Installation ID always visible with copy button
- [x] **PASS**: Machine binding status displayed
- [x] **PASS**: Clear status icons for all license states:
  - ✅ Valid
  - 🔒 Not Installed
  - ⏰ Expired
  - ❌ Invalid
  - 🔄 Wrong Installation
  - ⚙️ Not Configured (dev)

### Error States
- [x] **PASS**: 402 responses show clear "Pro License Required" banner
- [x] **PASS**: 403 responses show "Machine Binding Error" with support guidance
- [x] **PASS**: Installation ID shown in error banners for easy support contact

### Watermarking
- [x] **PASS**: Diff reports include license watermark
- [x] **PASS**: Bundle exports include watermark metadata

## 🧪 Quality Gates

### Pre-Release Verification
```powershell
# All must pass before tagging
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --release
```

### Build Verification
```powershell
# Verify release build produces correct binaries
cargo build --release --bin edr-server --bin edr-locald --bin capture_windows_rotating
```

## ✅ Final Sign-Off

| Check | Status | Date | Notes |
|-------|--------|------|-------|
| Security Audit | ✅ PASS | $(date) | No private key material in shipping binaries |
| Packaging Audit | ✅ PASS | $(date) | Allowlist validation in place |
| UX Audit | ✅ PASS | $(date) | License panel complete |
| Quality Gates | ⏳ PENDING | | Run before final tag |
| Tag v0.3.5 | ⏳ PENDING | | After quality gates pass |

---

## Changelog Summary for v0.3.5

### Added
- DPAPI protection for license at-rest storage (Windows)
- Clock tamper detection in license validation
- Machine fingerprint status in License panel
- 403 error handling for machine binding errors
- Comprehensive `SHIP_CHECKLIST.md` audit document

### Changed
- Canonical `packaging/allowlist.json` as single source of truth
- Deterministic MANIFEST.txt generation with SHA256 per file
- Enhanced error messages with Installation ID for support

### Security
- CI binary scanning for forbidden patterns
- Forbidden binaries validation in release workflow
- Machine binding prevents license file copying
- Watermarking in diff reports and bundle exports
