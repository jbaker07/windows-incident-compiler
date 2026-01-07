# Changelog

All notable changes to this project will be documented in this file.

## [0.3.4] - 2026-01-06

### Added
- **Machine Fingerprint Binding** (Anti-piracy)
  - Licenses can now optionally bind to machine fingerprint (SHA256 of machine GUID + CPU + OS build)
  - "PORTABLE" fingerprint allows dev/testing licenses that work on any machine
  - Graceful degradation if fingerprint unavailable (VMs, restricted environments)

- **Multi-Key Verification** (Key Rotation Support)
  - `LICENSE_PUBLIC_KEYS_ROTATED` array supports multiple public keys
  - Old licenses continue to work after key rotation
  - Verification tries all keys in order

- **Watermarking Module** (for future export integration)
  - `Watermark` struct embeds customer/license/install info in exports
  - Visible watermark format for headers/footers
  - Machine-readable JSON metadata for programmatic extraction

- **CI Security Scanning**
  - New `security-scan` job scans shipping binaries for sensitive strings
  - Fails if "SigningKey", "PRIVATE_KEY", etc. found in binaries
  - New `artifact-allowlist` job verifies required binaries exist

### Changed
- `LicensePayload` now has optional `bound_machine_fingerprint` field
- `LicenseVerifyResult` now includes `MachineFingerPrintMismatch` variant
- `LicenseStatus` now includes `WrongMachine` variant
- License verification uses `verify_with_fingerprint()` when fingerprint available

### Security
- Machine fingerprint prevents simple "copy license.json" piracy
- CI scans ensure no private key material in shipped binaries
- Artifact allowlist enforced in CI

## [0.3.3] - 2026-01-06

### Fixed
- **Build Command**: Added `--workspace` flag to `cargo build --release` in release workflow
  - Root cause of v0.3.2 failure: `cargo build --release` alone doesn't build all workspace crates
  - `capture_windows_rotating.exe` was not being built (lives in `agent-windows` crate)
  - Now explicitly builds all workspace members

## [0.3.2] - 2026-01-06

### Fixed
- **GitHub Actions Release Workflow**
  - Fixed PowerShell artifact collection with proper error handling (`-ErrorAction Stop`)
  - Use `Join-Path` for Windows path compatibility
  - Added comprehensive build diagnostics and logging
  
- **Security Hardening**
  - Explicit binary allowlist in release workflow (only ship: `edr-server.exe`, `edr-locald.exe`, `capture_windows_rotating.exe`)
  - Explicit forbidden binary list (`license_gen.exe`, `golden-cli.exe`, etc.)
  - Security violation check fails build if forbidden binaries found in dist
  - Added `MANIFEST.txt` to track all shipped files
  
- **Release Validation**
  - Added ZIP content validation step before GitHub Release creation
  - Automated verification that required binaries exist
  - Automated verification that forbidden binaries are excluded

## [0.3.1] - 2026-01-06

### Fixed
- Fixed GitHub Actions workflow: `dtolnay/rust-action` → `dtolnay/rust-toolchain`
  (Note: Workflow still failed due to PowerShell copy issues, fixed in v0.3.2)

## [0.3.0] - 2026-01-06

### Added
- **Local-first Pro Licensing System**
  - Ed25519 signed licenses with offline verification
  - Installation ID binding for license portability protection
  - Runtime entitlement checking (`diff_mode`, `pro_reports`, `team_features`)
  - License import via UI (file picker, drag-drop, paste JSON)
  
- **Diff Mode (Pro Feature)**
  - Signal snapshot comparison between runs
  - Added/Removed/Changed signal detection
  - API endpoint: `GET /api/diff?left=<run>&right=<run>`
  - UI Compare tab with diff visualization
  
- **License API Endpoints**
  - `GET /api/license/status` - Current license status and entitlements
  - `POST /api/license/install` - Import license JSON
  - `POST /api/license/reload` - Reload license from disk
  
- **License UI Tab**
  - Status display with entitlements list
  - Install ID with copy button for customer support
  - License import options (file/drag-drop/paste)
  
- **Vendor Tooling**
  - `license_gen` CLI for keypair generation and license signing
  - NOT included in customer distributions
  
- **Documentation**
  - `docs/LICENSING.md` - Complete licensing system documentation
  - `docs/SHIPPING.md` - Distribution packaging notes
  - `docs/SMOKE_CHECKLIST_LICENSING.md` - QA verification checklist

- **Release Automation**
  - GitHub Actions release workflow on `v*` tags
  - Automated binary collection and SHA256 checksums
  - Artifact zip bundle with UI assets

### Changed
- Diff module now always compiled (one-binary approach)
- Pro features gated at runtime via license, not compile-time

### Security
- Private signing key never embedded in distributed binaries
- `license_gen` binary excluded from release artifacts
- Ed25519 signatures prevent license tampering

## [0.1.0] - 2026-01-05

### Added
- Initial Windows EDR stack release
- Core signal detection and evidence collection
- Web UI for signal visualization
- PDF report generation
- Hypothesis arbitration system

[0.3.0]: https://github.com/jbaker07/windows-incident-compiler/compare/v0.1.0-core-green...v0.3.0
[0.1.0]: https://github.com/jbaker07/windows-incident-compiler/releases/tag/v0.1.0-core-green
