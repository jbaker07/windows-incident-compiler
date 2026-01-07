# Changelog

All notable changes to this project will be documented in this file.

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
