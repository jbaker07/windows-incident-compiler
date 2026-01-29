# Changelog

All notable changes to this project will be documented in this file.

## [0.3.8] - 2026-01-28

### Added
- **UI_SYNC_HARDENED-1**: UI sync invariant to prevent stale UI serving
  - `LOCINT_DEV_UI=1` env var serves directly from repo `ui/` (source) instead of `target/release/ui`
  - Server logs clearly: `[UI] DEV MODE: Serving from source ui/` when active
  - `/api/meta/ui_dir` now includes `source_ui_dir` and `source_ui_app_js_sha256` for mismatch detection
  - `dev_mode` flag in API response indicates active dev serving
  - Red warning banner in UI when source and served app.js hashes differ
  - Banner text: "UI STALE: Served files don't match source. Run scripts/sync_ui.ps1 or set LOCINT_DEV_UI=1"
  - Single source of truth: `BUILD_STAMP` in app.js, `BUILD_VERSION` now references it
  - `find_repo_root()` helper walks up to 10 directories looking for Cargo.toml + ui/

- **INVESTIGATE_CHAIN_LENS-1**: Attack Chain Lens for investigation (from prior commit)
  - Chain Lens section in Observed mode with multi-select picker
  - Chain step checklist showing satisfied/candidate/blocked/not_observed states
  - Evidence context banner when viewing proof from chain steps
  - `initChainLensForRun()` auto-applies run's `chain_ids` if present

### Fixed
- BUILD_STAMP and BUILD_VERSION in app.js were out of sync (now unified)
- UI mismatch between source `ui/` and served `target/release/ui` was silent (now loud)

## [0.3.7] - 2026-01-28

### Changed
- **INVESTIGATE_OBSERVED_FIRST-2**: Investigate tab redesign for Observed-first experience
  - Observed mode is now the true default when entering Investigate tab
  - Mode initialization enforced: legacy 'steps' mode converts to 'observed'
  - Explicit display control prevents container overlap (display:none + classList)
  - "Playbooks" button renamed to "Detectors (debug)" to reduce verifier prominence
  - Detectors mode: verifier split-pane collapsed by default with "Open Playbook Verifier" toggle
  - Blocker aggregation improved: shows real reason codes (LOG_ACCESS_DENIED, etc.) instead of "Unknown"
  - Fallback to capability hints when no reason_code present

### Fixed
- Container visibility overlap when switching Investigate modes
- "Top blocking reason: Unknown" now shows actual reason_code from playbook evaluation

## [0.3.6] - 2026-01-27

### Added
- **Observed Lens** (RUN_BRIEF-1)
  - New `GET /api/runs/:run_id/brief` endpoint for playbook-independent run view
  - Shows what actually happened during a run without requiring chain/playbook selection
  - Totals from `coverage_rollup` (NOT sampled `facts_sample`)
  - Coverage gaps from `run_meta.json` capability snapshot
  - Notable findings from `signals` table with deterministic `evidence_ptrs`
  - Activity episodes via 60-second window clustering
  - Unmapped activity showing fact types not covered by signals
  - UI: "Observed Lens" section in Evidence Summary mode

### Changed
- RUN_PIPELINE_TRUTH_REPORT.md updated with `/brief` endpoint response schema
- Evidence Summary mode now loads Observed Lens data in parallel

## [0.3.5] - 2025-01-08

### Added
- **Team V1 UX Polish**
  - Auto-refresh store status every 10 seconds when Team tab is open
  - Case list search with debounce (300ms)
  - Tag filter dropdown populated from all case tags
  - Sort options: Updated, Created, # Runs, # Notes
  - "Has Runs Only" filter to hide empty cases
  - Provenance chips showing host/user info on cases and runs
  - Case detail sub-tabs: Runs, Notes, Tags, Overview
  - Multi-select checkboxes for bulk run import
  - Bulk import progress bar with per-run status
  - Copy buttons throughout: bundle path, notes, case ID, diagnostics
  - Notes grouped by day with timeline view
  - Toast notifications (success/warning/error styles)
  - Create case form collapsible toggle

- **Team V2 Case Aggregation (Preview)**
  - New `GET /api/team/cases/:case_id/aggregate` endpoint
  - Merges data across all runs in a case without local import
  - Shows: run count, unique hosts, deduplicated findings, activity timeline
  - Findings deduplicated by rule_id with occurrence counts
  - Timeline limited to 100 events
  - Overview tab renders aggregate data when available

### Changed
- `importTeamRun` now uses toast notification instead of alert
- Team tab documentation added: `docs/TEAM_V1_WORKFLOW.md`
- UI verification checklist updated with Section L (Team UX Polish tests)
- API contract updated with aggregate endpoint documentation

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
