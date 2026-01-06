# PR: feat/pro-diff-mode → main

## Summary

Add local-first Pro licensing system with Ed25519 digital signatures for offline license verification.

### Core Changes (`crates/core`)
- **install_id**: Unique UUID per installation (persisted to `%PROGRAMDATA%\edr\install_id`)
- **license**: Ed25519 signature verification, license payload schema
- **license_manager**: Global license state, entitlement checking (`has_entitlement()`)
- **diff**: Signal snapshot comparison (Pro feature, runtime-gated)

### Server Changes (`crates/server`)
- **license_api**: `GET/POST /api/license/status`, `/api/license/install`, `/api/license/reload`
- **diff_api**: `GET /api/diff` - returns 402 without valid `diff_mode` entitlement
- **license_gen** (bin): Vendor-only tool for keypair generation + license signing

### UI Changes
- **License tab**: Status display, entitlements list, install_id with copy button
- **License import**: File picker, drag-drop, paste JSON
- **402 handling**: Pro banner with install_id and upgrade prompt in Compare tab

### Documentation
- `docs/LICENSING.md`: Complete vendor + customer documentation

## Gate Commands (All PASS)

```bash
cargo fmt -- --check                                        # PASS
cargo clippy --workspace --all-targets -- -D warnings       # PASS
cargo clippy --workspace --all-targets --features pro -- -D warnings  # PASS
RUSTFLAGS="-D warnings" cargo build --release               # PASS
RUSTFLAGS="-D warnings" cargo build --release --features pro  # PASS
cargo test --workspace --release                            # PASS
cargo test --workspace --release --features pro             # PASS
```

## Commits

- `a68283f` - feat(licensing): add local-first Pro licensing system with Ed25519 signatures
- `bace94c` - feat: add Pro feature scaffolding
- Base: `95f5bd7` (tag: `v0.1.0-core-green`)

## Tags

- **v0.3.0-pro-licensing-v1** → `a68283f`

## Security Audit

- ✅ Private key (`SigningKey`) only in `license_gen.rs` (vendor tool, not shipped)
- ✅ Public key in `crates/core/src/license.rs` (embedded in binary)
- ✅ Runtime gating via 402 response with install_id

## Merge Strategy

**Recommended: Regular merge (NO squash)**

Squashing would orphan the `v0.3.0-pro-licensing-v1` tag from main's history. A regular merge preserves the tag reference.

```bash
git checkout main
git merge feat/pro-diff-mode --no-ff -m "Merge feat/pro-diff-mode: Local-first Pro licensing"
git push origin main
```

## Files Changed

### New Files (10)
- `crates/core/src/diff.rs`
- `crates/core/src/install_id.rs`
- `crates/core/src/license.rs`
- `crates/core/src/license_manager.rs`
- `crates/server/src/bin/license_gen.rs`
- `crates/server/src/diff_api.rs`
- `crates/server/src/license_api.rs`
- `crates/server/tests/diff_api_tests.rs`
- `crates/server/tests/license_api_tests.rs`
- `docs/LICENSING.md`

### Modified Files (22)
- Cargo.lock, crates/core/Cargo.toml, crates/core/src/lib.rs
- crates/server/Cargo.toml, crates/server/src/lib.rs, crates/server/src/main.rs
- ui/app.js, ui/index.html
- Various test files (clippy fixes)
