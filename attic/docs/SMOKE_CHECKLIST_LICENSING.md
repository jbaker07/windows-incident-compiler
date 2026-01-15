# Smoke Checklist: Pro Licensing System

**Version**: v0.3.0  
**Date**: 2026-01-06  
**Status**: Pre-merge verification

---

## 1. Gate Commands (CI Must Pass)

Run all 7 commands and verify PASS:

```powershell
# 1. Format check
cargo fmt -- --check
# Expected: No output (success)

# 2. Clippy (default build)
cargo clippy --workspace --all-targets -- -D warnings
# Expected: No warnings/errors

# 3. Clippy (with pro feature)
cargo clippy --workspace --all-targets --features pro -- -D warnings
# Expected: No warnings/errors

# 4. Release build (default)
$env:RUSTFLAGS="-D warnings"; cargo build --release
# Expected: Compiles successfully

# 5. Release build (with pro feature)
$env:RUSTFLAGS="-D warnings"; cargo build --release --features pro
# Expected: Compiles successfully

# 6. Tests (default)
cargo test --workspace --release
# Expected: All tests pass

# 7. Tests (with pro feature)
cargo test --workspace --release --features pro
# Expected: All tests pass
```

| Gate | Status |
|------|--------|
| `cargo fmt -- --check` | ☐ PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | ☐ PASS |
| `cargo clippy --workspace --all-targets --features pro -- -D warnings` | ☐ PASS |
| `RUSTFLAGS="-D warnings" cargo build --release` | ☐ PASS |
| `RUSTFLAGS="-D warnings" cargo build --release --features pro` | ☐ PASS |
| `cargo test --workspace --release` | ☐ PASS |
| `cargo test --workspace --release --features pro` | ☐ PASS |

---

## 2. Manual Smoke Tests

### 2.1 Start Server

```powershell
cd target/release
./edr-server.exe
```

**Expected**: Server starts on http://localhost:3000

### 2.2 No License → 402 Response

```powershell
# API test
Invoke-RestMethod http://localhost:3000/api/diff?left=run_1&right=run_2
```

**Expected Response**:
```json
{
  "error": "pro_required",
  "feature": "diff_mode",
  "install_id": "<uuid>",
  "upgrade": true
}
```

**HTTP Status**: 402 Payment Required

### 2.3 UI Shows Pro Banner

1. Open http://localhost:3000
2. Navigate to **Compare** tab
3. Try to compare two runs

**Expected**: 
- 🔒 Pro License Required banner
- Shows install_id
- "Go to License Panel →" button

### 2.4 License Tab Shows Install ID

1. Click **🔑 License** tab

**Expected**:
- Status: "No License Installed"
- Install ID: `<uuid>` with copy button
- Import section visible

### 2.5 Install Valid License

Generate a test license (vendor machine):
```powershell
$env:EDR_LICENSE_PRIVATE_KEY_B64="<your-private-key>"
cargo run --bin license_gen -- `
  --install-id "<install-id-from-step-2.4>" `
  --customer "Test Customer" `
  --entitlements "diff_mode" `
  --output test_license.json
```

Import in UI:
1. License tab → Choose File → Select `test_license.json`
2. Click Import

**Expected**:
- Status changes to "✅ License Valid"
- Entitlements show "Diff Mode ✓"
- Customer name displayed

### 2.6 Valid License → 200 Response

```powershell
Invoke-RestMethod http://localhost:3000/api/diff?left=run_1&right=run_2
```

**Expected Response**:
```json
{
  "success": true,
  "data": {
    "diff": { ... },
    "meta": { ... }
  }
}
```

**HTTP Status**: 200 OK

### 2.7 Tampered License → 402

1. Open `%PROGRAMDATA%\edr\license.json`
2. Change any field (e.g., customer name)
3. Save and reload: `POST /api/license/reload`

**Expected**:
- Status: "❌ Invalid License"
- `/api/diff` returns 402 again

### 2.8 Binary Does Not Include license_gen

```powershell
# Verify license_gen is NOT in release folder
Test-Path target/release/license_gen.exe
# Expected: False
```

---

## 3. Security Verification

| Check | Status |
|-------|--------|
| Private key NOT in any source file | ☐ PASS |
| `license_gen` NOT in dist folder | ☐ PASS |
| Public key only in `license.rs` | ☐ PASS |
| 402 response includes install_id | ☐ PASS |
| Expired license returns 402 | ☐ PASS |
| Wrong install_id returns 402 | ☐ PASS |

---

## 4. Post-Merge Tag

After all checks pass and merge is complete:

```bash
git checkout main
git pull origin main
git tag -a v0.3.0 -m "Release: Pro licensing system with runtime entitlements"
git push origin v0.3.0
```

This will trigger the GitHub Actions release workflow.

---

## 5. Verification Signatures

| Tester | Date | All Checks Pass |
|--------|------|-----------------|
| ______ | ____ | ☐ Yes / ☐ No |

---

## Appendix: Quick Debug Commands

```powershell
# Check license status
Invoke-RestMethod http://localhost:3000/api/license/status

# Check install_id file
Get-Content "$env:PROGRAMDATA\edr\install_id"

# Check license file exists
Test-Path "$env:PROGRAMDATA\edr\license.json"

# Reload license after manual edit
Invoke-RestMethod -Method POST http://localhost:3000/api/license/reload

# Full license content
Get-Content "$env:PROGRAMDATA\edr\license.json" | ConvertFrom-Json | ConvertTo-Json -Depth 5
```
