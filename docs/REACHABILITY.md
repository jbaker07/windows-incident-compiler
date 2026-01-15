# Dependency Reachability Audit

Generated from `cargo tree --workspace --depth 1` on the real product entrypoints.

---

## 1. Workspace Crates

| Crate | Description | Reachable From | Status |
|-------|-------------|----------------|--------|
| `edr-server` | HTTP API server, contains `locint.rs` | **CORE ENTRYPOINT** | ✅ CORE |
| `edr-core` | Shared core types | edr-server, edr-locald, agent-windows | ✅ CORE |
| `edr-locald` | Detection daemon | spawned by supervisor | ✅ CORE |
| `agent-windows` | Capture agent (`capture_windows_rotating`) | spawned by supervisor | ✅ CORE |
| `workbench` | Attack documentation (MITRE techniques) | edr-server | ⚠️ OPTIONAL |
| `wi-run-all` | Integration test runner | dev/CI only | 🔧 DEV |

---

## 2. Core Binary Entrypoints

### 2.1 locint (Desktop GUI) - **PRIMARY**
```
crates/server/src/bin/locint.rs
```
- Ships as: `locint.exe`
- Dependencies: `edr-server`, `edr-core`
- Spawns: `edr-locald.exe`, `capture_windows_rotating.exe`
- Feature: `default` (always included)

### 2.2 edr-server (Headless CLI) - **SECONDARY**
```
crates/server/src/main.rs
```
- Ships as: `edr-server.exe`
- Dependencies: `edr-server`, `edr-core`
- Feature: `legacy_server` (disabled by default)
- Status: Deprecated, prefer locint

### 2.3 edr-locald (Detection Daemon) - **CORE**
```
crates/locald/src/main.rs
```
- Ships as: `edr-locald.exe`
- Dependencies: `edr-core`, rusqlite, regex
- Creates: `workbench.db` (signals, facts, coverage)

### 2.4 capture_windows_rotating (Capture Agent) - **CORE**
```
crates/agent-windows/src/main.rs
```
- Ships as: `capture_windows_rotating.exe`
- Dependencies: `edr-core`, windows-rs
- Creates: `segments/*.jsonl`

---

## 3. Non-Core Binaries (Feature-Gated)

### 3.1 golden-cli
```
crates/server/src/bin/golden_cli.rs
```
- Purpose: CI golden bundle testing
- Feature: `golden_bundle`
- Status: NOT shipped to users

### 3.2 license_gen
```
crates/server/src/bin/license_gen.rs
```
- Purpose: Internal license generation
- Feature: `dev_utils`
- Status: NOT shipped to users

---

## 4. Module Reachability (edr-server)

### ALWAYS COMPILED (Core)
| Module | Purpose |
|--------|---------|
| `bundle_exchange` | Export/import ZIP bundles |
| `db` | Signal storage types |
| `health` | Startup validation, health checks |
| `query_isolation` | Namespace filtering for imported runs |
| `report` | PDF generation |
| `server_core` | Shared server config types |
| `supervisor` | Process orchestration (capture, locald) |
| `write_isolation` | Prevent writes to imported data |
| `run_db` | Per-run workbench.db access |

### FEATURE-GATED (Non-Core)
| Module | Feature | Status |
|--------|---------|--------|
| `golden_bundle` | `golden_bundle` | CI only |
| `support_bundle` | `support_bundle` | Debug only |
| `integration_api` | `integrations` | Enterprise |

---

## 5. Cargo Features Matrix

```toml
[features]
default = ["core"]           # Ships with core only
core = ["edr-core/core"]     # Core loop
test-utils = []              # Test helpers
dev_utils = []               # license_gen, etc.
legacy_server = []           # edr-server.exe (deprecated)
golden_bundle = []           # CI testing
support_bundle = []          # Debug bundles
integrations = []            # SIEM integrations
pro = ["diff", "narrative", "watermark"]
diff = ["edr-core/diff"]     # Delta reports
narrative = ["edr-core/narrative"]  # NLP narratives
watermark = ["edr-core/watermark"]  # Watermarks
```

---

## 6. Candidates for Deletion/Attic

### 6.1 Confirmed Dead Code
| Path | Reason |
|------|--------|
| `crates/server/src/main.rs` | Use locint.rs instead (gated behind `legacy_server`) |

### 6.2 Move to attic/
| Path | Reason |
|------|--------|
| `crates/workbench/` | Attack documentation, not part of core detection loop |

### 6.3 Already Feature-Gated (Keep)
| Path | Feature |
|------|---------|
| `src/bin/golden_cli.rs` | `golden_bundle` |
| `src/bin/license_gen.rs` | `dev_utils` |

---

## 7. Runtime Process Tree

```
locint.exe (GUI server)
├── edr-locald.exe (detection daemon)
│   └── writes: run_dir/workbench.db
└── capture_windows_rotating.exe (telemetry capture)
    └── writes: run_dir/segments/*.jsonl
```

---

## 8. Verification Commands

```bash
# Build core only (default)
cargo build --release -p edr-server --bin locint

# Check what features are enabled
cargo tree -p edr-server --features core

# Build with all features (for verification)
cargo build --release -p edr-server --all-features
```

---

*Generated: Core Product Consolidation Phase*
