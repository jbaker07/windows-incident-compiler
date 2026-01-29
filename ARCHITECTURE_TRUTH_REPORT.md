# ARCHITECTURE TRUTH REPORT

**Generated:** 2026-01-27  
**Build Stamp:** `2026-01-27-BACKEND_CHAINS-1`  
**Purpose:** Establish authoritative mental model of the repository from actual files.

---

## 1) Repo Topology (Authoritative)

### Top-Level Directories

| Directory | Purpose | Evidence |
|-----------|---------|----------|
| `ui/` | **Source** UI files (hand-edited) | Contains `app.js`, `index.html`, `loading.html` |
| `target/release/ui/` | **Served** UI files (copied from `ui/`) | Server reads from here via `ServeDir` |
| `crates/` | Rust workspace crates | Contains `server/`, `agent-windows/`, `core/`, `locald/`, `workbench/`, `wi-run-all/` |
| `crates/server/` | Main API server (`locint` binary) | `src/bin/locint.rs` is the entry point |
| `playbooks/` | Playbook YAML definitions | `windows/` contains ~30 playbooks |
| `LocInt/` | **Stale** distribution folder | Contains old UI files + binaries (NOT used by dev server) |
| `scripts/` | Build/sync helper scripts | `sync_ui.ps1` copies `ui/` → `target/release/ui/` |
| `docs/` | Documentation | Markdown files |
| `src-tauri/` | Tauri desktop app wrapper | Not the main server |

### Which Component Serves `/ui/`

**Server Binary:** `target/release/locint.exe` (or debug build)

**Evidence:** [crates/server/src/bin/locint.rs#L465](crates/server/src/bin/locint.rs#L465)
```rust
.nest_service("/ui", ServeDir::new(&config.ui_dir))
```

**UI Directory Resolution:** [crates/server/src/server_core.rs#L93](crates/server/src/server_core.rs#L93)
```rust
ui_dir: exe_dir.join("ui"),
```

This means the server looks for `ui/` **adjacent to the executable**:
- For release builds: `target/release/ui/`
- For dev cargo run: depends on working directory

### Which Process Serves `/api/*`

**Process:** `locint.exe` (same binary as UI serving)

**Evidence:** [crates/server/src/bin/locint.rs#L380-L466](crates/server/src/bin/locint.rs#L380-L466) - All API routes defined in `make_router()` function.

**Started locally:**
```powershell
.\target\release\locint.exe
# OR
cargo run --release -p edr-server --bin locint
```

**Default port:** 3000 (verified via `netstat` - process listens on `0.0.0.0:3000`)

---

## 2) Backend Stack (Authoritative)

### Language/Framework

**Language:** Rust  
**Framework:** Axum (async web framework on Tokio)

**Evidence:** [crates/server/Cargo.toml](crates/server/Cargo.toml) - dependencies include `axum`, `tokio`, `tower-http`

### HTTP Route Registration

**Primary Router File:** [crates/server/src/bin/locint.rs](crates/server/src/bin/locint.rs)

**Route Registration Function:** `make_router()` at lines 375-466

**Key Route Groups:**
| Lines | Group | Endpoints |
|-------|-------|-----------|
| 381-401 | Runs | `/api/runs`, `/api/runs/:run_id/*` |
| 426-432 | Playbooks | `/api/playbooks/catalog`, `/api/playbooks/presets` |
| 423-424 | **Chains** | `/api/chains`, `/api/chains/compile` |
| 434-439 | Diagnostics | `/api/capability`, `/api/meta/routes` |
| 445 | Evidence | `/api/evidence/deref` |

### Run/Playbook/Signal Modules

| Data Type | Service Module | Handler Location |
|-----------|----------------|------------------|
| Runs | `services::run_control` | locint.rs:1500-2000 |
| Playbooks | inline in locint.rs (catalog handler) | locint.rs:5054-5490 |
| Signals | `services::signals` | locint.rs:2352-2470 |
| Evidence | `services::evidence` | locint.rs:1799-1970 |
| Chains | `services::chains` | locint.rs:7160-7260 |

---

## 3) UI Build + Serving Pipeline (Critical)

### Are index.html/app.js Hand-Edited or Built?

**Answer:** Hand-edited source files in `ui/` folder.

**Evidence:**
- No webpack, vite, or build tool configuration in repo
- No `dist/`, `build/`, or generated output folder
- `ui/app.js` has `BUILD_VERSION` string manually updated: [ui/app.js#L62](ui/app.js#L62)
- No package.json at root for JS build

### Copy Pipeline

**Source:** `ui/` (workspace root)  
**Target:** `target/release/ui/` (where server reads)

**Sync Script:** [scripts/sync_ui.ps1](scripts/sync_ui.ps1)
```powershell
Copy-Item -Path "$SourceDir\*" -Destination $TargetDir -Force -Recurse
```

### Why Changes Sometimes "Don't Show"

**Root Cause:** The server binary at `target/release/locint.exe` serves from `target/release/ui/`, NOT from workspace `ui/`.

If you edit `ui/app.js` but don't run `sync_ui.ps1` (or manually copy), the served file is stale.

**Current State Verification:**
```powershell
# Files ARE identical now (hash check passed):
$f1 = Get-FileHash "ui\app.js"
$f2 = Get-FileHash "target\release\ui\app.js"
$f1.Hash -eq $f2.Hash  # True
```

### BUILD Badge Location

**Defined in:** [ui/app.js#L62](ui/app.js#L62)
```javascript
const BUILD_VERSION = '2026-01-27-BACKEND_CHAINS-1';
```

**Logged at startup:** [ui/app.js#L63](ui/app.js#L63)
```javascript
console.log(`%c[UI BUILD] ${BUILD_VERSION}`, 'color: #8b5cf6; font-weight: bold;');
```

**Also in index.html script tag:** [ui/index.html#L2967](ui/index.html#L2967)
```html
<script src="/ui/app.js?v=2026-01-27-BACKEND_CHAINS-1"></script>
```

---

## 4) Playbook Catalog Source of Truth

### Where Does `/api/playbooks/catalog` Data Come From?

**Source:** Runtime scan of YAML files from filesystem

**Handler:** `playbooks_catalog_handler()` at [crates/server/src/bin/locint.rs#L5054-5490](crates/server/src/bin/locint.rs#L5054-5490)

**Discovery Logic:** `services::run_control::discover_playbooks_dir()` searches:
1. `exe_dir/playbooks/windows/` (for release builds)
2. Environment variable `EDR_PLAYBOOKS_DIR`
3. Workspace `playbooks/windows/` (for dev builds)

### Is It Static JSON or Dynamic?

**Dynamic** - Playbook YAML files are parsed at each API call.

### Where Are Family/Tags/Requirements Defined?

**In each playbook YAML file.** Example: [playbooks/windows/signal_file_staging.yaml#L1-50](playbooks/windows/signal_file_staging.yaml#L1-50)

```yaml
family: "collection"
requires:
  - security_log
  - audit_proc_creation
enhances_with:
  - sysmon
mitre:
  tactics:
    - collection
    - exfiltration
  techniques:
    - T1560.001
```

**Parsing at:** [locint.rs#L5165-5190](crates/server/src/bin/locint.rs#L5165-5190) extracts `family`, `category`, `requires`, `mitre_tactics`, `mitre_techniques`

---

## 5) Current Chain Logic Locations (Ground Truth)

### MICRO_CHAINS Registry

| Location | Type | Lines | Status |
|----------|------|-------|--------|
| `crates/server/src/services/chains.rs` | Backend (Rust) | 123-300 | ✅ CANONICAL |
| `ui/app.js` | Frontend | N/A | ❌ REMOVED (was 1612-1770) |
| `target/release/ui/chain_engine.js` | Frontend | N/A | ❌ DELETED |

**Canonical Definition:** [crates/server/src/services/chains.rs#L123-127](crates/server/src/services/chains.rs#L123-127)
```rust
static MICRO_CHAINS: OnceLock<HashMap<String, MicroChain>> = OnceLock::new();
```

### compileChainToPlaybooks

| Location | Type | Lines | Status |
|----------|------|-------|--------|
| `services::chains::compile_single_chain()` | Backend | 350-420 | ✅ CANONICAL |
| Frontend | N/A | N/A | ❌ REMOVED |

### stepToPlaybooks Mapping Creation

**Backend:** [crates/server/src/services/chains.rs#L420-450](crates/server/src/services/chains.rs#L420-450) - Built during `compile_single_chain()`

### Chain Stack Union Logic

**Backend:** [crates/server/src/services/chains.rs#L470-520](crates/server/src/services/chains.rs#L470-520) - `compile_chain_stack()` computes deduplicated union

### Frontend API Calls

| Function | File | Lines | Purpose |
|----------|------|-------|---------|
| `fetchChainDefinitions()` | ui/app.js | 1627-1650 | GET /api/chains |
| `compileChainStackViaBackend()` | ui/app.js | 1656-1680 | POST /api/chains/compile |
| `addChainToStack()` | ui/app.js | 5125-5170 | Calls compileChainStackViaBackend |
| `replaceChainStack()` | ui/app.js | 5175-5210 | Calls compileChainStackViaBackend |
| `removeChainFromStack()` | ui/app.js | 5215-5260 | Calls compileChainStackViaBackend |

---

## 6) Inconsistencies / Architectural Smells

| Symptom | Root Cause (Cited) | Why It Causes Errors | Fix Recommendation |
|---------|-------------------|---------------------|-------------------|
| LocInt/ui/ has different app.js | Legacy distribution folder with stale files | Confusion about which UI is served | Delete LocInt/ or mark as archive |
| Chain logic was duplicated in frontend | Original design had frontend-only chains | Opus created chain_engine.js that duplicated backend | ✅ FIXED - Backend is now canonical |
| UI shows stale build | Manual sync required: `ui/` → `target/release/ui/` | Edits to ui/ not reflected until sync | Add to workflow: always run sync_ui.ps1 |
| Multiple "ui" folders | `ui/`, `target/release/ui/`, `LocInt/ui/`, `src-tauri/...` | Unclear which is canonical source | Document: `ui/` = source, `target/release/ui/` = served |
| Playbook catalog parsed per-request | No caching in playbooks_catalog_handler | Slow for large catalogs, inefficient | Consider OnceLock caching like chains |
| index.html script tag version manual | `?v=...` param must be manually updated | Cache invalidation depends on human | Auto-generate from BUILD_VERSION |

---

## 7) Fastest Path to Backend Canonical Chains (Implemented)

### Current State (Already Implemented)

The changes from this session have **already established backend as canonical**:

#### Backend (Rust)

**Chain Definitions:** [crates/server/src/services/chains.rs](crates/server/src/services/chains.rs)
- 8 chains defined in static `MICRO_CHAINS` registry
- `get_all_chains()` returns all definitions
- `compile_chain_stack()` compiles chain IDs to playbook selections with deduplication

**API Endpoints:** [crates/server/src/bin/locint.rs#L423-424](crates/server/src/bin/locint.rs#L423-424)
```rust
.route("/api/chains", get(chains_list_handler))
.route("/api/chains/compile", post(chains_compile_handler))
```

**Handlers:** [crates/server/src/bin/locint.rs#L7160-7260](crates/server/src/bin/locint.rs#L7160-7260)

#### Frontend (JavaScript)

**Removed:**
- `MICRO_CHAINS` constant
- `compileChainToPlaybooks()` local function
- `recomputeStackBaseline()` local function
- `chain_engine.js` file
- Script tag for chain_engine.js

**Added:**
- `fetchChainDefinitions()` - calls GET /api/chains
- `compileChainStackViaBackend()` - calls POST /api/chains/compile
- All chain management functions now async and call backend

#### Response Schema

**GET /api/chains:**
```json
{
  "success": true,
  "data": {
    "chains": [
      {
        "id": "file-staging",
        "title": "File Staging",
        "description": "...",
        "icon": "📁",
        "category": "Collection",
        "steps": [...],
        "match_rules": {...},
        "requirements": [...]
      }
    ],
    "count": 8
  }
}
```

**POST /api/chains/compile:**
```json
{
  "success": true,
  "baseline": {
    "type": "stack",
    "chains": [
      {
        "chainId": "file-staging",
        "title": "File Staging",
        "icon": "📁",
        "steps": [...],
        "compiledPlaybookIds": ["signal_file_staging"],
        "stepToPlaybooks": {
          "file-staging-collect": {...},
          "file-staging-stage": {...},
          "file-staging-archive": {...}
        }
      }
    ],
    "baselinePlaybookIds": ["signal_file_staging", "signal_credential_access"]
  },
  "errors": []
}
```

### What Frontend Must NOT Do

1. ❌ Define chain definitions locally
2. ❌ Compile chains to playbooks locally
3. ❌ Compute playbook unions locally
4. ❌ Build stepToPlaybooks mapping locally

### Migration for Old Runs

Not required - chain state is stored in `state.baseline` which is already populated from backend compile responses. Old runs without chain state simply have empty `state.baseline.chains`.

---

## Key Takeaways (5 Bullets)

1. **UI Source vs Served:** Edit `ui/app.js`, then sync to `target/release/ui/` (or run `scripts/sync_ui.ps1`). The server binary reads from `target/release/ui/`, NOT workspace `ui/`.

2. **Single Binary:** `locint.exe` serves both `/ui/*` (static files) and `/api/*` (Axum handlers). No separate frontend server.

3. **Chains Are Backend-Canonical:** As of this session, `crates/server/src/services/chains.rs` is the single source of truth. Frontend calls `GET /api/chains` and `POST /api/chains/compile` - no local chain logic.

4. **Playbooks Are Dynamic:** The `/api/playbooks/catalog` endpoint parses YAML files from `playbooks/windows/` at runtime. Family/tags/requirements come from each YAML file.

5. **LocInt/ Is Stale:** The `LocInt/` folder contains old distribution binaries and UI. Ignore it for development - the working UI is in `ui/` and served from `target/release/ui/`.

---

## File Reference Index

| Component | Canonical Location | Lines |
|-----------|-------------------|-------|
| API Router | crates/server/src/bin/locint.rs | 375-466 |
| Chains Service | crates/server/src/services/chains.rs | 1-564 |
| Chains Handlers | crates/server/src/bin/locint.rs | 7160-7260 |
| UI Source | ui/app.js, ui/index.html | full files |
| UI Served | target/release/ui/ | copied from ui/ |
| Playbooks | playbooks/windows/*.yaml | ~30 files |
| Server Config | crates/server/src/server_core.rs | 60-145 |
| Sync Script | scripts/sync_ui.ps1 | 1-83 |
