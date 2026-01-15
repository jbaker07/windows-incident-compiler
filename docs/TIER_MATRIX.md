# LocInt Tier Matrix

**Version**: 1.0.0  
**Last Updated**: 2026-01-12  
**Applies To**: Windows, macOS (planned), Linux (planned)

This document defines the feature tiers for LocInt across all OS builds, documenting what is implemented today versus what is planned for Free/Pro/Team tiers.

---

## 1. Tier Definitions

| Tier | Target User | Pricing | Deployment |
|------|-------------|---------|------------|
| **Free** | Individual analysts, home users, students | $0 | Single-machine |
| **Pro** | Professional analysts, consultants | Paid (TBD) | Single-machine |
| **Team** | IR teams, MSSPs, enterprise | Paid (TBD) | Multi-user, shared workspace |
| **Dev** | Internal development, debug features | N/A | Debug builds only |

---

## 2. Feature/Tier Matrix

### 2.1 Core Run Workflow

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Start capture run | ✅ Yes | Free | None | `POST /api/run/start` | - |
| Stop capture run | ✅ Yes | Free | None | `POST /api/run/stop` | - |
| Run status polling | ✅ Yes | Free | None | `GET /api/run/status` | - |
| Run metrics | ✅ Yes | Free | None | `GET /api/run/metrics` | - |
| List past runs | ✅ Yes | Free | None | `GET /api/runs` | - |
| Get run details | ✅ Yes | Free | None | `GET /api/runs/:run_id` | - |
| Rename run | ✅ Yes | Free | None | `POST /api/runs/:run_id/rename` | - |
| Delete run | ✅ Yes | Free | None | `POST /api/runs/:run_id/delete` | - |
| Debug counts | ✅ Yes | Dev | UI-only | `GET /api/run/debug_counts` | - |

### 2.2 Capability Model

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Sensor status | ✅ Yes | Free | None | `GET /api/capability/status` | - |
| Detection plan | ✅ Yes | Free | None | `GET /api/capability/detection_plan` | - |
| Coverage gaps analysis | ✅ Yes | Dev | UI-only | `GET /api/capability/gaps` | - |
| Run coverage/facts | ✅ Yes | Free | None | `GET /api/runs/:run_id/coverage` | - |
| System state snapshot | ✅ Yes | Free | None | `GET /api/runs/:run_id/state` | - |

### 2.3 Playbook System

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Playbook catalog | ✅ Yes | Free | None | `GET /api/playbooks/catalog` | - |
| Playbook detail drawer | ✅ Yes | Free | UI-only | (UI component) | - |
| Run-scoped playbook status | ✅ Yes | Free | None | `GET /api/runs/:run_id/playbooks` | - |
| Near-miss detection | ✅ Yes | Free | None | (in playbooks response) | - |
| Validation helper (debug) | ✅ Yes | Dev | UI-only | (UI component, `?debug=1`) | - |

### 2.4 Findings & Signals

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| List signals | ✅ Yes | Free | None | `GET /api/signals` | - |
| Signal details | ✅ Yes | Free | None | `GET /api/signals/:id` | - |
| Signal stats | ✅ Yes | Free | None | `GET /api/signals/stats` | - |
| Explainability stats | ✅ Yes | Free | None | `GET /api/signals/explainability_stats` | - |

### 2.5 ExplainResponse System

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Signal explanation | ✅ Yes | Free | None | `GET /api/signals/:id/explain` | - |
| Explain header | ✅ Yes | Free | None | (in explain response) | - |
| Reason codes | ✅ Yes | Free | None | (in explain response) | - |
| Key fields | ✅ Yes | Free | None | (in explain response) | - |
| Narrative templates | ✅ Yes | Free | None | (in explain response) | - |
| Evidence pointers | ✅ Yes | Free | None | (in explain response) | - |

### 2.6 Evidence Dereference

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Evidence deref API | ✅ Yes | Free | None | `GET /api/evidence/deref` | - |
| Evidence viewer drawer | ✅ Yes | Free | UI-only | (UI component) | - |
| Path safety guardrails | ✅ Yes | Free | None | (backend validation) | - |
| Scan guardrails | ✅ Yes | Free | None | (backend limits) | - |

### 2.7 Next Steps System

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Next steps API | ✅ Yes | Free | None | `GET /api/runs/:run_id/next_steps` | - |
| Next steps UI panel | ✅ Yes | Free | UI-only | (UI component) | - |
| Deep links (search similar) | ✅ Yes | Free | None | (in next_steps response) | - |
| Action templates | ✅ Yes | Free | None | (in next_steps response) | - |

### 2.8 Wiring & Contract

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Route registry | ✅ Yes | Free | None | `GET /api/meta/routes` | - |
| Contract hash | ✅ Yes | Free | None | `GET /api/meta/contract` | - |
| Dataflow snapshot | ✅ Yes | Dev | UI-only | `GET /api/meta/dataflow_snapshot` | - |
| Feature flags | ✅ Yes | Free | None | `GET /api/features` | Needs tier-aware update |

### 2.9 Import/Export

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Export bundle | ✅ Yes | Free | None | `POST /api/export/bundle` | - |
| Import bundle | ✅ Yes | Free | None | `POST /api/import/bundle` | - |
| Imported mode UI | ✅ Yes | Free | UI-only | (UI state) | - |

### 2.10 Reports (Planned)

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| JSON export | ✅ Yes | Free | None | (via export bundle) | - |
| PDF report generation | ❌ No | Pro | Backend flag | (TBD) | Full implementation |
| Custom report templates | ❌ No | Team | License | (TBD) | Full implementation |
| Scheduled reports | ❌ No | Team | License | (TBD) | Full implementation |

### 2.11 Search & Analysis (Planned)

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Search similar in run | ⚠️ Stub | Pro | Backend flag | (deep link only) | Backend search logic |
| Cross-run search | ❌ No | Pro | Backend flag | (TBD) | Full implementation |
| Entity timeline | ❌ No | Pro | Backend flag | (TBD) | Full implementation |

### 2.12 Diff/Changes (Planned)

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Run changes API | ⚠️ Stub | Pro | Backend flag | `GET /api/runs/:run_id/changes` | Diff logic |
| Baseline comparison | ❌ No | Pro | Backend flag | (TBD) | Full implementation |
| Change visualization | ❌ No | Pro | UI-only | (TBD) | UI components |

### 2.13 Integrations (Planned)

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| SIEM export | ❌ No | Team | License | (TBD) | Full implementation |
| Ticketing integration | ❌ No | Team | License | (TBD) | Full implementation |
| API webhooks | ❌ No | Team | License | (TBD) | Full implementation |

### 2.14 Multi-User & Workspace (Planned)

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Notes on findings | ❌ No | Pro | Backend flag | (TBD) | Full implementation |
| Case management | ❌ No | Team | License | (TBD) | Full implementation |
| Multi-run workspace | ❌ No | Team | License | (TBD) | Full implementation |
| User authentication | ❌ No | Team | License | (TBD) | Full implementation |
| Audit log | ❌ No | Team | License | (TBD) | Full implementation |

### 2.15 System & App

| Feature | Implemented | Tier | Gating | Endpoints | Missing Pieces |
|---------|-------------|------|--------|-----------|----------------|
| Health check | ✅ Yes | Free | None | `GET /api/health` | - |
| Selfcheck | ✅ Yes | Free | None | `GET /api/selfcheck` | - |
| App state | ✅ Yes | Free | None | `GET /api/app/state` | - |
| Restart as admin | ✅ Yes | Free | None | `POST /api/app/restart_admin` | - |
| Capture profiles | ✅ Yes | Free | None | `GET /api/capture/profiles` | - |

---

## 3. Tier Summary

### Free Tier (Implemented Today)
All core functionality required for individual incident analysis:
- ✅ Complete run workflow (start/stop/manage)
- ✅ Full capability model (sensors, detection plan)
- ✅ Complete playbook system with near-miss detection
- ✅ Full signal/finding workflow with explanations
- ✅ Evidence dereference with viewer
- ✅ Next steps guidance
- ✅ Import/export bundles
- ✅ Wiring audit & contract validation

### Pro Tier (Planned)
Advanced analysis features for professional use:
- 🔜 PDF report generation
- 🔜 Search similar entities
- 🔜 Cross-run search
- 🔜 Entity timeline
- 🔜 Baseline diff/comparison
- 🔜 Notes on findings

### Team Tier (Planned)
Multi-user and enterprise features:
- 🔜 Case management
- 🔜 Multi-run workspace
- 🔜 User authentication
- 🔜 SIEM integration
- 🔜 Ticketing integration
- 🔜 API webhooks
- 🔜 Custom report templates
- 🔜 Audit log

### Dev Tier (Internal)
Debug and development features (not shipped to users):
- ✅ Debug counts endpoint
- ✅ Gaps analysis endpoint
- ✅ Dataflow snapshot
- ✅ Validation helper (`?debug=1`)

---

## 4. Packaging Decision

### Decision: **Option A — One Download Per OS**

A single download per OS (Windows, macOS, Linux) with license-based tier unlocking.

#### Justification

1. **Simpler Distribution**: One binary per platform reduces SKU sprawl and simplifies downloads, updates, and support documentation.

2. **Frictionless Upgrade Path**: Users can upgrade from Free to Pro/Team by entering a license key without re-downloading or reinstalling.

3. **Truth Constraint Compliance**: Free tier ships with complete, truthful functionality — no demo data, no artificial limitations. Pro/Team features are additive, not unlocked versions of crippled features.

4. **Engineering Simplicity**: Single codebase with feature flags is easier to maintain than multiple build variants. Backend feature checks are centralized.

5. **UX Consistency**: UI can show "Pro" features as locked with clear upgrade CTAs rather than hiding them entirely, educating users about upgrade benefits.

---

## 5. Gating Rules

### 5.1 Gating Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| **None** | Always enabled | Free tier features |
| **UI-only** | UI hides/shows, backend always works | Debug features, dev tools |
| **Backend flag** | Backend checks tier, returns 403 if locked | Pro features |
| **License enforced** | Requires valid license key | Team features |

### 5.2 Backend Gating Implementation

#### Tier Resolution
```
1. Check environment: EDR_LICENSE_KEY or license.json
2. If valid Pro license → tier = "pro"
3. If valid Team license → tier = "team"
4. If dev build (debug symbols) → tier = "dev"
5. Otherwise → tier = "free"
```

#### Feature Flag Endpoint
```
GET /api/meta/features
→ {
    "success": true,
    "data": {
      "tier": "free",
      "tier_display": "Free",
      "features": {
        // Core (always true)
        "run_workflow": true,
        "capability_model": true,
        "playbook_system": true,
        "signals_explain": true,
        "evidence_deref": true,
        "next_steps": true,
        "import_export": true,
        
        // Pro features
        "pdf_reports": false,
        "search_similar": false,
        "cross_run_search": false,
        "entity_timeline": false,
        "baseline_diff": false,
        "notes": false,
        
        // Team features
        "case_management": false,
        "multi_workspace": false,
        "integrations": false,
        "custom_templates": false,
        "audit_log": false,
        
        // Dev features (only in dev builds)
        "debug_endpoints": false,
        "gaps_analysis": false,
        "dataflow_snapshot": false
      },
      "upgrade_url": "https://locint.io/upgrade"
    }
  }
```

#### Locked Endpoint Response
```
HTTP 403 Forbidden
{
  "success": false,
  "error": {
    "code": "FEATURE_LOCKED",
    "message": "PDF reports require Pro tier",
    "required_tier": "pro",
    "current_tier": "free",
    "upgrade_url": "https://locint.io/upgrade"
  }
}
```

### 5.3 UI Gating Implementation

```javascript
// On app init, fetch features
const features = await api('/api/meta/features');

// For locked features, show upgrade prompt
if (!features.data.features.pdf_reports) {
  renderLockedFeature('pdf_reports', features.data.upgrade_url);
}

// Wiring audit classifies locked vs broken
// - LOCKED: Feature flag = false, expected
// - BROKEN: Feature flag = true but endpoint fails
```

### 5.4 Wiring Audit Classification

| State | Feature Flag | Endpoint Status | Classification |
|-------|--------------|-----------------|----------------|
| Working | `true` | 200 OK | ✅ WORKING |
| Locked | `false` | 403 FEATURE_LOCKED | 🔒 LOCKED |
| Broken | `true` | 4xx/5xx (not 403) | ❌ BROKEN |
| Missing | N/A | 404 | ❌ MISSING |

---

## 6. Build/Ship Plan

### Phase 1: Free Tier (Current - Q1 2026)

- [x] Core run workflow
- [x] Capability model
- [x] Playbook system
- [x] Signals & explain
- [x] Evidence dereference
- [x] Next steps
- [x] Import/export
- [x] Wiring audit
- [ ] **Implement `/api/meta/features` endpoint** ← This task
- [ ] **Add 403 FEATURE_LOCKED response helper**
- [ ] **Update wiring audit for locked classification**
- [ ] Windows installer (MSI/MSIX)
- [ ] Documentation site

### Phase 2: Pro Tier (Q2-Q3 2026)

- [ ] License key validation
- [ ] PDF report generation
- [ ] Search similar implementation
- [ ] Entity timeline view
- [ ] Baseline diff
- [ ] Notes on findings
- [ ] macOS build
- [ ] Pro license sales page

### Phase 3: Team Tier (Q4 2026+)

- [ ] User authentication (local accounts or SSO)
- [ ] Case management
- [ ] Multi-run workspace
- [ ] SIEM export adapters
- [ ] Ticketing integration
- [ ] API webhooks
- [ ] Linux build
- [ ] Team license management

---

## 7. OS Build Matrix

| OS | Status | Tier Support | Notes |
|----|--------|--------------|-------|
| **Windows** | ✅ Shipping | Free/Pro/Team | Primary platform |
| **macOS** | 🔜 Planned | Free/Pro/Team | Q2 2026 target |
| **Linux** | 🔜 Planned | Free/Pro/Team | Q3-Q4 2026 target |

Each OS gets a single download. Tier features are identical across platforms (platform-specific sensors may vary).

---

## 8. Appendix: Endpoint Tier Map

Quick reference for backend gating implementation:

```rust
// Free (no gating)
"/api/run/start"           → free
"/api/run/stop"            → free
"/api/run/status"          → free
"/api/runs"                → free
"/api/signals"             → free
"/api/signals/:id/explain" → free
"/api/evidence/deref"      → free
"/api/export/bundle"       → free
"/api/import/bundle"       → free

// Pro (backend flag)
"/api/reports/pdf"         → pro  // TBD
"/api/search/similar"      → pro  // TBD
"/api/timeline/entity"     → pro  // TBD

// Team (license enforced)
"/api/cases"               → team // TBD
"/api/workspace"           → team // TBD
"/api/integrations"        → team // TBD

// Dev (debug builds only)
"/api/run/debug_counts"    → dev
"/api/capability/gaps"     → dev
"/api/meta/dataflow_snapshot" → dev
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-12 | LocInt Team | Initial tier matrix |
