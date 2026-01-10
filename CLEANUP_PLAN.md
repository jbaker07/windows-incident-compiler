# Cleanup Plan - 2026-01-09

## Summary

This document classifies all files for cleanup action.

---

## ROOT LEVEL MARKDOWN FILES

| Path | Type | Referenced By | Decision | Reason |
|------|------|---------------|----------|--------|
| `README.md` | doc | -- (root) | **KEEP** | Primary documentation |
| `CHANGELOG.md` | doc | self, standard | **KEEP** | Release history |
| `SHIP_CHECKLIST.md` | doc | self only | **ARCHIVE** | Useful for history, not actively linked |
| `GROUNDED_GATES_RUNBOOK.md` | doc | none | **ARCHIVE** | Historical dev runbook, not linked |
| `RUNBOOK_VERIFY.md` | doc | none | **ARCHIVE** | Historical dev runbook, not linked |

---

## docs/ DIRECTORY

| Path | Type | Referenced By | Decision | Reason |
|------|------|---------------|----------|--------|
| `docs/LICENSING.md` | doc | 16 refs (README, workflows, code) | **KEEP** | Critical licensing doc |
| `docs/SHIPPING.md` | doc | 10 refs | **KEEP** | Release process doc |
| `docs/playbooks_windows_coverage.md` | doc | 5 refs (README) | **KEEP** | Linked from README |
| `docs/facts_windows.md` | doc | 3 refs (README) | **KEEP** | Linked from README |
| `docs/ui_workflow.md` | doc | 2 refs (README) | **KEEP** | Linked from README |
| `docs/SMOKE_CHECKLIST_LICENSING.md` | doc | 1 ref (LICENSING.md) | **KEEP** | Referenced by critical doc |
| `docs/IMPORT_ARCHITECTURE.md` | doc | 1 ref (IMPORT_TROUBLESHOOTING) | **KEEP** | Import system design |
| `docs/IMPORT_PIPELINE_MAP.md` | doc | 2 refs | **KEEP** | Import pipeline reference |
| `docs/IMPORT_TROUBLESHOOTING.md` | doc | 0 refs (but references others) | **KEEP** | Import docs cluster |
| `docs/DESKTOP_ARCHITECTURE.md` | doc | 0 refs | **ARCHIVE** | Useful but not linked |
| `docs/explainability_inventory.md` | doc | 0 refs | **ARCHIVE** | Useful but not linked |
| `docs/MISSION_REAL_TELEMETRY.md` | doc | 0 refs (NEW) | **KEEP** | New Mission workflow doc |
| `docs/MISSION_UI_WORKFLOW.md` | doc | 0 refs (NEW) | **KEEP** | New Mission workflow doc |
| `docs/MISSION_WORKFLOW_WALKTHROUGH.md` | doc | 0 refs (NEW) | **KEEP** | New Mission workflow doc |
| `docs/schemas/*.json` | schema | code validation | **KEEP** | JSON schemas for artifacts |

---

## scripts/ DIRECTORY

| Path | Type | Referenced By | Decision | Reason |
|------|------|---------------|----------|--------|
| `scripts/run_stack_windows.ps1` | script | 29 refs (README, docs) | **KEEP** | Primary Windows stack script |
| `scripts/enable_advanced_telemetry.ps1` | script | 18 refs (README) | **KEEP** | Telemetry setup |
| `scripts/eval_windows.ps1` | script | 12 refs | **KEEP** | E2E evaluation |
| `scripts/diagnose_import.ps1` | script | 4 refs | **KEEP** | Import debugging |
| `scripts/smoke_stack.ps1` | script | 4 refs | **KEEP** | Smoke test |
| `scripts/verify_explainability.ps1` | script | 4 refs | **KEEP** | Explainability verification |
| `scripts/e2e_explainability_verify.ps1` | script | 3 refs | **KEEP** | E2E verify |
| `scripts/quick_explain_check.ps1` | script | 3 refs | **KEEP** | Quick explain check |
| `scripts/verify_narration.ps1` | script | 1 ref (self) | **ARCHIVE** | May be stale, only self-ref |

---

## dist/ DIRECTORY (ACCIDENTAL COMMIT)

| Path | Type | Referenced By | Decision | Reason |
|------|------|---------------|----------|--------|
| `dist/*.exe` | binary | none | **DELETE** | Binaries should NOT be in git |
| `dist/ui/*` | build | none | **DELETE** | Build artifacts should NOT be in git |
| `dist/README.md` | doc | none | **DELETE** | Part of dist bundle |
| `dist/LICENSING.md` | doc | none | **DELETE** | Duplicate of docs/ version |

---

## .github/ DIRECTORY

| Path | Type | Referenced By | Decision | Reason |
|------|------|---------------|----------|--------|
| `.github/workflows/ci.yml` | workflow | CI | **KEEP** | CI pipeline |
| `.github/workflows/release.yml` | workflow | release | **KEEP** | Release pipeline |
| `.github/PULL_REQUEST_TEMPLATE.md` | template | GitHub | **KEEP** | PR template |

---

## testdata/ DIRECTORY

| Path | Type | Referenced By | Decision | Reason |
|------|------|---------------|----------|--------|
| `testdata/imports/*` | test data | import tests | **KEEP** | Test fixtures |

---

## test_e2e/ DIRECTORY

| Path | Type | Referenced By | Decision | Reason |
|------|------|---------------|----------|--------|
| `test_e2e/index.json` | test data | tests | **KEEP** | Test fixture |

---

## README BROKEN LINKS TO FIX

The README references docs that don't exist:
- `docs/VM_BRINGUP.md` - **REMOVE LINK**
- `docs/PUSH_CHECKLIST.md` - **REMOVE LINK**
- `BASELINE_SYSTEM_DESIGN.md` - **REMOVE LINK**

---

## ACTIONS SUMMARY

### Files to ARCHIVE (move to docs/archive/)

1. `SHIP_CHECKLIST.md` → `docs/archive/SHIP_CHECKLIST.md`
2. `GROUNDED_GATES_RUNBOOK.md` → `docs/archive/GROUNDED_GATES_RUNBOOK.md`
3. `RUNBOOK_VERIFY.md` → `docs/archive/RUNBOOK_VERIFY.md`
4. `docs/DESKTOP_ARCHITECTURE.md` → `docs/archive/DESKTOP_ARCHITECTURE.md`
5. `docs/explainability_inventory.md` → `docs/archive/explainability_inventory.md`
6. `scripts/verify_narration.ps1` → `scripts/archive/verify_narration.ps1`

### Files to DELETE

1. `dist/` entire directory - binaries and build artifacts should not be in git

### Links to FIX in README.md

Remove these broken links:
- `docs/VM_BRINGUP.md`
- `docs/PUSH_CHECKLIST.md`
- `BASELINE_SYSTEM_DESIGN.md`

---

## VERIFICATION

After cleanup:
- [ ] `cargo fmt -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo build --release` passes
- [ ] `cargo test --workspace --release` passes
- [ ] All docs links in README resolve
- [ ] `git status` shows clean working tree
