# Unsupported Playbooks (Tag-Based)

These playbooks are **quarantined** because they use `tag:` conditions in their rules,
which the current slot-matching engine does not support.

## Why They Don't Work

The slot matcher (`slot_matcher.rs`) builds detection slots from playbook rules.
It only processes `fact_type:` conditions, not `tag:` conditions:

```rust
// In build_slots_from_yaml():
if let YamlCondition::FieldMatch { fact_type, field, matches, .. } = cond {
    if let Some(ft) = fact_type {  // <-- Only handles fact_type, ignores tag
        // ... build slot
    }
}
```

These playbooks define rules like:
```yaml
conditions:
  - tag: "service_install"   # <-- Not processed! No slots built.
```

## Quarantined Playbooks

| Playbook | Original Purpose |
|----------|------------------|
| signal_group_membership_change.yaml | Detect admin group changes |
| signal_lateral_movement_detection.yaml | Detect lateral movement |
| signal_log_tamper_detection.yaml | Detect log tampering |
| signal_log_tampering.yaml | Detect log tampering (alt) |
| signal_process_injection.yaml | Detect process injection |
| signal_registry_persistence.yaml | Detect registry persistence |
| signal_service_persistence.yaml | Detect malicious services |
| signal_task_persistence.yaml | Detect scheduled task persistence |

## To Fix

Option A: Convert tag conditions to fact_type + field match:
```yaml
# Instead of:
conditions:
  - tag: "service_install"

# Use:
conditions:
  - fact_type: PersistArtifact
  - field: artifact_type
    matches: "service"
```

Option B: Implement tag-to-fact-type translation in `build_slots_from_yaml()`.

## Accounting

Before quarantine: 30 total YAML files, 22 loaded, 8 skipped (TAG_BASED_UNSUPPORTED)
After quarantine: 22 total YAML files, 22 loaded, 0 skipped

---
Quarantined: 2026-01-10 by Architecture Audit AGENT 2
