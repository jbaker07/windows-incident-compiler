# Import System Troubleshooting Checklist

> **Note**: This document covers the **UI Import pipeline** (Tauri desktop app / `import_bundle` CLI).
> For backend integrations (Wazuh/Zeek live ingestion), see `crates/locald/src/integrations/`.
> For a full map of both pipelines, see [IMPORT_PIPELINE_MAP.md](IMPORT_PIPELINE_MAP.md).

When imports fail silently or produce unexpected results, check these common failure modes in order.

---

## 🔴 Failure Mode 1: FileKind Misclassification

**Symptom**: File shows `parsed: false` or wrong adapter used

### Checklist

```
□ Check manifest.json for the file's detected `kind`
□ Verify filename matches expected pattern in FileKind::detect()
□ Check file content starts with expected magic bytes/structure
□ Confirm file extension is in the parseable list
```

### Where to Look

| Check | Location |
|-------|----------|
| Detection logic | `src-tauri/src/import_types.rs` → `FileKind::detect()` |
| Parseable check | `src-tauri/src/import_types.rs` → `is_parseable()` |
| Adapter matching | `src-tauri/src/adapters/mod.rs` → `can_handle()` |

### Common Fixes

```rust
// FileKind::detect() - Add new pattern
if name.contains("custom_tool") && ext == "json" {
    return FileKind::CustomTool;
}

// is_parseable() - Don't forget to add new kinds
FileKind::CustomTool => true,

// Adapter::can_handle() - Must match FileKind
fn can_handle(&self, file: &ManifestFile) -> bool {
    matches!(file.kind, FileKind::CustomTool)
}
```

### Debug Command

```powershell
# Check what FileKind was detected for each file
Get-Content imports/*/manifest.json | ConvertFrom-Json | 
  Select-Object -ExpandProperty files | 
  Select-Object rel_path, kind, parsed, parser
```

---

## 🟠 Failure Mode 2: Entity Key Mismatch

**Symptom**: Events exist but playbooks don't correlate them (no signals from related events)

### Checklist

```
□ Compare entity key formats between adapters producing related events
□ Verify IP addresses are normalized (no leading zeros, consistent IPv4/IPv6)
□ Check hostname casing (should be lowercase)
□ Confirm process keys include expected fields (pid, name, path)
□ Verify file keys use consistent path separators
```

### Entity Key Contracts

| Key Type | Required Format | Example |
|----------|-----------------|---------|
| `net_key` | `{src_ip}:{src_port}->{dest_ip}:{dest_port}` | `192.168.1.10:54321->10.0.0.5:443` |
| `host_key` | `{ip}` or `{hostname}` (lowercase) | `192.168.1.10` or `webserver01` |
| `proc_key` | `{hostname}:{pid}:{name}` | `host1:1234:cmd.exe` |
| `file_key` | `{hostname}:{path}` (normalized) | `host1:c:/windows/temp/mal.exe` |
| `identity_key` | `{domain}\\{user}` or `{user}` | `CORP\\jsmith` |
| `url_key` | `{scheme}://{host}{path}` | `https://evil.com/shell.php` |
| `domain_key` | `{domain}` (lowercase, no trailing dot) | `evil.com` |

### Where to Look

| Check | Location |
|-------|----------|
| Key constructors | `src-tauri/src/import_types.rs` → `EntityKey::*_key()` |
| Adapter key generation | Each adapter's event building code |
| Playbook correlation | `playbooks/import/*.yaml` → `correlation.group_by` |

### Debug Command

```powershell
# Extract entity keys from events to check consistency
Get-Content imports/*/events.json | ConvertFrom-Json |
  ForEach-Object { $_.fields | Get-Member -MemberType NoteProperty } |
  Where-Object Name -match "key|ip|host" |
  Select-Object -Unique Name
```

---

## 🟡 Failure Mode 3: Event Type Mapping Drift

**Symptom**: Events parse successfully but playbooks don't trigger

### Checklist

```
□ Verify adapter outputs event_type matching playbook trigger
□ Check CanonicalEventType enum has the type
□ Confirm playbook trigger.required_events.type matches exactly
□ Look for typos in event_type strings (case-sensitive)
```

### Event Type Contract

| Adapter | Must Output | Playbook Expects |
|---------|-------------|------------------|
| nmap | `host_discovered`, `port_discovered` | `host_discovered`, `port_discovered` |
| suricata | `net_alert`, `dns_query`, `http_txn` | `net_alert` |
| yara | `yara_match` | `yara_match` |
| zap | `web_vulnerability` | `web_vulnerability` |
| atomic | `technique_executed` | `technique_executed` |
| evtx_json | `logon_success`, `process_create`, etc. | Windows event types |
| osquery | `process_info`, `user_info`, `listening_port` | Same |

### Where to Look

| Check | Location |
|-------|----------|
| Canonical types | `src-tauri/src/import_types.rs` → `CanonicalEventType` |
| Adapter output | Each adapter's `event_type:` assignment |
| Playbook triggers | `playbooks/import/*.yaml` → `trigger.required_events` |

### Debug Command

```powershell
# List all event types produced by import
Get-Content imports/*/events.json | ConvertFrom-Json |
  Group-Object event_type | 
  Select-Object Name, Count | 
  Sort-Object Count -Descending

# Check what playbooks expect
Get-ChildItem playbooks/import/*.yaml | ForEach-Object {
  $content = Get-Content $_ -Raw
  if ($content -match "type:\s*(\w+)") { $Matches[1] }
} | Sort-Object -Unique
```

---

## 🟢 Failure Mode 4: Playbook Slot Predicate Mismatch

**Symptom**: Events match type but signal doesn't fire or has empty fields

### Checklist

```
□ Verify event fields contain keys referenced in playbook
□ Check field value types match predicates (string vs number)
□ Confirm array fields are actually arrays (not comma-separated strings)
□ Look for null/undefined fields that playbook assumes exist
```

### Field Contract Examples

| Playbook Expects | Adapter Must Provide |
|------------------|---------------------|
| `fields.ip` | `fields.insert("ip", json!(ip_str))` |
| `fields.port` as number | `fields.insert("port", json!(port_u16))` not `json!("80")` |
| `fields.tags` as array | `fields.insert("tags", json!(vec!["a","b"]))` |
| `fields.severity` | Value in expected range (1-3 or "low"/"medium"/"high") |

### Where to Look

| Check | Location |
|-------|----------|
| Playbook field refs | `playbooks/import/*.yaml` → `fields:`, `explanation:` |
| Adapter field output | Each adapter's `fields.insert()` calls |
| Signal field mapping | `signal_template.fields` in playbooks |

### Debug Command

```powershell
# Check what fields an event type actually has
Get-Content imports/*/events.json | ConvertFrom-Json |
  Where-Object event_type -eq "yara_match" |
  Select-Object -First 1 -ExpandProperty fields |
  Get-Member -MemberType NoteProperty |
  Select-Object Name

# Compare with playbook expectations
Get-Content playbooks/import/yara_malware_detection.yaml |
  Select-String -Pattern "fields\." -AllMatches |
  ForEach-Object { $_.Matches.Value } |
  Sort-Object -Unique
```

---

## 🔵 Failure Mode 5: Adapter Parse Errors

**Symptom**: `warnings` array in manifest has entries, `events_extracted: 0`

### Checklist

```
□ Check manifest.json warnings for specific error messages
□ Verify file encoding (UTF-8 expected)
□ Look for malformed JSON/XML/CSV in source file
□ Check for BOM (byte order mark) at file start
□ Verify line endings (CRLF vs LF issues)
```

### Common Parse Errors

| Error | Cause | Fix |
|-------|-------|-----|
| "JSON parse error line X" | Malformed JSON | Check source file syntax |
| "XML parse error" | Invalid XML structure | Validate with xmllint |
| "Missing required field" | Schema mismatch | Check adapter's expected format |
| "Timestamp parse failed" | Unknown date format | Add format to `parse_timestamp()` |
| "UTF-8 decode error" | Non-UTF8 encoding | Convert file or handle encoding |

### Debug Command

```powershell
# Check for parse warnings
Get-Content imports/*/manifest.json | ConvertFrom-Json |
  Select-Object -ExpandProperty files |
  Where-Object { $_.warnings.Count -gt 0 } |
  Select-Object rel_path, warnings
```

---

## 🟣 Failure Mode 6: Import Limits Exceeded

**Symptom**: Partial import, truncated events, or rejection

### Checklist

```
□ Check total bundle size (< 2GB default)
□ Count total files (< 50,000 default)
□ Check max depth (< 16 levels default)
□ Verify individual file sizes
□ Look for blocked extensions (.exe, .dll, .ps1)
```

### Default Limits

| Limit | Default | Config Location |
|-------|---------|-----------------|
| Max bundle size | 2 GB | `ImportLimits::max_total_bytes` |
| Max files | 50,000 | `ImportLimits::max_files` |
| Max depth | 16 | `ImportLimits::max_depth` |
| Max events/file | 100,000 | `ImportLimits::max_events` |
| Blocked extensions | exe,dll,ps1,bat,... | `SafeImporter::BLOCKED_EXTENSIONS` |

### Debug Command

```powershell
# Check bundle stats
Get-Content imports/*/manifest.json | ConvertFrom-Json |
  Select-Object bundle_id, @{N='files';E={$_.summary.total_files}}, 
    @{N='bytes';E={$_.summary.total_bytes}},
    @{N='rejected';E={$_.summary.rejected_files}}
```

---

## Quick Diagnostic Script

Save as `diagnose_import.ps1`:

```powershell
param([string]$BundleId)

$manifestPath = "imports/$BundleId/manifest.json"
if (-not (Test-Path $manifestPath)) {
    Write-Error "Bundle not found: $BundleId"
    exit 1
}

$manifest = Get-Content $manifestPath | ConvertFrom-Json

Write-Host "=== Bundle: $BundleId ===" -ForegroundColor Cyan
Write-Host "Files: $($manifest.summary.total_files)"
Write-Host "Parsed: $($manifest.summary.parsed_files)"
Write-Host "Events: $($manifest.summary.events_extracted)"
Write-Host "Rejected: $($manifest.summary.rejected_files)"
Write-Host "Warnings: $($manifest.summary.warnings_count)"

Write-Host "`n=== File Types ===" -ForegroundColor Cyan
$manifest.files | Group-Object kind | Sort-Object Count -Descending | Format-Table Name, Count

Write-Host "`n=== Unparsed Files ===" -ForegroundColor Yellow
$manifest.files | Where-Object { -not $_.parsed -and $_.kind -ne "Unknown" } | 
  Select-Object rel_path, kind, @{N='warnings';E={$_.warnings -join '; '}} | Format-Table

Write-Host "`n=== Parse Warnings ===" -ForegroundColor Yellow
$manifest.files | Where-Object { $_.warnings.Count -gt 0 } |
  ForEach-Object { Write-Host "$($_.rel_path): $($_.warnings -join ', ')" }

$eventsPath = "imports/$BundleId/events.json"
if (Test-Path $eventsPath) {
    Write-Host "`n=== Event Types ===" -ForegroundColor Cyan
    Get-Content $eventsPath | ConvertFrom-Json |
      Group-Object event_type | Sort-Object Count -Descending | Format-Table Name, Count
}
```

Usage: `.\diagnose_import.ps1 -BundleId "bundle_20250105_123456"`

---

## Adding New Adapters Checklist

When adding support for a new tool:

```
□ 1. Add FileKind variant to import_types.rs
□ 2. Add detection pattern to FileKind::detect()
□ 3. Add kind to is_parseable() (return true)
□ 4. Create adapter file in src-tauri/src/adapters/
□ 5. Implement Adapter trait (name, can_handle, parse)
□ 6. Register in adapters/mod.rs (pub mod + AdapterRegistry::new)
□ 7. Use canonical event types from CanonicalEventType
□ 8. Use EntityKey constructors for correlation keys
□ 9. Add to grounded_gates.rs is_parseable_kind()
□ 10. Update README.md import matrix
□ 11. (Optional) Create playbook in playbooks/import/
□ 12. Test with real tool output
```

---

## See Also

- [IMPORT_PIPELINE_MAP.md](IMPORT_PIPELINE_MAP.md) - Two-pipeline architecture overview
- [IMPORT_ARCHITECTURE.md](IMPORT_ARCHITECTURE.md) - System design
- [README.md](../README.md#-evidence-import) - Format matrix
- `src-tauri/src/import_types.rs` - Canonical model (UI import)
- `src-tauri/src/adapters/` - UI import adapter implementations
- `crates/locald/src/integrations/` - Backend live ingestion (different pipeline)
