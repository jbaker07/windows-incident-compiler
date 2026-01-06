# quick_explain_check.ps1
# Quick one-liner to verify a specific signal's explanation
#
# Usage:
#   .\scripts\quick_explain_check.ps1 -SignalId "abc123..."
#   .\scripts\quick_explain_check.ps1  # fetches first signal automatically

param(
    [string]$ServerUrl = "http://127.0.0.1:3000",
    [string]$SignalId = ""
)

$ErrorActionPreference = "Stop"

Write-Host "Explainability Quick Check" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# If no signal ID provided, fetch the first one
if (-not $SignalId) {
    Write-Host "Fetching signals..." -ForegroundColor DarkGray
    $resp = Invoke-RestMethod -Uri "$ServerUrl/api/signals?limit=1" -Method Get
    if (-not $resp.success -or -not $resp.data -or $resp.data.Count -eq 0) {
        Write-Host "No signals found. Generate some telemetry first!" -ForegroundColor Yellow
        exit 1
    }
    $SignalId = $resp.data[0].signal_id
    Write-Host "Using signal: $SignalId" -ForegroundColor DarkGray
}

# Fetch explanation
Write-Host ""
Write-Host "Fetching explanation for signal: $($SignalId.Substring(0, [Math]::Min(24, $SignalId.Length)))..." -ForegroundColor DarkGray
$expResp = Invoke-RestMethod -Uri "$ServerUrl/api/signals/$SignalId/explain" -Method Get

if (-not $expResp.success) {
    Write-Host "✗ No explanation available: $($expResp.error)" -ForegroundColor Red
    exit 1
}

$exp = $expResp.data

Write-Host ""
Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "│ EXPLANATION BUNDLE                                          │" -ForegroundColor DarkCyan
Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "Signal:     $($exp.signal_id.Substring(0, [Math]::Min(32, $exp.signal_id.Length)))..."
Write-Host "Playbook:   $($exp.playbook_id)" -ForegroundColor Green
Write-Host "Title:      $($exp.playbook_title)"
Write-Host "Family:     $($exp.family)"
Write-Host ""

# Summary
if ($exp.summary) {
    Write-Host "Summary:" -ForegroundColor Yellow
    Write-Host "  $($exp.summary)"
    Write-Host ""
}

# Slots
Write-Host "Slots ($($exp.slots.Count)):" -ForegroundColor Yellow
foreach ($slot in $exp.slots) {
    $statusColor = switch ($slot.status) {
        "filled" { "Green" }
        "partial" { "Yellow" }
        "expired" { "DarkGray" }
        default { "Red" }
    }
    $req = if ($slot.required) { "[REQ]" } else { "[OPT]" }
    $factCount = if ($slot.matched_facts) { $slot.matched_facts.Count } else { 0 }
    Write-Host "  $req $($slot.name): " -NoNewline
    Write-Host "$($slot.status)" -ForegroundColor $statusColor -NoNewline
    Write-Host " ($factCount facts)"
}
Write-Host ""

# Evidence
$evidenceCount = if ($exp.evidence) { $exp.evidence.Count } else { 0 }
Write-Host "Evidence ($evidenceCount):" -ForegroundColor Yellow
if ($exp.evidence) {
    foreach ($ev in $exp.evidence | Select-Object -First 3) {
        Write-Host "  $($ev.ptr.stream_id):$($ev.ptr.segment_id):$($ev.ptr.record_index)" -ForegroundColor Cyan
        Write-Host "    Source: $($ev.source)"
        if ($ev.excerpt) {
            $excerpt = $ev.excerpt
            if ($excerpt.Length -gt 80) { $excerpt = $excerpt.Substring(0, 80) + "..." }
            Write-Host "    Excerpt: $excerpt" -ForegroundColor DarkGray
        }
    }
    if ($exp.evidence.Count -gt 3) {
        Write-Host "  ... and $($exp.evidence.Count - 3) more"
    }
}
Write-Host ""

# Entities
Write-Host "Entities:" -ForegroundColor Yellow
$entities = $exp.entities
if ($entities) {
    if ($entities.proc_keys -and $entities.proc_keys.Count -gt 0) {
        Write-Host "  Processes: $($entities.proc_keys -join ', ')"
    }
    if ($entities.file_keys -and $entities.file_keys.Count -gt 0) {
        Write-Host "  Files: $($entities.file_keys -join ', ')"
    }
    if ($entities.identity_keys -and $entities.identity_keys.Count -gt 0) {
        Write-Host "  Users: $($entities.identity_keys -join ', ')"
    }
    if ($entities.net_keys -and $entities.net_keys.Count -gt 0) {
        Write-Host "  Network: $($entities.net_keys -join ', ')"
    }
    if ($entities.registry_keys -and $entities.registry_keys.Count -gt 0) {
        Write-Host "  Registry: $($entities.registry_keys -join ', ')"
    }
}
Write-Host ""

# Counters
if ($exp.counters) {
    Write-Host "Counters:" -ForegroundColor Yellow
    Write-Host "  Required slots: $($exp.counters.required_slots_filled)/$($exp.counters.required_slots_total) filled"
    Write-Host "  Optional slots: $($exp.counters.optional_slots_filled)/$($exp.counters.optional_slots_total) filled"
    Write-Host "  Facts emitted:  $($exp.counters.facts_emitted)"
}
Write-Host ""

# Limitations
if ($exp.limitations -and $exp.limitations.Count -gt 0) {
    Write-Host "Limitations:" -ForegroundColor Red
    foreach ($lim in $exp.limitations) {
        Write-Host "  ⚠ $lim" -ForegroundColor Yellow
    }
    Write-Host ""
}

Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "✓ Explanation bundle is valid" -ForegroundColor Green
