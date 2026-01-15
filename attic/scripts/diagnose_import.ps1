<#
.SYNOPSIS
    Diagnose an import bundle for common issues.

.DESCRIPTION
    Reads manifest.json and events.json from an import bundle and reports:
    - Summary counts (files, parsed, events, rejected, warnings)
    - File type breakdown by FileKind
    - Unparsed files that should have been parsed
    - Parse warnings
    - Event type histogram

.PARAMETER BundleId
    The bundle ID (folder name under imports/)

.PARAMETER ImportsRoot
    Root directory containing import bundles. Default: imports/

.EXAMPLE
    .\diagnose_import.ps1 -BundleId "bundle_20250105_123456"
    
.EXAMPLE
    .\diagnose_import.ps1 -BundleId "bundle_20250105_123456" -ImportsRoot "C:\edr\imports"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$BundleId,
    
    [string]$ImportsRoot = "imports"
)

$ErrorActionPreference = "Stop"

# Resolve paths
$manifestPath = Join-Path $ImportsRoot $BundleId "manifest.json"
$eventsPath = Join-Path $ImportsRoot $BundleId "events.json"

if (-not (Test-Path $manifestPath)) {
    Write-Error "Bundle not found: $BundleId (looked for $manifestPath)"
    exit 1
}

# Load manifest
try {
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
} catch {
    Write-Error "Failed to parse manifest.json: $_"
    exit 1
}

# === Summary ===
Write-Host "=== Bundle: $BundleId ===" -ForegroundColor Cyan
Write-Host "Imported At: $($manifest.imported_at)"
Write-Host "Source: $($manifest.source_type) - $($manifest.source_path)"
Write-Host ""
Write-Host "Files: $($manifest.summary.total_files)"
Write-Host "Parsed: $($manifest.summary.parsed_files)"
Write-Host "Events: $($manifest.summary.events_extracted)"
Write-Host "Rejected: $($manifest.summary.rejected_files)"
Write-Host "Warnings: $($manifest.summary.warnings_count)"

# === File Types ===
Write-Host "`n=== File Types ===" -ForegroundColor Cyan
$manifest.files | Group-Object kind | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize

# === Unparsed Files ===
$unparsed = $manifest.files | Where-Object { 
    -not $_.parsed -and $_.kind -ne "Unknown" -and $_.kind -ne "Pcap" -and $_.kind -ne "Evtx"
}
if ($unparsed) {
    Write-Host "`n=== Unparsed Files (potential issues) ===" -ForegroundColor Yellow
    $unparsed | ForEach-Object {
        $warnings = if ($_.warnings) { $_.warnings -join "; " } else { "(no warnings)" }
        Write-Host "  $($_.rel_path) [$($_.kind)] - $warnings" -ForegroundColor Yellow
    }
} else {
    Write-Host "`n=== All parseable files were parsed ===" -ForegroundColor Green
}

# === Parse Warnings ===
$filesWithWarnings = $manifest.files | Where-Object { $_.warnings -and $_.warnings.Count -gt 0 }
if ($filesWithWarnings) {
    Write-Host "`n=== Parse Warnings ===" -ForegroundColor Yellow
    $filesWithWarnings | ForEach-Object {
        Write-Host "  $($_.rel_path):" -ForegroundColor Yellow
        $_.warnings | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkYellow }
    }
}

# === Rejected Files ===
if ($manifest.rejected -and $manifest.rejected.Count -gt 0) {
    Write-Host "`n=== Rejected Files ===" -ForegroundColor Red
    $manifest.rejected | ForEach-Object {
        Write-Host "  $($_.path): $($_.reason)" -ForegroundColor Red
    }
}

# === Event Types ===
if (Test-Path $eventsPath) {
    Write-Host "`n=== Event Types ===" -ForegroundColor Cyan
    try {
        $events = Get-Content $eventsPath -Raw | ConvertFrom-Json
        if ($events -is [array]) {
            $events | Group-Object event_type | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize
        } else {
            Write-Host "  (events.json is not an array)" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  (failed to parse events.json: $_)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "`n=== No events.json found ===" -ForegroundColor DarkGray
}

# === Limits Applied ===
Write-Host "`n=== Import Limits ===" -ForegroundColor Cyan
Write-Host "  Max total bytes: $($manifest.limits.max_total_bytes)"
Write-Host "  Max files: $($manifest.limits.max_files)"
Write-Host "  Max depth: $($manifest.limits.max_depth)"
Write-Host "  Max events: $($manifest.limits.max_events)"

Write-Host "`n=== Diagnosis Complete ===" -ForegroundColor Green
