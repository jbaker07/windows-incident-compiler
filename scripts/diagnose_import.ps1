<#
.SYNOPSIS
    Diagnose an import bundle for common issues.
.DESCRIPTION
    Reads the manifest.json the desktop importer (or the import_bundle CLI)
    wrote for a bundle and reports:
    - Summary counts (files, bytes, parsed, events, rejected, warnings)
    - File kind breakdown
    - Files of a parseable kind that were not parsed
    - Parse warnings and rejected files
    - Event types, when the bundle folder has an events.json
    - The import limits that were applied
.PARAMETER BundleId
    The bundle ID (the folder name of the bundle).
.PARAMETER ImportsRoot
    A folder that holds bundle folders directly. When set, the bundle is read
    from <ImportsRoot>\<BundleId>\manifest.json.
.PARAMETER TelemetryRoot
    The telemetry root the desktop app writes to. Used when ImportsRoot is not
    set: the bundle is searched in <TelemetryRoot>\imports and in
    <TelemetryRoot>\runs\*\imports. Defaults to EDR_TELEMETRY_ROOT, then
    C:\ProgramData\edr.
.EXAMPLE
    .\diagnose_import.ps1 -BundleId "bundle_1a20b3da754_f936"
.EXAMPLE
    .\diagnose_import.ps1 -BundleId "bundle_1a20b3da754_f936" -ImportsRoot "testdata\import_bundles"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$BundleId,

    [string]$ImportsRoot = "",

    [string]$TelemetryRoot = $(if ($env:EDR_TELEMETRY_ROOT) { $env:EDR_TELEMETRY_ROOT } else { "C:\ProgramData\edr" })
)

$ErrorActionPreference = "Stop"

# Bundle ids are folder names made by the importer. Refuse anything that could
# walk out of the imports folder.
if ($BundleId -notmatch '^[A-Za-z0-9_.-]+$' -or $BundleId -like '*..*') {
    Write-Host "Invalid bundle id: $BundleId" -ForegroundColor Red
    exit 1
}

# Resolve the bundle folder
$candidates = @()
if ($ImportsRoot) {
    $candidates += Join-Path $ImportsRoot $BundleId
} else {
    $candidates += Join-Path (Join-Path $TelemetryRoot "imports") $BundleId
    $runsDir = Join-Path $TelemetryRoot "runs"
    if (Test-Path $runsDir) {
        Get-ChildItem -Path $runsDir -Directory | ForEach-Object {
            $candidates += Join-Path (Join-Path $_.FullName "imports") $BundleId
        }
    }
}

$bundleDir = $candidates | Where-Object { Test-Path (Join-Path $_ "manifest.json") } | Select-Object -First 1
if (-not $bundleDir) {
    Write-Host "Bundle not found: $BundleId" -ForegroundColor Red
    Write-Host "Looked for manifest.json in:"
    $candidates | ForEach-Object { Write-Host "  $_" }
    exit 1
}

$manifestPath = Join-Path $bundleDir "manifest.json"
$eventsPath = Join-Path $bundleDir "events.json"

# Load manifest
try {
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
} catch {
    Write-Host "Failed to parse manifest.json: $_" -ForegroundColor Red
    exit 1
}

$files = @($manifest.files)
$rejected = @($manifest.rejected)
$warningCount = ($files | ForEach-Object { @($_.warnings).Count } | Measure-Object -Sum).Sum
if (-not $warningCount) { $warningCount = 0 }

# === Summary ===
Write-Host "=== Bundle: $($manifest.bundle_id) ===" -ForegroundColor Cyan
Write-Host "Folder:      $bundleDir"
Write-Host "Imported at: $($manifest.imported_at)"
Write-Host "Run:         $($manifest.run_id)"
Write-Host "Source:      $($manifest.source_type) - $($manifest.source_path)"
Write-Host ""
Write-Host "Files:    $($manifest.summary.total_files)"
Write-Host "Bytes:    $($manifest.summary.total_bytes)"
Write-Host "Parsed:   $($manifest.summary.parsed_files)"
Write-Host "Events:   $($manifest.summary.events_extracted)"
Write-Host "Rejected: $($manifest.summary.rejected_files)"
Write-Host "Warnings: $warningCount"

# === File Kinds ===
Write-Host "`n=== File Kinds ===" -ForegroundColor Cyan
$files | Group-Object kind | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize | Out-String | Write-Host

# === Unparsed Files ===
# Kinds the importer only stores: unknown, pcap and evtx (binary EVTX).
$storedOnly = @("unknown", "pcap", "evtx")
$unparsed = $files | Where-Object { -not $_.parsed -and ($storedOnly -notcontains $_.kind) }
if ($unparsed) {
    Write-Host "=== Files of a parseable kind that were not parsed ===" -ForegroundColor Yellow
    $unparsed | ForEach-Object {
        $warnings = if (@($_.warnings).Count -gt 0) { $_.warnings -join "; " } else { "(no warnings)" }
        Write-Host "  $($_.rel_path) [$($_.kind)] - $warnings" -ForegroundColor Yellow
    }
} else {
    Write-Host "=== All files of a parseable kind were parsed ===" -ForegroundColor Green
}

# === Parse Warnings ===
$filesWithWarnings = $files | Where-Object { @($_.warnings).Count -gt 0 }
if ($filesWithWarnings) {
    Write-Host "`n=== Parse Warnings ===" -ForegroundColor Yellow
    $filesWithWarnings | ForEach-Object {
        Write-Host "  $($_.rel_path):" -ForegroundColor Yellow
        $_.warnings | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkYellow }
    }
}

# === Rejected Files ===
if ($rejected.Count -gt 0) {
    Write-Host "`n=== Rejected Files ===" -ForegroundColor Red
    $rejected | ForEach-Object {
        Write-Host "  $($_.rel_path): $($_.reason) $($_.message)" -ForegroundColor Red
    }
}

# === Event Types ===
if (Test-Path $eventsPath) {
    Write-Host "`n=== Event Types ===" -ForegroundColor Cyan
    try {
        $events = Get-Content $eventsPath -Raw | ConvertFrom-Json
        if ($events -is [array]) {
            $events | Group-Object event_type | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize | Out-String | Write-Host
        } else {
            Write-Host "  (events.json is not an array)" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  (failed to parse events.json: $_)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "`n=== No events.json in the bundle folder ===" -ForegroundColor DarkGray
}

# === Limits Applied ===
Write-Host "`n=== Import Limits ===" -ForegroundColor Cyan
Write-Host "  Max total bytes:       $($manifest.limits.max_total_bytes)"
Write-Host "  Max files:             $($manifest.limits.max_files)"
Write-Host "  Max depth:             $($manifest.limits.max_depth)"
Write-Host "  Max single file bytes: $($manifest.limits.max_single_file_bytes)"
Write-Host "  Max compression ratio: $($manifest.limits.max_compression_ratio)"
Write-Host "  Max lines per file:    $($manifest.limits.max_lines_per_file)"

Write-Host "`n=== Diagnosis Complete ===" -ForegroundColor Green
exit 0
