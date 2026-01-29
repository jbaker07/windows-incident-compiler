# sync_ui.ps1 - Sync UI files from workspace root to target/release/ui
# IMPORTANT: The locint server serves from target/release/ui/, NOT workspace ui/
# Run this script after editing UI files to see changes in the browser!

param(
    [switch]$Watch,  # Watch for changes and auto-sync
    [switch]$Help
)

if ($Help) {
    Write-Host "Usage: .\scripts\sync_ui.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Watch    Watch for changes and auto-sync (requires Ctrl+C to stop)"
    Write-Host ""
    Write-Host "This script copies UI files from workspace root ui/ to target/release/ui/"
    Write-Host "where the locint server serves them from."
    exit 0
}

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$SourceDir = Join-Path $ProjectRoot "ui"
$TargetDir = Join-Path $ProjectRoot "target\release\ui"

function Sync-UiFiles {
    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
        Write-Host "Created target directory: $TargetDir"
    }
    
    Copy-Item -Path "$SourceDir\*" -Destination $TargetDir -Force -Recurse
    
    # Extract BUILD_STAMP for verification
    $appJs = Get-Content "$TargetDir\app.js" -TotalCount 30 -Raw
    if ($appJs -match "BUILD_STAMP = '([^']+)'") {
        $stamp = $matches[1]
        Write-Host "✅ Synced UI files (BUILD_STAMP: $stamp)" -ForegroundColor Green
    } else {
        Write-Host "✅ Synced UI files" -ForegroundColor Green
    }
}

Write-Host "=== UI Sync Tool ===" -ForegroundColor Cyan
Write-Host "Source: $SourceDir"
Write-Host "Target: $TargetDir"
Write-Host ""

if ($Watch) {
    Write-Host "Watching for changes (Ctrl+C to stop)..." -ForegroundColor Yellow
    
    # Initial sync
    Sync-UiFiles
    
    # Watch for changes
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $SourceDir
    $watcher.Filter = "*.*"
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true
    
    $action = {
        Start-Sleep -Milliseconds 500  # Debounce
        & Sync-UiFiles
    }
    
    Register-ObjectEvent $watcher "Changed" -Action $action | Out-Null
    Register-ObjectEvent $watcher "Created" -Action $action | Out-Null
    Register-ObjectEvent $watcher "Renamed" -Action $action | Out-Null
    
    try {
        while ($true) { Start-Sleep -Seconds 1 }
    } finally {
        $watcher.Dispose()
        Write-Host "Stopped watching."
    }
} else {
    # One-time sync
    Sync-UiFiles
}
