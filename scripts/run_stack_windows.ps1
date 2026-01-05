# run_stack_windows.ps1 - Start EDR stack on Windows
# Requires: cargo, Administrator access for capture
#
# Usage:
#   .\scripts\run_stack_windows.ps1              # Build and run
#   .\scripts\run_stack_windows.ps1 -NoBuild     # Run pre-built binaries
#   .\scripts\run_stack_windows.ps1 -Verify      # Run E2E verification then exit

param(
    [switch]$NoBuild,
    [switch]$Verify,
    [switch]$Help
)

if ($Help) {
    Write-Host "Usage: .\run_stack_windows.ps1 [-NoBuild] [-Verify]"
    Write-Host "  -NoBuild  Skip cargo build, use pre-built binaries"
    Write-Host "  -Verify   Run E2E verification (generate activity, check /api/signals, exit)"
    exit 0
}

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

# Check Admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator" -ForegroundColor Yellow
    Write-Host "Windows Event Log capture may fail without admin rights."
    Write-Host 'Run: Start-Process powershell -Verb RunAs -ArgumentList "-File", ".\scripts\run_stack_windows.ps1"'
    Write-Host ""
}

# Configuration
if (-not $env:EDR_TELEMETRY_ROOT) {
    $env:EDR_TELEMETRY_ROOT = "C:\ProgramData\edr"
}
$TelemetryRoot = $env:EDR_TELEMETRY_ROOT
$BaseUrl = "http://localhost:3000"

Write-Host "=========================================="
Write-Host " EDR Stack - Windows"
Write-Host "=========================================="
Write-Host "EDR_TELEMETRY_ROOT: $TelemetryRoot"
Write-Host "API Base URL:       $BaseUrl"
Write-Host "Admin:              $(if ($isAdmin) { 'Yes' } else { 'No (capture may fail)' })"
Write-Host ""

# Create directories
$dirs = @(
    "$TelemetryRoot\segments",
    "$TelemetryRoot\incidents\default",
    "$TelemetryRoot\exports\default",
    "$TelemetryRoot\metrics"
)
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Clean stale state from prior runs (important for reproducible verification)
if ($Verify) {
    $cleanItems = @("$TelemetryRoot\index.json", "$TelemetryRoot\analysis.db", "$TelemetryRoot\segments\index.json")
    foreach ($item in $cleanItems) {
        if (Test-Path $item) {
            Remove-Item $item -Force
            Write-Host "  Removed stale: $item"
        }
    }
    Get-ChildItem -Path "$TelemetryRoot\segments" -Filter "*.jsonl" -ErrorAction SilentlyContinue | Remove-Item -Force
}

# NOTE: index.json is written by capture at $TelemetryRoot\index.json (not in segments/)
# Do NOT pre-create it - capture handles atomic writes

# Build if requested
if (-not $NoBuild) {
    Write-Host "[1/5] Building release binaries..."
    cargo build --release -p agent-windows -p edr-locald -p edr-server
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Build failed"
        exit 1
    }
}

# Binary paths
$CaptureBin = "$ProjectRoot\target\release\capture_windows_rotating.exe"
$LocaldBin = "$ProjectRoot\target\release\edr-locald.exe"
$ServerBin = "$ProjectRoot\target\release\edr-server.exe"

# Verify binaries exist
$binaries = @($CaptureBin, $LocaldBin, $ServerBin)
foreach ($bin in $binaries) {
    if (-not (Test-Path $bin)) {
        Write-Host "ERROR: Binary not found: $bin"
        Write-Host "Run without -NoBuild to compile"
        exit 1
    }
}

# Process tracking for cleanup
$Processes = @()

function Cleanup {
    Write-Host ""
    Write-Host "[SHUTDOWN] Stopping all processes..."
    foreach ($proc in $script:Processes) {
        if (-not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "[SHUTDOWN] Complete"
}

# Register cleanup on exit
Register-EngineEvent PowerShell.Exiting -Action { Cleanup }

try {
    Write-Host "[2/5] Starting capture_windows_rotating..."
    $captureProc = Start-Process -FilePath $CaptureBin -NoNewWindow -PassThru -RedirectStandardOutput "$TelemetryRoot\capture.log" -RedirectStandardError "$TelemetryRoot\capture_err.log"
    $Processes += $captureProc
    Write-Host "  PID: $($captureProc.Id)"

    Start-Sleep -Seconds 2

    Write-Host "[3/5] Starting edr-locald..."
    $localdProc = Start-Process -FilePath $LocaldBin -NoNewWindow -PassThru -RedirectStandardOutput "$TelemetryRoot\locald.log" -RedirectStandardError "$TelemetryRoot\locald_err.log"
    $Processes += $localdProc
    Write-Host "  PID: $($localdProc.Id)"

    Start-Sleep -Seconds 1

    Write-Host "[4/5] Starting edr-server..."
    $serverProc = Start-Process -FilePath $ServerBin -NoNewWindow -PassThru -RedirectStandardOutput "$TelemetryRoot\server.log" -RedirectStandardError "$TelemetryRoot\server_err.log"
    $Processes += $serverProc
    Write-Host "  PID: $($serverProc.Id)"

    Write-Host ""
    Write-Host "=========================================="
    Write-Host " Stack Running"
    Write-Host "=========================================="
    Write-Host "UI URL:        $BaseUrl"
    Write-Host "API Health:    $BaseUrl/api/health"
    Write-Host "API Signals:   $BaseUrl/api/signals"
    Write-Host ""
    Write-Host "Logs:"
    Write-Host "  Capture:  Get-Content $TelemetryRoot\capture.log -Wait"
    Write-Host "  Locald:   Get-Content $TelemetryRoot\locald.log -Wait"
    Write-Host "  Server:   Get-Content $TelemetryRoot\server.log -Wait"
    Write-Host ""

    # If -Verify mode, generate activity and verify pipeline
    if ($Verify) {
        Write-Host "[5/5] Running E2E Verification (120+ seconds)..."
        
        # Generate activity that produces Windows events
        $null = whoami.exe /all 2>&1
        $null = hostname.exe 2>&1
        $null = ipconfig.exe /all 2>&1
        $null = nslookup example.com 2>&1
        $testFile = "$env:TEMP\edr_test_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        "EDR test file content" | Out-File -FilePath $testFile
        Remove-Item $testFile -ErrorAction SilentlyContinue
        # Small PowerShell activity
        $null = Get-Process | Select-Object -First 5
        $null = Get-Service | Select-Object -First 5
        
        Write-Host "  Generated: whoami, hostname, ipconfig, nslookup, file write/delete, Get-Process, Get-Service"
        
        # Wait 20 seconds for initial telemetry
        Write-Host "  Waiting 20 seconds for initial telemetry..."
        Start-Sleep -Seconds 20
        
        # Check capture is still alive
        if ($captureProc.HasExited) {
            Write-Host "  FAIL: Capture process exited early (code: $($captureProc.ExitCode))" -ForegroundColor Red
            # Dump logs immediately
            Write-Host ""
            Write-Host "=== CAPTURE STDERR (last 100 lines) ===" -ForegroundColor Yellow
            if (Test-Path "$TelemetryRoot\capture_err.log") {
                Get-Content "$TelemetryRoot\capture_err.log" -Tail 100
            }
            Cleanup
            exit 1
        }
        
        # Continue waiting to ensure 120s longevity
        Write-Host "  Capture still running. Waiting 100 more seconds for longevity test..."
        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep -Seconds 10
            if ($captureProc.HasExited) {
                Write-Host "  FAIL: Capture exited after $((20 + $i * 10)) seconds (code: $($captureProc.ExitCode))" -ForegroundColor Red
                Write-Host ""
                Write-Host "=== CAPTURE STDERR (last 100 lines) ===" -ForegroundColor Yellow
                if (Test-Path "$TelemetryRoot\capture_err.log") {
                    Get-Content "$TelemetryRoot\capture_err.log" -Tail 100
                }
                Cleanup
                exit 1
            }
            Write-Host "    Capture alive at $((20 + ($i + 1) * 10))s..."
        }
        Write-Host "  Capture survived 120+ seconds - OK" -ForegroundColor Green

        Write-Host ""
        Write-Host "=========================================="
        Write-Host " E2E Verification Checks"
        Write-Host "=========================================="
        
        $pass = $true
        $failReasons = @()
        
        # Check 1: Segments exist
        $segments = Get-ChildItem -Path "$TelemetryRoot\segments" -Filter "*.jsonl" -ErrorAction SilentlyContinue
        $segmentCount = ($segments | Measure-Object).Count
        Write-Host "[CHECK 1] Segments in $TelemetryRoot\segments:"
        if ($segmentCount -eq 0) {
            Write-Host "  FAIL: No .jsonl segments written" -ForegroundColor Red
            $pass = $false
            $failReasons += "No segments"
        } else {
            $totalSize = ($segments | Measure-Object -Property Length -Sum).Sum
            Write-Host "  Found $segmentCount segment(s), total $totalSize bytes - OK" -ForegroundColor Green
        }

        # Check 2: index.json at telemetry root (NOT in segments/)
        $indexPath = "$TelemetryRoot\index.json"
        Write-Host "[CHECK 2] Index at: $indexPath"
        if (Test-Path $indexPath) {
            try {
                $index = Get-Content $indexPath -Raw | ConvertFrom-Json
                $indexSegCount = if ($index.segments) { $index.segments.Count } else { 0 }
                Write-Host "  schema_version: $($index.schema_version), segments in index: $indexSegCount"
                
                # Verify each segment path exists
                $missingSegs = @()
                foreach ($seg in $index.segments) {
                    $relPath = if ($seg.rel_path) { $seg.rel_path } else { $seg.path }
                    $fullPath = Join-Path $TelemetryRoot $relPath
                    if (-not (Test-Path $fullPath)) {
                        $missingSegs += $relPath
                    }
                }
                if ($missingSegs.Count -gt 0) {
                    Write-Host "  FAIL: Missing segment files referenced by index:" -ForegroundColor Red
                    $missingSegs | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
                    $pass = $false
                    $failReasons += "Missing segments"
                } else {
                    Write-Host "  All segment paths valid - OK" -ForegroundColor Green
                }
            } catch {
                Write-Host "  FAIL: Could not parse index.json: $_" -ForegroundColor Red
                $pass = $false
                $failReasons += "Invalid index.json"
            }
        } else {
            Write-Host "  FAIL: index.json missing" -ForegroundColor Red
            if (Test-Path "$TelemetryRoot\segments\index.json") {
                Write-Host "  (Found at wrong location: segments\index.json)" -ForegroundColor Yellow
            }
            $pass = $false
            $failReasons += "No index.json"
        }

        # Check 3: API /api/health
        Write-Host "[CHECK 3] GET /api/health:"
        try {
            $health = Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 5
            Write-Host "  status=$($health.status) - OK" -ForegroundColor Green
        } catch {
            Write-Host "  FAIL: Server not responding - $_" -ForegroundColor Red
            $pass = $false
            $failReasons += "/api/health failed"
        }

        # Check 4: API /api/signals
        Write-Host "[CHECK 4] GET /api/signals:"
        try {
            $signals = Invoke-RestMethod -Uri "$BaseUrl/api/signals" -TimeoutSec 5
            $sigCount = if ($signals.signals) { $signals.signals.Count } elseif ($signals -is [array]) { $signals.Count } else { 0 }
            Write-Host "  signals=$sigCount (valid JSON) - OK" -ForegroundColor Green
        } catch {
            Write-Host "  FAIL: Could not fetch signals - $_" -ForegroundColor Red
            $pass = $false
            $failReasons += "/api/signals failed"
        }

        # Check 5: API /api/app/state
        Write-Host "[CHECK 5] GET /api/app/state:"
        try {
            $appState = Invoke-RestMethod -Uri "$BaseUrl/api/app/state" -TimeoutSec 5
            Write-Host "  Response OK" -ForegroundColor Green
        } catch {
            Write-Host "  FAIL: /api/app/state error - $_" -ForegroundColor Red
            $pass = $false
            $failReasons += "/api/app/state failed"
        }

        # Check 6: API /api/capabilities
        Write-Host "[CHECK 6] GET /api/capabilities:"
        try {
            $caps = Invoke-RestMethod -Uri "$BaseUrl/api/capabilities" -TimeoutSec 5
            Write-Host "  Response OK" -ForegroundColor Green
        } catch {
            Write-Host "  FAIL: /api/capabilities error - $_" -ForegroundColor Red
            $pass = $false
            $failReasons += "/api/capabilities failed"
        }

        # Check 7: UI at /
        Write-Host "[CHECK 7] GET / (UI HTML):"
        try {
            $ui = (Invoke-WebRequest -Uri "$BaseUrl/" -TimeoutSec 5 -UseBasicParsing).Content
            if ($ui -match "<html|<!DOCTYPE") {
                Write-Host "  HTML response - OK" -ForegroundColor Green
            } else {
                Write-Host "  FAIL: Response is not HTML" -ForegroundColor Red
                $pass = $false
                $failReasons += "UI not HTML"
            }
        } catch {
            Write-Host "  FAIL: Could not load UI - $_" -ForegroundColor Red
            $pass = $false
            $failReasons += "UI load failed"
        }

        # Check 8: Capture longevity (already done above, just confirm)
        Write-Host "[CHECK 8] Capture longevity (120s):"
        if (-not $captureProc.HasExited) {
            Write-Host "  Process $($captureProc.Id) still running - OK" -ForegroundColor Green
        } else {
            Write-Host "  FAIL: Capture exited" -ForegroundColor Red
            $pass = $false
            $failReasons += "Capture exited"
        }

        Write-Host ""
        if ($pass) {
            Write-Host "==========================================" -ForegroundColor Green
            Write-Host " RESULT: PASS" -ForegroundColor Green
            Write-Host "==========================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "Telemetry root: $TelemetryRoot"
            Write-Host "Segments: $segmentCount"
        } else {
            Write-Host "==========================================" -ForegroundColor Red
            Write-Host " RESULT: FAIL" -ForegroundColor Red
            Write-Host "==========================================" -ForegroundColor Red
            Write-Host "Failed checks: $($failReasons -join ', ')"
            Write-Host ""
            
            # Diagnostics dump
            Write-Host "=== DIAGNOSTICS ===" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "--- Telemetry directory tree ---"
            Get-ChildItem -Path $TelemetryRoot -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length | Format-Table -AutoSize
            
            Write-Host ""
            Write-Host "--- capture_err.log (last 100 lines) ---"
            if (Test-Path "$TelemetryRoot\capture_err.log") {
                Get-Content "$TelemetryRoot\capture_err.log" -Tail 100
            } else {
                Write-Host "(not found)"
            }
            
            Write-Host ""
            Write-Host "--- locald_err.log (last 100 lines) ---"
            if (Test-Path "$TelemetryRoot\locald_err.log") {
                Get-Content "$TelemetryRoot\locald_err.log" -Tail 100
            } else {
                Write-Host "(not found)"
            }
            
            Write-Host ""
            Write-Host "--- server_err.log (last 100 lines) ---"
            if (Test-Path "$TelemetryRoot\server_err.log") {
                Get-Content "$TelemetryRoot\server_err.log" -Tail 100
            } else {
                Write-Host "(not found)"
            }
        }

        Cleanup
        if ($pass) { exit 0 } else { exit 1 }
    }

    # Non-verify mode: wait for events to accumulate
    Write-Host "[5/5] Waiting 60 seconds for events to accumulate..."
    Start-Sleep -Seconds 60

    # Run proof_run
    Write-Host ""
    Write-Host "=========================================="
    Write-Host " Running proof_run"
    Write-Host "=========================================="
    $ProofRunBin = "$ProjectRoot\target\release\proof_run.exe"
    if (Test-Path $ProofRunBin) {
        & $ProofRunBin
        Write-Host ""
        Write-Host "Proof artifacts:"
        Get-ChildItem -Path $TelemetryRoot -Recurse -Include "proof_run*.json","incidents*.jsonl" | Select-Object -First 10 | ForEach-Object { Write-Host $_.FullName }
    } else {
        Write-Host "[WARN] proof_run binary not found. Build with: cargo build --release -p edr-locald"
    }

    Write-Host ""
    Write-Host "=========================================="
    Write-Host " Summary"
    Write-Host "=========================================="
    $segmentCount = (Get-ChildItem -Path "$TelemetryRoot\segments" -Filter "*.jsonl" -ErrorAction SilentlyContinue | Measure-Object).Count
    $incidentCount = (Get-ChildItem -Path "$TelemetryRoot\incidents\default" -Filter "*.json" -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "Segments written: $segmentCount"
    Write-Host "Incidents:        $incidentCount"
    Write-Host ""
    Write-Host "Press Ctrl-C to stop the stack..."
    Write-Host ""

    # Wait for interrupt
    while ($true) {
        Start-Sleep -Seconds 1
        # Check if any process has exited
        foreach ($proc in $Processes) {
            if ($proc.HasExited) {
                Write-Host "[WARN] Process $($proc.Id) exited with code $($proc.ExitCode)"
            }
        }
    }
} finally {
    Cleanup
}
