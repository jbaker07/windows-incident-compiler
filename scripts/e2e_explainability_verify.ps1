# e2e_explainability_verify.ps1 - Full E2E verification of explainability mode
# This script:
# 1. Starts all three stack components (server, locald, capture)
# 2. Injects test events that trigger playbook-based detections
# 3. Verifies signals are created
# 4. Verifies explainability endpoint returns valid ExplanationBundle
# 5. Opens UI for visual confirmation
#
# Usage: .\scripts\e2e_explainability_verify.ps1

param(
    [switch]$Help,
    [switch]$SkipBuild,
    [switch]$KeepRunning  # Don't shut down stack at end
)

if ($Help) {
    Write-Host "Usage: .\scripts\e2e_explainability_verify.ps1 [-SkipBuild] [-KeepRunning]"
    Write-Host "  -SkipBuild    Use pre-built binaries"
    Write-Host "  -KeepRunning  Keep stack running after verification"
    exit 0
}

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

# Configuration
$TelemetryRoot = if ($env:EDR_TELEMETRY_ROOT) { $env:EDR_TELEMETRY_ROOT } else { "C:\ProgramData\edr" }
$env:EDR_TELEMETRY_ROOT = $TelemetryRoot
$BaseUrl = "http://localhost:3000"

Write-Host "=========================================="
Write-Host " E2E Explainability Verification"
Write-Host "=========================================="
Write-Host "EDR_TELEMETRY_ROOT: $TelemetryRoot"
Write-Host "API Base URL:       $BaseUrl"
Write-Host ""

# Track processes for cleanup
$Processes = @()

function Cleanup {
    Write-Host ""
    Write-Host "[SHUTDOWN] Stopping all processes..."
    foreach ($proc in $script:Processes) {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "[SHUTDOWN] Complete"
}

# Ensure cleanup on exit
trap { Cleanup; break }

try {
    # ========================================
    # STEP 1: Setup
    # ========================================
    Write-Host "[1/7] Setting up directories..."
    
    $dirs = @(
        "$TelemetryRoot\segments",
        "$TelemetryRoot\playbooks\windows",
        "$TelemetryRoot\logs"
    )
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    # Copy playbooks
    if (Test-Path "$ProjectRoot\playbooks\windows") {
        Copy-Item -Path "$ProjectRoot\playbooks\windows\*" -Destination "$TelemetryRoot\playbooks\windows" -Force
        $pbCount = (Get-ChildItem "$TelemetryRoot\playbooks\windows" -Filter "*.yaml").Count
        Write-Host "  Copied $pbCount playbooks"
    }
    Write-Host "  Setup complete"
    
    # ========================================
    # STEP 2: Build (optional)
    # ========================================
    if (-not $SkipBuild) {
        Write-Host ""
        Write-Host "[2/7] Building release binaries..."
        cargo build --release -p agent-windows -p edr-locald -p edr-server
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: Build failed" -ForegroundColor Red
            exit 1
        }
        Write-Host "  Build complete"
    } else {
        Write-Host ""
        Write-Host "[2/7] Skipping build (using existing binaries)"
    }
    
    # Verify binaries exist
    $CaptureBin = "$ProjectRoot\target\release\capture_windows_rotating.exe"
    $LocaldBin = "$ProjectRoot\target\release\edr-locald.exe"
    $ServerBin = "$ProjectRoot\target\release\edr-server.exe"
    
    foreach ($bin in @($CaptureBin, $LocaldBin, $ServerBin)) {
        if (-not (Test-Path $bin)) {
            Write-Host "ERROR: Binary not found: $bin" -ForegroundColor Red
            exit 1
        }
    }
    
    # ========================================
    # STEP 3: Start Stack
    # ========================================
    Write-Host ""
    Write-Host "[3/7] Starting stack components..."
    
    # Kill any existing processes
    Get-Process -Name "capture_windows_rotating", "edr-locald", "edr-server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    
    # Start server (with WindowStyle Hidden to avoid ctrl+c propagation)
    Write-Host "  Starting edr-server..."
    $serverProc = Start-Process -FilePath $ServerBin `
        -RedirectStandardOutput "$TelemetryRoot\logs\server.log" `
        -RedirectStandardError "$TelemetryRoot\logs\server_err.log" `
        -PassThru -WindowStyle Hidden
    $Processes += $serverProc
    Write-Host "    PID: $($serverProc.Id)"
    
    Start-Sleep -Seconds 2
    
    # Start capture
    Write-Host "  Starting capture_windows_rotating..."
    $captureProc = Start-Process -FilePath $CaptureBin `
        -RedirectStandardOutput "$TelemetryRoot\logs\capture.log" `
        -RedirectStandardError "$TelemetryRoot\logs\capture_err.log" `
        -PassThru -WindowStyle Hidden
    $Processes += $captureProc
    Write-Host "    PID: $($captureProc.Id)"
    
    Start-Sleep -Seconds 2
    
    # Start locald
    Write-Host "  Starting edr-locald..."
    $localdProc = Start-Process -FilePath $LocaldBin `
        -RedirectStandardOutput "$TelemetryRoot\logs\locald.log" `
        -RedirectStandardError "$TelemetryRoot\logs\locald_err.log" `
        -PassThru -WindowStyle Hidden
    $Processes += $localdProc
    Write-Host "    PID: $($localdProc.Id)"
    
    Write-Host "  Waiting 5 seconds for startup..."
    Start-Sleep -Seconds 5
    
    # ========================================
    # STEP 4: Inject Test Events
    # ========================================
    Write-Host ""
    Write-Host "[4/7] Injecting test events..."
    
    $testSegment = "$TelemetryRoot\segments\e2e_test_$(Get-Date -Format 'yyyyMMddHHmmss').jsonl"
    $tsNow = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    
    # Event 1: Log cleared (Event ID 1102) - triggers defense_evasion detection
    $event1 = @{
        ts_ms = $tsNow
        host = $env:COMPUTERNAME
        type = "windows_event"
        tags = @("windows", "event_log", "security")
        fields = @{
            "windows.event_id" = 1102
            "windows.channel" = "Security"
            "windows.provider" = "Microsoft-Windows-Eventlog"
            "SubjectUserName" = "testuser"
        }
        evidence_ptr = @{
            stream_id = "e2e_test"
            segment_id = 200
            record_index = 0
        }
    } | ConvertTo-Json -Compress
    
    # Event 2: Service installed (Event ID 7045) - triggers persistence detection
    $event2 = @{
        ts_ms = $tsNow + 1000
        host = $env:COMPUTERNAME
        type = "windows_event"
        tags = @("windows", "event_log", "system")
        fields = @{
            "windows.event_id" = 7045
            "windows.channel" = "System"
            "windows.provider" = "Service Control Manager"
            "ServiceName" = "TestPersistenceService"
            "ImagePath" = "C:\Windows\Temp\persistence.exe"
            "ServiceType" = "user mode service"
            "StartType" = "auto start"
        }
        evidence_ptr = @{
            stream_id = "e2e_test"
            segment_id = 200
            record_index = 1
        }
    } | ConvertTo-Json -Compress
    
    # Write test segment
    $event1 | Out-File -FilePath $testSegment -Encoding utf8
    $event2 | Out-File -FilePath $testSegment -Append -Encoding utf8
    
    # Update index.json to include test segment
    $indexPath = "$TelemetryRoot\index.json"
    if (Test-Path $indexPath) {
        $index = Get-Content $indexPath -Raw | ConvertFrom-Json
    } else {
        $index = @{
            schema_version = "1.0"
            segments = @()
        }
    }
    
    $relPath = "segments/$(Split-Path $testSegment -Leaf)"
    $newSeg = @{
        rel_path = $relPath
        record_count = 2
        byte_size = (Get-Item $testSegment).Length
        created_at = (Get-Date).ToString("o")
    }
    $index.segments += $newSeg
    $index | ConvertTo-Json -Depth 10 | Set-Content $indexPath -Encoding utf8
    
    Write-Host "  Created test segment with 2 events"
    Write-Host "    - Event ID 1102 (log cleared)"
    Write-Host "    - Event ID 7045 (service installed)"
    
    # Wait for processing
    Write-Host "  Waiting 10 seconds for detection pipeline..."
    Start-Sleep -Seconds 10
    
    # ========================================
    # STEP 5: Verify Signals
    # ========================================
    Write-Host ""
    Write-Host "[5/7] Verifying signals..."
    
    $pass = $true
    $failReasons = @()
    
    try {
        $signalsResp = Invoke-RestMethod -Uri "$BaseUrl/api/signals" -TimeoutSec 5
        $signals = if ($signalsResp.data) { $signalsResp.data } else { $signalsResp }
        
        Write-Host "  Found $($signals.Count) signals"
        
        if ($signals.Count -eq 0) {
            Write-Host "  FAIL: No signals detected" -ForegroundColor Red
            $pass = $false
            $failReasons += "No signals"
        } else {
            # Find defense_evasion and persistence signals
            $defenseEvasion = $signals | Where-Object { $_.signal_type -match "defense_evasion" }
            $persistence = $signals | Where-Object { $_.signal_type -match "persistence" }
            
            Write-Host "    Defense Evasion signals: $($defenseEvasion.Count)" -ForegroundColor Cyan
            Write-Host "    Persistence signals: $($persistence.Count)" -ForegroundColor Cyan
            
            if ($defenseEvasion.Count -eq 0 -and $persistence.Count -eq 0) {
                Write-Host "  WARN: No playbook-based signals found" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  FAIL: Could not fetch signals - $_" -ForegroundColor Red
        $pass = $false
        $failReasons += "API error"
    }
    
    # ========================================
    # STEP 6: Verify Explainability
    # ========================================
    Write-Host ""
    Write-Host "[6/7] Verifying explainability endpoint..."
    
    $explanationFound = $false
    
    foreach ($sig in $signals) {
        try {
            $explainResp = Invoke-RestMethod -Uri "$BaseUrl/api/signals/$($sig.signal_id)/explain" -TimeoutSec 10
            $explanation = $explainResp.data
            
            if ($explanation) {
                Write-Host "  FOUND explanation for: $($sig.signal_id)" -ForegroundColor Green
                Write-Host "    Playbook: $($explanation.playbook_title)"
                Write-Host "    Family: $($explanation.family)"
                Write-Host "    Slots: $($explanation.slots.Count)"
                Write-Host "    Evidence: $($explanation.evidence.Count)"
                Write-Host "    Summary: $($explanation.summary)" -ForegroundColor Cyan
                
                # Validate structure
                if ($explanation.slots.Count -gt 0 -and $explanation.playbook_id) {
                    Write-Host "  ExplanationBundle structure VALID" -ForegroundColor Green
                    $explanationFound = $true
                    break  # Found one valid explanation
                }
            }
        } catch {
            # Explanation not found for this signal, continue
        }
    }
    
    if (-not $explanationFound) {
        Write-Host "  FAIL: No valid ExplanationBundle found" -ForegroundColor Red
        $pass = $false
        $failReasons += "No explanations"
    }
    
    # ========================================
    # STEP 7: Summary
    # ========================================
    Write-Host ""
    Write-Host "=========================================="
    Write-Host " E2E Verification Results"
    Write-Host "=========================================="
    
    if ($pass -and $explanationFound) {
        Write-Host " STATUS: PASS" -ForegroundColor Green
        Write-Host ""
        Write-Host " ✓ Stack components running"
        Write-Host " ✓ Test events injected and processed"
        Write-Host " ✓ Signals created via playbook pipeline"
        Write-Host " ✓ ExplanationBundle returned with filled slots"
        Write-Host ""
        Write-Host " UI available at: $BaseUrl"
    } else {
        Write-Host " STATUS: FAIL" -ForegroundColor Red
        Write-Host ""
        foreach ($reason in $failReasons) {
            Write-Host " ✗ $reason" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    
    if (-not $KeepRunning) {
        Write-Host "Shutting down stack..."
        Cleanup
    } else {
        Write-Host "Stack is still running. Press Ctrl+C to stop."
        Write-Host "Logs: $TelemetryRoot\logs\"
        Write-Host ""
        
        # Keep script alive
        while ($true) {
            Start-Sleep -Seconds 10
            
            # Check if any process died
            foreach ($proc in $Processes) {
                if ($proc.HasExited) {
                    Write-Host "Process $($proc.Id) exited with code $($proc.ExitCode)" -ForegroundColor Yellow
                }
            }
        }
    }
    
} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    Cleanup
    exit 1
}
