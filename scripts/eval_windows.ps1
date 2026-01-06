<#
.SYNOPSIS
    Windows EDR Evaluation Harness - Full E2E Detection + Explainability Verification
.DESCRIPTION
    Starts the full stack, generates scenario activity, validates detections, and produces metrics.
.PARAMETER ScenarioSet
    'basic' for quick validation, 'full' for comprehensive scenarios
.PARAMETER SkipBuild
    Use pre-built binaries
.PARAMETER KeepRunning
    Don't shut down stack after verification
.EXAMPLE
    .\eval_windows.ps1 -ScenarioSet basic
    .\eval_windows.ps1 -ScenarioSet full -KeepRunning
#>

param(
    [ValidateSet("basic", "full")]
    [string]$ScenarioSet = "basic",
    [switch]$SkipBuild,
    [switch]$KeepRunning,
    [switch]$Help
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

# ============================================================================
# Configuration
# ============================================================================
$TelemetryRoot = if ($env:EDR_TELEMETRY_ROOT) { $env:EDR_TELEMETRY_ROOT } else { "C:\ProgramData\edr" }
$env:EDR_TELEMETRY_ROOT = $TelemetryRoot
$BaseUrl = "http://localhost:3000"
$RunId = Get-Date -Format "yyyyMMdd_HHmmss"
$MetricsDir = "$TelemetryRoot\metrics"
$LogsDir = "$TelemetryRoot\logs"

# Thresholds
$Thresholds = @{
    basic = @{ min_detections = 1; explain_success_rate = 0.8 }
    full  = @{ min_detections = 3; explain_success_rate = 0.9 }
}

# Process tracking
$script:Processes = @()

Write-Host @"

==============================================================================
 EDR EVALUATION HARNESS - Windows
==============================================================================
 Run ID:         $RunId
 Scenario Set:   $ScenarioSet
 Telemetry Root: $TelemetryRoot
 API URL:        $BaseUrl
==============================================================================

"@ -ForegroundColor Cyan

# ============================================================================
# Helper Functions
# ============================================================================

function Cleanup {
    Write-Host "`n[SHUTDOWN] Stopping stack processes..."
    foreach ($proc in $script:Processes) {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

trap { Cleanup; break }

function Write-Step {
    param([int]$Step, [int]$Total, [string]$Message)
    Write-Host "[$Step/$Total] $Message" -ForegroundColor Yellow
}

function Write-Check {
    param([string]$Name, [bool]$Pass, [string]$Detail = "")
    $status = if ($Pass) { "[PASS]" } else { "[FAIL]" }
    $color = if ($Pass) { "Green" } else { "Red" }
    Write-Host "  $status " -ForegroundColor $color -NoNewline
    Write-Host "$Name" -NoNewline
    if ($Detail) { Write-Host " - $Detail" -ForegroundColor Gray } else { Write-Host "" }
}

function Test-ServerHealth {
    try {
        $health = Invoke-RestMethod -Uri "$BaseUrl/health" -TimeoutSec 5
        return $health.status -eq "ok"
    } catch {
        return $false
    }
}

function Wait-ForServer {
    param([int]$TimeoutSeconds = 30)
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        if (Test-ServerHealth) { return $true }
        Start-Sleep -Seconds 1
        $elapsed++
    }
    return $false
}

# ============================================================================
# STEP 1: Telemetry Prerequisites
# ============================================================================
Write-Step 1 8 "Checking telemetry prerequisites..."

$prereqScript = Join-Path $ScriptDir "enable_advanced_telemetry.ps1"
if (Test-Path $prereqScript) {
    $prereqResult = & $prereqScript -Quiet 2>&1
    $prereqExit = $LASTEXITCODE
    if ($prereqExit -ne 0) {
        Write-Host "  WARNING: Telemetry prerequisites not fully met" -ForegroundColor Yellow
        Write-Host "  Run: .\scripts\enable_advanced_telemetry.ps1 -AutoFix" -ForegroundColor Yellow
        # Continue but warn - don't fail for missing optional telemetry
    } else {
        Write-Check "Telemetry prerequisites" $true
    }
} else {
    Write-Host "  Skipping prereq check (script not found)"
}

# ============================================================================
# STEP 2: Setup Directories
# ============================================================================
Write-Step 2 8 "Setting up directories..."

$dirs = @($MetricsDir, $LogsDir, "$TelemetryRoot\segments", "$TelemetryRoot\playbooks\windows")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Copy playbooks
if (Test-Path "$ProjectRoot\playbooks\windows") {
    Copy-Item -Path "$ProjectRoot\playbooks\windows\*" -Destination "$TelemetryRoot\playbooks\windows" -Force -ErrorAction SilentlyContinue
    $pbCount = (Get-ChildItem "$TelemetryRoot\playbooks\windows" -Filter "*.yaml" -ErrorAction SilentlyContinue).Count
    Write-Host "  Copied $pbCount playbooks"
}

Write-Check "Directories" $true

# ============================================================================
# STEP 3: Build (optional)
# ============================================================================
Write-Step 3 8 "Building binaries..."

if (-not $SkipBuild) {
    $buildOutput = cargo build --release -p agent-windows -p edr-locald -p edr-server 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed:" -ForegroundColor Red
        Write-Host $buildOutput
        exit 1
    }
    Write-Check "Build" $true
} else {
    Write-Host "  Skipped (using existing binaries)"
}

# Verify binaries
$CaptureBin = "$ProjectRoot\target\release\capture_windows_rotating.exe"
$LocaldBin = "$ProjectRoot\target\release\edr-locald.exe"
$ServerBin = "$ProjectRoot\target\release\edr-server.exe"

$binariesExist = (Test-Path $CaptureBin) -and (Test-Path $LocaldBin) -and (Test-Path $ServerBin)
if (-not $binariesExist) {
    Write-Host "ERROR: Required binaries not found. Run without -SkipBuild" -ForegroundColor Red
    exit 1
}

# ============================================================================
# STEP 4: Start Stack
# ============================================================================
Write-Step 4 8 "Starting stack..."

# Kill any existing processes
Get-Process -Name "capture_windows_rotating", "edr-locald", "edr-server" -ErrorAction SilentlyContinue | 
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Start server
Write-Host "  Starting edr-server..."
$serverProc = Start-Process -FilePath $ServerBin `
    -RedirectStandardOutput "$LogsDir\server_$RunId.log" `
    -RedirectStandardError "$LogsDir\server_$RunId.err" `
    -PassThru -WindowStyle Hidden
$script:Processes += $serverProc
Write-Host "    PID: $($serverProc.Id)"

Start-Sleep -Seconds 2

# Start capture (requires admin for Security log)
Write-Host "  Starting capture_windows_rotating..."
$captureProc = Start-Process -FilePath $CaptureBin `
    -RedirectStandardOutput "$LogsDir\capture_$RunId.log" `
    -RedirectStandardError "$LogsDir\capture_$RunId.err" `
    -PassThru -WindowStyle Hidden
$script:Processes += $captureProc
Write-Host "    PID: $($captureProc.Id)"

Start-Sleep -Seconds 2

# Start locald
Write-Host "  Starting edr-locald..."
$localdProc = Start-Process -FilePath $LocaldBin `
    -RedirectStandardOutput "$LogsDir\locald_$RunId.log" `
    -RedirectStandardError "$LogsDir\locald_$RunId.err" `
    -PassThru -WindowStyle Hidden
$script:Processes += $localdProc
Write-Host "    PID: $($localdProc.Id)"

# Wait for server
Write-Host "  Waiting for server to be ready..."
if (-not (Wait-ForServer -TimeoutSeconds 15)) {
    Write-Host "ERROR: Server failed to start" -ForegroundColor Red
    Get-Content "$LogsDir\server_$RunId.err" -Tail 20 -ErrorAction SilentlyContinue
    Cleanup
    exit 1
}

Write-Check "Stack started" $true

# ============================================================================
# STEP 5: Generate Scenario Activity
# ============================================================================
Write-Step 5 8 "Generating scenario activity..."

# Inject test events for reliable detection
$testSegment = "$TelemetryRoot\segments\eval_$RunId.jsonl"
$tsNow = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

$testEvents = @()

# Event: Log cleared (1102) - Defense Evasion
$testEvents += @{
    ts_ms = $tsNow
    host = $env:COMPUTERNAME
    type = "windows_event"
    tags = @("windows", "event_log", "security")
    fields = @{
        "windows.event_id" = 1102
        "windows.channel" = "Security"
        "windows.provider" = "Microsoft-Windows-Eventlog"
        "SubjectUserName" = $env:USERNAME
    }
    evidence_ptr = @{ stream_id = "eval_$RunId"; segment_id = 1; record_index = 0 }
}

# Event: Service installed (7045) - Persistence
$testEvents += @{
    ts_ms = $tsNow + 1000
    host = $env:COMPUTERNAME
    type = "windows_event"
    tags = @("windows", "event_log", "system")
    fields = @{
        "windows.event_id" = 7045
        "windows.channel" = "System"
        "windows.provider" = "Service Control Manager"
        "ServiceName" = "EvalTestService"
        "ImagePath" = "C:\Windows\Temp\eval_test.exe"
    }
    evidence_ptr = @{ stream_id = "eval_$RunId"; segment_id = 1; record_index = 1 }
}

if ($ScenarioSet -eq "full") {
    # Additional events for full scenario
    
    # Event: Scheduled task (4698)
    $testEvents += @{
        ts_ms = $tsNow + 2000
        host = $env:COMPUTERNAME
        type = "windows_event"
        tags = @("windows", "event_log", "security")
        fields = @{
            "windows.event_id" = 4698
            "windows.channel" = "Security"
            "TaskName" = "\Microsoft\Windows\EvalTask"
            "TaskContent" = "cmd.exe /c eval"
        }
        evidence_ptr = @{ stream_id = "eval_$RunId"; segment_id = 1; record_index = 2 }
    }
    
    # Event: Network share access (5140)
    $testEvents += @{
        ts_ms = $tsNow + 3000
        host = $env:COMPUTERNAME
        type = "windows_event"
        tags = @("windows", "event_log", "security")
        fields = @{
            "windows.event_id" = 5140
            "windows.channel" = "Security"
            "ShareName" = "\\*\ADMIN$"
            "SubjectUserName" = $env:USERNAME
            "IpAddress" = "192.168.1.100"
        }
        evidence_ptr = @{ stream_id = "eval_$RunId"; segment_id = 1; record_index = 3 }
    }
}

# Write events to segment
foreach ($evt in $testEvents) {
    ($evt | ConvertTo-Json -Compress) | Out-File -FilePath $testSegment -Append -Encoding utf8
}

Write-Host "  Created $($testEvents.Count) test events"

# Update index.json
$indexPath = "$TelemetryRoot\index.json"
if (Test-Path $indexPath) {
    $index = Get-Content $indexPath -Raw | ConvertFrom-Json
} else {
    $index = @{ schema_version = "1.0"; segments = @() }
}
$index.segments += @{
    rel_path = "segments/eval_$RunId.jsonl"
    record_count = $testEvents.Count
    byte_size = (Get-Item $testSegment).Length
    created_at = (Get-Date).ToString("o")
}
$index | ConvertTo-Json -Depth 10 | Set-Content $indexPath -Encoding utf8

Write-Check "Scenarios injected" $true

# Wait for processing
Write-Host "  Waiting for detection pipeline (15s)..."
Start-Sleep -Seconds 15

# ============================================================================
# STEP 6: Validate Detections
# ============================================================================
Write-Step 6 8 "Validating detections..."

$metrics = @{
    run_id = $RunId
    scenario_set = $ScenarioSet
    timestamp = (Get-Date).ToString("o")
    signals = @()
    explanations = @()
    checks = @{}
}

try {
    $signalsResp = Invoke-RestMethod -Uri "$BaseUrl/api/signals" -TimeoutSec 10
    $signals = if ($signalsResp.data) { $signalsResp.data } else { @($signalsResp) }
    $metrics.checks.signals_count = $signals.Count
    
    Write-Host "  Found $($signals.Count) signals"
    
    $minDetections = $Thresholds[$ScenarioSet].min_detections
    $detectionsPass = $signals.Count -ge $minDetections
    Write-Check "Minimum detections ($minDetections)" $detectionsPass "$($signals.Count) found"
    
    # Record signals
    foreach ($sig in $signals) {
        $metrics.signals += @{
            signal_id = $sig.signal_id
            signal_type = $sig.signal_type
            severity = $sig.severity
            ts = $sig.ts
        }
    }
} catch {
    Write-Check "Signal API" $false $_.Exception.Message
    $detectionsPass = $false
}

# ============================================================================
# STEP 7: Validate Explainability
# ============================================================================
Write-Step 7 8 "Validating explainability..."

$explainSuccess = 0
$explainTotal = 0

foreach ($sig in $signals) {
    $explainTotal++
    try {
        $explainResp = Invoke-RestMethod -Uri "$BaseUrl/api/signals/$($sig.signal_id)/explain" -TimeoutSec 10
        $explanation = $explainResp.data
        
        if ($explanation -and $explanation.playbook_id) {
            $explainSuccess++
            
            $metrics.explanations += @{
                signal_id = $sig.signal_id
                playbook_id = $explanation.playbook_id
                playbook_title = $explanation.playbook_title
                family = $explanation.family
                slots_filled = ($explanation.slots | Where-Object { $_.status -eq "filled" }).Count
                slots_total = $explanation.slots.Count
                evidence_count = $explanation.evidence.Count
            }
            
            Write-Host "    $($sig.signal_id): $($explanation.playbook_title)" -ForegroundColor Green
        }
    } catch {
        # No explanation for this signal
    }
}

$explainRate = if ($explainTotal -gt 0) { $explainSuccess / $explainTotal } else { 0 }
$explainThreshold = $Thresholds[$ScenarioSet].explain_success_rate
$explainPass = $explainRate -ge $explainThreshold

$metrics.checks.explain_success_rate = $explainRate
$metrics.checks.explain_threshold = $explainThreshold

Write-Check "Explanation rate (>= $([int]($explainThreshold * 100))%)" $explainPass "$([int]($explainRate * 100))%"

# ============================================================================
# STEP 8: Write Metrics & Open UI
# ============================================================================
Write-Step 8 8 "Writing metrics and opening UI..."

# Write metrics
$metricsPath = "$MetricsDir\run_${RunId}_metrics.json"
$metrics | ConvertTo-Json -Depth 10 | Set-Content $metricsPath -Encoding utf8
Write-Host "  Metrics: $metricsPath"

# Write detections
$detectionsPath = "$MetricsDir\run_${RunId}_detections.jsonl"
foreach ($sig in $metrics.signals) {
    ($sig | ConvertTo-Json -Compress) | Out-File -FilePath $detectionsPath -Append -Encoding utf8
}
Write-Host "  Detections: $detectionsPath"

# Write explanations
$explanationsPath = "$MetricsDir\run_${RunId}_explanations.jsonl"
foreach ($exp in $metrics.explanations) {
    ($exp | ConvertTo-Json -Compress) | Out-File -FilePath $explanationsPath -Append -Encoding utf8
}
Write-Host "  Explanations: $explanationsPath"

# Open UI
Start-Process $BaseUrl
Write-Host "  UI opened in browser"

# ============================================================================
# Summary
# ============================================================================
Write-Host @"

==============================================================================
 EVALUATION RESULTS
==============================================================================
"@ -ForegroundColor Cyan

$overallPass = $detectionsPass -and $explainPass

Write-Host "  Signals:      $($metrics.checks.signals_count)"
Write-Host "  Explanations: $explainSuccess / $explainTotal"
Write-Host "  Metrics:      $metricsPath"

if ($overallPass) {
    Write-Host "`n  RESULT: PASS" -ForegroundColor Green
} else {
    Write-Host "`n  RESULT: FAIL" -ForegroundColor Red
}

Write-Host "`n  Logs: $LogsDir"
Write-Host "  UI:   $BaseUrl"

if (-not $KeepRunning) {
    Write-Host "`nShutting down stack..."
    Cleanup
    exit $(if ($overallPass) { 0 } else { 1 })
} else {
    Write-Host "`nStack is running. Press Ctrl+C to stop."
    try {
        while ($true) {
            Start-Sleep -Seconds 10
            # Check process health
            foreach ($proc in $script:Processes) {
                if ($proc.HasExited) {
                    Write-Host "Process $($proc.Id) exited" -ForegroundColor Yellow
                }
            }
        }
    } finally {
        Cleanup
    }
}
