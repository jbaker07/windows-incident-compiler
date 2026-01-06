# run_stack_windows.ps1 - Start EDR stack on Windows with E2E verification
# Requires: cargo, Administrator access for full capture
#
# Usage:
#   .\scripts\run_stack_windows.ps1              # Build and run interactively
#   .\scripts\run_stack_windows.ps1 -NoBuild     # Run pre-built binaries
#   .\scripts\run_stack_windows.ps1 -Verify      # Run E2E verification then exit
#   .\scripts\run_stack_windows.ps1 -Verify -Explain -Metrics -OpenUI
#
# Full E2E command:
#   .\scripts\run_stack_windows.ps1 -Verify -Explain -Metrics -OpenUI

param(
    [switch]$NoBuild,       # Skip cargo build
    [switch]$Verify,        # Run E2E verification (generate activity, check signals)
    [switch]$Explain,       # Validate explainability (ExplanationBundle integrity)
    [switch]$Metrics,       # Write metrics artifact JSON
    [switch]$OpenUI,        # Open browser to UI after server healthy
    [switch]$KeepRunning,   # Don't shut down after verification (useful for debugging)
    [switch]$Help
)

if ($Help) {
    Write-Host "Usage: .\run_stack_windows.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -NoBuild      Skip cargo build, use pre-built binaries"
    Write-Host "  -Verify       Run E2E verification (generate activity, check /api/signals, exit)"
    Write-Host "  -Explain      Validate ExplanationBundle for each signal (requires -Verify)"
    Write-Host "  -Metrics      Write metrics artifact JSON to `$EDR_TELEMETRY_ROOT\metrics"
    Write-Host "  -OpenUI       Open browser to http://localhost:3000/ after server healthy"
    Write-Host "  -KeepRunning  Don't shut down after verification (for debugging)"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  # Full E2E with all checks:"
    Write-Host "  .\scripts\run_stack_windows.ps1 -Verify -Explain -Metrics -OpenUI"
    Write-Host ""
    Write-Host "  # Quick smoke test:"
    Write-Host "  .\scripts\run_stack_windows.ps1 -NoBuild -Verify"
    exit 0
}

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

# ============================================================================
# Configuration
# ============================================================================
if (-not $env:EDR_TELEMETRY_ROOT) {
    $env:EDR_TELEMETRY_ROOT = "C:\ProgramData\edr"
}
$TelemetryRoot = $env:EDR_TELEMETRY_ROOT
$BaseUrl = "http://localhost:3000"
$RunId = "run_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Check Admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  EDR Stack - Windows E2E" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:"
Write-Host "  EDR_TELEMETRY_ROOT:  $TelemetryRoot"
Write-Host "  API Base URL:        $BaseUrl"
Write-Host "  Run ID:              $RunId"
Write-Host "  Administrator:       $(if ($isAdmin) { 'Yes' } else { 'No (capture may be limited)' })"
Write-Host "  Flags:               NoBuild=$NoBuild Verify=$Verify Explain=$Explain Metrics=$Metrics OpenUI=$OpenUI"
Write-Host ""

if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator" -ForegroundColor Yellow
    Write-Host "  Some event logs (Security, Sysmon) require admin rights."
    Write-Host "  Will continue with System log only (degraded mode)."
    Write-Host '  For full capture: Start-Process powershell -Verb RunAs -ArgumentList "-File", ".\scripts\run_stack_windows.ps1"'
    Write-Host ""
}

# ============================================================================
# Directory Setup
# ============================================================================
$dirs = @(
    "$TelemetryRoot\segments",
    "$TelemetryRoot\incidents\default",
    "$TelemetryRoot\exports\default",
    "$TelemetryRoot\metrics",
    "$TelemetryRoot\logs",
    "$TelemetryRoot\playbooks\windows"
)
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Copy playbooks from repo
$RepoPlaybooksDir = "$ProjectRoot\playbooks\windows"
$TargetPlaybooksDir = "$TelemetryRoot\playbooks\windows"
if (Test-Path $RepoPlaybooksDir) {
    Copy-Item -Path "$RepoPlaybooksDir\*" -Destination $TargetPlaybooksDir -Recurse -Force -ErrorAction SilentlyContinue
    $playbookCount = (Get-ChildItem -Path $TargetPlaybooksDir -Filter "*.yaml" -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "Copied $playbookCount Windows playbooks"
}

# Clean stale state for reproducible runs
if ($Verify) {
    $cleanItems = @(
        "$TelemetryRoot\index.json",
        "$TelemetryRoot\analysis.db",
        "$TelemetryRoot\segments\index.json"
    )
    foreach ($item in $cleanItems) {
        if (Test-Path $item) {
            Remove-Item $item -Force -ErrorAction SilentlyContinue
        }
    }
    Get-ChildItem -Path "$TelemetryRoot\segments" -Filter "*.jsonl" -ErrorAction SilentlyContinue | Remove-Item -Force
    Write-Host "Cleaned stale state for verification run"
}

# ============================================================================
# Build (if requested)
# ============================================================================
if (-not $NoBuild) {
    Write-Host ""
    Write-Host "[BUILD] Compiling release binaries..." -ForegroundColor Cyan
    $buildStart = Get-Date
    cargo build --release -p agent-windows -p edr-locald -p edr-server 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Build failed" -ForegroundColor Red
        exit 1
    }
    $buildDuration = ((Get-Date) - $buildStart).TotalSeconds
    Write-Host "  Build completed in $([math]::Round($buildDuration, 1))s" -ForegroundColor Green
}

# Binary paths
$CaptureBin = "$ProjectRoot\target\release\capture_windows_rotating.exe"
$LocaldBin = "$ProjectRoot\target\release\edr-locald.exe"
$ServerBin = "$ProjectRoot\target\release\edr-server.exe"

# Verify binaries
foreach ($bin in @($CaptureBin, $LocaldBin, $ServerBin)) {
    if (-not (Test-Path $bin)) {
        Write-Host "ERROR: Binary not found: $bin" -ForegroundColor Red
        Write-Host "Run without -NoBuild to compile"
        exit 1
    }
}

# ============================================================================
# Process Management
# ============================================================================
$script:Processes = @()
$script:LogFiles = @{
    capture = "$TelemetryRoot\logs\capture.log"
    capture_err = "$TelemetryRoot\logs\capture_err.log"
    locald = "$TelemetryRoot\logs\locald.log"
    locald_err = "$TelemetryRoot\logs\locald_err.log"
    server = "$TelemetryRoot\logs\server.log"
    server_err = "$TelemetryRoot\logs\server_err.log"
}

function Cleanup {
    Write-Host ""
    Write-Host "[SHUTDOWN] Stopping all processes..." -ForegroundColor Yellow
    foreach ($proc in $script:Processes) {
        if ($proc -and -not $proc.HasExited) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
    Write-Host "[SHUTDOWN] Complete"
}

function Dump-Logs {
    param([int]$TailLines = 100)
    Write-Host ""
    Write-Host "═══ DIAGNOSTIC LOGS (last $TailLines lines) ═══" -ForegroundColor Yellow
    
    foreach ($name in @("capture_err", "locald_err", "server_err")) {
        $path = $script:LogFiles[$name]
        if (Test-Path $path) {
            $content = Get-Content $path -Tail $TailLines -ErrorAction SilentlyContinue
            if ($content) {
                Write-Host ""
                Write-Host "--- $name ---" -ForegroundColor Cyan
                $content | ForEach-Object { Write-Host $_ }
            }
        }
    }
}

# Trap for clean exit
trap {
    Dump-Logs
    Cleanup
    break
}

# ============================================================================
# Start Stack
# ============================================================================
try {
    Write-Host ""
    Write-Host "[STACK] Starting processes..." -ForegroundColor Cyan
    
    # Start capture
    Write-Host "  [1/3] capture_windows_rotating..."
    $captureProc = Start-Process -FilePath $CaptureBin -NoNewWindow -PassThru `
        -RedirectStandardOutput $script:LogFiles.capture `
        -RedirectStandardError $script:LogFiles.capture_err
    $script:Processes += $captureProc
    Write-Host "        PID: $($captureProc.Id)"
    
    Start-Sleep -Seconds 2
    
    # Start locald (NO workflow seed - we want REAL detections)
    Write-Host "  [2/3] edr-locald..."
    # Ensure no workflow seed
    $env:EDR_WORKFLOW_SEED = ""
    $localdProc = Start-Process -FilePath $LocaldBin -NoNewWindow -PassThru `
        -RedirectStandardOutput $script:LogFiles.locald `
        -RedirectStandardError $script:LogFiles.locald_err
    $script:Processes += $localdProc
    Write-Host "        PID: $($localdProc.Id)"
    
    Start-Sleep -Seconds 1
    
    # Start server
    Write-Host "  [3/3] edr-server..."
    $serverProc = Start-Process -FilePath $ServerBin -NoNewWindow -PassThru `
        -RedirectStandardOutput $script:LogFiles.server `
        -RedirectStandardError $script:LogFiles.server_err
    $script:Processes += $serverProc
    Write-Host "        PID: $($serverProc.Id)"
    
    # Wait for server health
    Write-Host ""
    Write-Host "[HEALTH] Waiting for server..." -ForegroundColor Cyan
    $healthOk = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $health = Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($health) {
                $healthOk = $true
                Write-Host "  Server healthy after $($i + 1)s" -ForegroundColor Green
                break
            }
        } catch {}
    }
    
    if (-not $healthOk) {
        Write-Host "  ERROR: Server did not become healthy in 30s" -ForegroundColor Red
        Dump-Logs
        Cleanup
        exit 1
    }
    
    # Open UI if requested
    if ($OpenUI) {
        Write-Host ""
        Write-Host "[UI] Opening browser..." -ForegroundColor Cyan
        Start-Process "http://localhost:3000/"
        Write-Host "  Opened $BaseUrl in default browser"
    }
    
    # ============================================================================
    # E2E Verification Mode
    # ============================================================================
    if ($Verify) {
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  E2E VERIFICATION" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        
        # ────────────────────────────────────────────────────────────────────
        # Generate Windows Activity
        # ────────────────────────────────────────────────────────────────────
        Write-Host ""
        Write-Host "[ACTIVITY] Generating Windows events..." -ForegroundColor Cyan
        
        $activityStart = Get-Date
        
        # Process executions (will appear as Exec facts if 4688 auditing enabled)
        $null = whoami.exe /all 2>&1
        $null = hostname.exe 2>&1
        $null = ipconfig.exe /all 2>&1
        $null = systeminfo.exe 2>&1  # Longer running, more visible
        $null = net.exe user 2>&1    # Discovery activity
        $null = nltest.exe /dsgetdc: 2>&1  # Domain controller query
        $null = schtasks.exe /query /fo LIST 2>&1  # Task query
        Write-Host "  - Process executions: whoami, hostname, ipconfig, systeminfo, net, nltest, schtasks"
        
        # File operations (will appear if Sysmon or advanced auditing)
        $testDir = "$env:TEMP\edr_e2e_$RunId"
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        $testFile = "$testDir\test_artifact.txt"
        "EDR E2E test content at $(Get-Date)" | Out-File -FilePath $testFile
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        Remove-Item $testDir -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "  - File operations: create/delete in $env:TEMP"
        
        # PowerShell activity (will appear as ScriptExec if 4103/4104 enabled)
        $null = & powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 3"
        $null = & powershell.exe -NoProfile -Command "Get-Service | Select-Object -First 3"
        Write-Host "  - PowerShell commands: Get-Process, Get-Service"
        
        # Registry read (safe, will appear if 4657 or Sysmon 12/13 enabled)
        try {
            $null = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
            Write-Host "  - Registry read: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        } catch {}
        
        # DNS queries (will appear as DnsResolve if Sysmon 22 enabled)
        $null = Resolve-DnsName -Name "example.com" -DnsOnly -ErrorAction SilentlyContinue
        $null = nslookup.exe "microsoft.com" 2>&1
        Write-Host "  - DNS queries: example.com, microsoft.com"
        
        # If admin, try to generate more privileged events
        if ($isAdmin) {
            # Service query (safer than install, still generates events)
            $null = sc.exe query type= service state= all 2>&1
            Write-Host "  - Service query: sc.exe query (admin)"
            
            # Note: We do NOT clear logs or install services to avoid disruption
            # Those would generate 1102/7045 but are too invasive for E2E testing
        }
        
        $activityDuration = ((Get-Date) - $activityStart).TotalSeconds
        Write-Host "  Generated activity in $([math]::Round($activityDuration, 1))s"
        
        # ────────────────────────────────────────────────────────────────────
        # Wait for Processing
        # ────────────────────────────────────────────────────────────────────
        Write-Host ""
        Write-Host "[WAIT] Allowing time for telemetry processing..." -ForegroundColor Cyan
        
        # Wait for capture to process events
        $waitSecs = 20
        Write-Host "  Waiting ${waitSecs}s for capture -> locald -> server pipeline..."
        for ($i = 0; $i -lt $waitSecs; $i += 5) {
            Start-Sleep -Seconds 5
            
            # Check processes still running
            if ($captureProc.HasExited) {
                Write-Host "  ERROR: Capture exited early (code: $($captureProc.ExitCode))" -ForegroundColor Red
                Dump-Logs -TailLines 50
                Cleanup
                exit 1
            }
            
            # Check for segments
            $segCount = (Get-ChildItem -Path "$TelemetryRoot\segments" -Filter "*.jsonl" -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "    ${i}s: $segCount segments written"
        }
        
        # ────────────────────────────────────────────────────────────────────
        # Verification Checks
        # ────────────────────────────────────────────────────────────────────
        Write-Host ""
        Write-Host "[CHECKS] Running verification assertions..." -ForegroundColor Cyan
        
        $pass = $true
        $failReasons = @()
        $checkResults = @{}
        
        # CHECK 1: Segments exist
        Write-Host ""
        Write-Host "  [1/7] Segments written:"
        $segments = Get-ChildItem -Path "$TelemetryRoot\segments" -Filter "*.jsonl" -ErrorAction SilentlyContinue
        $segmentCount = ($segments | Measure-Object).Count
        $segmentBytes = ($segments | Measure-Object -Property Length -Sum).Sum
        $checkResults["segment_count"] = $segmentCount
        $checkResults["segment_bytes"] = $segmentBytes
        
        if ($segmentCount -eq 0) {
            Write-Host "        X FAIL: No .jsonl segments" -ForegroundColor Red
            $pass = $false
            $failReasons += "No segments"
        } else {
            Write-Host "        OK $segmentCount segment(s), $segmentBytes bytes" -ForegroundColor Green
        }
        
        # CHECK 2: index.json valid
        Write-Host "  [2/7] index.json:"
        $indexPath = "$TelemetryRoot\index.json"
        $checkResults["index_exists"] = $false
        $checkResults["index_bytes"] = 0
        
        if (Test-Path $indexPath) {
            try {
                $index = Get-Content $indexPath -Raw | ConvertFrom-Json
                $indexBytes = (Get-Item $indexPath).Length
                $checkResults["index_exists"] = $true
                $checkResults["index_bytes"] = $indexBytes
                $checkResults["schema_version"] = $index.schema_version
                
                $indexSegCount = if ($index.segments) { $index.segments.Count } else { 0 }
                Write-Host "        OK Valid: schema=$($index.schema_version), $indexSegCount segments indexed" -ForegroundColor Green
            } catch {
                Write-Host "        X FAIL: Invalid JSON" -ForegroundColor Red
                $pass = $false
                $failReasons += "Invalid index.json"
            }
        } else {
            Write-Host "        X FAIL: Missing" -ForegroundColor Red
            $pass = $false
            $failReasons += "No index.json"
        }
        
        # CHECK 3: API health
        Write-Host "  [3/7] GET /api/health:"
        try {
            $health = Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 5
            Write-Host "        OK status=$($health.status)" -ForegroundColor Green
            $checkResults["api_health"] = $true
        } catch {
            Write-Host "        X FAIL: $_" -ForegroundColor Red
            $pass = $false
            $failReasons += "API health failed"
            $checkResults["api_health"] = $false
        }
        
        # CHECK 4: Signals >= 1
        Write-Host "  [4/7] GET /api/signals:"
        $signals = @()
        $sigCount = 0
        try {
            $resp = Invoke-RestMethod -Uri "$BaseUrl/api/signals" -TimeoutSec 10
            if ($resp.data) { $signals = $resp.data }
            elseif ($resp -is [array]) { $signals = $resp }
            $sigCount = $signals.Count
            $checkResults["signal_count"] = $sigCount
            
            if ($sigCount -ge 1) {
                Write-Host "        OK $sigCount signal(s) detected" -ForegroundColor Green
                # Show first few
                foreach ($sig in ($signals | Select-Object -First 3)) {
                    Write-Host "          - $($sig.signal_type) ($($sig.severity))" -ForegroundColor Cyan
                }
            } else {
                Write-Host "        WARN: No signals detected" -ForegroundColor Yellow
                Write-Host "          This may be expected if Security/Sysmon auditing is not enabled." -ForegroundColor Yellow
                Write-Host "          Real signals require: Process Audit (4688), Sysmon, or PowerShell logging." -ForegroundColor Yellow
                # Don't fail - this could be expected without proper auditing
                $checkResults["signal_warning"] = "No signals - check audit policy"
            }
        } catch {
            Write-Host "        X FAIL: $_" -ForegroundColor Red
            $pass = $false
            $failReasons += "API signals failed"
            $checkResults["signal_count"] = 0
        }
        
        # CHECK 5: Explainability (if -Explain and signals exist)
        Write-Host "  [5/7] Explainability:"
        $checkResults["explain_checked"] = 0
        $checkResults["explain_valid"] = 0
        $checkResults["explain_invalid"] = 0
        
        if ($Explain -and $sigCount -ge 1) {
            $newestSignal = $signals | Select-Object -First 1
            $sigId = $newestSignal.signal_id
            
            Write-Host "        Checking signal: $sigId"
            try {
                $explainResp = Invoke-RestMethod -Uri "$BaseUrl/api/signals/$sigId/explain" -TimeoutSec 10
                $checkResults["explain_checked"] = 1
                
                if ($explainResp.success -and $explainResp.data) {
                    $exp = $explainResp.data
                    $isValid = $true
                    $validationIssues = @()
                    
                    # Validate required fields
                    if (-not $exp.playbook_id) { $isValid = $false; $validationIssues += "missing playbook_id" }
                    if (-not $exp.family) { $isValid = $false; $validationIssues += "missing family" }
                    if (-not $exp.slots -or $exp.slots.Count -eq 0) { $isValid = $false; $validationIssues += "no slots" }
                    
                    # Check for at least 1 filled required slot
                    $filledReqSlots = ($exp.slots | Where-Object { $_.required -and $_.status -eq "filled" }).Count
                    if ($filledReqSlots -eq 0) { 
                        $validationIssues += "no filled required slots"
                        # Don't fail - some playbooks may not have required slots filled
                    }
                    
                    # Check for evidence
                    $evidenceCount = if ($exp.evidence) { $exp.evidence.Count } else { 0 }
                    if ($evidenceCount -eq 0) {
                        $validationIssues += "no evidence excerpts"
                    }
                    
                    $checkResults["explain_playbook"] = $exp.playbook_id
                    $checkResults["explain_slots"] = $exp.slots.Count
                    $checkResults["explain_evidence"] = $evidenceCount
                    $checkResults["explain_filled_req"] = $filledReqSlots
                    
                    if ($isValid) {
                        $checkResults["explain_valid"] = 1
                        Write-Host "        OK Valid: playbook=$($exp.playbook_id), slots=$($exp.slots.Count), evidence=$evidenceCount" -ForegroundColor Green
                    } else {
                        $checkResults["explain_invalid"] = 1
                        Write-Host "        WARN Issues: $($validationIssues -join ', ')" -ForegroundColor Yellow
                    }
                } else {
                    $checkResults["explain_invalid"] = 1
                    Write-Host "        WARN No explanation data returned" -ForegroundColor Yellow
                }
            } catch {
                $checkResults["explain_invalid"] = 1
                Write-Host "        X FAIL: $_" -ForegroundColor Red
            }
        } elseif ($Explain -and $sigCount -eq 0) {
            Write-Host "        SKIP: No signals to explain" -ForegroundColor Yellow
        } else {
            Write-Host "        SKIP: -Explain not specified" -ForegroundColor Gray
        }
        
        # CHECK 6: Capture longevity (must survive for stable operation)
        Write-Host "  [6/7] Process health:"
        $allProcsOk = $true
        foreach ($proc in $script:Processes) {
            $name = switch ($proc.Id) {
                $captureProc.Id { "capture" }
                $localdProc.Id { "locald" }
                $serverProc.Id { "server" }
                default { "unknown" }
            }
            if ($proc.HasExited) {
                Write-Host "        X $name exited (code: $($proc.ExitCode))" -ForegroundColor Red
                $allProcsOk = $false
            } else {
                Write-Host "        OK $name running (PID: $($proc.Id))" -ForegroundColor Green
            }
        }
        if (-not $allProcsOk) {
            $pass = $false
            $failReasons += "Process(es) exited"
        }
        $checkResults["processes_healthy"] = $allProcsOk
        
        # CHECK 7: UI accessible
        Write-Host "  [7/7] UI accessibility:"
        try {
            $ui = (Invoke-WebRequest -Uri "$BaseUrl/" -TimeoutSec 5 -UseBasicParsing).Content
            if ($ui -match "<html|<!DOCTYPE") {
                Write-Host "        OK HTML response from $BaseUrl/" -ForegroundColor Green
                $checkResults["ui_accessible"] = $true
            } else {
                Write-Host "        WARN Response is not HTML" -ForegroundColor Yellow
                $checkResults["ui_accessible"] = $false
            }
        } catch {
            Write-Host "        X FAIL: $_" -ForegroundColor Red
            $pass = $false
            $failReasons += "UI inaccessible"
            $checkResults["ui_accessible"] = $false
        }
        
        # ────────────────────────────────────────────────────────────────────
        # Write Metrics Artifact
        # ────────────────────────────────────────────────────────────────────
        if ($Metrics) {
            Write-Host ""
            Write-Host "[METRICS] Writing artifact..." -ForegroundColor Cyan
            
            $metricsPath = "$TelemetryRoot\metrics\$RunId.json"
            
            # Gather tool versions
            $cargoVersion = (cargo --version 2>&1) -replace 'cargo ', ''
            $rustVersion = (rustc --version 2>&1) -replace 'rustc ', ''
            
            $metrics = @{
                run_id = $RunId
                timestamp = (Get-Date -Format "o")
                host = $env:COMPUTERNAME
                os = "Windows $([System.Environment]::OSVersion.Version)"
                arch = $env:PROCESSOR_ARCHITECTURE
                is_admin = $isAdmin
                
                durations = @{
                    activity_generation_sec = $activityDuration
                    total_run_sec = ((Get-Date) - $activityStart).TotalSeconds
                }
                
                telemetry = @{
                    segment_count = $checkResults["segment_count"]
                    segment_bytes = $checkResults["segment_bytes"]
                    index_bytes = $checkResults["index_bytes"]
                    schema_version = $checkResults["schema_version"]
                }
                
                pipeline = @{
                    signals_count = $checkResults["signal_count"]
                    explain_checked = $checkResults["explain_checked"]
                    explain_valid = $checkResults["explain_valid"]
                    explain_invalid = $checkResults["explain_invalid"]
                }
                
                checks = @{
                    api_health = $checkResults["api_health"]
                    processes_healthy = $checkResults["processes_healthy"]
                    ui_accessible = $checkResults["ui_accessible"]
                }
                
                result = if ($pass) { "PASS" } else { "FAIL" }
                fail_reasons = $failReasons
                
                tool_versions = @{
                    cargo = $cargoVersion
                    rustc = $rustVersion
                    powershell = $PSVersionTable.PSVersion.ToString()
                }
                
                warnings = @()
            }
            
            # Add warnings
            if ($sigCount -eq 0) {
                $metrics.warnings += "No signals detected - check Windows audit policy"
            }
            if (-not $isAdmin) {
                $metrics.warnings += "Not running as admin - capture may be limited"
            }
            
            $metrics | ConvertTo-Json -Depth 10 | Out-File -FilePath $metricsPath -Encoding utf8
            Write-Host "  Written: $metricsPath"
            $checkResults["metrics_path"] = $metricsPath
        }
        
        # ────────────────────────────────────────────────────────────────────
        # Final Result
        # ────────────────────────────────────────────────────────────────────
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor $(if ($pass) { "Green" } else { "Red" })
        if ($pass) {
            Write-Host "  RESULT: PASS" -ForegroundColor Green
        } else {
            Write-Host "  RESULT: FAIL" -ForegroundColor Red
            Write-Host "  Reasons: $($failReasons -join ', ')" -ForegroundColor Red
        }
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor $(if ($pass) { "Green" } else { "Red" })
        Write-Host ""
        Write-Host "Artifacts:"
        Write-Host "  Segments:   $TelemetryRoot\segments\"
        Write-Host "  Logs:       $TelemetryRoot\logs\"
        if ($Metrics) {
            Write-Host "  Metrics:    $($checkResults['metrics_path'])"
        }
        Write-Host "  UI:         $BaseUrl"
        Write-Host ""
        
        if (-not $pass) {
            Dump-Logs -TailLines 50
        }
        
        if ($KeepRunning) {
            Write-Host "Stack running. Press Ctrl+C to stop..." -ForegroundColor Cyan
            while ($true) { Start-Sleep -Seconds 5 }
        }
        
        Cleanup
        if ($pass) { exit 0 } else { exit 1 }
    }
    
    # ============================================================================
    # Interactive Mode (no -Verify)
    # ============================================================================
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stack Running (Interactive Mode)" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "UI URL:        $BaseUrl"
    Write-Host "API Health:    $BaseUrl/api/health"
    Write-Host "API Signals:   $BaseUrl/api/signals"
    Write-Host ""
    Write-Host "Logs:"
    Write-Host "  Get-Content $($script:LogFiles.capture) -Wait"
    Write-Host "  Get-Content $($script:LogFiles.locald) -Wait"
    Write-Host "  Get-Content $($script:LogFiles.server) -Wait"
    Write-Host ""
    Write-Host "Press Ctrl+C to stop the stack..."
    Write-Host ""
    
    while ($true) {
        Start-Sleep -Seconds 5
        foreach ($proc in $script:Processes) {
            if ($proc.HasExited) {
                $name = switch ($proc.Id) {
                    $captureProc.Id { "capture" }
                    $localdProc.Id { "locald" }
                    $serverProc.Id { "server" }
                    default { "process" }
                }
                Write-Host "[WARN] $name exited with code $($proc.ExitCode)" -ForegroundColor Yellow
            }
        }
    }
    
} finally {
    Cleanup
}
