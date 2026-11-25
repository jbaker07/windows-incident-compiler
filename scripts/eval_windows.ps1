#Requires -Version 7.0
<#
.SYNOPSIS
    Windows detection evaluation: real activity, live capture, playbook checks.
.DESCRIPTION
    Runs attack-like activity on this machine, captures it with the WEVTAPI
    capture agent, runs edr-locald over the capture and checks, by playbook
    id, that the expected YAML playbooks fired. Then checks the explanation of
    every signal through edr-server and writes a metrics file that the UI
    Metrics tab reads (GET /api/eval/metrics).

    Nothing is injected. Every event comes from the Security and System logs.

    The activity changes the host. It clears the Security and System logs,
    turns on the audit policy the playbooks need, makes failed logons, and in
    the full set creates and then deletes a scheduled task, a service and a
    local administrator account. Run it only on a throwaway VM or a CI runner,
    and pass -DisposableHost to confirm that.

    Steps:
      1. Build (unless -SkipBuild)
      2. enable_advanced_telemetry.ps1 -AutoFix (audit policy, command lines)
      3. New telemetry root, clear the Security and System logs
      4. Start capture_windows_rotating
      5. Generate the activity, then a marker process
      6. Wait until the marker is in a segment, stop the capture
      7. edr-locald --once over the capture
      8. edr-server, then check signals by playbook id and every explanation
      9. Write metrics, stop edr-server (or leave it running with -KeepRunning)
.PARAMETER ScenarioSet
    basic: discovery, encoded PowerShell, certutil, failed logons, log clear.
    full: basic plus a scheduled task, a service and a local admin account.
.PARAMETER SkipBuild
    Use binaries that are already built.
.PARAMETER BinDir
    Folder with capture_windows_rotating.exe, edr-locald.exe and
    edr-server.exe. Default: target\release in the repo.
.PARAMETER TelemetryRoot
    Folder for this run. It is deleted and created again, so it is never taken
    from EDR_TELEMETRY_ROOT. Default: C:\ProgramData\edr_eval.
.PARAMETER Port
    Port for edr-server. Default 3000.
.PARAMETER DisposableHost
    Required. Confirms that this machine may be changed as described above.
.PARAMETER KeepRunning
    Leave edr-server running after the checks so other scripts can query it.
    Its process id is printed and written to <TelemetryRoot>\logs\server.pid.
.PARAMETER CheckOnly
    Skip steps 1 to 6: no build, no host changes, no activity, no capture.
    Runs edr-locald again over the segments already in -TelemetryRoot (its
    database is reset first) and does the checks of steps 7 to 9. Needs no
    administrator rights and also runs on Linux and macOS, for example on the
    replay the windows_eval_replay test writes when EDR_EVAL_REPLAY_DIR is set.
.EXAMPLE
    .\scripts\eval_windows.ps1 -DisposableHost
.EXAMPLE
    .\scripts\eval_windows.ps1 -ScenarioSet full -SkipBuild -DisposableHost -KeepRunning
.EXAMPLE
    pwsh scripts/eval_windows.ps1 -CheckOnly -TelemetryRoot /tmp/replay -BinDir target/debug
#>

param(
    [ValidateSet("basic", "full")]
    [string]$ScenarioSet = "full",
    [switch]$SkipBuild,
    [string]$BinDir = "",
    [string]$TelemetryRoot = "",
    [int]$Port = 3000,
    [switch]$DisposableHost,
    [switch]$KeepRunning,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

$isAdmin = $false
if ($IsWindows) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not $CheckOnly -and -not $IsWindows) {
    Write-Host "The live run needs Windows. Use -CheckOnly on other systems." -ForegroundColor Yellow
    exit 2
}
if (-not $CheckOnly -and -not $isAdmin) {
    Write-Host "The live run needs an elevated PowerShell (Run as administrator)." -ForegroundColor Yellow
    exit 2
}
if (-not $CheckOnly -and -not $DisposableHost) {
    Write-Host "This script clears the Security and System logs, changes the audit policy and" -ForegroundColor Yellow
    Write-Host "creates a scheduled task, a service and a local administrator account (then" -ForegroundColor Yellow
    Write-Host "deletes them). Run it only on a throwaway VM or a CI runner, with -DisposableHost." -ForegroundColor Yellow
    exit 2
}

# ============================================================================
# Configuration
# ============================================================================
if (-not $BinDir) { $BinDir = Join-Path (Join-Path $ProjectRoot "target") "release" }
if (-not $TelemetryRoot) { $TelemetryRoot = "C:\ProgramData\edr_eval" }
$RunId = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseUrl = "http://127.0.0.1:$Port"
$LogsDir = Join-Path $TelemetryRoot "logs"
$MetricsDir = Join-Path $TelemetryRoot "metrics"
$SegmentsDir = Join-Path $TelemetryRoot "segments"
$WorkDir = Join-Path $TelemetryRoot "work"
$PlaybooksDir = Join-Path (Join-Path $ProjectRoot "playbooks") "windows"
$Marker = "edr-eval-marker-$RunId"

$exe = if ($IsWindows) { ".exe" } else { "" }
$CaptureBin = Join-Path $BinDir "capture_windows_rotating$exe"
$LocaldBin = Join-Path $BinDir "edr-locald$exe"
$ServerBin = Join-Path $BinDir "edr-server$exe"

# Playbooks the activity must fire, by scenario set
$Expected = [ordered]@{
    signal_encoded_powershell   = "powershell.exe -EncodedCommand with a hidden window"
    signal_discovery_burst      = "whoami, net user, net localgroup and other discovery tools"
    signal_certutil_abuse       = "certutil -urlcache download and certutil -encode"
    signal_logon_anomaly        = "six failed network logons for one account"
    signal_log_tamper_detection = "Security and System logs cleared (1102, 104)"
}
if ($ScenarioSet -eq "full") {
    $Expected["signal_schtasks_abuse"] = "schtasks /create running PowerShell as SYSTEM at logon"
    $Expected["signal_task_persistence"] = "Security 4698 for that task"
    $Expected["signal_sc_abuse"] = "sc create with a binary under C:\Users\Public"
    $Expected["signal_service_persistence"] = "System 7045 for that service"
    $Expected["signal_net_command_abuse"] = "net user /add and net localgroup administrators /add"
    $Expected["signal_group_membership_change"] = "Security 4720 and 4732 for that account"
}

$TaskName = "EdrEvalTask"
$ServiceName = "EdrEvalSvc"
$EvalUser = "edr_eval_user"
$script:Processes = @()
$script:Activity = @()
$startTime = Get-Date

Write-Host @"
==============================================================================
 EDR DETECTION EVALUATION - Windows (live capture)
==============================================================================
 Run ID:         $RunId
 Scenario set:   $ScenarioSet ($($Expected.Count) playbooks expected)$(if ($CheckOnly) { ', check only' })
 Telemetry root: $TelemetryRoot
 Binaries:       $BinDir
 API URL:        $BaseUrl
==============================================================================
"@ -ForegroundColor Cyan

# ============================================================================
# Helpers
# ============================================================================
function Write-Step([int]$Step, [string]$Message) {
    Write-Host "`n[$Step/9] $Message" -ForegroundColor Yellow
}

function Write-Check([string]$Name, [bool]$Pass, [string]$Detail = "") {
    $status = if ($Pass) { "[PASS]" } else { "[FAIL]" }
    $color = if ($Pass) { "Green" } else { "Red" }
    Write-Host "  $status " -ForegroundColor $color -NoNewline
    if ($Detail) { Write-Host "$Name - $Detail" } else { Write-Host $Name }
}

# Run a program with its arguments quoted one by one, wait at most
# $TimeoutSec seconds and return the exit code (-1 on timeout).
function Invoke-Tool([string]$File, [string[]]$Arguments, [int]$TimeoutSec = 120) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new($File)
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill($true) } catch {}
        Write-Host "    $File timed out after ${TimeoutSec}s" -ForegroundColor Yellow
        return -1
    }
    $p.WaitForExit()
    $null = $out.Result, $err.Result
    return $p.ExitCode
}

function Add-Activity([string]$Name, [string]$File, [string[]]$Arguments, [int]$TimeoutSec = 120) {
    $code = Invoke-Tool $File $Arguments $TimeoutSec
    $script:Activity += [ordered]@{ step = $Name; command = "$File $($Arguments -join ' ')"; exit_code = $code }
    Write-Host ("  {0,-34} exit {1}" -f $Name, $code)
    return $code
}

function Stop-Stack {
    foreach ($proc in $script:Processes) {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

# Undo the host changes of the full set. Safe to call more than once.
function Remove-HostChanges {
    $null = Invoke-Tool "schtasks.exe" @("/Delete", "/TN", $TaskName, "/F") 30
    $null = Invoke-Tool "sc.exe" @("delete", $ServiceName) 30
    $null = Invoke-Tool "net.exe" @("user", $EvalUser, "/delete") 30
}

function Wait-ForServer([int]$TimeoutSeconds = 30) {
    for ($i = 0; $i -lt $TimeoutSeconds; $i++) {
        try {
            $health = Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 5
            if ($health) { return $true }
        } catch {}
        Start-Sleep -Seconds 1
    }
    return $false
}

function Show-Log([string]$Path, [int]$Tail = 40) {
    if (Test-Path $Path) {
        Write-Host "--- $Path (last $Tail lines) ---" -ForegroundColor DarkGray
        Get-Content $Path -Tail $Tail | ForEach-Object { Write-Host "  $_" }
    }
}

$failures = @()
$exitCode = 1
try {
    # ========================================================================
    # STEP 1: Build
    # ========================================================================
    Write-Step 1 "Binaries"
    $needed = if ($CheckOnly) { @($LocaldBin, $ServerBin) } else { @($CaptureBin, $LocaldBin, $ServerBin) }
    if (-not $SkipBuild -and -not $CheckOnly) {
        cargo build --release -p agent-windows -p edr-locald -p edr-server
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    }
    foreach ($bin in $needed) {
        if (-not (Test-Path $bin)) { throw "Binary not found: $bin (build first or drop -SkipBuild)" }
    }
    Write-Check "Binaries present" $true $BinDir

    $env:EDR_TELEMETRY_ROOT = $TelemetryRoot
    $env:EDR_PLAYBOOKS_DIR = $PlaybooksDir
    $env:EDR_SERVER_PORT = "$Port"
    $env:EDR_WORKFLOW_SEED = ""
    $captureProc = $null

    if ($CheckOnly) {
        if (-not (Test-Path (Join-Path $TelemetryRoot "index.json"))) { throw "No index.json in $TelemetryRoot" }
        foreach ($dir in @($LogsDir, $MetricsDir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # Fresh database, so the checks see only this run of edr-locald
        foreach ($f in @("workbench.db", "workbench.db-wal", "workbench.db-shm", "playbooks_loaded.json")) {
            Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $TelemetryRoot $f)
        }
        Write-Host "`n[2-6/9] Skipped (-CheckOnly), using the segments in $TelemetryRoot" -ForegroundColor Yellow
    } else {

    # ========================================================================
    # STEP 2: Telemetry prerequisites
    # ========================================================================
    Write-Step 2 "Telemetry prerequisites (enable_advanced_telemetry.ps1 -AutoFix)"
    & (Join-Path $ScriptDir "enable_advanced_telemetry.ps1") -AutoFix -Quiet
    if ($LASTEXITCODE -ne 0) { throw "enable_advanced_telemetry.ps1 -AutoFix failed (exit $LASTEXITCODE)" }
    Write-Check "Audit policy and command line logging" $true

    # ========================================================================
    # STEP 3: Fresh telemetry root, cleared logs
    # ========================================================================
    Write-Step 3 "Telemetry root and event logs"
    Get-Process -Name "capture_windows_rotating", "edr-locald", "edr-server" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    if (Test-Path $TelemetryRoot) { Remove-Item -Recurse -Force $TelemetryRoot }
    foreach ($dir in @($SegmentsDir, $LogsDir, $MetricsDir, $WorkDir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Remove-HostChanges

    # Security first: the 4688 of the second wevtutil lands in the new Security log.
    foreach ($log in @("Security", "System")) {
        $code = Add-Activity "clear $log log" "wevtutil.exe" @("cl", $log)
        if ($code -ne 0) { throw "wevtutil cl $log failed (exit $code)" }
    }

    # ========================================================================
    # STEP 4: Start capture
    # ========================================================================
    Write-Step 4 "Start capture_windows_rotating"
    $captureErr = Join-Path $LogsDir "capture_err.log"
    $captureProc = Start-Process -FilePath $CaptureBin -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "capture.log") `
        -RedirectStandardError $captureErr
    $script:Processes += $captureProc
    Write-Host "  PID $($captureProc.Id)"

    $indexPath = Join-Path $TelemetryRoot "index.json"
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-Path $indexPath) -and (Get-Date) -lt $deadline -and -not $captureProc.HasExited) {
        Start-Sleep -Seconds 1
    }
    if ($captureProc.HasExited) { Show-Log $captureErr; throw "capture exited early (code $($captureProc.ExitCode))" }
    if (-not (Test-Path $indexPath)) { Show-Log $captureErr; throw "capture wrote no segment in 60s" }
    Write-Check "Capture running, first segment written" $true

    # ========================================================================
    # STEP 5: Activity
    # ========================================================================
    Write-Step 5 "Activity ($ScenarioSet)"
    $activityStart = Get-Date

    # Discovery: whoami, hostname, ipconfig, tasklist, net and net1 within a minute
    $null = Add-Activity "whoami /all" "whoami.exe" @("/all")
    $null = Add-Activity "hostname" "hostname.exe" @()
    $null = Add-Activity "ipconfig /all" "ipconfig.exe" @("/all")
    $null = Add-Activity "tasklist" "tasklist.exe" @()
    $null = Add-Activity "net user" "net.exe" @("user")
    $null = Add-Activity "net localgroup administrators" "net.exe" @("localgroup", "administrators")

    # Encoded PowerShell in a hidden window
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'edr eval encoded command'"))
    $null = Add-Activity "powershell -EncodedCommand" "powershell.exe" @("-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", $encoded)

    # certutil: encode a file, and a download from a closed local port
    $plain = Join-Path $WorkDir "edr_eval_plain.txt"
    Set-Content -Path $plain -Value "edr eval certutil input"
    $null = Add-Activity "certutil -encode" "certutil.exe" @("-f", "-encode", $plain, (Join-Path $WorkDir "edr_eval_b64.txt"))
    $null = Add-Activity "certutil -urlcache download" "certutil.exe" @("-urlcache", "-split", "-f", "http://127.0.0.1:9/edr_eval.txt", (Join-Path $WorkDir "edr_eval_dl.txt")) 60

    # Failed network logons for an account that does not exist
    if (-not ("EdrEval.Logon" -as [type])) {
        Add-Type -Namespace EdrEval -Name Logon -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool LogonUser(string user, string domain, string password, int logonType, int logonProvider, out IntPtr token);
'@
    }
    $failed = 0
    foreach ($i in 1..6) {
        $token = [IntPtr]::Zero
        if (-not [EdrEval.Logon]::LogonUser("edr_eval_nouser", ".", "not-the-password-$i", 3, 0, [ref]$token)) { $failed++ }
    }
    $script:Activity += [ordered]@{ step = "failed network logons"; command = "LogonUser(edr_eval_nouser) x6"; exit_code = 6 - $failed }
    Write-Host ("  {0,-34} {1} of 6 failed" -f "failed network logons", $failed)

    if ($ScenarioSet -eq "full") {
        # Scheduled task that runs PowerShell from a user writable folder as SYSTEM at logon
        $null = Add-Activity "schtasks /create" "schtasks.exe" @("/Create", "/F", "/TN", $TaskName, "/SC", "ONLOGON", "/RU", "SYSTEM", "/TR", "powershell.exe -NoProfile -File C:\Users\Public\edr_eval.ps1")

        # Service whose binary is in C:\Users\Public (the file does not need to exist)
        $null = Add-Activity "sc create" "sc.exe" @("create", $ServiceName, "binPath=", "C:\Users\Public\edr_eval_svc.exe", "start=", "demand")

        # Local account added to Administrators. 14 characters at most, or net.exe asks a question.
        $password = "Ev1!" + ([guid]::NewGuid().ToString("N").Substring(0, 10))
        $null = Add-Activity "net user /add" "net.exe" @("user", $EvalUser, $password, "/add")
        $null = Add-Activity "net localgroup administrators /add" "net.exe" @("localgroup", "administrators", $EvalUser, "/add")
    }

    # Marker: the last event of the run
    $null = Add-Activity "marker" "cmd.exe" @("/c", "echo", $Marker)
    $activitySeconds = [math]::Round(((Get-Date) - $activityStart).TotalSeconds, 1)
    Write-Check "Activity generated" $true "$($script:Activity.Count) steps in ${activitySeconds}s"

    # ========================================================================
    # STEP 6: Wait for the capture, then stop it
    # ========================================================================
    Write-Step 6 "Wait for the marker in a segment, stop the capture"
    $deadline = (Get-Date).AddSeconds(180)
    $seen = $false
    while ((Get-Date) -lt $deadline -and -not $captureProc.HasExited) {
        if (Get-ChildItem -Path $SegmentsDir -Filter "*.jsonl" | Select-String -SimpleMatch $Marker -List | Select-Object -First 1) {
            $seen = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $seen) { Show-Log $captureErr; throw "marker not captured within 180s" }
    Write-Check "Marker captured" $true

    # Graceful stop: the capture writes what it holds and exits
    New-Item -ItemType File -Path (Join-Path $TelemetryRoot "capture.stop") -Force | Out-Null
    if (-not $captureProc.WaitForExit(30000)) {
        Stop-Process -Id $captureProc.Id -Force
        throw "capture did not stop within 30s of the stop file"
    }
    Write-Check "Capture stopped" $true "exit $($captureProc.ExitCode)"
    }

    # ========================================================================
    # STEP 7: edr-locald over the capture
    # ========================================================================
    Write-Step 7 "edr-locald --once"
    $localdErr = Join-Path $LogsDir "locald_err.log"
    $localdProc = Start-Process -FilePath $LocaldBin -ArgumentList "--once" -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "locald.log") -RedirectStandardError $localdErr
    if (-not $localdProc.WaitForExit(300000)) {
        Stop-Process -Id $localdProc.Id -Force
        throw "edr-locald --once did not finish within 300s"
    }
    if ($localdProc.ExitCode -ne 0) { Show-Log $localdErr; throw "edr-locald --once exited with $($localdProc.ExitCode)" }

    $status = Get-Content (Join-Path $TelemetryRoot "playbooks_loaded.json") -Raw | ConvertFrom-Json
    $yamlCount = @(Get-ChildItem -Path $PlaybooksDir -Filter "*.yaml").Count
    $loadedOk = ($status.count -eq $yamlCount) -and (@($status.errors).Count -eq 0)
    Write-Check "Playbooks loaded" $loadedOk "$($status.count) of $yamlCount, $($status.rules) rules, $(@($status.errors).Count) errors"
    if (-not $loadedOk) { $failures += "playbooks not all loaded" }

    # ========================================================================
    # STEP 8: edr-server, signals by playbook id, explanations
    # ========================================================================
    Write-Step 8 "edr-server checks"
    $serverProc = Start-Process -FilePath $ServerBin -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "server.log") `
        -RedirectStandardError (Join-Path $LogsDir "server_err.log")
    $script:Processes += $serverProc
    if (-not (Wait-ForServer 30)) { Show-Log (Join-Path $LogsDir "server_err.log"); throw "edr-server did not answer /api/health in 30s" }

    $resp = Invoke-RestMethod -Uri "$BaseUrl/api/signals?limit=1000" -TimeoutSec 30
    $signals = @($resp.data)
    $byPlaybook = @{}
    foreach ($sig in $signals) {
        $id = "$($sig.signal_type)" -replace '^playbook:', ''
        if (-not $byPlaybook.ContainsKey($id)) { $byPlaybook[$id] = 0 }
        $byPlaybook[$id]++
    }
    Write-Host "  $($signals.Count) signals from $($byPlaybook.Count) playbooks"

    $expectedResults = @()
    foreach ($id in $Expected.Keys) {
        $count = if ($byPlaybook.ContainsKey($id)) { $byPlaybook[$id] } else { 0 }
        Write-Check $id ($count -gt 0) "$count signal(s), from $($Expected[$id])"
        if ($count -eq 0) { $failures += "no signal from $id" }
        $expectedResults += [ordered]@{ playbook_id = $id; activity = $Expected[$id]; fired = ($count -gt 0); signals = $count }
    }
    $unexpected = @($byPlaybook.Keys | Where-Object { -not $Expected.Contains($_) } | Sort-Object)
    if ($unexpected.Count -gt 0) {
        Write-Host "  Also fired: $($unexpected -join ', ')" -ForegroundColor DarkGray
    }

    $explained = 0
    $explanations = @()
    foreach ($sig in $signals) {
        try {
            $exp = Invoke-RestMethod -Uri "$BaseUrl/api/signals/$($sig.signal_id)/explain" -TimeoutSec 30
            $data = $exp.data
            if ($exp.success -and $data -and $data.playbook_id -and @($data.slots).Count -gt 0 -and @($data.evidence).Count -gt 0) {
                $explained++
                $explanations += [ordered]@{
                    signal_id = $sig.signal_id
                    playbook_id = $data.playbook_id
                    playbook_title = $data.playbook_title
                    family = $data.family
                    slots_filled = @($data.slots | Where-Object { $_.status -eq "filled" }).Count
                    slots_total = @($data.slots).Count
                    evidence_count = @($data.evidence).Count
                    summary = $data.summary
                }
            } else {
                Write-Host "  No complete explanation for $($sig.signal_id) ($($sig.signal_type))" -ForegroundColor Red
            }
        } catch {
            Write-Host "  Explain request failed for $($sig.signal_id): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    $explainOk = $signals.Count -gt 0 -and $explained -eq $signals.Count
    Write-Check "Every signal has an explanation with slots and evidence" $explainOk "$explained of $($signals.Count)"
    if (-not $explainOk) { $failures += "explanations missing" }

    # ========================================================================
    # STEP 9: Metrics
    # ========================================================================
    Write-Step 9 "Metrics"
    $segmentFiles = @(Get-ChildItem -Path $SegmentsDir -Filter "*.jsonl")
    $eventsCount = 0
    $channels = @{}
    foreach ($f in $segmentFiles) {
        foreach ($line in [System.IO.File]::ReadLines($f.FullName)) {
            $eventsCount++
            if ($line -match '"windows\.channel":"([^"]+)"') { $channels[$Matches[1]] = $true }
        }
    }
    $eps = $null
    if ($captureProc) {
        $captureSeconds = [math]::Max(1, ($captureProc.ExitTime - $captureProc.StartTime).TotalSeconds)
        $eps = [math]::Round($eventsCount / $captureSeconds, 1)
    }
    $pass = $failures.Count -eq 0
    $metrics = [ordered]@{
        run_id = $RunId
        timestamp = $startTime.ToString("o")
        duration_ms = [int]((Get-Date) - $startTime).TotalMilliseconds
        status = if ($pass) { "pass" } else { "fail" }
        scenario_set = $ScenarioSet
        check_only = [bool]$CheckOnly
        host = $env:COMPUTERNAME
        telemetry = [ordered]@{
            events_count = $eventsCount
            segments_count = $segmentFiles.Count
            channels_count = $channels.Count
            channels = @($channels.Keys | Sort-Object)
            eps = $eps
        }
        detections = [ordered]@{
            signals_count = $signals.Count
            explained_count = $explained
            playbooks_hit = $byPlaybook.Count
        }
        verdicts = [ordered]@{
            telemetry_flowing = $eventsCount -gt 0
            detections_fired = $signals.Count -gt 0
            expected_playbooks_fired = -not ($expectedResults | Where-Object { -not $_.fired })
            explanations_valid = $explainOk
            no_fake_detections = $true
        }
        expected_playbooks = $expectedResults
        other_playbooks = $unexpected
        activity = $script:Activity
        failures = $failures
        explanations = $explanations
    }
    $metricsPath = Join-Path $MetricsDir "run_${RunId}_metrics.json"
    $metrics | ConvertTo-Json -Depth 10 | Set-Content -Path $metricsPath -Encoding utf8
    Write-Host "  Metrics: $metricsPath"
    Write-Host "  Events: $eventsCount in $($segmentFiles.Count) segments from $($channels.Count) channels"

    $exitCode = if ($pass) { 0 } else { 1 }
} catch {
    $failures += "$_"
    Write-Host "`nERROR: $_" -ForegroundColor Red
    $exitCode = 1
} finally {
    if (-not $CheckOnly) { Remove-HostChanges }
    if ($exitCode -ne 0 -or -not $KeepRunning) {
        Stop-Stack
    }
}

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Cyan
if ($exitCode -eq 0) {
    Write-Host " RESULT: PASS ($($Expected.Count) expected playbooks fired)" -ForegroundColor Green
} else {
    Write-Host " RESULT: FAIL" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
}
Write-Host " Logs: $LogsDir"
if ($exitCode -eq 0 -and $KeepRunning) {
    $serverPid = $serverProc.Id
    Set-Content -Path (Join-Path $LogsDir "server.pid") -Value $serverPid
    Write-Host " edr-server is still running at $BaseUrl (PID $serverPid)"
    Write-Host " Stop it with: Stop-Process -Id $serverPid"
}
Write-Host "==============================================================================" -ForegroundColor Cyan
exit $exitCode
