# LocInt Stress Test Harness
# Rigorous, no-fake-data stress testing
# Usage: .\stress_runner.ps1 -Scenario <S1|S2|S3|S4|S5|S6|ALL>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("S1","S2","S3","S4","S5","S6","ALL")]
    [string]$Scenario = "ALL",
    
    [string]$ApiBase = "http://127.0.0.1:3000",
    [string]$OutputDir = ".\stress_results"
)

$ErrorActionPreference = "Continue"
$script:TestResults = @()

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "PASS"  { "Green" }
        "FAIL"  { "Red" }
        default { "White" }
    }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

function Invoke-ApiCall {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [object]$Body = $null,
        [int]$TimeoutSec = 30
    )
    
    $url = "$ApiBase$Endpoint"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $params = @{
            Uri = $url
            Method = $Method
            ContentType = "application/json"
            TimeoutSec = $TimeoutSec
        }
        
        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json -Depth 10)
        }
        
        $response = Invoke-RestMethod @params
        $stopwatch.Stop()
        
        return @{
            Success = $true
            Data = $response
            LatencyMs = $stopwatch.ElapsedMilliseconds
            StatusCode = 200
            Error = $null
        }
    }
    catch {
        $stopwatch.Stop()
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        
        return @{
            Success = $false
            Data = $null
            LatencyMs = $stopwatch.ElapsedMilliseconds
            StatusCode = $statusCode
            Error = $_.Exception.Message
        }
    }
}

function Wait-ForServer {
    param([int]$MaxWaitSec = 60)
    
    Write-Log "Waiting for server at $ApiBase..."
    $start = Get-Date
    
    while (((Get-Date) - $start).TotalSeconds -lt $MaxWaitSec) {
        $result = Invoke-ApiCall -Endpoint "/health"
        if ($result.Success) {
            Write-Log "Server is online" -Level "PASS"
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    
    Write-Log "Server did not respond within $MaxWaitSec seconds" -Level "ERROR"
    return $false
}

function Start-LocIntRun {
    param([string]$Preset = "extended", [int]$DurationMin = 5)
    
    Write-Log "Starting run with preset: $Preset, duration: $DurationMin min"
    
    $body = @{
        preset = $Preset
        duration_minutes = $DurationMin
    }
    
    $result = Invoke-ApiCall -Endpoint "/api/run/start" -Method "POST" -Body $body
    
    if ($result.Success -and $result.Data.success) {
        $runId = $result.Data.run_id
        Write-Log "Run started: $runId (latency: $($result.LatencyMs)ms)" -Level "PASS"
        return @{ Success = $true; RunId = $runId; LatencyMs = $result.LatencyMs }
    }
    else {
        Write-Log "Failed to start run: $($result.Error)" -Level "ERROR"
        return @{ Success = $false; RunId = $null; Error = $result.Error }
    }
}

function Stop-LocIntRun {
    Write-Log "Stopping run..."
    
    $result = Invoke-ApiCall -Endpoint "/api/run/stop" -Method "POST"
    
    if ($result.Success) {
        Write-Log "Run stopped (latency: $($result.LatencyMs)ms)" -Level "PASS"
        return @{ Success = $true; LatencyMs = $result.LatencyMs }
    }
    else {
        Write-Log "Failed to stop run: $($result.Error)" -Level "WARN"
        return @{ Success = $false; Error = $result.Error }
    }
}

function Get-RunStatus {
    $result = Invoke-ApiCall -Endpoint "/api/run/status"
    return $result
}

function Wait-ForCompile {
    param([string]$RunId, [int]$MaxWaitSec = 120)
    
    Write-Log "Waiting for compile to complete (max $MaxWaitSec sec)..."
    $start = Get-Date
    
    while (((Get-Date) - $start).TotalSeconds -lt $MaxWaitSec) {
        $result = Invoke-ApiCall -Endpoint "/api/runs/$RunId/coverage"
        
        if ($result.Success -and $result.Data.data) {
            $coverage = $result.Data.data
            $compileStatus = $coverage.compile_status
            $factsReady = $coverage.facts_ready
            
            Write-Log "Compile status: $compileStatus, facts_ready: $factsReady"
            
            if ($compileStatus -eq "finalized" -or $factsReady -eq $true) {
                Write-Log "Compile complete" -Level "PASS"
                return $true
            }
        }
        
        Start-Sleep -Seconds 2
    }
    
    Write-Log "Compile did not complete within $MaxWaitSec seconds" -Level "WARN"
    return $false
}

function Collect-RunDiagnostics {
    param([string]$RunId, [string]$ScenarioName)
    
    Write-Log "Collecting diagnostics for run $RunId..."
    
    $diagnostics = @{
        RunId = $RunId
        Scenario = $ScenarioName
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        Endpoints = @{}
        Errors = @()
    }
    
    # Collect from each endpoint
    $endpoints = @(
        @{ Name = "run_detail"; Path = "/api/runs/$RunId" }
        @{ Name = "coverage"; Path = "/api/runs/$RunId/coverage" }
        @{ Name = "state"; Path = "/api/runs/$RunId/state" }
        @{ Name = "next_steps"; Path = "/api/runs/$RunId/next_steps" }
        @{ Name = "facts"; Path = "/api/runs/$RunId/facts?limit=200" }
    )
    
    foreach ($ep in $endpoints) {
        $result = Invoke-ApiCall -Endpoint $ep.Path
        
        $diagnostics.Endpoints[$ep.Name] = @{
            Success = $result.Success
            LatencyMs = $result.LatencyMs
            StatusCode = $result.StatusCode
            Data = $result.Data
        }
        
        if (-not $result.Success) {
            $diagnostics.Errors += "$($ep.Name): $($result.Error)"
        }
        
        Write-Log "  $($ep.Name): $($result.StatusCode) ($($result.LatencyMs)ms)"
    }
    
    return $diagnostics
}

function Get-FactTypeHistogram {
    param([object]$CoverageData)
    
    if (-not $CoverageData -or -not $CoverageData.data) {
        return @{}
    }
    
    $factTypes = $CoverageData.data.fact_types
    if (-not $factTypes) {
        return @{}
    }
    
    $histogram = @{}
    foreach ($ft in $factTypes) {
        $histogram[$ft.fact_type] = $ft.count
    }
    
    return $histogram
}

function Test-EvidencePointers {
    param([object]$FactsData, [int]$SampleSize = 3)
    
    $results = @()
    
    if (-not $FactsData -or -not $FactsData.data -or -not $FactsData.data.facts) {
        return @{ Checked = 0; Valid = 0; Issues = @("No facts data available") }
    }
    
    $facts = $FactsData.data.facts
    $toCheck = [Math]::Min($SampleSize, $facts.Count)
    
    for ($i = 0; $i -lt $toCheck; $i++) {
        $fact = $facts[$i]
        $ptr = $fact.evidence_ptr
        
        $check = @{
            FactType = $fact.fact_type
            HasPointer = ($null -ne $ptr)
            PointerValid = $false
            Details = ""
        }
        
        if ($ptr) {
            # Check pointer structure
            $hasStreamId = ($null -ne $ptr.stream_id -and $ptr.stream_id -ne "")
            $hasSegmentId = ($null -ne $ptr.segment_id)
            $hasRecordIndex = ($null -ne $ptr.record_index)
            
            $check.PointerValid = $hasStreamId -and ($hasSegmentId -or $hasRecordIndex)
            $check.Details = "stream=$($ptr.stream_id), seg=$($ptr.segment_id), rec=$($ptr.record_index)"
        }
        
        $results += $check
    }
    
    $valid = ($results | Where-Object { $_.PointerValid }).Count
    
    return @{
        Checked = $results.Count
        Valid = $valid
        Issues = ($results | Where-Object { -not $_.PointerValid } | ForEach-Object { $_.FactType + ": " + $_.Details })
    }
}

function Save-ScenarioResult {
    param([object]$Result, [string]$ScenarioName)
    
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = Join-Path $OutputDir "${ScenarioName}_${ts}.json"
    
    $Result | ConvertTo-Json -Depth 20 | Set-Content -Path $filename -Encoding UTF8
    Write-Log "Results saved to: $filename"
    
    return $filename
}

function Format-ScenarioReport {
    param([object]$Result)
    
    $report = @"

================================================================================
SCENARIO: $($Result.Scenario)
================================================================================
Run ID:     $($Result.RunId)
Status:     $($Result.Status)
Duration:   $($Result.DurationSec) seconds

METRICS:
  Events:   $($Result.Metrics.Events)
  Facts:    $($Result.Metrics.Facts)
  Signals:  $($Result.Metrics.Signals)

LATENCY SUMMARY:
"@
    
    foreach ($ep in $Result.EndpointLatencies.Keys) {
        $lat = $Result.EndpointLatencies[$ep]
        $report += "`n  $($ep.PadRight(20)): $($lat)ms"
    }
    
    $report += "`n`nFACT TYPE HISTOGRAM (Top 10):"
    $sorted = $Result.FactTypeHistogram.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    foreach ($item in $sorted) {
        $report += "`n  $($item.Key.PadRight(25)): $($item.Value)"
    }
    
    $report += "`n`nEVIDENCE POINTER CHECK:"
    $report += "`n  Checked: $($Result.EvidenceCheck.Checked)"
    $report += "`n  Valid:   $($Result.EvidenceCheck.Valid)"
    if ($Result.EvidenceCheck.Issues.Count -gt 0) {
        $report += "`n  Issues:"
        foreach ($issue in $Result.EvidenceCheck.Issues) {
            $report += "`n    - $issue"
        }
    }
    
    $report += "`n`nERRORS:"
    if ($Result.Errors.Count -eq 0) {
        $report += "`n  None"
    }
    else {
        foreach ($err in $Result.Errors) {
            $report += "`n  - $err"
        }
    }
    
    $report += "`n`nPASS/FAIL: $($Result.Status)"
    $report += "`n================================================================================"
    
    return $report
}

# ============================================================================
# SCENARIO IMPLEMENTATIONS
# ============================================================================

function Run-S1-HighVolumeExec {
    Write-Log "=" * 60
    Write-Log "S1: HIGH VOLUME EXEC (2000 process spawns)"
    Write-Log "=" * 60
    
    $startTime = Get-Date
    $errors = @()
    
    # Start run
    $runResult = Start-LocIntRun -Preset "extended" -DurationMin 10
    if (-not $runResult.Success) {
        return @{ Scenario = "S1"; Status = "FAIL"; Error = "Failed to start run" }
    }
    $runId = $runResult.RunId
    
    # Wait for capture to initialize
    Start-Sleep -Seconds 3
    
    # Execute high volume process spawns
    Write-Log "Spawning 2000 processes..."
    $spawnStart = Get-Date
    
    # Use cmd batch for speed
    $batchCmd = "for /l %i in (1,1,2000) do @cmd /c echo x > nul 2>&1"
    cmd /c $batchCmd 2>&1 | Out-Null
    
    $spawnDuration = ((Get-Date) - $spawnStart).TotalSeconds
    Write-Log "Process spawns completed in $([math]::Round($spawnDuration, 2)) seconds"
    
    # Let events settle
    Write-Log "Waiting 10 seconds for events to settle..."
    Start-Sleep -Seconds 10
    
    # Stop run
    $stopResult = Stop-LocIntRun
    
    # Wait for compile
    $compileOk = Wait-ForCompile -RunId $runId -MaxWaitSec 180
    if (-not $compileOk) {
        $errors += "Compile did not complete"
    }
    
    # Collect diagnostics
    $diag = Collect-RunDiagnostics -RunId $runId -ScenarioName "S1"
    
    # Extract metrics
    $coverage = $diag.Endpoints.coverage.Data
    $metrics = @{
        Events = $coverage.data.events_total
        Facts = $coverage.data.facts_total
        Signals = $coverage.data.signals_total
    }
    
    # Latencies
    $latencies = @{}
    foreach ($ep in $diag.Endpoints.Keys) {
        $latencies[$ep] = $diag.Endpoints[$ep].LatencyMs
    }
    
    # Fact histogram
    $histogram = Get-FactTypeHistogram -CoverageData $coverage
    
    # Evidence check
    $factsData = $diag.Endpoints.facts.Data
    $evidenceCheck = Test-EvidencePointers -FactsData $factsData
    
    $errors += $diag.Errors
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    # Determine pass/fail
    $status = "PASS"
    if ($errors.Count -gt 0) { $status = "WARN" }
    if ($metrics.Events -lt 100) { $status = "FAIL"; $errors += "Too few events captured (<100)" }
    if ($evidenceCheck.Valid -lt $evidenceCheck.Checked) { $status = "WARN"; $errors += "Some evidence pointers invalid" }
    
    $result = @{
        Scenario = "S1-HighVolumeExec"
        RunId = $runId
        Status = $status
        StartTime = $startTime
        EndTime = $endTime
        DurationSec = [math]::Round($duration, 2)
        SpawnDurationSec = [math]::Round($spawnDuration, 2)
        Metrics = $metrics
        EndpointLatencies = $latencies
        FactTypeHistogram = $histogram
        EvidenceCheck = $evidenceCheck
        Errors = $errors
        RawDiagnostics = $diag
    }
    
    Write-Host (Format-ScenarioReport -Result $result)
    Save-ScenarioResult -Result $result -ScenarioName "S1"
    
    return $result
}

function Run-S2-HighVolumeDNS {
    Write-Log "=" * 60
    Write-Log "S2: HIGH VOLUME DNS (500 nslookups)"
    Write-Log "=" * 60
    
    $startTime = Get-Date
    $errors = @()
    
    # Start run
    $runResult = Start-LocIntRun -Preset "extended" -DurationMin 10
    if (-not $runResult.Success) {
        return @{ Scenario = "S2"; Status = "FAIL"; Error = "Failed to start run" }
    }
    $runId = $runResult.RunId
    
    Start-Sleep -Seconds 3
    
    # Execute DNS lookups
    Write-Log "Performing 500 DNS lookups..."
    $dnsStart = Get-Date
    
    $domains = @("example.com", "microsoft.com", "google.com", "github.com", "cloudflare.com")
    
    for ($i = 1; $i -le 500; $i++) {
        $domain = $domains[$i % $domains.Count]
        nslookup $domain 2>&1 | Out-Null
        
        if ($i % 100 -eq 0) {
            Write-Log "  Completed $i DNS lookups..."
        }
    }
    
    $dnsDuration = ((Get-Date) - $dnsStart).TotalSeconds
    Write-Log "DNS lookups completed in $([math]::Round($dnsDuration, 2)) seconds"
    
    Start-Sleep -Seconds 10
    
    $stopResult = Stop-LocIntRun
    $compileOk = Wait-ForCompile -RunId $runId -MaxWaitSec 120
    if (-not $compileOk) { $errors += "Compile did not complete" }
    
    $diag = Collect-RunDiagnostics -RunId $runId -ScenarioName "S2"
    
    $coverage = $diag.Endpoints.coverage.Data
    $metrics = @{
        Events = $coverage.data.events_total
        Facts = $coverage.data.facts_total
        Signals = $coverage.data.signals_total
    }
    
    $latencies = @{}
    foreach ($ep in $diag.Endpoints.Keys) {
        $latencies[$ep] = $diag.Endpoints[$ep].LatencyMs
    }
    
    $histogram = Get-FactTypeHistogram -CoverageData $coverage
    $factsData = $diag.Endpoints.facts.Data
    $evidenceCheck = Test-EvidencePointers -FactsData $factsData
    
    $errors += $diag.Errors
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    $status = "PASS"
    if ($errors.Count -gt 0) { $status = "WARN" }
    if ($metrics.Facts -lt 10) { $status = "FAIL"; $errors += "Too few facts extracted" }
    
    $result = @{
        Scenario = "S2-HighVolumeDNS"
        RunId = $runId
        Status = $status
        StartTime = $startTime
        EndTime = $endTime
        DurationSec = [math]::Round($duration, 2)
        DnsLookupDurationSec = [math]::Round($dnsDuration, 2)
        Metrics = $metrics
        EndpointLatencies = $latencies
        FactTypeHistogram = $histogram
        EvidenceCheck = $evidenceCheck
        Errors = $errors
        RawDiagnostics = $diag
    }
    
    Write-Host (Format-ScenarioReport -Result $result)
    Save-ScenarioResult -Result $result -ScenarioName "S2"
    
    return $result
}

function Run-S3-RegistryChurn {
    Write-Log "=" * 60
    Write-Log "S3: REGISTRY CHURN (500 HKCU keys)"
    Write-Log "=" * 60
    
    $startTime = Get-Date
    $errors = @()
    $regBasePath = "HKCU:\Software\LocIntStress"
    
    # Cleanup any previous test keys
    if (Test-Path $regBasePath) {
        Remove-Item -Path $regBasePath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Start run
    $runResult = Start-LocIntRun -Preset "extended" -DurationMin 10
    if (-not $runResult.Success) {
        return @{ Scenario = "S3"; Status = "FAIL"; Error = "Failed to start run" }
    }
    $runId = $runResult.RunId
    
    Start-Sleep -Seconds 3
    
    # Create base key
    New-Item -Path $regBasePath -Force | Out-Null
    
    Write-Log "Creating and deleting 500 registry keys..."
    $regStart = Get-Date
    
    # Create 500 keys
    for ($i = 1; $i -le 500; $i++) {
        $keyPath = "$regBasePath\k$i"
        New-Item -Path $keyPath -Force | Out-Null
        Set-ItemProperty -Path $keyPath -Name "TestValue" -Value "StressTest$i" -ErrorAction SilentlyContinue
        
        if ($i % 100 -eq 0) {
            Write-Log "  Created $i keys..."
        }
    }
    
    # Delete all keys
    Write-Log "Deleting keys..."
    for ($i = 1; $i -le 500; $i++) {
        $keyPath = "$regBasePath\k$i"
        Remove-Item -Path $keyPath -Force -ErrorAction SilentlyContinue
    }
    
    # Cleanup base
    Remove-Item -Path $regBasePath -Recurse -Force -ErrorAction SilentlyContinue
    
    $regDuration = ((Get-Date) - $regStart).TotalSeconds
    Write-Log "Registry operations completed in $([math]::Round($regDuration, 2)) seconds"
    
    Start-Sleep -Seconds 10
    
    $stopResult = Stop-LocIntRun
    $compileOk = Wait-ForCompile -RunId $runId -MaxWaitSec 120
    if (-not $compileOk) { $errors += "Compile did not complete" }
    
    $diag = Collect-RunDiagnostics -RunId $runId -ScenarioName "S3"
    
    $coverage = $diag.Endpoints.coverage.Data
    $metrics = @{
        Events = $coverage.data.events_total
        Facts = $coverage.data.facts_total
        Signals = $coverage.data.signals_total
    }
    
    $latencies = @{}
    foreach ($ep in $diag.Endpoints.Keys) {
        $latencies[$ep] = $diag.Endpoints[$ep].LatencyMs
    }
    
    $histogram = Get-FactTypeHistogram -CoverageData $coverage
    $factsData = $diag.Endpoints.facts.Data
    $evidenceCheck = Test-EvidencePointers -FactsData $factsData
    
    $errors += $diag.Errors
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    $status = "PASS"
    if ($errors.Count -gt 0) { $status = "WARN" }
    
    $result = @{
        Scenario = "S3-RegistryChurn"
        RunId = $runId
        Status = $status
        StartTime = $startTime
        EndTime = $endTime
        DurationSec = [math]::Round($duration, 2)
        RegistryOpDurationSec = [math]::Round($regDuration, 2)
        Metrics = $metrics
        EndpointLatencies = $latencies
        FactTypeHistogram = $histogram
        EvidenceCheck = $evidenceCheck
        Errors = $errors
        RawDiagnostics = $diag
    }
    
    Write-Host (Format-ScenarioReport -Result $result)
    Save-ScenarioResult -Result $result -ScenarioName "S3"
    
    return $result
}

function Run-S4-ApiSpamDuringCompile {
    Write-Log "=" * 60
    Write-Log "S4: API SPAM DURING COMPILE"
    Write-Log "=" * 60
    
    $startTime = Get-Date
    $errors = @()
    $apiCallResults = @()
    
    # Start run
    $runResult = Start-LocIntRun -Preset "extended" -DurationMin 5
    if (-not $runResult.Success) {
        return @{ Scenario = "S4"; Status = "FAIL"; Error = "Failed to start run" }
    }
    $runId = $runResult.RunId
    
    # Generate some activity
    Write-Log "Generating activity..."
    cmd /c "for /l %i in (1,1,100) do @cmd /c echo x > nul" 2>&1 | Out-Null
    
    Start-Sleep -Seconds 5
    
    # Stop run and immediately start API spam
    Write-Log "Stopping run and spamming API for 30 seconds..."
    $stopResult = Stop-LocIntRun
    
    $spamStart = Get-Date
    $spamDurationSec = 30
    $callCount = 0
    $errorCount = 0
    $latencies = @()
    
    while (((Get-Date) - $spamStart).TotalSeconds -lt $spamDurationSec) {
        # Call coverage endpoint
        $r1 = Invoke-ApiCall -Endpoint "/api/runs/$runId/coverage" -TimeoutSec 5
        $callCount++
        $latencies += $r1.LatencyMs
        if (-not $r1.Success) { $errorCount++ }
        
        # Call facts endpoint
        $r2 = Invoke-ApiCall -Endpoint "/api/runs/$runId/facts?limit=50" -TimeoutSec 5
        $callCount++
        $latencies += $r2.LatencyMs
        if (-not $r2.Success) { $errorCount++ }
        
        # Call state endpoint
        $r3 = Invoke-ApiCall -Endpoint "/api/runs/$runId/state" -TimeoutSec 5
        $callCount++
        $latencies += $r3.LatencyMs
        if (-not $r3.Success) { $errorCount++ }
        
        # Small delay to not completely overwhelm
        Start-Sleep -Milliseconds 100
    }
    
    $spamDuration = ((Get-Date) - $spamStart).TotalSeconds
    Write-Log "API spam completed: $callCount calls, $errorCount errors"
    
    # Calculate latency stats
    $avgLatency = ($latencies | Measure-Object -Average).Average
    $maxLatency = ($latencies | Measure-Object -Maximum).Maximum
    $minLatency = ($latencies | Measure-Object -Minimum).Minimum
    
    # Wait for compile to finish
    Start-Sleep -Seconds 5
    $compileOk = Wait-ForCompile -RunId $runId -MaxWaitSec 120
    if (-not $compileOk) { $errors += "Compile did not complete after API spam" }
    
    $diag = Collect-RunDiagnostics -RunId $runId -ScenarioName "S4"
    
    $coverage = $diag.Endpoints.coverage.Data
    $metrics = @{
        Events = $coverage.data.events_total
        Facts = $coverage.data.facts_total
        Signals = $coverage.data.signals_total
    }
    
    $histogram = Get-FactTypeHistogram -CoverageData $coverage
    $factsData = $diag.Endpoints.facts.Data
    $evidenceCheck = Test-EvidencePointers -FactsData $factsData
    
    $errors += $diag.Errors
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    $status = "PASS"
    if ($errorCount -gt ($callCount * 0.1)) { $status = "WARN"; $errors += "More than 10% API calls failed" }
    if ($maxLatency -gt 5000) { $status = "WARN"; $errors += "Max latency exceeded 5s" }
    if (-not $compileOk) { $status = "FAIL" }
    
    $endpointLatencies = @{}
    foreach ($ep in $diag.Endpoints.Keys) {
        $endpointLatencies[$ep] = $diag.Endpoints[$ep].LatencyMs
    }
    
    $result = @{
        Scenario = "S4-ApiSpamDuringCompile"
        RunId = $runId
        Status = $status
        StartTime = $startTime
        EndTime = $endTime
        DurationSec = [math]::Round($duration, 2)
        ApiSpam = @{
            TotalCalls = $callCount
            ErrorCount = $errorCount
            ErrorRate = [math]::Round(($errorCount / $callCount) * 100, 2)
            AvgLatencyMs = [math]::Round($avgLatency, 2)
            MaxLatencyMs = $maxLatency
            MinLatencyMs = $minLatency
        }
        Metrics = $metrics
        EndpointLatencies = $endpointLatencies
        FactTypeHistogram = $histogram
        EvidenceCheck = $evidenceCheck
        Errors = $errors
        RawDiagnostics = $diag
    }
    
    Write-Host (Format-ScenarioReport -Result $result)
    Write-Log "API Spam Stats: $callCount calls, Avg: $([math]::Round($avgLatency,2))ms, Max: ${maxLatency}ms, Errors: $errorCount"
    
    Save-ScenarioResult -Result $result -ScenarioName "S4"
    
    return $result
}

function Run-S5-RestartLocIntMidRun {
    Write-Log "=" * 60
    Write-Log "S5: RESTART LOCINT MID-RUN (Orphan Recovery)"
    Write-Log "=" * 60
    
    $startTime = Get-Date
    $errors = @()
    
    # Start run
    $runResult = Start-LocIntRun -Preset "extended" -DurationMin 10
    if (-not $runResult.Success) {
        return @{ Scenario = "S5"; Status = "FAIL"; Error = "Failed to start run" }
    }
    $runId = $runResult.RunId
    
    # Generate some activity
    Write-Log "Generating activity..."
    cmd /c "for /l %i in (1,1,50) do @cmd /c echo test > nul" 2>&1 | Out-Null
    
    Start-Sleep -Seconds 5
    
    # Kill locint process
    Write-Log "Killing locint.exe process..."
    $locintProcs = Get-Process -Name "locint" -ErrorAction SilentlyContinue
    
    if ($locintProcs) {
        $locintProcs | Stop-Process -Force
        Write-Log "Killed $($locintProcs.Count) locint process(es)"
    }
    else {
        Write-Log "No locint process found" -Level "WARN"
        $errors += "Could not find locint process to kill"
    }
    
    Start-Sleep -Seconds 3
    
    # Restart locint
    Write-Log "Restarting locint..."
    $locintPath = Join-Path $PSScriptRoot "..\target\release\locint.exe"
    if (-not (Test-Path $locintPath)) {
        $locintPath = "locint.exe"
    }
    
    try {
        Start-Process -FilePath $locintPath -WindowStyle Hidden
        Write-Log "Locint restart initiated"
    }
    catch {
        $errors += "Failed to restart locint: $_"
        Write-Log "Failed to restart locint: $_" -Level "ERROR"
    }
    
    # Wait for server to come back
    $serverBack = Wait-ForServer -MaxWaitSec 30
    if (-not $serverBack) {
        $errors += "Server did not come back online"
        return @{ Scenario = "S5"; Status = "FAIL"; Errors = $errors }
    }
    
    Start-Sleep -Seconds 5
    
    # Check run status - should be abandoned or orphaned
    Write-Log "Checking run status after restart..."
    $runDetail = Invoke-ApiCall -Endpoint "/api/runs/$runId"
    
    $runStatus = "unknown"
    if ($runDetail.Success -and $runDetail.Data.data) {
        $runStatus = $runDetail.Data.data.status
        Write-Log "Run $runId status: $runStatus"
    }
    
    # Also check if there's an active run
    $statusResult = Get-RunStatus
    $isRunning = $false
    if ($statusResult.Success -and $statusResult.Data.is_running) {
        $isRunning = $true
        Write-Log "Server reports a run is still active" -Level "WARN"
    }
    
    # Collect diagnostics
    $diag = Collect-RunDiagnostics -RunId $runId -ScenarioName "S5"
    
    $coverage = $diag.Endpoints.coverage.Data
    $metrics = @{
        Events = if ($coverage.data) { $coverage.data.events_total } else { 0 }
        Facts = if ($coverage.data) { $coverage.data.facts_total } else { 0 }
        Signals = if ($coverage.data) { $coverage.data.signals_total } else { 0 }
    }
    
    $latencies = @{}
    foreach ($ep in $diag.Endpoints.Keys) {
        $latencies[$ep] = $diag.Endpoints[$ep].LatencyMs
    }
    
    $histogram = Get-FactTypeHistogram -CoverageData $coverage
    $factsData = $diag.Endpoints.facts.Data
    $evidenceCheck = Test-EvidencePointers -FactsData $factsData
    
    $errors += $diag.Errors
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    # Determine status
    $status = "PASS"
    if ($errors.Count -gt 0) { $status = "WARN" }
    if (-not $serverBack) { $status = "FAIL" }
    
    $result = @{
        Scenario = "S5-RestartMidRun"
        RunId = $runId
        Status = $status
        StartTime = $startTime
        EndTime = $endTime
        DurationSec = [math]::Round($duration, 2)
        OrphanRecovery = @{
            RunStatusAfterRestart = $runStatus
            ServerReportedRunning = $isRunning
            ServerCameBack = $serverBack
        }
        Metrics = $metrics
        EndpointLatencies = $latencies
        FactTypeHistogram = $histogram
        EvidenceCheck = $evidenceCheck
        Errors = $errors
        RawDiagnostics = $diag
    }
    
    Write-Host (Format-ScenarioReport -Result $result)
    Write-Log "Orphan Recovery: run_status=$runStatus, server_running=$isRunning"
    
    Save-ScenarioResult -Result $result -ScenarioName "S5"
    
    return $result
}

function Run-S6-KillLocaldMidCompile {
    Write-Log "=" * 60
    Write-Log "S6: KILL LOCALD MID-COMPILE"
    Write-Log "=" * 60
    
    $startTime = Get-Date
    $errors = @()
    
    # Start run
    $runResult = Start-LocIntRun -Preset "extended" -DurationMin 5
    if (-not $runResult.Success) {
        return @{ Scenario = "S6"; Status = "FAIL"; Error = "Failed to start run" }
    }
    $runId = $runResult.RunId
    
    # Generate substantial activity
    Write-Log "Generating activity..."
    cmd /c "for /l %i in (1,1,200) do @cmd /c echo test > nul" 2>&1 | Out-Null
    
    Start-Sleep -Seconds 5
    
    # Stop run (triggers compile)
    Write-Log "Stopping run to trigger compile..."
    $stopResult = Stop-LocIntRun
    
    # Immediately kill locald
    Start-Sleep -Milliseconds 500
    Write-Log "Killing edr-locald process mid-compile..."
    
    $localdProcs = Get-Process -Name "edr-locald" -ErrorAction SilentlyContinue
    $killedCount = 0
    
    if ($localdProcs) {
        $localdProcs | Stop-Process -Force
        $killedCount = $localdProcs.Count
        Write-Log "Killed $killedCount locald process(es)"
    }
    else {
        Write-Log "No edr-locald process found" -Level "WARN"
        $errors += "Could not find locald process to kill"
    }
    
    Start-Sleep -Seconds 3
    
    # Check coverage state immediately
    Write-Log "Checking coverage state after locald kill..."
    $coverageAfterKill = Invoke-ApiCall -Endpoint "/api/runs/$runId/coverage"
    
    $compileStatusAfterKill = "unknown"
    $factsAfterKill = 0
    if ($coverageAfterKill.Success -and $coverageAfterKill.Data.data) {
        $compileStatusAfterKill = $coverageAfterKill.Data.data.compile_status
        $factsAfterKill = $coverageAfterKill.Data.data.facts_total
        Write-Log "After kill: compile_status=$compileStatusAfterKill, facts=$factsAfterKill"
    }
    
    # Wait and check if compile eventually completes or stays stuck
    Write-Log "Waiting 30s to see if compile recovers..."
    Start-Sleep -Seconds 30
    
    $coverageFinal = Invoke-ApiCall -Endpoint "/api/runs/$runId/coverage"
    
    $compileStatusFinal = "unknown"
    $factsFinal = 0
    if ($coverageFinal.Success -and $coverageFinal.Data.data) {
        $compileStatusFinal = $coverageFinal.Data.data.compile_status
        $factsFinal = $coverageFinal.Data.data.facts_total
        Write-Log "Final: compile_status=$compileStatusFinal, facts=$factsFinal"
    }
    
    # Collect diagnostics
    $diag = Collect-RunDiagnostics -RunId $runId -ScenarioName "S6"
    
    $coverage = $diag.Endpoints.coverage.Data
    $metrics = @{
        Events = if ($coverage.data) { $coverage.data.events_total } else { 0 }
        Facts = if ($coverage.data) { $coverage.data.facts_total } else { 0 }
        Signals = if ($coverage.data) { $coverage.data.signals_total } else { 0 }
    }
    
    $latencies = @{}
    foreach ($ep in $diag.Endpoints.Keys) {
        $latencies[$ep] = $diag.Endpoints[$ep].LatencyMs
    }
    
    $histogram = Get-FactTypeHistogram -CoverageData $coverage
    $factsData = $diag.Endpoints.facts.Data
    $evidenceCheck = Test-EvidencePointers -FactsData $factsData
    
    $errors += $diag.Errors
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    # Determine status
    $status = "PASS"
    if ($compileStatusFinal -ne "finalized") { $status = "WARN"; $errors += "Compile did not recover to finalized state" }
    if ($factsFinal -eq 0 -and $factsAfterKill -eq 0) { $status = "FAIL"; $errors += "No facts recovered" }
    
    $result = @{
        Scenario = "S6-KillLocaldMidCompile"
        RunId = $runId
        Status = $status
        StartTime = $startTime
        EndTime = $endTime
        DurationSec = [math]::Round($duration, 2)
        MidCompileKill = @{
            LocaldProcessesKilled = $killedCount
            CompileStatusAfterKill = $compileStatusAfterKill
            FactsAfterKill = $factsAfterKill
            CompileStatusFinal = $compileStatusFinal
            FactsFinal = $factsFinal
            CompileRecovered = ($compileStatusFinal -eq "finalized")
        }
        Metrics = $metrics
        EndpointLatencies = $latencies
        FactTypeHistogram = $histogram
        EvidenceCheck = $evidenceCheck
        Errors = $errors
        RawDiagnostics = $diag
    }
    
    Write-Host (Format-ScenarioReport -Result $result)
    Write-Log "Mid-Compile Kill: killed=$killedCount, recovered=$($compileStatusFinal -eq 'finalized')"
    
    Save-ScenarioResult -Result $result -ScenarioName "S6"
    
    return $result
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Generate-WeaknessReport {
    param([array]$Results)
    
    $weaknesses = @()
    
    foreach ($r in $Results) {
        # Check for specific weakness patterns
        
        # W1: Slow API responses
        foreach ($ep in $r.EndpointLatencies.Keys) {
            $lat = $r.EndpointLatencies[$ep]
            if ($lat -gt 2000) {
                $weaknesses += @{
                    Severity = if ($lat -gt 5000) { "HIGH" } else { "MEDIUM" }
                    Category = "Performance"
                    Issue = "Slow API response: $ep took ${lat}ms"
                    Scenario = $r.Scenario
                    RunId = $r.RunId
                    RootCause = "Likely: database query or file I/O bottleneck"
                    File = "crates/server/src/bin/locint.rs"
                    Fix = "Add query optimization or caching for $ep endpoint"
                    Risk = "Performance degradation under load"
                }
            }
        }
        
        # W2: Low fact extraction
        if ($r.Metrics -and $r.Metrics.Facts -lt 10 -and $r.Scenario -notmatch "S5|S6") {
            $weaknesses += @{
                Severity = "HIGH"
                Category = "Truthfulness"
                Issue = "Very few facts extracted: $($r.Metrics.Facts) facts"
                Scenario = $r.Scenario
                RunId = $r.RunId
                RootCause = "fact_extractor.rs may not be parsing events correctly"
                File = "crates/locald/src/os/windows/fact_extractor.rs"
                Fix = "Verify XML parsing for Sysmon/Security events"
                Risk = "Missing critical security telemetry"
            }
        }
        
        # W3: Evidence pointer issues
        if ($r.EvidenceCheck -and $r.EvidenceCheck.Valid -lt $r.EvidenceCheck.Checked) {
            $weaknesses += @{
                Severity = "MEDIUM"
                Category = "Truthfulness"
                Issue = "Invalid evidence pointers: $($r.EvidenceCheck.Checked - $r.EvidenceCheck.Valid) of $($r.EvidenceCheck.Checked)"
                Scenario = $r.Scenario
                RunId = $r.RunId
                RootCause = "capture_windows_rotating.rs not assigning EvidencePtr correctly"
                File = "crates/agent-windows/src/capture_windows_rotating.rs"
                Fix = "Ensure all events get valid evidence_ptr before write"
                Risk = "Cannot trace facts back to source events"
            }
        }
        
        # W4: API spam errors
        if ($r.ApiSpam -and $r.ApiSpam.ErrorRate -gt 5) {
            $weaknesses += @{
                Severity = "HIGH"
                Category = "Stability"
                Issue = "High API error rate under load: $($r.ApiSpam.ErrorRate)%"
                Scenario = $r.Scenario
                RunId = $r.RunId
                RootCause = "Database locking or connection pool exhaustion"
                File = "crates/server/src/db.rs"
                Fix = "Add connection pooling or WAL mode for SQLite"
                Risk = "UI shows errors during high activity"
            }
        }
        
        # W5: Compile not recovering
        if ($r.MidCompileKill -and -not $r.MidCompileKill.CompileRecovered) {
            $weaknesses += @{
                Severity = "HIGH"
                Category = "Stability"
                Issue = "Compile did not recover after locald kill"
                Scenario = $r.Scenario
                RunId = $r.RunId
                RootCause = "No compile recovery mechanism when locald crashes"
                File = "crates/locald/src/compiler.rs"
                Fix = "Add compile state persistence and recovery on restart"
                Risk = "Runs may be stuck in incomplete state forever"
            }
        }
        
        # W6: Orphan run not detected
        if ($r.OrphanRecovery -and $r.OrphanRecovery.ServerReportedRunning) {
            $weaknesses += @{
                Severity = "HIGH"
                Category = "Stability"
                Issue = "Orphan run not detected after locint restart"
                Scenario = $r.Scenario
                RunId = $r.RunId
                RootCause = "run_supervisor.rs not checking for orphaned runs on startup"
                File = "crates/server/src/run_supervisor.rs"
                Fix = "On startup, check for runs with running status but no active process"
                Risk = "Ghost runs that cannot be stopped"
            }
        }
        
        # W7: Errors in diagnostics
        foreach ($err in $r.Errors) {
            if ($err -match "500|timeout|locked|NETWORK_ERROR") {
                $weaknesses += @{
                    Severity = "MEDIUM"
                    Category = "Stability"
                    Issue = "Error during diagnostics: $err"
                    Scenario = $r.Scenario
                    RunId = $r.RunId
                    RootCause = "Endpoint failure or database issue"
                    File = "crates/server/src/bin/locint.rs"
                    Fix = "Investigate specific endpoint failure"
                    Risk = "UI may show incomplete or error states"
                }
            }
        }
    }
    
    # Sort by severity
    $severityOrder = @{ "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3 }
    $sorted = $weaknesses | Sort-Object { $severityOrder[$_.Severity] }
    
    return $sorted | Select-Object -First 10
}

function Main {
    Write-Log "LocInt Stress Test Harness"
    Write-Log "========================="
    Write-Log "Scenario: $Scenario"
    Write-Log "API Base: $ApiBase"
    Write-Log "Output: $OutputDir"
    Write-Log ""
    
    # Check server is up
    if (-not (Wait-ForServer)) {
        Write-Log "Cannot proceed - server not available" -Level "ERROR"
        return
    }
    
    $results = @()
    
    $scenarios = if ($Scenario -eq "ALL") { @("S1","S2","S3","S4","S5","S6") } else { @($Scenario) }
    
    foreach ($s in $scenarios) {
        Write-Log ""
        Write-Log "Running scenario $s..."
        
        $result = switch ($s) {
            "S1" { Run-S1-HighVolumeExec }
            "S2" { Run-S2-HighVolumeDNS }
            "S3" { Run-S3-RegistryChurn }
            "S4" { Run-S4-ApiSpamDuringCompile }
            "S5" { Run-S5-RestartLocIntMidRun }
            "S6" { Run-S6-KillLocaldMidCompile }
        }
        
        $results += $result
        
        # Pause between scenarios
        if ($scenarios.Count -gt 1) {
            Write-Log "Pausing 10 seconds before next scenario..."
            Start-Sleep -Seconds 10
        }
    }
    
    # Generate weakness report
    Write-Log ""
    Write-Log "=" * 60
    Write-Log "GENERATING WEAKNESS REPORT"
    Write-Log "=" * 60
    
    $weaknesses = Generate-WeaknessReport -Results $results
    
    Write-Log ""
    Write-Log "TOP 10 WEAKNESSES (Ranked by Severity)"
    Write-Log "-" * 60
    
    $rank = 1
    foreach ($w in $weaknesses) {
        Write-Log ""
        Write-Log "#$rank [$($w.Severity)] $($w.Category)"
        Write-Log "   Issue: $($w.Issue)"
        Write-Log "   Scenario: $($w.Scenario)"
        Write-Log "   Run: $($w.RunId)"
        Write-Log "   Root Cause: $($w.RootCause)"
        Write-Log "   File: $($w.File)"
        Write-Log "   Fix: $($w.Fix)"
        Write-Log "   Risk: $($w.Risk)"
        $rank++
    }
    
    # Save final report
    $finalReport = @{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        ScenariosRun = $scenarios
        Results = $results
        Weaknesses = $weaknesses
        Summary = @{
            TotalScenarios = $results.Count
            Passed = ($results | Where-Object { $_.Status -eq "PASS" }).Count
            Warnings = ($results | Where-Object { $_.Status -eq "WARN" }).Count
            Failed = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
        }
    }
    
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    $reportPath = Join-Path $OutputDir "stress_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $finalReport | ConvertTo-Json -Depth 20 | Set-Content -Path $reportPath -Encoding UTF8
    
    Write-Log ""
    Write-Log "=" * 60
    Write-Log "STRESS TEST COMPLETE"
    Write-Log "=" * 60
    Write-Log "Total: $($results.Count) scenarios"
    Write-Log "Passed: $($finalReport.Summary.Passed)"
    Write-Log "Warnings: $($finalReport.Summary.Warnings)"
    Write-Log "Failed: $($finalReport.Summary.Failed)"
    Write-Log "Report: $reportPath"
    
    return $finalReport
}

# Run main
Main
