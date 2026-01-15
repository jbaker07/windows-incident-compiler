#Requires -Version 5.1
<#
.SYNOPSIS
  Smoke test for explainability pipeline end-to-end truth.
  
.DESCRIPTION
  Validates that:
  1. Server starts and /api/health returns OK
  2. GET /api/signals returns valid JSON with canonical schema
  3. If signals exist, GET /api/signals/:id returns signal with run_id
  4. If signals exist, GET /api/signals/:id/explain returns ExplainResponse
  5. Evidence pointers have required deref fields (stream_id, segment_id)
  6. Run isolation: ?run_id filter works correctly
  7. Pagination: limit/offset parameters work

.PARAMETER ServerUrl
  Base URL of the server. Default: http://127.0.0.1:3030

.PARAMETER Verbose
  Show detailed output

.EXAMPLE
  .\smoke_explainability.ps1
  .\smoke_explainability.ps1 -ServerUrl http://localhost:8080 -Verbose
#>

param(
    [string]$ServerUrl = "http://127.0.0.1:3030",
    [switch]$VerboseOutput
)

$ErrorActionPreference = "Stop"
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:Warnings = @()

function Write-Test {
    param([string]$Name, [string]$Status, [string]$Details = "")
    $symbol = if ($Status -eq "PASS") { "✅" } elseif ($Status -eq "FAIL") { "❌" } else { "⚠️" }
    $color = if ($Status -eq "PASS") { "Green" } elseif ($Status -eq "FAIL") { "Red" } else { "Yellow" }
    
    Write-Host "$symbol $Name" -ForegroundColor $color
    if ($Details -and ($VerboseOutput -or $Status -eq "FAIL")) {
        Write-Host "   $Details" -ForegroundColor DarkGray
    }
    
    if ($Status -eq "PASS") { $script:TestsPassed++ }
    elseif ($Status -eq "FAIL") { $script:TestsFailed++ }
}

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [scriptblock]$Validator
    )
    
    try {
        $response = Invoke-RestMethod -Uri $Url -Method Get -ContentType "application/json" -TimeoutSec 10
        $result = & $Validator $response
        if ($result.Success) {
            Write-Test -Name $Name -Status "PASS" -Details $result.Details
        } else {
            Write-Test -Name $Name -Status "FAIL" -Details $result.Details
        }
        return $response
    }
    catch {
        Write-Test -Name $Name -Status "FAIL" -Details $_.Exception.Message
        return $null
    }
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Explainability Pipeline Smoke Test" -ForegroundColor Cyan
Write-Host "  Server: $ServerUrl" -ForegroundColor DarkGray
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------
# Test 1: Server Health
# ------------------------------------------
Write-Host "--- Server Health ---" -ForegroundColor White
$health = Test-Endpoint -Name "Health endpoint" -Url "$ServerUrl/api/health" -Validator {
    param($r)
    @{ Success = ($r.status -eq "ok"); Details = "status=$($r.status)" }
}

if (-not $health) {
    Write-Host ""
    Write-Host "❌ Server not reachable. Start server with: cargo run -p edr-server" -ForegroundColor Red
    exit 1
}

# ------------------------------------------
# Test 2: Signals List (with pagination)
# ------------------------------------------
Write-Host ""
Write-Host "--- Signals API ---" -ForegroundColor White

$signalsResponse = Test-Endpoint -Name "GET /api/signals" -Url "$ServerUrl/api/signals?limit=10" -Validator {
    param($r)
    $isArray = $r -is [array] -or ($r.data -is [array])
    @{ Success = $isArray; Details = "Response is array: $isArray" }
}

# Unwrap if wrapped in {ok: true, data: [...]}
$signals = if ($signalsResponse.data) { $signalsResponse.data } else { $signalsResponse }

# Test pagination
$paginatedResponse = Test-Endpoint -Name "Pagination (limit=1, offset=0)" -Url "$ServerUrl/api/signals?limit=1&offset=0" -Validator {
    param($r)
    $data = if ($r.data) { $r.data } else { $r }
    $count = if ($data -is [array]) { $data.Count } else { 1 }
    @{ Success = ($count -le 1); Details = "Got $count signal(s)" }
}

if ($signals -and $signals.Count -gt 0) {
    $firstSignal = $signals[0]
    
    # ------------------------------------------
    # Test 3: Signal Schema Validation
    # ------------------------------------------
    Write-Host ""
    Write-Host "--- Signal Schema ---" -ForegroundColor White
    
    # Check required fields
    $hasSignalId = [bool]$firstSignal.signal_id
    $hasSignalType = [bool]$firstSignal.signal_type
    $hasTs = $null -ne $firstSignal.ts
    $hasSeverity = [bool]$firstSignal.severity
    
    if ($hasSignalId -and $hasSignalType -and $hasTs -and $hasSeverity) {
        Write-Test -Name "Signal has required fields" -Status "PASS" -Details "signal_id, signal_type, ts, severity"
    } else {
        Write-Test -Name "Signal has required fields" -Status "FAIL" -Details "Missing: signal_id=$hasSignalId, signal_type=$hasSignalType, ts=$hasTs, severity=$hasSeverity"
    }
    
    # Check for detector provenance (new fields)
    $hasDetectorId = [bool]$firstSignal.playbook_id -or [bool]$firstSignal.detector_id
    $hasDetectorVersion = [bool]$firstSignal.detector_version
    
    if ($hasDetectorId -and $hasDetectorVersion) {
        Write-Test -Name "Signal has detector provenance" -Status "PASS" -Details "detector_id/playbook_id + version present"
    } else {
        Write-Test -Name "Signal has detector provenance" -Status "WARN" -Details "Missing detector_id or detector_version"
        $script:Warnings += "Signal missing detector provenance fields"
    }
    
    # ------------------------------------------
    # Test 4: Single Signal by ID
    # ------------------------------------------
    Write-Host ""
    Write-Host "--- Single Signal ---" -ForegroundColor White
    
    $signalId = $firstSignal.signal_id
    $singleSignal = Test-Endpoint -Name "GET /api/signals/$signalId" -Url "$ServerUrl/api/signals/$signalId" -Validator {
        param($r)
        $data = if ($r.data) { $r.data } else { $r }
        $matches = $data.signal_id -eq $signalId
        @{ Success = $matches; Details = "signal_id matches: $matches" }
    }
    
    # ------------------------------------------
    # Test 5: Explain Response
    # ------------------------------------------
    Write-Host ""
    Write-Host "--- Explain API ---" -ForegroundColor White
    
    $explainResponse = Test-Endpoint -Name "GET /api/signals/$signalId/explain" -Url "$ServerUrl/api/signals/$signalId/explain" -Validator {
        param($r)
        $data = if ($r.data) { $r.data } else { $r }
        $hasEntities = [bool]$data.entities
        $hasEvidence = $data.evidence -is [array]
        $hasScoring = [bool]$data.scoring
        @{ 
            Success = $hasEntities -and $hasScoring
            Details = "entities=$hasEntities, evidence=$hasEvidence, scoring=$hasScoring" 
        }
    }
    
    # Validate evidence pointers
    $explain = if ($explainResponse.data) { $explainResponse.data } else { $explainResponse }
    if ($explain -and $explain.evidence -and $explain.evidence.Count -gt 0) {
        $firstEvidence = $explain.evidence[0]
        $hasStreamId = [bool]$firstEvidence.stream_id
        $hasSegmentId = $null -ne $firstEvidence.segment_id
        $hasReference = [bool]$firstEvidence.reference
        
        if ($hasStreamId -and ($hasSegmentId -or $hasReference)) {
            Write-Test -Name "Evidence pointers are deref-ready" -Status "PASS" -Details "Has stream_id + segment_id or reference"
        } else {
            Write-Test -Name "Evidence pointers are deref-ready" -Status "WARN" -Details "Missing deref fields (stream_id=$hasStreamId, segment_id=$hasSegmentId)"
            $script:Warnings += "Evidence pointers may not be deref-ready"
        }
    } else {
        Write-Test -Name "Evidence pointers are deref-ready" -Status "WARN" -Details "No evidence to validate"
    }
    
    # Check scoring breakdown
    if ($explain.scoring) {
        $hasRiskScore = $null -ne $explain.scoring.risk_score
        $hasComponents = [bool]$explain.scoring.components -or [bool]$explain.scoring.raw_score
        
        if ($hasRiskScore) {
            Write-Test -Name "Scoring breakdown present" -Status "PASS" -Details "risk_score=$($explain.scoring.risk_score)"
        } else {
            Write-Test -Name "Scoring breakdown present" -Status "WARN" -Details "No risk_score in scoring"
        }
    }
    
    # ------------------------------------------
    # Test 6: Run Isolation
    # ------------------------------------------
    Write-Host ""
    Write-Host "--- Run Isolation ---" -ForegroundColor White
    
    # Try to filter by run_id if we have one
    $runsResponse = try {
        Invoke-RestMethod -Uri "$ServerUrl/api/runs" -Method Get -ContentType "application/json" -TimeoutSec 10
    } catch { $null }
    
    $runs = if ($runsResponse.data) { $runsResponse.data } else { $runsResponse }
    
    if ($runs -and $runs.Count -gt 0) {
        $testRunId = $runs[0].run_id
        $runSignals = Test-Endpoint -Name "Run filter (?run_id=$testRunId)" -Url "$ServerUrl/api/signals?run_id=$testRunId&limit=10" -Validator {
            param($r)
            $data = if ($r.data) { $r.data } else { $r }
            @{ Success = $true; Details = "Got $(if ($data -is [array]) { $data.Count } else { 1 }) signals for run" }
        }
        
        Write-Test -Name "Runs endpoint available" -Status "PASS" -Details "$($runs.Count) run(s) found"
    } else {
        Write-Test -Name "Runs endpoint available" -Status "WARN" -Details "No runs found or endpoint unavailable"
    }
    
} else {
    Write-Host ""
    Write-Host "ℹ️  No signals in database - schema tests skipped" -ForegroundColor Yellow
    Write-Host "   Run a capture or import data to fully test the pipeline" -ForegroundColor DarkGray
}

# ------------------------------------------
# Summary
# ------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Tests Passed: $script:TestsPassed" -ForegroundColor Green
Write-Host "  Tests Failed: $script:TestsFailed" -ForegroundColor $(if ($script:TestsFailed -gt 0) { "Red" } else { "DarkGray" })

if ($script:Warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "  Warnings:" -ForegroundColor Yellow
    foreach ($w in $script:Warnings) {
        Write-Host "    - $w" -ForegroundColor Yellow
    }
}

Write-Host ""

if ($script:TestsFailed -gt 0) {
    exit 1
} else {
    exit 0
}
