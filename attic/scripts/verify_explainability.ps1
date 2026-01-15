# verify_explainability.ps1
# End-to-end explainability verification script for Windows
#
# Usage:
#   .\scripts\verify_explainability.ps1
#   .\scripts\verify_explainability.ps1 -ServerUrl "http://127.0.0.1:9000"
#   .\scripts\verify_explainability.ps1 -RequireSignals -RequireEvidence -Verbose
#
# This script:
# 1. Checks that the server is running
# 2. Fetches all signals from /api/signals
# 3. For each signal, fetches /api/signals/{id}/explain
# 4. Validates the explanation bundle has required fields
# 5. Reports pass/fail status

param(
    [string]$ServerUrl = "http://127.0.0.1:3000",
    [int]$MinSignals = 0,
    [switch]$RequireSignals,
    [switch]$RequireEvidence,
    [switch]$RequireFilledSlot,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

function Write-Header($text) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Section($text) {
    Write-Host ""
    Write-Host "─── $text ───" -ForegroundColor DarkCyan
}

function Write-Pass($text) {
    Write-Host "  ✓ $text" -ForegroundColor Green
}

function Write-Fail($text) {
    Write-Host "  ✗ $text" -ForegroundColor Red
}

function Write-Warn($text) {
    Write-Host "  ⚠ $text" -ForegroundColor Yellow
}

function Write-Info($text) {
    if ($Verbose) {
        Write-Host "    $text" -ForegroundColor DarkGray
    }
}

$script:errors = @()
$script:warnings = @()
$script:signalsChecked = 0
$script:explanationsValid = 0
$script:explanationsInvalid = 0

Write-Header "EXPLAINABILITY VERIFICATION"

Write-Host "Server:           $ServerUrl"
Write-Host "Min signals:      $MinSignals"
Write-Host "Require signals:  $RequireSignals"
Write-Host "Require evidence: $RequireEvidence"
Write-Host "Require filled:   $RequireFilledSlot"

# Step 1: Check server is running
Write-Section "Checking server connectivity"
try {
    $healthResp = Invoke-RestMethod -Uri "$ServerUrl/health" -Method Get -TimeoutSec 10
    Write-Pass "Server is running at $ServerUrl"
} catch {
    try {
        # Fallback: try /metrics
        $metricsResp = Invoke-RestMethod -Uri "$ServerUrl/metrics" -Method Get -TimeoutSec 10
        Write-Pass "Server is running at $ServerUrl (via /metrics)"
    } catch {
        Write-Fail "Cannot connect to server at $ServerUrl"
        Write-Fail "Error: $_"
        Write-Host ""
        Write-Host "Make sure the EDR server is running:" -ForegroundColor Yellow
        Write-Host "  cargo run --release --bin edr-server" -ForegroundColor Yellow
        exit 1
    }
}

# Step 2: Fetch signals
Write-Section "Fetching signals from /api/signals"
try {
    $signalsResp = Invoke-RestMethod -Uri "$ServerUrl/api/signals?limit=100" -Method Get -TimeoutSec 30
    
    if (-not $signalsResp.success) {
        Write-Fail "API returned failure: $($signalsResp.error)"
        $script:errors += "Failed to fetch signals: $($signalsResp.error)"
    }
    
    $signals = $signalsResp.data
    if (-not $signals) { $signals = @() }
    
    Write-Pass "Found $($signals.Count) signals"
    
    if ($signals.Count -lt $MinSignals) {
        Write-Fail "Insufficient signals: found $($signals.Count), expected at least $MinSignals"
        $script:errors += "Insufficient signals"
    }
    
    if ($RequireSignals -and $signals.Count -eq 0) {
        Write-Fail "No signals found (--RequireSignals specified)"
        $script:errors += "No signals found"
    }
    
} catch {
    Write-Fail "Failed to fetch signals: $_"
    $script:errors += "Failed to fetch signals: $_"
    $signals = @()
}

# Step 3: Validate each signal's explanation
if ($signals.Count -gt 0) {
    Write-Section "Validating explanations for each signal"
    
    foreach ($sig in $signals) {
        $script:signalsChecked++
        $signalId = $sig.signal_id
        
        Write-Info "Signal: $signalId ($($sig.signal_type), $($sig.severity))"
        
        try {
            $explainResp = Invoke-RestMethod -Uri "$ServerUrl/api/signals/$signalId/explain" -Method Get -TimeoutSec 30
            
            if (-not $explainResp.success) {
                Write-Fail "Signal ${signalId} has no explanation: $($explainResp.error)"
                $script:errors += "Signal ${signalId} - no explanation"
                $script:explanationsInvalid++
                continue
            }
            
            $exp = $explainResp.data
            if (-not $exp) {
                Write-Fail "Signal ${signalId} - explanation data is null"
                $script:errors += "Signal ${signalId} - null explanation"
                $script:explanationsInvalid++
                continue
            }
            
            # Validate required fields
            $isValid = $true
            $validationErrors = @()
            
            # playbook_id must be non-empty
            if (-not $exp.playbook_id -or $exp.playbook_id -eq "") {
                $isValid = $false
                $validationErrors += "playbook_id is empty"
            }
            
            # family must be non-empty
            if (-not $exp.family -or $exp.family -eq "") {
                $isValid = $false
                $validationErrors += "family is empty"
            }
            
            # slots must exist
            if (-not $exp.slots -or $exp.slots.Count -eq 0) {
                $isValid = $false
                $validationErrors += "no slots defined"
            }
            
            # Validate slots have names
            if ($exp.slots) {
                foreach ($slot in $exp.slots) {
                    if (-not $slot.name -or $slot.name -eq "") {
                        $isValid = $false
                        $validationErrors += "slot has empty name"
                    }
                }
            }
            
            # Optional: require filled slot
            if ($RequireFilledSlot) {
                $filledCount = ($exp.slots | Where-Object { $_.status -eq "filled" }).Count
                if ($filledCount -eq 0) {
                    $isValid = $false
                    $validationErrors += "no filled slots (--RequireFilledSlot)"
                }
            }
            
            # Optional: require evidence
            if ($RequireEvidence) {
                $evidenceCount = 0
                if ($exp.evidence) { $evidenceCount = $exp.evidence.Count }
                if ($evidenceCount -eq 0) {
                    $isValid = $false
                    $validationErrors += "no evidence excerpts (--RequireEvidence)"
                }
            }
            
            if ($isValid) {
                $script:explanationsValid++
                if ($Verbose) {
                    $slotsCount = 0
                    if ($exp.slots) { $slotsCount = $exp.slots.Count }
                    $evidenceCount = 0
                    if ($exp.evidence) { $evidenceCount = $exp.evidence.Count }
                    Write-Pass "Signal $($signalId.Substring(0,16))... playbook=$($exp.playbook_id) slots=$slotsCount evidence=$evidenceCount"
                }
            } else {
                $script:explanationsInvalid++
                foreach ($err in $validationErrors) {
                    Write-Fail "Signal ${signalId} - $err"
                    $script:errors += "Signal ${signalId} - $err"
                }
            }
            
        } catch {
            Write-Fail "Failed to fetch explanation for ${signalId} - $_"
            $script:errors += "Signal ${signalId} - fetch failed"
            $script:explanationsInvalid++
        }
    }
}

# Print summary
Write-Section "SUMMARY"
Write-Host ""
Write-Host "Signals checked:       $($script:signalsChecked)"
Write-Host "Explanations valid:    $($script:explanationsValid)" -ForegroundColor Green
Write-Host "Explanations invalid:  $($script:explanationsInvalid)" -ForegroundColor $(if ($script:explanationsInvalid -gt 0) { "Red" } else { "Green" })

if ($script:warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "Warnings ($($script:warnings.Count)):" -ForegroundColor Yellow
    foreach ($w in $script:warnings) {
        Write-Warn $w
    }
}

if ($script:errors.Count -gt 0) {
    Write-Host ""
    Write-Host "Errors ($($script:errors.Count)):" -ForegroundColor Red
    foreach ($e in $script:errors) {
        Write-Fail $e
    }
}

Write-Host ""
if ($script:errors.Count -eq 0) {
    Write-Header "✓ ALL CHECKS PASSED"
    exit 0
} else {
    Write-Header "✗ SOME CHECKS FAILED"
    exit 1
}
