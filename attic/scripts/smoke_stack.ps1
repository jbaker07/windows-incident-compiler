# smoke_stack.ps1 - Verify EDR stack is running correctly (Windows)
#
# Usage: .\scripts\smoke_stack.ps1 [-Verbose]

param(
    [switch]$Verbose
)

$BaseUrl = if ($env:EDR_API_URL) { $env:EDR_API_URL } else { "http://localhost:3000" }
$Failed = 0

function Check-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [string]$ExpectedField = ""
    )
    
    if ($Verbose) { Write-Host "Checking $Name at $Url..." }
    
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
        $body = $response.Content
        
        if ($response.StatusCode -ne 200) {
            Write-Host "✗ $Name - HTTP $($response.StatusCode)"
            $script:Failed++
            return $false
        }
        
        # Check for valid JSON
        try {
            $json = $body | ConvertFrom-Json
        } catch {
            Write-Host "✗ $Name - Invalid JSON response"
            $script:Failed++
            return $false
        }
        
        # Check for expected field if specified
        if ($ExpectedField -and -not ($json.PSObject.Properties.Name -contains $ExpectedField)) {
            Write-Host "✗ $Name - Missing field: $ExpectedField"
            if ($Verbose) { Write-Host "Response: $body" }
            $script:Failed++
            return $false
        }
        
        Write-Host "✓ $Name - OK"
        if ($Verbose) { 
            $preview = $body.Substring(0, [Math]::Min(200, $body.Length))
            Write-Host "Response: $preview..."
        }
        return $true
    } catch {
        Write-Host "✗ $Name - Connection failed: $($_.Exception.Message)"
        $script:Failed++
        return $false
    }
}

Write-Host "=========================================="
Write-Host " EDR Stack Smoke Test"
Write-Host "=========================================="
Write-Host "Base URL: $BaseUrl"
Write-Host ""

# Check health endpoint
Check-Endpoint -Name "Health" -Url "$BaseUrl/api/health" -ExpectedField "status" | Out-Null

# Check capabilities endpoint
Check-Endpoint -Name "Capabilities" -Url "$BaseUrl/api/capabilities" -ExpectedField "sources" | Out-Null

# Check integrations endpoint
Check-Endpoint -Name "Integrations" -Url "$BaseUrl/api/integrations" | Out-Null

# Check signals endpoint (core telemetry)
Check-Endpoint -Name "Signals" -Url "$BaseUrl/api/signals" | Out-Null

Write-Host ""
Write-Host "=========================================="
if ($Failed -eq 0) {
    Write-Host " All checks passed ✓"
    Write-Host "=========================================="
    exit 0
} else {
    Write-Host " $Failed check(s) failed ✗"
    Write-Host "=========================================="
    exit 1
}
