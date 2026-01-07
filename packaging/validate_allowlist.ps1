# validate_allowlist.ps1
# Validates dist folder contents against packaging/allowlist.json
# Returns exit code 0 if valid, 1 if violations found

param(
    [Parameter(Mandatory=$true)]
    [string]$DistPath,
    
    [Parameter(Mandatory=$false)]
    [string]$AllowlistPath = "packaging/allowlist.json"
)

$ErrorActionPreference = "Stop"

Write-Host "=== EDR Artifact Allowlist Validation ===" -ForegroundColor Cyan
Write-Host "Dist path: $DistPath"
Write-Host "Allowlist: $AllowlistPath"
Write-Host ""

# Load allowlist
if (-not (Test-Path $AllowlistPath)) {
    Write-Error "Allowlist not found: $AllowlistPath"
    exit 1
}

$allowlist = Get-Content $AllowlistPath | ConvertFrom-Json

$violations = @()
$warnings = @()

# Check required binaries exist
Write-Host "Checking required binaries..." -ForegroundColor Yellow
foreach ($bin in $allowlist.allowed_binaries) {
    $binPath = Join-Path $DistPath $bin
    if (Test-Path $binPath) {
        Write-Host "  ✓ Found: $bin" -ForegroundColor Green
    } else {
        $violations += "MISSING required binary: $bin"
        Write-Host "  ✗ MISSING: $bin" -ForegroundColor Red
    }
}
Write-Host ""

# Check forbidden binaries NOT present
Write-Host "Checking forbidden binaries..." -ForegroundColor Yellow
foreach ($bin in $allowlist.forbidden_binaries) {
    $binPath = Join-Path $DistPath $bin
    if (Test-Path $binPath) {
        $violations += "FORBIDDEN binary present: $bin"
        Write-Host "  ✗ VIOLATION: $bin found in dist!" -ForegroundColor Red
    } else {
        Write-Host "  ✓ Not present (correct): $bin" -ForegroundColor Green
    }
}
Write-Host ""

# Check required directories
Write-Host "Checking required directories..." -ForegroundColor Yellow
foreach ($dir in $allowlist.required_dirs) {
    $dirPath = Join-Path $DistPath $dir
    if (Test-Path $dirPath -PathType Container) {
        Write-Host "  ✓ Found: $dir/" -ForegroundColor Green
    } else {
        $violations += "MISSING required directory: $dir/"
        Write-Host "  ✗ MISSING: $dir/" -ForegroundColor Red
    }
}
Write-Host ""

# Check required docs
Write-Host "Checking required documents..." -ForegroundColor Yellow
foreach ($doc in $allowlist.required_docs) {
    $docPath = Join-Path $DistPath $doc
    if (Test-Path $docPath) {
        Write-Host "  ✓ Found: $doc" -ForegroundColor Green
    } else {
        $violations += "MISSING required document: $doc"
        Write-Host "  ✗ MISSING: $doc" -ForegroundColor Red
    }
}
Write-Host ""

# Check optional docs (warn only)
Write-Host "Checking optional documents..." -ForegroundColor Yellow
foreach ($doc in $allowlist.optional_docs) {
    $docPath = Join-Path $DistPath $doc
    if (Test-Path $docPath) {
        Write-Host "  ✓ Found: $doc" -ForegroundColor Green
    } else {
        $warnings += "Optional document not found: $doc"
        Write-Host "  ⚠ Optional not present: $doc" -ForegroundColor Yellow
    }
}
Write-Host ""

# Check for unexpected files (anything not in allowlist)
Write-Host "Checking for unexpected files..." -ForegroundColor Yellow
$expectedFiles = @()
$expectedFiles += $allowlist.allowed_binaries
$expectedFiles += $allowlist.required_docs
$expectedFiles += $allowlist.optional_docs
$expectedFiles += $allowlist.generated_files

$actualFiles = Get-ChildItem $DistPath -File | ForEach-Object { $_.Name }

foreach ($file in $actualFiles) {
    if ($file -notin $expectedFiles) {
        $warnings += "Unexpected file in dist: $file"
        Write-Host "  ⚠ Unexpected: $file" -ForegroundColor Yellow
    }
}
Write-Host ""

# Summary
Write-Host "=== Validation Summary ===" -ForegroundColor Cyan

if ($violations.Count -gt 0) {
    Write-Host ""
    Write-Host "VIOLATIONS ($($violations.Count)):" -ForegroundColor Red
    foreach ($v in $violations) {
        Write-Host "  • $v" -ForegroundColor Red
    }
}

if ($warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "WARNINGS ($($warnings.Count)):" -ForegroundColor Yellow
    foreach ($w in $warnings) {
        Write-Host "  • $w" -ForegroundColor Yellow
    }
}

if ($violations.Count -eq 0) {
    Write-Host ""
    Write-Host "✓ All validations passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host ""
    Write-Host "✗ Validation FAILED with $($violations.Count) violation(s)" -ForegroundColor Red
    exit 1
}
