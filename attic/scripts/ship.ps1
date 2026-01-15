# ship.ps1 - Create shipping folder for LocInt
#
# Usage: .\scripts\ship.ps1
# Output: LocInt/ folder ready for distribution
#

$ErrorActionPreference = "Stop"

Write-Host "Building release binaries..."
cargo build --release --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

# Create shipping folder
$ship = "LocInt"
Write-Host "Creating shipping folder: $ship"

if (Test-Path $ship) {
    Remove-Item -Recurse -Force $ship
}

New-Item -ItemType Directory -Force -Path $ship | Out-Null
New-Item -ItemType Directory -Force -Path "$ship\ui" | Out-Null
New-Item -ItemType Directory -Force -Path "$ship\playbooks\windows" | Out-Null

# Copy binaries
Write-Host "Copying binaries..."
Copy-Item target\release\locint.exe $ship\
Copy-Item target\release\edr-locald.exe $ship\
Copy-Item target\release\capture_windows_rotating.exe $ship\

# Copy UI
Write-Host "Copying UI..."
Copy-Item ui\* $ship\ui\ -Recurse

# Copy playbooks
Write-Host "Copying playbooks..."
Copy-Item playbooks\windows\*.yaml $ship\playbooks\windows\

# Verify
Write-Host ""
Write-Host "=== Shipping folder contents ==="
Get-ChildItem -Recurse $ship | ForEach-Object {
    $relativePath = $_.FullName.Replace((Get-Location).Path + "\$ship\", "")
    if ($_.PSIsContainer) {
        Write-Host "  $relativePath/"
    } else {
        $size = [math]::Round($_.Length / 1MB, 2)
        Write-Host "  $relativePath ($size MB)"
    }
}

Write-Host ""
Write-Host "✅ Shipping folder ready: $ship"
Write-Host "   Double-click $ship\locint.exe to launch"
Write-Host ""
Write-Host "To distribute: zip the $ship folder and share it"
