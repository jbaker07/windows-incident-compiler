#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enable detection-grade telemetry channels for Windows EDR collection.
.DESCRIPTION
    - Enables Windows Event Log channels via wevtutil
    - Configures advanced audit policies via auditpol
    - Checks for Sysmon presence and configuration
    - Returns PASS/FAIL status
.EXAMPLE
    .\enable_advanced_telemetry.ps1
.NOTES
    Must run as Administrator
#>

[CmdletBinding()]
param(
    [switch]$SkipAuditPolicy,
    [switch]$AutoFix,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$script:FailCount = 0
$script:PassCount = 0
$script:WarnCount = 0

function Write-Status {
    param([string]$Message, [string]$Status)
    if ($Quiet -and $Status -eq "PASS") { return }
    $color = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        "INFO" { "Cyan" }
        "FIX"  { "Magenta" }
        default { "White" }
    }
    Write-Host "[$Status] " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Test-AdminPrivilege {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================================================
# SECTION 1: Administrator Check
# ============================================================================
Write-Host "`n=== EDR Advanced Telemetry Configuration ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

if (-not (Test-AdminPrivilege)) {
    Write-Status "Script requires Administrator privileges" "FAIL"
    Write-Host "  Run: Start-Process powershell -Verb RunAs -ArgumentList '-File', '$($MyInvocation.MyCommand.Path)'"
    exit 1
}
Write-Status "Running with Administrator privileges" "PASS"
$script:PassCount++

# ============================================================================
# SECTION 2: Enable Event Log Channels
# ============================================================================
Write-Host "`n--- Event Log Channels ---" -ForegroundColor Yellow

$channels = @(
    # Tier 0: Core (REQUIRED)
    @{ Name = "Security"; Required = $true; Tier = 0 },
    @{ Name = "System"; Required = $true; Tier = 0 },
    @{ Name = "Microsoft-Windows-Sysmon/Operational"; Required = $false; Tier = 0 },
    
    # Tier 1: High-Value (Recommended)
    @{ Name = "Microsoft-Windows-PowerShell/Operational"; Required = $false; Tier = 1 },
    @{ Name = "Microsoft-Windows-Windows Defender/Operational"; Required = $false; Tier = 1 },
    @{ Name = "Microsoft-Windows-WMI-Activity/Operational"; Required = $false; Tier = 1 },
    @{ Name = "Microsoft-Windows-TaskScheduler/Operational"; Required = $false; Tier = 1 },
    
    # Tier 2: Lateral Movement (Recommended)
    @{ Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; Required = $false; Tier = 2 },
    @{ Name = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; Required = $false; Tier = 2 },
    @{ Name = "Microsoft-Windows-WinRM/Operational"; Required = $false; Tier = 2 },
    
    # Tier 3: Extended (Optional)
    @{ Name = "Microsoft-Windows-DNS-Client/Operational"; Required = $false; Tier = 3 },
    @{ Name = "Microsoft-Windows-Bits-Client/Operational"; Required = $false; Tier = 3 },
    @{ Name = "Microsoft-Windows-CodeIntegrity/Operational"; Required = $false; Tier = 3 }
)

$tierNames = @{
    0 = "Core (Required)"
    1 = "High-Value"
    2 = "Lateral Movement"
    3 = "Extended"
}

$currentTier = -1
foreach ($channel in $channels) {
    if ($channel.Tier -ne $currentTier) {
        $currentTier = $channel.Tier
        Write-Host "`n  Tier $currentTier - $($tierNames[$currentTier]):" -ForegroundColor Cyan
    }
    
    $name = $channel.Name
    try {
        # Check if channel exists
        $info = wevtutil gl $name 2>&1
        if ($LASTEXITCODE -ne 0) {
            if ($channel.Required) {
                Write-Status "  $name - Channel not found (REQUIRED)" "FAIL"
                $script:FailCount++
            } else {
                Write-Status "  $name - Channel not found" "WARN"
                $script:WarnCount++
            }
            continue
        }
        
        # Check if enabled
        $enabled = ($info | Select-String -Pattern "enabled:\s*true" -Quiet)
        if ($enabled) {
            Write-Status "  $name - Enabled" "PASS"
            $script:PassCount++
        } else {
            if ($AutoFix) {
                wevtutil sl $name /e:true 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Status "  $name - Enabled (auto-fixed)" "FIX"
                    $script:PassCount++
                } else {
                    Write-Status "  $name - Failed to enable" "FAIL"
                    $script:FailCount++
                }
            } else {
                if ($channel.Required) {
                    Write-Status "  $name - Disabled (REQUIRED)" "FAIL"
                    Write-Host "      Fix: wevtutil sl `"$name`" /e:true"
                    $script:FailCount++
                } else {
                    Write-Status "  $name - Disabled" "WARN"
                    Write-Host "      Fix: wevtutil sl `"$name`" /e:true"
                    $script:WarnCount++
                }
            }
        }
    } catch {
        Write-Status "  $name - Error: $_" "FAIL"
        $script:FailCount++
    }
}

# ============================================================================
# SECTION 3: Sysmon Check
# ============================================================================
Write-Host "`n--- Sysmon Status ---" -ForegroundColor Yellow

$sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
$sysmonDriver = Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue

if ($sysmonService) {
    Write-Status "Sysmon service found: $($sysmonService.Name) ($($sysmonService.Status))" "PASS"
    $script:PassCount++
    
    if ($sysmonService.Status -ne "Running") {
        Write-Status "Sysmon service not running" "WARN"
        $script:WarnCount++
    }
    
    # Check driver status
    if ($sysmonDriver -and $sysmonDriver.Status -eq "Running") {
        Write-Status "Sysmon driver (SysmonDrv) running" "PASS"
        $script:PassCount++
    } else {
        Write-Status "Sysmon driver not running" "WARN"
        $script:WarnCount++
    }
    
    # Check config
    try {
        $sysmonExe = (Get-WmiObject Win32_Service -Filter "Name LIKE 'Sysmon%'" -ErrorAction SilentlyContinue).PathName
        if ($sysmonExe) {
            $sysmonExe = $sysmonExe -replace '"', '' -replace '\s+-.*$', ''
            if (Test-Path $sysmonExe) {
                $configCheck = & $sysmonExe -c 2>&1 | Select-String -Pattern "Rule" -Quiet
                if ($configCheck) {
                    Write-Status "Sysmon has configuration rules" "PASS"
                    $script:PassCount++
                } else {
                    Write-Status "Sysmon running with default (minimal) config" "WARN"
                    $script:WarnCount++
                }
            }
        }
    } catch {
        Write-Status "Could not query Sysmon configuration" "INFO"
    }
} else {
    Write-Status "Sysmon not installed" "WARN"
    $script:WarnCount++
    Write-Host @"
    
  Sysmon provides critical detection visibility:
  - Process creation with full command line and parent
  - Network connections with source process
  - File creation and registry modifications
  - Driver/DLL loading
  
  Installation:
    1. Download: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    2. Download config: https://github.com/SwiftOnSecurity/sysmon-config
    3. Install: sysmon64 -accepteula -i sysmonconfig-export.xml
"@
}

# ============================================================================
# SECTION 4: Audit Policy Status
# ============================================================================
Write-Host "`n--- Audit Policy Status ---" -ForegroundColor Yellow

if (-not $SkipAuditPolicy) {
    $requiredPolicies = @(
        @{ Subcategory = "Process Creation"; Expected = "Success" },
        @{ Subcategory = "Logon"; Expected = "Success and Failure" },
        @{ Subcategory = "Special Logon"; Expected = "Success" },
        @{ Subcategory = "Logoff"; Expected = "Success" },
        @{ Subcategory = "Security System Extension"; Expected = "Success" }
    )
    
    foreach ($policy in $requiredPolicies) {
        try {
            $result = auditpol /get /subcategory:"$($policy.Subcategory)" 2>&1
            $line = $result | Select-String -Pattern $policy.Subcategory
            if ($line) {
                $lineStr = $line.ToString()
                if ($lineStr -match "Success and Failure|Success") {
                    Write-Status "Audit: $($policy.Subcategory) - Enabled" "PASS"
                    $script:PassCount++
                } else {
                    Write-Status "Audit: $($policy.Subcategory) - Not configured" "WARN"
                    Write-Host "      Fix: auditpol /set /subcategory:`"$($policy.Subcategory)`" /success:enable /failure:enable"
                    $script:WarnCount++
                }
            }
        } catch {
            Write-Status "Audit: $($policy.Subcategory) - Query failed" "WARN"
            $script:WarnCount++
        }
    }
}

# ============================================================================
# SECTION 5: Command Line in Process Creation
# ============================================================================
Write-Host "`n--- Process Command Line Logging ---" -ForegroundColor Yellow

$cmdLineKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$cmdLineEnabled = $false
try {
    if (Test-Path $cmdLineKey) {
        $val = Get-ItemProperty -Path $cmdLineKey -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
        if ($val -and $val.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
            $cmdLineEnabled = $true
        }
    }
} catch {}

if ($cmdLineEnabled) {
    Write-Status "Command line in Security 4688 events: Enabled" "PASS"
    $script:PassCount++
} else {
    Write-Status "Command line in Security 4688 events: Disabled" "WARN"
    $script:WarnCount++
    if ($AutoFix) {
        try {
            if (-not (Test-Path $cmdLineKey)) {
                New-Item -Path $cmdLineKey -Force | Out-Null
            }
            Set-ItemProperty -Path $cmdLineKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
            Write-Status "Command line logging enabled (auto-fixed)" "FIX"
        } catch {
            Write-Host "      Manual fix: reg add `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f"
        }
    } else {
        Write-Host "      Fix: reg add `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f"
    }
}

# ============================================================================
# SECTION 6: PowerShell Script Block Logging
# ============================================================================
Write-Host "`n--- PowerShell Script Block Logging ---" -ForegroundColor Yellow

$psLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$psLogEnabled = $false
try {
    if (Test-Path $psLogKey) {
        $val = Get-ItemProperty -Path $psLogKey -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        if ($val -and $val.EnableScriptBlockLogging -eq 1) {
            $psLogEnabled = $true
        }
    }
} catch {}

if ($psLogEnabled) {
    Write-Status "PowerShell Script Block Logging: Enabled" "PASS"
    $script:PassCount++
} else {
    Write-Status "PowerShell Script Block Logging: Disabled" "WARN"
    $script:WarnCount++
    if ($AutoFix) {
        try {
            if (-not (Test-Path $psLogKey)) {
                New-Item -Path $psLogKey -Force | Out-Null
            }
            Set-ItemProperty -Path $psLogKey -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
            Write-Status "Script Block Logging enabled (auto-fixed)" "FIX"
        } catch {
            Write-Host "      See: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows"
        }
    } else {
        Write-Host "      Fix: New-Item -Path `"$psLogKey`" -Force; Set-ItemProperty -Path `"$psLogKey`" -Name EnableScriptBlockLogging -Value 1"
    }
}

# ============================================================================
# SECTION 7: Summary
# ============================================================================
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Passed:   $($script:PassCount)" -ForegroundColor Green
Write-Host "Warnings: $($script:WarnCount)" -ForegroundColor Yellow  
Write-Host "Failed:   $($script:FailCount)" -ForegroundColor Red

$exitCode = 0
if ($script:FailCount -gt 0) {
    Write-Host "`nRESULT: FAIL" -ForegroundColor Red
    Write-Host "Required telemetry sources are not available."
    Write-Host "Run with -AutoFix to attempt automatic remediation."
    $exitCode = 1
} elseif ($script:WarnCount -gt 3) {
    Write-Host "`nRESULT: WARN" -ForegroundColor Yellow
    Write-Host "Detection coverage will be limited."
    $exitCode = 0
} else {
    Write-Host "`nRESULT: PASS" -ForegroundColor Green
    Write-Host "Telemetry is configured for detection."
    $exitCode = 0
}

# Output telemetry summary for scripts
Write-Host "`n--- Telemetry Capabilities ---" -ForegroundColor Cyan
$caps = @{
    sysmon = if ($sysmonService) { $true } else { $false }
    powershell_logging = $psLogEnabled
    cmdline_logging = $cmdLineEnabled
}
Write-Host "  Sysmon:              $($caps.sysmon)"
Write-Host "  PowerShell Logging:  $($caps.powershell_logging)"
Write-Host "  CmdLine in 4688:     $($caps.cmdline_logging)"

exit $exitCode
