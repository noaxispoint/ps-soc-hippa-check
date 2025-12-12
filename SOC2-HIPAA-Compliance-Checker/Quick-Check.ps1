<#
.SYNOPSIS
    Quick SOC 2 / HIPAA Logging Compliance Check
.DESCRIPTION
    Rapid validation of critical logging and security requirements for fast assessment.
    This script checks the most important controls that are frequently out of compliance.
.NOTES
    Version: 1.0.0
    Author: Compliance Automation Team
    Requires: PowerShell 5.1+, Administrator privileges
.EXAMPLE
    .\Quick-Check.ps1
    Performs rapid validation of critical controls
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Quick SOC 2 / HIPAA Compliance Check" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""

$issues = @()
$passed = 0
$total = 0

function Test-Control {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [string]$Issue
    )
    
    $script:total++
    Write-Host "$script:total. Checking $Name..." -ForegroundColor Yellow
    
    $result = & $Test
    
    if ($result) {
        Write-Host "   [PASS]" -ForegroundColor Green
        $script:passed++
        return $true
    } else {
        Write-Host "   [FAIL] $Issue" -ForegroundColor Red
        $script:issues += "   - $Issue"
        return $false
    }
}

# Test 1: Critical audit policies
Test-Control -Name "Critical Audit Policies" -Test {
    $criticalPolicies = @("Logon", "User Account Management", "Security Group Management", "File System", "Audit Policy Change")
    $allOk = $true
    
    foreach ($policy in $criticalPolicies) {
        $result = auditpol /get /subcategory:"$policy" /r 2>$null | ConvertFrom-Csv
        if ($result.'Inclusion Setting' -notmatch "Success|Failure") {
            $allOk = $false
            break
        }
    }
    
    return $allOk
} -Issue "Some critical audit policies are not enabled"

# Test 2: Security event log size
Test-Control -Name "Security Log Size (2GB minimum)" -Test {
    $secLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    if ($secLog) {
        $secLogSizeKB = [Math]::Round($secLog.MaximumSizeInBytes / 1KB)
        return $secLogSizeKB -ge 2097152
    }
    return $false
} -Issue "Security log size is less than 2GB"

# Test 3: Event Log service
Test-Control -Name "Event Log Service" -Test {
    $eventLog = Get-Service -Name EventLog -ErrorAction SilentlyContinue
    return ($eventLog -and $eventLog.Status -eq 'Running')
} -Issue "Event Log service is not running"

# Test 4: Recent security events
Test-Control -Name "Recent Security Event Activity" -Test {
    $yesterday = (Get-Date).AddDays(-1)
    $recentEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$yesterday} -MaxEvents 1 -ErrorAction SilentlyContinue
    return ($null -ne $recentEvents)
} -Issue "No security events logged in the last 24 hours"

# Test 5: Command line auditing
Test-Control -Name "Command Line Process Auditing" -Test {
    $cmdLine = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    return ($cmdLine -and $cmdLine.ProcessCreationIncludeCmdLine_Enabled -eq 1)
} -Issue "Command line auditing is not enabled"

# Test 6: Password policy
Test-Control -Name "Password Policy (12+ characters)" -Test {
    secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet | Out-Null
    $policyContent = Get-Content "$env:TEMP\secpol.cfg"
    $minLength = ($policyContent | Select-String "MinimumPasswordLength = (\d+)").Matches.Groups[1].Value
    Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
    return ([int]$minLength -ge 12)
} -Issue "Minimum password length is less than 12 characters"

# Test 7: Account lockout
Test-Control -Name "Account Lockout Policy" -Test {
    secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet | Out-Null
    $policyContent = Get-Content "$env:TEMP\secpol.cfg"
    $lockoutThreshold = ($policyContent | Select-String "LockoutBadCount = (\d+)").Matches.Groups[1].Value
    Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
    return ([int]$lockoutThreshold -gt 0 -and [int]$lockoutThreshold -le 10)
} -Issue "Account lockout policy not properly configured"

# Test 8: BitLocker encryption
Test-Control -Name "BitLocker Disk Encryption" -Test {
    $bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitlocker) {
        $osVolume = $bitlocker | Where-Object { $_.VolumeType -eq 'OperatingSystem' }
        return ($osVolume -and ($osVolume.VolumeStatus -eq 'FullyEncrypted' -or $osVolume.VolumeStatus -eq 'EncryptionInProgress'))
    }
    return $false
} -Issue "OS drive is not encrypted with BitLocker"

# Test 9: Windows Defender
Test-Control -Name "Windows Defender Real-Time Protection" -Test {
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    return ($defender -and $defender.RealTimeProtectionEnabled)
} -Issue "Windows Defender real-time protection is disabled"

# Test 10: Firewall status
Test-Control -Name "Windows Firewall (All Profiles)" -Test {
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($profiles) {
        $allEnabled = $true
        foreach ($profile in $profiles) {
            if (-not $profile.Enabled) {
                $allEnabled = $false
                break
            }
        }
        return $allEnabled
    }
    return $false
} -Issue "Windows Firewall is disabled on one or more profiles"

# Test 11: Screen lock timeout
Test-Control -Name "Screen Lock Timeout (15 min max)" -Test {
    $timeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
    $active = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
    
    if ($timeout -and $active) {
        $timeoutMinutes = [int]$timeout.ScreenSaveTimeOut / 60
        $isActive = $active.ScreenSaveActive -eq "1"
        return ($timeoutMinutes -le 15 -and $timeoutMinutes -gt 0 -and $isActive)
    }
    return $false
} -Issue "Screen lock timeout not configured or exceeds 15 minutes"

# Test 12: Windows updates
Test-Control -Name "Recent Windows Updates" -Test {
    $lastUpdate = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
        ID = 19
    } -MaxEvents 1 -ErrorAction SilentlyContinue
    
    if ($lastUpdate) {
        $daysSince = ((Get-Date) - $lastUpdate.TimeCreated).Days
        return $daysSince -le 30
    }
    return $false
} -Issue "No Windows updates installed in the last 30 days"

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RESULTS: $passed/$total checks passed" -ForegroundColor $(if ($passed -eq $total) { 'Green' } else { 'Yellow' })
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

if ($issues.Count -gt 0) {
    Write-Host ""
    Write-Host "ISSUES FOUND:" -ForegroundColor Red
    Write-Host ""
    $issues | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    Write-Host ""
    Write-Host "► For detailed analysis and remediation steps:" -ForegroundColor Yellow
    Write-Host "  Run: .\Run-ComplianceCheck.ps1" -ForegroundColor Cyan
    Write-Host ""
    exit 1
} else {
    Write-Host ""
    Write-Host "✓ No critical issues found!" -ForegroundColor Green
    Write-Host ""
    Write-Host "► For comprehensive compliance validation:" -ForegroundColor Gray
    Write-Host "  Run: .\Run-ComplianceCheck.ps1" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}
