<#
.SYNOPSIS
    Validates Update and Patch Management
.DESCRIPTION
    Tests Windows Update settings and patch status
    SOC 2 CC7.2, CC8.1 | HIPAA § 164.308(a)(5)(ii)(B)
#>

Write-Host "Checking Update and Patch Management..." -ForegroundColor Cyan

# Check Windows Update Service
$wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue

if ($wuService) {
    $serviceRunning = $wuService.Status -eq 'Running' -or $wuService.StartType -eq 'Manual'
    
    Add-ComplianceCheck -Category "Update Management" `
        -Check "Windows Update Service" `
        -Requirement "SOC 2 CC8.1 - Change Management" `
        -NIST "SI-2" `
        -CIS "7.1" `
        -ISO27001 "A.12.6.1" `
        -PCIDSS "6.2" `
        -SOX "ITGC-06" `
        -Passed $serviceRunning `
        -CurrentValue "$($wuService.Status) ($($wuService.StartType))" `
        -ExpectedValue "Running or Manual" `
        -Remediation "Start-Service wuauserv"
    
    if ($serviceRunning) {
        Write-Host "  [PASS] Windows Update service is operational" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Windows Update service is disabled" -ForegroundColor Red
    }
}

# Check last update installation time
$lastUpdateLog = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
    ID = 19
} -MaxEvents 1 -ErrorAction SilentlyContinue

if ($lastUpdateLog) {
    $daysSinceUpdate = ((Get-Date) - $lastUpdateLog.TimeCreated).Days
    $updateRecent = $daysSinceUpdate -le 30
    
    Add-ComplianceCheck -Category "Update Management" `
        -Check "Recent Update Installation" `
        -Requirement "SOC 2 CC8.1 - Regular Patching" `
        -NIST "SI-2(2)" `
        -CIS "7.1, 7.3" `
        -ISO27001 "A.12.6.1" `
        -PCIDSS "6.2" `
        -SOX "ITGC-06" `
        -Passed $updateRecent `
        -CurrentValue "$daysSinceUpdate days ago" `
        -ExpectedValue "Within 30 days" `
        -Remediation "Check for and install Windows updates"
    
    if ($updateRecent) {
        Write-Host "  [PASS] Updates installed $daysSinceUpdate days ago" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Last update was $daysSinceUpdate days ago" -ForegroundColor Yellow
    }
}

# Check Windows version
$osInfo = Get-CimInstance Win32_OperatingSystem
$buildNumber = [int]$osInfo.BuildNumber
$windows11MinBuild = 22000
$supportedBuild = $buildNumber -ge $windows11MinBuild

Add-ComplianceCheck -Category "Update Management" `
    -Check "Supported Windows Version" `
    -Requirement "SOC 2 CC8.1 - Supported Software" `
    -NIST "SI-2" `
    -CIS "7.2" `
    -ISO27001 "A.12.6.1" `
    -PCIDSS "6.2" `
    -Passed $supportedBuild `
    -CurrentValue "Build $buildNumber" `
    -ExpectedValue "Supported Windows 11 build (22000+)" `
    -Remediation "Upgrade to a supported Windows version"

if ($supportedBuild) {
    Write-Host "  [PASS] Running supported Windows version (Build $buildNumber)" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Windows version may be unsupported (Build $buildNumber)" -ForegroundColor Yellow
}

Write-Host ""
