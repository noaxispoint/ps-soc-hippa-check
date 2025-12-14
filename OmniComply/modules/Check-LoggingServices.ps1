<#
.SYNOPSIS
    Validates Logging Services Health
.DESCRIPTION
    Checks if required logging services are running and configured properly
#>

Write-Host "Checking Logging Services..." -ForegroundColor Cyan

# Check Event Log service
$eventLogService = Get-Service -Name EventLog -ErrorAction SilentlyContinue

if ($eventLogService) {
    $serviceRunning = $eventLogService.Status -eq 'Running'
    $serviceAutomatic = $eventLogService.StartType -eq 'Automatic'
    
    Add-ComplianceCheck -Category "Logging Services" `
        -Check "Windows Event Log Service Running" `
        -Requirement "HIPAA § 164.312(b) - Audit Controls Active" `
        -NIST "AU-6" `
        -CIS "8.2" `
        -ISO27001 "A.12.4.1" `
        -SOX "ITGC-05" `
        -Passed $serviceRunning `
        -CurrentValue $eventLogService.Status `
        -ExpectedValue "Running" `
        -Remediation "Start-Service -Name EventLog"
    
    if ($serviceRunning) {
        Write-Host "  [PASS] Windows Event Log service is running" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Windows Event Log service is $($eventLogService.Status)" -ForegroundColor Red
    }
    
    Add-ComplianceCheck -Category "Logging Services" `
        -Check "Windows Event Log Service Startup Type" `
        -Requirement "SOC 2 CC7.2 - System Monitoring" `
        -NIST "AU-6" `
        -CIS "8.2" `
        -ISO27001 "A.12.4.1" `
        -SOX "ITGC-05" `
        -Passed $serviceAutomatic `
        -CurrentValue $eventLogService.StartType `
        -ExpectedValue "Automatic" `
        -Remediation "Set-Service -Name EventLog -StartupType Automatic"
    
    if ($serviceAutomatic) {
        Write-Host "  [PASS] Windows Event Log service startup is Automatic" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Windows Event Log service startup is $($eventLogService.StartType)" -ForegroundColor Yellow
    }
} else {
    Add-ComplianceCheck -Category "Logging Services" `
        -Check "Windows Event Log Service" `
        -Requirement "HIPAA § 164.312(b) - Audit Controls" `
        -NIST "AU-6" `
        -CIS "8.2" `
        -ISO27001 "A.12.4.1" `
        -SOX "ITGC-05" `
        -Passed $false `
        -CurrentValue "Service not found" `
        -ExpectedValue "Service exists and running" `
        -Remediation "Critical system service missing - reinstall Windows"
    
    Write-Host "  [FAIL] Windows Event Log service not found!" -ForegroundColor Red
}

# Check WinRM service (for event forwarding)
$winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue

if ($winrmService) {
    $winrmRunning = $winrmService.Status -eq 'Running'
    
    Add-ComplianceCheck -Category "Logging Services" `
        -Check "WinRM Service (for log forwarding)" `
        -Requirement "SOC 2 CC7.2 - Centralized Log Collection" `
        -NIST "AU-6, AU-9" `
        -CIS "8.2" `
        -ISO27001 "A.12.4.1, A.12.4.2" `
        -SOX "ITGC-05" `
        -Passed $winrmRunning `
        -CurrentValue $winrmService.Status `
        -ExpectedValue "Running (if using WinRM forwarding)" `
        -Remediation "Start-Service -Name WinRM; Enable-PSRemoting -Force"
    
    if ($winrmRunning) {
        Write-Host "  [PASS] WinRM service is running (event forwarding ready)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] WinRM service is $($winrmService.Status) (may not be needed if not forwarding)" -ForegroundColor Gray
    }
}

# Check Task Scheduler service
$taskScheduler = Get-Service -Name Schedule -ErrorAction SilentlyContinue

if ($taskScheduler) {
    $taskSchedulerRunning = $taskScheduler.Status -eq 'Running'
    
    Add-ComplianceCheck -Category "Logging Services" `
        -Check "Task Scheduler Service" `
        -Requirement "HIPAA § 164.308(a)(1)(ii)(D) - Automated Log Review" `
        -NIST "AU-6" `
        -CIS "8.2" `
        -ISO27001 "A.12.4.1" `
        -SOX "ITGC-05" `
        -Passed $taskSchedulerRunning `
        -CurrentValue $taskScheduler.Status `
        -ExpectedValue "Running" `
        -Remediation "Start-Service -Name Schedule"
    
    if ($taskSchedulerRunning) {
        Write-Host "  [PASS] Task Scheduler service is running" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Task Scheduler service is $($taskScheduler.Status)" -ForegroundColor Red
    }
}

Write-Host ""
