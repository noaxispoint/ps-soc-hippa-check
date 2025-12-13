<#
.SYNOPSIS
    Validates Change Management Controls
.DESCRIPTION
    Tests system change logging, approval workflows, and configuration management
    SOX ITGC-03 | NIST 800-53 CM-3 | ISO 27001 A.12.1.2
#>

Write-Host "Checking Change Management Controls..." -ForegroundColor Cyan

# Check for System Center Configuration Manager (SCCM) or similar
$sccmService = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue

if ($sccmService) {
    $sccmRunning = $sccmService.Status -eq 'Running'

    Add-ComplianceCheck -Category "Change Management" `
        -Check "Configuration Management Client (SCCM)" `
        -Requirement "SOX ITGC-03 - Centralized change management" `
        -NIST "CM-3" `
        -ISO27001 "A.12.1.2" `
        -SOX "ITGC-03" `
        -Passed $sccmRunning `
        -CurrentValue "SCCM Client: $($sccmService.Status)" `
        -ExpectedValue "Running (managed environment)" `
        -Remediation "Ensure SCCM client is operational for change tracking"

    if ($sccmRunning) {
        Write-Host "  [PASS] Configuration management client (SCCM) is running" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] SCCM client installed but not running" -ForegroundColor Gray
    }
} else {
    Add-ComplianceCheck -Category "Change Management" `
        -Check "Configuration Management System" `
        -Requirement "SOX ITGC-03 - Change tracking" `
        -NIST "CM-3" `
        -SOX "ITGC-03" `
        -Passed $false `
        -CurrentValue "No configuration management client detected" `
        -ExpectedValue "SCCM, Intune, or equivalent installed" `
        -Remediation "Deploy enterprise configuration management solution"

    Write-Host "  [INFO] No configuration management client detected (verify change management process)" -ForegroundColor Gray
}

# Check for change audit logging in Event Logs
try {
    # Look for software installation events (Event ID 11707 - Successful install, 11724 - Removal)
    $installEvents = Get-WinEvent -LogName "Application" -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -eq "MsiInstaller" -and ($_.Id -eq 11707 -or $_.Id -eq 11724) }

    if ($installEvents) {
        $installCount = ($installEvents | Where-Object { $_.Id -eq 11707 }).Count
        $removalCount = ($installEvents | Where-Object { $_.Id -eq 11724 }).Count

        Add-ComplianceCheck -Category "Change Management" `
            -Check "Software Installation Logging" `
            -Requirement "SOX ITGC-03 - Change documentation" `
            -NIST "CM-3(3), AU-2" `
            -ISO27001 "A.12.1.2" `
            -SOX "ITGC-03" `
            -Passed $true `
            -CurrentValue "$installCount install(s), $removalCount removal(s) logged recently" `
            -ExpectedValue "Software changes are logged" `
            -Remediation "Software installation logging is active"

        Write-Host "  [PASS] Software installation events logged: $installCount install(s), $removalCount removal(s)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] No recent software installation events (system may be stable)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check software installation logs" -ForegroundColor Gray
}

# Check for Windows Update change logs
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $historyCount = $updateSearcher.GetTotalHistoryCount()

    if ($historyCount -gt 0) {
        # Get recent updates (last 30 days)
        $recentHistory = $updateSearcher.QueryHistory(0, [Math]::Min(30, $historyCount))
        $recentCount = ($recentHistory | Where-Object { $_.Date -gt (Get-Date).AddDays(-30) }).Count

        Add-ComplianceCheck -Category "Change Management" `
            -Check "Patch Management Change Log" `
            -Requirement "SOX ITGC-03 - Patch change tracking" `
            -NIST "CM-3, SI-2" `
            -SOX "ITGC-03" `
            -Passed ($recentCount -gt 0) `
            -CurrentValue "$recentCount update(s) in last 30 days" `
            -ExpectedValue "Patch changes documented" `
            -Remediation "Windows Update history is being maintained"

        if ($recentCount -gt 0) {
            Write-Host "  [PASS] $recentCount patch update(s) logged in last 30 days" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] No patch updates in last 30 days (verify patch management)" -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host "  [INFO] Unable to query update history" -ForegroundColor Gray
}

# Check for system configuration change events (Event ID 4719 - Audit policy change)
try {
    $auditChanges = Get-WinEvent -LogName "Security" -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 4719 }

    if ($auditChanges) {
        Add-ComplianceCheck -Category "Change Management" `
            -Check "Audit Policy Change Logging" `
            -Requirement "SOX ITGC-03 - Security configuration changes" `
            -NIST "CM-3, AU-2" `
            -ISO27001 "A.12.1.2" `
            -SOX "ITGC-03" `
            -Passed $true `
            -CurrentValue "$($auditChanges.Count) audit policy change(s) logged" `
            -ExpectedValue "Configuration changes logged" `
            -Remediation "Audit policy change logging is enabled"

        Write-Host "  [PASS] $($auditChanges.Count) audit policy change(s) logged (change tracking active)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] No recent audit policy changes (system configuration stable)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check audit policy change logs" -ForegroundColor Gray
}

# Check for registry change auditing
$regAudit = auditpol /get /subcategory:"Registry" /r 2>$null | ConvertFrom-Csv |
    Where-Object { $_.'Inclusion Setting' -match "Success" }

$regAuditEnabled = $null -ne $regAudit

Add-ComplianceCheck -Category "Change Management" `
    -Check "Registry Change Auditing" `
    -Requirement "SOX ITGC-03 - System configuration change tracking" `
    -NIST "CM-3(5), AU-2" `
    -ISO27001 "A.12.1.2" `
    -SOX "ITGC-03" `
    -Passed $regAuditEnabled `
    -CurrentValue $(if ($regAuditEnabled) { "Enabled" } else { "Not enabled" }) `
    -ExpectedValue "Success events audited" `
    -Remediation "auditpol /set /subcategory:`"Registry`" /success:enable"

if ($regAuditEnabled) {
    Write-Host "  [PASS] Registry change auditing is enabled" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Registry change auditing is not enabled" -ForegroundColor Yellow
}

# Check for scheduled task creation/modification events (Event ID 4698, 4702)
try {
    $taskEvents = Get-WinEvent -LogName "Security" -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 4698 -or $_.Id -eq 4702 }

    if ($taskEvents) {
        Add-ComplianceCheck -Category "Change Management" `
            -Check "Scheduled Task Change Logging" `
            -Requirement "SOX ITGC-03 - Automated job changes" `
            -NIST "CM-3, AU-2" `
            -SOX "ITGC-03" `
            -Passed $true `
            -CurrentValue "$($taskEvents.Count) scheduled task change(s) logged" `
            -ExpectedValue "Task changes documented" `
            -Remediation "Scheduled task change logging is enabled"

        Write-Host "  [PASS] $($taskEvents.Count) scheduled task change(s) logged" -ForegroundColor Green
    }

} catch {
    Write-Host "  [INFO] Unable to check scheduled task change logs" -ForegroundColor Gray
}

# Check for Group Policy change events (Event ID 4713, 4716, 4717, 4718, 4739)
try {
    $gpChanges = Get-WinEvent -LogName "Security" -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in @(4713, 4716, 4717, 4718, 4739) }

    if ($gpChanges) {
        Add-ComplianceCheck -Category "Change Management" `
            -Check "Group Policy Change Logging" `
            -Requirement "SOX ITGC-03 - Policy change documentation" `
            -NIST "CM-3, AU-2" `
            -ISO27001 "A.12.1.2" `
            -SOX "ITGC-03" `
            -Passed $true `
            -CurrentValue "$($gpChanges.Count) Group Policy change(s) logged" `
            -ExpectedValue "Policy changes tracked" `
            -Remediation "Group Policy change logging is enabled"

        Write-Host "  [PASS] $($gpChanges.Count) Group Policy change(s) logged" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] No recent Group Policy changes detected" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check Group Policy change logs" -ForegroundColor Gray
}

# Check for change approval workflow (ServiceNow, JIRA, etc.)
# This is informational - would require API integration for full validation
Write-Host "  [INFO] Change approval workflow validation:" -ForegroundColor Gray
Write-Host "    Verify change tickets are created and approved before implementation" -ForegroundColor Gray
Write-Host "    Common systems: ServiceNow, JIRA, BMC Remedy, Azure DevOps" -ForegroundColor Gray

# Check for version control integration
$gitInstalled = Test-Path "C:\Program Files\Git\cmd\git.exe"

if ($gitInstalled) {
    Write-Host "  [INFO] Git version control detected (supports code change tracking)" -ForegroundColor Gray
}

# Check for system baseline/configuration documentation
Write-Host "  [INFO] SOX change management requirements:" -ForegroundColor Gray
Write-Host "    - Documented change request and approval process" -ForegroundColor Gray
Write-Host "    - Testing evidence before production deployment" -ForegroundColor Gray
Write-Host "    - Backout procedures documented" -ForegroundColor Gray
Write-Host "    - Post-implementation review" -ForegroundColor Gray

Write-Host ""
