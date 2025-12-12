<#
.SYNOPSIS
    Validates Security Settings Related to Logging
.DESCRIPTION
    Checks registry settings and security configurations that impact audit logging
#>

Write-Host "Checking Security Settings..." -ForegroundColor Cyan

# Check if command line process auditing is enabled
$cmdLineAudit = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue

$cmdLineEnabled = $null -ne $cmdLineAudit -and $cmdLineAudit.ProcessCreationIncludeCmdLine_Enabled -eq 1

Add-ComplianceCheck -Category "Security Settings" `
    -Check "Command Line Process Auditing" `
    -Requirement "HIPAA § 164.312(b) - Detailed Process Tracking" `
    -Passed $cmdLineEnabled `
    -CurrentValue $(if ($cmdLineEnabled) { "Enabled" } else { "Disabled" }) `
    -ExpectedValue "Enabled" `
    -Remediation "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord"

if ($cmdLineEnabled) {
    Write-Host "  [PASS] Command line process auditing is enabled" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Command line process auditing is disabled" -ForegroundColor Red
}

# Check if audit policy subcategories override category policies
$auditPolicyOverride = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue

$overrideEnabled = $null -ne $auditPolicyOverride -and $auditPolicyOverride.SCENoApplyLegacyAuditPolicy -eq 1

Add-ComplianceCheck -Category "Security Settings" `
    -Check "Advanced Audit Policy Override" `
    -Requirement "SOC 2 CC6.1 - Proper Audit Configuration" `
    -Passed $overrideEnabled `
    -CurrentValue $(if ($overrideEnabled) { "Enabled" } else { "Disabled" }) `
    -ExpectedValue "Enabled" `
    -Remediation "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord"

if ($overrideEnabled) {
    Write-Host "  [PASS] Advanced audit policy override is enabled" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Advanced audit policy override is disabled" -ForegroundColor Red
}

# Check PowerShell module logging
$psModuleLogging = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -ErrorAction SilentlyContinue

$psModuleEnabled = $null -ne $psModuleLogging -and $psModuleLogging.EnableModuleLogging -eq 1

Add-ComplianceCheck -Category "Security Settings" `
    -Check "PowerShell Module Logging" `
    -Requirement "SOC 2 CC7.2 - Command Execution Monitoring" `
    -Passed $psModuleEnabled `
    -CurrentValue $(if ($psModuleEnabled) { "Enabled" } else { "Disabled" }) `
    -ExpectedValue "Enabled" `
    -Remediation "Enable via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell"

if ($psModuleEnabled) {
    Write-Host "  [PASS] PowerShell module logging is enabled" -ForegroundColor Green
} else {
    Write-Host "  [INFO] PowerShell module logging is not enabled (recommended for enhanced monitoring)" -ForegroundColor Gray
}

# Check PowerShell script block logging
$psScriptBlockLogging = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue

$psScriptBlockEnabled = $null -ne $psScriptBlockLogging -and $psScriptBlockLogging.EnableScriptBlockLogging -eq 1

Add-ComplianceCheck -Category "Security Settings" `
    -Check "PowerShell Script Block Logging" `
    -Requirement "SOC 2 CC7.2 - Command Execution Monitoring" `
    -Passed $psScriptBlockEnabled `
    -CurrentValue $(if ($psScriptBlockEnabled) { "Enabled" } else { "Disabled" }) `
    -ExpectedValue "Enabled" `
    -Remediation "Enable via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell"

if ($psScriptBlockEnabled) {
    Write-Host "  [PASS] PowerShell script block logging is enabled" -ForegroundColor Green
} else {
    Write-Host "  [INFO] PowerShell script block logging is not enabled (recommended for enhanced monitoring)" -ForegroundColor Gray
}

Write-Host ""
