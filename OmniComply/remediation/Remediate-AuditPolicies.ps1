<#
.SYNOPSIS
    Remediate Audit Policy Configuration
.DESCRIPTION
    Automatically configures all required audit policies for SOC 2 and HIPAA compliance
.NOTES
    WARNING: This will modify system audit policies. Review before running.
#>

#Requires -RunAsAdministrator

Write-Host "Remediating Audit Policies..." -ForegroundColor Cyan
Write-Host "WARNING: This will modify system audit policies" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Continue? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Remediation cancelled" -ForegroundColor Yellow
    exit 0
}

# Configure all required audit policies
$policies = @(
    "Credential Validation",
    "Kerberos Authentication Service",
    "Kerberos Service Ticket Operations",
    "User Account Management",
    "Computer Account Management",
    "Security Group Management",
    "Distribution Group Management",
    "Application Group Management",
    "Other Account Management Events",
    "Logon",
    "Special Logon",
    "File System",
    "Registry",
    "Removable Storage",
    "Detailed File Share",
    "Audit Policy Change",
    "Authentication Policy Change",
    "Authorization Policy Change",
    "Sensitive Privilege Use",
    "Security State Change",
    "Security System Extension",
    "System Integrity"
)

foreach ($policy in $policies) {
    Write-Host "Configuring: $policy" -ForegroundColor Gray
    auditpol /set /subcategory:"$policy" /success:enable /failure:enable
}

# Special cases
Write-Host "Configuring: Logoff (success only)" -ForegroundColor Gray
auditpol /set /subcategory:"Logoff" /success:enable

Write-Host "Configuring: Account Lockout (failure only)" -ForegroundColor Gray
auditpol /set /subcategory:"Account Lockout" /failure:enable

Write-Host "Configuring: Process Creation (success only)" -ForegroundColor Gray
auditpol /set /subcategory:"Process Creation" /success:enable

# Enable command line auditing
Write-Host "Enabling command line process auditing" -ForegroundColor Gray
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# Enable audit policy subcategory override
Write-Host "Enabling advanced audit policy override" -ForegroundColor Gray
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord

Write-Host ""
Write-Host "Audit policy remediation complete!" -ForegroundColor Green
Write-Host "Run .\Invoke-OmniComply.ps1 to verify" -ForegroundColor Cyan
