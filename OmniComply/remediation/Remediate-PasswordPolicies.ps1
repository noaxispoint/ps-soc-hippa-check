<#
.SYNOPSIS
    Remediate Password and Account Lockout Policies
.DESCRIPTION
    Automatically configures password complexity, length, history, and account lockout policies
    for SOC 2, HIPAA, NIST, CIS, ISO 27001, PCI-DSS, and SOX compliance
.NOTES
    WARNING: This will modify system password policies. Review before running.
    Requires: Administrator privileges
#>

#Requires -RunAsAdministrator

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  PASSWORD POLICY REMEDIATION" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
Write-Host "This script will configure:" -ForegroundColor Cyan
Write-Host "  • Minimum password length: 12 characters" -ForegroundColor White
Write-Host "  • Password complexity: Enabled" -ForegroundColor White
Write-Host "  • Password history: 12 passwords" -ForegroundColor White
Write-Host "  • Maximum password age: 90 days" -ForegroundColor White
Write-Host "  • Minimum password age: 1 day" -ForegroundColor White
Write-Host "  • Account lockout threshold: 5 invalid attempts" -ForegroundColor White
Write-Host "  • Account lockout duration: 30 minutes" -ForegroundColor White
Write-Host "  • Reset lockout counter: 30 minutes" -ForegroundColor White
Write-Host ""
Write-Host "WARNING: These changes will affect all user accounts!" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Continue? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Remediation cancelled" -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Starting password policy remediation..." -ForegroundColor Cyan
Write-Host ""

# Export current security policy
Write-Host "[1/3] Exporting current security policy..." -ForegroundColor Gray
secedit /export /cfg "$env:TEMP\secpol_backup.cfg" /quiet | Out-Null

# Create new security policy configuration
Write-Host "[2/3] Configuring password policies..." -ForegroundColor Gray

$securityTemplate = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 12
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

$securityTemplate | Out-File -FilePath "$env:TEMP\secpol_new.cfg" -Encoding unicode -Force

# Import the new security policy
Write-Host "[3/3] Applying new password policies..." -ForegroundColor Gray
secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol_new.cfg" /quiet

# Verify the changes
Write-Host ""
Write-Host "Verifying changes..." -ForegroundColor Cyan

secedit /export /cfg "$env:TEMP\secpol_verify.cfg" /quiet | Out-Null
$policyContent = Get-Content "$env:TEMP\secpol_verify.cfg"

$minPasswordLength = ($policyContent | Select-String "MinimumPasswordLength = (\d+)").Matches.Groups[1].Value
$passwordComplexity = ($policyContent | Select-String "PasswordComplexity = (\d+)").Matches.Groups[1].Value
$passwordHistory = ($policyContent | Select-String "PasswordHistorySize = (\d+)").Matches.Groups[1].Value
$lockoutThreshold = ($policyContent | Select-String "LockoutBadCount = (\d+)").Matches.Groups[1].Value
$maxPasswordAge = ($policyContent | Select-String "MaximumPasswordAge = (\d+)").Matches.Groups[1].Value
$minPasswordAge = ($policyContent | Select-String "MinimumPasswordAge = (\d+)").Matches.Groups[1].Value
$lockoutDuration = ($policyContent | Select-String "LockoutDuration = (\d+)").Matches.Groups[1].Value
$resetLockoutCount = ($policyContent | Select-String "ResetLockoutCount = (\d+)").Matches.Groups[1].Value

Write-Host ""
Write-Host "Current Settings:" -ForegroundColor White
Write-Host "  ✓ Minimum password length: $minPasswordLength characters" -ForegroundColor Green
Write-Host "  ✓ Password complexity: $(if ($passwordComplexity -eq '1') { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($passwordComplexity -eq '1') { 'Green' } else { 'Red' })
Write-Host "  ✓ Password history: $passwordHistory passwords" -ForegroundColor Green
Write-Host "  ✓ Maximum password age: $maxPasswordAge days" -ForegroundColor Green
Write-Host "  ✓ Minimum password age: $minPasswordAge day(s)" -ForegroundColor Green
Write-Host "  ✓ Account lockout threshold: $lockoutThreshold attempts" -ForegroundColor Green
Write-Host "  ✓ Account lockout duration: $lockoutDuration minutes" -ForegroundColor Green
Write-Host "  ✓ Reset lockout counter: $resetLockoutCount minutes" -ForegroundColor Green

# Cleanup temporary files
Remove-Item "$env:TEMP\secpol_backup.cfg" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secpol_new.cfg" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secpol_verify.cfg" -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Password policy remediation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "  • Users will need to change passwords at next logon if they don't meet new requirements" -ForegroundColor White
Write-Host "  • Account lockouts will now occur after 5 failed login attempts" -ForegroundColor White
Write-Host "  • Run .\Invoke-OmniComply.ps1 to verify compliance" -ForegroundColor Cyan
Write-Host ""
