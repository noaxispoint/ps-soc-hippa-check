<#
.SYNOPSIS
    Master Remediation Script
.DESCRIPTION
    Runs all remediation scripts to fix compliance issues
.PARAMETER IUnderstandTheRisksAndAccept
    Bypass the "I UNDERSTAND" confirmation prompt for automated execution
.NOTES
    WARNING: This will make significant system changes. Use with caution!
#>

[CmdletBinding()]
param(
    [switch]$IUnderstandTheRisksAndAccept
)

#Requires -RunAsAdministrator

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host "  MASTER REMEDIATION SCRIPT" -ForegroundColor Red
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""
Write-Host "WARNING: This will make significant changes to:" -ForegroundColor Yellow
Write-Host "  • Audit policies" -ForegroundColor Yellow
Write-Host "  • Event log sizes" -ForegroundColor Yellow
Write-Host "  • Password policies" -ForegroundColor Yellow
Write-Host "  • Network security settings" -ForegroundColor Yellow
Write-Host "  • Windows Defender configuration" -ForegroundColor Yellow
Write-Host ""
Write-Host "It is STRONGLY recommended to:" -ForegroundColor Yellow
Write-Host "  1. Review individual remediation scripts first" -ForegroundColor Yellow
Write-Host "  2. Test in a non-production environment" -ForegroundColor Yellow
Write-Host "  3. Create a system restore point" -ForegroundColor Yellow
Write-Host ""

if (-not $IUnderstandTheRisksAndAccept) {
    $confirm = Read-Host "Type 'I UNDERSTAND' to continue"
    if ($confirm -ne "I UNDERSTAND") {
        Write-Host "Remediation cancelled" -ForegroundColor Yellow
        exit 0
    }
}

Write-Host ""
Write-Host "Starting remediation..." -ForegroundColor Cyan
Write-Host ""

# Run individual remediation scripts
$scriptPath = $PSScriptRoot

Write-Host "Running remediation scripts..." -ForegroundColor Cyan
Write-Host ""

if (Test-Path "$scriptPath\Remediate-AuditPolicies.ps1") {
    Write-Host "1. Audit Policies" -ForegroundColor White
    & "$scriptPath\Remediate-AuditPolicies.ps1" -Force
}

if (Test-Path "$scriptPath\Remediate-EventLogs.ps1") {
    Write-Host "2. Event Logs" -ForegroundColor White
    & "$scriptPath\Remediate-EventLogs.ps1"
}

if (Test-Path "$scriptPath\Remediate-PasswordPolicies.ps1") {
    Write-Host "3. Password Policies" -ForegroundColor White
    & "$scriptPath\Remediate-PasswordPolicies.ps1" -Force
}

if (Test-Path "$scriptPath\Remediate-NetworkSecurity.ps1") {
    Write-Host "4. Network Security" -ForegroundColor White
    & "$scriptPath\Remediate-NetworkSecurity.ps1" -Force
}

if (Test-Path "$scriptPath\Remediate-WindowsDefender.ps1") {
    Write-Host "5. Windows Defender & Firewall" -ForegroundColor White
    & "$scriptPath\Remediate-WindowsDefender.ps1" -Force
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  REMEDIATION COMPLETE" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Restart your computer" -ForegroundColor White
Write-Host "  2. Run .\Invoke-OmniComply.ps1 to verify" -ForegroundColor White
Write-Host ""
