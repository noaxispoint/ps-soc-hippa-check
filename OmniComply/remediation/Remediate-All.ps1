<#
.SYNOPSIS
    Master Remediation Script
.DESCRIPTION
    Runs all remediation scripts to fix compliance issues
.NOTES
    WARNING: This will make significant system changes. Use with caution!
#>

#Requires -RunAsAdministrator

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host "  MASTER REMEDIATION SCRIPT" -ForegroundColor Red
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""
Write-Host "WARNING: This will make significant changes to:" -ForegroundColor Yellow
Write-Host "  • Audit policies" -ForegroundColor Yellow
Write-Host "  • Event log sizes" -ForegroundColor Yellow
Write-Host "  • Security settings" -ForegroundColor Yellow
Write-Host ""
Write-Host "It is STRONGLY recommended to:" -ForegroundColor Yellow
Write-Host "  1. Review individual remediation scripts first" -ForegroundColor Yellow
Write-Host "  2. Test in a non-production environment" -ForegroundColor Yellow
Write-Host "  3. Create a system restore point" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Type 'I UNDERSTAND' to continue"
if ($confirm -ne "I UNDERSTAND") {
    Write-Host "Remediation cancelled" -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Starting remediation..." -ForegroundColor Cyan
Write-Host ""

# Run individual remediation scripts
$scriptPath = $PSScriptRoot

if (Test-Path "$scriptPath\Remediate-AuditPolicies.ps1") {
    & "$scriptPath\Remediate-AuditPolicies.ps1"
}

if (Test-Path "$scriptPath\Remediate-EventLogs.ps1") {
    & "$scriptPath\Remediate-EventLogs.ps1"
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  REMEDIATION COMPLETE" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Restart your computer" -ForegroundColor White
Write-Host "  2. Run .\Run-ComplianceCheck.ps1 to verify" -ForegroundColor White
Write-Host ""
