<#
.SYNOPSIS
    Remediate Event Log Configuration
.DESCRIPTION
    Configures event log sizes to meet compliance requirements
#>

#Requires -RunAsAdministrator

Write-Host "Remediating Event Log Configuration..." -ForegroundColor Cyan
Write-Host ""

# Configure Security log to 2GB
Write-Host "Setting Security log size to 2GB..." -ForegroundColor Gray
wevtutil sl Security /ms:2147483648

# Configure Application log to 1GB
Write-Host "Setting Application log size to 1GB..." -ForegroundColor Gray
wevtutil sl Application /ms:1073741824

# Configure System log to 1GB
Write-Host "Setting System log size to 1GB..." -ForegroundColor Gray
wevtutil sl System /ms:1073741824

Write-Host ""
Write-Host "Event log remediation complete!" -ForegroundColor Green
