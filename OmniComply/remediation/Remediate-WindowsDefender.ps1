<#
.SYNOPSIS
    Remediate Windows Defender and Firewall Settings
.DESCRIPTION
    Enables and configures Windows Defender real-time protection, updates signatures,
    enables advanced features, and configures Windows Firewall
.NOTES
    WARNING: This will modify Windows Defender and Firewall settings.
    Requires: Administrator privileges
#>

#Requires -RunAsAdministrator

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  WINDOWS DEFENDER & FIREWALL REMEDIATION" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
Write-Host "This script will configure:" -ForegroundColor Cyan
Write-Host "  • Enable Real-Time Protection" -ForegroundColor White
Write-Host "  • Update antivirus signatures" -ForegroundColor White
Write-Host "  • Enable all firewall profiles" -ForegroundColor White
Write-Host "  • Enable PUA (Potentially Unwanted Apps) protection" -ForegroundColor White
Write-Host "  • Enable Network Protection" -ForegroundColor White
Write-Host "  • Enable Cloud-delivered protection" -ForegroundColor White
Write-Host "  • Enable Behavior Monitoring" -ForegroundColor White
Write-Host ""

$confirm = Read-Host "Continue? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Remediation cancelled" -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Starting Windows Defender remediation..." -ForegroundColor Cyan
Write-Host ""

# 1. Enable Real-Time Protection
Write-Host "[1/8] Enabling Real-Time Protection..." -ForegroundColor Gray
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Write-Host "  ✓ Real-Time Protection enabled" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to enable Real-Time Protection: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Update Antivirus Signatures
Write-Host "[2/8] Updating antivirus signatures..." -ForegroundColor Gray
try {
    Update-MpSignature -ErrorAction Stop
    $status = Get-MpComputerStatus
    $lastUpdate = $status.AntivirusSignatureLastUpdated
    Write-Host "  ✓ Signatures updated (Last: $lastUpdate)" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to update signatures: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Enable All Firewall Profiles
Write-Host "[3/8] Enabling all firewall profiles..." -ForegroundColor Gray
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Write-Host "  ✓ All firewall profiles enabled" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to enable firewall profiles: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. Enable PUA Protection
Write-Host "[4/8] Enabling PUA protection..." -ForegroundColor Gray
try {
    Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
    Write-Host "  ✓ PUA protection enabled" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to enable PUA protection: $($_.Exception.Message)" -ForegroundColor Red
}

# 5. Enable Network Protection
Write-Host "[5/8] Enabling Network Protection..." -ForegroundColor Gray
try {
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
    Write-Host "  ✓ Network Protection enabled" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to enable Network Protection: $($_.Exception.Message)" -ForegroundColor Red
}

# 6. Enable Cloud-Delivered Protection
Write-Host "[6/8] Enabling Cloud-delivered protection..." -ForegroundColor Gray
try {
    Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
    Write-Host "  ✓ Cloud-delivered protection enabled (Advanced)" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to enable Cloud-delivered protection: $($_.Exception.Message)" -ForegroundColor Red
}

# 7. Enable Behavior Monitoring
Write-Host "[7/8] Enabling Behavior Monitoring..." -ForegroundColor Gray
try {
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
    Write-Host "  ✓ Behavior Monitoring enabled" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to enable Behavior Monitoring: $($_.Exception.Message)" -ForegroundColor Red
}

# 8. Enable IOAV Protection (scanning downloaded files and attachments)
Write-Host "[8/8] Enabling IOAV Protection..." -ForegroundColor Gray
try {
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
    Write-Host "  ✓ IOAV Protection enabled" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to enable IOAV Protection: $($_.Exception.Message)" -ForegroundColor Red
}

# Verify settings
Write-Host ""
Write-Host "Verifying Windows Defender status..." -ForegroundColor Cyan
try {
    $status = Get-MpComputerStatus
    $prefs = Get-MpPreference

    Write-Host ""
    Write-Host "Current Status:" -ForegroundColor White
    Write-Host "  Real-Time Protection: $(if ($status.RealTimeProtectionEnabled) { '✓ Enabled' } else { '✗ Disabled' })" -ForegroundColor $(if ($status.RealTimeProtectionEnabled) { 'Green' } else { 'Red' })
    Write-Host "  Antivirus Signatures: $(($status.AntivirusSignatureAge)) days old" -ForegroundColor $(if ($status.AntivirusSignatureAge -le 7) { 'Green' } else { 'Yellow' })
    Write-Host "  Behavior Monitoring: $(if (-not $prefs.DisableBehaviorMonitoring) { '✓ Enabled' } else { '✗ Disabled' })" -ForegroundColor $(if (-not $prefs.DisableBehaviorMonitoring) { 'Green' } else { 'Red' })
    Write-Host "  Cloud Protection: $(switch ($prefs.MAPSReporting) { 0 { 'Disabled' } 1 { 'Basic' } 2 { '✓ Advanced' } default { 'Unknown' } })" -ForegroundColor Green
    Write-Host "  Network Protection: $(switch ($prefs.EnableNetworkProtection) { 0 { 'Disabled' } 1 { '✓ Enabled' } 2 { 'Audit' } default { 'Unknown' } })" -ForegroundColor $(if ($prefs.EnableNetworkProtection -eq 1) { 'Green' } else { 'Yellow' })
    Write-Host "  PUA Protection: $(switch ($prefs.PUAProtection) { 0 { 'Disabled' } 1 { '✓ Enabled' } 2 { 'Audit' } default { 'Unknown' } })" -ForegroundColor $(if ($prefs.PUAProtection -eq 1) { 'Green' } else { 'Yellow' })
} catch {
    Write-Host "  ✗ Failed to verify status: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Verifying Windows Firewall status..." -ForegroundColor Cyan
try {
    $profiles = Get-NetFirewallProfile
    Write-Host ""
    foreach ($profile in $profiles) {
        $status = if ($profile.Enabled) { "✓ Enabled" } else { "✗ Disabled" }
        $color = if ($profile.Enabled) { "Green" } else { "Red" }
        Write-Host "  $($profile.Name) Profile: $status" -ForegroundColor $color
    }
} catch {
    Write-Host "  ✗ Failed to verify firewall: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  WINDOWS DEFENDER REMEDIATION COMPLETE" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Windows Defender is now fully configured" -ForegroundColor White
Write-Host "  2. Run .\Invoke-OmniComply.ps1 to verify" -ForegroundColor Cyan
Write-Host ""
