<#
.SYNOPSIS
    Remediate Network Security Settings
.DESCRIPTION
    Disables insecure protocols (SMBv1, LLMNR, NetBIOS) and enables secure configurations
    for SOC 2, HIPAA, NIST, CIS, ISO 27001, and PCI-DSS compliance
.NOTES
    WARNING: This will modify network security settings. Review before running.
    Requires: Administrator privileges
    May require system restart
#>

#Requires -RunAsAdministrator

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  NETWORK SECURITY REMEDIATION" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
Write-Host "This script will configure:" -ForegroundColor Cyan
Write-Host "  • Disable SMBv1 protocol (security risk)" -ForegroundColor White
Write-Host "  • Enable SMB client signing (required)" -ForegroundColor White
Write-Host "  • Enable SMB server signing (required)" -ForegroundColor White
Write-Host "  • Disable LLMNR (credential theft prevention)" -ForegroundColor White
Write-Host "  • Enable RDP Network Level Authentication" -ForegroundColor White
Write-Host "  • Enable Windows Firewall logging" -ForegroundColor White
Write-Host ""
Write-Host "WARNING: Some changes may require a system restart!" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Continue? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Remediation cancelled" -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Starting network security remediation..." -ForegroundColor Cyan
Write-Host ""

$restartRequired = $false

# 1. Disable SMBv1
Write-Host "[1/6] Disabling SMBv1 protocol..." -ForegroundColor Gray
try {
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smbv1 -and $smbv1.State -ne 'Disabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
        Write-Host "  ✓ SMBv1 disabled (restart required)" -ForegroundColor Green
        $restartRequired = $true
    } else {
        Write-Host "  ✓ SMBv1 already disabled" -ForegroundColor Green
    }
} catch {
    Write-Host "  ✗ Failed to disable SMBv1: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Enable SMB Client Signing
Write-Host "[2/6] Enabling SMB client signing..." -ForegroundColor Gray
try {
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Host "  ✓ SMB client signing enabled" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to enable SMB client signing: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Enable SMB Server Signing
Write-Host "[3/6] Enabling SMB server signing..." -ForegroundColor Gray
try {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Host "  ✓ SMB server signing enabled" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to enable SMB server signing: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. Disable LLMNR
Write-Host "[4/6] Disabling LLMNR..." -ForegroundColor Gray
try {
    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $llmnrPath)) {
        New-Item -Path $llmnrPath -Force | Out-Null
    }
    Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -ErrorAction Stop
    Write-Host "  ✓ LLMNR disabled" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to disable LLMNR: $($_.Exception.Message)" -ForegroundColor Red
}

# 5. Enable RDP Network Level Authentication
Write-Host "[5/6] Enabling RDP Network Level Authentication..." -ForegroundColor Gray
try {
    $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    if (Test-Path $rdpPath) {
        Set-ItemProperty -Path $rdpPath -Name "UserAuthentication" -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "  ✓ RDP NLA enabled" -ForegroundColor Green
    } else {
        Write-Host "  ⊘ RDP not configured on this system" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ✗ Failed to enable RDP NLA: $($_.Exception.Message)" -ForegroundColor Red
}

# 6. Enable Windows Firewall Logging
Write-Host "[6/6] Enabling Windows Firewall logging..." -ForegroundColor Gray
try {
    $profiles = @("Domain", "Public", "Private")
    foreach ($profile in $profiles) {
        Set-NetFirewallProfile -Name $profile -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384 -ErrorAction Stop
        Write-Host "  ✓ Firewall logging enabled for $profile profile" -ForegroundColor Green
    }
} catch {
    Write-Host "  ✗ Failed to enable firewall logging: $($_.Exception.Message)" -ForegroundColor Red
}

# Bonus: Disable NetBIOS over TCP/IP on all adapters
Write-Host ""
Write-Host "Bonus: Disabling NetBIOS over TCP/IP..." -ForegroundColor Gray
try {
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    $disabledCount = 0
    foreach ($adapter in $adapters) {
        # Set TcpipNetbiosOptions to 2 (Disable)
        $adapter.SetTcpipNetbios(2) | Out-Null
        $disabledCount++
    }
    Write-Host "  ✓ NetBIOS disabled on $disabledCount adapter(s)" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to disable NetBIOS: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  NETWORK SECURITY REMEDIATION COMPLETE" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

if ($restartRequired) {
    Write-Host "⚠  RESTART REQUIRED" -ForegroundColor Yellow
    Write-Host "   Some changes (SMBv1 disable) require a system restart to take effect." -ForegroundColor White
    Write-Host ""
    $restart = Read-Host "Restart now? (yes/no)"
    if ($restart -eq "yes") {
        Write-Host "Restarting in 10 seconds..." -ForegroundColor Yellow
        shutdown /r /t 10 /c "Restarting to apply network security settings"
    } else {
        Write-Host "Please restart your computer manually when convenient." -ForegroundColor Yellow
    }
} else {
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. No restart required for these changes" -ForegroundColor White
    Write-Host "  2. Run .\Invoke-OmniComply.ps1 to verify" -ForegroundColor Cyan
}

Write-Host ""
