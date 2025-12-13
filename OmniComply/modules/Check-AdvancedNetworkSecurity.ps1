<#
.SYNOPSIS
    Validates Advanced Network Security Settings
.DESCRIPTION
    Tests LLMNR, NetBIOS, RDP NLA, and firewall logging
    SOC 2 CC6.1, CC7.2 | HIPAA § 164.312(e)
#>

Write-Host "Checking Advanced Network Security..." -ForegroundColor Cyan

# Check LLMNR (Link-Local Multicast Name Resolution) - should be disabled
$llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue

$llmnrDisabled = $null -ne $llmnr -and $llmnr.EnableMulticast -eq 0

Add-ComplianceCheck -Category "Advanced Network Security" `
    -Check "LLMNR Disabled" `
    -Requirement "SOC 2 CC6.1 - Network Attack Surface Reduction" `
    -Passed $llmnrDisabled `
    -CurrentValue $(if ($llmnrDisabled) { "Disabled" } elseif ($null -eq $llmnr) { "Not configured (enabled by default)" } else { "Enabled" }) `
    -ExpectedValue "Disabled" `
    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0"

if ($llmnrDisabled) {
    Write-Host "  [PASS] LLMNR is disabled" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] LLMNR is enabled (credential theft risk)" -ForegroundColor Red
}

# Check NetBIOS over TCP/IP on all adapters
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
$netbiosDisabledCount = 0
$totalAdapters = 0

foreach ($adapter in $adapters) {
    $totalAdapters++
    # TcpipNetbiosOptions: 0=Default (DHCP), 1=Enabled, 2=Disabled
    if ($adapter.TcpipNetbiosOptions -eq 2) {
        $netbiosDisabledCount++
    }
}

$allDisabled = ($totalAdapters -gt 0) -and ($netbiosDisabledCount -eq $totalAdapters)

Add-ComplianceCheck -Category "Advanced Network Security" `
    -Check "NetBIOS over TCP/IP Disabled" `
    -Requirement "SOC 2 CC6.1 - Legacy Protocol Mitigation" `
    -Passed $allDisabled `
    -CurrentValue "$netbiosDisabledCount of $totalAdapters adapters have NetBIOS disabled" `
    -ExpectedValue "Disabled on all adapters" `
    -Remediation "Disable via network adapter properties or Group Policy"

if ($allDisabled) {
    Write-Host "  [PASS] NetBIOS over TCP/IP disabled on all adapters" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] NetBIOS over TCP/IP enabled on some adapters" -ForegroundColor Red
}

# Check RDP Network Level Authentication (NLA)
$rdpNLA = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue

if ($rdpNLA) {
    $nlaRequired = $rdpNLA.UserAuthentication -eq 1

    Add-ComplianceCheck -Category "Advanced Network Security" `
        -Check "RDP Network Level Authentication" `
        -Requirement "HIPAA § 164.312(e) - Transmission Security" `
        -Passed $nlaRequired `
        -CurrentValue $(if ($nlaRequired) { "Required" } else { "Not required" }) `
        -ExpectedValue "Required" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1"

    if ($nlaRequired) {
        Write-Host "  [PASS] RDP requires Network Level Authentication" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] RDP does not require NLA (security risk)" -ForegroundColor Red
    }
}

# Check Windows Firewall logging for all profiles
$profiles = @("Domain", "Public", "Private")
$loggingEnabled = 0

foreach ($profileName in $profiles) {
    $profile = Get-NetFirewallProfile -Name $profileName -ErrorAction SilentlyContinue
    if ($profile -and $profile.LogAllowed -eq $true -and $profile.LogBlocked -eq $true) {
        $loggingEnabled++
    }
}

$allLogging = $loggingEnabled -eq 3

Add-ComplianceCheck -Category "Advanced Network Security" `
    -Check "Firewall Logging Enabled" `
    -Requirement "SOC 2 CC7.2 - Network Monitoring" `
    -Passed $allLogging `
    -CurrentValue "$loggingEnabled of 3 profiles have logging enabled" `
    -ExpectedValue "Logging enabled on all profiles" `
    -Remediation "Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True"

if ($allLogging) {
    Write-Host "  [PASS] Firewall logging enabled on all profiles" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Firewall logging not enabled on all profiles" -ForegroundColor Yellow
}

# Check if firewall log file size is adequate
$domainProfile = Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue
if ($domainProfile -and $domainProfile.LogMaxSizeKilobytes) {
    $logSizeGood = $domainProfile.LogMaxSizeKilobytes -ge 4096  # At least 4MB

    Add-ComplianceCheck -Category "Advanced Network Security" `
        -Check "Firewall Log Size" `
        -Requirement "SOC 2 CC7.2 - Adequate Log Retention" `
        -Passed $logSizeGood `
        -CurrentValue "$($domainProfile.LogMaxSizeKilobytes) KB" `
        -ExpectedValue "At least 4096 KB (4 MB)" `
        -Remediation "Set-NetFirewallProfile -All -LogMaxSizeKilobytes 16384"

    if ($logSizeGood) {
        Write-Host "  [PASS] Firewall log size: $($domainProfile.LogMaxSizeKilobytes) KB" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Firewall log size too small: $($domainProfile.LogMaxSizeKilobytes) KB" -ForegroundColor Yellow
    }
}

Write-Host ""
