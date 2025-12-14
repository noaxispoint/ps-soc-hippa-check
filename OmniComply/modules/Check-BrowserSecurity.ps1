<#
.SYNOPSIS
    Validates Browser Security Settings
.DESCRIPTION
    Tests Microsoft Edge, Internet Explorer, and general browser security policies
    SOC 2 CC6.1, CC6.7 | HIPAA § 164.308(a)(5)(ii)(B) - Protection from malicious software
#>

Write-Host "Checking Browser Security Settings..." -ForegroundColor Cyan

# Check Microsoft Edge SmartScreen
$edgeSmartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue

if ($null -ne $edgeSmartScreen) {
    $smartScreenOn = $edgeSmartScreen.SmartScreenEnabled -eq 1

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Microsoft Edge SmartScreen" `
        -Requirement "SOC 2 CC7.1 - Phishing Protection" `
        -NIST "SI-3" `
        -CIS "10.1" `
        -ISO27001 "A.12.2.1" `
        -PCIDSS "5.1" `
        -Passed $smartScreenOn `
        -CurrentValue $(if ($smartScreenOn) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenEnabled' -Value 1"

    if ($smartScreenOn) {
        Write-Host "  [PASS] Microsoft Edge SmartScreen is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Microsoft Edge SmartScreen is disabled" -ForegroundColor Red
    }
} else {
    Write-Host "  [INFO] Microsoft Edge SmartScreen policy not configured (using defaults)" -ForegroundColor Gray
}

# Check Edge Enhanced Security Mode
$edgeEnhancedSecurity = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EnhanceSecurityMode" -ErrorAction SilentlyContinue

if ($null -ne $edgeEnhancedSecurity) {
    # 0 = Off, 1 = Basic, 2 = Balanced, 3 = Strict
    $enhancedSecurityOn = $edgeEnhancedSecurity.EnhanceSecurityMode -ge 1

    $securityLevel = switch ($edgeEnhancedSecurity.EnhanceSecurityMode) {
        0 { "Off" }
        1 { "Basic" }
        2 { "Balanced" }
        3 { "Strict" }
        default { "Unknown" }
    }

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Microsoft Edge Enhanced Security Mode" `
        -Requirement "SOC 2 CC6.1 - Browser Hardening" `
        -NIST "CM-7(1)" `
        -CIS "2.1" `
        -ISO27001 "A.14.1.2" `
        -Passed $enhancedSecurityOn `
        -CurrentValue $securityLevel `
        -ExpectedValue "Basic, Balanced, or Strict" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'EnhanceSecurityMode' -Value 2"

    if ($enhancedSecurityOn) {
        Write-Host "  [PASS] Edge Enhanced Security Mode is enabled ($securityLevel)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Edge Enhanced Security Mode is off" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] Edge Enhanced Security Mode not configured" -ForegroundColor Gray
}

# Check Edge password manager
$edgePasswordManager = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PasswordManagerEnabled" -ErrorAction SilentlyContinue

if ($null -ne $edgePasswordManager) {
    $passwordMgrEnabled = $edgePasswordManager.PasswordManagerEnabled -eq 1

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Microsoft Edge Password Manager" `
        -Requirement "SOC 2 CC6.1 - Credential Management" `
        -NIST "IA-5(1)" `
        -CIS "5.2" `
        -ISO27001 "A.9.4.3" `
        -Passed $true `
        -CurrentValue $(if ($passwordMgrEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled or use enterprise password manager" `
        -Remediation "Configure password management policy based on organizational requirements"

    if ($passwordMgrEnabled) {
        Write-Host "  [INFO] Edge password manager is enabled" -ForegroundColor Gray
    } else {
        Write-Host "  [INFO] Edge password manager is disabled (verify enterprise alternative exists)" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] Edge password manager policy not configured" -ForegroundColor Gray
}

# Check Edge DNS-over-HTTPS
$edgeDnsOverHttps = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue

if ($null -ne $edgeDnsOverHttps) {
    $dohMode = $edgeDnsOverHttps.DnsOverHttpsMode
    $dohEnabled = $dohMode -eq "secure" -or $dohMode -eq "automatic"

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Microsoft Edge DNS-over-HTTPS" `
        -Requirement "SOC 2 CC6.7 - Encrypted DNS" `
        -NIST "SC-8" `
        -CIS "2.1" `
        -ISO27001 "A.13.1.1, A.10.1.1" `
        -Passed $dohEnabled `
        -CurrentValue $dohMode `
        -ExpectedValue "secure or automatic" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'DnsOverHttpsMode' -Value 'automatic'"

    if ($dohEnabled) {
        Write-Host "  [PASS] Edge DNS-over-HTTPS is enabled ($dohMode)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Edge DNS-over-HTTPS mode: $dohMode" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] Edge DNS-over-HTTPS not configured" -ForegroundColor Gray
}

# Check Edge site isolation
$edgeSiteIsolation = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SitePerProcess" -ErrorAction SilentlyContinue

if ($null -ne $edgeSiteIsolation) {
    $siteIsolationEnabled = $edgeSiteIsolation.SitePerProcess -eq 1

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Microsoft Edge Site Isolation" `
        -Requirement "SOC 2 CC6.1 - Process Isolation" `
        -NIST "SC-39" `
        -CIS "2.1" `
        -ISO27001 "A.14.1.2" `
        -Passed $siteIsolationEnabled `
        -CurrentValue $(if ($siteIsolationEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'SitePerProcess' -Value 1"

    if ($siteIsolationEnabled) {
        Write-Host "  [PASS] Edge Site Isolation is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Edge Site Isolation is disabled" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] Edge Site Isolation not configured (enabled by default on modern Edge)" -ForegroundColor Gray
}

# Check if Internet Explorer is disabled (deprecated)
$ieDisabled = Get-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -ErrorAction SilentlyContinue

if ($ieDisabled) {
    $ieRemoved = $ieDisabled.State -eq "Disabled"

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Internet Explorer 11 Status" `
        -Requirement "SOC 2 CC7.1 - Deprecated Software Removal" `
        -NIST "CM-7(1), SI-2" `
        -CIS "2.1" `
        -ISO27001 "A.12.6.2, A.12.5.1" `
        -Passed $ieRemoved `
        -CurrentValue $(if ($ieRemoved) { "Disabled/Removed" } else { "Enabled" }) `
        -ExpectedValue "Disabled (deprecated)" `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName 'Internet-Explorer-Optional-amd64' -NoRestart"

    if ($ieRemoved) {
        Write-Host "  [PASS] Internet Explorer 11 is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Internet Explorer 11 is still enabled (deprecated, security risk)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] Unable to check Internet Explorer status" -ForegroundColor Gray
}

# Check Edge automatic updates
$edgeUpdatePolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "UpdateDefault" -ErrorAction SilentlyContinue

if ($null -ne $edgeUpdatePolicy) {
    # 1 = Updates enabled, 2 = Manual only, 3 = Auto only, 0 = Disabled
    $updatesEnabled = $edgeUpdatePolicy.UpdateDefault -eq 1 -or $edgeUpdatePolicy.UpdateDefault -eq 3

    $updateMode = switch ($edgeUpdatePolicy.UpdateDefault) {
        0 { "Disabled" }
        1 { "Enabled" }
        2 { "Manual only" }
        3 { "Automatic only" }
        default { "Unknown" }
    }

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Microsoft Edge Automatic Updates" `
        -Requirement "SOC 2 CC7.1 - Browser Update Management" `
        -NIST "SI-2" `
        -CIS "1.3" `
        -ISO27001 "A.12.6.1" `
        -SOX "ITGC-04" `
        -Passed $updatesEnabled `
        -CurrentValue $updateMode `
        -ExpectedValue "Enabled or Automatic" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' -Name 'UpdateDefault' -Value 1"

    if ($updatesEnabled) {
        Write-Host "  [PASS] Edge automatic updates are enabled ($updateMode)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Edge automatic updates are not enabled ($updateMode)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] Edge update policy not configured (using defaults)" -ForegroundColor Gray
}

# Check for browser extension restrictions
$edgeExtensionSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ExtensionInstallBlocklist" -ErrorAction SilentlyContinue

if ($null -ne $edgeExtensionSettings) {
    # Check if a blocklist exists (even if empty, shows policy is managed)
    $extensionPolicyExists = $true

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Browser Extension Controls" `
        -Requirement "SOC 2 CC6.1 - Extension Management" `
        -NIST "CM-7(5)" `
        -CIS "2.1" `
        -ISO27001 "A.12.5.1, A.12.6.2" `
        -Passed $extensionPolicyExists `
        -CurrentValue "Extension blocklist policy configured" `
        -ExpectedValue "Extension controls configured" `
        -Remediation "Configure extension allowlist/blocklist via Group Policy"

    Write-Host "  [PASS] Browser extension controls are configured" -ForegroundColor Green
} else {
    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Browser Extension Controls" `
        -Requirement "SOC 2 CC6.1 - Extension Management" `
        -NIST "CM-7(5)" `
        -CIS "2.1" `
        -ISO27001 "A.12.5.1, A.12.6.2" `
        -Passed $false `
        -CurrentValue "No extension controls configured" `
        -ExpectedValue "Extension allowlist/blocklist configured" `
        -Remediation "Configure via Group Policy: Computer Configuration > Administrative Templates > Microsoft Edge > Extensions"

    Write-Host "  [INFO] Browser extension controls not configured" -ForegroundColor Gray
}

# Check for download restrictions
$edgeDownloadRestrictions = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DownloadRestrictions" -ErrorAction SilentlyContinue

if ($null -ne $edgeDownloadRestrictions) {
    # 0 = No restrictions, 1 = Block dangerous, 2 = Block dangerous and uncommon, 3 = Block all
    $downloadRestrictionsEnabled = $edgeDownloadRestrictions.DownloadRestrictions -ge 1

    $restrictionLevel = switch ($edgeDownloadRestrictions.DownloadRestrictions) {
        0 { "No restrictions" }
        1 { "Block dangerous" }
        2 { "Block dangerous and uncommon" }
        3 { "Block all downloads" }
        default { "Unknown" }
    }

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Download Restrictions" `
        -Requirement "SOC 2 CC7.1 - Malware Prevention" `
        -NIST "SI-3" `
        -CIS "10.1" `
        -ISO27001 "A.12.2.1" `
        -PCIDSS "5.1" `
        -Passed $downloadRestrictionsEnabled `
        -CurrentValue $restrictionLevel `
        -ExpectedValue "Block dangerous or higher" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'DownloadRestrictions' -Value 1"

    if ($downloadRestrictionsEnabled) {
        Write-Host "  [PASS] Download restrictions are enabled ($restrictionLevel)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] No download restrictions configured" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] Download restrictions not configured" -ForegroundColor Gray
}

# Check for third-party cookies blocking
$edgeThirdPartyCookies = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BlockThirdPartyCookies" -ErrorAction SilentlyContinue

if ($null -ne $edgeThirdPartyCookies) {
    $thirdPartyCookiesBlocked = $edgeThirdPartyCookies.BlockThirdPartyCookies -eq 1

    Add-ComplianceCheck -Category "Browser Security" `
        -Check "Third-Party Cookie Blocking" `
        -Requirement "SOC 2 CC6.7 - Privacy Protection" `
        -NIST "AC-4" `
        -CIS "2.1" `
        -ISO27001 "A.18.1.4" `
        -Passed $thirdPartyCookiesBlocked `
        -CurrentValue $(if ($thirdPartyCookiesBlocked) { "Blocked" } else { "Allowed" }) `
        -ExpectedValue "Blocked" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'BlockThirdPartyCookies' -Value 1"

    if ($thirdPartyCookiesBlocked) {
        Write-Host "  [PASS] Third-party cookies are blocked" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Third-party cookies are allowed" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] Third-party cookie policy not configured" -ForegroundColor Gray
}

# Check for WebRTC IP handling (prevents IP leaks)
$edgeWebRTC = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WebRtcLocalIpsAllowedUrls" -ErrorAction SilentlyContinue

if ($null -ne $edgeWebRTC) {
    Write-Host "  [INFO] WebRTC local IP exposure is restricted" -ForegroundColor Gray
} else {
    Add-ComplianceCheck -Category "Browser Security" `
        -Check "WebRTC IP Leak Protection" `
        -Requirement "SOC 2 CC6.7 - Information Disclosure" `
        -NIST "AC-4" `
        -CIS "2.1" `
        -ISO27001 "A.13.1.1" `
        -Passed $false `
        -CurrentValue "Not configured" `
        -ExpectedValue "Restricted to trusted URLs" `
        -Remediation "Configure WebRtcLocalIpsAllowedUrls via Group Policy for VPN environments"

    Write-Host "  [INFO] WebRTC IP leak protection not configured (acceptable for most)" -ForegroundColor Gray
}

Write-Host ""
