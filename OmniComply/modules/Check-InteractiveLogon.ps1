<#
.SYNOPSIS
    Validates Interactive Logon Security Settings
.DESCRIPTION
    Tests logon banners, credential caching, and session policies
    SOC 2 CC6.1, CC6.7 | HIPAA § 164.308(a)(5)(ii)(D)
#>

Write-Host "Checking Interactive Logon Settings..." -ForegroundColor Cyan

# Check for legal notice/logon banner
$legalNoticeCaption = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -ErrorAction SilentlyContinue
$legalNoticeText = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -ErrorAction SilentlyContinue

$hasBanner = ($null -ne $legalNoticeCaption -and $legalNoticeCaption.LegalNoticeCaption -ne "") -and
             ($null -ne $legalNoticeText -and $legalNoticeText.LegalNoticeText -ne "")

$bannerInfo = if ($hasBanner) {
    "Caption: '$($legalNoticeCaption.LegalNoticeCaption)'"
} else {
    "No banner configured"
}

Add-ComplianceCheck -Category "Interactive Logon" `
    -Check "Legal Notice/Logon Banner" `
    -Requirement "SOC 2 CC6.1 - User Acknowledgment of Security Policies" `
    -Passed $hasBanner `
    -CurrentValue $bannerInfo `
    -ExpectedValue "Configured with legal notice" `
    -Remediation "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Message text/title for users attempting to log on"

if ($hasBanner) {
    Write-Host "  [PASS] Logon banner is configured" -ForegroundColor Green
} else {
    Write-Host "  [INFO] No logon banner configured (recommended for compliance)" -ForegroundColor Gray
}

# Check if last username is displayed at logon
$dontDisplayLastUser = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue

if ($dontDisplayLastUser) {
    $hideLastUser = $dontDisplayLastUser.DontDisplayLastUserName -eq 1

    Add-ComplianceCheck -Category "Interactive Logon" `
        -Check "Don't Display Last Username" `
        -Requirement "SOC 2 CC6.7 - Username Enumeration Prevention" `
        -Passed $hideLastUser `
        -CurrentValue $(if ($hideLastUser) { "Hidden" } else { "Displayed" }) `
        -ExpectedValue "Hidden" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1"

    if ($hideLastUser) {
        Write-Host "  [PASS] Last username is not displayed at logon" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Last username is displayed at logon (information disclosure)" -ForegroundColor Yellow
    }
} else {
    Add-ComplianceCheck -Category "Interactive Logon" `
        -Check "Don't Display Last Username" `
        -Requirement "SOC 2 CC6.7 - Username Enumeration Prevention" `
        -Passed $false `
        -CurrentValue "Not configured (username may be displayed)" `
        -ExpectedValue "Hidden" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Value 1 -Type DWord"

    Write-Host "  [WARN] Last username display setting not configured" -ForegroundColor Yellow
}

# Check machine inactivity limit
$inactivityLimit = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue

if ($inactivityLimit) {
    $timeoutSeconds = $inactivityLimit.InactivityTimeoutSecs
    $timeoutMinutes = $timeoutSeconds / 60
    $timeoutGood = $timeoutSeconds -gt 0 -and $timeoutSeconds -le 900  # 15 minutes or less

    Add-ComplianceCheck -Category "Interactive Logon" `
        -Check "Machine Inactivity Limit" `
        -Requirement "HIPAA § 164.312(a)(2)(iii) - Automatic Logoff" `
        -Passed $timeoutGood `
        -CurrentValue "$timeoutMinutes minutes" `
        -ExpectedValue "15 minutes or less" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900"

    if ($timeoutGood) {
        Write-Host "  [PASS] Machine inactivity limit: $timeoutMinutes minutes" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Machine inactivity limit: $timeoutMinutes minutes (recommend 15 or less)" -ForegroundColor Yellow
    }
} else {
    Add-ComplianceCheck -Category "Interactive Logon" `
        -Check "Machine Inactivity Limit" `
        -Requirement "HIPAA § 164.312(a)(2)(iii) - Automatic Logoff" `
        -Passed $false `
        -CurrentValue "Not configured" `
        -ExpectedValue "15 minutes or less" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900 -Type DWord"

    Write-Host "  [INFO] Machine inactivity limit not configured" -ForegroundColor Gray
}

# Check Smart Card removal behavior
$scRemoval = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScRemoveOption" -ErrorAction SilentlyContinue

if ($scRemoval) {
    $scLockWorkstation = $scRemoval.ScRemoveOption -eq "1"  # 1 = Lock workstation

    $scBehavior = switch ($scRemoval.ScRemoveOption) {
        "0" { "No action" }
        "1" { "Lock workstation" }
        "2" { "Force logoff" }
        "3" { "Disconnect if Remote Desktop" }
        default { "Unknown" }
    }

    Add-ComplianceCheck -Category "Interactive Logon" `
        -Check "Smart Card Removal Action" `
        -Requirement "SOC 2 CC6.1 - Physical Token Security" `
        -Passed $scLockWorkstation `
        -CurrentValue $scBehavior `
        -ExpectedValue "Lock workstation" `
        -Remediation "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Smart card removal behavior"

    if ($scLockWorkstation) {
        Write-Host "  [PASS] Smart card removal locks workstation" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Smart card removal behavior: $scBehavior" -ForegroundColor Gray
    }
}

# Check Ctrl+Alt+Del requirement
$disableCAD = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -ErrorAction SilentlyContinue

if ($disableCAD) {
    $cadRequired = $disableCAD.DisableCAD -eq 0  # 0 means enabled (require Ctrl+Alt+Del)

    Add-ComplianceCheck -Category "Interactive Logon" `
        -Check "Require Ctrl+Alt+Del for Logon" `
        -Requirement "SOC 2 CC6.7 - Secure Attention Sequence" `
        -Passed $cadRequired `
        -CurrentValue $(if ($cadRequired) { "Required" } else { "Not required" }) `
        -ExpectedValue "Required" `
        -Remediation "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Do not require CTRL+ALT+DEL (set to Disabled)"

    if ($cadRequired) {
        Write-Host "  [PASS] Ctrl+Alt+Del is required for logon" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Ctrl+Alt+Del is not required for logon" -ForegroundColor Gray
    }
}

# Check number of previous logons to cache
$cachedLogons = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -ErrorAction SilentlyContinue

if ($cachedLogons) {
    $cacheCount = [int]$cachedLogons.CachedLogonsCount
    $cacheSecure = $cacheCount -le 2

    Add-ComplianceCheck -Category "Interactive Logon" `
        -Check "Cached Logon Credentials Count" `
        -Requirement "SOC 2 CC6.7 - Credential Caching Limits" `
        -Passed $cacheSecure `
        -CurrentValue "$cacheCount cached logons" `
        -ExpectedValue "2 or fewer" `
        -Remediation "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Number of previous logons to cache"

    if ($cacheSecure) {
        Write-Host "  [PASS] Cached logon count: $cacheCount" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Cached logon count: $cacheCount (recommend 2 or fewer)" -ForegroundColor Yellow
    }
}

# Check prompt user to change password before expiration
$passwordExpiryWarning = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordExpiryWarning" -ErrorAction SilentlyContinue

if ($passwordExpiryWarning) {
    $warningDays = $passwordExpiryWarning.PasswordExpiryWarning
    $warningGood = $warningDays -ge 14  # At least 14 days notice

    Add-ComplianceCheck -Category "Interactive Logon" `
        -Check "Password Expiry Warning Days" `
        -Requirement "SOC 2 CC6.1 - Password Management" `
        -Passed $warningGood `
        -CurrentValue "$warningDays days" `
        -ExpectedValue "14 days or more" `
        -Remediation "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Prompt user to change password before expiration"

    if ($warningGood) {
        Write-Host "  [PASS] Password expiry warning: $warningDays days" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Password expiry warning: $warningDays days (recommend 14+)" -ForegroundColor Yellow
    }
}

Write-Host ""
