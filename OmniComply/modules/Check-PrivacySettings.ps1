<#
.SYNOPSIS
    Validates Privacy and Data Minimization Settings
.DESCRIPTION
    Tests Windows telemetry, diagnostic data, location services, and privacy controls
    GDPR Article 25 (Privacy by Design) | CCPA § 1798.150 | SOC 2 CC1.1
#>

Write-Host "Checking Privacy and Data Minimization Settings..." -ForegroundColor Cyan

# Check Windows Telemetry/Diagnostic Data Level
$telemetryLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue

if ($telemetryLevel) {
    $level = $telemetryLevel.AllowTelemetry
    $levelText = switch ($level) {
        0 { "Security (Enterprise only)" }
        1 { "Basic" }
        2 { "Enhanced" }
        3 { "Full" }
        default { "Unknown" }
    }

    # Level 0 (Security) or 1 (Basic) is recommended for privacy compliance
    $privacyCompliant = $level -le 1

    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Windows Diagnostic Data Level" `
        -Requirement "GDPR Article 25 - Data Minimization by Design" `
        -NIST "SI-12" `
        -CIS "2.3" `
        -ISO27001 "A.18.1.4" `
        -CCPA "Yes" `
        -GDPR "Article 25, 32" `
        -Passed $privacyCompliant `
        -CurrentValue $levelText `
        -ExpectedValue "Security or Basic" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 1" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > System > <strong>Allow Telemetry</strong> = <code>1 - Basic</code> (or 0 - Security for Enterprise SKUs)"

    if ($privacyCompliant) {
        Write-Host "  [PASS] Diagnostic data level: $levelText (privacy-compliant)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Diagnostic data level: $levelText (recommend Basic or Security)" -ForegroundColor Yellow
    }
} else {
    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Windows Diagnostic Data Level" `
        -Requirement "GDPR Article 25 - Data Minimization by Design" `
        -NIST "SI-12" `
        -CIS "2.3" `
        -ISO27001 "A.18.1.4" `
        -CCPA "Yes" `
        -GDPR "Article 25, 32" `
        -Passed $false `
        -CurrentValue "Not configured (may use default: Enhanced or Full)" `
        -ExpectedValue "Security or Basic" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 1 -Type DWord"

    Write-Host "  [WARN] Diagnostic data level not configured (privacy risk)" -ForegroundColor Yellow
}

# Check Location Services
$locationPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue

if ($locationPolicy) {
    $locationDisabled = $locationPolicy.DisableLocation -eq 1

    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Location Services Disabled" `
        -Requirement "GDPR Article 25 - Privacy by Default" `
        -NIST "SI-12" `
        -CIS "18.9" `
        -ISO27001 "A.18.1.4" `
        -CCPA "Yes" `
        -GDPR "Article 25" `
        -Passed $locationDisabled `
        -CurrentValue $(if ($locationDisabled) { "Disabled" } else { "Enabled" }) `
        -ExpectedValue "Disabled (unless required for business use)" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Value 1" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > System > <strong>Allow Location</strong> = <code>Block</code>"

    if ($locationDisabled) {
        Write-Host "  [PASS] Location services are disabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Location services are enabled (ensure business justification)" -ForegroundColor Gray
    }
} else {
    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Location Services Disabled" `
        -Requirement "GDPR Article 25 - Privacy by Default" `
        -NIST "SI-12" `
        -CIS "18.9" `
        -ISO27001 "A.18.1.4" `
        -CCPA "Yes" `
        -GDPR "Article 25" `
        -Passed $false `
        -CurrentValue "Not configured (may be enabled)" `
        -ExpectedValue "Disabled (unless required for business use)" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Value 1 -Type DWord"

    Write-Host "  [INFO] Location services policy not configured" -ForegroundColor Gray
}

# Check Advertising ID
$advertisingId = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue

if ($advertisingId) {
    $adIdDisabled = $advertisingId.DisabledByGroupPolicy -eq 1

    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Advertising ID Disabled" `
        -Requirement "GDPR Article 25 - Privacy by Default" `
        -NIST "SI-12" `
        -CIS "18.9" `
        -ISO27001 "A.18.1.4" `
        -CCPA "Yes" `
        -GDPR "Article 25" `
        -Passed $adIdDisabled `
        -CurrentValue $(if ($adIdDisabled) { "Disabled" } else { "Enabled" }) `
        -ExpectedValue "Disabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Value 1" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Privacy > <strong>Let apps use advertising ID</strong> = <code>Block</code>"

    if ($adIdDisabled) {
        Write-Host "  [PASS] Advertising ID is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Advertising ID is enabled (privacy concern)" -ForegroundColor Yellow
    }
} else {
    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Advertising ID Disabled" `
        -Requirement "GDPR Article 25 - Privacy by Default" `
        -NIST "SI-12" `
        -CIS "18.9" `
        -ISO27001 "A.18.1.4" `
        -CCPA "Yes" `
        -GDPR "Article 25" `
        -Passed $false `
        -CurrentValue "Not configured (may be enabled)" `
        -ExpectedValue "Disabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Value 1 -Type DWord"

    Write-Host "  [WARN] Advertising ID policy not configured" -ForegroundColor Yellow
}

# Check Activity History
$activityHistory = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -ErrorAction SilentlyContinue

if ($activityHistory) {
    $activityDisabled = $activityHistory.PublishUserActivities -eq 0

    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Activity History Collection Disabled" `
        -Requirement "GDPR Article 25 - Data Minimization" `
        -NIST "SI-12" `
        -CIS "18.9" `
        -ISO27001 "A.18.1.4" `
        -CCPA "Yes" `
        -GDPR "Article 25, 32" `
        -Passed $activityDisabled `
        -CurrentValue $(if ($activityDisabled) { "Disabled" } else { "Enabled" }) `
        -ExpectedValue "Disabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value 0; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value 0" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > System > <strong>Publish User Activities</strong> = <code>Disabled</code>, <strong>Enable Activity Feed</strong> = <code>Disabled</code>"

    if ($activityDisabled) {
        Write-Host "  [PASS] Activity history collection is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Activity history collection is enabled (privacy concern)" -ForegroundColor Yellow
    }
} else {
    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Activity History Collection Disabled" `
        -Requirement "GDPR Article 25 - Data Minimization" `
        -NIST "SI-12" `
        -CIS "18.9" `
        -ISO27001 "A.18.1.4" `
        -CCPA "Yes" `
        -GDPR "Article 25, 32" `
        -Passed $false `
        -CurrentValue "Not configured (may be enabled)" `
        -ExpectedValue "Disabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value 0 -Type DWord; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value 0 -Type DWord"

    Write-Host "  [WARN] Activity history policy not configured" -ForegroundColor Yellow
}

# Check Cloud Clipboard Sync
$clipboardSync = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -ErrorAction SilentlyContinue

if ($clipboardSync) {
    $clipboardDisabled = $clipboardSync.AllowClipboardHistory -eq 0

    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Cloud Clipboard Sync Disabled" `
        -Requirement "GDPR Article 32 - Data Transfer Controls" `
        -NIST "SI-12, SC-8" `
        -CIS "18.9" `
        -ISO27001 "A.13.2.1" `
        -CCPA "Yes" `
        -GDPR "Article 32" `
        -Passed $clipboardDisabled `
        -CurrentValue $(if ($clipboardDisabled) { "Disabled" } else { "Enabled" }) `
        -ExpectedValue "Disabled (unless required and controlled)" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowClipboardHistory' -Value 0" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > System > <strong>Allow Clipboard History</strong> = <code>Disabled</code>"

    if ($clipboardDisabled) {
        Write-Host "  [PASS] Cloud clipboard sync is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Cloud clipboard sync is enabled (ensure data handling compliance)" -ForegroundColor Gray
    }
} else {
    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "Cloud Clipboard Sync Disabled" `
        -Requirement "GDPR Article 32 - Data Transfer Controls" `
        -NIST "SI-12, SC-8" `
        -CIS "18.9" `
        -ISO27001 "A.13.2.1" `
        -CCPA "Yes" `
        -GDPR "Article 32" `
        -Passed $false `
        -CurrentValue "Not configured" `
        -ExpectedValue "Disabled (unless required and controlled)" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowClipboardHistory' -Value 0 -Type DWord"

    Write-Host "  [INFO] Cloud clipboard policy not configured" -ForegroundColor Gray
}

# Check OneDrive/Cloud Storage Auto-Sync (data sovereignty)
$oneDriveSync = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue

if ($oneDriveSync) {
    $oneDriveDisabled = $oneDriveSync.DisableFileSyncNGSC -eq 1

    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "OneDrive Personal Sync Disabled" `
        -Requirement "GDPR Article 44 - Data Sovereignty / Transfer to Third Countries" `
        -NIST "AC-20" `
        -CIS "18.9" `
        -ISO27001 "A.13.2.1" `
        -CCPA "Yes" `
        -GDPR "Article 44, 46" `
        -SOX "ITGC-03" `
        -Passed $oneDriveDisabled `
        -CurrentValue $(if ($oneDriveDisabled) { "Disabled (OneDrive Personal)" } else { "Enabled" }) `
        -ExpectedValue "Disabled for personal accounts (use business accounts with DLP)" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name 'DisableFileSyncNGSC' -Value 1" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > OneDrive > <strong>Prevent users from syncing personal OneDrive accounts</strong> = <code>Enabled</code>"

    if ($oneDriveDisabled) {
        Write-Host "  [PASS] OneDrive personal account sync is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] OneDrive personal account sync is enabled (ensure business controls)" -ForegroundColor Gray
    }
} else {
    Add-ComplianceCheck -Category "Privacy Settings" `
        -Check "OneDrive Personal Sync Disabled" `
        -Requirement "GDPR Article 44 - Data Sovereignty / Transfer to Third Countries" `
        -NIST "AC-20" `
        -CIS "18.9" `
        -ISO27001 "A.13.2.1" `
        -CCPA "Yes" `
        -GDPR "Article 44, 46" `
        -SOX "ITGC-03" `
        -Passed $false `
        -CurrentValue "Not configured" `
        -ExpectedValue "Disabled for personal accounts (use business accounts with DLP)" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name 'DisableFileSyncNGSC' -Value 1 -Type DWord"

    Write-Host "  [INFO] OneDrive personal account policy not configured" -ForegroundColor Gray
}

Write-Host ""
