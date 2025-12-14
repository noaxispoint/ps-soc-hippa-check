<#
.SYNOPSIS
    Validates Screen Lock and Session Controls
.DESCRIPTION
    Tests automatic logoff, screen lock timeout, and session management
    SOC 2 CC6.1 | HIPAA § 164.312(a)(2)(iii)
#>

Write-Host "Checking Screen Lock and Session Controls..." -ForegroundColor Cyan

# Check screen saver timeout
$screenSaverTimeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
$screenSaverActive = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
$screenSaverSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue

if ($screenSaverTimeout -and $screenSaverActive) {
    $timeoutSeconds = [int]$screenSaverTimeout.ScreenSaveTimeOut
    $timeoutMinutes = $timeoutSeconds / 60
    $timeoutGood = $timeoutMinutes -le 15 -and $timeoutMinutes -gt 0
    $isActive = $screenSaverActive.ScreenSaveActive -eq "1"
    
    Add-ComplianceCheck -Category "Screen Lock & Session" `
        -Check "Screen Saver Timeout" `
        -Requirement "HIPAA § 164.312(a)(2)(iii) - Automatic Logoff" `
        -NIST "AC-11" `
        -CIS "4.3" `
        -ISO27001 "A.11.2.8" `
        -Passed ($timeoutGood -and $isActive) `
        -CurrentValue "$timeoutMinutes minutes (Active: $isActive)" `
        -ExpectedValue "1-15 minutes and active" `
        -Remediation "Configure via Settings or Registry"
    
    if ($timeoutGood -and $isActive) {
        Write-Host "  [PASS] Screen saver timeout: $timeoutMinutes minutes" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Screen saver timeout: $timeoutMinutes minutes (Active: $isActive)" -ForegroundColor Red
    }
    
    # Check if password-protected
    if ($screenSaverSecure) {
        $isSecure = $screenSaverSecure.ScreenSaverIsSecure -eq "1"
        
        Add-ComplianceCheck -Category "Screen Lock & Session" `
            -Check "Password-Protected Screen Saver" `
            -Requirement "HIPAA § 164.312(a)(2)(iii) - Automatic Logoff" `
            -NIST "AC-11" `
            -CIS "4.3" `
            -ISO27001 "A.11.2.8" `
            -Passed $isSecure `
            -CurrentValue $(if ($isSecure) { "Enabled" } else { "Disabled" }) `
            -ExpectedValue "Enabled" `
            -Remediation "Enable via Settings > Personalization > Lock screen"
        
        if ($isSecure) {
            Write-Host "  [PASS] Screen saver is password-protected" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Screen saver is not password-protected" -ForegroundColor Red
        }
    }
} else {
    Add-ComplianceCheck -Category "Screen Lock & Session" `
        -Check "Screen Saver Configuration" `
        -Requirement "HIPAA § 164.312(a)(2)(iii) - Automatic Logoff" `
        -NIST "AC-11" `
        -CIS "4.3" `
        -ISO27001 "A.11.2.8" `
        -Passed $false `
        -CurrentValue "Not configured" `
        -ExpectedValue "Configured with 15-minute timeout" `
        -Remediation "Configure screen saver via Settings"
    
    Write-Host "  [FAIL] Screen saver not properly configured" -ForegroundColor Red
}

Write-Host ""
