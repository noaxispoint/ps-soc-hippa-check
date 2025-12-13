<#
.SYNOPSIS
    Validates User Account Control (UAC) Configuration
.DESCRIPTION
    Tests UAC settings to ensure proper privilege elevation and security
    SOC 2 CC6.1 | HIPAA § 164.312(a)(1)
#>

Write-Host "Checking User Account Control (UAC)..." -ForegroundColor Cyan

# Check if UAC is enabled
$uacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue

if ($uacEnabled) {
    $isEnabled = $uacEnabled.EnableLUA -eq 1

    Add-ComplianceCheck -Category "User Account Control" `
        -Check "UAC Enabled" `
        -Requirement "SOC 2 CC6.1 / HIPAA § 164.312(a)(1)" `
        -Passed $isEnabled `
        -CurrentValue $(if ($isEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1"

    if ($isEnabled) {
        Write-Host "  [PASS] UAC is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] UAC is disabled" -ForegroundColor Red
    }
}

# Check UAC admin approval mode
$consentPrompt = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue

if ($consentPrompt) {
    $properLevel = $consentPrompt.ConsentPromptBehaviorAdmin -eq 2
    $levelText = switch ($consentPrompt.ConsentPromptBehaviorAdmin) {
        0 { "Elevate without prompting" }
        1 { "Prompt for credentials on secure desktop" }
        2 { "Prompt for consent on secure desktop" }
        3 { "Prompt for credentials" }
        4 { "Prompt for consent" }
        5 { "Prompt for consent for non-Windows binaries" }
        default { "Unknown ($($consentPrompt.ConsentPromptBehaviorAdmin))" }
    }

    Add-ComplianceCheck -Category "User Account Control" `
        -Check "UAC Prompt Level for Administrators" `
        -Requirement "SOC 2 CC6.1 - Least Privilege" `
        -Passed $properLevel `
        -CurrentValue $levelText `
        -ExpectedValue "Prompt for consent on secure desktop" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2"

    if ($properLevel) {
        Write-Host "  [PASS] UAC prompt level: $levelText" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] UAC prompt level: $levelText (recommended: Prompt for consent on secure desktop)" -ForegroundColor Yellow
    }
}

# Check UAC secure desktop
$secureDesktop = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue

if ($secureDesktop) {
    $isSecure = $secureDesktop.PromptOnSecureDesktop -eq 1

    Add-ComplianceCheck -Category "User Account Control" `
        -Check "UAC Prompt on Secure Desktop" `
        -Requirement "SOC 2 CC6.1 - Credential Protection" `
        -Passed $isSecure `
        -CurrentValue $(if ($isSecure) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1"

    if ($isSecure) {
        Write-Host "  [PASS] UAC prompts on secure desktop" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] UAC prompts not on secure desktop" -ForegroundColor Red
    }
}

Write-Host ""
