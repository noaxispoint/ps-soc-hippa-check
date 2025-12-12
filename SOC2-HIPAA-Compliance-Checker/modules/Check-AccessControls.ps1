<#
.SYNOPSIS
    Validates Access Control Configuration
.DESCRIPTION
    Tests password policies, account lockout, and access control settings
    SOC 2 CC6.1, CC6.6, CC6.7 | HIPAA § 164.308(a)(3), § 164.308(a)(5), § 164.312(a)(1)
#>

Write-Host "Checking Access Controls..." -ForegroundColor Cyan

# Export security policy
secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet | Out-Null
$policyContent = Get-Content "$env:TEMP\secpol.cfg"

# Parse minimum password length
$minPasswordLength = ($policyContent | Select-String "MinimumPasswordLength = (\d+)").Matches.Groups[1].Value
$minLengthGood = [int]$minPasswordLength -ge 12

Add-ComplianceCheck -Category "Access Controls" `
    -Check "Minimum Password Length" `
    -Requirement "SOC 2 CC6.1 / HIPAA § 164.308(a)(5)(ii)(D)" `
    -Passed $minLengthGood `
    -CurrentValue "$minPasswordLength characters" `
    -ExpectedValue "12 or more characters" `
    -Remediation "Configure via Local Security Policy or Intune"

if ($minLengthGood) {
    Write-Host "  [PASS] Minimum password length: $minPasswordLength characters" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Minimum password length: $minPasswordLength characters (need 12+)" -ForegroundColor Red
}

# Parse password complexity
$complexityEnabled = ($policyContent | Select-String "PasswordComplexity = (\d+)").Matches.Groups[1].Value
$complexityGood = $complexityEnabled -eq "1"

Add-ComplianceCheck -Category "Access Controls" `
    -Check "Password Complexity Requirements" `
    -Requirement "SOC 2 CC6.1 / HIPAA § 164.308(a)(5)(ii)(D)" `
    -Passed $complexityGood `
    -CurrentValue $(if ($complexityGood) { "Enabled" } else { "Disabled" }) `
    -ExpectedValue "Enabled" `
    -Remediation "Enable via Local Security Policy"

if ($complexityGood) {
    Write-Host "  [PASS] Password complexity is enabled" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Password complexity is disabled" -ForegroundColor Red
}

# Parse password history
$passwordHistory = ($policyContent | Select-String "PasswordHistorySize = (\d+)").Matches.Groups[1].Value
$historyGood = [int]$passwordHistory -ge 12

Add-ComplianceCheck -Category "Access Controls" `
    -Check "Password History" `
    -Requirement "SOC 2 CC6.1 / HIPAA § 164.308(a)(5)(ii)(D)" `
    -Passed $historyGood `
    -CurrentValue "$passwordHistory passwords remembered" `
    -ExpectedValue "12 or more passwords" `
    -Remediation "Configure via Local Security Policy"

if ($historyGood) {
    Write-Host "  [PASS] Password history: $passwordHistory passwords" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Password history: $passwordHistory passwords (need 12+)" -ForegroundColor Red
}

# Parse account lockout threshold
$lockoutThreshold = ($policyContent | Select-String "LockoutBadCount = (\d+)").Matches.Groups[1].Value
$lockoutGood = [int]$lockoutThreshold -gt 0 -and [int]$lockoutThreshold -le 10

Add-ComplianceCheck -Category "Access Controls" `
    -Check "Account Lockout Threshold" `
    -Requirement "SOC 2 CC6.1 / HIPAA § 164.308(a)(5)(ii)(C)" `
    -Passed $lockoutGood `
    -CurrentValue "$lockoutThreshold invalid attempts" `
    -ExpectedValue "5-10 invalid attempts" `
    -Remediation "Configure via Local Security Policy"

if ($lockoutGood) {
    Write-Host "  [PASS] Account lockout threshold: $lockoutThreshold attempts" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Account lockout threshold: $lockoutThreshold attempts" -ForegroundColor Red
}

# Check for guest account
$guestDisabled = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled -eq $false

Add-ComplianceCheck -Category "Access Controls" `
    -Check "Guest Account Disabled" `
    -Requirement "SOC 2 CC6.1 / HIPAA § 164.312(a)(2)(i)" `
    -Passed $guestDisabled `
    -CurrentValue $(if ($guestDisabled) { "Disabled" } else { "Enabled" }) `
    -ExpectedValue "Disabled" `
    -Remediation "Disable-LocalUser -Name 'Guest'"

if ($guestDisabled) {
    Write-Host "  [PASS] Guest account is disabled" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Guest account is enabled" -ForegroundColor Red
}

# Clean up temp file
Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

Write-Host ""
