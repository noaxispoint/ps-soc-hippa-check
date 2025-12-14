<#
.SYNOPSIS
    Validates Application Control Policies
.DESCRIPTION
    Tests AppLocker and Windows Defender Application Control (WDAC) configuration
    SOC 2 CC6.1, CC7.1 | HIPAA § 164.312(a)(1)
#>

Write-Host "Checking Application Control (AppLocker/WDAC)..." -ForegroundColor Cyan

# Check AppLocker Service
$appIDSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue

if ($appIDSvc) {
    $appIDRunning = $appIDSvc.Status -eq 'Running'

    Add-ComplianceCheck -Category "Application Control" `
        -Check "AppLocker Service (AppIDSvc) Status" `
        -Requirement "SOC 2 CC6.1 - Application Whitelisting" `
        -NIST "CM-7(2)" `
        -CIS "9.2" `
        -ISO27001 "A.12.6.2, A.14.2.5" `
        -Passed $appIDRunning `
        -CurrentValue $appIDSvc.Status `
        -ExpectedValue "Running (if AppLocker is used)" `
        -Remediation "Start-Service AppIDSvc; Set-Service AppIDSvc -StartupType Automatic"

    if ($appIDRunning) {
        Write-Host "  [PASS] AppLocker service is running" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] AppLocker service is not running (not in use)" -ForegroundColor Gray
    }

    # Check AppLocker policies
    try {
        $appLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop

        if ($appLockerPolicy) {
            $ruleCount = 0
            $rulesByType = @{}

            foreach ($ruleCollection in $appLockerPolicy.RuleCollections) {
                $collectionName = $ruleCollection.GetType().Name -replace 'RuleCollection', ''
                $count = $ruleCollection.Count
                $ruleCount += $count
                if ($count -gt 0) {
                    $rulesByType[$collectionName] = $count
                }
            }

            $hasPolicies = $ruleCount -gt 0
            $rulesSummary = if ($rulesByType.Count -gt 0) {
                ($rulesByType.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ", "
            } else {
                "No rules"
            }

            Add-ComplianceCheck -Category "Application Control" `
                -Check "AppLocker Policies Configured" `
                -Requirement "SOC 2 CC6.1 - Application Whitelisting" `
                -NIST "CM-7(2)" `
                -CIS "9.2" `
                -ISO27001 "A.12.6.2, A.14.2.5" `
                -Passed $hasPolicies `
                -CurrentValue "$ruleCount total rules ($rulesSummary)" `
                -ExpectedValue "Policies configured" `
                -Remediation "Configure AppLocker policies via Group Policy or PowerShell" `
                -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > AppLocker > <strong>Configure AppLocker rules</strong> for Executable, Windows Installer, Script, and DLL rule collections (requires Windows Enterprise/Education)"

            if ($hasPolicies) {
                Write-Host "  [PASS] AppLocker policies configured: $rulesSummary" -ForegroundColor Green
            } else {
                Write-Host "  [INFO] No AppLocker policies configured" -ForegroundColor Gray
            }
        } else {
            Add-ComplianceCheck -Category "Application Control" `
                -Check "AppLocker Policies Configured" `
                -Requirement "SOC 2 CC6.1 - Application Whitelisting" `
                -NIST "CM-7(2)" `
                -CIS "9.2" `
                -ISO27001 "A.12.6.2, A.14.2.5" `
                -Passed $false `
                -CurrentValue "No effective policy" `
                -ExpectedValue "Policies configured" `
                -Remediation "Configure AppLocker policies via Group Policy"

            Write-Host "  [INFO] No AppLocker policies configured" -ForegroundColor Gray
        }
    } catch {
        Add-ComplianceCheck -Category "Application Control" `
            -Check "AppLocker Policy Query" `
            -Requirement "SOC 2 CC6.1 - Application Whitelisting" `
            -NIST "CM-7(2)" `
            -CIS "9.2" `
            -ISO27001 "A.12.6.2" `
            -Passed $false `
            -CurrentValue "Unable to query: $($_.Exception.Message)" `
            -ExpectedValue "Policies queryable" `
            -Remediation "Ensure PowerShell AppLocker module is available"

        Write-Host "  [INFO] Unable to query AppLocker policies" -ForegroundColor Gray
    }
}

# Check Windows Defender Application Control (WDAC) / Code Integrity
try {
    $ciPolicies = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

    if ($ciPolicies -and $ciPolicies.CodeIntegrityPolicyEnforcementStatus) {
        $ciEnabled = $ciPolicies.CodeIntegrityPolicyEnforcementStatus -eq 1

        $ciStatus = switch ($ciPolicies.CodeIntegrityPolicyEnforcementStatus) {
            0 { "Not configured" }
            1 { "Enforced" }
            2 { "Audit mode" }
            default { "Unknown" }
        }

        Add-ComplianceCheck -Category "Application Control" `
            -Check "Windows Defender Application Control (WDAC)" `
            -Requirement "SOC 2 CC7.1 - Code Integrity Enforcement" `
            -NIST "CM-7(2), SI-7" `
            -CIS "9.2" `
            -ISO27001 "A.14.2.5, A.12.6.2" `
            -Passed $ciEnabled `
            -CurrentValue $ciStatus `
            -ExpectedValue "Enforced or Audit mode" `
            -Remediation "Configure WDAC policy via Group Policy or PowerShell" `
            -IntuneRecommendation "Endpoint security > Application control > Create Policy > App Control for Business > Deploy custom WDAC policy XML (create policy with <code>New-CIPolicy</code> and deploy via Intune)"

        if ($ciEnabled) {
            Write-Host "  [PASS] WDAC (Code Integrity) is enforced" -ForegroundColor Green
        } elseif ($ciPolicies.CodeIntegrityPolicyEnforcementStatus -eq 2) {
            Write-Host "  [INFO] WDAC is in audit mode" -ForegroundColor Gray
        } else {
            Write-Host "  [INFO] WDAC is not configured" -ForegroundColor Gray
        }

        # Check User Mode Code Integrity (UMCI)
        $umciEnabled = $ciPolicies.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 1

        if ($null -ne $ciPolicies.UsermodeCodeIntegrityPolicyEnforcementStatus) {
            $umciStatus = switch ($ciPolicies.UsermodeCodeIntegrityPolicyEnforcementStatus) {
                0 { "Not configured" }
                1 { "Enforced" }
                2 { "Audit mode" }
                default { "Unknown" }
            }

            Add-ComplianceCheck -Category "Application Control" `
                -Check "User Mode Code Integrity (UMCI)" `
                -Requirement "SOC 2 CC6.1 - User-Mode Application Control" `
                -NIST "CM-7(2), SI-7" `
                -CIS "9.2" `
                -ISO27001 "A.14.2.5" `
                -Passed $umciEnabled `
                -CurrentValue $umciStatus `
                -ExpectedValue "Enforced or Audit mode" `
                -Remediation "Configure WDAC UMCI policy"

            if ($umciEnabled) {
                Write-Host "  [PASS] User Mode Code Integrity is enforced" -ForegroundColor Green
            } elseif ($ciPolicies.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2) {
                Write-Host "  [INFO] User Mode Code Integrity is in audit mode" -ForegroundColor Gray
            } else {
                Write-Host "  [INFO] User Mode Code Integrity is not configured" -ForegroundColor Gray
            }
        }
    } else {
        Add-ComplianceCheck -Category "Application Control" `
            -Check "Windows Defender Application Control (WDAC)" `
            -Requirement "SOC 2 CC7.1 - Code Integrity" `
            -NIST "CM-7(2), SI-7" `
            -CIS "9.2" `
            -ISO27001 "A.14.2.5, A.12.6.2" `
            -Passed $false `
            -CurrentValue "Not available or not configured" `
            -ExpectedValue "Enforced or Audit mode" `
            -Remediation "Configure WDAC policy for application control"

        Write-Host "  [INFO] WDAC not configured" -ForegroundColor Gray
    }
} catch {
    Add-ComplianceCheck -Category "Application Control" `
        -Check "WDAC Query Status" `
        -Requirement "SOC 2 CC7.1 - Application Control" `
        -NIST "CM-7(2), SI-7" `
        -CIS "9.2" `
        -ISO27001 "A.14.2.5" `
        -Passed $false `
        -CurrentValue "Unable to query" `
        -ExpectedValue "WDAC queryable" `
        -Remediation "Ensure Windows 10/11 with Device Guard support"

    Write-Host "  [INFO] Unable to query WDAC status" -ForegroundColor Gray
}

# Check SmartScreen for apps and files
$smartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue

if ($smartScreen) {
    $smartScreenOn = $smartScreen.SmartScreenEnabled -eq "RequireAdmin" -or $smartScreen.SmartScreenEnabled -eq "Warn"

    Add-ComplianceCheck -Category "Application Control" `
        -Check "SmartScreen for Apps and Files" `
        -Requirement "SOC 2 CC7.1 - Unverified Application Protection" `
        -NIST "SI-3" `
        -CIS "10.1" `
        -ISO27001 "A.12.2.1" `
        -PCIDSS "5.1" `
        -Passed $smartScreenOn `
        -CurrentValue $smartScreen.SmartScreenEnabled `
        -ExpectedValue "RequireAdmin or Warn" `
        -Remediation "Enable via Windows Security > App & browser control > Reputation-based protection" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > Windows Components > Windows Defender SmartScreen > Explorer > <strong>Configure Windows Defender SmartScreen</strong> = <code>Enabled - Warn and prevent bypass</code>"

    if ($smartScreenOn) {
        Write-Host "  [PASS] SmartScreen is enabled ($($smartScreen.SmartScreenEnabled))" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] SmartScreen is disabled or set to Off" -ForegroundColor Yellow
    }
} else {
    # Try alternative location for Windows 11
    $smartScreenAlt = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue

    if ($smartScreenAlt) {
        $smartScreenEnabled = $smartScreenAlt.EnableSmartScreen -eq 1

        Add-ComplianceCheck -Category "Application Control" `
            -Check "SmartScreen for Apps and Files" `
            -Requirement "SOC 2 CC7.1 - Unverified Application Protection" `
            -NIST "SI-3" `
            -CIS "10.1" `
            -ISO27001 "A.12.2.1" `
            -PCIDSS "5.1" `
            -Passed $smartScreenEnabled `
            -CurrentValue $(if ($smartScreenEnabled) { "Enabled" } else { "Disabled" }) `
            -ExpectedValue "Enabled" `
            -Remediation "Enable via Windows Security > App & browser control"

        if ($smartScreenEnabled) {
            Write-Host "  [PASS] SmartScreen is enabled" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] SmartScreen is disabled" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [INFO] SmartScreen status could not be determined" -ForegroundColor Gray
    }
}

Write-Host ""
