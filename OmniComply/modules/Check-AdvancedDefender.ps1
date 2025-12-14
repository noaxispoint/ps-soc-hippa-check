<#
.SYNOPSIS
    Validates Advanced Windows Defender Features
.DESCRIPTION
    Tests Attack Surface Reduction, Controlled Folder Access, Network Protection, and Exploit Protection
    SOC 2 CC7.1, CC7.2 | HIPAA § 164.308(a)(5)(ii)(B), § 164.312(a)(2)(iv)
#>

Write-Host "Checking Advanced Windows Defender Features..." -ForegroundColor Cyan

$defenderPrefs = Get-MpPreference -ErrorAction SilentlyContinue

if ($defenderPrefs) {
    # Check Controlled Folder Access (Ransomware Protection)
    $cfaEnabled = $defenderPrefs.EnableControlledFolderAccess -eq 1

    Add-ComplianceCheck -Category "Advanced Defender" `
        -Check "Controlled Folder Access (Ransomware Protection)" `
        -Requirement "HIPAA § 164.312(a)(2)(iv) - Data Protection" `
        -NIST "SI-3, CP-9" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -PCIDSS "5.1, 12.10.1" `
        -Passed $cfaEnabled `
        -CurrentValue $(if ($cfaEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
        -IntuneRecommendation "Endpoint security > Attack surface reduction > Create Policy > <strong>Enable Controlled folder access</strong> = <code>Enabled</code> (or <code>Audit Mode</code> for testing)"

    if ($cfaEnabled) {
        Write-Host "  [PASS] Controlled Folder Access is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Controlled Folder Access is disabled (recommended for ransomware protection)" -ForegroundColor Gray
    }

    # Check Network Protection
    $networkProtection = $defenderPrefs.EnableNetworkProtection
    $networkEnabled = $networkProtection -eq 1

    Add-ComplianceCheck -Category "Advanced Defender" `
        -Check "Network Protection" `
        -Requirement "SOC 2 CC7.1 - Malicious Site Protection" `
        -NIST "SI-3, SI-4" `
        -CIS "10.1" `
        -ISO27001 "A.12.2.1" `
        -Passed $networkEnabled `
        -CurrentValue $(switch ($networkProtection) { 0 { "Disabled" } 1 { "Enabled (Block)" } 2 { "Audit Mode" } default { "Unknown" } }) `
        -ExpectedValue "Enabled (Block mode)" `
        -Remediation "Set-MpPreference -EnableNetworkProtection Enabled" `
        -IntuneRecommendation "Endpoint security > Attack surface reduction > Create Policy > Exploit protection > <strong>Network protection</strong> = <code>Enable</code> (Block mode)"

    if ($networkEnabled) {
        Write-Host "  [PASS] Network Protection is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Network Protection is not enabled (blocks malicious websites)" -ForegroundColor Gray
    }

    # Check Cloud-delivered protection
    $cloudProtection = $defenderPrefs.MAPSReporting
    $cloudEnabled = $cloudProtection -ge 1

    Add-ComplianceCheck -Category "Advanced Defender" `
        -Check "Cloud-Delivered Protection" `
        -Requirement "SOC 2 CC7.1 - Advanced Threat Protection" `
        -NIST "SI-3(2)" `
        -CIS "10.1" `
        -ISO27001 "A.12.2.1" `
        -PCIDSS "5.1.2" `
        -Passed $cloudEnabled `
        -CurrentValue $(switch ($cloudProtection) { 0 { "Disabled" } 1 { "Basic" } 2 { "Advanced" } default { "Unknown" } }) `
        -ExpectedValue "Basic or Advanced" `
        -Remediation "Set-MpPreference -MAPSReporting Advanced" `
        -IntuneRecommendation "Endpoint security > Antivirus > Create Policy > Microsoft Defender Antivirus > <strong>Cloud-delivered protection level</strong> = <code>High</code>, <strong>Extended cloud check</strong> = <code>50</code> seconds"

    if ($cloudEnabled) {
        Write-Host "  [PASS] Cloud-delivered protection is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Cloud-delivered protection is disabled" -ForegroundColor Yellow
    }

    # Check Behavior Monitoring
    $behaviorMonitoring = $defenderPrefs.DisableBehaviorMonitoring -eq $false

    Add-ComplianceCheck -Category "Advanced Defender" `
        -Check "Behavior Monitoring" `
        -Requirement "SOC 2 CC7.1 - Threat Detection" `
        -NIST "SI-3(1)" `
        -CIS "10.1" `
        -ISO27001 "A.12.2.1" `
        -Passed $behaviorMonitoring `
        -CurrentValue $(if ($behaviorMonitoring) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false"

    if ($behaviorMonitoring) {
        Write-Host "  [PASS] Behavior monitoring is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Behavior monitoring is disabled" -ForegroundColor Red
    }

    # Check PUA (Potentially Unwanted Applications) Protection
    $puaProtection = $defenderPrefs.PUAProtection
    $puaEnabled = $puaProtection -eq 1

    Add-ComplianceCheck -Category "Advanced Defender" `
        -Check "PUA (Potentially Unwanted Applications) Protection" `
        -Requirement "SOC 2 CC7.1 - Unwanted Software Protection" `
        -NIST "SI-3" `
        -CIS "10.1" `
        -ISO27001 "A.12.2.1" `
        -Passed $puaEnabled `
        -CurrentValue $(switch ($puaProtection) { 0 { "Disabled" } 1 { "Enabled (Block)" } 2 { "Audit Mode" } default { "Unknown" } }) `
        -ExpectedValue "Enabled (Block mode)" `
        -Remediation "Set-MpPreference -PUAProtection Enabled"

    if ($puaEnabled) {
        Write-Host "  [PASS] PUA protection is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] PUA protection is not enabled" -ForegroundColor Gray
    }
}

# Check Attack Surface Reduction (ASR) Rules
try {
    $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction Stop
    $asrActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction Stop

    if ($asrRules -and $asrRules.Count -gt 0) {
        $enabledRules = 0
        for ($i = 0; $i -lt $asrRules.Count; $i++) {
            if ($asrActions[$i] -eq 1) {  # 1 = Block, 2 = Audit, 0 = Disabled
                $enabledRules++
            }
        }

        $hasASR = $enabledRules -gt 0

        Add-ComplianceCheck -Category "Advanced Defender" `
            -Check "Attack Surface Reduction (ASR) Rules" `
            -Requirement "SOC 2 CC7.1 - Attack Prevention" `
            -NIST "SI-3, SI-4" `
            -CIS "10.5" `
            -ISO27001 "A.12.2.1" `
            -PCIDSS "5.1" `
            -Passed $hasASR `
            -CurrentValue "$enabledRules of $($asrRules.Count) rules in block mode" `
            -ExpectedValue "At least 1 ASR rule enabled" `
            -Remediation "Configure ASR rules via Group Policy or Intune"

        if ($hasASR) {
            Write-Host "  [PASS] Attack Surface Reduction rules configured ($enabledRules enabled)" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] No ASR rules in block mode (recommended for advanced protection)" -ForegroundColor Gray
        }
    } else {
        Add-ComplianceCheck -Category "Advanced Defender" `
            -Check "Attack Surface Reduction (ASR) Rules" `
            -Requirement "SOC 2 CC7.1 - Attack Prevention" `
            -NIST "SI-3, SI-4" `
            -CIS "10.5" `
            -ISO27001 "A.12.2.1" `
            -PCIDSS "5.1" `
            -Passed $false `
            -CurrentValue "No rules configured" `
            -ExpectedValue "At least 1 ASR rule enabled" `
            -Remediation "Configure ASR rules via Group Policy or Intune"

        Write-Host "  [INFO] No ASR rules configured (recommended for advanced protection)" -ForegroundColor Gray
    }
} catch {
    Add-ComplianceCheck -Category "Advanced Defender" `
        -Check "Attack Surface Reduction (ASR) Rules" `
        -Requirement "SOC 2 CC7.1 - Attack Prevention" `
        -NIST "SI-3, SI-4" `
        -CIS "10.5" `
        -ISO27001 "A.12.2.1" `
        -PCIDSS "5.1" `
        -Passed $false `
        -CurrentValue "Unable to query ASR rules" `
        -ExpectedValue "At least 1 ASR rule enabled" `
        -Remediation "Configure ASR rules via Group Policy or Intune"

    Write-Host "  [INFO] ASR rules not configured" -ForegroundColor Gray
}

# Check Exploit Protection (system-wide)
try {
    $exploitProtection = Get-ProcessMitigation -System -ErrorAction Stop

    # Check for key exploit protections
    $dep = $exploitProtection.DEP.Enable -eq "ON"
    $sehop = $exploitProtection.SEHOP.Enable -eq "ON"

    Add-ComplianceCheck -Category "Advanced Defender" `
        -Check "Exploit Protection - DEP (Data Execution Prevention)" `
        -Requirement "SOC 2 CC6.1 - Memory Protection" `
        -NIST "SI-16, SI-7(1)" `
        -CIS "10.5" `
        -ISO27001 "A.12.2.1" `
        -Passed $dep `
        -CurrentValue $(if ($dep) { "Enabled" } else { "Disabled or NotSet" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Enable via Windows Security > App & browser control > Exploit protection"

    if ($dep) {
        Write-Host "  [PASS] DEP (Data Execution Prevention) is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] DEP is not enabled" -ForegroundColor Yellow
    }

    Add-ComplianceCheck -Category "Advanced Defender" `
        -Check "Exploit Protection - SEHOP" `
        -Requirement "SOC 2 CC6.1 - Exploit Mitigation" `
        -NIST "SI-16, SI-7(1)" `
        -CIS "10.5" `
        -ISO27001 "A.12.2.1" `
        -Passed $sehop `
        -CurrentValue $(if ($sehop) { "Enabled" } else { "Disabled or NotSet" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Enable via Windows Security > App & browser control > Exploit protection"

    if ($sehop) {
        Write-Host "  [PASS] SEHOP (Structured Exception Handler Overwrite Protection) is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] SEHOP is not enabled" -ForegroundColor Gray
    }
} catch {
    Add-ComplianceCheck -Category "Advanced Defender" `
        -Check "Exploit Protection Status" `
        -Requirement "SOC 2 CC6.1 - Exploit Mitigation" `
        -NIST "SI-16, SI-7(1)" `
        -CIS "10.5" `
        -ISO27001 "A.12.2.1" `
        -Passed $false `
        -CurrentValue "Unable to query exploit protection" `
        -ExpectedValue "Exploit protections enabled" `
        -Remediation "Enable via Windows Security > App & browser control > Exploit protection"

    Write-Host "  [INFO] Could not query exploit protection settings" -ForegroundColor Gray
}

Write-Host ""
