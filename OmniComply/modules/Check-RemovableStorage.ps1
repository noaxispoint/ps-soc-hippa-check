<#
.SYNOPSIS
    Validates Removable Storage Controls
.DESCRIPTION
    Tests USB and removable media security policies
    SOC 2 CC6.1 | HIPAA § 164.310(d)(1), § 164.312(a)(1)
#>

Write-Host "Checking Removable Storage Controls..." -ForegroundColor Cyan

# Check if removable storage is restricted via Group Policy
$removableStoragePolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -ErrorAction SilentlyContinue

if ($removableStoragePolicy) {
    # Check various removable device classes
    $deviceClasses = @{
        "Deny_All" = @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
            Name = "Deny_All"
            Description = "All Removable Storage Classes"
        }
        "Deny_Read" = @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
            Name = "Deny_Read"
            Description = "Removable Disks - Read Access"
        }
        "Deny_Write" = @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
            Name = "Deny_Write"
            Description = "Removable Disks - Write Access"
        }
    }

    $hasRestrictions = $false
    $restrictions = @()

    foreach ($check in $deviceClasses.GetEnumerator()) {
        $policy = Get-ItemProperty -Path $check.Value.Path -Name $check.Value.Name -ErrorAction SilentlyContinue
        if ($policy -and $policy.($check.Value.Name) -eq 1) {
            $hasRestrictions = $true
            $restrictions += $check.Value.Description
        }
    }

    $restrictionsSummary = if ($restrictions.Count -gt 0) {
        $restrictions -join "; "
    } else {
        "No restrictions"
    }

    Add-ComplianceCheck -Category "Removable Storage" `
        -Check "Removable Storage Restrictions" `
        -Requirement "HIPAA § 164.310(d)(1) - Device and Media Controls" `
        -NIST "MP-7" `
        -CIS "8.4" `
        -ISO27001 "A.8.2.3, A.11.2.9" `
        -SOX "ITGC-03" `
        -Passed $hasRestrictions `
        -CurrentValue $restrictionsSummary `
        -ExpectedValue "Restrictions configured" `
        -Remediation "Configure via Group Policy: Computer Configuration > Administrative Templates > System > Removable Storage Access" `
        -IntuneRecommendation "Endpoint security > Attack surface reduction > Create Policy > Device control > <strong>Removable storage</strong> = <code>Block</code> or <code>Audit</code>, or Devices > Configuration profiles > Settings catalog > Administrative Templates > System > Removable Storage Access > <strong>All Removable Storage classes: Deny all access</strong> = <code>Enabled</code>"

    if ($hasRestrictions) {
        Write-Host "  [PASS] Removable storage restrictions configured: $restrictionsSummary" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] No removable storage restrictions configured" -ForegroundColor Gray
    }
} else {
    Add-ComplianceCheck -Category "Removable Storage" `
        -Check "Removable Storage Policy" `
        -Requirement "HIPAA § 164.310(d)(1) - Device and Media Controls" `
        -NIST "MP-7" `
        -CIS "8.4" `
        -ISO27001 "A.8.2.3, A.11.2.9" `
        -SOX "ITGC-03" `
        -Passed $false `
        -CurrentValue "No policy configured" `
        -ExpectedValue "Policy configured to restrict USB/removable media" `
        -Remediation "Configure via Group Policy or Intune"

    Write-Host "  [INFO] No removable storage policy configured" -ForegroundColor Gray
}

# Check BitLocker To Go (encryption for removable drives)
$bitlockerToGo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyWriteAccess" -ErrorAction SilentlyContinue

if ($bitlockerToGo) {
    $requireEncryption = $bitlockerToGo.RDVDenyWriteAccess -eq 1

    Add-ComplianceCheck -Category "Removable Storage" `
        -Check "BitLocker To Go - Unencrypted Write Protection" `
        -Requirement "HIPAA § 164.312(a)(2)(iv) - Encryption of Removable Media" `
        -NIST "SC-28, MP-5" `
        -CIS "3.5" `
        -ISO27001 "A.8.2.3, A.10.1.1" `
        -PCIDSS "3.4" `
        -SOX "ITGC-03" `
        -Passed $requireEncryption `
        -CurrentValue $(if ($requireEncryption) { "Write protection enabled (encryption required)" } else { "Not enforced" }) `
        -ExpectedValue "Write protection enabled" `
        -Remediation "Configure via Group Policy: Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Removable Data Drives" `
        -IntuneRecommendation "Endpoint security > Disk encryption > Create Policy > BitLocker > Removable Data Drives > <strong>Deny write access to removable drives not protected by BitLocker</strong> = <code>Yes</code>"

    if ($requireEncryption) {
        Write-Host "  [PASS] BitLocker To Go write protection enabled (unencrypted drives blocked)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] BitLocker To Go write protection not enforced" -ForegroundColor Gray
    }
}

# Check for external device audit logging
$removableAudit = auditpol /get /subcategory:"Removable Storage" /r 2>$null | ConvertFrom-Csv |
    Where-Object { $_.'Inclusion Setting' -match "Success|Failure" }

$auditEnabled = $null -ne $removableAudit

Add-ComplianceCheck -Category "Removable Storage" `
    -Check "Removable Storage Auditing" `
    -Requirement "HIPAA § 164.312(b) - Audit Controls for Device Access" `
    -NIST "AU-2, AU-12" `
    -CIS "8.2" `
    -ISO27001 "A.12.4.1" `
    -SOX "ITGC-05" `
    -Passed $auditEnabled `
    -CurrentValue $(if ($auditEnabled) { $removableAudit.'Inclusion Setting' } else { "Not audited" }) `
    -ExpectedValue "Success and Failure" `
    -Remediation "auditpol /set /subcategory:`"Removable Storage`" /success:enable /failure:enable"

if ($auditEnabled) {
    Write-Host "  [PASS] Removable storage auditing is enabled" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Removable storage auditing is not enabled" -ForegroundColor Red
}

# Check Windows Defender USB protection
$defenderUSB = Get-MpPreference -ErrorAction SilentlyContinue

if ($defenderUSB) {
    # Check if scanning removable drives is enabled
    $scanRemovable = $defenderUSB.DisableRemovableDriveScanning -eq $false

    Add-ComplianceCheck -Category "Removable Storage" `
        -Check "Windows Defender - Removable Drive Scanning" `
        -Requirement "SOC 2 CC7.1 - Malware Protection for External Media" `
        -NIST "SI-3" `
        -CIS "10.1" `
        -ISO27001 "A.12.2.1" `
        -PCIDSS "5.1" `
        -Passed $scanRemovable `
        -CurrentValue $(if ($scanRemovable) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-MpPreference -DisableRemovableDriveScanning `$false"

    if ($scanRemovable) {
        Write-Host "  [PASS] Windows Defender scans removable drives" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Windows Defender removable drive scanning is disabled" -ForegroundColor Yellow
    }

    # Check AutoRun/AutoPlay settings
    $autoRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue

    if ($autoRun) {
        # Value should be 255 (0xFF) to disable all AutoRun
        # Or 0x9C (156) to disable removable drives and network drives
        $autoRunDisabled = $autoRun.NoDriveTypeAutoRun -ge 156

        $autoRunValue = "0x{0:X}" -f $autoRun.NoDriveTypeAutoRun

        Add-ComplianceCheck -Category "Removable Storage" `
            -Check "AutoRun Disabled for Removable Drives" `
            -Requirement "SOC 2 CC7.1 - Autorun Malware Prevention" `
            -NIST "SI-3" `
            -CIS "10.1" `
            -ISO27001 "A.12.2.1" `
            -PCIDSS "5.1" `
            -Passed $autoRunDisabled `
            -CurrentValue "$autoRunValue" `
            -ExpectedValue "0xFF (all) or 0x9C (removable)" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord" `
            -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > Windows Components > AutoPlay Policies > <strong>Turn off Autoplay</strong> = <code>Enabled</code>, <strong>Default behavior</strong> = <code>All drives</code>"

        if ($autoRunDisabled) {
            Write-Host "  [PASS] AutoRun is disabled for removable drives" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] AutoRun may not be fully disabled ($autoRunValue)" -ForegroundColor Yellow
        }
    } else {
        Add-ComplianceCheck -Category "Removable Storage" `
            -Check "AutoRun Configuration" `
            -Requirement "SOC 2 CC7.1 - Autorun Malware Prevention" `
            -NIST "SI-3" `
            -CIS "10.1" `
            -ISO27001 "A.12.2.1" `
            -PCIDSS "5.1" `
            -Passed $false `
            -CurrentValue "Not configured (AutoRun may be enabled)" `
            -ExpectedValue "Disabled for removable drives" `
            -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord -Force"

        Write-Host "  [WARN] AutoRun policy not configured (security risk)" -ForegroundColor Yellow
    }
}

Write-Host ""
