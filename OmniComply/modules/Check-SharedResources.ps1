<#
.SYNOPSIS
    Validates Shared Resources Security
.DESCRIPTION
    Tests file shares, printer shares, and administrative shares for security misconfigurations
    SOC 2 CC6.1, CC6.3 | HIPAA § 164.308(a)(4)(i), § 164.312(a)(1)
#>

Write-Host "Checking Shared Resources Security..." -ForegroundColor Cyan

# Check for file shares
try {
    $shares = Get-SmbShare -ErrorAction Stop | Where-Object {
        $_.Name -notmatch '^(ADMIN\$|C\$|IPC\$|print\$)$'
    }

    $hasUserShares = $shares.Count -gt 0

    $sharesList = if ($shares.Count -gt 0) {
        ($shares | ForEach-Object { "$($_.Name) ($($_.Path))" }) -join "; "
    } else {
        "No user-created shares"
    }

    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "File Shares Present" `
        -Requirement "SOC 2 CC6.1 - Shared Resource Management" `
        -NIST "AC-3" `
        -CIS "13.9" `
        -ISO27001 "A.13.1.1, A.13.2.1" `
        -SOX "ITGC-01" `
        -Passed $true `
        -CurrentValue "$($shares.Count) share(s): $sharesList" `
        -ExpectedValue "Shares should be reviewed and justified" `
        -Remediation "Review shares: Get-SmbShare; Remove unauthorized shares: Remove-SmbShare -Name 'ShareName'"

    if ($hasUserShares) {
        Write-Host "  [INFO] $($shares.Count) file share(s) detected - review for necessity" -ForegroundColor Gray
    } else {
        Write-Host "  [PASS] No user-created file shares (only default administrative shares)" -ForegroundColor Green
    }

} catch {
    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "SMB Share Query" `
        -Requirement "SOC 2 CC6.1 - Shared Resources" `
        -NIST "AC-3" `
        -CIS "13.9" `
        -ISO27001 "A.13.1.1" `
        -Passed $false `
        -CurrentValue "Unable to query: $($_.Exception.Message)" `
        -ExpectedValue "SMB shares queryable" `
        -Remediation "Ensure SMB service is available"

    Write-Host "  [ERROR] Unable to query SMB shares" -ForegroundColor Red
}

# Check share permissions for overly permissive access
try {
    $shares = Get-SmbShare -ErrorAction Stop | Where-Object {
        $_.Name -notmatch '^(ADMIN\$|C\$|IPC\$|print\$)$'
    }

    $insecureShares = @()

    foreach ($share in $shares) {
        $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue

        # Check for Everyone with Full Control
        $everyoneFull = $shareAccess | Where-Object {
            $_.AccountName -eq "Everyone" -and $_.AccessRight -eq "Full"
        }

        # Check for Guest access
        $guestAccess = $shareAccess | Where-Object {
            $_.AccountName -match "Guest"
        }

        if ($everyoneFull -or $guestAccess) {
            $insecureShares += "$($share.Name)"
        }
    }

    $noInsecureShares = $insecureShares.Count -eq 0

    $insecureList = if ($insecureShares.Count -gt 0) {
        $insecureShares -join ", "
    } else {
        "No insecure share permissions"
    }

    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "Share Permissions Security" `
        -Requirement "HIPAA § 164.308(a)(4)(i) - Access Authorization" `
        -NIST "AC-3, AC-6" `
        -CIS "13.9" `
        -ISO27001 "A.9.1.2, A.9.4.1" `
        -PCIDSS "7.1" `
        -SOX "ITGC-01" `
        -Passed $noInsecureShares `
        -CurrentValue "$($insecureShares.Count) insecure: $insecureList" `
        -ExpectedValue "No shares with 'Everyone Full Control' or Guest access" `
        -Remediation "Revoke-SmbShareAccess -Name 'ShareName' -AccountName 'Everyone' -Force; Grant-SmbShareAccess with specific users"

    if ($noInsecureShares) {
        Write-Host "  [PASS] No shares with overly permissive access detected" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($insecureShares.Count) share(s) with insecure permissions" -ForegroundColor Red
    }

} catch {
    Write-Host "  [INFO] Unable to check share permissions" -ForegroundColor Gray
}

# Check administrative share configuration
$adminSharesEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue

if ($null -ne $adminSharesEnabled) {
    $adminEnabled = $adminSharesEnabled.AutoShareWks -ne 0

    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "Administrative Shares (C$, ADMIN$)" `
        -Requirement "SOC 2 CC6.1 - Administrative Access Control" `
        -NIST "AC-6" `
        -CIS "13.9" `
        -ISO27001 "A.9.2.3" `
        -SOX "ITGC-01" `
        -Passed $adminEnabled `
        -CurrentValue $(if ($adminEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled (for remote administration)" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Value 1"

    if ($adminEnabled) {
        Write-Host "  [PASS] Administrative shares are enabled (C$, ADMIN$)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Administrative shares are disabled (may impact remote management)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] Administrative share setting using defaults" -ForegroundColor Gray
}

# Check for null session access to shares
$restrictNullSessions = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue

if ($null -ne $restrictNullSessions) {
    $nullSessionsRestricted = $restrictNullSessions.RestrictNullSessAccess -eq 1

    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "Null Session Access to Shares" `
        -Requirement "SOC 2 CC6.7 - Anonymous Access Prevention" `
        -NIST "AC-14" `
        -CIS "13.9" `
        -ISO27001 "A.9.1.2, A.13.1.1" `
        -SOX "ITGC-01" `
        -Passed $nullSessionsRestricted `
        -CurrentValue $(if ($nullSessionsRestricted) { "Restricted" } else { "Not restricted" }) `
        -ExpectedValue "Restricted" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1"

    if ($nullSessionsRestricted) {
        Write-Host "  [PASS] Null session access to shares is restricted" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Null session access to shares is not restricted" -ForegroundColor Red
    }
} else {
    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "Null Session Access to Shares" `
        -Requirement "SOC 2 CC6.7 - Anonymous Access Prevention" `
        -NIST "AC-14" `
        -CIS "13.9" `
        -ISO27001 "A.9.1.2, A.13.1.1" `
        -SOX "ITGC-01" `
        -Passed $false `
        -CurrentValue "Not configured" `
        -ExpectedValue "Restricted" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1 -Type DWord"

    Write-Host "  [WARN] Null session access restriction not configured" -ForegroundColor Yellow
}

# Check for printer shares
try {
    $printers = Get-Printer -ErrorAction Stop | Where-Object { $_.Shared -eq $true }

    $hasPrinterShares = $printers.Count -gt 0

    $printerList = if ($printers.Count -gt 0) {
        ($printers | ForEach-Object { "$($_.Name) (Share: $($_.ShareName))" }) -join "; "
    } else {
        "No shared printers"
    }

    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "Shared Printers" `
        -Requirement "SOC 2 CC6.1 - Printer Security" `
        -NIST "AC-3" `
        -CIS "13.9" `
        -ISO27001 "A.11.2.9" `
        -Passed $true `
        -CurrentValue "$($printers.Count) shared: $printerList" `
        -ExpectedValue "Shared printers should be reviewed" `
        -Remediation "Review printer shares: Get-Printer | Where-Object Shared; Disable sharing if not needed: Set-Printer -Name 'PrinterName' -Shared `$false"

    if ($hasPrinterShares) {
        Write-Host "  [INFO] $($printers.Count) shared printer(s) detected - review for necessity" -ForegroundColor Gray
    } else {
        Write-Host "  [PASS] No shared printers" -ForegroundColor Green
    }

} catch {
    Write-Host "  [INFO] Unable to query printer shares" -ForegroundColor Gray
}

# Check SMB signing configuration
$smbSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue

if ($null -ne $smbSigning) {
    $signingRequired = $smbSigning.RequireSecuritySignature -eq 1

    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "SMB Signing Required (Server)" `
        -Requirement "SOC 2 CC6.7 - SMB Security" `
        -NIST "SC-8" `
        -CIS "13.9" `
        -ISO27001 "A.13.1.1, A.13.2.3" `
        -PCIDSS "4.2" `
        -Passed $signingRequired `
        -CurrentValue $(if ($signingRequired) { "Required" } else { "Not required" }) `
        -ExpectedValue "Required" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1"

    if ($signingRequired) {
        Write-Host "  [PASS] SMB signing is required for server" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] SMB signing is not required for server (security risk)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] SMB signing setting not configured" -ForegroundColor Gray
}

# Check SMB encryption
try {
    $smbServerConfig = Get-SmbServerConfiguration -ErrorAction Stop

    $encryptionEnabled = $smbServerConfig.EncryptData -eq $true

    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "SMB Encryption" `
        -Requirement "HIPAA § 164.312(e)(1) - Transmission Security" `
        -NIST "SC-8, SC-13" `
        -CIS "13.9" `
        -ISO27001 "A.10.1.1, A.13.1.1" `
        -PCIDSS "4.1" `
        -SOX "ITGC-03" `
        -Passed $encryptionEnabled `
        -CurrentValue $(if ($encryptionEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-SmbServerConfiguration -EncryptData `$true -Force"

    if ($encryptionEnabled) {
        Write-Host "  [PASS] SMB encryption is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] SMB encryption is disabled (recommended for sensitive data)" -ForegroundColor Yellow
    }

    # Check SMB version restrictions
    $smb1Enabled = $smbServerConfig.EnableSMB1Protocol

    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "SMB v1 Protocol" `
        -Requirement "SOC 2 CC7.1 - Deprecated Protocol Removal" `
        -NIST "CM-7(1), SI-2" `
        -CIS "4.8" `
        -ISO27001 "A.12.6.2" `
        -PCIDSS "2.2.2" `
        -Passed (-not $smb1Enabled) `
        -CurrentValue $(if ($smb1Enabled) { "Enabled (INSECURE)" } else { "Disabled" }) `
        -ExpectedValue "Disabled" `
        -Remediation "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"

    if (-not $smb1Enabled) {
        Write-Host "  [PASS] SMB v1 protocol is disabled (secure)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] SMB v1 protocol is enabled (major security risk!)" -ForegroundColor Red
    }

} catch {
    Write-Host "  [INFO] Unable to check SMB server configuration" -ForegroundColor Gray
}

# Check for anonymous enumeration of shares
$restrictAnonymous = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue

if ($null -ne $restrictAnonymous) {
    # 0 = None (default), 1 = Do not allow enumeration, 2 = No access without explicit permissions
    $anonymousRestricted = $restrictAnonymous.RestrictAnonymous -ge 1

    $restrictValue = switch ($restrictAnonymous.RestrictAnonymous) {
        0 { "None (default)" }
        1 { "No enumeration" }
        2 { "No access" }
        default { "Unknown" }
    }

    Add-ComplianceCheck -Category "Shared Resources" `
        -Check "Anonymous Enumeration of Shares" `
        -Requirement "SOC 2 CC6.7 - Information Disclosure Prevention" `
        -NIST "AC-14" `
        -CIS "13.9" `
        -ISO27001 "A.9.1.2" `
        -SOX "ITGC-01" `
        -Passed $anonymousRestricted `
        -CurrentValue $restrictValue `
        -ExpectedValue "No enumeration (1) or No access (2)" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1"

    if ($anonymousRestricted) {
        Write-Host "  [PASS] Anonymous enumeration of shares is restricted ($restrictValue)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Anonymous enumeration of shares is not restricted" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] Anonymous enumeration restriction not configured" -ForegroundColor Gray
}

Write-Host ""
