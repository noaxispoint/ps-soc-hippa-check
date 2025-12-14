<#
.SYNOPSIS
    Validates Network Encryption and Secure Communications
.DESCRIPTION
    Tests TLS versions, SMB encryption, LDAP signing, and network authentication protocols
    GDPR Article 32.1.a (Encryption in Transit) | PCI-DSS 4.1 | HIPAA § 164.312(e)(1)
#>

Write-Host "Checking Network Encryption and Secure Communications..." -ForegroundColor Cyan

# Check SMB v1 Protocol (should be disabled)
$smbv1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue

if ($smbv1Feature) {
    $smbv1Disabled = $smbv1Feature.State -eq 'Disabled'

    Add-ComplianceCheck -Category "Network Encryption" `
        -Check "SMB v1 Protocol Disabled" `
        -Requirement "PCI-DSS 4.1 - Insecure Protocol Removal" `
        -NIST "SC-8, SC-8(1)" `
        -CIS "9.1" `
        -ISO27001 "A.13.1.1" `
        -PCIDSS "4.1" `
        -GDPR "Article 32.1.a" `
        -Passed $smbv1Disabled `
        -CurrentValue $smbv1Feature.State `
        -ExpectedValue "Disabled" `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > MS Security Guide > <strong>Configure SMB v1 server</strong> = <code>Disabled</code>, <strong>Configure SMB v1 client driver</strong> = <code>Disable driver</code>"

    if ($smbv1Disabled) {
        Write-Host "  [PASS] SMB v1 protocol is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] SMB v1 protocol is enabled (critical security risk)" -ForegroundColor Red
    }
} else {
    Write-Host "  [INFO] SMB v1 feature not found (may not be applicable)" -ForegroundColor Gray
}

# Check SMB Encryption Requirement
$smbEncryption = Get-SmbServerConfiguration -ErrorAction SilentlyContinue

if ($smbEncryption) {
    $encryptionRequired = $smbEncryption.EncryptData -or $smbEncryption.RejectUnencryptedAccess

    Add-ComplianceCheck -Category "Network Encryption" `
        -Check "SMB Encryption Enabled" `
        -Requirement "GDPR Article 32.1.a - Encryption of Personal Data in Transit" `
        -NIST "SC-8(1)" `
        -CIS "9.1" `
        -ISO27001 "A.13.1.1, A.13.2.3" `
        -PCIDSS "4.1" `
        -GDPR "Article 32.1.a" `
        -Passed $encryptionRequired `
        -CurrentValue "EncryptData: $($smbEncryption.EncryptData), RejectUnencrypted: $($smbEncryption.RejectUnencryptedAccess)" `
        -ExpectedValue "Encryption required" `
        -Remediation "Set-SmbServerConfiguration -EncryptData `$true -RejectUnencryptedAccess `$true -Force" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > Network > Lanman Server > <strong>SMB Server: Require security signature</strong> = <code>Enabled</code> (signing), or configure via PowerShell script deployment"

    if ($encryptionRequired) {
        Write-Host "  [PASS] SMB encryption is configured (EncryptData: $($smbEncryption.EncryptData))" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] SMB encryption not enforced (recommend for sensitive data)" -ForegroundColor Yellow
    }

    # Check SMB Signing
    $signingRequired = $smbEncryption.RequireSecuritySignature

    Add-ComplianceCheck -Category "Network Encryption" `
        -Check "SMB Signing Required" `
        -Requirement "SOC 2 CC6.1 - Data Integrity in Transit" `
        -NIST "SC-8(1)" `
        -CIS "9.1" `
        -ISO27001 "A.13.1.1" `
        -PCIDSS "4.1" `
        -GDPR "Article 32.1.a" `
        -Passed $signingRequired `
        -CurrentValue $signingRequired.ToString() `
        -ExpectedValue "True" `
        -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Local Policies Security Options > <strong>Microsoft network server: Digitally sign communications (always)</strong> = <code>Enabled</code>"

    if ($signingRequired) {
        Write-Host "  [PASS] SMB signing is required" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] SMB signing is not required (man-in-the-middle risk)" -ForegroundColor Red
    }
}

# Check TLS 1.2 Enabled
$tls12Client = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -ErrorAction SilentlyContinue
$tls12Server = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue

$tls12ClientEnabled = ($null -eq $tls12Client) -or ($tls12Client.Enabled -eq 1)
$tls12ServerEnabled = ($null -eq $tls12Server) -or ($tls12Server.Enabled -eq 1)
$tls12Enabled = $tls12ClientEnabled -and $tls12ServerEnabled

Add-ComplianceCheck -Category "Network Encryption" `
    -Check "TLS 1.2 Enabled" `
    -Requirement "PCI-DSS 4.1 - Strong Cryptography for Data in Transit" `
    -NIST "SC-8, SC-8(1)" `
    -CIS "9.1" `
    -ISO27001 "A.13.1.1, A.14.1.3" `
    -PCIDSS "4.1" `
    -GDPR "Article 32.1.a" `
    -SOX "ITGC-03" `
    -Passed $tls12Enabled `
    -CurrentValue "Client: $tls12ClientEnabled, Server: $tls12ServerEnabled" `
    -ExpectedValue "Enabled (default or explicit)" `
    -Remediation "See Microsoft documentation for enabling TLS 1.2 system-wide" `
    -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > Network > SSL Configuration Settings > <strong>SSL Cipher Suite Order</strong> (configure to prioritize TLS 1.2/1.3)"

if ($tls12Enabled) {
    Write-Host "  [PASS] TLS 1.2 is enabled" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] TLS 1.2 may not be properly enabled" -ForegroundColor Red
}

# Check TLS 1.0 and 1.1 Disabled (deprecated protocols)
$tls10Client = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue
$tls10Server = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue
$tls11Client = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -ErrorAction SilentlyContinue
$tls11Server = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -ErrorAction SilentlyContinue

$tls10Disabled = ($null -ne $tls10Client -and $tls10Client.Enabled -eq 0) -and ($null -ne $tls10Server -and $tls10Server.Enabled -eq 0)
$tls11Disabled = ($null -ne $tls11Client -and $tls11Client.Enabled -eq 0) -and ($null -ne $tls11Server -and $tls11Server.Enabled -eq 0)

$oldTlsDisabled = $tls10Disabled -and $tls11Disabled

Add-ComplianceCheck -Category "Network Encryption" `
    -Check "Legacy TLS (1.0/1.1) Disabled" `
    -Requirement "PCI-DSS 4.1 - Disable Insecure Protocols" `
    -NIST "SC-8, SC-23" `
    -CIS "9.1" `
    -ISO27001 "A.13.1.1" `
    -PCIDSS "4.1" `
    -GDPR "Article 32.1.a" `
    -Passed $oldTlsDisabled `
    -CurrentValue "TLS 1.0 Disabled: $tls10Disabled, TLS 1.1 Disabled: $tls11Disabled" `
    -ExpectedValue "Both disabled" `
    -Remediation "Disable TLS 1.0 and 1.1 via registry or Group Policy" `
    -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > Network > SSL Configuration Settings > Configure cipher suite order to exclude TLS 1.0/1.1, or deploy PowerShell script to disable via registry"

if ($oldTlsDisabled) {
    Write-Host "  [PASS] Legacy TLS protocols (1.0/1.1) are disabled" -ForegroundColor Green
} elseif (!$tls10Disabled -or !$tls11Disabled) {
    Write-Host "  [WARN] Legacy TLS protocols may still be enabled (PCI-DSS non-compliance)" -ForegroundColor Yellow
} else {
    Write-Host "  [INFO] Legacy TLS protocol status not explicitly configured" -ForegroundColor Gray
}

# Check LDAP Signing Requirement
$ldapSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue

if ($ldapSigning) {
    $ldapSigningLevel = $ldapSigning.LDAPServerIntegrity
    $ldapSigningRequired = $ldapSigningLevel -eq 2  # 2 = Require signing

    $signingText = switch ($ldapSigningLevel) {
        0 { "None" }
        1 { "Negotiate signing" }
        2 { "Require signing" }
        default { "Unknown" }
    }

    Add-ComplianceCheck -Category "Network Encryption" `
        -Check "LDAP Signing Required" `
        -Requirement "SOC 2 CC6.1 - Directory Service Protection" `
        -NIST "SC-8(1)" `
        -CIS "9.1" `
        -ISO27001 "A.13.1.1" `
        -GDPR "Article 32.1.a" `
        -Passed $ldapSigningRequired `
        -CurrentValue $signingText `
        -ExpectedValue "Require signing" `
        -Remediation "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Domain controller: LDAP server signing requirements" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Local Policies Security Options > <strong>Domain controller: LDAP server signing requirements</strong> = <code>Require signing</code> (Domain Controllers only)"

    if ($ldapSigningRequired) {
        Write-Host "  [PASS] LDAP signing is required" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] LDAP signing: $signingText (recommend 'Require signing' for DCs)" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] LDAP signing not applicable (not a domain controller)" -ForegroundColor Gray
}

# Check LAN Manager Authentication Level (NTLMv2)
$lmAuthLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

if ($lmAuthLevel) {
    $authLevel = $lmAuthLevel.LmCompatibilityLevel
    $isSecure = $authLevel -ge 5  # 5 = Send NTLMv2 response only/refuse LM & NTLM

    $authLevelText = switch ($authLevel) {
        0 { "Send LM & NTLM responses" }
        1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" }
        2 { "Send NTLM response only" }
        3 { "Send NTLMv2 response only" }
        4 { "Send NTLMv2 response only/refuse LM" }
        5 { "Send NTLMv2 response only/refuse LM & NTLM" }
        default { "Unknown" }
    }

    Add-ComplianceCheck -Category "Network Encryption" `
        -Check "NTLMv2 Authentication Required" `
        -Requirement "SOC 2 CC6.1 - Secure Authentication Protocols" `
        -NIST "IA-2, SC-8" `
        -CIS "9.1" `
        -ISO27001 "A.9.4.2, A.13.1.1" `
        -GDPR "Article 32.1.a" `
        -Passed $isSecure `
        -CurrentValue "Level $authLevel - $authLevelText" `
        -ExpectedValue "Level 5 - Send NTLMv2 only/refuse LM & NTLM" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Local Policies Security Options > <strong>Network security: LAN Manager authentication level</strong> = <code>Send NTLMv2 response only. Refuse LM & NTLM</code>"

    if ($isSecure) {
        Write-Host "  [PASS] Network authentication level: $authLevelText" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Network authentication level: $authLevelText (recommend level 5)" -ForegroundColor Yellow
    }
} else {
    Add-ComplianceCheck -Category "Network Encryption" `
        -Check "NTLMv2 Authentication Required" `
        -Requirement "SOC 2 CC6.1 - Secure Authentication Protocols" `
        -NIST "IA-2, SC-8" `
        -CIS "9.1" `
        -ISO27001 "A.9.4.2, A.13.1.1" `
        -GDPR "Article 32.1.a" `
        -Passed $false `
        -CurrentValue "Not configured" `
        -ExpectedValue "Level 5 - Send NTLMv2 only/refuse LM & NTLM" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type DWord"

    Write-Host "  [WARN] Network authentication level not configured" -ForegroundColor Yellow
}

Write-Host ""
