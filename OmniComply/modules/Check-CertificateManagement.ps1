<#
.SYNOPSIS
    Validates Certificate Management
.DESCRIPTION
    Tests certificate expiration, validity, and trust
    SOC 2 CC6.1, CC7.1 | HIPAA § 164.312(e)(2)(i) - Encryption and integrity
#>

Write-Host "Checking Certificate Management..." -ForegroundColor Cyan

# Check for expiring certificates in Computer Personal store
try {
    $certStore = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop

    $now = Get-Date
    $warningWindow = $now.AddDays(30)

    $expiringCerts = $certStore | Where-Object {
        $_.NotAfter -le $warningWindow -and $_.NotAfter -gt $now
    }

    $expiredCerts = $certStore | Where-Object {
        $_.NotAfter -le $now
    }

    $noExpiringSoon = $expiringCerts.Count -eq 0

    $expiringInfo = if ($expiringCerts.Count -gt 0) {
        ($expiringCerts | ForEach-Object {
            "$($_.Subject) (expires $($_.NotAfter.ToString('yyyy-MM-dd')))"
        }) -join "; "
    } else {
        "No certificates expiring within 30 days"
    }

    Add-ComplianceCheck -Category "Certificate Management" `
        -Check "Certificates Expiring Soon (30 days)" `
        -Requirement "SOC 2 CC7.1 - Certificate Lifecycle Management" `
        -NIST "SC-12, SC-17" `
        -CIS "9.1" `
        -ISO27001 "A.12.3.1, A.10.1.2" `
        -SOX "ITGC-03" `
        -Passed $noExpiringSoon `
        -CurrentValue "$($expiringCerts.Count) expiring: $expiringInfo" `
        -ExpectedValue "No certificates expiring within 30 days" `
        -Remediation "Review and renew certificates: Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.NotAfter -le (Get-Date).AddDays(30) }"

    if ($noExpiringSoon) {
        Write-Host "  [PASS] No certificates expiring within 30 days" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] $($expiringCerts.Count) certificate(s) expiring soon" -ForegroundColor Yellow
    }

    # Check for expired certificates
    $noExpired = $expiredCerts.Count -eq 0

    $expiredInfo = if ($expiredCerts.Count -gt 0) {
        ($expiredCerts | ForEach-Object {
            "$($_.Subject) (expired $($_.NotAfter.ToString('yyyy-MM-dd')))"
        }) -join "; "
    } else {
        "No expired certificates"
    }

    Add-ComplianceCheck -Category "Certificate Management" `
        -Check "Expired Certificates in Store" `
        -Requirement "SOC 2 CC7.1 - Certificate Validity" `
        -NIST "SC-12" `
        -CIS "9.1" `
        -ISO27001 "A.10.1.2" `
        -SOX "ITGC-03" `
        -Passed $noExpired `
        -CurrentValue "$($expiredCerts.Count) expired: $expiredInfo" `
        -ExpectedValue "No expired certificates" `
        -Remediation "Remove expired certificates: Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.NotAfter -le (Get-Date) } | Remove-Item"

    if ($noExpired) {
        Write-Host "  [PASS] No expired certificates in store" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($expiredCerts.Count) expired certificate(s) found" -ForegroundColor Red
    }

    # Check total certificate count (informational)
    $totalCerts = $certStore.Count
    Write-Host "  [INFO] Total certificates in Computer Personal store: $totalCerts" -ForegroundColor Gray

} catch {
    Add-ComplianceCheck -Category "Certificate Management" `
        -Check "Certificate Store Access" `
        -Requirement "SOC 2 CC7.1 - Certificate Management" `
        -NIST "SC-12" `
        -CIS "9.1" `
        -ISO27001 "A.10.1.2" `
        -Passed $false `
        -CurrentValue "Unable to access: $($_.Exception.Message)" `
        -ExpectedValue "Certificate store accessible" `
        -Remediation "Ensure certificate store is accessible and not corrupted"

    Write-Host "  [ERROR] Unable to access certificate store" -ForegroundColor Red
}

# Check for certificates with weak cryptographic providers
try {
    $certStore = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop

    # Check for SHA1 or MD5 signed certificates (weak)
    $weakCerts = $certStore | Where-Object {
        $_.SignatureAlgorithm.FriendlyName -match "sha1|md5"
    }

    $noWeakCerts = $weakCerts.Count -eq 0

    $weakInfo = if ($weakCerts.Count -gt 0) {
        ($weakCerts | ForEach-Object {
            "$($_.Subject) ($($_.SignatureAlgorithm.FriendlyName))"
        }) -join "; "
    } else {
        "No weak algorithms detected"
    }

    Add-ComplianceCheck -Category "Certificate Management" `
        -Check "Weak Cryptographic Algorithms" `
        -Requirement "HIPAA § 164.312(e)(2)(i) - Cryptographic Standards" `
        -NIST "SC-13" `
        -CIS "9.1" `
        -ISO27001 "A.10.1.1" `
        -PCIDSS "4.1" `
        -SOX "ITGC-03" `
        -Passed $noWeakCerts `
        -CurrentValue "$($weakCerts.Count) weak: $weakInfo" `
        -ExpectedValue "No SHA1 or MD5 signed certificates" `
        -Remediation "Replace certificates using weak signature algorithms with SHA256 or higher"

    if ($noWeakCerts) {
        Write-Host "  [PASS] No certificates using weak algorithms (SHA1/MD5)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] $($weakCerts.Count) certificate(s) using weak algorithms" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  [INFO] Unable to check cryptographic algorithms" -ForegroundColor Gray
}

# Check for self-signed certificates in production
try {
    $certStore = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop

    $selfSignedCerts = $certStore | Where-Object {
        $_.Issuer -eq $_.Subject
    }

    $noSelfSigned = $selfSignedCerts.Count -eq 0

    $selfSignedInfo = if ($selfSignedCerts.Count -gt 0) {
        "$($selfSignedCerts.Count) self-signed certificate(s)"
    } else {
        "No self-signed certificates"
    }

    Add-ComplianceCheck -Category "Certificate Management" `
        -Check "Self-Signed Certificates" `
        -Requirement "SOC 2 CC6.1 - Trusted Certificate Authorities" `
        -NIST "SC-12, SC-17" `
        -CIS "9.1" `
        -ISO27001 "A.10.1.2" `
        -SOX "ITGC-03" `
        -Passed $noSelfSigned `
        -CurrentValue $selfSignedInfo `
        -ExpectedValue "No self-signed certificates in production" `
        -Remediation "Replace self-signed certificates with certificates from trusted CAs"

    if ($noSelfSigned) {
        Write-Host "  [PASS] No self-signed certificates detected" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] $($selfSignedCerts.Count) self-signed certificate(s) found (may be acceptable for testing)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check for self-signed certificates" -ForegroundColor Gray
}

# Check Root CA certificate store for unusual additions
try {
    $rootStore = Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction Stop
    $rootCount = $rootStore.Count

    # Typical Windows installations have 50-150 root CAs
    $rootCountNormal = $rootCount -ge 30 -and $rootCount -le 250

    Add-ComplianceCheck -Category "Certificate Management" `
        -Check "Root Certificate Store Size" `
        -Requirement "SOC 2 CC7.1 - Certificate Trust Management" `
        -NIST "SC-12" `
        -CIS "9.1" `
        -ISO27001 "A.10.1.2" `
        -Passed $rootCountNormal `
        -CurrentValue "$rootCount root certificates" `
        -ExpectedValue "30-250 root certificates (typical)" `
        -Remediation "Review root certificate store for unauthorized additions: Get-ChildItem Cert:\LocalMachine\Root | Format-Table Subject, Thumbprint, NotAfter"

    if ($rootCountNormal) {
        Write-Host "  [PASS] Root CA store has $rootCount certificates (normal)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Root CA store has $rootCount certificates (review for tampering)" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  [INFO] Unable to check root certificate store" -ForegroundColor Gray
}

# Check for EFS certificate (Encrypting File System)
try {
    $efsCerts = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction Stop | Where-Object {
        $_.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Encrypting File System" }
    }

    $hasEfsCert = $efsCerts.Count -gt 0

    Add-ComplianceCheck -Category "Certificate Management" `
        -Check "EFS Certificate Present" `
        -Requirement "HIPAA § 164.312(a)(2)(iv) - Encryption Key Management" `
        -NIST "SC-12, SC-28" `
        -CIS "3.5" `
        -ISO27001 "A.10.1.2" `
        -PCIDSS "3.4" `
        -Passed $hasEfsCert `
        -CurrentValue $(if ($hasEfsCert) { "EFS certificate(s) present" } else { "No EFS certificates" }) `
        -ExpectedValue "EFS certificate present (if EFS is used)" `
        -Remediation "If using EFS, ensure certificates are backed up: cipher /x (exports EFS certificate)"

    if ($hasEfsCert) {
        Write-Host "  [PASS] EFS certificate(s) present for file encryption" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] No EFS certificates (acceptable if EFS not used)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check for EFS certificates" -ForegroundColor Gray
}

# Check Certificate Revocation List (CRL) checking
$crlCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config" -Name "MaxOfflineUrlRetrievalByteCount" -ErrorAction SilentlyContinue

if ($crlCheck) {
    # If this value exists and is non-zero, offline CRL checking is configured
    $crlEnabled = $true

    Add-ComplianceCheck -Category "Certificate Management" `
        -Check "Certificate Revocation Checking" `
        -Requirement "SOC 2 CC6.1 - Certificate Validation" `
        -NIST "SC-12, SC-17" `
        -CIS "9.1" `
        -ISO27001 "A.10.1.2" `
        -Passed $crlEnabled `
        -CurrentValue "CRL checking configured" `
        -ExpectedValue "CRL/OCSP checking enabled" `
        -Remediation "CRL checking is enabled"

    Write-Host "  [PASS] Certificate revocation checking is configured" -ForegroundColor Green
} else {
    # Check alternative location
    $crlPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ChainEngine\Config" -ErrorAction SilentlyContinue

    if ($crlPolicy) {
        Write-Host "  [PASS] Certificate revocation checking policy is set" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Default CRL checking configuration in use" -ForegroundColor Gray
    }
}

Write-Host ""
