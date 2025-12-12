<#
.SYNOPSIS
    Validates Encryption and Data Protection Controls
.DESCRIPTION
    Tests BitLocker, EFS, and encryption settings
    SOC 2 CC6.1 | HIPAA § 164.312(a)(2)(iv), § 164.312(e)(2)(ii)
#>

Write-Host "Checking Encryption Controls..." -ForegroundColor Cyan

# Check BitLocker status
$bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue

if ($bitlockerVolumes) {
    $osVolume = $bitlockerVolumes | Where-Object { $_.VolumeType -eq 'OperatingSystem' }
    
    if ($osVolume) {
        $osEncrypted = $osVolume.VolumeStatus -eq 'FullyEncrypted' -or $osVolume.VolumeStatus -eq 'EncryptionInProgress'
        $protectionOn = $osVolume.ProtectionStatus -eq 'On'
        
        Add-ComplianceCheck -Category "Encryption Controls" `
            -Check "OS Drive Encryption (BitLocker)" `
            -Requirement "HIPAA § 164.312(a)(2)(iv) / SOC 2 CC6.1" `
            -Passed $osEncrypted `
            -CurrentValue "$($osVolume.VolumeStatus)" `
            -ExpectedValue "FullyEncrypted" `
            -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -RecoveryPasswordProtector"
        
        if ($osEncrypted) {
            Write-Host "  [PASS] OS drive is encrypted: $($osVolume.VolumeStatus)" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] OS drive is not encrypted: $($osVolume.VolumeStatus)" -ForegroundColor Red
        }
        
        Add-ComplianceCheck -Category "Encryption Controls" `
            -Check "BitLocker Protection Status" `
            -Requirement "HIPAA § 164.312(a)(2)(iv)" `
            -Passed $protectionOn `
            -CurrentValue "$($osVolume.ProtectionStatus)" `
            -ExpectedValue "On" `
            -Remediation "Resume-BitLocker -MountPoint 'C:'"
        
        if ($protectionOn) {
            Write-Host "  [PASS] BitLocker protection is active" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] BitLocker protection is suspended or off" -ForegroundColor Red
        }
    }
} else {
    Add-ComplianceCheck -Category "Encryption Controls" `
        -Check "BitLocker Availability" `
        -Requirement "HIPAA § 164.312(a)(2)(iv)" `
        -Passed $false `
        -CurrentValue "BitLocker not available or no volumes detected" `
        -ExpectedValue "BitLocker enabled and protecting drives" `
        -Remediation "Verify Windows edition supports BitLocker (Pro, Enterprise, Education)"
    
    Write-Host "  [FAIL] BitLocker not available or no status detected" -ForegroundColor Red
}

# Check TPM status
$tpm = Get-Tpm -ErrorAction SilentlyContinue

if ($tpm) {
    $tpmReady = $tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled
    
    Add-ComplianceCheck -Category "Encryption Controls" `
        -Check "TPM Status" `
        -Requirement "SOC 2 CC6.1 - Hardware Security" `
        -Passed $tpmReady `
        -CurrentValue "Present: $($tpm.TpmPresent), Ready: $($tpm.TpmReady), Enabled: $($tpm.TpmEnabled)" `
        -ExpectedValue "Present, Ready, and Enabled" `
        -Remediation "Enable TPM in BIOS/UEFI settings"
    
    if ($tpmReady) {
        Write-Host "  [PASS] TPM is present, ready, and enabled" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] TPM not fully operational" -ForegroundColor Red
    }
}

# Check for secure boot
$secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue

Add-ComplianceCheck -Category "Encryption Controls" `
    -Check "Secure Boot" `
    -Requirement "SOC 2 CC6.1 - Boot Integrity" `
    -Passed $secureBootEnabled `
    -CurrentValue $(if ($secureBootEnabled) { "Enabled" } else { "Disabled or not supported" }) `
    -ExpectedValue "Enabled" `
    -Remediation "Enable Secure Boot in UEFI/BIOS settings"

if ($secureBootEnabled) {
    Write-Host "  [PASS] Secure Boot is enabled" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Secure Boot is not enabled or not supported" -ForegroundColor Yellow
}

Write-Host ""
