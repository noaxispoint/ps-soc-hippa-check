<#
.SYNOPSIS
    Validates Encryption and Data Protection Controls
.DESCRIPTION
    Tests BitLocker, EFS, and encryption settings
    Multi-Framework: SOC 2, HIPAA, NIST 800-53, CIS Controls v8, ISO 27001, PCI-DSS
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
            -NIST "SC-28, SC-28(1)" `
            -CIS "3.1" `
            -ISO27001 "A.10.1.1" `
            -PCIDSS "3.4, 3.5.1" `
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
            -NIST "SC-28" `
            -CIS "3.1" `
            -ISO27001 "A.10.1.1" `
            -PCIDSS "3.4" `
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
        -NIST "SC-28" `
        -CIS "3.1" `
        -ISO27001 "A.10.1.1" `
        -PCIDSS "3.4" `
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
        -NIST "SC-12, SC-13" `
        -CIS "3.1" `
        -ISO27001 "A.10.1.2" `
        -PCIDSS "3.6.1" `
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
$cpuArch = (Get-CimInstance Win32_Processor).Architecture
$isARM = ($cpuArch -eq 5 -or $cpuArch -eq 12)

try {
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    $secureBootStatus = "Enabled"
} catch {
    $secureBootEnabled = $false
    if ($isARM) {
        $secureBootStatus = "Cannot detect on ARM (firmware may vary)"
    } else {
        $secureBootStatus = "Disabled or not supported"
    }
}

Add-ComplianceCheck -Category "Encryption Controls" `
    -Check "Secure Boot" `
    -Requirement "SOC 2 CC6.1 - Boot Integrity" `
    -NIST "SI-7" `
    -CIS "3.3" `
    -ISO27001 "A.12.2.1" `
    -PCIDSS "11.5" `
    -Passed $secureBootEnabled `
    -CurrentValue $secureBootStatus `
    -ExpectedValue "Enabled" `
    -Remediation $(if ($isARM) { "Enable Secure Boot in device firmware settings (check manufacturer documentation)" } else { "Enable Secure Boot in UEFI/BIOS settings" })

if ($secureBootEnabled) {
    Write-Host "  [PASS] Secure Boot is enabled" -ForegroundColor Green
} elseif ($isARM) {
    Write-Host "  [WARN] Secure Boot detection not supported on this ARM device" -ForegroundColor Yellow
} else {
    Write-Host "  [WARN] Secure Boot is not enabled or not supported" -ForegroundColor Yellow
}

Write-Host ""
