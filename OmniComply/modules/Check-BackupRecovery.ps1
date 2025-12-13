<#
.SYNOPSIS
    Validates Backup and Recovery Configuration
.DESCRIPTION
    Tests Windows Backup, Volume Shadow Copy, and recovery settings
    SOC 2 CC5.1 | HIPAA § 164.308(a)(7)(ii)(A) - Data backup plan
#>

Write-Host "Checking Backup and Recovery Configuration..." -ForegroundColor Cyan

# Check Windows Backup service
$wbService = Get-Service -Name "wbengine" -ErrorAction SilentlyContinue

if ($wbService) {
    $wbRunning = $wbService.Status -eq 'Running'

    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Windows Backup Service (wbengine)" `
        -Requirement "SOC 2 CC5.1 - Backup Infrastructure" `
        -Passed $true `
        -CurrentValue "Status: $($wbService.Status), StartType: $($wbService.StartType)" `
        -ExpectedValue "Service exists (Manual start is normal)" `
        -Remediation "Windows Backup service is present"

    if ($wbService.StartType -eq 'Manual' -or $wbRunning) {
        Write-Host "  [PASS] Windows Backup service is available" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Windows Backup service status: $($wbService.Status)" -ForegroundColor Gray
    }
} else {
    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Windows Backup Service" `
        -Requirement "SOC 2 CC5.1 - Backup Infrastructure" `
        -Passed $false `
        -CurrentValue "Service not found" `
        -ExpectedValue "Windows Backup service available" `
        -Remediation "Install Windows Server Backup feature: Install-WindowsFeature Windows-Server-Backup"

    Write-Host "  [WARN] Windows Backup service not found (feature may not be installed)" -ForegroundColor Yellow
}

# Check for Windows Backup policy/schedule
try {
    $wbPolicy = Get-WBPolicy -ErrorAction Stop

    if ($wbPolicy) {
        $backupConfigured = $true

        # Get schedule details
        $schedule = $wbPolicy.Schedule
        $scheduleInfo = if ($schedule) {
            "Scheduled: $($schedule.Count) backup time(s)"
        } else {
            "No schedule configured"
        }

        Add-ComplianceCheck -Category "Backup and Recovery" `
            -Check "Windows Backup Policy Configured" `
            -Requirement "HIPAA § 164.308(a)(7)(ii)(A) - Backup Plan" `
            -Passed $backupConfigured `
            -CurrentValue $scheduleInfo `
            -ExpectedValue "Backup policy configured with schedule" `
            -Remediation "Configure Windows Backup: wbadmin enable backup -addtarget:<BackupTarget> -schedule:<Time>"

        Write-Host "  [PASS] Windows Backup policy is configured: $scheduleInfo" -ForegroundColor Green

        # Check backup targets
        if ($wbPolicy.BackupTargets) {
            $targets = ($wbPolicy.BackupTargets | ForEach-Object { $_.TargetLabel }) -join ", "
            Write-Host "  [INFO] Backup targets: $targets" -ForegroundColor Gray
        }

    } else {
        Add-ComplianceCheck -Category "Backup and Recovery" `
            -Check "Windows Backup Policy Configured" `
            -Requirement "HIPAA § 164.308(a)(7)(ii)(A) - Backup Plan" `
            -Passed $false `
            -CurrentValue "No backup policy configured" `
            -ExpectedValue "Backup policy configured" `
            -Remediation "Configure Windows Backup via GUI or: wbadmin enable backup -addtarget:<BackupTarget> -schedule:<Time>"

        Write-Host "  [INFO] No Windows Backup policy configured (verify alternative backup solution exists)" -ForegroundColor Gray
    }

} catch {
    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Windows Backup Policy Query" `
        -Requirement "SOC 2 CC5.1 - Backup Configuration" `
        -Passed $false `
        -CurrentValue "Unable to query backup policy" `
        -ExpectedValue "Backup policy queryable" `
        -Remediation "Ensure Windows Server Backup cmdlets are available or use alternative backup solution"

    Write-Host "  [INFO] Unable to query Windows Backup policy (cmdlets may not be available)" -ForegroundColor Gray
}

# Check Volume Shadow Copy Service (VSS)
$vssService = Get-Service -Name "VSS" -ErrorAction SilentlyContinue

if ($vssService) {
    $vssRunning = $vssService.Status -eq 'Running'
    $vssAutomatic = $vssService.StartType -eq 'Manual' -or $vssService.StartType -eq 'Automatic'

    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Volume Shadow Copy Service (VSS)" `
        -Requirement "SOC 2 CC5.1 - Point-in-Time Recovery" `
        -Passed $vssAutomatic `
        -CurrentValue "Status: $($vssService.Status), StartType: $($vssService.StartType)" `
        -ExpectedValue "Manual or Automatic" `
        -Remediation "Set-Service VSS -StartupType Manual"

    if ($vssAutomatic) {
        Write-Host "  [PASS] Volume Shadow Copy service is properly configured" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Volume Shadow Copy service is $($vssService.StartType)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [ERROR] Volume Shadow Copy service not found" -ForegroundColor Red
}

# Check shadow copies on system volume
try {
    $shadowCopies = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop

    if ($shadowCopies) {
        $shadowCount = $shadowCopies.Count
        $hasShadowCopies = $shadowCount -gt 0

        # Get most recent shadow copy
        $mostRecent = $shadowCopies | Sort-Object InstallDate -Descending | Select-Object -First 1
        $mostRecentDate = if ($mostRecent) { $mostRecent.InstallDate.ToString("yyyy-MM-dd HH:mm") } else { "N/A" }

        Add-ComplianceCheck -Category "Backup and Recovery" `
            -Check "System Volume Shadow Copies" `
            -Requirement "SOC 2 CC5.1 - Recovery Points" `
            -Passed $hasShadowCopies `
            -CurrentValue "$shadowCount shadow copies (most recent: $mostRecentDate)" `
            -ExpectedValue "Shadow copies available" `
            -Remediation "Enable System Protection: Enable-ComputerRestore -Drive 'C:\' ; Checkpoint-Computer -Description 'Manual Restore Point'"

        if ($hasShadowCopies) {
            Write-Host "  [PASS] $shadowCount shadow copy/copies available (most recent: $mostRecentDate)" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] No shadow copies available" -ForegroundColor Yellow
        }
    } else {
        Add-ComplianceCheck -Category "Backup and Recovery" `
            -Check "System Volume Shadow Copies" `
            -Requirement "SOC 2 CC5.1 - Recovery Points" `
            -Passed $false `
            -CurrentValue "No shadow copies" `
            -ExpectedValue "Shadow copies available" `
            -Remediation "Enable System Protection: Enable-ComputerRestore -Drive 'C:\' ; Checkpoint-Computer -Description 'Restore Point'"

        Write-Host "  [WARN] No shadow copies available (System Protection may be disabled)" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  [INFO] Unable to query shadow copies" -ForegroundColor Gray
}

# Check System Protection status
try {
    # Check if system protection is enabled on C: drive
    $systemProtection = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($systemProtection) {
        Add-ComplianceCheck -Category "Backup and Recovery" `
            -Check "System Protection (Restore Points)" `
            -Requirement "SOC 2 CC5.1 - System Recovery" `
            -Passed $true `
            -CurrentValue "System restore points available" `
            -ExpectedValue "System Protection enabled" `
            -Remediation "System Protection is enabled"

        Write-Host "  [PASS] System Protection is enabled (restore points available)" -ForegroundColor Green
    } else {
        Add-ComplianceCheck -Category "Backup and Recovery" `
            -Check "System Protection (Restore Points)" `
            -Requirement "SOC 2 CC5.1 - System Recovery" `
            -Passed $false `
            -CurrentValue "No restore points available" `
            -ExpectedValue "System Protection enabled" `
            -Remediation "Enable-ComputerRestore -Drive 'C:\'; Checkpoint-Computer -Description 'Initial Restore Point'"

        Write-Host "  [WARN] System Protection may be disabled (no restore points)" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  [INFO] Unable to check System Protection status" -ForegroundColor Gray
}

# Check for backup age (if backup history is available)
try {
    # Try to get last backup via event log
    $backupEvents = Get-WinEvent -LogName "Microsoft-Windows-Backup" -MaxEvents 1 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 4 }  # Event ID 4 = Backup completed successfully

    if ($backupEvents) {
        $lastBackup = $backupEvents[0].TimeCreated
        $daysSinceBackup = (Get-Date) - $lastBackup
        $backupRecent = $daysSinceBackup.TotalDays -le 7

        Add-ComplianceCheck -Category "Backup and Recovery" `
            -Check "Recent Backup Completion" `
            -Requirement "HIPAA § 164.308(a)(7)(ii)(A) - Retrievable Backup" `
            -Passed $backupRecent `
            -CurrentValue "Last backup: $($lastBackup.ToString('yyyy-MM-dd HH:mm')) ($([Math]::Round($daysSinceBackup.TotalDays, 1)) days ago)" `
            -ExpectedValue "Backup within last 7 days" `
            -Remediation "Run backup: wbadmin start backup -backupTarget:<Target> -include:<Volumes>"

        if ($backupRecent) {
            Write-Host "  [PASS] Recent backup found: $($lastBackup.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] Last backup was $([Math]::Round($daysSinceBackup.TotalDays, 1)) days ago" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [INFO] No recent Windows Backup events found (verify alternative backup solution)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check backup history" -ForegroundColor Gray
}

# Check BitLocker recovery key backup
try {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeStatus -ne "FullyDecrypted" }

    if ($bitlockerVolumes) {
        $volumesWithRecovery = 0
        $totalEncrypted = $bitlockerVolumes.Count

        foreach ($volume in $bitlockerVolumes) {
            # Check if recovery key is backed up (has RecoveryPassword key protector)
            $recoveryProtector = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
            if ($recoveryProtector) {
                $volumesWithRecovery++
            }
        }

        $allHaveRecovery = $volumesWithRecovery -eq $totalEncrypted

        Add-ComplianceCheck -Category "Backup and Recovery" `
            -Check "BitLocker Recovery Key Backup" `
            -Requirement "HIPAA § 164.308(a)(7)(ii)(D) - Encryption Key Backup" `
            -Passed $allHaveRecovery `
            -CurrentValue "$volumesWithRecovery of $totalEncrypted encrypted volume(s) have recovery protectors" `
            -ExpectedValue "All encrypted volumes have recovery keys" `
            -Remediation "Backup BitLocker recovery key: manage-bde -protectors -add C: -RecoveryPassword"

        if ($allHaveRecovery) {
            Write-Host "  [PASS] All $totalEncrypted encrypted volume(s) have recovery keys" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] Only $volumesWithRecovery of $totalEncrypted encrypted volume(s) have recovery keys" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [INFO] No encrypted volumes found (BitLocker not in use)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check BitLocker recovery key status" -ForegroundColor Gray
}

# Check for File History (Windows 8+)
$fileHistoryService = Get-Service -Name "fhsvc" -ErrorAction SilentlyContinue

if ($fileHistoryService) {
    $fhRunning = $fileHistoryService.Status -eq 'Running'
    $fhAutomatic = $fileHistoryService.StartType -eq 'Manual' -or $fileHistoryService.StartType -eq 'Automatic'

    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "File History Service" `
        -Requirement "SOC 2 CC5.1 - User Data Backup" `
        -Passed $fhAutomatic `
        -CurrentValue "Status: $($fileHistoryService.Status), StartType: $($fileHistoryService.StartType)" `
        -ExpectedValue "Manual or Automatic" `
        -Remediation "File History service is available for user data backup"

    if ($fhAutomatic) {
        Write-Host "  [PASS] File History service is available" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] File History service status: $($fileHistoryService.Status)" -ForegroundColor Gray
    }

    # Try to check if File History is configured
    $fhConfig = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\FileHistory" -Name "Protected" -ErrorAction SilentlyContinue

    if ($fhConfig -and $fhConfig.Protected -eq 1) {
        Write-Host "  [INFO] File History is configured for current user" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] File History service not found" -ForegroundColor Gray
}

# Check for OneDrive backup status (known folder backup)
$oneDriveBackup = Get-ItemProperty -Path "HKCU:\Software\Microsoft\OneDrive\Accounts\*" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty "UserFolder" -ErrorAction SilentlyContinue

if ($oneDriveBackup) {
    Write-Host "  [INFO] OneDrive is configured (may provide cloud backup)" -ForegroundColor Gray
} else {
    Write-Host "  [INFO] OneDrive backup not configured" -ForegroundColor Gray
}

Write-Host ""
