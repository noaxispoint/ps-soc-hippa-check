<#
.SYNOPSIS
    Validates Backup and Recovery Controls
.DESCRIPTION
    Tests system restore, volume shadow copy, backup configuration, and recovery capabilities
    GDPR Article 32.1.c (Resilience and Recovery) | SOC 2 CC7.5 | HIPAA § 164.308(a)(7)(ii)(A)
#>

Write-Host "Checking Backup and Recovery Controls..." -ForegroundColor Cyan

# Check System Restore Status
try {
    $systemProtection = Get-ComputerRestorePoint -ErrorAction Stop | Select-Object -First 1
    $hasRestorePoints = $null -ne $systemProtection

    # Check if System Protection is enabled on C: drive
    $systemDrive = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='C:'" -ErrorAction SilentlyContinue
    if ($systemDrive) {
        $protectionEnabled = (vssadmin list shadowstorage 2>&1) -match "C:"
    } else {
        $protectionEnabled = $false
    }

    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "System Restore Enabled" `
        -Requirement "GDPR Article 32.1.c - System Resilience and Recovery" `
        -NIST "CP-9, CP-10" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -GDPR "Article 32.1.c" `
        -SOX "ITGC-06" `
        -Passed $hasRestorePoints `
        -CurrentValue $(if ($hasRestorePoints) { "Enabled with restore points" } else { "No restore points found" }) `
        -ExpectedValue "Enabled with recent restore points" `
        -Remediation "Enable-ComputerRestore -Drive 'C:\'; Checkpoint-Computer -Description 'Manual Restore Point'" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > System > System Restore > <strong>Turn off System Restore</strong> = <code>Disabled</code> (to keep System Restore enabled)"

    if ($hasRestorePoints) {
        Write-Host "  [PASS] System Restore is enabled with restore points available" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] No system restore points found" -ForegroundColor Yellow
    }
} catch {
    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "System Restore Enabled" `
        -Requirement "GDPR Article 32.1.c - System Resilience and Recovery" `
        -NIST "CP-9, CP-10" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -GDPR "Article 32.1.c" `
        -SOX "ITGC-06" `
        -Passed $false `
        -CurrentValue "Unable to determine or disabled" `
        -ExpectedValue "Enabled with recent restore points" `
        -Remediation "Enable-ComputerRestore -Drive 'C:\'; Checkpoint-Computer -Description 'Manual Restore Point'"

    Write-Host "  [WARN] System Restore status could not be determined (may be disabled)" -ForegroundColor Yellow
}

# Check Volume Shadow Copy Service
$vssService = Get-Service -Name VSS -ErrorAction SilentlyContinue

if ($vssService) {
    $vssRunning = $vssService.Status -eq 'Running'
    $vssAutomatic = $vssService.StartType -eq 'Manual' -or $vssService.StartType -eq 'Automatic'

    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Volume Shadow Copy Service (VSS)" `
        -Requirement "SOC 2 CC7.5 - Backup Infrastructure" `
        -NIST "CP-9" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -GDPR "Article 32.1.c" `
        -SOX "ITGC-06" `
        -Passed $vssAutomatic `
        -CurrentValue "Status: $($vssService.Status), StartType: $($vssService.StartType)" `
        -ExpectedValue "Running or Manual (starts on demand)" `
        -Remediation "Set-Service -Name VSS -StartupType Manual" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Services > <strong>Volume Shadow Copy</strong> = <code>Manual</code> (automatic startup when needed)"

    if ($vssAutomatic) {
        Write-Host "  [PASS] Volume Shadow Copy Service is properly configured ($($vssService.StartType))" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Volume Shadow Copy Service startup type: $($vssService.StartType)" -ForegroundColor Red
    }
} else {
    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Volume Shadow Copy Service (VSS)" `
        -Requirement "SOC 2 CC7.5 - Backup Infrastructure" `
        -NIST "CP-9" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -GDPR "Article 32.1.c" `
        -Passed $false `
        -CurrentValue "Service not found" `
        -ExpectedValue "Running or Manual" `
        -Remediation "Verify VSS service is installed"

    Write-Host "  [FAIL] Volume Shadow Copy Service not found" -ForegroundColor Red
}

# Check for Shadow Copies on system drive
try {
    $shadowCopies = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction Stop | Where-Object { $_.VolumeName -like "*C:*" }
    $hasShadowCopies = ($shadowCopies | Measure-Object).Count -gt 0

    if ($hasShadowCopies) {
        $shadowCount = ($shadowCopies | Measure-Object).Count
        $newestShadow = $shadowCopies | Sort-Object InstallDate -Descending | Select-Object -First 1
        $daysSinceBackup = ((Get-Date) - [Management.ManagementDateTimeConverter]::ToDateTime($newestShadow.InstallDate)).Days
        $recentBackup = $daysSinceBackup -le 7
    } else {
        $shadowCount = 0
        $daysSinceBackup = $null
        $recentBackup = $false
    }

    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Recent Shadow Copies Available" `
        -Requirement "GDPR Article 32.1.c - Timely Recovery Capability" `
        -NIST "CP-9" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -GDPR "Article 32.1.c" `
        -HIPAA "§ 164.308(a)(7)(ii)(A)" `
        -Passed $recentBackup `
        -CurrentValue $(if ($hasShadowCopies) { "$shadowCount shadow copies (newest: $daysSinceBackup days ago)" } else { "No shadow copies" }) `
        -ExpectedValue "Recent shadow copies (within 7 days)" `
        -Remediation "Configure automatic shadow copies via System Properties > System Protection" `
        -IntuneRecommendation "Use Microsoft 365 Backup or third-party backup solutions deployed via Intune for enterprise backup management"

    if ($recentBackup) {
        Write-Host "  [PASS] Recent shadow copies available: $shadowCount copies" -ForegroundColor Green
    } elseif ($hasShadowCopies) {
        Write-Host "  [WARN] Shadow copies exist but oldest: $daysSinceBackup days" -ForegroundColor Yellow
    } else {
        Write-Host "  [WARN] No shadow copies found on C: drive" -ForegroundColor Yellow
    }
} catch {
    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Recent Shadow Copies Available" `
        -Requirement "GDPR Article 32.1.c - Timely Recovery Capability" `
        -NIST "CP-9" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -GDPR "Article 32.1.c" `
        -HIPAA "§ 164.308(a)(7)(ii)(A)" `
        -Passed $false `
        -CurrentValue "Unable to query" `
        -ExpectedValue "Recent shadow copies (within 7 days)" `
        -Remediation "Configure System Protection and verify VSS service"

    Write-Host "  [WARN] Could not query shadow copies" -ForegroundColor Yellow
}

# Check Windows Backup (wbadmin) - Server or Pro editions
try {
    $wbadminStatus = wbadmin get status 2>&1
    $backupConfigured = $wbadminStatus -match "No backup" -eq $false

    # Try to get backup summary
    $backupSummary = wbadmin get versions -backuptarget:C: 2>&1 | Out-String
    $hasBackups = $backupSummary -notmatch "No backups" -and $backupSummary -match "Version identifier"

    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Windows Backup Configured" `
        -Requirement "HIPAA § 164.308(a)(7)(ii)(A) - Data Backup Plan" `
        -NIST "CP-9" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -GDPR "Article 32.1.c" `
        -HIPAA "§ 164.308(a)(7)(ii)(A)" `
        -SOX "ITGC-06" `
        -Passed $hasBackups `
        -CurrentValue $(if ($hasBackups) { "Configured with backup history" } else { "No backup history found" }) `
        -ExpectedValue "Configured with regular backups" `
        -Remediation "Configure Windows Backup via wbadmin or Windows Server Backup MMC" `
        -IntuneRecommendation "Deploy enterprise backup solution (Azure Backup, Veeam, etc.) via Intune application deployment or configuration scripts"

    if ($hasBackups) {
        Write-Host "  [PASS] Windows Backup is configured with backup history" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Windows Backup not configured (use enterprise backup solution)" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [INFO] Windows Backup (wbadmin) not available or not configured" -ForegroundColor Gray
}

# Check for Recovery Partition
try {
    $partitions = Get-Partition -ErrorAction Stop
    $recoveryPartition = $partitions | Where-Object { $_.Type -eq 'Recovery' }
    $hasRecoveryPartition = $null -ne $recoveryPartition

    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "Recovery Partition Present" `
        -Requirement "SOC 2 CC7.5 - System Recovery Capability" `
        -NIST "CP-10" `
        -CIS "10.5" `
        -ISO27001 "A.17.1.3" `
        -GDPR "Article 32.1.c" `
        -Passed $hasRecoveryPartition `
        -CurrentValue $(if ($hasRecoveryPartition) { "Present" } else { "Not found" }) `
        -ExpectedValue "Recovery partition present" `
        -Remediation "Recovery partition should be created during Windows installation" `
        -IntuneRecommendation "Ensure Windows devices are deployed with recovery partitions via Windows Autopilot or custom imaging"

    if ($hasRecoveryPartition) {
        Write-Host "  [PASS] Recovery partition is present" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] No recovery partition found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [INFO] Could not query partition information" -ForegroundColor Gray
}

# Check File History Service (Windows 10/11 backup)
$fileHistoryService = Get-Service -Name fhsvc -ErrorAction SilentlyContinue

if ($fileHistoryService) {
    $fhRunning = $fileHistoryService.Status -eq 'Running'
    $fhAutomatic = $fileHistoryService.StartType -eq 'Manual' -or $fileHistoryService.StartType -eq 'Automatic'

    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "File History Service" `
        -Requirement "SOC 2 CC7.5 - User Data Backup" `
        -NIST "CP-9" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -GDPR "Article 32.1.c" `
        -Passed $fhAutomatic `
        -CurrentValue "Status: $($fileHistoryService.Status), StartType: $($fileHistoryService.StartType)" `
        -ExpectedValue "Manual or Automatic" `
        -Remediation "Configure File History via Settings > Update & Security > Backup" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > File History, or deploy OneDrive Known Folder Move for user data protection"

    if ($fhAutomatic) {
        Write-Host "  [PASS] File History service is available ($($fileHistoryService.StartType))" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] File History service: $($fileHistoryService.StartType)" -ForegroundColor Gray
    }
}

# Check OneDrive Backup Status (Known Folder Move)
$oneDriveBackup = Get-ItemProperty -Path "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1" -Name "UserFolder" -ErrorAction SilentlyContinue

if ($oneDriveBackup) {
    Add-ComplianceCheck -Category "Backup and Recovery" `
        -Check "OneDrive Known Folder Move (KFM)" `
        -Requirement "SOC 2 CC7.5 - User Data Protection" `
        -NIST "CP-9" `
        -CIS "10.5" `
        -ISO27001 "A.12.3.1" `
        -GDPR "Article 32.1.c" `
        -Passed $true `
        -CurrentValue "Configured" `
        -ExpectedValue "Configured for user data protection" `
        -Remediation "Configure via OneDrive settings or Group Policy" `
        -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > OneDrive > <strong>Silently move Windows known folders to OneDrive</strong> = <code>Enabled</code> with tenant ID"

    Write-Host "  [PASS] OneDrive Known Folder Move appears configured" -ForegroundColor Green
} else {
    Write-Host "  [INFO] OneDrive Known Folder Move not detected (user-level protection)" -ForegroundColor Gray
}

Write-Host ""
