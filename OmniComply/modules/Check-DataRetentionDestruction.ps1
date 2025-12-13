<#
.SYNOPSIS
    Validates Data Retention and Secure Destruction Controls
.DESCRIPTION
    Tests file retention policies, secure deletion tools, and data lifecycle management
    PCI-DSS 3.1, 9.8 | HIPAA § 164.310(d)(2) | NIST 800-53 MP-6
#>

Write-Host "Checking Data Retention and Destruction..." -ForegroundColor Cyan

# Check for File Server Resource Manager (FSRM) - used for retention policies
$fsrmService = Get-Service -Name "SrmSvc" -ErrorAction SilentlyContinue

if ($fsrmService) {
    $fsrmRunning = $fsrmService.Status -eq 'Running'

    Add-ComplianceCheck -Category "Data Retention" `
        -Check "File Server Resource Manager Service" `
        -Requirement "PCI-DSS 3.1 - Data retention policies" `
        -NIST "SI-12" `
        -ISO27001 "A.8.3.2" `
        -PCIDSS "3.1" `
        -Passed $fsrmRunning `
        -CurrentValue "FSRM Service: $($fsrmService.Status)" `
        -ExpectedValue "Running (if file retention policies are enforced)" `
        -Remediation "Start-Service SrmSvc; Set-Service SrmSvc -StartupType Automatic"

    if ($fsrmRunning) {
        Write-Host "  [PASS] File Server Resource Manager is running (retention policies can be enforced)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] FSRM is installed but not running (verify if file retention is managed differently)" -ForegroundColor Gray
    }

} else {
    Write-Host "  [INFO] File Server Resource Manager not installed (acceptable if not a file server)" -ForegroundColor Gray
}

# Check for Recycle Bin configuration (data retention)
$recycleBinSize = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket" -ErrorAction SilentlyContinue

if ($recycleBinSize) {
    Write-Host "  [INFO] Recycle Bin is configured (provides temporary data recovery)" -ForegroundColor Gray
}

# Check for Volume Shadow Copy retention settings
try {
    $shadowStorage = vssadmin list shadowstorage 2>$null

    if ($shadowStorage) {
        Write-Host "  [INFO] Volume Shadow Copy storage configured (point-in-time data retention)" -ForegroundColor Gray

        # Parse shadow storage to check retention
        if ($shadowStorage -match "Maximum Shadow Copy Storage space: (\S+)") {
            $maxStorage = $matches[1]
            Write-Host "    Maximum shadow storage: $maxStorage" -ForegroundColor Gray
        }
    }

} catch {
    Write-Host "  [INFO] Unable to query shadow copy storage" -ForegroundColor Gray
}

# Check for secure deletion tools (cipher.exe, sdelete.exe)
$cipherExists = Test-Path "$env:SystemRoot\System32\cipher.exe"

if ($cipherExists) {
    Add-ComplianceCheck -Category "Data Destruction" `
        -Check "Secure File Deletion Tool (cipher.exe)" `
        -Requirement "PCI-DSS 9.8 - Secure media destruction" `
        -NIST "MP-6, MP-6(1)" `
        -ISO27001 "A.8.3.2, A.11.2.7" `
        -PCIDSS "9.8.1" `
        -Passed $true `
        -CurrentValue "cipher.exe available for secure wiping" `
        -ExpectedValue "Secure deletion tools available" `
        -Remediation "cipher.exe is built into Windows"

    Write-Host "  [PASS] Secure deletion tool (cipher.exe) is available" -ForegroundColor Green
} else {
    Write-Host "  [WARN] cipher.exe not found (unexpected)" -ForegroundColor Yellow
}

# Check for SDelete (Sysinternals secure delete tool)
$sdeleteLocations = @(
    "C:\Windows\System32\sdelete.exe",
    "C:\Windows\SysWOW64\sdelete.exe",
    "C:\Tools\sdelete.exe",
    "C:\Program Files\Sysinternals\sdelete.exe"
)

$sdeleteFound = $false

foreach ($location in $sdeleteLocations) {
    if (Test-Path $location) {
        $sdeleteFound = $true
        Write-Host "  [INFO] SDelete (Sysinternals) found at: $location" -ForegroundColor Gray
        break
    }
}

if ($sdeleteFound) {
    Add-ComplianceCheck -Category "Data Destruction" `
        -Check "SDelete (Sysinternals) Tool" `
        -Requirement "PCI-DSS 9.8 - DOD 5220.22-M compliant wiping" `
        -NIST "MP-6(2)" `
        -PCIDSS "9.8.1" `
        -Passed $true `
        -CurrentValue "SDelete available for DOD-compliant secure deletion" `
        -ExpectedValue "Enterprise secure deletion tool deployed" `
        -Remediation "SDelete is installed"

    Write-Host "  [PASS] SDelete tool is available for secure file deletion" -ForegroundColor Green
}

# Check for data retention group policy settings
$retentionPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataRetention" -ErrorAction SilentlyContinue

if ($retentionPolicy) {
    Write-Host "  [INFO] Data retention policies configured via Group Policy" -ForegroundColor Gray
} else {
    Add-ComplianceCheck -Category "Data Retention" `
        -Check "Data Retention Policy Configuration" `
        -Requirement "PCI-DSS 3.1 - Retention policy defined and enforced" `
        -NIST "SI-12" `
        -ISO27001 "A.8.3.2" `
        -PCIDSS "3.1" `
        -Passed $false `
        -CurrentValue "No centralized retention policy detected" `
        -ExpectedValue "Documented and enforced retention policies" `
        -Remediation "Document data retention requirements and configure via Group Policy or FSRM"

    Write-Host "  [INFO] No centralized data retention policy detected (verify documentation exists)" -ForegroundColor Gray
}

# Check for automatic file cleanup (Disk Cleanup, Storage Sense)
$storageSense = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -ErrorAction SilentlyContinue

if ($storageSense -and $storageSense.01) {
    $storageSenseEnabled = $storageSense.01 -eq 1

    Add-ComplianceCheck -Category "Data Retention" `
        -Check "Storage Sense Automatic Cleanup" `
        -Requirement "PCI-DSS 3.1 - Automatic data lifecycle management" `
        -NIST "SI-12" `
        -PCIDSS "3.1" `
        -Passed $storageSenseEnabled `
        -CurrentValue $(if ($storageSenseEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled (for automated cleanup)" `
        -Remediation "Enable Storage Sense: Settings > System > Storage > Storage Sense"

    if ($storageSenseEnabled) {
        Write-Host "  [PASS] Storage Sense automatic cleanup is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Storage Sense is disabled (manual cleanup required)" -ForegroundColor Gray
    }
}

# Check for cardholder data search (PCI-DSS specific)
# Look for common patterns that might indicate cardholder data storage
Write-Host "  [INFO] Cardholder data detection (PCI-DSS 3.2):" -ForegroundColor Gray
Write-Host "    Periodic scans should be performed to detect PAN storage outside CDE" -ForegroundColor Gray
Write-Host "    Use specialized PAN discovery tools or scripts" -ForegroundColor Gray

# Check Event Logs for data deletion events
try {
    $deletionEvents = Get-WinEvent -LogName "Security" -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 4663 -and $_.Message -match "DELETE" }

    if ($deletionEvents) {
        $deleteCount = $deletionEvents.Count

        Add-ComplianceCheck -Category "Data Destruction" `
            -Check "File Deletion Audit Logging" `
            -Requirement "PCI-DSS 10.2 - Audit file deletions" `
            -NIST "AU-2, AU-12" `
            -ISO27001 "A.12.4.1" `
            -PCIDSS "10.2.7" `
            -Passed $true `
            -CurrentValue "$deleteCount file deletion events logged recently" `
            -ExpectedValue "File deletions are audited" `
            -Remediation "Ensure Object Access auditing is enabled for file deletions"

        Write-Host "  [PASS] $deleteCount file deletion events logged (auditing active)" -ForegroundColor Green
    } else {
        Add-ComplianceCheck -Category "Data Destruction" `
            -Check "File Deletion Audit Logging" `
            -Requirement "PCI-DSS 10.2 - Audit file deletions" `
            -NIST "AU-2" `
            -PCIDSS "10.2.7" `
            -Passed $false `
            -CurrentValue "No file deletion events logged" `
            -ExpectedValue "File deletions audited" `
            -Remediation "Enable Object Access auditing: auditpol /set /subcategory:`"File System`" /success:enable /failure:enable"

        Write-Host "  [INFO] No recent file deletion audit events (verify auditing is configured)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check deletion audit logs" -ForegroundColor Gray
}

# Check for scheduled cleanup tasks
$cleanupTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -match "Cleanup|Delete|Purge|Retention"
}

if ($cleanupTasks) {
    $activeCleanup = $cleanupTasks | Where-Object { $_.State -ne 'Disabled' }

    Add-ComplianceCheck -Category "Data Retention" `
        -Check "Scheduled Data Cleanup Tasks" `
        -Requirement "PCI-DSS 3.1 - Automated retention enforcement" `
        -NIST "SI-12" `
        -PCIDSS "3.1" `
        -Passed ($activeCleanup.Count -gt 0) `
        -CurrentValue "$($activeCleanup.Count) active cleanup task(s)" `
        -ExpectedValue "Automated cleanup tasks configured" `
        -Remediation "Create scheduled tasks for data retention enforcement"

    if ($activeCleanup.Count -gt 0) {
        Write-Host "  [PASS] $($activeCleanup.Count) scheduled cleanup task(s) configured" -ForegroundColor Green

        foreach ($task in $activeCleanup | Select-Object -First 5) {
            Write-Host "    - $($task.TaskName)" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [INFO] No active cleanup tasks found" -ForegroundColor Gray
    }
}

# Check BitLocker key escrow (secure key destruction capability)
try {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction Stop

    $volumesWithRecovery = 0
    $totalEncrypted = 0

    foreach ($volume in $bitlockerVolumes) {
        if ($volume.VolumeStatus -ne "FullyDecrypted") {
            $totalEncrypted++

            # Check if recovery key protector exists
            $recoveryProtector = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
            if ($recoveryProtector) {
                $volumesWithRecovery++
            }
        }
    }

    if ($totalEncrypted -gt 0) {
        Write-Host "  [INFO] $volumesWithRecovery of $totalEncrypted encrypted volume(s) have recovery keys" -ForegroundColor Gray
        Write-Host "    Ensure recovery keys are securely backed up and can be destroyed when volumes are decommissioned" -ForegroundColor Gray
    }

} catch {
    # BitLocker not available
}

# Check for disk sanitization documentation
Write-Host "  [INFO] Media sanitization requirements (PCI-DSS 9.8):" -ForegroundColor Gray
Write-Host "    - Shredding, degaussing, or secure wiping required for media disposal" -ForegroundColor Gray
Write-Host "    - Maintain documented procedures and disposal records" -ForegroundColor Gray

Write-Host ""
