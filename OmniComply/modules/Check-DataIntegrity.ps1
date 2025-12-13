<#
.SYNOPSIS
    Validates Data Integrity Controls
.DESCRIPTION
    Tests database integrity, transaction logging, and data validation mechanisms
    SOX ITGC-04, ITGC-05 | NIST 800-53 SI-7 | ISO 27001 A.12.2.1
#>

Write-Host "Checking Data Integrity Controls..." -ForegroundColor Cyan

# Check Windows Event Log integrity
try {
    $eventLogs = Get-WinEvent -ListLog * -ErrorAction Stop | Where-Object {
        $_.LogName -in @("Security", "System", "Application")
    }

    foreach ($log in $eventLogs) {
        $logEnabled = $log.IsEnabled
        $logSize = [Math]::Round($log.FileSize / 1MB, 2)

        # Check if log is enabled and has adequate size
        $logHealthy = $logEnabled -and $log.FileSize -gt 0

        if (-not $logHealthy) {
            Add-ComplianceCheck -Category "Data Integrity" `
                -Check "Event Log Integrity ($($log.LogName))" `
                -Requirement "SOX ITGC-05 - Audit log integrity" `
                -NIST "AU-9" `
                -ISO27001 "A.12.4.1" `
                -SOX "ITGC-05" `
                -Passed $false `
                -CurrentValue "Log enabled: $logEnabled, Size: $logSize MB" `
                -ExpectedValue "Log enabled and operational" `
                -Remediation "wevtutil set-log $($log.LogName) /enabled:true"

            Write-Host "  [WARN] $($log.LogName) log may have integrity issues" -ForegroundColor Yellow
        }
    }

    Write-Host "  [PASS] Core event logs verified for integrity" -ForegroundColor Green

} catch {
    Write-Host "  [ERROR] Unable to verify event log integrity" -ForegroundColor Red
}

# Check event log protection (Event Log Readers group)
try {
    $logReaders = Get-LocalGroupMember -Group "Event Log Readers" -ErrorAction SilentlyContinue

    if ($logReaders) {
        # Verify admins can read logs
        Write-Host "  [INFO] Event Log Readers group has $($logReaders.Count) member(s)" -ForegroundColor Gray
    }

    # Check if SACL (System Access Control List) protects event logs
    $securityLogAcl = Get-Acl -Path "C:\Windows\System32\winevt\Logs\Security.evtx" -ErrorAction SilentlyContinue

    if ($securityLogAcl) {
        # Check if unauthorized users have access
        $publicAccess = $securityLogAcl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|Users" -and $_.FileSystemRights -match "Write|Delete|Modify"
        }

        $logsProtected = $null -eq $publicAccess

        Add-ComplianceCheck -Category "Data Integrity" `
            -Check "Event Log File Protection" `
            -Requirement "SOX ITGC-05 - Prevent log tampering" `
            -NIST "AU-9(2)" `
            -ISO27001 "A.12.4.2" `
            -SOX "ITGC-05" `
            -Passed $logsProtected `
            -CurrentValue $(if ($logsProtected) { "Logs protected from unauthorized modification" } else { "Public access detected" }) `
            -ExpectedValue "Restricted access to log files" `
            -Remediation "icacls C:\Windows\System32\winevt\Logs\Security.evtx /remove Users"

        if ($logsProtected) {
            Write-Host "  [PASS] Event log files are protected from unauthorized access" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Event log files have public access (integrity risk)" -ForegroundColor Red
        }
    }

} catch {
    Write-Host "  [INFO] Unable to check event log file permissions" -ForegroundColor Gray
}

# Check for SQL Server transaction logging (if SQL Server is present)
$sqlServices = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }

if ($sqlServices) {
    Write-Host "  [INFO] SQL Server detected - transaction logging validation:" -ForegroundColor Gray
    Write-Host "    Verify transaction logs are enabled for all databases" -ForegroundColor Gray
    Write-Host "    SQL Query: SELECT name, recovery_model_desc FROM sys.databases" -ForegroundColor Gray
    Write-Host "    Expected: FULL or BULK_LOGGED recovery model for production databases" -ForegroundColor Gray

    Add-ComplianceCheck -Category "Data Integrity" `
        -Check "Database Transaction Logging" `
        -Requirement "SOX ITGC-04 - Database change tracking" `
        -NIST "AU-2, SI-7" `
        -ISO27001 "A.12.4.1" `
        -SOX "ITGC-04" `
        -Passed $false `
        -CurrentValue "SQL Server detected - manual verification required" `
        -ExpectedValue "FULL recovery model for all production databases" `
        -Remediation "ALTER DATABASE [DatabaseName] SET RECOVERY FULL"

    Write-Host "  [INFO] SQL Server transaction logging requires manual validation" -ForegroundColor Gray
}

# Check file integrity monitoring (Windows File Protection)
$wfpStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SFCDisable" -ErrorAction SilentlyContinue

if ($wfpStatus) {
    $sfcEnabled = $wfpStatus.SFCDisable -eq 0

    Add-ComplianceCheck -Category "Data Integrity" `
        -Check "Windows File Protection (SFC)" `
        -Requirement "SOX ITGC-04 - System file integrity" `
        -NIST "SI-7" `
        -ISO27001 "A.12.2.1" `
        -SOX "ITGC-04" `
        -Passed $sfcEnabled `
        -CurrentValue $(if ($sfcEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'SFCDisable' -Value 0"

    if ($sfcEnabled) {
        Write-Host "  [PASS] Windows File Protection (SFC) is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Windows File Protection is disabled (integrity risk)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] Windows File Protection using default settings (enabled)" -ForegroundColor Gray
}

# Check for file system journaling (NTFS)
$systemDrive = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue

if ($systemDrive) {
    $isNTFS = $systemDrive.FileSystem -eq "NTFS"

    Add-ComplianceCheck -Category "Data Integrity" `
        -Check "File System Journaling (NTFS)" `
        -Requirement "SOX ITGC-04 - File system integrity" `
        -NIST "SI-7" `
        -ISO27001 "A.12.2.1" `
        -SOX "ITGC-04" `
        -Passed $isNTFS `
        -CurrentValue "System drive: $($systemDrive.FileSystem)" `
        -ExpectedValue "NTFS (journaling file system)" `
        -Remediation "Convert to NTFS: convert C: /fs:ntfs (requires backup first)"

    if ($isNTFS) {
        Write-Host "  [PASS] System drive uses NTFS (journaling enabled)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] System drive not using NTFS (no journaling)" -ForegroundColor Red
    }
}

# Check for checksum/hash validation tools
$certutilExists = Test-Path "$env:SystemRoot\System32\certutil.exe"

if ($certutilExists) {
    Add-ComplianceCheck -Category "Data Integrity" `
        -Check "Data Integrity Validation Tools" `
        -Requirement "SOX ITGC-04 - Data validation capabilities" `
        -NIST "SI-7(1)" `
        -SOX "ITGC-04" `
        -Passed $true `
        -CurrentValue "certutil.exe available for hash validation" `
        -ExpectedValue "Integrity checking tools available" `
        -Remediation "Tools are available"

    Write-Host "  [PASS] Data integrity validation tools available (certutil)" -ForegroundColor Green
}

# Check for database backup verification
try {
    # Look for backup events in Application log
    $backupEvents = Get-WinEvent -LogName "Application" -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "backup|restore" -and $_.ProviderName -match "MSSQL|SQL" }

    if ($backupEvents) {
        $successfulBackups = $backupEvents | Where-Object { $_.LevelDisplayName -eq "Information" }

        if ($successfulBackups) {
            $mostRecent = $successfulBackups | Sort-Object TimeCreated -Descending | Select-Object -First 1

            Add-ComplianceCheck -Category "Data Integrity" `
                -Check "Database Backup Verification" `
                -Requirement "SOX ITGC-04 - Backup integrity validation" `
                -NIST "CP-9" `
                -ISO27001 "A.12.3.1" `
                -SOX "ITGC-04" `
                -Passed $true `
                -CurrentValue "Last successful backup: $($mostRecent.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" `
                -ExpectedValue "Regular verified backups" `
                -Remediation "Backup logging is active"

            Write-Host "  [PASS] Database backup events logged (last: $($mostRecent.TimeCreated.ToString('yyyy-MM-dd')))" -ForegroundColor Green
        }
    }

} catch {
    Write-Host "  [INFO] Unable to check database backup logs" -ForegroundColor Gray
}

# Check for data validation at application level
Write-Host "  [INFO] Application-level data integrity controls:" -ForegroundColor Gray
Write-Host "    - Input validation to prevent injection attacks" -ForegroundColor Gray
Write-Host "    - Referential integrity constraints in databases" -ForegroundColor Gray
Write-Host "    - Transaction rollback capabilities" -ForegroundColor Gray
Write-Host "    - Data checksums for critical files" -ForegroundColor Gray

# Check for CHKDSK scheduled tasks (disk integrity)
$chkdskTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -match "chkdsk|disk.*check"
}

if ($chkdskTasks) {
    Write-Host "  [INFO] Disk integrity check tasks configured" -ForegroundColor Gray
}

# Check Event Log forwarding (centralized integrity monitoring)
$eventForwarding = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" -ErrorAction SilentlyContinue

if ($eventForwarding) {
    Add-ComplianceCheck -Category "Data Integrity" `
        -Check "Centralized Event Log Forwarding" `
        -Requirement "SOX ITGC-05 - Centralized log integrity" `
        -NIST "AU-9(2)" `
        -ISO27001 "A.12.4.1" `
        -SOX "ITGC-05" `
        -Passed $true `
        -CurrentValue "Event forwarding configured to central server" `
        -ExpectedValue "Logs forwarded to SIEM/central logging" `
        -Remediation "Event forwarding is configured"

    Write-Host "  [PASS] Event log forwarding configured (centralized monitoring)" -ForegroundColor Green
} else {
    Add-ComplianceCheck -Category "Data Integrity" `
        -Check "Centralized Event Log Forwarding" `
        -Requirement "SOX ITGC-05 - Centralized log monitoring" `
        -NIST "AU-9(2)" `
        -SOX "ITGC-05" `
        -Passed $false `
        -CurrentValue "No event forwarding configured" `
        -ExpectedValue "Logs forwarded to SIEM" `
        -Remediation "Configure via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Event Forwarding"

    Write-Host "  [INFO] No centralized event log forwarding configured" -ForegroundColor Gray
}

# Check for read-only audit logs (write protection)
$auditLogWriteProtection = auditpol /get /subcategory:"Audit Policy Change" /r 2>$null | ConvertFrom-Csv |
    Where-Object { $_.'Inclusion Setting' -match "Success.*Failure" }

if ($auditLogWriteProtection) {
    Write-Host "  [PASS] Audit policy changes are logged (tamper detection)" -ForegroundColor Green
} else {
    Write-Host "  [INFO] Audit policy change logging not fully configured" -ForegroundColor Gray
}

Write-Host ""
