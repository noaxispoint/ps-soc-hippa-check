<#
.SYNOPSIS
    Validates Database Security Controls
.DESCRIPTION
    Tests SQL Server security settings, encryption, and access controls
    PCI-DSS 2.2, 3.4, 8.2 | HIPAA § 164.312(a)(1) | NIST 800-53 SC-28
#>

Write-Host "Checking Database Security..." -ForegroundColor Cyan

# Check for SQL Server services
$sqlServices = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue

if ($sqlServices) {
    $runningSqlServices = $sqlServices | Where-Object { $_.Status -eq 'Running' }

    if ($runningSqlServices) {
        Add-ComplianceCheck -Category "Database Security" `
            -Check "SQL Server Services Running" `
            -Requirement "PCI-DSS 2.2 - Database server hardening" `
            -NIST "CM-6" `
            -ISO27001 "A.12.6.1" `
            -PCIDSS "2.2.1" `
            -Passed $true `
            -CurrentValue "$($runningSqlServices.Count) SQL Server service(s) running" `
            -ExpectedValue "SQL Server services configured securely" `
            -Remediation "Review SQL Server security configuration and hardening"

        Write-Host "  [INFO] $($runningSqlServices.Count) SQL Server service(s) detected and running" -ForegroundColor Gray

        foreach ($sqlService in $runningSqlServices) {
            Write-Host "    - $($sqlService.DisplayName) [$($sqlService.Status)]" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [INFO] SQL Server services found but not running" -ForegroundColor Gray
    }

} else {
    Add-ComplianceCheck -Category "Database Security" `
        -Check "SQL Server Installation" `
        -Requirement "PCI-DSS 2.2 - Database presence check" `
        -NIST "CM-6" `
        -PCIDSS "2.2" `
        -Passed $true `
        -CurrentValue "No SQL Server services detected" `
        -ExpectedValue "N/A - No database services to secure" `
        -Remediation "N/A"

    Write-Host "  [INFO] No SQL Server services detected on this system" -ForegroundColor Gray
}

# Check SQL Server ports (should not be default 1433)
try {
    $tcpConnections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq 1433 }

    if ($tcpConnections) {
        Add-ComplianceCheck -Category "Database Security" `
            -Check "SQL Server Default Port" `
            -Requirement "PCI-DSS 2.2 - Change default ports" `
            -NIST "SC-7" `
            -ISO27001 "A.13.1.1" `
            -PCIDSS "2.2.3" `
            -Passed $false `
            -CurrentValue "SQL Server listening on default port 1433" `
            -ExpectedValue "SQL Server on non-default port" `
            -Remediation "Change SQL Server port via SQL Server Configuration Manager"

        Write-Host "  [WARN] SQL Server is listening on default port 1433 (security risk)" -ForegroundColor Yellow
    } else {
        # Check if SQL is running on a custom port
        $sqlProcessPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.OwningProcess -in (Get-Process -Name "sqlservr" -ErrorAction SilentlyContinue).Id }

        if ($sqlProcessPorts) {
            $customPorts = ($sqlProcessPorts | Select-Object -ExpandProperty LocalPort -Unique) -join ", "

            Add-ComplianceCheck -Category "Database Security" `
                -Check "SQL Server Custom Port" `
                -Requirement "PCI-DSS 2.2 - Non-default configuration" `
                -NIST "SC-7" `
                -ISO27001 "A.13.1.1" `
                -PCIDSS "2.2.3" `
                -Passed $true `
                -CurrentValue "SQL Server on custom port(s): $customPorts" `
                -ExpectedValue "Non-default port configuration" `
                -Remediation "SQL Server is properly configured on custom port(s)"

            Write-Host "  [PASS] SQL Server is using custom port(s): $customPorts" -ForegroundColor Green
        }
    }

} catch {
    Write-Host "  [INFO] Unable to check SQL Server port configuration" -ForegroundColor Gray
}

# Check SQL Server Browser service (should be disabled for security)
$sqlBrowser = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue

if ($sqlBrowser) {
    $browserDisabled = $sqlBrowser.StartType -eq 'Disabled' -or $sqlBrowser.Status -ne 'Running'

    Add-ComplianceCheck -Category "Database Security" `
        -Check "SQL Server Browser Service" `
        -Requirement "PCI-DSS 2.2 - Disable unnecessary services" `
        -NIST "CM-7" `
        -ISO27001 "A.12.6.2" `
        -PCIDSS "2.2.2" `
        -Passed $browserDisabled `
        -CurrentValue "Browser service: $($sqlBrowser.Status), StartType: $($sqlBrowser.StartType)" `
        -ExpectedValue "Disabled (unless specifically required)" `
        -Remediation "Stop-Service SQLBrowser; Set-Service SQLBrowser -StartupType Disabled"

    if ($browserDisabled) {
        Write-Host "  [PASS] SQL Server Browser service is disabled/stopped (secure)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] SQL Server Browser service is enabled (verify if required)" -ForegroundColor Yellow
    }
}

# Check for SQL Server authentication mode (Windows Auth preferred)
# This requires registry check as it's stored in SQL Server registry
$sqlInstances = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match "MSSQL" }

if ($sqlInstances) {
    foreach ($instance in $sqlInstances) {
        $instanceName = $instance.PSChildName

        # Try to get LoginMode
        $loginMode = Get-ItemProperty -Path "$($instance.PSPath)\MSSQLServer" -Name "LoginMode" -ErrorAction SilentlyContinue

        if ($loginMode) {
            # LoginMode: 1 = Windows Auth only, 2 = Mixed Mode
            $windowsAuthOnly = $loginMode.LoginMode -eq 1

            Add-ComplianceCheck -Category "Database Security" `
                -Check "SQL Server Authentication Mode ($instanceName)" `
                -Requirement "PCI-DSS 8.2 - Windows Authentication preferred" `
                -NIST "IA-2(1)" `
                -ISO27001 "A.9.4.2" `
                -PCIDSS "8.2.1" `
                -Passed $windowsAuthOnly `
                -CurrentValue $(if ($windowsAuthOnly) { "Windows Authentication Only" } else { "Mixed Mode (SQL + Windows)" }) `
                -ExpectedValue "Windows Authentication Only" `
                -Remediation "Change to Windows Auth in SQL Server Management Studio > Server Properties > Security"

            if ($windowsAuthOnly) {
                Write-Host "  [PASS] $instanceName uses Windows Authentication Only (secure)" -ForegroundColor Green
            } else {
                Write-Host "  [WARN] $instanceName uses Mixed Mode authentication (verify if SQL auth is required)" -ForegroundColor Yellow
            }
        }
    }
}

# Check for SQL Server Transparent Data Encryption (TDE) registry keys
# Note: Full TDE status requires SQL query, but we can check if feature is available
$sqlTdeFeature = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\ConfigurationState" -ErrorAction SilentlyContinue

if ($sqlTdeFeature) {
    Write-Host "  [INFO] SQL Server Enterprise features detected (TDE capable)" -ForegroundColor Gray
    Write-Host "  [INFO] Verify TDE is enabled for databases containing sensitive data via SQL query:" -ForegroundColor Gray
    Write-Host "    SELECT DB_NAME(database_id), encryption_state FROM sys.dm_database_encryption_keys" -ForegroundColor Gray
}

# Check Windows folder permissions for SQL Server data directories
# Common paths to check
$sqlDataPaths = @(
    "C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA",
    "D:\SQLData",
    "E:\SQLData"
)

foreach ($path in $sqlDataPaths) {
    $dataFolders = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue

    if ($dataFolders) {
        foreach ($folder in $dataFolders) {
            $acl = Get-Acl -Path $folder.FullName -ErrorAction SilentlyContinue

            if ($acl) {
                # Check if Everyone or Users group has access
                $everyoneAccess = $acl.Access | Where-Object { $_.IdentityReference -match "Everyone|Users" }

                if ($everyoneAccess) {
                    Add-ComplianceCheck -Category "Database Security" `
                        -Check "SQL Data Directory Permissions ($($folder.Name))" `
                        -Requirement "PCI-DSS 3.4 - Restrict file system access" `
                        -NIST "AC-3" `
                        -ISO27001 "A.9.1.1" `
                        -PCIDSS "3.4.2" `
                        -Passed $false `
                        -CurrentValue "Folder accessible by Everyone/Users group" `
                        -ExpectedValue "Access restricted to SQL Server service account and admins only" `
                        -Remediation "Remove Everyone/Users permissions: icacls '$($folder.FullName)' /remove Users"

                    Write-Host "  [WARN] SQL data directory has broad permissions: $($folder.FullName)" -ForegroundColor Yellow
                } else {
                    Write-Host "  [PASS] SQL data directory has restricted permissions: $($folder.FullName)" -ForegroundColor Green
                }
            }
        }
    }
}

# Check for SQL Server audit logging
$sqlAuditService = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Running' }

if ($sqlAuditService) {
    Write-Host "  [INFO] SQL Server is running - verify auditing is configured:" -ForegroundColor Gray
    Write-Host "    - C2 Audit Mode or SQL Server Audit should be enabled" -ForegroundColor Gray
    Write-Host "    - Check via: SELECT * FROM sys.server_audits" -ForegroundColor Gray

    # Check Windows Event Logs for SQL Server security events
    $sqlSecurityEvents = Get-WinEvent -LogName "Application" -MaxEvents 10 -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match "MSSQL" -and $_.LevelDisplayName -eq "Error" }

    if ($sqlSecurityEvents) {
        Write-Host "  [INFO] Found $($sqlSecurityEvents.Count) recent SQL Server error events in Application log" -ForegroundColor Gray
    }
}

# Check for database encryption at rest (BitLocker on SQL data volumes)
try {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction Stop

    foreach ($volume in $bitlockerVolumes) {
        # Check if this volume might contain SQL data
        if ($volume.MountPoint -match "[D-Z]:" -and $volume.VolumeType -eq 'Data') {
            $volumeEncrypted = $volume.VolumeStatus -eq 'FullyEncrypted'

            Add-ComplianceCheck -Category "Database Security" `
                -Check "Database Volume Encryption ($($volume.MountPoint))" `
                -Requirement "PCI-DSS 3.4 - Encryption at rest" `
                -NIST "SC-28" `
                -ISO27001 "A.10.1.1" `
                -PCIDSS "3.4.1" `
                -Passed $volumeEncrypted `
                -CurrentValue "Volume $($volume.MountPoint): $($volume.VolumeStatus)" `
                -ExpectedValue "FullyEncrypted" `
                -Remediation "Enable-BitLocker -MountPoint '$($volume.MountPoint)' -EncryptionMethod XtsAes256"

            if ($volumeEncrypted) {
                Write-Host "  [PASS] Data volume $($volume.MountPoint) is encrypted" -ForegroundColor Green
            } else {
                Write-Host "  [WARN] Data volume $($volume.MountPoint) is not encrypted: $($volume.VolumeStatus)" -ForegroundColor Yellow
            }
        }
    }

} catch {
    Write-Host "  [INFO] Unable to check BitLocker status for data volumes" -ForegroundColor Gray
}

Write-Host ""
