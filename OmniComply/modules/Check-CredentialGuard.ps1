<#
.SYNOPSIS
    Validates Credential Guard Configuration
.DESCRIPTION
    Tests Credential Guard status for credential theft protection
    SOC 2 CC6.1, CC6.7 | HIPAA § 164.312(a)(2)(i)
    Note: Requires Windows Enterprise or Education edition
#>

Write-Host "Checking Credential Guard..." -ForegroundColor Cyan

try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

    if ($deviceGuard) {
        # Check if Credential Guard is running
        $credGuardRunning = $deviceGuard.SecurityServicesRunning -contains 1

        Add-ComplianceCheck -Category "Credential Guard" `
            -Check "Credential Guard Running" `
            -Requirement "SOC 2 CC6.7 - Credential Protection" `
            -NIST "IA-5(1), SC-12" `
            -CIS "9.3" `
            -ISO27001 "A.9.4.3, A.10.1.2" `
            -Passed $credGuardRunning `
            -CurrentValue $(if ($credGuardRunning) { "Running" } else { "Not running" }) `
            -ExpectedValue "Running (Enterprise/Education only)" `
            -Remediation "Enable via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security"

        if ($credGuardRunning) {
            Write-Host "  [PASS] Credential Guard is running" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] Credential Guard is not running (requires Windows Enterprise/Education)" -ForegroundColor Gray
        }

        # Check if Credential Guard is configured
        $credGuardConfigured = $deviceGuard.SecurityServicesConfigured -contains 1

        Add-ComplianceCheck -Category "Credential Guard" `
            -Check "Credential Guard Configured" `
            -Requirement "SOC 2 CC6.7 - Credential Protection Configuration" `
            -NIST "IA-5(1), SC-12" `
            -CIS "9.3" `
            -ISO27001 "A.9.4.3, A.10.1.2" `
            -Passed $credGuardConfigured `
            -CurrentValue $(if ($credGuardConfigured) { "Configured" } else { "Not configured" }) `
            -ExpectedValue "Configured (Enterprise/Education only)" `
            -Remediation "Enable via Group Policy or Intune configuration"

        if ($credGuardConfigured) {
            Write-Host "  [PASS] Credential Guard is configured" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] Credential Guard is not configured" -ForegroundColor Gray
        }

        # Check Windows edition compatibility
        $osInfo = Get-CimInstance Win32_OperatingSystem
        $isEnterprise = $osInfo.Caption -match "Enterprise|Education"

        Add-ComplianceCheck -Category "Credential Guard" `
            -Check "Windows Edition Support" `
            -Requirement "SOC 2 CC6.7 - Platform Compatibility" `
            -NIST "SC-12" `
            -CIS "9.3" `
            -ISO27001 "A.9.4.3" `
            -Passed $isEnterprise `
            -CurrentValue $osInfo.Caption `
            -ExpectedValue "Windows Enterprise or Education" `
            -Remediation "Upgrade to Windows Enterprise or Education edition"

        if ($isEnterprise) {
            Write-Host "  [PASS] Windows edition supports Credential Guard" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] Windows edition does not support Credential Guard (Pro: $($osInfo.Caption))" -ForegroundColor Gray
        }

        # Additional Credential Guard details
        if ($credGuardRunning) {
            # Check UEFI lock status
            $configLock = $deviceGuard.ConfigurationStatus
            if ($configLock) {
                $lockStatus = switch ($configLock) {
                    0 { "Not configured" }
                    1 { "Configured" }
                    2 { "Locked (UEFI)" }
                    default { "Unknown" }
                }

                $isLocked = $configLock -eq 2

                Add-ComplianceCheck -Category "Credential Guard" `
                    -Check "Credential Guard UEFI Lock" `
                    -Requirement "SOC 2 CC6.1 - Tamper Protection" `
                    -NIST "SC-12, SI-7" `
                    -CIS "9.3" `
                    -ISO27001 "A.9.4.3, A.14.2.5" `
                    -Passed $isLocked `
                    -CurrentValue $lockStatus `
                    -ExpectedValue "Locked (UEFI)" `
                    -Remediation "Configure with UEFI lock via Group Policy"

                if ($isLocked) {
                    Write-Host "  [PASS] Credential Guard is UEFI locked (tamper-proof)" -ForegroundColor Green
                } else {
                    Write-Host "  [INFO] Credential Guard lock status: $lockStatus" -ForegroundColor Gray
                }
            }
        }
    }
} catch {
    Add-ComplianceCheck -Category "Credential Guard" `
        -Check "Credential Guard Query" `
        -Requirement "SOC 2 CC6.7 - Credential Protection" `
        -NIST "IA-5(1), SC-12" `
        -CIS "9.3" `
        -ISO27001 "A.9.4.3" `
        -Passed $false `
        -CurrentValue "Unable to query: $($_.Exception.Message)" `
        -ExpectedValue "Queryable on Enterprise/Education" `
        -Remediation "Ensure Windows 10/11 Enterprise or Education with VBS support"

    Write-Host "  [INFO] Credential Guard not available (requires Enterprise/Education)" -ForegroundColor Gray
}

# Check LSA Protection (related security feature)
$lsaProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue

if ($lsaProtection) {
    $lsaEnabled = $lsaProtection.RunAsPPL -eq 1

    Add-ComplianceCheck -Category "Credential Guard" `
        -Check "LSA Protection (Credential Hardening)" `
        -Requirement "SOC 2 CC6.7 - Additional Credential Protection" `
        -NIST "IA-5(1), SC-12" `
        -CIS "9.3" `
        -ISO27001 "A.9.4.3" `
        -Passed $lsaEnabled `
        -CurrentValue $(if ($lsaEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1"

    if ($lsaEnabled) {
        Write-Host "  [PASS] LSA Protection is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] LSA Protection is disabled (recommended for credential hardening)" -ForegroundColor Gray
    }
} else {
    Add-ComplianceCheck -Category "Credential Guard" `
        -Check "LSA Protection (Credential Hardening)" `
        -Requirement "SOC 2 CC6.7 - Additional Credential Protection" `
        -NIST "IA-5(1), SC-12" `
        -CIS "9.3" `
        -ISO27001 "A.9.4.3" `
        -Passed $false `
        -CurrentValue "Not configured" `
        -ExpectedValue "Enabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord"

    Write-Host "  [INFO] LSA Protection not configured (recommended for credential hardening)" -ForegroundColor Gray
}

# Check for cached credentials
$cachedLogons = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -ErrorAction SilentlyContinue

if ($cachedLogons) {
    $cacheCount = [int]$cachedLogons.CachedLogonsCount
    $cacheSecure = $cacheCount -le 2

    Add-ComplianceCheck -Category "Credential Guard" `
        -Check "Cached Logon Credentials Limit" `
        -Requirement "SOC 2 CC6.7 - Credential Storage" `
        -NIST "IA-5(13)" `
        -CIS "5.3" `
        -ISO27001 "A.9.4.3" `
        -Passed $cacheSecure `
        -CurrentValue "$cacheCount cached logons allowed" `
        -ExpectedValue "2 or fewer" `
        -Remediation "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options"

    if ($cacheSecure) {
        Write-Host "  [PASS] Cached logons limited to $cacheCount" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Cached logons set to $cacheCount (recommend 2 or fewer)" -ForegroundColor Yellow
    }
}

Write-Host ""
