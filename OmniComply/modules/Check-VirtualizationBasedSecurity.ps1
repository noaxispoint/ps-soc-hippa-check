<#
.SYNOPSIS
    Validates Virtualization-Based Security (VBS) Configuration
.DESCRIPTION
    Tests Core Isolation, Memory Integrity (HVCI), and VBS status
    SOC 2 CC6.1, CC7.1 | HIPAA § 164.312(a)(1)
#>

Write-Host "Checking Virtualization-Based Security..." -ForegroundColor Cyan

# Check if VBS is supported and enabled
try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

    if ($deviceGuard) {
        # Check VBS running status
        $vbsRunning = $deviceGuard.VirtualizationBasedSecurityStatus -eq 2

        $vbsStatus = switch ($deviceGuard.VirtualizationBasedSecurityStatus) {
            0 { "Not enabled" }
            1 { "Enabled but not running" }
            2 { "Enabled and running" }
            default { "Unknown" }
        }

        Add-ComplianceCheck -Category "Virtualization-Based Security" `
            -Check "VBS (Virtualization-Based Security) Status" `
            -Requirement "SOC 2 CC6.1 - Advanced Hardware Security" `
            -Passed $vbsRunning `
            -CurrentValue $vbsStatus `
            -ExpectedValue "Enabled and running" `
            -Remediation "Enable via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security"

        if ($vbsRunning) {
            Write-Host "  [PASS] VBS is enabled and running" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] VBS status: $vbsStatus (requires compatible hardware)" -ForegroundColor Gray
        }

        # Check HVCI (Hypervisor-Protected Code Integrity / Memory Integrity)
        $hvciRunning = $deviceGuard.SecurityServicesRunning -contains 2

        Add-ComplianceCheck -Category "Virtualization-Based Security" `
            -Check "Memory Integrity (HVCI) Running" `
            -Requirement "SOC 2 CC7.1 - Kernel Protection" `
            -Passed $hvciRunning `
            -CurrentValue $(if ($hvciRunning) { "Running" } else { "Not running" }) `
            -ExpectedValue "Running" `
            -Remediation "Enable via Windows Security > Device Security > Core isolation > Memory integrity"

        if ($hvciRunning) {
            Write-Host "  [PASS] Memory Integrity (HVCI) is running" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] Memory Integrity (HVCI) is not running (requires compatible drivers)" -ForegroundColor Gray
        }

        # Check HVCI configured
        $hvciConfigured = $deviceGuard.SecurityServicesConfigured -contains 2

        Add-ComplianceCheck -Category "Virtualization-Based Security" `
            -Check "Memory Integrity (HVCI) Configured" `
            -Requirement "SOC 2 CC7.1 - Kernel Protection" `
            -Passed $hvciConfigured `
            -CurrentValue $(if ($hvciConfigured) { "Configured" } else { "Not configured" }) `
            -ExpectedValue "Configured" `
            -Remediation "Enable via Windows Security > Device Security > Core isolation > Memory integrity"

        if ($hvciConfigured) {
            Write-Host "  [PASS] Memory Integrity (HVCI) is configured" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] Memory Integrity (HVCI) is not configured" -ForegroundColor Gray
        }

        # Check Required Security Properties
        if ($deviceGuard.RequiredSecurityProperties) {
            $hasHypervisor = $deviceGuard.RequiredSecurityProperties -contains 1
            $hasVBS = $deviceGuard.RequiredSecurityProperties -contains 2

            if ($hasHypervisor -and $hasVBS) {
                Write-Host "  [PASS] Required security properties configured (Hypervisor + VBS)" -ForegroundColor Green
            }
        }

        # Check Available Security Properties
        if ($deviceGuard.AvailableSecurityProperties) {
            $availableProps = $deviceGuard.AvailableSecurityProperties
            $propsText = ($availableProps | ForEach-Object {
                switch ($_) {
                    1 { "Hypervisor" }
                    2 { "VBS" }
                    3 { "VBS with UEFI Lock" }
                    default { "Unknown($_)" }
                }
            }) -join ", "

            Add-ComplianceCheck -Category "Virtualization-Based Security" `
                -Check "Hardware Security Capabilities" `
                -Requirement "SOC 2 CC6.1 - Platform Security" `
                -Passed ($availableProps.Count -ge 2) `
                -CurrentValue $propsText `
                -ExpectedValue "Hypervisor and VBS support" `
                -Remediation "Hardware must support virtualization extensions (Intel VT-x/AMD-V) and UEFI"

            if ($availableProps.Count -ge 2) {
                Write-Host "  [PASS] Hardware supports advanced security: $propsText" -ForegroundColor Green
            } else {
                Write-Host "  [INFO] Available security properties: $propsText" -ForegroundColor Gray
            }
        }
    }
} catch {
    Add-ComplianceCheck -Category "Virtualization-Based Security" `
        -Check "VBS Query Status" `
        -Requirement "SOC 2 CC6.1 - Virtualization-Based Security" `
        -Passed $false `
        -CurrentValue "Unable to query: $($_.Exception.Message)" `
        -ExpectedValue "VBS supported and queryable" `
        -Remediation "Ensure Windows 10/11 Enterprise or Pro with compatible hardware"

    Write-Host "  [INFO] VBS not available or not supported on this system" -ForegroundColor Gray
}

# Check System Guard Secure Launch (if available)
try {
    $systemGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

    if ($systemGuard.SystemGuardStatus) {
        $secureBootEnabled = $systemGuard.SystemGuardStatus -eq 2

        Add-ComplianceCheck -Category "Virtualization-Based Security" `
            -Check "System Guard Secure Launch" `
            -Requirement "SOC 2 CC6.1 - Boot Security" `
            -Passed $secureBootEnabled `
            -CurrentValue $(switch ($systemGuard.SystemGuardStatus) { 0 { "Not configured" } 1 { "Configured" } 2 { "Running" } default { "Unknown" } }) `
            -ExpectedValue "Running" `
            -Remediation "Requires compatible hardware with System Guard support"

        if ($secureBootEnabled) {
            Write-Host "  [PASS] System Guard Secure Launch is running" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] System Guard Secure Launch not running (requires specific hardware)" -ForegroundColor Gray
        }
    }
} catch {
    # System Guard not available - this is informational
    Write-Host "  [INFO] System Guard Secure Launch not available on this system" -ForegroundColor Gray
}

# Check Kernel DMA Protection
$dmaProtection = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue

if ($dmaProtection -and $null -ne $dmaProtection.KernelDMAProtectionStatus) {
    $dmaEnabled = $dmaProtection.KernelDMAProtectionStatus -eq 2

    $dmaStatus = switch ($dmaProtection.KernelDMAProtectionStatus) {
        0 { "Not supported" }
        1 { "Supported but not enabled" }
        2 { "Enabled" }
        default { "Unknown" }
    }

    Add-ComplianceCheck -Category "Virtualization-Based Security" `
        -Check "Kernel DMA Protection" `
        -Requirement "SOC 2 CC6.1 - DMA Attack Prevention" `
        -Passed $dmaEnabled `
        -CurrentValue $dmaStatus `
        -ExpectedValue "Enabled" `
        -Remediation "Enable in UEFI/BIOS settings (if supported)"

    if ($dmaEnabled) {
        Write-Host "  [PASS] Kernel DMA Protection is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Kernel DMA Protection: $dmaStatus" -ForegroundColor Gray
    }
}

Write-Host ""
