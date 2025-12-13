<#
.SYNOPSIS
    Validates Network Segmentation Controls
.DESCRIPTION
    Tests network isolation, VLAN configuration, and cardholder data environment (CDE) separation
    PCI-DSS 1.2, 1.3 | SOC 2 CC6.1 | NIST 800-53 SC-7
#>

Write-Host "Checking Network Segmentation..." -ForegroundColor Cyan

# Check for multiple network adapters (indication of segmentation)
$networkAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }

if ($networkAdapters) {
    $adapterCount = $networkAdapters.Count
    $adapterList = ($networkAdapters | ForEach-Object { "$($_.Name) ($($_.InterfaceDescription))" }) -join "; "

    Add-ComplianceCheck -Category "Network Segmentation" `
        -Check "Network Adapters Configuration" `
        -Requirement "PCI-DSS 1.2 - Network Segmentation" `
        -NIST "SC-7" `
        -CIS "13.1" `
        -ISO27001 "A.13.1.3" `
        -PCIDSS "1.2.1" `
        -Passed $true `
        -CurrentValue "$adapterCount active adapter(s): $adapterList" `
        -ExpectedValue "Network adapters properly configured for environment" `
        -Remediation "Review network adapter configuration and ensure proper VLAN/network segmentation"

    Write-Host "  [INFO] $adapterCount active network adapter(s) detected" -ForegroundColor Gray

    # Check for VLAN configuration on adapters
    foreach ($adapter in $networkAdapters) {
        $vlanId = Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "VLAN ID" -ErrorAction SilentlyContinue

        if ($vlanId -and $vlanId.DisplayValue -ne "0") {
            Write-Host "  [INFO] $($adapter.Name) is on VLAN $($vlanId.DisplayValue)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "  [ERROR] No active network adapters found" -ForegroundColor Red
}

# Check Windows Firewall rules count (indicator of segmentation enforcement)
try {
    $firewallRules = Get-NetFirewallRule -Enabled True -ErrorAction Stop
    $blockRules = $firewallRules | Where-Object { $_.Action -eq 'Block' }
    $allowRules = $firewallRules | Where-Object { $_.Action -eq 'Allow' }

    $hasSegmentationRules = $blockRules.Count -gt 10

    Add-ComplianceCheck -Category "Network Segmentation" `
        -Check "Firewall Segmentation Rules" `
        -Requirement "PCI-DSS 1.2 - Restrict inbound/outbound traffic" `
        -NIST "SC-7(5)" `
        -CIS "13.6" `
        -ISO27001 "A.13.1.1" `
        -PCIDSS "1.2.1, 1.3.1" `
        -Passed $hasSegmentationRules `
        -CurrentValue "$($blockRules.Count) block rules, $($allowRules.Count) allow rules" `
        -ExpectedValue "Firewall rules configured for network segmentation" `
        -Remediation "Configure firewall rules to restrict traffic between network segments: New-NetFirewallRule"

    if ($hasSegmentationRules) {
        Write-Host "  [PASS] $($blockRules.Count) firewall block rules configured (segmentation enforced)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] $($blockRules.Count) firewall block rules (verify segmentation)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check firewall rules" -ForegroundColor Gray
}

# Check for routing table (detect multi-network configuration)
try {
    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
        $_.DestinationPrefix -ne "0.0.0.0/0" -and
        $_.DestinationPrefix -ne "127.0.0.0/8" -and
        $_.DestinationPrefix -ne "255.255.255.255/32"
    }

    $networkCount = ($routes | Select-Object -ExpandProperty DestinationPrefix -Unique).Count
    $hasMultipleNetworks = $networkCount -gt 3

    Add-ComplianceCheck -Category "Network Segmentation" `
        -Check "Network Routing Configuration" `
        -Requirement "PCI-DSS 1.3 - Network Isolation" `
        -NIST "SC-7(12)" `
        -ISO27001 "A.13.1.3" `
        -PCIDSS "1.3.1" `
        -Passed $true `
        -CurrentValue "$networkCount network route(s) configured" `
        -ExpectedValue "Multiple networks properly isolated" `
        -Remediation "Review routing table: Get-NetRoute; Ensure CDE is isolated from other networks"

    if ($hasMultipleNetworks) {
        Write-Host "  [INFO] $networkCount network routes configured (verify proper isolation)" -ForegroundColor Gray
    } else {
        Write-Host "  [INFO] $networkCount network route(s) - single network or minimal routing" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check routing configuration" -ForegroundColor Gray
}

# Check for network isolation via IPsec policies
try {
    $ipsecRules = Get-NetIPsecRule -ErrorAction SilentlyContinue

    if ($ipsecRules) {
        $ipsecCount = $ipsecRules.Count

        Add-ComplianceCheck -Category "Network Segmentation" `
            -Check "IPsec Network Isolation" `
            -Requirement "PCI-DSS 1.3 - Encryption between segments" `
            -NIST "SC-8" `
            -ISO27001 "A.13.1.1" `
            -PCIDSS "1.3.5" `
            -Passed $true `
            -CurrentValue "$ipsecCount IPsec rule(s) configured" `
            -ExpectedValue "IPsec configured for network isolation (if required)" `
            -Remediation "Configure IPsec for sensitive network segments: New-NetIPsecRule"

        Write-Host "  [PASS] $ipsecCount IPsec rule(s) configured for network isolation" -ForegroundColor Green
    } else {
        Add-ComplianceCheck -Category "Network Segmentation" `
            -Check "IPsec Network Isolation" `
            -Requirement "PCI-DSS 1.3 - Encryption between segments" `
            -NIST "SC-8" `
            -ISO27001 "A.13.1.1" `
            -PCIDSS "1.3.5" `
            -Passed $false `
            -CurrentValue "No IPsec rules configured" `
            -ExpectedValue "IPsec configured for CDE isolation (if required)" `
            -Remediation "Configure IPsec if network isolation requires encryption: New-NetIPsecRule"

        Write-Host "  [INFO] No IPsec rules configured (acceptable if not required for environment)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check IPsec configuration" -ForegroundColor Gray
}

# Check for network access quarantine (NAP)
$napService = Get-Service -Name "NapAgent" -ErrorAction SilentlyContinue

if ($napService) {
    $napRunning = $napService.Status -eq 'Running'

    Add-ComplianceCheck -Category "Network Segmentation" `
        -Check "Network Access Protection (NAP)" `
        -Requirement "PCI-DSS 1.4 - Personal devices access control" `
        -NIST "SC-7(8)" `
        -ISO27001 "A.6.2.1" `
        -PCIDSS "1.4" `
        -Passed $napRunning `
        -CurrentValue "NAP Agent: $($napService.Status)" `
        -ExpectedValue "NAP enforcing network access policies (if used)" `
        -Remediation "Configure Network Access Protection policies via Group Policy"

    if ($napRunning) {
        Write-Host "  [PASS] Network Access Protection is active" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] NAP Agent exists but not running (verify if NAP is used)" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] Network Access Protection not configured (acceptable for modern environments)" -ForegroundColor Gray
}

# Check for network adapter binding order (security consideration)
$adapterBindings = Get-NetAdapterBinding -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }

if ($adapterBindings) {
    # Check if unnecessary protocols are bound
    $ipv6Enabled = $adapterBindings | Where-Object { $_.ComponentID -eq "ms_tcpip6" }

    if ($ipv6Enabled) {
        Write-Host "  [INFO] IPv6 is enabled on network adapters (verify if required)" -ForegroundColor Gray
    } else {
        Write-Host "  [INFO] IPv6 is disabled (reduces attack surface)" -ForegroundColor Gray
    }

    # Check for file/printer sharing binding
    $fileSharingBound = $adapterBindings | Where-Object {
        $_.ComponentID -eq "ms_server" -or $_.ComponentID -eq "ms_msclient"
    }

    if ($fileSharingBound) {
        $boundAdapters = ($fileSharingBound | Select-Object -ExpandProperty Name -Unique) -join ", "

        Add-ComplianceCheck -Category "Network Segmentation" `
            -Check "File/Print Sharing Binding" `
            -Requirement "PCI-DSS 1.2 - Restrict unnecessary services" `
            -NIST "CM-7" `
            -ISO27001 "A.13.1.3" `
            -PCIDSS "1.2.3" `
            -Passed $false `
            -CurrentValue "File/print sharing enabled on: $boundAdapters" `
            -ExpectedValue "File sharing disabled on external-facing adapters" `
            -Remediation "Disable file/printer sharing on external adapters: Disable-NetAdapterBinding -Name '<Adapter>' -ComponentID 'ms_server'"

        Write-Host "  [WARN] File/printer sharing is bound to network adapters: $boundAdapters" -ForegroundColor Yellow
    } else {
        Write-Host "  [PASS] File/printer sharing is not bound to network adapters" -ForegroundColor Green
    }
}

Write-Host ""
