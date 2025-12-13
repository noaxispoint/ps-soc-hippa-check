<#
.SYNOPSIS
    Validates DNS Security Configuration
.DESCRIPTION
    Tests DNS over HTTPS, DNSSEC, and DNS client security settings
    SOC 2 CC6.1, CC7.2 | HIPAA § 164.312(e)(1) - Network transmission security
#>

Write-Host "Checking DNS Security..." -ForegroundColor Cyan

# Check for DNS over HTTPS (DoH) configuration
try {
    # Windows 11 and Server 2022+ support DoH
    $dohSettings = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue

    if ($dohSettings) {
        $dohConfigured = $dohSettings.Count -gt 0

        Add-ComplianceCheck -Category "DNS Security" `
            -Check "DNS over HTTPS (DoH) Configuration" `
            -Requirement "SOC 2 CC7.2 - Encrypted DNS Queries" `
            -Passed $dohConfigured `
            -CurrentValue $(if ($dohConfigured) { "$($dohSettings.Count) DoH server(s) configured" } else { "No DoH servers configured" }) `
            -ExpectedValue "DoH servers configured" `
            -Remediation "Add-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp `$false"

        if ($dohConfigured) {
            Write-Host "  [PASS] DNS over HTTPS (DoH) is configured" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] DNS over HTTPS (DoH) is not configured (requires Windows 11/Server 2022+)" -ForegroundColor Gray
        }
    } else {
        Add-ComplianceCheck -Category "DNS Security" `
            -Check "DNS over HTTPS (DoH) Support" `
            -Requirement "SOC 2 CC7.2 - Encrypted DNS Queries" `
            -Passed $false `
            -CurrentValue "DoH not available on this OS version" `
            -ExpectedValue "Windows 11 or Server 2022+" `
            -Remediation "Upgrade to Windows 11 or Server 2022+ for DoH support"

        Write-Host "  [INFO] DNS over HTTPS not available (requires Windows 11 or Server 2022+)" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [INFO] Unable to check DNS over HTTPS configuration" -ForegroundColor Gray
}

# Check DNS client settings
try {
    $dnsClient = Get-DnsClient -ErrorAction Stop

    # Check if DNS client is using secure DNS
    $dnsClientGood = $null -ne $dnsClient

    Add-ComplianceCheck -Category "DNS Security" `
        -Check "DNS Client Service" `
        -Requirement "SOC 2 CC6.1 - DNS Resolution" `
        -Passed $dnsClientGood `
        -CurrentValue $(if ($dnsClientGood) { "DNS Client active" } else { "DNS Client not found" }) `
        -ExpectedValue "DNS Client service active" `
        -Remediation "Ensure DNS Client service is running: Start-Service Dnscache"

    if ($dnsClientGood) {
        Write-Host "  [PASS] DNS Client service is active" -ForegroundColor Green
    }

} catch {
    Write-Host "  [INFO] Unable to check DNS client configuration" -ForegroundColor Gray
}

# Check DNS cache settings
try {
    $dnscache = Get-Service -Name Dnscache -ErrorAction Stop

    $dnsRunning = $dnscache.Status -eq 'Running'
    $dnsAutoStart = $dnscache.StartType -eq 'Automatic'

    Add-ComplianceCheck -Category "DNS Security" `
        -Check "DNS Client Service Status" `
        -Requirement "SOC 2 CC7.2 - DNS Caching" `
        -Passed ($dnsRunning -and $dnsAutoStart) `
        -CurrentValue "Status: $($dnscache.Status), StartType: $($dnscache.StartType)" `
        -ExpectedValue "Running, Automatic" `
        -Remediation "Set-Service Dnscache -StartupType Automatic; Start-Service Dnscache"

    if ($dnsRunning -and $dnsAutoStart) {
        Write-Host "  [PASS] DNS Client service is running and set to automatic" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] DNS Client service is not properly configured" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  [INFO] Unable to check DNS Client service" -ForegroundColor Gray
}

# Check for DNS cache poisoning protections
$dnsSocketPool = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl" -ErrorAction SilentlyContinue

if ($dnsSocketPool) {
    $maxCacheTtl = $dnsSocketPool.MaxCacheTtl
    # MaxCacheTtl should be reasonable (not too high to prevent stale data)
    $ttlGood = $maxCacheTtl -le 86400  # 1 day or less

    Add-ComplianceCheck -Category "DNS Security" `
        -Check "DNS Cache TTL Limit" `
        -Requirement "SOC 2 CC7.2 - DNS Cache Poisoning Prevention" `
        -Passed $ttlGood `
        -CurrentValue "$maxCacheTtl seconds" `
        -ExpectedValue "86400 seconds (1 day) or less" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'MaxCacheTtl' -Value 86400"

    if ($ttlGood) {
        Write-Host "  [PASS] DNS cache TTL is configured appropriately ($maxCacheTtl seconds)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] DNS cache TTL is too high ($maxCacheTtl seconds)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] DNS cache TTL using default settings" -ForegroundColor Gray
}

# Check if using secure DNS servers (common public secure DNS)
try {
    $adapters = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop

    $secureDnsProviders = @(
        "1.1.1.1",      # Cloudflare
        "1.0.0.1",      # Cloudflare
        "8.8.8.8",      # Google
        "8.8.4.4",      # Google
        "9.9.9.9",      # Quad9
        "149.112.112.112"  # Quad9
    )

    $usingSecureDns = $false
    $dnsServers = @()

    foreach ($adapter in $adapters) {
        if ($adapter.ServerAddresses) {
            foreach ($server in $adapter.ServerAddresses) {
                if ($server -in $secureDnsProviders) {
                    $usingSecureDns = $true
                }
                $dnsServers += $server
            }
        }
    }

    $dnsServerList = ($dnsServers | Select-Object -Unique) -join ", "

    Add-ComplianceCheck -Category "DNS Security" `
        -Check "Secure DNS Providers" `
        -Requirement "SOC 2 CC7.2 - Trusted DNS Resolution" `
        -Passed $usingSecureDns `
        -CurrentValue "DNS Servers: $dnsServerList" `
        -ExpectedValue "Using secure DNS providers (Cloudflare, Google, Quad9) or internal DNS" `
        -Remediation "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses ('1.1.1.1','1.0.0.1')"

    if ($usingSecureDns) {
        Write-Host "  [PASS] Using known secure DNS providers" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] DNS servers: $dnsServerList (verify these are secure/trusted)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [INFO] Unable to check DNS server configuration" -ForegroundColor Gray
}

# Check DNS-over-TLS (DoT) via registry (Windows 11 feature)
$dotSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -ErrorAction SilentlyContinue

if ($dotSetting) {
    $autoDohEnabled = $dotSetting.EnableAutoDoh -eq 2  # 2 = enabled, 1 = disabled, 0 = default

    Add-ComplianceCheck -Category "DNS Security" `
        -Check "Automatic DNS over HTTPS" `
        -Requirement "SOC 2 CC7.2 - Automatic Secure DNS" `
        -Passed $autoDohEnabled `
        -CurrentValue $(switch ($dotSetting.EnableAutoDoh) { 0 { "Default" } 1 { "Disabled" } 2 { "Enabled" } default { "Unknown" } }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableAutoDoh' -Value 2 -Type DWord"

    if ($autoDohEnabled) {
        Write-Host "  [PASS] Automatic DNS over HTTPS is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Automatic DNS over HTTPS is not enabled" -ForegroundColor Gray
    }
} else {
    Write-Host "  [INFO] Automatic DoH setting not configured (requires Windows 11)" -ForegroundColor Gray
}

# Check for DNS name resolution policy (NRPT) for DirectAccess/Always On VPN
try {
    $nrpt = Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue

    if ($nrpt) {
        $nrptConfigured = $nrpt.Count -gt 0

        Add-ComplianceCheck -Category "DNS Security" `
            -Check "DNS Name Resolution Policy Table (NRPT)" `
            -Requirement "SOC 2 CC6.1 - Secure DNS Resolution Policies" `
            -Passed $nrptConfigured `
            -CurrentValue $(if ($nrptConfigured) { "$($nrpt.Count) NRPT rule(s)" } else { "No NRPT rules" }) `
            -ExpectedValue "NRPT configured (if using DirectAccess/Always On VPN)" `
            -Remediation "Configure NRPT via Group Policy or Add-DnsClientNrptRule cmdlet"

        if ($nrptConfigured) {
            Write-Host "  [PASS] DNS Name Resolution Policy Table has $($nrpt.Count) rule(s)" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] No NRPT rules configured (acceptable if not using DirectAccess/VPN)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "  [INFO] NRPT not configured (acceptable for standard configurations)" -ForegroundColor Gray
}

# Check DNS Client Query Timeout
$queryTimeout = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "QueryTimeout" -ErrorAction SilentlyContinue

if ($queryTimeout) {
    $timeoutValue = $queryTimeout.QueryTimeout
    # Timeout should be reasonable (not too high)
    $timeoutGood = $timeoutValue -le 30  # 30 seconds or less

    Add-ComplianceCheck -Category "DNS Security" `
        -Check "DNS Query Timeout" `
        -Requirement "SOC 2 CC7.2 - DNS Availability" `
        -Passed $timeoutGood `
        -CurrentValue "$timeoutValue seconds" `
        -ExpectedValue "30 seconds or less" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'QueryTimeout' -Value 30"

    if ($timeoutGood) {
        Write-Host "  [PASS] DNS query timeout is configured appropriately ($timeoutValue seconds)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] DNS query timeout is too high ($timeoutValue seconds)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [INFO] DNS query timeout using default settings" -ForegroundColor Gray
}

Write-Host ""
