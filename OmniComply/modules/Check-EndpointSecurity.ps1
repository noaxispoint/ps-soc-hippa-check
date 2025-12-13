<#
.SYNOPSIS
    Validates Endpoint Security Controls
.DESCRIPTION
    Tests antivirus, firewall, and security software status
    SOC 2 CC7.1, CC7.2 | HIPAA § 164.308(a)(5)(ii)(B)
#>

Write-Host "Checking Endpoint Security..." -ForegroundColor Cyan

# Check Windows Defender Antivirus status
$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

if ($defenderStatus) {
    # Real-time protection
    $rtpEnabled = $defenderStatus.RealTimeProtectionEnabled
    
    Add-ComplianceCheck -Category "Endpoint Security" `
        -Check "Real-Time Protection" `
        -Requirement "SOC 2 CC7.1 / HIPAA § 164.308(a)(5)(ii)(B)" `
        -Passed $rtpEnabled `
        -CurrentValue $(if ($rtpEnabled) { "Enabled" } else { "Disabled" }) `
        -ExpectedValue "Enabled" `
        -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"
    
    if ($rtpEnabled) {
        Write-Host "  [PASS] Real-time protection is enabled" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Real-time protection is disabled" -ForegroundColor Red
    }
    
    # Antivirus signatures
    $signaturesAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
    $signaturesRecent = $signaturesAge.TotalDays -le 7
    
    Add-ComplianceCheck -Category "Endpoint Security" `
        -Check "Antivirus Signature Age" `
        -Requirement "SOC 2 CC7.1 / HIPAA § 164.308(a)(5)(ii)(B)" `
        -Passed $signaturesRecent `
        -CurrentValue "$([Math]::Round($signaturesAge.TotalDays, 1)) days old" `
        -ExpectedValue "Updated within 7 days" `
        -Remediation "Update-MpSignature"
    
    if ($signaturesRecent) {
        Write-Host "  [PASS] Antivirus signatures updated $([Math]::Round($signaturesAge.TotalDays, 1)) days ago" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Antivirus signatures are $([Math]::Round($signaturesAge.TotalDays, 1)) days old" -ForegroundColor Red
    }
}

# Check Windows Firewall status
$firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue

if ($firewallProfiles) {
    foreach ($profile in $firewallProfiles) {
        $enabled = $profile.Enabled
        
        Add-ComplianceCheck -Category "Endpoint Security" `
            -Check "Firewall - $($profile.Name) Profile" `
            -Requirement "SOC 2 CC6.1 / HIPAA § 164.312(c)(1)" `
            -Passed $enabled `
            -CurrentValue $(if ($enabled) { "Enabled" } else { "Disabled" }) `
            -ExpectedValue "Enabled" `
            -Remediation "Set-NetFirewallProfile -Profile $($profile.Name) -Enabled True"
        
        if ($enabled) {
            Write-Host "  [PASS] Firewall $($profile.Name) profile is enabled" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Firewall $($profile.Name) profile is disabled" -ForegroundColor Red
        }
    }
}

Write-Host ""
