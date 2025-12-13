<#
.SYNOPSIS
    Validates Network Security Settings
.DESCRIPTION
    Tests SMB, RDP, and network protocol security
    SOC 2 CC6.1 | HIPAA § 164.312(e)
#>

Write-Host "Checking Network Security Settings..." -ForegroundColor Cyan

# Check SMBv1 (should be disabled)
$smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue

if ($smbv1) {
    $smbv1Disabled = $smbv1.State -eq 'Disabled'
    
    Add-ComplianceCheck -Category "Network Security" `
        -Check "SMBv1 Protocol Disabled" `
        -Requirement "SOC 2 CC6.1 - Insecure Protocol Mitigation" `
        -NIST "CM-7(1), SI-2" `
        -CIS "4.8" `
        -ISO27001 "A.12.6.2" `
        -PCIDSS "2.2.2" `
        -Passed $smbv1Disabled `
        -CurrentValue $smbv1.State `
        -ExpectedValue "Disabled" `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
    
    if ($smbv1Disabled) {
        Write-Host "  [PASS] SMBv1 is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] SMBv1 is enabled (security risk)" -ForegroundColor Red
    }
}

# Check SMB signing
$smbClientSigning = (Get-SmbClientConfiguration).RequireSecuritySignature
$smbServerSigning = (Get-SmbServerConfiguration).RequireSecuritySignature

Add-ComplianceCheck -Category "Network Security" `
    -Check "SMB Client Signing Required" `
    -Requirement "HIPAA § 164.312(e)(1) - Transmission Security" `
    -NIST "SC-8" `
    -CIS "13.9" `
    -ISO27001 "A.13.1.1" `
    -PCIDSS "4.2" `
    -Passed $smbClientSigning `
    -CurrentValue $(if ($smbClientSigning) { "Required" } else { "Not Required" }) `
    -ExpectedValue "Required" `
    -Remediation "Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force"

if ($smbClientSigning) {
    Write-Host "  [PASS] SMB client signing is required" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] SMB client signing is not required" -ForegroundColor Red
}

Add-ComplianceCheck -Category "Network Security" `
    -Check "SMB Server Signing Required" `
    -Requirement "HIPAA § 164.312(e)(1) - Transmission Security" `
    -NIST "SC-8" `
    -CIS "13.9" `
    -ISO27001 "A.13.1.1" `
    -PCIDSS "4.2" `
    -Passed $smbServerSigning `
    -CurrentValue $(if ($smbServerSigning) { "Required" } else { "Not Required" }) `
    -ExpectedValue "Required" `
    -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"

if ($smbServerSigning) {
    Write-Host "  [PASS] SMB server signing is required" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] SMB server signing is not required" -ForegroundColor Red
}

# Check Remote Desktop (RDP) status
$rdpEnabled = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue

if ($rdpEnabled) {
    $rdpDisabled = $rdpEnabled.fDenyTSConnections -eq 1
    
    Add-ComplianceCheck -Category "Network Security" `
        -Check "Remote Desktop Status" `
        -Requirement "SOC 2 CC6.1 - Remote Access Control" `
        -NIST "AC-17" `
        -CIS "12.6" `
        -ISO27001 "A.9.4.2" `
        -Passed $rdpDisabled `
        -CurrentValue $(if ($rdpDisabled) { "Disabled" } else { "Enabled" }) `
        -ExpectedValue "Disabled (unless required for remote support)" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1"
    
    if ($rdpDisabled) {
        Write-Host "  [PASS] Remote Desktop is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Remote Desktop is enabled (verify if required)" -ForegroundColor Yellow
    }
}

Write-Host ""
