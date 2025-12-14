<#
.SYNOPSIS
    Checks SMBv1 status and SMB signing configuration
.DESCRIPTION
    Detects whether SMBv1 is enabled on the server and reports SMB signing requirement.
    Flags presence of SMBv1 (CIS requirement to disable) and recommends enabling SMB signing.
    Relevant: CIS, NIST AC-17, SOC 2.
#>

Write-Host "Checking SMBv1 and SMB signing configuration..." -ForegroundColor Cyan

$passed = $true
$details = @()

try {
    if (Get-Command -Name Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        $smb = Get-SmbServerConfiguration
        $enableSMB1 = $smb.EnableSMB1Protocol
        $requireSigning = $smb.RequireSecuritySignature

        if ($enableSMB1) {
            $passed = $false
            $details += "SMBv1 is enabled"
        } else { $details += "SMBv1 is disabled" }

        if (-not $requireSigning) {
            $passed = $false
            $details += "SMB signing (RequireSecuritySignature) is not required"
        } else { $details += "SMB signing required" }
    } else {
        # Fallback to registry checks
        $smb1Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $smb1Val = $null
        try { $smb1Val = Get-ItemProperty -Path $smb1Key -Name SMB1 -ErrorAction SilentlyContinue } catch { }

        if ($smb1Val -and $smb1Val.SMB1 -eq 0) { $details += "Registry indicates SMB1 disabled" } 
        elseif ($smb1Val -and $smb1Val.SMB1 -eq 1) { $passed = $false; $details += "Registry indicates SMB1 enabled" } 
        else { $details += "Unable to determine SMB1 via registry or SMB cmdlets"; $passed = $false }
    }
} catch {
    $passed = $false
    $details += "Error while checking SMB settings: $($_.Exception.Message)"
}

$current = $details -join '; '

Add-ComplianceCheck -Category "Network Security" `
    -Check "SMBv1 Disabled and SMB Signing Enforced" `
    -Requirement "Disable SMBv1 and enable SMB signing (CIS)" `
    -NIST "AC-17" `
    -CIS "3.5" `
    -Passed $passed `
    -CurrentValue $current `
    -ExpectedValue "SMBv1 disabled; SMB signing required" `
    -Remediation "Disable SMBv1 and enable SMB signing: use Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true and/or update registry/GPOs."

if ($passed) { Write-Host "  [PASS] $current" -ForegroundColor Green } else { Write-Host "  [FAIL] $current" -ForegroundColor Red }

Write-Host ""
