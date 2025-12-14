<#
.SYNOPSIS
    Best-effort detection of MFA enforcement for interactive and privileged accounts
.DESCRIPTION
    Attempts to detect whether multi-factor authentication (MFA) or conditional access
    enforcement is in use for Azure AD (cloud) identities. This is a best-effort check
    because evaluating MFA requires querying Azure AD/tenant APIs and appropriate
    modules/credentials. If the session is not connected to Azure AD or required
    modules are unavailable, the check reports an inconclusive result with guidance.
    Relevant: SOC 2 CC6.2, NIST AC-17, HIPAA §164.312
#>

Write-Host "Checking MFA / Conditional Access Enforcement (best-effort)..." -ForegroundColor Cyan

$passed = $false
$details = "Not evaluated - no Azure AD session or modules available"

# Try MSOnline / AzureAD / Az modules for tenant-level MFA / conditional access checks
try {
    if (Get-Command -Name Get-MsolUser -ErrorAction SilentlyContinue) {
        # MSOnline module present — attempt quick test (requires Connect-MsolService)
        try {
            $test = Get-MsolUser -MaxResults 1 -ErrorAction Stop
            # If query succeeded, attempt to find any users with strong auth methods
            $mfaUsers = Get-MsolUser -All | Where-Object { $_.StrongAuthenticationMethods.Count -gt 0 }
            if ($mfaUsers.Count -gt 0) {
                $passed = $true
                $details = "Found users with MFA methods configured: $($mfaUsers.Count)"
            } else {
                $passed = $false
                $details = "No users returned with MFA methods (per MSOnline)."
            }
        } catch {
            $passed = $false
            $details = "MSOnline present but not connected. Run Connect-MsolService to evaluate."
        }
    } elseif (Get-Command -Name Get-AzureADMSConditionalAccessPolicy -ErrorAction SilentlyContinue) {
        # AzureADPreview or MS Graph module capable of conditional access queries
        try {
            $policies = Get-AzureADMSConditionalAccessPolicy -ErrorAction Stop
            if ($policies.Count -gt 0) {
                $passed = $true
                $details = "Conditional Access policies present: $($policies.Count)"
            } else {
                $passed = $false
                $details = "No Conditional Access policies found in the tenant."
            }
        } catch {
            $passed = $false
            $details = "Azure AD conditional access query failed — ensure module and connection available."
        }
    } elseif (Get-Command -Name Get-MgUser -ErrorAction SilentlyContinue) {
        # Microsoft Graph PowerShell module may be available — best-effort check
        try {
            $u = Get-MgUser -Top 1 -ErrorAction Stop
            # detailed strong auth methods require Graph calls; report as connected
            $passed = $false
            $details = "Microsoft Graph available but explicit MFA checks require additional Graph scopes."
        } catch {
            $passed = $false
            $details = "Microsoft Graph present but not connected/authorized for queries."
        }
    } else {
        $passed = $false
        $details = "No Azure AD / MSOnline / Microsoft.Graph modules detected in session."
    }
} catch {
    $passed = $false
    $details = "Unexpected error while attempting MFA detection: $($_.Exception.Message)"
}

Add-ComplianceCheck -Category "Authentication" `
    -Check "MFA / Conditional Access Enforcement (best-effort)" `
    -Requirement "SOC 2 CC6.2 - Strong authentication for privileged access" `
    -NIST "IA-2, IA-2(1), AC-17" `
    -CIS "4.2" `
    -ISO27001 "A.9.4" `
    -Passed $passed `
    -CurrentValue $details `
    -ExpectedValue "MFA/Conditional Access enforced for interactive and privileged logins" `
    -Remediation "Use Azure AD Conditional Access or per-user/tenant MFA; install/connect MSOnline/AzureAD/Microsoft.Graph modules and run checks with appropriate privileges."

if ($passed) { Write-Host "  [PASS] MFA/Conditional Access appears configured: $details" -ForegroundColor Green } else { Write-Host "  [WARN] MFA/Conditional Access check inconclusive/failed: $details" -ForegroundColor Yellow }

Write-Host ""
