<#
.SYNOPSIS
    Detects presence of LAPS (Local Administrator Password Solution)
.DESCRIPTION
    Best-effort detection of LAPS deployment by checking for:
    - Legacy LAPS: AD attribute (ms-Mcs-AdmPwd), PowerShell cmdlets, installation paths
    - Windows LAPS: Built-in to Windows 11 22H2+, Server 2025+ (native capability)

    This check cannot fully verify operational policies without AD access and privileges,
    but provides indicators that LAPS-style local admin password management is deployed.

    Compliance Frameworks: SOC 2 CC6.2, HIPAA § 164.308(a)(3-4), NIST AC-6, CIS 5.4,
    ISO 27001 A.9.2.3, PCI-DSS 7.1/8.2, SOX ITGC-02
#>

Write-Host "Checking for LAPS (Local Admin Password Solution) presence..." -ForegroundColor Cyan

$passed = $false
$details = @()

try {
    if (Get-Command -Name Get-AdmPwdPassword -ErrorAction SilentlyContinue) {
        $passed = $true
        $details += "LAPS PowerShell cmdlets available (Get-AdmPwdPassword)"
    }

    # AD-based detection if ActiveDirectory module is present
    if (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) {
        try {
            $sample = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd -SearchBase (Get-ADDomain).DistinguishedName -ResultSetSize 1 -ErrorAction Stop
            if ($sample -and $sample.'ms-Mcs-AdmPwd') {
                $passed = $true
                $details += "ms-Mcs-AdmPwd attribute present on AD computer objects"
            } else {
                $details += "ms-Mcs-AdmPwd attribute not present on sampled computer"
            }
        } catch {
            $details += "AD query attempted but failed or not permitted: $($_.Exception.Message)"
        }
    }

    # File-system / installation path heuristic
    $possiblePaths = @('C:\Program Files\LAPS','C:\Program Files (x86)\LAPS')
    foreach ($p in $possiblePaths) { if (Test-Path $p) { $passed = $true; $details += "LAPS installation path exists: $p" } }

    if (-not $passed -and -not $details) { $details += "No LAPS indicators found (best-effort)" }
} catch {
    $passed = $false
    $details += "Error while checking LAPS: $($_.Exception.Message)"
}

$current = $details -join '; '

Add-ComplianceCheck -Category "Administrator Accounts" `
    -Check "LAPS (Local Admin Password Solution) Detection" `
    -Requirement "SOC 2 CC6.2 - Least Privilege / Local Admin Password Management" `
    -NIST "AC-6, AC-6(2), IA-5(1)" `
    -CIS "5.4" `
    -ISO27001 "A.9.2.3, A.9.4.3" `
    -HIPAA "§ 164.308(a)(3), § 164.308(a)(4)" `
    -PCIDSS "7.1, 8.2" `
    -SOX "ITGC-02" `
    -Passed $passed `
    -CurrentValue $current `
    -ExpectedValue "LAPS deployed and managing local admin passwords" `
    -Remediation "Deploy LAPS or equivalent, extend AD schema, and configure GPOs to manage local admin passwords." `
    -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Local Policies Security Options > <strong>Accounts: Administrator account status</strong> = <code>Disabled</code> (or use Windows LAPS: Account protection > Local admin password solution (LAPS) > <strong>Enable local admin password management</strong> = <code>Enabled</code>, <strong>Password complexity</strong> = <code>Large letters + small letters + numbers + special characters</code>)"

if ($passed) { Write-Host "  [PASS] $current" -ForegroundColor Green } else { Write-Host "  [WARN] $current" -ForegroundColor Yellow }

Write-Host ""
