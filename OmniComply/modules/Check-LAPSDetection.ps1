<#
.SYNOPSIS
    Detects presence of LAPS (Local Administrator Password Solution)
.DESCRIPTION
    Best-effort detection of LAPS deployment by checking for AD attribute usage,
    presence of LAPS PowerShell cmdlets, or LAPS installation path. This check
    cannot fully verify operational policies without AD access and privileges.
    Relevant: CIS, SOC 2 (least privilege), NIST AC-6.
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
    -Check "LAPS (Local Admin Password Solution) Detection (best-effort)" `
    -Requirement "Manage local admin passwords (CIS LAPS)" `
    -NIST "AC-6" `
    -CIS "5.4" `
    -Passed $passed `
    -CurrentValue $current `
    -ExpectedValue "LAPS deployed and managing local admin passwords" `
    -Remediation "Deploy LAPS or equivalent, extend AD schema, and configure GPOs to manage local admin passwords."

if ($passed) { Write-Host "  [PASS] $current" -ForegroundColor Green } else { Write-Host "  [WARN] $current" -ForegroundColor Yellow }

Write-Host ""
