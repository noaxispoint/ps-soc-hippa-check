<#
.SYNOPSIS
    Checks recency of installed updates (hotfixes)
.DESCRIPTION
    Looks for the most recently installed Windows update and reports days since last
    update. Flags endpoints that have not had updates installed within a configurable
    threshold (default 30 days).
    Relevant: CIS, NIST SI-2, SOC 2.
#>

param(
    [int]$DaysThreshold = 30
)

Write-Host "Checking patch recency (hotfixes) with threshold $DaysThreshold days..." -ForegroundColor Cyan

$passed = $false
$details = "No hotfix information available"

try {
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue
    if ($hotfixes) {
        $latest = $hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($latest -and $latest.InstalledOn) {
            $days = (Get-Date) - $latest.InstalledOn
            $daysNum = [int]$days.TotalDays
            $details = "Most recent hotfix: $($latest.HotFixID) installed on $($latest.InstalledOn.ToString('yyyy-MM-dd')) ($daysNum days ago)"
            $passed = ($daysNum -le $DaysThreshold)
        } else {
            $details = "No InstalledOn timestamps available for hotfixes"
            $passed = $false
        }
    } else {
        $details = "Get-HotFix returned no results or is unsupported on this platform"
        $passed = $false
    }
} catch {
    $passed = $false
    $details = "Error while checking hotfixes: $($_.Exception.Message)"
}

Add-ComplianceCheck -Category "Vulnerability Management" `
    -Check "Patch Recency (Hotfixes)" `
    -Requirement "Install critical updates within SLA" `
    -NIST "SI-2" `
    -CIS "7.1" `
    -Passed $passed `
    -CurrentValue $details `
    -ExpectedValue "Recent critical updates installed within $DaysThreshold days" `
    -Remediation "Ensure automated patching (WSUS/SCCM/Intune) and install critical updates."

if ($passed) { Write-Host "  [PASS] $details" -ForegroundColor Green } else { Write-Host "  [WARN] $details" -ForegroundColor Yellow }

Write-Host ""
