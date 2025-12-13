<#
.SYNOPSIS
    SOC 2 and HIPAA Logging Compliance Validation for Windows 11
.DESCRIPTION
    Comprehensive audit of logging and security configuration against SOC 2 and HIPAA requirements.
    This is the main entry point that orchestrates all individual check modules.
.NOTES
    Version: 1.1.0
    Author: Compliance Automation Team
    Requires: PowerShell 5.1+, Administrator privileges
.EXAMPLE
    .\Run-ComplianceCheck.ps1
    Runs all compliance checks and generates reports
.EXAMPLE
    .\Run-ComplianceCheck.ps1 -OutputDirectory "C:\Reports"
    Runs checks and saves reports to specified directory
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = ".\reports",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipReportGeneration,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Continue"

# Initialize results structure
$script:ComplianceResults = @{
    Compliant = $true
    Checks = @()
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    ScriptVersion = "1.1.0"
    WindowsVersion = (Get-CimInstance Win32_OperatingSystem).Caption
    WindowsBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
}

function Add-ComplianceCheck {
    <#
    .SYNOPSIS
        Adds a compliance check result to the global results collection
    .PARAMETER Category
        The category or grouping of the check
    .PARAMETER Check
        The specific check being performed
    .PARAMETER Requirement
        The SOC 2 or HIPAA requirement being validated
    .PARAMETER Passed
        Boolean indicating if the check passed
    .PARAMETER CurrentValue
        The current configuration value
    .PARAMETER ExpectedValue
        The expected/required configuration value
    .PARAMETER Remediation
        PowerShell command or instructions to fix the issue
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Category,
        
        [Parameter(Mandatory=$true)]
        [string]$Check,
        
        [Parameter(Mandatory=$true)]
        [string]$Requirement,
        
        [Parameter(Mandatory=$true)]
        [bool]$Passed,
        
        [Parameter(Mandatory=$true)]
        [string]$CurrentValue,
        
        [Parameter(Mandatory=$true)]
        [string]$ExpectedValue,
        
        [Parameter(Mandatory=$true)]
        [string]$Remediation
    )
    
    $script:ComplianceResults.Checks += [PSCustomObject]@{
        Category = $Category
        Check = $Check
        Requirement = $Requirement
        Passed = $Passed
        CurrentValue = $CurrentValue
        ExpectedValue = $ExpectedValue
        Remediation = $Remediation
    }
    
    if (-not $Passed) {
        $script:ComplianceResults.Compliant = $false
    }
}

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-SubHeader {
    param([string]$Text)
    Write-Host ""
    Write-Host $Text -ForegroundColor Yellow
    Write-Host ("-" * $Text.Length) -ForegroundColor Yellow
}

# Banner
Clear-Host
Write-Header "SOC 2 / HIPAA COMPLIANCE CHECKER v$($script:ComplianceResults.ScriptVersion)"
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "OS: $($script:ComplianceResults.WindowsVersion) (Build $($script:ComplianceResults.WindowsBuild))" -ForegroundColor White

# Detect architecture
$cpuArch = (Get-CimInstance Win32_Processor).Architecture
$archName = switch ($cpuArch) {
    0 { "x86 (32-bit)" }
    5 { "ARM (32-bit)" }
    9 { "x64 (64-bit)" }
    12 { "ARM64 (64-bit)" }
    default { "Unknown ($cpuArch)" }
}
Write-Host "Architecture: $archName" -ForegroundColor White

# ARM compatibility warning
if ($cpuArch -eq 5 -or $cpuArch -eq 12) {
    Write-Host ""
    Write-Host "⚠ ARM ARCHITECTURE DETECTED" -ForegroundColor Yellow
    Write-Host "  Some checks may behave differently on ARM devices:" -ForegroundColor Yellow
    Write-Host "  • Secure Boot detection may not work on all ARM devices" -ForegroundColor Gray
    Write-Host "  • Native system tools (auditpol, secedit) should be ARM-native" -ForegroundColor Gray
    Write-Host "  • Performance may vary on emulated components" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "User: $env:USERNAME" -ForegroundColor White

# Verify prerequisites
Write-SubHeader "Verifying Prerequisites"

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}
Write-Host "✓ Running with Administrator privileges" -ForegroundColor Green

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "ERROR: PowerShell 5.1 or later is required!" -ForegroundColor Red
    Write-Host "Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    exit 1
}
Write-Host "✓ PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Green

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    Write-Host "✓ Created output directory: $OutputDirectory" -ForegroundColor Green
} else {
    Write-Host "✓ Output directory exists: $OutputDirectory" -ForegroundColor Green
}

# Check if modules directory exists
$modulesPath = Join-Path $PSScriptRoot "modules"
if (-not (Test-Path $modulesPath)) {
    Write-Host "ERROR: Modules directory not found at: $modulesPath" -ForegroundColor Red
    Write-Host "Please ensure the project structure is intact." -ForegroundColor Yellow
    exit 1
}
Write-Host "✓ Modules directory found" -ForegroundColor Green

Write-Host ""
Write-Host "Starting compliance checks..." -ForegroundColor Cyan
Write-Host ""

# Run all check modules
$checkModules = @(
    "Check-AuditPolicies.ps1",
    "Check-EventLogConfiguration.ps1",
    "Check-FileSystemAuditing.ps1",
    "Check-LoggingServices.ps1",
    "Check-SecuritySettings.ps1",
    "Check-AccessControls.ps1",
    "Check-EncryptionControls.ps1",
    "Check-EndpointSecurity.ps1",
    "Check-ScreenLockSettings.ps1",
    "Check-UpdateCompliance.ps1",
    "Check-NetworkSecurity.ps1"
)

$moduleCount = 0
$totalModules = $checkModules.Count

foreach ($module in $checkModules) {
    $moduleCount++
    $modulePath = Join-Path $modulesPath $module
    
    if (Test-Path $modulePath) {
        Write-Host "[$moduleCount/$totalModules] Running $module..." -ForegroundColor Cyan
        try {
            . $modulePath
        } catch {
            Write-Host "  [ERROR] Failed to execute $module : $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [WARN] Module not found: $module" -ForegroundColor Yellow
    }
}

# Generate summary
Write-Header "COMPLIANCE SUMMARY"

$totalChecks = $script:ComplianceResults.Checks.Count
$passedChecks = ($script:ComplianceResults.Checks | Where-Object {$_.Passed}).Count
$failedChecks = $totalChecks - $passedChecks
$passPercentage = if ($totalChecks -gt 0) { [Math]::Round(($passedChecks / $totalChecks) * 100, 1) } else { 0 }

Write-Host "Total Checks Performed: $totalChecks" -ForegroundColor White
Write-Host "Passed: $passedChecks ($passPercentage%)" -ForegroundColor Green
Write-Host "Failed: $failedChecks" -ForegroundColor Red
Write-Host ""

if ($script:ComplianceResults.Compliant) {
    Write-Host "████████████████████████████████████████" -ForegroundColor Green
    Write-Host "█  RESULT: FULLY COMPLIANT            █" -ForegroundColor Green
    Write-Host "████████████████████████████████████████" -ForegroundColor Green
} else {
    Write-Host "████████████████████████████████████████" -ForegroundColor Red
    Write-Host "█  RESULT: NON-COMPLIANT              █" -ForegroundColor Red
    Write-Host "████████████████████████████████████████" -ForegroundColor Red
}

# Display failed checks
Write-Header "FAILED CHECKS SUMMARY"

$failedItems = $script:ComplianceResults.Checks | Where-Object {-not $_.Passed}

if ($failedItems) {
    # Group by category
    $groupedFails = $failedItems | Group-Object -Property Category
    
    foreach ($group in $groupedFails) {
        Write-Host ""
        Write-Host "Category: $($group.Name)" -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Yellow
        
        foreach ($item in $group.Group) {
            Write-Host ""
            Write-Host "  Check: $($item.Check)" -ForegroundColor White
            Write-Host "  Requirement: $($item.Requirement)" -ForegroundColor Gray
            Write-Host "  Current: " -NoNewline -ForegroundColor Gray
            Write-Host $item.CurrentValue -ForegroundColor Red
            Write-Host "  Expected: " -NoNewline -ForegroundColor Gray
            Write-Host $item.ExpectedValue -ForegroundColor Green
            Write-Host "  Remediation: " -NoNewline -ForegroundColor Gray
            Write-Host $item.Remediation -ForegroundColor Cyan
        }
    }
} else {
    Write-Host "No failed checks! All controls are compliant." -ForegroundColor Green
}

# Category summary
Write-Header "CATEGORY BREAKDOWN"

$categoryStats = $script:ComplianceResults.Checks | Group-Object -Property Category | ForEach-Object {
    $passed = ($_.Group | Where-Object {$_.Passed}).Count
    $total = $_.Group.Count
    $percentage = [Math]::Round(($passed / $total) * 100, 1)
    
    [PSCustomObject]@{
        Category = $_.Name
        Passed = $passed
        Failed = ($total - $passed)
        Total = $total
        'Pass %' = $percentage
    }
} | Sort-Object -Property 'Pass %'

$categoryStats | Format-Table -AutoSize

# Generate reports
if (-not $SkipReportGeneration) {
    Write-Header "GENERATING REPORTS"
    
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    
    # JSON Report
    $jsonPath = Join-Path $OutputDirectory "SOC2-HIPAA-Compliance-Report-$timestamp.json"
    try {
        $script:ComplianceResults | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
        Write-Host "✓ JSON report saved: $jsonPath" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to save JSON report: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # CSV Report
    $csvPath = Join-Path $OutputDirectory "SOC2-HIPAA-Compliance-Report-$timestamp.csv"
    try {
        $script:ComplianceResults.Checks | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "✓ CSV report saved: $csvPath" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to save CSV report: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # HTML Report (summary only)
    $htmlPath = Join-Path $OutputDirectory "SOC2-HIPAA-Compliance-Report-$timestamp.html"
    try {
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>SOC 2 / HIPAA Compliance Report - $env:COMPUTERNAME</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .passed { color: #107c10; font-weight: bold; }
        .failed { color: #d13438; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; background-color: white; margin: 20px 0; }
        th { background-color: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .fail-row { background-color: #fff4f4; }
        .pass-row { background-color: #f4fff4; }
        .stat-box { display: inline-block; margin: 10px; padding: 15px; background-color: #f0f0f0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SOC 2 / HIPAA Compliance Report</h1>
        <p>Computer: $env:COMPUTERNAME | Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="stat-box">
            <strong>Total Checks:</strong> $totalChecks
        </div>
        <div class="stat-box">
            <strong class="passed">Passed:</strong> $passedChecks ($passPercentage%)
        </div>
        <div class="stat-box">
            <strong class="failed">Failed:</strong> $failedChecks
        </div>
        <div class="stat-box">
            <strong>Overall Status:</strong> $(if ($script:ComplianceResults.Compliant) { '<span class="passed">COMPLIANT</span>' } else { '<span class="failed">NON-COMPLIANT</span>' })
        </div>
    </div>
    
    <h2>Failed Checks</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Check</th>
            <th>Requirement</th>
            <th>Current Value</th>
            <th>Expected Value</th>
            <th>Remediation</th>
        </tr>
"@
        
        foreach ($item in $failedItems) {
            $htmlContent += @"
        <tr class="fail-row">
            <td>$($item.Category)</td>
            <td>$($item.Check)</td>
            <td>$($item.Requirement)</td>
            <td>$($item.CurrentValue)</td>
            <td>$($item.ExpectedValue)</td>
            <td><code>$($item.Remediation)</code></td>
        </tr>
"@
        }
        
        $htmlContent += @"
    </table>
    
    <h2>Category Breakdown</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Passed</th>
            <th>Failed</th>
            <th>Total</th>
            <th>Pass %</th>
        </tr>
"@
        
        foreach ($stat in $categoryStats) {
            $htmlContent += @"
        <tr>
            <td>$($stat.Category)</td>
            <td class="passed">$($stat.Passed)</td>
            <td class="failed">$($stat.Failed)</td>
            <td>$($stat.Total)</td>
            <td>$($stat.'Pass %')%</td>
        </tr>
"@
        }
        
        $htmlContent += @"
    </table>
</body>
</html>
"@
        
        $htmlContent | Out-File $htmlPath -Encoding UTF8
        Write-Host "✓ HTML report saved: $htmlPath" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to save HTML report: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Reports location: $(Resolve-Path $OutputDirectory)" -ForegroundColor Cyan
}

# Final summary
Write-Header "NEXT STEPS"

if ($failedChecks -gt 0) {
    Write-Host "1. Review the failed checks above" -ForegroundColor Yellow
    Write-Host "2. Prioritize remediation based on risk and compliance requirements" -ForegroundColor Yellow
    Write-Host "3. Run individual remediation scripts in the 'remediation' folder" -ForegroundColor Yellow
    Write-Host "4. Re-run this compliance check to verify fixes" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Quick remediation: .\remediation\Remediate-All.ps1 (use with caution!)" -ForegroundColor Cyan
} else {
    Write-Host "Congratulations! All compliance checks passed." -ForegroundColor Green
    Write-Host "Remember to:" -ForegroundColor White
    Write-Host "  • Run regular compliance checks (monthly recommended)" -ForegroundColor Gray
    Write-Host "  • Monitor for configuration drift" -ForegroundColor Gray
    Write-Host "  • Keep documentation updated" -ForegroundColor Gray
    Write-Host "  • Review audit logs regularly" -ForegroundColor Gray
}

Write-Host ""
Write-Host "For detailed remediation guidance, see: docs\REMEDIATION.md" -ForegroundColor Cyan
Write-Host ""

# Exit with appropriate code
exit $(if ($script:ComplianceResults.Compliant) { 0 } else { 1 })
