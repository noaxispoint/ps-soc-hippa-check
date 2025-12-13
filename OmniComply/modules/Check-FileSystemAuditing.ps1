<#
.SYNOPSIS
    Validates File System Auditing Configuration
.DESCRIPTION
    Checks if SACL auditing is enabled on sensitive directories
#>

Write-Host "Checking File System Auditing..." -ForegroundColor Cyan

# Check if Object Access auditing is enabled
$objectAccessEnabled = auditpol /get /subcategory:"File System" /r | ConvertFrom-Csv | 
    Where-Object { $_.'Inclusion Setting' -match "Success" -or $_.'Inclusion Setting' -match "Failure" }

if ($objectAccessEnabled) {
    Write-Host "  [PASS] Object Access auditing is enabled" -ForegroundColor Green
    
    Add-ComplianceCheck -Category "File System Auditing" `
        -Check "Object Access Policy Enabled" `
        -Requirement "HIPAA § 164.312(b) - File Access Auditing" `
        -Passed $true `
        -CurrentValue "Enabled" `
        -ExpectedValue "Enabled" `
        -Remediation "N/A"
} else {
    Write-Host "  [FAIL] Object Access auditing is not properly enabled" -ForegroundColor Red
    
    Add-ComplianceCheck -Category "File System Auditing" `
        -Check "Object Access Policy Enabled" `
        -Requirement "HIPAA § 164.312(b) - File Access Auditing" `
        -Passed $false `
        -CurrentValue "Disabled or Partial" `
        -ExpectedValue "Success and Failure" `
        -Remediation "auditpol /set /subcategory:`"File System`" /success:enable /failure:enable"
}

# Check common sensitive folders for SACL configuration
$sensitiveLocations = @(
    "$env:USERPROFILE\Documents",
    "$env:PUBLIC\Documents",
    "C:\ProgramData"
)

$saclCount = 0
$foldersChecked = 0

foreach ($folder in $sensitiveLocations) {
    if (Test-Path $folder) {
        $foldersChecked++
        try {
            $acl = Get-Acl $folder -Audit -ErrorAction Stop
            $auditRules = $acl.Audit
            
            if ($auditRules.Count -gt 0) {
                $saclCount++
                Write-Host "  [INFO] $folder has $($auditRules.Count) audit rule(s) configured" -ForegroundColor Gray
            }
        } catch {
            Write-Host "  [WARN] Unable to check SACL on $folder" -ForegroundColor Yellow
        }
    }
}

$saclsConfigured = $saclCount -gt 0

Add-ComplianceCheck -Category "File System Auditing" `
    -Check "SACL Configuration on Sensitive Folders" `
    -Requirement "HIPAA § 164.312(b) - Audit Controls for File Access" `
    -Passed $saclsConfigured `
    -CurrentValue "$saclCount of $foldersChecked checked folders have auditing" `
    -ExpectedValue "Auditing configured on folders containing ePHI/sensitive data" `
    -Remediation "Configure SACLs using icacls or PowerShell Set-Acl with audit rules"

if ($saclsConfigured) {
    Write-Host "  [PASS] File system auditing is configured on some sensitive folders" -ForegroundColor Green
} else {
    Write-Host "  [WARN] No file system auditing found on common sensitive folders" -ForegroundColor Yellow
}

# Check Detailed File Share auditing
$detailedFileShare = auditpol /get /subcategory:"Detailed File Share" /r | ConvertFrom-Csv |
    Where-Object { $_.'Inclusion Setting' -eq "Success and Failure" }

$fileSharePassed = $null -ne $detailedFileShare

Add-ComplianceCheck -Category "File System Auditing" `
    -Check "Detailed File Share Auditing" `
    -Requirement "HIPAA § 164.312(b) - Network Share Access Auditing" `
    -Passed $fileSharePassed `
    -CurrentValue $(if ($fileSharePassed) { "Enabled" } else { "Not Fully Enabled" }) `
    -ExpectedValue "Success and Failure" `
    -Remediation "auditpol /set /subcategory:`"Detailed File Share`" /success:enable /failure:enable"

if ($fileSharePassed) {
    Write-Host "  [PASS] Detailed File Share auditing is enabled" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Detailed File Share auditing is not fully enabled" -ForegroundColor Red
}

Write-Host ""
