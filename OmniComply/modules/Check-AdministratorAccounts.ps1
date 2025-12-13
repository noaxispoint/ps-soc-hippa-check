<#
.SYNOPSIS
    Validates Administrator Account Security
.DESCRIPTION
    Tests built-in administrator account status and local admin group membership
    SOC 2 CC6.2, CC6.3 | HIPAA § 164.308(a)(3)(ii)(A)
#>

Write-Host "Checking Administrator Account Security..." -ForegroundColor Cyan

# Check if built-in Administrator account is disabled
$builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "*-500" } | Select-Object -First 1

if ($builtinAdmin) {
    $adminDisabled = -not $builtinAdmin.Enabled

    Add-ComplianceCheck -Category "Administrator Accounts" `
        -Check "Built-in Administrator Account Disabled" `
        -Requirement "SOC 2 CC6.2 - Default Account Security" `
        -NIST "AC-2(1), AC-6" `
        -CIS "5.4" `
        -ISO27001 "A.9.2.3" `
        -PCIDSS "7.1, 7.2" `
        -Passed $adminDisabled `
        -CurrentValue $(if ($adminDisabled) { "Disabled" } else { "Enabled" }) `
        -ExpectedValue "Disabled" `
        -Remediation "Disable-LocalUser -Name 'Administrator' (or use SID)"

    if ($adminDisabled) {
        Write-Host "  [PASS] Built-in Administrator account is disabled" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Built-in Administrator account is enabled" -ForegroundColor Red
    }

    # Check if Administrator account has been renamed
    $adminRenamed = $builtinAdmin.Name -ne "Administrator"

    Add-ComplianceCheck -Category "Administrator Accounts" `
        -Check "Built-in Administrator Account Renamed" `
        -Requirement "SOC 2 CC6.2 - Account Hardening" `
        -NIST "AC-2(1)" `
        -CIS "5.4" `
        -ISO27001 "A.9.2.3" `
        -PCIDSS "7.1" `
        -Passed $adminRenamed `
        -CurrentValue $builtinAdmin.Name `
        -ExpectedValue "Renamed (not 'Administrator')" `
        -Remediation "Rename-LocalUser -Name 'Administrator' -NewName 'AdminRenamed'"

    if ($adminRenamed) {
        Write-Host "  [PASS] Built-in Administrator account renamed to: $($builtinAdmin.Name)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Built-in Administrator account not renamed (still 'Administrator')" -ForegroundColor Yellow
    }
}

# Check local Administrators group membership
$adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($adminGroup) {
    $adminCount = $adminGroup.Count
    $reasonableCount = $adminCount -le 3

    $memberList = ($adminGroup | ForEach-Object { $_.Name }) -join ", "

    Add-ComplianceCheck -Category "Administrator Accounts" `
        -Check "Local Administrators Group Size" `
        -Requirement "SOC 2 CC6.3 - Least Privilege" `
        -NIST "AC-6" `
        -CIS "5.4" `
        -ISO27001 "A.9.2.3" `
        -PCIDSS "7.1.2" `
        -Passed $reasonableCount `
        -CurrentValue "$adminCount members: $memberList" `
        -ExpectedValue "3 or fewer members" `
        -Remediation "Review and remove unnecessary admin accounts"

    if ($reasonableCount) {
        Write-Host "  [PASS] Administrators group has $adminCount members" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Administrators group has $adminCount members (review for least privilege)" -ForegroundColor Yellow
    }
}

# Check for stale admin accounts (not used in 90+ days)
$staleAdmins = Get-LocalUser | Where-Object {
    $_.Enabled -eq $true -and
    $_.LastLogon -and
    ((Get-Date) - $_.LastLogon).Days -gt 90
}

if ($staleAdmins) {
    $staleCount = $staleAdmins.Count
    $staleList = ($staleAdmins | ForEach-Object { "$($_.Name) (last logon: $($_.LastLogon.ToString('yyyy-MM-dd')))" }) -join "; "

    Add-ComplianceCheck -Category "Administrator Accounts" `
        -Check "Stale Administrator Accounts" `
        -Requirement "SOC 2 CC6.3 - Account Lifecycle Management" `
        -NIST "AC-2(3)" `
        -CIS "5.3" `
        -ISO27001 "A.9.2.1, A.9.2.6" `
        -PCIDSS "8.1.4" `
        -Passed ($staleCount -eq 0) `
        -CurrentValue "$staleCount stale accounts: $staleList" `
        -ExpectedValue "No stale accounts (unused >90 days)" `
        -Remediation "Disable or remove unused accounts"

    if ($staleCount -eq 0) {
        Write-Host "  [PASS] No stale administrator accounts found" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Found $staleCount stale accounts not used in 90+ days" -ForegroundColor Yellow
    }
} else {
    Add-ComplianceCheck -Category "Administrator Accounts" `
        -Check "Stale Administrator Accounts" `
        -Requirement "SOC 2 CC6.3 - Account Lifecycle Management" `
        -NIST "AC-2(3)" `
        -CIS "5.3" `
        -ISO27001 "A.9.2.1, A.9.2.6" `
        -PCIDSS "8.1.4" `
        -Passed $true `
        -CurrentValue "No stale accounts" `
        -ExpectedValue "No stale accounts (unused >90 days)" `
        -Remediation "N/A"

    Write-Host "  [PASS] No stale administrator accounts found" -ForegroundColor Green
}

Write-Host ""
