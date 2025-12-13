<#
.SYNOPSIS
    Validates Segregation of Duties (SoD) Controls
.DESCRIPTION
    Tests for conflicting role assignments, excessive privileges, and separation of responsibilities
    SOX ITGC-01, ITGC-02 | NIST 800-53 AC-5 | ISO 27001 A.6.1.2
#>

Write-Host "Checking Segregation of Duties..." -ForegroundColor Cyan

# Check local Administrators group membership
try {
    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop

    $adminCount = $adminGroup.Count
    $adminUsers = ($adminGroup | Where-Object { $_.ObjectClass -eq "User" }).Count
    $adminGroups = ($adminGroup | Where-Object { $_.ObjectClass -eq "Group" }).Count

    # SOX best practice: Limit direct admin assignments
    $adminCountAcceptable = $adminCount -le 5

    Add-ComplianceCheck -Category "Segregation of Duties" `
        -Check "Local Administrators Group Size" `
        -Requirement "SOX ITGC-01 - Limit administrative access" `
        -NIST "AC-5, AC-6(5)" `
        -CIS "5.4" `
        -ISO27001 "A.9.2.3" `
        -SOX "ITGC-01" `
        -Passed $adminCountAcceptable `
        -CurrentValue "$adminCount member(s): $adminUsers user(s), $adminGroups group(s)" `
        -ExpectedValue "5 or fewer administrators" `
        -Remediation "Review and reduce administrator group membership: Remove-LocalGroupMember -Group 'Administrators' -Member '<username>'"

    if ($adminCountAcceptable) {
        Write-Host "  [PASS] Local Administrators group has $adminCount member(s) (appropriate)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Local Administrators group has $adminCount member(s) (review for excess)" -ForegroundColor Yellow
    }

    # List current administrators
    Write-Host "  [INFO] Current administrators:" -ForegroundColor Gray
    foreach ($admin in $adminGroup) {
        Write-Host "    - $($admin.Name) [$($admin.ObjectClass)]" -ForegroundColor Gray
    }

} catch {
    Write-Host "  [ERROR] Unable to query Administrators group" -ForegroundColor Red
}

# Check for users with multiple high-privilege group memberships
try {
    $localUsers = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -eq $true }

    $usersWithConflicts = @()

    foreach ($user in $localUsers) {
        $userGroups = Get-LocalGroup -ErrorAction Stop | Where-Object {
            try {
                $members = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
                $members.Name -contains $user.Name
            } catch {
                $false
            }
        }

        # Check for conflicting group memberships (Admins + other privileged groups)
        $privilegedGroups = $userGroups | Where-Object {
            $_.Name -in @("Administrators", "Power Users", "Remote Desktop Users", "Backup Operators")
        }

        if ($privilegedGroups.Count -gt 2) {
            $usersWithConflicts += [PSCustomObject]@{
                User = $user.Name
                Groups = ($privilegedGroups.Name -join ", ")
                Count = $privilegedGroups.Count
            }
        }
    }

    $noConflicts = $usersWithConflicts.Count -eq 0

    Add-ComplianceCheck -Category "Segregation of Duties" `
        -Check "Conflicting Privilege Assignments" `
        -Requirement "SOX ITGC-01 - Segregation of incompatible duties" `
        -NIST "AC-5(1)" `
        -ISO27001 "A.6.1.2" `
        -SOX "ITGC-01" `
        -Passed $noConflicts `
        -CurrentValue "$($usersWithConflicts.Count) user(s) with multiple high-privilege groups" `
        -ExpectedValue "No users with conflicting privilege assignments" `
        -Remediation "Review and remove conflicting group memberships"

    if ($noConflicts) {
        Write-Host "  [PASS] No users with conflicting privilege assignments detected" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] $($usersWithConflicts.Count) user(s) with multiple high-privilege groups:" -ForegroundColor Yellow
        foreach ($conflict in $usersWithConflicts) {
            Write-Host "    - $($conflict.User): $($conflict.Groups)" -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host "  [INFO] Unable to check user privilege conflicts" -ForegroundColor Gray
}

# Check for shared accounts
try {
    $localUsers = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -eq $true }

    $sharedAccountPatterns = @("admin", "shared", "generic", "service", "test", "temp")
    $sharedAccounts = $localUsers | Where-Object {
        $username = $_.Name.ToLower()
        $sharedAccountPatterns | Where-Object { $username -match $_ }
    }

    $noSharedAccounts = $sharedAccounts.Count -eq 0

    Add-ComplianceCheck -Category "Segregation of Duties" `
        -Check "Shared/Generic Accounts" `
        -Requirement "SOX ITGC-02 - Individual accountability" `
        -NIST "AC-2(5), IA-2(1)" `
        -ISO27001 "A.9.2.1" `
        -SOX "ITGC-02" `
        -Passed $noSharedAccounts `
        -CurrentValue "$($sharedAccounts.Count) potential shared account(s): $($sharedAccounts.Name -join ', ')" `
        -ExpectedValue "No shared or generic accounts" `
        -Remediation "Replace shared accounts with individual user accounts"

    if ($noSharedAccounts) {
        Write-Host "  [PASS] No shared or generic accounts detected" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] $($sharedAccounts.Count) potential shared account(s) found" -ForegroundColor Yellow
        foreach ($account in $sharedAccounts) {
            Write-Host "    - $($account.Name)" -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host "  [INFO] Unable to check for shared accounts" -ForegroundColor Gray
}

# Check for service accounts with interactive logon rights
try {
    $serviceAccounts = Get-LocalUser -ErrorAction Stop | Where-Object {
        $_.Description -match "service" -or $_.Name -match "svc|service"
    }

    if ($serviceAccounts) {
        foreach ($svcAccount in $serviceAccounts) {
            # Check if service account is in Remote Desktop Users or Administrators
            $hasInteractiveAccess = $false

            try {
                $rdpMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
                $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

                if ($rdpMembers.Name -contains $svcAccount.Name -or $adminMembers.Name -contains $svcAccount.Name) {
                    $hasInteractiveAccess = $true
                }
            } catch {
                # Group may not exist
            }

            if ($hasInteractiveAccess) {
                Add-ComplianceCheck -Category "Segregation of Duties" `
                    -Check "Service Account Interactive Logon ($($svcAccount.Name))" `
                    -Requirement "SOX ITGC-01 - Service account restrictions" `
                    -NIST "AC-6(7)" `
                    -ISO27001 "A.9.2.1" `
                    -SOX "ITGC-01" `
                    -Passed $false `
                    -CurrentValue "Service account has interactive logon rights" `
                    -ExpectedValue "Service accounts should not have interactive logon" `
                    -Remediation "Remove service accounts from Administrators and Remote Desktop Users groups"

                Write-Host "  [WARN] Service account '$($svcAccount.Name)' has interactive logon rights" -ForegroundColor Yellow
            }
        }
    }

} catch {
    Write-Host "  [INFO] Unable to check service account permissions" -ForegroundColor Gray
}

# Check for users with 'never expires' passwords who also have admin rights
try {
    $localUsers = Get-LocalUser -ErrorAction Stop | Where-Object {
        $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true
    }

    if ($localUsers) {
        foreach ($user in $localUsers) {
            # Check if user is admin
            $isAdmin = $false

            try {
                $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                if ($adminMembers.Name -contains $user.Name) {
                    $isAdmin = $true
                }
            } catch {
                # Group query failed
            }

            if ($isAdmin) {
                Add-ComplianceCheck -Category "Segregation of Duties" `
                    -Check "Admin with Non-Expiring Password ($($user.Name))" `
                    -Requirement "SOX ITGC-02 - Password policy enforcement" `
                    -NIST "IA-5(1)" `
                    -SOX "ITGC-02" `
                    -Passed $false `
                    -CurrentValue "Administrator account with non-expiring password" `
                    -ExpectedValue "Admin accounts must have expiring passwords" `
                    -Remediation "Set-LocalUser -Name '$($user.Name)' -PasswordNeverExpires `$false"

                Write-Host "  [FAIL] Admin '$($user.Name)' has non-expiring password (SOX violation)" -ForegroundColor Red
            }
        }
    }

} catch {
    Write-Host "  [INFO] Unable to check password expiration for admins" -ForegroundColor Gray
}

# Check for role-based access control configuration
Write-Host "  [INFO] Segregation of Duties best practices:" -ForegroundColor Gray
Write-Host "    - Developers should not have production access" -ForegroundColor Gray
Write-Host "    - Database admins should not be application admins" -ForegroundColor Gray
Write-Host "    - Security admins should not be system admins" -ForegroundColor Gray
Write-Host "    - Backup operators should not be able to restore without approval" -ForegroundColor Gray

# Check for audit log access restrictions
$eventLogReaders = Get-LocalGroupMember -Group "Event Log Readers" -ErrorAction SilentlyContinue

if ($eventLogReaders) {
    Write-Host "  [INFO] Event Log Readers group has $($eventLogReaders.Count) member(s)" -ForegroundColor Gray
    Write-Host "    Verify these users cannot modify logs (read-only access)" -ForegroundColor Gray
}

# Check for conflicting database roles (if SQL Server is present)
$sqlServices = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }

if ($sqlServices) {
    Write-Host "  [INFO] SQL Server detected - verify database role segregation:" -ForegroundColor Gray
    Write-Host "    - DBAs should not have application-level permissions" -ForegroundColor Gray
    Write-Host "    - Developers should not have production DBA rights" -ForegroundColor Gray
    Write-Host "    - Use SQL query: SELECT * FROM sys.database_role_members" -ForegroundColor Gray
}

Write-Host ""
