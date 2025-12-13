<#
.SYNOPSIS
    Validates Advanced Audit Policy Configuration
.DESCRIPTION
    Checks all required audit policy subcategories for SOC 2 and HIPAA compliance
#>

Write-Host "Checking Audit Policies..." -ForegroundColor Cyan

# Define required audit policies
$RequiredAuditPolicies = @(
    # Account Logon - HIPAA § 164.312(b), § 164.308(a)(5)(ii)(C)
    @{
        Subcategory = "Credential Validation"
        Expected = "Success and Failure"
        Requirement = "HIPAA § 164.312(b) - Audit Controls"
        Category = "Account Logon"
        NIST = "AU-2, AU-12, AC-7"
        CIS = "8.2, 8.5"
        ISO27001 = "A.9.4.2, A.12.4.1"
        PCIDSS = "10.2.4, 10.2.5"
        SOX = "ITGC-05"
    },
    @{
        Subcategory = "Kerberos Authentication Service"
        Expected = "Success and Failure"
        Requirement = "HIPAA § 164.312(d) - Person or Entity Authentication"
        Category = "Account Logon"
    },
    @{
        Subcategory = "Kerberos Service Ticket Operations"
        Expected = "Success and Failure"
        Requirement = "HIPAA § 164.312(d) - Person or Entity Authentication"
        Category = "Account Logon"
    },
    
    # Account Management - SOC 2 CC6.2, CC6.3, HIPAA § 164.308(a)(3)(ii)(A)
    @{
        Subcategory = "User Account Management"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC6.2 - System Credentials / HIPAA § 164.308(a)(3)(ii)(A)"
        Category = "Account Management"
        NIST = "AC-2(4), AU-2"
        CIS = "5.1, 5.2"
        ISO27001 = "A.9.2.1, A.9.2.5"
        PCIDSS = "8.1.1, 8.1.4, 10.2.5"
        SOX = "ITGC-01"
    },
    @{
        Subcategory = "Computer Account Management"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC6.2 - System Credentials"
        Category = "Account Management"
    },
    @{
        Subcategory = "Security Group Management"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC6.3 - Access Removal / HIPAA § 164.308(a)(4)(ii)(C)"
        Category = "Account Management"
        NIST = "AC-2(4), AU-2"
        CIS = "5.4, 6.8"
        ISO27001 = "A.9.2.5, A.9.4.4"
        PCIDSS = "7.2.2, 10.2.5"
        SOX = "ITGC-01"
    },
    @{
        Subcategory = "Distribution Group Management"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC6.3 - Access Removal"
        Category = "Account Management"
    },
    @{
        Subcategory = "Application Group Management"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC6.3 - Access Removal"
        Category = "Account Management"
    },
    @{
        Subcategory = "Other Account Management Events"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC6.2 - System Credentials"
        Category = "Account Management"
    },
    
    # Logon/Logoff - HIPAA § 164.308(a)(5)(ii)(C)
    @{
        Subcategory = "Logon"
        Expected = "Success and Failure"
        Requirement = "HIPAA § 164.308(a)(5)(ii)(C) - Log-in Monitoring"
        Category = "Logon/Logoff"
        NIST = "AU-2, AC-7, AU-14"
        CIS = "8.2, 8.3"
        ISO27001 = "A.9.4.2, A.12.4.1"
        PCIDSS = "10.2.4, 10.2.5"
        SOX = "ITGC-05"
    },
    @{
        Subcategory = "Logoff"
        Expected = "Success"
        Requirement = "HIPAA § 164.308(a)(5)(ii)(C) - Log-in Monitoring"
        Category = "Logon/Logoff"
    },
    @{
        Subcategory = "Account Lockout"
        Expected = "Failure"
        Requirement = "HIPAA § 164.308(a)(5)(ii)(C) - Log-in Monitoring"
        Category = "Logon/Logoff"
    },
    @{
        Subcategory = "Special Logon"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC6.1 - Privileged Access Monitoring"
        Category = "Logon/Logoff"
    },
    
    # Object Access - HIPAA § 164.312(b)
    @{
        Subcategory = "File System"
        Expected = "Success and Failure"
        Requirement = "HIPAA § 164.312(b) - Audit Controls (File Access)"
        Category = "Object Access"
        NIST = "AU-2, AU-12"
        CIS = "8.5"
        ISO27001 = "A.12.4.1, A.12.4.3"
        PCIDSS = "10.2.1, 10.2.7"
        SOX = "ITGC-04"
    },
    @{
        Subcategory = "Registry"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC7.2 - System Monitoring"
        Category = "Object Access"
    },
    @{
        Subcategory = "Removable Storage"
        Expected = "Success and Failure"
        Requirement = "HIPAA § 164.312(b) - Audit Controls"
        Category = "Object Access"
    },
    @{
        Subcategory = "Detailed File Share"
        Expected = "Success and Failure"
        Requirement = "HIPAA § 164.312(b) - Audit Controls (File Access)"
        Category = "Object Access"
    },
    
    # Policy Change - SOC 2 CC7.3
    @{
        Subcategory = "Audit Policy Change"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC7.3 - Evaluation of Security Events"
        Category = "Policy Change"
        NIST = "AU-2, AU-6, CM-3"
        CIS = "8.11"
        ISO27001 = "A.12.4.1, A.12.4.4"
        PCIDSS = "10.2.7, 10.5.5"
        SOX = "ITGC-03"
    },
    @{
        Subcategory = "Authentication Policy Change"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC7.3 - Evaluation of Security Events"
        Category = "Policy Change"
    },
    @{
        Subcategory = "Authorization Policy Change"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC7.3 - Evaluation of Security Events"
        Category = "Policy Change"
    },
    
    # Privilege Use - SOC 2 CC6.1
    @{
        Subcategory = "Sensitive Privilege Use"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC6.1 - Logical Access Controls"
        Category = "Privilege Use"
    },
    
    # System - SOC 2 CC7.2
    @{
        Subcategory = "Security State Change"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC7.2 - System Monitoring"
        Category = "System"
    },
    @{
        Subcategory = "Security System Extension"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC7.2 - System Monitoring"
        Category = "System"
    },
    @{
        Subcategory = "System Integrity"
        Expected = "Success and Failure"
        Requirement = "SOC 2 CC7.2 - System Monitoring"
        Category = "System"
    },
    
    # Detailed Tracking - HIPAA § 164.312(b)
    @{
        Subcategory = "Process Creation"
        Expected = "Success"
        Requirement = "HIPAA § 164.312(b) - Audit Controls"
        Category = "Detailed Tracking"
    }
)

# Get current audit policy configuration
$auditOutput = auditpol /get /category:* /r | ConvertFrom-Csv

foreach ($policy in $RequiredAuditPolicies) {
    $currentPolicy = $auditOutput | Where-Object { 
        $_.'Subcategory' -eq $policy.Subcategory -or 
        $_.'Subcategory GUID' -match $policy.Subcategory 
    }
    
    if ($currentPolicy) {
        $currentSetting = $currentPolicy.'Inclusion Setting'
        $passed = $currentSetting -eq $policy.Expected
        
        Add-ComplianceCheck -Category "Audit Policy - $($policy.Category)" `
            -Check $policy.Subcategory `
            -Requirement $policy.Requirement `
            -NIST $policy.NIST `
            -CIS $policy.CIS `
            -ISO27001 $policy.ISO27001 `
            -PCIDSS $policy.PCIDSS `
            -SOX $policy.SOX `
            -Passed $passed `
            -CurrentValue $currentSetting `
            -ExpectedValue $policy.Expected `
            -Remediation "auditpol /set /subcategory:`"$($policy.Subcategory)`" /success:enable /failure:enable"
        
        if ($passed) {
            Write-Host "  [PASS] $($policy.Subcategory)" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] $($policy.Subcategory) - Current: $currentSetting" -ForegroundColor Red
        }
    } else {
        Add-ComplianceCheck -Category "Audit Policy - $($policy.Category)" `
            -Check $policy.Subcategory `
            -Requirement $policy.Requirement `
            -NIST $policy.NIST `
            -CIS $policy.CIS `
            -ISO27001 $policy.ISO27001 `
            -PCIDSS $policy.PCIDSS `
            -SOX $policy.SOX `
            -Passed $false `
            -CurrentValue "Not Found" `
            -ExpectedValue $policy.Expected `
            -Remediation "auditpol /set /subcategory:`"$($policy.Subcategory)`" /success:enable /failure:enable"
        
        Write-Host "  [FAIL] $($policy.Subcategory) - Policy not found" -ForegroundColor Red
    }
}

Write-Host ""
