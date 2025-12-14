<#
.SYNOPSIS
    Validates Event Log Configuration
.DESCRIPTION
    Checks event log sizes, retention policies, and availability
#>

Write-Host "Checking Event Log Configuration..." -ForegroundColor Cyan

# Define required log configurations
$RequiredLogConfigs = @(
    @{
        LogName = "Security"
        MinSize = 2097152  # 2GB in KB
        Requirement = "HIPAA § 164.308(a)(1)(ii)(D) - Sufficient log retention"
        Category = "Event Log Configuration"
        NIST = "AU-4, AU-11"
        CIS = "8.3"
        ISO27001 = "A.12.4.1, A.12.4.2"
        SOX = "ITGC-05"
    },
    @{
        LogName = "Application"
        MinSize = 1048576  # 1GB in KB
        Requirement = "SOC 2 CC7.2 - System Monitoring"
        Category = "Event Log Configuration"
        NIST = "AU-4, AU-11"
        CIS = "8.3"
        ISO27001 = "A.12.4.1"
        SOX = "ITGC-05"
    },
    @{
        LogName = "System"
        MinSize = 1048576  # 1GB in KB
        Requirement = "SOC 2 CC7.2 - System Monitoring"
        Category = "Event Log Configuration"
        NIST = "AU-4, AU-11"
        CIS = "8.3"
        ISO27001 = "A.12.4.1"
        SOX = "ITGC-05"
    }
)

foreach ($logConfig in $RequiredLogConfigs) {
    try {
        $log = Get-WinEvent -ListLog $logConfig.LogName -ErrorAction Stop
        
        # Check log size (convert bytes to KB)
        $currentSizeKB = [Math]::Round($log.MaximumSizeInBytes / 1KB)
        $minSizeKB = $logConfig.MinSize
        $passed = $currentSizeKB -ge $minSizeKB
        
        Add-ComplianceCheck -Category $logConfig.Category `
            -Check "$($logConfig.LogName) Log Size" `
            -Requirement $logConfig.Requirement `
            -NIST $logConfig.NIST `
            -CIS $logConfig.CIS `
            -ISO27001 $logConfig.ISO27001 `
            -SOX $logConfig.SOX `
            -Passed $passed `
            -CurrentValue "$currentSizeKB KB" `
            -ExpectedValue "Minimum $minSizeKB KB" `
            -Remediation "wevtutil sl $($logConfig.LogName) /ms:$($minSizeKB * 1024)" `
            -IntuneRecommendation "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > Windows Components > Event Log Service > $($logConfig.LogName) > <strong>Specify the maximum log file size (KB)</strong> = <code>$minSizeKB</code>"
        
        if ($passed) {
            Write-Host "  [PASS] $($logConfig.LogName) log size: $currentSizeKB KB" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] $($logConfig.LogName) log size: $currentSizeKB KB (minimum: $minSizeKB KB)" -ForegroundColor Red
        }
        
        # Check if log is enabled
        $logEnabled = $log.IsEnabled
        Add-ComplianceCheck -Category $logConfig.Category `
            -Check "$($logConfig.LogName) Log Enabled" `
            -Requirement $logConfig.Requirement `
            -NIST $logConfig.NIST `
            -CIS $logConfig.CIS `
            -ISO27001 $logConfig.ISO27001 `
            -SOX $logConfig.SOX `
            -Passed $logEnabled `
            -CurrentValue $logEnabled.ToString() `
            -ExpectedValue "True" `
            -Remediation "wevtutil sl $($logConfig.LogName) /e:true"
        
        if ($logEnabled) {
            Write-Host "  [PASS] $($logConfig.LogName) log is enabled" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] $($logConfig.LogName) log is disabled" -ForegroundColor Red
        }
        
        # Check retention policy
        $retentionDays = $log.LogMode
        $retentionGood = $retentionDays -eq "Circular" -or $retentionDays -eq "AutoBackup"
        
        Add-ComplianceCheck -Category $logConfig.Category `
            -Check "$($logConfig.LogName) Retention Policy" `
            -Requirement $logConfig.Requirement `
            -NIST $logConfig.NIST `
            -CIS $logConfig.CIS `
            -ISO27001 $logConfig.ISO27001 `
            -SOX $logConfig.SOX `
            -Passed $retentionGood `
            -CurrentValue $retentionDays `
            -ExpectedValue "Circular or AutoBackup" `
            -Remediation "Configure via Group Policy or wevtutil"
        
        if ($retentionGood) {
            Write-Host "  [PASS] $($logConfig.LogName) retention: $retentionDays" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] $($logConfig.LogName) retention: $retentionDays" -ForegroundColor Yellow
        }
        
    } catch {
        Add-ComplianceCheck -Category $logConfig.Category `
            -Check "$($logConfig.LogName) Log Accessibility" `
            -Requirement $logConfig.Requirement `
            -NIST $logConfig.NIST `
            -CIS $logConfig.CIS `
            -ISO27001 $logConfig.ISO27001 `
            -SOX $logConfig.SOX `
            -Passed $false `
            -CurrentValue "Error: $($_.Exception.Message)" `
            -ExpectedValue "Accessible" `
            -Remediation "Verify Event Log service is running"
        
        Write-Host "  [FAIL] Unable to access $($logConfig.LogName) log: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Check if logs are being written (events in last 24 hours)
$yesterday = (Get-Date).AddDays(-1)
try {
    $recentSecurityEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        StartTime = $yesterday
    } -MaxEvents 1 -ErrorAction Stop
    
    $logsActive = $null -ne $recentSecurityEvents
    
    Add-ComplianceCheck -Category "Event Log Configuration" `
        -Check "Security Log Activity" `
        -Requirement "HIPAA § 164.312(b) - Audit Controls Active" `
        -NIST "AU-6" `
        -CIS "8.2" `
        -ISO27001 "A.12.4.1" `
        -SOX "ITGC-05" `
        -Passed $logsActive `
        -CurrentValue $(if ($logsActive) { "Events found in last 24 hours" } else { "No events in last 24 hours" }) `
        -ExpectedValue "Events logged within 24 hours" `
        -Remediation "Verify audit policies are enabled and Event Log service is running"
    
    if ($logsActive) {
        Write-Host "  [PASS] Security log is actively recording events" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] No security events in last 24 hours" -ForegroundColor Red
    }
} catch {
    Add-ComplianceCheck -Category "Event Log Configuration" `
        -Check "Security Log Activity" `
        -Requirement "HIPAA § 164.312(b) - Audit Controls Active" `
        -NIST "AU-6" `
        -CIS "8.2" `
        -ISO27001 "A.12.4.1" `
        -SOX "ITGC-05" `
        -Passed $false `
        -CurrentValue "Unable to verify" `
        -ExpectedValue "Events logged within 24 hours" `
        -Remediation "Verify audit policies are enabled and Event Log service is running"
    
    Write-Host "  [FAIL] Unable to verify security log activity" -ForegroundColor Red
}

Write-Host ""
