<#
.SYNOPSIS
    Validates Time Synchronization Configuration
.DESCRIPTION
    Tests Windows Time service status and synchronization accuracy
    SOC 2 CC7.2 | HIPAA § 164.312(b) - Critical for accurate audit logs
#>

Write-Host "Checking Time Synchronization..." -ForegroundColor Cyan

# Check Windows Time service
$w32timeService = Get-Service -Name W32Time -ErrorAction SilentlyContinue

if ($w32timeService) {
    $serviceRunning = $w32timeService.Status -eq 'Running'
    $serviceAutomatic = $w32timeService.StartType -eq 'Automatic'

    Add-ComplianceCheck -Category "Time Synchronization" `
        -Check "Windows Time Service Running" `
        -Requirement "SOC 2 CC7.2 - Accurate Audit Timestamps" `
        -Passed $serviceRunning `
        -CurrentValue $w32timeService.Status `
        -ExpectedValue "Running" `
        -Remediation "Start-Service W32Time"

    if ($serviceRunning) {
        Write-Host "  [PASS] Windows Time service is running" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Windows Time service is not running" -ForegroundColor Red
    }

    Add-ComplianceCheck -Category "Time Synchronization" `
        -Check "Windows Time Service Startup Type" `
        -Requirement "SOC 2 CC7.2 - System Resilience" `
        -Passed $serviceAutomatic `
        -CurrentValue $w32timeService.StartType `
        -ExpectedValue "Automatic" `
        -Remediation "Set-Service W32Time -StartupType Automatic"

    if ($serviceAutomatic) {
        Write-Host "  [PASS] Windows Time service set to Automatic" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Windows Time service not set to Automatic" -ForegroundColor Yellow
    }
}

# Check time synchronization status
try {
    $w32tmStatus = w32tm /query /status 2>&1

    if ($w32tmStatus -match "Source: (.+)") {
        $timeSource = $Matches[1]
        $hasSource = $timeSource -ne "Local CMOS Clock" -and $timeSource -ne "Free-Running System Clock"

        Add-ComplianceCheck -Category "Time Synchronization" `
            -Check "Time Source Configuration" `
            -Requirement "SOC 2 CC7.2 - Reliable Time Source" `
            -Passed $hasSource `
            -CurrentValue $timeSource `
            -ExpectedValue "External time source (not local clock)" `
            -Remediation "Configure NTP server: w32tm /config /manualpeerlist:time.windows.com /syncfromflags:manual /update"

        if ($hasSource) {
            Write-Host "  [PASS] Time source: $timeSource" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Using local clock (should sync with external source)" -ForegroundColor Red
        }
    }

    # Check last successful sync
    if ($w32tmStatus -match "Last Successful Sync Time: (.+)") {
        $lastSync = $Matches[1]

        # Try to parse the date
        try {
            $syncDate = [DateTime]::Parse($lastSync)
            $hoursSinceSync = ((Get-Date) - $syncDate).TotalHours
            $recentSync = $hoursSinceSync -le 24

            Add-ComplianceCheck -Category "Time Synchronization" `
                -Check "Recent Time Synchronization" `
                -Requirement "SOC 2 CC7.2 - Time Accuracy" `
                -Passed $recentSync `
                -CurrentValue "$([Math]::Round($hoursSinceSync, 1)) hours ago" `
                -ExpectedValue "Within last 24 hours" `
                -Remediation "Force sync: w32tm /resync /force"

            if ($recentSync) {
                Write-Host "  [PASS] Last sync: $([Math]::Round($hoursSinceSync, 1)) hours ago" -ForegroundColor Green
            } else {
                Write-Host "  [WARN] Last sync: $([Math]::Round($hoursSinceSync, 1)) hours ago (may be stale)" -ForegroundColor Yellow
            }
        } catch {
            # Could not parse date
            Add-ComplianceCheck -Category "Time Synchronization" `
                -Check "Recent Time Synchronization" `
                -Requirement "SOC 2 CC7.2 - Time Accuracy" `
                -Passed $false `
                -CurrentValue "Unable to determine" `
                -ExpectedValue "Within last 24 hours" `
                -Remediation "Force sync: w32tm /resync /force"

            Write-Host "  [WARN] Could not determine last sync time" -ForegroundColor Yellow
        }
    }
} catch {
    Add-ComplianceCheck -Category "Time Synchronization" `
        -Check "Time Service Query" `
        -Requirement "SOC 2 CC7.2 - Time Synchronization" `
        -Passed $false `
        -CurrentValue "Error querying time service: $($_.Exception.Message)" `
        -ExpectedValue "Time service operational" `
        -Remediation "Ensure W32Time service is running and configured"

    Write-Host "  [FAIL] Could not query time service status" -ForegroundColor Red
}

# Check time zone consistency
$timeZone = Get-TimeZone
$tzSet = $null -ne $timeZone

Add-ComplianceCheck -Category "Time Synchronization" `
    -Check "Time Zone Configured" `
    -Requirement "SOC 2 CC7.2 - Consistent Timestamps" `
    -Passed $tzSet `
    -CurrentValue $(if ($tzSet) { $timeZone.Id } else { "Not configured" }) `
    -ExpectedValue "Valid time zone set" `
    -Remediation "Set via Settings > Time & Language > Date & time"

if ($tzSet) {
    Write-Host "  [PASS] Time zone: $($timeZone.Id)" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Time zone not configured" -ForegroundColor Red
}

Write-Host ""
