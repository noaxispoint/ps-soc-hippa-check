<#
.SYNOPSIS
    Checks presence and basic health indicators of endpoint detection/response (EDR)
.DESCRIPTION
    Attempts to detect common EDR/antivirus agents and basic health status. For
    Microsoft Defender it inspects `Get-MpComputerStatus`; for others it looks for
    known service/process names. This is a pragmatic check to detect whether an EDR
    agent appears installed and running.
    Relevant: SOC 2 CC6.6, NIST SI-4
#>

Write-Host "Checking EDR / antivirus presence and health..." -ForegroundColor Cyan

$found = @()

# Microsoft Defender
try {
    if (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp) {
            $status = @{ AntivirusEnabled = $mp.AntivirusEnabled; RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled; AMRunning = $mp.AMServiceEnabled }
            $found += @{ Name = 'Windows Defender'; Details = $status }
        }
    }
} catch { }

# Check for common vendor services/processes
$edrServiceNames = @('csagent','CSFalconService','sfcbd-watchdog','CrowdStrike','SentinelAgent','SENTINELONE','CbDefenseService','carbonblack','epsecurity','egui','PaloAlto')

foreach ($svcName in $edrServiceNames) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Stopped') {
            $found += @{ Name = $svc.DisplayName -or $svc.Name; Details = @{ Service = $svc.Name; Status = $svc.Status } }
        }
    } catch { }
}

# Fallback: look for known processes
$commonProcesses = @('csagent','csfalcon','sentinel_agent','carbonblack','carbonblack-service','mcshield','cncs')
foreach ($p in $commonProcesses) {
    try {
        $proc = Get-Process -Name $p -ErrorAction SilentlyContinue
        if ($proc) { $found += @{ Name = $proc.Name; Details = 'Process running' } }
    } catch { }
}

$passed = ($found.Count -gt 0)

if ($passed) {
    $summary = ($found | ForEach-Object { "$($_.Name): $($_.Details -join ',')" }) -join ' | '
    Add-ComplianceCheck -Category "Endpoint Security" `
        -Check "EDR / Antivirus Presence and Basic Health" `
        -Requirement "Detect and respond capabilities (EDR) enabled" `
        -NIST "SI-4" `
        -CIS "8.3" `
        -Passed $true `
        -CurrentValue $summary `
        -ExpectedValue "EDR/AV present and running on endpoints" `
        -Remediation "Install and enable enterprise EDR/AV agent; verify services are running."

    Write-Host "  [PASS] EDR/AV agents detected: $summary" -ForegroundColor Green
} else {
    Add-ComplianceCheck -Category "Endpoint Security" `
        -Check "EDR / Antivirus Presence and Basic Health" `
        -Requirement "Detect and respond capabilities (EDR) enabled" `
        -NIST "SI-4" `
        -CIS "8.3" `
        -Passed $false `
        -CurrentValue "No known EDR/AV agents detected by service/process heuristics" `
        -ExpectedValue "EDR/AV present and running on endpoints" `
        -Remediation "Deploy enterprise EDR/AV and verify health; check vendor docs for service names."

    Write-Host "  [FAIL] No EDR/AV agents detected by heuristics" -ForegroundColor Red
}

Write-Host ""
