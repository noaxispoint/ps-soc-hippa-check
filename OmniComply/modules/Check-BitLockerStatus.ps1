<#
.SYNOPSIS
    Checks BitLocker / full-disk encryption status for system volumes
.DESCRIPTION
    Uses `Get-BitLockerVolume` where available to confirm volumes are protected.
    Reports volumes that are not protected and provides remediation guidance.
    Relevant to HIPAA, SOC 2, NIST MP-3.
#>

Write-Host "Checking BitLocker / Disk Encryption status..." -ForegroundColor Cyan

try {
    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
} catch {
    $volumes = $null
}

if (-not $volumes) {
    Add-ComplianceCheck -Category "Encryption" `
        -Check "BitLocker / Disk Encryption Status" `
        -Requirement "Encryption at rest for sensitive data" `
        -NIST "MP-3" `
        -CIS "3.4" `
        -Passed $false `
        -CurrentValue "Get-BitLockerVolume not available or not supported in this session" `
        -ExpectedValue "All required system/data volumes encrypted with BitLocker or equivalent" `
        -Remediation "Ensure BitLocker (or equivalent) is enabled and run this check in elevated session."

    Write-Host "  [WARN] BitLocker module unavailable or not supported in this session" -ForegroundColor Yellow
} else {
    $unprotected = $volumes | Where-Object { ($_.ProtectionStatus -ne 'On') -and ($_.ProtectionStatus -ne 1) }

    $passed = ($unprotected.Count -eq 0)

    $currentValue = ($volumes | ForEach-Object { "$($_.MountPoint): Protection=$($_.ProtectionStatus)" }) -join "; "

    Add-ComplianceCheck -Category "Encryption" `
        -Check "BitLocker / Disk Encryption Status" `
        -Requirement "Encryption at rest for sensitive data" `
        -NIST "MP-3" `
        -CIS "3.4" `
        -Passed $passed `
        -CurrentValue $currentValue `
        -ExpectedValue "All required system/data volumes encrypted (ProtectionStatus=On)" `
        -Remediation "Enable BitLocker via `Enable-BitLocker` or use your enterprise disk-encryption solution."

    if ($passed) { Write-Host "  [PASS] All detected volumes report BitLocker protection" -ForegroundColor Green }
    else { Write-Host "  [FAIL] Some volumes are not BitLocker-protected: $($unprotected | ForEach-Object { $_.MountPoint })" -ForegroundColor Red }
}

Write-Host ""
