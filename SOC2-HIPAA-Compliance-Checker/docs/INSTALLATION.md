# Installation and Setup Guide

## System Requirements

- **Operating System:** Windows 11 or Windows Server 2016/2019/2022/2025
- **PowerShell:** Version 5.1 or later
- **Privileges:** Administrator/elevated privileges required
- **Disk Space:** ~50MB for the tool and reports

## Installation Steps

### 1. Download the Tool

```powershell
# Clone or download the repository
# Extract to your preferred location, e.g., C:\Tools\SOC2-HIPAA-Compliance-Checker
```

### 2. Set Execution Policy

Open PowerShell as Administrator and run:

```powershell
# Allow script execution (choose one)

# Option 1: For current user only (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Option 2: For all users
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

### 3. Verify Installation

```powershell
# Navigate to the tool directory
cd C:\Tools\SOC2-HIPAA-Compliance-Checker

# Verify all files are present
Get-ChildItem -Recurse

# Should show:
# - Run-ComplianceCheck.ps1
# - Quick-Check.ps1
# - modules\ directory with 11 check scripts
# - remediation\ directory
# - docs\ directory
```

### 4. Test Run

```powershell
# Run quick check to verify basic functionality
.\Quick-Check.ps1

# If successful, run full compliance check
.\Run-ComplianceCheck.ps1
```

## Deployment Options

### Option 1: Standalone Workstation

Simply extract and run on individual Windows 11 laptops.

### Option 2: Network Share

1. Copy to network share accessible by target machines
2. Create scheduled task or startup script
3. Reports can be centrally collected

```powershell
# Example: Run from network share
\\fileserver\compliance\Run-ComplianceCheck.ps1 -OutputDirectory "\\fileserver\compliance\reports\%COMPUTERNAME%"
```

### Option 3: Intune Deployment

Deploy as Proactive Remediation or Win32 app:

1. Package scripts as .intunewin file
2. Deploy to device groups
3. Configure detection and remediation scripts
4. Collect results via Azure Log Analytics

See [Intune Deployment Guide](./INTUNE-DEPLOYMENT.md) for details.

### Option 4: Group Policy

Deploy via Group Policy startup/shutdown scripts:

1. Copy scripts to SYSVOL
2. Create GPO with script assignment
3. Link to appropriate OUs

## Configuration

### Customizing Checks

Edit check modules in `modules\` directory to add/remove checks:

```powershell
# Example: Add custom check in modules\Check-AccessControls.ps1

Add-ComplianceCheck -Category "Access Controls" `
    -Check "Custom Password Policy" `
    -Requirement "Internal Policy 123" `
    -Passed $myCustomCheck `
    -CurrentValue "Current state" `
    -ExpectedValue "Expected state" `
    -Remediation "Fix command here"
```

### Output Directory

Change default output location:

```powershell
.\Run-ComplianceCheck.ps1 -OutputDirectory "C:\ComplianceReports"
```

### Scheduled Execution

Create scheduled task for regular compliance checks:

```powershell
# Run compliance check weekly
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Tools\SOC2-HIPAA-Compliance-Checker\Run-ComplianceCheck.ps1"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am

$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Weekly Compliance Check" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "SOC 2 / HIPAA compliance validation"
```

## Troubleshooting

### Issue: "Execution Policy" Error

**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Issue: "Access Denied" Errors

**Solution:** Run PowerShell as Administrator
- Right-click PowerShell icon
- Select "Run as Administrator"

### Issue: Scripts Not Found

**Solution:** Verify you're in the correct directory
```powershell
cd C:\Tools\SOC2-HIPAA-Compliance-Checker
Get-Location  # Should show the tool directory
```

### Issue: BitLocker Checks Fail

**Cause:** Windows Home edition doesn't support BitLocker

**Solution:**
- Upgrade to Windows Pro, Enterprise, or Education
- Or use third-party encryption (modify check script)

### Issue: Module Import Errors

**Solution:** Ensure all files extracted properly
```powershell
# Verify modules exist
Test-Path .\modules\Check-AuditPolicies.ps1
Test-Path .\modules\Check-AccessControls.ps1
# etc.
```

## Uninstallation

Simply delete the tool directory:

```powershell
Remove-Item -Path "C:\Tools\SOC2-HIPAA-Compliance-Checker" -Recurse -Force
```

If you created scheduled tasks, remove them:

```powershell
Unregister-ScheduledTask -TaskName "Weekly Compliance Check" -Confirm:$false
```

## Updates

To update the tool:

1. Backup your current installation
2. Download/extract new version
3. Copy any custom modifications from old version
4. Test in non-production environment

## Support

For installation issues:
- Review this guide thoroughly
- Check the main README.md
- Review error messages carefully
- Test with Quick-Check.ps1 first
