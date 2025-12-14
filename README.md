# OmniComply

## 📦 Overview

A comprehensive PowerShell-based compliance validation toolkit for Windows systems. This project provides a fully structured, ready-to-use solution for validating security configurations against multiple compliance frameworks including SOC 2, HIPAA, NIST, CIS, ISO 27001, PCI-DSS, and SOX.

## 📦 What's Included

### Complete Project Structure
```
OmniComply/
├── README.md                          # Comprehensive documentation
├── LICENSE                            # MIT License
├── .gitignore                         # Git configuration
├── Invoke-OmniComply.ps1             # Main entry point (orchestrator)
├── Quick-Check.ps1                   # Rapid validation script
│
├── modules/                          # Individual check modules (11 total)
│   ├── Check-AuditPolicies.ps1      # 26+ audit policy checks
│   ├── Check-EventLogConfiguration.ps1
│   ├── Check-FileSystemAuditing.ps1
│   ├── Check-LoggingServices.ps1
│   ├── Check-SecuritySettings.ps1
│   ├── Check-AccessControls.ps1     # Password & lockout policies
│   ├── Check-EncryptionControls.ps1 # BitLocker, TPM, Secure Boot
│   ├── Check-EndpointSecurity.ps1   # Defender, Firewall
│   ├── Check-ScreenLockSettings.ps1
│   ├── Check-UpdateCompliance.ps1
│   └── Check-NetworkSecurity.ps1    # SMB, RDP, protocols
│
├── remediation/                      # Automated fix scripts
│   ├── Remediate-AuditPolicies.ps1
│   ├── Remediate-EventLogs.ps1
│   └── Remediate-All.ps1            # Master remediation
│
├── reports/                          # Output directory for reports
│   └── .gitkeep
│
└── docs/                             # Additional documentation
    ├── CONTROLS.md                   # Detailed control mappings
    └── INSTALLATION.md               # Setup guide
```

## 🚀 Quick Start

### 1. Extract the Archive
```powershell
# Extract to your preferred location
Expand-Archive -Path OmniComply.zip -DestinationPath C:\Tools\

cd C:\Tools\OmniComply
```

### 2. Set Execution Policy
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Run Compliance Check
```powershell
# Quick validation (12 critical checks)
.\Quick-Check.ps1

# Full compliance scan (100+ checks)
.\Invoke-OmniComply.ps1
```

## 📊 What Gets Checked

### Comprehensive Coverage
- ✅ **26+ Audit Policies** - All SOC 2 and HIPAA logging requirements
- ✅ **Access Controls** - Passwords, lockouts, stale accounts
- ✅ **Encryption** - BitLocker, TPM, Secure Boot
- ✅ **Endpoint Security** - Antivirus, firewall, updates
- ✅ **Network Security** - SMB, RDP, protocols
- ✅ **Session Management** - Screen lock, automatic logoff
- ✅ **Event Logs** - Sizes, retention, activity

### Compliance Standards
- **SOC 2:** CC6.1, CC6.2, CC6.3, CC7.1, CC7.2, CC7.3, CC8.1
- **HIPAA:** §164.308 (Administrative), §164.310 (Physical), §164.312 (Technical)

## 📝 Output Reports

After running, the tool generates three report formats:

1. **JSON** - Full structured data for automation
2. **CSV** - Spreadsheet-friendly for analysis
3. **HTML** - Visual report for stakeholders

### Example Report Structure
```json
{
  "Compliant": false,
  "Timestamp": "2024-12-11T10:30:00",
  "ComputerName": "LAPTOP-001",
  "Checks": [
    {
      "Category": "Audit Policy",
      "Check": "Logon Auditing",
      "Requirement": "HIPAA § 164.308(a)(5)(ii)(C)",
      "Passed": true,
      "CurrentValue": "Success and Failure",
      "ExpectedValue": "Success and Failure",
      "Remediation": "N/A"
    }
  ]
}
```

## 🔧 Remediation

Each failed check includes specific PowerShell commands to fix it:

```powershell
# Manual remediation (copy/paste from report)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Semi-automated (run specific script)
.\remediation\Remediate-AuditPolicies.ps1

# Fully automated (use with caution!)
.\remediation\Remediate-All.ps1
```

## 🎯 Key Features

### 1. Zero Dependencies
- Uses only built-in Windows PowerShell
- No external modules required
- Works offline

### 2. Detailed Remediation
- Every failed check includes fix commands
- Step-by-step remediation scripts
- Safe to run (prompts for confirmation)

### 3. Modular Design
- Run all checks or individual modules
- Easy to customize for your environment
- Add custom checks easily

### 4. Enterprise Ready
- Deploy via Intune, GPO, or scheduled tasks
- Centralized reporting
- Batch processing for multiple systems

## 📖 Documentation

### Included Guides
- **README.md** - Comprehensive overview
- **CONTROLS.md** - Detailed SOC 2/HIPAA mappings
- **INSTALLATION.md** - Setup and deployment guide

### Key Sections to Review
1. Compliance coverage details
2. Deployment options (Intune, GPO, standalone)
3. Troubleshooting guide
4. Best practices

## 💡 Common Use Cases

### Weekly Compliance Checks
```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Tools\OmniComply\Invoke-OmniComply.ps1"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am

Register-ScheduledTask -TaskName "Compliance Check" -Action $action -Trigger $trigger
```

### Pre-Audit Validation
```powershell
# Run full check before audit
.\Invoke-OmniComply.ps1

# Review failures
notepad .\reports\OmniComply-Report-*.html

# Fix critical issues
.\remediation\Remediate-AuditPolicies.ps1

# Verify fixes
.\Invoke-OmniComply.ps1
```

### New Device Setup
```powershell
# Validate new laptop meets requirements
.\Quick-Check.ps1

# Apply all fixes
.\remediation\Remediate-All.ps1

# Confirm compliance
.\Invoke-OmniComply.ps1
```

## ⚠️ Important Notes

### Before Running
1. **Test First** - Run in non-production environment
2. **Review Scripts** - Examine remediation scripts before running
3. **Backup** - Create system restore point
4. **Document** - Keep records of changes made

### Limitations
- Requires Windows Pro/Enterprise/Education for BitLocker checks
- Some checks require domain membership
- Cannot check Azure AD/Entra ID policies (local policies only)

### Not a Silver Bullet
This tool checks technical controls. Full compliance also requires:
- Security policies and procedures
- Employee training programs
- Incident response plans
- Regular risk assessments
- Third-party audits

## 🆘 Support

### Troubleshooting
1. Check docs/INSTALLATION.md for setup issues
2. Review error messages in PowerShell
3. Verify Administrator privileges
4. Test with Quick-Check.ps1 first

### Customization
To add custom checks, edit module files in `modules/` directory:

```powershell
# Example: Add custom check
Add-ComplianceCheck -Category "Custom Category" `
    -Check "My Custom Check" `
    -Requirement "Internal Policy XYZ" `
    -Passed $myCheckResult `
    -CurrentValue "Current state" `
    -ExpectedValue "Expected state" `
    -Remediation "PowerShell command to fix"
```

## 📦 Package Contents

The compressed archive contains:
- ✅ All 11 check modules
- ✅ Main orchestration script
- ✅ Quick check script
- ✅ 3 remediation scripts
- ✅ Complete documentation
- ✅ MIT License
- ✅ Git configuration

**Total Files:** ~20 PowerShell scripts + documentation
**Total Size:** ~500KB (uncompressed)

## 🎓 Next Steps

1. **Extract** the archive to your desired location
2. **Read** the README.md for complete documentation
3. **Review** docs/CONTROLS.md to understand what's checked
4. **Test** with Quick-Check.ps1 on a single system
5. **Deploy** using your preferred method (manual, GPO, Intune)
6. **Schedule** regular compliance checks
7. **Monitor** and remediate failures

## 📞 Getting Started Now

```powershell
# 1. Open PowerShell as Administrator
# 2. Navigate to extracted folder
cd C:\Tools\OmniComply

# 3. Run quick check
.\Quick-Check.ps1

# 4. If issues found, run full check
.\Invoke-OmniComply.ps1

# 5. Review the HTML report
Invoke-Item .\reports\OmniComply-Report-*.html

# 6. Fix issues
.\remediation\Remediate-All.ps1

# 7. Verify
.\Invoke-OmniComply.ps1
```

## 🏆 Project Highlights

- **Comprehensive:** 100+ compliance checks across 11 categories
- **Actionable:** Every failure includes specific fix commands
- **Professional:** Enterprise-grade reporting (JSON, CSV, HTML)
- **Safe:** Confirmation prompts before making changes
- **Flexible:** Run all checks or individual modules
- **Well-Documented:** Complete documentation included
- **Production-Ready:** Tested and ready for deployment

---

**Version:** 1.0.0
**Created:** December 2024
**License:** MIT
**Platform:** Windows 11, Server 2016-2025

Comprehensive compliance checking for Windows endpoints.
