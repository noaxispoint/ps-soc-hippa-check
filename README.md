# OmniComply

## License

MIT License

Copyright (c) 2024 OmniComply Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 📦 Overview

A comprehensive PowerShell-based compliance validation toolkit for Windows systems. This project provides a fully structured, ready-to-use solution for validating security configurations against multiple compliance frameworks including SOC 2, HIPAA, NIST 800-53, CIS Controls v8, ISO 27001:2013, PCI-DSS, SOX, GDPR (General Data Protection Regulation), and CCPA (California Consumer Privacy Act).

## 📦 What's Included

### Complete Project Structure
```
OmniComply/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── .gitignore                         # Git configuration
├── Invoke-OmniComply.ps1             # Main entry point (orchestrator)
├── Quick-Check.ps1                   # Rapid validation script
│
├── modules/                          # Individual check modules (36 total)
│   ├── Check-AccessControls.ps1      # Password & lockout policies
│   ├── Check-AdministratorAccounts.ps1
│   ├── Check-AdvancedDefender.ps1    # ASR, Network Protection, Cloud Protection
│   ├── Check-AdvancedNetworkSecurity.ps1
│   ├── Check-ApplicationControl.ps1  # AppLocker, WDAC, SmartScreen
│   ├── Check-AuditPolicies.ps1       # 26+ audit policy checks
│   ├── Check-BackupAndRecovery.ps1   # System Restore, VSS, Backup (GDPR Art. 32.1.c)
│   ├── Check-BackupRecovery.ps1
│   ├── Check-BrowserSecurity.ps1
│   ├── Check-CertificateManagement.ps1
│   ├── Check-ChangeManagement.ps1
│   ├── Check-CredentialGuard.ps1     # Credential Guard, LSA Protection
│   ├── Check-DatabaseSecurity.ps1
│   ├── Check-DataIntegrity.ps1
│   ├── Check-DataRetentionDestruction.ps1
│   ├── Check-DNSSecurity.ps1
│   ├── Check-EncryptionControls.ps1  # BitLocker, TPM, Secure Boot
│   ├── Check-EndpointSecurity.ps1    # Defender, Firewall
│   ├── Check-EventLogConfiguration.ps1
│   ├── Check-FileSystemAuditing.ps1
│   ├── Check-InteractiveLogon.ps1
│   ├── Check-LoggingServices.ps1
│   ├── Check-NetworkEncryption.ps1   # TLS, SMB encryption, LDAP signing (GDPR Art. 32.1.a)
│   ├── Check-NetworkSecurity.ps1     # SMB, RDP, LLMNR, NetBIOS
│   ├── Check-NetworkSegmentation.ps1
│   ├── Check-PrivacySettings.ps1     # Telemetry, location, data minimization (GDPR/CCPA)
│   ├── Check-RemovableStorage.ps1    # USB controls, BitLocker To Go
│   ├── Check-ScreenLockSettings.ps1
│   ├── Check-SecuritySettings.ps1
│   ├── Check-SegregationOfDuties.ps1
│   ├── Check-SharedResources.ps1
│   ├── Check-TimeSync.ps1
│   ├── Check-UACSettings.ps1         # User Account Control
│   ├── Check-UpdateCompliance.ps1    # Windows Update status
│   ├── Check-VirtualizationBasedSecurity.ps1
│   └── Check-VulnerabilityManagement.ps1
│
├── remediation/                      # Automated fix scripts
│   ├── Remediate-All.ps1             # Master remediation (runs all)
│   ├── Remediate-AuditPolicies.ps1
│   ├── Remediate-NetworkSecurity.ps1 # SMB, LLMNR, NetBIOS, RDP
│   ├── Remediate-PasswordPolicies.ps1
│   └── Remediate-WindowsDefender.ps1 # Defender, Firewall, signatures
│
├── reports/                          # Output directory for reports
│   └── .gitkeep
│
└── docs/                             # Additional documentation
    ├── CONTROLS.md                   # Detailed control mappings
    └── INSTALLATION.md               # Setup guide
```

## 🚀 Quick Start

### 1. Clone or Download
```powershell
# Clone from GitHub
git clone https://github.com/yourusername/omnicomply.git
cd omnicomply

# Or download and extract ZIP
Expand-Archive -Path OmniComply.zip -DestinationPath C:\Tools\
cd C:\Tools\omnicomply
```

### 2. Set Execution Policy
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Run Compliance Check
```powershell
# Navigate to the OmniComply directory
cd OmniComply

# Quick validation (12 critical checks)
.\Quick-Check.ps1

# Full compliance scan (150+ checks across 33 modules)
.\Invoke-OmniComply.ps1
```

## 📊 What Gets Checked

### Comprehensive Coverage (150+ Checks Across 33 Modules)
- ✅ **26+ Audit Policies** - All SOC 2 and HIPAA logging requirements
- ✅ **Access Controls** - Passwords, lockouts, stale accounts
- ✅ **Encryption** - BitLocker, TPM, Secure Boot
- ✅ **Endpoint Security** - Antivirus, firewall, updates, real-time protection
- ✅ **Network Security** - SMB, RDP, LLMNR, NetBIOS, protocols
- ✅ **Session Management** - Screen lock, automatic logoff
- ✅ **Event Logs** - Sizes, retention, activity
- ✅ **Advanced Defender** - ASR rules, Network Protection, Cloud Protection
- ✅ **Application Control** - AppLocker, WDAC, SmartScreen
- ✅ **Credential Protection** - Credential Guard, LSA Protection
- ✅ **Removable Storage** - USB controls, BitLocker To Go, AutoRun
- ✅ **User Account Control** - UAC settings and prompt levels
- ✅ **Virtualization-Based Security** - VBS, HVCI
- ✅ **Browser Security** - Edge/Chrome security settings
- ✅ **Certificate Management** - Expired certs, trusted roots
- ✅ **Time Synchronization** - NTP configuration
- ✅ **And 17 more modules...**

### Compliance Standards
- **SOC 2:** CC6.1, CC6.2, CC6.3, CC6.7, CC7.1, CC7.2, CC7.3, CC8.1
- **HIPAA:** §164.308 (Administrative), §164.310 (Physical), §164.312 (Technical)
- **NIST 800-53:** 100+ control mappings (AC, AU, CM, IA, SC, SI, etc.)
- **CIS Controls v8:** Critical security controls 1-18
- **ISO 27001:2013:** Annex A control mappings
- **PCI-DSS:** Requirements 1-12
- **SOX:** IT General Controls (ITGC)

## 📝 Output Reports

After running, the tool generates three report formats:

1. **JSON** - Full structured data for automation and API integration
2. **CSV** - Spreadsheet-friendly for analysis and filtering
3. **HTML** - Professional visual report for stakeholders with Intune recommendations

### Example HTML Report Features
- Executive summary with pass/fail statistics
- Categorized findings with compliance framework mappings
- Specific remediation commands for each failure
- **NEW:** Microsoft Intune policy paths for enterprise deployment
- Color-coded severity levels
- Exportable and shareable format

### Intune Integration
Each failed check now includes specific Microsoft Intune policy paths, enabling enterprise admins to:
- Deploy fixes fleet-wide via Intune configuration profiles
- Navigate directly to the correct Intune policy location
- Configure settings once and apply to all managed devices
- Ensure consistent compliance across the organization

Example Intune recommendation:
```
Devices > Configuration profiles > Create profile > Settings catalog >
Administrative Templates > Windows Components > BitLocker Drive Encryption >
Operating System Drives > Require Device Encryption = Yes
```

## 🔧 Remediation

Each failed check includes specific PowerShell commands to fix it:

```powershell
# Manual remediation (copy/paste from report)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Semi-automated (run specific script with confirmation prompts)
.\remediation\Remediate-AuditPolicies.ps1

# Semi-automated (skip confirmation prompts)
.\remediation\Remediate-NetworkSecurity.ps1 -Force

# Fully automated (use with caution!)
.\remediation\Remediate-All.ps1 -IUnderstandTheRisksAndAccept
```

### Available Remediation Scripts
1. **Remediate-AuditPolicies.ps1** - Configures all required audit policies
2. **Remediate-NetworkSecurity.ps1** - Disables SMBv1, LLMNR, NetBIOS; enables signing
3. **Remediate-PasswordPolicies.ps1** - Sets password complexity and length requirements
4. **Remediate-WindowsDefender.ps1** - Enables real-time protection, updates signatures
5. **Remediate-All.ps1** - Runs all remediation scripts sequentially

All scripts support `-Force` parameter to bypass confirmation prompts for automation.

## 🎯 Key Features

### 1. Zero Dependencies
- Uses only built-in Windows PowerShell
- No external modules required
- Works offline

### 2. Detailed Remediation
- Every failed check includes fix commands
- Step-by-step remediation scripts with safety prompts
- Automated remediation options with `-Force` parameter
- Microsoft Intune policy paths for enterprise deployment

### 3. Modular Design
- Run all checks or individual modules
- Easy to customize for your environment
- Add custom checks easily via `Add-ComplianceCheck` function

### 4. Enterprise Ready
- Deploy via Intune, GPO, or scheduled tasks
- Centralized reporting (JSON, CSV, HTML)
- Batch processing for multiple systems
- Intune policy recommendations for fleet-wide deployment
- Support for automated execution (`-Force`, `-IUnderstandTheRisksAndAccept`)

### 5. Multi-Framework Compliance
- Single tool checks against 7+ compliance frameworks simultaneously
- Cross-referenced control mappings
- Comprehensive coverage reduces audit preparation time

## 📖 Documentation

### Included Guides
- **README.md** - This comprehensive overview
- **CONTROLS.md** - Detailed SOC 2/HIPAA/NIST/CIS/ISO mappings
- **INSTALLATION.md** - Setup and deployment guide

All documentation available in both Markdown (.md) and HTML (.html) formats.

### Key Sections to Review
1. Compliance coverage details (docs/CONTROLS.md)
2. Deployment options - Intune, GPO, standalone (docs/INSTALLATION.md)
3. Troubleshooting guide (docs/INSTALLATION.md)
4. Best practices for remediation

## 💡 Common Use Cases

### Weekly Compliance Checks
```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Tools\omnicomply\OmniComply\Invoke-OmniComply.ps1"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am

Register-ScheduledTask -TaskName "Weekly Compliance Check" -Action $action -Trigger $trigger
```

### Pre-Audit Validation
```powershell
# Run full check before audit
.\Invoke-OmniComply.ps1

# Review failures
Invoke-Item .\reports\OmniComply-Report-*.html

# Fix critical issues
.\remediation\Remediate-AuditPolicies.ps1 -Force
.\remediation\Remediate-WindowsDefender.ps1 -Force

# Verify fixes
.\Invoke-OmniComply.ps1
```

### New Device Setup
```powershell
# Validate new laptop meets requirements
.\Quick-Check.ps1

# Apply all fixes (with confirmation)
.\remediation\Remediate-All.ps1

# Or apply all fixes without prompts (automated deployment)
.\remediation\Remediate-All.ps1 -IUnderstandTheRisksAndAccept

# Confirm compliance
.\Invoke-OmniComply.ps1
```

### Intune Deployment (Enterprise)
```powershell
# Run compliance check
.\Invoke-OmniComply.ps1

# Review HTML report for Intune recommendations
Invoke-Item .\reports\OmniComply-Report-*.html

# Navigate to Microsoft Intune admin center
# Follow the Intune policy paths from the report to deploy settings fleet-wide
```

## ⚠️ Important Notes

### Before Running
1. **Test First** - Run in non-production environment
2. **Review Scripts** - Examine remediation scripts before running
3. **Backup** - Create system restore point
4. **Document** - Keep records of changes made
5. **Administrator Rights** - All scripts require elevation

### Limitations
- Requires Windows 10/11 Pro/Enterprise/Education for full feature support
- Some checks require domain membership (AD-specific policies)
- Cannot check Azure AD/Entra ID cloud policies (local policies only)
- Credential Guard and VBS features require Enterprise/Education editions
- BitLocker checks require TPM 2.0 and compatible hardware

### Not a Silver Bullet
This tool checks technical controls. Full compliance also requires:
- Security policies and procedures documentation
- Employee security awareness training programs
- Incident response and disaster recovery plans
- Regular risk assessments and vulnerability scans
- Third-party security audits and penetration testing
- Data classification and handling procedures
- Vendor risk management programs

## 🆘 Support & Troubleshooting

### Common Issues

**"Execution Policy" Error**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"Access Denied" or Permission Errors**
```powershell
# Run PowerShell as Administrator (required)
# Right-click PowerShell > "Run as Administrator"
```

**"Module Not Found" Errors**
```powershell
# Ensure you're in the OmniComply directory
cd OmniComply
.\Invoke-OmniComply.ps1
```

### Customization
To add custom checks, edit module files in `modules/` directory:

```powershell
# Example: Add custom check to any module
Add-ComplianceCheck -Category "Custom Category" `
    -Check "My Custom Check" `
    -Requirement "Internal Policy XYZ" `
    -NIST "AC-2" `
    -CIS "5.1" `
    -ISO27001 "A.9.2.1" `
    -Passed $myCheckResult `
    -CurrentValue "Current state" `
    -ExpectedValue "Expected state" `
    -Remediation "PowerShell command to fix" `
    -IntuneRecommendation "Devices > Configuration profiles > ..."
```

## 📦 Package Contents

### Scripts
- **33 Check Modules** - Comprehensive compliance validation
- **1 Main Orchestrator** - Invoke-OmniComply.ps1
- **1 Quick Check** - Quick-Check.ps1
- **5 Remediation Scripts** - Automated fixes with safety prompts
- **1 Conversion Utility** - convert_md_to_html.py

### Documentation
- README.md / README.html
- CONTROLS.md / CONTROLS.html
- INSTALLATION.md / INSTALLATION.html
- CHANGELOG.md / CHANGELOG.html
- CONTRIBUTING.md / CONTRIBUTING.html
- LICENSE

**Total Files:** ~45 PowerShell scripts + documentation + utilities
**Total Size:** ~1.5MB (uncompressed)

## 🎓 Next Steps

1. **Clone/Download** the repository
2. **Read** the README.md and INSTALLATION.md
3. **Review** docs/CONTROLS.md to understand what's checked
4. **Test** with Quick-Check.ps1 on a single system
5. **Run** full scan with Invoke-OmniComply.ps1
6. **Review** HTML report and Intune recommendations
7. **Remediate** failures using provided scripts or Intune policies
8. **Deploy** using your preferred method (manual, GPO, Intune, scheduled task)
9. **Schedule** regular compliance checks (weekly/monthly)
10. **Monitor** and maintain compliance over time

## 📞 Getting Started Now

```powershell
# 1. Open PowerShell as Administrator
# 2. Navigate to the OmniComply folder
cd C:\Tools\omnicomply\OmniComply

# 3. Run quick check (12 critical checks)
.\Quick-Check.ps1

# 4. Run full compliance scan (150+ checks)
.\Invoke-OmniComply.ps1

# 5. Review the HTML report
Invoke-Item .\reports\OmniComply-Report-*.html

# 6. Fix issues using provided remediation scripts
.\remediation\Remediate-WindowsDefender.ps1 -Force
.\remediation\Remediate-NetworkSecurity.ps1 -Force
.\remediation\Remediate-AuditPolicies.ps1 -Force

# 7. Verify compliance
.\Invoke-OmniComply.ps1

# 8. (Enterprise) Deploy Intune policies from report recommendations
```

## 🏆 Project Highlights

- **Comprehensive:** 150+ compliance checks across 33 modules
- **Multi-Framework:** SOC 2, HIPAA, NIST, CIS, ISO 27001, PCI-DSS, SOX
- **Actionable:** Every failure includes specific fix commands
- **Enterprise-Ready:** Intune policy paths for fleet-wide deployment
- **Professional:** Enterprise-grade reporting (JSON, CSV, HTML)
- **Safe:** Confirmation prompts before making changes (override with `-Force`)
- **Flexible:** Run all checks or individual modules
- **Well-Documented:** Complete documentation in MD and HTML formats
- **Production-Ready:** Tested on Windows 10/11 and Server 2016-2025
- **Open Source:** MIT License - use freely in your organization

---

## 📊 Statistics

- **36** compliance check modules
- **170+** individual security checks
- **9** compliance frameworks (SOC 2, HIPAA, NIST, CIS, ISO 27001, PCI-DSS, SOX, GDPR, CCPA)
- **53** Intune policy recommendations
- **5** automated remediation scripts
- **3** report output formats (JSON, CSV, HTML)

---

**Version:** 1.4.0
**Created:** 2025
**License:** MIT
**Platform:** Windows 10/11, Server 2016-2025
**Repository:** https://github.com/noaxispoint/omnicomply

Comprehensive compliance checking for Windows endpoints - from workstations to servers. Now including GDPR and CCPA privacy controls.
