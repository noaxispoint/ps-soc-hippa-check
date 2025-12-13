# OmniComply
**Universal Multi-Framework Security Compliance Validator for Windows**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20|%20Server%202019%2F2022-brightgreen)](https://www.microsoft.com/windows)
[![Architecture](https://img.shields.io/badge/Architecture-x64%20|%20ARM64-orange)](https://docs.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

![](https://img.shields.io/badge/Frameworks-7-blueviolet)
![](https://img.shields.io/badge/Modules-33-blue)
![](https://img.shields.io/badge/Checks-280%2B-success)

---

## 🎯 Overview

**OmniComply** is a comprehensive PowerShell-based security and compliance validation tool that audits Windows systems against **multiple compliance frameworks simultaneously**. Instead of running separate tools for each framework, OmniComply provides a unified assessment across:

- **SOC 2** Trust Services Criteria
- **HIPAA** Security Rule
- **NIST 800-53** Rev. 5
- **CIS Controls** v8
- **ISO 27001:2013**
- **PCI-DSS** v4.0
- **SOX** IT General Controls (ITGC)

With **280+ technical compliance checks** across **33 security domains**, OmniComply helps organizations demonstrate multi-framework compliance with a single tool.

---

## ✨ Key Features

- ✅ **Multi-Framework Compliance** - Single scan generates evidence for 7+ frameworks
- ✅ **Comprehensive Coverage** - 280+ checks across 33 security domains
- ✅ **Automated Remediation Guidance** - PowerShell commands to fix issues
- ✅ **Multiple Report Formats** - JSON, CSV, and HTML reports
- ✅ **ARM64 Compatible** - Full support for Windows on ARM devices
- ✅ **No Agent Required** - Pure PowerShell, no installation needed
- ✅ **Offline Capable** - No internet connection required
- ✅ **Enterprise Ready** - Suitable for SIEM integration and automation

---

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 or Windows Server 2019/2022
- PowerShell 5.1 or later
- Administrator privileges

### Basic Usage

1. **Clone or download this repository:**
   ```powershell
   git clone https://github.com/yourusername/omnicomply.git
   cd omnicomply/OmniComply
   ```

2. **Run the complete compliance scan:**
   ```powershell
   .\Invoke-OmniComply.ps1
   ```

3. **Run a quick check (critical controls only):**
   ```powershell
   .\Quick-Check.ps1
   ```

4. **View generated reports:**
   Reports are saved to `.\reports\` by default in JSON, CSV, and HTML formats.

---

## 📊 Compliance Frameworks Covered

### SOC 2 Trust Services Criteria
- **CC5.1** - COSO Internal Control Monitoring
- **CC6.1** - Logical Access Controls
- **CC6.2** - Access Credentials
- **CC6.3** - Access Removal
- **CC6.7** - Authentication & Authorization
- **CC7.1** - Security Incident Detection
- **CC7.2** - Security Event Monitoring
- **CC7.3** - Security Event Evaluation
- **CC8.1** - Change Management

### HIPAA Security Rule
- **§ 164.308(a)** - Administrative Safeguards
- **§ 164.310** - Physical Safeguards
- **§ 164.312** - Technical Safeguards
- **§ 164.316** - Audit Controls

### NIST 800-53 Rev. 5
- **AC** - Access Control (18 controls)
- **AU** - Audit and Accountability (15 controls)
- **CM** - Configuration Management (12 controls)
- **CP** - Contingency Planning (8 controls)
- **IA** - Identification and Authentication (10 controls)
- **MP** - Media Protection (6 controls)
- **SC** - System and Communications Protection (20 controls)
- **SI** - System and Information Integrity (14 controls)

### CIS Controls v8
- **IG1** - Basic Cyber Hygiene (90% coverage)
- **IG2** - Intermediate Security Controls (85% coverage)
- **IG3** - Advanced Security Controls (70% coverage)

### ISO 27001:2013 Annex A
- **A.9** - Access Control (11 controls)
- **A.10** - Cryptography (5 controls)
- **A.12** - Operations Security (15 controls)
- **A.13** - Communications Security (7 controls)

### PCI-DSS v4.0
- **Req 1** - Firewalls & Network Security
- **Req 2** - Secure Configurations
- **Req 3** - Protect Cardholder Data
- **Req 5** - Anti-Malware
- **Req 7** - Access Control
- **Req 8** - Authentication
- **Req 10** - Logging & Monitoring
- **Req 11** - Security Testing

### SOX IT General Controls (ITGC)
- **ITGC-01** - User Access Management
- **ITGC-02** - Password & Authentication
- **ITGC-03** - Change Management
- **ITGC-04** - Data Integrity
- **ITGC-05** - Security Event Logging
- **ITGC-06** - Patch Management
- **ITGC-07** - Data Encryption
- **ITGC-08** - Backup & Recovery

---

## 📁 Compliance Modules (33 Total)

### Core Security Baseline
1. **Audit Policies** - Advanced audit policy configuration
2. **Event Log Configuration** - Log size, retention, and protection
3. **File System Auditing** - NTFS permission auditing
4. **Logging Services** - Windows Event Log service
5. **Security Settings** - Password policies, account lockout
6. **Access Controls** - User rights assignments
7. **Encryption Controls** - BitLocker, TPM, Secure Boot
8. **Endpoint Security** - Windows Defender, real-time protection
9. **Screen Lock Settings** - Inactivity timeouts
10. **Update Compliance** - Windows Update status
11. **Network Security** - Firewall, RDP, SMB settings

### Advanced Security
12. **UAC Settings** - User Account Control
13. **Administrator Accounts** - Admin group membership
14. **Advanced Network Security** - LLMNR, NetBIOS, RDP NLA
15. **Time Synchronization** - NTP configuration
16. **Advanced Defender** - ASR rules, Controlled Folder Access
17. **Virtualization-Based Security** - VBS, HVCI, Core Isolation
18. **Credential Guard** - Credential theft protection
19. **Application Control** - AppLocker, WDAC
20. **Removable Storage** - USB controls, BitLocker To Go
21. **Interactive Logon** - Banners, session policies

### Enterprise & Compliance
22. **Certificate Management** - Certificate expiration, validation
23. **DNS Security** - DNS over HTTPS, secure DNS
24. **Shared Resources** - SMB shares, permissions
25. **Browser Security** - Edge, Internet Explorer settings
26. **Backup & Recovery** - Windows Backup, VSS, restore points

### PCI-DSS Specific
27. **Network Segmentation** - VLANs, firewall rules, IPsec
28. **Database Security** - SQL Server hardening
29. **Vulnerability Management** - Scanning, patch management
30. **Data Retention & Destruction** - Retention policies, secure deletion

### SOX Specific
31. **Change Management** - Change logging, approval tracking
32. **Segregation of Duties** - Role conflicts, shared accounts
33. **Data Integrity** - Transaction logging, audit protection

---

## 📖 Usage Examples

### Standard Compliance Scan
```powershell
.\Invoke-OmniComply.ps1
```

### Custom Report Directory
```powershell
.\Invoke-OmniComply.ps1 -OutputDirectory "C:\Compliance\Reports"
```

### Console Output Only (No Reports)
```powershell
.\Invoke-OmniComply.ps1 -SkipReportGeneration
```

### Quick Assessment (Critical Controls)
```powershell
.\Quick-Check.ps1
```

---

## 📄 Report Formats

OmniComply generates three report formats:

### 1. JSON Report
- **Use case**: SIEM integration, automation, API consumption
- **Contains**: Full compliance data with framework mappings
- **Example**: `OmniComply-Report-20251213-143022.json`

### 2. CSV Report
- **Use case**: Spreadsheet analysis, filtering, pivot tables
- **Contains**: All checks in tabular format
- **Example**: `OmniComply-Report-20251213-143022.csv`

### 3. HTML Report
- **Use case**: Executive reporting, audit evidence
- **Contains**: Summary, failed checks, category breakdown
- **Example**: `OmniComply-Report-20251213-143022.html`

---

## 🏗️ Architecture

```
OmniComply/
├── Invoke-OmniComply.ps1      # Main orchestration script
├── Quick-Check.ps1             # Rapid critical control validation
├── modules/                    # Individual compliance check modules (33)
│   ├── Check-AuditPolicies.ps1
│   ├── Check-EncryptionControls.ps1
│   ├── Check-NetworkSegmentation.ps1
│   └── ...
├── docs/                       # Documentation
│   ├── COMPLIANCE-FRAMEWORK-MAPPINGS.md
│   └── REMEDIATION.md
├── remediation/                # Automated fix scripts
└── reports/                    # Generated compliance reports
```

---

## 🛠️ Remediation

Each failed check includes PowerShell remediation commands. Example:

```powershell
# Issue: BitLocker not enabled
# Remediation:
Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -RecoveryPasswordProtector
```

See `docs/REMEDIATION.md` for detailed remediation guidance.

---

## 🌐 Platform Compatibility

| Platform | Architecture | Status |
|----------|-------------|--------|
| Windows 10 | x64 | ✅ Fully Supported |
| Windows 10 | ARM64 | ✅ Fully Supported* |
| Windows 11 | x64 | ✅ Fully Supported |
| Windows 11 | ARM64 | ✅ Fully Supported* |
| Server 2019 | x64 | ✅ Fully Supported |
| Server 2022 | x64 | ✅ Fully Supported |
| Server 2022 | ARM64 | ✅ Fully Supported* |

*ARM devices: Some checks (e.g., Secure Boot detection) may vary by device manufacturer.

---

## 🔒 Security Considerations

- **Read-Only**: OmniComply performs read-only checks and does not modify system configuration
- **No Telemetry**: No data is sent externally
- **No Installation**: Pure PowerShell scripts, no agent required
- **Audit Safe**: All actions are logged in Windows Event Logs
- **Open Source**: Full transparency - review the code yourself

---

## 📚 Documentation

- **[Compliance Framework Mappings](docs/COMPLIANCE-FRAMEWORK-MAPPINGS.md)** - Detailed framework-to-control mappings
- **[Remediation Guide](docs/REMEDIATION.md)** - Fix guidance for common issues

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

OmniComply is a compliance assessment tool and does not guarantee compliance with any framework. Organizations should:

- Validate results with qualified compliance professionals
- Perform regular manual reviews
- Implement defense-in-depth security practices
- Maintain current compliance documentation

Compliance is an ongoing process requiring people, processes, and technology.

---

## 🏆 Version History

### v1.4.0 (Current)
- **New**: Multi-framework support (NIST, CIS, ISO, PCI-DSS, SOX)
- **New**: PCI-DSS specific modules (Network Segmentation, Database Security, Vulnerability Management, Data Retention)
- **New**: SOX ITGC modules (Change Management, Segregation of Duties, Data Integrity)
- **Enhanced**: All checks now mapped to 7 frameworks
- **Improved**: ARM64 architecture detection and compatibility
- **Total**: 33 modules, 280+ checks

### v1.3.0
- **New**: Phase 3 modules (Certificates, DNS, Shared Resources, Browser, Backup)
- **Total**: 26 modules, 230+ checks

### v1.2.0
- **New**: Phase 1 & 2 modules (UAC, Admin Accounts, VBS, Credential Guard, etc.)
- **Enhanced**: ARM compatibility warnings
- **Total**: 21 modules, 180+ checks

### v1.1.0
- **New**: ARM architecture detection
- **Fixed**: UTF-8 BOM encoding issues
- **Total**: 16 modules, 100+ checks

### v1.0.0
- **Initial**: SOC 2 and HIPAA baseline modules
- **Total**: 11 modules, 100+ checks

---

**Made with ❤️ for the compliance community**

*Version 1.4.0 - December 2025*
