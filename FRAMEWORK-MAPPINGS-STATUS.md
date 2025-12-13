# Framework Mappings Status Report

## Executive Summary

ISO 27001, NIST 800-53, CIS Controls, PCI-DSS, and SOX framework mappings have been added to PowerShell compliance check modules.

**Date:** 2025-12-13
**Total Modules:** 21 requiring mappings
**Completed:** 5 modules (24%)
**Remaining:** 16 modules (76%)

## Completed Modules ✅

The following modules have been fully updated with framework mappings:

### 1. Check-BackupRecovery.ps1
- **Checks Updated:** 13
- **Frameworks Added:**
  - ISO 27001: A.10.1.2, A.12.3.1
  - NIST 800-53: CP-9, CP-9(1), SC-12
  - CIS Controls v8: 11.1, 11.2, 11.3
  - PCI-DSS: 12.10.1
  - SOX ITGC: ITGC-08

### 2. Check-EndpointSecurity.ps1
- **Checks Updated:** 3 (Antivirus & Firewall)
- **Frameworks Added:**
  - ISO 27001: A.12.2.1, A.13.1.1
  - NIST 800-53: SI-3, SI-3(1), SC-7
  - CIS Controls v8: 10.1, 13.3
  - PCI-DSS: 1.1, 1.2, 5.1, 5.1.2, 5.2

### 3. Check-NetworkSecurity.ps1
- **Checks Updated:** 4 (SMBv1, SMB Signing, RDP)
- **Frameworks Added:**
  - ISO 27001: A.9.4.2, A.12.6.2, A.13.1.1
  - NIST 800-53: AC-17, CM-7(1), SC-8, SI-2
  - CIS Controls v8: 4.8, 12.6, 13.9
  - PCI-DSS: 2.2.2, 4.2

### 4. Check-TimeSync.ps1
- **Checks Updated:** 7 (All time synchronization checks)
- **Frameworks Added:**
  - ISO 27001: A.12.4.4
  - NIST 800-53: AU-8, AU-8(1)
  - CIS Controls v8: 8.4
  - PCI-DSS: 10.4
  - SOX ITGC: ITGC-05

### 5. Check-UACSettings.ps1
- **Checks Updated:** 3 (All UAC checks)
- **Frameworks Added:**
  - ISO 27001: A.9.2.3
  - NIST 800-53: AC-6(2)
  - CIS Controls v8: 5.4
  - PCI-DSS: 7.1.2

## Modules Already Complete ✅

- **Check-EncryptionControls.ps1** - Already had full framework mappings

## Remaining Modules 📋

The following 16 modules still need framework mappings added. Complete specifications are available in `/Users/travis/git/omnicomply/FRAMEWORK-MAPPINGS-TO-ADD.md`:

### High Priority (Audit & Logging)
1. Check-EventLogConfiguration.ps1 (5 checks)
2. Check-FileSystemAuditing.ps1 (3 checks)
3. Check-LoggingServices.ps1 (3 checks)
4. Check-SecuritySettings.ps1 (4 checks)

### Medium Priority (Security Controls)
5. Check-AdvancedDefender.ps1 (8+ checks)
6. Check-AdvancedNetworkSecurity.ps1 (4 checks)
7. Check-ApplicationControl.ps1 (4+ checks)
8. Check-RemovableStorage.ps1 (5 checks)
9. Check-VirtualizationBasedSecurity.ps1 (6 checks)

### Standard Priority
10. Check-BrowserSecurity.ps1 (10+ checks)
11. Check-CertificateManagement.ps1 (6 checks)
12. Check-CredentialGuard.ps1 (3 checks)
13. Check-DNSSecurity.ps1 (5+ checks)
14. Check-InteractiveLogon.ps1 (7 checks)
15. Check-ScreenLockSettings.ps1 (2 checks)
16. Check-SharedResources.ps1 (9+ checks)

## Framework Mapping Patterns

### ISO 27001 Annex A Controls Used

| Control | Description | Modules |
|---------|-------------|---------|
| A.8.3.1 | Removable media management | Removable Storage |
| A.9.1.2 | Access to networks and services | Logon, Shared Resources |
| A.9.2.3 | Admin privileges | UAC, Access Controls |
| A.9.4.2 | Secure logon procedures | Logon, Credential Guard |
| A.9.4.3 | Password management | Credentials |
| A.10.1.1 | Cryptography - encryption | Encryption, Certificates |
| A.10.1.2 | Cryptography - key management | Encryption, Certificates, Backup |
| A.11.2.8 | Unattended equipment | Screen Lock, Logon |
| A.12.2.1 | Malware protection | Endpoint, Defender, VBS |
| A.12.3.1 | Backup | Backup & Recovery |
| A.12.4.1 | Event logging | All logging modules |
| A.12.4.4 | Clock synchronization | Time Sync |
| A.12.5.1 | Software on operational systems | Application Control |
| A.12.6.1 | Vulnerability management | Update, Patching |
| A.12.6.2 | Software installation restrictions | Network, Application Control |
| A.13.1.1 | Network controls | Network, Firewall, DNS |

### NIST 800-53 Rev. 5 Control Families

- **AC** (Access Control): Logon, UAC, Credentials
- **AU** (Audit and Accountability): Logging, Events, Time Sync
- **CM** (Configuration Management): Software, Updates
- **CP** (Contingency Planning): Backup & Recovery
- **IA** (Identification and Authentication): Credentials, Passwords
- **MP** (Media Protection): Removable Storage
- **SC** (System and Communications Protection): Network, Encryption
- **SI** (System and Information Integrity): Antivirus, Updates, VBS

### CIS Controls v8 Safeguards

- **3.x**: Data Protection (Encryption, Certificates)
- **4.x**: Secure Configuration (Updates, Browser)
- **5.x**: Account Management (UAC, Passwords, Logon)
- **8.x**: Audit Log Management (All logging modules)
- **10.x**: Malware Defenses (Endpoint, Defender, VBS)
- **11.x**: Data Recovery (Backup)
- **13.x**: Network Monitoring and Defense (Network, Firewall)

## Implementation Guide

### For Each Remaining Module:

1. Open the module file
2. Locate each `Add-ComplianceCheck` call
3. Reference `/Users/travis/git/omnicomply/FRAMEWORK-MAPPINGS-TO-ADD.md` for correct mappings
4. Add parameters in this order:
   ```powershell
   -Requirement "SOC 2/HIPAA requirement" `
   -NIST "NIST controls" `
   -CIS "CIS controls" `
   -ISO27001 "ISO 27001 controls" `
   -PCIDSS "PCI-DSS requirements" `  # If applicable
   -SOX "SOX ITGC" `  # If applicable
   ```

### Example Before:
```powershell
Add-ComplianceCheck -Category "Logging Services" `
    -Check "Windows Event Log Service Running" `
    -Requirement "HIPAA § 164.312(b) - Audit Controls Active" `
    -Passed $serviceRunning `
    -CurrentValue $eventLogService.Status `
    -ExpectedValue "Running" `
    -Remediation "Start-Service -Name EventLog"
```

### Example After:
```powershell
Add-ComplianceCheck -Category "Logging Services" `
    -Check "Windows Event Log Service Running" `
    -Requirement "HIPAA § 164.312(b) - Audit Controls Active" `
    -NIST "AU-2, AU-12" `
    -CIS "8.2" `
    -ISO27001 "A.12.4.1" `
    -SOX "ITGC-05" `
    -Passed $serviceRunning `
    -CurrentValue $eventLogService.Status `
    -ExpectedValue "Running" `
    -Remediation "Start-Service -Name EventLog"
```

## Quality Assurance

### Verification Steps:
1. Ensure ISO27001 parameter uses exact Annex A notation (e.g., "A.12.4.1")
2. NIST controls should reference Rev. 5 controls
3. CIS controls should reference v8 safeguards
4. PCI-DSS should reference v4.0 requirements
5. SOX should use ITGC-## notation

### Testing:
Run each module after updates to ensure no syntax errors:
```powershell
PowerShell -File /Users/travis/git/omnicomply/OmniComply/modules/Check-ModuleName.ps1
```

## Benefits of Multi-Framework Mapping

1. **Single Audit for Multiple Frameworks** - One compliance scan covers SOC 2, HIPAA, NIST, CIS, ISO 27001, PCI-DSS, and SOX
2. **Comprehensive Reporting** - Reports now include framework cross-references
3. **Auditor Efficiency** - Auditors can map findings to their specific framework
4. **Compliance Coverage** - Demonstrates alignment with industry best practices
5. **Risk Management** - Identifies gaps across multiple standards

## Next Steps

1. Continue adding mappings to remaining 16 modules following the priority order
2. Test each module after updates
3. Run full compliance scan to verify all mappings appear in reports
4. Update documentation with multi-framework compliance coverage

## Reference Documents

- **Mapping Specifications**: `/Users/travis/git/omnicomply/FRAMEWORK-MAPPINGS-TO-ADD.md`
- **Compliance Framework Reference**: `/Users/travis/git/omnicomply/OmniComply/docs/COMPLIANCE-FRAMEWORK-MAPPINGS.md`
- **Status Report**: This document

---

**Prepared by:** Claude Sonnet 4.5
**Project:** OmniComply Multi-Framework Compliance Tool
**Status:** Work in Progress (24% Complete)
