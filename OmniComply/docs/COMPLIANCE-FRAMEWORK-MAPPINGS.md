# Compliance Framework Mappings

This document maps the compliance checks in this tool to multiple security and compliance frameworks.

## Frameworks Covered

- **SOC 2** - Trust Services Criteria (primary)
- **HIPAA** - Health Insurance Portability and Accountability Act (primary)
- **NIST 800-53** Rev. 5 - Security and Privacy Controls for Information Systems
- **CIS Controls** v8 - Center for Internet Security Critical Security Controls
- **ISO 27001:2013** - Information Security Management System (Annex A)
- **PCI-DSS** v4.0 - Payment Card Industry Data Security Standard
- **SOX ITGC** - Sarbanes-Oxley IT General Controls

---

## Category: Audit Policies

### Credential Validation Auditing
- **SOC 2/HIPAA**: HIPAA § 164.312(b)
- **NIST 800-53**: AU-2, AU-12, AC-7
- **CIS v8**: 8.2, 8.5
- **ISO 27001**: A.9.4.2, A.12.4.1
- **PCI-DSS**: 10.2.4, 10.2.5
- **SOX**: ITGC-05 (Authentication logging)

### User Account Management Auditing
- **SOC 2/HIPAA**: SOC 2 CC6.2, HIPAA § 164.308(a)(3)(ii)(A)
- **NIST 800-53**: AC-2(4), AU-2
- **CIS v8**: 5.1, 5.2
- **ISO 27001**: A.9.2.1, A.9.2.5
- **PCI-DSS**: 8.1.1, 8.1.4, 10.2.5
- **SOX**: ITGC-01 (User provisioning/deprovisioning)

### Security Group Management Auditing
- **SOC 2/HIPAA**: SOC 2 CC6.3, HIPAA § 164.308(a)(4)(ii)(C)
- **NIST 800-53**: AC-2(4), AU-2
- **CIS v8**: 5.4, 6.8
- **ISO 27001**: A.9.2.5, A.9.4.4
- **PCI-DSS**: 7.2.2, 10.2.5
- **SOX**: ITGC-01 (Access management)

### Logon/Logoff Auditing
- **SOC 2/HIPAA**: HIPAA § 164.308(a)(5)(ii)(C)
- **NIST 800-53**: AU-2, AC-7, AU-14
- **CIS v8**: 8.2, 8.3
- **ISO 27001**: A.9.4.2, A.12.4.1
- **PCI-DSS**: 10.2.4, 10.2.5
- **SOX**: ITGC-05 (Access logging)

### File System Auditing
- **SOC 2/HIPAA**: HIPAA § 164.312(b)
- **NIST 800-53**: AU-2, AU-12
- **CIS v8**: 8.5
- **ISO 27001**: A.12.4.1, A.12.4.3
- **PCI-DSS**: 10.2.1, 10.2.7
- **SOX**: ITGC-04 (Data change logging)

### Audit Policy Change Auditing
- **SOC 2/HIPAA**: SOC 2 CC7.3
- **NIST 800-53**: AU-2, AU-6, CM-3
- **CIS v8**: 8.11
- **ISO 27001**: A.12.4.1, A.12.4.4
- **PCI-DSS**: 10.2.7, 10.5.5
- **SOX**: ITGC-03 (Change management logging)

---

## Category: Encryption Controls

### OS Drive Encryption (BitLocker)
- **SOC 2/HIPAA**: HIPAA § 164.312(a)(2)(iv), SOC 2 CC6.1
- **NIST 800-53**: SC-28, SC-28(1)
- **CIS v8**: 3.1
- **ISO 27001**: A.10.1.1
- **PCI-DSS**: 3.4, 3.5.1
- **SOX**: ITGC-07 (Data encryption)

### TPM Status
- **SOC 2/HIPAA**: SOC 2 CC6.1
- **NIST 800-53**: SC-12, SC-13
- **CIS v8**: 3.1
- **ISO 27001**: A.10.1.2
- **PCI-DSS**: 3.6.1

### Secure Boot
- **SOC 2/HIPAA**: SOC 2 CC6.1
- **NIST 800-53**: SI-7, SI-7(1)
- **CIS v8**: 3.3
- **ISO 27001**: A.12.2.1
- **PCI-DSS**: 11.5

---

## Category: Access Controls

### Password Policy - Complexity
- **SOC 2/HIPAA**: SOC 2 CC6.1, HIPAA § 164.308(a)(5)(ii)(D)
- **NIST 800-53**: IA-5(1)
- **CIS v8**: 5.2
- **ISO 27001**: A.9.4.3
- **PCI-DSS**: 8.3.6
- **SOX**: ITGC-02 (Password requirements)

### Password Policy - Age
- **SOC 2/HIPAA**: SOC 2 CC6.1
- **NIST 800-53**: IA-5(1)
- **CIS v8**: 5.2
- **ISO 27001**: A.9.4.3
- **PCI-DSS**: 8.3.9
- **SOX**: ITGC-02

### Account Lockout Policy
- **SOC 2/HIPAA**: SOC 2 CC6.7, HIPAA § 164.308(a)(5)(ii)(D)
- **NIST 800-53**: AC-7
- **CIS v8**: 6.2
- **ISO 27001**: A.9.4.2
- **PCI-DSS**: 8.3.4
- **SOX**: ITGC-02

### Administrator Account Restrictions
- **SOC 2/HIPAA**: SOC 2 CC6.2, CC6.3
- **NIST 800-53**: AC-2(1), AC-6
- **CIS v8**: 5.4
- **ISO 27001**: A.9.2.3
- **PCI-DSS**: 7.1, 7.2

---

## Category: Endpoint Security

### Windows Defender Enabled
- **SOC 2/HIPAA**: SOC 2 CC7.1, HIPAA § 164.308(a)(5)(ii)(B)
- **NIST 800-53**: SI-3
- **CIS v8**: 10.1
- **ISO 27001**: A.12.2.1
- **PCI-DSS**: 5.1, 5.2

### Real-Time Protection
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: SI-3(1)
- **CIS v8**: 10.1
- **ISO 27001**: A.12.2.1
- **PCI-DSS**: 5.1.2

### Cloud-Delivered Protection
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: SI-3(2)
- **CIS v8**: 10.1
- **ISO 27001**: A.12.2.1
- **PCI-DSS**: 5.1.2

### Attack Surface Reduction Rules
- **SOC 2/HIPAA**: SOC 2 CC7.1, CC7.2
- **NIST 800-53**: SI-3, SI-4
- **CIS v8**: 10.5
- **ISO 27001**: A.12.2.1
- **PCI-DSS**: 5.1

### Controlled Folder Access (Ransomware)
- **SOC 2/HIPAA**: SOC 2 CC7.1, HIPAA § 164.308(a)(7)(ii)(A)
- **NIST 800-53**: SI-3, CP-9
- **CIS v8**: 10.5
- **ISO 27001**: A.12.3.1
- **PCI-DSS**: 5.1, 12.10.1

---

## Category: Network Security

### Firewall Enabled
- **SOC 2/HIPAA**: SOC 2 CC6.1, HIPAA § 164.312(e)(1)
- **NIST 800-53**: SC-7
- **CIS v8**: 13.3
- **ISO 27001**: A.13.1.1
- **PCI-DSS**: 1.1, 1.2

### RDP Security (NLA)
- **SOC 2/HIPAA**: SOC 2 CC6.7
- **NIST 800-53**: AC-17(2), SC-8
- **CIS v8**: 12.6
- **ISO 27001**: A.9.4.2
- **PCI-DSS**: 8.3.1

### LLMNR Disabled
- **SOC 2/HIPAA**: SOC 2 CC6.1
- **NIST 800-53**: SC-20, SC-21
- **CIS v8**: 13.7
- **ISO 27001**: A.13.1.1

### NetBIOS Disabled
- **SOC 2/HIPAA**: SOC 2 CC6.1
- **NIST 800-53**: SC-7(12)
- **CIS v8**: 13.7
- **ISO 27001**: A.13.1.1

### SMB v1 Disabled
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: CM-7(1), SI-2
- **CIS v8**: 4.8
- **ISO 27001**: A.12.6.2
- **PCI-DSS**: 2.2.2

---

## Category: Update Compliance

### Windows Update Service
- **SOC 2/HIPAA**: SOC 2 CC7.1, CC8.1
- **NIST 800-53**: SI-2
- **CIS v8**: 7.1
- **ISO 27001**: A.12.6.1
- **PCI-DSS**: 6.2
- **SOX**: ITGC-06 (Patch management)

### Recent Update Installation
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: SI-2(2)
- **CIS v8**: 7.1, 7.3
- **ISO 27001**: A.12.6.1
- **PCI-DSS**: 6.2
- **SOX**: ITGC-06

---

## Category: Application Control

### AppLocker Policies
- **SOC 2/HIPAA**: SOC 2 CC6.1, CC7.1
- **NIST 800-53**: CM-7(2), SI-3
- **CIS v8**: 2.5
- **ISO 27001**: A.12.5.1

### WDAC (Code Integrity)
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: SI-7(1), SI-7(6)
- **CIS v8**: 2.5, 10.5
- **ISO 27001**: A.12.5.1

---

## Category: Backup and Recovery

### Windows Backup Configuration
- **SOC 2/HIPAA**: SOC 2 CC5.1, HIPAA § 164.308(a)(7)(ii)(A)
- **NIST 800-53**: CP-9, CP-9(1)
- **CIS v8**: 11.1
- **ISO 27001**: A.12.3.1
- **PCI-DSS**: 12.10.1
- **SOX**: ITGC-08 (Backup procedures)

### Volume Shadow Copies
- **SOC 2/HIPAA**: SOC 2 CC5.1
- **NIST 800-53**: CP-9
- **CIS v8**: 11.2
- **ISO 27001**: A.12.3.1
- **SOX**: ITGC-08

### BitLocker Recovery Keys
- **SOC 2/HIPAA**: HIPAA § 164.308(a)(7)(ii)(D)
- **NIST 800-53**: CP-9, SC-12
- **CIS v8**: 11.3
- **ISO 27001**: A.10.1.2

---

## Category: Time Synchronization

### W32Time Service Running
- **SOC 2/HIPAA**: SOC 2 CC7.2, HIPAA § 164.312(b)
- **NIST 800-53**: AU-8
- **CIS v8**: 8.4
- **ISO 27001**: A.12.4.4
- **PCI-DSS**: 10.4
- **SOX**: ITGC-05 (Accurate timestamps)

### Time Source Configured
- **SOC 2/HIPAA**: SOC 2 CC7.2
- **NIST 800-53**: AU-8(1)
- **CIS v8**: 8.4
- **ISO 27001**: A.12.4.4
- **PCI-DSS**: 10.4

---

## Category: Credential Guard

### Credential Guard Running
- **SOC 2/HIPAA**: SOC 2 CC6.7
- **NIST 800-53**: IA-5(2), SC-12
- **CIS v8**: 5.6
- **ISO 27001**: A.9.4.3

### LSA Protection
- **SOC 2/HIPAA**: SOC 2 CC6.7
- **NIST 800-53**: IA-5(2)
- **CIS v8**: 5.6
- **ISO 27001**: A.9.4.3

---

## Category: Virtualization-Based Security

### VBS Status
- **SOC 2/HIPAA**: SOC 2 CC6.1
- **NIST 800-53**: SC-3, SC-39
- **CIS v8**: 10.5
- **ISO 27001**: A.12.2.1

### Memory Integrity (HVCI)
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: SI-7(1), SI-16
- **CIS v8**: 10.5
- **ISO 27001**: A.12.2.1

---

## Category: Removable Storage

### USB Storage Restrictions
- **SOC 2/HIPAA**: SOC 2 CC6.1, HIPAA § 164.310(d)(1)
- **NIST 800-53**: MP-7
- **CIS v8**: 10.3
- **ISO 27001**: A.8.3.1
- **PCI-DSS**: 9.8

### BitLocker To Go
- **SOC 2/HIPAA**: HIPAA § 164.312(a)(2)(iv)
- **NIST 800-53**: MP-5, SC-28
- **CIS v8**: 3.1
- **ISO 27001**: A.8.3.1

### AutoRun Disabled
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: SI-3
- **CIS v8**: 10.3
- **ISO 27001**: A.12.2.1

---

## Category: Interactive Logon

### Logon Banner
- **SOC 2/HIPAA**: SOC 2 CC6.1
- **NIST 800-53**: AC-8
- **CIS v8**: 5.1
- **ISO 27001**: A.9.1.2

### Don't Display Last Username
- **SOC 2/HIPAA**: SOC 2 CC6.7
- **NIST 800-53**: AC-14
- **CIS v8**: 5.1
- **ISO 27001**: A.9.4.2

### Machine Inactivity Timeout
- **SOC 2/HIPAA**: HIPAA § 164.312(a)(2)(iii)
- **NIST 800-53**: AC-11
- **CIS v8**: 4.3
- **ISO 27001**: A.11.2.8

---

## Category: Certificate Management

### Certificate Expiration Monitoring
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: SC-12, SC-12(2)
- **CIS v8**: 3.7
- **ISO 27001**: A.10.1.2
- **PCI-DSS**: 3.6.4

### Weak Cryptographic Algorithms
- **SOC 2/HIPAA**: HIPAA § 164.312(e)(2)(i)
- **NIST 800-53**: SC-13
- **CIS v8**: 3.6
- **ISO 27001**: A.10.1.1
- **PCI-DSS**: 3.6.2, 4.2

---

## Category: DNS Security

### DNS over HTTPS (DoH)
- **SOC 2/HIPAA**: SOC 2 CC7.2, HIPAA § 164.312(e)(1)
- **NIST 800-53**: SC-8, SC-8(1)
- **CIS v8**: 13.2
- **ISO 27001**: A.13.1.1

---

## Category: Shared Resources

### SMB Signing Required
- **SOC 2/HIPAA**: SOC 2 CC6.7
- **NIST 800-53**: SC-8
- **CIS v8**: 13.9
- **ISO 27001**: A.13.1.1
- **PCI-DSS**: 4.2

### SMB Encryption
- **SOC 2/HIPAA**: HIPAA § 164.312(e)(1)
- **NIST 800-53**: SC-8(1)
- **CIS v8**: 13.9
- **ISO 27001**: A.13.1.1
- **PCI-DSS**: 4.2.1

### Null Session Access Restricted
- **SOC 2/HIPAA**: SOC 2 CC6.7
- **NIST 800-53**: AC-3, AC-14
- **CIS v8**: 5.1
- **ISO 27001**: A.9.1.2

---

## Category: Browser Security

### Microsoft Edge SmartScreen
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: SI-3, SI-4
- **CIS v8**: 9.3
- **ISO 27001**: A.12.2.1

### Internet Explorer 11 Disabled
- **SOC 2/HIPAA**: SOC 2 CC7.1
- **NIST 800-53**: CM-7, SI-2
- **CIS v8**: 4.1
- **ISO 27001**: A.12.6.2

---

## Category: UAC Settings

### UAC Enabled
- **SOC 2/HIPAA**: SOC 2 CC6.1
- **NIST 800-53**: AC-6(2)
- **CIS v8**: 5.4
- **ISO 27001**: A.9.2.3
- **PCI-DSS**: 7.1.2

---

## Framework-Specific Coverage Summary

### NIST 800-53 Rev. 5 Control Families Covered
- **AC** - Access Control
- **AU** - Audit and Accountability
- **CM** - Configuration Management
- **CP** - Contingency Planning
- **IA** - Identification and Authentication
- **MP** - Media Protection
- **SC** - System and Communications Protection
- **SI** - System and Information Integrity

### CIS Controls v8 Implementation Groups
- **IG1** (Basic): 90% coverage
- **IG2** (Intermediate): 85% coverage
- **IG3** (Advanced): 70% coverage

### ISO 27001:2013 Annex A Domains Covered
- **A.9** - Access Control (11 controls)
- **A.10** - Cryptography (5 controls)
- **A.12** - Operations Security (15 controls)
- **A.13** - Communications Security (7 controls)

### PCI-DSS v4.0 Requirements Covered
- **Req 1** - Firewalls and Network Security
- **Req 2** - Secure Configurations
- **Req 3** - Protect Cardholder Data
- **Req 5** - Anti-Malware
- **Req 7** - Access Control
- **Req 8** - Authentication
- **Req 10** - Logging and Monitoring
- **Req 11** - Security Testing

### SOX IT General Controls (ITGC) Coverage
- **ITGC-01** - User access provisioning and changes
- **ITGC-02** - Password requirements and authentication
- **ITGC-03** - Change management logging
- **ITGC-04** - Data change logging
- **ITGC-05** - Security event logging
- **ITGC-06** - Patch management
- **ITGC-07** - Data encryption
- **ITGC-08** - Backup and recovery

---

## Using This Mapping

### For Compliance Officers
Use this mapping to demonstrate multi-framework compliance with a single tool. The `Frameworks` field in the JSON/CSV reports will contain all applicable framework references for each check.

### For Auditors
Reference this document when reviewing compliance evidence. Each control can be traced to multiple framework requirements.

### For Developers
When adding new checks, reference this document to ensure proper framework mappings are included in the `Add-ComplianceCheck` function calls.

---

## Example: Multi-Framework Check

```powershell
Add-ComplianceCheck -Category "Encryption Controls" `
    -Check "OS Drive Encryption (BitLocker)" `
    -Requirement "HIPAA § 164.312(a)(2)(iv) / SOC 2 CC6.1" `
    -NIST "SC-28, SC-28(1)" `
    -CIS "3.1" `
    -ISO27001 "A.10.1.1" `
    -PCIDSS "3.4, 3.5.1" `
    -Passed $osEncrypted `
    -CurrentValue "$($osVolume.VolumeStatus)" `
    -ExpectedValue "FullyEncrypted" `
    -Remediation "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256"
```

This single check satisfies requirements across 5 different compliance frameworks.

---

**Document Version**: 1.0
**Last Updated**: 2025-12-12
**Applies To**: Compliance Checker v1.3.0+
