# ISO 27001 and Framework Mappings to Add

This document contains the framework mappings that need to be added to each PowerShell compliance module.

## Completed Modules
- ✅ Check-BackupRecovery.ps1
- ✅ Check-EndpointSecurity.ps1
- ✅ Check-NetworkSecurity.ps1 (partial)
- ✅ Check-EncryptionControls.ps1 (already had mappings)

## Mappings Reference

### Check-AdvancedDefender.ps1

**Controlled Folder Access (Ransomware Protection)**
- ISO27001: A.12.3.1
- NIST: SI-3, CP-9
- CIS: 10.5
- PCIDSS: 5.1, 12.10.1

**Network Protection**
- ISO27001: A.12.2.1
- NIST: SI-3, SI-4
- CIS: 10.1

**Cloud-Delivered Protection**
- ISO27001: A.12.2.1
- NIST: SI-3(2)
- CIS: 10.1
- PCIDSS: 5.1.2

**Behavior Monitoring**
- ISO27001: A.12.2.1
- NIST: SI-3(1)
- CIS: 10.1

**PUA Protection**
- ISO27001: A.12.2.1
- NIST: SI-3
- CIS: 10.1

**Attack Surface Reduction Rules**
- ISO27001: A.12.2.1
- NIST: SI-3, SI-4
- CIS: 10.5
- PCIDSS: 5.1

**Exploit Protection (DEP, SEHOP)**
- ISO27001: A.12.2.1
- NIST: SI-16, SI-7(1)
- CIS: 10.5

### Check-AdvancedNetworkSecurity.ps1

**LLMNR Disabled**
- ISO27001: A.13.1.1
- NIST: SC-20, SC-21
- CIS: 13.7

**NetBIOS over TCP/IP Disabled**
- ISO27001: A.13.1.1
- NIST: SC-7(12)
- CIS: 13.7

**RDP Network Level Authentication**
- ISO27001: A.9.4.2
- NIST: AC-17(2), SC-8
- CIS: 12.6
- PCIDSS: 8.3.1

**Firewall Logging Enabled**
- ISO27001: A.12.4.1
- NIST: AU-2, AU-12
- CIS: 8.5

**Firewall Log Size**
- ISO27001: A.12.4.1
- NIST: AU-4
- CIS: 8.3

### Check-ApplicationControl.ps1

**AppLocker Service**
- ISO27001: A.12.5.1
- NIST: CM-7(2), SI-3
- CIS: 2.5

**AppLocker Policies**
- ISO27001: A.12.5.1
- NIST: CM-7(2)
- CIS: 2.5

**WDAC (Code Integrity)**
- ISO27001: A.12.5.1
- NIST: SI-7(1), SI-7(6)
- CIS: 2.5, 10.5

**SmartScreen**
- ISO27001: A.12.2.1
- NIST: SI-3, SI-4
- CIS: 9.3

### Check-BrowserSecurity.ps1

**Edge SmartScreen**
- ISO27001: A.12.2.1
- NIST: SI-3, SI-4
- CIS: 9.3

**Edge Enhanced Security Mode**
- ISO27001: A.12.2.1
- NIST: CM-7
- CIS: 4.1

**Edge DNS-over-HTTPS**
- ISO27001: A.13.1.1
- NIST: SC-8, SC-8(1)
- CIS: 13.2

**Internet Explorer 11 Disabled**
- ISO27001: A.12.6.2
- NIST: CM-7, SI-2
- CIS: 4.1

**Edge Automatic Updates**
- ISO27001: A.12.6.1
- NIST: SI-2
- CIS: 7.1

### Check-CertificateManagement.ps1

**Certificates Expiring Soon**
- ISO27001: A.10.1.2
- NIST: SC-12, SC-12(2)
- CIS: 3.7
- PCIDSS: 3.6.4

**Expired Certificates**
- ISO27001: A.10.1.2
- NIST: SC-12
- CIS: 3.7

**Weak Cryptographic Algorithms**
- ISO27001: A.10.1.1
- NIST: SC-13
- CIS: 3.6
- PCIDSS: 3.6.2, 4.2

**Self-Signed Certificates**
- ISO27001: A.10.1.2
- NIST: SC-12
- CIS: 3.7

**Root CA Store Size**
- ISO27001: A.10.1.2
- NIST: SC-12
- CIS: 3.7

**Certificate Revocation Checking**
- ISO27001: A.10.1.2
- NIST: SC-12
- CIS: 3.7

### Check-CredentialGuard.ps1

**Credential Guard Running**
- ISO27001: A.9.4.3
- NIST: IA-5(2), SC-12
- CIS: 5.6

**LSA Protection**
- ISO27001: A.9.4.3
- NIST: IA-5(2)
- CIS: 5.6

**Cached Logon Credentials Limit**
- ISO27001: A.9.4.3
- NIST: IA-5(2)
- CIS: 5.2

### Check-DNSSecurity.ps1

**DNS over HTTPS (DoH)**
- ISO27001: A.13.1.1
- NIST: SC-8, SC-8(1)
- CIS: 13.2

**DNS Client Service**
- ISO27001: A.13.1.1
- NIST: SC-20
- CIS: 13.2

**DNS Cache TTL Limit**
- ISO27001: A.13.1.1
- NIST: SC-20
- CIS: 13.2

**Secure DNS Providers**
- ISO27001: A.13.1.1
- NIST: SC-20
- CIS: 13.2

### Check-EventLogConfiguration.ps1

**Log Sizes (Security, Application, System)**
- ISO27001: A.12.4.1
- NIST: AU-4, AU-11
- CIS: 8.3
- PCIDSS: 10.5
- SOX: ITGC-05

**Log Enabled**
- ISO27001: A.12.4.1
- NIST: AU-2, AU-12
- CIS: 8.2
- SOX: ITGC-05

**Retention Policy**
- ISO27001: A.12.4.1
- NIST: AU-11
- CIS: 8.3
- SOX: ITGC-05

**Security Log Activity**
- ISO27001: A.12.4.1
- NIST: AU-2, AU-12
- CIS: 8.2
- SOX: ITGC-05

### Check-FileSystemAuditing.ps1

**Object Access Policy Enabled**
- ISO27001: A.12.4.1, A.12.4.3
- NIST: AU-2, AU-12
- CIS: 8.5
- PCIDSS: 10.2.1, 10.2.7
- SOX: ITGC-04

**SACL Configuration**
- ISO27001: A.12.4.1, A.12.4.3
- NIST: AU-2, AU-12
- CIS: 8.5
- PCIDSS: 10.2.1
- SOX: ITGC-04

**Detailed File Share Auditing**
- ISO27001: A.12.4.1
- NIST: AU-2, AU-12
- CIS: 8.5
- PCIDSS: 10.2.1
- SOX: ITGC-04

### Check-InteractiveLogon.ps1

**Legal Notice/Logon Banner**
- ISO27001: A.9.1.2
- NIST: AC-8
- CIS: 5.1

**Don't Display Last Username**
- ISO27001: A.9.4.2
- NIST: AC-14
- CIS: 5.1

**Machine Inactivity Limit**
- ISO27001: A.11.2.8
- NIST: AC-11
- CIS: 4.3

**Smart Card Removal Action**
- ISO27001: A.9.4.2
- NIST: AC-11
- CIS: 5.1

**Require Ctrl+Alt+Del**
- ISO27001: A.9.4.2
- NIST: AC-8
- CIS: 5.1

**Cached Logon Credentials Count**
- ISO27001: A.9.4.3
- NIST: IA-5(2)
- CIS: 5.2

**Password Expiry Warning**
- ISO27001: A.9.4.3
- NIST: IA-5(1)
- CIS: 5.2

### Check-LoggingServices.ps1

**Windows Event Log Service**
- ISO27001: A.12.4.1
- NIST: AU-2, AU-12
- CIS: 8.2
- SOX: ITGC-05

**WinRM Service (log forwarding)**
- ISO27001: A.12.4.1
- NIST: AU-6, AU-9
- CIS: 8.9

**Task Scheduler Service**
- ISO27001: A.12.4.1
- NIST: AU-6
- CIS: 8.11

### Check-RemovableStorage.ps1

**Removable Storage Restrictions**
- ISO27001: A.8.3.1
- NIST: MP-7
- CIS: 10.3
- PCIDSS: 9.8

**BitLocker To Go**
- ISO27001: A.8.3.1
- NIST: MP-5, SC-28
- CIS: 3.1

**Removable Storage Auditing**
- ISO27001: A.8.3.1
- NIST: AU-2, MP-7
- CIS: 8.5

**Removable Drive Scanning**
- ISO27001: A.12.2.1
- NIST: SI-3
- CIS: 10.1

**AutoRun Disabled**
- ISO27001: A.12.2.1
- NIST: SI-3
- CIS: 10.3

### Check-ScreenLockSettings.ps1

**Screen Saver Timeout**
- ISO27001: A.11.2.8
- NIST: AC-11
- CIS: 4.3

**Password-Protected Screen Saver**
- ISO27001: A.11.2.8
- NIST: AC-11
- CIS: 4.3

### Check-SecuritySettings.ps1

**Command Line Process Auditing**
- ISO27001: A.12.4.1
- NIST: AU-2, AU-12
- CIS: 8.5

**Advanced Audit Policy Override**
- ISO27001: A.12.4.1
- NIST: AU-2
- CIS: 8.2

**PowerShell Module Logging**
- ISO27001: A.12.4.1
- NIST: AU-2, AU-12
- CIS: 8.5

**PowerShell Script Block Logging**
- ISO27001: A.12.4.1
- NIST: AU-2, AU-12
- CIS: 8.5

### Check-SharedResources.ps1

**File Shares Present**
- ISO27001: A.9.1.2
- NIST: AC-3
- CIS: 5.1

**Share Permissions Security**
- ISO27001: A.9.1.2, A.9.2.1
- NIST: AC-3, AC-6
- CIS: 5.1

**Null Session Access to Shares**
- ISO27001: A.9.1.2
- NIST: AC-3, AC-14
- CIS: 5.1

**SMB Signing Required**
- ISO27001: A.13.1.1
- NIST: SC-8
- CIS: 13.9
- PCIDSS: 4.2

**SMB Encryption**
- ISO27001: A.13.1.1
- NIST: SC-8(1)
- CIS: 13.9
- PCIDSS: 4.2.1

**SMB v1 Protocol**
- ISO27001: A.12.6.2
- NIST: CM-7(1), SI-2
- CIS: 4.8
- PCIDSS: 2.2.2

**Anonymous Enumeration of Shares**
- ISO27001: A.9.1.2
- NIST: AC-3
- CIS: 5.1

### Check-TimeSync.ps1

**Windows Time Service Running**
- ISO27001: A.12.4.4
- NIST: AU-8
- CIS: 8.4
- PCIDSS: 10.4
- SOX: ITGC-05

**Time Service Startup Type**
- ISO27001: A.12.4.4
- NIST: AU-8
- CIS: 8.4
- SOX: ITGC-05

**Time Source Configuration**
- ISO27001: A.12.4.4
- NIST: AU-8(1)
- CIS: 8.4
- PCIDSS: 10.4

**Recent Time Synchronization**
- ISO27001: A.12.4.4
- NIST: AU-8
- CIS: 8.4
- PCIDSS: 10.4

**Time Zone Configured**
- ISO27001: A.12.4.4
- NIST: AU-8
- CIS: 8.4

### Check-UACSettings.ps1

**UAC Enabled**
- ISO27001: A.9.2.3
- NIST: AC-6(2)
- CIS: 5.4
- PCIDSS: 7.1.2

**UAC Prompt Level for Administrators**
- ISO27001: A.9.2.3
- NIST: AC-6(2)
- CIS: 5.4

**UAC Prompt on Secure Desktop**
- ISO27001: A.9.2.3
- NIST: AC-6(2)
- CIS: 5.4

### Check-VirtualizationBasedSecurity.ps1

**VBS Status**
- ISO27001: A.12.2.1
- NIST: SC-3, SC-39
- CIS: 10.5

**Memory Integrity (HVCI) Running**
- ISO27001: A.12.2.1
- NIST: SI-7(1), SI-16
- CIS: 10.5

**Memory Integrity (HVCI) Configured**
- ISO27001: A.12.2.1
- NIST: SI-7(1), SI-16
- CIS: 10.5

**Hardware Security Capabilities**
- ISO27001: A.12.2.1
- NIST: SC-3, SC-39
- CIS: 10.5

**System Guard Secure Launch**
- ISO27001: A.12.2.1
- NIST: SI-7
- CIS: 3.3

**Kernel DMA Protection**
- ISO27001: A.12.2.1
- NIST: SC-3
- CIS: 10.5

## Implementation Instructions

For each module, locate each `Add-ComplianceCheck` call and add the appropriate framework parameters based on the mappings above.

Example format:
```powershell
Add-ComplianceCheck -Category "Category Name" `
    -Check "Check Name" `
    -Requirement "SOC 2/HIPAA requirement" `
    -NIST "NIST controls" `
    -CIS "CIS controls" `
    -ISO27001 "ISO 27001 controls" `
    -PCIDSS "PCI-DSS requirements" `  # Only if applicable
    -SOX "SOX ITGC" `  # Only if applicable
    -Passed $passed `
    -CurrentValue "value" `
    -ExpectedValue "expected" `
    -Remediation "remediation steps"
```

## Priority Order

1. ✅ Check-BackupRecovery.ps1 - COMPLETED
2. ✅ Check-EndpointSecurity.ps1 - COMPLETED
3. ✅ Check-NetworkSecurity.ps1 - COMPLETED
4. Check-TimeSync.ps1 - High priority (audit timestamps)
5. Check-FileSystemAuditing.ps1 - High priority (logging)
6. Check-EventLogConfiguration.ps1 - High priority (logging)
7. Check-RemovableStorage.ps1 - High priority (data protection)
8. Check-UACSettings.ps1 - High priority (access control)
9. Remaining modules - Complete as needed
