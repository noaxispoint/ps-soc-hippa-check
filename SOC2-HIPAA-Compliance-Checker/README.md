# SOC 2 & HIPAA Compliance Checker for Windows 11

A comprehensive PowerShell-based compliance validation toolkit for Windows 11 laptops and servers (2016-2025) that checks logging, access controls, encryption, and security settings against SOC 2 Trust Services Criteria and HIPAA Security Rule requirements.

## Features

- **Comprehensive Compliance Checks**: Validates 100+ controls across SOC 2 and HIPAA requirements
- **Detailed Reporting**: Generates JSON and CSV reports with specific remediation steps
- **Modular Architecture**: Individual check modules can be run independently
- **Zero External Dependencies**: Uses only built-in Windows PowerShell capabilities
- **Remediation Guidance**: Each failed check includes specific PowerShell commands to fix issues
- **Quick Check Mode**: Rapid validation of critical controls for fast assessment

## Requirements

- Windows 11 (or Windows Server 2016/2019/2022/2025)
- PowerShell 5.1 or later
- Administrator privileges
- Execution policy allowing script execution

## Project Structure

```
SOC2-HIPAA-Compliance-Checker/
├── README.md                           # This file
├── LICENSE                             # MIT License
├── Run-ComplianceCheck.ps1             # Main entry point script
├── Quick-Check.ps1                     # Rapid validation script
├── modules/                            # Individual check modules
│   ├── Check-AuditPolicies.ps1        # Audit policy validation
│   ├── Check-EventLogConfiguration.ps1 # Event log settings
│   ├── Check-FileSystemAuditing.ps1   # File access auditing
│   ├── Check-LoggingServices.ps1      # Service health checks
│   ├── Check-SecuritySettings.ps1     # Security configurations
│   ├── Check-AccessControls.ps1       # Password & access policies
│   ├── Check-EncryptionControls.ps1   # BitLocker & encryption
│   ├── Check-EndpointSecurity.ps1     # Antivirus & firewall
│   ├── Check-ScreenLockSettings.ps1   # Session management
│   ├── Check-UpdateCompliance.ps1     # Patch management
│   └── Check-NetworkSecurity.ps1      # Network protocols
├── reports/                            # Output directory for reports
├── remediation/                        # Automated remediation scripts
│   ├── Remediate-AuditPolicies.ps1
│   ├── Remediate-AccessControls.ps1
│   └── Remediate-All.ps1
└── docs/                               # Additional documentation
    ├── CONTROLS.md                     # Detailed control mapping
    ├── INSTALLATION.md                 # Installation guide
    └── REMEDIATION.md                  # Remediation procedures
```

## Quick Start

### 1. Set Execution Policy (if needed)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 2. Run Full Compliance Check

```powershell
# Navigate to project directory
cd SOC2-HIPAA-Compliance-Checker

# Run as Administrator
.\Run-ComplianceCheck.ps1
```

### 3. Run Quick Check

```powershell
# For rapid validation of critical controls
.\Quick-Check.ps1
```

## Usage Examples

### Full Compliance Assessment

```powershell
# Run all checks and generate reports
.\Run-ComplianceCheck.ps1

# Reports will be generated in ./reports/ directory:
# - SOC2-HIPAA-Compliance-Report-[timestamp].json
# - SOC2-HIPAA-Compliance-Report-[timestamp].csv
```

### Run Specific Module

```powershell
# Check only audit policies
.\modules\Check-AuditPolicies.ps1

# Check only encryption controls
.\modules\Check-EncryptionControls.ps1
```

### Automated Remediation

```powershell
# Review remediation script before running
Get-Content .\remediation\Remediate-AuditPolicies.ps1

# Run remediation (as Administrator)
.\remediation\Remediate-AuditPolicies.ps1

# Run all remediations (use with caution)
.\remediation\Remediate-All.ps1
```

## Compliance Coverage

### SOC 2 Trust Services Criteria

- **CC6.1** - Logical and Physical Access Controls
- **CC6.2** - Prior to Issuing System Credentials
- **CC6.3** - Removal of Access
- **CC6.6** - Management of Credentials for Infrastructure and Software
- **CC6.7** - Restriction of Access to Information Assets
- **CC7.1** - Detection of Security Events
- **CC7.2** - System Monitoring
- **CC7.3** - Evaluation of Security Events
- **CC8.1** - Change Management Controls

### HIPAA Security Rule

#### Administrative Safeguards (§ 164.308)
- **§ 164.308(a)(1)(ii)(D)** - Information System Activity Review
- **§ 164.308(a)(3)** - Workforce Security
- **§ 164.308(a)(4)** - Information Access Management
- **§ 164.308(a)(5)** - Security Awareness and Training
  - **(ii)(B)** - Protection from Malicious Software
  - **(ii)(C)** - Log-in Monitoring
  - **(ii)(D)** - Password Management

#### Physical Safeguards (§ 164.310)
- **§ 164.310(d)(2)(iii)** - Accountability (device encryption)

#### Technical Safeguards (§ 164.312)
- **§ 164.312(a)(1)** - Access Control
- **§ 164.312(a)(2)(i)** - Unique User Identification
- **§ 164.312(a)(2)(iii)** - Automatic Logoff
- **§ 164.312(a)(2)(iv)** - Encryption and Decryption
- **§ 164.312(b)** - Audit Controls
- **§ 164.312(c)(1)** - Integrity Controls
- **§ 164.312(d)** - Person or Entity Authentication
- **§ 164.312(e)** - Transmission Security
  - **(1)** - Integrity Controls
  - **(2)(ii)** - Encryption

## What Gets Checked

### Logging & Auditing (SOC 2 CC7.2, HIPAA § 164.312(b))
- ✅ Advanced audit policies (26+ subcategories)
- ✅ Event log sizes and retention
- ✅ File system auditing (SACL configuration)
- ✅ Process creation with command line logging
- ✅ PowerShell logging (module & script block)
- ✅ Logging service health

### Access Controls (SOC 2 CC6.1, HIPAA § 164.308(a)(5))
- ✅ Password length (12+ characters)
- ✅ Password complexity requirements
- ✅ Password history (12+ passwords)
- ✅ Password age (90 days maximum)
- ✅ Account lockout threshold (5-10 attempts)
- ✅ Account lockout duration (15+ minutes)
- ✅ Guest account disabled
- ✅ Default admin account renamed
- ✅ Stale account detection (90+ days)

### Encryption (HIPAA § 164.312(a)(2)(iv), SOC 2 CC6.1)
- ✅ BitLocker full disk encryption
- ✅ BitLocker protection status
- ✅ Encryption strength (XtsAes256)
- ✅ TPM status
- ✅ Secure Boot enabled
- ✅ EFS availability

### Endpoint Security (SOC 2 CC7.1, HIPAA § 164.308(a)(5)(ii)(B))
- ✅ Windows Defender real-time protection
- ✅ Antivirus signature freshness
- ✅ Behavior monitoring
- ✅ Cloud-delivered protection
- ✅ Recent security scans
- ✅ Tamper protection
- ✅ Windows Firewall status (all profiles)

### Session Management (HIPAA § 164.312(a)(2)(iii))
- ✅ Screen saver timeout (15 minutes)
- ✅ Password-protected screen saver
- ✅ Display timeout settings
- ✅ Lock screen policies
- ✅ Dynamic Lock (optional)

### Update Management (SOC 2 CC8.1, HIPAA § 164.308(a)(5)(ii)(B))
- ✅ Windows Update service status
- ✅ Pending critical updates
- ✅ Recent update installation
- ✅ Automatic update configuration
- ✅ Supported Windows version

### Network Security (SOC 2 CC6.1, HIPAA § 164.312(e))
- ✅ SMBv1 disabled
- ✅ SMB signing required
- ✅ SMB encryption enabled
- ✅ RDP security (NLA required)
- ✅ LLMNR disabled
- ✅ NetBIOS over TCP/IP disabled

## Output Reports

### JSON Report Format

```json
{
  "Compliant": false,
  "Timestamp": "2024-12-11T10:30:00",
  "ComputerName": "LAPTOP-001",
  "Checks": [
    {
      "Category": "Audit Policy - Account Logon",
      "Check": "Credential Validation",
      "Requirement": "HIPAA § 164.312(b) - Audit Controls",
      "Passed": true,
      "CurrentValue": "Success and Failure",
      "ExpectedValue": "Success and Failure",
      "Remediation": "N/A"
    }
  ]
}
```

### CSV Report

The CSV report contains the same information in spreadsheet-friendly format for easy filtering and analysis in Excel or other tools.

## Remediation

Each failed check includes specific remediation steps. You can:

1. **Manual Remediation**: Copy/paste commands from the report
2. **Semi-Automated**: Run individual remediation scripts
3. **Fully Automated**: Run the master remediation script (use with caution)

### Example Remediation

```powershell
# From a failed check, you'll see:
# Remediation: auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Simply copy and run the command
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

## Deployment with Intune

The checks can be deployed as Intune compliance policies or proactive remediations:

1. **Compliance Policy**: Use the detection scripts to mark devices as non-compliant
2. **Remediation Scripts**: Deploy fixes automatically to non-compliant devices
3. **Reporting**: Export results to Azure Log Analytics for dashboard creation

See `docs/INTUNE-DEPLOYMENT.md` for detailed instructions.

## Best Practices

### Before Running

1. **Test in Non-Production**: Always test in a lab environment first
2. **Review Remediation**: Examine remediation scripts before running
3. **Backup Policies**: Export current security policies before changes
4. **Document Changes**: Keep records of what was modified

### Running in Production

1. **Schedule Regular Scans**: Weekly or monthly compliance checks
2. **Review Reports**: Analyze trends over time
3. **Address Critical First**: Prioritize critical security gaps
4. **Validate Remediations**: Re-run checks after applying fixes

### Integration

1. **SIEM Integration**: Export results to your SIEM platform
2. **Ticketing System**: Auto-create tickets for failed checks
3. **Dashboard**: Build compliance dashboards from report data
4. **Alerting**: Set up alerts for critical compliance failures

## Troubleshooting

### "Execution Policy" Error

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "Access Denied" Errors

Ensure you're running PowerShell as Administrator:
```powershell
# Right-click PowerShell → "Run as Administrator"
```

### Module Not Found

Ensure you're running from the project directory:
```powershell
cd C:\Path\To\SOC2-HIPAA-Compliance-Checker
.\Run-ComplianceCheck.ps1
```

### BitLocker Checks Fail

BitLocker requires Windows Pro, Enterprise, or Education editions. Home edition is not supported.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request with detailed description

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool provides automated compliance checking but does not guarantee full SOC 2 or HIPAA compliance. It should be used as part of a comprehensive compliance program that includes:

- Regular security assessments
- Policy and procedure documentation
- Employee training
- Incident response planning
- Third-party audits

Consult with qualified compliance professionals and legal counsel for your specific requirements.

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Review the documentation in the `docs/` directory
- Check existing issues for solutions

## Changelog

### Version 1.0.0 (2024-12-11)
- Initial release
- Full SOC 2 Trust Services Criteria coverage
- Complete HIPAA Security Rule technical safeguards
- Comprehensive remediation guidance
- JSON and CSV reporting
- Modular architecture

## Roadmap

- [ ] Azure AD/Entra ID integration checks
- [ ] Cloud storage encryption validation
- [ ] Mobile device management (MDM) checks
- [ ] Automated remediation scheduling
- [ ] Web-based dashboard
- [ ] API for integration with other tools
- [ ] Support for Windows Server domain controllers
- [ ] Active Directory group policy validation
- [ ] Certificate management checks
- [ ] Backup and recovery validation

## Acknowledgments

Developed to help organizations achieve and maintain SOC 2 and HIPAA compliance for Windows endpoints. Special thanks to the information security community for their guidance on security best practices.
