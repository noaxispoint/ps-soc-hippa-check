# SOC 2 and HIPAA Controls Reference

This document maps each compliance check in the tool to specific SOC 2 Trust Services Criteria and HIPAA Security Rule requirements.

## SOC 2 Trust Services Criteria

### CC6 - Logical and Physical Access Controls

#### CC6.1 - Logical Access Security
**Checks:**
- Password length, complexity, history, age
- Account lockout threshold and duration
- Guest account disabled
- Privileged access monitoring (Special Logon auditing)
- BitLocker encryption
- TPM status
- Secure Boot
- Windows Firewall enabled
- SMBv1 disabled
- RDP security

**Purpose:** Implements logical access security software, infrastructure, and architectures over protected information assets.

#### CC6.2 - Prior to Issuing System Credentials
**Checks:**
- User Account Management auditing
- Computer Account Management auditing
- Credential Validation auditing

**Purpose:** Registers and authorizes new users before issuing system credentials.

#### CC6.3 - Removal of Access
**Checks:**
- Security Group Management auditing
- Distribution Group Management auditing
- Application Group Management auditing
- Stale account detection (90+ days inactive)

**Purpose:** Removes system access when user access is no longer appropriate.

### CC7 - System Operations

#### CC7.1 - Detection of Security Events
**Checks:**
- Windows Defender real-time protection
- Antivirus signature freshness
- Behavior monitoring
- Tamper protection

**Purpose:** Monitors for security events indicating malicious acts, natural disasters, and errors.

#### CC7.2 - System Monitoring
**Checks:**
- All audit policy configurations
- Event log sizes and activity
- Logging service health
- Registry auditing
- PowerShell logging
- Recent security scans

**Purpose:** Monitors system components and operations for anomalies.

#### CC7.3 - Evaluation of Security Events
**Checks:**
- Audit Policy Change auditing
- Authentication Policy Change auditing
- Authorization Policy Change auditing

**Purpose:** Evaluates security events to determine if they represent failures to meet objectives.

### CC8 - Change Management

#### CC8.1 - Change Management Controls
**Checks:**
- Windows Update service status
- Pending critical updates
- Recent update installation
- Supported Windows version
- Update configuration

**Purpose:** Manages changes to information assets through formal change management processes.

## HIPAA Security Rule

### Administrative Safeguards (§ 164.308)

#### § 164.308(a)(1)(ii)(D) - Information System Activity Review
**Checks:**
- Event log sizes and retention
- Security log activity
- Logging service health

**Purpose:** Implement procedures to regularly review records of information system activity.

#### § 164.308(a)(3)(ii)(A) - Authorization and/or Supervision
**Checks:**
- User Account Management auditing
- Authorization Policy Change auditing

**Purpose:** Implement procedures for authorization and supervision of workforce members working with ePHI.

#### § 164.308(a)(4)(ii)(C) - Access Authorization
**Checks:**
- Security Group Management auditing
- Access control policies

**Purpose:** Implement policies for granting access to ePHI.

#### § 164.308(a)(5) - Security Awareness and Training

##### (ii)(B) - Protection from Malicious Software
**Checks:**
- Windows Defender status
- Antivirus signatures
- Real-time protection
- Update compliance

**Purpose:** Implement procedures for guarding against and detecting malicious software.

##### (ii)(C) - Log-in Monitoring
**Checks:**
- Logon auditing
- Logoff auditing
- Account Lockout auditing
- Account lockout threshold

**Purpose:** Implement procedures for monitoring log-in attempts.

##### (ii)(D) - Password Management
**Checks:**
- Password length (12+ characters)
- Password complexity
- Password history
- Password age
- Account lockout

**Purpose:** Implement procedures for creating, changing, and safeguarding passwords.

### Physical Safeguards (§ 164.310)

#### § 164.310(d)(2)(iii) - Accountability (Device Encryption)
**Checks:**
- BitLocker encryption
- Encryption status
- Protection status

**Purpose:** Maintain a record of device movements and implement encryption.

### Technical Safeguards (§ 164.312)

#### § 164.312(a)(1) - Access Control
**Checks:**
- All access control checks
- Authentication auditing

**Purpose:** Implement technical policies and procedures for information systems with ePHI.

#### § 164.312(a)(2)(i) - Unique User Identification
**Checks:**
- User Account Management auditing
- Guest account disabled
- Unique credential auditing

**Purpose:** Assign unique identifiers for tracking user identity.

#### § 164.312(a)(2)(iii) - Automatic Logoff
**Checks:**
- Screen saver timeout
- Password-protected screen saver
- Display timeout settings

**Purpose:** Terminate electronic session after predetermined time of inactivity.

#### § 164.312(a)(2)(iv) - Encryption and Decryption
**Checks:**
- BitLocker encryption
- Encryption strength
- TPM status
- Secure Boot

**Purpose:** Implement mechanism to encrypt and decrypt ePHI.

#### § 164.312(b) - Audit Controls
**Checks:**
- All audit policy configurations
- Event log configuration
- File system auditing
- Process creation auditing
- Command line auditing

**Purpose:** Implement hardware/software mechanisms to record and examine activity in systems with ePHI.

#### § 164.312(c)(1) - Integrity Controls
**Checks:**
- Windows Firewall
- System Integrity auditing

**Purpose:** Implement policies to ensure ePHI is not improperly altered or destroyed.

#### § 164.312(d) - Person or Entity Authentication
**Checks:**
- Credential Validation auditing
- Kerberos authentication auditing
- Authentication Policy Change auditing

**Purpose:** Implement procedures to verify claimed identity.

#### § 164.312(e) - Transmission Security

##### (1) - Integrity Controls
**Checks:**
- SMB signing required
- Network protocol security

**Purpose:** Implement security measures to ensure transmitted ePHI is not improperly modified.

##### (2)(ii) - Encryption
**Checks:**
- SMB encryption
- Network security protocols

**Purpose:** Implement mechanism to encrypt ePHI during transmission.

## Compliance Matrix

| Check Category | SOC 2 Controls | HIPAA Controls |
|---|---|---|
| Audit Policies | CC7.2, CC7.3 | § 164.312(b) |
| Event Logs | CC7.2 | § 164.308(a)(1)(ii)(D), § 164.312(b) |
| Access Controls | CC6.1, CC6.2, CC6.3 | § 164.308(a)(5)(ii)(D), § 164.312(a)(2)(i) |
| Encryption | CC6.1 | § 164.310(d)(2)(iii), § 164.312(a)(2)(iv) |
| Endpoint Security | CC7.1, CC7.2 | § 164.308(a)(5)(ii)(B), § 164.312(c)(1) |
| Screen Lock | CC6.1 | § 164.312(a)(2)(iii) |
| Updates | CC8.1 | § 164.308(a)(5)(ii)(B) |
| Network Security | CC6.1 | § 164.312(e) |

## Implementation Priority

### Critical (Implement Immediately)
1. Audit logging enabled (§ 164.312(b))
2. Event log sizes configured
3. Password policies (§ 164.308(a)(5)(ii)(D))
4. Antivirus enabled (§ 164.308(a)(5)(ii)(B))
5. Firewall enabled (§ 164.312(c)(1))

### High Priority (Within 30 Days)
1. BitLocker encryption (§ 164.312(a)(2)(iv))
2. Account lockout policies
3. Screen lock timeout (§ 164.312(a)(2)(iii))
4. File system auditing
5. SMB security

### Medium Priority (Within 90 Days)
1. PowerShell logging
2. Process creation auditing
3. Network protocol hardening
4. Stale account cleanup
5. Update compliance

## References

- [SOC 2 Trust Services Criteria](https://www.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/trust-services-criteria.pdf)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
