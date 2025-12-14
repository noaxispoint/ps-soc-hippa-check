# Additional Prioritized Compliance Controls Proposal

This document lists prioritized additional controls to add to OmniComply, mapping each control to SOC 2, CIS, NIST, and HIPAA references, with detection approach, remediation notes, and implementation considerations.

**How to read:** Priority = High / Medium / Low. "Detection (examples)" gives pragmatic PowerShell or AD/tenant queries you can translate into `Check-*` modules.

---

## High Priority

1) SMBv1 Disabled & SMB Signing Enforced
- Mapping: CIS 3.x, NIST AC-17, SOC 2 CC6.2, HIPAA §164.312
- Why: SMBv1 is high-risk for lateral movement (WannaCry, etc.). SMB signing prevents tampering.
- Detection (examples):
  - `Get-SmbServerConfiguration | Select EnableSMB1Protocol, RequireSecuritySignature`
  - Registry fallback: `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1`
- Remediation: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true` or GPO/reg changes.
- Notes: Already implemented as `Check-SMBv1.ps1`.

2) Privileged account MFA enforcement (Azure AD & break-glass)
- Mapping: SOC 2 CC6.2, NIST IA-2, HIPAA §164.312
- Why: Admin accounts are primary attack targets; MFA for privileged roles is critical.
- Detection (examples):
  - Azure AD Conditional Access: `Get-AzureADMSConditionalAccessPolicy` (MS Graph/AzureAD)
  - Per-user strong auth methods via MSOnline/Microsoft.Graph: check admin group membership and per-user MFA state.
- Remediation: Enforce Conditional Access policies requiring MFA for all privileged roles; document break-glass exceptions.
- Notes: Requires Azure modules and tenant privileges; implement as an expanded `Check-MFAEnforcement` that enumerates admin groups.

3) Patch Recency & Critical Update SLA
- Mapping: CIS 7.x, NIST SI-2, SOC 2 CC6.6
- Why: Unpatched systems enable exploits; compliance often requires patch SLAs.
- Detection (examples):
  - `Get-HotFix | Sort InstalledOn -Descending | Select -First 1`
  - Integrations: WSUS/SCCM/Intune APIs for enterprise roll-ups.
- Remediation: Ensure automated patch management and reduced time-to-patch for critical CVEs.
- Notes: Implemented as `Check-PatchRecency.ps1` (hotfix heuristic). Consider enterprise aggregation support.

4) EDR/AV Presence & Health
- Mapping: NIST SI-4, CIS 8.x, SOC 2 CC6.6
- Why: Detection & response requires EDR coverage and healthy agents.
- Detection (examples):
  - `Get-MpComputerStatus` for Defender; check vendor service/process names for other EDRs.
  - Verify agent heartbeat via vendor console APIs where available.
- Remediation: Deploy/repair EDR agents; ensure telemetry ingestion to SIEM.
- Notes: Implemented as `Check-EDRHealth.ps1` (heuristics). Add vendor API checks for accuracy.

5) Backup Integrity & Recent Restore Test
- Mapping: HIPAA §164.308(a)(7), SOC 2 CC6.5
- Why: Backups are required and must be recoverable.
- Detection (examples):
  - Check backup job logs (Veaam/Windows Server Backup/enterprise APIs).
  - Look for recent successful job entries and periodic restore-run evidence.
- Remediation: Enforce backup scheduling and periodic test restores; centralize backup reports.

---

## Medium Priority

6) LAPS / Local Admin Password Management
- Mapping: CIS 5.4, NIST AC-6
- Why: Removes static shared local admin passwords that attackers reuse.
- Detection (examples):
  - Presence of LAPS AD attribute `ms-Mcs-AdmPwd`, LAPS cmdlets or install paths.
  - `Get-ADComputer -Properties ms-Mcs-AdmPwd` (requires AD privileges).
- Remediation: Deploy LAPS or equivalent, extend schema, GPO configure rotation.
- Notes: Implemented as `Check-LAPSDetection.ps1` (best-effort). Add AD-level verification when permitted.

7) PowerShell Audit & ScriptBlock Logging
- Mapping: CIS 6.x, NIST AU family, SOC 2 CC6.1
- Why: Improves detection of adversary scripting activity.
- Detection (examples):
  - Registry/GPO checks: `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\` keys for ScriptBlockLogging and ModuleLogging.
  - `Get-AuditPolicy -Category System` and specific subcategory checks.
- Remediation: Enable ScriptBlockLogging, ModuleLogging, and transcription via GPO/EDR.

8) Remote Admin Exposure (RDP/WinRM) & Firewall Rules
- Mapping: NIST AC-17, CIS 3.x
- Why: Exposed RDP/WinRM ports are frequent intrusion vectors.
- Detection (examples):
  - `Get-NetTCPConnection -LocalPort 3389 -State Listen`, `Get-NetFirewallRule` to identify rules allowing public access.
  - Correlate with public IP metadata where possible.
- Remediation: Restrict remote admin to VPN or JIT access, harden firewall rules.

9) SIEM/Log Forwarding and Retention Compliance
- Mapping: SOC 2 CC7, NIST AU-2/AU-6, HIPAA §164.312(b)
- Why: Centralized logging and retention are compliance requirements for detection and forensic investigations.
- Detection (examples):
  - Check Event Forwarding subscriptions: `wecutil gs` or existence of `C:\Windows\System32\winevt\Subscriptions.xml`.
  - Detect SIEM agent processes/configuration.
- Remediation: Configure Windows Event Forwarding/agents, set retention period to policy.

---

## Low Priority / Environment-Specific

10) TLS Cipher/Certificate Strength & Expiry
- Mapping: NIST SC-8, CIS 4.x, HIPAA §164.312(e)
- Detection: Cert store expiry (`Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) }`) and TLS scans for exposed services (openssl or Test-TlsCipherSuite).
- Remediation: Renew certs, disable weak ciphers via GPO or registry.

11) Secure Boot & TPM 2.0 Presence
- Mapping: NIST SC-13, CIS 1.x
- Detection: WMI queries for SecureBoot and TPM presence.
- Remediation: Enforce Secure Boot and TPM on supported hardware; document exceptions.

12) Code-signing Enforcement for Scripts/Drivers
- Mapping: CIS 6.1, NIST SI-4
- Detection: Check execution policy / AppLocker/WDAC policies.
- Remediation: Require signed PowerShell scripts, enforce AppLocker or WDAC policies.

---

## Implementation Notes
- Many enterprise-grade checks require AD, Azure AD, SCCM/WSUS, or vendor API access and elevated privileges — implement checks to degrade gracefully and report "inconclusive" when lacking permissions.
- Prefer idempotent, read-only checks. Where possible, provide remediation command snippets and links to vendor docs.
- Add configuration options to checks for environment-specific thresholds (e.g., patch recency days, acceptable admin counts).
- Aggregate enterprise results (WSUS/SCCM/Azure tenant) into a central report; consider adding connectors.

## Next recommended steps
1. Add or expand MFA check to enumerate privileged groups and verify Conditional Access targeted at those groups (High priority).
2. Implement SIEM/log-forwarding check and PowerShell logging check (Medium priority).
3. Add vendor API integrations for EDR and backup solutions to improve accuracy (High/Medium depending on environment).

---

File created: `OmniComply/docs/ADDITIONAL-CONTROLS.md` — copy or adjust content into PRs or issue tracker as desired.
