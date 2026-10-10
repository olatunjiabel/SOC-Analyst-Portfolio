# XDR Multi-Alert Correlation Investigation Report

## Overview

| Field | Details |
|---|---|
| **Timeline** | July 10–12, 2026 |
| **Analyst** | Olatunji Abel |
| **Platform** | Microsoft Defender XDR, Microsoft Defender for Endpoint, Microsoft Sentinel |
| **Device** | win-5l3oittdjlp (Windows Server 2022) |
| **User** | WIN-5L3OITTDJLP\Administrator; backdoor (local account created during the incident) |
| **Incident Title** | Hands-on keyboard attack was launched from a compromised account |
| **Incident ID** | 204 |
| **Severity** | High |
| **Status** | Active |
| **Verdict** | True Positive — Authorized Security Simulation |
| **Total Alerts** | 16 |
| **Observed Indicators and Artifacts** | Backdoor local account created and added to the local Administrators group via net.exe; EICAR test file created at C:\Temp\eicar.com via powershell.exe |
| **Observed Attack Activity** | CertUtil used via PowerShell to attempt to download eicar.txt on July 10, followed by reconnaissance commands, local account creation, and addition of the account to the local Administrators group on July 12 |

---

## Executive Summary

This investigation focused on a Microsoft Defender XDR incident titled "Hands-on keyboard attack was launched from a compromised account." A total of 16 alerts were correlated into one incident involving two users and one endpoint, `win-5l3oittdjlp`.

On July 10, 2026, Microsoft Defender for Endpoint blocked a Trojan detected during a CertUtil download attempt. The same PowerShell process later created an EICAR test file, which was quarantined by Windows Defender Antivirus.

On July 12, activity on the endpoint included reconnaissance commands, creation of a local account named `backdoor`, and addition of that account to the local Administrators group.

The investigation showed how related endpoint activities across two days were presented within a single XDR incident. The report documents the observed events, security response, MITRE ATT&CK mapping, and additional investigation steps that could be taken during a real incident.

![Incident Summary](screenshots/Potential-human-operated-malicious-activity.png)

---

## Reason for XDR Correlation

The incident was titled "Hands-on keyboard attack was launched from a compromised account." The alert story showed two processes, two users, and one endpoint: `win-5l3oittdjlp`.

The activity covered July 10 to July 12, 2026, and occurred on the same endpoint.

![Attack Story Overview](screenshots/Potential-human-operated-malicious-activity.png)

On July 10, Microsoft Defender for Endpoint blocked a Trojan detected during a CertUtil download attempt. Later, PowerShell created the EICAR test file, which was quarantined by Windows Defender Antivirus.

On July 12, the Administrator account ran commands including `whoami`, `net user`, `tasklist`, and `ipconfig`. These commands can be used for normal administration, but in this case they were followed by the creation of a local account named `backdoor` and its addition to the local Administrators group.

The sequence of activity is important. The reconnaissance commands alone do not prove malicious activity, but the account creation and privilege change that followed made the activity more suspicious. The shared endpoint and related activity across the two-day timeline help explain why Microsoft Defender XDR grouped the alerts into one incident.

---

## Investigation Timeline

| Date / Time | Event |
|---|---|
| July 10, 2026 – 12:24 PM | First alert triggered: "Potential human-operated malicious activity" |
| July 10, 2026 – 12:58:49 PM | Defender for Endpoint blocked execution of Trojan:Win32/Ceprolad.A — command line: certutil.exe -urlcache -split -f https://raw.githubusercontent.com/[test-repo]/eicar.txt eicar.txt, run under powershell.exe (PID 2380) — Remediation: Remove, Success |
| July 10, 2026 – 1:00:36 PM | Same powershell.exe process (PID 2380) created eicar.com (68 B) at C:\Temp\eicar.com |
| July 10, 2026 – 1:00:42 PM | eicar.com quarantined by Windows Defender Antivirus — Threat: Virus:DOS/EICAR_Test_File — Remediation: Quarantine, Success |
| July 12, 2026 – 9:19:01 AM | whoami.exe executed by Administrator |
| July 12, 2026 – 9:48:48 AM | "whoami.exe" /all executed by Administrator |
| July 12, 2026 – 9:48:58 AM | "net.exe" user executed by Administrator — local account enumeration |
| July 12, 2026 – 9:49:08 AM | tasklist.exe executed by Administrator |
| July 12, 2026 – 9:49:23 AM | "ipconfig.exe" /all executed by Administrator |
| July 12, 2026 – 9:49:35 AM | "net.exe" user backdoor ******** /add — backdoor local account created |
| July 12, 2026 – 9:49:44 AM | "net.exe" localgroup administrators backdoor /add — backdoor account escalated to local Administrators group |
| July 12, 2026 | Backdoor account remediated automatically by XDR and MDE; MDE policy prevented the account from accessing other endpoints onboarded on MDE |

**Certutil blocked execution (12:58:49 PM):**
![Certutil Trojan Block](screenshots/Certutil__-urlcache_-split_-f__-in-commandline.png)

**Remediation action on the Trojan download (Remove, Success):**
![Certutil Remediation](screenshots/Remediation-action-on-eicar-file-downloaded.png)

**eicar.com file creation confirmed via DeviceFileEvents (1:00:36 PM):**
![Eicar File Creation Query](screenshots/Eicar-Evidence.png)

**powershell.exe process detail showing eicar.com created, SHA1, VirusTotal ratio:**
![Eicar Process Detail](screenshots/powershell-eicar-file-created.png)

**eicar.com quarantined by Windows Defender Antivirus (1:00:42 PM):**
![Eicar Quarantine](screenshots/eicar-file-quarantined.png)

**Advanced Hunting query showing the full July 12 command sequence (whoami, net user, tasklist, ipconfig, net user backdoor, net localgroup):**
![Advanced Hunting Command Sequence](screenshots/Command-lines-run-by-admin.png)

**Backdoor account creation — net.exe (PID 14096), 9:49:34/35 AM:**
![Backdoor Account Creation](screenshots/Backdoor-account-creation.png)

**Backdoor privilege escalation — net.exe (PID 10844), 9:49:43/44 AM:**
![Backdoor Privilege Escalation](screenshots/Backdoor-privilege-escalation.png)

---

## Indicators of Attack (IOA)

- **certutil.exe LOLBin abuse** — invoked via PowerShell (PID 2380) with `-urlcache -split -f` to attempt to download `eicar.txt` from a GitHub raw content URL. CertUtil is a legitimate Windows tool that can also be misused for file downloads.
- **whoami.exe execution (x2)** — run at 9:19:01 AM and 9:48:48 AM (with `/all`). This command can reveal the current user and security context.
- **net.exe user (enumeration)** — run at 9:48:58 AM with no target account specified, consistent with checking existing local accounts before creating a new one.
- **tasklist.exe execution** — used to list running processes. This can help an investigator understand what was running on the endpoint; an attacker could also use it to identify processes of interest.
- **ipconfig.exe /all execution** — used to display network configuration. This information could help an attacker understand the endpoint's network settings, but the command alone does not establish an intent to contact command-and-control infrastructure.
- **Sequenced reconnaissance and account changes** — the sequence (`whoami` → account enumeration → `tasklist` → `ipconfig` → account creation → addition to the local Administrators group) occurred within roughly 45 seconds. This sequence is suspicious, although the available evidence alone does not establish whether it was scripted.

---

## Observed Indicators and Artifacts

**Evidence and Response tab — all 5 confirmed evidence items:**
![Evidence and Response Overview](screenshots/Evidence-and-Response-tab-overview.png)

- Local user account named "backdoor" created via net.exe  command: "net.exe" user backdoor ******** /add — executed Jul 12, 2026, 9:49:35 AM
- Backdoor account escalated to local Administrators group via net.exe — command: "net.exe" localgroup administrators backdoor /add — executed Jul 12, 2026, 9:49:44 AM (9 seconds after account creation)
- EICAR test file `eicar.com` (68 B) created via powershell.exe (PID 2380) at C:\Temp\eicar.com — Jul 10, 2026, 1:00:36 PM — SHA1: 3395856ce81f2b7382dee72602f798b642f14140 — VirusTotal detection ratio 66/68 — quarantined as Virus:DOS/EICAR_Test_File. This is a test artifact, not evidence that real malware was present.
- Trojan:Win32/Ceprolad.A — blocked before execution via certutil.exe run under the same powershell.exe process (PID 2380), Jul 10, 2026, 12:58:49 PM
- Second malicious PowerShell.exe execution (PID 13672) — bare invocation, no visible payload in command line, Blocked, execution time Jul 12, 2026, 9:16:27 AM

**Second malicious PowerShell.exe detail (PID 13672):**
![Second PowerShell Detail](screenshots/malicious-PowerShell-PID-13672.png)

- Compromised Administrator account (win-5l3oittdjlp\Administrator) used as the access point for all observed activity

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Command and Control | T1105 | Ingress Tool Transfer | certutil.exe used via PowerShell to attempt to download eicar.txt |
| Discovery | T1033 | System Owner/User Discovery | whoami.exe executed twice (9:19:01 AM, 9:48:48 AM) |
| Discovery | T1087.001 | Account Discovery: Local Account | "net.exe" user executed at 9:48:58 AM to enumerate local accounts |
| Discovery | T1057 | Process Discovery | tasklist.exe executed at 9:49:08 AM |
| Discovery | T1016 | System Network Configuration Discovery | ipconfig.exe /all executed at 9:49:23 AM |
| Persistence | T1136.001 | Create Account: Local Account | net.exe used to create "backdoor" local account at 9:49:35 AM |
| Privilege Escalation | T1098.007 | Account Manipulation: Additional Local or Domain Groups | "backdoor" account added to local Administrators group at 9:49:44 AM |

**MITRE ATT&CK Navigator heatmap:**
![MITRE Navigator Heatmap](screenshots/MITRE-ATT&CK-Navigator-heatmap.png)

---

## Incident Response Procedure

This section covers the incident response steps taken during the investigation and the additional actions I would recommend during a real incident. The investigation and automated remediation were performed in the lab, while the additional containment, recovery, and monitoring steps are recommendations for a real environment.

### 1. Alert Validation and Investigation

The first step was to validate the alerts generated by Microsoft Defender XDR by reviewing the incident page, alert story, incident graph, timeline, and affected entities.

The investigation focused on confirming:

- The affected device: `win-5l3oittdjlp`
- The compromised user account: `Administrator`
- The processes and command lines executed
- The relationship between the 16 alerts correlated into a single incident

Advanced Hunting queries, Alert-story, Incident graph, Timeline were used to validate:

- Suspicious PowerShell execution
- Certutil abuse
- Local account creation
- Privilege escalation activity
- User and device activity timeline

The investigation confirmed malicious activity due to the sequence of reconnaissance commands followed by the creation of a privileged backdoor account.

### 2. Recommended Device Containment

The creation of a backdoor administrative account makes containment an important response step in a real incident. The following actions are recommendations, not actions documented as completed in this lab.

Recommended containment actions:

- Isolate `win-5l3oittdjlp` from the network using Microsoft Defender for Endpoint.
- Prevent further communication between the compromised endpoint and other systems.
- Block potential lateral movement attempts from the affected device.

Device isolation limits the attacker's ability to execute additional commands, maintain persistence, or access other resources within the environment.

### 3. Recommended Account Remediation

The Administrator account should be investigated and secured because it was used during the observed activity. The following actions are recommendations for a real incident, not actions documented as completed in this lab.

Recommended remediation actions:

- Reset the password of the compromised Administrator account.
- Revoke active sessions associated with the compromised account.
- Review the permissions assigned to the account.
- Disable the unauthorized local account created by the attacker and remove it from the local Administrators group.

These actions prevent the attacker from maintaining privileged access to the endpoint.

### 4. Malware and Artifact Removal

The following response was documented in the lab, along with an additional recommended check:

Actions observed or documented:

- Microsoft Defender Antivirus quarantined the EICAR test file at `C:\Temp\eicar.com` successfully.
- Defender reported successful removal of the detected Trojan.
- **Recommended follow-up:** Perform additional endpoint scans to look for any remaining malicious files, scripts, or persistence mechanisms.

### 5. Recommended Blast Radius Investigation

Microsoft Defender XDR and Microsoft Sentinel could be used to investigate the scope of the compromise. The KQL queries documented below were not executed as part of this project.

The investigation focuses on:

- Checking whether the compromised Administrator account authenticated to other devices.
- Checking whether the created `backdoor` account appeared on other endpoints.
- Searching for additional suspicious PowerShell executions.
- Searching for similar certutil activity across the environment.
- Reviewing additional indicators of compromise.

Relevant data sources to investigate:

- `DeviceProcessEvents`
- `DeviceLogonEvents`
- `IdentityLogonEvents`
- `SecurityEvent`
- `SigninLogs`

The objective is to determine whether the attacker moved laterally or compromised additional systems.

### 6. Recommended Recovery and Monitoring

After containment and remediation have been completed and validated in a real incident:

- The affected endpoint would be returned to normal operation after validation.
- Microsoft Defender security controls would be confirmed as active.
- The endpoint and affected accounts would be monitored for recurring suspicious activity.
- Microsoft Defender recommendations would be reviewed to improve security posture.

Continuous monitoring would be maintained to detect any attempt by the attacker to regain access.

### 7. Recommended Escalation and Documentation

In a real incident, the case should be escalated to the appropriate IT and Security Operations teams, with the findings, timeline, and remediation steps documented for record-keeping and post-incident review.

## Blast Radius Investigation Queries

### Objective

In a real incident, I would investigate whether the compromised Administrator account or the newly created Backdoor account accessed other endpoints within the environment.

Since the simulated attack in this project occurred on one endpoint, I documented the KQL queries I would use to investigate possible lateral movement and check for suspicious activity on other devices.

The queries below demonstrate how I would approach this step using the available security logs. They were documented as part of the investigation procedure and were not executed as part of this project.

The investigation would aim to answer the following questions:

- Did the compromised Administrator account or attacker-created Backdoor account access other endpoints within the network during the incident timeframe?
- Did either account execute enumeration commands on other endpoints during the investigation period?
- Did either account authenticate to any additional devices outside the compromised endpoint?

---

## KQL Queries

### 1. Enumeration Commands Check

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-07-10) .. datetime(2026-07-12 23:59:59))
| where AccountName in~ ("Administrator", "Backdoor")
| where ProcessCommandLine has_any (
    "whoami",
    "net user",
    "tasklist",
    "ipconfig",
    "certutil",
    "localgroup administrators",
    "urlcache"
)
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated desc
```
### 2. Logon Check

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-07-10) .. datetime(2026-07-12 23:59:59))
| where AccountName in~ ("Administrator", "Backdoor")
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    LogonType,
    ActionType,
    RemoteIP
| order by TimeGenerated desc
```

## Business Impact

The **EICAR.com** file created on the system is a harmless test file used to check whether antivirus software can detect and respond to a test threat.

Although the EICAR file is harmless, using the same download technique with real malware could pose a serious threat to an organization.

### Asset Impact

If a real malware payload had been downloaded instead of the test file, and Microsoft Defender for Endpoint (MDE) and Microsoft Defender XDR had not detected and blocked it, the device could have been exposed to malware infection, ransomware, or other malicious activity.

The reconnaissance activity observed on the device, followed by the creation of a **Backdoor** account and its addition to the local Administrators group, created a serious security risk.

If an attacker controlled this account, they could have used its administrative privileges to make further changes to the affected endpoint.

If this happened on a critical server, containing the incident could require isolating the device from the network. This could cause downtime and affect business operations.

---

## Detection Strategy

To detect and prevent similar attacks, organizations should:

- Deploy an **Endpoint Detection and Response (EDR)** solution to detect suspicious PowerShell activity, CertUtil file downloads, and other unusual process activity.

- Create **detection rules** for suspicious local account creation and unexpected changes to the local Administrators group.

- Monitor sequences of reconnaissance commands such as `whoami`, `net user`, `tasklist`, and `ipconfig`, especially when followed by account creation or privilege escalation.

- Use **SIEM analytics rules** in Microsoft Sentinel to identify related events and investigate whether the same activity occurs on other endpoints.

- Use **SOAR playbooks** to support incident response actions such as device isolation, disabling unauthorized accounts, and sending security notifications.

- Maintain an **Incident Response Plan** and conduct threat hunting to investigate suspicious activity, determine the scope of a compromise, and improve detection coverage.

## Lessons Learned

- **How XDR Correlates Alerts into Incidents**  
  I learned how Microsoft Defender XDR can correlate related alerts into a single incident. In this case, the activity occurred on the same endpoint over two days.

- **Analytical Thinking**  
  This project improved my ability to connect events from different timelines and understand how individual activities can form part of a larger attack sequence.

- **Investigation Process**  
  I learned the importance of reviewing the Alert Story, incident timeline, process activity, and affected accounts instead of investigating each alert in isolation.

- **Staying Calm Under Pressure**  
  Even though this project was a simulation, I was initially overwhelmed by the number of alerts generated. I stayed calm and started the investigation by reviewing the Alert Story and timeline.

- **MITRE ATT&CK Mapping**  
  I learned how to map observed activities, such as file download attempts, account creation, and privilege escalation, to relevant MITRE ATT&CK techniques.

- **Value of EDR/XDR**  
  This project showed me the importance of endpoint detection and XDR correlation. Microsoft Defender for Endpoint blocked the detected Trojan and quarantined the EICAR test file, demonstrating how security tools can help detect and respond to suspicious activity.



