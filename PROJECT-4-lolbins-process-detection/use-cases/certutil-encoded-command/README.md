# Certutil Encoded Execution (LOLBIN Abuse)

##  Attack Simulation

Certutil is one of Windows Process used basically for Manual verification of Digital certificate, it can be used to execute commands too and also download files.

Hackers usually take advantage of this Certutil that is part of the Microsoft LOLBIN to download malwares on a target computers, encode files as well. Hackers love to use this Certutil in the background to do all this because the computer firewall hardly block LOLBINS execution. So therefore Analysts sometimes needs to manually hunt for this threats.

I simulated a Certutil LOLBIN attack using Powershell to run the Certutil encoded command to encode `notepad.exe`. Then I wrote a KQL detection query to detect the CommandLine, Parent Image and Image.

---


##  Log Source

* Sysmon (Event ID 1 – Process Creation)

---

##  Detection (KQL Query)

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| parse EventData with * '<Data Name="CommandLine">' CommandLine '</Data>' *
| parse EventData with * '<Data Name="Image">' Image '</Data>' *
| parse EventData with * '<Data Name="ParentImage">' ParentImage '</Data>' *
| where Image endswith "certutil.exe"
| where CommandLine has_any ("-encode", "-decode", "-urlcache")
| project TimeGenerated, Computer, Image, ParentImage, CommandLine
| order by TimeGenerated desc
```

---


###  Detection Result

![Certutil KQL Detection](../screenshots/certutil-kql-detection.png)

---

##  Investigation

The question is what is suspicious about Certutil running an encoded command right?

Well a normal user wouldn't know how to use Powershell let alone encoding commands. Moreover what is the use of hiding commands if it is legit.

So to investigate you look for:

* **CommandLine** — which shows the command used
* **Image** — which shows the process executed
* **Parent Image** — shows what executed the Image

In cases like this investigation must be done thoroughly, Parent Image and Image let you see properly if there is a C2 Beacon attack. LOLBIN is usually taken advantage of a lot by adversaries.

---

###  Process Execution Evidence (Parent-Child Relationship)
![Certutil CommandLine](../screenshots/certutil-commandline.png)


---

##  Analytics Rule Creation (Automated Detection)

As a SOC analyst, sometimes we need automated threat detection. This can be done in an Azure environment using Azure Analytics Rules and KQL to write queries that automatically detect threats.

I wrote a KQL detection rule to detect suspicious LOLBIN execution (Certutil). The aim of the KQL is to detect any execution of certutil that encodes, decodes, or downloads files using URL cache.

The KQL also demonstrates parent-child process relationships, which helps in identifying how the process was executed.

I used a threshold of ≥ 3. So anytime certutil.exe encodes, decodes, or runs suspicious commands 3 times or more, it automatically generates an alert.

The KQL also detects the first seen and last seen time of each attack.

During the analytics rule creation process, I mapped entities using the host (computer name where the attack happened). I also mapped process details such as Process Name and CommandLine.

All these are shown in the attack story, including the host computer and the type of process that was executed on it.

I correlated all alerts within a 30-minute window into one incident. The query runs every 5 minutes.

Then I created the rule and simulated the attack in PowerShell using certutil to encode a file, which successfully generated an alert and incident.

##  Certutil-Automated-Detection (KQL Query)

```kql
Event
| where Source =="Microsoft-Windows-Sysmon"
| where EventID ==1
| where TimeGenerated >= ago(30m)
| parse EventData with * '<Data Name="CommandLine">' CommandLine '</Data>' *
| parse EventData with * '<Data Name="ParentImage">' ParentImage '</Data>' *
| parse EventData with * '<Data Name="Image">' Image '</Data>' *
| where CommandLine has_any ("-encode","-decode","-urlcache")
| where Image endswith "certutil.exe" 
| where ParentImage has_any ("powershell.exe","mshta.exe","cmd.exe")
| summarize Process=count(),FirstSeen=min(TimeGenerated),Lastseen=max(TimeGenerated) by Computer,CommandLine,Image,ParentImage
| where Process >= 3 
| order by Lastseen desc
```

###  Analytics Rule Configuration

#### Entity Mapping
![Entity Mapping](../screenshots/certutil-entity-mapping.png)

#### Query Scheduling
![Query Scheduling](../screenshots/certutil-query-scheduling.png)

#### Incident Grouping
![Incident Grouping](../screenshots/certutil-incident-grouping.png)

#### Incident Graph
![Incident Graph](../screenshots/certutil-incident-graph.png)

#### Attack Story
![Attack Story](../screenshots/certutil-attack-graph.png)

---

### Outcome

The analytics rule successfully detected repeated certutil executions and generated an alert.

The incident graph and attack story provided visibility into the affected host and process execution chain, making investigation easier and faster.

---


##  SOC Workflow

When stuffs like this happen in a SOC Environment, it's triage first which is verifying the Alert, then investigate by using the SIEM tool like Microsoft Sentinel to see what has been done.

**1. Triage**
* Verify the alert by checking the alert details.
* Confirm if it's a false positive or true positive.

**2. Investigation**
* Use Microsoft Sentinel to investigate in detail by checking for any suspicious processes that ran on the endpoint.
* If any encoded command was run, it should be decoded to see the details of the command.
* Establish any parent-child relationship between suspicious processes.

**3. Containment**
* If it's a malware download, immediately check for the blast radius impact.
* If it is spreading, disconnect the endpoint from the network.

**4. Remediation**
* Use anti-malware to scan, e.g., Defender for Endpoint.
* Check for any external connections from a suspicious IP.
* Block any outbound connections from your endpoint to the suspicious IP.
* Microsoft Intune lets you know if the device health is safe to connect back.

**5. Reporting**
* Write a report about your findings.
* Escalate to the IT department if necessary.

---

##  Response Actions

* Device isolation
* Process termination
* Blocking suspicious Certutil usage
* Full endpoint malware scan

---

##  MITRE ATT&CK Mapping

* Technique: **T1140 – Deobfuscate/Decode Files or Information**
* Technique: **T1105 – Ingress Tool Transfer**
* Tactic: **Defense Evasion / Command and Control**

