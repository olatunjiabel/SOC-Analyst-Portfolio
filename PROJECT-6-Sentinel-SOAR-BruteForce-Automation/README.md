#  Microsoft Sentinel SOAR Project — Brute Force Detection

## Project Overview

The main aim of this project is to build a SOAR workflow using Microsoft Sentinel and Logic Apps, with Microsoft 365 Outlook used for email notifications.

In this lab, I used a brute-force incident to trigger the automation workflow. When a matching incident is processed, the Logic App sends an email notification to the SOC analyst through Outlook.

This project demonstrates how Microsoft Sentinel automation rules, Logic Apps, and Microsoft 365 can work together to notify a SOC analyst when a security incident occurs.

The project also helped me understand the permissions required to connect a Sentinel automation rule to a Logic App playbook.

SOAR (Security Orchestration, Automation, and Response) refers to the automated activities and workflows put in place to respond to alerts and incidents more efficiently.

This project shows how SOAR can:
- Reduce analyst workload
- Improve response time
- Automate repetitive response tasks
- Improve visibility into authentication attacks

---

## Prerequisites

- Microsoft Azure Subscription
- Microsoft Sentinel Workspace deployed
- Microsoft 365 Business Standard or E5 License (required for Logic App Outlook connector)
- Microsoft Defender for Office 365
- Log Analytics Workspace with SigninLogs enabled
- Role Assignment: **Sentinel Automation Contributor** assigned to **Azure Security Insights** via IAM

---

## Technologies Used

- **Microsoft Sentinel**
- **KQL** (Kusto Query Language)
- **Analytic Rule**
- **Automation Rule**
- **Logic App / Playbook**
- **Defender for Office 365 / Office 365 E5 License**
- **Role Assignment via IAM** - Sentinel Automation Contributor assigned to Azure Security Insights

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |

---

## What I Built

I configured a Microsoft Sentinel Analytics Rule using KQL to detect potential brute-force activity and generate an incident.

I then created a Logic App playbook to send an email notification to the SOC analyst through Outlook when a matching incident triggers the workflow.

When I tried to integrate the playbook with the Sentinel automation rule, I could not select the playbook. I resolved this by assigning the Sentinel Automation Contributor role to Azure Security Insights through IAM.

After assigning the role, I was able to integrate the playbook into the workflow. This helped me understand how permissions affect SOAR automation in Microsoft Sentinel.

![Analytics Rule](screenshots/01-analytics-rule.png)

**KQL Query Logic:**

```kql
SigninLogs
| where TimeGenerated >= ago(1h)
| summarize 
    FailedAttempts = countif(ResultType != 0),
    SuccessfulAttempts = countif(ResultType == 0),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IPAddress, UserPrincipalName
| where FailedAttempts >= 5 and SuccessfulAttempts >= 1
| sort by LastSeen desc
```

The KQL is set to automatically create an incident in Defender portal when there's 5 failed attempts or greater and successful attempts is greater than or equal to 1.

![KQL Detection Query](screenshots/03-kql-detection-query.png)

---

### 2. Automation Rule

The Playbook was assigned/integrated to that Analytic rule via the Automation Tab in Sentinel.

![Automation Rule](screenshots/02-automation-rule.png)

---

### 3. Incident Generated

After simulating a Brute Force Attack by entering multiple wrong passwords on my Microsoft user account, an incident was generated in Defender.

![Incident Generated](screenshots/04-incident-generated.png)

---

### 4. Logic App / Playbook
I created a Logic App with the following configuration:

**Trigger:** When an incident is created or updated in Microsoft Sentinel
**Condition:** Filter for brute force incidents only
**Actions:** 
- Send email notification to SOC analyst mailbox

The Logic App validates the incident and only triggers for brute force 
incidents, avoiding unnecessary alert fatigue.

![Logic App Playbook](screenshots/05-logic-app-playbook.png)

---

### 5. Email Alert Configuration

The Send an email (V2) action was configured to notify the SOC analyst mailbox with High importance whenever a brute force incident is triggered.

![Email Alert Configuration](screenshots/06-email-alert-configuration.png)

---

### 6. Outlook Alert — It Works! 

The SOC analyst receives a Brute-Force Alert email directly on Outlook every time the incident is triggered.

![Outlook Alert](screenshots/07-outlook-alert.png)

---

## Detection Method — Brute Force Attack Simulation

Using the Brute Force Attack method, I simulated by entering multiple wrong passwords on my Microsoft user account to generate an alert/incident in Defender.

- An Analytics Rule was already created beforehand with the KQL written and set to automatically create an incident in Defender portal when there's **5 failed attempts or greater** AND **successful attempts is greater than or equal to 1**.

---

## SOAR Workflow

```
Brute Force Attempt
      ↓
KQL Query Detection
      ↓
Analytics Rule
      ↓
Incident Creation
      ↓
Automation Rule
      ↓
Logic App Workflow
      ↓
Outlook Alert 
```

---

## What I Learned

To enable SOAR and to be able to add automation rules to my Analytic rule, I was prompted to assign the role of Sentinel Automation Contributor to Azure Security Insights in IAM (Identity Access Management).This is a very important step to do in other to carry out SOAR automation function properly.

The license for Defender for Office 365 Plan 2 E5 is needed or Business Premium License to be able to use the Outlook connector in the Logic App. This pushed me to set up a proper Microsoft 365 licensing configuration in my home lab.

This project helped me understand how SOAR can reduce manual work by automating parts of the incident notification process.

In my lab, the playbook sends an email notification to the SOC analyst through Outlook when a matching brute-force incident triggers the workflow. This can reduce the time between an incident appearing in Sentinel and the analyst being notified.

The workflow demonstrates automated notification, not automatic blocking of an IP address or disabling of a user account.

---

## Author

**Olatunji Abel**  
SOC Analyst | Home Lab | Microsoft Sentinel 
