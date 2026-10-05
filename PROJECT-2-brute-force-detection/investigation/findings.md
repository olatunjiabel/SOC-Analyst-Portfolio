# Investigation Findings – Project 2: False Positive Analysis

##  What I Found

| Field | Value |
|---|---|
| Account | Administrator |
| Source IP | 127.0.0.1 |
| Logon Type | 7 |
| Failed Attempts | 7 |
| Time Window | < 10 minutes |

---

##  Investigation & Triage Process

**Step 1 - Alert fired**
Analytics rule triggered after 3+ failed logins detected within 10 minutes.

**Step 2 - Checked source IP**

The Source IP was `127.0.0.1`, which is the local host loopback address. This indicates that the failed authentication attempts originated from the local machine rather than from a remote network source.

This reduced the likelihood of a traditional external brute-force attack.

### Step 3 - Checked Logon Type

The event showed **Logon Type 7**, which represents a workstation unlock attempt.

This was significant because common remote authentication attacks would typically involve other logon types, such as **Logon Type 3 (Network)** or **Logon Type 10 (Remote Interactive/RDP)**.

### Step 4 - Concluded False Positive

The combination of the local loopback source address (`127.0.0.1`) and **Logon Type 7** indicated that the failed authentication attempts were associated with a local workstation unlock rather than a remote brute-force attack.

I therefore classified the alert as a **false positive**, most likely caused by the user entering an incorrect password while attempting to unlock the workstation.

---

##  Detailed Analysis

After thorough investigation I was able to discover that the alert was a false positive because the logon type 7 is a session unlock logon. A logon type 10 would have been more suspicious which is RDP. The source IP was 127.0.0.1 local host loopback address which insinuates that the failed attempts originated from the machine itself. The combination of these findings made me come to the conclusion that it was just the user entering an incorrect password while unlocking their machine.

---

##  Evidence

Screenshots of the following are included in the `/screenshots` folder:

 ![Alert Triggered](../screenshots/Alert-triggered.png) (shows alert,logontype,Account,Failedattempts)
 ![Event Log](../screenshots/Event-log.png) (shows KQL rule is usable for analytics rule)

