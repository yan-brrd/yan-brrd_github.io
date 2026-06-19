# Incident Report: TKT-008 — Scheduled Task Created by Non-Admin User for Persistence

## Executive Summary

On 08/29/2017, Windows Security logs recorded the creation of a malicious scheduled task on a Frothly workstation. The task was named `\Microsoft\Windows\Defrag\ScheduledDefrag_Update`—masquerading as a legitimate operating system maintenance job. Created by a non-administrative user account, the task was configured to execute a binary located in the user-writable `AppData\Local\Temp` directory at frequent intervals. This represents a classic persistence technique used by malware after initial compromise. The persistence mechanism was detected via Windows Security Event logs (Event Code 4698) and confirmed through Splunk analysis.

**Severity:** Medium  
**Kill Chain Phase:** Installation  
**MITRE ATT&CK:** T1053.005, T1036

---

## IOCs / Artifacts

| Artifact | Value | Notes |
|---|---|---|
| **Affected Host** | Frothly workstation (BTUN-L) | Internal Windows system |
| **Task Name** | \Microsoft\Windows\Defrag\ScheduledDefrag_Update | Masquerading as legitimate OS task |
| **Creator Account** | Non-administrative user | Low-privilege execution context |
| **Payload Location** | AppData\Local\Temp | User-writable, volatile directory |
| **Detection Method** | Windows Event ID 4698 | Scheduled task creation log |
| **Execution Mechanism** | schtasks.exe | Windows Task Scheduler CLI |

---

## Splunk Search Queries

### Primary Search — Windows Security Event Logs
```
index=botsv2 sourcetype=wineventlog:security EventCode=4698
| table _time, Computer, TaskName, SubjectUserName, Command, Arguments
| sort -_time
```

### Alternative — Windows Registry Run Key Persistence
```
index=botsv2 sourcetype=winregistry
| search registry_path="*CurrentVersion\\Run*"
| table _time, Computer, registry_path, registry_value_data, user
| sort -_time
```

---

## Triage Analysis

### Q1: What is the exact scheduled task name? Why is this task name considered masquerading (MITRE T1036)?

**Exact Task Name:** `\Microsoft\Windows\Defrag\ScheduledDefrag_Update`

**Why It Is Masquerading:** The name heavily mimics legitimate, built-in operating system automation (`ScheduledDefrag`). By appending `_Update` and dropping the malicious task directly into the standard `\Microsoft\Windows\Defrag` folder structure, the adversary leverages MITRE T1036 (Masquerading) to make the task blend into thousands of routine Windows maintenance logs, deceiving busy system administrators or basic keyword filters.

### Q2: The executable path is in AppData\Local\Temp. What does this file location tell you about how it was placed there?

**Analysis:** The `AppData\Local\Temp` path is a highly volatile, user-writable directory. Because writing files to standard application paths (like `C:\Program Files`) requires elevated local administrator permissions, a non-admin account must drop its payloads into folders it natively owns. This tells us the binary was dropped via user-level execution, such as:
- A browser drive-by download
- A malicious email attachment extraction
- A secondary stager running under the context of the logged-in, non-privileged employee profile

### Q3: Map to Kill Chain Installation phase. Explain the difference between persistence and privilege escalation.

**Cyber Kill Chain Phase:** Installation

**Core Differences:**

- **Persistence:** Focuses entirely on maintaining access. The goal is to ensure the malicious payload survives system reboots, user logoffs, or network configuration changes, regardless of the user's rights.

- **Privilege Escalation:** Focuses on expanding control. The goal is to bypass active operating system security boundaries to transition from a low-privilege user account to a high-privilege account (such as SYSTEM or Local Administrator), gaining deep structural command over the system.

### Q4: How do MITRE techniques T1053.005 and T1036 interact in this attack chain? Describe each technique briefly.

**T1053.005 (Scheduled Task/Job: Scheduled Task):** The administrative mechanism used to register a script or binary with the Windows Task Scheduler engine, instructing it to launch at a specific interval or trigger event.

**T1036 (Masquerading):** The tactical manipulation of a file name, process name, path, or task name to look identical or highly similar to trusted operating system artifacts.

**Interaction:** The adversary uses T1053.005 to build the functional engine for persistence, while using T1036 to dress the task up in safe clothing. This camouflage hides the malicious entry from operational views, ensuring the persistent channel remains active as long as possible.

### Q5: List three specific forensic artifacts an analyst should collect from BTUN-L before the host is re-imaged.

**1. The XML Task Definition from C:\Windows\System32\Tasks**

Since Event Code 4698 failed to log due to an environment logging gap, extracting the raw XML file directly from the disk is the only way to preserve the task's exact configuration parameters, creation timestamps, and scheduling triggers.

**2. The Malicious Binary Executable from AppData\Local\Temp**

Essential for static/dynamic malware detonation and hash extraction (SHA-256) to update corporate blocklists.

**3. Windows Security Logs capturing Event Code 4688**

Since task creation logs failed, the process execution logs must be collected as forensic proof, as they capture the underlying command lines (`schtasks.exe /create ...`) used to establish the persistence hook.

---

## Timeline

| Timestamp | Event | Evidence |
|---|---|---|
| T-0 | Initial compromise / malware drop (date unknown) | User-level process execution |
| 08/29/2017 | Scheduled task created via schtasks.exe | Event ID 4698 logged |
| 08/29/2017 | Persistence mechanism becomes active | Task registered in Task Scheduler |
| Detection | Security audit discovers suspicious task | Splunk analysis of Event Code 4698 |
| Response | Host isolated; task disabled and deleted | EDR console action |

---

## Recommended Response Actions

### Containment

**Host Isolation:** Isolate workstation BTUN-L from the local network via the EDR console to stop any downstream C2 check-ins while preserving volatile RAM.

**Task Disabling:** Force-disable the `ScheduledDefrag_Update` task via the command-line utility:
```
schtasks /change /tn "\Microsoft\Windows\Defrag\ScheduledDefrag_Update" /disable
```

### Eradication

**Task Deletion:** Permanently delete the unauthorized scheduled task:
```
schtasks /delete /tn "\Microsoft\Windows\Defrag\ScheduledDefrag_Update" /f
```

**Payload Purge:** Locate and permanently delete the target binary residing inside the user's `AppData\Local\Temp` folder.

### Recovery

**Volatile Memory Sweep:** Run an endpoint malware scan on BTUN-L to ensure no active processes are running out of RAM.

**User Profile Sanitation:** Clear the user's local Temp directories and review active registry Run keys to ensure no alternative persistence mechanisms were introduced.

---

## Detection Gap & Recommendations

### Detection Gap

The Windows OS allowed a non-administrative user profile to register an automated background task executing unverified binary types out of a temporary directory without triggering a security challenge.

### Remediation

Enforce Group Policy Objects (GPOs) or AppLocker rules that restrict user-writable directories (like Temp and AppData) from executing executable formats (.exe, .bat, .vbs). Implement continuous monitoring profiles within the SIEM to flag any new scheduled tasks that reference user profile directories in their Command arguments.

---

## Report Metadata

| Field | Value |
|---|---|
| **Analyst Name** | Adrian Gian Barredo |
| **Date & Time** | 08/29/2017 |
| **Ticket ID** | TKT-008 |
| **Severity** | Medium |
| **Kill Chain Phase** | Installation |
| **MITRE ATT&CK Techniques** | T1053.005, T1036 |
| **Affected Host(s)** | Frothly Windows Workstation (BTUN-L) |
| **Execution Context** | Non-administrative user account |
| **Report Status** | Complete |
