# Sample Tickets

## TKT-001 — Abnormal Port Scan Activity Against Web Server

| Field | Value |
|---|---|
| **Ticket ID** | TKT-001 |
| **Severity** | Critical |
| **Kill Chain Phase** | Reconnaissance |
| **MITRE ATT&CK** | T1595.002, T1589 |
| **Status** | Closed |
| **Linked Report** | [Incident Report TKT-001](./incident-reports/TKT-001-port-scan.md) |

**Scenario:**
The SOC received an IDS alert flagging unusual inbound traffic. An external IP was observed generating a high volume of connection attempts against an internal Frothly web server (`172.31.38.181`) acr[...]

---

## TKT-007 — Large Data Transfer to External IP via HTTP POST

| Field | Value |
|---|---|
| **Ticket ID** | TKT-007 |
| **Severity** | High |
| **Kill Chain Phase** | Exfiltration |
| **MITRE ATT&CK** | T1048.003, T1567 |
| **Status** | Closed |
| **Linked Report** | [Incident Report TKT-007](./incident-reports/TKT-007-data-exfiltration.md) |

**Scenario:**
A DLP alert fired after detecting an unusually large outbound data transfer from a Frothly internal host to an external IP (`52.40.10.231`) not in the corporate whitelist. The transfer occurred via mu[...]

---

## TKT-008 — Scheduled Task Created by Non-Admin User for Persistence

| Field | Value |
|---|---|
| **Ticket ID** | TKT-008 |
| **Severity** | Medium |
| **Kill Chain Phase** | Installation |
| **MITRE ATT&CK** | T1053.005, T1036 |
| **Status** | Closed |
| **Linked Report** | [Incident Report TKT-008](./incident-reports/TKT-008-scheduled-task.md) |

**Scenario:**
Windows Security logs recorded the creation of a new scheduled task on a Frothly workstation. The task name closely mimics a legitimate Windows service name. It was created by a non-administrative user account and is configured to execute a binary located in a user-writable temp directory at a frequent interval — a classic persistence technique used by malware after initial compromise.

---

## TKT-010 — Drive-By Download via Malicious Ad Network Redirect

| Field | Value |
|---|---|
| **Ticket ID** | TKT-010 |
| **Severity** | Low |
| **Kill Chain Phase** | Delivery |
| **MITRE ATT&CK** | T1189, T1204.001 |
| **Status** | Closed |
| **Linked Report** | [Incident Report TKT-010](./incident-reports/TKT-010-drive-by-download.md) |

**Scenario:**
Proxy and HTTP stream logs show a Frothly workstation visiting a legitimate website that triggered a redirect chain through multiple hops ending at a suspicious external domain. A JavaScript file was downloaded followed by a Windows executable. No antivirus alert was generated at the time, highlighting a detection gap. The executable filename mimics a legitimate system service.
