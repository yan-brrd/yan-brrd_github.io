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
The SOC received an IDS alert flagging unusual inbound traffic. An external IP was observed generating a high volume of connection attempts against an internal Frothly web server (`172.31.38.181`) across multiple ports in a short time window. No successful authentication was logged. Task: confirm the scan activity, identify the source, and determine the scope.
