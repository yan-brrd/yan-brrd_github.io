# Incident Report: TKT-007 — Large Data Transfer to External IP via HTTP POST

## Executive Summary

On an unspecified date, an internal workstation (10.0.1.100)—previously compromised via malicious PowerShell execution—executed an automated script to exfiltrate 243.5 MB of corporate data to an unauthorized external IP address (52.40.10.231) over HTTP POST requests. The entire operation completed within a 3-minute window at an average rate of 81.17 MB per minute. The attacker masked the traffic using the `application/octet-stream` MIME type to bypass deep packet inspection and Data Loss Prevention filters. The incident was detected via real-time DLP alerts and confirmed through Splunk HTTP stream analysis.

**Severity:** High  
**Kill Chain Phase:** Exfiltration  
**MITRE ATT&CK:** T1048.003, T1567

---

## IOCs / Artifacts

| Artifact | Value | Notes |
|---|---|---|
| **Compromised Host** | 10.0.1.100 | Internal workstation (source of exfiltration) |
| **Exfiltration Destination** | 52.40.10.231 | External, unauthorized recipient IP |
| **Data Volume** | 243.5 MB | Total payload across 45 HTTP POST requests |
| **MIME Type** | application/octet-stream | Generic binary; indicates packing/encryption to bypass DLP |
| **Time Window** | 3 minutes | High-velocity exfiltration window |
| **Transfer Rate** | 81.17 MB/minute | Sustained outbound throughput |
| **Network Vector** | HTTP POST | Application-layer exfiltration method |

---

## Splunk Search Queries

### Primary Search — HTTP Stream Analysis
```
index=botsv2 sourcetype=stream:http http_method=POST src_ip="10.0.1.100"
| stats sum(bytes_out) as total_bytes, count as requests by dest_ip
| eval MB=round(total_bytes/1048576,2)
| sort -total_bytes
```

### Alternative — PAN Firewall Large Sessions
```
index=botsv2 sourcetype=pan:traffic src_ip="10.0.1.100"
| stats sum(bytes_sent) as total_sent by dest_ip
| eval MB=round(total_sent/1048576,2)
| sort -total_sent
```

---

## Triage Analysis

### Q1: What is the average transfer size per POST request? Calculate the MB/minute transfer rate.

**Average Transfer Size:** Based on the BOTS v2 HTTP stream logs for this session, the attacker transmitted a cumulative total of 243.5 MB across 45 distinct HTTP POST requests, resulting in an average transfer size of approximately **5.41 MB per request**.

**Transfer Rate:** The entire data exfiltration operation was executed over a compact window of exactly **3 minutes**.

**Calculation:**
- Transfer Rate = 243.5 MB / 3 minutes
- **Average Rate:** 81.17 MB per minute

### Q2: Why is 'application/octet-stream' a red flag when seen in large outbound POST requests?

**Red Flag Analysis:** The MIME type `application/octet-stream` signifies a raw, generic binary file with no explicitly defined structure or media type.

**Security Implications:** In legitimate enterprise workflows, outbound web traffic usually consists of:
- Structured forms (`application/x-www-form-urlencoded`)
- Specific API data formats (`application/json`)

A large volume of outbound `application/octet-stream` data indicates that a program is transmitting raw binary files—such as encrypted archives (.zip, .rar, .7z), compiled payloads, or memory dumps—to **bypass deep-packet inspection gateways and standard Data Loss Prevention (DLP) string filters**.

### Q3: Map to Kill Chain Exfiltration phase. Explain the difference between Exfiltration and Actions on Objectives.

**Cyber Kill Chain Phase:** Exfiltration

**Core Distinction:**

- **Exfiltration:** Focuses strictly on the physical or logical transmission of sensitive data across network boundaries to an external, adversary-controlled space.
  
- **Actions on Objectives:** Represents the ultimate goal or final destination of the campaign. While exfiltration can be part of this phase, Actions on Objectives covers broader structural damage, such as:
  - Deploying ransomware to encrypt internal systems
  - Destroying critical infrastructure
  - Defacing web properties
  - Manipulating business operations

### Q4: Identify MITRE T1048.003. What security controls would have detected or blocked this transfer?

**MITRE ATT&CK Mapping:** T1048.003 (Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Non-Application Protocol)

This covers adversaries leveraging standard application channels (like HTTP) to move data out-of-band rather than using traditional administrative file transfer routes.

**Defensive Controls for Detection/Blocking:**

- **Next-Generation Firewall (NGFW) & Gateway Throttling:** Implementing strict content inspection to block outbound connections to external IPs with no valid domain reputation or matching categorizations.

- **Data Loss Prevention (DLP) File Policies:** Configuring network DLP rules to automatically block or flag outbound HTTP POST requests that exceed a specific cumulative threshold (e.g., >50 MB) or contain unclassified binary MIME types.

- **Proxy / Cloud Access Security Broker (CASB):** Restricting outbound POST methods exclusively to corporate-approved cloud storage endpoints and requiring step-up authentication for large file transfers.

### Q5: Draft the triage escalation note — what mandatory information must be included before notifying management?

**CRITICAL INCIDENT ESCALATION NOTE**

---

**Date:** June 11, 2026

**1. INCIDENT OVERVIEW:**
Confirmed active data exfiltration originating from internal asset 10.0.1.100 to an unverified external C2 IP address (52.40.10.231).

**2. IMPACT & SCOPE:**
- **Compromised Host:** Workstation 10.0.1.100 (previously flagged for malicious PowerShell activity)
- **Data Volume Transmitted:** 243.5 MB of generic binary data (`application/octet-stream`) over a 3-minute window
- **Attack Vector:** Automated HTTP POST request scripting

**3. CONTAINMENT ACTIONS TAKEN:**
- Host 10.0.1.100 has been network-isolated via EDR to prevent further exfiltration
- Destination IP 52.40.10.231 has been blocked at the perimeter firewall

**4. NEXT REQUIRED STEPS:**
Initiate an immediate forensic investigation on the isolated host to locate the source directory of the exfiltrated data and identify if customer PII or proprietary trade secrets were included in the stolen staging archive.

---

## Timeline

| Timestamp | Event | Evidence |
|---|---|---|
| T-0 | Malicious PowerShell execution on 10.0.1.100 | EDR detection (previous alert) |
| T+[3min window] | Data exfiltration script execution initiated | HTTP POST streams detected |
| T+3min | Exfiltration completed (243.5 MB transferred) | Splunk stream:http data |
| Detection | DLP alert triggered on volume threshold | Real-time DLP system |
| Response | Host isolated; firewall rule deployed | EDR + Firewall ACL update |

---

## Recommended Response Actions

### Containment

**Host Isolation:** Immediately apply full network isolation to workstation 10.0.1.100 via the EDR system to completely sever outbound communication lines.

**Perimeter Destination Block:** Update edge firewall access control lists (ACLs) and web proxy gateways to drop and log all traffic traveling to destination IP 52.40.10.231.

### Eradication

**Identify Staged Files:** Audit local file-creation logs, Recent items, and Recycle Bin folders on the isolated workstation to locate the staging directory where the attacker compiled the 243.5 MB archive.

**Remove Script Mechanics:** Find and delete the malicious script, scheduled task, or background daemon responsible for generating the rapid HTTP POST sequence.

### Recovery

**Data Impact Assessment:** Perform a deep host file audit to map exactly what directories were accessed prior to the transfer to determine if customer PII, corporate source code, or proprietary financials were compromised.

**Clean System Re-image:** Re-image the asset's operating system entirely from a clean, corporate standard deployment image to guarantee full sanitization.

**Credential Rotation:** Force a mandatory password change and terminate active session tokens for all user accounts assigned to or cached on the workstation.

---

## Detection Gap & Recommendations

### Detection Gap

While the DLP engine successfully flagged the event after execution, the network gateway allowed a high-velocity outbound transfer of unclassified binary code (`application/octet-stream`) to an unrated external IP without enforcing inline bandwidth throttling or data-cap blockages.

### Remediation

Implement explicit Data Loss Prevention (DLP) boundary rules that dynamically block or quarantine any outbound HTTP POST sessions exceeding a total volume of 50 MB to non-whitelisted destinations. Configure proxy controls to inspect or block generic binary attachments moving outbound via standard web ports.

---

## Report Metadata

| Field | Value |
|---|---|
| **Analyst Name** | Adrian Gian Barredo |
| **Ticket ID** | TKT-007 |
| **Severity** | High |
| **Kill Chain Phase** | Exfiltration |
| **MITRE ATT&CK Techniques** | T1048.003, T1567 |
| **Affected Host(s)** | 10.0.1.100 |
| **Exfiltration Recipient** | 52.40.10.231 |
| **Data Volume Compromised** | 243.5 MB |
| **Report Status** | Complete |
