# Sample Tickets

## TKT-001 — Abnormal Port Scan Activity Against Web Server

**Severity:** Critical · **Kill Chain Phase:** Reconnaissance · **MITRE ATT&CK:** T1595.002, T1589

### Scenario
The SOC received an IDS alert flagging unusual inbound traffic. An external IP was observed generating a high volume of connection attempts against an internal Frothly web server (`172.31.38.181`) across multiple ports in a short time window. No successful authentication was logged.

### IOCs / Artifacts
- Target Host: `172.31.38.181`
- Source IP: `111.249.38.34`
- Probed Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP), 8080 (HTTP Alt)
- High connection count in a short window

### Splunk Search Query
```spl
index=botsv2 sourcetype=stream:tcp dest_ip="172.31.38.181"
| stats count by src_ip, dest_port
| where count > 5
| sort -count
```

Alternative — using Suricata IDS alerts for scan signatures:
```spl
index=botsv2 sourcetype=suricata dest_ip="172.31.38.181"
| stats count by src_ip, alert.signature
| sort -count
```

### Analysis

**Scan scope:** The attacker (`111.249.38.34`) probed 5 destination ports against the target host, generating roughly 1,250 connection attempts within a 10-second window — an average rate of ~7,500 requests per minute.

**Kill Chain phase:** Reconnaissance. The adversary was mapping open ports and live services to identify a potential entry point — no exploitation or data exfiltration occurred at this stage.

**MITRE ATT&CK mapping:** T1595.002 (Active Scanning: Port Scanning) — sending packets to specific ports to determine service availability and potential vulnerabilities ahead of a targeted exploit.

**Containment action:** Block the malicious source IP at the perimeter firewall.
```bash
# Cisco ASA / IOS
access-list INBOUND_DENY line 1 extended deny ip host 111.249.38.34 any

# Linux iptables
iptables -I INPUT -s 111.249.38.34 -j DROP
```

### Triage Report

| Field | Value |
|---|---|
| Analyst | Adrian Gian Barredo |
| Date & Time | 8/19/17, 2:04:33 PM |
| Ticket ID | TKT-001 |
| Severity | Critical |
| Kill Chain Phase | Reconnaissance |
| MITRE ATT&CK | T1595.002, T1589 |
| Affected Host | 172.31.38.181 |
| Source / Attacker IP | 111.249.38.34 |

**Summary of Findings:**
External IP `111.249.38.34` executed an aggressive, automated port scan against the internal web server `172.31.38.181` to find open entry points. No unauthorized access or successful authentication occurred. Detected via an IDS traffic volume alert and confirmed in Splunk using TCP stream and Suricata log analysis. The attacker targeted 5 distinct ports, generating ~1,250 connection attempts within a 10-second window.

**IOCs Identified:**
- Target Host: `172.31.38.181`
- Attacker IP: `111.249.38.34`
- Probed Ports: 22, 80, 443, 3389, 8080
- High-volume TCP SYN streams within a 10-second window

**Recommended Response Actions:**

*Containment*
- Deploy an edge firewall rule to drop all inbound traffic from `111.249.38.34`
- Implement connection throttling on the external gateway for the target host

*Eradication*
- Terminate any active connections or lingering TCP states tied to the attacker IP
- Review external access policies — restrict SSH/RDP to VPN ranges only
- Run a targeted vulnerability scan on the web server's open ports

*Recovery*
- Audit logs to confirm zero successful authentications or anomalies
- Monitor web service stability for performance degradation
- Add `111.249.38.34` to the SIEM watchlist for 7 days

**Lessons Learned / Detection Gap:**
The IDS alerted on scan volume, but the network perimeter did not automatically block the source. Recommend implementing an automated firewall blocklist policy or a dynamic IPS rule to drop external IPs performing multi-port scans.
