# Incident Report: TKT-001 — Abnormal Port Scan Activity Against Web Server

## Executive Summary

On 8/19/17 at 2:04:33 PM, an external IP address (111.249.38.34) executed an aggressive, automated port scan against internal web server 172.31.38.181 targeting five common service ports (22, 80, 443, 3389, 8080). The attacker generated approximately 1,250 connection attempts within a 10-second window. No unauthorized access or successful authentications occurred. The activity was detected via IDS alert and confirmed through Splunk analysis.

**Severity:** Critical  
**Kill Chain Phase:** Reconnaissance  
**MITRE ATT&CK:** T1595.002, T1589

---

## IOCs / Artifacts

| Artifact | Value | Notes |
|---|---|---|
| **Target Host** | 172.31.38.181 | Internal Frothly web server |
| **Attacker Source IP** | 111.249.38.34 | External scanning origin |
| **Probed Ports** | 22, 80, 443, 3389, 8080 | SSH, HTTP, HTTPS, RDP, HTTP-Alt |
| **Connection Count** | ~1,250 requests | Within 10-second window |
| **Network Artifact** | TCP SYN streams | High-volume synchronization packets |

---

## Splunk Search Queries

### Primary Search — TCP Stream Analysis
```
index=botsv2 sourcetype=stream:tcp dest_ip="172.31.38.181"
| stats count by src_ip, dest_port
| where count > 5
| sort -count
```

### Alternative — Suricata IDS Alerts
```
index=botsv2 sourcetype=suricata dest_ip="172.31.38.181"
| stats count by src_ip, alert.signature
| sort -count
```

---

## Triage Analysis

### Q1: Which source IP performed the scan? List all destination ports that were probed.

**Primary Scanner IP:** 111.249.38.34

**Probed Destination Ports:**
- 22 (SSH)
- 80 (HTTP)
- 443 (HTTPS)
- 3389 (RDP)
- 8080 (HTTP Alternate / Management)

### Q2: What is the total time window of the scan activity? Calculate the average requests-per-minute rate.

**Total Time Window:** 10 seconds (0.167 minutes)

**Calculation:**
- Requests per minute = 1,250 requests / 0.167 minutes
- **Average Rate:** ~7,500 requests-per-minute

### Q3: Using the Cyber Kill Chain, at which phase does this activity belong? Explain your reasoning.

**Phase:** Reconnaissance

**Reasoning:** The adversary is actively probing network perimeters to map out open ports, identify live hosts, and discover running applications or operating system versions. No active exploitation, malware delivery, or data exfiltration has occurred yet; the threat actor is merely harvesting information to find a potential entry point into the Frothly network.

### Q4: Map this event to a specific MITRE ATT&CK technique ID. Describe what the sub-technique means.

**MITRE ATT&CK ID:** T1595.002 (Reconnaissance: Active Scanning - Port Scanning)

**Sub-technique Description:** This sub-technique refers to an adversary sending packets to specific host ports to determine service availability, application versions, and potential vulnerabilities. The technique allows the attacker to identify accessible entry pathways before launching a targeted exploit.

### Q5: What should be the immediate containment action? Write the firewall rule you would apply.

**Immediate Containment Action:** Blacklist the malicious external IP at the perimeter network firewall to drop all inbound traffic before it reaches internal assets.

**Firewall Rules (Platform-Specific):**

**Cisco ASA/Cisco IOS ACL:**
```
access-list INBOUND_DENY line 1 extended deny ip host 111.249.38.34 any
```

**Linux iptables:**
```
iptables -I INPUT -s 111.249.38.34 -j DROP
```

**FortiGate CLI / Palo Alto:**
```
config firewall policy
edit <policy_id>
set srcaddr "111.249.38.34"
set dstaddr "172.31.38.181"
set action deny
end
```

---

## Timeline

| Timestamp | Event | Evidence |
|---|---|---|
| 8/19/17 2:04:33 PM | Port scan initiated from 111.249.38.34 | IDS alert triggered; TCP stream logs |
| 8/19/17 2:04:43 PM | Scan completed (10-second window) | ~1,250 SYN packets observed in Splunk |
| 8/19/17 2:05:00 PM | Alert reviewed by SOC; ticket opened | TKT-001 created |

---

## Recommended Response Actions

### Containment

**Immediate IP Blocking:** Deploy an edge firewall rule to drop all inbound traffic from 111.249.38.34.

**Rate Limiting:** Implement connection throttling on the external network gateway for host 172.31.38.181 to prevent future automated scanning spikes.

### Eradication

**Session Termination:** Kill any active network connections or lingering TCP states tied to the attacker IP.

**Access Control Review:** Verify external access policies and ensure management ports (SSH/22 and RDP/3389) are restricted to VPN ranges only.

**Vulnerability Scanning:** Run a targeted vulnerability scan on the web server's open ports to check for unpatched exposure.

### Recovery

**Log Verification:** Audit application and web access logs to fully confirm zero successful authentications or anomalies.

**Service Status Monitoring:** Check web service stability to ensure the connection surge caused no performance degradation.

**Continuous Monitoring:** Add 111.249.38.34 to the SIEM watchlist for the next 7 days to track potential repeat or distributed attempts.

---

## Detection Gap & Recommendations

### Detection Gap

The current IDS alerted on the volume, but the network perimeter did not automatically block the source. This allowed the full scanning activity to complete within the 10-second window.

### What Should Be Done

**Recommendation:** Implement an automated firewall shunning/blocklist policy or a dynamic Intrusion Prevention System (IPS) rule to automatically drop external IPs executing scanning on multiple ports. This would reduce reconnaissance dwell time and raise the cost of initial reconnaissance for adversaries.

---

## Report Metadata

| Field | Value |
|---|---|
| **Analyst Name** | Adrian Gian Barredo |
| **Date & Time** | 8/19/17 2:04:33 PM |
| **Ticket ID** | TKT-001 |
| **Severity** | Critical |
| **Kill Chain Phase** | Reconnaissance |
| **MITRE ATT&CK Techniques** | T1595.002, T1589 |
| **Affected Host(s)** | 172.31.38.181 |
| **Attacker IP** | 111.249.38.34 |
| **Report Status** | Complete |
