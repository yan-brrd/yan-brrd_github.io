# Incident Report: TKT-010 — Drive-By Download via Malicious Ad Network Redirect

## Executive Summary

On 08/15/2017, a Frothly workstation (10.0.2.109) fell victim to a passive drive-by compromise while navigating a legitimate website. A malicious advertisement network script forced a silent background redirect chain through multiple hops, dropping a staging JavaScript file that automatically initiated an unprompted download of a malicious Windows executable masquerading as a native operating system service. No antivirus alert was generated at the time of download, highlighting a critical detection gap in signature-based protection. The anomaly was discovered during an audit of proxy traffic and confirmed through Splunk HTTP stream analysis.

**Severity:** Low  
**Kill Chain Phase:** Delivery  
**MITRE ATT&CK:** T1189, T1204.001

---

## IOCs / Artifacts

| Artifact | Value | Notes |
|---|---|---|
| **Affected Workstation** | 10.0.2.109 | Internal endpoint victim |
| **Attack Vector** | Malicious ad network redirect | Multi-hop chain |
| **Payload Stages** | .js (JavaScript stager) + .exe (executable) | Sequential delivery |
| **Detection Status** | No antivirus alert | Signature-based AV blindspot |
| **Initial Entry Point** | Legitimate website | Compromised ad container |
| **Transport Method** | HTTP GET/POST | Unencrypted delivery |

---

## Splunk Search Queries

### Primary Search — HTTP Stream Executable and Script Downloads
```
index=botsv2 sourcetype=stream:http src_ip="10.0.2.109"
| search (uri_path="*.exe" OR uri_path="*.js" OR uri_path="*.php")
| table _time, dest_host, uri_path, http_content_type, bytes_in, http_referrer
| sort _time
```

### Alternative — Symantec Endpoint File Events
```
index=botsv2 sourcetype=symantec:ep:packet:file
| table _time, ComputerName, file_path, file_name, action
| sort -_time
| head 30
```

---

## Triage Analysis

### Q1: Reconstruct the full redirect chain using proxy logs. At which hop was the malicious payload introduced?

**Redirect Chain Reconstruction:**

The HTTP stream logs track a classic multi-hop malvertising redirect chain:

- **Hop 1 (Initial Referrer):** User visits a benign, high-traffic website hosting compromised ad scripts.

- **Hop 2 (Ad Network Redirect):** The compromised ad container forces a silent background redirect through an unverified advertising network routing URL (.php or traffic distribution system link).

- **Hop 3 (Exploit Kit Stager):** The router drops the session onto a malicious external landing domain, automatically downloading a background JavaScript file (.js).

- **Hop 4 (Payload Delivery):** The JavaScript script automatically executes an unprompted payload drop, fetching the masqueraded malicious Windows binary (.exe).

**Payload Introduction Point:** The malicious payload was introduced at Hop 3 & 4 on the final landing domain, while the initial redirection abuse occurred back at Hop 2 through the compromised ad network element.

### Q2: The antivirus did not fire on download. What detection gap does this highlight? What control would fill it?

**Detection Gap Highlighted:** This highlights a failure in signature-based detection. Standard antivirus tools rely on known blacklists and static cryptographic file hashes (MD5/SHA-256). If the attacker uses a freshly compiled binary, basic obfuscation, or a zero-day stager, traditional AV will let the download slide through completely unnoticed.

**Control to Fill the Gap:** An advanced Endpoint Detection and Response (EDR) agent or a Next-Generation Antivirus (NGAV) platform that leverages real-time behavioral heuristic analysis and machine learning would fill this gap. Instead of checking what the file looks like (its signature), it monitors what the file does upon execution (e.g., trying to write to system folders or spawning unapproved shells).

### Q3: Map to Kill Chain Delivery phase. How does a drive-by compromise differ from spear-phishing delivery?

**Cyber Kill Chain Phase:** Delivery

**Core Differences:**

- **Drive-by Compromise:** Requires passive user interaction. The attacker does not need to target the user directly; they poison a location the user naturally visits. The payload delivery is silently triggered simply by rendering the web page source code, without requiring the victim to download an attachment consciously.

- **Spear-Phishing Delivery:** Requires active, targeted user deception. The adversary explicitly crafts and sends a direct message (e.g., an email) tailored to the victim, relying on social engineering to trick them into manually opening an attached file or clicking an external link.

### Q4: Apply MITRE T1189 (Drive-by Compromise). What browser vulnerability type is most commonly exploited this way?

**Primary Vulnerability Type:** Memory Corruption Vulnerabilities (specifically Use-After-Free (UAF), Type Confusion, and Buffer Overflows).

**Exploitation Mechanics:** Adversaries craft malicious JavaScript structures designed to exploit these memory management flaws inside the browser's rendering engine (or active plugins like WebGL, Flash, or PDF readers). Once memory is corrupted, the script escapes the browser sandbox, allowing unauthorized remote code execution to write and run binaries directly on the host operating system.

### Q5: List three security controls (DNS filtering, browser isolation, content inspection) and explain how each would have helped.

**1. DNS Filtering**

By checking domain age and reputation scores in real time, a DNS filter would have completely dropped the connection at Hop 3 or Hop 4 by refusing to resolve the IP address of the newly generated or untrusted landing domain.

**2. Browser Isolation (Remote Browser Isolation - RBI)**

RBI executes all web-browsing code inside a disposable, containerized cloud sandbox rather than on the local endpoint. The malicious JavaScript and executable would have compromised the cloud container, leaving the actual employee workstation completely untouched.

**3. Network Content Inspection (Secure Web Gateway)**

An inline gateway sandbox would intercept the outbound .exe download packet at the perimeter, pausing the transfer for a few moments to dynamically detonate the binary in a secure environment and block it after observing malicious behaviors.

---

## Timeline

| Timestamp | Event | Evidence |
|---|---|---|
| 08/15/2017 (unknown time) | User visits compromised legitimate website | HTTP referrer log entry |
| T+[immediate] | Ad network redirect chain initiated | Hop 1→2→3→4 proxy logs |
| T+[seconds] | Malicious .js file downloaded | stream:http uri_path="*.js" |
| T+[seconds] | Malicious .exe executed via JavaScript | stream:http uri_path="*.exe" |
| Detection | Proxy audit discovers redirect chain | Manual log review |
| Response | Host isolated; domain blocklisted | EDR + Firewall action |

---

## Recommended Response Actions

### Containment

**Host Isolation:** Network-isolate workstation 10.0.2.109 via the central EDR console to prevent the dropped executable from launching or establishing outbound C2 beacons.

**Infrastructure Domain Block:** Extract the specific domain strings identified in the final redirect hops and add them immediately to the corporate perimeter firewall blocklist and secure proxy gateways.

### Eradication

**Staged File Purge:** Locate and permanently delete the downloaded .js file and any cached .exe binaries residing within the browser's temporary Internet download folders on the endpoint.

**Browser Cache Flush:** Clear out all temporary internet file hives, tracking cookies, and session state files associated with the local browser profile used during the time of infection.

### Recovery

**Static Malware Code Hash Extraction:** Extract the cryptographic hash (SHA-256) of the dropped executable to update central SIEM threat matrices and monitor for matching footprints across the rest of the enterprise subnet.

**Full Behavioral Forensic Sweep:** Run an aggressive, signatureless heuristic malware scan on the asset to ensure no active processes are attempting execution hooks out of memory before reconnecting the device.

---

## Detection Gap & Recommendations

### Detection Gap

The boundary secure web gateway allowed an unverified external ad script to push automated executable downloads to an internal endpoint without checking domain reputation or structural sandbox behaviors, while signature-based local AV failed to alert on the novel binary.

### Remediation

Enforce real-time DNS Filtering policies that block connectivity to newly registered or unrated domains. Integrate a Remote Browser Isolation (RBI) architecture or an inline Secure Web Gateway sandbox to inspect and block unprompted browser file downloads dynamically. Ensure EDR policies are optimized to alert instantly on browsers spawning or downloading executable binary attachments.

---

## Report Metadata

| Field | Value |
|---|---|
| **Analyst Name** | Adrian Gian Barredo |
| **Date & Time** | 08/15/2017 |
| **Ticket ID** | TKT-010 |
| **Severity** | Low |
| **Kill Chain Phase** | Delivery |
| **MITRE ATT&CK Techniques** | T1189, T1204.001 |
| **Affected Host(s)** | Internal Workstation (10.0.2.109) |
| **Attack Vector** | Malicious ad network redirect |
| **Report Status** | Complete |
