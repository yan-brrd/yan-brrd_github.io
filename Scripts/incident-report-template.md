# Incident Report Template

*Fill in one copy of this per incident. Keep language factual and specific — avoid hedging words like "maybe" or "possibly" unless the evidence is genuinely inconclusive.*

---

## 1. Case Summary

| Field | Detail |
|---|---|
| **Case ID** | INC-[0001] |
| **Date Detected** | [YYYY-MM-DD] |
| **Analyst** | [Your Name] |
| **Severity** | `Critical` / `High` / `Medium` / `Low` |
| **Status** | `Open` / `Investigating` / `Contained` / `Closed` |
| **Source of Detection** | e.g., Splunk dashboard alert, honeypot log, manual packet review |

**One-sentence summary:** [What happened, in one plain sentence — e.g., "Repeated failed SSH logins from a single external IP escalated to a successful authentication."]

---

## 2. Timeline of Events

| Time (UTC) | Event |
|---|---|
| [HH:MM] | [First indicator observed] |
| [HH:MM] | [Escalation point / what changed] |
| [HH:MM] | [Detection / analyst became aware] |
| [HH:MM] | [Response action taken] |

---

## 3. Indicators of Compromise (IOCs)

| Type | Value | Notes |
|---|---|---|
| IP Address | [x.x.x.x] | [source, destination, or both] |
| Username | [account name] | [targeted or compromised] |
| Hash / File | [hash or filename] | [if applicable] |
| Domain / URL | [domain] | [if applicable] |

---

## 4. Affected Systems / Scope

- **Systems involved:** [hostnames, IPs, or lab segment names]
- **Data or services at risk:** [be specific — or state "none identified" if true]
- **Scope confirmed via:** [e.g., Splunk search across all hosts, Wireshark capture review]

---

## 5. Analysis

[2–4 sentences explaining *why* this is significant. What does the evidence show? Tie it back to the specific log entries, packets, or honeypot output you reviewed — this is the section that proves you understand the "why," not just the "what."]

---

## 6. Actions Taken

- [ ] [Action 1 — e.g., blocked source IP at the lab firewall]
- [ ] [Action 2 — e.g., isolated affected host from the network segment]
- [ ] [Action 3 — e.g., escalated/ticketed for further review]

---

## 7. Recommendations

1. [Concrete, specific recommendation — not "improve security" but e.g., "disable password auth on SSH in favor of key-based auth"]
2. [Second recommendation]
3. [Third recommendation, if applicable]

---

## 8. Lessons Learned

[1–2 sentences: what would you do differently, or what did this case teach you about the tooling/process? This section is what turns a report into a portfolio artifact — it shows reflection, not just task completion.]

---
*Template based on standard SOC incident report structure (summary → timeline → IOCs → scope → analysis → response → recommendations). Customize freely.*
