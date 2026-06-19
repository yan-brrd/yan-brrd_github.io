<!-- Replace bracketed placeholders with your real details before publishing. -->

# CASE-002 · Incident Triage, Ticketing & Reporting

`Status: Documented` · `Category: Incident Response` · `Tools: [Ticketing platform], Incident Report Writing`

## Overview

This case covers the part of SOC work that happens *after* detection: deciding what matters, tracking it through to resolution, and writing it up clearly enough that another analyst could pick up the work or review the decision-making.

## Workflow

```
Alert / Finding  →  Ticket Logged  →  Triage  →  Investigation  →  Report  →  Close
```

1. **Log it** — every alert or finding worth tracking was entered into [ticketing platform] as a ticket, rather than left as a one-off search result.
2. **Triage it** — each ticket was scored for priority before deep investigation, using the criteria below.
3. **Investigate** — pulled supporting evidence (Splunk searches, packet captures, honeypot logs) to confirm or rule out the ticket.
4. **Report it** — higher-priority tickets were written up using the [incident report template](./incident-report-template.md).
5. **Close it** — ticket updated with final status and a link to the report.

## Triage / Priority Criteria

| Priority | Criteria | Example |
|---|---|---|
| **P1 – Critical** | Active compromise, confirmed data exposure | [TKT-007](./sample-tickets.md#tkt-007--large-data-transfer-to-external-ip-via-http-post) — Large data transfer to external IP (confirmed exfiltration via HTTP POST) |
| **P2 – High** | Strong indicator of compromise, no confirmed impact yet | [TKT-008](./sample-tickets.md#tkt-008--scheduled-task-created-by-non-admin-user-for-persistence) — Scheduled task created by non-admin user (persistence technique detected) |
| **P3 – Medium** | Suspicious but plausible benign explanation | [TKT-001](./sample-tickets.md#tkt-001--abnormal-port-scan-activity-against-web-server) — Abnormal port scan activity (reconnaissance, but no confirmed compromise) |
| **P4 – Low** | Informational / noise, logged for trend tracking | [TKT-010](./sample-tickets.md#tkt-010--drive-by-download-via-malicious-ad-network-redirect) — Drive-by download via malicious ad (user action required; low impact potential) |

## Sample Tickets

See [`sample-tickets.md`](./sample-tickets.md) for example tickets logged during this lab, showing the fields used and how priority was assigned.

## Incident Reports

The following incident reports were written from higher-priority tickets:

- [`TKT-001-port-scan.md`](./incident-reports/TKT-001-port-scan.md) — reconnaissance activity analysis
- [`TKT-007-data-exfiltration.md`](./incident-reports/TKT-007-data-exfiltration.md) — confirmed data exfiltration incident (P1)
- [`TKT-008-scheduled-task.md`](./incident-reports/TKT-008-scheduled-task.md) — suspicious scheduled task investigation
- [`TKT-010-drive-by-download.md`](./incident-reports/TKT-010-drive-by-download.md) — malware delivery and containment

## Skills Demonstrated

- Alert triage and prioritization under a defined framework
- Ticketing/case management workflow
- Incident report writing (summary, timeline, IOCs, recommendations)
- Clear, audience-aware technical communication

## Reflection

[1–3 sentences: what made triage harder than expected, or what you learned about writing reports for someone who wasn't there when the incident happened.]

