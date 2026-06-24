# Report template

Use this exact structure for the written deliverable. Fill every section. Skipped sections are a yellow flag — say why if a section doesn't apply.

---

```markdown
# Packet trace analysis — <capture name>

**Analyst:** <name or "automated">
**Date of analysis:** <YYYY-MM-DD>
**Capture file:** <path or URL> (SHA256 `<hash>`)
**Capture window:** <YYYY-MM-DD HH:MM:SSZ> → <YYYY-MM-DD HH:MM:SSZ> (duration <hh:mm:ss>)
**Mode:** troubleshooting | security | both

## TL;DR

One to three sentences. What is the thing the reader needs to know if they only read this? End with the recommended action.

## Capture overview

- **File:** <name>, <size>, <encap>, <n> packets, avg <rate> pps, peak <peak> pps
- **Top protocols:** <e.g. TCP 61%, UDP 22%, TLS 14%>
- **Top talkers (IP):** <src → dst, bytes>
- **Notable anomalies at the metadata layer:** <truncated / clock drift / unexpected encap / none>

## Timeline of key events

All timestamps in UTC, capture-relative offset in parentheses.

| # | Time (UTC)            | Offset    | Event                                          | Evidence frame(s) |
|---|-----------------------|-----------|------------------------------------------------|-------------------|
| 1 | 2025-03-14 08:12:40Z  | +00:00:00 | First DNS query for `example.com`              | 4                 |
| 2 | 2025-03-14 08:12:41Z  | +00:00:01 | TCP SYN → 10.0.0.2:443                         | 7                 |
| 3 | 2025-03-14 08:12:45Z  | +00:00:05 | First retransmit of `[PSH, ACK]` seq=1         | 19                |
| … |                       |           |                                                |                   |

## Key findings

Order by severity (highest first). Every finding has severity, evidence, and the filter to reproduce it.

### F1. <short title> — <SEVERITY>

**What:** one paragraph, plain language.
**Evidence:** frames <list>, filter:
```
tcp.stream == 7 && tcp.analysis.retransmission
```
**Interpretation:** what this implies. Label as a hypothesis if inference is involved.

### F2. …

(Continue for each finding.)

## Root cause hypothesis / threat assessment

Synthesize the findings into a coherent explanation. Prefer:

> "The available evidence is consistent with **<hypothesis>**. This would be confirmed by **<specific next observation>** and falsified by **<alternative>**."

For security mode, describe observed behaviour in defensive terms. Avoid attribution. Separate fact from inference clearly.

## Recommended next steps

Concrete, checkable items:

1. <Specific action, e.g. "Capture on the server NIC during the next failure window to compare against this trace">
2. <Config to verify, e.g. "Check firewall rule 12 — it appears to be dropping SYN/ACK from 10.0.0.2 during 08:12:45–08:13:10Z">
3. <Collection to extend, e.g. "Add DNS query logging on resolver 10.0.0.53 for 24h">

## Appendix A — filters used

```
<filter 1>
<filter 2>
...
```

## Appendix B — raw stats

```
$ capinfos <pcap>
…

$ tshark -r <pcap> -qz io,phs
…

$ tshark -r <pcap> -qz conv,tcp
…

$ tshark -r <pcap> -qz expert
…
```

## Appendix C — IOCs (security mode only)

| Type   | Value | First seen (UTC) | Notes |
|--------|-------|------------------|-------|
|        |       |                  |       |
```

---

## Style notes

- **Plain language in findings; precise filters in evidence.** A finding should be understandable by a senior engineer who doesn't know tshark syntax. The filter is there so someone who does can reproduce the work.
- **Severity levels:**
  - `CRITICAL` — active compromise, exfil in progress, service outage
  - `HIGH` — confirmed broken functionality or strong indicator of compromise
  - `MEDIUM` — significant performance degradation or suspicious behaviour needing verification
  - `LOW` — minor inefficiency, benign curiosity worth noting
  - `INFO` — observed behaviour, not a problem
- **Numbers, not adjectives.** "41% of segments in `tcp.stream == 7` are retransmits" beats "the connection has lots of retransmits."
- **Keep findings short.** If a finding needs more than 200 words, it's probably two findings.
