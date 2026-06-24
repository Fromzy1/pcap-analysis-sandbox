---
name: pcap-analysis
description: Analyze a packet capture (.pcap / .pcapng) the way a senior network or security engineer would — work from the raw trace to a structured written report with timeline, evidence, and recommendations. Triggers when the user shares a pcap/pcapng file, points to one by path, mentions packet captures, Wireshark/tshark traces, tcpdump output, or asks questions like "why is this app slow", "is this traffic malicious", "what's happening in this capture", "any retransmits / beaconing / exfil here", "troubleshoot this trace", or describes network symptoms (latency, TLS errors, DNS failures, suspicious connections, C2, data exfil, lateral movement) with a capture file in reach. Use this skill proactively whenever a pcap is part of the input — don't wait for the user to ask for a formal report.
---

# pcap-analysis

A disciplined workflow for turning a raw packet capture into a written analysis that a peer engineer could act on. Handles both performance troubleshooting and security / IR investigations in one flow — mode is inferred from the user's question.

## Why this workflow exists

Packet captures are cheap to collect and expensive to misread. The failure mode is predictable: open the pcap, eyeball a few packets, form a theory too early, and build the rest of the analysis around that theory. This skill forces a small amount of structure up front — **triage first, hypothesize second, write the evidence down** — so that the answer has receipts and another engineer can reproduce it.

The skill works best with a rich set of packet tools, but it degrades gracefully. Before investigating, establish what's available — see **Prep the environment** below.

## Operating principles

1. **Read the capture before reading any packet.** `capinfos` tells you whether the trace is even the right trace (timestamps, duration, encap, packet count, SHA). Half of "the pcap doesn't show the problem" reports end here.
2. **Use filters, not paging.** Never try to read a pcap linearly. Every claim in the report is backed by a specific `tshark -Y …` filter so the reader can re-run it.
3. **Name the mode.** Decide within the first couple of steps whether the question is *performance* (troubleshooting) or *evidence* (security / IR) — the drill-downs differ. If both apply, do performance first (faster to confirm or dismiss) then security.
4. **Cite packets the way you'd cite sources.** Findings reference frame numbers, timestamps, 5-tuple, and a filter. A sentence without a filter behind it is a guess.
5. **Short report, rich appendix.** The executive summary is for a human skimming on a phone; the appendix has the commands, filters, and raw stats so the work is reproducible.

## Workflow

### 0. Prep the environment

**Run `scripts/check_env.sh` first.** It probes for tools and prints a clear
status line. The output tells you which of four tiers you're in — adjust the
workflow accordingly.

```sh
bash scripts/check_env.sh
```

**Tier 1 — full sandbox present (best).**
A directory containing `activate.sh` alongside `.venv/` and `debs/` is reachable
(the script looks in the current dir, the user's selected folder, the parent of
this skill, and common names like `pcap_analysis_sandbox`). Source it:

```sh
source <found-path>/activate.sh
```

You get `tshark`, `editcap`, `mergecap`, `capinfos`, `reordercap`, `tcpflow`,
`tcptrace`, `tcpreplay`, `ngrep`, plus Python libs (scapy, pyshark, dpkt,
pandas, duckdb). `scripts/triage.sh` works fully. Use every recipe in the
playbooks.

**Tier 2 — system `tshark` only.**
`command -v tshark` succeeds but the Python libs aren't installed. Most of the
shell-only recipes in `references/tshark-recipes.md` still work. Skip the
Python/duckdb sections of the playbooks (beaconing periodicity analysis, flow
parquet export); fall back to equivalent `tshark -qz io,stat` tricks or
offer to install the Python libs with `pip install pyshark scapy dpkt pandas duckdb`.

**Tier 3 — Python libs only, no `tshark`.**
You can still dissect the pcap with `pyshark`, `scapy`, or `dpkt` from Python,
but `pyshark` itself needs `tshark` on PATH — so Tier 3 effectively means
`scapy`/`dpkt` only. That's enough for most troubleshooting (TCP flags, DNS
records, HTTP extraction) but you lose Wireshark's expert info, decryption,
and object export. Note the limitation in the report's appendix.

**Tier 4 — nothing.**
Stop and tell the user. Give them the one-liner to get to Tier 1 or Tier 2:

```
Option A (recommended): set up the pcap_analysis_sandbox —
   see https://github.com/… or ask me to bootstrap one in a folder you pick.
Option B (fastest): sudo apt install tshark  (gets Tier 2)
Option C (no sudo, Python-only Tier 3):
   uv venv && source .venv/bin/activate && uv pip install scapy pyshark dpkt pandas duckdb
```

Don't try to analyze the pcap from memory or guess at contents. The whole point
of the skill is that every claim is reproducible.

### 1. Triage (always, ~30 seconds)

Run `scripts/triage.sh <pcap>` from this skill. It bundles the first ten commands you would run anyway and prints a Markdown block you can paste into the report's "Capture overview" section.

What triage surfaces:

- file metadata (size, SHA256, encap, time range, packet count, avg/peak rate)
- protocol hierarchy (`tshark -qz io,phs`) — which protocols are even in the trace
- top IPv4/IPv6/TCP/UDP conversations (`conv,ip` / `conv,tcp` / `conv,udp`)
- expert info summary (`tshark -qz expert`) — retransmits, zero windows, malformed packets
- TCP health per conversation (`conv,tcp` with bytes and RTT)
- DNS and HTTP tree overviews (`dns,tree`, `http,tree`) when present
- a 10-row `io,stat` throughput timeline at capture-appropriate bucketing

Read the triage output before deciding where to drill. If the pcap is truncated, the clock looks wrong (e.g., all packets within 10ms), encapsulation is unexpected, or there are no packets for the application the user asked about, say so *before* investigating symptoms — you may be looking at the wrong capture.

### 2. Classify the question

Pick one (or both in sequence):

- **Troubleshooting** — "slow", "timing out", "resets", "can't connect", "poor quality", "losing packets", "why does X hang". Go to `references/troubleshooting.md`.
- **Security / IR** — "malicious", "beaconing", "exfil", "C2", "phishing", "is this a breach", "what did the attacker do", "suspicious", "IOCs". Go to `references/security.md`.

The references are compact playbooks. Don't dump their whole contents into the report — use them as your checklist.

### 3. Drill down with targeted filters

For each hypothesis, run a specific `tshark -Y` filter (or Python query) that either confirms or falsifies it. Keep the filters in a scratch list — they go into the appendix. Useful patterns are in `references/tshark-recipes.md`.

When a question needs correlated or statistical analysis (flows per minute, byte distributions, periodicity for beaconing), prefer:

1. `tshark -T fields -E separator=, …` → CSV → load with pandas or duckdb
2. `scripts/flows_to_parquet.py <pcap> <out.parquet>` for bigger captures (calls tshark under the hood and writes a typed Parquet file you can `duckdb` over)

### 4. Reconstruct objects when the trace calls for it

- Files in HTTP: `tshark -r pcap --export-objects http,./out` (or `tcpflow -r pcap -o ./flows`). Record SHA256s in the report.
- Certificates: `tshark -r pcap -Y tls.handshake.type==11 -V | less` or pyshark for programmatic pulls.
- Credentials / plaintext artifacts: `ngrep -I pcap -qt` with targeted patterns (limit to suspected flows; never bulk-grep payloads without a hypothesis — it's noisy and slow).

### 5. Write the report

Use `references/report-template.md` as the exact Markdown structure. Save it alongside the pcap (e.g., `pcaps/<pcap-name>.analysis.md`). The reader should be able to re-run every filter you cite.

**Non-negotiables for the report:**

- Every finding has a severity tag (`INFO` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) and a specific evidence block with filter + frame references.
- Timeline entries are UTC-first with the capture-relative offset in parentheses (`2025-03-14 08:12:44Z (+00:03:21)`). Mixing timezones across a report is how small incidents become big ones.
- "Root cause" is labelled a **hypothesis** unless you have end-to-end evidence. Write what would confirm or falsify it.
- "Recommended next steps" are concrete: a command to run, a config to check, a collection to extend. No "monitor for further activity."

### 6. Hand off cleanly

Link the report file in your response and include a one-line headline ("TL;DR: TCP retransmits from `10.4.1.2:443` are driving 41% of application latency; mitigation: …"). Don't paste the whole report back into chat — the file is the deliverable.

## When this skill should step back

- **You don't have the pcap.** Ask for the file path before writing anything speculative.
- **The capture is obviously encrypted and the question needs app-layer content.** Say so, propose SSLKEYLOGFILE or a server-side capture, stop.
- **The capture is truncated / corrupt** (capinfos flags it). Propose recapturing rather than analyzing partial evidence.
- **The question is really about a live system**, not a historical capture. Redirect to live tools (a live packet broker / capture-on-host, tcpdump on the host, switch mirror). Don't fake it from a stale trace.

## Bundled resources

- `scripts/triage.sh` — one-shot triage command; run on every pcap.
- `scripts/flows_to_parquet.py` — tshark → typed Parquet via pandas; for bigger captures.
- `references/troubleshooting.md` — playbook for performance / RCA questions.
- `references/security.md` — playbook for IR / evidence questions.
- `references/tshark-recipes.md` — filter and stats recipes, cross-referenced from the playbooks.
- `references/report-template.md` — exact Markdown structure for the deliverable.
