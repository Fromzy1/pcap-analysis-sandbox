# Security / IR playbook

Use when the user asks "is this malicious", "what happened", "find IOCs", "any beaconing / exfil / C2", or when the capture is given as evidence in an incident. The goal is a defensible description of what the trace shows — not speculation about attacker intent.

The report is evidence. Mark anything uncertain as a **hypothesis**. Avoid attribution. Prefer describing observable behavior and linking to what a defender should check next.

## Table of contents

1. Set the investigation scope
2. Beaconing / C2 detection
3. Data exfil patterns
4. DNS-based indicators (tunneling, DGA, abuse)
5. TLS / certificate anomalies
6. Lateral movement and internal recon
7. Malware delivery and file extraction
8. IOC extraction and presentation

---

## 1. Set the investigation scope

Start with four questions. Answering them shapes the rest of the investigation:

- **What time range does the trace cover, in UTC?** (capinfos) — the report's timeline anchors here.
- **Which endpoints are involved?** (conv,ip — top 10 talkers usually explain 95% of the traffic)
- **What protocols are present?** (io,phs)
- **What's the known-good baseline for this environment?** If you don't have one, flag that the analysis is context-free and recommend comparison to a clean capture.

Never start by looking for a specific IOC the user named — you'll miss everything else. Characterize the trace first.

## 2. Beaconing / C2 detection

Beaconing = periodic, low-volume outbound connections from an internal host to an external destination. Signals:

- **Periodicity.** Bin outbound flows per (src, dst, dport) into time buckets; look for regular intervals.
- **Low, consistent payload sizes.** C2 check-ins tend to be small and uniform.
- **Destinations outside the usual set.** Rare or never-before-seen external destinations.
- **Unusual hours.** Activity outside business hours from user workstations.

Workflow with duckdb (from the venv):

```python
import duckdb, pandas as pd
# Use scripts/flows_to_parquet.py to produce flows.parquet first
con = duckdb.connect()
con.execute("CREATE TABLE flows AS SELECT * FROM read_parquet('flows.parquet')")

# Candidates: many short flows to one external dest from one internal src
con.execute("""
SELECT ip_src, ip_dst, dport, COUNT(*) AS n_flows,
       AVG(bytes) AS avg_bytes, STDDEV(bytes) AS std_bytes,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM flows
WHERE ip_src LIKE '10.%' OR ip_src LIKE '192.168.%'
GROUP BY 1,2,3
HAVING n_flows >= 20 AND avg_bytes < 5000
ORDER BY n_flows DESC
LIMIT 20
""").fetchdf()
```

For periodicity, compute inter-arrival times per (src, dst) and look at the coefficient of variation. CV < 0.3 and a median interval in `[30s, 24h]` is a strong beacon signature.

**Important:** legitimate software beacons too — Windows Update, software telemetry, corporate VPN keepalives, NTP, monitoring agents. Don't call a pattern "beaconing" without naming what it isn't. "Beaconing to `1.1.1.1:443` every 60s" is likely a VPN health check; "beaconing to `pastebin.com`-resolved IP every 97s ±2s with 312-byte payloads" is much more interesting.

## 3. Data exfil patterns

Look for:

- **Large upload-dominant flows** from internal to external (`bytes_out >> bytes_in`).
- **Steady long-duration uploads** (minutes, not seconds) over HTTPS to cloud storage or file-sharing domains.
- **DNS / ICMP tunneling** — see section 4.
- **Unusual protocols outbound** — SSH or FTP going to external hosts.

```sh
tshark -r pcap -qz conv,ip | head -30    # byte totals per IP-pair
tshark -r pcap -qz conv,tcp | head -30
```

Sort by bytes from internal→external. If one internal host has several GB out to a single external destination in a short window, flag HIGH severity and describe the destination (SNI, rDNS, cert CN, ASN if available).

## 4. DNS indicators

DNS is the Swiss-army tool for attackers. Check:

- **Long query names and high-entropy labels.** Possible DNS tunneling.
  ```sh
  tshark -r pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name \
    | awk '{ if (length($0)>60) print }' | head
  ```
- **Unusual record types.** `TXT`, `NULL`, `CNAME` chains — all used for tunneling.
- **DGA (domain generation algorithm).** Many queries to random-looking second-level domains under the same TLD; most returning NXDOMAIN.
- **Fast-flux.** Same name resolving to a rapidly-changing set of A records.
- **Non-RFC1918 DNS servers.** Internal hosts talking to external resolvers directly (`dns` over `ip.dst != <corporate resolver>`).

For entropy analysis, extract names and score each label with Shannon entropy — scripts/flows_to_parquet.py captures enough to do this from Python.

## 5. TLS / certificate anomalies

```sh
# SNI inventory
tshark -r pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name | sort -u
```

What to look for:

- **Self-signed or untrusted CA** on outbound TLS to non-infrastructure destinations.
- **Expired or not-yet-valid certs** (compare notBefore/notAfter to capture start time).
- **SNI that doesn't match cert CN / SAN.** Plausible for SNI spoofing / domain-fronting.
- **Unusual JA3 client hashes** — requires a JA3 generation script; `pyshark` can give the raw ClientHello fields.
- **Very short TLS sessions with small data** — see beaconing section.

Record cert fingerprints (`tshark -Y "tls.handshake.type==11" -V | grep SHA`) as IOCs when relevant.

## 6. Lateral movement and internal recon

Signals specific to east-west traffic:

- **SMB from workstation→workstation.** Unusual outside admin tooling.
- **PSExec / service install** over SMB (`smb2.cmd == 10` CREATE to `\PIPE\svcctl`).
- **RDP, WMI, WinRM** from hosts that don't normally use them.
- **Port scans.** Many SYNs from one internal source to many internal dests on varied ports; few SYN/ACKs.

```sh
# Scan-like behavior: one src, many dsts, mostly failed handshakes
tshark -r pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst \
  | sort | uniq -c | sort -rn | head -20
```

## 7. Malware delivery and file extraction

Extract transferable objects and hash them:

```sh
mkdir -p /tmp/http-objs
tshark -r pcap --export-objects http,/tmp/http-objs
(cd /tmp/http-objs && sha256sum * | tee sha256sums.txt)
```

For encrypted delivery (HTTPS), objects can't be extracted without keys — note in the report. For SMB, `--export-objects smb` works analogously.

Include hashes in the IOC table. Don't run suspected malware — just hash and report.

## 8. IOC extraction and presentation

End every security-mode report with an IOC table in the appendix. Structure:

| Type         | Value                                  | First seen (UTC)     | Notes                              |
|--------------|----------------------------------------|----------------------|------------------------------------|
| IP           | 185.x.x.x                              | 2025-03-14 08:12:44Z | Beacon dest, port 443              |
| Domain       | abc-def-ghi.badnet.example             | 2025-03-14 08:12:40Z | Resolved to IP above               |
| SHA256       | 5f3…2a                                 | 2025-03-14 08:15:02Z | HTTP GET /update.bin → 1.2 MB PE   |
| JA3          | a0e9f5d64349fb13191bc781f81f42e1       | throughout           | Client fingerprint on beacon flows |
| User-Agent   | Mozilla/5.0 (X11…) StrangeLib/1.0      | throughout           | Non-browser UA                     |

Match the format to whatever the downstream consumer uses (STIX, MISP, an internal ticketing system). If uncertain, plain CSV is safest.

**One last thing.** Separate "facts from the pcap" from "inference." A good security report can be read like: "We observed *X* (evidence). This is consistent with *Y* (hypothesis). To confirm, check *Z* (next step)." If you can't write it that way, you're speculating.
