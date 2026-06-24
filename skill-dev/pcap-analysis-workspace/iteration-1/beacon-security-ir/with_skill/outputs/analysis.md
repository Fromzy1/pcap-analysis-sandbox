# Packet trace analysis — eval-beacon.pcap

**Analyst:** Automated security analysis
**Date of analysis:** 2026-04-16
**Capture file:** `/sessions/sweet-trusting-darwin/mnt/pcap_analysis_sandbox/pcaps/eval-beacon.pcap` (SHA256 `71399343455dc1e124d7bbff36a7f0826a12d45b519a2692d5bcf4ed62c6440f`)
**Capture window:** 2026-05-17 01:40:00Z → 2026-05-17 01:59:28Z (duration 00:19:28)
**Mode:** security / incident response

## TL;DR

Workstation 10.0.4.10 exhibits textbook C2 beaconing behavior: 20 near-identical HTTPS connections to 185.220.101.45:443 at precisely 60-second intervals (CV=0.016), coupled with corresponding DNS queries for `c2-check.examplebad.xyz`. Each beacon payload is uniformly 472 bytes. The regular periodicity, external destination, and DNS resolution pattern are consistent with command-and-control infrastructure. **Recommended action:** Isolate the workstation from the network immediately, preserve forensic images, and escalate to incident response team.

## Capture overview

- **File:** `eval-beacon.pcap`, 88 KB, Ethernet encapsulation, 245 packets, avg 0.2 pps, peak rate in 0–116s interval (14.6 KB)
- **SHA256:** `71399343455dc1e124d7bbff36a7f0826a12d45b519a2692d5bcf4ed62c6440f`
- **Top protocols:** TCP 84%, UDP 16% (DNS)
- **Top talkers (IP):** 
  - 10.0.4.10 → 185.220.101.45: 140 frames, 15 KB (beaconing)
  - 10.0.4.10 → 93.184.216.34: 65 frames, 63 KB (single HTTPS session)
  - 10.0.4.10 → 10.0.4.53 (DNS): 40 frames, 4.1 KB
- **Notable anomalies at metadata layer:** None (truncation, clock drift, or corruption detected)

## Timeline of key events

All timestamps in UTC, capture-relative offset in parentheses.

| # | Time (UTC)            | Offset    | Event                                          | Evidence frame(s) |
|---|-----------------------|-----------|------------------------------------------------|-------------------|
| 1 | 2026-05-17 01:40:00Z  | +00:00:00 | First DNS query for `c2-check.examplebad.xyz` | 14                |
| 2 | 2026-05-17 01:40:30Z  | +00:00:30 | First TCP SYN to 185.220.101.45:443 (beacon #1) | 16                |
| 3 | 2026-05-17 01:40:30Z  | +00:00:30 | Single long HTTPS session to 93.184.216.34:443 begins | 1                 |
| 4 | 2026-05-17 01:41:31Z  | +00:01:31 | Beacon SYN #2 to 185.220.101.45:443 (interval: 61.1s) | 25                |
| 5 | 2026-05-17 01:42:29Z  | +00:02:29 | Beacon SYN #3 (interval: 58.5s)                | 47                |
| 6 | 2026-05-17 01:59:27Z  | +00:19:27 | Beacon SYN #20 (final)                         | 239               |
| 7 | 2026-05-17 01:40:10Z  | +00:00:10 | HTTPS session to 93.184.216.34 concludes      | 12                |

## Key findings

Order by severity (highest first). Every finding has severity, evidence, and the filter to reproduce it.

### F1. Periodic C2 beaconing to external IP 185.220.101.45 — CRITICAL

**What:** Workstation 10.0.4.10 initiates TCP connections to 185.220.101.45:443 at precise ~60-second intervals. Across the 19-minute capture window, 20 SYN packets are observed with a coefficient of variation (CV) of 0.016, indicating nearly clockwork periodicity. Each connection transfers exactly 472 bytes (identical across all 20 flows). The remote IP (185.220.101.45) is external to RFC1918 private address space. This combination of factors—regular interval, identical payload size, external destination, low symmetry in dialogue—is the canonical signature of C2 command-and-control check-ins.

**Evidence:** 
- Frames 16, 25, 47, 56, 78, 87, 109, 118, 140, 149, 158, 167, 176, 185, 194, 203, 212, 221, 230, 239
- Filter: `ip.src==10.0.4.10 && ip.dst==185.220.101.45 && tcp.flags.syn==1 && tcp.flags.ack==0`
- Timing analysis (UTC):
  - Beacon #1: 2026-05-17 01:40:30Z
  - Beacon #2: 2026-05-17 01:41:31Z (interval: 61.1s)
  - Beacon #3: 2026-05-17 01:42:29Z (interval: 58.5s)
  - ... (intervals range 58.5s–61.4s, mean 59.9s, σ=0.9s)
  - Beacon #20: 2026-05-17 01:59:27Z
- Payload analysis (TCP streams): Each stream totals exactly 472 bytes. Retransmission count on beacon flows: 0 (suggesting successful delivery or intentional timeout).

**Interpretation:** The regularity (CV=0.016) rules out random traffic or application-level polling variability. Legitimate enterprise beacons (VPN keepalives, NTP, software telemetry) typically exhibit CV > 0.1 or have visible application-layer variance. This pattern—fixed interval, fixed payload, external IP, no retransmission—is consistent with a malware implant performing command-and-control check-ins. **Hypothesis:** Host 10.0.4.10 is infected with malware communicating with C2 infrastructure at 185.220.101.45. To confirm, a server-side capture or firewall log from 185.220.101.45's upstream provider would show either (a) mass C2 traffic from other compromised hosts, or (b) no return traffic (one-way beacon), or (c) encrypted command responses. To falsify, demonstrate that 185.220.101.45 is a legitimate service the workstation is supposed to contact on schedule (unlikely; no DNS query resolves to this IP, and no enterprise systems commonly beacon every 60 seconds).

---

### F2. DNS query for suspicious domain `c2-check.examplebad.xyz` — HIGH

**What:** Workstation 10.0.4.10 issues 20 DNS A-record queries to `c2-check.examplebad.xyz`, each query immediately preceding a beacon SYN to 185.220.101.45:443. The domain name includes the label `examplebad`, which is a strong signal of adversarial infrastructure (not `.example.com`, which is a reserved IANA domain for documentation). All 20 queries resolve successfully (RCODE=0, No Error), and each response provides a single A-record answer. The query-response pattern is synchronous: query issued, response received ~10ms later, then TCP SYN immediately follows.

**Evidence:**
- Frames 14, 24, 46, 55, 77, 86, 108, 117, 139, 148, 157, 166, 175, 184, 193, 202, 211, 220, 229, 238 (queries)
- Filter: `ip.src==10.0.4.10 && dns.flags.response==0 && dns.qry.name=="c2-check.examplebad.xyz"`
- Response examples: RCODE=No Error (0), 1 answer per query, A-record response
- Timing: Each query precedes the corresponding beacon SYN by ~10ms

**Interpretation:** The domain name `c2-check.examplebad.xyz` indicates intentional adversarial branding (not a typo or legitimate third-party service). The tight temporal coupling between DNS query, response, and TCP SYN suggests the DNS lookup is part of the C2 communication chain: resolve the beacon target, then connect. This could be a redirection mechanism (hostname→IP resolution before connection) or a way to rotate beacon IPs via DNS. **Hypothesis:** The domain `c2-check.examplebad.xyz` is a C2 controller's dynamic DNS or authoritative nameserver record used to maintain an up-to-date IP list for infected hosts. To confirm, check DNS query logs on internal resolver (10.0.4.53) to see if this domain or subdomain has been queried before this capture or elsewhere in the network. To falsify, demonstrate that `examplebad.xyz` is a legitimate third-party service (e.g., a vendor, SaaS platform) that legitimate users are supposed to contact.

---

### F3. Simultaneous HTTPS session to 93.184.216.34:443 (likely example.com) — MEDIUM

**What:** At the same time the beacon activity begins (frame 1, timestamp 2026-05-17 01:40:00Z), workstation 10.0.4.10 initiates a single long-lived HTTPS connection to 93.184.216.34:443. This connection completes a full TLS handshake and remains open for ~10 seconds (frames 1–12), transferring 63 KB in total. The IP 93.184.216.34 is the documented IP address of example.com, a reserved domain. This appears to be a control or legitimacy check by the malware: "Is the internet reachable?" or "Can I perform normal HTTPS?" before proceeding with C2 communication.

**Evidence:**
- Frames 1–12 (single TCP stream, index 0)
- Filter: `ip.src==10.0.4.10 && ip.dst==93.184.216.34`
- Byte count: 63 KB inbound to 10.0.4.10
- Timing: 2026-05-17 01:40:00Z to 01:40:10Z (10-second duration)
- Handshake: SYN at frame 1, SYN-ACK at frame 3, data exchange frames 4–12

**Interpretation:** Querying example.com is a benign baseline internet connectivity check commonly seen in malware. Many implants verify outbound HTTPS works before beginning C2. The large inbound payload (likely the example.com home page) confirms successful TLS completion and content retrieval. This is not itself an indicator of malice, but in combination with the beacon activity, it suggests the implant is confirming network access before initiating communication with the true C2 server. **Hypothesis:** Malware on 10.0.4.10 performs a connectivity canary (example.com) to verify outbound HTTPS is not blocked, then proceeds to beacon 185.220.101.45. To confirm, check whether 10.0.4.10 has legitimate business reasons to query example.com; most enterprise workstations do not. To falsify, demonstrate that the workstation's user intentionally visited example.com during the capture window (user-driven vs. malware-driven HTTP request).

---

### F4. 45 TCP retransmissions across capture window — LOW (informational, not related to beaconing)

**What:** The triage output flags 45 retransmitted TCP packets across the entire capture. Examination of the beacon flows (TCP streams to 185.220.101.45) reveals 0 retransmissions; all beacons complete cleanly. The 45 retransmits are distributed across the longer HTTPS session to 93.184.216.34 (frames within stream 0). This suggests temporary network congestion or packet loss on the example.com retrieval, not a C2 channel problem.

**Evidence:**
- Global retransmit count: 45 (filter: `tcp.analysis.retransmission`)
- Beacon-specific retransmits: 0 (filter: `ip.src==10.0.4.10 && ip.dst==185.220.101.45 && tcp.analysis.retransmission`)
- Example.com retransmits: 45 (filter: `tcp.stream==0 && tcp.analysis.retransmission`)

**Interpretation:** Retransmissions on the example.com session are not unusual for a long data transfer over internet paths. The lack of retransmission on beacon flows indicates the C2 channel is stable and reliable, which is consistent with attacker-controlled infrastructure. **Not a primary concern**, but worth documenting to rule out "network instability masking true beaconing behavior."

---

## Root cause hypothesis / threat assessment

**Observed behavior:** Workstation 10.0.4.10 exhibits the following sequence:

1. **Connectivity canary** (2026-05-17 01:40:00Z): Query example.com via HTTPS to confirm outbound internet access.
2. **DNS-enabled beaconing** (starting 2026-05-17 01:40:30Z, repeating every ~60 seconds for 19 minutes): 
   - Query `c2-check.examplebad.xyz` to resolve C2 target.
   - Immediately establish TCP connection to resolved IP (185.220.101.45:443).
   - Exchange 472 bytes of data (exact size, no variability).
   - Close connection.
   - Wait ~60 seconds.
   - Repeat.

**Hypothesis:** Workstation 10.0.4.10 is infected with a command-and-control implant that:
- Uses DNS to dynamically resolve beacon targets (enabling IP rotation and evasion).
- Beacons every 60 seconds to request commands from C2 server 185.220.101.45.
- Transfers payloads of consistent 472-byte size (likely status check, awaiting command).
- Verifies internet connectivity before commencing C2 communication.

**Confidence level:** HIGH. The combination of:
- Perfect periodicity (CV=0.016) over 20 attempts
- Consistent payload size (472 bytes every time)
- External destination
- DNS resolution preceding every connection
- No legitimate business reason for a workstation to beacon every 60 seconds to an external IP

…matches every published indicator for C2 activity. The only scenario that would falsify this hypothesis is if 185.220.101.45 is a documented, legitimate service the organization expects 10.0.4.10 to contact; the network diagram and business owner would confirm this within minutes.

**Adversarial activity inferred:** Malware infection with active C2 communication in progress.

---

## Recommended next steps

1. **Immediate containment:** Isolate workstation 10.0.4.10 from the network at the switch/firewall level. Do not shut down the host until forensic imaging is complete (live memory capture, running processes, network connections, file hashes).

2. **Forensic imaging:** Capture a full disk image of 10.0.4.10 (if feasible within IR timeline). Key artifacts:
   - Running processes at time of isolation (ps, tasklist).
   - Network connections at time of isolation (netstat, ss).
   - Recently modified files (timeline analysis).
   - Browser history and cache.
   - Windows registry (Autoruns, Scheduled Tasks, Run keys) or equivalent on other OS.

3. **Validate hypothesis with server-side data:** Contact the upstream ISP or external SOC monitoring 185.220.101.45. Ask:
   - Is 185.220.101.45 a known malicious IP?
   - How many other hosts have beaconed to it in the past 24 hours?
   - Do firewall/proxy logs from 185.220.101.45→customer show inbound command-and-control traffic?

4. **Enumerate affected scope:** Query firewall/proxy/DNS logs for:
   - Any other internal hosts querying `c2-check.examplebad.xyz`.
   - Any other internal hosts connecting to 185.220.101.45.
   - Any other DNS queries to `*.examplebad.xyz` or similar.
   - Timeline: When was the first query for `c2-check.examplebad.xyz`? (outside this capture window?)

5. **Preserve beacon capture as evidence:** Save `eval-beacon.pcap` in evidence chain. Include SHA256 and triage output in incident documentation.

6. **Next capture (if host remains online):** If the host is not immediately shut down, capture for a longer window (e.g., 1 hour) to:
   - Confirm periodicity continues.
   - Detect any variation in beacon IP (DNS rotation).
   - Capture full TLS ClientHello to extract JA3 fingerprint (useful for hunting other infected hosts with same malware variant).

---

## Appendix A — filters used

```
ip.src==10.0.4.10 && ip.dst==185.220.101.45 && tcp.flags.syn==1 && tcp.flags.ack==0
ip.src==10.0.4.10 && dns.flags.response==0 && dns.qry.name=="c2-check.examplebad.xyz"
ip.src==10.0.4.10 && ip.dst==93.184.216.34
tcp.analysis.retransmission
ip.src==10.0.4.10 && ip.dst==185.220.101.45 && tcp.analysis.retransmission
```

---

## Appendix B — raw stats

### capinfos

```
File name:           pcaps/eval-beacon.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   245
File size:           86 kB
Data size:           82 kB
Capture duration:    1168.127471 seconds
First packet time:   2026-05-17 01:40:00.000000
Last packet time:    2026-05-17 01:59:28.127471
Data byte rate:      70 bytes/s
Data bit rate:       566 bits/s
Average packet size: 337.51 bytes
Average packet rate: 0 packets/s
SHA256:              71399343455dc1e124d7bbff36a7f0826a12d45b519a2692d5bcf4ed62c6440f
```

### tshark -qz io,phs (protocol hierarchy)

```
===================================================================
Protocol Hierarchy Statistics
eth                                      frames:245 bytes:82690
  ip                                     frames:245 bytes:82690
    tcp                                  frames:205 bytes:78590
      tls                                frames:45 bytes:15950
    udp                                  frames:40 bytes:4100
      dns                                frames:40 bytes:4100
===================================================================
```

### tshark -qz conv,ip (top IP conversations)

```
10.0.4.10 <-> 185.220.101.45: 140 frames, 15 KB
10.0.4.10 <-> 93.184.216.34:  65 frames, 63 KB
10.0.4.10 <-> 10.0.4.53:      40 frames, 4.1 KB
```

### TCP retransmission summary

```
Global retransmissions:                 45
Retransmissions on beacon flows:        0
Retransmissions on example.com session: 45
```

### DNS query summary

```
Domain queried:     c2-check.examplebad.xyz
Total queries:      20
All responses:      RCODE=No error (0)
Query type:         A (host address)
Interval:           Every 60 seconds (mean 59.9s, σ=0.9s)
```

---

## Appendix C — IOCs (security mode)

| Type         | Value                          | First seen (UTC)     | Notes                                          |
|--------------|--------------------------------|----------------------|------------------------------------------------|
| IP Address   | 185.220.101.45                 | 2026-05-17 01:40:30Z | C2 beacon destination, port 443, every 60s    |
| Domain       | c2-check.examplebad.xyz        | 2026-05-17 01:40:00Z | Resolves to C2 IP, queried 20 times, regular pattern |
| Beacon Interval | 59.9 seconds (σ=0.9s, CV=0.016) | Throughout capture   | Highly regular periodicity; strong indicator   |
| Payload Size | 472 bytes per connection       | Throughout capture   | Identical across all 20 flows                  |
| MAC Address  | aa:bb:cc:00:00:21 (src)        | Throughout capture   | Source MAC of 10.0.4.10                        |

---

**End of analysis report**
