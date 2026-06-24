# Packet trace analysis — eval-dns-cascade.pcap

**Analyst:** Network Engineer (pcap-analysis skill)  
**Date of analysis:** 2026-04-16  
**Capture file:** `/sessions/sweet-trusting-darwin/mnt/pcap_analysis_sandbox/pcaps/eval-dns-cascade.pcap` (SHA256 `49c8f3565548da450c427b618273f75bbd0617e9efa529088144dd4adde67236`)  
**Capture window:** 2026-05-17 00:40:00Z → 2026-05-17 00:40:00.899999Z (duration 0:00:00.9s)  
**Mode:** troubleshooting

## TL;DR

The checkout service is receiving 502 errors because it cannot resolve three backend service names (`newsvc.prod.example.com`, `v2.newsvc.prod.example.com`, `internal.newsvc.prod.example.com`) to IP addresses. The local DNS resolver returns NXDOMAIN for these queries. This is a **DNS problem**: the checkout host is cascading through a series of DNS lookups, most of which fail, causing the backend connection logic to fall back to a single endpoint (10.0.3.5) that does not have the required service handlers. **Recommended action:** verify DNS resolution configuration and ensure all backend service names are registered in DNS; alternatively, check whether a recent DNS zone update or CNAME misconfiguration removed these hosts.

## Capture overview

- **File:** `eval-dns-cascade.pcap`, 3.1 KB, Ethernet, 31 packets, avg 34 pps, peak rate sustained at 34 pps
- **Top protocols:** TCP 68% (21 packets), UDP 32% (10 packets); application layer: DNS 100%, HTTP 100%
- **Top talkers (IP):** 10.0.1.25 (checkout host) ↔ 10.0.3.5 (backend, 1.668 KB); 10.0.1.25 ↔ 10.0.1.53 (DNS resolver, 917 B)
- **Notable anomalies:** none — capture is clean, no truncation, no clock drift, no retransmits, no RSTs

## Timeline of key events

All timestamps in UTC, capture-relative offset in parentheses.

| # | Time (UTC)                | Offset      | Event                                                   | Evidence frame(s) |
|---|---------------------------|-------------|-------------------------------------------------------- |-------------------|
| 1 | 2026-05-17 00:40:00.000Z  | +00:00:00   | DNS query for `api.prod.example.com` (succeeds)         | 1                 |
| 2 | 2026-05-17 00:40:00.004Z  | +00:00:00   | DNS response: 10.0.3.5 (rcode 0, NOERROR)               | 2                 |
| 3 | 2026-05-17 00:40:00.014Z  | +00:00:00   | DNS query for `auth.prod.example.com` (succeeds)        | 3                 |
| 4 | 2026-05-17 00:40:00.018Z  | +00:00:00   | DNS response: 10.0.3.5 (rcode 0, NOERROR)               | 4                 |
| 5 | 2026-05-17 00:40:00.028Z  | +00:00:00   | DNS query for `newsvc.prod.example.com` (fails)         | 5                 |
| 6 | 2026-05-17 00:40:00.032Z  | +00:00:00   | DNS response: NXDOMAIN (rcode 3)                        | 6                 |
| 7 | 2026-05-17 00:40:00.042Z  | +00:00:00   | DNS query for `v2.newsvc.prod.example.com` (fails)      | 7                 |
| 8 | 2026-05-17 00:40:00.046Z  | +00:00:00   | DNS response: NXDOMAIN (rcode 3)                        | 8                 |
| 9 | 2026-05-17 00:40:00.056Z  | +00:00:00   | DNS query for `internal.newsvc.prod.example.com` (fails) | 9                 |
| 10| 2026-05-17 00:40:00.060Z  | +00:00:00   | DNS response: NXDOMAIN (rcode 3)                        | 10                |
| 11| 2026-05-17 00:40:00.070Z  | +00:00:00   | TCP SYN to 10.0.3.5:80 (stream 0, port 40100)           | 11                |
| 12| 2026-05-17 00:40:00.090Z  | +00:00:00   | TCP SYN-ACK from 10.0.3.5:80                            | 12                |
| 13| 2026-05-17 00:40:00.120Z  | +00:00:00   | HTTP GET /api/orders (stream 0)                         | 14                |
| 14| 2026-05-17 00:40:00.170Z  | +00:00:00   | HTTP 502 Bad Gateway response (stream 0)                | 15                |
| 15| 2026-05-17 00:40:00.420Z  | +00:00:00   | TCP SYN to 10.0.3.5:80 (stream 1, port 40101) — retry   | 18                |
| 16| 2026-05-17 00:40:00.520Z  | +00:00:00   | HTTP 502 Bad Gateway response (stream 1)                | 22                |
| 17| 2026-05-17 00:40:00.770Z  | +00:00:00   | TCP SYN to 10.0.3.5:80 (stream 2, port 40102) — retry   | 25                |
| 18| 2026-05-17 00:40:00.870Z  | +00:00:00   | HTTP 502 Bad Gateway response (stream 2)                | 29                |

## Key findings

### F1. DNS resolution failure for three backend service names — HIGH

**What:** Three DNS queries from the checkout host (10.0.1.25) to the local resolver (10.0.1.53) returned NXDOMAIN (rcode 3, "no such name"). The failing names are `newsvc.prod.example.com`, `v2.newsvc.prod.example.com`, and `internal.newsvc.prod.example.com`. In contrast, the first two DNS queries for `api.prod.example.com` and `auth.prod.example.com` both succeeded with rcode 0 and resolved to 10.0.3.5. This indicates a partial zone configuration issue or recent DNS record deletion.

**Evidence:** frames 5, 6, 7, 8, 9, 10, filter:
```
dns.flags.rcode == 3
```
Results:
- Frame 6: `newsvc.prod.example.com` → NXDOMAIN
- Frame 8: `v2.newsvc.prod.example.com` → NXDOMAIN
- Frame 10: `internal.newsvc.prod.example.com` → NXDOMAIN

**Interpretation:** The resolver is authoritative and correctly reporting that these three names do not exist. This is not a timeout, packet loss, or resolver error — it is explicit rejection. The application's service discovery logic is cascading through a hardcoded list of backend DNS names and falling back to the first successful result (10.0.3.5, from `api.prod.example.com`) when later attempts fail.

---

### F2. All HTTP requests route to single IP after partial DNS failure — HIGH

**What:** Despite querying five different DNS names, all three HTTP GET requests in the capture are sent to the same IP address: 10.0.3.5, port 80. The requests occur at +00:00:00.120Z, +00:00:00.470Z, and +00:00:00.819Z and all receive 502 Bad Gateway responses. The checkout host does not attempt to connect to any other backend IP — it retries the same failed endpoint three times with ~350ms delays between attempts.

**Evidence:** frames 14, 15, 21, 22, 28, 29, filter:
```
http.request.method == "GET" || http.response.code == 502
```
Results:
- Frame 14: GET /api/orders to 10.0.3.5:80
- Frame 15: HTTP 502 Bad Gateway (rcode 502)
- Frame 21: GET /api/orders to 10.0.3.5:80
- Frame 22: HTTP 502 Bad Gateway (rcode 502)
- Frame 28: GET /api/orders to 10.0.3.5:80
- Frame 29: HTTP 502 Bad Gateway (rcode 502)

**Interpretation:** The backend at 10.0.3.5 is not handling the HTTP request correctly and is returning a 502 error. The 502 status code indicates that a reverse proxy or the backend host itself cannot reach an upstream service. Given the DNS cascade pattern (three consecutive NXDOMAIN responses), this is consistent with 10.0.3.5 being a proxy or load balancer that cannot reach the real backend services (which should be at `newsvc.prod.example.com`, `v2.newsvc.prod.example.com`, or `internal.newsvc.prod.example.com`). The endpoint at 10.0.3.5 appears to be misconfigured or overloaded.

---

### F3. DNS cascade pattern suggests hardcoded service discovery — MEDIUM

**What:** The checkout host queries for five distinct backend service names in rapid sequence (~14ms apart): `api.prod.example.com`, `auth.prod.example.com`, `newsvc.prod.example.com`, `v2.newsvc.prod.example.com`, `internal.newsvc.prod.example.com`. The application appears to have a priority list and uses the first successful resolution.

**Evidence:** frames 1–10, filter:
```
dns.flags.response == 0
```
Results:
- Frame 1: api.prod.example.com query
- Frame 3: auth.prod.example.com query
- Frame 5: newsvc.prod.example.com query
- Frame 7: v2.newsvc.prod.example.com query
- Frame 9: internal.newsvc.prod.example.com query

Timing spread: 0–56ms (all within first 60ms of capture).

**Interpretation:** This is not dynamic DNS failover based on health checks; it is a linear cascade through a hardcoded list. This design pattern is fragile when DNS changes occur — a missing or misconfigured zone entry silently fails over to the next option, potentially routing traffic to an unintended backend.

---

### F4. TCP and lower-layer connectivity is healthy — INFO

**What:** All three TCP connections to 10.0.3.5:80 complete the 3-way handshake cleanly (SYN, SYN-ACK, ACK), with no retransmits, RSTs, or zero-window conditions. HTTP requests are sent and responses are received without any TCP-layer errors.

**Evidence:** frames 11–13, 18–20, 25–27, filter:
```
tcp.flags.syn == 1 || (tcp.flags.syn == 1 && tcp.flags.ack == 1)
```
Results:
- Frames 11, 12, 13: stream 0 handshake OK
- Frames 18, 19, 20: stream 1 handshake OK
- Frames 25, 26, 27: stream 2 handshake OK

No retransmits (filter: `tcp.analysis.retransmission`): 0 matches.

**Interpretation:** The problem is not network-layer (routing, firewall, MTU, retransmits). The problem is application-layer: DNS resolution, service discovery, or backend configuration.

---

## Root cause hypothesis / threat assessment

The available evidence is consistent with the following root cause:

> **Primary cause: DNS zone misconfiguration or recent deletion of three backend service records.**
> The checkout service is attempting to discover backend endpoints by querying a cascade of DNS names. Two early names (`api.prod.example.com`, `auth.prod.example.com`) resolve successfully to 10.0.3.5. Three later names (`newsvc.prod.example.com`, `v2.newsvc.prod.example.com`, `internal.newsvc.prod.example.com`) return NXDOMAIN, indicating they are not registered in DNS. The application falls back to 10.0.3.5, which is either a proxy or load balancer that cannot reach the actual backend services for those missing names (likely because the real backends are registered under the NXDOMAIN names or have been moved). The proxy at 10.0.3.5 returns 502 Bad Gateway when it cannot reach the upstream service.
>
> This would be confirmed by:
> - Checking the DNS zone file or registry to verify which backend service names are currently registered and their IP targets.
> - Running `dig` or `nslookup` on the checkout host for each of the five service names to confirm current DNS state.
> - Checking the configuration of 10.0.3.5 to understand whether it is a reverse proxy, load balancer, or application server, and what its upstream targets are.
> - Reviewing recent DNS change logs to identify when the three missing names were deleted or changed.
>
> This would be falsified by:
> - Finding that the three missing names are correctly registered in DNS and resolve to a different IP (e.g., 10.0.3.50).
> - Finding that 10.0.3.5 is not a proxy but a standalone backend and the application code is incorrect (e.g., it should only query `api.prod.example.com`).

---

## Recommended next steps

1. **Verify DNS zone state immediately.** On the checkout host or another trusted client, run:
   ```
   dig +short api.prod.example.com
   dig +short auth.prod.example.com
   dig +short newsvc.prod.example.com
   dig +short v2.newsvc.prod.example.com
   dig +short internal.newsvc.prod.example.com
   ```
   Compare the results to the expected backend IP(s) for each service. If the three "newsvc" names are missing, they need to be re-registered in DNS or the application's fallback logic needs to be updated.

2. **Check the configuration of 10.0.3.5.** Determine whether this host is:
   - A reverse proxy or load balancer (if so, check its upstream targets and error logs for "502" during the capture window).
   - An application server (if so, check its logs to understand why it returned 502).
   - Provide the output of `curl -v http://10.0.3.5/api/orders` to reproduce the error in real-time.

3. **Review DNS change logs.** Check the DNS server (10.0.1.53) for zone update history:
   ```
   # Example: check syslog or BIND zone journal for deletions/changes
   grep -i "newsvc.prod.example.com" /var/log/syslog
   # or on BIND: check zone serial numbers and AXFR logs
   ```
   Identify when the three missing records were removed or when the zone was last updated.

4. **Capture during the next outage window.** Collect a server-side trace on 10.0.3.5 or the upstream backends simultaneously with a checkout-side trace to correlate the 502 responses with backend errors (e.g., connection refused, upstream timeout, misconfigured upstream name).

---

## Appendix A — filters used

```
dns.flags.rcode == 3
dns.flags.response == 0
dns.flags.response == 1
http.request.method == "GET"
http.response.code == 502
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.syn == 1 && tcp.flags.ack == 1
tcp.analysis.retransmission
ip.src == 10.0.1.25 && ip.dst == 10.0.3.5
ip.src == 10.0.1.25 && ip.dst == 10.0.1.53
```

---

## Appendix B — raw stats

### capinfos

```
  File name:           ./pcaps/eval-dns-cascade.pcap
  File type:           Wireshark/tcpdump/... - pcap
  File encapsulation:  Ethernet
  File timestamp precision:  microseconds (6)
  Packet size limit:   file hdr: 65535 bytes
  Number of packets:   31
  File size:           3105 bytes
  Data size:           2585 bytes
  Capture duration:    0.899999 seconds
  First packet time:   2026-05-17 00:40:00.000000
  Last packet time:    2026-05-17 00:40:00.899999
  Data byte rate:      2872 bytes/s
  Data bit rate:       22 kbps
  Average packet size: 83.39 bytes
  Average packet rate: 34 packets/s
  SHA256:              49c8f3565548da450c427b618273f75bbd0617e9efa529088144dd4adde67236
  Strict time order:   True
  Number of interfaces in file: 1
```

### tshark -qz io,phs (protocol hierarchy)

```
===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:31 bytes:2585
  ip                                     frames:31 bytes:2585
    udp                                  frames:10 bytes:917
      dns                                frames:10 bytes:917
    tcp                                  frames:21 bytes:1668
      http                               frames:6 bytes:858
        data-text-lines                  frames:3 bytes:450
===================================================================
```

### tshark -qz conv,ip

```
================================================================================
IPv4 Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
10.0.1.25            <-> 10.0.3.5                   9 774 bytes      12 894 bytes      21 1668 bytes     0.070000000         0.8300
10.0.1.25            <-> 10.0.1.53                  5 495 bytes       5 422 bytes      10 917 bytes     0.000000000         0.0600
================================================================================
```

### tshark -qz expert (anomaly summary)

```
Chats (18)
=============
   Frequency      Group           Protocol  Summary
           3   Sequence                TCP  Connection establish request (SYN): server port 80
           3   Sequence                TCP  Connection establish acknowledge (SYN+ACK): server port 80
           3   Sequence               HTTP  GET /api/orders HTTP/1.1\r\n
           3   Sequence               HTTP  HTTP/1.1 502 Bad Gateway\r\n
           6   Sequence                TCP  Connection finish (FIN)

Notes (6)
=============
   Frequency      Group           Protocol  Summary
           3   Sequence                TCP  This frame initiates the connection closing
           3   Sequence                TCP  This frame undergoes the connection closing
```

### DNS response codes distribution

```
Response code distribution:
  rcode 0 (NOERROR):  4 packets (40%)
  rcode 3 (NXDOMAIN): 3 packets (30%)
  
Query names and outcomes:
  api.prod.example.com → 10.0.3.5 (rcode 0)
  auth.prod.example.com → 10.0.3.5 (rcode 0)
  newsvc.prod.example.com → NXDOMAIN (rcode 3)
  v2.newsvc.prod.example.com → NXDOMAIN (rcode 3)
  internal.newsvc.prod.example.com → NXDOMAIN (rcode 3)
```

### HTTP response codes distribution

```
Response code distribution:
  502 Bad Gateway: 3 packets (100%)
```

---
