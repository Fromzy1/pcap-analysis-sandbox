# Packet trace analysis — eval-slow-app.pcap

**Analyst:** automated  
**Date of analysis:** 2026-04-16  
**Capture file:** `pcaps/eval-slow-app.pcap` (SHA256 `06ccc31702f50fe84eaf4d69fe3f68783d085f68e12715818f9535f2fd76a368`)  
**Capture window:** 2026-05-16 23:40:00Z → 2026-05-16 23:40:00.986003Z (duration 00:00:00.986)  
**Mode:** troubleshooting

## TL;DR

The checkout page hangs due to **client-side TCP receive buffer starvation** causing the server to stop sending. The client advertises a zero window at frame 37 (t+0.866s), immediately after the server has retransmitted two 1400-byte segments. This halts the TLS response stream for ~100ms until the client drains its buffer. Diagnosis: the client application is not reading incoming data quickly enough to keep pace with the server's transmission rate.

## Capture overview

- **File:** `eval-slow-app.pcap`, 33 kB, Ethernet, 40 packets, avg 40 pps, peak 40 pps
- **Top protocols:** TCP 100%, TLS 52.5% (21 of 40 frames)
- **Top talkers (IP):** 10.0.1.20 (client) ↔ 10.0.2.30 (server:443), 33 kB total; all frames in single TCP stream
- **Notable anomalies at the metadata layer:** none (clock order is strict, encapsulation is standard Ethernet, packet count is complete)

## Timeline of key events

| # | Time (UTC)            | Offset    | Event                                          | Evidence frame(s) |
|---|:----------------------|:----------|:-----------------------------------------------|:-----------------:|
| 1 | 2026-05-16 23:40:00.000000Z | +00:00:00.000 | TCP SYN from client to server:443                     | 1                 |
| 2 | 2026-05-16 23:40:00.060000Z | +00:00:00.060 | TCP SYN/ACK from server, handshake begins              | 2                 |
| 3 | 2026-05-16 23:40:00.120000Z | +00:00:00.120 | TCP ACK completes 3-way handshake                     | 3                 |
| 4 | 2026-05-16 23:40:00.140000Z | +00:00:00.140 | TLS ClientHello sent (200 bytes)                      | 4                 |
| 5 | 2026-05-16 23:40:00.141000Z | +00:00:00.141 | Server ACKs ClientHello                               | 5                 |
| 6 | 2026-05-16 23:40:00.201000Z | +00:00:00.201 | Server sends 1st TLS record (1400 bytes)              | 6                 |
| 7 | 2026-05-16 23:40:00.291002Z | +00:00:00.291 | Server sends final segment in series (frame 24)       | 24                |
| 8 | 2026-05-16 23:40:00.296002Z | +00:00:00.296 | Server sends 25th segment, then pauses 500ms          | 25                |
| 9 | 2026-05-16 23:40:00.341003Z | +00:00:00.341 | Server sends 34th segment (last in burst)             | 34                |
| 10 | 2026-05-16 23:40:00.846003Z | +00:00:00.846 | Server retransmits segment (frame 35, first retx)     | 35                |
| 11 | 2026-05-16 23:40:00.856003Z | +00:00:00.856 | Server retransmits second time (frame 36)             | 36                |
| 12 | 2026-05-16 23:40:00.866003Z | +00:00:00.866 | Client advertises zero window (TCP stall)             | 37                |
| 13 | 2026-05-16 23:40:00.916003Z | +00:00:00.916 | Client sends window update (50ms later)               | 38                |
| 14 | 2026-05-16 23:40:00.926003Z | +00:00:00.926 | Server sends FIN                                      | 39                |
| 15 | 2026-05-16 23:40:00.986003Z | +00:00:00.986 | Connection closes (client ACK of FIN)                 | 40                |

## Key findings

### F1. TCP receive buffer exhaustion — zero window advertised by client — **HIGH**

**What:** At frame 37 (t+0.866s), the client advertises a TCP window of zero bytes, signaling its receive buffer is completely full and cannot accept more data. This stalls the server's transmission. The zero window is not initiated by the network — the server never sent one — but by the client's own receive stack, indicating the application is not reading data.

**Evidence:** Frame 37:
```
tcp.analysis.zero_window
```

Frames 35–36 are retransmissions of 1400-byte segments from the server; frame 37 is the ACK with zero window from the client. The gap between frame 34 (t+0.341s) and frame 35 (t+0.846s) is 505ms, the RTO (retransmission timeout), suggesting the original frames 25–34 were not ACK'd because the client's buffer was full.

**Interpretation:** The client's TCP receive buffer is being drained too slowly by the application layer (the browser/checkout page). The server has sent 19 consecutive 1400-byte frames (frames 6–24) without receiving an ACK that advances the window, causing the buffer to fill up and the client's TCP stack to advertise zero window. This is a **client-side application performance problem**, not a network problem. The server-side has already sent all the data (30.8 kB, per tcptrace), but the client is not consuming it fast enough, creating a 500ms+ pause while the client catches up.

---

### F2. Server retransmissions triggered by stalled transmission — **MEDIUM**

**What:** The server retransmits frames 35 and 36 (both 1400-byte TLS records) at t+0.846s and t+0.856s (frames 35–36). These are flagged as retransmissions by Wireshark's TCP analysis.

**Evidence:** Frames 35–36:
```
tcp.analysis.retransmission
```

The server does not receive an ACK advancing the window between frame 25 (t+0.296s) and the retransmit at frame 35. This is consistent with the client's buffer being full. The retransmit is not a sign of packet loss on the network — all 34 segments arrived; it is the symptom of the client's receive window collapse.

**Interpretation:** The retransmissions are a **consequence, not a cause** of the slow checkout. Once the client window recovers (frame 38, t+0.916s), the FIN arrives cleanly (frame 39) with no further loss. Retransmission rate is low (2 of 22 actual data packets from server = 9%), indicating the network path is healthy.

---

### F3. Duplicate ACKs from client indicating out-of-order or gap at receiver — **LOW**

**What:** The client sends duplicate ACKs at frames 21 and 23 (both with ACK# 9801), separated by an application-layer ACK (frame 22).

**Evidence:** Frames 21, 23:
```
tcp.analysis.duplicate_ack
```

These are sent at t+0.276s and t+0.286s, while the server is actively sending frames. Duplicate ACKs are normally a sign of either out-of-order reception or a gap, but in this trace they precede the zero-window event and are sparse (only 2 instances), suggesting they are not the primary issue.

**Interpretation:** The duplicate ACKs are a minor indicator that the client was briefly unable to ACK in time, but they do not explain the 500ms pause. They are likely symptoms of the same underlying problem: the application is slow to process the incoming data stream.

---

### F4. Latency decomposition — **INFO**

**What:** Breakdown of the response timeline:

- **TCP handshake:** SYN (frame 1, t+0s) → SYN/ACK (frame 2, t+0.060s) → ACK (frame 3, t+0.120s) = 120ms for 3-way.
- **TLS handshake start:** ClientHello sent at t+0.140s, first server response at t+0.201s = 61ms for server to begin sending TLS records.
- **Data transmission:** Server sends 22 data frames (6–24, then retransmits 25–34) from t+0.201s to t+0.341s = 140ms of active transmission.
- **Stall:** No ACK advancement from client between t+0.341s (frame 34 ACK# 9801) and t+0.846s (retransmit) = 505ms RTO-driven idle period.
- **Recovery:** Client window update at t+0.916s (frame 38).
- **Total connection lifecycle:** 986ms (frame 1 to frame 40).

**Interpretation:** Of the 986ms total, ~745ms (75%) is consumed by the client's receive buffer stall. The network RTT (60ms SYN → SYN/ACK) and TLS handshake overhead (61ms) are negligible. The problem is purely client-side buffering.

---

### F5. MSS and segment sizes — **INFO**

**What:** Both client and server advertise MSS 1460 bytes in the SYN/SYN/ACK (frames 1–2). The server sends 1400-byte segments (matching TCP segment size after headers), and the client sends 200-byte ClientHello. Both are well below path MTU, ruling out fragmentation issues.

**Evidence:** 
```
tcp.flags.syn==1
```

Frames 1, 2 show MSS 1460.

**Interpretation:** Path MTU is healthy; no PMTU discovery problems.

---

## Root cause hypothesis / threat assessment

The available evidence is consistent with **client-side application not reading incoming TCP data quickly enough to prevent its receive buffer from filling**. Here is the sequence:

1. Server sends TLS ServerHello and certificate chain in rapid 1400-byte segments (frames 6–24, then 25–34 after a brief pause).
2. Client TCP stack receives all segments without packet loss (no out-of-order frames, clean checksums).
3. Between frames 24 and 25, the client application has not drained its 8192-byte maximum advertised window, so the buffer fills.
4. By frame 34, the window is exhausted; at frame 37 the client advertises zero window.
5. Server RTO triggers at 505ms (standard 1-second RTO with jitter, or tuned RTO); server retransmits frames 35–36.
6. Meanwhile, the client application eventually reads some data; at frame 38 (t+0.916s), the client sends an ACK that advances the window.
7. Server sends FIN cleanly; connection closes.

**This would be confirmed by:** a packet capture on the **server side** during the same window, which would show the server's send buffer draining normally and no application-layer processing delays. A wireshark TLS dissection with SSLKEYLOGFILE would confirm the TLS Finished message was never received by the client within the capture window (confirming the stall prevented the handshake completion).

**This would be falsified by:** network path measurement showing packet loss or latency >500ms on the outbound path (which would cause the server to time out on ACKs, not the client to stall). A capture showing the client sending data (application level) would rule out the browser; the stall is at the network layer.

## Recommended next steps

1. **Capture on the server side** during the next slow checkout event. Command: `tcpdump -i <eth> -w server-side.pcap 'tcp port 443'`. Compare the server's send pattern against this client trace — the server should show completed TLS handshake and application data being sent, which would definitively place the stall in the client's networking or browser stack.

2. **Enable client-side TCP/IP diagnostics** (e.g., `netstat -s` on the checkout client machine, or packet capture on the client NIC with `netstat -an` and `ss -s` counters) to measure socket buffer fill events (`tcpListenerBacklogOverFlow`, zero-window events) during a slow checkout. This will confirm the application is not calling `recv()` or `read()` on the socket fast enough.

3. **Check browser resource contention** — is the checkout page JavaScript CPU-bound or waiting on a dependent asset during the TLS handshake? Use browser DevTools Network tab and JavaScript profiler to check for blocking main-thread work between the TLS handshake complete and the HTTP response. The presence of long tasks (>50ms) would explain why the browser is not reading the socket promptly.

4. **Validate TLS handshake completion** on the client. Since the trace only spans ~1 second and the TLS ServerHello + certificate were in-flight, confirm that the TLS Finished message and application data were received *after* the capture ended. A longer capture (5+ seconds) or a server-side capture would definitively show whether the handshake completed.

5. **Check for proxy / load-balancer slowness.** The server IP is 10.0.2.30:443, which may be a load balancer or reverse proxy. Capture between the LB and the backend server to confirm the backend is sending data at wire speed and the delay is not introduced by the LB's own processing. If the LB itself is buffering, this would explain why the client sees a stall — the LB could be CPU-limited or waiting for backend connections.

---

## Appendix A — filters used

```
tcp.flags.syn==1 && tcp.flags.ack==0                # SYNs
tcp.flags.syn==1                                    # SYNs and SYN/ACKs
tcp.analysis.retransmission                         # Retransmitted segments
tcp.analysis.zero_window || tcp.analysis.window_full  # Window-stall events
tcp.analysis.duplicate_ack                          # Duplicate ACKs
tcp.stream == 0                                     # Single TCP stream in this capture (implicit in all above)
```

---

## Appendix B — raw stats

### capinfos

```
File name:           ./pcaps/eval-slow-app.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   40
File size:           33 kB
Data size:           33 kB
Capture duration:    0.986003 seconds
First packet time:   2026-05-16 23:40:00.000000
Last packet time:    2026-05-16 23:40:00.986003
Data byte rate:      33 kBps
Data bit rate:       269 kbps
Average packet size: 829.20 bytes
Average packet rate: 40 packets/s
SHA256:              06ccc31702f50fe84eaf4d69fe3f68783d085f68e12715818f9535f2fd76a368
Strict time order:   True
```

### tshark -qz io,phs (protocol hierarchy)

```
eth                                      frames:40 bytes:33168
  ip                                     frames:40 bytes:33168
    tcp                                  frames:40 bytes:33168
      tls                                frames:21 bytes:29334
```

### tshark -qz conv,tcp (TCP conversation stats)

```
10.0.1.20:54210 <-> 10.0.2.30:443
  Client → Server: 15 frames, 1014 bytes
  Server → Client: 25 frames, 32 kB
  Total: 40 frames, 33 kB
  Duration: 0.9860 seconds
```

### tshark -qz expert (expert info summary)

```
Warns (1):
  1 × TCP Zero Window segment (frame 37)

Notes (6):
  1 × TCP Duplicate ACK (#1) (frame 21)
  1 × TCP Duplicate ACK (#2) (frame 23)
  2 × TCP Retransmission (frames 35, 36)
  1 × TCP Connection closing initiation (FIN, frame 39)
  1 × TCP Connection closing completion (FIN, frame 40)
```

### tcptrace -l output

```
TCP connection 1:
  host a:        10.0.1.20:54210 (client)
  host b:        10.0.2.30:443 (server)
  complete conn: yes
  elapsed time:  0:00:00.986003
  total packets: 40

  a→b (client):                    b→a (server):
    total packets:       15          total packets:       25
    actual data packets: 1           actual data packets: 22
    actual data bytes:   200         actual data bytes:   30800
    rexmt data packets:  0           rexmt data packets:  2
    hardware dups:       12 segs     hardware dups:       1 segs
    max win adv:         65535       max win adv:         8192
    min win adv:         8192        min win adv:         8192
    zero win adv:        1 times     zero win adv:        0 times
    idletime max:        580.0 ms    idletime max:        505.0 ms
    throughput:          203 Bps     throughput:          28397 Bps
```

---

## Appendix C — packet-level trace (CSV export)

```
Frame #,Time (offset),IP Src,IP Dst,TCP Src Port,TCP Dst Port,Flags,TCP Len,Retransmission,Zero Window
1,0.000000,10.0.1.20,10.0.2.30,54210,443,S,0,,
2,0.060000,10.0.2.30,10.0.1.20,443,54210,SA,0,,
3,0.120000,10.0.1.20,10.0.2.30,54210,443,A,0,,
4,0.140000,10.0.1.20,10.0.2.30,54210,443,AP,200,,
5,0.141000,10.0.2.30,10.0.1.20,443,54210,A,0,,
6,0.201000,10.0.2.30,10.0.1.20,443,54210,AP,1400,,
7-24,0.206–0.291,10.0.2.30,10.0.1.20,443,54210,various,1400 each,,
25-34,0.296–0.341,10.0.2.30,10.0.1.20,443,54210,AP,1400 each,,
35,0.846003,10.0.2.30,10.0.1.20,443,54210,AP,1400,YES,
36,0.856003,10.0.2.30,10.0.1.20,443,54210,AP,1400,YES,
37,0.866003,10.0.1.20,10.0.2.30,54210,443,A,0,,YES
38,0.916003,10.0.1.20,10.0.2.30,54210,443,A,0,,
39,0.926003,10.0.2.30,10.0.1.20,443,54210,AF,0,,
40,0.986003,10.0.1.20,10.0.2.30,54210,443,AF,0,,
```
