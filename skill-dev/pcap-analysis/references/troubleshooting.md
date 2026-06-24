# Troubleshooting playbook

Use when the user's question is about *why something is slow, failing, or misbehaving*. The goal is to find a specific root cause hypothesis, backed by filters and frame references, not a generic "the network seems bad."

Work through these in order — each section is a hypothesis you either confirm or dismiss. Don't skip ahead: a "TLS handshake fails" finding is meaningless if the TCP layer was already broken and you didn't notice.

## Table of contents

1. Is the application even in the trace?
2. TCP health (handshake, retransmits, zero-windows, RSTs, MSS)
3. Latency decomposition (network vs server vs app)
4. DNS health
5. TLS health
6. HTTP / app-layer response codes
7. Specific protocol notes (QUIC, SMB, VoIP, gRPC)
8. When the trace is inconclusive

---

## 1. Is the application even in the trace?

Before anything else, confirm the flow under investigation is captured:

```sh
tshark -r pcap -qz conv,tcp | head -20
tshark -r pcap -qz conv,udp | head -20
tshark -r pcap -Y "ip.addr == <client> && ip.addr == <server>" | head
```

If there are zero packets between the expected endpoints, stop troubleshooting and question the capture point. A trace from the wrong side of a NAT / proxy / load balancer will lie convincingly.

Also check `tshark -r pcap -qz io,phs` — the protocol hierarchy shows whether the application protocol is present at all. If the user asks about HTTP and the trace is 99% QUIC, that's the answer.

## 2. TCP health

Run these in order — each depends on the previous being OK.

**Handshake:**
```sh
# Successful handshakes (SYN + SYN/ACK + ACK)
tshark -r pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields \
  -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport

# Half-open / failed (SYN with no matching SYN/ACK)
tshark -r pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e tcp.stream | sort -u > /tmp/syn_streams
tshark -r pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e tcp.stream | sort -u > /tmp/synack_streams
comm -23 /tmp/syn_streams /tmp/synack_streams
```

If many streams never got SYN/ACK, suspect a firewall drop, an ECN/DF issue, or the server is down. Note this as HIGH severity and stop — higher layers won't work.

**Retransmissions and duplicate ACKs:**
```sh
tshark -r pcap -qz io,stat,1,"COUNT(tcp.analysis.retransmission)tcp.analysis.retransmission","COUNT(tcp.analysis.duplicate_ack)tcp.analysis.duplicate_ack"
tshark -r pcap -Y "tcp.analysis.retransmission" -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.stream | head -40
```

Retransmission rate >1% of segments is a strong signal. Localize by `tcp.stream` — is it one flow or all flows? One flow suggests a path problem; all flows suggests a capture-side drop (NIC, mirror port) or real congestion.

**Zero windows / window-full:**
```sh
tshark -r pcap -Y "tcp.analysis.zero_window || tcp.analysis.window_full" -T fields \
  -e frame.number -e ip.src -e ip.dst -e tcp.window_size
```

These indicate a receiver that can't keep up — often an application that stopped reading. Note severity MEDIUM; usually the slowness is app-side, not network-side.

**RSTs:**
```sh
tshark -r pcap -Y "tcp.flags.reset==1" -T fields -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport | head -40
```

RSTs immediately after SYN/ACK = server refused. RSTs after data = abrupt close, often app-timeout or middlebox intervention.

**MSS / PMTU:**
Look at the MSS option in SYN/SYN-ACK. A conversation where one side advertises 1460 and the other 536 usually means a tunnel / VPN is mangling PMTU discovery.

```sh
tshark -r pcap -Y "tcp.flags.syn==1" -T fields -e ip.src -e ip.dst -e tcp.options.mss_val
```

## 3. Latency decomposition

Decompose total response latency into: DNS + TCP connect + TLS handshake + server processing. Report each.

- **DNS:** response time = answer frame time − query frame time, same `dns.id`.
- **TCP connect:** SYN/ACK time − SYN time.
- **TLS handshake:** Finished time − ClientHello time.
- **Server processing:** first data byte from server − last byte of request.
- **App latency:** request-to-response for HTTP, SMB, gRPC, etc.

`tcptrace -l pcap` prints per-connection RTT, retransmit, and throughput stats and is faster than recomputing these by hand. Use it for a first pass, then cross-check suspicious connections with `tshark`.

## 4. DNS

Common failures:

- `NXDOMAIN` (rcode 3): name doesn't exist. Report the query names and who asked.
- `SERVFAIL` (rcode 2): resolver gave up. Often upstream DNSSEC or forwarder issue.
- `REFUSED` (rcode 5): resolver policy refused. ACL.
- `No response`: filter on `dns.flags.response==0` without a matching response. Suspect packet loss or the resolver is wedged.

```sh
# Response code distribution
tshark -r pcap -Y "dns.flags.response==1" -T fields -e dns.flags.rcode | sort | uniq -c | sort -rn

# Unanswered queries
tshark -r pcap -Y "dns.flags.response==0" -T fields -e dns.id -e dns.qry.name > /tmp/q.tsv
tshark -r pcap -Y "dns.flags.response==1" -T fields -e dns.id -e dns.qry.name > /tmp/r.tsv
# then compare by id
```

For slow DNS, plot per-response latency:
```sh
tshark -r pcap -Y "dns" -T fields -e frame.time_relative -e dns.time -e dns.qry.name -e dns.flags.rcode
```

## 5. TLS

- **Handshake failed:** ClientHello present, no ServerHello, or an `alert` with description. `tshark -Y "tls.alert_message"` shows alert codes (40 = handshake failure, 43 = certificate unknown, 46 = certificate unknown, 70 = protocol version).
- **Version / cipher mismatch:** compare ClientHello `supported_versions` vs ServerHello chosen version. A server offering only TLS 1.2 to a client demanding 1.3 is a frequent pattern after server upgrades.
- **Name mismatch / expired cert:** `tshark -Y "tls.handshake.type==11" -V | grep -E "notBefore|notAfter|CN="` — verify cert CN vs SNI, and check date validity against `capinfos` start time.

For slow TLS handshakes without failure, measure time from ClientHello to Finished per `tcp.stream`. A consistent 1s+ suggests slow key exchange (oversized cert chain, slow OCSP fetch, or slow cert validation on the server).

## 6. HTTP / app-layer response codes

```sh
tshark -r pcap -Y "http.response" -T fields -e frame.number -e http.response.code -e http.request.uri -e ip.src -e ip.dst | head -50
tshark -r pcap -Y "http.response" -T fields -e http.response.code | sort | uniq -c | sort -rn
```

4xx concentrated on one URI = app bug or auth issue. 5xx spikes = server-side overload or crash (correlate with `tcp.analysis.zero_window` on the same flow).

## 7. Specific protocol notes

- **QUIC:** `tshark -Y "quic"` shows the frames, but encrypted past the Initial packet. Can still infer handshake success/failure and RTT. Distinguish via version negotiation (`quic.version`).
- **SMB:** `-qz smb2,srt` for service response times. Long SRTs on `SMB2_CREATE` / `SMB2_READ` = file server slow.
- **VoIP:** `-qz sip,stat`, `-qz rtp,streams`. MOS < 3.6 or jitter > 30ms is the usual threshold.
- **gRPC / HTTP/2:** frame-level analysis via `http2.stream`. Look for RST_STREAM errors.

## 8. When the trace is inconclusive

Sometimes the pcap simply doesn't contain the answer. Say that. Examples:

- All the latency is in "server processing" time — capture on the server, you're looking at a network-side trace of an app problem.
- Handshake fails without a diagnostic alert — capture on both sides to see what each saw differently.
- Traffic is encrypted end-to-end and the question is about content — need SSLKEYLOGFILE or an MITM proxy.

Writing "inconclusive, need capture X" is often the right answer and saves the reader time.
