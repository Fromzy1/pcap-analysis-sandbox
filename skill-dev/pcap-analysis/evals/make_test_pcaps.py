"""
Generate three synthetic pcaps for testing the pcap-analysis skill.

They're not meant to be realistic at the byte level — they're meant to carry
the *signals* a real investigation would look for, so the skill's workflow
has something to find. Scapy builds them in a few seconds.

Outputs:
  pcaps/eval-slow-app.pcap        — HTTP over TCP with gradual retransmits + window-full signals
  pcaps/eval-dns-cascade.pcap     — DNS NXDOMAIN cascade + downstream HTTP 502s
  pcaps/eval-beacon.pcap          — periodic small TLS-like connections to one odd destination

Run from the pcap_analysis_sandbox with `source activate.sh` first:
    python skill-dev/pcap-analysis/evals/make_test_pcaps.py
"""
from __future__ import annotations

import os
import random
from pathlib import Path

from scapy.all import (
    DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, Raw, wrpcap,
)

random.seed(1234)

OUT = Path("/sessions/sweet-trusting-darwin/mnt/pcap_analysis_sandbox/pcaps")
OUT.mkdir(exist_ok=True, parents=True)

BASE_TS = 1_779_000_000.0  # a repeatable mid-2026 timestamp


# ---------------------------------------------------------------------------
# Helper: put a timestamp on a packet when writing
# ---------------------------------------------------------------------------
def _set_ts(pkt, ts):
    pkt.time = ts
    return pkt


# ---------------------------------------------------------------------------
# Scenario A: a slow HTTP request with retransmits + one zero-window
# ---------------------------------------------------------------------------
def make_slow_app() -> list:
    pkts = []
    t = BASE_TS

    client = ("10.0.1.20", 54210, "aa:bb:cc:00:00:01")
    server = ("10.0.2.30", 443,   "aa:bb:cc:00:00:02")

    def eth(src_mac, dst_mac):
        return Ether(src=src_mac, dst=dst_mac)

    c_mac, s_mac = client[2], server[2]
    c_ip, c_port = client[0], client[1]
    s_ip, s_port = server[0], server[1]

    # Three-way handshake (RTT ~120ms)
    pkts.append(_set_ts(eth(c_mac, s_mac)/IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=s_port,
                flags="S", seq=1000, options=[("MSS", 1460)]), t))
    t += 0.060
    pkts.append(_set_ts(eth(s_mac, c_mac)/IP(src=s_ip, dst=c_ip)/TCP(sport=s_port, dport=c_port,
                flags="SA", seq=5000, ack=1001, options=[("MSS", 1460)]), t))
    t += 0.060
    pkts.append(_set_ts(eth(c_mac, s_mac)/IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=s_port,
                flags="A", seq=1001, ack=5001), t))
    t += 0.020

    # Client sends a small TLS-like payload (1 segment, 200 bytes).
    payload = bytes([random.randrange(256) for _ in range(200)])
    pkts.append(_set_ts(eth(c_mac, s_mac)/IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=s_port,
                flags="PA", seq=1001, ack=5001)/Raw(load=payload), t))
    t += 0.001

    # Server ACKs normally...
    pkts.append(_set_ts(eth(s_mac, c_mac)/IP(src=s_ip, dst=c_ip)/TCP(sport=s_port, dport=c_port,
                flags="A", seq=5001, ack=1201), t))
    t += 0.060

    # Server starts a 20-segment response, but several are "lost" — client
    # sends duplicate ACKs, server retransmits.
    seq = 5001
    for i in range(20):
        seg = bytes([random.randrange(256) for _ in range(1400)])
        pkts.append(_set_ts(eth(s_mac, c_mac)/IP(src=s_ip, dst=c_ip)/TCP(sport=s_port, dport=c_port,
                    flags="PA", seq=seq, ack=1201)/Raw(load=seg), t))
        t += 0.005
        seq += 1400

        # Simulate dropped segments 7, 8 — client ACKs only up to segment 6.
        if i < 6:
            pkts.append(_set_ts(eth(c_mac, s_mac)/IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=s_port,
                        flags="A", seq=1201, ack=seq), t))
            t += 0.005
        elif i in (6, 7, 8):
            # duplicate ACKs for seq up to end-of-seg-6
            dup_ack_target = 5001 + 7 * 1400
            pkts.append(_set_ts(eth(c_mac, s_mac)/IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=s_port,
                        flags="A", seq=1201, ack=dup_ack_target), t))
            t += 0.005

    # Retransmissions of segments 7 and 8 after a timeout
    t += 0.500  # RTO gap
    for idx in (7, 8):
        seg_seq = 5001 + idx * 1400
        seg = bytes([0xAA] * 1400)
        pkts.append(_set_ts(eth(s_mac, c_mac)/IP(src=s_ip, dst=c_ip)/TCP(sport=s_port, dport=c_port,
                    flags="PA", seq=seg_seq, ack=1201)/Raw(load=seg), t))
        t += 0.010

    # A zero-window event — client advertises window=0 momentarily
    pkts.append(_set_ts(eth(c_mac, s_mac)/IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=s_port,
                flags="A", seq=1201, ack=seq, window=0), t))
    t += 0.050
    pkts.append(_set_ts(eth(c_mac, s_mac)/IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=s_port,
                flags="A", seq=1201, ack=seq, window=65535), t))
    t += 0.010

    # Orderly FIN
    pkts.append(_set_ts(eth(s_mac, c_mac)/IP(src=s_ip, dst=c_ip)/TCP(sport=s_port, dport=c_port,
                flags="FA", seq=seq, ack=1201), t))
    t += 0.060
    pkts.append(_set_ts(eth(c_mac, s_mac)/IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=s_port,
                flags="FA", seq=1201, ack=seq+1), t))

    return pkts


# ---------------------------------------------------------------------------
# Scenario B: DNS resolution failures + downstream HTTP 502s
# ---------------------------------------------------------------------------
def make_dns_cascade() -> list:
    pkts = []
    t = BASE_TS + 3600  # one hour offset for separation

    client = ("10.0.1.25", "aa:bb:cc:00:00:11")
    resolver = ("10.0.1.53", "aa:bb:cc:00:00:12")
    # A working backend + a "broken" backend that returns 502
    real_backend = ("10.0.3.5", "aa:bb:cc:00:00:13")

    c_ip, c_mac = client
    r_ip, r_mac = resolver
    b_ip, b_mac = real_backend

    def eth_q(): return Ether(src=c_mac, dst=r_mac)
    def eth_r(): return Ether(src=r_mac, dst=c_mac)

    # Five DNS queries: 2 success (to real backend) and 3 NXDOMAIN for a fake name
    qnames = [
        ("api.prod.example.com", True),
        ("auth.prod.example.com", True),
        ("newsvc.prod.example.com", False),
        ("v2.newsvc.prod.example.com", False),
        ("internal.newsvc.prod.example.com", False),
    ]
    dns_id = 1000
    for qname, ok in qnames:
        q = eth_q()/IP(src=c_ip, dst=r_ip)/UDP(sport=50000+dns_id, dport=53) \
            /DNS(id=dns_id, rd=1, qd=DNSQR(qname=qname))
        pkts.append(_set_ts(q, t)); t += 0.004
        if ok:
            ans = eth_r()/IP(src=r_ip, dst=c_ip)/UDP(sport=53, dport=50000+dns_id) \
                /DNS(id=dns_id, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=qname),
                     an=DNSRR(rrname=qname, ttl=30, rdata=b_ip))
        else:
            # NXDOMAIN: qr=1, rcode=3
            ans = eth_r()/IP(src=r_ip, dst=c_ip)/UDP(sport=53, dport=50000+dns_id) \
                /DNS(id=dns_id, qr=1, aa=0, rd=1, ra=1, rcode=3, qd=DNSQR(qname=qname))
        pkts.append(_set_ts(ans, t)); t += 0.010
        dns_id += 1

    # For the two that succeeded, the client does 3 HTTP requests to the backend.
    # The backend returns 502 Bad Gateway on each (simulating broken upstream).
    def eth_cb(): return Ether(src=c_mac, dst=b_mac)
    def eth_bc(): return Ether(src=b_mac, dst=c_mac)

    for i in range(3):
        sport = 40100 + i
        seq_c = 20000 + i*100
        seq_s = 30000 + i*100
        # handshake
        pkts.append(_set_ts(eth_cb()/IP(src=c_ip, dst=b_ip)/TCP(sport=sport, dport=80, flags="S", seq=seq_c), t)); t += 0.02
        pkts.append(_set_ts(eth_bc()/IP(src=b_ip, dst=c_ip)/TCP(sport=80, dport=sport, flags="SA", seq=seq_s, ack=seq_c+1), t)); t += 0.02
        pkts.append(_set_ts(eth_cb()/IP(src=c_ip, dst=b_ip)/TCP(sport=sport, dport=80, flags="A", seq=seq_c+1, ack=seq_s+1), t)); t += 0.01
        # GET
        req = b"GET /api/orders HTTP/1.1\r\nHost: api.prod.example.com\r\nUser-Agent: checkout/1.0\r\n\r\n"
        pkts.append(_set_ts(eth_cb()/IP(src=c_ip, dst=b_ip)/TCP(sport=sport, dport=80, flags="PA", seq=seq_c+1, ack=seq_s+1)/Raw(load=req), t)); t += 0.05
        # 502 response
        resp_body = b"upstream not reachable"
        resp = (b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n\r\n" + resp_body)
        pkts.append(_set_ts(eth_bc()/IP(src=b_ip, dst=c_ip)/TCP(sport=80, dport=sport, flags="PA", seq=seq_s+1, ack=seq_c+1+len(req))/Raw(load=resp), t)); t += 0.01
        pkts.append(_set_ts(eth_cb()/IP(src=c_ip, dst=b_ip)/TCP(sport=sport, dport=80, flags="FA", seq=seq_c+1+len(req), ack=seq_s+1+len(resp)), t)); t += 0.02
        pkts.append(_set_ts(eth_bc()/IP(src=b_ip, dst=c_ip)/TCP(sport=80, dport=sport, flags="FA", seq=seq_s+1+len(resp), ack=seq_c+2+len(req)), t)); t += 0.02
        t += 0.2

    return pkts


# ---------------------------------------------------------------------------
# Scenario C: beaconing-like behaviour
# ---------------------------------------------------------------------------
def make_beacon() -> list:
    pkts = []
    t = BASE_TS + 7200

    internal = ("10.0.4.10", "aa:bb:cc:00:00:21")
    # Resolver + ordinary destination for "normal" traffic
    resolver = ("10.0.4.53", "aa:bb:cc:00:00:22")
    normal_ext = ("93.184.216.34", "aa:bb:cc:00:00:23")  # example.com-ish
    # Beacon destination
    beacon_ext = ("185.220.101.45", "aa:bb:cc:00:00:24")  # arbitrary odd IP
    beacon_name = "c2-check.examplebad.xyz"

    i_ip, i_mac = internal
    r_ip, r_mac = resolver
    n_ip, n_mac = normal_ext
    b_ip, b_mac = beacon_ext

    # Background: a normal HTTPS download from a known-good external (five reqs spread out)
    for i in range(5):
        sport = 45000 + i
        # handshake + a bit of data
        pkts.append(_set_ts(Ether(src=i_mac, dst=n_mac)/IP(src=i_ip, dst=n_ip)/TCP(sport=sport, dport=443, flags="S", seq=1000+i*10), t)); t += 0.05
        pkts.append(_set_ts(Ether(src=n_mac, dst=i_mac)/IP(src=n_ip, dst=i_ip)/TCP(sport=443, dport=sport, flags="SA", seq=2000+i*10, ack=1001+i*10), t)); t += 0.05
        pkts.append(_set_ts(Ether(src=i_mac, dst=n_mac)/IP(src=i_ip, dst=n_ip)/TCP(sport=sport, dport=443, flags="A", seq=1001+i*10, ack=2001+i*10), t)); t += 0.02
        # a decent-sized upload (simulating an app)
        for _ in range(10):
            payload = bytes([random.randrange(256) for _ in range(1200)])
            pkts.append(_set_ts(Ether(src=i_mac, dst=n_mac)/IP(src=i_ip, dst=n_ip)/TCP(sport=sport, dport=443, flags="PA", seq=1001+i*10, ack=2001+i*10)/Raw(load=payload), t))
            t += 0.02
        t += 120  # spread background over minutes

    # Beacon: every 60s ± 1s, a small TCP 443 session lasting a few packets,
    # preceded by a DNS query to the beacon name.
    t_beacon = BASE_TS + 7200 + 30  # start 30s in
    for beacon_i in range(20):
        # DNS query first
        dns_id = 4000 + beacon_i
        pkts.append(_set_ts(
            Ether(src=i_mac, dst=r_mac)/IP(src=i_ip, dst=r_ip)/UDP(sport=55000+beacon_i, dport=53)
            /DNS(id=dns_id, rd=1, qd=DNSQR(qname=beacon_name)), t_beacon));
        pkts.append(_set_ts(
            Ether(src=r_mac, dst=i_mac)/IP(src=r_ip, dst=i_ip)/UDP(sport=53, dport=55000+beacon_i)
            /DNS(id=dns_id, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=beacon_name),
                 an=DNSRR(rrname=beacon_name, ttl=60, rdata=b_ip)), t_beacon + 0.010))
        # Tiny TCP session
        sport = 50000 + beacon_i
        t_session = t_beacon + 0.020
        pkts.append(_set_ts(Ether(src=i_mac, dst=b_mac)/IP(src=i_ip, dst=b_ip)/TCP(sport=sport, dport=443, flags="S", seq=9000+beacon_i), t_session)); t_session += 0.10
        pkts.append(_set_ts(Ether(src=b_mac, dst=i_mac)/IP(src=b_ip, dst=i_ip)/TCP(sport=443, dport=sport, flags="SA", seq=8000+beacon_i, ack=9001+beacon_i), t_session)); t_session += 0.10
        pkts.append(_set_ts(Ether(src=i_mac, dst=b_mac)/IP(src=i_ip, dst=b_ip)/TCP(sport=sport, dport=443, flags="A", seq=9001+beacon_i, ack=8001+beacon_i), t_session)); t_session += 0.01
        beacon_payload = bytes([0xBB] * 312)  # consistent small payload
        pkts.append(_set_ts(Ether(src=i_mac, dst=b_mac)/IP(src=i_ip, dst=b_ip)/TCP(sport=sport, dport=443, flags="PA", seq=9001+beacon_i, ack=8001+beacon_i)/Raw(load=beacon_payload), t_session)); t_session += 0.10
        resp_payload = bytes([0xCC] * 64)
        pkts.append(_set_ts(Ether(src=b_mac, dst=i_mac)/IP(src=b_ip, dst=i_ip)/TCP(sport=443, dport=sport, flags="PA", seq=8001+beacon_i, ack=9001+beacon_i+len(beacon_payload))/Raw(load=resp_payload), t_session)); t_session += 0.05
        pkts.append(_set_ts(Ether(src=i_mac, dst=b_mac)/IP(src=i_ip, dst=b_ip)/TCP(sport=sport, dport=443, flags="FA", seq=9001+beacon_i+len(beacon_payload), ack=8001+beacon_i+len(resp_payload)), t_session)); t_session += 0.05
        pkts.append(_set_ts(Ether(src=b_mac, dst=i_mac)/IP(src=b_ip, dst=i_ip)/TCP(sport=443, dport=sport, flags="FA", seq=8001+beacon_i+len(resp_payload), ack=9002+beacon_i+len(beacon_payload)), t_session))

        # jitter the interval a little (±1.5s) but keep it recognizable
        t_beacon += 60.0 + random.uniform(-1.5, 1.5)

    # Sort all packets by their .time so the writer preserves order
    pkts.sort(key=lambda p: p.time)
    return pkts


def main():
    configs = [
        ("eval-slow-app.pcap", make_slow_app),
        ("eval-dns-cascade.pcap", make_dns_cascade),
        ("eval-beacon.pcap", make_beacon),
    ]
    for name, builder in configs:
        pkts = builder()
        # Ensure packets are in time order
        pkts.sort(key=lambda p: p.time)
        path = OUT / name
        wrpcap(str(path), pkts)
        print(f"wrote {len(pkts):5d} packets -> {path}")


if __name__ == "__main__":
    main()
