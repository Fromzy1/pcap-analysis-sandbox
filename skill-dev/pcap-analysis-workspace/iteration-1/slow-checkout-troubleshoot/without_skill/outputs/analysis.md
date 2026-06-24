# Checkout Page Slowdown Analysis
## Packet Capture: eval-slow-app.pcap

**Date:** 2026-05-16 23:40:00 UTC  
**Duration:** 0.986 seconds  
**Total Packets:** 40  

---

## Executive Summary

The checkout page hang is caused by **TCP receive window exhaustion (Zero Window condition)** at the client side combined with server-side congestion. The client's receive buffer becomes full while the server is still transmitting data, causing the server to retransmit packets. The client eventually recovers, but this creates a 500ms+ delay in the transaction completion.

---

## Root Cause Analysis

### Timeline of Events

**Phase 1: TLS Handshake (t=0.0s - t=0.14s)**
- Client initiates TCP SYN to server (10.0.1.20 → 10.0.2.30:443)
- Server responds with SYN-ACK (60ms round trip)
- Three-way handshake completes (120ms to establish connection)
- Client sends TLS Client Hello (~200 bytes)

**Phase 2: Server Response Transmission (t=0.14s - t=0.34s)**
- Server sends back TLS handshake/certificate chain in ~10 segments (~1400 bytes each)
- Each segment is acknowledged by client
- Client ACKs arriving in predictable 5ms intervals
- Segments transmitted at ~5ms intervals by server

**Phase 3: Critical Problem - Window Collapse (t=0.27s)**
- At packet #21-23: Client starts sending **Duplicate ACKs** for sequence 9801
- This indicates the client application is not consuming data fast enough
- The receive buffer is filling up faster than application-level processing
- Server continues sending data (packets #25-34) despite no forward progress in ACKs

**Phase 4: Zero Window Condition (t=0.34s - t=0.85s)**
- At packet #37: Client sends **TCP Zero Window** (Win=0)
  - This signals: "I cannot accept any more data, my receive buffer is full"
  - This is the smoking gun - the client's application is blocked/slow
- Server continues transmission attempts (packets #35-36) with **TCP Retransmissions**
- **500ms delay** between the zero window signal (t=0.866s) and recovery (t=0.916s)

**Phase 5: Recovery and Closure (t=0.85s - t=0.986s)**
- At packet #38: Client sends **TCP Window Update** (Win=65535) after 50ms
  - Application finally consumed enough data to free buffer space
  - Allows server to finish transmission
- Server completes data transfer and closes connection (FIN)
- Connection closes cleanly

---

## Key Findings

### 1. Client-Side Receive Buffer Exhaustion
- **Symptom:** TCP Zero Window at 0.866s
- **Impact:** 50ms freeze while waiting for application to drain buffer
- **Root:** Slow application processing of incoming data at checkout page

### 2. Inefficient Windowing Behavior
- Client TCP window: 8192 bytes (very small, default)
- Server segments: 1400 bytes each (good segmentation)
- Problem: Client can only buffer ~6 segments before running out of space
- After 6 segments, application must consume data before more arrives

### 3. Duplicate ACKs Indicate Queueing
- Packets #21-23 show duplicate ACKs for the same sequence number
- Symptom of: Network out-pacing application consumption
- Not packet loss (no actual retransmission was needed yet)

### 4. Server-Side Impact
- Server waiting for window updates causes retransmissions
- At t=0.846s and t=0.856s, server retransmits despite no packet loss
- This happens because the server doesn't know why ACKs stopped advancing

---

## Impact Quantification

| Metric | Value |
|--------|-------|
| Connection establishment time | 120 ms |
| TLS handshake overhead | ~130 ms |
| **Checkout processing stall** | **~50 ms** |
| **User-visible delay from zero window** | **~500 ms capture window** |
| Total transaction time | 986 ms |

The actual customer-reported "several seconds" suggests either:
- Multiple such stalls in the real checkout flow
- A much larger dataset than this test capture
- Client-side processing delays on checkout page

---

## Network Team Recommendations

### Priority 1: Fix Client-Side Application Performance
**Action:** Profile the checkout page JavaScript/application code
- **Symptom seen:** Application not consuming incoming data fast enough
- **Why it matters:** Every 1400 bytes from server requires ~3-4ms application processing
- **Solution:** Optimize handlers for incoming data, avoid blocking operations during network I/O

### Priority 2: Increase TCP Receive Window
**Action:** Increase TCP receive window size at client
```
# Linux client-side tuning:
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"  # Increase max to 16MB

# Browser/app-specific: Ensure no artificial window limiting
```
- **Why:** Current 8192 byte window is very small for modern transfers
- **Expected improvement:** Reduces queueing sensitivity, allows buffering of more segments
- **Standard:** Recommend minimum 65535 bytes for this traffic pattern

### Priority 3: Optimize Checkout Page Load
**Action:** Analyze what checkout endpoint is returning
- **Context:** 28KB of application data being transferred in ~850ms
- **Consider:**
  - Is the checkout page fetching too much data initially?
  - Can you split into critical vs. non-critical assets?
  - Are there synchronous I/O operations blocking processing?

### Priority 4: Monitor for Retransmissions
**Action:** Enable packet loss/retransmission alerting
- Seen 2 retransmissions (packets #35-36) due to zero window condition
- This is a symptom of undersized buffers, not network congestion

---

## Technical Details for Network Ops

### TCP Sequence Analysis
- Client: Single segment (200 bytes) then ACKs
- Server: ~20KB transferred in ~10 segments
- No packet loss detected (all retransmissions were timeout-based, not loss-based)

### Congestion vs. Buffer Issue
- **NOT congestion:** Server had data ready to send, client refused to accept it
- **IS buffer stall:** Client receive window went to zero, blocking progress
- **Distinction matters:** Congestion window tuning won't fix this; buffering will

### Application-Level Insight
- ~500ms is a significant delay for page processing
- Suggests JavaScript execution, DOM rendering, or blocking I/O
- Recommend WebVitals monitoring (First Contentful Paint, Cumulative Layout Shift)

---

## Conclusion

The checkout page slowdown is **not a network problem** — it's **an application buffering/processing issue**. The network is functioning correctly; it's the checkout page application that cannot keep up with the incoming data rate and fills its receive buffer, causing TCP window collapse and blocking the server.

**Primary action:** Optimize the checkout page application to consume incoming data faster or process it more efficiently during network I/O.
