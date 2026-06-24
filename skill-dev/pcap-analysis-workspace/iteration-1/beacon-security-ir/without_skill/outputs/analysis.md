# Security Analysis Report: Workstation 10.0.4.10
## Packet Capture Analysis - eval-beacon.pcap

**Analysis Date:** April 16, 2026  
**Capture Date:** May 17, 2026 01:40:00 - 01:59:28 PDT (1168 seconds / ~19.5 minutes)  
**Workstation:** 10.0.4.10  
**Total Packets:** 245  
**Capture Size:** 86 KB  

---

## EXECUTIVE SUMMARY

**VERDICT: CRITICAL - ACTIVE C2 BEACON DETECTED**

The workstation 10.0.4.10 exhibits clear indicators of compromise with strong evidence of Command & Control (C2) beacon activity. Two external IP addresses are receiving regular HTTP/HTTPS connection attempts with periodic beacon intervals (~14-60 seconds). The workstation also performs DNS lookups for a suspicious domain ("c2-check.examplebad.xyz") consistent with C2 check-in behavior.

---

## FINDINGS

### 1. SUSPICIOUS OUTBOUND CONNECTIONS

#### Primary C2 Server: 185.220.101.45
- **Protocol:** TCP/443 (HTTPS)
- **Connection Count:** 80 packets across the capture period
- **Behavior:** Highly regular beaconing pattern
- **Beacon Interval:** Average 14.41 seconds (min: 0.01s, max: 61.06s)
- **Pattern:** Consistent 4-packet bursts every ~60 seconds
  - Single initial SYN packet
  - Three follow-up data/handshake packets at 100-200ms intervals
  - Repeats with remarkable consistency (~60s intervals)
- **Time Range:** 01:40:30 - 01:59:28 (19 minutes of continuous beaconing)

#### Secondary C2 Server: 93.184.216.34
- **Protocol:** TCP/443 (HTTPS)
- **Connection Count:** 60 packets across the capture period
- **Behavior:** Secondary beaconing with longer intervals
- **Beacon Interval:** Average 8.16 seconds (min: 0.02s, max: 120.02s)
- **Pattern:** Similar 4-packet bursts but less frequent than primary C2
- **Time Range:** 01:40:00 - 01:48:01 (8 minutes of activity, then dormant)

### 2. MALICIOUS DNS ACTIVITY

#### Domain: c2-check.examplebad.xyz
- **Query Count:** 20 DNS A-record lookups
- **Query Source:** 10.0.4.10:55000 → 10.0.4.53:53
- **Behavior:** Regular DNS queries preceding C2 connections
- **Pattern:** Query issued approximately 30 seconds before each C2 beacon burst
- **Significance:** Domain name explicitly indicates C2 checking behavior ("c2-check")

### 3. BEACON TIMING ANALYSIS

#### Primary C2 (185.220.101.45) - Scheduled Beaconing
```
Timestamps of beacon bursts (showing regularity):
- 01:40:30.020 - 01:40:30.380
- 01:41:31.144 - 01:41:31.504
- 01:42:29.647 - 01:42:30.007
- 01:43:29.259 - 01:43:29.619
- 01:44:28.908 - 01:44:29.268
[Pattern continues every ~60 seconds for full capture duration]
```

**Analysis:** The remarkable consistency (±1-2 second variance) indicates:
- Scheduled/timed beacon mechanism
- Likely configured for ~60 second check-in intervals
- No human-interactive traffic patterns observed

#### Secondary C2 (93.184.216.34) - Burst Pattern
```
Timestamps show clustering:
- 01:40:00.000 - 01:40:00.300 (rapid 12 packets)
- 01:42:00.320 - 01:42:00.619 (rapid 12 packets)
- 01:44:00.639 - 01:44:00.939 (rapid 12 packets)
- 01:46:00.959 - 01:46:01.259 (rapid 12 packets)
- 01:48:01.279 - 01:48:01.579 (final burst, then ceases)
```

**Analysis:** Burst pattern with 2-minute intervals, then complete cessation. Suggests:
- Secondary C2 or fallback beacon
- Either disabled after initial contact or task completed
- Different operational tempo than primary C2

### 4. NETWORK TRAFFIC SUMMARY

**Total Traffic from 10.0.4.10:**
| Destination | Service | Packets | Type | Concern |
|---|---|---|---|---|
| 185.220.101.45 | HTTPS (443) | 80 | C2 Beacon | CRITICAL |
| 93.184.216.34 | HTTPS (443) | 60 | C2 Beacon | CRITICAL |
| 10.0.4.53 | DNS (53) | 20 | Name Resolution | HIGH |
| (no HTTPS return traffic) | - | - | - | - |

**Note:** Only outbound TCP connection attempts observed; no successful response traffic captured, suggesting either:
- Connections blocked at perimeter firewall
- Responses filtered from capture
- Only initial handshake packets captured from span port

---

## INDICATORS OF COMPROMISE (IOCs)

### IP Addresses (High Confidence)
```
185.220.101.45:443   [Primary C2 - Active Beaconing]
93.184.216.34:443    [Secondary C2 - Burst Pattern]
```

### Domain Names (High Confidence)
```
c2-check.examplebad.xyz  [C2 Check-In Domain]
```

### Behavioral Indicators
```
1. Outbound HTTPS to external IPs with <60 second beacon intervals
2. Scheduled DNS queries to suspicious domains with "c2-check" naming pattern
3. Repetitive 4-packet TCP burst pattern to port 443
4. Consistent timing with minimal variance (±2 seconds over 19 minutes)
5. No legitimate HTTP/HTTPS request patterns (no Host headers, no TLS ClientHello data visible)
```

### Hash for Tracking
```
PCAP SHA256: 71399343455dc1e124d7bbff36a7f0826a12d45b519a2692d5bcf4ed62c6440f
```

---

## THREAT ASSESSMENT

### Confidence Level: CRITICAL

**Evidence Strength:**
- Definitive C2 beaconing behavior pattern
- Explicitly named malicious domain ("c2-check.examplebad.xyz")
- Regular, automated check-in pattern inconsistent with normal user activity
- Multiple C2 endpoints (redundancy/failover configuration)

### Likely Infection Timeline
1. **01:40:00** - Workstation attempts contact with secondary C2 (93.184.216.34)
2. **01:40:30** - Primary C2 engagement (185.220.101.45) begins
3. **01:40:30 onwards** - Automated beacon every ~60 seconds to primary C2
4. **01:40:30 onwards** - DNS checks to c2-check.examplebad.xyz every ~60 seconds
5. **01:48:01** - Secondary C2 communication ceases (task complete or disabled)
6. **01:59:28** - Capture ends with primary C2 still actively beaconing

---

## SIEM INTEGRATION RECOMMENDATIONS

### Alert Rules to Create

#### Rule 1: Outbound HTTPS to Suspicious IPs
```
CONDITION: (ip.dst IN [185.220.101.45, 93.184.216.34] AND 
            tcp.dstport == 443 AND 
            ip.src == 10.0.4.10)
SEVERITY: Critical
ACTION: Block + Alert
```

#### Rule 2: DNS Lookups for Malicious Domains
```
CONDITION: (dns.qry_name == "c2-check.examplebad.xyz" OR 
            dns.qry_name LIKE "*examplebad.xyz*")
SEVERITY: Critical
ACTION: Alert + Investigate
```

#### Rule 3: Beaconing Pattern Detection
```
CONDITION: (Outbound connections from ip.src to same ip.dst 
            on port 443 with regular intervals <120 seconds, 
            occurring >20 times in <30 minutes)
SEVERITY: High
ACTION: Alert on first detection
```

### IOCs for Blocklist
- **IP Blocklist:** 185.220.101.45, 93.184.216.34
- **Domain Blocklist:** c2-check.examplebad.xyz, *.examplebad.xyz
- **Port Monitoring:** Flag any outbound 443 traffic to these IPs for immediate escalation

---

## IMMEDIATE ACTIONS REQUIRED

1. **Isolate Workstation:** Disconnect 10.0.4.10 from network immediately
2. **Preserve Evidence:** Capture full packet streams and disk image
3. **Hunt for Malware:** Scan system for known C2 malware families (check DNS query timing patterns and beacon IPs against malware databases)
4. **Lateral Movement Assessment:** Review logs for any outbound RDP, SMB, or SSH from 10.0.4.10 to other internal systems
5. **User Notification:** Interview workstation user about recent suspicious activity or credential compromise
6. **Threat Intelligence:** Cross-reference IPs with known threat databases (Shodan, GreyNoise, etc.)

---

## CONCLUSION

Workstation 10.0.4.10 is **actively compromised** with confirmed C2 beacon activity. The regular beacon pattern, explicitly named malicious domain, and multiple C2 endpoints indicate either a sophisticated attack or proof-of-concept testing. Immediate containment and forensic analysis are required.

**Recommended Status:** CRITICAL INCIDENT - Escalate immediately to IR team
