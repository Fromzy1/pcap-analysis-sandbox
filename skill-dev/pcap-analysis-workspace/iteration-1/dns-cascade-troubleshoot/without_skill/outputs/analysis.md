# 502 Bad Gateway Root Cause Analysis

## Summary
**Both DNS and backend issues are present, but the DNS problems are NOT the cause of the 502 errors.** The backend (10.0.3.5) is consistently returning 502 Bad Gateway responses regardless of DNS resolution success.

## Detailed Findings

### DNS Resolution Issues
The capture shows a DNS resolution cascade pattern:

1. **Successful DNS resolutions:**
   - `api.prod.example.com` → 10.0.3.5 ✓
   - `auth.prod.example.com` → 10.0.3.5 ✓

2. **Failed DNS resolutions (NXDOMAIN - "No such name"):**
   - `newsvc.prod.example.com` → NXDOMAIN
   - `v2.newsvc.prod.example.com` → NXDOMAIN
   - `internal.newsvc.prod.example.com` → NXDOMAIN

The DNS cascade suggests the checkout service is attempting to resolve multiple backend service names in sequence (possibly service discovery or failover logic). Three domains don't exist in DNS.

### Backend Issues (The Real Problem)
Despite successful DNS resolution to 10.0.3.5 for `api.prod.example.com`, the backend server returns **502 Bad Gateway** on every HTTP request:

- **Request 1** (t=0.120s): GET /api/orders → 502 Bad Gateway (t=0.170s)
- **Request 2** (t=0.470s): GET /api/orders → 502 Bad Gateway (t=0.520s)  
- **Request 3** (t=0.819s): GET /api/orders → 502 Bad Gateway (t=0.869s)

### Timeline Analysis
```
t=0.000-0.060s: DNS queries and responses (cascade through multiple domains)
t=0.070-0.110s: TCP 3-way handshake with 10.0.3.5
t=0.120s:       GET /api/orders request sent
t=0.170s:       502 Bad Gateway response received
t=0.180-0.200s: Connection cleanup (FIN-ACK)
[Pattern repeats 2 more times]
```

The backend server is accepting TCP connections (3-way handshake completes) but responding with 502 to application requests.

## Root Cause

**Primary Issue: Backend Service Failure**
- The backend server at 10.0.3.5 is responding with 502 Bad Gateway
- This indicates either:
  - An upstream proxy/gateway misconfiguration
  - A backend application server that's down/crashing
  - A misconfigured load balancer between the reverse proxy and actual backend
  - Application service startup failure or crashes

**Secondary Issue: DNS Cascading (Non-Critical)**
- The checkout service performs DNS lookups for multiple service names
- Three names consistently fail with NXDOMAIN
- This doesn't affect the 502 errors since connections to the resolved IPs are attempted

## Recommendations

1. **Immediate:** Investigate the backend service at 10.0.3.5
   - Check service logs for startup errors or crashes
   - Verify if it's actually running and listening
   - If it's a reverse proxy (nginx, HAProxy, etc.), check upstream backend configuration

2. **Secondary:** Clean up unused DNS entries
   - Remove or comment out the non-existent domains from service discovery
   - This won't fix the 502 but will reduce unnecessary DNS traffic

3. **Testing:** Monitor the backend service restart and verify 502 errors clear

## Conclusion
**This is a backend service problem, not a DNS problem.** The 502 errors persist despite successful DNS resolution. Focus incident response on the backend service health and configuration at 10.0.3.5.
