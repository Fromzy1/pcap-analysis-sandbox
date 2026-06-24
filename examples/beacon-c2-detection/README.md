# Example: C2 beacon detection (security / IR)

**Angle:** security incident response — find malicious behaviour and produce IOCs.
**Sample capture:** [`../../pcaps/eval-beacon.pcap`](../../pcaps/eval-beacon.pcap) (88 KB, ~20 min, switch span port)
**Full report the skill produced:** [`analysis.md`](analysis.md)

## The question asked

> SOC flagged workstation 10.0.4.10 for unusual behavior. I pulled a ~20 minute
> capture from their switch span port: `pcaps/eval-beacon.pcap`. Can you take a
> look and tell me if there's anything concerning? If so I need IOCs I can feed
> into our SIEM.

## Headline result

Textbook **C2 beaconing**: 20 near-identical HTTPS connections from `10.0.4.10`
to `185.220.101.45:443` at precise 60-second intervals (CV=0.016), each paired
with a DNS lookup for `c2-check.examplebad.xyz` and a uniform payload size. The
report ships a ready-to-ingest **IOC table** (malicious IP, domain, port/pattern)
and — importantly — does **not** flag the benign `93.184.216.34` (example.com)
connectivity check as a second C2 server. Recommended action: isolate the host,
preserve forensics, escalate to IR.

## Reproduce it

```sh
source ./activate.sh                                    # enter the sandbox env
bash skill-dev/pcap-analysis/scripts/triage.sh pcaps/eval-beacon.pcap
# then ask Claude (with the pcap-analysis skill) the question above
```

The beacon periodicity is easy to see directly:

```sh
# every beacon connection to the C2 destination, with timestamps
tshark -r pcaps/eval-beacon.pcap -Y "ip.dst==185.220.101.45 && tcp.flags.syn==1" \
  -T fields -e frame.number -e frame.time_relative
```
