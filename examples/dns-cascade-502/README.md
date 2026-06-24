# Example: 502s — DNS or backend? (performance / RCA)

**Angle:** performance root-cause — separate a DNS failure from an application failure.
**Sample capture:** [`../../pcaps/eval-dns-cascade.pcap`](../../pcaps/eval-dns-cascade.pcap) (3.1 KB, checkout host)
**Full report the skill produced:** [`analysis.md`](analysis.md)

## The question asked

> Ops is getting 502 errors from our checkout service and nobody knows why.
> Here's the capture from the checkout host: `pcaps/eval-dns-cascade.pcap`. Is
> this a DNS problem, a backend problem, or both? I need a short writeup for the
> incident ticket.

## Headline result

**Both — and the report keeps them straight.** The resolver returns **NXDOMAIN**
for three backend names (`newsvc.prod.example.com`, `v2.newsvc.prod.example.com`,
`internal.newsvc.prod.example.com`), while names that *do* resolve still get
**HTTP 502 Bad Gateway** from the backend at `10.0.3.5`. The writeup names the
failing domains, the backend IP, cites the frame numbers, and distinguishes
"DNS failed" from "the backend that answered is broken" — exactly the
correlation-vs-causation call an incident ticket needs.

## Reproduce it

```sh
source ./activate.sh
bash skill-dev/pcap-analysis/scripts/triage.sh pcaps/eval-dns-cascade.pcap
# then ask Claude (with the pcap-analysis skill) the question above
```

See the failures directly:

```sh
# NXDOMAIN responses (rcode 3) and the names that failed
tshark -r pcaps/eval-dns-cascade.pcap -Y "dns.flags.rcode==3" \
  -T fields -e frame.number -e dns.qry.name

# HTTP 502s and who returned them
tshark -r pcaps/eval-dns-cascade.pcap -Y "http.response.code==502" \
  -T fields -e frame.number -e ip.src
```
