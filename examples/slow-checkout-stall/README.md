# Example: checkout hangs for seconds (performance / RCA)

**Angle:** performance root-cause — is it TCP, the network, or the app?
**Sample capture:** [`../../pcaps/eval-slow-app.pcap`](../../pcaps/eval-slow-app.pcap) (33 KB, client-side)
**Full report the skill produced:** [`analysis.md`](analysis.md)

## The question asked

> Customers have been complaining that our checkout page hangs for several
> seconds before completing. I grabbed a short client-side capture during one of
> the slow moments — it's at `pcaps/eval-slow-app.pcap`. Can you tell me what's
> going on and what to do about it? A written analysis I can hand to our network
> team would be ideal.

## Headline result

The stall is **client-side TCP receive-buffer starvation**, not the network. The
client advertises a **zero window at frame 37** (t+0.866s), right after the
server retransmitted two 1400-byte segments — halting the response stream until
the client drains its buffer. The report pins it to a specific frame, gives the
exact filter to re-run, and proposes concrete next steps (the client app isn't
reading fast enough), rather than vaguely blaming "the network."

## Reproduce it

```sh
source ./activate.sh
bash skill-dev/pcap-analysis/scripts/triage.sh pcaps/eval-slow-app.pcap
# then ask Claude (with the pcap-analysis skill) the question above
```

The zero-window stall and retransmits, directly:

```sh
tshark -r pcaps/eval-slow-app.pcap \
  -Y "tcp.analysis.zero_window || tcp.analysis.retransmission" \
  -T fields -e frame.number -e frame.time_relative -e tcp.analysis.flags
```
