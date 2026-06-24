# Does the skill actually help? — before/after benchmark

Each of the three example scenarios was run **with** the pcap-analysis skill and
**without** it (same model, same captures, same questions, 3 runs per
configuration), then graded by a deterministic, non-LLM checker against fixed
assertions (e.g. "names the failing domains", "cites ≥3 frame numbers", "includes
an IOC table", "does not flag the benign host as C2").

## Summary

| Metric | With skill | Without skill | Delta |
|--------|-----------|---------------|-------|
| **Pass rate** | **100% ± 0%** | 80% ± 8% | **+20 pts** |
| Time | 145s ± 25s | 61s ± 13s | +85s |
| Tokens | 64.6k ± 3.4k | 44.9k ± 4.8k | +19.6k |

The skill trades more time and tokens (it triages first, drills with filters, and
writes an evidence-backed report) for **complete, correct, reproducible** output.
The baseline is faster and cheaper but leaves gaps — and in one case is actively
misleading.

## Per-scenario pass rate

| Scenario | With skill | Without skill | What the baseline missed |
|----------|-----------|---------------|--------------------------|
| [slow-checkout-stall](slow-checkout-stall/) | 6/6 | 5/6 | No concrete re-runnable tshark filter |
| [dns-cascade-502](dns-cascade-502/) | 7/7 | 6/7 | No specific frame-number citations |
| [beacon-c2-detection](beacon-c2-detection/) | 7/7 | 5/7 | **False-positive C2 IOC** + missing frame citations |

## The most important gap: a false positive that pollutes the SIEM

In the beacon scenario, the without-skill run flagged `93.184.216.34`
(example.com) as a **"secondary C2 server"** — at the same severity as the real
beacon destination. That host is a benign connectivity check. Feeding that IOC
into a SIEM would generate noise, waste analyst time, and erode trust in the
alerting.

The with-skill run correctly **rescued** `93.184.216.34` as benign (a single
normal HTTPS session, not periodic) and reserved the IOC table for the genuine
indicator (`185.220.101.45` / `c2-check.examplebad.xyz`). Precision on what is
*not* malicious is as valuable as catching what is.

## Takeaway

For quick "what's in this pcap?" glances, an unaided model is fine. For
**investigations that feed a ticket, a SIEM, or a network team** — where a missed
frame citation or a false-positive IOC has real downstream cost — the skill's
discipline (triage → filter → evidence → report) is what gets you to 100%.

---

*Source data: `skill-dev/pcap-analysis-workspace/iteration-1/` (`benchmark.json`,
per-scenario `with_skill/` and `without_skill/` outputs). Grading is reproducible
via `skill-dev/pcap-analysis-workspace/grade.py`.*
