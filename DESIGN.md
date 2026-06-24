# Design notes — pcap-analysis skill

How this skill is built and why. It is a [Claude Code Agent Skill](https://docs.claude.com/en/docs/claude-code/skills):
a `SKILL.md` plus bundled scripts and reference playbooks that Claude loads on
demand. This doc covers the architecture, the design decisions behind it, and how
the skill was evaluated.

## The problem

> Packet captures are cheap to collect and expensive to misread. The failure mode
> is predictable: open the pcap, eyeball a few packets, form a theory too early,
> and build the rest of the analysis around that theory.
> — `skill-dev/pcap-analysis/SKILL.md`

The skill exists to counter that failure mode. Its stance is **triage first,
hypothesize second, write the evidence down** — so the answer has receipts and a
second engineer can reproduce every claim.

## Architecture: progressive disclosure

The skill is layered so that only what's needed enters the model's context:

| Layer | File(s) | Role |
|-------|---------|------|
| Orchestrator | `SKILL.md` | Always loaded. Operating principles, the 6-step workflow, routing, guardrails. |
| Tactical scripts | `scripts/check_env.sh`, `triage.sh`, `flows_to_parquet.py` | Deterministic work shelled out instead of described prose-by-prose. |
| Playbooks | `references/troubleshooting.md`, `security.md`, `tshark-recipes.md`, `report-template.md` | Loaded **on demand** when the workflow routes to them. |

The reference docs are compact checklists, not tutorials — the skill is explicit
that the model should *"use them as your checklist"* rather than dump their
contents into the report. The point: keep the context lean and the analyst's
reasoning visible, and push repeatable mechanics into scripts that produce
paste-ready output rather than re-deriving them each run.

## Graceful degradation (Tier 1–4)

A packet analysis is only as good as the tools on hand, so the skill probes the
environment first (`scripts/check_env.sh`) and adapts instead of assuming:

- **Tier 1 — full sandbox:** `tshark` + the full CLI suite + Python (scapy,
  pyshark, dpkt, pandas, duckdb). Every recipe available.
- **Tier 2 — system `tshark` only:** shell recipes work; Python/duckdb steps
  (beaconing periodicity, parquet export) are skipped or substituted with
  `tshark -qz io,stat`.
- **Tier 3 — Python libs only:** dissect with scapy/dpkt; the lost capabilities
  (expert info, decryption, object export) are **noted in the report's appendix**.
- **Tier 4 — nothing:** stop and hand the user a one-liner to reach Tier 1/2/3.
  *"Don't try to analyze the pcap from memory or guess at contents."*

Degrading explicitly — and recording the limitation — is itself part of the
evidence discipline.

## Dual-mode routing

The same capture answers different questions, so the workflow picks a lane early:

- **Troubleshooting** (*"slow", "timing out", "resets", "can't connect"*) →
  `references/troubleshooting.md`, which works up from TCP health.
- **Security / IR** (*"beaconing", "exfil", "C2", "IOCs"*) →
  `references/security.md`, which starts from investigation scope.

If both apply, *"do performance first (faster to confirm or dismiss) then
security."* The two examples in [`examples/`](examples/) show each lane; the
benchmark runs both.

## Evidence discipline

The non-negotiable that shapes every output:

> Cite packets the way you'd cite sources. Findings reference frame numbers,
> timestamps, 5-tuple, and a filter. **A sentence without a filter behind it is a
> guess.** — `SKILL.md`, operating principle 4

Concretely, the report template enforces: a severity tag per finding, an evidence
block with the re-runnable `tshark -Y` filter and frame numbers, UTC-first
timestamps with capture-relative offsets, and "root cause" labelled a *hypothesis*
unless there's end-to-end evidence. The deliverable is a file, not a chat reply,
so the work is reproducible by a peer.

## Knowing when to stop

The skill defines explicit step-back conditions rather than producing confident
output regardless: no pcap in hand, an encrypted capture when the question needs
app-layer content, a truncated/corrupt capture, or a question that's really about
a live system (redirect to live capture, don't fake it from a stale trace). Not
answering is sometimes the correct answer.

## How it was evaluated

The benchmark in [`examples/before-after-benchmark.md`](examples/before-after-benchmark.md)
is real evidence, not a claim. The harness lives in
[`skill-dev/pcap-analysis-workspace/`](skill-dev/pcap-analysis-workspace/) and has
three parts:

1. **Synthetic captures with known ground truth.**
   `skill-dev/pcap-analysis/evals/make_test_pcaps.py` generates the test pcaps with
   Scapy. They embed *signals, not byte-level realism*: a 120 ms RTT with dropped-
   then-retransmitted segments and a zero-window stall; a DNS cascade where some
   names NXDOMAIN and a resolved backend still returns 502; and a C2 beacon at
   **60 s ± 1.5 s jitter** alongside a **benign decoy host** that a careless
   analyst would mis-flag. The RNG is seeded, so the captures — and their ground
   truth — are reproducible.

2. **With-skill vs without-skill runs.** Each scenario is run both ways, same
   model, same prompt, to isolate the skill's contribution.

3. **Deterministic grading — no LLM judge.** `grade.py` scores each report with
   plain Python/regex predicates against fixed assertions (e.g. *names the failing
   domains*, *cites ≥3 frame numbers*, *includes an IOC table*). One predicate,
   `example_ip_falsely_flagged`, scans a ±2-line window around the benign decoy IP
   and only fails the run if it's *actively* labelled malicious without a nearby
   "benign/connectivity-canary" rescue — which is exactly the false positive the
   baseline produced. Grading is objective and re-runnable.

Result: **100% (±0) with the skill vs 80% (±8) without**, across three scenarios,
three runs each. The full per-assertion breakdown renders in `iteration-1-review.html`.

## Trade-offs (honest)

- **Cost vs correctness.** The skill spends roughly 2× the time and tokens of an
  unaided run (triage, targeted filters, a structured report). That's the price of
  reproducibility; for a quick "what's in here?" glance, the unaided model is fine.
- **Deterministic grading over LLM-as-judge.** Regex predicates can't assess prose
  quality, but they're objective, fast, and free of grader drift — the right call
  when the goal is a *trustworthy* pass/fail signal.
- **Synthetic captures over real traffic.** Real captures are messier and more
  convincing, but synthetic ones are shareable (no PII) and have exact ground
  truth, which is what makes the grader meaningful.

## Repo map

| Path | What |
|------|------|
| [`skill-dev/pcap-analysis/`](skill-dev/pcap-analysis/) | The skill itself (SKILL.md, scripts, references, evals). Packaged as `pcap-analysis.skill`. |
| [`examples/`](examples/) | Three worked examples + the before/after benchmark. |
| [`skill-dev/pcap-analysis-workspace/`](skill-dev/pcap-analysis-workspace/) | The eval harness: `grade.py`, the HTML review report, graded run outputs. |
| [`pcaps/`](pcaps/) | The synthetic sample captures. |
| [`SETUP.md`](SETUP.md) | How to run the sandbox locally. |
