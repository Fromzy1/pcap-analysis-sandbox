"""
Grade the iteration-1 runs. Writes grading.json next to each run's outputs.

Each assertion is checked with a deterministic Python predicate — no LLM grader
in the loop. This matches the skill-creator guidance to prefer scripts for
programmatically-checkable assertions.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ITER = Path(__file__).resolve().parent / "iteration-1"


def load_text(outputs_dir: Path) -> str:
    f = outputs_dir / "analysis.md"
    return f.read_text(encoding="utf-8") if f.exists() else ""


# ---------------------------------------------------------------------------
# predicates keyed by assertion id
# ---------------------------------------------------------------------------
def count_frames_cited(t: str) -> int:
    # 'frame 37', 'frame #37', 'Frame 5', 'frames 5, 6, 7', 'packet #21', '#21'
    ids = set()
    for m in re.finditer(r"(?:frame|packet)s?\s*#?\s*(\d+)", t, re.IGNORECASE):
        try:
            ids.add(int(m.group(1)))
        except ValueError:
            pass
    return len(ids)


def has_tshark_filter(t: str) -> bool:
    patterns = [
        r"tcp\.analysis\.",
        r"dns\.flags\.",
        r"http\.response\.code",
        r"tls\.handshake\.",
        r"tcp\.flags\.",
        r"ip\.addr\s*==",
        r"ip\.src\s*==",
        r"ip\.dst\s*==",
        r"tshark\s+-[rYzT]",
    ]
    return any(re.search(p, t) for p in patterns)


def has_structure(t: str) -> bool:
    headings = re.findall(r"^#{1,3}\s+\S", t, re.MULTILINE)
    has_summary = bool(re.search(r"^#{1,3}\s+(TL;DR|Summary|Executive summary)", t,
                                  re.IGNORECASE | re.MULTILINE))
    return len(headings) >= 3 and has_summary


def example_ip_falsely_flagged(t: str) -> bool:
    """
    True when 93.184.216.34 is *actively* labelled as C2 / malicious / to-be-blocked,
    not merely mentioned in the report. A good report either omits it or names it
    as a connectivity canary / benign.
    """
    # Active false-positive phrasings. These are the exact constructs the baseline used.
    active_bad = re.compile(
        r"(secondary\s+c2|primary\s+c2|"
        r"c2\s+server|c2\s+beacon|"
        r"malicious\s+(ip|host|destination)|"
        r"block\s*list|blocklist|"
        r"indicator\s+of\s+compromise)",
        re.IGNORECASE,
    )
    # Benign phrasings that *rescue* a mention of the IP.
    benign_rescue = re.compile(
        r"(benign|connectivity\s+canary|likely\s+example\.com|"
        r"not\s+(itself\s+)?(an\s+indicator|malicious)|"
        r"probably\s+(not|a\s+normal)|reserved\s+domain)",
        re.IGNORECASE,
    )
    lines = t.splitlines()
    for i, line in enumerate(lines):
        if "93.184.216.34" not in line:
            continue
        window = "\n".join(lines[max(0, i - 2):i + 3])
        if active_bad.search(window) and not benign_rescue.search(window):
            return True
    return False


def mentions_mitigation(t: str) -> bool:
    if re.search(r"^#{1,3}\s*(Recommend|Next steps|Mitigation|Action)",
                 t, re.IGNORECASE | re.MULTILINE):
        return True
    return bool(re.search(r"(check|verify|capture|rollback|restart|configure|isolate|block|escalate)",
                          t, re.IGNORECASE))


def addresses_both_issues(t: str) -> bool:
    mentions_dns_issue = bool(re.search(r"(NXDOMAIN|DNS (resolution|zone) .*(fail|issue|missing))",
                                        t, re.IGNORECASE))
    mentions_backend_issue = bool(re.search(r"(502|Bad Gateway|backend .*(fail|issue|error))", t))
    return mentions_dns_issue and mentions_backend_issue


PREDICATES = {
    "mentions_zero_window":          lambda t: bool(re.search(r"zero[- ]window", t, re.IGNORECASE)),
    "mentions_retransmit":           lambda t: bool(re.search(r"retransm", t, re.IGNORECASE)),
    "cites_frame_numbers":           lambda t: count_frames_cited(t) >= 3,
    "cites_specific_filter":         lambda t: has_tshark_filter(t),
    "has_mitigation_or_next_steps":  lambda t: mentions_mitigation(t),
    "report_has_structure":          lambda t: has_structure(t),
    "mentions_nxdomain":             lambda t: "NXDOMAIN" in t.upper() or "RCODE 3" in t.upper() or "RCODE=3" in t.upper(),
    "names_failing_domains":         lambda t: bool(re.search(r"newsvc\.(prod\.)?example\.com", t, re.IGNORECASE)),
    "identifies_http_502":           lambda t: bool(re.search(r"\b502\b.*(Bad Gateway|Gateway)?|Bad Gateway", t)),
    "names_backend_ip":              lambda t: "10.0.3.5" in t,
    "addresses_both_dns_and_backend": lambda t: addresses_both_issues(t),
    "identifies_beacon_dest_ip":     lambda t: "185.220.101.45" in t,
    "identifies_beacon_domain":      lambda t: "c2-check.examplebad.xyz" in t,
    "identifies_beacon_interval":    lambda t: bool(re.search(r"(60\s*(s|sec|second)|periodic|interval)", t, re.IGNORECASE))
                                              and bool(re.search(r"185\.220\.101\.45", t)),
    "includes_ioc_section":          lambda t: bool(re.search(r"IOC", t)) or bool(re.search(r"^#{1,3}.*indicator", t, re.MULTILINE | re.IGNORECASE)),
    "does_not_falsely_flag_example_ip": lambda t: not example_ip_falsely_flagged(t),
}


def grade_one(outputs_dir: Path, meta: dict) -> dict:
    text = load_text(outputs_dir)
    results = []
    for a in meta["assertions"]:
        aid = a["id"]
        desc = a["description"]
        pred = PREDICATES.get(aid)
        if pred is None:
            results.append({"text": desc, "passed": False, "evidence": f"no predicate for {aid}"})
            continue
        try:
            passed = bool(pred(text))
            evidence = f"predicate '{aid}' returned {passed} on {len(text)} chars of output"
        except Exception as e:
            passed = False
            evidence = f"predicate '{aid}' raised: {e}"
        results.append({"text": desc, "passed": passed, "evidence": evidence})

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    return {
        "eval_id": meta["eval_id"],
        "eval_name": meta["eval_name"],
        # aggregate_benchmark.py expects `summary: {pass_rate, passed, failed, total}`
        "summary": {
            "pass_rate": passed / total if total else 0.0,
            "passed": passed,
            "failed": total - passed,
            "total": total,
        },
        "expectations": results,
    }


def main() -> None:
    for eval_dir in sorted(ITER.iterdir()):
        if not eval_dir.is_dir():
            continue
        meta_path = eval_dir / "eval_metadata.json"
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text())
        for cfg in ("with_skill", "without_skill"):
            out_dir = eval_dir / cfg / "outputs"
            result = grade_one(out_dir, meta)
            result["configuration"] = cfg
            (eval_dir / cfg / "grading.json").write_text(json.dumps(result, indent=2))
            s = result["summary"]
            print(f"  {eval_dir.name}/{cfg}: {s['passed']}/{s['total']}")


if __name__ == "__main__":
    main()
