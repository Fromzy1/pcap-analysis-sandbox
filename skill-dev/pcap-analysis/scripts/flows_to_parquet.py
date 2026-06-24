#!/usr/bin/env python3
"""
flows_to_parquet.py — extract a flat, typed flow table from a pcap into Parquet.

Calls tshark under the hood and writes a columnar file you can query with duckdb
or pandas. Useful for captures where analysis is easier in SQL than in
filter-and-eyeball mode (beaconing detection, periodicity, volume ranking).

Usage:
    python flows_to_parquet.py <pcap> <out.parquet> [--display-filter "expr"]

Columns emitted (best-effort — missing values are null, not empty string):
    frame_number, ts (epoch seconds, float64),
    ip_src, ip_dst, sport, dport, proto,
    bytes, tcp_flags, tcp_stream,
    sni, http_host, http_uri, http_method, http_status,
    dns_qname, dns_qtype, dns_rcode

Designed to be run from inside the pcap_analysis_sandbox venv:
    source /sessions/sweet-trusting-darwin/mnt/pcap_analysis_sandbox/activate.sh
    python flows_to_parquet.py pcaps/foo.pcap pcaps/foo.flows.parquet
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from io import StringIO

import pandas as pd

FIELDS: list[tuple[str, str, str]] = [
    # (tshark field, pandas column, pandas dtype)
    ("frame.number",                         "frame_number", "Int64"),
    ("frame.time_epoch",                     "ts",           "float64"),
    ("ip.src",                               "ip_src",       "string"),
    ("ip.dst",                               "ip_dst",       "string"),
    ("tcp.srcport",                          "tcp_sport",    "Int32"),
    ("tcp.dstport",                          "tcp_dport",    "Int32"),
    ("udp.srcport",                          "udp_sport",    "Int32"),
    ("udp.dstport",                          "udp_dport",    "Int32"),
    ("_ws.col.Protocol",                     "proto",        "string"),
    ("frame.len",                            "bytes",        "Int64"),
    ("tcp.flags.str",                        "tcp_flags",    "string"),
    ("tcp.stream",                           "tcp_stream",   "Int64"),
    ("tls.handshake.extensions_server_name", "sni",          "string"),
    ("http.host",                            "http_host",    "string"),
    ("http.request.uri",                     "http_uri",     "string"),
    ("http.request.method",                  "http_method",  "string"),
    ("http.response.code",                   "http_status",  "Int32"),
    ("dns.qry.name",                         "dns_qname",    "string"),
    ("dns.qry.type",                         "dns_qtype",    "Int32"),
    ("dns.flags.rcode",                      "dns_rcode",    "Int32"),
]


def build_tshark_cmd(pcap: str, display_filter: str | None) -> list[str]:
    cmd = [
        "tshark", "-r", pcap, "-n",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "header=y",
        "-E", "occurrence=f",  # first occurrence only for multi-valued fields
    ]
    for f, _, _ in FIELDS:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    return cmd


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("out_parquet")
    ap.add_argument("--display-filter", default=None,
                    help="optional tshark -Y expression to narrow the slice")
    args = ap.parse_args()

    if not shutil.which("tshark"):
        print("tshark not on PATH. source the pcap_analysis_sandbox activate.sh first.",
              file=sys.stderr)
        return 3

    cmd = build_tshark_cmd(args.pcap, args.display_filter)
    print("running:", " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        return proc.returncode

    df = pd.read_csv(
        StringIO(proc.stdout),
        sep="\t",
        header=0,
        names=[col for _, col, _ in FIELDS],  # rename inline
        dtype={col: "string" for _, col, _ in FIELDS},  # read as string, coerce below
        keep_default_na=False,
        na_values=[""],
        engine="c",
    )

    # Coerce to typed columns.
    for _, col, dtype in FIELDS:
        if dtype == "float64":
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("float64")
        elif dtype.startswith("Int"):
            df[col] = pd.to_numeric(df[col], errors="coerce").astype(dtype)
        # else: leave as string

    # Consolidate port columns.
    df["sport"] = df["tcp_sport"].combine_first(df["udp_sport"])
    df["dport"] = df["tcp_dport"].combine_first(df["udp_dport"])
    df = df.drop(columns=["tcp_sport", "tcp_dport", "udp_sport", "udp_dport"])

    # Re-order for readability.
    ordered = [
        "frame_number", "ts", "ip_src", "ip_dst", "sport", "dport", "proto",
        "bytes", "tcp_flags", "tcp_stream",
        "sni", "http_host", "http_uri", "http_method", "http_status",
        "dns_qname", "dns_qtype", "dns_rcode",
    ]
    df = df[ordered]

    df.to_parquet(args.out_parquet, index=False)
    print(f"wrote {len(df):,} rows -> {args.out_parquet}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
