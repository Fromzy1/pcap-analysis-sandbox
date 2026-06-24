#!/usr/bin/env bash
# check_env.sh — probe what packet-analysis tools are available and print a
# concise status report. Exits 0 on success regardless of tier so the caller
# can decide how to proceed.
#
# Looks for (in this order of preference):
#   Tier 1: a pcap_analysis_sandbox folder nearby (activate.sh + .venv + debs)
#   Tier 2: system tshark (+ optional Python libs)
#   Tier 3: Python libs only (scapy / pyshark / dpkt) — pyshark needs tshark so effectively scapy+dpkt
#   Tier 4: nothing — print install suggestions
#
# Usage:  bash scripts/check_env.sh
#
# Search paths for the sandbox, in order:
#   $PCAP_SANDBOX (env var, if set)
#   ./pcap_analysis_sandbox
#   ../pcap_analysis_sandbox
#   ../../pcap_analysis_sandbox
#   $HOME/pcap_analysis_sandbox
#   whichever folder is currently mounted in this Cowork session (if any)

set -u

# -------- sandbox discovery -------------------------------------------------
_candidates=(
    "${PCAP_SANDBOX:-}"
    "."                                 # am I standing in a sandbox?
    ".."
    "./pcap_analysis_sandbox"
    "../pcap_analysis_sandbox"
    "../../pcap_analysis_sandbox"
    "$HOME/pcap_analysis_sandbox"
)
# If VIRTUAL_ENV is already set (e.g. after sourcing activate.sh), check whether
# its parent directory is a sandbox.
if [ -n "${VIRTUAL_ENV:-}" ]; then
    _candidates+=("$(dirname "$VIRTUAL_ENV")")
fi
# Also consider any directory in the current working tree that contains activate.sh + .venv + debs
# (shallow scan — don't traverse the whole filesystem)
for dir in "$PWD"/* "$PWD"/../*; do
    [ -d "$dir" ] && _candidates+=("$dir")
done

found_sandbox=""
for c in "${_candidates[@]}"; do
    [ -z "$c" ] && continue
    if [ -f "$c/activate.sh" ] && [ -d "$c/.venv" ] && [ -d "$c/debs" ]; then
        found_sandbox="$(cd "$c" && pwd)"
        break
    fi
done

# -------- system tools ------------------------------------------------------
have_tshark=0; have_capinfos=0; have_editcap=0
have_tcpflow=0; have_tcptrace=0; have_tcpreplay=0; have_ngrep=0
command -v tshark    >/dev/null 2>&1 && have_tshark=1
command -v capinfos  >/dev/null 2>&1 && have_capinfos=1
command -v editcap   >/dev/null 2>&1 && have_editcap=1
command -v tcpflow   >/dev/null 2>&1 && have_tcpflow=1
command -v tcptrace  >/dev/null 2>&1 && have_tcptrace=1
command -v tcpreplay >/dev/null 2>&1 && have_tcpreplay=1
command -v ngrep     >/dev/null 2>&1 && have_ngrep=1

# -------- Python libs -------------------------------------------------------
have_python=0; have_scapy=0; have_pyshark=0; have_dpkt=0; have_pandas=0; have_duckdb=0
if command -v python3 >/dev/null 2>&1; then
    have_python=1
    python3 -c 'import scapy'   >/dev/null 2>&1 && have_scapy=1
    python3 -c 'import pyshark' >/dev/null 2>&1 && have_pyshark=1
    python3 -c 'import dpkt'    >/dev/null 2>&1 && have_dpkt=1
    python3 -c 'import pandas'  >/dev/null 2>&1 && have_pandas=1
    python3 -c 'import duckdb'  >/dev/null 2>&1 && have_duckdb=1
fi

# -------- decide tier -------------------------------------------------------
tier=4
if [ -n "$found_sandbox" ]; then
    tier=1
elif [ $have_tshark -eq 1 ]; then
    tier=2
elif [ $have_python -eq 1 ] && { [ $have_scapy -eq 1 ] || [ $have_dpkt -eq 1 ]; }; then
    tier=3
fi

# -------- report ------------------------------------------------------------
yn() { [ "$1" = "1" ] && echo "yes" || echo "no"; }

cat <<EOF
=== pcap-analysis environment check ===

Tier: $tier

Sandbox:   ${found_sandbox:-not found}
CLI tools:
  tshark     : $(yn $have_tshark)
  capinfos   : $(yn $have_capinfos)
  editcap    : $(yn $have_editcap)
  tcpflow    : $(yn $have_tcpflow)
  tcptrace   : $(yn $have_tcptrace)
  tcpreplay  : $(yn $have_tcpreplay)
  ngrep      : $(yn $have_ngrep)
Python libs:
  scapy      : $(yn $have_scapy)
  pyshark    : $(yn $have_pyshark)
  dpkt       : $(yn $have_dpkt)
  pandas     : $(yn $have_pandas)
  duckdb     : $(yn $have_duckdb)

EOF

case $tier in
    1)
        echo "Recommended next step:"
        echo "  source \"$found_sandbox/activate.sh\""
        ;;
    2)
        echo "tshark is on PATH. Full shell-based workflow works."
        echo "Optional: install Python libs for flow parquet / duckdb analysis:"
        echo "  pip install scapy pyshark dpkt pandas duckdb"
        ;;
    3)
        echo "Python dissection is available (scapy/dpkt). No tshark — skip the"
        echo "shell recipes and use Python. Install tshark for the full workflow:"
        echo "  sudo apt install tshark    # Debian/Ubuntu"
        echo "  brew install wireshark     # macOS"
        ;;
    4)
        echo "No pcap tools detected. Pick one of:"
        echo ""
        echo "  A) Set up the pcap_analysis_sandbox (recommended, no sudo needed)"
        echo "     - unzip the sandbox or ask the skill to bootstrap one"
        echo ""
        echo "  B) System install (requires sudo):"
        echo "     sudo apt install tshark tcpreplay tcpflow ngrep    # Ubuntu/Debian"
        echo "     brew install wireshark tcpreplay tcpflow ngrep     # macOS"
        echo ""
        echo "  C) Python-only (no sudo):"
        echo "     uv venv && source .venv/bin/activate"
        echo "     uv pip install scapy pyshark dpkt pandas duckdb"
        echo "     (note: pyshark still needs tshark binary installed separately)"
        ;;
esac

# Exit 0 even for tier 4 — the caller inspects the output.
exit 0
