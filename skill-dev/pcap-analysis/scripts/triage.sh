#!/usr/bin/env bash
# triage.sh — one-shot triage for a packet capture.
# Prints a Markdown block suitable for pasting into a pcap-analysis report.
#
# Usage:
#   triage.sh <pcap>
#
# Designed for the pcap_analysis_sandbox environment but will run anywhere
# tshark and capinfos are on PATH. Runs in a few seconds on captures up
# to a few hundred MB; for larger captures, slice with editcap first.
set -euo pipefail

pcap=${1:-}
if [[ -z "$pcap" || ! -r "$pcap" ]]; then
  echo "usage: $0 <pcap>" >&2
  exit 2
fi

for bin in capinfos tshark; do
  command -v "$bin" >/dev/null 2>&1 || {
    echo "error: '$bin' is not on PATH." >&2
    echo "Run 'bash scripts/check_env.sh' to see what's available and how to fix it." >&2
    exit 3
  }
done

sha=$(sha256sum "$pcap" | awk '{print $1}')
size=$(du -h "$pcap" | awk '{print $1}')

section() { printf '\n### %s\n\n```\n' "$1"; }
endsec()  { printf '```\n'; }

cat <<EOF
## Capture overview

- **File:** \`$pcap\` ($size)
- **SHA256:** \`$sha\`
EOF

section "capinfos"
capinfos "$pcap" 2>&1 | sed -e 's/^/  /'
endsec

section "tshark -qz io,phs (protocol hierarchy)"
tshark -r "$pcap" -qz io,phs 2>&1 | sed -n '/^===/,$p' | head -120
endsec

section "tshark -qz conv,ip (top IP conversations — first 20)"
tshark -r "$pcap" -qz conv,ip 2>&1 | head -25
endsec

section "tshark -qz conv,tcp (top TCP conversations — first 20)"
tshark -r "$pcap" -qz conv,tcp 2>&1 | head -25 || true
endsec

section "tshark -qz conv,udp (top UDP conversations — first 20)"
tshark -r "$pcap" -qz conv,udp 2>&1 | head -25 || true
endsec

section "tshark -qz expert (expert info summary)"
tshark -r "$pcap" -qz expert 2>&1 | head -80 || true
endsec

# If DNS is present, show tree; same for HTTP / TLS alerts
if tshark -r "$pcap" -Y "dns" -c 1 >/dev/null 2>&1; then
  section "tshark -qz dns,tree (DNS overview)"
  tshark -r "$pcap" -qz dns,tree 2>&1 | head -80 || true
  endsec
fi

if tshark -r "$pcap" -Y "http" -c 1 >/dev/null 2>&1; then
  section "tshark -qz http,tree (HTTP overview)"
  tshark -r "$pcap" -qz http,tree 2>&1 | head -80 || true
  endsec
fi

if tshark -r "$pcap" -Y "tls.alert_message" -c 1 >/dev/null 2>&1; then
  section "TLS alerts (tshark -Y tls.alert_message)"
  tshark -r "$pcap" -Y "tls.alert_message" -T fields \
    -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
    -e tls.alert_message.level -e tls.alert_message.desc 2>&1 | head -40 || true
  endsec
fi

# Retransmits / resets quick counts
section "TCP anomaly counts"
printf 'retransmissions: '; tshark -r "$pcap" -Y "tcp.analysis.retransmission" -T fields -e frame.number 2>/dev/null | wc -l
printf 'duplicate ACKs : '; tshark -r "$pcap" -Y "tcp.analysis.duplicate_ack" -T fields -e frame.number 2>/dev/null | wc -l
printf 'zero windows   : '; tshark -r "$pcap" -Y "tcp.analysis.zero_window"   -T fields -e frame.number 2>/dev/null | wc -l
printf 'window full    : '; tshark -r "$pcap" -Y "tcp.analysis.window_full"   -T fields -e frame.number 2>/dev/null | wc -l
printf 'RSTs           : '; tshark -r "$pcap" -Y "tcp.flags.reset==1"         -T fields -e frame.number 2>/dev/null | wc -l
printf 'unanswered SYNs: '; {
  tshark -r "$pcap" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e tcp.stream 2>/dev/null | sort -u > /tmp/_syn.$$ || true
  tshark -r "$pcap" -Y "tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e tcp.stream 2>/dev/null | sort -u > /tmp/_synack.$$ || true
  comm -23 /tmp/_syn.$$ /tmp/_synack.$$ 2>/dev/null | wc -l
  rm -f /tmp/_syn.$$ /tmp/_synack.$$
}
endsec

# IO stat — let tshark pick ~10 buckets across the capture window
dur=$(capinfos -u "$pcap" 2>/dev/null | awk -F': *' '/Capture duration/ {print int($2); exit}')
if [[ -n "${dur:-}" && "$dur" -gt 0 ]]; then
  step=$(( dur / 10 ))
  [[ $step -lt 1 ]] && step=1
  section "tshark -qz io,stat,$step (throughput timeline, 10 buckets)"
  tshark -r "$pcap" -qz "io,stat,$step" 2>&1 | sed -n '/===/,$p' | head -30
  endsec
fi

echo
echo "_End triage._"
