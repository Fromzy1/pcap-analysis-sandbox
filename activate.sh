# Source this file to enter the pcap analysis sandbox.
#
#   source ./activate.sh          # or
#   . ./activate.sh
#
# Safe to re-source. Prepends to PATH / LD_LIBRARY_PATH, activates the uv venv,
# and re-extracts the .deb tree into /sessions/.../opt if it got cleared between sessions.

# --- resolve this script's directory (bash / zsh compatible, sourced) ---
if [ -n "${BASH_SOURCE[0]:-}" ]; then
    _pcap_src="${BASH_SOURCE[0]}"
elif [ -n "${ZSH_VERSION:-}" ]; then
    _pcap_src="${(%):-%x}"
else
    _pcap_src="$0"
fi
PCAP_SANDBOX="$(cd "$(dirname "$_pcap_src")" && pwd)"
unset _pcap_src

# The native CLI tools live on ext4 scratch because the sandbox is on a
# bindfs/virtiofs mount that rejects some dpkg permissions. The .deb archives
# in $PCAP_SANDBOX/debs are the persistent source of truth — we re-extract
# if the scratch prefix is missing (new session).
PCAP_PREFIX="/sessions/sweet-trusting-darwin/opt"

if [ ! -x "$PCAP_PREFIX/usr/bin/tshark" ]; then
    echo "[pcap-sandbox] extracting .debs into $PCAP_PREFIX (first use of this session)..."
    mkdir -p "$PCAP_PREFIX"
    umask 0022
    for deb in "$PCAP_SANDBOX"/debs/*.deb; do
        dpkg-deb -x "$deb" "$PCAP_PREFIX" >/dev/null
    done
    # init.lua ships as a dangling symlink to /etc/wireshark/init.lua;
    # replace with an empty stub so tshark doesn't complain.
    rm -f "$PCAP_PREFIX/usr/share/wireshark/init.lua"
    mkdir -p "$PCAP_PREFIX/etc/wireshark"
    : > "$PCAP_PREFIX/etc/wireshark/init.lua"
    ln -sf "$PCAP_PREFIX/etc/wireshark/init.lua" \
           "$PCAP_PREFIX/usr/share/wireshark/init.lua"
fi

# Expose binaries + libs. Prepend so our tshark 3.6 wins over any system one.
export PATH="$PCAP_PREFIX/usr/bin:$PATH"
export LD_LIBRARY_PATH="$PCAP_PREFIX/usr/lib/aarch64-linux-gnu:$PCAP_PREFIX/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export WIRESHARK_DATA_DIR="$PCAP_PREFIX/usr/share/wireshark"

# Python venv (uv-managed).
# shellcheck disable=SC1091
. "$PCAP_SANDBOX/.venv/bin/activate"

# Friendly prompt hint.
export PS1="(pcap) ${PS1:-\$ }"

cat <<BANNER
[pcap-sandbox] ready
  prefix : $PCAP_PREFIX          (ext4 scratch, reset per session)
  sandbox: $PCAP_SANDBOX         (persistent)
  venv   : $VIRTUAL_ENV
  tshark : $(command -v tshark)
  python : $(command -v python)

Available CLI:
  tshark editcap mergecap capinfos reordercap  (from wireshark 3.6.2)
  tcpdump tcpreplay tcprewrite tcpflow tcptrace ngrep jq
Python libs:
  scapy, pyshark, dpkt, pypacker, nfstream, pandas, polars, pyarrow,
  duckdb, matplotlib, jupyterlab
BANNER
