# Setup — running the sandbox locally

A self-contained pcap analysis workbench: the native CLI tools and Python
libraries the skill expects, installed without root.

## Quick start

```sh
cd pcap_analysis_sandbox
source ./activate.sh
tshark -v
python -c "import pyshark, scapy, dpkt, nfstream; print('ok')"
```

Put `.pcap` / `.pcapng` files under `./pcaps/` and notebooks under `./notebooks/`.

## What's installed

### Native CLI (Ubuntu 22.04 arm64 debs, extracted without root)

| Binary        | Source package     | Use                                         |
|---------------|--------------------|---------------------------------------------|
| `tshark`      | `tshark`           | CLI Wireshark — read/filter/slice pcaps     |
| `editcap`     | `wireshark-common` | Split, truncate, rewrite timestamps         |
| `mergecap`    | `wireshark-common` | Merge multiple captures                     |
| `capinfos`    | `wireshark-common` | Metadata: times, packet counts, hashes      |
| `reordercap`  | `wireshark-common` | Fix packet order by timestamp               |
| `dumpcap`     | `wireshark-common` | Low-level live capture front-end            |
| `rawshark`    | `wireshark-common` | Dissector in field-extraction mode          |
| `text2pcap`   | `wireshark-common` | Convert ASCII hex dumps back to pcap        |
| `tcpdump`     | `tcpdump`          | The classic                                 |
| `tcpreplay`   | `tcpreplay`        | Replay pcaps to an interface                |
| `tcprewrite`  | `tcpreplay`        | Rewrite headers (MAC, IP, ports)            |
| `tcpprep`     | `tcpreplay`        | Build a tcpreplay cache file                |
| `tcpflow`     | `tcpflow`          | Reassemble TCP streams to files             |
| `tcptrace`    | `tcptrace`         | Connection stats, RTT, retransmit view      |
| `ngrep`       | `ngrep`            | grep across packet payloads                 |
| `jq`          | (system)           | JSON handling for `tshark -T json`/`ek`     |

### Python (uv venv at `./.venv`, Python 3.12)

| Package      | Notes                                                |
|--------------|------------------------------------------------------|
| `scapy`      | Packet crafting & dissection                         |
| `pyshark`    | Python wrapper around tshark (full dissector tree)   |
| `dpkt`       | Fast lightweight parsing                             |
| `pypacker`   | Lightweight packet parsing / crafting                |
| `nfstream`   | Flow extraction, ndpi-backed app classification      |
| `pandas`     | Dataframes for flow/transaction analysis             |
| `polars`     | Fast columnar dataframes                             |
| `pyarrow`    | Parquet/feather I/O for bigger datasets              |
| `duckdb`     | In-process SQL over pcap-derived tables              |
| `matplotlib` | Plotting                                             |
| `jupyterlab` | Notebook UI                                          |
| `ipykernel`, `tqdm`, `rich` | QoL                                   |

## Layout

```
pcap_analysis_sandbox/
├── activate.sh          # source this to enter the env
├── README.md            # project overview
├── DESIGN.md            # architecture & design notes
├── SETUP.md             # this file
├── examples/            # worked examples + benchmark
├── skill-dev/           # the skill itself + eval harness
├── bin/                 # micromamba (kept in case of future conda installs)
├── debs/                # .deb archives — the persistent source of truth
├── .venv/               # uv-managed Python env (persistent)
├── cache/               # uv + conda caches (safe to nuke)
├── pcaps/               # drop captures here
└── notebooks/           # Jupyter notebooks
```

On first activation each session, `activate.sh` re-extracts the debs to
`/sessions/sweet-trusting-darwin/opt` (ext4 scratch, ~instant). That path
is NOT persistent between sessions — the sandbox lives on a virtiofs
mount that rejects some deb permissions, so the archives stay in `debs/`
and the extracted tree is rebuilt on demand.

## What's intentionally NOT installed

These were on the original wish list but excluded from the "lean" install:

- **Zeek**, **Suricata** — large (100+ MB each); add later if you want
  protocol logs or IDS alerts. Available as jammy arm64 debs; extract with
  the same pattern (`apt-get download && dpkg-deb -x`).
- **bulk_extractor**, **foremost** — file-carving from payloads.
- **nfdump**, **SiLK**, **ntopng** — NetFlow-style aggregation.
- **captcp**, **xplot** — TCP visualization helpers.
- **dnstop**, **passivedns**, **sipgrep** — niche protocol views.
- **ClickHouse** — the Python side has `duckdb` covering the same
  "SQL over flat logs" use case without a running server.

To add one later:

```sh
cd pcap_analysis_sandbox/debs
apt-get download zeek suricata bulk-extractor   # plus their deps
# then re-source activate.sh
```

## Quick sanity smoke tests

```sh
source ./activate.sh

# Create a toy pcap with scapy
python - <<'PY'
from scapy.all import IP, TCP, Ether, wrpcap
pkts = [Ether()/IP(dst="10.0.0.1")/TCP(dport=80, flags="S") for _ in range(5)]
wrpcap("pcaps/smoke.pcap", pkts)
print("wrote pcaps/smoke.pcap")
PY

capinfos pcaps/smoke.pcap
tshark -r pcaps/smoke.pcap -T fields -e ip.src -e ip.dst -e tcp.flags
python -c "import pyshark; print(list(pyshark.FileCapture('pcaps/smoke.pcap'))[0])"
```
