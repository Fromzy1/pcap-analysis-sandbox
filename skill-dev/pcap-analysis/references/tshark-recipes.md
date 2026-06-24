# tshark recipe book

Short, copy-pasteable commands. Grouped by purpose. Assumes `tshark` is on PATH (the sandbox handles this via `activate.sh`).

## Capture metadata

```sh
capinfos pcap                                # size, time range, SHA256, encap, packet count
capinfos -M pcap                             # machine-readable
editcap -i 60 pcap out-chunk.pcap            # split into 60s chunks
editcap -A "2025-03-14 08:00:00" -B "2025-03-14 09:00:00" pcap window.pcap  # time window
mergecap -w merged.pcap a.pcap b.pcap        # merge (re-sort with reordercap)
reordercap messy.pcap ordered.pcap           # fix out-of-order timestamps
```

## Statistics modes (`-qz`)

```sh
tshark -r pcap -qz io,phs                    # protocol hierarchy — "what's in this trace"
tshark -r pcap -qz conv,ip                   # IP conversations (bytes per pair)
tshark -r pcap -qz conv,tcp                  # TCP conversations (with RTT if possible)
tshark -r pcap -qz conv,udp
tshark -r pcap -qz endpoints,ip              # by-endpoint stats
tshark -r pcap -qz expert                    # retransmits, malformed, warnings
tshark -r pcap -qz io,stat,60                # bytes/packets per 60s bucket
tshark -r pcap -qz io,stat,1,"COUNT(tcp.analysis.retransmission)tcp.analysis.retransmission"
tshark -r pcap -qz dns,tree
tshark -r pcap -qz http,tree
tshark -r pcap -qz http_req,tree
tshark -r pcap -qz smb2,srt                  # SMB2 service response times
tshark -r pcap -qz sip,stat
tshark -r pcap -qz rtp,streams
```

## Field extraction (`-T fields`)

Always pair with explicit `-e` fields. Use `-E separator=,` and `-E header=y` for CSV output.

```sh
tshark -r pcap -T fields -E separator=, -E header=y -E quote=d \
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.flags.str \
  -e _ws.col.Protocol > frames.csv
```

Useful per-protocol field sets:

```
# DNS
-e frame.time_epoch -e ip.src -e ip.dst -e dns.id -e dns.flags.response
-e dns.qry.name -e dns.qry.type -e dns.flags.rcode -e dns.a -e dns.time

# HTTP
-e frame.time_epoch -e ip.src -e ip.dst -e http.request.method
-e http.host -e http.request.uri -e http.user_agent
-e http.response.code -e http.content_type -e http.content_length

# TLS
-e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.type
-e tls.handshake.version -e tls.handshake.extensions_server_name
-e tls.handshake.ciphersuite -e tls.alert_message.desc
```

## JSON output for structured analysis

```sh
tshark -r pcap -T json -Y "dns" > dns.json            # full dissector tree
tshark -r pcap -T ek -Y "dns" > dns.ndjson            # elasticsearch-bulk, one line per packet
```

`jq` eats the `ek` format happily:

```sh
tshark -r pcap -T ek -Y "http.response" \
  | jq -c 'select(.layers.http != null) | {t:.timestamp, code:.layers.http["http_http_response_code"][0], uri:.layers.http["http_http_request_uri"][0]}'
```

## Display filters cheat sheet

```
ip.addr == 10.0.0.1 && !(tcp.port == 22)
tcp.stream == 37
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
tcp.analysis.zero_window || tcp.analysis.window_full
tcp.flags.syn==1 && tcp.flags.ack==0                 # SYNs
tcp.flags.reset==1                                   # RSTs
dns.flags.rcode == 3                                 # NXDOMAIN
dns.qry.name contains ".example.com"
tls.handshake.type == 1                              # ClientHello
tls.handshake.type == 11                             # Certificate
tls.alert_message
http.response.code >= 500
http.request.method == "POST"
frame.time_relative >= 30 && frame.time_relative <= 45
```

## Object extraction

```sh
tshark -r pcap --export-objects http,./out-http/
tshark -r pcap --export-objects smb,./out-smb/
tshark -r pcap --export-objects tftp,./out-tftp/
tshark -r pcap --export-objects dicom,./out-dicom/
```

For TCP payload reassembly outside of tshark:

```sh
tcpflow -r pcap -o ./flows/                          # one file per direction per flow
```

## ngrep (grep across payloads)

```sh
ngrep -I pcap -qt "User-Agent:"                     # any packet with "User-Agent:" in payload
ngrep -I pcap -qt 'POST ' 'port 80'                 # with a BPF filter
ngrep -I pcap -qt '' 'host 10.0.0.1 and port 443'
```

Use sparingly — fast for small captures, noisy on big ones. Combine with a display filter upstream:

```sh
tshark -r pcap -Y "http.request" -w - | ngrep -I - -qt "secret"
```

## Decrypting TLS

```sh
SSLKEYLOGFILE=/path/to/keys.log firefox              # capture the key log on the client
tshark -r pcap -o tls.keylog_file:/path/to/keys.log  # decrypt using it
```

## Export raw bytes of a single packet

```sh
tshark -r pcap -Y "frame.number == 42" -x
```

## Per-connection throughput and RTT without tshark

```sh
tcptrace -l pcap                                     # long-form, all connections
tcptrace -lxW pcap                                   # wide, shows RTT, retx, congestion
```

## One-off performance tips

- `-n` disables name resolution; faster and cleaner for analysis.
- `-2` forces two-pass dissection — needed for some reassembly stats but slower.
- For captures >1 GB, slice with `editcap` first (`-c` for packet count, `-A/-B` for time).
