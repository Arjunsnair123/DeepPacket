# DeepPacket

A multi-threaded deep packet inspection (DPI) tool written in pure Python, with no third-party dependencies. It reads a `.pcap` capture, identifies the application behind each connection, applies blocking rules, and writes the packets that survive to a new `.pcap`.

## Features

- **Application identification** from the TLS SNI (HTTPS) and HTTP `Host` header, mapped to apps such as YouTube, Netflix, GitHub, Discord and Zoom
- **Blocking rules** by source IP, application, or domain substring (rules can be combined and repeated)
- **Multi-threaded pipeline** with per-connection flow affinity, so no locks are needed on flow state
- **Processing report**: totals, per-thread counts, application breakdown, and every website seen

## Requirements

Python 3.8+. No packages to install.

## Usage

```
python main.py <input.pcap> <output.pcap> [options]
```

| Option | Description |
|---|---|
| `--block-ip IP` | Drop packets from this source IP |
| `--block-app APP` | Drop traffic identified as this app (e.g. `YouTube`) |
| `--block-domain TEXT` | Drop traffic whose domain contains this text |
| `--lbs N` | Number of load balancer threads (default 2) |
| `--fps N` | Fast path threads per load balancer (default 2) |

Each blocking option may be given more than once.

```
python main.py capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
python main.py capture.pcap filtered.pcap --block-domain tiktok --lbs 4 --fps 4
```

## Architecture

```
Reader (main thread)  ->  LoadBalancer threads  ->  FastPath threads  ->  Writer thread
```

1. **Reader** parses the capture and hands each packet to a load balancer.
2. **Load balancers** pick a fast path for the packet.
3. **Fast paths** identify the application, apply the rules, and keep or drop the packet.
4. **Writer** saves the kept packets to the output file.

All packets of a connection are routed to the same fast path (chosen from the flow key), so each fast path owns the state for its connections exclusively. Threads are connected by bounded queues, which gives backpressure on large captures, and shut down cleanly with a `STOP` marker that travels behind the last packet.

## Project layout

| File | Purpose |
|---|---|
| `main.py` | Command-line interface |
| `engine.py` | Threaded pipeline, flow tracking, rules, report |
| `parsing.py` | Ethernet / IP / TCP / UDP parsing, SNI and HTTP Host extraction |
| `apps.py` | Domain-to-application mapping |
| `pcap.py` | `.pcap` reading and writing |
| `generate_test_pcap.py` | Builds a synthetic test capture |

To add or adjust an application, edit `APP_RULES` in `apps.py`.

## Try it

```
python generate_test_pcap.py     # creates test_dpi.pcap
python main.py test_dpi.pcap out.pcap --block-app YouTube --block-ip 192.168.1.50
```

The sample capture has 77 packets (16 HTTPS, 2 HTTP, 4 DNS, 5 from `192.168.1.50`). With the command above, 71 packets are forwarded and 6 are dropped: the YouTube handshake and the five packets from `192.168.1.50`.

## Limitations

- Application detection relies on the SNI / Host header, so encrypted-SNI traffic and non-web protocols are reported by protocol only (`HTTPS`, `DNS`, `Unknown`).
- Domains not listed in `apps.py` show up as generic `HTTPS`.
- Output is a filtered `.pcap`; packets are not modified.
