"""The multi-threaded part.

Packets travel through a pipeline. Every box is a thread (except the first),
and every arrow is a queue.Queue that the next thread reads from:

    Reader (main thread)
        |  reads the file, parses packets, picks a load balancer
        v
    LoadBalancer threads   (--lbs, default 2)
        |  each picks one of its fast paths
        v
    FastPath threads       (--fps per load balancer, default 2)
        |  find the app, apply block rules, keep or drop
        v
    Writer thread
        writes the packets that were kept into the output file

WHY SO MANY THREADS?
  Work is split by *connection*. All packets of one connection are always sent
  to the same FastPath thread (we choose the thread from the flow_key). So a
  FastPath owns the notes (the `flows` dict) for its connections and nobody
  else touches them - no locks needed.

HOW DO THREADS STOP?
  When the reader is finished it puts the special value STOP into the queues.
  A thread that receives STOP passes it on to the queues after it, then ends.
  Because the queue is first-in-first-out, STOP arrives after every real packet,
  so nothing is lost.
"""

import queue
import threading
from collections import Counter

from apps import KNOWN_APPS, identify_app
from parsing import extract_http_host, extract_sni, parse_packet
from pcap import (read_pcap_header, read_pcap_packets,
                  write_pcap_header, write_pcap_packet)

STOP = None            # "no more packets" marker sent through the queues
QUEUE_SIZE = 1000      # a full queue makes the sender wait (stops memory blow-up)


# ---------------------------------------------------------------------------
# Block rules
# ---------------------------------------------------------------------------

class Rules:
    """What to block. Filled in before the threads start and only read after
    that, so the threads can share it safely without a lock."""

    def __init__(self):
        self.ips = set()
        self.apps = set()
        self.domains = []

    def block_ip(self, ip):
        self.ips.add(ip)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app):
        for known in KNOWN_APPS:
            if known.lower() == app.lower():
                self.apps.add(known)
                print(f"[Rules] Blocked app: {known}")
                return
        print(f"[Rules] Unknown app: {app}")

    def block_domain(self, domain):
        self.domains.append(domain.lower())
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, packet_src_ip, client_ip, app, host):
        return (
            packet_src_ip in self.ips
            or client_ip in self.ips        # replies belong to the client's connection
            or app in self.apps
            or any(domain in host.lower() for domain in self.domains)
        )


# ---------------------------------------------------------------------------
# Thread 1: Load balancer
# ---------------------------------------------------------------------------

class LoadBalancer(threading.Thread):
    """Takes packets from the reader and hands each one to a FastPath."""

    def __init__(self, lb_id, num_lbs, fast_paths):
        super().__init__(name=f"LB{lb_id}")
        self.num_lbs = num_lbs
        self.fast_paths = fast_paths
        self.inbox = queue.Queue(maxsize=QUEUE_SIZE)
        self.dispatched = 0

    def run(self):
        while True:
            pkt = self.inbox.get()          # waits here until a packet arrives

            if pkt is STOP:                 # reader is done: tell our fast paths
                for fp in self.fast_paths:
                    fp.inbox.put(STOP)
                return

            # Same connection -> same number -> same FastPath, every time.
            # (We divide by num_lbs first because the reader already used
            #  "hash % num_lbs" to pick this load balancer.)
            number = hash(pkt.flow_key) // self.num_lbs
            fp = self.fast_paths[number % len(self.fast_paths)]
            fp.inbox.put(pkt)
            self.dispatched += 1


# ---------------------------------------------------------------------------
# Thread 2: Fast path
# ---------------------------------------------------------------------------

class Flow:
    """Our notes about one connection."""

    def __init__(self, client_ip):
        self.client_ip = client_ip   # who sent the first packet
        self.app = "Unknown"
        self.host = ""               # website name, once we have seen it
        self.classified = False      # True once we know the app for sure
        self.blocked = False


class FastPath(threading.Thread):
    """Looks inside packets, finds the app and decides: forward or drop."""

    def __init__(self, fp_id, rules, writer_inbox):
        super().__init__(name=f"FP{fp_id}")
        self.rules = rules
        self.writer_inbox = writer_inbox
        self.inbox = queue.Queue(maxsize=QUEUE_SIZE)

        self.flows = {}              # flow_key -> Flow  (only this thread uses it)

        # Each thread counts its own numbers; the main thread adds them up
        # at the end. That way no locks are needed for counting.
        self.processed = 0
        self.forwarded = 0
        self.dropped = 0
        self.app_counts = Counter()  # app name -> number of packets
        self.hosts = {}              # website name -> app name

    def run(self):
        while True:
            pkt = self.inbox.get()
            if pkt is STOP:
                return
            self.handle(pkt)

    def handle(self, pkt):
        self.processed += 1

        # 1. Find (or start) the notes for this connection.
        flow = self.flows.get(pkt.flow_key)
        if flow is None:
            flow = Flow(client_ip=pkt.src_ip)
            self.flows[pkt.flow_key] = flow

        # 2. Work out which app it is (only until we know).
        if not flow.classified:
            self.classify(pkt, flow)

        # 3. Check the block rules. Once blocked, a connection stays blocked.
        if not flow.blocked:
            flow.blocked = self.rules.is_blocked(pkt.src_ip, flow.client_ip,
                                                 flow.app, flow.host)

        # 4. Count it.
        self.app_counts[flow.app] += 1
        if flow.host:
            self.hosts[flow.host] = flow.app

        # 5. Forward or drop.
        if flow.blocked:
            self.dropped += 1
        else:
            self.forwarded += 1
            self.writer_inbox.put(pkt)

    def classify(self, pkt, flow):
        # HTTPS: the website name is in the first packet (TLS Client Hello).
        if pkt.dst_port == 443 and len(pkt.payload) > 5:
            host = extract_sni(pkt.payload)
            if host:
                flow.host, flow.app, flow.classified = host, identify_app(host), True
                return

        # HTTP: the website name is in the "Host:" header.
        if pkt.dst_port == 80 and len(pkt.payload) > 10:
            host = extract_http_host(pkt.payload)
            if host:
                flow.host, flow.app, flow.classified = host, identify_app(host), True
                return

        # DNS always uses port 53.
        if pkt.dst_port == 53 or pkt.src_port == 53:
            flow.app, flow.classified = "DNS", True
            return

        # Guess from the port. We do NOT mark it classified, because a later
        # packet of this connection might still reveal the real name.
        if pkt.dst_port == 443:
            flow.app = "HTTPS"
        elif pkt.dst_port == 80:
            flow.app = "HTTP"


# ---------------------------------------------------------------------------
# Thread 3: Writer
# ---------------------------------------------------------------------------

def writer_loop(inbox, output_file):
    """Write every packet that arrives in `inbox` until STOP."""
    while True:
        pkt = inbox.get()
        if pkt is STOP:
            return
        write_pcap_packet(output_file, pkt)


# ---------------------------------------------------------------------------
# Putting it all together
# ---------------------------------------------------------------------------

def process(input_path, output_path, rules, num_lbs=2, fps_per_lb=2):
    writer_inbox = queue.Queue(maxsize=QUEUE_SIZE)

    # Create the worker threads.
    all_fps = []
    lbs = []
    for lb_id in range(num_lbs):
        my_fps = [FastPath(lb_id * fps_per_lb + i, rules, writer_inbox)
                  for i in range(fps_per_lb)]
        all_fps += my_fps
        lbs.append(LoadBalancer(lb_id, num_lbs, my_fps))

    print(f"\nStarting {num_lbs} load balancers and {len(all_fps)} fast paths")

    total_packets = total_bytes = tcp_packets = udp_packets = 0

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        byte_order, snaplen, link_type = read_pcap_header(infile)
        write_pcap_header(outfile, snaplen, link_type)

        # Start every thread. They wait for packets.
        writer = threading.Thread(target=writer_loop, args=(writer_inbox, outfile),
                                  name="Writer")
        for t in [writer] + all_fps + lbs:
            t.start()

        # The main thread is the reader: parse each packet and hand it over.
        for ts_sec, ts_usec, data in read_pcap_packets(infile, byte_order):
            pkt = parse_packet(ts_sec, ts_usec, data)
            if pkt is None:
                continue                          # not IPv4 TCP/UDP: ignore

            total_packets += 1
            total_bytes += len(data)
            if pkt.protocol == 6:
                tcp_packets += 1
            else:
                udp_packets += 1

            lb = lbs[hash(pkt.flow_key) % num_lbs]
            lb.inbox.put(pkt)

        # Shut down in order: reader -> LBs -> FPs -> writer.
        # join() means "wait until that thread has finished".
        for lb in lbs:
            lb.inbox.put(STOP)
        for lb in lbs:
            lb.join()
        for fp in all_fps:
            fp.join()
        writer_inbox.put(STOP)
        writer.join()

    # All threads are finished, so it is safe to add up their numbers.
    print_report(total_packets, total_bytes, tcp_packets, udp_packets, lbs, all_fps)


def print_report(total_packets, total_bytes, tcp_packets, udp_packets, lbs, fps):
    app_counts = Counter()
    hosts = {}
    for fp in fps:
        app_counts.update(fp.app_counts)
        hosts.update(fp.hosts)

    print("\n=== PROCESSING REPORT ===")
    print(f"Total packets : {total_packets}")
    print(f"Total bytes   : {total_bytes}")
    print(f"TCP / UDP     : {tcp_packets} / {udp_packets}")
    print(f"Forwarded     : {sum(fp.forwarded for fp in fps)}")
    print(f"Dropped       : {sum(fp.dropped for fp in fps)}")

    print("\n--- Per thread ---")
    for lb in lbs:
        print(f"{lb.name} dispatched {lb.dispatched}")
    for fp in fps:
        print(f"{fp.name} processed {fp.processed}")

    print("\n--- Applications ---")
    for app, count in app_counts.most_common():
        percent = 100 * count / total_packets if total_packets else 0
        print(f"{app:<12} {count:>6}  {percent:5.1f}%  {'#' * int(percent / 5)}")

    if hosts:
        print("\n--- Websites seen ---")
        for host, app in hosts.items():
            print(f"  {host} -> {app}")
