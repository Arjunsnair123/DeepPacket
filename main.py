"""Command line entry point.

Example:
    python main.py input.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50
"""

import argparse
import sys

from engine import Rules, process


def main():
    parser = argparse.ArgumentParser(description="Simple multi-threaded packet inspector")
    parser.add_argument("input", help="input .pcap file")
    parser.add_argument("output", help="output .pcap file (kept packets)")
    parser.add_argument("--block-ip", action="append", default=[], help="block a source IP")
    parser.add_argument("--block-app", action="append", default=[], help="block an app, e.g. YouTube")
    parser.add_argument("--block-domain", action="append", default=[], help="block a domain (substring)")
    parser.add_argument("--lbs", type=int, default=2, help="number of load balancer threads")
    parser.add_argument("--fps", type=int, default=2, help="fast path threads per load balancer")
    args = parser.parse_args()

    if args.lbs < 1 or args.fps < 1:
        sys.exit("--lbs and --fps must be at least 1")

    rules = Rules()
    for ip in args.block_ip:
        rules.block_ip(ip)
    for app in args.block_app:
        rules.block_app(app)
    for domain in args.block_domain:
        rules.block_domain(domain)

    try:
        process(args.input, args.output, rules, args.lbs, args.fps)
    except (OSError, ValueError) as error:
        sys.exit(f"Error: {error}")

    print(f"\nOutput written to: {args.output}")


if __name__ == "__main__":
    main()
