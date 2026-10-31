"""Turning raw packet bytes into something we can use.

A packet is a stack of headers, like envelopes inside envelopes:

    | Ethernet (14 bytes) | IP (20+ bytes) | TCP (20+ bytes) or UDP (8 bytes) | payload |

We walk through the bytes from left to right, reading what we need from each
header, and use the header's length field to know where the next one starts.
"""

from typing import NamedTuple

ETHERNET_HEADER_LEN = 14
IPV4 = 0x0800
TCP = 6
UDP = 17


class Packet(NamedTuple):
    """Everything the worker threads need to know about one packet."""
    ts_sec: int
    ts_usec: int
    data: bytes        # the full raw packet (this is what gets written out)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int      # 6 = TCP, 17 = UDP
    payload: bytes     # the part after all the headers (TLS / HTTP data)

    @property
    def flow_key(self):
        """Identifies a connection. Same value for both directions.

        A connection is "who talks to whom": two (ip, port) endpoints.
        Sorting the two endpoints means A->B and B->A give the same key.
        """
        a = (self.src_ip, self.src_port)
        b = (self.dst_ip, self.dst_port)
        return (min(a, b), max(a, b), self.protocol)


def parse_packet(ts_sec, ts_usec, data):
    """Return a Packet, or None if it is not an IPv4 TCP/UDP packet."""

    # ---- Ethernet header: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes type ----
    if len(data) < ETHERNET_HEADER_LEN:
        return None
    ether_type = int.from_bytes(data[12:14], "big")
    if ether_type != IPV4:
        return None

    # ---- IP header ----
    ip = ETHERNET_HEADER_LEN                       # where the IP header starts
    if len(data) < ip + 20:
        return None
    version = data[ip] >> 4                        # upper 4 bits of first byte
    ip_header_len = (data[ip] & 0x0F) * 4          # lower 4 bits = length in 4-byte words
    if version != 4 or ip_header_len < 20 or len(data) < ip + ip_header_len:
        return None
    protocol = data[ip + 9]
    src_ip = ".".join(str(b) for b in data[ip + 12 : ip + 16])
    dst_ip = ".".join(str(b) for b in data[ip + 16 : ip + 20])

    # ---- TCP or UDP header ----
    transport = ip + ip_header_len                 # where TCP/UDP header starts
    if protocol == TCP:
        if len(data) < transport + 20:
            return None
        tcp_header_len = (data[transport + 12] >> 4) * 4
        if tcp_header_len < 20 or len(data) < transport + tcp_header_len:
            return None
        payload_start = transport + tcp_header_len
    elif protocol == UDP:
        if len(data) < transport + 8:
            return None
        payload_start = transport + 8
    else:
        return None                                # ICMP etc. are ignored

    src_port = int.from_bytes(data[transport : transport + 2], "big")
    dst_port = int.from_bytes(data[transport + 2 : transport + 4], "big")

    return Packet(ts_sec, ts_usec, data, src_ip, dst_ip, src_port, dst_port,
                  protocol, data[payload_start:])


# ---------------------------------------------------------------------------
# Finding the website name inside the payload
# ---------------------------------------------------------------------------

def extract_sni(payload):
    """Find the website name in a TLS "Client Hello" message.

    When your browser opens an HTTPS site it first sends a Client Hello, and
    that message contains the site name in plain text (SNI = Server Name
    Indication). The rest of the connection is encrypted, but this part isn't.

    The Client Hello is a list of fields, some with fixed size and some with a
    length byte(s) in front. We skip over each one until we reach the
    extensions list, then look for the extension of type 0 (the server name).

    Returns the name (e.g. "www.youtube.com") or None.
    """
    # Record header (5 bytes) + handshake header (4 bytes) must be present.
    if len(payload) < 9:
        return None
    if payload[0] != 0x16:        # 0x16 = "handshake" record
        return None
    if payload[5] != 0x01:        # 0x01 = "Client Hello" message
        return None

    pos = 5 + 4                   # skip record header + handshake header
    pos += 2 + 32                 # skip client version (2) + random bytes (32)

    try:
        pos += 1 + payload[pos]                                      # session id
        pos += 2 + int.from_bytes(payload[pos : pos + 2], "big")     # cipher suites
        pos += 1 + payload[pos]                                      # compression methods

        # Now come the extensions: 2 bytes total length, then a list of
        #   [type: 2 bytes][length: 2 bytes][data: length bytes]
        extensions_end = pos + 2 + int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        extensions_end = min(extensions_end, len(payload))

        while pos + 4 <= extensions_end:
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            pos += 4

            if ext_type == 0:     # 0 = server_name extension
                # data = [list length: 2][name type: 1][name length: 2][name]
                name_len = int.from_bytes(payload[pos + 3 : pos + 5], "big")
                name = payload[pos + 5 : pos + 5 + name_len]
                return name.decode("latin-1")

            pos += ext_len        # not the one we want, skip it
    except IndexError:
        pass                      # packet was too short / malformed

    return None


HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")


def extract_http_host(payload):
    """Find the website name in a plain HTTP request ("Host: example.com")."""
    if payload[:4] not in HTTP_METHODS:
        return None

    for line in payload.split(b"\r\n"):
        if line.lower().startswith(b"host:"):
            host = line[5:].strip().decode("latin-1")
            return host.split(":")[0] or None   # drop a ":8080" style port
    return None
