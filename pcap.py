"""Reading and writing .pcap files.

A .pcap file looks like this:

    [ global header: 24 bytes ]
    [ packet header: 16 bytes ][ packet bytes ]
    [ packet header: 16 bytes ][ packet bytes ]
    ...

We use Python's `struct` module to turn those bytes into numbers.
Format letters:  I = 4-byte number,  H = 2-byte number,  i = signed 4-byte number
"<" means "little-endian" (the usual byte order), ">" means "big-endian".
"""

import struct

MAGIC = 0xA1B2C3D4   # first 4 bytes of every pcap file
GLOBAL_HEADER_SIZE = 24
PACKET_HEADER_SIZE = 16


def read_pcap_header(f):
    """Read the 24-byte global header.

    Returns (byte_order, snaplen, link_type).
    byte_order is "<" or ">", needed later to read the packet headers.
    """
    raw = f.read(GLOBAL_HEADER_SIZE)
    if len(raw) < GLOBAL_HEADER_SIZE:
        raise ValueError("File is too short to be a pcap file")

    # The magic number tells us which byte order the file was written in.
    if struct.unpack("<I", raw[:4])[0] == MAGIC:
        byte_order = "<"
    elif struct.unpack(">I", raw[:4])[0] == MAGIC:
        byte_order = ">"
    else:
        raise ValueError("Not a pcap file (bad magic number)")

    _, _, _, _, _, snaplen, link_type = struct.unpack(byte_order + "IHHiIII", raw)
    return byte_order, snaplen, link_type


def read_pcap_packets(f, byte_order):
    """Yield (ts_sec, ts_usec, data) for every packet in the file."""
    while True:
        header = f.read(PACKET_HEADER_SIZE)
        if len(header) < PACKET_HEADER_SIZE:
            return  # end of file

        ts_sec, ts_usec, captured_len, _ = struct.unpack(byte_order + "IIII", header)
        data = f.read(captured_len)
        if len(data) < captured_len:
            return  # file was cut off in the middle of a packet

        yield ts_sec, ts_usec, data


def write_pcap_header(f, snaplen, link_type):
    """Write a standard global header (we always write little-endian)."""
    f.write(struct.pack("<IHHiIII", MAGIC, 2, 4, 0, 0, snaplen, link_type))


def write_pcap_packet(f, pkt):
    """Write one packet record: 16-byte header followed by the packet bytes."""
    size = len(pkt.data)
    f.write(struct.pack("<IIII", pkt.ts_sec, pkt.ts_usec, size, size))
    f.write(pkt.data)
