#!/usr/bin/env python3
"""Sum TCP payload bytes per direction in a loopback pcap; divide by N connections.
Usage: pcap_bytes.py FILE N SERVER_PORT"""
import struct, sys
path, n, sport = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
c2s = s2c = 0
with open(path, "rb") as f:
    gh = f.read(24)
    endian = "<" if gh[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    link = struct.unpack(endian + "I", gh[20:24])[0]
    l2 = {1: 14, 113: 16, 276: 20}.get(link, 14)   # EN10MB, LINUX_SLL, SLL2
    while True:
        ph = f.read(16)
        if len(ph) < 16: break
        incl = struct.unpack(endian + "IIII", ph)[2]
        pkt = f.read(incl)
        ip = pkt[l2:]
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6: continue
        ihl = (ip[0] & 0xF) * 4
        tot = struct.unpack(">H", ip[2:4])[0]
        tcp = ip[ihl:]
        sp, dp = struct.unpack(">HH", tcp[:4])
        pay = tot - ihl - (tcp[12] >> 4) * 4
        if sp == sport: s2c += pay
        elif dp == sport: c2s += pay
print(f"c->s {c2s/n:6.0f} B   s->c {s2c/n:6.0f} B   total {(c2s+s2c)/n:6.0f} B/conn")
