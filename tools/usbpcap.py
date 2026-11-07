#!/usr/bin/env python3
"""Decode HID control transfers from a Windows USBPcap .pcapng capture.

usage: python3 -I tools/usbpcap.py capture.pcapng [--summary | --regs] [--device N] [--all]
"""
import argparse
import struct
import sys
from collections import Counter

LINKTYPE_USBPCAP = 249
XFER = {0: "iso", 1: "intr", 2: "ctrl", 3: "bulk"}
HID_REQ = {0x01: "GET_REPORT", 0x09: "SET_REPORT", 0x0A: "SET_IDLE", 0x0B: "SET_PROTOCOL"}
REPORT_TYPE = {1: "input", 2: "output", 3: "feature"}


def packets(path):
    """Yield (timestamp_s, usbpcap_packet_bytes) from a pcapng file."""
    d = open(path, "rb").read()
    p, end, linktypes, tsres, bo = 0, len(d), [], [], "<"
    while p + 12 <= end:
        btype = struct.unpack_from(bo + "I", d, p)[0]
        if btype == 0x0A0D0D0A:
            bo = "<" if d[p + 8:p + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            linktypes, tsres = [], []
        blen = struct.unpack_from(bo + "I", d, p + 4)[0]
        if blen < 12 or p + blen > end:
            break
        body = d[p + 8:p + blen - 4]
        if btype == 1:
            linktypes.append(struct.unpack_from(bo + "H", body, 0)[0])
            tsres.append(1e-6)
            o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack_from(bo + "HH", body, o)
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[o + 4]
                    tsres[-1] = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                o += 4 + ((ln + 3) & ~3)
        elif btype == 6:
            iface, th, tl, caplen = struct.unpack_from(bo + "IIII", body, 0)
            if iface < len(linktypes) and linktypes[iface] == LINKTYPE_USBPCAP:
                yield ((th << 32) | tl) * tsres[iface], body[20:20 + caplen]
        p += blen


def parse(pkt):
    hlen, irp, status, func, info, bus, dev, ep, xfer, dlen = struct.unpack_from("<HQIHBHHBBI", pkt, 0)
    stage = pkt[27] if xfer == 2 and hlen >= 28 else None
    return dict(irp=irp, status=status, info=info, bus=bus, dev=dev, ep=ep, xfer=xfer,
                stage=stage, data=pkt[hlen:hlen + dlen])


def print_regs(pkts, t0, device):
    """PixArt register access: vendor request 0x01, wIndex = value << 8 | reg."""
    pending, last_dev = {}, None
    for t, u in pkts:
        if u["xfer"] != 2 or (device is not None and u["dev"] != device):
            continue
        if u["stage"] == 0 and len(u["data"]) >= 8:
            rt, req, val, idx, ln = struct.unpack_from("<BBHHH", u["data"], 0)
            if rt & 0x7F != 0x40 or req != 0x01:
                continue
            if u["dev"] != last_dev:
                print(f"--- device {u['dev']}")
                last_dev = u["dev"]
            note = "" if val == 0x0100 else f"  (wValue=0x{val:04x})"
            if rt & 0x80:
                pending[u["irp"]] = (t, idx, note)
            else:
                print(f"{t - t0:9.3f} W {idx & 0xFF:02x} <- {idx >> 8:02x}{note}")
        elif u["info"] & 1 and u["irp"] in pending:
            ts, idx, note = pending.pop(u["irp"])
            val = u["data"].hex() if u["data"] else "??"
            print(f"{ts - t0:9.3f} R {idx & 0xFF:02x} -> {val}{note}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--device", type=int)
    ap.add_argument("--all", action="store_true", help="include non-HID control and interrupt traffic")
    ap.add_argument("--regs", action="store_true", help="decode vendor register reads/writes")
    a = ap.parse_args()

    pkts = [(t, parse(p)) for t, p in packets(a.pcap)]
    if not pkts:
        sys.exit("no USBPcap packets found")
    t0 = pkts[0][0]

    if a.summary:
        c = Counter((u["bus"], u["dev"], XFER.get(u["xfer"], str(u["xfer"])), hex(u["ep"])) for _, u in pkts)
        for (bus, dev, x, ep), n in sorted(c.items()):
            print(f"bus {bus} dev {dev:3} {x:4} ep {ep:5} {n:6} pkts")
        return

    if a.regs:
        print_regs(pkts, t0, a.device)
        return

    setups = {}
    for t, u in pkts:
        if a.device is not None and u["dev"] != a.device:
            continue
        ts = f"{t - t0:9.3f}"
        if u["xfer"] == 2:
            if u["stage"] == 0 and len(u["data"]) >= 8:
                rt, req, val, idx, ln = struct.unpack_from("<BBHHH", u["data"], 0)
                setups[u["irp"]] = (rt, req, val, idx, ln)
                if rt & 0x60 == 0x20 and req == 0x09:
                    payload = u["data"][8:]
                    kind = REPORT_TYPE.get(val >> 8, val >> 8)
                    print(f"{ts} dev {u['dev']} SET_REPORT {kind} id=0x{val & 0xFF:02x} if={idx} len={ln}: {payload.hex(' ')}")
                elif a.all or rt & 0x60 == 0x20:
                    name = HID_REQ.get(req, f"req 0x{req:02x}") if rt & 0x60 == 0x20 else f"std req 0x{req:02x}"
                    print(f"{ts} dev {u['dev']} {name} bmRT=0x{rt:02x} wValue=0x{val:04x} wIndex={idx} wLength={ln}")
            elif u["info"] & 1 and u["data"] and u["irp"] in setups:
                rt, req, val, idx, ln = setups[u["irp"]]
                if rt & 0x80 and (a.all or rt & 0x60 == 0x20):
                    print(f"{ts} dev {u['dev']}   -> reply ({len(u['data'])} B, status 0x{u['status']:08x}): {u['data'].hex(' ')}")
        elif a.all and u["data"]:
            print(f"{ts} dev {u['dev']} {XFER.get(u['xfer'])} ep 0x{u['ep']:02x}: {u['data'].hex(' ')}")


if __name__ == "__main__":
    main()
