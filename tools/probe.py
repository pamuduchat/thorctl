#!/usr/bin/env python3
"""Read-only dump of the mouse's vendor feature reports. Only issues GET_REPORT.

usage: sudo python3 -I tools/probe.py [--dev /dev/hidrawN] [--ids 0x10,0x11,0x12]
"""
import argparse
import fcntl
import glob
import os
import re
import sys

VID, PID = 0x093A, 0x2533
VENDOR_PAGE = bytes.fromhex("0600ff0901")
FEATURES = {0x10: 1, 0x11: 324, 0x12: 2}  # report id -> payload size, from the descriptor


def HIDIOCGFEATURE(length):
    return (3 << 30) | (length << 16) | (ord("H") << 8) | 0x07


def read(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def is_mouse(name):
    sysfs = f"/sys/class/hidraw/{name}/device"
    return (f"{VID:08X}:{PID:08X}" in read(f"{sysfs}/uevent")
            and read(f"{sysfs}/report_descriptor", "rb").startswith(VENDOR_PAGE))


def find_dev():
    for node in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        if is_mouse(os.path.basename(node)):
            return "/dev/" + os.path.basename(node)
    return None


def hexdump(b, width=16):
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print(f"  {i:04x}  {chunk.hex(' '):<{width * 3}} {text}")


def listen(dev):
    print("press mouse buttons (DPI, LED, side keys); Ctrl+C to stop")
    fd = os.open(dev, os.O_RDONLY)
    try:
        while True:
            r = os.read(fd, 64)
            print(f"  id 0x{r[0]:02x}: {r[1:].hex(' ')}", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        os.close(fd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev")
    ap.add_argument("--ids")
    ap.add_argument("--listen", action="store_true", help="print input reports until Ctrl+C")
    a = ap.parse_args()

    dev = a.dev or find_dev()
    if not dev:
        sys.exit(f"vendor interface for {VID:04x}:{PID:04x} not found")
    m = re.fullmatch(r"/dev/(hidraw\d+)", dev)
    if not m or not is_mouse(m.group(1)):
        sys.exit(f"{dev} is not the {VID:04x}:{PID:04x} vendor interface")

    ids = [int(x, 0) for x in a.ids.split(",")] if a.ids else list(FEATURES)
    if any(not 0 < rid < 256 for rid in ids):
        sys.exit("report ids must be 1..255")

    print(f"device: {dev}")
    if a.listen:
        listen(dev)
        return
    fd = os.open(dev, os.O_RDWR)
    try:
        for rid in ids:
            size = FEATURES.get(rid, 64) + 1
            buf = bytearray(size)
            buf[0] = rid
            try:
                n = fcntl.ioctl(fd, HIDIOCGFEATURE(size), buf, True)
            except OSError as e:
                print(f"report 0x{rid:02x}: error {e}")
                continue
            print(f"report 0x{rid:02x}: {n} bytes")
            hexdump(bytes(buf[:n]))
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
