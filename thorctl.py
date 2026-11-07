#!/usr/bin/env python3
"""Configure a Fantech Thor II X16 V2 (PixArt 093a:2533) on Linux.

Every command sends the Windows driver's standard connect sequence and reads registers.
Setting changes are only printed unless --apply is given; --apply saves a backup first.
"""
import argparse
import ctypes
import fcntl
import glob
import json
import os
import sys
import time

VID, PID = 0x093A, 0x2533
REQ = 0x01
GAP = 0.11  # the Windows driver spaces requests ~110 ms apart

STAGE_REGS = (0x02, 0x03, 0x04, 0x05)
STAGE_HI_BIT = {0x02: 0x20}  # reg 08 bit holding DPI idx bit 4; stages 2-4 unconfirmed
DPI_REG_HI = 0x08
RATE_REG = 0x0E
RATES = {1000: 0, 500: 1, 250: 2, 125: 3}
READ_REGS = (0x00,) + tuple(range(0x02, 0x12))
RESTORE_REGS = STAGE_REGS + (DPI_REG_HI, RATE_REG)
BACKUP_DIR = os.path.join(os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")), "thorctl")


class CtrlTransfer(ctypes.Structure):
    _fields_ = [("bRequestType", ctypes.c_uint8), ("bRequest", ctypes.c_uint8),
                ("wValue", ctypes.c_uint16), ("wIndex", ctypes.c_uint16),
                ("wLength", ctypes.c_uint16), ("timeout", ctypes.c_uint32),
                ("data", ctypes.c_void_p)]


USBDEVFS_CONTROL = (3 << 30) | (ctypes.sizeof(CtrlTransfer) << 16) | (ord("U") << 8) | 0


def find_node():
    for d in glob.glob("/sys/bus/usb/devices/*"):
        try:
            with open(f"{d}/idVendor") as v, open(f"{d}/idProduct") as p:
                if int(v.read(), 16) != VID or int(p.read(), 16) != PID:
                    continue
            with open(f"{d}/busnum") as b, open(f"{d}/devnum") as n:
                return f"/dev/bus/usb/{int(b.read()):03d}/{int(n.read()):03d}"
        except (OSError, ValueError):
            continue
    sys.exit(f"mouse {VID:04x}:{PID:04x} not found")


class Mouse:
    def __init__(self, apply):
        self.apply = apply
        self.node = find_node()
        self.fd = os.open(self.node, os.O_RDWR)

    def close(self):
        os.close(self.fd)

    def _ctrl(self, rtype, value, index, length):
        buf = ctypes.create_string_buffer(max(length, 1))
        xfer = CtrlTransfer(rtype, REQ, value, index, length, 1000, ctypes.addressof(buf))
        fcntl.ioctl(self.fd, USBDEVFS_CONTROL, xfer)
        time.sleep(GAP)
        return buf.raw[:length]

    def _send(self, reg, val, w_value=0x0100):
        self._ctrl(0x40, w_value, (val << 8) | reg, 0)

    def write(self, reg, val):
        print(f"  {'W' if self.apply else 'would write'} {reg:02x} <- {val:02x}")
        if self.apply:
            self._send(reg, val)

    def read(self, reg):
        return self._ctrl(0xC0, 0x0100, reg, 1)[0]

    def unlock(self):
        """Same sequence the Windows driver sends on every connect."""
        self._send(0x7F, 0x00)
        self._send(0x09, 0x00)
        self._send(0x00, 0x00, w_value=0x0000)
        self._send(0x09, 0x5A)
        self._send(0x7F, 0x01)


def read_all(m):
    return {reg: m.read(reg) for reg in READ_REGS}


def dpi_of(regs, stage_reg):
    idx = regs[stage_reg] & 0x0F
    bit = STAGE_HI_BIT.get(stage_reg)
    if bit and regs[DPI_REG_HI] & bit:
        idx |= 0x10
    return (idx + 1) * 200


def show(regs):
    for i, r in enumerate(STAGE_REGS, 1):
        note = "" if r in STAGE_HI_BIT else "  (values above 3200 not decoded yet)"
        print(f"DPI stage {i}: {dpi_of(regs, r)}{note}")
    code = regs[RATE_REG] >> 6
    print(f"report rate: {next(hz for hz, c in RATES.items() if c == code)} Hz")
    print("raw: " + " ".join(f"{r:02x}={v:02x}" for r, v in regs.items()))


def backup(regs):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    path = os.path.join(BACKUP_DIR, time.strftime("backup-%Y%m%d-%H%M%S.json"))
    with open(path, "w") as f:
        json.dump({f"{r:02x}": v for r, v in regs.items()}, f, indent=1)
    print(f"backup: {path}")


def set_dpi(m, regs, stage, dpi):
    reg = STAGE_REGS[stage - 1]
    idx = dpi // 200 - 1
    hi = STAGE_HI_BIT.get(reg)
    if idx > 0x0F and not hi:
        sys.exit(f"stage {stage}: DPI above 3200 isn't mapped yet (stage 1 supports up to 4200)")
    r08 = regs[DPI_REG_HI]
    if hi:
        r08 = (r08 | hi) if idx & 0x10 else (r08 & ~hi & 0xFF)
    m.write(DPI_REG_HI, r08)
    m.write(reg, (regs[reg] & 0xF0) | (idx & 0x0F))


def set_rate(m, regs, hz):
    m.write(RATE_REG, (RATES[hz] << 6) | (regs[RATE_REG] & 0x3F))
    print("  (the mouse reconnects after a report-rate change)")


def restore(m, path):
    with open(path) as f:
        saved = {int(k, 16): int(v) for k, v in json.load(f).items()}
    for reg in RESTORE_REGS:
        if reg in saved and 0 <= saved[reg] <= 0xFF:
            m.write(reg, saved[reg])


def dpi_value(s):
    v = int(s)
    if v % 200 or not 200 <= v <= 4200:
        raise argparse.ArgumentTypeError("DPI must be 200..4200 in steps of 200")
    return v


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true", help="actually send setting writes")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="read and decode current settings")
    p = sub.add_parser("dpi", help="set one DPI stage")
    p.add_argument("stage", type=int, choices=range(1, 5))
    p.add_argument("value", type=dpi_value)
    p = sub.add_parser("rate", help="set report rate")
    p.add_argument("hz", type=int, choices=sorted(RATES))
    p = sub.add_parser("restore", help="write DPI/rate registers back from a backup file")
    p.add_argument("file")
    return ap.parse_args(argv)


def main():
    a = parse_args()
    m = Mouse(apply=a.apply)
    try:
        print(f"device: {m.node}")
        m.unlock()
        regs = read_all(m)
        show(regs)
        if a.cmd == "status":
            return
        if a.apply:
            backup(regs)
        else:
            print("dry run (add --apply to send):")
        if a.cmd == "dpi":
            set_dpi(m, regs, a.stage, a.value)
        elif a.cmd == "rate":
            set_rate(m, regs, a.hz)
        elif a.cmd == "restore":
            restore(m, a.file)
        if a.apply and a.cmd != "rate":
            print("now:")
            show(read_all(m))
    finally:
        m.close()


if __name__ == "__main__":
    main()
