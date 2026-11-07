"""Offline checks: the encoder must reproduce writes seen in Windows captures. No device needed."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import thorctl as t  # noqa: E402


class Fake:
    def __init__(self):
        self.w = []

    def write(self, reg, val):
        self.w.append((reg, val))


BASE = {r: 0 for r in t.READ_REGS}
BASE.update({0x02: 0x0F, 0x03: 0x73, 0x08: 0x43, 0x0E: 0x22})


def regs(**kw):
    return {**BASE, **{int(k[1:], 16): v for k, v in kw.items()}}


def dpi(stage, value, state):
    f = Fake()
    t.set_dpi(f, state, stage, value)
    return f.w


class Encoding(unittest.TestCase):
    def test_dpi_high_bit_set(self):
        self.assertEqual(dpi(1, 3400, BASE), [(0x08, 0x63), (0x02, 0x00)])

    def test_dpi_high_bit_cleared(self):
        self.assertEqual(dpi(1, 800, regs(r02=0x04, r08=0x63)), [(0x08, 0x43), (0x02, 0x03)])

    def test_dpi_keeps_high_nibble(self):
        self.assertEqual(dpi(2, 800, regs(r03=0x75))[-1], (0x03, 0x73))

    def test_dpi_decode(self):
        self.assertEqual(t.dpi_of(regs(r02=0x04, r08=0x63), 0x02), 4200)
        self.assertEqual(t.dpi_of(BASE, 0x02), 3200)

    def test_unmapped_stage_refused(self):
        with self.assertRaises(SystemExit):
            dpi(2, 3400, BASE)

    def test_rates(self):
        for hz, want in {125: 0xE2, 250: 0xA2, 500: 0x62, 1000: 0x22}.items():
            f = Fake()
            t.set_rate(f, BASE, hz)
            self.assertEqual(f.w, [(0x0E, want)])

    def test_bad_args(self):
        for bad in (["dpi", "1", "4400"], ["dpi", "5", "800"], ["rate", "750"], ["dpi", "1", "850"]):
            with self.assertRaises(SystemExit):
                t.parse_args(bad)

    def test_ioctl_number(self):
        self.assertEqual(t.USBDEVFS_CONTROL, 0xC0185500)


if __name__ == "__main__":
    unittest.main()
