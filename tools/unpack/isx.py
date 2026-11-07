"""Unpack an InstallShield ISSetupStream overlay: python3 -I isx.py setup.exe outdir"""
import os
import struct
import sys
import zlib

MAGIC = (0x13, 0x35, 0x86, 0x07)
MAX_OUT = 1 << 30


def safe_path(out, name):
    base = os.path.basename(name.replace("\\", "/"))
    if base in ("", ".", ".."):
        raise ValueError(f"bad member name: {name!r}")
    return os.path.join(out, base)


def decode(buf, key):
    return bytes((~(key[i % len(key)] ^ (((b << 4) | (b >> 4)) & 0xFF))) & 0xFF
                 for i, b in enumerate(buf))


def main(src, out):
    d = open(src, "rb").read()
    p = d.rfind(b"ISSetupStream\0")
    if p < 0:
        sys.exit("no ISSetupStream found")
    n, _ = struct.unpack_from("<HI", d, p + 14)
    p += 46
    os.makedirs(out, exist_ok=True)
    for _ in range(n):
        name_len, flags, _, data_len = struct.unpack_from("<IIHI", d, p)
        p += 24
        name = d[p:p + name_len].decode("utf-16le")
        p += name_len
        data = d[p:p + data_len]
        p += data_len
        key = bytes(ord(c) ^ MAGIC[i % 4] for i, c in enumerate(name)) or b"\0"
        if flags & 4:
            data = b"".join(decode(data[i:i + 1024], key) for i in range(0, len(data), 1024))
        elif flags & 2:
            data = decode(data, key)
        z = zlib.decompressobj()
        data = z.decompress(data, MAX_OUT)
        if z.unconsumed_tail:
            sys.exit(f"{name}: exceeds {MAX_OUT} bytes")
        with open(safe_path(out, name), "wb") as fh:
            fh.write(data)
        print(name, len(data))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
