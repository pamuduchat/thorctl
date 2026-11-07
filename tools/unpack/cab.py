"""Extract an MSZIP cabinet: python3 -I cab.py in.cab outdir"""
import os
import struct
import sys
import zlib

MAX_OUT = 1 << 30


def safe_path(out, name):
    base = os.path.basename(name.replace("\\", "/"))
    if base in ("", ".", ".."):
        raise ValueError(f"bad member name: {name!r}")
    return os.path.join(out, base)


def main(src, out):
    d = open(src, "rb").read()
    b = d.find(b"MSCF\0\0\0\0")
    if b < 0:
        sys.exit("no cabinet found")
    c = d[b:]
    _, _, _, _, coff_files, _, _, _, n_folders, n_files, _ = struct.unpack_from("<4sIIIIIBBHHH", c, 0)
    os.makedirs(out, exist_ok=True)

    folders = []
    for f in range(n_folders):
        coff, nblk, typ = struct.unpack_from("<IHH", c, 36 + 8 * f)
        if typ & 0xF != 1:
            sys.exit(f"folder {f}: unsupported compression {typ & 0xF}")
        p, data = coff, bytearray()
        for _ in range(nblk):
            _, cb, ucb = struct.unpack_from("<IHH", c, p)
            p += 8
            blk = c[p:p + cb]
            p += cb
            if blk[:2] != b"CK":
                sys.exit(f"folder {f}: bad block at {p}")
            z = zlib.decompressobj(-15, zdict=bytes(data[-32768:])) if data else zlib.decompressobj(-15)
            u = z.decompress(blk[2:], ucb) + z.flush()
            if len(u) != ucb or len(data) + ucb > MAX_OUT:
                sys.exit(f"folder {f}: bad block size")
            data += u
        folders.append(bytes(data))

    p = coff_files
    for _ in range(n_files):
        size, off, ifold, _, _, _ = struct.unpack_from("<IIHHHH", c, p)
        p += 16
        e = c.index(b"\0", p)
        name = c[p:e].decode("latin1")
        p = e + 1
        if ifold >= len(folders):
            sys.exit(f"{name}: bad folder index")
        with open(safe_path(out, name), "wb") as fh:
            fh.write(folders[ifold][off:off + size])
    print(n_files, "files")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
