"""Pull the embedded cabinet out of an MSI: python3 -I ole.py in.msi out.cab"""
import struct
import sys

END = 0xFFFFFFFA


def streams(path):
    d = open(path, "rb").read()
    if d[:8] != bytes.fromhex("d0cf11e0a1b11ae1"):
        sys.exit("not an OLE compound file")
    ss = 1 << struct.unpack_from("<H", d, 30)[0]
    nsec = (len(d) - 512) // ss
    nfat, dirstart = struct.unpack_from("<I", d, 44)[0], struct.unpack_from("<I", d, 48)[0]
    difat_start, ndifat = struct.unpack_from("<II", d, 68)
    difat = list(struct.unpack_from("<109I", d, 76))

    def sec(n):
        if n >= nsec:
            raise ValueError(f"sector {n} out of range")
        return d[512 + n * ss:512 + (n + 1) * ss]

    s, seen = difat_start, set()
    while ndifat and s < END and s not in seen:
        seen.add(s)
        v = struct.unpack("<%dI" % (ss // 4), sec(s))
        difat += v[:-1]
        s, ndifat = v[-1], ndifat - 1

    fat = []
    for n in difat[:nfat]:
        fat += struct.unpack("<%dI" % (ss // 4), sec(n))

    def chain(n):
        out, seen = [], set()
        while n < END:
            if n in seen or n >= len(fat):
                raise ValueError("corrupt FAT chain")
            seen.add(n)
            out.append(sec(n))
            n = fat[n]
        return b"".join(out)

    dr = chain(dirstart)
    for i in range(0, len(dr), 128):
        e = dr[i:i + 128]
        nl = struct.unpack_from("<H", e, 64)[0]
        if not 2 <= nl <= 64:
            continue
        name = e[:nl - 2].decode("utf-16le", "replace")
        start, size = struct.unpack_from("<IQ", e, 116)
        if size >= 4096:
            yield name, chain(start)[:size]


def main(src, dst):
    for _, data in streams(src):
        if data[:4] == b"MSCF":
            with open(dst, "wb") as fh:
                fh.write(data)
            print("cab", len(data))
            return
    sys.exit("no cabinet stream found")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
