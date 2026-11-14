"""List or extract single members of a remote zip via HTTP Range (zip64 aware).

usage: remotezip.py URL list
       remotezip.py URL get MEMBER OUTFILE
"""
import struct
import sys
import urllib.request
import zlib


def rng(url, start, end):
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def size_of(url):
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers["Content-Length"])


def central_dir(url):
    total = size_of(url)
    tail = rng(url, max(0, total - 65536 - 22), total - 1)
    base = total - len(tail)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        raise SystemExit("EOCD not found")
    _, _, _, _, n, cd_size, cd_off, _ = struct.unpack("<IHHHHIIH", tail[i:i + 22])
    j = tail.rfind(b"PK\x06\x07", 0, i)
    if j >= 0:  # zip64 locator
        z64_off = struct.unpack("<Q", tail[j + 8:j + 16])[0]
        rec = rng(url, z64_off, z64_off + 55)
        n, cd_size, cd_off = struct.unpack("<QQQ", rec[32:56])
    cd = rng(url, cd_off, cd_off + cd_size - 1)
    entries, p = [], 0
    while p < len(cd) and cd[p:p + 4] == b"PK\x01\x02":
        (method, csize, usize, nlen, xlen, clen, lho) = (
            struct.unpack("<H", cd[p + 10:p + 12])[0],
            *struct.unpack("<II", cd[p + 20:p + 28]),
            *struct.unpack("<HHH", cd[p + 28:p + 34]),
            struct.unpack("<I", cd[p + 42:p + 46])[0],
        )
        name = cd[p + 46:p + 46 + nlen].decode("utf-8", "replace")
        extra = cd[p + 46 + nlen:p + 46 + nlen + xlen]
        q = 0
        while q + 4 <= len(extra):
            hid, hlen = struct.unpack("<HH", extra[q:q + 4])
            if hid == 1:
                vals, k = extra[q + 4:q + 4 + hlen], 0
                if usize == 0xFFFFFFFF:
                    usize = struct.unpack("<Q", vals[k:k + 8])[0]; k += 8
                if csize == 0xFFFFFFFF:
                    csize = struct.unpack("<Q", vals[k:k + 8])[0]; k += 8
                if lho == 0xFFFFFFFF:
                    lho = struct.unpack("<Q", vals[k:k + 8])[0]
            q += 4 + hlen
        entries.append((name, method, csize, usize, lho))
        p += 46 + nlen + xlen + clen
    return entries


def main():
    url, cmd = sys.argv[1], sys.argv[2]
    entries = central_dir(url)
    if cmd == "list":
        for name, method, csize, usize, _ in entries:
            print(f"{usize:>12} {csize:>12} m{method} {name}")
        return
    member, out = sys.argv[3], sys.argv[4]
    for name, method, csize, usize, lho in entries:
        if name == member:
            hdr = rng(url, lho, lho + 29)
            nlen, xlen = struct.unpack("<HH", hdr[26:30])
            start = lho + 30 + nlen + xlen
            data = rng(url, start, start + csize - 1)
            if method == 8:
                data = zlib.decompress(data, -15)
            elif method != 0:
                raise SystemExit(f"unsupported method {method}")
            with open(out, "wb") as f:
                f.write(data)
            print(f"wrote {out} ({len(data)} bytes)")
            return
    raise SystemExit(f"{member} not in zip")


if __name__ == "__main__":
    main()
