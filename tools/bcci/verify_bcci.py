#!/usr/bin/env python3
"""verify_bcci.py - independently validate .bcci bundles written by make_bcci.py.

Checks (all read-only):
  * tar structure via Python's tarfile AND via a minimal independent ustar parser
    (512-byte headers, header checksum, 'ustar\\0' '00' magic, octal size, data
    padded to 512, end-of-archive zero blocks); both must agree on names/offsets/sizes
  * exactly one .cci, optional "<prefix> (Update).cia" / "<prefix> (DLC).cia", same prefix,
    names <= 99 bytes ASCII, regular files only, nothing else in the archive
  * each CIA: header (0x2020, type 0, version 0), 0x40 section alignment, section sizes
    adding up to the entry size, ticket (sig type, issuer, format v1, title id, content
    rights for every TMD index), TMD (size, hash tree, no Encrypted flags, title id
    category/low bits), content bitmap == contents present, content_size, SHA-256 of
    every content vs TMD, NCCH magic + NoCrypto flag
  * the .cci entry is byte-identical (size + SHA-256) to the source CCI

Usage: verify_bcci.py <file.bcci> [...] [--source X.cci] [--roms <make_bcci --roms> --out-root <make_bcci --out>]
Without --source, the source image is looked up at <roms>/<subfolder>/<bundle stem>.cci|.3ds;
without --roms the byte-identity check of the image is skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import tarfile
from pathlib import Path

BLOCK = 512
BUF = 8 << 20
SIG_SIZES = {0x010000: 0x200, 0x010001: 0x100, 0x010002: 0x3C,
             0x010003: 0x200, 0x010004: 0x100, 0x010005: 0x3C}


def align(x, a):
    return (x + a - 1) // a * a


class Fail(Exception):
    pass


class Checker:
    def __init__(self):
        self.errors = []
        self.infos = []

    def check(self, cond, msg):
        if not cond:
            self.errors.append(msg)
        return cond

    def info(self, msg):
        self.infos.append(msg)


# ---------------------------------------------------------------- ustar parser
def parse_ustar(path: Path, ck: Checker):
    members = []
    size_total = path.stat().st_size
    with open(path, "rb") as f:
        pos = 0
        zero_blocks = 0
        while True:
            hdr = f.read(BLOCK)
            if len(hdr) < BLOCK:
                ck.check(False, f"ustar: truncated header at {pos}")
                break
            if hdr == bytes(BLOCK):
                zero_blocks += 1
                pos += BLOCK
                if zero_blocks == 2:
                    break
                continue
            ck.check(zero_blocks == 0, f"ustar: stray zero block before header at {pos}")
            name = hdr[0:100].split(b"\0", 1)[0]
            size_field = hdr[124:136]
            chk_field = hdr[148:156]
            typeflag = hdr[156:157]
            magic, version = hdr[257:263], hdr[263:265]
            prefix = hdr[345:500].split(b"\0", 1)[0]
            ck.check(magic == b"ustar\0" and version == b"00",
                     f"ustar: bad magic/version {magic!r}{version!r} for {name!r}")
            ck.check(prefix == b"", f"ustar: prefix field used for {name!r}")
            ck.check(typeflag in (b"0", b"\0"), f"ustar: non-regular typeflag {typeflag!r} for {name!r}")
            try:
                size = int(size_field.strip(b" \0").decode("ascii") or "0", 8)
                chk = int(chk_field.strip(b" \0").decode("ascii"), 8)
            except ValueError:
                raise Fail(f"ustar: non-octal size/checksum for {name!r}")
            calc = sum(hdr[:148]) + 8 * 0x20 + sum(hdr[156:])
            ck.check(calc == chk, f"ustar: header checksum mismatch for {name!r}")
            data_off = pos + BLOCK
            members.append((name.decode("ascii", "replace"), data_off, size, name))
            pos = data_off + align(size, BLOCK)
            if pos > size_total:
                raise Fail(f"ustar: member {name!r} runs past end of file")
            f.seek(pos)
            # padding bytes must be zero
            if size % BLOCK:
                f.seek(data_off + size)
                ck.check(f.read(BLOCK - size % BLOCK) == bytes(BLOCK - size % BLOCK),
                         f"ustar: non-zero padding after {name!r}")
                f.seek(pos)
        rest = f.read()
        ck.check(rest == bytes(len(rest)), "ustar: non-zero data after end-of-archive marker")
    ck.check(zero_blocks == 2, "ustar: missing end-of-archive zero blocks")
    return members


# ---------------------------------------------------------------- helpers
def read_at(path, off, n):
    with open(path, "rb") as f:
        f.seek(off)
        b = f.read(n)
    if len(b) != n:
        raise Fail(f"short read at {off}+{n}")
    return b


def sha256_range(path, off, n):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        f.seek(off)
        left = n
        while left:
            b = f.read(min(BUF, left))
            if not b:
                raise Fail("short read while hashing")
            h.update(b)
            left -= len(b)
    return h.digest()


def parse_tmd(b: bytes, ck: Checker, label: str):
    sig = struct.unpack_from(">I", b, 0)[0]
    if sig not in SIG_SIZES:
        raise Fail(f"{label}: TMD unknown signature type {sig:#x}")
    h = align(4 + SIG_SIZES[sig], 0x40)
    tid = struct.unpack_from(">Q", b, h + 0x4C)[0]
    ver, count = struct.unpack_from(">HH", b, h + 0x9C)
    info_off = h + 0xC4
    ch_off = info_off + 0x900
    real = ch_off + count * 0x30
    ck.check(len(b) == real, f"{label}: TMD size {len(b):#x} != real size {real:#x}")
    ck.check(hashlib.sha256(b[info_off:ch_off]).digest() == b[h + 0xA4:h + 0xC4],
             f"{label}: TMD info-records hash mismatch")
    covered = 0
    for r in range(64):
        start, n = struct.unpack_from(">HH", b, info_off + r * 0x24)
        if not n:
            continue
        covered += n
        ck.check(hashlib.sha256(b[ch_off + start * 0x30:ch_off + (start + n) * 0x30]).digest()
                 == b[info_off + r * 0x24 + 4:info_off + r * 0x24 + 0x24],
                 f"{label}: TMD info record {r} hash mismatch")
    ck.check(covered == count, f"{label}: TMD info records cover {covered}/{count} chunks")
    chunks = []
    for i in range(count):
        o = ch_off + i * 0x30
        cid, idx, typ, size = struct.unpack_from(">IHHQ", b, o)
        chunks.append(dict(pos=i, id=cid, index=idx, type=typ, size=size, hash=b[o + 0x10:o + 0x30]))
        ck.check(not (typ & 1), f"{label}: chunk {cid:08x} still flagged Encrypted")
    return dict(tid=tid, version=ver, chunks=chunks)


def ticket_rights(ci: bytes):
    """Return function(index)->bool implementing the GodMode9/Azahar content-index logic."""
    always1, hsize, total, ihoff, ihcount, ihsize, _ = struct.unpack_from(">HHIIHHI", ci, 0)
    if always1 != 1 or hsize != 0x14 or total != len(ci) or ihsize != 0x14:
        raise Fail("ticket content index main header malformed")
    fields = []
    for i in range(ihcount):
        doff, cnt, esz, tsz, typ, _ = struct.unpack_from(">IIIIHH", ci, ihoff + i * ihsize)
        if typ != 3 or esz != 0x84:
            continue
        for j in range(cnt):
            o = doff + j * esz
            start = struct.unpack_from(">H", ci, o + 2)[0]
            fields.append((start, ci[o + 4:o + 0x84]))

    def has(idx):
        if not fields:
            return idx < 256
        for start, bits in fields:
            if idx < start:
                break
            bp = idx - start
            if bp >= 1024:
                continue
            if bits[bp // 8] & (1 << (bp % 8)):
                return True
        return False
    return has, fields


def check_cia(path: Path, off: int, size: int, kind: str, low: int | None, ck: Checker):
    label = kind
    hdr = read_at(path, off, 0x2020)
    hsize, typ, ver, cert, tik, tmd, meta, content = struct.unpack_from("<IHHIIIIQ", hdr, 0)
    ck.check(hsize == 0x2020 and typ == 0 and ver == 0,
             f"{label}: header size/type/version {hsize:#x}/{typ}/{ver}")
    ck.check(meta == 0, f"{label}: meta size {meta} (expected 0)")
    cert_off = align(hsize, 0x40)
    tik_off = align(cert_off + cert, 0x40)
    tmd_off = align(tik_off + tik, 0x40)
    content_off = align(tmd_off + tmd, 0x40)
    end = content_off + content
    if meta:
        end = align(end, 0x40) + meta
    ck.check(end == size, f"{label}: sections end at {end:#x} but entry size is {size:#x}")
    for o in (cert_off, tik_off, tmd_off, content_off):
        ck.check(o % 0x40 == 0, f"{label}: section not 0x40-aligned at {o:#x}")
    # padding between sections must be zero
    for a, b in ((0x2020, cert_off), (cert_off + cert, tik_off), (tik_off + tik, tmd_off),
                 (tmd_off + tmd, content_off)):
        if b > a:
            ck.check(read_at(path, off + a, b - a) == bytes(b - a), f"{label}: non-zero padding at {a:#x}")

    # ticket
    t = read_at(path, off + tik_off, tik)
    sig = struct.unpack_from(">I", t, 0)[0]
    ck.check(sig == 0x10004, f"{label}: ticket sig type {sig:#x}")
    body = align(4 + SIG_SIZES.get(sig, 0x100), 0x40)
    issuer = t[body:body + 0x40].split(b"\0", 1)[0]
    ck.check(issuer == b"Root-CA00000003-XS0000000c", f"{label}: ticket issuer {issuer!r}")
    ck.check(t[body + 0x7C] == 1, f"{label}: ticket format version {t[body + 0x7C]}")
    ck.check(t[body + 0x7F:body + 0x8F] == bytes(16), f"{label}: ticket title key not zero")
    ck.check(struct.unpack_from(">I", t, body + 0x98)[0] == 0, f"{label}: ticket console id not 0")
    tik_tid = struct.unpack_from(">Q", t, body + 0x9C)[0]
    tik_ver = struct.unpack_from(">H", t, body + 0xA6)[0]
    ci = t[body + 0x164:]
    ci_size = struct.unpack_from(">I", ci, 4)[0]
    ck.check(ci_size == len(ci), f"{label}: ticket content index size {ci_size} != remaining {len(ci)}")
    has_right, fields = ticket_rights(ci[:ci_size])

    # TMD
    tm = parse_tmd(read_at(path, off + tmd_off, tmd), ck, label)
    ck.check(tm["tid"] == tik_tid, f"{label}: ticket TID {tik_tid:016X} != TMD TID {tm['tid']:016X}")
    ck.check(tm["version"] == tik_ver, f"{label}: ticket version {tik_ver} != TMD version {tm['version']}")
    want_high = {"Update": 0x0004000E, "DLC": 0x0004008C}[kind]
    ck.check(tm["tid"] >> 32 == want_high, f"{label}: TMD TID {tm['tid']:016X} wrong category")
    if low is not None:
        ck.check(tm["tid"] & 0xFFFFFFFF == low,
                 f"{label}: TMD TID {tm['tid']:016X} does not match CCI low {low:08X}")
    for c in tm["chunks"]:
        ck.check(has_right(c["index"]), f"{label}: ticket gives no right to content index {c['index']}")

    # bitmap / contents
    bitmap = hdr[0x20:0x2020]
    present = [c for c in tm["chunks"] if bitmap[c["index"] >> 3] & (0x80 >> (c["index"] & 7))]
    known = {c["index"] for c in tm["chunks"]}
    for byte_i, byte in enumerate(bitmap):
        if byte:
            for bit in range(8):
                if byte & (0x80 >> bit):
                    ck.check(byte_i * 8 + bit in known,
                             f"{label}: bitmap bit {byte_i * 8 + bit} set for index not in TMD")
    ck.check(sum(c["size"] for c in present) == content,
             f"{label}: content_size {content} != sum of present contents")
    pos_based = [c for c in tm["chunks"] if bitmap[c["pos"] >> 3] & (0x80 >> (c["pos"] & 7))]
    if [c["pos"] for c in pos_based] != [c["pos"] for c in present]:
        ck.info(f"{label}: NOTE bitmap by index differs from bitmap by position "
                f"(Azahar's CIAContainer indexes by position)")
    o = off + content_off
    for c in present:
        head = read_at(path, o, 0x200)
        ck.check(head[0x100:0x104] == b"NCCH", f"{label}: content {c['id']:08x} lacks NCCH magic")
        ck.check(bool(head[0x18F] & 0x04), f"{label}: content {c['id']:08x} NCCH not NoCrypto")
        ck.check(sha256_range(path, o, c["size"]) == c["hash"],
                 f"{label}: content {c['id']:08x} SHA-256 mismatch")
        o += c["size"]
    ck.info(f"{label}: TID {tm['tid']:016X} v{tm['version']}, {len(present)}/{len(tm['chunks'])} contents, "
            f"cert {cert} B, ticket {tik} B ({len(fields)} rights field(s)), TMD {tmd} B, "
            f"content {content:,} B")


def find_source(bcci: Path, roms: Path | None, out_root: Path | None) -> Path | None:
    if roms is None:
        return None
    if out_root is None:
        out_root = bcci.resolve().parent.parent
    try:
        rel = bcci.resolve().parent.relative_to(out_root.resolve())
    except ValueError:
        rel = Path(bcci.parent.name)
    for ext in (".cci", ".3ds"):
        cand = roms / rel / (bcci.stem + ext)
        if cand.is_file():
            return cand
    return None


def verify(bcci: Path, source: Path | None, roms: Path | None, out_root: Path | None) -> bool:
    ck = Checker()
    print(f"== {bcci}  ({bcci.stat().st_size:,} bytes)")
    try:
        # 1. Python tarfile
        with tarfile.open(bcci, "r:") as tf:
            tmembers = tf.getmembers()
            for m in tmembers:
                ck.check(m.isreg(), f"tarfile: {m.name} not a regular file")
                ck.check(not m.pax_headers, f"tarfile: {m.name} has pax headers")
        # 2. independent parser
        umembers = parse_ustar(bcci, ck)
        ck.check([(m.name, m.offset_data, m.size) for m in tmembers] ==
                 [(n, o, s) for n, o, s, _ in umembers],
                 "tarfile and ustar parser disagree on members")
        names = [n for n, _, _, _ in umembers]
        for n, _, _, raw in umembers:
            ck.check(len(raw) <= 99, f"name > 99 bytes: {n}")
            ck.check(all(32 <= c < 127 for c in raw), f"name not printable ASCII: {n!r}")
            ck.check("/" not in n and "\\" not in n, f"name not at root: {n}")
        ccis = [m for m in umembers if m[0].endswith(".cci")]
        if not ck.check(len(ccis) == 1, f"expected exactly 1 .cci entry, got {len(ccis)}"):
            raise Fail("cannot continue")
        prefix = ccis[0][0][:-4]
        allowed = {prefix + ".cci", prefix + " (Update).cia", prefix + " (DLC).cia"}
        for n in names:
            ck.check(n in allowed, f"unexpected entry {n!r} (prefix {prefix!r})")
        ck.check(len(set(names)) == len(names), "duplicate entry names")
        ck.info("entries: " + ", ".join(f"{n} [{s:,}]" for n, _, s, _ in umembers))

        # 3. CCI
        _, coff, csize, _ = ccis[0]
        ncsd = read_at(bcci, coff, 0x200)
        ck.check(ncsd[0x100:0x104] == b"NCSD", "cci entry lacks NCSD magic")
        p0 = struct.unpack_from("<I", ncsd, 0x120)[0] * 0x200
        ncch = read_at(bcci, coff + p0, 0x200)
        ck.check(ncch[0x100:0x104] == b"NCCH", "cci partition 0 lacks NCCH magic")
        pid = struct.unpack_from("<Q", ncch, 0x118)[0]
        ck.info(f"cci program id {pid:016X}")
        low = pid & 0xFFFFFFFF
        src = source or find_source(bcci, roms, out_root)
        if src is None and roms is None:
            ck.info("cci not compared with a source image (no --source or --roms given)")
        elif ck.check(src is not None and src.is_file(), "source CCI not found (use --source)"):
            ck.check(src.stat().st_size == csize, f"cci size {csize} != source {src.stat().st_size}")
            h_entry = sha256_range(bcci, coff, csize)
            h_src = sha256_range(src, 0, src.stat().st_size)
            ck.check(h_entry == h_src, "cci SHA-256 differs from source")
            ck.info(f"cci identical to {src} (sha256 {h_src.hex()[:16]}...)")

        # 4. CIAs
        for n, o, s, _ in umembers:
            if n == prefix + " (Update).cia":
                check_cia(bcci, o, s, "Update", low, ck)
            elif n == prefix + " (DLC).cia":
                check_cia(bcci, o, s, "DLC", low, ck)
    except Fail as e:
        ck.errors.append(str(e))
    except Exception as e:  # noqa: BLE001
        ck.errors.append(f"exception: {type(e).__name__}: {e}")
    for m in ck.infos:
        print("   " + m)
    for e in ck.errors:
        print("   FAIL: " + e)
    print("   RESULT: " + ("PASS" if not ck.errors else f"FAIL ({len(ck.errors)} problem(s))"))
    return not ck.errors


def main(argv=None):
    try:
        sys.stdout.reconfigure(errors="replace", line_buffering=True)
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("bcci", nargs="+")
    ap.add_argument("--source", help="source .cci (only with a single bundle)")
    ap.add_argument("--roms", help="make_bcci's --roms, to find each bundle's source image")
    ap.add_argument("--out-root", help="make_bcci's --out (default: each bundle's parent's parent)")
    a = ap.parse_args(argv)
    if a.source and len(a.bcci) != 1:
        ap.error("--source needs exactly one bundle")
    ok = True
    for b in a.bcci:
        ok &= verify(Path(b), Path(a.source) if a.source else None,
                     Path(a.roms) if a.roms else None, Path(a.out_root) if a.out_root else None)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
