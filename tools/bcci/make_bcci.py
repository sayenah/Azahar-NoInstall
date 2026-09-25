#!/usr/bin/env python3
r"""make_bcci.py - bundle a 3DS CCI game image with its installed update and DLC.

For every decrypted CCI (NCSD) image (.cci/.3ds) under --roms this tool looks up
the update (0004000E:<low>) and DLC (0004008C:<low>) titles installed by Azahar
under --title-root, rebuilds each of them into a standard CIA (generated ticket, TMD
with the Encrypted flags cleared and its hash tree recomputed, decrypted
contents), verifies every content against its TMD SHA-256, and writes one
uncompressed, strictly-USTAR tar ("<Game>.bcci") containing:

    <Game>.cci             the original image, byte for byte
    <Game> (Update).cia    if an update is installed
    <Game> (DLC).cia       if DLC is installed

Inputs are only ever opened for reading. Standard library only.

Example (Windows, portable Azahar):
    python make_bcci.py --roms E:\ROMs\n3ds --title-root E:\Azahar\user --out D:\bundles
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import re
import struct
import sys
import tarfile
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

# Azahar's emulated SD card keeps installed titles under this path (the two
# ID folders are all zeros in the emulator).
SDMC_TITLE_SUBPATH = Path("Nintendo 3DS", "0" * 32, "0" * 32, "title")

ROM_EXTENSIONS = {".cci", ".3ds"}

MEDIA_UNIT = 0x200
CIA_ALIGN = 0x40
CIA_HEADER_SIZE = 0x2020
TAR_BLOCK = 512
TAR_RECORD = 20 * TAR_BLOCK
MAX_TAR_NAME = 99

TID_HIGH_APP = 0x00040000
TID_HIGH_UPDATE = 0x0004000E
TID_HIGH_DLC = 0x0004008C

TMD_TYPE_ENCRYPTED = 0x0001
TMD_TYPE_OPTIONAL = 0x4000

SIG_SIZES = {0x010000: 0x200, 0x010001: 0x100, 0x010002: 0x3C,
             0x010003: 0x200, 0x010004: 0x100, 0x010005: 0x3C}

TICKET_ISSUER = b"Root-CA00000003-XS0000000c"
HASH_BUF = 8 << 20


def align(x: int, a: int) -> int:
    return (x + a - 1) // a * a


def fmt_version(v: int) -> str:
    return f"v{v} ({v >> 10}.{(v >> 4) & 0x3F}.{v & 0xF})"


# --------------------------------------------------------------------------
# Safety: never write outside the allowed area.
# --------------------------------------------------------------------------
def assert_writable(path: Path, forbidden_roots: list[Path],
                    read_only_drives: set[str] = frozenset()) -> None:
    p = Path(os.path.abspath(path))
    drive = (p.drive or "").upper()
    if drive and drive in read_only_drives:
        raise SystemExit(f"REFUSING to write to {p}: drive {drive} is read-only for this tool")
    for root in forbidden_roots:
        r = Path(os.path.abspath(root))
        try:
            p.relative_to(r)
            raise SystemExit(f"REFUSING to write to {p}: inside input tree {r}")
        except ValueError:
            pass


# --------------------------------------------------------------------------
# CCI / NCSD
# --------------------------------------------------------------------------
@dataclass
class CCIInfo:
    path: Path
    subfolder: str
    size: int
    media_id: int
    program_id: int
    ncch_nocrypto: bool
    error: str = ""

    @property
    def low(self) -> int:
        return self.program_id & 0xFFFFFFFF

    @property
    def high(self) -> int:
        return self.program_id >> 32


def read_cci(path: Path, subfolder: str) -> CCIInfo:
    size = path.stat().st_size
    with open(path, "rb") as f:
        hdr = f.read(0x200)
        if len(hdr) < 0x200 or hdr[0x100:0x104] != b"NCSD":
            return CCIInfo(path, subfolder, size, 0, 0, False, "no NCSD magic")
        media_id = struct.unpack_from("<Q", hdr, 0x108)[0]
        p0_off, p0_len = struct.unpack_from("<II", hdr, 0x120)
        if p0_len == 0:
            return CCIInfo(path, subfolder, size, media_id, 0, False, "partition 0 empty")
        f.seek(p0_off * MEDIA_UNIT)
        ncch = f.read(0x200)
    if len(ncch) < 0x200 or ncch[0x100:0x104] != b"NCCH":
        return CCIInfo(path, subfolder, size, media_id, 0, False, "partition 0 has no NCCH magic")
    program_id = struct.unpack_from("<Q", ncch, 0x118)[0]
    nocrypto = bool(ncch[0x188 + 7] & 0x04)
    err = ""
    if program_id != media_id:
        err = f"NCSD media id {media_id:016X} != NCCH program id {program_id:016X}"
    return CCIInfo(path, subfolder, size, media_id, program_id, nocrypto, err)


# --------------------------------------------------------------------------
# TMD
# --------------------------------------------------------------------------
@dataclass
class Chunk:
    pos: int
    cid: int
    index: int
    type: int
    size: int
    hash: bytes


@dataclass
class TMD:
    raw: bytes            # trimmed to real size
    file_size: int        # size of the file on disk
    sig_type: int
    hdr_off: int
    title_id: int
    title_version: int
    chunks: list[Chunk]
    hash_tree_ok: bool
    hash_tree_msg: str

    @property
    def real_size(self) -> int:
        return len(self.raw)


def parse_tmd(data: bytes) -> TMD:
    if len(data) < 4:
        raise ValueError("TMD too small")
    sig_type = struct.unpack_from(">I", data, 0)[0]
    if sig_type not in SIG_SIZES:
        raise ValueError(f"unknown TMD signature type 0x{sig_type:X}")
    hdr = align(4 + SIG_SIZES[sig_type], 0x40)
    if len(data) < hdr + 0xC4 + 0x900:
        raise ValueError("TMD truncated before content chunks")
    title_id = struct.unpack_from(">Q", data, hdr + 0x4C)[0]
    title_version, count = struct.unpack_from(">HH", data, hdr + 0x9C)
    chunk_off = hdr + 0xC4 + 0x900
    real = chunk_off + count * 0x30
    if len(data) < real:
        raise ValueError(f"TMD truncated: need 0x{real:X}, have 0x{len(data):X}")
    chunks = []
    for i in range(count):
        o = chunk_off + i * 0x30
        cid, idx, ctype, csize = struct.unpack_from(">IHHQ", data, o)
        chunks.append(Chunk(i, cid, idx, ctype, csize, bytes(data[o + 0x10:o + 0x30])))
    ok, msg = check_tmd_hash_tree(data[:real], hdr, count)
    return TMD(bytes(data[:real]), len(data), sig_type, hdr, title_id, title_version,
               chunks, ok, msg)


def check_tmd_hash_tree(data: bytes, hdr: int, count: int) -> tuple[bool, str]:
    info_off = hdr + 0xC4
    chunk_off = info_off + 0x900
    info = data[info_off:chunk_off]
    problems = []
    if hashlib.sha256(info).digest() != data[hdr + 0xA4:hdr + 0xC4]:
        problems.append("header info-records hash mismatch")
    covered = 0
    for r in range(64):
        o = r * 0x24
        start, n = struct.unpack_from(">HH", info, o)
        if n == 0:
            continue
        if start + n > count:
            problems.append(f"info record {r} covers chunks {start}..{start + n - 1} > count {count}")
            continue
        h = hashlib.sha256(data[chunk_off + start * 0x30:chunk_off + (start + n) * 0x30]).digest()
        if h != info[o + 4:o + 0x24]:
            problems.append(f"info record {r} hash mismatch")
        covered += n
    if covered != count:
        problems.append(f"info records cover {covered} of {count} chunks")
    return (not problems), "; ".join(problems)


def fixed_tmd_bytes(tmd: TMD) -> bytes:
    """TMD with Encrypted flags cleared and its hash tree recomputed."""
    d = bytearray(tmd.raw)
    hdr = tmd.hdr_off
    info_off = hdr + 0xC4
    chunk_off = info_off + 0x900
    count = len(tmd.chunks)
    for i in range(count):
        o = chunk_off + i * 0x30 + 6
        t = struct.unpack_from(">H", d, o)[0]
        struct.pack_into(">H", d, o, t & ~TMD_TYPE_ENCRYPTED)
    for r in range(64):
        o = info_off + r * 0x24
        start, n = struct.unpack_from(">HH", d, o)
        if n == 0:
            continue
        n = min(n, max(0, count - start))
        d[o + 4:o + 0x24] = hashlib.sha256(
            bytes(d[chunk_off + start * 0x30:chunk_off + (start + n) * 0x30])).digest()
    d[hdr + 0xA4:hdr + 0xC4] = hashlib.sha256(bytes(d[info_off:chunk_off])).digest()
    ok, msg = check_tmd_hash_tree(bytes(d), hdr, count)
    if not ok:
        raise ValueError("recomputed TMD hash tree still inconsistent: " + msg)
    return bytes(d)


# --------------------------------------------------------------------------
# Ticket
# --------------------------------------------------------------------------
def build_ticket(title_id: int, title_version: int, max_index: int) -> bytes:
    """Format-v1 common ticket, zeroed RSA-2048/SHA-256 signature, zero title key,
    content index granting every content index 0..(n*1024-1)."""
    sig = struct.pack(">I", 0x00010004) + bytes(0x100) + bytes(0x3C)   # body at 0x140
    body = bytearray(0x164)
    body[0:len(TICKET_ISSUER)] = TICKET_ISSUER
    body[0x7C] = 1                                   # ticket format version
    # 0x7F title key: zero (content is decrypted)
    # 0x90 ticket id: 0, 0x98 console id: 0 (common ticket)
    struct.pack_into(">Q", body, 0x9C, title_id)
    struct.pack_into(">H", body, 0xA6, title_version)
    body[0xB0] = 0                                   # license type
    body[0xB1] = 0                                   # common keyY index (eShop)
    n = max_index // 1024 + 1                        # rights fields of 1024 bits each
    total = 0x14 + 0x14 + 0x84 * n
    ci = struct.pack(">HHIIHHI", 1, 0x14, total, 0x14, 1, 0x14, 0)          # main header
    ci += struct.pack(">IIIIHH", 0x28, n, 0x84, 0x84 * n, 3, 0)            # index header
    for k in range(n):
        ci += struct.pack(">HH", 0, k * 1024) + b"\xFF" * 0x80              # rights field
    assert len(ci) == total
    return sig + bytes(body) + ci


# --------------------------------------------------------------------------
# Installed titles (update / DLC)
# --------------------------------------------------------------------------
@dataclass
class ContentFile:
    chunk: Chunk
    path: Path | None       # None -> not present


@dataclass
class InstalledTitle:
    kind: str               # "Update" or "DLC"
    title_id: int
    folder: Path
    tmd_path: Path | None = None
    tmd: TMD | None = None
    contents: list[ContentFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    verified: bool = False

    @property
    def present(self) -> list[ContentFile]:
        return [c for c in self.contents if c.path is not None]

    @property
    def usable(self) -> bool:
        return self.tmd is not None and not self.errors and bool(self.present)

    def summary(self) -> str:
        if self.tmd is None:
            return "unreadable"
        s = fmt_version(self.tmd.title_version)
        if self.kind == "DLC":
            s += f" {len(self.present)}/{len(self.contents)} contents"
        return s

    def input_mtime(self) -> float:
        m = self.tmd_path.stat().st_mtime if self.tmd_path else 0.0
        for c in self.present:
            m = max(m, c.path.stat().st_mtime)
        return m


def locate_contents(folder: Path, tmd: TMD) -> tuple[list[ContentFile], list[str]]:
    content_dir = folder / "content"
    sub = content_dir / "00000000"
    # Azahar puts contents in content/00000000/ when chunk 1 is Optional (DLC).
    use_sub = len(tmd.chunks) > 1 and bool(tmd.chunks[1].type & TMD_TYPE_OPTIONAL)
    primary, secondary = (sub, content_dir) if use_sub else (content_dir, sub)
    notes = []
    out = []
    for ch in tmd.chunks:
        name = f"{ch.cid:08x}.app"
        p = primary / name
        if p.is_file():
            out.append(ContentFile(ch, p))
        elif (secondary / name).is_file():
            out.append(ContentFile(ch, secondary / name))
            notes.append(f"content {name} found in unexpected folder {secondary.name}")
        else:
            out.append(ContentFile(ch, None))
    return out, notes


def load_installed(kind: str, folder: Path, high: int) -> InstalledTitle:
    low = int(folder.name, 16)
    t = InstalledTitle(kind, (high << 32) | low, folder)
    content_dir = folder / "content"
    tmds = sorted(content_dir.glob("*.tmd")) if content_dir.is_dir() else []
    if not tmds:
        t.errors.append("no .tmd found")
        return t
    candidates = []
    for p in tmds:
        try:
            data = p.read_bytes()
            tmd = parse_tmd(data)
        except Exception as e:  # noqa: BLE001
            t.notes.append(f"{p.name}: unparsable ({e})")
            continue
        contents, notes = locate_contents(folder, tmd)
        npresent = sum(1 for c in contents if c.path is not None)
        candidates.append((tmd.title_version, npresent, p, tmd, contents, notes))
    if not candidates:
        t.errors.append("no parsable .tmd")
        return t
    # Current TMD: highest title version; tie -> most contents present.
    candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
    ver, npresent, p, tmd, contents, notes = candidates[0]
    if len(tmds) > 1:
        desc = ", ".join(f"{c[2].name}=v{c[0]}({c[1]}/{len(c[3].chunks)} present)" for c in candidates)
        t.notes.append(f"MULTIPLE TMDs: {desc}; using {p.name}")
    t.tmd_path, t.tmd, t.contents = p, tmd, contents
    t.notes.extend(notes)

    if tmd.title_id != t.title_id:
        t.errors.append(f"TMD title id {tmd.title_id:016X} != folder {t.title_id:016X}")
    if tmd.file_size != tmd.real_size:
        t.notes.append(f"TMD file has {tmd.file_size - tmd.real_size} trailing bytes (trimmed)")
    if not tmd.hash_tree_ok:
        t.notes.append("original TMD hash tree inconsistent: " + tmd.hash_tree_msg + " (recomputed)")
    enc = sum(1 for c in tmd.chunks if c.type & TMD_TYPE_ENCRYPTED)
    if enc:
        t.notes.append(f"{enc}/{len(tmd.chunks)} TMD chunks flagged Encrypted (flag cleared)")
    if any(c.index != c.pos for c in tmd.chunks):
        t.notes.append("TMD chunk index != chunk position for some chunks "
                       "(CIA bitmap follows the index field)")
    idxs = [c.index for c in tmd.chunks]
    if len(set(idxs)) != len(idxs):
        t.errors.append("duplicate content index in TMD")
    for c in contents:
        if c.path is not None and c.path.stat().st_size != c.chunk.size:
            t.errors.append(f"{c.path.name}: size {c.path.stat().st_size} != TMD size {c.chunk.size}")
        if c.chunk.size % CIA_ALIGN:
            t.notes.append(f"content {c.chunk.cid:08x} size not a multiple of 0x40")
    missing = [c for c in contents if c.path is None]
    if kind == "Update" and missing:
        t.errors.append(f"update missing {len(missing)} of {len(contents)} contents")
    if kind == "DLC":
        if missing:
            t.notes.append(f"partial DLC: {len(contents) - len(missing)}/{len(contents)} contents present")
        if contents and contents[0].path is None:
            t.errors.append("DLC content index 0 (the DLC base content) is missing")
    # stray .app files not referenced by the chosen TMD
    referenced = {c.path.resolve() for c in contents if c.path is not None}
    stray = [q for q in content_dir.rglob("*.app") if q.resolve() not in referenced]
    if stray:
        t.notes.append(f"{len(stray)} .app file(s) not referenced by the TMD (ignored)")
    return t


def verify_title_contents(t: InstalledTitle, log) -> None:
    """SHA-256 + NCCH NoCrypto check of every present content. Sets errors."""
    for c in t.present:
        with open(c.path, "rb") as f:
            head = f.read(0x200)
            h = hashlib.sha256(head)
            while True:
                b = f.read(HASH_BUF)
                if not b:
                    break
                h.update(b)
        if h.digest() != c.chunk.hash:
            t.errors.append(f"{c.path.name}: SHA-256 mismatch vs TMD")
        if len(head) < 0x200 or head[0x100:0x104] != b"NCCH":
            t.errors.append(f"{c.path.name}: no NCCH magic at 0x100 (encrypted or not NCCH)")
        elif not (head[0x188 + 7] & 0x04):
            t.errors.append(f"{c.path.name}: NCCH NoCrypto flag not set (still encrypted?)")
    t.verified = True
    if t.errors:
        log(f"    !! {t.kind} {t.title_id:016X} failed verification: " + "; ".join(t.errors))


def describe_title(t: InstalledTitle) -> tuple[str, str]:
    """(product code, English short title) read from the title's first content, best effort."""
    first = next((c for c in t.contents if c.path is not None), None)
    if first is None:
        return "", ""
    try:
        with open(first.path, "rb") as f:
            h = f.read(0x200)
            if h[0x100:0x104] != b"NCCH":
                return "", ""
            code = "".join(ch for ch in h[0x150:0x160].split(b"\0", 1)[0].decode("ascii", "replace")
                           if ch.isprintable() and ch != "\ufffd")
            exefs_off, exefs_size = struct.unpack_from("<II", h, 0x1A0)
            name = ""
            if exefs_off and exefs_size:
                f.seek(exefs_off * MEDIA_UNIT)
                eh = f.read(0x200)
                for i in range(10 if len(eh) == 0x200 else 0):
                    fn = eh[i * 16:i * 16 + 8].rstrip(b"\0")
                    off, size = struct.unpack_from("<II", eh, i * 16 + 8)
                    if fn == b"icon" and size >= 0x8 + 0x200 * 2:
                        f.seek(exefs_off * MEDIA_UNIT + 0x200 + off)
                        smdh = f.read(0x8 + 0x200 * 2)
                        if smdh[:4] == b"SMDH":
                            raw = smdh[0x8 + 0x200:0x8 + 0x200 + 0x80]   # English short description
                            name = raw.decode("utf-16-le", "replace").split("\0", 1)[0]
                            name = " ".join(name.split())
                        break
            return code, name
    except (OSError, struct.error, ValueError):
        return "", ""


def scan_installed(title_root: Path) -> dict[tuple[str, int], InstalledTitle]:
    res = {}
    for kind, high, sub in (("Update", TID_HIGH_UPDATE, "0004000e"), ("DLC", TID_HIGH_DLC, "0004008c")):
        d = title_root / sub
        if not d.is_dir():
            continue
        for folder in sorted(d.iterdir()):
            if folder.is_dir() and re.fullmatch(r"[0-9a-fA-F]{8}", folder.name):
                t = load_installed(kind, folder, high)
                res[(kind, t.title_id & 0xFFFFFFFF)] = t
    return res


# --------------------------------------------------------------------------
# CIA stream
# --------------------------------------------------------------------------
class SegmentStream(io.RawIOBase):
    """Read-only stream over a list of in-memory blobs and file ranges.
    File segments may carry an expected SHA-256 that is re-checked while streaming."""

    def __init__(self, segments):
        super().__init__()
        self.segments = segments          # list of (bytes) or (Path, size, expected_hash)
        self.i = 0
        self.pos_in_seg = 0
        self.fh = None
        self.hasher = None

    def readable(self):
        return True

    def _seg_len(self, s):
        return len(s) if isinstance(s, (bytes, bytearray)) else s[1]

    def read(self, n=-1):
        if n is None or n < 0:
            n = 1 << 62
        out = bytearray()
        while n > 0 and self.i < len(self.segments):
            s = self.segments[self.i]
            remaining = self._seg_len(s) - self.pos_in_seg
            if remaining == 0:
                self._finish_seg()
                continue
            k = min(n, remaining)
            if isinstance(s, (bytes, bytearray)):
                out += s[self.pos_in_seg:self.pos_in_seg + k]
            else:
                if self.fh is None:
                    self.fh = open(s[0], "rb")
                    self.hasher = hashlib.sha256()
                b = self.fh.read(k)
                if len(b) != k:
                    raise IOError(f"short read from {s[0]}")
                self.hasher.update(b)
                out += b
            self.pos_in_seg += k
            n -= k
            if self.pos_in_seg == self._seg_len(s):
                self._finish_seg()      # closes file and checks its hash immediately
        return bytes(out)

    def _finish_seg(self):
        s = self.segments[self.i]
        if not isinstance(s, (bytes, bytearray)):
            if self.fh is not None:
                self.fh.close()
                self.fh = None
            if s[2] is not None and (self.hasher is None or self.hasher.digest() != s[2]):
                raise IOError(f"SHA-256 changed while streaming {s[0]}")
        self.i += 1
        self.pos_in_seg = 0
        self.hasher = None

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None
        super().close()


def pad_to(n: int, a: int = CIA_ALIGN) -> bytes:
    return bytes(align(n, a) - n)


def build_cia(t: InstalledTitle) -> tuple[int, list]:
    """Return (total size, segments) for the CIA of an installed title."""
    tmd_bytes = fixed_tmd_bytes(t.tmd)
    present = t.present
    ticket = build_ticket(t.title_id, t.tmd.title_version,
                          max(c.index for c in t.tmd.chunks))
    cert = b""
    content_size = sum(c.chunk.size for c in present)
    hdr = bytearray(CIA_HEADER_SIZE)
    struct.pack_into("<IHHIIIIQ", hdr, 0, CIA_HEADER_SIZE, 0, 0, len(cert), len(ticket),
                     len(tmd_bytes), 0, content_size)
    for c in present:
        idx = c.chunk.index
        hdr[0x20 + (idx >> 3)] |= 0x80 >> (idx & 7)
    segs = []
    off = 0

    def add(b: bytes):
        nonlocal off
        segs.append(b)
        off += len(b)

    add(bytes(hdr)); add(pad_to(off))
    add(cert); add(pad_to(off))
    add(ticket); add(pad_to(off))
    add(tmd_bytes); add(pad_to(off))
    for c in present:              # TMD chunk order
        segs.append((c.path, c.chunk.size, c.chunk.hash))
        off += c.chunk.size
    segs = [s for s in segs if not (isinstance(s, bytes) and len(s) == 0)]
    return off, segs


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------
SUFFIXES = {"cci": ".cci", "Update": " (Update).cia", "DLC": " (DLC).cia"}
MAX_STEM = MAX_TAR_NAME - max(len(s) for s in SUFFIXES.values())   # 86


def to_ascii(s: str) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"[\x00-\x1f\\/]", "_", s)
    return s


def entry_stem(stem: str) -> tuple[str, bool]:
    """ASCII stem that fits MAX_STEM bytes. Returns (stem, changed)."""
    orig = stem
    s = to_ascii(stem)
    if len(s) > MAX_STEM:
        # GodMode9-style dump names: "<TID> Title ... CTR-P-XXXX v0.0.0 J.standard Game-decrypted"
        s = re.sub(r"^[0-9A-Fa-f]{16}\s+", "", s)
        s = re.sub(r"\s+Game-decrypted$", "", s)
        s = re.sub(r"\s+[A-Z]\.standard$", "", s)
        s = re.sub(r"\s+v\d+\.\d+\.\d+$", "", s)
        s = re.sub(r"\s+CTR-[A-Z]-[A-Z0-9]{4}$", "", s)
    if len(s) > MAX_STEM:
        # drop trailing parenthetical tags beyond the first, then truncate at a word boundary
        while len(s) > MAX_STEM and re.search(r"\([^()]*\)[^()]*\([^()]*\)\s*$", s):
            s = re.sub(r"\s*\([^()]*\)\s*$", "", s)
    if len(s) > MAX_STEM:
        # keep the (short) tag block, e.g. " (USA) (En,Fr)", and word-truncate the title part
        m = re.match(r"^(.*?)(\s+\(.*)$", s)
        title, tags = (m.group(1), m.group(2)) if m else (s, "")
        if len(tags) > MAX_STEM // 2:
            title, tags = s, ""
        room = MAX_STEM - len(tags)
        cut = title[:room]
        sp = cut.rfind(" ")
        if len(title) > room and sp > room // 2:
            cut = cut[:sp]
        s = cut.rstrip(" .-_,") + tags
    s = s.rstrip(" .-_,")
    if not s:
        s = "game"
    return s, s != orig


# --------------------------------------------------------------------------
# Bundle writing
# --------------------------------------------------------------------------
def tar_size(sizes: list[int]) -> int:
    n = sum(TAR_BLOCK + align(s, TAR_BLOCK) for s in sizes) + 2 * TAR_BLOCK
    return align(n, TAR_RECORD)


def write_bundle(out_path: Path, entries: list[tuple[str, int, object, float]], log) -> None:
    partial = out_path.with_name(out_path.name + ".partial")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(partial, "wb") as raw:
            tf = tarfile.TarFile(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT,
                                 copybufsize=HASH_BUF, encoding="ascii", errors="strict")
            for name, size, opener, mtime in entries:
                ti = tarfile.TarInfo(name)
                ti.size = size
                ti.mtime = int(mtime)
                ti.mode = 0o644
                ti.type = tarfile.REGTYPE
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                t0 = time.time()
                with opener() as src:
                    tf.addfile(ti, src)
                log(f"    + {name}  ({size:,} bytes, {time.time() - t0:.1f}s)")
            tf.close()
        os.replace(partial, out_path)
    except BaseException:
        try:
            partial.unlink()
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
CATEGORIES = ["Base Set", "Digital", "Japan", "Translations", "Virtual Console"]


def find_ccis(roms: Path) -> list[tuple[str, Path]]:
    res = []
    subs = sorted([d for d in roms.iterdir() if d.is_dir()],
                  key=lambda d: (CATEGORIES.index(d.name) if d.name in CATEGORIES else 99, d.name))
    for d in subs:
        for f in sorted(d.iterdir(), key=lambda p: p.name.lower()):
            if f.is_file() and f.suffix.lower() in ROM_EXTENSIONS:
                res.append((d.name, f))
    for f in sorted(roms.iterdir()):
        if f.is_file() and f.suffix.lower() in ROM_EXTENSIONS:
            res.append(("", f))
    return res


def resolve_title_root(path: Path) -> Path:
    """Accepts the 'title' folder, the 'sdmc' folder or Azahar's user folder."""
    for cand in (path, path / SDMC_TITLE_SUBPATH, path / "sdmc" / SDMC_TITLE_SUBPATH):
        if (cand / "0004000e").is_dir() or (cand / "0004008c").is_dir():
            return cand
    raise SystemExit(f"No installed updates or DLC (0004000e/0004008c folders) found under {path}")


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace", line_buffering=True)
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--roms", required=True,
                    help="folder of decrypted .cci/.3ds images (one level of subfolders is scanned)")
    ap.add_argument("--title-root", required=True,
                    help="Azahar's installed-title folder: the 'title' folder itself, the 'sdmc' "
                         "folder, or Azahar's user folder")
    ap.add_argument("--out", required=True, help="output folder (mirrors the --roms subfolders)")
    ap.add_argument("--report", help="CSV report path, written in every mode (default: <out>/report.csv)")
    ap.add_argument("--read-only-drive", action="append", default=[], metavar="DRIVE",
                    help="refuse to write anything to this drive, e.g. E: (repeatable)")
    ap.add_argument("--only", action="append", default=[],
                    help="only games whose file name contains this substring (repeatable, case-insensitive)")
    ap.add_argument("--all", action="store_true", help="also bundle games with no update and no DLC")
    ap.add_argument("--dry-run", action="store_true", help="plan only: no hashing, no writing of bundles")
    ap.add_argument("--verify-only", action="store_true",
                    help="hash-verify update/DLC contents, write the report, but no bundles")
    ap.add_argument("--force", action="store_true", help="rebuild even if the output is up to date")
    ap.add_argument("--allow-translation-updates", action="store_true",
                    help="also bundle translated ROMs (folder or file name containing 'translat') "
                         "with the original-language "
                         "update/DLC sharing their title ID; skipped by default because the update's "
                         "RomFS may override the translation")
    args = ap.parse_args(argv)

    roms, title_root, out = Path(args.roms), resolve_title_root(Path(args.title_root)), Path(args.out)
    report = Path(args.report) if args.report else out / "report.csv"
    forbidden = [roms, title_root]
    read_only_drives = {d.upper().rstrip("\\/") for d in args.read_only_drive}
    assert_writable(out, forbidden, read_only_drives)
    assert_writable(report, forbidden, read_only_drives)

    def log(msg):
        print(msg, flush=True)

    t_start = time.time()
    log(f"Scanning installed titles in {title_root} ...")
    installed = scan_installed(title_root)
    log(f"  {sum(1 for k in installed if k[0] == 'Update')} updates, "
        f"{sum(1 for k in installed if k[0] == 'DLC')} DLC")

    ccis = find_ccis(roms)
    log(f"Found {len(ccis)} CCI files under {roms}")
    infos = []
    for sub, p in ccis:
        try:
            infos.append(read_cci(p, sub))
        except OSError as e:
            infos.append(CCIInfo(p, sub, 0, 0, 0, False, f"read error: {e}"))

    by_low: dict[int, list[CCIInfo]] = {}
    for ci in infos:
        if ci.program_id:
            by_low.setdefault(ci.low, []).append(ci)

    only = [s.lower() for s in args.only]
    rows = []
    counts = dict(built=0, uptodate=0, planned=0, failed=0, skipped=0)
    mode = "dry-run" if args.dry_run else ("verify-only" if args.verify_only else "build")
    log(f"Mode: {mode}\n")

    for ci in infos:
        name = ci.path.name
        stem = ci.path.stem
        selected = not only or any(s in name.lower() for s in only)
        upd = installed.get(("Update", ci.low)) if ci.program_id else None
        dlc = installed.get(("DLC", ci.low)) if ci.program_id else None
        notes = []
        if ci.error:
            notes.append(ci.error)
        if ci.program_id and ci.high != TID_HIGH_APP:
            notes.append(f"program id high {ci.high:08X} is not 00040000")
        if ci.program_id and not ci.ncch_nocrypto:
            notes.append("CCI partition 0 NCCH is not flagged NoCrypto")
        dups = [o for o in by_low.get(ci.low, []) if o is not ci] if ci.program_id else []
        if dups:
            notes.append("same TID as: " + " | ".join(f"{o.subfolder}/{o.path.name}" for o in dups))
        is_translation = "translat" in f"{ci.subfolder}/{ci.path.name}".lower()
        translation_conflict = is_translation and bool(upd or dlc)
        if translation_conflict:
            notes.append("WARNING: translated ROM + original-language update/DLC; "
                         "the update's RomFS may override the translation")
        estem, changed = entry_stem(stem)
        if changed:
            notes.append(f"entry names shortened to '{estem}'")
        out_path = out / ci.subfolder / (stem + ".bcci")

        row = dict(game=stem, subfolder=ci.subfolder,
                   base_tid=f"{ci.program_id:016X}" if ci.program_id else "",
                   cci_size=ci.size,
                   update=upd.summary() if upd else "",
                   update_tid=f"{upd.title_id:016X}" if upd else "",
                   dlc=dlc.summary() if dlc else "",
                   dlc_tid=f"{dlc.title_id:016X}" if dlc else "",
                   dlc_present=len(dlc.present) if dlc and dlc.tmd else "",
                   dlc_total=len(dlc.contents) if dlc and dlc.tmd else "",
                   output=str(out_path), output_size="", status="", notes="")

        if not selected:
            continue

        do_verify = not args.dry_run
        for t in (upd, dlc):
            if t is None:
                continue
            notes.extend(f"{t.kind}: {n}" for n in t.notes)
            if do_verify and t.tmd is not None and not t.errors and not t.verified:
                log(f"  verifying {t.kind} {t.title_id:016X} for {name} ...")
                verify_title_contents(t, log)
            if t.errors:
                notes.extend(f"{t.kind} SKIPPED: {e}" for e in t.errors)

        comps = [t for t in (upd, dlc) if t is not None and t.usable]
        if ci.error and not ci.program_id:
            row["status"] = "error: " + ci.error
            counts["failed"] += 1
        elif comps and translation_conflict and not args.allow_translation_updates:
            row["status"] = "skipped: translation (use --allow-translation-updates)"
            counts["skipped"] += 1
        elif not comps and not args.all:
            row["status"] = "no update/DLC" if not (upd or dlc) else "skipped: update/DLC unusable"
            counts["skipped"] += 1
        else:
            # compute entry list and exact output size
            entries = [(estem + SUFFIXES["cci"], ci.size,
                        (lambda p=ci.path: open(p, "rb")), ci.path.stat().st_mtime)]
            in_mtime = ci.path.stat().st_mtime
            try:
                for t in comps:
                    size, segs = build_cia(t)
                    entries.append((estem + SUFFIXES[t.kind], size,
                                    (lambda s=segs: SegmentStream(s)), t.input_mtime()))
                    in_mtime = max(in_mtime, t.input_mtime())
            except Exception as e:  # noqa: BLE001
                row["status"] = f"error building CIA: {e}"
                counts["failed"] += 1
                entries = None
            if entries:
                for e in entries:
                    assert len(e[0].encode("ascii")) <= MAX_TAR_NAME, e[0]
                total = tar_size([e[1] for e in entries])
                row["output_size"] = total
                what = "+".join(["cci"] + [t.kind for t in comps])
                if out_path.exists() and out_path.stat().st_mtime > in_mtime and not args.force:
                    row["status"] = f"up to date ({what})"
                    row["output_size"] = out_path.stat().st_size
                    counts["uptodate"] += 1
                elif args.dry_run or args.verify_only:
                    row["status"] = f"would build ({what})"
                    counts["planned"] += 1
                else:
                    log(f"Building {out_path} ({total:,} bytes: {what})")
                    assert_writable(out_path, forbidden, read_only_drives)
                    try:
                        write_bundle(out_path, entries, log)
                        actual = out_path.stat().st_size
                        if actual != total:
                            raise IOError(f"bundle size {actual} != expected {total}")
                        row["status"] = f"built ({what})"
                        row["output_size"] = actual
                        counts["built"] += 1
                    except Exception as e:  # noqa: BLE001
                        row["status"] = f"error writing bundle: {e}"
                        counts["failed"] += 1
                        log(f"    !! {e}")
        row["notes"] = "; ".join(notes)
        rows.append(row)
        log(f"[{row['status']}] {ci.subfolder}/{name}"
            + (f"  UPD {row['update']}" if upd else "") + (f"  DLC {row['dlc']}" if dlc else ""))

    # ---------------- report ----------------
    report.parent.mkdir(parents=True, exist_ok=True)
    cols = ["game", "subfolder", "base_tid", "cci_size", "update", "update_tid", "dlc", "dlc_tid",
            "dlc_present", "dlc_total", "output_size", "status", "output", "notes"]
    with open(report, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    lows = {ci.low for ci in infos if ci.program_id}
    orphans = [t for (kind, low), t in sorted(installed.items(), key=lambda kv: (kv[0][0], kv[0][1]))
               if low not in lows]
    if args.verify_only and not only:
        for t in orphans:
            if t.tmd is not None and not t.errors and not t.verified:
                log(f"  verifying orphan {t.kind} {t.title_id:016X} ...")
                verify_title_contents(t, log)
    both = [r for r in rows if r["update"] and r["dlc"]]
    upd_only = [r for r in rows if r["update"] and not r["dlc"]]
    dlc_only = [r for r in rows if r["dlc"] and not r["update"]]
    neither = [r for r in rows if not r["update"] and not r["dlc"]]
    lines = [
        f"Mode: {mode}   games considered: {len(rows)}   elapsed {time.time() - t_start:.0f}s",
        f"Games with update AND DLC: {len(both)}",
        f"Games with update only:    {len(upd_only)}",
        f"Games with DLC only:       {len(dlc_only)}",
        f"Games with neither:        {len(neither)}",
        f"Status counts: {counts}",
        "",
        f"ORPHANS (installed update/DLC with no matching CCI): {len(orphans)}",
    ]
    names = {}
    for t in orphans:
        code, nm = describe_title(t)
        names[t.title_id] = (code, nm)
        if nm:
            names[t.title_id & 0xFFFFFFFF] = nm
    for t in orphans:
        base = (TID_HIGH_APP << 32) | (t.title_id & 0xFFFFFFFF)
        code, nm = names[t.title_id]
        nm = nm or names.get(t.title_id & 0xFFFFFFFF, "")
        lines.append(f"  {t.kind:6s} {t.title_id:016X}  (base {base:016X})  {t.summary():28s} "
                     f"{code:12s} {nm}")
    orphan_csv = report.with_name(report.stem + "_orphans.csv")
    with open(orphan_csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["kind", "title_id", "base_tid", "version", "contents_present", "contents_total",
                    "product_code", "name"])
        for t in orphans:
            code, nm = names[t.title_id]
            w.writerow([t.kind, f"{t.title_id:016X}", f"{(TID_HIGH_APP << 32) | (t.title_id & 0xFFFFFFFF):016X}",
                        t.tmd.title_version if t.tmd else "", len(t.present), len(t.contents), code,
                        nm or names.get(t.title_id & 0xFFFFFFFF, "")])
    anomalies = [r for r in rows if r["notes"]]
    lines += ["", f"Games with notes/anomalies: {len(anomalies)}"]
    for r in anomalies:
        lines.append(f"  {r['subfolder']}/{r['game']}: {r['notes']}")
    verified_all = [t for t in installed.values() if t.verified]
    bad = [t for t in installed.values() if t.errors]
    lines += ["", f"Installed titles hash-verified this run: {len(verified_all)} of {len(installed)}; "
              f"titles with errors: {len(bad)}"]
    for t in bad:
        lines.append(f"  {t.kind} {t.title_id:016X}: " + "; ".join(t.errors))
    orphan_notes = [t for t in orphans if t.notes or t.errors]
    if orphan_notes:
        lines += ["", "Orphan title notes:"]
        for t in orphan_notes:
            lines.append(f"  {t.kind} {t.title_id:016X}: " + "; ".join(t.notes + t.errors))
    summary = "\n".join(lines)
    summary_path = report.with_name(report.stem + "_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary + "\n")
    log("\n" + summary)
    log(f"\nReport: {report}\nSummary: {summary_path}\nOrphans: {orphan_csv}")
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
