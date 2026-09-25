#!/usr/bin/env python3
r"""make_bcci.py - bundle each 3DS game with its update and DLC CIAs into one .bcci.

A bundle ROM (.bcci) is an uncompressed tar holding one game image plus the
CIAs that belong to it (azahar-emu/azahar#2369). Azahar NoInstall boots it and
serves the update/DLC straight out of it, without installing anything.

For every .cci/.3ds image in --roms this tool finds the update CIA
(title ID 0004000E:<low>) and DLC CIA (0004008C:<low>) of the same game in
--updates / --dlc, matching by the title ID inside each file (never by name
alone), and writes:

    <out>/<Game>.bcci
        <Game>.cci             the game image, byte for byte
        <Game> (Update).cia    the update CIA, byte for byte
        <Game> (DLC).cia       the DLC CIA, byte for byte

Before bundling, every plaintext CIA content is checked against the SHA-256 in
its TMD; after writing, every entry is re-read and compared with its source
file. Inputs are only ever read. Standard library only.

Example:
    python make_bcci.py --roms "E:\ROMs\n3ds\Base Set" --updates E:\ROMs\n3ds\Update
                        --dlc E:\ROMs\n3ds\DLC --out D:\bundles --read-only-drive E:
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import struct
import sys
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ROM_EXTENSIONS = {".cci", ".3ds"}
TID_HIGH_APP = 0x00040000
TID_HIGH_UPDATE = 0x0004000E
TID_HIGH_DLC = 0x0004008C
KIND_BY_HIGH = {TID_HIGH_UPDATE: "Update", TID_HIGH_DLC: "DLC"}

CIA_HEADER_SIZE = 0x2020
CIA_ALIGN = 0x40
TMD_ENCRYPTED = 0x0001
SIG_SIZES = {0x010000: 0x200, 0x010001: 0x100, 0x010002: 0x3C,
             0x010003: 0x200, 0x010004: 0x100, 0x010005: 0x3C}

# Upstream's tar reader (microtar) only understands plain ustar names.
MAX_ENTRY_NAME = 99
SUFFIXES = {"Game": ".cci", "Update": " (Update).cia", "DLC": " (DLC).cia"}
HASH_CHUNK = 8 << 20


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def sha256_file(path: Path, offset: int = 0, size: int | None = None) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        f.seek(offset)
        remaining = size if size is not None else os.path.getsize(path) - offset
        while remaining > 0:
            chunk = f.read(min(HASH_CHUNK, remaining))
            if not chunk:
                raise OSError(f"{path}: unexpected end of file")
            h.update(chunk)
            remaining -= len(chunk)
    return h.digest()


# --------------------------------------------------------------------------
# Safety: never write inside the inputs or to a read-only drive.
# --------------------------------------------------------------------------
def assert_writable(path: Path, inputs: list[Path], read_only_drives: set[str]) -> None:
    p = Path(os.path.abspath(path))
    drive = (p.drive or "").upper()
    if drive and drive in read_only_drives:
        raise SystemExit(f"REFUSING to write to {p}: drive {drive} is read-only for this tool")
    for root in inputs:
        r = Path(os.path.abspath(root))
        if p == r or r in p.parents:
            raise SystemExit(f"REFUSING to write to {p}: inside input folder {r}")


# --------------------------------------------------------------------------
# Game images
# --------------------------------------------------------------------------
@dataclass
class Game:
    path: Path
    base: int = 0  # offset of the image within `path` (non-zero inside a bundle)
    program_id: int = 0
    error: str = ""

    @property
    def low(self) -> int:
        return self.program_id & 0xFFFFFFFF


def read_game(path: Path, base: int = 0) -> Game:
    game = Game(path, base)
    try:
        with open(path, "rb") as f:
            f.seek(base)
            ncsd = f.read(0x200)
            if ncsd[0x100:0x104] != b"NCSD":
                game.error = "not an NCSD (CCI) image"
                return game
            partition0 = struct.unpack_from("<I", ncsd, 0x120)[0] * 0x200
            f.seek(base + partition0)
            ncch = f.read(0x200)
            if ncch[0x100:0x104] != b"NCCH":
                game.error = "partition 0 is not an NCCH"
                return game
            game.program_id = struct.unpack_from("<Q", ncch, 0x118)[0]
    except OSError as e:
        game.error = f"read error: {e}"
    if game.program_id and game.program_id >> 32 != TID_HIGH_APP:
        game.error = f"program ID {game.program_id:016X} is not an application"
    return game


# --------------------------------------------------------------------------
# CIAs
# --------------------------------------------------------------------------
@dataclass
class Cia:
    path: Path
    base: int = 0  # offset of the CIA within `path` (non-zero inside a bundle)
    size: int = 0
    title_id: int = 0
    version: int = 0
    contents: list[tuple[int, int, int, int, bytes]] = field(default_factory=list)  # id, index, type, size, hash
    present: list[int] = field(default_factory=list)  # positions in `contents`
    content_offset: int = 0
    encrypted: bool = False
    error: str = ""
    verified: bool = False

    @property
    def kind(self) -> str:
        return KIND_BY_HIGH.get(self.title_id >> 32, "?")

    @property
    def low(self) -> int:
        return self.title_id & 0xFFFFFFFF

    def summary(self) -> str:
        return f"v{self.version} {len(self.present)}/{len(self.contents)} contents"


def read_cia(path: Path, base: int = 0, size: int | None = None) -> Cia:
    cia = Cia(path, base)
    try:
        cia.size = file_size = size if size is not None else os.path.getsize(path) - base
        with open(path, "rb") as f:
            f.seek(base)
            header = f.read(CIA_HEADER_SIZE)
            if len(header) < CIA_HEADER_SIZE:
                cia.error = "truncated CIA header"
                return cia
            header_size, _type, _version, cert_size, ticket_size, tmd_size, _meta_size, content_size = \
                struct.unpack_from("<IHHIIIIQ", header, 0)
            if header_size != CIA_HEADER_SIZE:
                cia.error = f"unexpected CIA header size 0x{header_size:X}"
                return cia
            tmd_offset = align(align(align(header_size, CIA_ALIGN) + cert_size, CIA_ALIGN) + ticket_size,
                               CIA_ALIGN)
            cia.content_offset = align(tmd_offset + tmd_size, CIA_ALIGN)
            if cia.content_offset + content_size > file_size:
                cia.error = "CIA is truncated (content extends past end of file)"
                return cia
            f.seek(base + tmd_offset)
            tmd = f.read(tmd_size)
        sig_type = struct.unpack_from(">I", tmd, 0)[0]
        if sig_type not in SIG_SIZES:
            cia.error = f"unknown TMD signature type 0x{sig_type:X}"
            return cia
        body = align(4 + SIG_SIZES[sig_type], CIA_ALIGN)
        cia.title_id = struct.unpack_from(">Q", tmd, body + 0x4C)[0]
        cia.version = struct.unpack_from(">H", tmd, body + 0x9C)[0]
        count = struct.unpack_from(">H", tmd, body + 0x9E)[0]
        chunks = body + 0xC4 + 0x900
        if chunks + count * 0x30 > len(tmd):
            cia.error = "TMD is truncated"
            return cia
        bitmap = header[0x20:CIA_HEADER_SIZE]
        for i in range(count):
            cid, index, ctype, size = struct.unpack_from(">IHHQ", tmd, chunks + i * 0x30)
            digest = tmd[chunks + i * 0x30 + 0x10:chunks + i * 0x30 + 0x30]
            cia.contents.append((cid, index, ctype, size, digest))
            if bitmap[index // 8] & (0x80 >> (index % 8)):
                cia.present.append(i)
        if sum(cia.contents[i][3] for i in cia.present) != content_size:
            cia.error = "content sizes in the TMD do not add up to the CIA's content section"
            return cia
        cia.encrypted = any(cia.contents[i][2] & TMD_ENCRYPTED for i in cia.present)
    except (OSError, struct.error) as e:
        cia.error = f"read error: {e}"
    return cia


def verify_cia_contents(cia: Cia) -> None:
    """Checks each plaintext content against its TMD SHA-256 (encrypted content
    cannot be checked without its title key and is left to the emulator)."""
    offset = cia.base + cia.content_offset
    for i in cia.present:
        cid, _index, ctype, size, digest = cia.contents[i]
        if not ctype & TMD_ENCRYPTED and sha256_file(cia.path, offset, size) != digest:
            cia.error = f"content {cid:08x} does not match its TMD hash (corrupt dump?)"
            return
        offset += size
    cia.verified = True


def find_cias(folder: Path | None) -> list[Cia]:
    if folder is None:
        return []
    return [read_cia(p) for p in sorted(folder.rglob("*"))
            if p.is_file() and p.suffix.lower() == ".cia"]


# --------------------------------------------------------------------------
# Bundles
# --------------------------------------------------------------------------
def entry_stem(stem: str) -> str:
    """Shortens a game name so every entry name fits plain ustar."""
    limit = MAX_ENTRY_NAME - max(len(s) for s in SUFFIXES.values())
    stem = stem.encode("ascii", "replace").decode("ascii").replace("?", "_")
    return stem if len(stem) <= limit else stem[:limit].rstrip(" .-_")


def write_bundle(out_path: Path, entries: list[tuple[str, Path]]) -> None:
    partial = out_path.with_name(out_path.name + ".partial")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(partial, "w", format=tarfile.USTAR_FORMAT) as tar:
            for name, source in entries:
                info = tarfile.TarInfo(name)
                info.size = os.path.getsize(source)
                info.mtime = int(os.path.getmtime(source))
                info.mode = 0o644
                with open(source, "rb") as f:
                    tar.addfile(info, f)
        # Re-read every entry and compare it with its source before publishing.
        with tarfile.open(partial, "r") as tar:
            members = tar.getmembers()
            if [m.name for m in members] != [name for name, _ in entries]:
                raise RuntimeError("bundle entry list differs from what was written")
            for member, (_name, source) in zip(members, entries):
                if member.size != os.path.getsize(source) or \
                        sha256_file(partial, member.offset_data, member.size) != sha256_file(source):
                    raise RuntimeError(f"entry {member.name} differs from {source}")
        os.replace(partial, out_path)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace", line_buffering=True)
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--roms", required=True, help="folder of .cci/.3ds game images (not recursive)")
    ap.add_argument("--updates", help="folder of update CIAs (searched recursively)")
    ap.add_argument("--dlc", help="folder of DLC CIAs (searched recursively)")
    ap.add_argument("--out", required=True, help="output folder for the .bcci files")
    ap.add_argument("--report", help="CSV report path (default: <out>/report.csv)")
    ap.add_argument("--read-only-drive", action="append", default=[], metavar="DRIVE",
                    help="refuse to write anything to this drive, e.g. E: (repeatable)")
    ap.add_argument("--only", action="append", default=[],
                    help="only games whose file name contains this text (repeatable, case-insensitive)")
    ap.add_argument("--dry-run", action="store_true", help="match and report only; write no bundles")
    ap.add_argument("--force", action="store_true", help="rebuild bundles that are already up to date")
    args = ap.parse_args(argv)

    roms = Path(args.roms)
    updates = Path(args.updates) if args.updates else None
    dlc = Path(args.dlc) if args.dlc else None
    out = Path(args.out)
    report = Path(args.report) if args.report else out / "report.csv"
    inputs = [p for p in (roms, updates, dlc) if p is not None]
    read_only = {d.upper().rstrip("\\/") for d in args.read_only_drive}
    for p in (out, report):
        assert_writable(p, inputs, read_only)
    if updates is None and dlc is None:
        ap.error("give --updates and/or --dlc")

    start = time.time()
    games = [read_game(p) for p in sorted(roms.iterdir(), key=lambda p: p.name.lower())
             if p.is_file() and p.suffix.lower() in ROM_EXTENSIONS]
    cias = find_cias(updates) + find_cias(dlc)
    print(f"{len(games)} game images in {roms}; {len(cias)} CIAs in the update/DLC folders")

    # The highest version wins when several CIAs carry the same title.
    by_title: dict[int, Cia] = {}
    problems: list[tuple[Cia, str]] = []
    for cia in cias:
        if cia.error:
            problems.append((cia, cia.error))
        elif cia.kind == "?":
            problems.append((cia, f"title {cia.title_id:016X} is neither an update nor DLC"))
        elif cia.title_id not in by_title or by_title[cia.title_id].version < cia.version:
            if cia.title_id in by_title:
                problems.append((by_title[cia.title_id], "superseded by a newer version"))
            by_title[cia.title_id] = cia
        else:
            problems.append((cia, "superseded by a newer version"))

    games_by_low: dict[int, list[Game]] = {}
    for game in games:
        if game.program_id:
            games_by_low.setdefault(game.low, []).append(game)

    only = [s.lower() for s in args.only]
    counts = dict(built=0, uptodate=0, planned=0, failed=0, nothing=0)
    rows = []
    used: set[int] = set()
    for game in games:
        if only and not any(s in game.path.name.lower() for s in only):
            continue
        row = dict(game=game.path.name, title_id=f"{game.program_id:016X}" if game.program_id else "",
                   update="", dlc="", output="", status="")
        if game.error:
            row["status"] = f"error: {game.error}"
            counts["failed"] += 1
            rows.append(row)
            continue
        parts = []
        for high in (TID_HIGH_UPDATE, TID_HIGH_DLC):
            cia = by_title.get((high << 32) | game.low)
            if cia is None:
                continue
            used.add(cia.title_id)
            row["update" if high == TID_HIGH_UPDATE else "dlc"] = f"{cia.path.name} ({cia.summary()})"
            parts.append(cia)
        if len(games_by_low[game.low]) > 1:
            others = [g.path.name for g in games_by_low[game.low] if g is not game]
            row["status"] = "note: same title ID as " + "; ".join(others) + ". "
        if not parts:
            row["status"] += "no update or DLC"
            counts["nothing"] += 1
            rows.append(row)
            continue

        out_path = out / (game.path.stem + ".bcci")
        row["output"] = str(out_path)
        stem = entry_stem(game.path.stem)
        entries = [(stem + SUFFIXES["Game"], game.path)] + \
                  [(stem + SUFFIXES[cia.kind], cia.path) for cia in parts]
        newest_input = max(os.path.getmtime(src) for _, src in entries)
        what = " + ".join(["game"] + [f"{c.kind} {c.summary()}" for c in parts])

        if args.dry_run:
            row["status"] += f"planned: {what}"
            counts["planned"] += 1
        elif out_path.exists() and not args.force and os.path.getmtime(out_path) >= newest_input:
            row["status"] += "up to date"
            counts["uptodate"] += 1
        else:
            try:
                for cia in parts:
                    if not cia.verified:
                        verify_cia_contents(cia)
                    if cia.error:
                        raise RuntimeError(f"{cia.path.name}: {cia.error}")
                assert_writable(out_path, inputs, read_only)
                write_bundle(out_path, entries)
                row["status"] += f"built: {what}"
                counts["built"] += 1
            except (OSError, RuntimeError) as e:
                row["status"] += f"FAILED: {e}"
                counts["failed"] += 1
        print(f"[{row['status']}] {game.path.name}")
        rows.append(row)

    unmatched = [c for t, c in by_title.items() if t not in used and not only]
    for cia in unmatched:
        problems.append((cia, "no game in --roms has this title ID"))

    report.parent.mkdir(parents=True, exist_ok=True)
    with open(report, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["game"])
        writer.writeheader()
        writer.writerows(rows)
        if problems:
            f.write("\n")
            csv.writer(f).writerow(["cia", "title_id", "version", "problem"])
            for cia, problem in problems:
                csv.writer(f).writerow([str(cia.path), f"{cia.title_id:016X}" if cia.title_id else "",
                                        cia.version, problem])

    print(f"\n{counts}  ({time.time() - start:.0f}s)")
    for cia, problem in problems:
        print(f"  CIA not bundled: {cia.path.name}: {problem}")
    print(f"Report: {report}")
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
