#!/usr/bin/env python3
"""verify_bcci.py - check .bcci bundle ROMs, with no other files needed.

For each bundle:
  * walks the tar with its own minimal ustar parser (header checksums, sizes,
    512-byte padding, end-of-archive marker) and requires plain ustar names,
    the subset upstream's reader understands;
  * requires exactly one game image (.cci/.3ds) plus update/DLC CIAs, and no
    other files;
  * checks that each CIA is an update or DLC of that game (by title ID), with
    at most one of each;
  * checks every plaintext CIA content against the SHA-256 in its TMD.

Usage: verify_bcci.py <bundle.bcci | folder | wildcard> [...]
"""

from __future__ import annotations

import glob
import sys
from pathlib import Path

from make_bcci import (KIND_BY_HIGH, MAX_ENTRY_NAME, ROM_EXTENSIONS, read_cia, read_game,
                       verify_cia_contents)

BLOCK = 512


def ustar_entries(path: Path) -> list[tuple[str, int, int]]:
    """Returns (name, data offset, size) for every regular file in the tar."""
    entries = []
    size_total = path.stat().st_size
    with open(path, "rb") as f:
        offset = 0
        while True:
            f.seek(offset)
            header = f.read(BLOCK)
            if len(header) < BLOCK:
                raise ValueError("archive ends without an end-of-archive marker")
            if header == bytes(BLOCK):
                return entries
            stored = int(header[148:156].split(b"\0")[0].strip() or b"0", 8)
            actual = sum(header[:148]) + 8 * 0x20 + sum(header[156:])
            if stored != actual:
                raise ValueError(f"bad header checksum at offset {offset:#x}")
            if header[257:262] != b"ustar":
                raise ValueError(f"not a ustar header at offset {offset:#x}")
            name = header[:100].split(b"\0")[0].decode("ascii")
            if header[345:500].strip(b"\0"):
                raise ValueError(f"{name}: uses the ustar prefix field (name too long)")
            size = int(header[124:136].split(b"\0")[0].strip() or b"0", 8)
            kind = header[156:157]
            if kind not in (b"0", b"\0"):
                raise ValueError(f"{name}: not a regular file (type {kind!r})")
            data = offset + BLOCK
            if data + size > size_total:
                raise ValueError(f"{name}: truncated")
            entries.append((name, data, size))
            offset = data + (size + BLOCK - 1) // BLOCK * BLOCK


def verify(path: Path) -> list[str]:
    errors = []
    entries = ustar_entries(path)
    for name, _, _ in entries:
        if len(name.encode()) > MAX_ENTRY_NAME:
            errors.append(f"{name}: name longer than {MAX_ENTRY_NAME} bytes")
    images = [e for e in entries if Path(e[0]).suffix.lower() in ROM_EXTENSIONS]
    cias = [e for e in entries if Path(e[0]).suffix.lower() == ".cia"]
    others = [e[0] for e in entries if e not in images and e not in cias]
    if len(images) != 1:
        return errors + [f"expected exactly one game image, found {len(images)}"]
    if others:
        errors.append(f"unexpected entries: {', '.join(others)}")

    game = read_game(path, images[0][1])
    if game.error:
        return errors + [f"{images[0][0]}: {game.error}"]
    print(f"   game   {game.program_id:016X}  {images[0][0]}")

    seen = set()
    for name, data, size in cias:
        cia = read_cia(path, data, size)
        if not cia.error:
            verify_cia_contents(cia)
        if cia.error:
            errors.append(f"{name}: {cia.error}")
            continue
        kind = KIND_BY_HIGH.get(cia.title_id >> 32)
        if kind is None or cia.low != game.low:
            errors.append(f"{name}: title {cia.title_id:016X} is not an update/DLC of this game")
        elif kind in seen:
            errors.append(f"{name}: more than one {kind} CIA")
        seen.add(kind)
        state = "encrypted, not hash-checked" if cia.encrypted else "contents match TMD"
        print(f"   {kind or '?':6} {cia.title_id:016X}  {cia.summary()}, {state}  {name}")
    return errors


def expand(args: list[str]) -> list[Path]:
    """Folders mean every .bcci in them; wildcards are expanded here because
    the Windows shell leaves them to the program."""
    paths = []
    for arg in args:
        if Path(arg).is_dir():
            paths += sorted(Path(arg).glob("*.bcci"))
        elif glob.has_magic(arg):
            paths += sorted(Path(p) for p in glob.glob(arg))
        else:
            paths.append(Path(arg))
    return paths


def main(argv=None) -> int:
    paths = expand(argv if argv is not None else sys.argv[1:])
    if not paths:
        print(__doc__)
        return 2
    failed = 0
    for path in paths:
        print(f"== {path}")
        try:
            errors = verify(path)
        except (OSError, ValueError, UnicodeDecodeError) as e:
            errors = [str(e)]
        for error in errors:
            print(f"   ERROR: {error}")
        print("   RESULT: " + ("FAIL" if errors else "PASS"))
        failed += bool(errors)
    print(f"\n{len(paths) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
