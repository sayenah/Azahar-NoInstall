# Bundle ROM tools (`.bcci`)

Turn each 3DS game plus its update and DLC into **one file**: a bundle ROM
(`.bcci`), an uncompressed `tar` holding the game image and the CIAs that
belong to it, each byte for byte. This is upstream Azahar's bundle format
([azahar-emu/azahar#2369](https://github.com/azahar-emu/azahar/pull/2369), not yet
in an upstream release); Azahar NoInstall boots it directly and serves the
update and DLC straight out of it, without installing or extracting anything.

```
Game (USA).bcci
├── Game (USA).cci              the game image
├── Game (USA) (Update).cia     if the game has an update
└── Game (USA) (DLC).cia        if the game has DLC
```

Both scripts are Python 3.10+ with the standard library only.

## `make_bcci.py` — build bundles

```sh
python make_bcci.py --roms "<folder of .cci/.3ds>" --updates <update CIAs> --dlc <DLC CIAs> --out <output folder> --dry-run
python make_bcci.py --roms "<folder of .cci/.3ds>" --updates <update CIAs> --dlc <DLC CIAs> --out <output folder>
```

- Update and DLC CIAs are matched to games by the **title ID inside each
  file**, never by name, so misnamed files still land with the right game and
  nothing lands with the wrong one. If two CIAs carry the same title, the
  higher version wins.
- Before bundling, every plaintext CIA content is checked against the SHA-256
  in its TMD; a corrupt CIA stops its game from being bundled. After writing,
  every entry is re-read and compared with its source file, and the bundle is
  only published (renamed from `.partial`) if all of them match.
- Games with no update or DLC are left alone: their image already is one file.
- Reruns skip bundles newer than their inputs (`--force` rebuilds);
  `--only <text>` limits a run to matching games; `--dry-run` only reports.
- `--read-only-drive E:` refuses any write to that drive. Writing inside an
  input folder is always refused.
- `<out>/report.csv` lists what each game got, plus every CIA that was not
  bundled and why (no matching game, superseded, corrupt).
- Entry names are kept to 99 ASCII bytes of plain ustar, the subset upstream's
  tar reader understands; long names are shortened (the `.bcci` keeps the full
  name).

## `verify_bcci.py` — check bundles

```sh
python verify_bcci.py <bundle.bcci | folder | wildcard> [...]
```

Needs nothing but the bundles. Walks each tar with its own ustar parser,
requires exactly one game image plus update/DLC CIAs of that same game, and
checks every plaintext CIA content against the SHA-256 in its TMD.

## Limits

- Only Azahar NoInstall loads `.bcci` today; stock Azahar will once #2369
  ships. Real 3DS hardware cannot use it.
- Encrypted CIAs are bundled but cannot be hash-checked (Azahar NoInstall
  decrypts them on the fly when the console keys are present).
- No tool is needed for a single game:
  `tar -cf "Game.bcci" "Game.cci" "Game (Update).cia" "Game (DLC).cia"`.
