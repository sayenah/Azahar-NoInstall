# Bundle ROM tools (`.bcci`)

Turn each 3DS game plus its update and DLC into **one file**: a bundle ROM
(`.bcci`), an uncompressed `tar` holding the untouched game image and its
update/DLC as CIAs. This is upstream Azahar's bundle format
([azahar-emu/azahar#2369](https://github.com/azahar-emu/azahar/pull/2369), not yet
in an upstream release); Azahar NoInstall boots it directly and serves the
update and DLC in place, without installing or extracting anything.

```
Game (USA).bcci
├── Game (USA).cci              the original image, byte for byte
├── Game (USA) (Update).cia     if an update is installed
└── Game (USA) (DLC).cia        if DLC is installed
```

Both scripts are Python 3.10+ with the standard library only.

## `make_bcci.py` — build bundles

The update and DLC are taken from an Azahar installation where they are
already **installed** (decrypted), and rebuilt into CIAs:

- a generated ticket granting every content index (games check DLC ownership
  through it), with a zero title key since the content is decrypted;
- the installed TMD, with any Encrypted flags cleared and its hash tree
  recomputed (its signature cannot be, and emulators do not check it);
- no certificate chain (Azahar accepts a zero-size chain).

Every content is SHA-256-checked against its TMD before and while it is
written, and must be a decrypted NCCH. A title that fails is skipped, never
bundled.

```sh
python make_bcci.py --roms <folder of .cci/.3ds> --title-root <Azahar user folder> --out <output folder> --dry-run
python make_bcci.py --roms <folder of .cci/.3ds> --title-root <Azahar user folder> --out <output folder>
```

- `--roms` is scanned one subfolder deep; the output mirrors its subfolders.
- `--title-root` accepts Azahar's user folder, its `sdmc` folder, or the
  `.../Nintendo 3DS/<0…0>/<0…0>/title` folder itself.
- Only games with an update or DLC are bundled unless `--all` is given.
- Reruns skip bundles that are newer than their inputs (`--force` rebuilds).
- `--dry-run` only plans; `--verify-only` hash-checks every installed title.
- `--read-only-drive E:` refuses any write to that drive. Writing inside the
  `--roms` or `--title-root` trees is always refused.
- A report is written to `<out>/report.csv`, with `report_summary.txt` and
  `report_orphans.csv` (installed updates/DLC whose game is not in `--roms`).
- Translated ROMs (a folder or file name containing "translat") that share a
  title ID with an original-language update/DLC are skipped, since the
  update's RomFS may override the translation;
  `--allow-translation-updates` bundles them anyway.
- Entry names are kept to 99 ASCII bytes of plain ustar, the subset upstream's
  tar reader understands; long names are shortened (the `.bcci` keeps the full
  name).

## `verify_bcci.py` — check bundles

```sh
python verify_bcci.py <bundle.bcci> [...] [--roms <make_bcci --roms> --out-root <make_bcci --out>]
```

Reads each bundle with Python's `tarfile` and an independent ustar parser,
then checks every CIA (header, alignment, ticket rights, TMD hash tree,
content bitmap, the SHA-256 of every content, decrypted NCCH). With `--roms`
(or `--source X.cci` for a single bundle) it also confirms the bundled image
is byte-identical to the original.

## Limits

- Only Azahar NoInstall loads `.bcci` today; stock Azahar will once #2369
  ships. Real 3DS hardware cannot use it.
- The update and DLC must be installed, decrypted, in an Azahar user folder;
  loose update/DLC CIAs can simply be bundled with `tar` directly:
  `tar -cf "Game.bcci" "Game.cci" "Game (Update).cia" "Game (DLC).cia"`.
