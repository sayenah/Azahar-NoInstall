# Azahar NoInstall — Developer & Maintenance Guide

This document explains everything the **NoInstall fork** adds on top of upstream
Azahar: the architecture, every file that was touched, the release automation,
and the non-obvious gotchas. If you are a future contributor (human or AI)
picking this up cold, read this first — it is written to get you productive
without re-deriving the design.

> **Scope.** NoInstall = "run games, DLC, updates and DSiWare directly from
> `.zip`/`.cci`/`.cxi`/`.3ds`/`.cia` files without installing anything into the
> emulated console, decrypting encrypted content on the fly." Nothing here
> changes the actual 3DS emulation; it all sits at the file-access and loader
> layers.

---

## 1. Mental model

A stock 3DS emulator resolves *installed* title content through a small set of
functions that build host filesystem paths under the emulated NAND/SD. The
whole NoInstall design is: **make those same functions (and the loader) resolve
to the user's own files in place instead of to installed copies**, decrypting
transparently when needed. Three layers do this:

1. **Virtual container paths** — a path syntax + `IOFile` support that lets any
   existing reader address a byte-range inside a `.zip` or `.cia` as if it were
   a standalone file.
2. **The loader** — boots a `.zip`/`.cia`/encrypted ROM in place by resolving it
   to a virtual path (or a decrypted cache file) and handing that to the normal
   NCCH loader.
3. **The virtual title registry** — at game boot, finds the matching update/DLC
   (and any DSiWare) from the configured folders and intercepts the installed-
   content path lookups so the running game sees them as installed.

Decryption is a cross-cutting concern used by layers 2 and 3.

---

## 2. Branch & release model

| Branch / tag | Purpose |
|---|---|
| `noinstall/core` | **The default branch** and source of truth. All NoInstall commits live here, based on the fork point of `master`. Also carries the autosync workflow (GitHub reads scheduled workflows from the default branch). This is what visitors and clones get, and what the front-page README comes from. |
| `master` | The upstream-anchor. Shares history with `noinstall/core` at the fork point so the autosync can compute `merge-base(master, noinstall/core)` to isolate the feature commits. It does **not** need to advance to newer upstream (the autosync fetches upstream tags directly). Don't put feature code here. |
| `noinstall/<tag>` | A backport of the feature onto a specific upstream release tag (e.g. `noinstall/2125.1.3`). Produced by the autosync workflow (cherry-pick) or by hand when conflicts need resolving. The autosync workflow file is cherry-picked onto these too but is inert there (no `push` trigger). |
| `<tag>-noinstall` (tag) | Marks a published release built from `noinstall/<tag>`. |

> **Front page / README.** GitHub renders the README from the **default branch**
> (`noinstall/core`). If you ever change the default branch, the front page and
> the scheduled-workflow source move with it — keep the autosync workflow on
> whatever branch is default.

The **autosync workflow** (`.github/workflows/noinstall-autosync.yml`, runs daily
+ on demand) watches upstream for the newest stable release and newest newer RC.
For an unprocessed one it: cherry-picks `noinstall/core`'s own commits onto the
release tag (or reuses a hand-prepared `noinstall/<tag>` branch if it already
exists), builds macOS/Windows/Android, and publishes a `<tag>-noinstall` release
with all artifacts — only if every platform build succeeds. It processes one
release per run and re-dispatches itself if another is pending.

> The workflow **cherry-picks the feature commits** (`merge-base(master,
> noinstall/core)..noinstall/core`), it does **not** merge the whole branch —
> merging would drag all of master's history onto an older tag and conflict.

---

## 3. Architecture & file map

### 3.1 Virtual container paths — `src/common/virtual_container.{h,cpp}`

A read-only path scheme addressing content inside another file, separated by `#`:

```
Game.zip#Game.3ds                 → the entry "Game.3ds" inside Game.zip
Update.cia#0x2940:0x1000          → 0x1000 bytes at offset 0x2940 of Update.cia
Pack.zip#Update.cia#0x40:0x8      → a byte range within a zip entry
```

- Resolution happens inside `FileUtil::IOFile` (`src/common/file_util.cpp`):
  `Open()`, `Exists()`, `GetSize()`, `ReadImpl`/`ReadAtImpl`/`Seek`/`Tell`
  all understand virtual paths and present a read-only window into the resolved
  host file. Writes to a virtual path are refused.
- **Stored** (uncompressed) zip entries resolve to a direct byte-range of the
  zip — zero extraction, zero RAM.
- **Deflated** zip entries are transparently extracted once into
  `<CacheDir>/extracted/` (cache key = CRC32 + size + name) and resolved to the
  extracted copy.
- Zip reading is provided by **miniz** (`externals/miniz/`, vendored, MIT).
- `ClearExtractionCache()` wipes `<CacheDir>/extracted/` (which also contains the
  decrypted cache, see §3.4). Called on desktop exit
  (`GMainWindow::closeEvent`) and Android startup (`setUserDirectory` JNI).

Key public API: `IsVirtualPath`, `ResolveVirtualPath`, `ListZipContents`,
`ReadZipEntryPrefix`, `MakeVirtualPath`, `MakeVirtualRangePath`,
`ClearExtractionCache`.

### 3.2 Loader — `src/core/loader/loader.cpp`

`GetLoader()` is the entry point. NoInstall additions:

- **`.zip`** → `FindBootableZipEntry()` picks the best bootable entry
  (CCI > CXI > CIA > 3DSX > ELF), rewrites the load path to `zip#entry`.
- **`.cia`** → `GetCIADirectLoader()` boots the CIA's main content in place via
  `Service::AM::PrepareCIAContentForLoad()` (→ virtual range or decrypted cache).
- **`.cxi`/`.cci`/`.3ds`** → if encrypted, `Service::AM::PrepareEncryptedRomForLoad()`
  decrypts to cache and the loader loads that; plaintext ROMs load unchanged.

Game-list extensions: `src/citra_qt/game_list.cpp` (`supported_file_extensions`)
adds `cia`, `zip`. Drag-and-drop whitelist in `citra_qt.cpp` (`AcceptedExtensions`).

### 3.3 Virtual title registry — `src/core/file_sys/virtual_titles.{h,cpp}`

Populated in `Core::System::Load()` (`src/core/core.cpp`) via
`ScanForCompanionTitles(program_id, filepath)`; cleared in `System::Shutdown`.

- Scans the configured **Updates** and **DLC** folders for `.cia` (or `.zip`s of
  them) whose title ID is the booted game's update/DLC title ID
  (`0004000E<low>` / `0004008C<low>`). No-Intro `(Update)`/`(DLC)` filename
  matches are tried first; otherwise every candidate is probed. Also registers
  CIAs bundled inside the game's own `.zip`, and every DSiWare CIA in the
  **DSiWare** folder (manage-only — see §5).
- Candidate probing streams only the CIA header + TMD (no full extraction).
- **The choke point:** `Service::AM::GetTitleContentPath()` (am.cpp ~1280) and
  `GetTitleMetadataPath()` (~1240) consult the registry first
  (`VirtualTitles::GetContentPath` / `GetMetadataPath`). So the runtime NCCH
  archive, the update code overlay, and AM's content enumeration all see these
  titles as "installed" while nothing is written to disk.
- Registered titles are also appended to AM's title-list scan
  (`ScanForTitlesImpl` in am.cpp) so enumeration lists them.
- `GetContentPath` resolves each content lazily and memoizes it
  (`Entry.resolved_content_paths`): plaintext → virtual range, encrypted →
  decrypted cache file.

### 3.4 Decryption — `src/core/hle/service/am/am.{h,cpp}`

Decryption **reuses the proven install-time decryptor** rather than new crypto.
The install path's `NCCHCryptoFile` (a write-only NCCH decryptor) already does
KeyY-from-signature, secure-keyslot selection (0x2C/0x25/0x18/0x1B), seed crypto,
per-section CTRs, and flips `no_crypto`. NoInstall drives it directly:

- `NCCHCryptoFile::AuthorizeDecryption()` — public setter added so the
  no-install flow can authorize decryption (the install path gates this behind
  the `DECRYPTION_AUTHORIZED` hack, granted only to NIM/DLP; see §5). The ctor
  also gained `allow_compression` so cache output is never Z3DS-compressed.
- `DecryptNCCHPartitionToCache(source, offset, size, title_key?, ctr, cache_id,
  unique_crypto_output=true)` — streams a partition through `NCCHCryptoFile`,
  first stripping the CIA title-key AES-CBC layer if `title_key` is given.
  Output goes to `<CacheDir>/extracted/decrypted/`. Default output is
  console-unique-crypto (like installed content, non-shareable, read back
  transparently by `NCCHContainer` via its OpenUniqueCryptoFile retry);
  `unique_crypto_output=false` gives plaintext for NCSD reassembly.
- `PrepareCIAContentForLoad(cia_path, index)` — partial-loads header + TMD
  (ticket lazily, only for encrypted content). Returns a virtual range for
  plaintext content or a decrypted cache path for encrypted content. Used by
  the CIA loader and the registry.
- `PrepareEncryptedRomForLoad(path)` — for directly-booted `.cxi`/`.cci`/`.3ds`.
  Bare CXI: decrypt the whole NCCH. **NCSD (CCI/3DS): `DecryptNCSDToCache`
  copies the image and decrypts *every* encrypted partition in place** (main,
  manual, download-play child, bundled update), so all partitions load.
  Returns `nullopt` (load original unchanged) when nothing is encrypted.

Keys: loaded from `<SysData>/keys.txt` and a shipped obfuscated built-in blob
(`src/core/hw/default_keys.h`, `ENABLE_BUILTIN_KEYBLOB=ON`). Most retail content
decrypts with zero user setup. Missing keys/tickets fail gracefully with a log
line pointing at `keys.txt`.

### 3.5 Settings

Three string settings — `updates_folder`, `dlc_folder`, `dsiware_folder` —
declared once in `CMakeModules/GenerateSettingKeys.cmake` (shared list) and in
`src/common/settings.h`.

- **Desktop:** read/written in `src/citra_qt/configuration/config.cpp`
  (Data Storage group); UI in `configure_storage.{ui,cpp}` ("No-Install Content
  Folders").
- **Android (vanilla flavor):** mirrored in `SettingKeys.kt`, `StringSetting.kt`
  (`SECTION_STORAGE`); folder pickers in `HomeSettingsFragment.kt` persist a
  native path via `NativeLibrary.getNativePath`; read in `jni/config.cpp`;
  **declared in `jni/default_ini.h`** (required — the Android startup asserts
  that every shared setting key is either in the default ini or the omitted-keys
  list). `Game.kt` lists `.zip`/`.cia`. See §5 for the Google Play limitation.

---

## 4. Building & testing (local, macOS)

```sh
brew install cmake ninja ccache spirv-tools   # one-time
git checkout noinstall/core
git submodule update --init --recursive
mkdir -p build/dev && cd build/dev
cmake ../.. -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_ROOM_STANDALONE=OFF \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
ninja
./bin/RelWithDebInfo/tests            # all suites
./bin/RelWithDebInfo/tests "VirtualContainer zip entries,VirtualTitles companion scan"
```

Unit tests for the feature:
`src/tests/common/virtual_container.cpp` (zip layer, byte ranges) and
`src/tests/core/file_sys/virtual_titles.cpp` (registry, No-Intro matching,
title-ID probing, zipped/deflated CIAs, version preference). Both build synthetic
CIAs with miniz — they cannot exercise real decryption (needs real keys + real
NCCH), so decryption is verified manually against real files.

Run `clang-format -i` on any `.cpp/.h` you touch — CI enforces it, and MSVC
builds with **warnings-as-errors** (`/WX`), so unused variables etc. fail the
Windows build even when macOS/Linux pass.

---

## 5. Gotchas & troubleshooting

- **`git add -A` pollutes commits with submodule pointers.** Switching branches
  leaves checked-out submodules (e.g. `externals/cryptopp-cmake`,
  `externals/openal-soft` at a different rev) that `git add -A` grabs as stray
  gitlinks. Always `git diff --cached --stat` before committing; a stray
  `externals/...` `mode 160000` line means unstage it (`git rm --cached`) — it
  would break every cherry-pick. Prefer staging explicit paths.
- **MSVC / cryptopp on old tags.** Some release tags pin a cryptopp revision
  that no longer builds with the current MSVC STL
  (`stdext::make_checked_array_iterator` was removed). Fix on the backport
  branch by pinning `externals/cryptopp` to `weidai11/cryptopp` master (keeps the
  source layout the tag's `cryptopp-cmake` wrapper expects while version-guarding
  the code). Azahar's own fixed cryptopp forks reorganize the tree and are
  incompatible with that wrapper.
- **Synthetic test CIAs need only header + TMD.** A full `CIAContainer::Load`
  requires a ticket; the test fixtures don't include one. Production code
  (`PrepareCIAContentForLoad`) deliberately partial-loads (header + TMD, ticket
  only when a content is encrypted) so plaintext content works without a ticket.
- **The `DECRYPTION_AUTHORIZED` gate is deliberate.** Upstream Azahar decrypts
  arbitrary CIAs only for HLE callers NIM/DLP (eShop/download-play emulation);
  the user-facing Install menu leaves it off as an anti-piracy stance. NoInstall
  flips it **only** for the user-initiated no-install flow, scoped to files the
  user supplies. Keep it that way; do not authorize the stock Install path.
- **DSiWare can't be executed.** Azahar has no TWL/SRL loader, so DSiWare is
  manage-only (listed/registered) here, same as installed DSiWare upstream.
- **Android Google Play flavor** stores a `content://` URI for the folders and
  cannot enumerate them natively (its SAF bridge returns display names only).
  The sideloaded **vanilla** flavor (which the autosync builds) converts picks to
  real paths and works. Enabling Google Play would need a DocumentsTree root or a
  new JNI bridge returning child content URIs.
- **`.cci` cache is transient but large.** `DecryptNCSDToCache` copies the whole
  image then overwrites encrypted partitions — up to the game's size in transient
  cache, wiped on exit. Correctness over efficiency; optimize to a sparse write
  later if needed.
- **Workflow `startup_failure` with no jobs** is a transient GitHub issue
  (often from re-dispatching while a cancelled run tears down). Just re-dispatch;
  nothing is published on a startup failure.
- **Publish must not download artifacts into `dist/`.** The repo already has a
  top-level `dist/` directory (packaging files, incl. `dist/apple/`), so
  downloading into it and uploading `dist/*` attaches packaging folders and
  fails ("is a directory"). The workflow downloads into `release-artifacts/` and
  uploads only `*.zip`/`*.apk`/`*.aab`. If a publish fails after the build
  succeeded, you can publish by hand from the run's artifacts:
  `gh run download <run-id> -n release-macos -n release-windows -n release-android`
  then `gh release create <tag>-noinstall --target noinstall/<tag> <files...>`.

---

## 6. Extending the system

- **New bootable container extension:** add it to `GuessFromExtension`
  (`loader.cpp`), `supported_file_extensions` (`game_list.cpp`), `Game.kt`
  (Android), and handle it in `GetLoader`.
- **A new "served in place" content type:** register it in the virtual title
  registry (`virtual_titles.cpp`) and make sure the relevant
  `GetTitleContentPath`/`GetTitleMetadataPath` lookups reach the registry.
- **DLC ticket-rights checks:** if a game validates DLC tickets (rare), the
  ticket path isn't intercepted yet — add virtual ticket serving alongside the
  content/metadata interception.
- **Adding a platform to releases:** add a job to
  `noinstall-autosync.yml` mirroring upstream's `build.yml` for that platform,
  and add it to the `publish` job's `needs`.

---

## 7. Quick reference — files touched

| Area | Files |
|---|---|
| Zip / virtual paths | `src/common/virtual_container.{h,cpp}`, `src/common/file_util.{h,cpp}`, `externals/miniz/` |
| Loader | `src/core/loader/loader.cpp` |
| Registry | `src/core/file_sys/virtual_titles.{h,cpp}`, `src/core/core.cpp` |
| Decryption | `src/core/hle/service/am/am.{h,cpp}` |
| Content-path interception | `src/core/hle/service/am/am.cpp` (`GetTitleContentPath`, `GetTitleMetadataPath`, `ScanForTitlesImpl`) |
| Settings | `CMakeModules/GenerateSettingKeys.cmake`, `src/common/settings.h` |
| Desktop UI | `src/citra_qt/configuration/config.cpp`, `configure_storage.{ui,cpp}`, `citra_qt.cpp`, `game_list.cpp` |
| Android | `model/Game.kt`, `SettingKeys.kt`, `StringSetting.kt`, `Settings.kt`, `HomeSettingsFragment.kt`, `jni/config.cpp`, `jni/default_ini.h`, `jni/native.cpp`, `res/values/strings.xml` |
| Tests | `src/tests/common/virtual_container.cpp`, `src/tests/core/file_sys/virtual_titles.cpp` |
| CI | `.github/workflows/noinstall-autosync.yml` |
