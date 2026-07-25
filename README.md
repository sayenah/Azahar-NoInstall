<div align="center">

# 🎮 Azahar **NoInstall**

### A 3DS emulator that just *runs* your games — no installing, no clutter, no fuss.

A friendly fork of [**Azahar**](https://github.com/azahar-emu/azahar) that adds a complete **no-install workflow**: point it at your folders, click a game, and play. Updates, DLC, and DSiWare are picked up automatically. Encrypted and decrypted dumps both work. Nothing is ever written into the emulated console.

![Latest NoInstall Release](https://img.shields.io/github/v/release/sayenah/Azahar-NoInstall?label=NoInstall%20Release&color=8a63d2)
![Tracks Upstream](https://img.shields.io/badge/tracks-azahar--emu%2Fazahar-blue)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Android-brightgreen)
![License](https://img.shields.io/badge/license-GPLv2-orange)

</div>

---

## ✨ What makes this fork different

Stock Azahar (like Citra before it) makes you **install** `.cia` files — DLC, updates and DSiWare all get imported into the emulated console's storage, where they tangle up with your save files and turn cloud-syncing into a nightmare. This fork throws that whole model out.

| | Stock Azahar | **Azahar NoInstall** |
|---|:---:|:---:|
| Boot a game from a `.zip` | ❌ | ✅ |
| Boot a `.cia` without installing | ❌ | ✅ |
| DLC / Updates from a folder | ❌ (must install) | ✅ (drop-in, auto-matched) |
| Encrypted **and** decrypted dumps | ⚠️ install-only | ✅ everywhere |
| Writes into emulated NAND/SD | Always | **Never** |
| Save files stay separate from content | ❌ | ✅ |

### 📦 Run anything, in place

Open a game as a `.zip`, `.cci`, `.cxi`, `.3ds`, or `.cia` — it boots directly. A `.zip` can even bundle the game **and** its update/DLC together as a single self-contained pack.

### 🗂️ Folder-based DLC, Updates & DSiWare

Set three folders once. Drop your `.cia` files (or `.zip`s containing them) in. When you launch a game, its update and DLC are found automatically — matched by [No-Intro](https://no-intro.org/) filenames and **verified by title ID**, so the wrong content can never attach to the wrong game.

```
Updates/   Zelda OoT 3D (USA) (Update).cia
DLC/       Fire Emblem Awakening (USA) (DLC).zip
DSiWare/   Dr. Mario Express (USA).cia
Games/     Zelda OoT 3D (USA).zip
```

### 🔐 Encrypted or decrypted — both just work

Encrypted cartridge dumps and CIAs no longer need to be pre-decrypted. When the console keys are available (Azahar already ships the common ones; add your own `keys.txt` for the rest), encrypted content is decrypted on the fly into a **temporary cache that is wiped when you close the emulator**. Your original files are never modified, and nothing is left behind.

### 🧹 Zero clutter, by design

- Nothing is ever written into the emulated NAND/SD card.
- Save data (`.../title/<id>/data/`) stays cleanly separated from game content — **cloud-sync friendly at last**.
- Decompressed and decrypted files live in a transient cache that clears on exit.

---

## ⬇️ Download

Grab the latest build from the [**Releases**](https://github.com/sayenah/Azahar-NoInstall/releases) page. Every release is named `<version>-noinstall` and is **built automatically from the matching upstream Azahar release**, so you always get the NoInstall features on top of a real, versioned Azahar.

| Platform | File |
|---|---|
| 🪟 **Windows** (x64) | `...-windows-msvc.zip` |
| 🍎 **macOS** (Apple Silicon) | `...-macos-arm64.zip` — run `xattr -cr Azahar.app` once before first launch |
| 🤖 **Android** (sideload) | `...-android.apk` |

> [!NOTE]
> These are unofficial personal builds. They are **not** affiliated with or endorsed by the Azahar project. For the official emulator, see [azahar-emu/azahar](https://github.com/azahar-emu/azahar).

---

## 🚀 Getting started

1. **Add your game folders.** Desktop: the game list directory picker, as usual. Android: *Home → Select Applications Folder*.
2. **Set your content folders.**
   - **Desktop:** *Emulation → Configure → Storage → No-Install Content Folders* — pick your Updates, DLC and DSiWare folders.
   - **Android:** *Home → Select Updates / DLC / DSiWare Folder*.
3. **Name your files** with the No-Intro convention so they auto-match — e.g. `Game (Region) (Update).cia`, `Game (Region) (DLC).zip`. (If names don't match, every file in the folder is still probed by title ID as a fallback.)
4. **Play.** Click a game. Its update and DLC attach automatically; encrypted files decrypt transparently.

> [!TIP]
> Want *zero* disk writes even mid-session? Store your zips **uncompressed** (`zip -0`). Uncompressed (stored) entries are read directly out of the archive — nothing is ever extracted.

> [!IMPORTANT]
> Decryption requires the 3DS console keys. Azahar ships the common ones, so most retail content works out of the box. For anything that doesn't decrypt, place your own `keys.txt` in Azahar's `sysdata` folder. This fork only decrypts content **you supply** — please only use it with games you own.

---

## 🛠️ Building & contributing

- **Build from source:** the standard [Azahar build instructions](https://github.com/azahar-emu/azahar/wiki/Building-From-Source) apply unchanged.
- **How the NoInstall system works** (architecture, file map, gotchas, how to extend it, how the auto-release pipeline works): see [**`docs/NOINSTALL.md`**](docs/NOINSTALL.md). Start here if you're modifying this fork.

---

## ❤️ Credits & license

This project is a fork of **[Azahar](https://github.com/azahar-emu/azahar)**, itself born from the merger of PabloMK7's Citra fork and Lime3DS. All of the heavy lifting — the actual 3DS emulation — is their work, and this fork stands entirely on it. Please support and credit the upstream project.

Licensed under **GPLv2 or any later version**, the same as Azahar. See [`license.txt`](license.txt).
