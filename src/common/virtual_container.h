// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <optional>
#include <string>
#include <vector>
#include "common/common_types.h"

namespace FileUtil {

// Virtual container paths address read-only content inside another file without
// requiring it to be unpacked or installed. Segments are separated by '#':
//   "Game.zip#Game.3ds"            -> the entry "Game.3ds" inside Game.zip
//   "Update.cia#0x2940:0x1000"     -> 0x1000 bytes at offset 0x2940 of Update.cia
//   "Pack.zip#Update.cia#0x40:0x8" -> a range within a zip entry
//   "Game.bcci#Game (DLC).cia"     -> an entry inside a bundle (tar) archive
// Zip entries that are stored (uncompressed) resolve to a byte range of the zip
// file itself; compressed entries are transparently extracted once into the
// cache directory and resolve to the extracted copy. Bundle ROMs (.bcci, .bcxi,
// .bcia; see azahar-emu/azahar#2369) are plain uncompressed tar archives, so
// their entries always resolve to a byte range of the bundle itself.

/// Returns true if the path uses the '#' virtual container syntax.
bool IsVirtualPath(const std::string& path);

/// A resolved virtual path: a byte range of a real file on the host filesystem.
struct VirtualRange {
    std::string host_path;
    u64 offset = 0;
    u64 size = 0;
};

/// Resolves a virtual container path to a host file range, extracting
/// compressed zip entries to the cache directory when necessary.
/// Returns std::nullopt if any segment cannot be resolved.
std::optional<VirtualRange> ResolveVirtualPath(const std::string& path);

/// Returns true if the (non-virtual) path names an archive whose entries can be
/// listed and addressed: a zip, or a tar-based bundle ROM.
bool IsArchivePath(const std::string& path);

struct ArchiveEntryInfo {
    std::string name;
    u64 uncompressed_size = 0;
    bool stored = false;
};

/// Lists the file entries of a zip archive (directories are skipped).
/// Returns std::nullopt if the file is not a readable zip archive.
std::optional<std::vector<ArchiveEntryInfo>> ListZipContents(const std::string& zip_path);

/// Lists the regular file entries of a tar archive. Understands ustar plus the
/// GNU and pax long-name extensions. Returns std::nullopt if the file is not a
/// well-formed tar archive.
std::optional<std::vector<ArchiveEntryInfo>> ListTarContents(const std::string& tar_path);

/// Lists the file entries of any archive IsArchivePath accepts.
std::optional<std::vector<ArchiveEntryInfo>> ListArchiveContents(const std::string& archive_path);

/// Reads up to max_bytes from the start of a zip entry by streaming, without
/// extracting the entry to the cache. Returns std::nullopt on failure.
std::optional<std::vector<u8>> ReadZipEntryPrefix(const std::string& zip_path,
                                                  const std::string& entry_name,
                                                  std::size_t max_bytes);

/// Reads up to max_bytes from the start of an entry of any archive
/// IsArchivePath accepts, without extracting it to the cache.
std::optional<std::vector<u8>> ReadArchiveEntryPrefix(const std::string& archive_path,
                                                      const std::string& entry_name,
                                                      std::size_t max_bytes);

/// Deletes every file extracted from compressed zip entries. Safe to call
/// whenever no emulation session is running; entries are re-extracted on
/// demand the next time they are needed.
void ClearExtractionCache();

/// Builds a virtual path from a container path and an inner segment.
std::string MakeVirtualPath(const std::string& container, const std::string& entry);

/// Builds a raw-range virtual path segment addressing size bytes at offset.
std::string MakeVirtualRangePath(const std::string& container, u64 offset, u64 size);

} // namespace FileUtil
