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
// Zip entries that are stored (uncompressed) resolve to a byte range of the zip
// file itself; compressed entries are transparently extracted once into the
// cache directory and resolve to the extracted copy.

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

struct ZipEntryInfo {
    std::string name;
    u64 uncompressed_size = 0;
    bool stored = false;
};

/// Lists the file entries of a zip archive (directories are skipped).
/// Returns std::nullopt if the file is not a readable zip archive.
std::optional<std::vector<ZipEntryInfo>> ListZipContents(const std::string& zip_path);

/// Builds a virtual path from a container path and an inner segment.
std::string MakeVirtualPath(const std::string& container, const std::string& entry);

/// Builds a raw-range virtual path segment addressing size bytes at offset.
std::string MakeVirtualRangePath(const std::string& container, u64 offset, u64 size);

} // namespace FileUtil
