// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <fmt/format.h>
#include "common/common_paths.h"
#include "common/file_util.h"
#include "common/logging/log.h"
#include "common/virtual_container.h"
#include "miniz.h"

namespace FileUtil {

namespace {

constexpr char VIRTUAL_SEP = '#';

// Containers whose inner content may be addressed with the '#' syntax.
constexpr std::array<std::string_view, 3> CONTAINER_EXTENSIONS = {".zip", ".cia", ".zcia"};

bool HasContainerExtension(std::string_view segment) {
    return std::ranges::any_of(CONTAINER_EXTENSIONS, [&](std::string_view ext) {
        if (segment.size() < ext.size()) {
            return false;
        }
        const auto tail = segment.substr(segment.size() - ext.size());
        return std::equal(tail.begin(), tail.end(), ext.begin(), ext.end(), [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) == b;
        });
    });
}

std::vector<std::string> SplitSegments(const std::string& path) {
    std::vector<std::string> segments;
    std::size_t start = 0;
    while (true) {
        const std::size_t pos = path.find(VIRTUAL_SEP, start);
        if (pos == std::string::npos) {
            segments.push_back(path.substr(start));
            break;
        }
        segments.push_back(path.substr(start, pos - start));
        start = pos + 1;
    }
    return segments;
}

// Parses a raw-range segment of the form "0x<offset>:0x<size>" (hex) or
// "<offset>:<size>" (decimal). Returns false if the segment is not a range.
bool ParseRangeSegment(const std::string& segment, u64& offset, u64& size) {
    const std::size_t colon = segment.find(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= segment.size()) {
        return false;
    }
    const auto parse = [](const std::string& str, u64& out) {
        try {
            std::size_t consumed = 0;
            out = std::stoull(str, &consumed, 0);
            return consumed == str.size();
        } catch (...) {
            return false;
        }
    };
    return parse(segment.substr(0, colon), offset) && parse(segment.substr(colon + 1), size);
}

// Reads the local file header at local_header_ofs to find where the entry's
// data actually starts. The central directory does not store this directly.
std::optional<u64> GetStoredEntryDataOffset(const std::string& zip_path, u64 local_header_ofs) {
    constexpr u32 LOCAL_HEADER_MAGIC = 0x04034b50;
    constexpr std::size_t LOCAL_HEADER_SIZE = 30;

    IOFile zip_file(zip_path, "rb");
    if (!zip_file.IsOpen()) {
        return std::nullopt;
    }
    std::array<u8, LOCAL_HEADER_SIZE> header;
    if (zip_file.ReadAtBytes(header.data(), header.size(), local_header_ofs) != header.size()) {
        return std::nullopt;
    }
    u32 magic;
    u16 name_len, extra_len;
    std::memcpy(&magic, header.data(), sizeof(magic));
    std::memcpy(&name_len, header.data() + 26, sizeof(name_len));
    std::memcpy(&extra_len, header.data() + 28, sizeof(extra_len));
    if (magic != LOCAL_HEADER_MAGIC) {
        return std::nullopt;
    }
    return local_header_ofs + LOCAL_HEADER_SIZE + name_len + extra_len;
}

class ZipReader {
public:
    explicit ZipReader(const std::string& zip_path) : path{zip_path} {
        std::memset(&archive, 0, sizeof(archive));
        open = mz_zip_reader_init_file(&archive, zip_path.c_str(), 0) != 0;
    }

    ~ZipReader() {
        if (open) {
            mz_zip_reader_end(&archive);
        }
    }

    bool IsOpen() const {
        return open;
    }

    std::optional<mz_zip_archive_file_stat> FindEntry(const std::string& name) {
        const int index = mz_zip_reader_locate_file(&archive, name.c_str(), nullptr, 0);
        if (index < 0) {
            return std::nullopt;
        }
        mz_zip_archive_file_stat stat;
        if (!mz_zip_reader_file_stat(&archive, static_cast<mz_uint>(index), &stat)) {
            return std::nullopt;
        }
        return stat;
    }

    bool ExtractToFile(mz_uint index, const std::string& dest) {
        return mz_zip_reader_extract_to_file(&archive, index, dest.c_str(), 0) != 0;
    }

    mz_zip_archive archive;
    std::string path;
    bool open = false;
};

std::string GetExtractionCacheDir() {
    return GetUserPath(UserPath::CacheDir) + "extracted" DIR_SEP;
}

// Serializes extractions so two threads resolving the same compressed entry
// do not race writing the cache file.
std::mutex extraction_mutex;

// Returns the path of a decompressed copy of the given zip entry, extracting
// it into the cache directory if a valid copy is not already present. The
// cache key is derived from the entry's CRC32, size and name, so a changed
// zip invalidates naturally.
std::optional<std::string> GetOrExtractEntry(ZipReader& zip,
                                             const mz_zip_archive_file_stat& stat) {
    std::string safe_name = stat.m_filename;
    std::ranges::replace_if(
        safe_name, [](char c) { return c == '/' || c == '\\' || c == ':'; }, '_');
    const std::string cache_dir = GetExtractionCacheDir();
    const std::string cache_path = fmt::format("{}{:08x}_{:x}_{}", cache_dir, stat.m_crc32,
                                               stat.m_uncomp_size, safe_name);

    std::scoped_lock lock{extraction_mutex};
    if (Exists(cache_path) && GetSize(cache_path) == stat.m_uncomp_size) {
        return cache_path;
    }
    if (!CreateFullPath(cache_dir)) {
        LOG_ERROR(Common_Filesystem, "Failed to create extraction cache dir {}", cache_dir);
        return std::nullopt;
    }
    const std::string temp_path = cache_path + ".tmp";
    LOG_INFO(Common_Filesystem, "Extracting compressed zip entry {} from {}", stat.m_filename,
             zip.path);
    if (!zip.ExtractToFile(stat.m_file_index, temp_path)) {
        LOG_ERROR(Common_Filesystem, "Failed to extract {} from {}", stat.m_filename, zip.path);
        Delete(temp_path);
        return std::nullopt;
    }
    if (!Rename(temp_path, cache_path)) {
        Delete(temp_path);
        return std::nullopt;
    }
    return cache_path;
}

} // Anonymous namespace

bool IsVirtualPath(const std::string& path) {
    const std::size_t pos = path.find(VIRTUAL_SEP);
    if (pos == std::string::npos || pos == 0 || pos + 1 >= path.size()) {
        return false;
    }
    return HasContainerExtension(std::string_view(path).substr(0, pos));
}

std::optional<VirtualRange> ResolveVirtualPath(const std::string& path) {
    if (!IsVirtualPath(path)) {
        return std::nullopt;
    }
    const std::vector<std::string> segments = SplitSegments(path);

    VirtualRange range{.host_path = segments[0], .offset = 0, .size = 0};
    if (!Exists(range.host_path)) {
        return std::nullopt;
    }
    range.size = GetSize(range.host_path);

    for (std::size_t i = 1; i < segments.size(); ++i) {
        const std::string& segment = segments[i];

        u64 seg_offset, seg_size;
        if (ParseRangeSegment(segment, seg_offset, seg_size)) {
            if (seg_offset + seg_size < seg_offset || seg_offset + seg_size > range.size) {
                LOG_ERROR(Common_Filesystem, "Range segment '{}' exceeds container in {}", segment,
                          path);
                return std::nullopt;
            }
            range.offset += seg_offset;
            range.size = seg_size;
            continue;
        }

        // A zip entry segment is only meaningful when the current range is a
        // whole zip file, not a sub-range of some other container.
        if (range.offset != 0) {
            LOG_ERROR(Common_Filesystem, "Nested zip archives are not supported: {}", path);
            return std::nullopt;
        }
        ZipReader zip(range.host_path);
        if (!zip.IsOpen()) {
            LOG_ERROR(Common_Filesystem, "Not a readable zip archive: {}", range.host_path);
            return std::nullopt;
        }
        const auto stat = zip.FindEntry(segment);
        if (!stat) {
            LOG_ERROR(Common_Filesystem, "Entry '{}' not found in {}", segment, range.host_path);
            return std::nullopt;
        }
        if (stat->m_method == 0) {
            const auto data_offset = GetStoredEntryDataOffset(range.host_path,
                                                              stat->m_local_header_ofs);
            if (!data_offset) {
                return std::nullopt;
            }
            range.offset = *data_offset;
            range.size = stat->m_uncomp_size;
        } else {
            const auto extracted = GetOrExtractEntry(zip, *stat);
            if (!extracted) {
                return std::nullopt;
            }
            range.host_path = *extracted;
            range.offset = 0;
            range.size = stat->m_uncomp_size;
        }
    }
    return range;
}

std::optional<std::vector<ZipEntryInfo>> ListZipContents(const std::string& zip_path) {
    ZipReader zip(zip_path);
    if (!zip.IsOpen()) {
        return std::nullopt;
    }
    std::vector<ZipEntryInfo> entries;
    const mz_uint count = mz_zip_reader_get_num_files(&zip.archive);
    for (mz_uint i = 0; i < count; ++i) {
        mz_zip_archive_file_stat stat;
        if (!mz_zip_reader_file_stat(&zip.archive, i, &stat)) {
            continue;
        }
        if (mz_zip_reader_is_file_a_directory(&zip.archive, i)) {
            continue;
        }
        entries.push_back(ZipEntryInfo{
            .name = stat.m_filename,
            .uncompressed_size = stat.m_uncomp_size,
            .stored = stat.m_method == 0,
        });
    }
    return entries;
}

std::string MakeVirtualPath(const std::string& container, const std::string& entry) {
    return container + VIRTUAL_SEP + entry;
}

std::string MakeVirtualRangePath(const std::string& container, u64 offset, u64 size) {
    return fmt::format("{}{}0x{:x}:0x{:x}", container, VIRTUAL_SEP, offset, size);
}

} // namespace FileUtil
