// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "common/common_types.h"

namespace TestTar {

struct Member {
    std::string name; // at most 100 bytes; longer names need an 'L' or 'x' member first
    std::vector<u8> data;
    char type = '0';
};

inline std::vector<u8> ToBytes(const std::string& str) {
    return {str.begin(), str.end()};
}

/// Builds a pax extended-header record, "<length> <key>=<value>\n", where the
/// length counts the whole record including its own digits.
inline std::string PaxRecord(const std::string& key, const std::string& value) {
    const std::size_t body = 1 + key.size() + 1 + value.size() + 1;
    std::size_t length = body + 1;
    while (std::to_string(length).size() + body != length) {
        ++length;
    }
    return std::to_string(length) + " " + key + "=" + value + "\n";
}

/// Builds an uncompressed ustar archive from the given members.
inline std::vector<u8> Build(const std::vector<Member>& members) {
    std::vector<u8> tar;
    for (const auto& member : members) {
        std::vector<u8> header(512, 0);
        std::memcpy(header.data(), member.name.data(),
                    std::min<std::size_t>(member.name.size(), 100));
        std::snprintf(reinterpret_cast<char*>(&header[100]), 8, "%07o", 0644);
        std::snprintf(reinterpret_cast<char*>(&header[108]), 8, "%07o", 0);
        std::snprintf(reinterpret_cast<char*>(&header[116]), 8, "%07o", 0);
        std::snprintf(reinterpret_cast<char*>(&header[124]), 12, "%011llo",
                      static_cast<unsigned long long>(member.data.size()));
        std::snprintf(reinterpret_cast<char*>(&header[136]), 12, "%011o", 0);
        std::memset(&header[148], ' ', 8);
        header[156] = static_cast<u8>(member.type);
        std::memcpy(&header[257], "ustar", 6);
        std::memcpy(&header[263], "00", 2);
        unsigned checksum = 0;
        for (u8 byte : header) {
            checksum += byte;
        }
        std::snprintf(reinterpret_cast<char*>(&header[148]), 7, "%06o", checksum);
        header[155] = ' ';

        tar.insert(tar.end(), header.begin(), header.end());
        tar.insert(tar.end(), member.data.begin(), member.data.end());
        tar.resize((tar.size() + 511) / 512 * 512, 0);
    }
    tar.resize(tar.size() + 1024, 0); // end-of-archive marker
    return tar;
}

} // namespace TestTar
