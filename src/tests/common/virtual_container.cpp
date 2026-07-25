// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "common/file_util.h"
#include "common/virtual_container.h"
#include "miniz.h"

namespace {

std::vector<u8> MakePattern(std::size_t size) {
    std::vector<u8> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<u8>((i * 7 + (i >> 8)) & 0xFF);
    }
    return data;
}

struct ZipFixture {
    std::string dir;
    std::string zip_path;
    std::vector<u8> pattern = MakePattern(0x40000);

    ZipFixture() {
        dir = "./vc_test_tmp/";
        FileUtil::CreateFullPath(dir);
        zip_path = dir + "test.zip";
        FileUtil::Delete(zip_path);
        REQUIRE(mz_zip_add_mem_to_archive_file_in_place(zip_path.c_str(), "stored.bin",
                                                        pattern.data(), pattern.size(), nullptr, 0,
                                                        MZ_NO_COMPRESSION));
        REQUIRE(mz_zip_add_mem_to_archive_file_in_place(zip_path.c_str(), "deflated.bin",
                                                        pattern.data(), pattern.size(), nullptr, 0,
                                                        MZ_BEST_COMPRESSION));
    }

    ~ZipFixture() {
        FileUtil::DeleteDirRecursively(dir);
    }
};

void CheckEntryReads(const std::string& virtual_path, const std::vector<u8>& pattern) {
    FileUtil::IOFile file(virtual_path, "rb");
    REQUIRE(file.IsOpen());
    REQUIRE(file.GetSize() == pattern.size());

    // Sequential read from the start
    std::vector<u8> buffer(0x1000);
    REQUIRE(file.ReadBytes(buffer.data(), buffer.size()) == buffer.size());
    REQUIRE(std::equal(buffer.begin(), buffer.end(), pattern.begin()));
    REQUIRE(file.Tell() == buffer.size());

    // Positioned read in the middle
    REQUIRE(file.ReadAtBytes(buffer.data(), buffer.size(), 0x2340) == buffer.size());
    REQUIRE(std::equal(buffer.begin(), buffer.end(), pattern.begin() + 0x2340));

    // Seek relative to end
    REQUIRE(file.Seek(-0x10, SEEK_END));
    REQUIRE(file.Tell() == pattern.size() - 0x10);
    REQUIRE(file.ReadBytes(buffer.data(), 0x10) == 0x10);
    REQUIRE(std::equal(buffer.begin(), buffer.begin() + 0x10, pattern.end() - 0x10));

    // Reads cannot escape the view
    REQUIRE(file.ReadAtBytes(buffer.data(), buffer.size(), pattern.size() - 8) == 8);
}

} // Anonymous namespace

TEST_CASE("VirtualContainer zip entries", "[common]") {
    ZipFixture fixture;

    SECTION("path detection") {
        REQUIRE(FileUtil::IsVirtualPath(fixture.zip_path + "#stored.bin"));
        REQUIRE(FileUtil::IsVirtualPath("Update.cia#0x100:0x20"));
        REQUIRE_FALSE(FileUtil::IsVirtualPath(fixture.zip_path));
        REQUIRE_FALSE(FileUtil::IsVirtualPath("plain/file.3ds"));
        REQUIRE_FALSE(FileUtil::IsVirtualPath("weird#name.txt"));
    }

    SECTION("listing") {
        const auto entries = FileUtil::ListZipContents(fixture.zip_path);
        REQUIRE(entries.has_value());
        REQUIRE(entries->size() == 2);
        REQUIRE((*entries)[0].name == "stored.bin");
        REQUIRE((*entries)[0].stored);
        REQUIRE((*entries)[0].uncompressed_size == fixture.pattern.size());
        REQUIRE((*entries)[1].name == "deflated.bin");
        REQUIRE_FALSE((*entries)[1].stored);
    }

    SECTION("stored entry resolves to a range of the zip itself") {
        const auto range =
            FileUtil::ResolveVirtualPath(FileUtil::MakeVirtualPath(fixture.zip_path, "stored.bin"));
        REQUIRE(range.has_value());
        REQUIRE(range->host_path == fixture.zip_path);
        REQUIRE(range->size == fixture.pattern.size());
        CheckEntryReads(fixture.zip_path + "#stored.bin", fixture.pattern);
    }

    SECTION("deflated entry extracts to cache") {
        CheckEntryReads(fixture.zip_path + "#deflated.bin", fixture.pattern);
    }

    SECTION("range segments") {
        const std::string range_path = fixture.zip_path + "#stored.bin#0x1200:0x800";
        REQUIRE(FileUtil::Exists(range_path));
        REQUIRE(FileUtil::GetSize(range_path) == 0x800);

        FileUtil::IOFile file(range_path, "rb");
        REQUIRE(file.IsOpen());
        REQUIRE(file.GetSize() == 0x800);
        std::vector<u8> buffer(0x800);
        REQUIRE(file.ReadBytes(buffer.data(), buffer.size()) == buffer.size());
        REQUIRE(std::equal(buffer.begin(), buffer.end(), fixture.pattern.begin() + 0x1200));

        // Out-of-bounds range must not resolve
        REQUIRE_FALSE(FileUtil::Exists(fixture.zip_path + "#stored.bin#0x3f000:0x2000"));
    }

    SECTION("missing entries and writes are refused") {
        REQUIRE_FALSE(FileUtil::Exists(fixture.zip_path + "#nope.bin"));

        FileUtil::IOFile file(fixture.zip_path + "#stored.bin", "wb");
        REQUIRE_FALSE(file.IsGood());

        FileUtil::IOFile read_file(fixture.zip_path + "#stored.bin", "rb");
        REQUIRE(read_file.IsOpen());
        const u8 byte = 0xAA;
        REQUIRE(read_file.WriteBytes(&byte, 1) != 1);
    }
}
