// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "common/file_util.h"
#include "common/virtual_container.h"
#include "miniz.h"
#include "tests/common/tar_writer.h"

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

TEST_CASE("VirtualContainer tar bundles", "[common]") {
    const std::string dir = "./vc_tar_test_tmp/";
    FileUtil::CreateFullPath(dir);
    const auto pattern = MakePattern(0x40000);
    const std::string long_name = std::string(120, 'L') + ".cia";
    const std::string pax_name = std::string(130, 'P') + ".cia";

    const auto tar = TestTar::Build({
        {.name = "sub", .type = '5'},
        {.name = "Game (USA).cci", .data = pattern},
        {.name = "././@LongLink", .data = TestTar::ToBytes(long_name + '\0'), .type = 'L'},
        {.name = long_name.substr(0, 100), .data = std::vector<u8>(0x20, 0xAB)},
        {.name = "PaxHeaders/x",
         .data = TestTar::ToBytes(TestTar::PaxRecord("path", pax_name)),
         .type = 'x'},
        {.name = "truncated-pax-name", .data = std::vector<u8>(0x30, 0xCD)},
        {.name = "./dotted.bin", .data = std::vector<u8>(1, 0xEF)},
    });
    const std::string bcci_path = dir + "Game (USA).bcci";
    {
        FileUtil::IOFile file(bcci_path, "wb");
        REQUIRE(file.WriteBytes(tar.data(), tar.size()) == tar.size());
    }

    SECTION("path detection") {
        REQUIRE(FileUtil::IsArchivePath(bcci_path));
        REQUIRE(FileUtil::IsArchivePath(dir + "x.BCXI"));
        REQUIRE(FileUtil::IsArchivePath(dir + "x.bcia"));
        REQUIRE(FileUtil::IsArchivePath(dir + "x.zip"));
        REQUIRE_FALSE(FileUtil::IsArchivePath(dir + "x.cci"));
        REQUIRE_FALSE(FileUtil::IsArchivePath(bcci_path + "#Game (USA).cci"));
        REQUIRE(FileUtil::IsVirtualPath(bcci_path + "#Game (USA).cci"));
    }

    SECTION("listing skips directories and applies long names") {
        const auto entries = FileUtil::ListArchiveContents(bcci_path);
        REQUIRE(entries.has_value());
        REQUIRE(entries->size() == 4);
        REQUIRE((*entries)[0].name == "Game (USA).cci");
        REQUIRE((*entries)[0].uncompressed_size == pattern.size());
        REQUIRE((*entries)[0].stored);
        REQUIRE((*entries)[1].name == long_name);
        REQUIRE((*entries)[2].name == pax_name);
        REQUIRE((*entries)[3].name == "dotted.bin");
    }

    SECTION("entries resolve to ranges of the bundle itself") {
        const auto range =
            FileUtil::ResolveVirtualPath(FileUtil::MakeVirtualPath(bcci_path, "Game (USA).cci"));
        REQUIRE(range.has_value());
        REQUIRE(range->host_path == bcci_path);
        REQUIRE(range->offset == 1024); // after the directory header and its own header
        REQUIRE(range->size == pattern.size());
        CheckEntryReads(bcci_path + "#Game (USA).cci", pattern);

        FileUtil::IOFile long_file(bcci_path + "#" + long_name, "rb");
        REQUIRE(long_file.IsOpen());
        REQUIRE(long_file.GetSize() == 0x20);
        FileUtil::IOFile pax_file(bcci_path + "#" + pax_name, "rb");
        REQUIRE(pax_file.IsOpen());
        REQUIRE(pax_file.GetSize() == 0x30);
        u8 byte = 0;
        REQUIRE(pax_file.ReadBytes(&byte, 1) == 1);
        REQUIRE(byte == 0xCD);
    }

    SECTION("entry prefixes stream without extraction") {
        const auto prefix = FileUtil::ReadArchiveEntryPrefix(bcci_path, "Game (USA).cci", 0x100);
        REQUIRE(prefix.has_value());
        REQUIRE(std::equal(prefix->begin(), prefix->end(), pattern.begin()));
        REQUIRE_FALSE(FileUtil::ReadArchiveEntryPrefix(bcci_path, "missing.cia", 0x10));
    }

    SECTION("range segments inside a tar entry") {
        const std::string range_path = bcci_path + "#Game (USA).cci#0x1200:0x800";
        REQUIRE(FileUtil::GetSize(range_path) == 0x800);
        REQUIRE_FALSE(FileUtil::Exists(bcci_path + "#Game (USA).cci#0x3f000:0x2000"));
    }

    SECTION("corrupt or truncated archives are rejected") {
        auto corrupt = tar;
        corrupt[0] ^= 0xFF; // breaks the first header's checksum
        const std::string corrupt_path = dir + "corrupt.bcci";
        {
            FileUtil::IOFile file(corrupt_path, "wb");
            REQUIRE(file.WriteBytes(corrupt.data(), corrupt.size()) == corrupt.size());
        }
        REQUIRE_FALSE(FileUtil::ListArchiveContents(corrupt_path).has_value());

        const std::string truncated_path = dir + "truncated.bcci";
        {
            FileUtil::IOFile file(truncated_path, "wb");
            REQUIRE(file.WriteBytes(tar.data(), 0x2000) == 0x2000);
        }
        REQUIRE_FALSE(FileUtil::ListArchiveContents(truncated_path).has_value());
        REQUIRE_FALSE(FileUtil::Exists(truncated_path + "#Game (USA).cci"));
    }

    FileUtil::DeleteDirRecursively(dir);
}
