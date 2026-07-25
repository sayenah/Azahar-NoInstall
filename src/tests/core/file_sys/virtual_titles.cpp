// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <cstring>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "common/alignment.h"
#include "common/file_util.h"
#include "common/settings.h"
#include "common/virtual_container.h"
#include "core/file_sys/cia_container.h"
#include "core/file_sys/title_metadata.h"
#include "core/file_sys/virtual_titles.h"
#include "core/loader/loader.h"
#include "miniz.h"

namespace {

void WriteBE64(std::vector<u8>& buffer, std::size_t offset, u64 value) {
    for (int i = 0; i < 8; ++i) {
        buffer[offset + i] = static_cast<u8>(value >> (56 - i * 8));
    }
}

void WriteBE32(std::vector<u8>& buffer, std::size_t offset, u32 value) {
    for (int i = 0; i < 4; ++i) {
        buffer[offset + i] = static_cast<u8>(value >> (24 - i * 8));
    }
}

void WriteBE16(std::vector<u8>& buffer, std::size_t offset, u16 value) {
    buffer[offset] = static_cast<u8>(value >> 8);
    buffer[offset + 1] = static_cast<u8>(value);
}

// Builds a minimal TMD: RSA-2048/SHA-256 signature type, one content record.
std::vector<u8> BuildTestTmd(u64 title_id, u16 title_version, u64 content_size, u16 content_type) {
    constexpr std::size_t SIGNATURE_SIZE = 0x100;
    // TMD body starts at the signature rounded up to the next 0x40 boundary.
    constexpr std::size_t BODY_START = Common::AlignUp(sizeof(u32) + SIGNATURE_SIZE, 0x40);
    constexpr std::size_t BODY_SIZE = 0x9C4;
    constexpr std::size_t CHUNK_SIZE = 0x30;

    std::vector<u8> tmd(BODY_START + BODY_SIZE + CHUNK_SIZE, 0);
    WriteBE32(tmd, 0, 0x00010004); // signature type
    WriteBE64(tmd, BODY_START + 0x4C, title_id);
    WriteBE16(tmd, BODY_START + 0x9C, title_version);
    WriteBE16(tmd, BODY_START + 0x9E, 1); // content count

    const std::size_t chunk = BODY_START + BODY_SIZE;
    WriteBE32(tmd, chunk + 0x00, 0);            // content id
    WriteBE16(tmd, chunk + 0x04, 0);            // content index
    WriteBE16(tmd, chunk + 0x06, content_type); // type flags
    WriteBE64(tmd, chunk + 0x08, content_size);
    return tmd;
}

// Assembles a CIA with no certificates/ticket/meta and a single content blob.
std::vector<u8> BuildTestCia(u64 title_id, u16 title_version, const std::vector<u8>& content,
                             u16 content_type = 0) {
    const std::vector<u8> tmd = BuildTestTmd(title_id, title_version, content.size(), content_type);

    FileSys::CIAHeader header{};
    header.header_size = static_cast<u32>(FileSys::CIA_HEADER_SIZE);
    header.tmd_size = static_cast<u32>(tmd.size());
    header.content_size = content.size();
    header.SetContentPresent(0);

    const std::size_t tmd_offset =
        Common::AlignUp(FileSys::CIA_HEADER_SIZE, FileSys::CIA_SECTION_ALIGNMENT);
    const std::size_t content_offset =
        Common::AlignUp(tmd_offset + tmd.size(), FileSys::CIA_SECTION_ALIGNMENT);

    std::vector<u8> cia(content_offset + content.size(), 0);
    std::memcpy(cia.data(), &header, sizeof(header));
    std::memcpy(cia.data() + tmd_offset, tmd.data(), tmd.size());
    std::memcpy(cia.data() + content_offset, content.data(), content.size());
    return cia;
}

std::vector<u8> MakeContent(std::size_t size, u8 seed) {
    std::vector<u8> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<u8>(seed + i * 3);
    }
    return data;
}

void WriteFile(const std::string& path, const std::vector<u8>& data) {
    FileUtil::IOFile file(path, "wb");
    REQUIRE(file.IsOpen());
    REQUIRE(file.WriteBytes(data.data(), data.size()) == data.size());
}

struct FoldersFixture {
    std::string dir = "./vt_test_tmp/";
    std::string updates_dir = dir + "updates/";
    std::string dlc_dir = dir + "dlc/";
    std::string games_dir = dir + "games/";

    FoldersFixture() {
        FileUtil::CreateFullPath(updates_dir);
        FileUtil::CreateFullPath(dlc_dir);
        FileUtil::CreateFullPath(games_dir);
        Settings::values.updates_folder = updates_dir;
        Settings::values.dlc_folder = dlc_dir;
    }

    ~FoldersFixture() {
        Settings::values.updates_folder = std::string{};
        Settings::values.dlc_folder = std::string{};
        FileSys::VirtualTitles::Clear();
        FileUtil::DeleteDirRecursively(dir);
    }
};

constexpr u64 BASE_TID = 0x00040000AABBCC00ULL;
constexpr u64 UPDATE_TID = 0x0004000EAABBCC00ULL;
constexpr u64 DLC_TID = 0x0004008CAABBCC00ULL;

} // Anonymous namespace

TEST_CASE("VirtualTitles companion scan", "[core][file_sys]") {
    FoldersFixture fixture;
    const std::string game_path = fixture.games_dir + "MyGame (USA).3ds";

    SECTION("plain update CIA matched by No-Intro name") {
        const auto content = MakeContent(0x800, 0x11);
        WriteFile(fixture.updates_dir + "MyGame (USA) (Update).cia",
                  BuildTestCia(UPDATE_TID, 0x120, content));

        FileSys::VirtualTitles::ScanForCompanionTitles(BASE_TID, game_path);
        REQUIRE(FileSys::VirtualTitles::HasTitle(UPDATE_TID));

        const auto content_path = FileSys::VirtualTitles::GetContentPath(UPDATE_TID, 0);
        REQUIRE(content_path.has_value());
        FileUtil::IOFile content_file(*content_path, "rb");
        REQUIRE(content_file.GetSize() == content.size());
        std::vector<u8> read_back(content.size());
        REQUIRE(content_file.ReadBytes(read_back.data(), read_back.size()) == read_back.size());
        REQUIRE(read_back == content);

        const auto tmd_path = FileSys::VirtualTitles::GetMetadataPath(UPDATE_TID);
        REQUIRE(tmd_path.has_value());
        FileSys::TitleMetadata tmd;
        REQUIRE(tmd.Load(*tmd_path) == Loader::ResultStatus::Success);
        REQUIRE(tmd.GetTitleID() == UPDATE_TID);
        REQUIRE(tmd.GetTitleVersion() == 0x120);
    }

    SECTION("zipped DLC CIA (deflated) matched by zip name") {
        const auto content = MakeContent(0x1000, 0x22);
        const auto cia = BuildTestCia(DLC_TID, 0x10, content);
        const std::string zip_path = fixture.dlc_dir + "MyGame (USA) (DLC).zip";
        REQUIRE(mz_zip_add_mem_to_archive_file_in_place(zip_path.c_str(), "MyGame (USA) (DLC).cia",
                                                        cia.data(), cia.size(), nullptr, 0,
                                                        MZ_BEST_COMPRESSION));

        FileSys::VirtualTitles::ScanForCompanionTitles(BASE_TID, game_path);
        REQUIRE(FileSys::VirtualTitles::HasTitle(DLC_TID));

        const auto content_path = FileSys::VirtualTitles::GetContentPath(DLC_TID, 0);
        REQUIRE(content_path.has_value());
        FileUtil::IOFile content_file(*content_path, "rb");
        std::vector<u8> read_back(content.size());
        REQUIRE(content_file.ReadBytes(read_back.data(), read_back.size()) == read_back.size());
        REQUIRE(read_back == content);
    }

    SECTION("mismatched file name still registers via title ID probing") {
        WriteFile(fixture.updates_dir + "some other name entirely.cia",
                  BuildTestCia(UPDATE_TID, 3, MakeContent(0x100, 0x33)));

        FileSys::VirtualTitles::ScanForCompanionTitles(BASE_TID, game_path);
        REQUIRE(FileSys::VirtualTitles::HasTitle(UPDATE_TID));
    }

    SECTION("unrelated title id is not registered") {
        WriteFile(fixture.updates_dir + "MyGame (USA) (Update).cia",
                  BuildTestCia(0x0004000E11111111ULL, 3, MakeContent(0x100, 0x44)));

        FileSys::VirtualTitles::ScanForCompanionTitles(BASE_TID, game_path);
        REQUIRE_FALSE(FileSys::VirtualTitles::HasTitle(UPDATE_TID));
        REQUIRE_FALSE(FileSys::VirtualTitles::HasTitle(0x0004000E11111111ULL));
    }

    SECTION("encrypted content is rejected") {
        WriteFile(fixture.updates_dir + "MyGame (USA) (Update).cia",
                  BuildTestCia(UPDATE_TID, 3, MakeContent(0x100, 0x55),
                               FileSys::TMDContentTypeFlag::Encrypted));

        FileSys::VirtualTitles::ScanForCompanionTitles(BASE_TID, game_path);
        REQUIRE_FALSE(FileSys::VirtualTitles::HasTitle(UPDATE_TID));
    }

    SECTION("highest version wins") {
        WriteFile(fixture.updates_dir + "MyGame (USA) (Update).cia",
                  BuildTestCia(UPDATE_TID, 1, MakeContent(0x100, 0x66)));
        WriteFile(fixture.updates_dir + "MyGame (USA) (v2) (Update).cia",
                  BuildTestCia(UPDATE_TID, 2, MakeContent(0x100, 0x77)));

        FileSys::VirtualTitles::ScanForCompanionTitles(BASE_TID, game_path);
        const auto tmd_path = FileSys::VirtualTitles::GetMetadataPath(UPDATE_TID);
        REQUIRE(tmd_path.has_value());
        FileSys::TitleMetadata tmd;
        REQUIRE(tmd.Load(*tmd_path) == Loader::ResultStatus::Success);
        REQUIRE(tmd.GetTitleVersion() == 2);
    }

    SECTION("update CIA bundled inside the game's own zip") {
        const auto content = MakeContent(0x200, 0x88);
        const auto cia = BuildTestCia(UPDATE_TID, 7, content);
        const std::string game_zip = fixture.games_dir + "MyGame (USA).zip";
        const std::vector<u8> fake_game(0x100, 0x99);
        REQUIRE(mz_zip_add_mem_to_archive_file_in_place(game_zip.c_str(), "MyGame (USA).3ds",
                                                        fake_game.data(), fake_game.size(), nullptr,
                                                        0, MZ_NO_COMPRESSION));
        REQUIRE(mz_zip_add_mem_to_archive_file_in_place(game_zip.c_str(),
                                                        "MyGame (USA) (Update).cia", cia.data(),
                                                        cia.size(), nullptr, 0, MZ_NO_COMPRESSION));

        FileSys::VirtualTitles::ScanForCompanionTitles(
            BASE_TID, FileUtil::MakeVirtualPath(game_zip, "MyGame (USA).3ds"));
        REQUIRE(FileSys::VirtualTitles::HasTitle(UPDATE_TID));

        const auto content_path = FileSys::VirtualTitles::GetContentPath(UPDATE_TID, 0);
        REQUIRE(content_path.has_value());
        FileUtil::IOFile content_file(*content_path, "rb");
        std::vector<u8> read_back(content.size());
        REQUIRE(content_file.ReadBytes(read_back.data(), read_back.size()) == read_back.size());
        REQUIRE(read_back == content);
    }
}
