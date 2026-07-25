// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include "common/logging/log.h"
#include "common/string_util.h"
#include "common/virtual_container.h"
#include "core/core.h"
#include "core/file_sys/cia_container.h"
#include "core/file_sys/title_metadata.h"
#include "core/hle/kernel/process.h"
#include "core/hle/service/am/am.h"
#include "core/loader/3dsx.h"
#include "core/loader/artic.h"
#include "core/loader/elf.h"
#include "core/loader/ncch.h"

namespace Loader {

FileType IdentifyFile(FileUtil::IOFile& file) {
    FileType type;

#define CHECK_TYPE(loader)                                                                         \
    type = AppLoader_##loader::IdentifyType(&file);                                                \
    if (FileType::Error != type)                                                                   \
        return type;

    CHECK_TYPE(THREEDSX)
    CHECK_TYPE(ELF)
    CHECK_TYPE(NCCH)

#undef CHECK_TYPE

    return FileType::Unknown;
}

FileType IdentifyFile(const std::string& file_name) {
    FileUtil::IOFile file(file_name, "rb");
    if (!file.IsOpen()) {
        LOG_ERROR(Loader, "Failed to load file {}", file_name);
        return FileType::Unknown;
    }

    return IdentifyFile(file);
}

FileType GuessFromExtension(const std::string& extension_) {
    std::string extension = Common::ToLower(extension_);

    if (extension == ".elf" || extension == ".axf")
        return FileType::ELF;

    if (extension == ".cci" || extension == ".zcci" || extension == ".3ds")
        return FileType::CCI;

    if (extension == ".cxi" || extension == ".app" || extension == ".zcxi")
        return FileType::CXI;

    if (extension == ".3dsx" || extension == ".z3dsx")
        return FileType::THREEDSX;

    if (extension == ".cia" || extension == ".zcia")
        return FileType::CIA;

    return FileType::Unknown;
}

const char* GetFileTypeString(FileType type, bool is_compressed) {
    switch (type) {
    case FileType::CCI:
        return is_compressed ? "NCSD (Z)" : "NCSD";
    case FileType::CXI:
        return is_compressed ? "NCCH (Z)" : "NCCH";
    case FileType::CIA:
        return is_compressed ? "CIA (Z)" : "CIA";
    case FileType::ELF:
        return "ELF";
    case FileType::THREEDSX:
        return is_compressed ? "3DSX (Z)" : "3DSX";
    case FileType::ARTIC:
        return "ARTIC";
    case FileType::Error:
    case FileType::Unknown:
        break;
    }

    return "unknown";
}

/**
 * Get a loader for a file with a specific type
 * @param file The file to load
 * @param type The type of the file
 * @param filename the file name (without path)
 * @param filepath the file full path (with name)
 * @return std::unique_ptr<AppLoader> a pointer to a loader object;  nullptr for unsupported type
 */
static std::unique_ptr<AppLoader> GetFileLoader(Core::System& system, FileUtil::IOFile&& file,
                                                FileType type, const std::string& filename,
                                                const std::string& filepath) {
    switch (type) {

    // 3DSX file format.
    case FileType::THREEDSX:
        return std::make_unique<AppLoader_THREEDSX>(system, std::move(file), filename, filepath);

    // Standard ELF file format.
    case FileType::ELF:
        return std::make_unique<AppLoader_ELF>(system, std::move(file), filename);

    // NCCH/NCSD container formats.
    case FileType::CXI:
    case FileType::CCI:
        return std::make_unique<AppLoader_NCCH>(system, std::move(file), filepath);

    case FileType::ARTIC: {
        Apploader_Artic::ArticInitMode mode = Apploader_Artic::ArticInitMode::NONE;
        if (filename.starts_with("articinio://")) {
            mode = Apploader_Artic::ArticInitMode::O3DS;
        } else if (filename.starts_with("articinin://")) {
            mode = Apploader_Artic::ArticInitMode::N3DS;
        }
        auto strToUInt = [](const std::string& str) -> int {
            char* pEnd = NULL;
            unsigned long ul = ::strtoul(str.c_str(), &pEnd, 10);
            if (*pEnd)
                return -1;
            return static_cast<int>(ul);
        };

        u16 port = 5543;
        std::string server_addr = filename.substr(12);
        auto pos = server_addr.find(":");
        if (pos != server_addr.npos) {
            int newVal = strToUInt(server_addr.substr(pos + 1));
            if (newVal >= 0 && newVal <= 0xFFFF) {
                port = static_cast<u16>(newVal);
                server_addr = server_addr.substr(0, pos);
            }
        }
        return std::make_unique<Apploader_Artic>(system, server_addr, port, mode);
    }

    default:
        return nullptr;
    }
}

static bool IsZipPath(const std::string& path) {
    if (FileUtil::IsVirtualPath(path)) {
        return false;
    }
    std::string extension;
    Common::SplitPath(path, nullptr, nullptr, &extension);
    return Common::ToLower(extension) == ".zip";
}

static std::optional<std::string> FindBootableZipEntry(const std::string& zip_path) {
    const auto entries = FileUtil::ListZipContents(zip_path);
    if (!entries) {
        LOG_ERROR(Loader, "Not a readable zip archive: {}", zip_path);
        return std::nullopt;
    }

    // Lower is better; ties keep listing order. Full games are preferred over
    // homebrew formats when a zip contains several bootable files.
    const auto priority = [](FileType type) -> int {
        switch (type) {
        case FileType::CCI:
            return 0;
        case FileType::CXI:
            return 1;
        case FileType::CIA:
            return 2;
        case FileType::THREEDSX:
            return 3;
        case FileType::ELF:
            return 4;
        default:
            return -1;
        }
    };

    std::optional<std::string> best;
    int best_priority = std::numeric_limits<int>::max();
    for (const auto& entry : entries.value()) {
        // Skip macOS resource-fork junk and hidden entries
        if (entry.name.starts_with("__MACOSX") || entry.name.starts_with(".")) {
            continue;
        }
        std::string extension;
        Common::SplitPath(entry.name, nullptr, nullptr, &extension);
        const int entry_priority = priority(GuessFromExtension(extension));
        if (entry_priority >= 0 && entry_priority < best_priority) {
            best = entry.name;
            best_priority = entry_priority;
        }
    }
    if (!best) {
        LOG_ERROR(Loader, "No bootable file found inside {}", zip_path);
    }
    return best;
}

/**
 * Builds a loader that boots a CIA's executable content in place, without
 * installing it. The CIA's main content is addressed as a virtual byte range
 * (see virtual_container.h) and handed to the regular NCCH loader.
 */
static std::unique_ptr<AppLoader> GetCIADirectLoader(Core::System& system,
                                                     const std::string& filepath) {
    FileUtil::IOFile file(filepath, "rb");
    if (!file.IsOpen()) {
        return nullptr;
    }
    if (file.IsCompressed()) {
        LOG_ERROR(Loader, "Compressed CIA files cannot be booted directly: {}", filepath);
        return nullptr;
    }

    FileSys::CIAContainer container;
    if (container.Load(&file) != ResultStatus::Success) {
        LOG_ERROR(Loader, "Failed to parse CIA file {}", filepath);
        return nullptr;
    }

    const auto& tmd = container.GetTitleMetadata();
    const u64 title_id = tmd.GetTitleID();
    if (title_id & Service::AM::TWL_TITLE_ID_FLAG) {
        LOG_ERROR(Loader, "DSiWare titles cannot be executed: {}", filepath);
        return nullptr;
    }
    constexpr u32 TID_HIGH_APPLICATION = 0x00040000;
    if (static_cast<u32>(title_id >> 32) != TID_HIGH_APPLICATION) {
        LOG_ERROR(Loader,
                  "CIA {} is not an application (title ID {:016x}); updates and DLC are "
                  "picked up automatically from their content folders",
                  filepath, title_id);
        return nullptr;
    }
    file.Close();

    // Resolve the main content to a loadable path: a virtual range for
    // already-plaintext content, or a decrypted cache file for encrypted
    // content (when the console keys are available).
    const auto ncch_path =
        Service::AM::PrepareCIAContentForLoad(filepath, FileSys::TMDContentIndex::Main);
    if (!ncch_path) {
        LOG_ERROR(Loader,
                  "CIA {} could not be prepared for direct boot; if it is encrypted, ensure the "
                  "console keys (keys.txt) are present",
                  filepath);
        return nullptr;
    }

    FileUtil::IOFile ncch_file(*ncch_path, "rb");
    if (!ncch_file.IsOpen()) {
        return nullptr;
    }
    LOG_INFO(Loader, "Booting CIA {} directly", filepath);
    return std::make_unique<AppLoader_NCCH>(system, std::move(ncch_file), *ncch_path);
}

std::unique_ptr<AppLoader> GetLoader(const std::string& filename) {
    if (filename.starts_with("articbase://") || filename.starts_with("articinio://") ||
        filename.starts_with("articinin://")) {
        return GetFileLoader(Core::System::GetInstance(), FileUtil::IOFile(), FileType::ARTIC,
                             filename, "");
    }

    // A zip archive boots the best bootable entry it contains, in place.
    std::string load_path = filename;
    if (IsZipPath(load_path)) {
        const auto entry = FindBootableZipEntry(load_path);
        if (!entry) {
            return nullptr;
        }
        load_path = FileUtil::MakeVirtualPath(load_path, *entry);
    }

    FileUtil::IOFile file(load_path, "rb");
    if (!file.IsOpen()) {
        LOG_ERROR(Loader, "Failed to load file {}", load_path);
        return nullptr;
    }

    std::string filename_filename, filename_extension;
    Common::SplitPath(load_path, nullptr, &filename_filename, &filename_extension);

    FileType type = IdentifyFile(file);
    FileType filename_type = GuessFromExtension(filename_extension);

    if (type != filename_type) {
        // Do not show the error for CIA files, as their type cannot be determined.
        if (!(type == FileType::Unknown && filename_type == FileType::CIA)) {
            LOG_WARNING(Loader, "File {} has a different type than its extension.", load_path);
        }

        if (FileType::Unknown == type)
            type = filename_type;
    }

    LOG_DEBUG(Loader, "Loading file {} as {}...", load_path, GetFileTypeString(type));

    auto& system = Core::System::GetInstance();

    if (type == FileType::CIA) {
        file.Close();
        return GetCIADirectLoader(system, load_path);
    }

    // An encrypted NCCH/NCSD ROM (.cxi/.cci/.3ds) is decrypted in place to the
    // transient cache when the console keys are available, then loaded from
    // there; plaintext ROMs load unchanged.
    if (type == FileType::CXI || type == FileType::CCI) {
        file.Close();
        if (const auto decrypted = Service::AM::PrepareEncryptedRomForLoad(load_path)) {
            LOG_INFO(Loader, "Booting encrypted ROM {} via decrypted cache", load_path);
            load_path = *decrypted;
        }
        FileUtil::IOFile reopened(load_path, "rb");
        if (!reopened.IsOpen()) {
            LOG_ERROR(Loader, "Failed to load file {}", load_path);
            return nullptr;
        }
        return GetFileLoader(system, std::move(reopened), type, filename_filename, load_path);
    }

    return GetFileLoader(system, std::move(file), type, filename_filename, load_path);
}

} // namespace Loader
