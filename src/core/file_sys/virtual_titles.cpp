// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include "common/common_paths.h"
#include "common/file_util.h"
#include "common/logging/log.h"
#include "common/settings.h"
#include "common/string_util.h"
#include "common/virtual_container.h"
#include "core/file_sys/cia_container.h"
#include "core/file_sys/title_metadata.h"
#include "core/file_sys/virtual_titles.h"
#include "core/loader/loader.h"

namespace FileSys::VirtualTitles {

namespace {

constexpr u64 TID_HIGH_MASK = 0xFFFFFFFF00000000ULL;
constexpr u64 TID_HIGH_APPLICATION = 0x0004000000000000ULL;
constexpr u64 TID_HIGH_UPDATE = 0x0004000E00000000ULL;
constexpr u64 TID_HIGH_DLC = 0x0004008C00000000ULL;

struct Entry {
    std::string cia_path; // plain or virtual (zip entry) path of the CIA
    std::unique_ptr<CIAContainer> container;
    u16 version = 0;
};

std::mutex registry_mutex;
std::map<u64, Entry> registry;

// A candidate CIA file: either a plain file on disk or an entry inside a zip.
struct Candidate {
    std::string cia_path; // path handed to the virtual path scheme
    std::string zip_path; // empty for plain files
    std::string entry_name;
    bool name_matched = false;

    bool InZip() const {
        return !zip_path.empty();
    }
};

std::string StemOf(const std::string& path) {
    std::string stem;
    Common::SplitPath(path, nullptr, &stem, nullptr);
    return Common::ToLower(stem);
}

bool NameMatches(const std::string& stem, const std::string& base_stem, const char* marker) {
    return stem.starts_with(base_stem) && stem.find(marker) != std::string::npos;
}

std::optional<std::vector<u8>> ReadCandidatePrefix(const Candidate& candidate,
                                                   std::size_t max_bytes) {
    if (candidate.InZip()) {
        return FileUtil::ReadZipEntryPrefix(candidate.zip_path, candidate.entry_name, max_bytes);
    }
    FileUtil::IOFile file(candidate.cia_path, "rb");
    if (!file.IsOpen() || file.IsCompressed()) {
        return std::nullopt;
    }
    std::vector<u8> buffer(std::min<std::size_t>(max_bytes, file.GetSize()));
    if (file.ReadAtBytes(buffer.data(), buffer.size(), 0) != buffer.size()) {
        return std::nullopt;
    }
    return buffer;
}

/**
 * Parses the candidate's CIA header and TMD from a streamed prefix (no
 * extraction) and registers it if its title ID is one of the wanted ones.
 * Returns the registered title ID, or 0.
 */
u64 TryRegister(const Candidate& candidate, std::initializer_list<u64> wanted_tids) {
    constexpr std::size_t INITIAL_PREFIX_SIZE = 0x10000;
    auto prefix = ReadCandidatePrefix(candidate, INITIAL_PREFIX_SIZE);
    if (!prefix || prefix->size() < CIA_HEADER_SIZE) {
        return 0;
    }

    auto container = std::make_unique<CIAContainer>();
    if (container->LoadHeader(*prefix) != Loader::ResultStatus::Success) {
        return 0;
    }
    const std::size_t tmd_end =
        container->GetTitleMetadataOffset() + container->GetTitleMetadataSize();
    if (prefix->size() < tmd_end) {
        prefix = ReadCandidatePrefix(candidate, tmd_end);
        if (!prefix || prefix->size() < tmd_end) {
            return 0;
        }
    }
    if (container->LoadTitleMetadata(*prefix, container->GetTitleMetadataOffset()) !=
        Loader::ResultStatus::Success) {
        return 0;
    }

    const TitleMetadata& tmd = container->GetTitleMetadata();
    const u64 title_id = tmd.GetTitleID();
    if (std::ranges::find(wanted_tids, title_id) == wanted_tids.end()) {
        return 0;
    }

    for (std::size_t i = 0; i < tmd.GetContentCount(); ++i) {
        if (container->GetHeader()->IsContentPresent(i) &&
            (tmd.GetContentTypeByIndex(i) & TMDContentTypeFlag::Encrypted)) {
            LOG_WARNING(Service_AM,
                        "{} matches title {:016x} but has encrypted content and cannot be served "
                        "in place; decrypt it first",
                        candidate.cia_path, title_id);
            return 0;
        }
    }

    const u16 version = tmd.GetTitleVersion();
    std::scoped_lock lock{registry_mutex};
    const auto it = registry.find(title_id);
    if (it != registry.end() && it->second.version >= version) {
        return 0;
    }
    LOG_INFO(Service_AM, "Serving title {:016x} v{} in place from {}", title_id, version,
             candidate.cia_path);
    registry[title_id] = Entry{candidate.cia_path, std::move(container), version};
    return title_id;
}

void CollectFolderCandidates(const std::string& folder, const std::string& base_stem,
                             const char* marker, std::vector<Candidate>& candidates) {
    if (folder.empty() || !FileUtil::IsDirectory(folder)) {
        return;
    }
    FileUtil::FSTEntry folder_entries;
    FileUtil::ScanDirectoryTree(folder, folder_entries);
    for (const auto& file : folder_entries.children) {
        if (file.isDirectory) {
            continue;
        }
        std::string extension;
        Common::SplitPath(file.virtualName, nullptr, nullptr, &extension);
        extension = Common::ToLower(extension);

        if (extension == ".cia") {
            candidates.push_back(Candidate{
                .cia_path = file.physicalName,
                .name_matched = NameMatches(StemOf(file.virtualName), base_stem, marker),
            });
        } else if (extension == ".zip") {
            const auto zip_entries = FileUtil::ListZipContents(file.physicalName);
            if (!zip_entries) {
                continue;
            }
            const bool zip_matched = NameMatches(StemOf(file.virtualName), base_stem, marker);
            for (const auto& zip_entry : zip_entries.value()) {
                std::string entry_extension;
                Common::SplitPath(zip_entry.name, nullptr, nullptr, &entry_extension);
                if (Common::ToLower(entry_extension) != ".cia") {
                    continue;
                }
                candidates.push_back(Candidate{
                    .cia_path = FileUtil::MakeVirtualPath(file.physicalName, zip_entry.name),
                    .zip_path = file.physicalName,
                    .entry_name = zip_entry.name,
                    .name_matched =
                        zip_matched || NameMatches(StemOf(zip_entry.name), base_stem, marker),
                });
            }
        }
    }
}

// Registers candidates for one wanted title: name-matched candidates first,
// falling back to probing every candidate only if none of them matched.
void RegisterFrom(const std::vector<Candidate>& candidates, u64 wanted_tid) {
    bool found = false;
    for (const auto& candidate : candidates) {
        if (candidate.name_matched) {
            found |= TryRegister(candidate, {wanted_tid}) != 0;
        }
    }
    if (found) {
        return;
    }
    for (const auto& candidate : candidates) {
        if (!candidate.name_matched) {
            TryRegister(candidate, {wanted_tid});
        }
    }
}

} // Anonymous namespace

void Clear() {
    std::scoped_lock lock{registry_mutex};
    registry.clear();
}

void ScanForCompanionTitles(u64 base_title_id, const std::string& base_game_path) {
    Clear();
    if ((base_title_id & TID_HIGH_MASK) != TID_HIGH_APPLICATION) {
        return;
    }
    const u64 tid_low = base_title_id & 0xFFFFFFFFULL;
    const u64 update_tid = TID_HIGH_UPDATE | tid_low;
    const u64 dlc_tid = TID_HIGH_DLC | tid_low;

    // The stem of the game's outer file ("Game (USA)" for "Game (USA).zip" or
    // "Game (USA).3ds"), used for the No-Intro naming fast path.
    const std::string outer_path = base_game_path.substr(0, base_game_path.find('#'));
    const std::string base_stem = StemOf(outer_path);

    // Sibling .cia entries of the game's own zip act as a self-contained pack.
    std::string game_zip_extension;
    Common::SplitPath(outer_path, nullptr, nullptr, &game_zip_extension);
    if (Common::ToLower(game_zip_extension) == ".zip") {
        if (const auto zip_entries = FileUtil::ListZipContents(outer_path)) {
            std::vector<Candidate> pack_candidates;
            for (const auto& zip_entry : zip_entries.value()) {
                std::string entry_extension;
                Common::SplitPath(zip_entry.name, nullptr, nullptr, &entry_extension);
                if (Common::ToLower(entry_extension) != ".cia") {
                    continue;
                }
                pack_candidates.push_back(Candidate{
                    .cia_path = FileUtil::MakeVirtualPath(outer_path, zip_entry.name),
                    .zip_path = outer_path,
                    .entry_name = zip_entry.name,
                    .name_matched = true,
                });
            }
            for (const auto& candidate : pack_candidates) {
                TryRegister(candidate, {update_tid, dlc_tid});
            }
        }
    }

    std::vector<Candidate> update_candidates;
    CollectFolderCandidates(Settings::values.updates_folder.GetValue(), base_stem, "(update)",
                            update_candidates);
    RegisterFrom(update_candidates, update_tid);

    std::vector<Candidate> dlc_candidates;
    CollectFolderCandidates(Settings::values.dlc_folder.GetValue(), base_stem, "(dlc)",
                            dlc_candidates);
    RegisterFrom(dlc_candidates, dlc_tid);

    std::scoped_lock lock{registry_mutex};
    LOG_INFO(Service_AM, "Virtual title scan for {:016x}: update {}, DLC {}", base_title_id,
             registry.contains(update_tid) ? "found" : "not found",
             registry.contains(dlc_tid) ? "found" : "not found");
}

bool HasTitle(u64 title_id) {
    std::scoped_lock lock{registry_mutex};
    return registry.contains(title_id);
}

std::optional<std::string> GetMetadataPath(u64 title_id) {
    std::scoped_lock lock{registry_mutex};
    const auto it = registry.find(title_id);
    if (it == registry.end()) {
        return std::nullopt;
    }
    return FileUtil::MakeVirtualRangePath(it->second.cia_path,
                                          it->second.container->GetTitleMetadataOffset(),
                                          it->second.container->GetTitleMetadataSize());
}

std::optional<std::string> GetContentPath(u64 title_id, std::size_t index) {
    std::scoped_lock lock{registry_mutex};
    const auto it = registry.find(title_id);
    if (it == registry.end()) {
        return std::nullopt;
    }
    const auto& entry = it->second;
    if (index >= entry.container->GetTitleMetadata().GetContentCount() ||
        !entry.container->GetHeader()->IsContentPresent(index)) {
        return std::nullopt;
    }
    return FileUtil::MakeVirtualRangePath(entry.cia_path,
                                          entry.container->GetContentOffset(index),
                                          entry.container->GetContentSize(index));
}

} // namespace FileSys::VirtualTitles
