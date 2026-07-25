// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <optional>
#include <string>
#include <vector>
#include "common/common_types.h"

namespace FileSys::VirtualTitles {

/// Removes every registered virtual title.
void Clear();

/**
 * Scans for update and DLC CIAs that belong to the given application and
 * registers them as virtual titles, so that installed-content path lookups
 * (Service::AM::GetTitleContentPath / GetTitleMetadataPath) resolve into the
 * CIA files in place, with no installation.
 *
 * Candidates come from the configured Updates/DLC folders (plain .cia files or
 * zip archives containing them) and, when the game itself was booted from a
 * zip, from sibling .cia entries of that same archive. File names following
 * the No-Intro "(Update)"/"(DLC)" convention are tried first; if nothing
 * matches, every candidate in the folder is probed. Matches are always
 * verified by title ID, never by name alone.
 */
void ScanForCompanionTitles(u64 base_title_id, const std::string& base_game_path);

/// True if the given title is currently served virtually.
bool HasTitle(u64 title_id);

/// Title IDs of every currently registered virtual title.
std::vector<u64> GetAllTitleIds();

/// Path (usually virtual, see virtual_container.h) of the title's TMD.
std::optional<std::string> GetMetadataPath(u64 title_id);

/// Path of the content at the given TMD index, if it is present in the CIA.
std::optional<std::string> GetContentPath(u64 title_id, std::size_t index);

} // namespace FileSys::VirtualTitles
