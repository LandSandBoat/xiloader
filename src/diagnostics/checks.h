/*
===========================================================================

  Copyright (c) 2026 LandSandBoat Dev Teams

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see http://www.gnu.org/licenses/

===========================================================================
*/

#pragma once

#include "enums/check_status.h"
#include "enums/exit_code.h"
#include "enums/pol_language.h"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace xiloader
{

struct Config;

// One thing the loader depends on, and whether it is in order
struct Check
{
    std::string name;
    CheckStatus status = CheckStatus::Pass;
    std::string detail;
    std::string hint; // What the user can do about it
};

// JP, US or EU
auto languageName(Language language) -> const char*;

// The DLL polcore is registered to for that language, if it is registered
auto polcoreFile(Language language) -> std::optional<std::filesystem::path>;

// The languages PlayOnline is installed for
auto installedLanguages() -> std::vector<Language>;

// PlayOnline and the game for that language: registry, COM registration and the files behind it
auto checkInstall(Language language) -> std::vector<Check>;

// Windows, privileges and whether the install folders can be written to
auto checkEnvironment(Language language) -> std::vector<Check>;

// Loads polcore and looks for the code the loader patches. Not for a run that goes on to start the game.
auto checkPolcoreVersion(Language language) -> std::vector<Check>;

// Resolves the server, tries its three login ports and the TLS handshake. Needs Winsock started.
auto checkServer(const Config& config) -> std::vector<Check>;

// Prints the checks, or only the ones that didn't pass. Returns false when one failed.
auto report(const std::vector<Check>& checks, bool onlyProblems) -> bool;

// Everything above as one report; changes nothing and doesn't start the game
auto runDiagnostics(const Config& config) -> ExitCode;

} // namespace xiloader
