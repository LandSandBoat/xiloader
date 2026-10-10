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

#include <array>
#include <cstdint>
#include <string>

#include "enums/pol_language.h"

namespace xiloader
{

// Set from the command line and the --json file
struct Config
{
    // xiloader version number sent to auth server. Must be x.x.x with single characters for 'x'. Remember to also change in xiloader.rc.in
    static constexpr std::array<uint8_t, 3> versionNumber{ 2, 2, 0 };

    Language    language      = Language::English; // The language of the loader to be used for polcore.
    std::string serverAddress = "127.0.0.1";       // The server address to connect to.
    uint16_t    loginDataPort = 54230;             // Login server data port to connect to
    uint16_t    loginViewPort = 54001;             // Login view port to connect to
    uint16_t    loginAuthPort = 54231;             // Login auth port to connect to
    uint16_t    profilePort   = 51220;             // PlayOnline profile server port polcore connects to
    std::string username;                          // The username being logged in with.
    std::string password;                          // The password being logged in with.
    std::string otpCode;                           // The OTP code the user input
    bool        trustThisComputer = false;         // user checkbox / CLI flag for "trust this computer"
    bool        hairpin           = false;
    bool        plainMenus        = false; // Line-based menus instead of FTXUI; always on under Wine
    bool        hide              = false; // Determines whether or not to hide the console window after FFXI starts.

    // Defaults, then the --json file, then the command line. Throws std::runtime_error on bad input.
    static auto load(int argc, const char* const argv[]) -> Config;
};

} // namespace xiloader
