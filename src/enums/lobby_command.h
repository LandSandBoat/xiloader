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

#include <cstdint>

namespace xiloader
{

// See https://github.com/atom0s/XiPackets/tree/main/lobby
// Command bytes information, based on what the client visually reports when waiting for a response:
enum class LobbyCommand : uint8_t
{
    SelectCharacter  = 0x07, // Request login to character with account id and character id. Login verifies this and will notify if possible: "Notifying lobby server of current selections."
    DeleteCharacter  = 0x14, // Request character deletion, login will delete if enabled. "Deleting from lobby server"
    CharacterList    = 0x1F, // Request character list, login server only replies with "0x01": "Acquiring Player Data"
    CharacterCreated = 0x21, // Notify server character was created clientside (no effect in login server): "Registering character name onto the lobby server"
    CreateCharacter  = 0x22, // Notify server of character wishing to be created and login creates the character: "Checking name and Gold World Pass"
    ServerName       = 0x24, // Client requesting server name: "Acquiring FINAL FANTASY XI server data"
    Version          = 0x26, // Send version information to login, login replies with expansion/features bitmask: "Setting up connection."
    RenameCharacter  = 0x28, // Client sending character rename information if character was renamed by a GM (Not yet implemented in login)
    MoveGmCharacter  = 0x2B, // GM command to move character to a new world? See https://github.com/atom0s/XiPackets/blob/main/lobby/C2S_0x002B_RequestMoveGMChr.md
};

} // namespace xiloader
