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

// First byte of what the login server sends on the data port
enum class LobbyDataRequest : uint8_t
{
    AccountId     = 0x01,
    Key           = 0x02,
    CharacterList = 0x03,
    KeyAlternate  = 0x15, // answered like Key
};

// First byte of what xiloader sends on the data port
enum class LobbyDataReply : uint8_t
{
    AccountId   = 0xA1,
    Key         = 0xA2,
    SessionHash = 0xFE,
};

} // namespace xiloader
