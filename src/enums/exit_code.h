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

// What the process exits with, so a launcher can tell the failures apart
enum class ExitCode : uint8_t
{
    Success               = 0, // The game ran, or the user chose Exit
    BadArguments          = 1,
    StartupFailed         = 2, // Winsock, COM or the socket hooks
    ServerUnreachable     = 3,
    ConnectionLost        = 4, // The login server stopped answering
    PlayOnlineMissing     = 5, // Not installed, or not for the chosen language
    PlayOnlineUnsupported = 6, // Installed, but not a version the loader knows
    ProfileServerFailed   = 7,
    GameFailed            = 8,
};

} // namespace xiloader
