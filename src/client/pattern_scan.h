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
#include <span>
#include <string_view>

namespace xiloader::memory
{

// Locates a signature of bytes using the given mask within the given module.
// Returns start address of where the pattern was found, nullptr otherwise.
auto FindPattern(const char* moduleName, std::span<const uint8_t> pattern, std::string_view mask) -> uint8_t*;

} // namespace xiloader::memory
