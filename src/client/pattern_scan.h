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

#include <windows.h>

namespace xiloader::memory
{

/**
 * @brief Locates a signature of bytes using the given mask within the given module.
 *
 * @param moduleName    The name of the module to scan within.
 * @param lpPattern     The pattern of bytes to compare with.
 * @param pszMask       The mask to compare against.
 *
 * @return Start address of where the pattern was found, NULL otherwise.
 */
DWORD FindPattern(const char* moduleName, const unsigned char* lpPattern, const char* pszMask);

} // namespace xiloader::memory
