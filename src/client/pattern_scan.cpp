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

#include "pattern_scan.h"

#include <psapi.h>

#include <cstring>

namespace xiloader
{

/**
 * @brief Compares a pattern against a given memory pointer.
 *
 * @param lpDataPtr     The live data to compare with.
 * @param lpPattern     The pattern of bytes to compare with.
 * @param pszMask       The mask to compare against.
 *
 * @return True if pattern was found, false otherwise.
 */
static bool MaskCompare(const unsigned char* lpDataPtr, const unsigned char* lpPattern, const char* pszMask)
{
    for (; *pszMask; ++pszMask, ++lpDataPtr, ++lpPattern)
    {
        if (*pszMask == 'x' && *lpDataPtr != *lpPattern)
            return false;
    }
    return (*pszMask) == NULL;
}

/**
 * @brief Locates a signature of bytes using the given mask within the given module.
 *
 * @param moduleName    The name of the module to scan within.
 * @param lpPattern     The pattern of bytes to compare with.
 * @param pszMask       The mask to compare against.
 *
 * @return Start address of where the pattern was found, NULL otherwise.
 */
DWORD memory::FindPattern(const char* moduleName, const unsigned char* lpPattern, const char* pszMask)
{
    MODULEINFO mod = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(moduleName), &mod, sizeof(MODULEINFO)))
        return 0;

    const auto length = strlen(pszMask);
    if (length > mod.SizeOfImage)
        return 0;

    for (DWORD x = 0; x <= mod.SizeOfImage - length; x++)
    {
        if (MaskCompare(reinterpret_cast<unsigned char*>((DWORD)mod.lpBaseOfDll + x), lpPattern, pszMask))
            return ((DWORD)mod.lpBaseOfDll + x);
    }
    return 0;
}

} // namespace xiloader
