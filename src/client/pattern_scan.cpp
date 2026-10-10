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

// Compares a pattern against a given memory pointer.
// Returns true if pattern was found, false otherwise.
static auto MaskCompare(const unsigned char* lpDataPtr, const unsigned char* lpPattern, const char* pszMask) -> bool
{
    for (; *pszMask; ++pszMask, ++lpDataPtr, ++lpPattern)
    {
        if (*pszMask == 'x' && *lpDataPtr != *lpPattern)
            return false;
    }
    return (*pszMask) == NULL;
}

auto memory::FindPattern(const char* const moduleName, const unsigned char* const lpPattern, const char* const pszMask) -> DWORD
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
