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

#include <windows.h>

#include <psapi.h>

#include <algorithm>
#include <cstddef>

namespace xiloader
{

// Compares a pattern against a given memory pointer.
// Returns true if pattern was found, false otherwise.
static auto MaskCompare(const uint8_t* const data, const std::span<const uint8_t> pattern, const std::string_view mask) -> bool
{
    for (std::size_t i = 0; i < mask.size(); ++i)
    {
        if (mask[i] == 'x' && data[i] != pattern[i])
        {
            return false;
        }
    }

    return true;
}

// Searches one run of readable memory
static auto searchRun(uint8_t* const start, uint8_t* const end, const std::span<const uint8_t> pattern, const std::string_view mask) -> uint8_t*
{
    for (auto candidate = start; candidate + mask.size() <= end; ++candidate)
    {
        if (MaskCompare(candidate, pattern, mask))
        {
            return candidate;
        }
    }

    return nullptr;
}

auto memory::FindPattern(const char* const moduleName, const std::span<const uint8_t> pattern, const std::string_view mask) -> uint8_t*
{
    MODULEINFO mod = {};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(moduleName), &mod, sizeof(MODULEINFO)))
    {
        return nullptr;
    }

    if (mask.size() > pattern.size() || mask.size() > mod.SizeOfImage)
    {
        return nullptr;
    }

    const auto base = static_cast<uint8_t*>(mod.lpBaseOfDll);
    const auto end  = base + mod.SizeOfImage;

    // Not every page of a loaded module is readable, so only runs of committed, readable pages are searched
    uint8_t* runStart = nullptr;
    for (auto region = base; region < end;)
    {
        MEMORY_BASIC_INFORMATION info = {};
        if (VirtualQuery(region, &info, sizeof(info)) == 0)
        {
            break;
        }

        const auto regionEnd = std::min(end, static_cast<uint8_t*>(info.BaseAddress) + info.RegionSize);
        const bool readable  = info.State == MEM_COMMIT && (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;

        if (readable && runStart == nullptr)
        {
            runStart = region;
        }

        if (runStart != nullptr && (!readable || regionEnd == end))
        {
            auto runEnd = region;
            if (readable)
            {
                runEnd = regionEnd;
            }

            if (const auto found = searchRun(runStart, runEnd, pattern, mask))
            {
                return found;
            }

            runStart = nullptr;
        }

        region = regionEnd;
    }

    return nullptr;
}

} // namespace xiloader
