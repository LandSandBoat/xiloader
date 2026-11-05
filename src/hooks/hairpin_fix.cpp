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

#include "hairpin_fix.h"

#include "client/pattern_scan.h"
#include "console.h"

#include <cstdint>
#include <cstring>

namespace
{

constexpr DWORD kModulePollIntervalMs = 100;

DWORD g_NewServerAddress;     // Hairpin server address to be overriden with.
DWORD g_HairpinReturnAddress; // Hairpin return address to allow the code cave to return properly.

} // namespace

// Hairpin fix codecave.
__declspec(naked) void HairpinFixCave(void)
{
    __asm mov eax, g_NewServerAddress __asm mov[edx + 0x012E90], eax __asm mov[edx], eax __asm jmp g_HairpinReturnAddress
}

namespace
{

auto WINAPI ApplyHairpinFixThread([[maybe_unused]] const LPVOID lpParam) -> DWORD
{
    do
    {
        // Sleep until we find FFXiMain loaded..
        Sleep(kModulePollIntervalMs);
    } while (GetModuleHandleA("FFXiMain.dll") == nullptr);

    // Locate the main hairpin location..
    //
    // As of 07.08.2013:
    //      8B 82 902E0100        - mov eax, [edx+00012E90]
    //      89 02                 - mov [edx], eax <-- edit this

    constexpr uint8_t kHairpinPattern[] = { 0x8B, 0x82, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x02, 0x8B, 0x0D };

    const auto hairpinAddress = xiloader::memory::FindPattern("FFXiMain.dll", kHairpinPattern, "xx????xxxx");
    if (hairpinAddress == nullptr)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate main hairpin hack address!");
        return 0;
    }

    // Locate zoning IP change address..
    //
    // As of 07.08.2013
    //      74 08                 - je FFXiMain.dll+E5E72
    //      8B 0D 68322B03        - mov ecx, [FFXiMain.dll+463268]
    //      89 01                 - mov [ecx], eax <-- edit this
    //      8B 46 0C              - mov eax, [esi+0C]
    //      85 C0                 - test eax, eax

    constexpr uint8_t kZoneChangePattern[] = { 0x8B, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x01, 0x8B, 0x46 };

    const auto zoneChangeAddress = xiloader::memory::FindPattern("FFXiMain.dll", kZoneChangePattern, "xx????xxxx");
    if (zoneChangeAddress == nullptr)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate zone change hairpin address!");
        return 0;
    }

    // The game's code may be read-only
    DWORD hairpinProtection = 0;
    DWORD zoneProtection    = 0;
    if (!VirtualProtect(hairpinAddress, 8, PAGE_EXECUTE_READWRITE, &hairpinProtection) ||
        !VirtualProtect(zoneChangeAddress + 0x06, 2, PAGE_EXECUTE_READWRITE, &zoneProtection))
    {
        xiloader::console::output(xiloader::color::error, "Failed to apply the hairpin fix (error {}). Security software may be blocking changes to the game's code.", GetLastError());
        return 0;
    }

    // Apply the hairpin fix..
    const auto caveDest    = static_cast<int32_t>(reinterpret_cast<intptr_t>(&HairpinFixCave) - reinterpret_cast<intptr_t>(hairpinAddress) - 5);
    g_HairpinReturnAddress = reinterpret_cast<DWORD>(hairpinAddress + 0x08);

    hairpinAddress[0x00] = 0xE9; // jmp
    memcpy(hairpinAddress + 0x01, &caveDest, sizeof(caveDest));
    hairpinAddress[0x05] = 0x90; // nop
    hairpinAddress[0x06] = 0x90; // nop
    hairpinAddress[0x07] = 0x90; // nop

    // Apply zone ip change patch..
    memset(zoneChangeAddress + 0x06, 0x90, 2);

    VirtualProtect(hairpinAddress, 8, hairpinProtection, &hairpinProtection);
    VirtualProtect(zoneChangeAddress + 0x06, 2, zoneProtection, &zoneProtection);
    FlushInstructionCache(GetCurrentProcess(), hairpinAddress, 8);
    FlushInstructionCache(GetCurrentProcess(), zoneChangeAddress + 0x06, 2);

    xiloader::console::output(xiloader::color::success, "Hairpin fix applied!");
    return 0;
}

} // namespace

auto xiloader::startHairpinFix(const ULONG serverAddress) -> bool
{
    g_NewServerAddress = serverAddress;

    // TODO: this is not terminated? Does it need to be?
    return CreateThread(nullptr, 0, ApplyHairpinFixThread, nullptr, 0, nullptr) != nullptr;
}
