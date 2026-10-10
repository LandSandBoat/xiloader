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

#include "defines.h"

#include "console.h"
#include "functions.h"

namespace
{

DWORD g_NewServerAddress;     // Hairpin server address to be overriden with.
DWORD g_HairpinReturnAddress; // Hairpin return address to allow the code cave to return properly.

} // namespace

/**
 * @brief Hairpin fix codecave.
 */
__declspec(naked) void HairpinFixCave(void){
    __asm mov eax, g_NewServerAddress __asm mov[edx + 0x012E90], eax __asm mov[edx], eax __asm jmp g_HairpinReturnAddress
}

/**
 * @brief Applies the hairpin fix modifications.
 *
 * @param lpParam       Thread param object.
 *
 * @return Non-important return.
 */
DWORD xiloader::ApplyHairpinFixThread(LPVOID lpParam)
{
    do
    {
        /* Sleep until we find FFXiMain loaded.. */
        Sleep(100);
    } while (GetModuleHandleA("FFXiMain.dll") == NULL);

    g_NewServerAddress = static_cast<DWORD>(reinterpret_cast<DWORD_PTR>(lpParam));

    // Locate the main hairpin location..
    //
    // As of 07.08.2013:
    //      8B 82 902E0100        - mov eax, [edx+00012E90]
    //      89 02                 - mov [edx], eax <-- edit this

    auto hairpinAddress = (DWORD)xiloader::functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x82\xFF\xFF\xFF\xFF\x89\x02\x8B\x0D", "xx????xxxx");
    if (hairpinAddress == 0)
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

    auto zoneChangeAddress = (DWORD)xiloader::functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x0D\xFF\xFF\xFF\xFF\x89\x01\x8B\x46", "xx????xxxx");
    if (zoneChangeAddress == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate zone change hairpin address!");
        return 0;
    }

    // The game's code may be read-only
    DWORD hairpinProtection = 0;
    DWORD zoneProtection    = 0;
    if (!VirtualProtect((LPVOID)hairpinAddress, 8, PAGE_EXECUTE_READWRITE, &hairpinProtection) ||
        !VirtualProtect((LPVOID)(zoneChangeAddress + 0x06), 2, PAGE_EXECUTE_READWRITE, &zoneProtection))
    {
        xiloader::console::output(xiloader::color::error, "Failed to apply the hairpin fix (error %lu). Security software may be blocking changes to the game's code.", GetLastError());
        return 0;
    }

    /* Apply the hairpin fix.. */
    auto caveDest          = ((int)HairpinFixCave - ((int)hairpinAddress)) - 5;
    g_HairpinReturnAddress = hairpinAddress + 0x08;

    *(BYTE*)(hairpinAddress + 0x00) = 0xE9; // jmp
    *(UINT*)(hairpinAddress + 0x01) = caveDest;
    *(BYTE*)(hairpinAddress + 0x05) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x06) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x07) = 0x90; // nop

    /* Apply zone ip change patch.. */
    memset((LPVOID)(zoneChangeAddress + 0x06), 0x90, 2);

    VirtualProtect((LPVOID)hairpinAddress, 8, hairpinProtection, &hairpinProtection);
    VirtualProtect((LPVOID)(zoneChangeAddress + 0x06), 2, zoneProtection, &zoneProtection);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)hairpinAddress, 8);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)(zoneChangeAddress + 0x06), 2);

    xiloader::console::output(xiloader::color::success, "Hairpin fix applied!");
    return 0;
}
