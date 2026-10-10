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

#include "registry.h"

#include <windows.h>

#include <cstdio>

namespace
{

const char* const kRegistryKeys[3] = {
    "SOFTWARE\\PlayOnline",   // xiloader::Japanese
    "SOFTWARE\\PlayOnlineUS", // xiloader::English
    "SOFTWARE\\PlayOnlineEU"  // xiloader::European
};

} // namespace

namespace xiloader
{

auto registry::GetPlayOnlineKey(const xiloader::Language language) -> const char*
{
    int lang = static_cast<int>(language);

    if (lang < 0)
        lang = 0;
    if (lang > 2)
        lang = 2;

    return kRegistryKeys[lang];
}

auto registry::GetPlayOnlineLanguage(const xiloader::Language language) -> int
{
    int lang = static_cast<int>(language);

    const char* const SquareEnix = (lang == 0 /*xiloader::Japanese*/) ? "Square" : "SquareEnix";

    char szRegistryPath[MAX_PATH];
    sprintf_s(szRegistryPath, MAX_PATH, "%s\\%s\\PlayOnlineViewer\\Settings", registry::GetPlayOnlineKey(language), SquareEnix);

    HKEY  hKey       = NULL;
    DWORD dwRegValue = 0;
    DWORD dwRegSize  = sizeof(DWORD);
    DWORD dwRegType  = REG_DWORD;

    if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, szRegistryPath, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS)
    {
        if (::RegQueryValueExA(hKey, "Language", NULL, &dwRegType, (LPBYTE)&dwRegValue, &dwRegSize) == ERROR_SUCCESS)
        {
            if (dwRegType == REG_DWORD && dwRegSize == sizeof(DWORD))
                lang = (int)dwRegValue;
        }
        ::RegCloseKey(hKey);
    }

    return lang;
}

auto registry::GetPlayOnlineInstallFolder(const xiloader::Language language) -> const char*
{
    static char InstallFolder[MAX_PATH] = { 0 };

    char szRegistryPath[MAX_PATH];
    sprintf_s(szRegistryPath, MAX_PATH, "%s\\InstallFolder", registry::GetPlayOnlineKey(language));

    HKEY  hKey      = NULL;
    DWORD dwRegSize = sizeof(InstallFolder);
    DWORD dwRegType = REG_SZ;
    bool  found     = false;

    if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, szRegistryPath, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS)
    {
        if (::RegQueryValueExA(hKey, "1000", NULL, &dwRegType, (LPBYTE)InstallFolder, &dwRegSize) == ERROR_SUCCESS)
        {
            if (dwRegType == REG_SZ && dwRegSize > 0 && dwRegSize < sizeof(InstallFolder))
                found = true;
        }
        ::RegCloseKey(hKey);
    }

    if (found == false)
        InstallFolder[0] = '\0';

    return InstallFolder;
}

} // namespace xiloader
