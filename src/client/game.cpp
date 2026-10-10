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

#include "game.h"

#include "config.h"
#include "polcore_ids.h"

#include "enums/pol_function.h"

#include "client/pattern_scan.h"
#include "client/registry.h"
#include "console.h"
#include "lobby/data_connection.h"
#include "login/session.h"
#include "playonline.h"
#include "polrelay.h"

#include <wrl/client.h>

#include <utility>

namespace
{

constexpr size_t kEncBufferSize = 0x1000;

// Locates the INET mutex function call inside of polcore.dll
// Returns the pointer to the function call, 0 when it is not found.
inline auto FindINETMutex(const xiloader::Language language) -> DWORD
{
    const char* const module = xiloader::registry::GetPolcoreModule(language);
    const auto        result = (DWORD)xiloader::memory::FindPattern(module, (BYTE*)"\x8B\x56\x2C\x8B\x46\x28\x8B\x4E\x24\x52\x50\x51", "xxxxxxxxxxxx");
    if (result == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate the INET mutex in {}. This PlayOnline version is not supported, or --lang doesn't match your install.", module);
        return 0;
    }
    return (*(DWORD*)(result - 4) + (result));
}

// Locates the PlayOnline connection object inside of polcore.dll
// Returns pointer to the pol connection object, 0 when it is not found.
inline auto FindPolConn(const xiloader::Language language) -> DWORD
{
    const char* const module = xiloader::registry::GetPolcoreModule(language);
    const auto        result = (DWORD)xiloader::memory::FindPattern(module, (BYTE*)"\x81\xC6\x38\x03\x00\x00\x83\xC4\x04\x81\xFE", "xxxxxxxxxxx");
    if (result == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate the PlayOnline connection in {}. This PlayOnline version is not supported, or --lang doesn't match your install.", module);
        return 0;
    }
    return (*(DWORD*)(result - 10));
}

// Locates the current character information block.
// Returns pointer to the character information table.
inline auto FindCharacters(void* const* const commFuncs) -> LPVOID
{
    LPVOID lpCharTable = NULL;
    memcpy(&lpCharTable, (char*)commFuncs[0xD3] + 31, sizeof(lpCharTable));
    return lpCharTable;
}

} // namespace

namespace xiloader
{

auto runGame(const Config& config, const Session& session, LobbyDataConnection& lobbyData) -> int
{
    // Attempt to create polcore instance..
    const int                           languageId = std::to_underlying(config.language);
    Microsoft::WRL::ComPtr<IPOLCoreCom> polcore;
    if (CoCreateInstance(xiloader::CLSID_POLCoreCom[languageId], NULL, 0x17, xiloader::IID_IPOLCoreCom[languageId], (LPVOID*)polcore.GetAddressOf()) != S_OK)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize instance of polcore!");
        return ERROR_SUCCESS;
    }

    // Invoke the setup functions for polcore..
    // Create string for the login view port
    const std::string polcorecmd = " /game eAZcFcB -net 3 -port " + std::to_string(config.loginViewPort);
    // Cast to an LPSTR
    const LPSTR cmd = const_cast<char*>(polcorecmd.c_str());
    polcore->SetAreaCode(languageId);
    if (const auto hr = polcore->SetParamInit(GetModuleHandle(NULL), cmd); FAILED(hr))
    {
        xiloader::console::output(xiloader::color::error, "polcore failed to initialize (0x{:08X}).", static_cast<unsigned long>(hr));
    }

    // Obtain the common function table..
    xiloader::playonline::CommandFunc** lpCommandTable = nullptr;
    if (const auto hr = polcore->GetCommonFunctionTable((unsigned long**)&lpCommandTable); FAILED(hr) || lpCommandTable == nullptr)
    {
        xiloader::console::output(xiloader::color::error, "Failed to get polcore's function table (0x{:08X}).", static_cast<unsigned long>(hr));
        return 1;
    }

    // Invoke the inet mutex function..
    const auto findMutex = (void* (*)(...))FindINETMutex(config.language);
    if (findMutex == nullptr)
    {
        return 1;
    }
    findMutex();

    // Locate and prepare the pol connection..
    const auto polConnection = (char*)FindPolConn(config.language);
    if (polConnection == nullptr)
    {
        return 1;
    }
    memset(polConnection, 0x00, 0x68);
    const auto enc = (char*)malloc(kEncBufferSize);
    memset(enc, 0x00, kEncBufferSize);
    memcpy(polConnection + 0x48, &enc, sizeof(char**));

    // Locate the character storage buffer..
    lobbyData.setCharacterList((char*)FindCharacters((void**)lpCommandTable));

    // Invoke the setup functions for polcore..
    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::RegistryLang)](languageId);
    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::FfxiLang)](xiloader::registry::GetPlayOnlineLanguage(config.language));
    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::RegistryKey)](xiloader::registry::GetPlayOnlineKey(config.language));
    const char* const installFolder = xiloader::registry::GetPlayOnlineInstallFolder(config.language);
    if (installFolder[0] == '\0')
    {
        xiloader::console::output(xiloader::color::error, "PlayOnline install folder not found in the registry (HKLM\\{}\\InstallFolder). Check PlayOnline is installed and --lang matches your install.", xiloader::registry::GetPlayOnlineKey(config.language));
    }
    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::InstallFolder)](installFolder);
    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::FileInit)](); // Initialize polcore file system

    if (!xiloader::playonline::disableCipher(config.language))
    {
        xiloader::console::output(xiloader::color::error, "Unsupported polcore version.");
        return 1;
    }

    if (!xiloader::polrelay::start(config.serverAddress, config.profilePort, session))
    {
        return 1;
    }

    // Without the viewer, polcore keeps its built-in Japanese message texts
    if (config.language != xiloader::Language::Japanese)
    {
        xiloader::playonline::setEnglishMessageTexts(lpCommandTable);
    }

    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::InetMutex)]();

    if (!xiloader::playonline::logIn(lpCommandTable, session.accountId, config.language))
    {
        return 1;
    }

    xiloader::playonline::keepGameOnDisconnect(lpCommandTable);

    // Attempt to create FFXi instance..
    Microsoft::WRL::ComPtr<IFFXiEntry> ffxi;
    if (CoCreateInstance(xiloader::CLSID_FFXiEntry, NULL, 0x17, xiloader::IID_IFFXiEntry, (LPVOID*)ffxi.GetAddressOf()) != S_OK)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize instance of FFxi!");
        return ERROR_SUCCESS;
    }

    // Attempt to start Final Fantasy..
    IUnknown* message = NULL;
    if (config.hide)
    {
        xiloader::console::hide();
    }

    ffxi->GameStart(polcore.Get(), &message);

    if (config.hide)
    {
        xiloader::console::show();
    }

    return ERROR_SUCCESS;
}

} // namespace xiloader
