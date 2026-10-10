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

// How the INET mutex function is called
using InetMutex = void* (*)(...);

// Locates the INET mutex function call inside of polcore.dll
// Returns the pointer to the function call, nullptr when it is not found.
auto FindINETMutex(const xiloader::Language language) -> InetMutex
{
    constexpr uint8_t kPattern[] = { 0x8B, 0x56, 0x2C, 0x8B, 0x46, 0x28, 0x8B, 0x4E, 0x24, 0x52, 0x50, 0x51 };

    const char* const module = xiloader::registry::GetPolcoreModule(language);
    const auto        result = xiloader::memory::FindPattern(module, kPattern, "xxxxxxxxxxxx");
    if (result == nullptr)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate the INET mutex in {}. This PlayOnline version is not supported, or --lang doesn't match your install.", module);
        return nullptr;
    }

    // The match follows a call; its relative target is in the four bytes before it
    int32_t offset = 0;
    memcpy(&offset, result - 4, sizeof(offset));

    return reinterpret_cast<InetMutex>(result + offset);
}

// Locates the PlayOnline connection object inside of polcore.dll
// Returns pointer to the pol connection object, nullptr when it is not found.
auto FindPolConn(const xiloader::Language language) -> char*
{
    constexpr uint8_t kPattern[] = { 0x81, 0xC6, 0x38, 0x03, 0x00, 0x00, 0x83, 0xC4, 0x04, 0x81, 0xFE };

    const char* const module = xiloader::registry::GetPolcoreModule(language);
    const auto        result = xiloader::memory::FindPattern(module, kPattern, "xxxxxxxxxxx");
    if (result == nullptr)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate the PlayOnline connection in {}. This PlayOnline version is not supported, or --lang doesn't match your install.", module);
        return nullptr;
    }

    char* connection = nullptr;
    memcpy(&connection, result - 10, sizeof(connection));

    return connection;
}

// Locates the current character information block.
// Returns pointer to the character information table.
auto FindCharacters(xiloader::playonline::CommandFunc* const* const commFuncs) -> char*
{
    char* lpCharTable = nullptr;
    memcpy(&lpCharTable, reinterpret_cast<const char*>(commFuncs[0xD3]) + 31, sizeof(lpCharTable));
    return lpCharTable;
}

} // namespace

namespace xiloader
{

auto probePolcore(const Language language) -> std::vector<std::pair<const char*, bool>>
{
    return {
        { "INET mutex", FindINETMutex(language) != nullptr },
        { "PlayOnline connection", FindPolConn(language) != nullptr },
        { "IRC cipher", playonline::findCipherCall(language) != nullptr },
    };
}

auto runGame(const Config& config, const Session& session, LobbyDataConnection& lobbyData) -> ExitCode
{
    // Attempt to create polcore instance..
    const int                           languageId = std::to_underlying(config.language);
    Microsoft::WRL::ComPtr<IPOLCoreCom> polcore;
    if (CoCreateInstance(xiloader::CLSID_POLCoreCom[languageId], nullptr, 0x17, xiloader::IID_IPOLCoreCom[languageId], reinterpret_cast<LPVOID*>(polcore.GetAddressOf())) != S_OK)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize instance of polcore!");
        return ExitCode::PlayOnlineMissing;
    }

    // Invoke the setup functions for polcore..
    // Create string for the login view port
    std::string polcorecmd = " /game eAZcFcB -net 3 -port " + std::to_string(config.loginViewPort);
    const LPSTR cmd        = polcorecmd.data();
    polcore->SetAreaCode(languageId);
    if (const auto hr = polcore->SetParamInit(GetModuleHandle(nullptr), cmd); FAILED(hr))
    {
        xiloader::console::output(xiloader::color::error, "polcore failed to initialize (0x{:08X}).", static_cast<unsigned long>(hr));
    }

    // Obtain the common function table..
    xiloader::playonline::CommandFunc** lpCommandTable = nullptr;
    if (const auto hr = polcore->GetCommonFunctionTable(reinterpret_cast<unsigned long**>(&lpCommandTable)); FAILED(hr) || lpCommandTable == nullptr)
    {
        xiloader::console::output(xiloader::color::error, "Failed to get polcore's function table (0x{:08X}).", static_cast<unsigned long>(hr));
        return ExitCode::PlayOnlineUnsupported;
    }

    // Invoke the inet mutex function..
    const auto findMutex = FindINETMutex(config.language);
    if (findMutex == nullptr)
    {
        return ExitCode::PlayOnlineUnsupported;
    }
    findMutex();

    // Locate and prepare the pol connection..
    const auto polConnection = FindPolConn(config.language);
    if (polConnection == nullptr)
    {
        return ExitCode::PlayOnlineUnsupported;
    }
    memset(polConnection, 0x00, 0x68);
    static char       encBuffer[kEncBufferSize] = {};
    const char* const enc                       = encBuffer;
    memcpy(polConnection + 0x48, &enc, sizeof(enc));

    // Locate the character storage buffer..
    lobbyData.setCharacterList(FindCharacters(lpCommandTable));

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
        return ExitCode::PlayOnlineUnsupported;
    }

    if (const auto started = xiloader::polrelay::start(config.serverAddress, config.profilePort, session); !started)
    {
        xiloader::console::output(xiloader::color::error, "{}", started.error());
        return ExitCode::ProfileServerFailed;
    }

    // Without the viewer, polcore keeps its built-in Japanese message texts
    if (config.language != xiloader::Language::Japanese)
    {
        xiloader::playonline::setEnglishMessageTexts(lpCommandTable);
    }

    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::InetMutex)]();

    if (!xiloader::playonline::logIn(lpCommandTable, session.accountId, config.language))
    {
        return ExitCode::ProfileServerFailed;
    }

    xiloader::playonline::keepGameOnDisconnect(lpCommandTable);

    // Attempt to create FFXi instance..
    Microsoft::WRL::ComPtr<IFFXiEntry> ffxi;
    if (CoCreateInstance(xiloader::CLSID_FFXiEntry, nullptr, 0x17, xiloader::IID_IFFXiEntry, reinterpret_cast<LPVOID*>(ffxi.GetAddressOf())) != S_OK)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize instance of FFxi!");
        return ExitCode::GameFailed;
    }

    // Attempt to start Final Fantasy..
    IUnknown* message = nullptr;
    if (config.hide)
    {
        xiloader::console::hide();
    }

    ffxi->GameStart(polcore.Get(), &message);

    if (config.hide)
    {
        xiloader::console::show();
    }

    return ExitCode::Success;
}

} // namespace xiloader
