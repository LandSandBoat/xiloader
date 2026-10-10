/*
===========================================================================

Copyright (c) 2010-2015 Darkstar Dev Teams
Copyright (c) 2021-2026 LandSandBoat Dev Teams

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

This file is part of DarkStar-server source code.

===========================================================================
*/

#define NOMINMAX 1 // Interferes with std::numeric_limits

#include "defines.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <intrin.h>
#include <wrl/client.h>

#include "console.h"
#include "functions.h"
#include "guards.h"
#include "helpers.h"
#include "hooks/hairpin_fix.h"
#include "hooks/socket_hooks.h"
#include "lobby/data_connection.h"
#include "login/auth_connection.h"
#include "login/login.h"
#include "net/resolve.h"
#include "playonline.h"
#include "polrelay.h"

/**
 * @brief Locates the INET mutex function call inside of polcore.dll
 *
 * @return The pointer to the function call.
 */
inline DWORD FindINETMutex(const xiloader::Language language)
{
    const char* module = (language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto        result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x8B\x56\x2C\x8B\x46\x28\x8B\x4E\x24\x52\x50\x51", "xxxxxxxxxxxx");
    if (result == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate the INET mutex in %s. This PlayOnline version is not supported, or --lang doesn't match your install.", module);
    }
    return (*(DWORD*)(result - 4) + (result));
}

/**
 * @brief Locates the PlayOnline connection object inside of polcore.dll
 *
 * @return Pointer to the pol connection object.
 */
inline DWORD FindPolConn(const xiloader::Language language)
{
    const char* module = (language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto        result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x81\xC6\x38\x03\x00\x00\x83\xC4\x04\x81\xFE", "xxxxxxxxxxx");
    if (result == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate the PlayOnline connection in %s. This PlayOnline version is not supported, or --lang doesn't match your install.", module);
    }
    return (*(DWORD*)(result - 10));
}

/**
 * @brief Locates the current character information block.
 *
 * @return Pointer to the character information table.
 */
inline LPVOID FindCharacters(void** commFuncs)
{
    LPVOID lpCharTable = NULL;
    memcpy(&lpCharTable, (char*)commFuncs[0xD3] + 31, sizeof(lpCharTable));
    return lpCharTable;
}

// Everything between the banner and "Closing...": logs in, then hosts polcore and the game until it exits.
// Whatever was set up is torn down in reverse order on every way out.
int run(xiloader::Config& config)
{
    /* Initialize Winsock */
    const xiloader::Winsock winsock;
    if (winsock.error != 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize winsock, error code: %d", winsock.error);
        return 1;
    }

    /* Initialize COM */
    const xiloader::Com com;
    if (com.result != S_OK && com.result != S_FALSE)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize COM, error code: %d", com.result);
        return 1;
    }

    /* Attach detour for gethostbyname.. */
    xiloader::SocketHooks hooks(config);
    if (!hooks.attached)
    {
        xiloader::console::output(xiloader::color::error, "Failed to detour function 'gethostbyname'. Cannot continue!");
        return 1;
    }

    xiloader::AuthConnection  auth;
    const xiloader::RelayStop relayStop;

    /* Attempt to resolve the server address.. */
    ULONG ulAddress = 0;

    xiloader::console::output(xiloader::color::info, "Resolving '%s' ...", config.serverAddress.c_str());

    if (xiloader::resolveHostname(config.serverAddress.c_str(), &ulAddress))
    {
        config.serverAddress = inet_ntoa(*((struct in_addr*)&ulAddress));

        xiloader::console::output(xiloader::color::info, "Resolved server address to '%s:%d'", config.serverAddress.c_str(), config.loginAuthPort);

        /* Attempt to create socket to server..*/
        std::optional<xiloader::Session> session;
        xiloader::LobbyDataConnection    lobbyData;

        /* Attempt to verify the users account info.. */
        if (auth.connect(config.serverAddress, config.loginAuthPort) && (session = xiloader::login::run(auth, config)))
        {
            hooks.useSession(*session);

            /* Attempt to create connection to the login server.. */
            const bool connected = lobbyData.connect(config.serverAddress, config.loginDataPort);
            if (!connected)
            {
                int err = WSAGetLastError();
                xiloader::console::output(xiloader::color::error, "Failed to initialize connection to server on port %u, winsock error: %d", config.loginDataPort, err);
            }

            if (connected)
            {
                /* Start hairpin hack thread if required.. */
                if (config.hairpin)
                {
                    // TODO: this is not terminated? Does it need to be?
                    if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)xiloader::ApplyHairpinFixThread, reinterpret_cast<LPVOID>(static_cast<DWORD_PTR>(ulAddress)), 0, NULL) == NULL)
                    {
                        xiloader::console::output(xiloader::color::error, "Failed to start the hairpin fix thread (error %lu).", GetLastError());
                    }
                }

                // Create lobby data thread
                lobbyData.start(*session);

                /* Attempt to create polcore instance..*/
                const auto                          languageId = static_cast<int>(config.language);
                Microsoft::WRL::ComPtr<IPOLCoreCom> polcore;
                if (CoCreateInstance(xiloader::CLSID_POLCoreCom[languageId], NULL, 0x17, xiloader::IID_IPOLCoreCom[languageId], (LPVOID*)polcore.GetAddressOf()) != S_OK)
                {
                    xiloader::console::output(xiloader::color::error, "Failed to initialize instance of polcore!");
                }
                else
                {
                    /* Invoke the setup functions for polcore.. */
                    // Create string for the login view port
                    std::string polcorecmd = " /game eAZcFcB -net 3 -port " + std::to_string(config.loginViewPort);
                    // Cast to an LPSTR
                    LPSTR cmd = const_cast<char*>(polcorecmd.c_str());
                    polcore->SetAreaCode(languageId);
                    if (const auto hr = polcore->SetParamInit(GetModuleHandle(NULL), cmd); FAILED(hr))
                    {
                        xiloader::console::output(xiloader::color::error, "polcore failed to initialize (0x%08lX).", hr);
                    }

                    /* Obtain the common function table.. */
                    xiloader::playonline::CommandFunc** lpCommandTable;
                    if (const auto hr = polcore->GetCommonFunctionTable((unsigned long**)&lpCommandTable); FAILED(hr))
                    {
                        xiloader::console::output(xiloader::color::error, "Failed to get polcore's function table (0x%08lX).", hr);
                    }

                    /* Invoke the inet mutex function.. */
                    auto findMutex = (void* (*)(...))FindINETMutex(config.language);
                    findMutex();

                    /* Locate and prepare the pol connection.. */
                    auto polConnection = (char*)FindPolConn(config.language);
                    memset(polConnection, 0x00, 0x68);
                    auto enc = (char*)malloc(0x1000);
                    memset(enc, 0x00, 0x1000);
                    memcpy(polConnection + 0x48, &enc, sizeof(char**));

                    /* Locate the character storage buffer.. */
                    lobbyData.setCharacterList((char*)FindCharacters((void**)lpCommandTable));

                    /* Invoke the setup functions for polcore.. */
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::RegistryLang)](languageId);
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::FfxiLang)](xiloader::functions::GetRegistryPlayOnlineLanguage(config.language));
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::RegistryKey)](xiloader::functions::GetRegistryPlayOnlineKey(config.language));
                    const char* installFolder = xiloader::functions::GetRegistryPlayOnlineInstallFolder(config.language);
                    if (installFolder[0] == '\0')
                    {
                        xiloader::console::output(xiloader::color::error, "PlayOnline install folder not found in the registry (HKLM\\%s\\InstallFolder). Check PlayOnline is installed and --lang matches your install.", xiloader::functions::GetRegistryPlayOnlineKey(config.language));
                    }
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::InstallFolder)](installFolder);
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::FileInit)](); // Initialize polcore file system

                    if (!xiloader::playonline::disableCipher(config.language))
                    {
                        xiloader::console::output(xiloader::color::error, "Unsupported polcore version.");
                        return 1;
                    }

                    if (!xiloader::polrelay::start(config.serverAddress, config.profilePort, *session))
                    {
                        return 1;
                    }

                    // Without the viewer, polcore keeps its built-in Japanese message texts
                    if (config.language != xiloader::Language::Japanese)
                    {
                        xiloader::playonline::setEnglishMessageTexts(lpCommandTable);
                    }

                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::InetMutex)]();

                    if (!xiloader::playonline::logIn(lpCommandTable, session->accountId, config.language))
                    {
                        return 1;
                    }

                    xiloader::playonline::keepGameOnDisconnect(lpCommandTable);

                    /* Attempt to create FFXi instance..*/
                    Microsoft::WRL::ComPtr<IFFXiEntry> ffxi;
                    if (CoCreateInstance(xiloader::CLSID_FFXiEntry, NULL, 0x17, xiloader::IID_IFFXiEntry, (LPVOID*)ffxi.GetAddressOf()) != S_OK)
                    {
                        xiloader::console::output(xiloader::color::error, "Failed to initialize instance of FFxi!");
                    }
                    else
                    {
                        /* Attempt to start Final Fantasy.. */
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
                    }
                }
            }
        }
    }
    else
    {
        xiloader::console::output(xiloader::color::error, "Failed to resolve server hostname.");
    }

    return ERROR_SUCCESS;
}

/**
 * @brief Main program entrypoint.
 *
 * @param argc      The count of arguments being passed to this application on launch.
 * @param argv      Pointer to array of argument data.
 *
 * @return 1 on error, 0 on success.
 */
int __cdecl main(int argc, char* argv[])
{
    xiloader::Config config;

    try
    {
        config = xiloader::Config::load(argc, argv);
    }
    catch (const std::exception& err)
    {
        std::cerr << err.what() << std::endl;
        return 1;
    }

    std::array<uint8_t, 3> version = xiloader::Config::versionNumber;

    /* Output the banner.. */
    time_t currentTime = time(NULL);
    int    currentYear = localtime(&currentTime)->tm_year + 1900; // Year is returned as the number of years since 1900.
    xiloader::console::output(xiloader::color::lightred, "==========================================================");
    xiloader::console::output(xiloader::color::lightgreen, "DarkStar Boot Loader (c) 2015 DarkStar Team");
    xiloader::console::output(xiloader::color::lightgreen, "LandSandBoat Boot Loader (c) 2021-%d LandSandBoat Team (v%u.%u.%u)", currentYear, version[0], version[1], version[2]);
    xiloader::console::output(xiloader::color::lightblue, "Using %s", MBEDTLS_VERSION_STRING_FULL); // this prints "Using Mbed TLS #.#.#"
    xiloader::console::output(xiloader::color::lightpurple, "Git Repo   : https://github.com/LandSandBoat/xiloader");
    xiloader::console::output(xiloader::color::lightpurple, "Bug Reports: https://github.com/LandSandBoat/xiloader/issues");
    xiloader::console::output(xiloader::color::lightred, "==========================================================");

    const int result = run(config);

    xiloader::console::output(xiloader::color::error, "Closing...");
    Sleep(2000);

    return result;
}
