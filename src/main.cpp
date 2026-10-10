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

#include <winsock2.h>

#include <windows.h>

#include "config.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>

#include "client/game.h"
#include "console.h"
#include "guards.h"
#include "hooks/hairpin_fix.h"
#include "hooks/socket_hooks.h"
#include "lobby/data_connection.h"
#include "login/auth_connection.h"
#include "login/login.h"
#include "net/resolve.h"

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

    if (!xiloader::resolveHostname(config.serverAddress.c_str(), &ulAddress))
    {
        xiloader::console::output(xiloader::color::error, "Failed to resolve server hostname.");
        return ERROR_SUCCESS;
    }

    config.serverAddress = inet_ntoa(*((struct in_addr*)&ulAddress));

    xiloader::console::output(xiloader::color::info, "Resolved server address to '%s:%d'", config.serverAddress.c_str(), config.loginAuthPort);

    /* Attempt to verify the users account info.. */
    if (!auth.connect(config.serverAddress, config.loginAuthPort))
    {
        return ERROR_SUCCESS;
    }

    const auto session = xiloader::login::run(auth, config);
    if (!session)
    {
        return ERROR_SUCCESS;
    }

    hooks.useSession(*session);

    /* Attempt to create connection to the login server.. */
    xiloader::LobbyDataConnection lobbyData;
    if (!lobbyData.connect(config.serverAddress, config.loginDataPort))
    {
        int err = WSAGetLastError();
        xiloader::console::output(xiloader::color::error, "Failed to initialize connection to server on port %u, winsock error: %d", config.loginDataPort, err);
        return ERROR_SUCCESS;
    }

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

    return xiloader::runGame(config, *session, lobbyData);
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
