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
#include <conio.h>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <print>
#include <utility>

#include "app_data.h"
#include "client/game.h"
#include "console.h"
#include "diagnostics/checks.h"
#include "guards.h"
#include "hooks/hairpin_fix.h"
#include "hooks/socket_hooks.h"
#include "lobby/data_connection.h"
#include "login/auth_connection.h"
#include "login/known_servers.h"
#include "login/login.h"
#include "net/resolve.h"

namespace
{

constexpr DWORD kCloseDelayMs = 2000;

using xiloader::ExitCode;

} // namespace

// Everything between the banner and "Closing...": logs in, then hosts polcore and the game until it exits.
// Whatever was set up is torn down in reverse order on every way out.
auto run(xiloader::Config& config) -> ExitCode
{
    // Before asking for a password, make sure there is a game to start
    if (!xiloader::report(xiloader::checkInstall(config.language), true))
    {
        return ExitCode::PlayOnlineMissing;
    }

    // Initialize Winsock
    const xiloader::Winsock winsock;
    if (winsock.error != 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize winsock, error code: {}", winsock.error);
        return ExitCode::StartupFailed;
    }

    // Initialize COM
    const xiloader::Com com;
    if (com.result != S_OK && com.result != S_FALSE)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize COM, error code: {}", com.result);
        return ExitCode::StartupFailed;
    }

    // Attach detour for gethostbyname..
    xiloader::SocketHooks hooks(config);
    if (!hooks.attached)
    {
        xiloader::console::output(xiloader::color::error, "Failed to detour function 'gethostbyname'. Cannot continue!");
        return ExitCode::StartupFailed;
    }

    xiloader::AuthConnection  auth;
    const xiloader::RelayStop relayStop;

    // Attempt to resolve the server address..
    const std::string serverName = config.serverAddress;
    ULONG             ulAddress  = 0;

    xiloader::console::output(xiloader::color::info, "Resolving '{}' ...", config.serverAddress);

    if (!xiloader::resolveHostname(config.serverAddress.c_str(), &ulAddress))
    {
        xiloader::console::output(xiloader::color::error, "Failed to resolve server hostname.");
        return ExitCode::ServerUnreachable;
    }

    config.serverAddress = inet_ntoa(*(reinterpret_cast<struct in_addr*>(&ulAddress)));

    xiloader::console::output(xiloader::color::info, "Resolved server address to '{}:{}'", config.serverAddress, config.loginAuthPort);

    // Attempt to verify the users account info..
    if (const auto connected = auth.connect(config.serverAddress, config.loginAuthPort); !connected)
    {
        xiloader::console::output(xiloader::color::error, "{}", connected.error());
        return ExitCode::ServerUnreachable;
    }

    if (!xiloader::verifyServer(auth, serverName, config))
    {
        return ExitCode::ServerUntrusted;
    }

    const auto session = xiloader::login::run(auth, config);
    if (!session)
    {
        if (session.error() == xiloader::LoginOutcome::Quit)
        {
            return ExitCode::Success;
        }

        return ExitCode::ConnectionLost;
    }

    hooks.useSession(*session);

    // Attempt to create connection to the login server..
    xiloader::LobbyDataConnection lobbyData;
    if (const auto connected = lobbyData.connect(config.serverAddress, config.loginDataPort); !connected)
    {
        const int err = WSAGetLastError();
        xiloader::console::output(xiloader::color::error, "{}", connected.error());
        xiloader::console::output(xiloader::color::error, "Failed to initialize connection to server on port {}, winsock error: {}", config.loginDataPort, err);
        return ExitCode::ServerUnreachable;
    }

    // Start hairpin hack thread if required..
    if (config.hairpin)
    {
        if (!xiloader::startHairpinFix(ulAddress))
        {
            xiloader::console::output(xiloader::color::error, "Failed to start the hairpin fix thread (error {}).", GetLastError());
        }
    }

    // Create lobby data thread
    lobbyData.start(*session);

    return xiloader::runGame(config, *session, lobbyData);
}

// Main program entrypoint.
// Returns an ExitCode.
auto __cdecl main(const int argc, char* argv[]) -> int
{
    auto config = xiloader::Config::load(argc, argv);
    if (!config)
    {
        std::println(std::cerr, "{}", config.error());
        return std::to_underlying(ExitCode::BadArguments);
    }

    if (const auto folder = xiloader::appDataFolder("logs"))
    {
        xiloader::console::startLog(*folder);
    }

    const std::array<uint8_t, 3> version = xiloader::Config::versionNumber;

    // Output the banner..
    const time_t currentTime = time(nullptr);
    const int    currentYear = localtime(&currentTime)->tm_year + 1900; // Year is returned as the number of years since 1900.
    xiloader::console::output(xiloader::color::lightred, "==========================================================");
    xiloader::console::output(xiloader::color::lightgreen, "DarkStar Boot Loader (c) 2015 DarkStar Team");
    xiloader::console::output(xiloader::color::lightgreen, "LandSandBoat Boot Loader (c) 2021-{} LandSandBoat Team (v{}.{}.{})", currentYear, version[0], version[1], version[2]);
    xiloader::console::output(xiloader::color::lightblue, "Using {}", MBEDTLS_VERSION_STRING_FULL); // this prints "Using Mbed TLS #.#.#"
    xiloader::console::output(xiloader::color::lightpurple, "Git Repo   : https://github.com/LandSandBoat/xiloader");
    xiloader::console::output(xiloader::color::lightpurple, "Bug Reports: https://github.com/LandSandBoat/xiloader/issues");
    xiloader::console::output(xiloader::color::lightred, "==========================================================");

    // With no language asked for, go with what is installed
    if (!config->languageChosen)
    {
        const auto installed = xiloader::installedLanguages();
        if (!installed.empty() && !std::ranges::contains(installed, config->language))
        {
            config->language = installed.front();
            xiloader::console::output(xiloader::color::info, "PlayOnline is installed for {}; using that. Pass --lang to choose another.", xiloader::languageName(config->language));
        }
    }

    auto result = ExitCode::Success;
    if (config->diagnose)
    {
        result = xiloader::runDiagnostics(*config);
    }
    else
    {
        result = run(*config);
    }

    if (result != ExitCode::Success && !config->diagnose)
    {
        xiloader::console::output(xiloader::color::info, "Run xiloader with --diagnose for a report on the install and the server.");
    }

    if ((result != ExitCode::Success || config->diagnose) && !xiloader::console::logFile().empty())
    {
        xiloader::console::output(xiloader::color::info, "This output is saved in {}", xiloader::console::logFile().string());
    }

    // A window made just for the loader would take the error with it
    if ((result != ExitCode::Success || config->diagnose) && xiloader::console::ownsWindow())
    {
        xiloader::console::output(xiloader::color::error, "Press any key to close this window.");
        _getch();
    }
    else
    {
        xiloader::console::output(xiloader::color::error, "Closing...");
        Sleep(kCloseDelayMs);
    }

    return std::to_underlying(result);
}
