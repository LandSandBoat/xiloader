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

#include "checks.h"

#include "client/game.h"
#include "config.h"
#include "console.h"
#include "guards.h"
#include "login/auth_connection.h"
#include "net/resolve.h"

#include <ws2tcpip.h>

#include <algorithm>
#include <format>

namespace
{

using xiloader::Check;
using xiloader::CheckStatus;

// How long a port gets to answer
constexpr long kConnectTimeoutSeconds = 3;

auto canConnect(const ULONG address, const uint16_t port) -> bool
{
    const auto candidate = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (candidate == INVALID_SOCKET)
    {
        return false;
    }

    // Non-blocking, so an unanswered port costs the timeout rather than Windows' much longer default
    u_long nonBlocking = 1;
    ioctlsocket(candidate, FIONBIO, &nonBlocking);

    sockaddr_in target     = {};
    target.sin_family      = AF_INET;
    target.sin_port        = htons(port);
    target.sin_addr.s_addr = address;

    connect(candidate, reinterpret_cast<const sockaddr*>(&target), sizeof(target));

    fd_set writable = {};
    fd_set failed   = {};
    FD_SET(candidate, &writable);
    FD_SET(candidate, &failed);

    const timeval timeout   = { .tv_sec = kConnectTimeoutSeconds, .tv_usec = 0 };
    const bool    connected = select(0, nullptr, &writable, &failed, &timeout) > 0 && FD_ISSET(candidate, &writable);

    closesocket(candidate);

    return connected;
}

auto anyFailed(const std::vector<Check>& checks) -> bool
{
    return std::ranges::any_of(checks, [](const Check& check)
                               {
                                   return check.status == CheckStatus::Fail;
                               });
}

void append(std::vector<Check>& all, std::vector<Check> more)
{
    all.insert(all.end(), std::make_move_iterator(more.begin()), std::make_move_iterator(more.end()));
}

} // namespace

namespace xiloader
{

auto checkPolcoreVersion(const Language language) -> std::vector<Check>
{
    std::vector<Check> checks;

    const auto path = polcoreFile(language);
    if (!path)
    {
        // checkInstall has already said why
        return checks;
    }

    if (LoadLibraryExA(path->string().c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH) == nullptr)
    {
        checks.push_back({ .name   = "polcore loads",
                           .status = CheckStatus::Fail,
                           .detail = std::format("{} could not be loaded (error {})", path->string(), GetLastError()),
                           .hint   = "The file may be damaged, or a DLL it needs is missing. Run a file check from the PlayOnline Viewer." });
        return checks;
    }

    for (const auto& [what, found] : probePolcore(language))
    {
        if (found)
        {
            checks.push_back({ .name = std::format("polcore: {}", what), .detail = "found" });
        }
        else
        {
            checks.push_back({ .name   = std::format("polcore: {}", what),
                               .status = CheckStatus::Fail,
                               .detail = "not found",
                               .hint   = "This PlayOnline version isn't one the loader knows. Update xiloader, or report it with this output." });
        }
    }

    return checks;
}

auto checkServer(const Config& config) -> std::vector<Check>
{
    std::vector<Check> checks;

    ULONG address = 0;
    if (!resolveHostname(config.serverAddress.c_str(), &address))
    {
        checks.push_back({ .name   = "Server address",
                           .status = CheckStatus::Fail,
                           .detail = std::format("{} can't be resolved", config.serverAddress),
                           .hint   = "Check the --server address and your internet connection." });
        return checks;
    }

    char text[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &address, text, sizeof(text));
    checks.push_back({ .name = "Server address", .detail = std::format("{} is {}", config.serverAddress, text) });

    const std::pair<const char*, uint16_t> ports[] = {
        { "auth", config.loginAuthPort },
        { "data", config.loginDataPort },
        { "view", config.loginViewPort },
    };

    bool authReachable = false;
    for (const auto& [what, port] : ports)
    {
        if (canConnect(address, port))
        {
            checks.push_back({ .name = std::format("Server {} port", what), .detail = std::format("{} answers", port) });
            authReachable = authReachable || port == config.loginAuthPort;
        }
        else
        {
            checks.push_back({ .name   = std::format("Server {} port", what),
                               .status = CheckStatus::Fail,
                               .detail = std::format("nothing answers on {}:{}", text, port),
                               .hint   = "Check the server is running, the port is right and no firewall is in the way." });
        }
    }

    if (!authReachable)
    {
        return checks;
    }

    AuthConnection auth;
    if (const auto connected = auth.connect(text, config.loginAuthPort); connected)
    {
        checks.push_back({ .name = "Server TLS", .detail = "handshake completed" });

        if (const auto key = auth.fingerprint())
        {
            checks.push_back({ .name = "Server key", .detail = *key });
        }
    }
    else
    {
        checks.push_back({ .name   = "Server TLS",
                           .status = CheckStatus::Fail,
                           .detail = connected.error(),
                           .hint   = "The server may be older than this loader, or not xi_connect at all." });
    }

    return checks;
}

auto runDiagnostics(const Config& config) -> ExitCode
{
    const auto version = Config::versionNumber;
    console::output(color::info, "xiloader v{}.{}.{} diagnostics, language {}. Nothing is changed and the game is not started.", version[0], version[1], version[2], languageName(config.language));

    std::vector<Check> all = checkEnvironment(config.language);

    const auto install = checkInstall(config.language);
    append(all, install);

    const auto polcore = checkPolcoreVersion(config.language);
    append(all, polcore);

    std::vector<Check> server;
    if (const Winsock winsock; winsock.error == 0)
    {
        server = checkServer(config);
    }
    else
    {
        server.push_back({ .name = "Winsock", .status = CheckStatus::Fail, .detail = std::format("failed to start (error {})", winsock.error) });
    }
    append(all, server);

    console::output(color::lightred, "==========================================================");
    report(all, false);
    console::output(color::lightred, "==========================================================");

    if (anyFailed(install))
    {
        return ExitCode::PlayOnlineMissing;
    }

    if (anyFailed(polcore))
    {
        return ExitCode::PlayOnlineUnsupported;
    }

    if (anyFailed(server))
    {
        return ExitCode::ServerUnreachable;
    }

    console::output(color::success, "Nothing here would stop the game from starting.");
    return ExitCode::Success;
}

} // namespace xiloader
