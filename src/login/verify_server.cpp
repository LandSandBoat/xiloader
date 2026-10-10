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

#include "known_servers.h"

#include "app_data.h"
#include "auth_connection.h"
#include "config.h"
#include "console.h"
#include "ui/prompts.h"

namespace
{

constexpr const char* kStoreName = "known_servers.json";

void save(const xiloader::KnownServers& servers, const std::string& server, const std::string& fingerprint)
{
    if (!servers.remember(server, fingerprint))
    {
        xiloader::console::output(xiloader::color::warning, "Failed to save the server key.");
    }
}

} // namespace

namespace xiloader
{

auto verifyServer(const AuthConnection& connection, const std::string& name, const Config& config) -> bool
{
    const auto presented = connection.fingerprint();
    if (!presented)
    {
        console::output(color::error, "{}", presented.error());
        return false;
    }

    // With nowhere to keep a record every connection is a first one
    std::filesystem::path store;
    if (const auto folder = appDataFolder())
    {
        store = *folder / kStoreName;
    }

    const KnownServers servers(store);
    const auto         server   = serverKey(name, config.loginAuthPort);
    const auto         known    = servers.find(server);
    const bool         loopback = connection.isLoopback();

    switch (judgeServer(known, *presented, config.fingerprint, loopback))
    {
        case ServerTrust::Trusted:
        {
            return true;
        }
        case ServerTrust::Remember:
        {
            if (known && *known != *presented)
            {
                console::output(color::warning, "Server key for '{}' changed to {}.", server, *presented);
            }

            if (known != *presented)
            {
                save(servers, server, *presented);
            }

            return true;
        }
        case ServerTrust::Ask:
        {
            console::output(color::warning, "Unknown server '{}'.", server);
            console::output(color::warning, "Key fingerprint: {}", *presented);

            const auto menu = ui::makeMenu(config.plainMenus);
            if (!ui::okCancelDialog(*menu, "Trust this server"))
            {
                console::output(color::error, "Server not trusted. Use --fingerprint {} to skip this prompt.", *presented);
                return false;
            }

            save(servers, server, *presented);
            return true;
        }
        case ServerTrust::Changed:
        {
            console::output(color::error, "==========================================================");
            console::output(color::error, "Server key for '{}' has changed!", server);
            console::output(color::error, "Saved: {}", *known);
            console::output(color::error, "Got:   {}", *presented);
            console::output(color::error, "If this is expected, run once with --fingerprint {}", *presented);
            console::output(color::error, "==========================================================");
            return false;
        }
        case ServerTrust::PinMismatch:
        {
            console::output(color::error, "Server key for '{}' does not match --fingerprint.", server);
            console::output(color::error, "Expected: {}", normalizeFingerprint(config.fingerprint));
            console::output(color::error, "Got:      {}", *presented);
            return false;
        }
    }

    return false;
}

} // namespace xiloader
