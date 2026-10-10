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
        xiloader::console::output(xiloader::color::warning, "The server's key couldn't be saved, so it will be asked about again.");
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
                console::output(color::warning, "The key of server '{}' has changed to {}.", server, *presented);
            }

            if (known != *presented)
            {
                save(servers, server, *presented);
            }

            return true;
        }
        case ServerTrust::Ask:
        {
            console::output(color::warning, "The authenticity of server '{}' can't be established.", server);
            console::output(color::warning, "Its key fingerprint is {}", *presented);
            console::output(color::warning, "Compare it with the one the server's operator published. Nothing has been sent yet.");

            const auto menu = ui::makeMenu(config.plainMenus);
            if (!ui::okCancelDialog(*menu, "Trust this server"))
            {
                console::output(color::error, "The server was not trusted. To trust it without being asked, pass --fingerprint {}", *presented);
                return false;
            }

            save(servers, server, *presented);
            return true;
        }
        case ServerTrust::Changed:
        {
            console::output(color::error, "==========================================================");
            console::output(color::error, "The key of server '{}' is not the one it was trusted with.", server);
            console::output(color::error, "Someone may be intercepting the connection, or the server's certificate was replaced.");
            console::output(color::error, "On record: {}", *known);
            console::output(color::error, "Presented: {}", *presented);
            console::output(color::error, "Nothing was sent. If the server's operator confirms the new key, start the loader once with --fingerprint {}", *presented);
            console::output(color::error, "==========================================================");
            return false;
        }
        case ServerTrust::PinMismatch:
        {
            console::output(color::error, "The key of server '{}' is not the one --fingerprint asked for.", server);
            console::output(color::error, "Asked for: {}", normalizeFingerprint(config.fingerprint));
            console::output(color::error, "Presented: {}", *presented);
            console::output(color::error, "Nothing was sent.");
            return false;
        }
    }

    return false;
}

} // namespace xiloader
