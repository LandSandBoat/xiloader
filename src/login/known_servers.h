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

#pragma once

#include "enums/server_trust.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace xiloader
{

class AuthConnection;
struct Config;

// The key fingerprint of each server the user has trusted, the way ssh keeps known_hosts.
// Servers mostly use self-signed certificates, so the first key seen is what later connections are held to.
class KnownServers
{
public:
    explicit KnownServers(std::filesystem::path file);

    // server is a name and port as from serverKey
    auto find(const std::string& server) const -> std::optional<std::string>;
    // Returns false when the file can't be written
    auto remember(const std::string& server, const std::string& fingerprint) const -> bool;

private:
    std::filesystem::path file;
};

// What a server's key is filed under: the name as the user gave it, lowercased, and the auth port
auto serverKey(const std::string& name, uint16_t port) -> std::string;

// A fingerprint as the user may have typed it, in the form fingerprints are compared in: "SHA256:" and unpadded base64
auto normalizeFingerprint(const std::string& fingerprint) -> std::string;

// known is the fingerprint on record, pinned the one from --fingerprint (empty when not given).
// Without a pin a loopback server is never asked about or refused, so local development isn't in the way.
auto judgeServer(const std::optional<std::string>& known, const std::string& presented, const std::string& pinned, bool loopback) -> ServerTrust;

// Holds the connected server to its key on record before anything is sent to it, asking the user about a new one.
// name is the server as the user gave it. Returns false when the server isn't to be trusted.
auto verifyServer(const AuthConnection& connection, const std::string& name, const Config& config) -> bool;

} // namespace xiloader
