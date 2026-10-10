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

#include <cstdint>
#include <string>

#include <nlohmann/json_fwd.hpp>

namespace xiloader
{

// The trust tokens one server has issued to this computer; a valid token lets a login skip the OTP code.
// Tokens for every server share one file under %APPDATA%, encrypted for the current Windows user.
class TrustTokenManager
{
public:
    explicit TrustTokenManager(std::string server);

    auto isTrusted(const std::string& username) const -> bool;

    // Adds the user's token, if any, and whether the server should issue a new one
    void addToLoginRequest(nlohmann::json& request, const std::string& username, bool trustThisComputer) const;

    // Stores the token a successful login reply carries, if any
    void acceptLoginReply(const nlohmann::json& reply, const std::string& username) const;

    void revoke(const std::string& username) const;

private:
    // Returns an empty string when the user has no token; an expired token is removed from the file
    auto load(const std::string& username) const -> std::string;
    void save(const std::string& username, const std::string& token, int64_t expiresEpoch) const;

    auto key(const std::string& username) const -> std::string;

    std::string server;
    std::string storePath;
};

} // namespace xiloader
