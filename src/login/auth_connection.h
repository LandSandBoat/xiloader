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

#include "net/tls_client_config.h"

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include <cstdint>
#include <expected>
#include <string>

namespace xiloader
{

// The TLS connection to xi_connect's auth port. It stays open until the object is destroyed.
class AuthConnection
{
public:
    AuthConnection();
    ~AuthConnection();

    AuthConnection(const AuthConnection&)            = delete;
    AuthConnection& operator=(const AuthConnection&) = delete;
    AuthConnection(AuthConnection&&)                 = delete;
    AuthConnection& operator=(AuthConnection&&)      = delete;

    // Connects and completes the handshake. The error says which step failed.
    auto connect(const std::string& server, uint16_t port) -> std::expected<void, std::string>;

    // "SHA256:" and the unpadded base64 hash of the server's public key, as ssh prints them. Needs a completed connect.
    auto fingerprint() const -> std::expected<std::string, std::string>;

    // The server is this machine
    auto isLoopback() const -> bool;

    // Sends one request and waits for the reply. The error says why the connection failed.
    auto exchange(const std::string& request) -> std::expected<std::string, std::string>;

private:
    TlsClientConfig     config;
    mbedtls_net_context server = {};
    mbedtls_ssl_context ssl    = {};
};

} // namespace xiloader
