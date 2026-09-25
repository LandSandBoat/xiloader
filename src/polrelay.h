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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include <cstdint>
#include <string>
#include <vector>

#include <winsock2.h>

namespace xiloader
{
    // Relays polcore's PlayOnline connections (IRC and profile server) to the server over TLS.
    // PlayOnline hosts resolve to a placeholder address that Mine_connect redirects to the relay's local ports.
    // A single thread runs every connection, since mbedTLS isn't built thread-safe.
    namespace polrelay
    {
        // A local listener, the port polcore dials for it, and the server port it forwards to
        struct Listener
        {
            SOCKET   socket     = INVALID_SOCKET;
            uint16_t dialedPort = 0;
            uint16_t serverPort = 0;
            uint16_t localPort  = 0;
        };

        // Shared by all relay connections
        struct Tls
        {
            mbedtls_entropy_context  entropy;
            mbedtls_ctr_drbg_context random;
            mbedtls_ssl_config       config;
        };

        enum class Phase
        {
            Connecting,
            Handshaking,
            Relaying,
        };

        // One polcore connection: plain on the loopback side, TLS to the server
        struct Connection
        {
            SOCKET              local      = INVALID_SOCKET;
            uint16_t            serverPort = 0;
            mbedtls_net_context server;
            mbedtls_ssl_context ssl;
            Phase               phase = Phase::Connecting;

            // Bytes read from one side and not yet written to the other
            std::vector<unsigned char> toServer;
            std::vector<unsigned char> toLocal;

            // The pending TLS operation needs the server socket writable
            bool wantsWrite = false;

            // The server closed; the connection ends once toLocal is flushed
            bool serverClosed = false;

            // Connect and handshake must finish by deadline; pending bytes must move before stalledAt
            ULONGLONG deadline  = 0;
            ULONGLONG stalledAt = 0;

            Connection(SOCKET local, uint16_t serverPort);
            ~Connection();

            Connection(const Connection&)            = delete;
            Connection& operator=(const Connection&) = delete;
        };

        // Starts the relay thread, listening on free local ports for the IRC port and the profile port polcore dials.
        // Every connection to the server opens with the account id and session hash, which is how the server knows who it is.
        // Returns true once both listeners are up.
        auto start(uint16_t profilePort, uint32_t accountId) -> bool;

        // Closes every relay connection and joins the relay thread; call before removing the socket hooks
        void stop();

        // The placeholder address the PlayOnline host names should resolve to
        auto address() -> const std::string&;

        // Points a connection to the placeholder address at the matching relay listener, rewriting destination in place.
        // Returns true when it was a PlayOnline connection.
        auto redirect(sockaddr_in& destination) -> bool;
    } // namespace polrelay
} // namespace xiloader
