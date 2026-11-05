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

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include <winsock2.h>

#include "enums/relay_phase.h"
#include "login/session.h"

namespace xiloader
{

// Relays polcore's PlayOnline connections (IRC and profile server) and the game's lobby view connection to the server over TLS.
// PlayOnline hosts resolve to a placeholder address that Mine_connect redirects to the relay's local ports;
// the view connection is redirected by the server address and view port it dials.
// Every server connection has to present the key the login server was trusted with.
// A single thread runs every connection, since mbedTLS isn't built thread-safe.
namespace polrelay
{

// A local listener, the address and port dialed for it, and the server port it forwards to
struct Listener
{
    SOCKET   socket        = INVALID_SOCKET;
    ULONG    dialedAddress = 0;
    uint16_t dialedPort    = 0;
    uint16_t serverPort    = 0;
    uint16_t localPort     = 0;
    bool     playOnline    = false; // Opens with the account id and session hash, and resumes TLS sessions
};

// One polcore connection: plain on the loopback side, TLS to the server
struct Connection
{
    SOCKET              local      = INVALID_SOCKET;
    uint16_t            serverPort = 0;
    bool                playOnline = false;
    mbedtls_net_context server     = {};
    mbedtls_ssl_context ssl        = {};
    Phase               phase      = Phase::Connecting;

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

    Connection(SOCKET local, uint16_t serverPort, bool playOnline);
    ~Connection();

    Connection(const Connection&)            = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&&)                 = delete;
    Connection& operator=(Connection&&)      = delete;
};

// Starts the relay thread, listening on free local ports for the IRC and profile ports polcore dials and the view port the game dials.
// PlayOnline connections open with the account id and session hash, which is how the server knows who it is.
// trustedKey is the login server's key fingerprint.
// Succeeds once the listeners are up; the error says what kept the relay from starting.
auto start(const std::string& server, uint16_t profilePort, uint16_t viewPort, const Session& session, const std::string& trustedKey) -> std::expected<void, std::string>;

// Closes every relay connection and joins the relay thread; call before removing the socket hooks
void stop();

// The placeholder address the PlayOnline host names should resolve to
auto address() -> const std::string&;

// Points a connection dialed for a relay listener at that listener, rewriting destination in place.
// Returns true when it was redirected. The relay's own connections are left alone.
auto redirect(sockaddr_in& destination) -> bool;

// The peer is the view listener, so the socket is the game's view connection
auto isViewConnection(const sockaddr_in& peer) -> bool;

} // namespace polrelay
} // namespace xiloader
