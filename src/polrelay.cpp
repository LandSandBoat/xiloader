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

#include "defines.h"

#include "polrelay.h"

#include "console.h"

#include <mbedtls/error.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <system_error>
#include <thread>

namespace globals
{
    extern std::string g_ServerAddress;
    extern char        g_SessionHash[16];
} // namespace globals

namespace
{
    using xiloader::polrelay::Connection;
    using xiloader::polrelay::Listener;
    using xiloader::polrelay::Phase;
    using xiloader::polrelay::Tls;

    // The ports polcore dials; the profile server's own port can differ
    constexpr uint16_t kIrcPort     = 51240;
    constexpr uint16_t kProfilePort = 51220;

    // PlayOnline hosts resolve to this address; Mine_connect redirects it to our listeners
    const std::string kPlaceholderAddress = "127.64.0.1";

    // polcore holds at most 5 connections at once: IRC and its 4 profile slots
    constexpr std::size_t kMaxConnections = 8;

    constexpr ULONGLONG kHandshakeDeadlineMs = 10000;
    constexpr ULONGLONG kStallDeadlineMs     = 30000;

    // select timeout, which bounds how late stop() and the deadlines are noticed
    constexpr long kTickMs = 100;

    // Bytes per read, and the most held for polcore before reading more from the server
    constexpr std::size_t kChunkSize = 16384;

    Listener listeners[2] = {};

    Tls tls;

    in_addr serverAddress = {};

    // Sent first on every server connection: the account id (little-endian) and the session hash
    std::vector<unsigned char> hello;

    std::vector<std::unique_ptr<Connection>> connections;

    // Last session ticket, reused so each new connection skips the full handshake (valid on both ports)
    std::optional<mbedtls_ssl_session> ticket;

    std::jthread relayThread;

    auto errorText(const int ret) -> std::string
    {
        char text[128] = {};
        mbedtls_strerror(ret, text, sizeof(text));
        return text;
    }

    auto setUpTls() -> int
    {
        mbedtls_entropy_init(&tls.entropy);
        mbedtls_ctr_drbg_init(&tls.random);
        mbedtls_ssl_config_init(&tls.config);

        if (const auto ret = mbedtls_ctr_drbg_seed(&tls.random, mbedtls_entropy_func, &tls.entropy, nullptr, 0); ret != 0)
        {
            return ret;
        }

        if (const auto ret = mbedtls_ssl_config_defaults(&tls.config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT); ret != 0)
        {
            return ret;
        }

        // Servers typically use self-signed certificates
        mbedtls_ssl_conf_authmode(&tls.config, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_min_tls_version(&tls.config, MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_rng(&tls.config, mbedtls_ctr_drbg_random, &tls.random);
        mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(&tls.config, MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED);
        return 0;
    }

    void freeTls()
    {
        if (ticket)
        {
            mbedtls_ssl_session_free(&*ticket);
            ticket.reset();
        }

        mbedtls_ssl_config_free(&tls.config);
        mbedtls_ctr_drbg_free(&tls.random);
        mbedtls_entropy_free(&tls.entropy);
    }

    // Keeps the ports, which redirect reads from polcore's threads
    void closeListeners()
    {
        for (auto& listener : listeners)
        {
            closesocket(listener.socket);
            listener.socket = INVALID_SOCKET;
        }
    }

    void keepTicket(mbedtls_ssl_context* const ssl)
    {
        mbedtls_ssl_session session;
        mbedtls_ssl_session_init(&session);
        if (mbedtls_ssl_get_session(ssl, &session) != 0)
        {
            mbedtls_ssl_session_free(&session);
            return;
        }

        // The ticket now owns the session's allocations
        if (ticket)
        {
            mbedtls_ssl_session_free(&*ticket);
        }
        ticket = session;
    }

    auto setNonBlocking(const SOCKET socket) -> bool
    {
        u_long enabled = 1;
        return ioctlsocket(socket, FIONBIO, &enabled) == 0;
    }

    auto wouldBlock(const int ret) -> bool
    {
        return ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    void fail(const Connection& connection, const std::string& reason)
    {
        xiloader::console::output(xiloader::color::error, "Failed to reach the profile server on port %u (%s).", connection.serverPort, reason.c_str());
    }

    // Non-blocking connect; select reports the result as writable or failed
    auto open(Connection& connection) -> bool
    {
        const auto server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server == INVALID_SOCKET)
        {
            fail(connection, "no socket, winsock error " + std::to_string(WSAGetLastError()));
            return false;
        }

        // mbedtls_net_free closes it from here on
        connection.server.fd = static_cast<int>(server);

        const sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_port   = htons(connection.serverPort),
            .sin_addr   = serverAddress,
        };

        if (!setNonBlocking(server) ||
            (connect(server, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK))
        {
            fail(connection, "connection failed");
            return false;
        }

        if (const auto ret = mbedtls_ssl_setup(&connection.ssl, &tls.config); ret != 0)
        {
            fail(connection, errorText(ret));
            return false;
        }

        if (ticket)
        {
            mbedtls_ssl_set_session(&connection.ssl, &*ticket);
        }

        mbedtls_ssl_set_bio(&connection.ssl, &connection.server, mbedtls_net_send, mbedtls_net_recv, nullptr);
        connection.deadline = GetTickCount64() + kHandshakeDeadlineMs;
        return true;
    }

    // False once polcore closed; its data waits in toServer until the handshake is done
    auto readLocal(Connection& connection) -> bool
    {
        if (!connection.toServer.empty())
        {
            return true;
        }

        unsigned char buffer[kChunkSize];
        const auto    received = recv(connection.local, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
        if (received > 0)
        {
            connection.toServer.assign(buffer, buffer + received);
            return true;
        }

        return received == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK;
    }

    auto writeServer(Connection& connection) -> bool
    {
        connection.wantsWrite = false;
        while (!connection.toServer.empty())
        {
            const auto written = mbedtls_ssl_write(&connection.ssl, connection.toServer.data(), connection.toServer.size());
            if (written == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
            {
                keepTicket(&connection.ssl);
                continue;
            }

            if (wouldBlock(written))
            {
                connection.wantsWrite = written == MBEDTLS_ERR_SSL_WANT_WRITE;
                return true;
            }

            if (written <= 0)
            {
                return false;
            }

            connection.toServer.erase(connection.toServer.begin(), connection.toServer.begin() + written);
        }

        return true;
    }

    // Drains the records already received, up to one chunk ahead of polcore
    void readServer(Connection& connection)
    {
        unsigned char buffer[kChunkSize];
        while (!connection.serverClosed && connection.toLocal.size() < kChunkSize)
        {
            const auto read = mbedtls_ssl_read(&connection.ssl, buffer, kChunkSize - connection.toLocal.size());
            if (read == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
            {
                keepTicket(&connection.ssl);
                continue;
            }

            if (wouldBlock(read))
            {
                connection.wantsWrite = connection.wantsWrite || read == MBEDTLS_ERR_SSL_WANT_WRITE;
                return;
            }

            // Close or error: flush what arrived, then end
            if (read <= 0)
            {
                connection.serverClosed = true;
                return;
            }

            connection.toLocal.insert(connection.toLocal.end(), buffer, buffer + read);
        }
    }

    auto writeLocal(Connection& connection) -> bool
    {
        if (connection.toLocal.empty())
        {
            return true;
        }

        const auto sent = send(connection.local, reinterpret_cast<const char*>(connection.toLocal.data()), static_cast<int>(connection.toLocal.size()), 0);
        if (sent == SOCKET_ERROR)
        {
            return WSAGetLastError() == WSAEWOULDBLOCK;
        }

        connection.toLocal.erase(connection.toLocal.begin(), connection.toLocal.begin() + sent);
        return true;
    }

    // False once the connection is done
    auto step(Connection& connection, const fd_set& writable, const fd_set& failed, const ULONGLONG now) -> bool
    {
        const auto server = static_cast<SOCKET>(connection.server.fd);

        // After the server closes, only deliver what it already sent
        if (!connection.serverClosed && !readLocal(connection))
        {
            return false;
        }

        if (connection.phase == Phase::Connecting)
        {
            if (FD_ISSET(server, &failed))
            {
                fail(connection, "connection refused");
                return false;
            }

            if (!FD_ISSET(server, &writable))
            {
                return true;
            }

            connection.phase = Phase::Handshaking;
        }

        if (connection.phase == Phase::Handshaking)
        {
            const auto ret = mbedtls_ssl_handshake(&connection.ssl);
            if (wouldBlock(ret))
            {
                connection.wantsWrite = ret == MBEDTLS_ERR_SSL_WANT_WRITE;
                return true;
            }

            if (ret != 0)
            {
                fail(connection, errorText(ret));
                return false;
            }

            connection.phase     = Phase::Relaying;
            connection.stalledAt = now + kStallDeadlineMs;
            connection.toServer.insert(connection.toServer.begin(), hello.begin(), hello.end());
        }

        const auto queuedForServer = connection.toServer.size();
        if (!connection.serverClosed)
        {
            if (!writeServer(connection))
            {
                return false;
            }

            readServer(connection);
        }

        const auto queuedForLocal = connection.toLocal.size();
        if (!writeLocal(connection))
        {
            return false;
        }

        // Stalled only while holding bytes that aren't being written
        const auto wrote = connection.toServer.size() < queuedForServer || connection.toLocal.size() < queuedForLocal;
        if (wrote || (connection.toServer.empty() && connection.toLocal.empty()))
        {
            connection.stalledAt = now + kStallDeadlineMs;
        }

        return !(connection.serverClosed && connection.toLocal.empty());
    }

    auto expired(const Connection& connection, const ULONGLONG now) -> bool
    {
        if (connection.phase == Phase::Relaying)
        {
            const auto stalled = now >= connection.stalledAt;
            if (stalled)
            {
                xiloader::console::output(xiloader::color::warning, "Closed a stalled profile server connection on port %u.", connection.serverPort);
            }

            return stalled;
        }

        const auto late = now >= connection.deadline;
        if (late)
        {
            fail(connection, "timed out");
        }

        return late;
    }

    void accept(const Listener& listener)
    {
        const auto local = ::accept(listener.socket, nullptr, nullptr);
        if (local == INVALID_SOCKET)
        {
            return;
        }

        // Refuse anything past what polcore needs
        if (connections.size() >= kMaxConnections)
        {
            xiloader::console::output(xiloader::color::warning, "Refused a PlayOnline connection, %zu are already open.", connections.size());
            closesocket(local);
            return;
        }

        if (!setNonBlocking(local))
        {
            xiloader::console::output(xiloader::color::warning, "Refused a PlayOnline connection (winsock error %d).", WSAGetLastError());
            closesocket(local);
            return;
        }

        auto connection = std::make_unique<Connection>(local, listener.serverPort);
        if (open(*connection))
        {
            connections.push_back(std::move(connection));
        }
    }

    // Only watch what step() acts on, or select spins on unread data
    void watch(const Connection& connection, fd_set& readable, fd_set& writable, fd_set& failed)
    {
        const auto server = static_cast<SOCKET>(connection.server.fd);

        if (connection.toServer.empty())
        {
            FD_SET(connection.local, &readable);
        }

        if (!connection.toLocal.empty())
        {
            FD_SET(connection.local, &writable);
        }

        if (connection.phase == Phase::Connecting)
        {
            FD_SET(server, &writable);
            FD_SET(server, &failed);
            return;
        }

        if (connection.phase == Phase::Handshaking || connection.toLocal.empty())
        {
            FD_SET(server, &readable);
        }

        if (connection.wantsWrite || (connection.phase == Phase::Relaying && !connection.toServer.empty()))
        {
            FD_SET(server, &writable);
        }
    }

    void run(const std::stop_token stop)
    {
        while (!stop.stop_requested())
        {
            fd_set readable;
            fd_set writable;
            fd_set failed;
            FD_ZERO(&readable);
            FD_ZERO(&writable);
            FD_ZERO(&failed);

            for (const auto& listener : listeners)
            {
                FD_SET(listener.socket, &readable);
            }

            // Records mbedTLS already buffered don't show up in select
            auto buffered = false;
            for (const auto& connection : connections)
            {
                watch(*connection, readable, writable, failed);
                buffered = buffered || (connection->toLocal.empty() && mbedtls_ssl_check_pending(&connection->ssl) != 0);
            }

            const timeval timeout = { .tv_sec = 0, .tv_usec = buffered ? 0 : kTickMs * 1000 };
            if (select(0, &readable, &writable, &failed, &timeout) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "The profile server relay stopped (%d).", WSAGetLastError());
                break;
            }

            for (const auto& listener : listeners)
            {
                if (FD_ISSET(listener.socket, &readable))
                {
                    accept(listener);
                }
            }

            const auto now = GetTickCount64();
            std::erase_if(connections, [&](const std::unique_ptr<Connection>& connection)
            {
                return !step(*connection, writable, failed, now) || expired(*connection, now);
            });
        }

        connections.clear();
        closeListeners();
        freeTls();
    }

    // OS-picked port so multiple clients don't collide
    auto listen(Listener& entry, const uint16_t dialedPort, const uint16_t serverPort) -> bool
    {
        const auto listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET)
        {
            return false;
        }

        sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_addr   = { .S_un = { .S_addr = htonl(INADDR_LOOPBACK) } },
        };

        int length = sizeof(address);
        if (bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR ||
            getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == SOCKET_ERROR ||
            ::listen(listener, SOMAXCONN) == SOCKET_ERROR ||
            !setNonBlocking(listener))
        {
            closesocket(listener);
            return false;
        }

        entry = { .socket = listener, .dialedPort = dialedPort, .serverPort = serverPort, .localPort = ntohs(address.sin_port) };
        return true;
    }
} // namespace

namespace xiloader::polrelay
{
    Connection::Connection(const SOCKET local, const uint16_t serverPort)
    : local(local)
    , serverPort(serverPort)
    {
        mbedtls_net_init(&server);
        mbedtls_ssl_init(&ssl);
    }

    Connection::~Connection()
    {
        if (phase == Phase::Relaying && !serverClosed)
        {
            mbedtls_ssl_close_notify(&ssl);
        }

        mbedtls_ssl_free(&ssl);
        mbedtls_net_free(&server);
        closesocket(local);
    }

    auto start(const uint16_t profilePort, const uint32_t accountId) -> bool
    {
        hello.resize(sizeof(accountId) + sizeof(globals::g_SessionHash));
        std::memcpy(hello.data(), &accountId, sizeof(accountId));
        std::memcpy(hello.data() + sizeof(accountId), globals::g_SessionHash, sizeof(globals::g_SessionHash));

        if (inet_pton(AF_INET, globals::g_ServerAddress.c_str(), &serverAddress) != 1)
        {
            xiloader::console::output(xiloader::color::error, "The profile server relay needs a resolved server address (%s).", globals::g_ServerAddress.c_str());
            return false;
        }

        const auto abort = [](const std::string& reason)
        {
            xiloader::console::output(xiloader::color::error, "Failed to start the profile server relay (%s).", reason.c_str());
            closeListeners();
            freeTls();
            return false;
        };

        if (const auto ret = setUpTls(); ret != 0)
        {
            return abort(errorText(ret));
        }

        if (!listen(listeners[0], kIrcPort, kIrcPort) || !listen(listeners[1], kProfilePort, profilePort))
        {
            return abort(std::to_string(WSAGetLastError()));
        }

        try
        {
            relayThread = std::jthread(run);
        }
        catch (const std::system_error& error)
        {
            return abort(error.what());
        }

        return true;
    }

    void stop()
    {
        if (relayThread.joinable())
        {
            relayThread.request_stop();
            relayThread.join();
        }
    }

    auto address() -> const std::string&
    {
        return kPlaceholderAddress;
    }

    auto redirect(sockaddr_in& destination) -> bool
    {
        if (destination.sin_family != AF_INET || destination.sin_addr.s_addr != inet_addr(kPlaceholderAddress.c_str()))
        {
            return false;
        }

        const auto port  = ntohs(destination.sin_port);
        const auto entry = std::ranges::find(listeners, port, &Listener::dialedPort);
        if (entry == std::end(listeners))
        {
            return false;
        }

        destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        destination.sin_port        = htons(entry->localPort);
        return true;
    }
} // namespace xiloader::polrelay
