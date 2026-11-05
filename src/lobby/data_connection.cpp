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

#include "data_connection.h"

#include "console.h"

#include "enums/lobby_data.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <vector>

namespace
{

// Size of one character in polcore's list, and of one in the server's packet
constexpr int kListEntrySize   = 0x68;
constexpr int kPacketEntrySize = 0x10;

// The server's packets carry no length; a request is this long and the character list that long
constexpr std::size_t kRequestSize = 5;
constexpr std::size_t kListSize    = 0x148;

// Characters the list packet has room for
constexpr int kMaxCharacters = (kListSize - 8) / kPacketEntrySize;

constexpr std::size_t kBufferSize     = 4096;
constexpr int         kReplySize      = 28;
constexpr DWORD       kSendIntervalMs = 100;

auto packetSize(const xiloader::LobbyDataRequest type) -> std::size_t
{
    switch (type)
    {
        case xiloader::LobbyDataRequest::AccountId:
        case xiloader::LobbyDataRequest::Key:
        case xiloader::LobbyDataRequest::KeyAlternate:
            return kRequestSize;
        case xiloader::LobbyDataRequest::CharacterList:
            return kListSize;
    }

    return 0;
}

// Copies the characters of a list packet into polcore's list
void applyList(char* const list, const char* const packet)
{
    const auto count = std::min(static_cast<int>(static_cast<uint8_t>(packet[1])), kMaxCharacters);

    for (auto x = 0; x < count; x++)
    {
        list[0x00 + (x * kListEntrySize)] = 1;
        list[0x02 + (x * kListEntrySize)] = 1;
        list[0x10 + (x * kListEntrySize)] = static_cast<char>(x);
        list[0x11 + (x * kListEntrySize)] = 0x80u;
        list[0x18 + (x * kListEntrySize)] = 0x20;
        list[0x28 + (x * kListEntrySize)] = 0x20;

        memcpy(list + 0x04 + (x * kListEntrySize), packet + kPacketEntrySize * (x + 1) + 0x04, 4); // Character Id
        memcpy(list + 0x08 + (x * kListEntrySize), packet + kPacketEntrySize * (x + 1), 4);        // Content Id
    }
}

} // namespace

namespace xiloader
{

LobbyDataConnection::LobbyDataConnection()
{
    mbedtls_net_init(&server);
    mbedtls_ssl_init(&ssl);
}

LobbyDataConnection::~LobbyDataConnection()
{
    // Shutting the socket down wakes the thread out of recv; the session is only freed once the thread is done with it
    if (thread.joinable())
    {
        thread.request_stop();
        shutdown(static_cast<SOCKET>(server.fd), SD_BOTH);
        thread.join();
    }

    mbedtls_ssl_free(&ssl);
    mbedtls_net_free(&server);
}

auto LobbyDataConnection::connect(const std::string& address, const uint16_t port, const std::string& trustedKey) -> std::expected<void, std::string>
{
    if (const auto ret = tls.setUp(); ret != 0)
    {
        return std::unexpected(std::format("Failed to set up TLS ({}).", xiloader::mbedtlsErrorText(ret)));
    }

    // The key is held to the login server's below rather than to a CA
    mbedtls_ssl_conf_authmode(tls.get(), MBEDTLS_SSL_VERIFY_NONE);

    if (const auto ret = mbedtls_net_connect(&server, address.c_str(), std::to_string(port).c_str(), MBEDTLS_NET_PROTO_TCP); ret != 0)
    {
        return std::unexpected(std::format("Failed to connect to the data port ({}).", xiloader::mbedtlsErrorText(ret)));
    }

    if (const auto ret = mbedtls_ssl_setup(&ssl, tls.get()); ret != 0)
    {
        return std::unexpected(std::format("Failed to set up TLS ({}).", xiloader::mbedtlsErrorText(ret)));
    }

    mbedtls_ssl_set_bio(&ssl, &server, mbedtls_net_send, mbedtls_net_recv, nullptr);

    for (auto ret = mbedtls_ssl_handshake(&ssl); ret != 0; ret = mbedtls_ssl_handshake(&ssl))
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            return std::unexpected(std::format("TLS handshake with the data port failed ({}).", xiloader::mbedtlsErrorText(ret)));
        }
    }

    if (const auto matched = xiloader::checkPeerKey(ssl, trustedKey); !matched)
    {
        return std::unexpected(std::format("The data port is not the trusted server: {}.", matched.error()));
    }

    xiloader::console::output(xiloader::color::info, "Connected to server!");

    serverAddress = inet_addr(address.c_str());

    return {};
}

auto LobbyDataConnection::write(const char* const data, const std::size_t size) -> bool
{
    std::size_t sent = 0;
    while (sent < size)
    {
        const auto ret = mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>(data) + sent, size - sent);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
        {
            continue;
        }

        if (ret < 0)
        {
            return false;
        }

        sent += static_cast<std::size_t>(ret);
    }

    return true;
}

void LobbyDataConnection::start(const Session& session)
{
    thread = std::jthread([this, session](const std::stop_token& stop)
                          {
                              run(stop, session);
                          });
}

void LobbyDataConnection::setCharacterList(char* const list)
{
    const std::lock_guard lock(listMutex);

    characterList = list;

    if (list != nullptr && !heldList.empty())
    {
        applyList(list, heldList.data());
        heldList.clear();
    }
}

void LobbyDataConnection::run(const std::stop_token& stop, const Session& session)
{
    char recvBuffer[kBufferSize] = { 0 };
    char sendBuffer[kBufferSize] = { 0 };

    // send session hash
    sendBuffer[0] = static_cast<char>(xiloader::LobbyDataReply::SessionHash);
    memcpy(sendBuffer + 12, session.hash, 16);

    if (!write(sendBuffer, kReplySize))
    {
        xiloader::console::output("Failed to send session hash for data to server; disconnecting!");
        return;
    }
    memset(sendBuffer, 0, kReplySize);

    // What was read and not yet handled; a read can end mid-packet or hold several
    std::vector<char> pending;

    while (!stop.stop_requested())
    {
        // Attempt to receive the incoming data..
        const auto received = mbedtls_ssl_read(&ssl, reinterpret_cast<unsigned char*>(recvBuffer), sizeof(recvBuffer));
        if (received == MBEDTLS_ERR_SSL_WANT_READ || received == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
        {
            continue;
        }

        if (received <= 0)
        {
            // The server closed the connection, or the destructor closed the socket
            return;
        }

        pending.insert(pending.end(), recvBuffer, recvBuffer + received);

        while (!pending.empty())
        {
            const auto type = static_cast<xiloader::LobbyDataRequest>(pending[0]);
            const auto size = packetSize(type);
            if (size == 0)
            {
                // Not a packet this knows the length of, so there is no telling where the next one starts
                pending.clear();
                break;
            }

            if (pending.size() < size)
            {
                break;
            }

            const char* const packet   = pending.data();
            int               sendSize = 0;

            switch (type)
            {
                case xiloader::LobbyDataRequest::AccountId:
                    sendBuffer[0] = static_cast<char>(xiloader::LobbyDataReply::AccountId);
                    memcpy(sendBuffer + 0x01, &session.accountId, 4);
                    memcpy(sendBuffer + 0x05, &serverAddress, 4);
                    memcpy(sendBuffer + 12, session.hash, 16);

                    xiloader::console::output(xiloader::color::warning, "Sending account id..");
                    sendSize = kReplySize;
                    break;

                case xiloader::LobbyDataRequest::Key:
                case xiloader::LobbyDataRequest::KeyAlternate:
                    // The packet starts with LobbyDataReply::Key
                    memcpy(sendBuffer, "\xA2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58\xE0\x5D\xAD\x00\x00\x00\x00", 25);

                    xiloader::console::output(xiloader::color::warning, "Sending key..");
                    sendSize = kReplySize;
                    break;

                case xiloader::LobbyDataRequest::CharacterList:
                {
                    xiloader::console::output(xiloader::color::warning, "Receiving character list..");

                    const std::lock_guard lock(listMutex);

                    // Against a local server the list can arrive before polcore's buffer is known
                    if (characterList == nullptr)
                    {
                        heldList.assign(packet, packet + size);
                    }
                    else
                    {
                        applyList(characterList, packet);
                    }
                    break;
                }
            }

            pending.erase(pending.begin(), pending.begin() + size);

            if (sendSize == 0)
                continue;

            // Send the response buffer to the server..
            if (!write(sendBuffer, sendSize))
            {
                xiloader::console::output("Server connection done; disconnecting!");
                return;
            }

            Sleep(kSendIntervalMs);
        }
    }
}

} // namespace xiloader
