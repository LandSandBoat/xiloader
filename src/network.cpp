/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams
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

This file is part of DarkStar-server source code.

===========================================================================
*/

#include "network.h"
#include "app.h"
#include "helpers.h"
#include <iphlpapi.h>
#include <vector>

#include "enums/lobby_data.h"
#include "helpers.h"

// mbed tls state
namespace sslState
{

extern mbedtls_net_context               server_fd;
extern mbedtls_entropy_context           entropy;
extern mbedtls_ctr_drbg_context          ctr_drbg;
extern mbedtls_ssl_context               ssl;
extern mbedtls_ssl_config                conf;
extern mbedtls_x509_crt                  cacert;
extern std::unique_ptr<mbedtls_x509_crt> ca_chain;

}; // namespace sslState

namespace xiloader
{

/**
 * @brief Creates a connection on the given port.
 *
 * @param sock      The datasocket object to store information within.
 * @param port      The port to create the connection on.
 *
 * @return True on success, false otherwise.
 */
bool network::CreateConnection(datasocket* sock, const char* port)
{
    struct addrinfo hints;
    memset(&hints, 0x00, sizeof(hints));

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* Attempt to get the server information. */
    struct addrinfo* addr = NULL;
    if (getaddrinfo(xiloader::config.serverAddress.c_str(), port, &hints, &addr))
    {
        xiloader::console::output(xiloader::color::error, "Failed to obtain remote server information.");
        return 0;
    }

    /* Determine which address is valid to connect.. */
    for (auto ptr = addr; ptr != NULL; ptr->ai_next)
    {
        /* Attempt to create the socket.. */
        sock->s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock->s == INVALID_SOCKET)
        {
            xiloader::console::output(xiloader::color::error, "Failed to create socket.");

            freeaddrinfo(addr);
            return 0;
        }

        /* Attempt to connect to the server.. */
        if (connect(sock->s, ptr->ai_addr, ptr->ai_addrlen) == SOCKET_ERROR)
        {
            xiloader::console::output(xiloader::color::error, "Failed to connect to server!");

            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return 0;
        }

        xiloader::console::output(xiloader::color::info, "Connected to server!");
        break;
    }

    std::string localAddress = "";

    /* Attempt to locate the client address.. */
    char hostname[1024] = { 0 };
    if (gethostname(hostname, sizeof(hostname)) == 0)
    {
        PHOSTENT hostent = NULL;
        if ((hostent = gethostbyname(hostname)) != NULL)
            localAddress = inet_ntoa(*(struct in_addr*)*hostent->h_addr_list);
    }

    sock->LocalAddress  = inet_addr(localAddress.c_str());
    sock->ServerAddress = inet_addr(xiloader::config.serverAddress.c_str());

    return 1;
}

/**
 * @brief Creates a connection to the auth server on the given port.
 *
 * @param sock      The datasocket object to store information within.
 * @param port      The port to create the connection on.
 *
 * @return True on success, false otherwise.
 */
bool network::CreateAuthConnection(datasocket* sock, const char* port)
{
    struct addrinfo hints;
    memset(&hints, 0x00, sizeof(hints));

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* Attempt to get the server information. */
    struct addrinfo* addr = NULL;
    if (getaddrinfo(xiloader::config.serverAddress.c_str(), port, &hints, &addr))
    {
        xiloader::console::output(xiloader::color::error, "Failed to obtain remote server information.");
        return 0;
    }

    int ret = 0;

    ret = mbedtls_net_connect(&sslState::server_fd, xiloader::config.serverAddress.c_str(), port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        xiloader::console::output(xiloader::color::error, "mbedtls_net_connect failed, (%s)", mbedtls_low_level_strerr(ret));
        return 0;
    }

    if ((ret = mbedtls_ssl_config_defaults(&sslState::conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        xiloader::console::output(xiloader::color::error, "mbedtls_ssl_config_defaults failed, (%s)", mbedtls_low_level_strerr(ret));
        return 0;
    }

    // MBEDTLS_SSL_VERIFY_OPTIONAL provides warnings, but doesn't stop connections.
    mbedtls_ssl_conf_authmode(&sslState::conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_min_tls_version(&sslState::conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_ca_chain(&sslState::conf, sslState::ca_chain.get(), NULL);
    mbedtls_ssl_conf_rng(&sslState::conf, mbedtls_ctr_drbg_random, &sslState::ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&sslState::ssl, &sslState::conf)) != 0)
    {
        xiloader::console::output(xiloader::color::error, "mbedtls_ssl_setup failed, (%s)", mbedtls_low_level_strerr(ret));
        return 0;
    }

    mbedtls_ssl_set_bio(&sslState::ssl, &sslState::server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&sslState::ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            xiloader::console::output(xiloader::color::error, "mbedtls_ssl_handshake returned -0x%x", (unsigned int)-ret);
            return 0;
        }
    }

    uint32_t flags = 0;

    if ((flags = mbedtls_ssl_get_verify_result(&sslState::ssl)) != 0)
    {
        // We genuinely don't care if the error flags is ONLY that the cert isn't trusted,
        // If this is the only warning, just don't print it.
        if (flags != MBEDTLS_X509_BADCERT_NOT_TRUSTED)
        {
            char        vrfy_buf[1024] = {};
            std::string timestamp      = xiloader::console::getTimestamp();

            flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED; // Don't report the cert isn't trusted -- we don't care.

            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), timestamp.c_str(), flags);

            xiloader::console::output(xiloader::color::warning, "Remote server certificate warnings:", vrfy_buf);
            xiloader::console::print(xiloader::color::warning, vrfy_buf);
        }
    }
    else
    {
        xiloader::console::output(xiloader::color::info, "Remote server (%s) certificate is valid.", xiloader::config.serverAddress.c_str());
    }

    sockaddr clientAddr  = {};
    int      sockaddrLen = sizeof(clientAddr);
    getsockname(static_cast<SOCKET>(sslState::server_fd.fd), &clientAddr, &sockaddrLen);

    struct sockaddr_in* their_inaddr_ptr = (struct sockaddr_in*)&clientAddr;

    sock->LocalAddress  = their_inaddr_ptr->sin_addr.S_un.S_addr;
    sock->ServerAddress = inet_addr(xiloader::config.serverAddress.c_str());

    unsigned char recvBuffer[4096] = {};

    mbedtls_ssl_conf_read_timeout(&sslState::conf, 1000);

    return 1;
}

/**
 * @brief Resolves the given hostname to its long ip format.
 *
 * @param host      The host name to resolve.
 * @param lpOutput  Pointer to a ULONG to store the result.
 *
 * @return True on success, false otherwise.
 */
bool network::ResolveHostname(const char* host, PULONG lpOutput)
{
    struct addrinfo hints, *info = 0;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, "1000", &hints, &info))
        return false;

    *lpOutput = ((struct sockaddr_in*)info->ai_addr)->sin_addr.S_un.S_addr;

    freeaddrinfo(info);
    return true;
}

/**
 * @brief Sends one request on the auth connection and waits for the reply.
 *
 * @param request   The request to send.
 *
 * @return The reply, or nothing when the connection failed.
 */
std::optional<std::string> network::ExchangeAuth(const std::string& request)
{
    if (const auto written = mbedtls_ssl_write(&sslState::ssl, reinterpret_cast<const unsigned char*>(request.data()), request.size()); written < 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to send the login request (%s). The login server may have closed the connection.", xiloader::mbedtlsErrorText(written).c_str());
        return std::nullopt;
    }

    unsigned char recvBuffer[8192] = { 0 };

    const auto received = mbedtls_ssl_read(&sslState::ssl, recvBuffer, sizeof(recvBuffer));
    if (received == MBEDTLS_ERR_SSL_TIMEOUT)
    {
        xiloader::console::output(xiloader::color::error, "Remote failed to reply within the timeout, exiting...");
        return std::nullopt;
    }

    if (received <= 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to read the login reply (%s). The login server may have closed the connection.", xiloader::mbedtlsErrorText(received).c_str());
        return std::nullopt;
    }

    return std::string(reinterpret_cast<const char*>(recvBuffer), received);
}

/**
 * @brief Data communication between the local client and the game server.
 *
 * @param lpParam   Thread param object.
 *
 * @return Non-important return.
 */
DWORD __stdcall network::FFXiDataComm(LPVOID lpParam)
{
    auto sock = (xiloader::datasocket*)lpParam;

    int  sendSize         = 0;
    char recvBuffer[4096] = { 0 };
    char sendBuffer[4096] = { 0 };

    struct sockaddr_in client;
    unsigned int       socksize = sizeof(client);

    // send session hash
    sendBuffer[0] = static_cast<char>(xiloader::LobbyDataReply::SessionHash);
    memcpy(sendBuffer + 12, xiloader::state.sessionHash, 16);

    auto result = send(sock->s, sendBuffer, 28, 0);
    if (result == SOCKET_ERROR)
    {
        shutdown(sock->s, SD_SEND);
        closesocket(sock->s);
        sock->s = INVALID_SOCKET;

        xiloader::console::output("Failed to send session hash for data to server; disconnecting!");
        return 0;
    }
    memset(sendBuffer, 0, 28);

    while (xiloader::state.isRunning)
    {
        /* Attempt to receive the incoming data.. */
        if (recvfrom(sock->s, recvBuffer, sizeof(recvBuffer), 0, (struct sockaddr*)&client, (int*)&socksize) <= 0)
        {
            /*
            Under some conditions, this recvfrom call would immediately error with a WSAGetLastError value of 0 when no data was waiting.
            This would cause the call to occur over and over, saturating a cpu thread.
            */
            if (WSAGetLastError() == 0)
            {
                Sleep(100);
            }
            continue;
        }

        switch (static_cast<xiloader::LobbyDataRequest>(recvBuffer[0]))
        {
            case xiloader::LobbyDataRequest::AccountId:
                sendBuffer[0] = static_cast<char>(xiloader::LobbyDataReply::AccountId);
                memcpy(sendBuffer + 0x01, &sock->AccountId, 4);
                memcpy(sendBuffer + 0x05, &sock->ServerAddress, 4);
                memcpy(sendBuffer + 12, xiloader::state.sessionHash, 16);

                xiloader::console::output(xiloader::color::warning, "Sending account id..");
                sendSize = 28;
                break;

            case xiloader::LobbyDataRequest::Key:
            case xiloader::LobbyDataRequest::KeyAlternate:
                // The packet starts with LobbyDataReply::Key
                memcpy(sendBuffer, (char*)"\xA2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58\xE0\x5D\xAD\x00\x00\x00\x00", 25);

                xiloader::console::output(xiloader::color::warning, "Sending key..");
                sendSize = 28;
                break;

            case xiloader::LobbyDataRequest::CharacterList:
                xiloader::console::output(xiloader::color::warning, "Receiving character list..");
                for (auto x = 0; x < recvBuffer[1]; x++)
                {
                    xiloader::state.characterList[0x00 + (x * 0x68)] = 1;
                    xiloader::state.characterList[0x02 + (x * 0x68)] = 1;
                    xiloader::state.characterList[0x10 + (x * 0x68)] = (char)x;
                    xiloader::state.characterList[0x11 + (x * 0x68)] = 0x80u;
                    xiloader::state.characterList[0x18 + (x * 0x68)] = 0x20;
                    xiloader::state.characterList[0x28 + (x * 0x68)] = 0x20;

                    memcpy(xiloader::state.characterList + 0x04 + (x * 0x68), recvBuffer + 0x10 * (x + 1) + 0x04, 4); // Character Id
                    memcpy(xiloader::state.characterList + 0x08 + (x * 0x68), recvBuffer + 0x10 * (x + 1), 4);        // Content Id
                }
                sendSize = 0;
                break;
        }

        if (sendSize == 0)
            continue;

        /* Send the response buffer to the server.. */
        auto result = sendto(sock->s, sendBuffer, sendSize, 0, (struct sockaddr*)&client, socksize);
        if (sendSize == 72 || result == SOCKET_ERROR || sendSize == -1)
        {
            shutdown(sock->s, SD_SEND);
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;

            xiloader::console::output("Server connection done; disconnecting!");
            return 0;
        }

        sendSize = 0;
        Sleep(100);
    }

    return 0;
}

/**
 * @brief Starts the data communication between the client and server.
 *
 * @param lpParam   Thread param object.
 *
 * @return Non-important return.
 */
DWORD __stdcall network::FFXiServer(LPVOID lpParam)
{
    /* Attempt to start data communication with the server.. */
    if (CreateThread(NULL, 0, xiloader::network::FFXiDataComm, lpParam, 0, NULL) == NULL)
    {
        xiloader::console::output(xiloader::color::error, "Failed to start the login data thread (error %lu).", GetLastError());
    }
    Sleep(200);

    return 0;
}

}; // namespace xiloader
