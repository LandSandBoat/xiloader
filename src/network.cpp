/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

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

#include "helpers.h"
#include "menus.h"
#include "network.h"
#include <iphlpapi.h>
#include <vector>

#include "helpers.h"
#include "command_handler.h"

/* Externals */
namespace globals
{
    extern std::string            g_ServerAddress;
    extern std::string            g_Username;
    extern std::string            g_Password;
    extern std::string            g_OtpCode;
    extern char                   g_SessionHash[16];
    extern std::string            g_Email;
    extern std::array<uint8_t, 3> g_VersionNumber;
    extern uint16_t               g_ServerPort;
    extern uint16_t               g_LoginDataPort;
    extern uint16_t               g_LoginViewPort;
    extern uint16_t               g_LoginAuthPort;
    extern char*                  g_CharacterList;
    extern bool                   g_IsRunning;
    extern bool                   g_FirstLogin;
}

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
};

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
        if (getaddrinfo(globals::g_ServerAddress.c_str(), port, &hints, &addr))
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
        sock->ServerAddress = inet_addr(globals::g_ServerAddress.c_str());

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
        if (getaddrinfo(globals::g_ServerAddress.c_str(), port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain remote server information.");
            return 0;
        }

        int ret = 0;

        ret = mbedtls_net_connect(&sslState::server_fd, globals::g_ServerAddress.c_str(), port, MBEDTLS_NET_PROTO_TCP);
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
            xiloader::console::output(xiloader::color::info, "Remote server (%s) certificate is valid.", globals::g_ServerAddress.c_str());
        }

        sockaddr clientAddr  = {};
        int      sockaddrLen = sizeof(clientAddr);
        getsockname(static_cast<SOCKET>(sslState::server_fd.fd), &clientAddr, &sockaddrLen);

        struct sockaddr_in* their_inaddr_ptr = (struct sockaddr_in*)&clientAddr;

        sock->LocalAddress  = their_inaddr_ptr->sin_addr.S_un.S_addr;
        sock->ServerAddress = inet_addr(globals::g_ServerAddress.c_str());

        unsigned char recvBuffer[4096] = {};

        mbedtls_ssl_conf_read_timeout(&sslState::conf, 1000);

        return 1;
    }

    /**
     * @brief Creates a listening server on the given port and protocol.
     *
     * @param sock      The socket object to bind to.
     * @param protocol  The protocol to use on the new listening socket.
     * @param port      The port to bind to listen on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateListenServer(SOCKET* sock, int protocol, const char* port)
    {
        sockaddr_in sin     = {};
        sin.sin_family      = AF_INET;
        sin.sin_addr.s_addr = inet_addr("127.0.0.1");
        sin.sin_port        = htons(51220);

        /* Create the listening socket.. */
        *sock = socket(AF_INET, protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM, protocol);
        if (*sock == INVALID_SOCKET)
        {
            xiloader::console::output(xiloader::color::error, "Failed to create listening socket.");

            return false;
        }

        BOOL enable = 1;

        /* Set socket option on internal server to allow sharing the port for multibox users */
        if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(BOOL)) == SOCKET_ERROR)
        {
            xiloader::console::output(xiloader::color::error, "Failed to set reusable address option on socket. %d", WSAGetLastError());
            return false;
        }

        /* Bind to the local address.. */
        if (bind(*sock, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) == SOCKET_ERROR)
        {
            xiloader::console::output(xiloader::color::error, "Failed to bind to listening socket. %d", WSAGetLastError());

            closesocket(*sock);
            *sock = INVALID_SOCKET;
            return false;
        }

        /* Attempt to listen for clients if we are using TCP.. */
        if (protocol == IPPROTO_TCP)
        {
            if (listen(*sock, SOMAXCONN) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to listen for connections, %d", WSAGetLastError());

                closesocket(*sock);
                *sock = INVALID_SOCKET;
                return false;
            }
        }

        return true;
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

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(host, "1000", &hints, &info))
            return false;

        *lpOutput = ((struct sockaddr_in*)info->ai_addr)->sin_addr.S_un.S_addr;

        freeaddrinfo(info);
        return true;
    }

    /**
     * @brief Verifies the players login information; also handles creating new accounts.
     *
     * @param sock      The datasocket object with the connection socket.
     *
     * @return True on success, false otherwise.
     */
    bool network::VerifyAccount(datasocket* sock)
    {
        unsigned char recvBuffer[8192] = { 0 };
        unsigned char sendBuffer[8192] = { 0 };
        std::string new_password       = "";

        int8_t command = 0; // Same datatype as in xi_connect

        /* Create connection if required.. */

        // TODO: fix this check for TLS
        /* if (sock->s == NULL || sock->s == INVALID_SOCKET)
        {
            if (!xiloader::network::CreateConnection(sock, g_LoginAuthPort.c_str()))
                return false;
        }*/

        /* Determine if we should auto-login.. */
        bool bUseAutoLogin = !globals::g_Username.empty() && !globals::g_Password.empty() && globals::g_FirstLogin;
        if (bUseAutoLogin)
            xiloader::console::output(xiloader::color::lightgreen, "Autologin activated!");

        if (!bUseAutoLogin)
        {
            auto selected = MenuSelection::None;

            // Check for None, because the 2FA submenu can select None and needs to replay the main menu.
            // Any other option is a "real" selection
            while (selected == MenuSelection::None)
            {
                xiloader::console::output("What would you like to do?");
                selected = menus::mainMenu();

                if (selected == MenuSelection::TwoFactorSubmenu)
                {
                    xiloader::console::output("What would you like to do?");
                    selected = menus::twoFactorSubMenu();
                }
            }

            globals::g_Username = "";
            globals::g_Password = "";
            globals::g_OtpCode  = "";

            switch (selected)
            {
                case MenuSelection::Login:
                {
                    menus::enterCredentialsWithOTP(globals::g_Username, globals::g_Password, globals::g_OtpCode);

                    command = 0x10; // login
                    break;
                }
                case MenuSelection::CreateAccount:
                {
                    xiloader::console::output("Please enter your desired login information.");
                    xiloader::console::output("Username (3-15 characters)");
                    xiloader::console::output("Password (6-32 characters)");

                    while (!menus::createNewAccount(globals::g_Username, globals::g_Password))
                    {
                        xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
                    }

                    command = 0x20; // create account
                    break;
                }

                case MenuSelection::ChangePassword:
                {
                    xiloader::console::output("Before resetting your password, first verify your account details.");
                    xiloader::console::output("Please enter your login information. The OTP code is only necessary if you have one registered.");

                    menus::enterCredentialsWithOTP(globals::g_Username, globals::g_Password, globals::g_OtpCode);

                    xiloader::console::output("Enter new password (6-32 characters): ");

                    while (!menus::confirmNewPassword(new_password))
                    {
                        xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
                    }

                    command = 0x30; // change password
                    break;
                }
                case MenuSelection::RegisterTwoFactorOTP:
                {
                    menus::enterCredentialsNoOTP(globals::g_Username, globals::g_Password);

                    command = 0x31; // create TOTP
                    break;
                }

                case MenuSelection::RemoveTwoFactorOTP:
                {
                    xiloader::console::output("Please enter your login information; your OTP code may be substituted for the recovery code");
                    menus::enterCredentialsWithOTP(globals::g_Username, globals::g_Password, globals::g_OtpCode);

                    command = 0x32;
                    break;
                }

                case MenuSelection::RegenerateTwoFactorRemovalCode:
                {
                    xiloader::console::output("Please enter your login information; your OTP code may be substituted for the recovery code");
                    menus::enterCredentialsWithOTP(globals::g_Username, globals::g_Password, globals::g_OtpCode);

                    command = 0x33; // Regenerate recovery code
                    break;
                }
                case MenuSelection::ValidateTwoFactorOTP: // also enables OTP
                {
                    menus::enterCredentialsWithOTP(globals::g_Username, globals::g_Password, globals::g_OtpCode);

                    command = 0x34;
                    break;
                }
                case MenuSelection::Exit:
                {
                    exit(0); // Bit ugly, can't really exit properly with the current code flow
                    break;
                }

                default:
                {
                    xiloader::console::output("Invalid menu selection");
                    return 0;
                }
            }
        }
        else
        {
            /* User has auto-login enabled.. */
            command               = 0x10;
            globals::g_FirstLogin = false;
        }

        json login_json;
        login_json["username"]     = globals::g_Username;
        login_json["password"]     = globals::g_Password;
        login_json["otp"]          = globals::g_OtpCode;
        login_json["new_password"] = new_password;
        login_json["version"]      = globals::g_VersionNumber;
        login_json["command"]      = command;

        std::string str          = login_json.dump();
        const char* strBuffer    = str.c_str();
        size_t      strBufferLen = strlen(strBuffer);

        /* Send info to server and obtain response.. */
        mbedtls_ssl_write(&sslState::ssl, reinterpret_cast<const unsigned char*>(strBuffer), strBufferLen);

        std::memset(recvBuffer, 0, sizeof(recvBuffer));

        if (mbedtls_ssl_read(&sslState::ssl, recvBuffer, sizeof(recvBuffer)) == MBEDTLS_ERR_SSL_TIMEOUT)
        {
            xiloader::console::output(xiloader::color::error, "Remote failed to reply within the timeout, exiting...");
            exit(2);
        }

        json login_reply_json = json::parse(recvBuffer, nullptr, false);

        if (login_reply_json.is_discarded())
        {
            xiloader::console::output(xiloader::color::error, "Bad json reply from remote");
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return false;
        }

        bool retval = false;

        std::string errorMessage = jsonGet<std::string>(login_reply_json, "error_message").value_or({}); // {} = empty string

        if (errorMessage.empty())
        {
            auto maybeCommand = jsonGet<int8_t>(login_reply_json, "result");
            if (maybeCommand.has_value())
            {
                command = maybeCommand.value();
            }
            else
            {
                xiloader::console::output(xiloader::color::error, "xi_connect didn't send a proper reply command");
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;
            }

            retval = handleLoginCommand(command, login_reply_json, sock->AccountId, sock->s);
        }
        else
        {
            xiloader::console::output(xiloader::color::error, "Error from remote:");

            xiloader::console::printMultiLine(errorMessage, "\n", xiloader::color::error);
            return false;
        }

        // Socket is already closed if handleLoginCommand is true
        if (!retval)
        {
            closesocket(sock->s);
        }

        sock->s = INVALID_SOCKET;
        return retval;
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

        int sendSize = 0;
        char recvBuffer[4096] = { 0 };
        char sendBuffer[4096] = { 0 };

        struct sockaddr_in client;
        unsigned int       socksize = sizeof(client);

        // send session hash
        sendBuffer[0] = 0xFE;
        memcpy(sendBuffer + 12, globals::g_SessionHash, 16);

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

        while (globals::g_IsRunning)
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

            switch (recvBuffer[0])
            {
            case 0x0001:
                sendBuffer[0] = 0xA1u;
                memcpy(sendBuffer + 0x01, &sock->AccountId, 4);
                memcpy(sendBuffer + 0x05, &sock->ServerAddress, 4);
                memcpy(sendBuffer + 12, globals::g_SessionHash, 16);

                xiloader::console::output(xiloader::color::warning, "Sending account id..");
                sendSize = 28;
                break;

            case 0x0002:
            case 0x0015:
                memcpy(sendBuffer, (char*)"\xA2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58\xE0\x5D\xAD\x00\x00\x00\x00", 25);

                xiloader::console::output(xiloader::color::warning, "Sending key..");
                sendSize = 28;
                break;

            case 0x0003:
                xiloader::console::output(xiloader::color::warning, "Receiving character list..");
                for (auto x = 0; x < recvBuffer[1]; x++)
                {
                    globals::g_CharacterList[0x00 + (x * 0x68)] = 1;
                    globals::g_CharacterList[0x02 + (x * 0x68)] = 1;
                    globals::g_CharacterList[0x10 + (x * 0x68)] = (char)x;
                    globals::g_CharacterList[0x11 + (x * 0x68)] = 0x80u;
                    globals::g_CharacterList[0x18 + (x * 0x68)] = 0x20;
                    globals::g_CharacterList[0x28 + (x * 0x68)] = 0x20;

                    memcpy(globals::g_CharacterList + 0x04 + (x * 0x68), recvBuffer + 0x10 * (x + 1) + 0x04, 4); // Character Id
                    memcpy(globals::g_CharacterList + 0x08 + (x * 0x68), recvBuffer + 0x10 * (x + 1), 4);        // Content Id
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
     * @brief Data communication between the local client and the lobby server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::PolDataComm(LPVOID lpParam)
    {
        SOCKET client = *(SOCKET*)lpParam;
        unsigned char recvBuffer[1024] = { 0 };
        int result = 0, x = 0;
        time_t t = 0;
        bool bIsNewChar = false;

        do
        {
            /* Attempt to receive incoming data.. */
            result = recv(client, (char*)recvBuffer, sizeof(recvBuffer), 0);
            if (result <= 0)
            {
                xiloader::console::output(xiloader::color::error, "Client recv failed: %d", WSAGetLastError());
                break;
            }

            char temp = recvBuffer[0x04];
            memset(recvBuffer, 0x00, 32);

            switch (x)
            {
            case 0:
                recvBuffer[0] = 0x81;
                t = time(NULL);
                memcpy(recvBuffer + 0x14, &t, 4);
                result = 24;
                break;

            case 1:
                if (temp != 0x28)
                    bIsNewChar = true;
                recvBuffer[0x00] = 0x28;
                recvBuffer[0x04] = 0x20;
                recvBuffer[0x08] = 0x01;
                recvBuffer[0x0B] = 0x7F;
                result = bIsNewChar ? 144 : 24;
                if (bIsNewChar) bIsNewChar = false;
                break;
            }

            /* Echo back the buffer to the server.. */
            if (send(client, (char*)recvBuffer, result, 0) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Client send failed: %d", WSAGetLastError());
                break;
            }

            /* Increase the current packet count.. */
            x++;
            if (x == 3)
                break;

        } while (result > 0);

        /* Shutdown the client socket.. */
        if (shutdown(client, SD_SEND) == SOCKET_ERROR)
            xiloader::console::output(xiloader::color::error, "Client shutdown failed: %d", WSAGetLastError());
        closesocket(client);

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
        CreateThread(NULL, 0, xiloader::network::FFXiDataComm, lpParam, 0, NULL);
        Sleep(200);

        return 0;
    }

    /**
     * @brief Starts the local listen server to lobby server communications.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::PolServer(LPVOID lpParam)
    {
        UNREFERENCED_PARAMETER(lpParam);

        SOCKET sock = *reinterpret_cast<SOCKET*>(lpParam);
        SOCKET client;

        while (globals::g_IsRunning)
        {
            /* Attempt to accept incoming connections.. */
            if ((client = accept(sock, NULL, NULL)) == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Accept failed: %d", WSAGetLastError());

                closesocket(sock);
                return 1;
            }

            /* Start data communication for this client.. */
            CreateThread(NULL, 0, xiloader::network::PolDataComm, &client, 0, NULL);
        }

        closesocket(sock);
        return 0;
    }

}; // namespace xiloader
