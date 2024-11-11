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
#include "network.h"
#include <iphlpapi.h>
#include <vector>

/* Externals */
namespace globals
{
    extern std::string g_ServerAddress;
    extern std::string g_Username;
    extern std::string g_Password;
    extern char        g_SessionHash[16];
    extern std::string g_Email;
    extern std::string g_VersionNumber;
    extern std::string g_ServerPort;
    extern std::string g_LoginDataPort;
    extern std::string g_LoginViewPort;
    extern std::string g_LoginAuthPort;
    extern char*       g_CharacterList;
    extern bool        g_IsRunning;
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

        if ((mbedtls_net_connect(&sslState::server_fd, globals::g_ServerAddress.c_str(), port, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            xiloader::console::output(xiloader::color::error, "mbedtls_net_connect failed.");
            return 0;
        }

        if (mbedtls_ssl_config_defaults(&sslState::conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
        {
            xiloader::console::output(xiloader::color::error, "mbedtls_ssl_config_defaults failed.");
            return 0;
        }

        // MBEDTLS_SSL_VERIFY_OPTIONAL provides warnings, but doesn't stop connections.
        mbedtls_ssl_conf_authmode(&sslState::conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(&sslState::conf, sslState::ca_chain.get(), NULL);
        mbedtls_ssl_conf_rng(&sslState::conf, mbedtls_ctr_drbg_random, &sslState::ctr_drbg);

        int ret = 0;

        if ((ret = mbedtls_ssl_setup(&sslState::ssl, &sslState::conf)) != 0)
        {
            xiloader::console::output(xiloader::color::error, "mbedtls_ssl_setup returned %d", ret);
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
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
        hints.ai_protocol = protocol;
        hints.ai_flags = AI_PASSIVE;

        /* Attempt to resolve the local address.. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(NULL, port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain local address information.");
            return false;
        }

        /* Create the listening socket.. */
        *sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (*sock == INVALID_SOCKET)
        {
            xiloader::console::output(xiloader::color::error, "Failed to create listening socket.");

            freeaddrinfo(addr);
            return false;
        }

        /* Set socket option on internal server to allow sharing the port for multibox users */
        if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char*)(&[] { return TRUE; }), sizeof(BOOL)) == SOCKET_ERROR)
        {
            xiloader::console::output(xiloader::color::error, "Failed to set reusable address option on socket. %d", WSAGetLastError());

            freeaddrinfo(addr);
            return false;
        }

        /* Bind to the local address.. */
        if (bind(*sock, addr->ai_addr, (int)addr->ai_addrlen) == SOCKET_ERROR)
        {
            xiloader::console::output(xiloader::color::error, "Failed to bind to listening socket.");

            freeaddrinfo(addr);
            closesocket(*sock);
            *sock = INVALID_SOCKET;
            return false;
        }

        freeaddrinfo(addr);

        /* Attempt to listen for clients if we are using TCP.. */
        if (protocol == IPPROTO_TCP)
        {
            if (listen(*sock, SOMAXCONN) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to listen for connections.");

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
        static bool bFirstLogin = true;

        unsigned char recvBuffer[1024] = { 0 };
        unsigned char sendBuffer[1024] = { 0 };
        std::string new_password       = "";
        /* Create connection if required.. */

        // TODO: fix this check for TLS
        /* if (sock->s == NULL || sock->s == INVALID_SOCKET)
        {
            if (!xiloader::network::CreateConnection(sock, g_LoginAuthPort.c_str()))
                return false;
        }*/

        /* Determine if we should auto-login.. */
        bool bUseAutoLogin = !globals::g_Username.empty() && !globals::g_Password.empty() && bFirstLogin;
        if (bUseAutoLogin)
            xiloader::console::output(xiloader::color::lightgreen, "Autologin activated!");

        // TODO: kill all labels and gotos
        if (!bUseAutoLogin)
        {
            xiloader::console::output("==========================================================");
            xiloader::console::output("What would you like to do?");
            xiloader::console::output("   1.) Login");
            xiloader::console::output("   2.) Create New Account");
            xiloader::console::output("   3.) Change Account Password");
            xiloader::console::output("==========================================================");
            printf("\nEnter a selection: ");

            std::string input;
            std::cin >> input;
            std::cout << std::endl;

            /* User wants to log into an existing account or modify an existing account's password. */
            if (input == "1" || input == "3")
            {
                if (input == "3")
                    xiloader::console::output("Before resetting your password, first verify your account details.");
                xiloader::console::output("Please enter your login information.");
                std::cout << "\nUsername: ";
                std::cin >> globals::g_Username;
                std::cout << "Password: ";
                globals::g_Password.clear();

                /* Read in each char and instead of displaying it. display a "*" */
                char ch;
                while ((ch = static_cast<char>(_getch())) != '\r')
                {
                    if (ch == '\0')
                        continue;
                    else if (ch == '\b')
                    {
                        if (globals::g_Password.size())
                        {
                            globals::g_Password.pop_back();
                            std::cout << "\b \b";
                        }
                    }
                    else
                    {
                        globals::g_Password.push_back(ch);
                        std::cout << '*';
                    }
                }
                std::cout << std::endl;

                char event_code = (input == "1") ? 0x10 : 0x30;

                if (input == "3")
                {
                    std::string confirmed_password = "";
                    do
                    {
                        std::cout << "Enter new password (6-32 characters): ";
                        confirmed_password = "";
                        new_password       = "";
                        std::cin >> new_password;
                        std::cout << "Repeat Password           : ";
                        std::cin >> confirmed_password;
                        std::cout << std::endl;

                        if (new_password != confirmed_password)
                        {
                            xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
                        }
                    } while (new_password != confirmed_password);
                    new_password = confirmed_password;
                }
                sendBuffer[0x39] = event_code;
            }
            /* User wants to create a new account.. */
            else if (input == "2")
            {
            create_account:
                xiloader::console::output("Please enter your desired login information.");
                std::cout << "\nUsername (3-15 characters): ";
                std::cin >> globals::g_Username;
                std::cout << "Password (6-32 characters): ";
                globals::g_Password.clear();
                std::cin >> globals::g_Password;
                std::cout << "Repeat Password           : ";
                std::cin >> input;
                std::cout << std::endl;

                // TODO: warn if username/password is too long

                if (input != globals::g_Password)
                {
                    xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
                    goto create_account;
                }

                sendBuffer[0x39] = 0x20;
            }

            std::cout << std::endl;
        }
        else
        {
            /* User has auto-login enabled.. */
            sendBuffer[0x39] = 0x10;
            bFirstLogin = false;
        }

        sendBuffer[0] = 0xFF; // Magic for new xiloader bits

        sendBuffer[1] = 0x00; // Feature flags, none used yet.
        sendBuffer[2] = 0x00;
        sendBuffer[3] = 0x00;
        sendBuffer[4] = 0x00;
        sendBuffer[5] = 0x00;
        sendBuffer[6] = 0x00;
        sendBuffer[7] = 0x00;
        sendBuffer[8] = 0x00;

        /* Copy username and password into buffer.. */
        memcpy(sendBuffer + 0x09, globals::g_Username.c_str(), globals::g_Username.length());
        memcpy(sendBuffer + 0x19, globals::g_Password.c_str(), globals::g_Password.length());

        /* Copy changed password into buffer */
        memcpy(sendBuffer + 0x40, new_password.c_str(), 32);

        // 17 byte wide operator specific space starting at 0x50 // This region will be used for anything server operators may install into custom launchers.

        /* Copy version number into buffer */
        memcpy(sendBuffer + 0x61, globals::g_VersionNumber.c_str(), 5);

        /* Send info to server and obtain response.. */
        mbedtls_ssl_write(&sslState::ssl, reinterpret_cast<const unsigned char*>(sendBuffer), 102);
        mbedtls_ssl_read(&sslState::ssl, recvBuffer, 21);

        /* Handle the obtained result.. */
        switch (recvBuffer[0])
        {
            case 0x0001: // Success (Login)
            {
                xiloader::console::output(xiloader::color::success, "Successfully logged in as %s!", globals::g_Username.c_str());

                sock->AccountId = ref<UINT32>(recvBuffer, 1);
                std::memcpy(&globals::g_SessionHash, recvBuffer + 5, sizeof(globals::g_SessionHash));

                shutdown(sock->s, SD_BOTH);
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return true;
            }
            case 0x0002: // Error (Login)
            {
                xiloader::console::output(xiloader::color::error, "Failed to login. Invalid username or password.");
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;
            }
            case 0x0003: // Success (Create Account)
            {
                xiloader::console::output(xiloader::color::success, "Account successfully created!");
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;
            }
            case 0x0004: // Error (Create Account)
            {
                xiloader::console::output(xiloader::color::error, "Failed to create the new account. Username already taken.");
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;
            }
            case 0x0006: // Success (Changed Password)
            {
                xiloader::console::output(xiloader::color::success, "Password updated successfully!");
                std::cout << std::endl;
                globals::g_Password.clear();
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;
            }
            case 0x0007: // Error (Changed Password)
            {
                xiloader::console::output(xiloader::color::error, "Failed to change password.");
                std::cout << std::endl;
                globals::g_Password.clear();
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;
            }

            // Commands 0x0008 through 0x0008 are currently unused

            case 0x000A:
            {
                xiloader::console::output(xiloader::color::error, "Failed to login. Account already logged in.");
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;
            }
            case 0x000B:
            {
                xiloader::console::output(xiloader::color::error, "Failed to login. Expected xiloader version mismatch; check with your provider.");
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;
            }
        }

        /* We should not get here.. */
        closesocket(sock->s);
        sock->s = INVALID_SOCKET;
        return false;
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
        /* Attempt to create connection to the server.. */
        if (!xiloader::network::CreateConnection((xiloader::datasocket*)lpParam, globals::g_LoginDataPort.c_str()))
            return 1;

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

        SOCKET sock, client;

        /* Attempt to create listening server.. */
        if (!xiloader::network::CreateListenServer(&sock, IPPROTO_TCP, globals::g_ServerPort.c_str()))
            return 1;

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
