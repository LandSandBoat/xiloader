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

#include "socket_hooks.h"

#include <winsock2.h>

#include <windows.h>

#include "detours/detours.h"

#include "client/polrelay.h"
#include "console.h"

#include "enums/lobby_command.h"

#include <algorithm>
#include <intrin.h>
#include <string_view>

namespace
{

// The detours can't take arguments, so what they need is kept here
const xiloader::Config* config          = nullptr;
char                    sessionHash[16] = {};

} // namespace

/**
 * @brief Detour function definitions.
 */
extern "C"
{
    hostent*(WINAPI __stdcall* Real_gethostbyname)(const char* name)       = gethostbyname;
    int(WINAPI* Real_send)(SOCKET s, const char* buf, int len, int flags)  = send;
    int(WINAPI* Real_recv)(SOCKET s, char* buf, int len, int flags)        = recv;
    int(WINAPI* Real_connect)(SOCKET s, const sockaddr* name, int namelen) = connect;
}

/**
 * @brief gethostbyname detour callback.
 *
 * @param name The hostname to obtain information of.
 *
 * @return Hostname information object.
 */
hostent* __stdcall Mine_gethostbyname(const char* name)
{
    xiloader::console::output(xiloader::color::debug, "Resolving host: %s", name);

    if (!strcmp("ffxi00.pol.com", name))
    {
        return Real_gethostbyname(config->serverAddress.c_str());
    }

    // PlayOnline profile and IRC hosts (friend list and presence) go through the local TLS relay
    constexpr std::string_view kPlayOnlineHosts[] = { "pp000.pol.com", "ci000.pol.com", "gm000.pol.com", "gd000.pol.com" };
    if (std::ranges::find(kPlayOnlineHosts, std::string_view(name)) != std::end(kPlayOnlineHosts))
    {
        return Real_gethostbyname(xiloader::polrelay::address().c_str());
    }

    return Real_gethostbyname(name);
}

// This function's purpose is to identify a command byte and identify if it is meant for the lobby dataport or not.
// This way, we know we want to send.
static bool isLobbyCommand(const char* buffer, SOCKET socket)
{
    struct sockaddr_in sin;
    int                addrlen = sizeof(sin);

    getpeername(socket, reinterpret_cast<struct sockaddr*>(&sin), &addrlen);

    auto port = ntohs(sin.sin_port);

    if (port != config->loginDataPort && port != config->loginViewPort)
    {
        return false;
    }

    switch (static_cast<xiloader::LobbyCommand>(buffer[8]))
    {
        case xiloader::LobbyCommand::SelectCharacter:
        case xiloader::LobbyCommand::DeleteCharacter:
        case xiloader::LobbyCommand::CharacterList:
        case xiloader::LobbyCommand::CharacterCreated:
        case xiloader::LobbyCommand::CreateCharacter:
        case xiloader::LobbyCommand::ServerName:
        case xiloader::LobbyCommand::Version:
        case xiloader::LobbyCommand::RenameCharacter:
        case xiloader::LobbyCommand::MoveGmCharacter:
            break;
        default:
            return false;
    }

    // Check for magic numbers (XIFF command)
    return buffer[4] == 0x49 && buffer[5] == 0x58 && buffer[6] == 0x46 && buffer[7] == 0x46;
}

/**
 * @brief send detour callback. https://man7.org/linux/man-pages/man2/send.2.html
 */
int WINAPI Mine_send(SOCKET s, const char* buf, int len, int flags)
{
    const auto ret = _ReturnAddress();
    std::ignore    = ret;

    // check for lobby specific commands
    if (isLobbyCommand(buf, s))
    {
        // always send server provided session hash in packets with XIFF commands and is a lobby command
        std::memcpy((char*)buf + 12, sessionHash, 16);
    }

    return Real_send(s, buf, len, flags);
}

/**
 * @brief recv detour callback. https://man7.org/linux/man-pages/man2/recv.2.html
 */
int WINAPI Mine_recv(SOCKET s, char* buf, int len, int flags)
{
    const auto ret = _ReturnAddress();
    std::ignore    = ret;

    // xiloader::console::output(xiloader::color::lightblue, "recv %i", len);
    return Real_recv(s, buf, len, flags);
}

/**
 * @brief connect detour callback. https://man7.org/linux/man-pages/man2/connect.2.html
 */
int WINAPI Mine_connect(SOCKET s, const sockaddr* name, int namelen)
{
    // polcore's PlayOnline connections go to this process's relay ports
    if (name != nullptr && namelen >= static_cast<int>(sizeof(sockaddr_in)))
    {
        auto destination = *reinterpret_cast<const sockaddr_in*>(name);
        if (xiloader::polrelay::redirect(destination))
        {
            return Real_connect(s, reinterpret_cast<const sockaddr*>(&destination), sizeof(destination));
        }
    }

    int ret = Real_connect(s, name, namelen);

    return ret;
}

xiloader::SocketHooks::SocketHooks(const Config& config)
{
    ::config = &config;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourAttach(&(PVOID&)Real_send, Mine_send);
    DetourAttach(&(PVOID&)Real_recv, Mine_recv);
    DetourAttach(&(PVOID&)Real_connect, Mine_connect);
    attached = DetourTransactionCommit() == NO_ERROR;
}

xiloader::SocketHooks::~SocketHooks()
{
    if (!attached)
    {
        return;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourDetach(&(PVOID&)Real_send, Mine_send);
    DetourDetach(&(PVOID&)Real_recv, Mine_recv);
    DetourDetach(&(PVOID&)Real_connect, Mine_connect);
    DetourTransactionCommit();
}

void xiloader::SocketHooks::useSession(const Session& session)
{
    std::memcpy(sessionHash, session.hash, sizeof(sessionHash));
}
