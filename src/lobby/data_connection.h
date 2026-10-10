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

#include <winsock2.h>

#include "login/session.h"

#include <cstdint>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace xiloader
{

// The connection to the login server's data port.
// A thread answers the server's requests on it and copies the character list into polcore.
class LobbyDataConnection
{
public:
    LobbyDataConnection() = default;
    ~LobbyDataConnection();

    LobbyDataConnection(const LobbyDataConnection&)            = delete;
    LobbyDataConnection& operator=(const LobbyDataConnection&) = delete;

    // Returns false when the server can't be reached
    auto connect(const std::string& server, uint16_t port) -> bool;

    // Sends the session hash and starts answering the server
    void start(const Session& session);

    // Where polcore keeps its character list. A list that arrived before this is applied now.
    void setCharacterList(char* list);

private:
    void run(std::stop_token stop, Session session);

    SOCKET socket        = INVALID_SOCKET;
    ULONG  serverAddress = INADDR_NONE;

    // The list is written from the thread, or from setCharacterList when it arrived first
    std::mutex        listMutex;
    char*             characterList = nullptr;
    std::vector<char> heldList;

    std::jthread thread;
};

} // namespace xiloader
