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

#include "config.h"
#include "login/session.h"

namespace xiloader
{

// The socket detours, attached for as long as this lives
struct SocketHooks
{
    bool attached = false;

    // config has to outlive the hooks
    explicit SocketHooks(const Config& config);
    ~SocketHooks();

    SocketHooks(const SocketHooks&)            = delete;
    SocketHooks& operator=(const SocketHooks&) = delete;
    SocketHooks(SocketHooks&&)                 = delete;
    SocketHooks& operator=(SocketHooks&&)      = delete;

    // Stamped into the lobby commands the client sends from then on
    void useSession(const Session& session);
};

} // namespace xiloader
