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

namespace xiloader
{

struct AppState
{
    char  sessionHash[16] = {};      // Session hash sent from auth
    bool  firstLogin      = false;   // set to true when --user --pass are both set to allow for autologin
    char* characterList   = nullptr; // Pointer to the character list data being sent from the server.
    bool  isRunning       = false;   // Flag to determine if the network threads should hault.
};

extern Config   config;
extern AppState state;

} // namespace xiloader
