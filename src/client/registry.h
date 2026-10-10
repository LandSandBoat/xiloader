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

#include "enums/pol_language.h"

namespace xiloader::registry
{

// Obtains the PlayOnline registry key.
//  "SOFTWARE\PlayOnlineXX"
// Returns registry pathname.
auto GetPlayOnlineKey(xiloader::Language language) -> const char*;

// Obtains the PlayOnline language id from the system registry.
// Returns the language id from the registry, 1 otherwise.
auto GetPlayOnlineLanguage(xiloader::Language language) -> int;

// Obtains the PlayOnlineViewer folder from the system registry.
//  "C:\Program Files\PlayOnline\PlayOnlineViewer"
// Returns installation folder path.
auto GetPlayOnlineInstallFolder(xiloader::Language language) -> const char*;

} // namespace xiloader::registry
