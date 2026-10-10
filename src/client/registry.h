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

/**
 * @brief Obtains the PlayOnline registry key.
 *  "SOFTWARE\PlayOnlineXX"
 *
 * @param lang      The language id the loader was started with.
 *
 * @return registry pathname.
 */
const char* GetPlayOnlineKey(xiloader::Language language);

/**
 * @brief Obtains the PlayOnline language id from the system registry.
 *
 * @param lang      The language id the loader was started with.
 *
 * @return The language id from the registry, 1 otherwise.
 */
int GetPlayOnlineLanguage(xiloader::Language language);

/**
 * @brief Obtains the PlayOnlineViewer folder from the system registry.
 *  "C:\Program Files\PlayOnline\PlayOnlineViewer"
 *
 * @param lang      The language id the loader was started with.
 *
 * @return installation folder path.
 */
const char* GetPlayOnlineInstallFolder(xiloader::Language language);

} // namespace xiloader::registry
