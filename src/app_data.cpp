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

#include "app_data.h"

#include <windows.h>

namespace xiloader
{

auto appDataFolder() -> std::optional<std::filesystem::path>
{
    char       appdata[MAX_PATH] = {};
    const auto length            = GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
    if (length == 0 || length >= sizeof(appdata))
    {
        return std::nullopt;
    }

    auto            folder = std::filesystem::path(appdata) / "xiloader";
    std::error_code error;
    std::filesystem::create_directories(folder, error);
    if (error)
    {
        return std::nullopt;
    }

    return folder;
}

auto appDataFolder(const char* const name) -> std::optional<std::filesystem::path>
{
    const auto parent = appDataFolder();
    if (!parent)
    {
        return std::nullopt;
    }

    auto            folder = *parent / name;
    std::error_code error;
    std::filesystem::create_directories(folder, error);
    if (error)
    {
        return std::nullopt;
    }

    return folder;
}

} // namespace xiloader
