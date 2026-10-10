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

#include <cstdint>

namespace xiloader
{

class AuthConnection;

}

namespace xiloader::login
{

// Runs the login menu against xi_connect until an account is logged in.
// Also handles creating accounts, changing passwords and the 2FA options.
// Returns false when the user quits or the connection is lost.
auto run(AuthConnection& connection, uint32_t& accountId) -> bool;

} // namespace xiloader::login
