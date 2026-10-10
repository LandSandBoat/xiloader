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

#include "session.h"

#include "enums/login_outcome.h"

#include <expected>

namespace xiloader
{

class AuthConnection;
struct Config;

} // namespace xiloader

namespace xiloader::login
{

// Runs the login menu against xi_connect until an account is logged in.
// Also handles creating accounts, changing passwords and the 2FA options.
// The menus overwrite the credentials in config.
// The error is Quit or ConnectionLost.
auto run(AuthConnection& connection, Config& config) -> std::expected<Session, LoginOutcome>;

} // namespace xiloader::login
