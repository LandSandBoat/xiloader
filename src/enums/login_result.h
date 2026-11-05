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

enum class LoginResult : int8_t
{
    LoginSuccess          = 0x01,
    LoginError            = 0x02,
    CreateAccountSuccess  = 0x03,
    CreateAccountError    = 0x04,
    ChangePasswordSuccess = 0x06,
    ChangePasswordError   = 0x07,
    AlreadyLoggedIn       = 0x0A,
    VersionMismatch       = 0x0B,
    CreateTotpSuccess     = 0x10,
    VerifyTotpSuccess     = 0x11,
    RemoveTotpSuccess     = 0x12,
    TrustTokenInvalid     = 0x13,
};

} // namespace xiloader
