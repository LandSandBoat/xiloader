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

// Same datatype as in xi_connect
enum class LoginCommand : int8_t
{
    None                   = 0x00,
    Login                  = 0x10,
    CreateAccount          = 0x20,
    ChangePassword         = 0x30,
    CreateTotp             = 0x31,
    RemoveTotp             = 0x32,
    RegenerateRecoveryCode = 0x33,
    VerifyTotp             = 0x34, // also enables OTP
};

} // namespace xiloader
