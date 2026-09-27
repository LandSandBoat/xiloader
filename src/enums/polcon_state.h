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
    // POLCON_STEP's states (polcore 0x10044a50, state at 0x10099408); negative values are errors
    enum class PolconState : int32_t
    {
        Init                = 0x00,
        Start               = 0x11, // goes to Connected or ResolvePolcom depending on the open mode
        ResolvePolcom       = 0x12,
        BuildPolcomHost     = 0x13,
        StartPolcomResolve  = 0x14,
        CheckPolcomResolve  = 0x15,
        OpenIrc             = 0x16, // IRC session on 51240
        CheckIrcOpen        = 0x17,
        IrcReady            = 0x18,
        FormatProfileHost   = 0x19, // pp%03d.pol.com
        ResolveProfileHost  = 0x1A,
        SecurityToken       = 0x1B, // profile request 4/7
        CheckSecurityToken  = 0x1C,
        Connected           = 0x1E,
        CloseIrc            = 0x1F, // teardown on the failure path, then 0x20 and Failed
        Failed              = 0x21, // stays here after a failed open
        ChangeMyStatus      = 0x28, // profile request 4/5, open mode 3 only
        CheckChangeMyStatus = 0x29,
    };
} // namespace xiloader
