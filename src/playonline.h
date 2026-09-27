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
    // The PlayOnline login xiloader performs in place of the viewer, against the server's xi_profile
    namespace playonline
    {
        // One entry of polcore's common function table
        using CommandFunc = void*(...);

        // polcore's common function table, read but never modified
        using CommandTable = CommandFunc* const*;

        // What POLCON_OPEN reads: a connection kind, then five dial-up fields xiloader leaves empty
        struct ConnectionData
        {
            uint32_t kind;
            void*    dialUp[5];
            uint32_t unused[2];
        };

        static_assert(sizeof(ConnectionData) == 0x20, "polcore reads 8 dwords");

        // One profile list load: a table entry starts it and returns a ticket, another polls the ticket
        struct Load
        {
            const char* name;
            int         setup; // returns the ticket
            int         check; // 0 pending, 1 done, negative failed
            int         ticket;
            int         result;
        };

        // Replaces polcore's PlayOnline cipher with a plain copy; the relay encrypts the traffic instead.
        // The cipher is located through its call on the IRC send path.
        // Returns false when that call isn't found.
        auto disableCipher() -> bool;

        // Sets the English friend, group and character-name message texts the viewer normally loads from its StringTable.bin
        void setEnglishMessageTexts(CommandTable table);

        // Logs in to PlayOnline the way the viewer does: POL id and password, IRC session, then the lists FFXiMain expects.
        // A list that fails to load is retried in game.
        // Returns false when the profile server can't be reached; the game can't start without it.
        auto logIn(CommandTable table, uint32_t accountId) -> bool;

        // Keeps the game running when the PlayOnline connection drops, e.g. when xi_profile restarts.
        // FFXiMain's per-frame poll would end the game with POL-0008; the error is hidden, and the session reopens every 15 to 45 seconds and reloads the lists.
        // Rewrites two table entries.
        void keepGameOnDisconnect(CommandFunc** table);
    } // namespace playonline
} // namespace xiloader
