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

#include <cstddef>
#include <cstdint>
#include <utility>

namespace xiloader
{

// Entries of polcore's common function table
enum class PolFunction : uint16_t
{
    InetMutex     = 0x032F,
    RegistryLang  = 0x03C5,
    FfxiLang      = 0x01A4,
    RegistryKey   = 0x016F,
    InstallFolder = 0x007D,

    // PlayOnline login, as the viewer performs it
    PolconOpen        = 0x032E, // (type, connection data) opens the PlayOnline connection
    PolconStep        = 0x032F, // advances the connect state machine; 0x1E once connected (same entry as InetMutex)
    PolconIdle        = 0x0332, // lets polcore process pending network events
    SetPolid          = 0x0353,
    SetPassword       = 0x0354,
    SetPolcomHost     = 0x0355,
    EncodePolid       = 0x0356,
    EncodePassword    = 0x0358, // (out[17], password)
    FormatPolid       = 0x0161, // (low, high, out[8]) unmasks a POL id and writes its 8 digits, without a terminator
    MaskPolid         = 0x0163, // (low, high) masks a POL id with the session key, returned in edx:eax
    EncodeHost        = 0x0364,
    SetUserSlot       = 0x0366, // picks pub\homeNN for local message copies
    FileInit          = 0x03A4, // starts the file layer the game saves messages through
    MessageNotices    = 0x0408, // (1) turns on message notices
    SetEventHandler   = 0x0120, // (handler) sets the handler PlayOnline events such as new messages go to; FFXiMain installs its own
    NoticeHandler     = 0x014E, // polcore's IRC notice handler, slot 1 of the polcon handler block (read, not called)
    PolconHandler3    = 0x0191, // polcore's default for slot 3 of the polcon handler block (read, not called)
    PolconSetHandlers = 0x0367, // (six handlers) replaces the polcon handler block that each IRC open applies
    PolconClearError  = 0x0344, // clears the error POLCON_POLL keeps reporting after the connection drops
    PolconPoll        = 0x02C1, // FFXiMain polls it every frame; a negative result ends the game with POL-xxxx
    SetMessageTitle   = 0x0430, // (index < 10, text) replaces a built-in Japanese message title
    SetMessageText    = 0x0516, // (index < 10, text) replaces a built-in Japanese message text

    // Profile list loads the viewer runs after login: LOAD_* returns a ticket (one of 4 session slots), CHECK_* polls it (0 pending, 1 done, negative failed)
    LoadFriendList      = 0x00A3, // 2/3 LoadFriendList
    CheckFriendList     = 0x00A4,
    LoadHandleNameList  = 0x00AB, // 0/9 LoadHandleNameList
    CheckHandleNameList = 0x00AC,
    LoadCharacterList   = 0x00AF, // 1/3 LoadCharacterList
    CheckCharacterList  = 0x00B0,
    LoadMyStatus        = 0x0176, // 4/6 LoadMyStatus
    CheckMyStatus       = 0x0177,
    LoadGroupList       = 0x017F, // 7/12 group list
    CheckGroupList      = 0x0180,

    // PlayOnline options (pub\homeNN\option.bin): FFXiMain loads and stores the file but never creates it; the viewer seeds it from the default on account creation
    LoadOptionCheck   = 0x038C, // 0 pending, 1 done, negative failed
    StoreOption       = 0x038D, // writes the loaded options to the user slot; the file has to exist already
    StoreOptionCheck  = 0x038E, // 0 pending, 1 done, negative failed
    FreeOption        = 0x038F,
    LoadOptionDefault = 0x0396, // loads the viewer's default option.bin
};

constexpr auto tableIndex(const PolFunction function) -> std::size_t
{
    return std::to_underlying(function);
}

} // namespace xiloader
