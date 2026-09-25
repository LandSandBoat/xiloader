/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

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

This file is part of DarkStar-server source code.

===========================================================================
*/

#ifndef __XILOADER_DEFINES_H_INCLUDED__
#define __XILOADER_DEFINES_H_INCLUDED__

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#include <winsock2.h>

#include <windows.h>
#include <process.h>
#include <stdint.h>
#include <string>
#include <time.h>

#include "detours/detours.h"

#include "polcore.h"
#include "ffxi.h"
#include "ffximain.h"

/* Function Offset Definitions */
#define POLFUNC_INET_MUTEX      0x032F
#define POLFUNC_REGISTRY_LANG   0x03C5
#define POLFUNC_FFXI_LANG       0x01A4
#define POLFUNC_REGISTRY_KEY    0x016F
#define POLFUNC_INSTALL_FOLDER  0x007D

// PlayOnline login, as the viewer performs it
#define POLFUNC_POLCON_OPEN         0x032E // (type, connection data) opens the PlayOnline connection
#define POLFUNC_POLCON_STEP         0x032F // advances the connect state machine; 0x1E once connected (same entry as POLFUNC_INET_MUTEX)
#define POLFUNC_POLCON_IDLE         0x0332 // lets polcore process pending network events
#define POLFUNC_SET_POLID           0x0353
#define POLFUNC_SET_PASSWORD        0x0354
#define POLFUNC_SET_POLCOM_HOST     0x0355
#define POLFUNC_ENCODE_POLID        0x0356
#define POLFUNC_ENCODE_PASSWORD     0x0358 // (out[17], password)
#define POLFUNC_FORMAT_POLID        0x0161 // (low, high, out[8]) unmasks a POL id and writes its 8 digits, without a terminator
#define POLFUNC_MASK_POLID          0x0163 // (low, high) masks a POL id with the session key, returned in edx:eax
#define POLFUNC_ENCODE_HOST         0x0364
#define POLFUNC_SET_USER_SLOT       0x0366 // picks pub\homeNN for local message copies
#define POLFUNC_FILE_INIT           0x03A4 // starts the file layer the game saves messages through
#define POLFUNC_MESSAGE_NOTICES     0x0408 // (1) turns on message notices
#define POLFUNC_SET_EVENT_HANDLER   0x0120 // (handler) sets the handler PlayOnline events such as new messages go to; FFXiMain installs its own
#define POLFUNC_NOTICE_HANDLER      0x014E // polcore's IRC notice handler, slot 1 of the polcon handler block (read, not called)
#define POLFUNC_POLCON_HANDLER_3    0x0191 // polcore's default for slot 3 of the polcon handler block (read, not called)
#define POLFUNC_POLCON_SET_HANDLERS 0x0367 // (six handlers) replaces the polcon handler block that each IRC open applies
#define POLFUNC_POLCON_CLEAR_ERROR  0x0344 // clears the error POLCON_POLL keeps reporting after the connection drops
#define POLFUNC_POLCON_POLL         0x02C1 // FFXiMain polls it every frame; a negative result ends the game with POL-xxxx
#define POLFUNC_SET_MESSAGE_TITLE   0x0430 // (index < 10, text) replaces a built-in Japanese message title
#define POLFUNC_SET_MESSAGE_TEXT    0x0516 // (index < 10, text) replaces a built-in Japanese message text

// Profile list loads the viewer runs after login: LOAD_* returns a ticket (one of 4 session slots), CHECK_* polls it (0 pending, 1 done, negative failed)
#define POLFUNC_LOAD_FRIEND_LIST         0x00A3 // 2/3 LoadFriendList
#define POLFUNC_CHECK_FRIEND_LIST        0x00A4
#define POLFUNC_LOAD_HANDLE_NAME_LIST    0x00AB // 0/9 LoadHandleNameList
#define POLFUNC_CHECK_HANDLE_NAME_LIST   0x00AC
#define POLFUNC_LOAD_CHARACTER_LIST      0x00AF // 1/3 LoadCharacterList
#define POLFUNC_CHECK_CHARACTER_LIST     0x00B0
#define POLFUNC_LOAD_MY_STATUS           0x0176 // 4/6 LoadMyStatus
#define POLFUNC_CHECK_MY_STATUS          0x0177
#define POLFUNC_LOAD_GROUP_LIST          0x017F // 7/12 group list
#define POLFUNC_CHECK_GROUP_LIST         0x0180

namespace xiloader
{
    /* PolCore COM Class ID Definitions */
    const CLSID CLSID_POLCoreCom[] =
    {
        { 0x07974581, 0x0df6, 0x4ef0, { 0xbd, 0x05, 0x60, 0x4b, 0x3a, 0xda, 0x9b, 0xe9 } }, // JP
        { 0x3501f5dd, 0x7894, 0x42df, { 0x86, 0x6a, 0xa2, 0xb6, 0x52, 0x7d, 0x80, 0x49 } }, // US
        { 0xe5966fb3, 0xc97b, 0x42eb, { 0x84, 0xbf, 0x37, 0xf9, 0x5e, 0xe5, 0x4a, 0x9f } }, // EU
    };

    /* PolCore COM Object ID Defintions */
    const IID IID_IPOLCoreCom[] =
    {
        { 0x9a30d565, 0xa74c, 0x4b56, { 0xb9, 0x71, 0xdc, 0xf0, 0x21, 0x85, 0xb1, 0x0d } }, // JP
        { 0xe0516654, 0xef77, 0x435d, { 0xaa, 0x7d, 0x50, 0xd2, 0xc0, 0x69, 0xce, 0x34 } }, // US
        { 0xdfec2e93, 0x4971, 0x4a54, { 0xb8, 0xed, 0x63, 0x81, 0x5c, 0x20, 0x8c, 0x5a } }, // EU
    };

    /* FFXi COM Object Definitions */
    const CLSID CLSID_FFXiEntry = { 0x989D790D, 0x6236, 0x11D4, { 0x80, 0xE9, 0x00, 0x10, 0x5A, 0x81, 0xE8, 0x90 } };
    const IID IID_IFFXiEntry = { 0x989D790C, 0x6236, 0x11D4, { 0x80, 0xE9, 0x00, 0x10, 0x5A, 0x81, 0xE8, 0x90 } };

    /* PlayOnline Language Enumeration */
    enum Language
    {
        Japanese = 0,
        English = 1,
        European = 2
    };

}; // namespace xiloader

#endif // __XILOADER_DEFINES_H_INCLUDED__
