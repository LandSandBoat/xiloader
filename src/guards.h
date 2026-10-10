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

#include <winsock2.h>

#include <windows.h>

#include <objbase.h>

#include "client/polrelay.h"

namespace xiloader
{

struct Winsock
{
    WSADATA   data  = {};
    const int error = WSAStartup(MAKEWORD(2, 2), &data);

    Winsock()                          = default;
    Winsock(const Winsock&)            = delete;
    Winsock& operator=(const Winsock&) = delete;
    Winsock(Winsock&&)                 = delete;
    Winsock& operator=(Winsock&&)      = delete;

    ~Winsock()
    {
        if (error == 0)
        {
            WSACleanup();
        }
    }
};

struct Com
{
    const HRESULT result = CoInitialize(nullptr);

    Com()                      = default;
    Com(const Com&)            = delete;
    Com& operator=(const Com&) = delete;
    Com(Com&&)                 = delete;
    Com& operator=(Com&&)      = delete;

    ~Com()
    {
        if (SUCCEEDED(result))
        {
            CoUninitialize();
        }
    }
};

struct RelayStop
{
    RelayStop()                            = default;
    RelayStop(const RelayStop&)            = delete;
    RelayStop& operator=(const RelayStop&) = delete;
    RelayStop(RelayStop&&)                 = delete;
    RelayStop& operator=(RelayStop&&)      = delete;

    ~RelayStop()
    {
        xiloader::polrelay::stop();
    }
};

} // namespace xiloader
