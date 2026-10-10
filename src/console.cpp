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

#include "console.h"

#include <shobjidl.h>

namespace xiloader
{

void console::print(const xiloader::color c, const std::string& message)
{
    const auto                   stdout_handle = ::GetStdHandle(STD_OUTPUT_HANDLE);
    ::CONSOLE_SCREEN_BUFFER_INFO info;
    ::GetConsoleScreenBufferInfo(stdout_handle, &info);
    const auto attributes = info.wAttributes & 0xFFF0 | static_cast<::WORD>(c);
    ::SetConsoleTextAttribute(stdout_handle, static_cast<::WORD>(attributes));
    std::cout << message;
    ::SetConsoleTextAttribute(stdout_handle, info.wAttributes);
}

void console::visible(const bool visible)
{
    const auto console = ::GetConsoleWindow();

    // Adjust the task bar
    ::ITaskbarList* taskbar = nullptr;
    const auto      hr      = ::CoCreateInstance(
        CLSID_TaskbarList,
        nullptr,
        ::CLSCTX_INPROC_SERVER,
        IID_ITaskbarList,
        reinterpret_cast<void**>(&taskbar));
    if (SUCCEEDED(hr))
    {
        if (visible)
        {
            taskbar->AddTab(console);
        }
        else
        {
            taskbar->DeleteTab(console);
        }
        taskbar->Release();
    }

    // Adjust the window's visibility
    int command = SW_HIDE;
    if (visible)
    {
        command = SW_SHOW;
    }

    ::ShowWindow(console, command);
}

void console::hide()
{
    visible(false);
}

void console::show()
{
    visible(true);
}

}; // namespace xiloader
