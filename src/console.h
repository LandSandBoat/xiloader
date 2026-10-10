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

#pragma once

#include <ctime>
#include <iostream>
#include <string>
#include <windows.h>

#include "enums/console_color.h"

namespace xiloader
{

// Console class containing helper functions for console output.
class console
{
private:
    // Shows or hides the console based on the provided argument.
    static void visible(bool visible);

public:
    // Prints a text fragment with the specified color to the console.
    static void print(xiloader::color c, const std::string& message);

    // Prints the given message to the console.
    template <typename... Args>
    static void output(const char* const format, const Args... args)
    {
        output(xiloader::color::white, format, args...);
    }

    static auto getTimestamp() -> std::string
    {
        // Get the current timestamp
        ::__time32_t rawtime;
        ::_time32(&rawtime);

        ::tm timeinfo;
        ::_localtime32_s(&timeinfo, &rawtime);

        // Format the timestamp
        char timestamp[256];
        ::strftime(timestamp, sizeof timestamp, "[%m/%d/%y %H:%M:%S] ", &timeinfo);

        return timestamp;
    }

    // Prints the given message to the console with the specific color.
    template <typename... Args>
    static void output(const xiloader::color c, const char* const format, const Args... args)
    {
        const std::string timestamp = getTimestamp();

        // Output the timestamp
        print(xiloader::color::lightyelllow, timestamp.c_str());

        // Parse the incoming message
        const auto  length = ::snprintf(nullptr, 0, format, args...);
        std::string buffer(length > 0 ? length : 0, '\0');
        ::snprintf(buffer.data(), buffer.size() + 1, format, args...);
        // Output the message

        print(c, buffer);

        std::cout << std::endl;
    }

    static void printMultiLine(std::string msg, const std::string delimiter, const xiloader::color color)
    {
        auto pos = msg.find(delimiter);

        while (pos != -1)
        {
            xiloader::console::output(color, "%s", msg.substr(0, pos).c_str());
            msg.erase(0, pos + delimiter.length());

            pos = msg.find(delimiter);
        }

        xiloader::console::output(color, "%s", msg.c_str());
    }

    // Hides the console window.
    static void hide();

    // Shows the console window.
    static void show();
};

}; // namespace xiloader
