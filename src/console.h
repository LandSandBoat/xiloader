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
#include <filesystem>
#include <format>
#include <iostream>
#include <string>
#include <utility>
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

    static void log(const std::string& line);

public:
    // Prints a text fragment with the specified color to the console.
    static void print(xiloader::color c, const std::string& message);

    // Copies everything output prints into a new file in the folder from here on.
    // Each run gets its own file, so several clients can run at once; only the newest few are kept.
    static void startLog(const std::filesystem::path& folder);

    // Prints like output but keeps the message out of the log file, for things only the user should see
    static void outputUnlogged(xiloader::color c, const std::string& message);

    // Empty until startLog succeeds
    static auto logFile() -> const std::filesystem::path&;

    // The console window was made for this process and closes with it, as when the loader is double-clicked
    static auto ownsWindow() -> bool;

    // Prints the given message to the console.
    template <typename... Args>
    static void output(const std::format_string<Args...> format, Args&&... args)
    {
        output(xiloader::color::white, format, std::forward<Args>(args)...);
    }

    static auto getTimestamp() -> std::string
    {
        // Get the current timestamp
        ::__time32_t rawtime = 0;
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
    static void output(const xiloader::color c, const std::format_string<Args...> format, Args&&... args)
    {
        const std::string timestamp = getTimestamp();
        const std::string message   = std::format(format, std::forward<Args>(args)...);

        // Output the timestamp
        print(xiloader::color::lightyelllow, timestamp);

        // Output the message
        print(c, message);

        std::cout << '\n'
                  << std::flush;

        log(timestamp + message);
    }

    static void printMultiLine(std::string msg, const std::string& delimiter, const xiloader::color color)
    {
        auto pos = msg.find(delimiter);

        while (pos != -1)
        {
            xiloader::console::output(color, "{}", msg.substr(0, pos));
            msg.erase(0, pos + delimiter.length());

            pos = msg.find(delimiter);
        }

        xiloader::console::output(color, "{}", msg);
    }

    // Hides the console window.
    static void hide();

    // Shows the console window.
    static void show();
};

}; // namespace xiloader
