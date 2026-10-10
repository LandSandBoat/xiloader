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

#include <algorithm>
#include <fstream>
#include <mutex>
#include <string_view>
#include <vector>

namespace
{

constexpr std::size_t      kLogsKept  = 10;
constexpr std::string_view kLogPrefix = "xiloader-";
constexpr std::string_view kLogSuffix = ".log";

std::filesystem::path logPath;
std::ofstream         logStream;
std::mutex            logMutex; // output is called from the lobby, relay and game threads

} // namespace

namespace xiloader
{

void console::startLog(const std::filesystem::path& folder)
{
    // The names sort by start time
    std::vector<std::filesystem::path> logs;
    std::error_code                    error;
    for (const auto& entry : std::filesystem::directory_iterator(folder, error))
    {
        const auto name = entry.path().filename().string();
        if (name.starts_with(kLogPrefix) && name.ends_with(kLogSuffix))
        {
            logs.push_back(entry.path());
        }
    }

    std::ranges::sort(logs);
    while (logs.size() >= kLogsKept)
    {
        std::filesystem::remove(logs.front(), error);
        logs.erase(logs.begin());
    }

    SYSTEMTIME now = {};
    ::GetLocalTime(&now);

    const auto file = folder / std::format("{}{:04}{:02}{:02}-{:02}{:02}{:02}-{}{}", kLogPrefix, now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, ::GetCurrentProcessId(), kLogSuffix);

    logStream.open(file, std::ios::trunc);
    if (logStream)
    {
        logPath = file;
    }
}

auto console::logFile() -> const std::filesystem::path&
{
    return logPath;
}

void console::log(const std::string& line)
{
    const std::scoped_lock lock(logMutex);
    if (logStream)
    {
        logStream << line << '\n'
                  << std::flush;
    }
}

void console::outputUnlogged(const xiloader::color c, const std::string& message)
{
    print(xiloader::color::lightyelllow, getTimestamp());
    print(c, message);

    std::cout << '\n'
              << std::flush;
}

auto console::ownsWindow() -> bool
{
    DWORD processes[2] = {};
    DWORD mode         = 0;

    return ::GetConsoleProcessList(processes, 2) == 1 && ::GetConsoleMode(::GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
}

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
