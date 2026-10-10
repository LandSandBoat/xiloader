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

#include "menu.h"

#include <windows.h>

#include <iostream>
#include <print>

namespace
{

using xiloader::ui::Field;

auto promptLine(const std::string& label, const bool hidden = false) -> std::string
{
    const auto stdinHandle = ::GetStdHandle(STD_INPUT_HANDLE);
    DWORD      mode        = 0;
    if (hidden)
    {
        ::GetConsoleMode(stdinHandle, &mode);
        ::SetConsoleMode(stdinHandle, mode & ~ENABLE_ECHO_INPUT);
    }

    std::cout << label << std::flush;
    std::string line;
    std::getline(std::cin, line);

    if (hidden)
    {
        ::SetConsoleMode(stdinHandle, mode);
        std::println(std::cout);
    }

    return line;
}

// Line-based prompts on stdin and stdout
class PlainMenu final : public xiloader::ui::Menu
{
public:
    auto pick(const std::vector<std::string>& entries) -> int override
    {
        const auto count = static_cast<int>(entries.size());

        for (const auto& entry : entries)
        {
            std::println(std::cout, "  {}", entry);
        }

        while (std::cin)
        {
            const auto line = promptLine("> ");
            if (line.size() == 1 && line[0] >= '1' && line[0] < '1' + count)
            {
                return line[0] - '1';
            }
        }

        return count - 1; // stdin closed, last entry is always exit/cancel
    }

    void form(const std::vector<Field>& fields, const std::function<std::string()>& note) override
    {
        for (const auto& field : fields)
        {
            if (field.skipped && field.skipped())
            {
                continue;
            }

            if (field.checked)
            {
                const auto answer = promptLine("  " + field.label + "? (y/N): ");
                *field.checked    = answer == "y" || answer == "Y";
            }
            else
            {
                *field.text = promptLine("  " + field.label + ": ", field.hidden);
            }
        }

        std::string text;
        if (note)
        {
            text = note();
        }

        if (!text.empty())
        {
            std::println(std::cout, "  {}", text);
        }
    }
};

} // namespace

namespace xiloader::ui
{

auto makePlainMenu() -> std::unique_ptr<Menu>
{
    return std::make_unique<PlainMenu>();
}

} // namespace xiloader::ui
