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

#undef NDEBUG
#include <cassert>

#include "ui/menu.h"

#include <iostream>
#include <sstream>

namespace
{

using xiloader::ui::Field;

void checkPlainMenu()
{
    const auto menu = xiloader::ui::makePlainMenu();

    std::istringstream input("x\n9\n2\n" // pick: two invalid answers, then entry 2
                             "\n"        // pick: stdin runs out after this
    );
    std::ostringstream output;
    const auto         oldInput  = std::cin.rdbuf(input.rdbuf());
    const auto         oldOutput = std::cout.rdbuf(output.rdbuf());

    assert(menu->pick({ "1) a", "2) b", "3) c" }) == 1);
    assert(menu->pick({ "1) a", "2) exit" }) == 1);

    std::istringstream form("user\nsecret\ny\n");
    std::cin.clear();
    std::cin.rdbuf(form.rdbuf());

    std::string username;
    std::string password;
    std::string otp     = "untouched";
    bool        trust   = false;
    bool        trusted = false;

    menu->form(
        {
            { .label = "Username", .text = &username },
            { .label = "Password", .text = &password, .hidden = true },
            { .label = "OTP", .text = &otp, .skipped = [&]
                                            {
                                                return username == "user";
                                            } },
            { .label = "Trust", .checked = &trust },
        },
        [&]
        {
            trusted = true;
            return std::string("noted");
        });

    std::cin.rdbuf(oldInput);
    std::cout.rdbuf(oldOutput);

    assert(username == "user" && password == "secret");
    assert(otp == "untouched");
    assert(trust && trusted);
    assert(output.str().find("OTP") == std::string::npos);
    assert(output.str().find("noted") != std::string::npos);
}

} // namespace

auto main() -> int
{
    checkPlainMenu();
    std::cout << "ok" << std::endl;
    return 0;
}
