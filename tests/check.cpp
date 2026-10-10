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

#include "config.h"
#include "ui/menu.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

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

auto loadConfig(std::vector<const char*> argv) -> xiloader::Config
{
    argv.insert(argv.begin(), "xiloader");
    return xiloader::Config::load(static_cast<int>(argv.size()), argv.data());
}

auto rejects(std::vector<const char*> argv) -> bool
{
    try
    {
        loadConfig(std::move(argv));
    }
    catch (const std::runtime_error&)
    {
        return true;
    }

    return false;
}

auto writeJson(const char* name, const char* text) -> std::string
{
    const auto path = (std::filesystem::temp_directory_path() / name).string();
    std::ofstream(path) << text;
    return path;
}

void checkConfig()
{
    using xiloader::Language;

    const auto defaults = loadConfig({});
    assert(defaults.serverAddress == "127.0.0.1" && defaults.loginAuthPort == 54231);
    assert(defaults.language == Language::English && !defaults.hide && !defaults.plainMenus);

    const auto file = writeJson("xiloader_check.json", R"({"server":"a.example","username":"u","password":"p","otp":123456,
        "authport":1000,"dataport":1001,"language":"jp","hide":true,"trust_this_computer":true})");

    const auto fromFile = loadConfig({ "--json", file.c_str() });
    assert(fromFile.serverAddress == "a.example" && fromFile.loginAuthPort == 1000 && fromFile.loginDataPort == 1001);
    assert(fromFile.username == "u" && fromFile.password == "p" && fromFile.otpCode == "123456");
    assert(fromFile.language == Language::Japanese && fromFile.hide && fromFile.trustThisComputer);

    // The command line wins over the file
    const auto both = loadConfig({ "--json", file.c_str(), "--server", "b.example", "--authport", "2000", "--lang", "EU", "--hairpin" });
    assert(both.serverAddress == "b.example" && both.loginAuthPort == 2000 && both.loginDataPort == 1001);
    assert(both.language == Language::European && both.hairpin && both.username == "u");

    assert(loadConfig({ "--otp", "012345" }).otpCode == "012345");
    assert(loadConfig({ "--lang", "0" }).language == Language::Japanese);
    assert(loadConfig({ "--email", "ignored@example.com" }).username.empty());

    assert(rejects({ "--lang", "xx" }));
    assert(rejects({ "--authport", "70000" }));
    assert(rejects({ "--nope" }));
    assert(rejects({ "--json", "does_not_exist.json" }));
    assert(rejects({ "--json", writeJson("xiloader_check_bad1.json", R"({"authport":70000})").c_str() }));
    assert(rejects({ "--json", writeJson("xiloader_check_bad2.json", R"({"username":5})").c_str() }));
    assert(rejects({ "--json", writeJson("xiloader_check_bad3.json", R"({"language":"xx"})").c_str() }));
    assert(rejects({ "--json", writeJson("xiloader_check_bad4.json", "not json").c_str() }));
}

} // namespace

auto main() -> int
{
    checkPlainMenu();
    checkConfig();
    std::cout << "ok" << std::endl;
    return 0;
}
