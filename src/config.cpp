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

#include "config.h"

#include "argparse/argparse.hpp"
#include <nlohmann/json.hpp>

#include <cstring>
#include <format>
#include <fstream>

namespace
{

using json = nlohmann::json;
using xiloader::Config;
using xiloader::Language;

auto parseLanguage(const std::string& language) -> std::expected<Language, std::string>
{
    if (!_strnicmp(language.c_str(), "JP", 2) || !_strnicmp(language.c_str(), "0", 1))
    {
        return Language::Japanese;
    }

    if (!_strnicmp(language.c_str(), "US", 2) || !_strnicmp(language.c_str(), "1", 1))
    {
        return Language::English;
    }

    if (!_strnicmp(language.c_str(), "EU", 2) || !_strnicmp(language.c_str(), "2", 1))
    {
        return Language::European;
    }

    return std::unexpected(std::format("Unknown language '{}'. Use JP, US or EU (0, 1 or 2).", language));
}

// Leaves out untouched when the key is absent; a value of the wrong type is an error
template <typename T>
auto read(const json& data, const char* const key, T& out) -> std::expected<void, std::string>
{
    const auto value = data.find(key);
    if (value == data.end())
    {
        return {};
    }

    try
    {
        out = value->get<T>();
    }
    catch (const json::exception&)
    {
        return std::unexpected(std::format("--json: \"{}\" has the wrong type.", key));
    }

    return {};
}

auto readPort(const json& data, const char* const key, uint16_t& out) -> std::expected<void, std::string>
{
    const auto value = data.find(key);
    if (value == data.end())
    {
        return {};
    }

    if (!value->is_number_unsigned() || value->get<uint64_t>() > UINT16_MAX)
    {
        return std::unexpected(std::format("--json: \"{}\" must be a port number.", key));
    }

    out = value->get<uint16_t>();

    return {};
}

auto applyJsonFile(Config& config, const std::string& filename) -> std::expected<void, std::string>
{
    std::ifstream file(filename);
    if (!file)
    {
        return std::unexpected("--json was specified but the file at the input arg does not exist.");
    }

    const auto data = json::parse(file, nullptr, false);
    if (!data.is_object())
    {
        return std::unexpected("--json was specified but the file at the input arg is not valid json");
    }

    // The first error is the one reported
    std::expected<void, std::string> status;
    const auto                       check = [&](std::expected<void, std::string> result)
    {
        if (status && !result)
        {
            status = std::move(result);
        }
    };

    check(read(data, "server", config.serverAddress));
    check(read(data, "username", config.username));
    check(read(data, "password", config.password));
    check(read(data, "hairpin", config.hairpin));
    check(read(data, "hide", config.hide));
    check(read(data, "plain", config.plainMenus));
    check(read(data, "trust_this_computer", config.trustThisComputer));

    check(readPort(data, "dataport", config.loginDataPort));
    check(readPort(data, "viewport", config.loginViewPort));
    check(readPort(data, "authport", config.loginAuthPort));
    check(readPort(data, "profileport", config.profilePort));

    // try string and int
    if (const auto otp = data.find("otp"); otp != data.end() && otp->is_number_unsigned())
    {
        config.otpCode = std::to_string(otp->get<uint64_t>());
    }
    else
    {
        check(read(data, "otp", config.otpCode));
    }

    std::string language;
    check(read(data, "language", language));
    if (!status)
    {
        return status;
    }

    if (!language.empty())
    {
        const auto parsed = parseLanguage(language);
        if (!parsed)
        {
            return std::unexpected(parsed.error());
        }

        config.language = *parsed;
    }

    return {};
}

} // namespace

namespace xiloader
{

auto Config::load(const int argc, const char* const argv[]) -> std::expected<Config, std::string>
{
    argparse::ArgumentParser args("xiloader", std::format("{}.{}.{}", versionNumber[0], versionNumber[1], versionNumber[2]));

    // NOTE: .append() is used to allow multiple arguments to be passed to the same option.
    //     : Otherwise it will throw on repeated arguments (normally accidental).

    args.add_argument("--server")
        .help("The server address to connect to.")
        .append();

    args.add_argument("--user", "--username")
        .help("The username being logged in with.")
        .append();

    args.add_argument("--pass", "--password")
        .help("The password being logged in with.")
        .append();

    args.add_argument("--otp", "--otp-code")
        .help("The otp code being logged in with.")
        .append();

    args.add_argument("--email")
        .help("Ignored; accepted so existing shortcuts keep working.")
        .append();

    args.add_argument("--dataport")
        .scan<'i', uint16_t>()
        .help("(optional) The login server data port to connect to.")
        .append();

    args.add_argument("--viewport")
        .scan<'i', uint16_t>()
        .help("(optional) The login view port to connect to.")
        .append();

    args.add_argument("--authport")
        .scan<'i', uint16_t>()
        .help("(optional) The login auth port to connect to.")
        .append();

    args.add_argument("--profileport")
        .scan<'i', uint16_t>()
        .help("(optional) The PlayOnline profile server port to connect to.")
        .append();

    args.add_argument("--lang")
        .help("(optional) The language of your FFXI install: JP/US/EU (0/1/2).")
        .append();

    args.add_argument("--hairpin")
        .implicit_value(true)
        .help("(optional) Use this if connecting to a local server which you have exposed publicly. This should not have to be used if you are connecting to a remote server.")
        .append();

    args.add_argument("--hide")
        .implicit_value(true)
        .help("(optional) Determines whether or not to hide the console window after FFXI starts.")
        .append();

    args.add_argument("--plain")
        .implicit_value(true)
        .help("(optional) Use plain text menus. Always on under Wine.")
        .append();

    args.add_argument("--trust")
        .implicit_value(true)
        .help("(optional) Trust this computer for 30 days, skipping 2FA on subsequent logins.")
        .append();

    args.add_argument("--json", "--json-file")
        .help("(optional) The json file to load arguments in from. Command line arguments override it.")
        .append();

    try
    {
        args.parse_args(argc, argv);
    }
    catch (const std::exception& err)
    {
        return std::unexpected(std::format("{}\n{}", err.what(), args.help().str()));
    }

    Config config;

    if (const auto filename = args.present<std::string>("--json"))
    {
        if (const auto applied = applyJsonFile(config, *filename); !applied)
        {
            return std::unexpected(applied.error());
        }
    }

    const auto apply = [&]<typename T>(const char* name, T& out)
    {
        if (const auto value = args.present<T>(name))
        {
            out = *value;
        }
    };

    apply("--server", config.serverAddress);
    apply("--user", config.username);
    apply("--pass", config.password);
    apply("--otp", config.otpCode);
    apply("--dataport", config.loginDataPort);
    apply("--viewport", config.loginViewPort);
    apply("--authport", config.loginAuthPort);
    apply("--profileport", config.profilePort);
    apply("--hairpin", config.hairpin);
    apply("--hide", config.hide);
    apply("--plain", config.plainMenus);
    apply("--trust", config.trustThisComputer);

    if (const auto language = args.present<std::string>("--lang"))
    {
        const auto parsed = parseLanguage(*language);
        if (!parsed)
        {
            return std::unexpected(parsed.error());
        }

        config.language = *parsed;
    }

    return config;
}

} // namespace xiloader
