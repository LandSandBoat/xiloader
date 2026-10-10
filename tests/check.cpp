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
#include <chrono>

#include "app.h"
#include "config.h"
#include "lobby/data_connection.h"
#include "ui/menu.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

#include <ws2tcpip.h>

// console.cpp and the lobby connection read these
namespace xiloader
{

Config   config;
AppState state;

} // namespace xiloader

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

// Stands in for the login server's data port: one listener on a free loopback port
struct DataServer
{
    SOCKET   listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKET   client   = INVALID_SOCKET;
    uint16_t port     = 0;

    DataServer()
    {
        sockaddr_in address = {};
        address.sin_family  = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        assert(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        assert(listen(listener, 1) == 0);

        int length = sizeof(address);
        getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length);
        port = ntohs(address.sin_port);
    }

    ~DataServer()
    {
        closesocket(client);
        closesocket(listener);
    }

    auto read(const int size) -> std::string
    {
        std::string data(size, '\0');
        int         total = 0;
        while (total < size)
        {
            const auto got = recv(client, data.data() + total, size - total, 0);
            assert(got > 0);
            total += got;
        }
        return data;
    }
};

void checkLobbyData()
{
    WSADATA wsa = {};
    assert(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);

    std::memset(xiloader::state.sessionHash, 0x5A, sizeof(xiloader::state.sessionHash));

    // Room for the 20 characters the connection may write, then a canary
    constexpr int     kEntry = 0x68;
    std::vector<char> list(kEntry * 20 + 64, 0x77);

    {
        DataServer                    server;
        xiloader::LobbyDataConnection connection;
        assert(connection.connect("127.0.0.1", server.port));
        server.client = accept(server.listener, nullptr, nullptr);
        assert(server.client != INVALID_SOCKET);

        connection.start(0x11223344);

        const auto hello = server.read(28);
        assert(static_cast<uint8_t>(hello[0]) == 0xFE && hello[12] == 0x5A && hello[27] == 0x5A);

        // A list that arrives before polcore's buffer is known is dropped
        char early[0x30] = { 0x03, 2 };
        send(server.client, early, sizeof(early), 0);

        // The connection treats each read as one packet, so keep the next send out of it
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        const char accountRequest[1] = { 0x01 };
        send(server.client, accountRequest, 1, 0);
        const auto account = server.read(28);
        assert(static_cast<uint8_t>(account[0]) == 0xA1);
        assert(std::memcmp(account.data() + 1, "\x44\x33\x22\x11", 4) == 0);
        assert(account[12] == 0x5A);

        const char keyRequest[1] = { 0x02 };
        send(server.client, keyRequest, 1, 0);
        const auto key = server.read(28);
        assert(static_cast<uint8_t>(key[0]) == 0xA2 && static_cast<uint8_t>(key[17]) == 0x58);

        connection.setCharacterList(list.data());

        // Claims 200 characters but only carries two
        char           packet[0x30]   = { 0x03, static_cast<char>(200) };
        const uint32_t contentIds[]   = { 0xAAAA0001, 0xAAAA0002 };
        const uint32_t characterIds[] = { 0xBBBB0001, 0xBBBB0002 };
        for (int i = 0; i < 2; ++i)
        {
            std::memcpy(packet + 0x10 * (i + 1), &contentIds[i], 4);
            std::memcpy(packet + 0x10 * (i + 1) + 4, &characterIds[i], 4);
        }
        send(server.client, packet, sizeof(packet), 0);

        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // The key round trip proves the list packet before it was handled
        send(server.client, keyRequest, 1, 0);
        server.read(28);
    }

    assert(list[0] == 1 && list[kEntry] == 1 && list[kEntry + 0x10] == 1);
    assert(std::memcmp(list.data() + kEntry + 0x04, "\x02\x00\xBB\xBB", 4) == 0);
    assert(std::memcmp(list.data() + kEntry + 0x08, "\x02\x00\xAA\xAA", 4) == 0);
    assert(list[kEntry * 2] == 0x77);

    WSACleanup();
}

} // namespace

auto main() -> int
{
    checkPlainMenu();
    checkConfig();
    checkLobbyData();
    std::cout << "ok" << std::endl;
    return 0;
}
