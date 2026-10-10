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
#include <algorithm>
#include <cassert>
#include <chrono>

#include "client/pattern_scan.h"
#include "config.h"
#include "diagnostics/checks.h"
#include "lobby/data_connection.h"
#include "login/known_servers.h"
#include "otp/trust_token_manager.h"
#include "ui/menu.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <print>
#include <sstream>
#include <string_view>
#include <thread>

#include <ws2tcpip.h>

#include <nlohmann/json.hpp>

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
    assert(!output.str().contains("OTP"));
    assert(output.str().contains("noted"));
}

auto tryLoadConfig(std::vector<const char*> argv) -> std::expected<xiloader::Config, std::string>
{
    argv.insert(argv.begin(), "xiloader");
    return xiloader::Config::load(static_cast<int>(argv.size()), argv.data());
}

auto loadConfig(std::vector<const char*> argv) -> xiloader::Config
{
    return tryLoadConfig(std::move(argv)).value();
}

auto rejects(std::vector<const char*> argv) -> bool
{
    return !tryLoadConfig(std::move(argv)).has_value();
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

    DataServer(const DataServer&)            = delete;
    DataServer& operator=(const DataServer&) = delete;
    DataServer(DataServer&&)                 = delete;
    DataServer& operator=(DataServer&&)      = delete;

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

    auto read(const int size) const -> std::string
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

    xiloader::Session session{ .accountId = 0x11223344 };
    std::memset(session.hash, 0x5A, sizeof(session.hash));

    // Room for the 20 characters the connection may write, then a canary
    constexpr int     kEntry = 0x68;
    std::vector<char> list(kEntry * 20 + 64, 0x77);

    {
        DataServer                    server;
        xiloader::LobbyDataConnection connection;
        assert(connection.connect("127.0.0.1", server.port).has_value());
        server.client = accept(server.listener, nullptr, nullptr);
        assert(server.client != INVALID_SOCKET);

        connection.start(session);

        const auto hello = server.read(28);
        assert(static_cast<uint8_t>(hello[0]) == 0xFE && hello[12] == 0x5A && hello[27] == 0x5A);

        // A list that arrives before polcore's buffer is known is kept for later
        const char early[0x148] = { 0x03, 2 };
        send(server.client, early, sizeof(early), 0);

        // Two requests in one segment are answered one after the other
        const char requests[10] = { 0x01, 0, 0, 0, 0, 0x02 };
        send(server.client, requests, sizeof(requests), 0);

        const auto account = server.read(28);
        assert(static_cast<uint8_t>(account[0]) == 0xA1);
        assert(std::memcmp(account.data() + 1, "\x44\x33\x22\x11", 4) == 0);
        assert(account[12] == 0x5A);

        const auto key = server.read(28);
        assert(static_cast<uint8_t>(key[0]) == 0xA2 && static_cast<uint8_t>(key[17]) == 0x58);

        connection.setCharacterList(list.data());
        assert(list[0] == 1 && list[kEntry] == 1 && list[kEntry * 2] == 0x77);

        // Claims 200 characters; the packet has room for 20
        char packet[0x148] = { 0x03, static_cast<char>(200) };
        for (uint32_t i = 0; i < 20; ++i)
        {
            const uint32_t contentId   = 0xAAAA0000 + i;
            const uint32_t characterId = 0xBBBB0000 + i;
            std::memcpy(packet + 0x10 * (i + 1), &contentId, 4);
            std::memcpy(packet + 0x10 * (i + 1) + 4, &characterId, 4);
        }

        // Delivered in two pieces, with a request right behind it
        send(server.client, packet, 0x100, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        send(server.client, packet + 0x100, sizeof(packet) - 0x100, 0);
        send(server.client, requests + 5, 5, 0);

        // The reply to the request proves the list before it was handled
        server.read(28);
    }

    assert(list[0] == 1 && list[kEntry * 19] == 1 && list[kEntry * 19 + 0x10] == 19);
    assert(std::memcmp(list.data() + kEntry + 0x04, "\x01\x00\xBB\xBB", 4) == 0);
    assert(std::memcmp(list.data() + kEntry * 19 + 0x08, "\x13\x00\xAA\xAA", 4) == 0);
    assert(list[kEntry * 20] == 0x77);

    WSACleanup();
}

// Something for the scanner to find in this module
uint8_t scanTarget[] = { 0xDE, 0xC0, 0xAD, 0x0B, 0x11, 0x22, 0x33, 0x44, 0xFE, 0xED, 0xFA, 0xCE };

void checkPatternScan()
{
    const uint8_t exact[]    = { 0xDE, 0xC0, 0xAD, 0x0B, 0x11, 0x22, 0x33, 0x44, 0xFE, 0xED, 0xFA, 0xCE };
    const uint8_t wildcard[] = { 0xDE, 0xC0, 0xAD, 0x0B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xED, 0xFA, 0xCE };
    const uint8_t absent[]   = { 0xDE, 0xC0, 0xAD, 0x0B, 0x11, 0x22, 0x33, 0x44, 0xFE, 0xED, 0xFA, 0xCF };

    assert(xiloader::memory::FindPattern(nullptr, exact, "xxxxxxxxxxxx") == scanTarget);
    assert(xiloader::memory::FindPattern(nullptr, wildcard, "xxxx????xxxx") == scanTarget);

    // Without the mask the wildcard bytes have to match too
    assert(xiloader::memory::FindPattern(nullptr, wildcard, "xxxxxxxxxxxx") == nullptr);
    assert(xiloader::memory::FindPattern(nullptr, absent, "xxxxxxxxxxxx") == nullptr);
    assert(xiloader::memory::FindPattern("no_such_module.dll", exact, "xxxxxxxxxxxx") == nullptr);

    // A mask longer than the pattern is refused instead of read past
    assert(xiloader::memory::FindPattern(nullptr, exact, "xxxxxxxxxxxxxxxx") == nullptr);
}

// What it finds depends on the machine, so this only pins down what must hold everywhere
void checkInstallChecks()
{
    for (const auto language : { xiloader::Language::Japanese, xiloader::Language::English, xiloader::Language::European })
    {
        const auto checks    = xiloader::checkInstall(language);
        const bool installed = std::ranges::contains(xiloader::installedLanguages(), language);

        // One line each for the viewer folder, polcore and the game
        assert(checks.size() == 3);

        // A language polcore isn't registered for can't pass
        const bool passed = std::ranges::none_of(checks, [](const xiloader::Check& check)
                                                 {
                                                     return check.status == xiloader::CheckStatus::Fail;
                                                 });
        assert(installed || !passed);

        for (const auto& check : checks)
        {
            assert(!check.name.empty() && !check.detail.empty());
            assert(check.status == xiloader::CheckStatus::Pass || !check.hint.empty());
        }
    }

    assert(std::string_view(xiloader::languageName(xiloader::Language::European)) == "EU");
}

void checkKnownServers()
{
    using xiloader::judgeServer;
    using xiloader::ServerTrust;

    const std::string key   = "SHA256:AAAA";
    const std::string other = "SHA256:BBBB";

    // First sight asks, the key on record passes, another key is refused
    assert(judgeServer(std::nullopt, key, "", false) == ServerTrust::Ask);
    assert(judgeServer(key, key, "", false) == ServerTrust::Trusted);
    assert(judgeServer(other, key, "", false) == ServerTrust::Changed);

    // A loopback server is never asked about or refused
    assert(judgeServer(std::nullopt, key, "", true) == ServerTrust::Remember);
    assert(judgeServer(other, key, "", true) == ServerTrust::Remember);
    assert(judgeServer(key, key, "", true) == ServerTrust::Trusted);

    // --fingerprint decides on its own, whatever is on record and wherever the server is
    assert(judgeServer(std::nullopt, key, "AAAA", false) == ServerTrust::Remember);
    assert(judgeServer(other, key, "sha256:AAAA==", false) == ServerTrust::Remember);
    assert(judgeServer(key, key, "SHA256:BBBB", false) == ServerTrust::PinMismatch);
    assert(judgeServer(std::nullopt, key, "SHA256:aaaa", true) == ServerTrust::PinMismatch);

    assert(xiloader::normalizeFingerprint(" sha256:AbC= ") == "SHA256:AbC");
    assert(xiloader::serverKey("Play.Example.COM", 54231) == "play.example.com:54231");

    const auto file = std::filesystem::temp_directory_path() / "xiloader_check_known_servers.json";
    std::filesystem::remove(file);

    const xiloader::KnownServers servers(file);
    assert(!servers.find("a:1"));
    assert(servers.remember("a:1", key));
    servers.remember("b:2", other);
    servers.remember("a:1", other);
    assert(servers.find("a:1") == other && servers.find("b:2") == other && !servers.find("c:3"));

    // A damaged file reads as empty instead of failing
    std::ofstream(file) << "not json";
    assert(!servers.find("a:1"));
    std::filesystem::remove(file);

    // No store: nothing is known and nothing can be saved
    const xiloader::KnownServers nowhere{ std::filesystem::path() };
    assert(!nowhere.find("a:1") && !nowhere.remember("a:1", key));
}

void checkTrustTokens()
{
    const auto store = (std::filesystem::temp_directory_path() / "xiloader_check_trust_tokens.dat").string();
    std::filesystem::remove(store);

    const nlohmann::json reply = { { "trust_token", "token" }, { "trust_expires", static_cast<int64_t>(time(nullptr)) + 3600 } };

    const xiloader::TrustTokenManager issuer("server", "SHA256:AAAA", store);
    assert(!issuer.isTrusted("user"));
    issuer.acceptLoginReply(reply, "user");
    assert(issuer.isTrusted("user") && !issuer.isTrusted("other"));

    // Without a key to compare, the token is neither used nor thrown away
    assert(!xiloader::TrustTokenManager("server", "", store).isTrusted("user"));
    assert(issuer.isTrusted("user"));

    // A server with another key doesn't get it, and it is gone afterwards
    assert(!xiloader::TrustTokenManager("server", "SHA256:BBBB", store).isTrusted("user"));
    assert(!issuer.isTrusted("user"));

    // A token saved before keys were recorded is adopted by the first key that asks
    const xiloader::TrustTokenManager legacy("server", "", store);
    legacy.acceptLoginReply(reply, "user");
    assert(issuer.isTrusted("user"));
    assert(!xiloader::TrustTokenManager("server", "SHA256:BBBB", store).isTrusted("user"));

    std::filesystem::remove(store);
}

} // namespace

auto main() -> int
{
    checkPlainMenu();
    checkConfig();
    checkLobbyData();
    checkPatternScan();
    checkInstallChecks();
    checkKnownServers();
    checkTrustTokens();
    std::println("ok");
    return 0;
}
