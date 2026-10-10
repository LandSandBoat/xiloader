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

#include "trust_token_manager.h"

#ifndef NOMINMAX
#define NOMINMAX 1
#endif

#include <winsock2.h>

#include <windows.h>

#include <wincrypt.h>

#include <ctime>
#include <filesystem>
#include <fstream>
#include <vector>

#include <nlohmann/json.hpp>

#include "console.h"

using json = nlohmann::json;

namespace
{

constexpr int64_t kSecondsPerDay = 24 * 60 * 60;

auto getTrustTokenDir() -> std::string
{
    char*  appdata = nullptr;
    size_t len     = 0;
    _dupenv_s(&appdata, &len, "APPDATA");
    std::string dir;
    if (appdata)
    {
        dir = std::string(appdata) + "\\xiloader\\";
        free(appdata);
    }
    else
    {
        xiloader::console::output(xiloader::color::warning,
                                  "APPDATA not set; trust tokens will be stored in the current directory.");
        dir = ".\\";
    }
    std::filesystem::create_directories(dir);
    return dir;
}

auto readTokenStore(const std::string& filepath) -> json
{
    if (!std::filesystem::exists(filepath))
    {
        return json::object();
    }

    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        xiloader::console::output(xiloader::color::warning,
                                  "Failed to open the saved trust tokens at %s. You may be asked for your OTP code.",
                                  filepath.c_str());
        return json::object();
    }

    const auto fileSize = file.tellg();
    if (fileSize <= 0)
    {
        return json::object();
    }

    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> encrypted(static_cast<size_t>(fileSize));
    file.read(reinterpret_cast<char*>(encrypted.data()), fileSize);
    file.close();

    DATA_BLOB encryptedBlob;
    encryptedBlob.pbData = encrypted.data();
    encryptedBlob.cbData = static_cast<DWORD>(encrypted.size());

    DATA_BLOB decryptedBlob;
    if (!CryptUnprotectData(&encryptedBlob, nullptr, nullptr, nullptr, nullptr, 0, &decryptedBlob))
    {
        xiloader::console::output(xiloader::color::warning,
                                  "Failed to decrypt the saved trust tokens at %s (error %lu).",
                                  filepath.c_str(),
                                  GetLastError());
        return json::object();
    }

    const std::string jsonStr(reinterpret_cast<char*>(decryptedBlob.pbData), decryptedBlob.cbData);
    LocalFree(decryptedBlob.pbData);

    json tokenData = json::parse(jsonStr, nullptr, false);
    if (tokenData.is_discarded())
    {
        xiloader::console::output(xiloader::color::warning,
                                  "The saved trust tokens at %s are unreadable. You may be asked for your OTP code.",
                                  filepath.c_str());
        return json::object();
    }

    return tokenData;
}

void writeTokenStore(const std::string& filepath, const json& tokenData)
{
    std::string jsonStr = tokenData.dump();

    DATA_BLOB plainBlob;
    plainBlob.pbData = reinterpret_cast<BYTE*>(jsonStr.data());
    plainBlob.cbData = static_cast<DWORD>(jsonStr.size());

    DATA_BLOB encryptedBlob;
    if (CryptProtectData(&plainBlob, nullptr, nullptr, nullptr, nullptr, 0, &encryptedBlob))
    {
        std::ofstream file(filepath, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<char*>(encryptedBlob.pbData), encryptedBlob.cbData);
        file.close();
        LocalFree(encryptedBlob.pbData);
        if (file.fail())
        {
            xiloader::console::output(xiloader::color::warning,
                                      "Failed to save trust tokens to %s. Check that folder is writable.",
                                      filepath.c_str());
        }
    }
    else
    {
        xiloader::console::output(xiloader::color::warning,
                                  "Failed to encrypt the trust tokens (error %lu). They were not saved.",
                                  GetLastError());
    }
}

} // anonymous namespace

namespace xiloader
{

TrustTokenManager::TrustTokenManager(std::string server)
: server(std::move(server))
, storePath(getTrustTokenDir() + "trust_tokens.dat")
{
}

auto TrustTokenManager::key(const std::string& username) const -> std::string
{
    return server + "|" + username;
}

auto TrustTokenManager::load(const std::string& username) const -> std::string
{
    json tokenData = readTokenStore(storePath);

    const auto entry = tokenData.find(key(username));
    if (entry == tokenData.end() || !entry->contains("token") || !entry->contains("expires"))
    {
        return "";
    }

    if (static_cast<int64_t>(time(nullptr)) >= (*entry)["expires"].get<int64_t>())
    {
        // Token expired client-side, remove it
        tokenData.erase(entry);
        writeTokenStore(storePath, tokenData);
        return "";
    }

    return (*entry)["token"].get<std::string>();
}

void TrustTokenManager::save(const std::string& username, const std::string& token, const int64_t expiresEpoch) const
{
    json tokenData = readTokenStore(storePath);

    tokenData[key(username)] = { { "token", token }, { "expires", expiresEpoch } };

    writeTokenStore(storePath, tokenData);
}

auto TrustTokenManager::isTrusted(const std::string& username) const -> bool
{
    return !load(username).empty();
}

void TrustTokenManager::addToLoginRequest(json& request, const std::string& username, const bool trustThisComputer) const
{
    request["trust_token"]         = load(username);
    request["trust_this_computer"] = trustThisComputer;
}

void TrustTokenManager::acceptLoginReply(const json& reply, const std::string& username) const
{
    const auto token = reply.find("trust_token");
    if (token == reply.end() || !token->is_string() || token->get_ref<const std::string&>().empty())
    {
        return;
    }

    // Use server-provided expiry; fall back to 30 days if absent
    const auto now     = static_cast<int64_t>(time(nullptr));
    const auto expiry  = reply.find("trust_expires");
    const auto expires = expiry != reply.end() && expiry->is_number_integer()
                             ? expiry->get<int64_t>()
                             : now + (30 * kSecondsPerDay);

    save(username, token->get<std::string>(), expires);

    const auto days = (expires - now) / kSecondsPerDay;
    xiloader::console::output(xiloader::color::info, "This computer is now trusted for %lld day%s.", days, days == 1 ? "" : "s");
}

void TrustTokenManager::revoke(const std::string& username) const
{
    json tokenData = readTokenStore(storePath);

    if (tokenData.erase(key(username)) > 0)
    {
        writeTokenStore(storePath, tokenData);
    }
}

} // namespace xiloader
