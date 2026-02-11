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

#include "trust_token.h"

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

std::string getTrustTokenDir()
{
    char* appdata = nullptr;
    size_t len    = 0;
    _dupenv_s(&appdata, &len, "APPDATA");
    std::string dir;
    if (appdata)
    {
        dir = std::string(appdata) + "\\xiloader\\";
        free(appdata);
    }
    else
    {
        xiloader::console::output(xiloader::color::warning, "APPDATA not set; trust tokens will be stored in the current directory.");
        dir = ".\\";
    }
    std::filesystem::create_directories(dir);
    return dir;
}

std::string getTrustTokenFilepath()
{
    return getTrustTokenDir() + "trust_tokens.dat";
}

std::string buildTrustTokenKey(const std::string& server, const std::string& username)
{
    return server + "|" + username;
}

json readTokenStore()
{
    std::string filepath = getTrustTokenFilepath();
    if (!std::filesystem::exists(filepath))
    {
        return json::object();
    }

    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        return json::object();
    }

    auto fileSize = file.tellg();
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
        return json::object();
    }

    std::string jsonStr(reinterpret_cast<char*>(decryptedBlob.pbData), decryptedBlob.cbData);
    LocalFree(decryptedBlob.pbData);

    json tokenData = json::parse(jsonStr, nullptr, false);
    if (tokenData.is_discarded())
    {
        return json::object();
    }

    return tokenData;
}

void writeTokenStore(const json& tokenData)
{
    std::string filepath = getTrustTokenFilepath();
    std::string jsonStr  = tokenData.dump();

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
    }
}

} // anonymous namespace

std::string loadTrustToken(const std::string& server, const std::string& username)
{
    json tokenData = readTokenStore();

    std::string key = buildTrustTokenKey(server, username);
    if (!tokenData.contains(key))
    {
        return "";
    }

    auto& entry = tokenData[key];
    if (!entry.contains("token") || !entry.contains("expires"))
    {
        return "";
    }

    int64_t expires = entry["expires"].get<int64_t>();
    if (static_cast<int64_t>(time(nullptr)) >= expires)
    {
        // Token expired client-side, remove it
        tokenData.erase(key);
        writeTokenStore(tokenData);
        return "";
    }

    return entry["token"].get<std::string>();
}

void saveTrustToken(const std::string& server, const std::string& username,
                    const std::string& token, int64_t expiresEpoch)
{
    json tokenData = readTokenStore();

    std::string key = buildTrustTokenKey(server, username);
    tokenData[key]  = { { "token", token }, { "expires", expiresEpoch } };

    writeTokenStore(tokenData);
}

void removeTrustToken(const std::string& server, const std::string& username)
{
    json tokenData = readTokenStore();

    std::string key = buildTrustTokenKey(server, username);
    if (!tokenData.contains(key))
    {
        return;
    }

    tokenData.erase(key);
    writeTokenStore(tokenData);
}
