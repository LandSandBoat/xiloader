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

#include "known_servers.h"

#include <windows.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <format>
#include <fstream>
#include <string_view>

namespace
{

using json = nlohmann::json;

constexpr std::string_view kFingerprintPrefix = "SHA256:";

// Every client on the machine shares the record
constexpr const wchar_t* kStoreMutex = L"Local\\xiloader-known-servers";

// Held while the record is read or rewritten. Without the mutex the record is used unlocked.
class StoreLock
{
public:
    StoreLock()
    : mutex(CreateMutexW(nullptr, FALSE, kStoreMutex))
    {
        if (mutex != nullptr)
        {
            WaitForSingleObject(mutex, INFINITE);
        }
    }

    ~StoreLock()
    {
        if (mutex != nullptr)
        {
            ReleaseMutex(mutex);
            CloseHandle(mutex);
        }
    }

    StoreLock(const StoreLock&)            = delete;
    StoreLock& operator=(const StoreLock&) = delete;
    StoreLock(StoreLock&&)                 = delete;
    StoreLock& operator=(StoreLock&&)      = delete;

private:
    HANDLE mutex;
};

auto readStore(const std::filesystem::path& file) -> json
{
    std::ifstream stream(file);
    if (!stream)
    {
        return json::object();
    }

    auto data = json::parse(stream, nullptr, false);
    if (!data.is_object())
    {
        return json::object();
    }

    return data;
}

} // namespace

namespace xiloader
{

KnownServers::KnownServers(std::filesystem::path file)
: file(std::move(file))
{
}

auto KnownServers::find(const std::string& server) const -> std::optional<std::string>
{
    const StoreLock lock;
    const auto      data  = readStore(file);
    const auto      entry = data.find(server);
    if (entry == data.end() || !entry->is_string())
    {
        return std::nullopt;
    }

    return entry->get<std::string>();
}

auto KnownServers::remember(const std::string& server, const std::string& fingerprint) const -> bool
{
    if (file.empty())
    {
        return false;
    }

    const StoreLock lock;

    auto            data = json::object();
    std::error_code error;
    if (std::filesystem::exists(file, error))
    {
        std::ifstream stream(file);
        data = json::parse(stream, nullptr, false);

        // Rewriting a record that can't be read would drop every other key in it
        if (!data.is_object())
        {
            return false;
        }
    }

    data[server] = fingerprint;

    auto temporary = file;
    temporary += ".tmp";
    {
        std::ofstream stream(temporary, std::ios::trunc);
        stream << data.dump(4) << '\n';
        stream.flush();
        if (!stream.good())
        {
            return false;
        }
    }

    // Readers see the old record or the new one, never a partly written one
    return MoveFileExW(temporary.c_str(), file.c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
}

auto serverKey(const std::string& name, const uint16_t port) -> std::string
{
    std::string lowered = name;
    std::ranges::transform(lowered, lowered.begin(), [](const unsigned char c)
                           {
                               return static_cast<char>(std::tolower(c));
                           });

    return std::format("{}:{}", lowered, port);
}

auto normalizeFingerprint(const std::string& fingerprint) -> std::string
{
    const auto isSpace = [](const char c)
    {
        return std::isspace(static_cast<unsigned char>(c)) != 0;
    };

    std::string_view text = fingerprint;
    while (!text.empty() && isSpace(text.front()))
    {
        text.remove_prefix(1);
    }

    // The prefix is optional and its case doesn't matter; the base64 after it is case-sensitive
    if (text.size() >= kFingerprintPrefix.size() && _strnicmp(text.data(), kFingerprintPrefix.data(), kFingerprintPrefix.size()) == 0)
    {
        text.remove_prefix(kFingerprintPrefix.size());
    }

    while (!text.empty() && (text.back() == '=' || isSpace(text.back())))
    {
        text.remove_suffix(1);
    }

    return std::format("{}{}", kFingerprintPrefix, text);
}

auto judgeServer(const std::optional<std::string>& known, const std::string& presented, const std::string& pinned, const bool loopback) -> ServerTrust
{
    // Asking for a key by hand overrides what is on record, and replaces it
    if (!pinned.empty())
    {
        if (normalizeFingerprint(pinned) == presented)
        {
            return ServerTrust::Remember;
        }

        return ServerTrust::PinMismatch;
    }

    if (known && *known == presented)
    {
        return ServerTrust::Trusted;
    }

    if (loopback)
    {
        return ServerTrust::Remember;
    }

    if (known)
    {
        return ServerTrust::Changed;
    }

    return ServerTrust::Ask;
}

} // namespace xiloader
