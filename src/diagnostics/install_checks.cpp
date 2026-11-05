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

#include "checks.h"

#include "client/polcore_ids.h"
#include "client/registry.h"
#include "console.h"

#include <filesystem>
#include <format>
#include <optional>
#include <utility>

namespace
{

using xiloader::Check;
using xiloader::CheckStatus;
using xiloader::Language;

constexpr Language kLanguages[] = { Language::Japanese, Language::English, Language::European };

auto readRegistryString(const HKEY root, const std::string& key, const char* const value, const REGSAM view) -> std::optional<std::string>
{
    HKEY opened = nullptr;
    if (RegOpenKeyExA(root, key.c_str(), 0, KEY_QUERY_VALUE | view, &opened) != ERROR_SUCCESS)
    {
        return std::nullopt;
    }

    char       text[MAX_PATH] = {};
    DWORD      size           = sizeof(text) - 1;
    DWORD      type           = 0;
    const auto result         = RegQueryValueExA(opened, value, nullptr, &type, reinterpret_cast<BYTE*>(text), &size);
    RegCloseKey(opened);

    if (result != ERROR_SUCCESS || type != REG_SZ)
    {
        return std::nullopt;
    }

    return std::string(text);
}

// The DLL a COM class is registered to, as the 32-bit loader sees it
auto comServerPath(const CLSID& id) -> std::optional<std::filesystem::path>
{
    const auto key = std::format("CLSID\\{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}\\InprocServer32",
                                 id.Data1,
                                 id.Data2,
                                 id.Data3,
                                 id.Data4[0],
                                 id.Data4[1],
                                 id.Data4[2],
                                 id.Data4[3],
                                 id.Data4[4],
                                 id.Data4[5],
                                 id.Data4[6],
                                 id.Data4[7]);

    const auto path = readRegistryString(HKEY_CLASSES_ROOT, key, nullptr, KEY_WOW64_32KEY);
    if (!path || path->empty())
    {
        return std::nullopt;
    }

    return std::filesystem::path(*path);
}

auto polcoreClass(const Language language) -> const CLSID&
{
    return xiloader::CLSID_POLCoreCom[std::to_underlying(language)];
}

auto pathExists(const std::filesystem::path& path) -> bool
{
    std::error_code error;
    return std::filesystem::exists(path, error);
}

auto isElevated() -> bool
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        return false;
    }

    TOKEN_ELEVATION elevation = {};
    DWORD           size      = 0;
    const auto      known     = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);

    return known && elevation.TokenIsElevated != 0;
}

// Creates and removes a file to find out, since the folder's permissions alone don't say
auto canWriteTo(const std::filesystem::path& folder) -> bool
{
    const auto probe  = folder / "xiloader_write_check.tmp";
    const auto handle = CreateFileA(probe.string().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    CloseHandle(handle);
    return true;
}

auto otherLanguagesHint(const Language language) -> std::string
{
    std::string hint;
    for (const auto installed : xiloader::installedLanguages())
    {
        if (installed != language)
        {
            if (!hint.empty())
            {
                hint += " ";
            }

            hint += std::format("PlayOnline is installed for {}. Use --lang {}.", xiloader::languageName(installed), xiloader::languageName(installed));
        }
    }

    if (hint.empty())
    {
        hint = "Install PlayOnline and FFXI.";
    }

    return hint;
}

} // namespace

namespace xiloader
{

auto languageName(const Language language) -> const char*
{
    switch (language)
    {
        case Language::Japanese:
            return "JP";
        case Language::English:
            return "US";
        case Language::European:
            return "EU";
    }

    return "?";
}

auto polcoreFile(const Language language) -> std::optional<std::filesystem::path>
{
    return comServerPath(polcoreClass(language));
}

auto installedLanguages() -> std::vector<Language>
{
    std::vector<Language> installed;
    for (const auto language : kLanguages)
    {
        if (comServerPath(polcoreClass(language)))
        {
            installed.push_back(language);
        }
    }

    return installed;
}

auto checkInstall(const Language language) -> std::vector<Check>
{
    std::vector<Check> checks;
    const auto         name = languageName(language);

    // The viewer's folder, which polcore is pointed at
    const std::string viewer = registry::GetPlayOnlineInstallFolder(language);
    if (viewer.empty())
    {
        checks.push_back({ .name   = std::format("PlayOnline ({}) in the registry", name),
                           .status = CheckStatus::Fail,
                           .detail = std::format("HKLM\\{}\\InstallFolder has no viewer folder", registry::GetPlayOnlineKey(language)),
                           .hint   = otherLanguagesHint(language) });
    }
    else if (!pathExists(viewer))
    {
        checks.push_back({ .name   = std::format("PlayOnline ({}) folder", name),
                           .status = CheckStatus::Fail,
                           .detail = std::format("{} doesn't exist", viewer),
                           .hint   = "Reinstall PlayOnline." });
    }
    else
    {
        checks.push_back({ .name = std::format("PlayOnline ({}) folder", name), .detail = viewer });
    }

    // polcore, which the loader creates through COM
    const auto polcore = comServerPath(polcoreClass(language));
    if (!polcore)
    {
        checks.push_back({ .name   = std::format("polcore ({}) registration", name),
                           .status = CheckStatus::Fail,
                           .detail = "not registered",
                           .hint   = otherLanguagesHint(language) });
    }
    else if (!pathExists(*polcore))
    {
        checks.push_back({ .name   = std::format("polcore ({}) file", name),
                           .status = CheckStatus::Fail,
                           .detail = std::format("{} doesn't exist", polcore->string()),
                           .hint   = "Reinstall PlayOnline." });
    }
    else
    {
        checks.push_back({ .name = std::format("polcore ({})", name), .detail = polcore->string() });
    }

    // The game, which is created through COM as well
    const auto game = comServerPath(CLSID_FFXiEntry);
    if (!game)
    {
        checks.push_back({ .name   = "FINAL FANTASY XI registration",
                           .status = CheckStatus::Fail,
                           .detail = "not registered",
                           .hint   = "Install FFXI through the PlayOnline Viewer." });
    }
    else if (!pathExists(*game) || !pathExists(game->parent_path() / "FFXiMain.dll"))
    {
        checks.push_back({ .name   = "FINAL FANTASY XI files",
                           .status = CheckStatus::Fail,
                           .detail = std::format("FFXi.dll or FFXiMain.dll is missing from {}", game->parent_path().string()),
                           .hint   = "Run a file check from the PlayOnline Viewer." });
    }
    else
    {
        checks.push_back({ .name = "FINAL FANTASY XI", .detail = game->parent_path().string() });
    }

    return checks;
}

auto checkEnvironment(const Language language) -> std::vector<Check>
{
    std::vector<Check> checks;

    const auto product = readRegistryString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", KEY_WOW64_64KEY);
    const auto build   = readRegistryString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild", KEY_WOW64_64KEY);
    const bool isWine  = GetProcAddress(GetModuleHandleA("ntdll.dll"), "wine_get_version") != nullptr;

    std::string system = std::format("{} build {}", product.value_or("Windows"), build.value_or("?"));
    if (isWine)
    {
        system += ", under Wine";
    }
    checks.push_back({ .name = "System", .detail = system });

    if (isElevated())
    {
        checks.push_back({ .name = "Privileges", .detail = "running as administrator" });
    }
    else
    {
        checks.push_back({ .name   = "Privileges",
                           .status = CheckStatus::Warning,
                           .detail = "not running as administrator",
                           .hint   = "The game may ignore its registry settings (resolution, window mode)." });
    }

    // PlayOnline keeps per-account files under the viewer, and the game its settings and macros under its own folder
    const std::string viewer = registry::GetPlayOnlineInstallFolder(language);
    if (!viewer.empty() && pathExists(std::filesystem::path(viewer) / "pub"))
    {
        const auto pub = std::filesystem::path(viewer) / "pub";
        if (canWriteTo(pub))
        {
            checks.push_back({ .name = "PlayOnline folder", .detail = std::format("{} is writable", pub.string()) });
        }
        else
        {
            checks.push_back({ .name   = "PlayOnline folder",
                               .status = CheckStatus::Warning,
                               .detail = std::format("{} is not writable", pub.string()),
                               .hint   = "PlayOnline settings won't be saved. Run as administrator." });
        }
    }

    if (const auto game = comServerPath(CLSID_FFXiEntry); game.has_value() && pathExists(game->parent_path()))
    {
        const auto folder = game->parent_path();
        if (canWriteTo(folder))
        {
            checks.push_back({ .name = "Game folder", .detail = std::format("{} is writable", folder.string()) });
        }
        else
        {
            checks.push_back({ .name   = "Game folder",
                               .status = CheckStatus::Warning,
                               .detail = std::format("{} is not writable", folder.string()),
                               .hint   = "Macros and settings won't be saved. Run as administrator." });
        }
    }

    return checks;
}

auto report(const std::vector<Check>& checks, const bool onlyProblems) -> bool
{
    bool passed = true;

    for (const auto& check : checks)
    {
        if (check.status == CheckStatus::Fail)
        {
            passed = false;
        }

        if (onlyProblems && check.status == CheckStatus::Pass)
        {
            continue;
        }

        switch (check.status)
        {
            case CheckStatus::Pass:
                console::output(color::success, "[ ok ] {}: {}", check.name, check.detail);
                break;
            case CheckStatus::Warning:
                console::output(color::warning, "[warn] {}: {}", check.name, check.detail);
                break;
            case CheckStatus::Fail:
                console::output(color::error, "[fail] {}: {}", check.name, check.detail);
                break;
        }

        if (!check.hint.empty())
        {
            console::output(color::info, "       {}", check.hint);
        }
    }

    return passed;
}

} // namespace xiloader
