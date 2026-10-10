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

#include <windows.h>

#include "playonline.h"

#include "enums/polcon_state.h"
#include "enums/reconnect.h"

#include "client/pattern_scan.h"
#include "client/registry.h"
#include "console.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <random>
#include <span>

namespace
{

using xiloader::PolconState;
using xiloader::PolFunction;
using xiloader::Reconnect;
using xiloader::tableIndex;
using xiloader::playonline::CommandTable;
using xiloader::playonline::ConnectionData;
using xiloader::playonline::Load;

// How polcore's table entries are called: cdecl, returning a status or ticket
using Command = int(__cdecl*)(...);

// Characters of the PlayOnline password
constexpr char kPasswordCharacters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Timeout for the IRC session, and the wait between reconnect attempts
// No list load timeout: polcore frees a slot only from its check, and fails the load itself after 100 seconds
constexpr ULONGLONG kConnectDeadlineMs = 60000;
constexpr ULONGLONG kRetryDelayMinMs   = 15000;
constexpr ULONGLONG kRetryDelayMaxMs   = 45000;

constexpr DWORD kPollIntervalMs = 1;

// Lists the viewer loads after login; status first, then the rest in parallel (polcore has 4 profile slots)
constexpr Load kStatusLoads[] = {
    { .name = "status", .setup = PolFunction::LoadMyStatus, .check = PolFunction::CheckMyStatus },
};

constexpr Load kListLoads[] = {
    { .name = "friends", .setup = PolFunction::LoadFriendList, .check = PolFunction::CheckFriendList },
    { .name = "handles", .setup = PolFunction::LoadHandleNameList, .check = PolFunction::CheckHandleNameList },
    { .name = "characters", .setup = PolFunction::LoadCharacterList, .check = PolFunction::CheckCharacterList },
    { .name = "groups", .setup = PolFunction::LoadGroupList, .check = PolFunction::CheckGroupList },
};

// Kept from logIn for reconnecting
struct Session
{
    CommandTable table               = nullptr;
    uint8_t      encodedPassword[17] = {};
    int          slot                = 0;
} session;

// polcore's own POLCON_POLL and SET_EVENT_HANDLER, which keepGameOnDisconnect wraps
Command polconPoll      = nullptr;
Command setEventHandler = nullptr;

// FFXiMain's event handler; each IRC open resets it to polcore's no-op default
void* gameEventHandler = nullptr;

struct Reconnection
{
    Reconnect phase        = Reconnect::Connected;
    ULONGLONG until        = 0;
    bool      statusLoaded = false;
    Load      status[std::size(kStatusLoads)];
    Load      lists[std::size(kListLoads)];
} reconnection;

// Replaces polcore's PlayOnline cipher; the relay encrypts the traffic instead
void __cdecl PlainCrypt(const uint8_t* const source, uint8_t* const destination, const int32_t length, [[maybe_unused]] void* const context, [[maybe_unused]] const int32_t reset)
{
    if (length > 0 && source != destination)
    {
        memmove(destination, source, length);
    }
}

auto call(const PolFunction function) -> Command
{
    return reinterpret_cast<Command>(session.table[tableIndex(function)]);
}

// polcore reads the five dial-up settings through these pointers, so they point at an empty buffer
// Opening overwrites the password and the IRC host, so both are set after it
void openConnection()
{
    static uint8_t        zero[0x400] = {};
    static ConnectionData connection  = { .kind = 1, .dialUp = { zero, zero, zero, zero, zero } };

    call(PolFunction::PolconOpen)(3, &connection);
    call(PolFunction::SetPassword)(session.encodedPassword, 0);

    uint8_t encodedHost[0x42] = {};
    call(PolFunction::EncodeHost)(encodedHost, "ci000.pol.com");
    call(PolFunction::SetPolcomHost)(encodedHost);
}

// The user slot picks the local message folder; without message notices polcore marks every incoming message as lost
void configureSession()
{
    call(PolFunction::SetUserSlot)(session.slot);
    call(PolFunction::MessageNotices)(1);
}

// Blocking; steps one of polcore's option file state machines to completion
auto runOptionStep(const PolFunction check) -> bool
{
    int result = 0;
    while ((result = call(check)()) == 0)
    {
        call(PolFunction::PolconIdle)();
        Sleep(kPollIntervalMs);
    }

    return result == 1;
}

// Seeds pub\homeNN\option.bin from the viewer's default the way account creation does.
// FFXiMain only loads and stores an existing file, so without it in-game PlayOnline settings such as the profanity filter never persist.
void seedOptionFile(const std::filesystem::path& slot)
{
    const auto file = slot / "option.bin";

    // polcore opens the file for writing without creating it, so it has to exist before the store
    if (!std::ofstream(file, std::ios::binary))
    {
        xiloader::console::output(xiloader::color::warning, "Failed to create the PlayOnline option file %s.", std::filesystem::path(file).make_preferred().string().c_str());
        return;
    }

    call(PolFunction::LoadOptionDefault)();
    auto seeded = runOptionStep(PolFunction::LoadOptionCheck);
    if (seeded)
    {
        call(PolFunction::StoreOption)();
        seeded = runOptionStep(PolFunction::StoreOptionCheck);
    }

    call(PolFunction::FreeOption)();

    if (!seeded)
    {
        // An empty file would be loaded as the user's options
        std::error_code error;
        std::filesystem::remove(file, error);
    }

    xiloader::console::output(seeded ? xiloader::color::success : xiloader::color::warning, seeded ? "Created the PlayOnline option file." : "Failed to create the PlayOnline option file.");
}

void startLoads(const std::span<Load> loads)
{
    for (auto& load : loads)
    {
        load.ticket = call(load.setup)();
        load.result = load.ticket < 0 ? load.ticket : 0;
    }
}

// Checks each pending load once; true when none is pending any more
auto checkLoads(const std::span<Load> loads) -> bool
{
    for (auto& load : loads)
    {
        if (load.result == 0)
        {
            load.result = call(load.check)(load.ticket);
        }
    }

    return std::ranges::none_of(loads, [](const Load& load)
                                {
                                    return load.result == 0;
                                });
}

// Warns about each failed load; true when all of them succeeded
auto reportLoads(const std::span<const Load> loads) -> bool
{
    for (const auto& load : loads)
    {
        if (load.result != 1)
        {
            xiloader::console::output(xiloader::color::warning, "Failed to load the %s list (0x%X).", load.name, load.result);
        }
    }

    return std::ranges::all_of(loads, [](const Load& load)
                               {
                                   return load.result == 1;
                               });
}

// Blocking; only used before the game starts
auto runLoads(const std::span<Load> loads) -> bool
{
    startLoads(loads);

    while (!checkLoads(loads))
    {
        call(PolFunction::PolconIdle)();
        Sleep(kPollIntervalMs);
    }

    return reportLoads(loads);
}

auto __cdecl recordEventHandler(void* const handler) -> int
{
    gameEventHandler = handler;
    return setEventHandler(handler);
}

// Makes the next IRC open install the game's event handler instead of polcore's no-op default
void keepGameEventHandler()
{
    if (gameEventHandler == nullptr)
    {
        return;
    }

    void* handlers[6] = { nullptr, session.table[tableIndex(PolFunction::NoticeHandler)], nullptr, session.table[tableIndex(PolFunction::PolconHandler3)], nullptr, gameEventHandler };
    call(PolFunction::PolconSetHandlers)(handlers);
}

// Randomized so clients dropped by a server restart don't all reconnect at once
auto retryDelay() -> ULONGLONG
{
    static std::mt19937_64                          generator{ std::random_device{}() };
    static std::uniform_int_distribution<ULONGLONG> delay{ kRetryDelayMinMs, kRetryDelayMaxMs };
    return delay(generator);
}

void retryLater()
{
    reconnection.phase = Reconnect::Waiting;
    reconnection.until = GetTickCount64() + retryDelay();
}

void reconnectAfter(const int pollResult)
{
    xiloader::console::output(xiloader::color::warning, "Lost connection to the profile server (0x%X), reconnecting...", pollResult);
    retryLater();
}

// Reloads the lists without reconnecting
void reloadLater()
{
    xiloader::console::output(xiloader::color::warning, "Retrying the profile load later.");
    reconnection.phase = Reconnect::Reloading;
    reconnection.until = GetTickCount64() + retryDelay();
}

void startStatusLoads()
{
    std::ranges::copy(kStatusLoads, reconnection.status);
    startLoads(reconnection.status);
    reconnection.phase = Reconnect::LoadingStatus;
}

// Called every frame; the game keeps pumping polcore while this waits
void stepReconnect(const int pollResult)
{
    const auto now = GetTickCount64();
    switch (reconnection.phase)
    {
        case Reconnect::Connected:
            if (pollResult < 0)
            {
                reconnectAfter(pollResult);
            }
            break;

        case Reconnect::Waiting:
            if (now >= reconnection.until)
            {
                keepGameEventHandler();
                openConnection();
                reconnection.phase = Reconnect::Opening;
                reconnection.until = now + kConnectDeadlineMs;
            }
            break;

        case Reconnect::Opening:
        {
            const auto state = static_cast<PolconState>(call(PolFunction::PolconStep)());
            if (state == PolconState::Connected)
            {
                // The poll keeps reporting the old error until it is cleared
                call(PolFunction::PolconClearError)();
                configureSession();
                xiloader::console::output(xiloader::color::success, "Reconnected to the profile server.");
                startStatusLoads();
            }
            else if (state == PolconState::Failed || static_cast<int>(state) < 0 || now >= reconnection.until)
            {
                xiloader::console::output(xiloader::color::warning, "Failed to reconnect to the profile server (0x%X), retrying later.", static_cast<int>(state));
                retryLater();
            }
            break;
        }

        // An unchecked ticket keeps its slot, so loads finish even if IRC drops; no new batch starts after a drop
        case Reconnect::LoadingStatus:
            if (checkLoads(reconnection.status))
            {
                reconnection.statusLoaded = reportLoads(reconnection.status);
                if (pollResult < 0)
                {
                    reconnectAfter(pollResult);
                    break;
                }

                std::ranges::copy(kListLoads, reconnection.lists);
                startLoads(reconnection.lists);
                reconnection.phase = Reconnect::LoadingLists;
            }
            break;

        case Reconnect::LoadingLists:
            if (checkLoads(reconnection.lists))
            {
                const auto listsLoaded = reportLoads(reconnection.lists);
                if (pollResult < 0)
                {
                    reconnectAfter(pollResult);
                    break;
                }

                if (!reconnection.statusLoaded || !listsLoaded)
                {
                    reloadLater();
                    break;
                }

                xiloader::console::output(xiloader::color::success, "Profile reloaded.");
                reconnection.phase = Reconnect::Connected;
            }
            break;

        case Reconnect::Reloading:
            if (pollResult < 0)
            {
                reconnectAfter(pollResult);
            }
            else if (now >= reconnection.until)
            {
                startStatusLoads();
            }
            break;
    }
}

// Hides errors from FFXiMain, which would leave the game with POL-xxxx, and drives the reconnect
auto __cdecl pollIgnoringDisconnect() -> int
{
    const auto result = polconPoll();
    stepReconnect(result);
    return result < 0 ? 0 : result;
}

} // namespace

namespace xiloader::playonline
{

auto disableCipher(const Language language) -> bool
{
    const char* const module = (language == Language::European) ? "polcoreeu.dll" : "polcore.dll";

    // The IRC send path: push 1; push edx; lea eax,[ebx+8]; push edi; lea ecx,[esp+0x1c]; push eax; push ecx; call cipher
    const unsigned char site[] = { 0x6A, 0x01, 0x52, 0x8D, 0x43, 0x08, 0x57, 0x8D, 0x4C, 0x24, 0x1C, 0x50, 0x51, 0xE8 };

    const auto found = xiloader::memory::FindPattern(module, site, "xxxxxxxxxxxxxx");
    if (!found)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate the IRC send path in %s. This PlayOnline version is not supported, or --lang doesn't match your install.", module);
        return false;
    }

    const auto callSite = reinterpret_cast<uint8_t*>(found) + sizeof(site) - 1;
    const auto cipher   = callSite + 5 + *reinterpret_cast<const int32_t*>(callSite + 1);

    // jmp PlainCrypt over the cipher's first bytes; both take the same cdecl arguments
    DWORD protection = 0;
    if (!VirtualProtect(cipher, 5, PAGE_EXECUTE_READWRITE, &protection))
    {
        xiloader::console::output(xiloader::color::error, "Failed to patch %s (error %lu). Security software may be blocking changes to its code.", module, GetLastError());
        return false;
    }

    cipher[0]                               = 0xE9;
    *reinterpret_cast<int32_t*>(cipher + 1) = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&PlainCrypt) - reinterpret_cast<uintptr_t>(cipher + 5));
    VirtualProtect(cipher, 5, protection, &protection);
    FlushInstructionCache(GetCurrentProcess(), cipher, 5);
    return true;
}

void setEnglishMessageTexts(const CommandTable table)
{
    const char* const titles[] = {
        "Let's be friends!",
        "Friend registration accepted",
        "Friend registration declined",
        "Deleted",
        "Please delete.",
        "Would you like to join a friend group?",
        "Group registration accepted",
        "Group registration declined",
        "Removed from friend group",
        "Friend group disbanded",
    };

    // Same %s placeholders as the Japanese texts they replace
    const char* const texts[] = {
        "Would you like to be friends?",
        "%s accepted friend registration.\nWill be added to Friend List.",
        "%s declined friend registration.",
        nullptr,
        "The name you entered is unavailable.\nPlease choose another name.",
        "%s has agreed to join\nthe group \"%s.\"",
        "%s has declined to join\nthe group \"%s.\"",
        "You have been removed from\nthe group \"%s.\"",
        "The group \"%s\"\nhas been disbanded.",
    };

    for (std::size_t i = 0; i < std::size(titles); ++i)
    {
        table[tableIndex(PolFunction::SetMessageTitle)](i, titles[i]);
    }

    for (std::size_t i = 0; i < std::size(texts); ++i)
    {
        if (texts[i] != nullptr)
        {
            table[tableIndex(PolFunction::SetMessageText)](i, texts[i]);
        }
    }
}

auto logIn(const CommandTable table, const uint32_t accountId, const Language language) -> bool
{
    session.table = table;

    // Step 1: Compute a POL ID - we'll use the account ID, masked then formatted by polcore
    using MaskPolId     = uint64_t(__cdecl*)(uint32_t, uint32_t);
    const auto masked   = reinterpret_cast<MaskPolId>(session.table[tableIndex(PolFunction::MaskPolid)])(accountId, 0);
    char       polId[9] = {};
    call(PolFunction::FormatPolid)(static_cast<uint32_t>(masked), static_cast<uint32_t>(masked >> 32), polId);

    // Step 2.1.: Pick a POL Password - polcore signs with it, but the relay authenticates the connection so the server never checks it
    char               password[16] = {};
    std::random_device random;
    for (int i = 0; i < 15; ++i)
    {
        password[i] = kPasswordCharacters[random() % (sizeof(kPasswordCharacters) - 1)];
    }

    // Step 2.2.: Encode the password as polcore stores it
    call(PolFunction::EncodePassword)(session.encodedPassword, password);

    // Step 3: Encode and store the POL ID
    uint8_t encodedPolId[8] = {};
    call(PolFunction::EncodePolid)(encodedPolId, polId);
    call(PolFunction::SetPolid)(encodedPolId);

    // Step 4: Pick a user slot - it selects pub\homeNN, where the game keeps local message copies
    //
    // NOTE: This is a custom piece of code to ensure we're not sending different accounts to the same home folders.
    // While not entirely critical, this ensures unrelated POL messages are not showing on different accounts.
    // PlayOnline Viewer assigns each account to a different folder according to the order they were created (1-8).
    // The underlying polcore code supports up to 99 so we're starting from 50 to not conflict with retail either.
    //
    // polcore is not capable of creating the folders directly so we have to do it ourselves.
    session.slot    = 50 + static_cast<int>(accountId % 50);
    const auto slot = std::filesystem::path(xiloader::registry::GetPlayOnlineInstallFolder(language)) / std::format("pub/home{:02}", session.slot);
    const auto home = slot / "msg";
    for (const char* const folder : { "s/a", "s/b", "r/a", "r/b" })
    {
        std::error_code error;
        std::filesystem::create_directories(home / folder, error);
        if (error)
        {
            xiloader::console::output(xiloader::color::warning, "Failed to create the message folder %s (%s).", (home / folder).string().c_str(), error.message().c_str());
        }
    }

    // Step 5: Open the PlayOnline connection with the password and the IRC host
    openConnection();

    // Step 6: Drive polcore's connect state machine until the IRC session is up or fails
    const auto deadline = GetTickCount64() + kConnectDeadlineMs;
    auto       state    = PolconState::Init;
    while (GetTickCount64() < deadline)
    {
        state = static_cast<PolconState>(call(PolFunction::PolconStep)());
        if (state == PolconState::Connected || state == PolconState::Failed || static_cast<int>(state) < 0)
        {
            break;
        }

        call(PolFunction::PolconIdle)();
        Sleep(kPollIntervalMs);
    }

    if (state != PolconState::Connected)
    {
        xiloader::console::output(xiloader::color::error, "Failed to connect to the profile server (0x%X).", static_cast<int>(state));
        return false;
    }

    xiloader::console::output(xiloader::color::success, "Connected to the profile server.");

    // Step 7: Apply the user slot and turn on message notices like the viewer does
    configureSession();
    if (!std::filesystem::exists(slot / "option.bin"))
    {
        seedOptionFile(slot);
    }

    // Step 8: Load the lists the viewer loads after login
    Load status[std::size(kStatusLoads)];
    Load lists[std::size(kListLoads)];
    std::ranges::copy(kStatusLoads, status);
    std::ranges::copy(kListLoads, lists);

    const auto statusLoaded = runLoads(status);
    const auto listsLoaded  = runLoads(lists);
    if (!statusLoaded || !listsLoaded)
    {
        reloadLater();
        return true;
    }

    xiloader::console::output(xiloader::color::success, "Profile loaded.");
    return true;
}

void keepGameOnDisconnect(CommandFunc** const table)
{
    polconPoll                                 = reinterpret_cast<Command>(table[tableIndex(PolFunction::PolconPoll)]);
    table[tableIndex(PolFunction::PolconPoll)] = reinterpret_cast<CommandFunc*>(&pollIgnoringDisconnect);

    setEventHandler                                 = reinterpret_cast<Command>(table[tableIndex(PolFunction::SetEventHandler)]);
    table[tableIndex(PolFunction::SetEventHandler)] = reinterpret_cast<CommandFunc*>(&recordEventHandler);
}

} // namespace xiloader::playonline
