/*
===========================================================================

Copyright (c) 2010-2015 Darkstar Dev Teams
Copyright (c) 2021-2026 LandSandBoat Dev Teams

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

This file is part of DarkStar-server source code.

===========================================================================
*/

#define NOMINMAX 1 // Interferes with std::numeric_limits

#include "defines.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <intrin.h>

#include "console.h"
#include "functions.h"
#include "helpers.h"
#include "login/auth_connection.h"
#include "login/login.h"
#include "network.h"
#include "playonline.h"
#include "polrelay.h"

#include "enums/lobby_command.h"

namespace xiloader
{

Config   config;
AppState state;

} // namespace xiloader

namespace
{

DWORD g_NewServerAddress;     // Hairpin server address to be overriden with.
DWORD g_HairpinReturnAddress; // Hairpin return address to allow the code cave to return properly.

} // namespace

/**
 * @brief Detour function definitions.
 */
extern "C"
{
    hostent*(WINAPI __stdcall* Real_gethostbyname)(const char* name)       = gethostbyname;
    int(WINAPI* Real_send)(SOCKET s, const char* buf, int len, int flags)  = send;
    int(WINAPI* Real_recv)(SOCKET s, char* buf, int len, int flags)        = recv;
    int(WINAPI* Real_connect)(SOCKET s, const sockaddr* name, int namelen) = connect;
}

/**
 * @brief Hairpin fix codecave.
 */
__declspec(naked) void HairpinFixCave(void){
    __asm mov eax, g_NewServerAddress __asm mov[edx + 0x012E90], eax __asm mov[edx], eax __asm jmp g_HairpinReturnAddress
}

/**
 * @brief Applies the hairpin fix modifications.
 *
 * @param lpParam       Thread param object.
 *
 * @return Non-important return.
 */
DWORD ApplyHairpinFixThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    do
    {
        /* Sleep until we find FFXiMain loaded.. */
        Sleep(100);
    } while (GetModuleHandleA("FFXiMain.dll") == NULL);

    /* Convert server address.. */
    if (!xiloader::network::ResolveHostname(xiloader::config.serverAddress.c_str(), &g_NewServerAddress))
    {
        xiloader::console::output(xiloader::color::error, "Hairpin fix failed to resolve the server address %s (winsock error %d).", xiloader::config.serverAddress.c_str(), WSAGetLastError());
    }

    // Locate the main hairpin location..
    //
    // As of 07.08.2013:
    //      8B 82 902E0100        - mov eax, [edx+00012E90]
    //      89 02                 - mov [edx], eax <-- edit this

    auto hairpinAddress = (DWORD)xiloader::functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x82\xFF\xFF\xFF\xFF\x89\x02\x8B\x0D", "xx????xxxx");
    if (hairpinAddress == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate main hairpin hack address!");
        return 0;
    }

    // Locate zoning IP change address..
    //
    // As of 07.08.2013
    //      74 08                 - je FFXiMain.dll+E5E72
    //      8B 0D 68322B03        - mov ecx, [FFXiMain.dll+463268]
    //      89 01                 - mov [ecx], eax <-- edit this
    //      8B 46 0C              - mov eax, [esi+0C]
    //      85 C0                 - test eax, eax

    auto zoneChangeAddress = (DWORD)xiloader::functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x0D\xFF\xFF\xFF\xFF\x89\x01\x8B\x46", "xx????xxxx");
    if (zoneChangeAddress == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate zone change hairpin address!");
        return 0;
    }

    /* Apply the hairpin fix.. */
    auto caveDest          = ((int)HairpinFixCave - ((int)hairpinAddress)) - 5;
    g_HairpinReturnAddress = hairpinAddress + 0x08;

    *(BYTE*)(hairpinAddress + 0x00) = 0xE9; // jmp
    *(UINT*)(hairpinAddress + 0x01) = caveDest;
    *(BYTE*)(hairpinAddress + 0x05) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x06) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x07) = 0x90; // nop

    /* Apply zone ip change patch.. */
    memset((LPVOID)(zoneChangeAddress + 0x06), 0x90, 2);

    xiloader::console::output(xiloader::color::success, "Hairpin fix applied!");
    return 0;
}

/**
 * @brief gethostbyname detour callback.
 *
 * @param name The hostname to obtain information of.
 *
 * @return Hostname information object.
 */
hostent* __stdcall Mine_gethostbyname(const char* name)
{
    xiloader::console::output(xiloader::color::debug, "Resolving host: %s", name);

    if (!strcmp("ffxi00.pol.com", name))
    {
        return Real_gethostbyname(xiloader::config.serverAddress.c_str());
    }

    // PlayOnline profile and IRC hosts (friend list and presence) go through the local TLS relay
    constexpr std::string_view kPlayOnlineHosts[] = { "pp000.pol.com", "ci000.pol.com", "gm000.pol.com", "gd000.pol.com" };
    if (std::ranges::find(kPlayOnlineHosts, std::string_view(name)) != std::end(kPlayOnlineHosts))
    {
        return Real_gethostbyname(xiloader::polrelay::address().c_str());
    }

    return Real_gethostbyname(name);
}

// This function's purpose is to identify a command byte and identify if it is meant for the lobby dataport or not.
// This way, we know we want to send.
bool isLobbyCommand(const char* buffer, SOCKET socket)
{
    struct sockaddr_in sin;
    int                addrlen = sizeof(sin);

    getpeername(socket, reinterpret_cast<struct sockaddr*>(&sin), &addrlen);

    auto port = ntohs(sin.sin_port);

    if (port != xiloader::config.loginDataPort && port != xiloader::config.loginViewPort)
    {
        return false;
    }

    switch (static_cast<xiloader::LobbyCommand>(buffer[8]))
    {
        case xiloader::LobbyCommand::SelectCharacter:
        case xiloader::LobbyCommand::DeleteCharacter:
        case xiloader::LobbyCommand::CharacterList:
        case xiloader::LobbyCommand::CharacterCreated:
        case xiloader::LobbyCommand::CreateCharacter:
        case xiloader::LobbyCommand::ServerName:
        case xiloader::LobbyCommand::Version:
        case xiloader::LobbyCommand::RenameCharacter:
        case xiloader::LobbyCommand::MoveGmCharacter:
            break;
        default:
            return false;
    }

    // Check for magic numbers (XIFF command)
    return buffer[4] == 0x49 && buffer[5] == 0x58 && buffer[6] == 0x46 && buffer[7] == 0x46;
}

/**
 * @brief send detour callback. https://man7.org/linux/man-pages/man2/send.2.html
 */
int WINAPI Mine_send(SOCKET s, const char* buf, int len, int flags)
{
    const auto ret = _ReturnAddress();
    std::ignore    = ret;

    // check for lobby specific commands
    if (isLobbyCommand(buf, s))
    {
        // always send server provided session hash in packets with XIFF commands and is a lobby command
        std::memcpy((char*)buf + 12, xiloader::state.sessionHash, 16);
    }

    return Real_send(s, buf, len, flags);
}

/**
 * @brief recv detour callback. https://man7.org/linux/man-pages/man2/recv.2.html
 */
int WINAPI Mine_recv(SOCKET s, char* buf, int len, int flags)
{
    const auto ret = _ReturnAddress();
    std::ignore    = ret;

    // xiloader::console::output(xiloader::color::lightblue, "recv %i", len);
    return Real_recv(s, buf, len, flags);
}

/**
 * @brief connect detour callback. https://man7.org/linux/man-pages/man2/connect.2.html
 */
int WINAPI Mine_connect(SOCKET s, const sockaddr* name, int namelen)
{
    // polcore's PlayOnline connections go to this process's relay ports
    if (name != nullptr && namelen >= static_cast<int>(sizeof(sockaddr_in)))
    {
        auto destination = *reinterpret_cast<const sockaddr_in*>(name);
        if (xiloader::polrelay::redirect(destination))
        {
            return Real_connect(s, reinterpret_cast<const sockaddr*>(&destination), sizeof(destination));
        }
    }

    int ret = Real_connect(s, name, namelen);

    return ret;
}

/**
 * @brief Locates the INET mutex function call inside of polcore.dll
 *
 * @return The pointer to the function call.
 */
inline DWORD FindINETMutex(void)
{
    const char* module = (xiloader::config.language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto        result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x8B\x56\x2C\x8B\x46\x28\x8B\x4E\x24\x52\x50\x51", "xxxxxxxxxxxx");
    if (result == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate the INET mutex in %s. This PlayOnline version is not supported, or --lang doesn't match your install.", module);
    }
    return (*(DWORD*)(result - 4) + (result));
}

/**
 * @brief Locates the PlayOnline connection object inside of polcore.dll
 *
 * @return Pointer to the pol connection object.
 */
inline DWORD FindPolConn(void)
{
    const char* module = (xiloader::config.language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto        result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x81\xC6\x38\x03\x00\x00\x83\xC4\x04\x81\xFE", "xxxxxxxxxxx");
    if (result == 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to locate the PlayOnline connection in %s. This PlayOnline version is not supported, or --lang doesn't match your install.", module);
    }
    return (*(DWORD*)(result - 10));
}

/**
 * @brief Locates the current character information block.
 *
 * @return Pointer to the character information table.
 */
inline LPVOID FindCharacters(void** commFuncs)
{
    LPVOID lpCharTable = NULL;
    memcpy(&lpCharTable, (char*)commFuncs[0xD3] + 31, sizeof(lpCharTable));
    return lpCharTable;
}

/**
 * @brief Main program entrypoint.
 *
 * @param argc      The count of arguments being passed to this application on launch.
 * @param argv      Pointer to array of argument data.
 *
 * @return 1 on error, 0 on success.
 */
int __cdecl main(int argc, char* argv[])
{
    try
    {
        xiloader::config = xiloader::Config::load(argc, argv);
    }
    catch (const std::exception& err)
    {
        std::cerr << err.what() << std::endl;
        return 1;
    }

    // Autologin when both were supplied
    xiloader::state.firstLogin = !xiloader::config.username.empty() && !xiloader::config.password.empty();

    std::array<uint8_t, 3> version = xiloader::Config::versionNumber;

    /* Output the banner.. */
    time_t currentTime = time(NULL);
    int    currentYear = localtime(&currentTime)->tm_year + 1900; // Year is returned as the number of years since 1900.
    xiloader::console::output(xiloader::color::lightred, "==========================================================");
    xiloader::console::output(xiloader::color::lightgreen, "DarkStar Boot Loader (c) 2015 DarkStar Team");
    xiloader::console::output(xiloader::color::lightgreen, "LandSandBoat Boot Loader (c) 2021-%d LandSandBoat Team (v%u.%u.%u)", currentYear, version[0], version[1], version[2]);
    xiloader::console::output(xiloader::color::lightblue, "Using %s", MBEDTLS_VERSION_STRING_FULL); // this prints "Using Mbed TLS #.#.#"
    xiloader::console::output(xiloader::color::lightpurple, "Git Repo   : https://github.com/LandSandBoat/xiloader");
    xiloader::console::output(xiloader::color::lightpurple, "Bug Reports: https://github.com/LandSandBoat/xiloader/issues");
    xiloader::console::output(xiloader::color::lightred, "==========================================================");

    /* Initialize Winsock */
    WSADATA wsaData = { 0 };
    auto    ret     = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0)
    {
        xiloader::console::output(xiloader::color::error, "Failed to initialize winsock, error code: %d", ret);
        return 1;
    }

    /* Initialize COM */
    auto hResult = CoInitialize(NULL);
    if (hResult != S_OK && hResult != S_FALSE)
    {
        /* Cleanup Winsock */
        WSACleanup();

        xiloader::console::output(xiloader::color::error, "Failed to initialize COM, error code: %d", hResult);
        return 1;
    }

    /* Attach detour for gethostbyname.. */
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourAttach(&(PVOID&)Real_send, Mine_send);
    DetourAttach(&(PVOID&)Real_recv, Mine_recv);
    DetourAttach(&(PVOID&)Real_connect, Mine_connect);
    if (DetourTransactionCommit() != NO_ERROR)
    {
        /* Cleanup COM and Winsock */
        CoUninitialize();
        WSACleanup();

        xiloader::console::output(xiloader::color::error, "Failed to detour function 'gethostbyname'. Cannot continue!");
        return 1;
    }

    xiloader::AuthConnection auth;

    /* Attempt to resolve the server address.. */
    ULONG ulAddress = 0;

    xiloader::console::output(xiloader::color::info, "Resolving '%s' ...", xiloader::config.serverAddress.c_str());

    if (xiloader::network::ResolveHostname(xiloader::config.serverAddress.c_str(), &ulAddress))
    {
        xiloader::config.serverAddress = inet_ntoa(*((struct in_addr*)&ulAddress));

        xiloader::console::output(xiloader::color::info, "Resolved server address to '%s:%d'", xiloader::config.serverAddress.c_str(), xiloader::config.loginAuthPort);

        /* Attempt to create socket to server..*/
        xiloader::datasocket sock;
        std::string          loginport = std::to_string(xiloader::config.loginDataPort);

        /* Attempt to verify the users account info.. */
        if (auth.connect(xiloader::config.serverAddress, xiloader::config.loginAuthPort) && xiloader::login::run(auth, sock.AccountId))
        {
            /* Attempt to create connection to the login server.. */
            if (!xiloader::network::CreateConnection(&sock, loginport.c_str()))
            {
                sock.s  = INVALID_SOCKET;
                int err = WSAGetLastError();
                xiloader::console::output(xiloader::color::error, "Failed to initialize connection to server on port %s, winsock error: %d", loginport.c_str(), err);
            }

            // Check if sockets are invalid
            if (sock.s != INVALID_SOCKET)
            {
                /* Start hairpin hack thread if required.. */
                if (xiloader::config.hairpin)
                {
                    // TODO: this is not terminated? Does it need to be?
                    if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ApplyHairpinFixThread, NULL, 0, NULL) == NULL)
                    {
                        xiloader::console::output(xiloader::color::error, "Failed to start the hairpin fix thread (error %lu).", GetLastError());
                    }
                }

                // Create lobby data thread
                xiloader::state.isRunning = true;
                HANDLE hFFXiServer        = CreateThread(NULL, 0, xiloader::network::FFXiServer, &sock, 0, NULL);
                if (hFFXiServer == NULL)
                {
                    xiloader::console::output(xiloader::color::error, "Failed to start the login data thread (error %lu).", GetLastError());
                }

                /* Attempt to create polcore instance..*/
                const auto   languageId = static_cast<int>(xiloader::config.language);
                IPOLCoreCom* polcore    = NULL;
                if (CoCreateInstance(xiloader::CLSID_POLCoreCom[languageId], NULL, 0x17, xiloader::IID_IPOLCoreCom[languageId], (LPVOID*)&polcore) != S_OK)
                {
                    xiloader::console::output(xiloader::color::error, "Failed to initialize instance of polcore!");
                }
                else
                {
                    /* Invoke the setup functions for polcore.. */
                    // Create string for the login view port
                    std::string polcorecmd = " /game eAZcFcB -net 3 -port " + std::to_string(xiloader::config.loginViewPort);
                    // Cast to an LPSTR
                    LPSTR cmd = const_cast<char*>(polcorecmd.c_str());
                    polcore->SetAreaCode(languageId);
                    if (const auto hr = polcore->SetParamInit(GetModuleHandle(NULL), cmd); FAILED(hr))
                    {
                        xiloader::console::output(xiloader::color::error, "polcore failed to initialize (0x%08lX).", hr);
                    }

                    /* Obtain the common function table.. */
                    xiloader::playonline::CommandFunc** lpCommandTable;
                    if (const auto hr = polcore->GetCommonFunctionTable((unsigned long**)&lpCommandTable); FAILED(hr))
                    {
                        xiloader::console::output(xiloader::color::error, "Failed to get polcore's function table (0x%08lX).", hr);
                    }

                    /* Invoke the inet mutex function.. */
                    auto findMutex = (void* (*)(...))FindINETMutex();
                    findMutex();

                    /* Locate and prepare the pol connection.. */
                    auto polConnection = (char*)FindPolConn();
                    memset(polConnection, 0x00, 0x68);
                    auto enc = (char*)malloc(0x1000);
                    memset(enc, 0x00, 0x1000);
                    memcpy(polConnection + 0x48, &enc, sizeof(char**));

                    /* Locate the character storage buffer.. */
                    xiloader::state.characterList = (char*)FindCharacters((void**)lpCommandTable);

                    /* Invoke the setup functions for polcore.. */
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::RegistryLang)](languageId);
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::FfxiLang)](xiloader::functions::GetRegistryPlayOnlineLanguage(xiloader::config.language));
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::RegistryKey)](xiloader::functions::GetRegistryPlayOnlineKey(xiloader::config.language));
                    const char* installFolder = xiloader::functions::GetRegistryPlayOnlineInstallFolder(xiloader::config.language);
                    if (installFolder[0] == '\0')
                    {
                        xiloader::console::output(xiloader::color::error, "PlayOnline install folder not found in the registry (HKLM\\%s\\InstallFolder). Check PlayOnline is installed and --lang matches your install.", xiloader::functions::GetRegistryPlayOnlineKey(xiloader::config.language));
                    }
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::InstallFolder)](installFolder);
                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::FileInit)](); // Initialize polcore file system

                    if (!xiloader::playonline::disableCipher())
                    {
                        xiloader::console::output(xiloader::color::error, "Unsupported polcore version.");
                        return 1;
                    }

                    if (!xiloader::polrelay::start(xiloader::config.profilePort, sock.AccountId))
                    {
                        return 1;
                    }

                    // Without the viewer, polcore keeps its built-in Japanese message texts
                    if (xiloader::config.language != xiloader::Language::Japanese)
                    {
                        xiloader::playonline::setEnglishMessageTexts(lpCommandTable);
                    }

                    lpCommandTable[xiloader::tableIndex(xiloader::PolFunction::InetMutex)]();

                    if (!xiloader::playonline::logIn(lpCommandTable, sock.AccountId))
                    {
                        return 1;
                    }

                    xiloader::playonline::keepGameOnDisconnect(lpCommandTable);

                    /* Attempt to create FFXi instance..*/
                    IFFXiEntry* ffxi = NULL;
                    if (CoCreateInstance(xiloader::CLSID_FFXiEntry, NULL, 0x17, xiloader::IID_IFFXiEntry, (LPVOID*)&ffxi) != S_OK)
                    {
                        xiloader::console::output(xiloader::color::error, "Failed to initialize instance of FFxi!");
                    }
                    else
                    {
                        /* Attempt to start Final Fantasy.. */
                        IUnknown* message = NULL;
                        xiloader::console::hide();
                        ffxi->GameStart(polcore, &message);
                        xiloader::console::show();
                        ffxi->Release();
                    }

                    /* Cleanup polcore object.. */
                    if (polcore != NULL)
                        polcore->Release();
                }

                /* Cleanup threads.. */
                xiloader::state.isRunning = false;
                TerminateThread(hFFXiServer, 0);
                WaitForSingleObject(hFFXiServer, 1000);
                CloseHandle(hFFXiServer);
            }
        }
    }
    else
    {
        xiloader::console::output(xiloader::color::error, "Failed to resolve server hostname.");
    }

    xiloader::polrelay::stop();

    /* Detach detour for gethostbyname. */
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourDetach(&(PVOID&)Real_send, Mine_send);
    DetourDetach(&(PVOID&)Real_recv, Mine_recv);
    DetourDetach(&(PVOID&)Real_connect, Mine_connect);
    DetourTransactionCommit();

    /* Cleanup COM and Winsock */
    CoUninitialize();
    WSACleanup();

    xiloader::console::output(xiloader::color::error, "Closing...");
    Sleep(2000);

    return ERROR_SUCCESS;
}
