/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

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

#include "defines.h"

#include <ctime>

#include "console.h"
#include "functions.h"
#include "network.h"

#include "argparse/argparse.hpp"

/* Global Variables */
xiloader::Language g_Language = xiloader::Language::English; // The language of the loader to be used for polcore.
std::string g_ServerAddress = "127.0.0.1"; // The server address to connect to.
std::string g_ServerPort = "51220"; // The server lobby server port to connect to.
std::string g_LoginDataPort = "54230"; // Login server data port to connect to
std::string g_LoginViewPort = "54001"; // Login view port to connect to
std::string g_LoginAuthPort = "54231"; // Login auth port to connect to
std::string g_Username = ""; // The username being logged in with.
std::string g_Password = ""; // The password being logged in with.
char* g_CharacterList = NULL; // Pointer to the character list data being sent from the server.
bool g_IsRunning = false; // Flag to determine if the network threads should hault.
bool g_Hide = false; // Determines whether or not to hide the console window after FFXI starts.

/* Hairpin Fix Variables */
DWORD g_NewServerAddress; // Hairpin server address to be overriden with.
DWORD g_HairpinReturnAddress; // Hairpin return address to allow the code cave to return properly.

/**
 * @brief Detour function definitions.
 */
extern "C"
{
    hostent* (WINAPI __stdcall * Real_gethostbyname)(const char* name) = gethostbyname;
}

/**
 * @brief Hairpin fix codecave.
 */
__declspec(naked) void HairpinFixCave(void)
{
    __asm mov eax, g_NewServerAddress
    __asm mov [edx + 0x012E90], eax
    __asm mov [edx], eax
    __asm jmp g_HairpinReturnAddress
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
    xiloader::network::ResolveHostname(g_ServerAddress.c_str(), &g_NewServerAddress);

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
    auto caveDest = ((int)HairpinFixCave - ((int)hairpinAddress)) - 5;
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
 * @param name      The hostname to obtain information of.
 *
 * @return Hostname information object.
 */
hostent* __stdcall Mine_gethostbyname(const char* name)
{
    xiloader::console::output(xiloader::color::debug, "Resolving host: %s", name);

    if (!strcmp("ffxi00.pol.com", name))
        return Real_gethostbyname(g_ServerAddress.c_str());
    if (!strcmp("pp000.pol.com", name))
        return Real_gethostbyname("127.0.0.1");

    return Real_gethostbyname(name);
}

/**
 * @brief Locates the INET mutex function call inside of polcore.dll
 *
 * @return The pointer to the function call.
 */
inline DWORD FindINETMutex(void)
{
    const char* module = (g_Language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x8B\x56\x2C\x8B\x46\x28\x8B\x4E\x24\x52\x50\x51", "xxxxxxxxxxxx");
    return (*(DWORD*)(result - 4) + (result));
}

/**
 * @brief Locates the PlayOnline connection object inside of polcore.dll
 *
 * @return Pointer to the pol connection object.
 */
inline DWORD FindPolConn(void)
{
    const char* module = (g_Language == xiloader::Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto result = (DWORD)xiloader::functions::FindPattern(module, (BYTE*)"\x81\xC6\x38\x03\x00\x00\x83\xC4\x04\x81\xFE", "xxxxxxxxxxx");
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
    argparse::ArgumentParser args("xiloader", "0.0");

    args.add_argument("--server").help("The server address to connect to.");
    args.add_argument("--user", "--username").help("The username being logged in with.");
    args.add_argument("--pass", "--password").help("The password being logged in with.");

    args.add_argument("--serverport").help("(optional) The server's lobby port to connect to.");

    args.add_argument("--dataport").help("(optional) The login server data port to connect to.");

    args.add_argument("--viewport").help("(optional) The login view port to connect to.");

    args.add_argument("--authport").help("(optional) The login auth port to connect to.");

    args.add_argument("--lang").help("(optional) The language of your FFXI install: JP/US/EU (0/1/2).");

    args.add_argument("--hairpin")
        .implicit_value(true)
        .help("(optional) Use this if connecting to a local server which you have exposed publicly. This should not have to be used if you are connecting to a remote server.");

    args.add_argument("--hide")
        .implicit_value(true)
        .help("(optional) Determines whether or not to hide the console window after FFXI starts.");

    try
    {
        args.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << args;
        std::exit(1);
    }

    g_ServerAddress = args.is_used("--server") ? args.get<std::string>("--server") : g_ServerAddress;
    g_ServerPort    = args.is_used("--serverport") ? args.get<std::string>("--serverport") : g_ServerPort;

    g_LoginDataPort = args.is_used("--dataport") ? args.get<std::string>("--dataport") : g_LoginDataPort;
    g_LoginViewPort = args.is_used("--viewport") ? args.get<std::string>("--viewport") : g_LoginViewPort;
    g_LoginAuthPort = args.is_used("--authport") ? args.get<std::string>("--authport") : g_LoginAuthPort;

    g_Username = args.is_used("--user") ? args.get<std::string>("--user") : g_Username;
    g_Password = args.is_used("--pass") ? args.get<std::string>("--pass") : g_Password;

    if (args.is_used("--lang"))
    {
        std::string language = args.get<std::string>("--lang");

        if (!_strnicmp(language.c_str(), "JP", 2) || !_strnicmp(language.c_str(), "0", 1))
        {
            g_Language = xiloader::Language::Japanese;
        }
        if (!_strnicmp(language.c_str(), "US", 2) || !_strnicmp(language.c_str(), "1", 1))
        {
            g_Language = xiloader::Language::English;
        }
        if (!_strnicmp(language.c_str(), "EU", 2) || !_strnicmp(language.c_str(), "2", 1))
        {
            g_Language = xiloader::Language::European;
        }
    }

    bool bUseHairpinFix = args.is_used("--hairpin") ? args.get<bool>("--hairpin") : false;

    g_Hide = args.is_used("--hide") ? args.get<bool>("--hide") : g_Hide;

    /* Output the banner.. */
    time_t currentTime = time(NULL);
    int currentYear = localtime(&currentTime)->tm_year + 1900;  // Year is returned as the number of years since 1900.
    xiloader::console::output(xiloader::color::lightred, "==========================================================");
    xiloader::console::output(xiloader::color::lightgreen, "DarkStar Boot Loader (c) 2015 DarkStar Team");
    xiloader::console::output(xiloader::color::lightgreen, "LandSandBoat Boot Loader (c) 2021-%d LandSandBoat Team", currentYear);
    xiloader::console::output(xiloader::color::lightpurple, "Bug Reports: https://github.com/DarkstarProject/darkstar/issues");
    xiloader::console::output(xiloader::color::lightpurple, "Git Repo   : https://github.com/DarkstarProject/darkstar");
    xiloader::console::output(xiloader::color::lightred, "==========================================================");

    /* Initialize Winsock */
    WSADATA wsaData = { 0 };
    auto ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
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
    if (DetourTransactionCommit() != NO_ERROR)
    {
        /* Cleanup COM and Winsock */
        CoUninitialize();
        WSACleanup();

        xiloader::console::output(xiloader::color::error, "Failed to detour function 'gethostbyname'. Cannot continue!");
        return 1;
    }

    /* Read Command Arguments */
    for (auto x = 1; x < argc; ++x)
    {
        /* Server Address Argument */
        if (!_strnicmp(argv[x], "--server", 8))
        {
            g_ServerAddress = argv[++x];
            continue;
        }

        /* Server Port Argument */
        if (!_strnicmp(argv[x], "--serverport", 6))
        {
            g_ServerPort = argv[++x];
            continue;
        }

        /* Login Data Port Argument */
        if (!_strnicmp(argv[x], "--dataport", 6))
        {
            g_LoginDataPort = argv[++x];
            continue;
        }

        /* Login View Port Argument */
        if (!_strnicmp(argv[x], "--viewport", 6))
        {
            g_LoginViewPort = argv[++x];
            continue;
        }

        /* Login Auth Port Argument */
        if (!_strnicmp(argv[x], "--authport", 6))
        {
            g_LoginAuthPort = argv[++x];
            continue;
        }

        /* Username Argument */
        if (!_strnicmp(argv[x], "--user", 6))
        {
            g_Username = argv[++x];
            continue;
        }

        /* Password Argument */
        if (!_strnicmp(argv[x], "--pass", 6))
        {
            g_Password = argv[++x];
            continue;
        }

        /* Language Argument */
        if (!_strnicmp(argv[x], "--lang", 6))
        {
            std::string language = argv[++x];

            if (!_strnicmp(language.c_str(), "JP", 2) || !_strnicmp(language.c_str(), "0", 1))
                g_Language = xiloader::Language::Japanese;
            if (!_strnicmp(language.c_str(), "US", 2) || !_strnicmp(language.c_str(), "1", 1))
                g_Language = xiloader::Language::English;
            if (!_strnicmp(language.c_str(), "EU", 2) || !_strnicmp(language.c_str(), "2", 1))
                g_Language = xiloader::Language::European;

            continue;
        }

        /* Hairpin Argument */
        if (!_strnicmp(argv[x], "--hairpin", 9))
        {
            bUseHairpinFix = true;
            continue;
        }

        /* Hide Argument */
        if (!_strnicmp(argv[x], "--hide", 6))
        {
            g_Hide = true;
            continue;
        }

        xiloader::console::output(xiloader::color::warning, "Found unknown command argument: %s", argv[x]);
    }

    /* Attempt to resolve the server address.. */
    ULONG ulAddress = 0;
    if (xiloader::network::ResolveHostname(g_ServerAddress.c_str(), &ulAddress))
    {
        g_ServerAddress = inet_ntoa(*((struct in_addr*)&ulAddress));

        /* Attempt to create socket to server..*/
        xiloader::datasocket sock;
        if (xiloader::network::CreateConnection(&sock, g_LoginAuthPort.c_str()))
        {
            /* Attempt to verify the users account info.. */
            while (!xiloader::network::VerifyAccount(&sock))
                Sleep(10);

            /* Start hairpin hack thread if required.. */
            if (bUseHairpinFix)
            {
                CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ApplyHairpinFixThread, NULL, 0, NULL);
            }

            /* Create listen servers.. */
            g_IsRunning = true;
            HANDLE hFFXiServer = CreateThread(NULL, 0, xiloader::network::FFXiServer, &sock, 0, NULL);
            HANDLE hPolServer = CreateThread(NULL, 0, xiloader::network::PolServer, NULL, 0, NULL);

            /* Attempt to create polcore instance..*/
            IPOLCoreCom* polcore = NULL;
            if (CoCreateInstance(xiloader::CLSID_POLCoreCom[g_Language], NULL, 0x17, xiloader::IID_IPOLCoreCom[g_Language], (LPVOID*)&polcore) != S_OK)
            {
                xiloader::console::output(xiloader::color::error, "Failed to initialize instance of polcore!");
            }
            else
            {
                /* Invoke the setup functions for polcore.. */
                //Create string for the login view port
                std::string polcorecmd = " /game eAZcFcB -net 3 -port " + g_LoginViewPort;
                //Cast to an LPSTR
                LPSTR cmd = const_cast<char*>(polcorecmd.c_str());
                polcore->SetAreaCode(g_Language);
                polcore->SetParamInit(GetModuleHandle(NULL), cmd);

                /* Obtain the common function table.. */
                void * (**lpCommandTable)(...);
                polcore->GetCommonFunctionTable((unsigned long**)&lpCommandTable);

                /* Invoke the inet mutex function.. */
                auto findMutex = (void * (*)(...))FindINETMutex();
                findMutex();

                /* Locate and prepare the pol connection.. */
                auto polConnection = (char*)FindPolConn();
                memset(polConnection, 0x00, 0x68);
                auto enc = (char*)malloc(0x1000);
                memset(enc, 0x00, 0x1000);
                memcpy(polConnection + 0x48, &enc, sizeof(char**));

                /* Locate the character storage buffer.. */
                g_CharacterList = (char*)FindCharacters((void **)lpCommandTable);

                /* Invoke the setup functions for polcore.. */
                lpCommandTable[POLFUNC_REGISTRY_LANG](g_Language);
                lpCommandTable[POLFUNC_FFXI_LANG](xiloader::functions::GetRegistryPlayOnlineLanguage(g_Language));
                lpCommandTable[POLFUNC_REGISTRY_KEY](xiloader::functions::GetRegistryPlayOnlineKey(g_Language));
                lpCommandTable[POLFUNC_INSTALL_FOLDER](xiloader::functions::GetRegistryPlayOnlineInstallFolder(g_Language));
                lpCommandTable[POLFUNC_INET_MUTEX]();

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
            g_IsRunning = false;    
            TerminateThread(hFFXiServer, 0);
            TerminateThread(hPolServer, 0);

            WaitForSingleObject(hFFXiServer, 1000);
            WaitForSingleObject(hPolServer, 1000);

            CloseHandle(hFFXiServer);
            CloseHandle(hPolServer);
        }
    }
    else
    {
        xiloader::console::output(xiloader::color::error, "Failed to resolve server hostname.");
    }

    /* Detach detour for gethostbyname. */
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourTransactionCommit();

    /* Cleanup COM and Winsock */
    CoUninitialize();
    WSACleanup();

    xiloader::console::output(xiloader::color::error, "Closing...");
    Sleep(2000);

    return ERROR_SUCCESS;
}
