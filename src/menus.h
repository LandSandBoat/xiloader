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

#pragma once

#include "ftxui/component/captured_mouse.hpp"     // for ftxui
#include "ftxui/component/component.hpp"          // for Menu
#include "ftxui/component/component_options.hpp"  // for MenuOption
#include "ftxui/component/screen_interactive.hpp" // for ScreenInteractive

#include "trust_token.h"

#include "enums/menu_selection.h"

namespace menus
{

using namespace ftxui;

// Wine's console doesn't interpret VT sequences, so FTXUI output shows up as raw escape codes.
inline bool plainConsole()
{
    static const bool isWine = ::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "wine_get_version") != nullptr;
    return isWine;
}

inline std::string promptLine(const char* label, bool hidden = false)
{
    auto  stdinHandle = ::GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode        = 0;
    if (hidden)
    {
        ::GetConsoleMode(stdinHandle, &mode);
        ::SetConsoleMode(stdinHandle, mode & ~ENABLE_ECHO_INPUT);
    }

    std::cout << label << std::flush;
    std::string line;
    std::getline(std::cin, line);

    if (hidden)
    {
        ::SetConsoleMode(stdinHandle, mode);
        std::cout << std::endl;
    }

    return line;
}

// Shows a numbered menu and returns the selected index. Entries are expected to be prefixed "1) ", "2) ", ...
inline int pickEntry(const std::vector<std::string>& entries)
{
    const auto count = static_cast<int>(entries.size());

    if (plainConsole())
    {
        for (const auto& entry : entries)
        {
            std::cout << "  " << entry << std::endl;
        }

        while (std::cin)
        {
            const auto line = promptLine("> ");
            if (line.size() == 1 && line[0] >= '1' && line[0] < '1' + count)
            {
                return line[0] - '1';
            }
        }

        return count - 1; // stdin closed, last entry is always exit/cancel
    }

    auto screen   = ScreenInteractive::TerminalOutput();
    int  selected = 0; // Container::Vertical requires `int` input

    Components items;
    for (const auto& entry : entries)
    {
        items.push_back(MenuEntry(entry));
    }

    auto menu = Container::Vertical(items, &selected);

    menu |= border; // Add border

    // clang-format off
        menu |= CatchEvent([&](Event event)
        {
            if (event.is_character())
            {
                auto const c = event.character()[0];
                if (c >= '1' && c < '1' + count)
                {
                    selected = c - '1';
                    screen.Exit();
                    return true;
                }
            }
            else if (event == Event::Return)
            {
                screen.Exit();
                return true;
            }

            return false;
        });
    // clang-format on

    screen.Loop(menu);

    return selected;
}

MenuSelection twoFactorSubMenu()
{
    const auto selected = pickEntry({
        "1) Register 2FA OTP",
        "2) Remove 2FA OTP",
        "3) Regenerate 2FA OTP removal code",
        "4) Validate 2FA OTP",
        "5) Revoke Computer Trust",
        "6) Exit Menu",
    });

    // Because ftxui is rigid with its input, return a menu selection here
    switch (selected)
    {
        case 0:
        {
            return MenuSelection::RegisterTwoFactorOTP;
        }
        case 1:
        {
            return MenuSelection::RemoveTwoFactorOTP;
        }
        case 2:
        {
            return MenuSelection::RegenerateTwoFactorRemovalCode;
        }
        case 3:
        {
            return MenuSelection::ValidateTwoFactorOTP;
        }
        case 4:
        {
            return MenuSelection::RevokeComputerTrust;
        }
        case 5:
        default:
        {
            return MenuSelection::None; // In this instance, the caller will replay the main menu
        }
    }
}

MenuSelection mainMenu()
{
    const auto selected = pickEntry({
        "1) Login",
        "2) Create New Account",
        "3) Change Account Password",
        "4) 2FA Options",
        "5) Exit",
    });

    // Because ftxui is rigid with its input, get a menu selection here
    switch (selected)
    {
        case 0:
        {
            return MenuSelection::Login;
        }
        case 1:
        {
            return MenuSelection::CreateAccount;
        }
        case 2:
        {
            return MenuSelection::ChangePassword;
        }
        case 3:
        {
            return MenuSelection::TwoFactorSubmenu;
        }
        case 4:
        {
            return MenuSelection::Exit;
        }
            [[fallthrough]];
        default:
        {
            return MenuSelection::None; // In this instance, we will exit
        }
    }

    return MenuSelection::None;
}

void enterCredentialsWithOTP(std::string& username, std::string& password, std::string& OTP, bool* trustThisComputer = nullptr, const std::string& serverAddress = "")
{
    if (plainConsole())
    {
        username = promptLine("  Username: ");
        password = promptLine("  Password: ", true);
        if (!serverAddress.empty() && !loadTrustToken(serverAddress, username).empty())
        {
            return;
        }

        OTP = promptLine("  OTP Code (blank if none): ");
        if (trustThisComputer)
        {
            const auto answer  = promptLine("  Trust this computer? (y/N): ");
            *trustThisComputer = answer == "y" || answer == "Y";
        }
        return;
    }

    ftxui::InputOption password_option;
    password_option.password = true;

    ftxui::Component input_username = ftxui::Input(&username, "");
    ftxui::Component input_password = ftxui::Input(&password, "", password_option);
    ftxui::Component input_otp      = ftxui::Input(&OTP, "");

    std::vector<ftxui::Component> components = { input_username, input_password, input_otp };

    ftxui::Component checkbox_trust;
    if (trustThisComputer)
    {
        checkbox_trust = ftxui::Checkbox("Trust this computer", trustThisComputer);
        components.push_back(checkbox_trust);
    }

    auto component = ftxui::Container::Vertical(components);

    auto screen = ftxui::ScreenInteractive::TerminalOutput();

    // Trust token cache — only re-check when username changes
    std::string lastCheckedUser;
    bool        isTrusted = false;

    // clang-format off
        component |= ftxui::CatchEvent([&](ftxui::Event event)
        {
            if (event == event.Return)
            {
                if (input_username->Focused())
                {
                    input_password->TakeFocus();
                }
                else if (input_password->Focused())
                {
                    if (isTrusted)
                    {
                        screen.Exit();
                    }
                    else
                    {
                        input_otp->TakeFocus();
                    }
                }
                else if (input_otp->Focused())
                {
                    if (checkbox_trust)
                    {
                        checkbox_trust->TakeFocus();
                    }
                    else
                    {
                        screen.Exit();
                    }
                }
                else if (checkbox_trust && checkbox_trust->Focused())
                {
                    screen.Exit();
                }
                return true;
            }
            return false;
        });
    // clang-format on

    // Tweak how the component tree is rendered:
    // clang-format off
        auto renderer = ftxui::Renderer(component, [&]
        {
                // Check trust status when username changes
                if (!serverAddress.empty() && username != lastCheckedUser)
                {
                    lastCheckedUser = username;
                    isTrusted = !username.empty() && !loadTrustToken(serverAddress, username).empty();
                    if (isTrusted)
                    {
                        OTP.clear();
                    }
                }

                auto elements = std::vector<ftxui::Element>{
                    ftxui::hbox(ftxui::text("  Username: "), input_username->Render()),
                    ftxui::hbox(ftxui::text("  Password: "), input_password->Render()),
                };

                if (isTrusted)
                {
                    elements.push_back(ftxui::hbox(ftxui::text("  OTP Code: "), input_otp->Render(), ftxui::text(" (optional - trusted)") | ftxui::color(ftxui::Color::GrayDark)));
                    elements.push_back(ftxui::hbox(ftxui::text("  Computer is trusted") | ftxui::color(ftxui::Color::Green)));
                }
                else
                {
                    elements.push_back(ftxui::hbox(ftxui::text("  OTP Code: "), input_otp->Render()));
                    if (checkbox_trust)
                    {
                        elements.push_back(ftxui::hbox(ftxui::text("  "), checkbox_trust->Render()));
                    }
                }

                return ftxui::vbox(elements) | ftxui::border;
        });
    // clang-format on

    screen.Loop(renderer);
}

void enterCredentialsNoOTP(std::string& username, std::string& password)
{
    if (plainConsole())
    {
        username = promptLine("  Username: ");
        password = promptLine("  Password: ", true);
        return;
    }

    ftxui::InputOption password_option;
    password_option.password = true;

    ftxui::Component input_username = ftxui::Input(&username, "");
    ftxui::Component input_password = ftxui::Input(&password, "", password_option);

    // The component tree:
    auto component = ftxui::Container::Vertical({
        input_username,
        input_password,
    });

    auto screen = ftxui::ScreenInteractive::TerminalOutput();

    // clang-format off
        component |= ftxui::CatchEvent([&](ftxui::Event event)
        {
            if (event == event.Return)
            {
                if (input_username->Focused())
                {
                    input_password->TakeFocus();
                }
                else if (input_password->Focused())
                {
                    screen.Exit();
                }
                return true;
            }
            return false;
        });
    // clang-format on

    // Tweak how the component tree is rendered:
    // clang-format off
        auto renderer = ftxui::Renderer(component, [&]
        {
                return ftxui::vbox({    ftxui::hbox(ftxui::text("  Username: "), input_username->Render()),
                                        ftxui::hbox(ftxui::text("  Password: "), input_password->Render()),
                                   }) | ftxui::border;
        });
    // clang-format on

    screen.Loop(renderer);
}

bool confirmNewPassword(std::string& confirmed_password)
{
    if (plainConsole())
    {
        const auto newPassword = promptLine("  Password        : ", true);
        confirmed_password     = promptLine("  Confirm Password: ", true);
        return confirmed_password == newPassword;
    }

    ftxui::InputOption password_option;
    password_option.password = true;

    std::string new_password = "";
    confirmed_password       = "";

    ftxui::Component input_password           = ftxui::Input(&new_password, "", password_option);
    ftxui::Component input_confirmed_password = ftxui::Input(&confirmed_password, "", password_option);

    // The component tree:
    auto component = ftxui::Container::Vertical({
        input_password,
        input_confirmed_password,
    });

    auto screen = ftxui::ScreenInteractive::TerminalOutput();

    // clang-format off
        component |= ftxui::CatchEvent([&](ftxui::Event event)
        {
            if (event == event.Return)
            {
                if (input_password->Focused()) // 1st password field focused
                {
                    input_confirmed_password->TakeFocus();
                }
                else // confirmed password focused
                {
                    screen.Exit();
                }
                return true;
            }
            return false;
        });
    // clang-format on

    // Tweak how the component tree is rendered:
    // clang-format off
        auto renderer = ftxui::Renderer(component, [&]
        {
                return ftxui::vbox({    ftxui::hbox(ftxui::text("  Password        : "), input_password->Render()),
                                        ftxui::hbox(ftxui::text("  Confirm Password: "), input_confirmed_password->Render())
                                    }) | ftxui::border;
        });
    // clang-format on

    screen.Loop(renderer);

    if (confirmed_password != new_password)
    {
        return false;
    }

    return true;
}

bool okCancelDialog(std::string input)
{
    return pickEntry({ "1) " + input, "2) Cancel" }) == 0;
}

bool createNewAccount(std::string& username, std::string& confirmed_password)
{
    if (plainConsole())
    {
        username               = promptLine("  Username        : ");
        const auto newPassword = promptLine("  Password        : ", true);
        confirmed_password     = promptLine("  Confirm Password: ", true);
        return confirmed_password == newPassword;
    }

    ftxui::InputOption password_option;
    password_option.password = true;

    std::string password = "";
    username             = "";
    confirmed_password   = "";

    ftxui::Component input_username           = ftxui::Input(&username, "");
    ftxui::Component input_password           = ftxui::Input(&password, "", password_option);
    ftxui::Component input_confirmed_password = ftxui::Input(&confirmed_password, "", password_option);

    // The component tree:
    auto component = ftxui::Container::Vertical({
        input_username,
        input_password,
        input_confirmed_password,
    });

    auto screen = ftxui::ScreenInteractive::TerminalOutput();

    // clang-format off
        component |= ftxui::CatchEvent([&](ftxui::Event event)
        {
            if (event == event.Return)
            {
                if (input_username->Focused())
                {
                    input_password->TakeFocus();
                }
                else if (input_password->Focused()) // 1st password field focused
                {
                    input_confirmed_password->TakeFocus();
                }
                else // confirmed password focused
                {
                    screen.Exit();
                }
                return true;
            }
            return false;
        });
    // clang-format on

    // Tweak how the component tree is rendered:
    // clang-format off
        auto renderer = ftxui::Renderer(component, [&]
        {
            return ftxui::vbox(
            {
                ftxui::hbox(ftxui::text("  Username        : "), input_username->Render()),
                ftxui::hbox(ftxui::text("  Password        : "), input_password->Render()),
                ftxui::hbox(ftxui::text("  Confirm Password: "), input_confirmed_password->Render())
            }) | ftxui::border;
        });
    // clang-format on

    screen.Loop(renderer);

    if (confirmed_password != password)
    {
        return false;
    }

    return true;
}

void enterUsernameOnly(std::string& username)
{
    if (plainConsole())
    {
        username = promptLine("  Username: ");
        return;
    }

    ftxui::Component input_username = ftxui::Input(&username, "");

    auto component = ftxui::Container::Vertical({
        input_username,
    });

    auto screen = ftxui::ScreenInteractive::TerminalOutput();

    // clang-format off
        component |= ftxui::CatchEvent([&](ftxui::Event event)
        {
            if (event == event.Return)
            {
                screen.Exit();
                return true;
            }
            return false;
        });
    // clang-format on

    // clang-format off
        auto renderer = ftxui::Renderer(component, [&]
        {
                return ftxui::vbox({    ftxui::hbox(ftxui::text("  Username: "), input_username->Render()),
                                   }) | ftxui::border;
        });
    // clang-format on

    screen.Loop(renderer);
}

} // namespace menus
