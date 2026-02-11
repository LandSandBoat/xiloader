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

enum class MenuSelection : uint8_t
{
    None                           = 0,
    Login                          = 1,
    CreateAccount                  = 2,
    ChangePassword                 = 3,
    TwoFactorSubmenu               = 4, // Not a command to be processed
    RegisterTwoFactorOTP           = 5,
    RemoveTwoFactorOTP             = 6,
    RegenerateTwoFactorRemovalCode = 7,
    ValidateTwoFactorOTP           = 8,
    RevokeComputerTrust            = 9,
    Exit                           = 255,
};

namespace menus
{
    using namespace ftxui;

    MenuSelection twoFactorSubMenu()
    {
        auto screen   = ScreenInteractive::TerminalOutput();
        int  selected = 0; // Container::Vertical requires `int` input

        // clang-format off
        auto menu = Container::Vertical(
        {
            MenuEntry("1) Register 2FA OTP"),
            MenuEntry("2) Remove 2FA OTP"),
            MenuEntry("3) Regenerate 2FA OTP removal code"),
            MenuEntry("4) Validate 2FA OTP"),
            MenuEntry("5) Revoke Computer Trust"),
            MenuEntry("6) Exit Menu"),
        },
        &selected);

        menu |= border; // Add border

        menu |= CatchEvent([&](Event event)
        {
            if (event == Event::Character('1')) // Select "Register OTP"
            {
                selected = 0;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('2')) // Select "Remove OTP"
            {
                selected = 1;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('3')) // Select "Regenerate 2FA OTP removal code"
            {
                selected = 2;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('4')) // Select "Validate 2FA OTP"
            {
                selected = 3;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('5')) // Select "Revoke Computer Trust"
            {
                selected = 4;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('6')) // Select "Exit Menu"
            {
                selected = 5;
                screen.Exit();
                return true;
            }
            else if (event == event.Return)
            {
                screen.Exit();
                return true;
            }

            return false;
        });
        // clang-format on

        screen.Loop(menu);

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
        auto screen   = ScreenInteractive::TerminalOutput();
        int  selected = 0; // Container::Vertical requires `int` input

        // clang-format off
        auto menu = Container::Vertical(
        {
            MenuEntry("1) Login"),
            MenuEntry("2) Create New Account"),
            MenuEntry("3) Change Account Password"),
            MenuEntry("4) 2FA Options"),
            MenuEntry("5) Exit"),
        },
        &selected);

        menu |= border; // Add border

        menu |= CatchEvent([&](Event event)
        {

            if (event == Event::Character('1')) // Select "login"
            {
                selected = 0;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('2')) // Select "create new account"
            {
                selected = 1;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('3')) // Select "change account password"
            {
                selected = 2;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('4')) // Select "2FA Settings"
            {
                selected = 3;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('5')) // Select "Exit"
            {
                selected = 4;
                screen.Exit();
                return true;
            }
            else if (event == event.Return)
            {
                screen.Exit();
                return true;
            }

            return false;
        });
        // clang-format on

        screen.Loop(menu);

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
        ftxui::InputOption password_option;
        password_option.password = true;

        std::string new_password = "";
        confirmed_password = "";

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
        auto screen   = ScreenInteractive::TerminalOutput();
        int  selected = 0;

        // clang-format off
        auto menu = Container::Vertical(
        {
            MenuEntry("1) " + input ),
            MenuEntry("2) Cancel"),
        },
        &selected);

        menu |= border; // Add border

        menu |= CatchEvent([&](Event event)
        {

            if (event == Event::Character('1')) // Select "ok"
            {
                selected = 0;
                screen.Exit();
                return true;
            }
            else if (event == Event::Character('2')) // Select "cancel"
            {
                selected = 1;
                screen.Exit();
                return true;
            }
            else if (event == event.Return)
            {
                screen.Exit();
                return true;
            }

            return false;
        });
        // clang-format on

        screen.Loop(menu);

        return selected == 0;
    }
    bool createNewAccount(std::string& username, std::string& confirmed_password)
    {
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
