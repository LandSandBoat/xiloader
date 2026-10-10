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

#include "prompts.h"

#include "otp/trust_token_manager.h"

namespace xiloader::ui
{

auto mainMenu(Menu& menu) -> MenuSelection
{
    constexpr MenuSelection kSelections[] = {
        MenuSelection::Login,
        MenuSelection::CreateAccount,
        MenuSelection::ChangePassword,
        MenuSelection::TwoFactorSubmenu,
        MenuSelection::Exit,
    };

    return kSelections[menu.pick({
        "1) Login",
        "2) Create New Account",
        "3) Change Account Password",
        "4) 2FA Options",
        "5) Exit",
    })];
}

auto twoFactorSubMenu(Menu& menu) -> MenuSelection
{
    constexpr MenuSelection kSelections[] = {
        MenuSelection::RegisterTwoFactorOTP,
        MenuSelection::RemoveTwoFactorOTP,
        MenuSelection::RegenerateTwoFactorRemovalCode,
        MenuSelection::ValidateTwoFactorOTP,
        MenuSelection::RevokeComputerTrust,
        MenuSelection::None, // In this instance, the caller will replay the main menu
    };

    return kSelections[menu.pick({
        "1) Register 2FA OTP",
        "2) Remove 2FA OTP",
        "3) Regenerate 2FA OTP removal code",
        "4) Validate 2FA OTP",
        "5) Revoke Computer Trust",
        "6) Exit Menu",
    })];
}

void enterCredentialsWithOTP(Menu& menu, std::string& username, std::string& password, std::string& OTP, bool* trustThisComputer, const TrustTokenManager* trustTokens)
{
    // Trust token cache — only re-check when username changes
    std::string lastCheckedUser;
    bool        isTrusted = false;

    const auto trusted = [&]
    {
        if (trustTokens && username != lastCheckedUser)
        {
            lastCheckedUser = username;
            isTrusted       = !username.empty() && trustTokens->isTrusted(username);
            if (isTrusted)
            {
                OTP.clear();
            }
        }

        return isTrusted;
    };

    std::vector<Field> fields = {
        { .label = "Username", .text = &username },
        { .label = "Password", .text = &password, .hidden = true },
        { .label = "OTP Code (blank if none)", .text = &OTP, .skipped = trusted },
    };

    if (trustThisComputer)
    {
        fields.push_back({ .label = "Trust this computer", .checked = trustThisComputer, .skipped = trusted });
    }

    menu.form(fields, [&]
              {
                  if (trusted())
                  {
                      return std::string("Computer is trusted");
                  }

                  return std::string();
              });
}

void enterCredentialsNoOTP(Menu& menu, std::string& username, std::string& password)
{
    menu.form({
        { .label = "Username", .text = &username },
        { .label = "Password", .text = &password, .hidden = true },
    });
}

void enterUsernameOnly(Menu& menu, std::string& username)
{
    menu.form({ { .label = "Username", .text = &username } });
}

auto confirmNewPassword(Menu& menu, std::string& confirmedPassword) -> bool
{
    std::string newPassword;
    confirmedPassword.clear();

    menu.form({
        { .label = "Password        ", .text = &newPassword, .hidden = true },
        { .label = "Confirm Password", .text = &confirmedPassword, .hidden = true },
    });

    return confirmedPassword == newPassword;
}

auto createNewAccount(Menu& menu, std::string& username, std::string& confirmedPassword) -> bool
{
    std::string password;
    username.clear();
    confirmedPassword.clear();

    menu.form({
        { .label = "Username        ", .text = &username },
        { .label = "Password        ", .text = &password, .hidden = true },
        { .label = "Confirm Password", .text = &confirmedPassword, .hidden = true },
    });

    return confirmedPassword == password;
}

auto okCancelDialog(Menu& menu, const std::string& input) -> bool
{
    return menu.pick({ "1) " + input, "2) Cancel" }) == 0;
}

} // namespace xiloader::ui
