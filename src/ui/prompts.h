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

#include "menu.h"

#include "enums/menu_selection.h"

namespace xiloader
{

class TrustTokenManager;

}

namespace xiloader::ui
{

auto mainMenu(Menu& menu) -> MenuSelection;
auto twoFactorSubMenu(Menu& menu) -> MenuSelection;

// With trustTokens, the OTP code and the trust checkbox are skipped for a user this computer is trusted for
void enterCredentialsWithOTP(Menu& menu, std::string& username, std::string& password, std::string& OTP, bool* trustThisComputer = nullptr, const TrustTokenManager* trustTokens = nullptr);
void enterCredentialsNoOTP(Menu& menu, std::string& username, std::string& password);
void enterUsernameOnly(Menu& menu, std::string& username);

// Both return false when the two passwords differ
auto confirmNewPassword(Menu& menu, std::string& confirmedPassword) -> bool;
auto createNewAccount(Menu& menu, std::string& username, std::string& confirmedPassword) -> bool;

auto okCancelDialog(Menu& menu, const std::string& input) -> bool;

} // namespace xiloader::ui
