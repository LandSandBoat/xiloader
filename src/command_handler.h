/*
===========================================================================

  Copyright (c) 2025 LandSandBoat Dev Teams

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

/* Externals */
namespace globals
{
    extern std::string            g_ServerAddress;
    extern std::string            g_Username;
    extern std::string            g_Password;
    extern std::string            g_OtpCode;
    extern char                   g_SessionHash[16];
    extern std::string            g_Email;
    extern std::array<uint8_t, 3> g_VersionNumber;
    extern uint16_t               g_ServerPort;
    extern uint16_t               g_LoginDataPort;
    extern uint16_t               g_LoginViewPort;
    extern uint16_t               g_LoginAuthPort;
    extern char*                  g_CharacterList;
    extern bool                   g_IsRunning;
    extern bool                   g_FirstLogin;
} // namespace globals

#include "defines.h"
#include "helpers.h"
#include "network.h"

#include <nlohmann/json.hpp>
#include <qrcodegen.hpp>

using json = nlohmann::json;

bool handleLoginCommand(int8_t command, json& login_reply_json, uint32_t& accountId, SOCKET& sock)
{
    /* Handle the obtained result.. */
    switch (command)
    {
        case 0x0001: // Success (Login)
        {
            std::optional maybeAccountId = jsonGet<uint32_t>(login_reply_json, "account_id");
            if (maybeAccountId.has_value())
            {
                accountId = maybeAccountId.value();
            }
            else
            {
                xiloader::console::output(xiloader::color::error, "xi_connect failed to reply with an account ID");
                break;
            }

            auto maybeSessionHash = jsonGet<char, 16>(login_reply_json, "session_hash");

            if (maybeSessionHash.has_value())
            {
                std::memcpy(&globals::g_SessionHash, maybeSessionHash.value().data(), maybeSessionHash.value().size());
            }
            else
            {
                xiloader::console::output(xiloader::color::error, "xi_connect failed to reply with a valid session hash");
                break;
            }

            xiloader::console::output(xiloader::color::success, "Successfully logged in as %s!", globals::g_Username.c_str());

            shutdown(sock, SD_BOTH);

            return true;
        }
        case 0x0002: // Error (Login)
        {
            xiloader::console::output(xiloader::color::error, "Failed to login. Invalid username or password.");

            return false;
        }
        case 0x0003: // Success (Create Account)
        {
            xiloader::console::output(xiloader::color::success, "Account successfully created!");

            return false;
        }
        case 0x0004: // Error (Create Account)
        {
            xiloader::console::output(xiloader::color::error, "Failed to create the new account. Username already taken.");

            return false;
        }
        case 0x0006: // Success (Changed Password)
        {
            xiloader::console::output(xiloader::color::success, "Password updated successfully!");
            globals::g_Password.clear();

            return false;
        }
        case 0x0007: // Error (Changed Password)
        {
            xiloader::console::output(xiloader::color::error, "Failed to change password.");
            globals::g_Password.clear();

            return false;
        }

        // Commands 0x0008 through 0x0008 are currently unused

        case 0x000A:
        {
            xiloader::console::output(xiloader::color::error, "Failed to login. Account already logged in.");

            return false;
        }
        case 0x000B:
        {
            xiloader::console::output(xiloader::color::error, "Failed to login. Expected xiloader version mismatch; check with your provider.");

            return false;
        }

        // LOGIN_SUCCESS_CREATE_TOTP
        case 0x0010:
        {
            std::string                uri      = "";
            std::optional<std::string> maybeURI = jsonGet<std::string>(login_reply_json, "TOTP_uri");
            if (maybeURI.has_value())
            {
                uri = maybeURI.value();
            }
            else
            {
                xiloader::console::output(xiloader::color::error, "xi_connect failed to reply with a valid TOTP_uri");
                return false;
            }

            qrcodegen::QrCode qrCode = qrcodegen::QrCode::encodeText(uri.c_str(), qrcodegen::QrCode::Ecc::LOW);

            std::string svgString   = qrToSvgString(qrCode, 4);
            std::string svgFilePath = writeSvgToDisk("temp.svg", svgString);

            xiloader::console::output(xiloader::color::info, "Open your authenticator application on your phone and prepare to scan the QR code.");

            bool display = menus::okCancelDialog("Open QR code in my default browser");
            if (display)
            {
                ShellExecuteA(nullptr, "open", svgFilePath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                xiloader::console::output(xiloader::color::info, "Once saved please use the \"Validate 2FA OTP\" option to verify the OTP.");
            }

            return false;
        }

        // LOGIN_SUCCESS_VERIFY_TOTP
        case 0x0011:
        {
            xiloader::console::output(xiloader::color::info, "Your TOTP has been registered with the server");
            xiloader::console::output(xiloader::color::info, "You are now required to use an OTP to login.");

            std::optional<std::string> maybeRecoveryCode = jsonGet<std::string>(login_reply_json, "recovery_code");
            if (maybeRecoveryCode.has_value())
            {
                xiloader::console::output(xiloader::color::info, "Your recovery code is '%s'. Please write this down!", maybeRecoveryCode.value().c_str());
                xiloader::console::output(xiloader::color::info, "Tip: Try using shift + leftclick to select the text if it doesn't work.", maybeRecoveryCode.value().c_str());
                xiloader::console::output(xiloader::color::info, "You may remove you may remove your TOTP with this recovery code.");
            }

            std::string svgFilePath = getTemporaryPath() + "temp.svg";
            if (std::filesystem::exists(svgFilePath))
            {
                std::filesystem::remove(svgFilePath);
            }

            return false;
        }

        // LOGIN_SUCCESS_REMOVE_TOTP
        case 0x0012:
        {
            xiloader::console::output(xiloader::color::info, "Your TOTP has been removed.");
            xiloader::console::output(xiloader::color::info, "You no longer need to use an OTP code to login.");

            return false;
        }

    }

    return false;
}
