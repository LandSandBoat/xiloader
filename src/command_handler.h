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

#include "defines.h"
#include "helpers.h"
#include "network.h"
#include "otp/trust_token_manager.h"
#include "ui/prompts.h"

#include "enums/login_result.h"

#include <shellapi.h>

#include <nlohmann/json.hpp>
#include <qrcodegen.hpp>

using json = nlohmann::json;

bool handleLoginCommand(xiloader::LoginResult command, json& login_reply_json, uint32_t& accountId, SOCKET& sock, const xiloader::TrustTokenManager& trustTokens, xiloader::ui::Menu& menu)
{
    /* Handle the obtained result.. */
    switch (command)
    {
        case xiloader::LoginResult::LoginSuccess:
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
                std::memcpy(&xiloader::state.sessionHash, maybeSessionHash.value().data(), maybeSessionHash.value().size());
            }
            else
            {
                xiloader::console::output(xiloader::color::error, "xi_connect failed to reply with a valid session hash");
                break;
            }

            xiloader::console::output(xiloader::color::success, "Successfully logged in as %s!", xiloader::config.username.c_str());

            trustTokens.acceptLoginReply(login_reply_json, xiloader::config.username);

            shutdown(sock, SD_BOTH);

            return true;
        }
        case xiloader::LoginResult::LoginError:
        {
            xiloader::console::output(xiloader::color::error, "Failed to login. Invalid username or password.");

            return false;
        }
        case xiloader::LoginResult::CreateAccountSuccess:
        {
            xiloader::console::output(xiloader::color::success, "Account successfully created!");

            return false;
        }
        case xiloader::LoginResult::CreateAccountError:
        {
            xiloader::console::output(xiloader::color::error, "Failed to create the new account. Username already taken.");

            return false;
        }
        case xiloader::LoginResult::ChangePasswordSuccess:
        {
            xiloader::console::output(xiloader::color::success, "Password updated successfully!");
            xiloader::config.password.clear();

            return false;
        }
        case xiloader::LoginResult::ChangePasswordError:
        {
            xiloader::console::output(xiloader::color::error, "Failed to change password.");
            xiloader::config.password.clear();

            return false;
        }

        case xiloader::LoginResult::AlreadyLoggedIn:
        {
            xiloader::console::output(xiloader::color::error, "Failed to login. Account already logged in.");

            return false;
        }
        case xiloader::LoginResult::VersionMismatch:
        {
            xiloader::console::output(xiloader::color::error, "Failed to login. Expected xiloader version mismatch; check with your provider.");

            return false;
        }

        case xiloader::LoginResult::TrustTokenInvalid:
        {
            trustTokens.revoke(xiloader::config.username);
            xiloader::console::output(xiloader::color::error, "==========================================================");
            xiloader::console::output(xiloader::color::error, "Trust token rejected! It has been cleared from this computer.");
            xiloader::console::output(xiloader::color::error, "Please log in again and enter your OTP code.");
            xiloader::console::output(xiloader::color::error, "==========================================================");

            return false;
        }

        case xiloader::LoginResult::CreateTotpSuccess:
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

            bool display = xiloader::ui::okCancelDialog(menu, "Open QR code in my default browser");
            if (display)
            {
                // ShellExecuteA returns a value above 32 on success
                const auto opened = reinterpret_cast<INT_PTR>(ShellExecuteA(nullptr, "open", svgFilePath.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
                if (opened <= 32)
                {
                    xiloader::console::output(xiloader::color::error, "Failed to open the QR code (error %d). Open %s manually.", static_cast<int>(opened), svgFilePath.c_str());
                }

                xiloader::console::output(xiloader::color::info, "Once saved please use the \"Validate 2FA OTP\" option to verify the OTP.");
            }

            return false;
        }

        case xiloader::LoginResult::VerifyTotpSuccess:
        {
            xiloader::console::output(xiloader::color::info, "Your TOTP has been registered with the server");
            xiloader::console::output(xiloader::color::info, "You are now required to use an OTP to login.");

            std::optional<std::string> maybeRecoveryCode = jsonGet<std::string>(login_reply_json, "recovery_code");
            if (maybeRecoveryCode.has_value())
            {
                xiloader::console::output(xiloader::color::info, "Your recovery code is '%s'. Please write this down!", maybeRecoveryCode.value().c_str());
                xiloader::console::output(xiloader::color::info, "Tip: Try using shift + leftclick to select the text if it doesn't work.", maybeRecoveryCode.value().c_str());
                xiloader::console::output(xiloader::color::info, "You may remove your TOTP with this recovery code.");
            }

            std::string svgFilePath = getTemporaryPath() + "temp.svg";
            if (std::filesystem::exists(svgFilePath))
            {
                std::filesystem::remove(svgFilePath);
            }

            return false;
        }

        case xiloader::LoginResult::RemoveTotpSuccess:
        {
            xiloader::console::output(xiloader::color::info, "Your TOTP has been removed.");
            xiloader::console::output(xiloader::color::info, "You no longer need to use an OTP code to login.");

            trustTokens.revoke(xiloader::config.username);

            return false;
        }

        default:
        {
            xiloader::console::output(xiloader::color::error, "The login server sent an unknown result (0x%02X). Check this xiloader version is supported by the server.", static_cast<uint8_t>(command));
            break;
        }
    }

    return false;
}
