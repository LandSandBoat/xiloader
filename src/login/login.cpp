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

#include "login.h"

#include "auth_connection.h"
#include "config.h"
#include "console.h"
#include "json_get.h"
#include "otp/qr_code.h"
#include "otp/trust_token_manager.h"
#include "ui/prompts.h"

#include "enums/login_command.h"
#include "enums/login_outcome.h"
#include "enums/login_result.h"

#include <optional>
#include <utility>

namespace
{

using xiloader::AuthConnection;
using xiloader::Config;
using xiloader::LoginCommand;
using xiloader::LoginOutcome;
using xiloader::LoginResult;
using xiloader::Session;
using xiloader::TrustTokenManager;
using xiloader::ui::Menu;

struct Request
{
    LoginCommand command = LoginCommand::None;
    std::string  newPassword;
};

auto selectAction(Menu& menu) -> MenuSelection
{
    auto selected = MenuSelection::None;

    // Check for None, because the 2FA submenu can select None and needs to replay the main menu.
    // Any other option is a "real" selection
    while (selected == MenuSelection::None)
    {
        xiloader::console::output("What would you like to do?");
        selected = xiloader::ui::mainMenu(menu);

        if (selected == MenuSelection::TwoFactorSubmenu)
        {
            xiloader::console::output("What would you like to do?");
            selected = xiloader::ui::twoFactorSubMenu(menu);
        }
    }

    return selected;
}

// Asks for what the selected action needs. Returns nothing when there is no request to send.
auto promptRequest(const MenuSelection selected, Config& config, Menu& menu, const TrustTokenManager& trustTokens) -> std::optional<Request>
{
    config.username = "";
    config.password = "";
    config.otpCode  = "";

    switch (selected)
    {
        case MenuSelection::Login:
        {
            xiloader::ui::enterCredentialsWithOTP(menu, config.username, config.password, config.otpCode, &config.trustThisComputer, &trustTokens);

            return Request{ .command = LoginCommand::Login };
        }
        case MenuSelection::CreateAccount:
        {
            xiloader::console::output("Please enter your desired login information.");
            xiloader::console::output("Username (3-15 characters)");
            xiloader::console::output("Password (6-32 characters)");

            while (!xiloader::ui::createNewAccount(menu, config.username, config.password))
            {
                xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
            }

            return Request{ .command = LoginCommand::CreateAccount };
        }
        case MenuSelection::ChangePassword:
        {
            xiloader::console::output("Before resetting your password, first verify your account details.");
            xiloader::console::output("Please enter your login information. The OTP code is only necessary if you have one registered.");

            xiloader::ui::enterCredentialsWithOTP(menu, config.username, config.password, config.otpCode);

            xiloader::console::output("Enter new password (6-32 characters): ");

            Request request{ .command = LoginCommand::ChangePassword };
            while (!xiloader::ui::confirmNewPassword(menu, request.newPassword))
            {
                xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
            }

            return request;
        }
        case MenuSelection::RegisterTwoFactorOTP:
        {
            xiloader::ui::enterCredentialsNoOTP(menu, config.username, config.password);

            return Request{ .command = LoginCommand::CreateTotp };
        }
        case MenuSelection::RemoveTwoFactorOTP:
        {
            xiloader::console::output("Please enter your login information; your OTP code may be substituted for the recovery code");
            xiloader::ui::enterCredentialsWithOTP(menu, config.username, config.password, config.otpCode);

            return Request{ .command = LoginCommand::RemoveTotp };
        }
        case MenuSelection::RegenerateTwoFactorRemovalCode:
        {
            xiloader::console::output("Please enter your login information; your OTP code may be substituted for the recovery code");
            xiloader::ui::enterCredentialsWithOTP(menu, config.username, config.password, config.otpCode);

            return Request{ .command = LoginCommand::RegenerateRecoveryCode };
        }
        case MenuSelection::ValidateTwoFactorOTP: // also enables OTP
        {
            xiloader::ui::enterCredentialsWithOTP(menu, config.username, config.password, config.otpCode);

            return Request{ .command = LoginCommand::VerifyTotp };
        }
        case MenuSelection::RevokeComputerTrust:
        {
            std::string revokeUsername;
            xiloader::console::output("Enter the username to revoke trust for:");
            xiloader::ui::enterUsernameOnly(menu, revokeUsername);
            trustTokens.revoke(revokeUsername);
            xiloader::console::output(xiloader::color::info, "Computer trust revoked for '{}'.", revokeUsername);

            return std::nullopt;
        }
        default:
        {
            xiloader::console::output("Invalid menu selection");

            return std::nullopt;
        }
    }
}

auto toJson(const Request& request, const Config& config, const TrustTokenManager& trustTokens) -> json
{
    json login_json;
    login_json["username"]     = config.username;
    login_json["password"]     = config.password;
    login_json["otp"]          = config.otpCode;
    login_json["new_password"] = request.newPassword;
    login_json["version"]      = xiloader::Config::versionNumber;
    login_json["command"]      = std::to_underlying(request.command);

    if (request.command == LoginCommand::Login) // Only send trust fields for login
    {
        trustTokens.addToLoginRequest(login_json, config.username, config.trustThisComputer);
    }

    return login_json;
}

auto onLoginSuccess(const json& reply, Session& session, const Config& config, const TrustTokenManager& trustTokens) -> LoginOutcome
{
    const auto maybeAccountId = jsonGet<uint32_t>(reply, "account_id");
    if (!maybeAccountId.has_value())
    {
        xiloader::console::output(xiloader::color::error, "xi_connect failed to reply with an account ID");
        return LoginOutcome::Retry;
    }

    const auto maybeSessionHash = jsonGet<char, 16>(reply, "session_hash");
    if (!maybeSessionHash.has_value())
    {
        xiloader::console::output(xiloader::color::error, "xi_connect failed to reply with a valid session hash");
        return LoginOutcome::Retry;
    }

    session.accountId = maybeAccountId.value();
    std::memcpy(&session.hash, maybeSessionHash.value().data(), maybeSessionHash.value().size());

    xiloader::console::output(xiloader::color::success, "Successfully logged in as {}!", config.username);

    trustTokens.acceptLoginReply(reply, config.username);

    return LoginOutcome::LoggedIn;
}

void onCreateTotpSuccess(const json& reply, Menu& menu)
{
    const auto maybeURI = jsonGet<std::string>(reply, "TOTP_uri");
    if (!maybeURI.has_value())
    {
        xiloader::console::output(xiloader::color::error, "xi_connect failed to reply with a valid TOTP_uri");
        return;
    }

    const auto svgFilePath = xiloader::otp::writeQrCode(maybeURI.value());

    xiloader::console::output(xiloader::color::info, "Open your authenticator application on your phone and prepare to scan the QR code.");

    if (xiloader::ui::okCancelDialog(menu, "Open QR code in my default browser"))
    {
        xiloader::otp::openQrCode(svgFilePath);

        xiloader::console::output(xiloader::color::info, "Once saved please use the \"Validate 2FA OTP\" option to verify the OTP.");
    }
}

void onVerifyTotpSuccess(const json& reply)
{
    xiloader::console::output(xiloader::color::info, "Your TOTP has been registered with the server");
    xiloader::console::output(xiloader::color::info, "You are now required to use an OTP to login.");

    const auto maybeRecoveryCode = jsonGet<std::string>(reply, "recovery_code");
    if (maybeRecoveryCode.has_value())
    {
        xiloader::console::output(xiloader::color::info, "Your recovery code is '{}'. Please write this down!", maybeRecoveryCode.value());
        xiloader::console::output(xiloader::color::info, "Tip: Try using shift + leftclick to select the text if it doesn't work.");
        xiloader::console::output(xiloader::color::info, "You may remove your TOTP with this recovery code.");
    }

    xiloader::otp::removeQrCode();
}

auto handleReply(const std::string& text, Session& session, Config& config, const TrustTokenManager& trustTokens, Menu& menu) -> LoginOutcome
{
    const auto reply = json::parse(text, nullptr, false);
    if (reply.is_discarded())
    {
        xiloader::console::output(xiloader::color::error, "Bad json reply from remote");
        return LoginOutcome::Retry;
    }

    const auto errorMessage = jsonGet<std::string>(reply, "error_message").value_or({}); // {} = empty string
    if (!errorMessage.empty())
    {
        xiloader::console::output(xiloader::color::error, "Error from remote:");
        xiloader::console::printMultiLine(errorMessage, "\n", xiloader::color::error);
        return LoginOutcome::Retry;
    }

    const auto maybeResult = jsonGet<int8_t>(reply, "result");
    if (!maybeResult.has_value())
    {
        xiloader::console::output(xiloader::color::error, "xi_connect didn't send a proper reply command");
        return LoginOutcome::Retry;
    }

    switch (static_cast<LoginResult>(maybeResult.value()))
    {
        case LoginResult::LoginSuccess:
        {
            return onLoginSuccess(reply, session, config, trustTokens);
        }
        case LoginResult::LoginError:
        {
            xiloader::console::output(xiloader::color::error, "Failed to login. Invalid username or password.");
            break;
        }
        case LoginResult::CreateAccountSuccess:
        {
            xiloader::console::output(xiloader::color::success, "Account successfully created!");
            break;
        }
        case LoginResult::CreateAccountError:
        {
            xiloader::console::output(xiloader::color::error, "Failed to create the new account. Username already taken.");
            break;
        }
        case LoginResult::ChangePasswordSuccess:
        {
            xiloader::console::output(xiloader::color::success, "Password updated successfully!");
            config.password.clear();
            break;
        }
        case LoginResult::ChangePasswordError:
        {
            xiloader::console::output(xiloader::color::error, "Failed to change password.");
            config.password.clear();
            break;
        }
        case LoginResult::AlreadyLoggedIn:
        {
            xiloader::console::output(xiloader::color::error, "Failed to login. Account already logged in.");
            break;
        }
        case LoginResult::VersionMismatch:
        {
            xiloader::console::output(xiloader::color::error, "Failed to login. Expected xiloader version mismatch; check with your provider.");
            break;
        }
        case LoginResult::TrustTokenInvalid:
        {
            trustTokens.revoke(config.username);
            xiloader::console::output(xiloader::color::error, "==========================================================");
            xiloader::console::output(xiloader::color::error, "Trust token rejected! It has been cleared from this computer.");
            xiloader::console::output(xiloader::color::error, "Please log in again and enter your OTP code.");
            xiloader::console::output(xiloader::color::error, "==========================================================");
            break;
        }
        case LoginResult::CreateTotpSuccess:
        {
            onCreateTotpSuccess(reply, menu);
            break;
        }
        case LoginResult::VerifyTotpSuccess:
        {
            onVerifyTotpSuccess(reply);
            break;
        }
        case LoginResult::RemoveTotpSuccess:
        {
            xiloader::console::output(xiloader::color::info, "Your TOTP has been removed.");
            xiloader::console::output(xiloader::color::info, "You no longer need to use an OTP code to login.");

            trustTokens.revoke(config.username);
            break;
        }
        default:
        {
            xiloader::console::output(xiloader::color::error, "The login server sent an unknown result (0x{:02X}). Check this xiloader version is supported by the server.", static_cast<uint8_t>(maybeResult.value()));
            break;
        }
    }

    return LoginOutcome::Retry;
}

auto attempt(AuthConnection& connection, Session& session, Config& config, bool& autoLogin, const TrustTokenManager& trustTokens, Menu& menu) -> LoginOutcome
{
    std::optional<Request> request;

    // Determine if we should auto-login..
    if (!config.username.empty() && !config.password.empty() && autoLogin)
    {
        xiloader::console::output(xiloader::color::lightgreen, "Autologin activated!");
        autoLogin = false;

        request = Request{ .command = LoginCommand::Login };
    }
    else
    {
        const auto selected = selectAction(menu);
        if (selected == MenuSelection::Exit)
        {
            return LoginOutcome::Quit;
        }

        request = promptRequest(selected, config, menu, trustTokens);
    }

    if (!request)
    {
        return LoginOutcome::Retry;
    }

    // Send info to server and obtain response..
    const auto reply = connection.exchange(toJson(*request, config, trustTokens).dump());
    if (!reply)
    {
        xiloader::console::output(xiloader::color::error, "{}", reply.error());
        return LoginOutcome::ConnectionLost;
    }

    return handleReply(*reply, session, config, trustTokens, menu);
}

} // namespace

namespace xiloader::login
{

auto run(AuthConnection& connection, Config& config) -> std::expected<Session, LoginOutcome>
{
    const TrustTokenManager trustTokens(config.serverAddress);
    const auto              menu = xiloader::ui::makeMenu(config.plainMenus);

    // Credentials supplied up front are tried once before the menu shows
    bool autoLogin = !config.username.empty() && !config.password.empty();

    Session session;
    auto    outcome = LoginOutcome::Retry;
    while (outcome == LoginOutcome::Retry)
    {
        outcome = attempt(connection, session, config, autoLogin, trustTokens, *menu);
    }

    if (outcome != LoginOutcome::LoggedIn)
    {
        return std::unexpected(outcome);
    }

    return session;
}

} // namespace xiloader::login
