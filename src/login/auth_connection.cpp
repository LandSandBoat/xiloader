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

#include "auth_connection.h"

#include "console.h"

#include <format>

namespace
{

constexpr uint32_t    kReadTimeoutMs  = 1000;
constexpr std::size_t kRecvBufferSize = 8192;

} // namespace

namespace xiloader
{

AuthConnection::AuthConnection()
{
    mbedtls_net_init(&server);
    mbedtls_ssl_init(&ssl);
}

AuthConnection::~AuthConnection()
{
    mbedtls_net_free(&server);
    mbedtls_ssl_free(&ssl);
}

auto AuthConnection::connect(const std::string& address, const uint16_t port) -> std::expected<void, std::string>
{
    int ret = 0;

    if ((ret = config.setUp()) != 0)
    {
        return std::unexpected(std::format("Failed to set up TLS ({}).", mbedtlsErrorText(ret)));
    }

    ret = mbedtls_net_connect(&server, address.c_str(), std::to_string(port).c_str(), MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        return std::unexpected(std::format("mbedtls_net_connect failed, ({})", mbedtlsErrorText(ret)));
    }

    // MBEDTLS_SSL_VERIFY_OPTIONAL provides warnings, but doesn't stop connections.
    mbedtls_ssl_conf_authmode(config.get(), MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(config.get(), nullptr, nullptr); // No CA chain, so every certificate is reported as not trusted

    if ((ret = mbedtls_ssl_setup(&ssl, config.get())) != 0)
    {
        return std::unexpected(std::format("mbedtls_ssl_setup failed, ({})", mbedtlsErrorText(ret)));
    }

    mbedtls_ssl_set_bio(&ssl, &server, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            return std::unexpected(std::format("mbedtls_ssl_handshake returned -0x{:x}", (unsigned int)-ret));
        }
    }

    uint32_t flags = 0;

    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
    {
        // We genuinely don't care if the error flags is ONLY that the cert isn't trusted,
        // If this is the only warning, just don't print it.
        if (flags != MBEDTLS_X509_BADCERT_NOT_TRUSTED)
        {
            char              vrfy_buf[1024] = {};
            const std::string timestamp      = xiloader::console::getTimestamp();

            flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED; // Don't report the cert isn't trusted -- we don't care.

            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), timestamp.c_str(), flags);

            xiloader::console::output(xiloader::color::warning, "Remote server certificate warnings:");
            xiloader::console::print(xiloader::color::warning, vrfy_buf);
        }
    }
    else
    {
        xiloader::console::output(xiloader::color::info, "Remote server ({}) certificate is valid.", address);
    }

    mbedtls_ssl_conf_read_timeout(config.get(), kReadTimeoutMs);

    return {};
}

auto AuthConnection::exchange(const std::string& request) -> std::expected<std::string, std::string>
{
    if (const auto written = mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>(request.data()), request.size()); written < 0)
    {
        return std::unexpected(std::format("Failed to send the login request ({}). The login server may have closed the connection.", xiloader::mbedtlsErrorText(written)));
    }

    unsigned char recvBuffer[kRecvBufferSize] = { 0 };

    const auto received = mbedtls_ssl_read(&ssl, recvBuffer, sizeof(recvBuffer));
    if (received == MBEDTLS_ERR_SSL_TIMEOUT)
    {
        return std::unexpected(std::format("Remote failed to reply within the timeout, exiting..."));
    }

    if (received <= 0)
    {
        return std::unexpected(std::format("Failed to read the login reply ({}). The login server may have closed the connection.", xiloader::mbedtlsErrorText(received)));
    }

    return std::string(reinterpret_cast<const char*>(recvBuffer), received);
}

} // namespace xiloader
