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

#include "tls_client_config.h"

#include <mbedtls/base64.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>

#include <format>

namespace
{

constexpr std::size_t kErrorTextSize = 128;

// A SHA-256 hash, and room for it in base64 with its terminator
constexpr std::size_t kHashSize     = 32;
constexpr std::size_t kHashTextSize = 64;

} // namespace

namespace xiloader
{

auto mbedtlsErrorText(const int ret) -> std::string
{
    char text[kErrorTextSize] = {};
    mbedtls_strerror(ret, text, sizeof(text));
    return text;
}

auto peerFingerprint(const mbedtls_ssl_context& ssl) -> std::expected<std::string, std::string>
{
    const auto certificate = mbedtls_ssl_get_peer_cert(&ssl);
    if (certificate == nullptr)
    {
        return std::unexpected("The server presented no certificate.");
    }

    // The key rather than the whole certificate, so renewing a certificate for the same key changes nothing
    unsigned char hash[kHashSize] = {};
    if (const auto ret = mbedtls_sha256(certificate->pk_raw.p, certificate->pk_raw.len, hash, 0); ret != 0)
    {
        return std::unexpected(std::format("Failed to hash the server's key ({}).", mbedtlsErrorText(ret)));
    }

    unsigned char text[kHashTextSize] = {};
    std::size_t   length              = 0;
    if (const auto ret = mbedtls_base64_encode(text, sizeof(text), &length, hash, sizeof(hash)); ret != 0)
    {
        return std::unexpected(std::format("Failed to encode the server's key ({}).", mbedtlsErrorText(ret)));
    }

    std::string encoded(reinterpret_cast<const char*>(text), length);
    while (!encoded.empty() && encoded.back() == '=')
    {
        encoded.pop_back();
    }

    return "SHA256:" + encoded;
}

auto checkPeerKey(const mbedtls_ssl_context& ssl, const std::string& trustedKey) -> std::expected<void, std::string>
{
    const auto presented = peerFingerprint(ssl);
    if (!presented)
    {
        return std::unexpected(presented.error());
    }

    if (*presented != trustedKey)
    {
        return std::unexpected(std::format("server key {} is not the login server's", *presented));
    }

    return {};
}

TlsClientConfig::TlsClientConfig()
{
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&random);
    mbedtls_ssl_config_init(&config);
}

TlsClientConfig::~TlsClientConfig()
{
    mbedtls_ssl_config_free(&config);
    mbedtls_ctr_drbg_free(&random);
    mbedtls_entropy_free(&entropy);
}

auto TlsClientConfig::setUp() -> int
{
    if (const auto ret = mbedtls_ctr_drbg_seed(&random, mbedtls_entropy_func, &entropy, nullptr, 0); ret != 0)
    {
        return ret;
    }

    if (const auto ret = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT); ret != 0)
    {
        return ret;
    }

    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &random);
    return 0;
}

auto TlsClientConfig::get() -> mbedtls_ssl_config*
{
    return &config;
}

} // namespace xiloader
