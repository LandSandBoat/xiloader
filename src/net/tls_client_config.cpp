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

#include <mbedtls/error.h>

namespace xiloader
{

auto mbedtlsErrorText(const int ret) -> std::string
{
    char text[128] = {};
    mbedtls_strerror(ret, text, sizeof(text));
    return text;
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
