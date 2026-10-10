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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

#include <string>

namespace xiloader
{

// mbedTLS error code as readable text, e.g. "SSL - The connection indicated an EOF"
auto mbedtlsErrorText(int ret) -> std::string;

// What every TLS connection to the server starts from: a seeded random generator and a TLS 1.3 client config.
// mbedTLS isn't built thread-safe, so each thread needs its own.
class TlsClientConfig
{
public:
    TlsClientConfig();
    ~TlsClientConfig();

    TlsClientConfig(const TlsClientConfig&)            = delete;
    TlsClientConfig& operator=(const TlsClientConfig&) = delete;

    // Seeds the generator and applies the client defaults. Returns an mbedTLS error code, 0 on success.
    auto setUp() -> int;

    // For mbedtls_ssl_setup and the mbedtls_ssl_conf_* settings a caller adds
    auto get() -> mbedtls_ssl_config*;

private:
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context random;
    mbedtls_ssl_config       config;
};

} // namespace xiloader
