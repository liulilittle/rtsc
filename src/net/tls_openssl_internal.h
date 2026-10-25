// Internal seam between the OpenSSL backend and the platform-neutral facade.
// NOT part of the public API: only src/net/tls_factory.cpp includes this.
#pragma once

#include <memory>
#include <string>

#include "rtsc/net/tls.h"

namespace rtsc::tls {

// Defined in tls_openssl.cpp (non-Windows, built when RTSC_TLS_OPENSSL=ON).
// Returns nullptr and fills `why` when OpenSSL cannot serve the configuration.
std::unique_ptr<TlsTransport> CreateOpensslTransport(const Config& config,
                                                     std::string& why);

}  // namespace rtsc::tls
