// Internal seam between the SChannel backend and the platform-neutral facade.
// NOT part of the public API: only src/net/tls_factory.cpp includes this.
#pragma once

#include <memory>
#include <string>

#include "rtsc/net/tls.h"

namespace rtsc::tls {

// Defined in tls_schannel.cpp (Windows only). Returns nullptr and fills `why`
// when SChannel cannot serve the configuration.
std::unique_ptr<TlsTransport> CreateSchannelTransport(const Config& config,
                                                      std::string& why);

}  // namespace rtsc::tls
