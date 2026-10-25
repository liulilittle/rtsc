// Platform-neutral TLS backend factory. This is the ONLY definition of
// CreateTlsTransport / EnumerateTlsBackends (S21): keeping them here means
// every platform links rtsc_tls successfully, and "no backend" is a runtime
// kUnsupported rather than a build break.
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "rtsc/net/tls.h"

// Included unconditionally, even though CreateSchannelTransport is only CALLED
// on Windows (U20-5). The header declares a platform-neutral function, so it
// compiles everywhere; keeping the include outside #if means that if someone
// ever adds a Windows-only include to it, the Linux build fails immediately
// instead of silently passing. Measured: with the include inside #if, injecting
// <windows.h> into the internal header left the Linux build green.
#include "tls_schannel_internal.h"

#if defined(RTSC_TLS_OPENSSL)
#include "tls_openssl_internal.h"
#endif

namespace rtsc::tls {

std::unique_ptr<TlsTransport> CreateTlsTransport(std::string_view backend,
                                                const Config& config,
                                                std::string& why) {
    why.clear();
    const bool want_default = backend.empty() || backend == "default";
#if defined(_WIN32)
    if (want_default || backend == "schannel") {
        return CreateSchannelTransport(config, why);
    }
    why = "unknown TLS backend: " + std::string(backend);
    return nullptr;
#else
#if defined(RTSC_TLS_OPENSSL)
    if (want_default || backend == "openssl") {
        return CreateOpensslTransport(config, why);
    }
#endif
    (void)config;
    if (want_default) {
        why = "no TLS backend for this platform";
        return nullptr;
    }
    why = "unknown TLS backend: " + std::string(backend);
    return nullptr;
#endif
}

std::vector<BackendInfo> EnumerateTlsBackends() {
#if defined(_WIN32)
    return {{"schannel", true, ""}};
#elif defined(RTSC_TLS_OPENSSL)
    return {{"openssl", true, ""}};
#else
    return {};
#endif
}

}  // namespace rtsc::tls
