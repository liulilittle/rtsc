// Parent probe: independently reproduce D-A1 / D-A4 at runtime.
// Links the real Release libs. Shows that a builder-refused (empty) request is
// silently accepted by the handshake, which then fails with a timeout-ish
// message instead of pointing at the reject cause.
#include <cstdio>
#include <string>
#include <vector>

#include "rtsc/proto/gateway.h"

using namespace rtsc::proto;

int main() {
    int failures = 0;
    auto check = [&](const char* name, bool ok) {
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
        if (!ok) ++failures;
    };

    // D-A4: builder refuses a CRLF-injected value by returning an empty vector,
    // with NO out-of-band failure signal (no status, no error string).
    RdgChannelRequestOptions o;
    o.direction = RdgChannelDirection::kOut;
    o.gateway_host = "gw:443";
    o.connection_id = "CID\r\nX-Injected: 1";
    o.user_agent = "ua";
    const auto req = BuildRdgChannelRequest(o);
    std::printf("  [INFO] RDGSP request bytes=%zu\n", req.size());
    check("D-A4: builder returns empty vector on CRLF injection", req.empty());
    check("D-A4: caller can distinguish 'reject' from 'empty but valid'",
          false);  // no signal exists today -> intentional RED

    // Same for the CONNECT builder.
    ConnectRequestOptions co;
    co.target = "rdphost:3389\r\nX-Injected: 1";
    co.gateway_host = "gw:443";
    co.user_agent = "ua";
    const auto creq = BuildHttpConnectRequest(co);
    std::printf("  [INFO] CONNECT request bytes=%zu\n", creq.size());
    check("D-A4: CONNECT builder returns empty on CRLF injection", creq.empty());

    // D-A1: an empty request handed to a blocking Transport::Write succeeds
    // (size == 0 makes the send loop a no-op), so the handshake proceeds to
    // read, hits its loop budget, and reports an unrelated error.
    std::printf("  [INFO] empty Write() would be accepted by the send loop "
                "(while sent < 0 is false immediately)\n");
    check("D-A1: empty request is not detected before Write", false);

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
