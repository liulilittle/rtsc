// Parent probe: verify the three defects 乙 reported at byte/runtime level.
#include <cstdio>
#include <string>
#include <vector>

#include "rtsc/proto/gateway.h"

using namespace rtsc::proto;

static int failures = 0;
static void check(const char* n, bool ok) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", n);
    if (!ok) ++failures;
}

int main() {
    // --- D1: "0x10" must NOT be accepted as a terminal chunk ---------------
    {
        ChunkedDecoder d;
        auto out = d.Feed(reinterpret_cast<const uint8_t*>("0x10\r\nabc\r\n0\r\n\r\n"), 17);
        const std::string s(out.begin(), out.end());
        std::printf("  [INFO] feed \"0x10\\r\\nabc...\": decoded=%zu finished=%d failed=%d\n",
                    s.size(), (int)d.finished(), (int)d.failed());
        check("0x-prefixed size line is rejected (not read as terminal 0-chunk)",
              d.failed());
    }
    // --- D2: leading whitespace before the hex size must be rejected -------
    {
        ChunkedDecoder d;
        auto out = d.Feed(reinterpret_cast<const uint8_t*>(" 4\r\nWiki\r\n0\r\n\r\n"), 17);
        check("leading space before chunk size is rejected", d.failed());
    }
    // --- D3: trailing junk after the hex size must be rejected ------------
    {
        ChunkedDecoder d;
        auto out = d.Feed(reinterpret_cast<const uint8_t*>("4 garbage\r\nWiki\r\n0\r\n\r\n"), 24);
        const std::string s(out.begin(), out.end());
        check("trailing junk after chunk size is rejected", d.failed());
    }
    // --- D4: lone LF line endings must be rejected (RFC 9112) -------------
    {
        ChunkedDecoder d;
        auto out = d.Feed(reinterpret_cast<const uint8_t*>("4\nWiki\n0\n\n"), 12);
        check("lone LF line endings are rejected", d.failed());
    }
    // --- D5: chunk extension after ';' must still be accepted -------------
    {
        ChunkedDecoder d;
        auto out = d.Feed(reinterpret_cast<const uint8_t*>("4;ext=1\r\nWiki\r\n0\r\n\r\n"), 22);
        check("chunk extension ';ext=1' still accepted", !d.failed() && out.size() == 4);
    }
    // --- D6: CRLF injection into a header value ---------------------------
    {
        RdgChannelRequestOptions o;
        o.direction = RdgChannelDirection::kOut;
        o.gateway_host = "gw:443";
        o.connection_id = "CID\r\nX-Injected: 1";
        o.user_agent = "ua";
        const auto req = BuildRdgChannelRequest(o);
        const std::string s(req.begin(), req.end());
        std::printf("  [INFO] request=%s\n", s.c_str());
        check("CRLF in connection_id cannot inject a header",
              s.find("\r\nX-Injected:") == std::string::npos);
    }
    {
        RdgChannelRequestOptions o;
        o.direction = RdgChannelDirection::kIn;
        o.gateway_host = "gw:443\r\nX-Host-Injected: 1";
        o.connection_id = "CID";
        o.user_agent = "ua";
        const auto req = BuildRdgChannelRequest(o);
        const std::string s(req.begin(), req.end());
        check("CRLF in gateway_host cannot inject a header",
              s.find("\r\nX-Host-Injected:") == std::string::npos);
    }

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
