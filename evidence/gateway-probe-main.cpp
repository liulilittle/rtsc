// Runtime probe: print the ACTUAL bytes our gateway builders emit today.
// Links the real Release libs; no stubs. Proves the defects at byte level.
#include <cstdio>
#include <string>
#include <vector>

#include "rtsc/proto/gateway.h"

using namespace rtsc::proto;

static void Dump(const char* label, const std::vector<uint8_t>& v) {
    std::printf("---- %s (%zu bytes) ----\n", label, v.size());
    std::string s(v.begin(), v.end());
    // Print with visible CRLF markers so the exact wire form is auditable.
    for (char c : s) {
        if (c == '\r') std::printf("\\r");
        else if (c == '\n') std::printf("\\n\n");
        else std::putchar(c);
    }
    std::printf("\n");
}

static bool Has(const std::vector<uint8_t>& v, const char* needle) {
    const std::string s(v.begin(), v.end());
    return s.find(needle) != std::string::npos;
}

int main() {
    int failures = 0;
    auto check = [&](const char* name, bool ok) {
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
        if (!ok) ++failures;
    };

    // 1) RDG channel request (IN channel shape) as the current code builds it.
    RdgChannelRequestOptions ch;
    ch.method = kRdgInData;
    ch.connection_id = "11111111-2222-3333-4444-555555555555";
    ch.user_agent = "rtsc";
    ch.correlation_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    ch.user_id = "user@example";
    const std::vector<uint8_t> req = BuildRdgChannelRequest(ch);
    Dump("BuildRdgChannelRequest(RDG_IN_DATA)", req);

    std::printf("== assertions on the RDGSP channel request ==\n");
    check("host header is an authority, not the URL path",
          Has(req, "Host: /remoteDesktopGateway/") == false);
    check("request carries Transfer-Encoding: chunked",
          Has(req, "Transfer-Encoding: chunked") ||
              Has(req, "transfer-encoding: chunked"));
    check("request has no Content-Length: 0 on a streaming body",
          Has(req, "Content-Length: 0") == false);
    check("request carries RDG-Diagnostics-Info",
          Has(req, "RDG-Diagnostics-Info"));
    check("request carries RDG-Client-AppBuild",
          Has(req, "RDG-Client-AppBuild"));
    check("request carries RDG-Client-Generation",
          Has(req, "RDG-Client-Generation"));
    check("request carries RDG-Auth-Scheme", Has(req, "RDG-Auth-Scheme"));
    check("request carries RDG-INCHANNEL-RETRYMODE",
          Has(req, "RDG-INCHANNEL-RETRYMODE"));
    check("request carries Connection: Keep-Alive", Has(req, "Keep-Alive"));

    // 2) CONNECT request for comparison (generic proxy path).
    ConnectRequestOptions co;
    co.target = "rdphost:3389";
    co.gateway_host = "gw.example:443";
    co.user_agent = "rtsc";
    const std::vector<uint8_t> creq = BuildHttpConnectRequest(co);
    Dump("BuildHttpConnectRequest", creq);
    std::printf("== assertions on the CONNECT request ==\n");
    check("CONNECT host header is the gateway authority",
          Has(creq, "Host: gw.example:443"));

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
