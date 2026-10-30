// Runtime probe: print the ACTUAL bytes our gateway builders emit today.
// Links the real Release libs; no stubs. Header direction follows the
// disassembly ruling docs/spec/gateway-header-direction-ruling.md
// (mstscax FUN_1801c3818): correlation both channels, user-id IN-only
// (base64), generation / app-build / LB cookie OUT-only, chunked IN-only /
// Keep-Alive OUT.
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

    // 1) OUT channel request: OUT-only set present, user-id / chunked absent.
    RdgChannelRequestOptions out;
    out.method = kRdgOutData;
    out.direction = RdgChannelDirection::kOut;
    out.gateway_host = "gw.example:443";
    out.connection_id = "11111111-2222-3333-4444-555555555555";
    out.user_agent = "rtsc";
    out.correlation_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    out.user_id = "user@example";
    out.client_generation = "Win32#10.0=22631";
    out.load_balancer_cookie = "Cookie: mstshash=ABCD";
    out.app_build = "10.0.22631";
    out.auth_scheme = "SMARTCARD";
    out.diagnostics_info = "rdg diagnostics";
    const std::vector<uint8_t> oreq = BuildRdgChannelRequest(out);
    Dump("BuildRdgChannelRequest(RDG_OUT_DATA)", oreq);

    std::printf("== assertions on the OUT RDGSP channel request ==\n");
    check("OUT host header is an authority, not the URL path",
          Has(oreq, "Host: /remoteDesktopGateway/") == false);
    check("OUT carries Connection: Keep-Alive (plain request)",
          Has(oreq, "Connection: Keep-Alive"));
    check("OUT has no Transfer-Encoding: chunked",
          Has(oreq, "Transfer-Encoding") == false);
    check("OUT carries RDG-Connection-Id", Has(oreq, "RDG-Connection-Id"));
    check("OUT carries RDG-Diagnostics-Info", Has(oreq, "RDG-Diagnostics-Info"));
    check("OUT carries RDG-Correlation-Id", Has(oreq, "RDG-Correlation-Id"));
    check("OUT carries RDG-Client-Generation",
          Has(oreq, "RDG-Client-Generation"));
    check("OUT carries RDG-Client-AppBuild", Has(oreq, "RDG-Client-AppBuild"));
    check("OUT carries RDG-Auth-Scheme", Has(oreq, "RDG-Auth-Scheme"));
    check("OUT carries Load Balancer Cookie", Has(oreq, "Load Balancer Cookie"));
    check("OUT does NOT carry the IN-only user id",
          Has(oreq, "RDG-User-Id") == false);

    // 2) IN channel request (retry mode active): IN-only set present, OUT-only
    //    set absent.
    RdgChannelRequestOptions in;
    in.method = kRdgInData;
    in.direction = RdgChannelDirection::kIn;
    in.gateway_host = "gw.example:443";
    in.connection_id = "11111111-2222-3333-4444-555555555555";
    in.user_agent = "rtsc";
    in.correlation_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    in.user_id = "user@example";
    in.client_generation = "Win32#10.0=22631";
    in.retry_count = 1;
    in.diagnostics_info = "rdg diagnostics";
    const std::vector<uint8_t> ireq = BuildRdgChannelRequest(in);
    Dump("BuildRdgChannelRequest(RDG_IN_DATA, retry)", ireq);

    std::printf("== assertions on the IN RDGSP channel request ==\n");
    check("IN host header is an authority, not the URL path",
          Has(ireq, "Host: /remoteDesktopGateway/") == false);
    check("IN carries Transfer-Encoding: chunked",
          Has(ireq, "Transfer-Encoding: chunked"));
    check("IN has no Content-Length on the streaming body",
          Has(ireq, "Content-Length") == false);
    check("IN carries RDG-Diagnostics-Info", Has(ireq, "RDG-Diagnostics-Info"));
    check("IN carries RDG-Correlation-Id", Has(ireq, "RDG-Correlation-Id"));
    check("IN carries the base64 RDG-User-Id",
          Has(ireq, "RDG-User-Id: dXNlckBleGFtcGxl"));
    check("IN carries RDG-INCHANNEL-RETRYMODE with a retry count",
          Has(ireq, "RDG-INCHANNEL-RETRYMODE: IN_CHANNEL_RETRY_COUNT_1"));
    check("IN does NOT carry the OUT-only client generation",
          Has(ireq, "RDG-Client-Generation") == false);
    check("IN does NOT carry the OUT-only app build",
          Has(ireq, "RDG-Client-AppBuild") == false);
    check("IN does NOT carry the OUT-only load balancer cookie",
          Has(ireq, "Load Balancer Cookie") == false);

    // 3) CONNECT request (generic proxy path), unchanged.
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