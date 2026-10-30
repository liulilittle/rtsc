// Parent independent check for stage 2: does the builder-reject path produce a
// diagnosable error (contains CRLF/reject) and never a timeout-ish message?
#include <cstdio>
#include <string>
#include <vector>

#include "rtsc/proto/gateway.h"

using namespace rtsc::proto;

int main() {
    int failures = 0;
    auto check = [&](const char* n, bool ok) {
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", n);
        if (!ok) ++failures;
    };

    // The builders must refuse CRLF/NUL and return an empty vector; the caller
    // is responsible for turning that into a diagnosable error.
    {
        RdgChannelRequestOptions o;
        o.direction = RdgChannelDirection::kOut;
        o.gateway_host = "gw:443";
        o.connection_id = "CID\r\nX-Injected: 1";
        o.user_agent = "ua";
        check("RDGSP builder refuses CRLF in connection_id",
              BuildRdgChannelRequest(o).empty());
    }
    {
        RdgChannelRequestOptions o;
        o.direction = RdgChannelDirection::kOut;
        o.gateway_host = "gw\r\nX: 1";
        o.connection_id = "CID";
        o.user_agent = "ua";
        check("RDGSP builder refuses CRLF in gateway_host",
              BuildRdgChannelRequest(o).empty());
    }
    {
        ConnectRequestOptions c;
        c.target = "h:3389\r\nX: 1";
        c.gateway_host = "gw:443";
        c.user_agent = "ua";
        check("CONNECT builder refuses CRLF in target",
              BuildHttpConnectRequest(c).empty());
    }
    // Clean requests must still build (no false rejection).
    {
        RdgChannelRequestOptions o;
        o.direction = RdgChannelDirection::kIn;
        o.gateway_host = "gw:443";
        o.connection_id = "CID";
        o.user_agent = "ua";
        const auto r = BuildRdgChannelRequest(o);
        check("clean IN request builds", !r.empty());
        const std::string s(r.begin(), r.end());
        check("clean IN uses RDG_IN_DATA", s.rfind("RDG_IN_DATA ", 0) == 0);
        check("clean IN streams chunked",
              s.find("Transfer-Encoding: chunked") != std::string::npos);
        check("clean IN has no Content-Length",
              s.find("Content-Length") == std::string::npos);
    }
    // RFC6455 client frame: mask MUST be set, length encodings must be exact.
    {
        const std::vector<uint8_t> payload{0x41, 0x42, 0x43};  // "ABC"
        const uint8_t mask[4] = {0x11, 0x22, 0x33, 0x44};
        const auto f = WebSocketEncodeClientFrame(
        WebSocketOpcode::kBinary, payload.data(), payload.size(), 0x44332211u);
        std::printf("  [INFO] frame bytes=%zu\n", f.size());
        check("ws frame is non-empty", !f.empty());
        if (f.size() >= 2) {
            check("ws FIN+opcode=2 (binary)", f[0] == 0x82);
            check("ws MASK bit set", (f[1] & 0x80) != 0);
            check("ws length=3 in 7-bit field", (f[1] & 0x7f) == 3);
        }
        if (f.size() == 2 + 4 + 3) {
            // mask_key=0x44332211 -> wire key bytes 44 33 22 11
            check("ws mask key bytes are 44 33 22 11",
                  f[2] == 0x44 && f[3] == 0x33 && f[4] == 0x22 &&
                      f[5] == 0x11);
            check("ws payload is masked with the key",
                  f[6] == (0x41 ^ 0x44) && f[7] == (0x42 ^ 0x33) &&
                      f[8] == (0x43 ^ 0x22));
        } else {
            check("ws frame total size = 2+4+3", false);
        }
    }
    // Decoder must accept an EXTERNALLY built (server->client) unmasked frame.
    {
        // Server frames are NOT masked: FIN|binary, len=3, "xyz"
        const uint8_t wire[] = {0x82, 0x03, 'x', 'y', 'z'};
        WebSocketFrameDecoder d;
        std::vector<uint8_t> payload;
        bool got = false;
        for (size_t i = 0; i < sizeof(wire); ++i) {
            auto frames = d.Feed(&wire[i], 1);
            for (const auto& fr : frames) {
                payload = fr.payload;
                got = true;
            }
        }
        check("ws decoder accepts external unmasked frame", got);
        check("ws decoded payload = xyz",
              std::string(payload.begin(), payload.end()) == "xyz");
    }

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
