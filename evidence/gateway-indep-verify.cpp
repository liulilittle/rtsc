// INDEPENDENT verification of the phase-1 fixes (parent agent).
// Data layouts come from RFC 7230 / factory evidence, NOT from the executor's
// tests. Uses the external-bytes -> parse -> assert direction.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "rtsc/proto/gateway.h"

using namespace rtsc::proto;

static int failures = 0;
static void check(const char* name, bool ok) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}

static bool Has(const std::vector<uint8_t>& v, const char* n) {
    return std::string(v.begin(), v.end()).find(n) != std::string::npos;
}

static std::vector<uint8_t> FeedStr(ChunkedDecoder& d, const char* wire) {
    const size_t n = std::strlen(wire);
    return d.Feed(reinterpret_cast<const uint8_t*>(wire), n);
}

int main() {
    // ===== 1. Chunked decode from EXTERNAL byte strings (RFC 7230 4.1) =====
    {
        ChunkedDecoder d;
        auto out = FeedStr(d, "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
        check("chunked: RFC example not failed", !d.failed());
        check("chunked: RFC example yields Wikipedia",
              std::string(out.begin(), out.end()) == "Wikipedia");
        check("chunked: RFC example finished", d.finished());
    }
    {
        ChunkedDecoder d;
        auto out = FeedStr(d, "A;ext=1\r\n0123456789\r\n0\r\n\r\n");
        check("chunked: uppercase hex + extension accepted", !d.failed());
        check("chunked: 0xA bytes decoded", out.size() == 10);
    }
    {
        ChunkedDecoder d;
        auto out = FeedStr(d, "3\r\nabc\r\n0\r\nX-Trailer: v\r\n\r\n");
        check("chunked: trailer skipped", !d.failed());
        check("chunked: trailer body is exactly abc",
              std::string(out.begin(), out.end()) == "abc");
    }
    {
        ChunkedDecoder d;
        FeedStr(d, "10\r\nshort");
        d.EndOfStream();
        check("chunked: truncated chunk latches an error", d.failed());
    }
    {
        ChunkedDecoder d;
        FeedStr(d, "zz\r\nabc\r\n0\r\n\r\n");
        check("chunked: invalid hex rejected", d.failed());
    }
    {
        ChunkedDecoder d;
        std::vector<uint8_t> out;
        const char* wire = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        bool ok = true;
        for (const char* p = wire; *p != 0; ++p) {
            auto part = d.Feed(reinterpret_cast<const uint8_t*>(p), 1);
            out.insert(out.end(), part.begin(), part.end());
            if (d.failed()) { ok = false; break; }
        }
        check("chunked: byte-by-byte feed works",
              ok && std::string(out.begin(), out.end()) == "Wikipedia");
    }
    {
        // Max total ceiling must reject an oversized body instead of growing
        // without bound (DoS guard).
        ChunkedDecoder d(1024, 4096);
        std::string huge;
        for (int i = 0; i < 8; ++i) huge += "400\r\n" + std::string(0x400, 'x') + "\r\n";
        huge += "0\r\n\r\n";
        FeedStr(d, huge.c_str());
        check("chunked: total ceiling rejects oversize", d.failed());
    }

    // ===== 2. Chunked encode: independent hand parse =====
    {
        const std::string payload = "hello world";
        const std::vector<uint8_t> enc = ChunkedEncode(
            reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
        const std::string s(enc.begin(), enc.end());
        check("chunked-encode: starts with b\\r\\n", s.rfind("b\r\n", 0) == 0);
        check("chunked-encode: ends with 0\\r\\n\\r\\n",
              s.size() >= 5 && s.compare(s.size() - 5, 5, "0\r\n\r\n") == 0);
        check("chunked-encode: contains the payload verbatim",
              s.find(payload) != std::string::npos);
        const size_t eol = s.find("\r\n");
        check("chunked-encode: length token equals payload size",
              eol != std::string::npos &&
                  std::strtoul(s.substr(0, eol).c_str(), nullptr, 16) ==
                      payload.size());
    }

    // ===== 3. IsChunkedBody (plain fallback probe) =====
    {
        auto mk = [](const char* te) {
            HttpMessage m;
            if (te != nullptr) {
                m.headers.push_back(HttpHeader{"Transfer-Encoding", te});
            }
            return m;
        };
        check("IsChunkedBody: chunked", IsChunkedBody(mk("chunked")));
        check("IsChunkedBody: CHUNKED", IsChunkedBody(mk("CHUNKED")));
        check("IsChunkedBody: gzip, chunked", IsChunkedBody(mk("gzip, chunked")));
        check("IsChunkedBody: gzip only", !IsChunkedBody(mk("gzip")));
        check("IsChunkedBody: absent header", !IsChunkedBody(mk(nullptr)));
    }

    // ===== 4. Status -> HRESULT (factory FUN_1801bdd8c) =====
    check("status 401", MapGatewayStatusToHresult(401, false) == 0x80070005u);
    check("status 407", MapGatewayStatusToHresult(407, false) == 0x800706C1u);
    check("status 502", MapGatewayStatusToHresult(502, false) == 0x800706BAu);
    check("status 504", MapGatewayStatusToHresult(504, false) == 0x800706BAu);
    check("status 500 generic",
          MapGatewayStatusToHresult(500, false) == (0x80190000u | 500u));
    check("password expired",
          MapGatewayStatusToHresult(401, true) == 0x80070532u);

    // ===== 5. Header direction model (gateway-header-direction-ruling.md) =====
    {
        RdgChannelRequestOptions out;
        out.method = kRdgOutData;
        out.direction = RdgChannelDirection::kOut;
        out.gateway_host = "gw.example:443";
        out.connection_id = "CID";
        out.user_agent = "ua";
        out.correlation_id = "CORR";
        out.user_id = "USER";
        out.client_generation = "GEN";
        out.app_build = "AB";
        out.load_balancer_cookie = "LBC";
        const auto o = BuildRdgChannelRequest(out);
        check("OUT: Host is the authority", Has(o, "Host: gw.example:443"));
        check("OUT: no URL path in Host",
              !Has(o, "Host: /remoteDesktopGateway/"));
        check("OUT: Keep-Alive (plain request)", Has(o, "Connection: Keep-Alive"));
        check("OUT: no chunked coding", !Has(o, "Transfer-Encoding"));
        check("OUT: correlation id", Has(o, "RDG-Correlation-Id: CORR"));
        check("OUT: client generation", Has(o, "RDG-Client-Generation: GEN"));
        check("OUT: app build", Has(o, "RDG-Client-AppBuild: AB"));
        check("OUT: lb cookie", Has(o, "Load Balancer Cookie: LBC"));
        check("OUT: connection id", Has(o, "RDG-Connection-Id: CID"));
        check("OUT: no IN-only user id", !Has(o, "RDG-User-Id"));
    }
    {
        RdgChannelRequestOptions in;
        in.direction = RdgChannelDirection::kIn;
        in.gateway_host = "gw.example:443";
        in.connection_id = "CID";
        in.user_agent = "ua";
        in.correlation_id = "CORR";
        in.user_id = "USER";
        in.app_build = "AB";
        in.retry_count = 3;
        const auto i = BuildRdgChannelRequest(in);
        check("IN: chunked streaming", Has(i, "Transfer-Encoding: chunked"));
        check("IN: no Content-Length", !Has(i, "Content-Length"));
        check("IN: retry header carries the count",
              Has(i, "RDG-INCHANNEL-RETRYMODE: IN_CHANNEL_RETRY_COUNT_3"));
        check("IN: correlation id", Has(i, "RDG-Correlation-Id: CORR"));
        check("IN: user id base64",
              Has(i, "RDG-User-Id: VVNFUg=="));  // "USER" -> base64
        check("IN: no client generation leak", !Has(i, "RDG-Client-Generation"));
        check("IN: no app build leak", !Has(i, "RDG-Client-AppBuild"));
        check("IN: no lb cookie leak", !Has(i, "Load Balancer Cookie"));
    }

    // ===== 6. Default method (D10) =====
    {
        RdgChannelRequestOptions d;
        d.gateway_host = "gw:443";
        check("default method is RDG_IN_DATA",
              d.method == std::string(kRdgInData));
        const auto r = BuildRdgChannelRequest(d);
        check("default request line starts with RDG_IN_DATA",
              Has(r, "RDG_IN_DATA /remoteDesktopGateway/ HTTP/1.1"));
    }

    // ===== 7. Multi-challenge auth (D11) =====
    {
        std::vector<RdgAuthChallenge> out;
        auto st = RdgAuthChallenge::parse_challenges(
            "Negotiate, NTLM realm=\"gw\", Basic realm=\"x,y\"", out);
        check("multi-challenge parses", st == Status::Ok);
        check("multi-challenge yields 3", out.size() == 3);
        if (out.size() == 3) {
            check("quoted comma not split", out[2].realm == "x,y");
        }
    }

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
