// RD Gateway ([MS-TSGU]) and RDP-UDP ([MS-RDPEUDP]) tests.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/client/client.h"
#include "rtsc/net/gateway_transport.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/gateway.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/security/connection_driver.h"
#include "rtsc/server/server.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using namespace rtsc::net;

namespace {

// A scripted byte transport: it captures what the tunnel writes and replays a
// canned response.
class MockTransport : public Transport {
 public:
    std::vector<uint8_t> written;
    std::vector<uint8_t> to_read;
    size_t read_offset = 0;

    int Read(uint8_t* buf, size_t size) override {
        if (read_offset >= to_read.size()) return kReadTimeout;
        const size_t n = (std::min)(size, to_read.size() - read_offset);
        std::memcpy(buf, to_read.data() + read_offset, n);
        read_offset += n;
        return static_cast<int>(n);
    }
    bool Write(const uint8_t* data, size_t size) override {
        written.insert(written.end(), data, data + size);
        return true;
    }
    void Close() override {}
};

// A loopback datagram socket pair: Send() delivers to the peer's queue.
// Thread safe: the mutual-write concurrency test sends and receives from
// different threads on the same socket object.
class LoopbackUdpSocket : public UdpSocket {
 public:
    void SetPeer(LoopbackUdpSocket* peer) { peer_ = peer; }
    void DropNext(unsigned count) { drop_next_.store(count); }

    bool Send(const uint8_t* data, size_t size) override {
        if (drop_next_.load() > 0) {
            drop_next_.fetch_sub(1);
            return true;  // silently dropped
        }
        if (peer_ == nullptr) return false;
        std::lock_guard<std::mutex> lock(peer_->incoming_mutex_);
        peer_->incoming_.push_back(std::vector<uint8_t>(data, data + size));
        return true;
    }

    int Receive(uint8_t* buf, size_t size) override {
        std::lock_guard<std::mutex> lock(incoming_mutex_);
        if (incoming_.empty()) return 0;
        const std::vector<uint8_t> datagram = std::move(incoming_.front());
        incoming_.pop_front();
        const size_t n = (std::min)(size, datagram.size());
        std::memcpy(buf, datagram.data(), n);
        return static_cast<int>(n);
    }

    void Close() override {}

 private:
    LoopbackUdpSocket* peer_ = nullptr;
    std::mutex incoming_mutex_;
    std::deque<std::vector<uint8_t>> incoming_;
    std::atomic<unsigned> drop_next_{0};
};

std::vector<uint8_t> ToVec(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// Crafts an inbound ACK datagram for the peer socket to inject.
std::vector<uint8_t> MakeAckDatagram(uint32_t source_ack) {
    UdpAckFrame ack;
    ack.fec.source_ack = source_ack;
    ack.fec.receive_window_size = 64;
    ack.fec.flags = kUdpFlagAck;
    return UdpAckFrame::build(ack);
}

// Crafts an inbound data datagram for the peer socket to inject.
std::vector<uint8_t> MakeDataDatagram(uint32_t source_start,
                                      std::vector<uint8_t> payload) {
    UdpDataFrame frame;
    frame.fec.receive_window_size = 64;
    frame.fec.flags = kUdpFlagData;
    frame.source.coded = source_start;
    frame.source.source_start = source_start;
    frame.payload = std::move(payload);
    return UdpDataFrame::build(frame);
}

std::vector<uint8_t> HttpResponse(int code, const char* reason) {
    const std::string text = "HTTP/1.1 " + std::to_string(code) + " " +
                             reason + "\r\nContent-Length: 0\r\n\r\n";
    return std::vector<uint8_t>(text.begin(), text.end());
}

// A minimal RD Gateway: it answers the client's HTTP CONNECT with 200 and then
// pipes bytes between the client and the real RDP server, exactly like the
// gateway relays the RDP stream.
class MockGateway {
 public:
    // `gateway_port` may be 0: the kernel then picks a free port and bound_port()
    // reports which one. `server_port` is the real server the gateway relays to.
    MockGateway(uint16_t gateway_port, uint16_t server_port)
        : gateway_port_(gateway_port), server_port_(server_port) {}

    bool Start(std::string& error) {
        listener_ = rtsc::net::ListenTcp("127.0.0.1", gateway_port_, error);
        if (!listener_) return false;
        gateway_port_ = listener_->local_port();
        thread_ = std::thread([this] { Run(); });
        return true;
    }

    void Stop() {
        if (listener_) listener_->Close();
        if (thread_.joinable()) thread_.join();
    }

    uint16_t bound_port() const { return gateway_port_; }
    unsigned connect_requests() const { return connect_requests_; }

 private:
    static bool HasBlankLine(const std::vector<uint8_t>& buf) {
        for (size_t i = 0; i + 3 < buf.size(); ++i) {
            if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
                buf[i + 3] == '\n') {
                return true;
            }
        }
        return false;
    }

    static void Pump(rtsc::net::Transport& from, rtsc::net::Transport& to) {
        uint8_t buf[4096];
        for (;;) {
            const int n = from.Read(buf, sizeof(buf));
            if (n == rtsc::net::kReadTimeout) continue;
            if (n <= 0) break;
            if (!to.Write(buf, n)) break;
        }
    }

    void Run() {
        for (;;) {
            auto client = listener_->Accept();
            if (!client) break;
            HandleClient(std::move(client));
        }
    }

    void HandleClient(std::unique_ptr<rtsc::net::Transport> client) {
        std::vector<uint8_t> head;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            if (HasBlankLine(head)) break;
            uint8_t chunk[4096];
            const int n = client->Read(chunk, sizeof(chunk));
            if (n == rtsc::net::kReadTimeout) continue;
            if (n <= 0) {
                client->Close();
                return;
            }
            head.insert(head.end(), chunk, chunk + n);
        }
        if (!HasBlankLine(head)) {
            client->Close();
            return;
        }

        HttpRequestLine line;
        size_t consumed = 0;
        if (HttpRequestLine::parse(head.data(), head.size(), line, consumed) !=
                Status::Ok ||
            line.method != "CONNECT") {
            client->Close();
            return;
        }
        ++connect_requests_;

        std::string error;
        auto upstream = rtsc::net::ConnectTcp("127.0.0.1", server_port_, error);
        if (!upstream) {
            client->Close();
            return;
        }
        const std::string response =
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        if (!client->Write(
                reinterpret_cast<const uint8_t*>(response.data()),
                response.size())) {
            client->Close();
            upstream->Close();
            return;
        }

        rtsc::net::Transport* client_raw = client.get();
        rtsc::net::Transport* upstream_raw = upstream.get();
        // When either direction ends, close both sockets so the other pump
        // unblocks: otherwise the gateway thread would wait forever on a peer
        // that only closes much later.
        std::thread up([client_raw, upstream_raw] {
            Pump(*client_raw, *upstream_raw);
            client_raw->Close();
            upstream_raw->Close();
        });
        Pump(*upstream_raw, *client_raw);
        client_raw->Close();
        upstream_raw->Close();
        up.join();
        client->Close();
        upstream->Close();
    }

    uint16_t gateway_port_;
    uint16_t server_port_;
    std::unique_ptr<rtsc::net::Listener> listener_;
    std::thread thread_;
    unsigned connect_requests_ = 0;
};

}  // namespace

RTSC_TEST(rdp_connection_transport_round_trips) {
    RdpConnectionTransport in;
    in.version = 1;
    in.type = TransportType::kUdp;
    const std::vector<uint8_t> bytes = RdpConnectionTransport::build(in);
    CHECK_EQ(bytes.size(), static_cast<size_t>(8));

    RdpConnectionTransport out;
    CHECK(RdpConnectionTransport::parse(bytes.data(), bytes.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.version, static_cast<uint32_t>(1));
    CHECK(out.type == TransportType::kUdp);
    CHECK(std::string(to_string(out.type)) == "UDP");

    RdpConnectionTransport tcp;
    tcp.type = TransportType::kTcp;
    const std::vector<uint8_t> tcp_bytes = RdpConnectionTransport::build(tcp);
    CHECK(RdpConnectionTransport::parse(tcp_bytes.data(), tcp_bytes.size(), out) ==
          Status::Ok);
    CHECK(out.type == TransportType::kTcp);
}

RTSC_TEST(http_connect_request_is_well_formed) {
    ConnectRequestOptions options;
    options.target = "server.example:3389";
    options.gateway_host = "gateway.example:443";
    options.user_agent = "rtsc";
    options.transport = TransportType::kUdp;
    const std::vector<uint8_t> request = BuildHttpConnectRequest(options);
    const std::string text(request.begin(), request.end());

    CHECK(text.rfind("CONNECT server.example:3389 HTTP/1.1\r\n", 0) == 0);
    CHECK(text.find("Host: gateway.example:443\r\n") != std::string::npos);
    CHECK(text.find("User-Agent: rtsc\r\n") != std::string::npos);
    CHECK(text.find("X-Transport: 0x00000000\r\n") != std::string::npos);
    CHECK(text.find("Content-Length: 0\r\n") != std::string::npos);
    CHECK(text.size() >= 2 && text.substr(text.size() - 2) == "\r\n");
}

RTSC_TEST(http_response_parses_status_and_headers) {
    const std::string head = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";
    const std::string extra = "RDG-Connection-Id: {abc}\r\n\r\n";
    const std::string text = head + extra;
    const std::vector<uint8_t> wire(text.begin(), text.end());

    HttpMessage out;
    size_t consumed = 0;
    CHECK(HttpMessage::parse(wire.data(), wire.size(), out, consumed) ==
          Status::Ok);
    CHECK_EQ(out.status_code, 200);
    CHECK(out.reason == "OK");
    const HttpHeader* id = out.find("rdg-connection-id");
    CHECK(id != nullptr);
    if (id != nullptr) CHECK(id->value == "{abc}");
    CHECK_EQ(consumed, text.size());
}

RTSC_TEST(http_response_needs_more_data_until_blank_line) {
    const std::string partial = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";
    const std::vector<uint8_t> wire(partial.begin(), partial.end());
    HttpMessage out;
    size_t consumed = 0;
    CHECK(HttpMessage::parse(wire.data(), wire.size(), out, consumed) ==
          Status::NeedMoreData);
}

RTSC_TEST(rdg_channel_request_is_well_formed) {
    RdgChannelRequestOptions options;
    options.method = kRdgOutData;
    options.connection_id = "{958F92D8-DA20-467a-BBE3-65E7E9B4EDCF}";
    options.user_agent = "rtsc";
    const std::vector<uint8_t> request = BuildRdgChannelRequest(options);
    const std::string text(request.begin(), request.end());

    CHECK(text.rfind("RDG_OUT_DATA /remoteDesktopGateway/ HTTP/1.1\r\n", 0) == 0);
    CHECK(text.find("RDG-Connection-Id: {958F92D8-DA20-467a-BBE3-65E7E9B4EDCF}\r\n") !=
          std::string::npos);
    CHECK(text.find("Cache-Control: no-cache\r\n") != std::string::npos);
}

RTSC_TEST(rdg_channel_method_defaults_to_in_data) {
    // D10: a default-constructed options object must produce a valid method in
    // the request line instead of an empty method (" /remoteDesktopGateway/").
    RdgChannelRequestOptions options;
    options.connection_id = "{958F92D8-DA20-467a-BBE3-65E7E9B4EDCF}";
    options.gateway_host = "gw.example:443";
    options.user_agent = "rtsc";
    const std::vector<uint8_t> request = BuildRdgChannelRequest(options);
    const std::string text(request.begin(), request.end());
    CHECK(text.rfind("RDG_IN_DATA /remoteDesktopGateway/ HTTP/1.1\r\n", 0) == 0);
}

RTSC_TEST(rdg_channel_request_rejects_empty_method) {
    // An explicitly empty method must fail the build (a request line with a
    // leading space would be illegal), reported as an empty vector.
    RdgChannelRequestOptions options;
    options.method = "";
    options.connection_id = "{958F92D8-DA20-467a-BBE3-65E7E9B4EDCF}";
    options.gateway_host = "gw.example:443";
    options.user_agent = "rtsc";
    const std::vector<uint8_t> request = BuildRdgChannelRequest(options);
    CHECK(request.empty());
}

RTSC_TEST(rdg_channel_request_host_is_an_authority) {
    // D1: the Host header must be the gateway authority, never the URL path.
    RdgChannelRequestOptions options;
    options.method = kRdgInData;
    options.gateway_host = "gw.example:443";
    options.connection_id = "{id}";
    options.user_agent = "rtsc";
    const std::vector<uint8_t> request = BuildRdgChannelRequest(options);
    const std::string text(request.begin(), request.end());
    CHECK(text.find("Host: gw.example:443\r\n") != std::string::npos);
    CHECK(text.find("Host: /remoteDesktopGateway/") == std::string::npos);
}

RTSC_TEST(rdg_channel_request_streams_chunked_without_content_length) {
    // D2/D3: the IN streaming request body must be chunked (not Content-Length)
    // and must not carry the OUT Keep-Alive form.
    RdgChannelRequestOptions options;
    options.method = kRdgInData;
    options.direction = RdgChannelDirection::kIn;
    options.gateway_host = "gw.example:443";
    options.connection_id = "{id}";
    options.user_agent = "rtsc";
    const std::vector<uint8_t> request = BuildRdgChannelRequest(options);
    const std::string text(request.begin(), request.end());
    CHECK(text.find("Transfer-Encoding: chunked\r\n") != std::string::npos);
    CHECK(text.find("Content-Length") == std::string::npos);
    CHECK(text.find("Connection: Keep-Alive") == std::string::npos);
}

RTSC_TEST(rdg_channel_request_header_set_and_direction) {
    // D5 headers + per-direction set, per the parent's disassembly-ruled table
    // (mstscax FUN_1801c3818): both channels carry Connection-Id /
    // Diagnostics-Info / Correlation-Id; user-id is IN-only (base64);
    // generation / app-build / Load Balancer Cookie are OUT-only; the IN
    // channel streams (Transfer-Encoding: chunked), OUT is a Keep-Alive
    // request.
    RdgChannelRequestOptions out_options;
    out_options.method = kRdgOutData;
    out_options.direction = RdgChannelDirection::kOut;
    out_options.gateway_host = "gw.example:443";
    out_options.connection_id = "{conn}";
    out_options.user_agent = "rtsc";
    out_options.correlation_id = "{corr}";
    out_options.user_id = "user@example";
    out_options.client_generation = "Win32#10.0=22631";
    out_options.load_balancer_cookie = "Cookie: mstshash=ABCD";
    out_options.app_build = "10.0.22631";
    out_options.auth_scheme = "SMARTCARD";
    out_options.diagnostics_info = "rdg diagnostics";

    const std::vector<uint8_t> out_request = BuildRdgChannelRequest(out_options);
    const std::string out(out_request.begin(), out_request.end());
    CHECK(out.find("RDG-Connection-Id: {conn}\r\n") != std::string::npos);
    CHECK(out.find("RDG-Diagnostics-Info: rdg diagnostics\r\n") !=
          std::string::npos);
    CHECK(out.find("RDG-Correlation-Id: {corr}\r\n") != std::string::npos);
    CHECK(out.find("RDG-Client-Generation: Win32#10.0=22631\r\n") !=
          std::string::npos);
    CHECK(out.find("RDG-Client-AppBuild: 10.0.22631\r\n") != std::string::npos);
    CHECK(out.find("RDG-Auth-Scheme: SMARTCARD\r\n") != std::string::npos);
    CHECK(out.find("Load Balancer Cookie: Cookie: mstshash=ABCD\r\n") !=
          std::string::npos);
    // OUT is a plain Keep-Alive request: no user-id, no chunked coding.
    CHECK(out.find("RDG-User-Id") == std::string::npos);
    CHECK(out.find("Connection: Keep-Alive\r\n") != std::string::npos);
    CHECK(out.find("Transfer-Encoding") == std::string::npos);

    RdgChannelRequestOptions in_options = out_options;
    in_options.method = kRdgInData;
    in_options.direction = RdgChannelDirection::kIn;
    const std::vector<uint8_t> in_request = BuildRdgChannelRequest(in_options);
    const std::string in(in_request.begin(), in_request.end());
    CHECK(in.find("RDG-Connection-Id: {conn}\r\n") != std::string::npos);
    CHECK(in.find("RDG-Diagnostics-Info: rdg diagnostics\r\n") !=
          std::string::npos);
    CHECK(in.find("RDG-Correlation-Id: {corr}\r\n") != std::string::npos);
    // IN channels the user-id (base64) and streams chunked; no OUT-only set.
    CHECK(in.find("RDG-User-Id: dXNlckBleGFtcGxl\r\n") != std::string::npos);
    CHECK(in.find("Transfer-Encoding: chunked\r\n") != std::string::npos);
    CHECK(in.find("RDG-Client-Generation") == std::string::npos);
    CHECK(in.find("RDG-Client-AppBuild") == std::string::npos);
    CHECK(in.find("Load Balancer Cookie") == std::string::npos);
    CHECK(in.find("Connection: Keep-Alive") == std::string::npos);
}

RTSC_TEST(rdg_in_channel_retry_mode_header_present) {
    // Evidence 0x1806d0f60 (RDG-INCHANNEL-RETRYMODE) + IN_CHANNEL_RETRY_COUNT_%d.
    RdgChannelRequestOptions options;
    options.method = kRdgInData;
    options.direction = RdgChannelDirection::kIn;
    options.gateway_host = "gw.example:443";
    options.connection_id = "{conn}";
    options.user_agent = "rtsc";
    options.retry_count = 3;
    const std::vector<uint8_t> request = BuildRdgChannelRequest(options);
    const std::string text(request.begin(), request.end());
    CHECK(text.find("RDG-INCHANNEL-RETRYMODE: IN_CHANNEL_RETRY_COUNT_3\r\n") !=
          std::string::npos);
}

RTSC_TEST(rdg_out_channel_never_carries_retry_mode_header) {
    RdgChannelRequestOptions options;
    options.method = kRdgOutData;
    options.direction = RdgChannelDirection::kOut;
    options.gateway_host = "gw.example:443";
    options.connection_id = "{conn}";
    options.user_agent = "rtsc";
    options.retry_count = 5;
    const std::vector<uint8_t> request = BuildRdgChannelRequest(options);
    const std::string text(request.begin(), request.end());
    CHECK(text.find("RDG-INCHANNEL-RETRYMODE") == std::string::npos);
}

RTSC_TEST(rdg_channel_request_rejects_crlf_and_nul_in_values) {
    // CRITICAL: a header value that smuggles CRLF would inject a whole new
    // header; the builder must fail (return an empty request the caller can
    // detect) instead of emitting it. Every fed value field is exercised.
    const std::string injected = "rgdv\r\nX-Injected: 1";
    RdgChannelRequestOptions out;
    out.method = kRdgOutData;
    out.direction = RdgChannelDirection::kOut;
    out.gateway_host = "gw:443";
    out.connection_id = "CID";
    out.user_agent = "ua";
    RdgChannelRequestOptions in = out;
    in.method = kRdgInData;
    in.direction = RdgChannelDirection::kIn;

    struct Case {
        RdgChannelRequestOptions& o;
        void (*set)(RdgChannelRequestOptions&, const std::string&);
    };
    const std::vector<Case> cases = {
        {in, [](RdgChannelRequestOptions& o, const std::string& v) { o.method = v; }},
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.gateway_host = v; }},
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.connection_id = v; }},
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.user_agent = v; }},
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.diagnostics_info = v; }},
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.correlation_id = v; }},
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.auth_scheme = v; }},
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.client_generation = v; }},
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.load_balancer_cookie = v; }},
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.app_build = v; }},
        {in, [](RdgChannelRequestOptions& o, const std::string& v) { o.user_id = v; }},
    };
    for (const Case& c : cases) {
        c.set(c.o, injected);
        const std::vector<uint8_t> req = BuildRdgChannelRequest(c.o);
        CHECK(req.empty());  // caller-visible failure
    }
}

RTSC_TEST(chunked_encode_is_byte_exact) {
    const std::string data = "hello world";
    const std::vector<uint8_t> encoded =
        ChunkedEncode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    CHECK(encoded == ToVec("b\r\nhello world\r\n0\r\n\r\n"));
}

RTSC_TEST(chunked_encode_empty_is_just_the_terminator) {
    const std::vector<uint8_t> encoded = ChunkedEncode(nullptr, 0);
    CHECK(encoded == ToVec("0\r\n\r\n"));
}

RTSC_TEST(chunked_decode_external_wire_bytes) {
    // External wire string -> decoded bytes (NOT an encode->decode round trip).
    // 0xb (11 bytes) then a 6-byte chunk with extensions on both size lines.
    ChunkedDecoder decoder;
    const std::vector<uint8_t> out =
        decoder.Feed(ToVec("b;attrib=ignored\r\n0123456789a\r\n6;ext=val\r\nBCDE\xEA\xF0\r\n0\r\n\r\n"));
    CHECK(out == ToVec("0123456789aBCDE\xEA\xF0"));
    CHECK(decoder.finished());
    CHECK(!decoder.failed());
    CHECK_EQ(decoder.decoded_total(), static_cast<size_t>(17));
}

RTSC_TEST(chunked_decode_uppercase_hex_and_trailer_wire) {
    ChunkedDecoder decoder;
    const std::vector<uint8_t> out = decoder.Feed(ToVec(
        "4\r\nABCD\r\n2\r\nXY\r\n0\r\nChecksum: 1234\r\nX-End: yes\r\n\r\n"));
    CHECK(out == ToVec("ABCDXY"));
    CHECK(decoder.finished());
    CHECK(!decoder.failed());
}

RTSC_TEST(chunked_decode_incremental_byte_feed) {
    const std::string wire = "4\r\nABCD\r\n0\r\n\r\n";
    ChunkedDecoder decoder;
    std::vector<uint8_t> out;
    for (const char c : wire) {
        const std::vector<uint8_t> part =
            decoder.Feed(reinterpret_cast<const uint8_t*>(&c), 1);
        out.insert(out.end(), part.begin(), part.end());
    }
    CHECK(out == ToVec("ABCD"));
    CHECK(decoder.finished());
    CHECK(!decoder.failed());
}

RTSC_TEST(chunked_decode_truncated_stream_is_an_error) {
    ChunkedDecoder decoder;
    decoder.Feed(ToVec("4\r\nABC"));
    CHECK(!decoder.failed());
    decoder.EndOfStream();
    CHECK(decoder.failed());
    CHECK(decoder.error() == ChunkedError::kTruncated);
}

RTSC_TEST(chunked_decode_rejects_non_hex_size_line) {
    ChunkedDecoder decoder;
    decoder.Feed(ToVec("ZZ\r\n"));
    CHECK(decoder.failed());
    CHECK(decoder.error() == ChunkedError::kInvalidHex);
}

RTSC_TEST(chunked_decode_rejects_negative_length_sizes) {
    // 0xFFFFFFFFFFFFFFFF and 0x8000000000000000 both wrap past 2^63.
    ChunkedDecoder first;
    first.Feed(ToVec("FFFFFFFFFFFFFFFF\r\n"));
    CHECK(first.error() == ChunkedError::kNegativeLength);

    ChunkedDecoder second;
    second.Feed(ToVec("8000000000000000\r\n"));
    CHECK(second.error() == ChunkedError::kNegativeLength);
}

RTSC_TEST(chunked_decode_rejects_chunk_over_the_ceiling) {
    // The default per-chunk ceiling is 16 MiB; 0x1000001 is one byte over.
    ChunkedDecoder decoder;
    decoder.Feed(ToVec("1000001\r\n"));
    CHECK(decoder.error() == ChunkedError::kChunkTooLarge);
    CHECK_EQ(decoder.decoded_total(), static_cast<size_t>(0));
}

RTSC_TEST(chunked_decode_rejects_oversized_total) {
    // First chunk of ~8 KiB parses; the chunk terminator is consumed; the
    // second size line's projected total (8192 + 12288) pushes the 0x3000 body
    // ceiling over. The check happens at the size line, before the data is
    // buffered.
    ChunkedDecoder decoder(0x100000, 0x3000);
    decoder.Feed(ToVec("2000\r\n"));
    CHECK(!decoder.failed());
    std::string blob(0x2000, 'A');
    const std::vector<uint8_t> data =
        decoder.Feed(reinterpret_cast<const uint8_t*>(blob.data()), blob.size());
    CHECK_EQ(data.size(), static_cast<size_t>(0x2000));
    CHECK_EQ(decoder.decoded_total(), static_cast<size_t>(0x2000));
    decoder.Feed(ToVec("\r\n"));
    CHECK(!decoder.failed());
    decoder.Feed(ToVec("3000\r\n"));
    CHECK(decoder.error() == ChunkedError::kTotalTooLarge);
}

RTSC_TEST(chunked_decode_rejects_bad_chunk_terminator) {
    ChunkedDecoder decoder;
    decoder.Feed(ToVec("4\r\nABCDXX\r\n"));
    CHECK(decoder.failed());
    CHECK(decoder.error() == ChunkedError::kInvalidField);
}

RTSC_TEST(chunked_decode_rejects_0x_prefixed_size) {
    // "0x10" must NOT parse as "0" + junk: the 'x' is neither a hex digit nor
    // the ';' that starts a chunk extension, so the whole size line is bad.
    ChunkedDecoder decoder;
    decoder.Feed(ToVec("0x10\r\nabc\r\n0\r\n\r\n"));
    CHECK(decoder.error() == ChunkedError::kInvalidHex);
}

RTSC_TEST(chunked_decode_rejects_leading_space_before_size) {
    ChunkedDecoder decoder;
    decoder.Feed(ToVec(" 4\r\nWiki\r\n0\r\n\r\n"));
    CHECK(decoder.failed());
}

RTSC_TEST(chunked_decode_rejects_trailing_junk_after_size) {
    ChunkedDecoder decoder;
    decoder.Feed(ToVec("4 garbage\r\nWiki\r\n0\r\n\r\n"));
    CHECK(decoder.failed());
}

RTSC_TEST(chunked_decode_rejects_lone_lf_line_endings) {
    ChunkedDecoder decoder;
    decoder.Feed(ToVec("4\nWiki\n0\n\n"));
    CHECK(decoder.failed());
}

RTSC_TEST(chunked_decode_rejects_garbage_before_the_size_line_crlf) {
    // "4xy\r\n" is hex then junk then a valid CRLF: the junk (not ';') must
    // reject the size line rather than silently passing the whole segment.
    ChunkedDecoder decoder;
    decoder.Feed(ToVec("4xy\r\nABCD\r\n0\r\n\r\n"));
    CHECK(decoder.error() == ChunkedError::kInvalidHex);

    ChunkedDecoder plus;
    plus.Feed(ToVec("+4\r\nABCD\r\n0\r\n\r\n"));
    CHECK(plus.error() == ChunkedError::kInvalidHex);
}

RTSC_TEST(chunked_decode_accepts_chunk_extension_after_semicolon) {
    ChunkedDecoder decoder;
    const std::vector<uint8_t> out = decoder.Feed(ToVec("4;ext=1\r\nWiki\r\n0\r\n\r\n"));
    CHECK(!decoder.failed());
    CHECK(out == ToVec("Wiki"));
    CHECK(decoder.finished());
}

RTSC_TEST(chunked_plain_fallback_detects_transfer_encoding) {
    HttpMessage plain;
    CHECK(!IsChunkedBody(plain));

    HttpMessage chunked;
    chunked.headers.push_back({"Transfer-Encoding", "chunked"});
    CHECK(IsChunkedBody(chunked));

    HttpMessage list;
    list.headers.push_back({"Transfer-Encoding", "gzip, chunked"});
    CHECK(IsChunkedBody(list));

    HttpMessage mixed_case;
    mixed_case.headers.push_back({"transfer-encoding", "ChunkEd"});
    CHECK(IsChunkedBody(mixed_case));

    HttpMessage identity;
    identity.headers.push_back({"Transfer-Encoding", "identity"});
    CHECK(!IsChunkedBody(identity));
}

RTSC_TEST(gateway_status_maps_to_hresult) {
    // Evidence: mstscax FUN_1801bdd8c.
    CHECK_EQ(MapGatewayStatusToHresult(401, false), 0x80070005u);
    CHECK_EQ(MapGatewayStatusToHresult(0, true), 0x80070532u);
    CHECK_EQ(MapGatewayStatusToHresult(401, true), 0x80070532u);
    CHECK_EQ(MapGatewayStatusToHresult(407, false), 0x800706C1u);
    CHECK_EQ(MapGatewayStatusToHresult(502, false), 0x800706BAu);
    CHECK_EQ(MapGatewayStatusToHresult(504, false), 0x800706BAu);
    CHECK_EQ(MapGatewayStatusToHresult(500, false), 0x80190000u | 500u);
    CHECK_EQ(MapGatewayStatusToHresult(200, false), 0x80190000u | 200u);
}

RTSC_TEST(rdg_auth_challenge_parses_scheme_and_realm) {
    RdgAuthChallenge out;
    CHECK(RdgAuthChallenge::parse_www_authenticate(
              "TLSAuth realm=\"terminal services\"", out) == Status::Ok);
    CHECK(out.scheme == "TLSAuth");
    CHECK(out.realm == "terminal services");

    CHECK(RdgAuthChallenge::parse_www_authenticate("Negotiate", out) ==
          Status::Ok);
    CHECK(out.scheme == "Negotiate");
    CHECK(out.realm.empty());
}

RTSC_TEST(rdg_auth_multiple_challenges_in_one_header_value) {
    std::vector<RdgAuthChallenge> out;
    CHECK(RdgAuthChallenge::parse_challenges("Negotiate, NTLM", out) ==
          Status::Ok);
    CHECK_EQ(out.size(), static_cast<size_t>(2));
    CHECK(out[0].scheme == "Negotiate");
    CHECK(out[1].scheme == "NTLM");
}

RTSC_TEST(rdg_auth_comma_inside_quoted_realm_does_not_split) {
    std::vector<RdgAuthChallenge> out;
    CHECK(RdgAuthChallenge::parse_challenges(
              "Digest realm=\"a,b\", Basic realm=\"c\"", out) == Status::Ok);
    CHECK_EQ(out.size(), static_cast<size_t>(2));
    CHECK(out[0].scheme == "Digest");
    CHECK(out[0].realm == "a,b");
    CHECK(out[1].scheme == "Basic");
    CHECK(out[1].realm == "c");
}

RTSC_TEST(rdg_auth_multiple_params_per_challenge) {
    RdgAuthChallenge out;
    CHECK(RdgAuthChallenge::parse_www_authenticate(
              "TLSAuth realm=\"terminal services\" version=1 algo=MD5", out) ==
          Status::Ok);
    CHECK(out.scheme == "TLSAuth");
    CHECK(out.realm == "terminal services");
    CHECK_EQ(out.params.size(), static_cast<size_t>(3));
    CHECK(out.params[0].key == "realm");
    CHECK(out.params[0].value == "terminal services");
    CHECK(out.params[1].key == "version");
    CHECK(out.params[1].value == "1");
    CHECK(out.params[2].key == "algo");
    CHECK(out.params[2].value == "MD5");
}

RTSC_TEST(rdg_auth_multiple_header_values_are_collected) {
    HttpMessage message;
    message.headers.push_back({"WWW-Authenticate", "Negotiate"});
    message.headers.push_back({"WWW-Authenticate", "NTLM, Basic realm=\"x\""});
    std::vector<RdgAuthChallenge> out;
    CHECK(ParseWwwAuthenticateHeaders(message, out) == Status::Ok);
    CHECK_EQ(out.size(), static_cast<size_t>(3));
    CHECK(out[0].scheme == "Negotiate");
    CHECK(out[1].scheme == "NTLM");
    CHECK(out[2].scheme == "Basic");
    CHECK(out[2].realm == "x");
}

RTSC_TEST(rdg_auth_missing_header_is_invalid) {
    HttpMessage message;
    std::vector<RdgAuthChallenge> out;
    CHECK(ParseWwwAuthenticateHeaders(message, out) == Status::InvalidField);
    CHECK(out.empty());
}

RTSC_TEST(rdg_auth_token68_challenge_is_accepted) {
    // "NTLM <base64>" has no '=' and the base64 may itself end in '='; it must
    // not be rejected (or split at the padding).
    RdgAuthChallenge out;
    CHECK(RdgAuthChallenge::parse_www_authenticate(
              "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
              out) == Status::Ok);
    CHECK(out.scheme == "NTLM");
    CHECK(out.token == "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==");
    CHECK(out.realm.empty());
    CHECK_EQ(out.params.size(), static_cast<size_t>(0));

    std::vector<RdgAuthChallenge> multi;
    CHECK(RdgAuthChallenge::parse_challenges(
              "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
              multi) == Status::Ok);
    CHECK_EQ(multi.size(), static_cast<size_t>(1));
    CHECK(multi[0].scheme == "Negotiate");
    CHECK(multi[0].token.rfind("TlRMTVNT", 0) == 0);
}

RTSC_TEST(rdg_auth_malformed_challenge_is_invalid) {
    HttpMessage message;
    // An empty param key ("=value") is structurally invalid, and token68 mixed
    // with params is invalid too.
    message.headers.push_back({"WWW-Authenticate", "Basic =value"});
    std::vector<RdgAuthChallenge> out;
    CHECK(ParseWwwAuthenticateHeaders(message, out) == Status::InvalidField);

    HttpMessage mixed;
    mixed.headers.push_back({"WWW-Authenticate", "Basic realm=\"x\" zzz"});
    std::vector<RdgAuthChallenge> out2;
    CHECK(ParseWwwAuthenticateHeaders(mixed, out2) == Status::InvalidField);
}

RTSC_TEST(rdg_auth_request_header_value) {
    RdgAuthRequest request;
    request.scheme = "TLSAuth";
    request.token = "AAECAw==";
    CHECK(request.header_value() == "TLSAuth AAECAw==");
}

RTSC_TEST(rdg_soap_envelope_carries_the_token) {
    RdgSoapOptions options;
    options.action = "http://schemas.microsoft.com/rdg/CreateTunnel";
    options.message_id = "12345678-1234-1234-1234-123456789012";
    options.token = "AAECAwQFBgc=";
    options.service = "https://gateway.example/remoteDesktopGateway/";
    const std::vector<uint8_t> envelope = BuildRdgSoapEnvelope(options);
    const std::string text(envelope.begin(), envelope.end());

    CHECK(text.rfind("<?xml version=\"1.0\"", 0) == 0);
    CHECK(text.find("<s:Envelope") != std::string::npos);
    CHECK(text.find("AAECAwQFBgc=") != std::string::npos);
    CHECK(text.find("urn:uuid:12345678-1234-1234-1234-123456789012") !=
          std::string::npos);
}

RTSC_TEST(udp_fec_header_round_trips) {
    UdpFecHeader in;
    in.source_ack = 0xFFFF0001;
    in.receive_window_size = 64;
    in.flags = kUdpFlagData | kUdpFlagAck;
    const std::vector<uint8_t> bytes = UdpFecHeader::build(in);
    CHECK_EQ(bytes.size(), static_cast<size_t>(8));

    UdpFecHeader out;
    CHECK(UdpFecHeader::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.source_ack, static_cast<uint32_t>(0xFFFF0001));
    CHECK_EQ(out.receive_window_size, static_cast<uint16_t>(64));
    CHECK(out.has_flag(kUdpFlagData));
    CHECK(out.has_flag(kUdpFlagAck));
    CHECK(!out.has_flag(kUdpFlagSyn));
}

RTSC_TEST(udp_data_frame_round_trips) {
    UdpDataFrame in;
    in.fec.source_ack = 4;
    in.fec.receive_window_size = 64;
    in.fec.flags = kUdpFlagData;
    in.source.coded = 7;
    in.source.source_start = 9;
    in.payload = {0xDE, 0xAD, 0xBE, 0xEF};

    const std::vector<uint8_t> bytes = UdpDataFrame::build(in);
    CHECK_EQ(bytes.size(), static_cast<size_t>(8 + 8 + 4));

    UdpDataFrame out;
    CHECK(UdpDataFrame::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.fec.flags, static_cast<uint16_t>(kUdpFlagData));
    CHECK_EQ(out.source.coded, static_cast<uint32_t>(7));
    CHECK_EQ(out.source.source_start, static_cast<uint32_t>(9));
    CHECK(out.payload == in.payload);
}

RTSC_TEST(udp_ack_frame_round_trips) {
    UdpAckFrame in;
    in.fec.source_ack = 42;
    in.fec.receive_window_size = 128;
    in.fec.flags = kUdpFlagAck;
    const std::vector<uint8_t> bytes = UdpAckFrame::build(in);

    UdpAckFrame out;
    CHECK(UdpAckFrame::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK_EQ(out.fec.source_ack, static_cast<uint32_t>(42));
    CHECK_EQ(out.fec.receive_window_size, static_cast<uint16_t>(128));
}

RTSC_TEST(udp_syn_round_trips_with_and_without_synex) {
    UdpSyn in;
    in.fec.flags = kUdpFlagSyn | kUdpFlagSynlossy;
    in.fec.receive_window_size = 16;
    in.initial_sequence_number = 0x12345678;
    in.upstream_mtu = 1132;
    in.downstream_mtu = 1232;
    in.has_synex = true;
    in.synex_flags = 0x0001;  // RDPUDP_VERSION_INFO_VALID
    in.udp_version = 0x0002;  // RDPUDP_PROTOCOL_VERSION_2

    const std::vector<uint8_t> bytes = UdpSyn::build(in);
    UdpSyn out;
    CHECK(UdpSyn::parse(bytes.data(), bytes.size(), out) == Status::Ok);
    CHECK(out.has_synex);
    CHECK_EQ(out.initial_sequence_number, static_cast<uint32_t>(0x12345678));
    CHECK_EQ(out.upstream_mtu, static_cast<uint16_t>(1132));
    CHECK_EQ(out.downstream_mtu, static_cast<uint16_t>(1232));
    CHECK(out.fec.has_flag(kUdpFlagSynlossy));
    CHECK_EQ(out.synex_flags, static_cast<uint16_t>(0x0001));
    CHECK_EQ(out.udp_version, static_cast<uint16_t>(0x0002));

    UdpSyn plain;
    plain.fec.flags = kUdpFlagSyn;
    plain.initial_sequence_number = 1;
    plain.upstream_mtu = 1132;
    plain.downstream_mtu = 1132;
    const std::vector<uint8_t> plain_bytes = UdpSyn::build(plain);
    CHECK(UdpSyn::parse(plain_bytes.data(), plain_bytes.size(), out) ==
          Status::Ok);
    CHECK(!out.has_synex);
}

RTSC_TEST(multitransport_request_round_trips) {
    MultitransportRequest in;
    in.request_id = 0x11223344;
    in.requested_protocol = kUdpFecReliable;
    in.reserved = 0;
    in.security_cookie = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    const std::vector<uint8_t> bytes = MultitransportRequest::build(in);
    CHECK_EQ(bytes.size(), static_cast<size_t>(24));

    MultitransportRequest out;
    CHECK(MultitransportRequest::parse(bytes.data(), bytes.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.request_id, static_cast<uint32_t>(0x11223344));
    CHECK_EQ(out.requested_protocol, static_cast<uint16_t>(kUdpFecReliable));
    CHECK(out.security_cookie == in.security_cookie);
}

RTSC_TEST(multitransport_response_round_trips) {
    MultitransportResponse in;
    in.request_id = 7;
    in.result_code = 0;  // S_OK
    const std::vector<uint8_t> bytes = MultitransportResponse::build(in);
    CHECK_EQ(bytes.size(), static_cast<size_t>(8));

    MultitransportResponse out;
    CHECK(MultitransportResponse::parse(bytes.data(), bytes.size(), out) ==
          Status::Ok);
    CHECK_EQ(out.request_id, static_cast<uint32_t>(7));
    CHECK_EQ(out.result_code, static_cast<uint32_t>(0));
}

RTSC_TEST(gateway_tunnel_connects_and_passes_through) {
    MockTransport inner;
    std::vector<uint8_t> response = HttpResponse(200, "OK");
    const std::vector<uint8_t> payload = {0x03, 0x00, 0x00, 0x10, 0xAA, 0xBB};
    response.insert(response.end(), payload.begin(), payload.end());
    inner.to_read = response;

    GatewayTunnel::Config config;
    config.target = "server.example:3389";
    config.gateway_host = "gateway.example:443";
    config.user_agent = "rtsc";
    GatewayTunnel tunnel(inner, config);

    CHECK(tunnel.open());
    CHECK_EQ(tunnel.status_code(), 200);
    CHECK(tunnel.error().empty());

    const std::string head(inner.written.begin(), inner.written.end());
    CHECK(head.rfind("CONNECT server.example:3389 HTTP/1.1\r\n", 0) == 0);

    uint8_t buf[16] = {};
    const int n = tunnel.Read(buf, sizeof(buf));
    CHECK_EQ(n, static_cast<int>(payload.size()));
    CHECK(std::memcmp(buf, payload.data(), payload.size()) == 0);

    CHECK(tunnel.Write(payload.data(), payload.size()));
    CHECK_EQ(inner.written.size(), head.size() + payload.size());
}

RTSC_TEST(gateway_tunnel_rejects_non_200_response) {
    MockTransport inner;
    inner.to_read = HttpResponse(407, "Proxy Authentication Required");

    GatewayTunnel::Config config;
    config.target = "server.example:3389";
    config.gateway_host = "gateway.example:443";
    config.user_agent = "rtsc";
    GatewayTunnel tunnel(inner, config);

    CHECK(!tunnel.open());
    CHECK_EQ(tunnel.status_code(), 407);
    CHECK(!tunnel.error().empty());
}

RTSC_TEST(udp_transport_unreliable_delivers_a_datagram) {
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());

    UdpTransport::Config config;
    config.mode = UdpMode::kUnreliable;
    UdpTransport client(std::move(sock_a), config);
    UdpTransport server(std::move(sock_b), config);

    const uint8_t data[] = {1, 2, 3, 4};
    CHECK(client.Write(data, sizeof(data)));
    CHECK(!client.reliable());
    CHECK_EQ(client.send_count(), static_cast<unsigned>(1));

    uint8_t buf[16] = {};
    const int n = server.Read(buf, sizeof(buf));
    CHECK_EQ(n, static_cast<int>(sizeof(data)));
    CHECK(std::memcmp(buf, data, sizeof(data)) == 0);
}

RTSC_TEST(udp_transport_reliable_ping_pong_over_loopback) {
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());

    UdpTransport::Config config;
    config.mode = UdpMode::kReliable;
    config.ack_timeout_ms = 200;
    config.max_retries = 5;
    UdpTransport client(std::move(sock_a), config);
    UdpTransport server(std::move(sock_b), config);

    bool server_read_ok = false;
    std::vector<uint8_t> received;
    std::thread server_thread([&] {
        // Loop until the datagram arrives: Read() reports a bounded timeout
        // (kReadTimeout) while the peer is silent, which is not a disconnect.
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!server_read_ok && std::chrono::steady_clock::now() < deadline) {
            uint8_t buf[64];
            const int n = server.Read(buf, sizeof(buf));
            if (n > 0) {
                received.assign(buf, buf + n);
                server_read_ok = true;
            }
        }
        const uint8_t reply[] = {0x10, 0x20, 0x30};
        server.Write(reply, sizeof(reply));
    });

    const uint8_t data[] = {0xCA, 0xFE};
    CHECK(client.Write(data, sizeof(data)));
    CHECK_EQ(client.send_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.retry_count(), static_cast<unsigned>(0));
    CHECK(server_read_ok);
    CHECK((received == std::vector<uint8_t>{0xCA, 0xFE}));

    // Read() reports a bounded timeout while the peer is silent, so poll until
    // the reply arrives.
    uint8_t buf[64] = {};
    int n = -2;
    const auto read_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (n <= 0 && std::chrono::steady_clock::now() < read_deadline) {
        n = client.Read(buf, sizeof(buf));
    }
    CHECK_EQ(n, 3);
    CHECK(std::memcmp(buf, "\x10\x20\x30", 3) == 0);

    server_thread.join();
    CHECK_EQ(server.ack_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.ack_count(), static_cast<unsigned>(1));
}

RTSC_TEST(udp_transport_reliable_retransmits_a_dropped_datagram) {
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());
    LoopbackUdpSocket* client_sock = sock_a.get();

    UdpTransport::Config config;
    config.mode = UdpMode::kReliable;
    config.ack_timeout_ms = 50;
    config.max_retries = 5;
    UdpTransport client(std::move(sock_a), config);
    UdpTransport server(std::move(sock_b), config);

    bool server_read_ok = false;
    std::thread server_thread([&] {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!server_read_ok && std::chrono::steady_clock::now() < deadline) {
            uint8_t buf[64];
            const int n = server.Read(buf, sizeof(buf));
            if (n > 0) server_read_ok = true;
        }
    });

    // Drop the client's first data frame so the transport must retransmit.
    client_sock->DropNext(1);
    const uint8_t data[] = {0x55};
    CHECK(client.Write(data, sizeof(data)));
    CHECK(client.retry_count() >= 1u);
    CHECK(server_read_ok);

    server_thread.join();
}

RTSC_TEST(udp_transport_queues_two_frames_without_loss) {
    // D8: while the transport is inside SendDataFrame's ACK wait it drains the
    // socket; two inbound frames arriving back-to-back must both end up queued,
    // never overwriting each other (the old single stash slot dropped "first").
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());
    LoopbackUdpSocket* injector = sock_b.get();

    UdpTransport::Config config;
    config.mode = UdpMode::kReliable;
    config.ack_timeout_ms = 50;
    config.max_retries = 1;
    UdpTransport receiver(std::move(sock_a), config);

    const std::vector<uint8_t> d1 = MakeDataDatagram(1, ToVec("first"));
    const std::vector<uint8_t> d2 = MakeDataDatagram(2, ToVec("second"));
    injector->Send(d1.data(), d1.size());
    injector->Send(d2.data(), d2.size());
    // ACK for the receiver's own outbound frame so Write() completes.
    const std::vector<uint8_t> ack = MakeAckDatagram(1);
    injector->Send(ack.data(), ack.size());

    const uint8_t probe[] = {0x09};
    CHECK(receiver.Write(probe, 1));

    uint8_t buf[64] = {};
    const int n1 = receiver.Read(buf, sizeof(buf));
    CHECK_EQ(n1, 5);
    if (n1 == 5) CHECK(std::memcmp(buf, "first", 5) == 0);
    const int n2 = receiver.Read(buf, sizeof(buf));
    CHECK_EQ(n2, 6);
    if (n2 == 6) CHECK(std::memcmp(buf, "second", 6) == 0);
}

RTSC_TEST(udp_transport_acks_on_enqueue_and_delivers_without_loss) {
    // D8/R1 (audited ACK contract): an ACK is sent when the frame is durably
    // queued in the bounded FIFO -- loss-free and independent of the reader's
    // cadence -- so a peer that docks the frame in Write()'s drain loop must
    // already see the ACK before any Read(), and the data must still deliver.
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());
    LoopbackUdpSocket* peer = sock_b.get();

    UdpTransport::Config config;
    config.mode = UdpMode::kReliable;
    config.ack_timeout_ms = 50;
    config.max_retries = 1;
    UdpTransport receiver(std::move(sock_a), config);

    const std::vector<uint8_t> data = MakeDataDatagram(42, ToVec("payload"));
    const std::vector<uint8_t> our_ack = MakeAckDatagram(1);
    peer->Send(data.data(), data.size());
    peer->Send(our_ack.data(), our_ack.size());

    const uint8_t probe[] = {0x09};
    CHECK(receiver.Write(probe, 1));

    uint8_t scratch[64] = {};
    // The receiver's own outbound frame lands first in the peer's queue.
    CHECK(peer->Receive(scratch, sizeof(scratch)) > 0);
    // The queued remote frame was ACKed at enqueue, before any Read().
    const int ack_n = peer->Receive(scratch, sizeof(scratch));
    CHECK(ack_n > 0);
    UdpAckFrame ack;
    CHECK(UdpAckFrame::parse(scratch, ack_n, ack) == Status::Ok);
    CHECK_EQ(ack.fec.source_ack, static_cast<uint32_t>(42));

    // The data is still intact for the reader (no overwrite loss).
    uint8_t buf[64] = {};
    const int n = receiver.Read(buf, sizeof(buf));
    CHECK_EQ(n, 7);
    if (n == 7) CHECK(std::memcmp(buf, "payload", 7) == 0);
}

RTSC_TEST(udp_transport_ack_arrival_is_not_a_read_timeout) {
    // D9: an ACK datagram consumed by Read() must not surface as kReadTimeout;
    // the transport must keep polling and deliver the queued data frame.
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());
    LoopbackUdpSocket* peer = sock_b.get();

    UdpTransport::Config config;
    config.mode = UdpMode::kReliable;
    UdpTransport receiver(std::move(sock_a), config);

    const std::vector<uint8_t> ack = MakeAckDatagram(9);
    const std::vector<uint8_t> data = MakeDataDatagram(10, ToVec("data"));
    peer->Send(ack.data(), ack.size());
    peer->Send(data.data(), data.size());

    uint8_t buf[64] = {};
    const int n = receiver.Read(buf, sizeof(buf));
    CHECK_EQ(n, 4);
    if (n == 4) CHECK(std::memcmp(buf, "data", 4) == 0);
}

RTSC_TEST(udp_transport_sequence_wrap_is_not_a_duplicate) {
    // D12: source_start 0x00000000 follows 0xFFFFFFFF (mod 2^32) and must be a
    // fresh frame; a genuine repeat of an older sequence must still count.
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());
    LoopbackUdpSocket* injector = sock_b.get();

    UdpTransport::Config config;
    config.mode = UdpMode::kUnreliable;
    UdpTransport receiver(std::move(sock_a), config);

    const std::vector<uint8_t> a = MakeDataDatagram(0xFFFFFFFFu, ToVec("a"));
    const std::vector<uint8_t> b = MakeDataDatagram(0x00000000u, ToVec("b"));
    injector->Send(a.data(), a.size());
    injector->Send(b.data(), b.size());

    uint8_t buf[64] = {};
    CHECK_EQ(receiver.Read(buf, sizeof(buf)), 1);
    CHECK_EQ(buf[0], 'a');
    CHECK_EQ(receiver.duplicate_count(), static_cast<unsigned>(0));
    CHECK_EQ(receiver.Read(buf, sizeof(buf)), 1);
    CHECK_EQ(buf[0], 'b');
    CHECK_EQ(receiver.duplicate_count(), static_cast<unsigned>(0));

    const std::vector<uint8_t> dup =
        MakeDataDatagram(0xFFFFFFFFu, ToVec("x"));
    injector->Send(dup.data(), dup.size());
    CHECK_EQ(receiver.Read(buf, sizeof(buf)), kReadTimeout);  // dropped
    CHECK_EQ(receiver.duplicate_count(), static_cast<unsigned>(1));
}

RTSC_TEST(udp_transport_bad_datagrams_do_not_disconnect) {
    // D13: malformed datagrams are counted and skipped; only the cap forces a
    // failure, so valid traffic behind them still flows.
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());
    LoopbackUdpSocket* injector = sock_b.get();

    UdpTransport::Config config;
    config.mode = UdpMode::kUnreliable;
    config.max_bad_datagrams = 2;
    UdpTransport receiver(std::move(sock_a), config);

    const std::vector<uint8_t> bad = {0x07, 0x00, 0x00, 0x01};
    injector->Send(bad.data(), bad.size());
    injector->Send(bad.data(), bad.size());

    const std::vector<uint8_t> good = MakeDataDatagram(1, ToVec("ok"));
    injector->Send(good.data(), good.size());

    uint8_t buf[64] = {};
    const int n = receiver.Read(buf, sizeof(buf));
    CHECK_EQ(n, 2);
    if (n == 2) CHECK(std::memcmp(buf, "ok", 2) == 0);
    CHECK_EQ(receiver.bad_datagram_count(), static_cast<unsigned>(2));

    // Third malformed datagram blows past the cap: the transport now fails.
    injector->Send(bad.data(), bad.size());
    CHECK_EQ(receiver.Read(buf, sizeof(buf)), -1);
}

RTSC_TEST(udp_transport_inbound_queue_is_bounded) {
    // R2: the inbound queue is capped by the receive window, so a flooding
    // peer cannot grow memory without bound. A frame received while the queue
    // is full is dropped (and not ACKed).
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());
    LoopbackUdpSocket* injector = sock_b.get();

    UdpTransport::Config config;
    config.mode = UdpMode::kReliable;
    config.receive_window_size = 1;
    config.ack_timeout_ms = 50;
    config.max_retries = 1;
    UdpTransport receiver(std::move(sock_a), config);

    const std::vector<uint8_t> d1 = MakeDataDatagram(1, ToVec("one"));
    const std::vector<uint8_t> d2 = MakeDataDatagram(2, ToVec("two"));
    const std::vector<uint8_t> our_ack = MakeAckDatagram(1);
    injector->Send(d1.data(), d1.size());
    injector->Send(d2.data(), d2.size());
    injector->Send(our_ack.data(), our_ack.size());

    const uint8_t probe[] = {0x09};
    CHECK(receiver.Write(probe, 1));  // drain loop receives all three

    CHECK_EQ(receiver.stash_drop_count(), static_cast<unsigned>(1));

    uint8_t buf[64] = {};
    const int n = receiver.Read(buf, sizeof(buf));
    CHECK_EQ(n, 3);
    if (n == 3) CHECK(std::memcmp(buf, "one", 3) == 0);
    // The dropped frame is gone for good (no ACK was sent for it).
    CHECK_EQ(receiver.Read(buf, sizeof(buf)), kReadTimeout);
    CHECK_EQ(receiver.stash_drop_count(), static_cast<unsigned>(1));
}

RTSC_TEST(udp_transport_retransmit_reenters_after_the_window_frees) {
    // Parent mandate 1: a frame dropped when the queue is full must NOT be
    // silently lost forever. Once a slot frees (a read) the sender's
    // retransmission of the same sequence must be accepted, queued and
    // delivered -- proving the drop is flow control, not data loss.
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());
    LoopbackUdpSocket* injector = sock_b.get();

    UdpTransport::Config config;
    config.mode = UdpMode::kReliable;
    config.receive_window_size = 1;
    config.ack_timeout_ms = 50;
    config.max_retries = 1;
    UdpTransport receiver(std::move(sock_a), config);

    // Two frames, then the ACK for the receiver's own outbound frame. The
    // drain loop in Write() queues the first and drops the second (queue
    // full), proving the drop is just backpressure: frame 2 was never ACKed.
    const std::vector<uint8_t> f1 = MakeDataDatagram(1, ToVec("one"));
    const std::vector<uint8_t> f2 = MakeDataDatagram(2, ToVec("two"));
    const std::vector<uint8_t> our_ack = MakeAckDatagram(1);
    injector->Send(f1.data(), f1.size());
    injector->Send(f2.data(), f2.size());
    injector->Send(our_ack.data(), our_ack.size());

    const uint8_t probe[] = {0x09};
    CHECK(receiver.Write(probe, 1));
    CHECK_EQ(receiver.stash_drop_count(), static_cast<unsigned>(1));

    // The reader consumes the first frame, freeing one slot.
    uint8_t buf[64] = {};
    const int n1 = receiver.Read(buf, sizeof(buf));
    CHECK_EQ(n1, 3);
    if (n1 == 3) CHECK(std::memcmp(buf, "one", 3) == 0);

    // The sender retransmits the same sequence (frame 2). With a slot free it
    // must be accepted into the queue, ACKed, and delivered -- not dropped as
    // a stale duplicate.
    injector->Send(f2.data(), f2.size());
    const int n2 = receiver.Read(buf, sizeof(buf));
    CHECK_EQ(n2, 3);
    if (n2 == 3) CHECK(std::memcmp(buf, "two", 3) == 0);
    CHECK_EQ(receiver.stash_drop_count(), static_cast<unsigned>(1));
    CHECK_EQ(receiver.duplicate_count(), static_cast<unsigned>(0));
}

RTSC_TEST(udp_transport_two_sides_write_concurrently_progresses) {
    // R1: two reliable transports writing at once (no Read in between) must
    // both complete. With the D8 ruling, ACK is emitted on enqueue (sourceAck
    // = the received prefix's right edge), so each side's drain loop ACKs the
    // other's in-flight frame and both writes make progress without a
    // concurrent reader.
    auto sock_a = std::make_unique<LoopbackUdpSocket>();
    auto sock_b = std::make_unique<LoopbackUdpSocket>();
    sock_a->SetPeer(sock_b.get());
    sock_b->SetPeer(sock_a.get());

    UdpTransport::Config config;
    config.mode = UdpMode::kReliable;
    config.ack_timeout_ms = 80;
    config.max_retries = 12;
    UdpTransport a(std::move(sock_a), config);
    UdpTransport b(std::move(sock_b), config);

    std::atomic<bool> ok_a{false};
    std::atomic<bool> ok_b{false};
    const uint8_t a_msg[] = {0xAA, 0xBB};
    const uint8_t b_msg[] = {0x11, 0x22, 0x33};
    std::thread ta([&] { ok_a.store(a.Write(a_msg, sizeof(a_msg))); });
    std::thread tb([&] { ok_b.store(b.Write(b_msg, sizeof(b_msg))); });
    ta.join();
    tb.join();
    CHECK(ok_a.load());
    CHECK(ok_b.load());

    // The cross-delivered payloads are intact and in order.
    uint8_t buf[16] = {};
    const int na = a.Read(buf, sizeof(buf));
    CHECK_EQ(na, static_cast<int>(sizeof(b_msg)));
    if (na == static_cast<int>(sizeof(b_msg))) {
        CHECK(std::memcmp(buf, b_msg, sizeof(b_msg)) == 0);
    }
    const int nb = b.Read(buf, sizeof(buf));
    CHECK_EQ(nb, static_cast<int>(sizeof(a_msg)));
    if (nb == static_cast<int>(sizeof(a_msg))) {
        CHECK(std::memcmp(buf, a_msg, sizeof(a_msg)) == 0);
    }
}

RTSC_TEST(gateway_tunnel_end_to_end_against_the_in_tree_server) {
    rtsc::server::ServerConfig scfg;
    scfg.port = 0;  // ephemeral: the kernel picks a free port
    scfg.desktop_width = 64;
    scfg.desktop_height = 48;
    auto source = rtsc::server::MakeTestPatternSource();
    rtsc::server::RdpServer server(scfg);
    server.SetDesktopSource(source.get());

    std::string error;
    CHECK(server.Start(error));
    std::thread server_thread([&server]() { server.Run(); });

    // Both listeners bind an ephemeral port, so two concurrent runs of this
    // suite (or any other process on the machine) can no longer collide.
    MockGateway gateway(/*gateway_port=*/0, server.bound_port());
    CHECK(gateway.Start(error));

    ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = kProtocolRdp;
    mcfg.desktop_width = 64;
    mcfg.desktop_height = 48;
    mcfg.client_name = "RTSC";
    mcfg.encryption_methods = 0;  // plaintext Standard RDP Security

    ConnectMachine::Credentials creds;
    creds.domain = "NTDEV";
    creds.user_name = "rtsc";

    rtsc::security::Config secfg;
    rtsc::security::ConnectionDriver driver(mcfg, creds, secfg);
    rtsc::client::Client client(std::move(driver), 64, 48);

    std::string cerr;
    auto tcp = rtsc::net::ConnectTcp("127.0.0.1", gateway.bound_port(), cerr);
    CHECK(tcp != nullptr);
    if (tcp != nullptr) {
        GatewayTunnel::Config tcfg;
        tcfg.target = "127.0.0.1:3389";
        const std::string gateway_host =
            "127.0.0.1:" + std::to_string(gateway.bound_port());
        tcfg.gateway_host = gateway_host;
        tcfg.user_agent = "rtsc";
        tcfg.connect_timeout_ms = 5000;
        GatewayTunnel tunnel(*tcp, tcfg);
        CHECK(tunnel.open());
        CHECK(client.Connect(tunnel, error));
        if (!error.empty()) std::printf("  connect error: %s\n", error.c_str());
        CHECK(client.active());
        CHECK(client.driver().standard_rdp());
        CHECK_EQ(gateway.connect_requests(), static_cast<unsigned>(1));

        bool got_frame = false;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!got_frame && std::chrono::steady_clock::now() < deadline) {
            if (!client.Pump(tunnel, error)) break;
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (client.surface().GetPixel(0, 0, r, g, b, a) && r == 255 &&
                g == 255 && b == 255 && a == 255) {
                got_frame = true;
            }
        }
        if (!got_frame) std::printf("  frame error: %s\n", error.c_str());
        CHECK(got_frame);
        tcp->Close();
    }

    gateway.Stop();
    server.Stop();
    server_thread.join();
}

// ---------------------------------------------------------------------------
// Memory ceilings. Each case feeds a bounded but hostile input and requires the
// parser/tunnel to fail fast instead of growing in proportion to what the peer
// claims. They are deliberately small so a regression fails here, fast and under
// a memory watchdog, instead of taking the machine down again.
// ---------------------------------------------------------------------------

namespace {

std::vector<uint8_t> Bytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

// Serves `script` in `chunk`-byte slices, then goes silent: Read() keeps
// returning kReadTimeout (never EOF), optionally sleeping so the caller sees a
// real blocking socket's cadence. served() counts the bytes actually handed out,
// which is how a test proves the tunnel stopped reading instead of accumulating.
class ScriptedStallTransport : public Transport {
 public:
    ScriptedStallTransport(std::vector<uint8_t> script, size_t chunk,
                           int stall_ms = 0)
        : script_(std::move(script)), chunk_(chunk), stall_ms_(stall_ms) {}

    int Read(uint8_t* buf, size_t size) override {
        ++reads_;
        if (offset_ < script_.size()) {
            const size_t n = (std::min)((std::min)(chunk_, size),
                                        script_.size() - offset_);
            std::memcpy(buf, script_.data() + offset_, n);
            offset_ += n;
            served_ += n;
            return static_cast<int>(n);
        }
        if (stall_ms_ > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(stall_ms_));
        }
        return kReadTimeout;
    }
    bool Write(const uint8_t*, size_t) override { return true; }
    void Close() override {}

    size_t served() const { return served_; }
    unsigned reads() const { return reads_; }

 private:
    std::vector<uint8_t> script_;
    size_t chunk_;
    int stall_ms_;
    size_t offset_ = 0;
    size_t served_ = 0;
    unsigned reads_ = 0;
};

}  // namespace

RTSC_TEST(http_message_rejects_a_huge_content_length) {
    // 4294967295 is the classic 4 GiB announcement. It must be rejected from the
    // header alone; nothing may be sized from it.
    const std::vector<uint8_t> wire =
        Bytes("HTTP/1.1 200 OK\r\nContent-Length: 4294967295\r\n\r\n");
    HttpMessage out;
    size_t consumed = 0;
    const Status st = HttpMessage::parse(wire.data(), wire.size(), out, consumed);
    std::printf("  huge content-length: status=%s consumed=%zu\n", to_string(st),
                consumed);
    CHECK(st == Status::InvalidLength);
    CHECK_EQ(consumed, static_cast<size_t>(0));
    CHECK(out.headers.size() <= 1);
}

RTSC_TEST(http_message_rejects_a_wrapping_content_length) {
    // "18446744073709551616" is 2^64, one unit above a SIZE_MAX ceiling. The
    // old check multiplied first (value = value*10 + d) and only then compared,
    // so with a near-SIZE_MAX ceiling the accumulator wrapped to a small value
    // and the claim sailed through. The bounded compare must reject it from the
    // digits alone.
    HttpLimits huge;
    huge.max_entity_bytes = std::numeric_limits<size_t>::max();
    const std::string wire_text =
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n";
    const std::vector<uint8_t> wire(wire_text.begin(), wire_text.end());
    HttpMessage out;
    size_t consumed = 0;
    const Status st =
        HttpMessage::parse(wire.data(), wire.size(), out, consumed, huge);
    std::printf("  wrapping content-length: status=%s consumed=%zu\n",
                to_string(st), consumed);
    CHECK(st == Status::InvalidLength);
    CHECK_EQ(consumed, static_cast<size_t>(0));
    // The smell: a legitimate claim equal to the ceiling is still accepted, so
    // the ceiling itself is not mis-detected.
    const std::string ok_text =
        "HTTP/1.1 200 OK\r\nContent-Length: " +
        std::to_string(std::numeric_limits<size_t>::max()) + "\r\n\r\n";
    const std::vector<uint8_t> ok(ok_text.begin(), ok_text.end());
    CHECK(HttpMessage::parse(ok.data(), ok.size(), out, consumed, huge) ==
          Status::Ok);
}

RTSC_TEST(http_message_rejects_an_oversized_header_block) {
    // A head past the 64 KiB ceiling is a hard failure, never NeedMoreData:
    // waiting for more bytes is exactly what would keep growing the buffer.
    std::vector<uint8_t> wire = Bytes("HTTP/1.1 200 OK\r\n");
    for (size_t i = 0; i < 400; ++i) {
        const std::vector<uint8_t> line =
            Bytes("X-Pad-" + std::to_string(i) + ": " + std::string(200, 'a') +
                  "\r\n");
        wire.insert(wire.end(), line.begin(), line.end());
    }
    const std::vector<uint8_t> blank = Bytes("\r\n");
    wire.insert(wire.end(), blank.begin(), blank.end());
    std::printf("  oversized head: %zu bytes\n", wire.size());
    CHECK(wire.size() > 64u * 1024u);

    HttpMessage out;
    size_t consumed = 0;
    const Status st = HttpMessage::parse(wire.data(), wire.size(), out, consumed);
    std::printf("  oversized head: status=%s\n", to_string(st));
    CHECK(st == Status::InvalidLength);
}

RTSC_TEST(http_message_rejects_too_many_headers) {
    // Byte size alone is not enough: 600 tiny headers fit well inside 64 KiB but
    // each costs a std::string plus a vector slot, so the count ceiling has to
    // reject them on its own.
    std::vector<uint8_t> wire = Bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n");
    const std::vector<uint8_t> tiny = Bytes("a: b\r\n");
    for (size_t i = 0; i < 600; ++i) {
        wire.insert(wire.end(), tiny.begin(), tiny.end());
    }
    const std::vector<uint8_t> blank = Bytes("\r\n");
    wire.insert(wire.end(), blank.begin(), blank.end());
    CHECK(wire.size() < 64u * 1024u);

    HttpMessage out;
    size_t consumed = 0;
    const Status st = HttpMessage::parse(wire.data(), wire.size(), out, consumed);
    std::printf("  header count: bytes=%zu status=%s headers=%zu\n", wire.size(),
                to_string(st), out.headers.size());
    CHECK(st == Status::InvalidLength);
    CHECK(out.headers.size() <= 512);
}

RTSC_TEST(gateway_tunnel_stops_buffering_at_the_head_ceiling) {
    // 256 slices of 4 KiB (1 MiB) behind a head that never terminates, then
    // silence with the connection still open. The client must stop at its own
    // head ceiling instead of accumulating every slice or waiting for a blank
    // line that never arrives.
    std::vector<uint8_t> script = Bytes("HTTP/1.1 200 OK\r\nX-Pad: ");
    script.resize(script.size() + 256 * 4096, 'a');
    ScriptedStallTransport inner(std::move(script), 4096);

    GatewayTunnel::Config config;
    config.target = "server.example:3389";
    config.gateway_host = "gateway.example:443";
    config.user_agent = "rtsc";
    config.connect_timeout_ms = 5000;
    config.session_timeout_ms = 5000;

    const auto start = std::chrono::steady_clock::now();
    GatewayTunnel tunnel(inner, config);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    std::printf("  head ceiling: served=%zu reads=%u elapsed_ms=%lld error=%s\n",
                inner.served(), inner.reads(),
                static_cast<long long>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
                        .count()),
                tunnel.error().c_str());

    CHECK(!tunnel.open());
    // The 64 KiB head ceiling plus at most one 4 KiB read of overshoot: the
    // transport offered 1 MiB, and the client stopped near 64 KiB.
    CHECK(inner.served() <= 64u * 1024u + 4096u);
    CHECK(tunnel.error().find("size limit") != std::string::npos);
    // Both deadlines were 5 s, so this proves the ceiling and not a timeout ended
    // it.
    CHECK(elapsed < std::chrono::milliseconds(500));
}

RTSC_TEST(gateway_tunnel_gives_up_when_the_peer_stops_making_progress) {
    // The peer stops sending mid-head while the connection stays open. The
    // overall CONNECT deadline is 3 s and the inactivity deadline is 300 ms, so
    // only the inactivity deadline can end this quickly -- and it must report
    // itself as such, not as a size or budget failure.
    std::vector<uint8_t> script = Bytes("HTTP/1.1 200 OK\r\nX-Partial: ");
    script.resize(script.size() + 100, 'a');
    ScriptedStallTransport inner(std::move(script), 4096, 5);

    GatewayTunnel::Config config;
    config.target = "server.example:3389";
    config.gateway_host = "gateway.example:443";
    config.connect_timeout_ms = 3000;
    config.session_timeout_ms = 300;

    const auto start = std::chrono::steady_clock::now();
    GatewayTunnel tunnel(inner, config);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    std::printf("  no progress: served=%zu reads=%u elapsed_ms=%lld bytes_read=%zu error=%s\n",
                inner.served(), inner.reads(),
                static_cast<long long>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
                        .count()),
                tunnel.bytes_read(), tunnel.error().c_str());

    CHECK(!tunnel.open());
    CHECK(elapsed < std::chrono::milliseconds(2000));
    CHECK(tunnel.error().find("no progress") != std::string::npos);
    CHECK(tunnel.error().find("read budget") == std::string::npos);
    // Nothing beyond the head/message ceilings was ever accumulated.
    CHECK(tunnel.bytes_read() <= 64u * 1024u + 4096u);
}

RTSC_TEST(gateway_tunnel_stops_at_the_session_read_budget) {
    // A well-formed 200 opens the tunnel; the gateway then keeps sending bytes.
    // The session byte budget is a hardening switch (default 0 = unlimited), so
    // this test asks for it explicitly and requires a distinct budget error that
    // is not the inactivity one.
    std::vector<uint8_t> script =
        Bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    script.resize(script.size() + 64 * 1024, 0x41);
    ScriptedStallTransport inner(std::move(script), 4096, 5);

    GatewayTunnel::Config config;
    config.target = "server.example:3389";
    config.gateway_host = "gateway.example:443";
    config.user_agent = "rtsc";
    config.connect_timeout_ms = 2000;
    config.max_session_read_bytes = 8 * 1024;

    GatewayTunnel tunnel(inner, config);
    CHECK(tunnel.open());

    size_t delivered = 0;
    int last = 0;
    for (int loops = 0; loops < 1024; ++loops) {
        uint8_t buf[4096];
        last = tunnel.Read(buf, sizeof(buf));
        if (last == kReadTimeout) break;
        if (last < 0) break;
        delivered += static_cast<size_t>(last);
    }
    std::printf("  read budget: delivered=%zu bytes_read=%zu reads=%zu error=%s\n",
                delivered, tunnel.bytes_read(), tunnel.read_calls(),
                tunnel.error().c_str());

    CHECK_EQ(last, -1);
    CHECK(tunnel.error().find("read budget") != std::string::npos);
    CHECK(tunnel.error().find("no progress") == std::string::npos);
    // A 4 KiB read is in flight when the budget is crossed: at most one read of
    // overshoot, and nothing proportional to what the peer offered (64 KiB).
    CHECK(delivered <= config.max_session_read_bytes + 4096);
    CHECK(tunnel.bytes_read() <= config.max_session_read_bytes + 4096);
    CHECK(tunnel.read_calls() <= 3u);
}

RTSC_TEST(gateway_limits_are_configurable_per_instance) {
    // The ceilings are parameters, not baked-in policy: the same hostile wire is
    // rejected under the defaults and accepted when the caller raises them, so a
    // deployment (or a test) can retune the envelope without patching the parser.
    std::vector<uint8_t> head = Bytes("HTTP/1.1 200 OK\r\n");
    for (size_t i = 0; i < 400; ++i) {
        const std::vector<uint8_t> line =
            Bytes("X-Pad-" + std::to_string(i) + ": " + std::string(200, 'a') +
                  "\r\n");
        head.insert(head.end(), line.begin(), line.end());
    }
    const std::vector<uint8_t> blank = Bytes("\r\n");
    head.insert(head.end(), blank.begin(), blank.end());
    CHECK(head.size() > 64u * 1024u);
    std::printf("  configurable: head=%zu bytes\n", head.size());

    HttpMessage out;
    size_t consumed = 0;
    CHECK(HttpMessage::parse(head.data(), head.size(), out, consumed) ==
          Status::InvalidLength);
    HttpLimits loose_head;
    loose_head.max_head_bytes = 128 * 1024;
    CHECK(HttpMessage::parse(head.data(), head.size(), out, consumed, loose_head) ==
          Status::Ok);
    CHECK_EQ(out.headers.size(), static_cast<size_t>(400));

    // Entity ceiling: the claim is rejected while the digits are scanned, so
    // nothing is ever sized from it. Raising the ceiling accepts the claim.
    const std::vector<uint8_t> entity =
        Bytes("HTTP/1.1 200 OK\r\nContent-Length: 200000\r\n\r\n");
    CHECK(HttpMessage::parse(entity.data(), entity.size(), out, consumed) ==
          Status::InvalidLength);
    HttpLimits loose_entity;
    loose_entity.max_entity_bytes = 256 * 1024;
    CHECK(HttpMessage::parse(entity.data(), entity.size(), out, consumed,
                             loose_entity) == Status::Ok);

    // Header count ceiling: 600 one-byte headers must be rejected on the count
    // alone even though they fit the byte ceiling.
    std::vector<uint8_t> many = Bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n");
    const std::vector<uint8_t> tiny = Bytes("a: b\r\n");
    for (size_t i = 0; i < 600; ++i) {
        many.insert(many.end(), tiny.begin(), tiny.end());
    }
    many.insert(many.end(), blank.begin(), blank.end());
    CHECK(many.size() < 64u * 1024u);
    CHECK(HttpMessage::parse(many.data(), many.size(), out, consumed) ==
          Status::InvalidLength);
    HttpLimits loose_count;
    loose_count.max_header_count = 1024;
    CHECK(HttpMessage::parse(many.data(), many.size(), out, consumed, loose_count) ==
          Status::Ok);
    CHECK_EQ(out.headers.size(), static_cast<size_t>(601));

    // The tunnel uses the same knobs: a 400-header response that fits the raised
    // head ceiling is accepted end-to-end, which proves Config is wired into the
    // parser rather than ignored.
    MockTransport inner;
    inner.to_read = head;
    GatewayTunnel::Config config;
    config.target = "server.example:3389";
    config.gateway_host = "gateway.example:443";
    config.user_agent = "rtsc";
    config.connect_timeout_ms = 1000;
    config.max_head_bytes = 128 * 1024;
    GatewayTunnel tunnel(inner, config);
    CHECK(tunnel.open());
    CHECK_EQ(tunnel.status_code(), 200);
}

RTSC_TEST(gateway_tunnel_returns_after_the_supply_stops) {
    // The incident shape, bounded: the scripted transport offers 256 slices of
    // 4 KiB (1 MiB) and then no more data at all, with the connection left open.
    // The head is well formed, so the tunnel opens and reads that data; when the
    // supply stops the inactivity deadline must end the wait instead of waiting
    // forever, and nothing may be read past what was offered.
    std::vector<uint8_t> script =
        Bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    const size_t kSlices = 256;
    const size_t kSlice = 4096;
    script.resize(script.size() + kSlices * kSlice, 0x5A);
    ScriptedStallTransport inner(std::move(script), kSlice, 5);

    GatewayTunnel::Config config;
    config.target = "server.example:3389";
    config.gateway_host = "gateway.example:443";
    config.user_agent = "rtsc";
    config.connect_timeout_ms = 5000;
    config.session_timeout_ms = 300;  // inactivity, not a lifetime cap

    GatewayTunnel tunnel(inner, config);
    CHECK(tunnel.open());

    size_t delivered = 0;
    int last = 0;
    const auto start = std::chrono::steady_clock::now();
    for (int loops = 0; loops < 4096; ++loops) {
        uint8_t buf[4096];
        last = tunnel.Read(buf, sizeof(buf));
        if (last == kReadTimeout) continue;
        if (last < 0) break;
        delivered += static_cast<size_t>(last);
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    std::printf(
        "  supply stops: delivered=%zu bytes_read=%zu reads=%zu "
        "elapsed_ms=%lld error=%s\n",
        delivered, tunnel.bytes_read(), tunnel.read_calls(),
        static_cast<long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
        tunnel.error().c_str());

    CHECK_EQ(last, -1);
    CHECK(tunnel.error().find("no progress") != std::string::npos);
    // Exactly the supply was consumed: no retry amplification, no overshoot.
    CHECK(tunnel.bytes_read() <= kSlices * kSlice + 64);
    CHECK(inner.served() <= kSlices * kSlice + 64);
    CHECK(elapsed < std::chrono::milliseconds(3000));
}

RTSC_TEST(gateway_data_path_idle_is_not_a_peer_close) {
    // The no-progress deadline is opt-in. With the default (0) the tunnel must
    // keep returning kReadTimeout indefinitely after the supply stops: a real
    // RDP-over-gateway session can be idle for minutes, and treating that as a
    // peer close used to strand the session (Client::Pump read -1 "no
    // progress" and gave up on a healthy tunnel). An explicit deadline on the
    // same supply is exercised by gateway_tunnel_returns_after_the_supply_stops
    // (300 ms) and gateway_tunnel_gives_up_when... (300 ms), so this test only
    // proves the default itself does not cut the data path.
    std::vector<uint8_t> script =
        Bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    script.resize(script.size() + 8 * 1024, 0x5A);
    ScriptedStallTransport inner(std::move(script), 4096, 5);

    GatewayTunnel::Config config;
    config.target = "server.example:3389";
    config.gateway_host = "gateway.example:443";
    config.user_agent = "rtsc";
    config.connect_timeout_ms = 2000;

    GatewayTunnel tunnel(inner, config);
    CHECK(tunnel.open());
    CHECK_EQ(tunnel.error().find("no progress"), std::string::npos);

    // Drain the offered data; afterwards the inner transport stalls forever.
    uint8_t buf[4096];
    for (;;) {
        const int n = tunnel.Read(buf, sizeof(buf));
        if (n == kReadTimeout) break;
        CHECK(n > 0);
    }

    // Idle for well past a handshake-length deadline: with the default the
    // tunnel must stay silent, and reads must keep returning kReadTimeout
    // rather than a -1 "no progress" error.
    int idle_reads = 0;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(350);
    while (std::chrono::steady_clock::now() < deadline) {
        const int n = tunnel.Read(buf, sizeof(buf));
        if (n != kReadTimeout) break;  // any real result fails below
        ++idle_reads;
    }
    std::printf("  data-path idle: reads=%d error=%s\n", idle_reads,
                tunnel.error().c_str());
    CHECK(idle_reads > 0);
    // The default deadline never fired: no error at all, and in particular not
    // the inactivity one.
    CHECK(tunnel.error().find("no progress") == std::string::npos);
    CHECK(tunnel.error().empty());
}

int main() { return ::rtsc::test::run_all("rtsc_gateway_tests"); }
