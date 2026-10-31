// RD Gateway ([MS-TSGU]) and RDP-UDP ([MS-RDPEUDP]) tests.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/client/client.h"
#include "rtsc/credssp/ntlm.h"
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

// A scripted TLS backend for TlsByteTransport. `send_cap` limits how much of a
// Send call is consumed (mirroring OpenSSL's WANT_READ partial write);
// `read_extra` makes the first Receive over-produce beyond max_out, which the
// TLS contract explicitly allows.
class ScriptedTls : public rtsc::tls::TlsTransport {
 public:
    ScriptedTls(size_t send_cap, size_t read_extra)
        : send_cap_(send_cap), read_extra_(read_extra) {}

    int send_calls = 0;
    size_t consumed_total = 0;

    rtsc::tls::Error Handshake(const uint8_t*, size_t in_size, size_t& consumed,
                               std::vector<uint8_t>& out) override {
        consumed = in_size;
        out.clear();
        handshaken_ = true;
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error Send(const uint8_t*, size_t size, size_t& consumed,
                          std::vector<uint8_t>& out) override {
        ++send_calls;
        consumed = (send_cap_ == 0 || size <= send_cap_) ? size : send_cap_;
        consumed_total += consumed;
        out.assign(consumed, 0x5A);
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error Receive(const uint8_t*, size_t,
                             std::vector<uint8_t>& plaintext,
                             size_t max_out) override {
        if (served_) {
            plaintext.clear();
            return rtsc::tls::Error{};
        }
        served_ = true;
        plaintext.assign((max_out == 0 ? 100u : max_out + read_extra_), 0x41);
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error LocalCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error LocalSubjectPublicKey(std::vector<uint8_t>& out) const override {
        out.clear();
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error PeerSubjectPublicKeyInfo(
        std::vector<uint8_t>& out) const override {
        out.clear();
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {
        out.clear();
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error PeerCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        return rtsc::tls::Error{};
    }
    rtsc::tls::Error negotiated(rtsc::tls::NegotiatedInfo& out) const override {
        out = rtsc::tls::NegotiatedInfo{};
        return rtsc::tls::Error{};
    }
    rtsc::tls::RecordSizes record_sizes() const override {
        return rtsc::tls::RecordSizes{};
    }
    rtsc::tls::Error Shutdown(std::vector<uint8_t>& out) override {
        out.clear();
        return rtsc::tls::Error{};
    }
    bool handshake_complete() const noexcept override { return handshaken_; }
    bool closed() const noexcept override { return false; }
    size_t buffered_input() const noexcept override { return 0; }
    const rtsc::tls::Error& last_error() const noexcept override { return ok_; }
    const char* backend_name() const noexcept override { return "scripted"; }

 private:
    size_t send_cap_ = 0;
    size_t read_extra_ = 0;
    bool served_ = false;
    bool handshaken_ = false;
    rtsc::tls::Error ok_{};
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

// ---------------------------------------------------------------------------
// Scripted transports and a real-loopback StubGateway for RdgspTransport.
// ---------------------------------------------------------------------------

// A scripted byte transport for the RDGSP seam: serves one canned response per
// request, records each request's bytes. Read returns kReadTimeout once the
// response queue is empty (a silent-but-alive peer, like a real socket).
class ScriptedRdgsp : public Transport {
 public:
    void Reply(const std::string& head_and_body) {
        replies_.push_back(ToVec(head_and_body));
    }
    void Reply(const std::vector<uint8_t>& bytes) {
        replies_.push_back(bytes);
    }
    void CloseOnNextRead() { close_on_read_ = true; }

    int Read(uint8_t* buf, size_t size) override {
        // Close only after every queued reply has been served (a controlled
        // EOF mid-body for the truncation tests).
        if (replies_.empty()) return close_on_read_ ? 0 : kReadTimeout;
        const size_t n = (std::min)(size, replies_.front().size());
        std::memcpy(buf, replies_.front().data(), n);
        replies_.front().erase(
            replies_.front().begin(),
            replies_.front().begin() + static_cast<std::ptrdiff_t>(n));
        if (replies_.front().empty()) replies_.pop_front();
        return static_cast<int>(n);
    }
    bool Write(const uint8_t* data, size_t size) override {
        requests_.push_back(std::vector<uint8_t>(data, data + size));
        return true;
    }
    void Close() override { closed_ = true; }
    bool closed() const { return closed_; }
    const std::vector<std::vector<uint8_t>>& requests() const {
        return requests_;
    }

 private:
    std::deque<std::vector<uint8_t>> replies_;
    std::vector<std::vector<uint8_t>> requests_;
    bool close_on_read_ = false;
    bool closed_ = false;
};

std::string RequestText(const std::vector<uint8_t>& req) {
    return std::string(req.begin(), req.end());
}

// The RFC 6455 4.1 sample key/accept pair. Locked by the accept test and used
// to build valid stub 101 responses with a deterministic Sec-WebSocket-Accept.
const char* const kWebSocketSampleKey = "dGhlIHNhbXBsZSBub25jZQ==";
const char* const kWebSocketSampleAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

// Extracts the base64 "Sec-WebSocket-Key" value from a recorded request head.
bool WebSocketKeyFromRequest(const std::vector<uint8_t>& req, std::string& key) {
    const std::string text = RequestText(req);
    const std::string marker = "Sec-WebSocket-Key: ";
    const size_t at = text.find(marker);
    if (at == std::string::npos) return false;
    const size_t nl = text.find("\r\n", at);
    if (nl == std::string::npos) return false;
    key = text.substr(at + marker.size(), nl - (at + marker.size()));
    return !key.empty();
}

std::string StubNtlmType2Base64() {
    rtsc::credssp::ChallengeMessage chg;
    chg.flags = 0xE28A8235u;
    for (int i = 0; i < 8; ++i) {
        chg.server_challenge[static_cast<size_t>(i)] =
            static_cast<uint8_t>(0x10 + i);
    }
    chg.target_name = "GW";
    rtsc::credssp::AvPair ts;
    ts.id = rtsc::credssp::AvId::kTimestamp;
    ts.value = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    chg.av_pairs = {ts};
    std::vector<uint8_t> raw;
    const rtsc::credssp::Error e = chg.Encode(raw);
    CHECK(e.ok());
    return rtsc::proto::EncodeBase64(std::string(raw.begin(), raw.end()));
}

// Extracts the base64 token after "Authorization: NTLM " from a request.
bool NtlmTokenFromRequest(const std::vector<uint8_t>& req, std::string& token) {
    const std::string text = RequestText(req);
    const std::string marker = "Authorization: NTLM ";
    const size_t at = text.find(marker);
    if (at == std::string::npos) return false;
    const size_t nl = text.find("\r\n", at);
    token = text.substr(at + marker.size(), nl - (at + marker.size()));
    return !token.empty();
}

// Decodes the base64 NTLM AUTHENTICATE token in a request; returns true and
// fills `auth` on success. Used to verify the client's type-3 is structurally
// a valid NTLM exchange continuation.
bool DecodeNtlmType3FromRequest(const std::vector<uint8_t>& req,
                                rtsc::credssp::AuthenticateMessage& auth) {
    std::string token;
    if (!NtlmTokenFromRequest(req, token)) return false;
    std::vector<uint8_t> raw;
    // Local strict base64 decode for test-side verification.
    auto nibble = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
        if (c >= '0' && c <= '9') return 52 + (c - '0');
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    uint32_t acc = 0;
    int bits = 0;
    for (const char c : token) {
        if (c == '=') break;
        const int v = nibble(c);
        if (v < 0) return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            raw.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return auth.Decode(raw.data(), raw.size()).ok();
}

// A real-loopback RDGSP stub: listens on 127.0.0.1:0, accepts TWO connections
// (OUT first, then IN -- the client connects them in that order), and serves a
// per-scenario handshake over cleartext http (the factory's +0x6a8==0 mode).
// After a 200 the OUT handler echoes the client's IN-channel chunked body back
// to the client as chunked OUT-body bytes, so byte round-trips are real.
class StubGateway {
 public:
    enum class Scenario {
        k200Chunked,  // OUT 200 TE:chunked; echo IN body back chunked
        k200Plain,    // OUT 200 without TE; echo IN body back plain
        kNtlm200,     // OUT: 401 NTLM -> 401+type2 -> 200
        k401Always,   // OUT: always 401 NTLM
        kStatus403,
        kStatus407,
        kStatus502,
        kStatus504,
        kStatus307,
        kIn101,  // OUT 200; IN answers 101 -> client must hard-fail
    };

    explicit StubGateway(Scenario s) : scenario_(s) {}

    bool Start(std::string& error) {
        listener_ = rtsc::net::ListenTcp("127.0.0.1", 0, error);
        if (!listener_) return false;
        port_ = listener_->local_port();
        worker_ = std::thread([this] { Run(); });
        return true;
    }

    uint16_t bound_port() const { return port_; }

    void Stop() {
        if (listener_) listener_->Close();
        {
            std::lock_guard<std::mutex> lock(mux_);
            closed_ = true;
        }
        cv_.notify_all();
        if (out_) out_->Close();
        if (in_) in_->Close();
        if (worker_.joinable()) worker_.join();
    }

    size_t out_requests() const {
        std::lock_guard<std::mutex> lock(mux_);
        return out_requests_;
    }
    size_t in_requests() const {
        std::lock_guard<std::mutex> lock(mux_);
        return in_requests_;
    }
    bool type3_verified() const { return type3_verified_; }

 private:
    // Reads request bytes until the head's terminating blank line.
    static std::vector<uint8_t> ReadHead(Transport& t, int timeout_ms = 4000) {
        std::vector<uint8_t> head;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (EndsWithBlankLine(head)) return head;
            uint8_t chunk[4096];
            const int n = t.Read(chunk, sizeof(chunk));
            if (n == kReadTimeout) continue;
            if (n <= 0) return head;
            head.insert(head.end(), chunk, chunk + n);
        }
        return head;
    }

    static bool EndsWithBlankLine(const std::vector<uint8_t>& buf) {
        if (buf.size() < 4) return false;
        return buf[buf.size() - 4] == '\r' && buf[buf.size() - 3] == '\n' &&
               buf[buf.size() - 2] == '\r' && buf[buf.size() - 1] == '\n';
    }

    static size_t FindBlank(const std::vector<uint8_t>& buf) {
        for (size_t i = 0; i + 3 < buf.size(); ++i) {
            if (buf[i] == '\r' && buf[i + 1] == '\n' &&
                buf[i + 2] == '\r' && buf[i + 3] == '\n') {
                return i;
            }
        }
        return std::string::npos;
    }

    static bool WriteText(Transport& t, const std::string& s) {
        return t.Write(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    static bool WriteBytes(Transport& t, const std::vector<uint8_t>& b) {
        return t.Write(b.data(), b.size());
    }

    void Run() {
        out_ = listener_->Accept();
        in_ = listener_->Accept();
        if (!out_ || !in_) return;
        std::thread tout([this] { HandleOut(*out_); });
        std::thread tin([this] { HandleIn(*in_); });
        tout.join();
        tin.join();
    }

    void HandleOut(Transport& out) {
        bool echo_mode = false;
        int ntlm_round = 0;
        for (int round = 0; round < 8; ++round) {
            const std::vector<uint8_t> head = ReadHead(out);
            if (!EndsWithBlankLine(head)) break;  // peer closed mid-request
            {
                std::lock_guard<std::mutex> lock(mux_);
                ++out_requests_;
            }
            if (scenario_ == Scenario::k401Always) {
                if (!WriteText(out, "HTTP/1.1 401 Unauthorized\r\n"
                                   "WWW-Authenticate: NTLM\r\n"
                                   "Content-Length: 0\r\n\r\n")) {
                    return;
                }
                continue;
            }
            if (scenario_ == Scenario::kNtlm200) {
                if (ntlm_round == 0) {
                    // First request: no credentials yet.
                    ++ntlm_round;
                    if (!WriteText(out, "HTTP/1.1 401 Unauthorized\r\n"
                                       "WWW-Authenticate: NTLM\r\n"
                                       "Content-Length: 0\r\n\r\n")) {
                        return;
                    }
                    continue;
                }
                if (ntlm_round == 1) {
                    // Second request carries the type-1; challenge with type-2.
                    ++ntlm_round;
                    if (!WriteText(out, "HTTP/1.1 401 Unauthorized\r\n"
                                       "WWW-Authenticate: NTLM " +
                                           StubNtlmType2Base64() + "\r\n"
                                       "Content-Length: 0\r\n\r\n")) {
                        return;
                    }
                    continue;
                }
                // Third request carries the type-3: verify it decodes, then accept with
                // the same 200+chunked response the plain scenarios use.
                rtsc::credssp::AuthenticateMessage auth;
                if (DecodeNtlmType3FromRequest(head, auth) &&
                    !auth.nt_response.empty()) {
                    type3_verified_ = true;
                }
                if (!WriteText(out, "HTTP/1.1 200 OK\r\n"
                                   "Transfer-Encoding: chunked\r\n"
                                   "Content-Type: application/octet-stream\r\n"
                                   "RDG-Connection-Id: {stub}\r\n\r\n")) {
                    return;
                }
                echo_mode = true;
                break;
            }
            if (scenario_ == Scenario::kStatus403) {
                WriteText(out, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
                return;
            }
            if (scenario_ == Scenario::kStatus407) {
                WriteText(out, "HTTP/1.1 407 Proxy Authentication Required\r\n"
                               "Content-Length: 0\r\n\r\n");
                return;
            }
            if (scenario_ == Scenario::kStatus502) {
                WriteText(out, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                return;
            }
            if (scenario_ == Scenario::kStatus504) {
                WriteText(out, "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n");
                return;
            }
            if (scenario_ == Scenario::kStatus307) {
                WriteText(out, "HTTP/1.1 307 Temporary Redirect\r\n"
                               "Location: http://elsewhere/\r\n"
                               "Content-Length: 0\r\n\r\n");
                return;
            }
            // 200 scenarios.
            if (scenario_ == Scenario::k200Chunked || scenario_ == Scenario::kIn101) {
                if (!WriteText(out, "HTTP/1.1 200 OK\r\n"
                                   "Transfer-Encoding: chunked\r\n"
                                   "Content-Type: application/octet-stream\r\n"
                                   "RDG-Connection-Id: {stub}\r\n\r\n")) {
                    return;
                }
            } else if (scenario_ == Scenario::k200Plain) {
                if (!WriteText(out, "HTTP/1.1 200 OK\r\n"
                                   "Content-Type: application/octet-stream\r\n"
                                   "RDG-Connection-Id: {stub}\r\n\r\n")) {
                    return;
                }
            }
            echo_mode = true;
            break;
        }
        if (!echo_mode) return;
        // Echo pump: wait for IN-decoded payloads, re-encode them downstream.
        std::vector<uint8_t> payload;
        const bool chunked =
            scenario_ == Scenario::k200Chunked ||
            (scenario_ == Scenario::kNtlm200);
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(mux_);
                if (closed_) return;
                if (echo_.empty()) {
                    cv_.wait_for(lock, std::chrono::milliseconds(100));
                    continue;
                }
                payload = std::move(echo_.front());
                echo_.pop_front();
            }
            if (payload.empty()) continue;
            if (chunked) {
                const std::vector<uint8_t> frame = rtsc::proto::ChunkedEncodeChunk(
                    payload.data(), payload.size());
                if (!WriteBytes(out, frame)) return;
            } else if (!WriteBytes(out, payload)) {
                return;
            }
        }
    }

    void HandleIn(Transport& in) {
        // Parse the first chunked frame(s) out of the stream; a real client
        // streams indefinitely, so keep draining until the socket closes.
        std::vector<uint8_t> head = ReadHead(in);
        if (scenario_ == Scenario::kIn101) {
            WriteText(in, "HTTP/1.1 101 Switching Protocols\r\n"
                          "Upgrade: websocket\r\n"
                          "Connection: Upgrade\r\n\r\n");
            return;
        }
        WriteText(in, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        {
            std::lock_guard<std::mutex> lock(mux_);
            ++in_requests_;
        }
        // Read the rest as repeated "<hex>\r\n<data>\r\n" chunks; relay each
        // decoded payload to the OUT echo queue. Everything before the head's
        // terminating blank line is the request head, not chunk data.
        std::vector<uint8_t> buf;
        const size_t blank = FindBlank(head);
        if (blank != std::string::npos) {
            buf.assign(head.begin() + static_cast<ptrdiff_t>(blank) + 4,
                       head.end());
        } else {
            buf = head;  // degenerate: no blank line observed; treat as data
        }
        for (;;) {
            // Try to extract one complete chunk from the front.
            size_t hex_end = 0;
            while (hex_end + 1 < buf.size() &&
                   !(buf[hex_end] == '\r' && buf[hex_end + 1] == '\n')) {
                ++hex_end;
            }
            if (hex_end + 1 >= buf.size()) {
                // Need more bytes.
                uint8_t chunk[4096];
                const int n = in.Read(chunk, sizeof(chunk));
                if (n == kReadTimeout) {
                    if (closed_) return;
                    continue;
                }
                if (n <= 0) return;
                buf.insert(buf.end(), chunk, chunk + n);
                continue;
            }
            const std::string hex(buf.begin(),
                                  buf.begin() + static_cast<ptrdiff_t>(hex_end));
            const size_t data_off = hex_end + 2;
            char* endp = nullptr;
            const unsigned long len = std::strtoul(hex.c_str(), &endp, 16);
            if (endp != hex.c_str() + hex.size()) {
                buf.erase(buf.begin(), buf.begin() + data_off);
                continue;  // junk: skip to the next line as best effort
            }
            if (len == 0) {
                // Terminal 0-chunk.
                return;
            }
            if (buf.size() < data_off + len + 2) {
                uint8_t chunk[4096];
                const int n = in.Read(chunk, sizeof(chunk));
                if (n == kReadTimeout) {
                    if (closed_) return;
                    continue;
                }
                if (n <= 0) return;
                buf.insert(buf.end(), chunk, chunk + n);
                continue;
            }
            std::vector<uint8_t> payload(buf.begin() +
                                             static_cast<ptrdiff_t>(data_off),
                                         buf.begin() +
                                             static_cast<ptrdiff_t>(data_off + len));
            {
                std::unique_lock<std::mutex> qlock(mux_);
                echo_.push_back(std::move(payload));
            }
            cv_.notify_all();
            // Consume "<hex>\r\n<data>\r\n".
            buf.erase(buf.begin(),
                      buf.begin() + static_cast<ptrdiff_t>(data_off + len + 2));
        }
    }

    Scenario scenario_;
    std::unique_ptr<rtsc::net::Listener> listener_;
    uint16_t port_ = 0;
    std::thread worker_;
    std::shared_ptr<rtsc::net::Transport> out_;
    std::shared_ptr<rtsc::net::Transport> in_;

    mutable std::mutex mux_;
    std::condition_variable cv_;
    std::deque<std::vector<uint8_t>> echo_;
    bool closed_ = false;
    size_t out_requests_ = 0;
    size_t in_requests_ = 0;
    std::atomic<bool> type3_verified_{false};
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
        {out, [](RdgChannelRequestOptions& o, const std::string& v) { o.websocket_key = v; }},
    };
    for (const Case& c : cases) {
        c.set(c.o, injected);
        const std::vector<uint8_t> req = BuildRdgChannelRequest(c.o);
        CHECK(req.empty());  // caller-visible failure
    }
}

RTSC_TEST(build_websocket_accept_matches_rfc6455_sample) {
    // RFC 6455 4.1 pins exactly one key/accept pair. ComputeWebSocketAccept
    // must reproduce it byte-for-byte: the 101 check compares this value
    // case-sensitively (base64 is significant), so a wrong byte here fails the
    // handshake.
    CHECK(ComputeWebSocketAccept(kWebSocketSampleKey) ==
          std::string(kWebSocketSampleAccept));
}

RTSC_TEST(rdg_channel_upgrade_uses_injected_key_and_reports_it) {
    // A caller may pin its own Sec-WebSocket-Key; the builder must emit that
    // exact value AND report it back so the caller can compute the expected
    // Sec-WebSocket-Accept without guessing.
    RdgChannelRequestOptions options;
    options.method = kRdgOutData;
    options.direction = RdgChannelDirection::kOut;
    options.gateway_host = "gw.example:443";
    options.connection_id = "{conn}";
    options.user_agent = "rtsc";
    options.request_websocket_upgrade = true;
    options.websocket_key = kWebSocketSampleKey;
    std::string used;
    const std::vector<uint8_t> request = BuildRdgChannelRequest(options, &used);
    const std::string text(request.begin(), request.end());
    CHECK(text.find("Sec-WebSocket-Key: " + std::string(kWebSocketSampleKey) +
                         "\r\n") != std::string::npos);
    CHECK(used == kWebSocketSampleKey);
    // An upgraded OUT request carries exactly ONE Connection header
    // ("Upgrade"), never the old "Keep-Alive" default alongside it.
    const size_t first = text.find("Connection: ");
    CHECK(first != std::string::npos);
    CHECK(text.find("Connection: ", first + 1) == std::string::npos);
    CHECK(text.find("Connection: Upgrade\r\n") != std::string::npos);
    CHECK(text.find("Sec-WebSocket-Version: 13\r\n") != std::string::npos);
}

RTSC_TEST(rdg_channel_upgrade_generates_24char_key_when_not_injected) {
    // Empty websocket_key => the builder generates one: the RFC 6455 nonce is
    // 16 random bytes, so the base64 form is exactly 24 chars.
    RdgChannelRequestOptions options;
    options.method = kRdgOutData;
    options.direction = RdgChannelDirection::kOut;
    options.gateway_host = "gw.example:443";
    options.connection_id = "{conn}";
    options.user_agent = "rtsc";
    options.request_websocket_upgrade = true;
    std::string used;
    const std::vector<uint8_t> request = BuildRdgChannelRequest(options, &used);
    const std::string text(request.begin(), request.end());
    CHECK_EQ(used.size(), static_cast<size_t>(24));
    if (used.size() == 24) {
        const auto is_b64 = [](char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                   (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
        };
        for (const char c : used) CHECK(is_b64(c));
        std::string key;
        CHECK(WebSocketKeyFromRequest(request, key));
        CHECK(key == used);
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

RTSC_TEST(chunked_encode_chunk_omits_the_terminator) {
    // The IN channel writes a persistent stream of chunks for the whole
    // session; the 0-chunk would close the body, so per-write chunk framing
    // omits it.
    const std::string data = "hello";
    const std::vector<uint8_t> chunk =
        ChunkedEncodeChunk(reinterpret_cast<const uint8_t*>(data.data()),
                           data.size());
    CHECK(chunk == ToVec("5\r\nhello\r\n"));
    CHECK(ChunkedEncodeChunk(nullptr, 0).empty());
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

// ---------------------------------------------------------------------------
// RFC 6455 client frame codec (external wire bytes -> fields; never an
// encode->decode self-round trip, which the project has recorded as a defect
// pattern). Layout per [RFC 6455] section 5.2/5.3 (FIN / opcode / minimal
// extended length / mask key / mask).
// ---------------------------------------------------------------------------

RTSC_TEST(websocket_encode_is_byte_exact_for_masked_hello) {
    // The RFC 6455 "Hello" example: text frame (0x1), FIN set, mask bit set,
    // 5-byte payload, mask key 37 fa 21 3d.
    const std::vector<uint8_t> encoded =
        WebSocketEncodeClientFrame(WebSocketOpcode::kText,
                                   reinterpret_cast<const uint8_t*>("Hello"), 5,
                                   0x37FA213Du);
    CHECK(encoded == (std::vector<uint8_t>{0x81, 0x85, 0x37, 0xfa, 0x21,
                                           0x3d, 0x7f, 0x9f, 0x4d, 0x51,
                                           0x58}));
}

RTSC_TEST(websocket_encode_uses_minimal_126_length_form) {
    // 200-byte binary payload: 126 extended (2-byte big-endian) length form.
    std::vector<uint8_t> payload(200, 0xAB);
    const std::vector<uint8_t> encoded =
        WebSocketEncodeClientFrame(WebSocketOpcode::kBinary, payload.data(),
                                   payload.size(), 0x01020304u);
    CHECK_EQ(encoded.size(), static_cast<size_t>(2 + 2 + 4 + 200));
    CHECK(encoded[0] == 0x82);
    CHECK(encoded[1] == 0xFE);  // FIN+mask, 126 form
    CHECK(encoded[2] == 0x00);
    CHECK(encoded[3] == 0xC8);  // 200 big-endian
    // The RFC 6455 mask: payload[i] XOR key[i % 4]. 2 header + 2 length
    // + 4 key bytes precede the payload.
    const uint8_t key[4] = {0x01, 0x02, 0x03, 0x04};
    for (size_t i = 0; i < payload.size(); ++i) {
        CHECK(encoded[8 + i] ==
              static_cast<uint8_t>(payload[i] ^ key[i % 4]));
    }
}

RTSC_TEST(websocket_encode_uses_minimal_127_length_form) {
    // 70000-byte payload crosses 0xFFFF: 127 extended (8-byte big-endian).
    const size_t n = 70000;
    std::vector<uint8_t> payload(n, 0x01);
    const std::vector<uint8_t> encoded =
        WebSocketEncodeClientFrame(WebSocketOpcode::kBinary, payload.data(), n,
                                   0u);
    CHECK_EQ(encoded.size(), static_cast<size_t>(2 + 8 + 4 + n));
    CHECK(encoded[0] == 0x82);
    CHECK(encoded[1] == 0xFF);  // 127 form
    CHECK(encoded[2] == 0x00);
    CHECK(encoded[3] == 0x00);
    CHECK(encoded[4] == 0x00);
    CHECK(encoded[5] == 0x00);
    CHECK(encoded[6] == 0x00);
    CHECK(encoded[7] == 0x01);
    CHECK(encoded[8] == 0x11);
    CHECK(encoded[9] == 0x70);  // 70000 = 0x11170 big-endian
}

RTSC_TEST(websocket_decode_masked_hello_from_wire) {
    // The RFC 6455 masked "Hello" example, decoded as opaque wire bytes.
    // (Byte list form: adjacent "\xNN\xNN" hex escapes would merge in C++.)
    WebSocketFrameDecoder decoder;
    const std::vector<WebSocketFrame> frames =
        decoder.Feed(std::vector<uint8_t>{
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58});
    CHECK(!decoder.failed());
    CHECK_EQ(frames.size(), static_cast<size_t>(1));
    CHECK(frames[0].fin);
    CHECK(frames[0].opcode == WebSocketOpcode::kText);
    CHECK(frames[0].payload == ToVec("Hello"));
    CHECK_EQ(decoder.frames_parsed(), static_cast<size_t>(1));
}

RTSC_TEST(websocket_decode_unmasked_binary_frame) {
    // A server->client binary frame is NOT masked: opcode 2, 3 payload bytes.
    WebSocketFrameDecoder decoder;
    const std::vector<WebSocketFrame> frames =
        decoder.Feed(std::vector<uint8_t>{0x82, 0x03, 0x01, 0x02, 0x03});
    CHECK(!decoder.failed());
    CHECK_EQ(frames.size(), static_cast<size_t>(1));
    CHECK(frames[0].opcode == WebSocketOpcode::kBinary);
    const std::vector<uint8_t> want = {0x01, 0x02, 0x03};
    CHECK(frames[0].payload == want);
}

RTSC_TEST(websocket_decode_126_length_frame_across_fragments) {
    // 200-byte unmasked frame fed one byte at a time (incremental). Only the
    // very last byte can complete the frame; every earlier feed is partial.
    WebSocketFrameDecoder decoder;
    std::vector<uint8_t> payload(200, 0x11);
    std::vector<uint8_t> wire = {0x82, 0x7E, 0x00, 0xC8};
    wire.insert(wire.end(), payload.begin(), payload.end());
    bool completed = false;
    for (size_t i = 0; i < wire.size(); ++i) {
        const std::vector<WebSocketFrame> frames =
            decoder.Feed(&wire[i], 1);
        CHECK(!decoder.failed());
        if (i + 1 != wire.size()) {
            CHECK(frames.empty());  // still partial
        } else if (!frames.empty()) {
            completed = true;
        }
    }
    CHECK(completed);
    CHECK_EQ(decoder.frames_parsed(), static_cast<size_t>(1));
}

RTSC_TEST(websocket_decode_rejects_oversized_64bit_length) {
    // 127 form announcing 2^56 payload bytes (well above the 16 MiB cap) must
    // be rejected from the header alone, before any body could be buffered.
    WebSocketFrameDecoder decoder;
    decoder.Feed(std::vector<uint8_t>{0x82, 0x7F, 0x01, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00});
    CHECK(decoder.failed());
    CHECK(decoder.error() == WebSocketError::kPayloadTooLarge);
}

RTSC_TEST(websocket_decode_rejects_non_minimal_length_encoding) {
    // A 2-byte payload carried in the 127 form (fits in the 7-bit form) is a
    // non-minimal length encoding; a 200-byte payload in the 127 form (fits in
    // 126 form) is too. Both are rejected.
    WebSocketFrameDecoder first;
    first.Feed(std::vector<uint8_t>{0x82, 0x7F, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x02});
    CHECK(first.error() == WebSocketError::kNonMinimalLength);

    WebSocketFrameDecoder second;
    second.Feed(std::vector<uint8_t>{0x82, 0x7E, 0x00, 0x01});
    CHECK(second.error() == WebSocketError::kNonMinimalLength);
}

RTSC_TEST(websocket_decode_rejects_non_minimal_126_form) {
    WebSocketFrameDecoder decoder;
    decoder.Feed(std::vector<uint8_t>{0x82, 0x7E, 0x00, 0x01, 0xAB});
    CHECK(decoder.error() == WebSocketError::kNonMinimalLength);
    CHECK(decoder.failed());
}

RTSC_TEST(websocket_decode_rejects_invalid_opcode) {
    // 0x3 is not in the whitelist {0,1,2,8,9,10}; 0xB is a reserved control
    // ranking that is also not offered.
    WebSocketFrameDecoder bad;
    bad.Feed(std::vector<uint8_t>{0x83, 0x00});
    CHECK(bad.error() == WebSocketError::kInvalidOpcode);

    WebSocketFrameDecoder reserved;
    reserved.Feed(std::vector<uint8_t>{0x8B, 0x00});
    CHECK(reserved.error() == WebSocketError::kInvalidOpcode);
}

RTSC_TEST(websocket_decode_rejects_reserved_bits) {
    // RSV1 set (0x40) but no extension was negotiated.
    WebSocketFrameDecoder decoder;
    decoder.Feed(std::vector<uint8_t>{0xC1, 0x00});
    CHECK(decoder.error() == WebSocketError::kReservedBits);
}

RTSC_TEST(websocket_decode_rejects_control_frame_without_fin) {
    // Ping (opcode 9) with FIN==0 is illegal: control frames MUST be FIN.
    WebSocketFrameDecoder decoder;
    decoder.Feed(std::vector<uint8_t>{0x09, 0x00});
    CHECK(decoder.error() == WebSocketError::kControlFrameNotFinal);
}

RTSC_TEST(websocket_decode_rejects_oversized_control_frame) {
    // A close frame (opcode 8) announcing 126 payload bytes: control frames
    // MUST carry at most 125.
    WebSocketFrameDecoder decoder;
    decoder.Feed(std::vector<uint8_t>{0x88, 0x7E, 0x00, 0x7E});
    CHECK(decoder.error() == WebSocketError::kControlFrameTooLarge);

    // A ping with an extended 126 length but only the first two header bytes
    // so far: the parse must wait for the extended length (still benign).
    WebSocketFrameDecoder ping;
    ping.Feed(std::vector<uint8_t>{0x89, 0x7E});
    CHECK(!ping.failed());
    CHECK(ping.error() == WebSocketError::kNone);
}

RTSC_TEST(websocket_decode_control_frame_ping_payload) {
    // A valid ping with a 2-byte payload.
    WebSocketFrameDecoder decoder;
    const std::vector<WebSocketFrame> frames =
        decoder.Feed(std::vector<uint8_t>{0x89, 0x02, 0xAB, 0xCD});
    CHECK(!decoder.failed());
    CHECK_EQ(frames.size(), static_cast<size_t>(1));
    CHECK(frames[0].opcode == WebSocketOpcode::kPing);
    const std::vector<uint8_t> want = {0xAB, 0xCD};
    CHECK(frames[0].payload == want);
}

RTSC_TEST(websocket_decode_truncation_latches_on_stream_end) {
    WebSocketFrameDecoder decoder;
    decoder.Feed(std::vector<uint8_t>{0x82, 0x05, 0x01, 0x02});  // 5 declared, 2 given
    CHECK(!decoder.failed());
    decoder.EndOfStream();
    CHECK(decoder.failed());
    CHECK(decoder.error() == WebSocketError::kTruncated);
}

RTSC_TEST(websocket_decode_racked_masked_frames) {
    // Two masked frames back to back in one feed parse as two frames.
    WebSocketFrameDecoder decoder;
    const std::vector<WebSocketFrame> frames = decoder.Feed(
        std::vector<uint8_t>{0x81, 0x81, 0x00, 0x00, 0x00, 0x00, 0x41,  // 'A'
                             0x82, 0x81, 0x00, 0x00, 0x00, 0x00, 0x42});  // 'B'
    CHECK(!decoder.failed());
    CHECK_EQ(frames.size(), static_cast<size_t>(2));
    CHECK(frames[0].opcode == WebSocketOpcode::kText);
    CHECK(frames[0].payload == ToVec("A"));
    CHECK(frames[1].opcode == WebSocketOpcode::kBinary);
    CHECK(frames[1].payload == ToVec("B"));
}

RTSC_TEST(gateway_tunnel_rejects_injected_request_with_clear_error) {
    // D-A1/D-A4: a builder rejection (CRLF/NUL in a header value) must fail the
    // handshake with a *distinguishable* error (contains "CRLF"/"reject"), never
    // a silent empty Write() that burns the connection budget and ends with an
    // unhelpful "timed out".
    MockTransport inner;
    inner.to_read = HttpResponse(200, "OK");  // never sent: the request is rejected
    GatewayTunnel::Config config;
    config.target = "server\r\nX-Injected: 1";
    config.gateway_host = "gateway.example:443";
    config.user_agent = "rtsc";
    GatewayTunnel tunnel(inner, config);

    CHECK(!tunnel.open());
    CHECK(tunnel.error().find("CRLF") != std::string::npos ||
          tunnel.error().find("reject") != std::string::npos);
    CHECK(tunnel.error().find("timed out") == std::string::npos);
    CHECK(tunnel.error().find("too many reads") == std::string::npos);
    CHECK(inner.written.empty());  // noting reached the wire
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

    // The server thread publishes the outcome; a plain bool here would be a
    // data race (and the ACK is sent on enqueue, so client.Write can return
    // before the server thread has even returned from Read).
    std::atomic<bool> server_read_ok{false};
    std::vector<uint8_t> received;
    std::thread server_thread([&] {
        // Loop until the datagram arrives: Read() reports a bounded timeout
        // (kReadTimeout) while the peer is silent, which is not a disconnect.
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!server_read_ok.load() &&
               std::chrono::steady_clock::now() < deadline) {
            uint8_t buf[64];
            const int n = server.Read(buf, sizeof(buf));
            if (n > 0) {
                received.assign(buf, buf + n);
                server_read_ok.store(true);
            }
        }
        const uint8_t reply[] = {0x10, 0x20, 0x30};
        server.Write(reply, sizeof(reply));
    });

    const uint8_t data[] = {0xCA, 0xFE};
    CHECK(client.Write(data, sizeof(data)));
    CHECK_EQ(client.send_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.retry_count(), static_cast<unsigned>(0));
    // client.Write only proves the ACK arrived; the server thread may still be
    // between "ACK sent" and "Read returned", so wait for its publication.
    {
        const auto wait_until =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!server_read_ok.load() &&
               std::chrono::steady_clock::now() < wait_until) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(server_read_ok.load());
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

    std::atomic<bool> server_read_ok{false};
    std::thread server_thread([&] {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!server_read_ok.load() &&
               std::chrono::steady_clock::now() < deadline) {
            uint8_t buf[64];
            const int n = server.Read(buf, sizeof(buf));
            if (n > 0) server_read_ok.store(true);
        }
    });

    // Drop the client's first data frame so the transport must retransmit.
    client_sock->DropNext(1);
    const uint8_t data[] = {0x55};
    CHECK(client.Write(data, sizeof(data)));
    CHECK(client.retry_count() >= 1u);
    // The ACK rides on enqueue, so wait for the server thread's publication
    // rather than assuming client.Write implies it.
    {
        const auto wait_until =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!server_read_ok.load() &&
               std::chrono::steady_clock::now() < wait_until) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(server_read_ok.load());

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

// ---------------------------------------------------------------------------
// RdgspTransport: scripted-seam unit tests (deterministic, no sockets).
// ---------------------------------------------------------------------------

namespace {

using ConfigT = rtsc::net::RdgspTransport::Config;

// The connector owns the alias; the alias keeps the shared ScriptedRdgsp alive
// for the transport's lifetime, and the test's own shared_ptr outlives it, so
// nothing is double-freed and the plug frees the ScriptedRdgsp.
class ScriptedRdgspAlias : public Transport {
 public:
    explicit ScriptedRdgspAlias(std::shared_ptr<ScriptedRdgsp> inner)
        : inner_(std::move(inner)) {}
    int Read(uint8_t* buf, size_t size) override {
        return inner_->Read(buf, size);
    }
    bool Write(const uint8_t* data, size_t size) override {
        return inner_->Write(data, size);
    }
    void Close() override { inner_->Close(); }

 private:
    std::shared_ptr<ScriptedRdgsp> inner_;
};

std::function<std::unique_ptr<Transport>(std::string&)> AliasConnector(
    const std::shared_ptr<ScriptedRdgsp>& sp) {
    return [sp](std::string&) -> std::unique_ptr<Transport> {
        return std::make_unique<ScriptedRdgspAlias>(sp);
    };
}

ConfigT RdgspTestConfig(const std::shared_ptr<ScriptedRdgsp>& out,
                        const std::shared_ptr<ScriptedRdgsp>& in) {
    ConfigT c;
    c.host = "gw.example";
    c.port = 443;
    c.connection_id = "{958F92D8-DA20-467a-BBE3-65E7E9B4EDCF}";
    c.domain = "DOM";
    c.user_name = "user";
    c.password = "pass";
    c.deadlines.response_ms = 2000;
    c.deadlines.auth_ms = 2000;
    c.connect_out = AliasConnector(out);
    c.connect_in = AliasConnector(in);
    return c;
}

const char* kOutHead200Chunked =
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
    "Content-Type: application/octet-stream\r\n"
    "RDG-Connection-Id: {stub}\r\n\r\n";

const char* kInHead200 =
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

const char* kOutHead200Plain =
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

}  // namespace

RTSC_TEST(rdgsp_connect_chunked_roundtrip) {
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply(kOutHead200Chunked);
    out->Reply("3\r\nabc\r\n");
    out->Reply("5\r\n12345\r\n");
    in->Reply(kInHead200);

    ConfigT c = RdgspTestConfig(out, in);
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));
    CHECK(t.mode() == rtsc::net::RdgspTransport::Mode::kChunked);
    CHECK(!t.upgraded());
    CHECK(t.connected());

    uint8_t buf[64] = {};
    int n = t.Read(buf, sizeof(buf));
    CHECK_EQ(n, 3);
    if (n == 3) CHECK(std::memcmp(buf, "abc", 3) == 0);
    n = t.Read(buf, sizeof(buf));
    CHECK_EQ(n, 5);
    if (n == 5) CHECK(std::memcmp(buf, "12345", 5) == 0);

    CHECK(t.Write(reinterpret_cast<const uint8_t*>("xyz"), 3));
    // IN channel: write #1 is the request head, write #2 is the chunk frame.
    CHECK_EQ(in->requests().size(), static_cast<size_t>(2));
    const std::string in_head = RequestText(in->requests()[0]);
    CHECK(in_head.find("Transfer-Encoding: chunked\r\n") != std::string::npos);
    CHECK(RequestText(in->requests()[1]) == "3\r\nxyz\r\n");
}

RTSC_TEST(rdgsp_in_channel_streams_chunked_request_chunks) {
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply(kOutHead200Chunked);
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));

    const std::string payload(20, 'B');
    CHECK(t.Write(reinterpret_cast<const uint8_t*>(payload.data()),
                  payload.size()));
    // The body write is a single chunk ("14\r\n<20 bytes>\r\n"), never the
    // terminating 0-chunk, and it is a separate write after the request head.
    CHECK_EQ(in->requests().size(), static_cast<size_t>(2));
    CHECK(RequestText(in->requests()[1]) == "14\r\n" + payload + "\r\n");
}

RTSC_TEST(rdgsp_rejects_injected_request_clearly) {
    // D-A4/D-A1 for the RDGSP builder: a CRLF in a header value must fail
    // Connect() with a distinguishable error ("CRLF"/"reject"), never a
    // "timed out" / "too many reads".
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply(kOutHead200Chunked);
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    c.connection_id = "CID\r\nX-Injected: 1";  // hostile value
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(!t.Connect(err));
    CHECK(err.find("CRLF") != std::string::npos ||
          err.find("reject") != std::string::npos);
    CHECK(err.find("timed out") == std::string::npos);
    CHECK(err.find("too many reads") == std::string::npos);
    CHECK(out->requests().empty());  // nothing reached the wire
}

RTSC_TEST(rdgsp_401_retry_cap_fails) {
    // D-A8 / mutation probe: an always-401 gateway must exhaust max_auth_retries
    // and fail with 0x80070005, never hang or (worse) succeed.
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    for (int i = 0; i < 8; ++i) {
        out->Reply("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n"
                   "Content-Length: 0\r\n\r\n");
    }
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    c.max_auth_retries = 3;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(!t.Connect(err));
    CHECK_EQ(t.hresult(), 0x80070005u);
    CHECK(err.find("retries") != std::string::npos);
    CHECK_EQ(t.auth_retry_count(), 3);
    // Exactly max_auth_retries 401 rounds were answered before the failure.
    CHECK(out->requests().size() <= 5u);
}

RTSC_TEST(rdgsp_in_101_is_hard_error) {
    // Evidence FUN_1801bfd60:158-170: a WebSocket upgrade on the IN channel is
    // a hard error, never a silent mode switch.
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply(kOutHead200Chunked);
    in->Reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
              "Connection: Upgrade\r\n\r\n");
    ConfigT c = RdgspTestConfig(out, in);
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(!t.Connect(err));
    CHECK_EQ(t.hresult(), 0x80190000u | 101u);
    CHECK(err.find("switch protocols for IN channel") != std::string::npos);
    CHECK(!t.connected());
}

RTSC_TEST(rdgsp_307_is_not_followed) {
    // Zero-follow (SSRF defence): a 307 is mapped, never retried elsewhere.
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://evil/\r\n"
               "Content-Length: 0\r\n\r\n");
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(!t.Connect(err));
    CHECK_EQ(t.hresult(), 0x80190000u | 307u);
    CHECK_EQ(out->requests().size(), static_cast<size_t>(1));  // felt once
}

RTSC_TEST(rdgsp_status_codes_map_to_hresult) {
    const struct {
        const char* head;
        uint32_t hr;
    } cases[] = {
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
         0x80190000u | 403u},
        {"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
         0x800706C1u},
        {"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", 0x800706BAu},
        {"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n",
         0x800706BAu},
    };
    for (const auto& c : cases) {
        auto out = std::make_shared<ScriptedRdgsp>();
        auto in = std::make_shared<ScriptedRdgsp>();
        out->Reply(c.head);
        in->Reply(kInHead200);
        ConfigT cfg = RdgspTestConfig(out, in);
        rtsc::net::RdgspTransport t(cfg);
        std::string err;
        CHECK(!t.Connect(err));
        CHECK_EQ(t.hresult(), c.hr);
    }
}

RTSC_TEST(rdgsp_ntlm_three_legs_over_scripted_seam) {
    // RFC 4559: 401 (no token) -> client type-1 -> 401+base64(type-2) -> client
    // type-3 -> 200. The type-3 message must structurally decode and carry an
    // NT response.
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n"
               "Content-Length: 0\r\n\r\n");
    out->Reply("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM " +
                   StubNtlmType2Base64() + "\r\nContent-Length: 0\r\n\r\n");
    out->Reply(kOutHead200Plain);
    in->Reply(kInHead200);

    ConfigT c = RdgspTestConfig(out, in);
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));
    CHECK_EQ(out->requests().size(), static_cast<size_t>(3));

    {
        std::string token;
        CHECK(NtlmTokenFromRequest(out->requests()[1], token));
        CHECK(!token.empty());
    }
    rtsc::credssp::AuthenticateMessage auth;
    CHECK(DecodeNtlmType3FromRequest(out->requests()[2], auth));
    CHECK(!auth.nt_response.empty());
    CHECK(auth.user == "user");
    CHECK(auth.domain == "DOM");

    const std::string text = RequestText(out->requests()[0]);
    CHECK(text.find("Authorization:") == std::string::npos);
}

RTSC_TEST(rdgsp_chunked_half_eof_reports_truncation) {
    // A chunked body that ends mid-chunk is a hard error (-1), not an EOF.
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply(kOutHead200Chunked);
    out->Reply("5\r\nAB");  // declares 5 bytes, delivers 2
    out->CloseOnNextRead();
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));
    if (!err.empty()) std::printf("  half-eof connect error: %s\n", err.c_str());

    uint8_t buf[64];
    // The two delivered bytes of the truncated chunk surface first...
    const int partial = t.Read(buf, sizeof(buf));
    CHECK_EQ(partial, 2);
    if (partial == 2) CHECK(std::memcmp(buf, "AB", 2) == 0);
    // ...then the mid-chunk EOF latches as a hard truncation error (-1).
    const int n = t.Read(buf, sizeof(buf));
    CHECK_EQ(n, -1);
    CHECK(t.error().find("truncat") != std::string::npos);
}

RTSC_TEST(rdgsp_upgraded_101_reads_and_writes_websocket_frames) {
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    // A valid RFC 6455 101: Upgrade + Connection: Upgrade + the Accept derived
    // from the injected key (ComputeWebSocketAccept(kWebSocketSampleKey)).
    out->Reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Accept: " +
               std::string(kWebSocketSampleAccept) + "\r\n\r\n");
    // Server->client data frame: unmasked binary, 5-byte payload "hello".
    out->Reply(std::vector<uint8_t>{0x82, 0x05, 'h', 'e', 'l', 'l', 'o'});
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    c.websocket_key = kWebSocketSampleKey;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));
    CHECK(t.upgraded());
    CHECK(t.mode() == rtsc::net::RdgspTransport::Mode::kUpgraded);

    // Request-head completeness: the OUT upgrade ask carried the pinned key
    // (24-char base64) and the RFC 6455 version under which the Accept that
    // just validated was computed.
    std::string sent_key;
    CHECK(WebSocketKeyFromRequest(out->requests()[0], sent_key));
    CHECK(sent_key == kWebSocketSampleKey);
    CHECK(RequestText(out->requests()[0]).find("Sec-WebSocket-Version: 13\r\n") !=
          std::string::npos);

    uint8_t buf[64] = {};
    const int n = t.Read(buf, sizeof(buf));
    CHECK_EQ(n, 5);
    if (n == 5) CHECK(std::memcmp(buf, "hello", 5) == 0);

    // Client->server: a MASKED websocket binary frame lands on OUT as a write
    // after the OUT request head.
    CHECK(t.Write(reinterpret_cast<const uint8_t*>("hi"), 2));
    CHECK_EQ(out->requests().size(), static_cast<size_t>(2));
    const std::vector<uint8_t>& frame_bytes = out->requests()[1];
    rtsc::proto::WebSocketFrameDecoder dec;
    const std::vector<rtsc::proto::WebSocketFrame> frames =
        dec.Feed(frame_bytes.data(), frame_bytes.size());
    CHECK(!dec.failed());
    CHECK_EQ(frames.size(), static_cast<size_t>(1));
    if (frames.size() == 1) {
        CHECK(frames[0].opcode == rtsc::proto::WebSocketOpcode::kBinary);
        CHECK(frames[0].fin);
        CHECK(frames[0].payload == ToVec("hi"));
    }
}

RTSC_TEST(rdgsp_upgraded_each_frame_gets_a_fresh_mask) {
    // RFC 6455 5.3: each client frame carries its own mask key. One Write that
    // spans two frames (16 MiB + 1) used to reuse a single key for both.
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Accept: " +
               std::string(kWebSocketSampleAccept) + "\r\n\r\n");
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    c.websocket_key = kWebSocketSampleKey;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));
    CHECK(t.upgraded());

    const size_t kPayload =
        static_cast<size_t>(rtsc::proto::kMaxWebSocketPayloadBytes) + 1;
    std::vector<uint8_t> payload(kPayload, 0x5A);
    CHECK(t.Write(payload.data(), payload.size()));

    // ScriptedRdgsp records one entry per Write: [0] = request head,
    // [1] = first frame, [2] = second frame.
    CHECK_EQ(out->requests().size(), static_cast<size_t>(3));
    if (out->requests().size() == 3) {
        const std::vector<uint8_t>& first = out->requests()[1];
        const std::vector<uint8_t>& second = out->requests()[2];
        // Frame 1: 0x82, 0x80|127, 8-byte length, 4-byte mask, 16 MiB payload.
        CHECK_EQ(first.size(), static_cast<size_t>(2 + 8 + 4) + kPayload - 1);
        // Frame 2: 0x82, 0x80|1, 4-byte mask, 1-byte payload.
        CHECK_EQ(second.size(), static_cast<size_t>(2 + 4 + 1));
        if (first.size() >= 14 && second.size() >= 6) {
            CHECK(std::memcmp(first.data() + 10, second.data() + 2, 4) != 0);
        }
    }
}

RTSC_TEST(rdgsp_upgraded_write_can_stay_on_in) {
    // upgrade_steals_write=false: in kUpgraded the write side keeps using the
    // IN channel (the "IN keeps a management stream" fallback, UNVERIFIED).
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Accept: " +
               std::string(kWebSocketSampleAccept) + "\r\n\r\n");
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    c.websocket_key = kWebSocketSampleKey;
    c.upgrade_steals_write = false;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));
    CHECK(t.upgraded());

    // The write must land on the IN transport (as a WS frame), not OUT; write #1
    // on IN is the request head, write #2 is the frame.
    CHECK(t.Write(reinterpret_cast<const uint8_t*>("in"), 2));
    CHECK_EQ(out->requests().size(), static_cast<size_t>(1));  // only the head
    CHECK_EQ(in->requests().size(), static_cast<size_t>(2));
    rtsc::proto::WebSocketFrameDecoder dec;
    const std::vector<rtsc::proto::WebSocketFrame> frames =
        dec.Feed(in->requests()[1].data(), in->requests()[1].size());
    CHECK(!dec.failed());
    CHECK_EQ(frames.size(), static_cast<size_t>(1));
    if (frames.size() == 1) CHECK(frames[0].payload == ToVec("in"));
}

RTSC_TEST(rdgsp_upgraded_101_missing_accept_fails_closed) {
    // A 101 without Sec-WebSocket-Accept must fail closed: the connection is
    // already upgraded, and its bytes cannot be re-interpreted as an HTTP body
    // after the fact. The old "status code alone" accept was a frozen defect.
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\n\r\n");
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    c.websocket_key = kWebSocketSampleKey;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(!t.Connect(err));
    CHECK(t.hresult() != 0);
    CHECK(!t.connected());
    CHECK(!t.upgraded());
    CHECK(err.find("Sec-WebSocket-Accept") != std::string::npos);
}

RTSC_TEST(rdgsp_upgraded_101_wrong_accept_fails_closed) {
    // A 101 whose Sec-WebSocket-Accept does not match the computed value is a
    // man-in-the-middle / handshake-mismatch signal: hard error, never a
    // downgrade to the chunked path.
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Accept: " +
               std::string(28, 'A') + "\r\n\r\n");
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    c.websocket_key = kWebSocketSampleKey;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(!t.Connect(err));
    CHECK(t.hresult() != 0);
    CHECK(!t.connected());
    CHECK(!t.upgraded());
    CHECK(err.find("Sec-WebSocket-Accept") != std::string::npos);
}

RTSC_TEST(rdgsp_upgraded_101_rejects_missing_or_wrong_protocol_headers) {
    // All three legs of the RFC 6455 handshake must hold: Upgrade: websocket,
    // Connection containing the Upgrade token, and the matching Accept. A 101
    // with a correct Accept but a broken Upgrade/Connection leg still fails.
    const char* heads[] = {
        // No Upgrade / Connection headers at all.
        "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        // Wrong Upgrade value but a Connection header.
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        // Right Upgrade value but Connection lacks the Upgrade token.
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: close\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
    };
    for (const char* head : heads) {
        auto out = std::make_shared<ScriptedRdgsp>();
        auto in = std::make_shared<ScriptedRdgsp>();
        out->Reply(head);
        in->Reply(kInHead200);
        ConfigT c = RdgspTestConfig(out, in);
        c.websocket_key = kWebSocketSampleKey;
        rtsc::net::RdgspTransport t(c);
        std::string err;
        CHECK(!t.Connect(err));
        CHECK(t.hresult() != 0);
        CHECK(!t.upgraded());
        CHECK(err.find("Sec-WebSocket-Accept") != std::string::npos);
    }
}

RTSC_TEST(rdgsp_out_401_refreshes_websocket_key_each_attempt) {
    // The RFC 6455 nonce must not be reused across 401 retries: attempt 2
    // carries a fresh Sec-WebSocket-Key. (Accept validation uses the key of the
    // attempt that produced the 101, so a stale key would derail the check.)
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n"
               "Content-Length: 0\r\n\r\n");
    out->Reply(kOutHead200Plain);
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));
    CHECK(t.mode() == rtsc::net::RdgspTransport::Mode::kChunked);
    CHECK_EQ(out->requests().size(), static_cast<size_t>(2));
    if (out->requests().size() == 2) {
        std::string k1, k2;
        CHECK(WebSocketKeyFromRequest(out->requests()[0], k1));
        CHECK(WebSocketKeyFromRequest(out->requests()[1], k2));
        CHECK(!k1.empty());
        CHECK(k1 != k2);
    }
}

RTSC_TEST(rdgsp_unsupported_auth_scheme_fails_explicitly) {
    // Negotiate / Claims are not implemented: explicit 0x80004001, never a
    // silent skip.
    auto out = std::make_shared<ScriptedRdgsp>();
    auto in = std::make_shared<ScriptedRdgsp>();
    out->Reply("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\n"
               "Content-Length: 0\r\n\r\n");
    in->Reply(kInHead200);
    ConfigT c = RdgspTestConfig(out, in);
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(!t.Connect(err));
    CHECK_EQ(t.hresult(), 0x80004001u);
    CHECK(err.find("unsupported") != std::string::npos);
}

// ---------------------------------------------------------------------------
// StubGateway end-to-end over real loopback TCP (cleartext http, the factory's
// +0x6a8==0 mode).
// ---------------------------------------------------------------------------

RTSC_TEST(stub_gateway_200_chunked_byte_roundtrip) {
    StubGateway gw(StubGateway::Scenario::k200Chunked);
    std::string ger;
    CHECK(gw.Start(ger));
    ConfigT c;
    c.host = "127.0.0.1";
    c.port = gw.bound_port();
    c.connection_id = "{75869ED5-4E6B-4E2E-a17a-e955e8b5c399}";
    c.domain = "DOM";
    c.user_name = "user";
    c.password = "pass";
    c.deadlines.response_ms = 3000;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));
    CHECK(t.mode() == rtsc::net::RdgspTransport::Mode::kChunked);

    const uint8_t payload[] = {'h', 'e', 'l', 'l', 'o', '!', 0x7F,
                               0x00, 0xFF};
    CHECK(t.Write(payload, sizeof(payload)));

    uint8_t buf[64] = {};
    size_t got = 0;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (got < sizeof(payload) && std::chrono::steady_clock::now() < deadline) {
        const int n = t.Read(buf + got, sizeof(buf) - got);
        if (n == kReadTimeout) continue;
        if (n <= 0) break;
        got += static_cast<size_t>(n);
    }
    CHECK_EQ(got, sizeof(payload));
    if (got == sizeof(payload)) {
        CHECK(std::memcmp(buf, payload, sizeof(payload)) == 0);
    }
    gw.Stop();
}

RTSC_TEST(stub_gateway_plain_response_falls_back_to_raw) {
    // The OUT response carrying no Transfer-Encoding is passed through raw
    // (plain fallback), so an echo round-trips without chunked framing.
    StubGateway gw(StubGateway::Scenario::k200Plain);
    std::string ger;
    CHECK(gw.Start(ger));
    ConfigT c;
    c.host = "127.0.0.1";
    c.port = gw.bound_port();
    c.connection_id = "{75869ED5-4E6B-4E2E-a17a-e955e8b5c399}";
    c.domain = "DOM";
    c.user_name = "user";
    c.password = "pass";
    c.deadlines.response_ms = 3000;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));

    const uint8_t payload[] = {'p', 'l', 'a', 'i', 'n'};
    CHECK(t.Write(payload, sizeof(payload)));
    uint8_t buf[32] = {};
    size_t got = 0;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (got < sizeof(payload) && std::chrono::steady_clock::now() < deadline) {
        const int n = t.Read(buf + got, sizeof(buf) - got);
        if (n == kReadTimeout) continue;
        if (n <= 0) break;
        got += static_cast<size_t>(n);
    }
    CHECK_EQ(got, sizeof(payload));
    if (got == sizeof(payload)) {
        CHECK(std::memcmp(buf, payload, sizeof(payload)) == 0);
    }
    gw.Stop();
}

RTSC_TEST(stub_gateway_ntlm_three_legs_end_to_end) {
    StubGateway gw(StubGateway::Scenario::kNtlm200);
    std::string ger;
    CHECK(gw.Start(ger));
    ConfigT c;
    c.host = "127.0.0.1";
    c.port = gw.bound_port();
    c.connection_id = "{75869ED5-4E6B-4E2E-a17a-e955e8b5c399}";
    c.domain = "DOM";
    c.user_name = "user";
    c.password = "pass";
    c.deadlines.response_ms = 3000;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));
    if (!err.empty()) std::printf("  ntlm e2e connect error: %s\n", err.c_str());
    CHECK(gw.type3_verified());

    const uint8_t fb[] = {'N', 'T', 'L', 'M'};
    CHECK(t.Write(fb, sizeof(fb)));
    uint8_t buf[16] = {};
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    size_t got = 0;
    while (got < sizeof(fb) && std::chrono::steady_clock::now() < deadline) {
        const int n = t.Read(buf + got, sizeof(buf) - got);
        if (n == kReadTimeout) continue;
        if (n <= 0) break;
        got += static_cast<size_t>(n);
    }
    CHECK_EQ(got, sizeof(fb));
    gw.Stop();
}

RTSC_TEST(stub_gateway_in_101_is_hard_error) {
    StubGateway gw(StubGateway::Scenario::kIn101);
    std::string ger;
    CHECK(gw.Start(ger));
    ConfigT c;
    c.host = "127.0.0.1";
    c.port = gw.bound_port();
    c.connection_id = "{75869ED5-4E6B-4E2E-a17a-e955e8b5c399}";
    c.domain = "DOM";
    c.user_name = "user";
    c.password = "pass";
    c.deadlines.response_ms = 3000;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(!t.Connect(err));
    CHECK_EQ(t.hresult(), 0x80190000u | 101u);
    CHECK(err.find("switch protocols for IN channel") != std::string::npos);
    gw.Stop();
}

RTSC_TEST(stub_gateway_401_cap_end_to_end) {
    StubGateway gw(StubGateway::Scenario::k401Always);
    std::string ger;
    CHECK(gw.Start(ger));
    ConfigT c;
    c.host = "127.0.0.1";
    c.port = gw.bound_port();
    c.connection_id = "{75869ED5-4E6B-4E2E-a17a-e955e8b5c399}";
    c.domain = "DOM";
    c.user_name = "user";
    c.password = "pass";
    c.max_auth_retries = 3;
    c.deadlines.response_ms = 3000;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(!t.Connect(err));
    CHECK_EQ(t.hresult(), 0x80070005u);
    CHECK_EQ(t.auth_retry_count(), 3);
    gw.Stop();
}

RTSC_TEST(stub_gateway_status_mapping_end_to_end) {
    const struct {
        StubGateway::Scenario s;
        uint32_t hr;
    } cases[] = {
        {StubGateway::Scenario::kStatus403, 0x80190000u | 403u},
        {StubGateway::Scenario::kStatus407, 0x800706C1u},
        {StubGateway::Scenario::kStatus502, 0x800706BAu},
        {StubGateway::Scenario::kStatus504, 0x800706BAu},
        {StubGateway::Scenario::kStatus307, 0x80190000u | 307u},
    };
    for (const auto& c : cases) {
        StubGateway gw(c.s);
        std::string ger;
        CHECK(gw.Start(ger));
        ConfigT cfg;
        cfg.host = "127.0.0.1";
        cfg.port = gw.bound_port();
        cfg.connection_id = "{75869ED5-4E6B-4E2E-a17a-e955e8b5c399}";
        cfg.domain = "DOM";
        cfg.user_name = "user";
        cfg.password = "pass";
        cfg.deadlines.response_ms = 3000;
        rtsc::net::RdgspTransport t(cfg);
        std::string err;
        CHECK(!t.Connect(err));
        CHECK_EQ(t.hresult(), c.hr);
        gw.Stop();
    }
}

RTSC_TEST(stub_gateway_large_bidirectional_no_deadlock) {
    // Dual-connection proof: sustained bidirectional traffic over one transport
    // must never deadlock (each direction has its own connection). A time gate
    // turns any stall into a test failure instead of a hang.
    StubGateway gw(StubGateway::Scenario::k200Chunked);
    std::string ger;
    CHECK(gw.Start(ger));
    ConfigT c;
    c.host = "127.0.0.1";
    c.port = gw.bound_port();
    c.connection_id = "{75869ED5-4E6B-4E2E-a17a-e955e8b5c399}";
    c.domain = "DOM";
    c.user_name = "user";
    c.password = "pass";
    c.deadlines.response_ms = 3000;
    rtsc::net::RdgspTransport t(c);
    std::string err;
    CHECK(t.Connect(err));

    const size_t kBlock = 256 * 1024;
    std::vector<uint8_t> payload(kBlock);
    for (size_t i = 0; i < kBlock; ++i) {
        payload[i] = static_cast<uint8_t>(i * 7 + 3);
    }

    std::atomic<bool> write_ok{false};
    std::atomic<bool> read_ok{false};
    std::thread writer([&] {
        size_t off = 0;
        while (off < payload.size()) {
            const size_t n = (std::min)(static_cast<size_t>(16384),
                                        payload.size() - off);
            if (!t.Write(payload.data() + off, n)) return;
            off += n;
        }
        write_ok.store(true);
    });
    std::thread reader([&] {
        std::vector<uint8_t> got;
        got.reserve(kBlock);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (got.size() < kBlock &&
               std::chrono::steady_clock::now() < deadline) {
            uint8_t buf[8192];
            const int n = t.Read(buf, sizeof(buf));
            if (n == kReadTimeout) continue;
            if (n <= 0) return;
            got.insert(got.end(), buf, buf + n);
        }
        if (got.size() == kBlock &&
            std::memcmp(got.data(), payload.data(), kBlock) == 0) {
            read_ok.store(true);
        }
    });
    writer.join();
    reader.join();
    CHECK(write_ok.load());
    CHECK(read_ok.load());
    gw.Stop();
}

RTSC_TEST(tls_byte_transport_write_retries_until_all_consumed) {
    // The TLS backend may consume only part of one Send call and still report
    // kOk (OpenSSL WANT_READ). The adaptor must feed the tail until the whole
    // buffer went out: claiming success after 40/100 bytes loses the stream.
    auto raw = std::make_unique<MockTransport>();
    MockTransport* rawp = raw.get();
    auto tls = std::make_unique<ScriptedTls>(40, 0);
    ScriptedTls* tlsp = tls.get();
    std::string error;
    TlsByteTransport t(std::move(raw), std::move(tls), error, 1000);
    CHECK(error.empty());

    std::vector<uint8_t> payload(100, 0x42);
    const bool ok = t.Write(payload.data(), payload.size());
    CHECK(ok);
    CHECK_EQ(rawp->written.size(), static_cast<size_t>(100));
    CHECK_EQ(tlsp->consumed_total, static_cast<size_t>(100));
    CHECK(tlsp->send_calls > 1);
}

RTSC_TEST(tls_byte_transport_read_buffers_the_tail) {
    // max_out is a soft threshold: the backend may return one extra record
    // (516 bytes for a 16-byte buffer). The adaptor must retain the remainder
    // and serve it on later reads instead of dropping it.
    auto raw = std::make_unique<MockTransport>();
    auto tls = std::make_unique<ScriptedTls>(0, 500);
    std::string error;
    TlsByteTransport t(std::move(raw), std::move(tls), error, 1000);
    CHECK(error.empty());

    uint8_t buf[16];
    size_t delivered = 0;
    for (int i = 0; i < 100 && delivered < 516; ++i) {
        const int n = t.Read(buf, sizeof(buf));
        if (n <= 0) break;
        delivered += static_cast<size_t>(n);
    }
    CHECK_EQ(delivered, static_cast<size_t>(516));
}

int main() { return ::rtsc::test::run_all("rtsc_gateway_tests"); }
