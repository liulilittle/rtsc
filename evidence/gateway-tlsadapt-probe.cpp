// Parent probe: prove TlsByteTransport silently drops bytes.
//
// 1. Write(): the TLS backend may consume fewer than `size` bytes (OpenSSL's
//    SSL_write hits WANT_READ/WANT_WRITE and the backend still reports kOk with
//    consumed < size -- src/net/tls_openssl.cpp:207-220). The adaptor ignores
//    `consumed`, so the tail is lost while Write() returns true, violating
//    net::Transport's contract ("Sends all `size` bytes").
// 2. Read(): the backend may append more than max_out ("soft threshold", one
//    extra record); the adaptor copies min(size, plaintext.size()) and drops the
//    remainder.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "rtsc/net/gateway_transport.h"
#include "rtsc/net/tls.h"
#include "rtsc/net/transport.h"

namespace {

using rtsc::tls::Error;
using rtsc::tls::NegotiatedInfo;
using rtsc::tls::RecordSizes;

class ScriptedTls : public rtsc::tls::TlsTransport {
 public:
    ScriptedTls(size_t send_cap, size_t read_extra)
        : send_cap_(send_cap), read_extra_(read_extra) {}

    Error Handshake(const uint8_t*, size_t in_size, size_t& consumed,
                    std::vector<uint8_t>& out) override {
        consumed = in_size;
        out.clear();
        handshaken_ = true;
        return Error{};
    }
    Error Send(const uint8_t*, size_t size, size_t& consumed,
               std::vector<uint8_t>& out) override {
        consumed = (send_cap_ == 0 || size <= send_cap_) ? size : send_cap_;
        out.assign(consumed, 0x5A);
        return Error{};
    }
    Error Receive(const uint8_t*, size_t, std::vector<uint8_t>& plain,
                  size_t max_out) override {
        if (served_) {
            plain.clear();
            return Error{};
        }
        served_ = true;
        plain.assign((max_out == 0 ? 100u : max_out + read_extra_), 0x41);
        return Error{};
    }
    Error LocalCertificateDer(std::vector<uint8_t>& o) const override {
        o.clear();
        return Error{};
    }
    Error LocalSubjectPublicKey(std::vector<uint8_t>& o) const override {
        o.clear();
        return Error{};
    }
    Error PeerSubjectPublicKeyInfo(std::vector<uint8_t>& o) const override {
        o.clear();
        return Error{};
    }
    Error PeerSubjectPublicKey(std::vector<uint8_t>& o) const override {
        o.clear();
        return Error{};
    }
    Error PeerCertificateDer(std::vector<uint8_t>& o) const override {
        o.clear();
        return Error{};
    }
    Error negotiated(NegotiatedInfo& o) const override {
        o = NegotiatedInfo{};
        return Error{};
    }
    RecordSizes record_sizes() const override { return RecordSizes{}; }
    Error Shutdown(std::vector<uint8_t>& o) override {
        o.clear();
        return Error{};
    }
    bool handshake_complete() const noexcept override { return handshaken_; }
    bool closed() const noexcept override { return false; }
    size_t buffered_input() const noexcept override { return 0; }
    const Error& last_error() const noexcept override { return ok_; }
    const char* backend_name() const noexcept override { return "scripted"; }

 private:
    size_t send_cap_ = 0;
    size_t read_extra_ = 0;
    bool served_ = false;
    bool handshaken_ = false;
    Error ok_{};
};

class NullRaw : public rtsc::net::Transport {
 public:
    int Read(uint8_t* buf, size_t size) override {
        if (fed_) return rtsc::net::kReadTimeout;
        fed_ = true;
        const size_t n = (size < 16 ? size : 16);
        std::memset(buf, 0x11, n);
        return static_cast<int>(n);
    }
    bool Write(const uint8_t*, size_t s) override {
        written_total_ += s;
        return true;
    }
    void Close() override {}
    size_t written_total_ = 0;

 private:
    bool fed_ = false;
};

}  // namespace

int main() {
    int failures = 0;
    auto check = [&](const char* n, bool ok) {
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", n);
        if (!ok) ++failures;
    };

    {
        auto raw = std::make_unique<NullRaw>();
        NullRaw* rawp = raw.get();
        auto tls = std::make_unique<ScriptedTls>(40, 0);
        std::string err;
        rtsc::net::TlsByteTransport t(std::move(raw), std::move(tls), err,
                                      1000);
        std::vector<uint8_t> payload(100, 0x42);
        const bool ok = t.Write(payload.data(), payload.size());
        std::printf("  [INFO] Write returned %d, wire bytes=%zu (asked 100)\n",
                    (int)ok, rawp->written_total_);
        check("Write must not claim success when only part was consumed",
              rawp->written_total_ == 100);
    }

    {
        auto raw = std::make_unique<NullRaw>();
        auto tls = std::make_unique<ScriptedTls>(0, 500);
        std::string err;
        rtsc::net::TlsByteTransport t(std::move(raw), std::move(tls), err,
                                      1000);
        uint8_t buf[16]{};
        size_t delivered = 0;
        int n = t.Read(buf, sizeof(buf));
        if (n > 0) delivered += static_cast<size_t>(n);
        // The backend decrypted 516 bytes once (as a real backend does); if the
        // adaptor discarded the tail, a second read finds nothing left.
        n = t.Read(buf, sizeof(buf));
        if (n > 0) delivered += static_cast<size_t>(n);
        std::printf("  [INFO] two reads delivered %zu bytes; backend produced "
                    "516\n", delivered);
        check("Read must not silently discard the tail beyond the buffer",
              delivered == 516);
    }

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
