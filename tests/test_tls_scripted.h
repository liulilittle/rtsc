// Shared scripted TLS transport for the security-layer tests.
//
// The TLS transport is scripted so the security state machine can be driven end
// to end without a network peer or a platform TLS backend (SChannel/OpenSSL).
// Extracted from test_security_layer.cpp so test_server_security.cpp can run the
// same in-process loopback on platforms that have no TLS backend.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/net/tls.h"

namespace {

rtsc::tls::Error Ok() { return rtsc::tls::Error{}; }

// A scripted TLS transport. The handshake completes after two calls; Send and
// Receive are the identity so CredSSP DER messages pass through unchanged. This
// isolates the security layer's framing/state logic from SChannel.
class ScriptedTls : public rtsc::tls::TlsTransport {
 public:
    rtsc::tls::Error Handshake(const uint8_t* in, size_t in_size,
                               size_t& consumed,
                               std::vector<uint8_t>& out) override {
        (void)in;
        out.clear();
        if (!hello_sent_) {
            // First call: emit the peer's handshake token (ClientHello for a
            // client, ServerHello for a server) and stay incomplete.
            hello_sent_ = true;
            consumed = in_size;
            out = {0x16, 0x03, 0x01, 0x00, 0x05, 0x01};
            return Ok();
        }
        // Like a real TLS stack, the accept/handshake cannot complete until the
        // peer's token arrives. Pumping with no input must not advance the
        // state machine (the driver pumps after every write).
        if (in_size == 0) {
            consumed = 0;
            return Ok();
        }
        consumed = in_size;
        handshake_complete_ = true;
        return Ok();
    }
    rtsc::tls::Error Send(const uint8_t* plaintext, size_t size,
                          size_t& consumed, std::vector<uint8_t>& out) override {
        out.assign(plaintext, plaintext + size);
        consumed = size;
        return Ok();
    }
    rtsc::tls::Error Receive(const uint8_t* ciphertext, size_t size,
                             std::vector<uint8_t>& plaintext,
                             size_t max_out) override {
        (void)max_out;
        if (ciphertext != nullptr && size > 0) {
            plaintext.insert(plaintext.end(), ciphertext, ciphertext + size);
        }
        return Ok();
    }
    rtsc::tls::Error PeerSubjectPublicKeyInfo(
        std::vector<uint8_t>& out) const override {
        out = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        return Ok();
    }
    rtsc::tls::Error PeerSubjectPublicKey(
        std::vector<uint8_t>& out) const override {
        out = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        return Ok();
    }
    rtsc::tls::Error PeerCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        return Ok();
    }
    rtsc::tls::Error LocalCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        return Ok();
    }
    rtsc::tls::Error LocalSubjectPublicKey(
        std::vector<uint8_t>& out) const override {
        out = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        return Ok();
    }
    rtsc::tls::Error negotiated(rtsc::tls::NegotiatedInfo& out) const override {
        out = rtsc::tls::NegotiatedInfo{};
        out.tls_version = 0x0304;
        return Ok();
    }
    rtsc::tls::RecordSizes record_sizes() const override {
        rtsc::tls::RecordSizes s;
        s.header = 5;
        s.max_plaintext = 16384;
        s.overhead_upper = 44;
        s.overhead_actual = 17;
        s.block_size = 16;
        return s;
    }
    rtsc::tls::Error Shutdown(std::vector<uint8_t>& out) override {
        out.clear();
        return Ok();
    }
    bool handshake_complete() const noexcept override {
        return handshake_complete_;
    }
    bool closed() const noexcept override { return false; }
    size_t buffered_input() const noexcept override { return 0; }
    const rtsc::tls::Error& last_error() const noexcept override {
        return last_error_;
    }
    const char* backend_name() const noexcept override { return "scripted"; }

 private:
    bool hello_sent_ = false;
    bool handshake_complete_ = false;
    rtsc::tls::Error last_error_{};
};

}  // namespace
