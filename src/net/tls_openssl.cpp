// OpenSSL backend for rtsc::tls::TlsTransport.
//
// Design reference: docs/spec/tls-backend.design-a.md (dual backend: Windows =
// SChannel, other platforms = OpenSSL 3.x).
//
// The record layer is driven through a memory BIO pair: ciphertext is written
// into the read BIO and produced by the write BIO, mirroring the token-based
// SChannel backend. This keeps the TlsTransport contract identical across
// backends (consumed / append-only plaintext / idempotent terminal states).

#include "rtsc/net/tls.h"

#if !defined(_WIN32)

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "tls_openssl_internal.h"

namespace rtsc::tls {
namespace {

constexpr size_t kMaxPlaintext = 16384;

std::string OpensslError() {
    const unsigned long e = ERR_get_error();
    if (e == 0) return "no OpenSSL error";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf;
}

// Reads a DER length field. `pos` points just after the tag on entry and just
// after the length bytes on success.
bool ReadDerLen(const std::vector<uint8_t>& b, size_t& pos, size_t& len) {
    if (pos >= b.size()) return false;
    const uint8_t first = b[pos++];
    if ((first & 0x80) == 0) {
        len = first;
        return true;
    }
    const size_t n = first & 0x7F;
    if (n == 0 || n > 4 || pos + n > b.size()) return false;
    len = 0;
    for (size_t i = 0; i < n; ++i) len = (len << 8) | b[pos++];
    return true;
}

// Extracts the BIT STRING content of a SubjectPublicKeyInfo DER. For an RSA key
// that is the RSAPublicKey DER, exactly what CredSSP pubKeyAuth needs. Parsed
// by hand so no deprecated OpenSSL 3.0 RSA API is required.
std::vector<uint8_t> ExtractSpkiBitString(const std::vector<uint8_t>& spki) {
    std::vector<uint8_t> out;
    size_t pos = 0;
    if (spki.size() < 2 || spki[0] != 0x30) return out;
    ++pos;
    size_t outer = 0;
    if (!ReadDerLen(spki, pos, outer)) return out;
    const size_t outer_end = std::min(spki.size(), pos + outer);

    // AlgorithmIdentifier: SEQUENCE.
    if (pos >= outer_end || spki[pos] != 0x30) return out;
    ++pos;
    size_t alg = 0;
    if (!ReadDerLen(spki, pos, alg)) return out;
    pos += alg;

    // BIT STRING.
    if (pos >= outer_end || spki[pos] != 0x03) return out;
    ++pos;
    size_t bs = 0;
    if (!ReadDerLen(spki, pos, bs)) return out;
    if (pos >= spki.size()) return out;
    ++pos;  // unused-bits octet
    if (bs < 1 || pos + (bs - 1) > spki.size()) return out;
    out.assign(spki.begin() + static_cast<ptrdiff_t>(pos),
               spki.begin() + static_cast<ptrdiff_t>(pos + bs - 1));
    return out;
}

class OpensslTransport final : public TlsTransport {
 public:
    explicit OpensslTransport(const Config& config) : config_(config) {}
    ~OpensslTransport() override {
        if (ssl_) SSL_free(ssl_);  // frees the BIOs as well
        if (ctx_) SSL_CTX_free(ctx_);
    }

    bool Start(std::string& why) {
        OPENSSL_init_ssl(0, nullptr);
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (ctx_ == nullptr) {
            why = "SSL_CTX_new failed: " + OpensslError();
            return false;
        }

        if (config_.min_version == 0x0304) {
            SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
        } else if (config_.min_version == 0x0303) {
            SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
        }
        if (config_.max_version == 0x0303) {
            SSL_CTX_set_max_proto_version(ctx_, TLS1_2_VERSION);
        } else {
            SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
        }

        switch (config_.cert_policy) {
            case CertPolicy::kInsecure:
                SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
                break;
            case CertPolicy::kTofu:
                // kTofu + pin: the pin IS the identity (SChannel parity); a
                // chain check here would reject a self-signed gateway before
                // the pin comparison at PostHandshakeChecks can run. Without a
                // pin, kTofu keeps verifying the chain (no hostname check).
                //
                // UNVERIFIED on Windows hosts: tls_openssl.cpp is not built
                // here. Verify on Linux with -DRTSC_TLS_OPENSSL=ON by running
                // the tls_openssl suite, and against a self-signed gateway
                // using --gateway-trust=<spki>.
                SSL_CTX_set_verify(ctx_,
                                   config_.pin_is_set ? SSL_VERIFY_NONE
                                                      : SSL_VERIFY_PEER,
                                   nullptr);
                break;
            case CertPolicy::kStrict:
                SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
                break;
        }

        ssl_ = SSL_new(ctx_);
        if (ssl_ == nullptr) {
            why = "SSL_new failed: " + OpensslError();
            return false;
        }
        BIO* rbio = BIO_new(BIO_s_mem());
        BIO* wbio = BIO_new(BIO_s_mem());
        if (rbio == nullptr || wbio == nullptr) {
            BIO_free(rbio);
            BIO_free(wbio);
            why = "BIO_new failed";
            return false;
        }
        SSL_set_bio(ssl_, rbio, wbio);
        rbio_ = SSL_get_rbio(ssl_);
        wbio_ = SSL_get_wbio(ssl_);
        SSL_set_connect_state(ssl_);

        const std::string sni =
            config_.sni.empty() ? config_.peer_host : config_.sni;
        if (config_.send_sni && !sni.empty()) {
            SSL_set_tlsext_host_name(ssl_, sni.c_str());
        }
        if (config_.cert_policy == CertPolicy::kStrict && !sni.empty()) {
            SSL_set1_host(ssl_, sni.c_str());
        }
        return true;
    }

    // -------------------------------------------------------------- handshake
    Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,
                    std::vector<uint8_t>& out) override {
        consumed = 0;
        out.clear();
        if (terminal_) return last_error_;
        if (closed_) return MakeError(Status::kClosed, 0, "already closed");
        if (handshake_complete_) return MakeError(Status::kOk, 0, "");

        const size_t pending_before = BIO_ctrl_pending(rbio_);
        if (in != nullptr && in_size > 0) {
            if (BIO_write(rbio_, in, static_cast<int>(in_size)) !=
                static_cast<int>(in_size)) {
                return Fail(Status::kInternal, "BIO_write failed");
            }
        }

        const int rc = SSL_do_handshake(ssl_);
        DrainOut(out);

        if (rc == 1) {
            if (!PostHandshakeChecks()) return last_error_;
            handshake_complete_ = true;
        } else {
            const int err = SSL_get_error(ssl_, rc);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                return Fail(Status::kProtocolError,
                            "handshake failed: " + OpensslError());
            }
        }

        const size_t pending_after = BIO_ctrl_pending(rbio_);
        const size_t left = pending_after > pending_before
                                ? pending_after - pending_before
                                : 0;
        consumed = in_size > left ? in_size - left : 0;
        return MakeError(Status::kOk, 0, "");
    }

    // ------------------------------------------------------------------- send
    Error Send(const uint8_t* plaintext, size_t size, size_t& consumed,
               std::vector<uint8_t>& out) override {
        consumed = 0;
        out.clear();
        if (terminal_) return last_error_;
        if (closed_) return MakeError(Status::kClosed, 0, "already closed");
        if (!handshake_complete_) {
            return Fail(Status::kInternal, "send before handshake");
        }

        size_t written = 0;
        while (written < size) {
            const int n = SSL_write(
                ssl_, plaintext + written,
                static_cast<int>(std::min<size_t>(size - written, kMaxPlaintext)));
            if (n > 0) {
                written += static_cast<size_t>(n);
                continue;
            }
            const int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) break;
            return Fail(Status::kInternal, "SSL_write failed: " + OpensslError());
        }
        consumed = written;
        DrainOut(out);
        return MakeError(Status::kOk, 0, "");
    }

    // ---------------------------------------------------------------- receive
    Error Receive(const uint8_t* ciphertext, size_t size,
                  std::vector<uint8_t>& plaintext, size_t max_out) override {
        if (terminal_) {
            plaintext.clear();
            return last_error_;
        }
        if (ciphertext != nullptr && size > 0) {
            if (BIO_write(rbio_, ciphertext, static_cast<int>(size)) !=
                static_cast<int>(size)) {
                plaintext.clear();
                return Fail(Status::kInternal, "BIO_write failed");
            }
        }

        for (;;) {
            if (max_out != 0 && plaintext.size() >= max_out) break;
            uint8_t buf[kMaxPlaintext];
            const int n = SSL_read(ssl_, buf, sizeof(buf));
            if (n > 0) {
                plaintext.insert(plaintext.end(), buf, buf + n);
                continue;
            }
            const int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ) break;
            if (err == SSL_ERROR_ZERO_RETURN) {
                closed_ = true;
                return MakeError(Status::kClosed, 0, "peer close_notify");
            }
            plaintext.clear();
            return Fail(Status::kProtocolError,
                        "SSL_read failed: " + OpensslError());
        }
        return MakeError(Status::kOk, 0, "");
    }

    // ----------------------------------------------------------- peer identity
    Error PeerCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        X509* cert = SSL_get1_peer_certificate(ssl_);
        if (cert == nullptr) return MakeError(Status::kInternal, 0, "no peer cert");
        const int len = i2d_X509(cert, nullptr);
        if (len > 0) {
            out.resize(static_cast<size_t>(len));
            unsigned char* p = out.data();
            i2d_X509(cert, &p);
        }
        X509_free(cert);
        return MakeError(Status::kOk, 0, "");
    }

    Error PeerSubjectPublicKeyInfo(std::vector<uint8_t>& out) const override {
        out.clear();
        X509* cert = SSL_get1_peer_certificate(ssl_);
        if (cert == nullptr) return MakeError(Status::kInternal, 0, "no peer cert");
        X509_PUBKEY* pk = X509_get_X509_PUBKEY(cert);
        if (pk != nullptr) {
            const int len = i2d_X509_PUBKEY(pk, nullptr);
            if (len > 0) {
                out.resize(static_cast<size_t>(len));
                unsigned char* p = out.data();
                i2d_X509_PUBKEY(pk, &p);
            }
        }
        X509_free(cert);
        return MakeError(Status::kOk, 0, "");
    }

    Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {
        // The BIT STRING content of the SPKI, exactly what CredSSP pubKeyAuth
        // needs. Derived by parsing the SPKI DER (no deprecated RSA API).
        out.clear();
        std::vector<uint8_t> spki;
        if (!PeerSubjectPublicKeyInfo(spki).ok()) {
            return MakeError(Status::kInternal, 0, "no peer SPKI");
        }
        out = ExtractSpkiBitString(spki);
        if (out.empty()) {
            return MakeError(Status::kInternal, 0, "cannot extract SubjectPublicKey");
        }
        return MakeError(Status::kOk, 0, "");
    }

    // The OpenSSL backend has no server-role certificate wiring yet (the
    // in-tree RDP server uses the SChannel backend). These return kUnsupported
    // instead of fabricating an identity the handshake never produced.
    Error LocalCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        return MakeError(Status::kUnsupported, 0, "server role is not wired");
    }

    Error LocalSubjectPublicKey(std::vector<uint8_t>& out) const override {
        out.clear();
        return MakeError(Status::kUnsupported, 0, "server role is not wired");
    }

    // ------------------------------------------------------------ parameters
    Error negotiated(NegotiatedInfo& out) const override {
        out = NegotiatedInfo{};
        if (ssl_ == nullptr) return MakeError(Status::kInternal, 0, "no SSL");
        const char* v = SSL_get_version(ssl_);
        if (v != nullptr && std::strcmp(v, "TLSv1.3") == 0) {
            out.tls_version = 0x0304;
        } else if (v != nullptr && std::strcmp(v, "TLSv1.2") == 0) {
            out.tls_version = 0x0303;
        }
        const SSL_CIPHER* c = SSL_get_current_cipher(ssl_);
        if (c != nullptr) {
            out.cipher_suite = static_cast<uint16_t>(
                SSL_CIPHER_get_id(c) & 0xFFFF);
            const char* name = SSL_CIPHER_get_name(c);
            if (name != nullptr) {
                std::strncpy(out.cipher_suite_name, name,
                             sizeof(out.cipher_suite_name) - 1);
            }
        }
        return MakeError(Status::kOk, 0, "");
    }

    RecordSizes record_sizes() const override {
        RecordSizes s;
        s.max_plaintext = kMaxPlaintext;
        s.block_size = 16;
        const bool tls13 = tls_version_ == 0x0304;
        s.header = tls13 ? 5 : 13;
        s.overhead_upper = tls13 ? 44 : 16;
        s.overhead_actual = tls13 ? 17 : 16;
        return s;
    }

    // --------------------------------------------------------------- shutdown
    Error Shutdown(std::vector<uint8_t>& out) override {
        out.clear();
        if (terminal_) return last_error_;
        if (ssl_ == nullptr) return MakeError(Status::kOk, 0, "");
        SSL_shutdown(ssl_);
        DrainOut(out);
        closed_ = true;
        return MakeError(Status::kOk, 0, "");
    }

    // ------------------------------------------------------------------ state
    bool handshake_complete() const noexcept override {
        return handshake_complete_;
    }
    bool closed() const noexcept override { return closed_; }
    size_t buffered_input() const noexcept override {
        return rbio_ != nullptr ? BIO_ctrl_pending(rbio_) : 0;
    }
    const Error& last_error() const noexcept override { return last_error_; }
    const char* backend_name() const noexcept override { return "openssl"; }

 private:
    Error MakeError(Status status, int32_t native, const char* msg) const {
        last_error_ = Error{};
        last_error_.status = status;
        last_error_.native_code = native;
        last_error_.message = msg;
        return last_error_;
    }

    Error Fail(Status status, const std::string& msg) const {
        last_error_ = Error{};
        last_error_.status = status;
        last_error_.native_code = static_cast<int32_t>(ERR_get_error());
        last_error_.message = msg;
        if (status != Status::kOk && status != Status::kNeedMoreInput &&
            status != Status::kClosed) {
            terminal_ = true;
        }
        return last_error_;
    }

    void DrainOut(std::vector<uint8_t>& out) {
        for (;;) {
            const size_t pending = BIO_ctrl_pending(wbio_);
            if (pending == 0) break;
            const size_t old = out.size();
            out.resize(old + pending);
            const int n = BIO_read(wbio_, out.data() + old,
                                   static_cast<int>(pending));
            if (n <= 0) {
                out.resize(old);
                break;
            }
            out.resize(old + static_cast<size_t>(n));
        }
    }

    // After a successful handshake: record the version, apply the TOFU pin.
    bool PostHandshakeChecks() {
        const char* v = SSL_get_version(ssl_);
        tls_version_ = (v != nullptr && std::strcmp(v, "TLSv1.3") == 0) ? 0x0304
                                                                      : 0x0303;
        if (config_.min_version != 0 && tls_version_ < config_.min_version) {
            Fail(Status::kProtocolError, "negotiated version below the minimum");
            return false;
        }
        if (config_.max_version != 0 && tls_version_ > config_.max_version) {
            Fail(Status::kProtocolError, "negotiated version above the maximum");
            return false;
        }
        if (config_.cert_policy == CertPolicy::kTofu && config_.pin_is_set) {
            std::vector<uint8_t> spki;
            if (!PeerSubjectPublicKeyInfo(spki).ok()) {
                Fail(Status::kCertRejected, "cannot read the peer SPKI");
                return false;
            }
            uint8_t digest[32];
            unsigned int dlen = 0;
            if (EVP_Digest(spki.data(), spki.size(), digest, &dlen, EVP_sha256(),
                           nullptr) != 1 ||
                dlen != 32) {
                Fail(Status::kInternal, "SHA-256 failed");
                return false;
            }
            if (std::memcmp(digest, config_.pinned_spki_sha256.data(), 32) != 0) {
                Fail(Status::kCertRejected, "SPKI pin mismatch");
                return false;
            }
        }
        return true;
    }

    Config config_;
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    BIO* rbio_ = nullptr;
    BIO* wbio_ = nullptr;
    bool handshake_complete_ = false;
    bool closed_ = false;
    mutable bool terminal_ = false;
    uint16_t tls_version_ = 0;
    mutable Error last_error_{};
};

}  // namespace

std::unique_ptr<TlsTransport> CreateOpensslTransport(const Config& config,
                                                     std::string& why) {
    auto t = std::make_unique<OpensslTransport>(config);
    if (!t->Start(why)) return nullptr;
    return t;
}

}  // namespace rtsc::tls

#endif  // !_WIN32
