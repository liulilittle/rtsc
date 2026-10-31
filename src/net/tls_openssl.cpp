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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <climits>
#include <cstring>
#include <memory>
#include <mutex>
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

// ---------------------------------------------------------------------------
// A2: the server's default identity is a process-level ephemeral RSA-2048
// self-signed certificate (CN=rtsc-rdp-server), mirroring the SChannel backend
// which mints one with CertCreateSelfSignCertificate per process start. The
// certificate AND the private key are cached as raw DER only; no X509* /
// EVP_PKEY* lives past the generation scope, so static destruction order can
// never touch a freed key. Each Start reparses the DER with d2i_X509 /
// d2i_AutoPrivateKey and releases the fresh objects right after installing
// them, which sidesteps CONFIG destructor-order hazards entirely.
//
// The STABLE SPKI is the point of A2: for a kTofu + pin client the pin IS the
// identity, and a per-process stable key means a pin learned from the first
// connection keeps matching every later one.
// ---------------------------------------------------------------------------

struct EphemeralIdentity {
    std::vector<uint8_t> cert_der;
    std::vector<uint8_t> key_der;
};

std::once_flag g_ephemeral_once;
std::mutex g_ephemeral_mutex;
EphemeralIdentity g_ephemeral;

void BuildEphemeralIdentity(EphemeralIdentity& out) {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    X509* cert = X509_new();
    if (key == nullptr || cert == nullptr) {
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
        return;
    }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 10 * 365 * 24 * 3600);
    X509_set_pubkey(cert, key);
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("rtsc-rdp-server"), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    if (X509_sign(cert, key, EVP_sha256()) == 0) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return;
    }
    const int cert_len = i2d_X509(cert, nullptr);
    if (cert_len > 0) {
        out.cert_der.resize(static_cast<size_t>(cert_len));
        unsigned char* p = out.cert_der.data();
        i2d_X509(cert, &p);
    }
    const int key_len = i2d_PrivateKey(key, nullptr);
    if (key_len > 0) {
        out.key_der.resize(static_cast<size_t>(key_len));
        unsigned char* p = out.key_der.data();
        i2d_PrivateKey(key, &p);
    }
    X509_free(cert);
    EVP_PKEY_free(key);
}

const EphemeralIdentity& GetEphemeralIdentity() {
    // The mutex also guards concurrent Start calls while the once-flag's single
    // generation pass swaps the static buffers in.
    std::lock_guard<std::mutex> lock(g_ephemeral_mutex);
    std::call_once(g_ephemeral_once, [] { BuildEphemeralIdentity(g_ephemeral); });
    return g_ephemeral;
}

X509* ParsePemCertificate(const std::string& pem) {
    if (pem.size() > static_cast<size_t>(INT_MAX)) return nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) return nullptr;
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

EVP_PKEY* ParsePemPrivateKey(const std::string& pem) {
    if (pem.size() > static_cast<size_t>(INT_MAX)) return nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) return nullptr;
    // A cipher-armed PEM needs a callback; passing nullptr rejects it, which is
    // what the Config documents ("encrypted keys are rejected at Start").
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
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
        const bool server = config_.role == Role::kServer;
        ctx_ = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
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

        if (server) {
            if (!InstallServerIdentity(why)) return false;
            // The server never requests a client certificate (RDP does not use
            // mutual TLS), so the peer half is not validated here.
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        } else {
            switch (config_.cert_policy) {
                case CertPolicy::kInsecure:
                    SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
                    break;
                case CertPolicy::kTofu:
                    // kTofu + pin: the pin IS the identity (SChannel parity); a
                    // chain check here would reject a self-signed gateway before
                    // the pin comparison at PostHandshakeChecks can run. Without
                    // a pin, kTofu keeps verifying the chain (no hostname check).
                    SSL_CTX_set_verify(ctx_,
                                       config_.pin_is_set ? SSL_VERIFY_NONE
                                                          : SSL_VERIFY_PEER,
                                       nullptr);
                    break;
                case CertPolicy::kStrict:
                    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
                    break;
            }
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

        if (server) {
            SSL_set_accept_state(ssl_);
        } else {
            SSL_set_connect_state(ssl_);
            // SNI is a handshake HINT; the reference identifier for hostname
            // verification is the name the user asked to reach (peer_host),
            // exactly like the SChannel backend's VerifyHostname()
            // (tls_schannel.cpp: "peer_host ?: sni"). A gateway reached via a
            // proxy/prefix name must still be verified against the real target.
            const std::string sni =
                config_.sni.empty() ? config_.peer_host : config_.sni;
            if (config_.send_sni && !sni.empty()) {
                SSL_set_tlsext_host_name(ssl_, sni.c_str());
            }
            const std::string verify_name =
                config_.peer_host.empty() ? config_.sni : config_.peer_host;
            if (config_.cert_policy == CertPolicy::kStrict &&
                !verify_name.empty()) {
                SSL_set1_host(ssl_, verify_name.c_str());
            }
            // Known single-side divergence vs SChannel (documented, not a bug):
            // OpenSSL's X509_check_host has no ccSLD table, so it ACCEPTS
            // "*.co.uk" (SChannel rejects it) and it REJECTS trailing-dot FQDN
            // forms (SChannel normalizes them). SChannel is stricter on the
            // wildcard side; see tls_schannel.cpp DnsNameMatches.
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
                // A peer certificate that fails the chain check aborts the
                // handshake here. tls.h requires the failure reason to be
                // reportable, and a caller has to be able to tell "the
                // certificate was rejected" from "the peer misbehaved", so
                // map the verify result before falling back to a generic
                // protocol error.
                const long vr = SSL_get_verify_result(ssl_);
                if (vr != X509_V_OK) {
                    return Fail(Status::kCertRejected,
                                std::string("certificate verify failed: ") +
                                    X509_verify_cert_error_string(vr));
                }
                return Fail(Status::kProtocolError,
                            "handshake failed: " + OpensslError());
            }
        }

        // D1: the whole input is owned by OpenSSL once BIO_write staged it in
        // rbio_. SSL_do_handshake consumes a TLS record byte-for-byte or leaves
        // the entire record to the record layer; it never reports partial
        // record consumption (EXTRA is always 0). Reporting less than in_size
        // would make the caller keep the tail in its pending buffer AND then
        // feed those bytes into Receive, replaying the same record into the BIO
        // twice: identical sequence number -> AES-GCM nonce reuse ->
        // SSL_ERROR_SSL fatal. This mirrors the SChannel backend, whose stream
        // handshake likewise reports consumed = in_size (tls_schannel.cpp).
        // Any residual record is safe: the caller drains it through the
        // existing while (buffered_input() > 0) Receive(nullptr, 0, ...) loop.
        consumed = in_size;
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

    // The OpenSSL backend now wires the server-role certificate (A2 ephemeral
    // default, or a Config-injected PEM pair): local_cert_ is installed during
    // Start, so the identity is available immediately after creation (SChannel
    // parity: its Local* also serve once the server credentials exist, before
    // any handshake). A client-role transport never installs one and reports
    // the same kProtocolError SChannel's NotHandshaken returns.
    Error LocalCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        if (local_cert_ == nullptr) {
            return MakeError(Status::kProtocolError, 0, "handshake not complete");
        }
        const int len = i2d_X509(local_cert_, nullptr);
        if (len <= 0) {
            return MakeError(Status::kInternal, 0, "cannot encode the local certificate");
        }
        out.resize(static_cast<size_t>(len));
        unsigned char* p = out.data();
        i2d_X509(local_cert_, &p);
        return MakeError(Status::kOk, 0, "");
    }

    Error LocalSubjectPublicKey(std::vector<uint8_t>& out) const override {
        out.clear();
        if (local_cert_ == nullptr) {
            return MakeError(Status::kProtocolError, 0, "handshake not complete");
        }
        // Read the BIT STRING content through the X509_PUBKEY API. Never slice
        // the SPKI at a fixed offset: the offset differs between key sizes
        // (measured offset 22 for RSA-1024, 24 for RSA-2048).
        X509_PUBKEY* pub = X509_get_X509_PUBKEY(local_cert_);
        const unsigned char* pk = nullptr;
        int pklen = 0;
        if (pub == nullptr ||
            X509_PUBKEY_get0_param(nullptr, &pk, &pklen, nullptr, pub) != 1 ||
            pk == nullptr || pklen <= 0) {
            return MakeError(Status::kInternal, 0, "cannot read the local key");
        }
        out.assign(pk, pk + pklen);
        return MakeError(Status::kOk, 0, "");
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

// Installs the server-role certificate and private key into ctx_. Source A2
    // (default) is the process-level ephemeral identity; source B (optional)
    // is the Config-injected PEM pair, which must be complete and unencrypted
    // or Start fails. local_cert_ is the ctx-owned leaf certificate (valid as
    // long as ctx_ is alive) that the Local* accessors serve.
    bool InstallServerIdentity(std::string& why) {
        X509* cert = nullptr;
        EVP_PKEY* key = nullptr;
        const bool have_cert = !config_.server_certificate_pem.empty();
        const bool have_key = !config_.server_private_key_pem.empty();
        if (have_cert || have_key) {
            if (!have_cert || !have_key) {
                why = "both server_certificate_pem and server_private_key_pem are required";
                return false;
            }
            cert = ParsePemCertificate(config_.server_certificate_pem);
            if (cert == nullptr) {
                why = "cannot parse server_certificate_pem";
                return false;
            }
            key = ParsePemPrivateKey(config_.server_private_key_pem);
            if (key == nullptr) {
                X509_free(cert);
                why = "cannot parse server_private_key_pem (encrypted keys are rejected)";
                return false;
            }
        } else {
            const EphemeralIdentity& id = GetEphemeralIdentity();
            {
                const unsigned char* p = id.cert_der.data();
                cert = d2i_X509(nullptr, &p,
                                static_cast<long>(id.cert_der.size()));
            }
            {
                const unsigned char* p = id.key_der.data();
                key = d2i_AutoPrivateKey(nullptr, &p,
                                         static_cast<long>(id.key_der.size()));
            }
            if (cert == nullptr || key == nullptr) {
                if (cert) X509_free(cert);
                if (key) EVP_PKEY_free(key);
                why = "cannot reparse the ephemeral server identity";
                return false;
            }
        }

        const bool cert_ok = SSL_CTX_use_certificate(ctx_, cert) == 1;
        const bool key_ok = SSL_CTX_use_PrivateKey(ctx_, key) == 1;
        const bool pair_ok = cert_ok && key_ok &&
                             SSL_CTX_check_private_key(ctx_) == 1;
        X509_free(cert);
        EVP_PKEY_free(key);
        if (!cert_ok) {
            why = "SSL_CTX_use_certificate failed: " + OpensslError();
            return false;
        }
        if (!key_ok) {
            why = "SSL_CTX_use_PrivateKey failed: " + OpensslError();
            return false;
        }
        if (!pair_ok) {
            why = "private key does not match the certificate";
            return false;
        }
        local_cert_ = SSL_CTX_get0_certificate(ctx_);
        return true;
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
        // The pin / chain / hostname checks evaluate the PEER certificate, so
        // they only exist on the client role. A server-role transport never
        // requests or validates a client certificate (SSL_VERIFY_NONE), so
        // running these here would be meaningless.
        if (config_.role != Role::kServer && config_.cert_policy == CertPolicy::kTofu &&
            config_.pin_is_set) {
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
    // Server-role leaf certificate, owned by ctx_ (SSL_CTX_use_certificate
    // bumped the reference); nullptr on the client role, where the Local*
    // accessors report "handshake not complete".
    X509* local_cert_ = nullptr;
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
