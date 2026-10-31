// OpenSSL TLS backend: in-process loopback.
//
// Built only on non-Windows when RTSC_TLS_OPENSSL=ON. The server is a raw
// OpenSSL SSL object driven through memory BIOs; the client is the product
// TlsTransport. Bytes are shuttled between them until the handshake completes,
// then application data is exchanged both ways.

#include "rtsc/net/tls.h"

#if !defined(_WIN32)

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::tls;

namespace {

// A self-signed RSA certificate for the loopback server.
struct TestCert {
    EVP_PKEY* key = nullptr;
    X509* cert = nullptr;
    ~TestCert() {
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
    }
};

bool MakeSelfSigned(TestCert& out) {
    out.key = EVP_RSA_gen(2048);
    if (!out.key) return false;
    out.cert = X509_new();
    if (!out.cert) return false;

    X509_set_version(out.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(out.cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(out.cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(out.cert), 60 * 60);
    X509_set_pubkey(out.cert, out.key);

    X509_NAME* name = X509_get_subject_name(out.cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"),
                               -1, -1, 0);
    X509_set_issuer_name(out.cert, name);
    return X509_sign(out.cert, out.key, EVP_sha256()) != 0;
}

// The loopback server: a raw SSL with memory BIOs.
struct Server {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    BIO* rbio = nullptr;
    BIO* wbio = nullptr;
    TestCert cert;
    bool borrowed = false;

    ~Server() {
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
        // A borrowed certificate belongs to the caller; do not free it twice.
        if (borrowed) {
            cert.key = nullptr;
            cert.cert = nullptr;
        }
    }

    // `shared` lets several handshakes present the SAME certificate, which the
    // pin tests need: MakeSelfSigned mints a fresh key on every call, so a pin
    // computed from one server would never match another. `force_tls12` caps the
    // negotiated version so a caller can exercise the TLS 1.2 record path (the
    // coalesced-handshake test depends on a server being able to write its
    // first application record in the same flight as its last handshake bytes).
    bool Start(TestCert* shared = nullptr, bool force_tls12 = false) {
        if (shared != nullptr) {
            cert.key = shared->key;
            cert.cert = shared->cert;
            borrowed = true;
        } else if (!MakeSelfSigned(cert)) {
            return false;
        }
        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) return false;
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        if (force_tls12) SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
        if (SSL_CTX_use_certificate(ctx, cert.cert) != 1) return false;
        if (SSL_CTX_use_PrivateKey(ctx, cert.key) != 1) return false;
        ssl = SSL_new(ctx);
        if (!ssl) return false;
        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());
        if (!rbio || !wbio) return false;
        SSL_set_bio(ssl, rbio, wbio);
        SSL_set_accept_state(ssl);
        return true;
    }

    void Feed(const std::vector<uint8_t>& in) {
        if (!in.empty()) BIO_write(rbio, in.data(), static_cast<int>(in.size()));
    }

    std::vector<uint8_t> Drain() {
        std::vector<uint8_t> out;
        for (;;) {
            const size_t pending = BIO_ctrl_pending(wbio);
            if (pending == 0) break;
            const size_t old = out.size();
            out.resize(old + pending);
            const int n = BIO_read(wbio, out.data() + old, static_cast<int>(pending));
            if (n <= 0) { out.resize(old); break; }
            out.resize(old + static_cast<size_t>(n));
        }
        return out;
    }
};

// A bare OpenSSL client used as the peer when the PRODUCT transport plays the
// server role. VERIFY_NONE: the ephemeral/self-signed server certificate is
// expected, exactly like the in-tree client's kInsecure policy.
struct RawClient {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    BIO* rbio = nullptr;
    BIO* wbio = nullptr;

    ~RawClient() {
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
    }

    bool Start() {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return false;
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        ssl = SSL_new(ctx);
        if (!ssl) return false;
        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());
        if (!rbio || !wbio) return false;
        SSL_set_bio(ssl, rbio, wbio);
        SSL_set_connect_state(ssl);
        return true;
    }

    void Feed(const std::vector<uint8_t>& in) {
        if (!in.empty()) BIO_write(rbio, in.data(), static_cast<int>(in.size()));
    }

    std::vector<uint8_t> Drain() {
        std::vector<uint8_t> out;
        for (;;) {
            const size_t pending = BIO_ctrl_pending(wbio);
            if (pending == 0) break;
            const size_t old = out.size();
            out.resize(old + pending);
            const int n = BIO_read(wbio, out.data() + old, static_cast<int>(pending));
            if (n <= 0) { out.resize(old); break; }
            out.resize(old + static_cast<size_t>(n));
        }
        return out;
    }
};

// Drives a handshake where the PRODUCT transport is the server and `client` is
// a bare OpenSSL client. Shuttles memory-BIO bytes until both sides finish.
bool DriveServerHandshake(TlsTransport& server, RawClient& client) {
    for (int i = 0; i < 40; ++i) {
        const int rc = SSL_do_handshake(client.ssl);
        auto c_out = client.Drain();
        const bool client_done = (rc == 1);

        size_t consumed = 0;
        std::vector<uint8_t> s_out;
        const Error e = server.Handshake(c_out.empty() ? nullptr : c_out.data(),
                                         c_out.size(), consumed, s_out);
        if (!e.ok() && e.status != Status::kNeedMoreInput) return false;
        const bool server_done = server.handshake_complete();

        if (client_done && server_done && c_out.empty() && s_out.empty()) {
            return true;
        }
        if (!s_out.empty()) client.Feed(s_out);
    }
    return server.handshake_complete();
}

// Drives a handshake between two PRODUCT transports (client vs server).
bool DriveProductHandshake(TlsTransport& client, TlsTransport& server) {
    std::vector<uint8_t> c2s;
    std::vector<uint8_t> s2c;
    for (int i = 0; i < 40; ++i) {
        size_t cc = 0;
        std::vector<uint8_t> c_out;
        const Error ce = client.Handshake(c2s.data(), c2s.size(), cc, c_out);
        if (cc > c2s.size()) return false;
        c2s.erase(c2s.begin(), c2s.begin() + static_cast<std::ptrdiff_t>(cc));
        if (!ce.ok() && ce.status != Status::kNeedMoreInput) return false;
        if (!c_out.empty()) {
            s2c.reserve(s2c.size() + c_out.size());
            for (const uint8_t b : c_out) s2c.push_back(b);
        }

        size_t sc = 0;
        std::vector<uint8_t> s_out;
        const Error se = server.Handshake(s2c.data(), s2c.size(), sc, s_out);
        if (sc > s2c.size()) return false;
        s2c.erase(s2c.begin(), s2c.begin() + static_cast<std::ptrdiff_t>(sc));
        if (!se.ok() && se.status != Status::kNeedMoreInput) return false;
        if (!s_out.empty()) {
            c2s.reserve(c2s.size() + s_out.size());
            for (const uint8_t b : s_out) c2s.push_back(b);
        }

        if (client.handshake_complete() && server.handshake_complete()) return true;
    }
    return client.handshake_complete() && server.handshake_complete();
}

bool RawPeerSubjectPublicKey(SSL* ssl, std::vector<uint8_t>& out) {
    out.clear();
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (cert == nullptr) return false;
    X509_PUBKEY* pub = X509_get_X509_PUBKEY(cert);
    const unsigned char* pk = nullptr;
    int pklen = 0;
    const bool ok = pub != nullptr &&
                    X509_PUBKEY_get0_param(nullptr, &pk, &pklen, nullptr, pub) == 1 &&
                    pk != nullptr && pklen > 0;
    if (ok) out.assign(pk, pk + pklen);
    X509_free(cert);
    return ok;
}

bool RawPeerCertificateDer(SSL* ssl, std::vector<uint8_t>& out) {
    out.clear();
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (cert == nullptr) return false;
    const int len = i2d_X509(cert, nullptr);
    if (len > 0) {
        out.resize(static_cast<size_t>(len));
        unsigned char* p = out.data();
        i2d_X509(cert, &p);
    }
    X509_free(cert);
    return !out.empty();
}

bool WriteCertPem(X509* cert, std::string& out) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) return false;
    const bool ok = PEM_write_bio_X509(bio, cert) == 1;
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (ok && len > 0 && data != nullptr) out.assign(data, static_cast<size_t>(len));
    BIO_free(bio);
    return ok && !out.empty();
}

bool WriteKeyPem(EVP_PKEY* key, std::string& out) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) return false;
    const bool ok = PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0,
                                             nullptr, nullptr) == 1;
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (ok && len > 0 && data != nullptr) out.assign(data, static_cast<size_t>(len));
    BIO_free(bio);
    return ok && !out.empty();
}

// SHA-256 of a certificate's full SPKI, exactly what the TOFU pin compares.
bool CertSpkiDigest(X509* cert, std::array<uint8_t, 32>& digest) {
    X509_PUBKEY* pub = X509_get_X509_PUBKEY(cert);
    if (pub == nullptr) return false;
    const int len = i2d_X509_PUBKEY(pub, nullptr);
    if (len <= 0) return false;
    std::vector<uint8_t> spki(static_cast<size_t>(len));
    unsigned char* p = spki.data();
    i2d_X509_PUBKEY(pub, &p);
    unsigned int dlen = 0;
    return EVP_Digest(spki.data(), spki.size(), digest.data(), &dlen,
                      EVP_sha256(), nullptr) == 1 &&
           dlen == digest.size();
}

// A server-role product config: the loopback raw client does not validate the
// certificate, so kInsecure is fine.
Config MakeServerConfig() {
    Config c;
    c.role = Role::kServer;
    c.cert_policy = CertPolicy::kInsecure;
    return c;
}

// Drives the client and server handshakes until both finish (or a step limit).
bool DriveHandshake(TlsTransport& client, Server& server) {
    const uint8_t dummy = 0;
    for (int i = 0; i < 40; ++i) {
        // Server -> client.
        const int sr = SSL_do_handshake(server.ssl);
        auto s_out = server.Drain();
        if (sr == 1 && s_out.empty()) break;

        size_t consumed = 0;
        std::vector<uint8_t> c_out;
        const Error e = client.Handshake(s_out.empty() ? nullptr : s_out.data(),
                                         s_out.size(), consumed, c_out);
        if (!e.ok() && e.status != Status::kNeedMoreInput) return false;

        // Client -> server.
        if (!c_out.empty()) server.Feed(c_out);

        const int cerr = SSL_get_error(server.ssl, sr);
        if (client.handshake_complete() && cerr == SSL_ERROR_WANT_READ &&
            c_out.empty()) {
            break;
        }
        (void)dummy;
    }
    return client.handshake_complete();
}

Config MakeClientConfig() {
    Config c;
    c.peer_host = "localhost";
    c.cert_policy = CertPolicy::kInsecure;  // self-signed loopback
    return c;
}

}  // namespace

RTSC_TEST(openssl_backend_is_available) {
    const auto backends = EnumerateTlsBackends();
    bool found = false;
    for (const auto& b : backends) {
        if (std::string(b.name) == "openssl" && b.available) found = true;
    }
    CHECK(found);
}

RTSC_TEST(openssl_handshake_and_data_round_trip) {
    Server server;
    CHECK(server.Start());

    std::string why;
    auto client = CreateTlsTransport("openssl", MakeClientConfig(), why);
    CHECK(client != nullptr);
    if (!client) return;

    CHECK(DriveHandshake(*client, server));
    CHECK(client->handshake_complete());
    CHECK(client->last_error().ok());

    NegotiatedInfo info;
    CHECK(client->negotiated(info).ok());
    CHECK(info.tls_version == 0x0303 || info.tls_version == 0x0304);
    CHECK(info.cipher_suite != 0);

    // Peer certificate must be readable.
    std::vector<uint8_t> der;
    CHECK(client->PeerCertificateDer(der).ok());
    CHECK(!der.empty());

    // Application data: client -> server.
    const std::vector<uint8_t> msg = {'h', 'i'};
    size_t consumed = 0;
    std::vector<uint8_t> wire;
    CHECK(client->Send(msg.data(), msg.size(), consumed, wire).ok());
    CHECK_EQ(consumed, msg.size());
    CHECK(!wire.empty());
    server.Feed(wire);

    uint8_t rbuf[64];
    const int n = SSL_read(server.ssl, rbuf, sizeof(rbuf));
    CHECK_EQ(n, static_cast<int>(msg.size()));
    CHECK(std::memcmp(rbuf, msg.data(), msg.size()) == 0);
}

RTSC_TEST(openssl_peer_subject_public_key_matches_spki) {
    Server server;
    CHECK(server.Start());
    std::string why;
    auto client = CreateTlsTransport("openssl", MakeClientConfig(), why);
    CHECK(client != nullptr);
    if (!client) return;
    CHECK(DriveHandshake(*client, server));

    std::vector<uint8_t> spki;
    std::vector<uint8_t> spk;
    CHECK(client->PeerSubjectPublicKeyInfo(spki).ok());
    CHECK(client->PeerSubjectPublicKey(spk).ok());
    CHECK(!spki.empty());
    CHECK(!spk.empty());
    // The SubjectPublicKey must be a suffix of the SPKI (the BIT STRING content).
    CHECK(spki.size() > spk.size());
    CHECK(std::memcmp(spki.data() + (spki.size() - spk.size()), spk.data(),
                      spk.size()) == 0);
}

RTSC_TEST(openssl_no_backend_when_disabled_by_name) {
    std::string why;
    auto t = CreateTlsTransport("bogus", MakeClientConfig(), why);
    CHECK(t == nullptr);
    CHECK(!why.empty());
}

// ---------------------------------------------------------------------------
// Certificate policy. The loopback server always presents a self-signed
// certificate for "localhost", so kStrict (chain validation) must reject it
// and kTofu must accept it only when the pin matches.
// ---------------------------------------------------------------------------

namespace {

// Runs a loopback handshake with `cfg` against `shared`. Returns true when the
// client reports handshake_complete(); a rejecting policy must return false.
bool HandshakeWithPolicy(const Config& cfg, TestCert& shared,
                         Status& rejected_with) {
    Server server;
    if (!server.Start(&shared)) return false;
    std::string why;
    auto client = CreateTlsTransport("openssl", cfg, why);
    if (!client) return false;
    const bool done = DriveHandshake(*client, server);
    rejected_with = client->last_error().status;
    return done;
}

// SHA-256 of the peer SPKI from `shared`, exactly as the pin compares it.
bool SpkiDigest(TestCert& shared, std::array<uint8_t, 32>& digest) {
    Server server;
    if (!server.Start(&shared)) return false;
    std::string why;
    auto client = CreateTlsTransport("openssl", MakeClientConfig(), why);
    if (!client) return false;
    if (!DriveHandshake(*client, server)) return false;
    std::vector<uint8_t> spki;
    if (!client->PeerSubjectPublicKeyInfo(spki).ok() || spki.empty()) {
        return false;
    }
    unsigned int len = 0;
    return EVP_Digest(spki.data(), spki.size(), digest.data(), &len,
                      EVP_sha256(), nullptr) == 1 &&
           len == digest.size();
}

}  // namespace

RTSC_TEST(openssl_kinsecure_accepts_self_signed) {
    TestCert shared;
    CHECK(MakeSelfSigned(shared));
    Status rejected = Status::kOk;
    CHECK(HandshakeWithPolicy(MakeClientConfig(), shared, rejected));
    CHECK(rejected == Status::kOk);
}

RTSC_TEST(openssl_kstrict_rejects_self_signed_peer) {
    TestCert shared;
    CHECK(MakeSelfSigned(shared));
    Config c;
    c.peer_host = "localhost";
    c.cert_policy = CertPolicy::kStrict;
    Status rejected = Status::kOk;
    const bool done = HandshakeWithPolicy(c, shared, rejected);
    CHECK(!done);
    CHECK(rejected == Status::kCertRejected);
}

RTSC_TEST(openssl_ktofu_without_pin_rejects_untrusted_chain) {
    // Mirrors the SChannel semantics: kTofu without a pin still verifies the
    // chain, so a self-signed peer is rejected.
    TestCert shared;
    CHECK(MakeSelfSigned(shared));
    Config c;
    c.peer_host = "localhost";
    c.cert_policy = CertPolicy::kTofu;
    Status rejected = Status::kOk;
    const bool done = HandshakeWithPolicy(c, shared, rejected);
    CHECK(!done);
    CHECK(rejected == Status::kCertRejected);
}

RTSC_TEST(openssl_ktofu_pin_match_accepts_self_signed) {
    TestCert shared;
    CHECK(MakeSelfSigned(shared));
    std::array<uint8_t, 32> digest{};
    CHECK(SpkiDigest(shared, digest));

    Config c;
    c.peer_host = "localhost";
    c.cert_policy = CertPolicy::kTofu;
    c.pinned_spki_sha256 = digest;
    c.pin_is_set = true;
    Status rejected = Status::kOk;
    CHECK(HandshakeWithPolicy(c, shared, rejected));
}

RTSC_TEST(openssl_ktofu_pin_mismatch_is_rejected) {
    TestCert shared;
    CHECK(MakeSelfSigned(shared));
    std::array<uint8_t, 32> digest{};
    CHECK(SpkiDigest(shared, digest));
    digest[0] ^= 0xFF;  // corrupt one byte

    Config c;
    c.peer_host = "localhost";
    c.cert_policy = CertPolicy::kTofu;
    c.pinned_spki_sha256 = digest;
    c.pin_is_set = true;
    Status rejected = Status::kOk;
    const bool done = HandshakeWithPolicy(c, shared, rejected);
    CHECK(!done);
    CHECK(rejected == Status::kCertRejected);
}

// ---------------------------------------------------------------------------
// Server role. The product transport accepts a real TLS client (raw OpenSSL),
// exposes its local identity, and stays stable across Start calls / identity
// sources (A2 ephemeral default vs B injected PEM).
// ---------------------------------------------------------------------------

RTSC_TEST(openssl_server_role_reverse_loopback) {
    // The product plays kServer against a bare TLS 1.3 client.
    std::string why;
    auto server = CreateTlsTransport("openssl", MakeServerConfig(), why);
    CHECK(server != nullptr);
    if (!server) return;
    RawClient client;
    CHECK(client.Start());

    CHECK(DriveServerHandshake(*server, client));
    CHECK(server->handshake_complete());
    CHECK(server->last_error().ok());

    NegotiatedInfo info;
    CHECK(server->negotiated(info).ok());
    CHECK(info.tls_version == 0x0303 || info.tls_version == 0x0304);
    CHECK(info.cipher_suite != 0);

    // Application data: client -> server.
    const std::vector<uint8_t> msg = {'h', 'i'};
    CHECK_EQ(SSL_write(client.ssl, msg.data(), static_cast<int>(msg.size())),
             static_cast<int>(msg.size()));
    auto wire = client.Drain();
    CHECK(!wire.empty());
    std::vector<uint8_t> plain;
    CHECK(server->Receive(wire.data(), wire.size(), plain, 0).ok());
    CHECK(plain.size() == msg.size());
    CHECK(std::memcmp(plain.data(), msg.data(), msg.size()) == 0);

    // Application data: server -> client.
    const std::vector<uint8_t> pong = {'p', 'o', 'n', 'g'};
    size_t consumed = 0;
    std::vector<uint8_t> s_wire;
    CHECK(server->Send(pong.data(), pong.size(), consumed, s_wire).ok());
    CHECK_EQ(consumed, pong.size());
    CHECK(!s_wire.empty());
    client.Feed(s_wire);
    uint8_t rbuf[64];
    const int n = SSL_read(client.ssl, rbuf, sizeof(rbuf));
    CHECK_EQ(n, static_cast<int>(pong.size()));
    CHECK(std::memcmp(rbuf, pong.data(), pong.size()) == 0);

    // Shutdown closes politely.
    std::vector<uint8_t> sd;
    CHECK(server->Shutdown(sd).ok());
}

RTSC_TEST(openssl_coalesced_final_flight_plus_first_record) {
    // D1 lock: when the peer coalesces its LAST handshake flight with its FIRST
    // application record into one buffer, Handshake must report consumed ==
    // in_size. OpenSSL owns every byte once BIO_write staged it; reporting less
    // leaves the app record in the caller's pending buffer AND in the read BIO,
    // so a later Receive replays the same record -> identical TLS sequence
    // number -> AES-GCM nonce reuse -> SSL_ERROR_SSL fatal.
    //
    // TLS 1.2 is required: only then can the (bare) server write application
    // data immediately after its Finished without waiting for a client flight.
    Server server;
    CHECK(server.Start(nullptr, /*force_tls12=*/true));

    Config c = MakeClientConfig();
    c.max_version = 0x0303;  // lock both ends onto TLS 1.2
    std::string why;
    auto client = CreateTlsTransport("openssl", c, why);
    CHECK(client != nullptr);
    if (!client) return;

    // Pump the TLS 1.2 handshake until the server has completed its side and
    // produced ITS Finished, which the client has not seen yet.
    std::vector<uint8_t> coalesced;
    const uint8_t kApp[] = {'h', 'i'};
    for (int i = 0; i < 40; ++i) {
        const int sr = SSL_do_handshake(server.ssl);
        auto s_out = server.Drain();
        if (sr == 1 && !s_out.empty()) {
            // Server handshake done: s_out is its final flight (Finished).
            // Append a first application record to the SAME buffer.
            if (SSL_write(server.ssl, kApp, sizeof(kApp)) !=
                static_cast<int>(sizeof(kApp))) {
                CHECK(false);
                return;
            }
            auto extra = server.Drain();
            s_out.reserve(s_out.size() + extra.size());
            for (const uint8_t b : extra) s_out.push_back(b);
            coalesced = std::move(s_out);
            break;
        }
        size_t consumed = 0;
        std::vector<uint8_t> c_out;
        const Error e = client->Handshake(s_out.empty() ? nullptr : s_out.data(),
                                          s_out.size(), consumed, c_out);
        if (!e.ok() && e.status != Status::kNeedMoreInput) {
            CHECK(false);
            return;
        }
        if (!c_out.empty()) server.Feed(c_out);
    }
    CHECK(!coalesced.empty());
    if (coalesced.empty()) return;

    // The one Handshake call must absorb the whole coalesced buffer.
    size_t consumed = 0;
    std::vector<uint8_t> handshake_out;
    const Error e = client->Handshake(coalesced.data(), coalesced.size(), consumed,
                                      handshake_out);
    CHECK(e.ok());
    CHECK(client->handshake_complete());
    CHECK_EQ(consumed, coalesced.size());  // D1: red before the fix

    // Whatever the caller would have re-fed must be replayed onto a now-empty
    // leftover: with the fix `consumed == in_size` leaves nothing, so this is
    // a pure drain of the record already staged inside OpenSSL.
    std::vector<uint8_t> leftover(coalesced.begin() +
                                      static_cast<std::ptrdiff_t>(consumed),
                                  coalesced.end());
    std::vector<uint8_t> plain;
    const Error r =
        client->Receive(leftover.empty() ? nullptr : leftover.data(),
                        leftover.size(), plain, 0);
    CHECK(r.ok() && r.status != Status::kProtocolError);
    CHECK(plain.size() == sizeof(kApp));
    CHECK(std::memcmp(plain.data(), kApp, sizeof(kApp)) == 0);
    CHECK(client->buffered_input() == 0);
}

RTSC_TEST(openssl_server_coalesced_final_flight_plus_first_record) {
    // Server-role mirror of the D1 lock: a bare TLS client coalesces its FINAL
    // flight (Finished) with its FIRST application record into one buffer. The
    // product server's Handshake must absorb the whole buffer (consumed ==
    // in_size) and leave the app record drainable from the backend, so the
    // security layer's buffered_input() drain has something to lift out.
    std::string why;
    auto server = CreateTlsTransport("openssl", MakeServerConfig(), why);
    CHECK(server != nullptr);
    if (!server) return;

    RawClient client;
    CHECK(client.Start());

    const std::vector<uint8_t> msg = {'N', 'E', 'G', 'O', 'T', 'I', 'A', 'T',
                                      'E'};
    std::vector<uint8_t> coalesced;
    for (int i = 0; i < 40; ++i) {
        const int rc = SSL_do_handshake(client.ssl);
        auto c_out = client.Drain();
        if (rc == 1) {
            // Client Finished is in c_out; append the FIRST application record.
            if (SSL_write(client.ssl, msg.data(),
                          static_cast<int>(msg.size())) !=
                static_cast<int>(msg.size())) {
                CHECK(false);
                break;
            }
            auto extra = client.Drain();
            for (const uint8_t b : extra) c_out.push_back(b);
            coalesced = std::move(c_out);
            break;
        }
        size_t consumed = 0;
        std::vector<uint8_t> s_out;
        const Error e = server->Handshake(c_out.empty() ? nullptr : c_out.data(),
                                          c_out.size(), consumed, s_out);
        CHECK(e.ok() || e.status == Status::kNeedMoreInput);
        if (!s_out.empty()) client.Feed(s_out);
    }
    CHECK(!coalesced.empty());
    if (coalesced.empty()) return;

    size_t consumed = 0;
    std::vector<uint8_t> hs_out;
    const Error e =
        server->Handshake(coalesced.data(), coalesced.size(), consumed, hs_out);
    CHECK(e.ok());
    CHECK(server->handshake_complete());
    CHECK_EQ(consumed, coalesced.size());  // D1 contract on the server role too

    // The record the security layer must drain: re-feeding any unconsumed tail
    // would replay it into the BIO (identical sequence number -> GCM nonce
    // reuse); with consumed == in_size there is nothing to replay and a pure
    // drain retrieves the plaintext.
    std::vector<uint8_t> leftover(coalesced.begin() +
                                      static_cast<std::ptrdiff_t>(consumed),
                                  coalesced.end());
    std::vector<uint8_t> plain;
    const Error r =
        server->Receive(leftover.empty() ? nullptr : leftover.data(),
                        leftover.size(), plain, 0);
    CHECK(r.ok() && r.status != Status::kProtocolError);
    CHECK(plain.size() == msg.size());
    CHECK(std::memcmp(plain.data(), msg.data(), msg.size()) == 0);
    CHECK(server->buffered_input() == 0);
}

RTSC_TEST(openssl_server_local_identity_matches_peer) {
    // The product server's LocalSubjectPublicKey must be byte-identical to what
    // a real (bare OpenSSL) client extracts from the presented certificate, and
    // LocalCertificateDer must be a self-consistent DER blob.
    std::string why;
    auto server = CreateTlsTransport("openssl", MakeServerConfig(), why);
    CHECK(server != nullptr);
    if (!server) return;
    RawClient client;
    CHECK(client.Start());
    CHECK(DriveServerHandshake(*server, client));

    std::vector<uint8_t> local_spk, peer_spk;
    CHECK(server->LocalSubjectPublicKey(local_spk).ok());
    CHECK(RawPeerSubjectPublicKey(client.ssl, peer_spk));
    CHECK(!local_spk.empty());
    // RSA-2048 BIT STRING content is exactly 270 bytes starting with 30 82.
    CHECK_EQ(local_spk.size(), 270u);
    CHECK_EQ(local_spk[0], 0x30);
    CHECK_EQ(local_spk[1], 0x82);
    CHECK(local_spk == peer_spk);

    std::vector<uint8_t> local_der, peer_der;
    CHECK(server->LocalCertificateDer(local_der).ok());
    CHECK(!local_der.empty());
    // Must be re-parseable as X509.
    const unsigned char* p = local_der.data();
    X509* decoded = d2i_X509(nullptr, &p, static_cast<long>(local_der.size()));
    CHECK(decoded != nullptr);
    if (decoded) X509_free(decoded);
    // And must be exactly the certificate the raw client saw.
    CHECK(RawPeerCertificateDer(client.ssl, peer_der));
    CHECK(local_der == peer_der);
}

RTSC_TEST(openssl_server_a2_identity_stable_across_starts) {
    // A2: the process-level ephemeral identity must not change between Start
    // calls, so kTofu + pin keeps working for repeated connections.
    std::string why;
    std::vector<uint8_t> spk1, spk2, der1, der2;
    {
        auto s1 = CreateTlsTransport("openssl", MakeServerConfig(), why);
        CHECK(s1 != nullptr);
        if (!s1) return;
        CHECK(s1->LocalSubjectPublicKey(spk1).ok());
        CHECK(s1->LocalCertificateDer(der1).ok());
    }
    {
        auto s2 = CreateTlsTransport("openssl", MakeServerConfig(), why);
        CHECK(s2 != nullptr);
        CHECK(s2->LocalSubjectPublicKey(spk2).ok());
        CHECK(s2->LocalCertificateDer(der2).ok());
    }
    CHECK(!spk1.empty());
    CHECK(spk1 == spk2);
    CHECK(der1 == der2);
}

RTSC_TEST(openssl_server_b_injected_identity_replaces_ephemeral) {
    // B: PEM-encodized identity injected through Config. Two Start calls must
    // present the SAME certificate, kTofu + pin must accept it on two separate
    // connections, and a mismatched private key must be refused at Start.
    TestCert shared;
    CHECK(MakeSelfSigned(shared));
    std::string cert_pem, key_pem;
    CHECK(WriteCertPem(shared.cert, cert_pem));
    CHECK(WriteKeyPem(shared.key, key_pem));

    Config c = MakeServerConfig();
    c.server_certificate_pem = cert_pem;
    c.server_private_key_pem = key_pem;

    std::string why;
    auto s1 = CreateTlsTransport("openssl", c, why);
    CHECK(s1 != nullptr);
    if (!s1) return;
    std::vector<uint8_t> spk1, der1;
    CHECK(s1->LocalSubjectPublicKey(spk1).ok());
    CHECK(s1->LocalCertificateDer(der1).ok());

    auto s2 = CreateTlsTransport("openssl", c, why);
    CHECK(s2 != nullptr);
    std::vector<uint8_t> spk2, der2;
    CHECK(s2->LocalSubjectPublicKey(spk2).ok());
    CHECK(s2->LocalCertificateDer(der2).ok());
    CHECK(spk1 == spk2);
    CHECK(der1 == der2);

    // kTofu + pin: the pin is derived from the injected certificate's SPKI and
    // must match on two independent connections (parse reproducibility).
    std::array<uint8_t, 32> digest{};
    CHECK(CertSpkiDigest(shared.cert, digest));
    Config cc;
    cc.peer_host = "localhost";
    cc.cert_policy = CertPolicy::kTofu;
    cc.pinned_spki_sha256 = digest;
    cc.pin_is_set = true;
    {
        auto c1 = CreateTlsTransport("openssl", cc, why);
        CHECK(c1 != nullptr);
        CHECK(DriveProductHandshake(*c1, *s1));
    }
    {
        auto c2 = CreateTlsTransport("openssl", cc, why);
        CHECK(c2 != nullptr);
        CHECK(DriveProductHandshake(*c2, *s2));
    }

    // Mismatched private key: refused at Start, not at handshake time.
    TestCert wrong;
    CHECK(MakeSelfSigned(wrong));
    std::string wrong_key_pem;
    CHECK(WriteKeyPem(wrong.key, wrong_key_pem));
    Config bad = MakeServerConfig();
    bad.server_certificate_pem = cert_pem;
    bad.server_private_key_pem = wrong_key_pem;
    std::string bad_why;
    auto ts = CreateTlsTransport("openssl", bad, bad_why);
    CHECK(ts == nullptr);
    CHECK(!bad_why.empty());
}

RTSC_TEST(openssl_client_role_local_identity_is_protocol_error) {
    // Client role never has a local certificate: Local* reports the same
    // "handshake not complete" protocol error SChannel's NotHandshaken does,
    // both before and after the handshake.
    Server server;
    CHECK(server.Start());
    std::string why;
    auto client = CreateTlsTransport("openssl", MakeClientConfig(), why);
    CHECK(client != nullptr);
    if (!client) return;

    std::vector<uint8_t> der, spk;
    CHECK(client->LocalCertificateDer(der).status == Status::kProtocolError);
    CHECK(client->LocalSubjectPublicKey(spk).status == Status::kProtocolError);

    CHECK(DriveHandshake(*client, server));
    CHECK(client->LocalCertificateDer(der).status == Status::kProtocolError);
    CHECK(client->LocalSubjectPublicKey(spk).status == Status::kProtocolError);
}

int main() { return ::rtsc::test::run_all("rtsc_tls_openssl_tests"); }

#endif  // !_WIN32
