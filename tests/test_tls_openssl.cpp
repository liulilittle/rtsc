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
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

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

    ~Server() {
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
    }

    bool Start() {
        if (!MakeSelfSigned(cert)) return false;
        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) return false;
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
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

int main() { return ::rtsc::test::run_all("rtsc_tls_openssl_tests"); }

#endif  // !_WIN32
