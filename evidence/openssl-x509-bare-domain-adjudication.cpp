// Adjudicate: does OpenSSL's X509_check_host accept a bare domain against a
// "*.example.com" SAN? Audit A and B both said yes; the executor said no.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

// Builds a certificate whose SAN contains exactly one dNSName entry.
X509* MakeCert(const char* san) {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    if (!key) return nullptr;
    X509* x = X509_new();
    if (!x) { EVP_PKEY_free(key); return nullptr; }
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(san), -1,
                               -1, 0);
    X509_set_issuer_name(x, name);

    X509V3_CTX ctx{};
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
    std::string ext = "DNS:";
    ext += san;
    X509_EXTENSION* ex =
        X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, ext.c_str());
    if (!ex) { X509_free(x); EVP_PKEY_free(key); return nullptr; }
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);
    X509_sign(x, key, EVP_sha256());
    EVP_PKEY_free(key);
    return x;
}

int Check(const char* san, const char* host) {
    X509* x = MakeCert(san);
    if (!x) return -99;
    const int r = X509_check_host(x, host, std::strlen(host), 0, nullptr);
    X509_free(x);
    return r;
}

}  // namespace

int main() {
    struct Case { const char* san; const char* host; };
    const Case cases[] = {
        {"*.com", "x.com"},
        {"*.co.uk", "x.co.uk"},
        {"*.example.com", "example.com"},        // the disputed one
        {"*.example.com", "a.example.com"},
        {"*.example.com", "a.b.example.com"},
        {"example.com", "example.com."},
        {"example.com", "example.com"},
    };
    std::printf("openssl: %s\n\n", OpenSSL_version(OPENSSL_VERSION));
    for (const Case& c : cases) {
        const int r = Check(c.san, c.host);
        // X509_check_host: 1 = match, 0 = no match, <0 = error.
        const char* verdict = r == 1 ? "MATCH" : (r == 0 ? "no-match" : "error");
        std::printf("SAN %-16s <- host %-18s => %2d (%s)\n", c.san, c.host, r,
                    verdict);
    }
    return 0;
}
