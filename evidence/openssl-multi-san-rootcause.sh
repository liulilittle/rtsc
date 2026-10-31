#!/bin/bash
# Verify audit B's root cause with a minimal, known-good SAN construction:
# use X509V3_EXT_conf_nid with a config string (the same API the earlier
# successful probe used), and compare a multi-SAN cert against a wildcard-only
# cert for the SAME host.
set -e
cat > /tmp/msan3.cpp <<'EOF'
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// `san` is the value part of a subjectAltName entry list, e.g.
// "DNS:example.com,DNS:*.example.com"
static X509* mk(const char* san) {
    EVP_PKEY* k = EVP_RSA_gen(2048);
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, k);
    X509_NAME* n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
                               (const unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x, n);
    X509V3_CTX c{};
    X509V3_set_ctx_nodb(&c);
    X509V3_set_ctx(&c, x, x, 0, 0, 0);
    X509_EXTENSION* e = X509V3_EXT_conf_nid(0, &c, NID_subject_alt_name, san);
    if (!e) { fprintf(stderr, "ext build failed for [%s]\n", san); return x; }
    X509_add_ext(x, e, -1);
    X509_EXTENSION_free(e);
    X509_sign(x, k, EVP_sha256());
    EVP_PKEY_free(k);
    return x;
}

static void check(const char* label, X509* x, const char* host) {
    const int r = X509_check_host(x, host, strlen(host), 0, 0);
    printf("%-22s host=%-16s => %2d\n", label, host, r);
}

int main() {
    X509* multi = mk("DNS:example.com,DNS:*.example.com");
    check("multi-SAN", multi, "example.com");
    check("multi-SAN", multi, "a.example.com");
    check("multi-SAN", multi, "a.b.example.com");

    X509* wild = mk("DNS:*.example.com");
    check("wildcard-only", wild, "example.com");
    check("wildcard-only", wild, "a.example.com");
    check("wildcard-only", wild, "a.b.example.com");
    return 0;
}
EOF
g++ -std=c++20 -O1 /tmp/msan3.cpp -o /tmp/msan3 -lssl -lcrypto 2>&1 | tail -5
/tmp/msan3
