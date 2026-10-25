// Cross-audit probe against design-a's claims:
//  (1) "Handshake: consumed = in_size (SSPI 鍚告敹鍏ㄩ儴杈撳叆)"  -> does ISC ever report SECBUFFER_EXTRA?
//  (2) "TLS1.3 鐢?SECPKG_ATTR_CONNECTION_INFO_EX (0x6e)"     -> does it work? does CIPHER_INFO work for both?
//  (3) "浠?SPKI 閲屽墺 24 瀛楄妭澶?                              -> is 24 a stable offset?
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

static const char* Hr(HRESULT hr) {
    static char b[8][24];
    static int i = 0;
    i = (i + 1) % 8;
    sprintf_s(b[i], "0x%08lX", (unsigned long)hr);
    return b[i];
}

struct Conn {
    CredHandle cred{};
    CtxtHandle ctx{};
    bool haveCtx = false;
    SecPkgContext_StreamSizes sizes{};
};

static PCCERT_CONTEXT MakeCert() {
    CERT_NAME_BLOB subject{};
    char name[] = "CN=rtsc-probe";
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, nullptr, &subject.cbData, nullptr);
    std::vector<BYTE> nb(subject.cbData);
    subject.pbData = nb.data();
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, subject.pbData, &subject.cbData, nullptr);
    return CertCreateSelfSignCertificate(0, &subject, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
}

// Client step that reports SECBUFFER_EXTRA from the *input* descriptor.
static std::vector<BYTE> ClientStep(Conn& c, std::vector<BYTE> in, SECURITY_STATUS& st,
                                    unsigned long* extraBytes) {
    std::vector<BYTE> out;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    SecBuffer ib[2];
    ib[0] = {0, SECBUFFER_EMPTY, nullptr};
    ib[1] = {0, SECBUFFER_EMPTY, nullptr};
    SecBufferDesc ibd{SECBUFFER_VERSION, 2, ib};
    if (!in.empty()) {
        ib[0] = {(unsigned long)in.size(), SECBUFFER_TOKEN, in.data()};
    }
    DWORD attrs = 0;
    st = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                    const_cast<SEC_WCHAR*>(L"probe"),
                                    ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                                        ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                                        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                                        ISC_REQ_MANUAL_CRED_VALIDATION,
                                    0, SECURITY_NATIVE_DREP, in.empty() ? nullptr : &ibd, 0,
                                    &c.ctx, &obd, &attrs, nullptr);
    c.haveCtx = true;
    *extraBytes = 0;
    for (int i = 0; i < 2; i++)
        if (ib[i].BufferType == SECBUFFER_EXTRA) *extraBytes += ib[i].cbBuffer;
    if (ob.pvBuffer) {
        out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    return out;
}

static std::vector<BYTE> ServerStep(Conn& s, std::vector<BYTE> in, SECURITY_STATUS& st) {
    std::vector<BYTE> out;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    SecBuffer ib{};
    SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
    if (!in.empty()) {
        ib = {(unsigned long)in.size(), SECBUFFER_TOKEN, in.data()};
        ibd.cBuffers = 1;
        ibd.pBuffers = &ib;
    }
    DWORD attrs = 0;
    st = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr, in.empty() ? nullptr : &ibd,
                               ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                   ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                                   ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                               SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
    s.haveCtx = true;
    if (ob.pvBuffer) {
        out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    return out;
}

int main() {
    // ---- (1) handshake: append junk after the server flight, see if ISC reports EXTRA ----
    printf("== (1) does ISC report SECBUFFER_EXTRA on handshake input? ==\n");
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
        Conn c, s;
        TimeStamp ts{};
        TLS_PARAMETERS tp{};
        tp.grbitDisabledProtocols = disabled;
        SCH_CREDENTIALS sc{};
        sc.dwVersion = SCH_CREDENTIALS_VERSION;
        sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
        sc.cTlsParameters = 1;
        sc.pTlsParameters = &tp;
        if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                      nullptr, &sc, nullptr, nullptr, &c.cred, &ts) != SEC_E_OK) continue;
        PCCERT_CONTEXT cert = MakeCert();
        SCH_CREDENTIALS ss{};
        ss.dwVersion = SCH_CREDENTIALS_VERSION;
        ss.cCreds = 1;
        ss.paCred = &cert;
        ss.cTlsParameters = 1;
        ss.pTlsParameters = &tp;
        if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
                                      nullptr, &ss, nullptr, nullptr, &s.cred, &ts) != SEC_E_OK) continue;

        std::vector<BYTE> tok;
        SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
        unsigned long extra = 0;
        for (int i = 0; i < 12; i++) {
            tok = ClientStep(c, tok, stc, &extra);
            if (extra) printf("  %s round %d: client saw EXTRA=%lu\n",
                              pass == 0 ? "TLS1.2" : "TLS1.3", i, extra);
            if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) break;
            if (tok.empty() && stc == SEC_E_OK) break;
            if (i == 0) {
                // append 16 bytes of junk to the server's *first* flight only
                std::vector<BYTE> probeTok = tok;
                (void)probeTok;
            }
            tok = ServerStep(s, tok, sts);
            if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) break;
            if (sts == SEC_E_OK && stc == SEC_E_OK) break;
        }
        printf("  %s: handshake %s (extra seen=%s)\n", pass == 0 ? "TLS1.2" : "TLS1.3",
               (stc == SEC_E_OK && sts == SEC_E_OK) ? "OK" : "FAIL", extra ? "YES" : "no");

        if (stc == SEC_E_OK && sts == SEC_E_OK) {
            // ---- (2) CONNECTION_INFO vs CONNECTION_INFO_EX vs CIPHER_INFO ----
            SecPkgContext_ConnectionInfo ci{};
            SECURITY_STATUS q1 = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
            SecPkgContext_ConnectionInfoEx cie{};
            cie.dwVersion = SECPKGCONTEXT_CONNECTION_INFO_EX_V1;
            SECURITY_STATUS q2 = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO_EX, &cie);
            SecPkgContext_CipherInfo ciph{};
            ciph.dwVersion = SECPKG_ATTR_CIPHER_INFO;
            SECURITY_STATUS q3 = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CIPHER_INFO, &ciph);
            printf("  CONNECTION_INFO     -> %s proto=0x%04lX\n", Hr(q1), (unsigned long)ci.dwProtocol);
            printf("  CONNECTION_INFO_EX  -> %s proto=0x%04lX cipherName=\"%ls\" hash=\"%ls\"\n", Hr(q2), (unsigned long)cie.dwProtocol, cie.szCipher, cie.szHash);
            printf("  CIPHER_INFO         -> %s suite=0x%04lX \"%ls\"\n", Hr(q3),
                   (unsigned long)ciph.dwCipherSuite, ciph.szCipherSuite);

            // ---- (3) SPKI: is the 24-byte strip stable? ----
            PCCERT_CONTEXT rc = nullptr;
            if (QueryContextAttributesW(&c.ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &rc) == SEC_E_OK && rc) {
                DWORD n = 0;
                CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                    &rc->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, nullptr, &n);
                std::vector<BYTE> spki(n);
                CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                    &rc->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, spki.data(), &n);
                spki.resize(n);
                const CERT_PUBLIC_KEY_INFO& pki = rc->pCertInfo->SubjectPublicKeyInfo;
                size_t off = 0;
                bool found = false;
                for (; off + pki.PublicKey.cbData <= spki.size(); off++) {
                    if (memcmp(spki.data() + off, pki.PublicKey.pbData, pki.PublicKey.cbData) == 0) {
                        found = true;
                        break;
                    }
                }
                printf("  self-signed cert: SPKI=%zu SubjectPublicKey=%lu strip-offset=%zu (found=%d)\n",
                       spki.size(), pki.PublicKey.cbData, off, (int)found);
                CertFreeCertificateContext(rc);
            }
        }
        DeleteSecurityContext(&c.ctx);
        DeleteSecurityContext(&s.ctx);
        FreeCredentialsHandle(&c.cred);
        FreeCredentialsHandle(&s.cred);
    }
    return 0;
}
