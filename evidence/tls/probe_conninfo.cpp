// Minimal: print the FULL SecPkgContext_ConnectionInfo so the cipher-suite claim
// can be adjudicated (design-b D13 says 0x6610 == CALG_AES_256 only, no ECDHE).
// Build: cl /nologo /W4 /WX /EHsc /std:c++20 /utf-8 probe_conninfo.cpp
//          /Fe:probe_conninfo.exe /link secur32.lib crypt32.lib advapi32.lib
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <cstdio>
#include <vector>
using Bytes = std::vector<BYTE>;

struct Side {
    CredHandle cred{};
    CtxtHandle ctx{};
    bool haveCtx = false;
};

static PCCERT_CONTEXT MakeCert() {
    CERT_NAME_BLOB subj{};
    char name[] = "CN=rtsc-ci";
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, nullptr,
                        &subj.cbData, nullptr)) return nullptr;
    Bytes nb(subj.cbData);
    subj.pbData = nb.data();
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, subj.pbData,
                        &subj.cbData, nullptr)) return nullptr;
    return CertCreateSelfSignCertificate(0, &subj, 0, nullptr, nullptr, nullptr, nullptr,
                                         nullptr);
}

static bool Acquire(Side& s, bool server, PCCERT_CONTEXT cert) {
    TimeStamp ts{};
    PCCERT_CONTEXT creds[1] = {cert};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = SP_PROT_TLS1_0 | SP_PROT_TLS1_1 | SP_PROT_TLS1_3;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = server ? 0u : (SCH_CRED_NO_SERVERNAME_CHECK |
                                SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS);
    if (server) { sc.cCreds = 1; sc.paCred = creds; }
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    return AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                     server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
                                     nullptr, &sc, nullptr, nullptr, &s.cred, &ts) == SEC_E_OK;
}

static SECURITY_STATUS Step(Side& s, bool server, const Bytes& in, Bytes& out) {
    out.clear();
    BYTE buf[65536];
    SecBuffer ib{static_cast<unsigned long>(in.size()), SECBUFFER_TOKEN,
                 in.empty() ? nullptr : const_cast<BYTE*>(in.data())};
    SecBuffer ob{sizeof(buf), SECBUFFER_TOKEN, buf};
    SecBufferDesc ibd{SECBUFFER_VERSION, in.empty() ? 0u : 1u, &ib};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    DWORD attrs = 0;
    SECURITY_STATUS st;
    if (server) {
        DWORD r = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                  ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_STREAM;
        st = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr, &ibd, r,
                                   SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
    } else {
        DWORD r = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                  ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM |
                  ISC_REQ_MANUAL_CRED_VALIDATION;
        st = InitializeSecurityContextW(&s.cred, s.haveCtx ? &s.ctx : nullptr,
                                        const_cast<SEC_WCHAR*>(L"rtsc-ci"), r, 0,
                                        SECURITY_NATIVE_DREP, in.empty() ? nullptr : &ibd, 0,
                                        &s.ctx, &obd, &attrs, nullptr);
    }
    if (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) s.haveCtx = true;
    if (ob.cbBuffer > 0 && ob.pvBuffer) out.assign(buf, buf + ob.cbBuffer);
    return st;
}

int main() {
    PCCERT_CONTEXT cert = MakeCert();
    if (!cert) return 2;
    Side c, s;
    if (!Acquire(c, false, cert) || !Acquire(s, true, cert)) return 3;
    Bytes toS, toC, out;
    SECURITY_STATUS cs = Step(c, false, toC, out);
    toS = out;
    SECURITY_STATUS ss = SEC_I_CONTINUE_NEEDED;
    for (int r = 0; r < 8; ++r) {
        if (!toS.empty()) { ss = Step(s, true, toS, out); toS.clear(); toC = out; }
        if (cs == SEC_E_OK && ss == SEC_E_OK) break;
        if (toC.empty() && toS.empty()) break;
        if (!toC.empty()) { cs = Step(c, false, toC, out); toC.clear(); toS = out; }
        if (cs == SEC_E_OK && ss == SEC_E_OK) break;
    }
    if (cs != SEC_E_OK || ss != SEC_E_OK) { printf("handshake failed\n"); return 4; }

    SecPkgContext_ConnectionInfo ci{};
    SECURITY_STATUS st = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
    printf("CONNECTION_INFO -> 0x%08lX\n", static_cast<unsigned long>(st));
    printf("  dwProtocol      = 0x%08lX\n", static_cast<unsigned long>(ci.dwProtocol));
    printf("  aiCipher        = 0x%04X  (CALG_AES_256=0x6610 => class=3 type=3 sid=16)\n",
           static_cast<unsigned>(ci.aiCipher));
    printf("  dwCipherStrength= %lu\n", static_cast<unsigned long>(ci.dwCipherStrength));
    printf("  aiHash          = 0x%04X  (CALG_SHA_384=0x800D)\n",
           static_cast<unsigned>(ci.aiHash));
    printf("  dwHashStrength  = %lu\n", static_cast<unsigned long>(ci.dwHashStrength));
    printf("  aiExch          = 0x%04X  (CALG_ECDH=0xAA02, CALG_RSA_KEYX=0xA400)\n",
           static_cast<unsigned>(ci.aiExch));
    printf("  dwExchStrength  = %lu\n", static_cast<unsigned long>(ci.dwExchStrength));
    printf("  => keyx=%s\n",
           ci.aiExch == CALG_ECDH ? "ECDH"
           : ci.aiExch == CALG_RSA_KEYX ? "RSA_KEYX" : "other");

    // Does SECPKG_ATTR_CIPHER_INFO exist on this build? (design-b says the suite id
    // must come from here, not from aiCipher.)
    SecPkgContext_CipherInfo cinfo{};
    cinfo.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
    SECURITY_STATUS st2 = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CIPHER_INFO, &cinfo);
    printf("CIPHER_INFO -> 0x%08lX\n", static_cast<unsigned long>(st2));
    if (st2 == SEC_E_OK)
        printf("  dwCipherSuite = 0x%04X  szCipherSuite=%ls\n",
               static_cast<unsigned>(cinfo.dwCipherSuite), cinfo.szCipherSuite);

    if (c.haveCtx) DeleteSecurityContext(&c.ctx);
    if (s.haveCtx) DeleteSecurityContext(&s.ctx);
    FreeCredentialsHandle(&c.cred);
    FreeCredentialsHandle(&s.cred);
    CertFreeCertificateContext(cert);
    printf("RESULT=DONE\n");
    return 0;
}
