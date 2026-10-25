// Focused re-probe for design-b trap #3 only.
// Previous attempt was methodologically invalid: it fed the post-handshake bytes
// to InitializeSecurityContext *before* DecryptMessage, which contaminates state.
// Here the pending bytes go straight to DecryptMessage as the FIRST call.
// Build: cl /nologo /W4 /WX /EHsc /std:c++20 /utf-8 verify_t3.cpp
//          /Fe:verify_t3.exe /link secur32.lib crypt32.lib advapi32.lib
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
#include <cstring>
#include <vector>
using Bytes = std::vector<BYTE>;

static const char* Hr(long hr) {
    static char b[32];
    sprintf_s(b, "0x%08lX", static_cast<unsigned long>(hr));
    return b;
}

struct Side {
    CredHandle cred{};
    CtxtHandle ctx{};
    bool haveCtx = false;
};

static PCCERT_CONTEXT MakeCert() {
    CERT_NAME_BLOB subj{};
    char name[] = "CN=rtsc-t3";
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                        nullptr, &subj.cbData, nullptr)) return nullptr;
    Bytes nb(subj.cbData);
    subj.pbData = nb.data();
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                        subj.pbData, &subj.cbData, nullptr)) return nullptr;
    return CertCreateSelfSignCertificate(0, &subj, 0, nullptr, nullptr, nullptr,
                                         nullptr, nullptr);
}

static bool Acquire(Side& s, bool server, PCCERT_CONTEXT cert, bool tls13) {
    TimeStamp ts{};
    PCCERT_CONTEXT creds[1] = {cert};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = tls13 ? (SP_PROT_TLS1_0 | SP_PROT_TLS1_1 | SP_PROT_TLS1_2)
                                      : (SP_PROT_TLS1_0 | SP_PROT_TLS1_1 | SP_PROT_TLS1_3);
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = server ? 0u : (SCH_CRED_NO_SERVERNAME_CHECK |
                                SCH_CRED_MANUAL_CRED_VALIDATION |
                                SCH_CRED_NO_DEFAULT_CREDS);
    if (server) { sc.cCreds = 1; sc.paCred = creds; }
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    SECURITY_STATUS st = AcquireCredentialsHandleW(
        nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
        server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
        nullptr, &s.cred, &ts);
    return st == SEC_E_OK;
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
        DWORD req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                    ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_STREAM;
        st = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr, &ibd, req,
                                   SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
    } else {
        DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                    ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM |
                    ISC_REQ_MANUAL_CRED_VALIDATION;
        st = InitializeSecurityContextW(&s.cred, s.haveCtx ? &s.ctx : nullptr,
                                        const_cast<SEC_WCHAR*>(L"rtsc-t3"), req, 0,
                                        SECURITY_NATIVE_DREP, in.empty() ? nullptr : &ibd,
                                        0, &s.ctx, &obd, &attrs, nullptr);
    }
    if (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) s.haveCtx = true;
    if (ob.cbBuffer > 0 && ob.pvBuffer) out.assign(buf, buf + ob.cbBuffer);
    return st;
}

// First DecryptMessage call after the handshake; reports DATA/EXTRA separately.
static SECURITY_STATUS Dec1(Side& sd, const Bytes& ct, size_t& data, size_t& extra,
                            size_t& extraOffset) {
    Bytes buf(ct);
    const BYTE* base = buf.data();
    SecBuffer sb[4]{};
    sb[0] = {static_cast<unsigned long>(buf.size()), SECBUFFER_DATA, buf.data()};
    for (int i = 1; i < 4; ++i) sb[i] = {0, SECBUFFER_EMPTY, nullptr};
    SecBufferDesc d{SECBUFFER_VERSION, 4, sb};
    SECURITY_STATUS st = DecryptMessage(&sd.ctx, &d, 0, nullptr);
    data = 0; extra = 0; extraOffset = 0;
    for (int i = 0; i < 4; ++i) {
        if (sb[i].BufferType == SECBUFFER_DATA) data = sb[i].cbBuffer;
        if (sb[i].BufferType == SECBUFFER_EXTRA && sb[i].cbBuffer) {
            extra = sb[i].cbBuffer;
            const BYTE* p = static_cast<const BYTE*>(sb[i].pvBuffer);
            if (p >= base && p < base + buf.size())
                extraOffset = static_cast<size_t>(p - base);
        }
    }
    return st;
}

int main() {
    PCCERT_CONTEXT cert = MakeCert();
    if (!cert) return 2;
    for (int tls13 = 1; tls13 >= 0; --tls13) {
        printf("=== %s ===\n", tls13 ? "TLS1.3" : "TLS1.2");
        Side c, s;
        if (!Acquire(c, false, cert, tls13 != 0) || !Acquire(s, true, cert, tls13 != 0)) {
            printf("  acquire failed\n");
            continue;
        }
        Bytes toSrv, toCli, out;
        SECURITY_STATUS cs = Step(c, false, toCli, out);
        toSrv = out;
        SECURITY_STATUS ss = SEC_I_CONTINUE_NEEDED;
        for (int r = 0; r < 8; ++r) {
            if (!toSrv.empty()) {
                ss = Step(s, true, toSrv, out);
                toSrv.clear(); toCli = out;
            }
            if (cs == SEC_E_OK && ss == SEC_E_OK) break;
            if (toCli.empty() && toSrv.empty()) break;
            if (!toCli.empty()) {
                cs = Step(c, false, toCli, out);
                toCli.clear(); toSrv = out;
            }
            if (cs == SEC_E_OK && ss == SEC_E_OK) break;
        }
        if (cs != SEC_E_OK || ss != SEC_E_OK) {
            printf("  handshake failed cs=%s ss=%s\n", Hr(cs), Hr(ss));
            continue;
        }
        SecPkgContext_ConnectionInfo ci{};
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
        printf("  proto=0x%08lX cipher=0x%04X\n",
               static_cast<unsigned long>(ci.dwProtocol),
               static_cast<unsigned>(ci.aiCipher));
        printf("  pending=%zu bytes", toCli.size());
        for (size_t i = 0; i < toCli.size() && i < 8; ++i) printf(" %02x", toCli[i]);
        printf("\n");
        if (!toCli.empty()) {
            size_t data = 0, extra = 0, eoff = 0;
            SECURITY_STATUS st = Dec1(c, toCli, data, extra, eoff);
            printf("  DecryptMessage(pending) -> %s data=%zu extra=%zu extraOffset=%zu\n",
                   Hr(st), data, extra, eoff);
            if (extra) {
                Bytes tail(toCli.end() - static_cast<long>(extra), toCli.end());
                size_t d2 = 0, e2 = 0, o2 = 0;
                SECURITY_STATUS st2 = Dec1(c, tail, d2, e2, o2);
                printf("  DecryptMessage(extra)   -> %s data=%zu extra=%zu\n", Hr(st2),
                       d2, e2);
            }
        } else {
            printf("  (no post-handshake bytes observed on this run)\n");
        }
        if (c.haveCtx) DeleteSecurityContext(&c.ctx);
        if (s.haveCtx) DeleteSecurityContext(&s.ctx);
        FreeCredentialsHandle(&c.cred);
        FreeCredentialsHandle(&s.cred);
    }
    CertFreeCertificateContext(cert);
    printf("RESULT=DONE\n");
    return 0;
}
