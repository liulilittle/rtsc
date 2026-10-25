// One-shot probe: independently verify design-b's 5 SChannel traps.
//   T1 DecryptMessage SecBuffer count floor
//   T2 SECBUFFER_EXTRA pvBuffer aliases caller input
//   T3 TLS1.3 NewSessionTicket -> SEC_I_RENEGOTIATE
//   T4 cbTrailer is an upper bound, not the actual trailer length
//   T5 close_notify requires ISC_REQ_ALLOCATE_MEMORY
// Note: SCH_CREDENTIALS/TLS_PARAMETERS live behind #ifdef SCHANNEL_USE_BLACKLISTS
// in schannel.h (SDK 10.0.26100 line 409); UNICODE_STRING comes from winternl.h.
// Build: cl /nologo /W4 /WX /EHsc /std:c++20 /utf-8 verify_traps.cpp
//          /Fe:verify_traps.exe /link secur32.lib crypt32.lib advapi32.lib
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
    SecPkgContext_StreamSizes sizes{};
};

static PCCERT_CONTEXT MakeCert() {
    CERT_NAME_BLOB subj{};
    char name[] = "CN=rtsc-traps";
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                        nullptr, &subj.cbData, nullptr)) return nullptr;
    Bytes nb(subj.cbData);
    subj.pbData = nb.data();
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                        subj.pbData, &subj.cbData, nullptr)) return nullptr;
    return CertCreateSelfSignCertificate(0, &subj, 0, nullptr, nullptr, nullptr,
                                         nullptr, nullptr);
}

// mode 0 = legacy SCHANNEL_CRED TLS1.2 only; mode 1 = SCH_CREDENTIALS with
// TLS1.0|1.1|1.2 disabled (i.e. a real TLS1.3 floor).
static bool Acquire(Side& s, bool server, PCCERT_CONTEXT cert, int mode) {
    TimeStamp ts{};
    PCCERT_CONTEXT creds[1] = {cert};
    SECURITY_STATUS st;
    if (mode == 0) {
        SCHANNEL_CRED sc{};
        sc.dwVersion = SCHANNEL_CRED_VERSION;
        sc.grbitEnabledProtocols = server ? SP_PROT_TLS1_2_SERVER : SP_PROT_TLS1_2_CLIENT;
        if (server) { sc.cCreds = 1; sc.paCred = creds; }
        else sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK |
                          SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
        st = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                       server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
                                       nullptr, &sc, nullptr, nullptr, &s.cred, &ts);
    } else {
        TLS_PARAMETERS tp{};
        tp.grbitDisabledProtocols = SP_PROT_TLS1_0 | SP_PROT_TLS1_1 | SP_PROT_TLS1_2;
        SCH_CREDENTIALS sc{};
        sc.dwVersion = SCH_CREDENTIALS_VERSION;
        sc.dwFlags = server ? 0u : (SCH_CRED_NO_SERVERNAME_CHECK |
                                    SCH_CRED_MANUAL_CRED_VALIDATION |
                                    SCH_CRED_NO_DEFAULT_CREDS);
        if (server) { sc.cCreds = 1; sc.paCred = creds; }
        sc.cTlsParameters = 1;
        sc.pTlsParameters = &tp;
        st = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                       server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
                                       nullptr, &sc, nullptr, nullptr, &s.cred, &ts);
    }
    printf("  Acquire(%s, mode=%d) -> %s\n", server ? "srv" : "cli", mode, Hr(st));
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
                                        const_cast<SEC_WCHAR*>(L"rtsc-traps"), req, 0,
                                        SECURITY_NATIVE_DREP, in.empty() ? nullptr : &ibd,
                                        0, &s.ctx, &obd, &attrs, nullptr);
    }
    if (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) s.haveCtx = true;
    if (ob.cbBuffer > 0 && ob.pvBuffer) out.assign(buf, buf + ob.cbBuffer);
    return st;
}

// Returns true when both sides reach SEC_E_OK; `pending` = server->client bytes.
static bool Pair(Side& c, Side& s, PCCERT_CONTEXT cert, int mode, Bytes& pending) {
    if (!Acquire(c, false, cert, mode) || !Acquire(s, true, cert, mode)) return false;
    Bytes toSrv, toCli, out;
    SECURITY_STATUS cs = Step(c, false, toCli, out);
    toSrv = out;
    SECURITY_STATUS ss = SEC_I_CONTINUE_NEEDED;
    for (int r = 0; r < 8; ++r) {
        if (!toSrv.empty()) {
            ss = Step(s, true, toSrv, out);
            toSrv.clear(); toCli = out;
        }
        if (cs == SEC_E_OK && ss == SEC_E_OK) { pending = toCli; return true; }
        if (toCli.empty() && toSrv.empty()) return false;
        if (!toCli.empty()) {
            cs = Step(c, false, toCli, out);
            toCli.clear(); toSrv = out;
        }
        if (cs == SEC_E_OK && ss == SEC_E_OK) { pending = toCli; return true; }
    }
    return false;
}

// T4 is measured here: wire length is the SUM of returned cbBuffer values.
static SECURITY_STATUS Enc(Side& sd, const Bytes& pt, Bytes& out) {
    out.assign(sd.sizes.cbHeader + pt.size() + sd.sizes.cbTrailer, 0);
    SecBuffer sb[3]{};
    sb[0] = {sd.sizes.cbHeader, SECBUFFER_STREAM_HEADER, out.data()};
    sb[1] = {static_cast<unsigned long>(pt.size()), SECBUFFER_DATA,
             out.data() + sd.sizes.cbHeader};
    sb[2] = {sd.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER,
             out.data() + sd.sizes.cbHeader + pt.size()};
    memcpy(sb[1].pvBuffer, pt.data(), pt.size());
    SecBufferDesc d{SECBUFFER_VERSION, 3, sb};
    SECURITY_STATUS st = EncryptMessage(&sd.ctx, 0, &d, 0);
    if (st == SEC_E_OK) {
        unsigned long sum = sb[0].cbBuffer + sb[1].cbBuffer + sb[2].cbBuffer;
        printf("    [T4] alloc=%zu wire=%lu (hdr=%lu data=%lu trl=%lu) delta=%ld\n",
               out.size(), sum, static_cast<unsigned long>(sb[0].cbBuffer),
               static_cast<unsigned long>(sb[1].cbBuffer),
               static_cast<unsigned long>(sb[2].cbBuffer),
               static_cast<long>(out.size()) - static_cast<long>(sum));
        out.resize(sum);
    }
    return st;
}

static SECURITY_STATUS Dec(Side& sd, const Bytes& ct, int nbuf, size_t& extra,
                           long& off, bool& inRange) {
    Bytes buf(ct);
    const BYTE* base = buf.data();
    SecBuffer sb[5]{};
    unsigned long c = nbuf > 0 ? static_cast<unsigned long>(nbuf) : 1u;
    sb[0] = {static_cast<unsigned long>(buf.size()), SECBUFFER_DATA, buf.data()};
    for (unsigned long i = 1; i < c; ++i) sb[i] = {0, SECBUFFER_EMPTY, nullptr};
    SecBufferDesc d{SECBUFFER_VERSION, c, sb};
    SECURITY_STATUS st = DecryptMessage(&sd.ctx, &d, 0, nullptr);
    extra = 0; off = -1; inRange = false;
    for (unsigned long i = 0; i < c; ++i) {
        if (sb[i].BufferType != SECBUFFER_EXTRA || !sb[i].cbBuffer) continue;
        extra = sb[i].cbBuffer;
        const BYTE* p = static_cast<const BYTE*>(sb[i].pvBuffer);
        if (p >= base && p < base + buf.size()) {
            off = static_cast<long>(p - base);
            inRange = true;
        }
    }
    return st;
}

int main() {
    PCCERT_CONTEXT cert = MakeCert();
    if (!cert) { printf("FATAL cert err=%lu\n",
                        static_cast<unsigned long>(GetLastError())); return 2; }
    const char msg[] = "RTSC-TRAP-PROBE-PAYLOAD-0123456789";
    Bytes pt(msg, msg + sizeof(msg) - 1);
    size_t extra = 0; long off = -1; bool inRange = false;

    printf("=== TLS1.2 (legacy cred) ===\n");
    Side c, s; Bytes pending;
    if (!Pair(c, s, cert, 0, pending)) { printf("RESULT=FAIL tls12\n"); return 4; }
    SecPkgContext_ConnectionInfo ci{};
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &c.sizes);
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    printf("  proto=0x%08lX cipher=0x%04X hdr=%lu trl=%lu maxmsg=%lu pending=%zu\n",
           static_cast<unsigned long>(ci.dwProtocol), static_cast<unsigned>(ci.aiCipher),
           static_cast<unsigned long>(c.sizes.cbHeader),
           static_cast<unsigned long>(c.sizes.cbTrailer),
           static_cast<unsigned long>(c.sizes.cbMaximumMessage), pending.size());

    Bytes rec;
    Enc(c, pt, rec);

    printf("-- T1 buffer count floor --\n");
    for (int n = 1; n <= 3; ++n)
        printf("  nbuf=%d -> %s\n", n, Hr(Dec(s, rec, n, extra, off, inRange)));
    printf("  nbuf=4 same record -> %s (proves 1..3 consumed nothing)\n",
           Hr(Dec(s, rec, 4, extra, off, inRange)));
    Bytes rec2;
    Enc(c, pt, rec2);
    printf("  nbuf=5 -> %s\n", Hr(Dec(s, rec2, 5, extra, off, inRange)));

    printf("-- T2 EXTRA pointer aliasing --\n");
    {
        Bytes two, tmp;
        Enc(c, pt, two); Enc(c, pt, tmp);
        two.insert(two.end(), tmp.begin(), tmp.end());
        SECURITY_STATUS st = Dec(s, two, 4, extra, off, inRange);
        printf("  st=%s extra=%zu offset=%ld inCallerRange=%d input=%zu\n", Hr(st), extra,
               off, inRange ? 1 : 0, two.size());
    }

    printf("-- T5 close_notify flag --\n");
    for (int mode = 0; mode < 2; ++mode) {
        Side c2, s2; Bytes p2;
        if (!Pair(c2, s2, cert, 0, p2)) { printf("  pair failed\n"); continue; }
        DWORD ctl = SCHANNEL_SHUTDOWN;
        SecBuffer cb{sizeof(ctl), SECBUFFER_TOKEN, &ctl};
        SecBufferDesc cbd{SECBUFFER_VERSION, 1, &cb};
        SECURITY_STATUS s1 = ApplyControlToken(&c2.ctx, &cbd);
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        DWORD flags = ISC_REQ_STREAM | (mode == 1 ? ISC_REQ_ALLOCATE_MEMORY : 0u);
        DWORD attrs = 0;
        SECURITY_STATUS s2st = InitializeSecurityContextW(
            &c2.cred, &c2.ctx, const_cast<SEC_WCHAR*>(L"rtsc-traps"), flags, 0,
            SECURITY_NATIVE_DREP, nullptr, 0, &c2.ctx, &obd, &attrs, nullptr);
        printf("  alloc=%d: ctl=%s isc=%s out=%lu first=%02x\n", mode, Hr(s1), Hr(s2st),
               static_cast<unsigned long>(ob.cbBuffer),
               ob.pvBuffer && ob.cbBuffer ? *static_cast<BYTE*>(ob.pvBuffer) : 0);
        if (ob.pvBuffer) FreeContextBuffer(ob.pvBuffer);
        if (c2.haveCtx) DeleteSecurityContext(&c2.ctx);
        if (s2.haveCtx) DeleteSecurityContext(&s2.ctx);
        FreeCredentialsHandle(&c2.cred); FreeCredentialsHandle(&s2.cred);
    }

    printf("=== TLS1.3 (SCH_CREDENTIALS, 1.0|1.1|1.2 disabled) ===\n");
    Side c3, s3; Bytes pend3;
    if (!Pair(c3, s3, cert, 1, pend3)) {
        printf("  TLS1.3 handshake FAILED\n");
    } else {
        SecPkgContext_ConnectionInfo ci3{};
        QueryContextAttributesW(&c3.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci3);
        QueryContextAttributesW(&c3.ctx, SECPKG_ATTR_STREAM_SIZES, &c3.sizes);
        printf("  proto=0x%08lX cipher=0x%04X hdr=%lu trl=%lu maxmsg=%lu\n",
               static_cast<unsigned long>(ci3.dwProtocol),
               static_cast<unsigned>(ci3.aiCipher),
               static_cast<unsigned long>(c3.sizes.cbHeader),
               static_cast<unsigned long>(c3.sizes.cbTrailer),
               static_cast<unsigned long>(c3.sizes.cbMaximumMessage));
        Bytes r3;
        Enc(c3, pt, r3);
        printf("-- T3 post-handshake ticket --\n");
        printf("  pending=%zu", pend3.size());
        for (size_t i = 0; i < pend3.size() && i < 6; ++i) printf(" %02x", pend3[i]);
        printf("\n");
        if (!pend3.empty()) {
            Bytes out3;
            SECURITY_STATUS st = Step(c3, false, pend3, out3);
            printf("  client ISC(ticket bytes) -> %s out=%zu\n", Hr(st), out3.size());
            Bytes tail(pend3.begin(), pend3.end());
            SECURITY_STATUS sd = Dec(c3, tail, 4, extra, off, inRange);
            printf("  client Dec(ticket record) -> %s extra=%zu\n", Hr(sd), extra);
        }
        if (c3.haveCtx) DeleteSecurityContext(&c3.ctx);
        if (s3.haveCtx) DeleteSecurityContext(&s3.ctx);
        FreeCredentialsHandle(&c3.cred); FreeCredentialsHandle(&s3.cred);
    }

    if (c.haveCtx) DeleteSecurityContext(&c.ctx);
    if (s.haveCtx) DeleteSecurityContext(&s.ctx);
    FreeCredentialsHandle(&c.cred); FreeCredentialsHandle(&s.cred);
    CertFreeCertificateContext(cert);
    printf("RESULT=DONE\n");
    return 0;
}
