// One-shot probe: in-process SChannel loopback (client + server in one process).
// No sockets, no listening ports, no network. Answers design-a.md §6 U9.
// Build: cl /nologo /W4 /WX /EHsc /std:c++20 /utf-8 loopback_schannel.cpp
//          /Fe:loopback_schannel.exe /link secur32.lib crypt32.lib advapi32.lib
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SECURITY_WIN32
#include <windows.h>
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
    char name[] = "CN=rtsc-loopback";
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                        nullptr, &subj.cbData, nullptr)) return nullptr;
    Bytes nb(subj.cbData);
    subj.pbData = nb.data();
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                        subj.pbData, &subj.cbData, nullptr)) return nullptr;
    return CertCreateSelfSignCertificate(0, &subj, 0, nullptr, nullptr, nullptr,
                                         nullptr, nullptr);
}

// One acquire path for both roles. SCH_CRED_MANUAL_CRED_VALIDATION +
// SCH_CRED_NO_SERVERNAME_CHECK is what lets a self-signed peer through.
static bool Acquire(Side& s, bool server, PCCERT_CONTEXT cert, DWORD mask) {
    PCCERT_CONTEXT creds[1] = {cert};
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = mask;
    if (server) { sc.cCreds = 1; sc.paCred = creds; }
    else sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION |
                      SCH_CRED_NO_DEFAULT_CREDS;
    TimeStamp ts{};
    SECURITY_STATUS st = AcquireCredentialsHandleW(
        nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
        server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
        nullptr, &s.cred, &ts);
    printf("  AcquireCredentialsHandle(%s, mask=0x%lX) -> %s\n",
           server ? "server" : "client", static_cast<unsigned long>(mask), Hr(st));
    return st == SEC_E_OK;
}

// No *_REQ_ALLOCATE_MEMORY: combining it with a preallocated SecBuffer makes
// SChannel swap pvBuffer, so copying from our own buffer ships zeroes
// (observed: 169 garbage bytes -> SEC_E_ALGORITHM_MISMATCH 0x80090331).
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
        st = InitializeSecurityContextW(
            &s.cred, s.haveCtx ? &s.ctx : nullptr,
            const_cast<SEC_WCHAR*>(L"rtsc-loopback"), req, 0, SECURITY_NATIVE_DREP,
            in.empty() ? nullptr : &ibd, 0, &s.ctx, &obd, &attrs, nullptr);
    }
    if (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) s.haveCtx = true;
    if (ob.cbBuffer > 0 && ob.pvBuffer) out.assign(buf, buf + ob.cbBuffer);
    return st;
}

static bool Handshake(Side& c, Side& s, int& rounds) {
    Bytes toServer, toClient, out;
    SECURITY_STATUS cst = Step(c, false, toClient, out);
    toServer = out;
    printf("  round 1: client -> %s, %zu bytes\n", Hr(cst), toServer.size());
    SECURITY_STATUS sst = SEC_I_CONTINUE_NEEDED;
    for (rounds = 1; rounds <= 8; ++rounds) {
        if (!toServer.empty()) {
            sst = Step(s, true, toServer, out);
            toServer.clear(); toClient = out;
            printf("  round %d: server -> %s, %zu bytes\n", rounds, Hr(sst),
                   toClient.size());
        }
        if (cst == SEC_E_OK && sst == SEC_E_OK) return true;
        if (toClient.empty() && toServer.empty()) {
            printf("  STALL: cst=%s sst=%s\n", Hr(cst), Hr(sst));
            return false;
        }
        if (!toClient.empty()) {
            cst = Step(c, false, toClient, out);
            toClient.clear(); toServer = out;
            printf("  round %d: client -> %s, %zu bytes\n", rounds, Hr(cst),
                   toServer.size());
        }
        if (cst == SEC_E_OK && sst == SEC_E_OK) return true;
    }
    printf("  no convergence: cst=%s sst=%s\n", Hr(cst), Hr(sst));
    return false;
}

static void Info(const char* who, Side& s) {
    SecPkgContext_ConnectionInfo ci{};
    SecPkgContext_StreamSizes ss{};
    if (QueryContextAttributesW(&s.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK)
        printf("  %s: protocol=0x%08lX cipher=0x%04X bits=%lu\n", who,
               static_cast<unsigned long>(ci.dwProtocol),
               static_cast<unsigned>(ci.aiCipher),
               static_cast<unsigned long>(ci.dwCipherStrength));
    if (QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &ss) == SEC_E_OK) {
        s.sizes = ss;
        printf("  %s: stream sizes header=%lu trailer=%lu maxmsg=%lu block=%lu\n", who,
               static_cast<unsigned long>(ss.cbHeader),
               static_cast<unsigned long>(ss.cbTrailer),
               static_cast<unsigned long>(ss.cbMaximumMessage),
               static_cast<unsigned long>(ss.cbBlockSize));
    }
}

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
    return EncryptMessage(&sd.ctx, 0, &d, 0);
}

// Stream context: buffer[0] MUST be SECBUFFER_DATA holding the whole record
// (5-byte header included); sb[1..3] are SECBUFFER_EMPTY slots that SChannel
// fills with plaintext / SECBUFFER_EXTRA. SECBUFFER_STREAM as input is a
// datagram-context idiom and yields SEC_E_INVALID_TOKEN (0x80090308) here.
static SECURITY_STATUS Dec(Side& sd, const Bytes& ct, Bytes& pt, size_t& extra) {
    Bytes buf(ct);
    SecBuffer sb[4]{};
    sb[0] = {static_cast<unsigned long>(buf.size()), SECBUFFER_DATA, buf.data()};
    for (int i = 1; i < 4; ++i) sb[i] = {0, SECBUFFER_EMPTY, nullptr};
    SecBufferDesc d{SECBUFFER_VERSION, 4, sb};
    SECURITY_STATUS st = DecryptMessage(&sd.ctx, &d, 0, nullptr);
    pt.clear(); extra = 0;
    for (int i = 0; i < 4; ++i) {
        if (sb[i].BufferType == SECBUFFER_DATA && sb[i].cbBuffer)
            pt.assign(static_cast<BYTE*>(sb[i].pvBuffer),
                      static_cast<BYTE*>(sb[i].pvBuffer) + sb[i].cbBuffer);
        if (sb[i].BufferType == SECBUFFER_EXTRA && sb[i].cbBuffer)
            extra = sb[i].cbBuffer;
    }
    return st;
}

int main() {
    PCCERT_CONTEXT cert = MakeCert();
    if (!cert) {
        printf("FATAL: CertCreateSelfSignCertificate err=%lu\n",
               static_cast<unsigned long>(GetLastError()));
        return 2;
    }
    printf("self-signed cert: %lu bytes DER\n",
           static_cast<unsigned long>(cert->cbCertEncoded));

    Side c, s;
    int rounds = 0;
    // Server mask 0x400 (SERVER only) is correct and accepted; the 0xC00
    // (SERVER|CLIENT) variant used by the older probe was not needed.
    bool ok = Acquire(c, false, cert, SP_PROT_TLS1_2_CLIENT) &&
              Acquire(s, true, cert, SP_PROT_TLS1_2_SERVER) &&
              Handshake(c, s, rounds);
    if (!ok) {
        printf("RESULT=FAIL handshake\n");
        if (c.haveCtx) DeleteSecurityContext(&c.ctx);
        if (s.haveCtx) DeleteSecurityContext(&s.ctx);
        FreeCredentialsHandle(&c.cred); FreeCredentialsHandle(&s.cred);
        CertFreeCertificateContext(cert);
        return 4;
    }
    printf("handshake OK, rounds=%d\n-- negotiated --\n", rounds);
    Info("client", c);
    Info("server", s);

    int rc = 5;
    printf("-- peer cert --\n");
    PCCERT_CONTEXT peer = nullptr;
    SECURITY_STATUS st =
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer);
    printf("  client REMOTE_CERT_CONTEXT -> %s\n", Hr(st));
    if (st == SEC_E_OK && peer) {
        printf("  client sees server cert: %lu bytes, equals local=%d\n",
               static_cast<unsigned long>(peer->cbCertEncoded),
               CertCompareCertificate(X509_ASN_ENCODING, peer->pCertInfo,
                                      cert->pCertInfo));
        CertFreeCertificateContext(peer);
    }
    peer = nullptr;
    st = QueryContextAttributesW(&s.ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer);
    printf("  server REMOTE_CERT_CONTEXT -> %s (no client cert expected)\n", Hr(st));
    if (st == SEC_E_OK && peer) CertFreeCertificateContext(peer);

    printf("-- app data --\n");
    const char msg[] = "RTSC-TLS-LOOPBACK-PAYLOAD-0123456789";
    Bytes pt(msg, msg + sizeof(msg) - 1), ct, back, two, tmp;
    size_t extra = 0;
    st = Enc(c, pt, ct);
    printf("  client EncryptMessage(%zu) -> %s, record=%zu\n", pt.size(), Hr(st),
           ct.size());
    if (st == SEC_E_OK) st = Dec(s, ct, back, extra);
    printf("  server DecryptMessage -> %s plain=%zu extra=%zu match=%d\n", Hr(st),
           back.size(), extra, back == pt);
    if (st != SEC_E_OK || back != pt) goto done;

    st = Enc(s, pt, ct);
    printf("  server EncryptMessage(%zu) -> %s, record=%zu\n", pt.size(), Hr(st),
           ct.size());
    if (st == SEC_E_OK) st = Dec(c, ct, back, extra);
    printf("  client DecryptMessage -> %s plain=%zu extra=%zu match=%d\n", Hr(st),
           back.size(), extra, back == pt);
    if (st != SEC_E_OK || back != pt) goto done;

    // Two records in one buffer: the second must surface via SECBUFFER_EXTRA.
    Enc(c, pt, two); Enc(c, pt, tmp);
    two.insert(two.end(), tmp.begin(), tmp.end());
    st = Dec(s, two, back, extra);
    printf("  server DecryptMessage(2 records, %zu B) -> %s extra=%zu\n", two.size(),
           Hr(st), extra);
    if (st != SEC_E_OK || extra == 0) { rc = 6; goto done; }

    // Truncated record must be SEC_E_INCOMPLETE_MESSAGE (0x80090318).
    {
        Bytes trunc(two.begin(), two.begin() + 10);
        st = Dec(s, trunc, back, extra);
        printf("  server DecryptMessage(truncated 10 B) -> %s (want 0x80090318) %s\n",
               Hr(st), st == SEC_E_INCOMPLETE_MESSAGE ? "OK" : "MISMATCH");
        if (st != SEC_E_INCOMPLETE_MESSAGE) { rc = 7; goto done; }
    }
    rc = 0;

done:
    if (c.haveCtx) DeleteSecurityContext(&c.ctx);
    if (s.haveCtx) DeleteSecurityContext(&s.ctx);
    FreeCredentialsHandle(&c.cred); FreeCredentialsHandle(&s.cred);
    CertFreeCertificateContext(cert);
    printf("RESULT=%s\n", rc == 0 ? "PASS" : "FAIL");
    return rc;
}
