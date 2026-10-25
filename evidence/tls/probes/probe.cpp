// Throwaway diagnostic probe (NOT part of the rtsc build).
// Purpose: measure SChannel record-layer semantics in-process (loopback, no sockets).
//  1. TLS1.2 vs TLS1.3 stream sizes (header bytes!)
//  2. DecryptMessage: whole record / two records concatenated (SECBUFFER_EXTRA) / truncated record
//  3. close_notify -> SEC_I_CONTEXT_EXPIRED
//  4. SPKI extraction via SECPKG_ATTR_REMOTE_CERT_CONTEXT
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

static const char* Hr(HRESULT hr) {
    static char buf[64];
    sprintf_s(buf, "0x%08lX", (unsigned long)hr);
    return buf;
}

static void Dump(const char* tag, const unsigned char* p, size_t n, size_t maxn = 16) {
    printf("%s (%zu bytes):", tag, n);
    for (size_t i = 0; i < n && i < maxn; i++) printf(" %02x", p[i]);
    if (n > maxn) printf(" ...");
    printf("\n");
}

struct Conn {
    CredHandle cred{};
    CtxtHandle ctx{};
    bool haveCtx = false;
    SecPkgContext_StreamSizes sizes{};
};

static bool MakeCert(PCCERT_CONTEXT* out) {
    CERT_NAME_BLOB subject{};
    char name[] = "CN=rtsc-probe";
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                        nullptr, &subject.cbData, nullptr)) return false;
    std::vector<BYTE> nb(subject.cbData);
    subject.pbData = nb.data();
    if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                        subject.pbData, &subject.cbData, nullptr)) return false;
    *out = CertCreateSelfSignCertificate(0, &subject, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
    return *out != nullptr;
}

static bool AcquireBoth(DWORD protoMask, Conn& c, Conn& s) {
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = protoMask;
    sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION |
                 SCH_CRED_NO_DEFAULT_CREDS;
    TimeStamp ts{};
    SECURITY_STATUS st = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                                   SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
                                                   nullptr, &c.cred, &ts);
    printf("  AcquireCredentialsHandle(client) -> %s\n", Hr(st));
    if (st != SEC_E_OK) return false;

    PCCERT_CONTEXT cert = nullptr;
    if (!MakeCert(&cert)) { printf("  MakeCert failed 0x%08lX\n", GetLastError()); return false; }
    SCHANNEL_CRED ss{};
    ss.dwVersion = SCHANNEL_CRED_VERSION;
    ss.cCreds = 1;
    ss.paCred = &cert;
    ss.grbitEnabledProtocols = (protoMask | (protoMask >> 1));  // include SERVER bit
    ss.dwFlags = 0;
    st = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                   SECPKG_CRED_INBOUND, nullptr, &ss, nullptr, nullptr, &s.cred,
                                   &ts);
    printf("  AcquireCredentialsHandle(server) -> %s\n", Hr(st));
    return st == SEC_E_OK;
}

static std::vector<BYTE> ClientStep(Conn& c, const std::vector<BYTE>& in, SECURITY_STATUS& st) {
    std::vector<BYTE> out;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    SecBuffer ib{};
    SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
    if (!in.empty()) {
        ib.BufferType = SECBUFFER_TOKEN;
        ib.cbBuffer = (unsigned long)in.size();
        ib.pvBuffer = const_cast<BYTE*>(in.data());
        ibd.cBuffers = 1;
        ibd.pBuffers = &ib;
    }
    DWORD attrs = 0;
    DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                ISC_REQ_MANUAL_CRED_VALIDATION;
    st = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                    const_cast<SEC_WCHAR*>(L"rtsc-probe"), req, 0,
                                    SECURITY_NATIVE_DREP, in.empty() ? nullptr : &ibd, 0,
                                    &c.ctx, &obd, &attrs, nullptr);
    c.haveCtx = true;
    if (ob.pvBuffer) {
        out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    return out;
}

static std::vector<BYTE> ServerStep(Conn& s, const std::vector<BYTE>& in, SECURITY_STATUS& st) {
    std::vector<BYTE> out;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    SecBuffer ib{};
    SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
    if (!in.empty()) {
        ib.BufferType = SECBUFFER_TOKEN;
        ib.cbBuffer = (unsigned long)in.size();
        ib.pvBuffer = const_cast<BYTE*>(in.data());
        ibd.cBuffers = 1;
        ibd.pBuffers = &ib;
    }
    DWORD attrs = 0;
    st = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr,
                               in.empty() ? nullptr : &ibd,
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

static bool Handshake(Conn& c, Conn& s, const char* label, DWORD protoMask) {
    printf("[%s] handshake, protoMask=0x%08lX\n", label, (unsigned long)protoMask);
    if (!AcquireBoth(protoMask, c, s)) return false;
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 12; i++) {
        tok = ClientStep(c, tok, stc);
        printf("  round %d: client -> %zu bytes, st=%s\n", i, tok.size(), Hr(stc));
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) return false;
        if (tok.empty() && stc == SEC_E_OK) break;
        tok = ServerStep(s, tok, sts);
        printf("           server -> %zu bytes, st=%s\n", tok.size(), Hr(sts));
        if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) return false;
        if (sts == SEC_E_OK && stc == SEC_E_OK) break;
    }
    printf("  client ctx=%s server ctx=%s\n", Hr(stc), Hr(sts));
    if (stc != SEC_E_OK || sts != SEC_E_OK) return false;

    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &c.sizes);
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    printf("  STREAM_SIZES: header=%lu trailer=%lu maxmsg=%lu block=%lu\n",
           c.sizes.cbHeader, c.sizes.cbTrailer, c.sizes.cbMaximumMessage, c.sizes.cbBlockSize);
    SecPkgContext_ConnectionInfo ci{};
    if (QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK)
        printf("  CONNECTION_INFO: protocol=0x%08lX cipher=0x%04X bits=%lu\n",
               (unsigned long)ci.dwProtocol, (unsigned)ci.aiCipher, (unsigned long)ci.dwCipherStrength);
    return true;
}

static std::vector<BYTE> Encrypt(Conn& c, const std::vector<BYTE>& plain, SECURITY_STATUS& st) {
    size_t total = c.sizes.cbHeader + plain.size() + c.sizes.cbTrailer;
    std::vector<BYTE> rec(total);
    SecBuffer bs[3];
    bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
    bs[1] = {(unsigned long)plain.size(), SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
    bs[2] = {c.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader + plain.size()};
    memcpy(bs[1].pvBuffer, plain.data(), plain.size());
    SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
    st = EncryptMessage(&c.ctx, 0, &d, 0);
    if (st != SEC_E_OK) return {};
    size_t got = bs[0].cbBuffer + bs[1].cbBuffer + bs[2].cbBuffer;
    rec.resize(got);
    return rec;
}

struct DecResult {
    SECURITY_STATUS st;
    std::vector<BYTE> plain;
    std::vector<BYTE> extra;
};

static DecResult Decrypt(Conn& s, const std::vector<BYTE>& in) {
    DecResult r{};
    if (in.empty()) { r.st = SEC_E_INVALID_PARAMETER; return r; }
    std::vector<BYTE> buf(in);
    SecBuffer bs[2];
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    bs[1] = {0, SECBUFFER_EMPTY, nullptr};
    SecBufferDesc d{SECBUFFER_VERSION, 2, bs};
    r.st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    if (r.st == SEC_E_OK || r.st == SEC_I_CONTEXT_EXPIRED || r.st == SEC_I_RENEGOTIATE) {
        for (int i = 0; i < 2; i++) {
            if (bs[i].BufferType == SECBUFFER_DATA && bs[i].cbBuffer)
                r.plain.assign((BYTE*)bs[i].pvBuffer, (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
            if (bs[i].BufferType == SECBUFFER_EXTRA && bs[i].cbBuffer)
                r.extra.assign((BYTE*)bs[i].pvBuffer, (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
        }
    } else {
        // On failure SChannel reports consumed bytes in bs[0].cbBuffer for INCOMPLETE.
        printf("    (decrypt fail: buf[0].cbBuffer=%lu type=%lu)\n", bs[0].cbBuffer, bs[0].BufferType);
    }
    return r;
}

int main() {
    printf("=== probe: SChannel record layer semantics ===\n");
    printf("OS build %lu\\n", (unsigned long)GetVersion());

    for (int pass = 0; pass < 2; pass++) {
        DWORD mask = pass == 0 ? SP_PROT_TLS1_2_CLIENT : SP_PROT_TLS1_3_CLIENT;
        const char* label = pass == 0 ? "TLS1.2" : "TLS1.3";
        Conn c, s;
        if (!Handshake(c, s, label, mask)) { printf("[%s] handshake FAILED\n", label); continue; }

        // SPKI extraction
        PCCERT_CONTEXT remote = nullptr;
        SECURITY_STATUS st = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote);
        printf("  REMOTE_CERT_CONTEXT -> %s, cert=%p\n", Hr(st), (void*)remote);
        if (st == SEC_E_OK && remote) {
            DWORD n = 0;
            CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                &remote->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, nullptr, &n);
            std::vector<BYTE> spki(n);
            if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                    &remote->pCertInfo->SubjectPublicKeyInfo, 0, nullptr,
                                    spki.data(), &n)) {
                spki.resize(n);
                Dump("  SPKI DER", spki.data(), spki.size(), 8);
            }
            printf("  cert DER len=%lu\n", remote->cbCertEncoded);
            CertFreeCertificateContext(remote);
        }

        // one record
        std::vector<BYTE> plain = {0x03, 0x00, 0x00, 0x10, 0x02, 0xF0, 0x80, 'A', 'B', 'C',
                                   'D', 'E', 'F', 'G', 'H', 'I'};
        std::vector<BYTE> rec = Encrypt(c, plain, st);
        printf("  EncryptMessage(%zu B) -> %s, record=%zu bytes\n", plain.size(), Hr(st), rec.size());
        Dump("  record", rec.data(), rec.size(), 20);

        DecResult d1 = Decrypt(s, rec);
        printf("  decrypt(whole record) -> %s plain=%zu extra=%zu match=%d\n", Hr(d1.st),
               d1.plain.size(), d1.extra.size(),
               (int)(d1.plain == plain));

        // truncated record: header+half body
        std::vector<BYTE> trunc(rec.begin(), rec.begin() + 5 + (rec.size() - 5) / 2);
        DecResult d2 = Decrypt(s, trunc);
        printf("  decrypt(truncated %zu B) -> %s\n", trunc.size(), Hr(d2.st));

        // byte-at-a-time (worst case TCP segmentation)
        {
            Conn c2, s2;
            DWORD mask2 = mask;
            if (Handshake(c2, s2, label, mask2)) {
                SECURITY_STATUS st2;
                std::vector<BYTE> r2 = Encrypt(c2, plain, st2);
                SECURITY_STATUS firstFail = SEC_E_OK;
                size_t firstFailAt = 0;
                for (size_t k = 1; k < r2.size(); k++) {
                    std::vector<BYTE> part(r2.begin(), r2.begin() + k);
                    DecResult dd = Decrypt(s2, part);
                    if (dd.st != SEC_E_OK) { firstFail = dd.st; firstFailAt = k; break; }
                }
                printf("  byte-at-a-time: first non-OK at %zu B -> %s\n", firstFailAt, Hr(firstFail));
            }
        }

        // two records concatenated -> SECBUFFER_EXTRA
        {
            std::vector<BYTE> rec2 = Encrypt(c, plain, st);
            std::vector<BYTE> both = rec;
            both.insert(both.end(), rec2.begin(), rec2.end());
            DecResult d3 = Decrypt(s, both);
            printf("  decrypt(2 records, %zu B) -> %s plain=%zu extra=%zu\n", both.size(), Hr(d3.st),
                   d3.plain.size(), d3.extra.size());
            if (!d3.extra.empty()) {
                DecResult d4 = Decrypt(s, d3.extra);
                printf("  decrypt(EXTRA, %zu B) -> %s plain=%zu extra=%zu match=%d\n",
                       d3.extra.size(), Hr(d4.st), d4.plain.size(), d4.extra.size(),
                       (int)(d4.plain == plain));
            }
        }

        // close_notify
        {
            SecBuffer shut{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc sd{SECBUFFER_VERSION, 1, &shut};
            DWORD ctl = SCHANNEL_SHUTDOWN;
            SecBuffer cb{sizeof(ctl), SECBUFFER_TOKEN, &ctl};
            SecBufferDesc cbd{SECBUFFER_VERSION, 1, &cb};
            SECURITY_STATUS s1 = ApplyControlToken(&c.ctx, &cbd);
            DWORD attrs = 0;
            SECURITY_STATUS s2 = InitializeSecurityContextW(&c.cred, &c.ctx,
                                                           const_cast<SEC_WCHAR*>(L"rtsc-probe"),
                                                           ISC_REQ_STREAM, 0, SECURITY_NATIVE_DREP,
                                                           nullptr, 0, &c.ctx, &sd, &attrs, nullptr);
            printf("  close_notify: ApplyControlToken=%s ISC=%s out=%lu\n", Hr(s1), Hr(s2),
                   shut.cbBuffer);
            if (shut.pvBuffer && shut.cbBuffer) {
                std::vector<BYTE> cn((BYTE*)shut.pvBuffer, (BYTE*)shut.pvBuffer + shut.cbBuffer);
                Dump("  close_notify record", cn.data(), cn.size(), 10);
                DecResult d5 = Decrypt(s, cn);
                printf("  decrypt(close_notify) -> %s\n", Hr(d5.st));
                FreeContextBuffer(shut.pvBuffer);
            }
        }
        DeleteSecurityContext(&c.ctx);
        DeleteSecurityContext(&s.ctx);
        FreeCredentialsHandle(&c.cred);
        FreeCredentialsHandle(&s.cred);
    }
    printf("=== done ===\n");
    return 0;
}
