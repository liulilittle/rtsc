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
    static char b[8][20];
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

static bool MakeCert(PCCERT_CONTEXT* out) {
    CERT_NAME_BLOB subject{};
    char name[] = "CN=rtsc-probe";
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, nullptr, &subject.cbData, nullptr);
    std::vector<BYTE> nb(subject.cbData);
    subject.pbData = nb.data();
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, subject.pbData, &subject.cbData, nullptr);
    *out = CertCreateSelfSignCertificate(0, &subject, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
    return *out != nullptr;
}

static bool Loopback(Conn& c, Conn& s, DWORD protos) {
    TimeStamp ts{};
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = protos;
    sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                  nullptr, &sc, nullptr, nullptr, &c.cred, &ts) != SEC_E_OK) return false;
    PCCERT_CONTEXT cert = nullptr;
    if (!MakeCert(&cert)) return false;
    SCHANNEL_CRED ss{};
    ss.dwVersion = SCHANNEL_CRED_VERSION;
    ss.cCreds = 1;
    ss.paCred = &cert;
    ss.grbitEnabledProtocols = protos;
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
                                  nullptr, &ss, nullptr, nullptr, &s.cred, &ts) != SEC_E_OK) return false;

    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 12; i++) {
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        SecBuffer ib{};
        SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
        if (!tok.empty()) {
            ib = {(unsigned long)tok.size(), SECBUFFER_TOKEN, tok.data()};
            ibd.cBuffers = 1;
            ibd.pBuffers = &ib;
        }
        DWORD attrs = 0;
        stc = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                         const_cast<SEC_WCHAR*>(L"probe"),
                                         ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                                             ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                                             ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                                             ISC_REQ_MANUAL_CRED_VALIDATION,
                                         0, SECURITY_NATIVE_DREP, tok.empty() ? nullptr : &ibd, 0,
                                         &c.ctx, &obd, &attrs, nullptr);
        c.haveCtx = true;
        tok.clear();
        if (ob.pvBuffer) {
            tok.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
            FreeContextBuffer(ob.pvBuffer);
        }
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) return false;
        if (tok.empty() && stc == SEC_E_OK) break;
        {
            SecBuffer ob2{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd2{SECBUFFER_VERSION, 1, &ob2};
            SecBuffer ib2 = {(unsigned long)tok.size(), SECBUFFER_TOKEN, tok.data()};
            SecBufferDesc ibd2{SECBUFFER_VERSION, 1, &ib2};
            DWORD a2 = 0;
            sts = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr, &ibd2,
                                        ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                            ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                                            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                                        SECURITY_NATIVE_DREP, &s.ctx, &obd2, &a2, nullptr);
            s.haveCtx = true;
            tok.clear();
            if (ob2.pvBuffer) {
                tok.assign((BYTE*)ob2.pvBuffer, (BYTE*)ob2.pvBuffer + ob2.cbBuffer);
                FreeContextBuffer(ob2.pvBuffer);
            }
        }
        if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) return false;
        if (sts == SEC_E_OK && stc == SEC_E_OK) break;
    }
    if (stc != SEC_E_OK || sts != SEC_E_OK) return false;
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &c.sizes);
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    return true;
}

static std::vector<BYTE> Enc(Conn& c, size_t n) {
    std::vector<BYTE> plain(n, 'Z');
    std::vector<BYTE> rec(c.sizes.cbHeader + n + c.sizes.cbTrailer);
    SecBuffer bs[3];
    bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
    bs[1] = {(unsigned long)n, SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
    bs[2] = {c.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader + n};
    memcpy(bs[1].pvBuffer, plain.data(), n);
    SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
    if (EncryptMessage(&c.ctx, 0, &d, 0) != SEC_E_OK) return {};
    rec.resize(bs[0].cbBuffer + bs[1].cbBuffer + bs[2].cbBuffer);
    return rec;
}

static SECURITY_STATUS Dec(Conn& s, const std::vector<BYTE>& in, const char* tag, bool verbose = true) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    if (verbose) {
        printf("    %-30s in=%4zu -> %s", tag, in.size(), Hr(st));
        for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
        printf("\n");
    }
    return st;
}

int main() {
    printf("== 1. injected plaintext HelloRequest (renegotiation trigger) ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_2)) { printf("hs fail\n"); return 1; }
        std::vector<BYTE> hr = {0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00};
        Dec(c, hr, "HelloRequest record");
    }
    printf("== 2. injected plaintext close_notify alert record ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_2)) { printf("hs fail\n"); return 1; }
        std::vector<BYTE> alert = {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00};
        Dec(c, alert, "close_notify alert");
        Dec(c, Enc(s, 8), "app data after close_notify");
    }
    printf("== 3. partial record: must re-feed cumulative buffer ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_2)) { printf("hs fail\n"); return 1; }
        auto r = Enc(s, 16);
        std::vector<BYTE> head(r.begin(), r.begin() + 20);
        Dec(c, head, "first 20 of 45");
        std::vector<BYTE> tail(r.begin() + 20, r.end());
        Dec(c, tail, "only remaining 25 (non-cumulative)");
        Dec(c, r, "full 45 again (cumulative)");
    }
    printf("== 4. exact-record boundary: feed 45 then next 45 ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_2)) { printf("hs fail\n"); return 1; }
        auto a = Enc(s, 16);
        auto b = Enc(s, 16);
        Dec(c, a, "record a");
        Dec(c, b, "record b");
    }
    printf("== 5. SECBUFFER_EXTRA chain: 3 records at once ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_2)) { printf("hs fail\n"); return 1; }
        auto a = Enc(s, 16);
        auto b = Enc(s, 16);
        auto d = Enc(s, 16);
        std::vector<BYTE> all = a;
        all.insert(all.end(), b.begin(), b.end());
        all.insert(all.end(), d.begin(), d.end());
        // first call must be given all three; EXTRA holds the remainder
        std::vector<BYTE> buf(all);
        SecBuffer bs[4];
        for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
        bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bs};
        SECURITY_STATUS st = DecryptMessage(&s.ctx, &desc, 0, nullptr);
        printf("    first DecryptMessage(135B) -> %s", Hr(st));
        for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
        printf("\n");
        SecBuffer* extra = nullptr;
        for (int i = 0; i < 4; i++)
            if (bs[i].BufferType == SECBUFFER_EXTRA) extra = &bs[i];
        if (extra && extra->cbBuffer) {
            std::vector<BYTE> e((BYTE*)extra->pvBuffer, (BYTE*)extra->pvBuffer + extra->cbBuffer);
            Dec(s, e, "EXTRA");
        }
    }
    printf("== 6. SCHANNEL_CRED with TLS1.3 bit ==\n");
    {
        TimeStamp ts{};
        SCHANNEL_CRED sc{};
        sc.dwVersion = SCHANNEL_CRED_VERSION;
        sc.grbitEnabledProtocols = SP_PROT_TLS1_2 | SP_PROT_TLS1_3;
        CredHandle h{};
        SECURITY_STATUS st = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                                       SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
                                                       nullptr, &h, &ts);
        printf("    TLS1.2|TLS1.3 via SCHANNEL_CRED -> %s\n", Hr(st));
        if (st == SEC_E_OK) FreeCredentialsHandle(&h);
        sc.grbitEnabledProtocols = SP_PROT_TLS1_2;
        st = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                       SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr, &h, &ts);
        printf("    TLS1.2 only via SCHANNEL_CRED -> %s\n", Hr(st));
        if (st == SEC_E_OK) FreeCredentialsHandle(&h);
    }
    printf("== 7. QueryContextAttributes SECPKG_ATTR_KEYING_MATERIAL ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, SP_PROT_TLS1_2)) {
            SecPkgContext_KeyingMaterialInfo info{};
            info.cbLabel = 7;
            info.pszLabel = (SEC_CHAR*)"EXPORTER";
            info.cbContextValue = 0;
            info.pbContextValue = nullptr;
            info.cbKeyingMaterial = 32;
            SecPkgContext_KeyingMaterial km{};
            SECURITY_STATUS st = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_KEYING_MATERIAL,
                                                           &km);
            printf("    KEYING_MATERIAL query -> %s\n", Hr(st));
        }
    }
    return 0;
}
