#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

static const char* Hr(HRESULT hr) {
    static char b[8][16];
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

static std::vector<BYTE> Step(Conn& c, Conn* peer, const std::vector<BYTE>& in, SECURITY_STATUS& st, bool client) {
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
    if (client) {
        DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                    ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                    ISC_REQ_MANUAL_CRED_VALIDATION;
        st = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                        const_cast<SEC_WCHAR*>(L"rtsc-probe"), req, 0,
                                        SECURITY_NATIVE_DREP, in.empty() ? nullptr : &ibd, 0,
                                        &c.ctx, &obd, &attrs, nullptr);
    } else {
        DWORD req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                    ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
        st = AcceptSecurityContext(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                   in.empty() ? nullptr : &ibd, req, SECURITY_NATIVE_DREP,
                                   &c.ctx, &obd, &attrs, nullptr);
    }
    c.haveCtx = true;
    if (ob.pvBuffer) {
        out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    return out;
}

static bool Handshake(Conn& c, Conn& s) {
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2;
    sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    TimeStamp ts{};
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                  nullptr, &sc, nullptr, nullptr, &c.cred, &ts) != SEC_E_OK) return false;
    PCCERT_CONTEXT cert = nullptr;
    if (!MakeCert(&cert)) return false;
    SCHANNEL_CRED ss{};
    ss.dwVersion = SCHANNEL_CRED_VERSION;
    ss.cCreds = 1;
    ss.paCred = &cert;
    ss.grbitEnabledProtocols = SP_PROT_TLS1_2;
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
                                  nullptr, &ss, nullptr, nullptr, &s.cred, &ts) != SEC_E_OK) return false;
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 12; i++) {
        tok = Step(c, nullptr, tok, stc, true);
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) return false;
        if (tok.empty() && stc == SEC_E_OK) break;
        tok = Step(s, nullptr, tok, sts, false);
        if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) return false;
        if (sts == SEC_E_OK && stc == SEC_E_OK) break;
    }
    if (stc != SEC_E_OK || sts != SEC_E_OK) return false;
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &c.sizes);
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    return true;
}

static std::vector<BYTE> Enc(Conn& c, size_t n, SECURITY_STATUS& st) {
    std::vector<BYTE> plain(n, 'Z');
    std::vector<BYTE> rec(c.sizes.cbHeader + n + c.sizes.cbTrailer);
    SecBuffer bs[3];
    bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
    bs[1] = {(unsigned long)n, SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
    bs[2] = {c.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader + n};
    memcpy(bs[1].pvBuffer, plain.data(), n);
    SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
    st = EncryptMessage(&c.ctx, 0, &d, 0);
    if (st != SEC_E_OK) return {};
    rec.resize(bs[0].cbBuffer + bs[1].cbBuffer + bs[2].cbBuffer);
    return rec;
}

// nb = number of SecBuffers to pass (2 or 4)
static void Dec(const char* tag, Conn& s, const std::vector<BYTE>& in, int nb) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, (unsigned long)nb, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    printf("  %-34s in=%4zu nb=%d -> %s", tag, in.size(), nb, Hr(st));
    for (int i = 0; i < nb; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
    printf("\n");
}

int main() {
    printf("=== variant matrix ===\n");
    {
        Conn c, s;
        if (!Handshake(c, s)) { printf("hs fail\n"); return 1; }
        SECURITY_STATUS st;
        auto r = Enc(c, 16, st);
        printf("A) fresh ctx, 2 buffers:\n");
        Dec("whole record, nb=2", s, r, 2);
    }
    {
        Conn c, s;
        if (!Handshake(c, s)) { printf("hs fail\n"); return 1; }
        SECURITY_STATUS st;
        auto r = Enc(c, 16, st);
        printf("B) fresh ctx, 4 buffers:\n");
        Dec("whole record, nb=4", s, r, 4);
    }
    {
        Conn c, s;
        if (!Handshake(c, s)) { printf("hs fail\n"); return 1; }
        SECURITY_STATUS st;
        auto r = Enc(c, 16, st);
        printf("C) truncated at each length (fresh ctx per attempt is impossible; do cumulative):\n");
        Dec("trunc 5 (header only)", s, std::vector<BYTE>(r.begin(), r.begin() + 5), 4);
        Dec("trunc 10", s, std::vector<BYTE>(r.begin(), r.begin() + 10), 4);
        Dec("trunc 20", s, std::vector<BYTE>(r.begin(), r.begin() + 20), 4);
        Dec("full", s, r, 4);
    }
    {
        Conn c, s;
        if (!Handshake(c, s)) { printf("hs fail\n"); return 1; }
        SECURITY_STATUS st;
        auto r1 = Enc(c, 16, st);
        auto r2 = Enc(c, 16, st);
        std::vector<BYTE> both = r1;
        both.insert(both.end(), r2.begin(), r2.end());
        printf("D) two records in one buffer:\n");
        Dec("r1||r2", s, both, 4);
        Dec("r3", s, Enc(c, 16, st), 4);
    }
    {
        Conn c, s;
        if (!Handshake(c, s)) { printf("hs fail\n"); return 1; }
        SECURITY_STATUS st;
        auto r1 = Enc(c, 16, st);
        printf("E) 1-byte-at-a-time then rest:\n");
        Dec("1 byte", s, std::vector<BYTE>(r1.begin(), r1.begin() + 1), 4);
        Dec("2 bytes", s, std::vector<BYTE>(r1.begin(), r1.begin() + 2), 4);
        Dec("5 bytes", s, std::vector<BYTE>(r1.begin(), r1.begin() + 5), 4);
        Dec("full", s, r1, 4);
    }
    {
        Conn c, s;
        if (!Handshake(c, s)) { printf("hs fail\n"); return 1; }
        printf("F) max message size behaviour:\n");
        SECURITY_STATUS st;
        auto r = Enc(c, c.sizes.cbMaximumMessage, st);
        printf("  enc(maxmsg) -> %s, %zu bytes\n", Hr(st), r.size());
        Dec("maxmsg record", s, r, 4);
        auto r2 = Enc(c, c.sizes.cbMaximumMessage + 1, st);
        printf("  enc(maxmsg+1) -> %s, %zu bytes\n", Hr(st), r2.size());
    }
    {
        Conn c, s;
        if (!Handshake(c, s)) { printf("hs fail\n"); return 1; }
        printf("G) close_notify:\n");
        DWORD ctl = SCHANNEL_SHUTDOWN;
        SecBuffer cb{sizeof(ctl), SECBUFFER_TOKEN, &ctl};
        SecBufferDesc cbd{SECBUFFER_VERSION, 1, &cb};
        printf("  ApplyControlToken(SHUTDOWN) -> %s\n", Hr(ApplyControlToken(&c.ctx, &cbd)));
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        DWORD attrs = 0;
        SECURITY_STATUS st = InitializeSecurityContextW(&c.cred, &c.ctx,
                                                        const_cast<SEC_WCHAR*>(L"x"), ISC_REQ_STREAM, 0,
                                                        SECURITY_NATIVE_DREP, nullptr, 0, &c.ctx, &obd,
                                                        &attrs, nullptr);
        printf("  ISC after shutdown -> %s, out=%lu\n", Hr(st), ob.cbBuffer);
        if (ob.pvBuffer && ob.cbBuffer) {
            std::vector<BYTE> cn((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
            printf("  close_notify bytes:");
            for (size_t i = 0; i < cn.size() && i < 12; i++) printf(" %02x", cn[i]);
            printf("\n");
            Dec("close_notify", s, cn, 4);
            Dec("post-close app data", s, Enc(c, 8, st), 4);
            FreeContextBuffer(ob.pvBuffer);
        }
    }
    return 0;
}
