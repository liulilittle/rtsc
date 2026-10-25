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

static bool Loopback(Conn& c, Conn& s, DWORD disabled) {
    TimeStamp ts{};
    PCCERT_CONTEXT cert = nullptr;
    if (!MakeCert(&cert)) return false;
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                  nullptr, &sc, nullptr, nullptr, &c.cred, &ts) != SEC_E_OK) return false;
    SCH_CREDENTIALS ss{};
    ss.dwVersion = SCH_CREDENTIALS_VERSION;
    ss.cCreds = 1;
    ss.paCred = &cert;
    ss.cTlsParameters = 1;
    ss.pTlsParameters = &tp;
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

static SECURITY_STATUS One(Conn& s, const std::vector<BYTE>& in, size_t* dataLen, size_t* extraLen) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    if (dataLen) *dataLen = 0;
    if (extraLen) *extraLen = 0;
    for (int i = 0; i < 4; i++) {
        if (bs[i].BufferType == SECBUFFER_DATA && dataLen) *dataLen += bs[i].cbBuffer;
        if (bs[i].BufferType == SECBUFFER_EXTRA && extraLen) *extraLen += bs[i].cbBuffer;
    }
    return st;
}

int main() {
    printf("== A. drop EXTRA then feed next record: is the context still usable? ==\n");
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
        Conn c, s;
        if (!Loopback(c, s, disabled)) { printf("  hs fail\n"); continue; }
        auto a = Enc(c, 16);
        auto b = Enc(c, 16);
        std::vector<BYTE> both = a;
        both.insert(both.end(), b.begin(), b.end());
        size_t dl = 0, el = 0;
        SECURITY_STATUS st = One(s, both, &dl, &el);
        printf("  %s: 2-in-1 -> %s data=%zu extra=%zu (extra DROPPED)\n",
               pass == 0 ? "TLS1.3" : "TLS1.2", Hr(st), dl, el);
        auto c3 = Enc(c, 16);
        st = One(s, c3, &dl, &el);
        printf("      next fresh record -> %s data=%zu\n", Hr(st), dl);
    }

    printf("== B. recovery rate after a tampered record (10 trials each) ==\n");
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
        int recovered = 0, poisoned = 0;
        for (int t = 0; t < 10; t++) {
            Conn c, s;
            if (!Loopback(c, s, disabled)) continue;
            auto a = Enc(c, 16);
            auto bad = a;
            bad[bad.size() - 1] ^= 0x01;
            size_t dl = 0, el = 0;
            SECURITY_STATUS s1 = One(s, bad, &dl, &el);
            auto good = Enc(c, 16);
            SECURITY_STATUS s2 = One(s, good, &dl, &el);
            if (s1 != SEC_E_OK && s2 == SEC_E_OK) recovered++;
            else if (s1 != SEC_E_OK && s2 != SEC_E_OK) poisoned++;
        }
        printf("  %s: tampered then fresh -> recovered=%d poisoned=%d / 10\n",
               pass == 0 ? "TLS1.3" : "TLS1.2", recovered, poisoned);
    }

    printf("== C. consumed = size - extra (correct) vs header+data+trailer (wrong) ==\n");
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
        Conn c, s;
        if (!Loopback(c, s, disabled)) { printf("  hs fail\n"); continue; }
        auto a = Enc(c, 16);
        auto b = Enc(c, 16);
        std::vector<BYTE> both = a;
        both.insert(both.end(), b.begin(), b.end());
        std::vector<BYTE> buf(both);
        SecBuffer bs[4];
        for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
        bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
        SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
        SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
        unsigned long sum = 0, extra = 0;
        for (int i = 0; i < 4; i++) {
            sum += bs[i].cbBuffer;
            if (bs[i].BufferType == SECBUFFER_EXTRA) extra = bs[i].cbBuffer;
        }
        printf("  %s: input=%zu sum(cbBuffer)=%lu extra=%lu -> sum-overcounts-by=%ld\n",
               pass == 0 ? "TLS1.3" : "TLS1.2", both.size(), sum, extra, (long)sum - (long)both.size());
        printf("      bs[0]=%lu bs[1]=%lu bs[2]=%lu bs[3]=%lu types=%lu,%lu,%lu,%lu\n", bs[0].cbBuffer,
               bs[1].cbBuffer, bs[2].cbBuffer, bs[3].cbBuffer, bs[0].BufferType, bs[1].BufferType,
               bs[2].BufferType, bs[3].BufferType);
    }

    printf("== D. STREAM_SIZES vs actual record size ==\n");
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
        Conn c, s;
        if (!Loopback(c, s, disabled)) continue;
        for (size_t n : {1u, 16u, 1000u, 16384u}) {
            auto r = Enc(c, n);
            printf("  %s payload=%5zu actual=%5zu predicted(hdr+len+trl)=%5zu delta=%ld\n",
                   pass == 0 ? "TLS1.3" : "TLS1.2", n, r.size(),
                   c.sizes.cbHeader + n + c.sizes.cbTrailer,
                   (long)r.size() - (long)(c.sizes.cbHeader + n + c.sizes.cbTrailer));
        }
    }
    return 0;
}
