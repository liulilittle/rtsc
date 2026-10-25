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

// Feed `chunk` bytes; report status + missing hint. Returns status.
static SECURITY_STATUS Feed(Conn& s, const std::vector<BYTE>& chunk, unsigned long* missing,
                            unsigned long* dataLen, unsigned long* extraLen) {
    std::vector<BYTE> buf(chunk);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    *missing = 0;
    *dataLen = 0;
    *extraLen = 0;
    for (int i = 0; i < 4; i++) {
        if (bs[i].BufferType == SECBUFFER_MISSING) *missing = bs[i].cbBuffer;
        if (bs[i].BufferType == SECBUFFER_DATA) *dataLen = bs[i].cbBuffer;
        if (bs[i].BufferType == SECBUFFER_EXTRA) *extraLen = bs[i].cbBuffer;
    }
    return st;
}

static void Trial(const char* name, DWORD disabled, size_t payload, size_t firstChunk, int mode) {
    Conn c, s;
    if (!Loopback(c, s, disabled)) { printf("  hs fail\n"); return; }
    auto rec = Enc(c, payload);
    std::vector<BYTE> first(rec.begin(), rec.begin() + firstChunk);
    unsigned long miss = 0, dl = 0, el = 0;
    SECURITY_STATUS st = Feed(s, first, &miss, &dl, &el);
    printf("  %-46s rec=%5zu first=%4zu -> %s missing=%lu\n", name, rec.size(), firstChunk, Hr(st), miss);
    if (st != SEC_E_INCOMPLETE_MESSAGE) return;
    if (mode == 0) {
        // re-feed the whole cumulative buffer
        st = Feed(s, rec, &miss, &dl, &el);
        printf("      cumulative re-feed(%zu) -> %s data=%lu\n", rec.size(), Hr(st), dl);
    } else if (mode == 1) {
        // feed only the remainder
        std::vector<BYTE> rest(rec.begin() + firstChunk, rec.end());
        st = Feed(s, rest, &miss, &dl, &el);
        printf("      remainder only(%zu) -> %s data=%lu\n", rest.size(), Hr(st), dl);
    } else {
        // append remainder to a persistent buffer and re-feed all (same as mode 0 here)
        std::vector<BYTE> acc = first;
        acc.insert(acc.end(), rec.begin() + firstChunk, rec.end());
        st = Feed(s, acc, &miss, &dl, &el);
        printf("      append+re-feed(%zu) -> %s data=%lu\n", acc.size(), Hr(st), dl);
    }
}

int main() {
    printf("== small record (16B payload), TLS1.2 ==\n");
    Trial("re-feed cumulative", SP_PROT_TLS1_3_CLIENT, 16, 20, 0);
    Trial("feed remainder only", SP_PROT_TLS1_3_CLIENT, 16, 20, 1);
    Trial("append+re-feed", SP_PROT_TLS1_3_CLIENT, 16, 20, 2);
    printf("== large record (16384B payload), TLS1.2 ==\n");
    Trial("re-feed cumulative", SP_PROT_TLS1_3_CLIENT, 16384, 100, 0);
    Trial("feed remainder only", SP_PROT_TLS1_3_CLIENT, 16384, 100, 1);
    Trial("append+re-feed", SP_PROT_TLS1_3_CLIENT, 16384, 100, 2);
    printf("== large record split in 3 chunks, TLS1.2 ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, SP_PROT_TLS1_3_CLIENT)) {
            auto rec = Enc(c, 16384);
            size_t a = 100, b = 5000;
            unsigned long miss = 0, dl = 0, el = 0;
            SECURITY_STATUS st = Feed(s, std::vector<BYTE>(rec.begin(), rec.begin() + a), &miss, &dl, &el);
            printf("  chunk1(%zu) -> %s missing=%lu\n", a, Hr(st), miss);
            st = Feed(s, std::vector<BYTE>(rec.begin(), rec.begin() + b), &miss, &dl, &el);
            printf("  chunk1+2 cumulative(%zu) -> %s missing=%lu\n", b, Hr(st), miss);
            st = Feed(s, rec, &miss, &dl, &el);
            printf("  full(%zu) -> %s data=%lu\n", rec.size(), Hr(st), dl);
        }
    }
    printf("== 1-byte-at-a-time cumulative, small record, TLS1.2 ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, SP_PROT_TLS1_3_CLIENT)) {
            auto rec = Enc(c, 16);
            unsigned long miss = 0, dl = 0, el = 0;
            SECURITY_STATUS st = SEC_E_INCOMPLETE_MESSAGE;
            for (size_t k = 1; k < rec.size(); k++) {
                st = Feed(s, std::vector<BYTE>(rec.begin(), rec.begin() + k), &miss, &dl, &el);
                if (st != SEC_E_INCOMPLETE_MESSAGE) {
                    printf("  k=%zu -> %s data=%lu\n", k, Hr(st), dl);
                    break;
                }
            }
            st = Feed(s, rec, &miss, &dl, &el);
            printf("  final full -> %s data=%lu\n", Hr(st), dl);
        }
    }
    printf("== TLS1.3 equivalents ==\n");
    Trial("[1.3] re-feed cumulative", SP_PROT_TLS1_2_CLIENT, 16, 20, 0);
    Trial("[1.3] feed remainder only", SP_PROT_TLS1_2_CLIENT, 16, 20, 1);
    Trial("[1.3] large re-feed cumulative", SP_PROT_TLS1_2_CLIENT, 16384, 100, 0);
    return 0;
}
