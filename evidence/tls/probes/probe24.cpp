#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "ws2_32.lib")

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

static std::vector<BYTE> Enc(Conn& c, const std::vector<BYTE>& plain) {
    std::vector<BYTE> rec(c.sizes.cbHeader + plain.size() + c.sizes.cbTrailer);
    SecBuffer bs[3];
    bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
    bs[1] = {(unsigned long)plain.size(), SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
    bs[2] = {c.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader + plain.size()};
    memcpy(bs[1].pvBuffer, plain.data(), plain.size());
    SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
    if (EncryptMessage(&c.ctx, 0, &d, 0) != SEC_E_OK) return {};
    rec.resize(bs[0].cbBuffer + bs[1].cbBuffer + bs[2].cbBuffer);
    return rec;
}

static SECURITY_STATUS Dec1(Conn& s, const std::vector<BYTE>& in, std::vector<BYTE>* data,
                            std::vector<BYTE>* extra, unsigned long* missing = nullptr) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    if (data) data->clear();
    if (extra) extra->clear();
    for (int i = 0; i < 4; i++) {
        if (bs[i].BufferType == SECBUFFER_DATA && bs[i].cbBuffer && data)
            data->assign((BYTE*)bs[i].pvBuffer, (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
        if (bs[i].BufferType == SECBUFFER_EXTRA && bs[i].cbBuffer && extra)
            extra->assign((BYTE*)bs[i].pvBuffer, (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
        if (bs[i].BufferType == SECBUFFER_MISSING && missing) *missing = bs[i].cbBuffer;
    }
    return st;
}

static void RenegTest(DWORD disabled) {
    Conn c, s;
    if (!Loopback(c, s, disabled)) { printf("  hs fail\n"); return; }
    SecPkgContext_ConnectionInfo ci{};
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
    printf("  proto=0x%04lX\n", (unsigned long)ci.dwProtocol);
    std::vector<BYTE> data, extra;
    SECURITY_STATUS st = Dec1(s, Enc(c, std::vector<BYTE>{'a'}), &data, &extra);
    printf("  app data: %s\n", Hr(st));
    // server initiates renegotiation
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    DWORD attrs = 0;
    SECURITY_STATUS sst = AcceptSecurityContext(&s.cred, &s.ctx, nullptr,
                                                ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                                    ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY |
                                                    ASC_REQ_STREAM,
                                                SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
    printf("  server ASC(no input, ALLOCATE) -> %s, %lu bytes\n", Hr(sst), ob.cbBuffer);
    if (!ob.pvBuffer || !ob.cbBuffer) return;
    std::vector<BYTE> hello((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
    FreeContextBuffer(ob.pvBuffer);
    printf("  server flight (%zu B):", hello.size());
    for (size_t i = 0; i < hello.size() && i < 10; i++) printf(" %02x", hello[i]);
    printf("\n");
    SECURITY_STATUS dst = Dec1(c, hello, &data, &extra);
    printf("  client DecryptMessage -> %s (0x00090321 = SEC_I_RENEGOTIATE) data=%zu extra=%zu\n",
           Hr(dst), data.size(), extra.size());
    if (dst == SEC_I_RENEGOTIATE) {
        // Continue the handshake. Input must be the bytes SChannel did not consume.
        std::vector<BYTE> feed = extra.empty() ? std::vector<BYTE>{} : extra;
        printf("  feeding %zu bytes of EXTRA into ISC\n", feed.size());
        SecBuffer ib{};
        SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
        if (!feed.empty()) {
            ib = {(unsigned long)feed.size(), SECBUFFER_TOKEN, feed.data()};
            ibd.cBuffers = 1;
            ibd.pBuffers = &ib;
        }
        SecBuffer ob2{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd2{SECBUFFER_VERSION, 1, &ob2};
        DWORD a2 = 0;
        SECURITY_STATUS st2 = InitializeSecurityContextW(
            &c.cred, &c.ctx, const_cast<SEC_WCHAR*>(L"probe"),
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION,
            0, SECURITY_NATIVE_DREP, feed.empty() ? nullptr : &ibd, 0, &c.ctx, &obd2, &a2, nullptr);
        printf("  client ISC(reneg) -> %s, %lu bytes\n", Hr(st2), ob2.cbBuffer);
        if (ob2.pvBuffer && ob2.cbBuffer) {
            std::vector<BYTE> flight((BYTE*)ob2.pvBuffer, (BYTE*)ob2.pvBuffer + ob2.cbBuffer);
            FreeContextBuffer(ob2.pvBuffer);
            SecBuffer ib3 = {(unsigned long)flight.size(), SECBUFFER_TOKEN, flight.data()};
            SecBufferDesc ibd3{SECBUFFER_VERSION, 1, &ib3};
            SecBuffer ob3{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd3{SECBUFFER_VERSION, 1, &ob3};
            DWORD a3 = 0;
            SECURITY_STATUS st3 = AcceptSecurityContext(
                &s.cred, &s.ctx, &ibd3,
                ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                    ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                SECURITY_NATIVE_DREP, &s.ctx, &obd3, &a3, nullptr);
            printf("  server ASC(reneg flight) -> %s, %lu bytes\n", Hr(st3), ob3.cbBuffer);
            if (ob3.pvBuffer) {
                std::vector<BYTE> f2((BYTE*)ob3.pvBuffer, (BYTE*)ob3.pvBuffer + ob3.cbBuffer);
                FreeContextBuffer(ob3.pvBuffer);
                // client consumes the final flight via ISC
                SecBuffer ib4 = {(unsigned long)f2.size(), SECBUFFER_TOKEN, f2.data()};
                SecBufferDesc ibd4{SECBUFFER_VERSION, 1, &ib4};
                SecBuffer ob4{0, SECBUFFER_TOKEN, nullptr};
                SecBufferDesc obd4{SECBUFFER_VERSION, 1, &ob4};
                DWORD a4 = 0;
                SECURITY_STATUS st4 = InitializeSecurityContextW(
                    &c.cred, &c.ctx, const_cast<SEC_WCHAR*>(L"probe"),
                    ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION,
                    0, SECURITY_NATIVE_DREP, &ibd4, 0, &c.ctx, &obd4, &a4, nullptr);
                printf("  client ISC(final) -> %s, %lu bytes\n", Hr(st4), ob4.cbBuffer);
                if (ob4.pvBuffer) FreeContextBuffer(ob4.pvBuffer);
                if (st4 == SEC_E_OK) {
                    std::vector<BYTE> d2, e2;
                    SECURITY_STATUS st5 = Dec1(c, Enc(s, std::vector<BYTE>{'z'}), &d2, &e2);
                    printf("  after renegotiation, decrypt -> %s data=%zu\n", Hr(st5), d2.size());
                }
            }
        }
    }
}

int main() {
    printf("== server-initiated renegotiation, TLS1.2 ==\n");
    RenegTest(SP_PROT_TLS1_3_CLIENT);
    printf("== server-initiated renegotiation, TLS1.3 ==\n");
    RenegTest(SP_PROT_TLS1_2_CLIENT);
    return 0;
}
