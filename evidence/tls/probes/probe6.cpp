#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>
#include <schannel.h>
#include <credssp.h>
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
        {
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
        }
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) return false;
        if (tok.empty() && stc == SEC_E_OK) break;
        {
            SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
            SecBuffer ib = {(unsigned long)tok.size(), SECBUFFER_TOKEN, tok.data()};
            SecBufferDesc ibd{SECBUFFER_VERSION, 1, &ib};
            DWORD attrs = 0;
            sts = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr, &ibd,
                                        ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                            ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                                            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                                        SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
            s.haveCtx = true;
            tok.clear();
            if (ob.pvBuffer) {
                tok.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
                FreeContextBuffer(ob.pvBuffer);
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

static void Dec(Conn& s, const std::vector<BYTE>& in, const char* tag) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    printf("    %-26s in=%4zu -> %s", tag, in.size(), Hr(st));
    for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
    printf("\n");
}

int main() {
    printf("== 1. TLS1.2 server-initiated renegotiation ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_2)) { printf("hs fail\n"); return 1; }
        Dec(s, Enc(c, 16), "app data");
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        DWORD attrs = 0;
        SECURITY_STATUS st = AcceptSecurityContext(&s.cred, &s.ctx, nullptr, ASC_REQ_STREAM,
                                                   SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
        printf("    server ASC(no input) -> %s, %lu B\n", Hr(st), ob.cbBuffer);
        if (ob.cbBuffer) {
            std::vector<BYTE> hello((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
            printf("    hello bytes:");
            for (size_t i = 0; i < hello.size() && i < 8; i++) printf(" %02x", hello[i]);
            printf("\n");
            // client decrypts: should be SEC_I_RENEGOTIATE
            std::vector<BYTE> buf(hello);
            SecBuffer bs[4];
            for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
            bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
            SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
            SECURITY_STATUS dst = DecryptMessage(&c.ctx, &d, 0, nullptr);
            printf("    client DecryptMessage -> %s", Hr(dst));
            for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
            printf("\n");
            if (dst == SEC_I_RENEGOTIATE) {
                // continue handshake using the EXTRA bytes as input token
                SecBuffer* extra = nullptr;
                for (int i = 0; i < 4; i++)
                    if (bs[i].BufferType == SECBUFFER_EXTRA) extra = &bs[i];
                printf("    EXTRA present=%d cb=%lu\n", extra ? 1 : 0,
                       extra ? extra->cbBuffer : 0);
                SecBuffer ib = {extra ? extra->cbBuffer : 0, SECBUFFER_TOKEN,
                                extra ? extra->pvBuffer : nullptr};
                SecBufferDesc ibd{SECBUFFER_VERSION, (unsigned long)(extra ? 1 : 0), &ib};
                SecBuffer ob2{0, SECBUFFER_TOKEN, nullptr};
                SecBufferDesc obd2{SECBUFFER_VERSION, 1, &ob2};
                DWORD a2 = 0;
                SECURITY_STATUS st2 = InitializeSecurityContextW(
                    &c.cred, &c.ctx, const_cast<SEC_WCHAR*>(L"probe"), ISC_REQ_STREAM, 0,
                    SECURITY_NATIVE_DREP, extra ? &ibd : nullptr, 0, &c.ctx, &obd2, &a2, nullptr);
                printf("    client ISC(reneg) -> %s, %lu B\n", Hr(st2), ob2.cbBuffer);
                if (ob2.cbBuffer) {
                    std::vector<BYTE> flight((BYTE*)ob2.pvBuffer, (BYTE*)ob2.pvBuffer + ob2.cbBuffer);
                    SecBuffer ib2 = {(unsigned long)flight.size(), SECBUFFER_TOKEN, flight.data()};
                    SecBufferDesc ibd2{SECBUFFER_VERSION, 1, &ib2};
                    SecBuffer ob3{0, SECBUFFER_TOKEN, nullptr};
                    SecBufferDesc obd3{SECBUFFER_VERSION, 1, &ob3};
                    DWORD a3 = 0;
                    SECURITY_STATUS st3 = AcceptSecurityContext(&s.cred, &s.ctx, &ibd2,
                                                                ASC_REQ_STREAM, SECURITY_NATIVE_DREP,
                                                                &s.ctx, &obd3, &a3, nullptr);
                    printf("    server ASC(reneg) -> %s, %lu B\n", Hr(st3), ob3.cbBuffer);
                }
            }
        }
    }

    printf("== 2. TLS1.3 server-initiated renegotiation ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, SP_PROT_TLS1_3)) {
            Dec(s, Enc(c, 16), "app data");
            SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
            DWORD attrs = 0;
            SECURITY_STATUS st = AcceptSecurityContext(&s.cred, &s.ctx, nullptr, ASC_REQ_STREAM,
                                                       SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
            printf("    server ASC(no input) -> %s (0x00090360 = SEC_I_NO_RENEGOTIATION)\n", Hr(st));
        }
    }

    printf("== 3. security packages present ==\n");
    {
        ULONG c = 0;
        PSecPkgInfoW info = nullptr;
        if (EnumerateSecurityPackagesW(&c, &info) == SEC_E_OK) {
            for (ULONG i = 0; i < c; i++)
                if (wcscmp(info[i].Name, L"Schannel") == 0 || wcscmp(info[i].Name, L"CredSSP") == 0 ||
                    wcscmp(info[i].Name, L"Negotiate") == 0 || wcscmp(info[i].Name, L"NTLM") == 0)
                    printf("    %-12ls caps=0x%08lX maxTok=%lu\n", info[i].Name,
                           (unsigned long)info[i].fCapabilities, (unsigned long)info[i].cbMaxToken);
            FreeContextBuffer(info);
        }
    }

    printf("== 4. CredSSP package: AcquireCredentialsHandle ==\n");
    {
        TimeStamp ts{};
        CredHandle h{};
        SECURITY_STATUS st = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(L"CredSSP"),
                                                       SECPKG_CRED_OUTBOUND, nullptr, nullptr,
                                                       nullptr, nullptr, &h, &ts);
        printf("    AcquireCredentialsHandle(CredSSP, null authdata) -> %s\n", Hr(st));
        if (st == SEC_E_OK) FreeCredentialsHandle(&h);
        CREDSSP_CRED cc{};
        printf("    CREDSSP_CRED type enum exists (sizeof=%zu)\n", sizeof(cc));
    }

    printf("== 5. SChannel with ISC_REQ_USE_SUPPLIED_CREDS ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, SP_PROT_TLS1_2)) {
            // try requesting client cert with supplied creds
            SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
            DWORD attrs = 0;
            SECURITY_STATUS st = InitializeSecurityContextW(
                &c.cred, &c.ctx, const_cast<SEC_WCHAR*>(L"probe"),
                ISC_REQ_STREAM | ISC_REQ_USE_SUPPLIED_CREDS, 0, SECURITY_NATIVE_DREP, nullptr, 0,
                &c.ctx, &obd, &attrs, nullptr);
            printf("    ISC(+USE_SUPPLIED_CREDS) on established ctx -> %s\n", Hr(st));
        }
    }
    return 0;
}
