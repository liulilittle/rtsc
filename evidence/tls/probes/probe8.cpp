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

static SECURITY_STATUS Dec(Conn& s, const std::vector<BYTE>& in, const char* tag) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    printf("    %-34s in=%5zu -> %s", tag, in.size(), Hr(st));
    for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
    printf("\n");
    return st;
}

int main() {
    printf("== A. how many records can one DecryptMessage call take? ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_2)) { printf("hs fail\n"); return 1; }
        for (int n = 1; n <= 5; n++) {
            std::vector<BYTE> all;
            for (int i = 0; i < n; i++) {
                auto r = Enc(c, 16);
                all.insert(all.end(), r.begin(), r.end());
            }
            std::vector<BYTE> buf(all);
            SecBuffer bs[4];
            for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
            bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
            SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
            SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
            printf("    n=%d (%zu B) -> %s", n, all.size(), Hr(st));
            for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
            printf("\n");
            // drain EXTRA fully
            int guard = 0;
            while (st == SEC_E_OK && guard++ < 10) {
                SecBuffer* ex = nullptr;
                for (int i = 0; i < 4; i++)
                    if (bs[i].BufferType == SECBUFFER_EXTRA) ex = &bs[i];
                if (!ex || ex->cbBuffer == 0) break;
                std::vector<BYTE> e((BYTE*)ex->pvBuffer, (BYTE*)ex->pvBuffer + ex->cbBuffer);
                for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
                bs[0] = {(unsigned long)e.size(), SECBUFFER_DATA, e.data()};
                SecBufferDesc d2{SECBUFFER_VERSION, 4, bs};
                st = DecryptMessage(&s.ctx, &d2, 0, nullptr);
                printf("      drain EXTRA %zu B -> %s", e.size(), Hr(st));
                for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
                printf("\n");
            }
        }
    }

    printf("== B. server-initiated renegotiation via ApplyControlToken(SCHANNEL_RENEGOTIATE) ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_2)) { printf("hs fail\n"); return 1; }
        Dec(s, Enc(c, 16), "app data");
        DWORD ctl = SCHANNEL_RENEGOTIATE;
        SecBuffer cb{sizeof(ctl), SECBUFFER_TOKEN, &ctl};
        SecBufferDesc cbd{SECBUFFER_VERSION, 1, &cb};
        SECURITY_STATUS act = ApplyControlToken(&s.ctx, &cbd);
        printf("    server ApplyControlToken(RENEGOTIATE) -> %s\n", Hr(act));
        // drive the server side to emit its ClientHello-equivalent (HelloRequest)
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        DWORD attrs = 0;
        SECURITY_STATUS st = AcceptSecurityContext(&s.cred, &s.ctx, nullptr, ASC_REQ_STREAM,
                                                   SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
        printf("    server ASC(no input) -> %s, %lu B\n", Hr(st), ob.cbBuffer);
        if (ob.cbBuffer) {
            std::vector<BYTE> hello((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
            printf("    bytes:");
            for (size_t i = 0; i < hello.size() && i < 10; i++) printf(" %02x", hello[i]);
            printf("\n");
            std::vector<BYTE> buf(hello);
            SecBuffer bs[4];
            for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
            bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
            SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
            SECURITY_STATUS dst = DecryptMessage(&c.ctx, &d, 0, nullptr);
            printf("    client DecryptMessage -> %s", Hr(dst));
            for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
            printf("\n");
            FreeContextBuffer(ob.pvBuffer);
        }
    }

    printf("== C. same with TLS1.3 ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_3)) { printf("hs fail\n"); return 1; }
        Dec(s, Enc(c, 16), "app data");
        DWORD ctl = SCHANNEL_RENEGOTIATE;
        SecBuffer cb{sizeof(ctl), SECBUFFER_TOKEN, &ctl};
        SecBufferDesc cbd{SECBUFFER_VERSION, 1, &cb};
        printf("    server ApplyControlToken(RENEGOTIATE) -> %s\n", Hr(ApplyControlToken(&s.ctx, &cbd)));
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        DWORD attrs = 0;
        SECURITY_STATUS st = AcceptSecurityContext(&s.cred, &s.ctx, nullptr, ASC_REQ_STREAM,
                                                   SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
        printf("    server ASC -> %s, %lu B\n", Hr(st), ob.cbBuffer);
    }

    printf("== D. ClientHello injection: 1 record, 2 records with EXTRA, 5 records ==\n");
    {
        Conn c, s;
        if (!Loopback(c, s, SP_PROT_TLS1_2)) { printf("hs fail\n"); return 1; }
        auto r = Enc(c, 16);
        std::vector<BYTE> two = r;
        auto r2 = Enc(c, 16);
        two.insert(two.end(), r2.begin(), r2.end());
        Dec(s, two, "2 records, drain not performed");
        Dec(s, Enc(c, 16), "next record after EXTRA lost");
    }
    return 0;
}
