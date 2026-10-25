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

// mode 0 = legacy SCHANNEL_CRED, 1 = SCH_CREDENTIALS (v5)
static bool Creds(Conn& c, bool client, DWORD protos, int mode) {
    TimeStamp ts{};
    if (mode == 0) {
        SCHANNEL_CRED sc{};
        sc.dwVersion = SCHANNEL_CRED_VERSION;
        sc.grbitEnabledProtocols = protos;
        sc.dwFlags = client ? (SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION |
                               SCH_CRED_NO_DEFAULT_CREDS)
                            : 0;
        PCCERT_CONTEXT cert = nullptr;
        if (!client) { if (!MakeCert(&cert)) return false; sc.cCreds = 1; sc.paCred = &cert; }
        SECURITY_STATUS st = AcquireCredentialsHandleW(
            nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
            client ? SECPKG_CRED_OUTBOUND : SECPKG_CRED_INBOUND, nullptr, &sc, nullptr, nullptr,
            &c.cred, &ts);
        printf("    AcquireCredentialsHandle(mode=legacy, protos=0x%lX, %s) -> %s\n",
               (unsigned long)protos, client ? "client" : "server", Hr(st));
        return st == SEC_E_OK;
    }
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = 0;
    SCH_CREDENTIALS scr{};
    scr.dwVersion = SCH_CREDENTIALS_VERSION;
    scr.dwFlags = client ? (SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION |
                            SCH_CRED_NO_DEFAULT_CREDS)
                         : 0;
    scr.cTlsParameters = 1;
    scr.pTlsParameters = &tp;
    PCCERT_CONTEXT cert = nullptr;
    if (!client) { if (!MakeCert(&cert)) return false; scr.cCreds = 1; scr.paCred = &cert; }
    SECURITY_STATUS st = AcquireCredentialsHandleW(
        nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
        client ? SECPKG_CRED_OUTBOUND : SECPKG_CRED_INBOUND, nullptr, &scr, nullptr, nullptr,
        &c.cred, &ts);
    printf("    AcquireCredentialsHandle(mode=SCH_CREDENTIALS, %s) -> %s\n",
           client ? "client" : "server", Hr(st));
    return st == SEC_E_OK;
}

static std::vector<BYTE> Step(Conn& c, const std::vector<BYTE>& in, SECURITY_STATUS& st, bool client) {
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

static bool Handshake(Conn& c, Conn& s, int mode, DWORD protos) {
    printf("  [handshake mode=%d protos=0x%lX]\n", mode, (unsigned long)protos);
    if (!Creds(c, true, protos, mode)) return false;
    if (!Creds(s, false, protos, mode)) return false;
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 12; i++) {
        tok = Step(c, tok, stc, true);
        printf("    c: %zu B %s\n", tok.size(), Hr(stc));
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) return false;
        if (tok.empty() && stc == SEC_E_OK) break;
        tok = Step(s, tok, sts, false);
        printf("    s: %zu B %s\n", tok.size(), Hr(sts));
        if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) return false;
        if (sts == SEC_E_OK && stc == SEC_E_OK) break;
    }
    if (stc != SEC_E_OK || sts != SEC_E_OK) return false;
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &c.sizes);
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    SecPkgContext_ConnectionInfo ci{};
    if (QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK)
        printf("    proto=0x%08lX cipher=0x%04X bits=%lu\n", (unsigned long)ci.dwProtocol,
               (unsigned)ci.aiCipher, (unsigned long)ci.dwCipherStrength);
    printf("    sizes hdr=%lu trl=%lu max=%lu blk=%lu\n", c.sizes.cbHeader, c.sizes.cbTrailer,
           c.sizes.cbMaximumMessage, c.sizes.cbBlockSize);
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

static SECURITY_STATUS Dec(Conn& s, const std::vector<BYTE>& in, int nb, const char* tag) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, (unsigned long)nb, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    printf("    %-24s in=%4zu nb=%d -> %s", tag, in.size(), nb, Hr(st));
    for (int i = 0; i < nb; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
    printf("\n");
    return st;
}

int main() {
    printf("== 1. TLS1.3 with legacy SCHANNEL_CRED ==\n");
    {
        Conn c, s;
        Handshake(c, s, 0, SP_PROT_TLS1_3);
    }
    printf("== 2. TLS1.3 with SCH_CREDENTIALS v5 ==\n");
    {
        Conn c, s;
        if (Handshake(c, s, 1, 0)) {
            SECURITY_STATUS st;
            auto r = Enc(c, 16, st);
            printf("    record %zu bytes:", r.size());
            for (size_t i = 0; i < r.size() && i < 12; i++) printf(" %02x", r[i]);
            printf("\n");
            Dec(s, r, 4, "tls1.3 record");
        }
    }
    printf("== 3. TLS1.2 via SCH_CREDENTIALS ==\n");
    {
        Conn c, s;
        if (Handshake(c, s, 1, 0)) {
            SECURITY_STATUS st;
            Dec(s, Enc(c, 16, st), 4, "tls1.2 record");
        }
    }
    printf("== 4. 2-buffer vs 4-buffer (repeat, order swapped) ==\n");
    {
        Conn c, s;
        if (Handshake(c, s, 0, SP_PROT_TLS1_2)) {
            SECURITY_STATUS st;
            auto r1 = Enc(c, 16, st);
            Dec(s, r1, 4, "4-buffer");
            auto r2 = Enc(c, 16, st);
            Dec(s, r2, 2, "2-buffer");
            auto r3 = Enc(c, 16, st);
            Dec(s, r3, 3, "3-buffer");
        }
    }
    printf("== 5. EXTRA dropped -> next record ==\n");
    {
        Conn c, s;
        if (Handshake(c, s, 0, SP_PROT_TLS1_2)) {
            SECURITY_STATUS st;
            auto a = Enc(c, 16, st);
            auto b = Enc(c, 16, st);
            std::vector<BYTE> both = a;
            both.insert(both.end(), b.begin(), b.end());
            Dec(s, both, 4, "a||b (extra dropped)");
            Dec(s, Enc(c, 16, st), 4, "c after dropped extra");
        }
    }
    printf("== 6. close_notify variants ==\n");
    {
        Conn c, s;
        if (Handshake(c, s, 0, SP_PROT_TLS1_2)) {
            DWORD ctl = SCHANNEL_SHUTDOWN;
            SecBuffer cb{sizeof(ctl), SECBUFFER_TOKEN, &ctl};
            SecBufferDesc cbd{SECBUFFER_VERSION, 1, &cb};
            printf("    ApplyControlToken -> %s\n", Hr(ApplyControlToken(&c.ctx, &cbd)));
            // variant A: empty input desc
            {
                SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
                SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
                SecBuffer ib{0, SECBUFFER_EMPTY, nullptr};
                SecBufferDesc ibd{SECBUFFER_VERSION, 1, &ib};
                DWORD attrs = 0;
                SECURITY_STATUS st = InitializeSecurityContextW(
                    &c.cred, &c.ctx, const_cast<SEC_WCHAR*>(L"x"), ISC_REQ_STREAM, 0,
                    SECURITY_NATIVE_DREP, &ibd, 0, &c.ctx, &obd, &attrs, nullptr);
                printf("    A) ISC(empty desc) -> %s out=%lu\n", Hr(st), ob.cbBuffer);
                if (ob.cbBuffer) {
                    std::vector<BYTE> cn((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
                    Dec(s, cn, 4, "close_notify");
                    FreeContextBuffer(ob.pvBuffer);
                }
            }
        }
    }
    printf("== 7. 1-byte close_notify split (partial record) ==\n");
    {
        Conn c, s;
        if (Handshake(c, s, 0, SP_PROT_TLS1_2)) {
            DWORD ctl = SCHANNEL_SHUTDOWN;
            SecBuffer cb{sizeof(ctl), SECBUFFER_TOKEN, &ctl};
            SecBufferDesc cbd{SECBUFFER_VERSION, 1, &cb};
            ApplyControlToken(&c.ctx, &cbd);
            SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
            SecBuffer ib{0, SECBUFFER_EMPTY, nullptr};
            SecBufferDesc ibd{SECBUFFER_VERSION, 1, &ib};
            DWORD attrs = 0;
            SECURITY_STATUS st = InitializeSecurityContextW(
                &c.cred, &c.ctx, const_cast<SEC_WCHAR*>(L"x"), ISC_REQ_STREAM, 0,
                SECURITY_NATIVE_DREP, &ibd, 0, &c.ctx, &obd, &attrs, nullptr);
            if (ob.cbBuffer) {
                std::vector<BYTE> cn((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
                printf("    close_notify %zu bytes:", cn.size());
                for (size_t i = 0; i < cn.size() && i < 10; i++) printf(" %02x", cn[i]);
                printf("\n");
                Dec(s, std::vector<BYTE>(cn.begin(), cn.begin() + 3), 4, "partial(3B)");
                Dec(s, cn, 4, "rest");
                FreeContextBuffer(ob.pvBuffer);
            }
        }
    }
    return 0;
}
