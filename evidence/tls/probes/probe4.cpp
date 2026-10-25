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

static SECURITY_STATUS ClientCreds(Conn& c, DWORD flags, DWORD disabledProtos) {
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabledProtos;
    SCH_CREDENTIALS scr{};
    scr.dwVersion = SCH_CREDENTIALS_VERSION;
    scr.dwFlags = flags;
    scr.cTlsParameters = 1;
    scr.pTlsParameters = &tp;
    return AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                     SECPKG_CRED_OUTBOUND, nullptr, &scr, nullptr, nullptr, &c.cred, &ts);
}

static SECURITY_STATUS ServerCreds(Conn& s) {
    TimeStamp ts{};
    PCCERT_CONTEXT cert = nullptr;
    if (!MakeCert(&cert)) return E_FAIL;
    TLS_PARAMETERS tp{};
    SCH_CREDENTIALS scr{};
    scr.dwVersion = SCH_CREDENTIALS_VERSION;
    scr.cCreds = 1;
    scr.paCred = &cert;
    scr.cTlsParameters = 1;
    scr.pTlsParameters = &tp;
    return AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                     SECPKG_CRED_INBOUND, nullptr, &scr, nullptr, nullptr, &s.cred, &ts);
}

static std::vector<BYTE> Step(Conn& c, const std::vector<BYTE>& in, SECURITY_STATUS& st, bool client,
                             DWORD extraReq = 0) {
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
                    ISC_REQ_MANUAL_CRED_VALIDATION | extraReq;
        st = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                        const_cast<SEC_WCHAR*>(L"192.168.1.7"), req, 0,
                                        SECURITY_NATIVE_DREP, in.empty() ? nullptr : &ibd, 0,
                                        &c.ctx, &obd, &attrs, nullptr);
    } else {
        DWORD req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                    ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM | extraReq;
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

static bool Loopback(Conn& c, Conn& s, DWORD disabled) {
    if (ClientCreds(c, SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION |
                           SCH_CRED_NO_DEFAULT_CREDS,
                    disabled) != SEC_E_OK) return false;
    if (ServerCreds(s) != SEC_E_OK) return false;
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 12; i++) {
        tok = Step(c, tok, stc, true);
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) return false;
        if (tok.empty() && stc == SEC_E_OK) break;
        tok = Step(s, tok, sts, false);
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

static SECURITY_STATUS Dec(Conn& s, const std::vector<BYTE>& in, const char* tag) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    printf("    %-26s in=%4zu -> %s", tag, in.size(), Hr(st));
    for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
    printf("\n");
    return st;
}

static SOCKET ConnectTo(const char* host, int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

static void RealServer(DWORD flags, DWORD disabled, const char* label) {
    printf("  [%s] flags=0x%lX disabled=0x%lX\n", label, (unsigned long)flags, (unsigned long)disabled);
    Conn c;
    SECURITY_STATUS st = ClientCreds(c, flags, disabled);
    printf("    cred -> %s\n", Hr(st));
    if (st != SEC_E_OK) return;
    SOCKET sk = ConnectTo("192.168.1.7", 3389);
    if (sk == INVALID_SOCKET) { printf("    connect failed %d\n", WSAGetLastError()); return; }
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 8; i++) {
        tok = Step(c, tok, stc, true);
        printf("    c: %zu B %s\n", tok.size(), Hr(stc));
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) break;
        if (!tok.empty()) send(sk, (const char*)tok.data(), (int)tok.size(), 0);
        if (stc == SEC_E_OK) break;
        std::vector<BYTE> in(16384);
        int n = recv(sk, (char*)in.data(), (int)in.size(), 0);
        printf("    r: %d B\n", n);
        if (n <= 0) break;
        in.resize(n);
        tok = in;
    }
    if (stc == SEC_E_OK) {
        SecPkgContext_StreamSizes ss{};
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &ss);
        SecPkgContext_ConnectionInfo ci{};
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
        printf("    OK proto=0x%08lX cipher=0x%04X bits=%lu hdr=%lu trl=%lu max=%lu\n",
               (unsigned long)ci.dwProtocol, (unsigned)ci.aiCipher, (unsigned long)ci.dwCipherStrength,
               ss.cbHeader, ss.cbTrailer, ss.cbMaximumMessage);
        PCCERT_CONTEXT rc = nullptr;
        if (QueryContextAttributesW(&c.ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &rc) == SEC_E_OK && rc) {
            printf("    cert len=%lu subject-CN len=%lu\n", rc->cbCertEncoded,
                   rc->pCertInfo->Subject.cbData);
            CertFreeCertificateContext(rc);
        }
    }
    closesocket(sk);
    DeleteSecurityContext(&c.ctx);
    FreeCredentialsHandle(&c.cred);
}

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);

    printf("== A. real server 192.168.1.7:3389 ==\n");
    RealServer(SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS,
               0, "TLS1.2+1.3, manual validation + no name check");
    RealServer(SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS, 0,
               "manual validation only (no name-check flag)");
    RealServer(SCH_CRED_NO_DEFAULT_CREDS, 0, "auto validation (expect cert failure)");
    RealServer(SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS,
               SP_PROT_TLS1_3_CLIENT, "TLS1.3 disabled -> TLS1.2 only");
    RealServer(SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS,
               SP_PROT_TLS1_2_CLIENT, "TLS1.2 disabled -> TLS1.3 only");

    printf("== B. loopback renegotiation (server-initiated) ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, 0)) {
            SECURITY_STATUS st;
            auto r = Enc(c, 16, st);
            Dec(s, r, "record 1");
            // server asks for renegotiation: AcceptSecurityContext with no input
            SECURITY_STATUS sts = SEC_I_CONTINUE_NEEDED;
            std::vector<BYTE> hello = Step(s, {}, sts, false);
            printf("    server reneg request: %zu B %s\n", hello.size(), Hr(sts));
            if (!hello.empty()) {
                SECURITY_STATUS d = Dec(c, hello, "client sees HelloRequest");
                printf("    -> client DecryptMessage status %s\n", Hr(d));
                // complete renegotiation from the client side
                SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED;
                std::vector<BYTE> t = Step(c, hello, stc, true);
                printf("    client reneg flight: %zu B %s\n", t.size(), Hr(stc));
            }
        }
    }

    printf("== C. corrupted record ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, 0)) {
            SECURITY_STATUS st;
            auto r = Enc(c, 16, st);
            auto bad = r;
            bad[bad.size() - 1] ^= 0xFF;
            Dec(s, bad, "tampered tag");
            auto r2 = Enc(c, 16, st);
            Dec(s, r2, "next good record");
        }
    }

    printf("== D. close_notify with ALLOCATE_MEMORY ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, 0)) {
            DWORD ctl = SCHANNEL_SHUTDOWN;
            SecBuffer cb{sizeof(ctl), SECBUFFER_TOKEN, &ctl};
            SecBufferDesc cbd{SECBUFFER_VERSION, 1, &cb};
            printf("    ApplyControlToken -> %s\n", Hr(ApplyControlToken(&c.ctx, &cbd)));
            SECURITY_STATUS stc = SEC_E_OK;
            std::vector<BYTE> out = Step(c, {}, stc, true);
            printf("    ISC after shutdown -> %s, %zu B", Hr(stc), out.size());
            for (size_t i = 0; i < out.size() && i < 10; i++) printf(" %02x", out[i]);
            printf("\n");
            if (!out.empty()) {
                Dec(s, out, "close_notify");
                SECURITY_STATUS st2;
                auto r = Enc(c, 8, st2);
                printf("    encrypt after shutdown -> %s\n", Hr(st2));
                if (!r.empty()) Dec(s, r, "post-shutdown data");
            }
        }
    }

    printf("== E. TLS1.3 loopback record sizes vs TLS1.2 ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, 0)) {
            SecPkgContext_ConnectionInfo ci{};
            QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
            printf("    proto=0x%lX hdr=%lu trl=%lu max=%lu\n", (unsigned long)ci.dwProtocol,
                   c.sizes.cbHeader, c.sizes.cbTrailer, c.sizes.cbMaximumMessage);
        }
        Conn c2, s2;
        if (Loopback(c2, s2, SP_PROT_TLS1_3_CLIENT)) {
            SecPkgContext_ConnectionInfo ci{};
            QueryContextAttributesW(&c2.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
            printf("    TLS1.3-off proto=0x%lX hdr=%lu trl=%lu max=%lu\n", (unsigned long)ci.dwProtocol,
                   c2.sizes.cbHeader, c2.sizes.cbTrailer, c2.sizes.cbMaximumMessage);
        }
    }
    WSACleanup();
    return 0;
}
