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
    static char b[8][24];
    static int i = 0;
    i = (i + 1) % 8;
    sprintf_s(b[i], "0x%08lX", (unsigned long)hr);
    return b[i];
}

struct Session {
    CredHandle cred{};
    CtxtHandle ctx{};
    SOCKET sk = INVALID_SOCKET;
};

static bool Connect(Session& s, DWORD disabled, DWORD* protoOut) {
    WSADATA w{};
    static bool wsa = false;
    if (!wsa) { WSAStartup(MAKEWORD(2, 2), &w); wsa = true; }
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                  nullptr, &sc, nullptr, nullptr, &s.cred, &ts) != SEC_E_OK) return false;
    s.sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(3389);
    inet_pton(AF_INET, "192.168.1.7", &a.sin_addr);
    if (connect(s.sk, (sockaddr*)&a, sizeof(a)) != 0) return false;
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 8; i++) {
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
        stc = InitializeSecurityContextW(&s.cred, i ? &s.ctx : nullptr,
                                         const_cast<SEC_WCHAR*>(L"192.168.1.7"),
                                         ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                                             ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                                             ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                                             ISC_REQ_MANUAL_CRED_VALIDATION,
                                         0, SECURITY_NATIVE_DREP, tok.empty() ? nullptr : &ibd, 0,
                                         &s.ctx, &obd, &attrs, nullptr);
        tok.clear();
        if (ob.pvBuffer) {
            tok.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
            FreeContextBuffer(ob.pvBuffer);
        }
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) return false;
        if (!tok.empty()) send(s.sk, (const char*)tok.data(), (int)tok.size(), 0);
        if (stc == SEC_E_OK) break;
        std::vector<BYTE> in(16384);
        int r = recv(s.sk, (char*)in.data(), (int)in.size(), 0);
        if (r <= 0) return false;
        in.resize(r);
        tok = in;
    }
    if (stc != SEC_E_OK) return false;
    SecPkgContext_ConnectionInfo ci{};
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
    if (protoOut) *protoOut = ci.dwProtocol;
    return true;
}

int main() {
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? SP_PROT_TLS1_2_CLIENT : SP_PROT_TLS1_3_CLIENT;
        DWORD proto = 0;
        Session s;
        if (!Connect(s, disabled, &proto)) { printf("connect fail\n"); continue; }
        printf("== proto=0x%04lX ==\n", (unsigned long)proto);
        DWORD tv = 1500;
        setsockopt(s.sk, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        std::vector<BYTE> in(65536);
        int n = recv(s.sk, (char*)in.data(), (int)in.size(), 0);
        printf("  post-handshake recv -> %d bytes\n", n);
        if (n <= 0) { closesocket(s.sk); continue; }
        in.resize(n);
        printf("  first bytes:");
        for (int i = 0; i < 16 && i < n; i++) printf(" %02x", in[i]);
        printf("\n");
        // parse outer record types
        size_t off = 0;
        while (off + 5 <= in.size()) {
            unsigned type = in[off];
            size_t len = ((size_t)in[off + 3] << 8) | in[off + 4];
            printf("    record type=0x%02x len=%zu\n", type, len);
            off += 5 + len;
        }
        std::vector<BYTE> pending = in;
        for (int guard = 0; guard < 8 && !pending.empty(); guard++) {
            std::vector<BYTE> buf(pending);
            SecBuffer bs[4];
            for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
            bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
            SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
            SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
            printf("    decrypt iter %d (%zu B) -> %s", guard, buf.size(), Hr(st));
            for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
            printf("\n");
            if (st == SEC_I_RENEGOTIATE) {
                // The EXTRA buffer holds the raw post-handshake TLS message.
                for (int i = 0; i < 4; i++) {
                    if (bs[i].BufferType == SECBUFFER_EXTRA && bs[i].cbBuffer) {
                        const BYTE* p = (const BYTE*)bs[i].pvBuffer;
                        printf("      EXTRA %lu bytes:", bs[i].cbBuffer);
                        for (unsigned long k = 0; k < bs[i].cbBuffer && k < 12; k++)
                            printf(" %02x", p[k]);
                        printf("\n      handshake type=0x%02x (0x04=NewSessionTicket, 0x14=Finished)\n",
                               bs[i].cbBuffer >= 5 ? p[5] : 0);
                    }
                }
                // Continue the "renegotiation" by feeding EXTRA back into ISC.
                std::vector<BYTE> extra;
                for (int i = 0; i < 4; i++)
                    if (bs[i].BufferType == SECBUFFER_EXTRA && bs[i].cbBuffer)
                        extra.assign((BYTE*)bs[i].pvBuffer, (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
                SecBuffer ib{};
                SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
                if (!extra.empty()) {
                    ib = {(unsigned long)extra.size(), SECBUFFER_TOKEN, extra.data()};
                    ibd.cBuffers = 1;
                    ibd.pBuffers = &ib;
                }
                SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
                SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
                DWORD attrs = 0;
                SECURITY_STATUS st2 = InitializeSecurityContextW(
                    &s.cred, &s.ctx, const_cast<SEC_WCHAR*>(L"192.168.1.7"),
                    ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION,
                    0, SECURITY_NATIVE_DREP, extra.empty() ? nullptr : &ibd, 0, &s.ctx, &obd,
                    &attrs, nullptr);
                printf("      ISC(after RENEGOTIATE) -> %s out=%lu\n", Hr(st2), ob.cbBuffer);
                if (ob.pvBuffer) FreeContextBuffer(ob.pvBuffer);
                pending.clear();
                break;
            }
            if (st != SEC_E_OK) break;
            std::vector<BYTE> extra;
            for (int i = 0; i < 4; i++)
                if (bs[i].BufferType == SECBUFFER_EXTRA && bs[i].cbBuffer)
                    extra.assign((BYTE*)bs[i].pvBuffer, (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
            pending = extra;
        }
        // Is the context still usable for application data after all this?
        std::vector<BYTE> rec(5 + 16 + 44);
        SecBuffer ebs[3];
        ebs[0] = {5, SECBUFFER_STREAM_HEADER, rec.data()};
        ebs[1] = {16, SECBUFFER_DATA, rec.data() + 5};
        ebs[2] = {44, SECBUFFER_STREAM_TRAILER, rec.data() + 5 + 16};
        SecBufferDesc ebd{SECBUFFER_VERSION, 3, ebs};
        SECURITY_STATUS es = EncryptMessage(&s.ctx, 0, &ebd, 0);
        printf("  EncryptMessage after post-handshake -> %s (context usable=%d)\n", Hr(es),
               (int)(es == SEC_E_OK));
        closesocket(s.sk);
        DeleteSecurityContext(&s.ctx);
        FreeCredentialsHandle(&s.cred);
    }
    return 0;
}
