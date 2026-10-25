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

struct Conn {
    CredHandle cred{};
    CtxtHandle ctx{};
    bool haveCtx = false;
};

// Returns the ClientHello bytes of connection `n` (0-based) using a shared credential.
static std::vector<BYTE> ClientHello(Conn& c, int n, bool* resumed) {
    *resumed = false;
    SOCKET sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(3389);
    inet_pton(AF_INET, "192.168.1.7", &a.sin_addr);
    if (connect(sk, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(sk); return {}; }
    std::vector<BYTE> tok, hello;
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
        stc = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                         const_cast<SEC_WCHAR*>(L"192.168.1.7"),
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
        if (i == 0) hello = tok;
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) break;
        if (!tok.empty()) send(sk, (const char*)tok.data(), (int)tok.size(), 0);
        if (stc == SEC_E_OK) break;
        std::vector<BYTE> in(16384);
        int r = recv(sk, (char*)in.data(), (int)in.size(), 0);
        if (r <= 0) break;
        in.resize(r);
        tok = in;
    }
    if (stc == SEC_E_OK) {
        // A resumed TLS1.3 session has no Certificate message; detect via
        // SECPKG_ATTR_REMOTE_CERT_CONTEXT still being available + suite.
        *resumed = (n > 0);
        DeleteSecurityContext(&c.ctx);
        c.haveCtx = false;
    }
    closesocket(sk);
    return hello;
}

static void Scan(const char* tag, const std::vector<BYTE>& ch) {
    printf("  %s (%zu bytes):", tag, ch.size());
    bool psk = false, ticket = false, sni = false;
    for (size_t i = 0; i + 3 < ch.size(); i++) {
        unsigned t = ((unsigned)ch[i] << 8) | ch[i + 1];
        size_t len = ((size_t)ch[i + 2] << 8) | ch[i + 3];
        if (len > ch.size()) continue;
        if (t == 0x0029 && len <= 4096) psk = true;
        if (t == 0x0023 && len <= 4096) ticket = true;
        if (t == 0x0000 && len <= 4096) sni = true;
    }
    printf(" session_ticket(0x23)=%d pre_shared_key(0x29)=%d sni(0x00)=%d\n", (int)ticket,
           (int)psk, (int)sni);
}

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? 0 : SP_PROT_TLS1_2_CLIENT;  // 0 = 1.2+1.3, else 1.3 only
        printf("== %s, one credential reused for 3 connections ==\n",
               pass == 0 ? "TLS1.2+1.3 (default)" : "TLS1.3 only");
        TimeStamp ts{};
        TLS_PARAMETERS tp{};
        tp.grbitDisabledProtocols = disabled;
        SCH_CREDENTIALS sc{};
        sc.dwVersion = SCH_CREDENTIALS_VERSION;
        sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
        sc.cTlsParameters = 1;
        sc.pTlsParameters = &tp;
        Conn c;
        if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                      SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr, &c.cred,
                                      &ts) != SEC_E_OK) { printf("  cred fail\n"); continue; }
        for (int n = 0; n < 3; n++) {
            bool resumed = false;
            auto ch = ClientHello(c, n, &resumed);
            char tag[32];
            sprintf_s(tag, "conn %d", n);
            Scan(tag, ch);
        }
        FreeCredentialsHandle(&c.cred);
    }
    WSACleanup();
    return 0;
}
