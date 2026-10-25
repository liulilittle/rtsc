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

static SECURITY_STATUS ClientCreds(Conn& c, DWORD flags, DWORD disabled) {
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    SCH_CREDENTIALS scr{};
    scr.dwVersion = SCH_CREDENTIALS_VERSION;
    scr.dwFlags = flags;
    scr.cTlsParameters = 1;
    scr.pTlsParameters = &tp;
    return AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                     SECPKG_CRED_OUTBOUND, nullptr, &scr, nullptr, nullptr, &c.cred, &ts);
}

static std::vector<BYTE> Step(Conn& c, const std::vector<BYTE>& in, SECURITY_STATUS& st,
                             const wchar_t* target) {
    std::vector<BYTE> out;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    SecBuffer ib{};
    SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
    if (!in.empty()) {
        ib = {(unsigned long)in.size(), SECBUFFER_TOKEN, const_cast<BYTE*>(in.data())};
        ibd.cBuffers = 1;
        ibd.pBuffers = &ib;
    }
    DWORD attrs = 0;
    DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                ISC_REQ_MANUAL_CRED_VALIDATION;
    st = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                    const_cast<SEC_WCHAR*>(target), req, 0, SECURITY_NATIVE_DREP,
                                    in.empty() ? nullptr : &ibd, 0, &c.ctx, &obd, &attrs, nullptr);
    c.haveCtx = true;
    if (ob.pvBuffer) {
        out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    return out;
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

static void Run(const char* label, const wchar_t* target, DWORD flags, DWORD disabled, int reuseCred) {
    printf("  [%s] target=%ls\n", label, target ? target : L"(null)");
    static Conn shared;
    Conn local;
    Conn& c = reuseCred ? shared : local;
    if (!reuseCred || !c.cred.dwLower && !c.cred.dwUpper) {
        SECURITY_STATUS cs = ClientCreds(c, flags, disabled);
        if (cs != SEC_E_OK) { printf("    cred -> %s\n", Hr(cs)); return; }
    }
    SOCKET sk = ConnectTo("192.168.1.7", 3389);
    if (sk == INVALID_SOCKET) { printf("    connect failed\n"); return; }
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED;
    int rounds = 0;
    for (int i = 0; i < 8; i++) {
        tok = Step(c, tok, stc, target);
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) { printf("    ISC -> %s\n", Hr(stc)); break; }
        if (!tok.empty()) send(sk, (const char*)tok.data(), (int)tok.size(), 0);
        if (stc == SEC_E_OK) break;
        rounds++;
        std::vector<BYTE> in(16384);
        int n = recv(sk, (char*)in.data(), (int)in.size(), 0);
        if (n <= 0) { printf("    recv %d\n", n); break; }
        in.resize(n);
        tok = in;
    }
    if (stc == SEC_E_OK) {
        SecPkgContext_ConnectionInfo ci{};
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
        printf("    OK rounds=%d proto=0x%lX cipher=0x%04X\n", rounds, (unsigned long)ci.dwProtocol,
               (unsigned)ci.aiCipher);
        DeleteSecurityContext(&c.ctx);
        c.haveCtx = false;
    }
    closesocket(sk);
}

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    DWORD manual = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    printf("== target name / SNI variants (real server) ==\n");
    Run("target=IP + NO_SERVERNAME_CHECK", L"192.168.1.7", manual | SCH_CRED_NO_SERVERNAME_CHECK, 0, 0);
    Run("target=NULL + NO_SERVERNAME_CHECK", nullptr, manual | SCH_CRED_NO_SERVERNAME_CHECK, 0, 0);
    Run("target=NULL, manual only", nullptr, manual, 0, 0);
    Run("target=IP, manual only (hostname check)", L"192.168.1.7", manual, 0, 0);
    Run("target=wrong name, manual only", L"example.com", manual, 0, 0);
    printf("== reuse credential across 2 connections (session resumption?) ==\n");
    Run("conn 1", L"192.168.1.7", manual | SCH_CRED_NO_SERVERNAME_CHECK, 0, 1);
    Run("conn 2", L"192.168.1.7", manual | SCH_CRED_NO_SERVERNAME_CHECK, 0, 1);
    printf("== TLS1.0/1.1 only against a 1.2/1.3 server (expect failure) ==\n");
    Run("disable 1.2+1.3", L"192.168.1.7", manual | SCH_CRED_NO_SERVERNAME_CHECK,
        SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT, 0);
    WSACleanup();
    return 0;
}
