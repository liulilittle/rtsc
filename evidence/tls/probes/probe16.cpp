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

static SOCKET ConnectTo(const char* host, int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

struct Conn {
    CredHandle cred{};
    CtxtHandle ctx{};
    bool haveCtx = false;
};

static void Try(const char* label, DWORD protos) {
    TimeStamp ts{};
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = protos;
    sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    Conn c;
    SECURITY_STATUS cs = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                                   SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
                                                   nullptr, &c.cred, &ts);
    printf("  %-34s protos=0x%04lX cred=%s", label, (unsigned long)protos, Hr(cs));
    if (cs != SEC_E_OK) { printf("\n"); return; }
    SOCKET sk = ConnectTo("192.168.1.7", 3389);
    if (sk == INVALID_SOCKET) { printf(" connect-fail\n"); return; }
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
        if (i == 0 && tok.size() > 5)
            printf(" CHver=%02x%02x", tok[1], tok[2]);
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) { printf(" ISC=%s", Hr(stc)); break; }
        if (!tok.empty()) send(sk, (const char*)tok.data(), (int)tok.size(), 0);
        if (stc == SEC_E_OK) break;
        std::vector<BYTE> in(16384);
        int n = recv(sk, (char*)in.data(), (int)in.size(), 0);
        if (n <= 0) { printf(" recv=%d", n); break; }
        in.resize(n);
        tok = in;
    }
    if (stc == SEC_E_OK) {
        SecPkgContext_ConnectionInfo ci{};
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
        SecPkgContext_StreamSizes ss{};
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &ss);
        printf(" -> proto=0x%04lX aiCipher=0x%04X aiHash=0x%04X aiKeyExch=0x%04X bits=%lu hdr=%lu trl=%lu", (unsigned long)ci.dwProtocol, (unsigned)ci.aiCipher, (unsigned)ci.aiHash, (unsigned)ci.aiKeyExchange, (unsigned long)ci.dwCipherStrength, ss.cbHeader, ss.cbTrailer);
        DeleteSecurityContext(&c.ctx);
    }
    printf("\n");
    closesocket(sk);
}

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    printf("== protocol floor probe (legacy SCHANNEL_CRED) ==\n");
    Try("TLS1.0 only", SP_PROT_TLS1_0_CLIENT);
    Try("TLS1.1 only", SP_PROT_TLS1_1_CLIENT);
    Try("TLS1.0|1.1", SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT);
    Try("TLS1.2 only", SP_PROT_TLS1_2_CLIENT);
    Try("TLS1.2|1.3 (legacy cred)", SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT);
    Try("SSL3 only", SP_PROT_SSL3_CLIENT);
    WSACleanup();
    return 0;
}
