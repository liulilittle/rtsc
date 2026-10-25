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

static void Try(const char* label, DWORD disabled) {
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    Conn c;
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                  nullptr, &sc, nullptr, nullptr, &c.cred, &ts) != SEC_E_OK) {
        printf("  %s: cred fail\n", label);
        return;
    }
    SOCKET sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(3389);
    inet_pton(AF_INET, "192.168.1.7", &a.sin_addr);
    if (connect(sk, (sockaddr*)&a, sizeof(a)) != 0) { printf("  %s: connect fail\n", label); return; }
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
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) break;
        if (!tok.empty()) send(sk, (const char*)tok.data(), (int)tok.size(), 0);
        if (stc == SEC_E_OK) break;
        std::vector<BYTE> in(16384);
        int n = recv(sk, (char*)in.data(), (int)in.size(), 0);
        if (n <= 0) break;
        in.resize(n);
        tok = in;
    }
    if (stc == SEC_E_OK) {
        SecPkgContext_ConnectionInfo ci{};
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
        SecPkgContext_CipherInfo ciph{};
        ciph.dwVersion = SECPKG_ATTR_CIPHER_INFO;
        SECURITY_STATUS q = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CIPHER_INFO, &ciph);
        printf("  %-24s proto=0x%04lX aiCipher=0x%04X aiHash=0x%04X aiKeyExch=0x%04X bits=%lu\n",
               label, (unsigned long)ci.dwProtocol, (unsigned)ci.aiCipher, (unsigned)ci.aiHash,
               (unsigned long)ci.dwCipherStrength);
        if (q == SEC_E_OK)
            printf("      CIPHER_INFO -> 0x%04lX \"%ls\"  keyType=%lu exch=%lu hash=%lu cipherLen=%lu\n",
                   (unsigned long)ciph.dwCipherSuite, ciph.szCipherSuite,
                   (unsigned long)ciph.dwBaseCipherSuite, (unsigned long)ciph.dwCipherLen,
                   (unsigned long)ciph.dwHashLen, (unsigned long)ciph.dwCipherLen);
        else
            printf("      CIPHER_INFO -> 0x%08lX\n", (unsigned long)q);
        DeleteSecurityContext(&c.ctx);
    } else {
        printf("  %-24s handshake -> 0x%08lX\n", label, (unsigned long)stc);
    }
    closesocket(sk);
}

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    printf("== true negotiated cipher suite (SECPKG_ATTR_CIPHER_INFO) ==\n");
    Try("TLS1.2", SP_PROT_TLS1_3_CLIENT);
    Try("TLS1.3", SP_PROT_TLS1_2_CLIENT);
    Try("TLS1.0", SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT);
    WSACleanup();
    return 0;
}
