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

static void Try(const char* label, DWORD disabled, DWORD extraFlags) {
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS |
                 SCH_CRED_NO_SERVERNAME_CHECK | extraFlags;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    CredHandle cred{};
    SECURITY_STATUS cs = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                                   SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
                                                   nullptr, &cred, &ts);
    printf("  %-52s disabled=0x%08lX cred=%s", label, (unsigned long)disabled,
           cs == 0 ? "OK" : "FAIL");
    if (cs != 0) { printf(" (0x%08lX)\n", (unsigned long)cs); return; }
    SOCKET sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(3389);
    inet_pton(AF_INET, "192.168.1.7", &a.sin_addr);
    if (connect(sk, (sockaddr*)&a, sizeof(a)) != 0) { printf(" connect fail\n"); return; }
    CtxtHandle ctx{};
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
        stc = InitializeSecurityContextW(&cred, i ? &ctx : nullptr,
                                         const_cast<SEC_WCHAR*>(L"192.168.1.7"),
                                         ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                                             ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                                             ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                                             ISC_REQ_MANUAL_CRED_VALIDATION,
                                         0, SECURITY_NATIVE_DREP, tok.empty() ? nullptr : &ibd, 0,
                                         &ctx, &obd, &attrs, nullptr);
        tok.clear();
        if (ob.pvBuffer) {
            tok.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
            FreeContextBuffer(ob.pvBuffer);
        }
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
        SecPkgContext_ConnectionInfo ci{};
        QueryContextAttributesW(&ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
        SecPkgContext_CipherInfo ciph{};
        ciph.dwVersion = SECPKG_ATTR_CIPHER_INFO;
        QueryContextAttributesW(&ctx, SECPKG_ATTR_CIPHER_INFO, &ciph);
        SecPkgContext_StreamSizes ss{};
        QueryContextAttributesW(&ctx, SECPKG_ATTR_STREAM_SIZES, &ss);
        printf(" -> proto=0x%04lX suite=0x%04lX %ls hdr=%lu trl=%lu\n", (unsigned long)ci.dwProtocol,
               (unsigned long)ciph.dwCipherSuite, ciph.szCipherSuite, ss.cbHeader, ss.cbTrailer);
        DeleteSecurityContext(&ctx);
    } else {
        printf(" -> handshake 0x%08lX\n", (unsigned long)stc);
    }
    closesocket(sk);
    FreeCredentialsHandle(&cred);
}

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    const DWORD kOld = SP_PROT_SSL3_CLIENT | SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT;
    printf("== disabled-protocol bitmask as a 'minimum version' mechanism ==\n");
    Try("baseline (nothing disabled)", 0, 0);
    Try("disable SSL3+1.0+1.1 (min=1.2)", kOld, 0);
    Try("disable everything except 1.2", SP_PROT_TLS1_3_CLIENT | kOld, 0);
    Try("disable everything except 1.3", SP_PROT_TLS1_2_CLIENT | kOld, 0);
    Try("disable all TLS (expect failure)", SP_PROT_TLS1_X_CLIENT, 0);
    Try("unknown bit 0x80000000 set", 0x80000000u, 0);
    Try("unknown bit 0x00000001 set", 0x00000001u, 0);
    Try("min=1.2 + SCH_USE_STRONG_CRYPTO", kOld, SCH_USE_STRONG_CRYPTO);
    printf("== TLS_PARAMS_OPTIONAL on a client (documented server-only) ==\n");
    {
        TimeStamp ts{};
        TLS_PARAMETERS tp{};
        tp.grbitDisabledProtocols = kOld;
        tp.dwFlags = TLS_PARAMS_OPTIONAL;
        SCH_CREDENTIALS sc{};
        sc.dwVersion = SCH_CREDENTIALS_VERSION;
        sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
        sc.cTlsParameters = 1;
        sc.pTlsParameters = &tp;
        CredHandle cred{};
        SECURITY_STATUS cs = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                                       SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
                                                       nullptr, &cred, &ts);
        printf("  TLS_PARAMS_OPTIONAL(client) -> 0x%08lX\n", (unsigned long)cs);
        if (cs == 0) FreeCredentialsHandle(&cred);
    }
    WSACleanup();
    return 0;
}
