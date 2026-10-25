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

static void Try(const char* label, bool disableRsaKex, bool disableAes256) {
    DWORD only12 = SP_PROT_TLS1_3_CLIENT;
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = only12;
    CRYPTO_SETTINGS cs[2] = {};
    DWORD n = 0;
    UNICODE_STRING rsa = {};
    UNICODE_STRING aes = {};
    if (disableRsaKex) {
        rsa.Buffer = const_cast<PWSTR>(L"RSA");
        rsa.Length = rsa.MaximumLength = (USHORT)(3 * sizeof(WCHAR));
        cs[n].eAlgorithmUsage = TlsParametersCngAlgUsageKeyExchange;
        cs[n].strCngAlgId = rsa;
        n++;
    }
    if (disableAes256) {
        aes.Buffer = const_cast<PWSTR>(L"AES");
        aes.Length = aes.MaximumLength = (USHORT)(3 * sizeof(WCHAR));
        cs[n].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
        cs[n].strCngAlgId = aes;
        cs[n].dwMinBitLength = 0;
        cs[n].dwMaxBitLength = 0;
        n++;
    }
    tp.cDisabledCrypto = n;
    tp.pDisabledCrypto = cs;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    CredHandle cred{};
    SECURITY_STATUS csr = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                                    SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
                                                    nullptr, &cred, &ts);
    printf("  %-46s cred=0x%08lX", label, (unsigned long)csr);
    if (csr != SEC_E_OK) { printf("\n"); return; }
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
        printf(" -> proto=0x%04lX suite=0x%04lX %ls\n", (unsigned long)ci.dwProtocol,
               (unsigned long)ciph.dwCipherSuite, ciph.szCipherSuite);
        DeleteSecurityContext(&ctx);
    } else {
        printf(" -> handshake=0x%08lX\n", (unsigned long)stc);
    }
    closesocket(sk);
    FreeCredentialsHandle(&cred);
}

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    printf("== TLS1.2 default vs. algorithm blacklist ==\n");
    Try("baseline", false, false);
    Try("disable RSA key exchange", true, false);
    Try("disable AES-256", false, true);
    Try("disable RSA kex + AES-256", true, true);
    WSACleanup();
    return 0;
}
