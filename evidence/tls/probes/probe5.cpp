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
#pragma comment(lib, "bcrypt.lib")

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

static SECURITY_STATUS ClientCreds(Conn& c, DWORD flags) {
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    SCH_CREDENTIALS scr{};
    scr.dwVersion = SCH_CREDENTIALS_VERSION;
    scr.dwFlags = flags;
    scr.cTlsParameters = 1;
    scr.pTlsParameters = &tp;
    return AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                     SECPKG_CRED_OUTBOUND, nullptr, &scr, nullptr, nullptr, &c.cred, &ts);
}

static std::vector<BYTE> Step(Conn& c, const std::vector<BYTE>& in, SECURITY_STATUS& st, bool manualReq) {
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
    DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                (manualReq ? ISC_REQ_MANUAL_CRED_VALIDATION : 0);
    st = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                    const_cast<SEC_WCHAR*>(L"192.168.1.7"), req, 0,
                                    SECURITY_NATIVE_DREP, in.empty() ? nullptr : &ibd, 0,
                                    &c.ctx, &obd, &attrs, nullptr);
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

static void Try(const char* label, DWORD credFlags, bool manualReq) {
    printf("  [%s] credFlags=0x%lX ISC_REQ_MANUAL=%d\n", label, (unsigned long)credFlags, (int)manualReq);
    Conn c;
    SECURITY_STATUS st = ClientCreds(c, credFlags);
    if (st != SEC_E_OK) { printf("    cred -> %s\n", Hr(st)); return; }
    SOCKET sk = ConnectTo("192.168.1.7", 3389);
    if (sk == INVALID_SOCKET) { printf("    connect failed\n"); return; }
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 8; i++) {
        tok = Step(c, tok, stc, manualReq);
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) { printf("    ISC -> %s\n", Hr(stc)); break; }
        if (!tok.empty()) send(sk, (const char*)tok.data(), (int)tok.size(), 0);
        if (stc == SEC_E_OK) break;
        std::vector<BYTE> in(16384);
        int n = recv(sk, (char*)in.data(), (int)in.size(), 0);
        if (n <= 0) { printf("    recv %d\n", n); break; }
        in.resize(n);
        tok = in;
    }
    if (stc == SEC_E_OK) {
        printf("    HANDSHAKE OK\n");
        PCCERT_CONTEXT rc = nullptr;
        SECURITY_STATUS q = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &rc);
        if (q == SEC_E_OK && rc) {
            DWORD n = 0;
            CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                &rc->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, nullptr, &n);
            std::vector<BYTE> spki(n);
            CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                &rc->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, spki.data(), &n);
            spki.resize(n);
            printf("    SPKI len=%zu first8:", spki.size());
            for (size_t i = 0; i < 8 && i < spki.size(); i++) printf(" %02x", spki[i]);
            BYTE hash[32] = {};
            // SHA-256 via BCrypt
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
                BCryptHash(hAlg, nullptr, 0, spki.data(), (ULONG)spki.size(), hash, 32);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                printf("    SHA256(SPKI):");
                for (int i = 0; i < 32; i++) printf("%s%02x", i ? " " : " ", hash[i]);
                printf("\n");
            }
            // SPKI offset inside cert DER
            for (DWORD off = 0; off + spki.size() <= rc->cbCertEncoded; off++) {
                if (memcmp(rc->pbCertEncoded + off, spki.data(), spki.size()) == 0) {
                    printf("    SPKI at cert offset %lu\n", off);
                    break;
                }
            }
            CertFreeCertificateContext(rc);
        }
        // SECPKG_ATTR_CERT_CHECK_RESULT availability
        SecPkgContext_CertificateValidationResult cvr{};
        SECURITY_STATUS q2 = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CERT_CHECK_RESULT, &cvr);
        printf("    CERT_CHECK_RESULT -> %s hr=0x%08lX\n", Hr(q2), (unsigned long)cvr.hrVerifyChainStatus);
    }
    closesocket(sk);
    DeleteSecurityContext(&c.ctx);
    FreeCredentialsHandle(&c.cred);
}

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    printf("== cert policy matrix against real self-signed server ==\n");
    Try("no manual flags at all", SCH_CRED_NO_DEFAULT_CREDS, false);
    Try("cred MANUAL only", SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS, false);
    Try("cred MANUAL + ISC MANUAL", SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS, true);
    Try("ISC MANUAL only", SCH_CRED_NO_DEFAULT_CREDS, true);
    Try("DEFERRED validation", SCH_CRED_DEFERRED_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS, false);
    WSACleanup();
    return 0;
}
