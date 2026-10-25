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

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    CredHandle cred{};
    AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                              nullptr, &sc, nullptr, nullptr, &cred, &ts);
    SOCKET sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(3389);
    inet_pton(AF_INET, "192.168.1.7", &a.sin_addr);
    if (connect(sk, (sockaddr*)&a, sizeof(a)) != 0) { printf("connect fail\n"); return 1; }
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
    if (stc != SEC_E_OK) { printf("hs fail 0x%08lX\n", (unsigned long)stc); return 1; }
    PCCERT_CONTEXT rc = nullptr;
    if (QueryContextAttributesW(&ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &rc) != SEC_E_OK || !rc) {
        printf("no cert\n");
        return 1;
    }
    const CERT_PUBLIC_KEY_INFO& pki = rc->pCertInfo->SubjectPublicKeyInfo;
    printf("cert DER = %lu bytes\n", rc->cbCertEncoded);
    printf("Algorithm OID = %s (%lu bytes)\n", pki.Algorithm.pszObjId, pki.Algorithm.pszObjId ? (unsigned long)strlen(pki.Algorithm.pszObjId) : 0UL);
    printf("PublicKey BIT_BLOB: cbData=%lu unusedBits=%lu\n", pki.PublicKey.cbData, pki.PublicKey.cUnusedBits);
    printf("PublicKey first 8:");
    for (DWORD i = 0; i < 8 && i < pki.PublicKey.cbData; i++) printf(" %02x", pki.PublicKey.pbData[i]);
    printf("\n");

    DWORD n = 0;
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &pki, 0, nullptr, nullptr, &n);
    std::vector<BYTE> spki(n);
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &pki, 0, nullptr, spki.data(), &n);
    spki.resize(n);
    printf("SPKI (CryptEncodeObjectEx) = %zu bytes, head:", spki.size());
    for (size_t i = 0; i < 8; i++) printf(" %02x", spki[i]);
    printf("\n");
    // Is PublicKey.pbData verbatim inside SPKI? If yes, no ASN.1 parser is needed.
    bool found = false;
    for (size_t off = 0; off + pki.PublicKey.cbData <= spki.size(); off++) {
        if (memcmp(spki.data() + off, pki.PublicKey.pbData, pki.PublicKey.cbData) == 0) {
            printf("SubjectPublicKey found verbatim inside SPKI at offset %zu -> NO ASN.1 parsing needed\n", off);
            found = true;
            break;
        }
    }
    if (!found) printf("SubjectPublicKey NOT verbatim inside SPKI\n");
    // Is SPKI verbatim inside cert DER? (CredSSP needs a stable binding input.)
    bool inCert = false;
    for (DWORD off = 0; off + spki.size() <= rc->cbCertEncoded; off++) {
        if (memcmp(rc->pbCertEncoded + off, spki.data(), spki.size()) == 0) {
            printf("SPKI found verbatim inside cert DER at offset %lu\n", off);
            inCert = true;
            break;
        }
    }
    if (!inCert) printf("SPKI NOT verbatim inside cert DER\n");
    CertFreeCertificateContext(rc);
    closesocket(sk);
    DeleteSecurityContext(&ctx);
    FreeCredentialsHandle(&cred);
    WSACleanup();
    return 0;
}
