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

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);

    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = 0;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    CredHandle cred{};
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                  nullptr, &sc, nullptr, nullptr, &cred, &ts) != SEC_E_OK) {
        printf("cred fail\n");
        return 1;
    }
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
    if (stc != SEC_E_OK) { printf("handshake fail %s\n", Hr(stc)); return 1; }

    SecPkgContext_ConnectionInfo ci{};
    QueryContextAttributesW(&ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
    SecPkgContext_StreamSizes ss{};
    QueryContextAttributesW(&ctx, SECPKG_ATTR_STREAM_SIZES, &ss);
    printf("handshake OK proto=0x%04lX hdr=%lu trl=%lu max=%lu\n", (unsigned long)ci.dwProtocol,
           ss.cbHeader, ss.cbTrailer, ss.cbMaximumMessage);

    // Immediately after the handshake the server has nothing RDP-wise to send
    // until we send the MCS Connect Initial. But TLS1.3 servers typically push
    // NewSessionTicket records. Read with a short timeout and report.
    DWORD tv = 1500;
    setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int records = 0, emptyRecords = 0, calls = 0;
    for (int round = 0; round < 4; round++) {
        std::vector<BYTE> in(65536);
        int n = recv(sk, (char*)in.data(), (int)in.size(), 0);
        printf("recv -> %d bytes (err=%d)\n", n, n < 0 ? WSAGetLastError() : 0);
        if (n <= 0) break;
        in.resize(n);
        std::vector<BYTE> pending = in;
        while (!pending.empty()) {
            std::vector<BYTE> buf(pending);
            SecBuffer bs[4];
            for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
            bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
            SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
            SECURITY_STATUS st = DecryptMessage(&ctx, &d, 0, nullptr);
            calls++;
            if (st != SEC_E_OK) {
                printf("  DecryptMessage -> %s\n", Hr(st));
                break;
            }
            records++;
            unsigned long dl = 0;
            std::vector<BYTE> extra;
            for (int i = 0; i < 4; i++) {
                if (bs[i].BufferType == SECBUFFER_DATA) dl += bs[i].cbBuffer;
                if (bs[i].BufferType == SECBUFFER_EXTRA && bs[i].cbBuffer)
                    extra.assign((BYTE*)bs[i].pvBuffer, (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
            }
            if (dl == 0) emptyRecords++;
            printf("  record %d: plaintext=%lu bytes%s\n", records, dl,
                   dl ? "" : "   <-- empty (post-handshake ticket / alert)");
            pending = extra;
        }
    }
    printf("summary: decrypt calls=%d, records=%d, empty records=%d\n", calls, records, emptyRecords);
    closesocket(sk);
    DeleteSecurityContext(&ctx);
    FreeCredentialsHandle(&cred);
    WSACleanup();
    return 0;
}
