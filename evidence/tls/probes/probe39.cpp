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

struct Sess {
    CredHandle cred{};
    CtxtHandle ctx{};
    SOCKET sk = INVALID_SOCKET;
};

static bool Connect(Sess& s) {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = SP_PROT_TLS1_2_CLIENT;  // TLS1.3 only
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
    return stc == SEC_E_OK;
}

int main() {
    Sess s;
    if (!Connect(s)) { printf("connect fail\n"); return 1; }
    printf("== TLS1.3: NewSessionTicket arrives as SEC_I_RENEGOTIATE ==\n");
    DWORD tv = 1500;
    setsockopt(s.sk, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    std::vector<BYTE> in(65536);
    int n = recv(s.sk, (char*)in.data(), (int)in.size(), 0);
    printf("recv %d bytes\n", n);
    if (n <= 0) return 1;
    in.resize(n);

    // Behaviour A (naive): treat SEC_I_RENEGOTIATE as success, ignore EXTRA.
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    printf("A) DecryptMessage -> %s ; ignoring EXTRA (as if it were SEC_E_OK)\n", Hr(st));

    // Now send application data and try to read a server reply after the ticket.
    // EncryptMessage should still work, and subsequent DecryptMessage must not wedge.
    std::vector<BYTE> rec(5 + 8 + 44);
    SecBuffer ebs[3];
    ebs[0] = {5, SECBUFFER_STREAM_HEADER, rec.data()};
    ebs[1] = {8, SECBUFFER_DATA, rec.data() + 5};
    ebs[2] = {44, SECBUFFER_STREAM_TRAILER, rec.data() + 5 + 8};
    SecBufferDesc ebd{SECBUFFER_VERSION, 3, ebs};
    SECURITY_STATUS es = EncryptMessage(&s.ctx, 0, &ebd, 0);
    printf("   EncryptMessage -> %s\n", Hr(es));

    // Feed a *second* copy of the ticket record (simulating the next recv that
    // contains another ticket or a replayed buffer) and see whether the
    // context wedges because the first ticket was never consumed.
    std::vector<BYTE> buf2(in);
    SecBuffer bs2[4];
    for (int i = 0; i < 4; i++) bs2[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs2[0] = {(unsigned long)buf2.size(), SECBUFFER_DATA, buf2.data()};
    SecBufferDesc d2{SECBUFFER_VERSION, 4, bs2};
    SECURITY_STATUS st2 = DecryptMessage(&s.ctx, &d2, 0, nullptr);
    printf("   re-feeding the same ticket bytes -> %s\n", Hr(st2));

    // Drain properly on a fresh connection: loop until SEC_E_OK with no EXTRA.
    Sess s2;
    if (!Connect(s2)) return 1;
    setsockopt(s2.sk, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    std::vector<BYTE> in2(65536);
    int n2 = recv(s2.sk, (char*)in2.data(), (int)in2.size(), 0);
    if (n2 <= 0) return 1;
    in2.resize(n2);
    printf("== correct handling: drive ISC until it stops returning RENEGOTIATE ==\n");
    std::vector<BYTE> pending = in2;
    for (int guard = 0; guard < 8 && !pending.empty(); guard++) {
        std::vector<BYTE> b2(pending);
        SecBuffer b[4];
        for (int i = 0; i < 4; i++) b[i] = {0, SECBUFFER_EMPTY, nullptr};
        b[0] = {(unsigned long)b2.size(), SECBUFFER_DATA, b2.data()};
        SecBufferDesc dd{SECBUFFER_VERSION, 4, b};
        SECURITY_STATUS s3 = DecryptMessage(&s2.ctx, &dd, 0, nullptr);
        std::vector<BYTE> extra;
        for (int i = 0; i < 4; i++)
            if (b[i].BufferType == SECBUFFER_EXTRA && b[i].cbBuffer)
                extra.assign((BYTE*)b[i].pvBuffer, (BYTE*)b[i].pvBuffer + b[i].cbBuffer);
        printf("  iter %d: %s extra=%zu\n", guard, Hr(s3), extra.size());
        if (s3 == SEC_I_RENEGOTIATE && !extra.empty()) {
            SecBuffer ib = {(unsigned long)extra.size(), SECBUFFER_TOKEN, extra.data()};
            SecBufferDesc ibd{SECBUFFER_VERSION, 1, &ib};
            SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
            DWORD attrs = 0;
            SECURITY_STATUS s4 = InitializeSecurityContextW(
                &s2.cred, &s2.ctx, const_cast<SEC_WCHAR*>(L"192.168.1.7"),
                ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION,
                0, SECURITY_NATIVE_DREP, &ibd, 0, &s2.ctx, &obd, &attrs, nullptr);
            printf("       ISC(ticket) -> %s out=%lu\n", Hr(s4), ob.cbBuffer);
            if (ob.pvBuffer) FreeContextBuffer(ob.pvBuffer);
        }
        pending = extra;
    }
    // verify the context is still good
    std::vector<BYTE> r2(5 + 8 + 44);
    SecBuffer eb[3];
    eb[0] = {5, SECBUFFER_STREAM_HEADER, r2.data()};
    eb[1] = {8, SECBUFFER_DATA, r2.data() + 5};
    eb[2] = {44, SECBUFFER_STREAM_TRAILER, r2.data() + 13};
    SecBufferDesc ebd2{SECBUFFER_VERSION, 3, eb};
    printf("  final EncryptMessage -> %s\n", Hr(EncryptMessage(&s2.ctx, 0, &ebd2, 0)));
    return 0;
}
