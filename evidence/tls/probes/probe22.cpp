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
};

static void DumpRecords(const char* tag, const std::vector<BYTE>& buf) {
    printf("  %s (%zu bytes):", tag, buf.size());
    size_t off = 0;
    int n = 0;
    while (off + 5 <= buf.size() && n < 12) {
        BYTE type = buf[off];
        size_t len = ((size_t)buf[off + 3] << 8) | buf[off + 4];
        printf(" [rec%d type=0x%02x len=%zu]", n, type, len);
        if (off + 5 + len > buf.size()) { printf(" (TRUNCATED)"); break; }
        off += 5 + len;
        n++;
    }
    printf("  total_consumed=%zu\n", off);
}

static void Run(const char* label, const wchar_t* target, DWORD flags, DWORD disabled, bool dumpFlights) {
    printf("  [%s] target=%ls\n", label, target ? target : L"(null)");
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = flags;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    Conn c;
    SECURITY_STATUS cs = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                                   SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
                                                   nullptr, &c.cred, &ts);
    if (cs != SEC_E_OK) { printf("    cred -> %s\n", Hr(cs)); return; }
    SOCKET sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(3389);
    inet_pton(AF_INET, "192.168.1.7", &a.sin_addr);
    if (connect(sk, (sockaddr*)&a, sizeof(a)) != 0) { printf("    connect fail\n"); return; }
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED;
    int flight = 0;
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
                                         const_cast<SEC_WCHAR*>(target),
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
        if (dumpFlights && !tok.empty()) {
            char t[32];
            sprintf_s(t, "flight %d", flight);
            DumpRecords(t, tok);
            // scan for SNI (0x0000) and supported_versions (0x002b) extension types
            if (flight == 0) {
                bool sni = false, sv = false, alpn = false;
                for (size_t k = 0; k + 1 < tok.size(); k++) {
                    if (tok[k] == 0x00 && tok[k + 1] == 0x00) sni = true;
                    if (tok[k] == 0x00 && tok[k + 1] == 0x2b) sv = true;
                    if (tok[k] == 0x00 && tok[k + 1] == 0x10) alpn = true;
                }
                printf("    ext scan: SNI(0x0000)=%d supported_versions(0x002b)=%d ALPN(0x0010)=%d\n",
                       (int)sni, (int)sv, (int)alpn);
            }
            flight++;
        }
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) { printf("    ISC=%s\n", Hr(stc)); break; }
        if (!tok.empty()) send(sk, (const char*)tok.data(), (int)tok.size(), 0);
        if (stc == SEC_E_OK) break;
        std::vector<BYTE> in(16384);
        int n = recv(sk, (char*)in.data(), (int)in.size(), 0);
        if (n <= 0) { printf("    recv=%d\n", n); break; }
        in.resize(n);
        tok = in;
    }
    if (stc == SEC_E_OK) {
        SecPkgContext_ConnectionInfo ci{};
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
        printf("    OK proto=0x%04lX cipher=0x%04X\n", (unsigned long)ci.dwProtocol,
               (unsigned)ci.aiCipher);
        DeleteSecurityContext(&c.ctx);
    }
    closesocket(sk);
}

int main() {
    WSADATA w{};
    WSAStartup(MAKEWORD(2, 2), &w);
    DWORD manual = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
    printf("== ClientHello / flight composition (TLS1.2 forced) ==\n");
    Run("IP target, 1.2 forced", L"192.168.1.7", manual, SP_PROT_TLS1_3_CLIENT, true);
    printf("== ClientHello with DNS name target (SNI expected) ==\n");
    Run("DNS target, 1.2 forced", L"desktop-5bfdko3", manual, SP_PROT_TLS1_3_CLIENT, true);
    printf("== TLS1.3 forced ==\n");
    Run("IP target, 1.3 forced", L"192.168.1.7", manual, SP_PROT_TLS1_2_CLIENT, true);
    WSACleanup();
    return 0;
}
