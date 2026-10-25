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

static std::vector<BYTE> ClientHello(const wchar_t* target, DWORD flags, DWORD disabled,
                                     const wchar_t* alpn) {
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    tp.dwFlags = 0;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = flags;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    Conn c;
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                  nullptr, &sc, nullptr, nullptr, &c.cred, &ts) != SEC_E_OK)
        return {};
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    DWORD attrs = 0;
    SECURITY_STATUS st = InitializeSecurityContextW(
        &c.cred, nullptr, const_cast<SEC_WCHAR*>(target),
        ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
            ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
            ISC_REQ_MANUAL_CRED_VALIDATION,
        0, SECURITY_NATIVE_DREP, nullptr, 0, &c.ctx, &obd, &attrs, nullptr);
    std::vector<BYTE> out;
    if (ob.pvBuffer) {
        out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    if (c.haveCtx || true) {
        // leak the ctx on purpose; probe process
    }
    return out;
}

static void ScanExt(const char* tag, const std::vector<BYTE>& ch) {
    printf("== %s (%zu bytes) ==\n", tag, ch.size());
    if (ch.size() < 5 + 4 + 2 + 32) return;
    // TLS record header 5, handshake header 4, version 2, random 32, sid len 1 ...
    size_t p = 5 + 4 + 2 + 32;
    BYTE sidLen = ch[p];
    p += 1 + sidLen;
    size_t csLen = ((size_t)ch[p] << 8) | ch[p + 1];
    p += 2 + csLen;
    BYTE cmLen = ch[p];
    p += 1 + cmLen;
    if (p + 2 > ch.size()) { printf("  no extensions\n"); return; }
    size_t extTotal = ((size_t)ch[p] << 8) | ch[p + 1];
    p += 2;
    size_t end = p + extTotal;
    printf("  extensions total=%zu\n", extTotal);
    while (p + 4 <= end && p + 4 <= ch.size()) {
        unsigned type = ((unsigned)ch[p] << 8) | ch[p + 1];
        size_t len = ((size_t)ch[p + 2] << 8) | ch[p + 3];
        printf("    ext 0x%04x len=%zu:", type, len);
        for (size_t k = 0; k < len && k < 24; k++) printf(" %02x", ch[p + 4 + k]);
        if (type == 0x0010 && len >= 2) {
            printf("  <- ALPN: list_len=%u proto_len=%u proto='%.*s'", ch[p + 4],
                   ch[p + 6], (int)ch[p + 6], (const char*)&ch[p + 7]);
        }
        if (type == 0x0000 && len >= 5) {
            printf("  <- SNI type=%u name_len=%u name='%.*s'", ch[p + 6],
                   ((unsigned)ch[p + 7] << 8) | ch[p + 8], (int)(((unsigned)ch[p + 7] << 8) | ch[p + 8]),
                   (const char*)&ch[p + 9]);
        }
        printf("\n");
        p += 4 + len;
    }
}

int main() {
    DWORD manual = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
    ScanExt("TLS1.3 forced, IP target", ClientHello(L"192.168.1.7", manual, SP_PROT_TLS1_2_CLIENT, nullptr));
    ScanExt("TLS1.2 forced, IP target", ClientHello(L"192.168.1.7", manual, SP_PROT_TLS1_3_CLIENT, nullptr));
    ScanExt("TLS1.3 forced, DNS target", ClientHello(L"desktop-5bfdko3", manual, SP_PROT_TLS1_2_CLIENT, nullptr));
    ScanExt("TLS1.3 forced, null target", ClientHello(nullptr, manual, SP_PROT_TLS1_2_CLIENT, nullptr));
    return 0;
}
