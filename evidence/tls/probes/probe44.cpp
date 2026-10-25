// Clean single-call measurement: does ISC ever leave trailing bytes unconsumed
// (SECBUFFER_EXTRA) when the server's final flight is padded with junk?
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <cstdio>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

static const char* Hr(HRESULT hr) {
    static char b[4][24];
    static int i = 0;
    i = (i + 1) % 4;
    sprintf_s(b[i], "0x%08lX", (unsigned long)hr);
    return b[i];
}

static PCCERT_CONTEXT MakeCert() {
    CERT_NAME_BLOB subject{};
    char name[] = "CN=rtsc-probe";
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, nullptr, &subject.cbData, nullptr);
    std::vector<BYTE> nb(subject.cbData);
    subject.pbData = nb.data();
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, subject.pbData, &subject.cbData, nullptr);
    return CertCreateSelfSignCertificate(0, &subject, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
}

static const char* TypeName(unsigned long t) {
    switch (t) {
        case SECBUFFER_EMPTY: return "EMPTY";
        case SECBUFFER_DATA: return "DATA";
        case SECBUFFER_TOKEN: return "TOKEN";
        case SECBUFFER_PKG_PARAMS: return "PKG_PARAMS";
        case SECBUFFER_MISSING: return "MISSING";
        case SECBUFFER_EXTRA: return "EXTRA";
        case SECBUFFER_STREAM_TRAILER: return "STREAM_TRAILER";
        case SECBUFFER_STREAM_HEADER: return "STREAM_HEADER";
        default: return "?";
    }
}

int main() {
    const DWORD disabled = SP_PROT_TLS1_3_CLIENT;  // TLS1.2 only
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    CredHandle cc{};
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                  nullptr, &sc, nullptr, nullptr, &cc, &ts) != SEC_E_OK) return 1;
    PCCERT_CONTEXT cert = MakeCert();
    SCH_CREDENTIALS ss{};
    ss.dwVersion = SCH_CREDENTIALS_VERSION;
    ss.cCreds = 1;
    ss.paCred = &cert;
    ss.cTlsParameters = 1;
    ss.pTlsParameters = &tp;
    CredHandle sh{};
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
                                  nullptr, &ss, nullptr, nullptr, &sh, &ts) != SEC_E_OK) return 1;

    CtxtHandle cctx{}, sctx{};
    bool haveC = false, haveS = false;
    std::vector<BYTE> tok;

    // Round 0: ClientHello
    {
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        DWORD attrs = 0;
        SECURITY_STATUS st = InitializeSecurityContextW(
            &cc, nullptr, const_cast<SEC_WCHAR*>(L"p"),
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                ISC_REQ_MANUAL_CRED_VALIDATION,
            0, SECURITY_NATIVE_DREP, nullptr, 0, &cctx, &obd, &attrs, nullptr);
        haveC = true;
        printf("ClientHello: %s %lu bytes\n", Hr(st), ob.cbBuffer);
        if (ob.pvBuffer) {
            tok.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
            FreeContextBuffer(ob.pvBuffer);
        }
    }
    // Server flight 1
    {
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        SecBuffer ib = {(unsigned long)tok.size(), SECBUFFER_TOKEN, tok.data()};
        SecBufferDesc ibd{SECBUFFER_VERSION, 1, &ib};
        DWORD attrs = 0;
        SECURITY_STATUS st = AcceptSecurityContext(
            &sh, nullptr, &ibd,
            ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
            SECURITY_NATIVE_DREP, &sctx, &obd, &attrs, nullptr);
        haveS = true;
        printf("ServerFlight1: %s %lu bytes\n", Hr(st), ob.cbBuffer);
        if (ob.pvBuffer) {
            tok.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
            FreeContextBuffer(ob.pvBuffer);
        }
    }
    // Client flight 2 (with 64 junk bytes appended to the server flight)
    {
        std::vector<BYTE> input = tok;
        for (int k = 0; k < 64; k++) input.push_back((BYTE)(0xC0 + k));
        std::vector<BYTE> out;
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        SecBuffer ib[2];
        ib[0] = {(unsigned long)input.size(), SECBUFFER_TOKEN, input.data()};
        ib[1] = {0, SECBUFFER_EMPTY, nullptr};
        SecBufferDesc ibd{SECBUFFER_VERSION, 2, ib};
        DWORD attrs = 0;
        SECURITY_STATUS st = InitializeSecurityContextW(
            &cc, &cctx, const_cast<SEC_WCHAR*>(L"p"),
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                ISC_REQ_MANUAL_CRED_VALIDATION,
            0, SECURITY_NATIVE_DREP, &ibd, 0, &cctx, &obd, &attrs, nullptr);
        printf("\nClientFlight2: %s out=%lu  input=%zu\n", Hr(st), ob.cbBuffer, input.size());
        for (int b = 0; b < 2; b++) {
            const BYTE* p = (const BYTE*)ib[b].pvBuffer;
            long long off = (p && p >= input.data()) ? (long long)(p - input.data()) : -1;
            printf("  in[%d] type=%-12s cb=%lu ptr=%p offset=%lld\n", b, TypeName(ib[b].BufferType),
                   ib[b].cbBuffer, (const void*)p, off);
        }
        printf("  => consumed by SChannel = %zu - (sum of EXTRA) \n", input.size());
        if (ob.pvBuffer) FreeContextBuffer(ob.pvBuffer);
    }
    DeleteSecurityContext(&cctx);
    DeleteSecurityContext(&sctx);
    FreeCredentialsHandle(&cc);
    FreeCredentialsHandle(&sh);
    return 0;
}
