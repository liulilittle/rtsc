// Confirm that ISC's SECBUFFER_EXTRA on handshake input really is the *trailing*
// bytes (offset == input.size()-extra, content == the junk we appended).
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

static PCCERT_CONTEXT MakeCert() {
    CERT_NAME_BLOB subject{};
    char name[] = "CN=rtsc-probe";
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, nullptr, &subject.cbData, nullptr);
    std::vector<BYTE> nb(subject.cbData);
    subject.pbData = nb.data();
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, subject.pbData, &subject.cbData, nullptr);
    return CertCreateSelfSignCertificate(0, &subject, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
}

int main() {
    DWORD disabled = SP_PROT_TLS1_3_CLIENT;  // TLS1.2 only
    TimeStamp ts{};
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    CredHandle cc{};
    AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                              nullptr, &sc, nullptr, nullptr, &cc, &ts);
    PCCERT_CONTEXT cert = MakeCert();
    SCH_CREDENTIALS ss{};
    ss.dwVersion = SCH_CREDENTIALS_VERSION;
    ss.cCreds = 1;
    ss.paCred = &cert;
    ss.cTlsParameters = 1;
    ss.pTlsParameters = &tp;
    CredHandle sc2{};
    AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
                              nullptr, &ss, nullptr, nullptr, &sc2, &ts);

    CtxtHandle cctx{}, sctx{};
    bool ch = false, sh = false;
    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 12; i++) {
        // client
        {
            std::vector<BYTE> out;
            SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
            std::vector<BYTE> copy = tok;
            // append 40 junk bytes with a recognisable pattern
            if (i > 0) for (int k = 0; k < 40; k++) copy.push_back((BYTE)(0xC0 + k));
            SecBuffer ib[2];
            ib[0] = {0, SECBUFFER_EMPTY, nullptr};
            ib[1] = {0, SECBUFFER_EMPTY, nullptr};
            SecBufferDesc ibd{SECBUFFER_VERSION, 2, ib};
            if (!copy.empty()) ib[0] = {(unsigned long)copy.size(), SECBUFFER_TOKEN, copy.data()};
            DWORD attrs = 0;
            stc = InitializeSecurityContextW(&cc, ch ? &cctx : nullptr,
                                             const_cast<SEC_WCHAR*>(L"p"),
                                             ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                                                 ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                                                 ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                                                 ISC_REQ_MANUAL_CRED_VALIDATION,
                                             0, SECURITY_NATIVE_DREP, copy.empty() ? nullptr : &ibd, 0,
                                             &cctx, &obd, &attrs, nullptr);
            ch = true;
            if (ob.pvBuffer) {
                out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
                FreeContextBuffer(ob.pvBuffer);
            }
            if (i > 0) {
                printf("round %d: input=%zu\n", i, copy.size());
                for (int b = 0; b < 2; b++) {
                    if (ib[b].BufferType == SECBUFFER_EXTRA && ib[b].cbBuffer && ib[b].pvBuffer) {
                        const BYTE* p = (const BYTE*)ib[b].pvBuffer;
                        long long off = (long long)(p - copy.data());
                        printf("   EXTRA buf[%d]: cb=%lu offsetFromInputStart=%lld  (input-extra=%zu)\n",
                               b, ib[b].cbBuffer, off, copy.size() - ib[b].cbBuffer);
                        printf("   EXTRA content:");
                        for (unsigned long k = 0; k < ib[b].cbBuffer && k < 8; k++)
                            printf(" %02x", p[k]);
                        printf("   (junk starts at 0xC0)\n");
                    }
                }
            }
            tok = out;
        }
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) { printf("client %08lX\n", (unsigned long)stc); break; }
        if (tok.empty() && stc == SEC_E_OK) break;
        // server
        {
            std::vector<BYTE> out;
            SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
            SecBuffer ib = {(unsigned long)tok.size(), SECBUFFER_TOKEN, tok.data()};
            SecBufferDesc ibd{SECBUFFER_VERSION, 1, &ib};
            DWORD attrs = 0;
            sts = AcceptSecurityContext(&sc2, sh ? &sctx : nullptr, &ibd,
                                        ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                            ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                                            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                                        SECURITY_NATIVE_DREP, &sctx, &obd, &attrs, nullptr);
            sh = true;
            if (ob.pvBuffer) {
                out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
                FreeContextBuffer(ob.pvBuffer);
            }
            tok = out;
        }
        if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) { printf("server %08lX\n", (unsigned long)sts); break; }
        if (sts == SEC_E_OK && stc == SEC_E_OK) break;
    }
    return 0;
}
