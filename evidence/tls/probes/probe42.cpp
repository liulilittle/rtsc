// Cross-audit probe #2: is design-a's "Handshake: consumed = in_size" safe?
// Feed the final server flight WITH extra trailing bytes appended (simulating a
// server that coalesces Finished + post-handshake messages in one TCP segment).
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
    static char b[8][24];
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

static PCCERT_CONTEXT MakeCert() {
    CERT_NAME_BLOB subject{};
    char name[] = "CN=rtsc-probe";
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, nullptr, &subject.cbData, nullptr);
    std::vector<BYTE> nb(subject.cbData);
    subject.pbData = nb.data();
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, subject.pbData, &subject.cbData, nullptr);
    return CertCreateSelfSignCertificate(0, &subject, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
}

static std::vector<BYTE> CStep(Conn& c, const std::vector<BYTE>& in, SECURITY_STATUS& st,
                              unsigned long* consumedOut, unsigned long* extraOut) {
    std::vector<BYTE> out;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    std::vector<BYTE> copy(in);
    SecBuffer ib[2];
    ib[0] = {0, SECBUFFER_EMPTY, nullptr};
    ib[1] = {0, SECBUFFER_EMPTY, nullptr};
    SecBufferDesc ibd{SECBUFFER_VERSION, 2, ib};
    if (!copy.empty()) ib[0] = {(unsigned long)copy.size(), SECBUFFER_TOKEN, copy.data()};
    DWORD attrs = 0;
    st = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                    const_cast<SEC_WCHAR*>(L"probe"),
                                    ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                                        ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                                        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                                        ISC_REQ_MANUAL_CRED_VALIDATION,
                                    0, SECURITY_NATIVE_DREP, copy.empty() ? nullptr : &ibd, 0,
                                    &c.ctx, &obd, &attrs, nullptr);
    c.haveCtx = true;
    *consumedOut = 0;
    *extraOut = 0;
    for (int i = 0; i < 2; i++) {
        if (ib[i].BufferType == SECBUFFER_TOKEN) *consumedOut = ib[i].cbBuffer;
        if (ib[i].BufferType == SECBUFFER_EXTRA) *extraOut = ib[i].cbBuffer;
    }
    if (ob.pvBuffer) {
        out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    return out;
}

static std::vector<BYTE> SStep(Conn& s, const std::vector<BYTE>& in, SECURITY_STATUS& st) {
    std::vector<BYTE> out;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    std::vector<BYTE> copy(in);
    SecBuffer ib{};
    SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
    if (!copy.empty()) {
        ib = {(unsigned long)copy.size(), SECBUFFER_TOKEN, copy.data()};
        ibd.cBuffers = 1;
        ibd.pBuffers = &ib;
    }
    DWORD attrs = 0;
    st = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr, copy.empty() ? nullptr : &ibd,
                               ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                   ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                                   ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                               SECURITY_NATIVE_DREP, &s.ctx, &obd, &attrs, nullptr);
    s.haveCtx = true;
    if (ob.pvBuffer) {
        out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    return out;
}

int main() {
    printf("== does ISC tolerate trailing bytes after the final server flight? ==\n");
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
        const char* name = pass == 0 ? "TLS1.2" : "TLS1.3";
        for (int junk = 0; junk <= 64; junk += 32) {
            Conn c, s;
            TimeStamp ts{};
            TLS_PARAMETERS tp{};
            tp.grbitDisabledProtocols = disabled;
            SCH_CREDENTIALS sc{};
            sc.dwVersion = SCH_CREDENTIALS_VERSION;
            sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION |
                         SCH_CRED_NO_DEFAULT_CREDS;
            sc.cTlsParameters = 1;
            sc.pTlsParameters = &tp;
            if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                          SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr,
                                          &c.cred, &ts) != SEC_E_OK) continue;
            PCCERT_CONTEXT cert = MakeCert();
            SCH_CREDENTIALS ss{};
            ss.dwVersion = SCH_CREDENTIALS_VERSION;
            ss.cCreds = 1;
            ss.paCred = &cert;
            ss.cTlsParameters = 1;
            ss.pTlsParameters = &tp;
            if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                          SECPKG_CRED_INBOUND, nullptr, &ss, nullptr, nullptr,
                                          &s.cred, &ts) != SEC_E_OK) continue;

            std::vector<BYTE> tok;
            SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
            unsigned long consumed = 0, extra = 0;
            std::vector<BYTE> lastIn;
            for (int i = 0; i < 12; i++) {
                if (i > 0 && junk > 0) {
                    // second client step receives the server's *final* flight;
                    // pad it with junk to simulate coalescing.
                    for (int k = 0; k < junk; k++) tok.push_back((BYTE)(0xA0 + k));
                    lastIn = tok;
                }
                tok = CStep(c, tok, stc, &consumed, &extra);
                if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) break;
                if (tok.empty() && stc == SEC_E_OK) break;
                tok = SStep(s, tok, sts);
                if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) break;
                if (sts == SEC_E_OK && stc == SEC_E_OK) break;
            }
            printf("  %s junk=%2d: client=%s server=%s consumed=%lu extra=%lu input=%zu%s\n", name,
                   junk, Hr(stc), Hr(sts), consumed, extra, lastIn.size(),
                   (junk && lastIn.size() != consumed + extra) ? "  <-- BYTES UNACCOUNTED" : "");
            DeleteSecurityContext(&c.ctx);
            DeleteSecurityContext(&s.ctx);
            FreeCredentialsHandle(&c.cred);
            FreeCredentialsHandle(&s.cred);
        }
    }
    return 0;
}
