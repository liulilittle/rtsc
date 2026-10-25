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
    SecPkgContext_StreamSizes sizes{};
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

// requireClientCert: server sends CertificateRequest
static bool Loopback(Conn& c, Conn& s, DWORD disabled, bool requireClientCert, const char** why) {
    TimeStamp ts{};
    PCCERT_CONTEXT serverCert = MakeCert();
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
    SCH_CREDENTIALS sc{};
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                  nullptr, &sc, nullptr, nullptr, &c.cred, &ts) != SEC_E_OK) {
        *why = "client cred";
        return false;
    }
    SCH_CREDENTIALS ss{};
    ss.dwVersion = SCH_CREDENTIALS_VERSION;
    ss.cCreds = 1;
    ss.paCred = &serverCert;
    ss.cTlsParameters = 1;
    ss.pTlsParameters = &tp;
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
                                  nullptr, &ss, nullptr, nullptr, &s.cred, &ts) != SEC_E_OK) {
        *why = "server cred";
        return false;
    }
    DWORD sreq = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                 ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
    if (requireClientCert) sreq |= ASC_REQ_MUTUAL_AUTH;

    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 12; i++) {
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
                                         const_cast<SEC_WCHAR*>(L"probe"),
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
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) {
            *why = Hr(stc);
            return false;
        }
        if (tok.empty() && stc == SEC_E_OK) break;
        SecBuffer ob2{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc obd2{SECBUFFER_VERSION, 1, &ob2};
        SecBuffer ib2 = {(unsigned long)tok.size(), SECBUFFER_TOKEN, tok.data()};
        SecBufferDesc ibd2{SECBUFFER_VERSION, 1, &ib2};
        DWORD a2 = 0;
        sts = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr, &ibd2, sreq,
                                    SECURITY_NATIVE_DREP, &s.ctx, &obd2, &a2, nullptr);
        s.haveCtx = true;
        tok.clear();
        if (ob2.pvBuffer) {
            tok.assign((BYTE*)ob2.pvBuffer, (BYTE*)ob2.pvBuffer + ob2.cbBuffer);
            FreeContextBuffer(ob2.pvBuffer);
        }
        if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) {
            *why = Hr(sts);
            return false;
        }
        if (sts == SEC_E_OK && stc == SEC_E_OK) break;
    }
    if (stc != SEC_E_OK || sts != SEC_E_OK) {
        *why = "loop";
        return false;
    }
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &c.sizes);
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    return true;
}

int main() {
    const char* why = "";
    printf("== 1. zero-length application data ==\n");
    for (int pass = 0; pass < 2; pass++) {
        Conn c, s;
        why = "";
        if (!Loopback(c, s, pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT, false, &why)) {
            printf("  hs fail %s\n", why);
            continue;
        }
        std::vector<BYTE> rec(c.sizes.cbHeader + c.sizes.cbTrailer);
        SecBuffer bs[3];
        bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
        bs[1] = {0, SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
        bs[2] = {c.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader};
        SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
        SECURITY_STATUS st = EncryptMessage(&c.ctx, 0, &d, 0);
        printf("  %s EncryptMessage(0 bytes) -> %s h=%lu d=%lu t=%lu\n",
               pass == 0 ? "TLS1.2" : "TLS1.3", Hr(st), bs[0].cbBuffer, bs[1].cbBuffer,
               bs[2].cbBuffer);
        if (st == SEC_E_OK) {
            size_t total = bs[0].cbBuffer + bs[1].cbBuffer + bs[2].cbBuffer;
            rec.resize(total);
            std::vector<BYTE> buf(rec);
            SecBuffer db[4];
            for (int i = 0; i < 4; i++) db[i] = {0, SECBUFFER_EMPTY, nullptr};
            db[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
            SecBufferDesc dd{SECBUFFER_VERSION, 4, db};
            SECURITY_STATUS ds = DecryptMessage(&s.ctx, &dd, 0, nullptr);
            printf("      decrypt(%zu B) -> %s data=%lu\n", buf.size(), Hr(ds), db[1].cbBuffer);
        }
    }

    printf("== 2. server requests a client certificate (mutual auth) ==\n");
    for (int pass = 0; pass < 2; pass++) {
        Conn c, s;
        why = "";
        bool ok = Loopback(c, s, pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT, true, &why);
        printf("  %s mutual-auth handshake ok=%d reason=%s\n", pass == 0 ? "TLS1.2" : "TLS1.3",
               (int)ok, why);
    }

    printf("== 3. cDisabledCrypto (algorithm blacklist) ==\n");
    {
        TimeStamp ts{};
        CRYPTO_SETTINGS cs{};
        cs.eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
        UNICODE_STRING aes = {};
        aes.Buffer = const_cast<PWSTR>(L"AES");
        aes.Length = (USHORT)(6 * sizeof(WCHAR));
        aes.MaximumLength = aes.Length;
        cs.strCngAlgId = aes;
        cs.dwMinBitLength = 256;
        cs.dwMaxBitLength = 256;
        TLS_PARAMETERS tp{};
        tp.cDisabledCrypto = 1;
        tp.pDisabledCrypto = &cs;
        SCH_CREDENTIALS sc{};
        sc.dwVersion = SCH_CREDENTIALS_VERSION;
        sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
        sc.cTlsParameters = 1;
        sc.pTlsParameters = &tp;
        CredHandle h{};
        SECURITY_STATUS st = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                                       SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr,
                                                       nullptr, &h, &ts);
        printf("  blacklist AES-256 -> cred %s\n", Hr(st));
        if (st == SEC_E_OK) FreeCredentialsHandle(&h);
        // nonsense algorithm name
        cs.strCngAlgId.Buffer = const_cast<PWSTR>(L"NO-SUCH-ALG");
        cs.strCngAlgId.Length = cs.strCngAlgId.MaximumLength = (USHORT)(11 * sizeof(WCHAR));
        st = AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                       SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr, &h, &ts);
        printf("  blacklist bogus alg -> cred %s (silently ignored?)\n", Hr(st));
        if (st == SEC_E_OK) FreeCredentialsHandle(&h);
    }
    return 0;
}
