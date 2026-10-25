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

static bool MakeCert(PCCERT_CONTEXT* out) {
    CERT_NAME_BLOB subject{};
    char name[] = "CN=rtsc-probe";
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, nullptr, &subject.cbData, nullptr);
    std::vector<BYTE> nb(subject.cbData);
    subject.pbData = nb.data();
    CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr, subject.pbData, &subject.cbData, nullptr);
    *out = CertCreateSelfSignCertificate(0, &subject, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
    return *out != nullptr;
}

// mode 0 = SCHANNEL_CRED, 1 = SCH_CREDENTIALS
static bool Loopback(Conn& c, Conn& s, int mode, DWORD protos, bool dumpHello) {
    TimeStamp ts{};
    PCCERT_CONTEXT cert = nullptr;
    if (!MakeCert(&cert)) return false;
    if (mode == 0) {
        SCHANNEL_CRED sc{};
        sc.dwVersion = SCHANNEL_CRED_VERSION;
        sc.grbitEnabledProtocols = protos;
        sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
        if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                      nullptr, &sc, nullptr, nullptr, &c.cred, &ts) != SEC_E_OK) return false;
        SCHANNEL_CRED ss{};
        ss.dwVersion = SCHANNEL_CRED_VERSION;
        ss.cCreds = 1;
        ss.paCred = &cert;
        ss.grbitEnabledProtocols = protos;
        if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
                                      nullptr, &ss, nullptr, nullptr, &s.cred, &ts) != SEC_E_OK) return false;
    } else {
        TLS_PARAMETERS tp{};
        tp.grbitDisabledProtocols = 0;
        SCH_CREDENTIALS sc{};
        sc.dwVersion = SCH_CREDENTIALS_VERSION;
        sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
        sc.cTlsParameters = 1;
        sc.pTlsParameters = &tp;
        if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
                                      nullptr, &sc, nullptr, nullptr, &c.cred, &ts) != SEC_E_OK) return false;
        SCH_CREDENTIALS ss{};
        ss.dwVersion = SCH_CREDENTIALS_VERSION;
        ss.cCreds = 1;
        ss.paCred = &cert;
        ss.cTlsParameters = 1;
        ss.pTlsParameters = &tp;
        if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
                                      nullptr, &ss, nullptr, nullptr, &s.cred, &ts) != SEC_E_OK) return false;
    }

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
        if (dumpHello && i == 0 && !tok.empty()) {
            printf("    ClientHello %zu B:", tok.size());
            for (size_t k = 0; k < tok.size() && k < 12; k++) printf(" %02x", tok[k]);
            bool has43 = false, has2b = false;
            for (size_t k = 0; k + 1 < tok.size(); k++) {
                if (tok[k] == 0x00 && tok[k + 1] == 0x2b) has2b = true;
                if (tok[k] == 0x00 && tok[k + 1] == 0x0a) has43 = true;
            }
            printf("  ext:supported_versions(0x002b)=%d supported_groups(0x000a)=%d\n", (int)has2b, (int)has43);
        }
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) { printf("    client step %s\n", Hr(stc)); return false; }
        if (tok.empty() && stc == SEC_E_OK) break;
        {
            SecBuffer ob2{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc obd2{SECBUFFER_VERSION, 1, &ob2};
            SecBuffer ib2 = {(unsigned long)tok.size(), SECBUFFER_TOKEN, tok.data()};
            SecBufferDesc ibd2{SECBUFFER_VERSION, 1, &ib2};
            DWORD a2 = 0;
            sts = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr, &ibd2,
                                        ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                            ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                                            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                                        SECURITY_NATIVE_DREP, &s.ctx, &obd2, &a2, nullptr);
            s.haveCtx = true;
            tok.clear();
            if (ob2.pvBuffer) {
                tok.assign((BYTE*)ob2.pvBuffer, (BYTE*)ob2.pvBuffer + ob2.cbBuffer);
                FreeContextBuffer(ob2.pvBuffer);
            }
        }
        if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) { printf("    server step %s\n", Hr(sts)); return false; }
        if (sts == SEC_E_OK && stc == SEC_E_OK) break;
    }
    if (stc != SEC_E_OK || sts != SEC_E_OK) return false;
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &c.sizes);
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    return true;
}

static std::vector<BYTE> Enc(Conn& c, size_t n, SECURITY_STATUS* out = nullptr) {
    std::vector<BYTE> plain(n, 'Z');
    std::vector<BYTE> rec(c.sizes.cbHeader + n + c.sizes.cbTrailer);
    SecBuffer bs[3];
    bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
    bs[1] = {(unsigned long)n, SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
    bs[2] = {c.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader + n};
    memcpy(bs[1].pvBuffer, plain.data(), n);
    SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
    SECURITY_STATUS st = EncryptMessage(&c.ctx, 0, &d, 0);
    if (out) *out = st;
    if (st != SEC_E_OK) return {};
    rec.resize(bs[0].cbBuffer + bs[1].cbBuffer + bs[2].cbBuffer);
    return rec;
}

static SECURITY_STATUS Dec(Conn& s, const std::vector<BYTE>& in, const char* tag) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    printf("    %-30s in=%5zu -> %s", tag, in.size(), Hr(st));
    for (int i = 0; i < 4; i++) printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
    printf("\n");
    return st;
}

int main() {
    printf("== 1. legacy SCHANNEL_CRED with TLS1.3 bit: ClientHello contents ==\n");
    {
        Conn c, s;
        bool ok = Loopback(c, s, 0, SP_PROT_TLS1_3, true);
        printf("    handshake ok=%d\n", (int)ok);
        if (ok) {
            SecPkgContext_ConnectionInfo ci{};
            QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
            printf("    negotiated proto=0x%lX\n", (unsigned long)ci.dwProtocol);
        }
    }
    printf("== 2. legacy SCHANNEL_CRED with TLS1.2|TLS1.3: ClientHello contents ==\n");
    {
        Conn c, s;
        bool ok = Loopback(c, s, 0, SP_PROT_TLS1_2 | SP_PROT_TLS1_3, true);
        printf("    handshake ok=%d\n", (int)ok);
        if (ok) {
            SecPkgContext_ConnectionInfo ci{};
            QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
            printf("    negotiated proto=0x%lX\n", (unsigned long)ci.dwProtocol);
        }
    }
    printf("== 3. SCH_CREDENTIALS: ClientHello contents (expect 1.3) ==\n");
    {
        Conn c, s;
        bool ok = Loopback(c, s, 1, 0, true);
        printf("    handshake ok=%d\n", (int)ok);
        if (ok) {
            SecPkgContext_ConnectionInfo ci{};
            QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
            printf("    negotiated proto=0x%lX hdr=%lu trl=%lu max=%lu\n", (unsigned long)ci.dwProtocol,
                   c.sizes.cbHeader, c.sizes.cbTrailer, c.sizes.cbMaximumMessage);
            SECURITY_STATUS st;
            auto r1 = Enc(c, 16, &st);
            printf("    enc(16) st=%s record=%zu (sizes say %lu+16+%lu=%lu)\n", Hr(st), r1.size(),
                   c.sizes.cbHeader, c.sizes.cbTrailer,
                   c.sizes.cbHeader + 16 + c.sizes.cbTrailer);
            Dec(s, r1, "tls1.3 record");
            auto r2 = Enc(c, 16, &st);
            std::vector<BYTE> both = r1;
            both.insert(both.end(), r2.begin(), r2.end());
            Dec(s, both, "tls1.3 two records (drain once)");
            auto r3 = Enc(c, 16, &st);
            Dec(s, r3, "tls1.3 next record");
            // missing-byte semantics on TLS1.3
            auto r4 = Enc(c, 16, &st);
            Dec(s, std::vector<BYTE>(r4.begin(), r4.begin() + 5), "tls1.3 first 5 bytes");
            Dec(s, r4, "tls1.3 full");
        }
    }
    printf("== 4. SECBUFFER_MISSING at exact 13 bytes (TLS1.2) ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, 0, SP_PROT_TLS1_2, false)) {
            SECURITY_STATUS st;
            auto r = Enc(c, 16, &st);
            Dec(s, std::vector<BYTE>(r.begin(), r.begin() + 13), "first 13 bytes");
            Dec(s, std::vector<BYTE>(r.begin(), r.begin() + 14), "first 14 bytes");
            Dec(s, r, "full");
        }
    }
    printf("== 5. EncryptMessage with undersized buffer ==\n");
    {
        Conn c, s;
        if (Loopback(c, s, 1, 0, false)) {
            // header only, no room for trailer
            size_t n = 16;
            std::vector<BYTE> rec(c.sizes.cbHeader + n);
            SecBuffer bs[3];
            bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
            bs[1] = {(unsigned long)n, SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
            bs[2] = {0, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader + n};
            SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
            SECURITY_STATUS st = EncryptMessage(&c.ctx, 0, &d, 0);
            printf("    no trailer room -> %s\n", Hr(st));
        }
    }
    return 0;
}
