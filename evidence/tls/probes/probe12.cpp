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
#include <string>

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

static bool Loopback(Conn& c, Conn& s, DWORD disabled) {
    TimeStamp ts{};
    PCCERT_CONTEXT cert = nullptr;
    if (!MakeCert(&cert)) return false;
    TLS_PARAMETERS tp{};
    tp.grbitDisabledProtocols = disabled;
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
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) return false;
        if (tok.empty() && stc == SEC_E_OK) break;
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
        if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) return false;
        if (sts == SEC_E_OK && stc == SEC_E_OK) break;
    }
    if (stc != SEC_E_OK || sts != SEC_E_OK) return false;
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &c.sizes);
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    return true;
}

static std::vector<BYTE> Enc(Conn& c, const std::vector<BYTE>& plain) {
    std::vector<BYTE> rec(c.sizes.cbHeader + plain.size() + c.sizes.cbTrailer);
    SecBuffer bs[3];
    bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
    bs[1] = {(unsigned long)plain.size(), SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
    bs[2] = {c.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader + plain.size()};
    memcpy(bs[1].pvBuffer, plain.data(), plain.size());
    SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
    if (EncryptMessage(&c.ctx, 0, &d, 0) != SEC_E_OK) return {};
    rec.resize(bs[0].cbBuffer + bs[1].cbBuffer + bs[2].cbBuffer);
    return rec;
}

struct Drain {
    int messages = 0;
    std::vector<BYTE> joined;
    SECURITY_STATUS last = SEC_E_OK;
};

// Correct drain loop: keep only the EXTRA bytes for the next call.
static Drain DrainAll(Conn& s, const std::vector<BYTE>& input) {
    Drain out;
    std::vector<BYTE> pending = input;
    for (int guard = 0; guard < 32 && !pending.empty(); guard++) {
        std::vector<BYTE> buf(pending);
        SecBuffer bs[4];
        for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
        bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
        SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
        SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
        out.last = st;
        if (st != SEC_E_OK) {
            printf("      drain iter %d: %s on %zu B\n", guard, Hr(st), buf.size());
            break;
        }
        out.messages++;
        std::vector<BYTE> extra;
        for (int i = 0; i < 4; i++) {
            if (bs[i].BufferType == SECBUFFER_DATA && bs[i].cbBuffer)
                out.joined.insert(out.joined.end(), (BYTE*)bs[i].pvBuffer,
                                  (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
            if (bs[i].BufferType == SECBUFFER_EXTRA && bs[i].cbBuffer)
                extra.assign((BYTE*)bs[i].pvBuffer, (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
        }
        pending = extra;
    }
    return out;
}

int main() {
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
        printf("== %s ==\n", pass == 0 ? "TLS1.2" : "TLS1.3");
        Conn c, s;
        if (!Loopback(c, s, disabled)) { printf("  hs fail\n"); continue; }
        SecPkgContext_ConnectionInfo ci{};
        QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
        printf("  proto=0x%lX hdr=%lu trl=%lu\n", (unsigned long)ci.dwProtocol, c.sizes.cbHeader,
               c.sizes.cbTrailer);

        std::vector<BYTE> p1 = {'A', 'A', 'A', 'A'};
        std::vector<BYTE> p2 = {'B', 'B', 'B', 'B', 'B'};
        std::vector<BYTE> p3 = {'C', 'C'};
        std::vector<BYTE> all;
        for (auto* p : {&p1, &p2, &p3}) {
            auto r = Enc(c, *p);
            all.insert(all.end(), r.begin(), r.end());
        }
        printf("  3 records = %zu B\n", all.size());
        Drain d = DrainAll(s, all);
        printf("  messages=%d joined=%zu last=%s payload=", d.messages, d.joined.size(), Hr(d.last));
        for (BYTE b : d.joined) printf("%c", b);
        printf("\n");
        printf("  expected AAAA BBBBB CC -> match=%d\n",
               (int)(std::string(d.joined.begin(), d.joined.end()) == std::string("AAAABBBBBCC")));

        // exactly one record then a second call with the next record
        {
            auto r1 = Enc(c, p1);
            Drain a = DrainAll(s, r1);
            auto r2 = Enc(c, p2);
            Drain b = DrainAll(s, r2);
            printf("  sequential: %d/%d match=%d\n", a.messages, b.messages,
                   (int)(b.joined == p2));
        }
        // re-feed already-consumed bytes -> what happens?
        {
            auto r1 = Enc(c, p1);
            DrainAll(s, r1);
            Drain again = DrainAll(s, r1);
            printf("  re-feed consumed record -> %s (expect failure)\n", Hr(again.last));
            auto r3 = Enc(c, p3);
            Drain after = DrainAll(s, r3);
            printf("  next fresh record after that -> %s (context usable?)\n", Hr(after.last));
        }
    }
    return 0;
}
