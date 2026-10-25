#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

static const char* Hr(HRESULT hr) {
    static char buf[64];
    sprintf_s(buf, "0x%08lX", (unsigned long)hr);
    return buf;
}

struct Conn {
    CredHandle cred{};
    CtxtHandle ctx{};
    bool haveCtx = false;
    SecPkgContext_StreamSizes sizes{};
    DWORD proto = 0;
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

static std::vector<BYTE> ClientStep(Conn& c, const std::vector<BYTE>& in, SECURITY_STATUS& st) {
    std::vector<BYTE> out;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    SecBuffer ib{};
    SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
    if (!in.empty()) {
        ib.BufferType = SECBUFFER_TOKEN;
        ib.cbBuffer = (unsigned long)in.size();
        ib.pvBuffer = const_cast<BYTE*>(in.data());
        ibd.cBuffers = 1;
        ibd.pBuffers = &ib;
    }
    DWORD attrs = 0;
    DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                ISC_REQ_MANUAL_CRED_VALIDATION;
    st = InitializeSecurityContextW(&c.cred, c.haveCtx ? &c.ctx : nullptr,
                                    const_cast<SEC_WCHAR*>(L"rtsc-probe"), req, 0,
                                    SECURITY_NATIVE_DREP, in.empty() ? nullptr : &ibd, 0,
                                    &c.ctx, &obd, &attrs, nullptr);
    c.haveCtx = true;
    if (ob.pvBuffer) {
        out.assign((BYTE*)ob.pvBuffer, (BYTE*)ob.pvBuffer + ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    return out;
}

static std::vector<BYTE> ServerStep(Conn& s, const std::vector<BYTE>& in, SECURITY_STATUS& st) {
    std::vector<BYTE> out;
    SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
    SecBuffer ib{};
    SecBufferDesc ibd{SECBUFFER_VERSION, 0, nullptr};
    if (!in.empty()) {
        ib.BufferType = SECBUFFER_TOKEN;
        ib.cbBuffer = (unsigned long)in.size();
        ib.pvBuffer = const_cast<BYTE*>(in.data());
        ibd.cBuffers = 1;
        ibd.pBuffers = &ib;
    }
    DWORD attrs = 0;
    st = AcceptSecurityContext(&s.cred, s.haveCtx ? &s.ctx : nullptr,
                               in.empty() ? nullptr : &ibd,
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

static bool Handshake(Conn& c, Conn& s, DWORD protoMask) {
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = protoMask;
    sc.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    TimeStamp ts{};
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                  SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr,
                                  &c.cred, &ts) != SEC_E_OK) { printf("  credC fail\n"); return false; }
    PCCERT_CONTEXT cert = nullptr;
    if (!MakeCert(&cert)) { printf("  makecert fail\n"); return false; }
    SCHANNEL_CRED ss{};
    ss.dwVersion = SCHANNEL_CRED_VERSION;
    ss.cCreds = 1;
    ss.paCred = &cert;
    ss.grbitEnabledProtocols = protoMask | (protoMask >> 1);
    if (AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                  SECPKG_CRED_INBOUND, nullptr, &ss, nullptr, nullptr,
                                  &s.cred, &ts) != SEC_E_OK) { printf("  credS fail\n"); return false; }

    std::vector<BYTE> tok;
    SECURITY_STATUS stc = SEC_I_CONTINUE_NEEDED, sts = SEC_I_CONTINUE_NEEDED;
    for (int i = 0; i < 12; i++) {
        tok = ClientStep(c, tok, stc);
        if (stc != SEC_I_CONTINUE_NEEDED && stc != SEC_E_OK) { printf("  client step %s\n", Hr(stc)); return false; }
        if (tok.empty() && stc == SEC_E_OK) break;
        tok = ServerStep(s, tok, sts);
        if (sts != SEC_I_CONTINUE_NEEDED && sts != SEC_E_OK) { printf("  server step %s\n", Hr(sts)); return false; }
        if (sts == SEC_E_OK && stc == SEC_E_OK) break;
    }
    if (stc != SEC_E_OK || sts != SEC_E_OK) return false;
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &c.sizes);
    QueryContextAttributesW(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    return true;
}

static std::vector<BYTE> Encrypt(Conn& c, const std::vector<BYTE>& plain, SECURITY_STATUS& st) {
    size_t total = c.sizes.cbHeader + plain.size() + c.sizes.cbTrailer;
    std::vector<BYTE> rec(total);
    SecBuffer bs[3];
    bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
    bs[1] = {(unsigned long)plain.size(), SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
    bs[2] = {c.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader + plain.size()};
    memcpy(bs[1].pvBuffer, plain.data(), plain.size());
    SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
    st = EncryptMessage(&c.ctx, 0, &d, 0);
    if (st != SEC_E_OK) return {};
    size_t got = bs[0].cbBuffer + bs[1].cbBuffer + bs[2].cbBuffer;
    rec.resize(got);
    return rec;
}

static void Dec(const char* tag, Conn& s, const std::vector<BYTE>& in) {
    std::vector<BYTE> buf(in);
    SecBuffer bs[4];
    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
    bs[1] = {0, SECBUFFER_EMPTY, nullptr};
    bs[2] = {0, SECBUFFER_EMPTY, nullptr};
    bs[3] = {0, SECBUFFER_EMPTY, nullptr};
    SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
    SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
    printf("  %-28s in=%3zu -> %s", tag, in.size(), Hr(st));
    for (int i = 0; i < 4; i++)
        printf(" [%d:t%lu,cb%lu]", i, bs[i].BufferType, bs[i].cbBuffer);
    printf("\n");
}

int main() {
    printf("=== isolate: decrypt direction ===\n");
    Conn c, s;
    if (!Handshake(c, s, SP_PROT_TLS1_2_CLIENT)) { printf("handshake fail\n"); return 1; }
    printf("hdr=%lu trl=%lu max=%lu\n", c.sizes.cbHeader, c.sizes.cbTrailer, c.sizes.cbMaximumMessage);
    std::vector<BYTE> plain = {'H', 'E', 'L', 'L', 'O'};
    SECURITY_STATUS st;
    std::vector<BYTE> r1 = Encrypt(c, plain, st);
    printf("c->s record %zu bytes st=%s\n", r1.size(), Hr(st));
    Dec("c->s first record", s, r1);
    std::vector<BYTE> r2 = Encrypt(s, plain, st);
    printf("s->c record %zu bytes st=%s\n", r2.size(), Hr(st));
    Dec("s->c first record", c, r2);
    std::vector<BYTE> r3 = Encrypt(c, plain, st);
    Dec("c->s second record", s, r3);
    return 0;
}
