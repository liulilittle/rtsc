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

static bool Loopback(Conn& c, Conn& s, DWORD disabled, DWORD* protoOut) {
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
    SecPkgContext_ConnectionInfo ci{};
    QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci);
    if (protoOut) *protoOut = ci.dwProtocol;
    return true;
}

static std::vector<BYTE> Enc(Conn& c, const BYTE* p, size_t n) {
    std::vector<BYTE> rec(c.sizes.cbHeader + n + c.sizes.cbTrailer);
    SecBuffer bs[3];
    bs[0] = {c.sizes.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()};
    bs[1] = {(unsigned long)n, SECBUFFER_DATA, rec.data() + c.sizes.cbHeader};
    bs[2] = {c.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + c.sizes.cbHeader + n};
    memcpy(bs[1].pvBuffer, p, n);
    SecBufferDesc d{SECBUFFER_VERSION, 3, bs};
    if (EncryptMessage(&c.ctx, 0, &d, 0) != SEC_E_OK) return {};
    rec.resize(bs[0].cbBuffer + bs[1].cbBuffer + bs[2].cbBuffer);
    return rec;
}

int main() {
    for (int pass = 0; pass < 2; pass++) {
        DWORD disabled = pass == 0 ? SP_PROT_TLS1_3_CLIENT : SP_PROT_TLS1_2_CLIENT;
        DWORD proto = 0;
        Conn c, s;
        if (!Loopback(c, s, disabled, &proto)) { printf("hs fail\n"); continue; }
        printf("== proto=0x%04lX maxmsg=%lu ==\n", (unsigned long)proto,
               c.sizes.cbMaximumMessage);

        // 1) A 65528-byte TPKT payload must be chunked into ceil(65528/16384)=4 records.
        {
            std::vector<BYTE> big(65528);
            for (size_t i = 0; i < big.size(); i++) big[i] = (BYTE)(i * 13 + 7);
            std::vector<BYTE> wire;
            size_t off = 0;
            int records = 0;
            while (off < big.size()) {
                size_t chunk = big.size() - off;
                if (chunk > c.sizes.cbMaximumMessage) chunk = c.sizes.cbMaximumMessage;
                auto r = Enc(c, big.data() + off, chunk);
                if (r.empty()) { printf("  chunk encrypt FAILED at off=%zu\n", off); break; }
                wire.insert(wire.end(), r.begin(), r.end());
                off += chunk;
                records++;
            }
            printf("  65528-byte PDU -> %d records, %zu wire bytes\n", records, wire.size());
            // read back with the drain loop
            std::vector<BYTE> pending = wire;
            std::vector<BYTE> plain;
            int calls = 0;
            while (!pending.empty()) {
                std::vector<BYTE> buf(pending);
                SecBuffer bs[4];
                for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
                bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
                SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
                SECURITY_STATUS st = DecryptMessage(&s.ctx, &d, 0, nullptr);
                calls++;
                if (st != SEC_E_OK) { printf("  decrypt call %d -> %s\n", calls, Hr(st)); break; }
                std::vector<BYTE> extra;
                for (int i = 0; i < 4; i++) {
                    if (bs[i].BufferType == SECBUFFER_DATA && bs[i].cbBuffer)
                        plain.insert(plain.end(), (BYTE*)bs[i].pvBuffer,
                                     (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
                    if (bs[i].BufferType == SECBUFFER_EXTRA && bs[i].cbBuffer)
                        extra.assign((BYTE*)bs[i].pvBuffer, (BYTE*)bs[i].pvBuffer + bs[i].cbBuffer);
                }
                pending = extra;
            }
            printf("  read back: %d decrypt calls, %zu plaintext, match=%d\n", calls, plain.size(),
                   (int)(plain == big));
        }

        // 2) On SEC_E_DECRYPT_FAILURE the DATA buffer still holds plaintext.
        {
            Conn c2, s2;
            DWORD p2 = 0;
            if (Loopback(c2, s2, disabled, &p2)) {
                std::vector<BYTE> plain(48);
                for (size_t i = 0; i < plain.size(); i++) plain[i] = (BYTE)('a' + (i % 26));
                auto rec = Enc(c2, plain.data(), plain.size());
                auto bad = rec;
                bad[bad.size() - 1] ^= 0x01;
                std::vector<BYTE> buf(bad);
                SecBuffer bs[4];
                for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
                bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
                SecBufferDesc d{SECBUFFER_VERSION, 4, bs};
                SECURITY_STATUS st = DecryptMessage(&s2.ctx, &d, 0, nullptr);
                size_t dl = 0;
                for (int i = 0; i < 4; i++)
                    if (bs[i].BufferType == SECBUFFER_DATA) dl = bs[i].cbBuffer;
                printf("  tampered -> %s DATA cbBuffer=%zu (== record size %zu)\n", Hr(st), dl, bad.size());
                printf("      first 16 bytes of DATA buffer after failure:");
                for (int i = 0; i < 16 && (size_t)i < buf.size(); i++) printf(" %02x", buf[i]);
                printf("\n      original plaintext:");
                for (int i = 0; i < 16; i++) printf(" %02x", plain[i]);
                printf("\n");
            }
        }

        // 3) 4-buffer minimum, re-confirmed.
        {
            Conn c3, s3;
            DWORD p3 = 0;
            if (Loopback(c3, s3, disabled, &p3)) {
                auto rec = Enc(c3, (const BYTE*)"hi", 2);
                for (int nb = 1; nb <= 4; nb++) {
                    std::vector<BYTE> buf(rec);
                    SecBuffer bs[4];
                    for (int i = 0; i < 4; i++) bs[i] = {0, SECBUFFER_EMPTY, nullptr};
                    bs[0] = {(unsigned long)buf.size(), SECBUFFER_DATA, buf.data()};
                    SecBufferDesc d{SECBUFFER_VERSION, (unsigned long)nb, bs};
                    printf("  nbuf=%d -> %s\n", nb, Hr(DecryptMessage(&s3.ctx, &d, 0, nullptr)));
                }
            }
        }
    }
    return 0;
}
