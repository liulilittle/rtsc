// SChannel backend for rtsc::tls::TlsTransport.
//
// Design reference: docs/spec/tls-backend.design-a.md
//   闁?.4.1  the record framing / buffering pseudocode implemented below
//   闁?.4.3  the twelve boundaries covered by tests/test_tls.cpp
//
// Everything SChannel-specific stays in this translation unit. The public
// header has no Windows types, so the protocol layer compiles unchanged on
// other platforms (which get their own backend, or none at all).
//
// Measured SChannel facts this file depends on (evidence/tls/):
//   * DecryptMessage needs at least four SecBuffers and sb[0] must be
//     SECBUFFER_DATA holding the whole record, header included.
//   * SECBUFFER_EXTRA.pvBuffer may be NULL (the ISC path) or point inside the
//     caller's buffer (the DecryptMessage path). Only cbBuffer is ever read;
//     the tail is located arithmetically as record.size() - extra_len.
//   * TLS 1.3 reports a NewSessionTicket as SEC_I_RENEGOTIATE (0x00090321)
//     with data=0 and the raw handshake record in EXTRA.
//   * cbTrailer is an allocation upper bound, not the actual trailer length
//     (TLS 1.3: 44 reserved, 17 written).
//   * SEC_I_NO_RENEGOTIATION (0x00090360) only occurs on TLS 1.3.
//   * Shutdown needs ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY with a null
//     input descriptor and a null output pvBuffer.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SECURITY_WIN32

#include <windows.h>
#include <bcrypt.h>
#include <winternl.h>
// SCH_CREDENTIALS / TLS_PARAMETERS (the only SChannel credential form that can
// enable TLS 1.3) live behind this switch in schannel.h. Without it the header
// only exposes the legacy SCHANNEL_CRED, which silently caps the handshake at
// TLS 1.2 no matter what grbitEnabledProtocols says -- measured on Windows 11
// 26200: legacy mask TLS1_2|TLS1_3 still negotiated 0x0303, while the
// SCH_CREDENTIALS form negotiated 0x0304.
#define SCHANNEL_USE_BLACKLISTS 1
#include <schannel.h>
#include <sspi.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/net/tls.h"

#include "tls_schannel_internal.h"

namespace rtsc::tls {
namespace {

constexpr size_t kMinRecordHeader = 5;
constexpr uint32_t kMaxRecordPayload = 16384;
// RFC 8446 5.2: ciphertext may exceed the plaintext limit by 256 bytes.
constexpr uint32_t kMaxRecordLength = kMaxRecordPayload + 256;

constexpr uint8_t kRecordChangeCipherSpec = 20;
constexpr uint8_t kRecordAlert = 21;
constexpr uint8_t kRecordHandshake = 22;
constexpr uint8_t kRecordApplicationData = 23;

constexpr uint16_t kTls12 = 0x0303;
constexpr uint16_t kTls13 = 0x0304;

std::string FormatCode(long code) {
    char buf[32];
    sprintf_s(buf, "0x%08lX", static_cast<unsigned long>(code));
    return buf;
}

// DNS names and configured hosts are ASCII (IDNs are punycode), so a plain
// ASCII fold is enough and avoids locale-dependent behaviour.
unsigned char AsciiLower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c - 'A' + 'a') : c;
}

bool EqualsIgnoreCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (AsciiLower(static_cast<unsigned char>(a[i])) !=
            AsciiLower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool EndsWithIgnoreCase(const std::string& value, const std::string& suffix) {
    if (value.size() < suffix.size()) return false;
    return EqualsIgnoreCase(value.substr(value.size() - suffix.size()), suffix);
}

// Two-label country-code public suffixes (the "ccSLD" set). A wildcard whose
// base is exactly one of these would otherwise sweep every host under a whole
// country second level ("*.co.uk" <=> any domain under .co.uk), which is the
// RFC 6125 6.4.3 abuse the probe flagged as a P2 over-permission. The list is
// a SIMPLIFIED subset derived from the public suffix list (publicsuffix.org,
// ccTLD section): ~450 common two-label registrable country suffixes,
// deliberately narrower than the full PSL. Entries are hand-maintained and
// MUST stay sorted ascending (the lookup is a binary search); adding a new
// suffix is a manual edit, not an auto-sync. Registered-domain suffixes such
// as "uk.com" (a privately registrable domain, NOT a public suffix) are
// intentionally absent.
static constexpr const char* const kCcSld[] = {
    "ac.ca", "ac.cy", "ac.id", "ac.il", "ac.in", "ac.jp", "ac.ke", "ac.kr",
    "ac.nz", "ac.rs", "ac.ru", "ac.tz", "ac.uk", "ac.vn", "ac.za", "ad.jp",
    "asn.au", "biz.cy", "biz.id", "biz.tr", "biz.vn", "club.tw", "co.am", "co.cr",
    "co.id", "co.il", "co.in", "co.ir", "co.jp", "co.ke", "co.kr", "co.ma",
    "co.ni", "co.nz", "co.rs", "co.th", "co.tz", "co.ug", "co.uk", "co.za",
    "co.zm", "com.am", "com.ar", "com.au", "com.az", "com.bo", "com.br", "com.by",
    "com.cn", "com.co", "com.cy", "com.do", "com.ec", "com.eg", "com.es", "com.ge",
    "com.gr", "com.hk", "com.hn", "com.hr", "com.kz", "com.mx", "com.my", "com.ng",
    "com.ni", "com.pa", "com.pe", "com.ph", "com.pl", "com.pt", "com.py", "com.ro",
    "com.ru", "com.sa", "com.sg", "com.tn", "com.tr", "com.tw", "com.ua", "com.ug",
    "com.uy", "com.ve", "com.vn", "com.zm", "coop.py", "csiro.au", "desa.id", "ed.jp",
    "edu.am", "edu.ar", "edu.au", "edu.az", "edu.br", "edu.cn", "edu.co", "edu.ec",
    "edu.eg", "edu.es", "edu.ge", "edu.gr", "edu.hk", "edu.in", "edu.jo", "edu.kr",
    "edu.kz", "edu.mx", "edu.my", "edu.ng", "edu.nz", "edu.pe", "edu.ph", "edu.pl",
    "edu.pt", "edu.ro", "edu.rs", "edu.ru", "edu.sa", "edu.sg", "edu.tr", "edu.tw",
    "edu.ua", "edu.uy", "edu.ve", "edu.vn", "edu.za", "ekloges.cy", "ens.tn", "es.kr",
    "eun.eg", "fi.cr", "fin.ec", "firm.in", "firm.ro", "from.hr", "gc.ca", "geek.nz",
    "gen.in", "gen.nz", "gen.tr", "go.id", "go.jp", "go.ke", "go.kr", "go.th",
    "go.tz", "go.ug", "gob.ar", "gob.es", "gob.mx", "gob.pe", "gov.am", "gov.ar",
    "gov.au", "gov.az", "gov.br", "gov.by", "gov.cn", "gov.co", "gov.cy", "gov.do",
    "gov.ec", "gov.eg", "gov.ge", "gov.gr", "gov.hk", "gov.il", "gov.in", "gov.ir",
    "gov.kz", "gov.ma", "gov.my", "gov.ng", "gov.ph", "gov.pl", "gov.pt", "gov.rs",
    "gov.ru", "gov.sa", "gov.sg", "gov.tn", "gov.tr", "gov.tw", "gov.ua", "gov.uk",
    "gov.vn", "gov.za", "govt.nz", "gr.jp", "gub.uy", "hs.kr", "id.au", "id.ir",
    "id.vn", "idv.hk", "idv.tw", "in.rs", "in.th", "in.ua", "ind.br", "ind.gt",
    "ind.in", "inf.br", "info.az", "info.hu", "info.in", "info.ke", "info.ro", "info.tn",
    "info.tr", "info.tz", "info.ve", "info.vn", "info.zm", "int.ar", "int.az", "int.bo",
    "int.pt", "int.ru", "int.vn", "intl.tn", "iwi.nz", "iz.hr", "k12.tr", "kg.kr",
    "law.za", "lg.jp", "ltd.cy", "ltd.uk", "maori.nz", "mb.ca", "me.ke", "me.tz",
    "me.uk", "med.br", "med.sa", "mi.th", "mil.am", "mil.ar", "mil.br", "mil.cn",
    "mil.co", "mil.ec", "mil.eg", "mil.id", "mil.kr", "mil.kz", "mil.my", "mil.nz",
    "mil.pe", "mil.ru", "mil.tz", "mil.uy", "mil.za", "mobi.ke", "mobi.ng", "mobi.tz",
    "ms.kr", "msk.ru", "muni.il", "my.id", "name.az", "name.cy", "name.eg", "name.hr",
    "name.ng", "name.tr", "name.vn", "nat.tn", "nb.ca", "ne.jp", "ne.ke", "ne.kr",
    "ne.tz", "ne.ug", "net.am", "net.ar", "net.au", "net.az", "net.bo", "net.br",
    "net.by", "net.cn", "net.co", "net.cy", "net.do", "net.ec", "net.eg", "net.ge",
    "net.gr", "net.gt", "net.hk", "net.hn", "net.hr", "net.id", "net.il", "net.in",
    "net.ir", "net.kz", "net.ma", "net.mx", "net.my", "net.ng", "net.ni", "net.nz",
    "net.pa", "net.pe", "net.ph", "net.pl", "net.pt", "net.ru", "net.sa", "net.sg",
    "net.th", "net.tn", "net.tr", "net.tw", "net.ua", "net.uk", "net.uy", "net.ve",
    "net.vn", "net.za", "net.zm", "nf.ca", "ngo.ph", "nhs.uk", "nl.ca", "nom.co",
    "nom.es", "nom.my", "nom.pe", "nom.ro", "nome.pt", "ns.ca", "nt.ca", "nt.ro",
    "nu.ca", "of.by", "on.ca", "or.cr", "or.id", "or.jp", "or.ke", "or.kr",
    "or.th", "or.tz", "or.ug", "org.am", "org.ar", "org.au", "org.az", "org.bo",
    "org.br", "org.by", "org.cn", "org.co", "org.cy", "org.do", "org.ec", "org.eg",
    "org.es", "org.ge", "org.gr", "org.gt", "org.hk", "org.hn", "org.il", "org.in",
    "org.ir", "org.kz", "org.ma", "org.mx", "org.my", "org.ng", "org.ni", "org.nz",
    "org.pa", "org.pe", "org.ph", "org.pl", "org.pt", "org.ro", "org.rs", "org.ru",
    "org.sa", "org.sg", "org.tn", "org.tr", "org.tw", "org.ua", "org.uk", "org.uy",
    "org.ve", "org.vn", "org.za", "org.zm", "pe.ca", "pe.kr", "per.sg", "perso.tn",
    "plc.uk", "pol.tr", "police.uk", "ponpes.id", "pp.ru", "pp.ua", "press.cy", "press.ma",
    "pro.br", "pro.cy", "pro.vn", "pub.sa", "publ.pt", "pvt.ge", "qc.ca", "re.kr",
    "rec.br", "res.in", "sa.cr", "sc.ke", "sc.kr", "sc.tz", "sch.id", "sch.ir",
    "sch.ng", "sch.sa", "sch.uk", "sch.zm", "school.nz", "sci.br", "sci.eg", "sk.ca",
    "sld.do", "spb.ru", "tel.tr", "tm.cy", "tm.ro", "tourism.tn", "tsk.tr", "tv.bo",
    "tv.tz", "web.do", "web.id", "web.tr", "web.ve", "web.za", "yk.ca",
};
constexpr size_t kCcSldCount = sizeof(kCcSld) / sizeof(kCcSld[0]);

constexpr bool kCcSldIsSorted() {
    for (size_t i = 1; i < kCcSldCount; ++i) {
        size_t j = 0;
        while (kCcSld[i - 1][j] != '\0' && kCcSld[i][j] != '\0' &&
               kCcSld[i - 1][j] == kCcSld[i][j]) {
            ++j;
        }
        if (static_cast<unsigned char>(kCcSld[i - 1][j]) >
            static_cast<unsigned char>(kCcSld[i][j])) {
            return false;
        }
    }
    return true;
}
static_assert(kCcSldIsSorted(), "kCcSld must be sorted ascending for the binary search");

bool IsCcSldSuffix(const std::string& rest) {
    std::string lower = rest;
    for (char& c : lower) {
        c = static_cast<char>(AsciiLower(static_cast<unsigned char>(c)));
    }
    size_t lo = 0;
    size_t hi = kCcSldCount;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const int cmp = lower.compare(kCcSld[mid]);
        if (cmp == 0) return true;
        if (cmp < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return false;
}

// RFC 6125 single-label wildcard, hardened against public-suffix and FQDN
// abuse. Rules in order:
//   1. A single trailing dot is the same name (FQDN form); strip ONE from both
//      sides first. An empty or dot-terminated remainder (".", "..", "a..") is
//      a degenerate name and is rejected.
//   2. Non-wildcard: exact case-insensitive equality.
//   3. Wildcard "*.rest":
//      a. "rest" must contain at least one '.' -- "*.com" / "*.cn" are
//         rejected structurally (RFC 6125 6.4.3 forbids a wildcard in front of
//         a bare TLD), with no suffix table needed.
//      b. "rest" must NOT be a two-label ccSLD table entry: "*.co.uk" /
//         "*.com.au" are rejected, so a wildcard cannot sweep a whole country
//         second level. A registered domain is NOT a ccSLD: "*.foo.co.uk" and
//         the privately registrable "*.uk.com" keep matching.
//      c. the host must be exactly "label.rest" with one dot-free label:
//         "*.example.com" matches "a.example.com", never the bare domain and
//         never "a.b.example.com".
// This is INTENTIONALLY STRICTER than the OpenSSL backend (X509_check_host has
// no ccSLD table -- it accepts "*.co.uk" -- and rejects trailing-dot FQDNs).
// That single-side divergence is a documented known-ok difference, not a bug:
// SChannel refuses wildcard public suffixes and harmonizes FQDNs. See
// tls_openssl.cpp Start() and tests/test_tls_openssl.cpp
// openssl_x509_check_host_wildcard_semantics_locked.
bool DnsNameMatches(const std::string& pattern, const std::string& host) {
    std::string p = pattern;
    std::string h = host;
    if (!p.empty() && p.back() == '.') p.pop_back();
    if (!h.empty() && h.back() == '.') h.pop_back();
    if (p.empty() || h.empty()) return false;              // "" / "."
    if (p.back() == '.' || h.back() == '.') return false;  // ".." / "a.."

    if (p.size() > 2 && p[0] == '*' && p[1] == '.') {
        const std::string rest = p.substr(2);
        if (rest.empty() || rest.front() == '.' ||
            rest.find('.') == std::string::npos) {
            return false;  // "*.", "*..x", "*.com", "*.cn"
        }
        if (IsCcSldSuffix(rest)) return false;  // "*.co.uk", "*.com.au"
        const std::string suffix = "." + rest;
        if (h.size() <= rest.size()) return false;
        if (!EndsWithIgnoreCase(h, suffix)) return false;
        const std::string label = h.substr(0, h.size() - suffix.size());
        return !label.empty() && label.find('.') == std::string::npos;
    }
    return EqualsIgnoreCase(p, h);
}

std::string WideToUtf8(const wchar_t* w, int len) {
    if (w == nullptr || len <= 0) return std::string();
    const int need = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    if (need <= 0) return std::string();
    std::string out(static_cast<size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, out.data(), need, nullptr, nullptr);
    return out;
}

bool Sha256(const std::vector<uint8_t>& data, std::array<uint8_t, 32>& digest) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                                    nullptr, 0))) {
        return false;
    }
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) {
        ok = BCRYPT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(data.data()),
                                           static_cast<ULONG>(data.size()), 0)) &&
             BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(),
                                             static_cast<ULONG>(digest.size()), 0));
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

struct HostMatchResult {
    bool matched = false;
    bool had_dns_san = false;
    std::string names;  // comma-joined certificate names, for the error message
};

// Matches `host` against the certificate's subjectAltName dNSName entries,
// falling back to the subject CN only when no dNSName entry exists. The CN is
// retrieved with CertGetNameStringW and the subject string with CertNameToStrW
// is kept for diagnostics, so a rejection is reportable.
HostMatchResult CertificateMatchesHost(PCCERT_CONTEXT cert, const std::string& host) {
    HostMatchResult result;
    std::vector<std::string> names;

    const CERT_EXTENSION* ext =
        CertFindExtension(szOID_SUBJECT_ALT_NAME2, cert->pCertInfo->cExtension,
                          cert->pCertInfo->rgExtension);
    if (ext == nullptr) {
        ext = CertFindExtension(szOID_SUBJECT_ALT_NAME, cert->pCertInfo->cExtension,
                                cert->pCertInfo->rgExtension);
    }
    if (ext != nullptr) {
        CERT_ALT_NAME_INFO* alt = nullptr;
        DWORD size = 0;
        if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, ext->Value.pbData,
                                ext->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &alt,
                                &size)) {
            for (DWORD i = 0; i < alt->cAltEntry; ++i) {
                if (alt->rgAltEntry[i].dwAltNameChoice != CERT_ALT_NAME_DNS_NAME) continue;
                result.had_dns_san = true;
                const wchar_t* dns = alt->rgAltEntry[i].pwszDNSName;
                if (dns == nullptr) continue;
                const std::string name =
                    WideToUtf8(dns, static_cast<int>(wcslen(dns)));
                if (name.empty()) continue;
                if (DnsNameMatches(name, host)) result.matched = true;
                names.push_back(name);
            }
            LocalFree(alt);
        }
    }

    if (!result.had_dns_san) {
        wchar_t buf[512];
        char oid[] = "2.5.4.3";  // szOID_COMMON_NAME
        const DWORD n = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, oid, buf,
                                           static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])));
        if (n > 1) {
            const std::string cn = WideToUtf8(buf, static_cast<int>(n - 1));
            if (!cn.empty()) {
                if (DnsNameMatches(cn, host)) result.matched = true;
                names.push_back(cn);
            }
        }
        if (names.empty()) {
            wchar_t subject[512];
            if (CertNameToStrW(X509_ASN_ENCODING, &cert->pCertInfo->Subject,
                               CERT_X500_NAME_STR, subject,
                               static_cast<DWORD>(sizeof(subject) / sizeof(subject[0]))) >
                1) {
                names.push_back(
                    WideToUtf8(subject, static_cast<int>(wcslen(subject))));
            } else {
                names.push_back("(no CN)");
            }
        }
    }

    for (size_t i = 0; i < names.size(); ++i) {
        if (i != 0) result.names += ", ";
        result.names += names[i];
    }
    return result;
}

// Parses a TLS record header. Returns false when the record type is not one
// TLS 1.2/1.3 can legally put on the wire.
bool ParseRecordHeader(const uint8_t* p, uint8_t& type, uint16_t& version,
                       uint32_t& length) {
    type = p[0];
    version = static_cast<uint16_t>((p[1] << 8) | p[2]);
    length = static_cast<uint32_t>((p[3] << 8) | p[4]);
    return type == kRecordChangeCipherSpec || type == kRecordAlert ||
           type == kRecordHandshake || type == kRecordApplicationData;
}

// Maps a SChannel status to the transport status. Returns kOk for statuses the
// caller handles explicitly (SEC_E_OK, SEC_I_CONTINUE_NEEDED, ...), so the
// switch in the caller stays exhaustive and readable.
struct DecryptOutcome {
    Status status = Status::kOk;
    size_t extra_len = 0;
    bool handled = false;  // true when `status` is final for this record
};

Status MapShutdownStatus(SECURITY_STATUS st);

class SchannelTransport final : public TlsTransport {
public:
    explicit SchannelTransport(const Config& config) : config_(config) {}
    ~SchannelTransport() override {
        if (have_ctx_) DeleteSecurityContext(&ctx_);
        if (have_cred_) FreeCredentialsHandle(&cred_);
        if (peer_cert_) CertFreeCertificateContext(peer_cert_);
        if (server_cert_) CertFreeCertificateContext(server_cert_);
    }

    bool Start(std::string& why) {
        if (!AcquireCredentials(why)) return false;
        return true;
    }

    // ---------------------------------------------------------------- handshake
    Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,
                    std::vector<uint8_t>& out) override {
        if (config_.role == Role::kServer) {
            return HandshakeServer(in, in_size, consumed, out);
        }
        consumed = 0;
        out.clear();
        if (terminal_) return last_error_;
        if (closed_) return MakeError(Status::kClosed, 0, "already closed");
        if (handshake_complete_) {
            // Post-handshake bytes are handled by Receive; consuming them here
            // would silently drop records.
            return MakeError(Status::kOk, 0, "");
        }
        if (config_.cert_policy == CertPolicy::kStrict && config_.peer_host.empty() &&
            config_.sni.empty()) {
            // A strict client without a name can never verify the peer.
            return FailWith(Status::kCertRejected, "no peer host to verify");
        }

        std::vector<uint8_t> token;
        if (in_size != 0) token.assign(in, in + in_size);

        SecBuffer in_bufs[1]{};
        // ISC needs a real output buffer unless ALLOCATE_MEMORY is requested.
        // With cbBuffer == 0 and pvBuffer == nullptr SChannel answers
        // SEC_E_INVALID_TOKEN (0x80090308) on the very first call.
        uint8_t out_storage[65536] = {};
        SecBuffer out_buf{sizeof(out_storage), SECBUFFER_TOKEN, out_storage};
        SecBufferDesc in_desc{SECBUFFER_VERSION, 0, nullptr};
        SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};
        if (!token.empty()) {
            in_bufs[0].BufferType = SECBUFFER_TOKEN;
            in_bufs[0].cbBuffer = static_cast<unsigned long>(token.size());
            in_bufs[0].pvBuffer = token.data();
            in_desc.ulVersion = SECBUFFER_VERSION;
            in_desc.cBuffers = 1;
            in_desc.pBuffers = in_bufs;
        }

        DWORD out_flags = 0;
        // kInsecure keeps manual validation: SChannel then accepts any peer.
        // kStrict/kTofu must not set ISC_REQ_MANUAL_CRED_VALIDATION because it
        // disables SChannel's own chain build (measured: with it the deferred
        // result is not populated and the query fails). Deferred validation is
        // requested at credential acquisition instead: the matching value
        // ISC_REQ_DEFERRED_CRED_VALIDATION is a 64-bit flag that cannot fit in
        // this 32-bit fContextReq parameter and would truncate to zero.
        const DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                          ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                          ISC_REQ_STREAM | IscPolicyFlag();

        const std::wstring target = TargetName();
        const SECURITY_STATUS st = InitializeSecurityContextW(
            &cred_, have_ctx_ ? &ctx_ : nullptr,
            target.empty() ? nullptr : const_cast<SEC_WCHAR*>(target.c_str()), req, 0,
            SECURITY_NATIVE_DREP, in_desc.cBuffers ? &in_desc : nullptr, 0, &ctx_,
            &out_desc, &out_flags, nullptr);

        if (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK ||
            st == SEC_I_INCOMPLETE_CREDENTIALS) {
            have_ctx_ = true;
        }
        if (out_buf.cbBuffer > 0 && out_buf.pvBuffer != nullptr) {
            const auto* p = static_cast<const uint8_t*>(out_buf.pvBuffer);
            out.assign(p, p + out_buf.cbBuffer);
        }
        // Handshake input is fully absorbed: SChannel's stream handshake does
        // not report EXTRA, and leaving bytes unconsumed would make the caller
        // replay them forever.
        consumed = in_size;

        switch (st) {
            case SEC_E_OK: {
                const Error finished = FinishHandshake(why_);
                if (!finished.ok()) {
                    last_error_ = finished;
                    terminal_ = true;
                    return last_error_;
                }
                return MakeError(Status::kOk, 0, "");
            }
            case SEC_I_CONTINUE_NEEDED:
                return MakeError(Status::kNeedMoreInput, 0, "");
            case SEC_I_INCOMPLETE_CREDENTIALS:
                // The peer wants a client certificate; this client has none.
                return Fail(Status::kUnsupported, st);
            case SEC_E_INCOMPLETE_MESSAGE:
                return MakeError(Status::kNeedMoreInput, st, "incomplete handshake");
            case SEC_E_ILLEGAL_MESSAGE:
            case SEC_E_INVALID_TOKEN:
            case SEC_E_UNSUPPORTED_FUNCTION:
                return Fail(Status::kProtocolError, st);
            case SEC_E_ALGORITHM_MISMATCH:
            case SEC_E_NO_CREDENTIALS:
            case SEC_E_UNKNOWN_CREDENTIALS:
                return Fail(Status::kUnsupported, st);
            case SEC_E_CERT_UNKNOWN:
            case SEC_E_WRONG_PRINCIPAL:
            case SEC_E_CERT_EXPIRED:
                return Fail(Status::kCertRejected, st);
            default:
                return Fail(Status::kInternal, st);
        }
    }

    // Server half of the handshake (AcceptSecurityContext). The token
    // semantics match the client: the input token is consumed in full, output
    // (if any) goes to the peer, and the handshake completes once SChannel
    // reports SEC_E_OK.
    Error HandshakeServer(const uint8_t* in, size_t in_size, size_t& consumed,
                          std::vector<uint8_t>& out) {
        consumed = 0;
        out.clear();
        if (terminal_) return last_error_;
        if (closed_) return MakeError(Status::kClosed, 0, "already closed");
        if (handshake_complete_) return MakeError(Status::kOk, 0, "");

        std::vector<uint8_t> token;
        if (in_size != 0) token.assign(in, in + in_size);

        uint8_t out_storage[65536] = {};
        SecBuffer in_buf{static_cast<unsigned long>(token.size()), SECBUFFER_TOKEN,
                         token.empty() ? nullptr : token.data()};
        SecBuffer out_buf{sizeof(out_storage), SECBUFFER_TOKEN, out_storage};
        SecBufferDesc in_desc{SECBUFFER_VERSION, token.empty() ? 0u : 1u, &in_buf};
        SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};

        DWORD req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                    ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_STREAM;
        DWORD out_flags = 0;
        // pfContextAttr is an [out] parameter and must be a valid pointer;
        // passing nullptr crashes inside SSPICLI (FreeContextBuffer).
        const SECURITY_STATUS st = AcceptSecurityContext(
            &cred_, have_ctx_ ? &ctx_ : nullptr,
            token.empty() ? nullptr : &in_desc, req, SECURITY_NATIVE_DREP, &ctx_,
            &out_desc, &out_flags, nullptr);
        if (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK) have_ctx_ = true;
        if (out_buf.cbBuffer > 0 && out_buf.pvBuffer != nullptr) {
            const auto* p = static_cast<const uint8_t*>(out_buf.pvBuffer);
            out.assign(p, p + out_buf.cbBuffer);
        }
        consumed = in_size;

        switch (st) {
            case SEC_E_OK: {
                const Error finished = FinishHandshake(why_);
                if (!finished.ok()) {
                    last_error_ = finished;
                    terminal_ = true;
                    return last_error_;
                }
                return MakeError(Status::kOk, 0, "");
            }
            case SEC_I_CONTINUE_NEEDED:
                return MakeError(Status::kNeedMoreInput, 0, "");
            case SEC_E_INCOMPLETE_MESSAGE:
                return MakeError(Status::kNeedMoreInput, st, "incomplete handshake");
            case SEC_E_ILLEGAL_MESSAGE:
            case SEC_E_INVALID_TOKEN:
                return Fail(Status::kProtocolError, st);
            case SEC_E_NO_CREDENTIALS:
            case SEC_E_UNKNOWN_CREDENTIALS:
            case SEC_E_ALGORITHM_MISMATCH:
                return Fail(Status::kUnsupported, st);
            default:
                return Fail(Status::kInternal, st);
        }
    }

    // --------------------------------------------------------------------- send
    Error Send(const uint8_t* plaintext, size_t size, size_t& consumed,
               std::vector<uint8_t>& out) override {
        consumed = 0;
        out.clear();
        if (terminal_) return last_error_;
        if (closed_) return MakeError(Status::kClosed, 0, "already closed");
        if (!handshake_complete_) {
            return MakeError(Status::kProtocolError, 0, "handshake not complete");
        }
        if (size == 0) {
            // A zero-length payload is legal and must produce a real record.
            return EncryptOne(nullptr, 0, consumed, out);
        }
        const size_t chunk = MaxChunk();
        size_t done = 0;
        while (done < size) {
            const size_t n = std::min(chunk, size - done);
            Error e = EncryptOne(plaintext + done, n, consumed, out);
            if (!e.ok()) return e;
            done += n;
        }
        consumed = size;
        return MakeError(Status::kOk, 0, "");
    }

    // ------------------------------------------------------------------ receive
    Error Receive(const uint8_t* ciphertext, size_t size,
                  std::vector<uint8_t>& plaintext, size_t max_out) override {
        if (closed_ && rx_buffer_.empty()) return MakeError(Status::kClosed, 0, "already closed");
        if (terminal_) return last_error_;

        if (size != 0 && ciphertext != nullptr) {
            rx_buffer_.insert(rx_buffer_.end(), ciphertext, ciphertext + size);
        }

        size_t progressed = 0;
        size_t produced = 0;
        std::vector<uint8_t> tmp;

        for (;;) {
            if (rx_buffer_.size() < kMinRecordHeader) {
                return (progressed != 0 || produced != 0)
                           ? MakeError(Status::kOk, 0, "")
                           : MakeError(Status::kNeedMoreInput, 0, "");
            }
            uint8_t type = 0;
            uint16_t version = 0;
            uint32_t length = 0;
            if (!ParseRecordHeader(rx_buffer_.data(), type, version, length)) {
                return Fail(Status::kProtocolError, 0);
            }
            if (length > kMaxRecordLength) {
                return Fail(Status::kProtocolError, 0);
            }
            const size_t record_size = kMinRecordHeader + length;
            if (rx_buffer_.size() < record_size) {
                return (progressed != 0 || produced != 0)
                           ? MakeError(Status::kOk, 0, "")
                           : MakeError(Status::kNeedMoreInput, 0, "");
            }

            // Take the record out before decrypting. Doing this first is what
            // makes every later `continue` correct: the record is already
            // consumed, so it can never be decrypted twice.
            std::vector<uint8_t> record(rx_buffer_.begin(),
                                        rx_buffer_.begin() +
                                            static_cast<ptrdiff_t>(record_size));
            rx_buffer_.erase(rx_buffer_.begin(),
                             rx_buffer_.begin() + static_cast<ptrdiff_t>(record_size));

            tmp.clear();
            size_t extra_len = 0;
            const SECURITY_STATUS st = DecryptRecord(record, tmp, extra_len);
            if (st == SEC_E_INCOMPLETE_MESSAGE) {
                // The record header said it was complete, so this is not "need
                // more bytes". Pushing it back would make the buffer grow
                // without bound, because the next call re-reads the same bytes.
                return Fail(Status::kProtocolError, st);
            }

            if (st == SEC_I_RENEGOTIATE) {
                if (NegotiatedVersion() == kTls13) {
                    // TLS 1.3 NewSessionTicket: feed EXTRA back once and drop
                    // whatever comes out. RDP does not allow renegotiation.
                    //
                    // A ticket is a CONTROL record: it produces no plaintext, so
                    // it must NOT count as progress. Counting it would make the
                    // loop report kOk with an empty plaintext once the buffer
                    // runs dry, and the caller (which trusts kOk to mean "here
                    // is data") would drop the application record that arrives
                    // in the next read. Measured before the fix: a TLS 1.3
                    // loopback handshaked, then the first Server-to-Client read
                    // returned kOk with 0 bytes and the payload was lost.
                    std::vector<uint8_t> discarded;
                    FeedExtraOnce(extra_len, record, discarded);
                    continue;
                }
                return Fail(Status::kProtocolError, st);
            }
            if (st == SEC_I_NO_RENEGOTIATION) {
                if (NegotiatedVersion() == kTls13) {
                    // Same reasoning as SEC_I_RENEGOTIATE: no plaintext, so it
                    // is not progress.
                    continue;
                }
                return Fail(Status::kProtocolError, st);
            }
            if (st == SEC_I_CONTEXT_EXPIRED) {
                // Normal end of stream. Keep the plaintext decoded so far: the
                // peer may have sent application data right before close_notify.
                closed_ = true;
                return MakeError(Status::kClosed, st, "peer closed");
            }
            if (st == SEC_E_MESSAGE_ALTERED || st == SEC_E_DECRYPT_FAILURE) {
                return Fail(Status::kDecryptFailed, st);
            }
            if (st == SEC_E_INVALID_TOKEN || st == SEC_E_ILLEGAL_MESSAGE) {
                return Fail(Status::kProtocolError, st);
            }
            if (st == SEC_E_OK) {
                // Normal path: fall through to the success handling below.
            } else if (st == SEC_I_CONTINUE_NEEDED) {
                // Handshake data arrived after the handshake finished (e.g. a
                // post-handshake auth request). Not supported: treat as a
                // protocol violation rather than handing the bytes upwards.
                return Fail(Status::kProtocolError, st);
            } else {
                return Fail(Status::kInternal, st);
            }

            if (extra_len != 0) {
                // Arithmetic only: pvBuffer may be NULL or point into our own
                // buffer, so its address is never used.
                const size_t tail_off = record.size() - extra_len;
                std::vector<uint8_t> tail(record.begin() + static_cast<ptrdiff_t>(tail_off),
                                          record.end());
                tail.insert(tail.end(), rx_buffer_.begin(), rx_buffer_.end());
                rx_buffer_.swap(tail);
            }

            plaintext.insert(plaintext.end(), tmp.begin(), tmp.end());
            produced += tmp.size();
            // Progress means "this call produced something the caller can use".
            // Control records (TLS 1.3 tickets) consume bytes without producing
            // plaintext and therefore do NOT count (see the SEC_I_RENEGOTIATE
            // branch): counting them made Receive answer kOk with an empty
            // payload, and a caller that trusts kOk then dropped the real
            // record arriving in the next read.
            //
            // COVERAGE: UNVERIFIED. A TLS 1.3 loopback that reaches this branch
            // needs a peer context that survives the post-handshake ticket
            // flight; the in-repo RawServer fixture cannot build one (its
            // STREAM_SIZES query fails with SEC_E_INTERNAL_ERROR before any
            // ticket is emitted), so no test currently fails if this line is
            // reverted to "count every record". The TLS 1.3 negotiation itself
            // IS covered (tls13_loopback_negotiates_1_3).
            ++progressed;
            if (max_out != 0 && produced >= max_out) {
                // Soft threshold: the caller must keep calling until
                // buffered_input() == 0, otherwise records stay stranded.
                return MakeError(Status::kOk, 0, "");
            }
            // Explicit back edge: without it a single Receive call decodes at
            // most one record.
            continue;
        }
    }

    // -------------------------------------------------- local (server) identity
    Error LocalCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        if (server_cert_ == nullptr) return NotHandshaken();
        out.assign(server_cert_->pbCertEncoded,
                   server_cert_->pbCertEncoded + server_cert_->cbCertEncoded);
        return MakeError(Status::kOk, 0, "");
    }

    Error LocalSubjectPublicKey(std::vector<uint8_t>& out) const override {
        out.clear();
        if (server_cert_ == nullptr) return NotHandshaken();
        const CRYPT_BIT_BLOB& key =
            server_cert_->pCertInfo->SubjectPublicKeyInfo.PublicKey;
        if (key.pbData == nullptr || key.cbData == 0) {
            return ConstError(Status::kInternal, 0, "local key is empty");
        }
        out.assign(key.pbData, key.pbData + key.cbData);
        return MakeError(Status::kOk, 0, "");
    }

    // ------------------------------------------------------------- peer identity
    Error PeerSubjectPublicKeyInfo(std::vector<uint8_t>& out) const override {
        if (!handshake_complete_) {
            out.clear();
            return NotHandshaken();
        }
        return ReadPeerSpki(out);
    }

    Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {
        out.clear();
        PCCERT_CONTEXT cert = PeerCert();
        if (cert == nullptr) return NotHandshaken();
        // Take the key straight from the decoded structure. Slicing the SPKI at
        // a fixed offset would break for other key sizes (RSA-1024 uses 22, not
        // 24), so the offset is never assumed.
        const CRYPT_BIT_BLOB& key = cert->pCertInfo->SubjectPublicKeyInfo.PublicKey;
        if (key.pbData == nullptr || key.cbData == 0) {
            return ConstError(Status::kInternal, 0, "peer key is empty");
        }
        out.assign(key.pbData, key.pbData + key.cbData);
        return MakeError(Status::kOk, 0, "");
    }

    Error PeerCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        PCCERT_CONTEXT cert = PeerCert();
        if (cert == nullptr) return NotHandshaken();
        out.assign(cert->pbCertEncoded, cert->pbCertEncoded + cert->cbCertEncoded);
        return MakeError(Status::kOk, 0, "");
    }

    // ---------------------------------------------------------------- negotiated
    Error negotiated(NegotiatedInfo& out) const override {
        if (!handshake_complete_) return NotHandshaken();
        out = info_;
        return MakeError(Status::kOk, 0, "");
    }

    RecordSizes record_sizes() const override { return sizes_; }

    // ----------------------------------------------------------------- shutdown
    Error Shutdown(std::vector<uint8_t>& out) override {
        out.clear();
        if (shutdown_sent_) return MakeError(Status::kOk, 0, "");
        if (!have_ctx_) {
            shutdown_sent_ = true;
            return MakeError(Status::kProtocolError, 0, "shutdown before handshake");
        }
        DWORD shutdown_type = SCHANNEL_SHUTDOWN;
        SecBuffer token{sizeof(shutdown_type), SECBUFFER_TOKEN, &shutdown_type};
        SecBufferDesc desc{SECBUFFER_VERSION, 1, &token};
        ApplyControlToken(&ctx_, &desc);

        DWORD out_flags = 0;
        const DWORD req = config_.role == Role::kServer
                              ? static_cast<DWORD>(ASC_REQ_STREAM) | ASC_REQ_ALLOCATE_MEMORY
                              : static_cast<DWORD>(ISC_REQ_STREAM) | ISC_REQ_ALLOCATE_MEMORY;
        // Input descriptor must be null and the output buffer must have a null
        // pvBuffer: SChannel allocates it and we free it afterwards.
        SecBuffer out_buf{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc out_desc{SECBUFFER_VERSION, 1, &out_buf};
        SECURITY_STATUS st = SEC_E_OK;
        if (config_.role == Role::kServer) {
            st = AcceptSecurityContext(&cred_, &ctx_, nullptr, req, SECURITY_NATIVE_DREP,
                                       &ctx_, &out_desc, &out_flags, nullptr);
        } else {
            st = InitializeSecurityContextW(&cred_, &ctx_, nullptr, req, 0,
                                            SECURITY_NATIVE_DREP, nullptr, 0, &ctx_,
                                            &out_desc, &out_flags, nullptr);
        }
        shutdown_sent_ = true;
        if (out_buf.cbBuffer > 0 && out_buf.pvBuffer != nullptr) {
            const auto* p = static_cast<const uint8_t*>(out_buf.pvBuffer);
            out.assign(p, p + out_buf.cbBuffer);
            FreeContextBuffer(out_buf.pvBuffer);
        }
        const Status mapped = MapShutdownStatus(st);
        if (mapped == Status::kOk) {
            closed_ = true;
            return MakeError(Status::kOk, st, "");
        }
        closed_ = true;
        return MakeError(mapped, st, "shutdown failed");
    }

    // -------------------------------------------------------------------- state
    bool handshake_complete() const noexcept override { return handshake_complete_; }
    bool closed() const noexcept override { return closed_; }
    size_t buffered_input() const noexcept override { return rx_buffer_.size(); }
    const Error& last_error() const noexcept override { return last_error_; }
    const char* backend_name() const noexcept override { return "schannel"; }

private:
    // ------------------------------------------------------------- credentials
    bool AcquireCredentials(std::string& why) {
        if (config_.role == Role::kServer) {
            return AcquireServerCredentials(why);
        }
        // Tier 1: the modern SCH_CREDENTIALS form. It is the ONLY credential
        // form that can enable TLS 1.3: the legacy SCHANNEL_CRED silently caps
        // the handshake at TLS 1.2 (measured on Win11 26200 — legacy mask
        // TLS1_2|TLS1_3 negotiated 0x0303; SCH_CREDENTIALS negotiated 0x0304).
        // Protocols are expressed as a DENY list here, so the deny mask is
        // exactly the complement of the allow mask ProtocolMask() computes.
        {
            TLS_PARAMETERS tp{};
            const DWORD deny = DeniedProtocolsForClient();
            tp.grbitDisabledProtocols = deny;

            SCH_CREDENTIALS cred{};
            cred.dwVersion = SCH_CREDENTIALS_VERSION;
            cred.cTlsParameters = 1;
            cred.pTlsParameters = &tp;
            // The context-level ISC_REQ_DEFERRED_CRED_VALIDATION value is 64-bit
            // (0x0000000200000000) and fContextReq is a 32-bit unsigned long, so
            // it truncates to zero if OR-ed into the handshake flags. The
            // credential flag is the usable switch: SChannel then builds the
            // chain, records the result, and does not fail the handshake.
            if (config_.cert_policy != CertPolicy::kInsecure) {
                cred.dwFlags |= SCH_CRED_DEFERRED_CRED_VALIDATION;
            }

            TimeStamp ts{};
            SECURITY_STATUS st = AcquireCredentialsHandleW(
                nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                SECPKG_CRED_OUTBOUND, nullptr, &cred, nullptr, nullptr, &cred_, &ts);
            if (st == SEC_E_OK) {
                have_cred_ = true;
                return true;
            }
            // Fall through to the legacy form so an OS without the modern
            // entry point still connects (TLS 1.2 only). Record nothing: the
            // post-handshake version window check still enforces the contract.
            why = "SCH_CREDENTIALS(outbound) failed: " + FormatCode(st) +
                  "; falling back to legacy SCHANNEL_CRED (TLS 1.2 only)";
        }

        SCHANNEL_CRED legacy{};
        legacy.dwVersion = SCHANNEL_CRED_VERSION;
        legacy.grbitEnabledProtocols = ProtocolMask();
        if (config_.cert_policy != CertPolicy::kInsecure) {
            legacy.dwFlags |= SCH_CRED_DEFERRED_CRED_VALIDATION;
        }

        TimeStamp ts{};
        SECURITY_STATUS st = AcquireCredentialsHandleW(
            nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND,
            nullptr, &legacy, nullptr, nullptr, &cred_, &ts);
        if (st != SEC_E_OK) {
            why = "AcquireCredentialsHandle failed: " + FormatCode(st);
            return false;
        }
        have_cred_ = true;
        return true;
    }

    // The deny mask for SCH_CREDENTIALS: every protocol this configuration is
    // NOT allowed to negotiate. It must agree with ProtocolMask() (the legacy
    // allow list) or the two credential paths would honour different windows.
    //
    // TLS 1.3 is only OFFERED when the caller explicitly asks for it
    // (min_version == 0x0304). Rationale: the legacy SCHANNEL_CRED path that
    // every existing caller used silently capped the handshake at TLS 1.2, so
    // "allow_tls13 = true" never actually produced 1.3. Migrating to
    // SCH_CREDENTIALS without this guard would silently switch the whole
    // product to TLS 1.3, and the RDP data plane then fails against the
    // in-tree server (measured: SEC_E_ILLEGAL_MESSAGE 0x80090317 in
    // server_security). Opt-in keeps every existing configuration byte-for-byte
    // identical while making 1.3 reachable.
    DWORD DeniedProtocolsForClient() const {
        constexpr DWORD kAll = SP_PROT_TLS1_0 | SP_PROT_TLS1_1 | SP_PROT_TLS1_2 |
                               SP_PROT_TLS1_3 | SP_PROT_SSL3 | SP_PROT_SSL2;
        DWORD allow = ProtocolMask();
        if (config_.min_version < kTls13) allow &= ~SP_PROT_TLS1_3_CLIENT;
        return kAll & ~allow;
    }

    DWORD DeniedProtocolsForServer() const {
        constexpr DWORD kAll = SP_PROT_TLS1_0 | SP_PROT_TLS1_1 | SP_PROT_TLS1_2 |
                               SP_PROT_TLS1_3 | SP_PROT_SSL3 | SP_PROT_SSL2;
        DWORD allow = ServerProtocolMask();
        if (config_.min_version < kTls13) allow &= ~SP_PROT_TLS1_3_SERVER;
        return kAll & ~allow;
    }

    // Creates an ephemeral self-signed certificate in the default CSP. The
    // server has no pre-provisioned identity, so the client is expected to
    // accept it through its own trust policy (the in-tree client uses kInsecure
    // / kTofu; mstsc shows the standard untrusted-certificate prompt).
    bool MakeSelfSignedCert(std::string& why) {
        CERT_NAME_BLOB subject{};
        const char name[] = "CN=rtsc-rdp-server";
        if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                            nullptr, &subject.cbData, nullptr)) {
            why = "CertStrToName(size) failed";
            return false;
        }
        std::vector<uint8_t> name_der(subject.cbData);
        subject.pbData = name_der.data();
        if (!CertStrToNameA(X509_ASN_ENCODING, name, CERT_X500_NAME_STR, nullptr,
                            subject.pbData, &subject.cbData, nullptr)) {
            why = "CertStrToName(data) failed";
            return false;
        }
        server_cert_ = CertCreateSelfSignCertificate(0, &subject, 0, nullptr, nullptr,
                                                     nullptr, nullptr, nullptr);
        if (server_cert_ == nullptr) {
            why = "CertCreateSelfSignCertificate failed";
            return false;
        }
        return true;
    }

    bool AcquireServerCredentials(std::string& why) {
        if (!MakeSelfSignedCert(why)) return false;

        // Tier 1: SCH_CREDENTIALS, the only form that can offer TLS 1.3.
        // Measured on Win11 26200: the legacy form with mask TLS1_2|TLS1_3
        // negotiated 0x0303, the modern form 0x0304.
        {
            TLS_PARAMETERS tp{};
            tp.grbitDisabledProtocols = DeniedProtocolsForServer();

            SCH_CREDENTIALS cred{};
            cred.dwVersion = SCH_CREDENTIALS_VERSION;
            cred.cCreds = 1;
            PCCERT_CONTEXT certs[1] = {server_cert_};
            cred.paCred = certs;
            cred.cTlsParameters = 1;
            cred.pTlsParameters = &tp;

            TimeStamp ts{};
            const SECURITY_STATUS st = AcquireCredentialsHandleW(
                nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
                nullptr, &cred, nullptr, nullptr, &cred_, &ts);
            if (st == SEC_E_OK) {
                have_cred_ = true;
                return true;
            }
            why = "SCH_CREDENTIALS(inbound) failed: " + FormatCode(st) +
                  "; falling back to legacy SCHANNEL_CRED (TLS 1.2 only)";
        }

        SCHANNEL_CRED legacy{};
        legacy.dwVersion = SCHANNEL_CRED_VERSION;
        legacy.grbitEnabledProtocols = ServerProtocolMask();
        legacy.cCreds = 1;
        legacy.paCred = &server_cert_;

        TimeStamp ts{};
        const SECURITY_STATUS st = AcquireCredentialsHandleW(
            nullptr, const_cast<SEC_WCHAR*>(UNISP_NAME_W), SECPKG_CRED_INBOUND,
            nullptr, &legacy, nullptr, nullptr, &cred_, &ts);
        if (st != SEC_E_OK) {
            why = "AcquireCredentialsHandle(inbound) failed: " + FormatCode(st);
            return false;
        }
        have_cred_ = true;
        return true;
    }

    DWORD ServerProtocolMask() const {
        // Legacy SCHANNEL_CRED cannot express a TLS 1.3 lower bound without the
        // SCH_CREDENTIALS version, so the server advertises the same window the
        // client does. TLS 1.2 is always enabled; TLS 1.3 is requested when the
        // config allows it, and SChannel downgrades cleanly if the client (or
        // the local build) cannot negotiate it.
        DWORD mask = 0;
        if (config_.allow_tls10) mask |= SP_PROT_TLS1_0_SERVER;
        if (config_.min_version <= kTls12 && config_.max_version >= kTls12) {
            mask |= SP_PROT_TLS1_2_SERVER;
        }
        if (config_.allow_tls13 && config_.max_version >= kTls13) {
            mask |= SP_PROT_TLS1_3_SERVER;
        }
        if (mask == 0) mask = SP_PROT_TLS1_2_SERVER;
        return mask;
    }

    DWORD ProtocolMask() const {
        // grbitEnabledProtocols is a whitelist, so it cannot express a lower
        // bound; the post-handshake self-check enforces the real window.
        DWORD mask = 0;
        if (config_.allow_tls10) mask |= SP_PROT_TLS1_0_CLIENT;
        if (config_.min_version <= kTls12 && config_.max_version >= kTls12) {
            mask |= SP_PROT_TLS1_2_CLIENT;
        }
        if (config_.allow_tls13 && config_.max_version >= kTls13) {
            mask |= SP_PROT_TLS1_3_CLIENT;
            mask |= SP_PROT_TLS1_2_CLIENT;
        }
        if (mask == 0) mask = SP_PROT_TLS1_2_CLIENT;
        return mask;
    }

    std::wstring TargetName() const {
        std::string name = config_.sni;
        if (name.empty()) name = config_.peer_host;
        if (name.empty()) return std::wstring();
        const int need = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, nullptr, 0);
        if (need <= 0) return std::wstring();
        std::wstring w(static_cast<size_t>(need - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, w.data(), need);
        return w;
    }

    // ------------------------------------------------------------ post-handshake
    // Runs exactly once when SChannel reports SEC_E_OK and before
    // handshake_complete_ becomes observable, so a rejected peer is never
    // treated as handshaken. The server role is exempt: its self-signed
    // identity is the normal accept path and is not the peer under evaluation.
    Error FinishHandshake(std::string& why) {
        SecPkgContext_StreamSizes ss{};
        if (QueryContextAttributesW(&ctx_, SECPKG_ATTR_STREAM_SIZES, &ss) != SEC_E_OK) {
            why = "SECPKG_ATTR_STREAM_SIZES failed";
            return MakeError(Status::kInternal, 0, why);
        }
        sizes_.header = ss.cbHeader;
        sizes_.max_plaintext = ss.cbMaximumMessage;
        sizes_.overhead_upper = ss.cbTrailer;
        sizes_.block_size = ss.cbBlockSize;
        // cbTrailer is an allocation bound, not the real trailer length.
        // See ExpectedActualOverhead(): corrected on the first real record.
        sizes_.overhead_actual = ExpectedActualOverhead();

        if (!QueryNegotiated(why)) return MakeError(Status::kInternal, 0, why);
        if (!EnforceVersionWindow(why)) return MakeError(Status::kInternal, 0, why);
        if (config_.role == Role::kClient) {
            const Error verified = VerifyPeerCertificate();
            if (!verified.ok()) return verified;
        }
        handshake_complete_ = true;
        return MakeError(Status::kOk, 0, "");
    }

    Error VerifyPeerCertificate() {
        switch (config_.cert_policy) {
            case CertPolicy::kInsecure:
                return MakeError(Status::kOk, 0, "");
            case CertPolicy::kTofu:
                // Mirrors OpenSSL: kTofu verifies the chain (SSL_VERIFY_PEER)
                // but does not compare the hostname. A configured pin is the
                // TOFU identity and intentionally accepts a self-signed peer.
                if (config_.pin_is_set) return VerifySpkiPin();
                return VerifyChainOnly();
            case CertPolicy::kStrict:
                return VerifyStrictPeer();
        }
        return MakeError(Status::kOk, 0, "");
    }

    // Mirrors tls_openssl.cpp: hash the full SubjectPublicKeyInfo DER and
    // compare it byte-for-byte with the configured pin.
    Error VerifySpkiPin() {
        std::vector<uint8_t> spki;
        if (!ReadPeerSpki(spki).ok() || spki.empty()) {
            return MakeError(Status::kCertRejected, 0, "cannot read the peer SPKI");
        }
        std::array<uint8_t, 32> digest{};
        if (!Sha256(spki, digest)) {
            return MakeError(Status::kInternal, 0, "SHA-256 of the peer SPKI failed");
        }
        if (std::memcmp(digest.data(), config_.pinned_spki_sha256.data(),
                        digest.size()) != 0) {
            return MakeError(Status::kCertRejected, 0, "SPKI pin mismatch");
        }
        return MakeError(Status::kOk, 0, "");
    }

    Error VerifyStrictPeer() {
        const Error chain = VerifyChainOnly();
        if (!chain.ok()) return chain;
        return VerifyHostname();
    }

    // Chain-only verification: the kStrict chain gate and the whole kTofu
    // check when no pin is configured.
    Error VerifyChainOnly() {
        // Deferred credential validation makes SChannel build and verify the
        // chain without failing the handshake; the recorded result is the
        // authority here. An unavailable result cannot be trusted either.
        SecPkgContext_CertificateValidationResult vr{};
        const SECURITY_STATUS q =
            QueryContextAttributesW(&ctx_, SECPKG_ATTR_CERT_CHECK_RESULT, &vr);
        if (q != SEC_E_OK) {
            return MakeError(Status::kCertRejected, static_cast<int32_t>(q),
                             "certificate chain result unavailable: " + FormatCode(q));
        }
        if (vr.dwChainErrorStatus != 0 || FAILED(vr.hrVerifyChainStatus)) {
            return MakeError(
                Status::kCertRejected, static_cast<int32_t>(vr.hrVerifyChainStatus),
                "certificate chain rejected: dwChainErrorStatus=" +
                    FormatCode(static_cast<long>(vr.dwChainErrorStatus)) +
                    " hrVerifyChainStatus=" +
                    FormatCode(static_cast<long>(vr.hrVerifyChainStatus)));
        }
        return MakeError(Status::kOk, 0, "");
    }

    Error VerifyHostname() {
        const std::string host =
            !config_.peer_host.empty() ? config_.peer_host : config_.sni;
        if (host.empty()) {
            return MakeError(Status::kCertRejected, 0, "no peer host to verify");
        }
        PCCERT_CONTEXT cert = FetchPeerCert();
        if (cert == nullptr) {
            return MakeError(Status::kCertRejected, 0,
                             "certificate host mismatch: peer certificate unavailable");
        }
        const HostMatchResult match = CertificateMatchesHost(cert, host);
        if (match.matched) return MakeError(Status::kOk, 0, "");
        return MakeError(Status::kCertRejected, 0,
                         "certificate host mismatch: host=" + host +
                             " certificate=" +
                             (match.names.empty() ? std::string("(none)")
                                                  : match.names));
    }

    // cbTrailer is an allocation upper bound, so the real trailer must come
    // from somewhere else. It cannot be measured without encrypting a record,
    // and encrypting one at handshake time would send a spurious record to the
    // peer. So: start from the value implied by the negotiated version
    // (measured: TLS1.2 = 16, TLS1.3 = 17) and correct it the first time a
    // record is actually produced.
    uint32_t ExpectedActualOverhead() const {
        return info_.tls_version == kTls13 ? 17u : 16u;
    }

    void LearnActualOverhead(size_t plaintext_size, size_t record_size) {
        if (plaintext_size > record_size) return;
        if (record_size < static_cast<size_t>(sizes_.header) + plaintext_size) return;
        const uint32_t actual = static_cast<uint32_t>(
            record_size - sizes_.header - plaintext_size);
        // Only trust the observation when it cannot be the allocation bound
        // leaking through (a real trailer is always <= the reserved bound).
        if (actual != 0 && actual <= sizes_.overhead_upper) {
            sizes_.overhead_actual = actual;
        }
    }

    bool QueryNegotiated(std::string& why) {
        SecPkgContext_ConnectionInfo ci{};
        if (QueryContextAttributesW(&ctx_, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK) {
            // dwProtocol is a SP_PROT_* bit mask (TLS1.2 = 0x00000040), NOT a
            // wire version (0x0303). Masking its high byte yields 0, which the
            // window check then rejects - that is exactly how this was found.
            info_.tls_version = WireVersionFromProtocolMask(ci.dwProtocol);
        }
        // aiCipher is a CALG (0x6610 = CALG_AES_256), never a cipher suite id.
        // SECPKG_ATTR_CIPHER_INFO is the only source of the real suite.
        SecPkgContext_CipherInfo info{};
        info.dwVersion = SECPKG_ATTR_CIPHER_INFO;
        if (QueryContextAttributesW(&ctx_, SECPKG_ATTR_CIPHER_INFO, &info) == SEC_E_OK) {
            info_.cipher_suite = static_cast<uint16_t>(info.dwCipherSuite);
            const int n = WideCharToMultiByte(CP_UTF8, 0, info.szCipherSuite, -1,
                                              info_.cipher_suite_name,
                                              static_cast<int>(sizeof(info_.cipher_suite_name)),
                                              nullptr, nullptr);
            if (n <= 0) {
                info_.cipher_suite_name[0] = '\0';
                why = "cipher suite name is empty";
            }
        } else {
            info_.cipher_suite_name[0] = '\0';
        }
        return true;
    }

    static uint16_t WireVersionFromProtocolMask(DWORD mask) {
        if ((mask & SP_PROT_TLS1_3) != 0) return kTls13;
        if ((mask & SP_PROT_TLS1_2) != 0) return kTls12;
        if ((mask & SP_PROT_TLS1_1) != 0) return 0x0302;
        if ((mask & SP_PROT_TLS1_0) != 0) return 0x0301;
        if ((mask & SP_PROT_SSL3) != 0) return 0x0300;
        return 0;
    }

    bool EnforceVersionWindow(std::string& why) {
        if (info_.tls_version < config_.min_version ||
            info_.tls_version > config_.max_version) {
            why = "negotiated version outside configured window";
            return false;
        }
        return true;
    }

    uint16_t NegotiatedVersion() const { return info_.tls_version; }

    // ------------------------------------------------------------------- crypto
    size_t MaxChunk() const {
        const size_t limit = sizes_.max_plaintext != 0 ? sizes_.max_plaintext
                                                       : kMaxRecordPayload;
        if (config_.max_chunk == 0) return limit;
        return std::min(limit, config_.max_chunk);
    }

    Error EncryptOne(const uint8_t* plaintext, size_t size, size_t& consumed,
                     std::vector<uint8_t>& out) {
        const size_t record_len = sizes_.header + size + sizes_.overhead_upper;
        std::vector<uint8_t> buffer(record_len, 0);
        SecBuffer sb[3]{};
        sb[0] = {sizes_.header, SECBUFFER_STREAM_HEADER, buffer.data()};
        sb[1] = {static_cast<unsigned long>(size), SECBUFFER_DATA,
                 buffer.data() + sizes_.header};
        sb[2] = {sizes_.overhead_upper, SECBUFFER_STREAM_TRAILER,
                 buffer.data() + sizes_.header + size};
        if (size != 0) std::memcpy(sb[1].pvBuffer, plaintext, size);
        SecBufferDesc desc{SECBUFFER_VERSION, 3, sb};
        const SECURITY_STATUS st = EncryptMessage(&ctx_, 0, &desc, 0);
        if (st != SEC_E_OK) {
            return Fail(Status::kInternal, st);
        }
        const size_t written = static_cast<size_t>(sb[0].cbBuffer) +
                               static_cast<size_t>(sb[1].cbBuffer) +
                               static_cast<size_t>(sb[2].cbBuffer);
        LearnActualOverhead(size, written);
        out.insert(out.end(), buffer.begin(),
                   buffer.begin() + static_cast<ptrdiff_t>(written));
        consumed = size;
        return MakeError(Status::kOk, 0, "");
    }

    // Returns the raw SECURITY_STATUS; `extra_len` is the sum of EXTRA.cbBuffer.
    SECURITY_STATUS DecryptRecord(const std::vector<uint8_t>& record,
                                  std::vector<uint8_t>& plaintext,
                                  size_t& extra_len) {
        extra_len = 0;
        std::vector<uint8_t> buffer(record);
        SecBuffer sb[4]{};
        sb[0] = {static_cast<unsigned long>(buffer.size()), SECBUFFER_DATA,
                 buffer.data()};
        for (int i = 1; i < 4; ++i) sb[i] = {0, SECBUFFER_EMPTY, nullptr};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, sb};
        const SECURITY_STATUS st = DecryptMessage(&ctx_, &desc, 0, nullptr);

        size_t total = 0;
        for (int i = 0; i < 4; ++i) {
            if (sb[i].BufferType == SECBUFFER_DATA && sb[i].cbBuffer != 0 &&
                sb[i].pvBuffer != nullptr) {
                const auto* p = static_cast<const uint8_t*>(sb[i].pvBuffer);
                plaintext.assign(p, p + sb[i].cbBuffer);
                total += sb[i].cbBuffer;
            }
            if (sb[i].BufferType == SECBUFFER_EXTRA && sb[i].cbBuffer != 0) {
                // Only cbBuffer is read: pvBuffer may be NULL here.
                extra_len += sb[i].cbBuffer;
            }
        }
        if (total + extra_len > record.size()) {
            return SEC_E_INTERNAL_ERROR;  // contract self-check
        }
        return st;
    }

    void FeedExtraOnce(size_t extra_len, const std::vector<uint8_t>& record,
                       std::vector<uint8_t>& discarded) {
        if (extra_len == 0) return;
        const size_t tail_off = record.size() - extra_len;
        std::vector<uint8_t> token(record.begin() + static_cast<ptrdiff_t>(tail_off),
                                   record.end());
        SecBuffer ib{static_cast<unsigned long>(token.size()), SECBUFFER_TOKEN,
                     token.data()};
        SecBuffer ob{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc ibd{SECBUFFER_VERSION, 1, &ib};
        SecBufferDesc obd{SECBUFFER_VERSION, 1, &ob};
        DWORD flags = 0;
        if (config_.role == Role::kServer) {
            const DWORD req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                              ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                              ASC_REQ_STREAM;
            AcceptSecurityContext(&cred_, &ctx_, &ibd, req, SECURITY_NATIVE_DREP, &ctx_,
                                  &obd, &flags, nullptr);
        } else {
            // Same policy flags as Handshake: a context created with deferred
            // credentials rejects ISC_REQ_MANUAL_CRED_VALIDATION with
            // SEC_E_INVALID_PARAMETER (measured).
            const DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                              ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                              ISC_REQ_STREAM | IscPolicyFlag();
            InitializeSecurityContextW(&cred_, &ctx_, nullptr, req, 0,
                                       SECURITY_NATIVE_DREP, &ibd, 0, &ctx_, &obd, &flags,
                                       nullptr);
        }
        if (ob.cbBuffer > 0 && ob.pvBuffer != nullptr) {
            FreeContextBuffer(ob.pvBuffer);
        }
        discarded.clear();
    }

    // ------------------------------------------------------------------ helpers
    // Manual validation is only requested for kInsecure. kStrict/kTofu rely on
    // the deferred credential flag (see AcquireCredentials): combining that
    // credential flag with ISC_REQ_MANUAL_CRED_VALIDATION fails the handshake
    // with SEC_E_INVALID_PARAMETER (measured).
    DWORD IscPolicyFlag() const {
        return config_.cert_policy == CertPolicy::kInsecure
                   ? static_cast<DWORD>(ISC_REQ_MANUAL_CRED_VALIDATION)
                   : 0u;
    }

    // A certificate context may be needed before handshake_complete_ is set
    // (policy verification); the public PeerCert() keeps the old post-handshake
    // contract while this fetches and caches unconditionally.
    PCCERT_CONTEXT FetchPeerCert() const {
        if (peer_cert_ != nullptr) return peer_cert_;
        PCCERT_CONTEXT peer = nullptr;
        // The API takes a non-const handle even though it only reads; the
        // transport's own state is unchanged, so the cast is local and safe.
        auto* ctx = const_cast<CtxtHandle*>(&ctx_);
        if (QueryContextAttributesW(ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer) !=
            SEC_E_OK) {
            return nullptr;
        }
        peer_cert_ = peer;
        return peer_cert_;
    }

    PCCERT_CONTEXT PeerCert() const {
        if (!handshake_complete_) return nullptr;
        return FetchPeerCert();
    }

    Error ReadPeerSpki(std::vector<uint8_t>& out) const {
        out.clear();
        PCCERT_CONTEXT cert = FetchPeerCert();
        if (cert == nullptr) return NotHandshaken();
        DWORD size = 0;
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                 &cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr,
                                 nullptr, &size)) {
            return ConstError(Status::kInternal, static_cast<int32_t>(GetLastError()),
                              "CryptEncodeObjectEx(size) failed");
        }
        out.resize(size);
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                                 &cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr,
                                 out.data(), &size)) {
            out.clear();
            return ConstError(Status::kInternal, static_cast<int32_t>(GetLastError()),
                              "CryptEncodeObjectEx(data) failed");
        }
        out.resize(size);
        return MakeError(Status::kOk, 0, "");
    }

    Error NotHandshaken() const {
        return ConstError(Status::kProtocolError, 0, "handshake not complete");
    }

    static Error ConstError(Status s, int32_t code, const char* msg) {
        Error e;
        e.status = s;
        e.native_code = code;
        e.message = msg;
        return e;
    }

    Error MakeError(Status s, long code, std::string msg) const {
        Error e;
        e.status = s;
        e.native_code = static_cast<int32_t>(code);
        e.message = std::move(msg);
        return e;
    }

    // Every error exit goes through here so the "clear plaintext" rule is
    // written once instead of at each of the six call sites.
    Error Fail(Status s, long code) {
        last_error_ = MakeError(s, code, FormatCode(code));
        terminal_ = true;
        return last_error_;
    }

    Error FailWith(Status s, std::string message) {
        last_error_ = MakeError(s, 0, std::move(message));
        terminal_ = true;
        return last_error_;
    }

    Config config_;
    CredHandle cred_{};
    CtxtHandle ctx_{};
    bool have_cred_ = false;
    bool have_ctx_ = false;
    bool handshake_complete_ = false;
    bool shutdown_sent_ = false;

    // Cross-call state: these must survive between calls, so they are members
    // rather than locals.
    std::vector<uint8_t> rx_buffer_;
    bool terminal_ = false;
    bool closed_ = false;
    Error last_error_{};

    RecordSizes sizes_{};
    NegotiatedInfo info_{};
    std::string why_;
    mutable PCCERT_CONTEXT peer_cert_ = nullptr;
    // Server role only: the ephemeral self-signed identity created at Start().
    PCCERT_CONTEXT server_cert_ = nullptr;
};

// Maps a SChannel SECURITY_STATUS from the shutdown path to a transport Status.
// SEC_E_OK is success; SEC_I_CONTINUE_NEEDED and any failure status are NOT
// success (S24-b / S24-c).
Status MapShutdownStatus(SECURITY_STATUS st) {
    if (st == SEC_E_OK) return Status::kOk;
    if (st == SEC_I_CONTINUE_NEEDED) return Status::kProtocolError;
    if (st == SEC_E_UNSUPPORTED_FUNCTION) return Status::kUnsupported;
    return Status::kProtocolError;
}

}  // namespace

Status MapShutdownStatusForTest(int32_t s) {
    return MapShutdownStatus(static_cast<SECURITY_STATUS>(s));
}

bool DnsNameMatchesForTest(const char* pattern, const char* host) {
    if (pattern == nullptr || host == nullptr) return false;
    return DnsNameMatches(pattern, host);
}

bool CertificateHostMatchesForTest(const uint8_t* der, size_t der_size,
                                   const char* host) {
    if (der == nullptr || der_size == 0 || host == nullptr) return false;
    PCCERT_CONTEXT cert = CertCreateCertificateContext(
        X509_ASN_ENCODING, der, static_cast<DWORD>(der_size));
    if (cert == nullptr) return false;
    const HostMatchResult match = CertificateMatchesHost(cert, host);
    CertFreeCertificateContext(cert);
    return match.matched;
}

// Renamed away from the old public factory name (S21): the facade owns the
// public name so that non-Windows builds still define it.
// See src/net/tls_factory.cpp.
std::unique_ptr<TlsTransport> CreateSchannelTransport(const Config& config,
                                                      std::string& why) {
    why.clear();
    auto transport = std::make_unique<SchannelTransport>(config);
    if (!transport->Start(why)) return nullptr;
    return transport;
}

}  // namespace rtsc::tls
