// TLS transport interface for RTSC.
//
// Design reference: docs/spec/tls-backend.design-a.md section 3.2.
//
// This header is deliberately free of any platform or TLS-library dependency:
// the protocol layer must compile unchanged on Windows / Linux / Android /
// macOS. Everything backend-specific (SSPI types, OpenSSL types, error codes)
// stays inside the corresponding .cpp.
//
// Two invariants that callers must be able to rely on without knowing which
// backend is in use:
//
//   1. Terminal errors are idempotent. Once a terminal status is returned, every
//      later call returns the same error and touches no context. This is
//      required because the two SChannel TLS versions disagree on what happens
//      after a tampered record: TLS 1.3 recovers on its own, TLS 1.2 stays
//      poisoned (measured, see design-a section 3.2.1). Callers must not have to
//      branch on the TLS version.
//
//   2. On any failure other than kClosed, `plaintext` is guaranteed empty. A
//      failed decrypt can still leave ciphertext in SECBUFFER_DATA, and handing
//      that to the caller as plaintext would corrupt the upper layer.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace rtsc::tls {

enum class Status : uint8_t {
    kOk = 0,          // success; may still carry output, caller must inspect `out`
    kNeedMoreInput,   // need more peer bytes; current input fully absorbed, do not replay

    // ---- terminal: once returned, the backend latches and every later call
    //      returns the same error without touching the context.
    kPeerAlert,       // Reserved for backends that can report a peer fatal alert.
                      // NO backend produces this today: cannot expose level.
    kDecryptFailed,   // record authentication failed (GCM tag mismatch / tampering)
    kCertRejected,    // certificate policy rejected the peer
    kProtocolError,   // peer violated the protocol, or version outside [min,max]
    kUnsupported,     // backend cannot serve this configuration at all
    kInternal,        // backend-internal failure; the context is no longer trustworthy

    // ---- normal termination (not an error, but idempotent like one) ----
    kClosed,          // peer close_notify, or local shutdown already performed
};

// Number of terminal (error) statuses. Used by tests to keep the enumeration,
// Error::terminal() and the backend latch in agreement.
inline constexpr int kTerminalStatusCount = 6;

struct Error {
    Status status = Status::kOk;
    int32_t native_code = 0;  // SSPI SECURITY_STATUS / OpenSSL SSL_ERROR_* / errno
    std::string message;      // human readable only; never drives control flow

    bool ok() const noexcept { return status == Status::kOk; }

    // True when the error is unrecoverable and the caller must drop the
    // connection. kInternal is included on purpose: after an internal failure
    // the context cannot be trusted, so continuing is a gamble.
    bool terminal() const noexcept {
        return status == Status::kPeerAlert || status == Status::kDecryptFailed ||
               status == Status::kCertRejected || status == Status::kProtocolError ||
               status == Status::kInternal || status == Status::kUnsupported;
    }
};

// Record overhead. Upper bound and actual value are kept apart on purpose:
// TLS 1.3 reserves 44 bytes of trailer but only writes 17, so asserting on the
// upper bound would fail against a real connection (measured delta = 27).
struct RecordSizes {
    uint32_t header = 0;           // bytes before plaintext (TLS1.2 GCM=13; TLS1.3=5)
    uint32_t max_plaintext = 0;    // max bytes per EncryptMessage (measured 16384)
    uint32_t overhead_upper = 0;   // reserved trailer (TLS1.2=16; TLS1.3=44)
    uint32_t overhead_actual = 0;  // trailer actually written (TLS1.2=16; TLS1.3=17)
    uint32_t block_size = 0;       // measured 16, not 1

    // Allocation upper bound. Use only to preallocate. Never use it to advance a
    // write cursor or to assert the real record length; the real length is
    // whatever the backend put in the output vector.
    uint32_t alloc_upper_bound() const noexcept {
        return header + max_plaintext + overhead_upper;
    }
};

enum class CertPolicy : uint8_t {
    kInsecure,  // no validation at all (isolated environments only)
    // no pin: chain only (no hostname). With a pin: the pin IS the identity
    // (self-signed accepted), chain not required. Default.
    kTofu,
    // full chain + hostname validation, failure reason must be reportable
    kStrict,
};

// TLS endpoint role. The same TlsTransport interface serves both ends of the
// RDP connection: the client stack connects out (kClient), the in-tree RDP
// server accepts (kServer). The role is a config value, not a separate class,
// because every method after the handshake (Send / Receive / negotiated /
// record_sizes / Shutdown) is identical for both ends.
enum class Role : uint8_t {
    kClient,
    kServer,
};

struct Config {
    std::string peer_host;  // target address, used for SNI and logging; may be empty
    std::string sni;        // explicit SNI; empty = use peer_host; both empty = no SNI
    bool send_sni = true;

    // Endpoint role. Defaults to kClient so every existing caller (and the
    // Standard RDP Security path, which does not use TLS at all) is unchanged.
    Role role = Role::kClient;

    CertPolicy cert_policy = CertPolicy::kTofu;
    std::array<uint8_t, 32> pinned_spki_sha256{};
    bool pin_is_set = false;

    // Version bounds express intent only. The enforcement point is a self-check
    // inside Handshake before it reports success: SChannel's legacy
    // grbitEnabledProtocols cannot express a lower bound and silently downgrades.
    bool allow_tls10 = false;
    bool allow_tls13 = true;
    uint16_t min_version = 0x0302;  // TLS1.2
    uint16_t max_version = 0x0304;  // TLS1.3

    size_t max_chunk = 0;  // 0 = backend max_plaintext; otherwise the smaller wins

    // Server-role identity (used by backends that can present a certificate).
    // Both empty = the backend's ephemeral default (OpenSSL A2: a process-level
    // self-signed certificate, cached as raw DER bytes). When both are
    // non-empty they replace it; an encrypted private key is rejected at Start.
    std::string server_certificate_pem;  // PEM-encoded leaf certificate
    std::string server_private_key_pem;  // PEM-encoded private key (unencrypted)
};

struct NegotiatedInfo {
    uint16_t tls_version = 0;         // 0x0303 / 0x0304
    uint16_t cipher_suite = 0;        // from SECPKG_ATTR_CIPHER_INFO, not CALG
    char cipher_suite_name[64] = {};  // e.g. "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
};

class TlsTransport {
 public:
    virtual ~TlsTransport() = default;

    // ---- handshake: may take several round trips -----------------------------
    // The only correct way to compute `consumed` is
    //     consumed = in_size - sum(EXTRA.cbBuffer)
    // EXTRA.pvBuffer may be NULL (measured), so only cbBuffer may be read.
    // Self-check: consumed + sum(EXTRA) == in_size, otherwise kInternal.
    virtual Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,
                            std::vector<uint8_t>& out) = 0;

    // ---- send application data ----------------------------------------------
    // Plaintext larger than max_chunk must be split internally; it is not an
    // error. The real ciphertext length is out.size(); never alloc_upper_bound().
    virtual Error Send(const uint8_t* plaintext, size_t size, size_t& consumed,
                       std::vector<uint8_t>& out) = 0;

    // ---- receive application data -------------------------------------------
    // All post-handshake messages (TLS 1.3 tickets) are absorbed internally and
    // must never surface as a status code.
    //
    // `plaintext` is append-only: existing content is preserved and new bytes are
    // appended. One call may append plaintext from several records.
    // On any return other than kOk and kClosed, plaintext is guaranteed empty.
    // kClosed is the one exception: it keeps the plaintext, and the caller must
    // drain it first.
    //
    // `max_out` is a soft threshold, not a hard cap:
    //   * it means "at least this much is enough to return";
    //   * the actual append may exceed it by up to one record;
    //   * callers must not assume plaintext.size() <= max_out;
    //   * max_out == 0 means unlimited.
    // Drain obligation: when returning early because max_out was reached,
    // complete records may still be buffered. The caller must keep calling
    // Receive (size may be 0) until buffered_input() == 0, otherwise plaintext
    // is stranded inside the backend.
    virtual Error Receive(const uint8_t* ciphertext, size_t size,
                          std::vector<uint8_t>& plaintext, size_t max_out) = 0;

    // ---- local (server-role) identity ---------------------------------------
    // The server's own leaf certificate and SubjectPublicKey (BIT STRING
    // content). No production caller consumes either today: CredSSP pubKeyAuth
    // is a binding hash of the PEER's SubjectPublicKey plus the nonce, never a
    // local-key signature, and the channel-binding hash likewise comes from the
    // peer certificate. They are kept for future certificate-based identity
    // use (e.g. a configured server identity reported to management tooling).
    // Available from the moment a server-role transport is created; a
    // client-role transport returns kProtocolError ("handshake not complete")
    // on every call, mirroring the SChannel backend's NotHandshaken.
    virtual Error LocalCertificateDer(std::vector<uint8_t>& out) const = 0;
    // Local SubjectPublicKey (BIT STRING content), the same shape PeerSubjectPublicKey
    // reports for the peer (for an RSA-2048 key that is 270 bytes, starting with
    // 0x30 0x82). Never slice it from the SPKI at a fixed offset (the offset
    // differs between key sizes).
    virtual Error LocalSubjectPublicKey(std::vector<uint8_t>& out) const = 0;

    // ---- peer public key ----------------------------------------------------
    // Full SubjectPublicKeyInfo DER (measured: RSA-2048 = 294 B, RSA-1024 = 162 B).
    virtual Error PeerSubjectPublicKeyInfo(std::vector<uint8_t>& out) const = 0;
    // SubjectPublicKey only, taken straight from CERT_PUBLIC_KEY_INFO.PublicKey.
    // Never slice it out of the SPKI at a fixed offset: the offset differs
    // between key sizes (measured 24 for RSA-2048, 22 for RSA-1024).
    virtual Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const = 0;
    // Whole leaf certificate DER (used by the TOFU pin).
    virtual Error PeerCertificateDer(std::vector<uint8_t>& out) const = 0;

    // ---- negotiated parameters ----------------------------------------------
    virtual Error negotiated(NegotiatedInfo& out) const = 0;
    virtual RecordSizes record_sizes() const = 0;

    // ---- graceful close -----------------------------------------------------
    // Idempotent: repeated calls return kOk with an empty `out`.
    virtual Error Shutdown(std::vector<uint8_t>& out) = 0;

    // ---- state --------------------------------------------------------------
    virtual bool handshake_complete() const noexcept = 0;
    virtual bool closed() const noexcept = 0;
    virtual size_t buffered_input() const noexcept = 0;
    virtual const Error& last_error() const noexcept = 0;
    virtual const char* backend_name() const noexcept = 0;
};

struct BackendInfo {
    const char* name;  // "schannel" / "openssl" / "scripted" (tests)
    bool available;
    const char* reason;  // why it is unavailable
};

// Create by name; an empty `backend` means the platform default.
// `why` receives a human-readable reason when the result is null.
std::unique_ptr<TlsTransport> CreateTlsTransport(std::string_view backend,
                                                const Config& config, std::string& why);

std::vector<BackendInfo> EnumerateTlsBackends();

// Test hook: maps a native SChannel status to a transport Status for the
// shutdown path. Exposed for rule-level testing only.
Status MapShutdownStatusForTest(int32_t native_status);

// Test hook: certificate DNS-name matching used by kStrict hostname
// verification (case-insensitive, single-label wildcard). Exposed for
// rule-level testing only.
bool DnsNameMatchesForTest(const char* pattern, const char* host);

// Test hook: runs the kStrict hostname extraction (subjectAltName dNSName,
// falling back to the subject CN) against a DER-encoded certificate.
// Exposed for rule-level testing only.
bool CertificateHostMatchesForTest(const uint8_t* der, size_t der_size,
                                   const char* host);

inline std::unique_ptr<TlsTransport> CreatePlatformTlsTransport(const Config& c,
                                                               std::string& w) {
    return CreateTlsTransport(std::string_view{}, c, w);
}

}  // namespace rtsc::tls
