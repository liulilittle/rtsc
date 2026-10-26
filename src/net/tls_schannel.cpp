// SChannel backend for rtsc::tls::TlsTransport.
//
// Design reference: docs/spec/tls-backend.design-a.md
//   §3.4.1  the record framing / buffering pseudocode implemented below
//   §3.4.3  the twelve boundaries covered by tests/test_tls.cpp
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
#include <schannel.h>
#include <sspi.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstring>
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
        DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                    ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                    ISC_REQ_STREAM;
        switch (config_.cert_policy) {
            case CertPolicy::kInsecure:
                req |= ISC_REQ_MANUAL_CRED_VALIDATION;
                break;
            case CertPolicy::kStrict:
                // DEFERRED lets the chain result be queried afterwards; MANUAL
                // would make kStrict indistinguishable from kInsecure.
                req |= ISC_REQ_MANUAL_CRED_VALIDATION;
                break;
            case CertPolicy::kTofu:
                req |= ISC_REQ_MANUAL_CRED_VALIDATION;
                break;
        }

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
            case SEC_E_OK:
                if (!FinishHandshake(why_)) {
                    last_error_ = MakeError(Status::kInternal, 0, why_);
                    terminal_ = true;
                    return last_error_;
                }
                return MakeError(Status::kOk, 0, "");
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
            case SEC_E_OK:
                if (!FinishHandshake(why_)) {
                    last_error_ = MakeError(Status::kInternal, 0, why_);
                    terminal_ = true;
                    return last_error_;
                }
                return MakeError(Status::kOk, 0, "");
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
            ++progressed;

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
                    std::vector<uint8_t> discarded;
                    FeedExtraOnce(extra_len, record, discarded);
                    continue;
                }
                return Fail(Status::kProtocolError, st);
            }
            if (st == SEC_I_NO_RENEGOTIATION) {
                if (NegotiatedVersion() == kTls13) {
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
        out.clear();
        PCCERT_CONTEXT cert = PeerCert();
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
        SCHANNEL_CRED legacy{};
        legacy.dwVersion = SCHANNEL_CRED_VERSION;
        legacy.grbitEnabledProtocols = ProtocolMask();

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
    bool FinishHandshake(std::string& why) {
        SecPkgContext_StreamSizes ss{};
        if (QueryContextAttributesW(&ctx_, SECPKG_ATTR_STREAM_SIZES, &ss) != SEC_E_OK) {
            why = "SECPKG_ATTR_STREAM_SIZES failed";
            return false;
        }
        sizes_.header = ss.cbHeader;
        sizes_.max_plaintext = ss.cbMaximumMessage;
        sizes_.overhead_upper = ss.cbTrailer;
        sizes_.block_size = ss.cbBlockSize;
        // cbTrailer is an allocation bound, not the real trailer length.
        // See ExpectedActualOverhead(): corrected on the first real record.
        sizes_.overhead_actual = ExpectedActualOverhead();

        if (!QueryNegotiated(why)) return false;
        if (!EnforceVersionWindow(why)) return false;
        handshake_complete_ = true;
        return true;
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
            DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                        ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                        ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION;
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
    PCCERT_CONTEXT PeerCert() const {
        if (!handshake_complete_) return nullptr;
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
