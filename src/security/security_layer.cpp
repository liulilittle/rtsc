// Security layer implementation.
//
// Design: docs/spec/security-integration.audit-a.md section 4.1 (方案 B).
//
// The layer owns one input buffer (`pending_cipher_`). Step() appends the bytes
// received from the peer and then pumps the state machine. Each phase function
// consumes from that buffer and returns the next action (read / write / done).
//
// Framing rules change per phase, and that is exactly why the phase and the
// buffer must live in the same object (audit-a section 3.1):
//   * TLS handshake  -> record layer, handled inside TlsTransport::Handshake
//   * CredSSP        -> DER self-delimited SEQUENCE
//   * EUAR           -> exactly 4 bytes, no TPKT / X.224 / MCS wrapper
//   * MCS data plane -> TPKT length field

#include "rtsc/security/security_layer.h"

#include "rtsc/proto/share.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <utility>

namespace rtsc::security {

namespace {

constexpr uint32_t kAuthzSuccess = 0x00000000;
constexpr uint32_t kAuthzAccessDenied = 0x00000005;

// Reads the length of the DER SEQUENCE that starts at `start`. Returns the
// total encoded length (header + body), or 0 when the message is incomplete or
// the tag is not SEQUENCE. DER length forms: short form (<0x80) and long form
// (0x81..0x84, up to 4 length bytes).
size_t DerMessageLength(const std::vector<uint8_t>& buf, size_t start) {
    if (start >= buf.size()) return 0;
    if (buf[start] != 0x30) return 0;
    if (start + 1 >= buf.size()) return 0;

    size_t pos = start + 1;
    size_t len = 0;
    if (buf[pos] < 0x80) {
        len = buf[pos];
        pos += 1;
    } else {
        const size_t num_bytes = buf[pos] & 0x7F;
        if (num_bytes == 0 || num_bytes > 4) return 0;
        if (pos + num_bytes >= buf.size()) return 0;
        pos += 1;
        for (size_t i = 0; i < num_bytes; ++i) {
            len = (len << 8) | buf[pos + i];
        }
        pos += num_bytes;
    }

    const size_t total = (pos - start) + len;
    if (start + total > buf.size()) return 0;  // incomplete
    return total;
}

// Reads a complete TPKT frame length from `buf` at `start`, or 0 if incomplete.
size_t TpktFrameLength(const std::vector<uint8_t>& buf, size_t start) {
    if (start + 4 > buf.size()) return 0;
    if (buf[start] != 0x03 || buf[start + 1] != 0x00) return 0;
    const size_t len = (static_cast<size_t>(buf[start + 2]) << 8) |
                       static_cast<size_t>(buf[start + 3]);
    if (len < 4) return 0;
    if (start + len > buf.size()) return 0;
    return len;
}

}  // namespace

SecurityLayer::SecurityLayer() = default;

SecurityLayer::~SecurityLayer() = default;

std::unique_ptr<SecurityLayer> SecurityLayer::Create(const Config& config,
                                                     std::string& why) {
    auto layer = std::unique_ptr<SecurityLayer>(new SecurityLayer());
    layer->config_ = config;

    std::string tls_why;
    layer->tls_ = tls::CreatePlatformTlsTransport(config.tls_config, tls_why);
    // A missing platform backend is not fatal here: a caller (or a test) may
    // inject a transport via SetTlsTransportForTest. The first Step() fails if
    // the transport is still null, so a real connection still cannot proceed.
    why = layer->tls_ ? std::string() : tls_why;

    credssp::Credentials ccreds;
    ccreds.domain = config.credentials.domain;
    ccreds.user = config.credentials.user;
    ccreds.password = config.credentials.password;
    layer->credssp_ =
        std::make_unique<credssp::CredsspClient>(ccreds, config.credssp_version);

    layer->phase_ = Phase::kTlsHandshake;
    return layer;
}

StepResult SecurityLayer::Step(const uint8_t* in, size_t in_size) {
    if (!tls_) return Fail("no TLS transport available");
    if (in != nullptr && in_size > 0) {
        pending_cipher_.insert(pending_cipher_.end(), in, in + in_size);
    }

    // Pump across phase boundaries: when a phase completes without producing
    // output (e.g. the TLS handshake finished), the next phase may be able to
    // make progress without any new input. Looping here means the caller never
    // has to guess how many times to pump.
    for (;;) {
        switch (phase_) {
            case Phase::kTlsHandshake: {
                StepResult r = DriveTls();
                if (r.want != Want::kRead) return r;
                if (phase_ != Phase::kCredsspStart) return r;  // still handshaking
                break;  // handshake done: emit CredSSP step 1
            }
            case Phase::kCredsspStart:
                return DriveCredsspStart();
            case Phase::kCredsspAwait: {
                StepResult r = DriveCredssp();
                if (r.want != Want::kRead) return r;
                if (phase_ != Phase::kEuar) return r;
                break;  // CredSSP done: try to read the EUAR
            }
            case Phase::kEuar:
                return DriveEuar();
            case Phase::kDone: {
                StepResult r;
                r.want = Want::kDone;
                return r;
            }
            case Phase::kFailed: {
                StepResult r;
                r.want = Want::kFailed;
                r.error = error_;
                return r;
            }
        }
    }
}

StepResult SecurityLayer::Fail(const std::string& reason) {
    phase_ = Phase::kFailed;
    error_ = reason;
    StepResult r;
    r.want = Want::kFailed;
    r.error = error_;
    return r;
}

StepResult SecurityLayer::DriveTls() {
    size_t consumed = 0;
    std::vector<uint8_t> tls_out;
    const tls::Error err = tls_->Handshake(
        pending_cipher_.data(), pending_cipher_.size(), consumed, tls_out);

    if (!err.ok() && err.status != tls::Status::kNeedMoreInput) {
        return Fail("TLS handshake failed: " + err.message);
    }

    // Handshake consumes exactly `consumed` bytes; the rest are application
    // data that arrived in the same segment and must stay buffered.
    if (consumed > pending_cipher_.size()) {
        return Fail("TLS handshake consumed more than it was given");
    }
    pending_cipher_.erase(pending_cipher_.begin(),
                          pending_cipher_.begin() +
                              static_cast<ptrdiff_t>(consumed));

    StepResult result;
    if (!tls_out.empty()) {
        result.want = Want::kWrite;
        result.to_wire = std::move(tls_out);
    } else {
        result.want = Want::kRead;
    }

    if (tls_->handshake_complete()) {
        phase_ = Phase::kCredsspStart;
    }
    return result;
}

StepResult SecurityLayer::DriveCredsspStart() {
    // The server's SubjectPublicKey is needed for pubKeyAuth. Prefer the value
    // supplied by the caller; otherwise take it from the completed TLS session.
    std::vector<uint8_t> spk = config_.server_public_key;
    if (spk.empty()) {
        const tls::Error e = tls_->PeerSubjectPublicKey(spk);
        if (!e.ok()) {
            return Fail("cannot read the server SubjectPublicKey: " + e.message);
        }
        config_.server_public_key = spk;
    }
    credssp_->SetServerPublicKey(spk);

    // The NTLM channel binding (MsvAvChannelBindings) is derived from the
    // server's leaf certificate. Servers with Extended Protection for
    // Authentication reject a client that omits it. MsvAvTargetName carries the
    // RDP SPN "TERMSRV/<host>" ([MS-NLMP] 2.2.2.1 / 3.1.1.2).
    std::vector<uint8_t> cert;
    if (tls_->PeerCertificateDer(cert).ok() && !cert.empty()) {
        credssp_->SetServerCertificateDer(std::move(cert));
    }
    if (!config_.tls_config.peer_host.empty()) {
        credssp_->SetClientTargetName("TERMSRV/" + config_.tls_config.peer_host);
    }

    credssp::Bytes step1;
    const credssp::Error e = credssp_->Start(step1);
    if (!e.ok()) {
        return Fail("CredSSP Start failed: " + e.message);
    }

    phase_ = Phase::kCredsspAwait;
    return EncryptAndWrite(step1);
}

StepResult SecurityLayer::DriveCredssp() {
    std::vector<uint8_t> plaintext;
    if (!pending_cipher_.empty()) {
        // TlsTransport buffers incomplete records internally, so the whole
        // buffer can be handed over and then cleared.
        const tls::Error err = tls_->Receive(
            pending_cipher_.data(), pending_cipher_.size(), plaintext, 0);
        pending_cipher_.clear();
        if (!err.ok() && err.status != tls::Status::kClosed &&
            err.status != tls::Status::kNeedMoreInput) {
            return Fail("TLS receive failed: " + err.message);
        }
    }
    // Drain any records the backend still holds. This runs even when
    // pending_cipher_ is empty: a peer that coalesced its final handshake
    // flight with an application record puts that record into the backend
    // inside Handshake, and the stream backends then report the whole buffer as
    // consumed (consumed == in_size), so the record never reaches
    // pending_cipher_. Skipping the drain strands it and both ends wait
    // forever. (tls.h: the caller must keep receiving until buffered_input()
    // == 0.) Guarded by security_layer_credssp_drain_lifts_coalesced_record;
    // with the loop disabled that case stalls at kRead and is the only failure.
    while (tls_->buffered_input() > 0) {
        const tls::Error d = tls_->Receive(nullptr, 0, plaintext, 0);
        if (!d.ok() && d.status != tls::Status::kClosed &&
            d.status != tls::Status::kNeedMoreInput) {
            return Fail("TLS drain failed: " + d.message);
        }
        if (d.status == tls::Status::kNeedMoreInput) break;
    }
    plain_buf_.insert(plain_buf_.end(), plaintext.begin(), plaintext.end());

    if (plain_buf_.empty()) {
        StepResult r;
        r.want = Want::kRead;
        return r;
    }

    const size_t msg_len = DerMessageLength(plain_buf_, 0);
    if (msg_len == 0) {
        StepResult r;
        r.want = Want::kRead;  // incomplete DER message
        return r;
    }

    std::vector<uint8_t> msg(plain_buf_.begin(), plain_buf_.begin() +
                                                      static_cast<ptrdiff_t>(msg_len));
    plain_buf_.erase(plain_buf_.begin(),
                     plain_buf_.begin() + static_cast<ptrdiff_t>(msg_len));

    credssp::Bytes out_msg;
    const credssp::Error e =
        credssp_->OnServerResponse(msg.data(), msg.size(), out_msg);
    if (!e.ok()) {
        return Fail("CredSSP error: " + e.message);
    }

    if (credssp_->complete()) {
        // BuildStep5 produces the final CredSSP message (step 5, authInfo) and
        // reports completion, but that message is not on the wire yet. The
        // server emits the EUAR only after it has received step 5, so waiting
        // for the EUAR before sending deadlocks and the peer closes the
        // connection. Send step 5 first, then wait for the EUAR.
        if (!config_.expect_euar) {
            // PROTOCOL_HYBRID (0x2): no EUAR follows. Complete as soon as step
            // 5 is on the wire; any leftover plaintext is the head of the MCS
            // data plane and is consumed by ReceivePdu.
            phase_ = Phase::kDone;
            if (!out_msg.empty()) {
                return EncryptAndWrite(out_msg);
            }
            StepResult r;
            r.want = Want::kDone;
            return r;
        }
        euar_buf_.insert(euar_buf_.end(), plain_buf_.begin(), plain_buf_.end());
        plain_buf_.clear();
        phase_ = Phase::kEuar;
        if (!out_msg.empty()) {
            return EncryptAndWrite(out_msg);
        }
        return DriveEuar();
    }

    return EncryptAndWrite(out_msg);
}

StepResult SecurityLayer::DriveEuar() {
    // The EUAR is a bare 4-byte UINT32; it may already be buffered (when it
    // shared a TLS record with the last CredSSP message) or still on the wire.
    if (euar_buf_.size() < 4 && !pending_cipher_.empty()) {
        std::vector<uint8_t> plaintext;
        const tls::Error err = tls_->Receive(
            pending_cipher_.data(), pending_cipher_.size(), plaintext, 0);
        pending_cipher_.clear();
        if (!err.ok() && err.status != tls::Status::kClosed &&
            err.status != tls::Status::kNeedMoreInput) {
            return Fail("TLS receive failed: " + err.message);
        }
        // Guarded by security_layer_euar_drain_lifts_coalesced_record; with the
        // loop disabled the layer stays at kRead instead of reaching kDone.
        while (tls_->buffered_input() > 0) {
            const tls::Error d = tls_->Receive(nullptr, 0, plaintext, 0);
            if (!d.ok() && d.status != tls::Status::kClosed &&
                d.status != tls::Status::kNeedMoreInput) {
                return Fail("TLS drain failed: " + d.message);
            }
            if (d.status == tls::Status::kNeedMoreInput) break;
        }
        euar_buf_.insert(euar_buf_.end(), plaintext.begin(), plaintext.end());
    }

    if (euar_buf_.size() < 4) {
        StepResult r;
        r.want = Want::kRead;
        return r;
    }

    const uint32_t authz = static_cast<uint32_t>(euar_buf_[0]) |
                           (static_cast<uint32_t>(euar_buf_[1]) << 8) |
                           (static_cast<uint32_t>(euar_buf_[2]) << 16) |
                           (static_cast<uint32_t>(euar_buf_[3]) << 24);
    euar_buf_.erase(euar_buf_.begin(), euar_buf_.begin() + 4);

    // Bytes after the EUAR (if any) are the head of the MCS data plane; keep
    // them so ReceivePdu can peel frames out of them.
    if (!euar_buf_.empty()) {
        plain_buf_.insert(plain_buf_.begin(), euar_buf_.begin(), euar_buf_.end());
        euar_buf_.clear();
    }

    if (authz == kAuthzAccessDenied) {
        return Fail("EUAR: authorization denied (AUTHZ_ACCESS_DENIED)");
    }
    if (authz != kAuthzSuccess) {
        return Fail("EUAR: unknown authorization result");
    }

    phase_ = Phase::kDone;
    StepResult r;
    r.want = Want::kDone;
    return r;
}

StepResult SecurityLayer::EncryptAndWrite(const credssp::Bytes& plaintext) {
    if (plaintext.empty()) {
        StepResult r;
        r.want = Want::kRead;
        return r;
    }
    size_t consumed = 0;
    std::vector<uint8_t> tls_out;
    const tls::Error err =
        tls_->Send(plaintext.data(), plaintext.size(), consumed, tls_out);
    if (!err.ok()) {
        return Fail("TLS Send failed: " + err.message);
    }
    StepResult r;
    if (!tls_out.empty()) {
        r.want = Want::kWrite;
        r.to_wire = std::move(tls_out);
    } else {
        r.want = Want::kRead;
    }
    return r;
}

std::vector<uint8_t> SecurityLayer::SendPdu(const std::vector<uint8_t>& pdu) {
    if (phase_ != Phase::kDone) return {};
    size_t consumed = 0;
    std::vector<uint8_t> out;
    const tls::Error err = tls_->Send(pdu.data(), pdu.size(), consumed, out);
    if (!err.ok()) return {};
    return out;
}

std::vector<std::vector<uint8_t>> SecurityLayer::ReceivePdu(const uint8_t* in,
                                                            size_t in_size) {
    std::vector<std::vector<uint8_t>> frames;
    if (phase_ != Phase::kDone) return frames;

    std::vector<uint8_t> plaintext;
    if (in != nullptr && in_size > 0) {
        const tls::Error err = tls_->Receive(in, in_size, plaintext, 0);
        if (!err.ok() && err.status != tls::Status::kClosed &&
            err.status != tls::Status::kNeedMoreInput) {
            return frames;
        }
    }
    // Guarded by security_layer_receivepdu_drain_lifts_coalesced_record; with
    // the loop disabled ReceivePdu returns no frames for a coalesced record.
    while (tls_->buffered_input() > 0) {
        const tls::Error d = tls_->Receive(nullptr, 0, plaintext, 0);
        if (!d.ok() && d.status != tls::Status::kClosed &&
            d.status != tls::Status::kNeedMoreInput) {
            break;
        }
        if (d.status == tls::Status::kNeedMoreInput) break;
    }

    plain_buf_.insert(plain_buf_.end(), plaintext.begin(), plaintext.end());

    // Peel complete PDUs out of the plaintext buffer. Two framings share the
    // data plane: slow-path PDUs start with a TPKT header (0x03 0x00), while
    // Fast-Path PDUs ([MS-RDPBCGR] 2.2.9.1.2) start with a header byte whose low
    // two bits are zero and carry their own length. A server that has negotiated
    // Fast-Path output sends the desktop as Fast-Path updates, so both must be
    // delivered or the graphics stream stalls in this buffer.
    size_t start = 0;
    for (;;) {
        size_t len = TpktFrameLength(plain_buf_, start);
        if (len == 0 && start < plain_buf_.size()) {
            proto::FastPathPdu fp;
            if (proto::FastPathPdu::parse(plain_buf_.data() + start,
                                          plain_buf_.size() - start, false,
                                          fp) == proto::Status::Ok) {
                len = fp.length.value;
            }
        }
        if (len == 0) break;
        frames.emplace_back(plain_buf_.begin() + static_cast<ptrdiff_t>(start),
                            plain_buf_.begin() +
                                static_cast<ptrdiff_t>(start + len));
        start += len;
    }
    if (start > 0) {
        plain_buf_.erase(plain_buf_.begin(),
                         plain_buf_.begin() + static_cast<ptrdiff_t>(start));
    }
    return frames;
}

}  // namespace rtsc::security
