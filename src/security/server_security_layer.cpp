// Server security layer implementation.
//
// Design: mirror of src/security/security_layer.cpp (client half), with the
// server-side TLS accept and CredsspServer replacing the client half.

#include "rtsc/security/server_security_layer.h"

#include <cstring>
#include <utility>

#include "rtsc/proto/share.h"

namespace rtsc::security {

namespace {

// Reads the length of the DER SEQUENCE that starts at `start`. Returns the
// total encoded length (header + body), or 0 when the message is incomplete or
// the tag is not SEQUENCE.
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
    const size_t len = (static_cast<size_t>(buf[start + 2]) << 8) | buf[start + 3];
    if (len < 4) return 0;
    if (start + len > buf.size()) return 0;
    return len;
}

}  // namespace

ServerSecurityLayer::ServerSecurityLayer() = default;

ServerSecurityLayer::~ServerSecurityLayer() = default;

std::unique_ptr<ServerSecurityLayer> ServerSecurityLayer::Create(
    const ServerConfig& config, std::string& why) {
    if (config.tls_config.role != tls::Role::kServer) {
        why = "server security layer requires tls::Role::kServer";
        return nullptr;
    }
    auto layer = std::unique_ptr<ServerSecurityLayer>(new ServerSecurityLayer());
    layer->config_ = config;

    std::string tls_why;
    layer->tls_ = tls::CreatePlatformTlsTransport(config.tls_config, tls_why);
    why = layer->tls_ ? std::string() : tls_why;

    layer->credssp_ = std::make_unique<credssp::CredsspServer>(
        config.credential_lookup, config.credssp_version);
    layer->phase_ = Phase::kTlsHandshake;
    return layer;
}

StepResult ServerSecurityLayer::Step(const uint8_t* in, size_t in_size) {
    if (!tls_) return Fail("no TLS transport available");
    if (in != nullptr && in_size > 0) {
        pending_cipher_.insert(pending_cipher_.end(), in, in + in_size);
    }

    for (;;) {
        switch (phase_) {
            case Phase::kTlsHandshake: {
                StepResult r = DriveTls();
                if (r.want != Want::kRead) return r;
                if (phase_ != Phase::kCredsspAwait) return r;  // still accepting
                break;  // TLS done: start / continue CredSSP
            }
            case Phase::kCredsspAwait:
                return DriveCredssp();
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

StepResult ServerSecurityLayer::Fail(const std::string& reason) {
    phase_ = Phase::kFailed;
    error_ = reason;
    StepResult r;
    r.want = Want::kFailed;
    r.error = error_;
    return r;
}

StepResult ServerSecurityLayer::DriveTls() {
    // The server is reactive: it cannot produce anything until the client's
    // ClientHello arrives, and between client flights it waits for the next
    // token. Returning kRead while the buffer is empty is therefore correct
    // and not a stall.
    if (pending_cipher_.empty()) {
        StepResult r;
        r.want = Want::kRead;
        return r;
    }

    size_t consumed = 0;
    std::vector<uint8_t> tls_out;
    const tls::Error err = tls_->Handshake(pending_cipher_.data(),
                                           pending_cipher_.size(), consumed, tls_out);
    if (!err.ok() && err.status != tls::Status::kNeedMoreInput) {
        return Fail("TLS accept failed: " + err.message);
    }
    if (consumed > pending_cipher_.size()) {
        return Fail("TLS accept consumed more than it was given");
    }
    pending_cipher_.erase(pending_cipher_.begin(),
                          pending_cipher_.begin() +
                              static_cast<std::ptrdiff_t>(consumed));

    StepResult result;
    if (!tls_out.empty()) {
        result.want = Want::kWrite;
        result.to_wire = std::move(tls_out);
    } else {
        result.want = Want::kRead;
    }

    if (tls_->handshake_complete()) {
        if (!config_.credssp_required) {
            // PROTOCOL_SSL: transport security only, no CredSSP / EUAR.
            phase_ = Phase::kDone;
            return result;
        }
        // CredSSP needs the server's SubjectPublicKey for pubKeyAuth. Prefer
        // the caller-supplied value; otherwise read it from the local cert.
        std::vector<uint8_t> spk = config_.server_public_key;
        if (spk.empty()) {
            const tls::Error e = tls_->LocalSubjectPublicKey(spk);
            if (!e.ok()) {
                return Fail("cannot read the server SubjectPublicKey: " + e.message);
            }
            config_.server_public_key = spk;
        }
        credssp_->SetServerPublicKey(spk);
        phase_ = Phase::kCredsspAwait;
    }
    return result;
}

StepResult ServerSecurityLayer::DriveCredssp() {
    std::vector<uint8_t> plaintext;
    if (!pending_cipher_.empty()) {
        const tls::Error err = tls_->Receive(pending_cipher_.data(),
                                             pending_cipher_.size(), plaintext, 0);
        pending_cipher_.clear();
        if (!err.ok() && err.status != tls::Status::kClosed &&
            err.status != tls::Status::kNeedMoreInput) {
            return Fail("TLS receive failed: " + err.message);
        }
        while (tls_->buffered_input() > 0) {
            const tls::Error d = tls_->Receive(nullptr, 0, plaintext, 0);
            if (!d.ok() && d.status != tls::Status::kClosed &&
                d.status != tls::Status::kNeedMoreInput) {
                return Fail("TLS drain failed: " + d.message);
            }
            if (d.status == tls::Status::kNeedMoreInput) break;
        }
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

    std::vector<uint8_t> msg(plain_buf_.begin(),
                             plain_buf_.begin() + static_cast<std::ptrdiff_t>(msg_len));
    plain_buf_.erase(plain_buf_.begin(),
                     plain_buf_.begin() + static_cast<std::ptrdiff_t>(msg_len));

    credssp::Bytes out_msg;
    const credssp::Error e =
        credssp_->OnClientMessage(msg.data(), msg.size(), out_msg);
    if (!e.ok()) {
        return Fail("CredSSP error: " + e.message);
    }

    if (credssp_->complete()) {
        phase_ = Phase::kDone;
        // [MS-RDPBCGR] 2.2.10.2: the 4-byte EUAR is only sent when the client
        // advertised PROTOCOL_HYBRID_EX and the server selected it. A
        // HYBRID-only session (0x2) resumes directly with the MCS Connect
        // Initial; sending unsolicited bytes makes mstsc reset with 0x1204.
        if (!config_.euar_required) {
            StepResult r;
            r.want = Want::kDone;
            return r;
        }
        const credssp::Bytes euar(4, 0x00);
        return EncryptAndWrite(euar);
    }

    return EncryptAndWrite(out_msg);
}

StepResult ServerSecurityLayer::EncryptAndWrite(const credssp::Bytes& plaintext) {
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

std::vector<uint8_t> ServerSecurityLayer::SendPdu(const std::vector<uint8_t>& pdu) {
    if (phase_ != Phase::kDone) return {};
    size_t consumed = 0;
    std::vector<uint8_t> out;
    const tls::Error err = tls_->Send(pdu.data(), pdu.size(), consumed, out);
    if (!err.ok()) return {};
    return out;
}

std::vector<std::vector<uint8_t>> ServerSecurityLayer::ReceivePdu(const uint8_t* in,
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
    while (tls_->buffered_input() > 0) {
        const tls::Error d = tls_->Receive(nullptr, 0, plaintext, 0);
        if (!d.ok() && d.status != tls::Status::kClosed &&
            d.status != tls::Status::kNeedMoreInput) {
            break;
        }
        if (d.status == tls::Status::kNeedMoreInput) break;
    }

    plain_buf_.insert(plain_buf_.end(), plaintext.begin(), plaintext.end());

    size_t start = 0;
    for (;;) {
        size_t len = TpktFrameLength(plain_buf_, start);
        if (len == 0 && start < plain_buf_.size()) {
            proto::FastPathPdu fp;
            if (proto::FastPathPdu::parse(plain_buf_.data() + start,
                                          plain_buf_.size() - start, false, fp) ==
                proto::Status::Ok) {
                len = fp.length.value;
            }
        }
        if (len == 0) break;
        frames.emplace_back(plain_buf_.begin() + static_cast<std::ptrdiff_t>(start),
                            plain_buf_.begin() +
                                static_cast<std::ptrdiff_t>(start + len));
        start += len;
    }
    if (start > 0) {
        plain_buf_.erase(plain_buf_.begin(),
                         plain_buf_.begin() + static_cast<std::ptrdiff_t>(start));
    }
    return frames;
}

}  // namespace rtsc::security
