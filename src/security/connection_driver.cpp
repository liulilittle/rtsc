// Connection driver implementation.

#include "rtsc/security/connection_driver.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <utility>

namespace rtsc::security {

namespace {

using proto::ConnectPhase;

void Append(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
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

ConnectionDriver::ConnectionDriver(proto::ConnectMachine::Config machine_config,
                                   proto::ConnectMachine::Credentials credentials,
                                   Config security_config)
    : machine_(machine_config, credentials),
      machine_config_(machine_config),
      security_config_(std::move(security_config)),
      credentials_(std::move(credentials)) {}

const std::string& ConnectionDriver::phase_name() const {
    if (!client_info_sent_) {
        static const std::string kConnect = "connect";
        return kConnect;
    }
    if (licensing_ && !licensing_->done()) {
        static const std::string kLicensing = "licensing";
        return kLicensing;
    }
    static const std::string kSession = "session-setup";
    return kSession;
}

DriverStep ConnectionDriver::Fail(const std::string& reason) {
    DriverStep s;
    s.failed = true;
    s.error = reason;
    return s;
}

DriverStep ConnectionDriver::Start() {
    DriverStep out;
    const auto step = machine_.Start();
    out.to_send = step.output;
    return out;
}

DriverStep ConnectionDriver::OnData(const uint8_t* data, size_t size) {
    // ---- plaintext negotiation (X.224 Connection Confirm) -------------------
    if (machine_.state().phase == ConnectPhase::kAwaitNegotiation) {
        if (data != nullptr && size > 0) {
            plain_buf_.insert(plain_buf_.end(), data, data + size);
        }

        DriverStep out;
        size_t start = 0;
        for (;;) {
            const size_t len = TpktFrameLength(plain_buf_, start);
            if (len == 0) break;
            const auto step = machine_.OnData(
                plain_buf_.data() + start, len);
            Append(out.to_send, step.output);
            start += len;
        }
        if (start > 0) {
            plain_buf_.erase(plain_buf_.begin(),
                             plain_buf_.begin() + static_cast<ptrdiff_t>(start));
        }

        if (machine_.failed()) return Fail(machine_.state().error);

        if (machine_.state().phase == ConnectPhase::kAwaitExternalSecurity) {
            std::string why;
            security_ = SecurityLayer::Create(security_config_, why);
            if (!security_) return Fail("cannot create the security layer: " + why);
            if (tls_for_test_) {
                security_->SetTlsTransportForTest(std::move(tls_for_test_));
            }
            // Kick the handshake off (TLS ClientHello).
            DriverStep kick = DriveSecurity(nullptr, 0);
            Append(kick.to_send, out.to_send);
            return kick;
        }
        return out;
    }

    // ---- external security handshake ---------------------------------------
    if (machine_.state().phase == ConnectPhase::kAwaitExternalSecurity) {
        return DriveSecurity(data, size);
    }

    // ---- post-handshake data plane (everything is encrypted) ----------------
    DriverStep out;
    if (!security_) return Fail("post-handshake data with no security layer");

    const auto frames = security_->ReceivePdu(data, size);
    for (const auto& f : frames) {
        if (!client_info_sent_) {
            const auto step = machine_.OnData(f.data(), f.size());
            if (!step.output.empty()) {
                Append(out.to_send, security_->SendPdu(step.output));
            }
            if (machine_.failed()) return Fail(machine_.state().error);
            if (machine_.done()) {
                // The Client Info PDU has been sent; the licensing phase begins.
                client_info_sent_ = true;
                out.done = true;
                // Latch the I/O channel id parsed from the Server Network Data
                // block; post-active routing compares each inbound PDU against
                // it to tell graphics data from static virtual channel data.
                io_channel_id_ = machine_.state().io_channel_id;

                proto::LicensingMachine::Config lc;
                lc.user_channel_id = machine_.state().user_channel_id;
                lc.io_channel_id = machine_.state().io_channel_id;
                lc.user_name = credentials_.user_name;
                lc.machine_name = machine_config_.client_name;
                licensing_ = std::make_unique<proto::LicensingMachine>(lc);
                licensing_->Start();

                proto::SessionSetupMachine::Config sc;
                sc.user_channel_id = machine_.state().user_channel_id;
                sc.io_channel_id = machine_.state().io_channel_id;
                sc.desktop_width =
                    static_cast<uint16_t>(machine_config_.desktop_width);
                sc.desktop_height =
                    static_cast<uint16_t>(machine_config_.desktop_height);
                session_ = std::make_unique<proto::SessionSetupMachine>(sc);
                session_->Start();
            }
            continue;
        }
        RoutePostConnect(f, out);
        if (out.failed) return out;
    }
    return out;
}

void ConnectionDriver::RoutePostConnect(const std::vector<uint8_t>& pdu,
                                        DriverStep& out) {
    if (!licensing_) return;

    // A registered static virtual channel is routed by MCS channel id as soon
    // as the session is up, even before it is active: the rdpsnd
    // initialization (Server Audio Formats and Version PDU) can arrive during
    // the capability exchange, and the handler must see it then. Unregistered
    // channels keep the historical behaviour: they are only dropped once the
    // session is active, so licensing / session-setup PDUs are never mistaken
    // for virtual-channel data.
    proto::McsSendData sd;
    const bool parsed = proto::McsSendData::parse(pdu.data(), pdu.size(), sd) ==
                        proto::Status::Ok;
    if (parsed && sd.channel_id != io_channel_id_) {
        auto it = channel_handlers_.find(sd.channel_id);
        if (it != channel_handlers_.end() && it->second) {
            // [MS-RDPBCGR] 2.2.6.1: a static virtual channel PDU carries its
            // protocol in sd.user_data, which begins with the 8-byte
            // channelPduHeader (length(4 LE) + flags(4 LE)). The handler
            // decodes that header itself, so pass only user_data; passing the
            // full pdu would hand it the MCS Send Data header.
            it->second(sd.user_data.data(), sd.user_data.size());
            return;
        }
        if (session_ != nullptr && session_->active()) {
            ++unrouted_channel_count_;  // unknown channel: drop, not graphics
            return;
        }
    }

    // Once the session is active the I/O channel carries graphics / pointer /
    // orders data; the static virtual channels were routed above.
    if (session_ != nullptr && session_->active()) {
        if (session_pdu_handler_) session_pdu_handler_(pdu);
        return;
    }

    // Licensing PDUs carry a SEC_LICENSE_PKT security header; the capability
    // exchange PDUs do not. Detect the header to route correctly.
    bool is_licensing = false;
    if (proto::McsSendData::parse(pdu.data(), pdu.size(), sd) == proto::Status::Ok &&
        sd.user_data.size() >= 2) {
        const uint16_t flags = static_cast<uint16_t>(sd.user_data[0]) |
                               (static_cast<uint16_t>(sd.user_data[1]) << 8);
        is_licensing = (flags & static_cast<uint16_t>(proto::kSecLicensePkt)) != 0;
    }

    if (!licensing_->done()) {
        if (!is_licensing) return;  // not ours yet
        const auto ls = licensing_->OnPdu(pdu.data(), pdu.size());
        for (const auto& p : ls.to_send) {
            Append(out.to_send, security_->SendPdu(p));
        }
        if (ls.failed) {
            out.failed = true;
            out.error = "licensing failed: " + ls.error;
        }
        return;
    }

    if (!session_) return;
    const auto ss = session_->OnPdu(pdu.data(), pdu.size());
    for (const auto& p : ss.to_send) {
        Append(out.to_send, security_->SendPdu(p));
    }
    if (ss.failed) {
        out.failed = true;
        out.error = "session setup failed: " + ss.error;
    }
    if (ss.active) out.active = true;
}

DriverStep ConnectionDriver::DriveSecurity(const uint8_t* data, size_t size) {
    DriverStep out;
    const StepResult r = security_->Step(data, size);

    if (r.want == Want::kWrite) {
        // Return to the caller so it can put these bytes on the wire; it will
        // call OnData again once the peer's response has been read.
        out.to_send = r.to_wire;
        return out;
    }
    if (r.want == Want::kRead) {
        return out;  // empty: need more bytes from the peer
    }
    if (r.want == Want::kFailed) {
        return Fail("security handshake failed: " + r.error);
    }

    // r.want == Want::kDone: emit the MCS Connect Initial through the layer.
    const auto step = machine_.OnExternalSecurityComplete();
    if (machine_.failed()) return Fail(machine_.state().error);
    if (!step.output.empty()) {
        Append(out.to_send, security_->SendPdu(step.output));
    }
    return out;
}

}  // namespace rtsc::security
