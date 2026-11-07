// Connection driver implementation.

#include "rtsc/security/connection_driver.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <utility>

#include "rtsc/proto/rdp_neg.h"

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

// True when the full MCS Send Data PDU carries a share-control Deactivate All
// PDU ([MS-RDPBCGR] 2.2.3.1.1). A malformed PDU is not treated as one.
bool IsDeactivateAll(const std::vector<uint8_t>& pdu) {
    proto::McsSendData sd;
    if (proto::McsSendData::parse(pdu.data(), pdu.size(), sd) !=
        proto::Status::Ok) {
        return false;
    }
    proto::ShareControlHeader ctrl;
    if (proto::ShareControlHeader::parse(sd.user_data.data(), sd.user_data.size(),
                                         ctrl) != proto::Status::Ok) {
        return false;
    }
    return ctrl.type == proto::SharePduType::kDeactivateAll;
}

// Save Session Info is a share data PDU ([MS-RDPBCGR] 2.2.10.1.1). It is not
// graphics data: the session-setup machine records it even when the session is
// already active.
bool IsSaveSessionInfo(const std::vector<uint8_t>& pdu) {
    proto::McsSendData sd;
    if (proto::McsSendData::parse(pdu.data(), pdu.size(), sd) !=
        proto::Status::Ok) {
        return false;
    }
    proto::ShareControlHeader ctrl;
    if (proto::ShareControlHeader::parse(sd.user_data.data(), sd.user_data.size(),
                                         ctrl) != proto::Status::Ok) {
        return false;
    }
    if (ctrl.type != proto::SharePduType::kData) return false;
    proto::ShareDataHeader hdr;
    if (proto::ShareDataHeader::parse(sd.user_data.data(), sd.user_data.size(),
                                      hdr) != proto::Status::Ok) {
        return false;
    }
    return hdr.pdu_type2 == proto::ShareDataPduType::kSaveSessionInfo;
}

}  // namespace

ConnectionDriver::ConnectionDriver(proto::ConnectMachine::Config machine_config,
                                   proto::ConnectMachine::Credentials credentials,
                                   Config security_config)
    : machine_(machine_config, credentials),
      machine_config_(machine_config),
      security_config_(std::move(security_config)),
      credentials_(std::move(credentials)) {}

void ConnectionDriver::ResetForReconnect(std::vector<uint8_t> cookie) {
    machine_config_.auto_reconnect_cookie = std::move(cookie);
    machine_ = proto::ConnectMachine(machine_config_, credentials_);
    security_.reset();
    standard_.reset();
    licensing_.reset();
    session_.reset();
    plain_buf_.clear();
    client_info_sent_ = false;
    standard_rdp_ = false;
    io_channel_id_ = 0;
    unrouted_channel_count_ = 0;
    // channel_handlers_ and session_pdu_handler_ are intentionally kept: the
    // static virtual channel ids follow the advertised name order and are the
    // same after a reconnect, and the graphics handler belongs to the Client.
}

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
    const ConnectPhase phase = machine_.state().phase;

    // ---- plaintext phase ---------------------------------------------------
    // X.224 is always plaintext. Under Standard RDP Security (PROTOCOL_RDP)
    // the whole MCS handshake is plaintext too; it ends only after the Client
    // Info PDU has been emitted. Under TLS this branch stops at the Connection
    // Confirm and the security layer takes over.
    const bool plaintext_connect =
        phase == ConnectPhase::kAwaitNegotiation ||
        (standard_rdp_ && !client_info_sent_ && phase != ConnectPhase::kFailed);
    if (plaintext_connect) {
        if (data != nullptr && size > 0) {
            plain_buf_.insert(plain_buf_.end(), data, data + size);
        }

        DriverStep out;
        size_t start = 0;
        for (;;) {
            const size_t len = TpktFrameLength(plain_buf_, start);
            if (len == 0) break;

            // The Connect Response carries TS_UD_SC_SEC1, which is the only
            // place the server random and RSA certificate appear for Standard
            // RDP Security.
            if (standard_rdp_ &&
                machine_.state().phase == ConnectPhase::kAwaitConnectResponse) {
                std::string why;
                const std::vector<uint8_t> frame(
                    plain_buf_.begin() + static_cast<ptrdiff_t>(start),
                    plain_buf_.begin() + static_cast<ptrdiff_t>(start + len));
                if (!CaptureServerSecurity(frame, why)) return Fail(why);
            }

            const auto step = machine_.OnData(plain_buf_.data() + start, len);
            start += len;

            // The Connection Confirm selects the security model. The machine
            // has already produced the MCS Connect Initial for PROTOCOL_RDP.
            if (machine_.state().phase != ConnectPhase::kAwaitNegotiation &&
                !standard_rdp_ &&
                machine_.state().negotiated_protocol == proto::kProtocolRdp) {
                standard_rdp_ = true;
                standard_ = std::make_unique<StandardRdpSecurity>();
            }

            if (!client_info_sent_ && standard_rdp_ && machine_.done()) {
                // Security Exchange precedes Client Info, and Client Info
                // itself stays plaintext (SEC_INFO_PKT only).
                if (standard_->encryption_enabled()) {
                    std::string why;
                    const auto exchange = standard_->BuildSecurityExchange(
                        machine_.state().user_channel_id,
                        machine_.state().io_channel_id, why);
                    if (exchange.empty()) {
                        return Fail(
                            "cannot build the Security Exchange PDU: " + why);
                    }
                    Append(out.to_send, exchange);
                }
                Append(out.to_send, step.output);
                BeginPostClientInfo(out);
                // Anything after this frame belongs to the post-connect data
                // plane; leave it in plain_buf_ for the leftover hand-off.
                break;
            }
            Append(out.to_send, step.output);
        }
        if (start > 0) {
            plain_buf_.erase(plain_buf_.begin(),
                             plain_buf_.begin() + static_cast<ptrdiff_t>(start));
        }

        if (machine_.failed()) return Fail(machine_.state().error);

        if (!standard_rdp_ &&
            machine_.state().phase == ConnectPhase::kAwaitExternalSecurity) {
            // [MS-RDPBCGR] 2.2.10.2: the server sends the EUAR only when
            // PROTOCOL_HYBRID_EX was negotiated; HYBRID resumes directly with
            // the MCS Connect Initial.
            security_config_.expect_euar =
                (machine_.state().negotiated_protocol & proto::kProtocolHybridEx) != 0;
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

        // Bytes after the last connect frame already belong to the encrypted
        // data plane (the server may pipeline its License Request). Hand them
        // to the Standard RDP Security framer now that licensing_ exists.
        if (standard_rdp_ && client_info_sent_ && !plain_buf_.empty()) {
            const std::vector<uint8_t> leftover = std::move(plain_buf_);
            plain_buf_.clear();
            const auto frames =
                standard_->ReceivePdu(leftover.data(), leftover.size());
            if (standard_->failed()) return Fail(standard_->error());
            for (const auto& f : frames) {
                RoutePostConnect(f, out);
                if (out.failed) return out;
            }
        }
        return out;
    }

    // ---- external security handshake ---------------------------------------
    if (machine_.state().phase == ConnectPhase::kAwaitExternalSecurity) {
        return DriveSecurity(data, size);
    }

    // ---- post-handshake data plane -----------------------------------------
    DriverStep out;
    std::vector<std::vector<uint8_t>> frames;
    if (standard_rdp_) {
        frames = standard_->ReceivePdu(data, size);
        if (standard_->failed()) return Fail(standard_->error());
    } else {
        if (!security_) return Fail("post-handshake data with no security layer");
        frames = security_->ReceivePdu(data, size);
    }

    for (const auto& f : frames) {
        if (!client_info_sent_) {
            const auto step = machine_.OnData(f.data(), f.size());
            if (!step.output.empty()) AppendOutbound(step.output, out);
            if (out.failed) return out;
            if (machine_.failed()) return Fail(machine_.state().error);
            if (machine_.done()) {
                // The Client Info PDU has been sent; the licensing phase begins.
                BeginPostClientInfo(out);
            }
            continue;
        }
        RoutePostConnect(f, out);
        if (out.failed) return out;
    }
    return out;
}

void ConnectionDriver::BeginPostClientInfo(DriverStep& out) {
    if (client_info_sent_) return;
    client_info_sent_ = true;
    out.done = true;
    // Latch the I/O channel id parsed from the Server Network Data block;
    // post-active routing compares each inbound PDU against it to tell
    // graphics data from static virtual channel data.
    io_channel_id_ = machine_.state().io_channel_id;

    proto::LicensingMachine::Config lc;
    lc.user_channel_id = machine_.state().user_channel_id;
    lc.io_channel_id = machine_.state().io_channel_id;
    lc.user_name = credentials_.user_name;
    lc.machine_name = machine_config_.client_name;
    if (standard_rdp_) {
        // The in-tree server carries the RSA key only in TS_UD_SC_SEC1, and
        // omits it entirely when encryption is off. The fallback keeps the
        // plaintext Standard RDP Security path usable against that server.
        lc.server_certificate = standard_->server_certificate();
    }
    // The in-tree server omits the licensing certificate on the enhanced
    // (TLS/CredSSP) path too: it issues no CAL and does not validate the
    // client's encrypted premaster. A real server supplies the certificate and
    // the client still uses it; `allow_missing_server_key` only relaxes the
    // "no certificate at all" case, so it is safe to set for both paths.
    lc.allow_missing_server_key = true;
    licensing_ = std::make_unique<proto::LicensingMachine>(lc);
    licensing_->Start();

    proto::SessionSetupMachine::Config sc;
    sc.user_channel_id = machine_.state().user_channel_id;
    sc.io_channel_id = machine_.state().io_channel_id;
    sc.desktop_width = static_cast<uint16_t>(machine_config_.desktop_width);
    sc.desktop_height = static_cast<uint16_t>(machine_config_.desktop_height);
    // RAIL caps are claimed only when the "rail" static virtual channel was
    // advertised in the Client Network Data (RemoteApp mode).
    for (const auto& name : machine_config_.channel_names) {
        if (name == "rail") {
            sc.rail_mode = true;
            break;
        }
    }
    session_ = std::make_unique<proto::SessionSetupMachine>(sc);
    session_->Start();
}

void ConnectionDriver::AppendOutbound(const std::vector<uint8_t>& pdu,
                                      DriverStep& out) {
    if (standard_rdp_) {
        Append(out.to_send, standard_->SendPdu(pdu));
        if (standard_->failed()) {
            out.failed = true;
            out.error = standard_->error();
        }
        return;
    }
    if (security_) Append(out.to_send, security_->SendPdu(pdu));
}

bool ConnectionDriver::CaptureServerSecurity(const std::vector<uint8_t>& frame,
                                             std::string& why) {
    if (!standard_ || standard_->configured()) return true;

    proto::McsConnectResponse rsp;
    if (proto::McsConnectResponse::parse(frame.data(), frame.size(), rsp) !=
        proto::Status::Ok) {
        why = "malformed MCS Connect Response";
        return false;
    }
    const auto* sec = rsp.user_data.find(
        static_cast<uint16_t>(proto::GccUserDataBlock::kScSecurity));
    if (sec == nullptr) {
        why = "Server Security Data (TS_UD_SC_SEC1) is missing";
        return false;
    }

    StandardRdpSecurity::ServerSecurityData data;
    if (!StandardRdpSecurity::ParseServerSecurityData(
            sec->payload.data(), sec->payload.size(), data, why)) {
        return false;
    }
    return standard_->Configure(data, why);
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
    // orders data; the static virtual channels were routed above. A share
    // Deactivate All is the one exception: it starts the
    // Deactivation-Reactivation Sequence ([MS-RDPBCGR] 1.3.1.3), so it must
    // reach the session-setup machine instead of the graphics pipeline.
    if (session_ != nullptr && session_->active()) {
        if (IsDeactivateAll(pdu)) {
            const auto ss = session_->OnPdu(pdu.data(), pdu.size());
            for (const auto& p : ss.to_send) {
                AppendOutbound(p, out);
                if (out.failed) return;
            }
            if (ss.failed) {
                out.failed = true;
                out.error = "session setup failed: " + ss.error;
            }
            return;
        }
        if (IsSaveSessionInfo(pdu)) {
            // 2.2.10.1.1 arrives after activation on the I/O channel; hand it
            // to the session machine for recording instead of the graphics
            // pipeline (which would drop it as an unknown update).
            const auto ss = session_->OnPdu(pdu.data(), pdu.size());
            if (ss.failed) {
                out.failed = true;
                out.error = "session setup failed: " + ss.error;
            }
            return;
        }
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
            AppendOutbound(p, out);
            if (out.failed) return;
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
        AppendOutbound(p, out);
        if (out.failed) return;
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
        Append(out.to_send, r.to_wire);
        // With PROTOCOL_HYBRID (no EUAR) the handshake is complete as soon as
        // step 5 is produced: the layer already reports kDone even though this
        // flight carried the final CredSSP message. Emit the MCS Connect
        // Initial now; waiting for a read that never comes deadlocks.
        if (!security_->handshake_complete()) return out;
    } else if (r.want == Want::kRead) {
        return out;  // empty: need more bytes from the peer
    } else if (r.want == Want::kFailed) {
        return Fail("security handshake failed: " + r.error);
    }

    // Handshake complete: emit the MCS Connect Initial through the layer.
    const auto step = machine_.OnExternalSecurityComplete();
    if (machine_.failed()) return Fail(machine_.state().error);
    if (!step.output.empty()) {
        Append(out.to_send, security_->SendPdu(step.output));
    }
    return out;
}

std::vector<uint8_t> ConnectionDriver::SendApplicationPdu(
    const std::vector<uint8_t>& pdu) {
    if (standard_rdp_) {
        if (pdu.empty()) return {};
        const uint16_t user_channel = machine_.state().user_channel_id;
        if (user_channel == 0 || io_channel_id_ == 0) return {};
        const auto framed = proto::McsSendData::build_request(
            user_channel, io_channel_id_, pdu);
        if (framed.empty()) return {};
        return standard_->SendPdu(framed);
    }
    return security_ ? security_->SendPdu(pdu) : pdu;
}

std::vector<uint8_t> ConnectionDriver::SendChannelPdu(
    uint16_t channel_id, const std::vector<uint8_t>& pdu) {
    if (pdu.empty() || channel_id == 0) return {};
    const uint16_t user_channel = machine_.state().user_channel_id;
    if (user_channel == 0) return {};
    const auto framed =
        proto::McsSendData::build_request(user_channel, channel_id, pdu);
    if (framed.empty()) return {};
    if (standard_rdp_) return standard_->SendPdu(framed);
    // No security layer yet: writing the plaintext MCS frame would corrupt the
    // TLS stream, so drop it instead (the caller sends only after active).
    return security_ ? security_->SendPdu(framed) : std::vector<uint8_t>{};
}

uint16_t ConnectionDriver::ChannelIdForName(const std::string& name) const {
    const std::vector<std::string>& names = machine_config_.channel_names;
    const std::vector<uint16_t>& ids = machine_.state().static_virtual_channels;
    for (size_t i = 0; i < names.size() && i < ids.size(); ++i) {
        if (names[i] == name) return ids[i];
    }
    return 0;
}

}  // namespace rtsc::security
