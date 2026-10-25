// Session setup state machine implementation.
//
// Reference: docs/spec/capabilities.md section 12.

#include "rtsc/proto/session_setup.h"

#include <cstdio>
#include <utility>

#include "rtsc/proto/finalization.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/share.h"

namespace rtsc::proto {

namespace {

// STREAM_LOW: the stream ID used by client-to-server finalization PDUs.
constexpr uint8_t kStreamLow = 0x01;

std::vector<uint8_t> ControlPayload(ControlAction action) {
    ByteWriter w;
    w.u16le(static_cast<uint16_t>(action));
    w.u16le(0);  // grantId (ignored by the server)
    w.u32le(0);  // controlId (ignored by the server)
    return w.take();
}

}  // namespace

const char* to_string(SessionPhase phase) {
    switch (phase) {
        case SessionPhase::kInit: return "init";
        case SessionPhase::kWaitDemandActive: return "wait-demand-active";
        case SessionPhase::kConfirmSent: return "confirm-sent";
        case SessionPhase::kFinalizing: return "finalizing";
        case SessionPhase::kActive: return "active";
        case SessionPhase::kDeactivated: return "deactivated";
        case SessionPhase::kClosed: return "closed";
    }
    return "unknown";
}

SessionSetupMachine::SessionSetupMachine(const Config& config)
    : config_(config) {
    state_.user_channel_id = config.user_channel_id;
}

void SessionSetupMachine::Start() {
    state_.phase = SessionPhase::kWaitDemandActive;
}

SessionStep SessionSetupMachine::Fail(const std::string& reason) {
    state_.phase = SessionPhase::kClosed;
    state_.error = reason;
    SessionStep s;
    s.failed = true;
    s.error = reason;
    return s;
}

std::vector<uint8_t> SessionSetupMachine::FrameDataPdu(
    ShareDataPduType type, const std::vector<uint8_t>& payload) const {
    const auto share = BuildSlowPathDataPdu(state_.user_channel_id,
                                            state_.share_id, kStreamLow, type,
                                            payload);
    return McsSendData::build_request(state_.user_channel_id,
                                      config_.io_channel_id, share);
}

SessionStep SessionSetupMachine::OnPdu(const uint8_t* data, size_t size) {
    SessionStep out;
    if (state_.phase == SessionPhase::kClosed) {
        out.failed = true;
        out.error = state_.error;
        return out;
    }
    if (state_.phase == SessionPhase::kInit) {
        // The caller must call Start() after licensing.
        return out;
    }

    McsSendData sd;
    if (McsSendData::parse(data, size, sd) != Status::Ok) {
        return Fail("malformed MCS Send Data PDU");
    }
    if (sd.user_data.empty()) return out;

    if (state_.phase == SessionPhase::kWaitDemandActive) {
        // The first share PDU the server sends is the Demand Active PDU. A
        // licensing PDU carries a Basic security header (SEC_LICENSE_PKT) and
        // is not a share PDU; this machine does not run the licensing exchange,
        // so such a PDU is recorded by the caller and skipped here.
        if (sd.user_data.size() >= 2 &&
            (static_cast<uint16_t>(sd.user_data[0]) |
             (static_cast<uint16_t>(sd.user_data[1]) << 8)) ==
                static_cast<uint16_t>(kSecLicensePkt)) {
            return out;  // licensing PDU: not ours to process
        }
        return HandleDemandActive(sd.user_data.data(), sd.user_data.size());
    }

    return HandleSharePdu(sd.user_data.data(), sd.user_data.size());
}

SessionStep SessionSetupMachine::HandleDemandActive(const uint8_t* data,
                                                    size_t size) {
    SessionStep out;

    DemandActivePdu da;
    if (DemandActivePdu::parse(data, size, da) != Status::Ok) {
        return Fail("malformed Demand Active PDU");
    }
    if (da.total_length != size) {
        return Fail("Demand Active totalLength does not match the PDU size");
    }
    if (da.capabilities.sets.empty()) {
        return Fail("Demand Active carried no capability sets");
    }

    state_.server_channel_id = da.pdu_source;
    state_.share_id = da.share_id;
    state_.server_capabilities = da.capabilities;

    // The server's answer is authoritative for the desktop size: the client
    // advertises a size, but the Demand Active bitmap capability is what the
    // session actually uses, and a 1:1 lossless view must match it exactly.
    for (const auto& set : da.capabilities.sets) {
        if (set.type != CapabilityType::kBitmap) continue;
        BitmapCapabilitySet bmp;
        if (BitmapCapabilitySet::parse(set, bmp) == Status::Ok) {
            state_.desktop_width = bmp.desktop_width;
            state_.desktop_height = bmp.desktop_height;
        }
        break;
    }

    // Build Confirm Active.
    const auto caps = BuildDefaultClientCapabilities(
        config_.desktop_width, config_.desktop_height, config_.color_depth);
    const auto confirm = ConfirmActivePdu::encode(
        state_.user_channel_id, state_.share_id, state_.server_channel_id,
        config_.source_descriptor, caps);
    if (confirm.empty()) {
        return Fail("failed to build the Confirm Active PDU");
    }
    out.to_send.push_back(
        McsSendData::build_request(state_.user_channel_id, config_.io_channel_id,
                                   confirm));

    // Connection Finalization batch, in the mandatory order:
    //   Synchronize -> Control(Cooperate) -> Control(RequestControl) -> FontList
    {
        ByteWriter w;
        w.u16le(SynchronizePdu::kSyncMsgType);
        w.u16le(state_.server_channel_id);
        out.to_send.push_back(
            FrameDataPdu(ShareDataPduType::kSynchronize, w.take()));
    }
    out.to_send.push_back(FrameDataPdu(
        ShareDataPduType::kControl,
        ControlPayload(ControlAction::kCooperate)));
    out.to_send.push_back(FrameDataPdu(
        ShareDataPduType::kControl,
        ControlPayload(ControlAction::kRequestControl)));
    {
        ByteWriter w;
        w.u16le(0);                       // numberFonts
        w.u16le(0);                       // totalNumFonts
        w.u16le(FontListPdu::kListFlagsFirst | FontListPdu::kListFlagsLast);
        w.u16le(0x0032);                  // entrySize
        out.to_send.push_back(
            FrameDataPdu(ShareDataPduType::kFontList, w.take()));
    }

    confirm_sent_ = true;
    // S2 -> S3: everything up to Font List has been emitted.
    state_.phase = SessionPhase::kFinalizing;
    return out;
}

SessionStep SessionSetupMachine::HandleSharePdu(const uint8_t* data,
                                                size_t size) {
    SessionStep out;

    ShareControlHeader ctrl;
    if (ShareControlHeader::parse(data, size, ctrl) != Status::Ok) {
        return Fail("malformed share control header");
    }

    switch (ctrl.type) {
        case SharePduType::kDeactivateAll: {
            // S4 -> S5: the server is dropping the connection; graphics and
            // input handlers must be torn down. No state re-negotiation here.
            state_.phase = SessionPhase::kDeactivated;
            return out;
        }
        case SharePduType::kData:
            break;
        default:
            // Anything else at this stage is ignored (capabilities.md 12.2).
            return out;
    }

    ShareDataHeader hdr;
    if (ShareDataHeader::parse(data, size, hdr) != Status::Ok) {
        return Fail("malformed share data header");
    }

    switch (hdr.pdu_type2) {
        case ShareDataPduType::kSynchronize:
        case ShareDataPduType::kControl:
        case ShareDataPduType::kMonitorLayout:
            // Recorded implicitly; no state change (12.2).
            return out;
        case ShareDataPduType::kSetErrorInfo: {
            // 2.2.5.1: share data header (18) + errorInfo (4) + errorInfoData.
            if (size >= ShareDataHeader::kSize + 4) {
                const uint8_t* p = data + ShareDataHeader::kSize;
                state_.error_info = static_cast<uint32_t>(p[0]) |
                                    (static_cast<uint32_t>(p[1]) << 8) |
                                    (static_cast<uint32_t>(p[2]) << 16) |
                                    (static_cast<uint32_t>(p[3]) << 24);
                state_.has_error_info = true;
            }
            return out;  // does not change the state
        }
        case ShareDataPduType::kFontMap:
            // The Font Map PDU is the last PDU of the connection sequence.
            if (state_.phase == SessionPhase::kFinalizing) {
                state_.phase = SessionPhase::kActive;
                out.active = true;
            }
            return out;
        default:
            // Graphics / input PDUs before Font Map, or anything unlisted: the
            // state machine only reacts to the PDUs above (12.2).
            return out;
    }
}

}  // namespace rtsc::proto
