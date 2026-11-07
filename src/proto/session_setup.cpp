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

namespace {

constexpr uint32_t kLogonInfoV2PadSize = 558;
// TS_LOGON_INFO_VERSION_2::Size is 18 (the fixed part) per the spec dump, but
// some servers report the total 576; both are accepted ([FreeRDP info.c]).
constexpr uint32_t kLogonInfoV2SizeShort = 18;
constexpr uint32_t kLogonInfoV2SizeFull = 576;

// [MS-RDPBCGR] 2.2.10.1.1.2: Domain/UserName are null-terminated UTF-16LE.
// Limits from the fixed TS_LOGON_INFO (v1) fields, as FreeRDP does.
constexpr uint32_t kMaxDomainBytes = 52;
constexpr uint32_t kMaxUserNameBytes = 512;

std::string DecodeUtf16Le(const uint8_t* data, size_t size) {
    std::string out;
    for (size_t i = 0; i + 2 <= size; i += 2) {
        const uint32_t cp = static_cast<uint32_t>(data[i]) |
                            (static_cast<uint32_t>(data[i + 1]) << 8);
        if (cp == 0) break;
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

Status ParseLogonInfoV2(ByteReader& r, SaveSessionInfo& out) {
    uint16_t version = 0;
    uint32_t size = 0;
    uint32_t session_id = 0;
    uint32_t cb_domain = 0;
    uint32_t cb_user = 0;
    if (!r.u16le(version) || version != 1) return Status::InvalidVersion;
    if (!r.u32le(size)) return Status::InvalidLength;
    // Windows Server 2019/2022 send 12 rather than 570 ([FreeRDP info.c]).
    if (size != kLogonInfoV2SizeFull && size != kLogonInfoV2SizeShort) {
        return Status::InvalidLength;
    }
    if (!r.u32le(session_id) || !r.u32le(cb_domain) || !r.u32le(cb_user)) {
        return Status::InvalidLength;
    }
    if (!r.skip(kLogonInfoV2PadSize)) return Status::InvalidLength;
    if (cb_domain > kMaxDomainBytes || cb_user > kMaxUserNameBytes) {
        return Status::InvalidLength;
    }
    if ((cb_domain & 1) != 0 || (cb_user & 1) != 0) {
        return Status::InvalidLength;
    }
    if (r.remaining() < static_cast<size_t>(cb_domain) + cb_user) {
        return Status::InvalidLength;
    }
    const uint8_t* domain = r.cursor();
    if (!r.skip(cb_domain)) return Status::InvalidLength;
    const uint8_t* user = r.cursor();
    if (!r.skip(cb_user)) return Status::InvalidLength;

    out.has_logon = true;
    out.session_id = session_id;
    out.domain = DecodeUtf16Le(domain, cb_domain);
    out.user_name = DecodeUtf16Le(user, cb_user);
    return Status::Ok;
}

Status ParseLogonInfoExtended(ByteReader& r, SaveSessionInfo& out) {
    uint16_t length = 0;
    uint32_t fields_present = 0;
    const size_t length_offset = r.offset();
    if (!r.u16le(length) || !r.u32le(fields_present)) {
        return Status::InvalidLength;
    }
    // Length counts itself: 2 + 4 (FieldsPresent) + the field blocks. It must
    // fit in the remaining body.
    if (length < 6 ||
        r.remaining() < static_cast<size_t>(length) - 6) {
        return Status::InvalidLength;
    }
    const size_t end = length_offset + length;
    if (r.offset() > end) return Status::InvalidLength;
    if ((fields_present & 1u) == 0) {
        return Status::Ok;  // no LOGON_EX_AUTORECONNECTCOOKIE
    }
    uint32_t cb_field = 0;
    uint32_t cb_len = 0;
    uint32_t version = 0;
    uint32_t logon_id = 0;
    if (!r.u32le(cb_field) || cb_field < 28) return Status::InvalidLength;
    if (!r.u32le(cb_len) || cb_len != 28) return Status::InvalidLength;
    if (!r.u32le(version) || !r.u32le(logon_id)) return Status::InvalidLength;
    uint8_t random[16] = {};
    if (!r.bytes(random, sizeof(random))) return Status::InvalidLength;
    if (r.offset() > end) return Status::InvalidLength;

    out.has_auto_reconnect_cookie = true;
    out.auto_reconnect_version = version;
    out.auto_reconnect_logon_id = logon_id;
    out.auto_reconnect_random.assign(random, random + sizeof(random));
    return Status::Ok;
}

}  // namespace

Status ParseSaveSessionInfo(const uint8_t* data, size_t size,
                            SaveSessionInfo& out) {
    ByteReader r(data, size);
    uint32_t info_type = 0;
    if (!r.u32le(info_type)) return Status::InvalidLength;
    switch (info_type) {
        case 0:  // INFOTYPE_LOGON (v1): not decoded
        case 2:  // INFOTYPE_LOGON_PLAINNOTIFY: 576 bytes of padding, no data
            return Status::Ok;
        case 1:  // INFOTYPE_LOGON_LONG
            return ParseLogonInfoV2(r, out);
        case 3:  // INFOTYPE_LOGON_EXTENDED_INFO
            return ParseLogonInfoExtended(r, out);
        default:
            return Status::Ok;  // forward compatibility
    }
}

namespace {

void AppendUtf16Le(std::vector<uint8_t>& out, uint32_t cp) {
    if (cp > 0xFFFF) {
        cp -= 0x10000;
        const uint32_t hi = 0xD800 + (cp >> 10);
        const uint32_t lo = 0xDC00 + (cp & 0x3FF);
        out.push_back(static_cast<uint8_t>(hi & 0xFF));
        out.push_back(static_cast<uint8_t>((hi >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(lo & 0xFF));
        out.push_back(static_cast<uint8_t>((lo >> 8) & 0xFF));
        return;
    }
    out.push_back(static_cast<uint8_t>(cp & 0xFF));
    out.push_back(static_cast<uint8_t>((cp >> 8) & 0xFF));
}

// UTF-8 text -> null-terminated UTF-16LE. Returns false on invalid UTF-8.
bool Utf8ToUtf16Le(const std::string& text, std::vector<uint8_t>& out) {
    size_t i = 0;
    while (i < text.size()) {
        const uint8_t b = static_cast<uint8_t>(text[i]);
        uint32_t cp = 0;
        size_t extra = 0;
        if (b < 0x80) {
            cp = b;
        } else if ((b & 0xE0) == 0xC0) {
            cp = b & 0x1F;
            extra = 1;
        } else if ((b & 0xF0) == 0xE0) {
            cp = b & 0x0F;
            extra = 2;
        } else if ((b & 0xF8) == 0xF0) {
            cp = b & 0x07;
            extra = 3;
        } else {
            return false;
        }
        if (i + extra >= text.size()) return false;
        for (size_t k = 1; k <= extra; ++k) {
            const uint8_t c = static_cast<uint8_t>(text[i + k]);
            if ((c & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3F);
        }
        i += extra + 1;
        AppendUtf16Le(out, cp);
    }
    out.push_back(0);
    out.push_back(0);
    return true;
}

}  // namespace

std::vector<uint8_t> EncodeSaveSessionInfoLogon(uint32_t session_id,
                                                const std::string& domain,
                                                const std::string& user) {
    std::vector<uint8_t> domain_utf16;
    std::vector<uint8_t> user_utf16;
    if (!Utf8ToUtf16Le(domain, domain_utf16)) return {};
    if (!Utf8ToUtf16Le(user, user_utf16)) return {};
    if (domain_utf16.size() > kMaxDomainBytes ||
        user_utf16.size() > kMaxUserNameBytes) {
        return {};
    }
    ByteWriter w;
    w.u32le(1);                          // INFOTYPE_LOGON_LONG
    w.u16le(1);                          // SAVE_SESSION_PDU_VERSION_ONE
    w.u32le(kLogonInfoV2SizeFull);       // Size (fixed part, spec value)
    w.u32le(session_id);
    w.u32le(static_cast<uint32_t>(domain_utf16.size()));
    w.u32le(static_cast<uint32_t>(user_utf16.size()));
    for (uint32_t i = 0; i < kLogonInfoV2PadSize; ++i) w.u8(0);
    w.bytes(domain_utf16.data(), domain_utf16.size());
    w.bytes(user_utf16.data(), user_utf16.size());
    return w.take();
}

std::vector<uint8_t> EncodeSaveSessionInfoCookie(uint32_t version,
                                                 uint32_t logon_id,
                                                 const uint8_t random[16]) {
    ByteWriter w;
    w.u32le(3);   // INFOTYPE_LOGON_EXTENDED_INFO
    w.u16le(38);  // Length (includes itself: 2 + 4 + 4 + 28)
    w.u32le(1);   // FieldsPresent = LOGON_EX_AUTORECONNECTCOOKIE
    w.u32le(28);  // TS_LOGON_INFO_FIELD::cbFieldData
    w.u32le(28);  // ARC_SC_PRIVATE_PACKET::cbLen
    w.u32le(version);
    w.u32le(logon_id);
    w.bytes(random, 16);
    return w.take();
}

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

    if (state_.phase == SessionPhase::kDeactivated) {
        // Deactivation-Reactivation Sequence ([MS-RDPBCGR] 1.3.1.3): after a
        // Deactivate All PDU the server may either drop the connection or
        // re-run the Capability Exchange. Wait for the new Demand Active and
        // re-enter the same path the initial activation used; any other PDU
        // (including a repeated Deactivate All) is ignored until then.
        ShareControlHeader ctrl;
        if (ShareControlHeader::parse(sd.user_data.data(), sd.user_data.size(),
                                      ctrl) != Status::Ok) {
            return Fail("malformed share control header after Deactivate All");
        }
        if (ctrl.type == SharePduType::kDemandActive) {
            return HandleDemandActive(sd.user_data.data(), sd.user_data.size());
        }
        return out;
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
    // Both the Bitmap and the Input sets are consumed; the Input flags gate
    // client-sent features, so the scan must not break at the first match.
    for (const auto& set : da.capabilities.sets) {
        if (set.type == CapabilityType::kInput) {
            InputCapabilitySet input;
            if (InputCapabilitySet::parse(set, input) == Status::Ok) {
                state_.server_input_flags = input.input_flags;
            }
            continue;
        }
        if (set.type != CapabilityType::kBitmap) continue;
        BitmapCapabilitySet bmp;
        if (BitmapCapabilitySet::parse(set, bmp) == Status::Ok) {
            state_.desktop_width = bmp.desktop_width;
            state_.desktop_height = bmp.desktop_height;
        }
    }

    // Build Confirm Active.
    const auto caps = BuildDefaultClientCapabilities(
        config_.desktop_width, config_.desktop_height, config_.color_depth,
        config_.rail_mode);
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

    // Refresh Rect ([MS-RDPBCGR] 2.2.11.2) is NOT sent here: it belongs after
    // the server's Font Map completes activation (see HandleSharePdu).

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
            // [MS-RDPBCGR] 1.3.1.3: a Deactivate All PDU means either the
            // connection will be dropped or a Deactivation-Reactivation
            // Sequence will re-run the Capability Exchange. Enter kDeactivated
            // and let OnPdu decide when the next Demand Active arrives; while
            // deactivated, other share PDUs are ignored.
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
            // Recorded implicitly; no state change (12.2).
            return out;
        case ShareDataPduType::kMonitorLayout: {
            // The optional Monitor Layout PDU (2.2.12.1) arrives after the
            // Demand Active PDU. It only records the session layout; it does not
            // change the phase or trigger any reply (capabilities.md 12.2).
            MonitorLayoutPdu layout;
            if (MonitorLayoutPdu::parse_body(data + ShareDataHeader::kSize,
                                             size - ShareDataHeader::kSize,
                                             layout) == Status::Ok) {
                state_.monitors = layout.monitors;
                state_.has_monitor_layout = true;
            }
            return out;
        }
        case ShareDataPduType::kSaveSessionInfo: {
            // Logon identity and the auto-reconnect cookie ([MS-RDPBCGR]
            // 2.2.10.1.1). Recorded only; the phase does not change. A
            // malformed PDU is ignored so a decoration cannot end the session.
            SaveSessionInfo info;
            if (ParseSaveSessionInfo(data + ShareDataHeader::kSize,
                                     size - ShareDataHeader::kSize,
                                     info) == Status::Ok) {
                if (info.has_logon) {
                    state_.logon_info.has_logon = true;
                    state_.logon_info.session_id = info.session_id;
                    state_.logon_info.domain = info.domain;
                    state_.logon_info.user_name = info.user_name;
                }
                if (info.has_auto_reconnect_cookie) {
                    state_.logon_info.has_auto_reconnect_cookie = true;
                    state_.logon_info.auto_reconnect_version =
                        info.auto_reconnect_version;
                    state_.logon_info.auto_reconnect_logon_id =
                        info.auto_reconnect_logon_id;
                    state_.logon_info.auto_reconnect_random =
                        info.auto_reconnect_random;
                }
            }
            return out;
        }
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
                // Refresh Rect ([MS-RDPBCGR] 2.2.11.2), mirroring mstsc: the
                // client asks the server to send the desktop for the full
                // Demand-Active rectangle as soon as activation completes.
                // Without it a server that suppressed output for an idle
                // console never repaints and the client shows a black desktop.
                RefreshRectPdu refresh;
                RefreshRectPdu::Rect full;
                full.right = static_cast<uint16_t>(state_.desktop_width == 0
                                                       ? 0
                                                       : state_.desktop_width -
                                                             1);
                full.bottom = static_cast<uint16_t>(state_.desktop_height == 0
                                                        ? 0
                                                        : state_.desktop_height -
                                                              1);
                refresh.rectangles.push_back(full);
                out.to_send.push_back(FrameDataPdu(ShareDataPduType::kRefreshRect,
                                                   refresh.encode()));
            }
            return out;
        case ShareDataPduType::kSuppressOutput: {
            // [MS-RDPBCGR] 2.2.11.3.1: the client gates the server's desktop
            // output. With allowDisplayUpdates=1 the PDU names the desktop
            // rectangle and the client answers with a Refresh Rect for it,
            // mirroring mstsc. allowDisplayUpdates=0 keeps the output
            // suppressed and needs no reply. A malformed body is ignored: the
            // session continues.
            SuppressOutputPdu sup;
            if (SuppressOutputPdu::parse(data + ShareDataHeader::kSize,
                                         size - ShareDataHeader::kSize,
                                         sup) != Status::Ok) {
                return out;
            }
            if (sup.allow_display_updates) {
                RefreshRectPdu refresh;
                if (sup.rectangles.empty()) {
                    RefreshRectPdu::Rect full;
                    full.right = static_cast<uint16_t>(
                        state_.desktop_width == 0 ? 0 : state_.desktop_width - 1);
                    full.bottom = static_cast<uint16_t>(
                        state_.desktop_height == 0 ? 0
                                                   : state_.desktop_height - 1);
                    refresh.rectangles.push_back(full);
                } else {
                    refresh.rectangles = sup.rectangles;
                }
                out.to_send.push_back(
                    FrameDataPdu(ShareDataPduType::kRefreshRect,
                                 refresh.encode()));
            }
            return out;
        }
        default:
            // Graphics / input PDUs before Font Map, or anything unlisted: the
            // state machine only reacts to the PDUs above (12.2).
            return out;
    }
}

}  // namespace rtsc::proto

