#include "rtsc/proto/share.h"

namespace rtsc::proto {

const char* to_string(SharePduType type) {
    switch (type) {
        case SharePduType::kDemandActive: return "demand-active";
        case SharePduType::kConfirmActive: return "confirm-active";
        case SharePduType::kDeactivateAll: return "deactivate-all";
        case SharePduType::kData: return "data";
        case SharePduType::kServerRedirection: return "server-redirection";
    }
    return "unknown";
}

const char* to_string(ShareDataPduType type) {
    switch (type) {
        case ShareDataPduType::kUpdate: return "update";
        case ShareDataPduType::kControl: return "control";
        case ShareDataPduType::kPointer: return "pointer";
        case ShareDataPduType::kInput: return "input";
        case ShareDataPduType::kSynchronize: return "synchronize";
        case ShareDataPduType::kRefreshRect: return "refresh-rect";
        case ShareDataPduType::kPlaySound: return "play-sound";
        case ShareDataPduType::kSuppressOutput: return "suppress-output";
        case ShareDataPduType::kShutdownRequest: return "shutdown-request";
        case ShareDataPduType::kShutdownDenied: return "shutdown-denied";
        case ShareDataPduType::kSaveSessionInfo: return "save-session-info";
        case ShareDataPduType::kFontList: return "font-list";
        case ShareDataPduType::kFontMap: return "font-map";
        case ShareDataPduType::kSetKeyboardIndicators: return "set-keyboard-indicators";
        case ShareDataPduType::kPersistentKeyList: return "persistent-key-list";
        case ShareDataPduType::kBitmapCacheError: return "bitmap-cache-error";
        case ShareDataPduType::kSetKeyboardImeStatus: return "set-keyboard-ime-status";
        case ShareDataPduType::kOffscreenCacheError: return "offscreen-cache-error";
        case ShareDataPduType::kSetErrorInfo: return "set-error-info";
        case ShareDataPduType::kDrawNineGridError: return "draw-ninegrid-error";
        case ShareDataPduType::kDrawGdiPlusError: return "draw-gdiplus-error";
        case ShareDataPduType::kArcStatus: return "arc-status";
        case ShareDataPduType::kStatusInfo: return "status-info";
        case ShareDataPduType::kMonitorLayout: return "monitor-layout";
    }
    return "unknown";
}

// ---- ShareControlHeader ---------------------------------------------------

Status ShareControlHeader::parse(const uint8_t* data, size_t size,
                                 ShareControlHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    if (!r.u16le(out.total_length)) return Status::NeedMoreData;

    uint16_t pdu_type = 0;
    if (!r.u16le(pdu_type)) return Status::NeedMoreData;
    const uint16_t raw_type = static_cast<uint16_t>(pdu_type & 0x000F);
    out.pdu_version = static_cast<uint16_t>((pdu_type >> 4) & 0x0FFF);

    switch (raw_type) {
        case 0x1: out.type = SharePduType::kDemandActive; break;
        case 0x3: out.type = SharePduType::kConfirmActive; break;
        case 0x6: out.type = SharePduType::kDeactivateAll; break;
        case 0x7: out.type = SharePduType::kData; break;
        case 0xA: out.type = SharePduType::kServerRedirection; break;
        default:
            // Undefined pduType: the server reports ERRINFO_UNKNOWNPDUTYPE, so
            // the caller should treat this as a protocol error.
            return Status::InvalidType;
    }

    if (!r.u16le(out.pdu_source)) return Status::NeedMoreData;
    return Status::Ok;
}

void ShareControlHeader::write(ByteWriter& w) const {
    w.u16le(total_length);
    const uint16_t pdu_type = static_cast<uint16_t>(
        (static_cast<uint16_t>(type) & 0x000F) |
        ((static_cast<uint16_t>(pdu_version) & 0x0FFF) << 4));
    w.u16le(pdu_type);
    w.u16le(pdu_source);
}

// ---- ShareDataHeader ------------------------------------------------------

Status ShareDataHeader::parse(const uint8_t* data, size_t size,
                              ShareDataHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    Status s = ShareControlHeader::parse(data, size, out.control);
    if (s != Status::Ok) return s;
    if (out.control.type != SharePduType::kData) return Status::InvalidType;
    // Data PDUs always carry TS_PROTOCOL_VERSION in the upper 12 bits.
    if (out.control.pdu_version != ShareControlHeader::kProtocolVersion) {
        return Status::InvalidVersion;
    }

    ByteReader r(data, size);
    if (!r.skip(ShareControlHeader::kSize)) return Status::NeedMoreData;
    if (!r.u32le(out.share_id)) return Status::NeedMoreData;
    if (!r.u8(out.pad1)) return Status::NeedMoreData;
    if (!r.u8(out.stream_id)) return Status::NeedMoreData;
    if (!r.u16le(out.uncompressed_length)) return Status::NeedMoreData;
    uint8_t type2 = 0;
    if (!r.u8(type2)) return Status::NeedMoreData;
    out.pdu_type2 = static_cast<ShareDataPduType>(type2);
    if (!r.u8(out.compressed_type)) return Status::NeedMoreData;
    if (!r.u16le(out.compressed_length)) return Status::NeedMoreData;
    return Status::Ok;
}

void ShareDataHeader::write(ByteWriter& w) const {
    ShareControlHeader h = control;
    h.type = SharePduType::kData;
    h.pdu_version = ShareControlHeader::kProtocolVersion;
    h.write(w);
    w.u32le(share_id);
    w.u8(pad1);
    w.u8(stream_id);
    w.u16le(uncompressed_length);
    w.u8(static_cast<uint8_t>(pdu_type2));
    w.u8(compressed_type);
    w.u16le(compressed_length);
}

// ---- Security header ------------------------------------------------------

SecurityHeaderKind SelectSecurityHeader(uint32_t encryption_level,
                                        uint32_t encryption_method,
                                        bool force_basic) {
    constexpr uint32_t kMethodNone = 0x00000000;
    constexpr uint32_t kMethodFips = 0x00000010;
    constexpr uint32_t kMethod40 = 0x00000001;
    constexpr uint32_t kMethod128 = 0x00000002;
    constexpr uint32_t kMethod56 = 0x00000008;
    constexpr uint32_t kLevelLow = 0x00000001;

    if (encryption_method == kMethodFips) return SecurityHeaderKind::kFips;
    if (encryption_method == kMethod40 || encryption_method == kMethod128 ||
        encryption_method == kMethod56) {
        return SecurityHeaderKind::kNonFips;
    }
    if (encryption_level == kLevelLow) return SecurityHeaderKind::kBasic;
    if (force_basic) return SecurityHeaderKind::kBasic;
    if (encryption_level == 0 && encryption_method == kMethodNone) {
        return SecurityHeaderKind::kNone;
    }
    return SecurityHeaderKind::kNone;
}

Status SecurityHeader::parse(const uint8_t* data, size_t size,
                             SecurityHeaderKind kind, SecurityHeader& out) {
    out = SecurityHeader{};
    out.kind = kind;
    const size_t need = static_cast<size_t>(kind);
    if (need == 0) return Status::Ok;
    if (data == nullptr || size < need) return Status::NeedMoreData;

    ByteReader r(data, size);
    if (!r.u16le(out.flags)) return Status::NeedMoreData;
    // flagsHi is always present as 2 bytes; SEC_FLAGSHI_VALID only says whether
    // its content is meaningful.
    if (!r.u16le(out.flags_hi)) return Status::NeedMoreData;

    if (kind == SecurityHeaderKind::kBasic) return Status::Ok;

    if (kind == SecurityHeaderKind::kNonFips) {
        out.signature.resize(8);
        if (!r.bytes(out.signature.data(), out.signature.size())) {
            return Status::NeedMoreData;
        }
        return Status::Ok;
    }

    // FIPS: length(2) + version(1) + padlen(1) + signature(8).
    if (!r.u16le(out.fips_length)) return Status::NeedMoreData;
    if (!r.u8(out.fips_version)) return Status::NeedMoreData;
    if (!r.u8(out.padlen)) return Status::NeedMoreData;
    if (out.fips_length != kFipsSize) return Status::InvalidField;
    out.signature.resize(8);
    if (!r.bytes(out.signature.data(), out.signature.size())) {
        return Status::NeedMoreData;
    }
    return Status::Ok;
}

void SecurityHeader::write(ByteWriter& w) const {
    if (kind == SecurityHeaderKind::kNone) return;
    w.u16le(flags);
    w.u16le(flags_hi);
    if (kind == SecurityHeaderKind::kBasic) return;
    if (kind == SecurityHeaderKind::kFips) {
        w.u16le(kFipsSize);
        w.u8(fips_version);
        w.u8(padlen);
    }
    const size_t n = signature.size();
    for (size_t i = 0; i < n; ++i) w.u8(signature[i]);
}

// ---- Fast-Path ------------------------------------------------------------

bool ClassifyFastPath(uint8_t first_byte, FastPathAction& out) {
    switch (static_cast<uint8_t>(first_byte & 0x03)) {
        case 0x0:
            out = FastPathAction::kFastPath;
            return true;
        case 0x3:
            // Slow-path: the first byte is the TPKT version and must be 0x03.
            if (first_byte != 0x03) return false;
            out = FastPathAction::kX224;
            return true;
        default:
            return false;  // action 0x1 / 0x2 are undefined
    }
}

Status FastPathLength::parse(const uint8_t* data, size_t size,
                             FastPathLength& out) {
    if (data == nullptr || size < 1) return Status::NeedMoreData;
    if ((data[0] & 0x80) == 0) {
        out.value = data[0];
        out.two_byte = false;
    } else {
        if (size < 2) return Status::NeedMoreData;
        out.value = static_cast<size_t>(((data[0] & 0x7F) << 8) | data[1]);
        out.two_byte = true;
    }
    // The length counts the header byte(s) themselves, so 0 and 1 are both
    // impossible (minimum is 2: header + length1).
    if (out.value < 2) return Status::InvalidLength;
    return Status::Ok;
}

void FastPathLength::write(ByteWriter& w) const {
    if (!two_byte && value <= 0x7F) {
        w.u8(static_cast<uint8_t>(value));
    } else {
        w.u8(static_cast<uint8_t>(0x80 | ((value >> 8) & 0x7F)));
        w.u8(static_cast<uint8_t>(value & 0xFF));
    }
}

Status FastPathHeader::parse(const uint8_t* data, size_t size, bool input,
                             FastPathHeader& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    const uint8_t b = data[0];
    FastPathAction action;
    if (!ClassifyFastPath(b, action)) return Status::InvalidType;
    if (action != FastPathAction::kFastPath) return Status::InvalidType;
    out.action = action;
    out.count_or_reserved = static_cast<uint8_t>((b >> 2) & 0x0F);
    out.flags = static_cast<uint8_t>((b >> 6) & 0x03);
    // The output header's reserved bits MUST be zero on send; a receiver is
    // lenient here (forward compatibility), so it is not enforced.
    (void)input;
    return Status::Ok;
}

void FastPathHeader::write(ByteWriter& w, bool input) const {
    (void)input;
    const uint8_t b = static_cast<uint8_t>(
        (static_cast<uint8_t>(action) & 0x03) |
        ((count_or_reserved & 0x0F) << 2) | ((flags & 0x03) << 6));
    w.u8(b);
}

Status FastPathPdu::parse(const uint8_t* data, size_t size, bool input,
                          FastPathPdu& out) {
    Status s = FastPathHeader::parse(data, size, input, out.header);
    if (s != Status::Ok) return s;
    s = FastPathLength::parse(data + FastPathHeader::kSize,
                              size - FastPathHeader::kSize, out.length);
    if (s != Status::Ok) return s;

    const size_t prefix =
        FastPathHeader::kSize + (out.length.two_byte ? 2 : 1);
    if (out.length.value < prefix) return Status::InvalidLength;
    if (size < out.length.value) return Status::NeedMoreData;

    out.body.assign(data + prefix, data + out.length.value);
    return Status::Ok;
}

size_t FastPathInputEventSize(FastPathInputEventCode code) {
    switch (code) {
        case FastPathInputEventCode::kScancode: return 2;
        case FastPathInputEventCode::kMouse: return 7;
        case FastPathInputEventCode::kMouseX: return 7;
        case FastPathInputEventCode::kSync: return 1;
        case FastPathInputEventCode::kUnicode: return 3;
        case FastPathInputEventCode::kMouseRel: return 7;
        case FastPathInputEventCode::kQoeTimestamp: return 5;
    }
    return 0;
}

// ---- RefreshRectPdu ([MS-RDPBCGR] 2.2.11.2.1) ------------------------------

std::vector<uint8_t> RefreshRectPdu::encode() const {
    ByteWriter w;
    // numberOfAreas(1) + pad3Octets(3): the count comes FIRST, the padding
    // follows it. numberOfAreas is a u8 (max 255 areas; see share.h).
    w.u8(static_cast<uint8_t>(rectangles.size()));
    w.u8(0);
    w.u8(0);
    w.u8(0);
    for (const auto& rect : rectangles) {
        w.u16le(rect.left);
        w.u16le(rect.top);
        w.u16le(rect.right);
        w.u16le(rect.bottom);
    }
    return w.take();
}

Status RefreshRectPdu::parse(const uint8_t* data, size_t size,
                              RefreshRectPdu& out) {
    out.rectangles.clear();
    ByteReader r(data, size);
    uint8_t count = 0;
    if (!r.u8(count)) return Status::NeedMoreData;
    if (!r.skip(3)) return Status::NeedMoreData;  // pad3Octets
    for (uint8_t i = 0; i < count; ++i) {
        Rect rect;
        if (!r.u16le(rect.left)) return Status::NeedMoreData;
        if (!r.u16le(rect.top)) return Status::NeedMoreData;
        if (!r.u16le(rect.right)) return Status::NeedMoreData;
        if (!r.u16le(rect.bottom)) return Status::NeedMoreData;
        out.rectangles.push_back(rect);
    }
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- SuppressOutputPdu ([MS-RDPBCGR] 2.2.11.3.1) ---------------------------

Status SuppressOutputPdu::parse(const uint8_t* data, size_t size,
                                SuppressOutputPdu& out) {
    out = SuppressOutputPdu{};
    ByteReader r(data, size);
    uint8_t allow = 0;
    if (!r.u8(allow)) return Status::NeedMoreData;
    if (!r.skip(3)) return Status::NeedMoreData;  // pad3Octets
    // desktopRect is present if and only if allowDisplayUpdates == 1
    // ([MS-RDPBCGR] 2.2.11.3.1; FreeRDP update_read_suppress_output and
    // IronRDP do the same). There is no count field and no rectangle array.
    if (allow != 0) {
        RefreshRectPdu::Rect rect;
        if (!r.u16le(rect.left)) return Status::NeedMoreData;
        if (!r.u16le(rect.top)) return Status::NeedMoreData;
        if (!r.u16le(rect.right)) return Status::NeedMoreData;
        if (!r.u16le(rect.bottom)) return Status::NeedMoreData;
        out.rectangles.push_back(rect);
    }
    if (!r.empty()) return Status::InvalidLength;
    out.allow_display_updates = allow != 0;
    return Status::Ok;
}

}  // namespace rtsc::proto
