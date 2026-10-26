// RAIL (Remote Applications Integrated Locally) protocol implementation
// ([MS-RDPERP]).

#include "rtsc/proto/rail.h"

#include <cstring>
#include <utility>

namespace rtsc::proto {

namespace {

int16_t ReadI16(ByteReader& r, bool& ok) {
    uint16_t v = 0;
    if (!r.u16le(v)) {
        ok = false;
        return 0;
    }
    return static_cast<int16_t>(v);
}

void WriteI16(ByteWriter& w, int16_t v) {
    w.u16le(static_cast<uint16_t>(v));
}

}  // namespace

const char* to_string(RailOrderType t) {
    switch (t) {
        case RailOrderType::kExec: return "TS_RAIL_ORDER_EXEC";
        case RailOrderType::kActivate: return "TS_RAIL_ORDER_ACTIVATE";
        case RailOrderType::kSysparam: return "TS_RAIL_ORDER_SYSPARAM";
        case RailOrderType::kSyscommand: return "TS_RAIL_ORDER_SYSCOMMAND";
        case RailOrderType::kHandshake: return "TS_RAIL_ORDER_HANDSHAKE";
        case RailOrderType::kNotifyEvent: return "TS_RAIL_ORDER_NOTIFY_EVENT";
        case RailOrderType::kWindowMove: return "TS_RAIL_ORDER_WINDOWMOVE";
        case RailOrderType::kLocalMoveSize: return "TS_RAIL_ORDER_LOCALMOVESIZE";
        case RailOrderType::kMinMaxInfo: return "TS_RAIL_ORDER_MINMAXINFO";
        case RailOrderType::kClientStatus: return "TS_RAIL_ORDER_CLIENTSTATUS";
        case RailOrderType::kSysmenu: return "TS_RAIL_ORDER_SYSMENU";
        case RailOrderType::kLangbarInfo: return "TS_RAIL_ORDER_LANGBARINFO";
        case RailOrderType::kGetAppIdReq: return "TS_RAIL_ORDER_GET_APPID_REQ";
        case RailOrderType::kGetAppIdResp: return "TS_RAIL_ORDER_GET_APPID_RESP";
        case RailOrderType::kTaskbarInfo: return "TS_RAIL_ORDER_TASKBARINFO";
        case RailOrderType::kLanguageImeInfo: return "TS_RAIL_ORDER_LANGUAGEIMEINFO";
        case RailOrderType::kCompartmentInfo: return "TS_RAIL_ORDER_COMPARTMENTINFO";
        case RailOrderType::kHandshakeEx: return "TS_RAIL_ORDER_HANDSHAKE_EX";
        case RailOrderType::kZOrderSync: return "TS_RAIL_ORDER_ZORDER_SYNC";
        case RailOrderType::kCloak: return "TS_RAIL_ORDER_CLOAK";
        case RailOrderType::kPowerDisplayRequest:
            return "TS_RAIL_ORDER_POWER_DISPLAY_REQUEST";
        case RailOrderType::kSnapArrange: return "TS_RAIL_ORDER_SNAP_ARRANGE";
        case RailOrderType::kGetAppIdRespEx:
            return "TS_RAIL_ORDER_GET_APPID_RESP_EX";
        case RailOrderType::kTextScaleInfo: return "TS_RAIL_ORDER_TEXTSCALEINFO";
        case RailOrderType::kCaretBlinkInfo: return "TS_RAIL_ORDER_CARETBLINKINFO";
        case RailOrderType::kExecResult: return "TS_RAIL_ORDER_EXEC_RESULT";
    }
    return "TS_RAIL_ORDER_UNKNOWN";
}

Status RailPduHeader::parse(const uint8_t* data, size_t size, RailPduHeader& out) {
    ByteReader r(data, size);
    if (!r.u16le(out.order_type)) return Status::NeedMoreData;
    if (!r.u16le(out.order_length)) return Status::NeedMoreData;
    return Status::Ok;
}

void RailPduHeader::write(ByteWriter& w) const {
    w.u16le(order_type);
    w.u16le(order_length);
}

Status RailPdu::parse(const uint8_t* data, size_t size, RailPdu& out,
                      size_t& consumed) {
    consumed = 0;
    RailPduHeader header;
    if (RailPduHeader::parse(data, size, header) != Status::Ok) {
        return Status::NeedMoreData;
    }
    if (header.order_length < RailPduHeader::kSize) {
        return Status::InvalidLength;
    }
    if (header.order_length > size) {
        return Status::NeedMoreData;
    }
    out.header = header;
    out.body.assign(data + RailPduHeader::kSize, data + header.order_length);
    consumed = header.order_length;
    return Status::Ok;
}

void WriteRailPduHeader(ByteWriter& w, uint16_t order_type, size_t body_size) {
    RailPduHeader h;
    h.order_type = order_type;
    h.order_length = static_cast<uint16_t>(RailPduHeader::kSize + body_size);
    h.write(w);
}

Status ReadRailPduHeader(ByteReader& r, uint16_t expected_type, size_t& body_size) {
    RailPduHeader h;
    if (!r.u16le(h.order_type)) return Status::NeedMoreData;
    if (!r.u16le(h.order_length)) return Status::NeedMoreData;
    if (h.order_type != expected_type) return Status::InvalidType;
    if (h.order_length < RailPduHeader::kSize) return Status::InvalidLength;
    body_size = static_cast<size_t>(h.order_length) - RailPduHeader::kSize;
    return Status::Ok;
}

std::vector<uint8_t> BuildRailPdu(uint16_t order_type,
                                  const std::vector<uint8_t>& body) {
    std::vector<uint8_t> out;
    out.reserve(RailPduHeader::kSize + body.size());
    ByteWriter w;
    WriteRailPduHeader(w, order_type, body.size());
    w.bytes(body.data(), body.size());
    return w.take();
}

std::vector<uint8_t> RailUtf16ToLeBytes(const std::u16string& s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() * 2);
    for (char16_t c : s) {
        out.push_back(static_cast<uint8_t>(c & 0xFF));
        out.push_back(static_cast<uint8_t>(static_cast<uint16_t>(c) >> 8));
    }
    return out;
}

std::u16string RailLeBytesToUtf16(const uint8_t* data, size_t size) {
    std::u16string out;
    out.reserve(size / 2);
    for (size_t i = 0; i + 1 < size; i += 2) {
        const uint16_t lo = data[i];
        const uint16_t hi = data[i + 1];
        out.push_back(static_cast<char16_t>(lo | (hi << 8)));
    }
    return out;
}

// ---- orders ------------------------------------------------------------------

std::vector<uint8_t> RailHandshake::build() const {
    ByteWriter w;
    w.u32le(build_number);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailHandshake::parse(const uint8_t* data, size_t size, RailHandshake& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 4) return Status::InvalidLength;
    if (!r.u32le(out.build_number)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> RailHandshakeEx::build() const {
    ByteWriter w;
    w.u32le(build_number);
    w.u32le(flags);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailHandshakeEx::parse(const uint8_t* data, size_t size,
                              RailHandshakeEx& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 8) return Status::InvalidLength;
    if (!r.u32le(out.build_number)) return Status::NeedMoreData;
    if (!r.u32le(out.flags)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> RailClientStatus::build() const {
    ByteWriter w;
    w.u32le(flags);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailClientStatus::parse(const uint8_t* data, size_t size,
                               RailClientStatus& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 4) return Status::InvalidLength;
    if (!r.u32le(out.flags)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> RailSyscommand::build() const {
    ByteWriter w;
    w.u32le(window_id);
    w.u16le(command);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailSyscommand::parse(const uint8_t* data, size_t size,
                             RailSyscommand& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 6) return Status::InvalidLength;
    if (!r.u32le(out.window_id)) return Status::NeedMoreData;
    if (!r.u16le(out.command)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> RailSysmenu::build() const {
    ByteWriter w;
    w.u32le(window_id);
    WriteI16(w, left);
    WriteI16(w, top);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailSysmenu::parse(const uint8_t* data, size_t size, RailSysmenu& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 8) return Status::InvalidLength;
    bool ok = true;
    if (!r.u32le(out.window_id)) return Status::NeedMoreData;
    out.left = ReadI16(r, ok);
    out.top = ReadI16(r, ok);
    return ok ? Status::Ok : Status::NeedMoreData;
}

std::vector<uint8_t> RailWindowMove::build() const {
    ByteWriter w;
    w.u32le(window_id);
    WriteI16(w, left);
    WriteI16(w, top);
    WriteI16(w, right);
    WriteI16(w, bottom);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailWindowMove::parse(const uint8_t* data, size_t size,
                             RailWindowMove& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 12) return Status::InvalidLength;
    bool ok = true;
    if (!r.u32le(out.window_id)) return Status::NeedMoreData;
    out.left = ReadI16(r, ok);
    out.top = ReadI16(r, ok);
    out.right = ReadI16(r, ok);
    out.bottom = ReadI16(r, ok);
    return ok ? Status::Ok : Status::NeedMoreData;
}

std::vector<uint8_t> RailMinMaxInfo::build() const {
    ByteWriter w;
    w.u32le(window_id);
    WriteI16(w, max_width);
    WriteI16(w, max_height);
    WriteI16(w, max_pos_x);
    WriteI16(w, max_pos_y);
    WriteI16(w, min_track_width);
    WriteI16(w, min_track_height);
    WriteI16(w, max_track_width);
    WriteI16(w, max_track_height);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailMinMaxInfo::parse(const uint8_t* data, size_t size,
                             RailMinMaxInfo& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 20) return Status::InvalidLength;
    bool ok = true;
    if (!r.u32le(out.window_id)) return Status::NeedMoreData;
    out.max_width = ReadI16(r, ok);
    out.max_height = ReadI16(r, ok);
    out.max_pos_x = ReadI16(r, ok);
    out.max_pos_y = ReadI16(r, ok);
    out.min_track_width = ReadI16(r, ok);
    out.min_track_height = ReadI16(r, ok);
    out.max_track_width = ReadI16(r, ok);
    out.max_track_height = ReadI16(r, ok);
    return ok ? Status::Ok : Status::NeedMoreData;
}

std::vector<uint8_t> RailLocalMoveSize::build() const {
    ByteWriter w;
    w.u32le(window_id);
    w.u16le(is_move_size_start ? 1 : 0);
    w.u16le(move_size_type);
    WriteI16(w, pos_x);
    WriteI16(w, pos_y);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailLocalMoveSize::parse(const uint8_t* data, size_t size,
                                RailLocalMoveSize& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 12) return Status::InvalidLength;
    bool ok = true;
    uint16_t flag = 0;
    if (!r.u32le(out.window_id)) return Status::NeedMoreData;
    if (!r.u16le(flag)) return Status::NeedMoreData;
    out.is_move_size_start = flag != 0;
    if (!r.u16le(out.move_size_type)) return Status::NeedMoreData;
    out.pos_x = ReadI16(r, ok);
    out.pos_y = ReadI16(r, ok);
    return ok ? Status::Ok : Status::NeedMoreData;
}

std::vector<uint8_t> RailTaskbarInfo::build() const {
    ByteWriter w;
    w.u32le(taskbar_message);
    w.u32le(window_id_tab);
    w.u32le(body);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailTaskbarInfo::parse(const uint8_t* data, size_t size,
                              RailTaskbarInfo& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 12) return Status::InvalidLength;
    if (!r.u32le(out.taskbar_message)) return Status::NeedMoreData;
    if (!r.u32le(out.window_id_tab)) return Status::NeedMoreData;
    if (!r.u32le(out.body)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> RailLangbarInfo::build() const {
    ByteWriter w;
    w.u32le(language_bar_status);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailLangbarInfo::parse(const uint8_t* data, size_t size,
                              RailLangbarInfo& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 4) return Status::InvalidLength;
    if (!r.u32le(out.language_bar_status)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> RailGetAppIdReq::build() const {
    ByteWriter w;
    w.u32le(window_id);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailGetAppIdReq::parse(const uint8_t* data, size_t size,
                              RailGetAppIdReq& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != 4) return Status::InvalidLength;
    if (!r.u32le(out.window_id)) return Status::NeedMoreData;
    return Status::Ok;
}

// Reads a null-terminated UTF-16LE string from a fixed-size field. Returns false
// when the field has no null terminator within `size` bytes (a completely filled
// fixed field), which the spec does not allow.
bool ReadFixedUtf16Z(const uint8_t* data, size_t size, std::u16string& out) {
    out.clear();
    for (size_t i = 0; i + 1 < size; i += 2) {
        const uint16_t ch = static_cast<uint16_t>(data[i]) |
                             (static_cast<uint16_t>(data[i + 1]) << 8);
        if (ch == 0) return true;
        out.push_back(static_cast<char16_t>(ch));
    }
    return false;
}

std::vector<uint8_t> RailGetAppIdRespEx::build(std::string& why) const {
    why.clear();
    const std::vector<uint8_t> app = RailUtf16ToLeBytes(application_id);
    const std::vector<uint8_t> image = RailUtf16ToLeBytes(process_image_name);
    if (app.size() > kStringFieldSize) {
        why = "ApplicationId exceeds 520 bytes";
        return {};
    }
    if (image.size() > kStringFieldSize) {
        why = "ProcessImageName exceeds 520 bytes";
        return {};
    }
    // A fixed 520-byte field that is completely filled leaves no room for the
    // null terminator; FreeRDP rejects that, so do we.
    if (application_id.size() > kMaxStringUnits) {
        why = "ApplicationId needs a null terminator within 520 bytes";
        return {};
    }
    if (process_image_name.size() > kMaxStringUnits) {
        why = "ProcessImageName needs a null terminator within 520 bytes";
        return {};
    }

    ByteWriter w;
    w.u32le(window_id);
    w.bytes(app.data(), app.size());
    for (size_t i = app.size(); i < kStringFieldSize; ++i) w.u8(0);
    w.u32le(process_id);
    w.bytes(image.data(), image.size());
    for (size_t i = image.size(); i < kStringFieldSize; ++i) w.u8(0);
    return BuildRailPdu(kOrderType, w.take());
}

Status RailGetAppIdRespEx::parse(const uint8_t* data, size_t size,
                                 RailGetAppIdRespEx& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (body_size != kBodySize) return Status::InvalidLength;
    if (!r.u32le(out.window_id)) return Status::NeedMoreData;
    if (!ReadFixedUtf16Z(r.cursor(), kStringFieldSize, out.application_id)) {
        return Status::InvalidField;
    }
    if (!r.skip(kStringFieldSize)) return Status::NeedMoreData;
    if (!r.u32le(out.process_id)) return Status::NeedMoreData;
    if (!ReadFixedUtf16Z(r.cursor(), kStringFieldSize, out.process_image_name)) {
        return Status::InvalidField;
    }
    return Status::Ok;
}

std::vector<uint8_t> RailSysparamOrder::build() const {
    ByteWriter w;
    w.u32le(param);
    switch (param) {
        case kSpiSetDragFullWindows:
        case kSpiSetKeyboardCues:
        case kSpiSetKeyboardPref:
        case kSpiSetMouseButtonSwap:
        case kSpiSetScreenSaveActive:
        case kSpiSetScreenSaveSecure:
            w.u8(bool_value ? 1 : 0);
            break;
        case kSpiSetWorkArea:
        case kSpiDisplayChange:
        case kSpiTaskbarPos:
            WriteI16(w, rect_left);
            WriteI16(w, rect_top);
            WriteI16(w, rect_right);
            WriteI16(w, rect_bottom);
            break;
        case kSpiSetCaretWidth:
        case kSpiSetStickyKeys:
        case kSpiSetToggleKeys:
            w.u32le(uint_value);
            break;
        case kSpiSetFilterKeys:
            w.u32le(uint_value);
            w.u32le(0);
            w.u32le(0);
            w.u32le(0);
            w.u32le(0);
            break;
        case kSpiSetHighContrast: {
            const std::vector<uint8_t> scheme = RailUtf16ToLeBytes(color_scheme);
            w.u32le(high_contrast_flags);
            // ColorSchemeLength counts the 2-byte cbString prefix plus the
            // string bytes ([MS-RDPERP] 2.2.2.4.2).
            w.u32le(static_cast<uint32_t>(2 + scheme.size()));
            w.u16le(static_cast<uint16_t>(scheme.size()));
            w.bytes(scheme.data(), scheme.size());
            break;
        }
        default:
            break;
    }
    return BuildRailPdu(kOrderType, w.take());
}

Status RailSysparamOrder::parse(const uint8_t* data, size_t size,
                                RailSysparamOrder& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;
    if (!r.u32le(out.param)) return Status::NeedMoreData;

    bool ok = true;
    switch (out.param) {
        case kSpiSetDragFullWindows:
        case kSpiSetKeyboardCues:
        case kSpiSetKeyboardPref:
        case kSpiSetMouseButtonSwap:
        case kSpiSetScreenSaveActive:
        case kSpiSetScreenSaveSecure: {
            uint8_t flag = 0;
            if (!r.u8(flag)) return Status::NeedMoreData;
            out.bool_value = flag != 0;
            break;
        }
        case kSpiSetWorkArea:
        case kSpiDisplayChange:
        case kSpiTaskbarPos:
            out.rect_left = ReadI16(r, ok);
            out.rect_top = ReadI16(r, ok);
            out.rect_right = ReadI16(r, ok);
            out.rect_bottom = ReadI16(r, ok);
            return ok ? Status::Ok : Status::NeedMoreData;
        case kSpiSetCaretWidth:
        case kSpiSetStickyKeys:
        case kSpiSetToggleKeys:
            if (!r.u32le(out.uint_value)) return Status::NeedMoreData;
            break;
        case kSpiSetFilterKeys:
            for (int i = 0; i < 5; ++i) {
                uint32_t v = 0;
                if (!r.u32le(v)) return Status::NeedMoreData;
                if (i == 0) out.uint_value = v;
            }
            break;
        case kSpiSetHighContrast: {
            if (!r.u32le(out.high_contrast_flags)) return Status::NeedMoreData;
            uint32_t scheme_len = 0;
            if (!r.u32le(scheme_len)) return Status::NeedMoreData;
            if (scheme_len < 2) return Status::InvalidLength;
            if (static_cast<size_t>(scheme_len) > r.remaining()) {
                return Status::NeedMoreData;
            }
            uint16_t cb = 0;
            if (!r.u16le(cb)) return Status::NeedMoreData;
            const size_t str_len = static_cast<size_t>(scheme_len) - 2;
            if (static_cast<size_t>(cb) != str_len) return Status::InvalidLength;
            out.color_scheme = RailLeBytesToUtf16(r.cursor(), str_len);
            break;
        }
        default:
            return Status::InvalidField;
    }
    return Status::Ok;
}

std::vector<uint8_t> RailClientExecute::build(std::string& why) const {
    why.clear();
    const std::vector<uint8_t> exe = RailUtf16ToLeBytes(exe_or_file);
    const std::vector<uint8_t> work = RailUtf16ToLeBytes(working_dir);
    const std::vector<uint8_t> args = RailUtf16ToLeBytes(arguments);

    if (exe.empty()) {
        why = "ExeOrFile is empty (the spec requires it to be present)";
        return {};
    }
    if (exe.size() > kMaxExeOrFile) {
        why = "ExeOrFile exceeds 520 bytes";
        return {};
    }
    if (work.size() > kMaxWorkingDir) {
        why = "WorkingDir exceeds 520 bytes";
        return {};
    }
    if (args.size() > kMaxArguments) {
        why = "Arguments exceeds 16000 bytes";
        return {};
    }

    ByteWriter w;
    w.u16le(flags);
    w.u16le(static_cast<uint16_t>(exe.size()));
    w.u16le(static_cast<uint16_t>(work.size()));
    w.u16le(static_cast<uint16_t>(args.size()));
    w.bytes(exe.data(), exe.size());
    w.bytes(work.data(), work.size());
    w.bytes(args.data(), args.size());
    return BuildRailPdu(kOrderType, w.take());
}

Status RailClientExecute::parse(const uint8_t* data, size_t size,
                                RailClientExecute& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;

    if (!r.u16le(out.flags)) return Status::NeedMoreData;
    uint16_t exe_len = 0;
    uint16_t work_len = 0;
    uint16_t args_len = 0;
    if (!r.u16le(exe_len)) return Status::NeedMoreData;
    if (!r.u16le(work_len)) return Status::NeedMoreData;
    if (!r.u16le(args_len)) return Status::NeedMoreData;

    const size_t total = static_cast<size_t>(exe_len) + work_len + args_len;
    if (total > r.remaining()) return Status::NeedMoreData;

    const uint8_t* p = r.cursor();
    out.exe_or_file = RailLeBytesToUtf16(p, exe_len);
    out.working_dir = RailLeBytesToUtf16(p + exe_len, work_len);
    out.arguments = RailLeBytesToUtf16(p + exe_len + work_len, args_len);
    return Status::Ok;
}

std::vector<uint8_t> RailExecuteResult::build() const {
    ByteWriter w;
    w.u16le(flags);
    w.u16le(exec_result);
    w.u32le(raw_result);
    const std::vector<uint8_t> exe = RailUtf16ToLeBytes(exe_or_file);
    w.u16le(static_cast<uint16_t>(exe.size()));
    w.bytes(exe.data(), exe.size());
    return BuildRailPdu(kOrderType, w.take());
}

Status RailExecuteResult::parse(const uint8_t* data, size_t size,
                                RailExecuteResult& out) {
    ByteReader r(data, size);
    size_t body_size = 0;
    const Status st = ReadRailPduHeader(r, kOrderType, body_size);
    if (st != Status::Ok) return st;

    if (!r.u16le(out.flags)) return Status::NeedMoreData;
    if (!r.u16le(out.exec_result)) return Status::NeedMoreData;
    if (!r.u32le(out.raw_result)) return Status::NeedMoreData;
    uint16_t len = 0;
    if (!r.u16le(len)) return Status::NeedMoreData;
    if (static_cast<size_t>(len) > r.remaining()) return Status::NeedMoreData;
    out.exe_or_file = RailLeBytesToUtf16(r.cursor(), len);
    return Status::Ok;
}

// ---- virtual channel ---------------------------------------------------------

void RailChannel::OnChannelData(const uint8_t* data, size_t size) {
    if (data == nullptr || size < ChannelPduHeader::kSize) return;

    ChannelPduHeader header;
    if (ChannelPduHeader::parse(data, size, header) != Status::Ok) return;

    bool complete = false;
    std::vector<uint8_t> message;
    const Status st = reassembler_.Feed(header, data + ChannelPduHeader::kSize,
                                        size - ChannelPduHeader::kSize, complete,
                                        message);
    if (st != Status::Ok) {
        reassembler_.Reset();
        ++incomplete_message_count_;
        return;
    }
    if (!complete) {
        ++incomplete_message_count_;
        return;
    }
    OnMessage(message);
}

void RailChannel::OnMessage(const std::vector<uint8_t>& message) {
    size_t offset = 0;
    while (offset < message.size()) {
        RailPdu pdu;
        size_t consumed = 0;
        const Status st =
            RailPdu::parse(message.data() + offset, message.size() - offset, pdu,
                           consumed);
        if (st != Status::Ok) return;
        offset += consumed;
        ++pdu_count_;

        switch (pdu.header.order_type) {
            case RailHandshake::kOrderType: ++handshake_count_; break;
            case RailHandshakeEx::kOrderType: ++handshake_ex_count_; break;
            case RailSyscommand::kOrderType: ++syscommand_count_; break;
            case RailSysmenu::kOrderType: ++sysmenu_count_; break;
            case RailWindowMove::kOrderType: ++window_move_count_; break;
            case RailTaskbarInfo::kOrderType: ++taskbar_count_; break;
            case RailLangbarInfo::kOrderType: ++langbar_count_; break;
            case RailClientExecute::kOrderType: ++exec_count_; break;
            case RailExecuteResult::kOrderType: ++exec_result_count_; break;
            case RailGetAppIdRespEx::kOrderType: ++get_app_id_resp_ex_count_; break;
            default: break;
        }

        if (handler_) handler_(pdu);
    }
}

}  // namespace rtsc::proto
