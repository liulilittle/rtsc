// [MS-RDPESC] payload codec. See include/rtsc/proto/smartcard.h for the
// protocol rationale and the references the layout was taken from.
//
// Layout summary (verified against FreeRDP libfreerdp/utils/smartcard_pack.c
// and libfreerdp/utils/smartcard_call.c, which is what Windows interoperates
// with, and IronRDP crates/ironrdp-rdpdr/src/pdu/esc):
//
//   InputBuffer  = CommonTypeHeader(8) + PrivateTypeHeader(8) + <call body>
//   OutputBuffer = CommonTypeHeader(8) + PrivateTypeHeader(8) + <return body>
//
// Every return body starts with the 32-bit Result, which is the ReturnCode
// field of the [MS-RDPESC] 2.2.3.x structure; FreeRDP writes it as a
// placeholder before dispatching and rewrites it afterwards.

#include "rtsc/proto/smartcard.h"

#include <cstring>

namespace rtsc::proto {

namespace {

// [MS-RPCE] 2.2.6.1 common type header constants.
constexpr uint8_t kNdrVersion = 1;
constexpr uint8_t kNdrLittleEndian = 0x10;
constexpr uint16_t kNdrCommonHeaderLength = 8;
constexpr uint32_t kNdrCommonFiller = 0xCCCCCCCCu;
// [unique] pointer value, incremented per non-NULL pointer (FreeRDP
// smartcard_ndr_pointer_write / IronRDP ndr::encode_ptr).
constexpr uint32_t kNdrPtrBase = 0x00020000;

size_t Pad4(size_t n) { return (n + 3u) & ~size_t{3}; }
size_t Pad8(size_t n) { return (n + 7u) & ~size_t{7}; }

uint32_t ReadLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

class Cursor {
 public:
    Cursor(const uint8_t* data, size_t size) : r_(data, size) {}

    size_t remaining() const { return r_.remaining(); }

    Status U32(uint32_t& v) {
        return r_.u32le(v) ? Status::Ok : Status::NeedMoreData;
    }

    Status FixedBytes(std::vector<uint8_t>& out, size_t n) {
        if (r_.remaining() < n) return Status::NeedMoreData;
        out.resize(n);
        if (n > 0 && !r_.bytes(out.data(), n)) return Status::NeedMoreData;
        return Status::Ok;
    }

    // Consumes a [unique] pointer slot; NULL does not advance the pointer
    // index (matches FreeRDP smartcard_ndr_pointer_read and IronRDP).
    Status Pointer(bool& is_null) {
        uint32_t v = 0;
        const Status s = U32(v);
        if (s != Status::Ok) return s;
        if (v == 0) {
            is_null = true;
            return Status::Ok;
        }
        if (v != kNdrPtrBase + index_ * 4u) return Status::InvalidField;
        ++index_;
        is_null = false;
        return Status::Ok;
    }

    // [size_is] referent: Length(4) + bytes, padded to a 4-byte boundary.
    Status SimpleReferent(size_t max_bytes, std::vector<uint8_t>& out) {
        uint32_t len = 0;
        Status s = U32(len);
        if (s != Status::Ok) return s;
        if (len > max_bytes) return Status::InvalidField;
        s = FixedBytes(out, len);
        if (s != Status::Ok) return s;
        return Skip(Pad4(len) - len);
    }

    // [string] referent: Length(4) + Offset(4) + ActualCount(4) + chars,
    // padded to 4. Length MUST equal Offset + ActualCount.
    Status FullStringReferent(size_t max_bytes, std::string& out) {
        uint32_t length = 0;
        uint32_t offset = 0;
        uint32_t actual = 0;
        Status s = U32(length);
        if (s != Status::Ok) return s;
        s = U32(offset);
        if (s != Status::Ok) return s;
        s = U32(actual);
        if (s != Status::Ok) return s;
        if (static_cast<uint64_t>(offset) + actual != length) {
            return Status::InvalidField;
        }
        if (length == 0 || length > max_bytes) return Status::InvalidField;
        std::vector<uint8_t> raw;
        s = FixedBytes(raw, length);
        if (s != Status::Ok) return s;
        s = Skip(Pad4(length) - length);
        if (s != Status::Ok) return s;
        // [string] fields are NUL terminated; a missing terminator would make
        // the caller hand a non-terminated buffer to WinSCard.
        if (raw.back() != 0) return Status::InvalidField;
        out.assign(reinterpret_cast<const char*>(raw.data()), raw.size() - 1);
        return Status::Ok;
    }

    Status Skip(size_t n) {
        if (r_.remaining() < n) return Status::NeedMoreData;
        r_.skip(n);
        return Status::Ok;
    }

 private:
    ByteReader r_;
    uint32_t index_ = 0;
};

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

class Encoder {
 public:
    void U32(uint32_t v) { inline_.u32le(v); }

    void InlineBytes(const std::vector<uint8_t>& bytes) {
        if (!bytes.empty()) inline_.bytes(bytes.data(), bytes.size());
    }

    // Emits cbX(4) + NDR pointer(4). A zero count means a NULL pointer, which
    // is what FreeRDP writes for an absent/empty variable field.
    void CountedPointer(uint32_t count, bool present) {
        inline_.u32le(present ? count : 0);
        ValuePointer(present);
    }

    void ValuePointer(bool present) {
        if (!present) {
            inline_.u32le(0);
            return;
        }
        inline_.u32le(kNdrPtrBase + index_ * 4u);
        ++index_;
    }

    // Deferred [size_is] referent: Length(4) + bytes, padded to 4.
    void SimpleReferent(const std::vector<uint8_t>& bytes) {
        value_.u32le(static_cast<uint32_t>(bytes.size()));
        if (!bytes.empty()) value_.bytes(bytes.data(), bytes.size());
        Zeros(Pad4(bytes.size()) - bytes.size());
    }

    // Deferred referent whose Length is an element count.
    void CountedReferent(uint32_t count, const std::vector<uint8_t>& bytes) {
        value_.u32le(count);
        if (!bytes.empty()) value_.bytes(bytes.data(), bytes.size());
        Zeros(Pad4(bytes.size()) - bytes.size());
    }

    std::vector<uint8_t> Finish() const {
        const auto& head = inline_.data();
        const auto& tail = value_.data();
        std::vector<uint8_t> body;
        body.reserve(head.size() + tail.size());
        body.insert(body.end(), head.begin(), head.end());
        body.insert(body.end(), tail.begin(), tail.end());
        const size_t object_length = Pad8(body.size());

        std::vector<uint8_t> out;
        out.reserve(ScardNdrHeader::kSize + object_length);
        out.push_back(kNdrVersion);
        out.push_back(kNdrLittleEndian);
        out.push_back(static_cast<uint8_t>(kNdrCommonHeaderLength & 0xFF));
        out.push_back(static_cast<uint8_t>((kNdrCommonHeaderLength >> 8) & 0xFF));
        for (int i = 0; i < 4; ++i) {
            out.push_back(static_cast<uint8_t>((kNdrCommonFiller >> (8 * i)) & 0xFF));
        }
        for (int i = 0; i < 4; ++i) {
            out.push_back(static_cast<uint8_t>((object_length >> (8 * i)) & 0xFF));
        }
        out.insert(out.end(), 4, 0);  // private header filler
        out.insert(out.end(), body.begin(), body.end());
        out.insert(out.end(), object_length - body.size(), 0);
        return out;
    }

 private:
    void Zeros(size_t n) {
        for (size_t i = 0; i < n; ++i) value_.u8(0);
    }

    ByteWriter inline_;
    ByteWriter value_;
    uint32_t index_ = 0;
};

// ---------------------------------------------------------------------------
// Shared inline/value helpers
// ---------------------------------------------------------------------------

Status ReadContextInline(Cursor& c, ScardContext& out, bool& present) {
    uint32_t count = 0;
    Status s = c.U32(count);
    if (s != Status::Ok) return s;
    bool is_null = false;
    s = c.Pointer(is_null);
    if (s != Status::Ok) return s;
    if (count > kScardMaxContextBytes) return Status::InvalidField;
    if (count == 0 && !is_null) return Status::InvalidField;
    if (count != 0 && is_null) return Status::InvalidField;
    out.bytes.clear();
    present = !is_null;
    return Status::Ok;
}

Status ReadContextValue(Cursor& c, bool present, ScardContext& out) {
    if (!present) return Status::Ok;
    std::vector<uint8_t> raw;
    const Status s = c.SimpleReferent(kScardMaxContextBytes, raw);
    if (s != Status::Ok) return s;
    if (raw.empty()) return Status::InvalidField;
    out.bytes = std::move(raw);
    return Status::Ok;
}

Status ReadHandleInline(Cursor& c, ScardHandle& out, bool& ctx_present,
                        bool& handle_present) {
    Status s = ReadContextInline(c, out.context, ctx_present);
    if (s != Status::Ok) return s;
    uint32_t count = 0;
    s = c.U32(count);
    if (s != Status::Ok) return s;
    bool is_null = false;
    s = c.Pointer(is_null);
    if (s != Status::Ok) return s;
    if (count > kScardMaxContextBytes) return Status::InvalidField;
    if (count == 0 && !is_null) return Status::InvalidField;
    if (count != 0 && is_null) return Status::InvalidField;
    out.bytes.clear();
    handle_present = !is_null;
    return Status::Ok;
}

Status ReadHandleValue(Cursor& c, bool present, ScardHandle& out) {
    if (!present) return Status::Ok;
    std::vector<uint8_t> raw;
    const Status s = c.SimpleReferent(kScardMaxContextBytes, raw);
    if (s != Status::Ok) return s;
    if (raw.empty()) return Status::InvalidField;
    out.bytes = std::move(raw);
    return Status::Ok;
}

Status ReadIoRequestInline(Cursor& c, ScardIoRequest& out, bool& present) {
    Status s = c.U32(out.protocol);
    if (s != Status::Ok) return s;
    uint32_t extra = 0;
    s = c.U32(extra);
    if (s != Status::Ok) return s;
    bool is_null = false;
    s = c.Pointer(is_null);
    if (s != Status::Ok) return s;
    if (extra > kScardMaxExtraBytes) return Status::InvalidField;
    if (extra == 0 && !is_null) return Status::InvalidField;
    if (extra != 0 && is_null) return Status::InvalidField;
    out.extra.clear();
    present = !is_null;
    return Status::Ok;
}

Status ReadIoRequestValue(Cursor& c, bool present, ScardIoRequest& out) {
    if (!present) return Status::Ok;
    std::vector<uint8_t> raw;
    const Status s = c.SimpleReferent(kScardMaxExtraBytes, raw);
    if (s != Status::Ok) return s;
    if (raw.empty()) return Status::InvalidField;
    out.extra = std::move(raw);
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Call parsers (one per implemented SCARD_IOCTL)
// ---------------------------------------------------------------------------

Status ParseEstablishContext(Cursor& c, ScardCall& out) {
    return c.U32(out.scope);
}

Status ParseContextCall(Cursor& c, ScardCall& out) {
    bool present = false;
    Status s = ReadContextInline(c, out.context, present);
    if (s != Status::Ok) return s;
    return ReadContextValue(c, present, out.context);
}

Status ParseListReaderGroups(Cursor& c, ScardCall& out) {
    bool present = false;
    Status s = ReadContextInline(c, out.context, present);
    if (s != Status::Ok) return s;
    s = c.U32(out.groups_is_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.groups_cch);
    if (s != Status::Ok) return s;
    return ReadContextValue(c, present, out.context);
}

Status ParseListReaders(Cursor& c, ScardCall& out) {
    bool present = false;
    Status s = ReadContextInline(c, out.context, present);
    if (s != Status::Ok) return s;
    uint32_t bytes = 0;
    s = c.U32(bytes);
    if (s != Status::Ok) return s;
    if (bytes > kScardMaxMultiStringBytes) return Status::InvalidField;
    bool groups_null = false;
    s = c.Pointer(groups_null);
    if (s != Status::Ok) return s;
    if (!groups_null && bytes == 0) return Status::InvalidField;
    if (groups_null && bytes != 0) return Status::InvalidField;
    s = c.U32(out.readers_is_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.readers_cch);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, present, out.context);
    if (s != Status::Ok) return s;
    if (!groups_null) {
        std::vector<uint8_t> raw;
        s = c.SimpleReferent(kScardMaxMultiStringBytes, raw);
        if (s != Status::Ok) return s;
        if (raw.size() != bytes) return Status::InvalidField;
        if (raw.back() != 0) return Status::InvalidField;
        out.groups_msz = std::move(raw);
    }
    return Status::Ok;
}

Status ParseGetStatusChange(Cursor& c, ScardCall& out) {
    bool present = false;
    Status s = ReadContextInline(c, out.context, present);
    if (s != Status::Ok) return s;
    s = c.U32(out.timeout);
    if (s != Status::Ok) return s;
    uint32_t readers = 0;
    s = c.U32(readers);
    if (s != Status::Ok) return s;
    if (readers > kScardMaxReaders) return Status::InvalidField;
    bool states_null = false;
    s = c.Pointer(states_null);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, present, out.context);
    if (s != Status::Ok) return s;
    if (states_null) {
        // A conformant array of zero elements is written as a NULL pointer.
        if (readers != 0) return Status::InvalidField;
        return Status::Ok;
    }
    uint32_t max_count = 0;
    s = c.U32(max_count);
    if (s != Status::Ok) return s;
    if (max_count != readers) return Status::InvalidField;
    std::vector<ScardReaderStateA> states(readers);
    std::vector<bool> named(readers, false);
    for (uint32_t i = 0; i < readers; ++i) {
        bool is_null = false;
        s = c.Pointer(is_null);
        if (s != Status::Ok) return s;
        named[i] = !is_null;
        s = c.U32(states[i].current_state);
        if (s != Status::Ok) return s;
        s = c.U32(states[i].event_state);
        if (s != Status::Ok) return s;
        uint32_t cb_atr = 0;
        s = c.U32(cb_atr);
        if (s != Status::Ok) return s;
        if (cb_atr > kScardMaxAtr) return Status::InvalidField;
        std::vector<uint8_t> rgb;
        s = c.FixedBytes(rgb, kScardMaxAtr);  // fixed rgbAtr[36]
        if (s != Status::Ok) return s;
        rgb.resize(cb_atr);
        states[i].atr = std::move(rgb);
    }
    for (uint32_t i = 0; i < readers; ++i) {
        if (!named[i]) continue;
        s = c.FullStringReferent(kScardMaxMultiStringBytes, states[i].reader);
        if (s != Status::Ok) return s;
    }
    out.reader_states = std::move(states);
    return Status::Ok;
}

Status ParseConnect(Cursor& c, ScardCall& out) {
    bool reader_null = false;
    Status s = c.Pointer(reader_null);
    if (s != Status::Ok) return s;
    if (reader_null) return Status::InvalidField;  // szReader is required
    bool present = false;
    s = ReadContextInline(c, out.context, present);
    if (s != Status::Ok) return s;
    s = c.U32(out.share_mode);
    if (s != Status::Ok) return s;
    s = c.U32(out.preferred_protocols);
    if (s != Status::Ok) return s;
    s = c.FullStringReferent(kScardMaxMultiStringBytes, out.reader);
    if (s != Status::Ok) return s;
    return ReadContextValue(c, present, out.context);
}

Status ParseHCardAndDisposition(Cursor& c, ScardCall& out) {
    bool ctx_present = false;
    bool handle_present = false;
    Status s = ReadHandleInline(c, out.handle, ctx_present, handle_present);
    if (s != Status::Ok) return s;
    s = c.U32(out.disposition);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, ctx_present, out.handle.context);
    if (s != Status::Ok) return s;
    return ReadHandleValue(c, handle_present, out.handle);
}

Status ParseTransmit(Cursor& c, ScardCall& out) {
    bool ctx_present = false;
    bool handle_present = false;
    Status s = ReadHandleInline(c, out.handle, ctx_present, handle_present);
    if (s != Status::Ok) return s;
    bool send_extra_present = false;
    s = ReadIoRequestInline(c, out.send_pci, send_extra_present);
    if (s != Status::Ok) return s;
    uint32_t send_length = 0;
    s = c.U32(send_length);
    if (s != Status::Ok) return s;
    if (send_length > kScardMaxTransmitBytes) return Status::InvalidField;
    bool send_null = false;
    s = c.Pointer(send_null);
    if (s != Status::Ok) return s;
    if (!send_null && send_length == 0) return Status::InvalidField;
    if (send_null && send_length != 0) return Status::InvalidField;
    bool recv_pci_null = false;
    s = c.Pointer(recv_pci_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.recv_buffer_is_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.recv_length);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, ctx_present, out.handle.context);
    if (s != Status::Ok) return s;
    s = ReadHandleValue(c, handle_present, out.handle);
    if (s != Status::Ok) return s;
    if (send_extra_present) {
        s = ReadIoRequestValue(c, send_extra_present, out.send_pci);
        if (s != Status::Ok) return s;
    }
    if (!send_null) {
        std::vector<uint8_t> raw;
        s = c.SimpleReferent(kScardMaxTransmitBytes, raw);
        if (s != Status::Ok) return s;
        if (raw.size() != send_length) return Status::InvalidField;
        out.send_buffer = std::move(raw);
    }
    if (!recv_pci_null) {
        ScardIoRequest recv;
        bool recv_extra_present = false;
        s = ReadIoRequestInline(c, recv, recv_extra_present);
        if (s != Status::Ok) return s;
        if (recv_extra_present) {
            s = ReadIoRequestValue(c, recv_extra_present, recv);
            if (s != Status::Ok) return s;
        }
        out.recv_pci = std::move(recv);
    }
    return Status::Ok;
}

Status ParseControl(Cursor& c, ScardCall& out) {
    bool ctx_present = false;
    bool handle_present = false;
    Status s = ReadHandleInline(c, out.handle, ctx_present, handle_present);
    if (s != Status::Ok) return s;
    s = c.U32(out.control_code);
    if (s != Status::Ok) return s;
    uint32_t in_size = 0;
    s = c.U32(in_size);
    if (s != Status::Ok) return s;
    if (in_size > kScardMaxTransmitBytes) return Status::InvalidField;
    bool in_null = false;
    s = c.Pointer(in_null);
    if (s != Status::Ok) return s;
    if (!in_null && in_size == 0) return Status::InvalidField;
    if (in_null && in_size != 0) return Status::InvalidField;
    s = c.U32(out.out_buffer_is_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.out_buffer_size);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, ctx_present, out.handle.context);
    if (s != Status::Ok) return s;
    s = ReadHandleValue(c, handle_present, out.handle);
    if (s != Status::Ok) return s;
    if (!in_null) {
        std::vector<uint8_t> raw;
        s = c.SimpleReferent(kScardMaxTransmitBytes, raw);
        if (s != Status::Ok) return s;
        if (raw.size() != in_size) return Status::InvalidField;
        out.in_buffer = std::move(raw);
    }
    return Status::Ok;
}

Status ParseStatus(Cursor& c, ScardCall& out) {
    bool ctx_present = false;
    bool handle_present = false;
    Status s = ReadHandleInline(c, out.handle, ctx_present, handle_present);
    if (s != Status::Ok) return s;
    s = c.U32(out.reader_names_is_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.reader_names_cch);
    if (s != Status::Ok) return s;
    s = c.U32(out.atr_length);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, ctx_present, out.handle.context);
    if (s != Status::Ok) return s;
    return ReadHandleValue(c, handle_present, out.handle);
}

// ---------------------------------------------------------------------------
// Return encoders
// ---------------------------------------------------------------------------

void WriteContext(Encoder& e, const ScardContext& ctx) {
    e.CountedPointer(static_cast<uint32_t>(ctx.bytes.size()), !ctx.bytes.empty());
}

void WriteContextValue(Encoder& e, const ScardContext& ctx) {
    if (ctx.bytes.empty()) return;
    e.SimpleReferent(ctx.bytes);
}

void WriteHandle(Encoder& e, const ScardHandle& handle) {
    WriteContext(e, handle.context);
    e.CountedPointer(static_cast<uint32_t>(handle.bytes.size()),
                     !handle.bytes.empty());
}

void WriteHandleValue(Encoder& e, const ScardHandle& handle) {
    WriteContextValue(e, handle.context);
    if (!handle.bytes.empty()) e.SimpleReferent(handle.bytes);
}

// SCardIO_Request referent ([MS-RDPESC] 2.2.1.8): dwProtocol + cbExtraBytes +
// pbExtraBytes pointer inline, with the extra bytes deferred after it.
void WriteIoRequestInlineValue(Encoder& e, const ScardIoRequest& pci) {
    e.U32(pci.protocol);
    e.U32(static_cast<uint32_t>(pci.extra.size()));
    e.ValuePointer(!pci.extra.empty());
    if (!pci.extra.empty()) e.SimpleReferent(pci.extra);
}

bool ContextFits(const ScardContext& ctx) {
    return ctx.bytes.size() <= kScardMaxContextBytes;
}

bool HandleFits(const ScardHandle& handle) {
    return ContextFits(handle.context) &&
           handle.bytes.size() <= kScardMaxContextBytes;
}

// [MS-RDPESC] 2.2.3.4: cBytes is range(0,65536); the multistring includes its
// final NUL. A NULL msz is encoded as a zero count and a NULL pointer.
bool MultiStringFits(const std::optional<std::vector<uint8_t>>& value) {
    if (!value.has_value()) return true;
    return !value->empty() && value->size() <= kScardMaxMultiStringBytes;
}

}  // namespace

Status ScardNdrHeader::parse(const uint8_t* data, size_t size,
                             ScardNdrHeader& out, size_t& body_offset,
                             size_t& body_size) {
    body_offset = 0;
    body_size = 0;
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    if (data[0] != kNdrVersion) return Status::InvalidVersion;
    if (data[1] != kNdrLittleEndian) return Status::InvalidField;
    const uint16_t common_length =
        static_cast<uint16_t>(data[2] | (static_cast<uint16_t>(data[3]) << 8));
    if (common_length != kNdrCommonHeaderLength) return Status::InvalidLength;
    if (ReadLe32(data + 4) != kNdrCommonFiller) return Status::InvalidField;
    const uint32_t object_length = ReadLe32(data + 8);
    if (ReadLe32(data + 12) != 0) return Status::InvalidField;
    if (object_length > kScardMaxPayloadBytes) return Status::InvalidLength;
    // A declaration that runs past the supplied bytes is a truncated packet
    // (NeedMoreData); only a declaration above the protocol cap is malformed.
    if (size - kSize < object_length) return Status::NeedMoreData;
    out.object_buffer_length = object_length;
    body_offset = kSize;
    body_size = object_length;
    return Status::Ok;
}

bool ScardNdrHeader::looks_like_header(const uint8_t* data, size_t size) {
    ScardNdrHeader header;
    size_t offset = 0;
    size_t body = 0;
    return parse(data, size, header, offset, body) == Status::Ok;
}

bool IsSupportedScardIoctl(uint32_t code) {
    switch (static_cast<ScardIoctl>(code)) {
        case ScardIoctl::kEstablishContext:
        case ScardIoctl::kReleaseContext:
        case ScardIoctl::kListReaderGroupsA:
        case ScardIoctl::kListReadersA:
        case ScardIoctl::kGetStatusChangeA:
        case ScardIoctl::kConnectA:
        case ScardIoctl::kDisconnect:
        case ScardIoctl::kBeginTransaction:
        case ScardIoctl::kEndTransaction:
        case ScardIoctl::kStatusA:
        case ScardIoctl::kTransmit:
        case ScardIoctl::kControl:
            return true;
        default:
            return false;
    }
}

const char* ScardIoctlName(uint32_t code) {
    switch (static_cast<ScardIoctl>(code)) {
        case ScardIoctl::kEstablishContext: return "SCARD_IOCTL_ESTABLISHCONTEXT";
        case ScardIoctl::kReleaseContext: return "SCARD_IOCTL_RELEASECONTEXT";
        case ScardIoctl::kIsValidContext: return "SCARD_IOCTL_ISVALIDCONTEXT";
        case ScardIoctl::kListReaderGroupsA: return "SCARD_IOCTL_LISTREADERGROUPSA";
        case ScardIoctl::kListReaderGroupsW: return "SCARD_IOCTL_LISTREADERGROUPSW";
        case ScardIoctl::kListReadersA: return "SCARD_IOCTL_LISTREADERSA";
        case ScardIoctl::kListReadersW: return "SCARD_IOCTL_LISTREADERSW";
        case ScardIoctl::kGetStatusChangeA: return "SCARD_IOCTL_GETSTATUSCHANGEA";
        case ScardIoctl::kGetStatusChangeW: return "SCARD_IOCTL_GETSTATUSCHANGEW";
        case ScardIoctl::kConnectA: return "SCARD_IOCTL_CONNECTA";
        case ScardIoctl::kConnectW: return "SCARD_IOCTL_CONNECTW";
        case ScardIoctl::kDisconnect: return "SCARD_IOCTL_DISCONNECT";
        case ScardIoctl::kBeginTransaction: return "SCARD_IOCTL_BEGINTRANSACTION";
        case ScardIoctl::kEndTransaction: return "SCARD_IOCTL_ENDTRANSACTION";
        case ScardIoctl::kStatusA: return "SCARD_IOCTL_STATUSA";
        case ScardIoctl::kStatusW: return "SCARD_IOCTL_STATUSW";
        case ScardIoctl::kTransmit: return "SCARD_IOCTL_TRANSMIT";
        case ScardIoctl::kControl: return "SCARD_IOCTL_CONTROL";
    }
    return "SCARD_IOCTL_UNKNOWN";
}

Status ParseScardCall(uint32_t code, const uint8_t* data, size_t size,
                      ScardCall& out) {
    out = ScardCall{};
    if (!IsSupportedScardIoctl(code)) return Status::InvalidType;
    ScardNdrHeader header;
    size_t body_offset = 0;
    size_t body_size = 0;
    Status s = ScardNdrHeader::parse(data, size, header, body_offset, body_size);
    if (s != Status::Ok) return s;
    out.code = static_cast<ScardIoctl>(code);
    Cursor c(data + body_offset, body_size);
    switch (out.code) {
        case ScardIoctl::kEstablishContext: return ParseEstablishContext(c, out);
        case ScardIoctl::kReleaseContext: return ParseContextCall(c, out);
        case ScardIoctl::kListReaderGroupsA: return ParseListReaderGroups(c, out);
        case ScardIoctl::kListReadersA: return ParseListReaders(c, out);
        case ScardIoctl::kGetStatusChangeA: return ParseGetStatusChange(c, out);
        case ScardIoctl::kConnectA: return ParseConnect(c, out);
        case ScardIoctl::kDisconnect:
        case ScardIoctl::kBeginTransaction:
        case ScardIoctl::kEndTransaction:
            return ParseHCardAndDisposition(c, out);
        case ScardIoctl::kStatusA: return ParseStatus(c, out);
        case ScardIoctl::kTransmit: return ParseTransmit(c, out);
        case ScardIoctl::kControl: return ParseControl(c, out);
        default: return Status::InvalidType;
    }
}


std::vector<uint8_t> EncodeScardReturn(ScardIoctl code, const ScardReturn& ret) {
    if (!IsSupportedScardIoctl(static_cast<uint32_t>(code))) return {};

    // Every [MS-RDPESC] 2.2.3.x return starts with the 32-bit Result. Fields a
    // structure does not carry for this IOCTL are simply not written, matching
    // FreeRDP smartcard_pack_*_return.
    const bool ok = ret.return_code == 0;
    Encoder e;
    e.U32(ret.return_code);

    switch (code) {
        case ScardIoctl::kEstablishContext: {
            if (!ok) return e.Finish();
            if (!ContextFits(ret.context)) return {};
            WriteContext(e, ret.context);
            WriteContextValue(e, ret.context);
            return e.Finish();
        }
        case ScardIoctl::kListReaderGroupsA:
        case ScardIoctl::kListReadersA: {
            if (!MultiStringFits(ret.multi_string)) return {};
            // A failed call still reports cBytes = 0 with a NULL pointer.
            const bool present = ok && ret.multi_string.has_value();
            const uint32_t count =
                present ? static_cast<uint32_t>(ret.multi_string->size())
                        : (ok ? ret.multi_string_length : 0u);
            e.U32(count);
            e.ValuePointer(present);
            if (present) e.SimpleReferent(*ret.multi_string);
            return e.Finish();
        }
        case ScardIoctl::kGetStatusChangeA: {
            if (ret.reader_states.size() > kScardMaxReaders) return {};
            std::vector<uint8_t> raw;
            raw.reserve(ret.reader_states.size() * 48);
            for (const auto& st : ret.reader_states) {
                if (st.atr.size() > kScardMaxAtr) return {};
                ByteWriter w;
                w.u32le(st.current_state);
                w.u32le(st.event_state);
                w.u32le(static_cast<uint32_t>(st.atr.size()));
                for (size_t i = 0; i < kScardMaxAtr; ++i) {
                    w.u8(i < st.atr.size() ? st.atr[i] : 0);
                }
                const auto& d = w.data();
                raw.insert(raw.end(), d.begin(), d.end());
            }
            const bool present = ok && !ret.reader_states.empty();
            e.U32(present ? static_cast<uint32_t>(ret.reader_states.size()) : 0u);
            e.ValuePointer(present);
            if (present) {
                // ReaderState_Return is a conformant array whose referent is
                // Length(4) + elements (Length is an element count).
                e.CountedReferent(static_cast<uint32_t>(ret.reader_states.size()),
                                  raw);
            }
            return e.Finish();
        }
        case ScardIoctl::kConnectA: {
            if (!ok) {
                WriteContext(e, ScardContext{});
                WriteContext(e, ScardContext{});  // cbHandle = 0 + NULL
                e.U32(0);
                return e.Finish();
            }
            if (!HandleFits(ret.handle)) return {};
            WriteHandle(e, ret.handle);
            e.U32(ret.active_protocol);
            WriteHandleValue(e, ret.handle);
            return e.Finish();
        }
        case ScardIoctl::kReleaseContext:
        case ScardIoctl::kDisconnect:
        case ScardIoctl::kBeginTransaction:
        case ScardIoctl::kEndTransaction:
            return e.Finish();  // Long_Return (2.2.3.3)
        case ScardIoctl::kControl: {
            if (ret.out_buffer.has_value() &&
                ret.out_buffer->size() > kScardMaxTransmitBytes) {
                return {};
            }
            const bool present = ok && ret.out_buffer.has_value();
            const uint32_t count =
                present ? static_cast<uint32_t>(ret.out_buffer->size())
                        : (ok ? ret.out_length : 0u);
            e.U32(count);
            e.ValuePointer(present);
            if (present) e.SimpleReferent(*ret.out_buffer);
            return e.Finish();
        }
        case ScardIoctl::kStatusA: {
            if (ret.atr.size() > kScardMaxStatusAtr) return {};
            if (!MultiStringFits(ret.reader_names)) return {};
            const bool present = ok && ret.reader_names.has_value();
            const uint32_t count =
                present ? static_cast<uint32_t>(ret.reader_names->size())
                        : (ok ? ret.reader_names_length : 0u);
            e.U32(count);
            e.ValuePointer(present);
            e.U32(ret.state);
            e.U32(ret.protocol);
            std::vector<uint8_t> atr = ret.atr;
            atr.resize(kScardMaxStatusAtr, 0);
            e.InlineBytes(atr);  // fixed pbAtr[32]
            e.U32(static_cast<uint32_t>(ret.atr.size()));
            if (present) e.SimpleReferent(*ret.reader_names);
            return e.Finish();
        }
        case ScardIoctl::kTransmit: {
            if (ret.recv_buffer.has_value() &&
                ret.recv_buffer->size() > kScardMaxTransmitBytes) {
                return {};
            }
            if (ret.recv_pci.has_value() &&
                ret.recv_pci->extra.size() > kScardMaxExtraBytes) {
                return {};
            }
            const bool pci_present = ok && ret.recv_pci.has_value();
            const bool buffer_present = ok && ret.recv_buffer.has_value();
            const uint32_t count =
                buffer_present ? static_cast<uint32_t>(ret.recv_buffer->size())
                               : (ok ? ret.recv_length : 0u);
            // pioRecvPci pointer, then cbRecvLength, then pbRecvBuffer pointer.
            e.ValuePointer(pci_present);
            e.U32(count);
            e.ValuePointer(buffer_present);
            // Referents follow the inline part in pointer order:
            //   1. pioRecvPci -> {dwProtocol, cbExtraBytes, pbExtraBytes ptr}
            //      plus the deferred extra bytes,
            //   2. pbRecvBuffer -> Length(4) + bytes.
            if (pci_present) {
                WriteIoRequestInlineValue(e, *ret.recv_pci);
            }
            if (buffer_present) e.SimpleReferent(*ret.recv_buffer);
            return e.Finish();
        }
        default:
            return {};
    }
}

}  // namespace rtsc::proto