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

    // [string] wchar_t referent: Length/Offset/ActualCount are character
    // counts; the payload is UTF-16LE and padded to 4 bytes.
    Status FullWideStringReferent(size_t max_chars, std::u16string& out) {
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
        if (length == 0 || length > max_chars) return Status::InvalidField;
        const size_t bytes = static_cast<size_t>(length) * 2;
        std::vector<uint8_t> raw;
        s = FixedBytes(raw, bytes);
        if (s != Status::Ok) return s;
        s = Skip(Pad4(bytes) - bytes);
        if (s != Status::Ok) return s;
        // The final UTF-16 code unit must be NUL.
        if (raw[bytes - 2] != 0 || raw[bytes - 1] != 0) {
            return Status::InvalidField;
        }
        out.clear();
        out.reserve(length - 1);
        for (size_t i = 0; i + 2 <= bytes - 2; i += 2) {
            out.push_back(static_cast<char16_t>(
                static_cast<uint16_t>(raw[i]) |
                (static_cast<uint16_t>(raw[i + 1]) << 8)));
        }
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

// ReaderStateA[] referent shared by GetStatusChangeA_Call (2.2.2.11) and
// LocateCardsA_Call (2.2.2.9): MaxCount must equal the inline count, then the
// fixed fields, then one [string] referent per non-NULL szReader.
Status ReadReaderStateArray(Cursor& c, uint32_t readers, bool states_null,
                            std::vector<ScardReaderStateA>& out) {
    if (states_null) {
        // A conformant array of zero elements is written as a NULL pointer.
        if (readers != 0) return Status::InvalidField;
        return Status::Ok;
    }
    uint32_t max_count = 0;
    Status s = c.U32(max_count);
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
    out = std::move(states);
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
    return ReadReaderStateArray(c, readers, states_null, out.reader_states);
}

// ReaderStateW array for GetStatusChangeW_Call ([MS-RDPESC] 2.2.2.12).
Status ReadReaderStateArrayW(Cursor& c, uint32_t readers, bool states_null,
                             std::vector<ScardReaderStateW>& out) {
    if (states_null) {
        if (readers != 0) return Status::InvalidField;
        return Status::Ok;
    }
    uint32_t max_count = 0;
    Status s = c.U32(max_count);
    if (s != Status::Ok) return s;
    if (max_count != readers) return Status::InvalidField;
    std::vector<ScardReaderStateW> states(readers);
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
        s = c.FullWideStringReferent(kScardMaxMultiStringBytes,
                                     states[i].reader);
        if (s != Status::Ok) return s;
    }
    out = std::move(states);
    return Status::Ok;
}

Status ParseGetStatusChangeW(Cursor& c, ScardCall& out) {
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
    return ReadReaderStateArrayW(c, readers, states_null, out.reader_states_w);
}

// LocateCardsA_Call ([MS-RDPESC] 2.2.2.9): Context, cBytes, mszCards,
// cReaders, rgReaderStates. The wire form carries only the context (FreeRDP
// smartcard_unpack_locate_cards_a_call unpacks no hCard), and the mszCards
// NDR length must equal cBytes.
Status ParseLocateCardsA(Cursor& c, ScardCall& out) {
    bool context_present = false;
    Status s = ReadContextInline(c, out.context, context_present);
    if (s != Status::Ok) return s;
    uint32_t bytes = 0;
    s = c.U32(bytes);
    if (s != Status::Ok) return s;
    if (bytes > kScardMaxMultiStringBytes) return Status::InvalidField;
    bool cards_null = false;
    s = c.Pointer(cards_null);
    if (s != Status::Ok) return s;
    if (cards_null && bytes != 0) return Status::InvalidField;
    uint32_t readers = 0;
    s = c.U32(readers);
    if (s != Status::Ok) return s;
    if (readers > kScardMaxReaders) return Status::InvalidField;
    bool states_null = false;
    s = c.Pointer(states_null);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, context_present, out.context);
    if (s != Status::Ok) return s;
    if (!cards_null) {
        std::vector<uint8_t> raw;
        s = c.SimpleReferent(kScardMaxMultiStringBytes, raw);
        if (s != Status::Ok) return s;
        if (raw.size() != bytes) return Status::InvalidField;
        if (!raw.empty() && raw.back() != 0) return Status::InvalidField;
        out.cards_msz = std::move(raw);
    }
    return ReadReaderStateArray(c, readers, states_null, out.reader_states);
}

// LocateCardsW_Call ([MS-RDPESC] 2.2.2.10): same wire shape as LocateCardsA,
// but mszCards is a UTF-16LE multistring and rgReaderStates uses
// ReaderStateW. Per the IDL mszCards is a byte array sized by cBytes, so the
// NDR Length equals cBytes and cBytes bytes follow (see evidence section 19
// for the FreeRDP elementSize discrepancy).
Status ParseLocateCardsW(Cursor& c, ScardCall& out) {
    bool context_present = false;
    Status s = ReadContextInline(c, out.context, context_present);
    if (s != Status::Ok) return s;
    uint32_t bytes = 0;
    s = c.U32(bytes);
    if (s != Status::Ok) return s;
    if (bytes > kScardMaxMultiStringBytes) return Status::InvalidField;
    bool cards_null = false;
    s = c.Pointer(cards_null);
    if (s != Status::Ok) return s;
    if (cards_null && bytes != 0) return Status::InvalidField;
    uint32_t readers = 0;
    s = c.U32(readers);
    if (s != Status::Ok) return s;
    if (readers > kScardMaxReaders) return Status::InvalidField;
    bool states_null = false;
    s = c.Pointer(states_null);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, context_present, out.context);
    if (s != Status::Ok) return s;
    if (!cards_null) {
        std::vector<uint8_t> raw;
        s = c.SimpleReferent(kScardMaxMultiStringBytes, raw);
        if (s != Status::Ok) return s;
        if (raw.size() != bytes) return Status::InvalidField;
        if (bytes % 2 != 0) return Status::InvalidField;
        if (bytes < 4 || raw[bytes - 1] != 0 || raw[bytes - 2] != 0 ||
            raw[bytes - 3] != 0 || raw[bytes - 4] != 0) {
            return Status::InvalidField;
        }
        out.cards_msz = std::move(raw);
    }
    return ReadReaderStateArrayW(c, readers, states_null, out.reader_states_w);
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

// ConnectW_Call ([MS-RDPESC] 2.2.2.14) shares Connect_Common with ConnectA;
// only szReader is a WCHAR [string].
Status ParseConnectW(Cursor& c, ScardCall& out) {
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
    s = c.FullWideStringReferent(kScardMaxMultiStringBytes, out.reader_name);
    if (s != Status::Ok) return s;
    return ReadContextValue(c, present, out.context);
}

// Reconnect_Call ([MS-RDPESC] 2.2.2.15): REDIR_SCARDHANDLE, dwShareMode,
// dwPreferredProtocols, dwInitialization; referents: context, handle.
Status ParseReconnect(Cursor& c, ScardCall& out) {
    bool ctx_present = false;
    bool handle_present = false;
    Status s = ReadHandleInline(c, out.handle, ctx_present, handle_present);
    if (s != Status::Ok) return s;
    s = c.U32(out.share_mode);
    if (s != Status::Ok) return s;
    s = c.U32(out.preferred_protocols);
    if (s != Status::Ok) return s;
    s = c.U32(out.initialization);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, ctx_present, out.handle.context);
    if (s != Status::Ok) return s;
    return ReadHandleValue(c, handle_present, out.handle);
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

// State_Call ([MS-RDPESC] 2.2.2.17): REDIR_SCARDHANDLE, fpbAtrIsNULL,
// cbAtrLen; referents: context, handle.
Status ParseState(Cursor& c, ScardCall& out) {
    bool ctx_present = false;
    bool handle_present = false;
    Status s = ReadHandleInline(c, out.handle, ctx_present, handle_present);
    if (s != Status::Ok) return s;
    s = c.U32(out.atr_is_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.atr_capacity);
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

// GetAttrib_Call ([MS-RDPESC] 2.2.2.21): hCard, dwAttrId, fpbAttrIsNULL,
// cbAttrLen; the handle referents follow the inline fields in pointer order.
Status ParseGetAttrib(Cursor& c, ScardCall& out) {
    bool ctx_present = false;
    bool handle_present = false;
    Status s = ReadHandleInline(c, out.handle, ctx_present, handle_present);
    if (s != Status::Ok) return s;
    s = c.U32(out.attr_id);
    if (s != Status::Ok) return s;
    s = c.U32(out.attr_is_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.attr_capacity);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, ctx_present, out.handle.context);
    if (s != Status::Ok) return s;
    return ReadHandleValue(c, handle_present, out.handle);
}

// SetAttrib_Call ([MS-RDPESC] 2.2.2.22): hCard, dwAttrId, cbAttrLen, pbAttr.
// The NDR array length must equal cbAttrLen; a mismatch is malformed (the
// FreeRDP 3.20.1 heap-overflow fix enforces the same invariant).
Status ParseSetAttrib(Cursor& c, ScardCall& out) {
    bool ctx_present = false;
    bool handle_present = false;
    Status s = ReadHandleInline(c, out.handle, ctx_present, handle_present);
    if (s != Status::Ok) return s;
    s = c.U32(out.attr_id);
    if (s != Status::Ok) return s;
    s = c.U32(out.set_attr_length);
    if (s != Status::Ok) return s;
    if (out.set_attr_length > kScardMaxMultiStringBytes) {
        return Status::InvalidField;
    }
    uint32_t pointer = 0;
    s = c.U32(pointer);
    if (s != Status::Ok) return s;
    if (pointer == 0 && out.set_attr_length != 0) return Status::InvalidField;
    s = ReadContextValue(c, ctx_present, out.handle.context);
    if (s != Status::Ok) return s;
    s = ReadHandleValue(c, handle_present, out.handle);
    if (s != Status::Ok) return s;
    if (pointer != 0) {
        std::vector<uint8_t> raw;
        s = c.SimpleReferent(kScardMaxMultiStringBytes, raw);
        if (s != Status::Ok) return s;
        if (raw.size() != out.set_attr_length) return Status::InvalidField;
        out.set_attr_value = std::move(raw);
    }
    return Status::Ok;
}

// ReadCacheA_Call ([MS-RDPESC] 2.2.2.25): [string] szLookupName comes first,
// then ReadCache_Common {Context, UUID* CardIdentifier, FreshnessCounter,
// fPbDataIsNULL, cbDataLen}. Referents follow pointer order: the lookup name,
// the context bytes, then the 16-byte UUID.
Status ParseReadCacheA(Cursor& c, ScardCall& out) {
    bool name_null = false;
    Status s = c.Pointer(name_null);
    if (s != Status::Ok) return s;
    if (name_null) return Status::InvalidField;  // [string] is required
    bool context_present = false;
    s = ReadContextInline(c, out.context, context_present);
    if (s != Status::Ok) return s;
    bool uuid_null = false;
    s = c.Pointer(uuid_null);
    if (s != Status::Ok) return s;
    if (uuid_null) return Status::InvalidField;  // UUID* is required
    s = c.U32(out.freshness);
    if (s != Status::Ok) return s;
    s = c.U32(out.cache_is_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.cache_capacity);
    if (s != Status::Ok) return s;
    s = c.FullStringReferent(kScardMaxMultiStringBytes, out.lookup_name);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, context_present, out.context);
    if (s != Status::Ok) return s;
    std::vector<uint8_t> uuid;
    s = c.FixedBytes(uuid, 16);  // NDR_PTR_FIXED UUID
    if (s != Status::Ok) return s;
    out.card_id = std::move(uuid);
    return Status::Ok;
}

// ReadCacheW_Call ([MS-RDPESC] 2.2.2.26) is ReadCacheA_Call with a UTF-16LE
// [string] lookup name.
Status ParseReadCacheW(Cursor& c, ScardCall& out) {
    bool name_null = false;
    Status s = c.Pointer(name_null);
    if (s != Status::Ok) return s;
    if (name_null) return Status::InvalidField;  // [string] is required
    bool context_present = false;
    s = ReadContextInline(c, out.context, context_present);
    if (s != Status::Ok) return s;
    bool uuid_null = false;
    s = c.Pointer(uuid_null);
    if (s != Status::Ok) return s;
    if (uuid_null) return Status::InvalidField;  // UUID* is required
    s = c.U32(out.freshness);
    if (s != Status::Ok) return s;
    s = c.U32(out.cache_is_null);
    if (s != Status::Ok) return s;
    s = c.U32(out.cache_capacity);
    if (s != Status::Ok) return s;
    s = c.FullWideStringReferent(kScardMaxMultiStringBytes, out.lookup_name_w);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, context_present, out.context);
    if (s != Status::Ok) return s;
    std::vector<uint8_t> uuid;
    s = c.FixedBytes(uuid, 16);  // NDR_PTR_FIXED UUID
    if (s != Status::Ok) return s;
    out.card_id = std::move(uuid);
    return Status::Ok;
}

// WriteCacheA_Call ([MS-RDPESC] 2.2.2.27): [string] szLookupName first, then
// WriteCache_Common {Context, UUID* CardIdentifier, FreshnessCounter,
// cbDataLen, [unique] pbData}. Referents: name, context, UUID, data.
Status ParseWriteCacheA(Cursor& c, ScardCall& out) {
    bool name_null = false;
    Status s = c.Pointer(name_null);
    if (s != Status::Ok) return s;
    if (name_null) return Status::InvalidField;  // [string] is required
    bool context_present = false;
    s = ReadContextInline(c, out.context, context_present);
    if (s != Status::Ok) return s;
    bool uuid_null = false;
    s = c.Pointer(uuid_null);
    if (s != Status::Ok) return s;
    if (uuid_null) return Status::InvalidField;  // UUID* is required
    s = c.U32(out.freshness);
    if (s != Status::Ok) return s;
    uint32_t length = 0;
    s = c.U32(length);
    if (s != Status::Ok) return s;
    if (length > kScardMaxMultiStringBytes) return Status::InvalidField;
    bool data_null = false;
    s = c.Pointer(data_null);
    if (s != Status::Ok) return s;
    if (data_null && length != 0) return Status::InvalidField;
    s = c.FullStringReferent(kScardMaxMultiStringBytes, out.lookup_name);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, context_present, out.context);
    if (s != Status::Ok) return s;
    std::vector<uint8_t> uuid;
    s = c.FixedBytes(uuid, 16);  // NDR_PTR_FIXED UUID
    if (s != Status::Ok) return s;
    out.card_id = std::move(uuid);
    if (!data_null) {
        std::vector<uint8_t> raw;
        s = c.SimpleReferent(kScardMaxMultiStringBytes, raw);
        if (s != Status::Ok) return s;
        if (raw.size() != length) return Status::InvalidField;
        out.write_cache_data = std::move(raw);
    }
    return Status::Ok;
}

// WriteCacheW_Call ([MS-RDPESC] 2.2.2.28) is WriteCacheA_Call with a UTF-16LE
// [string] lookup name.
Status ParseWriteCacheW(Cursor& c, ScardCall& out) {
    bool name_null = false;
    Status s = c.Pointer(name_null);
    if (s != Status::Ok) return s;
    if (name_null) return Status::InvalidField;  // [string] is required
    bool context_present = false;
    s = ReadContextInline(c, out.context, context_present);
    if (s != Status::Ok) return s;
    bool uuid_null = false;
    s = c.Pointer(uuid_null);
    if (s != Status::Ok) return s;
    if (uuid_null) return Status::InvalidField;  // UUID* is required
    s = c.U32(out.freshness);
    if (s != Status::Ok) return s;
    uint32_t length = 0;
    s = c.U32(length);
    if (s != Status::Ok) return s;
    if (length > kScardMaxMultiStringBytes) return Status::InvalidField;
    bool data_null = false;
    s = c.Pointer(data_null);
    if (s != Status::Ok) return s;
    if (data_null && length != 0) return Status::InvalidField;
    s = c.FullWideStringReferent(kScardMaxMultiStringBytes, out.lookup_name_w);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, context_present, out.context);
    if (s != Status::Ok) return s;
    std::vector<uint8_t> uuid;
    s = c.FixedBytes(uuid, 16);  // NDR_PTR_FIXED UUID
    if (s != Status::Ok) return s;
    out.card_id = std::move(uuid);
    if (!data_null) {
        std::vector<uint8_t> raw;
        s = c.SimpleReferent(kScardMaxMultiStringBytes, raw);
        if (s != Status::Ok) return s;
        if (raw.size() != length) return Status::InvalidField;
        out.write_cache_data = std::move(raw);
    }
    return Status::Ok;
}

// GetReaderIcon_Call ([MS-RDPESC] 2.2.2.31): Context, [string] wchar_t
// szReaderName. The name referent is UTF-16LE with character-counted lengths.
Status ParseGetReaderIcon(Cursor& c, ScardCall& out) {
    bool context_present = false;
    Status s = ReadContextInline(c, out.context, context_present);
    if (s != Status::Ok) return s;
    bool name_null = false;
    s = c.Pointer(name_null);
    if (s != Status::Ok) return s;
    if (name_null) return Status::InvalidField;  // [string] is required
    s = ReadContextValue(c, context_present, out.context);
    if (s != Status::Ok) return s;
    return c.FullWideStringReferent(kScardMaxMultiStringBytes, out.reader_name);
}

// GetDeviceTypeId_Call ([MS-RDPESC] 2.2.2.32) has the same wire form as
// GetReaderIcon_Call: Context plus a WCHAR [string] reader name.
Status ParseGetDeviceTypeId(Cursor& c, ScardCall& out) {
    return ParseGetReaderIcon(c, out);
}

// GetTransmitCount_Call ([MS-RDPESC] 2.2.2.29): REDIR_SCARDHANDLE only.
Status ParseGetTransmitCount(Cursor& c, ScardCall& out) {
    bool ctx_present = false;
    bool handle_present = false;
    Status s = ReadHandleInline(c, out.handle, ctx_present, handle_present);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, ctx_present, out.handle.context);
    if (s != Status::Ok) return s;
    return ReadHandleValue(c, handle_present, out.handle);
}

// LocateCardsByATRA_Call ([MS-RDPESC] 2.2.2.23): Context, cAtrs, rgAtrMasks,
// cReaders, rgReaderStates. The mask array Length is an element count and each
// element is 76 bytes (cbAtr + rgbAtr[36] + rgbMask[36]).
Status ParseLocateCardsByAtrA(Cursor& c, ScardCall& out) {
    bool context_present = false;
    Status s = ReadContextInline(c, out.context, context_present);
    if (s != Status::Ok) return s;
    uint32_t atrs = 0;
    s = c.U32(atrs);
    if (s != Status::Ok) return s;
    if (atrs > kScardMaxAtrMasks) return Status::InvalidField;
    bool masks_null = false;
    s = c.Pointer(masks_null);
    if (s != Status::Ok) return s;
    if (masks_null && atrs != 0) return Status::InvalidField;
    if (!masks_null && atrs == 0) return Status::InvalidField;
    uint32_t readers = 0;
    s = c.U32(readers);
    if (s != Status::Ok) return s;
    if (readers > kScardMaxReaders) return Status::InvalidField;
    bool states_null = false;
    s = c.Pointer(states_null);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, context_present, out.context);
    if (s != Status::Ok) return s;
    if (!masks_null) {
        uint32_t count = 0;
        s = c.U32(count);
        if (s != Status::Ok) return s;
        if (count != atrs) return Status::InvalidField;
        std::vector<ScardAtrMask> masks(atrs);
        for (uint32_t i = 0; i < atrs; ++i) {
            s = c.U32(masks[i].cb_atr);
            if (s != Status::Ok) return s;
            if (masks[i].cb_atr > kScardMaxAtr) return Status::InvalidField;
            std::vector<uint8_t> atr;
            std::vector<uint8_t> mask;
            s = c.FixedBytes(atr, kScardMaxAtr);   // fixed rgbAtr[36]
            if (s != Status::Ok) return s;
            s = c.FixedBytes(mask, kScardMaxAtr);  // fixed rgbMask[36]
            if (s != Status::Ok) return s;
            atr.resize(masks[i].cb_atr);
            mask.resize(masks[i].cb_atr);
            masks[i].atr = std::move(atr);
            masks[i].mask = std::move(mask);
        }
        out.atr_masks = std::move(masks);
    }
    return ReadReaderStateArray(c, readers, states_null, out.reader_states);
}

// LocateCardsByATRW_Call ([MS-RDPESC] 2.2.2.24): same wire shape as the A
// variant (ATR masks are byte arrays); only rgReaderStates uses ReaderStateW.
Status ParseLocateCardsByAtrW(Cursor& c, ScardCall& out) {
    bool context_present = false;
    Status s = ReadContextInline(c, out.context, context_present);
    if (s != Status::Ok) return s;
    uint32_t atrs = 0;
    s = c.U32(atrs);
    if (s != Status::Ok) return s;
    if (atrs > kScardMaxAtrMasks) return Status::InvalidField;
    bool masks_null = false;
    s = c.Pointer(masks_null);
    if (s != Status::Ok) return s;
    if (masks_null && atrs != 0) return Status::InvalidField;
    if (!masks_null && atrs == 0) return Status::InvalidField;
    uint32_t readers = 0;
    s = c.U32(readers);
    if (s != Status::Ok) return s;
    if (readers > kScardMaxReaders) return Status::InvalidField;
    bool states_null = false;
    s = c.Pointer(states_null);
    if (s != Status::Ok) return s;
    s = ReadContextValue(c, context_present, out.context);
    if (s != Status::Ok) return s;
    if (!masks_null) {
        uint32_t count = 0;
        s = c.U32(count);
        if (s != Status::Ok) return s;
        if (count != atrs) return Status::InvalidField;
        std::vector<ScardAtrMask> masks(atrs);
        for (uint32_t i = 0; i < atrs; ++i) {
            s = c.U32(masks[i].cb_atr);
            if (s != Status::Ok) return s;
            if (masks[i].cb_atr > kScardMaxAtr) return Status::InvalidField;
            std::vector<uint8_t> atr;
            std::vector<uint8_t> mask;
            s = c.FixedBytes(atr, kScardMaxAtr);   // fixed rgbAtr[36]
            if (s != Status::Ok) return s;
            s = c.FixedBytes(mask, kScardMaxAtr);  // fixed rgbMask[36]
            if (s != Status::Ok) return s;
            atr.resize(masks[i].cb_atr);
            mask.resize(masks[i].cb_atr);
            masks[i].atr = std::move(atr);
            masks[i].mask = std::move(mask);
        }
        out.atr_masks = std::move(masks);
    }
    return ReadReaderStateArrayW(c, readers, states_null, out.reader_states_w);
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

    // ListReadersW_Return msz is a UTF-16LE multistring: even byte count and
    // a double-NUL terminator.
    bool WideMultiStringFits(const std::optional<std::vector<uint8_t>>& value) {
        if (!value.has_value()) return true;
        const auto& v = *value;
        if (v.size() < 4 || v.size() > kScardMaxMultiStringBytes) return false;
        if (v.size() % 2 != 0) return false;
        return v[v.size() - 1] == 0 && v[v.size() - 2] == 0 &&
               v[v.size() - 3] == 0 && v[v.size() - 4] == 0;
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
        case ScardIoctl::kIsValidContext:
        case ScardIoctl::kListReaderGroupsA:
        case ScardIoctl::kListReaderGroupsW:
        case ScardIoctl::kListReadersA:
        case ScardIoctl::kListReadersW:
        case ScardIoctl::kLocateCardsA:
        case ScardIoctl::kLocateCardsW:
        case ScardIoctl::kLocateCardsByAtrA:
        case ScardIoctl::kLocateCardsByAtrW:
        case ScardIoctl::kAccessStartedEvent:
        case ScardIoctl::kCancel:
        case ScardIoctl::kState:
        case ScardIoctl::kReconnect:
        case ScardIoctl::kGetStatusChangeA:
        case ScardIoctl::kGetStatusChangeW:
        case ScardIoctl::kConnectA:
        case ScardIoctl::kConnectW:
        case ScardIoctl::kDisconnect:
        case ScardIoctl::kBeginTransaction:
        case ScardIoctl::kEndTransaction:
        case ScardIoctl::kStatusA:
        case ScardIoctl::kStatusW:
        case ScardIoctl::kTransmit:
        case ScardIoctl::kControl:
        case ScardIoctl::kGetAttrib:
        case ScardIoctl::kSetAttrib:
        case ScardIoctl::kReadCacheA:
        case ScardIoctl::kReadCacheW:
        case ScardIoctl::kWriteCacheA:
        case ScardIoctl::kWriteCacheW:
        case ScardIoctl::kGetReaderIcon:
        case ScardIoctl::kGetDeviceTypeId:
        case ScardIoctl::kGetTransmitCount:
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
        case ScardIoctl::kLocateCardsA: return "SCARD_IOCTL_LOCATECARDSA";
        case ScardIoctl::kLocateCardsByAtrA: return "SCARD_IOCTL_LOCATECARDSBYATRA";
        case ScardIoctl::kAccessStartedEvent: return "SCARD_IOCTL_ACCESSSTARTEDEVENT";
        case ScardIoctl::kCancel: return "SCARD_IOCTL_CANCEL";
        case ScardIoctl::kState: return "SCARD_IOCTL_STATE";
        case ScardIoctl::kReconnect: return "SCARD_IOCTL_RECONNECT";
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
        case ScardIoctl::kGetAttrib: return "SCARD_IOCTL_GETATTRIB";
        case ScardIoctl::kSetAttrib: return "SCARD_IOCTL_SETATTRIB";
        case ScardIoctl::kReadCacheA: return "SCARD_IOCTL_READCACHEA";
        case ScardIoctl::kWriteCacheA: return "SCARD_IOCTL_WRITECACHEA";
        case ScardIoctl::kGetReaderIcon: return "SCARD_IOCTL_GETREADERICON";
        case ScardIoctl::kGetDeviceTypeId: return "SCARD_IOCTL_GETDEVICETYPEID";
        case ScardIoctl::kGetTransmitCount: return "SCARD_IOCTL_GETTRANSMITCOUNT";
    }
    return "SCARD_IOCTL_UNKNOWN";
}

Status ParseScardCall(uint32_t code, const uint8_t* data, size_t size,
                      ScardCall& out) {
    out = ScardCall{};
    if (!IsSupportedScardIoctl(code)) return Status::InvalidType;
    // ScardAccessStartedEvent_Call (2.2.2.30) is a bare 4-byte buffer, not an
    // NDR-serialized structure; its contents are uninitialized and ignored.
    if (code == static_cast<uint32_t>(ScardIoctl::kAccessStartedEvent)) {
        if (size != 4) return Status::InvalidLength;
        out.code = ScardIoctl::kAccessStartedEvent;
        return Status::Ok;
    }
    ScardNdrHeader header;
    size_t body_offset = 0;
    size_t body_size = 0;
    Status s = ScardNdrHeader::parse(data, size, header, body_offset, body_size);
    if (s != Status::Ok) return s;
    out.code = static_cast<ScardIoctl>(code);
    Cursor c(data + body_offset, body_size);
    switch (out.code) {
        case ScardIoctl::kEstablishContext: return ParseEstablishContext(c, out);
        case ScardIoctl::kReleaseContext:
        case ScardIoctl::kIsValidContext:
        case ScardIoctl::kCancel: return ParseContextCall(c, out);
        case ScardIoctl::kListReaderGroupsA: return ParseListReaderGroups(c, out);
        case ScardIoctl::kListReaderGroupsW: return ParseListReaderGroups(c, out);
        case ScardIoctl::kListReadersA: return ParseListReaders(c, out);
        case ScardIoctl::kListReadersW: return ParseListReaders(c, out);
        case ScardIoctl::kLocateCardsA: return ParseLocateCardsA(c, out);
        case ScardIoctl::kLocateCardsW: return ParseLocateCardsW(c, out);
        case ScardIoctl::kLocateCardsByAtrA: return ParseLocateCardsByAtrA(c, out);
        case ScardIoctl::kLocateCardsByAtrW: return ParseLocateCardsByAtrW(c, out);
        case ScardIoctl::kGetStatusChangeA: return ParseGetStatusChange(c, out);
        case ScardIoctl::kGetStatusChangeW: return ParseGetStatusChangeW(c, out);
        case ScardIoctl::kConnectA: return ParseConnect(c, out);
        case ScardIoctl::kConnectW: return ParseConnectW(c, out);
        case ScardIoctl::kReconnect: return ParseReconnect(c, out);
        case ScardIoctl::kDisconnect:
        case ScardIoctl::kBeginTransaction:
        case ScardIoctl::kEndTransaction:
            return ParseHCardAndDisposition(c, out);
        case ScardIoctl::kState: return ParseState(c, out);
        case ScardIoctl::kStatusA: return ParseStatus(c, out);
        case ScardIoctl::kStatusW: return ParseStatus(c, out);
        case ScardIoctl::kTransmit: return ParseTransmit(c, out);
        case ScardIoctl::kControl: return ParseControl(c, out);
        case ScardIoctl::kGetAttrib: return ParseGetAttrib(c, out);
        case ScardIoctl::kSetAttrib: return ParseSetAttrib(c, out);
        case ScardIoctl::kReadCacheA: return ParseReadCacheA(c, out);
        case ScardIoctl::kReadCacheW: return ParseReadCacheW(c, out);
        case ScardIoctl::kWriteCacheA: return ParseWriteCacheA(c, out);
        case ScardIoctl::kWriteCacheW: return ParseWriteCacheW(c, out);
        case ScardIoctl::kGetReaderIcon: return ParseGetReaderIcon(c, out);
        case ScardIoctl::kGetDeviceTypeId: return ParseGetDeviceTypeId(c, out);
        case ScardIoctl::kGetTransmitCount: return ParseGetTransmitCount(c, out);
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
        case ScardIoctl::kListReaderGroupsW:
        case ScardIoctl::kListReadersW: {
            if (!WideMultiStringFits(ret.multi_string)) return {};
            const bool present = ok && ret.multi_string.has_value();
            const uint32_t count =
                present ? static_cast<uint32_t>(ret.multi_string->size())
                        : (ok ? ret.multi_string_length : 0u);
            e.U32(count);
            e.ValuePointer(present);
            if (present) e.SimpleReferent(*ret.multi_string);
            return e.Finish();
        }
        case ScardIoctl::kLocateCardsA:
        case ScardIoctl::kLocateCardsW:
        case ScardIoctl::kLocateCardsByAtrA:
        case ScardIoctl::kLocateCardsByAtrW:
        case ScardIoctl::kGetStatusChangeA:
        case ScardIoctl::kGetStatusChangeW: {
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
            // FreeRDP keeps the reader states on SCARD_E_TIMEOUT: the server
            // needs the updated states to see what changed. Every other
            // failure drops them.
            const bool keep =
                ok || ret.return_code == kScardETimeout;
            const bool present = keep && !ret.reader_states.empty();
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
        case ScardIoctl::kConnectA:
        case ScardIoctl::kConnectW: {
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
        case ScardIoctl::kReconnect:
            // Reconnect_Return 2.2.3.7 writes dwActiveProtocol even on
            // failure (FreeRDP smartcard_pack_reconnect_return).
            e.U32(ret.active_protocol);
            return e.Finish();
        case ScardIoctl::kReleaseContext:
        case ScardIoctl::kIsValidContext:
        case ScardIoctl::kSetAttrib:
        case ScardIoctl::kWriteCacheA:
        case ScardIoctl::kWriteCacheW:
        case ScardIoctl::kAccessStartedEvent:
        case ScardIoctl::kCancel:
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
        case ScardIoctl::kGetAttrib: {
            if (ret.attr.has_value() &&
                ret.attr->size() > kScardMaxMultiStringBytes) {
                return {};
            }
            const bool present = ok && ret.attr.has_value();
            const uint32_t count =
                present ? static_cast<uint32_t>(ret.attr->size())
                        : (ok ? ret.attr_length : 0u);
            e.U32(count);
            e.ValuePointer(present);
            if (present) e.SimpleReferent(*ret.attr);
            return e.Finish();
        }
        case ScardIoctl::kReadCacheA:
        case ScardIoctl::kReadCacheW: {
            if (ret.cache.has_value() &&
                ret.cache->size() > kScardMaxMultiStringBytes) {
                return {};
            }
            const bool present = ok && ret.cache.has_value();
            const uint32_t count =
                present ? static_cast<uint32_t>(ret.cache->size())
                        : (ok ? ret.cache_length : 0u);
            if (count > kScardMaxMultiStringBytes) return {};
            e.U32(count);
            e.ValuePointer(present);
            if (present) e.SimpleReferent(*ret.cache);
            return e.Finish();
        }
        case ScardIoctl::kGetReaderIcon: {
            if (ret.icon.has_value() &&
                ret.icon->size() > kScardMaxIconBytes) {
                return {};
            }
            const bool present = ok && ret.icon.has_value();
            const uint32_t count =
                present ? static_cast<uint32_t>(ret.icon->size())
                        : (ok ? ret.icon_length : 0u);
            if (count > kScardMaxIconBytes) return {};
            e.U32(count);
            e.ValuePointer(present);
            if (present) e.SimpleReferent(*ret.icon);
            return e.Finish();
        }
        case ScardIoctl::kGetDeviceTypeId:
            // GetDeviceTypeId_Return 2.2.3.13 writes dwDeviceId even on
            // failure (FreeRDP smartcard_pack_device_type_id_return).
            e.U32(ret.device_type_id);
            return e.Finish();
        case ScardIoctl::kGetTransmitCount:
            // GetTransmitCount_Return 2.2.3.13 writes cTransmitCount even on
            // failure (FreeRDP smartcard_pack_get_transmit_count_return).
            e.U32(ret.transmit_count);
            return e.Finish();
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
        case ScardIoctl::kStatusW: {
            if (ret.atr.size() > kScardMaxStatusAtr) return {};
            if (!WideMultiStringFits(ret.reader_names)) return {};
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
        case ScardIoctl::kState: {
            if (ret.state_atr.has_value() &&
                ret.state_atr->size() > kScardMaxAtr) {
                return {};
            }
            const bool present = ok && ret.state_atr.has_value();
            const uint32_t count =
                present ? static_cast<uint32_t>(ret.state_atr->size())
                        : (ok ? ret.state_atr_length : 0u);
            if (count > kScardMaxAtr) return {};
            e.U32(ret.state);
            e.U32(ret.protocol);
            e.U32(count);
            e.ValuePointer(present);
            if (present) e.SimpleReferent(*ret.state_atr);
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