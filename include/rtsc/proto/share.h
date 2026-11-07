#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// Slow-path (share) PDU headers and Fast-Path framing ([MS-RDPBCGR] 2.2.8 /
// 2.2.9). Everything below the MCS Send Data payload lives here.

// TS_SHARECONTROLHEADER pduType.type ([MS-RDPBCGR] 2.2.8.1.1.1.1).
// Only these five values are defined; the rest are holes.
enum class SharePduType : uint16_t {
    kDemandActive = 0x1,
    kConfirmActive = 0x3,
    kDeactivateAll = 0x6,
    kData = 0x7,
    kServerRedirection = 0xA,
};

const char* to_string(SharePduType type);

// sharedPDUType, the real type of a PDUTYPE_DATAPDU ([MS-RDPBCGR]
// 2.2.8.1.1.1.2). Sparse: 24 defined values spread over 0x02..0x37.
enum class ShareDataPduType : uint8_t {
    kUpdate = 0x02,
    kControl = 0x14,
    kPointer = 0x1B,
    kInput = 0x1C,
    kSynchronize = 0x1F,
    kRefreshRect = 0x21,
    kPlaySound = 0x22,
    kSuppressOutput = 0x23,
    kShutdownRequest = 0x24,
    kShutdownDenied = 0x25,
    kSaveSessionInfo = 0x26,
    kFontList = 0x27,
    kFontMap = 0x28,
    kSetKeyboardIndicators = 0x29,
    kPersistentKeyList = 0x2B,
    kBitmapCacheError = 0x2C,
    kSetKeyboardImeStatus = 0x2D,
    kOffscreenCacheError = 0x2E,
    kSetErrorInfo = 0x2F,
    kDrawNineGridError = 0x30,
    kDrawGdiPlusError = 0x31,
    kArcStatus = 0x32,
    kStatusInfo = 0x36,
    kMonitorLayout = 0x37,
};

const char* to_string(ShareDataPduType type);

// TS_SECURITY_HEADER flags ([MS-RDPBCGR] 2.2.8.1.1.2.1).
// SEC_LICENSE_ENCRYPT_CS and SEC_LICENSE_ENCRYPT_SC are both 0x0200 and are
// distinguished only by direction, so there is a single constant here.
enum SecurityFlag : uint16_t {
    kSecExchangePkt = 0x0001,
    kSecTransportReq = 0x0002,
    kSecTransportRsp = 0x0004,
    kSecEncrypt = 0x0008,
    kSecResetSeqno = 0x0010,   // defined but MUST be ignored
    kSecIgnoreSeqno = 0x0020,  // defined but MUST be ignored
    kSecInfoPkt = 0x0040,
    kSecLicensePkt = 0x0080,
    kSecLicenseEncrypt = 0x0200,  // CS when S->C, SC when C->S
    kSecRedirectionPkt = 0x0400,
    kSecSecureChecksum = 0x0800,
    kSecAutodetectReq = 0x1000,
    kSecAutodetectRsp = 0x2000,
    kSecHeartbeat = 0x4000,
    kSecFlagsHiValid = 0x8000,
};

// TS_SHARECONTROLHEADER ([MS-RDPBCGR] 2.2.8.1.1.1.1), 6 bytes.
struct ShareControlHeader {
    static constexpr size_t kSize = 6;
    static constexpr uint16_t kProtocolVersion = 0x1;
    // totalLength == 0x8000 means the frame may be a T.128 FlowPDU and MUST be
    // ignored; the real length then has to come from the MCS payload.
    static constexpr uint16_t kFlowPduMarker = 0x8000;

    uint16_t total_length = kSize;
    SharePduType type = SharePduType::kData;
    uint16_t pdu_version = kProtocolVersion;
    uint16_t pdu_source = 0;

    static Status parse(const uint8_t* data, size_t size, ShareControlHeader& out);
    void write(ByteWriter& w) const;
};

// TS_SHAREDATAHEADER ([MS-RDPBCGR] 2.2.8.1.1.1.2), 18 bytes: the share control
// header plus 12 more bytes.
struct ShareDataHeader {
    static constexpr size_t kSize = 18;

    ShareControlHeader control;
    uint32_t share_id = 0;
    uint8_t pad1 = 0;              // pure padding, observed values vary
    uint8_t stream_id = 0;
    uint16_t uncompressed_length = 0;  // declared, not validated (see spec)
    ShareDataPduType pdu_type2 = ShareDataPduType::kUpdate;
    uint8_t compressed_type = 0;
    uint16_t compressed_length = 0;

    static Status parse(const uint8_t* data, size_t size, ShareDataHeader& out);
    void write(ByteWriter& w) const;
};

// How many bytes of security header precede the payload. This is decided by the
// negotiated encryption level and method, never by the flags field.
enum class SecurityHeaderKind : uint8_t {
    kNone = 0,      // EncryptionLevel NONE and method NONE
    kBasic = 4,     // TS_SECURITY_HEADER
    kNonFips = 12,  // TS_SECURITY_HEADER1 (4 + 8-byte MAC)
    kFips = 16,     // TS_SECURITY_HEADER2
};

// Picks the header kind from the negotiated parameters.
//
// Exception: the Client Info and licensing PDUs always carry a security header
// even when no encryption is in effect, so callers pass `force_basic` for them.
SecurityHeaderKind SelectSecurityHeader(uint32_t encryption_level,
                                        uint32_t encryption_method,
                                        bool force_basic = false);

// A parsed security header. Only the fields that the selected kind defines are
// meaningful; the rest stay zero.
struct SecurityHeader {
    static constexpr size_t kBasicSize = 4;
    static constexpr size_t kNonFipsSize = 12;
    static constexpr size_t kFipsSize = 16;

    SecurityHeaderKind kind = SecurityHeaderKind::kNone;
    uint16_t flags = 0;
    uint16_t flags_hi = 0;  // fixed 2 bytes, valid only with kSecFlagsHiValid
    std::vector<uint8_t> signature;  // 8 bytes for NonFips/Fips
    uint16_t fips_length = 0;        // FIPS only, MUST be 0x0010
    uint8_t fips_version = 0;        // FIPS only, SHOULD be 1
    uint8_t padlen = 0;              // FIPS only

    size_t size() const { return static_cast<size_t>(kind); }
    bool has_mac() const { return !signature.empty(); }

    static Status parse(const uint8_t* data, size_t size, SecurityHeaderKind kind,
                        SecurityHeader& out);
    void write(ByteWriter& w) const;
};

// ---- Fast-Path ------------------------------------------------------------

// action, the low 2 bits of the first byte ([MS-RDPBCGR] 2.2.8.1.2 / 2.2.9.1.2).
enum class FastPathAction : uint8_t {
    kFastPath = 0x0,
    kX224 = 0x3,  // slow-path: the first byte is the TPKT version (0x03)
};

// Fast-path input event codes ([MS-RDPBCGR] 2.2.8.1.2.2).
enum class FastPathInputEventCode : uint8_t {
    kScancode = 0x0,
    kMouse = 0x1,
    kMouseX = 0x2,
    kSync = 0x3,
    kUnicode = 0x4,
    kMouseRel = 0x5,
    kQoeTimestamp = 0x6,
};

// messageType of a slow-path TS_INPUT_EVENT ([MS-RDPBCGR] 2.2.8.1.1.3.1.1).
// These are NOT the fast-path event codes above and are not a 0..4 sequence:
// the specification assigns 0x0000/0x0002/0x0004/0x0005/0x8001/0x8002/0x8004.
enum class SlowPathInputEventType : uint16_t {
    kSync = 0x0000,
    kUnused = 0x0002,
    kScancode = 0x0004,
    kUnicode = 0x0005,
    kMouse = 0x8001,
    kMouseX = 0x8002,
    kMouseRel = 0x8004,
};

// A slow-path TS_INPUT_EVENT is eventTime(4) + messageType(2) + a 6-byte event
// body (TS_KEYBOARD_EVENT, TS_UNICODE_KEYBOARD_EVENT, TS_POINTER_EVENT,
// TS_POINTERX_EVENT, TS_SYNC_EVENT and TS_UNUSED_EVENT are each 6 bytes), so
// every defined event occupies exactly 12 bytes.
constexpr size_t kSlowPathInputEventHeaderSize = 6;
constexpr size_t kSlowPathInputEventSize = 12;

// Fast-path update codes ([MS-RDPBCGR] 2.2.9.1.2.1).
enum class FastPathUpdateCode : uint8_t {
    kOrders = 0x0,
    kBitmap = 0x1,
    kPalette = 0x2,
    kSynchronize = 0x3,
    kSurfaceCommands = 0x4,
    kPtrNull = 0x5,
    kPtrDefault = 0x6,
    kPtrPosition = 0x8,
    kColorPointer = 0x9,
    kCachedPointer = 0xA,
    kPointer = 0xB,
    kLargePointer = 0xC,
};

// Fast-path fragmentation state ([MS-RDPBCGR] 2.2.9.1.2.1).
enum class FastPathFragmentation : uint8_t {
    kSingle = 0x0,
    kLast = 0x1,
    kFirst = 0x2,
    kNext = 0x3,
};

// Decides whether the first byte starts a fast-path or a slow-path PDU.
// Returns false for the two undefined action values (0x1 / 0x2).
bool ClassifyFastPath(uint8_t first_byte, FastPathAction& out);

// Fast-path length encoding: 1 byte when bit7 is clear, otherwise a big-endian
// pair (length1 & 0x7F) << 8 | length2. This is the only big-endian length in
// RDP, which makes it a frequent source of bugs.
struct FastPathLength {
    static constexpr size_t kMax = 32767;

    size_t value = 0;
    bool two_byte = false;

    static Status parse(const uint8_t* data, size_t size, FastPathLength& out);
    void write(ByteWriter& w) const;
};

// The 1-byte fast-path header.
//   input : action[1:0] | numEvents[5:2] | flags[7:6]
//   output: action[1:0] | reserved[5:2] | flags[7:6]
struct FastPathHeader {
    static constexpr size_t kSize = 1;

    FastPathAction action = FastPathAction::kFastPath;
    uint8_t count_or_reserved = 0;  // numEvents for input, reserved for output
    uint8_t flags = 0;

    static Status parse(const uint8_t* data, size_t size, bool input,
                        FastPathHeader& out);
    void write(ByteWriter& w, bool input) const;
};

// A parsed Fast-Path PDU: header, length and the body that follows.
struct FastPathPdu {
    FastPathHeader header;
    FastPathLength length;
    // Bytes between the length field and the end of the PDU (this may include
    // fipsInformation, the MAC, and the extended numEvents byte).
    std::vector<uint8_t> body;

    // Parses one complete fast-path PDU. `size` must be at least
    // length.value; trailing bytes are ignored so a caller can chain PDUs.
    static Status parse(const uint8_t* data, size_t size, bool input,
                        FastPathPdu& out);
};

// Fixed wire size of a fast-path input event, or 0 for an unknown eventCode.
size_t FastPathInputEventSize(FastPathInputEventCode code);

// TS_REFRESH_RECT_PDU body ([MS-RDPBCGR] 2.2.11.2.1): the client asks the
// server to (re)send the display data for the given inclusive rectangles.
struct RefreshRectPdu {
    struct Rect {
        uint16_t left = 0;
        uint16_t top = 0;
        uint16_t right = 0;    // inclusive
        uint16_t bottom = 0;   // inclusive
    };

    std::vector<Rect> rectangles;

    // numberOfAreas(1) + pad3Octets(3) + areas * 8 bytes
    // ([MS-RDPBCGR] 2.2.11.2.1; FreeRDP update_write_refresh_rect: count +
    // Seek(3)). numberOfAreas is a u8, so at most 255 rectangles can be
    // encoded; every caller here sends exactly one full-desktop area.
    std::vector<uint8_t> encode() const;
    static Status parse(const uint8_t* data, size_t size, RefreshRectPdu& out);
};

// TS_SUPPRESS_OUTPUT_PDU body ([MS-RDPBCGR] 2.2.11.3.1): the client gates the
// server's desktop output. With allowDisplayUpdates=1 the PDU carries the
// desktop rectangle and the server answers with a Refresh Rect (mstsc
// behavior); with 0 it is just the 4-byte header.
struct SuppressOutputPdu {
    bool allow_display_updates = false;
    std::vector<RefreshRectPdu::Rect> rectangles;

    // allowDisplayUpdates(1) + pad3Octets(3) + desktopRect(8), where the
    // desktopRect is present if and only if allowDisplayUpdates == 1. There is
    // no count field and no rectangle array.
    static Status parse(const uint8_t* data, size_t size, SuppressOutputPdu& out);
};

// Human-readable text for a Set Error Info errorInfo code ([MS-RDPBCGR]
// 2.2.5.1.1). Covers the protocol-independent codes (0x00..0x1A) that explain
// an ordinary session disconnect; anything else reports "unknown error".
const char* SetErrorInfoText(uint32_t error_info);

}  // namespace rtsc::proto
