#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// TS_SECURITY_HEADER flags ([MS-RDPBCGR] 2.2.8.1.1.2.1).
namespace sec {

constexpr uint16_t kSecExchangePkt = 0x0001;
constexpr uint16_t kSecEncrypt = 0x0008;
constexpr uint16_t kSecInfoPkt = 0x0040;
constexpr uint16_t kSecLicenseEncryptSc = 0x0200;
constexpr uint16_t kSecFlagshiValid = 0x8000;

}  // namespace sec

// TS_INFO_PACKET::flags ([MS-RDPBCGR] 2.2.1.11.1.1).
namespace info {

constexpr uint32_t kMouse = 0x00000001;
constexpr uint32_t kDisableCtrlAltDel = 0x00000002;
constexpr uint32_t kAutoLogon = 0x00000008;
constexpr uint32_t kUnicode = 0x00000010;
constexpr uint32_t kMaximizeShell = 0x00000020;
constexpr uint32_t kLogonNotify = 0x00000040;
constexpr uint32_t kCompression = 0x00000080;
constexpr uint32_t kCompressionTypeMask = 0x00001E00;
constexpr uint32_t kEnableWindowsKey = 0x00000100;
constexpr uint32_t kRemoteConsoleAudio = 0x00002000;
constexpr uint32_t kForceEncryptedCsPdu = 0x00004000;
constexpr uint32_t kRail = 0x00008000;
constexpr uint32_t kLogonErrors = 0x00010000;
constexpr uint32_t kMouseHasWheel = 0x00020000;
constexpr uint32_t kPasswordIsScPin = 0x00040000;
constexpr uint32_t kNoAudioPlayback = 0x00080000;
constexpr uint32_t kUsingSavedCreds = 0x00100000;
constexpr uint32_t kAudioCapture = 0x00200000;
constexpr uint32_t kVideoDisable = 0x00400000;
constexpr uint32_t kHidefRailSupported = 0x02000000;

// PACKET_COMPR_TYPE_* shifted into the CompressionTypeMask field.
constexpr uint32_t CompressionType(uint32_t type) {
    return (type << 9) & kCompressionTypeMask;
}

}  // namespace info

// TS_INFO_PACKET::performanceFlags ([MS-RDPBCGR] 2.2.5.1.1). The enable bits
// are what mstsc sends for full-quality sessions; a client that omits them
// gets aliased text and a non-composited desktop (the "screenshot" look).
namespace perf {

constexpr uint32_t kDisableWallpaper = 0x00000001;
constexpr uint32_t kDisableFullWindowDrag = 0x00000002;
constexpr uint32_t kDisableMenuAnimations = 0x00000004;
constexpr uint32_t kDisableTheming = 0x00000008;
constexpr uint32_t kDisableCursorShadow = 0x00000020;
constexpr uint32_t kDisableCursorSettings = 0x00000040;
constexpr uint32_t kEnableFontSmoothing = 0x00000080;
constexpr uint32_t kEnableDesktopComposition = 0x00000100;

}  // namespace perf

// TS_SYSTEMTIME (16 bytes, [MS-RDPBCGR] 2.2.1.11.1.1.1.1). wYear MUST be 0.
struct TsSystemTime {
    uint16_t year = 0;
    uint16_t month = 0;
    uint16_t day_of_week = 0;
    uint16_t day = 0;
    uint16_t hour = 0;
    uint16_t minute = 0;
    uint16_t second = 0;
    uint16_t milliseconds = 0;

    void write(ByteWriter& w) const;
    Status read(ByteReader& r);

    bool is_zero() const;
};

// TS_TIME_ZONE_INFORMATION (172 bytes, [MS-RDPBCGR] 2.2.1.11.1.1.1).
// Names are stored as UTF-8 and encoded as 32 fixed UTF-16LE units on the wire.
struct TsTimeZoneInformation {
    static constexpr size_t kWireSize = 172;
    static constexpr size_t kNameUnits = 32;

    int32_t bias = 0;
    std::string standard_name;
    TsSystemTime standard_date;
    int32_t standard_bias = 0;
    std::string daylight_name;
    TsSystemTime daylight_date;
    int32_t daylight_bias = 0;

    void write(ByteWriter& w) const;
    Status read(ByteReader& r);
};

// ARC_CS_PRIVATE_PACKET ([MS-RDPBCGR] 2.2.1.11.1.1.1.1). 28 bytes, opaque here.
struct ArcCsPrivatePacket {
    static constexpr size_t kWireSize = 28;
    std::vector<uint8_t> bytes;  // exactly kWireSize when present

    void write(ByteWriter& w) const;
    Status read(ByteReader& r);
};

// TS_EXTENDED_INFO_PACKET ([MS-RDPBCGR] 2.2.1.11.1.1.1).
// Presence is strictly chained: a field may only appear if every field before
// it is present.
struct TsExtendedInfoPacket {
    static constexpr uint16_t kAfInet = 0x0002;
    static constexpr uint16_t kAfInet6 = 0x0017;

    uint16_t client_address_family = kAfInet;
    std::string client_address;  // UTF-8; cbClientAddress includes the terminator
    std::string client_dir;      // UTF-8; cbClientDir includes the terminator

    bool has_time_zone = false;
    TsTimeZoneInformation time_zone;

    bool has_session_id = false;
    uint32_t session_id = 0;

    bool has_performance_flags = false;
    uint32_t performance_flags = 0;

    bool has_auto_reconnect = false;
    ArcCsPrivatePacket auto_reconnect_cookie;

    bool has_reserved = false;
    uint16_t reserved1 = 0;
    uint16_t reserved2 = 0;

    bool has_dynamic_dst = false;
    std::string dynamic_dst_time_zone_key_name;  // UTF-8, no terminator on the wire
    uint16_t dynamic_daylight_time_disabled = 0;

    // Encodes the packet, honouring the chained presence rules: a field is only
    // emitted when its flag is set, and all earlier fields are then emitted too.
    void write(ByteWriter& w, bool unicode) const;

    // Decodes as many fields as the remaining bytes allow, enforcing the chain.
    Status read(ByteReader& r, bool unicode);
};

// TS_INFO_PACKET ([MS-RDPBCGR] 2.2.1.11.1.1).
//
// Text fields are held as UTF-8. On the wire they are UTF-16LE when
// info::kUnicode is set, otherwise single-byte ANSI which this layer treats as
// Latin-1 (see docs/spec/mcs-domain.md §10.2 note 3). The cb* lengths always
// exclude the mandatory NUL terminator.
struct TsInfoPacket {
    uint32_t code_page = 0;
    uint32_t flags = 0;

    std::string domain;
    std::string user_name;
    std::string password;
    std::string alternate_shell;
    std::string working_dir;

    bool has_extended_info = false;
    TsExtendedInfoPacket extended_info;

    bool unicode() const { return (flags & info::kUnicode) != 0; }

    void write(ByteWriter& w) const;
    Status read(ByteReader& r);

    // Size of the encoded packet in bytes (used for buffer sizing and tests).
    size_t encoded_size() const;
};

// CLIENT_INFO_PDU = securityHeader + TS_INFO_PACKET ([MS-RDPBCGR] 2.2.1.11).
struct ClientInfoPdu {
    uint16_t security_flags = sec::kSecInfoPkt;
    uint16_t security_flags_hi = 0;
    TsInfoPacket info;

    // Builds the userData payload for an MCS Send Data Request.
    std::vector<uint8_t> build() const;

    static Status parse(const uint8_t* data, size_t size, ClientInfoPdu& out);
};

// TS_SECURITY_PACKET, the Security Exchange PDU payload ([MS-RDPBCGR] 2.2.1.10.1).
//
// The encryptedClientRandom buffer must already contain the RSA-encrypted
// 32-byte client random followed by zero padding up to (bitlen/8)+8 bytes; the
// RSA step belongs to the crypto layer, not to this protocol layer.
struct SecurityExchangePdu {
    uint16_t flags = static_cast<uint16_t>(sec::kSecExchangePkt | sec::kSecLicenseEncryptSc);
    uint16_t flags_hi = 0;
    std::vector<uint8_t> encrypted_client_random;

    // Buffer size mandated by [MS-RDPBCGR] 2.2.1.10.1.1 for a given key length.
    static size_t BufferSizeForKeyBits(uint32_t bit_length);

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, SecurityExchangePdu& out);
};

}  // namespace rtsc::proto
