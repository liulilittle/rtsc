// Clipboard virtual channel (cliprdr) structure layer ([MS-RDPECLIP] 2.2).
//
// Reference: [MS-RDPECLIP] 2.2.1 (header) and 2.2.2 (message payloads).
//
// This module covers the CLIPRDR_HEADER, the format list, the format data
// request / response, and the capability exchange payload. The channel runs
// over a static virtual channel, so each PDU here is the channel data that a
// ChannelPduHeader wraps.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// CLIPRDR_HEADER.msgType ([MS-RDPECLIP] 2.2.1).
enum class CliprdrMsgType : uint16_t {
    kMonitorReady = 0x0001,
    kFormatList = 0x0002,
    kFormatListResponse = 0x0003,
    kFormatDataRequest = 0x0004,
    kFormatDataResponse = 0x0005,
    kTempDirectory = 0x0006,
    kClipCaps = 0x0007,
    kFileContentsRequest = 0x0008,
    kFileContentsResponse = 0x0009,
    kLockClipData = 0x000A,
    kUnlockClipData = 0x000B,
};

const char* to_string(CliprdrMsgType type);

// CLIPRDR_HEADER.msgFlags.
enum CliprdrMsgFlag : uint16_t {
    kClipResponseOk = 0x0001,
    kClipResponseFail = 0x0002,
    kClipAsciiNames = 0x0004,
};

// Standard clipboard format IDs ([MS-RDPECLIP] 2.2.3.1).
enum CliprdrFormat : uint32_t {
    kCfText = 1,
    kCfBitmap = 2,
    kCfDib = 8,
    kCfUnicodeText = 13,
    kCfHdrop = 15,
    kCfDibV5 = 17,
};

// CLIPRDR_HEADER ([MS-RDPECLIP] 2.2.1), 8 bytes.
struct CliprdrHeader {
    static constexpr size_t kSize = 8;

    CliprdrMsgType msg_type = CliprdrMsgType::kMonitorReady;
    uint16_t msg_flags = 0;
    uint32_t data_len = 0;

    static Status parse(const uint8_t* data, size_t size, CliprdrHeader& out);
    void write(ByteWriter& w) const;
};

// A parsed cliprdr PDU: header + payload.
struct CliprdrPdu {
    CliprdrHeader header;
    std::vector<uint8_t> data;

    static Status parse(const uint8_t* data, size_t size, CliprdrPdu& out);
};

// Builds a complete cliprdr PDU (header + payload).
std::vector<uint8_t> BuildCliprdrPdu(CliprdrMsgType type, uint16_t flags,
                                     const std::vector<uint8_t>& data);

// CB_FORMAT_LIST: a sequence of little-endian u32 format IDs.
struct CliprdrFormatList {
    std::vector<uint32_t> formats;

    static Status parse(const std::vector<uint8_t>& data, CliprdrFormatList& out);
    std::vector<uint8_t> encode() const;
};

// CB_FORMAT_DATA_REQUEST: a single requested format ID.
struct CliprdrFormatDataRequest {
    uint32_t format_id = 0;

    static Status parse(const std::vector<uint8_t>& data,
                        CliprdrFormatDataRequest& out);
    std::vector<uint8_t> encode() const;
};

// CB_FILECONTENTS_REQUEST dwFlags ([MS-RDPECLIP] 2.2.5.3).
enum CliprdrFileContentsFlag : uint32_t {
    kFileContentsSize = 0x00000001,
    kFileContentsRange = 0x00000002,
};

// CLIPRDR_FILECONTENTS_REQUEST ([MS-RDPECLIP] 2.2.5.3). The fixed header is 24
// bytes (streamID..cbRequested) followed by an optional clipDataId(4) used for
// clip-data locking: a request is 24 or 28 bytes on the wire. There is no
// presence field; the extra 4 bytes are the id itself.
struct CliprdrFileContentsRequest {
    uint32_t stream_id = 0;
    int32_t lindex = 0;
    uint32_t dw_flags = 0;
    uint32_t n_position_low = 0;
    uint32_t n_position_high = 0;
    uint32_t cb_requested = 0;
    bool has_clip_data_id = false;
    uint32_t clip_data_id = 0;

    static Status parse(const std::vector<uint8_t>& body,
                        CliprdrFileContentsRequest& out);
    std::vector<uint8_t> encode() const;
};

// CLIPRDR_FILECONTENTS_RESPONSE ([MS-RDPECLIP] 2.2.5.4): a streamID followed
// by the requested bytes. The PDU header flags carry the OK/FAIL verdict; a
// FAIL response has no useful payload.
struct CliprdrFileContentsResponse {
    uint32_t stream_id = 0;
    std::vector<uint8_t> data;

    static Status parse(const std::vector<uint8_t>& body, bool ok,
                        CliprdrFileContentsResponse& out);
    std::vector<uint8_t> encode(bool ok) const;
};

// FILE_ATTRIBUTE_DIRECTORY (Win32) reflected in the CLIPRDR descriptor.
constexpr uint32_t kFileAttributeDirectory = 0x00000010;

// FD_* flags for CliprdrFileDescriptor::dw_flags (Win32 FILEDESCRIPTORW).
constexpr uint32_t kFileDescriptorSize = 0x00000040;       // FD_FILESIZE
constexpr uint32_t kFileDescriptorAttributes = 0x00000004; // FD_ATTRIBUTES

// CLIPRDR_FILE_DESCRIPTOR ([MS-RDPECLIP] 2.2.5.2.3.1), fixed 592 bytes:
//   dwFlags | reserved1(32) | dwFileAttributes | reserved2(16) |
//   ftLastWriteTime(u64) | nFileSizeHigh | nFileSizeLow |
//   cFileName(520B UTF-16LE, <=260 code units incl. null, zero-padded).
struct CliprdrFileDescriptor {
    static constexpr size_t kSize = 592;

    uint32_t dw_flags = 0;
    uint32_t file_attributes = 0;
    uint64_t last_write_time = 0;
    uint64_t file_size = 0;
    std::u16string file_name;

    bool is_directory() const {
        return (file_attributes & kFileAttributeDirectory) != 0;
    }

    static Status parse(ByteReader& reader, CliprdrFileDescriptor& out);
    // Appends the descriptor to `w`; returns false (writing nothing) when
    // file_name does not fit the 520-byte name block.
    bool write(ByteWriter& w) const;
};

// CLIPRDR_FILELIST ([MS-RDPECLIP] 2.2.5.2): cItems(4) followed by cItems
// descriptors of CliprdrFileDescriptor::kSize bytes each.
struct CliprdrFileList {
    std::vector<CliprdrFileDescriptor> files;

    static Status parse(const std::vector<uint8_t>& data, CliprdrFileList& out);
    // Returns an empty vector on failure (a zero-file list encodes to a 4-byte
    // cItems, so an empty result is unambiguously an error).
    std::vector<uint8_t> encode() const;
};

// The registered clipboard format used to exchange file lists. Our
// advertisement uses kDeFactoFileListFormatId because Windows peers
// (re-)register the name locally and may hand out a different id per session;
// we always advertise the same private fallback id. UNVERIFIED against a real
// peer.
constexpr char16_t kFileGroupDescriptorName[] = u"FileGroupDescriptorW";
constexpr uint32_t kDeFactoFileListFormatId = 0x046C0000;

}  // namespace rtsc::proto
