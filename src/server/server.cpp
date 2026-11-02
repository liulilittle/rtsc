// RDP server role: the server half of the [MS-RDPBCGR] connection sequence.
//
// Reference: [MS-RDPBCGR] 1.3.1.1 / 3.2.5 / 3.3.5, [MS-RDPELE] 1.3, 2.2.
//
// This file implements include/rtsc/server/server.h. It is transport agnostic
// below the net::Transport seam and free of any platform header, so it builds
// unchanged on Windows and Linux (the Linux gate compiles it). Only the RSA
// backend is Windows-only; when a keypair cannot be generated the server fails
// closed to "no encryption" instead of serving with a broken key.
//
// Session isolation (D1): every accepted peer gets its own RdpSession with its
// own X.224/MCS state, security state, capability sets and framebuffer. The
// only objects shared between sessions are the immutable ServerConfig, the
// DesktopSource pointer and the Authenticator, all read-only during a session.

#include "rtsc/server/server.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <memory>
#include <new>
#include <mutex>
#include <set>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "rtsc/channel/cliprdr_server.h"
#include "rtsc/channel/rdpdr_server.h"
#include "rtsc/channel/rdpsnd_server.h"
#include "rtsc/clipboard/clipboard.h"
#include "rtsc/clipboard/file_list.h"
#include "rtsc/crypto/hash.h"
#include "rtsc/crypto/random.h"
#include "rtsc/crypto/rdp_security.h"
#include "rtsc/crypto/rsa_server.h"
#include "rtsc/net/tls.h"
#include "rtsc/net/transport.h"
#include "rtsc/security/server_security_layer.h"
#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/capabilities.h"
#include "rtsc/proto/client_info.h"
#include "rtsc/proto/connection_initiation.h"
#include "rtsc/proto/finalization.h"
#include "rtsc/proto/input.h"
#include "rtsc/proto/licensing.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/proto/share.h"
#include "rtsc/proto/tpkt.h"
#include "rtsc/proto/x224.h"
#include "rtsc/server/desktop_input.h"
#include "rtsc/server/desktop_input_map.h"

namespace rtsc::server {

namespace {

using proto::ByteReader;
using proto::ByteWriter;
using proto::Status;

// ---- GCC user data block types ([MS-RDPBCGR] 2.2.1.3.1 .. 2.2.1.4.3) --------
constexpr uint16_t kCsCore = 0xC001;
constexpr uint16_t kCsSecurity = 0xC002;
constexpr uint16_t kCsNetwork = 0xC003;
constexpr uint16_t kScCore = 0x0C01;
constexpr uint16_t kScSecurity = 0x0C02;
constexpr uint16_t kScNetwork = 0x0C03;

// ---- Standard RDP security constants ([MS-RDPBCGR] 2.2.1.4.3, 5.3) ----------
// encryptionMethods bits follow the specification, not the mislabeled
// RdpEncryptionMethod enum: 40BIT=0x01, 128BIT=0x02, 56BIT=0x08, FIPS=0x10.
constexpr uint32_t kMethod40 = 0x00000001;
constexpr uint32_t kMethod128 = 0x00000002;
constexpr uint32_t kMethod56 = 0x00000008;
constexpr uint32_t kMethodFips = 0x00000010;
constexpr uint32_t kLevelClientCompatible = 0x00000002;

// Security header flags this server emits.
constexpr uint16_t kSecEncrypt = 0x0008;
constexpr uint16_t kSecInfoPkt = 0x0040;
constexpr uint16_t kSecLicensePkt = 0x0080;

// MCS channel identifiers. The I/O channel and the user channel are the two the
// client joins; the server channel id is fixed by the specification.
constexpr uint16_t kIoChannelId = 1003;
constexpr uint16_t kUserChannelId = 1001;
constexpr uint16_t kServerChannelId = 1002;
constexpr uint16_t kFirstStaticChannelId = 1004;
// Upper bound on the static virtual channels one client may request. RDP peers
// request a handful; the bound keeps the channel table (and thus the Server
// Network Data channelIdArray) well inside the TPKT u16 length and the channel
// id range, while still covering every real client.
constexpr uint32_t kMaxStaticChannels = 32;

constexpr uint8_t kStreamLow = 0x01;
constexpr size_t kReadChunk = 16384;
// Period between active-phase desktop refreshes. Deliberately wall-clock based
// and independent of client input: resetting on input (the earlier idle-tick
// counter) froze the desktop whenever the client streamed input faster than
// the idle threshold could expire.
constexpr std::chrono::milliseconds kRefreshInterval{1000};

// ---- teardown failure injection (test-only) --------------------------------
// RdpServer::Stop() has two steps that can only fail under a real
// std::bad_alloc (the registry snapshot copy) or std::system_error (the
// condition-variable wait). Neither can be triggered deterministically from a
// test, so the test build of this file (RTSC_SERVER_TESTING) lets
// RTSC_TEST_STOP_FAIL force one of them on:
//   * "snapshot": the next snapshot copies behave as if the allocation failed;
//   * "wait": every condition-variable wait behaves as std::system_error.
// The production library does not contain this code (the macro is never
// defined there). Even when forced, Stop() must honour its contract -- deliver
// the stop request and never return early -- so the suite drives the shipped
// teardown paths rather than a test-only duplicate.
enum class StopFailureInjection { kNone, kSnapshot, kWait };

#if defined(RTSC_SERVER_TESTING)
StopFailureInjection StopFailureFromEnvironment() {
#if defined(_MSC_VER)
    char* buffer = nullptr;
    size_t length = 0;
    if (_dupenv_s(&buffer, &length, "RTSC_TEST_STOP_FAIL") != 0 ||
        buffer == nullptr) {
        return StopFailureInjection::kNone;
    }
    const std::string value(buffer);
    std::free(buffer);
#else
    const char* raw = std::getenv("RTSC_TEST_STOP_FAIL");
    if (raw == nullptr) return StopFailureInjection::kNone;
    const std::string value(raw);
#endif
    if (value == "snapshot") return StopFailureInjection::kSnapshot;
    if (value == "wait") return StopFailureInjection::kWait;
    return StopFailureInjection::kNone;
}
#else
StopFailureInjection StopFailureFromEnvironment() {
    return StopFailureInjection::kNone;
}
#endif

// Writes a BER length determinant (short form, or the 0x81 / 0x82 long form).
void WriteBerLength(ByteWriter& w, size_t len) {
    if (len < 0x80) {
        w.u8(static_cast<uint8_t>(len));
    } else if (len <= 0xFF) {
        w.u8(0x81);
        w.u8(static_cast<uint8_t>(len));
    } else {
        w.u8(0x82);
        w.u16be(static_cast<uint16_t>(len));
    }
}

// ---- Desktop geometry validation -------------------------------------------

// The session builds a framebuffer of width * height * 4 bytes and tiles it
// into bands whose row stride is width * 4. A zero width therefore divides by
// zero in SendFrame (65535 / chunk_row) and a zero height cannot be tiled, so
// a zero geometry is refused at the server entry points instead of being
// served. The entry points cover both sources of the geometry: the configured
// default (ServerConfig) and the client-declared TS_CLIENT_CORE_DATA size
// ([MS-RDPBCGR] 2.2.1.3.2), which falls back to the configured default when
// the client sends zero.
// Computes width * height * 4 without overflowing size_t. The product is only
// formed after a division-based check, so no geometry can wrap it into a small
// allocation. Callers use this before allocating a framebuffer.
bool FrameBufferBytes(uint16_t width, uint16_t height, size_t* out) {
    if (width == 0 || height == 0) return false;
    const size_t w = width;
    const size_t h = height;
    if (w > (SIZE_MAX / 4) / h) return false;
    *out = w * h * 4;
    return true;
}

// Clamps a requested geometry into the server limits (server.h kMaxDesktop*):
// each axis first, then both axes proportionally so the framebuffer fits
// kMaxFramebufferBytes. The aspect ratio survives the scale, and the clamped
// size is what Demand Active announces, so the client adapts to it.
void ClampDesktopSize(uint16_t width, uint16_t height, uint16_t* out_width,
                      uint16_t* out_height) {
    uint32_t w = std::min<uint32_t>(width, kMaxDesktopWidth);
    uint32_t h = std::min<uint32_t>(height, kMaxDesktopHeight);
    const uint64_t max_pixels = kMaxFramebufferBytes / 4;
    if (static_cast<uint64_t>(w) * h > max_pixels) {
        const double factor = std::sqrt(static_cast<double>(max_pixels) /
                                        (static_cast<double>(w) * h));
        w = std::max<uint32_t>(1, static_cast<uint32_t>(w * factor));
        h = std::max<uint32_t>(1, static_cast<uint32_t>(h * factor));
        // Rounding may still leave the product a pixel over the budget.
        while (static_cast<uint64_t>(w) * h > max_pixels) {
            if (w >= h && w > 1) {
                --w;
            } else if (h > 1) {
                --h;
            } else {
                break;
            }
        }
    }
    *out_width = static_cast<uint16_t>(w);
    *out_height = static_cast<uint16_t>(h);
}

bool ValidateDesktopSize(uint16_t width, uint16_t height, std::string* error) {
    if (width == 0 || height == 0) {
        if (error != nullptr) {
            *error = "the desktop geometry must be non-zero (got " +
                     std::to_string(width) + "x" + std::to_string(height) + ")";
        }
        return false;
    }
    size_t bytes = 0;
    if (!FrameBufferBytes(width, height, &bytes) ||
        width > kMaxDesktopWidth || height > kMaxDesktopHeight ||
        bytes > kMaxFramebufferBytes) {
        if (error != nullptr) {
            *error = "the configured desktop geometry " + std::to_string(width) +
                     "x" + std::to_string(height) + " exceeds the server limit (" +
                     std::to_string(kMaxDesktopWidth) + "x" +
                     std::to_string(kMaxDesktopHeight) + ", " +
                     std::to_string(kMaxFramebufferBytes) +
                     "-byte framebuffer)";
        }
        return false;
    }
    return true;
}

// ---- Server GCC user data blocks -------------------------------------------

// Each helper returns the block payload; BuildConnectResponse wraps it with the
// 4-byte TS_UD_HEADER.

std::vector<uint8_t> BuildServerCoreBody(uint32_t client_requested_protocols) {
    ByteWriter body;
    body.u32le(0x00080004);  // RDP 5.0
    body.u32le(client_requested_protocols);
    return body.take();
}

// TS_UD_SC_SEC1. When method and level are both zero the serverRandomLen /
// serverCertLen / serverRandom / serverCertificate fields MUST NOT be present.
std::vector<uint8_t> BuildServerSecurityBody(uint32_t method, uint32_t level,
                                             const std::vector<uint8_t>& random,
                                             const std::vector<uint8_t>& cert) {
    ByteWriter body;
    body.u32le(method);
    body.u32le(level);
    if (method != 0 || level != 0) {
        body.u32le(static_cast<uint32_t>(random.size()));
        body.u32le(static_cast<uint32_t>(cert.size()));
        if (!random.empty()) body.bytes(random.data(), random.size());
        if (!cert.empty()) body.bytes(cert.data(), cert.size());
    }
    return body.take();
}

std::vector<uint8_t> BuildServerNetworkBody(uint16_t io_channel,
                                            const std::vector<uint16_t>& channels) {
    ByteWriter body;
    body.u16le(io_channel);
    body.u16le(static_cast<uint16_t>(channels.size()));
    for (uint16_t id : channels) body.u16le(id);
    if ((channels.size() & 1u) != 0) body.u16le(0);  // Pad when the count is odd.
    return body.take();
}

// ---- X.224 -----------------------------------------------------------------

std::vector<uint8_t> BuildX224Pdu(uint8_t code, const std::vector<uint8_t>& body) {
    proto::X224Tpdu tpdu;
    tpdu.code = code;
    tpdu.source_reference = proto::X224Tpdu::kCcfSourceReference;
    tpdu.length_indicator = static_cast<uint8_t>(proto::X224Tpdu::kSize + body.size());
    const auto tpdu_bytes = tpdu.encode();

    const size_t total = proto::TpktHeader::kSize + tpdu_bytes.size() + body.size();
    proto::TpktHeader tpkt;
    tpkt.length = static_cast<uint16_t>(total);

    ByteWriter w;
    const auto tpkt_bytes = tpkt.encode();
    w.bytes(tpkt_bytes.data(), tpkt_bytes.size());
    w.bytes(tpdu_bytes.data(), tpdu_bytes.size());
    if (!body.empty()) w.bytes(body.data(), body.size());
    return w.take();
}

// RDP_NEG_RSP: type(1) flags(1) length(2)=8 selectedProtocol(4).
std::vector<uint8_t> BuildX224Confirm(uint32_t selected_protocol) {
    ByteWriter b;
    b.u8(static_cast<uint8_t>(proto::NegType::kResponse));
    b.u8(0);  // flags
    b.u16le(8);
    b.u32le(selected_protocol);
    return BuildX224Pdu(proto::X224Tpdu::kConnectionConfirm, b.take());
}

// RDP_NEG_FAILURE: type(1) flags(1) length(2)=8 failureCode(4).
std::vector<uint8_t> BuildX224NegFailure(uint32_t failure_code) {
    ByteWriter b;
    b.u8(static_cast<uint8_t>(proto::NegType::kFailure));
    b.u8(0);
    b.u16le(8);
    b.u32le(failure_code);
    return BuildX224Pdu(proto::X224Tpdu::kConnectionConfirm, b.take());
}

// ---- MCS -------------------------------------------------------------------

// Builds the TPKT-framed MCS Connect Response. The byte layout is the one the
// client parser (McsConnectResponse::parse) walks, and it matches the annotated
// [MS-RDPBCGR] 4.1.4 dump.
std::vector<uint8_t> BuildConnectResponse(
    const std::vector<proto::GccUserData::Block>& blocks) {
    ByteWriter block_bytes;
    for (const auto& b : blocks) proto::GccUserData::write_block(block_bytes, b.type, b.payload);
    const size_t s = block_bytes.size();

    // GCC Conference Create Response (T.124 ConnectData).
    ByteWriter gcc;
    static const uint8_t kOid[7] = {0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01};
    gcc.bytes(kOid, sizeof(kOid));
    gcc.u8(0x2A);  // connectPDU length determinant (ignored by the client)
    gcc.u8(0x14);  // CHOICE index 1 = conferenceCreateResponse
    gcc.u8(0x76); gcc.u8(0x0A);  // nodeID
    gcc.u8(0x01); gcc.u8(0x01);  // tag
    gcc.u8(0x00);                 // result = rt-successful
    gcc.u8(0x01);                 // UserData SET OF size = 1
    gcc.u8(0xC0);                 // value present + h221NonStandard
    gcc.u8(0x00);                 // h221 length - 4
    gcc.u8(0x4D); gcc.u8(0x63); gcc.u8(0x44); gcc.u8(0x6E);  // "McDn"
    if (s < 0x80) {
        gcc.u8(static_cast<uint8_t>(s));
    } else {
        gcc.u8(static_cast<uint8_t>(0x80 | (s >> 8)));
        gcc.u8(static_cast<uint8_t>(s & 0xFF));
    }
    gcc.bytes(block_bytes.data().data(), s);

    // BER body: result, calledConnectId, domainParameters, userData.
    ByteWriter body;
    body.u8(0x0A); body.u8(0x01); body.u8(0x00);  // result ENUMERATED 0
    body.u8(0x02); body.u8(0x01); body.u8(0x00);  // calledConnectId INTEGER 0
    body.u8(0x30); body.u8(0x1A);                 // SEQUENCE, 26 bytes
    static const uint8_t kDomain[26] = {
        0x02, 0x01, 0x22, 0x02, 0x01, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xFF, 0xF8, 0x02,
        0x01, 0x02};
    body.bytes(kDomain, sizeof(kDomain));
    body.u8(0x04);  // userData OCTET STRING
    WriteBerLength(body, gcc.size());
    body.bytes(gcc.data().data(), gcc.size());

    const size_t body_len = body.size();
    const size_t ber_len_size = body_len < 0x80 ? 1 : (body_len <= 0xFF ? 2 : 3);
    const size_t total =
        proto::TpktHeader::kSize + 3 + 2 + ber_len_size + body_len;  // 3 = X.224 Data
    proto::TpktHeader tpkt;
    tpkt.length = static_cast<uint16_t>(total);

    ByteWriter w;
    const auto tpkt_bytes = tpkt.encode();
    w.bytes(tpkt_bytes.data(), tpkt_bytes.size());
    w.u8(0x02); w.u8(0xF0); w.u8(0x80);
    w.u8(proto::mcs::kTagConnectInitial);
    w.u8(proto::mcs::kConnectResponseTagByte);
    WriteBerLength(w, body_len);
    w.bytes(body.data().data(), body.size());
    return w.take();
}

// Wraps a DomainMCSPDU body in TPKT + X.224 Data (the MCS framing).
std::vector<uint8_t> BuildMcsFrame(const std::vector<uint8_t>& body) {
    const size_t total = proto::TpktHeader::kSize + 3 + body.size();
    proto::TpktHeader tpkt;
    tpkt.length = static_cast<uint16_t>(total);

    ByteWriter w;
    const auto tpkt_bytes = tpkt.encode();
    w.bytes(tpkt_bytes.data(), tpkt_bytes.size());
    w.u8(0x02); w.u8(0xF0); w.u8(0x80);
    if (!body.empty()) w.bytes(body.data(), body.size());
    return w.take();
}

// Attach User Confirm: octet0 = choice(11)<<2 | initiator-present(1), octet1 =
// result, then the initiator UserId.
std::vector<uint8_t> BuildAttachUserConfirm(uint16_t initiator) {
    ByteWriter body;
    body.u8(static_cast<uint8_t>((proto::mcs::kAttachUserConfirm << 2) | 0x02));
    body.u8(0x00);
    body.u16be(static_cast<uint16_t>(initiator - proto::mcs::kMinDynamicChannelId));
    return BuildMcsFrame(body.take());
}

// Channel Join Confirm: result(0), initiator UserId, requested channel id, and
// the granted channel id (always present and equal to the request).
std::vector<uint8_t> BuildChannelJoinConfirm(uint16_t initiator, uint16_t requested,
                                             uint16_t channel) {
    ByteWriter body;
    body.u8(static_cast<uint8_t>((proto::mcs::kChannelJoinConfirm << 2) | 0x02));
    body.u8(0x00);
    body.u16be(static_cast<uint16_t>(initiator - proto::mcs::kMinDynamicChannelId));
    body.u16be(requested);
    body.u16be(channel);
    return BuildMcsFrame(body.take());
}

// Extracts the GCC user data blocks from a Connect Initial's T.124 ConnectData.
bool ExtractGccBlocks(const std::vector<uint8_t>& gcc, proto::GccUserData& out) {
    ByteReader r(gcc.data(), gcc.size());
    if (!r.skip(7)) return false;  // t124Identifier
    size_t declared = 0;
    if (proto::mcs::decode_per_length(r, declared) != Status::Ok) return false;
    if (!r.skip(8 + 4)) return false;  // CCrq header + "Duca"
    size_t block_len = 0;
    if (proto::mcs::decode_per_length(r, block_len) != Status::Ok) return false;
    if (block_len > r.remaining()) return false;
    return proto::GccUserData::parse(r.cursor(), block_len, out) == Status::Ok;
}

// ---- Server capability sets (Demand Active) --------------------------------

std::vector<proto::CapabilitySet> BuildServerCapabilities(uint16_t width,
                                                          uint16_t height,
                                                          uint16_t depth) {
    std::vector<proto::CapabilitySet> sets;

    proto::GeneralCapabilitySet general;
    general.os_major_type = 0x0001;  // Windows
    general.os_minor_type = 0x0003;  // Windows NT
    // Fast-path output is what this server actually sends.
    general.extra_flags = proto::GeneralCapabilitySet::kFastpathOutputSupported;
    sets.push_back(general.encode());

    proto::BitmapCapabilitySet bitmap;
    bitmap.preferred_bits_per_pixel = depth;
    bitmap.desktop_width = width;
    bitmap.desktop_height = height;
    bitmap.bitmap_compression_flag = 1;      // MUST
    bitmap.multiple_rectangle_support = 1;   // MUST
    sets.push_back(bitmap.encode());

    proto::OrderCapabilitySet order;
    const size_t order_indices[] = {0x00, 0x01, 0x02};
    for (size_t idx : order_indices) {
        if (idx < order.order_support.size()) order.order_support[idx] = 1;
    }
    sets.push_back(order.encode());

    proto::PointerCapabilitySet pointer;
    pointer.color_pointer_cache_size = 32;
    pointer.pointer_cache_size = 32;
    sets.push_back(pointer.encode());

    proto::ShareCapabilitySet share;
    share.node_id = 0;
    sets.push_back(share.encode());

    proto::VirtualChannelCapabilitySet vc;
    vc.flags = proto::VirtualChannelCapabilitySet::kNoComp;
    sets.push_back(vc.encode());

    proto::FontCapabilitySet font;
    font.has_support_flags = true;
    font.font_support_flags = proto::FontCapabilitySet::kFontSupportFontList;
    sets.push_back(font.encode());

    proto::InputCapabilitySet input;
    sets.push_back(input.encode());

    return sets;
}

// TS_DEMAND_ACTIVE_PDU. totalLength = 18 + sourceDescriptor + combinedCapabilities
// (the capability sets themselves occupy combined - 4 bytes).
std::vector<uint8_t> BuildDemandActive(uint16_t pdu_source, uint32_t share_id,
                                       const std::string& source_descriptor,
                                       const std::vector<proto::CapabilitySet>& sets,
                                       uint32_t session_id) {
    ByteWriter caps;
    uint16_t count = 0;
    uint16_t combined = 0;
    proto::WriteCapabilitySets(caps, sets, count, combined);

    const size_t src_len = source_descriptor.size();
    const size_t total = 18 + src_len + combined;

    ByteWriter w;
    w.u16le(static_cast<uint16_t>(total));
    w.u16le(static_cast<uint16_t>(
        static_cast<uint16_t>(proto::SharePduType::kDemandActive) |
        (proto::ShareControlHeader::kProtocolVersion << 4)));
    w.u16le(pdu_source);
    w.u32le(share_id);
    w.u16le(static_cast<uint16_t>(src_len));
    w.u16le(combined);
    if (src_len != 0) {
        w.bytes(reinterpret_cast<const uint8_t*>(source_descriptor.data()), src_len);
    }
    w.u16le(count);
    w.u16le(0);  // pad2Octets
    w.bytes(caps.data().data(), caps.size());
    w.u32le(session_id);
    return w.take();
}

// Encodes a horizontal band (optionally a column slice of one) of a top-down
// RGBA framebuffer into an uncompressed bottom-up BGRA bitmap rectangle
// (32bpp). `full_width` is the desktop width (the source stride); the emitted
// rectangle covers columns [src_x, src_x + width) of rows [src_y, src_y +
// height).
std::vector<uint8_t> EncodeBitmapBand(uint16_t full_width, uint32_t src_x,
                                      uint16_t width, uint32_t src_y,
                                      uint16_t height,
                                      const std::vector<uint8_t>& rgba) {
    const size_t src_stride = static_cast<size_t>(full_width) * 4;
    const size_t row = static_cast<size_t>(width) * 4;
    std::vector<uint8_t> out(row * height);
    for (uint32_t r = 0; r < height; ++r) {
        const size_t s_row =
            (static_cast<size_t>(src_y) + r) * src_stride +
            static_cast<size_t>(src_x) * 4;
        const size_t d_row = static_cast<size_t>(height - 1 - r) * row;  // bottom-up
        for (uint32_t x = 0; x < width; ++x) {
            const size_t s = s_row + static_cast<size_t>(x) * 4;
            const size_t d = d_row + static_cast<size_t>(x) * 4;
            out[d + 0] = rgba[s + 2];  // B
            out[d + 1] = rgba[s + 1];  // G
            out[d + 2] = rgba[s + 0];  // R
            out[d + 3] = rgba[s + 3];  // A
        }
    }
    return out;
}

// TS_UPDATE_BITMAP_DATA for one band: numberRectangles(2) + TS_BITMAP_DATA (a
// single rectangle). The TS_GRAPHICS_UPDATE updateType is written by SendFrame.
std::vector<uint8_t> BuildBitmapBand(uint16_t width, uint16_t dest_left,
                                     uint16_t dest_y, uint16_t height,
                                     const std::vector<uint8_t>& pixels) {
    ByteWriter w;
    w.u16le(1);            // numberRectangles
    w.u16le(dest_left);    // destLeft
    w.u16le(dest_y);       // destTop
    // destRight/destBottom are INCLUSIVE coordinates: destRight - destLeft + 1
    // must equal width ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.2; mstsc drops the
    // rectangle when they disagree).
    w.u16le(static_cast<uint16_t>(dest_left + width - 1));   // destRight
    w.u16le(static_cast<uint16_t>(dest_y + height - 1));  // destBottom
    w.u16le(width);
    w.u16le(height);
    w.u16le(32);     // bitsPerPixel
    w.u16le(0);       // flags: no compression, no compression header
    w.u16le(static_cast<uint16_t>(pixels.size()));
    w.bytes(pixels.data(), pixels.size());
    return w.take();
}

// ---- Licensing -------------------------------------------------------------

// LICENSE_ERROR_MESSAGE with STATUS_VALID_CLIENT + ST_NO_TRANSITION: the client
// needs no license and the licensing phase is complete.
std::vector<uint8_t> BuildLicenseError() {
    proto::LicenseErrorMessage err;
    err.error_code = static_cast<uint32_t>(proto::LicenseErrorCode::kStatusValidClient);
    err.state_transition =
        static_cast<uint32_t>(proto::LicenseStateTransition::kNoTransition);
    return err.encode();
}

// ---- Session ---------------------------------------------------------------

// True only for the sharedPDUType values [MS-RDPBCGR] 2.2.8.1.1.1.2 actually
// defines. A length-based parse alone is not enough to call a payload a share
// data PDU: a fast-path input PDU whose bytes happen to form a valid
// TS_SHAREDATAHEADER (e.g. byte2=0x17/byte3=0x00 make pduType=DATA|version 1)
// must still reach the fast-path decoder. The whitelist is therefore consulted
// before marking the payload as consumed.
bool IsKnownShareDataPduType(proto::ShareDataPduType type) {
    switch (type) {
        case proto::ShareDataPduType::kUpdate:
        case proto::ShareDataPduType::kControl:
        case proto::ShareDataPduType::kPointer:
        case proto::ShareDataPduType::kInput:
        case proto::ShareDataPduType::kSynchronize:
        case proto::ShareDataPduType::kRefreshRect:
        case proto::ShareDataPduType::kPlaySound:
        case proto::ShareDataPduType::kSuppressOutput:
        case proto::ShareDataPduType::kShutdownRequest:
        case proto::ShareDataPduType::kShutdownDenied:
        case proto::ShareDataPduType::kSaveSessionInfo:
        case proto::ShareDataPduType::kFontList:
        case proto::ShareDataPduType::kFontMap:
        case proto::ShareDataPduType::kSetKeyboardIndicators:
        case proto::ShareDataPduType::kPersistentKeyList:
        case proto::ShareDataPduType::kBitmapCacheError:
        case proto::ShareDataPduType::kSetKeyboardImeStatus:
        case proto::ShareDataPduType::kOffscreenCacheError:
        case proto::ShareDataPduType::kSetErrorInfo:
        case proto::ShareDataPduType::kDrawNineGridError:
        case proto::ShareDataPduType::kDrawGdiPlusError:
        case proto::ShareDataPduType::kArcStatus:
        case proto::ShareDataPduType::kStatusInfo:
        case proto::ShareDataPduType::kMonitorLayout:
            return true;
    }
    return false;
}

// Decodes the button bits of a TS_FP_POINTER_EVENT / TS_FP_POINTERX_EVENT /
// TS_FP_RELPOINTER_EVENT ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.3/.4). A button bit is
// meaningful on its own: a release carries the same bit as the press and only
// omits PTRFLAGS_DOWN, so the identity must be decoded outside the "down"
// branch. `mouse_x` selects the PTRXFLAGS namespace, where the button bits are
// 0x0001/0x0002 instead of 0x1000/0x2000/0x4000.
void DecodePointerButtons(uint16_t pf, bool mouse_x, InputEvent& ev) {
    ev.button_down = (pf & proto::kPtrDown) != 0;
    if (mouse_x) {
        if ((pf & proto::kPtrXButton2) != 0) ev.button = 5;
        else if ((pf & proto::kPtrXButton1) != 0) ev.button = 4;
        return;
    }
    if ((pf & proto::kPtrButton3) != 0) ev.button = 3;
    else if ((pf & proto::kPtrButton2) != 0) ev.button = 2;
    else if ((pf & proto::kPtrButton1) != 0) ev.button = 1;
}

// Fills `ev` from the (pointerFlags, xPos, yPos) triple of a fast-path
// TS_FP_POINTER_EVENT / TS_FP_POINTERX_EVENT ([MS-RDPBCGR] 2.2.8.1.2.2.3/.4)
// or a slow-path TS_POINTER_EVENT / TS_POINTERX_EVENT (2.2.8.1.1.3.1.1.3/.4):
// the two payloads are identical, so one decoder keeps both wire formats
// producing the same InputEvent (P-10: no second semantic).
void DecodePointerEvent(uint16_t pf, uint16_t x_pos, uint16_t y_pos,
                        bool mouse_x, InputEvent& ev) {
    ev.kind = InputEvent::Kind::kMouse;
    const bool wheel =
        (pf & proto::kPtrWheel) != 0 || (pf & proto::kPtrHwheel) != 0;
    if (wheel) {
        // PTRFLAGS_WHEEL / PTRFLAGS_HWHEEL share one 9-bit two's-complement
        // rotation field ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.1): 0x0100 is its sign
        // bit, not a standalone negative flag, and the unit is WHEEL_DELTA
        // (120) per notch. WHEEL wins when a sender sets both bits.
        const bool vertical = (pf & proto::kPtrWheel) != 0;
        ev.kind = InputEvent::Kind::kWheel;
        ev.horizontal = !vertical;
        const uint16_t raw =
            static_cast<uint16_t>(pf & proto::kPtrWheelRotationMask);
        ev.wheel_delta =
            static_cast<int16_t>((raw & 0x0100) != 0 ? raw - 0x0200 : raw);
        // A wheel event must ignore every other pointer flag and both
        // coordinates ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.3). Leaving a button or a
        // stale position here would make the injection seam click or jump the
        // cursor on a plain scroll.
        ev.x = 0;
        ev.y = 0;
        return;
    }
    ev.x = x_pos;
    ev.y = y_pos;
    // PTRFLAGS_MOVE (0x0800): the pointer must move to (x, y). A button
    // release does NOT carry this bit, which is what makes "move" and
    // "release" distinguishable (P-5).
    ev.is_move = (pf & proto::kPtrMove) != 0;
    DecodePointerButtons(pf, mouse_x, ev);
}

// Server-wide desktop input control lease.
//
// Every session injects into the same physical desktop, so letting several
// sessions inject at once interleaves two peers' pointer/keyboard streams into
// one machine. ServerConfig::max_input_sessions caps how many sessions may hold
// the lease simultaneously (default 1). The first injectable decoded input
// event from a session acquires the lease; a session that arrives while every
// slot is taken is refused (and counted) for that event. There is deliberately
// no wait queue:
// the refused session tries again on its next event, so the lease moves to it as
// soon as a holder disconnects and releases.
struct InputLease {
    explicit InputLease(size_t max_sessions)
        : max_sessions(max_sessions),
          denied(std::make_shared<std::atomic<size_t>>(0)),
          release_failures(std::make_shared<std::atomic<size_t>>(0)) {}

    std::mutex mu;
    std::set<uint32_t> holders;  // input session ids currently injecting
    const size_t max_sessions;   // 0 = unlimited (explicit opt-out)
    std::shared_ptr<std::atomic<size_t>> denied;
    // Teardown calls whose sink release threw. The released key/button ups may
    // have been lost, so this is the only operator-visible signal of it.
    std::shared_ptr<std::atomic<size_t>> release_failures;
};

// One accepted peer. Owns its transport, its X.224/MCS state, its security
// state, its capability sets and its framebuffer. Nothing mutable is shared
// with another session: this is the D1 single-writer-per-session model.
class RdpSession {
 public:
    RdpSession(std::unique_ptr<net::Transport> transport, const ServerConfig& config,
               DesktopSource* source, Authenticator authenticator,
               InputCallback input_callback, uint32_t session_id,
               DesktopInputSink* input_sink, uint32_t input_session_id,
               clipboard::Clipboard* clipboard,
               clipboard::FileListProvider* file_provider,
               std::shared_ptr<std::atomic<size_t>> unknown_input_events,
               std::shared_ptr<std::atomic<size_t>> malformed_input_pdus,
               std::shared_ptr<InputLease> input_lease)
        : transport_(std::move(transport)),
          config_(config),
          source_(source),
          authenticator_(std::move(authenticator)),
          input_callback_(std::move(input_callback)),
          session_id_(session_id),
          input_sink_(input_sink),
          input_session_id_(input_session_id),
          unknown_input_events_(std::move(unknown_input_events)),
          malformed_input_pdus_(std::move(malformed_input_pdus)),
          input_lease_(std::move(input_lease)) {
        // One CliprdrServer per session, all sharing the borrowed local
        // clipboard (shared-desktop semantics). It is used only from this
        // session's thread. The send lambda reads cliprdr_channel_id_ at send
        // time (it is set later, when the client network data is parsed).
        if (clipboard != nullptr) {
            cliprdr_ = std::make_unique<rtsc::channel::CliprdrServer>(
                clipboard,
                [this](const std::vector<uint8_t>& message) {
                    if (cliprdr_channel_id_ == 0) return;
                    SendMcsUserData(cliprdr_channel_id_, message);
                });
            if (file_provider != nullptr) cliprdr_->SetFileListProvider(file_provider);
        }
        // One RdpdrServer per session for the rdpdr static virtual channel
        // (the minimum handshake; v1 announces no devices). Created whenever
        // the server is configured to run it; the client's channel id is
        // resolved later in DoConnectResponse, so the send lambda reads
        // rdpdr_channel_id_ at send time like the cliprdr one.
        if (config.enable_rdpdr_handshake) {
            rdpdr_ = std::make_unique<rtsc::channel::RdpdrServer>(
                [this](const std::vector<uint8_t>& message) {
                    if (rdpdr_channel_id_ == 0) return;
                    SendMcsUserData(rdpdr_channel_id_, message);
                });
        }
        // One RdpsndServer per session for the rdpsnd static virtual channel
        // (server-side audio output), each fed by its own capture source
        // created through the ServerConfig factory seam. Like the rdpdr and
        // cliprdr handlers it is started in ActiveLoop, and the send lambda
        // reads rdpsnd_channel_id_ at send time (resolved later, in
        // DoConnectResponse). With no factory configured nothing is created,
        // so the default configuration does not change.
        if (config.enable_rdpsnd && config.audio_source_factory) {
            auto audio_source = config.audio_source_factory();
            if (audio_source) {
                rdpsnd_ = std::make_unique<rtsc::channel::RdpsndServer>(
                    std::move(audio_source),
                    [this](const std::vector<uint8_t>& message) {
                        if (rdpsnd_channel_id_ == 0) return;
                        SendMcsUserData(rdpsnd_channel_id_, message);
                    });
            }
        }
    }

    // Serves the connection until the peer disconnects or Stop() is called.
    void Run() {
        if (!DoX224()) return;
        if (secure_requested_) {
            if (!DoSecureHandshake()) return;
        }
        if (!DoConnectResponse()) return;
        if (!DoChannelJoin()) return;
        if (!DoSecurityAndClientInfo()) return;
        if (!DoLicensing()) return;
        if (!DoDemandActive()) return;
        if (!DoFinalization()) return;
        ActiveLoop();
    }

    // Unblocks a pending Read() so the session thread can exit. This is the
    // only method meant to be called from another thread; todo: the thread
    // safety of the underlying transport Close is whatever the transport
    // provides (the TCP transport tolerates a concurrent close, other
    // transports should document the same).
    void Stop() {
        stop_requested_.store(true, std::memory_order_relaxed);
        if (transport_) transport_->Close();
    }

    // Releases the desktop input lease and every key/button this session still
    // holds. Called exactly once from the teardown paths, before the session
    // leaves the registry, so the borrowed sink is never used after the host has
    // destroyed it. A session that never acquired the lease never injected, so
    // it has nothing to release and does not call the sink.
    void ReleaseInput() {
        if (input_released_) return;
        input_released_ = true;
        // Drop any half-open PAUSE window so a later lease on this session
        // cannot inherit it.
        pause_filter_.Reset();
        if (!input_lease_held_) return;
        input_lease_held_ = false;
        // Release the sink BEFORE freeing the lease slot. ReleaseSession
        // appends this session's synthetic key/button ups while the lease is
        // still held; freeing the slot first would let another session acquire
        // it and queue a key-down that the worker can emit before those ups,
        // lifting the new holder's key.
        if (config_.enable_desktop_input && input_sink_ != nullptr) {
            try {
                input_sink_->ReleaseSession(input_session_id_);
            } catch (...) {
                // Teardown must still free the slot below: the flags above are
                // already set, so a skipped erase would leak it permanently.
                // Count it: the sink may have lost the synthetic ups, leaving
                // local keys/buttons down with no other visible signal.
                input_lease_->release_failures->fetch_add(
                    1, std::memory_order_relaxed);
            }
        }
        {
            std::lock_guard<std::mutex> lock(input_lease_->mu);
            input_lease_->holders.erase(input_session_id_);
        }
    }

    const Credentials& credentials() const { return credentials_; }
    bool active() const { return active_; }

    // Overwrites a string's bytes before they are freed. A plain memset can be
    // dropped as a dead store when the buffer is released right afterwards, so
    // the store goes through a volatile pointer.
    static void SecureWipe(std::string& s) noexcept {
        if (s.empty()) return;
        volatile char* p = &s[0];
        for (size_t i = 0; i < s.size(); ++i) p[i] = '\0';
        s.clear();
    }

    // Overwrites every credential field so no plaintext account material
    // survives in the freed heap block when the session object is released.
    void ScrubCredentials() noexcept {
        SecureWipe(credentials_.domain);
        SecureWipe(credentials_.user_name);
        SecureWipe(credentials_.password);
        SecureWipe(credentials_.alternate_shell);
        SecureWipe(credentials_.working_dir);
    }

    ~RdpSession() { ScrubCredentials(); }

 private:
    // Hands one decoded event to the sink, taking the lease only when the event
    // can actually become a platform input for THIS session. A non-injectable
    // event (kSync, kMouseRel, a zero scan code or code point, or a bare
    // kMouse) must not be able to hold the single lease: otherwise one SYNC
    // could starve every peer that really controls the desktop. A pure move
    // whose geometry is not mappable (AbsoluteMoveMappable false) is in the
    // same class: TranslateInput fail-closes it to no action, so taking the
    // lease for it would starve a session that can really inject. A session
    // that already holds the lease still forwards the event so the sink's
    // unsupported-event counter keeps counting it.
    void InjectIfLeasable(const InputEvent& ev) {
        if (input_sink_ == nullptr) return;
        // The PAUSE sequence (0xE1 envelope) has no faithful SendInput form and
        // must be dropped as a WHOLE, before the lease gate: otherwise it would
        // inject a bare NumLock down/up (toggling the local NumLock) and take
        // the single lease slot without producing a real action.
        if (pause_filter_.ShouldDrop(ev)) return;
        if (!input_lease_held_) {
            if (!IsInjectable(ev, inject_geometry_)) return;
            if (!AcquireInputLease()) return;
        }
        input_sink_->Inject(input_session_id_, ev);
    }

    // Returns true when this session may inject the current event. The first
    // injectable call takes a lease slot (unless the configured limit is
    // already reached, in which case the event is counted as denied); later
    // calls are cheap while the lease is held. A refused session retries on its
    // next injectable event, so it takes over when an earlier holder
    // disconnects -- no waiter queue is needed and a session that stops typing
    // does not block the hand-off.
    bool AcquireInputLease() {
        if (input_sink_ == nullptr || !config_.enable_desktop_input) return false;
        if (input_lease_held_) return true;
        if (input_lease_ == nullptr) return false;
        bool acquired = false;
        {
            std::lock_guard<std::mutex> lock(input_lease_->mu);
            // max_sessions == 0 is the explicit "unlimited" setting; otherwise
            // a slot must still be free.
            if (input_lease_->max_sessions == 0 ||
                input_lease_->holders.size() < input_lease_->max_sessions) {
                input_lease_->holders.insert(input_session_id_);
                acquired = true;
            }
        }
        if (!acquired) {
            input_lease_->denied->fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        input_lease_held_ = true;
        // The sink learns the geometry only for the session that may inject;
        // the negotiation stored it while the lease was still unheld.
        if (inject_geometry_known_) {
            input_sink_->SetGeometry(input_session_id_, inject_geometry_);
        }
        return true;
    }

    // ---- transport helpers -------------------------------------------------
    bool Send(const std::vector<uint8_t>& frame) {
        if (frame.empty()) return false;
        if (secure_) {
            const auto ct = sec_ ? sec_->SendPdu(frame) : std::vector<uint8_t>{};
            return !ct.empty() && transport_->Write(ct.data(), ct.size());
        }
        return transport_->Write(frame.data(), frame.size());
    }

    // Peels one TPKT frame out of `buf`. Returns false when `buf` does not yet
    // hold a complete frame.
    static bool ExtractFrame(std::vector<uint8_t>& buf, std::vector<uint8_t>& frame) {
        if (buf.size() < 2) return false;
        if (buf[0] != 0x03 || buf[1] != 0x00) return false;
        if (buf.size() < 4) return false;
        const size_t len = (static_cast<size_t>(buf[2]) << 8) | buf[3];
        if (len < 4) return false;
        if (buf.size() < len) return false;
        const auto begin = buf.begin();
        frame.assign(begin, begin + static_cast<std::ptrdiff_t>(len));
        buf.erase(begin, begin + static_cast<std::ptrdiff_t>(len));
        return true;
    }

    // Reads the next frame. `refresh_due` (optional) enables the active-phase
    // desktop refresh: when the read wait elapses and the wall clock has
    // passed `*refresh_due`, the desktop frame is re-sent on a fixed ~1 s
    // cadence, independent of whether the client is sending input. A refresh
    // send failure is fatal: the error is recorded and the read (and with it
    // the session) ends.
    bool ReadFrame(std::vector<uint8_t>& frame,
                   std::chrono::steady_clock::time_point* refresh_due = nullptr) {
        if (has_pending_) {
            frame = std::move(pending_);
            has_pending_ = false;
            return true;
        }
        for (;;) {
            if (secure_) {
                if (!secure_frames_.empty()) {
                    frame = std::move(secure_frames_.front());
                    secure_frames_.pop_front();
                    return true;
                }
            } else if (ExtractFrame(read_buf_, frame)) {
                return true;
            }
            uint8_t tmp[kReadChunk];
            const int n = transport_->Read(tmp, sizeof(tmp));
            if (n == net::kReadTimeout) {
                if (stop_requested_.load(std::memory_order_relaxed)) return false;
                const auto now = std::chrono::steady_clock::now();
                if (refresh_due != nullptr && !output_suppressed_) {
                    if (now >= *refresh_due) {
                        // Periodic desktop refresh: mstsc discards updates
                        // that arrive before its surface is ready, so the
                        // desktop is re-sent on a fixed ~1 s cadence. This is
                        // deliberately independent of client input — keying
                        // it off an idle counter reset by input froze the
                        // desktop exactly while the user was interacting.
                        // While the client has suppressed output
                        // ([MS-RDPBCGR] 2.2.11.3.1) nothing is sent; the
                        // stale deadline then makes the refresh fire as soon
                        // as output resumes.
                        *refresh_due = now + kRefreshInterval;
                        if (!SendFrame()) {
                            last_error_ = "periodic desktop refresh failed";
                            return false;
                        }
                    }
                }
                // cliprdr local-clipboard change detection on the same ~1 s
                // cadence. It is independent of display output suppression
                // (clipboard sync is not a display update) and of the
                // handshake (ReadFrame only passes refresh_due in the active
                // phase).
                if (refresh_due != nullptr && cliprdr_ != nullptr &&
                    now >= next_clipboard_poll_) {
                    next_clipboard_poll_ = now + kRefreshInterval;
                    cliprdr_->Poll(now);
                }
                // rdpsnd audio is pumped from the ActiveLoop body (every
                // iteration), not here: a client that keeps sending input
                // never lets ReadFrame time out, and pumping only on the
                // timeout path would silence audio exactly while the user is
                // interacting. The pump has its own 20 ms emission window, so
                // calling it on every iteration is cheap.
                continue;
            }
            if (n <= 0) return false;
            if (secure_) {
                auto frames = sec_->ReceivePdu(tmp, static_cast<size_t>(n));
                for (auto& f : frames) secure_frames_.push_back(std::move(f));
            } else {
                read_buf_.insert(read_buf_.end(), tmp, tmp + static_cast<size_t>(n));
            }
        }
    }

    // Wraps a share PDU (or any application data) in an MCS Send Data
    // Indication on `channel_id`, applying the session RC4 layer when
    // encryption is in effect. Static virtual channels (cliprdr) and the I/O
    // channel share this path; the two differ only in the channel id.
    bool SendMcsUserData(uint16_t channel_id,
                         const std::vector<uint8_t>& user_data) {
        std::vector<uint8_t> ud = user_data;
        if (encrypted_) {
            ud = EncryptPayload(kSecEncrypt, user_data);
            if (ud.empty()) return false;
        }
        const auto frame =
            proto::McsSendData::build_indication(kServerChannelId, channel_id, ud);
        return !frame.empty() && Send(frame);
    }

    // The I/O-channel form of SendMcsUserData (graphics / share PDUs).
    bool SendRawUserData(const std::vector<uint8_t>& user_data) {
        return SendMcsUserData(io_channel_, user_data);
    }

    // A licensing PDU carries its own Basic security header (SEC_LICENSE_PKT),
    // which the client's licensing machine expects; the session layer is applied
    // on top when encryption is in effect.
    bool SendLicensingPdu(const std::vector<uint8_t>& payload) {
        ByteWriter sh;
        sh.u16le(kSecLicensePkt);
        sh.u16le(0);
        std::vector<uint8_t> ud = sh.take();
        ud.insert(ud.end(), payload.begin(), payload.end());
        if (encrypted_) {
            ud = EncryptPayload(kSecEncrypt, ud);
            if (ud.empty()) return false;
        }
        const auto frame =
            proto::McsSendData::build_indication(kServerChannelId, io_channel_, ud);
        return !frame.empty() && Send(frame);
    }

    // ---- security header handling ------------------------------------------
    std::vector<uint8_t> EncryptPayload(uint16_t flags,
                                        const std::vector<uint8_t>& plain) {
        std::vector<uint8_t> data = plain;
        const auto mac = security_.Encrypt(data);
        ByteWriter w;
        w.u16le(flags);
        w.u16le(0);
        w.bytes(mac.data(), mac.size());
        w.bytes(data.data(), data.size());
        return w.take();
    }

    bool DecryptPayload(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
        if (in.size() < proto::SecurityHeader::kNonFipsSize) return false;
        std::array<uint8_t, 8> mac{};
        std::memcpy(mac.data(), in.data() + 4, mac.size());
        out.assign(in.begin() + proto::SecurityHeader::kNonFipsSize, in.end());
        return security_.Decrypt(out, mac);
    }

    // Applies the session RC4 layer to an inbound MCS userData when the session
    // is encrypted and the PDU is marked SEC_ENCRYPT. The decrypted result is
    // the plaintext PDU (still carrying its own Basic security header).
    bool DecryptIfEncrypted(std::vector<uint8_t>& ud) {
        if (!encrypted_ || ud.size() < 2) return true;
        const uint16_t flags =
            static_cast<uint16_t>(ud[0] | (ud[1] << 8));
        if ((flags & kSecEncrypt) == 0) return true;
        std::vector<uint8_t> plain;
        if (!DecryptPayload(ud, plain)) return false;
        ud = std::move(plain);
        return true;
    }

    // Unwraps an inbound graphics / finalization PDU. Those carry a security
    // header only when the session is encrypted.
    bool UnwrapInbound(const std::vector<uint8_t>& user_data,
                       std::vector<uint8_t>& out) {
        if (encrypted_) return DecryptPayload(user_data, out);
        out = user_data;
        return true;
    }

    // ---- connection sequence -----------------------------------------------
    bool DoX224() {
        std::vector<uint8_t> frame;
        if (!ReadFrame(frame)) return false;
        proto::TpktHeader tpkt;
        if (proto::TpktHeader::parse(frame.data(), frame.size(), tpkt) != Status::Ok) {
            return false;
        }
        if (tpkt.length != frame.size()) return false;
        const uint8_t* p = frame.data() + proto::TpktHeader::kSize;
        const size_t n = frame.size() - proto::TpktHeader::kSize;
        proto::X224Tpdu tpdu;
        if (proto::X224Tpdu::parse(p, n, tpdu) != Status::Ok) return false;
        if (tpdu.code != proto::X224Tpdu::kConnectionRequest) return false;

        size_t off = proto::X224Tpdu::kSize;
        // Optional cookie / routing token, terminated by CRLF.
        if (off < n) {
            size_t end = off;
            while (end + 1 < n && !(p[end] == 0x0D && p[end + 1] == 0x0A)) ++end;
            if (end + 1 < n) off = end + 2;
        }
        if (off + 8 <= n && p[off] == 0x01) {  // TYPE_RDP_NEG_REQ
            requested_protocols_ = static_cast<uint32_t>(p[off + 4]) |
                                   (static_cast<uint32_t>(p[off + 5]) << 8) |
                                   (static_cast<uint32_t>(p[off + 6]) << 16) |
                                   (static_cast<uint32_t>(p[off + 7]) << 24);
        }

        // Enhanced security: accept PROTOCOL_SSL / PROTOCOL_HYBRID when the
        // server is configured for it. HYBRID additionally runs CredSSP (the
        // mstsc default); SSL is transport security only.
        if ((requested_protocols_ & (proto::kProtocolSsl | proto::kProtocolHybrid |
                                     proto::kProtocolHybridEx)) != 0 &&
            config_.enable_enhanced_security) {
            // [MS-RDPBCGR] 2.2.1.2.1 / 2.2.10.2: HYBRID_EX selects CredSSP plus
            // the Early User Authorization Result PDU; plain HYBRID selects
            // CredSSP only. mstsc advertises 0x0B and expects HYBRID_EX (0x8)
            // back, so selecting 0x2 while still sending the EUAR makes it
            // report a protocol error (0x1204) and reset.
            if ((requested_protocols_ & proto::kProtocolHybridEx) != 0) {
                selected_protocol_ = proto::kProtocolHybridEx;
                credssp_required_ = true;
                euar_required_ = true;
            } else if ((requested_protocols_ & proto::kProtocolHybrid) != 0) {
                selected_protocol_ = proto::kProtocolHybrid;
                credssp_required_ = true;
                euar_required_ = false;
            } else {
                selected_protocol_ = proto::kProtocolSsl;
                credssp_required_ = false;
                euar_required_ = false;
            }
            secure_requested_ = true;
            Send(BuildX224Confirm(selected_protocol_));
            return true;
        }

        if (requested_protocols_ != 0 && config_.require_external_security) {
            // This server implements Standard RDP Security only. A client that
            // insists on external security is told so explicitly.
            Send(BuildX224NegFailure(
                static_cast<uint32_t>(proto::NegFailureCode::kHybridRequiredByServer)));
            return false;
        }
        Send(BuildX224Confirm(0));
        return true;
    }

    // Runs the TLS accept plus CredSSP server plus EUAR. On success every
    // subsequent read/write is encrypted through `sec_`.
    bool DoSecureHandshake() {
        security::ServerConfig scfg;
        scfg.tls_config = config_.tls_config;
        scfg.tls_config.role = tls::Role::kServer;
        scfg.credssp_version = config_.credssp_version;
        scfg.credential_lookup = config_.credential_lookup;
        scfg.credssp_required = credssp_required_;
        scfg.euar_required = euar_required_;
        sec_ = security::ServerSecurityLayer::Create(scfg, last_error_);
        if (!sec_) return false;

        std::vector<uint8_t> pending;
        for (;;) {
            const security::StepResult r = sec_->Step(pending.data(), pending.size());
            pending.clear();
            if (r.want == security::Want::kWrite) {
                if (!r.to_wire.empty() &&
                    !transport_->Write(r.to_wire.data(), r.to_wire.size())) {
                    return false;
                }
                continue;
            }
            if (r.want == security::Want::kDone) {
                secure_ = true;
                // With PROTOCOL_HYBRID the client pipelines the MCS Connect
                // Initial right behind CredSSP step 5 (no EUAR to wait for).
                // Any complete PDU already sitting in the layer's plaintext
                // buffer must be handed to the MCS reader now, otherwise
                // ReadFrame blocks waiting for bytes that already arrived.
                auto leftover = sec_->ReceivePdu(nullptr, 0);
                for (auto& f : leftover) secure_frames_.push_back(std::move(f));
                return true;
            }
            if (r.want == security::Want::kFailed) {
                last_error_ = r.error;
                return false;
            }
            // kRead: wait for the next ciphertext flight.
            uint8_t tmp[kReadChunk];
            const int n = transport_->Read(tmp, sizeof(tmp));
            if (n == net::kReadTimeout) {
                if (stop_requested_.load(std::memory_order_relaxed)) return false;
                continue;
            }
            if (n <= 0) return false;
            pending.assign(tmp, tmp + static_cast<size_t>(n));
        }
    }

    bool DoConnectResponse() {
        std::vector<uint8_t> frame;
        if (!ReadFrame(frame)) return false;
        proto::McsConnectInitial ci;
        if (proto::McsConnectInitial::parse(frame.data(), frame.size(), ci) !=
            Status::Ok) {
            return false;
        }
        proto::GccUserData user_data;
        if (!ExtractGccBlocks(ci.gcc_conference_create_request, user_data)) {
            return false;
        }

        if (const auto* core = user_data.find(kCsCore)) {
            if (core->payload.size() >= 8) {
                const uint16_t w =
                    static_cast<uint16_t>(core->payload[4] | (core->payload[5] << 8));
                const uint16_t h =
                    static_cast<uint16_t>(core->payload[6] | (core->payload[7] << 8));
                if (w != 0) client_desktop_width_ = w;
                if (h != 0) client_desktop_height_ = h;
            }
        }

        uint32_t methods = 0;
        if (const auto* sec = user_data.find(kCsSecurity)) {
            if (sec->payload.size() >= 4) {
                methods = static_cast<uint32_t>(sec->payload[0]) |
                          (static_cast<uint32_t>(sec->payload[1]) << 8) |
                          (static_cast<uint32_t>(sec->payload[2]) << 16) |
                          (static_cast<uint32_t>(sec->payload[3]) << 24);
            }
        }

        // TS_UD_CS_NET ([MS-RDPBCGR] 2.2.1.3.4): a u32 channelCount followed
        // by channelDefArray entries of channelName[8] + options(4). The
        // historical code read the count as a u16 (a misparse of the u32 field)
        // and never parsed the names, so it could not tell the cliprdr channel
        // from rdpdr/rdpsnd. The server assigns channel ids 1004 + index and
        // records which static channel is the cliprdr one for the active-loop
        // dispatch.
        if (const auto* net = user_data.find(kCsNetwork)) {
            ByteReader net_r(net->payload.data(), net->payload.size());
            uint32_t count = 0;
            if (net_r.u32le(count)) {
                // A peer may request an arbitrary number of channels; clamp the
                // table so the Server Network Data channelIdArray cannot
                // overflow the TPKT u16 length or the channel-id range.
                if (count > kMaxStaticChannels) {
                    count = kMaxStaticChannels;
                }
                requested_channels_.clear();
                cliprdr_channel_id_ = 0;
                rdpdr_channel_id_ = 0;
                rdpsnd_channel_id_ = 0;
                for (uint32_t i = 0; i < count; ++i) {
                    // Each entry is name[8] + options(4). A truncated name
                    // table aborts the parse: nothing further is consumed and
                    // no more channel ids are assigned (the ones already
                    // emitted stay valid).
                    if (net_r.remaining() < 12) break;
                    char name[9] = {0};
                    uint8_t byte = 0;
                    for (size_t k = 0; k < 8; ++k) {
                        if (!net_r.u8(byte)) break;
                        name[k] = static_cast<char>(byte);
                    }
                    net_r.skip(4);  // options
                    requested_channels_.push_back(
                        static_cast<uint16_t>(kFirstStaticChannelId + i));
                    if (cliprdr_channel_id_ == 0 &&
                        name[0] != '\0' && std::strcmp(name, "cliprdr") == 0) {
                        cliprdr_channel_id_ =
                            static_cast<uint16_t>(kFirstStaticChannelId + i);
                    }
                    if (rdpdr_channel_id_ == 0 &&
                        name[0] != '\0' && std::strcmp(name, "rdpdr") == 0) {
                        rdpdr_channel_id_ =
                            static_cast<uint16_t>(kFirstStaticChannelId + i);
                    }
                    if (rdpsnd_channel_id_ == 0 &&
                        name[0] != '\0' && std::strcmp(name, "rdpsnd") == 0) {
                        rdpsnd_channel_id_ =
                            static_cast<uint16_t>(kFirstStaticChannelId + i);
                    }
                }
            }
        }

        // Pick the strongest method the client advertised.
        chosen_method_ = 0;
        if ((methods & kMethod128) != 0) {
            chosen_method_ = kMethod128;
        } else if ((methods & kMethod56) != 0) {
            chosen_method_ = kMethod56;
        } else if ((methods & kMethod40) != 0) {
            chosen_method_ = kMethod40;
        }
        encryption_level_ = chosen_method_ != 0 ? kLevelClientCompatible : 0;

        // With an external security protocol (TLS / CredSSP) the Server Security
        // Data MUST carry method=0 and level=0 and MUST NOT include a server
        // certificate ([MS-RDPBCGR] 2.2.1.4.3). mstsc advertises 128-bit
        // encryption even under CredSSP; sending a certificate it must not
        // unpack fails with disconnectReasonServerCertificateUnpackErr (0x706).
        // Standard RDP Security keeps the negotiated method and certificate.
        if (secure_requested_) {
            chosen_method_ = 0;
            encryption_level_ = 0;
        }

        // The licensing Server License Request always carries a 32-byte random,
        // whether or not Standard RDP Security encryption is in effect.
        server_random_.resize(32);
        if (!crypto::RandomBytes(server_random_, server_random_.size())) {
            server_random_.clear();
        }

        if (chosen_method_ != 0 && !server_random_.empty() &&
            rsa_.Generate(config_.rsa_bits)) {
            cert_ = rsa_.BuildCertificate();
        } else {
            // Fail closed: no encryption rather than a broken key.
            chosen_method_ = 0;
            encryption_level_ = 0;
        }

        // The client-declared geometry is untrusted: [MS-RDPBCGR] 2.2.1.3.2
        // carries it as two uint16 fields, so a peer may ask for
        // 65535 x 65535 (a 17,179,344,900-byte framebuffer). Clamp it into the
        // server limits; the clamped size is what Demand Active announces
        // below, so the client adapts instead of the server allocating it.
        ClampDesktopSize(client_desktop_width_ != 0 ? client_desktop_width_
                                                    : config_.desktop_width,
                         client_desktop_height_ != 0 ? client_desktop_height_
                                                     : config_.desktop_height,
                         &desktop_width_, &desktop_height_);
        // The negotiated framebuffer is the coordinate space of the inbound
        // pointer events (the clamp above is what Demand Active announces).
        // Remember it here; the sink is told only once this session actually
        // acquires the input lease, so a non-holder never appears in the
        // sink's geometry bookkeeping.
        //
        // The capture/desktop rectangles come from the source: the capture
        // may be a single monitor or a sub-rectangle, so only the source knows
        // where its pixels are on the virtual screen. A source that does not
        // report them (a synthetic one) leaves `mapped` false, which makes the
        // mapping layer drop absolute moves instead of guessing.
        const DesktopGeometry geometry =
            source_ != nullptr ? source_->Geometry() : DesktopGeometry{};
        inject_geometry_ = InjectGeometry{desktop_width_, desktop_height_};
        inject_geometry_.capture =
            InjectRect{geometry.capture_x, geometry.capture_y,
                       geometry.capture_width, geometry.capture_height};
        inject_geometry_.desktop =
            InjectRect{geometry.desktop_x, geometry.desktop_y,
                       geometry.desktop_width, geometry.desktop_height};
        inject_geometry_.mapped = geometry.mapped;
        inject_geometry_.pixels_are_physical = geometry.pixels_are_physical;
        inject_geometry_known_ = true;

        std::vector<proto::GccUserData::Block> blocks;
        blocks.push_back({kScCore, BuildServerCoreBody(requested_protocols_)});
        blocks.push_back({kScSecurity,
                          BuildServerSecurityBody(chosen_method_, encryption_level_,
                                                  server_random_, cert_)});
        blocks.push_back(
            {kScNetwork, BuildServerNetworkBody(kIoChannelId, requested_channels_)});

        Send(BuildConnectResponse(blocks));
        return true;
    }

    bool DoChannelJoin() {
        // The client sends Erect Domain Request then Attach User Request.
        bool sent_attach_confirm = false;
        while (!sent_attach_confirm) {
            std::vector<uint8_t> frame;
            if (!ReadFrame(frame)) return false;
            const uint8_t choice = McsChoice(frame);
            if (choice == proto::mcs::kErectDomainRequest) continue;
            if (choice == proto::mcs::kAttachUserRequest) {
                Send(BuildAttachUserConfirm(kUserChannelId));
                sent_attach_confirm = true;
                continue;
            }
            return false;
        }

        // Channel Join Requests: the client joins its user channel, the I/O
        // channel and every static virtual channel it asked for.
        for (;;) {
            std::vector<uint8_t> frame;
            if (!ReadFrame(frame)) return false;
            const uint8_t choice = McsChoice(frame);
            if (choice != proto::mcs::kChannelJoinRequest) {
                pending_ = std::move(frame);
                has_pending_ = true;
                return true;
            }
            proto::McsChannelJoinRequest req;
            if (proto::McsChannelJoinRequest::parse(frame.data(), frame.size(), req) !=
                Status::Ok) {
                return false;
            }
            Send(BuildChannelJoinConfirm(req.initiator, req.channel_id, req.channel_id));
        }
    }

    static uint8_t McsChoice(const std::vector<uint8_t>& frame) {
        if (frame.size() < proto::TpktHeader::kSize + 4) return 0xFF;
        return static_cast<uint8_t>(
            frame[proto::TpktHeader::kSize + 3] >> 2);
    }

    bool DoSecurityAndClientInfo() {
        // Security Exchange first (when encryption is on), then Client Info.
        for (;;) {
            std::vector<uint8_t> frame;
            if (!ReadFrame(frame)) return false;
            proto::McsSendData sd;
            if (proto::McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok) {
                return false;
            }
            std::vector<uint8_t> ud = sd.user_data;
            if (!DecryptIfEncrypted(ud)) return false;
            if (ud.size() < 2) return false;
            const uint16_t flags =
                static_cast<uint16_t>(ud[0] | (ud[1] << 8));

            if ((flags & 0x0001) != 0) {  // SEC_EXCHANGE_PKT
                if (!HandleSecurityExchange(ud)) return false;
                continue;
            }
            if ((flags & kSecInfoPkt) != 0) {  // SEC_INFO_PKT
                return HandleClientInfo(ud);
            }
            return false;
        }
    }

    bool HandleSecurityExchange(const std::vector<uint8_t>& payload) {
        proto::SecurityExchangePdu pdu;
        if (proto::SecurityExchangePdu::parse(payload.data(), payload.size(), pdu) !=
            Status::Ok) {
            return false;
        }
        std::vector<uint8_t> client_random;
        if (!rsa_.DecryptClientRandom(pdu.encrypted_client_random, client_random)) {
            return false;
        }

        crypto::RdpSessionKeys keys =
            crypto::DeriveRdpSessionKeys(client_random, server_random_, chosen_method_);
        if (keys.encrypt_key.empty()) return false;

        // DeriveRdpSessionKeys is written from the client's point of view: its
        // encrypt_key is the client-to-server key. Swap the two directions so the
        // context's send stream is the server-to-client key.
        crypto::RdpSessionKeys server_keys = keys;
        server_keys.encrypt_key = keys.decrypt_key;
        server_keys.decrypt_key = keys.encrypt_key;
        security_.Init(server_keys);
        encrypted_ = true;
        return true;
    }

    bool HandleClientInfo(const std::vector<uint8_t>& payload) {
        proto::ClientInfoPdu ci;
        if (proto::ClientInfoPdu::parse(payload.data(), payload.size(), ci) != Status::Ok) {
            return false;
        }
        credentials_.domain = ci.info.domain;
        credentials_.user_name = ci.info.user_name;
        credentials_.password = ci.info.password;
        credentials_.alternate_shell = ci.info.alternate_shell;
        credentials_.working_dir = ci.info.working_dir;

        if (!config_.accept_any_credentials && authenticator_) {
            return authenticator_(credentials_);
        }
        return true;
    }

    bool DoLicensing() {
        // This server issues no CALs, so the licensing phase is a single PDU:
        // ERROR_ALERT(STATUS_VALID_CLIENT + ST_NO_TRANSITION), sent unprompted
        // right after the Client Info PDU. That is byte-for-byte what a real
        // Windows server without a license server does (observed on Win11
        // 26100: "80 00 00 00 ff 03 10 00 07 00 00 00 02 00 00 00 04 00 00 00")
        // and what mstsc accepts: offering it a full SERVER_LICENSE_REQUEST
        // instead makes its licensing state machine disconnect with
        // disconnectReasonLicensingFailed (0x808).
        const bool extended_error = false;  // the observed preamble flags byte is 0x03
        return SendLicensingPdu(proto::LicensingPdu::Encode(
            proto::LicenseMessageType::kErrorAlert, BuildLicenseError(),
            extended_error));
    }

    bool DoDemandActive() {
        share_id_ = session_id_ * 0x01000000u + 0x12345678u;
        const auto caps =
            BuildServerCapabilities(desktop_width_, desktop_height_, config_.color_depth);
        const auto da = BuildDemandActive(kServerChannelId, share_id_, "RTSC", caps,
                                        session_id_);
        if (!SendRawUserData(da)) return false;

        bool got_confirm = false;
        bool got_font_list = false;
        while (!got_font_list) {
            std::vector<uint8_t> frame;
            if (!ReadFrame(frame)) return false;
            proto::McsSendData sd;
            if (proto::McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok) {
                return false;
            }
            std::vector<uint8_t> payload;
            if (!UnwrapInbound(sd.user_data, payload)) return false;
            if (payload.size() < 6) return false;

            const uint16_t pdu_type =
                static_cast<uint16_t>(payload[2] | (payload[3] << 8)) & 0x000F;
            if (pdu_type == static_cast<uint16_t>(proto::SharePduType::kConfirmActive)) {
                proto::ConfirmActivePdu ca;
                if (proto::ConfirmActivePdu::parse(payload.data(), payload.size(), ca) !=
                    Status::Ok) {
                    return false;
                }
                got_confirm = true;
                continue;
            }
            // A PDUTYPE_DATAPDU: pduType2 sits at offset 14 of the share header.
            if (payload.size() > 14 &&
                payload[14] == static_cast<uint8_t>(proto::ShareDataPduType::kFontList)) {
                got_font_list = true;
            }
        }
        return got_confirm;
    }

    bool DoFinalization() {
        // Server Synchronize -> Control(Cooperate) -> Control(GrantedControl) ->
        // Font Map, in that order.
        {
            ByteWriter p;
            p.u16le(1);  // messageType = SYNC
            p.u16le(0);  // targetUser (ignored)
            const auto share = proto::BuildSlowPathDataPdu(
                kServerChannelId, share_id_, kStreamLow,
                proto::ShareDataPduType::kSynchronize, p.take());
            if (!SendRawUserData(share)) return false;
        }
        {
            ByteWriter p;
            p.u16le(0x0004);  // CTRLCOOPERATE
            p.u16le(0);
            p.u32le(0);
            const auto share = proto::BuildSlowPathDataPdu(
                kServerChannelId, share_id_, kStreamLow,
                proto::ShareDataPduType::kControl, p.take());
            if (!SendRawUserData(share)) return false;
        }
        {
            ByteWriter p;
            p.u16le(0x0002);  // CTRLGRANTCONTROLLED
            p.u16le(kUserChannelId);
            p.u32le(kServerChannelId);
            const auto share = proto::BuildSlowPathDataPdu(
                kServerChannelId, share_id_, kStreamLow,
                proto::ShareDataPduType::kControl, p.take());
            if (!SendRawUserData(share)) return false;
        }
        {
            ByteWriter p;
            p.u16le(0);        // numberEntries
            p.u16le(0);        // totalNumEntries
            p.u16le(0x0003);   // mapFlags = first | last
            p.u16le(0x0004);   // entrySize
            const auto share = proto::BuildSlowPathDataPdu(
                kServerChannelId, share_id_, kStreamLow,
                proto::ShareDataPduType::kFontMap, p.take());
            if (!SendRawUserData(share)) return false;
        }
        active_ = true;
        return true;
    }

    bool SendFrame() {
        if (!source_) return false;
        // The framebuffer size is computed (and checked for overflow) before
        // the source allocates anything. desktop_width_/desktop_height_ are
        // already clamped to the server limit; this keeps the path safe on its
        // own as well.
        if (desktop_width_ == 0 || desktop_height_ == 0) return false;
        size_t need = 0;
        if (!FrameBufferBytes(desktop_width_, desktop_height_, &need)) return false;
        std::vector<uint8_t> rgba;
        if (!source_->Capture(desktop_width_, desktop_height_, rgba)) return false;
        if (rgba.size() < need) return false;

        // An MCS Send Data userData is capped at 16383 bytes; reserve the share
        // data header (18) + update header (4) + bitmap header (20) so each
        // bitmap rectangle always fits. bitmapLength is a u16, bounding the
        // pixel block by 65535 bytes as well ([MS-RDPBCGR]
        // 2.2.9.1.1.3.1.2.2). A desktop larger than one rectangle is tiled:
        // horizontal bands, and each band split into column chunks when a
        // single 4Bpp row would overflow the budget (wide monitors). The
        // client composites every rectangle by destination coordinates.
        constexpr size_t kBytesPerPixel = 4;
        const size_t overhead = 18 + 4 + 20;
        const size_t budget = proto::mcs::kMaxSendDataUserData > overhead
                                  ? proto::mcs::kMaxSendDataUserData - overhead
                                  : 0;
        const uint16_t chunk_w = static_cast<uint16_t>(
            std::min<size_t>(desktop_width_, budget / kBytesPerPixel));
        const size_t chunk_row = static_cast<size_t>(chunk_w) * kBytesPerPixel;
        // Both divisions below need a non-zero row stride. A zero width used
        // to reach them and the integer division by zero (0xC0000094) killed
        // the whole process; the entry points now refuse a zero geometry, and
        // this guard keeps the frame path safe on its own.
        if (chunk_w == 0 || chunk_row == 0) return false;
        size_t max_rows = budget / chunk_row;
        max_rows = std::min<size_t>(max_rows, 65535 / chunk_row);
        if (max_rows == 0) max_rows = 1;  // unreachable for u16 widths; defensive
        const uint16_t band = static_cast<uint16_t>(
            std::min<size_t>(max_rows, desktop_height_));

        // uint32_t, not uint16_t: a uint16_t row counter wrapped back to zero
        // when desktop_height_ was close to 65535 and `band` was even, which
        // made the loop infinite (SendFrame never returned and the session
        // flooded the wire). desktop_height_ is bounded by kMaxDesktopHeight,
        // so this counter can no longer wrap.
        for (uint32_t y = 0; y < desktop_height_; y += band) {
            const uint32_t remaining_h = static_cast<uint32_t>(desktop_height_) - y;
            const uint16_t h = static_cast<uint16_t>(std::min<uint32_t>(band, remaining_h));
            for (uint32_t x = 0; x < desktop_width_; x += chunk_w) {
                const uint32_t remaining_w = static_cast<uint32_t>(desktop_width_) - x;
                const uint16_t w = static_cast<uint16_t>(std::min<uint32_t>(chunk_w, remaining_w));
                const auto pixels = EncodeBitmapBand(desktop_width_, x, w, y, h, rgba);
                const auto bitmap = BuildBitmapBand(w, static_cast<uint16_t>(x),
                                                    static_cast<uint16_t>(y), h, pixels);
                // TS_GRAPHICS_UPDATE = updateType + TS_UPDATE_BITMAP_DATA, where
                // TS_UPDATE_BITMAP_DATA = numberRectangles + rectangles
                // ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.1; the updateType appears once).
                ByteWriter payload;
                payload.u16le(0x0001);  // TS_GRAPHICS_UPDATE.updateType
                payload.bytes(bitmap.data(), bitmap.size());
                const auto share = proto::BuildSlowPathDataPdu(
                    kServerChannelId, share_id_, kStreamLow, proto::ShareDataPduType::kUpdate,
                    payload.take());
                if (!SendRawUserData(share)) return false;
            }
        }
        return true;
    }

    void ActiveLoop() {
        // The cliprdr handler speaks first (design §1 "服务器先发"): started
        // exactly once, after the connection finalization and before the first
        // active-loop iteration, so its Clipboard Capabilities / Monitor Ready
        // / Format List precede any client channel data. With no clipboard
        // configured there is nothing to do. The rdpdr handler follows right
        // after (its Server Announce is the server half of the channel
        // handshake); keeping cliprdr first preserves the existing frame
        // order the integration tests assert on.
        if (cliprdr_ != nullptr) cliprdr_->Start();
        if (rdpdr_ != nullptr) rdpdr_->Start();
        // Only start audio capture when the client actually joined the rdpsnd
        // channel: a peer that never requested it must not make us open a
        // capture device (a real WASAPI backend would otherwise record the
        // console's audio for a client that will never hear it).
        if (rdpsnd_ != nullptr && rdpsnd_channel_id_ != 0) rdpsnd_->Start();
        SendFrame();
        // The single frame sent at active can race the client's Confirm Active
        // processing (mstsc drops updates that arrive before its surface is
        // ready and stays black), so the desktop is refreshed on a fixed ~1 s
        // cadence, independent of client input.
        auto next_refresh = std::chrono::steady_clock::now() + kRefreshInterval;
        next_clipboard_poll_ = next_refresh;
        std::vector<uint8_t> frame;
        while (!stop_requested_.load(std::memory_order_relaxed)) {
            // Pump the rdpsnd channel once per iteration (20 ms gate inside
            // Poll), so audio keeps flowing while the client is streaming
            // input and ReadFrame never times out.
            if (rdpsnd_ != nullptr && rdpsnd_channel_id_ != 0) {
                rdpsnd_->Poll(std::chrono::steady_clock::now());
            }
            // Reap route-A rdpdr IRPs whose completion never came back
            // (docs/spec/rdpdr-server-io-design.md section 8): the async I/O
            // engine keeps its outstanding table, and Poll is the only place
            // that ages the entries out (default 30 s deadline). The gate makes
            // it a no-op while no IRP is in flight; Poll is O(n) with
            // n <= kMaxOutstanding. Kept on every iteration (like the rdpsnd
            // pump) so a client that never lets ReadFrame time out cannot leak
            // table slots indefinitely.
            if (rdpdr_ != nullptr && rdpdr_->outstanding_count() != 0) {
                rdpdr_->Poll(std::chrono::steady_clock::now());
            }
            if (!ReadFrame(frame, &next_refresh)) break;
            proto::McsSendData sd;
            if (proto::McsSendData::parse(frame.data(), frame.size(), sd) != Status::Ok) {
                continue;
            }
            // Three-way dispatch on the MCS channel id (design §3.2 / MCS
            // integration point 3): the I/O channel keeps the original share
            // PDU / fast-path input path, the cliprdr static virtual channel
            // feeds the CliprdrServer handler (reassembling the virtual
            // channel protocol), the rdpdr static virtual channel feeds the
            // RdpdrServer minimum handshake, the rdpsnd static virtual channel
            // feeds the RdpsndServer audio handler, and every other static
            // channel is ignored (rail is not served in this scope).
            //
            // The inbound user data is decrypted for EVERY frame, whatever the
            // channel: RC4 is a stream cipher, so a SEC_ENCRYPT-carrying frame
            // that is skipped desynchronises the session's decrypt stream and
            // corrupts the next real message (regression guard: the GUI send
            // integration test sends fake channel PDUs under encryption and
            // asserts the following input still decodes).
            std::vector<uint8_t> payload;
            if (!UnwrapInbound(sd.user_data, payload)) continue;
            if (sd.channel_id == io_channel_) {
                bool was_share_data = false;
                if (!HandleSlowPathPdu(payload, &next_refresh, &was_share_data)) {
                    break;
                }
                // A well-formed share data PDU is never a fast-path PDU, so it
                // must not be fed to the fast-path decoder a second time: a
                // large slow-path input PDU can otherwise look like a plausible
                // fast-path header (P-10).
                if (!was_share_data) HandleInputPdu(payload);
            } else if (cliprdr_ != nullptr && cliprdr_channel_id_ != 0 &&
                       sd.channel_id == cliprdr_channel_id_) {
                cliprdr_->OnChannelData(payload.data(), payload.size());
            } else if (rdpdr_ != nullptr && rdpdr_channel_id_ != 0 &&
                       sd.channel_id == rdpdr_channel_id_) {
                rdpdr_->OnChannelData(payload.data(), payload.size());
            } else if (rdpsnd_ != nullptr && rdpsnd_channel_id_ != 0 &&
                       sd.channel_id == rdpsnd_channel_id_) {
                rdpsnd_->OnChannelData(payload.data(), payload.size());
            }
            // Other channels: decrypted (keeps the RC4 stream in sync) but
            // otherwise ignored.
        }
    }

    // Handles the client's slow-path share PDUs (everything a Fast-Path input
    // PDU is not). Three matter to this server ([MS-RDPBCGR] 1.3.7 /
    // 2.2.11.2.1 / 2.2.11.3.1 / 2.2.8.1.1.3): Refresh Rect asks for an
    // immediate redraw of the named areas, Suppress Output gates the periodic
    // desktop refresh, and PDUTYPE2_INPUT carries slow-path input events.
    // Everything else is ignored. Returns false when a refresh send failed:
    // the session must then end (the caller breaks its loop). `handled` is set
    // to true when the payload was consumed here: a defined share data type, or
    // a TS_SHAREDATAHEADER carrying an undefined pduType2 (malformed, dropped
    // and counted). It stays false only when the header is too short or does
    // not parse, so a real fast-path PDU can still reach the fast-path decoder.
    bool HandleSlowPathPdu(
        const std::vector<uint8_t>& payload,
        std::chrono::steady_clock::time_point* next_refresh,
        bool* handled = nullptr) {
        if (handled != nullptr) *handled = false;
        if (payload.size() < proto::ShareDataHeader::kSize) return true;
        proto::ShareDataHeader hdr;
        if (proto::ShareDataHeader::parse(payload.data(), payload.size(), hdr) !=
            Status::Ok) {
            return true;  // not a share data PDU (e.g. fast-path input)
        }
        // A share-data header whose pduType2 is undefined is malformed, not a
        // fast-path input PDU. Reinterpreting it with the fast-path decoder let
        // a 24-byte packet emit phantom key events (and, with injection on,
        // reach the sink). Consume it here: count it as malformed and do NOT
        // fall through. Only a header that is too short or does not parse (a
        // real fast-path PDU) is left for HandleInputPdu.
        if (!IsKnownShareDataPduType(hdr.pdu_type2)) {
            if (malformed_input_pdus_) {
                malformed_input_pdus_->fetch_add(1, std::memory_order_relaxed);
            }
            if (handled != nullptr) *handled = true;
            return true;
        }
        if (handled != nullptr) *handled = true;
        if (hdr.pdu_type2 == proto::ShareDataPduType::kRefreshRect) {
            proto::RefreshRectPdu refresh;
            if (proto::RefreshRectPdu::parse(payload.data() +
                                                 proto::ShareDataHeader::kSize,
                                             payload.size() -
                                                 proto::ShareDataHeader::kSize,
                                             refresh) != Status::Ok) {
                return true;  // malformed: ignored
            }
            // Immediate full-desktop resend: this server serves the whole
            // framebuffer, so every requested area is inside one frame.
            if (!SendFrame()) {
                last_error_ = "refresh-rect resend failed";
                return false;
            }
            if (next_refresh != nullptr) {
                *next_refresh = std::chrono::steady_clock::now() + kRefreshInterval;
            }
        } else if (hdr.pdu_type2 == proto::ShareDataPduType::kSuppressOutput) {
            proto::SuppressOutputPdu sup;
            if (proto::SuppressOutputPdu::parse(payload.data() +
                                                    proto::ShareDataHeader::kSize,
                                                payload.size() -
                                                    proto::ShareDataHeader::kSize,
                                                sup) != Status::Ok) {
                return true;  // malformed: ignored
            }
            // allowDisplayUpdates=0 suppresses the periodic refresh;
            // allowDisplayUpdates=1 resumes it (the stale deadline makes the
            // next read timeout fire a refresh immediately).
            output_suppressed_ = !sup.allow_display_updates;
        } else if (hdr.pdu_type2 == proto::ShareDataPduType::kInput) {
            // Slow-path input ([MS-RDPBCGR] 2.2.8.1.1.3): a client that did not
            // negotiate fast-path sends PDUTYPE2_INPUT (0x1C) instead.
            ParseSlowPathInput(payload.data() + proto::ShareDataHeader::kSize,
                               payload.size() - proto::ShareDataHeader::kSize);
        }
        return true;
    }

    // Decodes a slow-path TS_INPUT_PDU_DATA ([MS-RDPBCGR] 2.2.8.1.1.3.1):
    // numEvents(2) + pad2Octets(2), followed by numEvents x TS_INPUT_EVENT
    // (eventTime(4) + messageType(2) + a 6-byte body, 2.2.8.1.1.3.1.1).
    //
    // The messageType values are the specification's, NOT a 0..4 sequence:
    //   0x0000 SYNC, 0x0002 UNUSED, 0x0004 SCANCODE, 0x0005 UNICODE,
    //   0x8001 MOUSE, 0x8002 MOUSEX, 0x8004 MOUSEREL.
    // Every decoded event reuses the fast-path fill/callback path (including
    // DecodePointerEvent for the wheel/HWHEEL 9-bit sign extension), so both
    // wire formats yield the same InputEvent.
    //
    // Malformed input never reads past `n`: a short header or event body
    // abandons the PDU, and the abandonment is counted separately
    // (malformed_input_pdus_) because numberEvents disagreeing with the payload
    // is a framing error, not an unknown event type. An unknown messageType is
    // counted (P-11) and the rest of the PDU is abandoned because that event's
    // length is unknown -- the same policy as an unknown fast-path eventCode.
    void ParseSlowPathInput(const uint8_t* p, size_t n) {
        const auto mark_malformed = [this]() {
            if (malformed_input_pdus_) {
                malformed_input_pdus_->fetch_add(1, std::memory_order_relaxed);
            }
        };
        if (n < 4) {
            mark_malformed();
            return;
        }
        const uint16_t count = static_cast<uint16_t>(p[0] | (p[1] << 8));
        size_t pos = 4;  // numberEvents(2) + pad2Octets(2)
        for (uint16_t i = 0; i < count; ++i) {
            if (pos + proto::kSlowPathInputEventHeaderSize > n) {
                mark_malformed();
                return;
            }
            const uint16_t message_type = static_cast<uint16_t>(
                p[pos + 4] | (p[pos + 5] << 8));  // eventTime is ignored
            if (pos + proto::kSlowPathInputEventSize > n) {
                mark_malformed();
                return;
            }
            const uint8_t* body = p + pos + proto::kSlowPathInputEventHeaderSize;
            pos += proto::kSlowPathInputEventSize;

            InputEvent ev;
            switch (static_cast<proto::SlowPathInputEventType>(message_type)) {
                case proto::SlowPathInputEventType::kSync:
                    // TS_SYNC_EVENT: pad2Octets(2) + toggleFlags(4). The toggle
                    // bits have the same values as the fast-path eventFlags.
                    ev.kind = InputEvent::Kind::kSync;
                    ev.sync_flags = static_cast<uint8_t>(body[2] & 0x1F);
                    break;
                case proto::SlowPathInputEventType::kScancode: {
                    // TS_KEYBOARD_EVENT: keyboardFlags(2) + keyCode(2) + pad(2).
                    // A scancode is an 8-bit value, so only the low byte of
                    // keyCode is meaningful ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.1).
                    const uint16_t kbd_flags =
                        static_cast<uint16_t>(body[0] | (body[1] << 8));
                    const uint16_t key_code =
                        static_cast<uint16_t>(body[2] | (body[3] << 8));
                    ev.kind = InputEvent::Kind::kKey;
                    ev.scancode = static_cast<uint8_t>(key_code & 0xFF);
                    ev.release = (kbd_flags & 0x8000) != 0;    // KBDFLAGS_RELEASE
                    ev.extended = (kbd_flags & 0x0100) != 0;   // KBDFLAGS_EXTENDED
                    ev.extended1 = (kbd_flags & 0x0200) != 0;  // KBDFLAGS_EXTENDED1
                    break;
                }
                case proto::SlowPathInputEventType::kUnicode: {
                    // TS_UNICODE_KEYBOARD_EVENT: keyboardFlags(2) +
                    // unicodeCode(2) + pad(2).
                    const uint16_t kbd_flags =
                        static_cast<uint16_t>(body[0] | (body[1] << 8));
                    ev.kind = InputEvent::Kind::kUnicode;
                    ev.unicode_code =
                        static_cast<uint16_t>(body[2] | (body[3] << 8));
                    ev.release = (kbd_flags & 0x8000) != 0;
                    break;
                }
                case proto::SlowPathInputEventType::kMouse:
                case proto::SlowPathInputEventType::kMouseX:
                    // TS_POINTER_EVENT / TS_POINTERX_EVENT: pointerFlags(2) +
                    // xPos(2) + yPos(2), decoded by the same helper the
                    // fast-path pointer events use.
                    DecodePointerEvent(
                        static_cast<uint16_t>(body[0] | (body[1] << 8)),
                        static_cast<uint16_t>(body[2] | (body[3] << 8)),
                        static_cast<uint16_t>(body[4] | (body[5] << 8)),
                        static_cast<proto::SlowPathInputEventType>(message_type) ==
                            proto::SlowPathInputEventType::kMouseX,
                        ev);
                    break;
                case proto::SlowPathInputEventType::kUnused:
                    continue;  // TS_UNUSED_EVENT: nothing to deliver
                case proto::SlowPathInputEventType::kMouseRel:
                    // TS_RELPOINTER_EVENT: pointerFlags(2) + xDelta(2) +
                    // yDelta(2); the deltas are SIGNED i16, unlike the
                    // unsigned absolute x/y of TS_POINTER_EVENT
                    // ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.7). Its pointerFlags are
                    // IDENTICAL to TS_FP_RELPOINTER_EVENT's, so this fills the
                    // same InputEvent the fast-path branch produces (P-10):
                    // kind=kMouseRel, rel_x/rel_y signed, is_move false, and
                    // the X1/X2 fallback in the PTRXFLAGS namespace. It is a
                    // real input event, never counted as unknown.
                    ev.kind = InputEvent::Kind::kMouseRel;
                    {
                        const uint16_t pf = static_cast<uint16_t>(
                            body[0] | (body[1] << 8));
                        ev.rel_x = static_cast<int16_t>(
                            static_cast<uint16_t>(body[2] | (body[3] << 8)));
                        ev.rel_y = static_cast<int16_t>(
                            static_cast<uint16_t>(body[4] | (body[5] << 8)));
                        DecodePointerButtons(pf, false, ev);
                        if (ev.button == 0) {
                            if ((pf & proto::kPtrXButton2) != 0) {
                                ev.button = 5;
                            } else if ((pf & proto::kPtrXButton1) != 0) {
                                ev.button = 4;
                            }
                        }
                    }
                    break;
                default:
                    // Unknown messageType: its length is unknown, so this PDU
                    // cannot be resynchronised.
                    if (unknown_input_events_) {
                        unknown_input_events_->fetch_add(
                            1, std::memory_order_relaxed);
                    }
                    return;
            }
            InjectIfLeasable(ev);
            if (input_callback_) input_callback_(ev);
        }
    }

    void HandleInputPdu(const std::vector<uint8_t>& payload) {
        if (payload.empty()) return;
        if ((payload[0] & 0x03) != 0x00) return;  // slow-path: not an input PDU
        proto::FastPathPdu fp;
        if (proto::FastPathPdu::parse(payload.data(), payload.size(), true, fp) !=
            Status::Ok) {
            return;
        }
        ParseInputEvents(fp);
    }

    void ParseInputEvents(const proto::FastPathPdu& fp) {
        const uint8_t* p = fp.body.data();
        const size_t n = fp.body.size();
        size_t pos = 0;
        if (fp.header.count_or_reserved == 0) pos = 1;  // extended numEvents byte
        while (pos < n) {
            const uint8_t h = p[pos++];
            const uint8_t code = static_cast<uint8_t>(h >> 5);
            const uint8_t flags = static_cast<uint8_t>(h & 0x1F);
            InputEvent ev;
            switch (static_cast<proto::FastPathInputEventCode>(code)) {
                case proto::FastPathInputEventCode::kScancode: {
                    if (pos + 1 > n) return;
                    ev.kind = InputEvent::Kind::kKey;
                    ev.scancode = p[pos++];
                    ev.release = (flags & proto::kKbdRelease) != 0;
                    // FASTPATH_INPUT_KBDFLAGS_EXTENDED means "the keyCode is
                    // prefixed by 0xE0", so it stays a separate flag; the
                    // scancode itself is never offset by 0x100. EXTENDED1 is
                    // the 0xE1 prefix used by the PAUSE sequence
                    // ([MS-RDPBCGR] 2.2.8.1.2.2.1).
                    ev.extended = (flags & proto::kKbdExtended) != 0;
                    ev.extended1 = (flags & proto::kKbdExtended1) != 0;
                    break;
                }
                case proto::FastPathInputEventCode::kUnicode: {
                    if (pos + 2 > n) return;
                    ev.kind = InputEvent::Kind::kUnicode;
                    ev.unicode_code =
                        static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
                    pos += 2;
                    ev.release = (flags & proto::kKbdRelease) != 0;
                    break;
                }
                case proto::FastPathInputEventCode::kMouse:
                case proto::FastPathInputEventCode::kMouseX: {
                    if (pos + 6 > n) return;
                    const uint16_t pf =
                        static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
                    const uint16_t x_pos =
                        static_cast<uint16_t>(p[pos + 2] | (p[pos + 3] << 8));
                    const uint16_t y_pos =
                        static_cast<uint16_t>(p[pos + 4] | (p[pos + 5] << 8));
                    pos += 6;
                    DecodePointerEvent(
                        pf, x_pos, y_pos,
                        static_cast<proto::FastPathInputEventCode>(code) ==
                            proto::FastPathInputEventCode::kMouseX,
                        ev);
                    break;
                }
                case proto::FastPathInputEventCode::kSync:
                    ev.kind = InputEvent::Kind::kSync;
                    ev.sync_flags = flags;
                    break;
                case proto::FastPathInputEventCode::kMouseRel: {
                    // TS_FP_RELPOINTER_EVENT: xDelta/yDelta are SIGNED i16,
                    // unlike the unsigned absolute x/y above
                    // ([MS-RDPBCGR] 2.2.8.1.2.2.7). A real input event, so it
                    // is delivered once as kMouseRel (never as a phantom kKey).
                    // Its pointerFlags are IDENTICAL to TS_RELPOINTER_EVENT's
                    // ([MS-RDPBCGR] 2.2.8.1.2.2.7), and that table lists
                    // PTRXFLAGS_BUTTON1 0x0001 (button 4) / PTRXFLAGS_BUTTON2
                    // 0x0002 (button 5) ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.7), so a
                    // relative event can carry X1/X2 as well.
                    // is_move stays false: that flag means "move the absolute
                    // pointer to (x, y)", and this event has x = y = 0.
                    if (pos + 6 > n) return;
                    const uint16_t pf =
                        static_cast<uint16_t>(p[pos] | (p[pos + 1] << 8));
                    ev.kind = InputEvent::Kind::kMouseRel;
                    ev.rel_x = static_cast<int16_t>(
                        static_cast<uint16_t>(p[pos + 2] | (p[pos + 3] << 8)));
                    ev.rel_y = static_cast<int16_t>(
                        static_cast<uint16_t>(p[pos + 4] | (p[pos + 5] << 8)));
                    DecodePointerButtons(pf, false, ev);
                    // PTRFLAGS has no X1/X2 bits: those live in the PTRXFLAGS
                    // namespace (0x0001/0x0002) that relative events share with
                    // TS_RELPOINTER_EVENT ([MS-RDPBCGR] 2.2.8.1.2.2.7 and
                    // 2.2.8.1.1.3.1.1.7), so decode them as a fallback in the
                    // same order as DecodePointerButtons' X branch (X2 first).
                    if (ev.button == 0) {
                        if ((pf & proto::kPtrXButton2) != 0) ev.button = 5;
                        else if ((pf & proto::kPtrXButton1) != 0) ev.button = 4;
                    }
                    pos += 6;
                    break;
                }
                case proto::FastPathInputEventCode::kQoeTimestamp:
                    // TS_FP_QOETIMESTAMP_EVENT is metadata (a timestamp), not
                    // an input event: consume it and emit NOTHING. Letting it
                    // fall through to the callback delivered the default
                    // InputEvent (kind=kKey, scancode=0) -- a phantom key.
                    if (pos + 4 > n) return;
                    pos += 4;
                    continue;
                default:
                    // Unknown eventCode. [MS-RDPBCGR] 2.2.8.1.2.2 says the
                    // server SHOULD drop the connection; this server
                    // deliberately deviates (SHOULD is not MUST) so a capture
                    // can identify the offending client version instead of
                    // losing the session. The event is counted and the rest of
                    // this PDU is abandoned: its size is unknown, so there is
                    // no safe way to resynchronise.
                    if (unknown_input_events_) {
                        unknown_input_events_->fetch_add(
                            1, std::memory_order_relaxed);
                    }
                    return;
            }
            InjectIfLeasable(ev);
            if (input_callback_) input_callback_(ev);
        }
    }

    std::unique_ptr<net::Transport> transport_;
    ServerConfig config_;
    DesktopSource* source_ = nullptr;
    Authenticator authenticator_;
    InputCallback input_callback_;
    uint32_t session_id_ = 0;
    // Borrowed injection sink and the id used only to attribute injected input
    // to this session. Deliberately separate from session_id_ (which feeds the
    // wire shareId): making the wire id per-session would change Demand Active.
    DesktopInputSink* input_sink_ = nullptr;
    uint32_t input_session_id_ = 0;
    // Server-wide lease (shared with every session) and this session's state:
    // whether it holds a slot, and the geometry to announce if/when it does.
    std::shared_ptr<InputLease> input_lease_;
    bool input_lease_held_ = false;
    InjectGeometry inject_geometry_;
    bool inject_geometry_known_ = false;
    bool input_released_ = false;
    // Per-session PAUSE (0xE1) envelope state; see PauseSequenceFilter.
    PauseSequenceFilter pause_filter_;
    // Server-level counter shared with every session: an unknown eventCode is
    // counted here so the operator can observe it without logs (P-11).
    std::shared_ptr<std::atomic<size_t>> unknown_input_events_;
    // Server-level counter for slow-path input PDUs abandoned on a
    // numberEvents/payload mismatch (a framing error, not an unknown event).
    std::shared_ptr<std::atomic<size_t>> malformed_input_pdus_;

    std::vector<uint8_t> read_buf_;
    std::vector<uint8_t> pending_;
    bool has_pending_ = false;
    std::atomic<bool> stop_requested_{false};

    // Enhanced security state (TLS + CredSSP). `secure_requested_` is set by
    // DoX224 when the negotiated protocol is SSL or HYBRID; `secure_` becomes
    // true once the handshake completes and every frame is encrypted.
    bool secure_requested_ = false;
    bool secure_ = false;
    uint32_t selected_protocol_ = 0;
    bool credssp_required_ = true;
    bool euar_required_ = false;
    std::unique_ptr<security::ServerSecurityLayer> sec_;
    std::deque<std::vector<uint8_t>> secure_frames_;
    std::string last_error_;

    uint32_t requested_protocols_ = 0;
    uint16_t client_desktop_width_ = 0;
    uint16_t client_desktop_height_ = 0;
    uint16_t desktop_width_ = 0;
    uint16_t desktop_height_ = 0;
    std::vector<uint16_t> requested_channels_;
    uint16_t io_channel_ = kIoChannelId;
    // The MCS channel id of the client's cliprdr static virtual channel,
    // resolved from the Client Network Data name table in DoConnectResponse
    // (1004 + index of the "cliprdr" name). 0 when the client did not
    // advertise the cliprdr channel.
    uint16_t cliprdr_channel_id_ = 0;
    // The MCS channel id of the client's rdpdr static virtual channel,
    // resolved the same way (1004 + index of the "rdpdr" name). 0 when the
    // client did not advertise the rdpdr channel.
    uint16_t rdpdr_channel_id_ = 0;
    // The MCS channel id of the client's rdpsnd static virtual channel,
    // resolved the same way (1004 + index of the "rdpsnd" name). 0 when the
    // client did not advertise the rdpsnd channel.
    uint16_t rdpsnd_channel_id_ = 0;

    uint32_t chosen_method_ = 0;
    uint32_t encryption_level_ = 0;
    std::vector<uint8_t> server_random_;
    std::vector<uint8_t> cert_;
    crypto::RsaServerKeyPair rsa_;
    crypto::RdpSecurityContext security_;
    bool encrypted_ = false;

    uint32_t share_id_ = 0;
    bool active_ = false;
    // Set by a client Suppress Output PDU (allowDisplayUpdates=0,
    // [MS-RDPBCGR] 2.2.11.3.1): suspends the periodic desktop refresh until
    // the client resumes output.
    bool output_suppressed_ = false;
    // The per-session cliprdr handler. Null when no local clipboard was
    // configured (RdpServer::SetClipboard); created with the session even
    // before the client's channel id is known, and started in ActiveLoop.
    std::unique_ptr<rtsc::channel::CliprdrServer> cliprdr_;
    // The per-session rdpdr handler (the minimum channel handshake). Null when
    // ServerConfig::enable_rdpdr_handshake is false; created with the session
    // and started in ActiveLoop.
    std::unique_ptr<rtsc::channel::RdpdrServer> rdpdr_;
    // The per-session rdpsnd handler (server-side audio output). Null when
    // ServerConfig::enable_rdpsnd is false or no audio_source_factory is
    // installed; created with the session and started in ActiveLoop.
    std::unique_ptr<rtsc::channel::RdpsndServer> rdpsnd_;
    // Deadline of the next cliprdr local-clipboard change poll (~1 s cadence,
    // set at ActiveLoop entry).
    std::chrono::steady_clock::time_point next_clipboard_poll_{};
    Credentials credentials_;
};

}  // namespace

// ---- RdpServer -------------------------------------------------------------

struct RdpServer::Impl {
    explicit Impl(const ServerConfig& config)
        : config(config),
          input_lease(std::make_shared<InputLease>(config.max_input_sessions)) {}

    // State shared with the detached session threads. It is a shared_ptr so a
    // thread that is still finishing after Stop() cannot touch a destroyed
    // Impl: the thread keeps the registry alive until its very last statement.
    struct Registry {
        std::mutex mu;
        std::condition_variable cv;
        // Live sessions. The owning reference is the session thread's
        // shared_ptr; this registry only keeps them reachable for Stop(), and
        // the thread unregisters itself when it finishes.
        std::vector<std::shared_ptr<RdpSession>> sessions;
        // Atomic because the decrement must not depend on a mutex lock
        // succeeding: it is the only thing Stop() waits for, so it has to be
        // reachable from every path (see the exactly-once handoff below).
        std::atomic<size_t> live{0};
    };

    ServerConfig config;
    // Desktop input control lease shared by every session of this server.
    std::shared_ptr<InputLease> input_lease;
    std::unique_ptr<net::Listener> listener;
    // The port the listening socket is actually bound to; captured at bind time
    // so it survives the listener's destruction. Non-zero whenever `listener`
    // was created successfully, including a kernel-assigned ephemeral port
    // when config.port was 0.
    uint16_t bound_port = 0;
    std::atomic<bool> running{false};
    std::shared_ptr<Registry> registry = std::make_shared<Registry>();
    std::atomic<size_t> total_session_count{0};
    // Monotonic id used only to attribute injected input to a session. Starts
    // at 1 so 0 remains "no session"; it never feeds the wire shareId.
    std::atomic<uint32_t> next_input_session_id{0};
    // Unknown fast-path input eventCodes, counted per server (P-11). A
    // shared_ptr so a detached session thread cannot outlive the counter.
    std::shared_ptr<std::atomic<size_t>> unknown_input_events =
        std::make_shared<std::atomic<size_t>>(0);
    // Slow-path input PDUs abandoned on a numberEvents/payload mismatch.
    std::shared_ptr<std::atomic<size_t>> malformed_input_pdus =
        std::make_shared<std::atomic<size_t>>(0);
    // One-shot guard for the accept-all WARNING. Intentionally a plain bool:
    // Start()/Run()/ServeOne() may be called concurrently only by embedding
    // at their own risk; firing a duplicate warning under a racy double
    // Start is benign and not worth a lock.
    bool warned_accept_all = false;

    // Binds the listening socket and records the effective port. Returns false
    // and fills `why` on failure.
    bool Listen(std::string& why) {
        listener = net::ListenTcp("0.0.0.0", config.port, why);
        if (!listener) return false;
        bound_port = listener->local_port();
        return true;
    }
};

RdpServer::RdpServer(const ServerConfig& config)
    : impl_(std::make_unique<Impl>(config)), config_(config) {}

RdpServer::~RdpServer() {
    // Stop() is isolated step by step, but the destructor must not rely on that
    // for correctness: an escaping exception here is std::terminate.
    try {
        Stop();
    } catch (...) {
    }
}

void RdpServer::SetDesktopSource(DesktopSource* source) { source_ = source; }

void RdpServer::SetAuthenticator(Authenticator auth) {
    authenticator_ = std::move(auth);
}

void RdpServer::SetInputCallback(InputCallback cb) {
    input_callback_ = std::move(cb);
}

void RdpServer::SetInputSink(DesktopInputSink* sink) { input_sink_ = sink; }

void RdpServer::SetClipboard(clipboard::Clipboard* clipboard) {
    clipboard_ = clipboard;
}

void RdpServer::SetFileListProvider(clipboard::FileListProvider* provider) {
    file_list_provider_ = provider;
}

void RdpServer::WarnIfAcceptAll() {
    // Say it once, loudly: the default configuration does not check
    // credentials (the library default keeps the first-milestone behaviour, and
    // a real deployment is expected to call SetAuthenticator). Silently
    // accepting every peer is exactly the state an operator must notice. The
    // once flag covers all entry points, so Start()/Run()/ServeOne() together
    // still warn exactly once per server.
    if ((config_.accept_any_credentials || !authenticator_) &&
        !impl_->warned_accept_all) {
        impl_->warned_accept_all = true;
        std::fprintf(stderr,
                     "[rtsc-server] WARNING: credential validation is not "
                     "enforced (accept_any_credentials=%s, authenticator=%s); "
                     "every client is accepted\n",
                     config_.accept_any_credentials ? "true" : "false",
                     authenticator_ ? "set" : "unset");
    }
}

bool RdpServer::Start(std::string& error) {
    if (!ValidateDesktopSize(config_.desktop_width, config_.desktop_height,
                             &error)) {
        last_error_ = error;
        return false;
    }
    WarnIfAcceptAll();
    if (impl_->listener) return true;
    std::string why;
    if (!impl_->Listen(why)) {
        error = why;
        last_error_ = why;
        return false;
    }
    return true;
}

void RdpServer::Run() {
    if (!ValidateDesktopSize(config_.desktop_width, config_.desktop_height,
                             &last_error_)) {
        return;
    }
    WarnIfAcceptAll();
    if (!impl_->listener) {
        std::string why;
        if (!impl_->Listen(why)) {
            last_error_ = why;
            return;
        }
    }
    impl_->running.store(true, std::memory_order_relaxed);
    // Fast-path hint only; use the same relaxed order as the authoritative
    // re-check under the registry mutex below. Promptness optimisations here
    // (acquire) would not change any invariant.
    while (impl_->running.load(std::memory_order_relaxed)) {
        auto transport = impl_->listener->Accept();
        if (!transport) break;

        auto registry = impl_->registry;
        std::shared_ptr<RdpSession> session;
        {
            // Register under the lock so Stop() either sees the session (and
            // stops it) or the loop has already exited. The live count is
            // raised here, before the thread exists, so the thread's teardown
            // can never decrement it before it was raised (a size_t underflow
            // would make Stop() wait forever). A failed launch rolls it back
            // below.
            std::lock_guard<std::mutex> lock(registry->mu);
            // Re-check under the registry mutex. Stop() sets `running` false
            // before taking this same mutex, so once this mutation is visible
            // here (mutex happens-before, also on weak-memory machines) no
            // session can register any more, and the Stop() snapshot taken
            // under the same mutex can never miss a session that registered.
            // Relaxed is conservative; acquire would only shorten promptness.
            if (!impl_->running.load(std::memory_order_relaxed)) break;
            session = std::make_shared<RdpSession>(
                std::move(transport), config_, source_, authenticator_,
                input_callback_, 0, input_sink_,
                impl_->next_input_session_id.fetch_add(
                    1, std::memory_order_relaxed) + 1,
                clipboard_, file_list_provider_, impl_->unknown_input_events,
                impl_->malformed_input_pdus, impl_->input_lease);
            registry->sessions.push_back(session);
            registry->live.fetch_add(1, std::memory_order_relaxed);
        }
        // The thread owns the session and is detached: keeping the std::thread
        // object in a container until Stop() leaked one kernel thread handle
        // per connection (measured +1 per connect on a long-running host,
        // 107 -> 115 over 8 rounds). Stop() waits for the registry's live count
        // to reach zero instead of joining.
        // Exactly-once release of the live slot. Ownership of the decrement is
        // handed off through `counted`, so it does not depend on the launcher
        // being honest: a launcher may run the body to completion *and then*
        // report failure, in which case both the body's teardown and the
        // rollback would otherwise decrement (size_t underflow -> SIZE_MAX ->
        // Stop() blocks forever). Whichever side exchanges the flag first owns
        // the decrement; the other becomes a no-op.
        // The erase is best effort and lives in its own block: a throwable
        // operation must not be able to skip the count release.
        auto counted = std::make_shared<std::atomic<bool>>(true);
        auto release = [registry, session, counted]() noexcept {
            try {
                std::lock_guard<std::mutex> guard(registry->mu);
                auto& live_sessions = registry->sessions;
                live_sessions.erase(
                    std::remove(live_sessions.begin(), live_sessions.end(),
                                session),
                    live_sessions.end());
            } catch (...) {
                // The registry entry is only used to reach the session from
                // Stop(); leaving it behind is harmless, the count is not.
            }
            if (counted->exchange(false, std::memory_order_acq_rel)) {
                // Only the decrement happens after the lock, so no other
                // throwable statement can sit between them.
                try {
                    std::lock_guard<std::mutex> guard(registry->mu);
                    registry->live.fetch_sub(1, std::memory_order_relaxed);
                } catch (...) {
                    // std::mutex::lock() failed (programmer error); releasing
                    // the count still matters more than the wake-up protocol.
                    registry->live.fetch_sub(1, std::memory_order_relaxed);
                }
            }
            try {
                registry->cv.notify_all();
            } catch (...) {
            }
        };
        // noexcept: the body runs on a detached thread, so an exception
        // escaping it would call std::terminate and kill the whole process
        // (every other session included). The session phase is caught here and
        // teardown is the single no-throw `release` above.
        auto body = [registry, session, release]() noexcept {
            try {
                session->Run();
            } catch (const std::exception& e) {
                std::fprintf(stderr, "[rtsc-server] session failed: %s\n",
                             e.what());
            } catch (...) {
                std::fprintf(stderr,
                             "[rtsc-server] session failed: unknown exception\n");
            }
            try {
                session->Stop();
            } catch (...) {
            }
            try {
                session->ScrubCredentials();
            } catch (...) {
            }
            try {
                session->ReleaseInput();
            } catch (...) {
            }
            release();
        };
        bool started = false;
        if (config_.session_thread_launcher) {
            try {
                started = config_.session_thread_launcher(body);
            } catch (...) {
                started = false;
            }
        } else {
            try {
                std::thread(body).detach();
                started = true;
            } catch (const std::exception& e) {
                // Thread/handle exhaustion: the connection is dropped, the
                // session is not counted and the accept loop keeps going.
                std::fprintf(stderr,
                             "[rtsc-server] session thread could not be "
                             "started: %s\n",
                             e.what());
                started = false;
            }
        }
        if (!started) {
            // no-throw, exactly-once: if the launcher already ran the body to
            // completion this is a no-op for the count.
            release();
            continue;  // `session` is released here: the transport is closed.
        }
        impl_->total_session_count.fetch_add(1, std::memory_order_relaxed);
    }
}

bool RdpServer::ServeOne() {
    if (!ValidateDesktopSize(config_.desktop_width, config_.desktop_height,
                             &last_error_)) {
        return false;
    }
    WarnIfAcceptAll();
    if (!impl_->listener) {
        std::string why;
        if (!impl_->Listen(why)) {
            last_error_ = why;
            return false;
        }
    }
    auto transport = impl_->listener->Accept();
    if (!transport) return false;
    RdpSession session(
        std::move(transport), config_, source_, authenticator_, input_callback_,
        0, input_sink_,
        impl_->next_input_session_id.fetch_add(1, std::memory_order_relaxed) + 1,
        clipboard_, file_list_provider_, impl_->unknown_input_events,
        impl_->malformed_input_pdus, impl_->input_lease);
    // Same containment as the threaded path: a failing session (e.g.
    // std::bad_alloc) must not take the caller down with it. Teardown is
    // contained step by step too: Close() is not noexcept, so a throwing Stop()
    // must not skip ScrubCredentials()/ReleaseInput() (that would leak the
    // input lease slot and the session's rate-limit bucket).
    try {
        session.Run();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[rtsc-server] session failed: %s\n", e.what());
    } catch (...) {
        std::fprintf(stderr, "[rtsc-server] session failed: unknown exception\n");
    }
    try {
        session.Stop();
    } catch (...) {
    }
    try {
        session.ScrubCredentials();
    } catch (...) {
    }
    try {
        session.ReleaseInput();
    } catch (...) {
    }
    return true;
}

void RdpServer::Stop() {
    // Idempotent and safe when called twice: the wait predicate is the live
    // count, so a second call simply observes zero.
    // Publishing the stop. Deliberately left relaxed (conservative; an explicit
    // release/acquire pair would not add an invariant): the correctness chain
    // is the registry mutex, not the atomic. This store is sequenced before
    // Stop() takes registry->mu below, and every registration re-checks
    // running under that same mutex in Run(), so the mutex happens-before edge
    // (valid on weak-memory machines too) guarantees that a session which
    // could be missed by the snapshot cannot register: either the snapshot
    // below already saw it, or the register sees this false and breaks.
    impl_->running.store(false, std::memory_order_relaxed);
    // Both calls below go through virtual interfaces that are not noexcept (a
    // transport Close() or a session Stop() may be implemented by an embedder).
    // Stop() also runs from ~RdpServer, so one escaping exception would
    // terminate the process; each step is isolated so the teardown continues.
    if (impl_->listener) {
        try {
            impl_->listener->Close();
        } catch (...) {
        }
    }

    const auto registry = impl_->registry;
    // Ask every live session to stop, then wait until their detached threads
    // have actually finished (server.h: Stop() closes the listener and every
    // live session, then waits for their threads). Detached threads cannot be
    // joined, so the wait is on the registry's live count -- the same
    // guarantee the join used to give.
    //
    // Two invariants this function must never break:
    //
    // I1 -- never silently succeed. Every path where the teardown could not be
    // performed has to leave a diagnostic line on stderr (with the number of
    // sessions still live). A quiet return would make a lost teardown
    // indistinguishable from a clean one.
    //
    // I2 -- never return while a session thread may still touch a borrowed
    // host object. The session threads call the borrowed DesktopSource /
    // DesktopInputSink / Clipboard / FileListProvider, and server.h documents
    // that those objects may be destroyed right after Stop() returns. The
    // listener close alone does NOT unblock an accepted session (it only stops
    // new accepts); only RdpSession::Stop() closes that session's transport.
    // So the only safe exit is live == 0. A timeout is not success and must
    // never end the wait.
    const StopFailureInjection injection = StopFailureFromEnvironment();

    // Snapshot so the sessions can be stopped outside the registry lock. The
    // copy allocates, so it can fail (std::bad_alloc). Losing the snapshot must
    // not lose the stop requests: fall back to walking the registry under the
    // lock. RdpSession::Stop() is one atomic store plus one transport Close(),
    // and the transport tolerates a concurrent close (see RdpSession::Stop),
    // so calling it under the lock is safe and always delivers the request.
    std::vector<std::shared_ptr<RdpSession>> sessions;
    bool snapshot_taken = false;
    try {
        if (injection == StopFailureInjection::kSnapshot) {
            throw std::bad_alloc();
        }
        std::lock_guard<std::mutex> lock(registry->mu);
        sessions = registry->sessions;
        snapshot_taken = true;
    } catch (...) {
        // I1: an allocation failure is exactly the case that used to skip every
        // s->Stop() and leave Stop() waiting forever. Report how many sessions
        // are still live, then stop the sessions in place.
        const size_t live_before_stop =
            registry->live.load(std::memory_order_relaxed);
        std::fprintf(stderr,
                     "[rtsc-server] stop: session snapshot failed; %zu "
                     "session(s) live; stopping them under the registry lock\n",
                     live_before_stop);
        try {
            std::lock_guard<std::mutex> lock(registry->mu);
            for (const auto& session : registry->sessions) {
                try {
                    session->Stop();
                } catch (...) {
                }
            }
        } catch (...) {
            // Cannot even take the registry lock (programmer error / mutex
            // misuse). Still report: the wait below will keep reporting too.
            std::fprintf(stderr,
                         "[rtsc-server] stop: registry lock failed; %zu "
                         "session(s) may still be live and the stop requests "
                         "could not be delivered\n",
                         registry->live.load(std::memory_order_relaxed));
        }
    }
    if (snapshot_taken) {
        for (const auto& session : sessions) {
            try {
                session->Stop();
            } catch (...) {
            }
        }
    }
    // Dropping `sessions` releases any session the thread had not released yet;
    // it also frees its credentials with the object.
    sessions.clear();

    // I2: wait for the detached session threads to finish. A failure of the
    // wait itself (std::system_error on mutex misuse) is NOT a completed
    // teardown -- swallowing it and returning used to hand the host a server
    // whose session threads were still calling the borrowed objects (UAF).
    // Timeouts are not completion either. So this loop only exits on live == 0;
    // every other iteration reports what is still outstanding and keeps going.
    const auto wait_started = std::chrono::steady_clock::now();
    for (;;) {
        bool stopped = false;
        bool wait_failed = false;
        try {
            std::unique_lock<std::mutex> lock(registry->mu);
            // The predicate is checked before the (possibly failing) wait, so a
            // teardown that already finished returns immediately even when the
            // wait itself is broken.
            if (registry->live.load(std::memory_order_relaxed) == 0) {
                stopped = true;
            } else if (injection == StopFailureInjection::kWait) {
                throw std::system_error(
                    std::make_error_code(std::errc::operation_canceled));
            } else {
                stopped = registry->cv.wait_for(
                    lock, std::chrono::seconds(2),
                    [&registry] { return registry->live == 0; });
            }
        } catch (...) {
            wait_failed = true;
        }
        if (stopped) return;
        const size_t live = registry->live.load(std::memory_order_relaxed);
        if (live == 0) return;
        const auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::steady_clock::now() -
                                         wait_started)
                                         .count();
        if (wait_failed) {
            std::fprintf(stderr,
                         "[rtsc-server] stop: wait failed; %zu session(s) still "
                         "live after %llds; still waiting\n",
                         live, static_cast<long long>(elapsed_seconds));
            // A permanently broken condition variable must not spin a core at
            // 100%: back off between retries. The wait stays bounded by the
            // live count, never by a timeout.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        } else {
            std::fprintf(stderr,
                         "[rtsc-server] stop: %zu session(s) still live after "
                         "%llds\n",
                         live, static_cast<long long>(elapsed_seconds));
        }
    }
}

size_t RdpServer::session_count() const {
    std::lock_guard<std::mutex> lock(impl_->registry->mu);
    return impl_->registry->live;
}

uint16_t RdpServer::bound_port() const { return impl_->bound_port; }

size_t RdpServer::total_session_count() const {
    return impl_->total_session_count.load(std::memory_order_relaxed);
}

size_t RdpServer::unknown_input_event_count() const {
    return impl_->unknown_input_events->load(std::memory_order_relaxed);
}

size_t RdpServer::malformed_input_pdu_count() const {
    return impl_->malformed_input_pdus->load(std::memory_order_relaxed);
}

size_t RdpServer::input_lease_denied_count() const {
    return impl_->input_lease->denied->load(std::memory_order_relaxed);
}

size_t RdpServer::input_release_failure_count() const {
    return impl_->input_lease->release_failures->load(
        std::memory_order_relaxed);
}

// ---- Test pattern ----------------------------------------------------------

namespace {

class TestPatternSource : public DesktopSource {
 public:
    bool Capture(uint16_t width, uint16_t height,
                 std::vector<uint8_t>& rgba) override {
        // A zero dimension would allocate an empty framebuffer and the border
        // loop below would then write past its end (a heap overflow). Refuse
        // it explicitly instead.
        if (width == 0 || height == 0) return false;
        rgba.assign(static_cast<size_t>(width) * height * 4, 0);
        for (uint32_t y = 0; y < height; ++y) {
            for (uint32_t x = 0; x < width; ++x) {
                const size_t i = (static_cast<size_t>(y) * width + x) * 4;
                rgba[i + 0] = static_cast<uint8_t>(x & 0xFF);
                rgba[i + 1] = static_cast<uint8_t>(y & 0xFF);
                rgba[i + 2] = static_cast<uint8_t>((x + y) & 0xFF);
                rgba[i + 3] = 0xFF;
            }
        }
        // A bright border so the frame is immediately recognisable.
        for (uint32_t x = 0; x < width; ++x) {
            SetPixel(rgba, width, x, 0, 255, 255, 255);
            SetPixel(rgba, width, x, height - 1, 255, 255, 255);
        }
        for (uint32_t y = 0; y < height; ++y) {
            SetPixel(rgba, width, 0, y, 255, 255, 255);
            SetPixel(rgba, width, width - 1, y, 255, 255, 255);
        }
        return true;
    }

 private:
    static void SetPixel(std::vector<uint8_t>& rgba, uint16_t width, uint32_t x,
                         uint32_t y, uint8_t r, uint8_t g, uint8_t b) {
        const size_t i = (static_cast<size_t>(y) * width + x) * 4;
        rgba[i + 0] = r;
        rgba[i + 1] = g;
        rgba[i + 2] = b;
        rgba[i + 3] = 255;
    }
};

}  // namespace

std::unique_ptr<DesktopSource> MakeTestPatternSource() {
    return std::make_unique<TestPatternSource>();
}

}  // namespace rtsc::server
