// RDP server role: the server half of the [MS-RDPBCGR] connection sequence.
//
// Reference: [MS-RDPBCGR] 1.3.1.1 / 3.2.5 / 3.3.5, [MS-RDPELE] 1.3, 2.2.
//
// This file is the implementation of include/rtsc/server/server.h. It is
// deliberately transport agnostic below the net::Transport seam and free of any
// platform header, so it builds unchanged on Windows and Linux (the Linux gate
// compiles it; only the RSA backend is Windows-only, and the server fails
// closed to "no encryption" when the keypair cannot be generated).
//
// Session isolation (D1): every accepted peer gets its own RdpSession with its
// own X.224/MCS state, security state, capability sets and framebuffer. The
// only objects shared between sessions are the immutable ServerConfig, the
// DesktopSource pointer and the Authenticator, all of which are read-only
// during a session.

#include "rtsc/server/server.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "rtsc/crypto/hash.h"
#include "rtsc/crypto/random.h"
#include "rtsc/crypto/rdp_security.h"
#include "rtsc/crypto/rsa_server.h"
#include "rtsc/net/transport.h"
#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/capabilities.h"
#include "rtsc/proto/client_info.h"
#include "rtsc/proto/connection_initiation.h"
#include "rtsc/proto/finalization.h"
#include "rtsc/proto/licensing.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/share.h"
#include "rtsc/proto/tpkt.h"
#include "rtsc/proto/x224.h"

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
// encryptionMethods bits. Note the values follow the specification, not the
// (mislabeled) RdpEncryptionMethod enum: 40BIT=0x01, 128BIT=0x02, 56BIT=0x08,
// FIPS=0x10.
constexpr uint32_t kMethod40 = 0x00000001;
constexpr uint32_t kMethod128 = 0x00000002;
constexpr uint32_t kMethod56 = 0x00000008;
constexpr uint32_t kMethodFips = 0x00000010;
constexpr uint32_t kLevelClientCompatible = 0x00000002;

// Security header flags used by this server.
constexpr uint16_t kSecEncrypt = 0x0008;
constexpr uint16_t kSecInfoPkt = 0x0040;
constexpr uint16_t kSecLicensePkt = 0x0080;

// MCS channel identifiers. The I/O channel and the user channel are the two the
// client joins; the server channel id is fixed by the specification.
constexpr uint16_t kIoChannelId = 1003;
constexpr uint16_t kUserChannelId = 1001;
constexpr uint16_t kServerChannelId = 1002;
constexpr uint16_t kFirstStaticChannelId = 1004;

// The stream id used by the finalization / graphics PDUs.
constexpr uint8_t kStreamLow = 0x01;

// The X.224 connection-confirm source reference mandated by the specification.
constexpr uint16_t kCcfSourceReference = 0x1234;

constexpr size_t kReadChunk = 16384;

const char* StatusName(Status s) { return proto::to_string(s); }

// Writes a BER length determinant (short form, or 0x81/0x82 long form).
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

// ---- Server GCC user data blocks -------------------------------------------

std::vector<uint8_t> BuildServerCoreData(uint32_t client_requested_protocols) {
    ByteWriter body;
    body.u32le(0x00080004);  // RDP 5.0
    body.u32le(client_requested_protocols);
    std::vector<uint8_t> out;
    proto::GccUserData::write_block(out_writer(out), kScCore, body.data());
    return out;
}

// A tiny adapter so GccUserData::write_block can target a caller vector.
ByteWriter& out_writer(std::vector<uint8_t>& v) {
    static thread_local std::vector<uint8_t> scratch;
    scratch = v;
    (void)scratch;
    // ByteWriter owns its buffer; this helper is not used (kept for clarity).
    static thread_local ByteWriter w;
    (void)w;
    return w;
}

}  // namespace

}  // namespace rtsc::server
