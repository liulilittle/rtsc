#include "rtsc/proto/mcs.h"

#include <utility>

#include "rtsc/proto/tpkt.h"
#include "rtsc/proto/x224.h"

namespace rtsc::proto {

namespace {

constexpr uint8_t kTpktVersion = 3;
constexpr size_t kTpktHeaderSize = 4;
constexpr uint8_t kX224Data[3] = {0x02, 0xF0, 0x80};

// T.124 ConnectData prefix ([MS-RDPBCGR] 4.1.3/4.1.4).
//   t124Identifier: PER Key::object = 00 05 00 14 7C 00 01
//   CCrq header:    ConnectGCCPDU/CCrq/ConferenceName/TerminationMethod/
//                   UserData bits + H.221 length determinant (00)
//   CCrsp header:   same fields with CHOICE index 1 (conferenceCreateResponse)
constexpr uint8_t kT124Identifier[7] = {0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01};
constexpr uint8_t kCcrqHeader[8] = {0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00};
constexpr uint8_t kH221KeyClient[4] = {0x44, 0x75, 0x63, 0x61};  // "Duca"
constexpr uint8_t kH221KeyServer[4] = {0x4D, 0x63, 0x44, 0x6E};  // "McDn"

// The 9 fixed bytes between the CCrsp connectPDU length determinant and the
// H.221 key: CHOICE index 1, nodeID (2), tag (2), result (1), UserData size
// (1), value/Key present bits (1), H.221 length determinant (1).
constexpr size_t kCcrspPrefixSize = 9;
constexpr uint8_t kCcrspChoiceIndex = 0x10;  // conferenceCreateResponse = 1

// DomainParameters values from [MS-RDPBCGR] 3.2.5.3.3 as captured in the
// 4.1.3 dump. Note that 64535 and 65535 are written without a leading 0x00
// sign octet in the official vector (`02 02 FC 17`, `02 02 FF FF`), so the
// encoder below emits minimal unsigned big-endian magnitudes.
constexpr int64_t kTargetParameters[8] = {34, 2, 0, 1, 0, 1, 65535, 2};
constexpr int64_t kMinimumParameters[8] = {1, 1, 1, 1, 0, 1, 1056, 2};
constexpr int64_t kMaximumParameters[8] = {65535, 64535, 65535, 1, 0, 1, 65535, 2};

constexpr size_t kDomainParameterCount = 8;

size_t ber_length_size(size_t len) {
    if (len < 0x80) return 1;
    if (len <= 0xFF) return 2;
    if (len <= 0xFFFF) return 3;
    return 4;
}

void write_ber_length(ByteWriter& w, size_t len) {
    if (len < 0x80) {
        w.u8(static_cast<uint8_t>(len));
        return;
    }
    uint8_t tmp[4];
    size_t n = 0;
    size_t v = len;
    while (v > 0) {
        tmp[n++] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
    w.u8(static_cast<uint8_t>(0x80 | n));
    for (size_t i = 0; i < n; ++i) w.u8(tmp[n - 1 - i]);
}

// Minimal unsigned big-endian INTEGER body (see kMaximumParameters comment).
void write_domain_parameters(BerWriter& w, const int64_t (&values)[kDomainParameterCount]) {
    const size_t mark = w.begin_sequence();
    for (const int64_t value : values) {
        uint8_t tmp[8];
        size_t n = 0;
        uint64_t v = static_cast<uint64_t>(value);
        do {
            tmp[n++] = static_cast<uint8_t>(v & 0xFF);
            v >>= 8;
        } while (v != 0);
        w.raw_byte(kBerInteger);
        w.raw_byte(static_cast<uint8_t>(n));
        for (size_t i = 0; i < n; ++i) w.raw_byte(tmp[n - 1 - i]);
    }
    w.end_constructed(mark, kBerSequence);
}

Status read_domain_parameters(BerReader& r) {
    BerReader sub(nullptr, 0);
    Status s = r.read_constructed(kBerSequence, sub);
    if (s != Status::Ok) return s;
    for (size_t i = 0; i < kDomainParameterCount; ++i) {
        int64_t value = 0;
        s = sub.read_integer(value);
        if (s != Status::Ok) return s;
    }
    if (!sub.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// T.125 uses the multi-octet BER tag 0x7F 0x65 / 0x7F 0x66. BerReader's
// read_header() only understands single-octet tags (it would take 0x65 for a
// 101-byte short-form length), so the application tag is consumed here.
Status read_mcs_application_tag(const uint8_t* data, size_t size, uint8_t expected_second,
                                BerReader& out) {
    if (size < 3) return Status::NeedMoreData;
    if (data[0] != mcs::kTagConnectInitial) return Status::InvalidType;
    if (data[1] != expected_second) return Status::InvalidType;

    size_t pos = 2;
    size_t len = 0;
    const uint8_t first = data[pos++];
    if (first < 0x80) {
        len = first;
    } else {
        const size_t n = first & 0x7F;
        if (n == 0 || n > 4) return Status::InvalidLength;  // indefinite / too long
        if (size - pos < n) return Status::NeedMoreData;
        if (data[pos] == 0x00) return Status::InvalidLength;  // non-minimal
        for (size_t i = 0; i < n; ++i) len = (len << 8) | data[pos++];
        if (len < 0x80) return Status::InvalidLength;  // should have used short form
    }
    if (len > size - pos) return Status::NeedMoreData;
    if (len != size - pos) return Status::InvalidLength;  // trailing garbage
    out = BerReader(data + pos, len);
    return Status::Ok;
}

Status read_tpkt(const uint8_t* data, size_t size) {
    TpktHeader tpkt;
    Status s = TpktHeader::parse(data, size, tpkt);
    if (s != Status::Ok) return s;
    if (tpkt.length != size) return Status::InvalidLength;
    return Status::Ok;
}

}  // namespace

namespace mcs {

Status encode_per_length(ByteWriter& w, size_t len) {
    if (len <= 0x7F) {
        w.u8(static_cast<uint8_t>(len));
        return Status::Ok;
    }
    // X.691 §10.9.3.7: 127 < n < 16384 uses two octets 10xxxxxx xxxxxxxx.
    // Larger values would need the fragmentation form (11xxxxxx), which RDP
    // never uses.
    if (len <= 0x3FFF) {
        w.u8(static_cast<uint8_t>(0x80 | (len >> 8)));
        w.u8(static_cast<uint8_t>(len & 0xFF));
        return Status::Ok;
    }
    return Status::InvalidLength;
}

Status decode_per_length(ByteReader& r, size_t& len) {
    uint8_t first = 0;
    if (!r.u8(first)) return Status::NeedMoreData;
    if ((first & 0x80) == 0) {
        len = first;
        return Status::Ok;
    }
    if ((first & 0xC0) == 0x80) {
        uint8_t second = 0;
        if (!r.u8(second)) return Status::NeedMoreData;
        len = (static_cast<size_t>(first & 0x3F) << 8) | second;
        return Status::Ok;
    }
    return Status::InvalidLength;  // 0xC0..0xFF = fragmentation, not allowed
}

}  // namespace mcs

Status GccUserData::parse(const uint8_t* data, size_t size, GccUserData& out) {
    out.blocks.clear();
    size_t offset = 0;
    while (offset < size) {
        if (size - offset < GccUserDataHeader::kSize) return Status::NeedMoreData;
        const uint16_t type = static_cast<uint16_t>(data[offset] |
                                                    (data[offset + 1] << 8));
        const uint16_t length = static_cast<uint16_t>(
            data[offset + 2] | (data[offset + 3] << 8));
        if (length < GccUserDataHeader::kSize) return Status::InvalidLength;
        const size_t payload_size = length - GccUserDataHeader::kSize;
        if (payload_size > size - offset - GccUserDataHeader::kSize) {
            return Status::NeedMoreData;
        }
        Block block;
        block.type = type;
        block.payload.assign(data + offset + GccUserDataHeader::kSize,
                             data + offset + length);
        out.blocks.push_back(std::move(block));
        offset += length;
    }
    return Status::Ok;
}

void GccUserData::write_block(ByteWriter& w, uint16_t type,
                              const std::vector<uint8_t>& payload) {
    w.u16le(type);
    w.u16le(static_cast<uint16_t>(payload.size() + GccUserDataHeader::kSize));
    if (!payload.empty()) w.bytes(payload.data(), payload.size());
}

const GccUserData::Block* GccUserData::find(uint16_t type) const {
    for (const auto& block : blocks) {
        if (block.type == type) return &block;
    }
    return nullptr;
}

std::vector<uint8_t> McsConnectInitial::build(const GccUserData& user_data) {
    ByteWriter block_bytes;
    for (const auto& block : user_data.blocks) {
        if (block.payload.size() + GccUserDataHeader::kSize > 0xFFFF) return {};
        GccUserData::write_block(block_bytes, block.type, block.payload);
    }

    // Length identities from evidence/mstscax/gcc-ccrq.md §5.
    const size_t s = block_bytes.size();
    const size_t connect_pdu_len = (s < 0x80 ? 13 : 14) + s;
    const size_t user_data_len = (connect_pdu_len < 0x80 ? 8 : 9) + connect_pdu_len;
    if (connect_pdu_len > 0x3FFF || user_data_len > 0x3FFF) return {};

    ByteWriter gcc;
    gcc.bytes(kT124Identifier, sizeof(kT124Identifier));
    if (mcs::encode_per_length(gcc, connect_pdu_len) != Status::Ok) return {};
    gcc.bytes(kCcrqHeader, sizeof(kCcrqHeader));
    gcc.bytes(kH221KeyClient, sizeof(kH221KeyClient));
    if (mcs::encode_per_length(gcc, s) != Status::Ok) return {};
    gcc.bytes(block_bytes.data().data(), block_bytes.size());
    if (gcc.size() != user_data_len) return {};

    const uint8_t domain_selector[1] = {0x01};
    BerWriter body;
    body.octet_string(domain_selector, sizeof(domain_selector));  // calling
    body.octet_string(domain_selector, sizeof(domain_selector));  // called
    body.boolean(true);
    write_domain_parameters(body, kTargetParameters);
    write_domain_parameters(body, kMinimumParameters);
    write_domain_parameters(body, kMaximumParameters);
    body.octet_string(gcc.data());

    const size_t body_len = body.size();
    const size_t total = kTpktHeaderSize + sizeof(kX224Data) + 2 +
                         ber_length_size(body_len) + body_len;
    if (total > 0xFFFF) return {};

    ByteWriter frame;
    frame.u8(kTpktVersion);
    frame.u8(0);
    frame.u16be(static_cast<uint16_t>(total));
    frame.bytes(kX224Data, sizeof(kX224Data));
    frame.u8(mcs::kTagConnectInitial);
    frame.u8(mcs::kConnectInitialTagByte);
    write_ber_length(frame, body_len);
    frame.bytes(body.data().data(), body.size());
    return frame.take();
}

Status McsConnectInitial::parse(const uint8_t* data, size_t size,
                                McsConnectInitial& out) {
    out.gcc_conference_create_request.clear();
    if (data == nullptr) return Status::NeedMoreData;
    Status s = read_tpkt(data, size);
    if (s != Status::Ok) return s;

    s = X224DataPrefix::parse(data + kTpktHeaderSize, size - kTpktHeaderSize);
    if (s != Status::Ok) return s;

    BerReader r(nullptr, 0);
    s = read_mcs_application_tag(data + kTpktHeaderSize + sizeof(kX224Data),
                                 size - kTpktHeaderSize - sizeof(kX224Data),
                                 mcs::kConnectInitialTagByte, r);
    if (s != Status::Ok) return s;

    const uint8_t* selector = nullptr;
    size_t selector_len = 0;
    s = r.read_octet_string_view(selector, selector_len);
    if (s != Status::Ok) return s;
    s = r.read_octet_string_view(selector, selector_len);
    if (s != Status::Ok) return s;

    bool upward = false;
    s = r.read_boolean(upward);
    if (s != Status::Ok) return s;

    for (size_t i = 0; i < 3; ++i) {
        s = read_domain_parameters(r);
        if (s != Status::Ok) return s;
    }

    const uint8_t* user_data = nullptr;
    size_t user_data_size = 0;
    s = r.read_octet_string_view(user_data, user_data_size);
    if (s != Status::Ok) return s;
    if (!r.empty()) return Status::InvalidLength;

    out.gcc_conference_create_request.assign(user_data, user_data + user_data_size);
    return Status::Ok;
}

Status McsConnectResponse::parse(const uint8_t* data, size_t size,
                                 McsConnectResponse& out) {
    out.result = 0;
    out.channels.clear();
    out.user_data.blocks.clear();
    if (data == nullptr) return Status::NeedMoreData;
    Status s = read_tpkt(data, size);
    if (s != Status::Ok) return s;

    s = X224DataPrefix::parse(data + kTpktHeaderSize, size - kTpktHeaderSize);
    if (s != Status::Ok) return s;

    BerReader r(nullptr, 0);
    s = read_mcs_application_tag(data + kTpktHeaderSize + sizeof(kX224Data),
                                 size - kTpktHeaderSize - sizeof(kX224Data),
                                 mcs::kConnectResponseTagByte, r);
    if (s != Status::Ok) return s;

    int64_t result = 0;
    s = r.read_integer(result);
    if (s != Status::Ok) return s;
    if (result < 0 || result > 0xFFFFFFFFLL) return Status::InvalidField;
    out.result = static_cast<uint32_t>(result);

    int64_t called_connect_id = 0;
    s = r.read_integer(called_connect_id);
    if (s != Status::Ok) return s;

    s = read_domain_parameters(r);
    if (s != Status::Ok) return s;

    const uint8_t* user_data = nullptr;
    size_t user_data_size = 0;
    s = r.read_octet_string_view(user_data, user_data_size);
    if (s != Status::Ok) return s;
    if (!r.empty()) return Status::InvalidLength;

    // T.124 ConnectData: the declared connectPDU length is ignored for
    // framing ([MS-RDPBCGR] 4.1.4: "the length of the connectPDU ... is
    // ignored by the client"); the OCTET STRING size is authoritative.
    if (user_data_size < sizeof(kT124Identifier)) return Status::NeedMoreData;
    for (size_t i = 0; i < sizeof(kT124Identifier); ++i) {
        if (user_data[i] != kT124Identifier[i]) return Status::InvalidField;
    }

    ByteReader gcc(user_data + sizeof(kT124Identifier),
                   user_data_size - sizeof(kT124Identifier));
    size_t declared = 0;
    s = mcs::decode_per_length(gcc, declared);
    if (s != Status::Ok) return s;

    if (gcc.remaining() < kCcrspPrefixSize + sizeof(kH221KeyServer) + 1) {
        return Status::NeedMoreData;
    }
    const uint8_t* p = gcc.cursor();
    if ((p[0] & 0xF0) != kCcrspChoiceIndex) return Status::InvalidField;
    // Byte 8 is the H.221 length determinant (len - 4); RDP always uses 4.
    if (p[8] != 0x00) return Status::InvalidField;
    for (size_t i = 0; i < sizeof(kH221KeyServer); ++i) {
        if (p[kCcrspPrefixSize + i] != kH221KeyServer[i]) return Status::InvalidField;
    }
    if (!gcc.skip(kCcrspPrefixSize + sizeof(kH221KeyServer))) {
        return Status::NeedMoreData;
    }

    size_t block_len = 0;
    s = mcs::decode_per_length(gcc, block_len);
    if (s != Status::Ok) return s;
    if (block_len > gcc.remaining()) return Status::NeedMoreData;
    s = GccUserData::parse(gcc.cursor(), block_len, out.user_data);
    if (s != Status::Ok) return s;

    // TS_UD_SC_NET (0x0C03): MCSChannelId(2) + channelCount(2) + ids(2 each).
    const GccUserData::Block* net = out.user_data.find(0x0C03);
    if (net == nullptr) return Status::Ok;
    if (net->payload.size() < 4) return Status::InvalidLength;
    const size_t count = static_cast<size_t>(net->payload[2]) |
                         (static_cast<size_t>(net->payload[3]) << 8);
    if (net->payload.size() < 4 + count * 2) return Status::InvalidLength;
    out.channels.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        McsChannelDef channel;
        channel.id = static_cast<uint16_t>(net->payload[4 + i * 2]) |
                     static_cast<uint16_t>(net->payload[5 + i * 2] << 8);
        channel.options = 0;
        out.channels.push_back(channel);
    }
    return Status::Ok;
}

}  // namespace rtsc::proto
