#include "rtsc/proto/mcs.h"

#include <algorithm>

#include "rtsc/proto/tpkt.h"

namespace rtsc::proto {

namespace {

constexpr size_t kTpktHeaderSize = 4;
constexpr uint8_t kX224Data[3] = {0x02, 0xF0, 0x80};

// PER aligned octet-string length determinant (X.691 搂10.9.3.6/.7).
// RDP forbids the fragmentation form, so anything above 0x3FFF is rejected.
Status WriteLength(ByteWriter& w, size_t len) {
    if (len <= 0x7F) {
        w.u8(static_cast<uint8_t>(len));
        return Status::Ok;
    }
    if (len <= 0x3FFF) {
        w.u8(static_cast<uint8_t>(0x80 | (len >> 8)));
        w.u8(static_cast<uint8_t>(len & 0xFF));
        return Status::Ok;
    }
    return Status::InvalidLength;
}

Status ReadLength(ByteReader& r, size_t& len) {
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
    return Status::InvalidLength;
}

// Wraps a DomainMCSPDU body in TPKT + X.224 Data.
std::vector<uint8_t> Frame(const std::vector<uint8_t>& body) {
    const size_t total = kTpktHeaderSize + sizeof(kX224Data) + body.size();
    if (total > 0xFFFF) return {};

    TpktHeader tpkt;
    tpkt.length = static_cast<uint16_t>(total);
    const auto header = tpkt.encode();

    ByteWriter w;
    w.bytes(header.data(), header.size());
    w.bytes(kX224Data, sizeof(kX224Data));
    if (!body.empty()) w.bytes(body.data(), body.size());
    return w.take();
}

// Validates TPKT + X.224 Data and returns a reader positioned at the
// DomainMCSPDU body.
Status StripTransport(const uint8_t* data, size_t size, ByteReader& out) {
    TpktHeader tpkt;
    Status s = TpktHeader::parse(data, size, tpkt);
    if (s != Status::Ok) return s;
    if (tpkt.length != size) return Status::InvalidLength;
    if (size < kTpktHeaderSize + sizeof(kX224Data)) return Status::NeedMoreData;

    ByteReader r(data + kTpktHeaderSize, size - kTpktHeaderSize);
    uint8_t b0 = 0, b1 = 0, b2 = 0;
    if (!r.u8(b0) || !r.u8(b1) || !r.u8(b2)) return Status::NeedMoreData;
    if (b0 != kX224Data[0] || b1 != kX224Data[1] || b2 != kX224Data[2]) {
        return Status::InvalidType;
    }
    out = r;
    return Status::Ok;
}

// Reads the leading octet, verifies the 6-bit choice index and drops the
// 2 alignment bits.
Status ReadChoice(ByteReader& r, uint8_t expected) {
    uint8_t octet = 0;
    if (!r.u8(octet)) return Status::NeedMoreData;
    if (static_cast<uint8_t>(octet >> 2) != expected) return Status::InvalidType;
    if ((octet & 0x03) != 0) return Status::InvalidField;  // padding must be zero
    return Status::Ok;
}

// DynamicChannelId / UserId: 1001..65535, encoded as (id - 1001) in 2 octets.
Status WriteUserId(ByteWriter& w, uint16_t id) {
    if (id < mcs::kMinDynamicChannelId) return Status::InvalidField;
    w.u16be(static_cast<uint16_t>(id - mcs::kMinDynamicChannelId));
    return Status::Ok;
}

Status ReadUserId(ByteReader& r, uint16_t& id) {
    uint16_t raw = 0;
    if (!r.u16be(raw)) return Status::NeedMoreData;
    const uint32_t value = static_cast<uint32_t>(raw) + mcs::kMinDynamicChannelId;
    if (value > mcs::kMaxDynamicChannelId) return Status::InvalidField;
    id = static_cast<uint16_t>(value);
    return Status::Ok;
}

// ChannelId: 0..65535, written as-is.
Status WriteChannelId(ByteWriter& w, uint16_t id) {
    w.u16be(id);
    return Status::Ok;
}

Status ReadChannelId(ByteReader& r, uint16_t& id) {
    if (!r.u16be(id)) return Status::NeedMoreData;
    return Status::Ok;
}

// Half-constrained INTEGER (0..MAX): 1-octet length determinant then magnitude.
Status WriteUnsignedInteger(ByteWriter& w, uint32_t value) {
    size_t n = 1;
    if (value > 0xFF) n = 2;
    if (value > 0xFFFF) n = 3;
    if (value > 0xFFFFFF) n = 4;
    w.u8(static_cast<uint8_t>(n));
    for (size_t i = 0; i < n; ++i) {
        const size_t shift = 8 * (n - 1 - i);
        w.u8(static_cast<uint8_t>((value >> shift) & 0xFF));
    }
    return Status::Ok;
}

Status ReadUnsignedInteger(ByteReader& r, uint32_t& value) {
    uint8_t n = 0;
    if (!r.u8(n)) return Status::NeedMoreData;
    if (n == 0 || n > 4) return Status::InvalidLength;
    if (r.remaining() < n) return Status::NeedMoreData;
    uint32_t v = 0;
    for (uint8_t i = 0; i < n; ++i) {
        uint8_t b = 0;
        if (!r.u8(b)) return Status::NeedMoreData;
        v = (v << 8) | b;
    }
    value = v;
    return Status::Ok;
}

}  // namespace

const char* to_string(McsResult r) {
    switch (r) {
        case McsResult::kSuccessful: return "rt-successful";
        case McsResult::kDomainMerging: return "rt-domain-merging";
        case McsResult::kDomainNotHierarchical: return "rt-domain-not-hierarchical";
        case McsResult::kNoSuchChannel: return "rt-no-such-channel";
        case McsResult::kNoSuchDomain: return "rt-no-such-domain";
        case McsResult::kNoSuchUser: return "rt-no-such-user";
        case McsResult::kNotAdmitted: return "rt-not-admitted";
        case McsResult::kOtherUserId: return "rt-other-user-id";
        case McsResult::kParametersUnacceptable: return "rt-parameters-unacceptable";
        case McsResult::kTokenNotAvailable: return "rt-token-not-available";
        case McsResult::kTokenNotPossessed: return "rt-token-not-possessed";
        case McsResult::kTooManyChannels: return "rt-too-many-channels";
        case McsResult::kTooManyTokens: return "rt-too-many-tokens";
        case McsResult::kTooManyUsers: return "rt-too-many-users";
        case McsResult::kUnspecifiedFailure: return "rt-unspecified-failure";
        case McsResult::kUserRejected: return "rt-user-rejected";
    }
    return "rt-unknown";
}

const char* to_string(McsDisconnectReason r) {
    switch (r) {
        case McsDisconnectReason::kDomainDisconnected: return "rn-domain-disconnected";
        case McsDisconnectReason::kProviderInitiated: return "rn-provider-initiated";
        case McsDisconnectReason::kTokenPurged: return "rn-token-purged";
        case McsDisconnectReason::kUserRequested: return "rn-user-requested";
        case McsDisconnectReason::kChannelPurged: return "rn-channel-purged";
    }
    return "rn-unknown";
}

// ---- Erect Domain Request -------------------------------------------------

std::vector<uint8_t> McsErectDomainRequest::build(uint32_t sub_height,
                                                  uint32_t sub_interval) {
    ByteWriter body;
    body.u8(mcs::DomainMcspduOctet(mcs::kErectDomainRequest));
    WriteUnsignedInteger(body, sub_height);
    WriteUnsignedInteger(body, sub_interval);
    const auto bytes = body.data();
    return Frame(std::vector<uint8_t>(bytes.begin(), bytes.end()));
}

Status McsErectDomainRequest::parse(const uint8_t* data, size_t size,
                                    McsErectDomainRequest& out) {
    ByteReader r(nullptr, 0);
    Status s = StripTransport(data, size, r);
    if (s != Status::Ok) return s;
    s = ReadChoice(r, mcs::kErectDomainRequest);
    if (s != Status::Ok) return s;
    s = ReadUnsignedInteger(r, out.sub_height);
    if (s != Status::Ok) return s;
    s = ReadUnsignedInteger(r, out.sub_interval);
    if (s != Status::Ok) return s;
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- Attach User Request --------------------------------------------------

std::vector<uint8_t> McsAttachUserRequest::build() {
    const std::vector<uint8_t> body = {mcs::DomainMcspduOctet(mcs::kAttachUserRequest)};
    return Frame(body);
}

Status McsAttachUserRequest::parse(const uint8_t* data, size_t size) {
    ByteReader r(nullptr, 0);
    Status s = StripTransport(data, size, r);
    if (s != Status::Ok) return s;
    s = ReadChoice(r, mcs::kAttachUserRequest);
    if (s != Status::Ok) return s;
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- Attach User Confirm --------------------------------------------------

Status McsAttachUserConfirm::parse(const uint8_t* data, size_t size,
                                   McsAttachUserConfirm& out) {
    ByteReader r(nullptr, 0);
    Status s = StripTransport(data, size, r);
    if (s != Status::Ok) return s;

    // Layout from the [MS-RDPBCGR] 4.1.6 dump (0x2E 0x00 0x06):
    //   octet0 = choice(6) | initiator-present(1) | result bit3(1)
    //   octet1 = result bits 2..0 + padding
    uint8_t b0 = 0;
    if (!r.u8(b0)) return Status::NeedMoreData;
    if (static_cast<uint8_t>(b0 >> 2) != mcs::kAttachUserConfirm) {
        return Status::InvalidType;
    }
    out.has_initiator = (b0 & 0x02) != 0;
    uint8_t result_high = static_cast<uint8_t>(b0 & 0x01);

    uint8_t b1 = 0;
    if (!r.u8(b1)) return Status::NeedMoreData;
    const uint8_t result = static_cast<uint8_t>((result_high << 3) | (b1 >> 5));
    if (result > 15) return Status::InvalidField;
    out.result = static_cast<McsResult>(result);
    if ((b1 & 0x1F) != 0) return Status::InvalidField;  // alignment padding

    if (out.has_initiator) {
        s = ReadUserId(r, out.initiator);
        if (s != Status::Ok) return s;
    }
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- Channel Join Request -------------------------------------------------

std::vector<uint8_t> McsChannelJoinRequest::build(uint16_t initiator,
                                                  uint16_t channel_id) {
    ByteWriter body;
    body.u8(mcs::DomainMcspduOctet(mcs::kChannelJoinRequest));
    if (WriteUserId(body, initiator) != Status::Ok) return {};
    WriteChannelId(body, channel_id);
    const auto bytes = body.data();
    return Frame(std::vector<uint8_t>(bytes.begin(), bytes.end()));
}

Status McsChannelJoinRequest::parse(const uint8_t* data, size_t size,
                                    McsChannelJoinRequest& out) {
    ByteReader r(nullptr, 0);
    Status s = StripTransport(data, size, r);
    if (s != Status::Ok) return s;
    s = ReadChoice(r, mcs::kChannelJoinRequest);
    if (s != Status::Ok) return s;
    s = ReadUserId(r, out.initiator);
    if (s != Status::Ok) return s;
    s = ReadChannelId(r, out.channel_id);
    if (s != Status::Ok) return s;
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- Channel Join Confirm -------------------------------------------------

Status McsChannelJoinConfirm::parse(const uint8_t* data, size_t size,
                                    McsChannelJoinConfirm& out) {
    ByteReader r(nullptr, 0);
    Status s = StripTransport(data, size, r);
    if (s != Status::Ok) return s;

    // Layout from the [MS-RDPBCGR] 4.1.7 dump (0x3E 0x00 0x00 0x06 0x03 0xEF ...):
    //   octet0 = choice(6) | channelId-present(1) | result bit3(1)
    //   octet1 = result bits 2..0 + padding
    uint8_t b0 = 0;
    if (!r.u8(b0)) return Status::NeedMoreData;
    if (static_cast<uint8_t>(b0 >> 2) != mcs::kChannelJoinConfirm) {
        return Status::InvalidType;
    }
    out.has_channel_id = (b0 & 0x02) != 0;
    const uint8_t result_high = static_cast<uint8_t>(b0 & 0x01);

    uint8_t b1 = 0;
    if (!r.u8(b1)) return Status::NeedMoreData;
    const uint8_t result = static_cast<uint8_t>((result_high << 3) | (b1 >> 5));
    if (result > 15) return Status::InvalidField;
    out.result = static_cast<McsResult>(result);
    if ((b1 & 0x1F) != 0) return Status::InvalidField;

    s = ReadUserId(r, out.initiator);
    if (s != Status::Ok) return s;
    s = ReadChannelId(r, out.requested);
    if (s != Status::Ok) return s;
    if (out.has_channel_id) {
        s = ReadChannelId(r, out.channel_id);
        if (s != Status::Ok) return s;
    }
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- Send Data ------------------------------------------------------------

namespace {

std::vector<uint8_t> BuildSendData(uint8_t choice, uint16_t initiator,
                                   uint16_t channel_id,
                                   const std::vector<uint8_t>& user_data,
                                   McsDataPriority priority) {
    if (user_data.size() > mcs::kMaxSendDataUserData) return {};
    if (initiator < mcs::kMinDynamicChannelId) return {};

    ByteWriter body;
    body.u8(mcs::DomainMcspduOctet(choice));
    if (WriteUserId(body, initiator) != Status::Ok) return {};
    WriteChannelId(body, channel_id);

    // dataPriority(2) | segmentation(2) | padding(4) -> always 0x70 for RDP.
    const uint8_t flags = static_cast<uint8_t>(
        (static_cast<uint8_t>(priority) << 6) |
        (static_cast<uint8_t>(McsSegmentation::kBeginEnd) << 4));
    body.u8(flags);

    if (WriteLength(body, user_data.size()) != Status::Ok) return {};
    if (!user_data.empty()) body.bytes(user_data.data(), user_data.size());

    const auto bytes = body.data();
    return Frame(std::vector<uint8_t>(bytes.begin(), bytes.end()));
}

}  // namespace

std::vector<uint8_t> McsSendData::build_request(uint16_t initiator, uint16_t channel_id,
                                                const std::vector<uint8_t>& user_data,
                                                McsDataPriority priority) {
    return BuildSendData(mcs::kSendDataRequest, initiator, channel_id, user_data, priority);
}

std::vector<uint8_t> McsSendData::build_indication(uint16_t initiator, uint16_t channel_id,
                                                   const std::vector<uint8_t>& user_data,
                                                   McsDataPriority priority) {
    return BuildSendData(mcs::kSendDataIndication, initiator, channel_id, user_data,
                         priority);
}

Status McsSendData::parse(const uint8_t* data, size_t size, McsSendData& out) {
    ByteReader r(nullptr, 0);
    Status s = StripTransport(data, size, r);
    if (s != Status::Ok) return s;

    uint8_t octet = 0;
    if (!r.u8(octet)) return Status::NeedMoreData;
    const uint8_t choice = static_cast<uint8_t>(octet >> 2);
    if (choice != mcs::kSendDataRequest && choice != mcs::kSendDataIndication) {
        return Status::InvalidType;
    }
    if ((octet & 0x03) != 0) return Status::InvalidField;

    s = ReadUserId(r, out.initiator);
    if (s != Status::Ok) return s;
    s = ReadChannelId(r, out.channel_id);
    if (s != Status::Ok) return s;

    uint8_t flags = 0;
    if (!r.u8(flags)) return Status::NeedMoreData;
    const uint8_t priority = static_cast<uint8_t>(flags >> 6);
    if (priority > 3) return Status::InvalidField;
    out.priority = static_cast<McsDataPriority>(priority);
    out.segmentation = static_cast<McsSegmentation>((flags >> 4) & 0x03);
    if ((flags & 0x0F) != 0) return Status::InvalidField;  // alignment padding

    size_t len = 0;
    s = ReadLength(r, len);
    if (s != Status::Ok) return s;
    if (len > mcs::kMaxSendDataUserData) return Status::InvalidLength;
    if (r.remaining() < len) return Status::NeedMoreData;
    out.user_data.assign(r.cursor(), r.cursor() + len);
    if (!r.skip(len)) return Status::NeedMoreData;
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

// ---- Disconnect Provider Ultimatum ----------------------------------------

std::vector<uint8_t> McsDisconnectProviderUltimatum::build(McsDisconnectReason reason) {
    if (static_cast<uint8_t>(reason) > 4) return {};
    // octet0 = choice(6) | reason bits 2..1 ; octet1 = reason bit 0 + padding
    const uint8_t r = static_cast<uint8_t>(reason);
    ByteWriter body;
    body.u8(static_cast<uint8_t>(mcs::DomainMcspduOctet(mcs::kDisconnectProviderUltimatum) |
                                 ((r >> 1) & 0x03)));
    body.u8(static_cast<uint8_t>((r & 0x01) << 7));
    const auto bytes = body.data();
    return Frame(std::vector<uint8_t>(bytes.begin(), bytes.end()));
}

Status McsDisconnectProviderUltimatum::parse(const uint8_t* data, size_t size,
                                             McsDisconnectProviderUltimatum& out) {
    ByteReader r(nullptr, 0);
    Status s = StripTransport(data, size, r);
    if (s != Status::Ok) return s;

    uint8_t b0 = 0;
    if (!r.u8(b0)) return Status::NeedMoreData;
    if (static_cast<uint8_t>(b0 >> 2) != mcs::kDisconnectProviderUltimatum) {
        return Status::InvalidType;
    }
    const uint8_t reason_high = static_cast<uint8_t>(b0 & 0x03);

    uint8_t b1 = 0;
    if (!r.u8(b1)) return Status::NeedMoreData;
    const uint8_t reason = static_cast<uint8_t>((reason_high << 1) | (b1 >> 7));
    if (reason > 4) return Status::InvalidField;
    out.reason = static_cast<McsDisconnectReason>(reason);
    if ((b1 & 0x7F) != 0) return Status::InvalidField;  // alignment padding
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

}  // namespace rtsc::proto
