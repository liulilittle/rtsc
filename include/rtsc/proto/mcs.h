#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/ber.h"
#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// T.125 MCS domain/selector constants used by RDP ([MS-RDPBCGR] 2.2.1.3-2.2.1.6).
namespace mcs {

// MCS channel identifiers. Only the server channel id is fixed by the spec;
// every other id is assigned by the peer (docs/spec/mcs-domain.md §5.3).
constexpr uint16_t kServerChannelId = 1002;  // 0x03EA, fixed by [MS-RDPBCGR] 3.2.1.1
constexpr uint16_t kMinDynamicChannelId = 1001;  // lowest assignable user/channel id
constexpr uint16_t kMaxDynamicChannelId = 65535;  // T.125 §7 Part 1 upper bound
constexpr uint16_t kGlobalChannelId = 0;  // "may be zero" channelId in Channel Join

// T.125 Connect Initial / Connect Response application tags.
constexpr uint8_t kTagConnectInitial = 0x7F;  // 0x7F 0x65
constexpr uint8_t kTagConnectResponse = 0x7F; // 0x7F 0x66

// Second byte of the multi-byte application tags above.
constexpr uint8_t kConnectInitialTagByte = 0x65;
constexpr uint8_t kConnectResponseTagByte = 0x66;

// PER aligned length determinant used by the T.124 GCC layer.
// 1 byte below 0x80; 2 bytes (0x80|hi, lo) up to 0x3FFF. The 14-bit ceiling
// follows X.691: 0x4000..0xFFFF would have to start with 0xC0..0xFF, which
// receivers decode as the fragmentation form, so those lengths are rejected.
// (mstscax.dll's FUN_180161ce0 only rejects > 0xFFFF and can therefore emit a
// fragment marker for 0x4000..0xFFFF; see evidence/mstscax/gcc-ccrq.md §5.)
Status encode_per_length(ByteWriter& w, size_t len);
Status decode_per_length(ByteReader& r, size_t& len);

// Upper bound on the whole Send Data PDU ([MS-RDPBCGR] 2.2: "MUST be restricted
// to 16,383 or fewer bytes in length to avoid ... PER extended size determinant").
constexpr size_t kMaxSendDataUserData = 16383;

}  // namespace mcs

// One MCS channel definition from a GCC Conference Create Request/Response.
struct McsChannelDef {
    uint16_t id = 0;
    uint16_t options = 0;
};

// RDP-specific GCC user data blocks ([MS-RDPBCGR] 2.2.1.3.1 .. 2.2.1.3.9).
enum class GccUserDataBlock : uint16_t {
    kCsCore = 0xC001,      // Client Core Data
    kCsSecurity = 0xC002,  // Client Security Data
    kCsNetwork = 0xC003,   // Client Network Data
    kCsCluster = 0xC004,   // Client Cluster Data
    kCsMonitor = 0xC005,   // Client Monitor Data
    kScCore = 0x0C01,      // Server Core Data
    kScSecurity = 0x0C02,  // Server Security Data
    kScNetwork = 0x0C03,   // Server Network Data
    kMcsMsgChannel = 0x1001,
    kMcsChannelJoin = 0x1002,
};

struct GccUserDataHeader {
    static constexpr size_t kSize = 4;
    uint16_t type = 0;
    uint16_t length = 0;  // includes this 4-byte header
};

// Parsed GCC user data: ordered list of (type, payload) blocks.
struct GccUserData {
    struct Block {
        uint16_t type = 0;
        std::vector<uint8_t> payload;
    };
    std::vector<Block> blocks;

    // Parses the concatenated userData blocks.
    static Status parse(const uint8_t* data, size_t size, GccUserData& out);

    // Appends one block (type + length + payload) to `w`.
    static void write_block(ByteWriter& w, uint16_t type, const std::vector<uint8_t>& payload);

    const Block* find(uint16_t type) const;
};

// T.125 MCS Connect Initial PDU ([MS-RDPBCGR] 2.2.1.3).
struct McsConnectInitial {
    // The GCC Conference Create Request (T.124) octet string payload.
    std::vector<uint8_t> gcc_conference_create_request;

    // Builds the complete TPKT-framed Connect Initial with an RDP Client
    // Core/Security/Network/Cluster/Monitor user data set.
    static std::vector<uint8_t> build(const GccUserData& user_data);

    static Status parse(const uint8_t* data, size_t size, McsConnectInitial& out);
};

// T.125 MCS Connect Response PDU ([MS-RDPBCGR] 2.2.1.4).
struct McsConnectResponse {
    uint32_t result = 0;
    std::vector<McsChannelDef> channels;
    GccUserData user_data;

    static Status parse(const uint8_t* data, size_t size, McsConnectResponse& out);
};

// T.125 `Result` enumeration, shared by Attach User Confirm and Channel Join
// Confirm (T.125 §7 Part 9). RDP only ever sends/accepts 0 and 14.
enum class McsResult : uint8_t {
    kSuccessful = 0,
    kDomainMerging = 1,
    kDomainNotHierarchical = 2,
    kNoSuchChannel = 3,
    kNoSuchDomain = 4,
    kNoSuchUser = 5,
    kNotAdmitted = 6,
    kOtherUserId = 7,
    kParametersUnacceptable = 8,
    kTokenNotAvailable = 9,
    kTokenNotPossessed = 10,
    kTooManyChannels = 11,
    kTooManyTokens = 12,
    kTooManyUsers = 13,
    kUnspecifiedFailure = 14,
    kUserRejected = 15,
};

const char* to_string(McsResult r);

// T.125 `Reason` enumeration for Disconnect Provider Ultimatum (T.125 §7 Part 9).
enum class McsDisconnectReason : uint8_t {
    kDomainDisconnected = 0,
    kProviderInitiated = 1,
    kTokenPurged = 2,
    kUserRequested = 3,
    kChannelPurged = 4,
};

const char* to_string(McsDisconnectReason r);

// T.125 `DataPriority` enumeration (T.125 §7 Part 1).
enum class McsDataPriority : uint8_t {
    kTop = 0,
    kHigh = 1,
    kMedium = 2,
    kLow = 3,
};

// T.125 `Segmentation` BIT STRING { begin(0), end(1) } SIZE(2).
enum class McsSegmentation : uint8_t {
    kMiddle = 0,      // 0b00
    kEnd = 1,         // 0b01
    kBegin = 2,       // 0b10
    kBeginEnd = 3,    // 0b11
};

// T.125 `DomainMCSPDU` choice indices used by RDP.
namespace mcs {

constexpr uint8_t kErectDomainRequest = 1;
constexpr uint8_t kDisconnectProviderUltimatum = 8;
constexpr uint8_t kAttachUserRequest = 10;
constexpr uint8_t kAttachUserConfirm = 11;
constexpr uint8_t kChannelJoinRequest = 14;
constexpr uint8_t kChannelJoinConfirm = 15;
constexpr uint8_t kSendDataRequest = 25;
constexpr uint8_t kSendDataIndication = 26;

// Encodes a DomainMCSPDU choice index as the leading octet: 6-bit index in the
// high bits plus 2 bits of octet alignment padding ([MS-RDPBCGR] 4.1.5 dumps).
constexpr uint8_t DomainMcspduOctet(uint8_t choice) {
    return static_cast<uint8_t>(choice << 2);
}

}  // namespace mcs

// Erect Domain Request ([MS-RDPBCGR] 2.2.1.5). Both fields are SHOULD-zero.
struct McsErectDomainRequest {
    uint32_t sub_height = 0;
    uint32_t sub_interval = 0;

    static std::vector<uint8_t> build(uint32_t sub_height = 0, uint32_t sub_interval = 0);
    static Status parse(const uint8_t* data, size_t size, McsErectDomainRequest& out);
};

// Attach User Request ([MS-RDPBCGR] 2.2.1.6). Carries no fields.
struct McsAttachUserRequest {
    static std::vector<uint8_t> build();
    static Status parse(const uint8_t* data, size_t size);
};

// Attach User Confirm ([MS-RDPBCGR] 2.2.1.7).
struct McsAttachUserConfirm {
    McsResult result = McsResult::kSuccessful;
    bool has_initiator = false;
    uint16_t initiator = 0;  // User Channel ID (1001..65535)

    static Status parse(const uint8_t* data, size_t size, McsAttachUserConfirm& out);
};

// Channel Join Request ([MS-RDPBCGR] 2.2.1.8).
struct McsChannelJoinRequest {
    uint16_t initiator = 0;   // UserId (1001..65535)
    uint16_t channel_id = 0;  // ChannelId (0..65535, may be zero)

    static std::vector<uint8_t> build(uint16_t initiator, uint16_t channel_id);
    static Status parse(const uint8_t* data, size_t size, McsChannelJoinRequest& out);
};

// Channel Join Confirm ([MS-RDPBCGR] 2.2.1.9).
struct McsChannelJoinConfirm {
    McsResult result = McsResult::kSuccessful;
    uint16_t initiator = 0;
    uint16_t requested = 0;
    bool has_channel_id = false;
    uint16_t channel_id = 0;

    static Status parse(const uint8_t* data, size_t size, McsChannelJoinConfirm& out);
};

// MCS Send Data Request / Indication ([MS-RDPBCGR] 3.2.5.1 / 3.3.5.1).
// Both directions share the same body; only the DomainMCSPDU choice differs.
struct McsSendData {
    uint16_t initiator = 0;
    uint16_t channel_id = 0;
    McsDataPriority priority = McsDataPriority::kHigh;
    McsSegmentation segmentation = McsSegmentation::kBeginEnd;
    std::vector<uint8_t> user_data;

    static std::vector<uint8_t> build_request(uint16_t initiator, uint16_t channel_id,
                                              const std::vector<uint8_t>& user_data,
                                              McsDataPriority priority = McsDataPriority::kHigh);
    static std::vector<uint8_t> build_indication(uint16_t initiator, uint16_t channel_id,
                                                 const std::vector<uint8_t>& user_data,
                                                 McsDataPriority priority = McsDataPriority::kHigh);
    static Status parse(const uint8_t* data, size_t size, McsSendData& out);
};

// Disconnect Provider Ultimatum ([MS-RDPBCGR] 2.2.2.3).
struct McsDisconnectProviderUltimatum {
    McsDisconnectReason reason = McsDisconnectReason::kUserRequested;

    static std::vector<uint8_t> build(McsDisconnectReason reason = McsDisconnectReason::kUserRequested);
    static Status parse(const uint8_t* data, size_t size, McsDisconnectProviderUltimatum& out);
};

}  // namespace rtsc::proto
