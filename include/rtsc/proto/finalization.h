#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/share.h"

namespace rtsc::proto {

// Connection Finalization PDUs ([MS-RDPBCGR] 1.3.1.1 phase 8).
//
// Ordering rules (1.3.1.1):
//   - The client-to-server PDUs have no dependency on any server-to-client PDU,
//     so they may be batched, provided the internal order is preserved:
//       Synchronize -> Control(Cooperate) -> Control(RequestControl)
//         -> [PersistentKeyList...] -> FontList
//   - The server-to-client PDUs do depend on client PDUs:
//       Server Synchronize responds to Confirm Active (not to Client Synchronize)
//       Server Control(Cooperate) follows Server Synchronize
//       Server Control(GrantedControl) responds to Client RequestControl
//       Server FontMap responds to Client FontList, and unlocks graphics output

// TS_SYNCHRONIZE_PDU ([MS-RDPBCGR] 2.2.1.14.1), 22 bytes including the header.
struct SynchronizePdu {
    static constexpr size_t kSize = ShareDataHeader::kSize + 4;
    static constexpr uint16_t kSyncMsgType = 1;

    uint16_t message_type = kSyncMsgType;
    // The client SHOULD set this to the Server Channel ID. The server SHOULD set
    // it to 0 but in practice leaves it uninitialized, so a receiver must ignore
    // the field rather than validate it.
    uint16_t target_user = 0;

    static Status parse(const uint8_t* data, size_t size, SynchronizePdu& out);
    // Writes the share data header (pduType2 = synchronize) plus the payload.
    void write(ByteWriter& w, const ShareDataHeader& header) const;
};

// TS_CONTROL_PDU action values ([MS-RDPBCGR] 2.2.1.15.1).
enum class ControlAction : uint16_t {
    kRequestControl = 0x0001,
    kGrantedControl = 0x0002,
    kDetach = 0x0003,
    kCooperate = 0x0004,
};

const char* to_string(ControlAction action);

// TS_CONTROL_PDU ([MS-RDPBCGR] 2.2.1.15.1), 26 bytes including the header.
// Reused by four PDUs: Client Cooperate, Client Request Control, Server
// Cooperate, Server Granted Control.
struct ControlPdu {
    static constexpr size_t kSize = ShareDataHeader::kSize + 8;

    ControlAction action = ControlAction::kCooperate;
    // Both fields MUST be ignored by the receiver: the client sends zeros, but
    // Server Granted Control carries the user/server channel IDs.
    uint16_t grant_id = 0;
    uint32_t control_id = 0;

    static Status parse(const uint8_t* data, size_t size, ControlPdu& out);
    void write(ByteWriter& w, const ShareDataHeader& header) const;
};

// TS_FONT_LIST_PDU ([MS-RDPBCGR] 2.2.1.18.1), 26 bytes including the header.
//
// All four payload fields MUST be ignored by the server; the SHOULD values below
// are what a client sends.
struct FontListPdu {
    static constexpr size_t kSize = ShareDataHeader::kSize + 8;
    static constexpr uint16_t kListFlagsFirst = 0x0001;
    static constexpr uint16_t kListFlagsLast = 0x0002;

    uint16_t number_fonts = 0;
    uint16_t total_num_fonts = 0;
    uint16_t list_flags = kListFlagsFirst | kListFlagsLast;
    uint16_t entry_size = 0x0032;  // 50

    static Status parse(const uint8_t* data, size_t size, FontListPdu& out);
    void write(ByteWriter& w, const ShareDataHeader& header) const;
};

// TS_FONT_MAP_PDU ([MS-RDPBCGR] 2.2.1.22.1), 26 bytes including the header.
//
// The entrySize differs from Font List (4, not 50); do not share the constant.
struct FontMapPdu {
    static constexpr size_t kSize = ShareDataHeader::kSize + 8;
    static constexpr uint16_t kMapFlagsFirst = 0x0001;
    static constexpr uint16_t kMapFlagsLast = 0x0002;

    uint16_t number_entries = 0;
    uint16_t total_num_entries = 0;
    uint16_t map_flags = kMapFlagsFirst | kMapFlagsLast;
    uint16_t entry_size = 0x0004;

    static Status parse(const uint8_t* data, size_t size, FontMapPdu& out);
    void write(ByteWriter& w, const ShareDataHeader& header) const;
};

// TS_DEACTIVATE_ALL_PDU ([MS-RDPBCGR] 2.2.3.1.1).
//
// Note the section number: 2.2.3.1, not 2.2.1.13.3 (which does not exist).
struct DeactivateAllPdu {
    uint32_t share_id = 0;
    std::vector<uint8_t> source_descriptor;  // SHOULD be 0x00

    static Status parse(const uint8_t* data, size_t size, DeactivateAllPdu& out);
};

// TS_BITMAPCACHE_PERSISTENT_LIST_PDU ([MS-RDPBCGR] 2.2.1.17.1).
//
// Layout: 18-byte share data header + 24 fixed bytes + 8 bytes per entry.
// The entry count is derived from the five numEntriesCacheN fields, which is the
// only reliable bound for the trailing array.
struct PersistentKeyListPdu {
    static constexpr size_t kFixedSize = ShareDataHeader::kSize + 24;
    static constexpr size_t kEntrySize = 8;
    static constexpr uint32_t kMaxTotalKeys = 262144;
    static constexpr uint8_t kPersistFirstPdu = 0x01;
    static constexpr uint8_t kPersistLastPdu = 0x02;

    uint16_t num_entries[5] = {0, 0, 0, 0, 0};
    uint16_t total_entries[5] = {0, 0, 0, 0, 0};
    uint8_t bit_mask = 0;
    // Each entry is Key1 (low 32 bits) then Key2 (high 32 bits).
    std::vector<uint32_t> key1;
    std::vector<uint32_t> key2;

    // Parses the PDU and validates that the entry counts match the length.
    static Status parse(const uint8_t* data, size_t size,
                        PersistentKeyListPdu& out);
};

// Builds a fully framed slow-path data PDU: share data header (with totalLength
// and pduType2 filled in) followed by the payload.
//
// `payload_size` is the payload length excluding the header; `stream_id` is
// normally STREAM_LOW (0x01) for client-to-server finalization PDUs.
std::vector<uint8_t> BuildSlowPathDataPdu(uint16_t pdu_source, uint32_t share_id,
                                          uint8_t stream_id,
                                          ShareDataPduType pdu_type2,
                                          const std::vector<uint8_t>& payload);

}  // namespace rtsc::proto
