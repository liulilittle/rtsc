// Smart card device redirection payloads ([MS-RDPESC]).
//
// The smart card device is announced over the rdpdr channel as
// RDPDR_DTYP_SMARTCARD (0x00000020) with a zero-length DeviceData field
// ([MS-RDPEFS] 2.2.1.3) and carries IRP_MJ_DEVICE_CONTROL requests whose
// IoControlCode is one of the SCARD_IOCTL_* values below.
//
// The InputBuffer/OutputBuffer of those requests are NOT plain little-endian
// structs: [MS-RDPESC] 1.3 step 1/step 9 says the call and return packets are
// encoded with the NDR type serialization of [MS-RPCE] 2.2.6. That means every
// buffer starts with an 8-byte common type header ([MS-RPCE] 2.2.6.1), an
// 8-byte private type header ([MS-RPCE] 2.2.6.2), and then the structure in NDR
// representation: fixed fields inline, variable fields as [unique]/[size_is]
// pointers (0x00020000 + index*4, NULL = 0) whose referents follow the inline
// part in pointer order, each referent padded to a 4-byte boundary, and the
// whole stream padded to 8 bytes with ObjectBufferLength covering that padding.
//
// Field order comes from the [MS-RDPESC] IDL (section 6 Appendix A, restated in
// the 2.2.1/2.2.2/2.2.3 per-structure sections). The wire behaviour of the
// referent ordering was cross-checked against FreeRDP
// libfreerdp/utils/smartcard_pack.c (the implementation Windows interoperates
// with) and IronRDP crates/ironrdp-rdpdr/src/pdu/esc/{rpce,ndr}.rs.
//
// The SCARD_IOCTL_* values are taken from the [MS-RDPESC] 3.1.4 section titles.
// Note that some older task lists quote different numbers (LISTREADERSA
// 0x00090024, DISCONNECT 0x0009002C, TRANSMIT 0x00090038, STATUSA 0x000900F0);
// in the spec those values are LISTREADERGROUPSW, LISTREADERSW, an unused
// number and READCACHEA respectively.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// SCARD_IOCTL_* ([MS-RDPESC] 3.1.4 section titles carry the values).
enum class ScardIoctl : uint32_t {
    kEstablishContext = 0x00090014,   // 3.1.4.1
    kReleaseContext = 0x00090018,     // 3.1.4.2
    kIsValidContext = 0x0009001C,     // 3.1.4.3
    kListReaderGroupsA = 0x00090020,  // 3.1.4.5
    kListReaderGroupsW = 0x00090024,  // 3.1.4.6
    kListReadersA = 0x00090028,       // 3.1.4.7
    kListReadersW = 0x0009002C,       // 3.1.4.8
    kLocateCardsA = 0x00090098,       // 3.1.4.21
    kLocateCardsW = 0x0009009C,       // 3.1.4.22
    kGetStatusChangeA = 0x000900A0,   // 3.1.4.23
    kGetStatusChangeW = 0x000900A4,   // 3.1.4.24
    kCancel = 0x000900A8,             // 3.1.4.27
    kConnectA = 0x000900AC,           // 3.1.4.28
    kConnectW = 0x000900B0,           // 3.1.4.29
    kReconnect = 0x000900B4,          // 3.1.4.36
    kDisconnect = 0x000900B8,         // 3.1.4.30
    kBeginTransaction = 0x000900BC,   // 3.1.4.31
    kEndTransaction = 0x000900C0,     // 3.1.4.32
    kState = 0x000900C4,              // 3.1.4.40
    kStatusA = 0x000900C8,            // 3.1.4.33
    kStatusW = 0x000900CC,            // 3.1.4.34
    kTransmit = 0x000900D0,           // 3.1.4.35
    kControl = 0x000900D4,            // 3.1.4.37
    kGetAttrib = 0x000900D8,          // 3.1.4.38
    kSetAttrib = 0x000900DC,          // 3.1.4.39
    kAccessStartedEvent = 0x000900E0,  // 3.1.4.4
    kLocateCardsByAtrA = 0x000900E8,  // 3.1.4.25
    kLocateCardsByAtrW = 0x000900EC,  // 3.1.4.26
    kReadCacheA = 0x000900F0,         // 3.1.4.42
    kReadCacheW = 0x000900F4,         // 3.1.4.43
    kWriteCacheA = 0x000900F8,        // 3.1.4.44
    kWriteCacheW = 0x000900FC,        // 3.1.4.45
    kGetTransmitCount = 0x00090100,   // 3.1.4.41
    kGetReaderIcon = 0x00090104,      // 3.1.4.47
    kGetDeviceTypeId = 0x00090108,    // 3.1.4.48
};

// Range limits from the IDL in [MS-RDPESC] 6 Appendix A.
constexpr size_t kScardMaxContextBytes = 16;      // cbContext/cbHandle 0..16
constexpr size_t kScardMaxExtraBytes = 1024;      // SCardIO_Request cbExtraBytes
constexpr size_t kScardMaxTransmitBytes = 66560;  // cbSendLength/cbRecvLength
constexpr size_t kScardMaxMultiStringBytes = 65536;  // cBytes 0..65536
constexpr size_t kScardMaxReaders = 11;           // GetStatusChange cReaders
constexpr size_t kScardMaxAtrMasks = 1000;        // LocateCardsByATR cAtrs

// SCARD_E_TIMEOUT: GetStatusChange/LocateCards_Return keeps cReaders on
// timeout (FreeRDP smartcard_pack_get_status_change_return).
constexpr uint32_t kScardETimeout = 0x8010000A;
constexpr size_t kScardMaxAtr = 36;               // ReaderState_Common rgbAtr
constexpr size_t kScardMaxStatusAtr = 32;         // Status_Return pbAtr
constexpr size_t kScardMaxIconBytes = 4194304;    // GetReaderIcon_Return cbDataLen
// Upper bound on the NDR object buffer a single smart card IRP may declare.
// The enclosing rdpdr channel message is smaller, but checking here rejects a
// malformed length before any large allocation happens.
constexpr size_t kScardMaxPayloadBytes = 1u << 20;

// REDIR_SCARDCONTEXT ([MS-RDPESC] 2.2.1.1): cbContext + opaque pbContext.
// An empty `bytes` encodes cbContext = 0 with a NULL pbContext, which the
// protocol uses for a failed EstablishContext return.
struct ScardContext {
    std::vector<uint8_t> bytes;

    bool empty() const { return bytes.empty(); }
};

// REDIR_SCARDHANDLE ([MS-RDPESC] 2.2.1.2).
struct ScardHandle {
    ScardContext context;
    std::vector<uint8_t> bytes;
};

// SCardIO_Request ([MS-RDPESC] 2.2.1.8).
struct ScardIoRequest {
    uint32_t protocol = 0;
    std::vector<uint8_t> extra;
};

// ReaderState_Common_Call ([MS-RDPESC] 2.2.1.5) plus the ANSI reader name.
struct ScardReaderStateA {
    std::string reader;
    uint32_t current_state = 0;
    uint32_t event_state = 0;
    std::vector<uint8_t> atr;  // at most kScardMaxAtr bytes
};

// ReaderStateW ([MS-RDPESC] 2.2.1.7): reader name is UTF-16LE.
struct ScardReaderStateW {
    std::u16string reader;
    uint32_t current_state = 0;
    uint32_t event_state = 0;
    std::vector<uint8_t> atr;  // at most kScardMaxAtr bytes
};

// ReaderState_Return ([MS-RDPESC] 2.2.1.11).
struct ScardReaderStateReturn {
    uint32_t current_state = 0;
    uint32_t event_state = 0;
    std::vector<uint8_t> atr;  // at most kScardMaxAtr bytes
};

// LocateCards_ATRMask ([MS-RDPESC] 2.2.1.6).
struct ScardAtrMask {
    uint32_t cb_atr = 0;
    std::vector<uint8_t> atr;   // cb_atr bytes
    std::vector<uint8_t> mask;  // cb_atr bytes
};

// A decoded SCARD_IOCTL call (TS server -> TS client). Only the fields that
// belong to `code` are populated; the rest keep their default values.
struct ScardCall {
    ScardIoctl code = ScardIoctl::kEstablishContext;

    // EstablishContext_Call 2.2.2.1.
    uint32_t scope = 0;

    // Context_Call 2.2.2.2.
    ScardContext context;

    // ListReaderGroups_Call 2.2.2.3.
    uint32_t groups_is_null = 0;
    uint32_t groups_cch = 0;

    // ListReaders_Call 2.2.2.4.
    std::vector<uint8_t> groups_msz;  // raw ANSI multistring
    uint32_t readers_is_null = 0;
    uint32_t readers_cch = 0;

    // GetStatusChangeA_Call 2.2.2.11.
    uint32_t timeout = 0;
    std::vector<ScardReaderStateA> reader_states;

    // GetStatusChangeW_Call 2.2.2.12 (reader names are UTF-16LE).
    std::vector<ScardReaderStateW> reader_states_w;

    // LocateCardsA_Call 2.2.2.9. `cards_msz` is the raw ANSI multistring.
    std::vector<uint8_t> cards_msz;

    // LocateCardsByATRA_Call 2.2.2.23.
    std::vector<ScardAtrMask> atr_masks;

    // ConnectA_Call 2.2.2.13 (Connect_Common 2.2.1.3).
    std::string reader;
    uint32_t share_mode = 0;
    uint32_t preferred_protocols = 0;

    // HCardAndDisposition_Call 2.2.2.16 (Disconnect/Begin/EndTransaction).
    ScardHandle handle;
    uint32_t disposition = 0;

    // State_Call 2.2.2.17.
    uint32_t atr_is_null = 0;
    uint32_t atr_capacity = 0;

    // Reconnect_Call 2.2.2.15 (reuses handle/share_mode/preferred_protocols).
    uint32_t initialization = 0;

    // Transmit_Call 2.2.2.19.
    ScardIoRequest send_pci;
    std::vector<uint8_t> send_buffer;
    std::optional<ScardIoRequest> recv_pci;
    uint32_t recv_buffer_is_null = 0;
    uint32_t recv_length = 0;

    // Control_Call 2.2.2.20.
    uint32_t control_code = 0;
    std::vector<uint8_t> in_buffer;
    uint32_t out_buffer_is_null = 0;
    uint32_t out_buffer_size = 0;

    // Status_Call 2.2.2.18.
    uint32_t reader_names_is_null = 0;
    uint32_t reader_names_cch = 0;
    uint32_t atr_length = 0;

    // GetAttrib_Call 2.2.2.21.
    uint32_t attr_id = 0;
    uint32_t attr_is_null = 0;
    uint32_t attr_capacity = 0;

    // SetAttrib_Call 2.2.2.22.
    uint32_t set_attr_length = 0;
    std::vector<uint8_t> set_attr_value;

    // ReadCacheA_Call 2.2.2.25 / ReadCache_Common 2.2.1.9.
    std::string lookup_name;
    // ReadCacheW_Call 2.2.2.26 uses a UTF-16LE [string] lookup name.
    std::u16string lookup_name_w;
    std::vector<uint8_t> card_id;  // UUID, 16 bytes
    uint32_t freshness = 0;
    uint32_t cache_is_null = 0;
    uint32_t cache_capacity = 0;

    // WriteCacheA_Call 2.2.2.27 / WriteCache_Common 2.2.1.10.
    std::vector<uint8_t> write_cache_data;

    // GetReaderIcon_Call 2.2.2.31: [string] wchar_t* szReaderName.
    std::u16string reader_name;
};

// A SCARD_IOCTL return (TS client -> TS server). Only the fields that belong to
// the IOCTL are encoded; the rest are ignored.
struct ScardReturn {
    uint32_t return_code = 0;

    // EstablishContext_Return 2.2.3.2.
    ScardContext context;

    // ListReaderGroups_Return / ListReaders_Return 2.2.3.4. `nullopt` means a
    // NULL msz (length-probe reply) and `multi_string_length` supplies cBytes;
    // otherwise cBytes is the referent size.
    std::optional<std::vector<uint8_t>> multi_string;
    uint32_t multi_string_length = 0;

    // GetStatusChange_Return 2.2.3.5.
    std::vector<ScardReaderStateReturn> reader_states;

    // Connect_Return 2.2.3.8.
    ScardHandle handle;
    uint32_t active_protocol = 0;

    // Transmit_Return 2.2.3.11. `nullopt` means a NULL pbRecvBuffer
    // (length-probe reply) and `recv_length` supplies cbRecvLength.
    std::optional<ScardIoRequest> recv_pci;
    std::optional<std::vector<uint8_t>> recv_buffer;
    uint32_t recv_length = 0;

    // Control_Return 2.2.3.6. Same NULL-buffer convention.
    std::optional<std::vector<uint8_t>> out_buffer;
    uint32_t out_length = 0;

    // Status_Return 2.2.3.10. Same NULL-multistring convention.
    std::optional<std::vector<uint8_t>> reader_names;
    uint32_t reader_names_length = 0;
    uint32_t state = 0;
    uint32_t protocol = 0;
    std::vector<uint8_t> atr;  // at most kScardMaxStatusAtr bytes

    // State_Return 2.2.3.9. `nullopt` means a NULL rgAtr (probe reply) and
    // `state_atr_length` supplies cbAtrLen.
    std::optional<std::vector<uint8_t>> state_atr;
    uint32_t state_atr_length = 0;

    // GetAttrib_Return 2.2.3.12. `nullopt` means a NULL pbAttr (length-probe
    // reply) and `attr_length` supplies cbAttrLen.
    std::optional<std::vector<uint8_t>> attr;
    uint32_t attr_length = 0;

    // ReadCache_Return 2.2.3.1. Same NULL-data convention.
    std::optional<std::vector<uint8_t>> cache;
    uint32_t cache_length = 0;

    // GetReaderIcon_Return 2.2.3.14. `nullopt` means a NULL pbData.
    std::optional<std::vector<uint8_t>> icon;
    uint32_t icon_length = 0;

    // GetDeviceTypeId_Return 2.2.3.13.
    uint32_t device_type_id = 0;

    // GetTransmitCount_Return 2.2.3.13.
    uint32_t transmit_count = 0;
};

// NDR common type header ([MS-RPCE] 2.2.6.1), 8 bytes:
//   Version(1)=1, Endianness(1)=0x10, CommonHeaderLength(2)=8, Filler(4)=0xCCCCCCCC
// NDR private header ([MS-RPCE] 2.2.6.2), 8 bytes:
//   ObjectBufferLength(4), Filler(4)=0
// ObjectBufferLength includes the trailing 8-byte padding.
struct ScardNdrHeader {
    static constexpr size_t kCommonSize = 8;
    static constexpr size_t kPrivateSize = 8;
    static constexpr size_t kSize = kCommonSize + kPrivateSize;

    uint32_t object_buffer_length = 0;

    // Validates both headers. On success `body_offset` is kSize and
    // `body_size` is ObjectBufferLength, which the caller must also compare
    // with (size - body_offset) before trusting it for slicing.
    static Status parse(const uint8_t* data, size_t size, ScardNdrHeader& out,
                        size_t& body_offset, size_t& body_size);

    // True when the bytes start with a well-formed header pair whose declared
    // object buffer fits inside `size`.
    static bool looks_like_header(const uint8_t* data, size_t size);
};

// Decodes the SCARD_IOCTL call in `data` (the InputBuffer of a DR_CONTROL_REQ,
// including the NDR headers). Returns Status::InvalidType for an IOCTL this
// module does not implement; every length or pointer inconsistency is
// InvalidField / InvalidLength / NeedMoreData (fail closed).
Status ParseScardCall(uint32_t code, const uint8_t* data, size_t size,
                      ScardCall& out);

// Encodes the return packet for `code` (the OutputBuffer of the
// DR_CONTROL_RSP, including the NDR headers and the 8-byte alignment padding).
// Returns an empty vector when the payload violates a [MS-RDPESC] range.
std::vector<uint8_t> EncodeScardReturn(ScardIoctl code, const ScardReturn& ret);

// True when `code` is one of the SCARD_IOCTL_* values this module implements.
bool IsSupportedScardIoctl(uint32_t code);

// Human-readable IOCTL name for diagnostics.
const char* ScardIoctlName(uint32_t code);

}  // namespace rtsc::proto
