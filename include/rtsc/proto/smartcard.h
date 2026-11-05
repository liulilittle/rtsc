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
    kGetStatusChangeA = 0x000900A0,   // 3.1.4.23
    kGetStatusChangeW = 0x000900A4,   // 3.1.4.24
    kConnectA = 0x000900AC,           // 3.1.4.28
    kConnectW = 0x000900B0,           // 3.1.4.29
    kDisconnect = 0x000900B8,         // 3.1.4.30
    kBeginTransaction = 0x000900BC,   // 3.1.4.31
    kEndTransaction = 0x000900C0,     // 3.1.4.32
    kStatusA = 0x000900C8,            // 3.1.4.33
    kStatusW = 0x000900CC,            // 3.1.4.34
    kTransmit = 0x000900D0,           // 3.1.4.35
    kControl = 0x000900D4,            // 3.1.4.37
};

// Range limits from the IDL in [MS-RDPESC] 6 Appendix A.
constexpr size_t kScardMaxContextBytes = 16;      // cbContext/cbHandle 0..16
constexpr size_t kScardMaxExtraBytes = 1024;      // SCardIO_Request cbExtraBytes
constexpr size_t kScardMaxTransmitBytes = 66560;  // cbSendLength/cbRecvLength
constexpr size_t kScardMaxMultiStringBytes = 65536;  // cBytes 0..65536
constexpr size_t kScardMaxReaders = 11;           // GetStatusChange cReaders
constexpr size_t kScardMaxAtr = 36;               // ReaderState_Common rgbAtr
constexpr size_t kScardMaxStatusAtr = 32;         // Status_Return pbAtr
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

// ReaderState_Return ([MS-RDPESC] 2.2.1.11).
struct ScardReaderStateReturn {
    uint32_t current_state = 0;
    uint32_t event_state = 0;
    std::vector<uint8_t> atr;  // at most kScardMaxAtr bytes
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

    // ConnectA_Call 2.2.2.13 (Connect_Common 2.2.1.3).
    std::string reader;
    uint32_t share_mode = 0;
    uint32_t preferred_protocols = 0;

    // HCardAndDisposition_Call 2.2.2.16 (Disconnect/Begin/EndTransaction).
    ScardHandle handle;
    uint32_t disposition = 0;

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
