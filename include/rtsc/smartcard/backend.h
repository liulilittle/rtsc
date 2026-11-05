// Platform-neutral smart card backend seam ([MS-RDPESC] 3.1.4).
//
// The rdpdr channel handler decodes a SCARD_IOCTL_* call out of the NDR
// payload (rtsc/proto/smartcard.h) and forwards the operation to an
// ISmartCardBackend, which executes it against the local Smart Cards for
// Windows stack. The Win32 implementation (src/smartcard/backend_win32.cpp)
// loads winscard.dll at runtime; everything else gets a backend that fails
// closed with SCARD_E_NO_SERVICE.
//
// Contexts and handles are opaque to the protocol server: [MS-RDPESC] 2.2.1.1
// says the pbContext bytes are implementation-specific and MUST NOT be
// interpreted or changed by the server. This backend therefore never exposes a
// native handle on the wire: it allocates its own 8-byte little-endian ids and
// keeps the mapping in-process, so a malicious server cannot forge a native
// handle by sending chosen context bytes.
//
// Every method returns a WinSCard LONG status: 0 is SCARD_S_SUCCESS, the
// SCARD_E_* / SCARD_W_* values are carried verbatim in the ReturnCode field of
// the corresponding [MS-RDPESC] 2.2.3.x return structure.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace rtsc::smartcard {

// Smart Cards for Windows status codes (scarderr.h). Only the values this
// module returns or special-cases are listed.
enum ScardStatus : uint32_t {
    kScardSuccess = 0x00000000,
    kScardECanceled = 0x80100002,
    kScardEInvalidHandle = 0x80100003,
    kScardEInvalidParameter = 0x80100004,
    kScardEInsufficientBuffer = 0x80100008,
    kScardEUnknownReader = 0x80100009,
    kScardETimeout = 0x8010000A,
    kScardESharingViolation = 0x8010000B,
    kScardENoSmartcard = 0x8010000C,
    kScardEProtoMismatch = 0x8010000F,
    kScardENotTransacted = 0x80100016,
    kScardEReaderUnavailable = 0x80100017,
    kScardENoService = 0x8010001D,
    kScardEServiceStopped = 0x8010001E,
    kScardEUnsupportedFeature = 0x80100022,
    kScardENoReadersAvailable = 0x8010002E,
    kScardWUnsupportedCard = 0x80100065,
    kScardWUnresponsiveCard = 0x80100066,
    kScardWUnpoweredCard = 0x80100067,
    kScardWResetCard = 0x80100068,
    kScardWRemovedCard = 0x80100069,
};

// SCARD_SHARE_* ([MS-RDPESC] 2.2.6 / winscard.h).
constexpr uint32_t kScardShareExclusive = 1;
constexpr uint32_t kScardShareShared = 2;
constexpr uint32_t kScardShareDirect = 3;

// SCARD_DISPOSITION_* ([MS-RDPESC] 2.2.5 / winscard.h SCARD_LEAVE_CARD etc.).
constexpr uint32_t kScardLeaveCard = 0;
constexpr uint32_t kScardResetCard = 1;
constexpr uint32_t kScardUnpowerCard = 2;
constexpr uint32_t kScardEjectCard = 3;

// SCARD_PROTOCOL_* ([MS-RDPESC] 2.2.4 / winsmcrd.h).
constexpr uint32_t kScardProtocolUndefined = 0x00000000;
constexpr uint32_t kScardProtocolT0 = 0x00000001;
constexpr uint32_t kScardProtocolT1 = 0x00000002;
constexpr uint32_t kScardProtocolRaw = 0x00010000;

// SCARD_STATE_* reader state flags ([MS-RDPESC] 2.2.7 / winscard.h).
constexpr uint32_t kScardStateUnaware = 0x00000000;
constexpr uint32_t kScardStateIgnore = 0x00000001;
constexpr uint32_t kScardStateChanged = 0x00000002;
constexpr uint32_t kScardStateUnknown = 0x00000004;
constexpr uint32_t kScardStateUnavailable = 0x00000008;
constexpr uint32_t kScardStateEmpty = 0x00000010;
constexpr uint32_t kScardStatePresent = 0x00000020;
constexpr uint32_t kScardStateAtrMatch = 0x00000040;
constexpr uint32_t kScardStateExclusive = 0x00000080;
constexpr uint32_t kScardStateInUse = 0x00000100;
constexpr uint32_t kScardStateMute = 0x00000200;
constexpr uint32_t kScardStateUnpowered = 0x00000400;

// SCARD_PROTOCOL_RAW / T=15 etc. are not needed by the rdpdr handler: the
// SCardIO_Request protocol value is passed through from the wire.

// Protocol control information ([MS-RDPESC] 2.2.1.8 SCardIO_Request).
struct ScardPci {
    uint32_t protocol = 0;
    std::vector<uint8_t> extra;
};

// One reader in a GetStatusChange call. `event_state` and `atr` are outputs.
struct ScardReaderState {
    std::string reader;
    uint32_t current_state = 0;
    uint32_t event_state = 0;
    std::vector<uint8_t> atr;
};

// Result of one backend operation. Methods return the raw WinSCard status.
class ISmartCardBackend {
 public:
    virtual ~ISmartCardBackend() = default;

    // False when the local smart card service is unavailable. The handler
    // still answers every IOCTL (with SCARD_E_NO_SERVICE) so the server is
    // never left waiting.
    virtual bool available() const = 0;

    // Establishes a context; on success fills `context` with the opaque id
    // that subsequent calls carry back.
    virtual uint32_t EstablishContext(uint32_t scope,
                                      std::vector<uint8_t>& context) = 0;

    virtual uint32_t ReleaseContext(const std::vector<uint8_t>& context) = 0;

    // ANSI multistring (NUL-separated, double-NUL terminated) of reader
    // groups / readers. `groups` may be empty, meaning no group filter.
    virtual uint32_t ListReaderGroups(const std::vector<uint8_t>& context,
                                      std::vector<uint8_t>& groups) = 0;
    virtual uint32_t ListReaders(const std::vector<uint8_t>& context,
                                 const std::vector<uint8_t>& groups,
                                 std::vector<uint8_t>& readers) = 0;

    // Blocks up to `timeout_ms` (INFINITE when 0xFFFFFFFF) for a state
    // change; on return each entry has event_state/atr filled.
    virtual uint32_t GetStatusChange(const std::vector<uint8_t>& context,
                                     uint32_t timeout_ms,
                                     std::vector<ScardReaderState>& states) = 0;

    // Opens a card. On success fills the opaque handle and the negotiated
    // protocol.
    virtual uint32_t Connect(const std::vector<uint8_t>& context,
                             const std::string& reader, uint32_t share_mode,
                             uint32_t preferred_protocols,
                             std::vector<uint8_t>& handle,
                             uint32_t& active_protocol) = 0;

    virtual uint32_t Disconnect(const std::vector<uint8_t>& context,
                                const std::vector<uint8_t>& handle,
                                uint32_t disposition) = 0;
    virtual uint32_t BeginTransaction(const std::vector<uint8_t>& context,
                                      const std::vector<uint8_t>& handle) = 0;
    virtual uint32_t EndTransaction(const std::vector<uint8_t>& context,
                                    const std::vector<uint8_t>& handle,
                                    uint32_t disposition) = 0;

    // Reads reader names (ANSI multistring), card state, active protocol and
    // ATR. `atr` is truncated to 32 bytes (Status_Return.pbAtr).
    virtual uint32_t Status(const std::vector<uint8_t>& context,
                            const std::vector<uint8_t>& handle,
                            std::vector<uint8_t>& reader_names, uint32_t& state,
                            uint32_t& protocol, std::vector<uint8_t>& atr) = 0;

    // SCardTransmit. `recv_capacity` is the buffer size the server offered.
    // On success fills `recv` with the response APDU and `recv_pci` with the
    // protocol control information the card returned.
    virtual uint32_t Transmit(const std::vector<uint8_t>& context,
                              const std::vector<uint8_t>& handle,
                              const ScardPci& send_pci,
                              const std::vector<uint8_t>& send,
                              bool wants_recv_pci, uint32_t recv_capacity,
                              ScardPci& recv_pci,
                              std::vector<uint8_t>& recv) = 0;

    // SCardControl (vendor escape). `out_capacity` is the buffer size the
    // server offered.
    virtual uint32_t Control(const std::vector<uint8_t>& context,
                             const std::vector<uint8_t>& handle,
                             uint32_t control_code,
                             const std::vector<uint8_t>& in,
                             uint32_t out_capacity,
                             std::vector<uint8_t>& out) = 0;
};

// A backend whose every call fails with SCARD_E_NO_SERVICE. Exposed for the
// platform factory and for tests.
std::unique_ptr<ISmartCardBackend> MakeNullSmartCardBackend();

// Opens the platform backend. On Windows this dynamically loads winscard.dll
// (no link-time dependency, and a host without the smart card service still
// runs); everywhere else, and when the DLL or an entry point is missing, it
// returns a backend whose every call fails with SCARD_E_NO_SERVICE.
std::unique_ptr<ISmartCardBackend> MakeSmartCardBackend();

}  // namespace rtsc::smartcard
