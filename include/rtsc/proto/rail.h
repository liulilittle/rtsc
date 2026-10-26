// RAIL (Remote Applications Integrated Locally) protocol ([MS-RDPERP]).
//
// RAIL is the protocol behind RemoteApp / Remote Programs: the server draws the
// remote application's windows as RDP graphics, and the two peers exchange
// window-management orders over a static virtual channel so the local window
// chrome (system menu, move/size, minimize/maximize, taskbar, language bar)
// behaves like a local window. The client launches the remote application with
// the Client Execute PDU.
//
// Reference: [MS-RDPERP] 2.2.2.1 (PDU header), 2.2.2.2 (client orders),
// 2.2.1.3 (server orders). Every order is a TS_RAIL_PDU_HEADER (orderType +
// orderLength) followed by a fixed body; the length field is the total PDU size
// including the header.
//
// This module is the wire structure layer only: it encodes/decodes orders and
// reassembles the chunked virtual-channel messages. The RemoteApp state machine
// (which order to send when) is a caller concern.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/channel.h"

namespace rtsc::proto {

// [MS-RDPERP] 1.3.1: the RAIL static virtual channel is named "RAIL". mstsc
// registers it under this name in the Client Network Data block
// ([MS-RDPBCGR] 2.2.1.3.5). The name is 8 bytes, null padded on the wire.
inline constexpr const char* kRailChannelName = "rail";

// TS_RAIL_PDU_HEADER.orderType ([MS-RDPERP] 2.2.2.1).
enum class RailOrderType : uint16_t {
    kExec = 0x0001,
    kActivate = 0x0002,
    kSysparam = 0x0003,
    kSyscommand = 0x0004,
    kHandshake = 0x0005,
    kNotifyEvent = 0x0006,
    kWindowMove = 0x0008,
    kLocalMoveSize = 0x0009,
    kMinMaxInfo = 0x000A,
    kClientStatus = 0x000B,
    kSysmenu = 0x000C,
    kLangbarInfo = 0x000D,
    kGetAppIdReq = 0x000E,
    kGetAppIdResp = 0x000F,
    kTaskbarInfo = 0x0010,
    kLanguageImeInfo = 0x0011,
    kCompartmentInfo = 0x0012,
    kHandshakeEx = 0x0013,
    kZOrderSync = 0x0014,
    kCloak = 0x0015,
    kPowerDisplayRequest = 0x0016,
    kSnapArrange = 0x0017,
    kGetAppIdRespEx = 0x0018,
    kTextScaleInfo = 0x0019,
    kCaretBlinkInfo = 0x001A,
    kExecResult = 0x0080,
};

const char* to_string(RailOrderType t);

// ---- flags and command values ------------------------------------------------

// TS_RAIL_ORDER_EXEC flags ([MS-RDPERP] 2.2.2.3.1).
enum RailExecFlag : uint16_t {
    kRailExecExpandWorkingDirectory = 0x0001,
    kRailExecTranslateFiles = 0x0002,
    kRailExecFile = 0x0004,
    kRailExecExpandArguments = 0x0008,
    kRailExecAppUserModelId = 0x0010,
};

// TS_RAIL_ORDER_EXEC_RESULT.execResult ([MS-RDPERP] 2.2.1.4.1).
enum RailExecResult : uint16_t {
    kRailExecOk = 0x0000,
    kRailExecHookNotLoaded = 0x0001,
    kRailExecDecodeFailed = 0x0002,
    kRailExecNotInAllowlist = 0x0003,
    kRailExecFileNotFound = 0x0005,
    kRailExecFail = 0x0006,
    kRailExecSessionLocked = 0x0007,
};

// TS_RAIL_ORDER_SYSCOMMAND.command ([MS-RDPERP] 2.2.2.2.3).
enum RailSyscommandCode : uint16_t {
    kScSize = 0xF000,
    kScMove = 0xF010,
    kScMinimize = 0xF020,
    kScMaximize = 0xF030,
    kScClose = 0xF060,
    kScKeymenu = 0xF100,
    kScRestore = 0xF120,
    kScDefault = 0xF160,
};

// TS_RAIL_ORDER_CLIENTSTATUS.flags ([MS-RDPERP] 2.2.2.1.1).
enum RailClientStatusFlag : uint32_t {
    kRailClientAllowLocalMoveSize = 0x00000001,
    kRailClientAutoReconnect = 0x00000002,
    kRailClientZOrderSync = 0x00000004,
    kRailClientWindowResizeMarginSupported = 0x00000010,
    kRailClientHighDpiIconsSupported = 0x00000020,
    kRailClientAppBarRemotingSupported = 0x00000040,
    kRailClientPowerDisplayRequestSupported = 0x00000080,
    kRailClientGetAppIdResponseExSupported = 0x00000100,
    kRailClientBidirectionalCloakSupported = 0x00000200,
    kRailClientSuppressIconOrders = 0x00000400,
};

// TS_RAIL_ORDER_HANDSHAKE_EX.railHandshakeFlags ([MS-RDPERP] 2.2.2.1.2).
enum RailHandshakeExFlag : uint32_t {
    kRailHidef = 0x00000001,
    kRailExtendedSpiSupported = 0x00000002,
    kRailSnapArrangeSupported = 0x00000004,
    kRailTextScaleSupported = 0x00000008,
    kRailCaretBlinkSupported = 0x00000010,
    kRailExtendedSpi2Supported = 0x00000020,
};

// TS_RAIL_ORDER_TASKBARINFO.TaskbarMessage ([MS-RDPERP] 2.2.1.2.2).
enum RailTaskbarMessage : uint32_t {
    kRailTaskbarTabRegister = 0x00000001,
    kRailTaskbarTabUnregister = 0x00000002,
    kRailTaskbarTabOrder = 0x00000003,
    kRailTaskbarTabActive = 0x00000004,
    kRailTaskbarTabProperties = 0x00000005,
};

// TS_RAIL_ORDER_LANGBARINFO.languageBarStatus ([MS-RDPERP] 2.2.1.2.1).
enum RailLangbarStatus : uint32_t {
    kRailLangbarShowNormal = 0x00000001,
    kRailLangbarDock = 0x00000002,
    kRailLangbarMinimized = 0x00000004,
    kRailLangbarHidden = 0x00000008,
    kRailLangbarNoTransparency = 0x00000010,
    kRailLangbarLowTransparency = 0x00000020,
    kRailLangbarHighTransparency = 0x00000040,
    kRailLangbarLabels = 0x00000080,
    kRailLangbarNoLabels = 0x00000100,
};

// TS_RAIL_ORDER_LOCALMOVESIZE.moveSizeType ([MS-RDPERP] 2.2.1.3.2).
enum RailMoveSizeType : uint16_t {
    kRailWmszLeft = 0x0001,
    kRailWmszRight = 0x0002,
    kRailWmszTop = 0x0003,
    kRailWmszTopLeft = 0x0004,
    kRailWmszTopRight = 0x0005,
    kRailWmszBottom = 0x0006,
    kRailWmszBottomLeft = 0x0007,
    kRailWmszBottomRight = 0x0008,
    kRailWmszMove = 0x0009,
    kRailWmszKeyMove = 0x000A,
    kRailWmszKeySize = 0x000B,
};

// TS_RAIL_ORDER_SYSPARAM.param ([MS-RDPERP] 2.2.2.4.1). The values are the
// constants the RAIL protocol defines; note they are NOT the Win32 SDK SPI_*
// values for the extended parameters (e.g. SPI_SETCARETWIDTH is 0x00002007 here,
// not the SDK's 0x00002006).
enum RailSysparam : uint32_t {
    kSpiSetDragFullWindows = 0x00000025,
    kSpiSetKeyboardCues = 0x0000100B,
    kSpiSetKeyboardPref = 0x00000045,
    kSpiSetMouseButtonSwap = 0x00000021,
    kSpiSetWorkArea = 0x0000002F,
    kSpiDisplayChange = 0x0000F001,
    kSpiTaskbarPos = 0x0000F000,
    kSpiSetHighContrast = 0x00000043,
    kSpiSetCaretWidth = 0x00002007,
    kSpiSetStickyKeys = 0x0000003B,
    kSpiSetToggleKeys = 0x00000035,
    kSpiSetFilterKeys = 0x00000033,
    // Server-to-client system parameters ([MS-RDPERP] 2.2.1.5).
    kSpiSetScreenSaveActive = 0x00000011,
    kSpiSetScreenSaveSecure = 0x00000077,
};

// ---- PDU header and generic PDU ----------------------------------------------

// TS_RAIL_PDU_HEADER (4 bytes): orderType (2) + orderLength (2). orderLength is
// the total PDU length including this header.
struct RailPduHeader {
    static constexpr size_t kSize = 4;

    uint16_t order_type = 0;
    uint16_t order_length = 0;

    static Status parse(const uint8_t* data, size_t size, RailPduHeader& out);
    void write(ByteWriter& w) const;
};

// A parsed RAIL PDU: the header plus the body bytes (header excluded).
struct RailPdu {
    RailPduHeader header;
    std::vector<uint8_t> body;

    // Parses one PDU from the front of `data`. `consumed` receives the number of
    // bytes the PDU occupied (header + body). Returns NeedMoreData when the
    // declared orderLength exceeds the available bytes, and InvalidField when
    // orderLength is smaller than the header itself.
    static Status parse(const uint8_t* data, size_t size, RailPdu& out,
                        size_t& consumed);
};

// Writes the 4-byte header for a PDU whose body is `body_size` bytes.
void WriteRailPduHeader(ByteWriter& w, uint16_t order_type, size_t body_size);

// Reads and validates the 4-byte header against `expected_type`. `body_size`
// receives the body length (orderLength - header size).
Status ReadRailPduHeader(ByteReader& r, uint16_t expected_type,
                         size_t& body_size);

// Builds a complete RAIL PDU (header + body) for `order_type`.
std::vector<uint8_t> BuildRailPdu(uint16_t order_type,
                                  const std::vector<uint8_t>& body);

// ---- UTF-16 helpers ----------------------------------------------------------

// RAIL strings are UTF-16LE on the wire ([MS-RDPERP] 2.2.2.3.1: "a non
// null-terminated string of Unicode characters"). These helpers convert between
// the in-memory UTF-16 string and the little-endian byte form.
std::vector<uint8_t> RailUtf16ToLeBytes(const std::u16string& s);
std::u16string RailLeBytesToUtf16(const uint8_t* data, size_t size);

// ---- orders ------------------------------------------------------------------

// TS_RAIL_ORDER_HANDSHAKE (0x0005): buildNumber (4).
struct RailHandshake {
    static constexpr uint16_t kOrderType = 0x0005;
    uint32_t build_number = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailHandshake& out);
};

// TS_RAIL_ORDER_HANDSHAKE_EX (0x0013): buildNumber (4) + railHandshakeFlags (4).
struct RailHandshakeEx {
    static constexpr uint16_t kOrderType = 0x0013;
    uint32_t build_number = 0;
    uint32_t flags = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailHandshakeEx& out);
};

// TS_RAIL_ORDER_CLIENTSTATUS (0x000B): flags (4).
struct RailClientStatus {
    static constexpr uint16_t kOrderType = 0x000B;
    uint32_t flags = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailClientStatus& out);
};

// TS_RAIL_ORDER_SYSCOMMAND (0x0004): windowId (4) + command (2). Sent by the
// client for minimize / maximize / restore / close and the system-menu shortcut.
struct RailSyscommand {
    static constexpr uint16_t kOrderType = 0x0004;
    uint32_t window_id = 0;
    uint16_t command = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailSyscommand& out);
};

// TS_RAIL_ORDER_SYSMENU (0x000C): windowId (4) + left (2) + top (2).
struct RailSysmenu {
    static constexpr uint16_t kOrderType = 0x000C;
    uint32_t window_id = 0;
    int16_t left = 0;
    int16_t top = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailSysmenu& out);
};

// TS_RAIL_ORDER_WINDOWMOVE (0x0008): windowId (4) + left/top/right/bottom (2 each).
// The window's new position and size on the server.
struct RailWindowMove {
    static constexpr uint16_t kOrderType = 0x0008;
    uint32_t window_id = 0;
    int16_t left = 0;
    int16_t top = 0;
    int16_t right = 0;
    int16_t bottom = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailWindowMove& out);
};

// TS_RAIL_ORDER_MINMAXINFO (0x000A): windowId + 8 signed 16-bit metrics.
struct RailMinMaxInfo {
    static constexpr uint16_t kOrderType = 0x000A;
    uint32_t window_id = 0;
    int16_t max_width = 0;
    int16_t max_height = 0;
    int16_t max_pos_x = 0;
    int16_t max_pos_y = 0;
    int16_t min_track_width = 0;
    int16_t min_track_height = 0;
    int16_t max_track_width = 0;
    int16_t max_track_height = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailMinMaxInfo& out);
};

// TS_RAIL_ORDER_LOCALMOVESIZE (0x0009): windowId (4) + isMoveSizeStart (1) +
// moveSizeType (2) + posX (2) + posY (2).
struct RailLocalMoveSize {
    static constexpr uint16_t kOrderType = 0x0009;
    uint32_t window_id = 0;
    bool is_move_size_start = false;
    uint16_t move_size_type = 0;
    int16_t pos_x = 0;
    int16_t pos_y = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailLocalMoveSize& out);
};

// TS_RAIL_ORDER_TASKBARINFO (0x0010): TaskbarMessage (4) + WindowIdTab (4) +
// Body (4).
struct RailTaskbarInfo {
    static constexpr uint16_t kOrderType = 0x0010;
    uint32_t taskbar_message = 0;
    uint32_t window_id_tab = 0;
    uint32_t body = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailTaskbarInfo& out);
};

// TS_RAIL_ORDER_LANGBARINFO (0x000D): languageBarStatus (4).
struct RailLangbarInfo {
    static constexpr uint16_t kOrderType = 0x000D;
    uint32_t language_bar_status = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailLangbarInfo& out);
};

// TS_RAIL_ORDER_GET_APPID_REQ (0x000E): windowId (4).
struct RailGetAppIdReq {
    static constexpr uint16_t kOrderType = 0x000E;
    uint32_t window_id = 0;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailGetAppIdReq& out);
};

// TS_RAIL_ORDER_SYSPARAM (0x0003): systemParam (4) + a body that depends on the
// parameter. The boolean and rectangle parameters are the ones a RemoteApp
// client normally sends; the extended SPI parameters are carried as a 32-bit
// value; the high-contrast parameter carries a TS_HIGHCONTRAST structure
// (Flags + ColorSchemeLength + UNICODE_STRING ColorScheme).
struct RailSysparamOrder {
    static constexpr uint16_t kOrderType = 0x0003;

    uint32_t param = 0;
    bool bool_value = false;
    uint32_t uint_value = 0;
    int16_t rect_left = 0;
    int16_t rect_top = 0;
    int16_t rect_right = 0;
    int16_t rect_bottom = 0;
    // TS_HIGHCONTRAST (only for kSpiSetHighContrast).
    uint32_t high_contrast_flags = 0;
    std::u16string color_scheme;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailSysparamOrder& out);
};

// TS_RAIL_ORDER_EXEC (0x0001): the Client Execute PDU. Launches the remote
// application (LocalApp / RemoteApp) or, for the start-menu case, the shell
// program. Flags (2) + three length-prefixed UTF-16 strings.
struct RailClientExecute {
    static constexpr uint16_t kOrderType = 0x0001;
    static constexpr size_t kMaxExeOrFile = 520;
    static constexpr size_t kMaxWorkingDir = 520;
    static constexpr size_t kMaxArguments = 16000;

    uint16_t flags = 0;
    std::u16string exe_or_file;
    std::u16string working_dir;
    std::u16string arguments;

    // Returns an empty vector (and sets `why`) when a string exceeds its limit.
    std::vector<uint8_t> build(std::string& why) const;
    static Status parse(const uint8_t* data, size_t size, RailClientExecute& out);
};

// TS_RAIL_ORDER_EXEC_RESULT (0x0080): the Server Execute Result PDU.
// flags (2) + execResult (2) + rawResult (4) + a length-prefixed UTF-16 string.
struct RailExecuteResult {
    static constexpr uint16_t kOrderType = 0x0080;

    uint16_t flags = 0;
    uint16_t exec_result = 0;
    uint32_t raw_result = 0;
    std::u16string exe_or_file;

    std::vector<uint8_t> build() const;
    static Status parse(const uint8_t* data, size_t size, RailExecuteResult& out);
};

// ---- virtual channel ---------------------------------------------------------

// Reassembles the chunked RAIL virtual-channel messages and dispatches each
// complete PDU. The connection driver hands the raw MCS Send Data user_data
// (CHANNEL_PDU_HEADER + chunks) to OnChannelData, exactly like the other static
// virtual channel handlers.
class RailChannel {
 public:
    using PduHandler = std::function<void(const RailPdu&)>;

    void SetHandler(PduHandler handler) { handler_ = std::move(handler); }

    // Feeds one inbound virtual-channel chunk (the MCS Send Data user_data). A
    // message may be split across calls.
    void OnChannelData(const uint8_t* data, size_t size);

    // ---- diagnostics --------------------------------------------------------
    unsigned pdu_count() const { return pdu_count_; }
    unsigned handshake_count() const { return handshake_count_; }
    unsigned handshake_ex_count() const { return handshake_ex_count_; }
    unsigned syscommand_count() const { return syscommand_count_; }
    unsigned sysmenu_count() const { return sysmenu_count_; }
    unsigned window_move_count() const { return window_move_count_; }
    unsigned taskbar_count() const { return taskbar_count_; }
    unsigned langbar_count() const { return langbar_count_; }
    unsigned exec_count() const { return exec_count_; }
    unsigned exec_result_count() const { return exec_result_count_; }
    unsigned incomplete_message_count() const { return incomplete_message_count_; }

 private:
    void OnMessage(const std::vector<uint8_t>& message);

    ChannelReassembler reassembler_;
    PduHandler handler_;

    unsigned pdu_count_ = 0;
    unsigned handshake_count_ = 0;
    unsigned handshake_ex_count_ = 0;
    unsigned syscommand_count_ = 0;
    unsigned sysmenu_count_ = 0;
    unsigned window_move_count_ = 0;
    unsigned taskbar_count_ = 0;
    unsigned langbar_count_ = 0;
    unsigned exec_count_ = 0;
    unsigned exec_result_count_ = 0;
    unsigned incomplete_message_count_ = 0;
};

}  // namespace rtsc::proto
