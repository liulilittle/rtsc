// RD Gateway ([MS-TSGU]) and RDP-UDP / multitransport ([MS-RDPEUDP],
// [MS-RDPEMT]) wire structures.
//
// The RD Gateway tunnels RDP through HTTP: the client opens a tunnel to the
// gateway and then runs the ordinary RDP connection sequence (X.224 -> TLS ->
// CredSSP -> MCS -> ...) through it. The gateway may also hand the client a
// UDP side channel ([MS-RDPEMT]) which the RDP-UDP protocol carries; that
// channel comes in a reliable (RDP-UDP-R / UDPFECR) and an unreliable
// (RDP-UDP-L / UDPFECL) mode.
//
// This module is the wire structure layer only. It covers:
//   * RDP_CONNECTION_TRANSPORT (the transport type the gateway carries),
//   * the HTTP/1.1 CONNECT tunnel request and response,
//   * the RDGSP HTTP channel requests (RDG_IN_DATA / RDG_OUT_DATA),
//   * the RD Gateway authentication exchange (TLSAuth / SOAP),
//   * the RDP-UDP datagram structures (SYN, data, ACK),
//   * the multitransport request/response PDU bodies.
//
// The socket-level tunnel (HTTP CONNECT over a byte transport) and the UDP
// transport live in rtsc/net/gateway_transport.h.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// ---------------------------------------------------------------------------
// RDP_CONNECTION_TRANSPORT
// ---------------------------------------------------------------------------

// The transport the gateway connection uses. The numeric values are the
// RDP_CONNECTION_TRANSPORT.TransportType constants.
enum class TransportType : uint32_t {
    kUdp = 0x00000000,
    kTcp = 0x00000001,
};

const char* to_string(TransportType t);

// RDP_CONNECTION_TRANSPORT ([MS-TSGU]): version (4) + transportType (4).
struct RdpConnectionTransport {
    static constexpr size_t kSize = 8;
    static constexpr uint32_t kVersion = 1;

    uint32_t version = kVersion;
    TransportType type = TransportType::kTcp;

    static std::vector<uint8_t> build(const RdpConnectionTransport& t);
    static Status parse(const uint8_t* data, size_t size,
                        RdpConnectionTransport& out);
};

// ---------------------------------------------------------------------------
// HTTP/1.1
// ---------------------------------------------------------------------------

// The request line of an HTTP/1.1 message.
struct HttpRequestLine {
    std::string method;
    std::string target;
    std::string version;

    // Parses the leading request line. `consumed` is the line length including
    // its CRLF. Returns NeedMoreData when the CRLF is not present yet.
    static Status parse(const uint8_t* data, size_t size, HttpRequestLine& out,
                        size_t& consumed);
};

struct HttpHeader {
    std::string name;
    std::string value;
};

// Hard ceilings for the HTTP message parser. They are enforced before anything
// is allocated, so a peer that announces a huge length cannot make the client
// reserve in proportion to it.
//
// The head (status line plus every header line) is limited to 64 KiB, the
// Content-Length entity to 128 KiB, and the header count to 512 (each line costs
// a std::string plus a vector slot, so a flood of one-byte headers has to be
// rejected on the count alone).
inline constexpr size_t kMaxHttpHeaderBytes = 64 * 1024;
inline constexpr size_t kMaxHttpEntityBytes = 128 * 1024;
inline constexpr size_t kMaxHttpHeaderCount = 512;

// Explicit ceilings for one parse. The defaults are the memory-safety bounds;
// a caller that legitimately needs a larger message can raise them per parse
// instead of having the limit hard-coded into the wire layer.
struct HttpLimits {
    size_t max_head_bytes = kMaxHttpHeaderBytes;
    size_t max_entity_bytes = kMaxHttpEntityBytes;
    size_t max_header_count = kMaxHttpHeaderCount;
};

// An HTTP/1.1 response: status line + headers (the body is out of scope; the
// tunnel switches to the RDP byte stream after the blank line).
struct HttpMessage {
    int status_code = 0;
    std::string reason;
    std::vector<HttpHeader> headers;

    // Parses the status line and the header block, up to and including the
    // terminating blank line. `consumed` is the number of header bytes.
    static Status parse(const uint8_t* data, size_t size, HttpMessage& out,
                        size_t& consumed);
    // Same, with caller-supplied ceilings. A limit violation is a hard failure
    // (InvalidLength), never NeedMoreData: waiting for more bytes is exactly the
    // behaviour that lets a peer grow the buffer without bound.
    static Status parse(const uint8_t* data, size_t size, HttpMessage& out,
                        size_t& consumed, const HttpLimits& limits);

    const HttpHeader* find(const std::string& name) const;
    std::string header_or(const std::string& name,
                          const std::string& fallback = "") const;
};

struct ConnectRequestOptions {
    std::string target;        // "host:port" the tunnel should reach
    std::string gateway_host;  // "host:port" of the gateway itself
    std::string user_agent;
    std::string cookie;         // optional
    std::string authorization;  // optional Authorization header value
    TransportType transport = TransportType::kTcp;
};

// Builds an HTTP/1.1 CONNECT request for the RD Gateway tunnel.
std::vector<uint8_t> BuildHttpConnectRequest(const ConnectRequestOptions& options);

// RDGSP HTTP transport custom methods and headers ([MS-TSGU] 2.2.3).
// The header set and its directionality follow the factory evidence
// (docs/spec/gateway-evidence.md section 2: the strings procured from
// mstscax.dll).
inline constexpr const char* kRdgInData = "RDG_IN_DATA";
inline constexpr const char* kRdgOutData = "RDG_OUT_DATA";
inline constexpr const char* kRdgConnectionIdHeader = "RDG-Connection-Id";
inline constexpr const char* kRdgCorrelationIdHeader = "RDG-Correlation-Id";
inline constexpr const char* kRdgUserIdHeader = "RDG-User-Id";
inline constexpr const char* kRdgDiagnosticsInfoHeader = "RDG-Diagnostics-Info";
inline constexpr const char* kRdgClientAppBuildHeader = "RDG-Client-AppBuild";
inline constexpr const char* kRdgClientGenerationHeader = "RDG-Client-Generation";
inline constexpr const char* kRdgAuthSchemeHeader = "RDG-Auth-Scheme";
inline constexpr const char* kRdgLoadBalancerCookieHeader = "Load Balancer Cookie";
inline constexpr const char* kRdgInchannelRetryModeHeader = "RDG-INCHANNEL-RETRYMODE";

// Direction of an RDGSP channel request. The factory's error strings separate
// headers sent on both channels ("AddRequestHeader ... for IN or OUT channel
// failed") from OUT-only ones ("... for OUT channel failed"), so the caller
// must tell the builder which channel it is targeting.
enum class RdgChannelDirection { kIn, kOut };

struct RdgChannelRequestOptions {
    std::string method = kRdgInData;  // D10: default to the IN channel method
    RdgChannelDirection direction = RdgChannelDirection::kIn;
    std::string gateway_host;  // D1: Host = the gateway authority (host:port)
    std::string connection_id;  // client-generated GUID (both channels)
    std::string user_agent;
    // Header direction follows docs/spec/gateway-header-direction-ruling.md
    // (mstscax FUN_1801c3818). Both channels carry correlation-id; the
    // user-id is IN-only (base64 on the wire); client generation / app build /
    // Load Balancer Cookie are OUT-only.
    std::string correlation_id;
    std::string user_id;           // IN-only, base64-encoded when emitted
    std::string client_generation; // OUT-only
    std::string load_balancer_cookie;  // OUT-only
    // Optional headers (value formats not in the factory evidence, UNVERIFIED):
    // app build is OUT-only; auth scheme is sent on both channels.
    std::string app_build;         // RDG-Client-AppBuild (OUT-only)
    std::string auth_scheme;       // RDG-Auth-Scheme (factory values e.g.
                                   // SMARTCARD / CONNID; none defaulted here)
    std::string diagnostics_info;  // RDG-Diagnostics-Info
    // RFC 6455 Sec-WebSocket-Key for the OUT upgrade ask. Empty (the default)
    // makes the builder generate a fresh 16-byte base64 nonce per request; a
    // non-empty value is emitted verbatim. The actual key the request carried
    // is reported through BuildRdgChannelRequest's out_websocket_key, so the
    // caller can compute the expected Sec-WebSocket-Accept without guessing.
    std::string websocket_key;
    // Optional Authorization header (NTLM / Basic client authentication). Used
    // by RdgspTransport's 401 handling. Also validated against CRLF / NUL in
    // the builder's injection check chain (a hostile value here would smuggle
    // a header).
    std::string authorization;
    // When set, the OUT channel request carries an RFC 6455 upgrade ask
    // (Connection: Upgrade / Upgrade: websocket / Sec-WebSocket-Key /
    // Sec-WebSocket-Version). The exact factory request headers are not in the
    // evidence (mstscax uses WinHTTP's UPGRADE_TO_WEB_SOCKET, which generates
    // them implicitly): the layout is standard [RFC 6455] client framing,
    // UNVERIFIED against the shipped binary.
    bool request_websocket_upgrade = false;
    // IN-channel retry mode (evidence section 3: `0x1806d0f60` carries
    // `RDG-INCHANNEL-RETRYMODE` and `IN_CHANNEL_RETRY_COUNT_%d`). Emitted only
    // for kIn when retry_count is positive, as
    //   RDG-INCHANNEL-RETRYMODE: IN_CHANNEL_RETRY_COUNT_<retry_count>
    int retry_count = 0;
};

// Builds an RDGSP HTTP channel request (the IN/OUT channel creation request).
// When request_websocket_upgrade is set, the emitted Sec-WebSocket-Key is
// reported through *out_websocket_key (never null-checked when provided): the
// caller needs it to validate the 101's Sec-WebSocket-Accept. An empty
// websocket_key in the options means "generate one".
std::vector<uint8_t> BuildRdgChannelRequest(const RdgChannelRequestOptions& options,
                                            std::string* out_websocket_key = nullptr);

// RFC 6455 4.1: the server's Sec-WebSocket-Accept for a given client key is
// base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")). Pure function:
// the 101-validation code path and the tests share it.
std::string ComputeWebSocketAccept(const std::string& key);

// ---------------------------------------------------------------------------
// HTTP chunked transfer coding (RFC 9112 section 7.1)
// ---------------------------------------------------------------------------

// Ceilings for the chunked body decoder: a single chunk is bounded by the
// project channel-message ceiling and the whole decoded body by 64 MiB. Both
// are checked at the chunk-size line, before any data is buffered, so a peer
// cannot make the decoder allocate in proportion to a size announcement. The
// defaults are the memory-safety bounds; a caller may lower them per instance.
inline constexpr size_t kMaxChunkedChunkBytes = 16u * 1024u * 1024u;
inline constexpr size_t kMaxChunkTotalBytes = 64u * 1024u * 1024u;

// Encodes `data` as one HTTP chunked entity: "<hex-size>\r\n<data>\r\n" with a
// lowercase hex size, terminated by "0\r\n\r\n" (empty input encodes as just
// "0\r\n\r\n").
std::vector<uint8_t> ChunkedEncode(const uint8_t* data, size_t size);
inline std::vector<uint8_t> ChunkedEncode(const std::vector<uint8_t>& data) {
    return ChunkedEncode(data.data(), data.size());
}

// Encodes `data` as ONE chunk of a request body: "<hex-size>\r\n<data>\r\n",
// WITHOUT the terminating 0-chunk (ChunkedEncode appends it). The RDGSP IN
// channel writes a long-lived stream of such chunks over a whole session; only
// the server (or the last chunk) terminates the body, so per-write framing must
// not close it. Empty input encodes to nothing.
std::vector<uint8_t> ChunkedEncodeChunk(const uint8_t* data, size_t size);
inline std::vector<uint8_t> ChunkedEncodeChunk(
    const std::vector<uint8_t>& data) {
    return ChunkedEncodeChunk(data.data(), data.size());
}

// Why the chunked decoder failed. kNone is not a failure; every other value is
// a hard error the decoder latches and reports from then on.
enum class ChunkedError {
    kNone,
    kTruncated,       // the stream ended before the terminating 0-chunk
    kInvalidHex,      // the chunk-size line has no parseable hex length
    kNegativeLength,  // the chunk size wraps past 2^63 (an "unsigned -1")
    kChunkTooLarge,   // a single chunk exceeds the per-chunk ceiling
    kTotalTooLarge,   // the decoded total exceeds the overall ceiling
    kInvalidField,    // structural violation (bad terminator, empty size line)
};

const char* to_string(ChunkedError e);

// Incremental chunked-body decoder (RFC 9112 section 7.1). Feed the stream
// fragments as they arrive; each call returns the data fully decoded by that
// call. Sizes are case-insensitive hex, chunk extensions (";ext=val") and
// trailing header fields after the terminating 0-chunk are skipped.
class ChunkedDecoder {
 public:
    explicit ChunkedDecoder(size_t max_chunk_bytes = kMaxChunkedChunkBytes,
                            size_t max_total_bytes = kMaxChunkTotalBytes);

    ChunkedDecoder(const ChunkedDecoder&) = delete;
    ChunkedDecoder& operator=(const ChunkedDecoder&) = delete;

    // Decodes as much of `data` as possible and returns the freshly decoded
    // data. On a latched failure or after the terminal chunk returns an empty
    // vector; check finished()/error().
    std::vector<uint8_t> Feed(const uint8_t* data, size_t size);
    std::vector<uint8_t> Feed(const std::vector<uint8_t>& bytes);

    // Signals that the underlying byte stream has ended. If the body had not
    // reached its terminating 0-chunk the decoder latches kTruncated.
    void EndOfStream();

    bool finished() const { return finished_; }
    bool failed() const { return error_ != ChunkedError::kNone; }
    ChunkedError error() const { return error_; }
    size_t decoded_total() const { return decoded_total_; }

 private:
    enum class State { kSize, kData, kChunkEnd, kTrailers, kDone };

    // Parses a chunk-size line into `out`; extension text after the hex digits
    // is skipped. Returns kInvalidHex / kNegativeLength / kInvalidField.
    ChunkedError ParseSizeLine(const std::string& line, size_t& out) const;

    size_t max_chunk_bytes_;
    size_t max_total_bytes_;
    size_t decoded_total_ = 0;
    size_t pending_ = 0;                 // bytes remaining in the current chunk
    std::vector<uint8_t> buffer_;        // unconsumed input across feeds
    State state_ = State::kSize;
    bool finished_ = false;
    ChunkedError error_ = ChunkedError::kNone;
};

// Plain fallback probe: true when the HTTP response's Transfer-Encoding says
// the entity body is chunked (case-insensitive token scan; the value may be a
// comma-separated list). A missing header means a plain (non-chunked) body.
bool IsChunkedBody(const HttpMessage& message);

// Maps a failed RDGSP channel HTTP status code to an HRESULT, following the
// factory's status mapping (evidence: mstscax `FUN_1801bdd8c`).
//   401 -> E_ACCESSDENIED (0x80070005)
//   password-expired -> ERROR_PASSWORD_EXPIRED (0x80070532)
//   407 -> ERROR_PROXY_ACCESS_DENIED (0x800706C1)
//   502 / 504 -> ERROR_SERVER_UNAVAILABLE (0x800706BA)
//   anything else -> 0x80190000 | status
uint32_t MapGatewayStatusToHresult(int status_code, bool password_expired);

// ---------------------------------------------------------------------------
// RFC 6455 WebSocket framing (client role, RDGSP OUT upgraded data plane)
// ---------------------------------------------------------------------------

// WebSocket opcodes ([RFC 6455] section 5.2). The RDGSP upgrade only needs the
// whitelisted subset; `kContinuation` supports fragmented messages.
enum class WebSocketOpcode : uint8_t {
    kContinuation = 0x0,
    kText = 0x1,
    kBinary = 0x2,
    kClose = 0x8,
    kPing = 0x9,
    kPong = 0xA,
};

// A control frame is one whose opcode high bit is set (opcode >= 0x8,
// [RFC 6455] section 5.5). Control frames MUST be FIN and MUST carry at most
// 125 payload bytes.
bool IsWebSocketControlOpcode(WebSocketOpcode opcode);

// One frame's payload is capped at the project channel-message ceiling
// (16 MiB, the same value kMaxChunkedChunkBytes uses). A 64-bit extended
// length above this is rejected while the header is parsed, before anything
// is sized from it.
inline constexpr uint64_t kMaxWebSocketPayloadBytes = 16u * 1024u * 1024u;

// Encodes one complete client frame: FIN set, opcode as given, payload masked
// with `mask_key` (client frames are always masked, [RFC 6455] section 5.3).
// The extended-length form is minimal (126 for 126..65535, 127 beyond).
std::vector<uint8_t> WebSocketEncodeClientFrame(WebSocketOpcode opcode,
                                                const uint8_t* payload,
                                                size_t size, uint32_t mask_key);

// Why the frame decoder failed. kNone / kNeedMoreData are not failures; every
// other value is a hard error the decoder latches.
enum class WebSocketError {
    kNone,
    kNeedMoreData,      // a complete frame is not buffered yet
    kTruncated,         // the byte stream ended mid-frame
    kInvalidOpcode,     // opcode outside the whitelist {0,1,2,8,9,10}
    kReservedBits,      // RSV1-3 set although no extension was negotiated
    kControlFrameNotFinal,  // a control frame with FIN == 0
    kControlFrameTooLarge,  // a control frame with more than 125 payload bytes
    kPayloadTooLarge,       // 64-bit length above kMaxWebSocketPayloadBytes
    kNonMinimalLength,      // 126/127 form used for a length that fits earlier
};

const char* to_string(WebSocketError e);

// A decoded frame: the FIN bit, the opcode, and the unmasked payload.
struct WebSocketFrame {
    bool fin = true;
    WebSocketOpcode opcode = WebSocketOpcode::kBinary;
    std::vector<uint8_t> payload;
};

// Incremental client-role frame decoder. Feed network fragments; each call
// returns every frame fully decoded by that call. The MASK bit is honored (a
// masked frame is unmasked with its key), so both normal server frames
// (unmasked) and, symmetrically, masked test frames decode identically.
class WebSocketFrameDecoder {
 public:
    WebSocketFrameDecoder() = default;
    WebSocketFrameDecoder(const WebSocketFrameDecoder&) = delete;
    WebSocketFrameDecoder& operator=(const WebSocketFrameDecoder&) = delete;

    // Decodes as much of `data` as possible and returns the complete frames.
    // On a latched failure returns an empty vector; check failed()/error().
    std::vector<WebSocketFrame> Feed(const uint8_t* data, size_t size);
    std::vector<WebSocketFrame> Feed(const std::vector<uint8_t>& bytes);

    // Signals the underlying byte stream ended. A partial frame latches
    // kTruncated.
    void EndOfStream();

    bool failed() const { return error_ != WebSocketError::kNone; }
    WebSocketError error() const { return error_; }
    size_t frames_parsed() const { return frames_parsed_; }

 private:
    std::vector<uint8_t> buffer_;
    WebSocketError error_ = WebSocketError::kNone;
    size_t frames_parsed_ = 0;
};

// ---------------------------------------------------------------------------
// RD Gateway authentication (TLSAuth / SOAP)
// ---------------------------------------------------------------------------

// A key=value authentication parameter of a challenge.
struct RdgAuthParam {
    std::string key;
    std::string value;  // quotes stripped
};

// RFC 4648 base64 encoding. Used internally for RDG-User-Id; exposed so the
// RDGSP transport can build the NTLM / Basic Authorization tokens from the same
// transform.
std::string EncodeBase64(const std::string& bytes);

// A parsed WWW-Authenticate challenge: `scheme` plus its auth params (RFC
// 7235). `realm` is the convenience mirror of the realm= param, preserved from
// the original single-challenge API. An RFC 7235 challenge is either a
// token68 (`NTLM <base64>`) or a param list; `token` carries the token68 body
// when the challenge has no params at all.
struct RdgAuthChallenge {
    std::string scheme;
    std::string realm;
    std::string token;
    std::vector<RdgAuthParam> params;

    // Parses ONE challenge: `scheme`, `scheme k=v`, or `scheme k=v k2=v2`.
    // Backward compatible with the original `scheme realm="..."` form.
    static Status parse_www_authenticate(const std::string& value,
                                         RdgAuthChallenge& out);

    // Parses one header value that may contain several comma-separated
    // challenges (a comma inside a quoted value does not split) and appends
    // each to `out`. Multiple WWW-Authenticate header values are handled by
    // calling this once per header value (see ParseWwwAuthenticateHeaders).
    static Status parse_challenges(const std::string& header_value,
                                   std::vector<RdgAuthChallenge>& out);
};

// Parses every WWW-Authenticate header of `message` (a response may carry
// several header lines). Returns InvalidField when the message carries none.
Status ParseWwwAuthenticateHeaders(const HttpMessage& message,
                                   std::vector<RdgAuthChallenge>& out);

// An Authorization header value: `scheme token`.
struct RdgAuthRequest {
    std::string scheme;
    std::string token;

    std::string header_value() const;
};

// A SOAP 1.2 envelope carrying the RD Gateway security token (TLSAuth). The
// RDG SOAP body carries the token in the WS-Security BinarySecurityToken
// element; the envelope is the HTTP entity body of the SOAP request.
struct RdgSoapOptions {
    std::string action;      // SOAPAction
    std::string message_id;  // wsa:MessageID
    std::string token;       // base64 token
    std::string service;     // service namespace URI
};

std::vector<uint8_t> BuildRdgSoapEnvelope(const RdgSoapOptions& options);

// ---------------------------------------------------------------------------
// RDP-UDP transport ([MS-RDPEUDP])
// ---------------------------------------------------------------------------

enum class UdpMode : uint8_t {
    kReliable = 0,   // RDP-UDP-R / UDPFECR
    kUnreliable = 1, // RDP-UDP-L / UDPFECL
};

const char* to_string(UdpMode mode);

// RDPUDP_FEC_HEADER.uFlags ([MS-RDPEUDP] 2.2.2.1).
enum UdpFecFlag : uint16_t {
    kUdpFlagSyn = 0x0001,
    kUdpFlagFin = 0x0002,
    kUdpFlagAck = 0x0004,
    kUdpFlagData = 0x0008,
    kUdpFlagFec = 0x0010,
    kUdpFlagCn = 0x0020,
    kUdpFlagCwr = 0x0040,
    kUdpFlagAckOfAcks = 0x0100,
    kUdpFlagSynlossy = 0x0200,
    kUdpFlagAckDelayed = 0x0400,
    kUdpFlagCorrelationId = 0x0800,
    kUdpFlagSynex = 0x1000,
};

// RDPUDP_FEC_HEADER (8 bytes): snSourceAck (4) + uReceiveWindowSize (2) +
// uFlags (2).
struct UdpFecHeader {
    static constexpr size_t kSize = 8;

    uint32_t source_ack = 0;
    uint16_t receive_window_size = 0;
    uint16_t flags = 0;

    static std::vector<uint8_t> build(const UdpFecHeader& h);
    static Status parse(const uint8_t* data, size_t size, UdpFecHeader& out);
    bool has_flag(uint16_t flag) const { return (flags & flag) != 0; }
};

// RDPUDP_SOURCE_PAYLOAD_HEADER (8 bytes): snCoded (4) + snSourceStart (4).
struct UdpSourcePayloadHeader {
    static constexpr size_t kSize = 8;

    uint32_t coded = 0;
    uint32_t source_start = 0;

    static std::vector<uint8_t> build(const UdpSourcePayloadHeader& h);
    static Status parse(const uint8_t* data, size_t size,
                        UdpSourcePayloadHeader& out);
};

// A data datagram: FEC header + source payload header + payload. The payload
// length is implicit (the datagram size minus both headers).
struct UdpDataFrame {
    UdpFecHeader fec;
    UdpSourcePayloadHeader source;
    std::vector<uint8_t> payload;

    static std::vector<uint8_t> build(const UdpDataFrame& f);
    static Status parse(const uint8_t* data, size_t size, UdpDataFrame& out);
};

// An ACK datagram: a FEC header with RDPUDP_FLAG_ACK and no payload.
struct UdpAckFrame {
    UdpFecHeader fec;

    static std::vector<uint8_t> build(const UdpAckFrame& f);
    static Status parse(const uint8_t* data, size_t size, UdpAckFrame& out);
};

// The SYN datagram body: RDPUDP_SYNDATA_PAYLOAD + RDPUDP_SYNDATAEX_PAYLOAD.
struct UdpSyn {
    UdpFecHeader fec;
    uint32_t initial_sequence_number = 0;
    uint16_t upstream_mtu = 0;
    uint16_t downstream_mtu = 0;
    bool has_synex = false;
    uint16_t synex_flags = 0;
    uint16_t udp_version = 0;

    static std::vector<uint8_t> build(const UdpSyn& s);
    static Status parse(const uint8_t* data, size_t size, UdpSyn& out);
};

// ---------------------------------------------------------------------------
// Multitransport ([MS-RDPEMT] / [MS-RDPBCGR] 2.2.15)
// ---------------------------------------------------------------------------

// INITITATE_REQUEST_PROTOCOL_* values ([MS-RDPBCGR] 2.2.15.1).
enum MultitransportProtocol : uint16_t {
    kUdpFecReliable = 0x01,  // RDP-UDP FEC reliable transport
    kUdpFecLossy = 0x02,     // RDP-UDP FEC lossy transport
};

// Initiate Multitransport Request PDU body (after the security header).
struct MultitransportRequest {
    uint32_t request_id = 0;
    uint16_t requested_protocol = 0;
    uint16_t reserved = 0;
    std::vector<uint8_t> security_cookie;  // 16 bytes

    static std::vector<uint8_t> build(const MultitransportRequest& r);
    static Status parse(const uint8_t* data, size_t size,
                        MultitransportRequest& out);
};

// Initiate Multitransport Response PDU body (after the security header).
struct MultitransportResponse {
    uint32_t request_id = 0;
    uint32_t result_code = 0;

    static std::vector<uint8_t> build(const MultitransportResponse& r);
    static Status parse(const uint8_t* data, size_t size,
                        MultitransportResponse& out);
};

}  // namespace rtsc::proto
