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
inline constexpr const char* kRdgInData = "RDG_IN_DATA";
inline constexpr const char* kRdgOutData = "RDG_OUT_DATA";
inline constexpr const char* kRdgConnectionIdHeader = "RDG-Connection-Id";
inline constexpr const char* kRdgCorrelationIdHeader = "RDG-Correlation-Id";
inline constexpr const char* kRdgUserIdHeader = "RDG-User-Id";

struct RdgChannelRequestOptions {
    std::string method;         // RDG_IN_DATA / RDG_OUT_DATA
    std::string connection_id;  // client-generated GUID
    std::string user_agent;
    std::string correlation_id; // optional
    std::string user_id;        // optional
};

// Builds an RDGSP HTTP channel request (the IN/OUT channel creation request).
std::vector<uint8_t> BuildRdgChannelRequest(const RdgChannelRequestOptions& options);

// ---------------------------------------------------------------------------
// RD Gateway authentication (TLSAuth / SOAP)
// ---------------------------------------------------------------------------

// A parsed WWW-Authenticate challenge: `scheme realm="..."` or a bare scheme.
struct RdgAuthChallenge {
    std::string scheme;
    std::string realm;

    static Status parse_www_authenticate(const std::string& value,
                                         RdgAuthChallenge& out);
};

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
