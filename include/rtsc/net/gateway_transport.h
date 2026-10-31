// RD Gateway tunnel and RDP-UDP transport.
//
// GatewayTunnel decorates a blocking byte Transport (a TCP connection to the
// RD Gateway) with the HTTP/1.1 CONNECT handshake. Once the gateway answers
// 200, the tunnel is transparent: the RDP connection sequence (X.224 -> TLS ->
// CredSSP -> MCS -> ...) runs over the same byte stream, so the existing
// security stack is reused unchanged.
//
// UdpTransport adapts the RDP-UDP protocol ([MS-RDPEUDP]) to the blocking byte
// Transport interface. It supports the two operational modes: reliable
// (RDP-UDP-R / UDPFECR, with retransmission) and unreliable (RDP-UDP-L /
// UDPFECL, best-effort). The mode is selected through RDP_CONNECTION_TRANSPORT
// / the Initiate Multitransport Request PDU.
//
// The socket itself is behind the UdpSocket seam so the transport logic stays
// platform neutral (and testable with a scripted socket).

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "rtsc/net/tls.h"
#include "rtsc/net/transport.h"
#include "rtsc/proto/gateway.h"

namespace rtsc::net {

// A datagram socket. Receive() returns the number of bytes read (>0), 0 when
// the bounded wait elapsed with no datagram, or -1 on error.
class UdpSocket {
 public:
    virtual ~UdpSocket() = default;

    virtual bool Send(const uint8_t* data, size_t size) = 0;
    virtual int Receive(uint8_t* buf, size_t size) = 0;
    virtual void Close() = 0;
};

// Opens a UDP socket bound to `local_port` and connected to `host:peer_port`.
// Returns nullptr and fills `error` on failure.
std::unique_ptr<UdpSocket> ConnectUdp(const std::string& host,
                                      uint16_t local_port, uint16_t peer_port,
                                      std::string& error);

// A UDP transport with the RDP-UDP reliable / unreliable modes.
class UdpTransport : public Transport {
 public:
    struct Config {
        proto::UdpMode mode = proto::UdpMode::kReliable;
        uint16_t receive_window_size = 64;
        int ack_timeout_ms = 100;
        int max_retries = 5;
        // D13: malformed datagrams are counted and skipped instead of tearing
        // the link down; only once the count exceeds this cap is the transport
        // failed. 0 disables the cap (never fail on bad datagrams).
        int max_bad_datagrams = 16;
    };

    UdpTransport(std::unique_ptr<UdpSocket> socket, const Config& config);
    ~UdpTransport() override;

    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;

    int Read(uint8_t* buf, size_t size) override;
    bool Write(const uint8_t* data, size_t size) override;
    void Close() override;

    proto::UdpMode mode() const { return config_.mode; }
    bool reliable() const { return config_.mode == proto::UdpMode::kReliable; }
    unsigned send_count() const { return send_count_; }
    unsigned retry_count() const { return retry_count_; }
    unsigned ack_count() const { return ack_count_; }
    unsigned duplicate_count() const { return duplicate_count_; }
    unsigned bad_datagram_count() const { return bad_datagram_count_; }
    unsigned stash_drop_count() const { return stash_drop_count_; }

 private:
    // ReceiveDatagram() outcome codes. The transport distinguishes "an ACK was
    // consumed" (0) from "the bounded wait elapsed" (another value) and from a
    // hard failure (-1); in particular an ACK-only datagram must never surface
    // as a read timeout (D9).
    enum DatagramResult : int {
        kDatagramError = -1,   // socket error / bad-datagram cap exceeded
        kDatagramAck = 0,      // an ACK datagram was consumed
        kDatagramPayload = 1,  // a data frame was queued for Read()
        kDatagramTimeout = 2,  // bounded wait elapsed, no datagram
        kDatagramSkipped = 3,  // malformed datagram counted and skipped (D13)
    };

    // One queued inbound data frame and the source sequence number it must be
    // ACKed with once the payload has been handed to the reader (D8).
    struct StashedFrame {
        uint32_t source_start = 0;
        std::vector<uint8_t> payload;
    };

    // Sends one data frame and (in reliable mode) waits for its ACK.
    bool SendDataFrame(const std::vector<uint8_t>& payload);
    // Receives one datagram; dispatches it. Returns one of the DatagramResult
    // codes above.
    int ReceiveDatagram();
    void SendAck(uint32_t source_start);
    void StashPayload(uint32_t source_start, std::vector<uint8_t> payload);

    std::unique_ptr<UdpSocket> socket_;
    Config config_;
    bool closed_ = false;

    uint32_t next_coded_ = 1;
    uint32_t next_source_ = 1;
    uint32_t highest_received_ = 0;
    bool has_highest_received_ = false;
    uint32_t acked_source_ = 0;
    bool has_acked_source_ = false;

    // FIFO of received-but-not-yet-consumed frames (D8: a single slot used to
    // let a second frame overwrite an unconsumed first one).
    std::deque<StashedFrame> stashed_;

    unsigned send_count_ = 0;
    unsigned retry_count_ = 0;
    unsigned ack_count_ = 0;
    unsigned duplicate_count_ = 0;
    unsigned bad_datagram_count_ = 0;
    unsigned stash_drop_count_ = 0;
};

// An HTTP/1.1 CONNECT tunnel over a byte transport.
//
// The inner transport must outlive this object (it is held by reference). The
// CONNECT handshake runs in the constructor; check open() before use.
class GatewayTunnel : public Transport {
 public:
    struct Config {
        std::string target;        // "host:port" the tunnel should reach
        std::string gateway_host;  // "host:port" of the gateway itself
        std::string user_agent;
        std::string cookie;         // optional
        std::string authorization;  // optional Authorization header value
        proto::TransportType transport = proto::TransportType::kTcp;
        int connect_timeout_ms = 10000;
        // Resource ceilings for the handshake parsers. They are configuration,
        // not hard-coded policy: a deployment that needs a different envelope can
        // raise or tighten them. The defaults are the memory-safety bounds, so a
        // peer cannot make the tunnel buffer without limit.
        size_t max_head_bytes = proto::kMaxHttpHeaderBytes;
        size_t max_header_count = proto::kMaxHttpHeaderCount;
        size_t max_entity_bytes = proto::kMaxHttpEntityBytes;
        // Session-wide read accounting. 0 means "no session-wide cap": memory
        // safety is already guaranteed by the per-message ceilings above, while a
        // real RDP session legitimately moves many tens of MiB, so a lifetime byte
        // cap is only useful as a hardening / test setting.
        size_t max_session_read_bytes = 0;
        size_t max_session_reads = 0;
        // No-progress deadline: if the peer delivers nothing for this long the read
        // fails with its own "no progress" error instead of waiting forever.
        // 0 (the default) disables it everywhere. It must NOT be treated as a
        // session lifetime: a real RDP-over-gateway session is legitimately
        // idle for long stretches (an open desktop with no input), and a
        // default data-path cutoff used to strand such sessions because
        // Client::Pump read "no progress" as a peer close. The CONNECT
        // handshake is still bounded by connect_timeout_ms independently, so a
        // dead gateway cannot hang even with this left at 0. An embedder that
        // wants an idle cutoff may still set one explicitly.
        int session_timeout_ms = 0;
    };

    GatewayTunnel(Transport& inner, const Config& config);

    bool open() const { return open_; }
    int status_code() const { return status_code_; }
    const std::string& error() const { return error_; }
    const std::string& target() const { return config_.target; }
    // Session read accounting, for callers and tests that police the ceilings.
    size_t bytes_read() const { return bytes_read_; }
    size_t read_calls() const { return read_calls_; }

    int Read(uint8_t* buf, size_t size) override;
    bool Write(const uint8_t* data, size_t size) override;
    void Close() override;

 private:
    bool PerformHandshake();
    // Enforces the session read budget (bytes, call count, no-progress deadline)
    // and then performs one bounded read (at most kReadChunkSize bytes) into
    // `buf`. Returns the byte count, kReadTimeout when the peer is merely silent,
    // or -1 after setting error_.
    int ReadChunk(uint8_t* buf, size_t size);
    // True once the peer has made no progress for session_timeout_ms. This is an
    // inactivity deadline, never a session lifetime.
    bool SessionExpired() const;
    // The parser ceilings, taken from Config so the wire layer stays policy-free.
    proto::HttpLimits Limits() const;

    Transport& inner_;
    Config config_;
    bool open_ = false;
    bool closed_ = false;
    int status_code_ = 0;
    std::string error_;
    // Bytes read from the inner transport so far, and how many reads produced
    // them. 0 in Config means "uncapped".
    size_t bytes_read_ = 0;
    size_t read_calls_ = 0;
    // Timestamp of the last byte received. The inactivity deadline is measured
    // from it, so a long-lived but active session is never cut off.
    std::chrono::steady_clock::time_point last_activity_;
    // Bytes that arrived after the CONNECT response head (the server may
    // pipeline the first RDP flight with its response).
    std::vector<uint8_t> leftover_;
};

// A byte transport wrapped in a TLS layer (the RD Gateway's OUTER TLS). The
// gateway handshake and the inner RDP TLS/CredSSP run over the *plaintext* of
// this transport. Pure composition: the TLS logic is deferred to rtsc::tls
// backends (SChannel / OpenSSL), this class only shuttles bytes and drains
// records after the handshake.
class TlsByteTransport : public Transport {
 public:
    // Wraps `raw` and completes the TLS handshake before returning. On failure
    // returns nullptr and fills `error` (the caller keeps ownership failure
    // details, not the transport). `handshake_timeout_ms` bounds the whole
    // handshake; a peer that goes silent burns the bound, never the caller.
    static std::unique_ptr<Transport> Wrap(
        std::unique_ptr<Transport> raw, const rtsc::tls::Config& tls_config,
        std::string& error, int handshake_timeout_ms = 30000);

    // Test seam: builds the adaptor from an already-created TLS stack (the
    // tests inject a scripted TlsTransport) and completes the handshake now.
    TlsByteTransport(std::unique_ptr<Transport> raw,
                     std::unique_ptr<rtsc::tls::TlsTransport> tls,
                     std::string& error,
                     int handshake_timeout_ms = 30000);

    TlsByteTransport(const TlsByteTransport&) = delete;
    TlsByteTransport& operator=(const TlsByteTransport&) = delete;

    int Read(uint8_t* buf, size_t size) override;
    bool Write(const uint8_t* data, size_t size) override;
    void Close() override;

    // Drive the TLS handshake over `raw_`: pump the TLS stack with the raw
    // transport's bytes and write the stack's handshake output. True on
    // completion. `error_` is set on failure.
    bool PerformHandshake(int handshake_timeout_ms);

 private:
    // Copies at most `size` bytes out of `plaintext` and keeps the remainder in
    // pending_: the TLS contract calls max_out a soft threshold ("actual append
    // may exceed it by up to one record"), so over-produced plaintext must be
    // retained rather than discarded.
    int ServePlaintext(uint8_t* buf, size_t size,
                       const std::vector<uint8_t>& plaintext);
    // Serves bytes buffered by ServePlaintext (possibly across several reads).
    int DrainPending(uint8_t* buf, size_t size);

    std::unique_ptr<Transport> raw_;
    std::unique_ptr<rtsc::tls::TlsTransport> tls_;
    std::string error_;
    bool closed_ = false;
    // Decrypted plaintext the backend produced beyond what the caller asked
    // for. `pending_offset_` is the first unconsumed byte.
    std::vector<uint8_t> pending_;
    size_t pending_offset_ = 0;
};

// RD Gateway RDGSP transport ([MS-TSGU] 2.2.3): the client-side wrapper that
// turns TWO plain byte connections into the single Transport the RDP client
// consumes. The routing follows the factory topology ruling (docs/spec/
// gateway-stage2-evidence.md section 10):
//
//   OUT connection : downlink (gateway -> client). HTTP request (RDG_OUT_DATA)
//                    whose RESPONSE BODY is the RDP stream. 200 -> chunked
//                    decode (+ plain fallback), 101 -> raw duplex RFC 6455
//                    frames.
//   IN  connection : uplink (client -> gateway). HTTP request (RDG_IN_DATA)
//                    with a long-lived chunked REQUEST BODY carrying the RDP
//                    uplink.
//
// The two connections are established independently (H0: connect OUT, connect
// IN), the OUT channel authenticates first (401 -> NTLM three legs), then the
// IN channel reuses the won Authorization and fails loudly if the server tries
// to upgrade IT to WebSocket ("Server returned switch protocols for IN channel"
// is a hard error, evidence FUN_1801bfd60:158-170).
//
// D-A2 (adjusted audit ruling, W11 stage 2): the original single-connection
// model was disproven by the dual-connection evidence, so the old Defect is no
// longer a write-boundary defect in the same sense. A note remains (see the
// body below): under dual connections OUT saturation can still block Write;
// the mitigation is an independent read thread draining OUT while the caller
// writes. UNVERIFIED / follow-up: not implemented in this batch.
//
// D-A5 (recorded, P2): ConnectionDriver's plaintext-phase state machine is not
// re-entrant, so a torn gateway can NOT be rebuilt by re-running Connect() on
// the same RdgspTransport + driver pair. This batch records the limitation
// only; reconnection is a follow-up.
class RdgspTransport : public Transport {
 public:
    // The authentication scheme selector for the 401 handling. NTLM (default)
    // runs the RFC 4559 three legs over the ntlm.h MESSAGE layer (never the
    // CredsspClient state machine). Basic is the documented fallback when the
    // server offers it under kStrict-equivalent HTTPS. Negotiate / Claims are
    // NOT implemented and fail explicitly.
    enum class AuthScheme { kNtlm, kBasic, kUnsupported };

    // Data-plane routing selected by the OUT response: 200 -> chunked body,
    // 101 -> upgraded raw duplex.
    enum class Mode { kChunked, kUpgraded };

    // Handshake / data deadlines (evidence table FUN_1801c6b44
    // 120000/60000/30000/90000/30000 ms). The five values map to
    // connect / response head / auth round-trip / IN write / OUT read in that
    // order; the field-level mapping is UNVERIFIED against named factory
    // fields, only the value set is evidenced.
    struct Deadlines {
        int connect_ms = 120000;
        int response_ms = 60000;
        int auth_ms = 30000;
        int write_ms = 90000;
        int read_ms = 30000;
    };

    struct Config {
        // -- gateway identity (Scheme://host:port/remoteDesktopGateway/) -----
        std::string host;              // gateway host (default plain-http connect)
        uint16_t port = 443;           // default gateway port
        std::string connection_id;     // client-generated GUID, both channels
        std::string user_agent = "MS-RDGateway/1.0";  // factory string
        // The RDP target hostname (used for the inner RDP TLS/CredSSP target
        // by the caller; informational here).
        std::string target_host;

        // -- authentication -------------------------------------------------
        std::string domain;
        std::string user_name;
        std::string password;
        AuthScheme auth_scheme = AuthScheme::kNtlm;
        // D-A8: the factory's 401 retry cap has NO source constant (field
        // +0xd3c is externally configured, evidence FUN_1801c235c). Default 3,
        // configurable. UNVERIFIED against the shipped binary.
        int max_auth_retries = 3;

        // -- routing switch ---------------------------------------------------
        // When the OUT channel upgrades (101) the write side moves to OUT.
        // false keeps IN writes in kUpgraded mode (the "IN carries management
        // streams after upgrade" fallback; UNVERIFIED, see evidence section 11).
        bool upgrade_steals_write = true;

        // -- RFC 6455 upgrade (OUT channel) -----------------------------------
        // Pinned Sec-WebSocket-Key for the OUT upgrade request. Empty (the
        // default) makes the builder generate a FRESH key for every attempt, so
        // a 401 retry never reuses a nonce. Setting it pins one exact key (test
        // seam / deterministic deployment): the caller must then answer the
        // matching Sec-WebSocket-Accept. The 101 handler recomputes the Accept
        // from the key THIS attempt actually sent, so a pinned key and a fresh
        // key are validated identically.
        std::string websocket_key;

        Deadlines deadlines;

        // -- connection factory seam (test / deployment injection) ----------
        // Called once per channel during Connect(). A null connector falls back
        // to ConnectTcp(host, port) -- the factory's built-in cleartext "http
        // when the HTTPS switch is off" mode (+0x6a8 == 0, evidence
        // FUN_1801bd574), which is exactly what the stub tests use.
        using Connector =
            std::function<std::unique_ptr<Transport>(std::string& error)>;
        Connector connect_out;
        Connector connect_in;
    };

    explicit RdgspTransport(const Config& config);

    RdgspTransport(const RdgspTransport&) = delete;
    RdgspTransport& operator=(const RdgspTransport&) = delete;

    // The whole handshake (H0-H8). Explicitly separate from the constructor so
    // failures produce a digestible error instead of an exception-ish state.
    bool Connect(std::string& error);

    bool connected() const { return connected_; }
    Mode mode() const { return mode_; }
    bool upgraded() const { return mode_ == Mode::kUpgraded; }
    const std::string& error() const { return error_; }
    // The mapped HRESULT of the failure, when one exists (see the status table
    // in docs/spec/gateway-stage2-design.md section 7).
    uint32_t hresult() const { return hresult_; }
    int auth_retry_count() const { return auth_retry_count_; }
    int in_retry_count() const { return in_retry_count_; }
    const std::string& last_authorization() const {
        return last_authorization_;
    }

    int Read(uint8_t* buf, size_t size) override;
    bool Write(const uint8_t* data, size_t size) override;
    void Close() override;

 private:
    // H1 / H5: writes one channel request and reads until the head parses.
    // Returns the status code, or -1 with error_ set.
    int SendAndReadResponse(Transport& t, const std::vector<uint8_t>& request,
                            int timeout_ms, proto::HttpMessage& response,
                            std::vector<uint8_t>& leftover);
    // One 401 response: advances the NTLM legs / Basic / rejects unsupported
    // schemes. Returns false with error_ set.
    bool HandleChallenge(const proto::HttpMessage& response,
                         std::string& authorization);
    // H0-H4: establishes OUT (200/101 or authed 200/101).
    bool EstablishOutChannel(std::string& error);
    // H5-H7: establishes IN (RDG_IN_DATA, chunked body; IN 101 is a hard error).
    bool EstablishInChannel(std::string& error);
    // RFC 6455 4.1 three-way check on a 101: Upgrade: websocket, a Connection
    // header carrying the Upgrade token, and Sec-WebSocket-Accept equal to
    // ComputeWebSocketAccept(the key this attempt sent). Any mismatch fails
    // closed through Fail() (the connection is already upgraded, so the bytes
    // cannot be re-read as an HTTP body).
    bool ValidateWebSocketUpgrade(const proto::HttpMessage& response,
                                  const std::string& used_key);
    void Fail(const std::string& reason, uint32_t hr);

    // Read data plane helpers.
    int ReadChunked(uint8_t* buf, size_t size);
    int ReadUpgraded(uint8_t* buf, size_t size);
    // Queues the data frames in `frames` for ReadUpgraded to deliver (control
    // frames are consumed but not surfaced).
    void ExtendFrames(const std::vector<proto::WebSocketFrame>& frames);

    Config config_;
    bool connected_ = false;
    bool closed_ = false;
    std::string error_;
    uint32_t hresult_ = 0;
    Mode mode_ = Mode::kChunked;

    std::unique_ptr<Transport> out_;
    std::unique_ptr<Transport> in_;

    // OUT response head (kept for the challenge parser / chunked detection).
    proto::HttpMessage out_response_;
    std::vector<uint8_t> leftover_;

    std::string last_authorization_;
    int auth_retry_count_ = 0;
    int in_retry_count_ = 0;

    bool out_plain_ = false;  // OUT body is not chunked: pass through raw
    proto::ChunkedDecoder chunked_decoder_{proto::kMaxChunkedChunkBytes,
                                           ~static_cast<size_t>(0)};
    std::vector<uint8_t> read_buffer_;
    proto::WebSocketFrameDecoder websocket_decoder_;
    std::vector<proto::WebSocketFrame> pending_frames_;
    size_t pending_frame_index_ = 0;
};

}  // namespace rtsc::net
