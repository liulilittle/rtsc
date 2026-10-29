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
#include <memory>
#include <string>
#include <vector>

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

 private:
    // Sends one data frame and (in reliable mode) waits for its ACK.
    bool SendDataFrame(const std::vector<uint8_t>& payload);
    // Receives one datagram; dispatches it. Returns 1 when a payload was stashed
    // for Read(), 0 on timeout / ACK-only, -1 on error.
    int ReceiveDatagram();
    void SendAck(uint32_t source_start);
    void StashPayload(std::vector<uint8_t> payload);

    std::unique_ptr<UdpSocket> socket_;
    Config config_;
    bool closed_ = false;

    uint32_t next_coded_ = 1;
    uint32_t next_source_ = 1;
    uint32_t highest_received_ = 0;
    bool has_highest_received_ = false;
    uint32_t acked_source_ = 0;
    bool has_acked_source_ = false;

    std::vector<uint8_t> stashed_;

    unsigned send_count_ = 0;
    unsigned retry_count_ = 0;
    unsigned ack_count_ = 0;
    unsigned duplicate_count_ = 0;
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

}  // namespace rtsc::net
