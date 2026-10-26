// RD Gateway tunnel and RDP-UDP transport logic (platform neutral).

#include "rtsc/net/gateway_transport.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <utility>

namespace rtsc::net {

UdpTransport::UdpTransport(std::unique_ptr<UdpSocket> socket,
                           const Config& config)
    : socket_(std::move(socket)), config_(config) {}

UdpTransport::~UdpTransport() { Close(); }

int UdpTransport::Read(uint8_t* buf, size_t size) {
    if (closed_ || buf == nullptr || size == 0) return closed_ ? -1 : 0;
    for (;;) {
        if (!stashed_.empty()) {
            const size_t n = std::min(size, stashed_.size());
            std::memcpy(buf, stashed_.data(), n);
            stashed_.erase(stashed_.begin(),
                           stashed_.begin() + static_cast<std::ptrdiff_t>(n));
            return static_cast<int>(n);
        }
        const int r = ReceiveDatagram();
        if (r == 1) continue;
        if (r == 0) return kReadTimeout;
        return -1;
    }
}

bool UdpTransport::Write(const uint8_t* data, size_t size) {
    if (closed_) return false;
    if (data == nullptr || size == 0) return true;
    return SendDataFrame(std::vector<uint8_t>(data, data + size));
}

void UdpTransport::Close() {
    if (closed_) return;
    closed_ = true;
    socket_->Close();
}

bool UdpTransport::SendDataFrame(const std::vector<uint8_t>& payload) {
    proto::UdpDataFrame frame;
    frame.fec.source_ack = has_highest_received_ ? highest_received_ : 0;
    frame.fec.receive_window_size = config_.receive_window_size;
    frame.fec.flags = proto::kUdpFlagData;
    if (!reliable()) frame.fec.flags |= proto::kUdpFlagSynlossy;
    frame.source.coded = next_coded_++;
    frame.source.source_start = next_source_++;
    frame.payload = payload;
    const std::vector<uint8_t> bytes = proto::UdpDataFrame::build(frame);
    ++send_count_;
    if (!socket_->Send(bytes.data(), bytes.size())) return false;
    if (!reliable()) return true;

    // Stop-and-wait: wait for the ACK for this source sequence number. Inbound
    // data is ACKed and stashed while waiting, so the peer can make progress.
    for (int attempt = 0; attempt < config_.max_retries; ++attempt) {
        if (attempt > 0) {
            ++retry_count_;
            if (!socket_->Send(bytes.data(), bytes.size())) return false;
        }
        const auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::milliseconds(config_.ack_timeout_ms);
        for (;;) {
            if (has_acked_source_ &&
                acked_source_ >= frame.source.source_start) {
                return true;
            }
            if (std::chrono::steady_clock::now() >= deadline) break;
            const int r = ReceiveDatagram();
            if (r < 0) return false;
        }
    }
    return false;
}

int UdpTransport::ReceiveDatagram() {
    uint8_t buf[65536];
    const int n = socket_->Receive(buf, sizeof(buf));
    if (n == 0) return 0;
    if (n < 0) return -1;
    const std::vector<uint8_t> datagram(buf, buf + n);

    proto::UdpAckFrame ack;
    if (proto::UdpAckFrame::parse(datagram.data(), datagram.size(), ack) ==
        proto::Status::Ok) {
        acked_source_ = ack.fec.source_ack;
        has_acked_source_ = true;
        ++ack_count_;
        return 0;
    }

    proto::UdpDataFrame frame;
    if (proto::UdpDataFrame::parse(datagram.data(), datagram.size(), frame) ==
        proto::Status::Ok) {
        if (has_highest_received_ &&
            frame.source.source_start <= highest_received_) {
            ++duplicate_count_;
        } else {
            highest_received_ = frame.source.source_start;
            has_highest_received_ = true;
            StashPayload(std::move(frame.payload));
        }
        if (reliable()) SendAck(frame.source.source_start);
        return 1;
    }
    return -1;
}

void UdpTransport::SendAck(uint32_t source_start) {
    proto::UdpAckFrame ack;
    ack.fec.source_ack = source_start;
    ack.fec.receive_window_size = config_.receive_window_size;
    ack.fec.flags = proto::kUdpFlagAck;
    const std::vector<uint8_t> bytes = proto::UdpAckFrame::build(ack);
    socket_->Send(bytes.data(), bytes.size());
}

void UdpTransport::StashPayload(std::vector<uint8_t> payload) {
    stashed_ = std::move(payload);
}

// ---- gateway tunnel ----------------------------------------------------------

GatewayTunnel::GatewayTunnel(Transport& inner, const Config& config)
    : inner_(inner), config_(config) {
    PerformHandshake();
}

bool GatewayTunnel::PerformHandshake() {
    proto::ConnectRequestOptions options;
    options.target = config_.target;
    options.gateway_host = config_.gateway_host;
    options.user_agent = config_.user_agent;
    options.cookie = config_.cookie;
    options.authorization = config_.authorization;
    options.transport = config_.transport;
    const std::vector<uint8_t> request = proto::BuildHttpConnectRequest(options);
    if (!inner_.Write(request.data(), request.size())) {
        error_ = "failed to send the gateway CONNECT request";
        return false;
    }

    std::vector<uint8_t> buffer;
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(config_.connect_timeout_ms);
    for (;;) {
        proto::HttpMessage message;
        size_t consumed = 0;
        const proto::Status st = proto::HttpMessage::parse(
            buffer.data(), buffer.size(), message, consumed);
        if (st == proto::Status::Ok) {
            status_code_ = message.status_code;
            if (status_code_ != 200) {
                error_ = "gateway refused the tunnel (HTTP " +
                         std::to_string(status_code_) + ")";
                return false;
            }
            // Preserve any bytes that followed the response head: they already
            // belong to the RDP byte stream.
            if (consumed < buffer.size()) {
                leftover_.assign(buffer.begin() + static_cast<std::ptrdiff_t>(consumed),
                                 buffer.end());
            }
            open_ = true;
            return true;
        }
        if (st != proto::Status::NeedMoreData) {
            error_ = "malformed gateway response";
            return false;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            error_ = "gateway CONNECT timed out";
            return false;
        }
        uint8_t chunk[4096];
        const int n = inner_.Read(chunk, sizeof(chunk));
        if (n == kReadTimeout) continue;
        if (n <= 0) {
            error_ = "gateway closed during CONNECT";
            return false;
        }
        buffer.insert(buffer.end(), chunk, chunk + n);
    }
}

int GatewayTunnel::Read(uint8_t* buf, size_t size) {
    if (closed_) return -1;
    if (!open_) {
        error_ = "gateway tunnel is not open";
        return -1;
    }
    if (!leftover_.empty()) {
        const size_t n = std::min(size, leftover_.size());
        std::memcpy(buf, leftover_.data(), n);
        leftover_.erase(leftover_.begin(),
                        leftover_.begin() + static_cast<std::ptrdiff_t>(n));
        return static_cast<int>(n);
    }
    return inner_.Read(buf, size);
}

bool GatewayTunnel::Write(const uint8_t* data, size_t size) {
    if (closed_) return false;
    if (!open_) {
        error_ = "gateway tunnel is not open";
        return false;
    }
    return inner_.Write(data, size);
}

void GatewayTunnel::Close() {
    if (closed_) return;
    closed_ = true;
    inner_.Close();
}

}  // namespace rtsc::net
