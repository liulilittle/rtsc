// RD Gateway tunnel and RDP-UDP transport logic (platform neutral).

#include "rtsc/net/gateway_transport.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <utility>

#include "rtsc/credssp/ntlm.h"
#include "rtsc/crypto/random.h"

namespace rtsc::net {

namespace {

// RDP-UDP source sequence numbers wrap at 2^32 (RFC 1982 serial arithmetic):
// `a` is "after" `b` when their signed difference is positive. Plain
// comparison mis-orders a frame that arrives right after a wrap (the old
// `acked_source_ >= start` / `start <= highest` comparisons did exactly that).
inline bool SeqAfter(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) > 0;
}

inline bool SeqAtOrAfter(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) >= 0;
}

}  // namespace

UdpTransport::UdpTransport(std::unique_ptr<UdpSocket> socket,
                           const Config& config)
    : socket_(std::move(socket)), config_(config) {}

UdpTransport::~UdpTransport() { Close(); }

int UdpTransport::Read(uint8_t* buf, size_t size) {
    if (closed_ || buf == nullptr || size == 0) return closed_ ? -1 : 0;
    for (;;) {
        if (!stashed_.empty()) {
            const size_t n = std::min(size, stashed_.front().payload.size());
            std::memcpy(buf, stashed_.front().payload.data(), n);
            if (n < stashed_.front().payload.size()) {
                // Partial read of one frame: keep the remainder queued.
                stashed_.front().payload.erase(
                    stashed_.front().payload.begin(),
                    stashed_.front().payload.begin() +
                        static_cast<std::ptrdiff_t>(n));
                return static_cast<int>(n);
            }
            // The frame was ACKed when it was queued (D8): an ACK means "the
            // frame is durably buffered in the bounded FIFO", never "the
            // reader consumed it". That keeps peer progress independent of the
            // application's read cadence (R1) while the queue guarantees the
            // frame is never dropped by an overwrite. Consuming just delivers.
            stashed_.pop_front();
            return static_cast<int>(n);
        }
        const int r = ReceiveDatagram();
        if (r == kDatagramPayload || r == kDatagramAck ||
            r == kDatagramSkipped) {
            continue;  // queued payload / consumed ACK / skipped bad datagram
        }
        if (r == kDatagramTimeout) return kReadTimeout;
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
            // D12: wrap-safe "acked_source_ covers our frame".
            if (has_acked_source_ &&
                SeqAtOrAfter(acked_source_, frame.source.source_start)) {
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
    if (n == 0) return kDatagramTimeout;
    if (n < 0) return kDatagramError;
    const std::vector<uint8_t> datagram(buf, buf + n);

    proto::UdpAckFrame ack;
    if (proto::UdpAckFrame::parse(datagram.data(), datagram.size(), ack) ==
        proto::Status::Ok) {
        acked_source_ = ack.fec.source_ack;
        has_acked_source_ = true;
        ++ack_count_;
        // D9: an ACK is not a read timeout; it is its own outcome so Read()
        // keeps polling instead of reporting kReadTimeout for a live peer.
        return kDatagramAck;
    }

    proto::UdpDataFrame frame;
    if (proto::UdpDataFrame::parse(datagram.data(), datagram.size(), frame) ==
        proto::Status::Ok) {
        if (has_highest_received_ &&
            !SeqAfter(frame.source.source_start, highest_received_)) {
            ++duplicate_count_;
            // A repeat of a frame already accepted: re-ACK it so a stop-and-wait
            // sender whose ACK was lost does not burn a retransmission timeout.
            if (reliable()) SendAck(frame.source.source_start);
        } else if (config_.receive_window_size > 0 &&
                   stashed_.size() >=
                       static_cast<size_t>(config_.receive_window_size)) {
            // R2: the inbound queue is bounded (the receive window), so a peer
            // that floods without a reader cannot grow memory without bound. A
            // frame received while the queue is full is dropped and NOT ACKed
            // (the honest "I have not accepted this data" signal that makes a
            // reliable sender retry once a slot frees).
            ++stash_drop_count_;
        } else {
            highest_received_ = frame.source.source_start;
            has_highest_received_ = true;
            StashPayload(frame.source.source_start, std::move(frame.payload));
            // D8/R1: a frame ACKed here is durably queued (the FIFO never
            // overwrites, and it is bounded), so ACKing at enqueue is lossless
            // and keeps the peer's stop-and-wait independent of this side's
            // read cadence.
            if (reliable()) SendAck(frame.source.source_start);
        }
        return kDatagramPayload;
    }

    // D13: a malformed datagram is counted and skipped instead of tearing the
    // link down on the first offender; only a flood past the configured cap
    // forces the -1 failure.
    ++bad_datagram_count_;
    if (config_.max_bad_datagrams > 0 &&
        static_cast<unsigned>(config_.max_bad_datagrams) < bad_datagram_count_) {
        return kDatagramError;
    }
    return kDatagramSkipped;
}

void UdpTransport::SendAck(uint32_t source_start) {
    proto::UdpAckFrame ack;
    ack.fec.source_ack = source_start;
    ack.fec.receive_window_size = config_.receive_window_size;
    ack.fec.flags = proto::kUdpFlagAck;
    const std::vector<uint8_t> bytes = proto::UdpAckFrame::build(ack);
    socket_->Send(bytes.data(), bytes.size());
}

void UdpTransport::StashPayload(uint32_t source_start,
                                std::vector<uint8_t> payload) {
    // FIFO (D8): a single slot used to drop the previous unconsumed frame when
    // a second one arrived.
    stashed_.push_back({source_start, std::move(payload)});
}

// ---- gateway tunnel ----------------------------------------------------------

namespace {

// Every read is bounded: a fixed 4 KiB stack chunk, a cap on the number of loop
// iterations, a session-wide byte/call budget, and a no-progress deadline. None
// of those grows with what the peer sends, and none of them retries a failure
// (retrying is what turns a hostile peer into memory pressure).
constexpr size_t kReadChunkSize = 4096;
// Hard ceiling on loop iterations, independent of any timing. A peer that keeps
// a read loop turning forever hits this even when the clock is frozen.
constexpr int kMaxReadLoops = 1 << 20;

}  // namespace

GatewayTunnel::GatewayTunnel(Transport& inner, const Config& config)
    : inner_(inner), config_(config) {
    last_activity_ = std::chrono::steady_clock::now();
    PerformHandshake();
}

proto::HttpLimits GatewayTunnel::Limits() const {
    proto::HttpLimits limits;
    if (config_.max_head_bytes > 0) {
        limits.max_head_bytes = config_.max_head_bytes;
    }
    if (config_.max_entity_bytes > 0) {
        limits.max_entity_bytes = config_.max_entity_bytes;
    }
    if (config_.max_header_count > 0) {
        limits.max_header_count = config_.max_header_count;
    }
    return limits;
}

bool GatewayTunnel::SessionExpired() const {
    if (config_.session_timeout_ms <= 0) return false;
    return std::chrono::steady_clock::now() - last_activity_ >=
           std::chrono::milliseconds(config_.session_timeout_ms);
}

int GatewayTunnel::ReadChunk(uint8_t* buf, size_t size) {
    // 0 means "no session-wide cap" for both counters: the per-message ceilings
    // are what bound memory, so an unlimited session is still memory safe.
    const bool over_bytes = config_.max_session_read_bytes != 0 &&
                            bytes_read_ >= config_.max_session_read_bytes;
    const bool over_calls =
        config_.max_session_reads != 0 && read_calls_ >= config_.max_session_reads;
    if (over_bytes || over_calls) {
        error_ = "gateway session exceeded its configured read budget";
        return -1;
    }
    if (SessionExpired()) {
        // Deliberately distinct from the byte budget: this is "the peer stopped
        // sending", which is a different operational signal from an explicit cap.
        error_ = "gateway made no progress within the session deadline";
        return -1;
    }
    ++read_calls_;
    const int n = inner_.Read(buf, (std::min)(size, kReadChunkSize));
    if (n > 0) {
        bytes_read_ += static_cast<size_t>(n);
        last_activity_ = std::chrono::steady_clock::now();
    }
    return n;
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
    // D-A1/D-A4: an empty request is a builder rejection (CRLF / NUL in a
    // configured value), never a legitimate zero-length send. Writing zero
    // bytes would "succeed", the handshake would then burn its deadline waiting
    // for a response that was never asked for, and the caller would be told
    // "timed out" instead of the real problem. Fail loudly and distinctly so
    // the caller can tell a misconfiguration from a dead gateway.
    if (request.empty()) {
        error_ =
            "gateway request rejected by builder (CRLF/NUL in a header value)";
        return false;
    }
    if (!inner_.Write(request.data(), request.size())) {
        error_ = "failed to send the gateway CONNECT request";
        return false;
    }

    std::vector<uint8_t> buffer;
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(config_.connect_timeout_ms);
    // One message worth of bytes plus one read of slack: derived from the
    // configured ceilings, so raising them raises the bound in step, while the
    // peer can never push more than that into `buffer`.
    const proto::HttpLimits limits = Limits();
    const size_t buffer_limit = limits.max_head_bytes + kReadChunkSize;
    for (int loops = 0; loops < kMaxReadLoops; ++loops) {
        proto::HttpMessage message;
        size_t consumed = 0;
        const proto::Status st = proto::HttpMessage::parse(
            buffer.data(), buffer.size(), message, consumed, limits);
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
                leftover_.assign(
                    buffer.begin() + static_cast<std::ptrdiff_t>(consumed),
                    buffer.end());
            }
            open_ = true;
            return true;
        }
        if (st != proto::Status::NeedMoreData) {
            // A limit violation is reported as itself; it is a hard failure, not
            // something to wait on or retry, because retrying is what amplifies a
            // hostile peer into memory pressure.
            error_ = st == proto::Status::InvalidLength
                         ? "gateway response exceeded a size limit"
                         : "malformed gateway response";
            return false;
        }
        if (buffer.size() > buffer_limit) {
            error_ = "gateway response exceeded a size limit";
            return false;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            error_ = "gateway CONNECT timed out";
            return false;
        }
        if (SessionExpired()) {
            // Distinct from the byte budget on purpose: this is "the peer stopped
            // making progress", a different operational signal from a session that
            // hit an explicit cap.
            error_ = "gateway made no progress within the session deadline";
            return false;
        }
        uint8_t chunk[kReadChunkSize];
        const int n = ReadChunk(chunk, sizeof(chunk));
        if (n == kReadTimeout) continue;  // the deadline above is the exit
        if (n <= 0) {
            if (error_.empty()) error_ = "gateway closed during CONNECT";
            return false;
        }
        buffer.insert(buffer.end(), chunk, chunk + n);
    }
    if (error_.empty()) error_ = "gateway CONNECT needed too many reads";
    return false;
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
    return ReadChunk(buf, size);
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

// ---- outer TLS byte transport ----------------------------------------------

TlsByteTransport::TlsByteTransport(std::unique_ptr<Transport> raw,
                                   std::unique_ptr<tls::TlsTransport> tls,
                                   std::string& error,
                                   int handshake_timeout_ms)
    : raw_(std::move(raw)), tls_(std::move(tls)) {
    if (!PerformHandshake(handshake_timeout_ms)) {
        error = error_;
    }
}

std::unique_ptr<Transport> TlsByteTransport::Wrap(
    std::unique_ptr<Transport> raw, const tls::Config& tls_config,
    std::string& error, int handshake_timeout_ms) {
    std::string why;
    std::unique_ptr<tls::TlsTransport> tls =
        tls::CreatePlatformTlsTransport(tls_config, why);
    if (!tls) {
        error = "cannot create the gateway TLS stack: " + why;
        return nullptr;
    }
    std::unique_ptr<TlsByteTransport> wrapped(
        new TlsByteTransport(std::move(raw), std::move(tls), error,
                             handshake_timeout_ms));
    if (!error.empty()) return nullptr;
    return wrapped;
}

// Drives the TLS handshake to completion over the raw transport. The pump
// mirrors the security layer's contract: Handshake() takes whatever input is
// buffered (possibly none), produces output to write, and only when it stops
// producing does the loop read more peer bytes. tls_->buffered_input() is
// trusted to hold partial records, so nothing is discarded.
bool TlsByteTransport::PerformHandshake(int handshake_timeout_ms) {
    const int timeout =
        handshake_timeout_ms > 0 ? handshake_timeout_ms : 30000;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    std::vector<uint8_t> pending_in;
    for (;;) {
        if (tls_->handshake_complete()) return true;
        if (std::chrono::steady_clock::now() >= deadline) {
            error_ = "gateway TLS handshake timed out";
            return false;
        }
        size_t consumed = 0;
        std::vector<uint8_t> produced;
        const tls::Error e =
            tls_->Handshake(pending_in.data(), pending_in.size(), consumed,
                            produced);
        if (e.status != tls::Status::kOk &&
            e.status != tls::Status::kNeedMoreInput) {
            error_ = "gateway TLS handshake failed: " + e.message;
            return false;
        }
        if (consumed > pending_in.size()) {
            error_ = "gateway TLS handshake consumed more input than given";
            return false;
        }
        pending_in.erase(pending_in.begin(),
                         pending_in.begin() + static_cast<ptrdiff_t>(consumed));

        if (!produced.empty()) {
            if (!raw_->Write(produced.data(), produced.size())) {
                error_ = "gateway TLS handshake write failed";
                return false;
            }
            continue;
        }
        if (tls_->handshake_complete()) return true;

        uint8_t chunk[16384];
        const int n = raw_->Read(chunk, sizeof(chunk));
        if (n == kReadTimeout) continue;
        if (n <= 0) {
            error_ = "gateway closed during the TLS handshake";
            return false;
        }
        pending_in.insert(pending_in.end(), chunk, chunk + n);
    }
}

int TlsByteTransport::ServePlaintext(uint8_t* buf, size_t size,
                                     const std::vector<uint8_t>& plaintext) {
    const size_t n = (std::min)(size, plaintext.size());
    std::memcpy(buf, plaintext.data(), n);
    if (plaintext.size() > n) {
        pending_.assign(plaintext.begin() + static_cast<std::ptrdiff_t>(n),
                        plaintext.end());
        pending_offset_ = 0;
    }
    return static_cast<int>(n);
}

int TlsByteTransport::DrainPending(uint8_t* buf, size_t size) {
    const size_t n = (std::min)(size, pending_.size() - pending_offset_);
    std::memcpy(buf, pending_.data() + pending_offset_, n);
    pending_offset_ += n;
    if (pending_offset_ >= pending_.size()) {
        pending_.clear();
        pending_offset_ = 0;
    }
    return static_cast<int>(n);
}

int TlsByteTransport::Read(uint8_t* buf, size_t size) {
    if (closed_) return -1;
    if (buf == nullptr || size == 0) return 0;
    // max_out is a soft threshold, so the backend may have produced more
    // plaintext than the caller asked for. Serve that tail before touching the
    // socket again; discarding it silently truncates the stream.
    if (pending_offset_ < pending_.size()) return DrainPending(buf, size);
    pending_.clear();
    pending_offset_ = 0;

    // Drain records the backend already holds before asking the socket.
    for (;;) {
        std::vector<uint8_t> plaintext;
        const tls::Error e = tls_->Receive(nullptr, 0, plaintext, size);
        if (e.status != tls::Status::kOk &&
            e.status != tls::Status::kClosed &&
            e.status != tls::Status::kNeedMoreInput) {
            error_ = "gateway TLS receive failed (drain): " + e.message;
            return -1;
        }
        if (!plaintext.empty() && e.status != tls::Status::kClosed) {
            return ServePlaintext(buf, size, plaintext);
        }
        if (tls_->buffered_input() > 0) continue;

        uint8_t chunk[16384];
        const int n = raw_->Read(chunk, sizeof(chunk));
        if (n == kReadTimeout) return kReadTimeout;
        if (n <= 0) return n;  // EOF 0 / error -1
        std::vector<uint8_t> out;
        const tls::Error r =
            tls_->Receive(chunk, static_cast<size_t>(n), out, size);
        if (r.status != tls::Status::kOk && r.status != tls::Status::kClosed &&
            r.status != tls::Status::kNeedMoreInput) {
            error_ = "gateway TLS receive failed: " + r.message;
            return -1;
        }
        if (!out.empty() && r.status != tls::Status::kClosed) {
            return ServePlaintext(buf, size, out);
        }
        if (r.status == tls::Status::kClosed) return 0;
        return kReadTimeout;  // fed a record fragment; keep polling
    }
}

bool TlsByteTransport::Write(const uint8_t* data, size_t size) {
    if (closed_) return false;
    // The TLS contract lets a backend consume only part of the input (OpenSSL
    // stops on WANT_READ/WANT_WRITE and still reports kOk). Feed the tail until
    // every byte is consumed; returning true after a partial consume loses the
    // remainder while violating the "sends all bytes" transport contract.
    size_t offset = 0;
    int stalls = 0;
    while (offset < size) {
        size_t consumed = 0;
        std::vector<uint8_t> out;
        const tls::Error e = tls_->Send(data + offset, size - offset, consumed, out);
        if (!e.ok()) {
            error_ = "gateway TLS send failed: " + e.message;
            return false;
        }
        if (consumed > size - offset) {
            error_ = "gateway TLS send consumed more bytes than given";
            return false;
        }
        if (!out.empty() && !raw_->Write(out.data(), out.size())) {
            error_ = "gateway TLS write failed";
            return false;
        }
        offset += consumed;
        if (offset == size) break;

        if (consumed != 0) {
            stalls = 0;
            continue;
        }

        // No progress: the backend is waiting for peer bytes. Read one raw
        // chunk, hand it to Receive so the TLS state can advance, then retry.
        // A silent or closed peer is a write failure, never an endless wait.
        if (++stalls > 32) {
            error_ = "gateway TLS send made no progress";
            return false;
        }
        uint8_t chunk[16384];
        const int n = raw_->Read(chunk, sizeof(chunk));
        if (n == kReadTimeout) {
            error_ = "gateway TLS send made no progress (read timeout)";
            return false;
        }
        if (n <= 0) {
            error_ = "gateway TLS send cannot progress: peer closed";
            return false;
        }
        std::vector<uint8_t> plaintext;
        const tls::Error r =
            tls_->Receive(chunk, static_cast<size_t>(n), plaintext, 0);
        if (r.status != tls::Status::kOk && r.status != tls::Status::kClosed &&
            r.status != tls::Status::kNeedMoreInput) {
            error_ = "gateway TLS receive failed while sending: " + r.message;
            return false;
        }
        if (!plaintext.empty()) {
            // Application data that arrived while draining belongs to Read().
            pending_.insert(pending_.end(), plaintext.begin(), plaintext.end());
        }
    }
    return true;
}

void TlsByteTransport::Close() {
    if (closed_) return;
    closed_ = true;
    pending_.clear();
    pending_offset_ = 0;
    raw_->Close();
}

// ---- RDGSP transport --------------------------------------------------------

namespace {

// RFC 4648 base64 decoding (strict): accepts ASCII input, returns false on
// anything invalid (bad alphabet, truncated padding). Used for the NTLM
// type-2 token carried in the WWW-Authenticate value.
bool DecodeBase64(const std::string& in, std::vector<uint8_t>& out) {
    auto nibble = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
        if (c >= '0' && c <= '9') return 52 + (c - '0');
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    out.reserve(in.size() * 3 / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (c == '=') {
            // Padding is only legal at the end and must fit the output.
            const size_t tail = in.size() - i;
            if (tail > 2) return false;
            break;
        }
        const int v = nibble(c);
        if (v < 0) return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    if (bits >= 6) return false;  // dangling partial group
    return true;
}

std::string AsString(const std::vector<uint8_t>& b) {
    return std::string(b.begin(), b.end());
}

// Current UTC time as an NTLM FILETIME (100 ns intervals since 1601-01-01).
uint64_t NowFileTime() {
    const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
    const auto hundred_ns = std::chrono::duration_cast<
        std::chrono::duration<int64_t, std::ratio<1, 10000000>>>(
        since_epoch);
    return static_cast<uint64_t>(hundred_ns.count()) +
           116444736000000000ULL;  // 1601-1970 offset in 100 ns
}

// Serializes an AV_PAIR list the way NTLMv2 wants it: each pair sans the
// trailing MsvAvEOL ([MS-NLMP] 2.2.2.1, the terminator is NOT part of the
// client-challenge blob).
std::vector<uint8_t> EncodeAvPairsNoEol(const std::vector<credssp::AvPair>& in) {
    std::vector<uint8_t> out;
    for (const auto& p : in) {
        if (p.id == credssp::AvId::kEol) break;
        const uint16_t id = static_cast<uint16_t>(p.id);
        const uint16_t len = static_cast<uint16_t>(p.value.size());
        out.push_back(static_cast<uint8_t>(id & 0xFF));
        out.push_back(static_cast<uint8_t>(id >> 8));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.push_back(static_cast<uint8_t>(len >> 8));
        out.insert(out.end(), p.value.begin(), p.value.end());
    }
    return out;
}

// Builds the NTLM AUTHENTICATE (type 3) message from a server CHALLENGE
// (type 2) using the message-level ntlm.h layer and the NTLMv2 computation.
// The CredsspClient state machine is deliberately NOT reused (its TSRequest /
// channel-binding envelope is CredSSP-specific; HTTP NTLM is bare messages).
bool BuildNtlmType3(const credssp::ChallengeMessage& chg,
                    const RdgspTransport::Config& cfg, std::vector<uint8_t>& out,
                    std::string& err) {
    credssp::NtlmV2Inputs in;
    in.user = cfg.user_name;
    in.domain = cfg.domain;
    in.password = cfg.password;
    in.server_challenge.assign(chg.server_challenge.begin(),
                               chg.server_challenge.end());

    std::vector<uint8_t> client_challenge(8);
    if (!crypto::RandomBytes(client_challenge.data(), client_challenge.size())) {
        err = "CSPRNG failure while building the NTLM response";
        return false;
    }

    const uint64_t ft = NowFileTime();
    std::vector<uint8_t> timestamp(8);
    for (size_t i = 0; i < 8; ++i) {
        timestamp[i] = static_cast<uint8_t>((ft >> (8 * i)) & 0xFF);
    }

    std::vector<uint8_t> ts_value;
    in.suppress_lm_response =
        chg.FindAvPair(credssp::AvId::kTimestamp, ts_value).ok();
    in.client_challenge = std::move(client_challenge);
    in.timestamp = std::move(timestamp);
    in.target_info = EncodeAvPairsNoEol(chg.av_pairs);

    credssp::NtlmV2Output computed;
    const credssp::Error e = credssp::ComputeNtlmV2(in, computed);
    if (!e.ok()) {
        err = "NTLMv2 computation failed: " + e.message;
        return false;
    }

    credssp::AuthenticateMessage auth;
    auth.domain = cfg.domain;
    auth.user = cfg.user_name;
    auth.workstation.clear();
    auth.lm_response = std::move(computed.lm_response);
    auth.nt_response = std::move(computed.nt_response);
    auth.encrypted_random_session_key.clear();
    // HTTP NTLM needs no MIC / session key exchange; echoing the challenge's
    // flags keeps the negotiation honest.
    auth.flags = chg.flags;
    auth.mic_is_set = false;
    return auth.Encode(out).ok();
}

std::string GatewayAuthority(const RdgspTransport::Config& cfg) {
    return cfg.host + ":" + std::to_string(cfg.port);
}

}  // namespace

RdgspTransport::RdgspTransport(const Config& config) : config_(config) {}

void RdgspTransport::Fail(const std::string& reason, uint32_t hr) {
    error_ = reason;
    hresult_ = hr;
}

int RdgspTransport::SendAndReadResponse(Transport& t,
                                        const std::vector<uint8_t>& request,
                                        int timeout_ms,
                                        proto::HttpMessage& response,
                                        std::vector<uint8_t>& leftover) {
    leftover.clear();
    if (request.empty()) {
        // D-A1/D-A4: the builder rejected a configured value (CRLF / NUL).
        // Distinguishable from "empty but valid": the caller reports this as a
        // misconfiguration, never as a timeout / too-many-reads.
        Fail("RDGSP request rejected by builder (CRLF/NUL in a header value)",
             0);
        return -1;
    }
    if (!t.Write(request.data(), request.size())) {
        Fail("failed to write the RDGSP request", 0);
        return -1;
    }
    std::vector<uint8_t> buffer;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    // The head is bounded by the parser ceiling plus one read of slack, so a
    // peer cannot make us buffer without limit while we wait.
    const size_t buffer_limit =
        proto::kMaxHttpHeaderBytes + 4096;
    for (;;) {
        size_t consumed = 0;
        const proto::Status st =
            proto::HttpMessage::parse(buffer.data(), buffer.size(), response,
                                      consumed);
        if (st == proto::Status::Ok) {
            if (consumed < buffer.size()) {
                leftover.assign(
                    buffer.begin() + static_cast<std::ptrdiff_t>(consumed),
                    buffer.end());
            }
            return response.status_code;
        }
        if (st != proto::Status::NeedMoreData) {
            Fail("malformed RDGSP response", 0);
            return -1;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            Fail("RDGSP response timed out", 0);
            return -1;
        }
        uint8_t chunk[4096];
        const int n = t.Read(chunk, sizeof(chunk));
        if (n == kReadTimeout) continue;  // the deadline above is the exit
        if (n <= 0) {
            Fail("RDGSP connection closed before the response head", 0);
            return -1;
        }
        if (buffer.size() > buffer_limit ||
            n > static_cast<int>(buffer_limit - buffer.size())) {
            Fail("RDGSP response head exceeded a size limit", 0);
            return -1;
        }
        buffer.insert(buffer.end(), chunk, chunk + n);
    }
}

bool RdgspTransport::HandleChallenge(const proto::HttpMessage& response,
                                     std::string& authorization) {
    std::vector<proto::RdgAuthChallenge> challenges;
    if (proto::ParseWwwAuthenticateHeaders(response, challenges) !=
        proto::Status::Ok) {
        Fail("gateway HTTP 401 carried no WWW-Authenticate challenge", 0);
        return false;
    }
    const bool ntlm_allowed = config_.auth_scheme != RdgspTransport::AuthScheme::kBasic;
    const bool basic_allowed =
        config_.auth_scheme != RdgspTransport::AuthScheme::kUnsupported;
    bool saw_ntlm = false;
    bool saw_basic = false;
    const proto::RdgAuthChallenge* chosen = nullptr;
    for (const auto& c : challenges) {
        if (c.scheme == "NTLM") {
            saw_ntlm = true;
            if (ntlm_allowed && chosen == nullptr) chosen = &c;
        } else if (c.scheme == "Basic") {
            saw_basic = true;
            if (basic_allowed && chosen == nullptr) chosen = &c;
        }
    }
    if (chosen == nullptr) {
        if (saw_ntlm || saw_basic) {
            Fail("server offered only a disabled authentication scheme", 0);
        } else {
            // Negotiate / other schemes are not implemented in this batch:
            // explicit failure, never a silent skip (design stage-2 section 3).
            Fail("unsupported authentication scheme", 0x80004001);
        }
        return false;
    }
    const proto::RdgAuthChallenge& c = *chosen;
    if (c.scheme == "Basic") {
        const std::string raw = config_.user_name + ":" + config_.password;
        authorization = "Basic " + proto::EncodeBase64(raw);
        return true;
    }
    if (c.scheme == "NTLM") {
        if (c.token.empty()) {
            // First 401: server asked for the client's NEGOTIATE (type 1).
            credssp::NegotiateMessage neg;
            std::vector<uint8_t> raw;
            const credssp::Error e = neg.Encode(raw);
            if (!e.ok()) {
                Fail("NTLM type-1 encode failed: " + e.message, 0);
                return false;
            }
            authorization = "NTLM " + proto::EncodeBase64(AsString(raw));
            return true;
        }
        // Second 401: carries the base64 CHALLENGE (type 2); answer with
        // AUTHENTICATE (type 3).
        std::vector<uint8_t> token;
        if (!DecodeBase64(c.token, token)) {
            Fail("malformed NTLM base64 token", 0);
            return false;
        }
        credssp::ChallengeMessage chg;
        const credssp::Error e = chg.Decode(token.data(), token.size());
        if (!e.ok()) {
            Fail("malformed NTLM type-2 challenge: " + e.message, 0);
            return false;
        }
        std::string why;
        std::vector<uint8_t> type3;
        if (!BuildNtlmType3(chg, config_, type3, why)) {
            Fail(why, 0);
            return false;
        }
        authorization = "NTLM " + proto::EncodeBase64(AsString(type3));
        return true;
    }
    Fail("unexpected challenge scheme", 0);
    return false;
}

bool RdgspTransport::EstablishOutChannel(std::string& error) {
    if (config_.auth_scheme == RdgspTransport::AuthScheme::kUnsupported) {
        Fail("unsupported authentication scheme", 0x80004001);
        error = error_;
        return false;
    }
    std::string authorization;
    const std::string authority = GatewayAuthority(config_);
    for (int attempt = 0;; ++attempt) {
        proto::RdgChannelRequestOptions o;
        o.method = proto::kRdgOutData;
        o.direction = proto::RdgChannelDirection::kOut;
        o.gateway_host = authority;
        o.connection_id = config_.connection_id;
        o.user_agent = config_.user_agent;
        o.authorization = authorization;
        // The OUT channel asks for an RFC 6455 upgrade; a 200 means the gateway
        // did not support it and the body stays chunked/plain. The exact
        // upgrade headers are UNVERIFIED (the factory delegates to WinHTTP).
        o.request_websocket_upgrade = true;

        proto::HttpMessage response;
        std::vector<uint8_t> leftover;
        const int st =
            SendAndReadResponse(*out_,
                                proto::BuildRdgChannelRequest(o),
                                config_.deadlines.response_ms, response,
                                leftover);
        if (st < 0) {
            error = error_;
            return false;
        }
        out_response_ = response;
        leftover_ = leftover;

        if (st == 200) {
            mode_ = Mode::kChunked;
            out_plain_ = !proto::IsChunkedBody(response);
            return true;
        }
        if (st == 101) {
            // Evidence: OUT only; state switches to raw duplex frames.
            mode_ = Mode::kUpgraded;
            out_plain_ = false;
            return true;
        }
        if (st != 401) {
            const uint32_t hr = proto::MapGatewayStatusToHresult(st, false);
            Fail("RDGSP OUT channel failed (HTTP " + std::to_string(st) + ")",
                 hr);
            error = error_;
            return false;
        }
        if (attempt >= config_.max_auth_retries) {
            Fail("RDGSP OUT authentication retries exceeded (HTTP 401)",
                 0x80070005);
            error = error_;
            return false;
        }
        ++auth_retry_count_;
        if (!HandleChallenge(response, authorization)) {
            error = error_;
            return false;
        }
        last_authorization_ = authorization;
    }
}

bool RdgspTransport::EstablishInChannel(std::string& error) {
    const std::string authority = GatewayAuthority(config_);
    const std::string authorization = last_authorization_;
    for (int attempt = 0;; ++attempt) {
        proto::RdgChannelRequestOptions o;
        o.method = proto::kRdgInData;
        o.direction = proto::RdgChannelDirection::kIn;
        o.gateway_host = authority;
        o.connection_id = config_.connection_id;
        o.user_agent = config_.user_agent;
        o.authorization = authorization;
        o.retry_count = in_retry_count_;

        proto::HttpMessage response;
        std::vector<uint8_t> leftover;
        const int st =
            SendAndReadResponse(*in_, proto::BuildRdgChannelRequest(o),
                                config_.deadlines.response_ms, response,
                                leftover);
        if (st < 0) {
            error = error_;
            return false;
        }
        if (st == 101) {
            // Evidence FUN_1801bfd60:158-170 -- a WebSocket upgrade must only
            // ever happen on the OUT channel.
            Fail("Server returned switch protocols for IN channel",
                 0x80190000u | 101u);
            error = error_;
            return false;
        }
        if (st == 200) return true;
        if (st != 401) {
            const uint32_t hr = proto::MapGatewayStatusToHresult(st, false);
            Fail("RDGSP IN channel failed (HTTP " + std::to_string(st) + ")",
                 hr);
            error = error_;
            return false;
        }
        if (attempt >= config_.max_auth_retries) {
            Fail("RDGSP IN authentication retries exceeded (HTTP 401)",
                 0x80070005);
            error = error_;
            return false;
        }
        ++in_retry_count_;
    }
}

bool RdgspTransport::Connect(std::string& error) {
    if (connected_) return true;
    error_.clear();
    hresult_ = 0;
    auth_retry_count_ = 0;
    in_retry_count_ = 0;
    mode_ = Mode::kChunked;
    out_plain_ = false;
    leftover_.clear();
    read_buffer_.clear();
    pending_frames_.clear();
    pending_frame_index_ = 0;

    const auto connect_channel = [this](const Config::Connector& connector,
                                        const char* which,
                                        std::unique_ptr<Transport>& slot,
                                        std::string& err) {
        if (connector) {
            slot = connector(err);
        } else {
            slot = ConnectTcp(config_.host, config_.port, err);
        }
        if (!slot) {
            err = std::string(which) + " channel connect failed: " + err;
            return false;
        }
        return true;
    };

    // H0: both connections are established independently.
    if (!connect_channel(config_.connect_out, "OUT", out_, error)) return false;
    if (!connect_channel(config_.connect_in, "IN", in_, error)) return false;

    if (!EstablishOutChannel(error)) return false;
    if (!EstablishInChannel(error)) return false;

    connected_ = true;
    error.clear();
    return true;
}

int RdgspTransport::ReadChunked(uint8_t* buf, size_t size) {
    // A configured session may be idle for long stretches: no data -> the
    // inner transport's bounded wait gives kReadTimeout, which is NOT a
    // disconnect, exactly like the other transports in this stack.
    if (out_plain_) {
        if (!read_buffer_.empty()) {
            const size_t n = (std::min)(size, read_buffer_.size());
            std::memcpy(buf, read_buffer_.data(), n);
            read_buffer_.erase(read_buffer_.begin(),
                               read_buffer_.begin() +
                                   static_cast<std::ptrdiff_t>(n));
            return static_cast<int>(n);
        }
        if (!leftover_.empty()) {
            const size_t n = (std::min)(size, leftover_.size());
            std::memcpy(buf, leftover_.data(), n);
            leftover_.erase(leftover_.begin(),
                            leftover_.begin() + static_cast<std::ptrdiff_t>(n));
            return static_cast<int>(n);
        }
        const int n = out_->Read(buf, size);
        if (n == kReadTimeout || n > 0) return n;
        if (n == 0) return 0;
        Fail("RDGSP OUT read failed", 0);
        return -1;
    }

    if (!leftover_.empty()) {
        const std::vector<uint8_t> first = std::move(leftover_);
        leftover_.clear();
        std::vector<uint8_t> decoded =
            chunked_decoder_.Feed(first.data(), first.size());
        if (chunked_decoder_.failed()) {
            Fail("RDGSP chunked body failed to decode", 0);
            return -1;
        }
        read_buffer_.insert(read_buffer_.end(), decoded.begin(), decoded.end());
    }
    for (;;) {
        if (!read_buffer_.empty()) {
            const size_t n = (std::min)(size, read_buffer_.size());
            std::memcpy(buf, read_buffer_.data(), n);
            read_buffer_.erase(read_buffer_.begin(),
                               read_buffer_.begin() +
                                   static_cast<std::ptrdiff_t>(n));
            return static_cast<int>(n);
        }
        uint8_t chunk[16384];
        const int n = out_->Read(chunk, sizeof(chunk));
        if (n == kReadTimeout) return kReadTimeout;
        if (n <= 0) {
            chunked_decoder_.EndOfStream();
            if (chunked_decoder_.failed()) {
                Fail("RDGSP chunked body was truncated", 0);
                return -1;
            }
            return 0;  // orderly end of the response body
        }
        const std::vector<uint8_t> decoded =
            chunked_decoder_.Feed(chunk, static_cast<size_t>(n));
        if (chunked_decoder_.failed()) {
            Fail("RDGSP chunked body failed to decode", 0);
            return -1;
        }
        read_buffer_.insert(read_buffer_.end(), decoded.begin(), decoded.end());
    }
}

void RdgspTransport::ExtendFrames(
    const std::vector<proto::WebSocketFrame>& frames) {
    for (const auto& f : frames) {
        // Only data frames carry RDP bytes. Ping/pong/close are consumed here
        // as control frames and NOT surfaced (the keepalive reply is UNVERIFIED
        // / a follow-up against a real gateway).
        if (f.opcode == proto::WebSocketOpcode::kContinuation ||
            f.opcode == proto::WebSocketOpcode::kText ||
            f.opcode == proto::WebSocketOpcode::kBinary) {
            pending_frames_.push_back(f);
        }
    }
}

int RdgspTransport::ReadUpgraded(uint8_t* buf, size_t size) {
    if (!leftover_.empty()) {
        const std::vector<uint8_t> first = std::move(leftover_);
        leftover_.clear();
        const std::vector<proto::WebSocketFrame> frames =
            websocket_decoder_.Feed(first.data(), first.size());
        if (websocket_decoder_.failed()) {
            Fail("RDGSP WebSocket frame failed to decode", 0);
            return -1;
        }
        ExtendFrames(frames);
    }
    for (;;) {
        // Deliver a queued data frame's payload before touching the network.
        while (pending_frame_index_ < pending_frames_.size()) {
            const auto& payload = pending_frames_[pending_frame_index_].payload;
            if (!payload.empty()) {
                const size_t n = (std::min)(size, payload.size());
                std::memcpy(buf, payload.data(), n);
                // Keep the remainder for the next Read().
                if (n < payload.size()) {
                    pending_frames_[pending_frame_index_].payload.erase(
                        pending_frames_[pending_frame_index_].payload.begin(),
                        pending_frames_[pending_frame_index_].payload.begin() +
                            static_cast<std::ptrdiff_t>(n));
                } else {
                    ++pending_frame_index_;
                }
                return static_cast<int>(n);
            }
            ++pending_frame_index_;
        }
        if (pending_frame_index_ == pending_frames_.size()) {
            pending_frames_.clear();
            pending_frame_index_ = 0;
        }
        uint8_t chunk[16384];
        const int n = out_->Read(chunk, sizeof(chunk));
        if (n == kReadTimeout) return kReadTimeout;
        if (n <= 0) {
            websocket_decoder_.EndOfStream();
            if (websocket_decoder_.failed()) {
                Fail("RDGSP WebSocket stream was truncated", 0);
                return -1;
            }
            return 0;
        }
        const std::vector<proto::WebSocketFrame> frames =
            websocket_decoder_.Feed(chunk, static_cast<size_t>(n));
        if (websocket_decoder_.failed()) {
            Fail("RDGSP WebSocket frame failed to decode", 0);
            return -1;
        }
        ExtendFrames(frames);
    }
}

int RdgspTransport::Read(uint8_t* buf, size_t size) {
    if (closed_ || !connected_) return -1;
    if (buf == nullptr || size == 0) return 0;
    return upgraded() ? ReadUpgraded(buf, size) : ReadChunked(buf, size);
}

bool RdgspTransport::Write(const uint8_t* data, size_t size) {
    if (closed_ || !connected_) return false;
    if (data == nullptr || size == 0) return true;
    if (mode_ == Mode::kChunked) {
        size_t off = 0;
        while (off < size) {
            const size_t n =
                (std::min)(size_t{proto::kMaxChunkedChunkBytes}, size - off);
            const std::vector<uint8_t> encoded =
                proto::ChunkedEncodeChunk(data + off, n);
            if (!in_->Write(encoded.data(), encoded.size())) {
                Fail("RDGSP IN channel write failed", 0);
                return false;
            }
            off += n;
        }
        return true;
    }
    // Upgraded: the write side moves to OUT unless configured not to (the "IN
    // still carries management data after upgrade" fallback, UNVERIFIED).
    Transport& t = config_.upgrade_steals_write ? *out_ : *in_;
    size_t off = 0;
    while (off < size) {
        const size_t n =
            (std::min)(static_cast<size_t>(proto::kMaxWebSocketPayloadBytes),
                       size - off);
        // RFC 6455 5.3: every client frame carries its own freshly generated
        // mask key; reusing one key across frames is a protocol violation.
        uint8_t keyb[4] = {};
        if (!crypto::RandomBytes(keyb, sizeof(keyb))) {
            Fail("CSPRNG failure while masking the WebSocket frame", 0);
            return false;
        }
        const uint32_t mask = static_cast<uint32_t>(keyb[0]) |
                              (static_cast<uint32_t>(keyb[1]) << 8) |
                              (static_cast<uint32_t>(keyb[2]) << 16) |
                              (static_cast<uint32_t>(keyb[3]) << 24);
        const std::vector<uint8_t> frame = proto::WebSocketEncodeClientFrame(
            proto::WebSocketOpcode::kBinary, data + off, n, mask);
        if (!t.Write(frame.data(), frame.size())) {
            Fail("RDGSP upgraded channel write failed", 0);
            return false;
        }
        off += n;
    }
    return true;
}

void RdgspTransport::Close() {
    if (closed_) return;
    closed_ = true;
    if (out_) out_->Close();
    if (in_) in_->Close();
}

}  // namespace rtsc::net
