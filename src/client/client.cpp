// End-to-end RDP client implementation.

#include "rtsc/client/client.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "rtsc/proto/input.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/output.h"

namespace rtsc::client {

namespace {

constexpr size_t kReadChunk = 16384;

// The statistics window: a frame rate and a bandwidth over the last second.
constexpr auto kStatWindow = std::chrono::seconds(1);

}  // namespace

Client::Client(security::ConnectionDriver driver, uint16_t width, uint16_t height)
    : driver_(std::move(driver)), graphics_(width, height) {
    driver_.SetSessionPduHandler(
        [this](const std::vector<uint8_t>& pdu) { OnSessionPdu(pdu); });
    activity_id_ = GenerateActivityId();
}

void Client::NoteFrame() {
    const Clock::time_point now = Clock::now();
    frame_times_.push_back(now);
    while (frame_times_.size() > 1 &&
           now - frame_times_.front() >= kStatWindow) {
        frame_times_.pop_front();
    }
}

double Client::frames_per_second() const noexcept {
    if (frame_times_.size() < 2) return 0.0;
    const double secs =
        std::chrono::duration<double>(frame_times_.back() - frame_times_.front())
            .count();
    if (!(secs > 0.0)) return 0.0;
    return static_cast<double>(frame_times_.size() - 1) / secs;
}

void Client::NoteInputSent() {
    last_input_send_ = Clock::now();
    has_input_pending_ = true;
}

void Client::NoteInboundData(size_t bytes) {
    const Clock::time_point now = Clock::now();
    // The round-trip closes on the first inbound data after an input write.
    if (has_input_pending_) {
        rtt_ms_ = std::chrono::duration<double, std::milli>(now - last_input_send_)
                      .count();
        has_rtt_ = true;
        has_input_pending_ = false;
    }
    inbound_bytes_.push_back({now, bytes});
    while (inbound_bytes_.size() > 1 &&
           now - inbound_bytes_.front().first >= kStatWindow) {
        inbound_bytes_.pop_front();
    }
}

double Client::bandwidth_mbps() const noexcept {
    if (inbound_bytes_.size() < 2) return 0.0;
    size_t total = 0;
    for (const auto& e : inbound_bytes_) total += e.second;
    const double secs =
        std::chrono::duration<double>(inbound_bytes_.back().first -
                                      inbound_bytes_.front().first)
            .count();
    if (!(secs > 0.0)) return 0.0;
    return static_cast<double>(total) * 8.0 / secs / 1.0e6;
}

void Client::OnSessionPdu(const std::vector<uint8_t>& pdu) {
    if (pdu.empty()) return;

    // Fast-path PDUs start with a byte whose low two bits are the action.
    if ((pdu[0] & 0x03) == 0x00) {
        proto::FastPathOutputPdu fp;
        if (proto::FastPathOutputPdu::parse(pdu.data(), pdu.size(), fp) ==
            proto::Status::Ok) {
            graphics_.ApplyFastPathOutput(fp);
        }
        return;
    }

    // Slow-path: TPKT / X.224 / MCS / share data header.
    proto::McsSendData sd;
    if (proto::McsSendData::parse(pdu.data(), pdu.size(), sd) !=
        proto::Status::Ok) {
        return;
    }
    proto::SlowPathGraphicsUpdate upd;
    const proto::Status pst = proto::SlowPathGraphicsUpdate::parse(
        sd.user_data.data(), sd.user_data.size(), upd);
    if (pst == proto::Status::Ok) {
        graphics_.ApplySlowPathUpdate(upd);
    }
}

bool Client::Connect(net::Transport& transport, std::string& error) {
    const auto start = driver_.Start();
    if (!start.to_send.empty() &&
        !transport.Write(start.to_send.data(), start.to_send.size())) {
        error = "failed to send the X.224 Connection Request";
        return false;
    }
    if (start.failed) {
        error = start.error;
        return false;
    }

    uint8_t buf[kReadChunk];
    // A bounded handshake: a silent peer costs a bounded-wait timeout, not a
    // failed connect, so the loop only gives up on a wall-clock deadline.
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (!driver_.session_active()) {
        const int n = transport.Read(buf, sizeof(buf));
        if (n == net::kReadTimeout) {
            if (std::chrono::steady_clock::now() >= deadline) break;
            continue;
        }
        if (n <= 0) {
            error = "peer closed or read error during connect";
            return false;
        }
        NoteInboundData(static_cast<size_t>(n));
        const auto step = driver_.OnData(buf, static_cast<size_t>(n));
        if (step.failed) {
            error = step.error;
            return false;
        }
        if (!step.to_send.empty() &&
            !transport.Write(step.to_send.data(), step.to_send.size())) {
            error = "write failed during connect";
            return false;
        }
        if (step.active) return true;
    }
    error = "connection did not reach the active session";
    return false;
}

bool Client::Pump(net::Transport& transport, std::string& error) {
    uint8_t buf[kReadChunk];
    const int n = transport.Read(buf, sizeof(buf));
    if (n == net::kReadTimeout) {
        // The peer is silent. This is the normal idle case, not a disconnect:
        // keep the session alive and let the caller carry on pumping window
        // messages. Treating it as an error would end the session the moment
        // the server went quiet (and, before the bounded wait existed, froze
        // the window for the whole socket timeout).
        return true;
    }
    if (n <= 0) {
        error = "peer closed or read error";
        return false;
    }
    NoteInboundData(static_cast<size_t>(n));
    const auto step = driver_.OnData(buf, static_cast<size_t>(n));
    if (step.failed) {
        error = step.error;
        return false;
    }
    if (!step.to_send.empty() &&
        !transport.Write(step.to_send.data(), step.to_send.size())) {
        error = "write failed";
        return false;
    }
    return true;
}

std::vector<uint8_t> Client::EncodeInput(const ui::InputEvent& ev) const {
    using proto::EncodeFastPathInputPdu;
    using proto::EncodeKeyboardEvent;
    using proto::EncodeMouseEvent;
    using proto::EncodeRelativeMouseEvent;
    using proto::EncodeSyncEvent;

    switch (ev.kind) {
        case ui::InputEvent::Kind::kKey:
            return EncodeFastPathInputPdu(
                {EncodeKeyboardEvent(ev.scancode, ev.key_release,
                                     ev.key_extended)});
        case ui::InputEvent::Kind::kMouseMove:
            return EncodeFastPathInputPdu(
                {EncodeMouseEvent(proto::kPtrMove, ev.x, ev.y)});
        case ui::InputEvent::Kind::kMouseButton: {
            uint16_t flags = 0;
            if (ev.button == 1) flags |= proto::kPtrButton1;
            if (ev.button == 2) flags |= proto::kPtrButton2;
            if (ev.button == 3) flags |= proto::kPtrButton3;
            if (ev.button_down) flags |= proto::kPtrDown;
            return EncodeFastPathInputPdu({EncodeMouseEvent(flags, ev.x, ev.y)});
        }
        case ui::InputEvent::Kind::kMouseWheel: {
            uint16_t flags = proto::kPtrWheel;
            const int16_t delta = ev.wheel_delta;
            const int16_t magnitude =
                static_cast<int16_t>(delta < 0 ? -delta : delta);
            if (delta < 0) flags |= proto::kPtrWheelNegative;
            flags |= static_cast<uint16_t>(
                magnitude & proto::kPtrWheelRotationMask);
            return EncodeFastPathInputPdu({EncodeMouseEvent(flags, ev.x, ev.y)});
        }
        case ui::InputEvent::Kind::kClose:
        case ui::InputEvent::Kind::kNone:
        default:
            return {};
    }
}

std::vector<uint8_t> Client::EncodeCtrlAltDel() const {
    return proto::EncodeFastPathInputPdu(proto::EncodeCtrlAltDel());
}

bool Client::SendPdu(net::Transport& transport,
                     const std::vector<uint8_t>& pdu, std::string& error) {
    if (pdu.empty()) return true;
    // Post-active input is application data on the secured transport. Under
    // TLS the driver's security layer wraps it; under Standard RDP Security
    // the driver puts it inside an MCS Send Data Request and applies RC4.
    const auto wire = driver_.SendApplicationPdu(pdu);
    if (wire.empty()) return true;
    if (!transport.Write(wire.data(), wire.size())) {
        error = "input write failed";
        return false;
    }
    return true;
}

bool Client::SendCtrlAltDel(net::Transport& transport, std::string& error) {
    return SendPdu(transport, EncodeCtrlAltDel(), error);
}

}  // namespace rtsc::client
