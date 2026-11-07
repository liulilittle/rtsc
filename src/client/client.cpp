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

// One wheel notch is WHEEL_DELTA = 120 rotation units on the wire
// ([MS-RDPBCGR] 2.2.8.1.1.3.1.1.1 "Number of rotation units"); the UI layer
// reports notches instead (ui::InputEvent::wheel_delta).
constexpr int kWheelUnitsPerNotch = 120;

// The rotation field is 9 bits two's complement, so the range it can carry is
// -256..+255: PTRFLAGS_WHEEL_NEGATIVE (0x0100) is the field's sign bit, which
// makes 0x0300 mean -256. The splitter below advances in symmetric steps of 255
// so both directions are identical; that leaves the single -256 code point
// unused, which is harmless (a notch is 120 units, so -256 is not reachable
// anyway). 255 is therefore the step size, NOT "the whole range".
constexpr int kWheelStep = 255;

// A single UI wheel event is expanded to at most this many wire events
// (8 * 255 units = 2,040 units = 17 notches). The cap bounds what a garbage or
// hostile wheel_delta can amplify into; a real wheel cannot scroll 17 notches
// in one event. The excess rotation is DROPPED -- not folded or clamped into a
// remaining chunk -- and the lost amount is accumulated (in UNITS) in
// dropped_wheel_units_count_ so that the truncation is observable rather than
// silent.
constexpr int kMaxWheelChunksPerEvent = 8;

// The statistics window: a frame rate and a bandwidth over the last second.
constexpr auto kStatWindow = std::chrono::seconds(1);

}  // namespace

Client::Client(security::ConnectionDriver driver, uint16_t width, uint16_t height)
    : driver_(std::move(driver)), graphics_(width, height) {
    driver_.SetSessionPduHandler(
        [this](const std::vector<uint8_t>& pdu) { OnSessionPdu(pdu); });
    activity_id_ = GenerateActivityId();
}

uint16_t Client::StartRailChannel(uint32_t build_number, uint32_t client_flags) {
    const uint16_t id = driver_.ChannelIdForName(proto::kRailChannelName);
    if (id == 0) return 0;
    rail_channel_id_ = id;
    driver_.SetChannelHandler(
        id, [this](const uint8_t* data, size_t size) { rail_.OnChannelData(data, size); });
    rail_.Start(build_number, client_flags);
    return id;
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

bool Client::Reconnect(net::Transport& transport, std::string& error) {
    // Rebuild the ARC_CS_PRIVATE_PACKET ([MS-RDPBCGR] 2.2.1.11.1.1.1) from the
    // server's ARC_SC_PRIVATE_PACKET before the session state is dropped.
    std::vector<uint8_t> cookie;
    const auto& logon = driver_.logon_info();
    if (logon.has_auto_reconnect_cookie &&
        logon.auto_reconnect_random.size() == 16) {
        cookie.reserve(28);
        const auto put32 = [&cookie](uint32_t v) {
            cookie.push_back(static_cast<uint8_t>(v & 0xFF));
            cookie.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
            cookie.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
            cookie.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        };
        put32(28);  // cbLen
        put32(logon.auto_reconnect_version);
        put32(logon.auto_reconnect_logon_id);
        cookie.insert(cookie.end(), logon.auto_reconnect_random.begin(),
                      logon.auto_reconnect_random.end());
    }
    driver_.ResetForReconnect(std::move(cookie));
    return Connect(transport, error);
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
    // Deactivation-Reactivation ([MS-RDPBCGR] 1.3.1.3): the replayed Demand
    // Active can grant a different desktop size, and the graphics surface must
    // follow it or every later frame is decoded into a stale-sized bitmap.
    if (step.active) {
        const uint16_t w = driver_.desktop_width();
        const uint16_t h = driver_.desktop_height();
        if (w != 0 && h != 0 &&
            (w != graphics_.surface().width() ||
             h != graphics_.surface().height())) {
            graphics_.Resize(w, h);
        }
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
        case ui::InputEvent::Kind::kUnicode:
            // TS_FP_UNICODE_KEYBOARD_EVENT ([MS-RDPBCGR] 2.2.8.1.2.2.2): the
            // server maps the code point through the session keyboard layout,
            // so this is the only way to type a character the client's own
            // layout has no scancode for. One event per UTF-16 code unit.
            return EncodeFastPathInputPdu(
                {proto::EncodeUnicodeEvent(ev.unicode_code, ev.key_release)});
        case ui::InputEvent::Kind::kMouseMove:
            return EncodeFastPathInputPdu(
                {EncodeMouseEvent(proto::kPtrMove, ev.x, ev.y)});
        case ui::InputEvent::Kind::kMouseButton: {
            uint16_t flags = 0;
            if (ev.button == 1) flags |= proto::kPtrButton1;
            if (ev.button == 2) flags |= proto::kPtrButton2;
            if (ev.button == 3) flags |= proto::kPtrButton3;
            // A MOUSEX event (eventCode 2) carries PTRXFLAGS, not PTRFLAGS:
            // X1/X2 are PTRXFLAGS_BUTTON1/2 = 0x0001/0x0002 ([MS-RDPBCGR]
            // 2.2.8.1.1.3.1.1.4). The 0x1000/0x2000 PTRFLAGS bits belong to the
            // plain POINTER event, where they are the left/right buttons; using
            // them on X events aliased X1 on the left button on the server.
            const bool extended = (ev.button == 4 || ev.button == 5);
            if (ev.button == 4) flags |= proto::kPtrXButton1;
            if (ev.button == 5) flags |= proto::kPtrXButton2;
            if (ev.button_down) flags |= proto::kPtrDown;
            return EncodeFastPathInputPdu(
                {EncodeMouseEvent(flags, ev.x, ev.y, extended)});
        }
        case ui::InputEvent::Kind::kMouseWheel: {
            // [MS-RDPBCGR] 2.2.8.1.1.3.1.1.1: PTRFLAGS_HWHEEL MUST NOT be sent
            // to a server that did not indicate support in its Input
            // Capability Set. A vertical wheel is an ordinary MOUSE event and
            // is never gated. Dropping the event is the correct behaviour
            // (disconnecting over one unsupported axis would be far worse than
            // degrading it to vertical-only), but it must not be silent, hence
            // the monotonic counter.
            if (ev.horizontal && !driver_.server_supports_hwheel()) {
                ++dropped_hwheel_count_;
                return {};
            }
            // The UI layer reports notches; the wire carries WHEEL_DELTA (120)
            // rotation units per notch. FreeRDP PR #6806 fixed the old
            // "positive value plus negative flag" encoding (the server saw 136
            // instead of 120). PTRFLAGS_WHEEL_NEGATIVE (0x0100) is the sign bit
            // OF the 9-bit two's-complement WheelRotationMask field, so the
            // masked value must be sent as-is and the bit must not be OR'ed in
            // separately (that made -1 look like 0x0301 = -257, not -120).
            //
            // One UI event can exceed that field (3 notches = 360 units, field
            // -256..+255), so it is split into chunks of at most 255 units in
            // the SAME Fast-Path PDU. All chunks carry the sign of the original
            // delta and are emitted largest magnitude first (a fixed order, so
            // the byte stream is deterministic). Up to the cap below, the sum
            // of the chunks is the source rotation. The cap is 8 chunks =
            // 2,040 units = 17 notches; any rotation beyond it is DROPPED (no
            // partial remainder is folded into the last chunk, so every wire
            // value stays an exact 255-unit step) and the discarded UNITS are
            // added to dropped_wheel_units_count_. This is a deliberate bound
            // on a hostile delta, but the loss is counted, not silent.
            const int64_t units =
                static_cast<int64_t>(ev.wheel_delta) * kWheelUnitsPerNotch;
            const int64_t magnitude = units < 0 ? -units : units;
            int64_t chunks = magnitude / kWheelStep;
            if (magnitude % kWheelStep != 0) ++chunks;
            if (chunks == 0) chunks = 1;  // a zero delta stays one no-op event
            if (chunks > kMaxWheelChunksPerEvent) {
                chunks = kMaxWheelChunksPerEvent;
            }
            std::vector<std::vector<uint8_t>> events;
            events.reserve(static_cast<size_t>(chunks));
            int64_t remaining = magnitude;
            for (int64_t i = 0; i < chunks; ++i) {
                const int64_t part =
                    remaining < kWheelStep ? remaining : kWheelStep;
                remaining -= part;
                const int64_t rotation = units < 0 ? -part : part;
                uint16_t flags =
                    ev.horizontal ? proto::kPtrHwheel : proto::kPtrWheel;
                flags |= static_cast<uint16_t>(
                    rotation & proto::kPtrWheelRotationMask);
                events.push_back(EncodeMouseEvent(flags, ev.x, ev.y));
            }
            // `remaining` is the part of |units| that did not fit in the cap:
            // count the rotation UNITS that never reach the server. Zero when
            // the delta fits (including the exact 17-notch boundary).
            if (remaining > 0) {
                dropped_wheel_units_count_ += static_cast<size_t>(remaining);
            }
            return EncodeFastPathInputPdu(events);
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

bool Client::SendInput(net::Transport& transport, const ui::InputEvent& ev,
                       std::string& error, bool* encoded) {
    const std::vector<uint8_t> pdu = EncodeInput(ev);
    if (encoded != nullptr) *encoded = !pdu.empty();
    return SendPdu(transport, pdu, error);
}

bool Client::SendChannelPdu(net::Transport& transport, uint16_t channel_id,
                            const std::vector<uint8_t>& pdu,
                            std::string& error) {
    if (pdu.empty()) return true;
    const auto wire = driver_.SendChannelPdu(channel_id, pdu);
    if (wire.empty()) return true;
    if (!transport.Write(wire.data(), wire.size())) {
        error = "channel write failed";
        return false;
    }
    return true;
}

bool Client::SendCtrlAltDel(net::Transport& transport, std::string& error) {
    return SendPdu(transport, EncodeCtrlAltDel(), error);
}

bool Client::SendPauseKey(net::Transport& transport, std::string& error) {
    return SendPdu(
        transport, proto::EncodeFastPathInputPdu(proto::EncodePauseKey()), error);
}

}  // namespace rtsc::client
