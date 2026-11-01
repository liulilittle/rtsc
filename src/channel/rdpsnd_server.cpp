// Server-side rdpsnd (audio output) handler ([MS-RDPEA] 3.2.6).

#include "rtsc/channel/rdpsnd_server.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <utility>

namespace rtsc::channel {

namespace {

using rtsc::proto::Status;

// The in-flight window: at most 8 audio blocks may be waiting for a Wave
// Confirm (~160 ms at 20 ms per block), bounded so a silent client cannot make
// the server accumulate unbounded audio data (design 7.1, FP3).
constexpr size_t kMaxInFlight = 8;
// One block per 20 ms, matching the sine source's 20 ms blocks.
constexpr std::chrono::milliseconds kAudioBlockInterval(20);
// The maximum Wave2 body a 16-bit BodySize field can carry is 12 header bytes
// + data, so data alone must stay under 65536 - 12.
constexpr size_t kMaxWave2Data = 65535 - 12;

}  // namespace

const char* RdpsndServer::to_string(Phase p) {
    switch (p) {
        case Phase::kIdle: return "idle";
        case Phase::kAwaitClientFormats: return "await-client-formats";
        case Phase::kAwaitQualityMode: return "await-quality-mode";
        case Phase::kAwaitTrainingConfirm: return "await-training-confirm";
        case Phase::kReady: return "ready";
        case Phase::kClosed: return "closed";
    }
    return "unknown";
}

RdpsndServer::RdpsndServer(
    std::unique_ptr<rtsc::audio::AudioCaptureSource> source, SendFn send,
    std::chrono::milliseconds negotiation_timeout)
    : source_(std::move(source)),
      send_(std::move(send)),
      negotiation_timeout_(negotiation_timeout) {}

RdpsndServer::~RdpsndServer() {
    // source_ is an embedder-supplied capture source, so Stop() is an external
    // virtual call. This destructor must not throw.
    try {
        if (source_ && started_) source_->Stop();
    } catch (...) {
    }
}

void RdpsndServer::Start() {
    if (started_) return;
    if (!source_) return;
    if (!source_->Start()) return;  // capture failed: keep the channel silent
    started_ = true;
    advertised_format_ = FormatFromSource(source_->format());
    SendRdpsnd(rtsc::proto::SndMsgType::kFormats,
               rtsc::proto::BuildClientFormatsBody(
                   rtsc::proto::kSndCapsAlive, 0, 0, 0,
                   rtsc::proto::kSndVersionWin8, {advertised_format_}));
    ++server_formats_count_;
    phase_ = Phase::kAwaitClientFormats;
    negotiation_deadline_ = std::chrono::steady_clock::now() +
                            negotiation_timeout_;
}

void RdpsndServer::OnChannelData(const uint8_t* data, size_t size) {
    if (data == nullptr || size < rtsc::proto::ChannelPduHeader::kSize) {
        ++malformed_pdu_count_;
        return;
    }
    rtsc::proto::ChannelPduHeader header;
    if (rtsc::proto::ChannelPduHeader::parse(data, size, header) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    bool complete = false;
    std::vector<uint8_t> message;
    const Status st = reassembler_.Feed(
        header, data + rtsc::proto::ChannelPduHeader::kSize,
        size - rtsc::proto::ChannelPduHeader::kSize, complete, message);
    if (st != Status::Ok) {
        ++malformed_pdu_count_;
        reassembler_.Reset();
        return;
    }
    if (!complete) return;
    OnMessage(message);
}

void RdpsndServer::OnMessage(const std::vector<uint8_t>& message) {
    size_t offset = 0;
    while (offset + rtsc::proto::SndProlog::kSize <= message.size()) {
        rtsc::proto::SndProlog prolog;
        if (rtsc::proto::SndProlog::parse(message.data() + offset,
                                          message.size() - offset, prolog) !=
            Status::Ok) {
            ++malformed_pdu_count_;
            return;
        }
        // SNDC_WAVE (legacy WaveInfo + Wave continuation) is a server-only PDU;
        // a peer that sends one has nothing this handler can answer, but the
        // length-prefix interpretation does not apply to it either, so it is
        // skipped with the fixed WaveInfo size exactly like the client does.
        if (prolog.msg_type == rtsc::proto::SndMsgType::kWave) {
            offset += rtsc::proto::SndProlog::kSize +
                      rtsc::proto::SndWaveInfo::kFixedSize;
            continue;
        }
        const size_t body_begin = offset + rtsc::proto::SndProlog::kSize;
        if (body_begin + prolog.body_size > message.size()) {
            ++malformed_pdu_count_;
            return;
        }
        const std::vector<uint8_t> body(
            message.begin() + static_cast<std::ptrdiff_t>(body_begin),
            message.begin() + static_cast<std::ptrdiff_t>(body_begin +
                                                          prolog.body_size));
        OnPdu(prolog, body);
        offset = body_begin + prolog.body_size;
    }
}

void RdpsndServer::OnPdu(const rtsc::proto::SndProlog& prolog,
                         const std::vector<uint8_t>& body) {
    switch (prolog.msg_type) {
        case rtsc::proto::SndMsgType::kFormats:
            OnClientFormats(body);
            break;
        case rtsc::proto::SndMsgType::kQualityMode:
            OnQualityMode(body);
            break;
        case rtsc::proto::SndMsgType::kTraining:
            OnTrainingConfirm(body);
            break;
        case rtsc::proto::SndMsgType::kWaveConfirm:
            OnWaveConfirm(body);
            break;
        default:
            // A client-originated message this server does not handle; ignored.
            break;
    }
}

void RdpsndServer::OnClientFormats(const std::vector<uint8_t>& body) {
    if (phase_ != Phase::kAwaitClientFormats) {
        ++out_of_order_count_;
        return;
    }
    rtsc::proto::SndServerFormats formats;
    if (rtsc::proto::SndServerFormats::parse(body, formats) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    ++client_formats_count_;
    client_alive_ = (formats.flags & rtsc::proto::kSndCapsAlive) != 0;
    client_version_ = formats.version;
    // D-E: only an acceptable format list (non-empty, 16-bit PCM 1..2ch from
    // the advertised set) counts as valid. An empty or unplayable answer means
    // the client cannot consume the audio this server produces: record it via
    // format_valid(), release capture and serve permanent silence (kReady, no
    // deadline, never SNDC_CLOSE) so the session stays up as a no-op.
    const bool acceptable = AcceptableFormats(formats);
    format_valid_ = acceptable;

    if (!client_alive_ || !acceptable) {
        // ALIVE=0 (design 7.1 FP2) or an unusable format list (D-E): silent
        // kReady. Capture is released (B2: no idle WASAPI loopback capture),
        // nothing is streamed and the channel is never closed. Stream
        // Poll() in this state returns before touching the source again.
        if (source_) source_->Stop();
        phase_ = Phase::kReady;
        return;
    }

    if (client_version_ >= 6) {
        // Version >= 6: wait for the client's Quality Mode PDU. Per [MS-RDPEA]
        // 2.2.2.3 / 3.2.5.1.1.3 the Quality Mode PDU is client-to-server, so
        // the server MUST NOT send one (D-A); it only waits for it.
        phase_ = Phase::kAwaitQualityMode;
        negotiation_deadline_ =
            std::chrono::steady_clock::now() + negotiation_timeout_;
    } else {
        // A pre-6 peer has no Quality Mode phase; go straight to training.
        SendTrainingPduAndWait(std::chrono::steady_clock::now());
    }
}

void RdpsndServer::OnQualityMode(const std::vector<uint8_t>& body) {
    if (phase_ != Phase::kAwaitQualityMode) {
        ++out_of_order_count_;
        return;
    }
    rtsc::proto::SndQualityModeBody quality;
    if (rtsc::proto::ParseQualityModeBody(body, quality) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    ++quality_mode_count_;
    SendTrainingPduAndWait(std::chrono::steady_clock::now());
}

void RdpsndServer::SendTrainingPduAndWait(
    std::chrono::steady_clock::time_point now) {
    SendRdpsnd(rtsc::proto::SndMsgType::kTraining,
               rtsc::proto::BuildTrainingBody(0, 0));
    ++training_sent_count_;
    phase_ = Phase::kAwaitTrainingConfirm;
    negotiation_deadline_ = now + negotiation_timeout_;
}

bool RdpsndServer::AcceptableFormats(
    const rtsc::proto::SndServerFormats& formats) const {
    // D-E: the client's answer is usable only when it carries at least one
    // playable format this server can produce — 16-bit PCM, 1..2 channels,
    // matching the single advertised format. An empty list (number_of_formats
    // == 0), an 8-bit / non-PCM / out-of-range channel selection and a format
    // outside the advertised set all fail.
    if (formats.formats.empty()) return false;
    for (const auto& f : formats.formats) {
        if (f.format_tag == rtsc::proto::SndAudioFormat::kFormatPcm &&
            f.bits_per_sample == 16 && f.channels >= 1 && f.channels <= 2 &&
            f.samples_per_sec == advertised_format_.samples_per_sec &&
            f.channels == advertised_format_.channels &&
            f.bits_per_sample == advertised_format_.bits_per_sample) {
            return true;
        }
    }
    return false;
}

void RdpsndServer::OnTrainingConfirm(const std::vector<uint8_t>& body) {
    if (phase_ != Phase::kAwaitTrainingConfirm) {
        ++out_of_order_count_;
        return;
    }
    rtsc::proto::SndTraining training;
    if (rtsc::proto::ParseTrainingConfirmBody(body, training) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    ++training_confirm_count_;
    phase_ = Phase::kReady;
}

void RdpsndServer::OnWaveConfirm(const std::vector<uint8_t>& body) {
    rtsc::proto::SndWaveConfirm confirm;
    if (rtsc::proto::ParseWaveConfirmBody(body, confirm) != Status::Ok) {
        ++malformed_pdu_count_;
        return;
    }
    ++wave_confirm_count_;
    const auto it =
        std::find(in_flight_.begin(), in_flight_.end(), confirm.block_no);
    if (it == in_flight_.end()) {
        ++out_of_order_count_;
        return;
    }
    in_flight_.erase(it);
}

void RdpsndServer::Poll(std::chrono::steady_clock::time_point now) {
    // Negotiation deadlines are split by state (D-B): the formats and
    // training-confirm waits are fatal, the quality-mode wait is not. A
    // silent client's missing Quality Mode PDU is replaced by DYNAMIC_QUALITY
    // and the negotiation proceeds to training ([MS-RDPEA] 3.3.5.1.1.3 <19>).
    // Streaming (kReady) never times out; a closed / idle (capture-failed)
    // channel has nothing to do.
    if (phase_ == Phase::kAwaitClientFormats) {
        if (now >= negotiation_deadline_) SendClose();
        return;
    }
    if (phase_ == Phase::kAwaitQualityMode) {
        if (now >= negotiation_deadline_) {
            // Event 6 (spec 3.1.5): "Quality Mode PDU or timeout" -> the
            // missing PDU becomes DYNAMIC_QUALITY and the negotiation proceeds
            // to Training. Non-fatal: no SNDC_CLOSE.
            ++quality_mode_timeout_count_;
            SendTrainingPduAndWait(now);
        }
        return;
    }
    if (phase_ == Phase::kAwaitTrainingConfirm) {
        if (now >= negotiation_deadline_) SendClose();
        return;
    }
    if (phase_ != Phase::kReady) return;

    // ALIVE=0, an unacceptable format answer (D-E) and peers below version 8
    // get no Wave2. In the silent kReady i.e. format_valid()==false the source
    // was already stopped; Poll returns without touching it.
    if (!client_alive_ || !format_valid_ ||
        client_version_ < rtsc::proto::kSndVersionWin8) {
        return;
    }

    // The audio epoch and the pump cadence are anchored to the first Poll
    // after readiness, so the first block carries timeStamp = 0.
    if (!epoch_) epoch_ = now;
    if (!next_audio_due_) next_audio_due_ = now;
    if (now < *next_audio_due_) return;
    *next_audio_due_ = now + kAudioBlockInterval;

    if (in_flight_.size() >= kMaxInFlight) {
        // Full window: the new block is dropped (counted) to keep the old
        // blocks continuous (design 7.1, FP3).
        ++dropped_blocks_;
        return;
    }

    std::vector<uint8_t> pcm;
    if (!source_ || !source_->Poll(pcm) || pcm.empty()) return;
    EmitWave2(pcm, now);
}

void RdpsndServer::SendRdpsnd(rtsc::proto::SndMsgType type,
                              const std::vector<uint8_t>& body) {
    if (!send_) return;
    const std::vector<uint8_t> pdu = rtsc::proto::BuildSndPdu(type, body);
    for (const auto& chunk :
         rtsc::proto::FragmentChannelMessage(pdu)) {
        send_(chunk);
    }
}

void RdpsndServer::SendClose() {
    if (phase_ == Phase::kClosed) return;
    SendRdpsnd(rtsc::proto::SndMsgType::kClose, {});
    ++close_sent_count_;
    if (source_) source_->Stop();
    phase_ = Phase::kClosed;
    in_flight_.clear();
}

void RdpsndServer::EmitWave2(const std::vector<uint8_t>& data,
                             std::chrono::steady_clock::time_point now) {
    const uint64_t elapsed_ms = static_cast<uint64_t>(std::max<int64_t>(
        0, std::chrono::duration_cast<std::chrono::milliseconds>(now - *epoch_)
               .count()));
    const uint16_t time_stamp =
        static_cast<uint16_t>(elapsed_ms & 0xFFFF);
    const uint8_t block_no = next_block_no_;
    // The wave data cannot exceed what the 16-bit BodySize carries; upstream
    // (the 20 ms sine source) never produces more than one block, so trailing
    // bytes are dropped defensively rather than overflowing the wire field.
    const size_t actual =
        data.size() < kMaxWave2Data ? data.size() : kMaxWave2Data;
    const std::vector<uint8_t> payload(
        data.begin(),
        data.begin() + static_cast<std::ptrdiff_t>(actual));
    SendRdpsnd(rtsc::proto::SndMsgType::kWave2,
               rtsc::proto::BuildWave2Body(time_stamp, 0, block_no, 0,
                                           payload));
    ++wave2_count_;
    bytes_sent_ += payload.size();
    in_flight_.push_back(block_no);
    next_block_no_ = static_cast<uint8_t>(next_block_no_ + 1);
}

rtsc::proto::SndAudioFormat RdpsndServer::FormatFromSource(
    const rtsc::audio::PcmFormat& format) {
    // Design 7.2 / D13: nAvgBytesPerSec = rate * channels * 2,
    // nBlockAlign = channels * 2 (16-bit PCM).
    rtsc::proto::SndAudioFormat fmt;
    fmt.format_tag = rtsc::proto::SndAudioFormat::kFormatPcm;
    fmt.channels = format.channels;
    fmt.samples_per_sec = format.samples_per_sec;
    fmt.bits_per_sample = format.bits_per_sample;
    fmt.avg_bytes_per_sec = format.samples_per_sec * format.channels * 2;
    fmt.block_align = static_cast<uint16_t>(format.channels * 2);
    fmt.cb_size = 0;
    return fmt;
}

}  // namespace rtsc::channel