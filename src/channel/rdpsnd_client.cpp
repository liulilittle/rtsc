// rdpsnd (audio output) static virtual channel handler ([MS-RDPEA]).

#include "rtsc/channel/rdpsnd_client.h"

#include <algorithm>
#include <cstdint>
#include <utility>

namespace rtsc::channel {

namespace {

constexpr uint32_t kFullVolume = 0xFFFFFFFFu;
// wVersion reported by this client. Version 8 makes the server use the single
// Wave2 PDU per audio sample instead of the older WaveInfo + Wave pair.
constexpr uint16_t kClientVersion = rtsc::proto::kSndVersionWin8;

}  // namespace

RdpsndClient::RdpsndClient(AudioSink* sink, SendFn send)
    : sink_(sink), send_(std::move(send)) {}

RdpsndClient::~RdpsndClient() = default;

void RdpsndClient::Reset() {
    reassembler_.Reset();
    pending_wave_.reset();
    server_formats_.clear();
    client_formats_.clear();
    selected_format_ = {};
    server_version_ = 0;
    // The counters are diagnostics for one session; a reconnect starts a new
    // one, so they restart with it.
    server_formats_count_ = 0;
    client_formats_count_ = 0;
    quality_mode_count_ = 0;
    wave2_count_ = 0;
    wave_confirm_count_ = 0;
    training_confirm_count_ = 0;
    close_count_ = 0;
    bytes_played_ = 0;
    audio_received_ = false;
}

void RdpsndClient::OnChannelData(const uint8_t* data, size_t size) {
    if (data == nullptr || size < rtsc::proto::ChannelPduHeader::kSize) return;

    rtsc::proto::ChannelPduHeader header;
    if (rtsc::proto::ChannelPduHeader::parse(data, size, header) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    bool complete = false;
    std::vector<uint8_t> message;
    const rtsc::proto::Status st = reassembler_.Feed(
        header, data + rtsc::proto::ChannelPduHeader::kSize,
        size - rtsc::proto::ChannelPduHeader::kSize, complete, message);
    if (st != rtsc::proto::Status::Ok) {
        reassembler_.Reset();
        return;
    }
    if (!complete) return;
    OnMessage(message);
}

void RdpsndClient::OnMessage(const std::vector<uint8_t>& message) {
    size_t offset = 0;
    while (offset + rtsc::proto::SndProlog::kSize <= message.size()) {
        rtsc::proto::SndProlog prolog;
        if (rtsc::proto::SndProlog::parse(message.data() + offset,
                                         message.size() - offset, prolog) !=
            rtsc::proto::Status::Ok) {
            return;
        }

        // SNDC_WAVE carries a WaveInfo PDU whose BodySize is not a plain body
        // length, so it is handled separately from the length-prefixed types.
        if (prolog.msg_type == rtsc::proto::SndMsgType::kWave) {
            OnWavePdu(message, offset);
            offset += rtsc::proto::SndProlog::kSize +
                      rtsc::proto::SndWaveInfo::kFixedSize;
            continue;
        }

        const size_t body_begin = offset + rtsc::proto::SndProlog::kSize;
        if (body_begin + prolog.body_size > message.size()) return;
        const std::vector<uint8_t> body(message.begin() + body_begin,
                                        message.begin() + body_begin +
                                            prolog.body_size);
        OnPdu(prolog, body);
        offset = body_begin + prolog.body_size;
    }
}

void RdpsndClient::OnPdu(const rtsc::proto::SndProlog& prolog,
                         const std::vector<uint8_t>& body) {
    switch (prolog.msg_type) {
        case rtsc::proto::SndMsgType::kFormats:
            OnServerFormats(body);
            break;
        case rtsc::proto::SndMsgType::kWave2:
            OnWave2(body);
            break;
        case rtsc::proto::SndMsgType::kTraining:
            OnTraining(body);
            break;
        case rtsc::proto::SndMsgType::kSetVolume:
            OnSetVolume(body);
            break;
        case rtsc::proto::SndMsgType::kClose:
            OnClose();
            break;
        case rtsc::proto::SndMsgType::kSetPitch:
        case rtsc::proto::SndMsgType::kCryptKey:
        case rtsc::proto::SndMsgType::kWaveEncrypt:
        case rtsc::proto::SndMsgType::kUdpWave:
        case rtsc::proto::SndMsgType::kUdpWaveLast:
        case rtsc::proto::SndMsgType::kQualityMode:
        case rtsc::proto::SndMsgType::kWaveConfirm:
        default:
            break;
    }
}

void RdpsndClient::OnWavePdu(const std::vector<uint8_t>& message, size_t offset) {
    const uint8_t* body = message.data() + offset + rtsc::proto::SndProlog::kSize;
    const size_t body_size = message.size() - offset - rtsc::proto::SndProlog::kSize;

    if (pending_wave_.has_value()) {
        // Continuation Wave PDU: the rest of the audio sample.
        const size_t data_begin = std::min<size_t>(4, body_size);
        pending_wave_->data.insert(pending_wave_->data.end(), body + data_begin,
                                   body + body_size);
        PendingWave wave = *pending_wave_;
        pending_wave_.reset();
        PlaySample(wave.data, wave.format_no, wave.time_stamp, wave.block_no);
        return;
    }

    rtsc::proto::SndWaveInfo info;
    const std::vector<uint8_t> info_body(body, body + body_size);
    if (rtsc::proto::SndWaveInfo::parse(info_body, info) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    PendingWave wave;
    wave.time_stamp = info.time_stamp;
    wave.format_no = info.format_no;
    wave.block_no = info.block_no;
    wave.data = info.data;
    pending_wave_ = std::move(wave);
}

void RdpsndClient::OnServerFormats(const std::vector<uint8_t>& body) {
    rtsc::proto::SndServerFormats formats;
    if (rtsc::proto::SndServerFormats::parse(body, formats) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    server_formats_ = formats.formats;
    server_version_ = formats.version;
    ++server_formats_count_;

    const rtsc::proto::SndAudioFormat* chosen =
        SelectFormat(formats.formats);
    if (chosen == nullptr) return;  // no playable format in the server list

    selected_format_ = *chosen;
    SendClientFormats(*chosen);
    // The Quality Mode PDU is required when both peers are at least version 6.
    if (formats.version >= 6) {
        const std::vector<uint8_t> quality =
            rtsc::proto::BuildQualityModeBody(rtsc::proto::kQualityHigh);
        SendRdpsnd(rtsc::proto::SndMsgType::kQualityMode, quality);
        ++quality_mode_count_;
    }
}

void RdpsndClient::OnWave2(const std::vector<uint8_t>& body) {
    rtsc::proto::SndWave2 wave;
    if (rtsc::proto::SndWave2::parse(body, wave) != rtsc::proto::Status::Ok) {
        return;
    }
    ++wave2_count_;
    PlaySample(wave.data, wave.format_no, wave.time_stamp, wave.block_no);
}

void RdpsndClient::OnTraining(const std::vector<uint8_t>& body) {
    rtsc::proto::SndTraining training;
    if (rtsc::proto::SndTraining::parse(body, training) !=
        rtsc::proto::Status::Ok) {
        return;
    }
    const std::vector<uint8_t> confirm =
        rtsc::proto::BuildTrainingConfirmBody(training.time_stamp,
                                              training.pack_size);
    SendRdpsnd(rtsc::proto::SndMsgType::kTraining, confirm);
    ++training_confirm_count_;
}

void RdpsndClient::OnSetVolume(const std::vector<uint8_t>& body) {
    if (body.size() < 4) return;
    const uint32_t volume = static_cast<uint32_t>(body[0]) |
                            (static_cast<uint32_t>(body[1]) << 8) |
                            (static_cast<uint32_t>(body[2]) << 16) |
                            (static_cast<uint32_t>(body[3]) << 24);
    if (sink_ != nullptr) {
        sink_->SetVolume(static_cast<uint16_t>(volume & 0xFFFF),
                         static_cast<uint16_t>(volume >> 16));
    }
}

void RdpsndClient::OnClose() {
    ++close_count_;
    pending_wave_.reset();
}

const rtsc::proto::SndAudioFormat* RdpsndClient::SelectFormat(
    const std::vector<rtsc::proto::SndAudioFormat>& formats) {
    const rtsc::proto::SndAudioFormat* best = nullptr;
    int best_score = -1;
    for (const auto& format : formats) {
        int score = -1;
        if (format.format_tag == rtsc::proto::SndAudioFormat::kFormatPcm &&
            format.bits_per_sample == 16) {
            if (format.samples_per_sec == 44100 && format.channels == 2) {
                score = 100;
            } else if (format.samples_per_sec == 48000 &&
                       format.channels == 2) {
                score = 90;
            } else if (format.samples_per_sec == 44100 &&
                       format.channels == 1) {
                score = 80;
            } else if (format.channels == 2) {
                score = 50;
            } else {
                score = 40;
            }
        } else if (format.format_tag == rtsc::proto::SndAudioFormat::kFormatPcm) {
            score = 10;
        }
        if (score > best_score) {
            best_score = score;
            best = &format;
        }
    }
    return best;
}

void RdpsndClient::SendRdpsnd(rtsc::proto::SndMsgType type,
                              const std::vector<uint8_t>& body) {
    if (!send_) return;
    const std::vector<uint8_t> pdu = rtsc::proto::BuildSndPdu(type, body);
    const std::vector<std::vector<uint8_t>> chunks =
        rtsc::proto::FragmentChannelMessage(pdu,
                                            rtsc::proto::kDefaultChannelChunkSize);
    for (const auto& chunk : chunks) send_(chunk);
}

void RdpsndClient::SendClientFormats(
    const rtsc::proto::SndAudioFormat& format) {
    const uint32_t flags = rtsc::proto::kSndCapsAlive |
                           rtsc::proto::kSndCapsVolume;
    const std::vector<uint8_t> body = rtsc::proto::BuildClientFormatsBody(
        flags, kFullVolume, 0, 0, kClientVersion, {format});
    SendRdpsnd(rtsc::proto::SndMsgType::kFormats, body);
    client_formats_ = {format};
    ++client_formats_count_;
}

void RdpsndClient::SendWaveConfirm(uint16_t time_stamp, uint8_t block_no) {
    const std::vector<uint8_t> body =
        rtsc::proto::BuildWaveConfirmBody(time_stamp, block_no);
    SendRdpsnd(rtsc::proto::SndMsgType::kWaveConfirm, body);
    ++wave_confirm_count_;
}

void RdpsndClient::PlaySample(const std::vector<uint8_t>& data,
                              uint16_t format_no, uint16_t time_stamp,
                              uint8_t block_no) {
    if (sink_ != nullptr && !client_formats_.empty() && !data.empty()) {
        const size_t index =
            std::min<size_t>(format_no, client_formats_.size() - 1);
        const rtsc::proto::SndAudioFormat& format = client_formats_[index];
        rtsc::audio::PcmFormat pcm_format;
        pcm_format.channels = format.channels;
        pcm_format.samples_per_sec = format.samples_per_sec;
        pcm_format.bits_per_sample = format.bits_per_sample;
        sink_->Submit(data, pcm_format);
        bytes_played_ += data.size();
        audio_received_ = true;
    }
    SendWaveConfirm(time_stamp, block_no);
}

}  // namespace rtsc::channel
