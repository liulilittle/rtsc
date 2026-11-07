// rdpsnd (audio output) static virtual channel handler ([MS-RDPEA]).
//
// The connection driver hands this class the raw MCS Send Data user_data of the
// rdpsnd channel, which is a CHANNEL_PDU_HEADER followed by one or more rdpsnd
// PDUs. The handler reassembles the chunked channel message, runs the audio
// output virtual channel protocol, and submits decoded PCM to an AudioPlayer.
//
// Initialization: the server first sends a Server Audio Formats and Version PDU
// (SNDC_FORMATS). The handler answers with a Client Audio Formats and Version
// PDU (advertising TSSNDCAPS_ALIVE and one 16-bit PCM format chosen from the
// server's list) and, for protocol versions >= 6, a Quality Mode PDU. The
// server then streams Wave2 (SNDC_WAVE2) PDUs, and the handler replies with a
// Wave Confirm PDU (SNDC_WAVECONFIRM) for each consumed sample.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "rtsc/audio/audio_sink.h"
#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpsnd.h"

namespace rtsc::channel {

// Audio backend sink (see rtsc/audio/audio_sink.h). Implemented by the
// platform audio layer (waveOut) or by a test double. The interface is
// deliberately identical to the channel handler's needs so the GUI can hand its
// sink straight to the handler.
using AudioSink = rtsc::audio::AudioSink;

class RdpsndClient {
 public:
    // Receives a complete channel message: CHANNEL_PDU_HEADER + rdpsnd PDU(s).
    // The caller wraps it in an MCS Send Data Request and writes it.
    using SendFn = std::function<void(const std::vector<uint8_t>&)>;

    RdpsndClient(AudioSink* sink, SendFn send);
    ~RdpsndClient();

    RdpsndClient(const RdpsndClient&) = delete;
    RdpsndClient& operator=(const RdpsndClient&) = delete;

    // Feeds one inbound virtual-channel chunk (the MCS Send Data user_data).
    // A message may be split across calls.
    void OnChannelData(const uint8_t* data, size_t size);

    // Drops the per-session protocol state after the transport was replaced
    // (auto-reconnect, [MS-RDPBCGR] 1.3.5). The configuration (audio sink,
    // send function) is kept; every negotiated format and the reassembly
    // buffer are not. The server re-runs the format exchange in the new
    // session, which repopulates them.
    void Reset();

    // ---- diagnostics -------------------------------------------------------
    unsigned server_formats_count() const { return server_formats_count_; }
    unsigned client_formats_count() const { return client_formats_count_; }
    unsigned quality_mode_count() const { return quality_mode_count_; }
    unsigned wave2_count() const { return wave2_count_; }
    unsigned wave_confirm_count() const { return wave_confirm_count_; }
    unsigned training_confirm_count() const { return training_confirm_count_; }
    unsigned close_count() const { return close_count_; }
    size_t bytes_played() const { return bytes_played_; }
    bool audio_received() const { return audio_received_; }
    uint16_t server_version() const { return server_version_; }
    rtsc::proto::SndAudioFormat selected_format() const {
        return selected_format_;
    }

 private:
    struct PendingWave {
        uint16_t time_stamp = 0;
        uint16_t format_no = 0;
        uint8_t block_no = 0;
        std::vector<uint8_t> data;
    };

    void OnMessage(const std::vector<uint8_t>& message);
    void OnPdu(const rtsc::proto::SndProlog& prolog,
               const std::vector<uint8_t>& body);
    void OnWavePdu(const std::vector<uint8_t>& message, size_t offset);
    void OnServerFormats(const std::vector<uint8_t>& body);
    void OnWave2(const std::vector<uint8_t>& body);
    void OnTraining(const std::vector<uint8_t>& body);
    void OnSetVolume(const std::vector<uint8_t>& body);
    void OnClose();

    static const rtsc::proto::SndAudioFormat* SelectFormat(
        const std::vector<rtsc::proto::SndAudioFormat>& formats);

    void SendRdpsnd(rtsc::proto::SndMsgType type,
                    const std::vector<uint8_t>& body);
    void SendClientFormats(const rtsc::proto::SndAudioFormat& format);
    void SendWaveConfirm(uint16_t time_stamp, uint8_t block_no);
    void PlaySample(const std::vector<uint8_t>& data, uint16_t format_no,
                    uint16_t time_stamp, uint8_t block_no);

    AudioSink* sink_;
    SendFn send_;

    rtsc::proto::ChannelReassembler reassembler_;
    std::optional<PendingWave> pending_wave_;

    std::vector<rtsc::proto::SndAudioFormat> server_formats_;
    std::vector<rtsc::proto::SndAudioFormat> client_formats_;
    rtsc::proto::SndAudioFormat selected_format_;
    uint16_t server_version_ = 0;

    unsigned server_formats_count_ = 0;
    unsigned client_formats_count_ = 0;
    unsigned quality_mode_count_ = 0;
    unsigned wave2_count_ = 0;
    unsigned wave_confirm_count_ = 0;
    unsigned training_confirm_count_ = 0;
    unsigned close_count_ = 0;
    size_t bytes_played_ = 0;
    bool audio_received_ = false;
};

}  // namespace rtsc::channel
