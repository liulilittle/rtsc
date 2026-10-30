// Server-side rdpsnd (audio output) static virtual channel handler
// ([MS-RDPEA] 3.2.6).
//
// The server role owns the capture side: it advertises one PCM format, waits
// for the client's formats answer (and, for peers >= version 6, the client's
// Quality Mode PDU, which [MS-RDPEA] 2.2.2.3 requires the client to send —
// the server never sends one), then proceeds to the training exchange and
// finally pumps audio blocks from an injected AudioCaptureSource into Wave2
// PDUs ([MS-RDPEA] 2.2.3.10), tracking the client's Wave Confirms against a
// bounded in-flight window.
//
// State machine (design 7.1/7.2 as amended):
//   kIdle --Start(capture ok)--> kAwaitClientFormats
//   kAwaitClientFormats --(valid formats, alive, version>=6)--> kAwaitQualityMode
//   kAwaitClientFormats --(valid formats, alive, version<6)--> kAwaitTrainingConfirm
//   kAwaitClientFormats --(silent peer: ALIVE=0 or unplayable formats)--> kReady
//   kAwaitQualityMode --(quality mode)--> kAwaitTrainingConfirm
//   kAwaitQualityMode --(deadline)--> kAwaitTrainingConfirm   (non-fatal; the
//      missing Quality Mode PDU becomes DYNAMIC_QUALITY, spec 3.3.5.1.1.3 <19>)
//   kAwaitTrainingConfirm --(training confirm)--> kReady
//   kAwaitClientFormats / kAwaitTrainingConfirm --(deadline)--> SNDC_CLOSE + kClosed
//
// Negotiation deadlines (default 5 s, injectable for tests): only the
// formats and training-confirm waits are fatal. The quality-mode wait is not:
// a silent client degrades to DYNAMIC_QUALITY and the negotiation proceeds to
// training. A peer that is not alive or that answered with an unusable format
// list (empty, or not 16-bit PCM 1-2ch matching the advertised format) becomes
// a permanent silent kReady: capture is released, nothing streams and the
// channel is never closed. Streaming (kReady) never times out. Wave2 is only
// streamed to version>=8 peers whose formats validated. At most kMaxInFlight=8
// blocks may be in flight; a full window drops new blocks (counted).
//
// One RdpsndServer is created per session and used only from the session
// thread. The AudioCaptureSource is owned and started/stopped here. The SendFn
// is invoked synchronously on that thread (a blocking transport stalls the
// session, the same limitation as the cliprdr handler), so it must not block
// for long.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "rtsc/audio/audio_source.h"
#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpsnd.h"

namespace rtsc::channel {

class RdpsndServer {
 public:
    // Receives one complete channel chunk (CHANNEL_PDU_HEADER + audio PDU).
    using SendFn = std::function<void(const std::vector<uint8_t>&)>;

    RdpsndServer(std::unique_ptr<rtsc::audio::AudioCaptureSource> source,
                 SendFn send,
                 std::chrono::milliseconds negotiation_timeout =
                     std::chrono::milliseconds(5000));
    ~RdpsndServer();

    RdpsndServer(const RdpsndServer&) = delete;
    RdpsndServer& operator=(const RdpsndServer&) = delete;

    // ---- connection lifecycle ----------------------------------------------

    // Starts capture and sends the opening Server Audio Formats and Version
    // PDU. Idempotent. When capture cannot start the channel stays silent
    // (no SNDC_FORMATS, no timeout).
    void Start();

    // Feeds one inbound virtual-channel chunk (the MCS Send Data user_data of
    // one channel indication). A message may be split across calls.
    void OnChannelData(const uint8_t* data, size_t size);

    // Runs the negotiation dead-lines and the audio pump. Called once per tick
    // from the session's active loop; the pump emits at most one block per
    // 20 ms window and is a cheap no-op otherwise.
    void Poll(std::chrono::steady_clock::time_point now);

    // ---- diagnostics -------------------------------------------------------

    // The protocol phase (six states, design 7.1).
    enum class Phase {
        kIdle,
        kAwaitClientFormats,
        kAwaitQualityMode,
        kAwaitTrainingConfirm,
        kReady,
        kClosed,
    };
    static const char* to_string(Phase p);
    Phase phase() const { return phase_; }

    bool started() const { return started_; }

    // State learned from the client's formats answer. format_valid() is true
    // only when the answer carried at least one playable format matching the
    // advertised set (16-bit PCM, 1..2 channels, equal to the advertised
    // format); otherwise the channel serves permanent silence.
    bool client_alive() const { return client_alive_; }
    bool format_valid() const { return format_valid_; }
    uint16_t client_version() const { return client_version_; }

    unsigned server_formats_count() const { return server_formats_count_; }
    unsigned client_formats_count() const { return client_formats_count_; }
    unsigned quality_mode_count() const { return quality_mode_count_; }
    unsigned quality_mode_timeout_count() const {
        return quality_mode_timeout_count_;
    }
    unsigned training_sent_count() const { return training_sent_count_; }
    unsigned training_confirm_count() const { return training_confirm_count_; }
    unsigned wave2_count() const { return wave2_count_; }
    unsigned wave_confirm_count() const { return wave_confirm_count_; }
    unsigned close_sent_count() const { return close_sent_count_; }
    unsigned malformed_pdu_count() const { return malformed_pdu_count_; }
    unsigned out_of_order_count() const { return out_of_order_count_; }
    unsigned dropped_blocks() const { return dropped_blocks_; }
    size_t in_flight() const { return in_flight_.size(); }
    size_t bytes_sent() const { return bytes_sent_; }

 private:
    void OnMessage(const std::vector<uint8_t>& message);
    void OnPdu(const rtsc::proto::SndProlog& prolog,
               const std::vector<uint8_t>& body);
    void OnClientFormats(const std::vector<uint8_t>& body);
    void OnQualityMode(const std::vector<uint8_t>& body);
    void OnTrainingConfirm(const std::vector<uint8_t>& body);
    void OnWaveConfirm(const std::vector<uint8_t>& body);

    void SendRdpsnd(rtsc::proto::SndMsgType type,
                    const std::vector<uint8_t>& body);
    void SendClose();
    // Enters the training wait: emits the (empty-body) Training PDU, moves to
    // kAwaitTrainingConfirm and re-arms the deadline from `now`.
    void SendTrainingPduAndWait(std::chrono::steady_clock::time_point now);
    void EmitWave2(const std::vector<uint8_t>& data,
                   std::chrono::steady_clock::time_point now);
    static rtsc::proto::SndAudioFormat FormatFromSource(
        const rtsc::audio::PcmFormat& format);
    // True when the client's format list is usable: non-empty and every
    // entry is 16-bit PCM with 1..2 channels matching the advertised format.
    bool AcceptableFormats(const rtsc::proto::SndServerFormats& formats) const;

    std::unique_ptr<rtsc::audio::AudioCaptureSource> source_;
    SendFn send_;
    rtsc::proto::ChannelReassembler reassembler_;
    std::chrono::milliseconds negotiation_timeout_{5000};

    Phase phase_ = Phase::kIdle;
    bool started_ = false;
    bool client_alive_ = false;
    bool format_valid_ = false;
    uint16_t client_version_ = 0;
    // The single format this server advertised; the client's answer must be a
    // subset of it.
    rtsc::proto::SndAudioFormat advertised_format_;

    // The block number assigned to the next Wave2, starting at 1 and wrapping
    // through 255 to 0 (design 7.2). With a window of 8 blocks the wrap can
    // never collide with an in-flight block.
    uint8_t next_block_no_ = 1;
    // Block numbers of the Wave2 PDUs not yet confirmed by the client.
    std::vector<uint8_t> in_flight_;
    // Audio timestamps and the 20 ms pump cadence are anchored to the first
    // Poll after the channel becomes ready (lazily fixed there).
    std::optional<std::chrono::steady_clock::time_point> epoch_;
    std::optional<std::chrono::steady_clock::time_point> next_audio_due_;
    std::chrono::steady_clock::time_point negotiation_deadline_{};

    unsigned server_formats_count_ = 0;
    unsigned client_formats_count_ = 0;
    unsigned quality_mode_count_ = 0;
    unsigned quality_mode_timeout_count_ = 0;
    unsigned training_sent_count_ = 0;
    unsigned training_confirm_count_ = 0;
    unsigned wave2_count_ = 0;
    unsigned wave_confirm_count_ = 0;
    unsigned close_sent_count_ = 0;
    unsigned malformed_pdu_count_ = 0;
    unsigned out_of_order_count_ = 0;
    unsigned dropped_blocks_ = 0;
    size_t bytes_sent_ = 0;
};

}  // namespace rtsc::channel