// Platform-neutral audio output interface for the rdpsnd virtual channel.
//
// The rdpsnd handler decodes the server's audio PDUs and hands interleaved PCM
// to an AudioSink. The sink owns the device and the playback thread; Submit is
// safe to call from the protocol thread while playback runs elsewhere.

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace rtsc::audio {

// Interleaved PCM description. Only 16-bit samples are produced by the rdpsnd
// handler today, but the interface stays width-agnostic.
struct PcmFormat {
    uint16_t channels = 2;
    uint32_t samples_per_sec = 44100;
    uint16_t bits_per_sample = 16;
};

class AudioSink {
 public:
    virtual ~AudioSink() = default;

    // Enqueues interleaved PCM for playback. Thread-safe; returns immediately.
    virtual void Submit(const std::vector<uint8_t>& pcm,
                        const PcmFormat& format) = 0;

    // Applies a volume change (0x0000 silence .. 0xFFFF full, per channel).
    virtual void SetVolume(uint16_t left, uint16_t right) = 0;

    // True once a device has been opened successfully.
    virtual bool ok() const = 0;
};

// No-op sink used on platforms without an audio backend (and as a test double).
class NullAudioSink final : public AudioSink {
 public:
    void Submit(const std::vector<uint8_t>&, const PcmFormat&) override {}
    void SetVolume(uint16_t, uint16_t) override {}
    bool ok() const override { return false; }
};

// Creates the waveOut-backed sink (Windows only). Returns nullptr when the
// platform has no backend; the caller decides how to report that.
std::unique_ptr<AudioSink> CreateWaveOutSink();

}  // namespace rtsc::audio
