// Platform-neutral audio capture source seam and sine-wave test source.

#include "rtsc/audio/audio_source.h"

#include <cmath>
#include <cstdint>
#include <vector>

namespace rtsc::audio {

namespace {

// 20 ms at 44100 Hz = 882 stereo frames.
constexpr size_t kFramesPerBlock = 882;
// Interleaved 16-bit stereo: 4 bytes per frame.
constexpr size_t kBytesPerFrame = 4;
constexpr size_t kBlockBytes = kFramesPerBlock * kBytesPerFrame;

// Half of int16 full scale (headroom below saturation; the design-fixed peak).
constexpr double kAmplitude = 8192.0;
constexpr double kFrequency = 440.0;
constexpr double kSampleRate = 44100.0;

class SineCaptureSource final : public AudioCaptureSource {
 public:
    bool Start() override {
        if (running_) return true;
        running_ = true;
        sample_index_ = 0;
        return true;
    }

    void Stop() override { running_ = false; }

    bool Poll(std::vector<uint8_t>& pcm) override {
        pcm.clear();
        if (!running_) return false;
        pcm.reserve(kBlockBytes);
        const double phase_step = 2.0 * 3.14159265358979323846 * kFrequency /
                                  kSampleRate;
        for (size_t i = 0; i < kFramesPerBlock; ++i) {
            // Phase is continuous across calls: this block starts where the
            // previous one ended.
            const double v = kAmplitude * std::sin(phase_step * static_cast<double>(sample_index_++));
            const int16_t sample =
                static_cast<int16_t>(static_cast<uint16_t>(static_cast<int32_t>(std::lround(v))));
            const uint16_t u = static_cast<uint16_t>(sample);
            const uint8_t lo = static_cast<uint8_t>(u & 0xFF);
            const uint8_t hi = static_cast<uint8_t>((u >> 8) & 0xFF);
            // Stereo: the same tone on both channels (interleaved L R L R).
            pcm.push_back(lo);
            pcm.push_back(hi);
            pcm.push_back(lo);
            pcm.push_back(hi);
        }
        return true;
    }

    PcmFormat format() const override { return {2, 44100, 16}; }

    bool ok() const override { return running_; }

 private:
    bool running_ = false;
    uint64_t sample_index_ = 0;
};

}  // namespace

std::unique_ptr<AudioCaptureSource> CreateSineSource() {
    return std::make_unique<SineCaptureSource>();
}

}  // namespace rtsc::audio