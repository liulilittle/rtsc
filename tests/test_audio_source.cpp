// Server-side audio capture source tests: the platform-neutral sine source
// must report a sane format, produce bounded PCM with a real signal, and
// follow the Start/Poll/Stop/ok lifecycle deterministically (design 7.3).

#include "rtsc/audio/audio_source.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

namespace {

// Peak of |int16 sample| over a byte vector of stereo 16-bit interleaved PCM.
int32_t MaxAbsSample(const std::vector<uint8_t>& pcm) {
    int32_t max_abs = 0;
    for (size_t i = 0; i + 1 < pcm.size(); i += 2) {
        const int16_t v = static_cast<int16_t>(
            pcm[i] | (static_cast<uint16_t>(pcm[i + 1]) << 8));
        const int32_t a = v < 0 ? -static_cast<int32_t>(v) : v;
        if (a > max_abs) max_abs = a;
    }
    return max_abs;
}

std::vector<uint8_t> PollBytes(rtsc::audio::AudioCaptureSource& s) {
    std::vector<uint8_t> pcm;
    s.Poll(pcm);
    return pcm;
}

}  // namespace

RTSC_TEST(sine_source_format_and_lifecycle) {
    auto src = rtsc::audio::CreateSineSource();
    CHECK(src != nullptr);
    if (src == nullptr) return;

    // Not started: no audio, format still the configured 44100/16/2.
    CHECK(!src->ok());
    std::vector<uint8_t> none;
    CHECK(!src->Poll(none));
    CHECK(none.empty());
    CHECK_EQ(src->format().channels, static_cast<uint16_t>(2));
    CHECK_EQ(src->format().samples_per_sec, static_cast<uint32_t>(44100));
    CHECK_EQ(src->format().bits_per_sample, static_cast<uint16_t>(16));

    CHECK(src->Start());
    CHECK(src->ok());

    std::vector<uint8_t> pcm;
    CHECK(src->Poll(pcm));
    CHECK(!pcm.empty());
    // One 20 ms block at 44100 Hz / 2 ch / 16 bit = 882 frames * 4 bytes.
    CHECK_EQ(pcm.size(), static_cast<size_t>(3528));
    CHECK_EQ(pcm.size() % 4, static_cast<size_t>(0));

    const int32_t max_abs = MaxAbsSample(pcm);
    // The sine's peak is 8192 (headroom below int16 saturation), and 882
    // frames at 440 Hz sweep enough phase to come within 0.005 of the peak.
    CHECK(max_abs >= 8000);
    CHECK(max_abs <= 8192);

    // Stop: ok() clears and Poll goes silent, clearing the buffer.
    src->Stop();
    CHECK(!src->ok());
    pcm.assign(5, 0xEE);
    CHECK(!src->Poll(pcm));
    CHECK(pcm.empty());
}

RTSC_TEST(sine_source_deterministic_and_continuous) {
    auto a = rtsc::audio::CreateSineSource();
    auto b = rtsc::audio::CreateSineSource();
    CHECK(a != nullptr && b != nullptr);
    if (a == nullptr || b == nullptr) return;
    a->Start();
    b->Start();

    // Two fresh instances start from the same phase: identical first block.
    const auto block_a1 = PollBytes(*a);
    const auto block_b1 = PollBytes(*b);
    CHECK(block_a1 == block_b1);
    CHECK_EQ(block_a1.size(), static_cast<size_t>(3528));

    // A second poll continues the waveform (never silent, never identical).
    const auto block_a2 = PollBytes(*a);
    CHECK_EQ(block_a2.size(), block_a1.size());
    CHECK(block_a2 != block_a1);
    CHECK(MaxAbsSample(block_a2) >= 8000);
}

int main() { return rtsc::test::run_all("rtsc_audio_source_tests"); }