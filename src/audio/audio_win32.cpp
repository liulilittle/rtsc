// waveOut-backed audio sink for the rdpsnd virtual channel.
//
// Design: the protocol thread calls Submit() and only ever touches the queue
// under a short lock. A single worker thread owns the waveOut device: it opens
// it with the current format, writes queued buffers one at a time, and reopens
// the device when the server switches audio formats. A manual-reset completion
// event (CALLBACK_EVENT) signals buffer completion, so no window or message
// loop is required and the sink works in a headless run.
//
// Only 16-bit PCM is supported; the rdpsnd handler selects a 16-bit PCM format
// from the server's list, so no sample conversion is needed.

#include "rtsc/audio/audio_sink.h"

#if defined(_WIN32)

#include <Windows.h>
#include <mmsystem.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "winmm.lib")

namespace rtsc::audio {
namespace {

// How long an OpenDeviceLocked() failure postpones the next reopen attempt.
// Set in the worker loop so a missing / busy audio device cannot turn the
// sink into a busy loop (design D12).
constexpr auto kDeviceRetryInterval = std::chrono::milliseconds(1000);

class WaveOutPlayer final : public AudioSink {
 public:
    WaveOutPlayer()
        : completion_event_(::CreateEvent(nullptr, TRUE, FALSE, nullptr)) {}

    ~WaveOutPlayer() override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stopping_.store(true);
        }
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
        std::lock_guard<std::mutex> lk(device_mu_);
        CloseDeviceLocked();
        if (completion_event_ != nullptr) {
            ::CloseHandle(completion_event_);
            completion_event_ = nullptr;
        }
    }

    WaveOutPlayer(const WaveOutPlayer&) = delete;
    WaveOutPlayer& operator=(const WaveOutPlayer&) = delete;

    void Submit(const std::vector<uint8_t>& pcm, const PcmFormat& format) override {
        if (pcm.empty()) return;
        bool start_thread = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (stopping_.load()) return;
            if (!have_format_ || format_.channels != format.channels ||
                format_.samples_per_sec != format.samples_per_sec ||
                format_.bits_per_sample != format.bits_per_sample) {
                format_ = format;
                have_format_ = true;
                reopen_ = true;
            }
            queue_.push_back(pcm);
            start_thread = !started_;
            started_ = true;
        }
        cv_.notify_all();
        if (start_thread) {
            thread_ = std::thread([this] { Worker(); });
        }
    }

    void SetVolume(uint16_t left, uint16_t right) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            volume_ = static_cast<DWORD>(left) |
                      (static_cast<DWORD>(right) << 16);
            volume_dirty_ = true;
        }
        std::lock_guard<std::mutex> lk(device_mu_);
        if (wave_out_ != nullptr) ::waveOutSetVolume(wave_out_, volume_);
    }

    bool ok() const override {
        std::lock_guard<std::mutex> lk(device_mu_);
        return ok_;
    }

 private:
    void Worker() {
        std::vector<std::vector<uint8_t>> local;
        for (;;) {
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [this] {
                    return stopping_.load() || reopen_ || !queue_.empty();
                });
                if (stopping_.load()) return;
                if (reopen_) {
                    const auto now = std::chrono::steady_clock::now();
                    // Backoff gate (design D12): after a device-open failure
                    // wait out kDeviceRetryInterval before trying again, so a
                    // missing / busy device cannot spin the worker.
                    if (next_retry_ && now < *next_retry_) {
                        queue_.clear();
                        have_format_ = false;
                        reopen_ = false;
                        continue;
                    }
                    {
                        std::lock_guard<std::mutex> dk(device_mu_);
                        CloseDeviceLocked();
                        if (!OpenDeviceLocked()) {
                            // Failure keeps the worker resident (no `return`,
                            // no detach): the queue is dropped, the format is
                            // forgotten so the next Submit re-arms reopen_,
                            // and the retry is postponed.
                            queue_.clear();
                            have_format_ = false;
                            next_retry_ = now + kDeviceRetryInterval;
                            reopen_ = false;
                            continue;
                        }
                    }
                    next_retry_.reset();
                    reopen_ = false;
                }
                local.swap(queue_);
            }
            for (auto& bytes : local) {
                if (stopping_.load()) return;
                if (!WriteOne(bytes)) break;
            }
            local.clear();
        }
    }

    bool OpenDeviceLocked() {
        if (format_.bits_per_sample != 16 || format_.channels == 0 ||
            format_.channels > 8) {
            return false;
        }
        WAVEFORMATEX wf{};
        wf.wFormatTag = WAVE_FORMAT_PCM;
        wf.nChannels = format_.channels;
        wf.nSamplesPerSec = format_.samples_per_sec;
        wf.wBitsPerSample = 16;
        wf.nBlockAlign =
            static_cast<WORD>(format_.channels * (16 / 8));
        wf.nAvgBytesPerSec = format_.samples_per_sec * wf.nBlockAlign;
        wf.cbSize = 0;

        HWAVEOUT wo = nullptr;
        const MMRESULT mr = ::waveOutOpen(
            &wo, WAVE_MAPPER, &wf,
            reinterpret_cast<DWORD_PTR>(completion_event_), 0, CALLBACK_EVENT);
        if (mr != MMSYSERR_NOERROR) {
            return false;
        }
        wave_out_ = wo;
        ok_ = true;
        if (volume_dirty_) ::waveOutSetVolume(wave_out_, volume_);
        return true;
    }

    void CloseDeviceLocked() {
        if (wave_out_ != nullptr) {
            ::waveOutReset(wave_out_);
            ::waveOutClose(wave_out_);
            wave_out_ = nullptr;
        }
        ok_ = false;
    }

    bool WriteOne(const std::vector<uint8_t>& bytes) {
        std::lock_guard<std::mutex> lk(device_mu_);
        if (wave_out_ == nullptr || bytes.empty()) return false;
        WAVEHDR hdr{};
        hdr.lpData = reinterpret_cast<LPSTR>(const_cast<uint8_t*>(bytes.data()));
        hdr.dwBufferLength = static_cast<DWORD>(bytes.size());
        if (::waveOutPrepareHeader(wave_out_, &hdr, sizeof(hdr)) !=
            MMSYSERR_NOERROR) {
            return false;
        }
        ::ResetEvent(completion_event_);
        if (::waveOutWrite(wave_out_, &hdr, sizeof(hdr)) != MMSYSERR_NOERROR) {
            ::waveOutUnprepareHeader(wave_out_, &hdr, sizeof(hdr));
            return false;
        }
        while ((hdr.dwFlags & WHDR_DONE) == 0) {
            ::WaitForSingleObject(completion_event_, 100);
            if (stopping_.load()) break;
        }
        ::waveOutUnprepareHeader(wave_out_, &hdr, sizeof(hdr));
        return true;
    }

    mutable std::mutex mu_;
    mutable std::mutex device_mu_;
    std::condition_variable cv_;
    std::thread thread_;
    bool started_ = false;
    std::atomic<bool> stopping_{false};
    bool reopen_ = false;
    bool have_format_ = false;
    PcmFormat format_{2, 44100, 16};
    std::vector<std::vector<uint8_t>> queue_;
    // Earliest time at which a new device-open attempt may run (design D12).
    // Guarded by mu_; set after an OpenDeviceLocked() failure, reset on a
    // successful open.
    std::optional<std::chrono::steady_clock::time_point> next_retry_;
    DWORD volume_ = 0xFFFFFFFFu;
    bool volume_dirty_ = false;

    HWAVEOUT wave_out_ = nullptr;
    bool ok_ = false;
    HANDLE completion_event_ = nullptr;
};

}  // namespace

std::unique_ptr<AudioSink> CreateWaveOutSink() {
    return std::make_unique<WaveOutPlayer>();
}

}  // namespace rtsc::audio

#else  // !_WIN32

namespace rtsc::audio {

std::unique_ptr<AudioSink> CreateWaveOutSink() { return nullptr; }

}  // namespace rtsc::audio

#endif  // _WIN32
