// Platform-neutral audio capture source for the server-side rdpsnd channel.
//
// The AudioSink interface (audio_sink.h) describes where decoded PCM goes on
// the client; AudioCaptureSource is its mirror on the server. The server role
// pulls interleaved PCM from a source with Poll() and pumps it into Wave2 PDUs
// ([MS-RDPEA]) towards the client. A source is created per session through a
// factory seam (ServerConfig::audio_source_factory), so a real system-audio
// backend (WASAPI loopback, v2) and the deterministic sine test source are
// interchangeable without touching the server or the channel handler.
//
// Poll() is called from the session thread on a fixed cadence; it must not
// block for long and must be safe to call after Stop().

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "rtsc/audio/audio_sink.h"

namespace rtsc::audio {

class AudioCaptureSource {
 public:
    virtual ~AudioCaptureSource() = default;

    // Starts capture. Returns false when the backend could not start; a
    // non-running source reports ok() == false and Poll yields nothing.
    virtual bool Start() = 0;

    // Stops capture. Idempotent.
    virtual void Stop() = 0;

    // Pulls the interleaved PCM produced since the last call into `pcm`
    // (replacing its contents). Returns true when new samples were produced.
    virtual bool Poll(std::vector<uint8_t>& pcm) = 0;

    // The interleaved PCM format the source produces.
    virtual PcmFormat format() const = 0;

    // True while capture is running and healthy.
    virtual bool ok() const = 0;
};

// Deterministic, platform-neutral sine-wave source: 44100 Hz / 16-bit / 2 ch.
// Every Poll yields one 20 ms block (3528 bytes) of a mid-level 440 Hz tone,
// phase-continuous across calls, so the server tests and the e2e loopback get
// a bounded, reproducible PCM stream on any host (including headless CI).
std::unique_ptr<AudioCaptureSource> CreateSineSource();

}  // namespace rtsc::audio