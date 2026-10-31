// RTSC performance benchmark.
//
// Measures the three hot paths behind the "extreme performance (remote desktop
// CPU must not explode)" requirement:
//   1. Bitmap decode throughput: raw / Interleaved RLE / RDP6 (ARGB + AYCoCg)
//      / NSCodec, at a fixed 1920x1080 frame.
//   2. End-to-end frame latency through the scripted TLS loopback (the same
//      in-memory transport the security-layer tests use), including the
//      graphics-pipeline decode.
//   3. Process CPU occupancy (CPU time / wall time) while decoding.
//
// The benchmark is deterministic: inputs are generated from fixed patterns, a
// warm-up pass runs before timing, and every measurement reports the median
// plus min / max / mean / stddev over repeated runs. Every number printed here
// comes from an actual timed run; nothing is hard-coded.

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "rtsc/client/graphics.h"
#include "rtsc/credssp/credssp.h"
#include "rtsc/credssp/ntlm.h"
#include "rtsc/credssp/ts_request.h"
#include "rtsc/crypto/hash.h"
#include "rtsc/net/tls.h"
#include "rtsc/proto/bitmap.h"
#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/nsc.h"
#include "rtsc/proto/output.h"
#include "rtsc/proto/rdp6.h"
#include "rtsc/security/security_layer.h"
#include "rtsc/ui/surface.h"
#include "rtsc/util/crash_guard.h"

namespace {

using rtsc::credssp::Bytes;

constexpr uint16_t kWidth = 1920;
constexpr uint16_t kHeight = 1080;
constexpr size_t kPixels = static_cast<size_t>(kWidth) * kHeight;
constexpr size_t kRgbaBytes = kPixels * 4;

// ---------------------------------------------------------------------------
// Timing / statistics helpers
// ---------------------------------------------------------------------------

double NowSeconds() {
    return std::chrono::duration<double>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

struct Stats {
    double min = 0.0;
    double max = 0.0;
    double mean = 0.0;
    double median = 0.0;
    double stddev = 0.0;
};

Stats ComputeStats(const std::vector<double>& samples) {
    const size_t n = samples.size();
    if (n == 0) return Stats{};
    std::vector<double> sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    double sum = 0.0;
    for (double s : samples) sum += s;
    const double mean = sum / static_cast<double>(n);
    double variance = 0.0;
    for (double s : samples) {
        const double d = s - mean;
        variance += d * d;
    }
    variance /= static_cast<double>(n);

    Stats st;
    st.min = sorted.front();
    st.max = sorted.back();
    st.mean = mean;
    st.median = sorted[n / 2];
    st.stddev = std::sqrt(variance);
    return st;
}

struct BenchResult {
    const char* name = "";
    double input_bytes = 0.0;
    double median_ms = 0.0;
    double min_ms = 0.0;
    double max_ms = 0.0;
    double mean_ms = 0.0;
    double stddev_ms = 0.0;
    double input_mbps = 0.0;
    double output_mbps = 0.0;
    double fps = 0.0;
};

// A timed throughput benchmark: warm up, then time `iters` individual runs and
// reduce to statistics. `fn` must decode one frame.
template <typename Fn>
BenchResult RunThroughput(const char* name, size_t input_bytes, Fn&& fn,
                          int warmup = 3, int iters = 30) {
    for (int i = 0; i < warmup; ++i) {
        fn();
    }
    std::vector<double> times;
    times.reserve(static_cast<size_t>(iters));
    for (int i = 0; i < iters; ++i) {
        const double t0 = NowSeconds();
        fn();
        const double t1 = NowSeconds();
        times.push_back(t1 - t0);
    }
    const Stats st = ComputeStats(times);
    BenchResult r;
    r.name = name;
    r.input_bytes = static_cast<double>(input_bytes);
    r.median_ms = st.median * 1000.0;
    r.min_ms = st.min * 1000.0;
    r.max_ms = st.max * 1000.0;
    r.mean_ms = st.mean * 1000.0;
    r.stddev_ms = st.stddev * 1000.0;
    r.input_mbps = r.input_bytes / (st.median * 1e6);
    r.output_mbps = static_cast<double>(kRgbaBytes) / (st.median * 1e6);
    r.fps = 1.0 / st.median;
    return r;
}

// ---------------------------------------------------------------------------
// Deterministic input generators (1920x1080)
// ---------------------------------------------------------------------------

std::vector<uint8_t> MakeRaw32() {
    std::vector<uint8_t> d(kRgbaBytes);
    for (size_t y = 0; y < kHeight; ++y) {
        for (size_t x = 0; x < kWidth; ++x) {
            const size_t i = (y * kWidth + x) * 4;
            d[i + 0] = static_cast<uint8_t>((x * 3 + y * 5) & 0xFF);
            d[i + 1] = static_cast<uint8_t>((x * 7 + y * 11) & 0xFF);
            d[i + 2] = static_cast<uint8_t>((x * 13 + y * 17) & 0xFF);
            d[i + 3] = static_cast<uint8_t>((x * 19 + y * 23) & 0xFF);
        }
    }
    return d;
}

// A fixed 16bpp image: 60x60 blocks with a solid interior and a detailed
// border. The interior encodes as long colour runs; the border as raw colour
// images, so the stream exercises both RLE order classes.
std::vector<uint16_t> MakeRleSource() {
    std::vector<uint16_t> px(kPixels);
    for (size_t y = 0; y < kHeight; ++y) {
        for (size_t x = 0; x < kWidth; ++x) {
            const size_t bx = x / 60;
            const size_t by = y / 60;
            const uint16_t base = static_cast<uint16_t>((bx * 7 + by * 13) & 0xFFFF);
            const bool detail = (x % 60) < 8 || (y % 60) < 8;
            const uint16_t v =
                detail ? static_cast<uint16_t>((x * 3 + y * 5) & 0xFFFF)
                       : static_cast<uint16_t>((base + ((x % 60) / 8) * 0x0421) & 0xFFFF);
            px[y * kWidth + x] = v;
        }
    }
    return px;
}

void PushColorRun(std::vector<uint8_t>& out, size_t run, uint16_t color) {
    out.push_back(0xF3);  // MEGA_MEGA_COLOR_RUN
    out.push_back(static_cast<uint8_t>(run & 0xFF));
    out.push_back(static_cast<uint8_t>((run >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(color & 0xFF));
    out.push_back(static_cast<uint8_t>((color >> 8) & 0xFF));
}

void PushColorImage(std::vector<uint8_t>& out, const std::vector<uint16_t>& px,
                    size_t start, size_t count) {
    out.push_back(0xF4);  // MEGA_MEGA_COLOR_IMAGE
    out.push_back(static_cast<uint8_t>(count & 0xFF));
    out.push_back(static_cast<uint8_t>((count >> 8) & 0xFF));
    for (size_t k = 0; k < count; ++k) {
        const uint16_t v = px[start + k];
        out.push_back(static_cast<uint8_t>(v & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    }
}

std::vector<uint8_t> MakeRle16() {
    const std::vector<uint16_t> px = MakeRleSource();
    std::vector<uint8_t> out;
    out.reserve(kPixels * 2 / 4);
    size_t i = 0;
    while (i < kPixels) {
        size_t run = 1;
        while (i + run < kPixels && px[i + run] == px[i] && run < 65535) ++run;
        if (run >= 4) {
            PushColorRun(out, run, px[i]);
            i += run;
        } else {
            const size_t start = i;
            size_t count = 0;
            while (i < kPixels && count < 65535) {
                size_t r = 1;
                while (i + r < kPixels && px[i + r] == px[i] && r < 65535) ++r;
                if (r >= 4) break;
                ++i;
                ++count;
            }
            PushColorImage(out, px, start, count);
        }
    }
    return out;
}

std::vector<uint8_t> MakeRdp6Argb() {
    std::vector<uint8_t> d;
    d.reserve(1 + 4 * kPixels);
    d.push_back(0x00);  // CLL=0 (ARGB), CS=0, RLE=0, NA=0 (alpha present)
    for (int p = 0; p < 4; ++p) {
        for (size_t i = 0; i < kPixels; ++i) {
            d.push_back(static_cast<uint8_t>((i * 3 + p * 37) & 0xFF));
        }
    }
    return d;
}

std::vector<uint8_t> MakeRdp6AyCoCg() {
    std::vector<uint8_t> d;
    d.reserve(1 + 3 * kPixels);
    d.push_back(0x21);  // CLL=1 (AYCoCg), CS=0, RLE=0, NA=1 (no alpha)
    for (int p = 0; p < 3; ++p) {
        for (size_t i = 0; i < kPixels; ++i) {
            d.push_back(static_cast<uint8_t>((i * 5 + p * 53) & 0xFF));
        }
    }
    return d;
}

std::vector<uint8_t> MakeNsc() {
    // NSCodec, AYCoCg, chroma subsampling, raw planes.
    const uint16_t rw = static_cast<uint16_t>((kWidth + 7) / 8 * 8);
    const uint16_t rh = static_cast<uint16_t>((kHeight + 1) / 2 * 2);
    const uint32_t y_size = static_cast<uint32_t>(rw) * kHeight;
    const uint32_t c_size =
        static_cast<uint32_t>(rw / 2) * static_cast<uint32_t>(rh / 2);
    const uint32_t a_size = static_cast<uint32_t>(kWidth) * kHeight;

    std::vector<uint8_t> d;
    d.reserve(20 + static_cast<size_t>(y_size) + 2 * c_size + a_size);
    auto u32 = [&d](uint32_t v) {
        d.push_back(static_cast<uint8_t>(v & 0xFF));
        d.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        d.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        d.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };
    u32(y_size);
    u32(c_size);
    u32(c_size);
    u32(a_size);
    d.push_back(1);  // colourLossLevel = 1
    d.push_back(1);  // chromaSubsamplingLevel = 1
    d.push_back(0);  // reserved
    d.push_back(0);  // reserved
    for (uint32_t i = 0; i < y_size; ++i) d.push_back(static_cast<uint8_t>((i * 3) & 0xFF));
    for (uint32_t i = 0; i < c_size; ++i) d.push_back(static_cast<uint8_t>((i * 5) & 0xFF));
    for (uint32_t i = 0; i < c_size; ++i) d.push_back(static_cast<uint8_t>((i * 7) & 0xFF));
    for (uint32_t i = 0; i < a_size; ++i) d.push_back(static_cast<uint8_t>((i * 11) & 0xFF));
    return d;
}

// ---------------------------------------------------------------------------
// Scripted TLS loopback (same technique as tests/test_security_layer.cpp)
// ---------------------------------------------------------------------------

rtsc::tls::Error TlsOk() { return rtsc::tls::Error{}; }

class ScriptedTls : public rtsc::tls::TlsTransport {
 public:
    rtsc::tls::Error Handshake(const uint8_t* in, size_t in_size,
                               size_t& consumed,
                               std::vector<uint8_t>& out) override {
        (void)in;
        out.clear();
        consumed = in_size;
        ++rounds_;
        if (rounds_ == 1) {
            out = {0x16, 0x03, 0x01, 0x00, 0x05, 0x01};
            return TlsOk();
        }
        handshake_complete_ = true;
        return TlsOk();
    }
    rtsc::tls::Error Send(const uint8_t* plaintext, size_t size,
                          size_t& consumed, std::vector<uint8_t>& out) override {
        out.assign(plaintext, plaintext + size);
        consumed = size;
        return TlsOk();
    }
    rtsc::tls::Error Receive(const uint8_t* ciphertext, size_t size,
                             std::vector<uint8_t>& plaintext,
                             size_t max_out) override {
        (void)max_out;
        if (ciphertext != nullptr && size > 0) {
            plaintext.insert(plaintext.end(), ciphertext, ciphertext + size);
        }
        return TlsOk();
    }
    rtsc::tls::Error PeerSubjectPublicKeyInfo(
        std::vector<uint8_t>& out) const override {
        out = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        return TlsOk();
    }
    rtsc::tls::Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {
        out = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        return TlsOk();
    }
    rtsc::tls::Error PeerCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        return TlsOk();
    }
    rtsc::tls::Error LocalCertificateDer(std::vector<uint8_t>& out) const override {
        out.clear();
        return TlsOk();
    }
    rtsc::tls::Error LocalSubjectPublicKey(
        std::vector<uint8_t>& out) const override {
        out = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
        return TlsOk();
    }
    rtsc::tls::Error negotiated(rtsc::tls::NegotiatedInfo& out) const override {
        out = rtsc::tls::NegotiatedInfo{};
        out.tls_version = 0x0304;
        return TlsOk();
    }
    rtsc::tls::RecordSizes record_sizes() const override {
        rtsc::tls::RecordSizes s;
        s.header = 5;
        s.max_plaintext = 16384;
        s.overhead_upper = 44;
        s.overhead_actual = 17;
        s.block_size = 16;
        return s;
    }
    rtsc::tls::Error Shutdown(std::vector<uint8_t>& out) override {
        out.clear();
        return TlsOk();
    }
    bool handshake_complete() const noexcept override {
        return handshake_complete_;
    }
    bool closed() const noexcept override { return false; }
    size_t buffered_input() const noexcept override { return 0; }
    const rtsc::tls::Error& last_error() const noexcept override {
        return last_error_;
    }
    const char* backend_name() const noexcept override { return "scripted"; }

 private:
    int rounds_ = 0;
    bool handshake_complete_ = false;
    rtsc::tls::Error last_error_{};
};

// Server CHALLENGE (same shape as tests/test_security_layer.cpp).
Bytes ServerChallengeMessage() {
    using namespace rtsc::credssp;
    ChallengeMessage m;
    m.flags = ntlm_flag::kUnicode | ntlm_flag::kRequestTarget | ntlm_flag::kSign |
              ntlm_flag::kSeal | ntlm_flag::kNtlm | ntlm_flag::kAlwaysSign |
              ntlm_flag::kExtendedSessionSecurity | ntlm_flag::kTargetInfo |
              ntlm_flag::kVersion | ntlm_flag::k128 | ntlm_flag::kKeyExch |
              ntlm_flag::k56 | ntlm_flag::kTargetTypeServer;
    m.server_challenge = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    m.target_name = "Server";
    AvPair domain;
    domain.id = AvId::kNbDomainName;
    domain.value = rtsc::crypto::Utf16Le("Domain");
    AvPair server;
    server.id = AvId::kNbComputerName;
    server.value = rtsc::crypto::Utf16Le("Server");
    AvPair ts;
    ts.id = AvId::kTimestamp;
    ts.value = Bytes(8, 0);
    m.av_pairs = {domain, server, ts};
    Bytes out;
    m.Encode(out);
    return out;
}

rtsc::security::Config MakeSecurityConfig(bool tls_insecure) {
    rtsc::security::Config cfg;
    cfg.tls_config.peer_host = "127.0.0.1";
    // Certificate verification is on by default; --tls-insecure is the
    // explicit escape hatch for isolated environments.
    cfg.tls_config.cert_policy = tls_insecure
                                     ? rtsc::tls::CertPolicy::kInsecure
                                     : rtsc::tls::CertPolicy::kStrict;
    cfg.credssp_version = 6;
    cfg.credentials.domain = "Domain";
    cfg.credentials.user = "User";
    cfg.credentials.password = "Password";
    return cfg;
}

// Drives the security layer through TLS -> CredSSP -> EUAR until the handshake
// completes. Returns false when any step fails.
bool DriveHandshake(rtsc::security::SecurityLayer& layer) {
    using rtsc::credssp::TsRequest;

    auto r = layer.Step(nullptr, 0);
    if (r.want == rtsc::security::Want::kFailed) return false;

    const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x02};
    r = layer.Step(server_hello, sizeof(server_hello));
    if (r.want == rtsc::security::Want::kFailed) return false;

    TsRequest challenge;
    challenge.version = 6;
    challenge.nego_token = ServerChallengeMessage();
    Bytes ch_der;
    if (!challenge.Encode(ch_der).ok()) return false;
    r = layer.Step(ch_der.data(), ch_der.size());
    if (r.want == rtsc::security::Want::kFailed) return false;

    const Bytes echo = layer.credssp_for_test().MakeServerEchoForTest();
    TsRequest step4;
    step4.version = 6;
    step4.pub_key_auth = echo;
    Bytes step4_der;
    if (!step4.Encode(step4_der).ok()) return false;
    r = layer.Step(step4_der.data(), step4_der.size());
    if (r.want == rtsc::security::Want::kFailed) return false;

    const uint8_t euar[] = {0x00, 0x00, 0x00, 0x00};
    r = layer.Step(euar, sizeof(euar));
    return !layer.failed() && layer.handshake_complete();
}

// ---------------------------------------------------------------------------
// End-to-end frame: a full-screen 1920x1080 update, tiled into fast-path PDUs.
// The fast-path length field is 15 bits, so a full-screen uncompressed frame
// does not fit in one PDU and must be split (as a real server does).
// ---------------------------------------------------------------------------

constexpr int kTileW = 96;
constexpr int kTileH = 72;

std::vector<uint8_t> MakeTileStream(int tx, int ty) {
    std::vector<uint8_t> stream;
    stream.reserve(1 + 4 * static_cast<size_t>(kTileW) * kTileH);
    stream.push_back(0x00);  // RDP6 ARGB raw
    for (int p = 0; p < 4; ++p) {
        for (int i = 0; i < kTileW * kTileH; ++i) {
            stream.push_back(
                static_cast<uint8_t>((i * 3 + p * 37 + tx * 7 + ty * 11) & 0xFF));
        }
    }
    return stream;
}

std::vector<uint8_t> MakeTilePdu(int tx, int ty) {
    const std::vector<uint8_t> stream = MakeTileStream(tx, ty);

    // TS_UPDATE_BITMAP_DATA
    std::vector<uint8_t> upd;
    auto u16 = [&upd](uint16_t v) {
        upd.push_back(static_cast<uint8_t>(v & 0xFF));
        upd.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    u16(0x0001);  // updateType = BITMAP
    u16(1);       // numberRectangles
    u16(static_cast<uint16_t>(tx * kTileW));       // destLeft
    u16(static_cast<uint16_t>(ty * kTileH));       // destTop
    u16(static_cast<uint16_t>((tx + 1) * kTileW)); // destRight
    u16(static_cast<uint16_t>((ty + 1) * kTileH)); // destBottom
    u16(static_cast<uint16_t>(kTileW));            // width
    u16(static_cast<uint16_t>(kTileH));            // height
    u16(32);                                       // bitsPerPixel
    u16(0x0401);  // BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR
    u16(static_cast<uint16_t>(stream.size()));     // bitmapLength
    upd.insert(upd.end(), stream.begin(), stream.end());

    // Fast-path output PDU: header + 2-byte length + update.
    std::vector<uint8_t> pdu;
    pdu.reserve(6 + upd.size());
    pdu.push_back(0x00);  // fast-path header (action=kFastPath, flags=0)
    const size_t total = 1 + 2 + 1 + 2 + upd.size();
    pdu.push_back(static_cast<uint8_t>(0x80 | ((total >> 8) & 0x7F)));
    pdu.push_back(static_cast<uint8_t>(total & 0xFF));
    pdu.push_back(0x01);  // update header: code=kBitmap, single, no compression
    pdu.push_back(static_cast<uint8_t>(upd.size() & 0xFF));
    pdu.push_back(static_cast<uint8_t>((upd.size() >> 8) & 0xFF));
    pdu.insert(pdu.end(), upd.begin(), upd.end());
    return pdu;
}

std::vector<std::vector<uint8_t>> MakeFrame() {
    const int nx = kWidth / kTileW;   // 20
    const int ny = kHeight / kTileH;  // 15
    std::vector<std::vector<uint8_t>> pdus;
    pdus.reserve(static_cast<size_t>(nx) * ny);
    for (int ty = 0; ty < ny; ++ty) {
        for (int tx = 0; tx < nx; ++tx) {
            pdus.push_back(MakeTilePdu(tx, ty));
        }
    }
    return pdus;
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

void BenchmarkBitmapDecoders() {
    std::printf("=== Bitmap decode throughput (%ux%u) ===\n", kWidth, kHeight);
    std::printf("%-16s %10s %10s %10s %10s %10s %12s %12s %8s\n", "codec",
                "in(MB)", "median", "min", "max", "stddev", "in(MB/s)",
                "out(MB/s)", "fps");

    const std::vector<uint8_t> raw = MakeRaw32();
    {
        auto r = RunThroughput("raw-32bpp", raw.size(), [&raw]() {
            rtsc::proto::DecodedBitmap bm;
            rtsc::proto::DecodeRawBitmap(raw.data(), raw.size(), kWidth, kHeight,
                                         32, bm);
        });
        std::printf("%-16s %10.2f %9.3fms %9.3fms %9.3fms %9.3fms %11.1f %11.1f %7.1f\n",
                    r.name, r.input_bytes / 1e6, r.median_ms, r.min_ms, r.max_ms,
                    r.stddev_ms, r.input_mbps, r.output_mbps, r.fps);
    }

    const std::vector<uint8_t> rle = MakeRle16();
    {
        auto r = RunThroughput("rle-16bpp", rle.size(), [&rle]() {
            rtsc::proto::DecodedBitmap bm;
            rtsc::proto::DecodeRleBitmap(rle.data(), rle.size(), kWidth,
                                         kHeight, 16, bm);
        });
        std::printf("%-16s %10.2f %9.3fms %9.3fms %9.3fms %9.3fms %11.1f %11.1f %7.1f\n",
                    r.name, r.input_bytes / 1e6, r.median_ms, r.min_ms, r.max_ms,
                    r.stddev_ms, r.input_mbps, r.output_mbps, r.fps);
    }

    const std::vector<uint8_t> rdp6 = MakeRdp6Argb();
    {
        auto r = RunThroughput("rdp6-argb", rdp6.size(), [&rdp6]() {
            rtsc::proto::DecodedBitmap bm;
            rtsc::proto::DecodeRdp6Bitmap(rdp6.data(), rdp6.size(), kWidth,
                                          kHeight, bm);
        });
        std::printf("%-16s %10.2f %9.3fms %9.3fms %9.3fms %9.3fms %11.1f %11.1f %7.1f\n",
                    r.name, r.input_bytes / 1e6, r.median_ms, r.min_ms, r.max_ms,
                    r.stddev_ms, r.input_mbps, r.output_mbps, r.fps);
    }

    const std::vector<uint8_t> aycocg = MakeRdp6AyCoCg();
    {
        auto r = RunThroughput("rdp6-aycocg", aycocg.size(), [&aycocg]() {
            rtsc::proto::DecodedBitmap bm;
            rtsc::proto::DecodeRdp6Bitmap(aycocg.data(), aycocg.size(), kWidth,
                                          kHeight, bm);
        });
        std::printf("%-16s %10.2f %9.3fms %9.3fms %9.3fms %9.3fms %11.1f %11.1f %7.1f\n",
                    r.name, r.input_bytes / 1e6, r.median_ms, r.min_ms, r.max_ms,
                    r.stddev_ms, r.input_mbps, r.output_mbps, r.fps);
    }

    const std::vector<uint8_t> nsc = MakeNsc();
    {
        auto r = RunThroughput("nsc-aycocg-cs", nsc.size(), [&nsc]() {
            rtsc::proto::DecodedBitmap bm;
            rtsc::proto::NscDecodeBitmap(nsc.data(), nsc.size(), kWidth,
                                         kHeight, bm);
        });
        std::printf("%-16s %10.2f %9.3fms %9.3fms %9.3fms %9.3fms %11.1f %11.1f %7.1f\n",
                    r.name, r.input_bytes / 1e6, r.median_ms, r.min_ms, r.max_ms,
                    r.stddev_ms, r.input_mbps, r.output_mbps, r.fps);
    }
    std::printf("\n");
}

void BenchmarkLoopback(bool tls_insecure) {
    std::printf("=== End-to-end loopback latency (scripted TLS, 1920x1080 frame) ===\n");

    std::string why;
    auto layer =
        rtsc::security::SecurityLayer::Create(MakeSecurityConfig(tls_insecure), why);
    if (!layer) {
        std::printf("  FAILED: could not create security layer: %s\n", why.c_str());
        return;
    }
    layer->SetTlsTransportForTest(std::make_unique<ScriptedTls>());
    if (!DriveHandshake(*layer)) {
        std::printf("  FAILED: handshake did not complete\n");
        return;
    }

    const std::vector<std::vector<uint8_t>> frame = MakeFrame();

    // Sanity check: decode one frame and confirm it landed pixels.
    {
        rtsc::client::GraphicsPipeline pipeline(kWidth, kHeight);
        for (const auto& pdu : frame) {
            const std::vector<uint8_t> cipher = layer->SendPdu(pdu);
            const auto frames = layer->ReceivePdu(cipher.data(), cipher.size());
            for (const auto& fr : frames) {
                rtsc::proto::FastPathOutputPdu parsed;
                if (rtsc::proto::FastPathOutputPdu::parse(
                        fr.data(), fr.size(), parsed) == rtsc::proto::Status::Ok) {
                    pipeline.ApplyFastPathOutput(parsed);
                }
            }
        }
        uint8_t r = 0, g = 0, b = 0, a = 0;
        if (!pipeline.surface().GetPixel(kWidth / 2, kHeight / 2, r, g, b, a)) {
            std::printf("  FAILED: surface has no center pixel\n");
            return;
        }
        std::printf("  frame PDUs: %zu (tiled %dx%d), center pixel = rgba(%u,%u,%u,%u)\n",
                    frame.size(), kTileW, kTileH, r, g, b, a);
    }

    // Warm up, then time each full-frame round trip.
    for (int i = 0; i < 3; ++i) {
        for (const auto& pdu : frame) {
            const std::vector<uint8_t> cipher = layer->SendPdu(pdu);
            layer->ReceivePdu(cipher.data(), cipher.size());
        }
    }
    std::vector<double> times;
    const int iters = 20;
    times.reserve(static_cast<size_t>(iters));
    for (int i = 0; i < iters; ++i) {
        const double t0 = NowSeconds();
        for (const auto& pdu : frame) {
            const std::vector<uint8_t> cipher = layer->SendPdu(pdu);
            layer->ReceivePdu(cipher.data(), cipher.size());
        }
        const double t1 = NowSeconds();
        times.push_back(t1 - t0);
    }
    const Stats st = ComputeStats(times);
    std::printf("  round-trip (encrypt+decrypt): median %.3fms  min %.3fms  max %.3fms  "
                "mean %.3fms  stddev %.3fms\n",
                st.median * 1000.0, st.min * 1000.0, st.max * 1000.0,
                st.mean * 1000.0, st.stddev * 1000.0);
    std::printf("  effective loopback throughput: %.1f MB/s (32bpp frame = %.2f MB)\n",
                static_cast<double>(kRgbaBytes) / (st.median * 1e6),
                static_cast<double>(kRgbaBytes) / 1e6);

    // End-to-end including the graphics-pipeline decode (transport + parse +
    // decode). One pipeline is reused, matching the real client's render path.
    rtsc::client::GraphicsPipeline pipeline(kWidth, kHeight);
    const double t0 = NowSeconds();
    for (const auto& pdu : frame) {
        const std::vector<uint8_t> cipher = layer->SendPdu(pdu);
        const auto frames = layer->ReceivePdu(cipher.data(), cipher.size());
        for (const auto& fr : frames) {
            rtsc::proto::FastPathOutputPdu parsed;
            if (rtsc::proto::FastPathOutputPdu::parse(
                    fr.data(), fr.size(), parsed) == rtsc::proto::Status::Ok) {
                pipeline.ApplyFastPathOutput(parsed);
            }
        }
    }
    const double t1 = NowSeconds();
    std::printf("  end-to-end frame (transport+parse+decode): %.3fms (%.1f fps)\n",
                (t1 - t0) * 1000.0, 1.0 / (t1 - t0));
    std::printf("\n");
}

void BenchmarkCpuOccupancy() {
    std::printf("=== Process CPU occupancy (decode workload) ===\n");

    const std::vector<uint8_t> rdp6 = MakeRdp6Argb();
    const int warmup = 3;
    for (int i = 0; i < warmup; ++i) {
        rtsc::proto::DecodedBitmap bm;
        rtsc::proto::DecodeRdp6Bitmap(rdp6.data(), rdp6.size(), kWidth, kHeight,
                                      bm);
    }

    const double kDurationSeconds = 2.0;
    const double wall0 = NowSeconds();
    const std::clock_t cpu0 = std::clock();
    const std::clock_t cpu_start = cpu0;
    int frames = 0;
    for (;;) {
        rtsc::proto::DecodedBitmap bm;
        rtsc::proto::DecodeRdp6Bitmap(rdp6.data(), rdp6.size(), kWidth, kHeight,
                                      bm);
        ++frames;
        if (NowSeconds() - wall0 >= kDurationSeconds) break;
    }
    const std::clock_t cpu1 = std::clock();
    const double wall1 = NowSeconds();

    const double cpu_seconds =
        static_cast<double>(cpu1 - cpu_start) / static_cast<double>(CLOCKS_PER_SEC);
    const double wall_seconds = wall1 - wall0;
    const double occupancy = cpu_seconds / wall_seconds;
    std::printf("  workload: rdp6-argb decode, %.1fs wall, %d frames (%.1f fps)\n",
                wall_seconds, frames, static_cast<double>(frames) / wall_seconds);
    std::printf("  CPU time: %.3fs  wall time: %.3fs  occupancy: %.1f%%\n",
                cpu_seconds, wall_seconds, occupancy * 100.0);
    std::printf("  (occupancy = process CPU time / wall time; 100%% = one full core)\n");
    std::printf("\n");
}

void PrintEnvironment() {
    std::printf("=== Environment ===\n");
#ifdef _WIN32
    std::printf("  OS:          Windows (_WIN32)\n");
#else
    std::printf("  OS:          POSIX\n");
#endif
#if defined(_MSC_VER)
    std::printf("  Compiler:    MSVC %d\n", _MSC_VER);
#elif defined(__clang__)
    std::printf("  Compiler:    Clang %d.%d.%d\n", __clang_major__,
                __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    std::printf("  Compiler:    GCC %d.%d.%d\n", __GNUC__, __GNUC_MINOR__,
                __GNUC_PATCHLEVEL__);
#else
    std::printf("  Compiler:    unknown\n");
#endif
#if defined(NDEBUG)
    std::printf("  Build type:  Release (NDEBUG)\n");
#else
    std::printf("  Build type:  Debug\n");
#endif
#if defined(_M_X64) || defined(__x86_64__)
    std::printf("  Arch:        x86_64\n");
#elif defined(_M_ARM64) || defined(__aarch64__)
    std::printf("  Arch:        ARM64\n");
#else
    std::printf("  Arch:        unknown\n");
#endif
    std::printf("  Frame size:  %ux%u (%zu pixels, %.2f MB RGBA8888)\n", kWidth,
                kHeight, kPixels, static_cast<double>(kRgbaBytes) / 1e6);
    std::printf("\n");
}

}  // namespace

int main(int argc, char** argv) {
    bool tls_insecure = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tls-insecure") == 0) {
            tls_insecure = true;
        }
    }
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("RTSC performance benchmark\n\n");
    PrintEnvironment();
    BenchmarkBitmapDecoders();
    BenchmarkLoopback(tls_insecure);
    BenchmarkCpuOccupancy();
    return 0;
}
