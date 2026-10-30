// Server-side rdpsnd handler tests ([MS-RDPEA]). Covers design 7.1 (the
// six-phase state machine, negotiation timeouts, the 8-block in-flight
// window) and 7.2 (byte-exact Wire contract) plus the pre-flight gates:
//
//   S1 server SNDC_FORMATS / first Wave2 bytes are byte-exact and cross-check
//      against SndWave2::parse;
//   S2 the client's formats + ALIVE are received, validated, and answered with
//      a Quality Mode PDU (no premature Wave2 / Training);
//   S3 the training gate: no Wave2 before the client's Training Confirm;
//   S4 cBlockNo starts at 1 and wraps &0xFF;
//   S5 the 8-block window drops new input when full, old blocks stay intact;
//   S6 a training-confirm negotiation timeout ends the channel with SNDC_CLOSE;
//   S7 a client advertising ALIVE=0 never receives audio and never closes;
//   S8 malformed PDUs are counted and ignored without killing the session;
//   S9 a client that never answers formats times out to SNDC_CLOSE;
//   S10 the diagnostic counters reflect the exchange exactly.
// Plus the version<8 gate (no Wave2 for a pre-8 peer).

#include "rtsc/channel/rdpsnd_server.h"

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpsnd.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::channel::RdpsndServer;

namespace {

using Clock = std::chrono::steady_clock;
using rtsc::audio::AudioCaptureSource;
using rtsc::audio::PcmFormat;

// A scriptable capture source: returns the queued blocks in order, then stays
// silent. Start always succeeds so the negotiation path is reachable.
class FakeSource final : public AudioCaptureSource {
 public:
    explicit FakeSource(std::deque<std::vector<uint8_t>> blocks)
        : blocks_(std::move(blocks)) {}
    bool Start() override { running_ = true; return true; }
    void Stop() override { running_ = false; }
    bool Poll(std::vector<uint8_t>& pcm) override {
        if (!running_ || blocks_.empty()) {
            pcm.clear();
            return false;
        }
        pcm = blocks_.front();
        blocks_.pop_front();
        return true;
    }
    PcmFormat format() const override { return {2, 44100, 16}; }
    bool ok() const override { return running_; }
    bool running() const { return running_; }

 private:
    std::deque<std::vector<uint8_t>> blocks_;
    bool running_ = false;
};

std::unique_ptr<FakeSource> Source(std::vector<std::vector<uint8_t>> blocks) {
    return std::make_unique<FakeSource>(std::deque<std::vector<uint8_t>>(
        blocks.begin(), blocks.end()));
}

// Four-byte per-client block, small enough that the window arithmetic is easy
// to follow in the wrap / full tests.
std::vector<uint8_t> TaggedBlock(uint8_t tag) {
    return {0x10, tag, 0x20, 0x30};
}

// The single format the server advertises (design 7.2).
SndAudioFormat Advertised() {
    SndAudioFormat f;
    f.format_tag = SndAudioFormat::kFormatPcm;
    f.channels = 2;
    f.samples_per_sec = 44100;
    f.avg_bytes_per_sec = 176400;
    f.block_align = 4;
    f.bits_per_sample = 16;
    return f;
}

// Strips the 8-byte CHANNEL_PDU_HEADER leaving the rdpsnd PDU.
std::vector<uint8_t> Strict(const std::vector<uint8_t>& message) {
    return std::vector<uint8_t>(message.begin() + ChannelPduHeader::kSize,
                                message.end());
}

bool ParseMessage(const std::vector<uint8_t>& message, SndPdu& out) {
    return SndPdu::parse(Strict(message).data(), Strict(message).size(), out) ==
           Status::Ok;
}

size_t CountType(const std::vector<std::vector<uint8_t>>& sent,
                 SndMsgType type) {
    size_t n = 0;
    for (const auto& m : sent) {
        SndPdu p;
        if (ParseMessage(m, p) && p.prolog.msg_type == type) ++n;
    }
    return n;
}

std::optional<std::vector<uint8_t>> FirstBody(
    const std::vector<std::vector<uint8_t>>& sent, SndMsgType type) {
    for (const auto& m : sent) {
        SndPdu p;
        if (ParseMessage(m, p) && p.prolog.msg_type == type) return p.body;
    }
    return std::nullopt;
}

// The block numbers of every Wave2 PDU in `sent`, oldest first.
std::vector<uint8_t> Wave2Blocks(const std::vector<std::vector<uint8_t>>& sent,
                                 size_t from = 0) {
    std::vector<uint8_t> blocks;
    for (size_t i = from; i < sent.size(); ++i) {
        SndPdu p;
        if (!ParseMessage(sent[i], p)) continue;
        if (p.prolog.msg_type != SndMsgType::kWave2) continue;
        SndWave2 w;
        if (SndWave2::parse(p.body, w) != Status::Ok) continue;
        blocks.push_back(w.block_no);
    }
    return blocks;
}

// Feeds one complete rdpsnd PDU as one channel message.
void Feed(RdpsndServer& s, SndMsgType type, const std::vector<uint8_t>& body) {
    const auto pdu = BuildSndPdu(type, body);
    for (const auto& chunk : FragmentChannelMessage(pdu)) {
        s.OnChannelData(chunk.data(), chunk.size());
    }
}

// The client's Client Audio Formats PDU answering the server's offer.
void FeedClientFormats(RdpsndServer& s, uint16_t version = 8, bool alive = true,
                       const SndAudioFormat& format = Advertised()) {
    const uint32_t flags = alive ? kSndCapsAlive : 0;
    Feed(s, SndMsgType::kFormats,
         BuildClientFormatsBody(flags, 0xFFFFFFFF, 0, 0, version, {format}));
}

// Runs the whole negotiation up to kReady, assuming a version-8 client that
// answers formats, quality mode and training confirm.
void HandshakeReady(RdpsndServer& s) {
    FeedClientFormats(s);
    Feed(s, SndMsgType::kQualityMode, BuildQualityModeBody(kQualityHigh));
    Feed(s, SndMsgType::kTraining, BuildTrainingConfirmBody(0, 0));
}

std::vector<std::vector<uint8_t>> ManyBlocks(size_t n) {
    std::vector<std::vector<uint8_t>> blocks;
    blocks.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        blocks.push_back(TaggedBlock(static_cast<uint8_t>(i)));
    }
    return blocks;
}

}  // namespace

// S1: the server's opening SNDC_FORMATS carries the design-7.2 byte-exact
// AUDIO_FORMAT, and the first Wave2 PDU (post gate) is byte-exact too and
// cross-checks against SndWave2::parse.
RTSC_TEST(rdpsnd_server_s1_first_frame_bytes) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({{0x11, 0x22, 0x33, 0x44}}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); },
                   std::chrono::milliseconds(5000));
    const auto t0 = Clock::now();
    s.Start();
    CHECK(s.started());
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitClientFormats);

    // The SNDC_FORMATS body = 20 fixed bytes + one 18-byte AUDIO_FORMAT.
    const auto fmt_opt = FirstBody(sent, SndMsgType::kFormats);
    CHECK(fmt_opt.has_value());
    if (fmt_opt.has_value()) {
        const auto& b = *fmt_opt;
        CHECK_EQ(b.size(), static_cast<size_t>(38));
        CHECK_EQ(b[0], static_cast<uint8_t>(0x01));  // dwFlags = TSSNDCAPS_ALIVE
        CHECK_EQ(b[14], static_cast<uint8_t>(1));    // wNumberOfFormats low
        CHECK_EQ(b[15], static_cast<uint8_t>(0));
        CHECK_EQ(b[16], static_cast<uint8_t>(0));    // cLastBlockConfirmed
        CHECK_EQ(b[17], static_cast<uint8_t>(8));    // wVersion low
        // The single advertised format, byte-for-byte (44100/2ch/16bit).
        const std::vector<uint8_t> got_format(b.begin() + 20, b.end());
        const std::vector<uint8_t> want_format = {
            0x01, 0x00, 0x02, 0x00, 0x44, 0xAC, 0x00, 0x00, 0x10, 0xB1,
            0x02, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00};
        CHECK(got_format == want_format);
    }

    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));

    FeedClientFormats(s);
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitQualityMode);
    Feed(s, SndMsgType::kQualityMode, BuildQualityModeBody(kQualityHigh));
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitTrainingConfirm);

    // The empty-body training form (wPackSize = 0).
    const auto tr = FirstBody(sent, SndMsgType::kTraining);
    CHECK(tr.has_value());
    if (tr.has_value()) {
        CHECK_EQ(tr->size(), static_cast<size_t>(4));
        CHECK((*tr)[0] == 0 && (*tr)[1] == 0 && (*tr)[2] == 0 && (*tr)[3] == 0);
    }

    Feed(s, SndMsgType::kTraining, BuildTrainingConfirmBody(0, 0));
    CHECK(s.phase() == RdpsndServer::Phase::kReady);

    s.Poll(t0);  // first tick: fixes the timestamp epoch
    s.Poll(t0);  // second tick at the same instant: emits the first block
    CHECK_EQ(s.wave2_count(), static_cast<unsigned>(1));

    // Byte-exact first Wave2: prolog 0D 00 10 00, then a 12-byte header with
    // timeStamp=0, formatNo=0, blockNo=1, pad, audioTimeStamp=0, then data.
    std::optional<std::vector<uint8_t>> wave2_chunk;
    for (const auto& m : sent) {
        SndPdu p;
        if (ParseMessage(m, p) && p.prolog.msg_type == SndMsgType::kWave2) {
            wave2_chunk = Strict(m);
            break;
        }
    }
    CHECK(wave2_chunk.has_value());
    if (wave2_chunk.has_value()) {
        const std::vector<uint8_t> want = {
            0x0D, 0x00, 0x10, 0x00,                          // prolog
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,  // header
            0x00, 0x00, 0x00, 0x00,                          // audioTimeStamp
            0x11, 0x22, 0x33, 0x44};                         // data
        CHECK(*wave2_chunk == want);
    }

    // Cross-check: SndWave2::parse of the body recovers every field.
    const auto body_opt = FirstBody(sent, SndMsgType::kWave2);
    CHECK(body_opt.has_value());
    if (body_opt.has_value()) {
        SndWave2 parsed;
        CHECK(SndWave2::parse(*body_opt, parsed) == Status::Ok);
        CHECK_EQ(parsed.time_stamp, static_cast<uint16_t>(0));
        CHECK_EQ(parsed.format_no, static_cast<uint16_t>(0));
        CHECK_EQ(parsed.block_no, static_cast<uint8_t>(1));
        CHECK_EQ(parsed.audio_time_stamp, static_cast<uint32_t>(0));
        CHECK(parsed.data == std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
    }
    CHECK_EQ(s.in_flight(), static_cast<size_t>(1));
}

// S2: receiving the client's formats with ALIVE validates the exchange and
// answers with the Quality Mode PDU; nothing is streamed yet.
RTSC_TEST(rdpsnd_server_s2_client_formats_receipt) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({{0xAA}}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); },
                   std::chrono::milliseconds(5000));
    s.Start();
    const auto t0 = Clock::now();

    // A client formats PDU with garbage body counts as malformed, not a
    // negotiation event.
    Feed(s, SndMsgType::kFormats, {0x01});
    CHECK_EQ(s.client_formats_count(), static_cast<unsigned>(0));
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitClientFormats);

    FeedClientFormats(s);
    CHECK_EQ(s.client_formats_count(), static_cast<unsigned>(1));
    CHECK(s.client_alive());
    CHECK(s.format_valid());
    CHECK_EQ(s.client_version(), static_cast<uint16_t>(8));
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitQualityMode);

    // D-A: the Quality Mode PDU is client-to-server ([MS-RDPEA] 2.2.2.3), so
    // the server must not send one; it only advertises formats and waits.
    CHECK_EQ(CountType(sent, SndMsgType::kFormats), static_cast<size_t>(1));
    CHECK_EQ(CountType(sent, SndMsgType::kQualityMode), static_cast<size_t>(0));
    CHECK_EQ(CountType(sent, SndMsgType::kTraining), static_cast<size_t>(0));
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));

    // Even a Poll with source data must not stream in the negotiation states.
    s.Poll(t0);
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));
}

// S3: the training gate. Wave2 must not be sent until the client confirms the
// training exchange, and the wire order stays formats -> quality -> training ->
// wave2.
RTSC_TEST(rdpsnd_server_s3_training_gate) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({TaggedBlock(1)}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    const auto t0 = Clock::now();
    s.Start();

    FeedClientFormats(s);
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));
    s.Poll(t0);
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));

    Feed(s, SndMsgType::kQualityMode, BuildQualityModeBody(kQualityHigh));
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitTrainingConfirm);
    s.Poll(t0 + std::chrono::milliseconds(1));
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));

    Feed(s, SndMsgType::kTraining, BuildTrainingConfirmBody(0, 0));
    CHECK(s.phase() == RdpsndServer::Phase::kReady);

    s.Poll(t0);
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(1));

    std::vector<SndMsgType> types;
    for (const auto& m : sent) {
        SndPdu p;
        if (ParseMessage(m, p)) types.push_back(p.prolog.msg_type);
    }
    // D-A: the server never sends a Quality Mode PDU (client-to-server only),
    // so the outbound wire order is formats -> training -> wave2.
    const std::vector<SndMsgType> want = {SndMsgType::kFormats,
                                          SndMsgType::kTraining,
                                          SndMsgType::kWave2};
    CHECK(types == want);
}

// S4: cBlockNo starts at 1 and wraps through 255 to 0 (each block confirmed to
// keep the in-flight window open).
RTSC_TEST(rdpsnd_server_s4_block_no_wrap) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source(ManyBlocks(300)),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    const auto t0 = Clock::now();
    s.Start();
    HandshakeReady(s);

    for (int i = 0; i < 260; ++i) {
        s.Poll(t0 + std::chrono::milliseconds(25 * (i + 1)));
        const uint8_t expect = static_cast<uint8_t>((i + 1) & 0xFF);
        const auto blocks = Wave2Blocks(sent, 0);
        CHECK_EQ(blocks.size(), static_cast<size_t>(i + 1));
        if (blocks.empty() || blocks.back() != expect) {
            CHECK(blocks.empty() || blocks.back() == expect);
            break;  // the block numbers diverged; stop reporting
        }
        Feed(s, SndMsgType::kWaveConfirm, BuildWaveConfirmBody(0, expect));
    }
    CHECK_EQ(s.wave2_count(), static_cast<unsigned>(260));
    // First block is 1, and 255 then wraps to 0, then 1 again.
    const auto blocks = Wave2Blocks(sent);
    CHECK(!blocks.empty());
    CHECK_EQ(blocks[0], static_cast<uint8_t>(1));
    CHECK_EQ(blocks[254], static_cast<uint8_t>(255));
    CHECK_EQ(blocks[255], static_cast<uint8_t>(0));
    CHECK_EQ(blocks[256], static_cast<uint8_t>(1));
}

// S5: with a full 8-block in-flight window new input is dropped (counted) and
// the old blocks stay continuous; freeing a slot lets streaming resume.
RTSC_TEST(rdpsnd_server_s5_window_full_drops_new) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source(ManyBlocks(16)),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    const auto t0 = Clock::now();
    s.Start();
    HandshakeReady(s);
    CHECK_EQ(s.in_flight(), static_cast<size_t>(0));

    for (int i = 0; i < 8; ++i) {
        s.Poll(t0 + std::chrono::milliseconds(25 * (i + 1)));
    }
    CHECK_EQ(s.wave2_count(), static_cast<unsigned>(8));
    CHECK_EQ(s.in_flight(), static_cast<size_t>(8));
    CHECK_EQ(s.dropped_blocks(), static_cast<unsigned>(0));
    // The window holds blocks 1..8, sitting in order.
    CHECK(Wave2Blocks(sent) == std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8}));

    // One more tick with a full window: the source data is dropped, counted.
    s.Poll(t0 + std::chrono::milliseconds(25 * 9));
    CHECK_EQ(s.wave2_count(), static_cast<unsigned>(8));
    CHECK_EQ(s.dropped_blocks(), static_cast<unsigned>(1));

    // A confirm frees one slot; the next tick streams block 9.
    Feed(s, SndMsgType::kWaveConfirm, BuildWaveConfirmBody(0, 1));
    CHECK_EQ(s.in_flight(), static_cast<size_t>(7));
    s.Poll(t0 + std::chrono::milliseconds(25 * 10));
    CHECK_EQ(s.wave2_count(), static_cast<unsigned>(9));
    const auto blocks = Wave2Blocks(sent);
    CHECK(blocks ==
          std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8, 9}));
}

// S6: a client that never confirms the training PDU times the channel out
// (multi-second default, 50 ms injected here) into SNDC_CLOSE.
RTSC_TEST(rdpsnd_server_s6_training_confirm_timeout_closes) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({TaggedBlock(1)}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); },
                   std::chrono::milliseconds(50));
    s.Start();
    FeedClientFormats(s);
    Feed(s, SndMsgType::kQualityMode, BuildQualityModeBody(kQualityHigh));
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitTrainingConfirm);

    // One Poll before the deadline does nothing; after it the channel closes.
    s.Poll(Clock::now() + std::chrono::milliseconds(10));
    CHECK_EQ(s.close_sent_count(), static_cast<unsigned>(0));

    s.Poll(Clock::now() + std::chrono::milliseconds(120));
    CHECK_EQ(s.close_sent_count(), static_cast<unsigned>(1));
    CHECK_EQ(CountType(sent, SndMsgType::kClose), static_cast<size_t>(1));
    CHECK(s.phase() == RdpsndServer::Phase::kClosed);
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));
}

// S7: a client whose formats answer has ALIVE cleared never receives audio and
// the channel stays up without an SNDC_CLOSE (permanent silence, no timeout).
RTSC_TEST(rdpsnd_server_s7_alive_zero_stays_silent) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({TaggedBlock(1)}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    const auto t0 = Clock::now();
    s.Start();
    FeedClientFormats(s, /*version=*/8, /*alive=*/false);
    CHECK(!s.client_alive());
    CHECK(s.phase() == RdpsndServer::Phase::kReady);

    s.Poll(t0);
    s.Poll(t0 + std::chrono::milliseconds(1000));
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));
    CHECK_EQ(CountType(sent, SndMsgType::kClose), static_cast<size_t>(0));
    CHECK_EQ(s.close_sent_count(), static_cast<unsigned>(0));
    CHECK_EQ(s.dropped_blocks(), static_cast<unsigned>(0));
}

// S7b (D-E): a client whose formats answer is unusable (empty list, 8-bit PCM,
// or a selection outside the advertised format) is served permanent silence:
// format_valid() is false, the phase parks at kReady, nothing is ever closed,
// no Wave2 is produced, and capture is released (source stopped) so a real
// backend does not keep recording for a client that cannot play it.
RTSC_TEST(rdpsnd_server_invalid_format_silent) {
    struct Case {
        const char* name;
        SndAudioFormat format;
        uint16_t count;  // 0 => advertise an empty list
    };
    SndAudioFormat eight_bit = Advertised();
    eight_bit.bits_per_sample = 8;
    SndAudioFormat mono_48k = Advertised();
    mono_48k.channels = 1;
    mono_48k.samples_per_sec = 48000;
    const Case cases[] = {
        {"empty", Advertised(), 0},
        {"eight_bit", eight_bit, 1},
        {"not_advertised", mono_48k, 1},
    };

    for (const auto& c : cases) {
        std::vector<std::vector<uint8_t>> sent;
        auto source = std::make_unique<FakeSource>(
            std::deque<std::vector<uint8_t>>{TaggedBlock(1), TaggedBlock(2)});
        FakeSource* raw = source.get();
        RdpsndServer s(std::move(source),
                       [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
        const auto t0 = Clock::now();
        s.Start();
        CHECK(raw->running());

        const std::vector<uint8_t> body = BuildClientFormatsBody(
            kSndCapsAlive, 0xFFFFFFFF, 0, 0, 8,
            c.count == 0 ? std::vector<SndAudioFormat>{}
                         : std::vector<SndAudioFormat>{c.format});
        Feed(s, SndMsgType::kFormats, body);

        CHECK(!s.format_valid());
        CHECK(s.phase() == RdpsndServer::Phase::kReady);
        // Capture released: a real WASAPI backend must stop recording.
        CHECK(!raw->running());

        s.Poll(t0);
        s.Poll(t0 + std::chrono::milliseconds(25));
        s.Poll(t0 + std::chrono::milliseconds(1000));
        CHECK(CountType(sent, SndMsgType::kWave2) == 0);
        CHECK(s.wave2_count() == 0);
        CHECK(CountType(sent, SndMsgType::kClose) == 0);
        CHECK(s.close_sent_count() == 0);
    }
}

// S8: malformed / truncated channel data is counted and ignored; the session
// survives and a later valid formats PDU still works.
RTSC_TEST(rdpsnd_server_s8_malformed_ignored) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({TaggedBlock(1)}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    s.Start();

    // A channel chunk shorter than the CHANNEL_PDU_HEADER.
    const uint8_t junk[2] = {0xDE, 0xAD};
    s.OnChannelData(junk, 2);

    // A formats PDU whose body is truncated.
    Feed(s, SndMsgType::kFormats, {0x01});

    // A Wave Confirm PDU with a 2-byte body.
    Feed(s, SndMsgType::kWaveConfirm, {0x10, 0x20});

    CHECK(s.malformed_pdu_count() >= 3);
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitClientFormats);
    CHECK_EQ(CountType(sent, SndMsgType::kClose), static_cast<size_t>(0));

    // The session is unharmed by the garbage.
    FeedClientFormats(s);
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitQualityMode);
}

// S6b: a client that never sends its Quality Mode PDU is not fatal. The server
// advances to the training phase (missing quality = DYNAMIC_QUALITY, spec
// 3.3.5.1.1.3 note <19>): a Training PDU goes out, no SNDC_CLOSE, and the
// client's later training confirm still completes the handshake.
RTSC_TEST(rdpsnd_server_quality_timeout_advances_to_training) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({TaggedBlock(1)}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); },
                   std::chrono::milliseconds(50));
    s.Start();
    FeedClientFormats(s);
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitQualityMode);
    CHECK_EQ(CountType(sent, SndMsgType::kTraining),
             static_cast<size_t>(0));

    // One Poll before the deadline does nothing.
    s.Poll(Clock::now() + std::chrono::milliseconds(10));
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitQualityMode);
    CHECK_EQ(CountType(sent, SndMsgType::kTraining),
             static_cast<size_t>(0));
    CHECK_EQ(s.close_sent_count(), static_cast<unsigned>(0));

    // After the deadline the server proceeds to training: non-fatal.
    s.Poll(Clock::now() + std::chrono::milliseconds(120));
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitTrainingConfirm);
    CHECK_EQ(CountType(sent, SndMsgType::kTraining),
             static_cast<size_t>(1));
    CHECK_EQ(CountType(sent, SndMsgType::kClose),
             static_cast<size_t>(0));
    CHECK_EQ(s.close_sent_count(), static_cast<unsigned>(0));
    CHECK_EQ(s.training_sent_count(), static_cast<unsigned>(1));
    CHECK_EQ(CountType(sent, SndMsgType::kWave2),
             static_cast<size_t>(0));

    // The delayed training confirm still completes the exchange.
    Feed(s, SndMsgType::kTraining, BuildTrainingConfirmBody(0, 0));
    CHECK(s.phase() == RdpsndServer::Phase::kReady);
}

// S9: a client that never answers the opening SNDC_FORMATS times the channel
// out into SNDC_CLOSE.
RTSC_TEST(rdpsnd_server_s9_formats_timeout_closes) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({TaggedBlock(1)}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); },
                   std::chrono::milliseconds(50));
    s.Start();
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitClientFormats);

    s.Poll(Clock::now() + std::chrono::milliseconds(120));
    CHECK_EQ(s.close_sent_count(), static_cast<unsigned>(1));
    CHECK_EQ(CountType(sent, SndMsgType::kClose), static_cast<size_t>(1));
    CHECK(s.phase() == RdpsndServer::Phase::kClosed);
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));
}

// S10: the exchange counters reflect exactly what happened: one of each
// handshake step, three Wave2 with two confirms, one block still in flight.
RTSC_TEST(rdpsnd_server_s10_counts) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({TaggedBlock(1), TaggedBlock(2), TaggedBlock(3)}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    const auto t0 = Clock::now();
    s.Start();
    HandshakeReady(s);

    s.Poll(t0);
    s.Poll(t0 + std::chrono::milliseconds(25));
    s.Poll(t0 + std::chrono::milliseconds(50));
    Feed(s, SndMsgType::kWaveConfirm, BuildWaveConfirmBody(0, 1));
    Feed(s, SndMsgType::kWaveConfirm, BuildWaveConfirmBody(0, 2));

    CHECK_EQ(s.server_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(s.client_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(s.quality_mode_count(), static_cast<unsigned>(1));
    CHECK_EQ(s.training_sent_count(), static_cast<unsigned>(1));
    CHECK_EQ(s.training_confirm_count(), static_cast<unsigned>(1));
    CHECK_EQ(s.wave2_count(), static_cast<unsigned>(3));
    CHECK_EQ(s.wave_confirm_count(), static_cast<unsigned>(2));
    CHECK_EQ(s.bytes_sent(), static_cast<size_t>(3 * TaggedBlock(0).size()));
    CHECK_EQ(s.in_flight(), static_cast<size_t>(1));
    CHECK_EQ(s.dropped_blocks(), static_cast<unsigned>(0));
    CHECK_EQ(s.malformed_pdu_count(), static_cast<unsigned>(0));
    CHECK_EQ(s.out_of_order_count(), static_cast<unsigned>(0));
    CHECK_EQ(s.close_sent_count(), static_cast<unsigned>(0));
    CHECK(s.phase() == RdpsndServer::Phase::kReady);
}

// A pre-8 client (design: v1 streams Wave2 only) concludes the handshake but
// never receives a Wave2 PDU.
RTSC_TEST(rdpsnd_server_version7_no_wave2) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({TaggedBlock(1)}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    const auto t0 = Clock::now();
    s.Start();
    // Version 7 still enters the client-driven Quality Mode wait but cannot
    // stream Wave2.
    FeedClientFormats(s, /*version=*/7, /*alive=*/true);
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitQualityMode);
    Feed(s, SndMsgType::kQualityMode, BuildQualityModeBody(kQualityHigh));
    Feed(s, SndMsgType::kTraining, BuildTrainingConfirmBody(0, 0));
    CHECK(s.phase() == RdpsndServer::Phase::kReady);

    s.Poll(t0);
    CHECK_EQ(CountType(sent, SndMsgType::kWave2), static_cast<size_t>(0));
    CHECK_EQ(s.wave2_count(), static_cast<unsigned>(0));
    CHECK_EQ(s.dropped_blocks(), static_cast<unsigned>(0));
}

// A version 5 client skips the Quality Mode phase entirely and goes straight
// to training (design addition: version < 6 does not wait for a quality mode).
RTSC_TEST(rdpsnd_server_version5_skips_quality_mode) {
    std::vector<std::vector<uint8_t>> sent;
    RdpsndServer s(Source({TaggedBlock(1)}),
                   [&](const std::vector<uint8_t>& m) { sent.push_back(m); });
    s.Start();
    FeedClientFormats(s, /*version=*/5, /*alive=*/true);
    // No quality mode phase: straight to awaiting the training confirm.
    CHECK(s.phase() == RdpsndServer::Phase::kAwaitTrainingConfirm);
    CHECK_EQ(CountType(sent, SndMsgType::kTraining), static_cast<size_t>(1));
}

int main() { return rtsc::test::run_all("rtsc_rdpsnd_server_tests"); }