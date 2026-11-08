// rdpsnd virtual channel handler tests ([MS-RDPEA]).
//
// A mock AudioPlayer records the PCM and format it is asked to play, and the
// handler's outbound channel messages are captured so the Client Audio Formats,
// Quality Mode, Training Confirm and Wave Confirm PDUs can be inspected.

#include "rtsc/channel/rdpsnd_client.h"

#include <cstdint>
#include <optional>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpsnd.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

class MockPlayer final : public rtsc::audio::AudioSink {
 public:
    void Submit(const std::vector<uint8_t>& pcm,
                const rtsc::audio::PcmFormat& format) override {
        ++plays;
        last_pcm = pcm;
        last_channels = format.channels;
        last_rate = format.samples_per_sec;
        last_bits = format.bits_per_sample;
    }
    void SetVolume(uint16_t left, uint16_t right) override {
        ++volume_calls;
        last_volume = static_cast<uint32_t>(left) |
                      (static_cast<uint32_t>(right) << 16);
    }
    bool ok() const override { return true; }

    unsigned plays = 0;
    std::vector<uint8_t> last_pcm;
    uint16_t last_channels = 0;
    uint32_t last_rate = 0;
    uint16_t last_bits = 0;
    unsigned volume_calls = 0;
    uint32_t last_volume = 0;
};

// Wraps one rdpsnd PDU in a channel message (CHANNEL_PDU_HEADER + PDU).
std::vector<std::vector<uint8_t>> ChannelChunks(const std::vector<uint8_t>& pdu,
                                                size_t chunk_size = 1600) {
    return FragmentChannelMessage(pdu, chunk_size);
}

// Feeds a whole rdpsnd PDU to the handler as one channel message.
void FeedPdu(rtsc::channel::RdpsndClient& c, SndMsgType type,
             const std::vector<uint8_t>& body) {
    const auto pdu = BuildSndPdu(type, body);
    const auto chunks = ChannelChunks(pdu);
    for (const auto& chunk : chunks) c.OnChannelData(chunk.data(), chunk.size());
}

bool ParseSent(const std::vector<uint8_t>& message, SndPdu& out) {
    if (message.size() < ChannelPduHeader::kSize + SndProlog::kSize) {
        return false;
    }
    return SndPdu::parse(message.data() + ChannelPduHeader::kSize,
                         message.size() - ChannelPduHeader::kSize, out) ==
           Status::Ok;
}

std::optional<std::vector<uint8_t>> FindSentBody(
    const std::vector<std::vector<uint8_t>>& sent, SndMsgType type) {
    for (const auto& message : sent) {
        SndPdu pdu;
        if (ParseSent(message, pdu) && pdu.prolog.msg_type == type) {
            return pdu.body;
        }
    }
    return std::nullopt;
}

SndAudioFormat PcmFormat(uint16_t channels, uint32_t rate) {
    SndAudioFormat f;
    f.format_tag = 1;
    f.channels = channels;
    f.samples_per_sec = rate;
    f.avg_bytes_per_sec = rate * channels * 2;
    f.block_align = static_cast<uint16_t>(channels * 2);
    f.bits_per_sample = 16;
    return f;
}

std::vector<uint8_t> ServerFormatsBody(const std::vector<SndAudioFormat>& formats,
                                       uint16_t version) {
    ByteWriter w;
    w.u32le(0x00000001);
    w.u32le(0xFFFFFFFF);
    w.u32le(0);
    w.u16le(0);
    w.u16le(static_cast<uint16_t>(formats.size()));
    w.u8(0);
    w.u16le(version);
    w.u8(0);
    for (const auto& f : formats) f.write(w);
    return w.take();
}

std::vector<uint8_t> Wave2Body(uint16_t time_stamp, uint8_t block_no,
                               const std::vector<uint8_t>& data,
                               uint16_t format_no = 0) {
    ByteWriter w;
    w.u16le(time_stamp);
    w.u16le(format_no);  // index into the client's format list
    w.u8(block_no);
    w.u8(0); w.u8(0); w.u8(0);
    w.u32le(0x11223344);
    w.bytes(data.data(), data.size());
    return w.take();
}

}  // namespace

RTSC_TEST(rdpsnd_server_formats_triggers_client_formats) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });

    const std::vector<SndAudioFormat> formats = {
        PcmFormat(1, 8000),    // lower priority
        PcmFormat(2, 44100),   // preferred
        PcmFormat(2, 48000),
    };
    FeedPdu(client, SndMsgType::kFormats, ServerFormatsBody(formats, 8));

    CHECK_EQ(client.server_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.server_version(), static_cast<uint16_t>(8));
    // The handler must pick the 44100 Hz stereo PCM format.
    const SndAudioFormat& chosen = client.selected_format();
    CHECK_EQ(chosen.samples_per_sec, static_cast<uint32_t>(44100));
    CHECK_EQ(chosen.channels, static_cast<uint16_t>(2));
    CHECK_EQ(chosen.bits_per_sample, static_cast<uint16_t>(16));

    // Client Audio Formats PDU ...
    const auto cf = FindSentBody(sent, SndMsgType::kFormats);
    CHECK(cf.has_value());
    CHECK_EQ(client.client_formats_count(), static_cast<unsigned>(1));
    if (cf.has_value()) {
        CHECK(cf->size() >= static_cast<size_t>(20));
        const uint32_t flags = static_cast<uint32_t>((*cf)[0]) |
                               (static_cast<uint32_t>((*cf)[1]) << 8) |
                               (static_cast<uint32_t>((*cf)[2]) << 16) |
                               (static_cast<uint32_t>((*cf)[3]) << 24);
        CHECK((flags & kSndCapsAlive) != 0);
        CHECK((flags & kSndCapsVolume) != 0);
        CHECK_EQ((*cf)[14], static_cast<uint8_t>(1));  // wNumberOfFormats
        CHECK_EQ((*cf)[17], static_cast<uint8_t>(8));  // wVersion
    }
    // ... followed by the mandatory Quality Mode PDU (version >= 6).
    const auto qm = FindSentBody(sent, SndMsgType::kQualityMode);
    CHECK(qm.has_value());
    CHECK_EQ(client.quality_mode_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpsnd_wave2_plays_and_confirms) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });

    FeedPdu(client, SndMsgType::kFormats,
            ServerFormatsBody({PcmFormat(2, 44100)}, 8));

    const std::vector<uint8_t> pcm = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    FeedPdu(client, SndMsgType::kWave2, Wave2Body(0x4242, 9, pcm));

    CHECK_EQ(client.wave2_count(), static_cast<unsigned>(1));
    CHECK_EQ(player.plays, static_cast<unsigned>(1));
    CHECK(player.last_pcm == pcm);
    CHECK_EQ(player.last_rate, static_cast<uint32_t>(44100));
    CHECK_EQ(player.last_channels, static_cast<uint16_t>(2));
    CHECK_EQ(client.bytes_played(), pcm.size());
    CHECK(client.audio_received());

    const auto confirm = FindSentBody(sent, SndMsgType::kWaveConfirm);
    CHECK(confirm.has_value());
    CHECK_EQ(client.wave_confirm_count(), static_cast<unsigned>(1));
    if (confirm.has_value()) {
        CHECK_EQ(confirm->size(), static_cast<size_t>(4));
        CHECK_EQ((*confirm)[0], static_cast<uint8_t>(0x42));  // wTimeStamp low
        CHECK_EQ((*confirm)[2], static_cast<uint8_t>(9));     // cConfirmedBlockNo
    }
}

RTSC_TEST(rdpsnd_wave2_split_across_chunks) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });
    FeedPdu(client, SndMsgType::kFormats,
            ServerFormatsBody({PcmFormat(2, 44100)}, 8));

    const std::vector<uint8_t> pcm = {1, 2, 3, 4, 5, 6, 7, 8};
    const auto pdu = BuildSndPdu(SndMsgType::kWave2, Wave2Body(7, 3, pcm));
    // Split the Wave2 PDU into 3-byte chunks to exercise reassembly.
    const auto chunks = ChannelChunks(pdu, 3);
    CHECK(chunks.size() > 1);
    for (const auto& chunk : chunks) {
        client.OnChannelData(chunk.data(), chunk.size());
    }

    CHECK_EQ(player.plays, static_cast<unsigned>(1));
    CHECK(player.last_pcm == pcm);
    CHECK_EQ(client.wave_confirm_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpsnd_training_confirm_echoes_fields) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });

    ByteWriter w;
    w.u16le(0xCAFE);  // wTimeStamp
    w.u16le(0x0100);  // wPackSize
    FeedPdu(client, SndMsgType::kTraining, w.take());

    const auto confirm = FindSentBody(sent, SndMsgType::kTraining);
    CHECK(confirm.has_value());
    CHECK_EQ(client.training_confirm_count(), static_cast<unsigned>(1));
    if (confirm.has_value()) {
        CHECK_EQ(confirm->size(), static_cast<size_t>(4));
        CHECK_EQ((*confirm)[0], static_cast<uint8_t>(0xFE));
        CHECK_EQ((*confirm)[1], static_cast<uint8_t>(0xCA));
        CHECK_EQ((*confirm)[2], static_cast<uint8_t>(0x00));
        CHECK_EQ((*confirm)[3], static_cast<uint8_t>(0x01));
    }
}

RTSC_TEST(rdpsnd_set_volume_reaches_player) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });

    const std::vector<uint8_t> vol = {0x34, 0x12, 0x78, 0x56};
    FeedPdu(client, SndMsgType::kSetVolume, vol);
    CHECK_EQ(player.volume_calls, static_cast<unsigned>(1));
    CHECK_EQ(player.last_volume, static_cast<uint32_t>(0x56781234));
}

RTSC_TEST(rdpsnd_wave_info_pair_plays_and_confirms) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });
    FeedPdu(client, SndMsgType::kFormats,
            ServerFormatsBody({PcmFormat(2, 44100)}, 8));

    // WaveInfo PDU: 12-byte body (wTimeStamp + wFormatNo + cBlockNo + bPad + 4
    // data bytes). The continuation Wave PDU carries the remaining data.
    ByteWriter info;
    info.u16le(0x2222);
    info.u16le(0);
    info.u8(4);
    info.u8(0); info.u8(0); info.u8(0);
    info.u8(0x10); info.u8(0x20); info.u8(0x30); info.u8(0x40);
    FeedPdu(client, SndMsgType::kWave, info.take());

    ByteWriter cont;
    cont.u32le(0);  // bPad
    cont.u8(0x50); cont.u8(0x60);
    FeedPdu(client, SndMsgType::kWave, cont.take());

    CHECK_EQ(player.plays, static_cast<unsigned>(1));
    const std::vector<uint8_t> want = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    CHECK(player.last_pcm == want);
    CHECK_EQ(client.wave_confirm_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rdpsnd_unknown_format_is_ignored) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });
    // A non-PCM format (e.g. A-law) is not playable by this backend.
    SndAudioFormat f = PcmFormat(2, 44100);
    f.format_tag = 6;
    f.bits_per_sample = 8;
    FeedPdu(client, SndMsgType::kFormats, ServerFormatsBody({f}, 8));

    CHECK_EQ(client.client_formats_count(), static_cast<unsigned>(0));
    CHECK_EQ(player.plays, static_cast<unsigned>(0));
}

RTSC_TEST(rdpsnd_wave2_out_of_range_format_is_rejected) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });
    FeedPdu(client, SndMsgType::kFormats,
            ServerFormatsBody({PcmFormat(2, 44100)}, 8));
    CHECK_EQ(client.client_formats_count(), static_cast<unsigned>(1));

    // wFormatNo indexes the client's own format list ([MS-RDPEA] 2.2.3.4 and
    // 3.1.1.2). Index 1 does not exist when the client advertised one format:
    // the sample must be dropped, not silently played with format 0.
    const std::vector<uint8_t> pcm = {1, 2, 3, 4};
    FeedPdu(client, SndMsgType::kWave2, Wave2Body(7, 3, pcm, 1));

    CHECK_EQ(player.plays, static_cast<unsigned>(0));
    CHECK_EQ(client.bytes_played(), static_cast<size_t>(0));
    CHECK(!client.audio_received());
    CHECK_EQ(client.format_reject_count(), static_cast<unsigned>(1));
    // A rejected sample was never consumed, so no Wave Confirm is owed.
    CHECK(!FindSentBody(sent, SndMsgType::kWaveConfirm).has_value());
}

RTSC_TEST(rdpsnd_wave_info_out_of_range_format_is_rejected) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });
    FeedPdu(client, SndMsgType::kFormats,
            ServerFormatsBody({PcmFormat(2, 44100)}, 8));

    ByteWriter info;
    info.u16le(0x2222);
    info.u16le(1);  // out-of-range wFormatNo
    info.u8(4);
    info.u8(0); info.u8(0); info.u8(0);
    info.u8(0x10); info.u8(0x20); info.u8(0x30); info.u8(0x40);
    FeedPdu(client, SndMsgType::kWave, info.take());

    // The Wave continuation that follows a rejected WaveInfo must be swallowed:
    // it carries no header of its own, so parsing it as a fresh WaveInfo would
    // resurrect the sample under format 0. The payload below is deliberately
    // shaped so a misparse would produce a valid format-0 WaveInfo.
    ByteWriter cont;
    cont.u16le(0x3333);  // would-be wTimeStamp
    cont.u16le(0);       // would-be wFormatNo (valid index)
    cont.u8(7);          // would-be cBlockNo
    cont.u8(0); cont.u8(0); cont.u8(0);
    cont.u8(0x50); cont.u8(0x60); cont.u8(0x70); cont.u8(0x80);
    FeedPdu(client, SndMsgType::kWave, cont.take());

    // A further Wave PDU would complete that bogus sample if it had been kept.
    ByteWriter tail;
    tail.u32le(0);  // bPad
    tail.u8(0x90); tail.u8(0xA0);
    FeedPdu(client, SndMsgType::kWave, tail.take());

    CHECK_EQ(player.plays, static_cast<unsigned>(0));
    CHECK_EQ(client.format_reject_count(), static_cast<unsigned>(1));
    CHECK(!FindSentBody(sent, SndMsgType::kWaveConfirm).has_value());
}

// A Wave2 PDU before any format exchange has no format list at all: the index
// is necessarily out of range and must be rejected.
RTSC_TEST(rdpsnd_wave2_without_format_exchange_is_rejected) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });

    const std::vector<uint8_t> pcm = {9, 9};
    FeedPdu(client, SndMsgType::kWave2, Wave2Body(1, 0, pcm));

    CHECK_EQ(player.plays, static_cast<unsigned>(0));
    CHECK_EQ(client.format_reject_count(), static_cast<unsigned>(1));
    CHECK(!FindSentBody(sent, SndMsgType::kWaveConfirm).has_value());
}

// After a reconnect the server re-runs the format exchange. Reset() must drop
// the old session's formats and counters so the new Server Audio Formats PDU
// is answered with a fresh Client Audio Formats PDU.
RTSC_TEST(rdpsnd_reset_allows_a_second_format_exchange) {
    MockPlayer player;
    std::vector<std::vector<uint8_t>> sent;
    rtsc::channel::RdpsndClient client(&player, [&](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });

    const std::vector<SndAudioFormat> formats = {PcmFormat(2, 44100)};
    FeedPdu(client, SndMsgType::kFormats, ServerFormatsBody(formats, 8));
    CHECK_EQ(client.server_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.client_formats_count(), static_cast<unsigned>(1));

    client.Reset();
    CHECK_EQ(client.server_formats_count(), static_cast<unsigned>(0));
    CHECK_EQ(client.client_formats_count(), static_cast<unsigned>(0));
    CHECK_EQ(client.server_version(), static_cast<uint16_t>(0));
    CHECK_EQ(client.selected_format().samples_per_sec, static_cast<uint32_t>(0));

    sent.clear();
    FeedPdu(client, SndMsgType::kFormats, ServerFormatsBody(formats, 8));
    CHECK_EQ(client.server_formats_count(), static_cast<unsigned>(1));
    CHECK_EQ(client.client_formats_count(), static_cast<unsigned>(1));
    CHECK(FindSentBody(sent, SndMsgType::kFormats).has_value());
}

int main() { return ::rtsc::test::run_all("rtsc_rdpsnd_client_tests"); }
