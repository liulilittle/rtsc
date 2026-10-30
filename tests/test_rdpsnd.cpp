// Audio virtual channel (rdpsnd) structure layer ([MS-RDPEA] 2.2).

#include "rtsc/proto/rdpsnd.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

RTSC_TEST(snd_prolog_parses) {
    // msgType = SNDC_FORMATS (7), bPad = 0, BodySize = 0x0020.
    const std::vector<uint8_t> b = {0x07, 0x00, 0x20, 0x00};
    SndProlog p;
    CHECK(SndProlog::parse(b.data(), b.size(), p) == Status::Ok);
    CHECK(p.msg_type == SndMsgType::kFormats);
    CHECK_EQ(p.body_size, static_cast<uint16_t>(0x20));
    CHECK(SndProlog::parse(b.data(), 3, p) == Status::NeedMoreData);
}

RTSC_TEST(snd_close_pdu_round_trip) {
    const auto pdu = BuildSndPdu(SndMsgType::kClose, {});
    CHECK_EQ(pdu.size(), static_cast<size_t>(4));
    CHECK_EQ(pdu[0], static_cast<uint8_t>(0x01));
    CHECK_EQ(pdu[2], static_cast<uint8_t>(0));

    SndPdu out;
    CHECK(SndPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK(out.prolog.msg_type == SndMsgType::kClose);
    CHECK(out.body.empty());
}

RTSC_TEST(snd_wave2_pdu_parses) {
    // Wave2 body: timeStamp, formatNo, blockNo, 3 pad, audioTimeStamp, data.
    ByteWriter body;
    body.u16le(0x1234);  // wTimeStamp
    body.u16le(3);       // wFormatNo
    body.u8(0x07);       // cBlockNo
    body.u8(0); body.u8(0); body.u8(0);  // bPad (3 bytes)
    body.u32le(0xAABBCCDD);  // dwAudioTimeStamp
    body.u8(0x11); body.u8(0x22); body.u8(0x33);  // audio data

    const auto pdu = BuildSndPdu(SndMsgType::kWave2, body.take());
    SndPdu out;
    CHECK(SndPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK(out.prolog.msg_type == SndMsgType::kWave2);

    SndWave2 w;
    CHECK(SndWave2::parse(out.body, w) == Status::Ok);
    CHECK_EQ(w.time_stamp, static_cast<uint16_t>(0x1234));
    CHECK_EQ(w.format_no, static_cast<uint16_t>(3));
    CHECK_EQ(w.block_no, static_cast<uint8_t>(0x07));
    CHECK_EQ(w.audio_time_stamp, static_cast<uint32_t>(0xAABBCCDD));
    CHECK_EQ(w.data.size(), static_cast<size_t>(3));
    CHECK_EQ(w.data[0], static_cast<uint8_t>(0x11));
}

RTSC_TEST(snd_wave_confirm_pdu) {
    // Wave Confirm: msgType SNDC_WAVECONFIRM, body = wTimeStamp + cConfirmedBlockNo.
    ByteWriter body;
    body.u16le(0x0001);  // wTimeStamp
    body.u8(0x42);       // cConfirmedBlockNo
    body.u8(0x00);       // pad
    const auto pdu = BuildSndPdu(SndMsgType::kWaveConfirm, body.take());

    SndPdu out;
    CHECK(SndPdu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK(out.prolog.msg_type == SndMsgType::kWaveConfirm);
    CHECK_EQ(out.body.size(), static_cast<size_t>(4));
    CHECK_EQ(out.body[2], static_cast<uint8_t>(0x42));
}

RTSC_TEST(snd_rejects_truncated_body) {
    // BodySize = 16 but only 2 bytes follow.
    const std::vector<uint8_t> pdu = {0x07, 0x00, 0x10, 0x00, 0xAA, 0xBB};
    SndPdu out;
    CHECK(SndPdu::parse(pdu.data(), pdu.size(), out) == Status::NeedMoreData);
}

RTSC_TEST(snd_wave2_rejects_short_body) {
    const std::vector<uint8_t> body = {0x01, 0x02, 0x03};
    SndWave2 w;
    CHECK(SndWave2::parse(body, w) == Status::NeedMoreData);
}

RTSC_TEST(snd_audio_format_parses) {
    // AUDIO_FORMAT: PCM, 2ch, 44100, avg, block align 4, 16-bit, cbSize 0.
    const std::vector<uint8_t> b = {
        0x01, 0x00, 0x02, 0x00, 0x44, 0xAC, 0x00, 0x00, 0x10, 0xB1,
        0x02, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00};
    SndAudioFormat f;
    CHECK(SndAudioFormat::parse(b.data(), b.size(), f) == Status::Ok);
    CHECK_EQ(f.format_tag, static_cast<uint16_t>(0x0001));
    CHECK_EQ(f.channels, static_cast<uint16_t>(2));
    CHECK_EQ(f.samples_per_sec, static_cast<uint32_t>(44100));
    CHECK_EQ(f.avg_bytes_per_sec, static_cast<uint32_t>(176400));
    CHECK_EQ(f.block_align, static_cast<uint16_t>(4));
    CHECK_EQ(f.bits_per_sample, static_cast<uint16_t>(16));
    CHECK_EQ(f.cb_size, static_cast<uint16_t>(0));
    CHECK(f.data.empty());
    CHECK(SndAudioFormat::parse(b.data(), b.size() - 1, f) ==
          Status::NeedMoreData);
}

RTSC_TEST(snd_audio_format_with_extra_data) {
    ByteWriter w;
    w.u16le(1);   // PCM
    w.u16le(1);   // mono
    w.u32le(8000);
    w.u32le(16000);
    w.u16le(2);
    w.u16le(16);
    w.u16le(2);   // cbSize
    w.u8(0xAA); w.u8(0xBB);
    const auto b = w.take();
    SndAudioFormat f;
    CHECK(SndAudioFormat::parse(b.data(), b.size(), f) == Status::Ok);
    CHECK_EQ(f.cb_size, static_cast<uint16_t>(2));
    CHECK_EQ(f.data.size(), static_cast<size_t>(2));
    CHECK_EQ(f.data[1], static_cast<uint8_t>(0xBB));
    // Write() must round-trip the whole structure.
    ByteWriter out;
    f.write(out);
    CHECK(out.data() == b);
}

RTSC_TEST(snd_server_formats_parses) {
    ByteWriter w;
    w.u32le(0x00000001);  // dwFlags
    w.u32le(0xFFFFFFFF);  // dwVolume
    w.u32le(0);           // dwPitch
    w.u16le(0);           // wDGramPort
    w.u16le(2);           // wNumberOfFormats
    w.u8(0);              // cLastBlockConfirmed
    w.u16le(8);           // wVersion
    w.u8(0);              // bPad
    // format 0: PCM 44100 stereo
    w.u16le(1); w.u16le(2); w.u32le(44100); w.u32le(176400); w.u16le(4);
    w.u16le(16); w.u16le(0);
    // format 1: PCM 48000 mono
    w.u16le(1); w.u16le(1); w.u32le(48000); w.u32le(96000); w.u16le(2);
    w.u16le(16); w.u16le(0);
    const auto body = w.take();

    SndServerFormats sf;
    CHECK(SndServerFormats::parse(body, sf) == Status::Ok);
    CHECK_EQ(sf.flags, static_cast<uint32_t>(1));
    CHECK_EQ(sf.volume, static_cast<uint32_t>(0xFFFFFFFF));
    CHECK_EQ(sf.number_of_formats, static_cast<uint16_t>(2));
    CHECK_EQ(sf.version, static_cast<uint16_t>(8));
    CHECK_EQ(sf.formats.size(), static_cast<size_t>(2));
    CHECK_EQ(sf.formats[0].samples_per_sec, static_cast<uint32_t>(44100));
    CHECK_EQ(sf.formats[0].channels, static_cast<uint16_t>(2));
    CHECK_EQ(sf.formats[1].samples_per_sec, static_cast<uint32_t>(48000));
    CHECK_EQ(sf.formats[1].channels, static_cast<uint16_t>(1));
    // A short body must be rejected, not silently truncated.
    CHECK(SndServerFormats::parse({body.begin(), body.end() - 1}, sf) ==
          Status::NeedMoreData);
}

RTSC_TEST(snd_client_formats_body_layout) {
    SndAudioFormat f;
    f.format_tag = 1;
    f.channels = 2;
    f.samples_per_sec = 44100;
    f.avg_bytes_per_sec = 176400;
    f.block_align = 4;
    f.bits_per_sample = 16;
    const auto body = BuildClientFormatsBody(0x00000003, 0xFFFFFFFF, 0, 0, 8, {f});
    // 20 bytes of fixed fields + one 18-byte format.
    CHECK_EQ(body.size(), static_cast<size_t>(38));
    // prolog-less body layout: dwFlags, dwVolume, dwPitch, wDGramPort,
    // wNumberOfFormats, cLastBlockConfirmed, wVersion, bPad.
    CHECK_EQ(body[0], static_cast<uint8_t>(0x03));
    CHECK_EQ(body[7], static_cast<uint8_t>(0xFF));
    CHECK_EQ(body[14], static_cast<uint8_t>(1));  // wNumberOfFormats low byte
    CHECK_EQ(body[17], static_cast<uint8_t>(8));  // wVersion low byte
    // The chosen format follows.
    SndAudioFormat out;
    CHECK(SndAudioFormat::parse(body.data() + 20, body.size() - 20, out) ==
          Status::Ok);
    CHECK_EQ(out.samples_per_sec, static_cast<uint32_t>(44100));
    CHECK_EQ(out.channels, static_cast<uint16_t>(2));
}

RTSC_TEST(snd_quality_mode_and_confirm_bodies) {
    const auto q = BuildQualityModeBody(kQualityHigh);
    CHECK_EQ(q.size(), static_cast<size_t>(4));
    CHECK_EQ(q[0], static_cast<uint8_t>(0x02));  // HIGH_QUALITY
    CHECK_EQ(q[1], static_cast<uint8_t>(0x00));

    const auto c = BuildWaveConfirmBody(0x1234, 0x42);
    CHECK_EQ(c.size(), static_cast<size_t>(4));
    CHECK_EQ(c[0], static_cast<uint8_t>(0x34));
    CHECK_EQ(c[1], static_cast<uint8_t>(0x12));
    CHECK_EQ(c[2], static_cast<uint8_t>(0x42));
    CHECK_EQ(c[3], static_cast<uint8_t>(0x00));

    const auto t = BuildTrainingConfirmBody(0xBEEF, 0x0100);
    CHECK_EQ(t.size(), static_cast<size_t>(4));
    CHECK_EQ(t[0], static_cast<uint8_t>(0xEF));
    CHECK_EQ(t[1], static_cast<uint8_t>(0xBE));
    CHECK_EQ(t[2], static_cast<uint8_t>(0x00));
    CHECK_EQ(t[3], static_cast<uint8_t>(0x01));
}

RTSC_TEST(snd_wave_info_parses) {
    ByteWriter w;
    w.u16le(0x1111);  // wTimeStamp
    w.u16le(0);       // wFormatNo
    w.u8(7);          // cBlockNo
    w.u8(0); w.u8(0); w.u8(0);  // bPad
    w.u8(0xDE); w.u8(0xAD); w.u8(0xBE); w.u8(0xEF);  // first 4 data bytes
    const auto body = w.take();
    SndWaveInfo info;
    CHECK(SndWaveInfo::parse(body, info) == Status::Ok);
    CHECK_EQ(info.time_stamp, static_cast<uint16_t>(0x1111));
    CHECK_EQ(info.block_no, static_cast<uint8_t>(7));
    CHECK_EQ(info.data.size(), static_cast<size_t>(4));
    CHECK_EQ(info.data[0], static_cast<uint8_t>(0xDE));
    const std::vector<uint8_t> short_body(body.begin(), body.end() - 1);
    CHECK(SndWaveInfo::parse(short_body, info) == Status::NeedMoreData);
}

RTSC_TEST(snd_wave2_write_round_trip) {
    // BuildWave2Body -> SndWave2::parse must round-trip the header fields and
    // the data, with the byte-exact 12-byte header layout preceding the data.
    const std::vector<uint8_t> data = {0x11, 0x22, 0x33};
    const auto body = BuildWave2Body(0x1234, 0, 0x07, 0xAABBCCDD, data);
    // 12-byte header + payload.
    CHECK_EQ(body.size(), static_cast<size_t>(15));
    // wTimeStamp(2) wFormatNo(2) cBlockNo(1) bPad(3) dwAudioTimeStamp(4) data.
    CHECK_BYTES(body, 0x34, 0x12, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xDD,
                0xCC, 0xBB, 0xAA, 0x11, 0x22, 0x33);

    SndWave2 parsed;
    CHECK(SndWave2::parse(body, parsed) == Status::Ok);
    CHECK_EQ(parsed.time_stamp, static_cast<uint16_t>(0x1234));
    CHECK_EQ(parsed.format_no, static_cast<uint16_t>(0));
    CHECK_EQ(parsed.block_no, static_cast<uint8_t>(0x07));
    CHECK_EQ(parsed.audio_time_stamp, static_cast<uint32_t>(0xAABBCCDD));
    CHECK(parsed.data == data);

    // A block number of 0 and an empty data payload are both legal.
    const auto empty = BuildWave2Body(0, 0, 0, 0, {});
    CHECK_EQ(empty.size(), static_cast<size_t>(12));
    SndWave2 p2;
    CHECK(SndWave2::parse(empty, p2) == Status::Ok);
    CHECK(p2.data.empty());
}

RTSC_TEST(snd_training_body_builder) {
    // Empty-body training (the v1 handshake form): wTimeStamp + wPackSize only.
    const auto body = BuildTrainingBody(0xBEEF, 0);
    CHECK_EQ(body.size(), static_cast<size_t>(4));
    CHECK_BYTES(body, 0xEF, 0xBE, 0x00, 0x00);
    SndTraining t;
    CHECK(SndTraining::parse(body, t) == Status::Ok);
    CHECK_EQ(t.time_stamp, static_cast<uint16_t>(0xBEEF));
    CHECK_EQ(t.pack_size, static_cast<uint16_t>(0));
    CHECK(t.data.empty());

    // With trailing exercise data the same body carries the payload after the
    // fixed 4-byte header, which SndTraining::parse must recover.
    const auto with_data = BuildTrainingBody(0x0001, 16, {0xAA, 0xBB});
    CHECK_EQ(with_data.size(), static_cast<size_t>(6));
    SndTraining t2;
    CHECK(SndTraining::parse(with_data, t2) == Status::Ok);
    CHECK_EQ(t2.pack_size, static_cast<uint16_t>(16));
    CHECK(t2.data.size() == 2 && t2.data[0] == static_cast<uint8_t>(0xAA));
}

RTSC_TEST(snd_parse_wave_confirm_body) {
    // wTimeStamp(2) + cConfirmedBlockNo(1) + bPad(1).
    const std::vector<uint8_t> good = {0x34, 0x12, 0x42, 0x00};
    SndWaveConfirm c;
    CHECK(ParseWaveConfirmBody(good, c) == Status::Ok);
    CHECK_EQ(c.time_stamp, static_cast<uint16_t>(0x1234));
    CHECK_EQ(c.block_no, static_cast<uint8_t>(0x42));
    CHECK_EQ(c.pad, static_cast<uint8_t>(0));

    // A truncation is a hard error, not a silent partial parse.
    CHECK(ParseWaveConfirmBody({}, c) == Status::NeedMoreData);
    CHECK(ParseWaveConfirmBody({0x34, 0x12, 0x42}, c) == Status::NeedMoreData);
}

RTSC_TEST(snd_parse_quality_mode_body) {
    // wQualityMode(2) + reserved(2).
    const std::vector<uint8_t> good = {0x02, 0x00, 0x00, 0x00};
    SndQualityModeBody q;
    CHECK(ParseQualityModeBody(good, q) == Status::Ok);
    CHECK_EQ(q.quality_mode, static_cast<uint16_t>(kQualityHigh));
    CHECK_EQ(q.reserved, static_cast<uint16_t>(0));

    // The build helper used by the client side must parse back.
    const auto built = BuildQualityModeBody(kQualityMedium);
    SndQualityModeBody q2;
    CHECK(ParseQualityModeBody(built, q2) == Status::Ok);
    CHECK_EQ(q2.quality_mode, static_cast<uint16_t>(kQualityMedium));

    CHECK(ParseQualityModeBody({0x02, 0x00}, q) == Status::NeedMoreData);
}

RTSC_TEST(snd_parse_training_confirm_body_echo) {
    // The client echoes the server's Training body verbatim; the layout is
    // SndTraining (wTimeStamp + wPackSize + optional data).
    const auto sent = BuildTrainingBody(0xCAFE, 0x0100);
    SndTraining echoed;
    CHECK(ParseTrainingConfirmBody(sent, echoed) == Status::Ok);
    CHECK_EQ(echoed.time_stamp, static_cast<uint16_t>(0xCAFE));
    CHECK_EQ(echoed.pack_size, static_cast<uint16_t>(0x0100));

    // BuildTrainingConfirmBody (the client's own writer) parses the same way.
    const auto client_pdu = BuildTrainingConfirmBody(0x1234, 0x5678);
    SndTraining t;
    CHECK(ParseTrainingConfirmBody(client_pdu, t) == Status::Ok);
    CHECK_EQ(t.time_stamp, static_cast<uint16_t>(0x1234));
    CHECK_EQ(t.pack_size, static_cast<uint16_t>(0x5678));

    CHECK(ParseTrainingConfirmBody({0xEF, 0xBE, 0x00}, t) == Status::NeedMoreData);
}

int main() { return ::rtsc::test::run_all("rtsc_rdpsnd_tests"); }
