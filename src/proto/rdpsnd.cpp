// Audio virtual channel (rdpsnd) structure layer ([MS-RDPEA] 2.2).

#include "rtsc/proto/rdpsnd.h"

namespace rtsc::proto {

const char* to_string(SndMsgType type) {
    switch (type) {
        case SndMsgType::kClose: return "close";
        case SndMsgType::kWave: return "wave";
        case SndMsgType::kSetVolume: return "set-volume";
        case SndMsgType::kSetPitch: return "set-pitch";
        case SndMsgType::kWaveConfirm: return "wave-confirm";
        case SndMsgType::kTraining: return "training";
        case SndMsgType::kFormats: return "formats";
        case SndMsgType::kCryptKey: return "crypt-key";
        case SndMsgType::kWaveEncrypt: return "wave-encrypt";
        case SndMsgType::kUdpWave: return "udp-wave";
        case SndMsgType::kUdpWaveLast: return "udp-wave-last";
        case SndMsgType::kQualityMode: return "quality-mode";
        case SndMsgType::kWave2: return "wave2";
    }
    return "unknown";
}

Status SndProlog::parse(const uint8_t* data, size_t size, SndProlog& out) {
    if (data == nullptr || size < kSize) return Status::NeedMoreData;
    out.msg_type = static_cast<SndMsgType>(data[0]);
    out.pad = data[1];
    out.body_size = static_cast<uint16_t>(data[2] | (data[3] << 8));
    return Status::Ok;
}

void SndProlog::write(ByteWriter& w) const {
    w.u8(static_cast<uint8_t>(msg_type));
    w.u8(pad);
    w.u16le(body_size);
}

Status SndPdu::parse(const uint8_t* data, size_t size, SndPdu& out) {
    out.body.clear();
    Status s = SndProlog::parse(data, size, out.prolog);
    if (s != Status::Ok) return s;
    if (size < SndProlog::kSize + out.prolog.body_size) {
        return Status::NeedMoreData;
    }
    out.body.assign(data + SndProlog::kSize,
                    data + SndProlog::kSize + out.prolog.body_size);
    return Status::Ok;
}

std::vector<uint8_t> BuildSndPdu(SndMsgType type,
                                 const std::vector<uint8_t>& body) {
    SndProlog p;
    p.msg_type = type;
    p.pad = 0;
    p.body_size = static_cast<uint16_t>(body.size());

    ByteWriter w;
    p.write(w);
    if (!body.empty()) w.bytes(body.data(), body.size());
    return w.take();
}

Status SndWave2::parse(const std::vector<uint8_t>& body, SndWave2& out) {
    out.data.clear();
    if (body.size() < 12) return Status::NeedMoreData;
    ByteReader r(body.data(), body.size());
    r.u16le(out.time_stamp);
    r.u16le(out.format_no);
    r.u8(out.block_no);
    uint8_t pad[3] = {0, 0, 0};
    r.bytes(pad, 3);
    r.u32le(out.audio_time_stamp);
    out.data.assign(r.cursor(), r.cursor() + r.remaining());
    return Status::Ok;
}

Status SndAudioFormat::parse(const uint8_t* data, size_t size, SndAudioFormat& out) {
    out.data.clear();
    if (data == nullptr || size < kFixedSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    r.u16le(out.format_tag);
    r.u16le(out.channels);
    r.u32le(out.samples_per_sec);
    r.u32le(out.avg_bytes_per_sec);
    r.u16le(out.block_align);
    r.u16le(out.bits_per_sample);
    r.u16le(out.cb_size);
    if (r.remaining() < out.cb_size) return Status::NeedMoreData;
    out.data.assign(r.cursor(), r.cursor() + out.cb_size);
    return Status::Ok;
}

void SndAudioFormat::write(ByteWriter& w) const {
    w.u16le(format_tag);
    w.u16le(channels);
    w.u32le(samples_per_sec);
    w.u32le(avg_bytes_per_sec);
    w.u16le(block_align);
    w.u16le(bits_per_sample);
    w.u16le(cb_size);
    if (cb_size != 0 && !data.empty()) w.bytes(data.data(), data.size());
}

Status SndServerFormats::parse(const std::vector<uint8_t>& body, SndServerFormats& out) {
    out.formats.clear();
    if (body.size() < kFixedSize) return Status::NeedMoreData;
    ByteReader r(body.data(), body.size());
    r.u32le(out.flags);
    r.u32le(out.volume);
    r.u32le(out.pitch);
    r.u16le(out.dgram_port);
    r.u16le(out.number_of_formats);
    r.u8(out.last_block_confirmed);
    r.u16le(out.version);
    r.u8(out.pad);
    for (uint16_t i = 0; i < out.number_of_formats; ++i) {
        SndAudioFormat f;
        if (r.remaining() < SndAudioFormat::kFixedSize) return Status::NeedMoreData;
        const size_t consumed = SndAudioFormat::kFixedSize;
        const Status s = SndAudioFormat::parse(r.cursor(), r.remaining(), f);
        if (s != Status::Ok) return s;
        r.skip(consumed + f.cb_size);
        out.formats.push_back(std::move(f));
    }
    return Status::Ok;
}

std::vector<uint8_t> BuildClientFormatsBody(
    uint32_t flags, uint32_t volume, uint32_t pitch, uint16_t dgram_port,
    uint16_t version, const std::vector<SndAudioFormat>& formats) {
    ByteWriter w;
    w.u32le(flags);
    w.u32le(volume);
    w.u32le(pitch);
    w.u16le(dgram_port);
    w.u16le(static_cast<uint16_t>(formats.size()));
    w.u8(0);  // cLastBlockConfirmed
    w.u16le(version);
    w.u8(0);  // bPad
    for (const auto& f : formats) f.write(w);
    return w.take();
}

std::vector<uint8_t> BuildQualityModeBody(uint16_t quality_mode) {
    ByteWriter w;
    w.u16le(quality_mode);
    w.u16le(0);  // reserved
    return w.take();
}

std::vector<uint8_t> BuildWaveConfirmBody(uint16_t time_stamp, uint8_t block_no) {
    ByteWriter w;
    w.u16le(time_stamp);
    w.u8(block_no);
    w.u8(0);  // bPad
    return w.take();
}

std::vector<uint8_t> BuildTrainingConfirmBody(uint16_t time_stamp,
                                              uint16_t pack_size) {
    ByteWriter w;
    w.u16le(time_stamp);
    w.u16le(pack_size);
    return w.take();
}

Status SndWaveInfo::parse(const std::vector<uint8_t>& body, SndWaveInfo& out) {
    out.data.clear();
    if (body.size() < kFixedSize) return Status::NeedMoreData;
    ByteReader r(body.data(), body.size());
    r.u16le(out.time_stamp);
    r.u16le(out.format_no);
    r.u8(out.block_no);
    uint8_t pad[3] = {0, 0, 0};
    r.bytes(pad, 3);
    out.data.assign(r.cursor(), r.cursor() + r.remaining());
    return Status::Ok;
}

Status SndTraining::parse(const std::vector<uint8_t>& body, SndTraining& out) {
    out.data.clear();
    if (body.size() < kFixedSize) return Status::NeedMoreData;
    ByteReader r(body.data(), body.size());
    r.u16le(out.time_stamp);
    r.u16le(out.pack_size);
    out.data.assign(r.cursor(), r.cursor() + r.remaining());
    return Status::Ok;
}

// ---- Wave2 / Training builders and the confirm-side parsers ----------------

std::vector<uint8_t> BuildWave2Body(uint16_t time_stamp, uint16_t format_no,
                                    uint8_t block_no, uint32_t audio_time_stamp,
                                    const std::vector<uint8_t>& data) {
    ByteWriter w;
    w.u16le(time_stamp);
    w.u16le(format_no);
    w.u8(block_no);
    w.u8(0); w.u8(0); w.u8(0);  // bPad (3 bytes)
    w.u32le(audio_time_stamp);
    if (!data.empty()) w.bytes(data.data(), data.size());
    return w.take();
}

std::vector<uint8_t> BuildTrainingBody(uint16_t time_stamp, uint16_t pack_size,
                                       const std::vector<uint8_t>& data) {
    ByteWriter w;
    w.u16le(time_stamp);
    w.u16le(pack_size);
    if (!data.empty()) w.bytes(data.data(), data.size());
    return w.take();
}

Status ParseWaveConfirmBody(const std::vector<uint8_t>& body,
                            SndWaveConfirm& out) {
    if (body.size() < SndWaveConfirm::kFixedSize) return Status::NeedMoreData;
    ByteReader r(body.data(), body.size());
    r.u16le(out.time_stamp);
    r.u8(out.block_no);
    r.u8(out.pad);
    return Status::Ok;
}

Status ParseQualityModeBody(const std::vector<uint8_t>& body,
                            SndQualityModeBody& out) {
    if (body.size() < SndQualityModeBody::kFixedSize) return Status::NeedMoreData;
    ByteReader r(body.data(), body.size());
    r.u16le(out.quality_mode);
    r.u16le(out.reserved);
    return Status::Ok;
}

Status ParseTrainingConfirmBody(const std::vector<uint8_t>& body,
                                SndTraining& out) {
    // The client echoes the Training PDU body verbatim ([MS-RDPEA] 2.2.3.2), so
    // the parsing is literally SndTraining's.
    return SndTraining::parse(body, out);
}

}  // namespace rtsc::proto
