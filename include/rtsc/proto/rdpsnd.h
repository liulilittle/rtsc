// Audio virtual channel (rdpsnd) structure layer ([MS-RDPEA] 2.2).
//
// Reference: [MS-RDPEA] 2.2.1 (SNDPROLOG), 2.2.2.1.1 (AUDIO_FORMAT),
// 2.2.2.1 (Server Audio Formats and Version PDU), 2.2.2.2 (Client Audio
// Formats and Version PDU), 2.2.2.3 (Quality Mode PDU), 2.2.3.1 (Training
// PDU), 2.2.3.3 (WaveInfo PDU) and 2.2.3.4 (Wave2 PDU).
//
// Every rdpsnd PDU begins with a 4-byte SNDPROLOG (msgType + bPad + BodySize).
// For SNDC_WAVE the BodySize field has a different meaning; this module treats
// it as the body length (correct for every other type and for Wave2).

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// SNDPROLOG.msgType ([MS-RDPEA] 2.2.1).
enum class SndMsgType : uint8_t {
    kClose = 0x01,
    kWave = 0x02,
    kSetVolume = 0x03,
    kSetPitch = 0x04,
    kWaveConfirm = 0x05,
    kTraining = 0x06,
    kFormats = 0x07,
    kCryptKey = 0x08,
    kWaveEncrypt = 0x09,
    kUdpWave = 0x0A,
    kUdpWaveLast = 0x0B,
    kQualityMode = 0x0C,
    kWave2 = 0x0D,
};

const char* to_string(SndMsgType type);

// Capability flags in the Client Audio Formats and Version PDU dwFlags field
// ([MS-RDPEA] 2.2.2.2).
enum SndCapability : uint32_t {
    kSndCapsAlive = 0x00000001,  // client can consume audio data
    kSndCapsVolume = 0x00000002,  // client applies volume changes
    kSndCapsPitch = 0x00000004,  // client applies pitch changes
};

// wQualityMode values in the Quality Mode PDU ([MS-RDPEA] 2.2.2.3).
enum SndQualityMode : uint16_t {
    kQualityDynamic = 0x0000,
    kQualityMedium = 0x0001,
    kQualityHigh = 0x0002,
};

// Protocol versions reported in the wVersion field ([MS-RDPEA] 2.2.2.2).
enum SndVersion : uint16_t {
    kSndVersionWin8 = 0x0008,  // Wave2 is used when both peers are >= 8
};

// SNDPROLOG ([MS-RDPEA] 2.2.1), 4 bytes.
struct SndProlog {
    static constexpr size_t kSize = 4;

    SndMsgType msg_type = SndMsgType::kClose;
    uint8_t pad = 0;
    uint16_t body_size = 0;

    static Status parse(const uint8_t* data, size_t size, SndProlog& out);
    void write(ByteWriter& w) const;
};

// A parsed rdpsnd PDU: prolog + body.
struct SndPdu {
    SndProlog prolog;
    std::vector<uint8_t> body;

    static Status parse(const uint8_t* data, size_t size, SndPdu& out);
};

// Builds a complete rdpsnd PDU (prolog + body).
std::vector<uint8_t> BuildSndPdu(SndMsgType type,
                                 const std::vector<uint8_t>& body);

// AUDIO_FORMAT ([MS-RDPEA] 2.2.2.1.1), 18 bytes plus cbSize of extra data.
struct SndAudioFormat {
    static constexpr size_t kFixedSize = 18;
    static constexpr uint16_t kFormatPcm = 0x0001;

    uint16_t format_tag = 0;
    uint16_t channels = 0;
    uint32_t samples_per_sec = 0;
    uint32_t avg_bytes_per_sec = 0;
    uint16_t block_align = 0;
    uint16_t bits_per_sample = 0;
    uint16_t cb_size = 0;
    std::vector<uint8_t> data;

    static Status parse(const uint8_t* data, size_t size, SndAudioFormat& out);
    void write(ByteWriter& w) const;
};

// Server Audio Formats and Version PDU body ([MS-RDPEA] 2.2.2.1), 20 bytes of
// fixed fields followed by wNumberOfFormats AUDIO_FORMAT structures.
struct SndServerFormats {
    static constexpr size_t kFixedSize = 20;

    uint32_t flags = 0;
    uint32_t volume = 0;
    uint32_t pitch = 0;
    uint16_t dgram_port = 0;
    uint16_t number_of_formats = 0;
    uint8_t last_block_confirmed = 0;
    uint16_t version = 0;
    uint8_t pad = 0;
    std::vector<SndAudioFormat> formats;

    static Status parse(const std::vector<uint8_t>& body, SndServerFormats& out);
};

// Builds the Client Audio Formats and Version PDU body ([MS-RDPEA] 2.2.2.2):
// flags + volume + pitch + dgram port + format count + last block confirmed +
// version + pad, followed by the AUDIO_FORMAT array.
std::vector<uint8_t> BuildClientFormatsBody(
    uint32_t flags, uint32_t volume, uint32_t pitch, uint16_t dgram_port,
    uint16_t version, const std::vector<SndAudioFormat>& formats);

// Builds the Quality Mode PDU body ([MS-RDPEA] 2.2.2.3): wQualityMode + pad.
std::vector<uint8_t> BuildQualityModeBody(uint16_t quality_mode);

// Builds the Wave Confirm PDU body ([MS-RDPEA] 2.2.3.8):
// wTimeStamp + cConfirmedBlockNo + bPad.
std::vector<uint8_t> BuildWaveConfirmBody(uint16_t time_stamp, uint8_t block_no);

// Builds the Training Confirm PDU body ([MS-RDPEA] 2.2.3.2): the server's
// wTimeStamp and wPackSize echoed back verbatim.
std::vector<uint8_t> BuildTrainingConfirmBody(uint16_t time_stamp,
                                              uint16_t pack_size);

// WaveInfo PDU body ([MS-RDPEA] 2.2.3.3): wTimeStamp + wFormatNo + cBlockNo +
// bPad(3) + the first four bytes of audio data.
struct SndWaveInfo {
    static constexpr size_t kFixedSize = 12;

    uint16_t time_stamp = 0;
    uint16_t format_no = 0;
    uint8_t block_no = 0;
    std::vector<uint8_t> data;

    static Status parse(const std::vector<uint8_t>& body, SndWaveInfo& out);
};

// Training PDU body ([MS-RDPEA] 2.2.3.1): wTimeStamp + wPackSize + data.
struct SndTraining {
    static constexpr size_t kFixedSize = 4;

    uint16_t time_stamp = 0;
    uint16_t pack_size = 0;
    std::vector<uint8_t> data;

    static Status parse(const std::vector<uint8_t>& body, SndTraining& out);
};

// SNDWAVE2 ([MS-RDPEA] 2.2.3.4): the Wave2 PDU body.
struct SndWave2 {
    uint16_t time_stamp = 0;
    uint16_t format_no = 0;
    uint8_t block_no = 0;
    uint32_t audio_time_stamp = 0;
    std::vector<uint8_t> data;

    static Status parse(const std::vector<uint8_t>& body, SndWave2& out);
};

}  // namespace rtsc::proto
