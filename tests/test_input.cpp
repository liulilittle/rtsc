// Fast-path input events ([MS-RDPBCGR] 2.2.8.1.2).
//
// The mouse event is checked against the official 4.7 dump
// (20 00 08 ab 02 6f 01).

#include "rtsc/proto/input.h"

#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/share.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::string Hex(const std::vector<uint8_t>& b) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (uint8_t c : b) {
        s.push_back(k[c >> 4]);
        s.push_back(k[c & 0xF]);
    }
    return s;
}

}  // namespace

RTSC_TEST(keyboard_event_is_two_bytes) {
    const auto down = EncodeKeyboardEvent(0x1E, false, false);  // 'A' down
    CHECK_EQ(down.size(), static_cast<size_t>(2));
    CHECK_EQ(down[0], static_cast<uint8_t>(0x00));  // eventCode 0, flags 0
    CHECK_EQ(down[1], static_cast<uint8_t>(0x1E));

    const auto up = EncodeKeyboardEvent(0x1E, true, false);
    CHECK_EQ(up[0], static_cast<uint8_t>(0x01));  // FASTPATH_INPUT_KBDFLAGS_RELEASE

    const auto ext = EncodeKeyboardEvent(0x48, false, true);  // extended up-arrow
    CHECK_EQ(ext[0], static_cast<uint8_t>(0x02));  // EXTENDED
}

RTSC_TEST(unicode_event_is_three_bytes) {
    const auto e = EncodeUnicodeEvent(0x0041, false);
    CHECK_EQ(e.size(), static_cast<size_t>(3));
    CHECK_EQ(e[0], static_cast<uint8_t>(0x80));  // eventCode 4 << 5
    CHECK_EQ(e[1], static_cast<uint8_t>(0x41));
    CHECK_EQ(e[2], static_cast<uint8_t>(0x00));
}

RTSC_TEST(mouse_event_matches_official_dump) {
    const auto e = EncodeMouseEvent(kPtrMove, 683, 367);
    CHECK_EQ(e.size(), static_cast<size_t>(7));
    CHECK(Hex(e) == "200008ab026f01");
}

RTSC_TEST(extended_mouse_event_uses_code_two) {
    const auto e = EncodeMouseEvent(kPtrDown | kPtrButton1, 10, 20, true);
    CHECK_EQ(e.size(), static_cast<size_t>(7));
    CHECK_EQ(static_cast<uint8_t>(e[0] >> 5), static_cast<uint8_t>(2));  // MOUSEX
}

RTSC_TEST(relative_mouse_event_keeps_sign) {
    const auto e = EncodeRelativeMouseEvent(kPtrMove, -3, 5);
    CHECK_EQ(e.size(), static_cast<size_t>(7));
    CHECK_EQ(static_cast<uint8_t>(e[0] >> 5), static_cast<uint8_t>(5));  // RELPOINTER
    CHECK_EQ(e[3], static_cast<uint8_t>(0xFD));  // -3 as u16
    CHECK_EQ(e[4], static_cast<uint8_t>(0xFF));
    CHECK_EQ(e[5], static_cast<uint8_t>(0x05));  // +5
    CHECK_EQ(e[6], static_cast<uint8_t>(0x00));
}

RTSC_TEST(sync_event_is_one_byte) {
    const auto e = EncodeSyncEvent(kSyncNumLock | kSyncCapsLock);
    CHECK_EQ(e.size(), static_cast<size_t>(1));
    CHECK_EQ(static_cast<uint8_t>(e[0] >> 5), static_cast<uint8_t>(3));  // SYNC
    CHECK_EQ(static_cast<uint8_t>(e[0] & 0x1F), static_cast<uint8_t>(0x06));
}

RTSC_TEST(qoe_timestamp_event_is_five_bytes) {
    const auto e = EncodeQoeTimestampEvent(0x11223344);
    CHECK_EQ(e.size(), static_cast<size_t>(5));
    CHECK_EQ(static_cast<uint8_t>(e[0] >> 5), static_cast<uint8_t>(6));  // QOE
    CHECK_EQ(e[1], static_cast<uint8_t>(0x44));
    CHECK_EQ(e[4], static_cast<uint8_t>(0x11));
}

RTSC_TEST(ctrl_alt_del_pdu_matches_the_expected_sequence) {
    // The six scancode events, framed as one Fast-Path input PDU:
    // header 18 (6 events), length 0e, then Ctrl/Alt/Del down, Del/Alt/Ctrl up.
    const auto events = EncodeCtrlAltDel();
    CHECK_EQ(events.size(), static_cast<size_t>(6));
    const auto pdu = EncodeFastPathInputPdu(events);
    CHECK(Hex(pdu) == "180e001d0038025303530138011d");
}

RTSC_TEST(pause_key_uses_the_extended1_ctrl_numlock_sequence) {
    // Pause = CTRL(EXTENDED1) down, NUMLOCK down, CTRL(EXTENDED1) up,
    // NUMLOCK up. A single 00 45 / 01 45 pair is the defect this locks out.
    const auto events = EncodePauseKey();
    CHECK_EQ(events.size(), static_cast<size_t>(4));
    if (events.size() == 4) {
        CHECK(Hex(events[0]) == "041d");
        CHECK(Hex(events[1]) == "0045");
        CHECK(Hex(events[2]) == "051d");
        CHECK(Hex(events[3]) == "0145");
    }
}

RTSC_TEST(pause_key_pdu_matches_the_expected_sequence) {
    // The whole Pause two-key sequence framed as one Fast-Path input PDU:
    // header 10 (4 events), length 0a, then 04 1d / 00 45 / 05 1d / 01 45.
    const auto pdu = EncodeFastPathInputPdu(EncodePauseKey());
    CHECK(Hex(pdu) == "100a041d0045051d0145");
}

RTSC_TEST(fastpath_input_pdu_frames_one_event) {
    const auto pdu = EncodeFastPathInputPdu({EncodeMouseEvent(kPtrMove, 683, 367)});
    // header(1) + length(1) + event(7) = 9.
    CHECK_EQ(pdu.size(), static_cast<size_t>(9));
    CHECK_EQ(pdu[0], static_cast<uint8_t>(0x04));  // action 0, numEvents 1, flags 0
    CHECK_EQ(pdu[1], static_cast<uint8_t>(0x09));  // total length
    CHECK(Hex(std::vector<uint8_t>(pdu.begin() + 2, pdu.end())) ==
          "200008ab026f01");
}

RTSC_TEST(fastpath_input_pdu_uses_extended_count_above_15) {
    std::vector<std::vector<uint8_t>> events;
    for (int i = 0; i < 16; ++i) events.push_back(EncodeSyncEvent(0));
    const auto pdu = EncodeFastPathInputPdu(events);
    // header(1) + length(1) + numEvents(1) + 16 events(1) = 19.
    CHECK_EQ(pdu.size(), static_cast<size_t>(19));
    CHECK_EQ(static_cast<uint8_t>((pdu[0] >> 2) & 0x0F), static_cast<uint8_t>(0));
    CHECK_EQ(pdu[2], static_cast<uint8_t>(16));  // extended numEvents
}

RTSC_TEST(fastpath_input_pdu_rejects_empty_and_oversize) {
    CHECK(EncodeFastPathInputPdu({}).empty());
    std::vector<std::vector<uint8_t>> too_many(256, EncodeSyncEvent(0));
    CHECK(EncodeFastPathInputPdu(too_many).empty());
}

int main() { return ::rtsc::test::run_all("rtsc_input_tests"); }
