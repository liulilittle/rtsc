// RAIL ([MS-RDPERP]) wire structure and virtual channel tests.

#include "rtsc/proto/rail.h"

#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

std::vector<uint8_t> Chunk(uint32_t total, uint32_t flags,
                           const std::vector<uint8_t>& data) {
    ByteWriter w;
    w.u32le(total);
    w.u32le(flags);
    w.bytes(data.data(), data.size());
    return w.take();
}

}  // namespace

RTSC_TEST(rail_channel_name_is_spec_conformant) {
    CHECK(std::string(kRailChannelName) == "rail");
}

RTSC_TEST(rail_pdu_header_round_trips) {
    RailPduHeader h;
    h.order_type = RailHandshake::kOrderType;
    h.order_length = 8;
    ByteWriter w;
    h.write(w);
    CHECK_EQ(w.size(), static_cast<size_t>(4));

    RailPduHeader out;
    CHECK(RailPduHeader::parse(w.data().data(), w.size(), out) == Status::Ok);
    CHECK_EQ(out.order_type, static_cast<uint16_t>(RailHandshake::kOrderType));
    CHECK_EQ(out.order_length, static_cast<uint16_t>(8));
}

RTSC_TEST(rail_pdu_parse_reports_consumed_and_rejects_bad_length) {
    const std::vector<uint8_t> pdu = RailHandshake{0x1DB0}.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(8));

    RailPdu out;
    size_t consumed = 0;
    CHECK(RailPdu::parse(pdu.data(), pdu.size(), out, consumed) == Status::Ok);
    CHECK_EQ(consumed, static_cast<size_t>(8));
    CHECK_EQ(out.body.size(), static_cast<size_t>(4));

    // A declared length larger than the buffer is NeedMoreData, not Ok.
    RailPduHeader header;
    header.order_type = RailHandshake::kOrderType;
    header.order_length = 100;
    ByteWriter w;
    header.write(w);
    RailPdu bad;
    size_t bad_consumed = 0;
    CHECK(RailPdu::parse(w.data().data(), w.size(), bad, bad_consumed) ==
          Status::NeedMoreData);

    // A declared length below the header size is rejected.
    header.order_length = 2;
    ByteWriter w2;
    header.write(w2);
    CHECK(RailPdu::parse(w2.data().data(), w2.size(), bad, bad_consumed) ==
          Status::InvalidLength);
}

RTSC_TEST(rail_handshake_round_trips) {
    const std::vector<uint8_t> pdu = RailHandshake{0x00001DB0}.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(8));
    CHECK_EQ(pdu[0], 0x05);
    CHECK_EQ(pdu[1], 0x00);
    CHECK_EQ(pdu[2], 0x08);
    CHECK_EQ(pdu[3], 0x00);

    RailHandshake out;
    CHECK(RailHandshake::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.build_number, static_cast<uint32_t>(0x00001DB0));
}

RTSC_TEST(rail_handshake_ex_round_trips) {
    RailHandshakeEx in;
    in.build_number = 0x1DB0;
    in.flags = kRailHidef | kRailExtendedSpiSupported;
    const std::vector<uint8_t> pdu = in.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(12));

    RailHandshakeEx out;
    CHECK(RailHandshakeEx::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.build_number, static_cast<uint32_t>(0x1DB0));
    CHECK_EQ(out.flags,
             static_cast<uint32_t>(kRailHidef | kRailExtendedSpiSupported));
}

RTSC_TEST(rail_client_status_round_trips) {
    RailClientStatus in;
    in.flags = kRailClientAllowLocalMoveSize | kRailClientZOrderSync;
    const std::vector<uint8_t> pdu = in.build();

    RailClientStatus out;
    CHECK(RailClientStatus::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.flags,
             static_cast<uint32_t>(kRailClientAllowLocalMoveSize |
                                   kRailClientZOrderSync));
}

RTSC_TEST(rail_syscommand_minimize_and_maximize_round_trip) {
    RailSyscommand minimize;
    minimize.window_id = 0x1234;
    minimize.command = kScMinimize;
    const std::vector<uint8_t> pdu = minimize.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(10));

    RailSyscommand out;
    CHECK(RailSyscommand::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.window_id, static_cast<uint32_t>(0x1234));
    CHECK_EQ(out.command, static_cast<uint16_t>(kScMinimize));

    RailSyscommand maximize;
    maximize.window_id = 0x1234;
    maximize.command = kScMaximize;
    const std::vector<uint8_t> pdu2 = maximize.build();
    CHECK(RailSyscommand::parse(pdu2.data(), pdu2.size(), out) == Status::Ok);
    CHECK_EQ(out.command, static_cast<uint16_t>(kScMaximize));
}

RTSC_TEST(rail_sysmenu_round_trips_with_signed_coordinates) {
    RailSysmenu in;
    in.window_id = 7;
    in.left = -12;
    in.top = 340;
    const std::vector<uint8_t> pdu = in.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(12));

    RailSysmenu out;
    CHECK(RailSysmenu::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.window_id, static_cast<uint32_t>(7));
    CHECK_EQ(out.left, static_cast<int16_t>(-12));
    CHECK_EQ(out.top, static_cast<int16_t>(340));
}

RTSC_TEST(rail_window_move_round_trips) {
    RailWindowMove in;
    in.window_id = 0xABCD;
    in.left = 100;
    in.top = 200;
    in.right = 500;
    in.bottom = 400;
    const std::vector<uint8_t> pdu = in.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(16));

    RailWindowMove out;
    CHECK(RailWindowMove::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.window_id, static_cast<uint32_t>(0xABCD));
    CHECK_EQ(out.left, static_cast<int16_t>(100));
    CHECK_EQ(out.top, static_cast<int16_t>(200));
    CHECK_EQ(out.right, static_cast<int16_t>(500));
    CHECK_EQ(out.bottom, static_cast<int16_t>(400));
}

RTSC_TEST(rail_minmaxinfo_round_trips) {
    RailMinMaxInfo in;
    in.window_id = 3;
    in.max_width = 1600;
    in.max_height = 900;
    in.max_pos_x = -8;
    in.max_pos_y = -30;
    in.min_track_width = 120;
    in.min_track_height = 40;
    in.max_track_width = 4096;
    in.max_track_height = 4096;
    const std::vector<uint8_t> pdu = in.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(24));

    RailMinMaxInfo out;
    CHECK(RailMinMaxInfo::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.window_id, static_cast<uint32_t>(3));
    CHECK_EQ(out.max_width, static_cast<int16_t>(1600));
    CHECK_EQ(out.min_track_width, static_cast<int16_t>(120));
    CHECK_EQ(out.max_pos_y, static_cast<int16_t>(-30));
}

RTSC_TEST(rail_local_move_size_round_trips) {
    RailLocalMoveSize in;
    in.window_id = 9;
    in.is_move_size_start = true;
    in.move_size_type = kRailWmszTopLeft;
    in.pos_x = 11;
    in.pos_y = 22;
    const std::vector<uint8_t> pdu = in.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(16));

    RailLocalMoveSize out;
    CHECK(RailLocalMoveSize::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK(out.is_move_size_start);
    CHECK_EQ(out.move_size_type, static_cast<uint16_t>(kRailWmszTopLeft));
    CHECK_EQ(out.pos_x, static_cast<int16_t>(11));
    CHECK_EQ(out.pos_y, static_cast<int16_t>(22));
}

RTSC_TEST(rail_taskbar_info_round_trips) {
    RailTaskbarInfo in;
    in.taskbar_message = kRailTaskbarTabRegister;
    in.window_id_tab = 0x42;
    in.body = 1;
    const std::vector<uint8_t> pdu = in.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(16));

    RailTaskbarInfo out;
    CHECK(RailTaskbarInfo::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.taskbar_message,
             static_cast<uint32_t>(kRailTaskbarTabRegister));
    CHECK_EQ(out.window_id_tab, static_cast<uint32_t>(0x42));
    CHECK_EQ(out.body, static_cast<uint32_t>(1));
}

RTSC_TEST(rail_langbar_info_round_trips) {
    RailLangbarInfo in;
    in.language_bar_status = kRailLangbarShowNormal | kRailLangbarLabels;
    const std::vector<uint8_t> pdu = in.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(8));

    RailLangbarInfo out;
    CHECK(RailLangbarInfo::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.language_bar_status,
             static_cast<uint32_t>(kRailLangbarShowNormal | kRailLangbarLabels));
}

RTSC_TEST(rail_get_appid_req_round_trips) {
    RailGetAppIdReq in;
    in.window_id = 0x77;
    const std::vector<uint8_t> pdu = in.build();

    RailGetAppIdReq out;
    CHECK(RailGetAppIdReq::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.window_id, static_cast<uint32_t>(0x77));
}

RTSC_TEST(rail_get_appid_resp_ex_round_trips_all_fields) {
    // [MS-RDPERP] 2.2.2.8.2: windowId (4) + ApplicationId (520) + processId (4) +
    // ProcessImageName (520) = 1048 body bytes; orderLength = 1052.
    RailGetAppIdRespEx in;
    in.window_id = 0x20052;
    in.application_id = u"microsoft.windows.notepad";
    in.process_id = 0x1234;
    in.process_image_name = u"C:\\Windows\\System32\\notepad.exe";
    std::string why;
    const std::vector<uint8_t> pdu = in.build(why);
    CHECK(why.empty());
    CHECK_EQ(pdu.size(), static_cast<size_t>(1052));
    CHECK_EQ(pdu[0], 0x18);
    CHECK_EQ(pdu[1], 0x00);

    RailGetAppIdRespEx out;
    CHECK(RailGetAppIdRespEx::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.window_id, static_cast<uint32_t>(0x20052));
    CHECK(out.application_id == in.application_id);
    CHECK_EQ(out.process_id, static_cast<uint32_t>(0x1234));
    CHECK(out.process_image_name == in.process_image_name);
}

RTSC_TEST(rail_get_appid_resp_ex_rejects_bad_length_and_type) {
    RailGetAppIdRespEx in;
    in.window_id = 1;
    std::string why;
    const std::vector<uint8_t> pdu = in.build(why);

    RailGetAppIdRespEx out;
    // A declared orderLength smaller than the fixed body is InvalidLength.
    ByteWriter bad_len;
    bad_len.u16le(RailGetAppIdRespEx::kOrderType);
    bad_len.u16le(static_cast<uint16_t>(RailGetAppIdRespEx::kBodySize - 1));
    CHECK(RailGetAppIdRespEx::parse(bad_len.data().data(), bad_len.size(), out) ==
          Status::InvalidLength);

    // The header type is validated against 0x0018.
    ByteWriter bad_type;
    bad_type.u16le(RailGetAppIdReq::kOrderType);
    bad_type.u16le(static_cast<uint16_t>(RailGetAppIdRespEx::kOrderLength));
    bad_type.bytes(pdu.data() + 4, pdu.size() - 4);
    CHECK(RailGetAppIdRespEx::parse(bad_type.data().data(), bad_type.size(), out) ==
          Status::InvalidType);
}

RTSC_TEST(rail_get_appid_resp_ex_rejects_truncated_strings) {
    // A fixed 520-byte field that is completely filled leaves no room for the
    // null terminator the spec requires. FreeRDP rejects that
    // (rail_read_get_application_id_extended_response_order); so must we.
    const std::u16string full(260, u'A');
    std::string why;
    RailGetAppIdRespEx in;
    in.application_id = full;
    in.process_image_name = u"notepad.exe";
    CHECK(in.build(why).empty());
    CHECK(!why.empty());

    RailGetAppIdRespEx in2;
    in2.application_id = u"notepad";
    in2.process_image_name = full;
    CHECK(in2.build(why).empty());
    CHECK(!why.empty());

    // 259 code units still fit with a terminator.
    RailGetAppIdRespEx in3;
    in3.application_id = std::u16string(259, u'B');
    in3.process_image_name = u"ok";
    CHECK(!in3.build(why).empty());

    // A peer that sends the unterminated field on the wire is rejected.
    ByteWriter body;
    body.u32le(7);
    body.bytes(RailUtf16ToLeBytes(full).data(), 520);
    body.u32le(9);
    body.bytes(RailUtf16ToLeBytes(u"img").data(), 6);
    for (int i = 0; i < 514; ++i) body.u8(0);
    const std::vector<uint8_t> wire =
        BuildRailPdu(RailGetAppIdRespEx::kOrderType, body.take());
    RailGetAppIdRespEx out;
    CHECK(RailGetAppIdRespEx::parse(wire.data(), wire.size(), out) ==
          Status::InvalidField);
}

RTSC_TEST(rail_get_appid_resp_ex_is_server_to_client) {
    // 0x0018 is sent by the server in response to the client's 0x000E request;
    // the client only receives it, and there is no client -> server sender.
    RailGetAppIdRespEx in;
    in.window_id = 0x11;
    std::string why;
    const std::vector<uint8_t> pdu = in.build(why);
    const uint16_t wire_type =
        static_cast<uint16_t>(pdu[0]) | (static_cast<uint16_t>(pdu[1]) << 8);
    CHECK(wire_type == static_cast<uint16_t>(0x0018));
    CHECK(wire_type != RailGetAppIdReq::kOrderType);
    CHECK(wire_type != static_cast<uint16_t>(RailOrderType::kGetAppIdResp));
    // The enum name is used by the diagnostics.
    CHECK(std::string(to_string(RailOrderType::kGetAppIdRespEx)) ==
          std::string("TS_RAIL_ORDER_GET_APPID_RESP_EX"));
}

RTSC_TEST(rail_sysparam_boolean_and_rect_round_trip) {
    RailSysparamOrder drag;
    drag.param = kSpiSetDragFullWindows;
    drag.bool_value = true;
    std::vector<uint8_t> pdu = drag.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(9));
    RailSysparamOrder out;
    CHECK(RailSysparamOrder::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.param, static_cast<uint32_t>(kSpiSetDragFullWindows));
    CHECK(out.bool_value);

    RailSysparamOrder area;
    area.param = kSpiSetWorkArea;
    area.rect_left = 0;
    area.rect_top = 0;
    area.rect_right = 1600;
    area.rect_bottom = 900;
    pdu = area.build();
    CHECK_EQ(pdu.size(), static_cast<size_t>(16));
    CHECK(RailSysparamOrder::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.param, static_cast<uint32_t>(kSpiSetWorkArea));
    CHECK_EQ(out.rect_right, static_cast<int16_t>(1600));
    CHECK_EQ(out.rect_bottom, static_cast<int16_t>(900));
}

RTSC_TEST(rail_sysparam_extended_spi_uses_spec_values) {
    // [MS-RDPERP] 2.2.2.4.1: the extended SPI values are NOT the Win32 SDK
    // SPI_* values. These four were wrong before (SDK values), which made the
    // client reject a spec-conformant peer.
    RailSysparamOrder caret;
    caret.param = kSpiSetCaretWidth;
    caret.uint_value = 2;
    std::vector<uint8_t> pdu = caret.build();
    RailSysparamOrder out;
    CHECK(RailSysparamOrder::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.param, static_cast<uint32_t>(0x00002007));
    CHECK_EQ(out.uint_value, static_cast<uint32_t>(2));

    RailSysparamOrder sticky;
    sticky.param = kSpiSetStickyKeys;
    sticky.uint_value = 0x1234;
    pdu = sticky.build();
    CHECK(RailSysparamOrder::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.param, static_cast<uint32_t>(0x0000003B));
    CHECK_EQ(out.uint_value, static_cast<uint32_t>(0x1234));

    RailSysparamOrder toggle;
    toggle.param = kSpiSetToggleKeys;
    toggle.uint_value = 1;
    pdu = toggle.build();
    CHECK(RailSysparamOrder::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.param, static_cast<uint32_t>(0x00000035));
    CHECK_EQ(out.uint_value, static_cast<uint32_t>(1));

    RailSysparamOrder filter;
    filter.param = kSpiSetFilterKeys;
    filter.uint_value = 0x55;
    pdu = filter.build();
    CHECK(RailSysparamOrder::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.param, static_cast<uint32_t>(0x00000033));
    CHECK_EQ(out.uint_value, static_cast<uint32_t>(0x55));
}

RTSC_TEST(rail_sysparam_parses_spec_conformant_extended_spi_values) {
    // The parser must accept the literal [MS-RDPERP] 2.2.2.4.1 values, even
    // though they differ from the Win32 SDK values. Before the fix the switch
    // used the SDK values, so a spec-conformant peer (mstsc) was rejected.
    const uint32_t spec_values[] = {
        0x00002007,  // SPI_SETCARETWIDTH
        0x0000003B,  // SPI_SETSTICKYKEYS
        0x00000035,  // SPI_SETTOGGLEKEYS
        0x00000033,  // SPI_SETFILTERKEYS
    };
    for (const uint32_t value : spec_values) {
        ByteWriter w;
        w.u32le(value);
        if (value == kSpiSetFilterKeys) {
            for (int i = 0; i < 5; ++i) w.u32le(1);
        } else {
            w.u32le(1);
        }
        const std::vector<uint8_t> pdu =
            BuildRailPdu(RailSysparamOrder::kOrderType, w.take());
        RailSysparamOrder out;
        CHECK(RailSysparamOrder::parse(pdu.data(), pdu.size(), out) == Status::Ok);
        CHECK_EQ(out.param, value);
    }
}

RTSC_TEST(rail_sysparam_high_contrast_round_trips) {
    RailSysparamOrder in;
    in.param = kSpiSetHighContrast;
    in.high_contrast_flags = 0x7E;
    in.color_scheme = u"High Contrast Black";
    std::vector<uint8_t> pdu = in.build();
    CHECK(!pdu.empty());

    RailSysparamOrder out;
    CHECK(RailSysparamOrder::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.param, static_cast<uint32_t>(kSpiSetHighContrast));
    CHECK_EQ(out.high_contrast_flags, static_cast<uint32_t>(0x7E));
    CHECK(out.color_scheme == in.color_scheme);
}

RTSC_TEST(rail_client_execute_round_trips_utf16_strings) {
    RailClientExecute in;
    in.flags = kRailExecExpandArguments;
    in.exe_or_file = u"C:\\Windows\\System32\\notepad.exe";
    in.working_dir = u"C:\\Windows";
    in.arguments = u"README.txt";

    std::string why;
    const std::vector<uint8_t> pdu = in.build(why);
    CHECK(!pdu.empty());
    CHECK(why.empty());
    // header (4) + flags (2) + 3 lengths (6) + utf16 payload.
    const size_t expected = 12 + (in.exe_or_file.size() + in.working_dir.size() +
                                  in.arguments.size()) *
                                     2;
    CHECK_EQ(pdu.size(), expected);

    RailClientExecute out;
    CHECK(RailClientExecute::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.flags, static_cast<uint16_t>(kRailExecExpandArguments));
    CHECK(out.exe_or_file == in.exe_or_file);
    CHECK(out.working_dir == in.working_dir);
    CHECK(out.arguments == in.arguments);
}

RTSC_TEST(rail_client_execute_rejects_empty_and_oversized_fields) {
    RailClientExecute in;
    in.exe_or_file = u"";
    std::string why;
    CHECK(in.build(why).empty());
    CHECK(!why.empty());

    RailClientExecute big;
    big.exe_or_file = std::u16string(300, u'A');  // 600 bytes > 520
    CHECK(big.build(why).empty());
    CHECK(!why.empty());
}

RTSC_TEST(rail_execute_result_round_trips) {
    RailExecuteResult in;
    in.flags = 0;
    in.exec_result = kRailExecOk;
    in.raw_result = 0;
    in.exe_or_file = u"C:\\Windows\\System32\\notepad.exe";
    const std::vector<uint8_t> pdu = in.build();

    RailExecuteResult out;
    CHECK(RailExecuteResult::parse(pdu.data(), pdu.size(), out) == Status::Ok);
    CHECK_EQ(out.exec_result, static_cast<uint16_t>(kRailExecOk));
    CHECK_EQ(out.raw_result, static_cast<uint32_t>(0));
    CHECK(out.exe_or_file == in.exe_or_file);
}

RTSC_TEST(rail_channel_reassembles_chunked_message_and_dispatches) {
    RailChannel channel;
    unsigned handshakes = 0;
    unsigned syscommands = 0;
    unsigned window_moves = 0;
    channel.SetHandler([&](const RailPdu& pdu) {
        if (pdu.header.order_type == RailHandshake::kOrderType) ++handshakes;
        if (pdu.header.order_type == RailSyscommand::kOrderType) ++syscommands;
        if (pdu.header.order_type == RailWindowMove::kOrderType) ++window_moves;
    });

    const std::vector<uint8_t> message =
        RailHandshake{0x1DB0}.build();
    const auto chunks = FragmentChannelMessage(message, 4);  // forces chunking
    CHECK(chunks.size() > 1);
    for (const auto& chunk : chunks) {
        channel.OnChannelData(chunk.data(), chunk.size());
    }
    CHECK_EQ(channel.pdu_count(), static_cast<unsigned>(1));
    CHECK_EQ(channel.handshake_count(), static_cast<unsigned>(1));
    CHECK_EQ(handshakes, static_cast<unsigned>(1));
    CHECK_EQ(channel.incomplete_message_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rail_channel_dispatches_multiple_pdus_in_one_message) {
    RailChannel channel;
    const std::vector<uint8_t> message = [&] {
        std::vector<uint8_t> m = RailSyscommand{5, kScMinimize}.build();
        const std::vector<uint8_t> move =
            RailWindowMove{5, 0, 0, 320, 240}.build();
        m.insert(m.end(), move.begin(), move.end());
        return m;
    }();

    const auto chunks = FragmentChannelMessage(message, 8);
    for (const auto& chunk : chunks) {
        channel.OnChannelData(chunk.data(), chunk.size());
    }
    CHECK_EQ(channel.pdu_count(), static_cast<unsigned>(2));
    CHECK_EQ(channel.syscommand_count(), static_cast<unsigned>(1));
    CHECK_EQ(channel.window_move_count(), static_cast<unsigned>(1));
}

RTSC_TEST(rail_channel_ignores_foreign_chunk_without_first) {
    RailChannel channel;
    // A middle chunk with no open sequence is rejected and reset.
    const auto chunk = Chunk(10, kChannelShowProtocol, {1, 2});
    channel.OnChannelData(chunk.data(), chunk.size());
    CHECK_EQ(channel.pdu_count(), static_cast<unsigned>(0));
    CHECK_EQ(channel.incomplete_message_count(), static_cast<unsigned>(1));
}

int main() { return ::rtsc::test::run_all("rtsc_rail_tests"); }
