// The GUI-side debug host: turns the debug channel's command JSON into live
// client/window state.
//
// These tests pin the two properties that make the channel trustworthy as a
// diagnostic tool:
//   1. every field it reports comes from the real object, never a copy that
//      could drift, and
//   2. an unknown command fails loudly instead of answering a plausible-looking
//      empty object (a debugger that silently lies is worse than no debugger).
//
// The host is deliberately independent of rtsc_gui's main() so it can be linked
// here: it takes plain references and plain values.

#include <string>

#include "rtsc/debug/gui_debug_host.h"

#include "test_framework.h"
#include "test_main.h"

using rtsc::debug::DebugSnapshot;

namespace {

DebugSnapshot MakeSnapshot() {
    DebugSnapshot s;
    s.desktop_width = 1280;
    s.desktop_height = 1024;
    s.view_width = 800;
    s.view_height = 640;
    s.zoom = 1.25;
    s.fit = true;
    s.frames_rendered = 42;
    s.loop_iterations = 1000;
    s.input_events_sent = 7;
    s.dirty_left = 10;
    s.dirty_top = 20;
    s.dirty_right = 30;
    s.dirty_bottom = 40;
    s.session_active = true;
    s.host = "192.168.1.7";
    s.backend = "win32";
    return s;
}

}  // namespace

RTSC_TEST(gui_debug_state_reports_every_field) {
    const std::string out = rtsc::debug::ExecuteGuiCommand(MakeSnapshot(),
                                                           "\"op\":\"state\"");
    // The reply must carry each value verbatim so an operator can read it.
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"desktop_width\":1280") != std::string::npos);
    CHECK(out.find("\"desktop_height\":1024") != std::string::npos);
    CHECK(out.find("\"view_width\":800") != std::string::npos);
    CHECK(out.find("\"view_height\":640") != std::string::npos);
    CHECK(out.find("\"zoom\":1.25") != std::string::npos);
    CHECK(out.find("\"fit\":true") != std::string::npos);
    CHECK(out.find("\"frames_rendered\":42") != std::string::npos);
    CHECK(out.find("\"loop_iterations\":1000") != std::string::npos);
    CHECK(out.find("\"input_events_sent\":7") != std::string::npos);
    CHECK(out.find("\"session_active\":true") != std::string::npos);
    CHECK(out.find("\"host\":\"192.168.1.7\"") != std::string::npos);
    CHECK(out.find("\"backend\":\"win32\"") != std::string::npos);
}

RTSC_TEST(gui_debug_dirty_reports_the_exact_rectangle) {
    // The dirty rectangle is the one field the flicker investigation needed and
    // could never get: it must be reported exactly, not as "something changed".
    const std::string out = rtsc::debug::ExecuteGuiCommand(MakeSnapshot(),
                                                           "\"op\":\"dirty\"");
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"left\":10") != std::string::npos);
    CHECK(out.find("\"top\":20") != std::string::npos);
    CHECK(out.find("\"right\":30") != std::string::npos);
    CHECK(out.find("\"bottom\":40") != std::string::npos);
    CHECK(out.find("\"empty\":false") != std::string::npos);
}

RTSC_TEST(gui_debug_dirty_reports_empty_when_idle) {
    DebugSnapshot s = MakeSnapshot();
    s.dirty_left = s.dirty_top = s.dirty_right = s.dirty_bottom = 0;
    const std::string out = rtsc::debug::ExecuteGuiCommand(s, "\"op\":\"dirty\"");
    CHECK(out.find("\"empty\":true") != std::string::npos);
}

RTSC_TEST(gui_debug_unknown_op_fails_loudly) {
    // A debugger that answers 200 with an empty object for a typo would make a
    // broken query look like a passing check.
    const std::string out = rtsc::debug::ExecuteGuiCommand(MakeSnapshot(),
                                                           "\"op\":\"nonsense\"");
    CHECK(out.find("\"ok\":false") != std::string::npos);
    CHECK(out.find("\"error\"") != std::string::npos);
    CHECK(out.find("nonsense") != std::string::npos);
}

RTSC_TEST(gui_debug_missing_op_fails_loudly) {
    const std::string out = rtsc::debug::ExecuteGuiCommand(MakeSnapshot(), "");
    CHECK(out.find("\"ok\":false") != std::string::npos);
}

RTSC_TEST(gui_debug_ping_is_cheap_and_always_ok) {
    const std::string out = rtsc::debug::ExecuteGuiCommand(MakeSnapshot(),
                                                           "\"op\":\"ping\"");
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"pong\":true") != std::string::npos);
}

RTSC_TEST(gui_debug_string_fields_are_escaped) {
    // A host name is operator-supplied and can contain a quote or backslash; the
    // JSON must stay parseable instead of breaking the whole reply.
    DebugSnapshot s = MakeSnapshot();
    s.host = "a\"b\\c";
    const std::string out = rtsc::debug::ExecuteGuiCommand(s, "\"op\":\"state\"");
    CHECK(out.find("\"host\":\"a\\\"b\\\\c\"") != std::string::npos);
}

RTSC_TEST(gui_debug_surface_reports_pixel_statistics) {
    DebugSnapshot s = MakeSnapshot();
    s.non_black_pixels = 123456;
    s.distinct_colours = 256;
    s.total_pixels = 1310720;
    const std::string out = rtsc::debug::ExecuteGuiCommand(s, "\"op\":\"surface\"");
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"non_black_pixels\":123456") != std::string::npos);
    CHECK(out.find("\"distinct_colours\":256") != std::string::npos);
    CHECK(out.find("\"total_pixels\":1310720") != std::string::npos);
}

RTSC_TEST(gui_debug_surface_reports_zero_for_empty_surface) {
    DebugSnapshot s = MakeSnapshot();
    s.non_black_pixels = 0;
    s.distinct_colours = 0;
    s.total_pixels = 0;
    const std::string out = rtsc::debug::ExecuteGuiCommand(s, "\"op\":\"surface\"");
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"non_black_pixels\":0") != std::string::npos);
    CHECK(out.find("\"distinct_colours\":0") != std::string::npos);
    CHECK(out.find("\"total_pixels\":0") != std::string::npos);
}

RTSC_TEST(gui_debug_command_requests_surface_only_for_surface_op) {
    // main() uses this to decide whether to pay for a full pixel walk, so a
    // false positive costs a frame and a false negative hides the one command
    // the flicker investigation needed.
    CHECK(rtsc::debug::CommandRequestsSurface("\"op\":\"surface\""));
    CHECK(rtsc::debug::CommandRequestsSurface("\"op\" : \"surface\""));
    CHECK(!rtsc::debug::CommandRequestsSurface("\"op\":\"state\""));
    CHECK(!rtsc::debug::CommandRequestsSurface("\"op\":\"dirty\""));
    CHECK(!rtsc::debug::CommandRequestsSurface("\"op\":\"ping\""));
    CHECK(!rtsc::debug::CommandRequestsSurface(""));
    // A prefix of "surface" must not match: the op is compared whole.
    CHECK(!rtsc::debug::CommandRequestsSurface("\"op\":\"surfaceish\""));
    CHECK(!rtsc::debug::CommandRequestsSurface("\"op\":\"\""));
}

RTSC_TEST(gui_debug_screenshot_reports_skipped_when_path_empty) {
    // The host never fabricates a path; an empty screenshot_path means the
    // caller must not attempt a write.
    DebugSnapshot s = MakeSnapshot();
    s.screenshot_path.clear();
    const std::string out = rtsc::debug::ExecuteGuiCommand(s, "\"op\":\"screenshot\"");
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"skipped\":true") != std::string::npos);
}

RTSC_TEST(gui_debug_screenshot_reports_path_when_set) {
    DebugSnapshot s = MakeSnapshot();
    s.screenshot_path = "%TEMP%\\rtsc_screenshot.bmp";
    const std::string out = rtsc::debug::ExecuteGuiCommand(s, "\"op\":\"screenshot\"");
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"path\":\"%TEMP%\\\\rtsc_screenshot.bmp\"") != std::string::npos);
}

RTSC_TEST(gui_debug_encode_bmp32_round_trip) {
    // 2x2 RGBA: (255,0,0,255) (0,255,0,255) (0,0,255,255) (255,255,0,255)
    const uint8_t pixels[16] = {
        0xFF, 0x00, 0x00, 0xFF,  // red
        0x00, 0xFF, 0x00, 0xFF,  // green
        0x00, 0x00, 0xFF, 0xFF,  // blue
        0xFF, 0xFF, 0x00, 0xFF,  // yellow
    };
    const std::string bmp = rtsc::debug::EncodeBmp32(pixels, 2, 2);
    // 14 + 40 + 2*2*4 = 70 bytes
    CHECK(bmp.size() == 70);
    // Header
    CHECK(bmp[0] == 'B' && bmp[1] == 'M');
    // biWidth = 2, biHeight = -2
    CHECK(static_cast<unsigned char>(bmp[18]) == 2 && bmp[19] == 0 && bmp[20] == 0 && bmp[21] == 0);
    CHECK(static_cast<unsigned char>(bmp[22]) == 0xFE && static_cast<unsigned char>(bmp[23]) == 0xFF &&
          static_cast<unsigned char>(bmp[24]) == 0xFF && static_cast<unsigned char>(bmp[25]) == 0xFF);
    // biBitCount = 32
    CHECK(static_cast<unsigned char>(bmp[28]) == 32 && bmp[29] == 0);
    // bfOffBits = 54
    CHECK(static_cast<unsigned char>(bmp[10]) == 54);
    // Pixel data starts at 54; first pixel red -> BGR(0,0,255)
    CHECK(bmp[54] == 0x00 && bmp[55] == 0x00 && static_cast<unsigned char>(bmp[56]) == 0xFF &&
          static_cast<unsigned char>(bmp[57]) == 0xFF);
    // Second pixel green -> BGR(0,255,0)
    CHECK(bmp[58] == 0x00 && static_cast<unsigned char>(bmp[59]) == 0xFF && bmp[60] == 0x00 &&
          static_cast<unsigned char>(bmp[61]) == 0xFF);
    // Third pixel blue -> BGR(255,0,0)
    CHECK(static_cast<unsigned char>(bmp[62]) == 0xFF && bmp[63] == 0x00 && bmp[64] == 0x00 &&
          static_cast<unsigned char>(bmp[65]) == 0xFF);
    // Fourth pixel yellow -> BGR(0,255,255)
    CHECK(bmp[66] == 0x00 && static_cast<unsigned char>(bmp[67]) == 0xFF &&
          static_cast<unsigned char>(bmp[68]) == 0xFF && static_cast<unsigned char>(bmp[69]) == 0xFF);
}

RTSC_TEST(gui_debug_encode_bmp32_rejects_zero_dimensions) {
    const uint8_t pixels[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    CHECK(rtsc::debug::EncodeBmp32(pixels, 0, 1).empty());
    CHECK(rtsc::debug::EncodeBmp32(pixels, 1, 0).empty());
    CHECK(rtsc::debug::EncodeBmp32(nullptr, 1, 1).empty());
}

RTSC_TEST(gui_debug_screenshot_path_extract) {
    std::string path;
    CHECK(!rtsc::debug::ScreenshotPath("\"op\":\"screenshot\"", path));
    CHECK(!rtsc::debug::ScreenshotPath("\"op\":\"state\"\"", path));
    CHECK(rtsc::debug::ScreenshotPath("\"op\":\"screenshot\",\"path\":\"C:\\\\out.bmp\"", path));
    CHECK(path == "C:\\out.bmp");
}

RTSC_TEST(gui_debug_command_requests_frames_only_for_frames_op) {
    CHECK(rtsc::debug::CommandRequestsFrames("\"op\":\"frames\""));
    CHECK(rtsc::debug::CommandRequestsFrames("\"op\" : \"frames\""));
    CHECK(!rtsc::debug::CommandRequestsFrames("\"op\":\"state\""));
    CHECK(!rtsc::debug::CommandRequestsFrames("\"op\":\"dirty\""));
    CHECK(!rtsc::debug::CommandRequestsFrames("\"op\":\"ping\""));
    CHECK(!rtsc::debug::CommandRequestsFrames("\"op\":\"screenshot\""));
    CHECK(!rtsc::debug::CommandRequestsFrames(""));
    // A prefix of "frames" must not match: the op is compared whole.
    CHECK(!rtsc::debug::CommandRequestsFrames("\"op\":\"framesish\""));
    CHECK(!rtsc::debug::CommandRequestsFrames("\"op\":\"\""));
}

RTSC_TEST(gui_debug_format_frame_samples_joins_with_commas) {
    // Empty array.
    CHECK(rtsc::debug::FormatFrameSamples({}) == "\"ok\":true,\"frames\":[]");
    // Single element.
    std::vector<unsigned> single = {42};
    CHECK(rtsc::debug::FormatFrameSamples(single) == "\"ok\":true,\"frames\":[42]");
    // Multiple elements.
    std::vector<unsigned> multi = {10, 20, 30};
    CHECK(rtsc::debug::FormatFrameSamples(multi) == "\"ok\":true,\"frames\":[10,20,30]");
}

RTSC_TEST(gui_debug_frames_op_reports_samples) {
    DebugSnapshot s = MakeSnapshot();
    s.frame_samples = {5, 12, 30};
    const std::string out = rtsc::debug::ExecuteGuiCommand(s, "\"op\":\"frames\"");
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"frames\":[5,12,30]") != std::string::npos);
}

RTSC_TEST(gui_debug_command_requests_input_only_for_input_op) {
    CHECK(rtsc::debug::CommandRequestsInput("\"op\":\"input\""));
    CHECK(rtsc::debug::CommandRequestsInput("\"op\" : \"input\""));
    CHECK(!rtsc::debug::CommandRequestsInput("\"op\":\"frames\""));
    CHECK(!rtsc::debug::CommandRequestsInput("\"op\":\"state\""));
    CHECK(!rtsc::debug::CommandRequestsInput("\"op\":\"dirty\""));
    CHECK(!rtsc::debug::CommandRequestsInput("\"op\":\"ping\""));
    CHECK(!rtsc::debug::CommandRequestsInput("\"op\":\"screenshot\""));
    CHECK(!rtsc::debug::CommandRequestsInput(""));
    // A prefix of "input" must not match: the op is compared whole.
    CHECK(!rtsc::debug::CommandRequestsInput("\"op\":\"inputish\""));
    CHECK(!rtsc::debug::CommandRequestsInput("\"op\":\"\""));
}

RTSC_TEST(gui_debug_input_parses_key_down_and_up) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"key\",\"scancode\":30,\"down\":true},{\"kind\":\"key\",\"scancode\":30,\"down\":false}]}",
        1280, 1024, events, error));
    CHECK(error.empty());
    CHECK(events.size() == 2u);
    CHECK(events[0].kind == rtsc::debug::InputEventSpec::Kind::kKey);
    CHECK(events[0].scancode == 30 && !events[0].release);
    CHECK(events[1].kind == rtsc::debug::InputEventSpec::Kind::kKey);
    CHECK(events[1].scancode == 30 && events[1].release);
}

RTSC_TEST(gui_debug_input_parses_mouse_click_in_bounds) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"mouseclick\",\"x\":100,\"y\":200,\"button\":1,\"down\":true}]}",
        1280, 1024, events, error));
    CHECK(error.empty());
    CHECK(events.size() == 1u);
    CHECK(events[0].kind == rtsc::debug::InputEventSpec::Kind::kMouseClick);
    CHECK(events[0].x == 100 && events[0].y == 200);
    CHECK(events[0].button == 1 && events[0].down);
}

RTSC_TEST(gui_debug_input_rejects_mouse_outside_desktop) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(!rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"mouseclick\",\"x\":1280,\"y\":0,\"button\":1,\"down\":true}]}",
        1280, 1024, events, error));
    CHECK(!error.empty());
    CHECK(error.find("outside") != std::string::npos);
}

RTSC_TEST(gui_debug_input_rejects_unknown_kind) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(!rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"keystroke\",\"scancode\":30,\"down\":true}]}",
        1280, 1024, events, error));
    CHECK(!error.empty());
    CHECK(error.find("kind") != std::string::npos);
}

RTSC_TEST(gui_debug_input_rejects_empty_events) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(!rtsc::debug::ParseInputEvents("{\"op\":\"input\",\"events\":[]}", 1280, 1024, events, error));
    CHECK(!error.empty());
}

RTSC_TEST(gui_debug_input_format_reply) {
    CHECK(rtsc::debug::FormatInputReply(0) == "\"ok\":true,\"injected\":0");
    CHECK(rtsc::debug::FormatInputReply(3) == "\"ok\":true,\"injected\":3");
}

RTSC_TEST(gui_debug_input_op_reports_injected) {
    DebugSnapshot s = MakeSnapshot();
    s.input_injected = 1;
    const std::string out = rtsc::debug::ExecuteGuiCommand(s, "\"op\":\"input\"");
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"injected\":1") != std::string::npos);
}

// ---- spec -> front-end event translation ---------------------------------
// main.cpp used to do this inline, so a wrong mapping (left button sent as
// right, a dropped coordinate) could only be found on a live session against a
// real server. The translation now lives in the library and is pinned here.

RTSC_TEST(gui_debug_to_ui_key_maps_scancode_release_extended) {
    rtsc::debug::InputEventSpec spec;
    spec.kind = rtsc::debug::InputEventSpec::Kind::kKey;
    spec.scancode = 0x1D;
    spec.release = true;
    spec.extended = true;
    rtsc::ui::InputEvent ev;
    CHECK(rtsc::debug::ToUiInputEvent(spec, ev));
    CHECK(ev.kind == rtsc::ui::InputEvent::Kind::kKey);
    CHECK(ev.scancode == 0x1D);
    CHECK(ev.key_release);
    CHECK(ev.key_extended);
}

RTSC_TEST(gui_debug_to_ui_key_down_clears_release) {
    rtsc::debug::InputEventSpec spec;
    spec.kind = rtsc::debug::InputEventSpec::Kind::kKey;
    spec.scancode = 30;
    spec.release = false;
    spec.extended = false;
    rtsc::ui::InputEvent ev;
    CHECK(rtsc::debug::ToUiInputEvent(spec, ev));
    CHECK(!ev.key_release);
    CHECK(!ev.key_extended);
}

RTSC_TEST(gui_debug_to_ui_mouse_click_maps_button_and_position) {
    rtsc::debug::InputEventSpec spec;
    spec.kind = rtsc::debug::InputEventSpec::Kind::kMouseClick;
    spec.x = 100;
    spec.y = 200;
    spec.button = 1;
    spec.down = true;
    rtsc::ui::InputEvent ev;
    CHECK(rtsc::debug::ToUiInputEvent(spec, ev));
    // A click is a button event on the front-end side; the down flag decides
    // press vs release. Mapping it to kMouseMove would move without clicking.
    CHECK(ev.kind == rtsc::ui::InputEvent::Kind::kMouseButton);
    CHECK(ev.button == 1);
    CHECK(ev.button_down);
    CHECK(ev.x == 100);
    CHECK(ev.y == 200);
}

RTSC_TEST(gui_debug_to_ui_mouse_click_up_clears_down) {
    rtsc::debug::InputEventSpec spec;
    spec.kind = rtsc::debug::InputEventSpec::Kind::kMouseClick;
    spec.x = 5;
    spec.y = 6;
    spec.button = 2;
    spec.down = false;
    rtsc::ui::InputEvent ev;
    CHECK(rtsc::debug::ToUiInputEvent(spec, ev));
    CHECK(ev.kind == rtsc::ui::InputEvent::Kind::kMouseButton);
    CHECK(ev.button == 2);
    CHECK(!ev.button_down);
}

RTSC_TEST(gui_debug_to_ui_mouse_click_keeps_x1_x2_numbering) {
    for (uint8_t button = 4; button <= 5; ++button) {
        rtsc::debug::InputEventSpec spec;
        spec.kind = rtsc::debug::InputEventSpec::Kind::kMouseClick;
        spec.x = 1;
        spec.y = 1;
        spec.button = button;
        rtsc::ui::InputEvent ev;
        CHECK(rtsc::debug::ToUiInputEvent(spec, ev));
        CHECK(ev.kind == rtsc::ui::InputEvent::Kind::kMouseButton);
        // The protocol layers distinguish X1/X2 by 4/5; renumbering here would
        // turn a side-button click into a middle-button click.
        CHECK(ev.button == button);
    }
}

RTSC_TEST(gui_debug_to_ui_mouse_move_maps_coordinates) {
    rtsc::debug::InputEventSpec spec;
    spec.kind = rtsc::debug::InputEventSpec::Kind::kMouseMove;
    spec.x = 1279;
    spec.y = 1023;
    rtsc::ui::InputEvent ev;
    CHECK(rtsc::debug::ToUiInputEvent(spec, ev));
    CHECK(ev.kind == rtsc::ui::InputEvent::Kind::kMouseMove);
    CHECK(ev.x == 1279);
    CHECK(ev.y == 1023);
}

RTSC_TEST(gui_debug_to_ui_wheel_maps_delta_and_axis) {
    rtsc::debug::InputEventSpec spec;
    spec.kind = rtsc::debug::InputEventSpec::Kind::kMouseWheel;
    spec.wheel_delta = -3;
    spec.horizontal = true;
    rtsc::ui::InputEvent ev;
    CHECK(rtsc::debug::ToUiInputEvent(spec, ev));
    CHECK(ev.kind == rtsc::ui::InputEvent::Kind::kMouseWheel);
    CHECK(ev.wheel_delta == -3);
    CHECK(ev.horizontal);
}

RTSC_TEST(gui_debug_to_ui_wheel_vertical_clears_horizontal) {
    rtsc::debug::InputEventSpec spec;
    spec.kind = rtsc::debug::InputEventSpec::Kind::kMouseWheel;
    spec.wheel_delta = 2;
    spec.horizontal = false;
    rtsc::ui::InputEvent ev;
    CHECK(rtsc::debug::ToUiInputEvent(spec, ev));
    CHECK(ev.wheel_delta == 2);
    CHECK(!ev.horizontal);
}

RTSC_TEST(gui_debug_to_ui_events_preserves_order) {
    std::vector<rtsc::debug::InputEventSpec> specs;
    {
        rtsc::debug::InputEventSpec s;
        s.kind = rtsc::debug::InputEventSpec::Kind::kKey;
        s.scancode = 30;
        specs.push_back(s);
    }
    {
        rtsc::debug::InputEventSpec s;
        s.kind = rtsc::debug::InputEventSpec::Kind::kKey;
        s.scancode = 30;
        s.release = true;
        specs.push_back(s);
    }
    {
        rtsc::debug::InputEventSpec s;
        s.kind = rtsc::debug::InputEventSpec::Kind::kMouseMove;
        s.x = 10;
        s.y = 20;
        specs.push_back(s);
    }
    std::vector<rtsc::ui::InputEvent> out;
    CHECK(rtsc::debug::ToUiInputEvents(specs, out));
    CHECK(out.size() == 3u);
    // Order is the operator's sequence: a reordered down/up pair types nothing.
    CHECK(!out[0].key_release && out[0].scancode == 30);
    CHECK(out[1].key_release && out[1].scancode == 30);
    CHECK(out[2].kind == rtsc::ui::InputEvent::Kind::kMouseMove);
    CHECK(out[2].x == 10 && out[2].y == 20);
}

RTSC_TEST(gui_debug_to_ui_events_empty_input_is_empty_ok) {
    std::vector<rtsc::ui::InputEvent> out;
    out.push_back(rtsc::ui::InputEvent());
    CHECK(rtsc::debug::ToUiInputEvents({}, out));
    CHECK(out.empty());
}

// ---- unicode / text typing ------------------------------------------------

RTSC_TEST(gui_debug_input_parses_unicode_event) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"unicode\",\"code\":20013,\"down\":true}]}",
        1280, 1024, events, error));
    CHECK(error.empty());
    CHECK(events.size() == 1u);
    CHECK(events[0].kind == rtsc::debug::InputEventSpec::Kind::kUnicode);
    CHECK(events[0].unicode_code == 20013);
    CHECK(!events[0].release);
}

RTSC_TEST(gui_debug_input_parses_text_ascii_as_down_up_pairs) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"ab\"}]}",
        1280, 1024, events, error));
    CHECK(error.empty());
    // Two characters -> four wire events, in typing order.
    CHECK(events.size() == 4u);
    CHECK(events[0].kind == rtsc::debug::InputEventSpec::Kind::kUnicode);
    CHECK(events[0].unicode_code == 'a');
    CHECK(!events[0].release);
    CHECK(events[1].unicode_code == 'a' && events[1].release);
    CHECK(events[2].unicode_code == 'b' && !events[2].release);
    CHECK(events[3].unicode_code == 'b' && events[3].release);
}

RTSC_TEST(gui_debug_input_parses_text_utf8_multibyte) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    // U+4E2D "中" in raw UTF-8: E4 B8 AD.
    CHECK(rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"\xE4\xB8\xAD\"}]}",
        1280, 1024, events, error));
    CHECK(error.empty());
    CHECK(events.size() == 2u);
    CHECK(events[0].unicode_code == 0x4E2D);
    CHECK(events[1].unicode_code == 0x4E2D && events[1].release);
}

RTSC_TEST(gui_debug_input_parses_text_non_bmp_as_surrogate_pair) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    // U+1F600 emoji in raw UTF-8: F0 9F 98 80.
    CHECK(rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"\xF0\x9F\x98\x80\"}]}",
        1280, 1024, events, error));
    CHECK(error.empty());
    // One code point becomes two UTF-16 units, each typed down then up.
    CHECK(events.size() == 4u);
    CHECK(events[0].unicode_code == 0xD83D && !events[0].release);
    CHECK(events[1].unicode_code == 0xD83D && events[1].release);
    CHECK(events[2].unicode_code == 0xDE00 && !events[2].release);
    CHECK(events[3].unicode_code == 0xDE00 && events[3].release);
}

RTSC_TEST(gui_debug_input_rejects_empty_text) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(!rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"\"}]}",
        1280, 1024, events, error));
    CHECK(!error.empty());
}

RTSC_TEST(gui_debug_input_rejects_invalid_utf8_text) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    std::string body = "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"";
    body += static_cast<char>(0xFF);
    body += "\"}]}";
    CHECK(!rtsc::debug::ParseInputEvents(body, 1280, 1024, events, error));
    CHECK(!error.empty());
}

// The decoder must reject the three byte sequences a well-formed UTF-8 reader
// is required to reject ([RFC 3629] 3). Accepting them would let an operator
// type a code point the protocol cannot carry, or a lone surrogate that the
// server's UTF-16 path would combine with the next character.
static bool TextEventRejected(const std::string& raw) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    std::string body = "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"";
    body += raw;
    body += "\"}]}";
    return !rtsc::debug::ParseInputEvents(body, 1280, 1024, events, error) &&
           !error.empty();
}

RTSC_TEST(gui_debug_input_rejects_utf8_above_max_code_point) {
    // U+110000 is one past the last code point: F4 90 80 80.
    CHECK(TextEventRejected(std::string("\xF4\x90\x80\x80", 4)));
}

RTSC_TEST(gui_debug_input_rejects_utf8_encoded_surrogate) {
    // U+D800 encoded directly: ED A0 80 (CESU-style, illegal in UTF-8).
    CHECK(TextEventRejected(std::string("\xED\xA0\x80", 3)));
}

RTSC_TEST(gui_debug_input_rejects_overlong_utf8) {
    // Overlong two-byte form of U+0000: C0 80.
    CHECK(TextEventRejected(std::string("\xC0\x80", 2)));
    // Overlong three-byte form of U+002F: E0 80 AF.
    CHECK(TextEventRejected(std::string("\xE0\x80\xAF", 3)));
}

RTSC_TEST(gui_debug_input_rejects_truncated_utf8) {
    // First byte promises two units, string ends.
    CHECK(TextEventRejected(std::string("\xE4\xB8", 2)));
}

RTSC_TEST(gui_debug_input_rejects_unicode_zero) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(!rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"unicode\",\"code\":0,\"down\":true}]}",
        1280, 1024, events, error));
    CHECK(!error.empty());
}

RTSC_TEST(gui_debug_to_ui_unicode_maps_code_and_release) {
    rtsc::debug::InputEventSpec spec;
    spec.kind = rtsc::debug::InputEventSpec::Kind::kUnicode;
    spec.unicode_code = 0x4E2D;
    spec.release = true;
    rtsc::ui::InputEvent ev;
    CHECK(rtsc::debug::ToUiInputEvent(spec, ev));
    CHECK(ev.kind == rtsc::ui::InputEvent::Kind::kUnicode);
    CHECK(ev.unicode_code == 0x4E2D);
    CHECK(ev.key_release);
}

// ---- resize ---------------------------------------------------------------

RTSC_TEST(gui_debug_command_requests_resize_only_for_resize_op) {
    CHECK(rtsc::debug::CommandRequestsResize("\"op\":\"resize\",\"width\":800,\"height\":600"));
    CHECK(!rtsc::debug::CommandRequestsResize("\"op\":\"input\""));
    CHECK(!rtsc::debug::CommandRequestsResize("\"op\":\"resizeish\""));
    CHECK(!rtsc::debug::CommandRequestsResize(""));
}

RTSC_TEST(gui_debug_resize_request_parses_dimensions) {
    int w = 0;
    int h = 0;
    std::string error;
    CHECK(rtsc::debug::ResizeRequest(
        "\"op\":\"resize\",\"width\":800,\"height\":600", w, h, error));
    CHECK(error.empty());
    CHECK(w == 800);
    CHECK(h == 600);
}

RTSC_TEST(gui_debug_resize_request_rejects_missing_or_zero_dimensions) {
    int w = 0;
    int h = 0;
    std::string error;
    CHECK(!rtsc::debug::ResizeRequest("\"op\":\"resize\",\"width\":800", w, h, error));
    CHECK(!error.empty());
    CHECK(!rtsc::debug::ResizeRequest(
        "\"op\":\"resize\",\"width\":0,\"height\":600", w, h, error));
    CHECK(!rtsc::debug::ResizeRequest(
        "\"op\":\"resize\",\"width\":800,\"height\":-1", w, h, error));
}

RTSC_TEST(gui_debug_resize_request_rejects_values_above_uint16) {
    int w = 0;
    int h = 0;
    std::string error;
    // 65536 would truncate to 0 in a uint16_t; 70000 would become 4464.
    CHECK(!rtsc::debug::ResizeRequest(
        "\"op\":\"resize\",\"width\":65536,\"height\":600", w, h, error));
    CHECK(!rtsc::debug::ResizeRequest(
        "\"op\":\"resize\",\"width\":800,\"height\":70000", w, h, error));
    // 65535 is the maximum valid value.
    CHECK(rtsc::debug::ResizeRequest(
        "\"op\":\"resize\",\"width\":65535,\"height\":600", w, h, error));
    CHECK(w == 65535);
}

RTSC_TEST(gui_debug_resize_reply_echoes_dimensions) {
    CHECK(rtsc::debug::FormatResizeReply(800, 600) ==
          "\"ok\":true,\"width\":800,\"height\":600");
}

RTSC_TEST(gui_debug_resize_op_returns_dimensions) {
    DebugSnapshot s = MakeSnapshot();
    const std::string out = rtsc::debug::ExecuteGuiCommand(
        s, "\"op\":\"resize\",\"width\":1024,\"height\":768");
    CHECK(out.find("\"ok\":true") != std::string::npos);
    CHECK(out.find("\"width\":1024") != std::string::npos);
    CHECK(out.find("\"height\":768") != std::string::npos);
}

RTSC_TEST(gui_debug_resize_op_rejects_out_of_range) {
    DebugSnapshot s = MakeSnapshot();
    const std::string out = rtsc::debug::ExecuteGuiCommand(
        s, "\"op\":\"resize\",\"width\":70000,\"height\":768");
    CHECK(out.find("\"ok\":false") != std::string::npos);
    CHECK(out.find("resize") != std::string::npos);
}

// ---- JSON string escape decoding -----------------------------------------
// An HTTP client is free to send non-ASCII as JSON \uXXXX escapes instead of
// raw UTF-8. The debug channel must produce the same input either way, or a
// Chinese text event silently types mojibake.

RTSC_TEST(gui_debug_input_parses_text_json_unicode_escape) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    // U+4E2D "中" as the JSON escape \u4E2D.
    CHECK(rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"\\u4E2D\"}]}",
        1280, 1024, events, error));
    CHECK(error.empty());
    CHECK(events.size() == 2u);
    CHECK(events[0].unicode_code == 0x4E2D);
    CHECK(events[1].unicode_code == 0x4E2D && events[1].release);
}

RTSC_TEST(gui_debug_input_parses_text_json_surrogate_escape) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    // U+1F600 as the JSON surrogate pair \uD83D\uDE00.
    CHECK(rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"\\uD83D\\uDE00\"}]}",
        1280, 1024, events, error));
    CHECK(error.empty());
    CHECK(events.size() == 4u);
    CHECK(events[0].unicode_code == 0xD83D);
    CHECK(events[2].unicode_code == 0xDE00);
}

RTSC_TEST(gui_debug_input_parses_text_json_standard_escapes) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    // \n must become U+000A, not the letter 'n' (the old decoder appended the
    // escape character literally).
    CHECK(rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"\\n\"}]}",
        1280, 1024, events, error));
    CHECK(error.empty());
    CHECK(events.size() == 2u);
    CHECK(events[0].unicode_code == 0x0A);
}

RTSC_TEST(gui_debug_input_rejects_text_json_bad_hex_escape) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(!rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"\\uZZZZ\"}]}",
        1280, 1024, events, error));
    CHECK(!error.empty());
}

RTSC_TEST(gui_debug_input_rejects_text_json_lone_high_surrogate) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(!rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"\\uD83D\"}]}",
        1280, 1024, events, error));
    CHECK(!error.empty());
}

RTSC_TEST(gui_debug_input_rejects_text_json_lone_low_surrogate) {
    std::vector<rtsc::debug::InputEventSpec> events;
    std::string error;
    CHECK(!rtsc::debug::ParseInputEvents(
        "{\"op\":\"input\",\"events\":[{\"kind\":\"text\",\"text\":\"\\uDE00\"}]}",
        1280, 1024, events, error));
    CHECK(!error.empty());
}

int main() { return ::rtsc::test::run_all("rtsc_gui_debug_tests"); }
