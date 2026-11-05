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

int main() { return ::rtsc::test::run_all("rtsc_gui_debug_tests"); }
