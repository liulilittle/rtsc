// Pure mapping tests for the desktop input injection seam.
//
// TranslateInput() is platform neutral by design: it never includes
// <windows.h> and never calls SendInput, so these cases run on every platform
// and pin the wire semantics that the Win32 backend relies on. Expected values
// come from docs/spec/input-injection-seam.md (P-1..P-8) and
// docs/spec/input-injection-evidence.md (1.3-1.7).

#include <cstdint>
#include <vector>

#include "rtsc/server/desktop_input_map.h"
#include "test_framework.h"
#include "test_main.h"

namespace {

using rtsc::server::InjectGeometry;
using rtsc::server::InputEvent;
using rtsc::server::PlatformInput;
using rtsc::server::TranslateInput;

InputEvent KeyEvent(uint8_t scancode, bool extended, bool release) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kKey;
    ev.scancode = scancode;
    ev.extended = extended;
    ev.release = release;
    return ev;
}

}  // namespace

RTSC_TEST(desktop_input_key_a_down) {
    const std::vector<PlatformInput> out =
        TranslateInput(KeyEvent(0x1E, false, false), InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kKey);
    CHECK_EQ(out[0].scancode, 0x1E);
    CHECK_EQ(out[0].unicode, 0u);
    CHECK(!out[0].release);
    CHECK(!out[0].extended);
}

RTSC_TEST(desktop_input_key_release) {
    const std::vector<PlatformInput> out =
        TranslateInput(KeyEvent(0x1E, false, true), InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kKey);
    CHECK_EQ(out[0].scancode, 0x1E);
    CHECK(out[0].release);
    CHECK(!out[0].extended);
}

RTSC_TEST(desktop_input_extended_key_keeps_scancode) {
    // The 0xE0 prefix is a flag on the wire and a flag in Win32; the scan code
    // itself must not be offset by 0x100.
    const std::vector<PlatformInput> out =
        TranslateInput(KeyEvent(0x1D, true, false), InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kKey);
    CHECK_EQ(out[0].scancode, 0x1D);
    CHECK(out[0].extended);
    CHECK(!out[0].release);
}

RTSC_TEST(desktop_input_unicode) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kUnicode;
    ev.unicode_code = 0x6F22;
    ev.release = false;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kKey);
    CHECK_EQ(out[0].unicode, 0x6F22u);
    CHECK_EQ(out[0].scancode, 0u);
    CHECK(!out[0].release);
}

RTSC_TEST(desktop_input_absolute_move_full_range) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = true;
    ev.x = 0;
    ev.y = 0;
    std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{1920, 1080});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 0);
    CHECK_EQ(out[0].y, 0);

    ev.x = 1920;
    ev.y = 1080;
    out = TranslateInput(ev, InjectGeometry{1920, 1080});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseMove);
    CHECK_EQ(out[0].x, 65535);
    CHECK_EQ(out[0].y, 65535);
}

RTSC_TEST(desktop_input_button_left_down) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = false;
    ev.button = 1;
    ev.button_down = true;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseButton);
    CHECK_EQ(out[0].button, 1);
    CHECK(out[0].button_down);
}

RTSC_TEST(desktop_input_button_left_up_keeps_identity) {
    // A release carries the button bit without PTRFLAGS_DOWN; the identity must
    // survive, otherwise the local button stays pressed forever.
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = false;
    ev.button = 1;
    ev.button_down = false;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kMouseButton);
    CHECK_EQ(out[0].button, 1);
    CHECK(!out[0].button_down);
}

RTSC_TEST(desktop_input_wheel_positive_is_wire_units) {
    // wheel_delta is already WHEEL_DELTA units (120 per notch); multiplying by
    // 120 here would send 14400.
    InputEvent ev;
    ev.kind = InputEvent::Kind::kWheel;
    ev.wheel_delta = 120;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kWheel);
    CHECK_EQ(out[0].wheel, 120);
    CHECK(!out[0].horizontal);
}

RTSC_TEST(desktop_input_wheel_negative_is_wire_units) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kWheel;
    ev.wheel_delta = -120;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kWheel);
    CHECK_EQ(out[0].wheel, -120);
    CHECK(!out[0].horizontal);
}

RTSC_TEST(desktop_input_horizontal_wheel) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kWheel;
    ev.wheel_delta = 120;
    ev.horizontal = true;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kWheel);
    CHECK_EQ(out[0].wheel, 120);
    CHECK(out[0].horizontal);
}

RTSC_TEST(desktop_input_mouse_relative_not_injected) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouseRel;
    ev.rel_x = 10;
    ev.rel_y = -5;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK(out.empty());
}

RTSC_TEST(desktop_input_sync_not_injected) {
    InputEvent ev;
    ev.kind = InputEvent::Kind::kSync;
    ev.sync_flags = 0x06;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK(out.empty());
}

RTSC_TEST(desktop_input_wheel_ignores_xy) {
    // [MS-RDPBCGR] says xPos/yPos must be ignored for a wheel event; carrying
    // them into an absolute move would jump the pointer to the wheel origin.
    InputEvent ev;
    ev.kind = InputEvent::Kind::kWheel;
    ev.wheel_delta = 120;
    ev.x = 123;
    ev.y = 456;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK_EQ(out.size(), 1u);
    if (out.size() != 1) return;
    CHECK(out[0].kind == PlatformInput::Kind::kWheel);
    CHECK_EQ(out[0].x, 0);
    CHECK_EQ(out[0].y, 0);
    CHECK_EQ(out[0].wheel, 120);
}

RTSC_TEST(desktop_input_mouse_without_move_or_button_is_empty) {
    // A plain kMouse without PTRFLAGS_MOVE and without a button bit must not
    // become an absolute move to (0, 0).
    InputEvent ev;
    ev.kind = InputEvent::Kind::kMouse;
    ev.is_move = false;
    ev.button = 0;
    const std::vector<PlatformInput> out = TranslateInput(ev, InjectGeometry{});
    CHECK(out.empty());
}

int main() { return rtsc::test::run_all("rtsc_desktop_input_tests"); }
