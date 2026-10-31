// The wheel wire unit is 120 per notch (WHEEL_DELTA), not 1 -- this is what
// mstsc, FreeRDP and Remmina all send, and what gnome-remote-desktop divides by
// (axis_value / 120.0).
//
// Evidence:
//   * FreeRDP PR #6806 "clients: Use the correct wheel rotation value":
//     the old client sent "the positive wheel value with the negative flag,
//     which results in a wrong wheel value on the server side (136 instead of
//     120)" -- i.e. one notch is 120.
//   * Remmina 4a546fac: `PTR_FLAGS_WHEEL | 0x0188; // -120 (one scroll unit)`.
//   * gnome-remote-desktop f134b16: `axis_step = -axis_value / 120.0;`.
//
// So this repo has TWO defects in series:
//   1. the unit is wrong: ui::InputEvent.wheel_delta is in NOTCHES (the Win32
//      backend divides by 120 at window_win32.cpp:505-507), but the encoder puts
//      it on the wire verbatim, so one notch travels as 1 unit = 1/120 notch.
//   2. the negative encoding is wrong (magnitude + separate flag, not 9-bit
//      two's complement).
//
// Consequence: against a real Windows server a notch scrolls ~0 rows; against
// our own server (which also treats the wire value as notches) it happens to
// work, which is why the internal round trip never noticed.
#include <cstdio>
#include <cstdint>

static constexpr int kWheelDelta = 120;
static constexpr uint16_t kPtrWheel = 0x0200;
static constexpr uint16_t kPtrHwheel = 0x0400;
static constexpr uint16_t kMask = 0x01FF;

// --- today: notches straight onto the wire, magnitude + separate flag
static uint16_t Today(int16_t notches) {
    const uint16_t mag = static_cast<uint16_t>(notches < 0 ? -notches : notches);
    uint16_t f = kPtrWheel;
    if (notches < 0) f |= 0x0100;
    return static_cast<uint16_t>(f | (mag & kMask));
}

// --- correct: units = notches * 120, 9-bit two's complement
static bool Correct(int16_t notches, uint16_t& out) {
    const int32_t units = static_cast<int32_t>(notches) * kWheelDelta;
    if (units < -256 || units > 255) return false;  // needs splitting
    const uint16_t field =
        static_cast<uint16_t>(units >= 0 ? units : (0x200 + units));
    out = static_cast<uint16_t>(kPtrWheel | (field & kMask));
    return true;
}

// What gnome-remote-desktop does to a received frame (the reference decoder).
static double GndDecodeNotches(uint16_t flags) {
    uint16_t v = static_cast<uint16_t>(flags & kMask);
    if (v & 0x0100) {
        v = static_cast<uint16_t>(~v & kMask);
        ++v;
    }
    double step = -(v) / 120.0;
    if (flags & 0x0100) step = -step;
    return step;
}

int main() {
    int failures = 0;
    auto check = [&](const char* w, bool ok) {
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", w);
        if (!ok) ++failures;
    };

    std::printf("Today's encoder vs the reference decoder (gnome-remote-desktop)\n");
    const int16_t probe[] = {1, -1, 2, -2};
    for (int16_t n : probe) {
        const uint16_t f = Today(n);
        std::printf("  notch=%3d -> flags=0x%04X -> reference reads %.4f notches\n",
                    n, f, GndDecodeNotches(f));
    }
    {
        const uint16_t f = Today(1);
        // Reference decodes 1 unit as 1/120 of a notch.
        check("today: one notch travels as one unit (1/120 of a notch)",
              GndDecodeNotches(f) < 0.02);
    }

    std::printf("\nCorrect encoder vs the reference decoder\n");
    const int16_t probe2[] = {1, -1, 2, -2};
    for (int16_t n : probe2) {
        uint16_t f = 0;
        if (!Correct(n, f)) {
            std::printf("  notch=%3d -> exceeds the 9-bit field\n", n);
            continue;
        }
        std::printf("  notch=%3d -> flags=0x%04X -> reference reads %.4f notches\n",
                    n, f, GndDecodeNotches(f));
    }
    {
        uint16_t f = 0;
        check("correct: encode(1) uses 120 units", Correct(1, f) && f == 0x0278);
        check("correct: encode(-1) == 0x0388 (9-bit two's complement of -120)",
              Correct(-1, f) && f == 0x0388);
        check("correct: encode(2) == 0x02F0 (240)", Correct(2, f) && f == 0x02F0);
        check("correct: encode(-2) == 0x0310", Correct(-2, f) && f == 0x0310);
        // Magnitude only. gnome-remote-desktop negates the whole value
        // (axis_step = -value/120), so its sign convention is inverted
        // relative to this repo's "positive = up". What is unambiguous
        // and checkable here is the MAGNITUDE: 120 units == 1 notch.
        const double pos120 = GndDecodeNotches(0x0278);
        const double neg120 = GndDecodeNotches(0x0388);
        check("correct: magnitude of +120 units is 1 notch",
              pos120 > -1.01 && pos120 < -0.99);
        check("correct: magnitude of -120 units is 1 notch",
              neg120 > 0.99 && neg120 < 1.01);
    }
    {
        uint16_t f = 0;
        check("3 notches (360 units) does NOT fit: must be split",
              !Correct(3, f));
    }

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
