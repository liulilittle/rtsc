// Precisely bound the wheel field for THIS repo's convention.
//
// Repo convention (include/rtsc/ui/window.h:174-177): wheel_delta is in
// NOTCHES ("positive = up / right"), one per WHEEL_DELTA(120) crossing -- the
// Win32 backend already divides by WHEEL_DELTA (window_win32.cpp:505-507).
//
// The wire field is 9-bit sign-extended: mask 0x01FF, bit 8 = sign.
//   range = -256 .. +255 notches
//
// So audit B's "3 notches = 360 wraps" example does not apply: 3 notches is
// delta = 3, not 360. But its underlying concern IS reachable: a single
// WM_MOUSEWHEEL can carry a raw delta up to 32767, i.e. 273 notches, which
// exceeds +255 and would wrap.
#include <cstdio>
#include <cstdint>

static uint16_t Encode(int16_t notches) {
    const int32_t f = (notches >= 0) ? notches : (0x200 + notches);
    return static_cast<uint16_t>(0x0200 | (f & 0x01FF));
}
static int16_t Decode(uint16_t flags) {
    const int32_t f = flags & 0x01FF;
    return static_cast<int16_t>((f & 0x100) ? (f - 0x200) : f);
}

// What the Win32 backend can actually produce in one event.
static int16_t RawDeltaToNotches(int raw, int& remainder) {
    // One message only: accum starts at 0, so steps = raw / 120.
    const int steps = raw / 120;
    remainder = raw - steps * 120;
    if (steps > 32767) return 32767;
    if (steps < -32768) return -32768;
    return static_cast<int16_t>(steps);
}

static int failures = 0;
static void check(const char* what, bool ok) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

int main() {
    std::printf("9-bit sign-extended range: -256 .. +255 notches\n\n");

    // Realistic single-message scrolls.
    const int raws[] = {120, -120, 240, -240, 360, -360, 1200, -1200};
    for (int raw : raws) {
        int rem = 0;
        const int16_t n = RawDeltaToNotches(raw, rem);
        const uint16_t f = Encode(n);
        const int16_t back = Decode(f);
        const bool ok = back == n;
        std::printf("  raw=%6d -> %3d notch -> flags=0x%04X -> %4d %s\n", raw, n, f,
                    back, ok ? "ok" : "WRAP");
        check("realistic scrolls round-trip", ok);
    }

    std::printf("\n");
    // The reachable overflow: raw 32767 => 273 notches > 255.
    {
        int rem = 0;
        const int16_t n = RawDeltaToNotches(32767, rem);
        const uint16_t f = Encode(n);
        const int16_t back = Decode(f);
        std::printf("  raw= 32767 -> %3d notch (max int16) -> flags=0x%04X -> %4d\n",
                    n, f, back);
        check("273 notches overflows the 9-bit field (needs clamping)", back != n);
    }
    // A clamp keeps the direction but caps the magnitude.
    {
        int rem = 0;
        int16_t n = RawDeltaToNotches(32767, rem);
        const int16_t clamped = n > 255 ? 255 : (n < -256 ? -256 : n);
        const int16_t back = Decode(Encode(clamped));
        std::printf("  clamped to %d -> back=%d (direction preserved)\n", clamped,
                    back);
        check("clamping preserves the sign", (back > 0) == (n > 0));
    }

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
