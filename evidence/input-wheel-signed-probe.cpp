// The wheel rotation field is a 9-bit SIGNED value, not "magnitude + a separate
// negative flag".
//
// [MS-RDPBCGR] TS_POINTER_EVENT:
//   PTRFLAGS_WHEEL_NEGATIVE 0x0100
//     "The wheel rotation value (contained in the WheelRotationMask bit field)
//      is negative and MUST be sign-extended before injection at the server."
//   WheelRotationMask 0x01FF
//
// 0x01FF is nine bits wide and 0x0100 is bit 8 of that same field -- i.e. the
// sign bit. Treating 0x0100 as an independent flag AND masking it back into the
// magnitude counts it twice, which is what the repo does today.
//
// Correct:
//   encode(d) = (d >= 0) ? d : (0x200 + d)          // two's complement, 9 bits
//   decode(f) = (f & 0x100) ? (int)(f) - 0x200 : (int)(f)
#include <cstdio>
#include <cstdint>

static constexpr uint16_t kPtrHwheel = 0x0400;
static constexpr uint16_t kPtrWheel = 0x0200;
static constexpr uint16_t kPtrWheelRotationMask = 0x01FF;

// --- today's repo behaviour (mirrors client.cpp:231-238 / server.cpp:1573-1578)
static uint16_t BadEncode(int16_t d) {
    uint16_t flags = kPtrWheel;
    const int16_t mag = static_cast<int16_t>(d < 0 ? -d : d);
    if (d < 0) flags |= 0x0100;  // kPtrWheelNegative
    flags |= static_cast<uint16_t>(mag & kPtrWheelRotationMask);
    return flags;
}
static int16_t BadDecode(uint16_t pf) {
    const uint16_t rot = static_cast<uint16_t>(pf & kPtrWheelRotationMask);
    int16_t d = static_cast<int16_t>(rot);
    if ((pf & 0x0100) != 0) d = static_cast<int16_t>(-d);
    return d;
}

// --- correct 9-bit two's complement field
static uint16_t GoodEncode(int16_t d, bool horizontal) {
    uint16_t flags = horizontal ? kPtrHwheel : kPtrWheel;
    const int32_t f = (d >= 0) ? d : (0x200 + d);
    return static_cast<uint16_t>(flags | (f & kPtrWheelRotationMask));
}
static int16_t GoodDecode(uint16_t pf) {
    const int32_t f = pf & kPtrWheelRotationMask;
    return static_cast<int16_t>((f & 0x100) ? (f - 0x200) : f);
}

static int failures = 0;
static void check(const char* what, bool ok) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

int main() {
    const int16_t deltas[] = {1, -1, 120, -120, 240, -240, -255, 255};
    std::printf("== today (magnitude + separate negative flag) ==\n");
    for (int16_t d : deltas) {
        const uint16_t f = BadEncode(d);
        std::printf("  d=%5d -> flags=0x%04X -> back=%5d\n", d, f, BadDecode(f));
    }
    int bad_ok = 0;
    for (int16_t d : deltas) {
        if (BadDecode(BadEncode(d)) == d) ++bad_ok;
    }
    check("today's codec round-trips (expected to fail)",
          bad_ok == static_cast<int>(sizeof(deltas) / sizeof(deltas[0])));

    std::printf("\n== 9-bit sign-extended field ==\n");
    for (int16_t d : deltas) {
        const uint16_t f = GoodEncode(d, false);
        std::printf("  d=%5d -> flags=0x%04X -> back=%5d\n", d, f,
                    GoodDecode(f));
    }
    bool all = true;
    for (int16_t d : deltas) {
        if (GoodDecode(GoodEncode(d, false)) != d) all = false;
    }
    check("9-bit sign-extended codec round-trips", all);
    check("9-bit encode(-1) == 0x03FF (0x0200 | 0x1FF)", GoodEncode(-1, false) == 0x03FF);
    check("9-bit encode(-120) == 0x0388", GoodEncode(-120, false) == 0x0388);
    check("9-bit encode(120) == 0x0278", GoodEncode(120, false) == 0x0278);

    // Horizontal wheel uses the same field layout.
    check("HWHEEL encode(-1) == 0x05FF", GoodEncode(-1, true) == 0x05FF);
    check("HWHEEL decode(0x05F1) == -15", GoodDecode(0x05F1) == -15);
    check("vertical takes precedence when both bits set",
          (0x0600 & kPtrWheel) != 0);

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
