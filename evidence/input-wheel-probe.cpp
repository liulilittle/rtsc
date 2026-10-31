// Probe: the repo's own wheel encoder and decoder disagree on negative deltas.
//
// Encode (-1)  -> flags = kPtrWheel(0x0200) | kPtrWheelNegative(0x0100) | 1
//                       = 0x0301
// Decode(0x0301) -> rot = 0x0301 & kPtrWheelRotationMask(0x01FF) = 0x0101 = 257
//                   NEGATIVE set -> -257
//
// The mask (0x01FF) overlaps the flag bits (0x0200 / 0x0100), so the decoder
// reads the flag bits back as part of the rotation magnitude.
#include <cstdio>
#include <cstdint>

#include "rtsc/proto/input.h"

using namespace rtsc::proto;

// Mirror of src/client/client.cpp EncodeWheelFlags (delta -> flags).
static uint16_t Encode(int16_t delta, bool horizontal) {
    uint16_t flags = horizontal ? kPtrHwheel : kPtrWheel;
    const int16_t magnitude = static_cast<int16_t>(delta < 0 ? -delta : delta);
    if (delta < 0) flags |= kPtrWheelNegative;
    flags |= static_cast<uint16_t>(magnitude & kPtrWheelRotationMask);
    return flags;
}

// Mirror of src/server/server.cpp wheel decode (flags -> delta).
static int16_t Decode(uint16_t pf, int16_t* horizontal_out) {
    *horizontal_out = ((pf & kPtrHwheel) != 0) ? 1 : 0;
    const uint16_t rot = static_cast<uint16_t>(pf & kPtrWheelRotationMask);
    int16_t d = static_cast<int16_t>(rot);
    if ((pf & kPtrWheelNegative) != 0) d = static_cast<int16_t>(-d);
    return d;
}

static int failures = 0;
static void check(const char* what, bool ok) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

int main() {
    const int16_t deltas[] = {1, -1, 120, -120, 240, -240, 0};
    for (int16_t d : deltas) {
        const uint16_t flags = Encode(d, /*horizontal=*/false);
        int16_t horiz = 0;
        const int16_t back = Decode(flags, &horiz);
        std::printf("  [INFO] delta=%5d -> flags=0x%04X -> decoded=%5d\n", d,
                    flags, back);
        if (d == 0) continue;  // zero delta is not a wheel event
        check("vertical wheel round-trips", back == d);
    }

    // Horizontal wheel: the decoder does not recognise kPtrHwheel at all today,
    // so it reports a plain mouse event with a bogus delta.
    {
        const uint16_t flags = Encode(1, /*horizontal=*/true);
        int16_t horiz = 0;
        const int16_t back = Decode(flags, &horiz);
        std::printf("  [INFO] HWHEEL flags=0x%04X -> decoded=%d horizontal=%d\n",
                    flags, back, horiz);
        check("horizontal wheel is recognised", horiz == 1);
    }

    // A button-release carries no button identity, so an injector cannot tell
    // "pointer moved" from "left button went up".
    {
        const uint16_t release = kPtrButton1;  // left button released
        const uint16_t move = kPtrMove;
        const int16_t b1 = (release & kPtrButton1) != 0 ? 1 : 0;
        const int16_t b2 = (move & kPtrButton1) != 0 ? 1 : 0;
        std::printf("  [INFO] release flags=0x%04X button=%d, move flags=0x%04X "
                    "button=%d\n", release, b1, move, b2);
        check("a release is distinguishable from a move",
              (release & (kPtrButton1 | kPtrButton2 | kPtrButton3)) !=
                  (move & (kPtrButton1 | kPtrButton2 | kPtrButton3)));
    }

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
