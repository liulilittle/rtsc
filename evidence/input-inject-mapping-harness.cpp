// Pure-function harness for the proposed server-side input mapping
// (docs/spec/input-injection-evidence.md sections 5.3/6). It builds
// INPUT arrays but NEVER calls SendInput: no input is injected into the
// desktop by this program.
//
//   baseline      -> every assertion passes
//   --mutate=N    -> breaks one key decision; the assertion table MUST go red
//
// Build: evidence\input-inject-probe-build.bat (second cl invocation)
// Run:   evidence\input-inject-mapping-harness.exe [--mutate=N]

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

namespace {

// ---- proposed seam: what InputEvent carries (mirrors server.h currently) ----
enum class Kind { kKey, kMouse, kWheel, kSync, kUnicode };

struct Ev {
    Kind kind = Kind::kKey;
    unsigned char scancode = 0;
    unsigned short unicode_code = 0;
    bool release = false;
    bool extended = false;
    bool extended1 = false;  // NOT in server.h today (E1 prefix, PAUSE)
    unsigned short x = 0, y = 0;
    unsigned short button = 0;  // 1..5
    bool button_down = false;
    long wheel_delta = 0;  // wire units: 120 per notch
    bool horizontal = false;
    unsigned char sync_flags = 0;
};

struct Geometry {  // negotiated desktop (per session)
    int width = 1280, height = 1024;
};

struct Target {  // where the framebuffer came from, virtual-screen px
    int left = 0, top = 0, width = 1280, height = 1024;
    int vleft = 0, vtop = 0, vwidth = 1280, vheight = 1024;  // virtual desktop
};

constexpr ULONG_PTR kInjectTag = 0x52545343;  // 'RTSC'

int g_mutation = 0;

unsigned Normalize(int physical, int origin, int extent) {
    if (extent <= 1) return 0;
    const int den_extent = (g_mutation == 3) ? extent : extent - 1;
    const long long num = (long long)(physical - origin) * 65535LL;
    return (unsigned)((num + den_extent / 2) / den_extent);
}

unsigned short PhysOf(unsigned coord, int origin, int span, int desktop) {
    if (desktop <= 0) return (unsigned short)origin;
    long long v = origin + ((long long)coord * span + desktop / 2) / desktop;
    if (v < -32768) v = -32768;
    if (v > 32767) v = 32767;
    return (unsigned short)(short)v;
}

bool BuildInputs(const Ev& ev, const Geometry& g, const Target& t,
                 std::vector<INPUT>& out, std::string& err) {
    out.clear();
    err.clear();
    switch (ev.kind) {
        case Kind::kKey: {
            if (ev.extended1) {
                err = "E1-prefixed key (PAUSE) has no KEYEVENTF equivalent";
                return false;
            }
            if (ev.scancode == 0 && g_mutation != 7) {
                err = "scancode 0 is not a key (phantom event)";
                return false;
            }
            INPUT in{};
            in.type = INPUT_KEYBOARD;
            in.ki.wVk = 0;  // ignored when KEYEVENTF_SCANCODE is set
            in.ki.wScan = ev.scancode;
            in.ki.dwFlags = KEYEVENTF_SCANCODE;
            if (ev.extended && g_mutation != 1) in.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
            if (ev.release && g_mutation != 4) in.ki.dwFlags |= KEYEVENTF_KEYUP;
            in.ki.dwExtraInfo = kInjectTag;
            out.push_back(in);
            return true;
        }
        case Kind::kUnicode: {
            INPUT in{};
            in.type = INPUT_KEYBOARD;
            in.ki.wVk = 0;  // "wVk must be 0" with KEYEVENTF_UNICODE
            in.ki.wScan = ev.unicode_code;
            in.ki.dwFlags = KEYEVENTF_UNICODE;
            if (ev.release) in.ki.dwFlags |= KEYEVENTF_KEYUP;
            in.ki.dwExtraInfo = kInjectTag;
            out.push_back(in);
            return true;
        }
        case Kind::kMouse: {
            const int phys_x = (int)(short)PhysOf(ev.x, t.left, t.width, g.width);
            const int phys_y = (int)(short)PhysOf(ev.y, t.top, t.height, g.height);
            const unsigned nx = Normalize(phys_x, t.vleft, t.vwidth);
            const unsigned ny = Normalize(phys_y, t.vtop, t.vheight);
            INPUT move{};
            move.type = INPUT_MOUSE;
            move.mi.dx = (LONG)nx;
            move.mi.dy = (LONG)ny;
            move.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE |
                              MOUSEEVENTF_VIRTUALDESK;
            if (g_mutation == 6) move.mi.dwFlags = MOUSEEVENTF_MOVE;
            move.mi.dwExtraInfo = kInjectTag;
            out.push_back(move);
            if (ev.button != 0) {
                DWORD fl = 0;
                DWORD data = 0;
                switch (ev.button) {
                    case 1: fl = ev.button_down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP; break;
                    case 2: fl = ev.button_down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP; break;
                    case 3: fl = ev.button_down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP; break;
                    case 4: fl = ev.button_down ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
                            data = XBUTTON1; break;
                    case 5: fl = ev.button_down ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
                            data = XBUTTON2; break;
                    default: break;
                }
                if (g_mutation == 5 && ev.button == 4) data = XBUTTON2;
                INPUT btn{};
                btn.type = INPUT_MOUSE;
                btn.mi.dx = (LONG)nx;
                btn.mi.dy = (LONG)ny;
                btn.mi.mouseData = data;
                btn.mi.dwFlags = fl | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
                btn.mi.dwExtraInfo = kInjectTag;
                out.push_back(btn);
            }
            return true;
        }
        case Kind::kWheel: {
            long long data = (long long)ev.wheel_delta;
            if (g_mutation == 2) data = -data;
            INPUT in{};
            in.type = INPUT_MOUSE;
            in.mi.mouseData = (DWORD)(int)data;
            in.mi.dwFlags = ev.horizontal ? MOUSEEVENTF_HWHEEL : MOUSEEVENTF_WHEEL;
            in.mi.dwExtraInfo = kInjectTag;
            out.push_back(in);
            return true;
        }
        case Kind::kSync:
            return true;  // no Win32 equivalent; must not synthesize a keypress
    }
    return false;
}

int g_failures = 0;
int g_checks = 0;

void Check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        printf("  FAIL %s\n", what);
    }
}

Ev Key(unsigned char sc, bool release, bool ext) {
    Ev e;
    e.kind = Kind::kKey;
    e.scancode = sc;
    e.release = release;
    e.extended = ext;
    return e;
}

}  // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--mutate=", 9) == 0) g_mutation = atoi(argv[i] + 9);
    }
    Geometry g;
    Target t;  // capture rect == negotiated geometry, single 1280x1024 monitor
    std::vector<INPUT> in;
    std::string err;

    // A1: 'A' down -> scancode-only, no VK, no extended.
    Ev e = Key(0x1E, false, false);
    Check(BuildInputs(e, g, t, in, err), "A1 build");
    Check(in.size() == 1 && in[0].type == INPUT_KEYBOARD, "A1 one keyboard input");
    Check(in[0].ki.wVk == 0, "A1 wVk must be 0 (ignored with KEYEVENTF_SCANCODE)");
    Check(in[0].ki.wScan == 0x1E, "A1 wScan = RDP keyCode verbatim");
    Check(in[0].ki.dwFlags == KEYEVENTF_SCANCODE, "A1 flags = KEYEVENTF_SCANCODE only");

    // A2: right Ctrl (RDP 0x1D + extended) -> 0xE0 from the flag, NOT +0x100.
    e = Key(0x1D, false, true);
    Check(BuildInputs(e, g, t, in, err), "A2 build");
    Check(in[0].ki.wScan == 0x1D, "A2 wScan stays 0x1D (no 0x100 bias)");
    Check((in[0].ki.dwFlags & KEYEVENTF_EXTENDEDKEY) != 0, "A2 KEYEVENTF_EXTENDEDKEY set");

    // A3: right Ctrl up.
    e = Key(0x1D, true, true);
    Check(BuildInputs(e, g, t, in, err), "A3 build");
    Check(in[0].ki.dwFlags == (KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP),
          "A3 flags = SCANCODE|EXTENDEDKEY|KEYUP");

    // A4: unicode 'CJK' U+6F22.
    e = Ev();
    e.kind = Kind::kUnicode;
    e.unicode_code = 0x6F22;
    Check(BuildInputs(e, g, t, in, err), "A4 build");
    Check(in[0].ki.wVk == 0 && in[0].ki.wScan == 0x6F22, "A4 unicode wScan=0x6F22 wVk=0");
    Check(in[0].ki.dwFlags == KEYEVENTF_UNICODE, "A4 flags = KEYEVENTF_UNICODE");

    // A5: absolute normalization endpoints.
    e = Ev();
    e.kind = Kind::kMouse;
    e.x = 0;
    e.y = 0;
    Check(BuildInputs(e, g, t, in, err), "A5 build origin");
    Check(in[0].mi.dx == 0 && in[0].mi.dy == 0, "A5 (0,0) -> (0,0)");
    e.x = (unsigned short)(g.width - 1);
    e.y = (unsigned short)(g.height - 1);
    Check(BuildInputs(e, g, t, in, err), "A5 build corner");
    Check(in[0].mi.dx == 65535 && in[0].mi.dy == 65535, "A5 (w-1,h-1) -> (65535,65535)");
    Check((in[0].mi.dwFlags & (MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK)) ==
              (MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK),
          "A5 ABSOLUTE|VIRTUALDESK always set");
    // A5b: integer round trip must stay within one pixel for every sample.
    const int samples[] = {0, 1, g.width / 2, g.width - 2, g.width - 1};
    bool round_trip_ok = true;
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
        const int px = samples[i];
        const unsigned n = Normalize(px, 0, g.width);
        const int back = (int)(((long long)n * (g.width - 1) + 32767) / 65535);
        if (back - px > 1 || px - back > 1) round_trip_ok = false;
    }
    Check(round_trip_ok, "A5b round trip error <= 1 px for all samples");

    // A6: left click at (100,50) -> move then LEFTDOWN.
    e = Ev();
    e.kind = Kind::kMouse;
    e.x = 100;
    e.y = 50;
    e.button = 1;
    e.button_down = true;
    Check(BuildInputs(e, g, t, in, err), "A6 build");
    Check(in.size() == 2, "A6 move+button in one SendInput array");
    Check(in[0].mi.dwFlags == (MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK),
          "A6 first input is MOVE");
    Check(in[1].mi.dwFlags == (MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK),
          "A6 second input is LEFTDOWN at the same point");

    // A7: right button up (release must still name the button).
    e.button = 2;
    e.button_down = false;
    Check(BuildInputs(e, g, t, in, err), "A7 build");
    Check((in[1].mi.dwFlags & MOUSEEVENTF_RIGHTUP) != 0, "A7 RIGHTUP");

    // A8: X buttons carry XBUTTON1/XBUTTON2 in mouseData.
    e.button = 4;
    e.button_down = true;
    Check(BuildInputs(e, g, t, in, err), "A8 build");
    Check((in[1].mi.dwFlags & MOUSEEVENTF_XDOWN) != 0 && in[1].mi.mouseData == XBUTTON1,
          "A8 X1 -> XDOWN + XBUTTON1");
    e.button = 5;
    Check(BuildInputs(e, g, t, in, err), "A8 build x2");
    Check(in[1].mi.mouseData == XBUTTON2, "A8 X2 -> XBUTTON2");

    // A9: wheel signs/units.
    e = Ev();
    e.kind = Kind::kWheel;
    e.wheel_delta = 120;  // one notch forward
    Check(BuildInputs(e, g, t, in, err), "A9 build +1");
    Check(in.size() == 1 && in[0].mi.dwFlags == MOUSEEVENTF_WHEEL, "A9 WHEEL flag");
    Check(in[0].mi.mouseData == 120, "A9 +1 notch -> mouseData 120");
    e.wheel_delta = -120;
    Check(BuildInputs(e, g, t, in, err), "A9 build -1");
    Check((long)(int)in[0].mi.mouseData == -120, "A9 -1 notch -> mouseData -120 (two's complement)");
    e.wheel_delta = 120;
    e.horizontal = true;
    Check(BuildInputs(e, g, t, in, err), "A9 build hwheel");
    Check(in[0].mi.dwFlags == MOUSEEVENTF_HWHEEL, "A9 HWHEEL flag");
    Check(in[0].mi.mouseData == 120, "A9 horizontal + -> right (same sign)");

    // A10: sync events never synthesize a keypress (a toggle would double).
    e = Ev();
    e.kind = Kind::kSync;
    e.sync_flags = 0x02;
    Check(BuildInputs(e, g, t, in, err), "A10 build");
    Check(in.empty(), "A10 kSync -> no INPUT");

    // A11: E1 (PAUSE) is not expressible with KEYEVENTF_*.
    e = Key(0x45, false, false);
    e.extended1 = true;
    Check(!BuildInputs(e, g, t, in, err), "A11 extended1 must be refused");
    Check(!err.empty(), "A11 refusal carries a reason");

    // A12: a "phantom" kKey with scancode 0 must be refused. server.cpp emits
    // exactly that for kMouseRel/kQoeTimestamp (default-constructed InputEvent
    // reaches input_callback_ at server.cpp:1614), and injecting it would press
    // an invalid key that never releases.
    e = Key(0x00, false, false);
    Check(!BuildInputs(e, g, t, in, err), "A12 scancode 0 must be refused");

    printf("%s: %d checks, %d failure(s)%s\n", g_mutation ? "MUTANT" : "BASELINE",
           g_checks, g_failures, g_mutation ? "" : " (all green expected)");
    return g_failures == 0 ? 0 : 1;
}
