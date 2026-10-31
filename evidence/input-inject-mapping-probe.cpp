// Read-only probe for docs/spec/input-injection-evidence.md.
//
// It DOES NOT inject input: no SendInput / keybd_event / mouse_event /
// SetCursorPos call appears in this file. It only queries Win32 for the facts
// the injection design depends on:
//   * MapVirtualKeyW(VK, MAPVK_VK_TO_VSC) and MAPVK_VK_TO_VSC_EX results, so the
//     "scan code only, 0xE0 comes from KEYEVENTF_EXTENDEDKEY" decision can be
//     checked against the running OS;
//   * virtual-screen metrics / monitor rectangles (the space
//     MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_VIRTUALDESK normalizes over);
//   * the absolute-coordinate normalization and its round-trip error;
//   * the wheel unit conversion (notches -> WHEEL_DELTA multiples);
//   * the process's window station / desktop identity and session id, so the
//     "which desktop does the injector land on" claim is measured, not assumed.
//
// Build: evidence\input-inject-probe-build.bat
// Run:   evidence\input-inject-probe.exe > evidence\input-inject-mapping-probe.txt

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static const char* DesktopNameOf(HANDLE h) {
    static char buf[256];
    DWORD needed = 0;
    buf[0] = 0;
    if (!GetUserObjectInformationA(h, UOI_NAME, buf, sizeof(buf), &needed)) {
        snprintf(buf, sizeof(buf), "<error %lu>", GetLastError());
    }
    return buf;
}

static void PrintVk(const char* name, UINT vk) {
    const UINT vsc = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    const UINT vsc_ex = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC_EX);
    printf("%-12s vk=0x%02X  VK_TO_VSC=0x%04X  VK_TO_VSC_EX=0x%04X  (low=0x%02X high=0x%02X)\n",
           name, vk, vsc, vsc_ex, vsc_ex & 0xFF, (vsc_ex >> 8) & 0xFF);
}

static void PrintVscToVk(const char* label, UINT vsc_word) {
    const UINT vk = MapVirtualKeyW(vsc_word, MAPVK_VSC_TO_VK_EX);
    printf("%-34s scancode=0x%04X -> VK_EX=0x%02X\n", label, vsc_word, vk);
}

// The proposed mapping, expressed as the code the implementation would run.
static UINT Normalize(int physical, int origin, int extent) {
    if (extent <= 1) return 0;
    const long long num = (long long)(physical - origin) * 65535LL;
    const long long den = (long long)(extent - 1);
    return (UINT)((num + den / 2) / den);  // round half up
}

int main(void) {
    printf("== 1. MapVirtualKeyW: virtual key -> scan code ==\n");
    PrintVk("VK_LSHIFT", VK_LSHIFT);
    PrintVk("VK_RSHIFT", VK_RSHIFT);
    PrintVk("VK_LCONTROL", VK_LCONTROL);
    PrintVk("VK_RCONTROL", VK_RCONTROL);
    PrintVk("VK_LMENU", VK_LMENU);
    PrintVk("VK_RMENU", VK_RMENU);
    PrintVk("VK_LWIN", VK_LWIN);
    PrintVk("VK_RWIN", VK_RWIN);
    PrintVk("VK_APPS", VK_APPS);
    PrintVk("VK_DELETE", VK_DELETE);
    PrintVk("VK_HOME", VK_HOME);
    PrintVk("VK_END", VK_END);
    PrintVk("VK_NUMLOCK", VK_NUMLOCK);
    PrintVk("VK_PAUSE", VK_PAUSE);
    PrintVk("VK_SNAPSHOT", VK_SNAPSHOT);
    PrintVk("VK_DIVIDE", VK_DIVIDE);
    PrintVk("VK_RETURN", VK_RETURN);
    PrintVk("VK_CAPITAL", VK_CAPITAL);
    PrintVk("'A'", 'A');

    printf("\n== 2. MapVirtualKeyW: scan code -> virtual key (what the OS thinks a RDP keyCode means) ==\n");
    PrintVscToVk("0x0038 (RDP LAlt byte)", 0x0038);
    PrintVscToVk("0xE038 (RDP 0x38 + extended)", 0xE038);
    PrintVscToVk("0x001D (RDP LCtrl byte)", 0x001D);
    PrintVscToVk("0xE01D (RDP 0x1D + extended)", 0xE01D);
    PrintVscToVk("0x0045 (RDP NumLock byte)", 0x0045);
    PrintVscToVk("0xE045 (RDP 0x45 + extended)", 0xE045);
    PrintVscToVk("0x0053 (RDP DeleteByte? set1 Delete)", 0x0053);
    PrintVscToVk("0xE053 (0x53 + extended = Del)", 0xE053);
    PrintVscToVk("0xE05B (0x5B + extended = LWin)", 0xE05B);

    printf("\n== 3. Virtual screen / monitors (coordinate space for ABSOLUTE|VIRTUALDESK) ==\n");
    const int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    const int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    printf("virtual screen: origin=(%d,%d) size=%dx%d\n", vx, vy, vw, vh);
    printf("primary screen: %dx%d   monitors=%d\n", GetSystemMetrics(SM_CXSCREEN),
           GetSystemMetrics(SM_CYSCREEN), GetSystemMetrics(SM_CMONITORS));
    printf("mouse buttons=%d wheel present=%d\n", GetSystemMetrics(SM_CMOUSEBUTTONS),
           GetSystemMetrics(SM_MOUSEWHEELPRESENT));

    printf("\n== 4. Absolute normalization round trip (RDP desktop px -> 0..65535 -> px) ==\n");
    printf("formula: norm = round((px - origin) * 65535 / (extent - 1))\n");
    const int cases[][2] = {
        {0, 0}, {1, 0}, {vw / 2, vh / 2}, {vw - 1, vh - 1}, {vw - 2, vh - 2}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const int px = cases[i][0];
        const int py = cases[i][1];
        const UINT nx = Normalize(vx + px, vx, vw);
        const UINT ny = Normalize(vy + py, vy, vh);
        // Inverse of the same formula (what the system does with the
        // normalized value when the desktop is the virtual screen).
        const int back_x = vx + (int)(((long long)nx * (vw - 1) + 32767) / 65535);
        const int back_y = vy + (int)(((long long)ny * (vh - 1) + 32767) / 65535);
        printf("px=(%4d,%4d) -> norm=(%5u,%5u) -> back=(%4d,%4d) err=(%d,%d)\n", px, py,
               nx, ny, back_x - vx, back_y - vy, back_x - (vx + px),
               back_y - (vy + py));
    }

    printf("\n== 5. Wheel: notches -> mouseData (WHEEL_DELTA=120) ==\n");
    printf("WHEEL_DELTA=%d\n", WHEEL_DELTA);
    const int notches[] = {1, -1, 3, -3, 10, -10, 255, -255};
    for (size_t i = 0; i < sizeof(notches) / sizeof(notches[0]); ++i) {
        const long long data = (long long)notches[i] * WHEEL_DELTA;
        printf("notches=%4d -> mouseData=%11lld (DWORD)0x%08lX\n", notches[i], data,
               (unsigned long)(DWORD)(int)data);
    }

    printf("\n== 6. Which desktop would the injector land on? ==\n");
    DWORD session = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &session)) {
        printf("current process session id = %lu\n", (unsigned long)session);
    } else {
        printf("ProcessIdToSessionId failed: %lu\n", GetLastError());
    }
    printf("WTSGetActiveConsoleSessionId = 0x%08lX\n",
           (unsigned long)WTSGetActiveConsoleSessionId());

    const HWINSTA winsta = GetProcessWindowStation();
    printf("window station = %s\n", winsta ? DesktopNameOf(winsta) : "<null>");
    const HDESK thread_desktop = GetThreadDesktop(GetCurrentThreadId());
    printf("thread desktop = %s\n", thread_desktop ? DesktopNameOf(thread_desktop) : "<null>");
    const HDESK input_desktop = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (input_desktop) {
        printf("input desktop  = %s\n", DesktopNameOf(input_desktop));
        printf("thread desktop == input desktop: %s\n",
               (input_desktop == thread_desktop) ? "yes (handle equal)"
                                                 : "no (handle differs; compare names)");
        CloseDesktop(input_desktop);
    } else {
        printf("OpenInputDesktop failed: %lu\n", GetLastError());
    }
    return 0;
}
