// View scaling: maps a remote-desktop surface into a window-sized viewport.
//
// Sampling contract (docs/spec/scaling-evidence.md):
//   scale == 1.0 (both axes) -> exact copy        (BitBlt SRCCOPY, E1/E5)
//   scale > 1                -> nearest-neighbour (GDI HALFTONE measured, E7/E8)
//   scale < 1                -> area average      (intentional improvement)
// Deliberate deviations from mstsc, all documented in the evidence file:
//   D-1 downscale uses an exact box average; GDI's HALFTONE box is approximate.
//   D-2 alpha is resampled with the same weight as R/G/B; GDI ignores alpha.
//   D-3 integer upscales keep the k x k block fast path (same result, faster).
// Do not describe any of these as "the same as mstsc".

#include "rtsc/client/view.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

#include "rtsc/ui/window.h"

#include "resample.h"

namespace rtsc::client {

namespace {

// The UI command ids are owned by rtsc::ui (they name window menu items); they
// are pulled in here so the switch below reads as a plain command id.
using rtsc::ui::kCmdFit;
using rtsc::ui::kCmdToggleSmartSizing;
using rtsc::ui::kCmdZoomPresetFirst;
using rtsc::ui::kCmdZoomPresetLast;

constexpr double kMinZoom = 0.50;
constexpr double kMaxZoom = 5.00;
constexpr double kWheelStep = 0.10;
constexpr double kWheelFineStep = 0.025;

}  // namespace

double ClampZoom(double zoom) {
    if (!(zoom > 0.0)) return 1.0;  // NaN / non-positive: keep 1:1
    if (zoom < kMinZoom) return kMinZoom;
    if (zoom > kMaxZoom) return kMaxZoom;
    return zoom;
}

double ZoomCommandZoom(uint8_t command) {
    if (command >= kCmdZoomPresetFirst && command <= kCmdZoomPresetLast) {
        return rtsc::ui::ZoomPresetZoom(command - kCmdZoomPresetFirst);
    }
    return -1.0;
}

ViewTransform ComputeViewTransform(int src_w, int src_h, int dst_w, int dst_h,
                                   double zoom, bool fit) {
    ViewTransform vt;
    if (src_w <= 0 || src_h <= 0 || dst_w <= 0 || dst_h <= 0) return vt;

    double scale;
    if (fit) {
        const double sx = static_cast<double>(dst_w) / static_cast<double>(src_w);
        const double sy = static_cast<double>(dst_h) / static_cast<double>(src_h);
        scale = (sx < sy) ? sx : sy;
    } else {
        scale = zoom;
    }
    if (!(scale > 0.0)) scale = 1.0;

    vt.scale = scale;
    vt.width = static_cast<int>(std::lround(src_w * scale));
    vt.height = static_cast<int>(std::lround(src_h * scale));
    if (vt.width < 1) vt.width = 1;
    if (vt.height < 1) vt.height = 1;
    vt.scale_x = static_cast<double>(vt.width) / static_cast<double>(src_w);
    vt.scale_y = static_cast<double>(vt.height) / static_cast<double>(src_h);

    vt.x = (dst_w - vt.width) / 2;
    vt.y = (dst_h - vt.height) / 2;
    if (vt.x < 0) vt.x = 0;
    if (vt.y < 0) vt.y = 0;
    return vt;
}

Resample ChooseResample(const ViewTransform& vt, int sw, int sh) {
    if (sw <= 0 || sh <= 0 || vt.width <= 0 || vt.height <= 0) {
        return Resample::kExact;
    }
    // Size equality, not a zero origin: a centred view with letterbox bars is
    // still a 1:1 copy (docs/spec/scaling-evidence.md E5 / D-4).
    if (vt.width == sw && vt.height == sh) return Resample::kExact;
    // Any shrinking axis takes the area average, even when the other axis is
    // growing or unchanged: averaging is what the reference does for a
    // reduction, and per-axis mixing would smear the axis that is enlarging.
    if (vt.width < sw || vt.height < sh) return Resample::kArea;
    return Resample::kNearest;
}

void ScaleSurface(const ui::Surface& src, ui::Surface& dst,
                  const ViewTransform& vt) {
    ScaleSurfaceClipped(src, dst, vt, 0, 0, dst.width(), dst.height());
}

void ScaleSurfaceClipped(const ui::Surface& src, ui::Surface& dst,
                         const ViewTransform& vt, int clip_x0,
                         int clip_y0, int clip_x1, int clip_y1) {
    if (vt.width <= 0 || vt.height <= 0) return;
    const int src_w = src.width();
    const int src_h = src.height();
    if (src_w <= 0 || src_h <= 0) return;

    // Intersect the viewport, the destination and the caller's dirty
    // rectangle. Everything below then works on a sub-rectangle of the
    // destination, so the resamplers only touch the pixels that changed.
    const int x0 = std::max(std::max(0, vt.x), clip_x0);
    const int y0 = std::max(std::max(0, vt.y), clip_y0);
    const int x1 = std::min(std::min<int>(dst.width(), vt.x + vt.width),
                            clip_x1);
    const int y1 = std::min(std::min<int>(dst.height(), vt.y + vt.height),
                            clip_y1);
    if (x0 >= x1 || y0 >= y1) return;

    detail::ScaleRect r;
    r.sw = src_w;
    r.sh = src_h;
    r.dw = vt.width;
    r.dh = vt.height;
    r.dx = vt.x;
    r.dy = vt.y;
    r.x0 = x0;
    r.y0 = y0;
    r.x1 = x1;
    r.y1 = y1;

    const uint8_t* sdata = src.data();
    uint8_t* ddata = dst.data();
    const int stride = dst.width();

    switch (ChooseResample(vt, src_w, src_h)) {
        case Resample::kExact:
            // BitBlt(SRCCOPY) branch of mstscax!FUN_18003444c: pixel-exact.
            detail::CopyExact(sdata, r, ddata, stride);
            return;
        case Resample::kNearest:
            // GDI HALFTONE replicates source pixels when enlarging (E7/E8).
            detail::ResampleNearest(sdata, r, ddata, stride);
            return;
        case Resample::kArea:
            // Intentional improvement: exact coverage average, alpha included
            // (D-1/D-2). GDI's own reduction is only approximately this.
            detail::ResampleArea(sdata, r, ddata, stride);
            return;
    }
}

void MapViewportPoint(const ViewTransform& vt, int src_w, int src_h, int vx,
                      int vy, int& rx, int& ry) {
    if (vt.width <= 0 || vt.height <= 0 || src_w <= 0 || src_h <= 0) {
        rx = 0;
        ry = 0;
        return;
    }
    // The cursor must resolve to the source pixel the renderer actually painted
    // under it, so this is the inverse of the same centre-phase rule the
    // nearest-neighbour path uses (src/client/resample.cpp NearestIndex,
    // docs/spec/scaling-evidence.md E8):
    //   src = ((2*d + 1) * S - 1) / (2 * D)
    // Using the left edge here put a 100 -> 4 reduction 12 pixels away from what
    // the user sees (viewport 1 painted source 37, but mapped to 25).
    const long long dx = static_cast<long long>(vx) - vt.x;
    const long long dy = static_cast<long long>(vy) - vt.y;
      int sx = static_cast<int>(((2 * dx + 1) * src_w - 1) / (2LL * vt.width));
      int sy = static_cast<int>(((2 * dy + 1) * src_h - 1) / (2LL * vt.height));
    if (sx < 0) sx = 0;
    if (sy < 0) sy = 0;
    if (sx > src_w - 1) sx = src_w - 1;
    if (sy > src_h - 1) sy = src_h - 1;
    rx = sx;
    ry = sy;
}

void MapMonitorPointToDesktop(int monitor_left, int monitor_top, int origin_x,
                              int origin_y, int union_w, int union_h,
                              int local_x, int local_y, int& desktop_x,
                              int& desktop_y) {
    // Pointer events carry a 16-bit unsigned position relative to the top-left
    // corner of the *union* of all monitors ([MS-RDPBCGR]: TS_FP_POINTER_EVENT
    // xPos/yPos, and the desktop is the union), while a monitor's left/top is a
    // signed offset from the primary. Subtracting the union origin is what keeps
    // a monitor placed left of or above the primary from wrapping (a -1920 left
    // edge used to become 63616). The result is clamped to the union bounds
    // (view.h promises), so a wrapped unsigned position (~65531 from a negative
    // local coordinate) or an oversized input can never escape the union.
    desktop_x = monitor_left - origin_x + local_x;
    desktop_y = monitor_top - origin_y + local_y;
    if (union_w > 0) {
        if (desktop_x < 0) desktop_x = 0;
        if (desktop_x >= union_w) desktop_x = union_w - 1;
    } else if (desktop_x < 0) {
        desktop_x = 0;
    }
    if (union_h > 0) {
        if (desktop_y < 0) desktop_y = 0;
        if (desktop_y >= union_h) desktop_y = union_h - 1;
    } else if (desktop_y < 0) {
        desktop_y = 0;
    }
}

bool ApplyZoomInput(const ui::InputEvent& ev, ZoomState& state) {
    using Kind = ui::InputEvent::Kind;
    switch (ev.kind) {
        case Kind::kMouseWheel: {
            // A zero delta is not a view event: never zoom and never claim it
            // (the Win32 backend no longer emits one; this guards other
            // sources). At a zoom limit the wheel is CONSUMED so the front-end
            // does not forward it as a remote-desktop scroll: it could not
            // have changed the zoom, so there is nothing more to do with it.
            if (ev.wheel_delta == 0) return false;
            const double step = state.ctrl ? kWheelFineStep : kWheelStep;
            const double next =
                ClampZoom(state.zoom + (ev.wheel_delta > 0 ? step : -step));
            if (next == state.zoom) return true;
            state.zoom = next;
            state.fit = false;
            return true;
        }
        case Kind::kKey: {
            // Track Ctrl so the wheel step can switch to fine mode. The Ctrl key
            // itself is not consumed (it is needed for other shortcuts).
            if (ev.scancode == 0x1D) {  // VK_CONTROL
                state.ctrl = !ev.key_release;
                return false;
            }
            if (!state.ctrl || ev.key_release) return false;
            // Ctrl+digit presets. The Win32 backend reports the virtual-key
            // code in `scancode` (VK_1 == 0x31), while a test or another
            // backend may report the RDP scancode (0x02); accept both so the
            // shortcut is not backend dependent.
            int digit = -1;
            if (ev.scancode >= 0x30 && ev.scancode <= 0x39) {
                digit = ev.scancode - 0x30;  // VK_0 .. VK_9
            } else if (ev.scancode >= 0x02 && ev.scancode <= 0x0B) {
                digit = (ev.scancode - 0x02 + 1) % 10;  // RDP '1'..'9','0'
            }
            if (digit < 0) return false;
            if (digit == 0) {  // '0' -> fit to window
                state.fit = true;
                return true;
            }
            if (digit > 7) return false;
            // 1..7 -> 100/125/150/200/300/400/500%.
            static const double kDigitZoom[7] = {1.0, 1.25, 1.5, 2.0,
                                                 3.0, 4.0, 5.0};
            state.zoom = ClampZoom(kDigitZoom[digit - 1]);
            state.fit = false;
            return true;
        }
        case Kind::kUiCommand: {
            // Zoom presets and the fit/smart-sizing toggle. The window-only
            // commands (fullscreen, connection info, smart card) are handled by
            // the front-end, which owns the window and the dialog.
            const bool toggle_fit = ev.command == kCmdToggleSmartSizing;
            const double preset = ZoomCommandZoom(ev.command);
            if (preset > 0.0) {
                state.zoom = ClampZoom(preset);
                state.fit = false;
                return true;
            }
            if (ev.command == kCmdFit) {
                state.fit = true;
                return true;
            }
            if (toggle_fit) {
                state.fit = !state.fit;
                return true;
            }
            return false;
        }
        default:
            return false;
    }
}

std::string ZoomStatusText(const ZoomState& state) {
    if (state.fit) return "RTSC - fit to window";
    char buf[64];
    std::snprintf(buf, sizeof(buf), "RTSC - zoom %.0f%%", state.zoom * 100.0);
    return std::string(buf);
}

std::string WindowTitleText(const std::string& host, uint16_t port,
                            const ZoomState& state) {
    std::string title = host;
    if (port != 0) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), ":%u", static_cast<unsigned>(port));
        title += buf;
    }
    title += " - ";
    title += ZoomStatusText(state);
    return title;
}

int ReconnectSchedule::NextDelayMs() {
    if (exhausted()) return -1;
    const unsigned n = attempts_++;
    // The first attempt is immediate (0), then exponential from 1 s, capped:
    // 0, 1, 2, 4, 8, 15, 15, ...
    if (n == 0) return 0;
    int delay = 1000;
    for (unsigned i = 0; i < n - 1 && delay < kMaxDelayMs; ++i) delay *= 2;
    return delay > kMaxDelayMs ? kMaxDelayMs : delay;
}

}  // namespace rtsc::client
