// View scaling: maps a remote-desktop surface into a window-sized viewport.

#include "rtsc/client/view.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

#include "rtsc/ui/window.h"

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

    vt.x = (dst_w - vt.width) / 2;
    vt.y = (dst_h - vt.height) / 2;
    if (vt.x < 0) vt.x = 0;
    if (vt.y < 0) vt.y = 0;
    return vt;
}

void ScaleSurface(const ui::Surface& src, ui::Surface& dst,
                  const ViewTransform& vt) {
    if (vt.width <= 0 || vt.height <= 0) return;
    const int src_w = src.width();
    const int src_h = src.height();
    if (src_w <= 0 || src_h <= 0) return;

    const int x0 = std::max(0, vt.x);
    const int y0 = std::max(0, vt.y);
    const int x1 = std::min<int>(dst.width(), vt.x + vt.width);
    const int y1 = std::min<int>(dst.height(), vt.y + vt.height);
    if (x0 >= x1 || y0 >= y1) return;

    const uint8_t* sdata = src.data();
    uint8_t* ddata = dst.data();

    // Fast path 1: a 1:1 view (the default) is a plain row blit. Every
    // destination pixel is an exact copy of one source pixel, so the rendered
    // frame is bit-identical to the remote desktop (no scaling loss). This is
    // the path that makes the default view lossless.
    if (vt.x == 0 && vt.y == 0 && vt.width == src_w && vt.height == src_h) {
        const size_t bytes = static_cast<size_t>(x1 - x0) * 4;
        for (int y = y0; y < y1; ++y) {
            const uint8_t* s = sdata + static_cast<size_t>(y) * src_w * 4;
            uint8_t* d = ddata + static_cast<size_t>(y) * dst.width() * 4;
            std::memcpy(d, s, bytes);
        }
        return;
    }

    // Fast path 2: an integer scale factor (2x, 3x, ...) expands each source
    // pixel to an exact k x k block. One expanded row is built once and copied
    // k times, so the result is exact (no interpolation) and avoids the
    // per-pixel division of the generic path.
    if (vt.width % src_w == 0 && vt.height % src_h == 0 &&
        vt.width / src_w == vt.height / src_h) {
        const int k = vt.width / src_w;
        if (k >= 1 && k <= 64) {
            const int dx = std::max(x0, vt.x);
            const int ex0 = dx - vt.x;
            const int ex1 = std::min(x1, vt.x + vt.width) - vt.x;
            const size_t bytes = static_cast<size_t>(ex1 - ex0) * 4;
            const size_t stride = static_cast<size_t>(dst.width()) * 4;
            std::vector<uint8_t> row(static_cast<size_t>(vt.width) * 4);
            for (int sy = 0; sy < src_h; ++sy) {
                const uint8_t* srow =
                    sdata + static_cast<size_t>(sy) * src_w * 4;
                for (int sx = 0; sx < src_w; ++sx) {
                    const uint8_t* s = srow + static_cast<size_t>(sx) * 4;
                    uint8_t* d = row.data() + static_cast<size_t>(sx) * k * 4;
                    for (int i = 0; i < k; ++i) {
                        d[i * 4 + 0] = s[0];
                        d[i * 4 + 1] = s[1];
                        d[i * 4 + 2] = s[2];
                        d[i * 4 + 3] = s[3];
                    }
                }
                const int dy0 = std::max(y0, vt.y + sy * k);
                const int dy1 = std::min(y1, vt.y + sy * k + k);
                if (ex0 >= ex1) continue;
                const uint8_t* r = row.data() + static_cast<size_t>(ex0) * 4;
                uint8_t* dline = ddata + (static_cast<size_t>(dy0) * dst.width() + dx) * 4;
                for (int dy = dy0; dy < dy1; ++dy) {
                    std::memcpy(dline, r, bytes);
                    dline += stride;
                }
            }
            return;
        }
    }

    // Generic path (a user-initiated non-integer zoom): precompute the source
    // coordinate of every destination row and column once, then
    // bilinear-interpolate. Bilinear is smoother than nearest-neighbour, which
    // is what mstsc does for its scaled output. The 1:1 and integer paths above
    // stay exact; only this path interpolates.
    const int nw = x1 - x0;
    const int nh = y1 - y0;
    std::vector<int> ix0(nw), ix1(nw), iy0(nh), iy1(nh);
    std::vector<double> wx(nw), wy(nh);
    for (int i = 0; i < nw; ++i) {
        const double uu =
            static_cast<double>(x0 + i - vt.x) * src_w / vt.width;
        int a = static_cast<int>(std::floor(uu));
        double f = uu - a;
        if (a < 0) {
            a = 0;
            f = 0.0;
        }
        if (a > src_w - 1) {
            a = src_w - 1;
            f = 0.0;
        }
        int b = a + 1;
        if (b > src_w - 1) b = src_w - 1;
        ix0[i] = a;
        ix1[i] = b;
        wx[i] = f;
    }
    for (int j = 0; j < nh; ++j) {
        const double vv =
            static_cast<double>(y0 + j - vt.y) * src_h / vt.height;
        int a = static_cast<int>(std::floor(vv));
        double f = vv - a;
        if (a < 0) {
            a = 0;
            f = 0.0;
        }
        if (a > src_h - 1) {
            a = src_h - 1;
            f = 0.0;
        }
        int b = a + 1;
        if (b > src_h - 1) b = src_h - 1;
        iy0[j] = a;
        iy1[j] = b;
        wy[j] = f;
    }
    for (int j = 0; j < nh; ++j) {
        const int sy0 = iy0[j];
        const int sy1 = iy1[j];
        const double fy = wy[j];
        uint8_t* drow =
            ddata + (static_cast<size_t>(y0 + j) * dst.width() + x0) * 4;
        for (int i = 0; i < nw; ++i) {
            const int sx0 = ix0[i];
            const int sx1 = ix1[i];
            const double fx = wx[i];
            const uint8_t* p00 =
                sdata + (static_cast<size_t>(sy0) * src_w + sx0) * 4;
            const uint8_t* p10 =
                sdata + (static_cast<size_t>(sy0) * src_w + sx1) * 4;
            const uint8_t* p01 =
                sdata + (static_cast<size_t>(sy1) * src_w + sx0) * 4;
            const uint8_t* p11 =
                sdata + (static_cast<size_t>(sy1) * src_w + sx1) * 4;
            uint8_t* d = drow + static_cast<size_t>(i) * 4;
            for (int c = 0; c < 3; ++c) {
                const double top = p00[c] * (1.0 - fx) + p10[c] * fx;
                const double bot = p01[c] * (1.0 - fx) + p11[c] * fx;
                d[c] = static_cast<uint8_t>(
                    std::lround(top * (1.0 - fy) + bot * fy));
            }
            d[3] = p00[3];
        }
    }
}

void MapViewportPoint(const ViewTransform& vt, int src_w, int src_h, int vx,
                      int vy, int& rx, int& ry) {
    if (vt.width <= 0 || vt.height <= 0 || src_w <= 0 || src_h <= 0) {
        rx = 0;
        ry = 0;
        return;
    }
    int sx = (vx - vt.x) * src_w / vt.width;
    int sy = (vy - vt.y) * src_h / vt.height;
    if (sx < 0) sx = 0;
    if (sy < 0) sy = 0;
    if (sx > src_w - 1) sx = src_w - 1;
    if (sy > src_h - 1) sy = src_h - 1;
    rx = sx;
    ry = sy;
}

bool ApplyZoomInput(const ui::InputEvent& ev, ZoomState& state) {
    using Kind = ui::InputEvent::Kind;
    switch (ev.kind) {
        case Kind::kMouseWheel: {
            const double step = state.ctrl ? kWheelFineStep : kWheelStep;
            const double next =
                ClampZoom(state.zoom + (ev.wheel_delta > 0 ? step : -step));
            if (next == state.zoom) return false;
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

}  // namespace rtsc::client
