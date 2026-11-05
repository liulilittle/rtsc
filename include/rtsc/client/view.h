// View scaling: maps a remote-desktop surface into a window-sized viewport.
//
// This is the client-side "smart sizing" of mstsc: the remote desktop is scaled
// to the local window without re-negotiating the session desktop size. mstsc
// implements the same behaviour for its smart-sizing option.
//
// The server-driven alternative (Monitor Layout PDU / Deactivation-Reactivation,
// [MS-RDPBCGR] 2.2.12.1) needs Bitmap.desktopResizeFlag = TRUE
// ([MS-RDPBCGR] 2.2.7.1.2), which this client does not advertise, so scaling is
// the supported path here (see docs/spec/capabilities.md section 8.2).

#pragma once

#include <cstdint>
#include <string>

#include "rtsc/ui/surface.h"
#include "rtsc/ui/window.h"

namespace rtsc::client {

// Destination rectangle of a scaled view, in viewport pixels.
struct ViewTransform {
    int x = 0;
    int y = 0;
    int width = 0;
    int height = 0;
    double scale = 1.0;
    // Actual per-axis ratios (width/src_w, height/src_h). `scale` is the
    // requested zoom factor; when the destination size is rounded these can
    // differ slightly, and exactness is judged on the integer sizes, not on
    // `scale` (docs/spec/scaling-evidence.md E5).
    double scale_x = 1.0;
    double scale_y = 1.0;
};

// Which resampling rule a view uses. The three cases mirror the measured
// reference behaviour (docs/spec/scaling-evidence.md section 2):
//   kExact  - destination size equals source size: pixel-exact copy.
//   kNearest- enlargement: every destination pixel is a copy of a source pixel.
//   kArea   - reduction: coverage-weighted area average.
enum class Resample { kExact, kNearest, kArea };

// Picks the rule for a transform. `sw`/`sh` are the source dimensions. A view
// whose size matches the source is exact even when it is offset (letterbox):
// the criterion is size equality, not a zero origin.
Resample ChooseResample(const ViewTransform& vt, int sw, int sh);

// Clamps a zoom factor to the supported range (mstsc's 50% .. 500%).
double ClampZoom(double zoom);

// The zoom presets offered by the View menu and the title-bar system menu.
// The canonical table lives in rtsc::ui (the window labels its items with it);
// these aliases keep the client-side API in one place.
constexpr int kZoomPresetCount = rtsc::ui::kZoomPresetCount;
inline int ZoomPresetCount() { return rtsc::ui::ZoomPresetCount(); }
inline double ZoomPresetZoom(int index) { return rtsc::ui::ZoomPresetZoom(index); }
inline const char* ZoomPresetLabel(int index) {
    return rtsc::ui::ZoomPresetLabel(index);
}
inline int ZoomPresetIndex(double zoom) {
    return rtsc::ui::ZoomPresetIndex(zoom);
}

// Computes the destination rectangle for a source image (src_w x src_h) inside
// a dst_w x dst_h viewport.
//
//   fit == true : the source is scaled by the largest factor that keeps it
//                 inside the viewport, preserving the aspect ratio (letterboxed
//                 and centred). This is mstsc smart sizing.
//   fit == false: the source is scaled by `zoom` (1.0 == 1:1), centred.
ViewTransform ComputeViewTransform(int src_w, int src_h, int dst_w, int dst_h,
                                   double zoom, bool fit);

// Scales an RGBA8888 source into `dst` at (vt.x, vt.y) with size
// vt.width x vt.height, following the sampling behaviour measured for mstsc:
//   1:1 (destination size == source size)      -> exact row copy (no loss);
//   scale > 1 (any factor, incl. 2x/3x/1.37x)  -> nearest-neighbour block copy;
//   scale < 1                                  -> area average (coverage weighted,
//                                                 half-pixel centred).
// The 1:1 case is the BitBlt(SRCCOPY) branch of mstscax!FUN_18003444c; the
// upscale case is the nearest-neighbour behaviour of GDI HALFTONE measured at
// 2x/3x/1.37x. Downscale area averaging is an intentional improvement over
// GDI's approximate box (deviation D-1), and alpha is averaged with the same
// weight as R/G/B (deviation D-2). See docs/spec/scaling-evidence.md.
// Destination pixels outside the viewport are clipped. The default view is 1:1,
// so the common path is the exact copy.
void ScaleSurface(const ui::Surface& src, ui::Surface& dst,
                  const ViewTransform& vt);

// Same transform, but only the destination pixels inside `clip` are
// written. This is what makes a partial repaint possible: when the
// server sent a small rectangle, the client re-renders just the affected
// part of the viewport instead of the whole frame (mstsc does the same --
// it paints only the update rectangle). The result for the covered pixels
// is bit-identical to ScaleSurface over the whole destination.
void ScaleSurfaceClipped(const ui::Surface& src, ui::Surface& dst,
                         const ViewTransform& vt, int clip_x0, int clip_y0,
                         int clip_x1, int clip_y1);

// Maps a viewport point (vx, vy) back to the source image coordinate that
// ScaleSurface sampled there. Points in a letterbox bar (outside the image) are
// clamped to the image bounds. This is the inverse of the scale transform and
// keeps the remote pointer aligned with the local pointer while zoomed/fitted.
// The mapping uses the sampling phase of the renderer: a destination pixel d
// covers the centre of its source footprint,
//     sx = ((2 * (vx - vt.x) + 1) * src_w - 1) / (2 * vt.width)
// (resample.cpp NearestIndex), not the left-edge floor(d * src_w / width).
void MapViewportPoint(const ViewTransform& vt, int src_w, int src_h, int vx,
                      int vy, int& rx, int& ry);

// Translates a pointer position inside one monitor window (local client-area
// pixels) into the server desktop coordinate space. `monitor_left`/`top` are
// the signed primary-relative TS_MONITOR_DEF coordinates; `origin_x`/`origin_y`
// are the top-left corner of the monitors' union (GraphicsPipeline::origin_x/y)
// and `union_w`/`union_h` its size. The server desktop is that union and the
// pointer fields are 16-bit unsigned offsets from its top-left corner
// ([MS-RDPBCGR] 2.2.8.1.2.4), so primary-relative coordinates must never be
// sent: a monitor left of the primary would wrap around. The result is clamped
// to the union bounds.
void MapMonitorPointToDesktop(int monitor_left, int monitor_top, int origin_x,
                              int origin_y, int union_w, int union_h,
                              int local_x, int local_y, int& desktop_x,
                              int& desktop_y);

// The zoom/fit state shared by the render loop and the input handler.
struct ZoomState {
    double zoom = 1.0;
    // Smart sizing (fit to window) is off by default: the default view is 1:1
    // (contract view.h:86-87 / tools/rtsc_gui/main.cpp:304-306).
    bool fit = false;
    bool ctrl = false;  // Ctrl is held (VK_CONTROL); enables fine wheel zoom.
};

// Applies one input event to `state`. Returns true when the event was consumed
// by the view (so the caller must not forward it to the server). Wheel zooms in
// / out (Ctrl held = finer step) and leaves fit mode; Ctrl+digit and the UI
// command events select a preset (see kCmdZoomPresetFirst) or fit to window.
// The window-only commands (fullscreen, connection info, smart card) are not
// handled here because they need the window/dialog, not the zoom state.
bool ApplyZoomInput(const ui::InputEvent& ev, ZoomState& state);

// The zoom factor selected by a UI command, or -1 when the command is not a
// zoom preset (fit / smart-sizing toggle / window-only commands). Shared by the
// menu handlers and ApplyZoomInput so the preset mapping cannot drift between
// them.
double ZoomCommandZoom(uint8_t command);

// Human-readable status for the window title / status line.
std::string ZoomStatusText(const ZoomState& state);

}  // namespace rtsc::client
