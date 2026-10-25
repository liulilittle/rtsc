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
};

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
// vt.width x vt.height. Three paths, in order:
//   1:1 (vt is an exact copy)  -> a plain row blit, bit-exact (no loss);
//   integer scale (2x, 3x, ..) -> an exact k x k block copy per source pixel;
//   anything else              -> bilinear interpolation (smooth, lossy).
// Destination pixels outside the viewport are clipped. The default view is 1:1,
// so the common path is the exact blit; interpolation only runs when the user
// zooms to a non-integer factor.
void ScaleSurface(const ui::Surface& src, ui::Surface& dst,
                  const ViewTransform& vt);

// Maps a viewport point (vx, vy) back to the source image coordinate that
// ScaleSurface sampled there. Points in a letterbox bar (outside the image) are
// clamped to the image bounds. This is the inverse of the scale transform and
// keeps the remote pointer aligned with the local pointer while zoomed/fitted.
void MapViewportPoint(const ViewTransform& vt, int src_w, int src_h, int vx,
                      int vy, int& rx, int& ry);

// The zoom/fit state shared by the render loop and the input handler.
struct ZoomState {
    double zoom = 1.0;
    bool fit = true;
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
