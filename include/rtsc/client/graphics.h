// Graphics pipeline: applies decoded RDP graphics updates to a UI surface.
//
// This is the seam between the protocol layer (rtsc_proto: parsed updates and
// bitmap decoders) and the UI layer (rtsc_ui: the Surface the window presents).
// The protocol layer says "a bitmap update landed here"; this class turns that
// into pixels on the surface, choosing the right decoder from the update flags.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/client/view.h"
#include "rtsc/proto/bitmap.h"
#include "rtsc/proto/multimon.h"
#include "rtsc/proto/output.h"
#include "rtsc/render/order_engine.h"
#include "rtsc/ui/surface.h"

namespace rtsc::client {

// A half-open rectangle in surface coordinates: [left, right) x [top, bottom).
// `empty()` is true when nothing is covered, which is how the pipeline says
// "no pixel changed since the last clear_dirty()".
struct Rect {
    int left = 0;
    int top = 0;
    int right = 0;
    int bottom = 0;

    bool empty() const noexcept { return right <= left || bottom <= top; }
    int width() const noexcept { return right - left; }
    int height() const noexcept { return bottom - top; }

    // Smallest rectangle covering both operands. An empty operand is the
    // identity, so unioning into a cleared region starts the region there.
    static Rect Union(const Rect& a, const Rect& b) noexcept {
        if (a.empty()) return b;
        if (b.empty()) return a;
        Rect r;
        r.left = a.left < b.left ? a.left : b.left;
        r.top = a.top < b.top ? a.top : b.top;
        r.right = a.right > b.right ? a.right : b.right;
        r.bottom = a.bottom > b.bottom ? a.bottom : b.bottom;
        return r;
    }
};

class GraphicsPipeline {
 public:
    GraphicsPipeline(uint16_t width, uint16_t height);

    ui::Surface& surface() noexcept { return surface_; }
    const ui::Surface& surface() const noexcept { return surface_; }

    uint16_t width() const noexcept { return surface_.width(); }
    uint16_t height() const noexcept { return surface_.height(); }

    // ---- Multi-monitor -----------------------------------------------------

    // Installs the server's monitor layout and rebuilds the pipeline for it:
    // `surface()` becomes the virtual desktop (the union of all monitors) and
    // one surface per monitor is created. An empty `monitors` restores the
    // single-surface path. Any already-painted pixels are lost, like Resize().
    void set_monitor_layout(std::vector<proto::MonitorDef> monitors);

    size_t monitor_count() const noexcept { return monitors_.size(); }
    const proto::MonitorDef* monitor(size_t index) const;
    // The surface for monitor `index`, or nullptr when out of range / no layout.
    ui::Surface* monitor_surface(size_t index);
    const ui::Surface* monitor_surface(size_t index) const;

    // The virtual desktop size (the union of all monitors) and the position of
    // its top-left corner in the virtual desktop coordinate space. With no
    // layout the origin is (0,0) and the size is the single surface's.
    int virtual_width() const noexcept;
    int virtual_height() const noexcept;
    int origin_x() const noexcept { return origin_x_; }
    int origin_y() const noexcept { return origin_y_; }

    // Copies monitor `index`'s rectangle of the virtual desktop into `dst` at
    // 1:1 (clipped to `dst`). This is what a per-monitor window presents.
    void RenderMonitorTo(size_t index, ui::Surface& dst) const;

    // Same 1:1 copy, restricted to the rows/columns the given virtual-desktop
    // rectangle covers on this monitor. Returns false when the dirty rectangle
    // does not intersect the monitor at all, so the caller can skip the
    // present entirely. `dirty` is in virtual-desktop coordinates.
    bool RenderMonitorTo(size_t index, ui::Surface& dst, const Rect& dirty,
                         Rect& dst_dirty) const;

    // Recreates the surface at a new size (used when the server's Demand Active
    // reveals a desktop size that differs from the one the window was created
    // with). Any already-painted pixels are lost; callers use this right after
    // Connect(), before the desktop has been painted.
    void Resize(uint16_t width, uint16_t height);

    // The bounding box of every surface pixel changed by an inbound update
    // since the last clear_dirty(), clipped to the surface. It starts as the
    // whole surface because the first frame must always be painted.
    //
    // A remote desktop is idle most of the time, and when it is not, the
    // server sends small rectangles (a caret, a highlight, one window being
    // dragged). Repainting and re-uploading the entire surface for each of
    // those is what makes a naive client flicker while mstsc does not: the
    // window only needs the changed rectangle, and a frame that changes
    // nothing needs no paint at all.
    const Rect& dirty_region() const noexcept { return dirty_region_; }
    bool dirty() const noexcept { return !dirty_region_.empty(); }
    void clear_dirty() noexcept { dirty_region_ = Rect(); }

    // Marks the whole surface dirty (a fresh surface has unknown contents).
    void mark_all_dirty() noexcept {
        dirty_region_ = Rect{0, 0, surface_.width(), surface_.height()};
    }

    // Applies one parsed fast-path output PDU (bitmap / palette / synchronize /
    // pointer / orders updates). Returns the number of drawing orders applied
    // (an order count, not a rectangle/pixel count).
    int ApplyFastPathOutput(const proto::FastPathOutputPdu& pdu);

    // Applies one parsed slow-path graphics update (bitmap / orders / palette /
    // synchronize). Returns the number of drawing operations applied: for a
    // bitmap update that is the number of blitted rectangles, for an orders
    // update it is the number of orders applied (an order count, not a
    // rectangle/pixel count). Unimplemented update types are dropped and
    // return 0.
    int ApplySlowPathUpdate(const proto::SlowPathGraphicsUpdate& update);

    // Pointer position from the last pointer-position update, if any.
    bool has_pointer() const noexcept { return has_pointer_; }
    uint16_t pointer_x() const noexcept { return pointer_x_; }
    uint16_t pointer_y() const noexcept { return pointer_y_; }

    // True when the remote pointer must be composited over the desktop
    // (kPtrDefault received and not revoked by kPtrNull). mstsc always shows
    // the pointer; a client that draws none looks like a static screenshot.
    bool cursor_visible() const noexcept { return cursor_style_ == kArrow; }

    // The 8-bit palette (768 bytes) used by palette-indexed bitmaps.
    const std::vector<uint8_t>& palette() const noexcept { return palette_; }

    // View scaling (mstsc smart sizing). zoom 1.0 == 1:1; fit scales the whole
    // remote desktop into the viewport, preserving the aspect ratio.
    void set_zoom(double zoom) { zoom_ = ClampZoom(zoom); }
    double zoom() const noexcept { return zoom_; }
    void set_fit(bool fit) noexcept { fit_ = fit; }
    bool fit() const noexcept { return fit_; }

    // The destination rectangle for a viewport of view_w x view_h.
    ViewTransform view_transform(int view_w, int view_h) const;

    // Scales the remote surface into `dst` (clearing it first) according to the
    // current zoom / fit state. Letterbox bars are black.
    void RenderTo(ui::Surface& dst) const;

    // Same compositing, restricted to the destination pixels that the given
    // surface rectangle maps onto. Callers pass dirty_region() so a caret or a
    // dragged window repaints only its own area instead of the whole viewport.
    // Pixels outside the mapped area are left untouched (including the
    // letterbox bars, which only change when the view geometry changes).
    void RenderTo(ui::Surface& dst, const Rect& dirty) const;

 private:
    // Records that a source rectangle landed at (dst_x, dst_y) on the
    // surface, clipped to the surface bounds. Marking only the landed pixels
    // is what lets the render loop repaint a window drag without touching
    // the rest of the desktop.
    void MarkSurfaceRectDirty(int dst_x, int dst_y, int w, int h);

    // Decodes one TS_BITMAP_DATA rectangle and blits it onto the surface.
    bool ApplyBitmapRect(const proto::BitmapData& rect);

    // Composites the remote pointer over the rendered viewport when visible.
    void DrawCursor(ui::Surface& dst, const ViewTransform& vt) const;

    // Draws primary orders from a fast-path or slow-path orders update. One
    // shared instance keeps the cross-PDU parser state (orderType, bounds,
    // brush cache) coherent across both update paths.
    render::OrderEngine order_engine_;

    ui::Surface surface_;
    // Multi-monitor state. Empty for a single-monitor session; then
    // monitor_surfaces_ is empty too and surface_ is the only surface.
    std::vector<proto::MonitorDef> monitors_;
    std::vector<ui::Surface> monitor_surfaces_;
    int origin_x_ = 0;
    int origin_y_ = 0;
    std::vector<uint8_t> palette_;
    // Bounding box of pixels changed since clear_dirty(). Empty == idle.
    // The constructor marks the whole surface (see GraphicsPipeline::GraphicsPipeline).
    Rect dirty_region_;
    bool has_pointer_ = false;
    uint16_t pointer_x_ = 0;
    uint16_t pointer_y_ = 0;
    // Remote pointer visibility: kNone until the first pointer-style update,
    // kArrow after TS_PTR_DEFAULT_ATTR, kHidden after TS_PTR_NULL_ATTR.
    enum PointerStyle { kNone, kHidden, kArrow };
    PointerStyle cursor_style_ = kNone;
    double zoom_ = 1.0;
    // Smart sizing (fit to window) is off by default: the default view is 1:1
    // (contract view.h:86-87 / tools/rtsc_gui/main.cpp:304-306).
    bool fit_ = false;
};

}  // namespace rtsc::client
