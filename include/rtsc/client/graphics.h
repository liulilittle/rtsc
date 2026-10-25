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
#include "rtsc/proto/output.h"
#include "rtsc/render/order_engine.h"
#include "rtsc/ui/surface.h"

namespace rtsc::client {

class GraphicsPipeline {
 public:
    GraphicsPipeline(uint16_t width, uint16_t height);

    ui::Surface& surface() noexcept { return surface_; }
    const ui::Surface& surface() const noexcept { return surface_; }

    uint16_t width() const noexcept { return surface_.width(); }
    uint16_t height() const noexcept { return surface_.height(); }

    // Recreates the surface at a new size (used when the server's Demand Active
    // reveals a desktop size that differs from the one the window was created
    // with). Any already-painted pixels are lost; callers use this right after
    // Connect(), before the desktop has been painted.
    void Resize(uint16_t width, uint16_t height);

    // True when an inbound update changed the surface since the last
    // clear_dirty(). The render loop uses this to skip the whole clear/scale/
    // present cycle on an idle session, which is what keeps an idle remote
    // desktop from pinning a core.
    bool dirty() const noexcept { return dirty_; }
    void clear_dirty() noexcept { dirty_ = false; }

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

 private:
    // Decodes one TS_BITMAP_DATA rectangle and blits it onto the surface.
    bool ApplyBitmapRect(const proto::BitmapData& rect);

    // Draws primary orders from a fast-path or slow-path orders update. One
    // shared instance keeps the cross-PDU parser state (orderType, bounds,
    // brush cache) coherent across both update paths.
    render::OrderEngine order_engine_;

    ui::Surface surface_;
    std::vector<uint8_t> palette_;
    bool dirty_ = true;  // the first frame must always be rendered
    bool has_pointer_ = false;
    uint16_t pointer_x_ = 0;
    uint16_t pointer_y_ = 0;
    double zoom_ = 1.0;
    bool fit_ = true;
};

}  // namespace rtsc::client
