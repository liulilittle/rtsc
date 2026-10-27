// Graphics pipeline: applies decoded RDP graphics updates to a UI surface.

#include "rtsc/client/graphics.h"

#include <algorithm>
#include <cstring>

#include "rtsc/proto/rdp6.h"

namespace rtsc::client {

namespace {

// A default 8-bit palette (grayscale ramp) so palette-indexed bitmaps still
// render sensibly before the server sends a real palette.
std::vector<uint8_t> DefaultPalette() {
    std::vector<uint8_t> p(768, 0);
    for (int i = 0; i < 256; ++i) {
        p[i * 3 + 0] = static_cast<uint8_t>(i);
        p[i * 3 + 1] = static_cast<uint8_t>(i);
        p[i * 3 + 2] = static_cast<uint8_t>(i);
    }
    return p;
}

}  // namespace

GraphicsPipeline::GraphicsPipeline(uint16_t width, uint16_t height)
    : surface_(width, height), palette_(DefaultPalette()) {}

void GraphicsPipeline::Resize(uint16_t width, uint16_t height) {
    if (width == 0 || height == 0) return;
    if (width == surface_.width() && height == surface_.height()) return;
    surface_ = ui::Surface(width, height);
    dirty_ = true;  // the fresh surface must be painted
}

void GraphicsPipeline::set_monitor_layout(
    std::vector<proto::MonitorDef> monitors) {
    monitors_ = std::move(monitors);
    monitor_surfaces_.clear();
    if (monitors_.empty()) {
        // Single-monitor path: the surface is the whole desktop and the virtual
        // desktop origin is (0,0).
        origin_x_ = 0;
        origin_y_ = 0;
        return;
    }

    int min_l = 0, min_t = 0, max_r = 0, max_b = 0;
    bool first = true;
    for (const auto& m : monitors_) {
        if (first) {
            min_l = m.left;
            min_t = m.top;
            max_r = m.right;
            max_b = m.bottom;
            first = false;
        } else {
            min_l = std::min(min_l, m.left);
            min_t = std::min(min_t, m.top);
            max_r = std::max(max_r, m.right);
            max_b = std::max(max_b, m.bottom);
        }
    }
    origin_x_ = min_l;
    origin_y_ = min_t;
    const int vw = max_r - min_l + 1;
    const int vh = max_b - min_t + 1;
    if (vw <= 0 || vh <= 0) {
        // A degenerate layout (no usable monitor) is treated as no layout.
        monitors_.clear();
        monitor_surfaces_.clear();
        origin_x_ = 0;
        origin_y_ = 0;
        return;
    }
    surface_ = ui::Surface(static_cast<uint16_t>(vw), static_cast<uint16_t>(vh));
    monitor_surfaces_.reserve(monitors_.size());
    for (const auto& m : monitors_) {
        monitor_surfaces_.emplace_back(static_cast<uint16_t>(m.width()),
                                       static_cast<uint16_t>(m.height()));
    }
    dirty_ = true;  // the fresh virtual desktop must be painted
}

const proto::MonitorDef* GraphicsPipeline::monitor(size_t index) const {
    if (index >= monitors_.size()) return nullptr;
    return &monitors_[index];
}

ui::Surface* GraphicsPipeline::monitor_surface(size_t index) {
    if (index >= monitor_surfaces_.size()) return nullptr;
    return &monitor_surfaces_[index];
}

const ui::Surface* GraphicsPipeline::monitor_surface(size_t index) const {
    if (index >= monitor_surfaces_.size()) return nullptr;
    return &monitor_surfaces_[index];
}

int GraphicsPipeline::virtual_width() const noexcept {
    return surface_.width();
}

int GraphicsPipeline::virtual_height() const noexcept {
    return surface_.height();
}

void GraphicsPipeline::RenderMonitorTo(size_t index, ui::Surface& dst) const {
    if (index >= monitors_.size()) return;
    const proto::MonitorDef& m = monitors_[index];
    const int sx = m.left - origin_x_;
    const int sy = m.top - origin_y_;
    // The monitor is always inside the virtual desktop, so the source rectangle
    // is in range; only `dst` is clipped.
    if (sx < 0 || sy < 0) return;
    const int copy_w = std::min(static_cast<int>(dst.width()), m.width());
    const int copy_h = std::min(static_cast<int>(dst.height()), m.height());
    for (int y = 0; y < copy_h; ++y) {
        const int srow = sy + y;
        if (srow >= surface_.height()) break;
        const uint8_t* s = surface_.data() +
                           (static_cast<size_t>(srow) * surface_.width() + sx) * 4;
        uint8_t* d = dst.data() + static_cast<size_t>(y) * dst.width() * 4;
        std::memcpy(d, s, static_cast<size_t>(copy_w) * 4);
    }
    // 1:1 monitor copy: the pointer maps directly (minus the monitor origin).
    if (cursor_style_ == kArrow && has_pointer_) {
        ViewTransform vt;
        vt.x = -sx;
        vt.y = -sy;
        vt.width = surface_.width();
        vt.height = surface_.height();
        DrawCursor(dst, vt);
    }
}

int GraphicsPipeline::ApplyFastPathOutput(const proto::FastPathOutputPdu& pdu) {
    int drawn = 0;
    for (const auto& update : pdu.updates) {
        switch (update.code) {
            case proto::FastPathUpdateCode::kBitmap: {
                // The fast-path bitmap body starts with the 2-byte updateType
                // (FreeRDP fastpath_recv_update_common reads it the same way);
                // TS_UPDATE_BITMAP_DATA follows it.
                if (update.data.size() < 2) break;
                proto::UpdateBitmapData bm;
                if (proto::UpdateBitmapData::parse(
                        update.data.data() + 2, update.data.size() - 2,
                        bm) != proto::Status::Ok) {
                    break;
                }
                for (const auto& rect : bm.rectangles) {
                    if (ApplyBitmapRect(rect)) ++drawn;
                }
                break;
            }
            case proto::FastPathUpdateCode::kPalette: {
                proto::UpdatePaletteData pal;
                if (proto::UpdatePaletteData::parse(
                        update.data.data(), update.data.size(), pal) ==
                        proto::Status::Ok &&
                    pal.entries.size() == 768) {
                    palette_ = pal.entries;
                    ++drawn;  // a new palette repaints palette-indexed bitmaps
                }
                break;
            }
            case proto::FastPathUpdateCode::kPtrPosition: {
                if (update.data.size() >= 4) {
                    pointer_x_ = static_cast<uint16_t>(update.data[0] |
                                                       (update.data[1] << 8));
                    pointer_y_ = static_cast<uint16_t>(update.data[2] |
                                                       (update.data[3] << 8));
                    has_pointer_ = true;
                }
                break;
            }
            case proto::FastPathUpdateCode::kPtrDefault: {
                // TS_PTR_DEFAULT_ATTR (0x6, no payload): show the system arrow.
                cursor_style_ = kArrow;
                ++drawn;  // the style change must repaint
                break;
            }
            case proto::FastPathUpdateCode::kPtrNull: {
                // TS_PTR_NULL_ATTR (0x5, no payload): the server hides the
                // pointer (e.g. over a hidden-cursor surface).
                cursor_style_ = kHidden;
                ++drawn;
                break;
            }
            case proto::FastPathUpdateCode::kOrders: {
                render::OrdersUpdate orders;
                if (render::ParseOrdersUpdate(update.data.data(),
                                              update.data.size(),
                                              orders) == proto::Status::Ok) {
                    drawn += order_engine_.Apply(orders, surface_).applied;
                }
                break;
            }
            default:
                // Unimplemented update codes (surface commands, pointer shape,
                // synchronize, ...) are dropped.
                break;
        }
    }
    if (drawn > 0) dirty_ = true;
    return drawn;
}

int GraphicsPipeline::ApplySlowPathUpdate(
    const proto::SlowPathGraphicsUpdate& update) {
    switch (update.update_type) {
        case proto::kUpdateBitmap: {
            proto::UpdateBitmapData bm;
            if (proto::UpdateBitmapData::parse(update.update_data.data(),
                                               update.update_data.size(),
                                               bm) != proto::Status::Ok) {
                return 0;
            }
            int drawn = 0;
            for (const auto& rect : bm.rectangles) {
                if (ApplyBitmapRect(rect)) ++drawn;
            }
            if (drawn > 0) dirty_ = true;
            return drawn;
        }
        case proto::kUpdateOrders: {
            // SlowPathGraphicsUpdate::parse already consumed updateType, so
            // update_data starts at pad2OctetsA. ParseOrdersUpdateBody shares
            // the same field parsing and bound as the fast-path
            // ParseOrdersUpdate, and both paths feed the same order_engine_
            // member so the per-PDU parser state (orderType, bounds, brush
            // cache) is shared across fast and slow updates.
            render::OrdersUpdate orders;
            if (render::ParseOrdersUpdateBody(update.update_data.data(),
                                              update.update_data.size(),
                                              orders) != proto::Status::Ok) {
                return 0;
            }
            const int applied = order_engine_.Apply(orders, surface_).applied;
            if (applied > 0) dirty_ = true;
            return applied;
        }
        default:
            // Unimplemented update types (palette, synchronize, ...) are dropped.
            return 0;
    }
}

bool GraphicsPipeline::ApplyBitmapRect(const proto::BitmapData& rect) {
    if (rect.width == 0 || rect.height == 0) return false;

    // The wire payload is bitmapComprHdr? + bitmapDataStream.
    const uint8_t* stream = rect.bitmap_data.data();
    size_t stream_size = rect.bitmap_data.size();

    proto::DecodedBitmap decoded;
    proto::Status st = proto::Status::InvalidField;

    if ((rect.flags & proto::kBitmapCompression) == 0) {
        st = proto::DecodeRawBitmap(stream, stream_size, rect.width, rect.height,
                                    rect.bits_per_pixel, decoded, &palette_);
    } else if (rect.bits_per_pixel == 32) {
        // A 32-bpp compressed bitmapDataStream IS an RDP6_BITMAP_STREAM, which
        // starts at the format header: the 8-byte TS_CD_HEADER is never
        // present, regardless of NO_BITMAP_COMPRESSION_HDR ([MS-RDPBCGR]
        // 2.2.9.1.1.3.1.2.2 / 2.2.9.1.1.3.1.2.3 — 32-bpp compressed bitmaps use
        // RDP 6.0 Bitmap Compression, not the Interleaved RLE +
        // RLE_BITMAP_STREAM framing the TS_CD_HEADER belongs to). The planar
        // probe must therefore run before any header strip; stripping 8 bytes
        // here would eat the format header and fail the decode.
        st = proto::DecodeRdp6Bitmap(stream, stream_size, rect.width, rect.height,
                                     decoded);
    } else {
        if ((rect.flags & proto::kNoBitmapCompressionHdr) == 0) {
            // The 8-byte Compressed Data Header precedes the stream.
            if (stream_size < proto::BitmapCompressedHeader::kSize) return false;
            stream += proto::BitmapCompressedHeader::kSize;
            stream_size -= proto::BitmapCompressedHeader::kSize;
        }
        st = proto::DecodeRleBitmap(stream, stream_size, rect.width,
                                    rect.height, rect.bits_per_pixel,
                                    decoded, &palette_);
    }
    if (st != proto::Status::Ok) return false;

    // destLeft/destTop are virtual-desktop coordinates (relative to the primary
    // monitor's top-left), so they are translated by the union origin before the
    // blit. With no monitor layout the origin is (0,0) and this is a no-op.
    surface_.Blit(decoded.pixels.data(), decoded.width, decoded.height,
                  rect.dest_left - origin_x_, rect.dest_top - origin_y_);
    return true;
}

ViewTransform GraphicsPipeline::view_transform(int view_w, int view_h) const {
    return ComputeViewTransform(surface_.width(), surface_.height(), view_w,
                                view_h, zoom_, fit_);
}

void GraphicsPipeline::RenderTo(ui::Surface& dst) const {
    if (dst.width() == 0 || dst.height() == 0) return;
    const ViewTransform vt = view_transform(dst.width(), dst.height());
    if (vt.width <= 0 || vt.height <= 0) {
        dst.Fill(0, 0, 0, 255);
        return;
    }
    // Clear only the letterbox bars outside the scaled image. When the image
    // covers the whole viewport (the default 1:1 case) nothing is cleared, so a
    // frame costs one blit instead of a full-screen fill plus a blit.
    const int ix0 = std::max(0, vt.x);
    const int iy0 = std::max(0, vt.y);
    const int ix1 = std::min<int>(dst.width(), vt.x + vt.width);
    const int iy1 = std::min<int>(dst.height(), vt.y + vt.height);
    if (ix0 > 0) dst.FillRect(0, 0, ix0, dst.height(), 0, 0, 0, 255);
    if (ix1 < dst.width()) {
        dst.FillRect(ix1, 0, dst.width() - ix1, dst.height(), 0, 0, 0, 255);
    }
    if (iy0 > 0) dst.FillRect(ix0, 0, ix1 - ix0, iy0, 0, 0, 0, 255);
    if (iy1 < dst.height()) {
        dst.FillRect(ix0, iy1, ix1 - ix0, dst.height() - iy1, 0, 0, 0, 255);
    }
    ScaleSurface(surface_, dst, vt);
    DrawCursor(dst, vt);
}

void GraphicsPipeline::DrawCursor(ui::Surface& dst,
                                  const ViewTransform& vt) const {
    if (cursor_style_ != kArrow || !has_pointer_) return;
    // The pointer position uses the same primary-monitor-relative coordinates
    // as bitmap destLeft/destTop ([MS-RDPBCGR] 2.2.9.1.1.4.1), so it is
    // translated by the union origin exactly like ApplyBitmapRect.
    // Limitation: only the position is honoured — pointer *shape* updates
    // (TS_COLORPOINTERATTRIBUTE / TS_POINTERATTRIBUTE) are dropped and the
    // arrow is always drawn.
    const int px = static_cast<int>(pointer_x_) - origin_x_;
    const int py = static_cast<int>(pointer_y_) - origin_y_;
    // Map the virtual-desktop pointer position into the viewport (the same
    // mapping ScaleSurface applies to the desktop pixels).
    const int cx = vt.x + (px * vt.width) / surface_.width();
    const int cy = vt.y + (py * vt.height) / surface_.height();
    // Standard Windows arrow, 12x19: '#' = black outline, 'o' = white fill.
    static const char* kArrow[] = {
        "#...........",
        "##..........",
        "#o#.........",
        "#oo#........",
        "#ooo#.......",
        "#oooo#......",
        "#ooooo#.....",
        "#oooooo#....",
        "#ooooooo#...",
        "#oooooooo#..",
        "#ooooo#####.",
        "#oo#oo#.....",
        "#o#.#oo#....",
        "##..#oo#....",
        "#....#oo#...",
        ".....#oo#...",
        "......#oo#..",
        "......#oo#..",
        ".......#....",
    };
    constexpr int kArrowW = 12;
    constexpr int kArrowH = 19;
    for (int y = 0; y < kArrowH; ++y) {
        for (int x = 0; x < kArrowW; ++x) {
            const char c = kArrow[y][x];
            if (c == '.') continue;
            if (c == '#') {
                dst.SetPixel(cx + x, cy + y, 0, 0, 0, 255);
            } else {
                dst.SetPixel(cx + x, cy + y, 255, 255, 255, 255);
            }
        }
    }
}

}  // namespace rtsc::client
