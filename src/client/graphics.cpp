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

int GraphicsPipeline::ApplyFastPathOutput(const proto::FastPathOutputPdu& pdu) {
    int drawn = 0;
    for (const auto& update : pdu.updates) {
        switch (update.code) {
            case proto::FastPathUpdateCode::kBitmap: {
                proto::UpdateBitmapData bm;
                if (proto::UpdateBitmapData::parse(
                        update.data.data(), update.data.size(), bm) !=
                    proto::Status::Ok) {
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
    } else {
        if ((rect.flags & proto::kNoBitmapCompressionHdr) == 0) {
            // The 8-byte Compressed Data Header precedes the stream.
            if (stream_size < proto::BitmapCompressedHeader::kSize) return false;
            stream += proto::BitmapCompressedHeader::kSize;
            stream_size -= proto::BitmapCompressedHeader::kSize;
        }
        if (rect.bits_per_pixel == 32) {
            st = proto::DecodeRdp6Bitmap(stream, stream_size, rect.width,
                                         rect.height, decoded);
        } else {
            st = proto::DecodeRleBitmap(stream, stream_size, rect.width,
                                        rect.height, rect.bits_per_pixel,
                                        decoded, &palette_);
        }
    }
    if (st != proto::Status::Ok) return false;

    surface_.Blit(decoded.pixels.data(), decoded.width, decoded.height,
                  rect.dest_left, rect.dest_top);
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
}

}  // namespace rtsc::client
