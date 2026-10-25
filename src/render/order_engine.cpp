// Order engine: turns a parsed Orders Update into drawing on a ui::Surface.

#include "rtsc/render/order_engine.h"

#include "rtsc/proto/secondary.h"

namespace rtsc::render {

namespace {

// Defence against a hostile numberOrders: the largest update is a few hundred
// orders, so anything above this is malformed.
constexpr uint16_t kMaxNumberOrders = 4096;

// pad2OctetsA (2) + numberOrders (2) + pad2OctetsB (2): the fixed body header
// that follows updateType in TS_UPDATE_ORDERS_PDU_DATA ([MS-RDPEGDI] 2.2.2.2.1.1.2).
constexpr size_t kBodyHeaderSize = 6;

}  // namespace

proto::Status ParseOrdersUpdateBody(const uint8_t* data, size_t size,
                                    OrdersUpdate& out) {
    out = OrdersUpdate{};
    if (data == nullptr || size < kBodyHeaderSize) {
        return proto::Status::NeedMoreData;
    }

    // pad2OctetsA (2B) at offset 0 and pad2OctetsB (2B) at offset 4 are ignored;
    // numberOrders is the u16le at offset 2.
    const uint16_t number_orders = static_cast<uint16_t>(
        data[2] | (static_cast<uint16_t>(data[3]) << 8));
    if (number_orders > kMaxNumberOrders) return proto::Status::InvalidField;

    out.number_orders = number_orders;
    out.order_data.assign(data + kBodyHeaderSize, data + size);
    return proto::Status::Ok;
}

proto::Status ParseOrdersUpdate(const uint8_t* data, size_t size,
                                OrdersUpdate& out) {
    out = OrdersUpdate{};
    // updateType (2) + pad2OctetsA (2) + numberOrders (2) + pad2OctetsB (2).
    if (data == nullptr || size < 8) return proto::Status::NeedMoreData;

    const uint16_t update_type =
        static_cast<uint16_t>(data[0] | (static_cast<uint16_t>(data[1]) << 8));
    // UPDATETYPE_ORDERS is 0x0000.
    if (update_type != 0x0000) return proto::Status::InvalidField;

    return ParseOrdersUpdateBody(data + 2, size - 2, out);
}

OrderEngineResult OrderEngine::Apply(const OrdersUpdate& update,
                                     ui::Surface& surface) {
    OrderEngineResult result;
    const uint8_t* data = update.order_data.data();
    const size_t size = update.order_data.size();
    size_t pos = 0;

    for (uint16_t i = 0; i < update.number_orders; ++i) {
        if (pos >= size) {
            result.truncated = true;
            break;
        }

        const uint8_t control_flags = data[pos];
        if ((control_flags & proto::TS_SECONDARY) != 0) {
            // Secondary order: it carries an explicit length, so it can be
            // skipped without decoding. ParseOrderHeader would reject
            // TS_SECONDARY, so this must be handled before it.
            proto::SecondaryOrderHeader secondary;
            size_t used = 0;
            proto::Status st = proto::ParseSecondaryOrderHeader(
                data + pos, size - pos, secondary, used);
            size_t actual = 0;
            if (st == proto::Status::Ok) {
                // [MS-RDPEGDI] 2.2.2.2.1.2.1: actual = orderLength + 13.
                actual = static_cast<size_t>(secondary.order_length) + 13;
            } else if (st == proto::Status::NeedMoreData) {
                result.truncated = true;
                break;
            } else {
                // An alternate secondary order (IsAlternateSecondaryOrder: only
                // TS_SECONDARY, no TS_STANDARD) or a malformed header. The ALTSEC
                // header has no length field ([MS-RDPEGDI] 2.2.2.2.1.3.1.1), so
                // it cannot be skipped without decoding it. Fail closed rather
                // than guess a length and desync the stream.
                ++result.failed;
                break;
            }
            if (actual < 6 || pos + actual > size) {
                result.truncated = true;
                break;
            }

            if (st == proto::Status::Ok &&
                secondary.order_type == proto::kCacheBrushOrder) {
                proto::CacheBrushOrder brush;
                size_t brush_used = 0;
                st = proto::ParseCacheBrushOrder(data + pos + 6, actual - 6,
                                                 brush, brush_used);
                if (st != proto::Status::Ok) {
                    ++result.failed;
                    break;
                }
                // Store the raw brushData (wire order) for every defined brush
                // form; the render layer classifies and decodes it.
                if (brush.cache_entry < 64) {
                    CachedBrush& e = brush_cache_[brush.cache_entry];
                    e.valid = true;
                    e.format = brush.bitmap_format;
                    e.length = static_cast<uint8_t>(brush.brush_data.size());
                    for (size_t k = 0;
                         k < brush.brush_data.size() && k < sizeof(e.data); ++k) {
                        e.data[k] = brush.brush_data[k];
                    }
                }
                ++result.secondary_cached;
            } else {
                ++result.secondary_skipped;
            }
            pos += actual;
            if (result.truncated || result.failed > 0) break;
            continue;
        }

        proto::OrderHeader header;
        size_t consumed = 0;
        proto::Status status = proto::ParseOrderHeader(data + pos, size - pos,
                                                       state_, header, consumed);
        if (status == proto::Status::NeedMoreData) {
            result.truncated = true;
            break;
        }
        if (status != proto::Status::Ok) {
            ++result.failed;
            break;
        }
        if (consumed == 0) {
            // A zero advance would loop forever; treat it as a parse failure.
            ++result.failed;
            break;
        }
        pos += consumed;

        switch (header.order_type) {
            case proto::TS_ENC_DSTBLT_ORDER: {
                proto::DstBltOrder order;
                size_t used = 0;
                status = proto::ParseDstBltBody(header, data + pos, size - pos,
                                                body_state_, order, used);
                if (status == proto::Status::NeedMoreData) {
                    result.truncated = true;
                    break;
                }
                if (status != proto::Status::Ok) {
                    ++result.failed;
                    break;
                }
                if (used == 0) {
                    ++result.failed;
                    break;
                }
                pos += used;
                ApplyDstBlt(surface, order);
                ++result.applied;
                break;
            }
            case proto::TS_ENC_PATBLT_ORDER: {
                proto::PatBltOrder order;
                size_t used = 0;
                status = proto::ParsePatBltBody(header, data + pos, size - pos,
                                                body_state_, order, used);
                if (status == proto::Status::NeedMoreData) {
                    result.truncated = true;
                    break;
                }
                if (status != proto::Status::Ok) {
                    ++result.failed;
                    break;
                }
                if (used == 0) {
                    ++result.failed;
                    break;
                }
                pos += used;
                {
                    PatBltResult pr = ApplyPatBlt(surface, order, *this);
                    if (pr == PatBltResult::kUnsupported) {
                        ++result.unsupported;
                    } else if (pr == PatBltResult::kNoOp) {
                        ++result.noop;
                    } else {
                        ++result.applied;
                    }
                }
                break;
            }
            case proto::TS_ENC_SCRBLT_ORDER: {
                proto::ScrBltOrder order;
                size_t used = 0;
                status = proto::ParseScrBltBody(header, data + pos, size - pos,
                                                body_state_, order, used);
                if (status == proto::Status::NeedMoreData) {
                    result.truncated = true;
                    break;
                }
                if (status != proto::Status::Ok) {
                    ++result.failed;
                    break;
                }
                if (used == 0) {
                    ++result.failed;
                    break;
                }
                pos += used;
                ApplyScrBlt(surface, order);
                ++result.applied;
                break;
            }
            case proto::TS_ENC_OPAQUERECT_ORDER: {
                proto::OpaqueRectOrder order;
                size_t used = 0;
                status = proto::ParseOpaqueRectBody(header, data + pos,
                                                    size - pos, body_state_, order, used);
                if (status == proto::Status::NeedMoreData) {
                    result.truncated = true;
                    break;
                }
                if (status != proto::Status::Ok) {
                    ++result.failed;
                    break;
                }
                if (used == 0) {
                    ++result.failed;
                    break;
                }
                pos += used;
                ApplyOpaqueRect(surface, order);
                ++result.applied;
                break;
            }
            default:
                // Unknown / unimplemented orderType. OrderTypeFieldCount returns 0
                // for it, so its encoded length is unknowable and it cannot be
                // skipped safely. Mark it and stop rather than guess a length.
                // (A known orderType never reaches here; its unimplemented
                // variants are counted as `unsupported` above and skipped.)
                result.unknown_order_type = true;
                break;
        }

        if (result.truncated || result.failed > 0 || result.unknown_order_type) break;
    }

    return result;
}

const uint8_t* OrderEngine::Lookup(uint8_t index, uint8_t& format,
                                   uint8_t& length) const {
    if (index >= 64) return nullptr;
    const CachedBrush& e = brush_cache_[index];
    if (!e.valid) return nullptr;
    format = e.format;
    length = e.length;
    return e.data;
}

}  // namespace rtsc::render
