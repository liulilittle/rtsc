// Order engine: turns a parsed Orders Update into drawing on a ui::Surface.
//
// The Orders Update framing is decoded by rtsc::proto (FastPathOutputPdu /
// OrdersUpdate). This layer owns the per-PDU order parser state (orderType and
// bounds, which persist across PDUs) and dispatches each primary drawing order
// to its renderer.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtsc/proto/orders.h"
#include "rtsc/render/orders_apply.h"
#include "rtsc/ui/surface.h"

namespace rtsc::render {

// TS_UPDATE_ORDERS_PDU_DATA minus its share data header: updateType + padA +
// numberOrders + padB + orderData ([MS-RDPEGDI] 2.2.2.2.1.1.2).
struct OrdersUpdate {
    uint16_t number_orders = 0;
    std::vector<uint8_t> order_data;
};

// Parses the orderData update payload. `data` starts at updateType (i.e. the
// payload after the share data header). updateType must be UPDATETYPE_ORDERS;
// the two pad words are ignored; numberOrders is bounded to reject a hostile
// oversized value. A numberOrders/order_data length mismatch is NOT an error
// here: orderData may be longer or shorter than declared, and the truncation is
// surfaced by OrderEngine::Apply.
proto::Status ParseOrdersUpdate(const uint8_t* data, size_t size,
                                OrdersUpdate& out);

// Parses the body that follows updateType: pad2OctetsA(2B) + numberOrders(2B)
// + pad2OctetsB(2B) + orderData. Used by the slow-path update, whose
// SlowPathGraphicsUpdate::parse already consumed updateType. It shares the
// field parsing and the numberOrders bound with ParseOrdersUpdate, which reads
// off updateType and then delegates here. A size below the 6-byte fixed body
// header is NeedMoreData; an empty or short orderData is not an error, it is
// surfaced as truncation by OrderEngine::Apply.
proto::Status ParseOrdersUpdateBody(const uint8_t* data, size_t size,
                                    OrdersUpdate& out);

// Outcome of applying one Orders Update.
struct OrderEngineResult {
    // All counters are ORDER counts, not rectangle/pixel counts. `applied`
    // counts primary orders that were parsed and actually drew; `noop` counts
    // ones that parsed but drew nothing (BS_NULL, zero/negative size);
    // `unsupported` counts a known orderType with an unimplemented variant
    // (e.g. a cached brush style) that is safely skipped.
    int applied = 0;
    int noop = 0;
    int unsupported = 0;
    // Secondary drawing orders (TS_STANDARD|TS_SECONDARY): `secondary_cached`
    // counts CACHE_BRUSH orders stored into the brush cache, `secondary_skipped`
    // counts the other secondary orders skipped by their explicit length. Both
    // are ORDER counts.
    int secondary_cached = 0;
    int secondary_skipped = 0;
    int failed = 0;         // parse-failure count (loop aborts)
    bool truncated = false; // orderData ran out before numberOrders were read
    // True only for an unknown orderType, whose encoded length is unknowable
    // (OrderTypeFieldCount returns 0); the loop must stop. A known orderType
    // never sets this, even when it is unimplemented.
    bool unknown_order_type = false;
};

// Holds the cross-PDU order parser state and applies orders to a surface.
class OrderEngine : public BrushCacheView {
 public:
    // Applies every declared order. On the first unknown orderType, parse error
    // or truncation the loop stops; `unsupported`/`failed`/`truncated` record why.
    OrderEngineResult Apply(const OrdersUpdate& update,
                            ui::Surface& surface);

    // The persistent parser state (orderType, bounds, per-order body fields).
    const proto::OrderParserState& state() const noexcept { return state_; }

    // BrushCacheView: resolves a TS_CACHED_BRUSH PatBlt's cache index.
    const uint8_t* Lookup(uint8_t index, uint8_t& format,
                          uint8_t& length) const override;

 private:
    proto::OrderParserState state_;
    // Per-order body-field values persist across PDUs (absent fields reuse the
    // last value sent for that order type).
    proto::OrderBodyState body_state_;
    // Brush cache, 64 entries: [MS-RDPEGDI] 3.1.1.1.4 "Each cache can hold 64
    // brush entries"; CACHE_BRUSH_ORDER.cacheEntry MUST be 0..63 (2.2.2.2.1.2.7).
    // `data` holds the raw brushData bytes in wire order (rows bottom-first,
    // [MS-RDPEGDI] 2.2.2.2.1.2.7) for every defined brush form, so the render
    // layer can classify and decode mono / 4-color compressed / uncompressed.
    // iBytes is one byte, hence the 256-byte capacity.
    struct CachedBrush {
        bool valid = false;
        uint8_t format = 0;
        uint8_t length = 0;
        uint8_t data[256] = {};
    };
    CachedBrush brush_cache_[64];
};

}  // namespace rtsc::render
