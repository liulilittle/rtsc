// Order engine: dispatches primary drawing orders onto a ui::Surface.
//
// Entry convention: ParseOrdersUpdate takes the payload starting at updateType
// (the 18-byte share data header is not part of it). The test buffers therefore
// carry an 18-byte shareDataHeader placeholder before updateType.

#include "rtsc/client/graphics.h"
#include "rtsc/proto/output.h"
#include "rtsc/proto/share.h"
#include "rtsc/render/order_engine.h"

#include <cstdint>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using rtsc::proto::FastPathOutputPdu;
using rtsc::proto::FastPathUpdateCode;
using rtsc::proto::OrderParserState;
using rtsc::proto::OrderType;
using rtsc::proto::Status;
using rtsc::render::OrderEngine;
using rtsc::render::OrderEngineResult;
using rtsc::render::OrdersUpdate;
using rtsc::render::ParseOrdersUpdate;
using rtsc::render::ParseOrdersUpdateBody;
using rtsc::ui::Surface;

namespace {

// Builds an update payload: updateType + padA + numberOrders + padB + orders.
// An 18-byte shareDataHeader placeholder precedes updateType.
std::vector<uint8_t> MakeUpdate(uint16_t update_type, uint16_t pad_a,
                                 uint16_t number_orders, uint16_t pad_b,
                                 const std::vector<uint8_t>& orders) {
    std::vector<uint8_t> buf(18, 0x00);  // shareDataHeader placeholder
    auto u16 = [&buf](uint16_t v) {
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
    };
    u16(update_type);
    u16(pad_a);
    u16(number_orders);
    u16(pad_b);
    buf.insert(buf.end(), orders.begin(), orders.end());
    return buf;
}

}  // namespace

RTSC_TEST(order_engine_applies_mixed_orders) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // DstBlt 0x00, WHITENESS (0xFF), rect (0,0,4,4).
    push(0x09);
    push(0x00);
    push(0x1F);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x04);
    push(0x00);
    push(0x04);
    push(0x00);
    push(0xFF);
    // PatBlt 0x01, BS_SOLID, rect (0,0,2,2), PATCOPY, BackColor, ForeColor.
    // 12 fields but BrushExtra (field 11) is absent for BS_SOLID -> 0x7FF.
    push(0x09);
    push(0x01);
    push(0xFF);
    push(0x07);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0xF0);
    push(0x11);
    push(0x22);
    push(0x33);
    push(0xAA);
    push(0xBB);
    push(0xCC);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    // ScrBlt 0x02, rect (4,4,4,4), SRCCOPY, src (0,0).
    push(0x09);
    push(0x02);
    push(0x7F);
    push(0x04);
    push(0x00);
    push(0x04);
    push(0x00);
    push(0x04);
    push(0x00);
    push(0x04);
    push(0x00);
    push(0xCC);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);

    const auto buf = MakeUpdate(0x0000, 0x1234, 0x0003, 0x5678, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    CHECK_EQ(update.number_orders, static_cast<uint16_t>(3));

    Surface surface(8, 8);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.applied, 3);
    CHECK_EQ(r.unsupported, 0);
    CHECK_EQ(r.failed, 0);
    CHECK(!r.truncated);

    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    auto expect = [&](int x, int y, uint8_t er, uint8_t eg, uint8_t eb) {
        CHECK(surface.GetPixel(x, y, rr, gg, bb, aa));
        CHECK_EQ(rr, er);
        CHECK_EQ(gg, eg);
        CHECK_EQ(bb, eb);
    };
    expect(0, 0, 0xAA, 0xBB, 0xCC);  // PatBlt ForeColor
    expect(1, 1, 0xAA, 0xBB, 0xCC);
    expect(2, 0, 0xFF, 0xFF, 0xFF);  // DstBlt WHITENESS
    expect(3, 3, 0xFF, 0xFF, 0xFF);
    expect(4, 4, 0xAA, 0xBB, 0xCC);  // ScrBlt copied (0,0)
    expect(5, 5, 0xAA, 0xBB, 0xCC);
    expect(6, 4, 0xFF, 0xFF, 0xFF);  // src (2,0)
    expect(7, 7, 0xFF, 0xFF, 0xFF);
    expect(7, 0, 0x00, 0x00, 0x00);  // untouched
    expect(0, 7, 0x00, 0x00, 0x00);
}

RTSC_TEST(order_engine_number_orders_zero) {
    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0000, 0x0000, {});
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.applied, 0);
    CHECK_EQ(r.unsupported, 0);
    CHECK_EQ(r.failed, 0);
    CHECK(!r.truncated);
}

RTSC_TEST(order_engine_unknown_order_type_stops) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // Order 1: GlyphIndex (0x1B, 22 fields -> 3 flag bytes) — unknown to the engine.
    push(0x09);
    push(0x1B);
    push(0x7F);
    push(0x0F);
    push(0x00);
    // Order 2: DstBlt (0x00) — must NOT be processed after the unknown one.
    push(0x09);
    push(0x00);
    push(0x1F);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0xFF);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0002, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    surface.Fill(0x7F, 0x7F, 0x7F, 0x7F);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.applied, 0);
    CHECK_EQ(r.unsupported, 0);
    CHECK_EQ(r.failed, 0);
    CHECK(!r.truncated);
    CHECK(r.unknown_order_type);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0x7F));  // unchanged
}

// A parsed-but-unimplemented PatBlt (BS_NULL, or zero/negative size) must be
// counted and skipped WITHOUT aborting the rest of the PDU.
RTSC_TEST(order_engine_patblt_bsnull_does_not_stop) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    auto patblt = [&push](uint8_t style, uint16_t left, uint16_t top,
                          uint16_t width, uint16_t height, uint8_t rop,
                          uint8_t org_x, uint8_t org_y) {
        // fields 0..10 present (BrushExtra absent) -> fieldFlags 0x7FF.
        push(0x09); push(0x01); push(0xFF); push(0x07);
        push(static_cast<uint8_t>(left)); push(static_cast<uint8_t>(left >> 8));
        push(static_cast<uint8_t>(top)); push(static_cast<uint8_t>(top >> 8));
        push(static_cast<uint8_t>(width)); push(static_cast<uint8_t>(width >> 8));
        push(static_cast<uint8_t>(height)); push(static_cast<uint8_t>(height >> 8));
        push(rop);
        push(0x11); push(0x22); push(0x33);  // back
        push(0xAA); push(0xBB); push(0xCC);  // fore
        push(org_x); push(org_y);
        push(style);
        push(0x00);  // hatch
    };
    patblt(0x01 /* BS_NULL */, 0, 0, 2, 2, 0xF0, 0, 0);
    patblt(0x00 /* BS_SOLID */, 0, 0, 2, 2, 0xF0, 0, 0);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0002, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.noop, 1);
    CHECK_EQ(r.applied, 1);
    CHECK_EQ(r.unsupported, 0);
    CHECK_EQ(r.failed, 0);
    CHECK(!r.truncated);
    CHECK(!r.unknown_order_type);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0xAA));  // BS_SOLID PatBlt still ran
}

RTSC_TEST(order_engine_patblt_zero_size_noop) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // Order 1: PatBlt BS_SOLID with width = 0 -> noop.
    push(0x09); push(0x01); push(0xFF); push(0x07);
    push(0x00); push(0x00);  // left
    push(0x00); push(0x00);  // top
    push(0x00); push(0x00);  // width = 0
    push(0x02); push(0x00);  // height
    push(0xF0);              // rop
    push(0x11); push(0x22); push(0x33);  // back
    push(0xAA); push(0xBB); push(0xCC);  // fore
    push(0x00); push(0x00);  // orgX, orgY
    push(0x00);              // style = BS_SOLID
    push(0x00);              // hatch
    // Order 2: DstBlt WHITENESS -> still applied.
    push(0x09); push(0x00); push(0x1F);
    push(0x00); push(0x00);
    push(0x00); push(0x00);
    push(0x02); push(0x00);
    push(0x02); push(0x00);
    push(0xFF);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0002, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.noop, 1);
    CHECK_EQ(r.applied, 1);
    CHECK_EQ(r.failed, 0);
    CHECK(!r.unknown_order_type);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0xFF));
}

RTSC_TEST(order_engine_patblt_cached_brush_continues) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // Order 1: PatBlt with brush_style = 0x83 (TS_CACHED_BRUSH): unsupported
    // but the body still parses (fields 0..10; BrushExtra is only for
    // BS_PATTERN, so field 11 is absent here).
    push(0x09); push(0x01); push(0xFF); push(0x07);
    push(0x00); push(0x00);  // left
    push(0x00); push(0x00);  // top
    push(0x02); push(0x00);  // width
    push(0x02); push(0x00);  // height
    push(0xF0);              // rop
    push(0x11); push(0x22); push(0x33);  // back
    push(0xAA); push(0xBB); push(0xCC);  // fore
    push(0x00); push(0x00);  // orgX, orgY
    push(0x83);              // style = TS_CACHED_BRUSH
    push(0x00);              // hatch
    // Order 2: DstBlt WHITENESS -> must still be applied.
    push(0x09); push(0x00); push(0x1F);
    push(0x00); push(0x00);
    push(0x00); push(0x00);
    push(0x02); push(0x00);
    push(0x02); push(0x00);
    push(0xFF);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0002, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.unsupported, 1);
    CHECK_EQ(r.applied, 1);
    CHECK_EQ(r.failed, 0);
    CHECK(!r.truncated);
    CHECK(!r.unknown_order_type);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0xFF));
}

RTSC_TEST(order_engine_truncated) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // DstBlt header + a body one byte short of the required 9.
    push(0x09);
    push(0x00);
    push(0x1F);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x04);
    push(0x00);
    push(0x04);
    push(0x00);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0001, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK(r.truncated);
    CHECK_EQ(r.applied, 0);
}

RTSC_TEST(order_engine_update_type_must_be_orders) {
    const auto buf = MakeUpdate(0x0001, 0x0000, 0x0001, 0x0000, {});
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) ==
          Status::InvalidField);
}

RTSC_TEST(order_engine_state_persists_across_pdus) {
    // PDU 1: DstBlt with all fields (sets the body state).
    std::vector<uint8_t> orders1;
    auto push1 = [&orders1](uint8_t v) { orders1.push_back(v); };
    push1(0x09);
    push1(0x00);
    push1(0x1F);
    push1(0x01);
    push1(0x00);  // left = 1
    push1(0x02);
    push1(0x00);  // top = 2
    push1(0x03);
    push1(0x00);  // width = 3
    push1(0x04);
    push1(0x00);  // height = 4
    push1(0xCC);
    const auto b1 = MakeUpdate(0x0000, 0x0000, 0x0001, 0x0000, orders1);
    OrdersUpdate u1;
    CHECK(ParseOrdersUpdate(b1.data() + 18, b1.size() - 18, u1) == Status::Ok);

    // PDU 2: DstBlt with only bRop present (reuses the previous coords).
    std::vector<uint8_t> orders2;
    auto push2 = [&orders2](uint8_t v) { orders2.push_back(v); };
    push2(0x01);  // STANDARD only (orderType reused = DstBlt)
    push2(0x10);  // fieldFlags: only bRop present
    push2(0xFF);  // WHITENESS
    const auto b2 = MakeUpdate(0x0000, 0x0000, 0x0001, 0x0000, orders2);
    OrdersUpdate u2;
    CHECK(ParseOrdersUpdate(b2.data() + 18, b2.size() - 18, u2) == Status::Ok);

    Surface surface(8, 8);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    CHECK_EQ(engine.Apply(u1, surface).applied, 1);
    CHECK_EQ(engine.Apply(u2, surface).applied, 1);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(1, 2, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0xFF));  // rect (1,2,3,4) whitened
}

RTSC_TEST(order_engine_number_orders_upper_bound) {
    const auto buf = MakeUpdate(0x0000, 0x0000, 5000, 0x0000, {});
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) ==
          Status::InvalidField);
}

// Builds the body that follows updateType (no updateType, no shareDataHeader):
// pad2OctetsA(2) + numberOrders(2) + pad2OctetsB(2) + orderData.
std::vector<uint8_t> MakeBody(uint16_t pad_a, uint16_t number_orders,
                              uint16_t pad_b,
                              const std::vector<uint8_t>& orders) {
    std::vector<uint8_t> buf;
    auto u16 = [&buf](uint16_t v) {
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
    };
    u16(pad_a);
    u16(number_orders);
    u16(pad_b);
    buf.insert(buf.end(), orders.begin(), orders.end());
    return buf;
}

// The slow-path entry parses the body that follows updateType and draws with it.
RTSC_TEST(orders_update_body_parses_after_update_type) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // DstBlt 0x00, WHITENESS, rect (0,0,2,2).
    push(0x09); push(0x00); push(0x1F);
    push(0x00); push(0x00);
    push(0x00); push(0x00);
    push(0x02); push(0x00);
    push(0x02); push(0x00);
    push(0xFF);

    const auto body = MakeBody(0xABCD, 0x0001, 0x1234, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdateBody(body.data(), body.size(), update) == Status::Ok);
    CHECK_EQ(update.number_orders, static_cast<uint16_t>(1));
    CHECK(update.order_data == orders);  // pads ignored, orderData preserved

    Surface surface(8, 8);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    CHECK_EQ(engine.Apply(update, surface).applied, 1);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0xFF));  // drew from the body payload
}

// The fast and body entries must agree: ParseOrdersUpdate strips updateType and
// delegates, so the same logical content yields the same OrdersUpdate.
RTSC_TEST(orders_update_fast_and_body_agree) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // DstBlt 0x00, WHITENESS, rect (0,0,2,2).
    push(0x09); push(0x00); push(0x1F);
    push(0x00); push(0x00);
    push(0x00); push(0x00);
    push(0x02); push(0x00);
    push(0x02); push(0x00);
    push(0xFF);
    // DstBlt 0x00, BLACKNESS, rect (2,2,2,2).
    push(0x09); push(0x00); push(0x1F);
    push(0x02); push(0x00);
    push(0x02); push(0x00);
    push(0x02); push(0x00);
    push(0x02); push(0x00);
    push(0x00);

    const auto buf = MakeUpdate(0x0000, 0x1234, 0x0002, 0x5678, orders);
    const uint8_t* fast_data = buf.data() + 18;  // at updateType
    const size_t fast_size = buf.size() - 18;
    const uint8_t* body_data = fast_data + 2;    // after updateType
    const size_t body_size = fast_size - 2;

    OrdersUpdate fast;
    CHECK(ParseOrdersUpdate(fast_data, fast_size, fast) == Status::Ok);
    OrdersUpdate body;
    CHECK(ParseOrdersUpdateBody(body_data, body_size, body) == Status::Ok);

    CHECK_EQ(fast.number_orders, body.number_orders);
    CHECK(fast.order_data == body.order_data);
    CHECK(fast.order_data == orders);
}

// The body header is padA + numberOrders + padB (6 bytes). Below that the call
// cannot even read numberOrders; exactly 6 bytes is a legal empty body.
RTSC_TEST(orders_update_body_rejects_short) {
    const uint8_t five[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
    OrdersUpdate update;
    CHECK(ParseOrdersUpdateBody(five, 5, update) == Status::NeedMoreData);

    const uint8_t six[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    update = OrdersUpdate{};
    CHECK(ParseOrdersUpdateBody(six, 6, update) == Status::Ok);
    CHECK_EQ(update.number_orders, static_cast<uint16_t>(0));
    CHECK(update.order_data.empty());
}

RTSC_TEST(order_engine_pad_ignored) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    push(0x09);
    push(0x00);
    push(0x1F);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0xFF);

    const auto buf = MakeUpdate(0x0000, 0xABCD, 0x0001, 0x1234, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    CHECK_EQ(engine.Apply(update, surface).applied, 1);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0xFF));
}

// A secondary order (TS_STANDARD|TS_SECONDARY) whose orderType is not modelled
// must be skipped by its explicit length, and the following primary order must
// still be processed.
RTSC_TEST(order_engine_skips_unknown_secondary) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // Secondary CACHE_COLOR_TABLE (0x01): controlFlags 0x03, orderLength -3
    // (actual = -3 + 13 = 10 = 6 header + 4 body), extraFlags 0, orderType 1.
    push(0x03);
    push(0xFD);
    push(0xFF);
    push(0x00);
    push(0x00);
    push(0x01);
    push(0x01);
    push(0x02);
    push(0x03);
    push(0x04);
    // DstBlt WHITENESS (0,0,2,2) — must still run.
    push(0x09);
    push(0x00);
    push(0x1F);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0xFF);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0002, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.secondary_skipped, 1);
    CHECK_EQ(r.secondary_cached, 0);
    CHECK_EQ(r.applied, 1);
    CHECK_EQ(r.failed, 0);
    CHECK(!r.truncated);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0xFF));  // DstBlt still applied
}

// An alternate secondary order (only TS_SECONDARY) has a 1-byte header with no
// length field ([MS-RDPEGDI] 2.2.2.2.1.3.1.1), so it cannot be skipped without
// decoding it. The engine fails closed: the order is counted as failed and the
// rest of the PDU (here a DstBlt) is not applied.
RTSC_TEST(order_engine_alternate_secondary_fails_closed) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // Real ALTSEC SWITCH_SURFACE: header 0x02 (class=TS_SECONDARY, orderType=
    // TS_ALTSEC_SWITCH_SURFACE 0x00) + bitmapId 0x0000 (2 bytes).
    push(0x02);
    push(0x00);
    push(0x00);
    // DstBlt WHITENESS (0,0,2,2) — must NOT be applied after the fail-closed
    // alternate secondary.
    push(0x09);
    push(0x00);
    push(0x1F);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0xFF);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0002, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    surface.Fill(0x7F, 0x7F, 0x7F, 0x7F);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.failed, 1);
    CHECK_EQ(r.secondary_skipped, 0);
    CHECK_EQ(r.applied, 0);
    CHECK(!r.truncated);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0x7F));  // unchanged: DstBlt dropped
}

// A secondary order whose adjusted length runs past the end of orderData is a
// truncation, not a silent skip.
RTSC_TEST(order_engine_secondary_truncated) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // orderLength 93 -> actual 106, but only 2 body bytes follow.
    push(0x03);
    push(0x5D);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x01);
    push(0x01);
    push(0x02);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0001, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK(r.truncated);
    CHECK_EQ(r.secondary_skipped, 0);
}

// A CACHE_BRUSH secondary order populates the brush cache; the following PatBlt
// with TS_CACHED_BRUSH then draws with the cached 8x8 pattern.
RTSC_TEST(order_engine_caches_brush_then_patblt_uses_it) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // Secondary CACHE_BRUSH (0x07): controlFlags 0x03, orderLength 7 (actual 20),
    // extraFlags 0, orderType 7. Body: cacheEntry 0, BMF_1BPP, 8x8, Style 0x81,
    // iBytes 8, brushData = FF 00*7 (bottom row first per spec).
    push(0x03);
    push(0x07);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x07);
    push(0x00);
    push(0x01);
    push(0x08);
    push(0x08);
    push(0x81);
    push(0x08);
    push(0xFF);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    // PatBlt (0,0,8,8), PATCOPY, back=(11,22,33), fore=(AA,BB,CC),
    // BrushStyle 0x81 = TS_CACHED_BRUSH|BMF_1BPP, BrushHatch 0 (cache index).
    push(0x09);
    push(0x01);
    push(0xFF);
    push(0x07);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x08);
    push(0x00);
    push(0x08);
    push(0x00);
    push(0xF0);
    push(0x11);
    push(0x22);
    push(0x33);
    push(0xAA);
    push(0xBB);
    push(0xCC);
    push(0x00);
    push(0x00);
    push(0x81);
    push(0x00);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0002, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(16, 16);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.secondary_cached, 1);
    CHECK_EQ(r.applied, 1);
    CHECK_EQ(r.unsupported, 0);
    CHECK_EQ(r.failed, 0);
    CHECK(!r.truncated);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    auto px = [&](int x, int y, uint8_t er, uint8_t eg, uint8_t eb) {
        CHECK(surface.GetPixel(x, y, rr, gg, bb, aa));
        CHECK_EQ(rr, er);
        CHECK_EQ(gg, eg);
        CHECK_EQ(bb, eb);
    };
    // brushData[0] is the BOTTOM row (spec: rows are reversed), so the top row
    // (y=0) is all-fore and the bottom row (y=7) is all-back.
    px(0, 0, 0xAA, 0xBB, 0xCC);
    px(7, 0, 0xAA, 0xBB, 0xCC);
    px(0, 7, 0x11, 0x22, 0x33);
    px(7, 7, 0x11, 0x22, 0x33);
    px(3, 3, 0xAA, 0xBB, 0xCC);
}

// A TS_CACHED_BRUSH PatBlt whose cache index was never populated is unsupported
// (never silently drawn), and the loop continues.
RTSC_TEST(order_engine_cached_brush_miss_unsupported) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    // PatBlt (0,0,2,2), PATCOPY, BrushStyle 0x81, BrushHatch 5 (not cached).
    push(0x09);
    push(0x01);
    push(0xFF);
    push(0x07);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0xF0);
    push(0x11);
    push(0x22);
    push(0x33);
    push(0xAA);
    push(0xBB);
    push(0xCC);
    push(0x00);
    push(0x00);
    push(0x81);
    push(0x05);
    // DstBlt WHITENESS (0,0,2,2) — must still run.
    push(0x09);
    push(0x00);
    push(0x1F);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0xFF);

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0002, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(8, 8);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.unsupported, 1);
    CHECK_EQ(r.applied, 1);
    CHECK_EQ(r.failed, 0);
    CHECK(!r.truncated);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(surface.GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0xFF));  // DstBlt still applied
}

// Two cached brushes must be selected by BrushHatch (the cache index), not by
// entry 0.
RTSC_TEST(order_engine_cached_brush_uses_selected_index) {
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    auto cache_brush = [&push](uint8_t entry, uint8_t first_row,
                               uint8_t last_row) {
        // Secondary CACHE_BRUSH: actual = 6 + 14 = 20 -> orderLength 7.
        push(0x03);
        push(0x07);
        push(0x00);
        push(0x00);
        push(0x00);
        push(0x07);
        push(entry);
        push(0x01);  // BMF_1BPP
        push(0x08);
        push(0x08);
        push(0x81);
        push(0x08);
        push(first_row);
        push(0x00);
        push(0x00);
        push(0x00);
        push(0x00);
        push(0x00);
        push(0x00);
        push(last_row);
    };
    auto patblt = [&push](uint16_t left, uint8_t hatch) {
        push(0x09);
        push(0x01);
        push(0xFF);
        push(0x07);
        push(static_cast<uint8_t>(left));
        push(static_cast<uint8_t>(left >> 8));
        push(0x00);
        push(0x00);
        push(0x08);
        push(0x00);
        push(0x08);
        push(0x00);
        push(0xF0);
        push(0x11);
        push(0x22);
        push(0x33);
        push(0xAA);
        push(0xBB);
        push(0xCC);
        push(0x00);
        push(0x00);
        push(0x81);
        push(hatch);
    };
    // Index 0: brushData[0]=FF is the bottom row -> top row fore, bottom back.
    cache_brush(0, 0xFF, 0x00);
    // Index 1: brushData[7]=FF is the top row -> top row back, bottom fore.
    cache_brush(1, 0x00, 0xFF);
    patblt(0, 1);  // hatch 1 -> index 1
    patblt(8, 0);  // hatch 0 -> index 0

    const auto buf = MakeUpdate(0x0000, 0x0000, 0x0004, 0x0000, orders);
    OrdersUpdate update;
    CHECK(ParseOrdersUpdate(buf.data() + 18, buf.size() - 18, update) == Status::Ok);
    Surface surface(16, 16);
    surface.Fill(0x00, 0x00, 0x00, 0xFF);
    OrderEngine engine;
    OrderEngineResult r = engine.Apply(update, surface);
    CHECK_EQ(r.secondary_cached, 2);
    CHECK_EQ(r.applied, 2);
    CHECK_EQ(r.failed, 0);
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    auto px = [&](int x, int y, uint8_t er, uint8_t eg, uint8_t eb) {
        CHECK(surface.GetPixel(x, y, rr, gg, bb, aa));
        CHECK_EQ(rr, er);
        CHECK_EQ(gg, eg);
        CHECK_EQ(bb, eb);
    };
    // hatch 1 (index 1): top row back, bottom row fore.
    px(0, 0, 0x11, 0x22, 0x33);
    px(0, 7, 0xAA, 0xBB, 0xCC);
    // hatch 0 (index 0): top row fore, bottom row back.
    px(8, 0, 0xAA, 0xBB, 0xCC);
    px(8, 7, 0x11, 0x22, 0x33);
}

RTSC_TEST(graphics_dispatch_orders_update) {
    // A fast-path output PDU carrying one orders update.
    std::vector<uint8_t> orders;
    auto push = [&orders](uint8_t v) { orders.push_back(v); };
    push(0x09);
    push(0x00);
    push(0x1F);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0x02);
    push(0x00);
    push(0xFF);
    const auto payload = MakeUpdate(0x0000, 0x0000, 0x0001, 0x0000, orders);

    rtsc::proto::FastPathUpdate update;
    update.code = FastPathUpdateCode::kOrders;
    // updateData starts at updateType; the 18-byte shareDataHeader placeholder
    // is not part of it.
    update.data.assign(payload.begin() + 18, payload.end());
    rtsc::proto::FastPathOutputPdu pdu;
    pdu.flags = 0;
    pdu.updates.push_back(update);

    rtsc::client::GraphicsPipeline pipeline(8, 8);
    const int drawn = pipeline.ApplyFastPathOutput(pdu);
    CHECK_EQ(drawn, 1);  // one applied order counts toward the return value
    uint8_t rr = 0, gg = 0, bb = 0, aa = 0;
    CHECK(pipeline.surface().GetPixel(0, 0, rr, gg, bb, aa));
    CHECK_EQ(rr, static_cast<uint8_t>(0xFF));
}
