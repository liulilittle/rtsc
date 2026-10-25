// Graphics pipeline: applies decoded RDP updates to a UI surface.

#include "rtsc/client/graphics.h"

#include <cstdint>
#include <vector>

#include "rtsc/proto/output.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::client;
using namespace rtsc::proto;

namespace {

// Builds a TS_BITMAP_DATA rectangle with raw (uncompressed) BGRA data.
std::vector<uint8_t> RawRect(int dst_x, int dst_y, uint16_t w, uint16_t h,
                             const std::vector<uint8_t>& bgra) {
    ByteWriter d;
    d.u16le(static_cast<uint16_t>(dst_x));
    d.u16le(static_cast<uint16_t>(dst_y));
    d.u16le(static_cast<uint16_t>(dst_x + w - 1));
    d.u16le(static_cast<uint16_t>(dst_y + h - 1));
    d.u16le(w);
    d.u16le(h);
    d.u16le(32);   // bpp
    d.u16le(0);    // flags: uncompressed
    d.u16le(static_cast<uint16_t>(bgra.size()));  // bitmapLength
    d.bytes(bgra.data(), bgra.size());
    return d.take();
}

// Wraps bitmap rectangles into a fast-path bitmap update + PDU.
std::vector<uint8_t> FastPathBitmapPdu(
    const std::vector<std::vector<uint8_t>>& rects) {
    ByteWriter data;
    data.u16le(0x0001);  // UPDATETYPE_BITMAP
    data.u16le(static_cast<uint16_t>(rects.size()));
    for (const auto& r : rects) data.bytes(r.data(), r.size());
    const auto d = data.take();

    ByteWriter w;
    w.u8(0x00);  // fpOutputHeader
    w.u8(static_cast<uint8_t>(1 + 1 + 1 + 2 + d.size()));
    w.u8(0x01);  // updateCode = bitmap
    w.u16le(static_cast<uint16_t>(d.size()));
    w.bytes(d.data(), d.size());
    return w.take();
}

}  // namespace

RTSC_TEST(graphics_applies_raw_fastpath_bitmap) {
    GraphicsPipeline g(8, 8);
    // 1x1 BGRA = 11 22 33 FF -> RGBA 33 22 11 FF at (2,3).
    const auto pdu = FastPathBitmapPdu({RawRect(2, 3, 1, 1, {0x11, 0x22, 0x33, 0xFF})});

    FastPathOutputPdu parsed;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), parsed) == Status::Ok);
    CHECK_EQ(g.ApplyFastPathOutput(parsed), 1);

    uint8_t r = 0, gg = 0, b = 0, a = 0;
    CHECK(g.surface().GetPixel(2, 3, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0x33));
    CHECK_EQ(gg, static_cast<uint8_t>(0x22));
    CHECK_EQ(b, static_cast<uint8_t>(0x11));
    CHECK_EQ(a, static_cast<uint8_t>(0xFF));
    // A neighbour is untouched.
    CHECK(g.surface().GetPixel(0, 0, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));
}

RTSC_TEST(graphics_applies_two_rectangles) {
    GraphicsPipeline g(8, 8);
    const auto pdu = FastPathBitmapPdu({
        RawRect(0, 0, 1, 1, {0x00, 0x00, 0xFF, 0xFF}),  // red
        RawRect(1, 0, 1, 1, {0x00, 0xFF, 0x00, 0xFF}),  // green
    });
    FastPathOutputPdu parsed;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), parsed) == Status::Ok);
    CHECK_EQ(g.ApplyFastPathOutput(parsed), 2);

    uint8_t r = 0, gg = 0, b = 0, a = 0;
    CHECK(g.surface().GetPixel(0, 0, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
    CHECK(g.surface().GetPixel(1, 0, r, gg, b, a));
    CHECK_EQ(gg, static_cast<uint8_t>(0xFF));
}

RTSC_TEST(graphics_pointer_position_update) {
    GraphicsPipeline g(4, 4);
    ByteWriter w;
    w.u8(0x00);       // header
    w.u8(0x09);       // length = 1+1+1+2+4
    w.u8(0x08);       // updateCode = pointer position
    w.u16le(4);       // size
    w.u16le(0x1234);  // x
    w.u16le(0x5678);  // y
    const auto pdu = w.take();

    FastPathOutputPdu parsed;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), parsed) == Status::Ok);
    CHECK_EQ(g.ApplyFastPathOutput(parsed), 0);
    CHECK(g.has_pointer());
    CHECK_EQ(g.pointer_x(), static_cast<uint16_t>(0x1234));
    CHECK_EQ(g.pointer_y(), static_cast<uint16_t>(0x5678));
}

RTSC_TEST(graphics_palette_update) {
    GraphicsPipeline g(2, 2);
    ByteWriter d;
    d.u16le(0x0002);  // UPDATETYPE_PALETTE
    d.u16le(0);
    d.u16le(256);
    for (int i = 0; i < 256; ++i) {
        d.u8(static_cast<uint8_t>(i));  // R
        d.u8(0);                        // G
        d.u8(0);                        // B
    }
    const auto payload = d.take();

    const size_t total = 1 + 2 + 1 + 2 + payload.size();  // 2-byte length
    ByteWriter w;
    w.u8(0x00);
    w.u8(static_cast<uint8_t>(0x80 | ((total >> 8) & 0x7F)));
    w.u8(static_cast<uint8_t>(total & 0xFF));
    w.u8(0x02);  // updateCode = palette
    w.u16le(static_cast<uint16_t>(payload.size()));
    w.bytes(payload.data(), payload.size());
    const auto pdu = w.take();

    FastPathOutputPdu parsed;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), parsed) == Status::Ok);
    g.ApplyFastPathOutput(parsed);
    CHECK_EQ(g.palette().size(), static_cast<size_t>(768));
    CHECK_EQ(g.palette()[255 * 3], static_cast<uint8_t>(255));
}

RTSC_TEST(graphics_slowpath_bitmap_update) {
    GraphicsPipeline g(8, 8);
    ByteWriter d;
    d.u16le(0x0001);  // UPDATETYPE_BITMAP
    d.u16le(1);       // numberRectangles
    const auto rect = RawRect(4, 4, 1, 1, {0x00, 0x00, 0xFF, 0xFF});
    d.bytes(rect.data(), rect.size());
    const auto data = d.take();

    ByteWriter w;
    w.u16le(static_cast<uint16_t>(18 + 2 + data.size()));
    w.u16le(0x0017);
    w.u16le(0x03EF);
    w.u32le(0x000103EA);
    w.u8(0);
    w.u8(0x01);
    w.u16le(0);
    w.u8(0x02);  // pduType2 = PDUTYPE2_UPDATE
    w.u8(0);
    w.u16le(0);
    w.u16le(0x0001);  // UPDATETYPE_BITMAP
    w.bytes(data.data(), data.size());
    const auto pdu = w.take();

    SlowPathGraphicsUpdate upd;
    CHECK(SlowPathGraphicsUpdate::parse(pdu.data(), pdu.size(), upd) == Status::Ok);
    CHECK_EQ(g.ApplySlowPathUpdate(upd), 1);

    uint8_t r = 0, gg = 0, b = 0, a = 0;
    CHECK(g.surface().GetPixel(4, 4, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
}

// Builds the body of a TS_UPDATE_ORDERS_PDU_DATA: pad2OctetsA(2) +
// numberOrders(2) + pad2OctetsB(2) + orderData.
std::vector<uint8_t> OrdersBody(uint16_t pad_a, uint16_t number_orders,
                                uint16_t pad_b,
                                const std::vector<uint8_t>& orders) {
    ByteWriter b;
    b.u16le(pad_a);
    b.u16le(number_orders);
    b.u16le(pad_b);
    b.bytes(orders.data(), orders.size());
    return b.take();
}

// Builds a slow-path update PDU: share data header + updateType + type data.
std::vector<uint8_t> SlowPathOrdersPdu(uint16_t update_type,
                                       const std::vector<uint8_t>& data) {
    ByteWriter w;
    w.u16le(static_cast<uint16_t>(18 + 2 + data.size()));
    w.u16le(0x0017);
    w.u16le(0x03EF);
    w.u32le(0x000103EA);
    w.u8(0);
    w.u8(0x01);
    w.u16le(0);
    w.u8(0x02);  // pduType2 = PDUTYPE2_UPDATE
    w.u8(0);
    w.u16le(0);
    w.u16le(update_type);
    w.bytes(data.data(), data.size());
    return w.take();
}

RTSC_TEST(graphics_slowpath_orders_dispatch) {
    // One DstBlt 0x00, WHITENESS, rect (0,0,2,2).
    const std::vector<uint8_t> orders = {
        0x09, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x02, 0x00, 0xFF};
    const auto body = OrdersBody(0xABCD, 0x0001, 0x1234, orders);
    const auto pdu = SlowPathOrdersPdu(0x0000 /* UPDATETYPE_ORDERS */, body);

    SlowPathGraphicsUpdate upd;
    CHECK(SlowPathGraphicsUpdate::parse(pdu.data(), pdu.size(), upd) == Status::Ok);
    CHECK_EQ(upd.update_type, static_cast<uint16_t>(kUpdateOrders));
    // update_data starts at pad2OctetsA (updateType was consumed by parse).
    CHECK(upd.update_data == body);

    GraphicsPipeline g(8, 8);
    CHECK_EQ(g.ApplySlowPathUpdate(upd), 1);  // one applied order
    uint8_t r = 0, gg = 0, b = 0, a = 0;
    CHECK(g.surface().GetPixel(0, 0, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));
    CHECK_EQ(gg, static_cast<uint8_t>(0xFF));
    CHECK_EQ(b, static_cast<uint8_t>(0xFF));
    CHECK(g.surface().GetPixel(3, 3, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));  // outside the 2x2 rect
}

// A slow-path orders update and a fast-path orders update must share the same
// OrderEngine: the fast update omits the coordinates, so it reuses the ones the
// slow update sent. A second, independent engine would not know them.
RTSC_TEST(graphics_slow_and_fast_share_order_engine_state) {
    // Slow PDU: DstBlt with every field present -> sets the body state.
    const std::vector<uint8_t> slow_orders = {
        0x09, 0x00, 0x1F,        // control, orderType, fieldFlags 0x1F
        0x01, 0x00,              // left = 1
        0x02, 0x00,              // top = 2
        0x03, 0x00,              // width = 3
        0x04, 0x00,              // height = 4
        0xFF};                   // WHITENESS
    const auto slow_body = OrdersBody(0x0000, 0x0001, 0x0000, slow_orders);
    const auto slow_pdu = SlowPathOrdersPdu(0x0000, slow_body);

    // Fast PDU: DstBlt with only bRop present -> reuses the slow coordinates.
    const std::vector<uint8_t> fast_orders = {0x01, 0x10, 0xFF};
    const auto fast_body = OrdersBody(0x0000, 0x0001, 0x0000, fast_orders);
    ByteWriter fast_payload;  // updateType + body (fast entry includes updateType)
    fast_payload.u16le(0x0000);
    fast_payload.bytes(fast_body.data(), fast_body.size());

    FastPathUpdate update;
    update.code = FastPathUpdateCode::kOrders;
    update.data = fast_payload.take();
    FastPathOutputPdu pdu;
    pdu.flags = 0;
    pdu.updates.push_back(update);

    GraphicsPipeline g(8, 8);
    g.surface().Fill(0x00, 0x00, 0x00, 0xFF);

    SlowPathGraphicsUpdate slow_upd;
    CHECK(SlowPathGraphicsUpdate::parse(slow_pdu.data(), slow_pdu.size(),
                                        slow_upd) == Status::Ok);
    CHECK_EQ(g.ApplySlowPathUpdate(slow_upd), 1);

    // Reset, then let the fast update re-apply the same (slow-set) rectangle.
    g.surface().Fill(0x00, 0x00, 0x00, 0xFF);
    CHECK_EQ(g.ApplyFastPathOutput(pdu), 1);

    uint8_t r = 0, gg = 0, b = 0, a = 0;
    CHECK(g.surface().GetPixel(1, 2, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0xFF));  // reused slow coords (1,2,3,4)
    CHECK(g.surface().GetPixel(0, 0, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));     // not part of that rectangle
}

RTSC_TEST(graphics_dirty_flag_tracks_surface_changes) {
    // The render loop uses dirty() to skip the clear/scale/present cycle on an
    // idle session, so it must be set exactly when pixels change.
    GraphicsPipeline g(8, 8);
    CHECK(g.dirty());  // the first frame must always render
    g.clear_dirty();
    CHECK(!g.dirty());

    const auto pdu =
        FastPathBitmapPdu({RawRect(2, 3, 1, 1, {0x11, 0x22, 0x33, 0xFF})});
    FastPathOutputPdu parsed;
    CHECK(FastPathOutputPdu::parse(pdu.data(), pdu.size(), parsed) == Status::Ok);
    CHECK_EQ(g.ApplyFastPathOutput(parsed), 1);
    CHECK(g.dirty());  // a bitmap update dirties the surface
    g.clear_dirty();
    CHECK(!g.dirty());
}

RTSC_TEST(graphics_resize_recreates_the_surface) {
    GraphicsPipeline g(4, 4);
    g.surface().Fill(0xFF, 0, 0, 0xFF);
    g.Resize(8, 6);
    CHECK_EQ(g.width(), 8);
    CHECK_EQ(g.height(), 6);
    CHECK(g.dirty());  // the fresh surface must be painted

    uint8_t r = 0, gg = 0, b = 0, a = 0;
    CHECK(g.surface().GetPixel(0, 0, r, gg, b, a));
    CHECK_EQ(r, static_cast<uint8_t>(0));  // the new surface is blank
}

int main() { return ::rtsc::test::run_all("rtsc_graphics_tests"); }
