// Tests for the Display Control dynamic virtual channel client, driven through
// a real DrdynvcClient with an in-memory transport.

#include <string>
#include <vector>

#include "rtsc/channel/display_control_client.h"
#include "rtsc/channel/drdynvc_client.h"
#include "rtsc/proto/display_control.h"
#include "rtsc/proto/drdynvc.h"
#include "test_framework.h"
#include "test_main.h"

namespace {

using rtsc::channel::DrdynvcClient;
using rtsc::channel::DisplayControlClient;
using rtsc::proto::DisplayControlCaps;
using rtsc::proto::DisplayControlMonitor;

struct CapturedSend {
    std::vector<std::vector<uint8_t>> chunks;
    void Add(const std::vector<uint8_t>& c) { chunks.push_back(c); }
};

void FeedDvc(DrdynvcClient& t, const std::vector<uint8_t>& dvc_pdu) {
    for (const auto& chunk : rtsc::proto::FragmentChannelMessage(dvc_pdu)) {
        t.OnChannelData(chunk.data(), chunk.size());
    }
}

// Extracts the DISP payload from a sent DYNVC_DATA chunk.
std::vector<uint8_t> DvcPayload(const std::vector<uint8_t>& chunk) {
    rtsc::proto::DynvcPdu pdu;
    const rtsc::proto::Status s = rtsc::proto::DynvcPdu::parse(
        chunk.data() + rtsc::proto::ChannelPduHeader::kSize,
        chunk.size() - rtsc::proto::ChannelPduHeader::kSize, pdu);
    CHECK(s == rtsc::proto::Status::Ok);
    return pdu.data;
}

std::vector<uint8_t> CapsPdu(uint32_t max_monitors, uint32_t factor_a,
                             uint32_t factor_b) {
    std::vector<uint8_t> pdu = {
        0x05, 0x00, 0x00, 0x00,  // Type = DISPLAYCONTROL_CAPS_PDU
        0x14, 0x00, 0x00, 0x00,  // Length = 20 (fixed caps PDU)
    };
    auto push32 = [&pdu](uint32_t v) {
        pdu.push_back(static_cast<uint8_t>(v & 0xFF));
        pdu.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        pdu.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        pdu.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };
    push32(max_monitors);
    push32(factor_a);
    push32(factor_b);
    return pdu;
}

DisplayControlMonitor Monitor1024x768() {
    DisplayControlMonitor m;
    m.width = 1024;
    m.height = 768;
    return m;
}

// Opens the channel and delivers caps, leaving the client ready.
void MakeReady(DrdynvcClient& transport, DisplayControlClient& client,
               uint32_t max_monitors, uint32_t factor_a, uint32_t factor_b) {
    CHECK(client.Start());
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0,
                           client.channel_id(), {0, 0, 0, 0}));
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           client.channel_id(),
                           CapsPdu(max_monitors, factor_a, factor_b)));
}

}  // namespace

RTSC_TEST(display_control_opens_channel_on_start) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    CHECK(client.Start());
    CHECK(client.channel_id() != 0);
    CHECK(!client.ready());
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));
}

RTSC_TEST(display_control_caps_enable_ready) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    MakeReady(transport, client, 4, 8192, 8192);
    CHECK(client.ready());
    CHECK(client.channel_opened());
    CHECK_EQ(client.caps().max_num_monitors, static_cast<uint32_t>(4));
}

RTSC_TEST(display_control_rejects_layout_before_caps) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    CHECK(client.Start());
    // No caps yet: the request is remembered, not sent.
    CHECK(!client.SetMonitors({Monitor1024x768()}));
    CHECK(client.has_pending());
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));
}

RTSC_TEST(display_control_flushes_pending_layout_after_caps) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    CHECK(client.Start());
    CHECK(!client.SetMonitors({Monitor1024x768()}));
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0,
                           client.channel_id(), {0, 0, 0, 0}));
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           client.channel_id(),
                           CapsPdu(4, 8192, 8192)));
    CHECK(client.ready());
    CHECK_EQ(client.layout_count(), static_cast<unsigned>(1));
    CHECK(!client.has_pending());
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(2));
    // The flushed layout must be a DISPLAYCONTROL_MONITOR_LAYOUT_PDU.
    const std::vector<uint8_t> pdu = DvcPayload(cap.chunks[1]);
    CHECK_EQ(pdu.size(), static_cast<size_t>(56));
    CHECK_EQ(pdu[0], static_cast<uint8_t>(0x02));
    CHECK_EQ(pdu[7], static_cast<uint8_t>(0x00));
    CHECK_EQ(pdu[12], static_cast<uint8_t>(0x01));  // NumMonitors = 1
}

RTSC_TEST(display_control_sends_layout_when_ready) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    MakeReady(transport, client, 4, 8192, 8192);
    CHECK(client.SetMonitors({Monitor1024x768()}));
    CHECK_EQ(client.layout_count(), static_cast<unsigned>(1));
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(2));
}

RTSC_TEST(display_control_rejects_layout_beyond_caps) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    // max 1 monitor, area bound 200*200: 1024x768 is far beyond it.
    MakeReady(transport, client, 1, 200, 200);
    CHECK(!client.SetMonitors({Monitor1024x768()}));
    CHECK_EQ(client.layout_count(), static_cast<unsigned>(0));
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));
}

RTSC_TEST(display_control_rejects_invalid_monitor) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    MakeReady(transport, client, 4, 8192, 8192);
    DisplayControlMonitor odd = Monitor1024x768();
    odd.width = 1025;  // odd is forbidden
    CHECK(!client.SetMonitors({odd}));
    CHECK(!client.SetMonitors({}));
    CHECK_EQ(client.layout_count(), static_cast<unsigned>(0));
}

RTSC_TEST(display_control_malformed_caps_keeps_not_ready) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    CHECK(client.Start());
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0,
                           client.channel_id(), {0, 0, 0, 0}));
    // Wrong type: must never turn the client ready.
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kDataFirst, 0,
                           client.channel_id(),
                           {0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
                            0x00, 0x01, 0x00, 0x00, 0x00}));
    CHECK(!client.ready());
    CHECK(!client.SetMonitors({Monitor1024x768()}));
}

RTSC_TEST(display_control_close_resets_ready) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    MakeReady(transport, client, 4, 8192, 8192);
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kClose, 0,
                           client.channel_id(), {}));
    CHECK(!client.ready());
    CHECK(!client.channel_opened());
    CHECK(!client.SetMonitors({Monitor1024x768()}));
    CHECK(client.has_pending());
}

// A primary monitor is anchored at (0, 0) ([MS-RDPEDISP] 2.2.2.2.1): a layout
// that designates a primary elsewhere must never reach the wire.
RTSC_TEST(display_control_rejects_off_origin_primary) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    MakeReady(transport, client, 4, 8192, 8192);
    DisplayControlMonitor primary = Monitor1024x768();
    primary.flags = rtsc::proto::kDisplayControlMonitorPrimary;
    primary.left = 100;
    CHECK(!client.SetMonitors({primary}));
    CHECK_EQ(client.layout_count(), static_cast<unsigned>(0));
    primary.left = 0;
    CHECK(client.SetMonitors({primary}));
    CHECK_EQ(client.layout_count(), static_cast<unsigned>(1));
}

RTSC_TEST(display_control_rejects_overlapping_layout) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    MakeReady(transport, client, 4, 8192, 8192);

    DisplayControlMonitor a;
    a.width = 800;
    a.height = 600;
    DisplayControlMonitor b = a;
    b.left = 400;  // overlaps a
    CHECK(!client.SetMonitors({a, b}));
    CHECK_EQ(client.layout_count(), static_cast<unsigned>(0));
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));

    b.left = 800;  // edge-adjacent
    CHECK(client.SetMonitors({a, b}));
    CHECK_EQ(client.layout_count(), static_cast<unsigned>(1));
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(2));
    const std::vector<uint8_t> pdu = DvcPayload(cap.chunks[1]);
    CHECK_EQ(pdu.size(), static_cast<size_t>(96));  // 16 + 2*40
    CHECK_EQ(pdu[12], static_cast<uint8_t>(0x02));  // NumMonitors = 2
}

// After a reconnect the dynamic channel is gone. Reset() must drop the old
// caps and channel id; a later Start() opens a fresh channel (the transport's
// own Reset() clears the old channel ids).
RTSC_TEST(display_control_reset_allows_a_second_channel) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    DisplayControlClient client(transport);
    MakeReady(transport, client, 4, 8192, 8192);
    CHECK(client.ready());
    CHECK(client.channel_opened());
    const uint32_t first_id = client.channel_id();
    CHECK(first_id != 0);

    client.Reset();
    CHECK(!client.ready());
    CHECK(!client.channel_opened());
    CHECK_EQ(client.channel_id(), static_cast<uint32_t>(0));

    transport.Reset();
    cap.chunks.clear();
    CHECK(client.Start());
    CHECK(client.channel_id() != 0);
    CHECK_EQ(cap.chunks.size(), static_cast<size_t>(1));
    // The new channel opens after the new session's create response.
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0,
                           client.channel_id(), {0, 0, 0, 0}));
    CHECK(client.channel_opened());
}

// DrdynvcClient::Reset() drops the negotiated version and every dynamic
// channel id, so a re-Start() runs the capability exchange again.
RTSC_TEST(drdynvc_client_reset_clears_caps_and_channels) {
    CapturedSend cap;
    DrdynvcClient transport(nullptr,
                            [&](const std::vector<uint8_t>& c) {
                                cap.Add(c);
                            });
    transport.Start();
    CHECK_EQ(transport.caps_request_count(), static_cast<unsigned>(1));
    // Capability response ([MS-RDPEDYC] 2.2.1.1.2): header 0x50, Pad, Version.
    // VERSION1 is a 4-byte PDU; VERSION2/3 carry four priority charges.
    FeedDvc(transport, {0x50, 0x00, 0x01, 0x00});
    CHECK(transport.ready());
    CHECK_EQ(transport.version(), static_cast<uint16_t>(1));

    const uint32_t id = transport.CreateChannel("URBDRC");
    CHECK(id != 0);
    FeedDvc(transport, rtsc::proto::BuildDynvcPdu(
                           rtsc::proto::DynvcCmd::kCreate, 0, id, {0, 0, 0, 0}));

    transport.Reset();
    CHECK(!transport.ready());
    CHECK_EQ(transport.version(), static_cast<uint16_t>(0));
    CHECK_EQ(transport.caps_request_count(), static_cast<unsigned>(0));
    CHECK_EQ(transport.create_request_count(), static_cast<unsigned>(0));
    CHECK_EQ(transport.pending_channels(), static_cast<size_t>(0));

    transport.Start();
    CHECK_EQ(transport.caps_request_count(), static_cast<unsigned>(1));
    // Channel ids restart from 1 in the new session.
    CHECK_EQ(transport.CreateChannel("URBDRC"), static_cast<uint32_t>(1));
}

int main() {
    return ::rtsc::test::run_all("rtsc_display_control_client_tests");
}
