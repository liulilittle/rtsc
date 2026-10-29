// Server-side rdpdr virtual channel handler tests ([MS-RDPEFS] 3.2.5).
//
// Covers the RdpdrServer channel-level handshake (design S1-S6): Start's
// Server Announce byte layout, the response batch to the client announce reply
// (Server Capability + ClientId Confirm + User LoggedOn), out-of-order /
// malformed ignoring with counters, the empty device list (the server never
// announces devices in v1) and the no-op handling of a stray Device Io
// Request. The in-tree client only emits its client capability upon receiving
// the ClientId Confirm (rdpdr_client.cpp OnClientIdConfirm), so the server
// sends that confirmation together with the capability on the client announce
// reply instead of gating it on a capability that would never arrive (that is
// also what FreeRDP's rdpdr server does); S2 pins that ordering as a
// regression guard.

#include "rtsc/channel/rdpdr_server.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpdr.h"
#include "test_framework.h"
#include "test_main.h"

namespace proto = rtsc::proto;
using rtsc::channel::RdpdrServer;

namespace {

// Feeds one complete channel message (CHANNEL_PDU_HEADER + rdpdr PDU), split
// into nothing or several chunks depending on `chunk_size` (default keeps one
// chunk).
void FeedMessage(RdpdrServer& server, const std::vector<uint8_t>& pdu,
                 size_t chunk_size = proto::kDefaultChannelChunkSize) {
    for (const auto& chunk : proto::FragmentChannelMessage(pdu, chunk_size)) {
        server.OnChannelData(chunk.data(), chunk.size());
    }
}

// Wraps a proto-encoded PDU in the CHANNEL_PDU_HEADER and feeds it.
void FeedPdu(RdpdrServer& server, uint16_t packet_id,
             const std::vector<uint8_t>& body) {
    FeedMessage(server, proto::BuildRdpdrPdu(packet_id, body));
}

// Strips the 8-byte CHANNEL_PDU_HEADER from a captured output chunk, leaving
// the rdpdr PDU (header + body).
std::vector<uint8_t> StrictBody(const std::vector<uint8_t>& chunk) {
    return std::vector<uint8_t>(chunk.begin() + proto::ChannelPduHeader::kSize,
                                chunk.end());
}

// Parses one captured output chunk into an rdpdr PDU.
proto::RdpdrPdu DecodeSent(const std::vector<uint8_t>& chunk) {
    proto::RdpdrPdu pdu;
    CHECK(proto::RdpdrPdu::parse(StrictBody(chunk).data(),
                                 StrictBody(chunk).size(), pdu) ==
          proto::Status::Ok);
    return pdu;
}

// The outbound packet ids in order.
std::vector<uint16_t> SentIds(const std::vector<std::vector<uint8_t>>& sent) {
    std::vector<uint16_t> ids;
    ids.reserve(sent.size());
    for (const auto& chunk : sent) ids.push_back(DecodeSent(chunk).header.packet_id);
    return ids;
}

bool HasSent(const std::vector<std::vector<uint8_t>>& sent, uint16_t packet_id) {
    const auto ids = SentIds(sent);
    return std::find(ids.begin(), ids.end(), packet_id) != ids.end();
}

// Builds the client's capability PDU exactly as the in-tree client ships it:
// one general caps set (v2, full ioCode1, user-logged-on bit) plus a drive
// caps set.
std::vector<uint8_t> ClientCapabilityPdu() {
    proto::RdpdrGeneralCapsSet general_body;
    general_body.protocol_major_version = 1;
    general_body.protocol_minor_version = 0x000C;
    general_body.io_code1 = 0x00003FFF;
    general_body.extended_pdu = proto::kRdpdrDeviceRemovePdus |
                                proto::kRdpdrClientDisplayNamePdu |
                                proto::kRdpdrUserLoggedonPdu;
    proto::RdpdrCapabilitySet general;
    general.header.capability_type = proto::kCapGeneralType;
    general.header.version = proto::kGeneralCapabilityVersion02;
    general.data = general_body.encode(general.header.version);
    general.header.capability_length = static_cast<uint16_t>(
        proto::RdpdrCapabilityHeader::kSize + general.data.size());
    proto::RdpdrCapabilitySet drive;
    drive.header.capability_type = proto::kCapDriveType;
    drive.header.version = proto::kDriveCapabilityVersion02;
    drive.header.capability_length =
        static_cast<uint16_t>(proto::RdpdrCapabilityHeader::kSize);
    proto::RdpdrCoreCapability caps;
    caps.capabilities.push_back(general);
    caps.capabilities.push_back(drive);
    return caps.encode();
}

// Builds the client's announce reply (driven by the server's announce).
std::vector<uint8_t> ClientAnnounceReply(const RdpdrServer& server) {
    proto::RdpdrClientAnnounceReply reply;
    reply.version_major = 1;
    reply.version_minor = 0x000C;
    reply.client_id = server.client_id();
    return reply.encode();
}

// A server whose SendFn records every emitted chunk.
RdpdrServer MakeServer(std::vector<std::vector<uint8_t>>& sent) {
    return RdpdrServer([&sent](const std::vector<uint8_t>& m) {
        sent.push_back(m);
    });
}

}  // namespace

// S1: Start sends exactly one DR_CORE_SERVER_ANNOUNCE_REQ and nothing else,
// byte-exact against the proto encoder. Idempotent.
RTSC_TEST(rdpdr_server_start_sends_server_announce) {
    std::vector<std::vector<uint8_t>> sent;
    RdpdrServer server = MakeServer(sent);
    CHECK(server.phase() == RdpdrServer::Phase::kIdle);
    CHECK(!server.started());

    server.Start();
    CHECK(server.started());
    CHECK(server.phase() == RdpdrServer::Phase::kAwaitClientAnnounce);
    CHECK_EQ(server.server_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(server.client_announce_count(), static_cast<unsigned>(0));
    CHECK_EQ(sent.size(), static_cast<size_t>(1));

    proto::RdpdrPdu pdu = DecodeSent(sent[0]);
    CHECK(pdu.header.packet_id == proto::kPakidCoreServerAnnounce);
    CHECK_EQ(pdu.data.size(), static_cast<size_t>(8));

    // Byte-exact against the reference encoder with the same client id.
    proto::RdpdrServerAnnounce expect;
    expect.version_major = 1;
    expect.version_minor = 0x000C;
    expect.client_id = server.client_id();
    CHECK(StrictBody(sent[0]) == expect.encode());

    proto::RdpdrServerAnnounce parsed;
    CHECK(proto::RdpdrServerAnnounce::parse(StrictBody(sent[0]).data(),
                                            StrictBody(sent[0]).size(),
                                            parsed) == proto::Status::Ok);
    CHECK_EQ(parsed.version_major, static_cast<uint16_t>(1));
    CHECK_EQ(parsed.version_minor, static_cast<uint16_t>(0x000C));
    CHECK_EQ(parsed.client_id, server.client_id());

    // A second Start is a no-op.
    const size_t after_first = sent.size();
    server.Start();
    CHECK_EQ(sent.size(), after_first);
}

// S2: the client announce reply is answered with Server Capability, ClientId
// Confirm and User LoggedOn, in that order, on one channel message each.
// Chunked delivery is reassembled. (The confirm is sent here, together with
// the capability: the in-tree client only replies with its own capability
// after receiving the confirmation.)
RTSC_TEST(rdpdr_server_client_announce_brings_server_response_batch) {
    std::vector<std::vector<uint8_t>> sent;
    RdpdrServer server = MakeServer(sent);
    server.Start();
    CHECK_EQ(server.client_announce_count(), static_cast<unsigned>(0));

    // Deliver the announce reply in two chunks to exercise reassembly.
    FeedMessage(server, ClientAnnounceReply(server), 3);

    CHECK(server.client_announce_received());
    CHECK_EQ(server.client_announce_count(), static_cast<unsigned>(1));
    CHECK_EQ(server.out_of_order_count(), static_cast<unsigned>(0));
    CHECK(server.phase() == RdpdrServer::Phase::kReady);

    // Outbound order: [announce (Start), server-capability, clientid-confirm,
    // user-logged-on].
    const std::vector<uint16_t> want = {
        proto::kPakidCoreServerAnnounce,  proto::kPakidCoreServerCapability,
        proto::kPakidCoreClientidConfirm, proto::kPakidCoreUserLoggedon};
    CHECK(SentIds(sent) == want);

    // Server capability: one general caps set (v2), no IRP support (the
    // server provides no devices in v1), user-logged-on extended PDU bit.
    CHECK_EQ(server.server_capability_count(), static_cast<unsigned>(1));
    if (sent.size() >= 4) {
        proto::RdpdrCoreCapability caps;
        CHECK(proto::RdpdrCoreCapability::parse(StrictBody(sent[1]), caps) ==
              proto::Status::Ok);
    CHECK_EQ(caps.num_capabilities, static_cast<uint16_t>(1));
    CHECK_EQ(caps.capabilities.size(), static_cast<size_t>(1));
    if (!caps.capabilities.empty()) {
        const auto& set = caps.capabilities[0];
        CHECK_EQ(set.header.capability_type, static_cast<uint16_t>(proto::kCapGeneralType));
        CHECK_EQ(set.header.version, static_cast<uint32_t>(proto::kGeneralCapabilityVersion02));
        proto::RdpdrGeneralCapsSet general;
        CHECK(proto::RdpdrGeneralCapsSet::parse(set.data, set.header.version,
                                                 general) == proto::Status::Ok);
        CHECK_EQ(general.io_code1, static_cast<uint32_t>(0));
        CHECK_EQ(general.protocol_major_version, static_cast<uint16_t>(1));
        CHECK_EQ(general.protocol_minor_version, static_cast<uint16_t>(0x000C));
        CHECK_EQ(general.extended_pdu, static_cast<uint32_t>(proto::kRdpdrUserLoggedonPdu));
        }

        // ClientId Confirm echoes the server's announce client id.
        CHECK_EQ(server.clientid_confirm_count(), static_cast<unsigned>(1));
        proto::RdpdrServerClientIdConfirm confirm;
        // DR_CORE_SERVER_CLIENTID_CONFIRM is RDPDR_HEADER(4) + VersionMajor(2)
        // + VersionMinor(2) + ClientId(4) = 12 bytes; the version pair mirrors
        // the announce the client already accepted (a shorter packet fails a
        // real client's length check, taking the channel down).
        CHECK_EQ(StrictBody(sent[2]).size(), static_cast<size_t>(12));
        CHECK(proto::RdpdrServerClientIdConfirm::parse(
                  StrictBody(sent[2]).data(), StrictBody(sent[2]).size(),
                  confirm) == proto::Status::Ok);
        CHECK_EQ(confirm.version_major, server.version_major());
        CHECK_EQ(confirm.version_minor, server.version_minor());
        CHECK_EQ(confirm.client_id, server.client_id());

        // User LoggedOn: no payload.
        CHECK(server.user_logged_on_sent());
        CHECK_EQ(server.user_loggedon_count(), static_cast<unsigned>(1));
        CHECK(DecodeSent(sent[3]).data.empty());
    }
}

// S2b: the volume of the response batch stays frozen even when the client name
// request (which the in-tree client sends back-to-back with its announce
// reply) is interleaved: the name is recorded, not answered.
RTSC_TEST(rdpdr_server_records_client_name_between_announce_messages) {
    std::vector<std::vector<uint8_t>> sent;
    RdpdrServer server = MakeServer(sent);
    server.Start();

    proto::RdpdrClientNameRequest name;
    name.unicode_flag = 1;
    name.code_page = 0;
    name.computer_name = proto::RdpdrEncodeUtf16("HOST1");
    name.computer_name_len = static_cast<uint32_t>(name.computer_name.size());
    FeedMessage(server, name.encode());
    CHECK_EQ(server.client_name_count(), static_cast<unsigned>(1));
    CHECK(server.client_computer_name() == "HOST1");

    FeedMessage(server, ClientAnnounceReply(server));
    CHECK_EQ(server.client_name_count(), static_cast<unsigned>(1));
    CHECK_EQ(sent.size(), static_cast<size_t>(4));  // announce + 3 replies
}

// S3: the client capability that follows the confirm completes the exchange:
// it is recorded and the handshake stays READY, with no further outbound PDU.
RTSC_TEST(rdpdr_server_client_capability_completes_handshake) {
    std::vector<std::vector<uint8_t>> sent;
    RdpdrServer server = MakeServer(sent);
    server.Start();
    FeedMessage(server, ClientAnnounceReply(server));
    const size_t after_announce = sent.size();

    FeedMessage(server, ClientCapabilityPdu());
    CHECK(server.client_capability_received());
    CHECK_EQ(server.client_capability_count(), static_cast<unsigned>(1));
    CHECK(server.phase() == RdpdrServer::Phase::kReady);
    // The capability answers the server's confirm: nothing new goes out.
    CHECK_EQ(sent.size(), after_announce);
}

// S4: out-of-order and malformed input is ignored and counted, never answered.
RTSC_TEST(rdpdr_server_ignores_out_of_order_and_malformed) {
    std::vector<std::vector<uint8_t>> sent;
    RdpdrServer server = MakeServer(sent);

    // A client capability before Start (no announce sent yet) is out of order.
    FeedMessage(server, ClientCapabilityPdu());
    CHECK_EQ(server.out_of_order_count(), static_cast<unsigned>(1));
    CHECK_EQ(server.client_capability_count(), static_cast<unsigned>(0));
    CHECK(sent.empty());

    server.Start();

    // Garbage shorter than a CHANNEL_PDU_HEADER.
    const uint8_t tiny[3] = {1, 2, 3};
    server.OnChannelData(tiny, sizeof(tiny));
    CHECK_EQ(server.malformed_pdu_count(), static_cast<unsigned>(1));

    // A first, valid announce reply completes the exchange...
    FeedMessage(server, ClientAnnounceReply(server));
    CHECK_EQ(server.client_announce_count(), static_cast<unsigned>(1));
    const size_t after_exchange = sent.size();  // announce + 3 replies

    // ...so a duplicate announce reply is out of order.
    FeedMessage(server, ClientAnnounceReply(server));
    CHECK_EQ(server.out_of_order_count(), static_cast<unsigned>(2));
    CHECK_EQ(server.client_announce_count(), static_cast<unsigned>(1));

    // A malformed client capability body (truncated) parses as the rdpdr PDU
    // header but fails the capability decode: malformed, not answered.
    {
        proto::RdpdrPdu pdu;
        pdu.header.component = 0x4472;
        pdu.header.packet_id = proto::kPakidCoreClientCapability;
        pdu.data = {0x01, 0x00};  // numCapabilities=1 but no sets follow
        proto::ByteWriter w;
        pdu.header.write(w);
        w.bytes(pdu.data.data(), pdu.data.size());
        FeedMessage(server, w.take());
        CHECK_EQ(server.malformed_pdu_count(), static_cast<unsigned>(2));
        CHECK_EQ(server.client_capability_count(), static_cast<unsigned>(0));
    }

    // Nothing beyond the exchange batch was emitted by the bad input.
    CHECK_EQ(sent.size(), after_exchange);
}

// S5: v1 advertises an empty device list: the server never sends a device
// announce or reply, and the client's own (empty) device list is only counted.
RTSC_TEST(rdpdr_server_never_sends_devices) {
    std::vector<std::vector<uint8_t>> sent;
    RdpdrServer server = MakeServer(sent);
    server.Start();
    FeedMessage(server, ClientAnnounceReply(server));
    FeedMessage(server, ClientCapabilityPdu());

    proto::RdpdrDeviceListAnnounce list;  // deviceCount = 0
    FeedMessage(server, list.encode());
    CHECK_EQ(server.device_list_announce_count(), static_cast<unsigned>(1));

    CHECK(!HasSent(sent, proto::kPakidCoreDevicelistAnnounce));
    CHECK(!HasSent(sent, proto::kPakidCoreDeviceReply));
}

// S6: a stray DR_DEVICE_IOREQUEST (the server announced no device, so none
// should come) is ignored and counted; no completion is fabricated.
RTSC_TEST(rdpdr_server_stray_device_io_request_ignored_and_counted) {
    std::vector<std::vector<uint8_t>> sent;
    RdpdrServer server = MakeServer(sent);
    server.Start();
    FeedMessage(server, ClientAnnounceReply(server));
    const size_t after_announce = sent.size();

    proto::RdpdrDeviceIoRequest request;
    request.device_id = 7;
    request.file_id = 1;
    request.completion_id = 9;
    request.major_function = proto::kIrpMjCreate;
    request.minor_function = 0;
    FeedPdu(server, proto::kPakidCoreDeviceIorequest, request.encode());

    CHECK_EQ(server.device_io_request_count(), static_cast<unsigned>(1));
    CHECK(!HasSent(sent, proto::kPakidCoreDeviceIocompletion));
    CHECK_EQ(sent.size(), after_announce);
    CHECK(server.phase() == RdpdrServer::Phase::kReady);

    // A truncated body (16 bytes instead of the 20-byte DR_DEVICE_IOREQUEST)
    // is malformed, not a wrapped request: the rdpdr header must be stripped
    // before the header-unaware RdpdrDeviceIoRequest::parse sees the body.
    const std::vector<uint8_t> truncated = {1, 2, 3, 4, 5, 6, 7, 8,
                                            9, 10, 11, 12, 13, 14, 15, 16};
    FeedPdu(server, proto::kPakidCoreDeviceIorequest, truncated);
    CHECK_EQ(server.device_io_request_count(), static_cast<unsigned>(1));
    CHECK_EQ(server.malformed_pdu_count(), static_cast<unsigned>(1));
    CHECK(!HasSent(sent, proto::kPakidCoreDeviceIocompletion));
}

int main() { return rtsc::test::run_all("rtsc_rdpdr_server_tests"); }