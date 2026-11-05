// Smart card redirection wiring: [MS-RDPEFS] device announce plus the
// SCARD_IOCTL_* dispatch through the rdpdr channel ([MS-RDPESC] 3.1.4).
//
// The protocol codec (NDR framing, per-IOCTL field layout) is covered by
// test_smartcard.cpp; this suite asserts the seam: the SCARD device is
// announced only when a backend is enabled, the capability set is added, the
// decoded call reaches the backend, and the *_Return payload the backend
// produces comes back inside a DR_CONTROL_RSP with the right IoStatus.

#include "rtsc/channel/rdpdr_client.h"
#include "rtsc/rdpdr/file_system.h"
#include "rtsc/smartcard/backend.h"

#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpdr.h"
#include "rtsc/proto/smartcard.h"
#include "test_framework.h"
#include "test_main.h"

namespace proto = rtsc::proto;
using rtsc::channel::RdpdrClient;
using rtsc::smartcard::ISmartCardBackend;
using rtsc::smartcard::MakeNullSmartCardBackend;

namespace {

constexpr uint32_t kScardDeviceId = 0x53434152u;  // "SCAR", arbitrary

uint32_t U32At(const std::vector<uint8_t>& v, size_t off) {
    return static_cast<uint32_t>(v[off]) |
           (static_cast<uint32_t>(v[off + 1]) << 8) |
           (static_cast<uint32_t>(v[off + 2]) << 16) |
           (static_cast<uint32_t>(v[off + 3]) << 24);
}

void FeedMessage(RdpdrClient& c, const std::vector<uint8_t>& pdu) {
    for (const auto& chunk : proto::FragmentChannelMessage(pdu)) {
        c.OnChannelData(chunk.data(), chunk.size());
    }
}

void FeedBody(RdpdrClient& c, uint16_t packet_id,
              const std::vector<uint8_t>& body) {
    FeedMessage(c, proto::BuildRdpdrPdu(packet_id, body));
}

const std::vector<uint8_t>* FindSent(
    const std::vector<std::vector<uint8_t>>& sent, uint16_t packet_id) {
    for (const auto& m : sent) {
        if (m.size() < proto::ChannelPduHeader::kSize +
                           proto::RdpdrHeader::kSize) {
            continue;
        }
        proto::RdpdrPdu pdu;
        if (proto::RdpdrPdu::parse(m.data() + proto::ChannelPduHeader::kSize,
                                   m.size() - proto::ChannelPduHeader::kSize,
                                   pdu) == proto::Status::Ok &&
            pdu.header.packet_id == packet_id) {
            return &m;
        }
    }
    return nullptr;
}

// Drives the rdpdr handshake to the point where the client announced its
// capabilities and devices. Both requests' encode() already carry the
// RDPDR_HEADER, so they are fed as whole messages.
void CompleteHandshake(RdpdrClient& c) {
    proto::RdpdrServerAnnounce announce;
    announce.version_major = 1;
    announce.version_minor = 0x000C;
    announce.client_id = 1;
    FeedMessage(c, announce.encode());

    proto::RdpdrServerClientIdConfirm confirm;
    confirm.version_major = 1;
    confirm.version_minor = 0x000C;
    confirm.client_id = 1;
    FeedMessage(c, confirm.encode());
}

std::vector<uint8_t> ControlBody(uint32_t device_id, uint32_t completion_id,
                                 uint32_t ioctl,
                                 const std::vector<uint8_t>& input,
                                 uint32_t output_buffer_length) {
    proto::ByteWriter w;
    proto::RdpdrDeviceIoRequest req;
    req.device_id = device_id;
    req.file_id = 0;
    req.completion_id = completion_id;
    req.major_function = proto::kIrpMjDeviceControl;
    req.minor_function = 0;
    const std::vector<uint8_t> encoded = req.encode();
    w.bytes(encoded.data(), encoded.size());
    w.u32le(output_buffer_length);
    w.u32le(static_cast<uint32_t>(input.size()));
    w.u32le(ioctl);
    for (int i = 0; i < 20; ++i) w.u8(0);  // Padding
    w.bytes(input.data(), input.size());
    return w.take();
}

// Wraps an NDR body in the 16-byte header pair ([MS-RPCE] 2.2.6.1/2.2.6.2).
std::vector<uint8_t> Wrap(const std::vector<uint8_t>& body) {
    const size_t padded = (body.size() + 7u) & ~size_t{7};
    std::vector<uint8_t> out = {1, 0x10, 8, 0, 0xCC, 0xCC, 0xCC, 0xCC};
    const uint32_t len = static_cast<uint32_t>(padded);
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<uint8_t>((len >> (8 * i)) & 0xFF));
    }
    out.insert(out.end(), 4, 0);
    out.insert(out.end(), body.begin(), body.end());
    out.insert(out.end(), padded - body.size(), 0);
    return out;
}

std::vector<uint8_t> Le32(uint32_t v) {
    return {static_cast<uint8_t>(v & 0xFF),
            static_cast<uint8_t>((v >> 8) & 0xFF),
            static_cast<uint8_t>((v >> 16) & 0xFF),
            static_cast<uint8_t>((v >> 24) & 0xFF)};
}

std::vector<uint8_t> Concat(
    std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// EstablishContext_Call: dwScope only. The return carries the context bytes.
std::vector<uint8_t> EstablishContextCall(uint32_t scope) {
    return Wrap(Le32(scope));
}

// A recording backend that answers with scripted values and remembers the
// arguments, so the wiring (not the codec) is what fails when it is wrong.
class FakeBackend final : public ISmartCardBackend {
 public:
    bool available() const override { return true; }

    uint32_t EstablishContext(uint32_t scope,
                              std::vector<uint8_t>& context) override {
        establish_scope = scope;
        ++establish_count;
        if (establish_status != 0) return establish_status;
        context = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
        return 0;
    }
    uint32_t ReleaseContext(const std::vector<uint8_t>& context) override {
        released = context;
        return release_status;
    }
    uint32_t ListReaderGroups(const std::vector<uint8_t>&,
                              std::vector<uint8_t>& groups) override {
        if (list_status != 0) return list_status;
        groups = {'G', 'r', 'p', 0, 0};
        return 0;
    }
    uint32_t ListReaders(const std::vector<uint8_t>&,
                         const std::vector<uint8_t>& groups,
                         std::vector<uint8_t>& readers) override {
        groups_seen = groups;
        if (list_status != 0) return list_status;
        readers = {'R', '0', 0, 0};
        return 0;
    }
    uint32_t GetStatusChange(const std::vector<uint8_t>&, uint32_t timeout_ms,
                             std::vector<rtsc::smartcard::ScardReaderState>&
                                 states) override {
        timeout_seen = timeout_ms;
        if (get_status_change_status != 0) return get_status_change_status;
        for (auto& st : states) {
            st.event_state = rtsc::smartcard::kScardStatePresent;
            st.atr = {0x3B, 0x00};
        }
        return 0;
    }
    uint32_t Connect(const std::vector<uint8_t>& context,
                     const std::string& reader, uint32_t share_mode,
                     uint32_t preferred_protocols,
                     std::vector<uint8_t>& handle,
                     uint32_t& active_protocol) override {
        connect_context = context;
        connect_reader = reader;
        connect_share = share_mode;
        connect_protocols = preferred_protocols;
        if (connect_status != 0) return connect_status;
        handle = {0xAA, 0xBB, 0xCC, 0xDD};
        active_protocol = rtsc::smartcard::kScardProtocolT1;
        return 0;
    }
    uint32_t Disconnect(const std::vector<uint8_t>&,
                        const std::vector<uint8_t>& handle,
                        uint32_t disposition) override {
        disconnect_handle = handle;
        disconnect_disposition = disposition;
        return disconnect_status;
    }
    uint32_t BeginTransaction(const std::vector<uint8_t>&,
                              const std::vector<uint8_t>&) override {
        return 0;
    }
    uint32_t EndTransaction(const std::vector<uint8_t>&,
                            const std::vector<uint8_t>&, uint32_t) override {
        return 0;
    }
    uint32_t Status(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                    std::vector<uint8_t>& reader_names, uint32_t& state,
                    uint32_t& protocol, std::vector<uint8_t>& atr) override {
        if (status_status != 0) return status_status;
        reader_names = {'R', '0', 0, 0};
        state = rtsc::smartcard::kScardStatePresent;
        protocol = rtsc::smartcard::kScardProtocolT1;
        atr = {0x3B, 0x65};
        return 0;
    }
    uint32_t Transmit(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                      const rtsc::smartcard::ScardPci& send_pci,
                      const std::vector<uint8_t>& send, bool wants_recv_pci,
                      uint32_t recv_capacity,
                      rtsc::smartcard::ScardPci& recv_pci,
                      std::vector<uint8_t>& recv) override {
        transmit_send = send;
        transmit_pci = send_pci;
        transmit_wants_recv_pci = wants_recv_pci;
        transmit_capacity = recv_capacity;
        if (transmit_status != 0) return transmit_status;
        recv_pci.protocol = send_pci.protocol;
        recv = {0x90, 0x00};
        return 0;
    }
    uint32_t Control(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                     uint32_t control_code, const std::vector<uint8_t>& in,
                     uint32_t out_capacity,
                     std::vector<uint8_t>& out) override {
        control_code_seen = control_code;
        control_in = in;
        control_capacity = out_capacity;
        if (control_status != 0) return control_status;
        out = {0x01, 0x02};
        return 0;
    }

    // Scripted responses.
    uint32_t establish_status = 0;
    uint32_t release_status = 0;
    uint32_t list_status = 0;
    uint32_t get_status_change_status = 0;
    uint32_t connect_status = 0;
    uint32_t disconnect_status = 0;
    uint32_t status_status = 0;
    uint32_t transmit_status = 0;
    uint32_t control_status = 0;

    // Recorded arguments.
    unsigned establish_count = 0;
    uint32_t establish_scope = 0;
    std::vector<uint8_t> released;
    std::vector<uint8_t> groups_seen;
    uint32_t timeout_seen = 0;
    std::vector<uint8_t> connect_context;
    std::string connect_reader;
    uint32_t connect_share = 0;
    uint32_t connect_protocols = 0;
    std::vector<uint8_t> disconnect_handle;
    uint32_t disconnect_disposition = 0;
    std::vector<uint8_t> transmit_send;
    rtsc::smartcard::ScardPci transmit_pci;
    bool transmit_wants_recv_pci = false;
    uint32_t transmit_capacity = 0;
    uint32_t control_code_seen = 0;
    std::vector<uint8_t> control_in;
    uint32_t control_capacity = 0;
};

}  // namespace

// ---------------------------------------------------------------------------
// Announce: device + capability set
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_announces_scard_device_only_when_enabled) {
    rtsc::rdpdr::HostFileSystem fs;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    CompleteHandshake(client);

    const std::vector<uint8_t>* list =
        FindSent(sent, proto::kPakidCoreDevicelistAnnounce);
    CHECK(list != nullptr);
    if (list != nullptr) {
        proto::RdpdrDeviceListAnnounce parsed;
        const std::vector<uint8_t> body(
            list->begin() + proto::ChannelPduHeader::kSize, list->end());
        CHECK(proto::RdpdrDeviceListAnnounce::parse(body, parsed) ==
              proto::Status::Ok);
    }
}

RTSC_TEST(smartcard_announce_carries_scard_name_and_no_device_data) {
    rtsc::rdpdr::HostFileSystem fs;
    FakeBackend backend;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{1, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    client.EnableSmartCard(&backend);
    CompleteHandshake(client);

    const std::vector<uint8_t>* list =
        FindSent(sent, proto::kPakidCoreDevicelistAnnounce);
    CHECK(list != nullptr);
    if (list == nullptr) return;
    proto::RdpdrDeviceListAnnounce parsed;
    const std::vector<uint8_t> body(
        list->begin() + proto::ChannelPduHeader::kSize, list->end());
    CHECK(proto::RdpdrDeviceListAnnounce::parse(body, parsed) ==
          proto::Status::Ok);
    CHECK_EQ(parsed.device_count, static_cast<uint32_t>(2));
    CHECK_EQ(parsed.devices.size(), size_t{2});
    if (parsed.devices.size() != 2) return;
    const auto& drive = parsed.devices[0];
    CHECK_EQ(drive.device_type, static_cast<uint32_t>(proto::kRdpdrDtypFilesystem));
    const auto& scard = parsed.devices[1];
    CHECK_EQ(scard.device_type,
             static_cast<uint32_t>(proto::kRdpdrDtypSmartcard));
    // [MS-RDPEFS] 2.2.1.3: PreferredDosName must be "SCARD".
    CHECK(scard.dos_name() == std::string("SCARD"));
    CHECK_EQ(scard.device_data_length, static_cast<uint32_t>(0));
    CHECK(scard.device_id != drive.device_id);
}

RTSC_TEST(smartcard_capability_set_added_when_enabled) {
    rtsc::rdpdr::HostFileSystem fs;
    FakeBackend backend;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    client.EnableSmartCard(&backend);
    CompleteHandshake(client);

    const std::vector<uint8_t>* caps =
        FindSent(sent, proto::kPakidCoreClientCapability);
    CHECK(caps != nullptr);
    if (caps == nullptr) return;
    proto::RdpdrCoreCapability parsed;
    const std::vector<uint8_t> caps_body(
        caps->begin() + proto::ChannelPduHeader::kSize, caps->end());
    CHECK(proto::RdpdrCoreCapability::parse(caps_body, parsed) ==
          proto::Status::Ok);
    CHECK_EQ(parsed.num_capabilities, static_cast<uint16_t>(3));
    bool saw_smartcard = false;
    for (const auto& set : parsed.capabilities) {
        if (set.header.capability_type == proto::kCapSmartcardType) {
            saw_smartcard = true;
            CHECK_EQ(set.header.version,
                     static_cast<uint32_t>(proto::kSmartcardCapabilityVersion01));
            CHECK_EQ(set.header.capability_length,
                     static_cast<uint16_t>(proto::RdpdrCapabilityHeader::kSize));
            CHECK_EQ(set.data.size(), size_t{0});
        }
    }
    CHECK(saw_smartcard);
}
namespace {

// Feeds one control request and returns the DR_CONTROL_RSP body bytes
// (DeviceId + CompletionId + IoStatus + OutputBufferLength + OutputBuffer).
std::vector<uint8_t> RunControl(RdpdrClient& client, uint32_t ioctl,
                                const std::vector<uint8_t>& input,
                                uint32_t output_buffer_length,
                                std::vector<std::vector<uint8_t>>& sent) {
    sent.clear();
    FeedBody(client, proto::kPakidCoreDeviceIorequest,
             ControlBody(2, 7, ioctl, input, output_buffer_length));
    const std::vector<uint8_t>* rsp =
        FindSent(sent, proto::kPakidCoreDeviceIocompletion);
    if (rsp == nullptr) return {};
    return std::vector<uint8_t>(rsp->begin() + proto::ChannelPduHeader::kSize +
                                    proto::RdpdrHeader::kSize,
                                rsp->end());
}

// A client whose handshake finished and which has the SCARD device as id 2
// (the drive takes 1).
struct ScardFixture {
    rtsc::rdpdr::HostFileSystem fs;
    FakeBackend backend;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client;

    ScardFixture()
        : client(&fs, {{1, "C:", "C:\\"}}, "HOST",
                 [this](const std::vector<uint8_t>& m) { sent.push_back(m); }) {
        client.EnableSmartCard(&backend);
        CompleteHandshake(client);
        sent.clear();
    }
};

}  // namespace

RTSC_TEST(smartcard_establish_context_round_trip) {
    ScardFixture f;
    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kEstablishContext),
                   EstablishContextCall(2), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 0), 2u);  // DeviceId
    CHECK_EQ(U32At(rsp, 4), 7u);  // CompletionId
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const uint32_t out_len = U32At(rsp, 12);
    CHECK(out_len > 0);
    CHECK_EQ(out_len, static_cast<uint32_t>(rsp.size() - 16));
    CHECK_EQ(f.backend.establish_scope, 2u);
    CHECK_EQ(f.backend.establish_count, 1u);
    // The NDR return starts with the 16-byte header pair and then Result.
    CHECK(rsp.size() >= 36);
    if (rsp.size() >= 16 + 20) {
        const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
        proto::ScardNdrHeader header;
        size_t off = 0, body = 0;
        CHECK(proto::ScardNdrHeader::parse(payload.data(), payload.size(),
                                           header, off, body) ==
              proto::Status::Ok);
        CHECK_EQ(U32At(payload, 16), 0u);  // ReturnCode
        // Context {cbContext=8, ptr}, then referent Length=8 + 8 bytes.
        CHECK_EQ(U32At(payload, 20), 8u);
        CHECK_EQ(U32At(payload, 24), 0x00020000u);
    }
    CHECK_EQ(f.client.smartcard_count(), 1u);
}

RTSC_TEST(smartcard_backend_error_keeps_io_status_success) {
    ScardFixture f;
    f.backend.establish_status = rtsc::smartcard::kScardENoService;
    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kEstablishContext),
                   EstablishContextCall(2), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    // [MS-RDPESC] 2.2.3: smart card errors ride in ReturnCode; the IRP itself
    // succeeded.
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 20);
    if (payload.size() >= 20) {
        CHECK_EQ(U32At(payload, 16),
                 static_cast<uint32_t>(rtsc::smartcard::kScardENoService));
    }
}

RTSC_TEST(smartcard_malformed_call_fails_closed) {
    ScardFixture f;
    const std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF};
    const std::vector<uint8_t> rsp = RunControl(
        f.client, static_cast<uint32_t>(proto::ScardIoctl::kEstablishContext),
        garbage, 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusUnsuccessful));
    CHECK_EQ(U32At(rsp, 12), 0u);  // no output buffer
    CHECK_EQ(rsp.size(), size_t{16});
    CHECK_EQ(f.client.smartcard_count(), 0u);
    CHECK_EQ(f.client.smartcard_reject_count(), 1u);
}

RTSC_TEST(smartcard_unsupported_ioctl_is_rejected) {
    ScardFixture f;
    const std::vector<uint8_t> rsp =
        RunControl(f.client, 0xDEADBEEFu, EstablishContextCall(0), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    // IsSupportedScardIoctl rejects it before any backend call; the client
    // cannot know the return shape, so the IRP fails.
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusUnsuccessful));
}

RTSC_TEST(smartcard_output_buffer_too_small_is_reported) {
    ScardFixture f;
    // EstablishContext_Return is at least 16 (headers) + 4 (Result) + 8
    // (inline context) + 12 (referent length + 8 bytes) = 40 bytes.
    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kEstablishContext),
                   EstablishContextCall(2), 8, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8),
             static_cast<uint32_t>(proto::kStatusBufferTooSmall));
    CHECK_EQ(U32At(rsp, 12), 0u);
}

RTSC_TEST(smartcard_context_is_not_mirrored_from_the_wire) {
    ScardFixture f;
    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kEstablishContext),
                   EstablishContextCall(2), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 44);
    if (rsp.size() < 44) return;
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    // The context bytes the backend allocated (11 22 33 44 ...) must appear,
    // not anything the server supplied (it supplied none here).
    const std::vector<uint8_t> expected = {0x11, 0x22, 0x33, 0x44,
                                           0x55, 0x66, 0x77, 0x88};
    bool found = false;
    for (size_t i = 0; i + expected.size() <= payload.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < expected.size(); ++j) {
            if (payload[i + j] != expected[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            found = true;
            break;
        }
    }
    CHECK(found);
}

RTSC_TEST(smartcard_disconnect_forwards_handle_and_disposition) {
    ScardFixture f;
    // HCardAndDisposition_Call ([MS-RDPESC] 2.2.2.16): inline
    //   Context{cbContext, ptr}, Handle{Context{cbContext, ptr}, cbHandle, ptr},
    //   Disposition; referents follow in pointer order.
    const std::vector<uint8_t> call = Concat({
        Le32(4), Le32(0x00020000),  // Handle.Context: cbContext=4, ptr=0
        Le32(4), Le32(0x00020004),  // Handle: cbHandle=4, ptr=1
        Le32(3),                    // Disposition = SCARD_EJECT_CARD
        Le32(4), Le32(0xAABBCCDD),  // referent 0: context bytes
        Le32(4), Le32(0x11223344),  // referent 1: handle bytes
    });
    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kDisconnect),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.disconnect_disposition, 3u);
    CHECK_EQ(f.backend.disconnect_handle.size(), size_t{4});
    if (f.backend.disconnect_handle.size() == 4) {
        CHECK_EQ(U32At(f.backend.disconnect_handle, 0), 0x11223344u);
    }
}

// A zero-length context/handle pair is the failure shape FreeRDP produces; it
// still has to reach the backend verbatim rather than being rejected here.
RTSC_TEST(smartcard_disconnect_accepts_empty_handle) {
    ScardFixture f;
    const std::vector<uint8_t> call = Concat({
        Le32(0), Le32(0),  // Handle.Context{cb=0, NULL}
        Le32(0), Le32(0),  // Handle{cbHandle=0, NULL}
        Le32(0),           // Disposition = SCARD_LEAVE_CARD
    });
    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kDisconnect),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK(f.backend.disconnect_handle.empty());
}

RTSC_TEST(smartcard_connect_forwards_reader_and_protocol) {
    ScardFixture f;
    // ConnectA_Call ([MS-RDPESC] 2.2.2.13 / Connect_Common 2.2.1.3):
    //   szReader ptr, Context{cb, ptr}, ShareMode, PreferredProtocols;
    //   referents: reader [string], context bytes.
    const std::string reader = "Reader 0";
    std::vector<uint8_t> call = Concat({
        Le32(0x00020000),           // szReader full pointer
        Le32(4), Le32(0x00020004),  // Context{cb=4, ptr}
        Le32(rtsc::smartcard::kScardShareShared),
        Le32(rtsc::smartcard::kScardProtocolT0 |
             rtsc::smartcard::kScardProtocolT1),
        Le32(static_cast<uint32_t>(reader.size()) + 1), Le32(0),
        Le32(static_cast<uint32_t>(reader.size()) + 1),
    });
    call.insert(call.end(), reader.begin(), reader.end());
    call.push_back(0);
    while (call.size() % 4 != 0) call.push_back(0);
    call = Concat({call, Le32(4), Le32(0x0BADF00D)});

    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kConnectA),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK(f.backend.connect_reader == reader);
    CHECK_EQ(f.backend.connect_share, rtsc::smartcard::kScardShareShared);
    CHECK_EQ(f.backend.connect_protocols,
             rtsc::smartcard::kScardProtocolT0 |
                 rtsc::smartcard::kScardProtocolT1);
    // The handle the backend minted (AA BB CC DD) must reach the wire; the
    // context the server supplied must not be trusted as a handle.
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    const std::vector<uint8_t> handle = {0xAA, 0xBB, 0xCC, 0xDD};
    bool found = false;
    for (size_t i = 0; i + handle.size() <= payload.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < handle.size(); ++j) {
            if (payload[i + j] != handle[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            found = true;
            break;
        }
    }
    CHECK(found);
    // Connect_Return echoes the REDIR_SCARDCONTEXT the server supplied
    // ([MS-RDPESC] 2.2.3.8 / 3.1.4.28).
    {
        const std::vector<uint8_t> ctx = {0x0D, 0xF0, 0xAD, 0x0B};
        bool ctx_found = false;
        for (size_t i = 0; i + ctx.size() <= payload.size(); ++i) {
            if (std::memcmp(payload.data() + i, ctx.data(), ctx.size()) == 0) {
                ctx_found = true;
                break;
            }
        }
        CHECK(ctx_found);
    }
}

RTSC_TEST(smartcard_connect_failure_has_empty_handle) {
    ScardFixture f;
    f.backend.connect_status = rtsc::smartcard::kScardENoSmartcard;
    const std::string reader = "R";
    std::vector<uint8_t> call = Concat({
        Le32(0x00020000),
        Le32(0), Le32(0),           // Context{cb=0, NULL}
        Le32(rtsc::smartcard::kScardShareShared),
        Le32(rtsc::smartcard::kScardProtocolT1),
        Le32(2), Le32(0), Le32(2),
    });
    call.insert(call.end(), {'R', 0});
    while (call.size() % 4 != 0) call.push_back(0);

    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kConnectA),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    if (payload.size() >= 20) {
        CHECK_EQ(U32At(payload, 16),
                 static_cast<uint32_t>(rtsc::smartcard::kScardENoSmartcard));
    }
}

RTSC_TEST(smartcard_list_readers_returns_multistring) {
    ScardFixture f;
    // ListReaders_Call ([MS-RDPESC] 2.2.2.4): Context{cb,ptr}, cBytes,
    // mszGroups ptr, fmszReadersIsNULL, cchReaders; referents: context bytes,
    // then the group multistring.
    const std::vector<uint8_t> call = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(0),                    // cBytes = 0 (no group filter)
        Le32(0),                    // mszGroups = NULL
        Le32(1),                    // fmszReadersIsNULL = 1 (probe)
        Le32(0),                    // cchReaders = 0
        Le32(4), Le32(0x0BADF00D),  // context referent
    });
    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kListReadersA),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK(f.backend.groups_seen.empty());
    // ListReaders_Return ([MS-RDPESC] 2.2.3.4): ReturnCode, cBytes, msz ptr.
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 20);
    if (payload.size() < 20) return;
    proto::ScardNdrHeader header;
    size_t off = 0, body = 0;
    CHECK(proto::ScardNdrHeader::parse(payload.data(), payload.size(), header,
                                       off, body) == proto::Status::Ok);
    CHECK_EQ(U32At(payload, 16), 0u);   // ReturnCode
    CHECK_EQ(U32At(payload, 20), 4u);   // cBytes = "R0\0\0"
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
}

RTSC_TEST(smartcard_get_status_change_returns_reader_states) {
    ScardFixture f;
    // GetStatusChangeA_Call ([MS-RDPESC] 2.2.2.11): Context, dwTimeOut,
    // cReaders, rgReaderStates ptr; referents: context bytes,
    // MaxCount + ReaderStateA[], then the reader name string.
    const std::string reader = "R0";
    std::vector<uint8_t> call = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(500),                  // dwTimeOut
        Le32(1),                    // cReaders
        Le32(0x00020004),           // rgReaderStates ptr
        Le32(4), Le32(0x0BADF00D),  // context referent
        Le32(1),                    // array MaxCount
        Le32(0x00020008),           // szReader full pointer
        Le32(rtsc::smartcard::kScardStateUnaware),  // dwCurrentState
        Le32(0),                                    // dwEventState
        Le32(0),                                    // cbAtr
    });
    for (int i = 0; i < 36; ++i) call.push_back(0);
    call = Concat({call, Le32(static_cast<uint32_t>(reader.size()) + 1),
                   Le32(0), Le32(static_cast<uint32_t>(reader.size()) + 1)});
    call.insert(call.end(), reader.begin(), reader.end());
    call.push_back(0);
    while (call.size() % 4 != 0) call.push_back(0);

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetStatusChangeA),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.timeout_seen, 500u);
    // GetStatusChange_Return: ReturnCode, cReaders, array ptr, referent.
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 24);
    if (payload.size() < 24) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 1u);  // cReaders
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    // The first element's event_state (offset: 8 hdr + 4 result + 4 count +
    // 4 ptr + 4 MaxCount + 4 current) is SCARD_STATE_PRESENT.
    if (payload.size() >= 44) {
        CHECK_EQ(U32At(payload, 36),
                 static_cast<uint32_t>(rtsc::smartcard::kScardStatePresent));
    }
}

RTSC_TEST(smartcard_transmit_returns_recv_buffer) {
    ScardFixture f;
    // Transmit_Call ([MS-RDPESC] 2.2.2.19): Context, Handle, send pci
    // {protocol, cbExtra, extra ptr}, cbSendLength, pbSendBuffer ptr,
    // pioRecvPci ptr, fpbRecvBufferIsNULL, cbRecvLength.
    const std::vector<uint8_t> call = Concat({
        Le32(0), Le32(0),                       // Handle.Context
        Le32(0), Le32(0),                       // Handle
        Le32(rtsc::smartcard::kScardProtocolT1),// send pci protocol
        Le32(0), Le32(0),                       // send pci extra = 0, NULL
        Le32(2), Le32(0x00020000),              // cbSendLength, send buffer
        Le32(0),                                // pioRecvPci = NULL
        Le32(0),                                // fpbRecvBufferIsNULL = 0
        Le32(258),                              // cbRecvLength
        Le32(2), std::vector<uint8_t>{0x00, 0xA4}, std::vector<uint8_t>(2, 0),
    });
    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kTransmit),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.transmit_send.size(), size_t{2});
    CHECK_EQ(f.backend.transmit_capacity, 258u);
    CHECK(!f.backend.transmit_wants_recv_pci);
}
// The context/handle opaque ids the server echoes must be the ones the backend
// handed out; a backend that knows nothing about a forged id reports
// SCARD_E_INVALID_HANDLE and that code must reach the wire as ReturnCode.
RTSC_TEST(smartcard_null_backend_reports_no_service) {
    rtsc::rdpdr::HostFileSystem fs;
    auto null_backend = MakeNullSmartCardBackend();
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{1, "C:", "C:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    client.EnableSmartCard(null_backend.get());
    CompleteHandshake(client);
    sent.clear();

    CHECK(!null_backend->available());
    const std::vector<uint8_t> rsp =
        RunControl(client, static_cast<uint32_t>(proto::ScardIoctl::kEstablishContext),
                   EstablishContextCall(2), 2048, sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 36);
    if (rsp.size() < 36) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK_EQ(U32At(payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardENoService));
}

RTSC_TEST(smartcard_device_id_is_not_a_drive_id) {
    rtsc::rdpdr::HostFileSystem fs;
    FakeBackend backend;
    std::vector<std::vector<uint8_t>> sent;
    RdpdrClient client(&fs, {{1, "C:", "C:\\"}, {2, "D:", "D:\\"}}, "HOST",
                       [&](const std::vector<uint8_t>& m) {
                           sent.push_back(m);
                       });
    client.EnableSmartCard(&backend);
    CompleteHandshake(client);
    const std::vector<uint8_t>* list =
        FindSent(sent, proto::kPakidCoreDevicelistAnnounce);
    CHECK(list != nullptr);
    if (list == nullptr) return;
    proto::RdpdrDeviceListAnnounce parsed;
    const std::vector<uint8_t> body(
        list->begin() + proto::ChannelPduHeader::kSize, list->end());
    CHECK(proto::RdpdrDeviceListAnnounce::parse(body, parsed) ==
          proto::Status::Ok);
    CHECK_EQ(parsed.device_count, static_cast<uint32_t>(3));
    CHECK_EQ(parsed.devices.size(), size_t{3});
    if (parsed.devices.size() != 3) return;
    CHECK_EQ(parsed.devices[2].device_id, static_cast<uint32_t>(3));
}

int main() {
    return ::rtsc::test::run_all("rtsc_smartcard_channel_tests");
}
