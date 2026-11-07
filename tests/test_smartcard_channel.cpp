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

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
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

std::vector<uint8_t> Zeros(size_t n) { return std::vector<uint8_t>(n, 0); }

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
        if (block_establish.load()) {
            establish_entered.store(true);
            while (!establish_release.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
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
    uint32_t IsValidContext(const std::vector<uint8_t>& context) override {
        valid_context_seen = context;
        ++valid_context_calls;
        return valid_context_status;
    }
    uint32_t ListReaderGroups(const std::vector<uint8_t>&,
                              std::vector<uint8_t>& groups) override {
        if (list_status != 0) return list_status;
        groups = {'G', 'r', 'p', 0, 0};
        return 0;
    }
    uint32_t ListReaderGroupsW(const std::vector<uint8_t>&,
                               std::vector<uint8_t>& groups) override {
        if (list_status_w != 0) return list_status_w;
        groups = {'G', 0, 'r', 0, 'p', 0, 0, 0, 0, 0};
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
    uint32_t ListReadersW(const std::vector<uint8_t>&,
                          const std::vector<uint8_t>& groups,
                          std::vector<uint8_t>& readers) override {
        groups_seen_w = groups;
        if (list_status_w != 0) return list_status_w;
        readers = {'R', 0, 0, 0, '0', 0, 0, 0, 0, 0};
        return 0;
    }
    uint32_t GetStatusChange(const std::vector<uint8_t>&, uint32_t timeout_ms,
                             std::vector<rtsc::smartcard::ScardReaderState>&
                                 states) override {
        timeout_seen = timeout_ms;
        for (auto& st : states) {
            st.event_state = rtsc::smartcard::kScardStatePresent;
            st.atr = {0x3B, 0x00};
        }
        return get_status_change_status;
    }
    uint32_t GetStatusChangeW(
        const std::vector<uint8_t>&, uint32_t timeout_ms,
        std::vector<rtsc::smartcard::ScardReaderStateW>& states) override {
        timeout_seen_w = timeout_ms;
        names_seen_w.clear();
        for (const auto& st : states) names_seen_w.push_back(st.reader);
        if (get_status_change_status_w != 0)
            return get_status_change_status_w;
        for (auto& st : states) {
            st.event_state = rtsc::smartcard::kScardStatePresent;
            st.atr = {0x3B, 0x00};
        }
        return 0;
    }
    uint32_t LocateCards(const std::vector<uint8_t>& context,
                         const std::vector<uint8_t>& cards,
                         std::vector<rtsc::smartcard::ScardReaderState>&
                             states) override {
        locate_context = context;
        locate_cards = cards;
        locate_readers.clear();
        for (const auto& st : states) locate_readers.push_back(st.reader);
        ++locate_calls;
        if (locate_status != 0) return locate_status;
        for (auto& st : states) {
            st.event_state = locate_event_state;
            st.atr = locate_atr;
        }
        return 0;
    }
    uint32_t LocateCardsW(
        const std::vector<uint8_t>& context,
        const std::vector<uint8_t>& cards,
        std::vector<rtsc::smartcard::ScardReaderStateW>& states) override {
        locate_context_w = context;
        locate_cards_w = cards;
        locate_readers_w.clear();
        for (const auto& st : states) locate_readers_w.push_back(st.reader);
        ++locate_calls_w;
        if (locate_status_w != 0) return locate_status_w;
        for (auto& st : states) {
            st.event_state = locate_event_state_w;
            st.atr = locate_atr_w;
        }
        return 0;
    }
    uint32_t LocateCardsByAtr(
        const std::vector<uint8_t>& context,
        const std::vector<rtsc::smartcard::ScardAtrMask>& masks,
        std::vector<rtsc::smartcard::ScardReaderState>& states) override {
        locate_atr_context = context;
        locate_atr_masks = masks;
        locate_atr_readers.clear();
        for (const auto& st : states) locate_atr_readers.push_back(st.reader);
        ++locate_atr_calls;
        if (locate_atr_status != 0) return locate_atr_status;
        for (auto& st : states) {
            st.event_state = locate_atr_event_state;
            st.atr = locate_atr_atr;
        }
        return 0;
    }
    uint32_t LocateCardsByAtrW(
        const std::vector<uint8_t>& context,
        const std::vector<rtsc::smartcard::ScardAtrMask>& masks,
        std::vector<rtsc::smartcard::ScardReaderStateW>& states) override {
        locate_atr_context_w = context;
        locate_atr_masks_w = masks;
        locate_atr_readers_w.clear();
        for (const auto& st : states) locate_atr_readers_w.push_back(st.reader);
        ++locate_atr_calls_w;
        if (locate_atr_status_w != 0) return locate_atr_status_w;
        for (auto& st : states) {
            st.event_state = locate_atr_event_state_w;
            st.atr = locate_atr_atr_w;
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
    uint32_t ConnectW(const std::vector<uint8_t>& context,
                      const std::u16string& reader, uint32_t share_mode,
                      uint32_t preferred_protocols,
                      std::vector<uint8_t>& handle,
                      uint32_t& active_protocol) override {
        connect_w_context = context;
        connect_w_reader = reader;
        connect_w_share = share_mode;
        connect_w_protocols = preferred_protocols;
        if (connect_w_status != 0) return connect_w_status;
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
    uint32_t StatusW(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                     std::vector<uint8_t>& reader_names, uint32_t& state,
                     uint32_t& protocol, std::vector<uint8_t>& atr) override {
        if (status_w_status != 0) return status_w_status;
        reader_names = {'R', 0, '0', 0, 0, 0, 0, 0};
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
    uint32_t GetAttrib(const std::vector<uint8_t>& context,
                       const std::vector<uint8_t>& handle, uint32_t attr_id,
                       bool attr_is_null, uint32_t capacity,
                       std::vector<uint8_t>& attr,
                       uint32_t& attr_length) override {
        attr_context = context;
        attr_handle = handle;
        attr_id_seen = attr_id;
        attr_is_null_seen = attr_is_null;
        attr_capacity_seen = capacity;
        ++get_attrib_calls;
        if (get_attrib_status != 0) return get_attrib_status;
        attr_length = static_cast<uint32_t>(get_attrib_data.size());
        if (attr_is_null || capacity == 0) {
            attr.clear();
            return 0;
        }
        // Return the data even when it exceeds `capacity`: the handler owns
        // the SCARD_E_INSUFFICIENT_BUFFER decision.
        attr = get_attrib_data;
        return 0;
    }
    uint32_t SetAttrib(const std::vector<uint8_t>& context,
                       const std::vector<uint8_t>& handle, uint32_t attr_id,
                       const std::vector<uint8_t>& attr) override {
        set_attr_context = context;
        set_attr_handle = handle;
        set_attr_id_seen = attr_id;
        set_attr_value = attr;
        ++set_attrib_calls;
        return set_attrib_status;
    }
    uint32_t ReadCache(const std::vector<uint8_t>& context,
                       const std::vector<uint8_t>& card_id,
                       uint32_t freshness, const std::string& lookup_name,
                       bool length_only, uint32_t capacity,
                       std::vector<uint8_t>& data,
                       uint32_t& data_length) override {
        read_cache_context = context;
        read_cache_card_id = card_id;
        read_cache_freshness = freshness;
        read_cache_lookup = lookup_name;
        read_cache_length_only = length_only;
        read_cache_capacity = capacity;
        ++read_cache_calls;
        if (read_cache_status != 0) return read_cache_status;
        data_length = static_cast<uint32_t>(read_cache_data.size());
        if (!length_only) data = read_cache_data;
        return 0;
    }
    uint32_t ReadCacheW(const std::vector<uint8_t>& context,
                        const std::vector<uint8_t>& card_id,
                        uint32_t freshness, const std::u16string& lookup_name,
                        bool length_only, uint32_t capacity,
                        std::vector<uint8_t>& data,
                        uint32_t& data_length) override {
        read_cache_context_w = context;
        read_cache_card_id_w = card_id;
        read_cache_freshness_w = freshness;
        read_cache_lookup_w = lookup_name;
        read_cache_length_only_w = length_only;
        read_cache_capacity_w = capacity;
        ++read_cache_calls_w;
        if (read_cache_status_w != 0) return read_cache_status_w;
        data_length = static_cast<uint32_t>(read_cache_data_w.size());
        if (!length_only) data = read_cache_data_w;
        return 0;
    }
    uint32_t WriteCache(const std::vector<uint8_t>& context,
                        const std::vector<uint8_t>& card_id,
                        uint32_t freshness, const std::string& lookup_name,
                        const std::vector<uint8_t>& data) override {
        write_cache_context = context;
        write_cache_card_id = card_id;
        write_cache_freshness = freshness;
        write_cache_lookup = lookup_name;
        write_cache_data = data;
        ++write_cache_calls;
        return write_cache_status;
    }
    uint32_t WriteCacheW(const std::vector<uint8_t>& context,
                         const std::vector<uint8_t>& card_id,
                         uint32_t freshness, const std::u16string& lookup_name,
                         const std::vector<uint8_t>& data) override {
        write_cache_context_w = context;
        write_cache_card_id_w = card_id;
        write_cache_freshness_w = freshness;
        write_cache_lookup_w = lookup_name;
        write_cache_data_w = data;
        ++write_cache_calls_w;
        return write_cache_status_w;
    }
    uint32_t GetReaderIcon(const std::vector<uint8_t>& context,
                           const std::u16string& reader_name,
                           std::vector<uint8_t>& icon,
                           uint32_t& icon_length) override {
        reader_icon_context = context;
        reader_icon_name = reader_name;
        ++reader_icon_calls;
        if (reader_icon_status != 0) return reader_icon_status;
        icon = reader_icon_data;
        icon_length = static_cast<uint32_t>(icon.size());
        return 0;
    }
    uint32_t GetDeviceTypeId(const std::vector<uint8_t>& context,
                             const std::u16string& reader_name,
                             uint32_t& device_type_id) override {
        device_type_context = context;
        device_type_name = reader_name;
        ++device_type_calls;
        if (device_type_status != 0) return device_type_status;
        device_type_id = device_type_id_value;
        return 0;
    }
    uint32_t GetTransmitCount(const std::vector<uint8_t>& context,
                              const std::vector<uint8_t>& handle,
                              uint32_t& transmit_count) override {
        transmit_count_context = context;
        transmit_count_handle = handle;
        ++transmit_count_calls;
        if (transmit_count_status != 0) return transmit_count_status;
        transmit_count = transmit_count_value;
        return 0;
    }
    uint32_t AccessStartedEvent() override {
        ++access_started_calls;
        return access_started_status;
    }
    uint32_t Cancel(const std::vector<uint8_t>& context) override {
        cancel_context = context;
        ++cancel_calls;
        return cancel_status;
    }
    uint32_t State(const std::vector<uint8_t>& context,
                   const std::vector<uint8_t>& handle, uint32_t& state,
                   uint32_t& protocol, std::vector<uint8_t>& atr) override {
        state_context = context;
        state_handle = handle;
        ++state_calls;
        if (state_status != 0) return state_status;
        state = state_value;
        protocol = protocol_value;
        atr = state_atr;
        return 0;
    }
    uint32_t Reconnect(const std::vector<uint8_t>& context,
                       const std::vector<uint8_t>& handle,
                       uint32_t share_mode, uint32_t preferred_protocols,
                       uint32_t initialization,
                       uint32_t& active_protocol) override {
        reconnect_context = context;
        reconnect_handle = handle;
        reconnect_share = share_mode;
        reconnect_preferred = preferred_protocols;
        reconnect_initialization = initialization;
        ++reconnect_calls;
        if (reconnect_status != 0) return reconnect_status;
        active_protocol = reconnect_active;
        return 0;
    }

    // Scripted responses.
    // Test hook: when block_establish is set, EstablishContext signals entry
    // and waits for release, so a test can hold a worker-thread call in
    // flight while it replaces the session.
    std::atomic<bool> block_establish{false};
    std::atomic<bool> establish_entered{false};
    std::atomic<bool> establish_release{false};
    uint32_t establish_status = 0;
    uint32_t release_status = 0;
    uint32_t valid_context_status = 0;
    uint32_t list_status = 0;
    uint32_t list_status_w = 0;
    uint32_t get_status_change_status = 0;
    uint32_t get_status_change_status_w = 0;
    uint32_t locate_status = 0;
    uint32_t locate_status_w = 0;
    uint32_t locate_event_state = rtsc::smartcard::kScardStatePresent;
    std::vector<uint8_t> locate_atr = {0x3B, 0x00};
    std::vector<uint8_t> locate_context;
    std::vector<uint8_t> locate_cards;
    std::vector<std::string> locate_readers;
    std::vector<uint8_t> locate_context_w;
    std::vector<uint8_t> locate_cards_w;
    std::vector<std::u16string> locate_readers_w;
    unsigned locate_calls_w = 0;
    uint32_t locate_event_state_w = rtsc::smartcard::kScardStatePresent;
    std::vector<uint8_t> locate_atr_w = {0x3B, 0x00};
    unsigned locate_calls = 0;
    uint32_t locate_atr_status = 0;
    uint32_t locate_atr_status_w = 0;
    uint32_t locate_atr_event_state = rtsc::smartcard::kScardStateAtrMatch;
    std::vector<uint8_t> locate_atr_atr = {0x3B, 0x00};
    std::vector<uint8_t> locate_atr_context;
    std::vector<rtsc::smartcard::ScardAtrMask> locate_atr_masks;
    uint32_t locate_atr_event_state_w = rtsc::smartcard::kScardStateAtrMatch;
    std::vector<uint8_t> locate_atr_atr_w = {0x3B, 0x00};
    std::vector<uint8_t> locate_atr_context_w;
    std::vector<rtsc::smartcard::ScardAtrMask> locate_atr_masks_w;
    std::vector<std::u16string> locate_atr_readers_w;
    unsigned locate_atr_calls_w = 0;
    std::vector<std::string> locate_atr_readers;
    unsigned locate_atr_calls = 0;
    uint32_t connect_status = 0;
    uint32_t connect_w_status = 0;
    uint32_t disconnect_status = 0;
    uint32_t status_status = 0;
    uint32_t status_w_status = 0;
    uint32_t transmit_status = 0;
    uint32_t control_status = 0;
    uint32_t get_attrib_status = 0;
    uint32_t set_attrib_status = 0;

    // Recorded arguments.
    unsigned establish_count = 0;
    uint32_t establish_scope = 0;
    std::vector<uint8_t> released;
    std::vector<uint8_t> valid_context_seen;
    unsigned valid_context_calls = 0;
    std::vector<uint8_t> groups_seen;
    std::vector<uint8_t> groups_seen_w;
    uint32_t timeout_seen = 0;
    uint32_t timeout_seen_w = 0;
    std::vector<std::u16string> names_seen_w;
    std::vector<uint8_t> connect_context;
    std::string connect_reader;
    std::vector<uint8_t> connect_w_context;
    std::u16string connect_w_reader;
    uint32_t connect_w_share = 0;
    uint32_t connect_w_protocols = 0;
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
    std::vector<uint8_t> get_attrib_data;
    std::vector<uint8_t> attr_context;
    std::vector<uint8_t> attr_handle;
    uint32_t attr_id_seen = 0;
    bool attr_is_null_seen = false;
    uint32_t attr_capacity_seen = 0;
    unsigned get_attrib_calls = 0;
    std::vector<uint8_t> set_attr_context;
    std::vector<uint8_t> set_attr_handle;
    uint32_t set_attr_id_seen = 0;
    std::vector<uint8_t> set_attr_value;
    unsigned set_attrib_calls = 0;
    uint32_t read_cache_status = 0;
    uint32_t read_cache_status_w = 0;
    std::vector<uint8_t> read_cache_data;
    std::vector<uint8_t> read_cache_context;
    std::vector<uint8_t> read_cache_card_id;
    uint32_t read_cache_freshness = 0;
    std::string read_cache_lookup;
    std::vector<uint8_t> read_cache_context_w;
    std::vector<uint8_t> read_cache_card_id_w;
    uint32_t read_cache_freshness_w = 0;
    std::u16string read_cache_lookup_w;
    bool read_cache_length_only_w = false;
    uint32_t read_cache_capacity_w = 0;
    std::vector<uint8_t> read_cache_data_w = {'C', 'W'};
    unsigned read_cache_calls_w = 0;
    bool read_cache_length_only = false;
    uint32_t read_cache_capacity = 0;
    unsigned read_cache_calls = 0;
    uint32_t write_cache_status = 0;
    uint32_t write_cache_status_w = 0;
    std::vector<uint8_t> write_cache_context;
    std::vector<uint8_t> write_cache_card_id;
    uint32_t write_cache_freshness = 0;
    std::string write_cache_lookup;
    std::vector<uint8_t> write_cache_context_w;
    std::vector<uint8_t> write_cache_card_id_w;
    uint32_t write_cache_freshness_w = 0;
    std::u16string write_cache_lookup_w;
    std::vector<uint8_t> write_cache_data_w;
    unsigned write_cache_calls_w = 0;
    std::vector<uint8_t> write_cache_data;
    unsigned write_cache_calls = 0;
    uint32_t reader_icon_status = 0;
    std::vector<uint8_t> reader_icon_data;
    std::vector<uint8_t> reader_icon_context;
    std::u16string reader_icon_name;
    unsigned reader_icon_calls = 0;
    uint32_t device_type_status = 0;
    uint32_t device_type_id_value = 0;
    std::vector<uint8_t> device_type_context;
    std::u16string device_type_name;
    unsigned device_type_calls = 0;
    uint32_t transmit_count_status = 0;
    uint32_t transmit_count_value = 0;
    std::vector<uint8_t> transmit_count_context;
    std::vector<uint8_t> transmit_count_handle;
    unsigned transmit_count_calls = 0;
    uint32_t access_started_status = 0;
    unsigned access_started_calls = 0;
    uint32_t cancel_status = 0;
    std::vector<uint8_t> cancel_context;
    unsigned cancel_calls = 0;
    uint32_t state_status = 0;
    uint32_t state_value = 0;
    uint32_t protocol_value = 0;
    std::vector<uint8_t> state_atr;
    std::vector<uint8_t> state_context;
    std::vector<uint8_t> state_handle;
    unsigned state_calls = 0;
    uint32_t reconnect_status = 0;
    uint32_t reconnect_active = 0;
    std::vector<uint8_t> reconnect_context;
    std::vector<uint8_t> reconnect_handle;
    uint32_t reconnect_share = 0;
    uint32_t reconnect_preferred = 0;
    uint32_t reconnect_initialization = 0;
    unsigned reconnect_calls = 0;
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

// [MS-RDPESC] 3.1.4.3: ISVALIDCONTEXT carries Context_Call and answers with
// Long_Return (Result only). A backend error stays in ReturnCode while the IRP
// itself succeeds.
RTSC_TEST(smartcard_is_valid_context_round_trip) {
    ScardFixture f;
    const std::vector<uint8_t> context_call = Wrap(Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
    }));
    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kIsValidContext),
                   context_call, 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.valid_context_calls, 1u);
    CHECK(f.backend.valid_context_seen ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 20);
    if (payload.size() >= 20) {
        CHECK_EQ(U32At(payload, 16), 0u);  // SCARD_S_SUCCESS
    }
    CHECK_EQ(f.client.smartcard_count(), 1u);

    // Failure: the smart card status rides in ReturnCode, IoStatus stays 0.
    f.backend.valid_context_status = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> rsp2 =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kIsValidContext),
                   context_call, 2048, f.sent);
    CHECK(!rsp2.empty());
    CHECK(rsp2.size() >= 16);
    if (rsp2.size() < 16) return;
    CHECK_EQ(U32At(rsp2, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> payload2(rsp2.begin() + 16, rsp2.end());
    CHECK(payload2.size() >= 20);
    if (payload2.size() >= 20) {
        CHECK_EQ(U32At(payload2, 16),
                 static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
    }
}

// [MS-RDPESC] 2.2.2.21 / 2.2.3.12: GETATTRIB returns the attribute bytes, a
// length-only probe (NULL pbAttr), or SCARD_E_INSUFFICIENT_BUFFER.
RTSC_TEST(smartcard_get_attrib_round_trip) {
    ScardFixture f;
    f.backend.get_attrib_data = {0x41, 0x42};
    const auto make_call = [](uint32_t attr_is_null, uint32_t capacity) {
        return Wrap(Concat({
            Le32(4), Le32(0x00020000),
            Le32(4), Le32(0x00020004),
            Le32(0x00000007u),  // SCARD_ATTR_DEVICE_SYSTEM_NAME_A
            Le32(attr_is_null),
            Le32(capacity),
            Le32(4), std::vector<uint8_t>{0x00, 0x00, 0x01, 0xCD},
            Le32(4), std::vector<uint8_t>{0x11, 0x22, 0x33, 0x44},
        }));
    };

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetAttrib),
                   make_call(0, 16), 2048, f.sent);
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.get_attrib_calls, 1u);
    CHECK_EQ(f.backend.attr_id_seen, 7u);
    CHECK_EQ(f.backend.attr_capacity_seen, 16u);
    CHECK(f.backend.attr_context ==
          std::vector<uint8_t>({0x00, 0x00, 0x01, 0xCD}));
    CHECK(f.backend.attr_handle ==
          std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 28);
    if (payload.size() >= 28) {
        CHECK_EQ(U32At(payload, 16), 0u);  // ReturnCode
        CHECK_EQ(U32At(payload, 20), 2u);  // cbAttrLen
        CHECK(U32At(payload, 24) != 0u);   // pbAttr non-NULL
        CHECK_EQ(U32At(payload, 28), 2u);  // referent length
        CHECK_EQ(payload[32], 0x41);
        CHECK_EQ(payload[33], 0x42);
    }

    // Length probe: fpbAttrIsNULL=1 -> length, NULL pbAttr. The capacity is
    // deliberately non-zero so the probe branch is driven by the flag alone
    // (a mutation that ignores fpbAttrIsNULL must fail this case).
    f.backend.get_attrib_data = {0x41, 0x42, 0x43};
    const std::vector<uint8_t> probe =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetAttrib),
                   make_call(1, 16), 2048, f.sent);
    CHECK(probe.size() >= 16);
    if (probe.size() < 16) return;
    CHECK_EQ(U32At(probe, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> probe_payload(probe.begin() + 16, probe.end());
    CHECK(probe_payload.size() >= 28);
    if (probe_payload.size() >= 28) {
        CHECK_EQ(U32At(probe_payload, 16), 0u);
        CHECK_EQ(U32At(probe_payload, 20), 3u);  // length
        CHECK_EQ(U32At(probe_payload, 24), 0u);  // NULL
    }

    // Data larger than cbAttrLen -> SCARD_E_INSUFFICIENT_BUFFER, NULL buffer.
    const std::vector<uint8_t> small =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetAttrib),
                   make_call(0, 2), 2048, f.sent);
    CHECK(small.size() >= 16);
    if (small.size() < 16) return;
    CHECK_EQ(U32At(small, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> small_payload(small.begin() + 16, small.end());
    CHECK(small_payload.size() >= 28);
    if (small_payload.size() >= 28) {
        CHECK_EQ(U32At(small_payload, 16),
                 static_cast<uint32_t>(rtsc::smartcard::kScardEInsufficientBuffer));
        CHECK_EQ(U32At(small_payload, 20), 0u);
        CHECK_EQ(U32At(small_payload, 24), 0u);
    }

    // Backend failure: the smart card status rides in ReturnCode.
    f.backend.get_attrib_status = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetAttrib),
                   make_call(0, 16), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 28);
    if (failed_payload.size() >= 28) {
        CHECK_EQ(U32At(failed_payload, 16),
                 static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
    }
}

// [MS-RDPESC] 2.2.2.22 / 2.2.3.3: SETATTRIB forwards the attribute bytes and
// answers with Long_Return.
RTSC_TEST(smartcard_set_attrib_round_trip) {
    ScardFixture f;
    const std::vector<uint8_t> call = Wrap(Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00000007u),  // SCARD_ATTR_DEVICE_SYSTEM_NAME_A
        Le32(3),            // cbAttrLen
        Le32(0x00020008),   // pbAttr
        Le32(4), std::vector<uint8_t>{0x00, 0x00, 0x01, 0xCD},
        Le32(4), std::vector<uint8_t>{0x11, 0x22, 0x33, 0x44},
        Le32(3), std::vector<uint8_t>{'A', 'B', 'C', 0x00},
    }));
    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kSetAttrib), call,
                   2048, f.sent);
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.set_attrib_calls, 1u);
    CHECK_EQ(f.backend.set_attr_id_seen, 7u);
    CHECK(f.backend.set_attr_value ==
          std::vector<uint8_t>({'A', 'B', 'C'}));
    CHECK(f.backend.set_attr_context ==
          std::vector<uint8_t>({0x00, 0x00, 0x01, 0xCD}));
    CHECK(f.backend.set_attr_handle ==
          std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 20);
    if (payload.size() >= 20) {
        CHECK_EQ(U32At(payload, 16), 0u);  // Long_Return Result
    }

    // Failure: the smart card status rides in ReturnCode.
    f.backend.set_attrib_status = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kSetAttrib), call,
                   2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 20);
    if (failed_payload.size() >= 20) {
        CHECK_EQ(U32At(failed_payload, 16),
                 static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
    }
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

RTSC_TEST(smartcard_output_buffer_exact_fit_succeeds) {
    ScardFixture f;
    // EstablishContext_Return is 40 bytes (16 headers + 4 Result + 8 inline
    // context + 12 referent). An exact fit must succeed: the check is
    // `encoded.size() > output_limit`, not >=.
    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kEstablishContext),
                   EstablishContextCall(2), 40, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(U32At(rsp, 12), 40u);  // OutputBufferLength
}

RTSC_TEST(smartcard_async_poll_delivers_completion) {
    ScardFixture f;
    f.client.SetAsyncSmartCard(true);
    CHECK(f.client.async_smart_card());
    f.sent.clear();
    FeedBody(f.client, proto::kPakidCoreDeviceIorequest,
             ControlBody(2, 9,
                         static_cast<uint32_t>(
                             proto::ScardIoctl::kEstablishContext),
                         EstablishContextCall(2), 2048));
    const std::vector<uint8_t>* rsp = nullptr;
    for (int i = 0; i < 300 && rsp == nullptr; ++i) {
        f.client.PollSmartCard();
        rsp = FindSent(f.sent, proto::kPakidCoreDeviceIocompletion);
        if (rsp == nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(rsp != nullptr);
    if (rsp == nullptr) return;
    const std::vector<uint8_t> body(
        rsp->begin() + proto::ChannelPduHeader::kSize +
            proto::RdpdrHeader::kSize,
        rsp->end());
    CHECK(body.size() >= 16);
    if (body.size() < 16) return;
    CHECK_EQ(U32At(body, 0), 2u);  // DeviceId
    CHECK_EQ(U32At(body, 4), 9u);  // CompletionId
    CHECK_EQ(U32At(body, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    f.client.SetAsyncSmartCard(false);
    CHECK(!f.client.async_smart_card());
}

RTSC_TEST(smartcard_async_rejects_malformed_call) {
    ScardFixture f;
    f.client.SetAsyncSmartCard(true);
    f.sent.clear();
    FeedBody(f.client, proto::kPakidCoreDeviceIorequest,
             ControlBody(2, 10,
                         static_cast<uint32_t>(
                             proto::ScardIoctl::kEstablishContext),
                         {0xFF, 0xFF}, 2048));
    const std::vector<uint8_t>* rsp = nullptr;
    for (int i = 0; i < 300 && rsp == nullptr; ++i) {
        f.client.PollSmartCard();
        rsp = FindSent(f.sent, proto::kPakidCoreDeviceIocompletion);
        if (rsp == nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(rsp != nullptr);
    if (rsp == nullptr) return;
    const std::vector<uint8_t> body(
        rsp->begin() + proto::ChannelPduHeader::kSize +
            proto::RdpdrHeader::kSize,
        rsp->end());
    CHECK(body.size() >= 16);
    if (body.size() < 16) return;
    CHECK_EQ(U32At(body, 8),
             static_cast<uint32_t>(proto::kStatusUnsuccessful));
    CHECK_EQ(U32At(body, 12), 0u);
    CHECK_EQ(f.client.smartcard_reject_count(), 1u);
    f.client.SetAsyncSmartCard(false);
}

RTSC_TEST(smartcard_async_drops_completions_after_reset) {
    ScardFixture f;
    f.backend.block_establish = true;
    f.client.SetAsyncSmartCard(true);
    f.sent.clear();
    FeedBody(f.client, proto::kPakidCoreDeviceIorequest,
             ControlBody(2, 11,
                         static_cast<uint32_t>(
                             proto::ScardIoctl::kEstablishContext),
                         EstablishContextCall(2), 2048));
    for (int i = 0; i < 300 && !f.backend.establish_entered.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const bool entered = f.backend.establish_entered.load();
    // Replace the session while the call is still inside the backend.
    f.client.Reset();
    f.backend.establish_release = true;
    CHECK(entered);
    for (int i = 0; i < 100; ++i) {
        f.client.PollSmartCard();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    // The in-flight answer belongs to the old session and must be dropped.
    CHECK(FindSent(f.sent, proto::kPakidCoreDeviceIocompletion) == nullptr);
    f.client.SetAsyncSmartCard(false);
}

RTSC_TEST(smartcard_sync_mode_resumes_after_async) {
    ScardFixture f;
    f.client.SetAsyncSmartCard(true);
    f.client.SetAsyncSmartCard(false);
    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kEstablishContext),
                   EstablishContextCall(2), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
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

RTSC_TEST(smartcard_connect_w_forwards_wide_reader) {
    ScardFixture f;
    // ConnectW_Call ([MS-RDPESC] 2.2.2.14): szReader ptr, Context, ShareMode,
    // PreferredProtocols; referents: wide reader [string], context bytes.
    const std::u16string wide_reader = u"Reader 0";
    const std::vector<uint8_t> reader = {
        'R', 0, 'e', 0, 'a', 0, 'd', 0, 'e', 0, 'r', 0, ' ', 0, '0', 0, 0, 0};
    std::vector<uint8_t> call = Concat({
        Le32(0x00020000),           // szReader full pointer
        Le32(4), Le32(0x00020004),  // Context{cb=4, ptr}
        Le32(rtsc::smartcard::kScardShareShared),
        Le32(rtsc::smartcard::kScardProtocolT0 |
             rtsc::smartcard::kScardProtocolT1),
        Le32(9), Le32(0), Le32(9),  // Length, Offset, ActualCount (chars)
    });
    call.insert(call.end(), reader.begin(), reader.end());
    while (call.size() % 4 != 0) call.push_back(0);
    call = Concat({call, Le32(4), Le32(0x0BADF00D)});

    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kConnectW),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK(f.backend.connect_w_reader == wide_reader);
    CHECK_EQ(f.backend.connect_w_share, rtsc::smartcard::kScardShareShared);
    CHECK_EQ(f.backend.connect_w_protocols,
             rtsc::smartcard::kScardProtocolT0 |
                 rtsc::smartcard::kScardProtocolT1);
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

RTSC_TEST(smartcard_list_reader_groups_w_returns_wide_multistring) {
    ScardFixture f;
    // ListReaderGroups_Call ([MS-RDPESC] 2.2.2.3): Context,
    // fmszGroupsIsNULL, cchGroups; referent: context bytes.
    const std::vector<uint8_t> call = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(1),                    // fmszGroupsIsNULL = 1 (probe)
        Le32(0),                    // cchGroups
        Le32(4), Le32(0x0BADF00D),  // context referent
    });
    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(
                       proto::ScardIoctl::kListReaderGroupsW),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 44);
    if (payload.size() < 44) return;
    CHECK_EQ(U32At(payload, 16), 0u);   // ReturnCode
    CHECK_EQ(U32At(payload, 20), 10u);  // cBytes = "Grp\0\0" wide
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    CHECK_EQ(U32At(payload, 28), 10u);  // referent Length
    const std::vector<uint8_t> wide(payload.begin() + 32,
                                    payload.begin() + 42);
    CHECK(wide == std::vector<uint8_t>({'G', 0, 'r', 0, 'p', 0, 0, 0, 0, 0}));

    f.backend.list_status_w = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(
                       proto::ScardIoctl::kListReaderGroupsW),
                   Wrap(call), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 24);
    if (failed_payload.size() < 24) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
    CHECK_EQ(U32At(failed_payload, 24), 0u);
}

RTSC_TEST(smartcard_list_readers_w_returns_wide_multistring) {
    ScardFixture f;
    // ListReadersW_Call ([MS-RDPESC] 2.2.2.7) has the same wire form as
    // ListReadersA_Call; mszGroups is a UTF-16LE multistring.
    const std::vector<uint8_t> wide_groups = {
        'R', 0, 'e', 0, 'a', 0, 'd', 0, 'e', 0, 'r', 0, 's', 0, 0, 0};
    const std::vector<uint8_t> call = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(static_cast<uint32_t>(wide_groups.size())),
        Le32(0x00020004),           // mszGroups ptr
        Le32(1),                    // fmszReadersIsNULL = 1 (probe)
        Le32(0),                    // cchReaders = 0
        Le32(4), Le32(0x0BADF00D),  // context referent
        Le32(static_cast<uint32_t>(wide_groups.size())), wide_groups,
    });
    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kListReadersW),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK(f.backend.groups_seen_w == wide_groups);
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 20);
    if (payload.size() < 20) return;
    CHECK_EQ(U32At(payload, 16), 0u);   // ReturnCode
    CHECK_EQ(U32At(payload, 20), 10u);  // cBytes = "R\0" + "0\0" + "\0\0"
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    CHECK(payload.size() >= 44);
    if (payload.size() < 44) return;
    CHECK_EQ(U32At(payload, 28), 10u);  // referent Length
    const std::vector<uint8_t> wide(payload.begin() + 32, payload.begin() + 42);
    CHECK(wide == std::vector<uint8_t>({'R', 0, 0, 0, '0', 0, 0, 0, 0, 0}));

    // Failure: cBytes is zeroed and the pointer is NULL.
    f.backend.list_status_w = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kListReadersW),
                   Wrap(call), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 24);
    if (failed_payload.size() < 24) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
    CHECK_EQ(U32At(failed_payload, 24), 0u);
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

RTSC_TEST(smartcard_get_status_change_timeout_keeps_states) {
    ScardFixture f;
    // Same call as above; the backend reports SCARD_E_TIMEOUT after filling
    // the states. The return must keep cReaders so the server sees them
    // (FreeRDP smartcard_pack_get_status_change_return).
    const std::string reader = "R0";
    std::vector<uint8_t> call = Concat({
        Le32(4), Le32(0x00020000),
        Le32(500),
        Le32(1),
        Le32(0x00020004),
        Le32(4), Le32(0x0BADF00D),
        Le32(1),
        Le32(0x00020008),
        Le32(rtsc::smartcard::kScardStateUnaware), Le32(0), Le32(0),
    });
    for (int i = 0; i < 36; ++i) call.push_back(0);
    call = Concat({call, Le32(3), Le32(0), Le32(3)});
    call.insert(call.end(), reader.begin(), reader.end());
    call.push_back(0);
    while (call.size() % 4 != 0) call.push_back(0);
    f.backend.get_status_change_status = rtsc::smartcard::kScardETimeout;

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetStatusChangeA),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 24);
    if (payload.size() < 24) return;
    CHECK_EQ(U32At(payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardETimeout));
    CHECK_EQ(U32At(payload, 20), 1u);  // cReaders kept on timeout
    if (payload.size() >= 44) {
        CHECK_EQ(U32At(payload, 36),
                 static_cast<uint32_t>(rtsc::smartcard::kScardStatePresent));
    }
}

RTSC_TEST(smartcard_get_status_change_w_round_trip) {
    ScardFixture f;
    // GetStatusChangeW_Call ([MS-RDPESC] 2.2.2.12) has the same wire form as
    // GetStatusChangeA_Call; the reader name is a UTF-16LE [string].
    const std::vector<uint8_t> wide_reader = {'R', 0, '0', 0, 0, 0};
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
    call = Concat({call, Le32(3), Le32(0), Le32(3)});
    call.insert(call.end(), wide_reader.begin(), wide_reader.end());
    while (call.size() % 4 != 0) call.push_back(0);

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetStatusChangeW),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.timeout_seen_w, 500u);
    CHECK(f.backend.names_seen_w == std::vector<std::u16string>{u"R0"});
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 24);
    if (payload.size() < 24) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 1u);  // cReaders
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    if (payload.size() >= 44) {
        CHECK_EQ(U32At(payload, 36),
                 static_cast<uint32_t>(rtsc::smartcard::kScardStatePresent));
    }
}

RTSC_TEST(smartcard_locate_cards_w_round_trip) {
    ScardFixture f;
    // LocateCardsW_Call ([MS-RDPESC] 2.2.2.10): Context, cBytes, mszCards ptr,
    // cReaders, rgReaderStates ptr; mszCards and reader names are UTF-16LE.
    const std::vector<uint8_t> wide_cards = {
        'C', 0, 'a', 0, 'r', 0, 'd', 0, 'A', 0, 0, 0, 0, 0};
    const std::vector<uint8_t> wide_reader = {'R', 0, '0', 0, 0, 0};
    std::vector<uint8_t> call = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(static_cast<uint32_t>(wide_cards.size())),  // cBytes
        Le32(0x00020004),           // mszCards ptr
        Le32(1),                    // cReaders
        Le32(0x00020008),           // rgReaderStates ptr
        Le32(4), Le32(0x0BADF00D),  // context referent
        Le32(static_cast<uint32_t>(wide_cards.size())), wide_cards,
    });
    while (call.size() % 4 != 0) call.push_back(0);
    call = Concat({call, Le32(1), Le32(0x0002000C),
                   Le32(rtsc::smartcard::kScardStateUnaware), Le32(0),
                   Le32(0)});
    for (int i = 0; i < 36; ++i) call.push_back(0);
    call = Concat({call, Le32(3), Le32(0), Le32(3)});
    call.insert(call.end(), wide_reader.begin(), wide_reader.end());
    while (call.size() % 4 != 0) call.push_back(0);

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kLocateCardsW),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK(f.backend.locate_cards_w == wide_cards);
    CHECK(f.backend.locate_readers_w ==
          std::vector<std::u16string>{u"R0"});
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 24);
    if (payload.size() < 24) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 1u);  // cReaders
    if (payload.size() >= 44) {
        CHECK_EQ(U32At(payload, 36),
                 static_cast<uint32_t>(rtsc::smartcard::kScardStatePresent));
    }
}

RTSC_TEST(smartcard_locate_cards_round_trip) {
    ScardFixture f;
    // LocateCardsA_Call ([MS-RDPESC] 2.2.2.9): Context, cBytes, mszCards ptr,
    // cReaders, rgReaderStates ptr; referents: context, cards multistring,
    // MaxCount + ReaderStateA[], then the reader name string.
    const std::string reader = "R0";
    const std::string cards = std::string("CardA") + '\0' + '\0';
    std::vector<uint8_t> call = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(static_cast<uint32_t>(cards.size())),  // cBytes
        Le32(0x00020004),           // mszCards ptr
        Le32(1),                    // cReaders
        Le32(0x00020008),           // rgReaderStates ptr
        Le32(4), Le32(0x0BADF00D),  // context referent
        Le32(static_cast<uint32_t>(cards.size())),
        std::vector<uint8_t>(cards.begin(), cards.end()),
        std::vector<uint8_t>{0},  // pad to 4
        Le32(1),                  // array MaxCount
        Le32(0x0002000C),         // szReader full pointer
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
                   static_cast<uint32_t>(proto::ScardIoctl::kLocateCardsA),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.locate_calls, 1u);
    CHECK(f.backend.locate_context ==
          std::vector<uint8_t>({0x0D, 0xF0, 0xAD, 0x0B}));
    CHECK(f.backend.locate_cards ==
          std::vector<uint8_t>(cards.begin(), cards.end()));
    CHECK(f.backend.locate_readers.size() == size_t{1});
    if (f.backend.locate_readers.size() == 1) {
        CHECK(f.backend.locate_readers[0] == "R0");
    }
    // LocateCards_Return: ReturnCode, cReaders, array ptr, referent.
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 48);
    if (payload.size() < 48) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 1u);  // cReaders
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    CHECK_EQ(U32At(payload, 32),
             static_cast<uint32_t>(rtsc::smartcard::kScardStateUnaware));
    CHECK_EQ(U32At(payload, 36),
             static_cast<uint32_t>(rtsc::smartcard::kScardStatePresent));
    CHECK_EQ(U32At(payload, 40), 2u);  // cbAtr
    CHECK_EQ(payload[44], static_cast<uint8_t>(0x3B));
    CHECK_EQ(payload[45], static_cast<uint8_t>(0x00));

    // Failure: the status rides in ReturnCode and the state array is dropped.
    f.backend.locate_status = rtsc::smartcard::kScardEUnknownReader;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kLocateCardsA),
                   Wrap(call), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 28);
    if (failed_payload.size() < 28) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEUnknownReader));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
    CHECK_EQ(U32At(failed_payload, 24), 0u);
}

RTSC_TEST(smartcard_read_cache_round_trip) {
    ScardFixture f;
    // ReadCacheA_Call ([MS-RDPESC] 2.2.2.25): szLookupName ptr first, then
    // Context, UUID ptr, FreshnessCounter, fPbDataIsNULL, cbDataLen;
    // referents: lookup name, context bytes, 16-byte UUID.
    const std::vector<uint8_t> uuid = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    std::vector<uint8_t> call = Concat({
        Le32(0x00020000),           // szLookupName ptr
        Le32(4), Le32(0x00020004),  // Context
        Le32(0x00020008),           // CardIdentifier ptr
        Le32(7),                    // FreshnessCounter
        Le32(0),                    // fPbDataIsNULL
        Le32(16),                   // cbDataLen
        Le32(4), Le32(0), Le32(4),  // "Key\0" [string]
        std::vector<uint8_t>{'K', 'e', 'y', 0},
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},  // context referent
        uuid,
    });
    f.backend.read_cache_data = {0x10, 0x20, 0x30};

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kReadCacheA),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.read_cache_calls, 1u);
    CHECK_EQ(f.backend.read_cache_freshness, 7u);
    CHECK(f.backend.read_cache_lookup == "Key");
    CHECK(f.backend.read_cache_card_id == uuid);
    CHECK(f.backend.read_cache_context ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(!f.backend.read_cache_length_only);
    CHECK_EQ(f.backend.read_cache_capacity, 16u);
    // ReadCache_Return: ReturnCode, cbDataLen, data ptr, referent.
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 36);
    if (payload.size() < 36) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 3u);
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    CHECK_EQ(U32At(payload, 28), 3u);
    CHECK_EQ(payload[32], static_cast<uint8_t>(0x10));
    CHECK_EQ(payload[34], static_cast<uint8_t>(0x30));

    // Length probe: fPbDataIsNULL=1 answers cbDataLen with a NULL pointer.
    std::vector<uint8_t> probe = call;
    probe[20] = 1;  // fPbDataIsNULL (after name ptr + context + uuid ptr +
                    // freshness)
    const std::vector<uint8_t> probe_rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kReadCacheA),
                   Wrap(probe), 2048, f.sent);
    CHECK(probe_rsp.size() >= 16);
    if (probe_rsp.size() < 16) return;
    CHECK_EQ(U32At(probe_rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK(f.backend.read_cache_length_only);
    const std::vector<uint8_t> probe_payload(probe_rsp.begin() + 16,
                                             probe_rsp.end());
    CHECK(probe_payload.size() >= 28);
    if (probe_payload.size() < 28) return;
    CHECK_EQ(U32At(probe_payload, 16), 0u);
    CHECK_EQ(U32At(probe_payload, 20), 3u);
    CHECK_EQ(U32At(probe_payload, 24), 0u);  // NULL pbData

    // Failure: the cache status rides in ReturnCode, data is dropped.
    f.backend.read_cache_status = rtsc::smartcard::kScardWCacheItemNotFound;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kReadCacheA),
                   Wrap(call), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 28);
    if (failed_payload.size() < 28) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardWCacheItemNotFound));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
    CHECK_EQ(U32At(failed_payload, 24), 0u);
}

RTSC_TEST(smartcard_read_cache_w_round_trip) {
    ScardFixture f;
    // ReadCacheW_Call ([MS-RDPESC] 2.2.2.26) is ReadCacheA_Call with a UTF-16LE
    // szLookupName.
    const std::vector<uint8_t> uuid = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    const std::vector<uint8_t> wide_name = {'K', 0, 'e', 0, 'y', 0, 0, 0};
    std::vector<uint8_t> call = Concat({
        Le32(0x00020000),           // szLookupName ptr
        Le32(4), Le32(0x00020004),  // Context
        Le32(0x00020008),           // CardIdentifier ptr
        Le32(7),                    // FreshnessCounter
        Le32(0),                    // fPbDataIsNULL
        Le32(16),                   // cbDataLen
        Le32(4), Le32(0), Le32(4),  // "Key\0" wide [string]
        wide_name,
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},  // context
        uuid,
    });
    f.backend.read_cache_data_w = {0x10, 0x20, 0x30};

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kReadCacheW),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.read_cache_calls_w, 1u);
    CHECK_EQ(f.backend.read_cache_freshness_w, 7u);
    CHECK(f.backend.read_cache_lookup_w == u"Key");
    CHECK(f.backend.read_cache_card_id_w == uuid);
    CHECK(f.backend.read_cache_context_w ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(!f.backend.read_cache_length_only_w);
    CHECK_EQ(f.backend.read_cache_capacity_w, 16u);
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 36);
    if (payload.size() < 36) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 3u);
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    CHECK_EQ(U32At(payload, 28), 3u);
}

RTSC_TEST(smartcard_write_cache_round_trip) {
    ScardFixture f;
    // WriteCacheA_Call ([MS-RDPESC] 2.2.2.27): szLookupName ptr, Context,
    // UUID ptr, FreshnessCounter, cbDataLen, pbData ptr; referents: name,
    // context, 16-byte UUID, data.
    const std::vector<uint8_t> uuid = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),           // szLookupName ptr
        Le32(4), Le32(0x00020004),  // Context
        Le32(0x00020008),           // CardIdentifier ptr
        Le32(9),                    // FreshnessCounter
        Le32(3),                    // cbDataLen
        Le32(0x0002000C),           // pbData ptr
        Le32(4), Le32(0), Le32(4),  // "Key\0" [string]
        std::vector<uint8_t>{'K', 'e', 'y', 0},
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
        uuid,
        Le32(3), std::vector<uint8_t>{0x10, 0x20, 0x30}, std::vector<uint8_t>{0},
    });

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kWriteCacheA),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.write_cache_calls, 1u);
    CHECK_EQ(f.backend.write_cache_freshness, 9u);
    CHECK(f.backend.write_cache_lookup == "Key");
    CHECK(f.backend.write_cache_card_id == uuid);
    CHECK(f.backend.write_cache_context ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(f.backend.write_cache_data ==
          std::vector<uint8_t>({0x10, 0x20, 0x30}));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 20);
    if (payload.size() < 20) return;
    CHECK_EQ(U32At(payload, 16), 0u);  // Long_Return Result

    // Failure: the smart card status rides in ReturnCode.
    f.backend.write_cache_status = rtsc::smartcard::kScardEInvalidParameter;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kWriteCacheA),
                   Wrap(body), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 20);
    if (failed_payload.size() < 20) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidParameter));
}

RTSC_TEST(smartcard_write_cache_w_round_trip) {
    ScardFixture f;
    // WriteCacheW_Call ([MS-RDPESC] 2.2.2.28) is WriteCacheA_Call with a
    // UTF-16LE szLookupName.
    const std::vector<uint8_t> uuid = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    const std::vector<uint8_t> wide_name = {'K', 0, 'e', 0, 'y', 0, 0, 0};
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),           // szLookupName ptr
        Le32(4), Le32(0x00020004),  // Context
        Le32(0x00020008),           // CardIdentifier ptr
        Le32(9),                    // FreshnessCounter
        Le32(3),                    // cbDataLen
        Le32(0x0002000C),           // pbData ptr
        Le32(4), Le32(0), Le32(4),  // "Key\0" wide [string]
        wide_name,
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
        uuid,
        Le32(3), std::vector<uint8_t>{0x10, 0x20, 0x30},
        std::vector<uint8_t>{0},
    });

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kWriteCacheW),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.write_cache_calls_w, 1u);
    CHECK_EQ(f.backend.write_cache_freshness_w, 9u);
    CHECK(f.backend.write_cache_lookup_w == u"Key");
    CHECK(f.backend.write_cache_card_id_w == uuid);
    CHECK(f.backend.write_cache_context_w ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(f.backend.write_cache_data_w ==
          std::vector<uint8_t>({0x10, 0x20, 0x30}));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 20);
    if (payload.size() < 20) return;
    CHECK_EQ(U32At(payload, 16), 0u);  // Long_Return Result

    f.backend.write_cache_status_w = rtsc::smartcard::kScardEInvalidParameter;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kWriteCacheW),
                   Wrap(body), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 20);
    if (failed_payload.size() < 20) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidParameter));
}

RTSC_TEST(smartcard_get_reader_icon_round_trip) {
    ScardFixture f;
    // GetReaderIcon_Call ([MS-RDPESC] 2.2.2.31): Context, szReaderName ptr;
    // referents: context bytes, UTF-16LE [string] "R0".
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(0x00020004),           // szReaderName ptr
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
        Le32(3), Le32(0), Le32(3),  // "R0\0" in UTF-16 code units
        std::vector<uint8_t>{'R', 0, '0', 0, 0, 0},
        std::vector<uint8_t>{0, 0},  // pad to 4
    });
    f.backend.reader_icon_data = {0x89, 0x50, 0x4E, 0x47};

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetReaderIcon),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.reader_icon_calls, 1u);
    CHECK(f.backend.reader_icon_context ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(f.backend.reader_icon_name == u"R0");
    // GetReaderIcon_Return: ReturnCode, cbDataLen, data ptr, referent.
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 36);
    if (payload.size() < 36) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 4u);
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    CHECK_EQ(U32At(payload, 28), 4u);
    CHECK_EQ(payload[32], static_cast<uint8_t>(0x89));
    CHECK_EQ(payload[35], static_cast<uint8_t>(0x47));

    // Failure: the smart card status rides in ReturnCode, data is dropped.
    f.backend.reader_icon_status = rtsc::smartcard::kScardEUnknownReader;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetReaderIcon),
                   Wrap(body), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 28);
    if (failed_payload.size() < 28) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEUnknownReader));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
    CHECK_EQ(U32At(failed_payload, 24), 0u);
}

RTSC_TEST(smartcard_get_device_type_id_round_trip) {
    ScardFixture f;
    // GetDeviceTypeId_Call ([MS-RDPESC] 2.2.2.32): Context, szReaderName ptr;
    // same wire form as GetReaderIcon_Call.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(0x00020004),
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
        Le32(3), Le32(0), Le32(3),
        std::vector<uint8_t>{'R', 0, '0', 0, 0, 0},
        std::vector<uint8_t>{0, 0},
    });
    f.backend.device_type_id_value = 0x0000000A;

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetDeviceTypeId),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.device_type_calls, 1u);
    CHECK(f.backend.device_type_context ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(f.backend.device_type_name == u"R0");
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 24);
    if (payload.size() < 24) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 0x0000000Au);

    // Failure: dwDeviceId is still written (0) after the nonzero ReturnCode.
    f.backend.device_type_status = rtsc::smartcard::kScardEUnknownReader;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetDeviceTypeId),
                   Wrap(body), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 24);
    if (failed_payload.size() < 24) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEUnknownReader));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
}

RTSC_TEST(smartcard_get_transmit_count_round_trip) {
    ScardFixture f;
    // GetTransmitCount_Call ([MS-RDPESC] 2.2.2.29): REDIR_SCARDHANDLE
    // (context + handle); referents: context bytes, handle bytes.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(4), Le32(0x00020004),  // cbHandle + pbHandle ptr
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
        Le32(4), std::vector<uint8_t>{0x11, 0x22, 0x33, 0x44},
    });
    f.backend.transmit_count_value = 42;

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetTransmitCount),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.transmit_count_calls, 1u);
    CHECK(f.backend.transmit_count_context ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(f.backend.transmit_count_handle ==
          std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 24);
    if (payload.size() < 24) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 42u);

    // Failure: cTransmitCount is still written (0) after the ReturnCode.
    f.backend.transmit_count_status = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kGetTransmitCount),
                   Wrap(body), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 24);
    if (failed_payload.size() < 24) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
}

RTSC_TEST(smartcard_locate_cards_by_atr_round_trip) {
    ScardFixture f;
    // LocateCardsByATRA_Call ([MS-RDPESC] 2.2.2.23): Context, cAtrs,
    // rgAtrMasks ptr, cReaders, rgReaderStates ptr; referents: context,
    // ATR mask array (Length + 76-byte elements), ReaderStateA array.
    const std::string reader = "R0";
    std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(1),                    // cAtrs
        Le32(0x00020004),           // rgAtrMasks ptr
        Le32(1),                    // cReaders
        Le32(0x00020008),           // rgReaderStates ptr
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
        Le32(1),  // mask array Length (element count)
        Le32(2),  // cbAtr
        std::vector<uint8_t>{0x3B, 0x00}, Zeros(34),  // rgbAtr[36]
        std::vector<uint8_t>{0xFF, 0xFF}, Zeros(34),  // rgbMask[36]
        Le32(1),                                      // states MaxCount
        Le32(0x0002000C),                             // szReader ptr
        Le32(0), Le32(0), Le32(0),                    // current/event/cbAtr
    });
    for (int i = 0; i < 36; ++i) body.push_back(0);
    body = Concat({body, Le32(static_cast<uint32_t>(reader.size()) + 1),
                   Le32(0), Le32(static_cast<uint32_t>(reader.size()) + 1)});
    body.insert(body.end(), reader.begin(), reader.end());
    body.push_back(0);
    while (body.size() % 4 != 0) body.push_back(0);

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(
                       proto::ScardIoctl::kLocateCardsByAtrA),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.locate_atr_calls, 1u);
    CHECK(f.backend.locate_atr_context ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK_EQ(f.backend.locate_atr_masks.size(), size_t{1});
    if (f.backend.locate_atr_masks.size() == 1) {
        CHECK(f.backend.locate_atr_masks[0].atr ==
              std::vector<uint8_t>({0x3B, 0x00}));
        CHECK(f.backend.locate_atr_masks[0].mask ==
              std::vector<uint8_t>({0xFF, 0xFF}));
    }
    CHECK(f.backend.locate_atr_readers.size() == size_t{1});
    if (f.backend.locate_atr_readers.size() == 1) {
        CHECK(f.backend.locate_atr_readers[0] == "R0");
    }
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 48);
    if (payload.size() < 48) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 1u);
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    CHECK_EQ(U32At(payload, 36),
             static_cast<uint32_t>(rtsc::smartcard::kScardStateAtrMatch));
    CHECK_EQ(U32At(payload, 40), 2u);
    CHECK_EQ(payload[44], static_cast<uint8_t>(0x3B));

    // Failure: the status rides in ReturnCode and the state array is dropped.
    f.backend.locate_atr_status = rtsc::smartcard::kScardEUnknownReader;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(
                       proto::ScardIoctl::kLocateCardsByAtrA),
                   Wrap(body), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 28);
    if (failed_payload.size() < 28) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEUnknownReader));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
    CHECK_EQ(U32At(failed_payload, 24), 0u);
}

RTSC_TEST(smartcard_locate_cards_by_atr_w_round_trip) {
    ScardFixture f;
    // LocateCardsByATRW_Call ([MS-RDPESC] 2.2.2.24) has the same wire shape as
    // the A variant; the reader name is a UTF-16LE [string].
    const std::vector<uint8_t> wide_reader = {'R', 0, '0', 0, 0, 0};
    std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(1),                    // cAtrs
        Le32(0x00020004),           // rgAtrMasks ptr
        Le32(1),                    // cReaders
        Le32(0x00020008),           // rgReaderStates ptr
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
        Le32(1),  // mask array Length (element count)
        Le32(2),  // cbAtr
        std::vector<uint8_t>{0x3B, 0x00}, Zeros(34),  // rgbAtr[36]
        std::vector<uint8_t>{0xFF, 0xFF}, Zeros(34),  // rgbMask[36]
        Le32(1),                                      // states MaxCount
        Le32(0x0002000C),                             // szReader ptr
        Le32(0), Le32(0), Le32(0),                    // current/event/cbAtr
    });
    for (int i = 0; i < 36; ++i) body.push_back(0);
    body = Concat({body, Le32(3), Le32(0), Le32(3)});
    body.insert(body.end(), wide_reader.begin(), wide_reader.end());
    while (body.size() % 4 != 0) body.push_back(0);

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(
                       proto::ScardIoctl::kLocateCardsByAtrW),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.locate_atr_calls_w, 1u);
    CHECK_EQ(f.backend.locate_atr_masks_w.size(), size_t{1});
    if (f.backend.locate_atr_masks_w.size() == 1) {
        CHECK(f.backend.locate_atr_masks_w[0].atr ==
              std::vector<uint8_t>({0x3B, 0x00}));
        CHECK(f.backend.locate_atr_masks_w[0].mask ==
              std::vector<uint8_t>({0xFF, 0xFF}));
    }
    CHECK(f.backend.locate_atr_readers_w ==
          std::vector<std::u16string>{u"R0"});
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 24);
    if (payload.size() < 24) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 1u);  // cReaders
    if (payload.size() >= 44) {
        CHECK_EQ(U32At(payload, 36),
                 static_cast<uint32_t>(
                     rtsc::smartcard::kScardStateAtrMatch));
    }
}

RTSC_TEST(smartcard_access_started_event_round_trip) {
    ScardFixture f;
    // ScardAccessStartedEvent_Call ([MS-RDPESC] 2.2.2.30) is a bare 4-byte
    // buffer, not an NDR structure; the contents are ignored.
    const std::vector<uint8_t> call = {0xDE, 0xAD, 0xBE, 0xEF};
    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(
                       proto::ScardIoctl::kAccessStartedEvent),
                   call, 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.access_started_calls, 1u);
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 20);
    if (payload.size() < 20) return;
    CHECK_EQ(U32At(payload, 16), 0u);  // Long_Return Result

    // Failure: the service status rides in ReturnCode.
    f.backend.access_started_status = rtsc::smartcard::kScardENoService;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(
                       proto::ScardIoctl::kAccessStartedEvent),
                   call, 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 20);
    if (failed_payload.size() < 20) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardENoService));
}

RTSC_TEST(smartcard_cancel_round_trip) {
    ScardFixture f;
    // Context_Call ([MS-RDPESC] 2.2.2.2): context only.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
    });
    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kCancel),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.cancel_calls, 1u);
    CHECK(f.backend.cancel_context ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 20);
    if (payload.size() < 20) return;
    CHECK_EQ(U32At(payload, 16), 0u);  // Long_Return Result

    // Failure: the smart card status rides in ReturnCode.
    f.backend.cancel_status = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kCancel),
                   Wrap(body), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 20);
    if (failed_payload.size() < 20) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
}

RTSC_TEST(smartcard_state_round_trip) {
    ScardFixture f;
    // State_Call ([MS-RDPESC] 2.2.2.17): REDIR_SCARDHANDLE, fpbAtrIsNULL,
    // cbAtrLen; referents: context, handle.
    std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(4), Le32(0x00020004),  // cbHandle + pbHandle ptr
        Le32(0),                    // fpbAtrIsNULL
        Le32(36),                   // cbAtrLen
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
        Le32(4), std::vector<uint8_t>{0x11, 0x22, 0x33, 0x44},
    });
    f.backend.state_value = 0x34;
    f.backend.protocol_value = 2;
    f.backend.state_atr = {0x3B, 0x00};

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kState),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.state_calls, 1u);
    CHECK(f.backend.state_context ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(f.backend.state_handle ==
          std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 44);
    if (payload.size() < 44) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 0x34u);
    CHECK_EQ(U32At(payload, 24), 2u);
    CHECK_EQ(U32At(payload, 28), 2u);
    CHECK_EQ(U32At(payload, 32), 0x00020000u);
    CHECK_EQ(U32At(payload, 36), 2u);
    CHECK_EQ(payload[40], static_cast<uint8_t>(0x3B));

    // Probe: fpbAtrIsNULL=1 answers cbAtrLen with a NULL rgAtr.
    std::vector<uint8_t> probe = body;
    probe[16] = 1;
    const std::vector<uint8_t> probe_rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kState),
                   Wrap(probe), 2048, f.sent);
    CHECK(probe_rsp.size() >= 16);
    if (probe_rsp.size() < 16) return;
    const std::vector<uint8_t> probe_payload(probe_rsp.begin() + 16,
                                             probe_rsp.end());
    CHECK(probe_payload.size() >= 32);
    if (probe_payload.size() < 32) return;
    CHECK_EQ(U32At(probe_payload, 16), 0u);
    CHECK_EQ(U32At(probe_payload, 28), 2u);
    CHECK_EQ(U32At(probe_payload, 32), 0u);

    // fpbAtrIsNULL=0 with cbAtrLen=0 also succeeds with length + NULL.
    std::vector<uint8_t> empty = body;
    empty[20] = 0;
    empty[21] = 0;
    empty[22] = 0;
    empty[23] = 0;
    const std::vector<uint8_t> empty_rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kState),
                   Wrap(empty), 2048, f.sent);
    CHECK(empty_rsp.size() >= 16);
    if (empty_rsp.size() < 16) return;
    const std::vector<uint8_t> empty_payload(empty_rsp.begin() + 16,
                                             empty_rsp.end());
    CHECK(empty_payload.size() >= 32);
    if (empty_payload.size() < 32) return;
    CHECK_EQ(U32At(empty_payload, 16), 0u);
    CHECK_EQ(U32At(empty_payload, 28), 2u);
    CHECK_EQ(U32At(empty_payload, 32), 0u);

    // Insufficient buffer: capacity 1 < ATR length 2.
    std::vector<uint8_t> small = body;
    small[20] = 1;
    small[21] = 0;
    small[22] = 0;
    small[23] = 0;
    const std::vector<uint8_t> small_rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kState),
                   Wrap(small), 2048, f.sent);
    CHECK(small_rsp.size() >= 16);
    if (small_rsp.size() < 16) return;
    const std::vector<uint8_t> small_payload(small_rsp.begin() + 16,
                                             small_rsp.end());
    CHECK(small_payload.size() >= 32);
    if (small_payload.size() < 32) return;
    CHECK_EQ(U32At(small_payload, 16),
             static_cast<uint32_t>(
                 rtsc::smartcard::kScardEInsufficientBuffer));
    CHECK_EQ(U32At(small_payload, 28), 0u);
    CHECK_EQ(U32At(small_payload, 32), 0u);

    // Failure: the smart card status rides in ReturnCode.
    f.backend.state_status = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kState),
                   Wrap(body), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 32);
    if (failed_payload.size() < 32) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
    CHECK_EQ(U32At(failed_payload, 28), 0u);
    CHECK_EQ(U32At(failed_payload, 32), 0u);
}

RTSC_TEST(smartcard_reconnect_round_trip) {
    ScardFixture f;
    // Reconnect_Call ([MS-RDPESC] 2.2.2.15): REDIR_SCARDHANDLE, dwShareMode,
    // dwPreferredProtocols, dwInitialization; referents: context, handle.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(2),  // dwShareMode = SCARD_SHARE_SHARED
        Le32(3),  // dwPreferredProtocols = T0|T1
        Le32(1),  // dwInitialization = SCARD_RESET_CARD
        Le32(4), std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
        Le32(4), std::vector<uint8_t>{0x11, 0x22, 0x33, 0x44},
    });
    f.backend.reconnect_active = 3;

    const std::vector<uint8_t> rsp =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kReconnect),
                   Wrap(body), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(f.backend.reconnect_calls, 1u);
    CHECK(f.backend.reconnect_context ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(f.backend.reconnect_handle ==
          std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
    CHECK_EQ(f.backend.reconnect_share, 2u);
    CHECK_EQ(f.backend.reconnect_preferred, 3u);
    CHECK_EQ(f.backend.reconnect_initialization, 1u);
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 24);
    if (payload.size() < 24) return;
    CHECK_EQ(U32At(payload, 16), 0u);
    CHECK_EQ(U32At(payload, 20), 3u);

    // Failure: dwActiveProtocol is still written (0) after the ReturnCode.
    f.backend.reconnect_status = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> failed =
        RunControl(f.client,
                   static_cast<uint32_t>(proto::ScardIoctl::kReconnect),
                   Wrap(body), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    CHECK_EQ(U32At(failed, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 24);
    if (failed_payload.size() < 24) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
}

RTSC_TEST(smartcard_status_w_round_trip) {
    ScardFixture f;
    // Status_Call ([MS-RDPESC] 2.2.2.18): REDIR_SCARDHANDLE,
    // fmszReaderNamesIsNULL, cchReaderLen, cbAtrLen; referents: context,
    // handle. StatusW uses the same call as StatusA.
    const std::vector<uint8_t> call = Concat({
        Le32(4), Le32(0x00020000),  // Context
        Le32(4), Le32(0x00020004),  // hCard
        Le32(1),                    // fmszReaderNamesIsNULL = 1 (probe)
        Le32(0),                    // cchReaderLen
        Le32(32),                   // cbAtrLen
        Le32(4), Le32(0x0BADF00D),  // context referent
        Le32(4), Le32(0x0BADF00E),  // handle referent
    });
    const std::vector<uint8_t> rsp =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kStatusW),
                   Wrap(call), 2048, f.sent);
    CHECK(!rsp.empty());
    CHECK(rsp.size() >= 16);
    if (rsp.size() < 16) return;
    CHECK_EQ(U32At(rsp, 8), static_cast<uint32_t>(proto::kStatusSuccess));
    const std::vector<uint8_t> payload(rsp.begin() + 16, rsp.end());
    CHECK(payload.size() >= 80);
    if (payload.size() < 80) return;
    CHECK_EQ(U32At(payload, 16), 0u);   // ReturnCode
    CHECK_EQ(U32At(payload, 20), 8u);   // cBytes = "R0\0" + "\0" wide
    CHECK_EQ(U32At(payload, 24), 0x00020000u);
    CHECK_EQ(U32At(payload, 28),
             static_cast<uint32_t>(rtsc::smartcard::kScardStatePresent));
    CHECK_EQ(U32At(payload, 32),
             static_cast<uint32_t>(rtsc::smartcard::kScardProtocolT1));
    CHECK_EQ(static_cast<uint8_t>(payload[36]), 0x3B);
    CHECK_EQ(static_cast<uint8_t>(payload[37]), 0x65);
    CHECK_EQ(U32At(payload, 68), 2u);   // cbAtrLen
    CHECK_EQ(U32At(payload, 72), 8u);   // referent Length
    const std::vector<uint8_t> wide(payload.begin() + 76,
                                    payload.begin() + 84);
    CHECK(wide == std::vector<uint8_t>({'R', 0, '0', 0, 0, 0, 0, 0}));

    // Failure: cBytes is zeroed and the names pointer is NULL.
    f.backend.status_w_status = rtsc::smartcard::kScardEInvalidHandle;
    const std::vector<uint8_t> failed =
        RunControl(f.client, static_cast<uint32_t>(proto::ScardIoctl::kStatusW),
                   Wrap(call), 2048, f.sent);
    CHECK(failed.size() >= 16);
    if (failed.size() < 16) return;
    const std::vector<uint8_t> failed_payload(failed.begin() + 16,
                                              failed.end());
    CHECK(failed_payload.size() >= 24);
    if (failed_payload.size() < 24) return;
    CHECK_EQ(U32At(failed_payload, 16),
             static_cast<uint32_t>(rtsc::smartcard::kScardEInvalidHandle));
    CHECK_EQ(U32At(failed_payload, 20), 0u);
    CHECK_EQ(U32At(failed_payload, 24), 0u);
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
