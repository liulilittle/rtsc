#include "rtsc/proto/connect_machine.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "rtsc/proto/connection_initiation.h"
#include "rtsc/proto/rail.h"
#include "rtsc/proto/rdp_neg.h"

namespace rtsc::proto {

namespace {

// ---- GCC user data blocks -------------------------------------------------

constexpr uint16_t kCsCore = 0xC001;
constexpr uint16_t kCsSecurity = 0xC002;
constexpr uint16_t kCsNetwork = 0xC003;
constexpr uint16_t kCsCluster = 0xC004;
constexpr uint16_t kScCore = 0x0C01;
constexpr uint16_t kScSecurity = 0x0C02;
constexpr uint16_t kScNetwork = 0x0C03;
constexpr uint16_t kScMcsMsgChannel = 0x0C04;

// RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU ([MS-RDPBCGR] 2.2.1.3.2): the client
// understands the Monitor Layout PDU (2.2.12.1).
constexpr uint16_t kRnsUdCsSupportMonitorLayoutPdu = 0x0040;

constexpr uint16_t kSasSequenceDel = 0xAA03;
constexpr uint16_t kPostBeta2ColorDepth = 0xCA01;

// CHANNEL_OPTION_INITIALIZED | ENCRYPT_RDP | COMPRESS_RDP | SHOW_PROTOCOL
constexpr uint32_t kDefaultChannelOptions = 0xC0A00000;

void WriteFixedUtf16(ByteWriter& w, const std::string& utf8, size_t units) {
    size_t written = 0;
    for (size_t i = 0; i < utf8.size() && written < units; ++i) {
        w.u16le(static_cast<uint16_t>(static_cast<uint8_t>(utf8[i])));
        ++written;
    }
    while (written < units) {
        w.u16le(0);
        ++written;
    }
}

// TS_UD_CS_CORE ([MS-RDPBCGR] 2.2.1.3.2), 216 bytes for the fields up to and
// including serverSelectedProtocol.
std::vector<uint8_t> BuildClientCoreData(const ConnectMachine::Config& c,
                                         uint32_t selected_protocol) {
    // With a monitor layout the CS_CORE desktop size is the virtual desktop
    // union, not a single monitor. mstsc does the same.
    uint32_t desktop_width = c.desktop_width;
    uint32_t desktop_height = c.desktop_height;
    if (!c.monitors.empty()) {
        int32_t min_l = 0, min_t = 0, max_r = 0, max_b = 0;
        bool first = true;
        for (const auto& m : c.monitors) {
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
        desktop_width = static_cast<uint32_t>(max_r - min_l + 1);
        desktop_height = static_cast<uint32_t>(max_b - min_t + 1);
    }
    const uint16_t early_capability_flags =
        static_cast<uint16_t>(c.early_capability_flags |
                              (c.support_monitor_layout_pdu
                                   ? kRnsUdCsSupportMonitorLayoutPdu
                                   : 0));

    ByteWriter body;
    body.u32le(0x00080004);  // version: RDP 5.0
    body.u16le(static_cast<uint16_t>(desktop_width));
    body.u16le(static_cast<uint16_t>(desktop_height));
    body.u16le(static_cast<uint16_t>(c.color_depth));
    body.u16le(kSasSequenceDel);
    body.u32le(c.keyboard_layout);
    body.u32le(c.client_build);
    WriteFixedUtf16(body, c.client_name, 16);  // 32 bytes
    body.u32le(4);                             // keyboardType: IBM enhanced 101/102
    body.u32le(0);                             // keyboardSubType
    body.u32le(12);                            // keyboardFunctionKey
    WriteFixedUtf16(body, std::string(), 32);  // imeFileName, 64 bytes
    body.u16le(kPostBeta2ColorDepth);
    body.u16le(1);  // clientProductId
    body.u32le(0);  // serialNumber
    body.u16le(c.high_color_depth);
    body.u16le(c.supported_color_depths);
    body.u16le(early_capability_flags);
    WriteFixedUtf16(body, std::string(), 32);  // clientDigProductId, 64 bytes
    body.u8(static_cast<uint8_t>(c.connection_type));
    body.u8(0);  // pad1octet
    body.u32le(selected_protocol);

    ByteWriter out;
    GccUserData::write_block(out, kCsCore, body.data());
    return out.take();
}

std::vector<uint8_t> BuildClientSecurityData(const ConnectMachine::Config& c) {
    ByteWriter body;
    body.u32le(c.encryption_methods);
    body.u32le(0);  // extEncryptionMethods
    ByteWriter out;
    GccUserData::write_block(out, kCsSecurity, body.data());
    return out.take();
}

std::vector<uint8_t> BuildClientNetworkData(const ConnectMachine::Config& c) {
    ByteWriter body;
    body.u32le(static_cast<uint32_t>(c.channel_names.size()));
    for (const auto& name : c.channel_names) {
        char fixed[8] = {0};
        const size_t n = std::min<size_t>(name.size(), sizeof(fixed));
        std::memcpy(fixed, name.data(), n);
        for (char ch : fixed) body.u8(static_cast<uint8_t>(ch));
        body.u32le(kDefaultChannelOptions);
    }
    ByteWriter out;
    GccUserData::write_block(out, kCsNetwork, body.data());
    return out.take();
}

// Client Cluster Data (TS_UD_CS_CLUSTER, 0xC004). Only emitted for /admin:
// REDIRECTED_SESSIONID_FIELD_VALID (0x00000002) with a zero session id asks the
// server for the console/admin session ([MS-RDPBCGR] 2.2.1.3.5).
std::vector<uint8_t> BuildClientClusterData() {
    ByteWriter body;
    body.u32le(0x00000002);  // REDIRECTED_SESSIONID_FIELD_VALID
    body.u32le(0);           // RedirectedSessionID = 0 => console session
    ByteWriter out;
    GccUserData::write_block(out, kCsCluster, body.data());
    return out.take();
}

// Client Monitor Data (TS_UD_CS_MONITOR, 0xC005). Empty when the client has no
// monitor layout, so a single-monitor client sends no block at all.
std::vector<uint8_t> BuildClientMonitorData(
    const std::vector<MonitorDef>& monitors) {
    ClientMonitorData data;
    data.monitors = monitors;
    return data.encode();
}

void Append(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

// True when the client advertised `name` in its Client Network Data.
bool AdvertisesChannel(const ConnectMachine::Config& c, const char* name) {
    for (const auto& n : c.channel_names) {
        if (n == name) return true;
    }
    return false;
}

}  // namespace

const char* to_string(ConnectPhase p) {
    switch (p) {
        case ConnectPhase::kIdle: return "idle";
        case ConnectPhase::kAwaitNegotiation: return "await-negotiation";
        case ConnectPhase::kAwaitExternalSecurity: return "await-external-security";
        case ConnectPhase::kAwaitConnectResponse: return "await-connect-response";
        case ConnectPhase::kAwaitAttachUser: return "await-attach-user";
        case ConnectPhase::kAwaitChannelJoin: return "await-channel-join";
        case ConnectPhase::kReadyToSendClientInfo: return "ready-to-send-client-info";
        case ConnectPhase::kAwaitClientInfoAck: return "await-client-info-ack";
        case ConnectPhase::kFailed: return "failed";
    }
    return "unknown";
}

ConnectMachine::ConnectMachine(const Config& config, const Credentials& credentials)
    : config_(config), credentials_(credentials) {}

void ConnectMachine::Fail(const char* reason) {
    state_.phase = ConnectPhase::kFailed;
    state_.error = reason;
}

ConnectStep ConnectMachine::Step(ConnectPhase next) {
    state_.phase = next;
    ConnectStep s;
    s.needs_input = true;
    return s;
}

ConnectStep ConnectMachine::Start() {
    X224ConnectionRequest crq;
    crq.cookie = config_.cookie;
    crq.include_neg_req = true;
    crq.neg_req.flags = 0;
    crq.neg_req.requested_protocols = config_.requested_protocols;
    crq.include_correlation_info = config_.include_correlation_info;

    ConnectStep s;
    s.output = crq.encode();
    s.needs_input = false;
    state_.phase = ConnectPhase::kAwaitNegotiation;
    return s;
}

ConnectStep ConnectMachine::SendChannelJoin() {
    ConnectStep s;
    if (state_.join_index >= state_.join_queue.size()) {
        // All channels joined: emit the Client Info PDU.
        ClientInfoPdu pdu;
        pdu.security_flags = sec::kSecInfoPkt;
        // The Client Info PDU itself is always plaintext under Standard RDP
        // Security (only the later licensing/data PDUs carry SEC_ENCRYPT), so
        // the connection machine does not need the RC4 keys. The security
        // layer wraps the post-Client-Info traffic.
        pdu.info.code_page = 0x0409;  // en-US language id (Unicode mode)
        pdu.info.flags = info::kMouse | info::kUnicode | info::kDisableCtrlAltDel |
                         info::kMaximizeShell | info::kLogonNotify |
                         info::kEnableWindowsKey;
        // mstsc-quality image: request ClearType font smoothing and DWM
        // desktop composition ([MS-RDPBCGR] 2.2.5.1.1 performanceFlags).
        // Without the enable bits the server renders aliased text on a
        // non-composited desktop — visibly unlike the physical console.
        pdu.info.has_extended_info = true;
        {
            // mstsc always sends the extended block; the performanceFlags live
            // at the end of its chain (address/dir -> timezone -> sessionId ->
            // performanceFlags). An all-zero TS_TIME_ZONE_PDU means bias 0, so
            // the server runs the session on UTC rather than the client's
            // local timezone; wiring the real local timezone is future work.
            auto& ext = pdu.info.extended_info;
            ext.client_address_family = TsExtendedInfoPacket::kAfInet;
            ext.has_time_zone = true;
            ext.has_session_id = true;
            ext.session_id = 0;
            ext.has_performance_flags = true;
            ext.performance_flags = perf::kEnableFontSmoothing |
                                    perf::kEnableDesktopComposition;
            // Auto-reconnect ([MS-RDPBCGR] 2.2.1.11.1.1.1): the cookie comes
            // from the previous session's Save Session Info PDU. The extended
            // block is chained, so all earlier fields above are already set.
            if (config_.auto_reconnect_cookie.size() ==
                ArcCsPrivatePacket::kWireSize) {
                ext.has_auto_reconnect = true;
                ext.auto_reconnect_cookie.bytes =
                    config_.auto_reconnect_cookie;
            }
        }
        // [MS-RDPBCGR] 2.2.1.11.1.1 INFO_RAIL: the client supports the RAIL
        // (Remote Programs) protocol. It is set when the client advertised the
        // "rail" static virtual channel in the Client Network Data.
        if (AdvertisesChannel(config_, kRailChannelName)) {
            pdu.info.flags |= info::kRail;
        }
        if (credentials_.autologon) pdu.info.flags |= info::kAutoLogon;
        pdu.info.domain = credentials_.domain;
        pdu.info.user_name = credentials_.user_name;
        pdu.info.password = credentials_.password;
        pdu.info.alternate_shell = credentials_.alternate_shell;
        pdu.info.working_dir = credentials_.working_dir;

        const auto user_data = pdu.build();
        s.output = McsSendData::build_request(state_.user_channel_id,
                                              state_.io_channel_id, user_data);
        s.needs_input = true;
        state_.phase = ConnectPhase::kAwaitClientInfoAck;
        return s;
    }

    const uint16_t target = state_.join_queue[state_.join_index];
    s.output = McsChannelJoinRequest::build(state_.user_channel_id, target);
    s.needs_input = true;
    state_.phase = ConnectPhase::kAwaitChannelJoin;
    return s;
}

ConnectStep ConnectMachine::OnData(const uint8_t* data, size_t size) {
    ConnectStep s;
    s.needs_input = true;

    if (state_.phase == ConnectPhase::kFailed) return s;

    switch (state_.phase) {
        case ConnectPhase::kAwaitNegotiation: {
            X224ConnectionConfirm ccf;
            const Status st = X224ConnectionConfirm::parse(data, size, ccf);
            if (st != Status::Ok) {
                Fail("malformed X.224 Connection Confirm");
                s.needs_input = false;
                return s;
            }
            if (ccf.neg_data.kind == RdpNegData::Kind::kFailure) {
                Fail("server rejected the requested protocols (RDP_NEG_FAILURE)");
                s.needs_input = false;
                return s;
            }
            if (ccf.neg_data.kind == RdpNegData::Kind::kResponse) {
                state_.negotiated_protocol = ccf.neg_data.response.selected_protocol;
            } else {
                // No rdpNegData at all: the server selected standard RDP security.
                state_.negotiated_protocol = kProtocolRdp;
            }
            if (state_.negotiated_protocol == kProtocolRdp) {
                return SendConnectInitial();
            }
            // TLS / CredSSP / RDSTLS / RDSAAD must run before MCS.
            return Step(ConnectPhase::kAwaitExternalSecurity);
        }

        case ConnectPhase::kAwaitExternalSecurity:
            // The caller is expected to drive the external handshake and then
            // call OnExternalSecurityComplete(). Anything arriving here is a
            // protocol violation.
            Fail("unexpected data while waiting for the external security handshake");
            s.needs_input = false;
            return s;

        case ConnectPhase::kAwaitConnectResponse: {
            McsConnectResponse rsp;
            const Status st = McsConnectResponse::parse(data, size, rsp);
            if (st != Status::Ok) {
                Fail("malformed MCS Connect Response");
                s.needs_input = false;
                return s;
            }
            state_.server_result = rsp.result;
            if (rsp.result != 0) {
                Fail("MCS Connect Response result is not rt-successful");
                s.needs_input = false;
                return s;
            }

            const auto* net = rsp.user_data.find(kScNetwork);
            if (net == nullptr || net->payload.size() < 4) {
                Fail("Server Network Data missing or truncated");
                s.needs_input = false;
                return s;
            }
            ByteReader nr(net->payload.data(), net->payload.size());
            nr.u16le(state_.io_channel_id);
            uint16_t channel_count = 0;
            nr.u16le(channel_count);
            state_.static_virtual_channels.clear();
            for (uint16_t i = 0; i < channel_count; ++i) {
                uint16_t id = 0;
                if (!nr.u16le(id)) break;
                state_.static_virtual_channels.push_back(id);
            }

            const auto* msg = rsp.user_data.find(kScMcsMsgChannel);
            if (msg != nullptr && msg->payload.size() >= 2) {
                ByteReader mr(msg->payload.data(), msg->payload.size());
                mr.u16le(state_.message_channel_id);
            }

            if (state_.static_virtual_channels.empty()) {
                std::fprintf(stderr, "[GCC] static channels: none\n");
            } else {
                std::fprintf(stderr, "[GCC] static channels:");
                for (uint16_t id : state_.static_virtual_channels)
                    std::fprintf(stderr, " %u", id);
                std::fprintf(stderr, "\n");
            }
            if (const auto* sec = rsp.user_data.find(kScSecurity)) {
                std::fprintf(stderr, "[GCC] server security data len=%zu:",
                             sec->payload.size());
                for (uint8_t b : sec->payload) std::fprintf(stderr, " %02X", b);
                std::fprintf(stderr, "\n");
            }

            // Erect Domain Request then Attach User Request, in that order.
            std::vector<uint8_t> out;
            Append(out, McsErectDomainRequest::build());
            Append(out, McsAttachUserRequest::build());
            s.output = std::move(out);
            state_.phase = ConnectPhase::kAwaitAttachUser;
            return s;
        }

        case ConnectPhase::kAwaitAttachUser: {
            McsAttachUserConfirm cf;
            const Status st = McsAttachUserConfirm::parse(data, size, cf);
            if (st != Status::Ok) {
                Fail("malformed MCS Attach User Confirm");
                s.needs_input = false;
                return s;
            }
            if (cf.result != McsResult::kSuccessful) {
                Fail("MCS Attach User Confirm result is not rt-successful");
                s.needs_input = false;
                return s;
            }
            if (!cf.has_initiator) {
                Fail("MCS Attach User Confirm is missing the initiator field");
                s.needs_input = false;
                return s;
            }
            state_.user_channel_id = cf.initiator;

            state_.join_queue.clear();
            state_.join_queue.push_back(state_.user_channel_id);
            state_.join_queue.push_back(state_.io_channel_id);
            if (state_.message_channel_id != 0) {
                state_.join_queue.push_back(state_.message_channel_id);
            }
            for (uint16_t id : state_.static_virtual_channels) {
                state_.join_queue.push_back(id);
            }
            state_.join_index = 0;
            return SendChannelJoin();
        }

        case ConnectPhase::kAwaitChannelJoin: {
            McsChannelJoinConfirm cf;
            const Status st = McsChannelJoinConfirm::parse(data, size, cf);
            if (st != Status::Ok) {
                Fail("malformed MCS Channel Join Confirm");
                s.needs_input = false;
                return s;
            }
            if (cf.result != McsResult::kSuccessful) {
                Fail("MCS Channel Join Confirm result is not rt-successful");
                s.needs_input = false;
                return s;
            }
            if (!cf.has_channel_id) {
                Fail("MCS Channel Join Confirm is missing the channelId field");
                s.needs_input = false;
                return s;
            }
            const uint16_t expected = state_.join_queue[state_.join_index];
            if (cf.channel_id != expected) {
                Fail("MCS Channel Join Confirm channelId does not match the request");
                s.needs_input = false;
                return s;
            }
            ++state_.join_index;
            return SendChannelJoin();
        }

        case ConnectPhase::kAwaitClientInfoAck:
            // Licensing / Demand Active are handled by higher layers.
            s.output.clear();
            s.needs_input = true;
            return s;

        case ConnectPhase::kIdle:
        case ConnectPhase::kReadyToSendClientInfo:
        case ConnectPhase::kFailed:
            break;
    }
    Fail("unexpected state transition");
    s.needs_input = false;
    return s;
}

ConnectStep ConnectMachine::OnExternalSecurityComplete() {
    if (state_.phase != ConnectPhase::kAwaitExternalSecurity) {
        ConnectStep s;
        s.needs_input = false;
        return s;
    }
    return SendConnectInitial();
}

ConnectStep ConnectMachine::SendConnectInitial() {
    // Compose the GCC user data block list: CORE, SECURITY, NETWORK.
    ByteWriter blocks;
    {
        const auto core = BuildClientCoreData(config_, state_.negotiated_protocol);
        const auto sec = BuildClientSecurityData(config_);
        const auto net = BuildClientNetworkData(config_);
        blocks.bytes(core.data(), core.size());
        blocks.bytes(sec.data(), sec.size());
        blocks.bytes(net.data(), net.size());
        if (config_.admin_session) {
            const auto cluster = BuildClientClusterData();
            blocks.bytes(cluster.data(), cluster.size());
        }
        if (!config_.monitors.empty()) {
            const auto mon = BuildClientMonitorData(config_.monitors);
            blocks.bytes(mon.data(), mon.size());
        }
    }

    GccUserData parsed;
    const Status st = GccUserData::parse(blocks.data().data(), blocks.size(), parsed);
    if (st != Status::Ok) {
        Fail("failed to assemble Client Network Data blocks");
        ConnectStep s;
        s.needs_input = false;
        return s;
    }

    ConnectStep s;
    s.output = McsConnectInitial::build(parsed);
    if (s.output.empty()) {
        Fail("MCS Connect Initial exceeds the PER length limit");
        s.needs_input = false;
        return s;
    }
    s.needs_input = true;
    state_.phase = ConnectPhase::kAwaitConnectResponse;
    return s;
}

bool ApplyClientColorDepth(int bpp, uint16_t& high_color_depth,
                           uint16_t& supported_color_depths,
                           uint16_t& early_capability_flags) {
    uint16_t high = 0;
    uint16_t supported = 0;
    bool want_32 = false;
    switch (bpp) {
        case 4:
            high = 0x0004;  // HIGH_COLOR_4BPP
            break;
        case 8:
            high = 0x0008;  // HIGH_COLOR_8BPP
            break;
        case 15:
            high = 0x000F;  // HIGH_COLOR_15BPP
            supported = 0x0004;
            break;
        case 16:
            high = 0x0010;  // HIGH_COLOR_16BPP
            supported = 0x0002;
            break;
        case 24:
            high = 0x0018;  // HIGH_COLOR_24BPP
            supported = 0x0001;
            break;
        case 32:
            // highColorDepth has no 32 value; request 24 with the explicit
            // "want 32bpp" flag and advertise 24 as the fallback.
            high = 0x0018;
            supported = 0x0009;  // 24bpp | 32bpp
            want_32 = true;
            break;
        default:
            return false;
    }
    high_color_depth = high;
    supported_color_depths = supported;
    if (want_32) {
        early_capability_flags |= 0x0002;  // RNS_UD_CS_WANT_32BPP_SESSION
    } else {
        early_capability_flags &= static_cast<uint16_t>(~0x0002);
    }
    return true;
}

}  // namespace rtsc::proto
