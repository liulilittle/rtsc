// RAIL (Remote Programs Virtual Channel) client handler implementation
// ([MS-RDPERP]).

#include "rtsc/channel/rail_client.h"

#include <algorithm>
#include <utility>

namespace rtsc::channel {

namespace {

using rtsc::proto::ByteReader;
using rtsc::proto::ByteWriter;
using rtsc::proto::RailPdu;
using rtsc::proto::RailPduHeader;
using rtsc::proto::Status;

// TS_RAIL_ORDER_GET_APPID_RESP.ApplicationId is a fixed 520-byte (260 UTF-16
// code units) null-terminated field ([MS-RDPERP] 2.2.2.8.1; FreeRDP's
// RAIL_GET_APPID_RESP_ORDER.applicationId[260]):
// orderLength = 4 (header) + 4 (windowId) + 520 = 528.
constexpr size_t kGetAppIdRespFieldSize = 520;

// The order parsers in rail.h take a complete PDU (header + body), while
// RailChannel hands this handler a header and a body separately. Re-encode the
// two so the typed parsers can read them.
std::vector<uint8_t> FullPdu(const RailPdu& pdu) {
    ByteWriter w;
    pdu.header.write(w);
    w.bytes(pdu.body.data(), pdu.body.size());
    return w.take();
}

// Reads a null-terminated UTF-16LE string from `data`.
std::u16string ReadUtf16Z(const uint8_t* data, size_t size) {
    std::u16string out;
    for (size_t i = 0; i + 1 < size; i += 2) {
        const uint16_t ch = static_cast<uint16_t>(data[i]) |
                            (static_cast<uint16_t>(data[i + 1]) << 8);
        if (ch == 0) break;
        out.push_back(static_cast<char16_t>(ch));
    }
    return out;
}

}  // namespace

RailClient::RailClient() : RailClient(SendFn{}) {}

RailClient::RailClient(SendFn send) : send_(std::move(send)) {
    channel_.SetHandler([this](const RailPdu& pdu) { OnPdu(pdu); });
}

RailClient::~RailClient() = default;

void RailClient::OnChannelData(const uint8_t* data, size_t size) {
    channel_.OnChannelData(data, size);
}

void RailClient::OnPdu(const RailPdu& pdu) {
    const uint16_t type = pdu.header.order_type;
    const std::vector<uint8_t> full = FullPdu(pdu);

    if (type == rtsc::proto::RailWindowMove::kOrderType) {
        rtsc::proto::RailWindowMove o;
        if (rtsc::proto::RailWindowMove::parse(full.data(), full.size(), o) ==
            Status::Ok) {
            window_move_ = o;
            has_window_move_ = true;
        }
    } else if (type == rtsc::proto::RailMinMaxInfo::kOrderType) {
        rtsc::proto::RailMinMaxInfo o;
        if (rtsc::proto::RailMinMaxInfo::parse(full.data(), full.size(), o) ==
            Status::Ok) {
            minmax_info_ = o;
            has_minmax_info_ = true;
            ++minmax_info_count_;
        }
    } else if (type == rtsc::proto::RailTaskbarInfo::kOrderType) {
        rtsc::proto::RailTaskbarInfo o;
        if (rtsc::proto::RailTaskbarInfo::parse(full.data(), full.size(), o) ==
            Status::Ok) {
            taskbar_info_ = o;
            has_taskbar_info_ = true;
        }
    } else if (type == rtsc::proto::RailLangbarInfo::kOrderType) {
        rtsc::proto::RailLangbarInfo o;
        if (rtsc::proto::RailLangbarInfo::parse(full.data(), full.size(), o) ==
            Status::Ok) {
            langbar_info_ = o;
            has_langbar_info_ = true;
        }
    } else if (type == rtsc::proto::RailExecuteResult::kOrderType) {
        rtsc::proto::RailExecuteResult o;
        if (rtsc::proto::RailExecuteResult::parse(full.data(), full.size(), o) ==
            Status::Ok) {
            exec_result_ = o;
            has_exec_result_ = true;
        }
    } else if (type == rtsc::proto::RailClientStatus::kOrderType) {
        rtsc::proto::RailClientStatus o;
        if (rtsc::proto::RailClientStatus::parse(full.data(), full.size(), o) ==
            Status::Ok) {
            ++client_status_count_;
        }
    } else if (type == rtsc::proto::RailGetAppIdReq::kOrderType) {
        rtsc::proto::RailGetAppIdReq o;
        if (rtsc::proto::RailGetAppIdReq::parse(full.data(), full.size(), o) ==
            Status::Ok) {
            ++get_app_id_req_count_;
            if (auto_respond_get_app_id_) {
                std::u16string app_id;
                const auto it = app_ids_.find(o.window_id);
                if (it != app_ids_.end()) app_id = it->second;
                SendGetAppIdResp(o.window_id, app_id);
            }
        }
    } else if (type ==
               static_cast<uint16_t>(rtsc::proto::RailOrderType::kGetAppIdResp)) {
        // windowId (4) + ApplicationId (fixed 512 bytes, null-terminated).
        if (pdu.body.size() >= 4) {
            ByteReader r(pdu.body.data(), pdu.body.size());
            uint32_t window_id = 0;
            if (r.u32le(window_id)) {
                app_id_window_ = window_id;
                app_id_ = ReadUtf16Z(pdu.body.data() + 4, pdu.body.size() - 4);
                has_app_id_ = true;
                ++get_app_id_resp_count_;
            }
        }
    }

    if (handler_) handler_(pdu);
}

void RailClient::Start(uint32_t build_number, uint32_t client_flags) {
    SendHandshake(build_number);
    SendClientStatus(client_flags);
}

bool RailClient::SendHandshake(uint32_t build_number) {
    return SendRaw(rtsc::proto::RailHandshake{build_number}.build());
}

bool RailClient::SendHandshakeEx(uint32_t build_number, uint32_t flags) {
    rtsc::proto::RailHandshakeEx o;
    o.build_number = build_number;
    o.flags = flags;
    return SendRaw(o.build());
}

bool RailClient::SendClientStatus(uint32_t flags) {
    rtsc::proto::RailClientStatus o;
    o.flags = flags;
    return SendRaw(o.build());
}

bool RailClient::SendExec(const rtsc::proto::RailClientExecute& exec) {
    std::string why;
    const std::vector<uint8_t> pdu = exec.build(why);
    if (pdu.empty()) return false;
    return SendRaw(pdu);
}

bool RailClient::SendSyscommand(uint32_t window_id, uint16_t command) {
    return SendRaw(rtsc::proto::RailSyscommand{window_id, command}.build());
}

bool RailClient::SendSysmenu(uint32_t window_id, int16_t left, int16_t top) {
    return SendRaw(rtsc::proto::RailSysmenu{window_id, left, top}.build());
}

bool RailClient::SendGetAppIdReq(uint32_t window_id) {
    return SendRaw(rtsc::proto::RailGetAppIdReq{window_id}.build());
}

bool RailClient::SendGetAppIdResp(uint32_t window_id,
                                  const std::u16string& app_id) {
    const std::vector<uint8_t> encoded = rtsc::proto::RailUtf16ToLeBytes(app_id);
    ByteWriter body;
    body.u32le(window_id);
    body.bytes(encoded.data(), encoded.size());
    // Pad to the fixed 512-byte ApplicationId field.
    const size_t field = std::min(encoded.size(), kGetAppIdRespFieldSize);
    for (size_t i = field; i < kGetAppIdRespFieldSize; ++i) body.u8(0);
    return SendRaw(rtsc::proto::BuildRailPdu(
        static_cast<uint16_t>(rtsc::proto::RailOrderType::kGetAppIdResp),
        body.take()));
}

bool RailClient::SendActivate(uint32_t window_id, bool enabled) {
    ByteWriter body;
    body.u32le(window_id);
    body.u8(enabled ? 1 : 0);
    return SendRaw(rtsc::proto::BuildRailPdu(
        static_cast<uint16_t>(rtsc::proto::RailOrderType::kActivate),
        body.take()));
}

bool RailClient::SendLangbarInfo(uint32_t status) {
    rtsc::proto::RailLangbarInfo o;
    o.language_bar_status = status;
    return SendRaw(o.build());
}

bool RailClient::SendSysparam(const rtsc::proto::RailSysparamOrder& order) {
    return SendRaw(order.build());
}

bool RailClient::SendLocalMoveSize(const rtsc::proto::RailLocalMoveSize& order) {
    return SendRaw(order.build());
}

bool RailClient::SendRaw(const std::vector<uint8_t>& pdu) {
    if (pdu.empty() || !send_) return false;
    send_(pdu);
    ++send_count_;
    return true;
}

unsigned RailClient::pdu_count() const { return channel_.pdu_count(); }
unsigned RailClient::handshake_count() const {
    return channel_.handshake_count();
}
unsigned RailClient::handshake_ex_count() const {
    return channel_.handshake_ex_count();
}
unsigned RailClient::exec_count() const { return channel_.exec_count(); }
unsigned RailClient::exec_result_count() const {
    return channel_.exec_result_count();
}
unsigned RailClient::syscommand_count() const {
    return channel_.syscommand_count();
}
unsigned RailClient::sysmenu_count() const { return channel_.sysmenu_count(); }
unsigned RailClient::window_move_count() const {
    return channel_.window_move_count();
}
unsigned RailClient::minmax_info_count() const { return minmax_info_count_; }
unsigned RailClient::taskbar_count() const { return channel_.taskbar_count(); }
unsigned RailClient::langbar_count() const { return channel_.langbar_count(); }
unsigned RailClient::incomplete_message_count() const {
    return channel_.incomplete_message_count();
}

}  // namespace rtsc::channel
