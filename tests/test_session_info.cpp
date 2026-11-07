// Connection information: the field collection behind the dialog, and the
// session statistics (frame rate / input round-trip / bandwidth) it reads.
//
// The Win32 dialog itself is covered by the real-machine run and by the
// code-review points in the execution report: creating a modal dialog needs an
// interactive desktop, which the headless test run does not have. The field
// mapping is fully testable here.

#include "rtsc/client/client.h"
#include "rtsc/client/session_info.h"
#include "rtsc/client/version.h"

#include <cstdint>
#include <string>

#include "rtsc/net/transport.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/security/connection_driver.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc;
using namespace rtsc::client;
using namespace rtsc::security;

namespace {

ConnectionDriver MakeDriver() {
    rtsc::proto::ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=tester";
    mcfg.requested_protocols = rtsc::proto::kProtocolSsl;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr"};
    mcfg.encryption_methods = 0;

    rtsc::proto::ConnectMachine::Credentials creds;
    creds.domain = "Domain";
    creds.user_name = "User";
    creds.password = "Password";

    rtsc::security::Config scfg;
    scfg.tls_config.peer_host = "127.0.0.1";
    scfg.tls_config.cert_policy = rtsc::tls::CertPolicy::kInsecure;
    scfg.credentials.domain = "Domain";
    scfg.credentials.user = "User";
    scfg.credentials.password = "Password";

    return ConnectionDriver(mcfg, creds, scfg);
}

bool Contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

RTSC_TEST(session_info_timestamp_is_utc) {
    // The epoch is a fixed, timezone-independent reference.
    CHECK(FormatUtcTimestamp(0) == "1970-01-01 00:00:00 UTC");
    const SessionInfo si = CollectSessionInfo({}, 0);
    CHECK(si.timestamp_utc == "1970-01-01 00:00:00 UTC");
}

RTSC_TEST(session_info_fields_are_non_empty) {
    SessionInfoInput in;
    in.host = "192.168.1.7";
    in.local_os = "Windows 10.0.26200 (x64)";
    in.frames_per_second = 30.0;
    in.has_rtt = true;
    in.rtt_ms = 12.0;
    in.bandwidth_mbps = 95.5;
    in.smart_card = true;

    const SessionInfo si = CollectSessionInfo(in, 0);
    CHECK(!si.quality.empty());
    CHECK(!si.timestamp_utc.empty());
    CHECK(!si.activity_id.empty());
    CHECK(!si.client_version.empty());
    CHECK(!si.client_architecture.empty());
    CHECK(!si.local_os.empty());
    CHECK(!si.transport_protocol.empty());
    CHECK(!si.round_trip_time.empty());
    CHECK(!si.available_bandwidth.empty());
    CHECK(!si.frame_rate.empty());
    CHECK(!si.remote_session_type.empty());
    CHECK(!si.gateway_name.empty());
    CHECK(!si.gateway_logon_method.empty());
    CHECK(!si.remote_computer.empty());
}

RTSC_TEST(session_info_transport_is_tcp_not_udp) {
    // This client has no UDP transport; the field must not claim one.
    const SessionInfo si = CollectSessionInfo({}, 0);
    CHECK(si.transport_protocol == "TCP");
    CHECK(!Contains(si.transport_protocol, "UDP"));
    CHECK(Contains(si.quality, "TCP"));
}

RTSC_TEST(session_info_unmeasured_fields_report_na) {
    const SessionInfo si = CollectSessionInfo({}, 0);
    CHECK(si.round_trip_time == "N/A");
    CHECK(si.available_bandwidth == "N/A");
    CHECK(si.frame_rate == "N/A");
    CHECK(Contains(si.quality, "未知"));  // quality is unknown until measured
}

RTSC_TEST(session_info_measured_fields_are_formatted) {
    SessionInfoInput in;
    in.host = "192.168.1.7";
    in.has_rtt = true;
    in.rtt_ms = 12.0;
    in.bandwidth_mbps = 95.5;
    in.frames_per_second = 30.0;

    const SessionInfo si = CollectSessionInfo(in, 0);
    CHECK(si.round_trip_time == "12 ms");
    CHECK(si.available_bandwidth == "96 Mbps");
    CHECK(si.frame_rate == "30 FPS");
    CHECK(Contains(si.quality, "很好"));  // 12 ms is a good round-trip
}

RTSC_TEST(session_info_remote_computer_is_the_host) {
    SessionInfoInput in;
    in.host = "192.168.1.7";
    const SessionInfo si = CollectSessionInfo(in, 0);
    CHECK(si.remote_computer == "192.168.1.7");
}

RTSC_TEST(session_info_gateway_is_not_in_use) {
    // The connection is a direct TCP connection: no RD Gateway is configured.
    const SessionInfo si = CollectSessionInfo({}, 0);
    CHECK(si.gateway_name == "没有在使用中");
    CHECK(si.gateway_logon_method == "没有在使用中");
}

RTSC_TEST(session_info_gateway_reflects_the_tunnel) {
    // Stage-2 (E): with an RD Gateway in use the dialog reports the real
    // gateway authority and the authentication method, not "没有在使用中".
    SessionInfoInput in;
    in.host = "target.example";
    in.gateway_name = "gw.example:443";
    in.gateway_logon_method = "NTLM (RDGSP)";
    const SessionInfo si = CollectSessionInfo(in, 0);
    CHECK(si.gateway_name == "gw.example:443");
    CHECK(si.gateway_logon_method == "NTLM (RDGSP)");
    CHECK(si.remote_computer == "target.example");
}

RTSC_TEST(session_info_client_version_matches_the_macro) {
    const SessionInfo si = CollectSessionInfo({}, 0);
    CHECK(Contains(si.client_version, RTSC_VERSION_STRING));
    CHECK(si.client_version.find("0.1.0") != std::string::npos);
}

RTSC_TEST(session_info_activity_id_is_uuid_shaped) {
    const SessionInfo a = CollectSessionInfo({}, 0);
    const SessionInfo b = CollectSessionInfo({}, 0);
    // 8-4-4-4-12 hex, version 4, variant 1.
    CHECK_EQ(a.activity_id.size(), static_cast<size_t>(36));
    CHECK_EQ(a.activity_id[8], '-');
    CHECK_EQ(a.activity_id[13], '-');
    CHECK_EQ(a.activity_id[18], '-');
    CHECK_EQ(a.activity_id[23], '-');
    CHECK(a.activity_id[14] == '4');
    CHECK(a.activity_id[19] == '8' || a.activity_id[19] == '9' ||
          a.activity_id[19] == 'a' || a.activity_id[19] == 'b');
    // Two collections must not produce the same id.
    CHECK(a.activity_id != b.activity_id);
}

RTSC_TEST(session_info_local_os_is_reported) {
    const std::string os = LocalOsString();
    CHECK(!os.empty());
    CHECK(os != "unknown");
}

RTSC_TEST(client_statistics_start_unmeasured) {
    Client c(MakeDriver(), 8, 8);
    CHECK(!c.has_rtt());
    CHECK_EQ(c.rtt_ms(), 0.0);
    CHECK_EQ(c.frames_per_second(), 0.0);
    CHECK_EQ(c.bandwidth_mbps(), 0.0);
    CHECK(!c.activity_id().empty());
}

RTSC_TEST(client_frame_rate_counts_presented_frames) {
    Client c(MakeDriver(), 8, 8);
    for (int i = 0; i < 10; ++i) c.NoteFrame();
    // 10 frames inside one window: a non-zero rate, well below 10 fps because
    // the window is shorter than a second.
    CHECK(c.frames_per_second() > 0.0);
}

RTSC_TEST(client_bandwidth_counts_inbound_bytes) {
    Client c(MakeDriver(), 8, 8);
    c.NoteInboundData(1000);
    c.NoteInboundData(1000);
    CHECK(c.bandwidth_mbps() > 0.0);
}

RTSC_TEST(client_rtt_closes_on_inbound_data) {
    Client c(MakeDriver(), 8, 8);
    CHECK(!c.has_rtt());
    c.NoteInputSent();
    c.NoteInboundData(64);
    CHECK(c.has_rtt());
    CHECK(c.rtt_ms() >= 0.0);
    // The round-trip is consumed: further inbound data does not re-measure it
    // until another input is sent.
    const double first = c.rtt_ms();
    c.NoteInboundData(64);
    CHECK(c.rtt_ms() == first);
}

RTSC_TEST(session_info_session_type_includes_logon_identity) {
    SessionInfoInput in;
    const SessionInfo plain = CollectSessionInfo(in, 0);
    CHECK(plain.remote_session_type == "远程桌面 (RDP)");

    in.has_logon = true;
    in.session_id = 2;
    in.logon_domain = "CONTOSO";
    in.logon_user = "carol";
    const SessionInfo named = CollectSessionInfo(in, 0);
    CHECK(named.remote_session_type ==
          "远程桌面 (RDP) - 会话 2 - 用户 CONTOSO\\carol");

    // A user without a domain is still named, without a stray backslash.
    in.logon_domain.clear();
    const SessionInfo user_only = CollectSessionInfo(in, 0);
    CHECK(user_only.remote_session_type ==
          "远程桌面 (RDP) - 会话 2 - 用户 carol");

    // A logon notification without a name reports the session id only.
    in.has_logon = true;
    in.logon_domain.clear();
    in.logon_user.clear();
    const SessionInfo id_only = CollectSessionInfo(in, 0);
    CHECK(id_only.remote_session_type == "远程桌面 (RDP) - 会话 2");
}

int main() { return ::rtsc::test::run_all("rtsc_session_info_tests"); }
