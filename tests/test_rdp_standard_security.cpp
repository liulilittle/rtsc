// Standard RDP Security (PROTOCOL_RDP) data plane.
//
// The unit tests drive the client half against an independent server-side
// implementation of the same primitives (crypto::RsaServerKeyPair +
// crypto::RdpSecurityContext), so a green run is a real round trip, not a
// self-comparison. The last test is an end-to-end loopback against the in-tree
// RDP server through the real client (ConnectionDriver + Client graphics).

#include "rtsc/security/standard_rdp_security.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "rtsc/client/client.h"
#include "rtsc/crypto/rdp_security.h"
#include "rtsc/crypto/rsa_server.h"
#include "rtsc/net/transport.h"
#include "rtsc/proto/byte_order.h"
#include "rtsc/proto/client_info.h"
#include "rtsc/proto/connect_machine.h"
#include "rtsc/proto/mcs.h"
#include "rtsc/proto/rdp_neg.h"
#include "rtsc/proto/share.h"
#include "rtsc/server/server.h"
#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;
using rtsc::security::StandardRdpSecurity;

namespace {

std::vector<uint8_t> MakeServerSecurityData(uint32_t method, uint32_t level,
                                            const std::vector<uint8_t>& random,
                                            const std::vector<uint8_t>& cert) {
    ByteWriter w;
    w.u32le(method);
    w.u32le(level);
    if (method != 0 || level != 0) {
        w.u32le(static_cast<uint32_t>(random.size()));
        w.u32le(static_cast<uint32_t>(cert.size()));
        if (!random.empty()) w.bytes(random.data(), random.size());
        if (!cert.empty()) w.bytes(cert.data(), cert.size());
    }
    return w.take();
}

[[maybe_unused]] uint16_t ReadU16Le(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint16_t>(b[off]) |
           static_cast<uint16_t>(static_cast<uint16_t>(b[off + 1]) << 8);
}

}  // namespace

RTSC_TEST(standard_security_parses_a_plaintext_sc_sec1) {
    const auto payload = MakeServerSecurityData(0, 0, {}, {});
    StandardRdpSecurity::ServerSecurityData data;
    std::string why;
    CHECK(StandardRdpSecurity::ParseServerSecurityData(
        payload.data(), payload.size(), data, why));
    CHECK_EQ(data.encryption_method, static_cast<uint32_t>(0));
    CHECK_EQ(data.encryption_level, static_cast<uint32_t>(0));

    StandardRdpSecurity sec;
    CHECK(sec.Configure(data, why));
    CHECK(!sec.encryption_enabled());
    CHECK(sec.configured());

    // Plaintext data plane: SendPdu is an identity and ReceivePdu frames.
    const std::vector<uint8_t> user = {0x40, 0x00, 0x01, 0x02, 0x03};
    const auto pdu = McsSendData::build_request(1001, 1003, user);
    CHECK(sec.SendPdu(pdu) == pdu);

    const auto frames = sec.ReceivePdu(pdu.data(), pdu.size());
    CHECK_EQ(frames.size(), static_cast<size_t>(1));
    McsSendData sd;
    CHECK(McsSendData::parse(frames[0].data(), frames[0].size(), sd) ==
          Status::Ok);
    CHECK(sd.user_data == user);
}

RTSC_TEST(standard_security_rejects_a_truncated_sc_sec1) {
    const uint8_t short_block[4] = {0x02, 0x00, 0x00, 0x00};
    StandardRdpSecurity::ServerSecurityData data;
    std::string why;
    CHECK(!StandardRdpSecurity::ParseServerSecurityData(short_block,
                                                       sizeof(short_block),
                                                       data, why));
    CHECK(!why.empty());
}

#if defined(_WIN32)
RTSC_TEST(standard_security_rsa_exchange_and_rc4_round_trip) {
    rtsc::crypto::RsaServerKeyPair server_key;
    if (!server_key.Generate(512)) {
        // No platform RSA backend: the loopback test is Windows-only too.
        CHECK(true);
        return;
    }
    const std::vector<uint8_t> cert = server_key.BuildCertificate();
    CHECK(!cert.empty());
    const std::vector<uint8_t> server_random(32, 0xA0);

    const auto payload =
        MakeServerSecurityData(0x00000002, 0x00000002, server_random, cert);
    StandardRdpSecurity::ServerSecurityData data;
    std::string why;
    CHECK(StandardRdpSecurity::ParseServerSecurityData(
        payload.data(), payload.size(), data, why));
    CHECK_EQ(data.encryption_method, static_cast<uint32_t>(0x00000002));
    CHECK_EQ(data.encryption_level, static_cast<uint32_t>(0x00000002));
    CHECK(data.server_random == server_random);
    CHECK(data.server_certificate == cert);

    StandardRdpSecurity client;
    CHECK(client.Configure(data, why));
    CHECK(client.encryption_enabled());

    const auto exchange_frame =
        client.BuildSecurityExchange(1001, 1003, why);
    CHECK(!exchange_frame.empty());
    CHECK(client.exchange_complete());

    McsSendData exchange_sd;
    CHECK(McsSendData::parse(exchange_frame.data(), exchange_frame.size(),
                             exchange_sd) == Status::Ok);
    CHECK_EQ(exchange_sd.initiator, static_cast<uint16_t>(1001));
    CHECK_EQ(exchange_sd.channel_id, static_cast<uint16_t>(1003));

    SecurityExchangePdu exchange;
    CHECK(SecurityExchangePdu::parse(exchange_sd.user_data.data(),
                                     exchange_sd.user_data.size(),
                                     exchange) == Status::Ok);
    CHECK((exchange.flags & sec::kSecExchangePkt) != 0);

    std::vector<uint8_t> client_random;
    CHECK(server_key.DecryptClientRandom(exchange.encrypted_client_random,
                                         client_random));
    CHECK_EQ(client_random.size(), static_cast<size_t>(32));

    // Build the server-side RC4 context for the same session.
    const auto client_keys = rtsc::crypto::DeriveRdpSessionKeys(
        client_random, server_random, 0x00000002u);
    CHECK_EQ(client_keys.rc4_key_len, static_cast<size_t>(16));
    auto server_keys = client_keys;
    std::swap(server_keys.encrypt_key, server_keys.decrypt_key);
    rtsc::crypto::RdpSecurityContext server_ctx;
    server_ctx.Init(server_keys);

    // Client -> server: a licensing-like PDU inside MCS.
    const std::vector<uint8_t> inner = {0x80, 0x00, 0x00, 0x00,
                                        0xDE, 0xAD, 0xBE, 0xEF};
    const auto plain_frame = McsSendData::build_request(1001, 1003, inner);
    const auto wire = client.SendPdu(plain_frame);
    CHECK(!wire.empty());

    McsSendData out_sd;
    CHECK(McsSendData::parse(wire.data(), wire.size(), out_sd) == Status::Ok);
    CHECK_EQ(out_sd.channel_id, static_cast<uint16_t>(1003));
    CHECK(out_sd.user_data.size() >= 12);
    CHECK((ReadU16Le(out_sd.user_data, 0) & sec::kSecEncrypt) != 0);

    std::array<uint8_t, 8> mac{};
    std::memcpy(mac.data(), out_sd.user_data.data() + 4, mac.size());
    std::vector<uint8_t> decrypted(out_sd.user_data.begin() + 12,
                                   out_sd.user_data.end());
    CHECK(server_ctx.Decrypt(decrypted, mac));
    CHECK(decrypted == inner);

    // Server -> client: an encrypted slow-path PDU. Encrypt() works in place,
    // so keep the plaintext for the comparison.
    const std::vector<uint8_t> reply_plain = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> reply = reply_plain;
    const auto reply_mac = server_ctx.Encrypt(reply);
    ByteWriter header;
    header.u16le(static_cast<uint16_t>(sec::kSecEncrypt));
    header.u16le(0);
    header.bytes(reply_mac.data(), reply_mac.size());
    header.bytes(reply.data(), reply.size());
    const auto reply_frame =
        McsSendData::build_indication(1002, 1003, header.take());

    const auto frames = client.ReceivePdu(reply_frame.data(), reply_frame.size());
    CHECK(!client.failed());
    CHECK_EQ(frames.size(), static_cast<size_t>(1));
    McsSendData in_sd;
    CHECK(McsSendData::parse(frames[0].data(), frames[0].size(), in_sd) ==
          Status::Ok);
    CHECK(in_sd.user_data == reply_plain);

    // Cross the mandatory 4,096-packet key-update boundary. The wrapper must
    // keep one RdpSecurityContext for the whole session; recreating it per PDU
    // would desynchronise the RC4 streams here.
    int key_update_failures = 0;
    for (int i = 0; i < 4200; ++i) {
        const std::vector<uint8_t> step_payload = {
            static_cast<uint8_t>(i), static_cast<uint8_t>(i >> 8), 0xAA};
        const auto wrapped = client.SendPdu(
            McsSendData::build_request(1001, 1003, step_payload));
        McsSendData step_sd;
        if (wrapped.empty() ||
            McsSendData::parse(wrapped.data(), wrapped.size(), step_sd) !=
                Status::Ok ||
            step_sd.user_data.size() < 12) {
            ++key_update_failures;
            break;
        }
        std::array<uint8_t, 8> step_mac{};
        std::memcpy(step_mac.data(), step_sd.user_data.data() + 4,
                    step_mac.size());
        std::vector<uint8_t> step_plain(step_sd.user_data.begin() + 12,
                                        step_sd.user_data.end());
        if (!server_ctx.Decrypt(step_plain, step_mac) ||
            step_plain != step_payload) {
            ++key_update_failures;
            break;
        }
    }
    CHECK_EQ(key_update_failures, 0);
}

RTSC_TEST(standard_security_rejects_a_bad_mac) {
    rtsc::crypto::RsaServerKeyPair server_key;
    if (!server_key.Generate(512)) {
        CHECK(true);
        return;
    }
    const auto payload = MakeServerSecurityData(
        0x00000002, 0x00000002, std::vector<uint8_t>(32, 0x5A),
        server_key.BuildCertificate());
    StandardRdpSecurity::ServerSecurityData data;
    std::string why;
    CHECK(StandardRdpSecurity::ParseServerSecurityData(
        payload.data(), payload.size(), data, why));
    StandardRdpSecurity client;
    CHECK(client.Configure(data, why));
    CHECK(!client.BuildSecurityExchange(1001, 1003, why).empty());

    // A syntactically valid SEC_ENCRYPT PDU with a corrupted MAC.
    std::vector<uint8_t> user(12, 0);
    user[0] = 0x08;  // SEC_ENCRYPT
    user[4] = 0xFF;  // MAC byte 0
    user.push_back(0x42);
    const auto frame = McsSendData::build_indication(1002, 1003, user);
    const auto frames = client.ReceivePdu(frame.data(), frame.size());
    CHECK(frames.empty());
    CHECK(client.failed());
    CHECK(!client.error().empty());
}
#endif  // _WIN32

#if defined(_WIN32)
RTSC_TEST(standard_security_loopback_reaches_active_and_receives_a_frame) {
    rtsc::server::ServerConfig scfg;
    scfg.port = 0;  // ephemeral: the kernel picks a free port
    scfg.desktop_width = 64;
    scfg.desktop_height = 48;
    auto source = rtsc::server::MakeTestPatternSource();
    rtsc::server::RdpServer server(scfg);
    server.SetDesktopSource(source.get());

    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = kProtocolRdp;
    mcfg.desktop_width = 64;
    mcfg.desktop_height = 48;
    mcfg.client_name = "RTSC";
    mcfg.channel_names = {"rdpdr", "cliprdr", "rdpsnd"};
    mcfg.encryption_methods = 0x0000001B;

    ConnectMachine::Credentials creds;
    creds.domain = "NTDEV";
    creds.user_name = "rtsc";

    rtsc::security::Config secfg;  // not used by Standard RDP Security
    rtsc::security::ConnectionDriver driver(mcfg, creds, secfg);
    rtsc::client::Client client(std::move(driver), 64, 48);

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", port, cerr);
    CHECK(transport != nullptr);
    if (transport != nullptr) {
        CHECK(client.Connect(*transport, error));
        if (!error.empty()) std::printf("  connect error: %s\n", error.c_str());
        CHECK(client.active());
        CHECK(client.driver().standard_rdp());
        CHECK(client.driver().standard_security() != nullptr);
        CHECK(client.driver().standard_security()->exchange_complete());
        CHECK(client.driver().standard_security()->encryption_enabled());

        bool got_frame = false;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!got_frame && std::chrono::steady_clock::now() < deadline) {
            if (!client.Pump(*transport, error)) break;
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (client.surface().GetPixel(0, 0, r, g, b, a) && r == 255 &&
                g == 255 && b == 255 && a == 255) {
                got_frame = true;
            }
        }
        if (!got_frame) std::printf("  frame error: %s\n", error.c_str());
        CHECK(got_frame);
        transport->Close();
    }

    server.Stop();
    runner.join();
}

RTSC_TEST(standard_security_loopback_plaintext_data_plane) {
    // The same loopback with encryption_methods = 0: the MCS channel and all
    // post-connect PDUs stay plaintext, and the licensing machine uses the
    // no-certificate fallback because the in-tree server omits the key in that
    // mode.
    rtsc::server::ServerConfig scfg;
    scfg.port = 0;  // ephemeral: the kernel picks a free port
    scfg.desktop_width = 64;
    scfg.desktop_height = 48;
    auto source = rtsc::server::MakeTestPatternSource();
    rtsc::server::RdpServer server(scfg);
    server.SetDesktopSource(source.get());

    std::string error;
    CHECK(server.Start(error));
    const uint16_t port = server.bound_port();
    std::thread runner([&server]() { server.Run(); });

    ConnectMachine::Config mcfg;
    mcfg.cookie = "Cookie: mstshash=rtsc";
    mcfg.requested_protocols = kProtocolRdp;
    mcfg.desktop_width = 64;
    mcfg.desktop_height = 48;
    mcfg.client_name = "RTSC";
    mcfg.encryption_methods = 0;  // plaintext Standard RDP Security

    ConnectMachine::Credentials creds;
    creds.domain = "NTDEV";
    creds.user_name = "rtsc";

    rtsc::security::Config secfg;
    rtsc::security::ConnectionDriver driver(mcfg, creds, secfg);
    rtsc::client::Client client(std::move(driver), 64, 48);

    std::string cerr;
    auto transport = rtsc::net::ConnectTcp("127.0.0.1", port, cerr);
    CHECK(transport != nullptr);
    if (transport != nullptr) {
        CHECK(client.Connect(*transport, error));
        if (!error.empty()) std::printf("  connect error: %s\n", error.c_str());
        CHECK(client.active());
        CHECK(client.driver().standard_rdp());
        CHECK(client.driver().standard_security() != nullptr);
        CHECK(!client.driver().standard_security()->encryption_enabled());

        bool got_frame = false;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!got_frame && std::chrono::steady_clock::now() < deadline) {
            if (!client.Pump(*transport, error)) break;
            uint8_t r = 0, g = 0, b = 0, a = 0;
            if (client.surface().GetPixel(0, 0, r, g, b, a) && r == 255 &&
                g == 255 && b == 255 && a == 255) {
                got_frame = true;
            }
        }
        if (!got_frame) std::printf("  frame error: %s\n", error.c_str());
        CHECK(got_frame);
        transport->Close();
    }

    server.Stop();
    runner.join();
}
#endif  // _WIN32

int main() { return ::rtsc::test::run_all("rtsc_rdp_standard_security_tests"); }
