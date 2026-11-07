// RDP connection file (.rdp) settings codec tests.
//
// Expected values come from "Supported RDP properties" (Microsoft Learn,
// rdp-files): the key names, the s/i types and the documented ranges.

#include "rtsc/config/rdp_file.h"
#include "rtsc/config/credential_store.h"

#include <string>

#include "test_framework.h"
#include "test_main.h"

using rtsc::config::ParseRdpFile;
using rtsc::config::RdpFileSettings;
using rtsc::config::WriteRdpFile;

RTSC_TEST(rdp_file_parses_mstsc_sample) {
    const std::string text =
        "full address:s:server.example:3389\r\n"
        "username:s:alice\r\n"
        "domain:s:CONTOSO\r\n"
        "gatewayhostname:s:gw.example:443\r\n"
        "screen mode id:i:1\r\n"
        "desktopwidth:i:1920\r\n"
        "desktopheight:i:1080\r\n"
        "use multimon:i:1\r\n"
        "smart sizing:i:1\r\n"
        "redirectclipboard:i:1\r\n"
        "audiomode:i:2\r\n"
        "authentication level:i:1\r\n"
        "enablecredsspsupport:i:0\r\n"
        "redirectsmartcards:i:0\r\n"
        "keyboardhook:i:3\r\n"
        "drivestoredirect:s:C:\\;E:\\;\r\n"
        "\r\n";
    const RdpFileSettings s = ParseRdpFile(text);
    CHECK(s.full_address == "server.example:3389");
    CHECK(s.username == "alice");
    CHECK(s.domain == "CONTOSO");
    CHECK(s.gateway_hostname == "gw.example:443");
    CHECK_EQ(s.screen_mode_id, 1);
    CHECK_EQ(s.desktop_width, 1920);
    CHECK_EQ(s.desktop_height, 1080);
    CHECK_EQ(s.use_multimon, 1);
    CHECK_EQ(s.smart_sizing, 1);
    CHECK_EQ(s.redirect_clipboard, 1);
    CHECK_EQ(s.audiomode, 2);
    CHECK_EQ(s.authentication_level, 1);
    CHECK_EQ(s.enable_credssp, 0);
    CHECK_EQ(s.redirect_smartcards, 0);
    CHECK_EQ(s.keyboard_hook, 3);
    CHECK(s.drive_redirect == "C:\\;E:\\;");
}

RTSC_TEST(rdp_file_ignores_unknown_and_malformed) {
    const std::string text =
        "full address:s:host\r\n"
        "unknown key:s:value\r\n"
        "no separator\r\n"
        "bad type:x:1\r\n"
        "audiomode:i:not-a-number\r\n"
        "desktopwidth:i:\r\n"
        "screen mode id:i:1\r\n";
    const RdpFileSettings s = ParseRdpFile(text);
    CHECK(s.full_address == "host");
    CHECK_EQ(s.audiomode, 0);        // default kept
    CHECK_EQ(s.desktop_width, 0);    // unset
    CHECK_EQ(s.screen_mode_id, 1);   // parsed after the malformed lines
}

RTSC_TEST(rdp_file_last_duplicate_wins) {
    const RdpFileSettings s =
        ParseRdpFile("username:s:first\r\nusername:s:second\r\n");
    CHECK(s.username == "second");
}

RTSC_TEST(rdp_file_ignores_out_of_range_integers) {
    const std::string text =
        "desktopwidth:i:99999\r\n"
        "desktopheight:i:100\r\n"
        "audiomode:i:9\r\n"
        "screen mode id:i:0\r\n"
        "use multimon:i:2\r\n";
    const RdpFileSettings s = ParseRdpFile(text);
    CHECK_EQ(s.desktop_width, 0);
    CHECK_EQ(s.desktop_height, 0);
    CHECK_EQ(s.audiomode, 0);
    CHECK_EQ(s.screen_mode_id, 2);
    CHECK_EQ(s.use_multimon, 0);
}

RTSC_TEST(rdp_file_keys_are_case_insensitive) {
    const RdpFileSettings s =
        ParseRdpFile("FULL ADDRESS:s:host\r\nRedirectClipboard:i:1\r\n");
    CHECK(s.full_address == "host");
    CHECK_EQ(s.redirect_clipboard, 1);
}

RTSC_TEST(rdp_file_value_may_contain_colons) {
    const RdpFileSettings s =
        ParseRdpFile("full address:s:[::1]:3389\r\n");
    CHECK(s.full_address == "[::1]:3389");
}

RTSC_TEST(rdp_file_write_round_trip) {
    RdpFileSettings in;
    in.full_address = "server.example:3389";
    in.username = "alice";
    in.domain = "CONTOSO";
    in.gateway_hostname = "gw.example:443";
    in.drive_redirect = "C:\\;";
    in.screen_mode_id = 1;
    in.desktop_width = 1920;
    in.desktop_height = 1080;
    in.use_multimon = 1;
    in.smart_sizing = 1;
    in.redirect_clipboard = 1;
    in.audiomode = 2;
    in.authentication_level = 1;
    in.enable_credssp = 0;
    in.redirect_smartcards = 0;
    in.keyboard_hook = 3;

    const std::string text = WriteRdpFile(in);
    CHECK(!text.empty());
    CHECK(text.find("\r\n") != std::string::npos);
    const RdpFileSettings out = ParseRdpFile(text);
    CHECK(out.full_address == in.full_address);
    CHECK(out.username == in.username);
    CHECK(out.domain == in.domain);
    CHECK(out.gateway_hostname == in.gateway_hostname);
    CHECK(out.drive_redirect == in.drive_redirect);
    CHECK_EQ(out.screen_mode_id, in.screen_mode_id);
    CHECK_EQ(out.desktop_width, in.desktop_width);
    CHECK_EQ(out.desktop_height, in.desktop_height);
    CHECK_EQ(out.use_multimon, in.use_multimon);
    CHECK_EQ(out.smart_sizing, in.smart_sizing);
    CHECK_EQ(out.redirect_clipboard, in.redirect_clipboard);
    CHECK_EQ(out.audiomode, in.audiomode);
    CHECK_EQ(out.authentication_level, in.authentication_level);
    CHECK_EQ(out.enable_credssp, in.enable_credssp);
    CHECK_EQ(out.redirect_smartcards, in.redirect_smartcards);
    CHECK_EQ(out.keyboard_hook, in.keyboard_hook);
}

RTSC_TEST(rdp_file_write_rejects_line_break_injection) {
    RdpFileSettings s;
    s.full_address = "host";
    s.username = "alice\r\nfull address:s:evil.example";
    CHECK(WriteRdpFile(s).empty());

    s.username = "alice\nfull address:s:evil.example";
    CHECK(WriteRdpFile(s).empty());

    s.username = std::string("alice\0evil", 10);
    CHECK(WriteRdpFile(s).empty());
}

RTSC_TEST(rdp_file_write_omits_unset_geometry) {
    RdpFileSettings s;
    s.full_address = "host";
    const std::string text = WriteRdpFile(s);
    CHECK(!text.empty());
    CHECK(text.find("desktopwidth") == std::string::npos);
    CHECK(text.find("desktopheight") == std::string::npos);
    CHECK(text.find("drivestoredirect") == std::string::npos);
}

RTSC_TEST(rdp_file_builds_session_settings) {
    const RdpFileSettings s = rtsc::config::BuildSessionRdpFile(
        "server.example:3390", "alice", "CONTOSO", 1920, 1080, true, true,
        true, true, 1);
    CHECK(s.full_address == "server.example:3390");
    CHECK(s.username == "alice");
    CHECK(s.domain == "CONTOSO");
    CHECK_EQ(s.desktop_width, 1920);
    CHECK_EQ(s.desktop_height, 1080);
    CHECK_EQ(s.use_multimon, 1);
    CHECK_EQ(s.smart_sizing, 1);
    CHECK_EQ(s.screen_mode_id, 2);
    CHECK_EQ(s.redirect_clipboard, 1);
    CHECK_EQ(s.audiomode, 1);

    const RdpFileSettings off = rtsc::config::BuildSessionRdpFile(
        "host", "", "", 800, 600, false, false, false, false, 2);
    CHECK_EQ(off.use_multimon, 0);
    CHECK_EQ(off.smart_sizing, 0);
    CHECK_EQ(off.screen_mode_id, 1);
    CHECK_EQ(off.redirect_clipboard, 0);
    CHECK_EQ(off.audiomode, 2);

    // multimon and fit are independent: this case keeps them different so a
    // swapped mapping cannot hide behind equal inputs.
    const RdpFileSettings mixed = rtsc::config::BuildSessionRdpFile(
        "host", "", "", 800, 600, true, false, false, false, 0);
    CHECK_EQ(mixed.use_multimon, 1);
    CHECK_EQ(mixed.smart_sizing, 0);

    // The built settings survive a write/parse round trip.
    const RdpFileSettings parsed = ParseRdpFile(WriteRdpFile(s));
    CHECK(parsed.full_address == s.full_address);
    CHECK_EQ(parsed.use_multimon, s.use_multimon);
    CHECK_EQ(parsed.smart_sizing, s.smart_sizing);
    CHECK_EQ(parsed.screen_mode_id, s.screen_mode_id);
    CHECK_EQ(parsed.audiomode, s.audiomode);
}

RTSC_TEST(rdp_file_redirect_comports_round_trip) {
    const RdpFileSettings on = ParseRdpFile("redirectcomports:i:1\r\n");
    CHECK_EQ(on.redirect_comports, 1);
    const RdpFileSettings off = ParseRdpFile("redirectcomports:i:0\r\n");
    CHECK_EQ(off.redirect_comports, 0);
    // Out-of-range values keep the default.
    const RdpFileSettings bad = ParseRdpFile("redirectcomports:i:7\r\n");
    CHECK_EQ(bad.redirect_comports, 0);

    RdpFileSettings settings;
    settings.redirect_comports = 1;
    const RdpFileSettings parsed = ParseRdpFile(WriteRdpFile(settings));
    CHECK_EQ(parsed.redirect_comports, 1);

    const RdpFileSettings built = rtsc::config::BuildSessionRdpFile(
        "host", "", "", 800, 600, false, false, false, false, 0, true);
    CHECK_EQ(built.redirect_comports, 1);
    const RdpFileSettings built_off = rtsc::config::BuildSessionRdpFile(
        "host", "", "", 800, 600, false, false, false, false, 0);
    CHECK_EQ(built_off.redirect_comports, 0);
}

RTSC_TEST(rdp_file_redirect_printers_round_trip) {
    const RdpFileSettings on = ParseRdpFile("redirectprinters:i:1\r\n");
    CHECK_EQ(on.redirect_printers, 1);
    const RdpFileSettings off = ParseRdpFile("redirectprinters:i:0\r\n");
    CHECK_EQ(off.redirect_printers, 0);
    // Out-of-range values keep the default.
    const RdpFileSettings bad = ParseRdpFile("redirectprinters:i:7\r\n");
    CHECK_EQ(bad.redirect_printers, 0);

    RdpFileSettings settings;
    settings.redirect_printers = 1;
    const RdpFileSettings parsed = ParseRdpFile(WriteRdpFile(settings));
    CHECK_EQ(parsed.redirect_printers, 1);

    const RdpFileSettings built = rtsc::config::BuildSessionRdpFile(
        "host", "", "", 800, 600, false, false, false, false, 0, false, true);
    CHECK_EQ(built.redirect_printers, 1);
    CHECK_EQ(built.redirect_comports, 0);
    const RdpFileSettings built_off = rtsc::config::BuildSessionRdpFile(
        "host", "", "", 800, 600, false, false, false, false, 0);
    CHECK_EQ(built_off.redirect_printers, 0);
}

RTSC_TEST(credential_target_name_matches_mstsc) {
    CHECK(rtsc::config::CredentialTargetName("server.example") ==
          "TERMSRV/server.example");
    CHECK(rtsc::config::CredentialTargetName("10.0.0.1") ==
          "TERMSRV/10.0.0.1");
    CHECK(rtsc::config::CredentialTargetName("") == "TERMSRV/");
}

int main() { return ::rtsc::test::run_all("rtsc_rdp_file_tests"); }
