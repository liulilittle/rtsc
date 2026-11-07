// mstsc-compatible /v: /w: /h: parsing.

#include <cstdint>
#include <string>

#include "mstsc_args.h"
#include "test_framework.h"
#include "test_main.h"

using rtsc::gui::MstscEndpoint;

RTSC_TEST(mstsc_endpoint_accepts_host_and_port) {
    MstscEndpoint ep;
    CHECK(rtsc::gui::ParseMstscEndpoint("server.example", ep));
    CHECK(ep.host == "server.example");
    CHECK_EQ(ep.port, static_cast<uint16_t>(3389));

    CHECK(rtsc::gui::ParseMstscEndpoint("server.example:3390", ep));
    CHECK(ep.host == "server.example");
    CHECK_EQ(ep.port, static_cast<uint16_t>(3390));
}

RTSC_TEST(mstsc_endpoint_accepts_bracketed_ipv6) {
    MstscEndpoint ep;
    CHECK(rtsc::gui::ParseMstscEndpoint("[::1]:3391", ep));
    CHECK(ep.host == "::1");
    CHECK_EQ(ep.port, static_cast<uint16_t>(3391));

    CHECK(rtsc::gui::ParseMstscEndpoint("[2001:db8::5]", ep));
    CHECK(ep.host == "2001:db8::5");
    CHECK_EQ(ep.port, static_cast<uint16_t>(3389));
}

RTSC_TEST(mstsc_endpoint_accepts_bare_ipv6) {
    MstscEndpoint ep;
    CHECK(rtsc::gui::ParseMstscEndpoint("2001:db8::5", ep));
    CHECK(ep.host == "2001:db8::5");
    CHECK_EQ(ep.port, static_cast<uint16_t>(3389));
}

RTSC_TEST(mstsc_endpoint_rejects_bad_values) {
    MstscEndpoint ep;
    CHECK(!rtsc::gui::ParseMstscEndpoint("", ep));
    CHECK(!rtsc::gui::ParseMstscEndpoint(":3390", ep));
    CHECK(!rtsc::gui::ParseMstscEndpoint("host:", ep));
    CHECK(!rtsc::gui::ParseMstscEndpoint("host:0", ep));
    CHECK(!rtsc::gui::ParseMstscEndpoint("host:65536", ep));
    CHECK(!rtsc::gui::ParseMstscEndpoint("host:12x", ep));
    CHECK(!rtsc::gui::ParseMstscEndpoint("host name", ep));
    CHECK(!rtsc::gui::ParseMstscEndpoint("host\r\nInjected: 1", ep));
    CHECK(!rtsc::gui::ParseMstscEndpoint("[::1]:0", ep));
    CHECK(!rtsc::gui::ParseMstscEndpoint("[]:3390", ep));
}

RTSC_TEST(mstsc_dimension_accepts_in_range) {
    uint16_t v = 0;
    CHECK(rtsc::gui::ParseMstscDimension("1", v));
    CHECK_EQ(v, static_cast<uint16_t>(1));
    CHECK(rtsc::gui::ParseMstscDimension("1920", v));
    CHECK_EQ(v, static_cast<uint16_t>(1920));
    CHECK(rtsc::gui::ParseMstscDimension("65535", v));
    CHECK_EQ(v, static_cast<uint16_t>(65535));
}

RTSC_TEST(mstsc_dimension_rejects_bad_values) {
    uint16_t v = 0;
    CHECK(!rtsc::gui::ParseMstscDimension("", v));
    CHECK(!rtsc::gui::ParseMstscDimension("0", v));
    CHECK(!rtsc::gui::ParseMstscDimension("65536", v));
    CHECK(!rtsc::gui::ParseMstscDimension("-1", v));
    CHECK(!rtsc::gui::ParseMstscDimension("12x", v));
    CHECK(!rtsc::gui::ParseMstscDimension(" 12", v));
}

RTSC_TEST(mstsc_cli_special_is_exact_match) {
    using rtsc::gui::CliSpecial;
    CHECK(rtsc::gui::ClassifyCliSpecial("--help") == CliSpecial::kHelp);
    CHECK(rtsc::gui::ClassifyCliSpecial("-h") == CliSpecial::kHelp);
    CHECK(rtsc::gui::ClassifyCliSpecial("/?") == CliSpecial::kHelp);
    CHECK(rtsc::gui::ClassifyCliSpecial("--version") == CliSpecial::kVersion);
    CHECK(rtsc::gui::ClassifyCliSpecial("-V") == CliSpecial::kVersion);
    // Slash options with a value must not be classified as help.
    CHECK(rtsc::gui::ClassifyCliSpecial("/h:1080") == CliSpecial::kNone);
    CHECK(rtsc::gui::ClassifyCliSpecial("/v:host") == CliSpecial::kNone);
    CHECK(rtsc::gui::ClassifyCliSpecial("host") == CliSpecial::kNone);
    CHECK(rtsc::gui::ClassifyCliSpecial("") == CliSpecial::kNone);
}

RTSC_TEST(mstsc_endpoint_explicit_values_win_over_rdp_file) {
    MstscEndpoint ep;
    CHECK(rtsc::gui::ResolveEndpoint("cli.example", 3390,
                                     "file.example:3391", ep));
    CHECK(ep.host == "cli.example");
    CHECK_EQ(ep.port, static_cast<uint16_t>(3390));

    // No explicit port: the default, not the file's port.
    CHECK(rtsc::gui::ResolveEndpoint("cli.example", 0, "file.example:3391",
                                     ep));
    CHECK(ep.host == "cli.example");
    CHECK_EQ(ep.port, static_cast<uint16_t>(3389));
}

RTSC_TEST(mstsc_endpoint_falls_back_to_rdp_file) {
    MstscEndpoint ep;
    CHECK(rtsc::gui::ResolveEndpoint("", 0, "file.example:3391", ep));
    CHECK(ep.host == "file.example");
    CHECK_EQ(ep.port, static_cast<uint16_t>(3391));

    CHECK(rtsc::gui::ResolveEndpoint("", 0, "file.example", ep));
    CHECK(ep.host == "file.example");
    CHECK_EQ(ep.port, static_cast<uint16_t>(3389));
}

RTSC_TEST(mstsc_endpoint_rejects_missing_or_invalid_sources) {
    MstscEndpoint ep;
    CHECK(!rtsc::gui::ResolveEndpoint("", 0, "", ep));
    CHECK(!rtsc::gui::ResolveEndpoint("", 0, "bad host", ep));
    CHECK(!rtsc::gui::ResolveEndpoint("", 0, "host:0", ep));
}

RTSC_TEST(mstsc_full_address_omits_the_default_port) {
    CHECK(rtsc::gui::FormatFullAddress("server.example", 3389) ==
          "server.example");
    CHECK(rtsc::gui::FormatFullAddress("server.example", 3390) ==
          "server.example:3390");
}

RTSC_TEST(mstsc_full_address_brackets_bare_ipv6) {
    CHECK(rtsc::gui::FormatFullAddress("::1", 3389) == "[::1]");
    CHECK(rtsc::gui::FormatFullAddress("::1", 3390) == "[::1]:3390");
    // Already bracketed input is not bracketed twice.
    CHECK(rtsc::gui::FormatFullAddress("[::1]", 3389) == "[::1]");
}

RTSC_TEST(mstsc_channel_list_honours_redirection_flags) {
    using rtsc::gui::BuildStaticChannelNames;
    const std::vector<std::string> all =
        BuildStaticChannelNames(false, false, true, true);
    CHECK_EQ(all.size(), static_cast<size_t>(3));
    CHECK(all[0] == "rdpdr");
    CHECK(all[1] == "cliprdr");
    CHECK(all[2] == "rdpsnd");

    const std::vector<std::string> no_clipboard =
        BuildStaticChannelNames(false, false, false, true);
    CHECK_EQ(no_clipboard.size(), static_cast<size_t>(2));
    CHECK(no_clipboard[0] == "rdpdr");
    CHECK(no_clipboard[1] == "rdpsnd");

    const std::vector<std::string> no_audio =
        BuildStaticChannelNames(false, false, true, false);
    CHECK_EQ(no_audio.size(), static_cast<size_t>(2));
    CHECK(no_audio[0] == "rdpdr");
    CHECK(no_audio[1] == "cliprdr");

    const std::vector<std::string> neither =
        BuildStaticChannelNames(false, false, false, false);
    CHECK_EQ(neither.size(), static_cast<size_t>(1));
    CHECK(neither[0] == "rdpdr");

    const std::vector<std::string> extras =
        BuildStaticChannelNames(true, true, true, true);
    CHECK_EQ(extras.size(), static_cast<size_t>(5));
    CHECK(extras[3] == "rail");
    CHECK(extras[4] == "drdynvc");
}

int main() { return ::rtsc::test::run_all("rtsc_mstsc_args_tests"); }
