// In-process UI debug channel: HTTP request handling and batch semantics.
//
// The transport (sockets, the thread that pumps the queue) is exercised by the
// live GUI, not here; these tests pin the protocol so a malformed request can
// never take the GUI down and a batch always answers one result per command in
// order.

#include <string>
#include <vector>

#include "rtsc/debug/ui_debug_server.h"

#include "test_framework.h"
#include "test_main.h"

namespace {

// Records every command it is asked to run and echoes a fixed reply, so the
// tests can assert both the framing and that Execute really is reached.
class RecordingHost final : public rtsc::debug::UiDebugHost {
 public:
    std::string Execute(const std::string& json_body) override {
        seen.push_back(json_body);
        return "\"ok\":true,\"echo\":\"" + json_body + "\"";
    }
    std::vector<std::string> seen;
};

std::string Request(const std::string& method, const std::string& path,
                    const std::string& body) {
    std::string r = method + " " + path + " HTTP/1.1\r\n";
    r += "Host: 127.0.0.1\r\n";
    r += "Content-Type: application/json\r\n";
    r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    r += "\r\n";
    r += body;
    return r;
}

}  // namespace

RTSC_TEST(ui_debug_rejects_an_unknown_path) {
    RecordingHost host;
    const std::string reply =
        rtsc::debug::UiDebugServer::HandleRequest(&host, Request("GET", "/nope", ""));
    CHECK(reply.find("404") != std::string::npos);
}

RTSC_TEST(ui_debug_health_needs_no_host_call) {
    RecordingHost host;
    const std::string reply = rtsc::debug::UiDebugServer::HandleRequest(
        &host, Request("GET", "/health", ""));
    CHECK(reply.find("200") != std::string::npos);
    CHECK(reply.find("\"ok\":true") != std::string::npos);
    CHECK(host.seen.empty());  // health must not dispatch a command
}

RTSC_TEST(ui_debug_runs_a_batch_and_answers_one_result_per_command) {
    RecordingHost host;
    const std::string body =
        "{\"commands\":[{\"op\":\"a\"},{\"op\":\"b\"},{\"op\":\"c\"}]}";
    const std::string reply = rtsc::debug::UiDebugServer::HandleRequest(
        &host, Request("POST", "/debug", body));

    CHECK(reply.find("200") != std::string::npos);
    CHECK_EQ(host.seen.size(), size_t{3});
    CHECK(host.seen[0].find("\"op\":\"a\"") != std::string::npos);
    CHECK(host.seen[2].find("\"op\":\"c\"") != std::string::npos);
    // Three results, in order.
    const size_t first = reply.find("\"echo\"");
    const size_t last = reply.rfind("\"echo\"");
    CHECK(first != std::string::npos);
    CHECK(first != last);
}

RTSC_TEST(ui_debug_splits_commands_on_top_level_braces_only) {
    // A command carrying a nested object or an array must not be cut in the
    // middle: the splitter counts braces/brackets and ignores anything inside a
    // JSON string.
    //
    // The assertions check the EXACT body the host receives, not a substring:
    // searching for a fragment cannot tell a correctly delimited object from
    // one with its closing brace chopped off, and an earlier version of this
    // test was fooled by exactly that mutation.
    RecordingHost host;
    const std::string body =
        "{\"commands\":[{\"op\":\"tree\",\"filter\":{\"kind\":\"button\"}},"
        "{\"op\":\"click\",\"ids\":[1,2,3]}]}";
    const std::string reply = rtsc::debug::UiDebugServer::HandleRequest(
        &host, Request("POST", "/debug", body));

    CHECK(reply.find("200") != std::string::npos);
    CHECK_EQ(host.seen.size(), size_t{2});
    std::printf("[got0]=%s\n", host.seen[0].c_str());
    CHECK(host.seen[0] == std::string("\"op\":\"tree\",\"filter\":{\"kind\":\"button\"}"));
    CHECK(host.seen[1] == std::string("\"op\":\"click\",\"ids\":[1,2,3]"));
}

RTSC_TEST(ui_debug_treats_braces_inside_strings_as_data) {
    RecordingHost host;
    const std::string body =
        "{\"commands\":[{\"op\":\"type\",\"text\":\"}{][\"}]}";
    const std::string reply = rtsc::debug::UiDebugServer::HandleRequest(
        &host, Request("POST", "/debug", body));
    CHECK(reply.find("200") != std::string::npos);
    CHECK_EQ(host.seen.size(), size_t{1});
    // The braces inside the string are data: the body must be delivered whole,
    // keeping the quoted text intact and balanced by exactly the outer pair.
    CHECK(host.seen[0] == std::string("\"op\":\"type\",\"text\":\"}{][\""));
}

RTSC_TEST(ui_debug_rejects_a_body_without_a_commands_array) {
    RecordingHost host;
    const std::string reply = rtsc::debug::UiDebugServer::HandleRequest(
        &host, Request("POST", "/debug", "{\"nope\":1}"));
    CHECK(reply.find("400") != std::string::npos);
    CHECK(host.seen.empty());
}

RTSC_TEST(ui_debug_rejects_a_truncated_request) {
    RecordingHost host;
    // Content-Length promises 40 bytes, the body has none.
    const std::string reply = rtsc::debug::UiDebugServer::HandleRequest(
        &host,
        "POST /debug HTTP/1.1\r\nContent-Length: 40\r\n\r\n");
    CHECK(reply.find("400") != std::string::npos);
    CHECK(host.seen.empty());
}

RTSC_TEST(ui_debug_rejects_a_null_host_for_business_paths) {
    const std::string reply = rtsc::debug::UiDebugServer::HandleRequest(
        nullptr, Request("POST", "/debug", "{\"commands\":[{\"op\":\"a\"}]}"));
    // No host means the channel cannot run commands; it must fail loudly rather
    // than pretend success.
    CHECK(reply.find("503") != std::string::npos);
}

int main() { return ::rtsc::test::run_all("rtsc_ui_debug_tests"); }
