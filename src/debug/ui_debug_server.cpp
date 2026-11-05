// In-process UI debug channel. See the header for scope and protocol.
//
// The HTTP layer is deliberately tiny: it parses a request line, headers and a
// Content-Length body, and answers with a JSON envelope. There is no keep-alive
// pipelining, no chunked encoding, no TLS. That is the whole point -- it is a
// loopback development seam, and every line of HTTP machinery is code that can
// only break the debugger, never the product.

#include "rtsc/debug/ui_debug_server.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace rtsc::debug {
namespace {

#if defined(_WIN32)
using Socket = SOCKET;
constexpr Socket kInvalidSocket = INVALID_SOCKET;
void CloseSocket(Socket s) { ::closesocket(s); }
#else
using Socket = int;
constexpr Socket kInvalidSocket = -1;
void CloseSocket(Socket s) { ::close(s); }
#endif

// A parsed request. Only what the channel needs: method, path, body.
struct Request {
    std::string method;
    std::string path;
    std::string body;
    bool ok = false;
};

std::string StatusLine(int code) {
    switch (code) {
        case 200: return "HTTP/1.1 200 OK";
        case 400: return "HTTP/1.1 400 Bad Request";
        case 404: return "HTTP/1.1 404 Not Found";
        case 405: return "HTTP/1.1 405 Method Not Allowed";
        case 503: return "HTTP/1.1 503 Service Unavailable";
        default:  return "HTTP/1.1 500 Internal Server Error";
    }
}

std::string Response(int code, const std::string& json) {
    std::string out = StatusLine(code);
    out += "\r\nContent-Type: application/json\r\nContent-Length: ";
    out += std::to_string(json.size());
    out += "\r\nConnection: close\r\n\r\n";
    out += json;
    return out;
}

// Case-insensitive search for a header name at the start of a line.
bool HeaderStartsWith(const std::string& lower_line, const char* name) {
    const size_t n = std::strlen(name);
    return lower_line.size() >= n && lower_line.compare(0, n, name) == 0;
}

std::string ToLower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

Request ParseRequest(const std::string& raw) {
    Request req;
    const size_t line_end = raw.find("\r\n");
    if (line_end == std::string::npos) return req;
    const std::string request_line = raw.substr(0, line_end);

    // METHOD SP PATH SP VERSION
    const size_t sp1 = request_line.find(' ');
    if (sp1 == std::string::npos) return req;
    const size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return req;
    req.method = request_line.substr(0, sp1);
    req.path = request_line.substr(sp1 + 1, sp2 - sp1 - 1);

    // Headers: find Content-Length. A request without it has an empty body,
    // which /health and unknown paths both tolerate.
    size_t content_length = 0;
    bool have_length = false;
    size_t pos = line_end + 2;
    while (pos < raw.size()) {
        const size_t eol = raw.find("\r\n", pos);
        if (eol == std::string::npos) return req;
        if (eol == pos) break;  // empty line: end of headers
        const std::string line = ToLower(raw.substr(pos, eol - pos));
        if (HeaderStartsWith(line, "content-length:")) {
            const std::string value = line.substr(15);
            const size_t start = value.find_first_not_of(" \t");
            if (start == std::string::npos) return req;
            char* end = nullptr;
            const unsigned long long v =
                std::strtoull(value.c_str() + start, &end, 10);
            if (end == value.c_str() + start) return req;
            // A body larger than this is not a debug batch, it is a mistake.
            constexpr unsigned long long kMaxBody = 1u << 20;
            if (v > kMaxBody) return req;
            content_length = static_cast<size_t>(v);
            have_length = true;
        }
        pos = eol + 2;
    }

    if (have_length) {
        const size_t body_start = pos + 2;
        if (body_start + content_length > raw.size()) return req;  // truncated
        req.body = raw.substr(body_start, content_length);
    }
    req.ok = true;
    return req;
}

// Calls `fn` for every top-level JSON object inside the "commands" array.
//
// This is not a general JSON parser: the channel only needs to hand each command
// object to the host as raw text. What it DOES have to get right is not cutting
// a command in half, so it tracks brace/bracket depth and string state.
bool ForEachCommand(const std::string& body, const std::function<void(const std::string&)>& fn) {
    const size_t key = body.find("\"commands\"");
    if (key == std::string::npos) return false;
    size_t i = body.find('[', key);
    if (i == std::string::npos) return false;
    ++i;  // past '['

    while (i < body.size()) {
        // Skip whitespace and commas between elements.
        while (i < body.size() &&
               (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' ||
                body[i] == '\n' || body[i] == ',')) {
            ++i;
        }
        if (i >= body.size()) break;
        if (body[i] == ']') return true;  // end of the array
        if (body[i] != '{') return false;  // only objects are valid commands

        const size_t start = i;
        int depth = 0;
        bool in_string = false;
        bool escaped = false;
        for (; i < body.size(); ++i) {
            const char c = body[i];
            if (in_string) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    in_string = false;
                }
                continue;
            }
            if (c == '"') {
                in_string = true;
            } else if (c == '{' || c == '[') {
                ++depth;
            } else if (c == '}' || c == ']') {
                --depth;
                if (depth == 0) {
                    fn(body.substr(start, i - start + 1));
                    ++i;
                    break;
                }
            }
        }
        if (depth != 0) return false;  // unbalanced: truncated command
    }
    return true;
}

// Strips the outer braces so the host receives the object body, which is what
// its documented contract promises.
std::string InnerBody(const std::string& object) {
    if (object.size() < 2 || object.front() != '{' || object.back() != '}') {
        return object;
    }
    return object.substr(1, object.size() - 2);
}

}  // namespace

std::string UiDebugServer::HandleRequest(UiDebugHost* host,
                                        const std::string& request) {
    const Request req = ParseRequest(request);
    if (!req.ok) {
        return Response(400, "{\"error\":\"malformed request\"}");
    }
    if (req.method == "GET" && req.path == "/health") {
        return Response(200, "{\"ok\":true}");
    }
    if (req.path != "/debug") {
        return Response(404, "{\"error\":\"unknown path\"}");
    }
    if (req.method != "POST") {
        return Response(405, "{\"error\":\"POST required\"}");
    }
    if (host == nullptr) {
        // No host is bound: the channel is up but cannot inspect anything.
        // Saying 503 is the honest answer; pretending success would make a
        // broken setup look like a passing test.
        return Response(503, "{\"error\":\"no debug host bound\"}");
    }

    std::vector<std::string> commands;
    if (!ForEachCommand(req.body, [&](const std::string& obj) {
            commands.push_back(InnerBody(obj));
        })) {
        return Response(400, "{\"error\":\"bad commands array\"}");
    }
    if (commands.empty()) {
        // An empty batch is legal and answers an empty result list.
        return Response(200, "{\"results\":[]}");
    }

    std::string json = "{\"results\":[";
    for (size_t i = 0; i < commands.size(); ++i) {
        if (i != 0) json += ',';
        std::string result = host->Execute(commands[i]);
        if (result.empty()) result = "\"ok\":true";
        json += '{';
        json += result;
        json += '}';
    }
    json += "]}";
    return Response(200, json);
}

class UiDebugServer::Impl {
 public:
    ~Impl() { Stop(); }

    bool Start(uint16_t port, UiDebugHost* host, std::string& error) {
        host_ = host;
#if defined(_WIN32)
        WSADATA wsa{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            error = "WSAStartup failed";
            return false;
        }
        wsa_started_ = true;
#endif
        listen_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_ == kInvalidSocket) {
            error = "socket() failed";
            return false;
        }
        // Loopback only: this channel has no authentication.
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(listen_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            error = "bind(127.0.0.1:" + std::to_string(port) + ") failed";
            CloseSocket(listen_);
            listen_ = kInvalidSocket;
            return false;
        }
        if (::listen(listen_, 4) != 0) {
            error = "listen() failed";
            CloseSocket(listen_);
            listen_ = kInvalidSocket;
            return false;
        }

        // Report the real port (port 0 asks the OS for one).
        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        if (::getsockname(listen_, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
            port_ = ntohs(bound.sin_port);
        } else {
            port_ = port;
        }

        running_ = true;
        thread_ = std::thread([this] { Serve(); });
        return true;
    }

    void Stop() noexcept {
        if (!running_.exchange(false)) return;
        if (listen_ != kInvalidSocket) {
            CloseSocket(listen_);
            listen_ = kInvalidSocket;
        }
        if (thread_.joinable()) thread_.join();
#if defined(_WIN32)
        if (wsa_started_) {
            ::WSACleanup();
            wsa_started_ = false;
        }
#endif
        port_ = 0;
    }

    uint16_t port() const noexcept { return port_; }

 private:
    void Serve() {
        while (running_) {
            sockaddr_in peer{};
            socklen_t len = sizeof(peer);
            Socket client =
                ::accept(listen_, reinterpret_cast<sockaddr*>(&peer), &len);
            if (client == kInvalidSocket) {
                if (!running_) return;
                continue;  // a spurious accept failure must not kill the thread
            }
            HandleClient(client);
            CloseSocket(client);
        }
    }

    void HandleClient(Socket client) {
        std::string raw;
        char buf[4096];
        // Read until the headers are complete AND the promised body arrived.
        for (;;) {
            const int n = ::recv(client, buf, sizeof(buf), 0);
            if (n <= 0) break;
            raw.append(buf, static_cast<size_t>(n));
            const size_t header_end = raw.find("\r\n\r\n");
            if (header_end == std::string::npos) {
                if (raw.size() > (1u << 20)) break;  // runaway header
                continue;
            }
            const Request probe = ParseRequest(raw);
            // ParseRequest only succeeds once the whole body is present.
            if (probe.ok) break;
            if (raw.size() > (2u << 20)) break;
        }
        const std::string reply = HandleRequest(host_, raw);
        ::send(client, reply.data(), static_cast<int>(reply.size()), 0);
    }

    Socket listen_ = kInvalidSocket;
    std::atomic<bool> running_{false};
    std::thread thread_;
    UiDebugHost* host_ = nullptr;
    uint16_t port_ = 0;
#if defined(_WIN32)
    bool wsa_started_ = false;
#endif
};

UiDebugServer::UiDebugServer() : impl_(std::make_unique<Impl>()) {}
UiDebugServer::~UiDebugServer() = default;

bool UiDebugServer::Start(uint16_t port, UiDebugHost* host, std::string& error) {
    return impl_->Start(port, host, error);
}

void UiDebugServer::Stop() noexcept { impl_->Stop(); }

uint16_t UiDebugServer::port() const noexcept { return impl_->port(); }

}  // namespace rtsc::debug
