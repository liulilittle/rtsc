// RD Gateway ([MS-TSGU]) and RDP-UDP / multitransport wire structures.

#include "rtsc/proto/gateway.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

#include "rtsc/crypto/hash.h"
#include "rtsc/crypto/random.h"

namespace rtsc::proto {

namespace {

std::string ToLower(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

std::string Trim(const std::string& s) {
    size_t begin = 0;
    while (begin < s.size() &&
           std::isspace(static_cast<unsigned char>(s[begin])) != 0) {
        ++begin;
    }
    size_t end = s.size();
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(s[end - 1])) != 0) {
        --end;
    }
    return s.substr(begin, end - begin);
}

// Splits `s` at every `delimiter` that appears outside double-quoted spans (a
// comma inside a quoted auth-param value, e.g. realm="a,b", belongs to the
// value). The fragments are trimmed; empty ones stay (the caller filters).
std::vector<std::string> SplitOutsideQuotes(const std::string& s, char delimiter) {
    std::vector<std::string> parts;
    bool in_quote = false;
    size_t start = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '"') {
            in_quote = !in_quote;
        } else if (s[i] == delimiter && !in_quote) {
            parts.push_back(Trim(s.substr(start, i - start)));
            start = i + 1;
        }
    }
    parts.push_back(Trim(s.substr(start)));
    return parts;
}

// Splits `s` on whitespace outside double-quoted spans (a quoted value may
// contain spaces, e.g. realm="terminal services"). Quotes stay in the tokens
// and are stripped later by the challenge parser.
std::vector<std::string> SplitWhitespaceOutsideQuotes(const std::string& s) {
    std::vector<std::string> parts;
    bool in_quote = false;
    std::string current;
    for (const char c : s) {
        if (c == '"') {
            in_quote = !in_quote;
            current.push_back(c);
        } else if (!in_quote &&
                   std::isspace(static_cast<unsigned char>(c)) != 0) {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) parts.push_back(current);
    return parts;
}

// Strips a pair of surrounding double quotes, if present.
std::string Unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

// True when `s` is an RFC 7235 token68: characters from the token set with at
// most a trailing run of '=' (base64 padding: "TlRMTVNT...=="). This
// distinguishes a token payload from an auth-param ("realm=\"x\"" has a
// non-trailing '=').
bool IsToken68Like(const std::string& s) {
    if (s.empty()) return false;
    const auto is_token68_char = [](char c) {
        const unsigned char u = static_cast<unsigned char>(c);
        return (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') ||
               (u >= '0' && u <= '9') || c == '-' || c == '.' || c == '_' ||
               c == '~' || c == '+' || c == '/';
    };
    const size_t first_eq = s.find('=');
    if (first_eq == std::string::npos) {
        for (const char c : s) {
            if (!is_token68_char(c)) return false;
        }
        return true;
    }
    if (first_eq == 0) return false;
    for (size_t i = 0; i < first_eq; ++i) {
        if (!is_token68_char(s[i])) return false;
    }
    for (size_t i = first_eq; i < s.size(); ++i) {
        if (s[i] != '=') return false;  // '=' only in a trailing run
    }
    return true;
}

// True when a configured value could smuggle a header or a request-line break:
// CR, LF or a NUL byte. These must never reach the wire (header injection).
bool ContainsCrlfOrNul(const std::string& s) {
    return s.find_first_of("\r\n") != std::string::npos ||
           s.find('\0') != std::string::npos;
}

// Finds the next CRLF in `data` (of `size` bytes) starting at `start`; returns
// the index of the CR or npos.
size_t FindCrLf(const uint8_t* data, size_t size, size_t start) {
    for (size_t i = start; i + 1 < size; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n') return i;
    }
    return std::string::npos;
}

std::string BytesToString(const uint8_t* data, size_t size) {
    return std::string(data, data + size);
}

void AppendCrLf(ByteWriter& w) {
    w.u8('\r');
    w.u8('\n');
}

// Validates the Content-Length claims of a message against the entity ceiling.
// The check runs while the digits are scanned, so an announced length is
// rejected before anything is sized from it. The comparison is made before each
// multiply: "value * 10 + digit > limit" is asked as
//   value > limit/10 || (value == limit/10 && digit > limit%10)
// (the overflow-free form), so a ceiling close to SIZE_MAX cannot be bypassed
// by wrapping the accumulator.
Status CheckContentLength(const std::vector<HttpHeader>& headers,
                          const HttpLimits& limits) {
    bool has_length = false;
    size_t length = 0;
    for (const HttpHeader& header : headers) {
        if (ToLower(header.name) != "content-length") continue;
        if (header.value.empty()) return Status::InvalidField;
        size_t value = 0;
        for (char c : header.value) {
            if (c < '0' || c > '9') return Status::InvalidField;
            const size_t digit = static_cast<size_t>(c - '0');
            // Check before the multiply: value * 10 + digit > limit, without
            // overflowing the accumulator (a near-SIZE_MAX ceiling made the
            // previous post-multiply check wrappable).
            if (value > limits.max_entity_bytes / 10 ||
                (value == limits.max_entity_bytes / 10 &&
                 digit > limits.max_entity_bytes % 10)) {
                return Status::InvalidLength;
            }
            value = value * 10 + digit;
        }
        if (has_length && value != length) return Status::InvalidField;
        length = value;
        has_length = true;
    }
    return Status::Ok;
}

}  // namespace

// RFC 4648 base64 encoding (see the declaration in gateway.h). Used for
// RDG-User-Id and for the NTLM / Basic Authorization tokens.
std::string EncodeBase64(const std::string& bytes) {
    static constexpr char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3) {
        const uint32_t v = (static_cast<unsigned char>(bytes[i]) << 16) |
                           (static_cast<unsigned char>(bytes[i + 1]) << 8) |
                           static_cast<unsigned char>(bytes[i + 2]);
        out.push_back(kTable[(v >> 18) & 0x3F]);
        out.push_back(kTable[(v >> 12) & 0x3F]);
        out.push_back(kTable[(v >> 6) & 0x3F]);
        out.push_back(kTable[v & 0x3F]);
    }
    const size_t rest = bytes.size() - i;
    if (rest == 1) {
        const uint32_t v = static_cast<unsigned char>(bytes[i]) << 16;
        out.push_back(kTable[(v >> 18) & 0x3F]);
        out.push_back(kTable[(v >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (rest == 2) {
        const uint32_t v = (static_cast<unsigned char>(bytes[i]) << 16) |
                           (static_cast<unsigned char>(bytes[i + 1]) << 8);
        out.push_back(kTable[(v >> 18) & 0x3F]);
        out.push_back(kTable[(v >> 12) & 0x3F]);
        out.push_back(kTable[(v >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

const char* to_string(TransportType t) {
    switch (t) {
        case TransportType::kUdp: return "UDP";
        case TransportType::kTcp: return "TCP";
    }
    return "unknown";
}

std::vector<uint8_t> RdpConnectionTransport::build(
    const RdpConnectionTransport& t) {
    ByteWriter w;
    w.u32le(t.version);
    w.u32le(static_cast<uint32_t>(t.type));
    return w.take();
}

Status RdpConnectionTransport::parse(const uint8_t* data, size_t size,
                                      RdpConnectionTransport& out) {
    ByteReader r(data, size);
    if (!r.u32le(out.version)) return Status::NeedMoreData;
    uint32_t type = 0;
    if (!r.u32le(type)) return Status::NeedMoreData;
    out.type = static_cast<TransportType>(type);
    return Status::Ok;
}

// ---- HTTP --------------------------------------------------------------------

Status HttpRequestLine::parse(const uint8_t* data, size_t size,
                              HttpRequestLine& out, size_t& consumed) {
    consumed = 0;
    const size_t eol = FindCrLf(data, size, 0);
    if (eol == std::string::npos) return Status::NeedMoreData;
    const std::string line = BytesToString(data, eol);
    const size_t first = line.find(' ');
    if (first == std::string::npos) return Status::InvalidField;
    const size_t second = line.find(' ', first + 1);
    if (second == std::string::npos) return Status::InvalidField;
    out.method = line.substr(0, first);
    out.target = line.substr(first + 1, second - first - 1);
    out.version = line.substr(second + 1);
    consumed = eol + 2;
    return Status::Ok;
}

Status HttpMessage::parse(const uint8_t* data, size_t size, HttpMessage& out,
                          size_t& consumed) {
    return HttpMessage::parse(data, size, out, consumed, HttpLimits{});
}

Status HttpMessage::parse(const uint8_t* data, size_t size, HttpMessage& out,
                          size_t& consumed, const HttpLimits& limits) {
    consumed = 0;
    // The response head ends at the first empty line (CRLF CRLF). Every step is
    // bounded before it can grow anything: the status line, each header line and
    // the completed head are all checked against the configured ceilings, and a
    // violation is a hard failure rather than NeedMoreData (waiting for more
    // bytes is what would keep growing the caller's buffer).
    const size_t status_eol = FindCrLf(data, size, 0);
    if (status_eol == std::string::npos) {
        return size > limits.max_head_bytes ? Status::InvalidLength
                                            : Status::NeedMoreData;
    }
    if (status_eol + 2 > limits.max_head_bytes) return Status::InvalidLength;

    size_t status_consumed = 0;
    HttpRequestLine status;
    const Status st = HttpRequestLine::parse(data, size, status, status_consumed);
    if (st != Status::Ok) return st;
    if (status.method.rfind("HTTP/", 0) != 0) return Status::InvalidType;

    // The status line carries the code and the reason phrase. Build into a local
    // message so a failed parse never leaves stale headers behind.
    HttpMessage message;
    message.status_code = std::atoi(status.target.c_str());
    message.reason = Trim(status.version);

    size_t offset = status_consumed;
    size_t count = 0;
    for (;;) {
        const size_t eol = FindCrLf(data, size, offset);
        if (eol == std::string::npos) {
            return size > limits.max_head_bytes ? Status::InvalidLength
                                                : Status::NeedMoreData;
        }
        if (eol == offset) {
            const size_t head_end = offset + 2;
            if (head_end > limits.max_head_bytes) return Status::InvalidLength;
            const Status entity = CheckContentLength(message.headers, limits);
            if (entity != Status::Ok) return entity;
            out = std::move(message);
            consumed = head_end;
            return Status::Ok;
        }
        // A head with more lines than the ceiling is rejected on the count alone,
        // even when it fits the byte ceiling: each line costs a std::string plus
        // a vector slot.
        if (count >= limits.max_header_count) return Status::InvalidLength;
        const std::string line = BytesToString(data + offset, eol - offset);
        const size_t colon = line.find(':');
        if (colon == std::string::npos) return Status::InvalidField;
        HttpHeader h;
        h.name = Trim(line.substr(0, colon));
        h.value = Trim(line.substr(colon + 1));
        if (h.name.empty()) return Status::InvalidField;
        message.headers.push_back(std::move(h));
        ++count;
        offset = eol + 2;
        if (offset > limits.max_head_bytes) return Status::InvalidLength;
    }
}

const HttpHeader* HttpMessage::find(const std::string& name) const {
    const std::string want = ToLower(name);
    for (const auto& h : headers) {
        if (ToLower(h.name) == want) return &h;
    }
    return nullptr;
}

std::string HttpMessage::header_or(const std::string& name,
                                   const std::string& fallback) const {
    const HttpHeader* h = find(name);
    return h != nullptr ? h->value : fallback;
}

std::vector<uint8_t> BuildHttpConnectRequest(const ConnectRequestOptions& o) {
    // The configured target and every header value must be injection-free;
    // otherwise report failure as an empty request the caller can detect.
    if (ContainsCrlfOrNul(o.target) || ContainsCrlfOrNul(o.gateway_host) ||
        ContainsCrlfOrNul(o.user_agent) || ContainsCrlfOrNul(o.cookie) ||
        ContainsCrlfOrNul(o.authorization)) {
        return {};
    }
    ByteWriter w;
    const std::string request_line =
        "CONNECT " + o.target + " HTTP/1.1";
    w.bytes(reinterpret_cast<const uint8_t*>(request_line.data()),
            request_line.size());
    AppendCrLf(w);

    const auto write_header = [&w](const std::string& name,
                                   const std::string& value) {
        const std::string line = name + ": " + value;
        w.bytes(reinterpret_cast<const uint8_t*>(line.data()), line.size());
        AppendCrLf(w);
    };

    write_header("Host", o.gateway_host);
    write_header("User-Agent", o.user_agent);
    // The transport selector: RDP_CONNECTION_TRANSPORT.transportType, carried
    // as the gateway request's transport header. TCP is the default; UDP is
    // requested for a UDP side channel.
    char transport[16];
    std::snprintf(transport, sizeof(transport), "0x%08X",
                  static_cast<unsigned>(o.transport));
    write_header("X-Transport", transport);
    write_header("Content-Length", "0");
    if (!o.cookie.empty()) write_header("Cookie", o.cookie);
    if (!o.authorization.empty()) write_header("Authorization", o.authorization);
    AppendCrLf(w);
    return w.take();
}

std::vector<uint8_t> BuildRdgChannelRequest(const RdgChannelRequestOptions& o,
                                            std::string* out_websocket_key) {
    // Every configured value (the method belongs to the request line) must be
    // injection-free, and the method must not be empty (an empty method would
    // yield a request line with a leading space). A violation is reported as
    // an empty request vector the caller can detect.
    if (o.method.empty() || ContainsCrlfOrNul(o.method) ||
        ContainsCrlfOrNul(o.gateway_host) ||
        ContainsCrlfOrNul(o.user_agent) || ContainsCrlfOrNul(o.connection_id) ||
        ContainsCrlfOrNul(o.correlation_id) || ContainsCrlfOrNul(o.user_id) ||
        ContainsCrlfOrNul(o.client_generation) ||
        ContainsCrlfOrNul(o.load_balancer_cookie) ||
        ContainsCrlfOrNul(o.app_build) || ContainsCrlfOrNul(o.auth_scheme) ||
        ContainsCrlfOrNul(o.diagnostics_info) ||
        ContainsCrlfOrNul(o.websocket_key) ||
        ContainsCrlfOrNul(o.authorization)) {
        return {};
    }
    ByteWriter w;
    const std::string request_line =
        o.method + " /remoteDesktopGateway/ HTTP/1.1";
    w.bytes(reinterpret_cast<const uint8_t*>(request_line.data()),
            request_line.size());
    AppendCrLf(w);

    const auto write_header = [&w](const std::string& name,
                                   const std::string& value) {
        const std::string line = name + ": " + value;
        w.bytes(reinterpret_cast<const uint8_t*>(line.data()), line.size());
        AppendCrLf(w);
    };

    // D1: Host is the gateway authority (host:port), never the URL path. The
    // factory's request goes to "%s://%s:%hu%s" where the authority part is
    // what Host must carry.
    write_header("Host", o.gateway_host);
    write_header("User-Agent", o.user_agent);
    write_header("Accept", "*/*");
    write_header("Cache-Control", "no-cache");
    // Transfer coding splits by direction (doc: gateway-header-direction-ruling.md
    // FUN_1801c3818 :170-188): the IN channel streams with Transfer-Encoding:
    // chunked (and no Content-Length); the OUT channel is a plain Keep-Alive
    // request with an empty body.
    if (o.direction == RdgChannelDirection::kIn) {
        write_header("Transfer-Encoding", "chunked");
    } else {
        // The OUT request is a plain Keep-Alive request UNLESS an RFC 6455
        // upgrade is asked; the upgrade branch below then writes the single
        // "Connection: Upgrade" header. Never emit both (a duplicate
        // Connection header is ambiguous to a proxy).
        if (!o.request_websocket_upgrade) {
            write_header("Connection", "Keep-Alive");
        }
        // Content-Length: 0 -- the OUT request has no entity body. This is
        // UNVERIFIED against the factory binary: mstscax.dll has no explicit
        // Content-Length / Host strings (0 hits; WinHTTP generates them
        // implicitly), so this header is our own equivalent, not "as shipped".
        write_header("Content-Length", "0");
    }

    // Headers sent on both channels (ruling :74/:248/:226).
    write_header(kRdgConnectionIdHeader, o.connection_id);
    if (!o.diagnostics_info.empty()) {
        write_header(kRdgDiagnosticsInfoHeader, o.diagnostics_info);
    }
    if (!o.correlation_id.empty()) {
        write_header(kRdgCorrelationIdHeader, o.correlation_id);
    }

    if (o.direction == RdgChannelDirection::kIn) {
        // RDG-User-Id is IN-only and carries the base64 form of the user name
        // (ruling :544/:568).
        if (!o.user_id.empty()) {
            write_header(kRdgUserIdHeader, EncodeBase64(o.user_id));
        }
    } else {
        // OUT-only header set (ruling: `local_298 == 0` branch, :299-383 plus
        // the load balancer cookie at :77-95).
        if (!o.client_generation.empty()) {
            write_header(kRdgClientGenerationHeader, o.client_generation);
        }
        if (!o.app_build.empty()) {
            write_header(kRdgClientAppBuildHeader, o.app_build);
        }
        if (!o.load_balancer_cookie.empty()) {
            write_header(kRdgLoadBalancerCookieHeader,
                         o.load_balancer_cookie);
        }
    }

    // Optional header with no factory value evidence (UNVERIFIED); configurable
    // on both channels.
    if (!o.auth_scheme.empty()) write_header(kRdgAuthSchemeHeader, o.auth_scheme);

    // Optional client authentication (NTLM / Basic), added by RdgspTransport's
    // 401 handling. The value is in the CRLF / NUL injection chain above.
    if (!o.authorization.empty()) write_header("Authorization", o.authorization);

    // Optional RFC 6455 upgrade ask on the OUT channel. The factory drives this
    // with WinHTTP's UPGRADE_TO_WEB_SOCKET (which generates the exact headers
    // implicitly), so this explicit client-side layout is standard [RFC 6455]
    // framing and UNVERIFIED against the shipped binary.
    if (o.request_websocket_upgrade) {
        write_header("Connection", "Upgrade");
        write_header("Upgrade", "websocket");
        // A caller-pinned key (websocket_key) is used verbatim; an empty one
        // gets a fresh 16-byte base64 nonce (RFC 6455 4.1). Either way the
        // key actually emitted is reported through out_websocket_key so the
        // 101's Sec-WebSocket-Accept can be recomputed and checked.
        std::string key = o.websocket_key;
        if (key.empty()) {
            uint8_t key_bytes[16];
            if (rtsc::crypto::RandomBytes(key_bytes, sizeof(key_bytes))) {
                key = EncodeBase64(std::string(
                    reinterpret_cast<const char*>(key_bytes),
                    sizeof(key_bytes)));
            } else {
                // CSPRNG failure: the upgrade still proceeds with a fixed
                // ephemeral key (freshness, not a secret); failure is a local
                // environment issue, not a protocol error.
                key = EncodeBase64("rtsc-gw-fallback-key!!");
            }
        }
        if (out_websocket_key != nullptr) *out_websocket_key = key;
        write_header("Sec-WebSocket-Key", key);
        write_header("Sec-WebSocket-Version", "13");
    }

    // IN-channel retry mode (ruling :264-269, IN-only + retry flag).
    if (o.direction == RdgChannelDirection::kIn && o.retry_count > 0) {
        write_header(kRdgInchannelRetryModeHeader,
                     "IN_CHANNEL_RETRY_COUNT_" + std::to_string(o.retry_count));
    }

    AppendCrLf(w);
    return w.take();
}

// RFC 6455 4.1: accept = base64(SHA1(key + GUID)). The GUID is the fixed
// handshake magic; base64 payloads are case-significant, so the comparison the
// transport performs against the response header is exact.
std::string ComputeWebSocketAccept(const std::string& key) {
    const char* const kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const std::string input = key + kWebSocketGuid;
    const std::array<uint8_t, 20> digest =
        rtsc::crypto::Sha1(reinterpret_cast<const uint8_t*>(input.data()),
                           input.size());
    return EncodeBase64(std::string(
        reinterpret_cast<const char*>(digest.data()), digest.size()));
}

// ---- chunked transfer coding -------------------------------------------------

const char* to_string(ChunkedError e) {
    switch (e) {
        case ChunkedError::kNone: return "none";
        case ChunkedError::kTruncated: return "truncated";
        case ChunkedError::kInvalidHex: return "invalid hex";
        case ChunkedError::kNegativeLength: return "negative length";
        case ChunkedError::kChunkTooLarge: return "chunk too large";
        case ChunkedError::kTotalTooLarge: return "total too large";
        case ChunkedError::kInvalidField: return "invalid field";
    }
    return "unknown";
}

std::vector<uint8_t> ChunkedEncode(const uint8_t* data, size_t size) {
    ByteWriter w;
    if (size > 0) {
        char size_line[32];
        std::snprintf(size_line, sizeof(size_line), "%zx",
                      static_cast<size_t>(size));
        const size_t line_len = std::strlen(size_line);
        w.bytes(reinterpret_cast<const uint8_t*>(size_line), line_len);
        AppendCrLf(w);
        w.bytes(data, size);
        AppendCrLf(w);
    }
    w.u8('0');
    AppendCrLf(w);
    AppendCrLf(w);
    return w.take();
}

std::vector<uint8_t> ChunkedEncodeChunk(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) return {};
    ByteWriter w;
    char size_line[32];
    std::snprintf(size_line, sizeof(size_line), "%zx",
                  static_cast<size_t>(size));
    const size_t line_len = std::strlen(size_line);
    w.bytes(reinterpret_cast<const uint8_t*>(size_line), line_len);
    AppendCrLf(w);
    w.bytes(data, size);
    AppendCrLf(w);
    return w.take();
}

ChunkedDecoder::ChunkedDecoder(size_t max_chunk_bytes, size_t max_total_bytes)
    : max_chunk_bytes_(max_chunk_bytes), max_total_bytes_(max_total_bytes) {}

// Parses one "[hex-digits][chunk-ext]" size line. Empty/extenseless handling
// is the caller's (the state machine knows whether non-empty was required).
ChunkedError ChunkedDecoder::ParseSizeLine(const std::string& line,
                                           size_t& out) const {
    // RFC 9112: chunk-size = 1*HEXDIG. The first character must be a hex
    // digit (leading whitespace is rejected: the grammar has none), and after
    // the digits only a ';' chunk-extension may follow. Any other character
    // ("0x10" -> 'x', "4 garbage" -> ' ', "+4" -> '+') is a hard error, so a
    // "0x10" size line cannot be mis-read as a terminal 0-chunk.
    uint64_t value = 0;
    int digits = 0;
    size_t i = 0;
    for (; i < line.size(); ++i) {
        const char c = line[i];
        int nibble = -1;
        if (c >= '0' && c <= '9') {
            nibble = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            nibble = 10 + (c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            nibble = 10 + (c - 'A');
        } else {
            break;  // not a hex digit: see the ';'-only rule below
        }
        if (value > (0xFFFFFFFFFFFFFFFFull - nibble) / 16) {
            return ChunkedError::kNegativeLength;  // would wrap past 2^64
        }
        value = value * 16 + static_cast<uint64_t>(nibble);
        ++digits;
    }
    if (digits == 0) return ChunkedError::kInvalidHex;
    if (i < line.size() && line[i] != ';') return ChunkedError::kInvalidHex;
    if (value >= (1ull << 63)) return ChunkedError::kNegativeLength;
    if (value > static_cast<uint64_t>(max_chunk_bytes_)) {
        return ChunkedError::kChunkTooLarge;
    }
    out = static_cast<size_t>(value);
    return ChunkedError::kNone;
}

std::vector<uint8_t> ChunkedDecoder::Feed(const uint8_t* data, size_t size) {
    std::vector<uint8_t> out;
    if (data == nullptr || size == 0) return out;
    if (error_ != ChunkedError::kNone || finished_) return out;

    buffer_.insert(buffer_.end(), data, data + size);

    // Largest single size line we will buffer: 16 hex digits plus the
    // extension run. A peer that never sends a newline past this is rejected.
    constexpr size_t kMaxSizeLineBytes = 256;
    constexpr size_t kMaxTrailerBytes = 64 * 1024;

    for (;;) {
        if (state_ == State::kSize) {
            const char* base = reinterpret_cast<const char*>(buffer_.data());
            const std::string_view view(base, buffer_.size());
            const size_t nl = view.find('\n', 0);
            if (nl == std::string_view::npos) {
                if (buffer_.size() > kMaxSizeLineBytes) {
                    error_ = ChunkedError::kInvalidField;
                    buffer_.clear();
                    return out;
                }
                return out;  // need more data
            }
            // RFC 9112: every line ends with CRLF; a lone LF is invalid (a
            // lone '\r' just means the LF half is still in flight).
            const bool cr = nl > 0 && view[nl - 1] == '\r';
            if (!cr) {
                error_ = ChunkedError::kInvalidField;
                buffer_.clear();
                return out;
            }
            const size_t line_end = nl - 1;
            const std::string line(view.data(), line_end);

            size_t chunk;
            const ChunkedError e = ParseSizeLine(line, chunk);
            if (e != ChunkedError::kNone) {
                error_ = e;
                buffer_.clear();
                return out;
            }
            if (chunk == 0) {
                state_ = State::kTrailers;
            } else {
                if (decoded_total_ > max_total_bytes_ ||
                    chunk > max_total_bytes_ - decoded_total_) {
                    error_ = ChunkedError::kTotalTooLarge;
                    buffer_.clear();
                    return out;
                }
                pending_ = chunk;
                state_ = State::kData;
            }
            buffer_.erase(buffer_.begin(),
                          buffer_.begin() +
                              static_cast<std::ptrdiff_t>(nl + 1));
            continue;
        }

        if (state_ == State::kData) {
            const size_t take = (std::min)(pending_, buffer_.size());
            out.insert(out.end(), buffer_.begin(),
                       buffer_.begin() + static_cast<std::ptrdiff_t>(take));
            buffer_.erase(buffer_.begin(),
                          buffer_.begin() + static_cast<std::ptrdiff_t>(take));
            pending_ -= take;
            decoded_total_ += take;
            if (pending_ == 0) state_ = State::kChunkEnd;
            if (buffer_.empty()) return out;
            continue;
        }

        if (state_ == State::kChunkEnd) {
            // Each chunk's data must be followed by a CRLF (RFC 9112); a lone
            // '\r' just means the LF half is still in flight.
            if (buffer_.size() >= 2 && buffer_[0] == '\r' &&
                buffer_[1] == '\n') {
                buffer_.erase(buffer_.begin(), buffer_.begin() + 2);
            } else if (buffer_.size() == 1 && buffer_[0] == '\r') {
                return out;
            } else {
                error_ = ChunkedError::kInvalidField;
                buffer_.clear();
                return out;
            }
            state_ = State::kSize;
            continue;
        }

        if (state_ == State::kTrailers) {
            // After the 0-chunk: header lines until an empty line. The trailing
            // header fields are skipped, bounded so they cannot be a memory
            // sink in themselves.
            const char* base = reinterpret_cast<const char*>(buffer_.data());
            const std::string_view view(base, buffer_.size());
            const size_t nl = view.find('\n', 0);
            if (nl == std::string_view::npos) {
                if (buffer_.size() > kMaxTrailerBytes) {
                    error_ = ChunkedError::kInvalidField;
                    buffer_.clear();
                    return out;
                }
                return out;  // need more data
            }
            // RFC 9112: trailer lines end with CRLF.
            const bool cr = nl > 0 && view[nl - 1] == '\r';
            if (!cr) {
                error_ = ChunkedError::kInvalidField;
                buffer_.clear();
                return out;
            }
            const size_t line_end = nl - 1;
            const bool empty = line_end == 0;
            buffer_.erase(buffer_.begin(),
                          buffer_.begin() +
                              static_cast<std::ptrdiff_t>(nl + 1));
            if (empty) {
                state_ = State::kDone;
                finished_ = true;
                return out;
            }
            continue;
        }

        // State::kDone: the terminal 0-chunk (and any trailers) were consumed.
        return out;
    }
}

std::vector<uint8_t> ChunkedDecoder::Feed(const std::vector<uint8_t>& bytes) {
    return Feed(bytes.data(), bytes.size());
}

void ChunkedDecoder::EndOfStream() {
    if (finished_) return;
    if (error_ == ChunkedError::kNone) error_ = ChunkedError::kTruncated;
}

bool IsChunkedBody(const HttpMessage& message) {
    const HttpHeader* transfer = message.find("transfer-encoding");
    if (transfer == nullptr) return false;
    // The value may be a comma-separated coding list ("gzip, chunked"); tokens
    // are compared case-insensitively.
    for (const std::string& coding : SplitOutsideQuotes(transfer->value, ',')) {
        if (ToLower(Trim(coding)) == "chunked") return true;
    }
    return false;
}

uint32_t MapGatewayStatusToHresult(int status_code, bool password_expired) {
    // Evidence: mstscax FUN_1801bdd8c.
    if (password_expired) return 0x80070532;  // ERROR_PASSWORD_EXPIRED
    switch (status_code) {
        case 401: return 0x80070005;          // E_ACCESSDENIED
        case 407: return 0x800706C1;          // ERROR_PROXY_ACCESS_DENIED
        case 502:
        case 504: return 0x800706BA;          // ERROR_SERVER_UNAVAILABLE
        default:
            return 0x80190000u |
                   static_cast<uint32_t>(status_code);
    }
}

// ---- RFC 6455 WebSocket framing -------------------------------------------

bool IsWebSocketControlOpcode(WebSocketOpcode opcode) {
    const auto raw = static_cast<uint8_t>(opcode);
    return raw >= 0x08 && raw <= 0x0F;
}

const char* to_string(WebSocketError e) {
    switch (e) {
        case WebSocketError::kNone: return "none";
        case WebSocketError::kNeedMoreData: return "need more data";
        case WebSocketError::kTruncated: return "truncated";
        case WebSocketError::kInvalidOpcode: return "invalid opcode";
        case WebSocketError::kReservedBits: return "reserved bits";
        case WebSocketError::kControlFrameNotFinal: return "control frame not final";
        case WebSocketError::kControlFrameTooLarge: return "control frame too large";
        case WebSocketError::kPayloadTooLarge: return "payload too large";
        case WebSocketError::kNonMinimalLength: return "non-minimal length";
    }
    return "unknown";
}

std::vector<uint8_t> WebSocketEncodeClientFrame(WebSocketOpcode opcode,
                                                const uint8_t* payload,
                                                size_t size, uint32_t mask_key) {
    // [RFC 6455] section 5.2: a frame header is FIN (this codec always sends
    // complete frames) + RSV 0 + opcode, then the MASK bit and the payload
    // length. Client frames are always masked (section 5.3).
    ByteWriter w;
    w.u8(static_cast<uint8_t>(0x80u | static_cast<uint8_t>(opcode)));
    if (size <= 125) {
        w.u8(static_cast<uint8_t>(0x80u | size));
    } else if (size <= 0xFFFF) {
        w.u8(static_cast<uint8_t>(0x80u | 126u));
        w.u16be(static_cast<uint16_t>(size));
    } else {
        w.u8(static_cast<uint8_t>(0x80u | 127u));
        w.u64be(static_cast<uint64_t>(size));
    }
    // [RFC 6455] section 5.3: the 32-bit mask is transmitted as its four
    // octets most-significant byte first. The caller passes the mask as a
    // value whose bytes, in memory order, are what the key bytes read on the
    // wire (so mask 0x37FA213D writes 37 FA 21 3D, per the RFC example).
    const uint8_t key[4] = {static_cast<uint8_t>((mask_key >> 24) & 0xFF),
                            static_cast<uint8_t>((mask_key >> 16) & 0xFF),
                            static_cast<uint8_t>((mask_key >> 8) & 0xFF),
                            static_cast<uint8_t>(mask_key & 0xFF)};
    w.bytes(key, sizeof(key));
    for (size_t i = 0; i < size; ++i) {
        w.u8(static_cast<uint8_t>(payload[i] ^ key[i % 4]));
    }
    return w.take();
}

std::vector<WebSocketFrame> WebSocketFrameDecoder::Feed(const uint8_t* data,
                                                       size_t size) {
    std::vector<WebSocketFrame> out;
    if (data == nullptr || size == 0) return out;
    if (error_ != WebSocketError::kNone) return out;

    buffer_.insert(buffer_.end(), data, data + size);

    for (;;) {
        // Header byte 0: FIN | RSV1-3 | opcode.
        if (buffer_.size() < 2) return out;
        const uint8_t b0 = buffer_[0];
        const bool fin = (b0 & 0x80) != 0;
        const bool rsv = (b0 & 0x70) != 0;
        const uint8_t opcode_raw = b0 & 0x0F;
        if (rsv) {
            error_ = WebSocketError::kReservedBits;
            buffer_.clear();
            return out;
        }
        if (opcode_raw != 0x0 && opcode_raw != 0x1 && opcode_raw != 0x2 &&
            opcode_raw != 0x8 && opcode_raw != 0x9 && opcode_raw != 0xA) {
            error_ = WebSocketError::kInvalidOpcode;
            buffer_.clear();
            return out;
        }
        const WebSocketOpcode opcode = static_cast<WebSocketOpcode>(opcode_raw);

        // Header byte 1: MASK | 7-bit length (or an extended-length marker).
        const uint8_t b1 = buffer_[1];
        const bool masked = (b1 & 0x80) != 0;
        const uint8_t len7 = b1 & 0x7F;
        size_t header_size = 2;
        uint64_t payload_len = len7;
        if (len7 == 126 || len7 == 127) {
            const size_t ext = len7 == 126 ? 2 : 8;
            if (buffer_.size() < 2 + ext) return out;
            uint64_t extended = 0;
            for (size_t i = 0; i < ext; ++i) {
                extended = (extended << 8) | buffer_[2 + i];
            }
            // [RFC 6455] section 5.2: the length encoding MUST be minimal.
            if ((len7 == 126 && extended <= 125) ||
                (len7 == 127 && extended <= 0xFFFF)) {
                error_ = WebSocketError::kNonMinimalLength;
                buffer_.clear();
                return out;
            }
            header_size = 2 + ext;
            payload_len = extended;
        }

        const bool control = IsWebSocketControlOpcode(opcode);
        if (control) {
            if (!fin) {
                error_ = WebSocketError::kControlFrameNotFinal;
                buffer_.clear();
                return out;
            }
            // Control frames MUST carry at most 125 bytes ([RFC 6455] 5.5).
            // With a minimal encoding, len7 == 126/127 is already proof of an
            // oversized payload; an explicit check also covers the direct case.
            if (payload_len > 125) {
                error_ = WebSocketError::kControlFrameTooLarge;
                buffer_.clear();
                return out;
            }
        }

        // The 16 MiB per-frame ceiling is enforced on the announced length,
        // before any payload could be buffered in proportion to it.
        if (payload_len > kMaxWebSocketPayloadBytes) {
            error_ = WebSocketError::kPayloadTooLarge;
            buffer_.clear();
            return out;
        }

        const size_t key_size = masked ? 4 : 0;
        const size_t frame_size = header_size + key_size +
                                  static_cast<size_t>(payload_len);
        if (buffer_.size() < frame_size) return out;

        WebSocketFrame frame;
        frame.fin = fin;
        frame.opcode = opcode;
        frame.payload.assign(
            buffer_.begin() + static_cast<std::ptrdiff_t>(header_size + key_size),
            buffer_.begin() + static_cast<std::ptrdiff_t>(frame_size));
        if (masked) {
            const uint8_t* key = buffer_.data() + header_size;
            for (size_t i = 0; i < frame.payload.size(); ++i) {
                frame.payload[i] ^= key[i % 4];
            }
        }
        buffer_.erase(buffer_.begin(),
                      buffer_.begin() + static_cast<std::ptrdiff_t>(frame_size));
        ++frames_parsed_;
        out.push_back(std::move(frame));
        // Continue if more frames were buffered in this feed.
    }
}

std::vector<WebSocketFrame> WebSocketFrameDecoder::Feed(
    const std::vector<uint8_t>& bytes) {
    return Feed(bytes.data(), bytes.size());
}

void WebSocketFrameDecoder::EndOfStream() {
    if (failed()) return;
    // A half-consumed frame (header or payload) is a mid-frame truncation.
    if (!buffer_.empty()) error_ = WebSocketError::kTruncated;
}

// ---- authentication ----------------------------------------------------------

Status RdgAuthChallenge::parse_www_authenticate(const std::string& value,
                                                 RdgAuthChallenge& out) {
    const std::string trimmed = Trim(value);
    if (trimmed.empty()) return Status::InvalidField;
    const size_t space = trimmed.find_first_of(" \t");
    RdgAuthChallenge result;
    if (space == std::string::npos) {
        result.scheme = trimmed;
        out = std::move(result);
        return Status::Ok;
    }
    result.scheme = trimmed.substr(0, space);
    const std::string rest = Trim(trimmed.substr(space + 1));
    if (rest.empty()) return Status::InvalidField;
    // An RFC 7235 challenge body is either a single token68 ("NTLM <base64>",
    // whose trailing '=' is padding) or a list of auth-params, never a mixture.
    const std::vector<std::string> tokens = SplitWhitespaceOutsideQuotes(rest);
    if (tokens.size() == 1 && IsToken68Like(tokens[0])) {
        result.token = rest;
        out = std::move(result);
        return Status::Ok;
    }
    for (const std::string& token : tokens) {
        const size_t eq = token.find('=');
        if (eq == std::string::npos) return Status::InvalidField;
        const std::string key = Trim(token.substr(0, eq));
        if (key.empty()) return Status::InvalidField;
        const std::string raw = Trim(token.substr(eq + 1));
        const std::string param_value = Unquote(raw);
        result.params.push_back({key, param_value});
        if (ToLower(key) == "realm") result.realm = param_value;
    }
    out = std::move(result);
    return Status::Ok;
}

Status RdgAuthChallenge::parse_challenges(const std::string& header_value,
                                          std::vector<RdgAuthChallenge>& out) {
    std::vector<std::string> fragments = SplitOutsideQuotes(header_value, ',');
    // Drop empty fragments left by repeated commas / trailing commas.
    fragments.erase(
        std::remove_if(fragments.begin(), fragments.end(),
                       [](const std::string& s) { return Trim(s).empty(); }),
        fragments.end());
    if (fragments.empty()) return Status::InvalidField;
    for (const std::string& fragment : fragments) {
        RdgAuthChallenge challenge;
        const Status st = parse_www_authenticate(fragment, challenge);
        if (st != Status::Ok) return st;
        out.push_back(std::move(challenge));
    }
    return Status::Ok;
}

Status ParseWwwAuthenticateHeaders(const HttpMessage& message,
                                   std::vector<RdgAuthChallenge>& out) {
    bool found = false;
    for (const HttpHeader& header : message.headers) {
        if (ToLower(header.name) != "www-authenticate") continue;
        found = true;
        const Status st =
            RdgAuthChallenge::parse_challenges(header.value, out);
        if (st != Status::Ok) return st;
    }
    return found ? Status::Ok : Status::InvalidField;
}

std::string RdgAuthRequest::header_value() const {
    if (scheme.empty()) return token;
    return scheme + " " + token;
}

std::vector<uint8_t> BuildRdgSoapEnvelope(const RdgSoapOptions& o) {
    ByteWriter w;
    const auto put = [&w](const std::string& s) {
        w.bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    };
    put("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n");
    put("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" ");
    put("xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" ");
    put("xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">");
    put("\r\n");
    put("  <s:Header>\r\n");
    put("    <wsa:Action s:mustUnderstand=\"1\">" + o.action + "</wsa:Action>\r\n");
    put("    <wsa:MessageID>urn:uuid:" + o.message_id + "</wsa:MessageID>\r\n");
    put("    <wsa:To s:mustUnderstand=\"1\">" + o.service + "</wsa:To>\r\n");
    put("  </s:Header>\r\n");
    put("  <s:Body>\r\n");
    put("    <wsse:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">");
    put(o.token);
    put("</wsse:BinarySecurityToken>\r\n");
    put("  </s:Body>\r\n");
    put("</s:Envelope>\r\n");
    return w.take();
}

// ---- RDP-UDP -----------------------------------------------------------------

const char* to_string(UdpMode mode) {
    switch (mode) {
        case UdpMode::kReliable: return "reliable";
        case UdpMode::kUnreliable: return "unreliable";
    }
    return "unknown";
}

std::vector<uint8_t> UdpFecHeader::build(const UdpFecHeader& h) {
    ByteWriter w;
    w.u32le(h.source_ack);
    w.u16le(h.receive_window_size);
    w.u16le(h.flags);
    return w.take();
}

Status UdpFecHeader::parse(const uint8_t* data, size_t size, UdpFecHeader& out) {
    ByteReader r(data, size);
    if (!r.u32le(out.source_ack)) return Status::NeedMoreData;
    if (!r.u16le(out.receive_window_size)) return Status::NeedMoreData;
    if (!r.u16le(out.flags)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> UdpSourcePayloadHeader::build(
    const UdpSourcePayloadHeader& h) {
    ByteWriter w;
    w.u32le(h.coded);
    w.u32le(h.source_start);
    return w.take();
}

Status UdpSourcePayloadHeader::parse(const uint8_t* data, size_t size,
                                     UdpSourcePayloadHeader& out) {
    ByteReader r(data, size);
    if (!r.u32le(out.coded)) return Status::NeedMoreData;
    if (!r.u32le(out.source_start)) return Status::NeedMoreData;
    return Status::Ok;
}

std::vector<uint8_t> UdpDataFrame::build(const UdpDataFrame& f) {
    std::vector<uint8_t> fec = UdpFecHeader::build(f.fec);
    std::vector<uint8_t> src = UdpSourcePayloadHeader::build(f.source);
    std::vector<uint8_t> out;
    out.reserve(fec.size() + src.size() + f.payload.size());
    out.insert(out.end(), fec.begin(), fec.end());
    out.insert(out.end(), src.begin(), src.end());
    out.insert(out.end(), f.payload.begin(), f.payload.end());
    return out;
}

Status UdpDataFrame::parse(const uint8_t* data, size_t size, UdpDataFrame& out) {
    UdpFecHeader fec;
    if (UdpFecHeader::parse(data, size, fec) != Status::Ok) {
        return Status::NeedMoreData;
    }
    if (!fec.has_flag(kUdpFlagData)) return Status::InvalidType;
    if (size < UdpFecHeader::kSize + UdpSourcePayloadHeader::kSize) {
        return Status::NeedMoreData;
    }
    UdpSourcePayloadHeader src;
    if (UdpSourcePayloadHeader::parse(data + UdpFecHeader::kSize,
                                      size - UdpFecHeader::kSize, src) !=
        Status::Ok) {
        return Status::NeedMoreData;
    }
    out.fec = fec;
    out.source = src;
    out.payload.assign(data + UdpFecHeader::kSize + UdpSourcePayloadHeader::kSize,
                       data + size);
    return Status::Ok;
}

std::vector<uint8_t> UdpAckFrame::build(const UdpAckFrame& f) {
    return UdpFecHeader::build(f.fec);
}

Status UdpAckFrame::parse(const uint8_t* data, size_t size, UdpAckFrame& out) {
    UdpFecHeader fec;
    if (UdpFecHeader::parse(data, size, fec) != Status::Ok) {
        return Status::NeedMoreData;
    }
    if (!fec.has_flag(kUdpFlagAck)) return Status::InvalidType;
    out.fec = fec;
    return Status::Ok;
}

std::vector<uint8_t> UdpSyn::build(const UdpSyn& s) {
    ByteWriter w;
    std::vector<uint8_t> fec = UdpFecHeader::build(s.fec);
    w.bytes(fec.data(), fec.size());
    w.u32le(s.initial_sequence_number);
    w.u16le(s.upstream_mtu);
    w.u16le(s.downstream_mtu);
    if (s.has_synex) {
        w.u16le(s.synex_flags);
        w.u16le(s.udp_version);
    }
    return w.take();
}

Status UdpSyn::parse(const uint8_t* data, size_t size, UdpSyn& out) {
    UdpFecHeader fec;
    if (UdpFecHeader::parse(data, size, fec) != Status::Ok) {
        return Status::NeedMoreData;
    }
    if (!fec.has_flag(kUdpFlagSyn)) return Status::InvalidType;
    ByteReader r(data + UdpFecHeader::kSize, size - UdpFecHeader::kSize);
    if (!r.u32le(out.initial_sequence_number)) return Status::NeedMoreData;
    if (!r.u16le(out.upstream_mtu)) return Status::NeedMoreData;
    if (!r.u16le(out.downstream_mtu)) return Status::NeedMoreData;
    out.fec = fec;
    out.has_synex = false;
    if (r.remaining() >= 4) {
        out.has_synex = true;
        if (!r.u16le(out.synex_flags)) return Status::NeedMoreData;
        if (!r.u16le(out.udp_version)) return Status::NeedMoreData;
    }
    return Status::Ok;
}

// ---- multitransport ----------------------------------------------------------

std::vector<uint8_t> MultitransportRequest::build(
    const MultitransportRequest& r) {
    ByteWriter w;
    w.u32le(r.request_id);
    w.u16le(r.requested_protocol);
    w.u16le(r.reserved);
    const std::vector<uint8_t> cookie =
        r.security_cookie.size() == 16
            ? r.security_cookie
            : std::vector<uint8_t>(16, 0);
    w.bytes(cookie.data(), cookie.size());
    return w.take();
}

Status MultitransportRequest::parse(const uint8_t* data, size_t size,
                                    MultitransportRequest& out) {
    if (size < 24) return Status::NeedMoreData;
    ByteReader r(data, size);
    if (!r.u32le(out.request_id)) return Status::NeedMoreData;
    if (!r.u16le(out.requested_protocol)) return Status::NeedMoreData;
    if (!r.u16le(out.reserved)) return Status::NeedMoreData;
    if (r.remaining() < 16) return Status::NeedMoreData;
    out.security_cookie.assign(r.cursor(), r.cursor() + 16);
    return Status::Ok;
}

std::vector<uint8_t> MultitransportResponse::build(
    const MultitransportResponse& r) {
    ByteWriter w;
    w.u32le(r.request_id);
    w.u32le(r.result_code);
    return w.take();
}

Status MultitransportResponse::parse(const uint8_t* data, size_t size,
                                     MultitransportResponse& out) {
    if (size < 8) return Status::NeedMoreData;
    ByteReader r(data, size);
    if (!r.u32le(out.request_id)) return Status::NeedMoreData;
    if (!r.u32le(out.result_code)) return Status::NeedMoreData;
    return Status::Ok;
}

}  // namespace rtsc::proto
