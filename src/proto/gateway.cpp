// RD Gateway ([MS-TSGU]) and RDP-UDP / multitransport wire structures.

#include "rtsc/proto/gateway.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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
// rejected before anything is sized from it: `length` never holds a value that
// already failed the ceiling, so the multiply cannot overflow.
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
            value = value * 10 + static_cast<size_t>(c - '0');
            if (value > limits.max_entity_bytes) return Status::InvalidLength;
        }
        if (has_length && value != length) return Status::InvalidField;
        length = value;
        has_length = true;
    }
    return Status::Ok;
}

}  // namespace

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

std::vector<uint8_t> BuildRdgChannelRequest(const RdgChannelRequestOptions& o) {
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

    write_header("Host", "/remoteDesktopGateway/");
    write_header("User-Agent", o.user_agent);
    write_header("Accept", "*/*");
    write_header("Cache-Control", "no-cache");
    write_header("Connection", "Keep-Alive");
    write_header("Content-Length", "0");
    write_header(kRdgConnectionIdHeader, o.connection_id);
    if (!o.correlation_id.empty()) {
        write_header(kRdgCorrelationIdHeader, o.correlation_id);
    }
    if (!o.user_id.empty()) write_header(kRdgUserIdHeader, o.user_id);
    AppendCrLf(w);
    return w.take();
}

// ---- authentication ----------------------------------------------------------

Status RdgAuthChallenge::parse_www_authenticate(const std::string& value,
                                                 RdgAuthChallenge& out) {
    const std::string trimmed = Trim(value);
    if (trimmed.empty()) return Status::InvalidField;
    const size_t space = trimmed.find(' ');
    if (space == std::string::npos) {
        out.scheme = trimmed;
        out.realm.clear();
        return Status::Ok;
    }
    out.scheme = trimmed.substr(0, space);
    const std::string rest = Trim(trimmed.substr(space + 1));
    const size_t eq = rest.find('=');
    if (eq == std::string::npos) return Status::InvalidField;
    const std::string key = Trim(rest.substr(0, eq));
    std::string realm = Trim(rest.substr(eq + 1));
    if (!realm.empty() && realm.front() == '"' && realm.back() == '"') {
        realm = realm.substr(1, realm.size() - 2);
    }
    if (ToLower(key) != "realm") return Status::InvalidField;
    out.realm = realm;
    return Status::Ok;
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
