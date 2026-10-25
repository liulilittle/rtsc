// CredSSP message layer: TSRequest and TSCredentials DER codec.
//
// Reference: docs/spec/security-layer.md sections 5.1, 5.2, 5.5, 5.7.
//
// Encoding is always canonical DER (minimal integer, minimal length, ascending
// context tags). Decoding is deliberately more permissive in exactly one place:
// the server writes errorCode as a raw 4-byte unsigned NTSTATUS without the
// leading 0x00 that DER requires for a negative INTEGER, and rejecting that
// would make the client unable to report the server's own failure code.

#include "rtsc/credssp/ts_request.h"

#include <cstring>
#include <utility>

#include "rtsc/crypto/hash.h"

namespace rtsc::credssp {
namespace {

constexpr uint8_t kTagInteger = 0x02;
constexpr uint8_t kTagOctetString = 0x04;
constexpr uint8_t kTagSequence = 0x30;
// Context-specific constructed, tag number n.
constexpr uint8_t kContextualBase = 0xA0;

constexpr uint8_t kTagVersion = 0;
constexpr uint8_t kTagNegoTokens = 1;
constexpr uint8_t kTagAuthInfo = 2;
constexpr uint8_t kTagPubKeyAuth = 3;
constexpr uint8_t kTagErrorCode = 4;
constexpr uint8_t kTagClientNonce = 5;

constexpr size_t kNonceSize = 32;

// Minimal reader over a byte range. Every method checks bounds before reading;
// a truncated input produces kTruncated rather than reading past the end.
class Reader {
public:
    Reader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    size_t remaining() const { return size_ - offset_; }
    bool empty() const { return offset_ >= size_; }
    size_t offset() const { return offset_; }

    Error ReadByte(uint8_t& out) {
        if (remaining() < 1) return Fail(Status::kTruncated, "byte");
        out = data_[offset_++];
        return Ok();
    }

    Error ReadLength(size_t& out) {
        uint8_t first = 0;
        Error e = ReadByte(first);
        if (!e.ok()) return e;
        if ((first & 0x80) == 0) {
            out = first;
            return Ok();
        }
        const size_t n = first & 0x7F;
        if (n == 0) return Fail(Status::kMalformed, "indefinite length");
        if (n > 4) return Fail(Status::kMalformed, "length too long");
        if (remaining() < n) return Fail(Status::kTruncated, "length octets");
        size_t v = 0;
        for (size_t i = 0; i < n; ++i) {
            v = (v << 8) | data_[offset_++];
        }
        out = v;
        return Ok();
    }

    // Reads a TLV whose tag must equal `expected`, returning a view of its
    // contents (not copied).
    Error ReadExpected(uint8_t expected, const uint8_t*& value, size_t& length) {
        uint8_t tag = 0;
        Error e = ReadByte(tag);
        if (!e.ok()) return e;
        if (tag != expected) return Fail(Status::kMalformed, "unexpected tag");
        e = ReadLength(length);
        if (!e.ok()) return e;
        if (remaining() < length) return Fail(Status::kTruncated, "value");
        value = data_ + offset_;
        offset_ += length;
        return Ok();
    }

    // Peeks the next tag without consuming it.
    Error PeekTag(uint8_t& tag) const {
        if (remaining() < 1) return Fail(Status::kTruncated, "peek");
        tag = data_[offset_];
        return Ok();
    }

    Error Skip(size_t n) {
        if (remaining() < n) return Fail(Status::kTruncated, "skip");
        offset_ += n;
        return Ok();
    }

private:
    const uint8_t* data_;
    size_t size_;
    size_t offset_ = 0;
};

// Reads an INTEGER as an unsigned 32-bit value.
//
// Two spellings are accepted on purpose:
//   * canonical DER for a non-negative value: no redundant leading 0x00
//   * canonical DER for a negative value: leading 0x00 followed by a byte with
//     the high bit set (how a well-behaved peer writes 0xC000006D)
//   * the server's non-canonical form: a raw 4-byte value with the high bit set
//     and no leading 0x00
// All three describe the same bit pattern, so they are collapsed to the raw
// 32-bit value the peer meant.
Error ReadUnsignedInteger(Reader& r, uint32_t& out) {
    const uint8_t* value = nullptr;
    size_t length = 0;
    Error e = r.ReadExpected(kTagInteger, value, length);
    if (!e.ok()) return e;
    if (length == 0) return Fail(Status::kMalformed, "empty integer");
    if (length > 5) return Fail(Status::kMalformed, "integer too long");

    size_t start = 0;
    // A single leading 0x00 is the sign guard for a 4-byte value with the high
    // bit set; anything more is redundant padding and rejected.
    if (length == 5) {
        if (value[0] != 0x00) return Fail(Status::kMalformed, "integer overflow");
        start = 1;
    }
    const size_t n = length - start;
    if (n == 0) return Fail(Status::kMalformed, "empty integer");
    if (n > 4) return Fail(Status::kMalformed, "integer too long");
    uint32_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | value[start + i];
    out = v;
    return Ok();
}

std::string Utf16LeToUtf8(const uint8_t* data, size_t size) {
    std::string out;
    out.reserve(size / 2);
    for (size_t i = 0; i + 1 < size; i += 2) {
        const uint32_t unit = static_cast<uint32_t>(data[i]) |
                              (static_cast<uint32_t>(data[i + 1]) << 8);
        if (unit < 0x80) {
            out.push_back(static_cast<char>(unit));
        } else if (unit < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (unit >> 6)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (unit >> 12)));
            out.push_back(static_cast<char>(0x80 | ((unit >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        }
    }
    return out;
}

}  // namespace

// ---- DER writers ----------------------------------------------------------

void WriteLength(Bytes& out, size_t length) {
    if (length < 0x80) {
        out.push_back(static_cast<uint8_t>(length));
        return;
    }
    uint8_t tmp[4];
    int n = 0;
    size_t v = length;
    while (v != 0) {
        tmp[n++] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
    out.push_back(static_cast<uint8_t>(0x80 | n));
    for (int i = n - 1; i >= 0; --i) out.push_back(tmp[i]);
}

void WriteOctetString(Bytes& out, const uint8_t* data, size_t size) {
    out.push_back(kTagOctetString);
    WriteLength(out, size);
    if (size != 0) out.insert(out.end(), data, data + size);
}

void WriteInteger(Bytes& out, uint32_t value) {
    uint8_t tmp[4];
    int n = 0;
    uint32_t v = value;
    do {
        tmp[n++] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    } while (v != 0);
    // A leading 0x00 is required when the top bit of the first octet is set,
    // otherwise the value would be read as negative.
    const bool needs_pad = (tmp[n - 1] & 0x80) != 0;
    out.push_back(kTagInteger);
    WriteLength(out, static_cast<size_t>(n + (needs_pad ? 1 : 0)));
    if (needs_pad) out.push_back(0x00);
    for (int i = n - 1; i >= 0; --i) out.push_back(tmp[i]);
}

void WriteContextual(Bytes& out, uint8_t tag_number, const Bytes& content) {
    out.push_back(static_cast<uint8_t>(kContextualBase | tag_number));
    WriteLength(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
}

// ---- TsRequest ------------------------------------------------------------

Error TsRequest::Encode(Bytes& out) const {
    out.clear();

    if (client_nonce.empty()) {
        // fine
    } else if (client_nonce.size() != kNonceSize) {
        return Fail(Status::kUnsupported, "clientNonce must be 32 bytes");
    } else if (version < 5) {
        return Fail(Status::kUnsupported, "clientNonce requires version >= 5");
    }

    Bytes body;

    Bytes ver;
    WriteInteger(ver, version);
    WriteContextual(body, kTagVersion, ver);

    if (!nego_token.empty()) {
        // NegoData ::= SEQUENCE OF SEQUENCE { [0] OCTET STRING }
        Bytes token;
        WriteOctetString(token, nego_token.data(), nego_token.size());
        Bytes tagged;
        WriteContextual(tagged, 0, token);
        Bytes inner;
        inner.push_back(kTagSequence);
        WriteLength(inner, tagged.size());
        inner.insert(inner.end(), tagged.begin(), tagged.end());
        Bytes list;
        list.push_back(kTagSequence);
        WriteLength(list, inner.size());
        list.insert(list.end(), inner.begin(), inner.end());
        WriteContextual(body, kTagNegoTokens, list);
    }

    if (!auth_info.empty()) {
        Bytes s;
        WriteOctetString(s, auth_info.data(), auth_info.size());
        WriteContextual(body, kTagAuthInfo, s);
    }

    if (!pub_key_auth.empty()) {
        Bytes s;
        WriteOctetString(s, pub_key_auth.data(), pub_key_auth.size());
        WriteContextual(body, kTagPubKeyAuth, s);
    }

    if (has_error_code) {
        Bytes s;
        WriteInteger(s, error_code);
        WriteContextual(body, kTagErrorCode, s);
    }

    if (!client_nonce.empty()) {
        Bytes s;
        WriteOctetString(s, client_nonce.data(), client_nonce.size());
        WriteContextual(body, kTagClientNonce, s);
    }

    out.push_back(kTagSequence);
    WriteLength(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return Ok();
}

Error TsRequest::Decode(const uint8_t* data, size_t size) {
    *this = TsRequest{};
    Reader outer(data, size);

    const uint8_t* seq = nullptr;
    size_t seq_len = 0;
    Error e = outer.ReadExpected(kTagSequence, seq, seq_len);
    if (!e.ok()) return e;
    if (!outer.empty()) return Fail(Status::kMalformed, "trailing bytes");

    Reader body(seq, seq_len);
    uint8_t last_tag = 0;
    bool have_version = false;

    while (!body.empty()) {
        uint8_t tag = 0;
        e = body.PeekTag(tag);
        if (!e.ok()) return e;
        if (tag < kContextualBase) {
            return Fail(Status::kMalformed, "expected context tag");
        }
        const uint8_t number = static_cast<uint8_t>(tag & 0x1F);
        if (number > kTagClientNonce) {
            return Fail(Status::kUnsupported, "unknown context tag");
        }
        // DER requires ascending order; the wire from real peers obeys it.
        if (number <= last_tag && !(last_tag == 0 && number == 0 && !have_version)) {
            return Fail(Status::kMalformed, "context tags out of order");
        }
        last_tag = number;

        const uint8_t* content = nullptr;
        size_t content_len = 0;
        e = body.ReadExpected(tag, content, content_len);
        if (!e.ok()) return e;
        Reader inner(content, content_len);

        switch (number) {
            case kTagVersion: {
                e = ReadUnsignedInteger(inner, version);
                if (!e.ok()) return e;
                have_version = true;
                break;
            }
            case kTagNegoTokens: {
                const uint8_t* list = nullptr;
                size_t list_len = 0;
                e = inner.ReadExpected(kTagSequence, list, list_len);
                if (!e.ok()) return e;
                Reader list_reader(list, list_len);
                const uint8_t* item = nullptr;
                size_t item_len = 0;
                e = list_reader.ReadExpected(kTagSequence, item, item_len);
                if (!e.ok()) return e;
                Reader item_reader(item, item_len);
                const uint8_t* tok_tag = nullptr;
                size_t tok_tag_len = 0;
                e = item_reader.ReadExpected(static_cast<uint8_t>(kContextualBase), tok_tag,
                                             tok_tag_len);
                if (!e.ok()) return e;
                Reader tok_reader(tok_tag, tok_tag_len);
                const uint8_t* tok = nullptr;
                size_t tok_len = 0;
                e = tok_reader.ReadExpected(kTagOctetString, tok, tok_len);
                if (!e.ok()) return e;
                nego_token.assign(tok, tok + tok_len);
                break;
            }
            case kTagAuthInfo:
            case kTagPubKeyAuth:
            case kTagClientNonce: {
                const uint8_t* v = nullptr;
                size_t n = 0;
                e = inner.ReadExpected(kTagOctetString, v, n);
                if (!e.ok()) return e;
                Bytes value(v, v + n);
                if (number == kTagAuthInfo) {
                    auth_info = std::move(value);
                } else if (number == kTagPubKeyAuth) {
                    pub_key_auth = std::move(value);
                } else {
                    client_nonce = std::move(value);
                }
                break;
            }
            case kTagErrorCode: {
                e = ReadUnsignedInteger(inner, error_code);
                if (!e.ok()) return e;
                has_error_code = true;
                break;
            }
            default:
                return Fail(Status::kUnsupported, "unknown context tag");
        }
    }

    if (!have_version) return Fail(Status::kMalformed, "missing version");
    return Ok();
}

// ---- PasswordCredentials --------------------------------------------------

Error PasswordCredentials::Encode(Bytes& out) const {
    out.clear();

    const Bytes domain_utf16 = crypto::Utf16Le(domain);
    const Bytes user_utf16 = crypto::Utf16Le(user);
    const Bytes password_utf16 = crypto::Utf16Le(password);

    Bytes creds_body;
    {
        Bytes s;
        WriteOctetString(s, domain_utf16.data(), domain_utf16.size());
        WriteContextual(creds_body, 0, s);
    }
    {
        Bytes s;
        WriteOctetString(s, user_utf16.data(), user_utf16.size());
        WriteContextual(creds_body, 1, s);
    }
    {
        Bytes s;
        WriteOctetString(s, password_utf16.data(), password_utf16.size());
        WriteContextual(creds_body, 2, s);
    }
    Bytes creds;
    creds.push_back(kTagSequence);
    WriteLength(creds, creds_body.size());
    creds.insert(creds.end(), creds_body.begin(), creds_body.end());

    Bytes body;
    {
        Bytes s;
        WriteInteger(s, kCredTypePassword);
        WriteContextual(body, 0, s);
    }
    {
        Bytes s;
        WriteOctetString(s, creds.data(), creds.size());
        WriteContextual(body, 1, s);
    }
    out.push_back(kTagSequence);
    WriteLength(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return Ok();
}

Error PasswordCredentials::Decode(const uint8_t* data, size_t size) {
    *this = PasswordCredentials{};
    Reader outer(data, size);

    const uint8_t* seq = nullptr;
    size_t seq_len = 0;
    Error e = outer.ReadExpected(kTagSequence, seq, seq_len);
    if (!e.ok()) return e;
    if (!outer.empty()) return Fail(Status::kMalformed, "trailing bytes");

    Reader body(seq, seq_len);
    uint32_t cred_type = 0;
    bool have_type = false;
    const uint8_t* creds = nullptr;
    size_t creds_len = 0;

    while (!body.empty()) {
        uint8_t tag = 0;
        e = body.PeekTag(tag);
        if (!e.ok()) return e;
        if (tag < kContextualBase) return Fail(Status::kMalformed, "expected context tag");
        const uint8_t number = static_cast<uint8_t>(tag & 0x1F);
        const uint8_t* content = nullptr;
        size_t content_len = 0;
        e = body.ReadExpected(tag, content, content_len);
        if (!e.ok()) return e;
        Reader inner(content, content_len);
        if (number == 0) {
            e = ReadUnsignedInteger(inner, cred_type);
            if (!e.ok()) return e;
            have_type = true;
        } else if (number == 1) {
            e = inner.ReadExpected(kTagOctetString, creds, creds_len);
            if (!e.ok()) return e;
        } else {
            return Fail(Status::kMalformed, "unknown field");
        }
    }

    if (!have_type) return Fail(Status::kMalformed, "missing credType");
    if (cred_type != kCredTypePassword) {
        return Fail(Status::kUnsupported, "credType is not password");
    }
    if (creds == nullptr) return Fail(Status::kMalformed, "missing credentials");

    Reader creds_outer(creds, creds_len);
    const uint8_t* creds_seq = nullptr;
    size_t creds_seq_len = 0;
    e = creds_outer.ReadExpected(kTagSequence, creds_seq, creds_seq_len);
    if (!e.ok()) return e;

    Reader creds_body(creds_seq, creds_seq_len);
    std::string* fields[3] = {&domain, &user, &password};
    bool seen[3] = {false, false, false};
    while (!creds_body.empty()) {
        uint8_t tag = 0;
        e = creds_body.PeekTag(tag);
        if (!e.ok()) return e;
        if (tag < kContextualBase) return Fail(Status::kMalformed, "expected context tag");
        const uint8_t number = static_cast<uint8_t>(tag & 0x1F);
        if (number > 2) return Fail(Status::kMalformed, "unknown credential field");
        const uint8_t* content = nullptr;
        size_t content_len = 0;
        e = creds_body.ReadExpected(tag, content, content_len);
        if (!e.ok()) return e;
        Reader inner(content, content_len);
        const uint8_t* v = nullptr;
        size_t n = 0;
        e = inner.ReadExpected(kTagOctetString, v, n);
        if (!e.ok()) return e;
        // UTF-16LE must be an even number of bytes; an odd length means the
        // value is truncated or was encoded in the wrong byte order.
        if ((n % 2) != 0) return Fail(Status::kMalformed, "odd UTF-16 length");
        *fields[number] = Utf16LeToUtf8(v, n);
        seen[number] = true;
    }
    for (bool s : seen) {
        if (!s) return Fail(Status::kMalformed, "missing credential field");
    }
    return Ok();
}

}  // namespace rtsc::credssp
