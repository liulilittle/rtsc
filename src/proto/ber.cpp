#include "rtsc/proto/ber.h"

namespace rtsc::proto {

namespace {

constexpr size_t kMaxBerLengthBytes = 4;

}  // namespace

void BerWriter::write_length(size_t len) {
    if (len < 0x80) {
        buf_.push_back(static_cast<uint8_t>(len));
        return;
    }
    uint8_t tmp[kMaxBerLengthBytes];
    size_t n = 0;
    size_t v = len;
    while (v > 0) {
        tmp[n++] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
    buf_.push_back(static_cast<uint8_t>(0x80 | n));
    for (size_t i = 0; i < n; ++i) buf_.push_back(tmp[n - 1 - i]);
}

void BerWriter::boolean(bool v) {
    buf_.push_back(kBerBoolean);
    write_length(1);
    buf_.push_back(v ? 0xFF : 0x00);
}

void BerWriter::integer(int64_t v) {
    buf_.push_back(kBerInteger);
    uint8_t tmp[8];
    size_t n = 0;
    int64_t x = v;
    do {
        tmp[n++] = static_cast<uint8_t>(x & 0xFF);
        x >>= 8;
    } while (x != 0 && x != -1);
    // The most significant byte must carry the sign bit: pad 0x00 for a
    // positive value whose top bit is set, 0xFF for a negative one whose top
    // bit is clear. A negative value that already sign-extended needs nothing.
    if (x == 0 && (tmp[n - 1] & 0x80) != 0) {
        tmp[n++] = 0x00;
    } else if (x == -1 && (tmp[n - 1] & 0x80) == 0) {
        tmp[n++] = 0xFF;
    }
    write_length(n);
    for (size_t i = 0; i < n; ++i) buf_.push_back(tmp[n - 1 - i]);
}

void BerWriter::enumerated(int64_t v) {
    buf_.push_back(kBerEnumerated);
    uint8_t tmp[8];
    size_t n = 0;
    int64_t x = v;
    do {
        tmp[n++] = static_cast<uint8_t>(x & 0xFF);
        x >>= 8;
    } while (x != 0 && x != -1);
    if (x == 0 && (tmp[n - 1] & 0x80) != 0) {
        tmp[n++] = 0x00;
    } else if (x == -1 && (tmp[n - 1] & 0x80) == 0) {
        tmp[n++] = 0xFF;
    }
    write_length(n);
    for (size_t i = 0; i < n; ++i) buf_.push_back(tmp[n - 1 - i]);
}

void BerWriter::octet_string(const uint8_t* p, size_t n) {
    buf_.push_back(kBerOctetString);
    write_length(n);
    if (n > 0) buf_.insert(buf_.end(), p, p + n);
}

size_t BerWriter::begin_sequence() { return begin_constructed(kBerSequence); }

size_t BerWriter::begin_constructed(uint8_t tag) {
    buf_.push_back(tag);
    const size_t mark = buf_.size();
    buf_.push_back(0);  // placeholder for the length
    return mark;
}

void BerWriter::end_constructed(size_t mark, uint8_t tag) {
    (void)tag;
    const size_t len = buf_.size() - mark - 1;
    if (len < 0x80) {
        buf_[mark] = static_cast<uint8_t>(len);
        return;
    }
    uint8_t tmp[kMaxBerLengthBytes];
    size_t n = 0;
    size_t v = len;
    while (v > 0) {
        tmp[n++] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
    std::vector<uint8_t> len_bytes;
    len_bytes.push_back(static_cast<uint8_t>(0x80 | n));
    for (size_t i = 0; i < n; ++i) len_bytes.push_back(tmp[n - 1 - i]);
    buf_.erase(buf_.begin() + static_cast<std::ptrdiff_t>(mark));
    buf_.insert(buf_.begin() + static_cast<std::ptrdiff_t>(mark), len_bytes.begin(),
                len_bytes.end());
}

bool BerReader::peek_tag(uint8_t& tag) const {
    if (remaining() < 1) return false;
    tag = data_[offset_];
    return true;
}

Status BerReader::read_header(uint8_t& tag, const uint8_t*& value, size_t& value_len) {
    if (remaining() < 2) return Status::NeedMoreData;
    tag = data_[offset_];
    size_t pos = offset_ + 1;
    const uint8_t first = data_[pos++];
    size_t len = 0;
    if (first < 0x80) {
        len = first;
    } else {
        const size_t n = first & 0x7F;
        if (n == 0) return Status::InvalidLength;  // indefinite form is not allowed
        if (n > kMaxBerLengthBytes) return Status::InvalidLength;
        if (remaining() < 2 + n) return Status::NeedMoreData;
        if (data_[pos] == 0x00) return Status::InvalidLength;  // non-minimal
        for (size_t i = 0; i < n; ++i) len = (len << 8) | data_[pos++];
        if (len < 0x80) return Status::InvalidLength;  // should have used short form
    }
    if (size_ - pos < len) return Status::NeedMoreData;
    value = data_ + pos;
    value_len = len;
    offset_ = pos + len;
    return Status::Ok;
}

Status BerReader::read_boolean(bool& out) {
    uint8_t tag = 0;
    const uint8_t* v = nullptr;
    size_t n = 0;
    const Status s = read_header(tag, v, n);
    if (s != Status::Ok) return s;
    if (tag != kBerBoolean) return Status::InvalidType;
    if (n != 1) return Status::InvalidLength;
    out = v[0] != 0x00;
    return Status::Ok;
}

Status BerReader::read_integer(int64_t& out) {
    uint8_t tag = 0;
    const uint8_t* v = nullptr;
    size_t n = 0;
    const Status s = read_header(tag, v, n);
    if (s != Status::Ok) return s;
    if (tag != kBerInteger && tag != kBerEnumerated) return Status::InvalidType;
    if (n == 0 || n > 8) return Status::InvalidLength;
    int64_t value = (v[0] & 0x80) ? -1 : 0;
    for (size_t i = 0; i < n; ++i) {
        value = (value << 8) | static_cast<int64_t>(v[i]);
    }
    out = value;
    return Status::Ok;
}

Status BerReader::read_octet_string(std::vector<uint8_t>& out) {
    const uint8_t* p = nullptr;
    size_t n = 0;
    const Status s = read_octet_string_view(p, n);
    if (s != Status::Ok) return s;
    out.assign(p, p + n);
    return Status::Ok;
}

Status BerReader::read_octet_string_view(const uint8_t*& p, size_t& n) {
    uint8_t tag = 0;
    const Status s = read_header(tag, p, n);
    if (s != Status::Ok) return s;
    if (tag != kBerOctetString) return Status::InvalidType;
    return Status::Ok;
}

Status BerReader::read_constructed(uint8_t expected_tag, BerReader& out) {
    uint8_t tag = 0;
    const uint8_t* v = nullptr;
    size_t n = 0;
    const Status s = read_header(tag, v, n);
    if (s != Status::Ok) return s;
    if (tag != expected_tag) return Status::InvalidType;
    out = BerReader(v, n);
    return Status::Ok;
}

}  // namespace rtsc::proto
