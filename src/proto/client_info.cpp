#include "rtsc/proto/client_info.h"

#include <cstring>

namespace rtsc::proto {

namespace {

// Fixed-size UTF-16LE name field: exactly `units` UTF-16 code units, NUL padded.
void WriteFixedUtf16(ByteWriter& w, const std::string& utf8, size_t units) {
    size_t written = 0;
    for (size_t i = 0; i < utf8.size() && written < units; ++i) {
        // Names are expected to be ASCII; each byte becomes one code unit. A
        // full UTF-8 decoder is unnecessary here because the wire format only
        // carries the characters we were given, and the field is NUL padded.
        w.u16le(static_cast<uint16_t>(static_cast<uint8_t>(utf8[i])));
        ++written;
    }
    while (written < units) {
        w.u16le(0);
        ++written;
    }
}

std::string ReadFixedUtf16(ByteReader& r, size_t units) {
    std::string out;
    for (size_t i = 0; i < units; ++i) {
        uint16_t u = 0;
        if (!r.u16le(u)) return out;
        if (u == 0) {
            // Consume the rest of the field without appending.
            for (size_t j = i + 1; j < units; ++j) {
                uint16_t skip = 0;
                if (!r.u16le(skip)) return out;
            }
            return out;
        }
        if (u < 0x80) out.push_back(static_cast<char>(u));
        else out.push_back('?');  // non-ASCII in a fixed name field: lossy, documented
    }
    return out;
}

// Variable-length string field. `cb` excludes the mandatory terminator.
void WriteVarString(ByteWriter& w, const std::string& utf8, bool unicode) {
    if (unicode) {
        for (char c : utf8) w.u16le(static_cast<uint16_t>(static_cast<uint8_t>(c)));
        w.u16le(0);
    } else {
        for (char c : utf8) w.u8(static_cast<uint8_t>(c));
        w.u8(0);
    }
}

uint16_t VarStringBytes(const std::string& utf8, bool unicode) {
    const size_t unit = unicode ? 2 : 1;
    return static_cast<uint16_t>(utf8.size() * unit);
}

// Reads `cb` bytes of text plus its terminator. `cb` excludes the terminator.
Status ReadVarString(ByteReader& r, uint16_t cb, bool unicode, std::string& out) {
    out.clear();
    if (unicode) {
        if (r.remaining() < static_cast<size_t>(cb) + 2) return Status::NeedMoreData;
        for (uint16_t i = 0; i < cb / 2; ++i) {
            uint16_t u = 0;
            if (!r.u16le(u)) return Status::NeedMoreData;
            out.push_back(u < 0x80 ? static_cast<char>(u) : '?');
        }
        if ((cb & 1) != 0) {
            uint8_t skip = 0;
            if (!r.u8(skip)) return Status::NeedMoreData;
        }
        uint16_t term = 0;
        if (!r.u16le(term)) return Status::NeedMoreData;
        return Status::Ok;
    }
    if (r.remaining() < static_cast<size_t>(cb) + 1) return Status::NeedMoreData;
    for (uint16_t i = 0; i < cb; ++i) {
        uint8_t c = 0;
        if (!r.u8(c)) return Status::NeedMoreData;
        out.push_back(static_cast<char>(c));
    }
    uint8_t term = 0;
    if (!r.u8(term)) return Status::NeedMoreData;
    return Status::Ok;
}

}  // namespace

// ---- TS_SYSTEMTIME --------------------------------------------------------

void TsSystemTime::write(ByteWriter& w) const {
    w.u16le(year);
    w.u16le(month);
    w.u16le(day_of_week);
    w.u16le(day);
    w.u16le(hour);
    w.u16le(minute);
    w.u16le(second);
    w.u16le(milliseconds);
}

Status TsSystemTime::read(ByteReader& r) {
    if (r.remaining() < 16) return Status::NeedMoreData;
    r.u16le(year);
    r.u16le(month);
    r.u16le(day_of_week);
    r.u16le(day);
    r.u16le(hour);
    r.u16le(minute);
    r.u16le(second);
    r.u16le(milliseconds);
    return Status::Ok;
}

bool TsSystemTime::is_zero() const {
    return year == 0 && month == 0 && day_of_week == 0 && day == 0 && hour == 0 &&
           minute == 0 && second == 0 && milliseconds == 0;
}

// ---- TS_TIME_ZONE_INFORMATION ---------------------------------------------

void TsTimeZoneInformation::write(ByteWriter& w) const {
    w.u32le(static_cast<uint32_t>(bias));
    WriteFixedUtf16(w, standard_name, kNameUnits);
    standard_date.write(w);
    w.u32le(static_cast<uint32_t>(standard_bias));
    WriteFixedUtf16(w, daylight_name, kNameUnits);
    daylight_date.write(w);
    w.u32le(static_cast<uint32_t>(daylight_bias));
}

Status TsTimeZoneInformation::read(ByteReader& r) {
    if (r.remaining() < kWireSize) return Status::NeedMoreData;
    uint32_t raw_bias = 0;
    r.u32le(raw_bias);
    bias = static_cast<int32_t>(raw_bias);
    standard_name = ReadFixedUtf16(r, kNameUnits);
    Status s = standard_date.read(r);
    if (s != Status::Ok) return s;
    uint32_t raw_std_bias = 0;
    r.u32le(raw_std_bias);
    standard_bias = static_cast<int32_t>(raw_std_bias);
    daylight_name = ReadFixedUtf16(r, kNameUnits);
    s = daylight_date.read(r);
    if (s != Status::Ok) return s;
    uint32_t raw_dst_bias = 0;
    r.u32le(raw_dst_bias);
    daylight_bias = static_cast<int32_t>(raw_dst_bias);
    return Status::Ok;
}

// ---- ARC_CS_PRIVATE_PACKET ------------------------------------------------

void ArcCsPrivatePacket::write(ByteWriter& w) const {
    if (bytes.size() == kWireSize) {
        w.bytes(bytes.data(), bytes.size());
        return;
    }
    for (size_t i = 0; i < kWireSize; ++i) w.u8(0);
}

Status ArcCsPrivatePacket::read(ByteReader& r) {
    if (r.remaining() < kWireSize) return Status::NeedMoreData;
    bytes.assign(r.cursor(), r.cursor() + kWireSize);
    if (!r.skip(kWireSize)) return Status::NeedMoreData;
    return Status::Ok;
}

// ---- TS_EXTENDED_INFO_PACKET ----------------------------------------------

void TsExtendedInfoPacket::write(ByteWriter& w, bool unicode) const {
    w.u16le(client_address_family);

    const uint16_t addr_cb = static_cast<uint16_t>(
        client_address.size() * (unicode ? 2 : 1) + (unicode ? 2 : 1));
    w.u16le(addr_cb);
    WriteVarString(w, client_address, unicode);

    const uint16_t dir_cb = static_cast<uint16_t>(
        client_dir.size() * (unicode ? 2 : 1) + (unicode ? 2 : 1));
    w.u16le(dir_cb);
    WriteVarString(w, client_dir, unicode);

    if (!has_time_zone) return;
    time_zone.write(w);

    if (!has_session_id) return;
    w.u32le(session_id);

    if (!has_performance_flags) return;
    w.u32le(performance_flags);

    if (!has_auto_reconnect) return;
    // The cbAutoReconnectCookie field itself is always present once the chain
    // reaches it; the 28-byte cookie only follows when cb is 0x001C.
    const bool cookie_present =
        auto_reconnect_cookie.bytes.size() == ArcCsPrivatePacket::kWireSize;
    w.u16le(static_cast<uint16_t>(cookie_present ? ArcCsPrivatePacket::kWireSize : 0));
    if (!cookie_present) return;
    auto_reconnect_cookie.write(w);
    if (!has_reserved) return;
    w.u16le(reserved1);
    w.u16le(reserved2);

    if (!has_dynamic_dst) return;
    w.u16le(static_cast<uint16_t>(dynamic_dst_time_zone_key_name.size() * 2));
    for (char c : dynamic_dst_time_zone_key_name) {
        w.u16le(static_cast<uint16_t>(static_cast<uint8_t>(c)));
    }
    w.u16le(dynamic_daylight_time_disabled);
}

Status TsExtendedInfoPacket::read(ByteReader& r, bool unicode) {
    if (r.remaining() < 2) return Status::NeedMoreData;
    r.u16le(client_address_family);
    if (client_address_family != kAfInet && client_address_family != kAfInet6) {
        return Status::InvalidField;
    }

    if (r.remaining() < 2) return Status::NeedMoreData;
    uint16_t addr_cb = 0;
    r.u16le(addr_cb);
    if (addr_cb < (unicode ? 2 : 1)) return Status::InvalidLength;
    {
        const uint16_t payload = static_cast<uint16_t>(addr_cb - (unicode ? 2 : 1));
        Status s = ReadVarString(r, payload, unicode, client_address);
        if (s != Status::Ok) return s;
    }

    if (r.remaining() < 2) return Status::NeedMoreData;
    uint16_t dir_cb = 0;
    r.u16le(dir_cb);
    if (dir_cb < (unicode ? 2 : 1)) return Status::InvalidLength;
    {
        const uint16_t payload = static_cast<uint16_t>(dir_cb - (unicode ? 2 : 1));
        Status s = ReadVarString(r, payload, unicode, client_dir);
        if (s != Status::Ok) return s;
    }

    if (r.remaining() < TsTimeZoneInformation::kWireSize) return Status::Ok;
    has_time_zone = true;
    Status s = time_zone.read(r);
    if (s != Status::Ok) return s;

    if (r.remaining() < 4) return Status::Ok;
    has_session_id = true;
    r.u32le(session_id);

    if (r.remaining() < 4) return Status::Ok;
    has_performance_flags = true;
    r.u32le(performance_flags);

    if (r.remaining() < 2) return Status::Ok;
    has_auto_reconnect = true;
    uint16_t arc_cb = 0;
    r.u16le(arc_cb);
    if (arc_cb != 0 && arc_cb != ArcCsPrivatePacket::kWireSize) return Status::InvalidLength;
    if (arc_cb != 0) {
        s = auto_reconnect_cookie.read(r);
        if (s != Status::Ok) return s;
    }

    if (r.remaining() < 4) return Status::Ok;
    has_reserved = true;
    r.u16le(reserved1);
    r.u16le(reserved2);

    if (r.remaining() < 2) return Status::Ok;
    has_dynamic_dst = true;
    uint16_t key_cb = 0;
    r.u16le(key_cb);
    if (key_cb > 254) return Status::InvalidLength;
    if (r.remaining() < static_cast<size_t>(key_cb) + 2) return Status::NeedMoreData;
    for (uint16_t i = 0; i < key_cb / 2; ++i) {
        uint16_t u = 0;
        r.u16le(u);
        dynamic_dst_time_zone_key_name.push_back(u < 0x80 ? static_cast<char>(u) : '?');
    }
    r.u16le(dynamic_daylight_time_disabled);
    return Status::Ok;
}

// ---- TS_INFO_PACKET -------------------------------------------------------

void TsInfoPacket::write(ByteWriter& w) const {
    const bool uni = unicode();

    w.u32le(code_page);
    w.u32le(flags);

    w.u16le(VarStringBytes(domain, uni));
    w.u16le(VarStringBytes(user_name, uni));
    w.u16le(VarStringBytes(password, uni));
    w.u16le(VarStringBytes(alternate_shell, uni));
    w.u16le(VarStringBytes(working_dir, uni));

    WriteVarString(w, domain, uni);
    WriteVarString(w, user_name, uni);
    WriteVarString(w, password, uni);
    WriteVarString(w, alternate_shell, uni);
    WriteVarString(w, working_dir, uni);

    if (has_extended_info) extended_info.write(w, uni);
}

size_t TsInfoPacket::encoded_size() const {
    ByteWriter w;
    write(w);
    return w.size();
}

Status TsInfoPacket::read(ByteReader& r) {
    if (r.remaining() < 18) return Status::NeedMoreData;
    r.u32le(code_page);
    r.u32le(flags);

    uint16_t cb_domain = 0, cb_user = 0, cb_password = 0, cb_shell = 0, cb_dir = 0;
    r.u16le(cb_domain);
    r.u16le(cb_user);
    r.u16le(cb_password);
    r.u16le(cb_shell);
    r.u16le(cb_dir);

    const bool uni = unicode();
    Status s = ReadVarString(r, cb_domain, uni, domain);
    if (s != Status::Ok) return s;
    s = ReadVarString(r, cb_user, uni, user_name);
    if (s != Status::Ok) return s;
    s = ReadVarString(r, cb_password, uni, password);
    if (s != Status::Ok) return s;
    s = ReadVarString(r, cb_shell, uni, alternate_shell);
    if (s != Status::Ok) return s;
    s = ReadVarString(r, cb_dir, uni, working_dir);
    if (s != Status::Ok) return s;

    if (r.empty()) return Status::Ok;
    has_extended_info = true;
    return extended_info.read(r, uni);
}

// ---- CLIENT_INFO_PDU ------------------------------------------------------

std::vector<uint8_t> ClientInfoPdu::build() const {
    ByteWriter w;
    w.u16le(security_flags);
    w.u16le(security_flags_hi);
    info.write(w);
    return w.take();
}

Status ClientInfoPdu::parse(const uint8_t* data, size_t size, ClientInfoPdu& out) {
    ByteReader r(data, size);
    if (r.remaining() < 4) return Status::NeedMoreData;
    r.u16le(out.security_flags);
    r.u16le(out.security_flags_hi);
    if ((out.security_flags & sec::kSecInfoPkt) == 0) return Status::InvalidField;
    return out.info.read(r);
}

// ---- SECURITY_EXCHANGE_PDU ------------------------------------------------

size_t SecurityExchangePdu::BufferSizeForKeyBits(uint32_t bit_length) {
    return static_cast<size_t>(bit_length / 8) + 8;
}

std::vector<uint8_t> SecurityExchangePdu::build() const {
    ByteWriter w;
    w.u16le(flags);
    w.u16le(flags_hi);
    w.u32le(static_cast<uint32_t>(encrypted_client_random.size()));
    if (!encrypted_client_random.empty()) {
        w.bytes(encrypted_client_random.data(), encrypted_client_random.size());
    }
    return w.take();
}

Status SecurityExchangePdu::parse(const uint8_t* data, size_t size,
                                  SecurityExchangePdu& out) {
    ByteReader r(data, size);
    if (r.remaining() < 8) return Status::NeedMoreData;
    r.u16le(out.flags);
    r.u16le(out.flags_hi);
    if ((out.flags & sec::kSecExchangePkt) == 0) return Status::InvalidField;

    uint32_t len = 0;
    r.u32le(len);
    if (r.remaining() < len) return Status::NeedMoreData;
    out.encrypted_client_random.assign(r.cursor(), r.cursor() + len);
    if (!r.skip(len)) return Status::NeedMoreData;
    if (!r.empty()) return Status::InvalidLength;
    return Status::Ok;
}

}  // namespace rtsc::proto
