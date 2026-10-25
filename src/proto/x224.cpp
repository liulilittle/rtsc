#include "rtsc/proto/x224.h"

namespace rtsc::proto {

Status X224Tpdu::parse(const uint8_t* data, size_t size, X224Tpdu& out) {
    if (size < kSize) return Status::NeedMoreData;
    ByteReader r(data, size);
    r.u8(out.length_indicator);
    r.u8(out.code);
    r.u16be(out.destination_reference);
    r.u16be(out.source_reference);
    r.u8(out.class_options);
    return Status::Ok;
}

Status X224Tpdu::validate() const {
    switch (code) {
        case kConnectionRequest:
        case kConnectionConfirm:
        case kDisconnectRequest:
            break;
        case kData:
            return Status::InvalidType;
        default:
            return Status::InvalidType;
    }
    // A Class 0 TPDU without parameters has LI == 6.
    if (length_indicator != 6) return Status::InvalidLength;
    if (class_options != kClass0) return Status::InvalidField;
    return Status::Ok;
}

std::vector<uint8_t> X224Tpdu::encode() const {
    ByteWriter w;
    w.u8(length_indicator);
    w.u8(code);
    w.u16be(destination_reference);
    w.u16be(source_reference);
    w.u8(class_options);
    return w.take();
}

X224Tpdu X224Tpdu::make_connection_request() {
    X224Tpdu t;
    t.code = kConnectionRequest;
    t.destination_reference = 0;
    t.source_reference = 0;
    return t;
}

X224Tpdu X224Tpdu::make_connection_confirm(uint16_t source_reference) {
    X224Tpdu t;
    t.code = kConnectionConfirm;
    t.destination_reference = 0;
    t.source_reference = source_reference;
    return t;
}

X224Tpdu X224Tpdu::make_disconnect_request() {
    X224Tpdu t;
    t.code = kDisconnectRequest;
    t.destination_reference = 0;
    t.source_reference = 0;
    return t;
}

Status X224DataPrefix::parse(const uint8_t* data, size_t size) {
    if (size < kSize) return Status::NeedMoreData;
    if (data[0] != kLengthIndicator) return Status::InvalidLength;
    if (data[1] != kCode) return Status::InvalidType;
    if (data[2] != kEot) return Status::InvalidField;
    return Status::Ok;
}

void X224DataPrefix::encode(ByteWriter& w) {
    w.u8(kLengthIndicator);
    w.u8(kCode);
    w.u8(kEot);
}

}  // namespace rtsc::proto
