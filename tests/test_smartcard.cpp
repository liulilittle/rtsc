// [MS-RDPESC] payload codec tests.
//
// Expected byte sequences are derived from the [MS-RDPESC] field order
// (2.2.1.x common structures, 2.2.2.x calls, 2.2.3.x returns) wrapped in the
// [MS-RPCE] 2.2.6.1/2.2.6.2 NDR headers, not from this implementation's
// output. The NDR pointer convention (0x00020000 + index*4, NULL = 0), the
// deferred-referent ordering and the 4-byte referent padding were cross-checked
// against FreeRDP libfreerdp/utils/smartcard_pack.c and IronRDP
// crates/ironrdp-rdpdr/src/pdu/esc/{rpce,ndr}.rs.

#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/smartcard.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

constexpr uint8_t kC = 0xCC;

// [MS-RPCE] 2.2.6.1: Version=1, Endianness=0x10, CommonHeaderLength=8,
// Filler=0xCCCCCCCC.
std::vector<uint8_t> CommonHeader() {
    return {0x01, 0x10, 0x08, 0x00, kC, kC, kC, kC};
}

// [MS-RPCE] 2.2.6.2: ObjectBufferLength + zero filler.
std::vector<uint8_t> PrivateHeader(uint32_t object_len) {
    return {static_cast<uint8_t>(object_len & 0xFF),
            static_cast<uint8_t>((object_len >> 8) & 0xFF),
            static_cast<uint8_t>((object_len >> 16) & 0xFF),
            static_cast<uint8_t>((object_len >> 24) & 0xFF), 0, 0, 0, 0};
}

std::vector<uint8_t> Le32(uint32_t v) {
    return {static_cast<uint8_t>(v & 0xFF), static_cast<uint8_t>((v >> 8) & 0xFF),
            static_cast<uint8_t>((v >> 16) & 0xFF),
            static_cast<uint8_t>((v >> 24) & 0xFF)};
}

std::vector<uint8_t> Bytes(std::initializer_list<uint8_t> v) { return v; }

std::vector<uint8_t> Zeros(size_t n) { return std::vector<uint8_t>(n, 0); }

std::vector<uint8_t> Concat(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// Wraps a body in the NDR headers, appending zero padding so the total stream
// length is a multiple of 8 and recording body+padding as ObjectBufferLength.
std::vector<uint8_t> Wrap(const std::vector<uint8_t>& body) {
    size_t padded = body.size();
    while ((padded % 8) != 0) ++padded;
    std::vector<uint8_t> out = CommonHeader();
    std::vector<uint8_t> ph = PrivateHeader(static_cast<uint32_t>(padded));
    out.insert(out.end(), ph.begin(), ph.end());
    out.insert(out.end(), body.begin(), body.end());
    out.insert(out.end(), padded - body.size(), 0);
    return out;
}

bool Same(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return a == b;
}

std::string AsString(const std::vector<uint8_t>& v) {
    return std::string(v.begin(), v.end());
}

}  // namespace

// ---------------------------------------------------------------------------
// IOCTL table
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_ioctl_codes_match_spec_3_1_4) {
    // [MS-RDPESC] 3.1.4 section titles carry the authoritative values.
    // Read through volatile locals so the comparison is not a compile-time
    // constant (MSVC warns C4127 on the CHECK_EQ do/while in that case).
    volatile uint32_t code = 0;
    code = static_cast<uint32_t>(ScardIoctl::kEstablishContext);
    CHECK_EQ(code,  0x00090014u);
    code = static_cast<uint32_t>(ScardIoctl::kReleaseContext);
    CHECK_EQ(code,  0x00090018u);
    code = static_cast<uint32_t>(ScardIoctl::kListReaderGroupsA);
    CHECK_EQ(code,  0x00090020u);
    code = static_cast<uint32_t>(ScardIoctl::kListReaderGroupsW);
    CHECK_EQ(code,  0x00090024u);
    code = static_cast<uint32_t>(ScardIoctl::kListReadersA);
    CHECK_EQ(code,  0x00090028u);
    code = static_cast<uint32_t>(ScardIoctl::kListReadersW);
    CHECK_EQ(code,  0x0009002Cu);
    code = static_cast<uint32_t>(ScardIoctl::kLocateCardsA);
    CHECK_EQ(code,  0x00090098u);
    code = static_cast<uint32_t>(ScardIoctl::kLocateCardsByAtrA);
    CHECK_EQ(code,  0x000900E8u);
    code = static_cast<uint32_t>(ScardIoctl::kLocateCardsByAtrW);
    CHECK_EQ(code,  0x000900ECu);
    code = static_cast<uint32_t>(ScardIoctl::kAccessStartedEvent);
    CHECK_EQ(code,  0x000900E0u);
    code = static_cast<uint32_t>(ScardIoctl::kGetStatusChangeA);
    CHECK_EQ(code,  0x000900A0u);
    code = static_cast<uint32_t>(ScardIoctl::kCancel);
    CHECK_EQ(code,  0x000900A8u);
    code = static_cast<uint32_t>(ScardIoctl::kState);
    CHECK_EQ(code,  0x000900C4u);
    code = static_cast<uint32_t>(ScardIoctl::kConnectA);
    CHECK_EQ(code,  0x000900ACu);
    code = static_cast<uint32_t>(ScardIoctl::kConnectW);
    CHECK_EQ(code,  0x000900B0u);
    code = static_cast<uint32_t>(ScardIoctl::kReconnect);
    CHECK_EQ(code,  0x000900B4u);
    code = static_cast<uint32_t>(ScardIoctl::kDisconnect);
    CHECK_EQ(code,  0x000900B8u);
    code = static_cast<uint32_t>(ScardIoctl::kBeginTransaction);
    CHECK_EQ(code,  0x000900BCu);
    code = static_cast<uint32_t>(ScardIoctl::kEndTransaction);
    CHECK_EQ(code,  0x000900C0u);
    code = static_cast<uint32_t>(ScardIoctl::kStatusA);
    CHECK_EQ(code,  0x000900C8u);
    code = static_cast<uint32_t>(ScardIoctl::kStatusW);
    CHECK_EQ(code,  0x000900CCu);
    code = static_cast<uint32_t>(ScardIoctl::kTransmit);
    CHECK_EQ(code,  0x000900D0u);
    code = static_cast<uint32_t>(ScardIoctl::kControl);
    CHECK_EQ(code,  0x000900D4u);
    code = static_cast<uint32_t>(ScardIoctl::kGetAttrib);
    CHECK_EQ(code,  0x000900D8u);
    code = static_cast<uint32_t>(ScardIoctl::kSetAttrib);
    CHECK_EQ(code,  0x000900DCu);
    code = static_cast<uint32_t>(ScardIoctl::kReadCacheA);
    CHECK_EQ(code,  0x000900F0u);
    code = static_cast<uint32_t>(ScardIoctl::kReadCacheW);
    CHECK_EQ(code,  0x000900F4u);
    code = static_cast<uint32_t>(ScardIoctl::kWriteCacheA);
    CHECK_EQ(code,  0x000900F8u);
    code = static_cast<uint32_t>(ScardIoctl::kWriteCacheW);
    CHECK_EQ(code,  0x000900FCu);
    code = static_cast<uint32_t>(ScardIoctl::kGetReaderIcon);
    CHECK_EQ(code,  0x00090104u);
    code = static_cast<uint32_t>(ScardIoctl::kGetDeviceTypeId);
    CHECK_EQ(code,  0x00090108u);
    code = static_cast<uint32_t>(ScardIoctl::kGetTransmitCount);
    CHECK_EQ(code,  0x00090100u);
}

RTSC_TEST(smartcard_unsupported_ioctls_are_rejected) {
    CHECK(IsSupportedScardIoctl(0x00090014u));
    CHECK(IsSupportedScardIoctl(0x000900D0u));
    CHECK(IsSupportedScardIoctl(0x0009001Cu));  // ISVALIDCONTEXT (批134)
    CHECK(!IsSupportedScardIoctl(0x000900E4u));  // RELEASESTARTEDEVENT (not used)
    CHECK(!IsSupportedScardIoctl(0x00090038u));  // not a spec IOCTL at all
    CHECK(!IsSupportedScardIoctl(0));
    // 0x00090064 is INTRODUCEREADERW (client-to-server only): the A reader
    // state path must not be reachable through it by accident.
    ScardCall call;
    uint8_t dummy[16] = {0};
    CHECK(ParseScardCall(0x00090064u, dummy, sizeof(dummy), call) ==
          Status::InvalidType);
    CHECK(ParseScardCall(0x000900E4u, dummy, sizeof(dummy), call) ==
          Status::InvalidType);
}

RTSC_TEST(smartcard_ioctl_names) {
    CHECK(std::string(ScardIoctlName(0x00090014u)) ==
          std::string("SCARD_IOCTL_ESTABLISHCONTEXT"));
    CHECK(std::string(ScardIoctlName(0x000900A0u)) ==
          std::string("SCARD_IOCTL_GETSTATUSCHANGEA"));
    CHECK(std::string(ScardIoctlName(0x000900D0u)) ==
          std::string("SCARD_IOCTL_TRANSMIT"));
    CHECK(std::string(ScardIoctlName(0xDEADBEEFu)) ==
          std::string("SCARD_IOCTL_UNKNOWN"));
}

// ---------------------------------------------------------------------------
// NDR headers ([MS-RPCE] 2.2.6.1 / 2.2.6.2)
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_ndr_header_roundtrip) {
    const std::vector<uint8_t> buf = Wrap(Le32(0x11223344u));
    ScardNdrHeader h;
    size_t off = 0;
    size_t body = 0;
    CHECK(ScardNdrHeader::parse(buf.data(), buf.size(), h, off, body) == Status::Ok);
    CHECK_EQ(off, size_t{16});
    CHECK_EQ(body, size_t{8});
    CHECK_EQ(h.object_buffer_length, 8u);
    CHECK_EQ(buf.size(), size_t{24});
    CHECK(ScardNdrHeader::looks_like_header(buf.data(), buf.size()));
}

RTSC_TEST(smartcard_ndr_header_rejects_bad_version) {
    std::vector<uint8_t> buf = Wrap(Le32(0));
    buf[0] = 2;  // Version MUST be 1
    ScardNdrHeader h;
    size_t off = 0;
    size_t body = 0;
    CHECK(ScardNdrHeader::parse(buf.data(), buf.size(), h, off, body) ==
          Status::InvalidVersion);
    CHECK(!ScardNdrHeader::looks_like_header(buf.data(), buf.size()));
}

RTSC_TEST(smartcard_ndr_header_rejects_big_endian) {
    std::vector<uint8_t> buf = Wrap(Le32(0));
    buf[1] = 0x00;  // 0x10 = little-endian
    ScardNdrHeader h;
    size_t off = 0;
    size_t body = 0;
    CHECK(ScardNdrHeader::parse(buf.data(), buf.size(), h, off, body) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_ndr_header_rejects_bad_length_and_filler) {
    const std::vector<uint8_t> good = Wrap(Le32(0));
    {
        std::vector<uint8_t> b = good;
        b[2] = 9;  // CommonHeaderLength MUST be 8
        ScardNdrHeader h;
        size_t off = 0, body = 0;
        CHECK(ScardNdrHeader::parse(b.data(), b.size(), h, off, body) ==
              Status::InvalidLength);
    }
    {
        std::vector<uint8_t> b = good;
        b[7] = 0;  // Filler MUST be 0xCCCCCCCC
        ScardNdrHeader h;
        size_t off = 0, body = 0;
        CHECK(ScardNdrHeader::parse(b.data(), b.size(), h, off, body) ==
              Status::InvalidField);
    }
    {
        std::vector<uint8_t> b = good;
        b[12] = 1;  // private filler MUST be zero
        ScardNdrHeader h;
        size_t off = 0, body = 0;
        CHECK(ScardNdrHeader::parse(b.data(), b.size(), h, off, body) ==
              Status::InvalidField);
    }
}

RTSC_TEST(smartcard_ndr_header_object_length_past_end_needs_more_data) {
    std::vector<uint8_t> buf = Wrap(Le32(0));
    const uint32_t too_big = static_cast<uint32_t>(buf.size() - 16 + 8);
    buf[8] = static_cast<uint8_t>(too_big & 0xFF);
    buf[9] = static_cast<uint8_t>((too_big >> 8) & 0xFF);
    buf[10] = static_cast<uint8_t>((too_big >> 16) & 0xFF);
    buf[11] = static_cast<uint8_t>((too_big >> 24) & 0xFF);
    ScardNdrHeader h;
    size_t off = 0, body = 0;
    CHECK(ScardNdrHeader::parse(buf.data(), buf.size(), h, off, body) ==
          Status::NeedMoreData);
}

RTSC_TEST(smartcard_ndr_header_truncated_is_need_more_data) {
    const std::vector<uint8_t> buf = Wrap(Le32(0));
    ScardNdrHeader h;
    size_t off = 0, body = 0;
    CHECK(ScardNdrHeader::parse(buf.data(), 15, h, off, body) ==
          Status::NeedMoreData);
    CHECK(!ScardNdrHeader::looks_like_header(buf.data(), 7));
    CHECK(!ScardNdrHeader::looks_like_header(nullptr, 0));
}

// ---------------------------------------------------------------------------
// SCARD_IOCTL_ESTABLISHCONTEXT ([MS-RDPESC] 2.2.2.1 / 2.2.3.2)
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_establish_context_call_parse) {
    const std::vector<uint8_t> buf = Wrap(Le32(2));  // SCARD_SCOPE_SYSTEM
    ScardCall call;
    CHECK(ParseScardCall(0x00090014u, buf.data(), buf.size(), call) == Status::Ok);
    CHECK(call.code == ScardIoctl::kEstablishContext);
    CHECK_EQ(call.scope, 2u);
}

RTSC_TEST(smartcard_establish_context_call_truncated) {
    const std::vector<uint8_t> buf = Wrap(Bytes({0x02, 0x00}));
    ScardCall call;
    CHECK(ParseScardCall(0x00090014u, buf.data(), 16 + 2, call) ==
          Status::NeedMoreData);
}

RTSC_TEST(smartcard_establish_context_return_exact_bytes) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.context.bytes = {0x00, 0x00, 0x01, 0xCD};
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kEstablishContext, ret);

    // ReturnCode(4) + cbContext(4) + pbContext ptr(4), then the referent:
    // Length(4) + 4 context bytes, padded to 8.
    const std::vector<uint8_t> body = Concat({
        Le32(0),           // ReturnCode
        Le32(4),           // cbContext
        Le32(0x00020000),  // first NDR pointer
        Le32(4),           // referent length
        Bytes({0x00, 0x00, 0x01, 0xCD}),
    });  // 20 bytes -> padded to 24
    CHECK(Same(got, Wrap(body)));
    CHECK_EQ(got.size(), size_t{16 + 24});
}

RTSC_TEST(smartcard_establish_context_return_failure_is_result_only) {
    ScardReturn ret;
    ret.return_code = 0x8010001Du;  // SCARD_E_NO_SERVICE
    ret.context.bytes = {0x11, 0x22};
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kEstablishContext, ret);
    CHECK(Same(got, Wrap(Le32(0x8010001Du))));
}

RTSC_TEST(smartcard_establish_context_return_rejects_oversized_context) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.context.bytes.assign(kScardMaxContextBytes + 1, 0x5A);
    CHECK(EncodeScardReturn(ScardIoctl::kEstablishContext, ret).empty());
}

// ---------------------------------------------------------------------------
// SCARD_IOCTL_LISTREADERSA ([MS-RDPESC] 2.2.2.4 / 2.2.3.4)
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_list_readers_a_call_parse) {
    // Context {4 bytes} + groups "Readers\0" (ANSI multistring, 8 bytes).
    const std::vector<uint8_t> body = Concat({
        Le32(4),           // cbContext
        Le32(0x00020000),  // pbContext ptr
        Le32(8),           // cBytes of mszGroups
        Le32(0x00020004),  // mszGroups ptr
        Le32(0),           // fmszReadersIsNULL
        Le32(0xFFFFFFFFu), // cchReaders
        Le32(4),           // context referent length
        Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(8),  // groups referent length
        Bytes({'R', 'e', 'a', 'd', 'e', 'r', 's', 0}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090028u, buf.data(), buf.size(), call) == Status::Ok);
    CHECK(call.code == ScardIoctl::kListReadersA);
    CHECK_EQ(call.context.bytes.size(), size_t{4});
    CHECK_EQ(call.groups_msz.size(), size_t{8});
    CHECK(AsString(call.groups_msz) == std::string("Readers\0", 8));
    CHECK_EQ(call.readers_is_null, 0u);
    CHECK_EQ(call.readers_cch, 0xFFFFFFFFu);
}

RTSC_TEST(smartcard_list_readers_a_call_rejects_null_group_pointer) {
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0),  // empty context
        Le32(8), Le32(0),  // cBytes but NULL pointer
        Le32(0), Le32(0),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090028u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_list_readers_a_call_rejects_length_mismatch) {
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0), Le32(8), Le32(0x00020000), Le32(0), Le32(0),
        Le32(4),  // referent says 4, inline said 8
        Bytes({'a', 'b', 'c', 0}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090028u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_list_readers_a_call_accepts_null_groups) {
    // A NULL mszGroups with cBytes = 0 is the "all reader groups" form.
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0),
        Le32(0), Le32(0),
        Le32(0), Le32(0),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090028u, buf.data(), buf.size(), call) == Status::Ok);
    CHECK(call.groups_msz.empty());
}

RTSC_TEST(smartcard_list_readers_w_call_parse) {
    // Same Context_Call wire form; mszGroups is a UTF-16LE multistring.
    const std::vector<uint8_t> wide_groups = {
        'R', 0, 'e', 0, 'a', 0, 'd', 0, 'e', 0, 'r', 0, 's', 0, 0, 0};
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(static_cast<uint32_t>(wide_groups.size())), Le32(0x00020004),
        Le32(0), Le32(0xFFFFFFFFu),
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(static_cast<uint32_t>(wide_groups.size())), wide_groups,
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x0009002Cu, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.code == ScardIoctl::kListReadersW);
    CHECK(call.groups_msz == wide_groups);
}

RTSC_TEST(smartcard_list_reader_groups_w_return_exact_bytes) {
    ScardReturn ret;
    ret.multi_string = std::vector<uint8_t>{'G', 0, 'r', 0, 'p', 0, 0, 0,
                                            0, 0};
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kListReaderGroupsW, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(10), Le32(0x00020000),
                                 Le32(10), ret.multi_string.value(),
                                 Zeros(2)}))));
}

RTSC_TEST(smartcard_list_reader_groups_w_return_rejects_odd_length) {
    ScardReturn ret;
    ret.multi_string = std::vector<uint8_t>{'G', 0, 0, 0, 0};
    CHECK(EncodeScardReturn(ScardIoctl::kListReaderGroupsW, ret).empty());
}

RTSC_TEST(smartcard_list_readers_w_return_exact_bytes) {
    ScardReturn ret;
    ret.multi_string = std::vector<uint8_t>{'R', 0, 0, 0, '0', 0, 0, 0, 0, 0};
    // ReturnCode(4) + cBytes(4) + ptr(4) + referent(Length 4 + 10 + 2 pad).
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kListReadersW, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(10), Le32(0x00020000),
                                 Le32(10), ret.multi_string.value(),
                                 Zeros(2)}))));
}

RTSC_TEST(smartcard_list_readers_w_return_rejects_odd_length) {
    ScardReturn ret;
    ret.multi_string = std::vector<uint8_t>{'R', 0, 0, 0, 0};
    CHECK(EncodeScardReturn(ScardIoctl::kListReadersW, ret).empty());
}

RTSC_TEST(smartcard_list_readers_w_return_requires_double_nul) {
    ScardReturn ret;
    ret.multi_string = std::vector<uint8_t>{'R', 0, 0, 0};
    CHECK(EncodeScardReturn(ScardIoctl::kListReadersW, ret).empty());
}

RTSC_TEST(smartcard_list_readers_return_exact_bytes) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.multi_string = std::vector<uint8_t>{'R', 'e', 'a', 'd', 'e', 'r', 's',
                                            0, 0};  // 9 bytes
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kListReadersA, ret);
    // ReturnCode(4) + cBytes(4) + ptr(4) + referent(Length 4 + 9 bytes + 3 pad)
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(9), Le32(0x00020000), Le32(9),
        Bytes({'R', 'e', 'a', 'd', 'e', 'r', 's', 0, 0}),
        Zeros(3),
    });  // 12 + 16 = 28 -> padded to 32
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_list_readers_return_rejects_oversized_multistring) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.multi_string = std::vector<uint8_t>(kScardMaxMultiStringBytes + 1, 'x');
    CHECK(EncodeScardReturn(ScardIoctl::kListReadersA, ret).empty());
}

RTSC_TEST(smartcard_list_readers_return_empty_multistring_is_rejected) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.multi_string = std::vector<uint8_t>{};
    CHECK(EncodeScardReturn(ScardIoctl::kListReadersA, ret).empty());
}

RTSC_TEST(smartcard_list_readers_return_probe_null_string) {
    // Insufficient-buffer reply: cBytes carries the required size and the
    // pointer is NULL.
    ScardReturn ret;
    ret.return_code = 0x80100008u;  // SCARD_E_INSUFFICIENT_BUFFER
    ret.multi_string_length = 96;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kListReadersA, ret);
    // A failed call reports cBytes = 0 (see FreeRDP
    // smartcard_pack_list_readers_return: size is zeroed on failure).
    CHECK(Same(got, Wrap(Concat({Le32(0x80100008u), Le32(0), Le32(0)}))));
}

// ---------------------------------------------------------------------------
// SCARD_IOCTL_GETSTATUSCHANGEA ([MS-RDPESC] 2.2.2.11 / 2.2.3.5)
// ---------------------------------------------------------------------------

namespace {

std::vector<uint8_t> OneReaderStateBody() {
    // inline: context{cb,ptr}, dwTimeOut, cReaders, states ptr
    // referent 1: context bytes
    // referent 2: conformant array MaxCount(4) + element
    //   {name ptr, dwCurrentState, dwEventState, cbAtr, rgbAtr[36]}
    // referent 3: reader name string (full pointer)
    std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(0),           // dwTimeOut
        Le32(1),           // cReaders
        Le32(0x00020004),  // rgReaderStates ptr
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),  // context referent
        Le32(1),           // array MaxCount
        Le32(0x00020008),  // szReader full pointer
        Le32(0x00000004u), // dwCurrentState = SCARD_STATE_UNKNOWN
        Le32(0x00000000u), // dwEventState
        Le32(0),           // cbAtr
    });
    for (int i = 0; i < 36; ++i) body.push_back(static_cast<uint8_t>(i));
    // Reader name full pointer: Length + Offset + ActualCount + bytes + pad.
    const std::vector<uint8_t> name_len = Le32(3);
    const std::vector<uint8_t> name_off = Le32(0);
    body.insert(body.end(), name_len.begin(), name_len.end());
    body.insert(body.end(), name_off.begin(), name_off.end());
    body.insert(body.end(), name_len.begin(), name_len.end());  // actual count
    body.insert(body.end(), {'R', '0', 0});
    body.push_back(0);
    return body;
}

}  // namespace

RTSC_TEST(smartcard_get_status_change_w_call_parse) {
    // GetStatusChangeW_Call ([MS-RDPESC] 2.2.2.12): Context, dwTimeOut,
    // cReaders, rgReaderStates ptr; reader name is a UTF-16LE [string].
    const std::vector<uint8_t> wide_reader = {'R', 0, '0', 0, 0, 0};
    std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(500),
        Le32(1),
        Le32(0x00020004),
        Le32(4), Bytes({0x0B, 0xAD, 0xF0, 0x0D}),
        Le32(1),
        Le32(0x00020008),
        Le32(0), Le32(0), Le32(0),
    });
    for (int i = 0; i < 36; ++i) body.push_back(0);
    body = Concat({body, Le32(3), Le32(0), Le32(3)});
    body.insert(body.end(), wide_reader.begin(), wide_reader.end());
    while (body.size() % 4 != 0) body.push_back(0);
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900A4u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.code == ScardIoctl::kGetStatusChangeW);
    CHECK_EQ(call.timeout, 500u);
    CHECK_EQ(call.reader_states_w.size(), size_t{1});
    if (call.reader_states_w.size() == 1) {
        CHECK(call.reader_states_w[0].reader == u"R0");
        CHECK_EQ(call.reader_states_w[0].current_state, 0u);
    }
}

RTSC_TEST(smartcard_get_status_change_a_call_parse) {
    const std::vector<uint8_t> buf = Wrap(OneReaderStateBody());
    ScardCall call;
    CHECK(ParseScardCall(0x000900A0u, buf.data(), buf.size(), call) == Status::Ok);
    CHECK_EQ(call.timeout, 0u);
    CHECK_EQ(call.reader_states.size(), size_t{1});
    CHECK(call.reader_states[0].reader == std::string("R0"));
    CHECK_EQ(call.reader_states[0].current_state, 4u);
    CHECK_EQ(call.reader_states[0].event_state, 0u);
    CHECK_EQ(call.reader_states[0].atr.size(), size_t{0});
}

RTSC_TEST(smartcard_get_status_change_a_call_rejects_too_many_readers) {
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0),
        Le32(0),
        Le32(12),  // kScardMaxReaders is 11
        Le32(0x00020000),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900A0u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_get_status_change_a_call_rejects_array_count_mismatch) {
    std::vector<uint8_t> body = OneReaderStateBody();
    // Layout: inline 20 bytes (context cb+ptr, timeout, cReaders, states
    // ptr), then the context referent (Length 4 + 4 bytes) at 20, so the
    // array MaxCount starts at 28.
    const size_t max_count_at = 28;
    body[max_count_at + 0] = 2;  // MaxCount must equal cReaders
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900A0u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_get_status_change_a_call_rejects_oversized_atr) {
    std::vector<uint8_t> body = OneReaderStateBody();
    // cbAtr sits after: MaxCount(28) + name ptr(32) + current(36) +
    // event(40) = 44.
    const size_t cb_atr_at = 44;
    body[cb_atr_at + 0] = 37;  // kScardMaxAtr is 36
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900A0u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_get_status_change_return_exact_bytes) {
    ScardReturn ret;
    ret.return_code = 0;
    ScardReaderStateReturn st;
    st.current_state = 0x20;  // SCARD_STATE_PRESENT
    st.event_state = 0x22;
    st.atr = {0x3B, 0x8F};
    ret.reader_states.push_back(st);
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetStatusChangeA, ret);
    // ReturnCode(4) + cReaders(4) + ptr(4), referent: MaxCount(4) + element
    // {current(4), event(4), cbAtr(4), rgbAtr[36]} padded to 4.
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(1), Le32(0x00020000),
        Le32(1),
        Le32(0x20), Le32(0x22), Le32(2),
        Bytes({0x3B, 0x8F}),
        Zeros(34),
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_get_status_change_return_rejects_oversized_atr) {
    ScardReturn ret;
    ret.return_code = 0;
    ScardReaderStateReturn st;
    st.atr.assign(kScardMaxAtr + 1, 0);
    ret.reader_states.push_back(st);
    CHECK(EncodeScardReturn(ScardIoctl::kGetStatusChangeA, ret).empty());
}

RTSC_TEST(smartcard_get_status_change_return_rejects_too_many_states) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.reader_states.resize(kScardMaxReaders + 1);
    CHECK(EncodeScardReturn(ScardIoctl::kGetStatusChangeA, ret).empty());
}

RTSC_TEST(smartcard_get_status_change_return_keeps_states_on_timeout) {
    // FreeRDP smartcard_pack_get_status_change_return keeps cReaders when the
    // ReturnCode is SCARD_E_TIMEOUT so the server sees the updated states.
    ScardReturn ret;
    ret.return_code = 0x8010000Au;  // SCARD_E_TIMEOUT
    ScardReaderStateReturn st;
    st.current_state = 0x20;
    st.event_state = 0x20;
    ret.reader_states.push_back(st);
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetStatusChangeA, ret);
    CHECK(!got.empty());
    if (got.empty()) return;
    // ReturnCode(4) + cReaders(4) + ptr(4) + referent MaxCount(4) ...
    CHECK_EQ(got[20], static_cast<uint8_t>(0x01));  // cReaders little-endian
    CHECK_EQ(got[28], static_cast<uint8_t>(0x01));  // referent MaxCount
}

RTSC_TEST(smartcard_get_status_change_return_drops_states_on_other_failure) {
    ScardReturn ret;
    ret.return_code = 0x80100003u;  // SCARD_E_INVALID_HANDLE
    ret.reader_states.push_back(ScardReaderStateReturn{});
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetStatusChangeA, ret);
    CHECK(!got.empty());
    if (got.empty()) return;
    CHECK_EQ(got[20], static_cast<uint8_t>(0x00));  // cReaders = 0
    CHECK_EQ(got[24], static_cast<uint8_t>(0x00));  // NULL pointer
}

// ---------------------------------------------------------------------------
// SCARD_IOCTL_CONNECTA ([MS-RDPESC] 2.2.2.13 / 2.2.3.8)
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_connect_a_call_parse) {
    // inline: szReader ptr, then Connect_Common {context, share, protocols}
    // referents: reader string (full pointer), context bytes
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),           // szReader ptr
        Le32(4), Le32(0x00020004),  // context
        Le32(2),                    // SCARD_SHARE_SHARED
        Le32(3),                    // T0 | T1
        Le32(15), Le32(0), Le32(15),  // reader Length/Offset/Actual
        Bytes({'R', 'e', 'a', 'd', 'e', 'r', ' ', '0', ' ', 'x', 'y', 'z', 'q',
               'w', 0}),
        Bytes({0}),  // pad to 4
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900ACu, buf.data(), buf.size(), call) == Status::Ok);
    CHECK(call.reader == std::string("Reader 0 xyzqw"));
    CHECK_EQ(call.context.bytes.size(), size_t{4});
    CHECK_EQ(call.share_mode, 2u);
    CHECK_EQ(call.preferred_protocols, 3u);
}

RTSC_TEST(smartcard_connect_a_call_rejects_missing_nul) {
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(0), Le32(0),
        Le32(2), Le32(3),
        Le32(2), Le32(0), Le32(2),
        Bytes({'A', 'B'}),  // no NUL terminator
        Bytes({0, 0}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900ACu, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_connect_a_call_rejects_null_reader) {
    const std::vector<uint8_t> body = Concat({
        Le32(0),  // szReader NULL
        Le32(0), Le32(0), Le32(0), Le32(0),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900ACu, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_connect_return_exact_bytes) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.handle.context.bytes = {0x00, 0x00, 0x01, 0xCD};
    ret.handle.bytes = {0x11, 0x22, 0x33, 0x44};
    ret.active_protocol = 2;  // SCARD_PROTOCOL_T1
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kConnectA, ret);
    // ReturnCode(4) + hCard{cbContext(4), ctx ptr(4), cbHandle(4), h ptr(4)}
    // + dwActiveProtocol(4), referents: context bytes, handle bytes.
    const std::vector<uint8_t> body = Concat({
        Le32(0),
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(2),
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_connect_return_failure_has_empty_handle) {
    ScardReturn ret;
    ret.return_code = 0x80100009u;  // SCARD_E_UNKNOWN_READER
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kConnectA, ret);
    const std::vector<uint8_t> body = Concat({
        Le32(0x80100009u),
        Le32(0), Le32(0),  // context NULL
        Le32(0), Le32(0),  // handle NULL
        Le32(0),           // dwActiveProtocol
    });
    CHECK(Same(got, Wrap(body)));
}

// ---------------------------------------------------------------------------
// SCARD_IOCTL_DISCONNECT / BEGINTRANSACTION / ENDTRANSACTION
// ([MS-RDPESC] 2.2.2.16 / 2.2.3.3)
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_hcard_and_disposition_call_parse) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),  // hCard.Context
        Le32(4), Le32(0x00020004),  // cbHandle + pbHandle ptr
        Le32(1),                    // dwDisposition = SCARD_RESET_CARD
        Le32(4), Bytes({0xAA, 0xBB, 0xCC, 0xDD}),  // context bytes
        Le32(4), Bytes({0x01, 0x02, 0x03, 0x04}),  // handle bytes
    });
    const std::vector<uint8_t> buf = Wrap(body);
    for (uint32_t code : {0x000900B8u, 0x000900BCu, 0x000900C0u}) {
        ScardCall call;
        CHECK(ParseScardCall(code, buf.data(), buf.size(), call) == Status::Ok);
        CHECK_EQ(call.handle.bytes.size(), size_t{4});
        CHECK_EQ(call.handle.context.bytes.size(), size_t{4});
        CHECK_EQ(call.disposition, 1u);
    }
}

RTSC_TEST(smartcard_long_return_exact_bytes) {
    ScardReturn ret;
    ret.return_code = 0x80100003u;  // SCARD_E_INVALID_HANDLE
    for (ScardIoctl code : {ScardIoctl::kReleaseContext,
                            ScardIoctl::kIsValidContext,
                            ScardIoctl::kSetAttrib,
                            ScardIoctl::kWriteCacheA,
                            ScardIoctl::kCancel,
                            ScardIoctl::kDisconnect,
                            ScardIoctl::kBeginTransaction,
                            ScardIoctl::kEndTransaction}) {
        const std::vector<uint8_t> got = EncodeScardReturn(code, ret);
        CHECK(Same(got, Wrap(Le32(0x80100003u))));
    }
}

RTSC_TEST(smartcard_release_context_call_parse) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090018u, buf.data(), buf.size(), call) == Status::Ok);
    CHECK_EQ(call.context.bytes.size(), size_t{4});
    CHECK_EQ(call.context.bytes[0], 0xDE);
}

// [MS-RDPESC] 3.1.4.3: ISVALIDCONTEXT carries the same Context_Call as
// RELEASECONTEXT and answers with Long_Return.
RTSC_TEST(smartcard_is_valid_context_call_parse) {
    const std::vector<uint8_t> body = Concat({
        Le32(8), Le32(0x00020000),
        Le32(8), Bytes({0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x0009001Cu, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK_EQ(call.context.bytes.size(), size_t{8});
    CHECK_EQ(call.context.bytes[7], 0x80);
}

// ---------------------------------------------------------------------------
// SCARD_IOCTL_TRANSMIT ([MS-RDPESC] 2.2.2.19 / 2.2.3.11)
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_transmit_call_parse) {
    // inline: hCard{cbContext, ctx ptr, cbHandle, h ptr},
    //         ioSendPci{dwProtocol, cbExtraBytes, extra ptr},
    //         cbSendLength, pbSendBuffer ptr, pioRecvPci ptr (NULL),
    //         fpbRecvBufferIsNULL, cbRecvLength
    // referents: context, handle, send buffer (simple pointer).
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(2), Le32(0), Le32(0),  // ioSendPci: T1, no extra bytes, NULL
        Le32(5),                    // cbSendLength
        Le32(0x00020008),           // pbSendBuffer
        Le32(0),                    // pioRecvPci NULL
        Le32(0),                    // fpbRecvBufferIsNULL = FALSE
        Le32(258),                  // cbRecvLength
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
        Le32(5), Bytes({0x00, 0xA4, 0x04, 0x00, 0x07}), Zeros(3),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900D0u, buf.data(), buf.size(), call) == Status::Ok);
    CHECK_EQ(call.send_pci.protocol, 2u);
    CHECK_EQ(call.send_pci.extra.size(), size_t{0});
    CHECK_EQ(call.send_buffer.size(), size_t{5});
    CHECK_EQ(call.send_buffer[1], 0xA4);
    CHECK(!call.recv_pci.has_value());
    CHECK_EQ(call.recv_buffer_is_null, 0u);
    CHECK_EQ(call.recv_length, 258u);
}

RTSC_TEST(smartcard_transmit_call_parse_with_recv_pci) {
    // pointer order: context(0), handle(1), send pci extra(2), send buffer(3),
    // recv pci(4), recv pci extra(5).
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(1), Le32(2), Le32(0x00020008),  // send pci: T1, 2 extra bytes
        Le32(1), Le32(0x0002000C),           // send buffer, 1 byte
        Le32(0x00020010),                    // pioRecvPci non-NULL
        Le32(0), Le32(0),
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),  // context referent
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),  // handle referent
        Le32(2), Bytes({0xAB, 0xCD}), Zeros(2),    // send pci extra
        Le32(1), Bytes({0x5A}), Zeros(3),          // send buffer
        Le32(1), Le32(1), Le32(0x00020014),        // recv pci inline
        Le32(1), Bytes({0x55}), Zeros(3),          // recv pci extra
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900D0u, buf.data(), buf.size(), call) == Status::Ok);
    CHECK_EQ(call.send_pci.extra.size(), size_t{2});
    CHECK_EQ(call.send_pci.extra[1], 0xCD);
    CHECK_EQ(call.send_buffer.size(), size_t{1});
    CHECK(call.recv_pci.has_value());
    CHECK_EQ(call.recv_pci->protocol, 1u);
    CHECK_EQ(call.recv_pci->extra.size(), size_t{1});
    CHECK_EQ(call.recv_pci->extra[0], 0x55);
}

RTSC_TEST(smartcard_transmit_call_rejects_oversized_send_buffer) {
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0), Le32(0), Le32(0),
        Le32(2), Le32(0), Le32(0),
        Le32(static_cast<uint32_t>(kScardMaxTransmitBytes + 1)),
        Le32(0x00020000),
        Le32(0), Le32(0), Le32(0),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900D0u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_transmit_call_rejects_oversized_pci_extra) {
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0), Le32(0), Le32(0),
        Le32(2), Le32(static_cast<uint32_t>(kScardMaxExtraBytes + 1)),
        Le32(0x00020000),
        Le32(0), Le32(0), Le32(0), Le32(0), Le32(0),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900D0u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_transmit_return_exact_bytes) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.recv_buffer = std::vector<uint8_t>{0x90, 0x00};
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kTransmit, ret);
    // ReturnCode(4) + pioRecvPci ptr(4) + cbRecvLength(4) + pbRecvBuffer ptr(4),
    // referent: Length(4) + 2 bytes + 2 pad.
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0), Le32(2), Le32(0x00020000),
        Le32(2), Bytes({0x90, 0x00}), Zeros(2),
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_transmit_return_with_recv_pci) {
    ScardReturn ret;
    ret.return_code = 0;
    ScardIoRequest pci;
    pci.protocol = 1;
    pci.extra = {0x42};
    ret.recv_pci = pci;
    ret.recv_buffer = std::vector<uint8_t>{0x61};
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kTransmit, ret);
    // Pointer order: recv pci (0), recv buffer (1), pci extra (2).
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0x00020000), Le32(1), Le32(0x00020004),
        Le32(1), Le32(1), Le32(0x00020008),  // recv pci inline + extra ptr
        Le32(1), Bytes({0x42}), Zeros(3),    // recv pci extra referent
        Le32(1), Bytes({0x61}), Zeros(3),    // recv buffer referent
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_transmit_return_rejects_oversized_buffer) {
    ScardReturn ret;
    ret.recv_buffer = std::vector<uint8_t>(kScardMaxTransmitBytes + 1, 0x5A);
    CHECK(EncodeScardReturn(ScardIoctl::kTransmit, ret).empty());
}

RTSC_TEST(smartcard_transmit_return_probe_null_buffer) {
    // fpbRecvBufferIsNULL probe: the server reads only cbRecvLength.
    ScardReturn ret;
    ret.return_code = 0;
    ret.recv_length = 0x1234;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kTransmit, ret);
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0), Le32(0x1234), Le32(0),
    });
    CHECK(Same(got, Wrap(body)));
}

// ---------------------------------------------------------------------------
// SCARD_IOCTL_CONTROL ([MS-RDPESC] 2.2.2.20 / 2.2.3.6)
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_control_call_parse) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x42000001u),  // dwControlCode
        Le32(3),            // cbInBufferSize
        Le32(0x00020008),   // pvInBuffer ptr
        Le32(0),            // fpvOutBufferIsNULL
        Le32(1024),         // cbOutBufferSize
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
        Le32(3), Bytes({0x01, 0x02, 0x03}), Zeros(1),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900D4u, buf.data(), buf.size(), call) == Status::Ok);
    CHECK_EQ(call.control_code, 0x42000001u);
    CHECK_EQ(call.in_buffer.size(), size_t{3});
    CHECK_EQ(call.out_buffer_is_null, 0u);
    CHECK_EQ(call.out_buffer_size, 1024u);
}

RTSC_TEST(smartcard_control_call_rejects_length_mismatch) {
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(0), Le32(0), Le32(0),
        Le32(0x42000001u),
        Le32(5),            // cbInBufferSize
        Le32(0x00020000),   // pvInBuffer
        Le32(0), Le32(0),
        Le32(2), Bytes({0x01, 0x02}), Zeros(2),  // referent says 2
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900D4u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_control_return_exact_bytes) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.out_buffer = std::vector<uint8_t>{0xAA, 0xBB, 0xCC};
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kControl, ret);
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(3), Le32(0x00020000),
        Le32(3), Bytes({0xAA, 0xBB, 0xCC}), Zeros(1),
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_get_attrib_return_exact_bytes) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.attr = std::vector<uint8_t>{0x10, 0x20};
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetAttrib, ret);
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(2), Le32(0x00020000),
        Le32(2), Bytes({0x10, 0x20}), Zeros(4),
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_get_attrib_return_length_probe_has_null_buffer) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.attr_length = 7;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetAttrib, ret);
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(7), Le32(0),
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_get_attrib_call_parse) {
    // GetAttrib_Call: hCard inline, dwAttrId, fpbAttrIsNULL, cbAttrLen;
    // referents: context then handle.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00000007u),  // SCARD_ATTR_DEVICE_SYSTEM_NAME_A
        Le32(0),            // fpbAttrIsNULL = FALSE
        Le32(256),          // cbAttrLen
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900D8u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK_EQ(call.attr_id, 0x00000007u);
    CHECK_EQ(call.attr_is_null, 0u);
    CHECK_EQ(call.attr_capacity, 256u);
    CHECK_EQ(call.handle.bytes.size(), size_t{4});
    CHECK_EQ(call.handle.bytes[3], 0x44);
    CHECK_EQ(call.handle.context.bytes.size(), size_t{4});
}

RTSC_TEST(smartcard_set_attrib_call_parse) {
    // SetAttrib_Call: hCard inline, dwAttrId, cbAttrLen, pbAttr pointer;
    // referents: context, handle, pbAttr array.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00000007u),  // SCARD_ATTR_DEVICE_SYSTEM_NAME_A
        Le32(3),            // cbAttrLen
        Le32(0x00020008),   // pbAttr
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
        Le32(3), Bytes({'A', 'B', 'C'}), Zeros(1),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900DCu, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK_EQ(call.attr_id, 0x00000007u);
    CHECK_EQ(call.set_attr_length, 3u);
    CHECK_EQ(call.set_attr_value.size(), size_t{3});
    CHECK_EQ(call.set_attr_value[0], static_cast<uint8_t>('A'));
    CHECK_EQ(call.set_attr_value[2], static_cast<uint8_t>('C'));
    CHECK_EQ(call.handle.bytes.size(), size_t{4});
    CHECK_EQ(call.handle.bytes[3], 0x44);
}

RTSC_TEST(smartcard_set_attrib_call_rejects_ndr_length_mismatch) {
    // cbAttrLen says 5, the NDR array carries 2: malformed (the FreeRDP
    // 3.20.1 heap-overflow class).
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00000007u),
        Le32(5),
        Le32(0x00020008),
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
        Le32(2), Bytes({0xAA, 0xBB}), Zeros(2),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900DCu, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_locate_cards_w_call_parse) {
    // LocateCardsW_Call ([MS-RDPESC] 2.2.2.10): cBytes counts the bytes of the
    // UTF-16LE mszCards multistring; reader names are UTF-16LE too.
    const std::vector<uint8_t> wide_cards = {
        'C', 0, 'a', 0, 'r', 0, 'd', 0, 'A', 0, 0, 0, 0, 0};
    const std::vector<uint8_t> wide_reader = {'R', 0, '0', 0, 0, 0};
    std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(static_cast<uint32_t>(wide_cards.size())), Le32(0x00020004),
        Le32(1), Le32(0x00020008),
        Le32(4), Bytes({0x0B, 0xAD, 0xF0, 0x0D}),
        Le32(static_cast<uint32_t>(wide_cards.size())), wide_cards,
    });
    while (body.size() % 4 != 0) body.push_back(0);
    body = Concat({body, Le32(1), Le32(0x0002000C), Le32(0), Le32(0),
                   Le32(0)});
    for (int i = 0; i < 36; ++i) body.push_back(0);
    body = Concat({body, Le32(3), Le32(0), Le32(3)});
    body.insert(body.end(), wide_reader.begin(), wide_reader.end());
    while (body.size() % 4 != 0) body.push_back(0);
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x0009009Cu, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.code == ScardIoctl::kLocateCardsW);
    CHECK(call.cards_msz == wide_cards);
    CHECK_EQ(call.reader_states_w.size(), size_t{1});
    if (call.reader_states_w.size() == 1) {
        CHECK(call.reader_states_w[0].reader == u"R0");
    }
}

RTSC_TEST(smartcard_locate_cards_a_call_parse) {
    // LocateCardsA_Call: Context, cBytes, mszCards ptr, cReaders,
    // rgReaderStates ptr; referents: context, cards multistring, array.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(7), Le32(0x00020004),
        Le32(1), Le32(0x00020008),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(7), Bytes({'C', 'a', 'r', 'd', 'A', 0, 0}), Zeros(1),
        Le32(1),
        Le32(0x0002000C),
        Le32(3), Le32(0), Le32(0), Zeros(36),
        Le32(3), Le32(0), Le32(3),
        Bytes({'R', '0', 0}), Zeros(1),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090098u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(call.cards_msz ==
          std::vector<uint8_t>({'C', 'a', 'r', 'd', 'A', 0, 0}));
    CHECK_EQ(call.reader_states.size(), size_t{1});
    if (call.reader_states.size() == 1) {
        CHECK(call.reader_states[0].reader == "R0");
        CHECK_EQ(call.reader_states[0].current_state, 3u);
    }
}

RTSC_TEST(smartcard_locate_cards_a_call_rejects_ndr_length_mismatch) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(7), Le32(0x00020004),
        Le32(0), Le32(0),  // cReaders = 0, NULL array
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(2), Bytes({'A', 0}), Zeros(2),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090098u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_locate_cards_a_call_rejects_too_many_readers) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(0), Le32(0),
        Le32(11), Le32(0),  // cReaders > 10
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090098u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_locate_cards_return_exact_bytes) {
    ScardReturn ret;
    ScardReaderStateReturn st;
    st.current_state = 1;
    st.event_state = 2;
    st.atr = {0xAA};
    ret.reader_states.push_back(st);
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kLocateCardsA, ret);
    std::vector<uint8_t> expected = Concat({
        Le32(0), Le32(1), Le32(0x00020000), Le32(1),
        Le32(1), Le32(2), Le32(1),
        Bytes({0xAA}), Zeros(35),
    });
    CHECK(Same(got, Wrap(expected)));
}

RTSC_TEST(smartcard_locate_cards_return_failure_drops_states) {
    ScardReturn ret;
    ret.return_code = 0x80100009u;  // SCARD_E_UNKNOWN_READER
    ret.reader_states.push_back(ScardReaderStateReturn{});
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kLocateCardsA, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0x80100009u), Le32(0), Le32(0)}))));
}

RTSC_TEST(smartcard_read_cache_a_call_parse) {
    // ReadCacheA_Call: szLookupName ptr, Context, UUID ptr, FreshnessCounter,
    // fPbDataIsNULL, cbDataLen; referents: name, context, 16-byte UUID.
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00020008),
        Le32(7), Le32(1), Le32(16),
        Le32(4), Le32(0), Le32(4),
        Bytes({'K', 'e', 'y', 0}),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Bytes({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900F0u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.lookup_name == "Key");
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK_EQ(call.card_id.size(), size_t{16});
    if (call.card_id.size() == 16) {
        CHECK_EQ(call.card_id[0], static_cast<uint8_t>(0x01));
        CHECK_EQ(call.card_id[15], static_cast<uint8_t>(0x10));
    }
    CHECK_EQ(call.freshness, 7u);
    CHECK_EQ(call.cache_is_null, 1u);
    CHECK_EQ(call.cache_capacity, 16u);
}

RTSC_TEST(smartcard_read_cache_w_call_parse) {
    // ReadCacheW_Call: same as A but szLookupName is a UTF-16LE [string].
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00020008),
        Le32(7), Le32(1), Le32(16),
        Le32(4), Le32(0), Le32(4),
        Bytes({'K', 0, 'e', 0, 'y', 0, 0, 0}),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Bytes({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900F4u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.code == ScardIoctl::kReadCacheW);
    CHECK(call.lookup_name_w == u"Key");
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK_EQ(call.card_id.size(), size_t{16});
    CHECK_EQ(call.freshness, 7u);
    CHECK_EQ(call.cache_is_null, 1u);
    CHECK_EQ(call.cache_capacity, 16u);
}

RTSC_TEST(smartcard_read_cache_a_call_rejects_null_lookup_name) {
    const std::vector<uint8_t> body = Concat({
        Le32(0),  // szLookupName NULL
        Le32(4), Le32(0x00020000),
        Le32(0x00020004),
        Le32(0), Le32(0), Le32(0),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Zeros(16),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900F0u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_read_cache_a_call_rejects_null_uuid) {
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0),  // CardIdentifier NULL
        Le32(0), Le32(0), Le32(0),
        Le32(4), Le32(0), Le32(4),
        Bytes({'K', 'e', 'y', 0}),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900F0u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_read_cache_return_exact_bytes) {
    ScardReturn ret;
    ret.cache = std::vector<uint8_t>({0x10, 0x20, 0x30});
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kReadCacheA, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(3), Le32(0x00020000),
                                 Le32(3), Bytes({0x10, 0x20, 0x30}),
                                 Zeros(1)}))));
}

RTSC_TEST(smartcard_read_cache_return_length_probe_has_null_buffer) {
    ScardReturn ret;
    ret.cache_length = 5;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kReadCacheA, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(5), Le32(0)}))));
}

RTSC_TEST(smartcard_read_cache_return_failure_drops_data) {
    ScardReturn ret;
    ret.return_code = 0x80100070u;  // SCARD_W_CACHE_ITEM_NOT_FOUND
    ret.cache = std::vector<uint8_t>({0xAA});
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kReadCacheA, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0x80100070u), Le32(0), Le32(0)}))));
}

RTSC_TEST(smartcard_write_cache_a_call_parse) {
    // WriteCacheA_Call: szLookupName ptr, Context, UUID ptr, FreshnessCounter,
    // cbDataLen, pbData ptr; referents: name, context, UUID, data.
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00020008),
        Le32(9), Le32(3), Le32(0x0002000C),
        Le32(4), Le32(0), Le32(4),
        Bytes({'K', 'e', 'y', 0}),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Bytes({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}),
        Le32(3), Bytes({0x10, 0x20, 0x30}), Zeros(1),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900F8u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.lookup_name == "Key");
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK_EQ(call.card_id.size(), size_t{16});
    CHECK_EQ(call.freshness, 9u);
    CHECK(call.write_cache_data ==
          std::vector<uint8_t>({0x10, 0x20, 0x30}));
}

RTSC_TEST(smartcard_write_cache_w_call_parse) {
    // WriteCacheW_Call: same as A but szLookupName is a UTF-16LE [string].
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00020008),
        Le32(9), Le32(3), Le32(0x0002000C),
        Le32(4), Le32(0), Le32(4),
        Bytes({'K', 0, 'e', 0, 'y', 0, 0, 0}),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Bytes({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}),
        Le32(3), Bytes({0x10, 0x20, 0x30}), Zeros(1),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900FCu, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.code == ScardIoctl::kWriteCacheW);
    CHECK(call.lookup_name_w == u"Key");
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK_EQ(call.card_id.size(), size_t{16});
    CHECK_EQ(call.freshness, 9u);
    CHECK(call.write_cache_data ==
          std::vector<uint8_t>({0x10, 0x20, 0x30}));
}

RTSC_TEST(smartcard_write_cache_a_call_accepts_null_data) {
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00020008),
        Le32(0), Le32(0), Le32(0),  // cbDataLen = 0, pbData NULL
        Le32(4), Le32(0), Le32(4),
        Bytes({'K', 'e', 'y', 0}),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Zeros(16),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900F8u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.write_cache_data.empty());
}

RTSC_TEST(smartcard_write_cache_a_call_rejects_ndr_length_mismatch) {
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00020008),
        Le32(0), Le32(5), Le32(0x0002000C),
        Le32(4), Le32(0), Le32(4),
        Bytes({'K', 'e', 'y', 0}),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Zeros(16),
        Le32(2), Bytes({0xAA, 0xBB}), Zeros(2),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900F8u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_write_cache_a_call_rejects_oversized_data) {
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0x00020008),
        Le32(0), Le32(65537), Le32(0),
        Le32(4), Le32(0), Le32(4),
        Bytes({'K', 'e', 'y', 0}),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Zeros(16),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900F8u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_write_cache_a_call_rejects_null_uuid) {
    const std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0),  // CardIdentifier NULL
        Le32(0), Le32(0), Le32(0),
        Le32(4), Le32(0), Le32(4),
        Bytes({'K', 'e', 'y', 0}),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900F8u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_get_reader_icon_call_parse) {
    // GetReaderIcon_Call: Context, szReaderName ptr; referents: context,
    // UTF-16LE [string] with character-counted lengths.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(0x00020004),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(3), Le32(0), Le32(3),
        Bytes({'R', 0, '0', 0, 0, 0}), Zeros(2),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090104u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.reader_name == u"R0");
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
}

RTSC_TEST(smartcard_get_reader_icon_call_rejects_null_name) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(0),  // szReaderName NULL
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090104u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_get_reader_icon_call_rejects_missing_nul) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(0x00020004),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(2), Le32(0), Le32(2),
        Bytes({'R', 0, '0', 0}),  // no UTF-16 NUL terminator
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090104u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_get_reader_icon_return_exact_bytes) {
    ScardReturn ret;
    ret.icon = std::vector<uint8_t>({0x89, 0x50, 0x4E, 0x47});
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetReaderIcon, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(4), Le32(0x00020000),
                                 Le32(4),
                                 Bytes({0x89, 0x50, 0x4E, 0x47})}))));
}

RTSC_TEST(smartcard_get_reader_icon_return_failure_drops_data) {
    ScardReturn ret;
    ret.return_code = 0x80100009u;  // SCARD_E_UNKNOWN_READER
    ret.icon = std::vector<uint8_t>({0xAA});
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetReaderIcon, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0x80100009u), Le32(0), Le32(0)}))));
}

RTSC_TEST(smartcard_get_reader_icon_return_rejects_oversized_data) {
    ScardReturn ret;
    ret.icon = std::vector<uint8_t>(kScardMaxIconBytes + 1, 0x11);
    CHECK(EncodeScardReturn(ScardIoctl::kGetReaderIcon, ret).empty());
}

RTSC_TEST(smartcard_get_device_type_id_call_parse) {
    // Same wire form as GetReaderIcon_Call: Context + WCHAR [string].
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(0x00020004),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(3), Le32(0), Le32(3),
        Bytes({'R', 0, '0', 0, 0, 0}), Zeros(2),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090108u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.reader_name == u"R0");
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
}

RTSC_TEST(smartcard_get_device_type_id_return_exact_bytes) {
    ScardReturn ret;
    ret.device_type_id = 0x0000000A;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetDeviceTypeId, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(0x0000000A)}))));
}

RTSC_TEST(smartcard_get_device_type_id_return_failure_keeps_device_id) {
    ScardReturn ret;
    ret.return_code = 0x80100009u;  // SCARD_E_UNKNOWN_READER
    ret.device_type_id = 0x0000000A;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetDeviceTypeId, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0x80100009u), Le32(0x0000000A)}))));
}

RTSC_TEST(smartcard_get_transmit_count_call_parse) {
    // GetTransmitCount_Call: REDIR_SCARDHANDLE (context + handle).
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090100u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.handle.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(call.handle.bytes ==
          std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
}

RTSC_TEST(smartcard_get_transmit_count_return_exact_bytes) {
    ScardReturn ret;
    ret.transmit_count = 42;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetTransmitCount, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(42)}))));
}

RTSC_TEST(smartcard_get_transmit_count_return_failure_keeps_count) {
    ScardReturn ret;
    ret.return_code = 0x80100003u;  // SCARD_E_INVALID_HANDLE
    ret.transmit_count = 42;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kGetTransmitCount, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0x80100003u), Le32(42)}))));
}

RTSC_TEST(smartcard_locate_cards_by_atr_a_call_parse) {
    // LocateCardsByATRA_Call: Context, cAtrs, masks ptr, cReaders, states
    // ptr; referents: context, mask array, ReaderStateA array.
    std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(1), Le32(0x00020004),
        Le32(1), Le32(0x00020008),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(1),
        Le32(2),
        Bytes({0x3B, 0x00}), Zeros(34),
        Bytes({0xFF, 0xFF}), Zeros(34),
        Le32(1),
        Le32(0x0002000C),
        Le32(7), Le32(0), Le32(0), Zeros(36),
        Le32(3), Le32(0), Le32(3),
        Bytes({'R', '0', 0}), Zeros(1),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900E8u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK_EQ(call.atr_masks.size(), size_t{1});
    if (call.atr_masks.size() == 1) {
        CHECK_EQ(call.atr_masks[0].cb_atr, 2u);
        CHECK(call.atr_masks[0].atr ==
              std::vector<uint8_t>({0x3B, 0x00}));
        CHECK(call.atr_masks[0].mask ==
              std::vector<uint8_t>({0xFF, 0xFF}));
    }
    CHECK_EQ(call.reader_states.size(), size_t{1});
    if (call.reader_states.size() == 1) {
        CHECK(call.reader_states[0].reader == "R0");
        CHECK_EQ(call.reader_states[0].current_state, 7u);
    }
}

RTSC_TEST(smartcard_locate_cards_by_atr_w_call_parse) {
    // LocateCardsByATRW_Call: same as A but reader names are UTF-16LE.
    std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(1), Le32(0x00020004),
        Le32(1), Le32(0x00020008),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(1),
        Le32(2),
        Bytes({0x3B, 0x00}), Zeros(34),
        Bytes({0xFF, 0xFF}), Zeros(34),
        Le32(1),
        Le32(0x0002000C),
        Le32(7), Le32(0), Le32(0), Zeros(36),
        Le32(3), Le32(0), Le32(3),
        Bytes({'R', 0, '0', 0, 0, 0}), Zeros(2),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900ECu, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.code == ScardIoctl::kLocateCardsByAtrW);
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK_EQ(call.atr_masks.size(), size_t{1});
    if (call.atr_masks.size() == 1) {
        CHECK_EQ(call.atr_masks[0].cb_atr, 2u);
        CHECK(call.atr_masks[0].atr ==
              std::vector<uint8_t>({0x3B, 0x00}));
        CHECK(call.atr_masks[0].mask ==
              std::vector<uint8_t>({0xFF, 0xFF}));
    }
    CHECK_EQ(call.reader_states_w.size(), size_t{1});
    if (call.reader_states_w.size() == 1) {
        CHECK(call.reader_states_w[0].reader == u"R0");
        CHECK_EQ(call.reader_states_w[0].current_state, 7u);
    }
}

RTSC_TEST(smartcard_locate_cards_by_atr_a_call_rejects_too_many_masks) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(1001), Le32(0x00020004),
        Le32(0), Le32(0),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900E8u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_locate_cards_by_atr_a_call_rejects_oversized_atr) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(1), Le32(0x00020004),
        Le32(0), Le32(0),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(1),
        Le32(37), Zeros(36), Zeros(36),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900E8u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_locate_cards_by_atr_a_call_rejects_mask_count_mismatch) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(2), Le32(0x00020004),
        Le32(0), Le32(0),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(1),  // array MaxCount != cAtrs
        Le32(0), Zeros(36), Zeros(36),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900E8u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_locate_cards_by_atr_a_call_rejects_pointer_count_mismatch) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(0), Le32(0x00020004),  // cAtrs = 0 but non-NULL masks pointer
        Le32(0), Le32(0),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900E8u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_locate_cards_by_atr_a_return_exact_bytes) {
    ScardReturn ret;
    ScardReaderStateReturn st;
    st.current_state = 1;
    st.event_state = 0x40;
    st.atr = {0x3B, 0x00};
    ret.reader_states.push_back(st);
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kLocateCardsByAtrA, ret);
    std::vector<uint8_t> expected = Concat({
        Le32(0), Le32(1), Le32(0x00020000), Le32(1),
        Le32(1), Le32(0x40), Le32(2),
        Bytes({0x3B, 0x00}), Zeros(34),
    });
    CHECK(Same(got, Wrap(expected)));
}

RTSC_TEST(smartcard_access_started_event_call_is_bare_four_bytes) {
    const uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    ScardCall call;
    CHECK(ParseScardCall(0x000900E0u, payload, sizeof(payload), call) ==
          Status::Ok);
    CHECK(call.code == ScardIoctl::kAccessStartedEvent);
    CHECK(ParseScardCall(0x000900E0u, payload, 3, call) ==
          Status::InvalidLength);
    CHECK(ParseScardCall(0x000900E0u, payload, 5, call) ==
          Status::InvalidLength);
}

RTSC_TEST(smartcard_access_started_event_return_exact_bytes) {
    ScardReturn ret;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kAccessStartedEvent, ret);
    CHECK(Same(got, Wrap(Le32(0))));
    ret.return_code = 0x8010001Du;  // SCARD_E_NO_SERVICE
    const std::vector<uint8_t> failed =
        EncodeScardReturn(ScardIoctl::kAccessStartedEvent, ret);
    CHECK(Same(failed, Wrap(Le32(0x8010001Du))));
}

RTSC_TEST(smartcard_cancel_call_parse) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900A8u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.code == ScardIoctl::kCancel);
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
}

RTSC_TEST(smartcard_state_call_parse) {
    // State_Call: REDIR_SCARDHANDLE, fpbAtrIsNULL, cbAtrLen.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(1), Le32(36),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900C4u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.handle.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(call.handle.bytes ==
          std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
    CHECK_EQ(call.atr_is_null, 1u);
    CHECK_EQ(call.atr_capacity, 36u);
}

RTSC_TEST(smartcard_state_return_exact_bytes) {
    ScardReturn ret;
    ret.state = 0x34;
    ret.protocol = 2;
    ret.state_atr = std::vector<uint8_t>({0x3B, 0x00});
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kState, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(0x34), Le32(2), Le32(2),
                                 Le32(0x00020000), Le32(2),
                                 Bytes({0x3B, 0x00}), Zeros(2)}))));
}

RTSC_TEST(smartcard_state_return_probe_has_null_atr) {
    ScardReturn ret;
    ret.state = 0x34;
    ret.protocol = 2;
    ret.state_atr_length = 2;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kState, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(0x34), Le32(2), Le32(2),
                                 Le32(0)}))));
}

RTSC_TEST(smartcard_state_return_failure_drops_atr) {
    ScardReturn ret;
    ret.return_code = 0x80100008u;  // SCARD_E_INSUFFICIENT_BUFFER
    ret.state = 0x34;
    ret.protocol = 2;
    ret.state_atr = std::vector<uint8_t>({0x3B});
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kState, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0x80100008u), Le32(0x34), Le32(2),
                                 Le32(0), Le32(0)}))));
}

RTSC_TEST(smartcard_connect_w_call_parse) {
    // ConnectW_Call ([MS-RDPESC] 2.2.2.14): szReader ptr, Context,
    // ShareMode, PreferredProtocols; referents: wide reader, context.
    const std::vector<uint8_t> reader = {
        'R', 0, 'e', 0, 'a', 0, 'd', 0, 'e', 0, 'r', 0, 0, 0};
    std::vector<uint8_t> body = Concat({
        Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(2), Le32(3),
        Le32(7), Le32(0), Le32(7),
    });
    body.insert(body.end(), reader.begin(), reader.end());
    while (body.size() % 4 != 0) body.push_back(0);
    body = Concat({body, Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD})});
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900B0u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.code == ScardIoctl::kConnectW);
    CHECK(call.reader_name == u"Reader");
    CHECK_EQ(call.share_mode, 2u);
    CHECK_EQ(call.preferred_protocols, 3u);
    CHECK(call.context.bytes ==
          std::vector<uint8_t>({0x00, 0x00, 0x01, 0xCD}));
}

RTSC_TEST(smartcard_connect_w_return_exact_bytes) {
    ScardReturn ret;
    ret.handle.context.bytes = {0x00, 0x00, 0x01, 0xCD};
    ret.handle.bytes = {0xAA, 0xBB, 0xCC, 0xDD};
    ret.active_protocol = 2;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kConnectW, ret);
    const std::vector<uint8_t> body = Concat({
        Le32(0),
        Le32(4), Le32(0x00020000), Le32(4), Le32(0x00020004),
        Le32(2),
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(4), Bytes({0xAA, 0xBB, 0xCC, 0xDD}),
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_reconnect_call_parse) {
    // Reconnect_Call: REDIR_SCARDHANDLE, share mode, preferred protocols,
    // initialization.
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(2), Le32(3), Le32(1),
        Le32(4), Bytes({0xDE, 0xAD, 0xBE, 0xEF}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900B4u, buf.data(), buf.size(), call) ==
          Status::Ok);
    CHECK(call.handle.context.bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(call.handle.bytes ==
          std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}));
    CHECK_EQ(call.share_mode, 2u);
    CHECK_EQ(call.preferred_protocols, 3u);
    CHECK_EQ(call.initialization, 1u);
}

RTSC_TEST(smartcard_reconnect_return_exact_bytes) {
    ScardReturn ret;
    ret.active_protocol = 3;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kReconnect, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0), Le32(3)}))));
}

RTSC_TEST(smartcard_reconnect_return_failure_keeps_protocol) {
    ScardReturn ret;
    ret.return_code = 0x80100003u;  // SCARD_E_INVALID_HANDLE
    ret.active_protocol = 3;
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kReconnect, ret);
    CHECK(Same(got, Wrap(Concat({Le32(0x80100003u), Le32(3)}))));
}

RTSC_TEST(smartcard_control_return_rejects_oversized_buffer) {
    ScardReturn ret;
    ret.out_buffer = std::vector<uint8_t>(kScardMaxTransmitBytes + 1, 0x11);
    CHECK(EncodeScardReturn(ScardIoctl::kControl, ret).empty());
}

// ---------------------------------------------------------------------------
// SCARD_IOCTL_STATUSA ([MS-RDPESC] 2.2.2.18 / 2.2.3.10)
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_status_a_call_parse) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020000),
        Le32(4), Le32(0x00020004),
        Le32(0),           // fmszReaderNamesIsNULL
        Le32(0xFFFFFFFFu), // cchReaderLen
        Le32(32),          // cbAtrLen
        Le32(4), Bytes({0x00, 0x00, 0x01, 0xCD}),
        Le32(4), Bytes({0x11, 0x22, 0x33, 0x44}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x000900C8u, buf.data(), buf.size(), call) == Status::Ok);
    CHECK_EQ(call.reader_names_is_null, 0u);
    CHECK_EQ(call.reader_names_cch, 0xFFFFFFFFu);
    CHECK_EQ(call.atr_length, 32u);
}

RTSC_TEST(smartcard_status_return_exact_bytes) {
    ScardReturn ret;
    ret.return_code = 0;
    ret.reader_names = std::vector<uint8_t>{'R', 0, 0};
    ret.state = 0x20;
    ret.protocol = 2;
    ret.atr = {0x3B, 0x8F};
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kStatusA, ret);
    std::vector<uint8_t> body = Concat({
        Le32(0), Le32(3), Le32(0x00020000),
        Le32(0x20), Le32(2),
        Bytes({0x3B, 0x8F}), Zeros(30),  // pbAtr[32]
        Le32(2),                         // cbAtrLen
        Le32(3), Bytes({'R', 0, 0}), Zeros(1),  // names referent
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_status_return_rejects_oversized_atr) {
    ScardReturn ret;
    ret.atr.assign(kScardMaxStatusAtr + 1, 0);
    CHECK(EncodeScardReturn(ScardIoctl::kStatusA, ret).empty());
}

RTSC_TEST(smartcard_status_w_return_exact_bytes) {
    ScardReturn ret;
    ret.reader_names = std::vector<uint8_t>{'R', 0, 0, 0, 0, 0};
    ret.state = 0x20;
    ret.protocol = 2;
    ret.atr = {0x3B, 0x8F};
    const std::vector<uint8_t> got =
        EncodeScardReturn(ScardIoctl::kStatusW, ret);
    const std::vector<uint8_t> body = Concat({
        Le32(0), Le32(6), Le32(0x00020000),
        Le32(0x20), Le32(2),
        Bytes({0x3B, 0x8F}), Zeros(30),  // pbAtr[32]
        Le32(2),                         // cbAtrLen
        Le32(6), Bytes({'R', 0, 0, 0, 0, 0}), Zeros(2),  // names referent
    });
    CHECK(Same(got, Wrap(body)));
}

RTSC_TEST(smartcard_status_w_return_rejects_odd_names) {
    ScardReturn ret;
    ret.reader_names = std::vector<uint8_t>{'R', 0, 0, 0, 0};
    CHECK(EncodeScardReturn(ScardIoctl::kStatusW, ret).empty());
}

// ---------------------------------------------------------------------------
// Fail-closed inputs
// ---------------------------------------------------------------------------

RTSC_TEST(smartcard_parse_rejects_wrong_pointer_index) {
    const std::vector<uint8_t> body = Concat({
        Le32(4), Le32(0x00020004),  // first pointer must be 0x00020000
        Le32(4), Bytes({1, 2, 3, 4}),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090018u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_parse_rejects_context_pointer_inconsistency) {
    {
        // cbContext = 0 but a non-NULL pointer.
        const std::vector<uint8_t> buf = Wrap(Concat({Le32(0), Le32(0x00020000)}));
        ScardCall call;
        CHECK(ParseScardCall(0x00090018u, buf.data(), buf.size(), call) ==
              Status::InvalidField);
    }
    {
        // cbContext != 0 but a NULL pointer.
        const std::vector<uint8_t> buf = Wrap(Concat({Le32(4), Le32(0)}));
        ScardCall call;
        CHECK(ParseScardCall(0x00090018u, buf.data(), buf.size(), call) ==
              Status::InvalidField);
    }
}

RTSC_TEST(smartcard_parse_rejects_context_over_16_bytes) {
    const std::vector<uint8_t> body = Concat({
        Le32(17), Le32(0x00020000),
        Le32(17), std::vector<uint8_t>(17, 0x5A), Zeros(3),
    });
    const std::vector<uint8_t> buf = Wrap(body);
    ScardCall call;
    CHECK(ParseScardCall(0x00090018u, buf.data(), buf.size(), call) ==
          Status::InvalidField);
}

RTSC_TEST(smartcard_parse_requires_ndr_headers) {
    ScardCall call;
    uint8_t scope[4] = {2, 0, 0, 0};
    // A 4-byte buffer cannot hold the 16-byte NDR prefix at all; version is
    // only checked once the full header is present.
    CHECK(ParseScardCall(0x00090014u, scope, sizeof(scope), call) ==
          Status::NeedMoreData);
}

RTSC_TEST(smartcard_parse_rejects_overlong_payload_declaration) {
    std::vector<uint8_t> buf = Wrap(Le32(2));
    const uint32_t huge = static_cast<uint32_t>(kScardMaxPayloadBytes + 1);
    for (int i = 0; i < 4; ++i) {
        buf[8 + i] = static_cast<uint8_t>((huge >> (8 * i)) & 0xFF);
    }
    ScardCall call;
    CHECK(ParseScardCall(0x00090014u, buf.data(), buf.size(), call) ==
          Status::InvalidLength);
}

RTSC_TEST(smartcard_return_declares_exact_object_length) {
    // Every encoded return must declare an ObjectBufferLength that covers the
    // remainder of the buffer exactly.
    ScardReturn ret;
    ret.return_code = 0;
    ret.multi_string = std::vector<uint8_t>{'A', 0, 0};
    const std::vector<uint8_t> buf =
        EncodeScardReturn(ScardIoctl::kListReadersA, ret);
    CHECK(buf.size() >= ScardNdrHeader::kSize);
    if (buf.size() >= ScardNdrHeader::kSize) {
        ScardNdrHeader h;
        size_t off = 0, body = 0;
        CHECK(ScardNdrHeader::parse(buf.data(), buf.size(), h, off, body) ==
              Status::Ok);
        CHECK_EQ(off + body, buf.size());
        CHECK_EQ(buf.size() % 8, size_t{0});
    }
}

RTSC_TEST(smartcard_return_rejects_unsupported_ioctl) {
    ScardReturn ret;
    // Client-to-server only: INTRODUCEREADERGROUPA (0x00090050) and
    // INTRODUCEREADERW (0x00090064) are never handled by the TS client.
    CHECK(EncodeScardReturn(static_cast<ScardIoctl>(0x00090050u), ret).empty());
    CHECK(EncodeScardReturn(static_cast<ScardIoctl>(0x00090064u), ret).empty());
}

int main() { return ::rtsc::test::run_all("rtsc_smartcard_tests"); }
