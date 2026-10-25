// Independent red/green harness for the capability-set walk.
//
// PURPOSE: reproduce the F-03 / F-12 / F-13 findings by modelling the pseudo-code
// that capabilities.md:844-853 actually contains, then modelling the corrected
// walk that adds the three missing upper bounds.
//
// FIDELITY NOTE (raised by audit A in capabilities.consult-a.md 11.3 / 12.4):
// The document pseudo-code has NO upper-bound checks and NO `lcc < 4` guard.
// It DOES have the line-849 check `if len < 4: error`, which this harness
// reproduces (case F). A harness cannot literally perform the out-of-bounds read
// without crashing, so every "read" below is preceded by an explicit
// `WouldRead()` test. That test is a *model* of "this read would go past the
// end", not an actual access; harness output therefore reports a MODELLED
// conclusion, not a real OOB access. The control flow is otherwise byte-for-byte
// the document's, including the uint16 underflow on `lcc - 4` and the final
// `assert(p == caps_end)`. Verbatim cross-check: a_r4_literal.py.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

struct Result {
    std::string tag;
    size_t off = 0;
    size_t len = 0;
    size_t end = 0;
};

// Models `read n bytes at off` against a buffer of `size` bytes without touching
// memory outside it. Returns false when the document's code would have read OOB.
bool WouldRead(size_t off, size_t n, size_t size) {
    return off <= size && n <= size - off;
}

// capabilities.md:844-853, verbatim control flow.
//   caps_start = p; caps_end = caps_start + lengthCombinedCapabilities - 4
//   for i in 0..numberCapabilities:
//       type = LE16(p); len = LE16(p+2)
//       if len < 4: error            # line 849, present in the document
//       process(type, p, len); p += len
//   assert(p == caps_end)
Result WalkDoc(const std::vector<uint8_t>& buf, uint16_t count, uint16_t lcc) {
    // The document computes `lcc - 4` in a 16-bit context; with lcc < 4 that
    // underflows to a huge value instead of erroring. Modelled as uint16_t.
    const size_t end = static_cast<uint16_t>(static_cast<uint16_t>(lcc) - 4);
    size_t p = 0;
    for (uint16_t i = 0; i < count; ++i) {
        // The document has no bounds check on the header read. Model it.
        if (!WouldRead(p, 4, buf.size())) return {"OOB-READ-HEADER", p, 4, end};
        const uint16_t len =
            static_cast<uint16_t>(buf[p + 2] | static_cast<uint16_t>(buf[p + 3] << 8));
        // Line 849 of the document: `if len < 4: error`. This check IS present in
        // the pseudo-code and must be reproduced verbatim - omitting it would be
        // the mirror image of adding checks the document does not have.
        if (len < 4) return {"ERR-len<4", p, len, end};
        if (!WouldRead(p, len, buf.size())) return {"OOB-READ-BODY", p, len, end};
        p += len;
    }
    // `assert(p == caps_end)` in the document.
    if (p != end) return {"ASSERT-FAIL", p, 0, end};
    return {"OK", p, 0, end};
}

// The corrected walk: all three upper bounds plus an explicit count check.
Result WalkFixed(const std::vector<uint8_t>& buf, uint16_t count, uint16_t lcc) {
    if (lcc < 4) return {"ERR-lcc<4", 0, 0, 0};
    const size_t end = static_cast<size_t>(lcc) - 4;
    if (end > buf.size()) return {"ERR-window>buf", 0, 0, end};
    if (static_cast<size_t>(count) * 4 > end) return {"ERR-count-too-big", 0, 0, end};
    size_t p = 0;
    for (uint16_t i = 0; i < count; ++i) {
        if (p + 4 > end) return {"ERR-header-oob", p, 4, end};
        const uint16_t len =
            static_cast<uint16_t>(buf[p + 2] | static_cast<uint16_t>(buf[p + 3] << 8));
        if (len < 4) return {"ERR-len<4", p, len, end};
        if (p + len > end) return {"ERR-body-oob", p, len, end};
        p += len;
    }
    if (p != end) return {"ERR-trailing", p, 0, end};
    return {"OK", p, 0, end};
}

void Report(const char* name, const std::vector<uint8_t>& buf, uint16_t count, uint16_t lcc) {
    const Result d = WalkDoc(buf, count, lcc);
    const Result f = WalkFixed(buf, count, lcc);
    std::printf("%-28s doc=%-18s off=%zu len=%zu end=%zu | fix=%s\n", name, d.tag.c_str(),
                d.off, d.len, d.end, f.tag.c_str());
}

}  // namespace

int main() {
    // A: numberCapabilities = 3 but only one 24-byte General set is present.
    //    F-12. The loop reaches p == end == 24 and still reads a header.
    {
        std::vector<uint8_t> b = {0x01, 0x00, 0x18, 0x00};
        b.resize(24, 0);
        Report("A count>data (F-12)", b, 3, static_cast<uint16_t>(4 + 24));
    }
    // B: lengthCapability = 200 with only 8 bytes left. F-03.
    {
        std::vector<uint8_t> b = {0x01, 0x00, 0xC8, 0x00, 0, 0, 0, 0};
        Report("B len>remaining (F-03)", b, 1, static_cast<uint16_t>(4 + 8));
    }
    // C: well-formed single General set (green control).
    {
        std::vector<uint8_t> b = {0x01, 0x00, 0x18, 0x00};
        b.resize(24, 0);
        Report("C legal (green)", b, 1, static_cast<uint16_t>(4 + 24));
    }
    // D: lengthCombinedCapabilities = 2. F-13. Underflows to 65534, so the walk
    //    finishes cleanly and only the final assert fails - NOT an OOB read.
    {
        std::vector<uint8_t> b = {0x01, 0x00, 0x18, 0x00};
        b.resize(24, 0);
        Report("D lcc=2 (F-13)", b, 1, 2);
    }
    // E: trailing slack - one valid set, lcc declares 8 more bytes.
    {
        std::vector<uint8_t> b = {0x01, 0x00, 0x18, 0x00};
        b.resize(32, 0);
        Report("E trailing slack", b, 1, static_cast<uint16_t>(4 + 32));
    }
    // F: lengthCapability = 0 would make the walk never advance (F-03 variant).
    {
        std::vector<uint8_t> b = {0x01, 0x00, 0x00, 0x00};
        b.resize(24, 0);
        Report("F len=0", b, 2, static_cast<uint16_t>(4 + 24));
    }
    return 0;
}
