// Binary Raster Operation (ROP2) engine ([MS-RDPEGDI] 2.2.2.1.1.2).
//
// The oracle below is an independent Reverse Polish Notation interpreter.
// The truth values are derived by evaluating the spec's RPN expression for
// every code; they are not a hand-copied truth table. rop2_eval is then
// compared against that oracle for all 16 codes x the four (s, d) inputs.

#include "rtsc/proto/rop.h"

#include <cstdint>
#include <cstdio>

#include "test_framework.h"
#include "test_main.h"

using namespace rtsc::proto;

namespace {

// Evaluates a ROP2 RPN expression over single-bit operands.
//   operands: D (destination), P (pen/source), 0, 1
//   operators: n (unary NOT), a (AND), o (OR), x (XOR)
// Returns the number of values left on the stack (1 for a valid expression)
// and stores the top value in `out`.
int RpnEvalDepth(const char* expr, uint8_t s, uint8_t d, uint8_t& out) {
    uint8_t stack[8];
    int sp = 0;
    for (const char* c = expr; *c != '\0'; ++c) {
        switch (*c) {
            case 'D': stack[sp++] = static_cast<uint8_t>(d != 0 ? 1 : 0); break;
            case 'P': stack[sp++] = static_cast<uint8_t>(s != 0 ? 1 : 0); break;
            case '0': stack[sp++] = 0; break;
            case '1': stack[sp++] = 1; break;
            case 'n': {
                const uint8_t a = stack[--sp];
                stack[sp++] = static_cast<uint8_t>(a ^ 1);
                break;
            }
            case 'a': {
                const uint8_t b = stack[--sp];
                const uint8_t a = stack[--sp];
                stack[sp++] = static_cast<uint8_t>(a & b);
                break;
            }
            case 'o': {
                const uint8_t b = stack[--sp];
                const uint8_t a = stack[--sp];
                stack[sp++] = static_cast<uint8_t>(a | b);
                break;
            }
            case 'x': {
                const uint8_t b = stack[--sp];
                const uint8_t a = stack[--sp];
                stack[sp++] = static_cast<uint8_t>(a ^ b);
                break;
            }
            default: break;  // ignore any non-operator byte
        }
    }
    out = sp > 0 ? stack[sp - 1] : 0;
    return sp;
}

uint8_t RpnEval(const char* expr, uint8_t s, uint8_t d) {
    uint8_t out = 0;
    RpnEvalDepth(expr, s, d, out);
    return out;
}

// Evaluates a ROP3 RPN expression over single-bit operands.
//   operands: S (source), D (destination), P (pattern/pen), 0, 1
//   operators: n (unary NOT), a (AND), o (OR), x (XOR)
// Returns the stack depth (1 for a valid expression) and the top value.
int RpnEval3Depth(const char* expr, uint8_t s, uint8_t d, uint8_t p,
                  uint8_t& out) {
    uint8_t stack[16];
    int sp = 0;
    for (const char* c = expr; *c != '\0'; ++c) {
        switch (*c) {
            case 'S': stack[sp++] = static_cast<uint8_t>(s != 0 ? 1 : 0); break;
            case 'D': stack[sp++] = static_cast<uint8_t>(d != 0 ? 1 : 0); break;
            case 'P': stack[sp++] = static_cast<uint8_t>(p != 0 ? 1 : 0); break;
            case '0': stack[sp++] = 0; break;
            case '1': stack[sp++] = 1; break;
            case 'n': {
                const uint8_t a = stack[--sp];
                stack[sp++] = static_cast<uint8_t>(a ^ 1);
                break;
            }
            case 'a': {
                const uint8_t b = stack[--sp];
                const uint8_t a = stack[--sp];
                stack[sp++] = static_cast<uint8_t>(a & b);
                break;
            }
            case 'o': {
                const uint8_t b = stack[--sp];
                const uint8_t a = stack[--sp];
                stack[sp++] = static_cast<uint8_t>(a | b);
                break;
            }
            case 'x': {
                const uint8_t b = stack[--sp];
                const uint8_t a = stack[--sp];
                stack[sp++] = static_cast<uint8_t>(a ^ b);
                break;
            }
            default: break;  // ignore any non-operator byte
        }
    }
    out = sp > 0 ? stack[sp - 1] : 0;
    return sp;
}

uint8_t RpnEval3(const char* expr, uint8_t s, uint8_t d, uint8_t p) {
    uint8_t out = 0;
    RpnEval3Depth(expr, s, d, p, out);
    return out;
}

struct Rop2Case {
    uint8_t code;
    const char* name;
    const char* rpn;
};

// [MS-RDPEGDI] 2.2.2.1.1.2, in code order 0x01..0x10.
const Rop2Case kRop2Cases[16] = {
    {R2_BLACK,       "R2_BLACK",       "0"},
    {R2_NOTMERGEPEN, "R2_NOTMERGEPEN", "DPon"},
    {R2_MASKNOTPEN,  "R2_MASKNOTPEN",  "DPna"},
    {R2_NOTCOPYPEN,  "R2_NOTCOPYPEN",  "Pn"},
    {R2_MASKPENNOT,  "R2_MASKPENNOT",  "PDna"},
    {R2_NOT,         "R2_NOT",         "Dn"},
    {R2_XORPEN,      "R2_XORPEN",      "DPx"},
    {R2_NOTMASKPEN,  "R2_NOTMASKPEN",  "DPan"},
    {R2_MASKPEN,     "R2_MASKPEN",     "DPa"},
    {R2_NOTXORPEN,   "R2_NOTXORPEN",   "DPxn"},
    {R2_NOP,         "R2_NOP",         "D"},
    {R2_MERGENOTPEN, "R2_MERGENOTPEN", "DPno"},
    {R2_COPYPEN,     "R2_COPYPEN",     "P"},
    {R2_MERGEPENNOT, "R2_MERGEPENNOT", "PDno"},
    {R2_MERGEPEN,    "R2_MERGEPEN",    "PDo"},
    {R2_WHITE,       "R2_WHITE",       "1"},
};

// [MS-RDPEGDI] 2.2.2.2.1.1.1.7, in index order 0x00..0xFF. This is the
// independent oracle: the truth bytes are derived by evaluating these RPN
// expressions, never hand-copied.
const char* const kRop3Rpn[256] = {
    "0", "DPSoon", "DPSona", "PSon", "SDPona", "DPon", "PDSxnon", "PDSaon",  // 0x00
    "SDPnaa", "PDSxon", "DPna", "PSDnaon", "SPna", "PDSnaon", "PDSonon", "Pn",  // 0x08
    "PDSona", "DSon", "SDPxnon", "SDPaon", "DPSxnon", "DPSaon", "PSDPSanaxx", "SSPxDSxaxn",  // 0x10
    "SPxPDxa", "SDPSanaxn", "PDSPaox", "SDPSxaxn", "PSDPaox", "DSPDxaxn", "PDSox", "PDSoan",  // 0x18
    "DPSnaa", "SDPxon", "DSna", "SPDnaon", "SPxDSxa", "PDSPanaxn", "SDPSaox", "SDPSxnox",  // 0x20
    "DPSxa", "PSDPSaoxxn", "DPSana", "SSPxPDxaxn", "SPDSoax", "PSDnox", "PSDPxox", "PSDnoan",  // 0x28
    "PSna", "SDPnaon", "SDPSoox", "Sn", "SPDSaox", "SPDSxnox", "SDPox", "SDPoan",  // 0x30
    "PSDPoax", "SPDnox", "SPDSxox", "SPDnoan", "PSx", "SPDSonox", "SPDSnaox", "PSan",  // 0x38
    "PSDnaa", "DPSxon", "SDxPDxa", "SPDSanaxn", "SDna", "DPSnaon", "DSPDaox", "PSDPxaxn",  // 0x40
    "SDPxa", "PDSPDaoxxn", "DPSDoax", "PDSnox", "SDPana", "SSPxDSxoxn", "PDSPxox", "PDSnoan",  // 0x48
    "PDna", "DSPnaon", "DPSDaox", "SPDSxaxn", "DPSonon", "Dn", "DPSox", "DPSoan",  // 0x50
    "PDSPoax", "DPSnox", "DPx", "DPSDonox", "DPSDxox", "DPSnoan", "DPSDnaox", "DPan",  // 0x58
    "PDSxa", "DSPDSaoxxn", "DSPDoax", "SDPnox", "SDPSoax", "DSPnox", "DSx", "SDPSonox",  // 0x60
    "DSPDSonoxxn", "PDSxxn", "DPSax", "PSDPSoaxxn", "SDPax", "PDSPDoaxxn", "SDPSnoax", "PDSxnan",  // 0x68
    "PDSana", "SSDxPDxaxn", "SDPSxox", "SDPnoan", "DSPDxox", "DSPnoan", "SDPSnaox", "DSan",  // 0x70
    "PDSax", "DSPDSoaxxn", "DPSDnoax", "SDPxnan", "SPDSnoax", "DPSxnan", "SPxDSxo", "DPSaan",  // 0x78
    "DPSaa", "SPxDSxon", "DPSxna", "SPDSnoaxn", "SDPxna", "PDSPnoaxn", "DSPDSoaxx", "PDSaxn",  // 0x80
    "DSa", "SDPSnaoxn", "DSPnoa", "DSPDxoxn", "SDPnoa", "SDPSxoxn", "SSDxPDxax", "PDSanan",  // 0x88
    "PDSxna", "SDPSnoaxn", "DPSDPoaxx", "SPDaxn", "PSDPSoaxx", "DPSaxn", "DPSxx", "PSDPSonoxx",  // 0x90
    "SDPSonoxn", "DSxn", "DPSnax", "SDPSoaxn", "SPDnax", "DSPDoaxn", "DSPDSaoxx", "PDSxan",  // 0x98
    "DPa", "PDSPnaoxn", "DPSnoa", "DPSDxoxn", "PDSPonoxn", "PDxn", "DSPnax", "PDSPoaxn",  // 0xa0
    "DPSoa", "DPSoxn", "D", "DPSono", "SPDSxax", "DPSDaoxn", "DSPnao", "DPno",  // 0xa8
    "PDSnoa", "PDSPxoxn", "SSPxDSxox", "SDPanan", "PSDnax", "DPSDoaxn", "DPSDPaoxx", "SDPxan",  // 0xb0
    "PSDPxax", "DSPDaoxn", "DPSnao", "DSno", "SPDSanax", "SDxPDxan", "DPSxo", "DPSano",  // 0xb8
    "PSa", "SPDSnaoxn", "SPDSonoxn", "PSxn", "SPDnoa", "SPDSxoxn", "SDPnax", "PSDPoaxn",  // 0xc0
    "SDPoa", "SPDoxn", "DPSDxax", "SPDSaoxn", "S", "SDPono", "SDPnao", "SPno",  // 0xc8
    "PSDnoa", "PSDPxoxn", "PDSnax", "SPDSoaxn", "SSPxPDxax", "DPSanan", "PSDPSaoxx", "DPSxan",  // 0xd0
    "PDSPxax", "SDPSaoxn", "DPSDanax", "SPxDSxan", "SPDnao", "SDno", "SDPxo", "SDPano",  // 0xd8
    "PDSoa", "PDSoxn", "DSPDxax", "PSDPaoxn", "SDPSxax", "PDSPaoxn", "SDPSanax", "SPxPDxan",  // 0xe0
    "SSPxDSxax", "DSPDSanaxxn", "DPSao", "DPSxno", "SDPao", "SDPxno", "DSo", "SDPnoo",  // 0xe8
    "P", "PDSono", "PDSnao", "PSno", "PSDnao", "PDno", "PDSxo", "PDSano",  // 0xf0
    "PDSao", "PDSxno", "DPo", "DPSnoo", "PSo", "PSDnoo", "DPSoo", "1",  // 0xf8
};

// Per-channel oracle: applies the RPN expression to every bit of one byte.
uint8_t RpnByte(const char* expr, uint8_t s, uint8_t d) {
    uint8_t out = 0;
    for (int bit = 0; bit < 8; ++bit) {
        const uint8_t sb = static_cast<uint8_t>((s >> bit) & 1u);
        const uint8_t db = static_cast<uint8_t>((d >> bit) & 1u);
        out = static_cast<uint8_t>(out | (RpnEval(expr, sb, db) << bit));
    }
    return out;
}

// Per-channel ROP3 oracle: applies the RPN expression to every bit of one byte.
uint8_t RpnByte3(const char* expr, uint8_t s, uint8_t d, uint8_t p) {
    uint8_t out = 0;
    for (int bit = 0; bit < 8; ++bit) {
        const uint8_t sb = static_cast<uint8_t>((s >> bit) & 1u);
        const uint8_t db = static_cast<uint8_t>((d >> bit) & 1u);
        const uint8_t pb = static_cast<uint8_t>((p >> bit) & 1u);
        out = static_cast<uint8_t>(out | (RpnEval3(expr, sb, db, pb) << bit));
    }
    return out;
}

void ReportBitMismatch(const char* name, uint8_t code, const char* rpn, uint8_t s,
                       uint8_t d, uint8_t got, uint8_t want) {
    std::printf("  MISMATCH %s (0x%02X) rpn=%s s=%u d=%u got=%u want=%u\n", name,
                code, rpn, s, d, got, want);
}

}  // namespace

RTSC_TEST(rop2_codes_are_contiguous_0x01_to_0x10) {
    for (int i = 0; i < 16; ++i) {
        CHECK_EQ(kRop2Cases[i].code, static_cast<uint8_t>(i + 1));
    }
}

RTSC_TEST(rop2_rpn_expressions_are_well_formed) {
    // Every spec expression must consume its operands and leave exactly one
    // value, for all four input combinations.
    for (const Rop2Case& c : kRop2Cases) {
        for (uint8_t s = 0; s <= 1; ++s) {
            for (uint8_t d = 0; d <= 1; ++d) {
                uint8_t out = 0;
                CHECK_EQ(RpnEvalDepth(c.rpn, s, d, out), 1);
            }
        }
    }
}

RTSC_TEST(rop2_eval_matches_rpn_all_codes_all_bits) {
    for (const Rop2Case& c : kRop2Cases) {
        for (uint8_t s = 0; s <= 1; ++s) {
            for (uint8_t d = 0; d <= 1; ++d) {
                const uint8_t want = RpnEval(c.rpn, s, d);
                const uint8_t got = rop2_eval(c.code, s, d);
                if (got != want) {
                    ReportBitMismatch(c.name, c.code, c.rpn, s, d, got, want);
                }
                CHECK_EQ(got, want);
            }
        }
    }
}

RTSC_TEST(rop2_apply_per_channel_matches_rpn) {
    const uint32_t pixels[] = {
        0x12345678u, 0x00FF00FFu, 0xA5A5A5A5u, 0xFFFFFFFFu,
        0x00000000u, 0xDEADBEEFu, 0x80000001u, 0xCAFEBABEu,
    };
    for (const Rop2Case& c : kRop2Cases) {
        for (uint32_t sp : pixels) {
            for (uint32_t dp : pixels) {
                const uint32_t got = rop2_apply_per_channel(c.code, sp, dp);
                const uint8_t r = RpnByte(c.rpn, static_cast<uint8_t>(sp >> 16),
                                          static_cast<uint8_t>(dp >> 16));
                const uint8_t g = RpnByte(c.rpn, static_cast<uint8_t>(sp >> 8),
                                          static_cast<uint8_t>(dp >> 8));
                const uint8_t b = RpnByte(c.rpn, static_cast<uint8_t>(sp),
                                          static_cast<uint8_t>(dp));
                const uint32_t want = (dp & 0xFF000000u) |
                                      (static_cast<uint32_t>(r) << 16) |
                                      (static_cast<uint32_t>(g) << 8) |
                                      static_cast<uint32_t>(b);
                if (got != want) {
                    std::printf(
                        "  MISMATCH %s (0x%02X) src=%08X dst=%08X got=%08X want=%08X\n",
                        c.name, c.code, sp, dp, got, want);
                }
                CHECK_EQ(got, want);
            }
        }
    }
}

RTSC_TEST(rop2_eval_known_single_bit_cases) {
    // Spot checks stated directly from the spec descriptions, independent of
    // the RPN table above.
    CHECK_EQ(rop2_eval(R2_BLACK, 0, 0), 0);
    CHECK_EQ(rop2_eval(R2_BLACK, 1, 1), 0);
    CHECK_EQ(rop2_eval(R2_WHITE, 0, 0), 1);
    CHECK_EQ(rop2_eval(R2_WHITE, 1, 0), 1);
    CHECK_EQ(rop2_eval(R2_COPYPEN, 0, 1), 0);
    CHECK_EQ(rop2_eval(R2_COPYPEN, 1, 0), 1);
    CHECK_EQ(rop2_eval(R2_NOP, 0, 1), 1);
    CHECK_EQ(rop2_eval(R2_NOP, 1, 0), 0);
    // R2_NOTXORPEN is the inverse of XOR: equal bits -> 1.
    CHECK_EQ(rop2_eval(R2_NOTXORPEN, 0, 0), 1);
    CHECK_EQ(rop2_eval(R2_NOTXORPEN, 1, 1), 1);
    CHECK_EQ(rop2_eval(R2_NOTXORPEN, 0, 1), 0);
    CHECK_EQ(rop2_eval(R2_NOTXORPEN, 1, 0), 0);
    // R2_MERGEPEN is OR: 1 unless both are 0.
    CHECK_EQ(rop2_eval(R2_MERGEPEN, 0, 0), 0);
    CHECK_EQ(rop2_eval(R2_MERGEPEN, 1, 1), 1);
}

RTSC_TEST(rop2_unknown_code_is_identity) {
    // rop.h contract: codes outside 0x01..0x10 fall back to R2_NOP, i.e.
    // rop2_eval(unknown, s, d) == d.
    CHECK_EQ(rop2_eval(0x00, 1, 0), 0);
    CHECK_EQ(rop2_eval(0x00, 1, 1), 1);
    CHECK_EQ(rop2_eval(0x11, 0, 1), 1);
    CHECK_EQ(rop2_eval(0x11, 1, 0), 0);
    CHECK_EQ(rop2_eval(0xFF, 1, 1), 1);
    CHECK_EQ(rop2_eval(0xFF, 0, 0), 0);
}

// ---------------------------------------------------------------------------
// ROP3 ([MS-RDPEGDI] 2.2.2.2.1.1.1.7)
// ---------------------------------------------------------------------------

RTSC_TEST(rop3_rpn_expressions_are_well_formed) {
    for (int idx = 0; idx < 256; ++idx) {
        for (uint8_t s = 0; s <= 1; ++s)
            for (uint8_t d = 0; d <= 1; ++d)
                for (uint8_t p = 0; p <= 1; ++p) {
                    uint8_t out = 0;
                    CHECK_EQ(RpnEval3Depth(kRop3Rpn[idx], s, d, p, out), 1);
                }
    }
}

RTSC_TEST(rop3_eval_matches_rpn_all_256) {
    for (int idx = 0; idx < 256; ++idx) {
        const char* expr = kRop3Rpn[idx];
        for (uint8_t s = 0; s <= 1; ++s)
            for (uint8_t d = 0; d <= 1; ++d)
                for (uint8_t p = 0; p <= 1; ++p) {
                    const uint8_t want = RpnEval3(expr, s, d, p);
                    const uint8_t got = rop3_eval(static_cast<uint8_t>(idx), s, d, p);
                    if (got != want) {
                        std::printf(
                            "  MISMATCH idx=0x%02X rpn=%s s=%u d=%u p=%u got=%u want=%u\n",
                            idx, expr, s, d, p, got, want);
                    }
                    CHECK_EQ(got, want);
                }
    }
}

RTSC_TEST(rop3_table_matches_standard_index) {
    // bit-rotation self-consistency (secondary check; not the primary
    // evidence): the spec's rop3Index is the truth table under
    // the ordering (p<<2)|(s<<1)|d; reordering into the API's
    // (s<<2)|(d<<1)|p must reproduce kRop3Table.
    for (int idx = 0; idx < 256; ++idx) {
        uint8_t expect = 0;
        for (int s = 0; s < 2; ++s)
            for (int d = 0; d < 2; ++d)
                for (int p = 0; p < 2; ++p)
                    if (idx & (1 << ((p << 2) | (s << 1) | d)))
                        expect |= static_cast<uint8_t>(1 << ((s << 2) | (d << 1) | p));
        CHECK_EQ(kRop3Table[idx], expect);
    }
}

RTSC_TEST(rop3_index_from_code_uses_bits_23_to_16) {
    CHECK_EQ(rop3_index_from_code(0x00F00021u), static_cast<uint8_t>(0xF0));
    CHECK_EQ(rop3_index_from_code(0x00CC0020u), static_cast<uint8_t>(0xCC));
    CHECK_EQ(rop3_index_from_code(0x00550009u), static_cast<uint8_t>(0x55));
    CHECK_EQ(rop3_index_from_code(0x00FF0062u), static_cast<uint8_t>(0xFF));
    CHECK_EQ(rop3_index_from_code(0x12345678u), static_cast<uint8_t>(0x34));
}

RTSC_TEST(rop3_spec_dump_index_code_mapping) {
    // 0xF0 <-> 0x00F00021 (PATCOPY, RPN P)
    CHECK_EQ(rop3_index_from_code(0x00F00021u), static_cast<uint8_t>(0xF0));
    for (uint8_t s = 0; s <= 1; ++s)
        for (uint8_t d = 0; d <= 1; ++d)
            for (uint8_t p = 0; p <= 1; ++p)
                CHECK_EQ(rop3_eval(0xF0, s, d, p), p);
    // 0xCC <-> 0x00CC0020 (SRCCOPY, RPN S)
    CHECK_EQ(rop3_index_from_code(0x00CC0020u), static_cast<uint8_t>(0xCC));
    for (uint8_t s = 0; s <= 1; ++s)
        for (uint8_t d = 0; d <= 1; ++d)
            for (uint8_t p = 0; p <= 1; ++p)
                CHECK_EQ(rop3_eval(0xCC, s, d, p), s);
    // 0x55 <-> 0x00550009 (DSTINVERT, RPN Dn)
    CHECK_EQ(rop3_index_from_code(0x00550009u), static_cast<uint8_t>(0x55));
    for (uint8_t s = 0; s <= 1; ++s)
        for (uint8_t d = 0; d <= 1; ++d)
            for (uint8_t p = 0; p <= 1; ++p)
                CHECK_EQ(rop3_eval(0x55, s, d, p), static_cast<uint8_t>(d ^ 1));
}

RTSC_TEST(rop3_apply_per_channel_matches_rpn) {
    const uint32_t pixels[] = {
        0x12345678u, 0x00FF00FFu, 0xA5A5A5A5u, 0xFFFFFFFFu,
    };
    for (int idx = 0; idx < 256; ++idx) {
        const char* expr = kRop3Rpn[idx];
        for (uint32_t sp : pixels)
            for (uint32_t dp : pixels)
                for (uint32_t pp : pixels) {
                    const uint32_t got =
                        rop3_apply_per_channel(static_cast<uint8_t>(idx), sp, dp, pp);
                    const uint8_t r = RpnByte3(expr, static_cast<uint8_t>(sp >> 16),
                                               static_cast<uint8_t>(dp >> 16),
                                               static_cast<uint8_t>(pp >> 16));
                    const uint8_t g = RpnByte3(expr, static_cast<uint8_t>(sp >> 8),
                                               static_cast<uint8_t>(dp >> 8),
                                               static_cast<uint8_t>(pp >> 8));
                    const uint8_t b = RpnByte3(expr, static_cast<uint8_t>(sp),
                                               static_cast<uint8_t>(dp),
                                               static_cast<uint8_t>(pp));
                    const uint32_t want = (dp & 0xFF000000u) |
                                          (static_cast<uint32_t>(r) << 16) |
                                          (static_cast<uint32_t>(g) << 8) |
                                          static_cast<uint32_t>(b);
                    if (got != want) {
                        std::printf(
                            "  MISMATCH idx=0x%02X src=%08X dst=%08X pat=%08X got=%08X want=%08X\n",
                            idx, sp, dp, pp, got, want);
                    }
                    CHECK_EQ(got, want);
                }
    }
}

RTSC_TEST(rop3_apply_per_channel_alpha_independent_of_rgb) {
    // dst alpha 0xFF with RGB 0; src/pat RGB nonzero. Alpha must stay 0xFF
    // while RGB follows the operation.
    const uint32_t src = 0x00123456u;
    const uint32_t dst = 0xFF000000u;
    const uint32_t pat = 0x00654321u;
    for (int idx = 0; idx < 256; ++idx) {
        const uint32_t got =
            rop3_apply_per_channel(static_cast<uint8_t>(idx), src, dst, pat);
        CHECK_EQ(got >> 24, 0xFFu);
        const uint8_t r = RpnByte3(kRop3Rpn[idx], static_cast<uint8_t>(src >> 16),
                                   static_cast<uint8_t>(dst >> 16),
                                   static_cast<uint8_t>(pat >> 16));
        const uint8_t g = RpnByte3(kRop3Rpn[idx], static_cast<uint8_t>(src >> 8),
                                   static_cast<uint8_t>(dst >> 8),
                                   static_cast<uint8_t>(pat >> 8));
        const uint8_t b = RpnByte3(kRop3Rpn[idx], static_cast<uint8_t>(src),
                                   static_cast<uint8_t>(dst),
                                   static_cast<uint8_t>(pat));
        const uint32_t want = 0xFF000000u | (static_cast<uint32_t>(r) << 16) |
                              (static_cast<uint32_t>(g) << 8) |
                              static_cast<uint32_t>(b);
        CHECK_EQ(got, want);
    }
    // Concrete case where alpha (0xFF) differs from the RGB result (0x00):
    // index 0x00 is BLACKNESS -> RGB 0, alpha still 0xFF.
    CHECK_EQ(rop3_apply_per_channel(0x00, src, dst, pat) & 0xFFFFFFu, 0x000000u);
    CHECK_EQ(rop3_apply_per_channel(0x00, src, dst, pat) >> 24, 0xFFu);
}

RTSC_TEST(rop3_apply_per_channel_boundaries) {
    const uint32_t zeros = 0x00000000u;
    const uint32_t ones = 0xFFFFFFFFu;
    for (int idx = 0; idx < 256; ++idx) {
        const char* expr = kRop3Rpn[idx];
        const uint32_t z = static_cast<uint32_t>(RpnByte3(expr, 0, 0, 0));
        const uint32_t want_z = (z << 16) | (z << 8) | z;
        CHECK_EQ(rop3_apply_per_channel(static_cast<uint8_t>(idx), zeros, zeros, zeros),
                 want_z);

        const uint32_t o = static_cast<uint32_t>(RpnByte3(expr, 0xFF, 0xFF, 0xFF));
        const uint32_t want_o = 0xFF000000u | (o << 16) | (o << 8) | o;
        CHECK_EQ(rop3_apply_per_channel(static_cast<uint8_t>(idx), ones, ones, ones),
                 want_o);
    }
}

int main() { return ::rtsc::test::run_all("rtsc_rop_tests"); }
