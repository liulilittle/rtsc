// Binary Raster Operation (ROP2) engine ([MS-RDPEGDI] 2.2.2.1.1.2).
// Ternary Raster Operation (ROP3) engine ([MS-RDPEGDI] 2.2.2.2.1.1.1.7).
//
// A ROP2 code names a Boolean function of the source pen bit P and the
// destination bit D. The spec defines each code in Reverse Polish Notation
// over the operators AND (a), OR (o), NOT (n) and XOR (x); this module
// evaluates the same functions directly.
//
// Cross-checked against the [MS-RDPEGDI] 2.2.2.1.1.2 table and the Win32
// SetROP2 mix modes (R2_WHITE is the spec name for 0x10; R2_WHITENESS is
// kept as an alias).

#pragma once

#include <cstdint>

// wingdi.h (pulled in by windows.h) defines R2_* mix-mode macros with these
// exact names. Undefine them so the Rop2Code enum below keeps its identifiers;
// without this, any translation unit that includes windows.h before this header
// fails to parse the enum.
#ifdef R2_BLACK
#undef R2_BLACK
#endif
#ifdef R2_NOTMERGEPEN
#undef R2_NOTMERGEPEN
#endif
#ifdef R2_MASKNOTPEN
#undef R2_MASKNOTPEN
#endif
#ifdef R2_NOTCOPYPEN
#undef R2_NOTCOPYPEN
#endif
#ifdef R2_MASKPENNOT
#undef R2_MASKPENNOT
#endif
#ifdef R2_NOT
#undef R2_NOT
#endif
#ifdef R2_XORPEN
#undef R2_XORPEN
#endif
#ifdef R2_NOTMASKPEN
#undef R2_NOTMASKPEN
#endif
#ifdef R2_MASKPEN
#undef R2_MASKPEN
#endif
#ifdef R2_NOTXORPEN
#undef R2_NOTXORPEN
#endif
#ifdef R2_NOP
#undef R2_NOP
#endif
#ifdef R2_MERGENOTPEN
#undef R2_MERGENOTPEN
#endif
#ifdef R2_COPYPEN
#undef R2_COPYPEN
#endif
#ifdef R2_MERGEPENNOT
#undef R2_MERGEPENNOT
#endif
#ifdef R2_MERGEPEN
#undef R2_MERGEPEN
#endif
#ifdef R2_WHITE
#undef R2_WHITE
#endif
#ifdef R2_WHITENESS
#undef R2_WHITENESS
#endif

namespace rtsc::proto {

// ROP2 raster-operation codes ([MS-RDPEGDI] 2.2.2.1.1.2).
enum Rop2Code : uint8_t {
    R2_BLACK       = 0x01,  // 0
    R2_NOTMERGEPEN = 0x02,  // DPon
    R2_MASKNOTPEN  = 0x03,  // DPna
    R2_NOTCOPYPEN  = 0x04,  // Pn
    R2_MASKPENNOT  = 0x05,  // PDna
    R2_NOT         = 0x06,  // Dn
    R2_XORPEN      = 0x07,  // DPx
    R2_NOTMASKPEN  = 0x08,  // DPan
    R2_MASKPEN     = 0x09,  // DPa
    R2_NOTXORPEN   = 0x0A,  // DPxn
    R2_NOP         = 0x0B,  // D
    R2_MERGENOTPEN = 0x0C,  // DPno
    R2_COPYPEN     = 0x0D,  // P
    R2_MERGEPENNOT = 0x0E,  // PDno
    R2_MERGEPEN    = 0x0F,  // PDo
    R2_WHITE       = 0x10,  // 1
    R2_WHITENESS   = 0x10,  // alias of R2_WHITE
};

// Evaluates one ROP2 code on a single source (s) and destination (d) bit.
// Returns 0 or 1. `s` and `d` are treated as booleans (nonzero -> 1).
// Codes outside 0x01..0x10 fall back to R2_NOP (destination unchanged).
uint8_t rop2_eval(uint8_t code, uint8_t s, uint8_t d);

// Applies a ROP2 code to a packed 0xAARRGGBB pixel (R=bits16-23, G=bits8-15,
// B=bits0-7, A=bits24-31). The R, G and B bytes are combined independently,
// bit by bit, with the same code; the alpha byte is passed through unchanged
// from `dst`. Note this is NOT the ui::Surface RGBA8888 memory byte order;
// integration callers must convert.
uint32_t rop2_apply_per_channel(uint8_t code, uint32_t src, uint32_t dst);

// Ternary raster-operation truth table ([MS-RDPEGDI] 2.2.2.2.1.1.1.7).
// kRop3Table[idx] is the 8-bit truth byte for rop3Index `idx`: bit
// ((s<<2)|(d<<1)|p) is the result for source bit s, destination bit d and
// pattern/pen bit p. The table is derived from the spec's RPN expressions.
extern const uint8_t kRop3Table[256];

// Extracts the ROP3 index from a 32-bit ROP3 code: bits[23:16].
uint8_t rop3_index_from_code(uint32_t rop3);

// Evaluates the ternary raster operation selected by `idx` on single source
// (s), destination (d) and pattern (p) bits. Returns 0 or 1.
uint8_t rop3_eval(uint8_t idx, uint8_t s, uint8_t d, uint8_t p);

// Applies the ternary raster operation selected by `idx` to packed 0xAARRGGBB
// source, destination and pattern pixels (R=bits16-23, G=bits8-15, B=bits0-7,
// A=bits24-31). The R, G and B bytes are combined independently, bit by bit;
// the alpha byte is passed through unchanged from `dst`. Note this is NOT the
// ui::Surface RGBA8888 memory byte order; integration callers must convert.
uint32_t rop3_apply_per_channel(uint8_t idx, uint32_t src, uint32_t dst,
                                uint32_t pat);

}  // namespace rtsc::proto
