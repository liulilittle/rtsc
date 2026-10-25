// Binary Raster Operation (ROP2) engine ([MS-RDPEGDI] 2.2.2.1.1.2).
// Ternary Raster Operation (ROP3) engine ([MS-RDPEGDI] 2.2.2.2.1.1.1.7).

#include "rtsc/proto/rop.h"

namespace rtsc::proto {

namespace {

// Applies a single-bit ROP2 code to one byte, bit by bit.
uint8_t ApplyByte(uint8_t code, uint8_t s, uint8_t d) {
    uint8_t out = 0;
    for (int bit = 0; bit < 8; ++bit) {
        const uint8_t sb = static_cast<uint8_t>((s >> bit) & 1u);
        const uint8_t db = static_cast<uint8_t>((d >> bit) & 1u);
        out = static_cast<uint8_t>(out | (rop2_eval(code, sb, db) << bit));
    }
    return out;
}

// Applies a single-bit ROP3 operation to one byte, bit by bit.
uint8_t ApplyByte3(uint8_t idx, uint8_t s, uint8_t d, uint8_t p) {
    uint8_t out = 0;
    for (int bit = 0; bit < 8; ++bit) {
        const uint8_t sb = static_cast<uint8_t>((s >> bit) & 1u);
        const uint8_t db = static_cast<uint8_t>((d >> bit) & 1u);
        const uint8_t pb = static_cast<uint8_t>((p >> bit) & 1u);
        out = static_cast<uint8_t>(out | (rop3_eval(idx, sb, db, pb) << bit));
    }
    return out;
}

}  // namespace

uint8_t rop2_eval(uint8_t code, uint8_t s, uint8_t d) {
    const uint8_t p = static_cast<uint8_t>(s != 0 ? 1 : 0);  // pen / source
    const uint8_t q = static_cast<uint8_t>(d != 0 ? 1 : 0);  // destination
    switch (code) {
        case R2_BLACK:       return static_cast<uint8_t>(0);            // 0
        case R2_NOTMERGEPEN: return static_cast<uint8_t>((p | q) ^ 1);  // DPon
        case R2_MASKNOTPEN:  return static_cast<uint8_t>(q & (p ^ 1));  // DPna
        case R2_NOTCOPYPEN:  return static_cast<uint8_t>(p ^ 1);        // Pn
        case R2_MASKPENNOT:  return static_cast<uint8_t>(p & (q ^ 1));  // PDna
        case R2_NOT:         return static_cast<uint8_t>(q ^ 1);        // Dn
        case R2_XORPEN:      return static_cast<uint8_t>(p ^ q);        // DPx
        case R2_NOTMASKPEN:  return static_cast<uint8_t>((p & q) ^ 1);  // DPan
        case R2_MASKPEN:     return static_cast<uint8_t>(p & q);        // DPa
        case R2_NOTXORPEN:   return static_cast<uint8_t>((p ^ q) ^ 1);  // DPxn
        case R2_NOP:         return q;                                  // D
        case R2_MERGENOTPEN: return static_cast<uint8_t>(q | (p ^ 1));  // DPno
        case R2_COPYPEN:     return p;                                  // P
        case R2_MERGEPENNOT: return static_cast<uint8_t>(p | (q ^ 1));  // PDno
        case R2_MERGEPEN:    return static_cast<uint8_t>(p | q);        // PDo
        case R2_WHITE:       return static_cast<uint8_t>(1);            // 1
        default:             return q;  // unknown -> identity (R2_NOP)
    }
}

uint32_t rop2_apply_per_channel(uint8_t code, uint32_t src, uint32_t dst) {
    uint32_t out = dst & 0xFF000000u;  // alpha passthrough from destination
    out |= static_cast<uint32_t>(ApplyByte(code, static_cast<uint8_t>(src >> 16),
                                           static_cast<uint8_t>(dst >> 16))) << 16;
    out |= static_cast<uint32_t>(ApplyByte(code, static_cast<uint8_t>(src >> 8),
                                           static_cast<uint8_t>(dst >> 8))) << 8;
    out |= static_cast<uint32_t>(ApplyByte(code, static_cast<uint8_t>(src),
                                           static_cast<uint8_t>(dst)));
    return out;
}

// Ternary raster-operation truth table ([MS-RDPEGDI] 2.2.2.2.1.1.1.7).
// Derived from the spec's 256 RPN expressions; bit ((s<<2)|(d<<1)|p) is the
// result for source s, destination d and pattern p.
extern const uint8_t kRop3Table[256] = {
    0x00, 0x01, 0x04, 0x05, 0x10, 0x11, 0x14, 0x15,  // 0x00
    0x40, 0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55,  // 0x08
    0x02, 0x03, 0x06, 0x07, 0x12, 0x13, 0x16, 0x17,  // 0x10
    0x42, 0x43, 0x46, 0x47, 0x52, 0x53, 0x56, 0x57,  // 0x18
    0x08, 0x09, 0x0C, 0x0D, 0x18, 0x19, 0x1C, 0x1D,  // 0x20
    0x48, 0x49, 0x4C, 0x4D, 0x58, 0x59, 0x5C, 0x5D,  // 0x28
    0x0A, 0x0B, 0x0E, 0x0F, 0x1A, 0x1B, 0x1E, 0x1F,  // 0x30
    0x4A, 0x4B, 0x4E, 0x4F, 0x5A, 0x5B, 0x5E, 0x5F,  // 0x38
    0x20, 0x21, 0x24, 0x25, 0x30, 0x31, 0x34, 0x35,  // 0x40
    0x60, 0x61, 0x64, 0x65, 0x70, 0x71, 0x74, 0x75,  // 0x48
    0x22, 0x23, 0x26, 0x27, 0x32, 0x33, 0x36, 0x37,  // 0x50
    0x62, 0x63, 0x66, 0x67, 0x72, 0x73, 0x76, 0x77,  // 0x58
    0x28, 0x29, 0x2C, 0x2D, 0x38, 0x39, 0x3C, 0x3D,  // 0x60
    0x68, 0x69, 0x6C, 0x6D, 0x78, 0x79, 0x7C, 0x7D,  // 0x68
    0x2A, 0x2B, 0x2E, 0x2F, 0x3A, 0x3B, 0x3E, 0x3F,  // 0x70
    0x6A, 0x6B, 0x6E, 0x6F, 0x7A, 0x7B, 0x7E, 0x7F,  // 0x78
    0x80, 0x81, 0x84, 0x85, 0x90, 0x91, 0x94, 0x95,  // 0x80
    0xC0, 0xC1, 0xC4, 0xC5, 0xD0, 0xD1, 0xD4, 0xD5,  // 0x88
    0x82, 0x83, 0x86, 0x87, 0x92, 0x93, 0x96, 0x97,  // 0x90
    0xC2, 0xC3, 0xC6, 0xC7, 0xD2, 0xD3, 0xD6, 0xD7,  // 0x98
    0x88, 0x89, 0x8C, 0x8D, 0x98, 0x99, 0x9C, 0x9D,  // 0xa0
    0xC8, 0xC9, 0xCC, 0xCD, 0xD8, 0xD9, 0xDC, 0xDD,  // 0xa8
    0x8A, 0x8B, 0x8E, 0x8F, 0x9A, 0x9B, 0x9E, 0x9F,  // 0xb0
    0xCA, 0xCB, 0xCE, 0xCF, 0xDA, 0xDB, 0xDE, 0xDF,  // 0xb8
    0xA0, 0xA1, 0xA4, 0xA5, 0xB0, 0xB1, 0xB4, 0xB5,  // 0xc0
    0xE0, 0xE1, 0xE4, 0xE5, 0xF0, 0xF1, 0xF4, 0xF5,  // 0xc8
    0xA2, 0xA3, 0xA6, 0xA7, 0xB2, 0xB3, 0xB6, 0xB7,  // 0xd0
    0xE2, 0xE3, 0xE6, 0xE7, 0xF2, 0xF3, 0xF6, 0xF7,  // 0xd8
    0xA8, 0xA9, 0xAC, 0xAD, 0xB8, 0xB9, 0xBC, 0xBD,  // 0xe0
    0xE8, 0xE9, 0xEC, 0xED, 0xF8, 0xF9, 0xFC, 0xFD,  // 0xe8
    0xAA, 0xAB, 0xAE, 0xAF, 0xBA, 0xBB, 0xBE, 0xBF,  // 0xf0
    0xEA, 0xEB, 0xEE, 0xEF, 0xFA, 0xFB, 0xFE, 0xFF,  // 0xf8
};

uint8_t rop3_index_from_code(uint32_t rop3) {
    return static_cast<uint8_t>((rop3 >> 16) & 0xFFu);
}

uint8_t rop3_eval(uint8_t idx, uint8_t s, uint8_t d, uint8_t p) {
    return static_cast<uint8_t>(
        (kRop3Table[idx] >> ((s << 2) | (d << 1) | p)) & 1u);
}

uint32_t rop3_apply_per_channel(uint8_t idx, uint32_t src, uint32_t dst,
                                uint32_t pat) {
    uint32_t out = dst & 0xFF000000u;  // alpha passthrough from destination
    out |= static_cast<uint32_t>(ApplyByte3(idx, static_cast<uint8_t>(src >> 16),
                                            static_cast<uint8_t>(dst >> 16),
                                            static_cast<uint8_t>(pat >> 16))) << 16;
    out |= static_cast<uint32_t>(ApplyByte3(idx, static_cast<uint8_t>(src >> 8),
                                            static_cast<uint8_t>(dst >> 8),
                                            static_cast<uint8_t>(pat >> 8))) << 8;
    out |= static_cast<uint32_t>(ApplyByte3(idx, static_cast<uint8_t>(src),
                                            static_cast<uint8_t>(dst),
                                            static_cast<uint8_t>(pat)));
    return out;
}

}  // namespace rtsc::proto
