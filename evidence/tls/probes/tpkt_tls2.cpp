// Red evidence #2: a TLS record whose *ciphertext* happens to contain a
// plausible TPKT header is silently accepted as a PDU by TpktStream.
#include <cstdio>
#include <vector>

#include "rtsc/proto/framing.h"

using namespace rtsc::proto;

int main() {
    // Simulated TLS 1.2 app-data record. Bytes 0..4 = record header.
    // Ciphertext bytes at offset 9..12 spell 03 00 00 08 -> a "valid" TPKT of
    // length 8 with a 4-byte payload. TpktStream cannot tell this is noise.
    const uint8_t record[] = {0x17, 0x03, 0x03, 0x00, 0x28,  // record header
                              0x00, 0x00, 0x00, 0x00,        // explicit nonce
                              0x03, 0x00, 0x00, 0x08,        // <- fake TPKT header
                              0xde, 0xad, 0xbe, 0xef,        // fake "X.224" payload
                              0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                              0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f, 0x1e,
                              0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96};

    TpktStream s;
    s.Append(record, sizeof(record));
    std::vector<uint8_t> payload;
    for (int i = 0; i < 6; i++) {
        const Status st = s.Next(payload);
        printf("Next #%d -> status=%d payload=%zu dropped=%zu\n", i, (int)st, payload.size(),
               s.dropped_bytes());
        if (st == Status::Ok) {
            printf("   ACCEPTED as a PDU:");
            for (uint8_t b : payload) printf(" %02x", b);
            printf("\n");
        }
        if (st == Status::NeedMoreData) break;
    }
    return 0;
}
