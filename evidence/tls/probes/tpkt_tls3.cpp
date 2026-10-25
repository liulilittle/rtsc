// Red evidence #2: feeding raw TLS ciphertext into the existing TpktStream.
// Shows (a) silent resync to a bogus 10240-byte frame, (b) eventual acceptance
// of a "PDU" that is pure ciphertext.
#include <cstdio>
#include <vector>

#include "rtsc/proto/framing.h"

using namespace rtsc::proto;

static std::vector<uint8_t> FakeRecord(uint8_t seed) {
    // 45-byte TLS 1.2 app-data record shape: 5-byte header + 8-byte nonce + ct + tag.
    std::vector<uint8_t> r = {0x17, 0x03, 0x03, 0x00, 0x28};
    for (int i = 0; i < 40; i++) r.push_back((uint8_t)(seed * 31 + i * 7));
    return r;
}

int main() {
    printf("== A. one record into TpktStream ==\n");
    {
        TpktStream s;
        auto r = FakeRecord(1);
        s.Append(r.data(), r.size());
        std::vector<uint8_t> payload;
        const Status st = s.Next(payload);
        printf("Next -> status=%d payload=%zu buffered=%zu dropped=%zu\n", (int)st, payload.size(),
               s.buffered(), s.dropped_bytes());
        printf("   (status 1 = NeedMoreData: the framer believes a %u-byte TPKT frame starts at "
               "offset 2, so it will wait forever)\n",
               (unsigned)((r[2] << 8) | r[3]));
    }

    printf("== B. many records into TpktStream ==\n");
    {
        TpktStream s;
        std::vector<uint8_t> all;
        for (int i = 0; i < 12; i++) {
            auto r = FakeRecord((uint8_t)i);
            all.insert(all.end(), r.begin(), r.end());
            s.Append(r.data(), r.size());
        }
        printf("fed %zu bytes of ciphertext\n", all.size());
        std::vector<uint8_t> payload;
        for (int i = 0; i < 8; i++) {
            const Status st = s.Next(payload);
            printf("  Next #%d -> status=%d payload=%zu dropped=%zu\n", i, (int)st, payload.size(),
                   s.dropped_bytes());
            if (st == Status::Ok) {
                printf("     ACCEPTED as a PDU:");
                for (uint8_t b : payload) printf(" %02x", b);
                printf("\n");
            }
            if (st == Status::NeedMoreData) break;
        }
    }

    printf("== C. control: same bytes are valid after TLS decryption ==\n");
    {
        const uint8_t plain[] = {0x03, 0x00, 0x00, 0x10, 0x02, 0xf0, 0x80,
                                 'A',  'B',  'C',  'D',  'E',  'F',  'G',  'H',  'I'};
        TpktStream p;
        p.Append(plain, sizeof(plain));
        std::vector<uint8_t> payload;
        const Status st = p.Next(payload);
        printf("Next -> status=%d payload=%zu dropped=%zu\n", (int)st, payload.size(),
               p.dropped_bytes());
    }
    return 0;
}
