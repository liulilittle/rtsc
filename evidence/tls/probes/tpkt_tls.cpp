// Red-evidence probe: what happens if the existing TpktStream is (wrongly) fed
// raw TLS ciphertext instead of decrypted plaintext.
#include <cstdio>
#include <vector>

#include "rtsc/proto/framing.h"
#include "rtsc/proto/tpkt.h"

using namespace rtsc::proto;

int main() {
    // A real TLS 1.2 application_data record captured from the loopback probe
    // (TLS1.2, AES256-GCM, 16-byte payload): 45 bytes, starts 17 03 03 00 28.
    // The plaintext inside is a valid TPKT frame: 03 00 00 10 02 f0 80 + 9 bytes.
    const uint8_t record[] = {0x17, 0x03, 0x03, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x01, 0x21, 0xa7, 0x35, 0xff, 0xe6, 0x2f, 0x8a,
                              0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
                              0xbb, 0xcc, 0xdd, 0xee, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
                              0x69, 0x78, 0x87, 0x96, 0xa5};

    TpktStream s;
    s.Append(record, sizeof(record));

    std::vector<uint8_t> payload;
    for (int i = 0; i < 5; i++) {
        const Status st = s.Next(payload);
        printf("Next #%d -> status=%d payload=%zu buffered=%zu dropped=%zu\n", i, (int)st,
               payload.size(), s.buffered(), s.dropped_bytes());
        if (st == Status::NeedMoreData) break;
    }

    // Now feed the *decrypted* plaintext of the same record and show it works.
    const uint8_t plain[] = {0x03, 0x00, 0x00, 0x10, 0x02, 0xf0, 0x80,
                             'A',  'B',  'C',  'D',  'E',  'F',  'G',  'H',  'I'};
    TpktStream p;
    p.Append(plain, sizeof(plain));
    const Status st = p.Next(payload);
    printf("plaintext Next -> status=%d payload=%zu dropped=%zu\n", (int)st, payload.size(),
           p.dropped_bytes());

    // Demonstrate the silent-resync hazard: prefix 3 junk bytes then a real frame.
    const uint8_t junk[] = {0x03, 0x99, 0x00, 0x03, 0x00, 0x00, 0x06, 0xAA, 0xBB};
    TpktStream j;
    j.Append(junk, sizeof(junk));
    for (int i = 0; i < 4; i++) {
        const Status js = j.Next(payload);
        printf("junk Next #%d -> status=%d payload=%zu dropped=%zu\n", i, (int)js, payload.size(),
               j.dropped_bytes());
        if (js != Status::Ok) break;
    }
    return 0;
}
