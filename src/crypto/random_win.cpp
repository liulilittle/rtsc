// Windows CSPRNG: BCryptGenRandom with the system preferred RNG.
//
// This translation unit is compiled only on Windows (see CMakeLists.txt, which
// adds it under if(WIN32) and links bcrypt there). Keeping it separate from the
// POSIX implementation means neither file has to carry the other platform's
// headers, which is what the Linux build gate (scripts/linux-build-gate.sh,
// WINDOWS_H_COUNT == 0) checks.
//
// Never use #pragma comment(lib, ...) here: the library dependency belongs in
// CMake so the platform switch stays in one place.

#include <windows.h>

#include <bcrypt.h>

#include <utility>
#include <vector>

#include "rtsc/crypto/random.h"

namespace rtsc::crypto {

namespace {

bool FillBuffer(uint8_t* out, size_t n) {
    // BCryptGenRandom takes a ULONG length. Chunk large requests rather than
    // truncating the cast, so the caller always gets exactly n bytes.
    size_t done = 0;
    while (done < n) {
        const size_t remaining = n - done;
        const ULONG chunk = remaining > 0x10000000u ? 0x10000000u
                                                    : static_cast<ULONG>(remaining);
        const NTSTATUS status = ::BCryptGenRandom(
            nullptr, out + done, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) return false;
        done += chunk;
    }
    return true;
}

}  // namespace

bool RandomBytes(uint8_t* out, size_t n) {
    if (n == 0) return true;
    if (out == nullptr) return false;
    // Fill a scratch buffer first: on failure the caller's buffer is untouched,
    // so a partial write can never masquerade as usable key material.
    std::vector<uint8_t> scratch(n, 0);
    if (!FillBuffer(scratch.data(), n)) return false;
    for (size_t i = 0; i < n; ++i) out[i] = scratch[i];
    return true;
}

bool RandomBytes(std::vector<uint8_t>& out, size_t n) {
    if (n == 0) {
        out.clear();
        return true;
    }
    std::vector<uint8_t> scratch(n, 0);
    if (!FillBuffer(scratch.data(), n)) {
        out.clear();
        return false;
    }
    out = std::move(scratch);
    return true;
}

}  // namespace rtsc::crypto
