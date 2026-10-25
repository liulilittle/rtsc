// POSIX CSPRNG: getrandom(2), with a /dev/urandom fallback for old kernels.
//
// Compiled only on non-Windows platforms (see CMakeLists.txt). It must never
// include a Windows header: scripts/linux-build-gate.sh counts windows.h
// occurrences in the build log and fails the gate on any hit.
//
// Defensive only: g++ predefines _GNU_SOURCE on Linux, which already enables
// _DEFAULT_SOURCE. Kept so a non-libstdc++ toolchain still sees getrandom().
// It is NOT required for this project's Linux gate (measured, see
// evidence/exec/batch1-a-csprng-portability-probe.txt).
#if defined(__linux__)
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#endif

#if defined(__has_include)
#if __has_include(<sys/random.h>)
#define RTSC_HAVE_SYS_RANDOM_H 1
#endif
#endif

#include <cerrno>
#include <cstddef>
#include <utility>
#include <vector>

// Unconditional on purpose. The /dev/urandom fallback calls open/read/close
// even when getrandom() is available, so putting these inside a conditional
// block leaves O_RDONLY and friends undeclared on the ENOSYS path.
#include <fcntl.h>
#include <unistd.h>

#ifdef RTSC_HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#include "rtsc/crypto/random.h"

namespace rtsc::crypto {

namespace {

#ifdef RTSC_HAVE_SYS_RANDOM_H
// getrandom() may return fewer bytes than requested and may fail with EINTR;
// treating either as fatal would turn an unrelated signal into an intermittent
// handshake failure reported as Status::kInternal.
bool FillWithGetrandom(uint8_t* out, size_t n, bool* unsupported) {
    size_t done = 0;
    while (done < n) {
        const ssize_t got = ::getrandom(out + done, n - done, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) *unsupported = true;
            return false;
        }
        if (got == 0) return false;  // no progress: fail rather than spin
        done += static_cast<size_t>(got);
    }
    return true;
}
#endif

bool FillFromDevUrandom(uint8_t* out, size_t n) {
    int fd;
    do {
        fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return false;

    size_t done = 0;
    while (done < n) {
        const ssize_t got = ::read(fd, out + done, n - done);
        if (got < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        if (got == 0) {
            ::close(fd);
            return false;
        }
        done += static_cast<size_t>(got);
    }
    ::close(fd);
    return true;
}

bool FillBuffer(uint8_t* out, size_t n) {
#ifdef RTSC_HAVE_SYS_RANDOM_H
    bool unsupported = false;
    if (FillWithGetrandom(out, n, &unsupported)) return true;
    if (!unsupported) return false;  // a real error, not a missing syscall
#endif
    return FillFromDevUrandom(out, n);
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
