// Cryptographic random number source.
//
// Reference: docs/spec/security-layer.md sections 5.3 (nonce) and 5.6
// (ExportedSessionKey: "16-byte random value").
//
// This header is deliberately platform neutral: it must not pull in windows.h
// or any POSIX header, because it is included by code that builds on both
// Windows and Linux. The platform implementations live in
// src/crypto/random_win.cpp (BCryptGenRandom) and src/crypto/random_posix.cpp
// (getrandom with a /dev/urandom fallback).
//
// The contract is fail-closed and exception free (this codebase does not throw):
//   * success -> true, and every requested byte is written;
//   * failure -> false, and the output buffer is left EMPTY (never zero-filled,
//     never partially filled). A zero-filled fallback would silently recreate
//     the predictable-key defect the caller is trying to avoid.
//
// Weak generators (rand, srand, std::random_device, mt19937) are forbidden for
// key material: see docs/spec/security-layer.md section on randomness.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rtsc::crypto {

// Fills `out[0..n)` with cryptographically strong random bytes.
// Returns false and leaves `out` untouched on failure; the caller must treat
// that as a local environment failure, not as a protocol error.
bool RandomBytes(uint8_t* out, size_t n);

// Resizes `out` to `n` and fills it. On failure `out` is cleared, so a caller
// that checks only the return value still cannot end up with a zero key.
bool RandomBytes(std::vector<uint8_t>& out, size_t n);

}  // namespace rtsc::crypto
