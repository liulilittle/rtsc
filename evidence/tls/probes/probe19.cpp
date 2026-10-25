#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")

static const char* St(NTSTATUS s) {
    static char b[8][20];
    static int i = 0;
    i = (i + 1) % 8;
    sprintf_s(b[i], "0x%08lX", (unsigned long)s);
    return b[i];
}

int main() {
    const wchar_t* algs[] = {BCRYPT_MD4_ALGORITHM, BCRYPT_MD5_ALGORITHM, BCRYPT_SHA1_ALGORITHM,
                             BCRYPT_SHA256_ALGORITHM, BCRYPT_RC4_ALGORITHM, BCRYPT_AES_ALGORITHM,
                             BCRYPT_3DES_ALGORITHM, L"HMAC-MD5",
                             BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_RSA_ALGORITHM};
    for (auto a : algs) {
        BCRYPT_ALG_HANDLE h = nullptr;
        NTSTATUS s = BCryptOpenAlgorithmProvider(&h, a, nullptr, 0);
        printf("  %-32ls -> %s\n", a, St(s));
        if (s == 0) {
            DWORD flags = 0, cb = 0;
            if (BCryptGetProperty(h, BCRYPT_ALGORITHM_NAME, (PUCHAR)&flags, 0, &cb, 0) == 0) {}
            BCryptCloseAlgorithmProvider(h, 0);
        }
    }
    printf("--- HMAC-MD5 with MD5 provider ---\n");
    BCRYPT_ALG_HANDLE h = nullptr;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&h, BCRYPT_MD5_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    printf("  open(MD5, HMAC) -> %s\n", St(s));
    if (s == 0) BCryptCloseAlgorithmProvider(h, 0);
    printf("--- RNG ---\n");
    BYTE buf[16] = {};
    printf("  BCryptGenRandom -> %s\n", St(BCryptGenRandom(nullptr, buf, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG)));
    return 0;
}
