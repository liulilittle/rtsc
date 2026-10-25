// Offline NTLMv2/MIC cross-check against the local Microsoft NTLMSSP.
//
// The client messages (NEGOTIATE, NTLMv2 response, MIC, AUTHENTICATE) are
// produced by rtsc's own src/credssp/ntlm.cpp. They are handed to Microsoft's
// NTLM security package as the SERVER (AcceptSecurityContext), which verifies
// them exactly like msv1_0 does on a real RDP server. Nothing touches the
// network: the account is a local SAM account.
//
// Exit code 0 when the package accepts the AUTHENTICATE, non-zero otherwise.
// Usage: sspi_verify_ours.exe <user> <password> [domain]
//   domain defaults to the local computer name (correct for a local account).
//
// Requires: Windows, secur32.lib, and the rtsc_credssp / rtsc_crypto libs.

#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "rtsc/credssp/ntlm.h"

using namespace rtsc::credssp;

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <user> <password> [domain]\n", argv[0]);
        return 2;
    }
    const char* user = argv[1];
    const char* password = argv[2];
    char computer[256] = {0};
    DWORD cn = sizeof(computer);
    GetComputerNameA(computer, &cn);
    std::string domain = argc > 3 ? argv[3] : computer;

    CredHandle cred;
    TimeStamp ts;
    SECURITY_STATUS ss = AcquireCredentialsHandleA(
        nullptr, (SEC_CHAR*)"NTLM", SECPKG_CRED_INBOUND, nullptr, nullptr, nullptr,
        nullptr, &cred, &ts);
    if (ss != SEC_E_OK) {
        std::fprintf(stderr, "AcquireCredentialsHandle = 0x%08lx\n",
                     (unsigned long)ss);
        return 3;
    }

    // Client NEGOTIATE, produced by rtsc.
    NegotiateMessage neg;
    neg.flags = ntlm_flag::kCredsspClient;
    Bytes negotiate;
    neg.Encode(negotiate);

    std::vector<unsigned char> chbuf(0x10000, 0);
    SecBuffer inb; inb.BufferType = SECBUFFER_TOKEN; inb.pvBuffer = negotiate.data();
    inb.cbBuffer = (unsigned long)negotiate.size();
    SecBuffer outb; outb.BufferType = SECBUFFER_TOKEN; outb.pvBuffer = chbuf.data();
    outb.cbBuffer = (unsigned long)chbuf.size();
    SecBufferDesc ind = {SECBUFFER_VERSION, 1, &inb};
    SecBufferDesc outd = {SECBUFFER_VERSION, 1, &outb};
    CtxtHandle ctx;
    ULONG attrs = 0;
    ss = AcceptSecurityContext(&cred, nullptr, &ind, ASC_REQ_ALLOCATE_MEMORY, 0, &ctx,
                               &outd, &attrs, &ts);
    if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
        std::fprintf(stderr, "ASC#1(NEGOTIATE) = 0x%08lx\n", (unsigned long)ss);
        return 3;
    }
    Bytes challenge((unsigned char*)outb.pvBuffer,
                    (unsigned char*)outb.pvBuffer + outb.cbBuffer);

    ChallengeMessage ch;
    Error e = ch.Decode(challenge.data(), challenge.size());
    if (!e.ok()) {
        std::fprintf(stderr, "cannot decode CHALLENGE\n");
        return 3;
    }
    Bytes tsval;
    const bool have_ts = ch.FindAvPair(AvId::kTimestamp, tsval).ok();

    // Rebuild target_info the same way credssp.cpp does.
    Bytes target_info;
    for (const auto& p : ch.av_pairs) {
        uint8_t hdr[4] = {(uint8_t)((uint16_t)p.id & 0xFF), (uint8_t)((uint16_t)p.id >> 8),
                          (uint8_t)(p.value.size() & 0xFF), (uint8_t)(p.value.size() >> 8)};
        target_info.insert(target_info.end(), hdr, hdr + 4);
        target_info.insert(target_info.end(), p.value.begin(), p.value.end());
    }
    if (have_ts) {
        uint8_t hdr[4] = {0x06, 0x00, 0x04, 0x00};
        uint8_t fl[4] = {0x02, 0x00, 0x00, 0x00};
        target_info.insert(target_info.end(), hdr, hdr + 4);
        target_info.insert(target_info.end(), fl, fl + 4);
    }
    { uint8_t hdr[4] = {0x0A, 0x00, 0x10, 0x00};
      target_info.insert(target_info.end(), hdr, hdr + 4);
      target_info.insert(target_info.end(), 16, 0); }
    target_info.insert(target_info.end(), 4, 0);

    NtlmV2Inputs in;
    in.user = user; in.domain = domain; in.password = password;
    in.server_challenge.assign(ch.server_challenge.begin(), ch.server_challenge.end());
    in.client_challenge = {1, 2, 3, 4, 5, 6, 7, 8};
    in.timestamp = have_ts ? tsval : Bytes(8, 0);
    in.target_info = target_info;
    in.suppress_lm_response = have_ts;
    NtlmV2Output v2;
    e = ComputeNtlmV2(in, v2);
    if (!e.ok()) {
        std::fprintf(stderr, "ComputeNtlmV2 failed\n");
        return 3;
    }

    Bytes exported(16);
    for (int i = 0; i < 16; ++i) exported[i] = (uint8_t)(0xA0 + i);
    AuthenticateMessage auth;
    auth.flags = ch.flags & ntlm_flag::kCredsspClient;
    auth.domain = domain; auth.user = user; auth.workstation = "";
    auth.lm_response = v2.lm_response; auth.nt_response = v2.nt_response;
    if ((ch.flags & ntlm_flag::kKeyExch) != 0)
        auth.encrypted_random_session_key = Rc4Crypt(v2.session_base_key, exported);
    Bytes auth_bytes;
    auth.Encode(auth_bytes);
    if (have_ts) {
        auto mic = ComputeMic(exported, negotiate, challenge, auth_bytes);
        memcpy(auth_bytes.data() + 72, mic.data(), 16);
    }

    std::vector<unsigned char> out2buf(0x10000, 0);
    SecBuffer inb2; inb2.BufferType = SECBUFFER_TOKEN; inb2.pvBuffer = auth_bytes.data();
    inb2.cbBuffer = (unsigned long)auth_bytes.size();
    SecBuffer outb2; outb2.BufferType = SECBUFFER_TOKEN; outb2.pvBuffer = out2buf.data();
    outb2.cbBuffer = (unsigned long)out2buf.size();
    SecBufferDesc ind2 = {SECBUFFER_VERSION, 1, &inb2};
    SecBufferDesc outd2 = {SECBUFFER_VERSION, 1, &outb2};
    ss = AcceptSecurityContext(&cred, &ctx, &ind2, ASC_REQ_ALLOCATE_MEMORY, 0, &ctx,
                               &outd2, &attrs, &ts);
    FreeCredentialsHandle(&cred);
    DeleteSecurityContext(&ctx);

    std::printf("ASC#2(OUR AUTHENTICATE) = 0x%08lx  %s\n", (unsigned long)ss,
                ss == SEC_E_OK ? "ACCEPTED" : "REJECTED");
    return ss == SEC_E_OK ? 0 : 1;
}
