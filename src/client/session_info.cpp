// Connection information: field collection (see session_info.h).

#include "rtsc/client/session_info.h"

#include <cstdio>
#include <cstring>

#include "rtsc/crypto/random.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
// RtlGetVersion is exported by ntdll.dll but is not declared by the Windows SDK
// headers. GetVersionExW would work but is deprecated and trips C4996 under
// /W4 /WX, which is fatal because the project builds with /WX. RtlGetVersion is
// not deprecated and reports the real version even without a manifest.
extern "C" LONG NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW version_info);
#else
#include <sys/utsname.h>
#endif

namespace rtsc::client {

namespace {

const char* kArch =
#if defined(_WIN64) || defined(__x86_64__) || defined(__aarch64__)
    "x64";
#else
    "x86";
#endif

std::string FormatDouble(const char* suffix, double value) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.0f %s", value, suffix);
    return std::string(buf);
}

}  // namespace

std::string FormatUtcTimestamp(std::time_t now) {
    std::tm g{};
#if defined(_WIN32)
    if (gmtime_s(&g, &now) != 0) return "N/A";
#else
    if (gmtime_r(&now, &g) == nullptr) return "N/A";
#endif
    char buf[48];
    const size_t n = std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &g);
    return n == 0 ? std::string("N/A") : std::string(buf);
}

std::string LocalOsString() {
#if defined(_WIN32)
    RTL_OSVERSIONINFOW ovi{};
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    if (RtlGetVersion(&ovi) == 0) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "Windows %lu.%lu.%lu (%s)",
                      ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber,
                      kArch);
        return std::string(buf);
    }
    return "Windows (unknown)";
#else
    struct utsname u {};
    if (uname(&u) == 0) {
        std::string s = u.sysname;
        s += " ";
        s += u.release;
        s += " (";
        s += u.machine;
        s += ")";
        return s;
    }
    return "unknown";
#endif
}

std::string GenerateActivityId() {
    uint8_t b[16];
    if (!crypto::RandomBytes(b, sizeof(b))) {
        // Fail closed to a fixed, clearly non-random id rather than an empty
        // one: the dialog must always show something in the field.
        return "00000000-0000-4000-8000-000000000000";
    }
    b[6] = static_cast<uint8_t>((b[6] & 0x0F) | 0x40);  // version 4
    b[8] = static_cast<uint8_t>((b[8] & 0x3F) | 0x80);  // variant 1
    char buf[40];
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                  "%02x%02x%02x%02x%02x%02x",
                  b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9],
                  b[10], b[11], b[12], b[13], b[14], b[15]);
    return std::string(buf);
}

SessionInfo CollectSessionInfo(const SessionInfoInput& in, std::time_t now) {
    SessionInfo si;

    si.timestamp_utc = FormatUtcTimestamp(now);
    si.activity_id = GenerateActivityId();

    // [Client details]
    si.client_architecture = kArch;
    si.client_version =
        std::string(RTSC_VERSION_STRING) + " " + kArch;  // e.g. "0.1.0 x64"
    si.local_os = in.local_os.empty() ? LocalOsString() : in.local_os;

    // [Network details]. The transport is TCP: this client does not implement
    // the RDP UDP transport, so the field states that honestly.
    si.transport_protocol = "TCP";
    si.round_trip_time =
        in.has_rtt ? FormatDouble("ms", in.rtt_ms) : std::string("N/A");
    si.available_bandwidth =
        in.bandwidth_mbps > 0.0 ? FormatDouble("Mbps", in.bandwidth_mbps)
                                : std::string("N/A");
    si.frame_rate = in.frames_per_second > 0.0
                        ? FormatDouble("FPS", in.frames_per_second)
                        : std::string("N/A");

    // Quality banner: derived from the measured round-trip time, and naming the
    // transport actually in use (TCP here).
    std::string level;
    if (!in.has_rtt) {
        level = "未知";
    } else if (in.rtt_ms < 50.0) {
        level = "很好";
    } else if (in.rtt_ms < 150.0) {
        level = "良好";
    } else {
        level = "一般";
    }
    si.quality = "你的连接质量" + level + "，且已启用 " + si.transport_protocol + "。";

    // [Remote computer details]. The gateway fields report the real tunnel
    // when one is in use (--gateway / RTSC_GATEWAY); empty input keeps the
    // "no gateway in use" text a direct connection shows.
    si.remote_session_type = "远程桌面 (RDP)";
    si.gateway_name =
        in.gateway_name.empty() ? "没有在使用中" : in.gateway_name;
    si.gateway_logon_method =
        in.gateway_logon_method.empty() ? "没有在使用中"
                                        : in.gateway_logon_method;
    si.remote_computer = in.host;

    return si;
}

}  // namespace rtsc::client
