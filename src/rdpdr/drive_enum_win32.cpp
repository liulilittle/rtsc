// Drive enumeration for RDPDR drive redirection (route B).
//
// EnumerateLocalDrives() is Windows-only (GetLogicalDrives + GetDriveTypeW);
// the pure selection policy SelectDrives() is platform neutral so it compiles
// everywhere, which keeps the unit tests runnable on the Linux build gate.

#include "rtsc/rdpdr/drive_enum.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace rtsc::rdpdr {

namespace {

char Upper(char c) { return static_cast<char>(std::toupper(static_cast<unsigned char>(c))); }

std::string Trim(const std::string& s) {
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string TrimUpper(std::string s) {
    s = Trim(s);
    for (char& c : s) c = Upper(c);
    return s;
}

DriveInfo MakeDrive(char letter) {
    DriveInfo drive;
    drive.dos_name = std::string(1, letter) + ":";
    drive.local_root = std::string(1, letter) + ":\\";
    return drive;
}

}  // namespace

std::vector<DriveInfo> SelectDrives(
    const std::vector<std::pair<char, int>>& candidates, const char* spec) {
    if (spec == nullptr || spec[0] == '\0') {
        // Opt-in only (user decision 2026-10-28): no RTSC_REDIRECT_DRIVES
        // means no redirection at all. Mirroring mstsc, where the user ticks
        // the drives to share, keeps the default from handing a remote peer
        // read/write access to the whole system disk.
        return {};
    }

    const std::string whole = TrimUpper(spec);
    if (whole == "ALL") {
        std::vector<DriveInfo> out;
        for (const auto& candidate : candidates) {
            out.push_back(MakeDrive(Upper(candidate.first)));
        }
        std::sort(out.begin(), out.end(),
                  [](const DriveInfo& a, const DriveInfo& b) {
                      return a.dos_name < b.dos_name;
                  });
        return out;
    }

    std::set<char> wanted;
    size_t start = 0;
    while (true) {
        const size_t comma = whole.find(',', start);
        const std::string token =
            Trim(whole.substr(start, comma == std::string::npos
                                          ? std::string::npos
                                          : comma - start));
        if (token.size() != 1 || token[0] < 'A' || token[0] > 'Z') {
            return {};  // invalid token: select nothing, never widen
        }
        wanted.insert(token[0]);
        if (comma == std::string::npos) break;
        start = comma + 1;
    }

    std::vector<DriveInfo> out;
    for (const char letter : wanted) {
        for (const auto& candidate : candidates) {
            if (Upper(candidate.first) == letter) {
                out.push_back(MakeDrive(letter));
                break;
            }
        }
    }
    return out;
}

std::vector<DriveInfo> EnumerateLocalDrives(const char* spec) {
#if defined(_WIN32)
    const DWORD mask = ::GetLogicalDrives();
    std::vector<std::pair<char, int>> candidates;
    for (int i = 0; i < 26; ++i) {
        if ((mask & (1u << i)) == 0) continue;
        wchar_t root[4] = {static_cast<wchar_t>(L'A' + i), L':', L'\\', L'\0'};
        candidates.emplace_back(static_cast<char>('A' + i),
                                static_cast<int>(::GetDriveTypeW(root)));
    }
    return SelectDrives(candidates, spec);
#else
    (void)spec;
    return {};
#endif
}

}  // namespace rtsc::rdpdr