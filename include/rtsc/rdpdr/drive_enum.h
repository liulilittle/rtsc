// Local drive enumeration for RDPDR drive redirection (route B).
//
// The selection policy is a pure function over a caller-supplied candidate list
// (drive letter + Windows drive type), so it can be unit-tested without a real
// drive list. EnumerateLocalDrives() is the thin host wrapper: on Windows it
// reads GetLogicalDrives() and GetDriveTypeW(); elsewhere it yields no drives.

#pragma once

#include <string>
#include <utility>
#include <vector>

namespace rtsc::rdpdr {

// Windows drive types (GetDriveTypeW), mirrored here so the filter itself stays
// platform neutral and testable.
enum DriveType : int {
    kDriveUnknown = 0,
    kDriveNoRootDir = 1,
    kDriveRemovable = 2,
    kDriveFixed = 3,
    kDriveRemote = 4,
    kDriveCdrom = 5,
    kDriveRamdisk = 6,
};

// One redirected drive. `dos_name` is the DEVICE_ANNOUNCE preferred DOS name
// (e.g. "C:"); `local_root` is the local directory the drive maps to (e.g.
// "C:\\").
struct DriveInfo {
    std::string dos_name;
    std::string local_root;
};

// Pure drive-selection policy. `candidates` pairs each present drive letter
// with its DriveType. `spec` is the RTSC_REDIRECT_DRIVES value:
//   * nullptr / ""  -> no drives (redirection is opt-in, like mstsc's
//                      per-drive tick boxes)
//   * "ALL"         -> every candidate
//   * "C,E"         -> exactly the listed letters (case-insensitive)
// A whitelist token that is not a single letter invalidates the whole spec and
// selects nothing, so a misconfiguration never widens the redirect surface.
// The result is ordered by drive letter.
std::vector<DriveInfo> SelectDrives(
    const std::vector<std::pair<char, int>>& candidates, const char* spec);

// Converts an .rdp "drivestoredirect" value into the RTSC_REDIRECT_DRIVES
// spec accepted by SelectDrives:
//   * ""                         -> "" (nothing)
//   * "*" or any DynamicDrives   -> "ALL"
//   * "C:\;E:\;"                 -> "C,E"
// Unknown tokens are ignored; a token that is not a drive root never widens
// the selection. The result is uppercase and comma separated.
std::string DriveRedirectToSpec(const std::string& value);

// Enumerates the host's local drives and applies SelectDrives. Windows uses
// GetLogicalDrives() + GetDriveTypeW(); any other platform returns an empty
// list (there is no redirectable local-drive concept there yet).
std::vector<DriveInfo> EnumerateLocalDrives(const char* spec);

}  // namespace rtsc::rdpdr
