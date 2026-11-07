// Drive-enumeration policy tests (route B: rtsc_rdpdr/drive_enum.h).
//
// The selection policy is a pure function over a caller-supplied candidate list
// (letter + Windows drive type), so these cases never touch a real drive.

#include "rtsc/rdpdr/drive_enum.h"

#include <string>
#include <utility>
#include <vector>

#include "test_framework.h"
#include "test_main.h"

using rtsc::rdpdr::DriveInfo;
using rtsc::rdpdr::kDriveCdrom;
using rtsc::rdpdr::kDriveFixed;
using rtsc::rdpdr::kDriveRamdisk;
using rtsc::rdpdr::kDriveRemote;
using rtsc::rdpdr::kDriveRemovable;
using rtsc::rdpdr::SelectDrives;

namespace {

// A representative host: two fixed drives plus every type that must not be
// redirected by default.
std::vector<std::pair<char, int>> MixedHost() {
    return {{'C', kDriveFixed}, {'D', kDriveRemovable}, {'E', kDriveRemote},
            {'F', kDriveCdrom}, {'R', kDriveRamdisk}, {'X', kDriveFixed}};
}

std::string Names(const std::vector<DriveInfo>& drives) {
    std::string out;
    for (const auto& drive : drives) {
        if (!out.empty()) out.push_back(',');
        out += drive.dos_name;
    }
    return out;
}

}  // namespace

// Opt-in only (user decision 2026-10-28): with no RTSC_REDIRECT_DRIVES the
// redirect surface is empty, so a plain rtsc_gui run never hands the remote
// peer access to a local disk. mstsc behaves the same way (drives are ticked
// explicitly).
RTSC_TEST(drive_enum_default_redirects_nothing) {
    const auto candidates = MixedHost();
    CHECK(SelectDrives(candidates, nullptr).empty());
    CHECK(SelectDrives(candidates, "").empty());
}

RTSC_TEST(drive_enum_whitelist_selects_listed_letters) {
    const auto candidates = MixedHost();
    const std::vector<DriveInfo> picked = SelectDrives(candidates, "C,E");
    CHECK(Names(picked) == "C:,E:");

    // Letters are case-insensitive and may name non-fixed drives explicitly.
    CHECK(Names(SelectDrives(candidates, "d,c")) == "C:,D:");

    // A letter the host does not expose is ignored.
    CHECK(Names(SelectDrives(candidates, "Q")) == "");
    CHECK(Names(SelectDrives(candidates, "C,Q")) == "C:");
}

RTSC_TEST(drive_enum_all_selects_every_drive) {
    const auto candidates = MixedHost();
    CHECK(Names(SelectDrives(candidates, "ALL")) == "C:,D:,E:,F:,R:,X:");
    CHECK(Names(SelectDrives(candidates, "all")) == "C:,D:,E:,F:,R:,X:");
}

RTSC_TEST(drive_enum_invalid_spec_redirects_nothing) {
    const auto candidates = MixedHost();
    // Not a drive letter, wrong separator, empty items: every token is
    // invalid, so nothing is selected (a misconfiguration never widens the
    // redirect surface).
    CHECK(SelectDrives(candidates, "9").empty());
    CHECK(SelectDrives(candidates, "C;E").empty());
    CHECK(SelectDrives(candidates, ",").empty());
    CHECK(SelectDrives(candidates, "C,,E").empty());
    CHECK(SelectDrives(candidates, "CC").empty());
}

RTSC_TEST(drive_enum_names_and_roots_are_canonical) {
    // Candidate order must not leak into the result: the selection is sorted by
    // drive letter and each entry carries the DEVICE_ANNOUNCE dos name and the
    // local root.
    const std::vector<std::pair<char, int>> shuffled = {
        {'X', kDriveFixed}, {'C', kDriveFixed}};
    const std::vector<DriveInfo> picked = SelectDrives(shuffled, "ALL");
    CHECK_EQ(picked.size(), static_cast<size_t>(2));
    if (picked.size() == 2) {
        CHECK(picked[0].dos_name == "C:");
        CHECK(picked[0].local_root == "C:\\");
        CHECK(picked[1].dos_name == "X:");
        CHECK(picked[1].local_root == "X:\\");
    }
}

RTSC_TEST(drive_redirect_rdp_value_maps_to_spec) {
    using rtsc::rdpdr::DriveRedirectToSpec;
    CHECK(DriveRedirectToSpec("").empty());
    CHECK(DriveRedirectToSpec("*") == "ALL");
    CHECK(DriveRedirectToSpec("C:\\;E:\\;") == "C,E");
    CHECK(DriveRedirectToSpec("c:\\") == "C");
    CHECK(DriveRedirectToSpec("DynamicDrives") == "ALL");
    CHECK(DriveRedirectToSpec("C:\\;DynamicDrives") == "ALL");
    // Unknown tokens are ignored; a non-drive token never widens the set.
    CHECK(DriveRedirectToSpec("Zebra").empty());
    CHECK(DriveRedirectToSpec("C:\\;bogus") == "C");
}

int main() { return rtsc::test::run_all("rtsc_drive_enum_tests"); }
