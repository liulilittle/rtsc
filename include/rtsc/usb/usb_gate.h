// RTSC_REDIRECT_USB gate policy ([MS-RDPEDYC] URBDRC wiring, tools/rtsc_gui).
//
// Platform neutral so the empty-string semantics can be unit tested: an unset
// OR empty environment variable must disable USB redirection (the GUI used to
// treat a set-but-empty RTSC_REDIRECT_USB= as "on", advertising the drdynvc
// static channel for a redirect that shares nothing).

#pragma once

#include <cstddef>

namespace rtsc::usb {

// True when RTSC_REDIRECT_USB requests USB redirection at all. "ALL" and a
// "VID:PID" whitelist are both enabled states; the per-device selection is the
// caller's UsbSpecAllows, which still filters nothing for an empty whitelist.
inline bool UsbGateEnabled(const char* spec) {
    return spec != nullptr && spec[0] != '\0';
}

}  // namespace rtsc::usb