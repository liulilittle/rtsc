// Win32 connection-information dialog (mstsc parity).
//
// NOT part of the public rtsc API: it is a Win32-only helper used by
// tools/rtsc_gui. The dialog shows the SessionInfo fields collected by
// rtsc::client::CollectSessionInfo and is modal to the client window.

#pragma once

#include <functional>

#include "rtsc/client/session_info.h"

namespace rtsc::gui {

// Shows the modal connection-information dialog. `collect` is called when the
// dialog opens and then once a second, so the frame rate, round-trip time and
// the UTC timestamp stay live while it is open. `parent` may be nullptr.
void ShowConnectionInfoDialog(
    void* parent,
    const std::function<rtsc::client::SessionInfo()>& collect);

}  // namespace rtsc::gui
