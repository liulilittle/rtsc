// Screenshot save helper for the GUI.
//
// The remote desktop lives in an RGBA Surface (rtsc::ui::Surface). Saving it
// must not depend on the window backend or on a dialog, so the naming and the
// file write are platform-neutral and directly testable; the Win32 front-end
// only supplies the chosen path.

#pragma once

#include <ctime>
#include <string>

#include "rtsc/ui/surface.h"

namespace rtsc::gui {

// "rtsc-screenshot-YYYYMMDD-HHMMSS.bmp" for `now` interpreted as UTC. UTC is
// deliberate: the name is a stable identifier, not a local-time greeting, and
// a fixed input makes the format testable across time zones.
std::string DefaultScreenshotName(std::time_t now);

// Writes `surface` as a 32bpp BMP (BGRA, top-down) using the shared encoder in
// rtsc::debug. Returns false and fills `error` when `path` is empty or the file
// cannot be written; on failure no partial file is left behind.
bool SaveScreenshotBmp(const rtsc::ui::Surface& surface,
                       const std::string& path, std::string& error);

}  // namespace rtsc::gui
