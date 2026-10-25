// Internal seam between the X11 window backend and the platform-neutral
// facade. NOT part of the public API: only src/ui/window.cpp includes this.
#pragma once

#include <memory>
#include <string>

#include "rtsc/ui/window.h"

namespace rtsc::ui {

// Defined in window_x11.cpp (non-Windows, RTSC_UI_X11). Returns nullptr and
// fills `why` when no X display can be opened.
std::unique_ptr<Window> CreateX11Window(uint16_t width, uint16_t height,
                                        std::string& why);

}  // namespace rtsc::ui
