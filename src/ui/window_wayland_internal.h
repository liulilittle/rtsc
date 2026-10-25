// Internal seam between the Wayland window backend and the platform-neutral
// facade. NOT part of the public API: only src/ui/window.cpp includes this.
#pragma once

#include <memory>
#include <string>

#include "rtsc/ui/window.h"

namespace rtsc::ui {

// Defined in window_wayland.cpp (non-Windows, RTSC_UI_WAYLAND). Returns nullptr
// and fills `why` when no Wayland display can be connected.
std::unique_ptr<Window> CreateWaylandWindow(uint16_t width, uint16_t height,
                                            std::string& why);

}  // namespace rtsc::ui
