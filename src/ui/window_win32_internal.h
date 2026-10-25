// Internal seam between the Win32 window backend and the platform-neutral
// facade. NOT part of the public API: only src/ui/window.cpp includes this.
#pragma once

#include <memory>
#include <string>

#include "rtsc/ui/window.h"

namespace rtsc::ui {

// Defined in window_win32.cpp (Windows only). Returns nullptr and fills `why`
// when a window cannot be created (e.g. no interactive desktop).
std::unique_ptr<Window> CreateWin32Window(uint16_t width, uint16_t height,
                                          std::string& why);

}  // namespace rtsc::ui
