// Windows USB backend for the URBDRC client: SetupAPI enumeration + WinUSB
// transfers. Windows only; the URBDRC channel handler stays platform neutral.

#pragma once

#ifdef _WIN32

#include <memory>

#include "rtsc/usb/usb_device.h"

namespace rtsc::usb {

// Creates the Win32 USB device enumerator. Returns nullptr on platforms where
// the backend cannot be initialised.
std::unique_ptr<UsbDeviceEnumerator> CreateWin32Enumerator();

}  // namespace rtsc::usb

#endif  // _WIN32
