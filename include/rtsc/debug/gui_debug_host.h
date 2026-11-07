// GUI-side implementation of the in-process debug channel's host.
//
// WHY THIS IS SEPARATE FROM main()
//
// rtsc_gui is an executable that runs a full network client, so no test can
// link it. Keeping the command handling in a small library that takes a plain
// snapshot (instead of reaching into the client) makes the interesting part --
// what a command answers -- testable, while main() only has to fill the
// snapshot in once per drained queue.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/ui/window.h"

namespace rtsc::debug {

// One point-in-time view of what the GUI knows. main() fills this from the live
// client/window on the UI thread, then the command handler turns it into JSON.
struct DebugSnapshot {
    int desktop_width = 0;
    int desktop_height = 0;
    int view_width = 0;
    int view_height = 0;
    double zoom = 1.0;
    bool fit = false;
    unsigned frames_rendered = 0;
    unsigned loop_iterations = 0;
    unsigned input_events_sent = 0;
    // The pending dirty rectangle, in REMOTE-DESKTOP coordinates. Empty means
    // the next frame has nothing to repaint.
    int dirty_left = 0;
    int dirty_top = 0;
    int dirty_right = 0;
    int dirty_bottom = 0;
    // Command-line value for the "screenshot" command. When non-empty the
    // handler writes a BMP of the current view and reports "\"path\":<path>".
    std::string screenshot_path;
    bool session_active = false;
    std::string host;
    std::string backend;
    // Pixel statistics for the "surface" command (filled on demand).
    unsigned non_black_pixels = 0;
    unsigned distinct_colours = 0;
    unsigned total_pixels = 0;
    // Sampled render frames for the "frames" command (filled by main()).
    std::vector<unsigned> frame_samples;
    // Number of input events main() successfully sent when it processed this
    // "input" command; the reply reports it so an operator sees the effect.
    int input_injected = 0;
    // Set by main() when an input command fails to parse or to send; the
    // handler reports ok:false with this reason instead of a silent zero.
    std::string input_error;
};

// One decoded input event from an "input" command body. Coordinates are in
// REMOTE-DESKTOP space: the channel is a diagnostic tool, so it must not
// silently reinterpret operator-supplied pixels through the view transform.
struct InputEventSpec {
    enum class Kind : uint8_t {
        kKey,
        kMouseClick,
        kMouseMove,
        kMouseWheel,
        kUnicode,
    };
    Kind kind = Kind::kKey;
    uint8_t scancode = 0;
    bool release = false;
    bool extended = false;
    int x = 0;
    int y = 0;
    uint8_t button = 0;
    bool down = false;
    int wheel_delta = 0;
    bool horizontal = false;
    uint16_t unicode_code = 0;
};

// Executes one command and returns a JSON object body (no enclosing braces),
// exactly as UiDebugHost::Execute promises.
//
// Recognised ops: "ping", "state", "dirty", "surface", "screenshot", "frames",
// "input". Anything else -- including a missing "op" -- answers ok=false with an
// error naming the offending value. That is deliberate: a debugger that silently
// answers "fine" to a typo turns a broken query into a false pass.
std::string ExecuteGuiCommand(const DebugSnapshot& snapshot, const std::string& json_body);

// Returns true if the command body is asking for the pixel-statistics command.
bool CommandRequestsSurface(const std::string& json_body);

// Returns true if the command body is asking for the screenshot command.
bool CommandRequestsScreenshot(const std::string& json_body);

// Extracts the "path" field from a screenshot command body.
bool ScreenshotPath(const std::string& json_body, std::string& path);

// Encodes a top-down RGBA pixel buffer as a 32bpp BMP (BGRA, negative height).
// Returns empty on invalid dimensions.
std::string EncodeBmp32(const uint8_t* rgba, uint32_t width, uint32_t height);

// Serializes the collected frame samples to a JSON array string.
std::string FormatFrameSamples(const std::vector<unsigned>& samples);

// Returns true if the command body is asking for the frame-sample command.
bool CommandRequestsFrames(const std::string& json_body);

// Returns true if the command body is asking for the input-injection command.
bool CommandRequestsInput(const std::string& json_body);

// Decodes the "events" array of an input command. Returns false with `error`
// set when any element is malformed, when a mouse coordinate falls outside the
// remote desktop, or when the array is empty -- a channel that accepted a typo
// would inject the wrong keystroke into a live session.
bool ParseInputEvents(const std::string& json_body, int desktop_width,
                      int desktop_height,
                      std::vector<InputEventSpec>& out, std::string& error);

// Builds the "input" reply body from the number of events the caller injected.
std::string FormatInputReply(int injected);

// Returns true if the command body is asking for the resize command.
bool CommandRequestsResize(const std::string& json_body);

// Extracts "width" and "height" from a resize command. Returns false with
// `error` set when either is missing, zero, negative, or above 65535 -- the
// window surface dimensions are uint16_t, and silently truncating a requested
// 70000 to 4464 would resize to a size the operator never asked for.
bool ResizeRequest(const std::string& json_body, int& width, int& height,
                   std::string& error);

// Builds the "resize" reply body from the dimensions the caller applied.
std::string FormatResizeReply(int width, int height);

// Translates one decoded channel event into the front-end input shape. Returns
// false for a kind the front-end cannot carry. Kept in the library (rather than
// main.cpp) so the mapping -- especially the mouseclick -> kMouseButton rename,
// the button numbering, and the coordinate carry-through -- is covered by the
// unit suite: a channel that silently mapped left to right would inject the
// wrong click into a live session.
bool ToUiInputEvent(const InputEventSpec& spec, rtsc::ui::InputEvent& out);

// Translates a whole decoded array in order. Returns false if any element was
// untranslatable, so the caller never sends a silently truncated sequence.
bool ToUiInputEvents(const std::vector<InputEventSpec>& specs,
                     std::vector<rtsc::ui::InputEvent>& out);

}  // namespace rtsc::debug
