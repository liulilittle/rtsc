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
    bool session_active = false;
    std::string host;
    std::string backend;
};

// Executes one command and returns a JSON object body (no enclosing braces),
// exactly as UiDebugHost::Execute promises.
//
// Recognised ops: "ping", "state", "dirty". Anything else -- including a missing
// "op" -- answers ok=false with an error naming the offending value. That is
// deliberate: a debugger that silently answers "fine" to a typo turns a broken
// query into a false pass.
std::string ExecuteGuiCommand(const DebugSnapshot& snapshot, const std::string& json_body);

}  // namespace rtsc::debug
