// Win32 help/about dialog.
//
// NOT part of the public rtsc API: it is a Win32-only helper used by
// tools/rtsc_gui, shown when the window menu raises kCmdHelp ("帮助(H)").
//
// SCOPE / NO mstsc CLAIM: mstsc's Help item opens the Windows Help viewer with
// the Remote Desktop help content. This project ships no help content, and the
// reverse-engineering discipline forbids inventing mstsc behaviour that has no
// binary evidence (see memory.md "本工程最顶级纪律"). What this dialog does
// instead is state plainly what THIS program is and which build it is, which is
// verifiable from the binary itself. It deliberately does not pretend to be a
// help viewer.

#pragma once

namespace rtsc::gui {

// Shows the modal about/help dialog. `parent` may be nullptr. `version` is the
// full version line (e.g. "rtsc_gui 0.1.0"). The dialog owns no state: it is
// built from the strings passed in, so it can be exercised without a client.
void ShowHelpDialog(void* parent, const char* version);

}  // namespace rtsc::gui
