// Connection information: the data behind the "Connection information" dialog
// that mstsc exposes from its title-bar system menu.
//
// This module is deliberately platform neutral and free of any window type: it
// turns a few live numbers (frame rate, round-trip time, bandwidth, the remote
// host) into the flat string table the dialog renders. The dialog lives in
// tools/rtsc_gui (Win32) and the tests exercise the collector here, so the field
// mapping cannot drift between them.
//
// What is measured and what is not:
//   * transport protocol : always "TCP". This client has no UDP transport
//                          ([MS-RDPBCGR] with UDP is a follow-up); the field is
//                          not guessed.
//   * frame rate         : measured by Client::NoteFrame (frames presented in
//                          the last second).
//   * round-trip time    : measured as the client's own input round-trip: the
//                          time from writing an input PDU to the next inbound
//                          server data. Reported as N/A until an input has been
//                          answered.
//   * available bandwidth: measured as inbound bytes per second. Reported as
//                          N/A until a second of traffic has been seen.

#pragma once

#include <ctime>
#include <string>

#include "rtsc/client/version.h"

namespace rtsc::client {

// The live values the collector needs. Kept as a struct so CollectSessionInfo
// stays testable: the tests supply fixed values instead of a live session.
struct SessionInfoInput {
    std::string host;          // the remote computer (from the command line)
    std::string local_os;      // override for tests; empty asks LocalOsString()
    double frames_per_second = 0.0;
    bool has_rtt = false;
    double rtt_ms = 0.0;
    double bandwidth_mbps = 0.0;  // 0 == not measured yet
    bool smart_card = true;
};

// Every field of the dialog, already formatted as text.
struct SessionInfo {
    // Connection quality banner.
    std::string quality;
    // Timestamp (UTC) and activity id.
    std::string timestamp_utc;
    std::string activity_id;
    // [Client details]
    std::string client_version;
    std::string client_architecture;
    std::string local_os;
    // [Network details]
    std::string transport_protocol;
    std::string round_trip_time;
    std::string available_bandwidth;
    std::string frame_rate;
    // [Remote computer details]
    std::string remote_session_type;
    std::string gateway_name;
    std::string gateway_logon_method;
    std::string remote_computer;
};

// Collects the dialog fields. `now` is injected so the timestamp is testable.
SessionInfo CollectSessionInfo(const SessionInfoInput& in, std::time_t now);

// Formats a UTC timestamp as "YYYY-MM-DD HH:MM:SS UTC".
std::string FormatUtcTimestamp(std::time_t now);

// The local operating system, e.g. "Windows 10.0.26200 (x64)".
std::string LocalOsString();

// A random activity id in canonical UUID form (version 4, variant 1).
std::string GenerateActivityId();

}  // namespace rtsc::client
