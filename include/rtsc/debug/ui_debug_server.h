// In-process UI debug channel (CDP-style, loopback HTTP + JSON).
//
// WHY THIS EXISTS
//
// Driving the GUI from outside costs one screenshot -> look -> one action round
// trip per step, and a screenshot only shows pixels: it cannot answer "how many
// frames were rendered", "which dirty rectangle was uploaded", "what zoom and
// fit state does the pipeline hold", or "did the input event actually reach the
// encoder". Every one of those questions came up while diagnosing the flicker
// and menu defects, and each time the answer had to be inferred from logs after
// the fact.
//
// This channel collapses a whole scenario into one call and returns structured
// state instead of pixels.
//
// SCOPE AND SAFETY
//
// - Default OFF. Nothing starts unless --ui-debug-port=<n> is given.
// - Binds 127.0.0.1 only. There is no authentication: it is a local
//   development seam, not a remote API.
// - No product behaviour changes when the flag is absent.
//
// PROTOCOL
//
//   POST /debug   body: {"commands":[{"op":"...","...":"..."}, ...]}
//                 reply: {"results":[{"ok":true,...}, ...]}
//   GET  /health  reply: {"ok":true,"uptime_ms":N}
//
// Commands run on the UI thread (the render loop drains the queue once per
// iteration), never on the HTTP thread, so a command can inspect and mutate
// client/window state without racing the compositor.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace rtsc::debug {

// What a command handler may touch. Implemented by the GUI; kept as an abstract
// interface so the server itself stays testable without a window or a client.
class UiDebugHost {
 public:
    virtual ~UiDebugHost() = default;

    // Executes one command given as a raw JSON object body (without braces) and
    // appends the result JSON object body (without braces). A handler must not
    // throw; report failures through `ok=false` and an `error` field.
    //
    // Runs on the HTTP worker thread. Implementations that need UI state must
    // forward to the UI thread; the provided implementation does this by
    // queueing, see UiDebugRunner.
    virtual std::string Execute(const std::string& json_body) = 0;
};

class UiDebugServer {
 public:
    UiDebugServer();
    ~UiDebugServer();

    UiDebugServer(const UiDebugServer&) = delete;
    UiDebugServer& operator=(const UiDebugServer&) = delete;

    // Starts listening on 127.0.0.1:port. Returns false and fills `error` when
    // the socket cannot be bound. Port 0 asks the OS for an ephemeral port;
    // port() then reports the real one.
    bool Start(uint16_t port, UiDebugHost* host, std::string& error);

    void Stop() noexcept;

    // The bound port, or 0 when not running.
    uint16_t port() const noexcept;

    // Runs one request synchronously against the bound socket model. Exposed so
    // the HTTP semantics can be tested without real sockets.
    static std::string HandleRequest(UiDebugHost* host, const std::string& request);

 private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rtsc::debug
