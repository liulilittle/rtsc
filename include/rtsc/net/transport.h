// Blocking byte transport, the lowest layer under the connection driver.
//
// The protocol and security layers are deliberately transport agnostic: they
// produce and consume byte vectors. This interface is the seam where a real
// socket is plugged in. It stays free of platform types so the layers above
// compile unchanged on every platform; the implementation (Winsock, POSIX)
// lives in the corresponding .cpp.
//
// The server role adds the Listener abstraction: the same blocking byte stream,
// but the socket is bound and accepting instead of connecting.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace rtsc::net {

// Read() returns this sentinel when its bounded wait elapsed without any data
// becoming available. It is neither an orderly EOF (0) nor an error (-1): the
// peer is merely silent, so the caller should keep polling. This is what keeps
// a silent server from stalling the caller (and with it the UI message pump).
constexpr int kReadTimeout = -2;

// How long Read() waits for data before reporting kReadTimeout. Short on
// purpose: the render loop polls the window between reads, and a wait of tens
// of milliseconds adds avoidable input and screen-update latency -- with no
// data in flight the pump sleeps the whole timeout each iteration (real-session
// measurements showed ~30 ms read stalls with the loop at 30/s during the idle
// stretch). 2 ms is the smallest value that still costs negligible CPU on an
// idle session: the loop only re-renders when the surface actually changed,
// so polling mostly times out well under 1% of a core.
//
// Note on the effective wait on Windows: Winsock select() quantizes its timeout
// to the system timer tick, so a 2 ms timeval actually returns after the next
// ~15.6 ms tick and a 30 ms timeval after two ticks (~31 ms). Lowering the
// constant therefore halves the real worst-case idle poll (31 -> ~15.6 ms) and
// doubles the idle loop rate; the value is still what a platform that honors
// the timeval precisely would use.
constexpr int kReadTimeoutMs = 2;

class Transport {
 public:
    virtual ~Transport() = default;

    // Reads up to `size` bytes. Returns the number read (>0), 0 on orderly
    // EOF, -1 on error, or kReadTimeout (-2) when the bounded wait elapsed
    // with no data (a silent peer; retry, do not treat as a disconnect).
    // May return fewer than `size` bytes.
    virtual int Read(uint8_t* buf, size_t size) = 0;

    // Sends all `size` bytes. Returns false on error.
    virtual bool Write(const uint8_t* data, size_t size) = 0;

    // Closes the underlying socket. Idempotent.
    virtual void Close() = 0;
};

// Opens a blocking TCP connection. Returns nullptr and fills `error` on failure.
std::unique_ptr<Transport> ConnectTcp(const std::string& host, uint16_t port,
                                      std::string& error);

// A listening TCP socket, the server-side counterpart of Transport.
//
// Close() is safe to call from another thread and unblocks a pending Accept().
class Listener {
 public:
    virtual ~Listener() = default;

    // Accepts one connection. Blocks until a peer connects, Close() is called,
    // or the listener fails; returns nullptr in the latter two cases.
    virtual std::unique_ptr<Transport> Accept() = 0;

    // Closes the listening socket. Idempotent.
    virtual void Close() = 0;

    // The TCP port the socket is actually bound to, as reported by the kernel
    // (getsockname) at bind time. When ListenTcp() is given port 0 the kernel
    // picks a free port; this accessor is the only way for a caller to learn
    // which one, so tests can bind an ephemeral port instead of hardcoding one
    // and racing every other process on the machine for it.
    //
    // The value is captured once, so it stays readable after Close().
    virtual uint16_t local_port() const = 0;
};

// Binds and listens on `host:port`. Returns nullptr and fills `error` on failure.
std::unique_ptr<Listener> ListenTcp(const std::string& host, uint16_t port,
                                    std::string& error);

}  // namespace rtsc::net
