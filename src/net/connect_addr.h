// Non-blocking, budget-sliced multi-address TCP connect, shared by the two
// transport backends.
//
// This is an internal seam, deliberately separate from the public Transport API
// (which stays free of platform types): its argument is a raw addrinfo chain,
// which is a Winsock / POSIX concept. It exists so a test can inject an address
// list and prove that a first address which burns its whole budget slice (a
// firewall blackhole) does NOT prevent a later reachable address from being
// attempted.
//
// Ownership: the caller owns the addrinfo chain; it is never freed here.

#pragma once

#include <memory>
#include <string>
#include <utility>

struct addrinfo;

namespace rtsc::net {

class Transport;

// Outcome of a multi-address connect attempt. On failure `transport` is null
// and `timed_out` records whether the budget was exhausted (as opposed to a
// hard error such as an RST refusal, which fails the address immediately).
struct ConnectAttempt {
    std::unique_ptr<Transport> transport;
    bool timed_out = false;

    ConnectAttempt() = default;
    ConnectAttempt(std::unique_ptr<Transport> connected, bool timed_out_flag)
        : transport(std::move(connected)), timed_out(timed_out_flag) {}
};

// Tries every address in the (non-null) chain in order. Each address gets at
// most one equal slice of the kConnectTimeoutMs budget (floor 100 ms): an
// address that silently drops SYN only consumes its own slice, and a later
// reachable address is still attempted with its own budget. The whole attempt
// is additionally capped at kConnectTimeoutMs in total, so many addresses
// cannot stretch it. On success the socket is restored to blocking mode.
ConnectAttempt ConnectAddresses(addrinfo* addr_head);

}  // namespace rtsc::net