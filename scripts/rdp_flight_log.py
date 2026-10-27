#!/usr/bin/env python3
"""rdp_flight_log.py - a logging TCP proxy used for RDP server verification.

Listens on a local port and forwards every byte to a target host:port, logging
the direction, length and wall-clock time of each TCP read. TLS payloads are
ciphertext, so the log shows the *flight structure* (how many round trips, how
large, when the peer closed) without needing the session keys. That is enough to
tell which protocol phase a client reached before the connection ended.

Usage:
    python rdp_flight_log.py --listen 3391 --target 127.0.0.1:3390 [--seconds N]
                             [--log FILE]

This is a verification aid only; it is not part of the protocol stack.
"""

import argparse
import socket
import sys
import threading
import time


def log(log_file, text):
    stamp = time.strftime("%H:%M:%S")
    line = "[%s.%03d] %s" % (stamp, int((time.time() % 1) * 1000), text)
    print(line, flush=True)
    if log_file:
        log_file.write(line + "\n")
        log_file.flush()


def pump(src, dst, direction, log_file, state):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            state["bytes_" + direction] += len(data)
            log(log_file, "%s %5d bytes (total %d)" % (direction, len(data),
                                                       state["bytes_" + direction]))
            dst.sendall(data)
    except OSError as exc:
        log(log_file, "%s error: %s" % (direction, exc))
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        state[direction + "_closed"] = True
        log(log_file, "%s EOF/close" % direction)


def handle(client, target, log_file):
    try:
        upstream = socket.create_connection(target, timeout=15)
    except OSError as exc:
        log(log_file, "target connect failed: %s" % exc)
        client.close()
        return
    # The connect timeout must not become the steady-state recv timeout: a
    # client that is waiting on a GUI dialog would otherwise be cut off after
    # 15 idle seconds.
    upstream.settimeout(None)
    state = {"bytes_c2s": 0, "bytes_s2c": 0}
    log(log_file, "connection open c=%s" % (client.getpeername(),))
    t1 = threading.Thread(target=pump, args=(client, upstream, "c2s", log_file,
                                              state), daemon=True)
    t2 = threading.Thread(target=pump, args=(upstream, client, "s2c", log_file,
                                              state), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()
    log(log_file, "connection closed c2s=%d s2c=%d" % (state["bytes_c2s"],
                                                       state["bytes_s2c"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--target", required=True, help="host:port")
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--log", default=None)
    args = ap.parse_args()

    host, port_s = args.target.rsplit(":", 1)
    target = (host, int(port_s))
    log_file = open(args.log, "a", encoding="utf-8") if args.log else None

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.listen))
    srv.listen(8)
    srv.settimeout(1.0)
    log(log_file, "proxy listening on %d -> %s" % (args.listen, args.target))

    deadline = time.time() + args.seconds
    while time.time() < deadline:
        try:
            client, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle, args=(client, target, log_file),
                         daemon=True).start()

    log(log_file, "proxy stopped")
    srv.close()
    if log_file:
        log_file.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
