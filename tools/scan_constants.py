"""Scan a PE for RDP protocol constants and report file offsets + context.

Usage: python scan_constants.py <pe-file> [--context N]
All output goes to stdout; nothing is written outside the repo.
"""
import sys
import re

PATTERNS = {
    "gcc_ccrq_prefix": bytes.fromhex("000500147c0001"),
    "gcc_ccrq_prefix2": bytes.fromhex("000500147c0001".replace(" ", "")),
    "t124_oid_tail": bytes.fromhex("147c0001"),
    "mcs_connect_initial_tag": bytes.fromhex("7f65"),
    "mcs_connect_response_tag": bytes.fromhex("7f66"),
    "x224_data": bytes.fromhex("02f080"),
    "tpkt_v3": bytes.fromhex("0300"),
    "rdp_neg_req": bytes.fromhex("01000800"),
    "rdp_neg_rsp": bytes.fromhex("02000800"),
    "rdp_neg_failure": bytes.fromhex("03000800"),
}

TEXT_PATTERNS = {
    "cookie_mstshash": b"Cookie: mstshash=",
    "cookie_mstshash_w": "Cookie: mstshash=".encode("utf-16le"),
    "MS_T120": b"MS_T120",
    "MS_T120_w": "MS_T120".encode("utf-16le"),
    "CredSSP": b"CredSSP",
    "CredSSP_w": "CredSSP".encode("utf-16le"),
    "NTLM": b"NTLM",
    "RDPBCGR": b"RDPBCGR",
    "rdpdr": b"rdpdr",
    "rdpsnd": b"rdpsnd",
    "cliprdr": b"cliprdr",
    "drdynvc": b"drdynvc",
    "Microsoft Account": b"MicrosoftAccount",
    "remote desktop": b"Remote Desktop",
    "NLA": b"NLA",
    "TLS": b"TLS",
}


def find_all(hay: bytes, needle: bytes, limit: int = 64):
    out = []
    start = 0
    while len(out) < limit:
        i = hay.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def hexdump(data: bytes, base: int, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        textpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {base + off:08X}  {hexpart:<{width * 3}}  {textpart}")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    ctx = 32
    if "--context" in sys.argv:
        ctx = int(sys.argv[sys.argv.index("--context") + 1])

    with open(path, "rb") as f:
        data = f.read()
    print(f"file: {path}")
    print(f"size: {len(data)}")
    print()

    for name, pat in PATTERNS.items():
        hits = find_all(data, pat)
        print(f"[bin] {name}: {len(hits)} hit(s)")
        for h in hits[:4]:
            print(hexdump(data[max(0, h - 8):h + ctx], max(0, h - 8)))
        print()

    for name, pat in TEXT_PATTERNS.items():
        hits = find_all(data, pat)
        if not hits:
            continue
        print(f"[str] {name}: {len(hits)} hit(s) at {[hex(h) for h in hits[:8]]}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
