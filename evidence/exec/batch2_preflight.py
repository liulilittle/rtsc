"""Pre-flight for batch 2: verify every anchor in §19.3.3's red table still
locates exactly the intended code, and report the hit count.

The table tells the executor to Select-String each anchor and "confirm exactly 1
line". Before dispatching, check that this instruction is actually satisfiable
today -- if an anchor now hits 0 or 2+, the executor would be blocked.
"""
import io
import re

SRC = r'F:\rtsc\src\net\tls_schannel.cpp'
src = io.open(SRC, encoding='utf-8').read().splitlines()

ANCHORS = [
    ('S24-a', r'SecBuffer token\{0, SECBUFFER_TOKEN, nullptr\}', 1),
    ('S24-c', r'ApplyControlToken\(&ctx_, &desc\);', 1),
    ('S24-b', r'if \(st == SEC_E_OK \|\| st == SEC_I_CONTINUE_NEEDED\)', 1),
    ('S22',   r'return MakeError\(Status::kOk, st, "shutdown best effort"\);', 1),
    ('S9',    r'if \(closed_\) return MakeError\(Status::kClosed', 3),
    ('S19',   r'mask \|= SP_PROT_TLS1_3_CLIENT', 1),
    ('S10',   r'consumed = in_size;', 1),
]

print('=== batch 2 anchor pre-flight ===')
ok = True
for name, pat, expected in ANCHORS:
    rx = re.compile(pat)
    hits = [i + 1 for i, s in enumerate(src) if rx.search(s)]
    status = 'OK' if len(hits) == expected else 'MISMATCH'
    if len(hits) != expected:
        ok = False
    print('%-6s expect %d  got %d  %-9s %s' % (name, expected, len(hits), status, hits))
    if hits:
        print('       %r' % src[hits[0] - 1].strip()[:88])
    if name == 'S9':
        # A20-4: "the first closed_ hit after Receive" silently picks the wrong
        # guard if someone inserts one between the signature and the real guard.
        # Use a two-sided window whose BOTH ends are unique anchors instead, and
        # require exactly one hit inside -- an insertion then fails loudly.
        lo = next((i + 1 for i, s in enumerate(src)
                   if 'Error Receive(const uint8_t* ciphertext' in s), None)
        hi = next((i + 1 for i, s in enumerate(src)
                   if 'size_t progressed = 0;' in s), None)
        if lo is None or hi is None:
            ok = False
            print('       S9 window bounds not found (lo=%s hi=%s)' % (lo, hi))
        else:
            in_win = [h for h in hits if lo < h < hi]
            print('       window (%d,%d) closed_ hits = %s' % (lo, hi, in_win))
            if len(in_win) != 1:
                ok = False
                print('       FAIL: expected exactly 1 closed_ guard in the window')

print()
print('=== S23 anchor: the table describes it in prose, not as a regex ===')
for i, s in enumerate(src):
    if 'SEC_I_CONTEXT_EXPIRED' in s:
        print('  %4d | %s' % (i + 1, s.strip()[:88]))
print()
print('RESULT:', 'all anchors locatable' if ok else 'BLOCKED: fix the table first')

# Exit code must carry the verdict (auditor B round 12): verify.ps1 tests
# $LASTEXITCODE, so printing BLOCKED while exiting 0 makes this gate unable to
# fail. Same defect as batch1_preflight.py; fixed in both.
raise SystemExit(0 if ok else 1)
