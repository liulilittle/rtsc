"""Verify the executor handoff package (section 19) with SEMANTIC checks.

Two earlier versions failed the red test:
  v1  checked only "line number <= file length"     -> old numbers passed
  v2  hardcoded the expected line numbers           -> never read the doc,
                                                       so doc regressions passed

This version reads the cited number OUT OF THE DOC, then asserts that the line it
points at in the source contains the construct the surrounding prose names. If
someone reverts a citation to the pre-batch-0 number, the verifier reads that old
number and finds the wrong construct there.

Keyed by doc line, because the doc line is stable while the cited number is what
we are testing.
"""
import io
import re
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
FILES = {
    'tls': r'F:\rtsc\src\net\tls_schannel.cpp',
    'credssp': r'F:\rtsc\src\credssp\credssp.cpp',
    'cm': r'F:\rtsc\src\proto\connect_machine.cpp',
    'test': r'F:\rtsc\tests\test_tls.cpp',
}
SRC = {k: io.open(v, encoding='utf-8').read().splitlines() for k, v in FILES.items()}
L = io.open(DOC, encoding='utf-8').read().splitlines()

SHUTDOWN_IF = 'if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {'
CLOSED_SHORT = 'if (closed_) return MakeError(Status::kClosed'
DECODE_FAIL = 'if (!e.ok()) return Fail(e.status, "cannot decode TSRequest");'
# doc line -> (file, needle, required citation line)
# The third element pins WHICH citation on the line must resolve, so a line with
# several citations cannot pass by having an unrelated one happen to match.
EXPECT = {
    3421: ('tls', '#include "rtsc/net/tls.h"', 40),
    3779: ('credssp', 'nonce_.assign(kNonceSize, 0);', 46),
    3780: ('credssp', DECODE_FAIL, 93),
    3782: ('credssp', 'ciphertext', None),
    3884: ('cm', 'pdu.info.password', 168),
    4002: ('tls', 'SecBuffer token{0, SECBUFFER_TOKEN, nullptr};', 411),
    4007: ('tls', SHUTDOWN_IF, 431),
    4021: ('tls', 'kNeedMoreInput', 180),
    4030: ('tls', CLOSED_SHORT, 232),
    4053: ('tls', SHUTDOWN_IF, 431),
    4054: ('tls', SHUTDOWN_IF, 431),
    4102: ('test', 'CHECK_EQ(consumed, pt.size());', 745),
    4123: ('tls', CLOSED_SHORT, 232),
    # ---- sections 17/18 (auditor-facing, P2; fixed before batch 2) ----
    2473: ('tls', CLOSED_SHORT, 232),
    2814: ('tls', 'Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,', 101),
    2943: ('tls', 'if (!have_ctx_) {', 407),
    3075: ('tls', CLOSED_SHORT, 232),
    # ---- reachable from section 19's cross-chapter refs (B's P1 finding) ----
    2443: ('tls', 'if (rx_buffer_.size() < kMinRecordHeader) {', 244),
    2895: ('tls', SHUTDOWN_IF, 431),
    2919: ('tls', SHUTDOWN_IF, 431),
    2920: ('tls', SHUTDOWN_IF, 431),
    2928: ('tls', SHUTDOWN_IF, 431),
    3121: ('tls', SHUTDOWN_IF, 431),
    3123: ('tls', CLOSED_SHORT, 232),
    3162: ('tls', 'if (shutdown_sent_) return MakeError(Status::kOk, 0, "");', 406),
    3169: ('tls', 'if (!have_ctx_) {', 407),
    3822: ('tls', CLOSED_SHORT, 106),
}

# doc line -> additional citation on the same line that must also resolve
EXPECT_MULTI = {
    4002: ('tls', SHUTDOWN_IF),
    4102: ('test', 'CHECK_EQ(consumed, pt.size());'),
    4123: ('tls', 'closed_ = true;'),
    2814: ('tls', 'Error Receive(const uint8_t* ciphertext, size_t size,'),
}

CITE = re.compile(r'`(?:credssp\.cpp|tls_schannel\.cpp|t)?:(\d+)(?:-(\d+))?`')
# Inside fenced code blocks the citation appears as a plain comment, e.g.
# "// 只把 token 改对，:431 原样留着". Accept that form too.
CITE_BARE = re.compile(r'(?<![`\w]):(\d+)(?:-(\d+))?(?!`)')

ok = bad = 0
problems = []

for dl, (tgt, needle, req) in sorted(EXPECT.items()):
    if dl > len(L):
        bad += 1
        problems.append((dl, tgt, needle, 'doc line missing'))
        continue
    line = L[dl - 1]
    nums = [(int(m.group(1)), int(m.group(2)) if m.group(2) else int(m.group(1)))
            for m in CITE.finditer(line)]
    if not nums:
        nums = [(int(m.group(1)), int(m.group(2)) if m.group(2) else int(m.group(1)))
                for m in CITE_BARE.finditer(line)]
    if not nums:
        bad += 1
        problems.append((dl, tgt, needle, 'no citation on this doc line'))
        continue
    if req is not None:
        nums = [(a, b) for a, b in nums if a == req]
        if not nums:
            bad += 1
            problems.append((dl, tgt, needle,
                             'doc line does not cite :%d' % req))
            continue
    src = SRC[tgt]
    hits = []
    for a, b in nums:
        if a <= len(src) and b <= len(src):
            # A range citation names a construct that STARTS the range, so the
            # needle must be at the first line, not merely somewhere inside.
            # Otherwise "99-199" passes for a construct that lives at 101, and
            # the verifier cannot tell a correct range from an off-by-2 one.
            head = ' '.join(src[a - 1].split())
            span = ' '.join(' '.join(src[a - 1:b]).split())
            want = ' '.join(needle.split())
            if want in head or (a == b and want in span):
                hits.append((a, b))
    if hits:
        ok += 1
    else:
        bad += 1
        tried = ', '.join('%d-%d' % (a, b) if a != b else str(a) for a, b in nums)
        actual = src[nums[0][0] - 1].strip()[:64] if nums[0][0] <= len(src) else '<OOR>'
        problems.append((dl, tgt, needle, 'cited %s -> got %r' % (tried, actual)))

# the second citation on a multi-citation line must also be right
for dl, (tgt, needle) in sorted(EXPECT_MULTI.items()):
    line = L[dl - 1]
    nums = [(int(m.group(1)), int(m.group(2)) if m.group(2) else int(m.group(1)))
            for m in CITE.finditer(line)]
    src = SRC[tgt]
    found = any(
        a <= len(src) and b <= len(src) and
        ' '.join(needle.split()) in ' '.join(' '.join(src[a - 1:b]).split())
        for a, b in nums)
    if found:
        ok += 1
    else:
        bad += 1
        problems.append((dl, tgt, needle, 'second citation does not resolve'))

print('=== section 19 handoff package: semantic citation check ===')
print('citations verified OK :', ok)
print('citations MISMATCH    :', bad)
if problems:
    print()
    print('=== problems ===')
    for dl, tgt, needle, why in problems:
        print('  doc:%-5d %-8s need=%r' % (dl, tgt, needle[:44]))
        print('                          %s' % why)
sys.exit(1 if bad else 0)
