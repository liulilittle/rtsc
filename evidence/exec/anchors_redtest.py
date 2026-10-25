"""Red test for anchor gate v9 -- covers every probe both auditors built.

A's probes (round 8):
  A1  anchor = cur[431] (line BEFORE the cited :432)
  A2  anchor = cur[433] (line AFTER)
  A3  range 101-201, anchor from cur[154]  -> must PASS (inside range)
  A4  range 101-149, anchor from cur[154]  -> must FAIL (outside)
  A5  stale t:291 with anchor text living at :293 -> must FAIL
  A6  WEAK: doc:2876 :432 -> :304, anchor untouched -> must FAIL (v9 uniqueness)

B's probes (round 18):
  B1  anchor exists elsewhere in file, not at cited line -> must FAIL
  B2  anchor is a very common line -> must FAIL
  B3  anchor text does not exist -> must FAIL

Plus: baseline must pass.
"""
import io
import subprocess
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
VER = r'F:\rtsc\evidence\exec\verify_anchors.py'
SHADOW = r'F:\rtsc\.tmp\v9_probe.md'
REDVER = r'F:\rtsc\.tmp\v9_probe_ver.py'

orig = io.open(DOC, encoding='utf-8').read()
ver = io.open(VER, encoding='utf-8').read()
redver = ver.replace(r"DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'",
                     r"DOC = r'F:\rtsc\.tmp\v9_probe.md'")
assert redver != ver
io.open(REDVER, 'w', encoding='utf-8', newline='').write(redver)


def run(doc_text):
    io.open(SHADOW, 'w', encoding='utf-8', newline='').write(doc_text)
    p = subprocess.run([sys.executable, REDVER], capture_output=True, text=True,
                       encoding='utf-8')
    return p.returncode, p.stdout


def first_line(out, key):
    for l in out.splitlines():
        if key in l:
            return l.strip()
    return ''


CASES = [
    ('baseline unchanged', None, 0),
    # A1/A2: anchor from the neighbouring line of :432
    ('A1 anchor from cur[431]',
     ('`src/net/tls_schannel.cpp:432`（锚点 `closed_ = true;  (in Shutdown)`）',
      '`src/net/tls_schannel.cpp:432`（锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {  (in Shutdown)`）'),
     1),
    ('A2 anchor from cur[433]',
     ('`src/net/tls_schannel.cpp:432`（锚点 `closed_ = true;  (in Shutdown)`）',
      '`src/net/tls_schannel.cpp:432`（锚点 `return MakeError(Status::kOk, st, "");  (in Shutdown)`）'),
     1),
    # A6 / B-weak: citation moved to :304, anchor untouched
    ('A6 :432 -> :304 anchor untouched',
     ('`t:432`（锚点 `closed_ = true;  (in Shutdown)`）',
      '`t:304`（锚点 `closed_ = true;  (in Shutdown)`）'),
     1),
    # B1: anchor exists elsewhere in the file
    ('B1 anchor exists elsewhere',
     ('`t:432`（锚点 `closed_ = true;  (in Shutdown)`）',
      '`t:432`（锚点 `return Fail(Status::kProtocolError, st);`）'),
     1),
    # B2: very common line
    ('B2 anchor very common',
     ('`t:432`（锚点 `closed_ = true;  (in Shutdown)`）',
      '`t:432`（锚点 `return MakeError(Status::kOk, 0, "");`）'),
     1),
    # B3: text does not exist
    ('B3 anchor does not exist',
     ('`t:432`（锚点 `closed_ = true;  (in Shutdown)`）',
      '`t:432`（锚点 `this_text_appears_nowhere_xyz`）'),
     1),
    # ---- round 9: range boundaries (auditor B's G1 / R-2) ----
    # C1: shift a `sig .. }` range by -2. Anchor untouched, so only brace
    #     balance can reject it.
    ('C1 "sig .. }" range -2',
     ('`src/net/tls_schannel.cpp:371-384`（锚点 `Error PeerSubjectPublicKey(',
      '`src/net/tls_schannel.cpp:369-382`（锚点 `Error PeerSubjectPublicKey('),
     1),
    # C2: extend the end past the real closing brace.
    ('C2 "sig .. }" range end +2',
     ('`src/net/tls_schannel.cpp:371-384`（锚点 `Error PeerSubjectPublicKey(',
      '`src/net/tls_schannel.cpp:371-386`（锚点 `Error PeerSubjectPublicKey('),
     1),
    # C3: `sig .. }` anchor whose start fragment is moved off by +1.
    ('C3 "sig .. }" start +1',
     ('锚点 `Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {` .. `}`',
      '锚点 `out.clear();` .. `}`'),
     1),
    # C4: single-fragment range whose only fragment sits mid-range, cited range
    #     shifted by -2. This is exactly the doc:1828 shape.
    ('C4 single-frag midrange -2',
     ('`src/net/tls_schannel.cpp:371-384`（锚点 `Error PeerSubjectPublicKey(',
      '`src/net/tls_schannel.cpp:371-384`（锚点 `return MakeError(Status::kOk, 0, "");`'),
     1),
    # ---- round 10: inner-block masquerade (auditor A's X1) ----
    # C5: cite an inner `if` block as if it were the function body, with a
    #     self-consistent anchor. Brace-balanced, so only "must start at a
    #     function signature" can reject it.
    ('C5 inner block as function body',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:493-496`（锚点 `if (QueryContextAttributesW` .. `}`'),
     1),
    # C6: depth==0 range -- no block opened at all, cb merely contains `}`.
    ('C6 depth==0 range accepted',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:103-116`（锚点 `consumed = 0;` .. `}`'),
     1),
    # ---- round 11: false-positive guards (auditors A and B, R-2) ----
    # D1-D5: a CORRECT citation of a real function whose signature is not in the
    # old return-type whitelist. These must PASS (exit=0). They were FALSE
    # ALARMS before `starts_a_function` was made a blacklist.
    ('D1 correct cite: destructor',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:89-93`（锚点 `~SchannelTransport() override {` .. `}`'),
     0),
    ('D2 correct cite: uint32_t return',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:517-519`（锚点 `uint32_t ExpectedActualOverhead() const {` .. `}`'),
     0),
    ('D3 correct cite: static uint16_t',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:561-568`（锚点 `static uint16_t WireVersionFromProtocolMask(DWORD mask) {` .. `}`'),
     0),
    ('D4 correct cite: PCCERT_CONTEXT',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:671-684`（锚点 `PCCERT_CONTEXT PeerCert() const {` .. `}`'),
     0),
    ('D5 correct cite: static Error',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:690-696`（锚点 `static Error ConstError(Status s, int32_t code, const char* msg) {` .. `}`'),
     0),
    # ---- round 12: `} else if (...)` continuation ----
    # E1: `} else if (...)` must be rejected. NOTE (auditor B's Q-3): this probe
    #     does NOT discriminate the CLOSING_PREFIX guard. brace_balanced(315,321)
    #     is already False (the range's depth walk never reaches 1), so E1 stays
    #     exit=1 with or without the guard. It is kept as a brace_balanced
    #     regression test, NOT as evidence that the guard works.
    ('E1 "} else if" continuation (bb regression)',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:315-321`（锚点 `} else if (st == SEC_I_CONTINUE_NEEDED) {` .. `}`'),
     1),
    # ---- round 12, auditor B's Q-2: non-functions accepted as functions ----
    # E2 IS the discriminating probe. t:349 is the bare statement `out.clear();`
    # and the range 349-358 DOES brace-balance (it ends on a real `}`), so
    # brace_balanced says yes and only starts_a_function can reject it. Under
    # v12 (`head = split('(')[0]` finds `out.clear`) this was ACCEPTED -- B
    # measured exit=0 end-to-end. It must now be exit=1.
    ('E2 bare statement as function body',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:349-358`（锚点 `out.clear();` .. `}`'),
     1),
    # E3: aggregate initializer, also brace_balanced-valid (cb=596).
    ('E3 aggregate init as function body',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:595-596`（锚点 `sb[1] = {static_cast<unsigned long>(size), SECBUFFER_DATA,` .. `}`'),
     1),
    # ---- round 12, auditors A AND B independently reported this one ----
    # E4: t:362 is the THIRD line of a wrapped `if` condition:
    #   :360 if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
    #   :361      &cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr,
    #   :362      out.data(), &size)) {
    # It has `(`, its brace@20 > paren@18, and its head is `out.data`, so v14
    # accepted it; brace_balanced(362,366) is True as well, so BOTH layers
    # passed. Only statement_head (walk back to `if`) can reject it.
    ('E4 wrapped-if tail as function body',
     ('`src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`',
      '`src/net/tls_schannel.cpp:362-366`（锚点 `out.data(), &size)) {` .. `}`'),
     1),
    # E5 was going to cite src/credssp/ntlm.cpp:239, but the doc never cites
    # ntlm.cpp (only ntlm.h), so that anchor cannot resolve and the probe would
    # pass for the wrong reason. The lambda guard is exercised synthetically in
    # the SYNTHETIC section below instead.
]

fails = 0
for name, subst, want in CASES:
    if subst is None:
        text = orig
    else:
        old, new = subst
        if old not in orig:
            print('%-38s SKIP (anchor not found: %r)' % (name, old[:50]))
            fails += 1
            continue
        text = orig.replace(old, new, 1)
    code, out = run(text)
    ok = (code == want)
    print('%-38s exit=%d expect=%d  %s' % (name, code, want, 'OK' if ok else '*** WRONG ***'))
    if not ok:
        fails += 1
        print('   ', first_line(out, 'WRONGLINE')[:150])

# ---- synthetic unit probes for guards that are NOT reachable via the doc ----
# E5 could not be written as a doc citation: the doc never cites ntlm.cpp, so an
# anchor there would not resolve and the probe would go green for the wrong
# reason (the same scaffolding bug auditor B hit in round 12). Test the guard
# directly instead.
import importlib.util

_spec = importlib.util.spec_from_file_location('_va_syn', VER)
_va = importlib.util.module_from_spec(_spec)
try:
    _spec.loader.exec_module(_va)
except SystemExit:
    pass

SYNTH = [
    ('S1 operator[] is a function', 'int operator[](int i) {', 0),
    ('S2 operator() is a function', 'int operator()(int x) {', 0),
    ('S3 real signature', 'Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {', 0),
    ('S4 lambda [&](...) {', 'auto emit = [&](const Bytes& v, size_t field) {', 1),
    ('S5 lambda [](...) {', 'auto f = [](int x) {', 1),
    ('S6 bare statement', 'out.clear();', 1),
    ('S7 comment', '// other platforms (which get their own backend)', 1),
    ('S8 aggregate init', 'sb[1] = {static_cast<unsigned long>(size), SECBUFFER_DATA,', 1),
    # S9: a comment carrying an unbalanced paren must not shift the walk-back.
    # Without comment stripping, statement_head() stopped at the comment and the
    # legitimate wrapped signature below it was judged to start at the comment.
    # The signature's FIRST line is the correct citation; the last line is not.
    ('S9 comment paren does not shift head', 'Error Foo(int x,', 0),
]

_va.SRC['_syn.cpp'] = [t for _, t, _ in SYNTH]
for name, text, want_reject in SYNTH:
    got = _va.starts_a_function(_va.SRC['_syn.cpp'], SYNTH.index((name, text, want_reject)) + 1)
    ok = (not got) == bool(want_reject)
    print('%-38s fn=%-5s expect=%-7s %s'
          % (name, got, 'reject' if want_reject else 'accept', 'OK' if ok else '*** WRONG ***'))
    if not ok:
        fails += 1

# The wrapped-signature case needs three lines, so it gets its own check:
# statement_head must walk past the comment and land on line 1.
_WRAPPED = [
    'Error Foo(int x,',
    '  // note ( unbalanced open paren',
    '  int y) {',
]
_va.SRC['_wrap.cpp'] = _WRAPPED
_h = _va.statement_head(_va.SRC['_wrap.cpp'], 3)
_ok = (_h == 1)
print('%-38s head=%-4d expect=1  %s'
      % ('S10 comment does not shift head', _h, 'OK' if _ok else '*** WRONG ***'))
if not _ok:
    fails += 1

sys.exit(1 if fails else 0)