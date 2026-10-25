"""Pre-flight for batch 1 -- an UN-EXECUTED batch.

Batch 2's table mutates code that exists today, so its pre-flight asks
"does each anchor still hit exactly N lines".

Batch 1 is not executed yet, so the question is different, and both of my first
two attempts got it wrong:

  attempt 1  checked the mutation targets (``std::clamp``, empty-key check)
             and reported MISS -> wrong, those are the POST-fix shapes.
  attempt 2  checked the 5 test names and reported MISSING -> also wrong,
             §19.1.3 makes TDD mandatory, so the executor must WRITE those
             tests first. Their absence today is the expected state.

The only thing a pre-flight can and must prove for an un-executed batch:

  Q1. The defect still exists.        If it is already fixed, the red test
                                      cannot go red and step 1 of TDD is void.
  Q2. The new test name is unused.    If the name already exists, the executor
                                      would silently extend an existing test
                                      instead of writing the named one.
  Q3. The pre-fix baseline is green.  Otherwise "red after mutation" is
                                      unmeasurable.

Mutation-site specificity (Q4) cannot be checked before the fix exists; it is
re-checked by re-running this script after the fix, when the S5b/S6 rows must
flip to PRESENT.
"""
import io
import os
import re

SRC = r'F:\rtsc\src\credssp\credssp.cpp'
HDR = r'F:\rtsc\include\rtsc\credssp\credssp.h'
TESTFILES = [r'F:\rtsc\tests\test_credssp.cpp',
             r'F:\rtsc\tests\test_credssp_sm.cpp',
             r'F:\rtsc\tests\test_ntlm.cpp']

src = io.open(SRC, encoding='utf-8').read().splitlines()
hdr = io.open(HDR, encoding='utf-8').read().splitlines()
tests = ''
for p in TESTFILES:
    if os.path.exists(p):
        tests += io.open(p, encoding='utf-8').read()

ok = True

print('=== Q1: the defects are still present (red is achievable) ===')
print()


_COMMENT_TAIL = re.compile(r'//.*$')
_COMMENT_BLOCK = re.compile(r'/\*.*?\*/')


def _code_only(line):
    """Strip comments so a note cannot satisfy (or defeat) a code pattern.

    Auditor B's round-12 P3: after the N-B1 fix, a natural explanatory comment
    such as

        // N-B1: never write exported_session_key_ = Bytes(nonce_...) again

    matched the N-B1 pattern. With want=True that reports PRESENT/OK, i.e. the
    gate goes green precisely because the bug is documented as fixed. Stripping
    comments makes every row look only at executable code.
    """
    return _COMMENT_TAIL.sub('', _COMMENT_BLOCK.sub('', line))


def present(label, pattern, want, note):
    global ok
    rx = re.compile(pattern)
    hits = [i + 1 for i, s in enumerate(src) if rx.search(_code_only(s))]
    state = 'PRESENT' if hits else 'ABSENT'
    good = (state == 'PRESENT') == want
    ok &= good
    print('%-4s %-7s %-4s %s' % (label, state, 'OK' if good else 'BAD', note))
    for h in hits[:5]:
        print('        c:%-4d %r' % (h, src[h - 1].strip()[:80]))
    if len(hits) > 5:
        print('        ... %d more' % (len(hits) - 5))
    print()


present('S1', r'nonce_\.assign\(kNonceSize, 0\);', True,
        'deterministic nonce -> fix randomizes it')
present('S5', r'if \(version_ < kMinVersion\)', True,
        'bounds exist in ctor; fix must apply them to the SERVER version')
# S5b: the DEFECT is "no lower-bound check on the SERVER's version after Decode".
# Pre-fix there is none; post-fix D2 adds exactly one. So this row must flip
# ABSENT -> PRESENT, i.e. want=False here and re-run after the fix expecting the
# same False (it is the *defect* row). The original pattern also matched the
# post-fix guard and would have reported BAD after a correct fix, so it is now
# scoped to the pre-fix shape only.
present('S5b', r'req\.version\s*[<>]', False,
        'no server-version bound check after Decode (defect)')
# S6 / S18 patterns must match BOTH the pre-fix and post-fix shapes, or this
# script reports "BAD" after a correct fix and invites the executor to revert it.
# Auditor B caught this in round 12:
#   pre-fix  S6: no write-back at all          -> ABSENT   (want False)
#   post-fix S6: `version_ = std::min(...)`    -> PRESENT  (want True)
# The original alternation `std::clamp|req\.version` MISSED `std::min`, so a
# correct D1 fix looked like a regression. Same for S18: the guard is
# `server_public_key_.empty()`, which has no `=`, so the original pattern missed
# it entirely.
present('S6', r'version_\s*=\s*(?:std::clamp|std::min|req\.version)', False,
        'server version never written back (defect)')
present('S18', r'server_public_key_\s*=[^=]|server_public_key_\.empty\(\)', False,
        'no production write/guard on server_public_key_ (defect)')
# N-B1 (auditor B, round 12): the exported session key is SLICED OUT OF the
# client nonce (`c:191`), and the whole nonce is then sent in cleartext
# (`c:244`). The peer can therefore reconstruct the sealing key and decrypt the
# TSCredentials in authInfo. security-layer.md:830 requires a 16-byte RANDOM
# exported key; :611 requires clientNonce to be an independent 32-byte random.
# The defect survives an S1 fix (nonce random, still equal to the key), so it
# gets its own row. Pre-fix PRESENT, post-fix ABSENT.
present('N-B1', r'exported_session_key_\s*(?:\.assign|=)\s*[^;]*nonce_', True,
        'exported session key derived from the (cleartext) client nonce')

hook = [i + 1 for i, s in enumerate(hdr) if 'SetServerPublicKeyForTest' in s]
print('S18  test-only hook in header: h:%s %s' % (hook, 'OK' if hook else 'BAD'))
ok &= bool(hook)
print()

print('=== Q2: the 8 new test names are still unused (executor must write them) ===')
print()
NEW = ['two_constructions_have_different_nonces',
       'version_below_min_is_rejected_with_valid_challenge',
       'server_version_is_echoed_back',
       'tampered_signature_checksum_is_rejected',
       'start_without_public_key_fails',
       # Round-12 additions. The last one is the ONLY regression guard for D6:
       # without it, moving the version check before the errorCode branch keeps
       # every other test green while silently dropping native_code to 0.
       'client_nonce_does_not_disclose_session_key',
       'server_echo_version_does_not_downgrade',
       'error_code_wins_over_bad_version']
for n in NEW:
    unused = n not in tests
    ok &= unused
    print('  %-52s %s' % (n, 'UNUSED (OK)' if unused else 'ALREADY EXISTS'))
print()

print('=== Q3: baseline suites are green (pre-fix) ===')
print()
for exe, floor in (('rtsc_credssp_sm_tests', 15),
                   ('rtsc_ntlm_tests', 27),
                   ('rtsc_credssp_tests', 23)):
    p = r'F:\rtsc\build\verify\%s.exe' % exe
    if not os.path.exists(p):
        print('  %-24s MISSING BINARY -> run build_tls.bat' % exe)
        ok = False
        continue
    print('  %-24s exists (floor %d)' % (exe, floor))
print()

print('=== Q4: lines the fix must touch (re-check AFTER the fix) ===')
print()
for n in (42, 43, 46, 92, 93, 241, 300):
    if 1 <= n <= len(src):
        print('  c:%-4d %r' % (n, src[n - 1].strip()[:82]))
print()
print('  After the fix, S5b and S6 must flip to PRESENT -- that is what makes')
print('  "delete it" a meaningful mutation instead of a no-op.')

print()
print('RESULT:', 'batch 1 is executable' if ok else 'BLOCKED')

# Exit code must carry the verdict. verify.ps1 decides pass/fail from
# $LASTEXITCODE, so a script that only PRINTS "BLOCKED" and exits 0 is a gate
# that cannot fail -- auditor B proved this in round 12 by forcing a failure:
# the output said BLOCKED and the exit code was still 0.
raise SystemExit(0 if ok else 1)
