"""Batch 2 test-existence gate.

Purpose: the batch-2 acceptance in security-integration.audit-a.md section 19.3.3
uses a total-count threshold (`>= 34 tests`). A total count cannot tell whether a
SPECIFIC test exists, so skipping S10 (P2, defensive) while writing the other
seven would still pass. This gate checks each required test by name.

Contract:
  * every name in REQUIRED must appear as `RTSC_TEST(<name>)` in the test file;
  * the file must also contain at least MIN_TESTS tests (double check);
  * on any failure: print exactly what is missing, then raise SystemExit(1).

Exit codes: 0 = pass, 1 = missing test / too few tests / unreadable file.

Usage:
  python batch2_gate.py [--file PATH] [--min-tests N]

Negative self-test (see --selftest): runs the same checker against a synthetic
source that lacks one required test and asserts the checker returns 1.
"""

import argparse
import io
import re
import sys

REQUIRED = [
    'shutdown_emits_close_notify_alert',                 # S24-a
    'shutdown_reports_continue_needed_as_failure',       # S24-b
    'shutdown_maps_failure_status_to_error',             # S24-c
    'shutdown_before_handshake_is_rejected',             # S22
    'shutdown_then_receive_still_drains',                # S9
    'tls13_only_config_does_not_fail_acquire',           # S19
    'peer_alert_native_code_is_not_an_alert_description',         # S23
    'coalesced_finished_and_app_data_are_both_delivered',  # S10
]

DEFAULT_FILE = r'F:\rtsc\tests\test_tls.cpp'
MIN_TESTS = 34


def check_source(src, min_tests):
    """Return (ok, lines, found_count, missing, total)."""
    names = re.findall(r'RTSC_TEST\((\w+)\)', src)
    found = set(names)
    missing = [t for t in REQUIRED if t not in found]
    total = len(names)

    out = []
    out.append('batch2 gate: %d RTSC_TEST found (need >= %d)' % (total, min_tests))
    out.append('required tests: %d' % len(REQUIRED))
    for t in REQUIRED:
        out.append(('  OK    ' if t in found else '  MISS  ') + t)

    ok = True
    if missing:
        ok = False
        out.append('')
        out.append('MISSING %d test(s):' % len(missing))
        for t in missing:
            out.append('  - ' + t)
    if total < min_tests:
        ok = False
        out.append('')
        out.append('TOO FEW TESTS: %d < %d' % (total, min_tests))
    return ok, out, len(found & set(REQUIRED)), missing, total


TLS_HEADER = r'F:\rtsc\include\rtsc\net\tls.h'

# S23 is a CONTRACT defect: the code is right, the comment lies. A behavioural
# test cannot catch "someone changed the comment back", so the comment itself is
# gated. Positive + negative: a negative-only check is defeated by wording such
# as "native_code != alert description".
CONTRACT_MUST_CONTAIN = [
    'kpeeralert',
    'cannot',
    'no backend produces',
]
CONTRACT_MUST_NOT_CONTAIN = [
    'native_code = alert description',
]


def check_tls_header_contract(path):
    """Return (ok, lines). Verifies tls.h:42's kPeerAlert contract comment.

    Three things must be true, and they are asserted separately so a failure
    names the real cause:
      1. the old false promise is gone;
      2. the comment says the description cannot be filled;
      3. the comment says NO backend produces this status today.
    """
    try:
        src = io.open(path, encoding='utf-8', errors='replace').read()
    except OSError as e:
        return False, ['ERROR: cannot read %s: %s' % (path, e)]

    # Restrict to the kPeerAlert declaration + its continuation comment lines.
    lines = src.splitlines()
    start = None
    for i, l in enumerate(lines):
        if l.lstrip().startswith('kPeerAlert,'):
            start = i
            break
    if start is None:
        return False, ['CONTRACT FAIL: kPeerAlert declaration not found in %s' % path]

    block = [lines[start]]
    for l in lines[start + 1:]:
        st = l.lstrip()
        if st.startswith('//'):
            block.append(l)
        else:
            break
    text = ' '.join(x.strip().lstrip('/').strip() for x in block)
    low = text.lower()

    out = []
    ok = True
    for bad in CONTRACT_MUST_NOT_CONTAIN:
        if bad.lower() in low:
            ok = False
            out.append('  CONTRACT FAIL: kPeerAlert comment still claims %r' % bad)
        else:
            out.append('  CONTRACT OK  : no longer claims %r' % bad)
    for good in CONTRACT_MUST_CONTAIN:
        if good in low:
            out.append('  CONTRACT OK  : mentions %r' % good)
        else:
            ok = False
            out.append('  CONTRACT FAIL: comment must mention %r' % good)
    return ok, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', default=DEFAULT_FILE)
    ap.add_argument('--min-tests', type=int, default=MIN_TESTS)
    ap.add_argument('--selftest', action='store_true',
                    help='negative self-test: drop one required test, expect exit 1')
    ap.add_argument('--header', default=TLS_HEADER,
                    help='tls.h to check the S23 contract against')
    args = ap.parse_args()

    if args.selftest:
        src = 'RTSC_TEST(placeholder_one) {}\nRTSC_TEST(placeholder_two) {}\n'
        for t in REQUIRED[:-1]:                      # deliberately omit the last one
            src += 'RTSC_TEST(%s) {}\n' % t
        ok, lines, nfound, missing, total = check_source(src, min_tests=1)
        print('SELFTEST (synthetic source, last required test omitted)')
        for l in lines:
            print(l)
        if ok:
            print('SELFTEST FAILED: checker accepted a source missing a required test')
            return 1
        print('SELFTEST PASSED: checker rejected the incomplete source (as required)')

        # contract checker: must reject the OLD comment and accept the current one.
        old_txt = ('kPeerAlert,       // TLS fatal alert received; '
                   'native_code = alert description\n')
        new_txt = ('kPeerAlert,  // Reserved for backends that can report a peer fatal '
                   'alert. NO backend produces this today: cannot expose level.\n')
        import tempfile, os
        bad = 0
        for txt, want_ok, label in ((old_txt, False, 'old comment'),
                                    (new_txt, True, 'fixed comment')):
            fd, path = tempfile.mkstemp(suffix='.h')
            try:
                os.write(fd, txt.encode('utf-8'))
                os.close(fd)
                got, _ = check_tls_header_contract(path)
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            verdict = 'OK' if got == want_ok else 'WRONG'
            if got != want_ok:
                bad += 1
            print('  contract selftest [%s]: got ok=%s want=%s -> %s'
                  % (label, got, want_ok, verdict))
        if bad:
            print('SELFTEST FAILED: contract checker misjudged %d sample(s)' % bad)
            return 1
        print('SELFTEST PASSED: contract checker accepts fixed, rejects old')
        return 0

    try:
        src = io.open(args.file, encoding='utf-8', errors='replace').read()
    except OSError as e:
        print('ERROR: cannot read %s: %s' % (args.file, e))
        raise SystemExit(1)

    ok, lines, nfound, missing, total = check_source(src, args.min_tests)
    for l in lines:
        print(l)

    c_ok, c_lines = check_tls_header_contract(args.header)
    print('')
    print('--- S23 contract (tls.h kPeerAlert) ---')
    for l in c_lines:
        print(l)

    print('')
    if ok and c_ok:
        print('BATCH2 GATE PASS: all %d required tests present, %d total; '
              'S23 contract OK' % (len(REQUIRED), total))
        return 0
    if not ok:
        print('BATCH2 GATE FAIL: %d/%d required tests present, %d total'
              % (nfound, len(REQUIRED), total))
    if not c_ok:
        print('BATCH2 CONTRACT FAIL: tls.h kPeerAlert comment regressed (S23)')
    raise SystemExit(1)
    print('BATCH2 GATE FAIL: %d/%d required tests present, %d total'
          % (nfound, len(REQUIRED), total))
    raise SystemExit(1)


if __name__ == '__main__':
    sys.exit(main())
