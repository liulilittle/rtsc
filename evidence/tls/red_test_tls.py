"""Red-evidence harness for the TLS backend (consult-b rule: a green test only
proves the test ran, not that it can fail).

Each mutation breaks ONE rule from design-a section 3.4.1/3.4.3 and must make
the suite fail. The file is restored byte-for-byte afterwards (sha256 checked),
so a crash mid-run cannot leave a mutated source behind.
"""
import hashlib
import io
import os
import shutil
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = r'F:\rtsc'
SRC = os.path.join(ROOT, 'src', 'net', 'tls_schannel.cpp')
BAK = os.path.join(ROOT, '.tmp', 'tls_schannel.cpp.orig')
EXE = os.path.join(ROOT, 'build', 'verify', 'rtsc_tls_tests.exe')
# Build through a .bat wrapper: passing a quoted vcvars path through
# subprocess' list2cmdline escaping makes cmd see literal backslashes and the
# call fails silently with an empty message.
BUILD_BAT = os.path.join(ROOT, '.tmp', 'build_tls.bat')

MUTATIONS = [
    ('M1_no_back_edge',
     'B1: drop the loop back edge so one Receive decodes at most one record',
     '            // Explicit back edge: without it a single Receive call decodes at\n'
     '            // most one record.\n'
     '            continue;\n',
     '            if (produced != 0) { return MakeError(Status::kOk, 0, ""); }\n'),

    ('M2_clear_output_in_loop',
     'N5: clear the caller buffer inside the loop (loses earlier records)',
     '            plaintext.insert(plaintext.end(), tmp.begin(), tmp.end());',
     '            plaintext.clear();\n'
     '            plaintext.insert(plaintext.end(), tmp.begin(), tmp.end());'),

    ('M3_no_record_length_bound',
     'N4: accept any declared record length, so a malformed header waits forever',
     '            if (length > kMaxRecordLength) {',
     '            if (length > 0xFFFFFFF0u) {'),

    ('M4_no_terminal_latch',
     'N7: do not latch terminal errors, so a later record is decoded again',
     '        if (terminal_) return last_error_;\n\n'
     '        if (size != 0 && ciphertext != nullptr) {',
     '        if (false) return last_error_;\n\n'
     '        if (size != 0 && ciphertext != nullptr) {'),

    ('M5_incomplete_returns_needmore',
     'N6: push an INCOMPLETE complete-record back instead of failing',
     '                // The record header said it was complete, so this is not "need\n'
     '                // more bytes". Pushing it back would make the buffer grow\n'
     '                // without bound, because the next call re-reads the same bytes.\n'
     '                return Fail(Status::kProtocolError, st);',
     '                return MakeError(Status::kNeedMoreInput, st, "wrong");'),

    ('M6_no_progress_counter',
     'N8: report kNeedMoreInput even when records were consumed',
     '                return (progressed != 0 || produced != 0)\n'
     '                           ? MakeError(Status::kOk, 0, "")\n'
     '                           : MakeError(Status::kNeedMoreInput, 0, "");',
     '                return MakeError(Status::kNeedMoreInput, 0, "");'),

    ('M7_no_drain_on_max_out',
     'B9: ignore max_out entirely, so the drain contract is never exercised',
     '            if (max_out != 0 && produced >= max_out) {\n'
     '                // Soft threshold: the caller must keep calling until\n'
     '                // buffered_input() == 0, otherwise records stay stranded.\n'
     '                return MakeError(Status::kOk, 0, "");\n'
     '            }',
     '            if (max_out == 0) {\n'
     '                return MakeError(Status::kOk, 0, "");\n'
     '            }'),

    ('M8_record_not_consumed',
     'N1: decrypt before consuming, so the same record is decrypted twice',
     '            rx_buffer_.erase(rx_buffer_.begin(),\n'
     '                             rx_buffer_.begin() + static_cast<ptrdiff_t>(record_size));',
     '            // mutation: record left in the buffer'),
]


def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()


def build():
    r = subprocess.run(['cmd', '/c', BUILD_BAT], capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def run():
    r = subprocess.run([EXE], capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    tail = [l for l in (r.stdout or '').splitlines() if l.strip()]
    return r.returncode, tail[-1] if tail else ''


def main():
    orig_sha = sha(SRC)
    shutil.copyfile(SRC, BAK)
    print('baseline sha256:', orig_sha[:16])
    rc, msg = build()
    if rc != 0:
        print('BASELINE BUILD FAILED:', msg[-400:])
        return 2
    rc, msg = run()
    print('baseline run   : exit=%d  %s' % (rc, msg))
    if rc != 0:
        print('baseline is not green; refusing to mutate')
        return 2

    original_text = io.open(SRC, encoding='utf-8', newline='').read()
    results = []
    try:
        for name, desc, old, new in MUTATIONS:
            if old not in original_text:
                results.append((name, desc, 'ANCHOR-MISSING', ''))
                print('%-26s ANCHOR MISSING' % name)
                continue
            mutated = original_text.replace(old, new, 1)
            io.open(SRC, 'w', encoding='utf-8', newline='').write(mutated)
            brc, bmsg = build()
            if brc != 0:
                err = [l for l in bmsg.splitlines() if 'error' in l.lower()]
                results.append((name, desc, 'BUILD-FAIL', err[0][:70] if err else ''))
                print('%-26s BUILD-FAIL (counts as caught)' % name)
            else:
                rrc, rmsg = run()
                verdict = 'CAUGHT' if rrc != 0 else 'MISSED'
                results.append((name, desc, verdict, rmsg))
                print('%-26s %-8s %s' % (name, verdict, rmsg[:60]))
            io.open(SRC, 'w', encoding='utf-8', newline='').write(original_text)
    finally:
        io.open(SRC, 'w', encoding='utf-8', newline='').write(original_text)

    restored = sha(SRC)
    print()
    print('restored sha256:', restored[:16], 'IDENTICAL' if restored == orig_sha else 'MISMATCH')
    if restored != orig_sha:
        print('RESTORE FAILED')
        return 3

    rc, msg = build()
    rc2, msg2 = run()
    print('rebuilt green  : build=%d run=%d %s' % (rc, rc2, msg2))

    missed = [r for r in results if r[2] == 'MISSED']
    missing = [r for r in results if r[2] == 'ANCHOR-MISSING']
    print()
    print('mutations: %d  caught: %d  missed: %d  anchor-missing: %d'
          % (len(results), len([r for r in results if r[2] in ('CAUGHT', 'BUILD-FAIL')]),
             len(missed), len(missing)))
    ok = not missed and not missing and restored == orig_sha and rc2 == 0
    print('RESULT=%s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
