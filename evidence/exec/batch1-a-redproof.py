"""Independent red-proof reproduction for batch 1 (audit A).

For each defect: mutate credssp.cpp back to the pre-fix behaviour, rebuild the
SM test target, run it, and assert the expected test turns RED. Then restore the
file and verify its SHA256 is byte-identical to the recorded baseline.

Writes a report to F:\\rtsc\\evidence\\exec\\batch1-a-redproof-a.txt

Usage: python batch1-a-redproof.py
"""

import hashlib
import io
import os
import re
import subprocess
import sys

TARGET = r'F:\rtsc\src\credssp\credssp.cpp'
BUILD = r'F:\rtsc\build\verify'
EXE = os.path.join(BUILD, 'rtsc_credssp_sm_tests.exe')
OUT = r'F:\rtsc\evidence\exec\batch1-a-redproof-a.txt'

VSWROOT = r'C:\Program Files\Microsoft Visual Studio\2022\Enterprise'
VCVARS = os.path.join(VSWROOT, r'VC\Auxiliary\Build\vcvars64.bat')
CMAKE = os.path.join(VSWROOT, r'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe')


def sha256_file(path):
    return hashlib.sha256(open(path, 'rb').read()).hexdigest()


def find_cmake():
    if os.path.exists(CMAKE):
        return CMAKE
    for root in (r'C:\Program Files\Microsoft Visual Studio',
                 r'C:\Program Files (x86)\Microsoft Visual Studio'):
        for dp, dn, fn in os.walk(root):
            if 'cmake.exe' in fn and os.path.basename(dp).lower() == 'bin':
                return os.path.join(dp, 'cmake.exe')
    return 'cmake'


def build():
    """Build through vcvars64 so MSVC can find the standard library.

    Running cmake.exe directly leaves INCLUDE/LIB unset, and every compile then
    dies with C1083 "cannot open include file: 'array'". verify.ps1 does the
    same call-vcvars dance for this reason.
    """
    cmdline = 'call "{0}" >nul 2>&1 && "{1}" --build "{2}" --target rtsc_credssp_sm_tests'.format(
        VCVARS, find_cmake(), BUILD)
    p = subprocess.run(cmdline, shell=True, capture_output=True, text=True,
                       errors='replace')
    return p.returncode, (p.stdout or '') + (p.stderr or '')


def run_tests():
    p = subprocess.run([EXE], capture_output=True, text=True, errors='replace')
    text = (p.stdout or '') + (p.stderr or '')
    failing = re.findall(r'\[\s*FAIL\s*\]\s*(\S+)', text)
    # fall back to the summary line if the harness prints differently
    m = re.search(r'(\d+) tests?, (\d+) checks?, (\d+) failing', text)
    summary = m.group(0) if m else '(no summary)'
    return p.returncode, text, failing, summary


MUTATIONS = [
    ('S1', 'nonce back to constant',
     'if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();',
     'nonce_.assign(kNonceSize, 0);',
     'two_constructions_have_different_nonces'),

    ('S5', 'drop lower-bound version check',
     'if (req.version < kMinVersion) {',
     'if (false && req.version < kMinVersion) {',
     'version_below_min_is_rejected_with_valid_challenge'),

    ('S6', 'min -> no write-back',
     'version_ = std::min(version_, req.version);  // downgrade only, never upgrade',
     '/* mutation: no write-back */;',
     'server_version_is_echoed_back'),

    ('N-B1', 'exported key taken from nonce again',
     '''if (!crypto::RandomBytes(exported_session_key_, kExportedKeySize)) {
            return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
        }''',
     'exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);',
     'client_nonce_does_not_disclose_session_key'),

    ('S11', 'skip MAC compare',
     'if (checksum != expected_mac) {',
     'if (false && checksum != expected_mac) {',
     'tampered_signature_checksum_is_rejected'),

    ('S18', 'drop public-key guard',
     'if (server_public_key_.empty()) {',
     'if (false && server_public_key_.empty()) {',
     'start_without_public_key_fails'),

    ('R2', 'echo path writes version back',
     '''if (step_ == Step::kAwaitServerEcho) {
        return BuildStep5(req, out);''',
     '''if (step_ == Step::kAwaitServerEcho) {
        version_ = req.version;  // mutation: unscoped write-back
        return BuildStep5(req, out);''',
     'server_echo_version_does_not_downgrade'),

    ('D6', 'version check moved before errorCode',
     '    if (req.has_error_code) {',
     '''    if (step_ == Step::kAwaitChallenge && req.version < kMinVersion) {
        return Fail(Status::kUnsupported, "unsupported TSRequest version");
    }
    if (req.has_error_code) {''',
     'error_code_wins_over_bad_version'),
]


def main():
    original = io.open(TARGET, encoding='utf-8', newline='').read()
    base_hash = sha256_file(TARGET)
    lines = []
    lines.append('BATCH 1 RED-PROOF REPRODUCTION (audit A, independent)')
    lines.append('=' * 78)
    lines.append('baseline sha256 = ' + base_hash)
    lines.append('build dir       = ' + BUILD)
    lines.append('')
    ok_all = True
    results = []

    try:
        for code, desc, old, new, expected in MUTATIONS:
            if old not in original:
                lines.append('[SKIP] %-5s %s -- anchor not found' % (code, desc))
                ok_all = False
                results.append((code, desc, expected, 'ANCHOR-MISSING', ''))
                continue

            mutated = original.replace(old, new, 1)
            io.open(TARGET, 'w', encoding='utf-8', newline='').write(mutated)

            rc, blog = build()
            if rc != 0:
                tail = '\n'.join(blog.strip().splitlines()[-6:])
                lines.append('[BUILD-FAIL] %-5s %s' % (code, desc))
                lines.append(tail)
                ok_all = False
                results.append((code, desc, expected, 'BUILD-FAIL', ''))
            else:
                trc, tlog, failing, summary = run_tests()
                hit = expected in failing
                status = 'RED-OK' if hit else 'NOT-RED'
                if not hit:
                    ok_all = False
                lines.append('[%s] %-5s %-42s expect=%s' % (status, code, desc, expected))
                lines.append('        summary: ' + summary)
                if failing:
                    lines.append('        failing: ' + ', '.join(failing))
                results.append((code, desc, expected, status, summary))
    finally:
        io.open(TARGET, 'w', encoding='utf-8', newline='').write(original)

    restored_hash = sha256_file(TARGET)
    lines.append('')
    lines.append('restored sha256 = ' + restored_hash)
    lines.append('restore verified = ' + str(restored_hash == base_hash))
    if restored_hash != base_hash:
        ok_all = False

    # Final rebuild + run on the restored tree, to prove the tree is healthy.
    rc, blog = build()
    lines.append('post-restore rebuild rc = %d' % rc)
    if rc == 0:
        trc, tlog, failing, summary = run_tests()
        lines.append('post-restore tests: ' + summary)
        lines.append('post-restore failing: ' + (', '.join(failing) if failing else '(none)'))
        if failing:
            ok_all = False
    else:
        ok_all = False

    lines.append('')
    lines.append('=' * 78)
    red = sum(1 for r in results if r[3] == 'RED-OK')
    lines.append('mutations: %d, red-proven: %d, verdict: %s'
                 % (len(results), red, 'PASS' if ok_all else 'FAIL'))
    io.open(OUT, 'w', encoding='utf-8', newline='').write('\n'.join(lines) + '\n')
    print('\n'.join(lines))
    return 0 if ok_all else 1


if __name__ == '__main__':
    sys.exit(main())
