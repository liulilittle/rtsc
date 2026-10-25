"""Independent red-proof reproduction for batch 1 (audit A) -- isolated tree.

Runs in a private copy of the sources so it never touches the shared worktree.
The executor reported verify catching a half-mutated credssp.cpp at 19:35/19:36;
that was an earlier version of this script writing into F:\\rtsc directly. Fixed
by building a shadow tree.

Mutation style: delete the fix (revert to pre-fix behaviour) instead of writing
`if (false && ...)`, which MSVC rejects with C4127 under /W4 /WX.

Usage: python batch1-a-redproof-shadow.py
"""

import hashlib
import io
import os
import re
import shutil
import subprocess
import sys

SRC = r'F:\rtsc'
SH = r'F:\rtsc\.tmp\redproof_tree'
SH_BUILD = os.path.join(SH, 'build_red')
SH_TARGET = os.path.join(SH, 'src', 'credssp', 'credssp.cpp')
SH_EXE = os.path.join(SH_BUILD, 'rtsc_credssp_sm_tests.exe')

REAL_TARGET = os.path.join(SRC, 'src', 'credssp', 'credssp.cpp')
OUT = r'F:\rtsc\evidence\exec\batch1-a-redproof-a.txt'

VSWROOT = r'C:\Program Files\Microsoft Visual Studio\2022\Enterprise'
VCVARS = os.path.join(VSWROOT, r'VC\Auxiliary\Build\vcvars64.bat')
CMAKE = os.path.join(VSWROOT, r'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe')


def sha(path):
    return hashlib.sha256(open(path, 'rb').read()).hexdigest()


def run_cmd(cmdline, timeout=900):
    p = subprocess.run(cmdline, shell=True, capture_output=True, text=True,
                       errors='replace', timeout=timeout)
    return p.returncode, (p.stdout or '') + (p.stderr or '')


def make_shadow():
    if os.path.isdir(SH):
        shutil.rmtree(SH)
    os.makedirs(SH)
    for item in ('CMakeLists.txt',):
        shutil.copy2(os.path.join(SRC, item), os.path.join(SH, item))
    for item in ('include', 'src', 'tests', 'tools'):
        shutil.copytree(os.path.join(SRC, item), os.path.join(SH, item))
    return True


def configure_and_build():
    cfg = 'call "{0}" >nul 2>&1 && "{1}" -S "{2}" -B "{3}" -G Ninja -DCMAKE_BUILD_TYPE=Debug'.format(
        VCVARS, CMAKE, SH, SH_BUILD)
    rc, out = run_cmd(cfg)
    if rc != 0:
        return rc, 'CONFIGURE FAILED\n' + out
    return build()


def build():
    cmd = 'call "{0}" >nul 2>&1 && "{1}" --build "{2}" --target rtsc_credssp_sm_tests'.format(
        VCVARS, CMAKE, SH_BUILD)
    return run_cmd(cmd)


def run_tests():
    p = subprocess.run([SH_EXE], capture_output=True, text=True, errors='replace')
    text = (p.stdout or '') + (p.stderr or '')
    failing = re.findall(r'\[\s*FAIL\s*\]\s*(\S+)', text)
    m = re.search(r'(\d+) tests?, (\d+) checks?, (\d+) failing', text)
    return p.returncode, failing, (m.group(0) if m else '(no summary)'), text


S5_BLOCK = '''        if (req.version < kMinVersion) {
            return Fail(Status::kUnsupported, "unsupported TSRequest version");
        }
'''
S11_BLOCK = '''    if (checksum != expected_mac) {
        plaintext.clear();
        return Fail(Status::kMalformed, "sealed field MAC mismatch");
    }
'''
S18_BLOCK = '''    if (server_public_key_.empty()) {
        return Fail(Status::kUnsupported, "server public key not set");
    }
'''

MUTATIONS = [
    ('S1', 'nonce back to a constant (pre-fix)',
     'if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();',
     'nonce_.assign(kNonceSize, 0);',
     'two_constructions_have_different_nonces'),

    ('S5', 'remove the lower-bound version check',
     S5_BLOCK, '        /* mutation: version check removed */\n',
     'version_below_min_is_rejected_with_valid_challenge'),

    ('S6', 'remove the version write-back (min)',
     '        version_ = std::min(version_, req.version);  // downgrade only, never upgrade\n',
     '        /* mutation: no write-back */\n',
     'server_version_is_echoed_back'),

    ('N-B1', 'exported key derived from nonce again',
     '''        if (!crypto::RandomBytes(exported_session_key_, kExportedKeySize)) {
            return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
        }
''',
     '        exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);\n',
     'client_nonce_does_not_disclose_session_key'),

    ('S11', 'remove the echo MAC comparison',
     S11_BLOCK,
     '    (void)checksum;\n    (void)expected_mac;  /* mutation: MAC compare removed */\n',
     'tampered_signature_checksum_is_rejected'),

    ('S18', 'remove the public-key guard',
     S18_BLOCK,
     '    /* mutation: public-key guard removed */\n',
     'start_without_public_key_fails'),

    ('R2', 'write the step-4 version back (unscoped)',
     '''    if (step_ == Step::kAwaitServerEcho) {
        return BuildStep5(req, out);''',
     '''    if (step_ == Step::kAwaitServerEcho) {
        version_ = req.version;  // mutation: unscoped write-back
        return BuildStep5(req, out);''',
     'server_echo_version_does_not_downgrade'),

    ('D6', 'move the version check before the errorCode branch',
     '    if (req.has_error_code) {',
     '''    if (step_ == Step::kAwaitChallenge && req.version < kMinVersion) {
        return Fail(Status::kUnsupported, "unsupported TSRequest version");
    }
    if (req.has_error_code) {''',
     'error_code_wins_over_bad_version'),
]


def main():
    real_hash_before = sha(REAL_TARGET)
    lines = ['BATCH 1 RED-PROOF (audit A, isolated shadow tree)',
             '=' * 78,
             'real tree credssp.cpp sha256 (before) = ' + real_hash_before,
             'shadow tree = ' + SH,
             '']

    make_shadow()
    original = io.open(SH_TARGET, encoding='utf-8', newline='').read()
    lines.append('shadow credssp.cpp sha256 = ' + sha(SH_TARGET))
    lines.append('')

    rc, out = configure_and_build()
    if rc != 0:
        lines.append('BASELINE BUILD FAILED')
        lines.append(out[-2000:])
        io.open(OUT, 'w', encoding='utf-8', newline='').write('\n'.join(lines) + '\n')
        print('\n'.join(lines))
        return 1

    trc, failing, summary, _ = run_tests()
    lines.append('BASELINE (unmutated shadow): ' + summary)
    lines.append('  failing: ' + (', '.join(failing) if failing else '(none)'))
    lines.append('')
    baseline_ok = (not failing)

    results = []
    for code, desc, old, new, expected in MUTATIONS:
        if old not in original:
            lines.append('[ANCHOR-MISSING] %-5s %s' % (code, desc))
            results.append((code, desc, expected, 'ANCHOR-MISSING', ''))
            continue
        io.open(SH_TARGET, 'w', encoding='utf-8', newline='').write(
            original.replace(old, new, 1))
        brc, bout = build()
        if brc != 0:
            lines.append('[BUILD-FAIL] %-5s %s' % (code, desc))
            for l in bout.strip().splitlines():
                if 'error' in l.lower():
                    lines.append('    ' + l.strip()[:150])
            results.append((code, desc, expected, 'BUILD-FAIL', ''))
            continue
        trc, failing, summary, _ = run_tests()
        hit = expected in failing
        lines.append('[%s] %-5s %s' % ('RED-OK' if hit else 'NOT-RED', code, desc))
        lines.append('        expect red: ' + expected)
        lines.append('        summary: ' + summary)
        if failing:
            lines.append('        failing: ' + ', '.join(failing))
        results.append((code, desc, expected, 'RED-OK' if hit else 'NOT-RED', summary))

    io.open(SH_TARGET, 'w', encoding='utf-8', newline='').write(original)
    rc, out = build()
    trc, failing, summary, _ = run_tests()
    lines.append('')
    lines.append('shadow restored: rebuild rc=%d, %s' % (rc, summary))
    lines.append('  failing: ' + (', '.join(failing) if failing else '(none)'))

    real_hash_after = sha(REAL_TARGET)
    lines.append('')
    lines.append('real tree credssp.cpp sha256 (after)  = ' + real_hash_after)
    lines.append('real tree untouched = ' + str(real_hash_before == real_hash_after))

    red = sum(1 for r in results if r[3] == 'RED-OK')
    ok = (red == len(results) and baseline_ok and not failing
          and real_hash_before == real_hash_after)
    lines.append('')
    lines.append('=' * 78)
    lines.append('mutations=%d red-proven=%d baseline_green=%s verdict=%s'
                 % (len(results), red, baseline_ok, 'PASS' if ok else 'FAIL'))
    io.open(OUT, 'w', encoding='utf-8', newline='').write('\n'.join(lines) + '\n')
    print('\n'.join(lines))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
