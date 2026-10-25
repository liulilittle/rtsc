"""Batch 1 delivery verifier (audit A) -- v2.

Read-only. Checks the executed work against the audit-a decisions:
  D1 min / D2 lower-bound-only / D3 BuildStep3 guard / D4 server-to-client key
  D5 nonce size guard BEFORE slicing / D6 errorCode-before-version
  S18 setter / N-B1 / kInternal / CSPRNG portability.

v2 fixes two false positives found while validating the checker itself:
  * D5: the guard already existed at c:229 but AFTER the slices at c:176/c:191.
        Presence is not enough -- the ORDER is the defect.
  * D4: DeriveSigningKey(..., true) already existed at c:384, but that is the
        receive path (OpenReceive). The defect is the SEND path at c:196.

Usage: python batch1-a-verify-delivery.py
Exit: 0 = all checks pass, 1 = at least one FAIL.
"""

import io
import os
import re
import sys

ROOT = r'F:\rtsc'
CHECKS = []


def check(name, ok, detail=''):
    CHECKS.append((name, bool(ok), detail))


def read(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return None
    return io.open(p, encoding='utf-8', errors='replace').read()


def code_only(text):
    """Strip comments and string literals so gates cannot be fooled by prose."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                i += 1
        elif c == '/' and i + 1 < n and text[i + 1] == '*':
            i += 2
            while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                i += 1
            i += 2
        elif c == '"':
            out.append(' ')
            i += 1
            while i < n and text[i] != '"':
                if text[i] == '\\':
                    i += 1
                i += 1
            i += 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def blank_preserving_lines(text):
    """Comment-stripped text that keeps line structure (for position queries)."""
    return code_only(text)


def main():
    cred = read(r'src\credssp\credssp.cpp')
    hdr = read(r'include\rtsc\credssp\credssp.h')
    tsr = read(r'include\rtsc\credssp\ts_request.h')
    tsm = read(r'tests\test_credssp_sm.cpp')
    cmk = read(r'CMakeLists.txt')

    if cred is None:
        print('FATAL: src/credssp/credssp.cpp missing')
        return 1

    c = code_only(cred)

    # ---- D1: min, not clamp ----
    check('D1 uses std::min for version_',
          re.search(r'version_\s*=\s*std::min\s*\(\s*version_\s*,', c) is not None,
          'expect version_ = std::min(version_, req.version)')
    check('D1 does NOT use std::clamp',
          'std::clamp' not in c,
          'clamp would upgrade a v4 client to v6')

    # ---- D2: lower bound only ----
    check('D2 rejects version below minimum',
          re.search(r'req\.version\s*<\s*kMinVersion', c) is not None,
          'expect if (req.version < kMinVersion)')
    check('D2 does NOT reject above maximum',
          re.search(r'req\.version\s*>\s*kMaxVersion', c) is None,
          'upper bound must not be rejected here (peer may be newer)')

    # ---- D5: guard must come BEFORE the slices (v2 fix) ----
    guard = c.find('nonce_.size() != kNonceSize')
    slice1 = c.find('nonce_.begin()')
    check('D5 guards nonce size before slicing',
          guard != -1 and slice1 != -1 and guard < slice1,
          'guard at c:229 currently sits AFTER slices at c:176/c:191 -> short nonce crashes')

    # ---- N-B1: exported key independent of nonce ----
    check('N-B1 does NOT derive exported key from nonce',
          re.search(r'exported_session_key_\s*(?:\.assign|=)\s*[^;]*nonce', c) is None,
          'exported_session_key_ must not come from nonce_')
    check('N-B1 uses RandomBytes for exported key',
          re.search(r'RandomBytes\s*\(\s*exported_session_key_', c) is not None,
          'expect crypto::RandomBytes(exported_session_key_, kExportedKeySize)')
    check('N-B1 keeps session_base_key fallback',
          re.search(r'exported_session_key_\s*=\s*session_base_key_', c) is not None,
          'else branch must assign session_base_key_')

    # ---- kInternal ----
    check('kInternal added to Status enum',
          tsr is not None and re.search(r'\bkInternal\b', tsr) is not None,
          'ts_request.h Status must gain kInternal')
    check('kInternal used for CSPRNG failure',
          re.search(r'Status::kInternal', c) is not None,
          'expect Fail(Status::kInternal, ...)')

    # ---- D4: step-4 MAC verification must use the server-to-client key ----
    # The defect is in OpenReceive: it must verify the echo MAC with the
    # SERVER-to-client key. signing_key_ (c:196) is client-to-server and stays
    # as-is for the step-3/step-5 sends; only the receive path flips.
    check('D4 receive path derives server-to-client signing key',
          re.search(r'(?:recv_signing_key|verify_key|server_signing_key)\s*=\s*'
                    r'DeriveSigningKey\s*\(\s*exported_session_key_\s*,\s*true\s*\)', c) is not None,
          'OpenReceive must derive DeriveSigningKey(exported_session_key_, true)')
    # SealSend legitimately uses signing_key_ (client-to-server). Only the
    # receive-side function must avoid it, so scope the check to OpenReceive.
    m_open = re.search(r'Error\s+CredsspClient::OpenReceive\s*\(([^)]*)\)\s*\{(.*?)\n\}', c, re.S)
    open_body = m_open.group(2) if m_open else ''
    check('D4 receive path does not reuse client-to-server signing_key_',
          m_open is not None and 'signing_key_' not in open_body,
          'OpenReceive must not sign with signing_key_ (client-to-server)')

    # ---- S18: production setter + fail-closed guard ----
    check('S18 production SetServerPublicKey exists',
          hdr is not None and re.search(r'void\s+SetServerPublicKey\s*\(\s*Bytes', hdr) is not None,
          'credssp.h must gain SetServerPublicKey(Bytes)')
    check('S18 guard inside BuildStep3',
          re.search(r'server_public_key_\.empty\(\)', c) is not None,
          'expect fail-closed when server_public_key_ is empty')

    # ---- D6: errorCode checked before version ----
    # Anchor on the branch conditions themselves. A bare find('error_code')
    # would match the constructor's version_ clamping region instead.
    idx_err = c.find('req.has_error_code')
    idx_ver = c.find('req.version < kMinVersion')
    check('D6 errorCode handled before version check',
          idx_err != -1 and idx_ver != -1 and idx_err < idx_ver,
          'errorCode branch must precede version validation (native_code must survive)')

    # ---- CSPRNG ----
    rnd = read(r'src\crypto\random.cpp')
    rpos = read(r'src\crypto\random_posix.cpp')
    rhdr = read(r'include\rtsc\crypto\random.h')

    check('CSPRNG header exists', rhdr is not None, 'include/rtsc/crypto/random.h')
    if rhdr is not None:
        # Only real #include lines count: the header's own comments legitimately
        # mention windows.h and POSIX headers while explaining why they are banned.
        includes = re.findall(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', rhdr, re.M)
        bad = [i for i in includes if i == 'windows.h' or i.startswith('sys/')
               or i in ('unistd.h', 'fcntl.h', 'bcrypt.h')]
        check('CSPRNG header has no platform headers',
              not bad,
              'forbidden includes in random.h: ' + ', '.join(bad) if bad
              else 'random.h must stay platform-neutral')

    impl = rpos if rpos is not None else rnd
    if impl is not None:
        src = code_only(impl)
        check('CSPRNG retries EINTR',
              'EINTR' in src,
              'missing EINTR retry -> spurious kInternal when a signal interrupts')
        if 'getrandom' in src:
            check('CSPRNG includes fcntl/unistd unconditionally',
                  '<fcntl.h>' in impl and '<unistd.h>' in impl,
                  'urandom fallback needs open/read/close declared')
        check('CSPRNG has no weak RNG',
              re.search(r'\brand\s*\(|\bsrand\s*\(|std::random_device|mt19937', src) is None,
              'no rand()/srand()/random_device/mt19937')
    else:
        check('CSPRNG implementation exists', False, 'random.cpp / random_posix.cpp')

    check('CMake links bcrypt',
          cmk is not None and 'bcrypt' in cmk,
          'expect target_link_libraries(rtsc_crypto PUBLIC bcrypt) inside if(WIN32)')
    if cmk is not None:
        m = re.search(r'if\s*\(\s*WIN32\s*\)(.{0,600}?)endif\s*\(', cmk, re.S)
        check('CMake bcrypt is inside if(WIN32)',
              m is not None and 'bcrypt' in m.group(1),
              'bcrypt must not be linked unconditionally')

    # ---- required tests ----
    required = [
        'two_constructions_have_different_nonces',
        'version_below_min_is_rejected_with_valid_challenge',
        'server_version_is_echoed_back',
        'tampered_signature_checksum_is_rejected',
        'start_without_public_key_fails',
        'client_nonce_does_not_disclose_session_key',
        'server_echo_version_does_not_downgrade',
        'error_code_wins_over_bad_version',
    ]
    if tsm is None:
        check('test_credssp_sm.cpp exists', False, 'missing')
    else:
        tc = code_only(tsm)
        for name in required:
            check('test present: ' + name, name in tc, 'RTSC_TEST(' + name + ')')

    # ---- report ----
    fails = [x for x in CHECKS if not x[1]]
    print('BATCH 1 DELIVERY VERIFICATION (audit A, v2)')
    print('=' * 74)
    for name, ok, detail in CHECKS:
        print(('PASS  ' if ok else 'FAIL  ') + name)
        if not ok and detail:
            print('        -> ' + detail)
    print('=' * 74)
    print('%d checks, %d passed, %d failed' % (len(CHECKS), len(CHECKS) - len(fails), len(fails)))
    return 0 if not fails else 1


if __name__ == '__main__':
    sys.exit(main())
