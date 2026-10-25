"""Positive control for batch1-a-verify-delivery.py.

Runs the same decision checks against the reference implementation, which is
known to satisfy every decision. If any check fails here, the checker itself is
wrong -- not the delivery.

Usage: python batch1-a-positive-control.py
Exit: 0 = all checks pass on the reference (checker is trustworthy).
"""

import io
import re
import sys

REF = r'F:\rtsc\evidence\exec\batch1-a-fixed-credssp-reference.cpp'
HDR = r'F:\rtsc\include\rtsc\credssp\credssp.h'


def code_only(text):
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


def main():
    ref = io.open(REF, encoding='utf-8').read()
    c = code_only(ref)

    tests = {}
    tests['D1 uses std::min'] = re.search(
        r'version_\s*=\s*std::min\s*\(\s*version_\s*,', c) is not None
    tests['D1 no std::clamp'] = 'std::clamp' not in c
    tests['D2 rejects below min'] = re.search(r'req\.version\s*<\s*kMinVersion', c) is not None
    tests['D2 no upper reject'] = re.search(r'req\.version\s*>\s*kMaxVersion', c) is None

    guard = c.find('nonce_.size() != kNonceSize')
    slice1 = c.find('nonce_.begin()')
    tests['D5 guard before slice'] = guard != -1 and slice1 != -1 and guard < slice1

    tests['N-B1 not from nonce'] = re.search(
        r'exported_session_key_\s*(?:\.assign|=)\s*[^;]*nonce', c) is None
    tests['N-B1 RandomBytes'] = re.search(
        r'RandomBytes\s*\(\s*exported_session_key_', c) is not None
    tests['N-B1 session_base_key fallback'] = re.search(
        r'exported_session_key_\s*=\s*session_base_key_', c) is not None

    tests['kInternal used'] = 'Status::kInternal' in c
    tests['S18 empty guard'] = re.search(r'server_public_key_\.empty\(\)', c) is not None

    m = re.search(
        r'signing_key_\s*=\s*DeriveSigningKey\s*\(\s*exported_session_key_\s*,\s*(\w+)\s*\)', c)
    tests['D4 SEND uses true'] = m is not None and m.group(1) == 'true'

    # Locate the errorCode branch itself (req.has_error_code), not the bare
    # substring "error_code": the constructor also touches version_ near
    # kMinVersion, which made a naive find() compare the wrong offsets.
    ie = c.find('req.has_error_code')
    iv = c.find('req.version < kMinVersion')
    tests['D6 errorCode before version'] = ie != -1 and iv != -1 and ie < iv

    print('POSITIVE CONTROL: reference implementation vs decision checks')
    print('=' * 66)
    for k, v in tests.items():
        print(('PASS  ' if v else 'FAIL  ') + k)
    print('=' * 66)
    bad = [k for k, v in tests.items() if not v]
    print('%d checks, %d passed, %d failed' % (len(tests), len(tests) - len(bad), len(bad)))
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
