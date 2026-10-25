#!/usr/bin/env python
# Static sanity check of the FINAL reference implementation.
# No compilation, no exe. Verifies structure and the D1-D6 + N-B1 shapes.
import io

P = r'F:\rtsc\.tmp\audit-batch1\shadow\src\credssp.cpp.fixed'
H = r'F:\rtsc\.tmp\audit-batch1\shadow\include\rtsc\credssp\credssp.h'
s = io.open(P, encoding='utf-8', newline='').read()
h = io.open(H, encoding='utf-8', newline='').read()
TS_H = r'F:\rtsc\.tmp\audit-batch1\shadow\include\rtsc\credssp\ts_request.h'
ts_h = io.open(TS_H, encoding='utf-8', newline='').read()

# brace balance, skipping strings and comments
depth = 0
in_str = esc = in_line = in_blk = False
i = 0
bad = None
while i < len(s):
    c = s[i]
    n = s[i + 1] if i + 1 < len(s) else ''
    if in_blk:
        if c == '*' and n == '/':
            in_blk = False
            i += 2
            continue
        i += 1
        continue
    if in_line:
        if c == '\n':
            in_line = False
        i += 1
        continue
    if in_str:
        if esc:
            esc = False
        elif c == '\\':
            esc = True
        elif c == '"':
            in_str = False
        i += 1
        continue
    if c == '/' and n == '*':
        in_blk = True
        i += 2
        continue
    if c == '/' and n == '/':
        in_line = True
        i += 1
        continue
    if c == '"':
        in_str = True
        i += 1
        continue
    if c == '{':
        depth += 1
    elif c == '}':
        depth -= 1
        if depth < 0:
            bad = i
            break
    i += 1

print('brace_depth_final =', depth, '(0 = balanced)')
print('negative_depth_at =', bad)
print()

# scoped sections
sec_challenge = s.split('if (step_ == Step::kAwaitChallenge) {')[1].split('return BuildStep3')[0]

checks = [
    ('S1 random include', '#include "rtsc/crypto/random.h"' in s),
    ('S1 RandomBytes for nonce', 'crypto::RandomBytes(nonce_, kNonceSize)' in s),
    ('S1 zero-fill removed', 'nonce_.assign(kNonceSize, 0);' not in s),
    ('D5 nonce guard present', s.count('nonce must be 32 bytes') == 2),
    ('D2 lower-bound inside branch', 'req.version < kMinVersion' in sec_challenge),
    ('D2 upper bound NOT rejected', 'req.version > kMaxVersion' not in s),
    ('D1 min inside branch', 'std::min(version_, req.version)' in sec_challenge),
    ('D1 clamp absent', 'std::clamp' not in s),
    ('D1+D2 not before the branch',
     s.index('if (step_ == Step::kAwaitChallenge) {') < s.index('req.version < kMinVersion')),
    ('errorCode branch before version check',
     s.index('if (req.has_error_code)') < s.index('req.version < kMinVersion')),
    ('S18 guard', 'server public key not set' in s),
    ('S18 setter in header', 'SetServerPublicKey(Bytes spk)' in h),
    ('S18 test hook kept', 'SetServerPublicKeyForTest' in h),
    ('utility include in header', '#include <utility>' in h),
    ('S18 guard before D5 guard',
     s.index('server public key not set') < s.index('nonce must be 32 bytes')),
    ('D5 guard before token check',
     s.index('nonce must be 32 bytes') < s.index('challenge without token')),
    ('S11 recv signing key', 'recv_signing_key' in s),
    ('S11 MAC mismatch', 'sealed field MAC mismatch' in s),
    ('S11 version check', 'sealed field unsupported version' in s),
    ('S11 seq check', 'sealed field out of sequence' in s),
    ('S11 recv_seq after MAC', s.index('sealed field MAC mismatch') < s.index('++recv_seq_;')),
    ('N-B1 exported NOT from nonce',
     'exported_session_key_.assign(nonce_' not in s),
    ('N-B1 independent RandomBytes', 'crypto::RandomBytes(exported_session_key_, 16)' in s),
    ('N-B1 else branch kept', 'exported_session_key_ = session_base_key_;' in s),
    ('N-B1 failure is kInternal',
     'Fail(Status::kInternal, "CSPRNG unavailable for exported session key")' in s),
    ('Status::kInternal declared in ts_request.h', 'kInternal,' in ts_h),
]

ok = True
for name, v in checks:
    print(('PASS ' if v else 'FAIL ') + name)
    ok = ok and v

print()
print('ALL_STATIC_CHECKS_PASS =', ok)
