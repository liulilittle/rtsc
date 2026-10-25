"""Red test B: document untouched, only the SOURCE is perturbed.

Auditor A's critique of my earlier red test was correct: injecting old numbers
into the DOCUMENT only proves the anchor lookup works, because the anchor text
itself contains the line number (":169" is inside the anchor). That test cannot
distinguish "anchor matched" from "semantic check ran".

This test changes nothing in the document. It rewrites the SOURCE line that a
check points at, and asserts the verifier reports a mismatch. If it does, the
semantic comparison is doing real work.
"""
import io
import subprocess
import sys

VER = r'F:\rtsc\evidence\exec\verify_citations.py'
SRC_REAL = r'F:\rtsc\src\net\tls_schannel.cpp'

ver = io.open(VER, encoding='utf-8').read()

# Redirect both DOC and the tls source to shadow copies.
SHADOW_SRC = r'F:\rtsc\.tmp\shadow_tls.cpp'
SHADOW_VER = r'F:\rtsc\.tmp\verify_citations_semred.py'

orig = io.open(SRC_REAL, encoding='utf-8').read()
lines = orig.splitlines(keepends=True)

# :169 is `consumed = in_size;` -- two checks point at it (doc:725, doc:3128).
assert 'consumed = in_size;' in lines[168], repr(lines[168])
lines[168] = lines[168].replace('consumed = in_size;',
                                'consumed = in_size_other;  // SEMANTIC RED')
io.open(SHADOW_SRC, 'w', encoding='utf-8', newline='').write(''.join(lines))

red = ver.replace(
    r"'tls': r'F:\rtsc\src\net\tls_schannel.cpp',",
    r"'tls': r'F:\rtsc\.tmp\shadow_tls.cpp',")
assert red != ver, 'failed to redirect the tls source'
io.open(SHADOW_VER, 'w', encoding='utf-8', newline='').write(red)

print('--- source perturbed, document untouched ---')
print('src:169 -> consumed = in_size_other;  // SEMANTIC RED')
p = subprocess.run([sys.executable, SHADOW_VER], capture_output=True, text=True,
                   encoding='utf-8')
print(p.stdout.strip())
print('exit=%d' % p.returncode)
if p.returncode != 1:
    print()
    print('FAIL: semantic check does not run independently of the anchor text.')
    print('      The verifier is only testing that anchors can be found.')
    sys.exit(1)

p2 = subprocess.run([sys.executable, VER], capture_output=True, text=True,
                    encoding='utf-8')
print()
print('--- real source restored ---')
print(p2.stdout.strip())
print('exit=%d' % p2.returncode)
sys.exit(0 if p2.returncode == 0 else 1)
