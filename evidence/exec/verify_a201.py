"""Independent verification of the A20-1 repair.

Verifies the ONLY thing that matters: for every citation `path:N`, does line N
of the current file contain the construct the document claims?

The anchor text written next to each citation is used as the expected content.
A citation passes if the anchor's leading token appears on the cited line.
Citations with no anchor (prose-only) are listed as unverifiable rather than
counted as passes.
"""
import io
import re
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
SRC = r'F:\rtsc\src\net\tls_schannel.cpp'
FAC = r'F:\rtsc\src\net\tls_factory.cpp'

src = io.open(SRC, encoding='utf-8').read().splitlines()
fac = io.open(FAC, encoding='utf-8').read().splitlines()
doc = io.open(DOC, encoding='utf-8').read()

# citation optionally followed by （锚点 `...`）
CITE = re.compile(
    r'`(?:src/net/)?tls_schannel\.cpp:(\d+)(?:-(\d+))?`'
    r'(?:（(?:批 0 后；)?锚点 `([^`]*)`）)?')
MOVED = re.compile(r'`src/net/tls_factory\.cpp`（批 0 搬迁：([^）]*)）')

ok = bad = noanchor = moved = 0
problems = []

for m in CITE.finditer(doc):
    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else None
    anchor = m.group(3)
    if anchor is None:
        noanchor += 1
        problems.append(('NOANCHOR', start, end, '', ''))
        continue
    # first token of the anchor is enough to identify the construct
    token = anchor.split('(')[0].strip()
    token = token.split('..')[0].strip()
    token = ' '.join(token.split())
    if not token or token == 'None':
        bad += 1
        problems.append(('BADANCHOR', start, end, anchor, ''))
        continue
    lines = src if start - 1 < len(src) else []
    span = lines[start - 1: (end if end else start)]
    hit = any(token in ' '.join(l.split()) for l in span)
    if hit:
        ok += 1
    else:
        bad += 1
        actual = lines[start - 1].strip()[:60] if start - 1 < len(lines) else '<EOF>'
        problems.append(('MISMATCH', start, end, token, actual))

for m in MOVED.finditer(doc):
    moved += 1

print('=== A20-1 independent verification ===')
print('citations with anchor, verified OK :', ok)
print('citations with anchor, MISMATCH    :', bad)
print('citations without anchor           :', noanchor)
print('moved-to-factory citations         :', moved)
print()
if problems:
    print('=== details ===')
    for kind, start, end, token, actual in problems:
        rng = '%d-%d' % (start, end) if end else str(start)
        print('  %-10s :%-9s expected=%r actual=%r' % (kind, rng, token[:40], actual))

sys.exit(0 if bad == 0 else 1)
