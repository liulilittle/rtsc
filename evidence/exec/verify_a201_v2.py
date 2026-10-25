"""Independent verification of the A20-1 repair (v2).

Adds one category the v1 verifier lacked: RECORD citations.

Some line-number references exist to *describe a past defect* ("doc:1523 used to
say :242, it should be :244"). Those must keep the OLD number, otherwise the
record of what was wrong disappears. They are not navigation targets and must not
be repaired. v1 counted them as "missing anchor", which is technically true but
not a defect.
"""
import io
import re
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
SRC = r'F:\rtsc\src\net\tls_schannel.cpp'

src = io.open(SRC, encoding='utf-8').read().splitlines()
doc = io.open(DOC, encoding='utf-8').read()

CITE = re.compile(
    r'`(?:src/net/)?tls_schannel\.cpp:(\d+)(?:-(\d+))?`'
    r'(?:（(?:批 0 后；)?锚点 `([^`]*)`）)?')
MOVED = re.compile(r'`src/net/tls_factory\.cpp`（批 0 搬迁：([^）]*)）')

# A line is a RECORD citation if it describes a past/incorrect value.
RECORD_MARKERS = ('应为', '应为 `:', 'used to', '曾经', '原引用', '遗留')

ok = bad = noanchor = moved = record = 0
problems = []

for m in CITE.finditer(doc):
    # find the line this match sits on
    line_start = doc.rfind('\n', 0, m.start()) + 1
    line_end = doc.find('\n', m.end())
    line = doc[line_start: line_end if line_end != -1 else len(doc)]

    if any(k in line for k in RECORD_MARKERS):
        record += 1
        continue

    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else None
    anchor = m.group(3)
    if anchor is None:
        noanchor += 1
        problems.append(('NOANCHOR', start, end, '', line.strip()[:70]))
        continue
    token = anchor.split('(')[0].split('..')[0].strip()
    token = ' '.join(token.split())
    if not token or token == 'None':
        bad += 1
        problems.append(('BADANCHOR', start, end, anchor, ''))
        continue
    span = src[start - 1: (end if end else start)]
    if any(token in ' '.join(l.split()) for l in span):
        ok += 1
    else:
        bad += 1
        actual = src[start - 1].strip()[:60] if start - 1 < len(src) else '<EOF>'
        problems.append(('MISMATCH', start, end, token, actual))

for _ in MOVED.finditer(doc):
    moved += 1

print('=== A20-1 independent verification (v2) ===')
print('anchored citations, verified OK :', ok)
print('anchored citations, MISMATCH    :', bad)
print('navigation citations w/o anchor :', noanchor)
print('record citations (must keep old):', record)
print('moved-to-factory citations      :', moved)
print()
if problems:
    print('=== details ===')
    for kind, start, end, token, extra in problems:
        rng = '%d-%d' % (start, end) if end else str(start)
        print('  %-10s :%-9s expected=%r %r' % (kind, rng, token[:40], extra[:50]))

sys.exit(0 if bad == 0 and noanchor == 0 else 1)
