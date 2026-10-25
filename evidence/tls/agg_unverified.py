"""Aggregate every "新增未验证项" table scattered across consult-b.md.

consult-b step 21 §4(c): these items live in 17 different sections and nothing
aggregates them. Un-aggregated, "known unverified" silently becomes
"unknown unknown". This script extracts them mechanically so the summary cannot
drift from the source (hand-copying 100+ rows would guarantee drift).
"""
import io
import json
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

SRC = r'F:\rtsc\docs\spec\tls-backend.consult-b.md'
OUT = r'F:\rtsc\evidence\tls\unverified-aggregate.json'

t = io.open(SRC, encoding='utf-8').read()
lines = t.split('\n')

# find headings
heads = [(i, l) for i, l in enumerate(lines)
         if re.match(r'^#{2,4}\s', l) and ('未验证' in l)]

print('sections with 未验证:', len(heads))
for i, h in heads:
    print('  line %d: %s' % (i + 1, h.strip()))

SPLIT = re.compile(r'(?<!\\)\|')


def cells(row):
    return [c.strip() for c in SPLIT.split(row.strip().strip('|'))]


rows_all = []
for idx, (start, heading) in enumerate(heads):
    end = heads[idx + 1][0] if idx + 1 < len(heads) else len(lines)
    section = lines[start:end]
    # the table may be followed by prose; take the contiguous table block
    block = []
    in_table = False
    for l in section:
        s = l.strip()
        if s.startswith('|'):
            in_table = True
            block.append(s)
        elif in_table:
            if s == '':
                continue
            break
    if not block:
        continue
    header = cells(block[0])
    for r in block[1:]:
        c = cells(r)
        if set(''.join(c)) <= set('-: '):
            continue
        rows_all.append({
            'section': heading.strip('# ').strip(),
            'section_line': start + 1,
            'ncols': len(c),
            'cells': c,
            'header': header,
        })

print()
print('total table rows collected:', len(rows_all))
from collections import Counter
print('ncols distribution:', Counter(r['ncols'] for r in rows_all))
print('header shapes:', Counter('|'.join(r['header']) for r in rows_all).most_common(5))

io.open(OUT, 'w', encoding='utf-8', newline='').write(
    json.dumps(rows_all, ensure_ascii=False, indent=2))
print('wrote', OUT)
print()
for r in rows_all[:8]:
    print('  [%s] %s' % (r['section'][:28], ' | '.join(r['cells'])[:130]))
