"""Summarise aggregated unverified items, using the correct column semantics.

Three issues found and handled here (each was a real measuring error first):

1. TWO DIFFERENT TABLE SHAPES exist and must not be read alike:
     A) 甲编号 | 内容 | 我方状态 | 证据   -> column 3 IS a status
     B) #      | 内容 | 级别     | 说明   -> column 3 is a CONFIDENCE GRADE
   Reading B's grade as a status produced 70 bogus "未知" rows.

2. THE SOURCE ITSELF HAS 2 MALFORMED ROWS. In consult-b.md, two rows contain an
   unescaped `|` inside a backtick span:
       | L1e | 其他正则的锚点是否也有 `^` vs `(?:^ | ;)` 不一致 | B | ... |
       | M1d | `(?:^ | ; | :\\s)` 是否会误匹配...             | B | ... |
   A markdown table requires `\\|` there. Splitting on unescaped pipes is
   CORRECT; it exposes the source defect. Rows with >4 cells are rejoined by
   merging the middle cells, and the defect is reported (not silently fixed -
   consult-b.md must not be modified).

3. GRADE '—' MEANS "NOT APPLICABLE", NOT "UNKNOWN". 28 rows say the item is
   "不适用 / 由设计决定". Labelling those "未知" overstates risk.

Output keeps every item verbatim so any classification can be re-audited.
"""
import io
import json
import re
import sys
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

rows = json.load(io.open(r'F:\rtsc\evidence\tls\unverified-aggregate.json',
                         encoding='utf-8'))

GRADE_RE = re.compile(r'^[A-D]$')
CLOSED_PREFIX = ('已关闭', '已解决', '已确认', '已修复')


def normalise(r):
    """Rejoin rows whose content cell contained an unescaped pipe."""
    c = list(r['cells'])
    if len(c) > 4:
        c = [c[0], ' | '.join(c[1:-2]), c[-2], c[-1]]
    return c, len(r['cells']) > 4


def classify(r):
    c, rejoined = normalise(r)
    if r['header'] and r['header'][0] == '甲编号':
        raw = c[2].replace('*', '').strip()
        if raw.startswith(CLOSED_PREFIX):
            return '已关闭', '', raw, rejoined
        if raw.startswith('部分关闭'):
            return '部分关闭', '', raw, rejoined
        if raw.startswith('仍开'):
            return '仍开', '', raw, rejoined
        return '未知(%s)' % raw, '', raw, rejoined
    grade = c[2].replace('*', '').strip()
    if not GRADE_RE.match(grade):
        if grade in ('—', '-', '--', 'N/A'):
            return '不适用', '—', '', rejoined
        return '未知(grade=%r)' % grade, grade, '', rejoined
    return '未验证', grade, '', rejoined


out = []
malformed = []
for r in rows:
    state, grade, raw, rejoined = classify(r)
    if rejoined:
        malformed.append({'id': r['cells'][0], 'section': r['section'],
                          'raw_cells': r['cells']})
    out.append({
        'section': r['section'],
        'section_line': r['section_line'],
        'id': r['cells'][0],
        'content': normalise(r)[0][1],
        'state': state,
        'grade': grade,
        'raw_status': raw,
        'note': normalise(r)[0][3] if len(normalise(r)[0]) > 3 else '',
    })

stat = Counter(o['state'] for o in out)
grade = Counter(o['grade'] for o in out if o['grade'])

print('== status ==')
for k, v in stat.most_common():
    print('  %-12s %d' % (k, v))
print()
print('== confidence grade (shape B only) ==')
for k, v in sorted(grade.items()):
    print('  %-4s %d' % (k, v))
print()
print('== source rows with an unescaped pipe (defect in consult-b.md) ==')
for m in malformed:
    print('  %-5s %-24s cells=%s' % (m['id'], m['section'][:22], m['raw_cells']))
print()

open_items = [o for o in out if o['state'] in ('仍开', '未验证', '部分关闭')]
print('open / partially open: %d of %d' % (len(open_items), len(out)))
print('not applicable (—):    %d' % stat.get('不适用', 0))
print('closed:                %d' % stat.get('已关闭', 0))

io.open(r'F:\rtsc\evidence\tls\unverified-summary.json', 'w',
        encoding='utf-8', newline='').write(json.dumps({
            'items': out,
            'status_counts': dict(stat),
            'grade_counts': dict(grade),
            'source_defects': malformed,
        }, ensure_ascii=False, indent=2))
print()
print('wrote unverified-summary.json')
