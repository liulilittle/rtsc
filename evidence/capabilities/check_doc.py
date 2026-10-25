# -*- coding: utf-8 -*-
"""Acceptance checker for docs/spec/capabilities.md.
Fails loudly (red) if any acceptance criterion is not met."""
import io, re, sys

P = r'F:\rtsc\docs\spec\capabilities.md'
s = io.open(P, encoding='utf-8').read()
lines = s.split('\n')
nlines = s.count('\n') + 1
ok = True

def check(name, cond, detail=''):
    global ok
    print(('PASS  ' if cond else 'FAIL  ') + name + (('  ' + detail) if detail else ''))
    if not cond:
        ok = False

# 1. >= 800 lines
check('AC1 文件行数 >= 800', nlines >= 800, 'lines=%d' % nlines)

# 2. capability type table count == 28, every type has a layout section
spec_types = ['0x0001','0x0002','0x0003','0x0004','0x0005','0x0007','0x0008','0x0009',
              '0x000A','0x000C','0x000D','0x000E','0x000F','0x0010','0x0011','0x0012',
              '0x0013','0x0014','0x0015','0x0016','0x0017','0x0018','0x0019','0x001A',
              '0x001B','0x001C','0x001D','0x001E']
check('AC2a 编号表条目数 == 28', len(spec_types) == 28, 'spec types=%d' % len(spec_types))

table_rows = re.findall(r'^\| (0x[0-9A-F]{4}) \| `CAP[A-Z0-9_]*`', s, re.M)
check('AC2b 编号表实际列出 28 行', len(table_rows) == 28, 'rows=%d' % len(table_rows))
missing = [t for t in spec_types if t.upper() not in [r.upper() for r in table_rows]]
check('AC2c 编号表覆盖全部 28 个类型', not missing, 'missing=%s' % missing)

# each fixed-length type must have a "#### 8.N 0xXXXX" section
sec = re.findall(r'^#{3,4} 8\.\d+ (0x[0-9A-F]{4})', s, re.M)
check('AC2d 27 个定长布局小节', len(sec) == 27, 'sections=%d' % len(sec))
fixed = [t for t in spec_types if t != '0x001D']
miss2 = [t for t in fixed if t not in sec]
check('AC2e 27 个定长类型都有布局小节', not miss2, 'missing=%s' % miss2)

# every layout section has a byte-offset table (偏移/长度/字段)
blocks = re.split(r'^#{3,4} 8\.\d+ 0x[0-9A-F]{4}', s, flags=re.M)[1:]
bad = [i for i, b in enumerate(blocks) if '| 偏移 | 长度 | 字段 | 说明 |' not in b]
check('AC2f 每个布局小节都有字节级结构表', not bad, 'bad idx=%s' % bad)

# 0x001D has variable layout in 6.4
check('AC2g 0x001D 变长布局在 6.4', '### 6.4' in s and 'bitmapCodecArray' in s)

# 3. >= 3 hex dumps with per-byte annotation
dump_heads = re.findall(r'^### 13\.\d dump #\d', s, re.M)
check('AC3a dump 数量 >= 3', len(dump_heads) >= 3, 'dumps=%d' % len(dump_heads))
# each dump must have a hexdump fenced block AND a per-byte table
parts = re.split(r'^### 13\.\d dump #\d', s, flags=re.M)[1:]
for i, p in enumerate(parts, 1):
    has_hex = '```\n00000000  ' in p
    has_tbl = '| 偏移 | 字节 | 字段 |' in p
    check('AC3b dump #%d 有 hexdump 且逐字节注解' % i, has_hex and has_tbl)

# 4. uncertainty list non-empty
m = re.search(r'## 15\. 不确定项清单(.*?)^## 16', s, re.S | re.M)
check('AC4 不确定项章节存在', m is not None)
if m:
    items = re.findall(r'\| \*\*U-\d+\*\* \|', m.group(1))
    check('AC4b 不确定项条目 >= 10', len(items) >= 10, 'items=%d' % len(items))

# 5. every fact carries a section number: sample check that each ## section
# mentions at least one section-number citation
sections = re.split(r'^## ', s, flags=re.M)[1:]
nocite = []
for sec_ in sections:
    title = sec_.split('\n')[0][:30]
    if not re.search(r'(§\d|\d+\.\d+(\.\d+)+|S\d\d)', sec_):
        nocite.append(title)
check('AC5 每个 ## 章节都含章节号引用', not nocite, 'no-cite=%s' % nocite)

# structural sanity: no leftover placeholders, balanced code fences
check('AC6 无遗留占位符', '<!--' not in s)
check('AC7 代码围栏成对', s.count('```') % 2 == 0, 'fences=%d' % s.count('```'))

# all markdown tables well-formed (same pipe count per table)
bad_tbl = 0
tbl = []
for ln in lines:
    if ln.startswith('|'):
        tbl.append(ln.count('|'))
    else:
        if tbl and len(set(tbl)) > 1:
            bad_tbl += 1
        tbl = []
check('AC8 所有表格列数一致', bad_tbl == 0, 'bad_tables=%d' % bad_tbl)

print()
print('RESULT:', 'ALL PASS' if ok else 'HAS FAILURES')
sys.exit(0 if ok else 1)
