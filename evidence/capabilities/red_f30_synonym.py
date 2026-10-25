"""§17.7 第 2 条自检的红证：F-30 本体的"同义表述"覆盖。

原判据只认 '无 dump 佐证' / '缺 dump 佐证' 两个精确短语。
若执行 AI 改写成 "未见 dump" / "无官方 dump" / "缺乏 dump 支撑" 就整条漏检（假阴性）。
本测试验证新正则 _NO_DUMP_RE 对 8 种同义写法都命中，且对"正常行"不误命中。
"""
import io
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

SRC = r'F:\rtsc\evidence\capabilities\accept_consult_b.py'
src = io.open(SRC, encoding='utf-8').read()

start = src.index('_NO_DUMP_RE = re.compile(')
end = src.index('_bad30 = []')
block = src[start:end]
ns = {'re': re}
exec(block, ns)
rx = ns['_NO_DUMP_RE']
print('正则:', rx.pattern[:120].replace('\n', ' '))
print()

MUST_HIT = [
    '| 某项 | 无 dump 佐证 |',
    '| 某项 | 缺 dump 佐证 |',
    '| 某项 | 未见 dump |',
    '| 某项 | 无官方 dump |',
    '| 某项 | 缺乏 dump 支撑 |',
    '| 某项 | 无 dump |',
    '| 某项 | 仅有原文表比对 |',
    '| 某项 | 未取证 |',
]
MUST_MISS = [
    '| 21 类型 × 31 实例的长度 | 规范原文 + dump 反向匹配 31/31 通过 |',
    '| Font List / Font Map 均为 26 字节 | 规范原文 + dump 实测 26 字节 |',
    '| 项 | 核实方式 |',
    '| 28 个 capabilitySetType 的编号与名称 | 规范原文表（S08）逐行比对 |',
]

ok_all = True
print('--- 必须命中（同义表述变体）---')
for t in MUST_HIT:
    hit = bool(rx.search(t))
    ok_all &= hit
    print('[%s] %-46s hit=%s' % ('PASS' if hit else 'BAD', t[:44], hit))
print()
print('--- 必须不命中（正常行，防过宽）---')
for t in MUST_MISS:
    hit = bool(rx.search(t))
    ok_all &= (not hit)
    print('[%s] %-46s hit=%s' % ('PASS' if not hit else 'BAD', t[:44], hit))

print()
print('同义覆盖红证:', '全部符合预期' if ok_all else '有不符合预期')
if not ok_all:
    raise SystemExit(1)
print('ASSERT OK')
