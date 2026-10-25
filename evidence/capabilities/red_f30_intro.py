"""F-30「导语强度」判据的红证：三个变体必须分别 PASS / FAIL / FAIL。

不修改 capabilities.md —— 从 accept_consult_b.py 里**只抽取** WEAK/ABS 常量与
_judge_intro() 函数定义，单独 exec 后对 6 个用例求值。
"""
import io
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

SRC = r'F:\rtsc\evidence\capabilities\accept_consult_b.py'
src = io.open(SRC, encoding='utf-8').read()

start = src.index('WEAK = (')
end = src.index('_intro_lines = [')
block = src[start:end]
assert 'def _judge_intro' in block, '抽取失败：未包含 _judge_intro'

ns = {}
exec(block, ns)
_judge_intro = ns['_judge_intro']
print('抽取到常量:', ns['WEAK'], ns['ABS'])
print()

cases = [
    ('变体1 当前文档：削弱语「多数并辅以」+ 1 行无 dump',
     '以下各项**已用官方原文核实**（多数并辅以官方 dump 双向验证，逐行注明核实方式），可作确定事实使用：',
     [2516], True),
    ('变体2 绝对声明：无削弱语的「原文 + dump 双向核实」+ 1 行无 dump',
     '以下各项**已用官方原文 + dump 双向核实**，可作确定事实使用：',
     [2516], False),
    ('变体3 无强度词：「以下各项已核实：」+ 1 行无 dump',
     '以下各项已核实：',
     [2516], False),
    ('对照4 绝对声明 + 每行都有 dump',
     '以下各项**已用官方原文 + dump 双向核实**：',
     [], True),
    ('对照5 削弱语 + 每行都有 dump',
     '以下各项已核实（多数并辅以官方 dump 双向验证）：',
     [], True),
    ('对照6 无导语',
     '',
     [2516], True),
]

ok_all = True
for name, intro, rows, expect in cases:
    ok, reason = _judge_intro(intro, rows, True)
    good = (ok == expect)
    ok_all &= good
    print('[%s] %-54s ok=%-5s expect=%-5s  %s'
          % ('PASS' if good else 'BAD', name, ok, expect, reason))

v = [_judge_intro(c[1], c[2], True)[0] for c in cases[:3]]
print()
print('三变体红证结果: PASS=%s FAIL=%s FAIL=%s  -> %s'
      % (v[0], not v[1], not v[2],
         '符合预期' if (v[0] and not v[1] and not v[2]) else '不符合预期'))
print('全部 6 个用例符合预期:', ok_all)
if not ok_all:
    raise SystemExit(1)
print('ASSERT OK')
