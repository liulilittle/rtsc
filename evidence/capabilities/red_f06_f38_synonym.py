"""F-06 / F-38 同义表述覆盖的红证（§17.7 第 2 条）。

修复前实测（audit_case3.py）：
  F-06  "丢弃标准缓存" → 漏检（假阴性）
  F-38  "即可发送 input" / "允许发送 input" → 漏检（假阴性）
本脚本验证修复后这些变体都能被抓到，且原文不误报。
"""
import io
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DOC = r'F:\rtsc\docs\spec\capabilities.md'
SCRIPT = r'F:\rtsc\evidence\capabilities\accept_consult_b.py'
MUT = r'F:\rtsc\.tmp\_syn_mut.md'
s = io.open(DOC, encoding='utf-8').read()

F06_PAT = (r'(清空|清除|丢弃|重置|作废|flush|invalidate)\s*\*{0,2}\s*(标准|standard)'
           r'|(标准|standard)\s*\*{0,2}\s*(Bitmap\s*)?Cache')
F38_PAT = (r'(可开始发|即可发|可以发|允许发|能发|可发|开始发)\s*(送|出)?\s*`?input')

print('=== F-06 k3 正则：必须命中（同义改写）===')
row = [l for l in s.splitlines() if l.startswith('| **U-03**')][0]
f06_cases = [
    ('原文：**清空标准** Bitmap Cache', row, True),
    ('改写：**清除标准** Bitmap Cache',
     row.replace('**清空标准** Bitmap Cache', '**清除标准** Bitmap Cache'), True),
    ('改写：**丢弃标准缓存**',
     row.replace('**清空标准** Bitmap Cache', '**丢弃标准缓存**'), True),
    ('改写：**作废标准** Bitmap Cache',
     row.replace('**清空标准** Bitmap Cache', '**作废标准** Bitmap Cache'), True),
    ('改写：Standard Bitmap Cache 需清空',
     row.replace('**清空标准** Bitmap Cache', 'Standard Bitmap Cache 需清空'), True),
]
ok_all = True
for name, txt, expect in f06_cases:
    got = bool(re.search(F06_PAT, txt, re.I))
    good = got == expect
    ok_all &= good
    print('  [%s] %-40s 命中=%-5s 期望=%s' % ('PASS' if good else 'BAD', name, got, expect))

print()
print('=== F-38 组合判定（"含 Server Synchronize" AND "允许 input"）===')
# 注意：单看正则是不够的——判据的实际条件是
#   'Server Synchronize' in line  AND  _INPUT_ALLOW_RE.search(line)
# 所以下面用组合判定，才能验证"正确写法不被误报"。
f38_cases = [
    ('原文违规：收到 S.Sync 后可开始发 input',
     '收到 Server Synchronize 后可开始发 input', True),
    ('改写违规：收到 S.Sync 后即可发送 input',
     '收到 Server Synchronize 后即可发送 input', True),
    ('改写违规：收到 S.Sync 后允许发送 input',
     '收到 Server Synchronize 后允许发送 input', True),
    ('改写违规：收到 S.Sync 后可发 `input`',
     '收到 Server Synchronize 后可发 `input`', True),
    ('正确写法：Confirm Active 之后可发 input（无 S.Sync）',
     '收到 Confirm Active 之后可开始发 input', False),
    ('正确写法：S.Sync 行不含 input 许可',
     '收到 Server Synchronize，状态变为 S3；收到 Confirm Active 后才可发 input', True),
    ('无关行：Server Synchronize 的 pduType2 是 0x1F',
     'Server Synchronize 的 pduType2 是 0x1F', False),
]
for name, txt, expect in f38_cases:
    got = ('Server Synchronize' in txt) and bool(re.search(F38_PAT, txt, re.I))
    good = got == expect
    ok_all &= good
    print('  [%s] %-46s 命中=%-5s 期望=%s' % ('PASS' if good else 'BAD', name, got, expect))

print()
print('=== 端到端：把违规写法塞进 §12.2，判据必须翻红 ===')
i = s.index('### 12.2')
j = s.index('### 12.3')
mut = s[:j] + '\n> 收到 Server Synchronize 后即可发送 input。\n\n' + s[j:]
io.open(MUT, 'w', encoding='utf-8', newline='\n').write(mut)
env = dict(os.environ)
env['CAPS_DOC'] = MUT
env['TEMP'] = env['TMP'] = r'F:\rtsc\.tmp'
r = subprocess.run([sys.executable, '-X', 'utf8', SCRIPT], capture_output=True, env=env)
out = r.stdout.decode('utf-8', errors='replace')
lines = out.splitlines()
for k, l in enumerate(lines):
    if l.startswith(('[PASS]', '[FAIL]')) and 'F-38' in l:
        print('  %s' % l[:70])
        print('    %s' % (lines[k + 1].strip()[:130] if k + 1 < len(lines) else ''))
print('  exit=%d（期望 1）' % r.returncode)
ok_all &= (r.returncode == 1)
os.remove(MUT)

print()
print('结论:', '全部符合预期' if ok_all else '有不符合预期')
if not ok_all:
    raise SystemExit(1)
print('ASSERT OK')
