#!/usr/bin/env python
# Final consistency gate (fixed: scoped to sections, not global indices).
import io, re

P = r'F:\rtsc\docs\spec\batch1-audit-a.md'
s = io.open(P, encoding='utf-8', newline='').read()
L = s.splitlines()

print('lines', len(L), 'bytes', len(s.encode('utf-8')), 'FFFD', s.count('\ufffd'))
print()

sec82 = s.split('### 8.2')[1].split('### 8.3')[0]
x1 = s.split('#### 交叉 1')[1].split('#### 交叉 2')[0]

i_branch = sec82.index('if (step_ == Step::kAwaitChallenge) {')
i_d2 = sec82.index('if (req.version < kMinVersion) {')
i_min = sec82.index('version_ = std::min(version_, req.version);')
i_bs3 = sec82.index('return BuildStep3(req, out);')

checks = [
    ('8.2 D2 在分支内', i_d2 > i_branch),
    ('8.2 min 在 D2 之后', i_min > i_d2),
    ('8.2 两者都在 BuildStep3 之前', i_min < i_bs3),
    ('8.2 标注 D2 也收窄', '`min` 与 D2 都只在协商点执行' in sec82),
    ('8.3 标注已收窄', '已收窄：只在 `kAwaitChallenge` 分支内' in s),
    ('12.6 已改为定案', '收窄后（最终定案）' in s),
    ('12.6 第4步version=1 标为"与修复前完全一致"',
     '第 4 步不检查版本）→ **与修复前完全一致**' in x1),
    ('8.8 锚点已改', '在该分支**内第一行**插入 D2 下界检查' in s),
    ('12.7 第22条存在', '| **22** |' in s),
    ('12.1b 窗口等价说明', '窗口偏移 `o ∈ [0, 16]`' in s),
    ('12.8 门槛=21', "rtsc_credssp_sm_tests'=21" in s),
    ('无旧门槛=20', "rtsc_credssp_sm_tests'=20" not in s),
    ('12.1b N-B1 用例名', 'client_nonce_does_not_disclose_session_key' in s),
    ('12.3b 收窄用例名', 'server_echo_version_does_not_downgrade' in s),
    ('13.6 已记录最终表态', '我对乙的第 3 点' in s),
]
ok = True
for n, v in checks:
    print(('PASS ' if v else 'FAIL ') + n)
    ok = ok and v

print()
print('ALL_CONSISTENT =', ok)
