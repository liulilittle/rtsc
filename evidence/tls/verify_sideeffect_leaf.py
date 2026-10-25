"""G8 验收：同行 `;` 写法必须与两行写法等价。

consult-b 第⑭步 G8：`pass`/`continue` 用 `^\\s*`（行首），`return` 用 `(?:^|;)`，
导致 `closed_ = true; pass`（同行）漏检 —— 而伪代码 :650 自己就用同行 `;` 写法。
"""
import importlib.util
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

spec = importlib.util.spec_from_file_location(
    'vem', r'F:\rtsc\evidence\tls\verify_elif_semantics.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# (标签, code_lines, 期望)
CASES = [
    # ---- 乙给的验收三条 ----
    ('A1 同行: closed_=true; pass',
     ['        closed_ = true; pass'], ('RET', 'closed_flag_with_pass')),
    ('A2 同行: closed_=true; continue',
     ['        closed_ = true; continue'], ('RET', 'closed_flag_with_continue')),
    ('A3 同行: x = 1; continue',
     ['        x = 1; continue'], ('CONT_SKIP', None)),

    # ---- 回归：两行写法必须仍对 ----
    ('R1 两行: closed_=true / pass',
     ['        closed_ = true', '        pass'], ('RET', 'closed_flag_with_pass')),
    ('R2 两行: closed_=true / continue',
     ['        closed_ = true', '        continue'], ('RET', 'closed_flag_with_continue')),
    ('R3 两行: closed_=true / return kClosed',
     ['        closed_ = true', '        return kClosed'], ('RET', 'kClosed')),
    ('R4 同行: closed_=true; return kClosed',
     ['        closed_ = true; return kClosed'], ('RET', 'kClosed')),

    # ---- 原有 5 个用例（L1b 回归）----
    ('O1 return kClosed（无 flag）',
     ['        return kClosed'], ('RET', 'kClosed_WITHOUT_FLAG')),
    ('O2 closed_=true; return kOk',
     ['        closed_ = true; return kOk'], ('RET', 'kOk_WITH_CLOSED_FLAG')),
    ('O3 pass（无 flag）',
     ['        pass'], (m.FALLTHROUGH_OK, None)),
    ('O4 continue（无 flag）',
     ['        continue'], (m.CONT_SKIP, None)),

    # consult-b 第⑭步 Q3：closed_ + continue 是矛盾（关闭后继续推进状态机）
    ('Q3a 同行: closed_=true; continue',
     ['        closed_ = true; continue'], ('RET', 'closed_flag_with_continue')),
    ('Q3b 两行: closed_=true / continue',
     ['        closed_ = true', '        continue'], ('RET', 'closed_flag_with_continue')),

    # ---- consult-b 第⑮步 G10：内联 if 写法（`(?:^|;)` 漏检）----
    ('G10a 内联: if x: return kClosed（无flag）',
     ['        if x: return kClosed'], ('RET', 'kClosed_WITHOUT_FLAG')),
    ('G10b 内联: if x: closed_ = true; return kClosed',
     ['        if x: closed_ = true; return kClosed'], ('RET', 'kClosed')),
    ('G10c 内联: if x: return kOk',
     ['        if x: return kOk'], ('RET', 'kOk')),
    ('G10d 内联: if x: pass',
     ['        if x: pass'], (m.FALLTHROUGH_OK, None)),
    ('G10e 内联: if x: continue',
     ['        if x: continue'], (m.CONT_SKIP, None)),
    ('G10f 内联: if x: closed_ = true; pass',
     ['        if x: closed_ = true; pass'], ('RET', 'closed_flag_with_pass')),

    # ---- 带注释的同行写法（乙的 C 用例）----
    ('C1 同行+注释: closed_=true; pass # x',
     ['        closed_ = true; pass  # x'], ('RET', 'closed_flag_with_pass')),
]

ok = 0
for label, lines, want in CASES:
    got = m._classify_leaf(lines)
    hit = (got == want)
    ok += 1 if hit else 0
    print('[%s] %-42s got=%-30s want=%s'
          % ('PASS' if hit else 'BAD', label, got, want))

print()
print('G8 验收：%d/%d' % (ok, len(CASES)))
if ok != len(CASES):
    raise SystemExit(1)
print('ASSERT OK（同行 `;` 与两行写法完全等价）')
