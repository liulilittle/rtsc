"""对 pseudo_lint 做红证：人为注入每个缺陷，断言对应检查项必须翻红。

这是「检查器本身是否有效」的唯一验证方法（consult-b B14c 提出，我来落地）。
若某条注入后检查器不报，说明该检查项是空转的。
"""
import io
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DOC = r'F:\rtsc\docs\spec\tls-backend.design-a.md'
LINT = r'F:\rtsc\evidence\tls\pseudo_lint.py'
TMPD = r'F:\rtsc\.tmp'
ORIG = io.open(DOC, encoding='utf-8').read()


def run(text):
    p = os.path.join(TMPD, '_pl_case.md')
    io.open(p, 'w', encoding='utf-8', newline='').write(text)
    env = dict(os.environ, PYTHONIOENCODING='utf-8', TEMP=TMPD, TMP=TMPD)
    r = subprocess.run([sys.executable, LINT, '--file', p],
                       capture_output=True, env=env)
    out = r.stdout.decode('utf-8', errors='replace')
    ids = re.findall(r'^\[(FAIL|WARN)\]\s+(S\d+)', out, re.M)
    os.remove(p)
    return r.returncode, ids, out


def drop(pattern, repl=''):
    def f(s):
        if pattern not in s:
            raise SystemExit('ANCHOR-MISSING: %r' % pattern[:70])
        return s.replace(pattern, repl, 1)
    return f


def chain(*fs):
    def f(s):
        for g in fs:
            s = g(s)
        return s
    return f


# (标签, 期望命中的检查项, 变异函数)
CASES = [
    # S1 缺回边：删掉 B1 修复点那条 continue
    ('S1 缺回边', 'S1',
     drop('    continue                                      # B1：回到 loop，继续解缓冲里的下一条',
          '    # (continue removed by test)')),

    # S2 变量未定义：把 extra_len 的解包改回只返回状态
    ('S2 extra_len 无定义', 'S2',
     drop('    st, extra_len = backend_decrypt(record, tmp)  # B2：extra_len = Σ(EXTRA.cbBuffer)',
          '    st = backend_decrypt(record, tmp)')),

    # S3 Fail 不清空：删掉 Fail() 体内的 clear
    ('S3 Fail 无 clear', 'S3',
     drop('  plaintext_out.clear()                           # 整批丢弃，含错误前已解出的记录\n',
          '')),

    # S4 状态链无 else：删掉 if st == INTERNAL 块**和**其 else 兜底块
    #   （只删 if 会留下 dangling else，语义仍"有兜底"，无法模拟 B13；
    #     这是 design-a 加上 S4 兜底后本用例必须同步的地方）
    # 粗粒度：删掉整链末尾的 else 兜底（保持 elif 链完整）
    ('S4 删掉else兜底', 'S4',
     lambda s: s.replace(
         '    else:\n'
         '        return Fail(kInternal)                    # > [父会话 第⑨步 S4 / 第⑩步 D1]\n',
         '', 1)),

    # S5 章节逆序：把 3.4.2 标题改成 3.4.9（人为制造逆序）
    ('S5 章节逆序', 'S5',
     drop('#### 3.4.2 `Receive` 控制流自检', '#### 3.4.9 `Receive` 控制流自检')),

    # S6 出口表与代码不对账：删掉出口表一行
    #   （锚点用 E17 —— S4 兜底新增出口后 E16 已顺延为 E17）
    ('S6 出口表不对账', 'S6',
     drop('| E18 | L102 | **成功路径末尾 → `continue`**',
          '| E17x | L85 | **成功路径末尾 → `continue`**')),

    # S9 明文契约漏 kClosed 排除
    ('S9 漏 kClosed 排除', 'S9',
     drop('7. **`> [consult-b 修正 6 / 父会话 第⑧步 C4]` 失败路径的明文**：任何 `!= kOk`\n'
          '   **且 `!= kClosed`** 的返回之前必须 `plaintext.clear()`。\n'
          '   **`kClosed` 是例外**：它是正常终止，同一批里 close_notify 之前的应用数据必须保留给调用方\n'
          '   （见 §3.3 `kClosed` 行与 C3）。\n',
          '7. **失败路径的明文**：任何 `!= kOk` 的返回之前必须 `plaintext.clear()`。\n')),

    # S11 标题条数不符：把十二个改成十个
    ('S11 标题条数不符', 'S11',
     drop('#### 3.4.3 必须覆盖的十二个边界', '#### 3.4.3 必须覆盖的十个边界')),

    # S13 记录未消费：把 take_front 挪到状态分支之后（模拟 N1 原始形态）
    ('S13 记录未消费', 'S13',
     lambda s: s.replace(
         '    record = take_front(rx_buffer_, 5 + len)',
         '    record = _DEFERRED_', 1).replace(
         '    # ---- N3：EXTRA 用算术定位，不碰 pvBuffer ----',
         '    record = take_front(rx_buffer_, 5 + len)\n'
         '    # ---- N3：EXTRA 用算术定位，不碰 pvBuffer ----', 1)),

    # S14 循环内 clear：在循环体里插一条 plaintext_out.clear()
    ('S14 循环内 clear', 'S14',
     drop('    tmp.clear()\n',
          '    tmp.clear()\n    plaintext_out.clear()   # injected\n')),

    # S15 缺终止闩锁：删掉入口的 closed_ 与 terminal_ 检查
    ('S15 缺终止闩锁', 'S15',
     drop('  if closed_:                                     # B3：正常终止（close_notify 之后）\n'
          '      return kClosed                              #     必须恒返回 kClosed（§3.3 契约）\n'
          '  if terminal_:                                   # N7：错误终止闩锁\n'
          '      return last_error_\n', '')),

    # ---- consult-b 第⑨步 F1：S14 必须抓所有 plaintext_out 重置写法 ----
    ('S14 用赋值绕过', 'S14',
     drop('    tmp.clear()\n',
          '    tmp.clear()\n    plaintext_out = {}\n')),

    # ---- F3/F4：S12 语义反转必须被抓 ----
    ('S12 语义反转', 'S12',
     drop('**本方法不产生**，仅在 `Handshake` 已返回 `kUnsupported` 后经 `terminal_` **幂等返回**',
          '**本方法会产生**，`Handshake` 也可能返回 `kUnsupported`')),

    # ---- F5：新增 FailWarn() 不清空必须被抓 ----
    ('S3 新增FailWarn', 'S3',
     drop('Fail(status):',
          'FailWarn(status):\n'
          '  last_error_ = {status, last_native_code_, last_message_}\n'
          '  terminal_ = true\n'
          '  return last_error_\n'
          '\n'
          'Fail(status):')),

    # ---- P1：S1 不应把 `if True: continue` 误报（语义等价）----
    ('S1 等价ifTrue', 'S1',
     drop('    continue                                      # B1：回到 loop，继续解缓冲里的下一条',
          '    if True:\n        continue'), True),

    # ---- S11 二十 中文数字 ----
    ('S11 二十', 'S11',
     drop('#### 3.4.3 必须覆盖的十二个边界', '#### 3.4.3 必须覆盖的二十个边界')),

    # ---- S10 重复编号 ----
    ('S10 重复编号', 'S10',
     drop('#### 3.4.3 必须覆盖的十二个边界', '#### 3.4.2 必须覆盖的十二个边界')),

    # ---- consult-b 第⑧步 注入 C：保留 else 但把 elif 链打断成独立 if ----
    # 这是真实缺陷的细粒度形态（不是"删掉整块"），S4 必须能抓到。
    ('S4 else绑错对象', 'S4',
     lambda s: s.replace('    elif st == RENEGOTIATE:', '    if st == RENEGOTIATE:', 1)
                .replace('    elif st == NO_RENEGOTIATION:', '    if st == NO_RENEGOTIATION:', 1)
                .replace('    elif st == CONTEXT_EXPIRED:', '    if st == CONTEXT_EXPIRED:', 1)
                .replace('    elif st in {ALTERED, DECRYPT_FAILURE}:', '    if st in {ALTERED, DECRYPT_FAILURE}:', 1)
                .replace('    elif st == PEER_ALERT:', '    if st == PEER_ALERT:', 1)
                .replace('    elif st == INTERNAL:', '    if st == INTERNAL:', 1)
                .replace('    elif st == OK:', '    if st == OK:', 1)),

    # ---- S2 改名绕过：删掉成员声明，断言 S2 必须翻红 ----
    ('S2 删成员声明', 'S2',
     drop('int32_t     last_native_code_ = 0;\n', '')),

    # ---- 等价改写不得翻红（consult-a 第⑨步：S6 两个错误互相抵消的假绿）----
    # 这三条断言的期望是"不翻红"（neg=True），与上面的"注入缺陷必须翻红"相反。
    # 若工具在语义等价改写上翻红，说明它数的量不是"出口数"。
    ('S6 等价:行内return拆行', 'S6',
     drop('        closed_ = true; return kClosed',
          '        closed_ = true\n        return kClosed'), True),

    ('S6 等价:删Fail内return', 'S6',
     lambda s: s.replace('  terminal_ = true', '  terminal_ = true  # keep', 1)
                .replace('  return last_error_\n```', '  pass\n```', 1), True),

    # S12 kUnsupported 无 Receive 契约行：删掉该行
    ('S12 缺 Receive 行', 'S12',
     lambda s: s.replace('| `Handshake` | `kUnsupported` |',
                         '| `Handshake` | `kUnsupported-x` |', 1)
     if '| `Receive` | `kUnsupported` |' not in s
     else s.replace('| `Receive` | `kUnsupported` |',
                    '| `Receive-x` | `kUnsupported` |', 1)),
]


def main():
    rc0, ids0, out0 = run(ORIG)
    base = {i for _, i in ids0}
    print('基线：exit=%d  命中=%s' % (rc0, sorted(base)))
    print()

    ok = 0
    n_skip = 0
    for case in CASES:
        label, want, mut = case[0], case[1], case[2]
        neg = case[3] if len(case) > 3 else False
        try:
            txt = mut(ORIG)
        except SystemExit as e:
            # SKIP 计为失败：锚点失效说明文档结构与红证脱节，
            # 而"跳过"最容易被误读成"通过"（consult-b 第⑧步）。
            print('[BAD] %-24s 锚点失效（必须修，不得跳过）：%s' % (label, e))
            n_skip += 1
            continue
        rc, ids, out = run(txt)
        hit = want in {i for _, i in ids}
        good = (not hit) if neg else hit
        ok += 1 if good else 0
        print('[%s] %-24s 期望=%-4s%s 翻红=%-5s exit=%d'
              % ('PASS' if good else 'BAD', label, want,
                 '(不得)' if neg else '', hit, rc))
        if not good:
            print('        实际命中=%s' % sorted({i for _, i in ids}))
            for line in out.split('\n'):
                if 'TOTAL' in line or 'Traceback' in line:
                    print('        ' + line)

    print()
    print('红证：%d/%d 注入被正确检出%s'
          % (ok, len(CASES), ('（锚点失效 %d）' % n_skip) if n_skip else ''))
    if ok != len(CASES):
        raise SystemExit(1)
    print('ASSERT OK')


if __name__ == '__main__':
    main()
