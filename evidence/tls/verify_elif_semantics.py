"""把 design-a 的 Receive 状态分派翻译成可执行语义，逐状态断言期望行为。

**为什么这个脚本必须自带变异自测**（consult-b 第⑨步 E1）：
上一版有两个致命缺陷，导致它对 4/5 个真实缺陷都报 PASS：
  1. `if kw == 'else': return ('RET','kInternal')` —— **硬编码**，从不读 else 的 body。
     于是「else 体改成 pass（未知状态落空到成功路径）」这种 D1 复发被漏检。
  2. 断言 `ok = not (act=='RET' and status=='kInternal' and st=='OK')` —— **只判一件事**。
     「elif st == OK: return Fail(kProtocolError)」（所有正常数据变错误）被漏检。

现在改为：
  * else 分支**读 body** 提取 `Fail(kXxx)` / `pass` / `continue`
  * 断言用**逐状态 EXPECT 字典**，任何一项不符即失败
  * 自带 5 个变异自测（MUT1-MUT5），每个都必须被检出

用法：
    python verify_elif_semantics.py                 # 验证 design-a.md
    python verify_elif_semantics.py --file X.md     # 验证任意文档
    python verify_elif_semantics.py --no-selftest   # 只验证，不跑变异自测
"""
import argparse
import io
import os
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DEFAULT_DOC = r'F:\rtsc\docs\spec\tls-backend.design-a.md'

# 逐状态期望：st -> (action, status)
# action: 'CONT'（落到成功路径/回边）或 'RET'（返回）
# 行为分类（consult-b 第⑩步 G2）：
#   CONT_SKIP        = continue，回到循环顶，**丢弃本轮明文**
#   FALLTHROUGH_OK   = pass，**继续往下**，会执行 plaintext_out += tmp
#   RET              = 返回
# 二者绝不可混为一谈：pass→continue 会让所有正常数据被静默丢弃。
CONT_SKIP = 'CONT_SKIP'
FALLTHROUGH_OK = 'FALLTHROUGH_OK'

EXPECT = {
    'OK':                 (FALLTHROUGH_OK, None),
    'INCOMPLETE':         ('RET', 'kProtocolError'),
    'RENEGOTIATE':        (CONT_SKIP, None),           # 默认 TLS1.3：喂回 ISC 后 continue
    'NO_RENEGOTIATION':   (CONT_SKIP, None),
    'CONTEXT_EXPIRED':    ('RET', 'kClosed'),
    'ALTERED':            ('RET', 'kDecryptFailed'),
    'DECRYPT_FAILURE':    ('RET', 'kDecryptFailed'),
    'PEER_ALERT':         ('RET', 'kPeerAlert'),
    'INTERNAL':           ('RET', 'kInternal'),
    'BOGUS':              ('RET', 'kInternal'),        # 未知状态必须兜底
}


def extract_pseudocode(doc_text):
    """抽出含 Receive( 的伪代码块，返回 (行列表, 该块起始文件行号 1-based)。"""
    L = doc_text.split('\n')
    for i, l in enumerate(L):
        if l.strip().startswith('```'):
            j = i + 1
            while j < len(L) and not L[j].strip().startswith('```'):
                j += 1
            blk = L[i + 1:j]
            if any(re.match(r'^Receive\(', b) for b in blk):
                return blk, i + 2
    raise SystemExit('未找到含 Receive( 的伪代码块')


def split_at_fail(body):
    """切掉 Fail() 辅助函数定义，只留 Receive 主体。"""
    for k, b in enumerate(body):
        if b.strip().startswith('Fail('):
            return body[:k]
    return body


def parse_chain(body):
    """解析最外层 if/elif/else 链，返回 [(kw, cond, body_lines)]。"""
    entries = []
    for k, b in enumerate(body):
        m = re.match(r'^(\s*)(if|elif|else)\b(.*?):\s*$', b)
        if not m:
            continue
        entries.append((k, len(m.group(1)), m.group(2), m.group(3).strip()))
    if not entries:
        return []
    # 只看 **以 st 开头**的 if/elif + 紧随其后的 else。
    # 必须用 re.match(r'^st\b')，不能用 'st' in cond ——
    # 后者会把 `if best_len > 0:` / `if last_st > 0:` 这类无关 if 拉进链
    # （consult-b 第⑫步 Q1 实测：会 raise UnsupportedCond 判死合法文档）。
    cand = [(k, ind, kw, cond) for k, ind, kw, cond in entries
            if (kw in ('if', 'elif') and re.match(r'^st\b', cond)) or kw == 'else']
    if not cand:
        return []
    top = min(ind for _, ind, _, _ in cand if _ != 'else' or True)
    # 取最外层那一组（含 st 的）
    outer = [(k, kw, cond) for k, ind, kw, cond in cand if ind == top]

    chain = []
    for idx, (k, kw, cond) in enumerate(outer):
        # 分支体 = 后续缩进 > 该分支缩进的行。
        # 不能简单用"到下一个分支为止"——链末分支之后还有成功路径，
        # 那不属于任何分支（consult-b 第⑩步：else 只含 return Fail(kInternal)）。
        seg = _branch_body(body, k, top)
        chain.append((kw, cond, seg))
    return chain


class UnsupportedCond(Exception):
    pass


def match_cond(cond, st):
    """解析 `st <op> X` 形式。**不认识的写法必须 raise，不能猜。**

    consult-b 第⑪步 Q1(1)：旧实现只做子串匹配
        if 'INCOMPLETE' in cond: return st == 'INCOMPLETE'
    于是 `st == X` 改成 `st != X` 后 cond 里仍含 X，照样返回 st == X
    → 7 个运算符变异全部漏检（G1 的第三次同型复发）。

    现在只接受三种形式，其余 raise：
        st == NAME
        st != NAME
        st in {A, B, ...}
    """
    if not cond:
        return True                                   # else
    c = cond.strip()

    m = re.match(r'^st\s+in\s*\{(.*)\}$', c)
    if m:
        members = {x.strip() for x in m.group(1).split(',') if x.strip()}
        return st in members

    m = re.match(r'^st\s*(==|!=)\s*(\w+)$', c)
    if m:
        eq = (st == m.group(2))
        return eq if m.group(1) == '==' else (not eq)

    raise UnsupportedCond('match_cond: 不支持的条件表达式 %r' % c)


def eval_inner_cond(cond, tls13):
    """解析内层条件 `X <op> Y`。**不认识必须 raise。**

    consult-b 第⑪步 Q1(2)：旧实现
        if 'tls_version' in inner_cond and '0x0304' in inner_cond: truth = tls13
    把 `==` 改成 `!=` / `>=` 后两个子串仍在 → 仍返回 tls13 → 语义反转不可见。
    """
    c = cond.strip()

    m = re.match(r'^negotiated\.tls_version\s*(==|!=|>=|<=|>|<)\s*(0x[0-9a-fA-F]+)$', c)
    if m:
        op, lit = m.group(1), int(m.group(2), 16)
        actual = 0x0304 if tls13 else 0x0303
        return {'==': actual == lit, '!=': actual != lit,
                '>=': actual >= lit, '<=': actual <= lit,
                '>': actual > lit, '<': actual < lit}[op]

    m = re.match(r'^(True|False|1|0)$', c)
    if m:
        return m.group(1) in ('True', '1')

    raise UnsupportedCond('eval_inner_cond: 不支持的条件表达式 %r' % c)


def _dedent(lines):
    """去掉公共缩进，便于按相对层级解析嵌套。"""
    real = [l for l in lines if l.strip() and not l.strip().startswith('#')]
    if not real:
        return lines
    base = min(len(l) - len(l.lstrip(' ')) for l in real)
    return [l[base:] if len(l) >= base else l for l in lines]


def _branch_body(lines, idx, ind):
    """取 idx 行（缩进 ind）的块体：后续缩进 > ind 的行。"""
    out = []
    for l in lines[idx + 1:]:
        if not l.strip():
            continue
        if len(l) - len(l.lstrip(' ')) <= ind:
            break
        out.append(l)
    return out


def _classify_leaf(code_lines):
    """对一段**不含嵌套分支**的代码判定行为。

    consult-b 第⑪步 Q1(3)：只建模控制流、不建模副作用，会让
    「删掉 `closed_ = true` 只留 `return kClosed`」完全不可见
    → 后续 Receive 继续读已关闭连接（B3/N7 复发）。
    因此 `return kClosed` 必须同时置 `closed_ = true`，否则判为 BAD_CLOSED。

    **适用边界（consult-b 第⑯步 Q2/Q3）**：本函数假定输入是**伪代码语句序列**，
    不是完整 C++。语句分隔符识别为 `行首` / `;` / `内联 if 的 ": "`（即 `(?:^|;|:\s)`）。
    因此以下写法**不被支持**，若出现在输入里会产生误判：
      * `case X:` 标签、`label:` 标签
      * 初始化列表 `{a: b}`、类型标注 `int x: ...`
      * 三元 `cond ? a : b` 作为语句分隔（行首 return 会先命中，故当前无害）
    当前伪代码块（design-a §3.4.1）实测 `case`=0 / `label`=0 / 初始化=0，
    三元 2 处均在行首 return 之后，故不触发。**新增写法前请先扫这三类。**
    结构化切分是更彻底的方案，但当前收益不足以证明重构成本（影响 24 个用例）。

    **死代码说明（consult-b 第⑯步 Q3 / G11）**：输入含死代码时
    （如 `return X; continue`），返回的标签反映**检查顺序**而非源码顺序，
    因此可能指向永不执行的那条语句。这不影响"是否检出矛盾"，
    只影响诊断可读性。真正的死代码问题应由独立检查器负责。
    """
    txt = '\n'.join(l.split('#')[0] for l in code_lines)

    # 副作用检查（双向 + pass 覆盖），consult-b 第⑬步 Q4 验收：
    #   * return kClosed 但未置 closed_ = true  → 后续 Receive 继续读已关连接
    #   * 置了 closed_ = true 却 return kOk      → 关了却报成功（违反 C3/C4）
    #   * 置了 closed_ = true 却 pass            → 标记已关却继续当成功处理（落到累加明文）
    # 第三条是 consult-b 实测的真盲区：`closed_=true; pass` 在 OK 分支 rc=0。
    has_close_flag = re.search(r'closed_\s*=\s*true', txt) is not None
    if re.search(r'(?:^|;|:\s)\s*return\s+kClosed', txt, re.M) and not has_close_flag:
        return ('RET', 'kClosed_WITHOUT_FLAG')
    if has_close_flag and re.search(r'(?:^|;|:\s)\s*return\s+kOk', txt, re.M):
        return ('RET', 'kOk_WITH_CLOSED_FLAG')
    if has_close_flag and re.search(r'(?:^|;|:\s)\s*pass\b', txt, re.M):
        return ('RET', 'closed_flag_with_pass')
    if has_close_flag and re.search(r'(?:^|;|:\s)\s*continue\b', txt, re.M):
        return ('RET', 'closed_flag_with_continue')

    m = re.search(r'Fail\w*\s*\(\s*(k\w+)\s*\)', txt)
    if m:
        return ('RET', m.group(1))
    m = re.search(r'(?:^|;|:\s)\s*return\s+(k\w+)', txt, re.M)
    if m:
        return ('RET', m.group(1))
    if re.search(r'(?:^|;|:\s)\s*return\b', txt, re.M):
        return ('RET', '<unknown>')
    if re.search(r'(?:^|;|:\s)\s*continue\b', txt, re.M):
        return (CONT_SKIP, None)
    if re.search(r'(?:^|;|:\s)\s*pass\b', txt, re.M):
        return (FALLTHROUGH_OK, None)
    return None                            # 无叶子语句（可能只有嵌套）


def interpret_segment(seg, cond, tls13):
    """从一个分支的 body 提取行为。

    **不硬编码任何分支的行为**（consult-b 第⑩步 G1：上一版对 RENEGOTIATE
    硬编码 `if tls13: CONT else: kProtocolError`，导致 6 个变异漏检）。

    做法：递归解析 body 里的内层 if/else。
      * 若无内层分支 → 直接按叶子语句判定
      * 若有内层 `if <条件>:` / `else:` → 按 tls13 选分支后递归
    """
    lines = _dedent(seg)

    # 找第一个内层 if（用于 RENEGOTIATE 的 tls_version 分支等）
    for k, l in enumerate(lines):
        m = re.match(r'^(\s*)if\s+(.+?):\s*$', l)
        if not m:
            continue
        ind = len(m.group(1))
        inner_cond = m.group(2)
        then_body = _branch_body(lines, k, ind)

        # 找与之配对的 else
        else_body = []
        for j in range(k + 1 + len(then_body), len(lines)):
            if re.match(r'^\s*else\s*:\s*$', lines[j]):
                else_body = _branch_body(lines, j, ind)
                break
            if lines[j].strip() and len(lines[j]) - len(lines[j].lstrip(' ')) <= ind:
                break

        # 求值内层条件（运算符由 eval_inner_cond 解析；不认识会 raise）
        truth = eval_inner_cond(inner_cond, tls13)

        chosen = then_body if truth else else_body
        leaf = _classify_leaf(chosen)
        if leaf is not None:
            return leaf
        # 分支体里还有嵌套 → 递归
        return interpret_segment(chosen, cond, tls13)

    # 无内层分支：直接判定
    leaf = _classify_leaf(lines)
    if leaf is not None:
        return leaf
    return (FALLTHROUGH_OK, None)          # 空体：继续往下（等价 pass）


def evaluate(chain, st, tls13=True):
    for kw, cond, seg in chain:
        if match_cond(cond, st):
            return interpret_segment(seg, cond, tls13)
    return ('FALLTHROUGH', None)           # 链无兜底


def analyze(doc_text, verbose=True):
    body, base = extract_pseudocode(doc_text)
    body = split_at_fail(body)
    chain = parse_chain(body)
    if not chain:
        raise SystemExit('未解析出状态分派链')

    if verbose:
        print('=== 状态分派链（%d 项，伪代码起始文件行 %d）===' % (len(chain), base))
        for kw, cond, _ in chain:
            print('  %-5s %s' % (kw, cond or '(兜底)'))

    results = {}
    for st in EXPECT:
        act, status = evaluate(chain, st)
        results[st] = (act, status)

    if verbose:
        print()
        print('=== 逐状态求值 vs 期望 ===')
        for st in EXPECT:
            got = results[st]
            want = EXPECT[st]
            ok = (got == want)
            print('  st=%-20s got=%-6s %-16s want=%-6s %-16s %s'
                  % (st, got[0], got[1] or '-', want[0], want[1] or '-',
                     'OK' if ok else '*** MISMATCH ***'))

    bad = [st for st in EXPECT if results[st] != EXPECT[st]]

    # ---- TLS1.2 专项 ----
    # 只测 1.3 会让 1.2 分支的变异完全不可见（consult-b 第⑩步 G1c）。
    # consult-b 第⑪步 Q2 又发现：NO_RENEGOTIATION 在 1.2 下也不应静默 continue
    #   —— 该码仅 TLS1.3 出现（probe24 实测），1.2 收到即协议违规。
    EXPECT_R12 = {
        'RENEGOTIATE':      ('RET', 'kProtocolError'),   # RDP 不允许重协商
        'NO_RENEGOTIATION': ('RET', 'kProtocolError'),   # 该码仅 TLS1.3 出现
    }
    if verbose:
        print()
        print('=== TLS1.2 专项 ===')
    for st, want in EXPECT_R12.items():
        got = evaluate(chain, st, tls13=False)
        ok12 = (got == want)
        if verbose:
            print('  st=%-20s (tls13=False) got=%-6s %-16s want=%-6s %-16s %s'
                  % (st, got[0], got[1] or '-', want[0], want[1] or '-',
                     'OK' if ok12 else '*** MISMATCH ***'))
        if not ok12:
            bad = bad + ['%s@1.2' % st]

    return bad, results


# ---------------------------------------------------------------- 变异自测
# 每个变异只改文档文本，断言 analyze 必须报出不符（bad 非空）。
MUTS = [
    ('MUT1 else 体改 pass（D1 复发：未知状态落空到成功路径）',
     lambda s: s.replace(
         '    else:\n'
         '        return Fail(kInternal)                    # > [父会话 第⑨步 S4 / 第⑩步 D1]\n',
         '    else:\n'
         '        pass\n', 1)),

    ('MUT2 elif INTERNAL 体改 pass（INTERNAL 落空到成功路径）',
     lambda s: s.replace(
         '    elif st == INTERNAL:\n'
         '        return Fail(kInternal)                    # B5 + C1\n',
         '    elif st == INTERNAL:\n'
         '        pass\n', 1)),

    ('MUT3 PEER_ALERT 体改 return kOk',
     lambda s: s.replace(
         '    elif st == PEER_ALERT:\n'
         '        return Fail(kPeerAlert)                   # C1：Fail() 内部统一 clear\n',
         '    elif st == PEER_ALERT:\n'
         '        return kOk\n', 1)),

    ('MUT4 elif OK 体改成 Fail(kProtocolError)',
     lambda s: s.replace(
         '    elif st == OK:\n'
         '        pass                                      # 正常路径：继续到下方成功处理\n',
         '    elif st == OK:\n'
         '        return Fail(kProtocolError)\n', 1)),

    ('MUT5 删掉 elif st == OK 整条（D1 真实形态）',
     lambda s: s.replace(
         '    elif st == OK:\n'
         '        pass                                      # 正常路径：继续到下方成功处理\n',
         '', 1)),

    # ---- consult-b 第⑩步 G1：RENEGOTIATE 内层结构（旧版硬编码漏检）----
    ('G1a 1.3 的 continue 改成 Fail',
     lambda s: s.replace(
         '            feed EXTRA back to ISC once; discard output\n'
         '            continue                              # 记录已消费；progressed 已 +1\n',
         '            feed EXTRA back to ISC once; discard output\n'
         '            return Fail(kProtocolError)\n', 1)),

    ('G1b 删内层 if 只留无条件 continue',
     lambda s: s.replace(
         '        if negotiated.tls_version == 0x0304:\n'
         '            feed EXTRA back to ISC once; discard output\n'
         '            continue                              # 记录已消费；progressed 已 +1\n'
         '        else:\n'
         '            return Fail(kProtocolError)           # RDP 不允许重协商\n',
         '        continue\n', 1)),

    ('G1c 1.2 的 Fail 改成 continue',
     lambda s: s.replace(
         '        else:\n'
         '            return Fail(kProtocolError)           # RDP 不允许重协商\n',
         '        else:\n'
         '            continue\n', 1)),

    # ---- consult-b 第⑩步 G2：pass 与 continue 语义相反 ----
    ('G2 OK 分支 pass 改 continue（明文被静默丢弃）',
     lambda s: s.replace(
         '    elif st == OK:\n'
         '        pass                                      # 正常路径：继续到下方成功处理\n',
         '    elif st == OK:\n'
         '        continue\n', 1)),

    # ---- consult-b 第⑬步 Q4 真盲区：closed_=true 后 pass（OK 分支）----
    ('Q4b closed_=true 后 pass（OK 分支）',
     lambda s: s.replace(
         '    elif st == OK:\n'
         '        pass                                      # 正常路径：继续到下方成功处理\n',
         '    elif st == OK:\n'
         '        closed_ = true\n'
         '        pass\n', 1)),

    # ---- consult-b 第⑫步 Q4：closed_ = true 却返回 kOk 是矛盾组合 ----
    ('Q4 closed_=true 却 return kOk',
     lambda s: s.replace(
         '        closed_ = true; return kClosed            # 正常 EOF，不置 terminal_',
         '        closed_ = true; return kOk', 1)),

    # ---- consult-b 第⑪步 Q2：NO_RENEGOTIATION 在 1.2 下必须终止 ----
    ('Q2a NO_RENEG 去掉 1.2 分支（静默 continue）',
     lambda s: s.replace(
         '        if negotiated.tls_version == 0x0304:\n'
         '            continue                              # 1.3：正常，记录已消费；progressed 已 +1\n'
         '        else:\n'
         '            return Fail(kProtocolError)           # 1.2：本码不应出现\n',
         '        continue\n', 1)),

    # ---- consult-b 第⑪步 Q1(3)：副作用（closed_ = true）必须被建模 ----
    ('H3 删掉 closed_ = true 只留 return kClosed',
     lambda s: s.replace('        closed_ = true; return kClosed            # 正常 EOF，不置 terminal_',
                         '        return kClosed                            # 正常 EOF，不置 terminal_', 1)),

    # ---- consult-b 第⑪步 Q1(1)：外层运算符必须被解析（7 个 != 变异）----
    ('H1a st == INCOMPLETE 改 !=',
     lambda s: s.replace('    if st == INCOMPLETE:', '    if st != INCOMPLETE:', 1)),
    ('H1b st == RENEGOTIATE 改 !=',
     lambda s: s.replace('    elif st == RENEGOTIATE:', '    elif st != RENEGOTIATE:', 1)),
    ('H1c st == NO_RENEGOTIATION 改 !=',
     lambda s: s.replace('    elif st == NO_RENEGOTIATION:', '    elif st != NO_RENEGOTIATION:', 1)),
    ('H1d st == CONTEXT_EXPIRED 改 !=',
     lambda s: s.replace('    elif st == CONTEXT_EXPIRED:', '    elif st != CONTEXT_EXPIRED:', 1)),
    ('H1e st == PEER_ALERT 改 !=',
     lambda s: s.replace('    elif st == PEER_ALERT:', '    elif st != PEER_ALERT:', 1)),
    ('H1f st == INTERNAL 改 !=',
     lambda s: s.replace('    elif st == INTERNAL:', '    elif st != INTERNAL:', 1)),
    ('H1g st == OK 改 !=',
     lambda s: s.replace('    elif st == OK:', '    elif st != OK:', 1)),

    # ---- consult-b 第⑪步 Q1(2)：内层运算符必须被解析 ----
    ('H2a tls_version == 0x0304 改 !=',
     lambda s: s.replace('if negotiated.tls_version == 0x0304:',
                         'if negotiated.tls_version != 0x0304:', 1)),
    # consult-b 第⑪步 H2b 原用例用 `==` -> `>=`，但那是**语义等价**变异：
    #   1.3: 0x0304 >= 0x0304 == True   （同 ==）
    #   1.2: 0x0303 >= 0x0304 == False  （同 ==）
    # 等价改写**不应**被检出，故改为真正的语义反转 `>`：
    #   1.3: 0x0304 > 0x0304 == False  （与 == 相反）
    ('H2b tls_version == 0x0304 改 >（真反转）',
     lambda s: s.replace('if negotiated.tls_version == 0x0304:',
                         'if negotiated.tls_version > 0x0304:', 1)),

    # 等价改写不得翻红（>= 与 == 在这两个取值上等价）
    ('H2c tls_version == 改 >=（等价，不得红）',
     lambda s: s.replace('if negotiated.tls_version == 0x0304:',
                         'if negotiated.tls_version >= 0x0304:', 1), True),

    # ---- consult-b 第⑩步 Y3：集合内容必须解析 ----
    ('Y3 集合改成单值比较',
     lambda s: s.replace('elif st in {ALTERED, DECRYPT_FAILURE}:',
                         'elif st == ALTERED:', 1)),
]


def selftest(doc_text):
    print()
    print('=== 变异自测（每个变异都必须被检出）===')
    ok = 0
    for case in MUTS:
        label, mut = case[0], case[1]
        neg = case[2] if len(case) > 2 else False   # neg=True：等价改写，不得检出
        txt = mut(doc_text)
        if txt == doc_text:
            print('[BAD] %-52s 变异未生效（锚点失效）' % label)
            continue
        try:
            bad, _ = analyze(txt, verbose=False)
        except SystemExit as e:
            print('[BAD] %-52s 解析失败：%s' % (label, e))
            continue
        hit = bool(bad)
        good = (not hit) if neg else hit
        ok += 1 if good else 0
        print('[%s] %-52s 检出=%-5s%s 不符状态=%s'
              % ('PASS' if good else 'BAD', label, hit,
                 '（不得）' if neg else '', bad or '无'))
    print()
    print('变异自测：%d/%d 被检出' % (ok, len(MUTS)))
    return ok == len(MUTS)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', default=DEFAULT_DOC)
    ap.add_argument('--no-selftest', action='store_true')
    a = ap.parse_args(argv)

    doc = io.open(a.file, encoding='utf-8').read()
    bad, _ = analyze(doc)
    print()
    if bad:
        print('FAIL: 状态语义与期望不符 -> %s' % bad)
        return 1
    print('PASS: 10 个状态语义全部符合期望（OK 走成功路径，未知状态兜底）')

    if not a.no_selftest:
        if not selftest(doc):
            print('FAIL: 变异自测未全过 —— 本脚本自身不可信')
            return 1
        print('ASSERT OK')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
