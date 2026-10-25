"""伪代码结构检查器（pseudo_lint）。

存在理由：doc-lint 的 5 条检查全是**文本级**（正则匹配），
而 design-a 的 N1-N8 / B1-B13 / C1-C8 中绝大多数是**结构级**缺陷：
  - 缺回边（B1）
  - 标识符未定义（B2 extra_len / B6 tmp / B10 native_code,message）
  - 出口不满足不变量（B12/C1 四个 Fail 出口不清 plaintext_out）
  - 状态链无兜底（B13）
  - 章节编号逆序（B4 标题数 / B11 3.4.3 在 3.4.2 前）
  - 自检表与伪代码不对账（C7 出口数 17 vs 16 vs 13）

这些属性正则问不出来（正则只能问"模式在不在"，问不了"该在的地方是不是没在"），
但伪代码是缩进结构化的，可以廉价地做 AST-lite 分析。

用法：
    python pseudo_lint.py --file F:\\rtsc\\docs\\spec\\tls-backend.design-a.md
    python pseudo_lint.py --file ... --json

退出码：0=全绿，1=有 fail，2=有 warn 但无 fail。
"""
import argparse
import io
import os
import json
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ---------------------------------------------------------------- 伪代码提取

FUNC_HEAD = re.compile(r'^([A-Z][A-Za-z_]*)\(([^)]*)\)\s*:\s*$')


def load(path):
    return io.open(path, encoding='utf-8').read()


def extract_blocks(lines):
    """返回 [(start_idx, end_idx, [code_lines])]，只取含 Receive( 的伪代码块。"""
    blocks = []
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith('```'):
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith('```'):
                j += 1
            body = lines[i + 1:j]
            if any(FUNC_HEAD.match(l) for l in body):
                blocks.append((i, j, body))
            i = j + 1
        else:
            i += 1
    return blocks


def indent_of(line):
    return len(line) - len(line.lstrip(' '))


def is_code(line):
    s = line.strip()
    return bool(s) and not s.startswith('#')


# ---------------------------------------------------------------- 检查项

class Finding:
    def __init__(self, sid, level, msg, lines=None):
        self.sid = sid
        self.level = level          # fail | warn
        self.msg = msg
        self.lines = lines or []

    def as_dict(self):
        return {'id': self.sid, 'level': self.level,
                'msg': self.msg, 'lines': self.lines}

    def __str__(self):
        loc = (' @' + ','.join(str(x) for x in self.lines[:6])) if self.lines else ''
        return '[%s] %-4s %s%s' % (self.level.upper(), self.sid, self.msg, loc)


def check_loop_backedge(body, base):
    """S1：循环体最后一条可执行语句必须是 continue 或 return（抓 B1）。"""
    out = []
    for k, l in enumerate(body):
        if l.strip() == 'loop:':
            li = indent_of(l)
            body_idx = [m for m in range(k + 1, len(body))
                        if is_code(body[m]) and indent_of(body[m]) > li]
            if not body_idx:
                out.append(Finding('S1', 'fail', 'loop: 后没有循环体', [base + k + 1]))
                continue
            # 只看循环体**顶层**（缩进最浅）的最后一条语句：
            # 若它是 continue/return 则必然有回边；
            # 若它是 if/for 之类的复合语句，则条件不成立时会落空 → 缺回边。
            min_ind = min(indent_of(body[m]) for m in body_idx)
            top = [m for m in body_idx if indent_of(body[m]) == min_ind]
            last = top[-1]
            st = body[last].strip()

            def guarantees_backedge(idx, ind):
                """判断该语句是否**无条件**保证回到循环顶。

                consult-b 第⑨步 P1：`if True: continue` 语义等价于 `continue`，
                不应误报。判定规则：
                  - 以 continue/return 开头 → 是
                  - `if <恒真>:` 且其块内含 continue/return → 是（恒真 = True/1）
                  - 其他复合语句 → 否（条件不成立会落空）
                """
                if st.startswith('continue') or st.startswith('return'):
                    return True
                m = re.match(r'^if\s+(True|1)\s*:\s*$', st)
                if m:
                    blk = []
                    for x in body[idx + 1:]:
                        if not x.strip():
                            continue
                        if indent_of(x) <= ind:
                            break
                        blk.append(x)
                    return any(y.strip().startswith(('continue', 'return'))
                               for y in blk)
                return False

            if not guarantees_backedge(last, min_ind):
                out.append(Finding(
                    'S1', 'fail',
                    '循环体顶层末条语句不保证回到循环顶（条件不成立时会落空 → '
                    '一次调用只能解一条记录）：%r'
                    '（若条件恒真，请简化为无条件 continue/return，'
                    '以便静态检查确认回边）' % st[:60], [base + last + 1]))
    return out


def collect_assignments(body):
    """收集所有定义点（赋值/解包/参数/成员声明）。"""
    defined = set()
    for l in body:
        s = l.strip()
        m = FUNC_HEAD.match(s)
        if m:
            for p in m.group(2).split(','):
                p = p.strip()
                if p:
                    defined.add(p)
            continue
        if s.startswith('#'):
            continue
        # 元组解包 (a, b) = ...  或  a, b = ...
        m = re.match(r'^\(([^)]*)\)\s*=', s)
        if m:
            for p in m.group(1).split(','):
                defined.add(p.strip())
            continue
        m = re.match(r'^([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)+)\s*=', s)
        if m:
            for p in m.group(1).split(','):
                defined.add(p.strip())
            continue
        m = re.match(r'^([A-Za-z_]\w*)\s*=(?!=)', s)
        if m:
            defined.add(m.group(1))
    return defined


# 字面量白名单（会被改名绕过，故另加"所有 last_*_ 成员"的规则）
CRITICAL = ['tmp', 'extra_len', 'record', 'progressed', 'produced']
# 曾用名 -> 现用名（改名后仍要检查定义点，防"改名即绕过"）
ALIASES = {
    'native_code': ('native_code', 'last_native_code_'),
    'message': ('message', 'last_message_'),
}


def check_defined(body, base, doc_text):
    """S2：关键标识符必须有定义点（抓 B2/B6/B10）。"""
    out = []
    defined = collect_assignments(body)
    # 成员声明块（```cpp ... ```）里的定义也算定义点
    doc_members = set(re.findall(r'^\s*[\w:<>,\s]+?\b(last_\w+|rx_buffer_|terminal_|closed_|'
                                 r'last_error_)\s*[;=]', doc_text, re.M))
    defined |= doc_members

    for name in CRITICAL:
        used = [base + k + 1 for k, l in enumerate(body)
                if re.search(r'\b%s\b' % re.escape(name), l) and is_code(l)]
        if used and name not in defined:
            out.append(Finding('S2', 'fail',
                               '%r 被使用但无定义点（赋值/解包/参数/成员声明）' % name, used))

    # 改名绕过检测：任一别名（旧名或新名）出现，就必须在定义集合里找到它
    for canon, names in ALIASES.items():
        present = [n for n in names
                   if re.search(r'\b%s\b' % re.escape(n), doc_text)]
        if not present:
            continue
        used_in_body = [base + k + 1 for k, l in enumerate(body)
                        if any(re.search(r'\b%s\b' % re.escape(n), l) for n in names)
                        and is_code(l)]
        if used_in_body and not any(n in defined for n in names):
            out.append(Finding('S2', 'fail',
                               '%s 被使用但无定义点（含改名后 %s）'
                               % (canon, '/'.join(names)), used_in_body))
    return out


def check_fail_clears(body, base, doc):
    """S3：每个 return Fail(...) 出口必须满足"plaintext_out 已清空"（抓 B12/C1）。

    两种合格形态：
      (a) Fail() 本体含 plaintext_out.clear()  → 一处覆盖全部出口（推荐）
      (b) 每个 Fail 调用点之前 8 行内有 plaintext_out.clear()
    """
    out = []
    # 收集**所有** Fail* 辅助函数（Fail / FailWarn / FailFatal ...），
    # 每个都必须自己清空。consult-b 第⑨步 F5 实测：只查 Fail() 会让
    # 新增的 FailWarn() 逃逸（它不清 clear，但同样返回错误）。
    helper_clears = {}
    cur = None
    for l in body:
        m = re.match(r'^(Fail\w*)\s*\(', l.strip())
        if m:
            cur = m.group(1)
            helper_clears.setdefault(cur, False)
            continue
        if cur is not None:
            if is_code(l) and indent_of(l) == 0:
                cur = None
            elif 'plaintext_out.clear()' in l:
                helper_clears[cur] = True
    fail_clears = bool(helper_clears) and all(helper_clears.values())
    missing_clear = sorted(k for k, v in helper_clears.items() if not v)

    sites = [(base + k + 1, l) for k, l in enumerate(body)
             if re.match(r'^\s*return\s+Fail\(', l)]
    if not sites:
        return out
    if missing_clear:
        out.append(Finding('S3', 'fail',
                           '辅助错误函数未清空 plaintext_out：%s（每个 Fail* 都必须 clear）'
                           % missing_clear))
    if fail_clears:
        return out                       # 形态 (a)：一处覆盖
    for ln, _ in sites:
        k = ln - base - 1
        window = body[max(0, k - 8):k]
        if not any('plaintext_out.clear()' in w for w in window):
            out.append(Finding('S3', 'fail',
                               'return Fail() 出口未清空 plaintext_out（违反 §3.2.4 契约）', [ln]))
    return out


def check_state_else(body, base):
    """S4：状态链必须有真正的整链兜底（抓 B13 与"else 绑错对象"）。

    关键：伪代码里 7 个 `if st` 是**同层并列独立语句**，不是 elif 链。
    若末尾写 `else:`，它只绑定**紧邻的最后一个** `if st`，
    前面的 if 全不匹配时仍会落空到成功路径（或被这个 else 误判为错误）。

    判据（可判定，不依赖"有没有 else"）：
      设 chain = 所有顶层 `if st...` 的行号（同缩进）。
      合格形态只有两种：
        (A) elif 链：除第一个外，其余都以 `elif` 开头；
            且最后一个 `if/elif` 之后有同层 `else:`。
        (B) 显式守卫：在第一个 `if st` 之前出现
            `if st not in {...}` 或 `if st == UNKNOWN` 之类的全集检查。
      其余一律 fail。
    """
    out = []
    chain = [(k, indent_of(l)) for k, l in enumerate(body)
             if re.match(r'^\s*(if|elif)\s+st\b', l)]
    if not chain:
        return out

    # 取最外层（缩进最浅）那一组
    top = min(i for _, i in chain)
    outer = [(k, body[k]) for k, i in chain if i == top]
    first_k = outer[0][0]

    # 形态 (B)：显式守卫（第一个 if st 之前有 not in / UNKNOWN 检查）
    guard = any(re.search(r'\bst\s+not\s+in\b|\bst\s*==\s*UNKNOWN\b|\bst\s*!=\s*OK\b',
                          body[j])
                for j in range(0, first_k))

    # 形态 (A)：elif 链 + 末尾 else
    n_if = sum(1 for _, l in outer if l.strip().startswith('if '))
    n_elif = sum(1 for _, l in outer if l.strip().startswith('elif '))
    last_k = outer[-1][0]
    has_else = any(l.strip().startswith('else') and indent_of(l) == top
                   for l in body[last_k + 1:])

    ok_a = (n_if == 1 and n_elif == len(outer) - 1 and has_else)
    ok_b = guard

    if not (ok_a or ok_b):
        detail = ('%d 个 if + %d 个 elif，末尾 %s else'
                  % (n_if, n_elif, '有' if has_else else '无'))
        out.append(Finding(
            'S4', 'fail',
            '状态链无整链兜底（%s）——并列独立 if 的 else 只绑最后一个 if，'
            '其余状态会落空到成功路径；应改 elif 链或加显式守卫' % detail,
            [base + k + 1 for k, _ in outer]))
    return out


def check_consume_before_exit(body, base):
    """S13：记录必须在**状态分支**之前被消费（抓 N1）。

    N1 的原始形态是：take_front/erase 写在状态分支之后，
    于是分支里的 continue 会跳过消费 → 同一记录被重复解密（0x80090330）。

    可靠的机械判据（对结构化伪代码可判定）：
      设 first_branch = 第一个 `if st` 的行号，
         first_exit_in_branch = 其后第一个 continue/return 的行号，
         take_front = 首次出现 take_front( 的行号。
      若 take_front > first_exit_in_branch → 存在"跳过消费就退出"的路径 → fail。
    头部检查（if type / if len / if size）在 first_branch 之前，天然不受影响。
    """
    out = []
    branch = [k for k, l in enumerate(body) if re.match(r'^\s*if\s+st\b', l)]
    if not branch:
        return out
    first_branch = branch[0]
    exit_after = [k for k, l in enumerate(body)
                  if k > first_branch and re.match(r'^\s*(continue|return)\b', l.strip())]
    if not exit_after:
        return out
    first_exit = exit_after[0]
    tf = [k for k, l in enumerate(body) if 'take_front(' in l]
    if not tf:
        out.append(Finding('S13', 'fail', '伪代码无 take_front（记录消费点缺失）',
                           [base + first_branch + 1]))
        return out
    if tf[0] > first_exit:
        out.append(Finding(
            'S13', 'fail',
            'take_front 在状态分支的退出之后（分支里的 continue 会跳过消费 → N1 重复解密）',
            [base + tf[0] + 1, base + first_exit + 1]))
    return out


def check_no_clear_in_loop(body, base):
    """S14：循环体内禁止 plaintext_out.clear()（抓 N5 明文被覆盖）。"""
    out = []
    loop_ind = None
    for k, l in enumerate(body):
        if l.strip() == 'loop:':
            loop_ind = indent_of(l)
            continue
        if loop_ind is not None and is_code(l) and indent_of(l) > loop_ind:
            code = l.split('#')[0]
            # N5 的本质是"每次迭代重置输出"，clear() 只是其中一种写法。
            # consult-b 第⑨步 F1 实测：`plaintext_out = {}` 能绕过只匹配 clear() 的检查。
            if re.search(r'plaintext_out\s*(?:\.clear\(|\.assign\(|=)', code):
                out.append(Finding('S14', 'fail',
                                   '循环体内重置了 plaintext_out（clear/assign/赋值）→ '
                                   '多记录时前面的明文被覆盖（N5）',
                                   [base + k + 1]))
    return out


def check_terminal_latch(body, base):
    """S15：Receive 入口必须有 closed_ 与 terminal_ 双检查（抓 N7/B3）。"""
    out = []
    try:
        loop_k = next(k for k, l in enumerate(body) if l.strip() == 'loop:')
    except StopIteration:
        return out
    head = '\n'.join(body[:loop_k])
    miss = [n for n in ('terminal_', 'closed_') if n not in head]
    if miss:
        out.append(Finding('S15', 'fail',
                           'Receive 入口缺终止态检查：%s（N7 闩锁 / B3 kClosed 幂等）' % miss,
                           [base + 1]))
    return out


def check_section_order(lines):
    """S5：§3.4.x 小节必须按编号递增顺序出现（抓 B11）。"""
    out = []
    seen = []
    for i, l in enumerate(lines):
        m = re.match(r'^####\s+3\.4\.(\d+)', l)
        if m:
            seen.append((int(m.group(1)), i + 1))
    nums = [n for n, _ in seen]
    if nums != sorted(nums):
        out.append(Finding('S5', 'fail',
                           '§3.4.x 小节顺序逆序：%s（出现顺序 %s）'
                           % (nums, [n for n, _ in seen]), [ln for _, ln in seen]))
    return out


def _split_main_and_helpers(body):
    """把伪代码块切成「主函数体」与「辅助函数体」。

    切点 = 第一行形如 `Name(args):` 且该名字不是主函数（Receive）的定义行。
    例：`Fail(status):` 之后全是辅助函数，不属于 Receive 的出口统计。
    """
    main = []
    helpers = []
    in_helper = False
    for l in body:
        m = FUNC_HEAD.match(l.strip())
        if m and m.group(1) != 'Receive':
            in_helper = True
        if in_helper:
            helpers.append(l)
        else:
            main.append(l)
    return main, helpers


RET_RE = re.compile(r'(?:^|;)\s*return\b')
CONT_RE = re.compile(r'(?:^|;)\s*continue\b')


def count_exits(lines):
    """统计出口：行首 return、行内 return（`x = 1; return y`）、continue。

    三个坑（由 consult-a 第⑨步实测指出，本函数是修复后的口径）：
      1. 行内 return（`closed_ = true; return kClosed`）不以 return 开头 → 必须用 (?:^|;)
      2. 辅助函数（Fail()）体内的 return 不属于主函数 → 必须先切分
      3. 1 与 2 同时发生会互相抵消，总数"对上了"但两个错误都没暴露（假绿）
    """
    n = 0
    for l in lines:
        if l.strip().startswith('#'):
            continue
        if RET_RE.search(l) or CONT_RE.search(l):
            n += 1
    return n


def check_exit_table(lines, body, base):
    """S6/S7：出口表必须与伪代码对账，且每行引用 §3.3 行号（抓 C7 / 打勾 vs 比对）。"""
    out = []
    main, helpers = _split_main_and_helpers(body)
    n_main = count_exits(main)
    n_helper = count_exits(helpers)

    rows = [(i + 1, l) for i, l in enumerate(lines) if re.match(r'^\| E\d+ \|', l)]
    if not rows:
        out.append(Finding('S6', 'fail', '未找到出口清单表（| E1 | ...）'))
        return out

    if len(rows) != n_main:
        out.append(Finding(
            'S6', 'fail',
            '出口表行数(%d) != 主函数真实出口数(%d)（辅助函数内 %d 个 return 不计入）'
            % (len(rows), n_main, n_helper),
            [rows[0][0]]))

    bad = []
    for ln, l in rows:
        cells = [c.strip() for c in l.strip().strip('|').split('|')]
        if len(cells) < 5:
            bad.append((ln, '列数不足'))
            continue
        ref = [c for c in cells if '\u00a7' in c]
        if not ref:
            bad.append((ln, '无任何列引用契约章节：%r' % cells[-1][:40]))
        elif any(c in ('\u540c\u4e0a', '\u540c\u4e0a\u3002') for c in ref):
            bad.append((ln, '引用写成"\u540c\u4e0a"，不可定位（应重写章节号）'))
    if bad:
        out.append(Finding('S7', 'warn',
                           '出口表 %d 行未引用契约表行号（"打勾"\u2260"比对"）' % len(bad),
                           [ln for ln, _ in bad]))
    return out


def check_status_consistency(doc):
    """S8：Status 枚举 / terminal() / Fail() 注释 / §3.3 契约表 必须一致（抓 B5/B8）。"""
    out = []
    m = re.search(r'enum class Status[^{]*\{(.*?)\n\};', doc, re.S)
    if not m:
        return [Finding('S8', 'fail', '未找到 Status 枚举')]
    enum_body = '\n'.join(l for l in m.group(1).split('\n')
                           if not l.strip().startswith('//'))
    enum_vals = re.findall(r'\b(k[A-Z]\w+)', enum_body)
    enum_set = set(enum_vals)

    m = re.search(r'bool terminal\(\)[^{]*\{(.*?)\n  \}', doc, re.S)
    term_set = set(re.findall(r'\b(k[A-Z]\w+)', m.group(1))) if m else set()

    # Fail() 注释里列出的状态
    # consult-b 第⑨步 P2 实测：硬编码 `Fail(status):` 会让签名一改
    # （如 `Fail(status, code):`）就 fail_set 为空 → 全量误报 6 个状态。
    m = re.search(r'^Fail\w*\s*\([^)]*\)\s*:\n(.*?)^\S', doc, re.M | re.S)
    fail_block = m.group(0) if m else ''
    fail_set = set(re.findall(r'\b(k[A-Z]\w+)', fail_block))

    # §3.3 契约表里出现的状态
    sec = re.search(r'### 3\.3 .*?(?=\n### |\n> `> \[)', doc, re.S)
    contract_set = set(re.findall(r'\b(k[A-Z]\w+)', sec.group(0))) if sec else set()

    terminal_vals = {v for v in term_set if v in enum_set}
    missing_in_fail = sorted(terminal_vals - fail_set)
    if missing_in_fail:
        out.append(Finding('S8', 'fail',
                           'terminal() 含但 Fail() 注释漏列：%s' % missing_in_fail))

    missing_in_contract = sorted(v for v in enum_set
                                 if v not in ('kOk', 'kNeedMoreInput') and v not in contract_set)
    if missing_in_contract:
        out.append(Finding('S8', 'fail',
                           'Status 值在 §3.3 契约表无对应行：%s' % missing_in_contract))
    return out


def check_receive_rows(doc):
    """S12：由 Handshake 产生、由 Receive 传播的状态，§3.3 必须有**语义正确**的 Receive 行。

    consult-b 第⑨步 F3/F4 实测：只查"状态名是否出现"会被两种方式绕过——
      ① 把「本方法不产生」改成「本方法会产生」（语义完全反转）
      ② 整行缩成只有 `` `kUnsupported` ``（没有任何语义说明）
    因此必须同时检查：
      * 存在 Receive 行
      * 该行含「不产生」或「经 terminal_」（正向语义）
      * 该行**不含**「会产生」（反向语义，防止反转）

    **定位声明（consult-b 第⑩步 Q2）**：本检查的职责是「防止这一行被删掉或写成空壳」，
    不是「保证语义完全正确」。实测它对 4 种正确换说法会误报
    （「此码不会从本方法返回」「Receive 不负责」「仅透传」「非本方法职责」），
    因此定为 **warn**；语义正确性最终靠 code review。
    不加更多同义词：每加一个词就多一个误报源，而误报会让维护者关掉检查，比漏检更糟。
    """
    out = []
    for st in ('kUnsupported', 'kCertRejected'):
        rows = [l for l in doc.split('\n')
                if l.startswith('| `Receive`') and st in l]
        if not rows:
            out.append(Finding('S12', 'fail',
                               '%s 在 §3.3 无 Receive 契约行（实现者会在 Receive 里找产生点）' % st))
            continue
        # 语义可能分散在多行（kCertRejected 的否定说明在 kProtocolError 行，
        # 正向说明在 kUnsupported 行），合并所有提及该状态的 Receive 行判断。
        row = '\n'.join(rows)
        has_pos = ('\u4e0d\u4ea7\u751f' in row) or ('\u7ecf `terminal_`' in row)
        has_neg = re.search(r'\u4f1a\u4ea7\u751f|\u4ea7\u751f\u4e8e', row) is not None
        if not has_pos:
            out.append(Finding('S12', 'warn',
                               '%s 的 Receive 行缺正向语义（应含「不产生」或「经 terminal_」）：%r'
                               % (st, row[:60])))
        if has_neg:
            out.append(Finding('S12', 'warn',
                               '%s 的 Receive 行含反向语义（「会产生/产生于」）：%r'
                               % (st, row[:60])))
    return out


def check_kok_exclusion(doc):
    """S9：所有"!= kOk"的措辞必须显式排除 kClosed（抓 C4）。"""
    out = []
    NORM = re.compile(r'(\u4efb\u4f55|\u6240\u6709).{0,40}!= *`?kOk`?')
    L = doc.split('\n')
    for i, l in enumerate(L):
        if not NORM.search(l):
            continue
        # 契约可能跨行包裹：取后 4 行组成段落，判断"必须 clear"与 kClosed 排除是否同段
        para = '\n'.join(L[i:i + 5])
        if 'clear' not in para:
            continue
        # 排除"描述旧错误"的语境（含 原稿/修正/旧/曾）
        if re.search(r'(\u539f\u7a3f|\u4fee\u6b63|\u65e7|\u66fe|\u5df2\u5220|\u4e0d\u5f97\u518d)', para):
            continue
        if 'kClosed' not in para:
            out.append(Finding('S9', 'fail',
                               '明文契约写"!= kOk"但同段未排除 kClosed（kClosed 可能带明文）',
                               [i + 1]))
    return out


def check_dup_numbering(lines):
    """S10：同一层级标题编号不得重复（doc_lint F5 的补强，专抓 B4 型）。"""
    out = []
    seen = {}
    for i, l in enumerate(lines):
        m = re.match(r'^(#{2,4})\s+(\d+(?:\.\d+)*)\.?\s+(.*)$', l)
        if m:
            key = (len(m.group(1)), m.group(2))
            seen.setdefault(key, []).append((i + 1, m.group(3)[:40]))
    for (lvl, num), hits in seen.items():
        if len(hits) > 1:
            out.append(Finding('S10', 'fail',
                               '标题编号 %s 重复 %d 次' % (num, len(hits)),
                               [h[0] for h in hits]))
    return out


def check_decl_claims(lines):
    """S11：标题里的"N 个边界/坑/规则"必须与实列条数一致（抓 B4 型）。"""
    out = []
    def cn2int(t):
        """通用中文数字解析（consult-b 第⑨步：原字典只到十六，二十/二十一 漏检）。"""
        D = {'零': 0, '一': 1, '二': 2, '三': 3, '四': 4, '五': 5,
             '六': 6, '七': 7, '八': 8, '九': 9}
        if t.isdigit():
            return int(t)
        if '十' not in t:
            return D.get(t) if len(t) == 1 else None
        tens, _, ones = t.partition('十')
        hi = D.get(tens, None) if tens else 1
        if tens and hi is None:
            return None
        lo = D.get(ones, 0) if ones else 0
        if ones and ones not in D:
            return None
        return hi * 10 + lo
    for i, l in enumerate(lines):
        m = re.match(r'^#{2,5}\s+.*?(\d+|[一二三四五六七八九十]+)\s*个(边界|坑|规则|出口|不变量)', l)
        if not m:
            continue
        want = cn2int(m.group(1))
        if want is None:
            continue
        # 统计该标题后到下一个同级/更高级标题之间的有序列表项
        lvl = len(l) - len(l.lstrip('#'))
        cnt = 0
        for j in range(i + 1, len(lines)):
            s = lines[j]
            m2 = re.match(r'^(#{1,6})\s', s)
            if m2 and len(m2.group(1)) <= lvl:
                break
            if re.match(r'^\s*(?:\d+\.|[-*+])\s', s):
                cnt += 1
        if cnt and cnt != want:
            out.append(Finding('S11', 'fail',
                               '标题称 %d 个%s，实列 %d 条' % (want, m.group(2), cnt),
                               [i + 1]))
    return out


# ---------------------------------------------------------------- 主流程

def run(path):
    doc = load(path)
    lines = doc.split('\n')
    blocks = extract_blocks(lines)
    findings = []

    if not blocks:
        findings.append(Finding('S0', 'fail', '未找到伪代码块'))
    for start, end, body in blocks:
        base = start + 1                    # 伪代码首行在文件中的 1-based 行号
        findings += check_loop_backedge(body, base)
        findings += check_defined(body, base, doc)
        findings += check_fail_clears(body, base, doc)
        findings += check_state_else(body, base)
        findings += check_consume_before_exit(body, base)
        findings += check_no_clear_in_loop(body, base)
        findings += check_terminal_latch(body, base)
        findings += check_exit_table(lines, body, base)

    findings += check_section_order(lines)
    findings += check_status_consistency(doc)
    findings += check_receive_rows(doc)
    findings += check_kok_exclusion(doc)
    findings += check_dup_numbering(lines)
    findings += check_decl_claims(lines)
    return findings



# ---------------------------------------------------------------- 历史回归
# 每个历史快照"已知必中"的检查项，来自当轮审计报告（可追溯）。
# 断言「命中项 ⊇ KNOWN」而不是「fail 数单调不增」，理由（consult-b 第⑨步 Q2）：
#   1. fail 数是 (文档版本 × 检查器版本) 的二元函数，检查器在演化，前提不成立
#   2. 修复会产生中间态（如 3.4.2/3.4.3 互换瞬间 S5/S11 可能同时红）
#   3. fail 数会掩盖"换了一批缺陷"——14→13 可能是"修 2 增 1"
# 注意：只登记 **fail** 级命中。S7（出口表未引用契约章节）是 warn 级，
# 不计入 KNOWN——它在多个历史版本里以 warn 出现，不构成"检查器失准"。
KNOWN = {
    'design-a.bak.md':            {'S1', 'S2', 'S4', 'S6', 'S8', 'S12', 'S14', 'S15'},
    'design-a.step7.snapshot.md': {'S2', 'S3', 'S4', 'S5', 'S8', 'S11', 'S12', 'S14'},
    'design-a.step7.v2.md':       {'S2', 'S3', 'S4', 'S5', 'S8', 'S12', 'S14'},
    'design-a.step8.base.md':     {'S2', 'S4', 'S12'},
}


def regress(paths, current=None):
    """B14c：在历史快照上回归，断言「命中项 ⊇ KNOWN」。

    ⊇ 而非 ==：检查器改进后能抓更多不算失败，只需登记到 KNOWN。
    额外命中会打印提示（要么补 KNOWN，要么是真回归）。
    """
    print('%-30s %-9s %-6s %s' % ('snapshot', 'fail_ids', 'known', 'verdict'))
    print('-' * 86)
    rc = 0
    for path in paths:
        if not os.path.exists(path):
            print('%-30s MISSING（路径不存在，检查断言而非删条目）' % os.path.basename(path))
            rc = 1
            continue
        name = os.path.basename(path)
        f = run(path)
        ids = {x.sid for x in f if x.level == 'fail'}
        must = KNOWN.get(name)
        if must is None:
            print('%-30s %-6d %-8s 未登记（请在 KNOWN 中补充）'
                  % (name, len(ids), '-'))
            continue
        missing = must - ids
        extra = ids - must
        ok = not missing
        if not ok:
            rc = 1
        print('%-30s %-6d %-8d %s%s'
              % (name, len(ids), len(must),
                 'OK' if ok else 'MISSING=%s' % sorted(missing),
                 ('  extra=%s' % sorted(extra)) if extra else ''))
    if current:
        f = run(current)
        ids = {x.sid for x in f if x.level == 'fail'}
        print('%-30s %-6d %-8s %s' % (os.path.basename(current), len(ids), '0',
                                      'OK' if not ids else 'STILL FAIL=%s' % sorted(ids)))
        if ids:
            rc = 1
    print()
    print('REGRESS %s' % ('OK（每个历史快照的已知缺陷都被检出，当前全绿）'
                          if rc == 0 else 'FAILED'))
    return rc


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--file')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--regress', nargs='+',
                    help='历史快照路径；断言「命中项 ⊇ KNOWN」')
    ap.add_argument('--current', help='与 --regress 同用：当前文档必须 fail=0')
    a = ap.parse_args(argv)

    if a.regress:
        return regress(a.regress, a.current)
    if not a.file:
        ap.error('--file or --regress required')

    findings = run(a.file)
    if a.json:
        print(json.dumps([f.as_dict() for f in findings], ensure_ascii=False, indent=2))
    else:
        for f in findings:
            print(f)
        nf = sum(1 for f in findings if f.level == 'fail')
        nw = sum(1 for f in findings if f.level == 'warn')
        print('\nTOTAL fail=%d warn=%d' % (nf, nw))
    nf = sum(1 for f in findings if f.level == 'fail')
    return 1 if nf else (2 if findings else 0)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
