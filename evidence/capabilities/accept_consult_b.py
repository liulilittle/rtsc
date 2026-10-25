r"""W11 第⑤步验收判据（审计乙视角，侧重措辞与语义）。

用法：
    $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
    python -X utf8 F:\rtsc\evidence\capabilities\accept_consult_b.py

设计原则：
  1. 只读 capabilities.md，不修改。
  2. 每条判据给出 PASS/FAIL 与实测证据行号，便于执行 AI 自检。
  3. 措辞类判据一律带"否定语境豁免"——正确的修订常常要写"不是越界读"，
     粗暴地搜"越界==0"会把正确写法判成 FAIL。
  4. 语义类判据（表格分类是否合理等）无法机械判定，本脚本只做"信号提示"，
     标记 NEEDS-HUMAN，不参与 PASS/FAIL 汇总。
"""
import hashlib
import io
import os
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# 允许用环境变量指向"变异副本"，供 mutation_test.py 做红证（§17.7 第 5/6 条）。
# 默认仍是正本；生产使用时不要设 CAPS_DOC。
DOC = os.environ.get('CAPS_DOC') or r'F:\rtsc\docs\spec\capabilities.md'
raw = open(DOC, 'rb').read()
L = raw.decode('utf-8').splitlines()

RESULTS = []      # (id, name, ok, detail)
HUMAN = []        # (id, name, hint)


def rows(pred):
    return [(i, l) for i, l in enumerate(L, 1) if pred(l)]


def one(pred, what):
    r = rows(pred)
    if not r:
        raise SystemExit('ANCHOR-MISSING: ' + what)
    return r[0]


def section(start_pred, end_pred):
    st, _ = one(start_pred, 'section start')
    ends = [i for i, l in enumerate(L, 1) if i > st and end_pred(l)]
    en = ends[0] if ends else len(L)
    return st, en, L[st - 1:en - 1]


def body_rows(pred):
    """Like rows(), but skips the changelog section (## 18 修订记录).

    The changelog legitimately QUOTES the old wording (e.g. "「严格串行」改为…")
    to record what was changed. A naive global scan would flag that quotation as
    the defect still being present. This is the same class of bug as the F-02
    false positive: the criterion assumed something about the document's layout.
    """
    cl = [i for i, l in enumerate(L, 1) if re.match(r'^## 18\.', l)]
    cl_start = cl[0] if cl else len(L) + 1
    nxt = [i for i, l in enumerate(L, 1) if i > cl_start and re.match(r'^## \d+\.', l)]
    cl_end = nxt[0] if nxt else len(L) + 1
    return [(i, l) for i, l in enumerate(L, 1)
            if pred(l) and not (cl_start <= i < cl_end)]


def add(fid, name, ok, detail):
    RESULTS.append((fid, name, ok, detail))
    print('[%s] %-10s %s' % ('PASS' if ok else 'FAIL', fid, name))
    print('            ' + detail)


def human(fid, name, hint):
    HUMAN.append((fid, name, hint))
    print('[HUMAN]    %-10s %s' % (fid, name))
    print('            ' + hint)


def negated_ok(text, needle, span=14):
    """needle 的每次出现都必须处于否定语境（不是/而非/非/不得/禁止）。"""
    hits = list(re.finditer(re.escape(needle), text))
    if not hits:
        return True, 0, []
    bad = []
    for m in hits:
        pre = text[max(0, m.start() - span):m.start()]
        if not re.search(r'不是|而非|非|不得|禁止|不算', pre):
            bad.append(text[max(0, m.start() - 20):m.end() + 6].replace('\n', ' '))
    return (not bad), len(hits), bad


print('=' * 78)
print('capabilities.md  lines=%d  bytes=%d' % (len(L), len(raw)))
print('sha256=%s' % hashlib.sha256(raw).hexdigest())
print('=' * 78)

# ---------------------------------------------------------------- F-15
ln, row = one(lambda l: l.startswith('| **U-14**'), 'U-14 row')
c1 = bool(re.search(r'ordersupport', row, re.I))
c2 = bool(re.search(r'numcellcaches|cellinfo', row, re.I))
c3 = row.count('全部 MAC 失配') + row.count('全部MAC失配') + row.count('MAC 全部失配')
mac_cond = True
if re.search(r'MAC', row):
    mac_cond = bool(re.search(r'若.{0,60}?(则|即)?.{0,30}?失配|可能失配', row))
add('F-15', 'U-14 不得用绝对 MAC 断言',
    c1 and c2 and c3 == 0 and mac_cond,
    'line=%d orderSupport=%s NumCellCaches|CellInfo=%s 绝对失配次数=%d MAC条件式=%s'
    % (ln, c1, c2, c3, mac_cond))
human('F-15', 'U-14 合并策略是否仍表达"取交集/更保守"',
      '看该行是否仍有"取交集/AND/取小"等非 last-wins 措辞；只要出现 last-wins 或"后者覆盖前者"即需返工。')

# ---------------------------------------------------------------- F-13
# 作用域 v3（本轮修正 2 个 latent gap）：
#   v1: sub 只取"含 lcc<4 的行"（= 873 / 902 两行），结论行 904
#       「**assert 失败 / 长度下溢**，**不是越界读**」**不在作用域内** →
#       把 904 改成"是越界读"，v1 仍 PASS（假阴性，实测确认）。
#   v2: 粗暴扩成"整个连续引用块"，把 879 `# ① 头越界`、883 `# ③ 体越界`、
#       896/898 的 case A/B「越界读」全部纳入 → 基线直接 FAIL（过度扩大，
#       这些"越界"都是**正确**表述：边界检查名 + 真实越界案例）。
#   v3: 精确规则——只扩展**同一引用段落**（连续的 `>` 行，遇 `>` 空行即断）；
#       代码块内的 lcc<4 行不扩展（其"头越界/体越界"是检查项名称，不是后果描述）。
#       实测作用域 = {873} ∪ {902,903,904}，共 4 行。
def _scope_lcc(block, hits):
    out = set(hits)
    for i in hits:
        if not block[i].lstrip().startswith('>'):
            continue                      # 代码块行：不扩展
        j = i
        while (j + 1 < len(block)
               and block[j + 1].lstrip().startswith('>')
               and block[j + 1].strip() != '>'):
            j += 1
            out.add(j)
    return out


st, en, blk = section(lambda l: l.startswith('### 6.1'), lambda l: l.startswith('### 6.2'))
_hit_idx = [i for i, l in enumerate(blk) if re.search(r'lcc\s*<\s*4|lcc<4', l)]
sub = [blk[i] for i in sorted(_scope_lcc(blk, _hit_idx))]
subt = '\n'.join(sub)
down = bool(re.search(r'下溢|assert\s*失败|assert\(', subt, re.I))
# 注意 re.I：§6.1 行 903 写的是 `ASSERT-FAIL`（全大写），不加 re.I 会漏。
neg_ok, n_occ, bad = negated_ok(subt, '越界')
add('F-13', 'lcc<4 只能写"下溢/assert 失败"（作用域含结论段）',
    bool(sub) and down and neg_ok,
    'line=%d..%d 作用域 %d 行 下溢/assert=%s 越界出现=%d 未被否定=%s'
    % (st, en, len(sub), down, n_occ, bad if bad else '无'))
# 对照：父会话提议的粗暴判据
naive = ('越界' not in subt)
print('            [对照] 粗暴判据「作用域内 越界==0」= %s（%s）'
      % (naive, '与精化判据同结论' if naive == neg_ok else '会与精化判据分歧，故不采用'))

# ---------------------------------------------------------------- F-03 / F-12
tm = sorted(set(re.findall(r'对端可控|对端触发|可被对端触发|恶意服务端|攻击者可控', '\n'.join(blk))))
add('F-03/F-12', '必须写明威胁模型',
    len(tm) > 0,
    '命中词=%s（"恶意服务端"单独计数=%d，"对端可控"=%d）'
    % (tm, '\n'.join(blk).count('恶意服务端'), '\n'.join(blk).count('对端可控')))
bt = '\n'.join(blk)
# v2（变异测试发现）：v1 只认 `numberCapabilities.{0,60}?(偏大|大于|超出|超过)`。
# 若把"计数偏大"改写成"计数不符/计数错误/虚高"，v1 会漏检（假阴性）。
d12 = bool(re.search(r'numberCapabilities.{0,60}?'
                     r'(偏大|大于|超出|超过|不符|错误|虚高|过多|伪造)', bt))
d03 = bool(re.search(r'lengthCapability.{0,60}?'
                     r'(大于|超出|无上界|越界|> 剩余|>剩余|超限|过长)', bt))
add('F-03/F-12', '两条缺陷各自描述（同义表述覆盖）',
    d12 and d03,
    'count偏大=%s len超限=%s（§6.1 行 %d..%d）' % (d12, d03, st, en))

# ---------------------------------------------------------------- F-06
# §17.7 第 2 条（同义表述）补齐：k3 原先只认"清空标准"/"标准 Bitmap Cache"。
# 实测（audit_case3.py）：写成"丢弃标准缓存"就漏检（假阴性）。
# 改为"动词(清空/清除/丢弃/重置/作废) + 标准"或"标准 + 缓存"的宽松组合。
ln3, r3 = one(lambda l: l.startswith('| **U-03**'), 'U-03 row')
k1 = 'Persistent' in r3
k2 = '保留' in r3
k3 = bool(re.search(
    r'(清空|清除|丢弃|重置|作废|flush|invalidate)\s*\*{0,2}\s*(标准|standard)'
    r'|(标准|standard)\s*\*{0,2}\s*(Bitmap\s*)?Cache',
    r3, re.I))
add('F-06', 'U-03 区分标准/持久缓存（同义表述覆盖）',
    k1 and k2 and k3,
    'line=%d Persistent=%s 保留=%s 清空标准=%s' % (ln3, k1, k2, k3))

# ---------------------------------------------------------------- F-38
# §17.7 第 2 条补齐：bad38 原先只认"可开始发(送) input"。
# 实测（audit_case3.py）：违规写法改成"即可发送 input"/"允许发送 input" 就漏检。
# 改为"Server Synchronize 行 + 任意'可发送 input'语义"。
st2, en2, blk2 = section(lambda l: l.startswith('### 12.2'), lambda l: l.startswith('### 12.3'))
_INPUT_ALLOW_RE = re.compile(
    r'(可开始发|即可发|可以发|允许发|能发|可发|开始发)\s*(送|出)?\s*`?input',
    re.I)
bad38 = [l for l in blk2 if 'Server Synchronize' in l and _INPUT_ALLOW_RE.search(l)]
has_pair = any(re.search(r'Confirm Active', l) and re.search(r'input', l, re.I) for l in blk2)
add('F-38', 'input 许可不得挂在 Server Synchronize',
    not bad38 and has_pair,
    '§12.2 行 %d..%d 仍挂 input 的行数=%d；Confirm Active 与 input 同段=%s'
    % (st2, en2, len(bad38), has_pair))
if bad38:
    print('            残留行: ' + ' | '.join(x[:90] for x in bad38))

# ---------------------------------------------------------------- F-41
# v2（变异测试发现）：v1 用 `'SHOULD' in l`，而该行同时**引用**了规范原文
# "SHOULD be dropped"。把规定用语删掉、只留引用，v1 仍判 PASS（假阴性）。
# 修法：先剥掉「；原文 …」这类引用片段，再要求动作部分含 SHOULD。
def _action_part(line):
    for sep in ('；原文', '；官方原文', '原文：', '（原文'):
        i = line.find(sep)
        if i != -1:
            line = line[:i]
    return line


cl = [l for l in L if 'totalLength' in l and '断链' in l and l.strip().startswith('- [')]
ok41 = bool(cl) and all('SHOULD' in _action_part(l) for l in cl)
add('F-41', 'totalLength 不一致写 SHOULD（剥离原文引用后）',
    ok41,
    '检查项命中=%d 行，动作部分含 SHOULD=%d 行；缺 SHOULD 的行: %s'
    % (len(cl), sum('SHOULD' in _action_part(l) for l in cl),
       [l[:80] for l in cl if 'SHOULD' not in _action_part(l)] or '无'))

# ---------------------------------------------------------------- 补充：F-02 / F-21 / F-29 / F-35 / F-37
# F-02 判据（第二版，修正第一版的误报）：
#   第一版要求"含明文的行本身必须带限定语"，这是错的——markdown 的合法结构是
#   "块前说明行（写限定）+ 代码块（写数据）"，限定语与数据天然不同行。
#   第二版改为：数据行 **或其向上 3 行内** 出现 明文/解密/不是/Decrypted 之一。
try:
    st4, en4, blk4 = section(lambda l: l.startswith('### 13.4'),
                             lambda l: l.startswith('### 13.5'))
except SystemExit:
    st4, en4, blk4 = 1, len(L), L

CIPHER = '26 18 5e 76'          # 线上密文前缀（官方 7 字节 26 18 5e 76 0e de 28）
PLAIN = '20 00 08 ab'           # 解密后载荷前缀（7 字节 20 00 08 ab 02 6f 01）
LIMIT = ('明文', '解密', '不是', 'Decrypted', 'decrypted')

plain_hits = [(st4 + k, blk4[k]) for k in range(len(blk4)) if PLAIN in blk4[k]]
plain_unqualified = []
for ln_, txt_ in plain_hits:
    ctx = '\n'.join(blk4[max(0, (ln_ - st4) - 3):(ln_ - st4) + 1])
    if not any(k in ctx for k in LIMIT):
        plain_unqualified.append(ln_)

cipher_in_win = [st4 + k for k in range(len(blk4)) if CIPHER in blk4[k]]
# 表格行也必须改成密文（F-02 的最小修正要求"行 2171 的字节改为密文"）。
# 只数出现次数会被"注释行 + hexdump 行"凑够 2 次而漏掉表格行，故单列一条。
cipher_in_table = [st4 + k for k in range(len(blk4))
                   if CIPHER in blk4[k] and blk4[k].lstrip().startswith('|')]
cipher_global = [i for i, _ in rows(lambda l: CIPHER in l)]

ok02 = (len(cipher_in_win) >= 2) and bool(cipher_in_table) and (not plain_unqualified)
add('F-02', '§13.4 线上密文已改回',
    ok02,
    '§13.4 窗口=%d..%d；密文行=%s（需>=2）；密文表格行=%s（需>=1）；'
    '明文行=%s（均需"或上3行内"带限定）；未带限定=%s；全文密文=%s'
    % (st4, en4, cipher_in_win, cipher_in_table,
       [i for i, _ in plain_hits], plain_unqualified or '无', cipher_global))
if plain_unqualified:
    for ln_ in plain_unqualified:
        print('            未带限定的明文行 %d: %s' % (ln_, L[ln_ - 1][:100]))
if not cipher_in_table:
    print('            §13.4 表格里没有密文行（表格可能仍写明文）')

f21 = rows(lambda l: 'lengthSourceDescriptor + lengthCombinedCapabilities + 4' in l)
add('F-21', 'totalLength 闭式不得再 +4',
    not f21,
    '仍含 "+ lengthCombinedCapabilities + 4" 的行=%s' % ([i for i, _ in f21] or '无'))

# F-29：真值随文档修订变化（原 87 → 现 97，因补登了 S90–S99 的 10 个 guid）。
# 判据不锁死数字，而是锁"文档自述的计数 == 实测计数"这个一致性。
_srows = [(i, l) for i, l in enumerate(L, 1) if re.match(r'\| S\d+ ', l)]
_learn = [m.group(1) for _, l in _srows
          for m in [re.search(r'(ms-rdp\w+/[0-9a-f-]{36})', l)] if m]
_nlearn = len(set(_learn))
_claimed = re.findall(r'(\d+)\s*个\s*`?learn\.microsoft\.com`?', '\n'.join(L))
_claimed = sorted(set(int(x) for x in _claimed))
_stale85 = body_rows(lambda l: '85/85' in l)
ok29 = (_nlearn in _claimed) and (not _stale85)
add('F-29', 'URL 计数与实测一致、无残留 85/85',
    ok29,
    '实测 distinct learn URL=%d；文档自述计数=%s；正文残留 85/85 的行=%s'
    % (_nlearn, _claimed, [i for i, _ in _stale85] or '无'))

f35 = body_rows(lambda l: '严格串行' in l)
add('F-35', '不得再写"严格串行"',
    not f35,
    '正文（排除 §18 修订记录）仍含"严格串行"的行=%s' % ([i for i, _ in f35] or '无'))

f37 = rows(lambda l: '4,096' in l)
add('F-37', '会话密钥更新已补 4,096',
    len(f37) > 0,
    '含 4,096 的行=%s' % ([i for i, _ in f37] or '无（未补）'))

# ---------------------------------------------------------------- F-28 机械版（大小写不敏感）
# 为什么必须不分大小写：§8.21 / §8.22 的表格里写的是 `LengthCapability`（首字母大写），
# 而 §8 其余 25 节写 `lengthCapability`。只匹配小写会漏掉这 2 行（实测：cs=0 / ci=2）。
_f28 = [(i, l) for i, l in body_rows(lambda l: True)
        if l.lstrip().startswith('|')
        and re.search(r'lengthcapability', l, re.I)
        and re.search(r'MUST\s*=\s*\d+', l)]
add('F-28', '正文无 lengthCapability|MUST=N（大小写不敏感）',
    not _f28,
    '残留行=%s' % ([i for i, _ in _f28] or '无'))
for i, l in _f28:
    print('            残留 %d: %s' % (i, l.strip()[:110]))

# ---------------------------------------------------------------- F-30 / F-20（§15.1 自洽性）
try:
    st15, en15, blk15 = section(lambda l: l.startswith('### 15.1'),
                                lambda l: l.startswith('## 16.'))
except SystemExit:
    st15, en15, blk15 = 1, len(L), L
t151 = '\n'.join(blk15)

# F-30 本体：不得有"某项本身缺 dump 却仍列在已核实表内"。
# 豁免：主语是"未覆盖的 6 个类型"的**边界声明**（F-20 要求的诚实披露），
#       特征是含 '6 个' 或具体未覆盖类型编号。
#
# §17.7 第 2 条自检：原版只认 '无 dump 佐证' / '缺 dump 佐证' 两个精确短语，
# 若执行 AI 改写成"未见 dump"/"无官方 dump"/"无佐证"就整条漏检（假阴性）。
# 改为同义集合 + 正则，覆盖常见改写。
_UNCOV = ('6 个', '0x0004', '0x0019', '0x001A', '0x001B', '0x001C', '0x001E')
_NO_DUMP_RE = re.compile(
    r'(无|缺|没有|未见|未获|缺乏)\s*(官方\s*)?(dump|Dump|DUMP)\s*(佐证|支撑|验证)?'
    r'|(仅有|只有)\s*(规范)?原文(表)?(比对|佐证|依据)?'
    r'|无\s*佐证|未\s*取证')
_bad30 = []
for l in blk15:
    if not l.strip().startswith('|'):
        continue
    if not _NO_DUMP_RE.search(l):
        continue
    if any(m in l for m in _UNCOV):
        continue
    _bad30.append(l)
add('F-30', '§15.1 无"自承未核实"的行（6 类型边界声明豁免；同义表述覆盖）',
    not _bad30,
    '§15.1 行 %d..%d；违规行=%s' % (st15, en15, [l[:70] for l in _bad30] or '无'))

# F-20 本体：§15.1 必须保留"6 个类型无 dump"的诚实披露，且分区恒等式成立。
_has6 = any(('6 个' in l) and _NO_DUMP_RE.search(l) for l in blk15)
add('F-20', '§15.1 保留 6 类型无 dump 的披露（同义表述覆盖）',
    _has6,
    '含"6 个…无 dump 佐证"的行数=%d' % sum(1 for l in blk15
                                          if '6 个' in l and _NO_DUMP_RE.search(l)))

# F-20 分区恒等式：28 = 21(dump 覆盖) + 6(无 dump) + 1(0x001D 变长)
_st = [i for i, l in enumerate(L, 1) if l.startswith('### 6.2')][0]
_en = [i for i, l in enumerate(L, 1) if i > _st and re.match(r'^#{2,3} ', l)][0]
_tbl = [l for l in L[_st - 1:_en - 1] if re.match(r'\| 0x[0-9A-Fa-f]{4} ', l)]
_allids = set(re.match(r'\| (0x[0-9A-Fa-f]{4}) ', l).group(1).lower() for l in _tbl)
_dump = set(t.lower() for t in re.findall(r'type=(0x[0-9A-Fa-f]{4})', '\n'.join(L)))
_row = [l for l in blk15 if l.startswith('| 21 类型')]
_six = set(t.lower() for t in re.findall(r'0x00[0-9A-Fa-f]{2}', _row[0])) & _allids if _row else set()
_VAR = {'0x001d'}
_part = (len(_allids) == len(_dump) + len(_six) + len(_VAR)
         and not (_dump & _six) and (_dump | _six | _VAR) == _allids)
add('F-20', '分区恒等式 28 = 21 + 6 + 1',
    _part,
    '28=%d dump=%d six=%d var=%d；两两不相交=%s；并集=28=%s'
    % (len(_allids), len(_dump), len(_six), len(_VAR),
       not (_dump & _six) and not (_dump & _VAR) and not (_six & _VAR),
       (_dump | _six | _VAR) == _allids))

# F-30 导语强度：导语的强度声明必须与数据行的实际覆盖**一致**。
#
# 第四版（修正第四次误报）。前三版都错在"只认关键词、不认限定语"：
#   v1/v2: 见到 'dump 双向' 就要求每行都有 dump —— 把「多数并辅以…」当成「全部都是…」，
#          结果把**正确的修复**判成未修复（假阳性）。
#   v3(本版) 引入三档强度判定：
#     ① 削弱性限定语（多数/大部分/部分/逐行注明/不完全/少数）→ 允许存在无 dump 行 → PASS
#     ② 绝对性声明（全部/所有/每一项/均，且**无**削弱语）→ 每行必须有 dump → 缺一即 FAIL
#     ③ 无强度词（既不说全部也不说多数）→ 默认按"全部"处理 → 每行必须有 dump
#   判别顺序很重要：先看削弱语（它能把绝对语降级，如"全部…多数已…"仍以削弱语为准？不，
#   同时出现时以更保守的一侧判——见 _judge_intro 的实现在下）。

WEAK = ('多数', '大部分', '部分', '个别', '逐行注明', '不完全', '少数', '绝大部分')
# 注意：'各项' 会同时出现在削弱语写法（"各项…多数…"）里，但 WEAK 分支优先，
# 所以不影响判定，只让"绝对语"分支的 reason 更准确。
ABS = ('全部', '所有', '每一项', '均', '各项', '每一项都')


def _judge_intro(intro_text, rows_no_dump, has_dump_col):
    """返回 (ok, reason)。

    intro_text   : §15.1 的导语文本（可能为空）
    rows_no_dump : 不含 dump 的数据行行号列表
    has_dump_col : 是否存在"核实方式"列（有列才谈得上逐行注明）
    """
    if not intro_text:
        return True, '无导语，不作强度断言'
    weak = [w for w in WEAK if w in intro_text]
    abso = [a for a in ABS if a in intro_text]
    if weak:
        # 削弱语存在 → 声明强度已下调，允许无 dump 行
        return True, '削弱语=%s → 允许 %d 行无 dump' % (weak, len(rows_no_dump))
    if abso:
        if rows_no_dump:
            return False, '绝对语=%s 但 %d 行无 dump' % (abso, len(rows_no_dump))
        return True, '绝对语=%s 且每行都有 dump' % (abso,)
    # 无任何强度词：默认按"全部"处理（保守）
    if rows_no_dump:
        return False, '无强度词（默认按"全部"）但 %d 行无 dump' % len(rows_no_dump)
    return True, '无强度词但每行都有 dump'


_intro_lines = [l for l in blk15
                if l.strip() and not l.lstrip().startswith('|')
                and not l.startswith('#')
                and ('核实' in l or 'dump' in l)]
_intro_text = '\n'.join(_intro_lines)
_rows_no_dump = [(st15 + k) for k, l in enumerate(blk15)
                 if l.lstrip().startswith('|') and not l.startswith('|---')
                 and not l.startswith('| 项 ')
                 and 'dump' not in l]
_ok_intro, _intro_reason = _judge_intro(_intro_text, _rows_no_dump, True)
add('F-30', '§15.1 导语强度 ≤ 内容强度（识别削弱语）',
    _ok_intro,
    '导语=%r；无 dump 的行=%s；判定=%s'
    % (_intro_text.replace('\n', ' ')[:70], _rows_no_dump or '无', _intro_reason))

# ---------------------------------------------------------------- 人工判读
human('F-16', '§7.3"必须"表是否拆成两张',
      '看 §7 是否出现"规范 MUST 可推出"与"本项目功能需要"两张独立表；若仍是一张混装表 = 未修。'
      '此判据无法机械判定，因为"哪几个 set 属工程需要"需人读语义。')
human('F-17', '§7.3 是否补 3 个 ERRINFO 码',
      '搜 0x000010EA / 0x000010E9 / 0x000010F4 三个码是否都在 §7.3 出现且带触发条件。'
      '机械可查"是否出现"，但"是否给了正确触发条件"需人读。')
human('F-08/F-09/F-10', '§12 状态机新增迁移是否语义正确',
      '新增的 Set Error Info / Monitor Layout / 兜底迁移，需人读确认：状态不变（不是跳到新状态）、'
      '动作列写的是"记录"而非"处理完成"、且不破坏原有 S1..S6 语义。')
human('F-28', '§8 各节 lengthCapability 标签是否只改标签不改数值',
      '逐个 capability 节看：数值必须仍是 24/28/88/...（与 §14.1 dump 一致），'
      '只允许把 "MUST = N" 改成 "定长 N（结构推导）"。若数值被改动 = 引入新缺陷。')
human('F-31', '§0.2 新增 S90+ 的 guid 是否真实可达',
      '新增登记项必须能 HEAD 200；机械脚本只能查"是否登记"，无法查"guid 是否对应正确章节"。')
human('F-34', 'sourceDescriptor 措辞是否降级为"dump 实测"',
      '看 §4.3/§5.3 是否把"内容为 source descriptor 字符串"改成"dump 实测内容为…；语义见 [T128]（未取证）"。'
      '这是语义降级，机械搜"实测"会有大量误命中。')

# ---------------------------------------------------------------- 汇总
print()
print('=' * 78)
npass = sum(1 for r in RESULTS if r[2])
print('机械判据：%d / %d 通过' % (npass, len(RESULTS)))
fails = [r[0] for r in RESULTS if not r[2]]
print('未通过：%s' % (fails if fails else '无'))
print('需人工判读：%d 条 → %s' % (len(HUMAN), [h[0] for h in HUMAN]))
print('=' * 78)
sys.exit(0 if npass == len(RESULTS) else 1)
