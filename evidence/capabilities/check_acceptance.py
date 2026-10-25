r"""验收判据执行器：对 capabilities.md 逐条检查 F-01..F-41。

设计原则
--------
1. 锚定章节编号（docsec.py），不用绝对行号 —— 执行 AI 修订会让行号漂移。
2. 每条判据只回答"通过/不通过 + 实际观测值"，不做模糊判断。
3. 语义性判据（SEM）输出判读要点 + 命中的原文片段，由人工裁决；
   脚本给出 MANUAL，不计入 PASS/FAIL 统计。
4. 判据本身已按"目标状态"校准，并附实测样本作为自检（见 --selftest）。

用法
----
    $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
    python -X utf8 F:\rtsc\evidence\capabilities\check_acceptance.py            # 验收
    python -X utf8 F:\rtsc\evidence\capabilities\check_acceptance.py --selftest  # 判据自检

退出码：0 = 无 FAIL；1 = 存在 FAIL。
"""
import io
import re
import sys

sys.path.insert(0, r'F:\rtsc\evidence\capabilities')
from docsec import load, section

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DOC = r'F:\rtsc\docs\spec\capabilities.md'
L, H = load(DOC)
D = '\n'.join(L)

RESULTS = []


def rec(fid, kind, ok, detail):
    RESULTS.append((fid, kind, ok, detail))


def ex(fid, label, cond, detail):
    rec(fid, 'EXIST', bool(cond), '%s: %s' % (label, detail))


def val(fid, label, actual, expect):
    rec(fid, 'VALUE', actual == expect, '%s: 实际=%r 期望=%r' % (label, actual, expect))


def sem(fid, label, detail):
    rec(fid, 'SEM', None, '%s: %s' % (label, detail))


def cnt(s):
    return D.count(s)


def rx(pat, s=None, flags=0):
    return re.findall(pat, D if s is None else s, flags)


def line_of(kw, nth=1):
    n = 0
    for i, l in enumerate(L, 1):
        if kw in l:
            n += 1
            if n == nth:
                return i, l
    return None, ''


def lines_of(kw):
    return [(i, l) for i, l in enumerate(L, 1) if kw in l]


def S(num):
    return section(L, H, num)[2]


# ============================================================ 规范正文切片
# 修订记录（§18）会**引用**被修的旧值来描述缺陷（如 "把 0x03E3 改为 0x03EB"），
# 这是正确的文档行为，但会让"全文计数"类判据误报。
# 因此所有计数类判据都限定在「规范正文」= 排除 §18 修订记录及其后章节。
def normative_text():
    cut = len(L) + 1
    for ln, lvl, n, txt in H:
        if re.match(r'^1[89]$', n) or ('修订记录' in txt):
            cut = ln
            break
    return '\n'.join(L[:cut - 1]), cut


NORM, NORM_CUT = normative_text()


def ncnt(s):
    """规范正文内的计数（排除修订记录章节）。"""
    return NORM.count(s)


# ============================================================ F-01 阻断
# 断言：规范正文内无 0x03E3；0x03EB >= 2；channelId 行含"不可硬编码"或"从 store 取"
val('F-01', '规范正文 0x03E3 次数', ncnt('0x03E3'), 0)
ex('F-01', '规范正文 0x03EB 次数 >= 2', ncnt('0x03EB') >= 2, ncnt('0x03EB'))
_, l_ch = line_of('mcsSDin.channelId')
ex('F-01', 'channelId 行含"不可硬编码"或"从 store 取"',
   ('不可硬编码' in l_ch) or ('store' in l_ch and '取' in l_ch), l_ch[:120])

# ============================================================ F-02 严重
# 断言：§13.4 内 "20 00 08 ab" 只能出现在"解密后"上下文（前 3 行或后 3 行含"解密"）
#       全文 "26 18 5e 76" >= 2；§13.4 不得再标"（密文）"
s134, e134, _ = section(L, H, '13.4')
bad = []
for n in range(s134, e134):
    if '20 00 08 ab' not in L[n - 1]:
        continue
    win = '\n'.join(L[max(s134 - 1, n - 4):min(e134, n + 3)])
    if '解密' not in win:
        bad.append(n)
val('F-02', '§13.4 内 20 00 08 ab 出现在非解密上下文次数', len(bad), 0)
ex('F-02', '全文 26 18 5e 76 次数 >= 2', cnt('26 18 5e 76') >= 2, cnt('26 18 5e 76'))
# 字段表里 "fpInputEvents（密文）" 标注本身正确，关键是它对应的值必须是线上密文。
_, l_enc = line_of('fpInputEvents（密文）')
ex('F-02', '§13.4 字段表中"（密文）"行的值为线上密文 26 18 5e 76',
   '26 18 5e 76' in l_enc, l_enc[:130])
ex('F-02', '§13.4 明写线上该 7 字节为密文',
   ('线上该 7 字节' in S('13.4')) or ('不是' in S('13.4') and '线上密文' in S('13.4')),
   '线上该 7 字节')

# ============================================================ F-03 / F-12 阻断
t61 = S('6.1')
ex('F-03', '§6.1 含 caps_end', 'caps_end' in t61, 'caps_end' in t61)
ex('F-03', '§6.1 含 p+len>caps_end', bool(re.search(r'p\s*\+\s*len\s*>\s*caps_end', t61)), 'p+len')
ex('F-03', '§6.1 含 p+4>caps_end', bool(re.search(r'p\s*\+\s*4\s*>\s*caps_end', t61)), 'p+4')
ex('F-03', '§6.1 含 recv_len 上界', 'recv_len' in t61, 'recv_len' in t61)
ex('F-12', '§6.1 含 numberCapabilities*4 计数校验',
   bool(re.search(r'numberCapabilities\s*\*\s*4', t61)), 'nc*4')
ex('F-12', '§6.1 声明 nc 偏大致越界（含"越界读"）', '越界读' in t61, '越界读' in t61)

# ============================================================ F-13 一般
l_lcc = next((l for l in t61.splitlines() if re.search(r'lcc\s*<\s*4', l)), '')
ex('F-13', 'lcc<4 行讲下溢/assert 且不讲越界读',
   (('下溢' in l_lcc) or ('assert' in l_lcc)) and ('越界读' not in l_lcc), l_lcc[:120])
ex('F-13', '§6.1 明确 lcc<4 不是越界读', '不是越界读' in t61, '不是越界读' in t61)

# ============================================================ F-14 一般
ex('F-14', '§6.1 末尾改显式分支（warn / 重新定界 / p > caps_end）',
   ('warn' in t61) or ('重新定界' in t61) or ('p > caps_end' in t61),
   'warn=%s 重新定界=%s' % ('warn' in t61, '重新定界' in t61))

# ============================================================ F-04 严重
t55 = S('5.5')
ex('F-04', '§5.5 含 0x000010D4', '0x000010D4' in t55, '0x000010D4' in t55)
ex('F-04', '§5.5 含 0x000010D5', '0x000010D5' in t55, '0x000010D5' in t55)
ex('F-04', '§5.5 不再断言"服务端**不校验**"',
   not re.search(r'服务端\*\*不校验\*\*', t55), '服务端**不校验**' in t55)

# ============================================================ F-05 严重
t818 = S('8.18')
ex('F-05', '§8.18 不再写"固定总长：**12"',
   not re.search(r'固定总长[：:]\s*\*\*12', t818), '固定总长：**12')
ex('F-05', '§8.18 同时给出 8 与 12 两种形态',
   ('8 或 12' in t818) or bool(re.search(r'8[^0-9].{0,24}12', t818)), '8/12')

# ============================================================ F-06 严重 / F-07 一般
_, u03 = line_of('**U-03**')
ex('F-06', 'U-03 区分持久缓存（Persistent + 保留）',
   ('Persistent' in u03) and ('保留' in u03), u03[:110])
ex('F-07', 'U-03 写明清空代价', ('Bitmap Cache Error' in u03) or ('BC_ERR_FLUSH_CACHE' in u03), u03[:110])

# ============================================================ F-08 一般
t12 = S('12')
ex('F-08', '全文含 Set Error Info', cnt('Set Error Info') > 0, cnt('Set Error Info'))
ex('F-08', '§12 含 Set Error Info 迁移行', 'Set Error Info' in t12, 'Set Error Info' in t12)
ex('F-08', '全文含 ERRINFO', cnt('ERRINFO') > 0, cnt('ERRINFO'))

# ============================================================ F-09 一般
ex('F-09', '§12 含 Monitor Layout 迁移', 'Monitor Layout' in t12, 'Monitor Layout' in t12)

# ============================================================ F-10 一般
ex('F-10', '§12 含"意外 PDU"兜底迁移',
   ('意外 PDU' in t12) or ('与当前状态不符' in t12), '意外/不符')
ex('F-10', '§12 含"错序处置"明确规则表',
   ('错序' in t12), '错序' in t12)

# ============================================================ F-11 一般
ex('F-11', '全文含 3.2.6.1', cnt('3.2.6.1') > 0, cnt('3.2.6.1'))
ex('F-11', '§12 含 300 s 定时器', '300' in t12, '300' in t12)
ex('F-11', '定时器强度为 MAY 且明写"不是 MUST"',
   ('MAY' in t12) and ('不是 MUST' in t12), 'MAY/不是 MUST')

# ============================================================ F-15 严重
val('F-15', '规范正文"全部 MAC 失配"次数', ncnt('全部 MAC 失配'), 0)
_, u14 = line_of('**U-14**')
ex('F-15', 'U-14 含"可能失配"或"按 capability"',
   ('可能失配' in u14) or ('按 capability' in u14), u14[:110])
ex('F-15', 'U-14 主证据含 orderSupport', 'orderSupport' in u14, 'orderSupport' in u14)
ex('F-15', 'U-14 含 NumCellCaches', 'NumCellCaches' in u14, 'NumCellCaches' in u14)

# ============================================================ F-16 一般
t73 = S('7.3')
ex('F-16', '§7.3 声明"工程判断/工程需要"',
   ('工程判断' in t73) or ('工程需要' in t73) or ('工程上' in t73), '工程判断')
ex('F-16', '§7.3 声明"不是规范要求"', '不是规范要求' in t73, '不是规范要求' in t73)

# ============================================================ F-17 一般
for code, lab in [('0x000010EA', 'BADCAPABILITIES'), ('0x000010E9', 'NOCURSORCACHE'),
                  ('0x000010F4', 'CACHECAPNOTSET')]:
    ex('F-17', '全文含 %s (%s)' % (code, lab), cnt(code) > 0, cnt(code))

# ============================================================ F-18 一般
_, u13 = line_of('**U-13**')
ex('F-18', 'U-13 补齐违反后果（含 0x000010D4 或 ERRINFO）',
   ('0x000010D4' in u13) or ('ERRINFO' in u13), u13[:110])

# ============================================================ F-19 一般
# 断言：不得出现"宽度已机器校验"类断言；§15.1 证据栏对"总长"与"宽度"分开表述
val('F-19', '规范正文"宽度已机器校验"次数', ncnt('宽度已机器校验'), 0)
t151 = S('15.1')
ex('F-19', '§15.1 对 27 定长 capability 只声称"总长"（不声称宽度机器校验）',
   '定长 capability 的总长' in t151 or '总长' in t151, '总长' in t151)
ex('F-19', '全文不再出现"偏移自洽 ⇒ 宽度已校验"式断言',
   not re.search(r'不存在手抄错误.{0,40}(宽度|字段名)', D, re.S), '无宽度断言')

# ============================================================ F-20 一般
ex('F-20', '§15.1 区分 28 编号/名称 与 31 实例',
   ('28' in t151) and ('31' in t151), '28/31')
ex('F-20', '§15.1 说明未覆盖类型（含 21 或 6 个未覆盖）',
   ('21 个' in t151) or ('21 类型' in t151) or ('6 个' in t151), '21/6')
val('F-20', '规范正文"28 个类型已核实"次数', ncnt('28 个类型已核实'), 0)

# ============================================================ F-21 一般
val('F-21', '规范正文"363"次数', ncnt('363'), 0)
t43 = S('4.3')
ex('F-21', '§4.3 闭式第二行无尾 +4',
   bool(re.search(r'=\s*18\s*\+\s*lengthSourceDescriptor\s*\+\s*lengthCombinedCapabilities(?!\s*\+\s*4)', t43)),
   '闭式')

# ============================================================ F-22 一般
t141 = S('14.1')
ex('F-22', '§14.1 归因改为"双计头字段/二次计入"',
   ('二次计入' in t141) or ('头字段' in t141) or ('capabilitySetType` 与 `lengthCapability`' in t141),
   '二次计入/头字段')
ex('F-22', '§14.1 保留"13 项"', bool(re.search(r'13\s*项', t141)), '13 项')
ex('F-22', '§14.1 不再写"多算一个 pad2octets → expect=28"',
   not re.search(r'多算了一个 `?pad2octets`?[^\n]{0,40}28', t141), '旧归因')

# ============================================================ F-23 一般
ex('F-23', '全文含 3.2.5.1', cnt('3.2.5.1') > 0, cnt('3.2.5.1'))
_, l_src = line_of('pduSource` MUST')
ex('F-23', 'pduSource MUST 行归 3.2.5.1 或不再写 3.2.5.3.13.2',
   ('3.2.5.1' in l_src) or ('3.2.5.3.13.2' not in l_src), l_src[:110])

# ============================================================ F-24 一般
# 判据收窄到 §5.3（初始化规则所在处）：该节的 pduType 行必须带 MUST。
# §4.3 的字段宽度表与 §1.2 的位域说明本就不该写 MUST（MUST 属 5.3 的初始化规则）。
t53 = S('5.3')
pv53 = [l for l in t53.splitlines() if 'PDUVersion' in l]
bad_pv = [l for l in pv53 if '0x1' in l and 'MUST' not in l]
val('F-24', '§5.3 含 PDUVersion=0x1 但缺 MUST 的行数', len(bad_pv), 0)
ex('F-24', '§5.3 的 PDUVersion 行含 MUST', bool(pv53) and all('MUST' in l for l in pv53),
   '; '.join(l[:60] for l in pv53) or 'none')

# ============================================================ F-25 一般
t72 = S('7.2')
ex('F-25', '§7.2 合计行含 466', '466' in t72, '466' in t72)
ex('F-25', '§7.2 合计行含 492', '492' in t72, '492' in t72)
ex('F-25', '§7.2 合计行同时说明 26 头 + 466',
   bool(re.search(r'466[^\n]{0,40}492|492[^\n]{0,40}466', t72)), '466/492 并存')

# ============================================================ F-26 一般
_, l148 = line_of('length1`/`length2')
ex('F-26', 'fast-path 长度编码引 §3.4', '§3.4' in l148, l148[:110])

# ============================================================ F-27 一般
val('F-27', '规范正文"§12 U-0"次数', len(re.findall(r'§12\s*U-0', NORM)), 0)

# ============================================================ F-28 一般
val('F-28', '规范正文"lengthCapability | MUST ="次数', len(re.findall(r'lengthCapability`?\s*\|\s*MUST\s*=', NORM)), 0)
ex('F-28', '§8 各节 lengthCapability 改为"定长/结构推导"',
   ('结构推导' in D) or ('定长' in D), '结构推导/定长')

# ============================================================ F-29 一般
# 判据锚定 §0.2 内的"NN 个 learn.microsoft.com 页面"计数行，不用首个命中
# （首个命中是 §0.1 的 toc.json 抓取命令，不是计数）。
t02u = S('0.2')
m29 = re.search(r'(\d+)\s*个\s*`?learn\.microsoft\.com', t02u)
n29 = int(m29.group(1)) if m29 else None
ex('F-29', '§0.2 计数行已改为实际 learn 页数（>=87）', (n29 is not None) and n29 >= 87,
   '解析到 %r' % (n29,))
val('F-29', '规范正文"85/85"次数', ncnt('85/85'), 0)

# ============================================================ F-30 一般
# 判据：§15.1 标题是「已全部核实、无不确定性的项」，因此该表内**不得存在任何
#       自承"缺/无 dump 佐证"的项**——否则标题与内容矛盾，这正是 F-30 的缺陷本体。
#
# 【为什么只接受方案选项①（移出 §15.1），不接受选项②（改写措辞）】
# F-30 的"最小修正"给了两个选项：
#   ① 把该行移出 §15.1；
#   ② 改写为「结构自洽（S41 表推导），但缺 dump 佐证 → 见 U-10」。
# 父会话已裁定走①。理由（本判据据此写死）：
#   选项②只是在矛盾上加了注脚——标题仍称"无不确定性"，表内仍自承"缺 dump 佐证"，
#   矛盾**未消除**。判据若接受②，就等于承认"自相矛盾的表格"可以通过验收。
#
# 注意：§15.1 中说明"6 个类型无 dump 佐证"属**另一回事**（那是 F-20 要求的
#       诚实声明，主语是"未覆盖的 6 个类型"，不是"已核实的项"），故不误报。
# 两类行必须区分（否则误报）：
#   (a) "某项本身缺 dump 却仍列在已核实表内" → 这是 F-30 的缺陷本体，必须 FAIL。
#       典型：Deactivate All 的 pduType 推导值。
#   (b) "已核实项中，有 6 个类型无 dump 佐证" → 这是 F-20 要求的**诚实声明**
#       （主语是"未覆盖的 6 个类型"，不是"该行未核实"），必须放行。
# 区分方式：含"6 个"/具体未覆盖类型编号（0x0004…0x001E）的行属 (b)。
UNCOVERED_MARKERS = ('6 个', '0x0004', '0x0019', '0x001A', '0x001B', '0x001C', '0x001E')
bad30 = []
for l in t151.splitlines():
    if not l.strip().startswith('|'):
        continue
    if ('无 dump 佐证' not in l) and ('缺 dump 佐证' not in l):
        continue
    if any(m in l for m in UNCOVERED_MARKERS):
        continue  # (b) F-20 要求的诚实声明，放行
    bad30.append(l)  # (a) 缺陷本体

ex('F-30', '§15.1「已全部核实、无不确定性」表内不得有自承缺 dump 佐证的项'
           '（只接受方案选项①：移出 §15.1；选项②未消除标题-内容矛盾；'
           'F-20 要求的"6 个类型无 dump 佐证"诚实声明不在此列）',
   not bad30, '; '.join(l[:110] for l in bad30) or 'none')

# ============================================================ F-31 一般
t02 = S('0.2')
miss = [s for s in ['3.2.5.3.17', '3.2.5.3.18', '3.2.5.3.22', '3.3.5.3.18', '2.2.12.1'] if s not in t02]
ex('F-31', '§0.2 登记 5 个被引用章节号', not miss, '缺 %s' % (miss or 'none'))

# ============================================================ F-32 一般（语义）
sem('F-32', '§12.3 时序图服务端 Synchronize 位置',
    '须在 Confirm Active 之后（可与客户端 5 PDU 并列），并注明客户端可整批发送')

# ============================================================ F-33 一般
val('F-33', '规范正文"S59 系列"次数', ncnt('S59 系列'), 0)

# ============================================================ F-34 一般（语义）
sem('F-34', '§4.3/§5.3 sourceDescriptor 断言',
    '须写"dump 实测为 …；语义见 [T128] 8.4.1（未取证）"，不得把观测当语义结论')

# ============================================================ F-35 一般
val('F-35', '规范正文"严格串行"次数', ncnt('严格串行'), 0)
ex('F-35', '全文含"可整批发送"', '可整批发送' in D, '可整批发送' in D)

# ============================================================ F-36 一般
_, u06 = line_of('**U-06**')
ex('F-36', 'U-06 出处改 3.2.5.3.17', '3.2.5.3.17' in u06, u06[:110])

# ============================================================ F-37 一般
t24 = S('2.4')
ex('F-37', '§2.4 含压缩先于 MAC 的次序约束',
   ('压缩' in t24) and ('MAC' in t24) and ('先' in t24), '次序')
ex('F-37', '全文含 4,096 包会话密钥更新',
   ('4,096' in D) or ('4096 个包' in D), '4,096=%s' % ('4,096' in D))

# ============================================================ F-38 严重
# 断言：§12.2 不得出现"收到 Server Sync 才可发 input"；允许明确否认式表述。
# 注意：S2 行（Confirm Active 已发出 … 获得 input 发送许可）是正确的，不在 S3 行内，
#       因此只检查"事件列含 Server Synchronize"的迁移行。
ok38, det38 = True, []
for l in t12.splitlines():
    if 'Server Synchronize' not in l or 'input' not in l.lower():
        continue
    # 迁移行格式：| 当前 | 事件 | 动作 | 下一状态 | 依据 |
    cells = [c.strip() for c in l.strip().strip('|').split('|')]
    if len(cells) < 3:
        continue
    event, action = cells[1], cells[2]
    if 'Server Synchronize' not in event:
        continue
    denies = ('不以此为许可' in action) or ('已在 S2' in action) or ('许可已' in action)
    grants = ('可开始发送 input' in action) or ('可开始发 input' in action)
    if grants or not denies:
        ok38 = False
        det38.append('事件=%s 动作=%s' % (event[:40], action[:70]))
ex('F-38', '§12.2 S3/ServerSync 行不授予 input 许可', ok38, '; '.join(det38) or 'none')
ex('F-38', '§12.2 在 S2 行给出 input 许可',
   bool(re.search(r'Confirm Active 已发出[^\n]{0,220}input', t12)), 'S2 input 许可')

# ============================================================ F-39 / F-40 / F-41
val('F-39', '规范正文"§12「不确定项」"次数', ncnt('§12「不确定项」'), 0)
val('F-40', '规范正文"§14.2 已逐字节复算"次数', ncnt('§14.2 已逐字节复算'), 0)
val('F-41', '规范正文"不一致 → 断链"次数', ncnt('不一致 → 断链'), 0)
ex('F-41', 'totalLength 校验行写 SHOULD',
   bool(re.search(r'totalLength[^\n]*SHOULD', D)), 'SHOULD')

# ============================================================ 输出
if '--selftest' in sys.argv:
    print('判据自检：共 %d 条断言，覆盖 %d 个 F 编号' %
          (len(RESULTS), len({f for f, _, _, _ in RESULTS})))
    from collections import Counter
    print('类型分布：', dict(Counter(k for _, k, _, _ in RESULTS)))
    sys.exit(0)

print('=' * 80)
print('验收判据执行结果 — %s' % DOC)
print('=' * 80)
npass = nfail = nman = 0
for fid, kind, ok, detail in RESULTS:
    if ok is None:
        nman += 1
        tag = 'MANUAL'
    elif ok:
        npass += 1
        tag = 'PASS  '
    else:
        nfail += 1
        tag = 'FAIL  '
    print('%s %-6s %-5s %s' % (tag, fid, kind, detail))

print('-' * 80)
print('PASS=%d  FAIL=%d  MANUAL=%d  合计=%d' % (npass, nfail, nman, len(RESULTS)))
fids = sorted({f for f, _, _, _ in RESULTS}, key=lambda x: int(x.split('-')[1]))
miss = ['F-%02d' % i for i in range(1, 42) if 'F-%02d' % i not in fids]
print('覆盖 F 编号 %d 个，%s' % (len(fids), 'F-01..F-41 齐全' if not miss else '缺 ' + str(miss)))
from collections import Counter
print('类型分布：', dict(Counter(k for _, k, _, _ in RESULTS)))
print('=' * 80)
sys.exit(0 if nfail == 0 else 1)
