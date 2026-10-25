"""17 条判据的变异测试（mutation test）—— §17.7 第 5 条"负向红证"的全量版。

v2（本轮）：新增 **翻红原因断言**（§17.9.7 第 6 条）。
仅断言"翻红了"是不够的——翻红可能是**别的原因**（例如文本变长导致另一个无关正则失配）。
因此每个用例除 `翻红=True` 外，还断言目标判据的 reason 文本含预期关键词，
证明"翻红的原因正是判据想测的那个语义"。

对每条判据，在内存里构造一个**只破坏该判据**的文档副本，写到 .tmp，
用 CAPS_DOC 环境变量喂给 accept_consult_b.py，断言：
  (1) 目标判据必须 FAIL（证明判据有区分力，不是恒真）；
  (2) 目标判据的 reason 必须含预期关键词（证明翻红原因正确，不是别的断言失配）；
  (3) 记录串扰（= 多个判据指向同一缺陷，属预期，不是错误）。

不修改 capabilities.md 正本；变异副本写到 F:\\rtsc\\.tmp\\_mut_caps.md 并在结束时删除。
"""
import io
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DOC = r'F:\rtsc\docs\spec\capabilities.md'
SCRIPT = r'F:\rtsc\evidence\capabilities\accept_consult_b.py'
TMPD = r'F:\rtsc\.tmp'
MUTDOC = os.path.join(TMPD, '_mut_caps.md')
ORIG = io.open(DOC, encoding='utf-8').read()


def sub_all(old, new, count=-1):
    def f(s):
        if old not in s:
            raise SystemExit('ANCHOR-MISSING: %r' % old[:60])
        return s.replace(old, new, count)
    return f


def sub_in_section(head, old, new, count=-1):
    """只在某个 ###/## 小节内替换，避免影响别处。"""
    def f(s):
        i = s.index(head)
        cands = [x for x in (s.find('\n### ', i + 1), s.find('\n## ', i + 1)) if x != -1]
        k = min(cands) if cands else len(s)
        blk = s[i:k]
        if old not in blk:
            raise SystemExit('ANCHOR-MISSING(%s): %r' % (head, old[:50]))
        return s[:i] + blk.replace(old, new, count) + s[k:]
    return f


def chain(*fs):
    def f(s):
        for g in fs:
            s = g(s)
        return s
    return f


def drop_persistent(s):
    i = s.index('| **U-03** |')
    j = s.index('\n', i)
    row = s[i:j]
    if 'Persistent' not in row:
        raise SystemExit('ANCHOR-MISSING: U-03 行无 Persistent')
    return s[:i] + row.replace('Persistent', '长效缓存') + s[j:]


# (标签, 目标判据, 变异函数, 翻红原因必须含的关键词)
# 关键词取自各判据 add() 的 reason 模板中**随变异而变化**的那一段，
# 不是随便挑的词——这样它只能被"预期语义"满足，不能被无关断言失配满足。
MUTS = [
    # ---- F-15：在 U-14 行塞入绝对 MAC 断言
    # reason 模板：'绝对失配次数=%d'，变异后应为 1（基线 0）
    ('F-15 绝对 MAC 断言', 'F-15',
     sub_all('未禁止重复 |', '未禁止重复，全部 MAC 失配 |'),
     '绝对失配次数=1'),

    # ---- F-13：在**含 lcc<4 的行**上插入一处未被否定的"越界"
    # reason 模板：'越界出现=%d 未被否定=%s'。基线作用域内"越界"只有 1 次
    # （行 904 的"不是越界读"，被否定语境豁免）；变异后再加 1 次且未被否定。
    # 断言 '未被否定=[' —— 直接证明"否定语境检查真的抓到了"，比断言计数更贴语义。
    ('F-13 未否定的越界', 'F-13',
     sub_all('# 否则 lcc - 4 在 uint16 下溢为 65534',
             '# 这会导致越界'),
     '未被否定=['),

    # ---- F-03/F-12：抹掉 §6.1 内**全部**威胁模型词
    # reason 模板：'"对端可控"=%d'，变异后应为 0
    ('F-03/F-12 无威胁模型', 'F-03/F-12',
     chain(sub_in_section('### 6.1', '（对端可控）', '（外部输入）'),
           sub_in_section('### 6.1', '可被对端触发的内存越界',
                          '可被触发的内存越界')),
     '"对端可控"=0'),

    # ---- F-06：U-03 行去掉**所有** Persistent
    # reason 模板：'Persistent=%s'，变异后应为 False
    ('F-06 缺 Persistent', 'F-06', drop_persistent,
     'Persistent=False'),

    # ---- F-38：§12.2 重新把 input 许可挂到 Server Synchronize
    # reason 模板：'仍挂 input 的行数=%d'，变异后应为 1（基线 0）
    ('F-38 input 挂 Server Synchronize', 'F-38',
     sub_in_section('### 12.2', '### 12.2 状态迁移表',
                    '### 12.2 状态迁移表\n\n> 收到 Server Synchronize 后可开始发 input。'),
     '仍挂 input 的行数=1'),

    # ---- F-41：删掉动作部分的 SHOULD（保留"；原文 SHOULD be dropped"引用）
    # reason 模板：'动作部分含 SHOULD=%d 行'，变异后应为 0（基线 1）
    # 这一条最关键：它同时验证"剥离引用"的逻辑真的生效了
    ('F-41 动作缺 SHOULD', 'F-41',
     sub_all('不一致 → **SHOULD** 断链（§2.1 / §4.4', '不一致 → 断链（§2.1 / §4.4'),
     '动作部分含 SHOULD=0'),

    # ---- F-02：把 §13.4 **表格行**的密文改回明文
    # reason 模板：'密文表格行=%s（需>=1）'，变异后应为空列表
    ('F-02 表格回退明文', 'F-02',
     sub_all('`fpInputEvents（密文）` | `26 18 5e 76 0e de 28`',
             '`fpInputEvents（密文）` | `20 00 08 ab 02 6f 01`'),
     '密文表格行=[]'),

    # ---- F-21：把闭式改回带 +4 的错误写法
    # reason 模板：'仍含 "+ lengthCombinedCapabilities + 4" 的行=%s'
    ('F-21 闭式 +4', 'F-21',
     sub_all('= 18 + lengthSourceDescriptor + lengthCombinedCapabilities\n',
             '= 18 + lengthSourceDescriptor + lengthCombinedCapabilities + 4\n'),
     '[751]'),

    # ---- F-29：把自述计数改错（97 → 85）
    # reason 模板：'文档自述计数=%s'，变异后应为 [85]
    ('F-29 计数不符', 'F-29',
     sub_all('97 个 `learn.microsoft.com`', '85 个 `learn.microsoft.com`'),
     '文档自述计数=[85]'),

    # ---- F-35：正文重新出现"严格串行"
    # reason 模板：'仍含"严格串行"的行=%s'
    ('F-35 严格串行', 'F-35',
     sub_all('## 15. 不确定项清单', '发送路径严格串行。\n\n## 15. 不确定项清单'),
     '严格串行"的行=['),

    # ---- F-37：把 4,096 全部改成 4096（无千分位）
    # reason 模板：'含 4,096 的行=%s'
    ('F-37 无 4,096', 'F-37',
     lambda s: s.replace('4,096', '4096'),
     '未补'),

    # ---- F-28：塞一行 LengthCapability | MUST = N
    # reason 模板：'残留行=%s'
    ('F-28 残留 MUST=N', 'F-28',
     sub_all('| 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |',
             '| 2 | 2 | `LengthCapability` | MUST = 8 |'),
     '残留行=['),

    # ---- F-30 本体：塞一行自承缺 dump 且不属于 6 类型豁免
    # reason 模板：'违规行=%s'
    ('F-30 自承未核实', 'F-30',
     sub_all('| Font List / Font Map 均为 26 字节 |',
             '| 某个未知项 | 无 dump 佐证 |\n| Font List / Font Map 均为 26 字节 |'),
     '违规行=['),

    # ---- F-20 披露：删掉"6 个"
    # reason 模板：'含"6 个…无 dump 佐证"的行数=%d'，变异后应为 0
    ('F-20 缺 6 类型披露', 'F-20',
     sub_all('另有 6 个类型（', '另有类型（'),
     '的行数=0'),

    # ---- F-20 恒等式：把 **§6.2 表**里的 Bitmap 类型号改掉
    # reason 模板：'并集=28=%s'，变异后应为 False
    ('F-20 恒等式失衡', 'F-20',
     sub_in_section('### 6.2', '| 0x0002 | `CAPSTYPE_BITMAP` |',
                    '| 0x00F2 | `CAPSTYPE_BITMAP` |'),
     '并集=28=False'),

    # ---- F-30 导语强度：把削弱语改成绝对声明
    # reason 模板：'判定=%s'，变异后应含"绝对语"
    ('F-30 导语绝对化', 'F-30',
     sub_all('以下各项**已用官方原文核实**；多数另有官方 dump 佐证，'
             '个别仅有原文表比对（逐行注明核实方式），可作确定事实使用：',
             '以下各项**已用官方原文 + dump 双向核实**，可作确定事实使用：'),
     '绝对语'),
]


def run(doc_text):
    io.open(MUTDOC, 'w', encoding='utf-8', newline='\n').write(doc_text)
    env = dict(os.environ)
    env['CAPS_DOC'] = MUTDOC
    env['TEMP'] = TMPD
    env['TMP'] = TMPD
    r = subprocess.run([sys.executable, '-X', 'utf8', SCRIPT],
                       capture_output=True, env=env)
    out = r.stdout.decode('utf-8', errors='replace')
    fails, passes, reasons = [], [], {}
    lines = out.splitlines()
    for k, l in enumerate(lines):
        m = re.match(r'^\[(PASS|FAIL)\]\s+(\S+)', l)
        if not m:
            continue
        st, fid = m.group(1), m.group(2)
        reason = lines[k + 1].strip() if k + 1 < len(lines) else ''
        if st == 'FAIL':
            fails.append(fid)
        else:
            passes.append(fid)
        reasons.setdefault(fid, []).append(reason)
    return r.returncode, fails, passes, reasons


rc0, f0, p0, _ = run(ORIG)
print('基线：PASS=%d FAIL=%d exit=%d' % (len(p0), len(f0), rc0))
if f0:
    print('基线不为全绿，先修基线：', f0)
    os.remove(MUTDOC)
    raise SystemExit(1)
print()

all_ok = True
n_hit = 0
n_reason = 0
for label, target, mut, kw in MUTS:
    try:
        txt = mut(ORIG)
    except SystemExit as e:
        print('[SKIP] %-28s %s' % (label, e))
        all_ok = False
        continue
    if txt == ORIG:
        print('[SKIP] %-28s 变异未生效（文本相同）' % label)
        all_ok = False
        continue
    rc, fails, passes, reasons = run(txt)
    hit = target in fails
    side = [x for x in fails if x != target]
    rs = reasons.get(target, [])
    reason_ok = any(kw in r for r in rs)
    ok = hit and rc == 1 and reason_ok
    all_ok &= ok
    n_hit += 1 if hit else 0
    n_reason += 1 if reason_ok else 0
    print('[%s] %-28s 目标=%-10s 翻红=%-5s 原因=%-5s exit=%d 串扰=%s'
          % ('PASS' if ok else 'BAD', label, target, hit, reason_ok, rc, side or '无'))
    if hit and not reason_ok:
        print('            期望原因含 %r，实际 reason=%s' % (kw, rs))
    if not hit:
        print('            目标未翻红；实际 FAIL=%s' % (fails or '无'))

print()
print('变异测试：翻红 %d/%d，原因正确 %d/%d' % (n_hit, len(MUTS), n_reason, len(MUTS)))
print('结论:', '全部符合预期' if all_ok else '有不符合预期')
os.remove(MUTDOC)
if not all_ok:
    raise SystemExit(1)
print('ASSERT OK')
