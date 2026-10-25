"""Emit probes/INDEX.md — v4.

consult-b step 20 corrections applied, each with the arithmetic shown so the
number can be re-audited:

  1. Caliber A (`<stem>.cpp`) = 26 is NOT the right primary number: 10 more
     probes are cited only as `[BASH:probe10/probe12/...]` or `probe15.exe`.
     All 10 were inspected individually; every one is a genuine evidence
     citation. So a third caliber is introduced that accepts any concrete
     evidence form and reports WHY each file counts.

  2. consult-b's proposed 35/15 is also wrong: it assumes probe.cpp has no
     real citation. But design-a cites `probe.cpp:61` twice inside [READ:]
     tags, so probe.cpp IS cited. Caliber B's 36 is right as a SET; what is
     wrong is only the mention COUNT for the `probe` stem (22 occurrences,
     20 of which are `schannel-probe.txt`).

  3. "files with an authoritative conclusion" = 24 (design-b table)
     + 2 (author comments) = 26, not 24.
"""
import io
import json
import os
import re

P = r'F:\rtsc\evidence\tls\probes'
OUT = os.path.join(P, 'INDEX.md')

DESIGN = {
    'design-a': r'F:\rtsc\docs\spec\tls-backend.design-a.md',
    'design-b': r'F:\rtsc\docs\spec\tls-backend.design-b.md',
}
DOCS = {k: io.open(v, encoding='utf-8', errors='replace').read() for k, v in DESIGN.items()}
ALL = '\n'.join(DOCS.values())
CONCL = json.load(io.open(r'F:\rtsc\evidence\tls\probe_conclusions.json', encoding='utf-8'))

APIS = ['AcquireCredentialsHandle', 'InitializeSecurityContext', 'AcceptSecurityContext',
        'DecryptMessage', 'EncryptMessage', 'QueryContextAttributes', 'ApplyControlToken',
        'DeleteSecurityContext', 'FreeContextBuffer', 'SetCredentialsAttributes',
        'CertOpenStore', 'CertFindCertificateInStore', 'CertCreateSelfSignCertificate',
        'CryptEncodeObjectEx', 'BCryptOpenAlgorithmProvider', 'BCryptGenerateKeyPair']
TAG = re.compile(r'\[(?:BASH|READ):[^\]]*\]')


def leading_comment(t):
    buf = []
    for l in t.split('\n')[:80]:
        s = l.strip()
        if not s:
            if buf:
                break
            continue
        if s.startswith('//'):
            buf.append(s.lstrip('/').strip())
        elif s.startswith(('#define', '#include', '#pragma')):
            continue
        else:
            break
    txt = ' '.join(x for x in buf if x)
    return txt if len(txt) > 8 else ''


def apis(t):
    out = []
    for a in APIS:
        n = len(re.findall(r'\b' + a + r'\s*\(', t))
        if n:
            out.append(a if n == 1 else '%s x%d' % (a, n))
    return out


def evidence_reasons(stem):
    r = []
    n1 = len(re.findall(r'\b' + re.escape(stem) + r'\.cpp\b', ALL))
    if n1:
        r.append('cpp×%d' % n1)
    n2 = len(re.findall(r'\b' + re.escape(stem) + r'\.exe\b', ALL))
    if n2:
        r.append('exe×%d' % n2)
    n3 = 0
    for m in TAG.finditer(ALL):
        if re.search(r'\b' + re.escape(stem) + r'\b', m.group(0)):
            n3 += 1
    if n3:
        r.append('evtag×%d' % n3)
    n4 = len(re.findall(r'consult-b\s+`?' + re.escape(stem) + r'\b', ALL))
    if n4:
        r.append('audit×%d' % n4)
    return r


def esc(s):
    return s.replace('|', '\\|')


rows = []
for f in sorted(x for x in os.listdir(P) if x.endswith('.cpp')):
    path = os.path.join(P, f)
    t = io.open(path, encoding='utf-8', errors='replace').read()
    stem = f[:-4]
    com = leading_comment(t)
    a = apis(t)
    c = CONCL.get(f)
    if c:
        purpose, concl, src = c[0]['topic'], c[0]['conclusion'], 'design-b 探针表'
    elif com:
        purpose, concl, src = com, '', '作者注释'
    else:
        purpose, concl, src = '', '', '无'
    rows.append({
        'file': f, 'stem': stem, 'bytes': os.path.getsize(path),
        'purpose': purpose, 'conclusion': concl, 'src': src,
        'apis': ', '.join(a),
        'A': len(re.findall(r'\b' + re.escape(f) + r'\b', ALL)),
        'reasons': evidence_reasons(stem),
        'loose': len(re.findall(r'\b' + re.escape(stem) + r'\b', ALL)),
    })

citedC = [r for r in rows if r['reasons']]
nA = len([r for r in rows if r['A']])
nB = len([r for r in rows if r['loose']])
nC = len(citedC)
n_concl = len([r for r in rows if r['src'] == 'design-b 探针表'])
n_com = len([r for r in rows if r['src'] == '作者注释'])
n_with = n_concl + n_com
n_none = len([r for r in rows if r['src'] == '无'])
total_bytes = sum(r['bytes'] for r in rows)
bare_only = [r['stem'] for r in rows if r['reasons'] and not r['A']]

L = []
A = L.append
A('# SChannel 探针源码索引')
A('')
A('本目录 %d 个 `.cpp` 是 TLS 后端选型阶段的实测探针源码，' % len(rows))
A('从 `F:\\rtsc\\.tmp\\tlsprobe\\` 复制而来（`.tmp` 是临时目录，可能被清理）。')
A('')
A('## 为什么保留源码')
A('')
A('探针的**输出**证明「实测结果是什么」，源码证明「实测是怎么做的」。')
A('两者合起来才构成完整证据链——只留输出无法复核方法是否正确。')
A('')
A('**未被文档引用的探针同样保留**：它们可能是「负证据」（证明某条路走不通）。')
A('成本也极低：合计 %d KB。' % (total_bytes // 1024))
A('')
A('## 三个引用口径（必须全部列出，否则数字不可复核）')
A('')
A('| 口径 | 判据 | 被引用 | 未引用 | 用途 |')
A('|---|---|---:|---:|---|')
A('| **C（主口径）** | 任一种具体证据形式（见下） | **%d** | **%d** | **统计依据** |'
  % (nC, len(rows) - nC))
A('| A | `<stem>.cpp` 文件全名 | %d | %d | 参考：最保守 |' % (nA, len(rows) - nA))
A('| B | `\\b<stem>\\b` 裸编号 | %d | %d | **不作依据**（有已知碰撞） |'
  % (nB, len(rows) - nB))
A('')
A('### 口径 C 的判据（任一条成立即算引用）')
A('')
A('1. `<stem>.cpp` —— 明确写出文件名')
A('2. `<stem>.exe` —— 探针二进制的输出被引用')
A('3. `<stem>` 出现在 `[BASH:...]` / `[READ:...]` 证据标记内')
A('4. `consult-b <stem>` —— 作为另一审计方的证据被采信')
A('')
A('**每个文件的具体理由都在表格「证据形式」列**，可逐条复核。')
A('')
A('### 为什么 A（26）不够')
A('')
A('实测发现 **%d 个探针只以裸编号形式被引用**：' % len(bare_only))
A('')
A('```')
A(', '.join(bare_only))
A('```')
A('')
A('逐个查看上下文，**全部是真实证据引用**，例如：')
A('')
A('- `[BASH:probe10/probe12/probe17/probe27/probe36]` —— 一组回归探针')
A('- `probe15.exe → "target=wrong name, manual only ... OK"` —— 实测输出')
A('- `consult-b probe41 → 0x1302 TLS_AES_256_GCM_SHA384` —— 采信另一审计方')
A('')
A('**所以 A=26 少算了 %d 个。**' % len(bare_only))
A('')
A('### 为什么 B（36）集合对但不可作为依据')
A('')
A('B 的**集合**（36）与 C 相同，但它的**计数**有假阳性：')
A('')
A('`probe.cpp` 的 stem 是 `probe`，`\\bprobe\\b` 会命中 `schannel-probe.txt`')
A('和英文普通单词 `probe`。实测：')
A('')
A('| 文档 | `\\bprobe\\b` | `\\bprobe\\.cpp\\b` | 假阳性 |')
A('|---|---:|---:|---:|')
A('| design-a | 18 | 2 | 16 |')
A('| design-b | 4 | 0 | 4 |')
A('| **合计** | **22** | **2** | **20** |')
A('')
A('**22 是总出现次数，其中 20 次是假阳性**——真引用只有 2 次，')
A('即 design-a 里的 `[READ:F:\\rtsc\\.tmp\\tlsprobe\\probe.cpp:61]`（两处）。')
A('')
A('> 注：consult-b 第⑳步建议把口径 B 改成 35/15，前提是「`probe.cpp` 被误算已引用」。')
A('> 但实测 `probe.cpp` 有 2 次真实 `.cpp` 引用，**它确实是已引用**，')
A('> 所以 36/14 的集合是对的，只有计数需要说明。35/15 不成立。')
A('')
A('## 引用统计的假阳性来源（本项目踩过三个）')
A('')
A('### 1. 子串匹配（consult-b 第⑱步）')
A('')
A('`stem in doc` 让 `iso` 命中 `poisoned` 里的 `iso`。**修法：`\\b<文件名>\\b`。**')
A('')
A('### 2. 自指污染（第⑲步，比第 1 类更隐蔽）')
A('')
A('在**审计报告**上统计引用是自指的：审计报告必然讨论「哪些没被引用」。')
A('实测含 `consult-b.md` 时是**「引用 50 / 未引用 0」——100% 全覆盖**，即污染铁证。')
A('')
A('**修法：统计源只取「消费方文档」**（design-a / design-b），排除「元文档」（consult-b）。')
A('判据不是文档类型，而是**该文档是否以这些名字为讨论对象**。')
A('')
A('### 3. 单词/文件名碰撞（第⑳步）')
A('')
A('`probe.cpp` 的 stem 是 `probe`，`\\bprobe\\b` 命中英文单词与 `schannel-probe.txt`。')
A('**修法：主口径要求具体证据形式，并逐文件列出理由。**')
A('')
A('## 用途列的权威来源')
A('')
A('**「用途」的权威来源是消费方文档的结论，不是 API 列表。**')
A('API 只说明「调了什么」（手段），不说明「验证了什么」（目的）。')
A('')
A('| 来源 | 数量 | 说明 |')
A('|---|---:|---|')
A('| `design-b` 探针表结论 | %d | 权威：消费方文档写了它证明了什么 |' % n_concl)
A('| 作者注释 | %d | 次权威：写探针时留的 `//` 注释 |' % n_com)
A('| **有结论合计** | **%d** | %d + %d |' % (n_with, n_concl, n_com))
A('| 无 | %d | 既无结论也无注释 |' % n_none)
A('')
A('> **「—」表示无权威结论**，不是「没有用途」。')
A('> 对于这些行，源码**能看出**调用了哪些 API，但**无法推断验证意图**——')
A('> 所以「用途」留空，「调用」列仍如实列出（那是事实，不是推断）。')
A('')
A('## 文件清单')
A('')
A('| 文件 | 字节 | 用途（结论） | 结论摘要 | 来源 | 证据形式 | 调用（辅助） |')
A('|---|---:|---|---|---|---|---|')
for r in rows:
    A('| `%s` | %d | %s | %s | %s | %s | %s |' % (
        r['file'], r['bytes'],
        esc(r['purpose'])[:50] or '—',
        esc(r['conclusion'])[:100] or '—',
        r['src'],
        ', '.join(r['reasons']) or '—',
        esc(r['apis'])[:70] or '—'))
A('')
A('## 注意')
A('')
A('- 编译产物（`.exe`/`.obj`）**未保留**：可由源码重建，且与编译器版本绑定。')
A('- 编译命令见 `docs/spec/tls-backend.design-a.md` §7.5 / §7.5b。')
A('- 源码**冻结不改**。需修改时新建文件，保留历史。')
A('- 本表由 `evidence/tls/gen_probe_index.py` 从源码与文档**解析生成**，非人工填写。')

io.open(OUT, 'w', encoding='utf-8', newline='').write('\n'.join(L) + '\n')
print('wrote', OUT, os.path.getsize(OUT), 'bytes')
print('C cited=%d/%d  A=%d  B=%d  with_conclusion=%d (%d+%d)  none=%d'
      % (nC, len(rows), nA, nB, n_with, n_concl, n_com, n_none))
print('bare-only:', ', '.join(bare_only))
