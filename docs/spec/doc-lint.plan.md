# 文档一致性检查（doc-lint）方案

- 目的：把「改 A 处漏了引用 A 的 B 处」这类**文档内部矛盾**自动化。
- 触发背景：本项目已发生 2 次同类缺陷
  - `design-a.md:86` 表格两行粘连 → `SEC_E_MESSAGE_ALTERED` 行渲染丢失（乙发现）
  - `design-a.md:631` 写「最终 21 条」而 `:669` 写「20 条」（父会话发现）
- 原则：**只把误报为零的检查设为 fail**；有合理误报可能的设为 warn。
- 状态：方案（先审后改）。实施见 §8。

---

## §0 检查对象

12 个文档（`F:\rtsc\docs\spec\`）：

| # | 文件 | 类型 | 行数 | 跑哪些检查 |
|---|---|---|---|---|
| 1 | `connection-initiation.md` | spec | 128 | F1 F2 F3 F5 |
| 2 | `mcs-connect.md` | spec | 1021 | F1 F2 F3 F5 |
| 3 | `mcs-domain.md` | spec | 2282 | F1 F2 F3 F5 |
| 4 | `security-layer.md` | spec | 1816 | F1 F2 F3 F5 |
| 5 | `share-data.md` | spec | 2072 | F1 F2 F3 F5 |
| 6 | `licensing.md` | spec | 2099 | F1 F2 F3 F5 |
| 7 | `capabilities.md` | spec | 2771 | F1 F2 F3 F5 |
| 8 | `tls-backend.design-a.md` | design | 1140 | F1 F2 F3 F4 F5 |
| 9 | `tls-backend.design-b.md` | design | 566 | F1 F2 F3 F4 F5 |
| 10 | `capabilities.consult-a.md` | **审计** | 1371 | F1 F3 only |
| 11 | `capabilities.consult-b.md` | **审计** | 2128 | F1 F3 only |
| 12 | `tls-backend.consult-b.md` | **审计** | 704 | F1 F3 only |

**审计类文档（`*.consult-*.md` / `*.audit-*.md`）只跑 F1（表格完整性）与 F3（文件引用存在性）**，
不跑 F2（数字一致性）与 F4（章节引用）——它们**职责就是大量引用旧值**
（"原写 21 条"、"把 `0x03E3` 改为 `0x03EB`"），跑残留检查会 100% 误报。

---

## §1 F1 —— 表格行完整性（fail）

### 算法

```python
FENCE = re.compile(r'^\s*```')
def check_tables(lines):
    fence = False
    problems = []
    for i, raw in enumerate(lines, 1):
        if FENCE.match(raw):
            fence = not fence
            continue
        if fence:
            continue
        s = raw.strip()
        if not s.startswith('|'):
            continue
        # 1) 行首 | 但行尾不是 |  -> 表格行被截断
        if not s.endswith('|'):
            problems.append((i, 'row-not-closed', s[:80]))
            continue
        # 2) 去掉行内代码后再找 "||" -> 两行粘连成一个单元格
        nocode = re.sub(r'`[^`]*`', '``', s)
        if '||' in nocode:
            problems.append((i, 'sticky-cells', s[:80]))
    return problems
```

### 为什么必须去行内代码

`security-layer.md:869` 有 `` `SPK || magic || nonce` `` —— 这是**合法**的
"拼接顺序"说明，`||` 在反引号内。不去代码会误报 1 处（已实测）。

### 误报风险

| 场景 | 是否误报 | 处置 |
|---|---|---|
| 行内代码里的 `\|\|`（C 逻辑或） | 会 | 已用 `` `[^`]*` `` 剔除代码段 |
| 表格单元格内用 `\|` 转义的竖线 | 不会 | 转义后是 `\|` 不是 `\|`+`|`，不构成 `||` |
| 表格最后一行漏写尾 `|`（手写时常见） | **会**（但这是真缺陷） | 归 fail，人工修 |
| 多行表格跨页/跨代码块 | 不会 | fence 状态机跳过代码块 |

### 漏报风险

- **抓不到 `:86` 原始形态**：那次是 `...| kNeedMoreInput || 0x8009030F | SEC_E_MESSAGE_ALTERED |...`，
  该行**以 `|` 结尾**，所以 `row-not-closed` 抓不到；但 `sticky-cells` 能抓到（`||` 在代码外）。
  **已验证**：修复前该行会被 `sticky-cells` 命中。
- 抓不到"表格列数不一致"（某行少一列但首尾都有 `|`）。这是有意不做：
  中文表格里 `|` 出现在行内代码/数学符号的情况多，列数校验误报率高。

---

## §2 F2 —— 数字/结论一致性（warn）

### 算法

```python
CLAIM = re.compile(r'(?:最终条数|合并后|最终|共计|合计)\s*[:：]?\s*'
                   r'\*{0,2}\s*(\d+)\s*\*{0,2}\s*条')
# 历史/引用语境：出现这些词的行不算"当前结论"
HIST = re.compile(r'原写|最初|原本|撤回|降级|演变|历史|修订|变更|留痕|'
                  r'→|->|原 \d+|旧值|乙说|它说|引用|转述|合并前|旧稿')
def check_counts(lines):
    cur, hist = [], []
    for i, s in enumerate(lines, 1):
        for m in CLAIM.finditer(s):
            (hist if HIST.search(s) else cur).append((i, m.group(1), s.strip()[:80]))
    return cur, hist
```

判定：

- `cur` 里出现的值集合基数 > 1 → **warn**，打印全部位置
- `cur` 基数 == 1 → 通过（不打印）
- `hist` 永远只做信息输出（不参与判定）

### 为什么是 warn 不是 fail

同一个文档里**可以合法地**出现多个"N 条"（不同对象）：
- `capabilities.consult-b.md:1283`「13.5 缺陷 41 个严重度分布」——这是"41 个"另一个统计口径
- `tls-backend.consult-b.md:19`「合并后 **17 条**」——这是乙的口径，与甲的 20 条**都对**

所以不能自动 fail。warn + 打印全部位置，由人判断。

### 误报风险

| 场景 | 处置 |
|---|---|
| 审计报告引用被审文档的旧结论 | `HIST` 命中 `乙说/它说/引用/转述` → 归 hist |
| 同一文档统计两个不同对象（缺陷数 vs 用例数） | 会 warn；靠打印行号人工判断 |
| 修订记录章节（`## 12. 修订记录`） | `HIST` 命中 `修订/变更` → 归 hist |

### 漏报风险

- **只覆盖"条数"**。数字矛盾的其他形态（`0x03E3` vs `0x03EB`、"294 字节" vs "270 字节"）
  抓不到——那需要语义理解，不是正则能做的。
- 如果矛盾双方用了不同措辞（一边"20 条"、一边"twenty"），抓不到。
- 如果矛盾双方都没有 `最终/合并后/共计` 前缀，抓不到。
  **这是本检查最大局限**：它只覆盖"带结论性前缀的条数声明"。
  但恰好 `:631`/`:669` 那次双方都有前缀，所以对本项目最痛的那类有效。

---

## §3 F3 —— 文件引用存在性（fail）

### 算法

```python
ABS = re.compile(r'F:\\rtsc\\[^\s`\)\]|,;]*')
EXT = re.compile(r'\.(md|cpp|h|hpp|py|ps1|txt|json|lib|exe|out|log)$', re.I)
def check_file_refs(text):
    bad = []
    for m in ABS.finditer(text):
        raw = m.group(0).rstrip(".,;:'\"")
        path = re.sub(r':\d+(-\d+)?$', '', raw)   # 去掉 :行号 / :起-止
        if '.tmp' in path.lower():      continue  # 临时文件不校验
        if '*' in path:                 continue  # 通配符不校验
        if not EXT.search(path):        continue  # 只校验带已知扩展名的
        if not os.path.exists(path):
            bad.append(raw)
    return bad
```

### 为什么排除 `.tmp` 与通配符

- `.tmp` 是临时目录，内容随时消失，**不是缺陷**
- `F:\rtsc\.tmp\tlsprobe\*.cpp` 这类通配符无法逐字校验

### 误报风险

| 场景 | 处置 |
|---|---|
| 文档里写"计划创建但尚未创建"的路径 | 会 fail；这类应改写为代码块或不带扩展名 |
| 大小写差异（Windows 不敏感，Linux 敏感） | 本检查用 `os.path.exists`，Windows 下不敏感；**这是漏报风险**（见下） |
| 相对路径 | 不检查（只查 `F:\rtsc\` 绝对路径） |

### 漏报风险

- **相对路径完全不查**（`design-a.md:661` 写 `design-b.md` 这种）。
  原因：相对路径的基准目录不确定（相对文档？相对仓库根？），强行解析误报率高。
  → 已用 F4 的"文件限定章节引用"部分补偿。
- 大小写错误在 Windows 上抓不到。

---

## §4 F4 —— 文件限定章节引用（fail，仅 design 文档）

### 算法

```python
QREF = re.compile(r'([A-Za-z0-9_.\-]+\.md)\s*§\s*(\d+(?:\.\d+)*)')
HEAD = re.compile(r'^(#{1,6})\s+§?\s*(\d+(?:\.\d+)*)\.?(?=[\s\u4e00-\u9fff（(：:]|$)')
```

对每个 `QREF` 命中：取被引用文档的标题集合，若章节号不在其中 → fail。

### 关键：为什么放弃"裸 `§N`"检查

实测数据（12 个文档）：

| 文档 | 裸 `§N` 总数 | 能在本文档标题中找到 | 同行有外部规范标记 | **无法解释** |
|---|---|---|---|---|
| `licensing.md` | 659 | 199 | 202 | **258** |
| `capabilities.consult-a.md` | 340 | 227 | 5 | **108** |
| `capabilities.consult-b.md` | 372 | 225 | 1 | **146** |
| `mcs-domain.md` | 133 | 68 | 42 | **23** |

`licensing.md` 的 258 处"无法解释"，绝大多数是 `[MS-RDPBCGR] §2.2.1.12.1.1` 这类
**外部规范章节**，只是同行没有 `[MS-` 前缀（写在上一行或表格前一行）。

**结论：裸 `§N` 检查的误报率 ≈ 39%（258/659），必须放弃。**

### 为什么"文件限定"可靠

`<doc>.md §N` 形式只有 2 处（都在 `design-a.md`），且**都能精确解析**：
- 指向 `security-layer.md §8` → `security-layer.md` 确实有 `## 8. 实现选型建议`

误报 0，故设为 fail。

### 漏报风险

- 覆盖率极低：只有 2 处。大部分跨文档引用是裸 `§8`（如 `design-a.md:630` 的
  「`security-layer.md §8` 的文档缺陷」——这里 `§8` 与文件名之间没有紧邻，
  正则要求 `\.md\s*§`，中间有空格可以，但若写成 `security-layer.md 的 §8` 就抓不到）。
- 已在实现里放宽为 `\.md\s*(?:的\s*)?§\s*` 以提高覆盖。

---

## §5 F5 —— 标题编号唯一性（fail，仅 design 文档）

### 算法

```python
HEAD = re.compile(r'^(#{1,6})\s+§?\s*(\d+(?:\.\d+)*)\.?(?=[\s\u4e00-\u9fff（(：:]|$)')
```

同一文档内相同章节号出现 >1 次 → fail。

### 误报风险

**高**，实测两次误报，都因正则不认"点号后缀"：
- `capabilities.md` 有 `## 1) 官方 DOCX 全文` 这类**代码块内的**编号列表（已由 fence 跳过）
- 早期版本正则漏了 `## 8. 实现选型建议` 的**句点**，导致 `security-layer.md` 标题集合缺失 `8`，
  进而使 F4 误报 2 处

修正后（`\.?` + 后向断言）实测 12 个文档 **dup = 0**，误报 0。

### 漏报风险

- 只查"编号重复"，不查"编号跳号"（`3.1` → `3.3` 缺 `3.2`）。
  原因：spec 文档常有"有意保留的编号空洞"（历史删除），跳号检查误报高。
- 不查 `### 18.5 修订记录` 内部的 `1.` `2.` 列表（那些不是章节号）。

---

## §6 分级与退出码

| 检查 | 级别 | 理由 |
|---|---|---|
| F1 表格完整性 | **fail** | 误报 0（已用代码段剔除验证） |
| F2 条数一致性 | **warn** | 合法多口径存在（41 个 / 17 条 / 20 条） |
| F3 文件引用存在 | **fail** | 误报 0（排除 .tmp 与通配符后） |
| F4 文件限定章节引用 | **fail** | 误报 0（仅 2 处，均可解析） |
| F5 标题编号唯一 | **fail** | 修正正则后误报 0 |

退出码：**有 fail → 1；只有 warn → 0**。

### 为什么 F2 不进 fail

如果把 F2 设 fail，则：
- `tls-backend.consult-b.md` 会因为「17 条」（乙口径）与「21 条」（它引用甲的旧值）直接 fail
- 而这两个值**在乙的报告里都是正确的**（它就是在讨论"你的 21 条 vs 我的 17 条"）

对审计文档设 fail 会逼迫审计员"为了过 lint 而不敢引用旧值"，这是反向激励。

---

## §7 如何避免把"修订记录/变更历史"里的旧值当残留

三层机制：

1. **文档级**：`*.consult-*.md` / `*.audit-*.md` 不跑 F2/F4（只有 F1/F3）。
2. **行级**：`HIST` 正则命中即归入 `hist`，不参与判定。词表：
   `原写|最初|原本|撤回|降级|演变|历史|修订|变更|留痕|→|->|原 \d+|旧值|乙说|它说|引用|转述|合并前|旧稿`
3. **章节级**（可选增强，本轮不实现）：识别 `## ... 修订记录` / `### ... 变更` 标题，
   其下所有行归 hist。当前行级已足够（`design-a.md` 的 7 处 claim 中 4 处被行级正确归类）。

**已知残留**：`design-a.md:674`「**最终条数：20 条**（D1–D21，其中 **D14 已降级、不计入**）」
被 `HIST` 的"降级"命中而误归 hist。这不影响判定（它本身是 20，与 cur 的 20 一致），
但会让"hist 数量"看起来偏多。已在实现里加例外：**`最终条数` 前缀强制归 cur**。

---

## §8 实施计划

### 8.1 文件

- `F:\rtsc\evidence\doc\doc_lint.py`（新建，Python 3，仅标准库）
- `F:\rtsc\verify.ps1`（新增 `[switch]$DocLint`，默认不跑）

### 8.2 `doc_lint.py` 接口

```
python doc_lint.py [--root F:\rtsc] [--json] [--only F1,F3] [file...]
```

- 无参数：跑 §0 表里的 12 个文档
- `--json`：机器可读输出（供 CI 解析）
- `--only`：只跑指定检查
- 退出码：有 fail → 1，否则 0

输出格式（每个文档一行摘要 + fail/warn 明细）：

```
connection-initiation.md           F1 ok  F2 n/a  F3 ok  F5 ok          fail=0 warn=0
tls-backend.design-a.md            F1 ok  F2 WARN(20 vs 17) F3 ok  F4 ok  F5 ok   fail=0 warn=1
  WARN F2:631  value=21  (历史语境，已排除)
  ...
TOTAL fail=0 warn=1
```

### 8.3 `verify.ps1` 改动

```powershell
param([switch]$Clean, [switch]$CrashCheck, [switch]$DocLint)

# ... 既有内容不变 ...

if ($DocLint) {
    Write-Host "== doc lint =="
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $py) {
        Write-Host "  [skip] python not found: doc lint skipped"
    } else {
        $env:PYTHONIOENCODING = 'utf-8'
        $lint = Join-Path $root "evidence\doc\doc_lint.py"
        if (-not (Test-Path $lint)) { Write-Error "doc_lint.py not found at $lint"; exit 1 }
        & $py $lint --root $root
        if ($LASTEXITCODE -ne 0) { Write-Error "doc lint failed"; exit 1 }
    }
}
```

要点：
- **默认不跑**（无 `-DocLint` 时行为完全不变）
- Python 缺失时 **skip 而非 fail**（不阻断无 Python 环境）
- 设 `PYTHONIOENCODING='utf-8'`（PowerShell 5.1 的编码坑）

### 8.4 为什么用 Python 不用 PowerShell

项目已踩过：PowerShell 5.1 读 UTF-8 无 BOM 的中文会按 GBK 解码，导致
`§`、中文标题、正则全部失效。Python 3 的 `io.open(encoding='utf-8', newline='')`
可精确控制，且正则能力足够。

---

## §9 12 个文档的基线（实测，2026-10-22）

用本方案的算法（未落盘前先在 `.tmp` 验证）跑出的结果：

| # | 文档 | F1 | F2 | F3 | F4 | F5 | fail | warn |
|---|---|---|---|---|---|---|---|---|
| 1 | `connection-initiation.md` | ok | n/a(0 claim) | ok(0 ref) | n/a | ok(7) | 0 | 0 |
| 2 | `mcs-connect.md` | ok | n/a(0) | ok(0) | n/a | ok(47) | 0 | 0 |
| 3 | `mcs-domain.md` | ok | n/a(0) | ok(0) | n/a | ok(83) | 0 | 0 |
| 4 | `security-layer.md` | ok | n/a(0) | ok(0) | n/a | ok(76) | 0 | 0 |
| 5 | `share-data.md` | ok | n/a(0) | ok(0) | n/a | ok(86) | 0 | 0 |
| 6 | `licensing.md` | ok | n/a(0) | ok(5, 0 miss) | n/a | ok(92) | 0 | 0 |
| 7 | `capabilities.md` | ok | n/a(0) | ok(7, 0 miss) | n/a | ok(125) | 0 | 0 |
| 8 | `tls-backend.design-a.md` | ok | **20/20 一致** | ok(30, 0 miss) | ok(2) | ok(42) | 0 | 0 |
| 9 | `tls-backend.design-b.md` | ok | n/a(0) | ok(9, 0 miss) | ok(0) | ok(33) | 0 | 0 |
| 10 | `capabilities.consult-a.md` | ok | n/a(跳过) | ok(14, 0 miss) | n/a | n/a | 0 | 0 |
| 11 | `capabilities.consult-b.md` | ok | n/a(跳过) | ok(22, 0 miss) | n/a | n/a | 0 | 0 |
| 12 | `tls-backend.consult-b.md` | ok | n/a(跳过) | ok(1, 0 miss) | n/a | n/a | 0 | 0 |

**基线：fail = 0，warn = 0**（在已修复 `:631` 之后）。
这意味着**检查项可以全部启用为 fail**，且不会阻断现有 CI。

补充：`tls-backend.consult-b.md` 若强行跑 F2 会 warn（17 vs 21），
正是它"只跑 F1/F3"策略的依据。

---

## §10 自测计划（注入测试）

| # | 注入 | 期望 |
|---|---|---|
| T1 | 在 `design-a.md` 加一行 `见 §9.9.9` 且该文档无此标题、同行无外部标记 | F4 **不**报（裸 §N 不检查）；若写成 `security-layer.md §9.9.9` → F4 fail |
| T2 | 在 `design-a.md` 把某行改成 `\| a \| b \|\| c \|` | F1 fail（sticky-cells） |
| T3 | 在 `design-a.md` 加 `## §4 现有 §8 缺陷清单（合并后 **25 条**）` | F2 warn（20 vs 25） |
| T4 | 在 `design-a.md` 加 `F:\rtsc\docs\spec\does-not-exist.md:12` | F3 fail |
| T5 | 在 `design-a.md` 加 `## 4. 重复标题` | F5 fail |
| T6 | 不加 `-DocLint` 跑 `verify.ps1` | 行为与改动前完全一致（12 套 ctest 全绿） |

注入后**必须恢复原文件**（用备份 + 校验行数/字节数）。

---

## §11 风险与止损线

| 风险 | 缓解 | 止损 |
|---|---|---|
| F1 误报（合法 `\|\|`） | 剔除行内代码 | 若基线 >0 误报 → 降为 warn |
| F2 噪声过多（多口径） | warn 不 fail + 打印位置 | 若 warn > 20/文档 → 只输出计数 |
| F3 误报（计划中的路径） | 排除 .tmp/通配符/无扩展名 | 若基线 >0 误报 → 排除 `docs/` 下自引用 |
| F4 覆盖率过低 | 放宽为 `\.md\s*(?:的\s*)?§` | 若仍 <5 处 → 保留但标"低覆盖" |
| 拖慢 CI | 默认不跑，`-DocLint` 开关 | 单文档 < 100ms，12 文档 < 1.2s |

**止损原则**：任一检查在基线跑出**真误报**（合法写法被判错），先修规则；
若规则无法在 30 分钟内修好，该检查降级为 warn 并在此文档记录。

---

## §12 不做的事（明确范围）

1. **不查列数一致性**（中文表格 + 行内 `|` 误报高）
2. **不查裸 `§N` 悬空**（实测误报 258 处）
3. **不查编号跳号**（有意空洞）
4. **不查数字/十六进制值的语义一致性**（`0x03E3` vs `0x03EB` 需语义理解）
5. **不查相对路径存在性**（基准目录不确定）
6. **不查 markdown 渲染结果**（需渲染器，超范围）
7. **不改任何 spec 内容**——只读检查
