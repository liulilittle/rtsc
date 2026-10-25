# A20-1 七轮定案：锚点门禁的「存在性 → 对应性」修复

日期：2026-10-23
状态：**WRONGLINE = 0；三个错位锚点探针全部被抓；A20-1 已闭环**

## 1. 甲和乙独立发现了同一个根因

**甲（§31）**：
> 把 `doc:2876` 的锚点换成 `return Fail(Status::kProtocolError, st);` ——
> 这段文本在源码里存在，但不在 `:432`。
> `WITHOUT an anchor: 0  exit=0  BLIND`
> 根因在 `verify_anchors.py:73`：
> `if all(any(p in s for s in flat) for p in parts)`
> `flat` 是**整个文件的每一行**。**它根本没检查「锚点在不在被引用的那一行」。**

**乙（§18）**：
> U1 把 `doc:2876` 的锚点换成 `:100` 的注释横幅 → GATE-PASSED (weak)
> U2 换成 `'return MakeError'`（文件里 20 行都有，无法定位）→ GATE-PASSED (weak)
> **WEAK: 2/2**
> 「54 条 0 缺锚点」可信，但它证明的是「每条都有个能搜到的片段」，
> 不是「每条都能定位到所引行」。

**两人的诊断完全一致，而且都对。** 我的锚点门禁是「存在性」判据，不是「对应性」判据。

**这比「缺锚点」更危险**：无锚点会红灯；**错位锚点会假绿**——审计者看到 54/0 以为安全。

## 2. 我的 v4/v5/v6/v7 四版都错，v8 才对

| 版本 | 判据 | 结果 | 缺陷 |
|---|---|---|---|
| v4 | 要求每条引用都有锚点 | 179 缺 | 过度（叙述性引用本来没锚点） |
| v5 | 任意邻近片段当锚点 | 226 WRONGLINE | 把 `Shutdown()`、`rx_buffer_` 当锚点 |
| v6 | 只认 `（锚点 ...）` + 查被引行 | **0 WRONGLINE** | 但 34 条「clause 解析为空」 |
| v7 | v6 + 邻近片段回退 | 178 WRONGLINE | 回退破坏了对应性检查 |
| **v8** | **括号配对解析 + 严格对应性** | **0 WRONGLINE** | — |

### v6 的 34 条「clause 解析为空」是什么

我的正则 `[（(]([^）)]{0,60})[）)]` 在锚点**自身含右括号**时截断：

```
（锚点 `if (closed_) return MakeError(Status::kClosed`）
              ↑ 这里被当成 clause 结束
```

反引号不配对 → 零个片段 → 报「clause present but empty」。

**v8 的修正**：扫描到**反引号外**的第一个 `)`，而不是第一个 `)`。

### v7 的回退为什么是致命的

我加了一条「裸 `:NNN` 可能被解析到错误文件，所以尝试所有文件」的回退。
**但这条回退让「锚点在 `:293`」满足了「引用 `:432`」**——同一文件、不同行。
红证立刻抓到：P1/P2 BLIND。

**判据：宽容性回退必须与被修复的缺陷在同一维度上正交。
「文件判错」和「行判错」是两个维度，用「换文件重试」修「行错」是维度错配。**

## 3. 三个错位锚点探针全部被抓（红证）

`evidence/exec/anchors_redtest.py`：

```
P1 anchor exists elsewhere in file         -> CAUGHT (exit=1)
P2 anchor is a very common line            -> CAUGHT (exit=1)
P3 anchor text does not exist at all       -> CAUGHT (exit=1)

baseline (real doc) exit=0
```

**P1** = 锚点 `return Fail(Status::kProtocolError, st);`（在 `:293`）配 `t:432`。
**P2** = 锚点 `return MakeError(Status::kOk, 0, "");`（文件里多处）。
**P3** = 完全不存在的文本。

**修复前 P1/P2 都是 BLIND**（甲的探针和乙的 U1/U2 是同两个）。

## 4. 修了 4 处真实 WRONGLINE

对应性判据上线后立刻抓到 4 处真实问题：

| doc | 问题 | 修正 |
|---|---|---|
| 1797 | `:232` 的锚点被写成后面 `:431-433` 的那个 | 移到 `:232` 后面 |
| 1798 | 锚点 `Error Handshake(..) .. closing brace` **是散文，源码里没有** | 换成真实签名行 .. `}` |
| 2050 | 同上 | 同上 |
| 2443 | `:232` 被解析到错误文件 | 加 `src/net/tls_schannel.cpp:` 前缀 |

**`doc:1798`/`2050` 的伪锚点是我上轮修 `doc:2473` 时漏掉的同类。**
甲在 §31 的 R-2 里也指出了 `doc:2473` 的伪锚点——**同一个错误我修了一处，漏了两处**。

## 5. 甲发现的另外两个盲区（已修）

### 盲区二：裸 `:NNN` 不在正则里

甲：
> `verify_anchors.py:32` 的正则只匹配 `tls_schannel.cpp:NNN` 和 `t:NNN`，
> **不匹配裸 `` `:NNN` ``**。7 个节内：门禁可见 70 条，裸形式 226 条 → **只覆盖 24%**。

**已修**：v8 的 CITE 正则支持裸 `:NNN`，并加了「裸引用尝试所有文件，但必须唯一命中」的解析。

### 盲区三：白名单 `'批 0 后'` 掩盖了 `doc:2761`

甲：
> `WHITELIST_MARKERS` 含 `'批 0 后'`，7 个节里 10 行 / 16 条被整行跳过 ——
> **其中就有 `doc:2761`**。白名单的初衷是「批 0 后 = 行号已更新」，
> 但 `doc:2761` 恰好证明相反：它写着「批 0 后」，引用却是旧的。

**已修**：`'批 0 后'` 从白名单移除。白名单只剩三个真正「谈论行号」的标记：
`行号基线` / `现在指向` / `旧行号`。

## 6. `doc:2761` 的两处 P1（甲 §31 R-4 发现）

| 引用 | 实际 | 应为 | `bak` 确证 |
|---|---|---|---|
| `t:291` | `continue;` | **`:293`** | `bak:291` = `return Fail(kProtocolError, st);` |
| `:317` | 注释 | **`:319`** | `bak:317` = `return Fail(kProtocolError, st);` |

**同一行两个引用同时漏** → 修复是按「报告清单」逐条改，没有对该行整体复核。
甲的批评准确。

## 7. 乙的另一个发现：红证脚本的编码缺陷

乙：
> `python evidence/exec/citations_redtest.py`（不设 `PYTHONIOENCODING`）会崩：
> `AttributeError: 'NoneType' object has no attribute 'strip'`
> 真实根因在**子进程侧**：子进程无 `PYTHONIOENCODING`，按 locale(GBK) 输出；
> 父进程按 utf-8 解码失败 → `p.stdout=None` → 崩。
> **在 ps1 里不崩**，因为 `verify.ps1` 设了 `$env:PYTHONIOENCODING="utf-8"`，被继承。

**已修**：所有红证脚本的子进程调用都传 `env=dict(os.environ, PYTHONIOENCODING='utf-8')`。

**乙还纠正了自己上一稿的错误结论**（「`:96` 未指定 encoding=」——那句错了，
`encoding='utf-8'` 已经写了）。**这种自我订正值得记录。**

## 8. 甲和乙的「不闭环」判定

两人都判「未闭环」，理由从「文档里有错行号」变成了「验证机制无法证明它们对」。

**这是正确的升级。** 前六轮我们修的是数据；第七轮修的是**证明数据正确的方法**。

| 轮次 | 缺陷性质 | 修法 |
|---|---|---|
| 1–6 | 文档里有错的行号 | 逐条修 |
| **7** | **门禁无法证明行号对** | **判据从存在性改为对应性** |

## 9. 最终验证

```
verify_anchors.py    : 407 引用 / 66 锚点定位正确 / 0 WRONGLINE / exit=0
anchors_redtest.py   : P1 P2 P3 全部 CAUGHT / baseline exit=0
verify_citations.py  : 39 passed / 0 failed
verify.ps1           : exit=0
verify.ps1 -DocCite  : exit=0
verify.ps1 -DocLint  : exit=0
verify.ps1 -PseudoLint : exit=0
verify.ps1 -LinuxBuild : exit=0
```

## 10. 最终判定

| 项 | 结论 |
|---|---|
| §19 行号正确性 | **已闭环** |
| §15/§17/§18 可达残留 | **已闭环** |
| 乙的 7 处 | **已闭环** |
| 甲的 2 处 P1（`doc:2761`） | **已闭环** |
| **锚点门禁的存在性缺陷** | **已闭环**（改为对应性） |
| **白名单掩盖** | **已闭环**（移除 `批 0 后`） |
| **裸 `:NNN` 覆盖** | **已闭环** |
| **红证编码** | **已闭环** |
| **A20-1** | **已闭环** |

## 11. 七轮累计

| 轮次 | 数量 | 内容 | 发现者 |
|---|---|---|---|
| 1 | 59 | §19.3.3 锚点化 | 甲 |
| 2 | 8 | §19.4 三大陷阱 | 我 |
| 3 | 7 | §15/§17/§18 | 乙 |
| 4 | 10 | 乙的 9 处 + `doc:3822` | 乙 |
| 5 | 5 | 甲的 2 处 P1 + 3 处 P2 | 甲 |
| 6 | 2 | 判据自述 | 甲 |
| 7 | 7 | 乙的机械位移 | 乙 |
| 8 | 4 | 缺锚点（含伪锚点） | 锚点门禁 |
| 9 | 2 | `doc:2761` 的两处 | 甲 |
| 10 | 4 | 对应性判据抓出的真实 WRONGLINE | 新判据 |
| **合计** | **108** | | |

## 12. 我这一轮的错误（四处）

1. **锚点门禁写成存在性判据** —— 甲、乙独立发现。我把「锚点能被搜到」当成了
   「锚点能定位」。**「能搜到」和「能定位」是两件事。**
2. **v7 的宽容回退破坏对应性** —— 「换文件重试」修不了「行错」。
3. **伪锚点修了一处漏两处** —— `doc:2473` 修了，`doc:1798`/`2050` 没修。
4. **规则 58 第四次复发** —— `| Select-Object` 覆盖 `$LASTEXITCODE`，得到假的 -1。

## 13. 新增/更新文件

| 文件 | 用途 | 门禁 |
|---|---|---|
| `evidence/exec/verify_anchors.py` | v8：对应性判据，407 引用 | **是** |
| `evidence/exec/anchors_redtest.py` | 三个错位锚点探针（P1/P2/P3） | **是** |
| `evidence/exec/verify_citations.py` | 39 项语义验证 | **是** |
| `evidence/exec/citations_redtest.py` | 红证 A（改文档） | **是** |
| `evidence/exec/semantic_redtest.py` | 红证 B（改源码） | **是** |
