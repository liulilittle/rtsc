# A20-1 第十二轮复裁：我上一轮的修复是死代码

日期：2026-10-23
状态：**门禁 v14；21 探针全绿；E2/E3 为真红证**

## 1. 两个人的报告，我全都要独立复验

甲报「A20-1 已闭环」，乙报「不通过，2 条 P2」。

**结果：乙对，甲错。** 而甲的 R-1/R-2 数据本身**又是对的**。

## 2. 我先把自己的核对方法判错了

甲说 `CLOSING_PREFIX` 命中 87 行、其中 3 个真开块。
我用原始文件 + `indent<=8` 过滤，测得 **66 行 / 1 个**，一度以为甲数据造假。

**错的是我**。`verify_anchors.py:45`：

```python
SRC[k] = [' '.join(x.split()) for x in io.open(v, encoding='utf-8').read().splitlines()]
```

`SRC` 是**去缩进 + 合并空白**的归一化源码。门禁从来没见过缩进。
按 `SRC` 复测：**87 / 3 / 0**，与甲完全一致。

### 顺带发现的脆弱点

`^\s{0,8}` 的缩进上限**在归一化源码上恒为真**，是空条件。
更糟的是它是个陷阱：

```
t:315 原始缩进 12  ->  CLOSING_PREFIX.match(raw) = False
t:320 原始缩进 12  ->  CLOSING_PREFIX.match(raw) = False
t:555 原始缩进 8   ->  CLOSING_PREFIX.match(raw) = True
```

**如果哪天去掉归一化，315/320 会直接漏过，而 555 不会**——
上限看起来一直在起作用，实际只在缩进 ≤8 时起作用。

已把 `INNER_BLOCK` / `CLOSING_PREFIX` 都改为 `^\s*`，并在注释里写明
「归一化是刻意的，不要恢复小的缩进上限而不重新检查它是否在悄悄承重」。

## 3. 乙的两条 P2 全部复现

### P2-1：`starts_a_function` 对注释/语句/聚合初始化返回 True

```
t:9    True  '// other platforms (which get their own backend, or none at all).'
t:349  True  'out.clear();'
t:372  True  'out.clear();'
t:595  True  'sb[1] = {static_cast<unsigned long>(size), SECBUFFER_DATA,'
t:653  True  'SecBuffer ib{static_cast<unsigned long>(token.size()), SECBUFFER_TOKEN,'
```

根因：

```python
head = line.split('(')[0]
return bool(re.search(r'[A-Za-z_]\w*', head)) or '~' in head
```

`'// other platforms'`、`'out.clear'`、`'sb[1] = '` 里全都捞得到标识符。
**I6 形同虚设。** 乙端到端跑了 5 个 ACCEPTED，全部命中。

### P2-2：我上一轮加的 `CLOSING_PREFIX` 是死代码

```
brace_balanced(315,321) = False        <- E1 的拒绝来自这里
starts_a_function(315)  = False        <- 但从不被查询（短路）
```

`range_matches` 末行：

```python
return brace_balanced(src, ca, cb) and starts_a_function(src, ca)
```

`brace_balanced` 先返回 False，右侧不求值。

更要命的是**可达性**：本文件中「以 `}` 开头且能自行配平」的行 **= 0 条**。
所以 `CLOSING_PREFIX` 在这份数据上**永远无法改变任何判定**。

**我在注释里写「两条规则偶然互补不是设计」，然后自己写了第四条死规则。**

## 4. 新判据：`{` 必须在最后一个 `)` 之后

判据不是猜的，是从实测的两个集合里找出来的：

| 样本 | 行 | `brace@` | `paren@` | 结论 |
|---|---|---|---|---|
| 真 | t:371 `Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {` | 69 | 52 | brace > paren -> accept |
| 真 | t:89 `~SchannelTransport() override {` | 30 | 19 | accept |
| 真 | t:517 `uint32_t ExpectedActualOverhead() const {` | 40 | 32 | accept |
| 真 | t:561 `static uint16_t WireVersionFromProtocolMask(DWORD mask) {` | 56 | 54 | accept |
| 真 | t:671 `PCCERT_CONTEXT PeerCert() const {` | 32 | 24 | accept |
| 真 | t:690 `static Error ConstError(Status s, int32_t code, const char* msg) {` | 65 | 63 | accept |
| 假 | t:595 `sb[1] = {static_cast<...>(size), SECBUFFER_DATA,` | 8 | 40 | brace < paren -> reject |
| 假 | t:653 `SecBuffer ib{static_cast<...>(token.size()), ...` | 12 | 52 | reject |
| 假 | t:349 `out.clear();` | -1 | 10 | 无 `{` + 括号配平 -> reject |
| 假 | t:9 注释 | -1 | 63 | `//` 前缀 -> reject |

**语义**：函数体的 `{` 在参数列表**闭合之后**；聚合初始化的 `{` 在参数列表**之前**。
这条判据是在陈述语法事实，不是在拟合样本。

## 5. 修复过程中我误伤了 8 个折行签名

只加「`{` 必须在 `)` 之后」后：

```
WRONGLINE : 3
  doc:1798  src/net/tls_schannel.cpp:101-201  range anchor misplaced
  doc:2050  同上
  doc:2473  同上
```

原因：折行签名的**开块行不含 `{`**（`{` 在参数列表末行）。

```
t:68   'bool ParseRecordHeader(const uint8_t* p, uint8_t& type, uint16_t& vers'  endsWith ','
t:101  'Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,'     endsWith ','
t:204  'Error Send(...)' / t:230 / t:589 / t:616 / t:647 / t:740   全部 endsWith ','
```

补判据：**无 `{` 时，`(` 必须未配平**（说明参数列表在下面继续）。
`out.clear();` 的括号是配平的，所以仍被拒。

## 6. E1 不是红证，E2/E3 才是

乙的 Q-3 用变异测试证明 E1 不具区分性：`CLOSING_PREFIX` 删掉后 E1 仍 exit=1。

**我照做并确认。** 于是：

- E1 重标为「brace_balanced 回归测试」，不再当作守卫红证
- 新增 **E2**（`t:349-358` 裸语句，`brace_balanced=True`，cb=358 是真正的 `}`）
- 新增 **E3**（`t:595-596` 聚合初始化，`brace_balanced=True`，cb=596）

**E2/E3 是真红证**——突变验证：

```
去掉新判据后：
  E2 exit=0 expect=1  *** WRONG ***
  E3 exit=0 expect=1  *** WRONG ***
  D1-D5 仍 exit=0     OK
恢复后 SHA256 不变
```

`brace_balanced` 说「是」，只有 `starts_a_function` 能否决——**这才叫区分性**。

## 7. 21 探针全绿

```
baseline                              exit=0 OK
A1 A2 A6 / B1 B2 B3                   exit=1 OK
C1 C2 C3 C4 C5 C6                     exit=1 OK
D1 D2 D3 D4 D5                        exit=0 OK
E1 (bb regression)                    exit=1 OK
E2 bare statement                     exit=1 OK   <- 真红证
E3 aggregate init                     exit=1 OK   <- 真红证
```

## 8. 最终验证

```
verify_anchors.py    exit=0  407 引用 / 70 定位 / WRONGLINE 0
anchors_redtest.py   exit=0  21/21
verify_citations.py  exit=0  43 passed / 0 failed
batch1_preflight.py  exit=0  batch 1 is executable
verify.ps1           exit=0
verify.ps1 -DocCite  exit=0  doc citation gate passed
```

## 9. 教训

**我犯了两个错误，都是「验了但验错了对象」**：

1. 核对甲的数据时，我测的是**原始文件**，门禁测的是**归一化源码**。
   差 21 行、差 2 个开块。**用错模型去校验别人的结论，结论正确也会被我判成造假。**

2. 修 `starts_a_function` 时，我加了 `CLOSING_PREFIX` 却没验**可达性**。
   它在真实数据上 0 次生效，我却写了「两个规则互相兜底不是设计」——
   **然后自己加了第四条永不生效的规则。**
   真要验的是：**这个守卫在本数据上改变过判定吗？**
   答案：没有。而 `brace_balanced` 掩盖了这一点。

→ memory 108 / 109
