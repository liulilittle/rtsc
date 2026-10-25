# A20-1 第十一轮：白名单改黑名单 + 三处 bare 引用

日期：2026-10-23
状态：**门禁 v12；18 探针全绿（含 5 条假阳性守卫）；甲乙同报同一缺陷**

## 1. 甲乙各自独立报告同一个缺陷：SIG 白名单漏判真函数

甲说「5 处假阳性」，乙说「穷举 24 个真函数，SIG 漏 5 个」。**两人的清单完全一致**：

```
:89   ~SchannelTransport() override {                        析构，无返回类型
:517  uint32_t ExpectedActualOverhead() const {              uint32_t 不在白名单
:561  static uint16_t WireVersionFromProtocolMask(DWORD) {   static + uint16_t
:671  PCCERT_CONTEXT PeerCert() const {                      PCCERT_CONTEXT 不在白名单
:690  static Error ConstError(...) {                         返回类型在列表，被 static 挡住
```

### 我早先的普查漏了它们

我用「SIG 匹配 / 不匹配」二分，**把不匹配的统统归为「内层块」**。
实际 `tls_schannel.cpp` 里 88 个开块行，SIG 拒绝 70 个，
**其中 5 个是真函数**——我的二分掩盖了这一点。

甲的普查（27 个定义）和乙的穷举（24 个真函数）**都是从「什么是函数」出发，
不是从「SIG 认什么」出发**。这是正确方向。

## 2. 修法：白名单 → 黑名单

甲和乙都指向同一条：

> 甲：别用白名单，用排除法。
> 乙：开块行的花括号使 depth 0→1 且该行不是 `if/for/while/switch/else/do/try/catch/struct/class/namespace/enum`。

采用：

```python
INNER_BLOCK = re.compile(
    r'^\s{0,8}(?:namespace|struct|class|enum|union|typedef|using|'
    r'if|else|for|while|do|switch|case|default|try|catch|return)\b')

def starts_a_function(src, ca):
    line = src[ca - 1]
    if INNER_BLOCK.match(line):
        return False
    if '(' not in line:          # 续行（如 `SEC_E_OK) {`）
        return False
    head = line.split('(')[0]
    return bool(re.search(r'[A-Za-z_]\w*', head)) or '~' in head
```

### 为什么白名单必然漏

**返回类型是开放集合**：任何用户类型、任何 typedef、任何 `static`/`constexpr`/`inline` 组合。
白名单写 `Error|bool|void|DWORD|std::\w+|Status|int|size_t` 覆盖了本文件 18/24 个函数，
**但下一个函数随时可能是 `uint32_t`。**

**黑名单是封闭集合**：C++ 里能开块且不是函数的构造就那十来个关键字。
**这是「结构」而非「枚举」。**

## 3. 我额外加的一条：`(` 必须在开块行

首版黑名单改完后，我发现续行仍被误判：

```
t:679  `SEC_E_OK) {`                              <- 上方是 if (QueryContextAttributesW(...
t:572  `info_.tls_version > config_.max_version) {`  <- 上方是 if (info_.tls_version < ...
```

这些行不含 `if`，黑名单放行；但它们是**折行条件式的尾部**，不是函数。

**判据：函数签名的参数列表必然从该行开始，所以开块行必含 `(`。**
加上 `if '(' not in line: return False` 后，13 个续行全部正确拒绝。

## 4. 乙报的 3 处 bare 引用 —— 全部属实并已修

| doc | 旧引用 | 散文 | `cur[旧]` | 已改为 |
|---|---|---|---|---|
| 2443 | `t:244` | 「<5 字节返回 kOk」 | `if (rx_buffer_.size() < kMinRecordHeader) {` | `t:245-247` |
| 2815 | `t:233` | 「`Receive` 从 `rx_buffer_` 消费」 | `if (terminal_) return last_error_;` | `t:271` |
| 2830 | `t:402-434` | 「`SchannelTransport::Shutdown`」 | `cur:402`=**空行** | `t:404-436` |

`bak` 确证 +2：`bak:242→cur:244`、`bak:231→cur:233`、`bak:402→cur:404`。

### doc:2830 最严重：区间整体错位且跨层

```
t:402-434  depth=2  cur[402]=''（空行）        cur[434]='}'（内层 if 闭合）
t:404-436  depth=1  cur[404]='Error Shutdown(...)'  cur[436]='}'
```

**即使补上 `sig .. }` 锚点，`brace_balanced` 也会拒绝（depth=2）。**

## 5. 修这三处时暴露了门禁自己的一个 bug

我按乙的清单改完后跑门禁，`doc:2443` 报：

```
`t:246` anchor does not occur at cur[246]
```

**`cur[246]` 明明是 `? MakeError(Status::kOk, 0, "")`。**

根因在 `resolve_file`：`t:246` 是裸引用（无文件名），它**向左扫最近的已出现文件名**，
而同一行前面有 `tls.h:148-150` → **把 `t:246` 归给了 `tls.h`**。

**`t:` 是 `tls_schannel.cpp` 的显式别名，不应参与「向左找文件名」的推断。**

```python
def cite_file(m, dl):
    if m.group(1):
        return m.group(1)
    if m.group(0).startswith('`t:'):
        return 'tls_schannel.cpp'
    return resolve_file(dl, m.start())
```

**这个 bug 一直存在，只是在此之前没有 `t:` 和另一个文件名同行的引用。**

## 6. 第二层：`:246` 的锚点不唯一

修完文件归属后，`t:246` 报：

```
anchor not unique: hits [246, 261], cited 246
```

`? MakeError(Status::kOk, 0, "")` 在 `:246`（<5 字节）和 `:261`（<record_size）各一次。
**这是真缺陷——锚点无法区分两个分支。**

改成区间 `t:245-247`，锚点钉住首末行：
```
`t:245-247`（批 0 后；锚点 `return (progressed != 0 || produced != 0)` ..
 `: MakeError(Status::kNeedMoreInput, 0, "");`）
```

**`verify_citations.py` 的 `:244` 也同步改为 `:245`。**

## 7. 18 个探针全部正确

```
baseline unchanged                     exit=0 OK
A1 anchor from cur[431]                exit=1 OK
A2 anchor from cur[433]                exit=1 OK
A6 :432 -> :304 anchor untouched       exit=1 OK
B1 anchor exists elsewhere             exit=1 OK
B2 anchor very common                  exit=1 OK
B3 anchor does not exist               exit=1 OK
C1 "sig .. }" range -2                 exit=1 OK
C2 "sig .. }" range end +2             exit=1 OK
C3 "sig .. }" start +1                 exit=1 OK
C4 single-frag midrange -2             exit=1 OK
C5 inner block as function body        exit=1 OK
C6 depth==0 range accepted             exit=1 OK
D1 correct cite: destructor            exit=0 OK   <- 新：假阳性守卫
D2 correct cite: uint32_t return       exit=0 OK   <- 新
D3 correct cite: static uint16_t       exit=0 OK   <- 新
D4 correct cite: PCCERT_CONTEXT        exit=0 OK   <- 新
D5 correct cite: static Error          exit=0 OK   <- 新
```

**D1–D5 是「正确引用必须通过」的守卫。**
之前的 13 个探针全是「错误引用必须失败」，**没有一条守假阳性**。
这是本轮最重要的测试结构改进：**假阴性和假阳性必须同时被钉住。**

## 8. 全量普查：0 mismatch

```
=== full census: every brace-opening line at indent<=8 ===
  mismatches: 0
```

88 个开块行逐个判定「是函数 / 是内层块」，**零错判**。

## 9. 最终验证

```
verify_anchors.py    : 407 引用 / 70 定位唯一正确 / WRONGLINE 0 / exit=0
anchors_redtest.py   : 18/18 探针正确 / exit=0
verify_citations.py  : 43 passed / 0 failed / exit=0
batch2_preflight.py  : 7 条锚点全部可定位 / exit=0
verify.ps1           : exit=0
verify.ps1 -DocCite  : exit=0
verify.ps1 -DocLint  : exit=0
verify.ps1 -PseudoLint : exit=0
```

## 10. 十一轮累计

| 轮次 | 数量 | 内容 | 发现者 |
|---|---|---|---|
| 1–7 | 108 | 见 `a201-round7.md` | 甲/乙/我 |
| 8 | 15 | 区间引用 + 单点旧行号 | 甲 |
| 9 | 4 | CMakeLists 旧值 | 乙 |
| 10 | 4 | 行数基线 | 乙 |
| 11 | 12 | v9 暴露的锚点形式 | 门禁 |
| 12 | 6 | `doc:2091` + 行数 + G1 | 甲 |
| 13 | 2 | `sig .. }` 退化 | 乙 |
| 14 | 8 | S22 成组错误 | 我 |
| 15 | 2 | `doc:2091` 旁证 | 乙 |
| 16 | 1 | depth==0 放行 | 乙 |
| 17 | 1 | 内层块冒充函数体 | 甲 |
| 18 | 5 | **SIG 白名单假阳性** | 甲+乙 |
| 19 | 3 | **bare 引用旧行号** | 乙 |
| 20 | 2 | **`t:` 归属 bug + 锚点不唯一** | 门禁 |
| **合计** | **173** | | |

## 11. 本轮新增 memory

| # | 规则 |
|---|---|
| **101** | 白名单必然漏，黑名单才封闭——「枚举合法值」换成「枚举非法值」 |
| **102** | 测试必须同时守假阴性和假阳性（13 个「必须失败」探针守不住误杀） |
| **103** | 短别名（`t:`）是显式文件归属，不能参与「向左找文件名」的推断 |
| **104** | 二分普查（SIG 认/不认）会掩盖「不认但正确」这一类 |

## 12. 我这一轮的判断失误

**我用「SIG 匹配 / 不匹配」做普查，把 70 个不匹配全部归为「内层块」。**
实际有 5 个是真函数。

**根因**：我把「SIG 不认」当成了「不是函数」的同义词。
**SIG 是白名单，它不认 ≠ 它不是。**

甲乙都是从「什么是函数」出发做普查的，所以抓到了。
**判据：验证一个分类器时，必须独立定义「正类」再比对，不能拿分类器自己的判定当基准。**
（这正是 memory 规则 104。）
