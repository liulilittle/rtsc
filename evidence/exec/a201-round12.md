# A20-1 第十二轮：`} else if` 续行被误判为函数

日期：2026-10-23
状态：**门禁 v13；19 探针全绿；88 开块行 0 mismatch**

## 1. 本轮背景：甲乙子代理额度阻塞

甲乙第十一轮复核期间，两个子代理先后返回：
- `free-model rate limit reached; slow down and retry`
- `upstream unavailable for model deepseek-v4-1-flash:free`

宿主回合两次异常终止。**这是账户/额度类硬阻塞，重派必再失败。**
已记入 `discover.md`，暂停目标并上报用户；用户 `/goal resume` 后恢复。

**恢复后我继续自己推进（不空等）**，本轮成果由此产生。

## 2. 我独立发现的盲区：`} else if (...) {`

上一轮把 `starts_a_function` 从白名单改成黑名单后，我审计它的覆盖：

```
t:315  accept=True   '} else if (st == SEC_I_CONTINUE_NEEDED) {'
t:320  accept=False  '} else {'
t:555  accept=False  '} else {'
```

### 为什么漏

两层判据都失效，且方向相反：

| 判据 | 对 `} else if (...)` 的反应 |
|---|---|
| `INNER_BLOCK`（`^(?:if|else|...)`） | **不匹配**——行首是 `}`，不是 `else` |
| `'(' not in line` | **不匹配**——该行确实有 `(` |
| `head` 含标识符 | **匹配**——`}` 后面的 `else` 是标识符 |

结果：判定为「函数」。

### 为什么之前没暴露

`brace_balanced(315, 321)` 返回 **False**（depth 不是 1），所以区间引用仍被拒绝。
**但这是两条规则偶然互补，不是设计。**

如果哪天出现一个 `} else if (...) {` 开头、且 depth 恰好为 1 的区间，
两道防线会同时失守。

## 3. 修法：加 `}` 前缀拒绝

```python
CLOSING_PREFIX = re.compile(r'^\s{0,8}\}')

def starts_a_function(src, ca):
    line = src[ca - 1]
    if INNER_BLOCK.match(line):
        return False
    if CLOSING_PREFIX.match(line):     # <- 新增
        return False
    if '(' not in line:
        return False
    head = line.split('(')[0]
    return bool(re.search(r'[A-Za-z_]\w*', head)) or '~' in head
```

**理由**：函数签名的 `{` 之前不会先有一个 `}`。
`} else if` / `} while` / `} catch` 都是**上一条语句的延续**。

## 4. 全量普查：88 个开块行，0 mismatch

独立定义「能作函数起点」的条件（不拿分类器自己的判定当基准）：

- 开块、缩进 ≤ 8
- 不以 `}` 开头（续行）
- 不是 `INNER_BLOCK` / 聚合关键字
- 含 `(`（折行签名的 `(` 在首行）

```
=== census with a CORRECTED oracle ===
  total=88  mismatches=0
```

### 5 个真函数全部接受
```
t:89   True  ~SchannelTransport() override {
t:517  True  uint32_t ExpectedActualOverhead() const {
t:561  True  static uint16_t WireVersionFromProtocolMask(DWORD mask) {
t:671  True  PCCERT_CONTEXT PeerCert() const {
t:690  True  static Error ConstError(Status s, int32_t code, const char* msg) {
```

### 内层块与续行全部拒绝
```
t:315  False  } else if (st == SEC_I_CONTINUE_NEEDED) {     <- 本轮修的
t:320  False  } else {
t:555  False  } else {
t:493  False  if (QueryContextAttributesW(...) !=
t:137  False  switch (config_.cert_policy) {
t:243  False  for (;;) {
t:679  False  SEC_E_OK) {                                   <- 折行条件尾
t:572  False  info_.tls_version > config_.max_version) {     <- 折行条件尾
```

## 5. 我的 oracle 第一版也是错的

第一版普查报了 14 个 mismatch，全是：
```
t:69   got=False want=True  uint32_t& length) {
t:102  got=False want=True  std::vector<uint8_t>& out) override {
t:679  got=False want=True  SEC_E_OK) {
```

**我把「多行签名的续行」当成了函数起点。**

正确规则：**函数签名的 `(` 必然从该行开始**（C++ 的折行只会发生在参数列表内部）。
所以 `cur:101` 是 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,`
（含 `(`），`cur:102` 是 `std::vector<uint8_t>& out) override {`（不含 `(`）。

**修正 oracle 后 0 mismatch。**

**教训**：审计工具的「独立定义」也可能错，必须自查。
第一版的 14 个 mismatch 有 14 个是我 oracle 的错，门禁的 0 个。

## 6. 19 个探针全部正确

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
D1 correct cite: destructor            exit=0 OK
D2 correct cite: uint32_t return       exit=0 OK
D3 correct cite: static uint16_t       exit=0 OK
D4 correct cite: PCCERT_CONTEXT        exit=0 OK
D5 correct cite: static Error          exit=0 OK
E1 "} else if" continuation            exit=1 OK   <- 新增
```

**探针结构已完整**：13 条「该拒」+ 5 条「该收」+ 1 条新盲区回归。

## 7. 最终验证

```
verify_anchors.py    : 407 引用 / 70 定位唯一正确 / WRONGLINE 0 / exit=0
anchors_redtest.py   : 19/19 探针正确 / exit=0
verify_citations.py  : 43 passed / 0 failed / exit=0
batch2_preflight.py  : 7 条锚点全部可定位 / exit=0
verify.ps1           : exit=0
verify.ps1 -DocCite  : exit=0
全量普查              : 88 开块行 / 0 mismatch
```

## 8. 十二轮累计

| 轮次 | 数量 | 内容 | 发现者 |
|---|---|---|---|
| 1–7 | 108 | 见 `a201-round7.md` | 甲/乙/我 |
| 8–13 | 33 | 见 round8–9 | 甲/乙 |
| 14 | 8 | S22 成组错误 | 我 |
| 15 | 2 | `doc:2091` 旁证 | 乙 |
| 16 | 1 | depth==0 放行 | 乙 |
| 17 | 1 | 内层块冒充函数体 | 甲 |
| 18 | 5 | SIG 白名单假阳性 | 甲+乙 |
| 19 | 3 | bare 引用旧行号 | 乙 |
| 20 | 2 | `t:` 归属 + 锚点不唯一 | 门禁 |
| 21 | 1 | **`} else if` 续行误判** | 我 |
| **合计** | **174** | | |

## 9. 本轮新增 memory

| # | 规则 |
|---|---|
| **105** | 两条判据偶然互补 ≠ 设计正确——每条必须独立成立 |
| **106** | 审计工具的「独立定义」也可能错，必须自查（我 oracle 第一版 14 个假 mismatch） |

## 10. 关于「偶然互补」

`brace_balanced(315,321)=False` 挡住了 `starts_a_function(315)=True` 的错。

**这不能算「门禁正确」，只能算「这次恰好没出事」。**

判据：**一个判据的每个分支都必须单独正确。**
若 A 错、B 对，且 B 恰好覆盖 A 的错，则：
- A 的错误仍在（换一个 B 覆盖不到的输入就暴露）；
- 后来者会误以为 A 是对的，据以推理。

**修 A，不是靠 B 兜底。**
