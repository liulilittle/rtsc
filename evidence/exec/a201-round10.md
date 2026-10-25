# A20-1 第十轮：内层块冒充函数体 + 乙的两处旁证

日期：2026-10-23
状态：**门禁 v11；13 探针全绿；甲乙共报 4 项，我全部独立复现**

## 1. 甲报的 X1（内层块冒充函数体）—— 属实，且比他描述的更严重

甲写：
> 把 `doc:1828` 的 `FinishHandshake`（`t:491-509`）改成函数内第一个 if 块 `t:493-496`：
> `X1  cite inner block 493-496 as a function range  ->  exit=0  WRONGLINE=0  BLIND`

### 甲的探针有个技术错误

`doc:1828` 的 `t:491-509` **没有锚点从句**：

```
doc:1828  cite='`t:491-509`'  has_clause=False  parts=[]
```

所以它走的是 `noanchor_other` 计数，**从来没经过 `brace_balanced`**。
甲的探针「改引用 + 不改锚点」→ 仍然没有锚点 → 门禁不检查它。
**甲测到的 exit=0 不是 X1，是「无锚点引用不检查」。**

### 但 X1 本身是真的

我用**真正有锚点**的 `doc:1798`（`t:101-201` + `Error Handshake(...)` .. `}`）复现：

```
X1-true: cite 493-496 + anchor if(...) .. }        exit=0  WRONGLINE=0   BLIND
X1-half: cite 493-496 + anchor Handshake           exit=1  CAUGHT
X1-anchoronly: cite 101-201 + anchor if(...)       exit=1  CAUGHT
X1-worst: cite 493-496 + short anchor              exit=0  WRONGLINE=0   BLIND
```

**「引用和锚点一起改」→ 放行。** 这正是甲说的「锚点自洽但不符合散文语义」。

## 2. 修法：I6 起点必须是函数签名

甲建议「接受这个盲区，记为 P3」。**我不同意——有便宜的修法。**

`range_matches` 里末片段是 `}` 时，区间已经由 `brace_balanced` 证明是「一个完整的块」。
**那么它必须是一个函数体，不能是内层 if/loop。**

```python
SIG = re.compile(r'^\s{0,8}(?:Error|bool|void|DWORD|std::\w+|Status|int|size_t)\s+'
                 r'([A-Za-z_]\w*)\s*\(')

def starts_a_function(src, ca):
    return bool(SIG.match(src[ca - 1]))
```

```python
if last == '}':
    return brace_balanced(src, ca, cb) and starts_a_function(src, ca)
```

### 实测

```
t:101-201  Handshake body (CORRECT)          -> PASS
t:371-384  PeerSubjectPublicKey (CORRECT)    -> PASS
t:491-509  FinishHandshake (CORRECT)         -> PASS
t:493-496  inner if block (X1-true)          -> FAIL (not a signature)
t:497-500  assignment run (X1-nested)        -> FAIL
t:99-199   shifted -2                        -> FAIL
t:528-530  another inner block               -> FAIL
```

**对真实文档零误报**：4 条走 `brace_balanced` 的引用全部 PASS。

### 为什么这不是「超出静态检查能力」

甲说「要抓 X1 必须让门禁解析中文散文」。**不需要。**
X1 的特征不是「散文说函数、引用说 if」，而是「**引用声称一个完整块，却不是函数**」。
这个特征是**源码侧的**，静态可查。

## 3. 乙报的 P2（`doc:2091` 的 `:423`/`:404`）—— 属实

```
cur:423 = 'SECURITY_NATIVE_DREP, nullptr, 0, &ctx_,'
cur:425 = 'shutdown_sent_ = true;'          <- 散文「shutdown_sent_ 已为真」
cur:404 = 'Error Shutdown(...) override {'   <- 散文「再次 Shutdown() 在 :404 返回空」
cur:406 = 'if (shutdown_sent_) return ...'   <- 实际返回空的行
```

`bak` 确证：`bak:423` = `shutdown_sent_ = true;`、`bak:404` = `if (shutdown_sent_) return ...`
→ **+2 位移**。已修。

**这正是我上一轮说的「成组错误」的延续**：我修了 S22 的 8 处修复点，
**但没扫同一行的旁证**。乙抓住了。→ memory 97。

## 4. 乙报的 P3（`depth==0` 被接受）—— 结论对，例子错

乙写：
> `brace_balanced(47, 64)` → `cur[47] = 'constexpr size_t kMinRecordHeader = 5;'`（不开启块），
> depth 在 `47..63` 为 0 → 通过。

**实测 depth = 1**，因为 `cur:60` 是 `std::string FormatCode(long code) {`，开启了块。
乙看漏了这一行。

**但结论是对的**：`if depth not in (0, 1)` 确实接受 `depth == 0`。
我构造了真正的 depth==0 案例：

```
t:103-116  depth0=OK  ca='consumed = 0;'  cb='SecBuffer in_bufs[1]{};'
t:103-120  depth0=OK  ca='consumed = 0;'  cb='uint8_t out_storage[65536] = {'
```

`t:103` 是 `consumed = 0;`（不开启块），`t:116` 恰好含 `}` → depth=0 → 通过。

**已修**：`if depth != 1: return False`。对真实文档的 4 条引用无影响（全是 depth=1）。

## 5. 13 个探针全部正确

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
C5 inner block as function body        exit=1 OK   <- 甲的 X1
C6 depth==0 range accepted             exit=1 OK   <- 乙的 P3
```

## 6. 乙主动撤回了一个假缺陷

乙写：
> **我必须撤回 §20 的「P2 I1 退化路径」**：我的 `r2a_retry.py` 计算 clause 边界时切错了位置，
> 替换没落到锚点文本上，门禁看到的是**未修改的文档** → exit=0。

**这是诚实的自我更正，值得记下。** 他的探针没有自校验
（没检查「替换是否真的落到文档里」），这和他自己批评过的「只看描述不验证」是同一类错误。

**我的 `anchors_redtest.py` 有自校验**（`old not in orig` → SKIP + 计 fail），所以没踩这个坑。

## 7. 最终验证

```
verify_anchors.py    : 407 引用 / 67 定位唯一正确 / WRONGLINE 0 / exit=0
anchors_redtest.py   : 13/13 探针正确 / exit=0
verify_citations.py  : 43 passed / 0 failed / exit=0
batch2_preflight.py  : 7 条锚点全部可定位 / exit=0
verify.ps1           : exit=0
verify.ps1 -DocCite  : exit=0
verify.ps1 -DocLint  : exit=0
verify.ps1 -PseudoLint : exit=0
```

## 8. 十轮累计

| 轮次 | 数量 | 内容 | 发现者 |
|---|---|---|---|
| 1–7 | 108 | 见 `a201-round7.md` | 甲/乙/我 |
| 8 | 15 | 区间引用 + 单点旧行号 | 甲 |
| 9 | 4 | CMakeLists 旧值 + 计数 | 乙 |
| 10 | 4 | 行数基线 | 乙 |
| 11 | 12 | v9 暴露的锚点形式 | 门禁 |
| 12 | 6 | `doc:2091` + 3 行数 + G1 | 甲 |
| 13 | 2 | `sig .. }` 退化 + `:3514` | 乙 |
| 14 | 8 | **S22 成组错误** | 我 |
| 15 | 2 | **`doc:2091` 旁证 `:423`/`:404`** | 乙 |
| 16 | 1 | **depth==0 放行** | 乙 |
| 17 | 1 | **内层块冒充函数体（X1）** | 甲 |
| **合计** | **163** | | |

## 9. 本轮新增 memory

| # | 规则 |
|---|---|
| **97** | 成组错误要扫「同一行的旁证」，不只是「同一构造的修复点」 |
| **98** | 「锚点自洽」不等于「锚点符合散文」——但有些语义是源码侧可查的（完整块 vs 函数） |
| **99** | 探针必须有自校验（替换是否真的落地），否则测的是未修改的基线 |
| **100** | 别人报的例子可能有技术错误，但结论可能仍对——两者必须分开核 |

## 10. 乙的例子错在哪

乙的 P3 例子 `brace_balanced(47, 64)` 实际 depth=1（`cur:60` 开启了块）。
**但他要说的规则问题是真的**——我另找案例证明了。

**判据：核别人的发现时，必须分开核「例子」和「结论」。**
例子错但结论对 → 修规则，不驳回。
例子对但结论错 → 只修例子。
**两者都核，才叫独立验证。**
