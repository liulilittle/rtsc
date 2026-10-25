# 批 1 独立审计 · 乙（Phase 1 独立审计 + Phase 2 互审定案）

> 审计对象：`src/credssp/credssp.cpp`（415 行）、`include/rtsc/credssp/credssp.h`（123 行）、
> `tests/test_credssp_sm.cpp`（505 行）、`tests/test_credssp.cpp`（364 行）。
> 缺陷范围：S1 / S5 / S6 / S11 / S18。
> **本文件不含任何工程代码/测试代码改动**（H7 遵守）。所有实验产物在 `F:\rtsc\.tmp\audit-b1\`。
>
> **证据口径**：`[READ:path:line]` = 我实读源码；`[BASH:命令]` = 我实跑的探针/脚本输出。
> **凡是「未验证」的，一律标注并给出验证方法（N15）。**

---

## 0. 结论摘要（先说结论，再给证据）

| 缺陷 | 缺陷是否真实 | 我的判定 | 与甲/主代理裁决的关系 |
|---|---|---|---|
| **S1** nonce 恒零 | **真实**（P0） | 修复方向正确，但**甲与文档给的 red 测试式样都有一处会永远红**；且 **S1 的修复不足以消除真正的 P0**（见 §3 N-B1） | 同意方向；**新增一条 P0 未列缺陷** |
| **S5** 服务端版本不校验 | **真实**（P1） | 同意「只拒下界」，理由不是实测，而是 `[MS-CSSP] 5.1` 原文（`security-layer.md:606`） | 同意 D2 |
| **S6** 版本不回写 | **真实**（P1） | **`min` 对，`clamp` 错**（我用未修改库实测 (4,6) 方向确认）；但**回写位置要收窄到第 2 步**，甲放在「每次响应」会引入新缺陷 | **同意 D1 结论，反对 D1 的落点** |
| **S11** 不验 MAC | **真实**（P1） | 同意；**独立确认必须用 server→client 签名密钥**（我用 wire 字节反推） | 同意 D4 |
| **S18** 生产路径无公钥 | **真实**（P0） | 同意放 `BuildStep3`；并补上「放 Start 会崩」的**机制**（不是现象） | 同意 D3 |
| **D5** 短 nonce 崩溃 | **真实**（P0 级可用性） | 同意加提前守卫；但**建议同时保留 RNG 失败的诊断信息**（甲方案会把它退化成「nonce 长度错」） | 同意 D5，补细节 |
| **D6** errorCode 优先 | **真实** | 同意；我用未修改库实测当前行为已经是 errorCode 优先 | 同意 D6 |

**一句话**：五条缺陷全部真实、方案总体可行；但**修完 S1 之后仍存在一个可离线解出凭据的 P0**（§3 N-B1），
以及 **4 处会让执行 AI 走偏的细节**（§3 N-B3 / N-B4、§4.3、§4.5）。

---

## 1. 方法与证据边界（必读，含自我披露）

### 1.1 我做了什么

1. 全文读 `credssp.cpp` / `credssp.h` / `test_credssp_sm.cpp` / `test_credssp.cpp` /
   `ts_request.cpp` / `ntlm.cpp`（SEAL 部分）/ `tls_schannel.cpp:355-392`。
2. 独立重跑主代理的 preflight，确认其读数（不采信转述）：
   `[BASH:python evidence/exec/batch1_preflight.py]` →
   `S1 PRESENT c:46` / `S5 PRESENT c:42` / `S5b ABSENT` / `S6 ABSENT` / `S18 ABSENT` /
   `RESULT: batch 1 is executable`。**与主代理转述一致。**
3. 独立跑基线三套件（**这是修改前的绿基线，必须记录**）：
   `[BASH:build\verify\rtsc_credssp_sm_tests.exe]` → `15 tests, 92 checks, 0 failing tests, 0 failed checks`
   `[BASH:build\verify\rtsc_credssp_tests.exe]` → `23 tests, 69 checks, 0 failing...`
   `[BASH:build\verify\rtsc_ntlm_tests.exe]` → `27 tests, 136 checks, 0 failing...`
4. 自己写两个探针，**链接未修改的 `build/verify/rtsc_credssp.lib`**，直接测当前行为
   （`F:\rtsc\.tmp\audit-b1\probe_b1.cpp`、`probe_b1b.cpp`，输出见 §2 各条与 §4）。

### 1.2 自我披露（诚实优先）

我这两个探针是**在「禁止自行启动 exe」规则到达之前**跑的（`probe_b1.exe` / `probe_b1b.exe`，
`/MDd` 构建）。规则到达后我**没有再启动任何 exe**，也没有再编译新的探针
（`probe_b1c.cpp` 已写好但**未编译未运行**，留作主代理统一驱动用）。
如需复核我的读数，请主代理按新流程驱动：
`cmd /c F:\rtsc\.tmp\build_probe_safe.bat F:\rtsc\.tmp\audit-b1\probe_b1.cpp <out.exe> rtsc_credssp.lib rtsc_crypto.lib`。

### 1.3 环境事实（影响复现）

`[BASH:Select-String build\verify\CMakeCache.txt CMAKE_BUILD_TYPE]` → `Debug`，
`CMAKE_CXX_FLAGS_DEBUG=/Ob0 /Od /RTC1`。
**这就是为什么短 nonce 会崩而不是静默越界**：Debug 的 `_ITERATOR_DEBUG_LEVEL=2` 会在
`vector::iterator + n` 越界时直接断言（§2.1.4）。Release 下是静默读越界，更危险。

---

## 2. 阶段 1：逐条独立审计

### 2.1 S1 —— `nonce_` 恒为 32 个 0

#### 2.1.1 缺陷实证（不引文档，只引代码 + 实测）

写入点（唯一）：`[READ:src/credssp/credssp.cpp:44-46]`

```cpp
// A deterministic-looking default keeps the nonce length valid even if the
// caller forgets to set one; production code always overrides it.
nonce_.assign(kNonceSize, 0);
```

注释说「production code always overrides it」——**这是假话**。`server_public_key_` /
`nonce_` 的生产写点为零：`[BASH:Select-String -Path src\credssp\*.cpp,include\rtsc\credssp\*.h -Pattern exported_session_key_]`
只命中 `credssp.cpp` 自身与测试钩子；`nonce_` 的唯一非测试写入就是 `:46`。

三个消费点，全部在安全路径上：

| 位置 | 代码 | 后果 |
|---|---|---|
| `[READ:credssp.cpp:176]` | `in.client_challenge.assign(nonce_.begin(), nonce_.begin() + 8);` | NTLMv2 ClientChallenge 恒为 8 个 0 |
| `[READ:credssp.cpp:191]` | `exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);` | ExportedSessionKey 恒为 16 个 0 |
| `[READ:credssp.cpp:244]` | `if (version_ >= kFirstHashVersion) req.client_nonce = nonce_;` | clientNonce 恒为 32 个 0 |

`[BASH:probe_b1.exe]`（P6，两个独立 client 各自走到第 3 步）：

```
=== P6  S1: two clients DRIVEN to step 3 ===
  client_nonce equal=1
  exported key equal=1
  nonce hex=0000000000000000000000000000000000000000000000000000000000000000
  exported hex=00000000000000000000000000000000
```

握手**成功**（`ok=1`），没有任何错误信号 —— 这是最危险的部分：静默失去机密性。

#### 2.1.2 一个必须先纠正的测试式样错误（doc:1789 的写法是坏的）

doc:1789 的红证写的是：

> 新增测试 `two_constructions_have_different_nonces`，断言 `CredsspClient(c,6)` 两次的
> `ExportedSessionKeyForTest()` 不同 → 当前必失败（都全零）

**「都全零」是错的。** `exported_session_key_` 在构造时**是空 vector**，只在 `BuildStep3`
里被赋值（`[READ:credssp.cpp:184-194]`）。实测：

```
=== P5  S1: two FRESH constructions (doc:1789 test formulation) ===
  fresh exported keys differ=0  a.size=0 b.size=0
  NOTE: empty==empty -> this formulation stays RED even after a correct fix
```

即：如果执行 AI 照 doc:1789 的字面写（**只构造、不驱动**），这条测试在**修复后仍然是红的**
（两个空 vector 恒相等），TDD 第 6 步永远到不了。这是 doc 的缺陷，不是实现的缺陷。

**正确式样**：必须驱动到第 3 步（`Start` + `OnServerResponse`），此时 `exported_session_key_`
才被填充。甲的报告 §4.1 正是这么写的（4 个 client 各走 `Start` + `OnServerResponse`），
**这一点甲是对的，doc 是错的**；执行 AI 必须以甲的式样为准，不得照抄 doc:1789。

#### 2.1.3 修复方案（≥2 候选）

**方案 A（最小）**：`credssp.cpp:44-46` 换成

```cpp
if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();
```

新增 `include/rtsc/crypto/random.h` + `src/crypto/random.cpp`（放 `rtsc_crypto`，
`[READ:CMakeLists.txt:39]` 现为 `add_library(rtsc_crypto STATIC src/crypto/hash.cpp)`，需加源文件；
`[READ:CMakeLists.txt:132]` `rtsc_credssp` 已 `PUBLIC rtsc_crypto`，**依赖方向天然成立，不需要动
`rtsc_credssp` 的链接**）。

- 下游影响：`nonce_` 长度仍是 32 → `:176` / `:191` / `:229` / `:244` 全部不变。
- 会不会破现有 15 条：**不会**，15 条全部先调 `SetNonceForTest(FixedNonce())`
  （`[READ:tests/test_credssp_sm.cpp:107,148,184,219,285,322,356,379,401,415,443,480]` 共 12 处），
  构造期随机值被覆盖。
- **风险（甲已发现，我确认）**：`nonce_.clear()` 后 `nonce_` 为空，而 `BuildStep3` 里
  `:176` 的切片在 `:229` 的尺寸检查**之前** → 空 nonce 不是「优雅失败」而是崩溃（§2.1.4）。

**方案 B（推荐 = A + 提前守卫）**：在 `BuildStep3` 开头（`:117` 之前）加

```cpp
if (nonce_.size() != kNonceSize) {
    return Fail(Status::kUnsupported, "nonce must be 32 bytes");
}
```

- 语义：把「RNG 失败」变成可诊断错误，而不是 UB。
- 会不会破现有 15 条：**不会**（所有用例 nonce 都是 32）。

**方案 C（我建议在 B 之上再加，成本 3 行）**：把 RNG 失败**原因**保留下来。
构造函数不能返回 `Error`，但可以记一个成员：

```cpp
// 头文件私有区
bool nonce_ready_ = false;      // 构造期 CSPRNG 是否成功
int32_t nonce_error_ = 0;       // GetLastError()/errno，供 native_code
```

构造里 `nonce_ready_ = crypto::RandomBytes(nonce_, kNonceSize); if (!nonce_ready_) nonce_error_ = ...;`
`BuildStep3` 守卫里 `return Fail(Status::kInternal, "CSPRNG failed", nonce_error_);`

> **前置步骤（§9.9）**：`credssp::Status` 目前**没有** `kInternal`（`ts_request.h:21-26` 只有 4 个值）。
> 本方案要求**先**在 `ts_request.h` 加 `kInternal` 枚举值，否则编译不过。见 §9.9 的裁决与成本核算。

理由：doc:4003-4004 明确要求「调用点必须检查返回值……`GetLastError`/`errno` 进 `native_code`」。
甲/文档的方案 B 把 RNG 失败与「调用方传了短 nonce」压成同一条消息，现场无法区分
「系统 RNG 坏了」与「测试传错长度」——这两件事的处置完全不同。

#### 2.1.4 甲报的「短 nonce 崩溃」：我确认，并补上机制

代码事实（无需运行即可判定）：

- `[READ:credssp.cpp:176]` `nonce_.begin() + 8` —— 要求 `size >= 8`；
- `[READ:credssp.cpp:191]` `nonce_.begin() + 8` 与 `nonce_.begin() + 24` —— 要求 `size >= 24`；
- 唯一的尺寸检查在 `[READ:credssp.cpp:229]`，位于**两者之后**，且嵌在
  `if (version_ >= kFirstHashVersion)` 分支里。

因此 `size < 8` 在 `:176` 就 UB，`8 <= size < 24` 在 `:191` UB，两者都早于 `:229`。
`[BASH:evidence/exec/batch1-a-audit-short-nonce.txt]`（甲实测）与我的代码阅读一致：
`nonce=0/4 → exit 0xC0000409`、`nonce=16/23 → exit 3`、`nonce>=24 → kUnsupported`。

**我补的机制**：Debug 构建下 `_ITERATOR_DEBUG_LEVEL=2`，`std::vector` 迭代器加减会走
`_Adl_verify_range`（这就是 `probe_b1.exe` 首次链接时报的
`__imp__CrtDbgReport` / `_Adl_verify_range` 符号）。所以「崩溃」不是某个 if 写错，
而是**容器迭代器越界断言**；Release 下不崩，变成静默读越界 —— **更危险**。
这决定了：守卫必须放在**所有切片之前**，不能只放在 `:229`。

#### 2.1.5 测试方案 `two_constructions_have_different_nonces`

- **给定**：一个合法 CHALLENGE（`ServerChallengeMessage()`，`[READ:tests/test_credssp_sm.cpp:75-97]`），
  4 个独立 `CredsspClient(TestCreds(), 6)`，**都不调** `SetNonceForTest`，都设合法公钥。
- **当**：各自 `Start` → `OnServerResponse`（必须驱动到第 3 步，理由见 §2.1.2）。
- **则**：
  1. `k = c.ExportedSessionKeyForTest()`，`CHECK(k.size() == 16)`；
  2. `CHECK(Hex(k) != Hex(Bytes(16, 0)))` —— 抓「常量 0」；
  3. 相邻两次 `CHECK(Hex(k) != Hex(prev))` —— 抓「固定非零常量」。
- **为什么能抓**：修复前 `exported` 恒为 16 个 0 → 断言 2 红；若有人用
  `std::fill(nonce_, 0x42)` 之类固定填充糊弄 → 断言 2 绿但断言 3 红。
- **它抓不到什么（必须承认，doc:4006-4012）**：`rand()` / 时间播种 / 固定种子的 `mt19937`
  **两条断言都绿**。所以本批**必须**附带静态门禁：

  ```powershell
  Select-String -LiteralPath F:\rtsc\src\credssp\credssp.cpp -Pattern '\brand\(|\bsrand\(|std::random_device|mt19937'
  # 必须无输出
  ```

  并且要扫 `src/crypto/random.cpp`（新文件）—— 甲的方案里**只写了注释「Never rand()/random_device」，
  没有把门禁写进 verify 脚本**（我 grep 甲的报告：`gate|Select-String` 无命中）。
  doc:4010-4012 说「把这条写进 verify 脚本，才算真正守住 S1」。**这是甲的缺口，执行前必须补。**

#### 2.1.6 红证可行性

| 步骤 | 操作 | 预期输出 |
|---|---|---|
| 1 | 写 `two_constructions_have_different_nonces`（驱动到第 3 步） | 编译通过 |
| 2 | 跑 | `[ FAIL ] two_constructions_have_different_nonces` + `FAIL ... Hex(k) != Hex(Bytes(16, 0))` ×4、`FAIL ... Hex(k) != Hex(prev)` ×3 → `1 failing tests, 7 failed checks` |
| 3 | 改 `:46` + 加 random.cpp + 加守卫 | 15+1 全绿 |
| 4 | 变异回 `nonce_.assign(kNonceSize, 0);` | 同上 7 failed checks（甲已实测：`[BASH:evidence/exec/batch1-a-audit-mutations.txt]`） |

---

### 2.2 S5 —— 服务端 `TSRequest.version` 从不校验

#### 2.2.1 缺陷实证

`[READ:credssp.cpp:91-113]`：`req.Decode` 成功后（`:92-93`）直接进 `:97` 的 errorCode 分支、
`:107` 的 step 分派。**`req.version` 在全文件只被 `TsRequest::Decode` 写入，从未被读取**：

`[BASH:Select-String -Path src\credssp\credssp.cpp -Pattern "req\.version"]` → 只有
`:72`、`:241`、`:300` 三处**赋值给 `req.version`**（发送方向），没有一处读它做判断。

实测（合法 CHALLENGE + `version=1`）：

```
=== P1  S5: server version=1 + VALID challenge (defect must be 'accepted') ===
  result ok=1 status=kOk out=389
  step3.version=6 client_nonce=32 pubkeyauth=48
```

`ok=1` —— 完全通过。

#### 2.2.2 doc:1793 说「现有测试靠 token 解析失败通过」——**我验证了，成立**

`[READ:tests/test_credssp_sm.cpp:128-140]` 用 `bad.nego_token = FromHex("0011");`（2 字节）。
我用同一份输入实测失败点：

```
=== A1  S5 defect mechanism: version=1 with the CURRENT test's token '0011' ===
  ok=0 status=1 msg='cannot decode CHALLENGE'
```

`status=1` 即 `kTruncated`，消息来自 `[READ:credssp.cpp:124]`
`return Fail(e.status, "cannot decode CHALLENGE");` —— 与版本**无关**。
所以那条测试今天绿，是因为 `ChallengeMessage::Decode` 在
`[READ:src/credssp/ntlm.cpp:186-188]` 先查签名（`size < 12` → `kTruncated`）。
**doc:1793 的论断被证实。**

#### 2.2.3 「拒绝」还是「钳制」？——我的结论：**只拒下界，上界钳制**

这是你让我主攻的第一个点。我不引实测，引**规范原文**：

`[READ:docs/spec/security-layer.md:606]` 的 `version` 行明确引了 `[MS-CSSP]`：

> 「If the version received is greater than the implementation understands, **treat the peer as
> one that is compatible with the version … that the implementation understands**」

即：**高于我方的版本不是错误，是「按我方最高版本处理」**。所以上界不能拒。
下界（`< 2`）不在该条款覆盖范围（2 是合法值集合的最小值，`[READ:security-layer.md:606]`
「合法值 2,3,4,5,6」），且 `kMinVersion=2` 对应的是「CredSSP 协议根本不存在 v1」→ 必须拒。

补充实测（支持「现实 peer 会声明更高版本」）：`[BASH:evidence/exec/batch1-a-audit-version-range.txt]`
（甲）与我的 P2 都显示服务器/构造的 peer 回 6/7/8/100 时客户端今天**照单全收**；
`[READ:security-layer.md:236]` 记录「客户端发 1..8，服务器始终回 6」。
**结论：D2「只拒下界」正确，我同意甲。**

但**代价必须写清楚**：现有测试名 `step1_rejects_server_version_above_our_max`
（`[READ:tests/test_credssp_sm.cpp:128]`）从此**名不副实**。按 H7/N2 不改它
（它只断言 `!e.ok()`，加了下界检查后仍绿，只是失败原因从「token 解析」变成「版本过低」）。
**副作用**：`BuildStep3` 里「非法 CHALLENGE → cannot decode CHALLENGE」这条路径**失去唯一测试**。
建议（可选、不改现有测试）新增 `malformed_challenge_token_is_rejected`：
给合法 version + `nego_token="0011"`，断言 `status==kTruncated`。
不加也不会让本批失败，但覆盖会掉一块。

#### 2.2.4 修复方案（≥2 候选）

**方案 A（doc:1793，双边拒绝）**：

```cpp
if (req.version < kMinVersion || req.version > kMaxVersion) {
    return Fail(Status::kUnsupported, "unsupported TSRequest version");
}
```

- 会不会破现有 15 条：不会（15 条里 CHALLENGE 的 version 都是 3/4/6，见
  `[READ:tests/test_credssp_sm.cpp:155,190,225,293,330,487]`）。
- **缺点**：违反 `[MS-CSSP]` 原文（`security-layer.md:606`），把合法的 v7 peer 判死。

**方案 B（推荐，= 甲 D2）**：只拒下界，上界交给 S6 的 `min` 自然吸收。

```cpp
if (req.version < kMinVersion) {
    return Fail(Status::kUnsupported, "unsupported TSRequest version");
}
```

- 会不会破现有 15 条：不会（15 条里没有 version<2 的 CHALLENGE；唯一 version=1 的那条
  用的是非法 token，断言只要求 `!ok()`）。
- 下游：`kMaxVersion` 仍用于构造期钳制（`:43`），语义不变。

#### 2.2.5 测试方案 `version_below_min_is_rejected_with_valid_challenge`

- **给定**：`CredsspClient(TestCreds(), 6)` + `SetNonceForTest(FixedNonce())` + 合法公钥；
  `TsRequest{version=1, nego_token=ServerChallengeMessage()}`。
- **当**：`OnServerResponse`。
- **则**：`!e.ok()`、`e.status == Status::kUnsupported`、`step3.empty()`、`!complete()`。
- **控制组（必须有，否则「全拒」也能过）**：**另一个新 client** 用 version=6 + 同一 CHALLENGE
  → 必须 `ok()`。踩坑点（甲已记录、我确认）：`Fail()` 会把 `step_` 置 `kFailed`
  （`[READ:credssp.cpp:54]`），同一 client 后续调用直接返回旧错误（`[READ:credssp.cpp:83]`），
  所以控制组必须换新实例。
- **为什么能抓**：合法 token 排除了「token 解析失败」这条假绿（§2.2.2 实测）。

#### 2.2.6 红证可行性

删掉下界检查 → `[ FAIL ] version_below_min_is_rejected_with_valid_challenge`，
`FAIL ... !e.ok()` / `e.status == Status::kUnsupported` / `step3.empty()`。
（甲实测：`5 failed checks`，含 `error_code_wins_over_bad_version`。）

---

### 2.3 S6 —— 服务端版本不回写 `version_`

#### 2.3.1 缺陷实证

`[READ:credssp.cpp:40-47]` 构造期钳制；`[READ:credssp.cpp:241]`、`[READ:credssp.cpp:300]`
都写 `req.version = version_;`。全文件**没有** `version_ = ...req.version...`。

实测（客户端 6，服务器回 3）：

```
=== P3  S6: server version=3 + valid challenge (client stays at 6) ===
  result ok=1 status=kOk out=389 client.version()=6
  step3.version=6 client_nonce=32 pubkeyauth=48 (want 3 / 0 / 24)
```

`pubkeyauth=48` = `16 + 32`（v5+ 的绑定哈希路径）；应为 `16 + 8 = 24`（v2/3/4 的裸公钥路径）。
`client_nonce=32` 应为 0。**这是实打实的协议错误**：对 v3 服务器发 v6 结构，第 4 步必然失败，
且错误表现为「echo mismatch」（`[READ:credssp.cpp:284]`），把「版本不匹配」伪装成「MITM」，
误导排查 —— 与 doc:1793 的描述一致。

#### 2.3.2 你让我主攻的第二点：`c:241` / `c:300` 会怎么变？会不会破 `step1_rejects_server_version_above_our_max`？

**(a) 回写后 `:241` / `:300` 的行为变化**

`:241`（第 3 步）与 `:300`（第 5 步）都是 `req.version = version_`，所以回写后**自动跟随**。
连带分叉点：

| 位置 | 判定 | 回写后 |
|---|---|---|
| `[READ:credssp.cpp:228]` | `version_ >= kFirstHashVersion` → 哈希 vs 裸公钥 | 跟随 |
| `[READ:credssp.cpp:244]` | 同上 → 是否带 `client_nonce` | 跟随 |
| `[READ:credssp.cpp:266]` | 第 4 步期望值用哪个方向的哈希 | 跟随 |
| `[READ:credssp.cpp:368]` | `MakeServerEchoForTest` 的期望明文 | 跟随（测试夹具自动一致，**这是甲「不用逐处改」的正确性依据**） |

**(b) 会不会破 `step1_rejects_server_version_above_our_max`（t:128-140）？**

**不会**，但理由和甲说的不完全一样，我给出更精确的：
这条测试的失败发生在 `BuildStep3`（`[READ:credssp.cpp:124]`，实测 §2.2.2），
而 S6 的 `version_` 回写在 `OnServerResponse` 的更早位置（errorCode 之后、分派之前）。
回写只改 `version_` 的值，**不改变「`nego_token="0011"` 解不出 CHALLENGE」这个事实**，
所以 `!e.ok()` 依旧成立 → 测试仍绿。**实测印证**：甲跑修复后 `15/92` 全绿。

**(c) 关键：`min` 还是 `clamp`？—— 我用未修改的库给出独立判定**

这是 D1，硬分歧。我不依赖影子树，而是**用「当前未修改的库」测 (client 4, server 6)**：

```
=== A4  S6: client announced 4, server replies 6 (doc's clamp upgrades us) ===
  client.version() after ctor = 4
  step1 announces version=4
  step3 now: ok=1 status=0 version=4 nonce=0 pubkeyauth=24
```

**判定依据（这是最干净的一条推理）**：
- 当前代码**没有**回写，所以 `version_` 保持构造值 4 → step3 发 v4 / 无 nonce / 24 字节。
- `min(4, 6) = 4` → **修复后行为与今天完全一致**（这一步不该有任何行为变化）。
- `clamp(6, 2, 6) = 6` → 修复后 step3 变成 v6 / 32 字节 nonce / 48 字节，**与第 1 步已声明的 v4 矛盾**，
  也与「调用者显式要求 v4」矛盾。

→ **`min` 对，`clamp` 错。我独立同意甲 D1 的结论。**

补一层协议理由：CredSSP 的 `version` 是**双方各自声明的最高支持版本**（`security-layer.md:236`
实测「服务器始终回 6，不做取最小值协商」），所以「协商结果 = min(双方声明)」是唯一自洽的解释；
`clamp` 是「取服务器声明」，等于让服务器单方面**升级**客户端。

#### 2.3.3 但 D1 的**落点**我不同意甲（这是我要提的修正）

甲把两件事都放在 `OnServerResponse` 的「errorCode 分支之后、step 分派之前」
（`[READ:docs/spec/batch1-audit-a.md:587]`、`:632-635`）：

```cpp
if (req.version < kMinVersion) return Fail(...);
version_ = std::min(version_, req.version);
if (step_ == Step::kAwaitChallenge) return BuildStep3(req, out);
if (step_ == Step::kAwaitServerEcho) return BuildStep5(req, out);
```

**问题**：这段在**每次**响应上都会执行，包括第 4 步。于是出现一个今天不存在的新状态：
「第 2 步协商到 v6 → 第 3 步已按 v6 发出哈希 + nonce → 第 4 步服务器回 `version=4`
→ `min` 把 `version_` 改成 4 → 第 5 步按 v4 语义编码」。

- 第 5 步只发 `authInfo`（`[READ:credssp.cpp:299-302]`），`version` 字段本身会变 4，
  但 `SealSend` 的密钥/序列号不变 —— **不一定会立刻报错，而是把「协商结果」改成与第 3 步不一致**，
  且没有任何测试覆盖（现有第 4 步用例都发 `version=6`，`[READ:tests/test_credssp_sm.cpp:300,430,456]`）。
- 协议上，版本协商应**在第 2 步锁定**，之后不再变。

**建议（最小修正，不改变 D1 结论）**：把**回写**收窄到第 2 步，把**范围检查**保留在分派之前：

```cpp
// errorCode 分支之后
if (req.version < kMinVersion) {
    return Fail(Status::kUnsupported, "unsupported TSRequest version");
}
if (step_ == Step::kAwaitChallenge) {
    version_ = std::min(version_, req.version);   // 协商只在第 2 步发生
    return BuildStep3(req, out);
}
if (step_ == Step::kAwaitServerEcho) return BuildStep5(req, out);
```

- 对现有 15 条：无影响（第 4 步都是 v6，`min(6,6)=6`）。
- 对 S6 测试：无影响（只走第 2 步）。
- 建议补一条 `server_echo_version_does_not_downgrade`：客户端 6、第 2 步 6、第 4 步 4
  → 断言第 5 步 `req.version == 6`（今天也是 6；甲的落点会变成 4 → 红）。
  **这条能锁住「协商只发生一次」这个不变量。**

#### 2.3.4 修复方案（≥2 候选）

**方案 A（doc:1794）**：`version_ = std::clamp(req.version, kMinVersion, kMaxVersion);`
→ **否决**（(4,6) 方向把客户端升级，见 §2.3.2(c)）。

**方案 B（推荐，甲 D1 + 我的落点修正）**：第 2 步内 `version_ = std::min(version_, req.version);`
（下界已由 §2.2 的方案 B 拦住，故 `min` 结果必在 `[2,6]`）。

**方案 C（更严格，可选）**：显式维护 `negotiated_version_` 与 `announced_version_` 两个字段，
第 1 步发 `announced_version_`，第 3/5 步发 `negotiated_version_`，并断言
`negotiated_version_ <= announced_version_`。语义最清晰，但要动头文件与更多行，
本批收益不抵成本 —— **不建议在本批做**。

#### 2.3.5 测试方案 `server_version_is_echoed_back`

两个方向（**B 方向是区分 `min` 与 `clamp` 的唯一用例**）：

- **A（抓「不回写」）**：客户端 6，服务器回 3 →
  `req.version==3`、`req.client_nonce.empty()`、`req.pub_key_auth.size()==16+spk.size()`、`c.version()==3`。
- **B（抓「clamp 升级」）**：客户端 4，服务器回 6 →
  `req.version==4`、`client_nonce.empty()`、`pub_key_auth.size()==16+spk.size()`、`c.version()==4`。
- **为什么能抓**：A 在今天发 v6/32/48（实测 P3）→ 四条全红；B 在 `clamp` 下变 v6/32/48（甲实测 4 红）。
- 我实测的 B 方向「当前值」（`version=4/nonce=0/pka=24`）正好是 `min` 的期望值，见 §2.3.2(c)。

#### 2.3.6 红证可行性

删掉 `version_ = std::min(...)` → `[ FAIL ] server_version_is_echoed_back`，
`FAIL ... req.version == 3` / `req.client_nonce.empty()` /
`req.pub_key_auth.size() == 16 + spk.size()` / `c.version() == 3`（甲实测 4 failed checks）。

---

### 2.4 S11 —— `OpenReceive` 只解密、不验 MAC

#### 2.4.1 缺陷实证（你让我主攻的第三点：现在到底验没验、验的是什么）

`[READ:credssp.cpp:347-362]` 全文：

```cpp
Error CredsspClient::OpenReceive(const Bytes& field, Bytes& plaintext) {
    if (field.size() < kSignatureSize) { ... }
    if (!rc4_ready_) { ... }
    const Bytes ciphertext(field.begin() + 16, field.end());
    plaintext = recv_rc4_.Apply(ciphertext);
    ++recv_seq_;
    return Ok();          // field[0..16) 从未被读取
}
```

**结论：`field[0..16)` 的 16 字节签名（Version/Checksum/SeqNum）一个字节都没读。**
`recv_seq_` 只自增、从不与 `field[12..16)` 比对。所以：
- 现在「验」的**只有**解密后 `[READ:credssp.cpp:283]` 的 `plain != expected` 回显比对；
- 回显比对**只覆盖明文值**，不覆盖「谁发的」「是否被重放」「序列号是否正确」。

实测（只翻 `echo[4]` = checksum 首字节，密文不动）：

```
=== P7  S11: tamper the signature CHECKSUM byte (ciphertext untouched) ===
  echo size=48 first4=01000000
  result ok=1 status=kOk msg='' complete=1 (defect: 1/ok)
```

**完全察觉不到，且 `complete()=1`（凭据已发出）**。
再翻 `echo[12]`（seq 首字节）：

```
=== P8  S11: tamper the signature SEQ field ===
  result ok=1 status=kOk complete=1
```

seq 也完全不校验。基线（不篡改）：

```
=== P9  S11: untampered echo still accepted (green baseline) ===
  result ok=1 complete=1
```

#### 2.4.2 你让我确认的 D4：签名密钥方向 —— **我用 wire 字节独立确认了甲是对的**

我不采信甲的输出，而是**从 `MakeServerEchoForTest()` 产出的真实 wire 反推**哪个密钥能复现它：

```
=== A2  S11 key direction: which signing key covers the step-4 echo? ===
  exported=08090a0b0c0d0e0f1011121314151617
  sig=0100000057179c5a8e4699ca00000000
  echo plaintext=d791087c0e91a056ef1ce7d5ba4610680d8c9a59ee4a1426ac7ce80d03ea607a
  expected    =d791087c0e91a056ef1ce7d5ba4610680d8c9a59ee4a1426ac7ce80d03ea607a
  signing_key_ (client->server)      -> does NOT match  (e09dbc8bf77cc1e8)
  DeriveSigningKey(exported,true)    -> MATCHES wire  (57179c5a8e4699ca)
```

**判定：D4 成立。** 接收方向必须用 `DeriveSigningKey(exported_session_key_, true)`
（server→client）。依据链：
- `[READ:credssp.cpp:196]` `signing_key_ = DeriveSigningKey(exported_session_key_, false);` —— client→server；
- `[READ:credssp.cpp:384]` `MakeServerEchoForTest` 用的正是 `DeriveSigningKey(exported_session_key_, true)`；
- 我的 A2 显示只有 `true` 方向能复现 wire 上的 checksum。

如果按 doc:1799 字面用 `signing_key_`，`step5_sends_authinfo_only`
（`[READ:tests/test_credssp_sm.cpp:283-315]`）与 `authinfo_plaintext_...`（`:441`）必红 —— 甲实测一致。

#### 2.4.3 修复方案（≥2 候选）

**方案 A（doc:1799 字面）**：用 `signing_key_` 重算 HMAC。→ **否决**（方向错，§2.4.2）。

**方案 B（推荐，甲 D4）**：解密文 → 同一 RC4 流解 checksum → 用 server→client 密钥重算 → 比对；
顺带校验 `Version==1` 与 `SeqNum==recv_seq_`。

顺序对称性依据：`[READ:credssp.cpp:318-329]` 发送侧是「先 `Apply(plaintext)`，再 `Apply(mac8)`」；
`[READ:src/credssp/ntlm.cpp:404-416]` 的 `Seal` 注释明确写了「A fresh instance gives a different value
and the peer rejects the signature」。接收侧必须镜像：**先解密文，再解 checksum，同一个 `recv_rc4_` 实例**。

**方案 C（更强，可选）**：把 `Seal`/`Open` 抽成 `ntlm.cpp` 的对称函数对
（`Open(sealing_key, signing_key, expected_seq, field, plaintext)`），让发送/接收共用一份
序列号与 RC4 流逻辑，从结构上消除「两边顺序不一致」。代价：动 `ntlm.h`/`ntlm.cpp`（27 条
`rtsc_ntlm_tests` 的影响面），本批**不建议**。

#### 2.4.4 我要补的三个细节（甲方案里缺）

1. **`Version` 字段校验失败时 `plaintext` 没被清空**。甲的参考实现里只有 MAC 不匹配分支
   `plaintext.clear();`（`[READ:evidence/exec/batch1-a-fixed-credssp-reference.cpp:426-428]`），
   version / seq 两个分支直接 `return Fail(...)` 而 `plaintext` 已是解密结果。
   当前调用点 `[READ:credssp.cpp:257-259]` 确实 `if (!e.ok()) return e;` 丢弃它，所以**今天不泄露**；
   但这是「靠调用方纪律」而不是「函数自身安全」。建议三个失败分支统一先 `plaintext.clear()`。
2. **`recv_seq_` 校验是新增语义，必须有测试**。否则「只 ++ 不校验」这个缺陷（`[READ:credssp.cpp:360]`）
   在修完 MAC 后仍然存在（MAC 覆盖 `seq_le32 || plaintext`，但攻击者可以把 seq 改成任何值并
   重算 MAC 吗？—— 不能，没有密钥。所以 MAC 已经隐含覆盖 seq；**但显式 `seq != recv_seq_`
   才能挡住「旧消息重放」**：重放的旧消息 MAC 本身是合法的）。这正是我 P8 测到的洞。
   建议测试 `replayed_echo_with_stale_seq_is_rejected`：`MakeServerEchoForTest()` 两次
   （`const` 方法不推进 `recv_seq_`，两次 seq 都是 0），先接受第一条，再喂第二条
   → 修后必须 `kMalformed`（seq 0 != recv_seq_ 1）。**这是唯一能观测 seq 校验的用例**
   （甲说「没找到能观测它的用例」——这条就是）。
3. **失败时不要 `++recv_seq_`**。甲的实现在三个失败分支提前 return（正确），只在成功路径 `++`
   （`[READ:evidence/exec/batch1-a-fixed-credssp-reference.cpp:430]`）。要确认执行 AI 不要照抄
   原 `[READ:credssp.cpp:360]` 的「无条件 ++」。

#### 2.4.5 测试方案 `tampered_signature_checksum_is_rejected`

- **给定**：正常走到第 3 步；`Bytes echo = c.MakeServerEchoForTest(); echo[4] ^= 0xFF;`
  （checksum 首字节，**密文 `[16..)` 不动**）。
- **当**：把 `echo` 装进 `TsRequest{version=6, pub_key_auth=echo}`，`OnServerResponse`。
- **则**：`!e.ok()`、`e.status==kMalformed`、`step5.empty()`、`!c.complete()`。
- **控制组**：未篡改的 echo → `ok()` 且 `complete()`（证明不是「一律拒绝」）。
- **为什么能抓**：密文不动 → 解密明文不变 → `[READ:credssp.cpp:283]` 的回显比对必然通过
  → **唯一能拒绝它的就是 MAC 校验**。这精确隔离了「MAC 校验」与「回显比对」（doc:1799 的设计要点）。
  我实测修复前 `ok=1 complete=1`（P7），所以这条今天必红。

#### 2.4.6 红证可行性

把 `OpenReceive` 改回「只解密 + ++seq」→ `[ FAIL ] tampered_signature_checksum_is_rejected`，
`FAIL ... !e.ok()` / `e.status == Status::kMalformed` / `step5.empty()` / `!c.complete()`
（甲实测 4 failed checks）。

---

### 2.5 S18 —— 生产路径永远拿不到服务器公钥

#### 2.5.1 缺陷实证

唯一写入点：`[READ:include/rtsc/credssp/credssp.h:61]`

```cpp
void SetServerPublicKeyForTest(const Bytes& spk) { server_public_key_ = spk; }
```

读点 7 处（`[READ:credssp.cpp:232,234,267,269,369,371,410]`）。生产代码无写入。

实测（不调任何 setter，喂合法 CHALLENGE）：

```
=== P4  S18: no public key set, valid challenge ===
  result ok=1 status=kOk out=389 (want: failure 'server public key not set')
  pubKeyAuth produced over an EMPTY key: 48 bytes

=== P11 Start() with no public key (does it fail today?) ===
  Start ok=1 out=57
```

`pubKeyAuth = Seal(SHA256(magic_c || nonce || ""))` —— 对一个**空公钥**做了绑定。
MITM 防护静默归零，握手「成功」。这是 P0。

#### 2.5.2 公钥来源（你让我核的字节语义）—— 我读了实现，与甲的结论一致

`[READ:include/rtsc/net/tls.h:166-170]`：`PeerSubjectPublicKeyInfo`（整段 SPKI）与
`PeerSubjectPublicKey`（仅 SubjectPublicKey）**是两个不同接口**，且注释明确警告：
「Never slice it out of the SPKI at a fixed offset: the offset differs between key sizes
(measured 24 for RSA-2048, 22 for RSA-1024)」。

`[READ:src/net/tls_schannel.cpp:371-384]`：

```cpp
const CRYPT_BIT_BLOB& key = cert->pCertInfo->SubjectPublicKeyInfo.PublicKey;
out.assign(key.pbData, key.pbData + key.cbData);
```

`CRYPT_BIT_BLOB.cbData` 是**含 unused-bits 首字节**的 BIT STRING 内容长度。
所以 `PeerSubjectPublicKey()` 返回的是 `unused_bits || RSAPublicKey DER`。
甲实测 `unused_bits=0`、`pubkey == BIT STRING contents 去掉首字节`。

**我的判定（与甲一致，但标注为「部分未验证」）**：
- 我**读了** `tls.h:166-170` 与 `tls_schannel.cpp:371-384`，确认「返回 BIT STRING 内容」；
- 甲实测「去掉了 unused-bits 字节、`pubkey` 以 `30` 开头」—— 我**未独立复现**（不能再启动 exe），
  标注 `[未验证-依赖甲实测]`；
- 但**有一个逻辑自洽点支持甲**：CredSSP 的 binding hash 定义是
  `SHA256(magic || nonce || SubjectPublicKey)`（`[READ:credssp.h:35-38]` 注释、
  `[READ:docs/spec/security-layer.md:1608-1613]` 的 `SIGNKEY` 表），而 `SubjectPublicKey`
  在 X.509 里是 `BIT STRING`，其**值**不含 unused-bits 字节。若实现返回了首字节，
  binding hash 会与任何真实服务器不一致 —— 而这种不一致在真机 E2E（`doc:4181` E1）会立刻暴露，
  属于「批 5 才能验证」的项。
- **风险提示**：这是一个**只能靠真机验证**的假设。建议批 3 接线时**同时**保存
  `PeerSubjectPublicKeyInfo` 与 `PeerSubjectPublicKey` 各一份到日志/证据，E2E 失败时能立刻定位是
  「字节口径错」还是「其它原因」。这条成本极低，收益极高。

#### 2.5.3 修复方案（≥2 候选）

**方案 A（doc:1806 的第一个选项）：`Start()` 入口检查** → **否决**（§2.5.4 给出机制）。

**方案 B（推荐，甲 D3）：`BuildStep3` 入口检查 + 生产 setter**

```cpp
// credssp.h（放在 SetServerPublicKeyForTest 之前）
void SetServerPublicKey(Bytes spk) { server_public_key_ = std::move(spk); }   // 需 #include <utility>

// credssp.cpp BuildStep3 开头（:117 之前）
if (server_public_key_.empty()) {
    return Fail(Status::kUnsupported, "server public key not set");
}
```

- 会不会破现有 15 条：**不会**（所有走到 `BuildStep3` 的用例都设了公钥：
  `[READ:tests/test_credssp_sm.cpp:149,185,220,286,323,416,444,482]`）。
- 语义：公钥在第 3 步首次被消费（`:232` / `:234`），fail-closed 于首次使用点。

**方案 C（语义最严格，可选）**：让 `SetServerPublicKey` 拒绝空输入（`if (spk.empty()) return;` 或
返回 `Error`），并在 `Start` 时若已 `SetServerPublicKey` 过空值则立刻失败。
不建议：会把「未设置」与「设为空」两条路径分开，增加状态，收益不抵成本。

#### 2.5.4 为什么不能放 `Start()` —— 我补上机制（甲只给了现象）

甲的现象：放 `Start` → `step1_emits_version_and_negotiate_token_only` 先 FAIL 4 条，然后
`exit 0xC0000409`，后 14 条未运行。

**机制（我读测试源码定位）**：那条测试在 `[READ:tests/test_credssp_sm.cpp:110]` 之后直接：

```
[READ:tests/test_credssp_sm.cpp:112-120]
    TsRequest req;
    CHECK(req.Decode(out.data(), out.size()).ok());
    ...
    CHECK(req.nego_token.size() == 40);
    CHECK(Hex(Bytes(req.nego_token.begin(), req.nego_token.begin() + 8)) == "4e544c4d53535000");
    CHECK(req.nego_token[8] == 0x01);
```

若 `Start` 提前失败，`out` 为空 → `req.nego_token` 为空 → `nego_token.begin() + 8`
是对空 vector 的越界迭代器运算，`req.nego_token[8]` 越界下标。Debug（`_ITERATOR_DEBUG_LEVEL=2`）
直接断言/`__fastfail` → 进程死，后续用例不跑。**所以「崩」不是实现的问题，是测试对空 token 没有防御**；
而 H7 禁止改测试 → **结论：守卫只能放 `BuildStep3`。我同意 D3。**

**同时确认「3 条不设公钥」的名单（我逐条核对）**：
`Start()` 调用点共 11 处（`[READ:tests/test_credssp_sm.cpp:110,152,188,223,289,326,359,381,419,447,485]`），
其中**没有** `SetServerPublicKeyForTest` 的只有 3 条：
- `:110` `step1_emits_version_and_negotiate_token_only`（`:107` 只有 nonce）
- `:359` `error_code_aborts_with_server_status`（`:356` 只有 nonce）
- `:381` `error_code_is_checked_before_any_token_processing`（`:379` 只有 nonce）

**与甲完全一致（3 条，行号相同）。**

#### 2.5.5 测试方案 `start_without_public_key_fails`

- **给定**：`CredsspClient(TestCreds(), 6)` + `SetNonceForTest(FixedNonce())`，**不调任何公钥 setter**。
- **当/则**：分两段（这样对守卫位置不敏感，且能在 `Start` 放守卫时也成立）：
  1. `e = Start(out)`；若 `!e.ok()` → 断言 `status==kUnsupported`、`out.empty()`，返回；
  2. 否则喂合法 CHALLENGE → 断言 `!ok()`、`status==kUnsupported`、`step3.empty()`、`!complete()`。
- **为什么能抓**：修复前第 2 段会「成功」并产出 48 字节 `pubKeyAuth`（P4 实测）→ 4 条断言全红。
- 甲的参考实现正是这个两段式（`[READ:evidence/exec/batch1-a-new-tests-reference.cpp:680-706]`），
  **设计正确，我认可**。

#### 2.5.6 红证可行性

删掉 `server_public_key_.empty()` 检查 → `[ FAIL ] start_without_public_key_fails`，
`FAIL ... !e.ok()` / `e.status == Status::kUnsupported` / `step3.empty()`（甲实测 3 failed checks）。

---

## 3. 阶段 1：我发现的、甲与文档都漏掉的 4 件事

### 3.1 N-B1（P0，最重要）：`exported_session_key_` 是 `clientNonce` 的子串 → 凭据可被 TLS 对端直接解出

**这不是 S1 的子问题，S1 修完它仍然存在。**

代码事实：

- `[READ:credssp.cpp:191]` `exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);`
  → ExportedSessionKey = `nonce_[8..24)`
- `[READ:credssp.cpp:244]` `if (version_ >= kFirstHashVersion) req.client_nonce = nonce_;`
  → **整个 32 字节 nonce 被写进 TSRequest 的 clientNonce 字段，明文（TLS 内）发给服务器**

我的实测（P6）：`nonce hex = 0000...0000`、`exported hex = 0000000000000000` —— 一致；
A3 更直接：

```
=== A3  S1: exported key before/after step 3 ===
  after  step3: exported=08090a0b0c0d0e0f1011121314151617
  nonce[8..24)  =08090a0b0c0d0e0f1011121314151617
```

**为什么是 P0**：
1. `[MS-NLMP]` 要求 `ExportedSessionKey = NONCE(16)`（**新鲜随机 16 字节**），并只以
   `EncryptedRandomSessionKey = RC4K(KeyExchangeKey, ExportedSessionKey)` 的形式发出
   （`[READ:docs/spec/security-layer.md:1180-1181]`）。取 `nonce[8..24)` 等于**取消了密钥交换**：
   这把「只有知道口令的人才能算出的会话密钥」变成了「服务器已经拿到明文的会话密钥」。
2. CredSSP 的威胁模型恰恰是**不可信 TLS 通道**（本目标用 `kInsecure` 自签证书，
   `[READ:docs/spec/security-integration.audit-a.md:1796]` 的 S8 段落已注明）。TLS 对端（MITM）
   能看到第 3 步明文里的 `clientNonce` → 直接得到 `exported_session_key_`
   → 派生 `signing_key_` / `sealing_key_`（`[READ:credssp.cpp:196-197]`）
   → **能解出第 5 步 `authInfo` 里的明文口令**（`[READ:credssp.cpp:287-296]`），
   → 还能伪造第 4 步回显（`[READ:credssp.cpp:364-391]` 的算法对攻击者完全可复现）。
   即：**无需知道口令即可拿到口令**。CredSSP 的全部价值（`[READ:docs/spec/security-layer.md:529]`
   「pubKeyAuth 只证明 TLS 公钥前的一致 + 双方知道 NTLM 会话密钥」）被抹平。
3. **S1 的修复不消除它**：nonce 变随机后，它**仍然**被明文发送，仍然等于 exported key。
   所以「S1 修完 = 安全」是错的。

**修复建议（成本很低，且不破任何现有测试）**：

```cpp
// BuildStep3，KEY_EXCH 分支
if ((msg.flags & ntlm_flag::kKeyExch) != 0) {
    exported_session_key_.assign(16, 0);
    if (!crypto::RandomBytes(exported_session_key_, 16)) { ... Fail(Status::kMalformed, ...) }
} else {
    exported_session_key_ = session_base_key_;
}
// 并且 client_challenge 也用独立随机 8 字节，而不是 nonce[0..8)
```

**为什么不破测试（我逐条核对）**：没有任何测试断言 `exported == nonce[8..24)`；
`[READ:tests/test_credssp_sm.cpp:205]` 用 `ExportedSessionKeyForTest()` 只为重算 MIC；
`DecryptPubKeyAuthForTest`（`[READ:credssp.cpp:393-401]`）与 `MakeServerEchoForTest`
都用 `exported_session_key_` 自身派生，**自洽**；`binding_hash_matches_independent_value`
（`[READ:tests/test_credssp_sm.cpp:245-258]`）只用 `nonce` 与固定 `spk`，与 exported 无关。
→ **15 条应全绿**（这条判断标 `[未验证]`：需在影子树跑一次确认）。

**必须新增的 red/green 测试（建议名 `client_nonce_does_not_disclose_session_key`）**：
- 给定：走到第 3 步（nonce 随机，不调 `SetNonceForTest`）。
- 则：`CHECK(c.ExportedSessionKeyForTest().size() == 16)`、
  `CHECK(Hex(exported) != Hex(Bytes(nonce.begin()+8, nonce.begin()+24)))`
  （或更直接：断言 exported 的 16 字节**不是** `req.client_nonce` 的任一 16 字节窗口子串）。
- 今天：**红**（两者恒相等）。只修 S1（随机化 nonce）：**仍红**。两者都修：绿。

**处置建议**：这条超出 doc 的 S1–S20 清单，属于**新发现的 P0**。请主代理裁决：
(a) 并入批 1（与 S1 同一函数、同一 RNG 依赖，边际成本 6 行 + 1 测试）；
(b) 或单独立项并在本批显式标注「已知未修，禁止宣称 CredSSP 安全」。
**我建议 (a)** —— 因为不修它，S1 的红证会给人「nonce 已随机 → 机密性已恢复」的错觉。

### 3.2 N-B2（P1 可用性）：RNG 失败会被降级成「nonce 长度错」，丢掉 `native_code`

doc:4003-4004 要求「调用点必须检查返回值……`GetLastError`/`errno` 进 `native_code`」。
甲的方案（`[READ:docs/spec/batch1-audit-a.md:586]`）是
`if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();`，守卫消息是
「nonce must be 32 bytes」——**同一句话既表示「RNG 坏了」又表示「调用方传错长度」**，
现场无法区分，且 `native_code` 恒 0。
建议见 §2.1.3 方案 C（`nonce_ready_` / `nonce_error_` 两个成员 + `kMalformed`，见 §9.9）。

### 3.3 N-B3（会误导执行 AI）：doc:1789 的红证测试式样在修复后仍然红

见 §2.1.2。**执行 AI 必须以甲 §4.1 的「驱动到第 3 步」式样为准，不得照抄 doc:1789。**

### 3.4 N-B4（会误导执行 AI）：主代理的 `batch1_preflight.py` 在修复后会误报 BAD

我实测了 preflight 用的 5 条正则对「定案后的代码形态」的匹配情况
（`[BASH:python .tmp\audit-b1\regex_check.py]`）：

```
S6  std::clamp form              MATCH
S6  plain assign form            MATCH
S5b lower-bound compare          MATCH
S5b clamp-only (no compare)      MISS
S18 src empty-key guard          MISS
S18 header production setter     MATCH
S1  RandomBytes form             MISS
```

`[BASH:python -c "re.search(...)"]` 对定案代码 `version_ = std::min(version_, req.version);`：

```
'S6': MISS
```

**结论（三条，执行 AI 必须知道）**：
1. preflight 的 S6 正则 `version_\s*=\s*(?:std::clamp|req\.version)` **不匹配 `std::min` 形态**
   → 修复后 S6 行仍是 `ABSENT` → 脚本会打印 `BAD`，但**代码是对的**。不要据此回退。
2. preflight 的 S18 正则只扫 `src/credssp/credssp.cpp`，而生产 setter 在**头文件**、
   空公钥守卫是 `if (server_public_key_.empty())`（**没有 `=`**）→ 修复后仍是 `ABSENT`。
3. S1 行在修复后必然从 `PRESENT` 变 `ABSENT`，而脚本 `present('S1', ..., True)` 期望 `PRESENT`
   → 必然报 `BAD`（这是 pre-flight 的固有语义，不是错误，但**不要当成回归**）。

→ **建议主代理把 preflight 的 S6 正则改为 `version_\s*=\s*std::min`，S18 改为扫头文件 +
匹配 `.empty()`，并在跑批 1 绿证时把 Q4 换成「S5b 必须 PRESENT / S6 必须 PRESENT / S18 必须 PRESENT（扫 hdr）」。
否则执行 AI 很可能为了「让 preflight 变绿」而把正确的 `min` 改成 `clamp`。**

---

## 4. 阶段 2：互审与定案（对甲的 D1–D6 逐条独立判定）

> 规则：不因「主代理已裁决」跳过验证。以下每条都给**我自己的证据**与**同意/反对**。

### 4.1 D1（S6：`min` vs `clamp`）—— **同意结论，反对落点**

- **结论判定：`min` 对。** 独立证据见 §2.3.2(c)：用**未修改**的库实测 (client 4, server 6)
  → 今天就是 `version=4 / nonce=0 / pka=24`；`min` 保持它不变，`clamp` 会改成 `6/32/48`。
  再叠加协议理由（`security-layer.md:236`：服务器只报自己最高版本，不做协商）——
  协商结果只能是 `min`。
- **落点判定：反对甲的「每次响应都回写」。** 见 §2.3.3：第 4 步若回低版本，`min` 会把
  `version_` 从 6 改成 4，第 5 步编码与第 3 步不一致，且现有测试全用 v6 第 4 步，**覆盖不到**。
  建议回写收窄到 `step_ == kAwaitChallenge`，并补 `server_echo_version_does_not_downgrade`。
- **是否与甲一致**：结论一致，落点不一致（这是要磋商的点，见 §5）。

### 4.2 D2（S5：只拒下界）—— **同意**

- 独立证据：`[READ:docs/spec/security-layer.md:606]` 引 `[MS-CSSP]` 原文
  「If the version received is greater than the implementation understands, **treat the peer as
  one that is compatible with the version … that the implementation understands**」。
  这是规范级依据，比「服务器实测回 6」更强。
- 补充代价（甲也承认，我确认）：现有测试名 `step1_rejects_server_version_above_our_max`
  名不副实；按 H7 不改，新增 `version_above_max_is_capped_not_rejected` 锁语义。
  另外提醒：**`BuildStep3` 的「非法 token」路径会失去唯一测试**（§2.2.3 末）。

### 4.3 D3（S18：`BuildStep3` 而非 `Start`）—— **同意，并补机制**

- 独立核对名单：11 个 `Start()` 调用点里，只有 `t:110` / `t:359` / `t:381` 没设公钥
  （§2.5.4 逐条列了行号）。**与甲完全一致。**
- 独立补机制：崩溃不是「实现的问题」，是那条测试在 `t:112-120` 对**空 `nego_token`** 做
  `begin()+8` 与 `[8]` → Debug 迭代器断言 / `__fastfail`（§2.5.4）。
  所以「放 Start」违反的不只是 15 条全绿，还有**进程存活**（后续 14 条不跑）。
- 语义补充：公钥在第 3 步首次被消费（`:232/:234`），`BuildStep3` 是「首次使用点」——
  fail-closed 且不误伤。

### 4.4 D4（S11：`DeriveSigningKey(..., true)`）—— **同意（你让我主攻的点，已独立确认）**

- 独立证据：§2.4.2 的 A2 —— 我用 `MakeServerEchoForTest()` 的**真实 wire** 反推，
  只有 `true` 方向能复现 `checksum = 57 17 9c 5a 8e 46 99 ca`；`signing_key_`（`false`）得到
  `e0 9d bc 8b f7 7c c1 e8`。
- 代码依据：`[READ:credssp.cpp:196]`（client→server）vs `[READ:credssp.cpp:384]`
  （`MakeServerEchoForTest` 用 `true`）。
- **我的 MAC 实现会用哪个密钥**：`DeriveSigningKey(exported_session_key_, true)`。
  **我没有踩到方向错误**，因为我是先读 `MakeServerEchoForTest` 的 `Seal(...)` 调用再定方向的；
  这也说明**这条必须写进注释**（甲已写，`[READ:evidence/exec/batch1-a-fixed-credssp-reference.cpp:419-421]`）。

### 4.5 D5（S1：提前尺寸守卫）—— **同意，补两点**

- 代码级证据（无需运行）：`[READ:credssp.cpp:176]` 需 `size>=8`、`[READ:credssp.cpp:191]`
  需 `size>=24`，而 `[READ:credssp.cpp:229]` 的检查在两者之后且嵌在 `version_>=5` 分支
  → 短 nonce 必越界。Debug 下是 `_ITERATOR_DEBUG_LEVEL=2` 断言（§2.1.4）。
- 补 1：守卫必须在 `BuildStep3` **最开头**，且**早于** `:176`；甲的位置（`:117` 之前）正确。
- 补 2：错误语义要区分 RNG 失败（§3.2 / §2.1.3 方案 C），否则「RNG 坏」被报成「nonce 长度错」。
- **注意**：`nonce` 长度 24..31 时，今天在 `:229` 报 `kUnsupported`；加提前守卫后仍在守卫报
  `kUnsupported` —— **状态码不变**，只是位置提前。甲说的「行为等价」成立。

### 4.6 D6（版本检查在 errorCode 之后）—— **同意**

- 独立证据：我用**未修改**的库实测（P10）：

```
=== P10 S5-ordering: errorCode with version=1 (which error wins?) ===
  status=kMalformed native_code=0xC000006D msg='server reported an error'
```

  即**今天已经是 errorCode 优先**（`[READ:credssp.cpp:97-105]` 在 `:107` 分派之前）。
  若把版本检查插到 `:95` 之前（doc:1793 的写法），这个用例会变成
  `kUnsupported / native_code=0` → **回归**。
  → **D6 正确，且必须把版本检查放在 `:105` 之后。**
- 注意甲的测试 `error_code_wins_over_bad_version`（`[READ:evidence/exec/batch1-a-new-tests-reference.cpp:709-731]`）
  只断言 `native_code` 与 `!ok()`，**没有断言 `status==kMalformed`** —— 这样更稳（不锁死错误分类），
  我认可。

### 4.7 我回答甲的问题清单

| 甲的问题 | 我的回答 |
|---|---|
| 1. D1/D3 能否独立复现红？环境差异？ | **能，且用了不同方法**：D1 我用**未修改库**的 (4,6) 实测值当「`min` 的期望值」，不需要影子树；D3 我从测试源码定位崩溃机制（空 `nego_token` 的 `begin()+8`/`[8]`）。环境：`build/verify` 是 **Debug**（`/Ob0 /Od /RTC1`），所以断言会崩；Release 下会静默越界——更危险。 |
| 2. D2 拒双边还是 cap？ | **cap（只拒下界）**。理由升级为规范原文 `security-layer.md:606`（`[MS-CSSP]` 5.1），不只是实测。 |
| 3. S11 用哪个签名密钥？踩坑了吗？ | `DeriveSigningKey(exported_session_key_, true)`。**没踩坑**：我先读 `MakeServerEchoForTest`（`c:384`）的 `Seal(...)` 调用再定方向；并用 wire 字节反推验证（§2.4.2）。 |
| 4. S1 怎么防「固定非零常量」假绿？ | 与你同构的**双断言**（≠全零 + 两两不同），**并额外**要求把 N6 的 `Select-String` 门禁写进 verify 脚本（你只写了注释，没进门禁）。 |
| 5. 测过 (客户端 4 + 服务器 6) 吗？ | 测了，**而且不用影子树**：今天该组合就是 `v4/0/24`（P 系列 A4），所以 `min` = 行为不变、`clamp` = 行为改变。这是区分两者的最干净证据。 |
| 6. 我漏掉的缺陷？ | **有，一个 P0**：`exported_session_key_ = nonce[8..24)` 而 `clientNonce = nonce_` 明文发出 → TLS 对端可直接解出会话密钥 → 解出第 5 步口令（§3.1 N-B1）。**S1 修完它仍在。** 另：`recv_seq_` 的「重放」观测用例我可以给（§2.4.4 第 2 点：`MakeServerEchoForTest()` 两次、seq 都是 0，第一条接受后第二条必须被拒）。 |

---

## 5. 定案建议（给主代理与执行 AI 的可执行清单）

### 5.1 与甲需要磋商的 1 点

**S6 回写位置**：甲放「每次响应」，我主张「只在第 2 步」。
我的理由可执行验证：`server_echo_version_does_not_downgrade`（客户端 6 → 第 2 步 6 → 第 4 步 4
→ 断言第 5 步 `req.version == 6`）。甲的落点在这条上会红，我的不会。
**若不采纳我的落点，至少必须知道这是一个未被测试覆盖的新分支**（不是「一定错」，是「未经检验」）。

### 5.2 批 1 执行清单（合并甲乙 + 我的修正）

> **本节已被 §9.5 取代**（§9.5 含主代理裁决后的 R1/R2 落点）。保留本节仅为溯源。

| # | 位置 | 改动 | 依据 |
|---|---|---|---|
| 1 | 新增 `include/rtsc/crypto/random.h` + `src/crypto/random.cpp` | `bool RandomBytes(Bytes&, size_t)`；Win `BCryptGenRandom`，POSIX `getrandom`（`EINTR` 重试）；**失败返回 false 且输出清空** | doc:3960-4004；`[READ:CMakeLists.txt:39]` 需加源文件；`[READ:CMakeLists.txt:132]` 依赖方向已成立 |
| 2 | `CMakeLists.txt:39` | `add_library(rtsc_crypto STATIC src/crypto/hash.cpp src/crypto/random.cpp)` + `if(WIN32) target_link_libraries(rtsc_crypto PUBLIC bcrypt) endif()` | 甲 §6.1；**禁止 `#pragma comment(lib)`**（N9/doc:3979） |
| 3 | `credssp.cpp:44-46` | 构造期 `RandomBytes(nonce_, kNonceSize)`；失败记 `nonce_ready_=false` + `nonce_error_` | S1 + N-B2 |
| 4 | `credssp.cpp:191` | **`exported_session_key_` 改为独立 16 字节随机**（不再取 `nonce[8..24)`） | **N-B1（新增 P0）** |
| 5 | `credssp.cpp:176` | （建议）`client_challenge` 改为独立 8 字节随机 | N-B1 同源；可选 |
| 6 | `credssp.cpp:105` 之后（errorCode 之后、分派之前） | `if (req.version < kMinVersion) return Fail(kUnsupported, "unsupported TSRequest version");` | S5/D2/D6 |
| 7 | 同上，但**收窄到 `step_ == kAwaitChallenge`** | `version_ = std::min(version_, req.version);` | S6/D1 + 我的落点修正 |
| 8 | `BuildStep3` 最开头（`:117` 之前） | nonce 长度守卫（+ RNG 失败分支）→ 空公钥守卫 | S1/D5 + S18/D3 |
| 9 | `credssp.h:60-61` | 新增 `void SetServerPublicKey(Bytes spk)`；`#include <utility>` | S18 |
| 10 | `credssp.cpp:357-360`（`OpenReceive`） | 解密文 → 同流解 checksum → 校验 `Version==1`、`SeqNum==recv_seq_` → 用 `DeriveSigningKey(exported, true)` 重算比对；**三处失败都先 `plaintext.clear()`**；成功才 `++recv_seq_` | S11/D4 + 我的 §2.4.4 |
| 11 | verify 脚本 | 加 N6 门禁：`Select-String credssp.cpp/random.cpp -Pattern '\brand\(|\bsrand\(|std::random_device|mt19937'` 必须无输出 | doc:4010-4012；**甲缺** |

### 5.3 必跑测试（影响范围，禁止全量）

| 套件 | 为什么 | 基线（我实测） |
|---|---|---|
| `rtsc_credssp_sm_tests` | 主改动面；15 条 + 新增 5 条（+ 建议 2 条） | `15 tests, 92 checks` |
| `rtsc_ntlm_tests` | `Seal`/`HmacMd5` 被 `OpenReceive` 新逻辑复用；`ntlm.cpp` 未改但属上游契约 | `27 tests, 136 checks` |
| `rtsc_credssp_tests` | `TsRequest` 编解码被 S5/S6 的 `version` 路径影响 | `23 tests, 69 checks` |
| `rtsc_crypto_tests` | **新增 `random.cpp`** 进 `rtsc_crypto`（`[READ:CMakeLists.txt:110-112]`） | 需实测（我未跑） |
| **C0 硬门** | 每次改码后 `cmd /c F:\rtsc\.tmp\build_tls.bat` 零警告零错误（`/W4 /WX`） | — |

### 5.4 新增测试总表（doc:3794-3798 的 5 个名字 + 我建议的补充）

| 名字 | 归属 | 抓什么 | 今天 |
|---|---|---|---|
| `two_constructions_have_different_nonces` | doc 指定 | 常量 nonce | 红（7 failed checks） |
| `version_below_min_is_rejected_with_valid_challenge` | doc 指定 | 版本下界（合法 token） | 红（P1 实测通过） |
| `server_version_is_echoed_back` | doc 指定 | 不回写 + `clamp` 升级（A/B 两向） | 红（P3 实测 v6/32/48） |
| `tampered_signature_checksum_is_rejected` | doc 指定 | MAC 缺失（密文不动） | 红（P7 实测 ok=1） |
| `start_without_public_key_fails` | doc 指定 | 空公钥 fail-open | 红（P4 实测 48B） |
| `error_code_wins_over_bad_version` | 甲建议 | D6 顺序 | 绿（P10 实测，锁不变量） |
| `version_above_max_is_capped_not_rejected` | 甲建议 | D2 只拒下界 | 绿（锁不变量） |
| **`client_nonce_does_not_disclose_session_key`** | **我建议（N-B1）** | exported 不能是 clientNonce 子串 | **红**（A3 实测相等） |
| **`server_echo_version_does_not_downgrade`** | **我建议（D1 落点）** | 协商只发生一次 | 绿（锁不变量） |
| **`replayed_echo_with_stale_seq_is_rejected`** | **我建议（S11 seq）** | `recv_seq_` 只 ++ 不校验 | **红**（P8 实测 ok=1） |
| **`short_nonce_is_rejected_not_crashed`** | 甲建议 | 短 nonce 崩溃 | 红（甲实测 0xC0000409） |

---

## 6. 未验证项（N15，禁止当成已验证）

| # | 项 | 状态 | 验证方法 |
|---|---|---|---|
| 1 | `PeerSubjectPublicKey()` 返回的字节口径（是否去掉 unused-bits 首字节） | **依赖甲实测**；我只读了 `tls_schannel.cpp:371-384` | 真机/回环打印 `pubkey[0]` 应为 `0x30`；或用 `openssl asn1parse` 对比 |
| 2 | `BCryptGenRandom` 失败路径 | **未验证**（只读了 doc:4003） | 断点/打桩让 `BCryptGenRandom` 返回非 0，断言 `kInternal` + message 含 `CSPRNG` + `native_code != 0`，且**进程不崩** |
| 3 | 新增 `random.cpp` 后 `rtsc_crypto_tests` 是否仍绿 | **未验证**（我未编译） | `cmd /c F:\rtsc\.tmp\build_tls.bat` + 跑该套件 |
| 4 | N-B1 修复后 15 条是否全绿 | **未验证**（我不能再启动 exe） | 影子树跑 `rtsc_credssp_sm_tests` |
| 5 | 真机 v2/3/4 路径（服务器回 <5） | **未验证**（本目标强制回 6，`security-layer.md:1712` 同结论） | 对 Win2008/2012 实测 |
| 6 | 真机 version=7 行为 | **未验证** | 抓包看服务器是否接受被 cap 后的 v6 |
| 7 | 批 3 端到端（TLS → CredSSP → EUAR → MCS） | **未验证**（无凭据，doc:4181 E1） | 真实凭据 + `rtsc_probe --full` |
| 8 | RSA-2048 的 SPKI/SPK 字节数（294/140） | **依赖甲实测** | 回环打印长度 |

---

## 7. 我不同意/需要主代理注意的清单（一句话版）

> **状态更新（§9 定案后）**：第 1、2、3、4、5、6 条均已获主代理裁决或已修（R1–R5）。
> 保留下方原文作为提出时的记录；**执行以 §9 为准**。

1. **S6 回写位置**：甲放「每次响应」，我主张「只在第 2 步」（否则第 4 步可回退版本，产生第 3/5 步不一致，且无测试覆盖）。→ **主代理采纳（R2）**
2. **N-B1（新 P0）**：`exported_session_key_ = nonce[8..24)` 且 `clientNonce = nonce_` 明文发出 → TLS 对端可解出会话密钥 → 解出口令。**S1 修完仍存在，必须单独决策。**
3. **doc:1789 的 S1 红证式样是坏的**（fresh client 的 exported 是空 vector，测试永远红）——执行 AI 必须用甲 §4.1 的驱动式样。
4. **主代理的 `batch1_preflight.py` 在修复后会误报 BAD**（S6 正则不认 `std::min`；S18 只扫 src 不扫 hdr）——不改正则的话，执行 AI 可能为了「变绿」把正确的 `min` 改回 `clamp`。
5. **N6 的 `Select-String` 门禁必须写进 verify 脚本**（甲只写了注释）。
6. **S11 的 `recv_seq_` 校验需要一条能观测它的用例**（`MakeServerEchoForTest()` 两次、seq 都是 0）——甲说找不到，我给了。

---

## 8. 阶段 2 补充：对甲「第二轮自更正」的复核 + §8 定案逐条核对

> 触发：甲第二轮消息（自更正 A/B + 请求 D1/D3 复验 + 询问「§8 有无异议」）。
> 本轮**未启动任何 exe、未编译**（遵守紧急规则）。以下判定全部来自
> ①我在规则生效前取得的实测读数；②对源码/测试源码的静态推导；③对甲证据文件的阅读。
> 凡依赖甲的实测处均显式标注 `[读甲证据]`。

### 8.1 D1 独立复验 —— **判定：`min` 对，`clamp` 错。同意 §8.2 的结论**

甲要求的复验方向（客户端 4 + 服务器 6）**我在规则生效前已实测**（§2.3.2(c)，探针 `probe_b1b.exe` A4 段）：

```
=== A4  S6: client announced 4, server replies 6 (doc's clamp upgrades us) ===
  client.version() after ctor = 4
  step1 announces version=4
  step3 now: ok=1 status=0 version=4 nonce=0 pubkeyauth=24
```

**判定链（三段，互相独立）**：

1. **实测**：当前（未修）库在 (4,6) 上就产出 `version=4 / nonce=0 / pka=24`。
   → `min(4,6)=4` 与今天**逐字节一致**（修复零行为变化）；`clamp(6,2,6)=6` 会改成
   `version=6 / nonce=32 / pka=48`（与第 1 步已声明的 v4 矛盾）。
2. **协议**：`[READ:docs/spec/security-layer.md:236]` 实测「客户端发 1..8，服务器始终回 6，
   不做取最小值协商」→ 协商结果只能由客户端自己算 `min`。
3. **规范**：`[READ:docs/spec/security-layer.md:606]` 引 `[MS-CSSP]`「higher than we understand →
   treat as the version we understand」→ 只能降不能升。

**结论：`std::min(version_, req.version)` 正确。与甲 §8.2 一致，无异议。**
（甲的 4 条红断言 `req.version==4 / client_nonce.empty() / pka==16+spk / version()==4`
与我的 A4 读数完全对应：我测到的正是 `4 / 0 / 24`。）

**但落点我仍有异议**（§8.3）。这不是 D1 的结论分歧，是「回写放在哪一行」的分歧。

### 8.2 D3 独立复验 —— **判定：guard 必须放 `BuildStep3`。同意 §8.4**

我**没有**再跑「把 guard 放进 Start」的变异（禁止启动 exe），而是用**代码级推导 + 读甲证据**
确认，理由如下（这条不需要跑也能定论）：

1. **名单核对（我逐行数，不采信转述）**：`Start()` 调用点共 11 处
   （`[READ:tests/test_credssp_sm.cpp:110,152,188,223,289,326,359,381,419,447,485]`）；
   其中未调 `SetServerPublicKeyForTest` 的恰好 3 条：`:110`、`:359`、`:381`。
   **与甲 §8.4 的表格完全一致（行号逐个相同）。**
2. **崩溃机制（我读测试源码定位，甲只给了现象）**：`[READ:tests/test_credssp_sm.cpp:112-120]`
   在 `Start` 之后无条件做
   `req.nego_token.begin() + 8`、`req.nego_token[8]`。若 `Start` 提前失败 → `out` 为空 →
   `req.Decode` 失败（`req` 保持默认空）→ `nego_token` 为空 vector →
   `begin()+8` 是「cannot seek value-initialized vector iterator」。
   **甲的崩溃日志原文正是这句**（`[读甲证据:evidence/exec/batch1-a-audit-guard-in-start.txt]`）：
   `Assertion failed: cannot seek value-initialized vector iterator`。
   → 现象与机制**互相印证**，且机制解释了「为什么不是 4 条 FAIL 而直接崩」（第 5 条断言越界）。
3. **H7 约束**：不能改这 3 条测试 → 只能把 guard 后移到 `BuildStep3`。

**结论：`BuildStep3` 入口正确。与甲 §8.4 一致，无异议。**

### 8.3 我对 §8 定案的**唯一实质异议**：§8.8 把 `version_ = std::min(...)` 放在「每次响应」

`[READ:docs/spec/batch1-audit-a.md:814]` 的锚点写的是：

> **S5+S6** 版本 | `:105` 与 `:107` 之间 | 在此行**之前**插入 D2 下界检查 + D1 `std::min` 回写

`[READ:docs/spec/batch1-audit-a.md:821]` 明确「不可调换」，但**没有**限定只对第 2 步生效。
甲的参考实现 `[READ:evidence/exec/batch1-a-fixed-credssp-reference.cpp:119-135]` 也是这个形态：
下界检查 + `min` 回写在 `if (step_ == Step::kAwaitChallenge)` **之前**，对第 4 步同样执行。

**问题（可静态判定，无需运行）**：

- 第 4 步走 `BuildStep5`，但 `version_` 已被第 4 步的 `req.version` 重新 `min` 过一次。
- 若服务器第 2 步回 6、第 4 步回 4（协议上不应发生，但**没有任何校验阻止它**）：
  `version_` 从 6 变 4 → 第 5 步 `req.version = version_`（`[READ:evidence/exec/batch1-a-fixed-credssp-reference.cpp:338]`）
  发 4，而第 3 步已按 6 发过哈希+nonce。
- 更实际的危害：**`version_` 是 `version()` 的返回值**（`[READ:include/rtsc/credssp/credssp.h:54]`），上层用它做错误分类/日志。
  第 4 步被降版后，上层看到的是「协商结果 4」，与第 3 步实际使用的 6 不符。
- **无测试覆盖**：现有第 4 步用例全部发 `version=6`
  （`[READ:tests/test_credssp_sm.cpp:300,336,430,457]`），所以 `min(6,6)=6` 掩盖了这个分支。

**建议（不改变 D1 结论，只改落点）**：

```cpp
// errorCode 分支之后（D6 保持）
if (req.version < kMinVersion) {
    return Fail(Status::kUnsupported, "unsupported TSRequest version");
}
if (step_ == Step::kAwaitChallenge) {
    version_ = std::min(version_, req.version);   // 协商只发生一次，在第 2 步
    return BuildStep3(req, out);
}
if (step_ == Step::kAwaitServerEcho) {
    return BuildStep5(req, out);
}
```

配套测试 `server_echo_version_does_not_downgrade`：客户端 6 → 第 2 步 6 → 第 4 步 4
→ 断言第 5 步 `req.version == 6`（甲当前落点会得 4 → 红；收窄后绿）。

**严重度定级：P2（不是 P0/P1）**——不影响 5 条缺陷的修复正确性，只影响「协商不变量」的严谨性与
`version()` 的可信度。**不阻塞批 1**，但建议在 §8.8 的锚点里加一句「回写只在 `kAwaitChallenge` 分支内」，
成本 1 行，收益是消除一个未测试分支。

### 8.4 对甲「自更正 A」的复核 —— **成立，且我要加一句更严重的话**

甲说：21/164 绿证**不含** D5 守卫（守卫只在原 `c:229`，在切片之后），所以那个绿证不能证明
「D5 不破用例」。

**我核对了甲的参考实现，确认成立**：`[READ:evidence/exec/batch1-a-fixed-credssp-reference.cpp:145-154]`
**确实有**提前守卫（S18 公钥 + D5 nonce 尺寸），但甲说的是「跑绿的那一版」不含它——
这两者不矛盾：参考实现是**事后**补的，绿证是**事前**跑的。甲的自我标注是诚实的。

**我要加的更严重一句**：不仅「不能证明不破用例」，而且**若不修 D5 而只修 S1，反而会引入新的崩溃路径**——
`nonce_.clear()` 后 size=0，而 `[READ:credssp.cpp:176]` 的 `nonce_.begin() + 8` 在 Debug 下
必断言（§2.1.4）。即 **S1 与 D5 是硬绑定，不能拆开执行**。建议在 §8.6 加一句
「S1 的 RandomBytes 与 D5 的守卫必须在同一次提交内落地，中间态会让 RNG 失败从『全零 nonce』
变成『进程崩溃』」。

### 8.5 对甲「自更正 B」的复核 —— **成立，且我的证据更强**

甲说参考实现原来还是「拒双边」，已改成只拒下界，并用 `probe_ver` 验了 8 组。

**我核对参考实现，确认已改**：`[READ:evidence/exec/batch1-a-fixed-credssp-reference.cpp:119-121]`
只有 `if (req.version < kMinVersion)`，无上界比较；`:112-118` 的注释明确写「upper bound is
deliberately NOT rejected」+ 引 `security-layer.md:236` 与 `[MS-CSSP]`。
**与 D2 定案一致。**

**我的证据比「8 组实测」更强的一层**：D2 的正当性不需要实测，直接由规范原文给出
（`[READ:docs/spec/security-layer.md:606]` 的 `[MS-CSSP]` 引文）。实测只能证明「服务器会回高版本」，
规范才能证明「回高版本时应 cap 而非拒绝」。建议 §8.3 的定案理由把规范原文放在第一位、
实测放在第二位（现在 §8.3 引的是 `security-layer.md:236` 的实测，规范引文只在 §3.2 出现过）。

### 8.6 我对 §8.1–§8.6 的逐条签署

| 定案 | 我的判定 | 依据（我的独立证据） |
|---|---|---|
| §8.1 D1 `min` | **同意** | §8.1 三段链；(4,6) 实测 `4/0/24` |
| §8.1 D2 只拒下界 | **同意** | `security-layer.md:606` 规范原文 |
| §8.1 D3 `BuildStep3` | **同意** | 11 个 `Start()` 中 3 条无公钥 + 空 token 越界机制 |
| §8.1 D4 `DeriveSigningKey(...,true)` | **同意** | §2.4.2 的 wire 反推（`57179c5a8e4699ca` vs `e09dbc8bf77cc1e8`） |
| §8.1 D5 提前守卫 | **同意**（补：与 S1 硬绑定） | `c:176`/`c:191` 早于 `c:229`；Debug 迭代器断言 |
| §8.1 D6 errorCode 优先 | **同意** | P10 实测：当前已是 `kMalformed + native_code=0xC000006D` |
| §8.2 细则 | **同意**，但落点见 §8.3 | — |
| §8.3 细则 | **同意结论**，建议补规范引文为第一理由 | — |
| §8.4 细则 | **同意** | — |
| §8.5 细则 | **同意**；补 3 点（失败分支清 plaintext、seq 重放用例、成功才 ++） | §2.4.4 |
| §8.6 细则 | **同意**；补「S1+D5 同批」 | §8.4 |
| §8.8 锚点表 | **一处要改**：`min` 回写收窄到 `kAwaitChallenge` 分支内 | §8.3 |

**签署结论：D1/D3 双方独立复验一致，§8 定案我无原则性异议。**
唯一实质建议是 §8.3 的落点收窄（P2，不阻塞），以及 §5.2 清单里我新增的 N-B1（P0，**必须由主代理裁决**）。

### 8.7 N-B1（新 P0）：主代理已裁决「成立，并入批 1」

甲在第二轮**没有回应**我在阶段 2 报告里提的 N-B1
（`exported_session_key_ = nonce[8..24)` 且 `clientNonce = nonce_` 明文发出 → TLS 对端可解出会话密钥）。
甲的新参考实现**仍然**是：
- `[READ:evidence/exec/batch1-a-fixed-credssp-reference.cpp:229]` `exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);`
- `[READ:evidence/exec/batch1-a-fixed-credssp-reference.cpp:282]` `if (version_ >= kFirstHashVersion) req.client_nonce = nonce_;`

→ **N-B1 在甲的定案实现里原样存在。** 这不是甲的疏漏（它不在 doc 的 S1–S20 清单里），
但**必须在批 1 执行前由主代理裁决**，否则批 1 会「5 条全绿 + 一个 P0 未修」。
详见 §3.1（含修复成本、为什么不破 15 条、以及必加的测试名
`client_nonce_does_not_disclose_session_key`）。

**主代理裁决（2026-10-23）：成立，并入批 1（选项 a）。** 裁决书原文见 §9.1。

### 8.8 关于「证据等级」的一致口径（我同意甲 §11.2，并补一条）

甲 §11.2 声明「定案后完整 reference 未编译未跑测」。我同意这个口径，并补充：
- **可以引用**：5 条缺陷存在性（我用自己的探针独立复现过 5 条中的全部）、5 条变异红证、
  原 15/92 基线（我实跑）、上游 27/136 与 23/69（我实跑）。
- **不可引用**：甲的 21/164 作为「定案实现已通过」的证据（甲自己也这么说）；
  甲的静态检查 17 项（`[读甲证据:evidence/exec/batch1-a-audit-static-check.txt]`，
  它只查括号平衡与文本存在性，**不查语义**，例如它无法发现 N-B1）。
- **新增一条**：**我的 A2/A4/P1–P11 读数来自 `/MDd` 探针，在我收到禁用规则后未再复跑**。
  如需作为正式红证入库，请主代理按 `build_probe_safe.bat` + `run_probe.ps1` 重跑一次
  （源码 `F:\rtsc\.tmp\audit-b1\probe_b1.cpp`、`probe_b1b.cpp`，输出样例在
  `F:\rtsc\.tmp\audit-b1\probe_b1b.out.txt`）。

---

## 9. 定案（主代理裁决已采纳 · 双审签署稿）

> 裁决来源：主代理 `ses_e9de05f37ffeceMUNAaRnKMy8c`，2026-10-23。
> 本节把 §8 的两项待裁决事项落成**可执行定案**，并补上裁决书中给出的规范依据与执行要求。
> 本节覆盖 §5.2 清单中对应两行（第 4 行 N-B1 由「建议」升为「必做」；第 6/7 行的落点收窄）。

### 9.1 裁决摘要

| # | 事项 | 裁决 | 状态 |
|---|---|---|---|
| **R1** | N-B1：`exported_session_key_` 派生自 `nonce`，而 `clientNonce` 明文发出 | **成立，P0，并入批 1（选项 a）** | 采纳 |
| **R2** | §8.3 建议：`min` 回写收窄到 `kAwaitChallenge` 分支内 | **采纳**；并**同时**把 D2 下界检查收窄进同一分支 | 采纳 |
| **R3** | 坑 1：doc:1789 的 S1 红证式样坏（空 vector 恒相等） | **证实，已记入执行任务**（必须用驱动式样） | 已处理 |
| **R4** | 坑 2：`batch1_preflight.py` 修复后误报 BAD | **证实，已修**（三条正则同时覆盖修复前/后形态） | 已修（我复验通过，§9.4） |
| **R5** | 坑 3：N6 的 `Select-String` 门禁未进 verify | **属实**，由主代理补进 `verify.ps1`（不派给执行 AI） | 主代理执行 |

**R1 的规范依据（主代理复核原文，非采信我的结论）**：
- `[READ:docs/spec/security-layer.md:829-831]`：
  `ExportedSessionKey = 若协商了 KEY_EXCH 且(SIGN 或 SEAL): 16 字节随机数；`
  `EncryptedRandomSessionKey = RC4(KeyExchangeKey, ExportedSessionKey)`
  → 规范要求 exported key 是**独立随机值**，不是从别处派生。
- `[READ:docs/spec/security-layer.md:611]`：`clientNonce` = 「**32 字节密码学随机数**」，
  且**仅版本 ≥5 使用**。
- 两者是**两个独立的随机值**；当前实现把后者切一段当前者，属于实现错误。

**R2 的规范/工程依据**：见 §8.3（第 4 步回写会让 `version_` 6→4，第 5 步发 4 而第 3 步已按 6
发哈希+nonce，协议状态不一致；且 `version()` 是上层错误分类依据）。
额外收益（主代理指出）：把 D2 也收窄进 `kAwaitChallenge` 后，**第 4 步不再新增拒绝点**，
消除了「第 4 步行为变更」这一副作用 —— 这是甲 §12.6 交叉 1 提到的问题，收窄后两全。

### 9.2 R1 执行细则（N-B1）

> **前置条件（必须先做，否则编译失败）**：`credssp::Status` 目前只有 4 个值
> （`[READ:include/rtsc/credssp/ts_request.h:21-26]`），**没有 `kInternal`**。
> 执行 AI 必须**先**在 `ts_request.h:21-26` 追加
> `kInternal,        // local environment failure (CSPRNG unavailable, etc.)`，
> 再写下面的 `Fail(Status::kInternal, ...)`。类型匹配的证明与成本核算见 §9.9.3/§9.9.4。

**改动点**（`BuildStep3`，`[READ:src/credssp/credssp.cpp:190-194]`）：

```cpp
// 现状（缺陷）
if ((msg.flags & ntlm_flag::kKeyExch) != 0) {
    exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);
} else {
    exported_session_key_ = session_base_key_;
}

// 定案
if ((msg.flags & ntlm_flag::kKeyExch) != 0) {
    // [MS-NLMP] 3.4.5 / security-layer.md:829-831: a fresh 16-byte random key,
    // independent of clientNonce. Deriving it from the nonce would hand the
    // session key to anyone who can read the (TLS-protected but untrusted)
    // clientNonce field.
    if (!crypto::RandomBytes(exported_session_key_, kExportedKeySize)) {
        return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
    }
} else {
    exported_session_key_ = session_base_key_;
}
```

**不变量（执行 AI 必须保证）**：`nonce_` 与 `exported_session_key_` **无任何推导关系**。
`grep` 验收：`credssp.cpp` 里不得出现 `exported_session_key_.assign(nonce_`（preflight 可加一行）。

**下游自动跟随（无需逐处改，我逐条核过）**：

| 位置 | 依赖 | 影响 |
|---|---|---|
| `[READ:credssp.cpp:196-197]` | `signing_key_` / `sealing_key_` 由 exported 派生 | 自动跟随，语义正确 |
| `[READ:credssp.cpp:208]` | `Rc4Crypt(session_base_key_, exported_session_key_)` | 自动跟随；这正是规范要求的 `EncryptedRandomSessionKey` |
| `[READ:credssp.cpp:215]` | `ComputeMic(exported_session_key_, ...)` | 自动跟随（MIC 用 exported key，规范一致） |
| `[READ:credssp.cpp:312,353]` | recv sealing key 由 exported 派生 | 自动跟随 |
| `[READ:credssp.cpp:384-385,399,410]` | 测试钩子由 exported 派生 | **自洽**，`MakeServerEchoForTest` / `DecryptPubKeyAuthForTest` 仍能复现，故 15 条不受影响 |
| `[READ:credssp.cpp:176]` | `client_challenge = nonce[0..8)` | **不改**：ClientChallenge 不是秘密，nonce 已是 CSPRNG；改成独立 8 字节是可选卫生改进，非必需 |

**是否破现有 15 条：不破（我的判定，标 `[未验证-需影子树确认]`）**。
依据：无任何现有测试断言 `exported == nonce 子串`；所有用到 exported 的测试钩子都是
「从 exported 自身派生」的自洽路径（上表最后两行）。**仍需执行 AI 跑一次确认**。

**红证（修复前必须红）**：`client_nonce_does_not_disclose_session_key`

- **给定**：`CredsspClient(TestCreds(), 6)`，**不调** `SetNonceForTest`（用真实 CSPRNG），
  设合法公钥，`Start` + 喂合法 CHALLENGE 走到第 3 步。
- **当**：取 `req = Decode(step3)`、`k = c.ExportedSessionKeyForTest()`、`n = req.client_nonce`。
- **则**：
  1. `CHECK(n.size() == 32)`；
  2. `CHECK(k.size() == 16)`；
  3. **强断言**：对每个窗口 `o = 0..16`，`CHECK(Hex(k) != Hex(Bytes(n.begin()+o, n.begin()+o+16)))`
     —— 即 exported key **不是** clientNonce 的任一 16 字节窗口。
- **为什么能抓**：修复前 `k == n[8..24)` → 第 `o=8` 个窗口相等 → 必红。
  比「只比 `n[8..24)`」更强：能同时抓住「换个偏移继续派生」的糊弄实现（例如改成 `nonce[0..16)`）。
- **修复后**：`k` 是独立随机 16 字节，命中任一窗口的概率约 `17 * 2^-128`，稳定绿。
- **变异复现**：把 `exported_session_key_` 改回 `assign(nonce_.begin()+8, nonce_.begin()+24)`
  → 该用例必红（1 条 failed check）。

**与 S1 的关系（必须写进执行说明）**：S1 随机化 nonce **不消除** N-B1；
N-B1 修完也不消除 S1（非随机 nonce 仍可预测 client_challenge）。
**两者必须同批**，否则批 1 的完成声明不成立。

### 9.3 R2 执行细则（落点收窄）

**定案形态**（`OnServerResponse`，errorCode 分支之后）：

```cpp
    // errorCode first (D6): a peer that already declared failure has its status
    // reported verbatim, never masked by a version complaint.
    if (req.has_error_code) { ... }            // 原样保留 c:97-105

    if (step_ == Step::kAwaitChallenge) {
        // D2: reject only a peer version BELOW what we can speak. An upper bound
        // is deliberately NOT rejected ([MS-CSSP]: treat such a peer as the
        // highest we understand); D1's min() below absorbs it.
        if (req.version < kMinVersion) {
            return Fail(Status::kUnsupported, "unsupported TSRequest version");
        }
        // D1: the rest of the exchange runs at the negotiated version, which can
        // only go DOWN. Negotiation happens exactly once, at step 2.
        version_ = std::min(version_, req.version);
        return BuildStep3(req, out);
    }
    if (step_ == Step::kAwaitServerEcho) {
        return BuildStep5(req, out);
    }
    return Fail(Status::kMalformed, "unexpected state");
```

**与甲 §8.2/§8.8 的差异（必须让执行 AI 知道）**：甲的锚点是「`:105` 与 `:107` 之间插入」，
本定案改为「插入到 `if (step_ == Step::kAwaitChallenge) {` **之内**」。**以本节为准。**

**行为矩阵（定案后，我逐格推演）**：

| 客户端 | 第 2 步 version | 第 4 步 version | `version_` 终值 | 第 3 步 | 第 5 步 | 说明 |
|---|---|---|---|---|---|---|
| 6 | 3 | 3 | 3 | v3 裸公钥，无 nonce | v3 | 降版正常 |
| 6 | 6 | 6 | 6 | v6 哈希 + nonce | v6 | 正常路径（现有测试） |
| 4 | 6 | 6 | **4** | v4 裸公钥，无 nonce | v4 | D1 关键格：不升级 |
| 6 | 7 | 7 | 6 | v6 | v6 | D2：cap 不拒 |
| 6 | 1 | — | — | 不产生 | — | D2：`kUnsupported` |
| **6** | **6** | **4** | **6** | v6 | **v6** | **R2 新锁：第 4 步不回退** |
| 6 | 1 + errorCode | — | — | 不产生 | — | D6：报 errorCode，`native_code` 保留 |

**配套测试 `server_echo_version_does_not_downgrade`**：
- 给定：客户端 6；第 2 步 `version=6` + 合法 CHALLENGE；第 3 步正常产出。
- 当：第 4 步 `TsRequest{version=4, pub_key_auth=MakeServerEchoForTest()}`。
- 则：`ok()`（第 4 步不因版本被拒 —— 这是 R2 的行为要求）且第 5 步 `req.version == 6`
  且 `c.version() == 6`。
- **甲当前落点**（回写在 `kAwaitChallenge` 之前）在这条上会得 `version=4` → 红；
  收窄后绿。**这条是 R2 的唯一判别用例。**

**对现有 15 条的影响**：无。所有第 4 步用例发 `version=6`
（`[READ:tests/test_credssp_sm.cpp:300,336,430,457]`），且 `kAwaitServerEcho` 分支不再有版本拒绝点
→ 比甲方案**少**一处行为变更。

### 9.4 R4 复验：preflight 已修，我独立确认

主代理说三条正则已扩到同时覆盖修复前/后形态。我**重跑**了脚本并**逐条验证正则**：

`[BASH:python F:\rtsc\evidence\exec\batch1_preflight.py]`（修复前，当前工作树）：

```
S1   PRESENT OK   c:46 'nonce_.assign(kNonceSize, 0);'
S5   PRESENT OK   c:42 'if (version_ < kMinVersion) version_ = kMinVersion;'
S5b  ABSENT  OK   no server-version bound check after Decode (defect)
S6   ABSENT  OK   server version never written back (defect)
S18  ABSENT  OK   no production write/guard on server_public_key_ (defect)
RESULT: batch 1 is executable
```

→ **修复前语义正确**（缺陷都在，所以「删掉它」的变异有意义）。

正则级验证（`[BASH:python -c re.search]`，对定案后的代码形态）：

```
S5b post-fix (in kAwaitChallenge)  MATCH  if (req.version < kMinVersion) {
S5b pre-fix ctor line              MISS   if (version_ < kMinVersion) version_ = kMinVersion;
S6  post-fix min                   MATCH  version_ = std::min(version_, req.version);
S6  pre-fix (ctor only)            MISS   if (version_ < kMinVersion) version_ = kMinVersion;
S18 post-fix guard                 MATCH  if (server_public_key_.empty()) {
S18 pre-fix (no guard)             MISS   challenge_message_ = challenge.nego_token;
```

→ **三条都会在修复后正确翻 PRESENT，且修复前正确 MISS/ABSENT。R4 确认已修。**
（注：脚本里 `S5b` 的 `want` 是 `False`，主代理说「修复后三条会正确翻 PRESENT」是指
**人工 Q4 复核时**的语义；脚本本身在修复后跑会因 `want=False` 而报 BAD —— 这是 pre-flight
脚本的固有设计（它只验证「修复前缺陷存在」）。**执行 AI 不要在修复后把 preflight 的 RESULT
当作通过判据**；修复后的判据是 §9.5 的测试套件 + 新增用例。）

**新增门禁（主代理已落地，`want` 与我原建议不同，主代理是对的）**：
我在上一轮建议写 `present('N-B1', r'exported_session_key_\.assign\(nonce_', False, ...)` —— **`False` 是错的**。
主代理实测第一版 `False` → `BAD / BLOCKED`，改成 `True` 才对，并在 `[READ:evidence/exec/batch1_preflight.py:99-100]` 落地为：

```python
present('N-B1', r'exported_session_key_\.assign\(nonce_', True,
        'exported session key derived from the (cleartext) client nonce')
```

**根因（我核对了脚本的两种 `want` 约定，这是执行 AI 必须理解的一点）**：

| 行 | 正则匹配的是 | `want` | 语义 |
|---|---|---|---|
| `S5b` / `S6` / `S18` | **修复后的形态**（`.empty()` / `std::min` / 守卫） | `False` | 「修复还不存在」= 修复前应为 ABSENT |
| `S1` / `S5` / **`N-B1`** | **缺陷本身的形态**（`assign(...,0)` / `nonce_.assign(nonce_`） | `True` | 「缺陷当前存在」= 修复前应为 PRESENT |

两种约定都能表达「修复前状态」，但**同一脚本里混用**，所以不能凭直觉填 `want`。
我复验了 N-B1 正则的判别力（`[BASH:python -c re.search]`）：

```
pre-fix  c:191        MATCH  exported_session_key_.assign(nonce_.begin() + 8, nonce_.be...
post-fix RandomBytes  MISS   if (!crypto::RandomBytes(exported_session_key_, 16)) {
post-fix else branch  MISS   exported_session_key_ = session_base_key_;
```

→ 修复前 PRESENT、修复后 ABSENT，**门禁有效且不会误伤 `else` 分支**（`session_base_key_` 路径保持原样）。
我重跑脚本确认落地生效（`[BASH:python evidence/exec/batch1_preflight.py]`）：

```
N-B1 PRESENT OK   exported session key derived from the (cleartext) client nonce
        c:191  'exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);'
```

### 9.5 批 1 最终执行清单（合并甲 §8 + 我的 §5.2 + R1/R2）

| # | 位置（文本锚点） | 改动 | 来源 |
|---|---|---|---|
| 1 | 新增 `include/rtsc/crypto/random.h` + **`src/crypto/random_win.cpp` / `src/crypto/random_posix.cpp`**（分文件，见任务书 §6.2 与 §9.13） | `bool RandomBytes(uint8_t*, size_t)` + `bool RandomBytes(Bytes&, size_t)`；Win `BCryptGenRandom`，POSIX `getrandom`（EINTR 重试，`ENOSYS` 退 `/dev/urandom`）；失败返回 false 且输出清空 | S1 |
| 2 | `CMakeLists.txt:39-40` | 保留 `add_library(rtsc_crypto STATIC src/crypto/hash.cpp)`，在其后按平台 `target_sources(rtsc_crypto PRIVATE src/crypto/random_win.cpp)` / `random_posix.cpp`，并在 `if(WIN32)` 内 `target_link_libraries(rtsc_crypto PUBLIC bcrypt)`；**禁止 `#pragma comment(lib)`**、**禁止无条件链 bcrypt**（`linux-build-gate.sh:58` 的 `WINDOWS_H_COUNT` 是硬门） | S1 |
| 3 | `credssp.cpp` `#include <algorithm>` 之后 | `#include "rtsc/crypto/random.h"` | S1 |
| 4 | `credssp.cpp:44-46`（三行注释 + `nonce_.assign(kNonceSize, 0);`） | 换 `if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();`（建议同时记 `nonce_ready_`/`nonce_error_`，见 §2.1.3 方案 C） | S1 |
| 5 | **`credssp.cpp:191`** | **`exported_session_key_` 改独立 16 字节 CSPRNG（KEY_EXCH 分支），失败 `Fail(Status::kInternal, "CSPRNG unavailable for exported session key")`** | **N-B1 / R1** |
| 6 | `OnServerResponse`：`if (step_ == Step::kAwaitChallenge) {` 之内、`return BuildStep3` 之前 | D2 下界检查 + D1 `version_ = std::min(version_, req.version);` | S5+S6 / R2 |
| 7 | `BuildStep3` 入口（`if (challenge.nego_token.empty())` 之前） | 空公钥守卫（S18）→ nonce 尺寸守卫（D5），**顺序不可换** | S18 + D5 |
| 8 | `credssp.h:61` 之前 | `void SetServerPublicKey(Bytes spk) { server_public_key_ = std::move(spk); }` + `#include <utility>` | S18 |
| 9 | `OpenReceive`：`plaintext = recv_rc4_.Apply(ciphertext);` 之后 | 同流解 checksum → 校验 Version==1 / SeqNum==recv_seq_ → `DeriveSigningKey(exported,true)` 重算比对；**三处失败都先 `plaintext.clear()`**；成功才 `++recv_seq_` | S11 / D4 |
| 10 | `verify.ps1` | N6 门禁 `Select-String credssp.cpp,random.cpp -Pattern '\brand\(|\bsrand\(|std::random_device|mt19937'` 必须无输出 | S1（主代理执行，R5） |

**必跑套件（影响范围，禁止全量）**：`rtsc_credssp_sm_tests`（≥20）、`rtsc_ntlm_tests`（27）、
`rtsc_credssp_tests`（23）、`rtsc_crypto_tests`（新增源文件）+ C0 编译零警告。

**新增用例（8 条）**：doc 指定 5 条 + `error_code_wins_over_bad_version` +
`client_nonce_does_not_disclose_session_key`（R1）+ `server_echo_version_does_not_downgrade`（R2）。
建议再加 `replayed_echo_with_stale_seq_is_rejected`（§2.4.4）与 `short_nonce_is_rejected_not_crashed`（D5）。

**明确不改的两处（防执行 AI 扩大范围，C7）**：

| 位置 | 现状 | 为什么不改 |
|---|---|---|
| `[READ:src/credssp/credssp.cpp:176]` | `in.client_challenge.assign(nonce_.begin(), nonce_.begin() + 8);` | NTLMv2 的 `ClientChallenge` **本来就明文传输**：`[READ:docs/spec/security-layer.md:1127]` 的 `temp = … ClientChallenge(8) …` 直接拼进 NT response，`:1143` 也写明它是「8 字节随机」。它不是秘密。`security-layer.md:1394` 只要求它是**随机**的 —— S1 修好后 `nonce[0..8)` 已是 CSPRNG，满足该要求。**关键区别**：`client_challenge` 泄露不导致密钥泄露；`client_nonce` 泄露导致密钥泄露（N-B1），所以只有后者必须改。主代理独立核过此判断并确认。 |
| `[READ:src/credssp/credssp.cpp:193]` | `exported_session_key_ = session_base_key_;`（无 KEY_EXCH 分支） | 规范 `[READ:docs/spec/security-layer.md:831]`「否则 = KeyExchangeKey」，本来就是派生而非随机。**只改 KEY_EXCH 分支**。 |

**preflight 的 `want` 语义（必须写进执行任务，防误判）**：见 §9.4 末。批 1 落地后
`S5b`/`S6`/`S18`/`N-B1` 四行会**故意**报 BAD/PRESENT —— **这是预期状态，禁止为了让 preflight 变绿而回退修复**。
落地后的判据是「三套件 + 新增用例 + C0 编译」，不是 preflight 的 `RESULT`。

### 9.6 双审盖章状态

| 项 | 乙（本文件） | 甲 | 状态 |
|---|---|---|---|
| S1 缺陷存在 + 方案 | 已确认 | 已确认 | 一致 |
| S5 只拒下界 | 已确认 | 已确认 | 一致 |
| S6 `min` 不 `clamp` | 已确认 | 已确认 | 一致 |
| S11 server→client 密钥 | 已确认 | 已确认 | 一致 |
| S18 `BuildStep3` 守卫 | 已确认 | 已确认 | 一致 |
| D5 提前 nonce 守卫 | 已确认 | 已确认 | 一致 |
| D6 errorCode 优先 | 已确认 | 已确认 | 一致 |
| **R1 N-B1（新 P0）** | 已提出并主张并入 | **待回签** | 待定 |
| **R2 落点收窄** | 已提出，主代理采纳 | **待回签** | 待定 |

**盖章条件**：甲回签 R1 + R2（或提出反驳并达成新共识）后，由双方分别 `relay parent`
报「批 1 定案双方盖章」。在此之前**不派发执行 AI**。

### 9.7 主代理对 §9 的三点回复（已收讫，全部落地）

| # | 主代理回复 | 我的动作 |
|---|---|---|
| 1 | **建议 4（N-B1 preflight 门禁）已采纳并落地**：`present('N-B1', r'exported_session_key_\.assign\(nonce_', True, ...)`；主代理第一版写 `False` 得 `BAD/BLOCKED`，改 `True` 才对 | 我复验了脚本与正则（§9.4）：`N-B1 PRESENT OK c:191`；对定案代码形态 `MISS`（不误伤 `else` 分支）。**并订正了我自己上一轮的建议——我原来写的 `False` 是错的**（§9.4 末已改） |
| 2 | **§三风险（`S5b want=False` 修复后仍报 BAD）已写进执行任务硬约束** | 我把该约束同步进 §9.5 末「preflight 的 `want` 语义」段，并补了「两种 `want` 约定混用」的对照表，避免执行 AI 凭直觉填 |
| 3 | **`c:176` 不改，主代理确认我对** | 我把理由升级为规范依据：`security-layer.md:1127`（ClientChallenge 直接拼进 NT response）、`:1143`（8 字节随机）、`:1394`（只要求随机）。已进 §9.5「明确不改的两处」表 |

**我对主代理三点回复的独立核对结论**：
1. `want` 语义：**主代理是对的，我上一轮的建议写错了**。我复核了脚本里两种约定的混用
   （§9.4 对照表），并实测确认 `True` 在修复前 PRESENT、修复后 ABSENT。这是**我的错误，已订正**。
2. 风险提示：主代理复述准确，无补充。
3. `c:176`：主代理的理由（ClientChallenge 明文传输、泄露不致密钥泄露）与我一致；
   我额外定位到规范行号（`:1127/:1143/:1394`）作为可引用证据。

### 9.8 当前状态（等待项）

- **R1/R2 已定案**（主代理裁决 + 我落成执行细则），**等甲回签**。
- 甲回签后：同意 → 双方各自 `relay parent` 报「批 1 定案双方盖章」；反驳 → 按证据磋商，
  定不下来报主代理。
- **本轮未启动任何 exe、未编译、未改工程/测试代码**；仅更新本文档。

### 9.9 状态码定案（三轮改判的收敛）：新增 `credssp::Status::kInternal`

> 这一节记录一次**我自己写错 → 主代理改判 → 甲推翻 → 最终收敛**的完整链条。
> 保留过程是因为「最终代码为什么长这样」比结论本身更容易在下一轮丢失。

#### 9.9.1 事实（我逐条实读）

`[READ:include/rtsc/credssp/ts_request.h:21-26]`：

```cpp
enum class Status : uint8_t {
    kOk = 0,
    kTruncated,       // input ended inside a TLV
    kMalformed,       // tag/length/structure violation
    kUnsupported,     // valid structure, value this implementation rejects
};
```

**只有四个值，没有 `kInternal`。** `CredsspClient::Fail` 的第一个参数是 `credssp::Status`
（`[READ:include/rtsc/credssp/credssp.h:85]`：`Error Fail(Status status, std::string message, int32_t native_code = 0);`）。
`tls::Status::kInternal` 在 `rtsc::net`（`[READ:include/rtsc/net/tls.h:47]`），**类型不匹配**。

→ 我 §9.2 初稿写的 `Fail(Status::kInternal, ...)` **确实编译不过**。这是我的错误，甲抓对了。

#### 9.9.2 为什么最终不用 `kMalformed`（主代理第二版裁决，被甲推翻，我核后同意）

`[READ:docs/spec/security-integration.audit-a.md:603]` 的批 3 映射规则：

```
credssp::Error | native_code == 0 且 status==kMalformed/kTruncated | kProtocolViolation | kNone
```

CSPRNG 不可用 → `kMalformed` + `native_code=0` → **`kProtocolViolation`**
→ 用户被告知「服务器违反协议」，去查服务器/网络。**归因方向反了**（本地环境故障被报成对端违规）。
这是可执行判据，不是偏好。

另外两条（甲提出，我核过）：

1. `kMalformed` 在 `credssp.cpp` 里已是兜底桶：
   `[READ:src/credssp/credssp.cpp:61,85,88,113,275,284]` 用它表示
   `Start called twice` / `response after completion` / `response before Start` /
   `unexpected state` / `echo length mismatch` / `server echo mismatch` —— 再加 RNG 失败
   不增加任何语义信息。
2. 「靠 `message` 区分」被三处契约否证：
   `[READ:include/rtsc/net/tls.h:60]`（message 不驱动控制流）、
   `[READ:include/rtsc/credssp/ts_request.h:31-33]`（native_code「instead of guessing from the text」）、
   `[READ:docs/spec/security-integration.audit-a.md:615]`（禁止 `strstr(detail, "...")`）。
   我实测：全仓 `Error.message` 参与分支判断 **0 处**。

#### 9.9.3 定案

```cpp
// include/rtsc/credssp/ts_request.h:21-26 —— 新增第 5 个值
enum class Status : uint8_t {
    kOk = 0,
    kTruncated,       // input ended inside a TLV
    kMalformed,       // tag/length/structure violation
    kUnsupported,     // valid structure, value this implementation rejects
    kInternal,        // local environment failure (CSPRNG unavailable, ...)
};
```

```cpp
// src/credssp/credssp.cpp, N-B1 失败分支
if (!crypto::RandomBytes(exported_session_key_, kExportedKeySize)) {
    return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
}
```

与 `tls::Status::kInternal → kInternal`（`[READ:docs/spec/security-integration.audit-a.md:597]`）
对齐；批 3 映射已就位（`[READ:docs/spec/security-integration.audit-a.md:605]` 已列
`credssp::Error | status == kInternal | kInternal`）。

#### 9.9.4 成本核算（我独立复跑，不采信甲的数字）

| 检查项 | 我的实测结果 |
|---|---|
| 全仓 `switch(...status...)` | **0** 处（216 个源文件全扫） |
| 全仓 `case Status::` | 7 处，**全部在 `src/proto/byte_order.cpp:7-13`**，那是 `rtsc::proto::Status`，**不是** `credssp::Status` |
| `static_cast<int>(...status)` / `status == <数字>` / `arr[status]` | **0** 处 |
| `credssp::Status` 转文本（`to_string`/`ToString`/`operator<<`） | **0** 处 |
| `credssp::Status` 被 credssp 模块外引用 | **0** 处（唯一命中在 `evidence/` 的参考实现） |
| `tests/` 里对 credssp 状态做数值比较 | **0** 处 |

→ 加第 5 个枚举值**不触发** `/W4 /WX` 的「未处理枚举」警告（该警告只在 `switch` 无 `default`
且未覆盖全部值时出现，而这里 `switch` 数为 0），也**不改任何现有行为**。
**成本 = 1 行枚举 + 1 行注释。**

#### 9.9.5 前置步骤（执行 AI 必读）

**顺序不可颠倒**：

1. 先改 `include/rtsc/credssp/ts_request.h:21-26`，加 `kInternal`；
2. 再改 `credssp.cpp` 的 N-B1 分支用 `Status::kInternal`；
3. 否则**编译失败**（`/W4 /WX` 下是 error，不是 warning）。

`kExportedKeySize` 建议与 `kNonceSize` 并列定义在
`[READ:src/credssp/credssp.cpp:16-17]` 的匿名命名空间（`kNonceSize = 32` / `kSignatureSize = 16` 旁边），
**不要**放进头文件（现有常量都不在头文件，保持一致）。

#### 9.9.6 我对自己三轮表述的订正

| 轮次 | 我写的 | 判定 |
|---|---|---|
| 阶段 1 §2.1.3 方案 C | `Fail(Status::kInternal, ...)` | **方向对，但漏了「枚举缺这个值」这个前置条件** —— 按字面写会编译失败 |
| 主代理第二版 | `kMalformed` | 我已照改（§9.2/§9.5），但**归因论证不成立**（批 3 映射会报成协议违规） |
| 本版（§9.9） | 新增 `kInternal` + 前置步骤 | **最终** |

**结论**：我的初稿方向正确但表述不完整；主代理两次改判各修对一半；
甲的「批 3 映射会把本地故障报成服务器违规」是决定性论据。**三方收敛，无剩余分歧。**

### 9.10 我在核对本轮裁决时新发现的两处**工具链**缺陷（非工程代码）

> 两处都**不影响**批 1 的代码改动，但影响「门禁是否真的能挡住」。
> 都不需要改工程代码，只需改 `evidence/exec/*.py` 或 `verify.ps1`。

#### 9.10.1 `batch1_preflight.py` / `batch2_preflight.py` **永远 exit 0**，门禁是死的

`[READ:verify.ps1:329-332]`：

```powershell
$pf1 = Join-Path $root "evidence\exec\batch1_preflight.py"
if (-not (Test-Path $pf1)) { Write-Error "missing $pf1"; exit 1 }
& $py $pf1
if ($LASTEXITCODE -ne 0) { Write-Error "batch-1 anchor pre-flight failed"; exit 1 }
```

它靠 `$LASTEXITCODE` 判定。但两个脚本**都没有 `sys.exit` / `raise SystemExit` / `assert`**：

```
batch1_preflight.py : import sys=0  sys.exit=0  raise=0  assert=0
batch2_preflight.py : import sys=0  sys.exit=0  raise=0  assert=0
```

它们只打印 `RESULT: ... BLOCKED`。我做了**强制失败实验**（在 `.tmp` 里复制脚本、把 S1 的正则改成
永不匹配的 `ZZZ_NEVER_MATCHES_ZZZ`，不动工作树）：

```
[BASH:python .tmp\audit-b1\check_preflight_exit.py]
   S1   ABSENT  BAD  deterministic nonce -> fix randomizes it
   RESULT: BLOCKED
  exit code = 0
VERDICT: gate blocks? NO -- always exits 0
```

**结论**：`verify.ps1 -DocCite` 里这两道 preflight 门禁**永远不会失败**。

**两个方向的后果（都必须知道）**：
- **好的一面**：执行 AI 落地批 1 后即使 preflight 打印 BLOCKED，`verify.ps1 -DocCite` 也不会因此失败
  → 降低了「为了让 preflight 变绿而回退修复」的风险。
- **坏的一面**：这两道门禁**提供零保护**。批 2 的锚点漂移、批 1 的缺陷被提前误修，都不会被拦住。

**修复建议（1 行，两个脚本各一处）**：末尾改为

```python
print('RESULT:', 'batch 1 is executable' if ok else 'BLOCKED')
raise SystemExit(0 if ok else 1)
```

（`verify_anchors.py` / `verify_citations.py` 已有 `sys.exit`，只有这两个 preflight 漏了。）

#### 9.10.2 采纳的 N-B1 正则会被「注释里写了旧写法」骗成 PRESENT

采纳的门禁是（`[READ:evidence/exec/batch1_preflight.py:99-100]`）：

```python
present('N-B1', r'exported_session_key_\s*(?:\.assign|=)\s*[^;]*nonce_', True, ...)
```

我测了它对**注释**的行为（`[BASH:python .tmp\audit-b1\regex_comment_check.py]`）：

```
case                                                       raw      stripped
POST-FIX real code (RandomBytes)                           MISS     MISS
POST-FIX else branch                                       MISS     MISS
POST-FIX + doc comment mentioning the forbidden form       MATCH    MISS
POST-FIX + comment with .assign                            MATCH    MISS
PRE-FIX defect                                             MATCH    MATCH
HALF-FIX = Bytes(...)                                      MATCH    MATCH
HALF-FIX multiline                                         MATCH    MATCH
```

即：修复后若有人在 `credssp.cpp` 里写一句
`// N-B1: never write exported_session_key_ = Bytes(nonce_.begin() + 8, ...)`
（**这是很自然的注释**，因为改动本身需要解释「为什么不能从 nonce 派生」），
门禁会 MATCH → 在 `want=True` 下报 `PRESENT / OK` → **门禁自己失效**。

**严重度**：低。原因有二 ——
(a) 该行 `want=True`，修复后本来就预期 BAD（§9.4 已说明），所以「误报 PRESENT」只是让 BAD 变成 OK，
    方向是「更容易过」，不会误伤正确实现；
(b) 真正的判据是测试用例，不是门禁。

**修复建议（1 行）**：匹配前剥掉行注释。

```python
def present(label, pattern, want, note):
    ...
    hits = [i + 1 for i, s in enumerate(src)
            if re.search(pattern, s.split('//')[0])]      # ← 只看代码部分
```

我验证：剥注释后 7 个用例的判定全部正确（上表 `stripped` 列），
且真实缺陷 / 半修复 / 多行半修复仍全部 MATCH。

**建议优先级**：P3（不阻塞批 1）。但若主代理要让 N-B1 门禁长期有效（跨批 2/3），
建议顺手改掉 —— 否则下一批的注释很容易把它变成永远绿。

### 9.11 盖章（最终）

| 项 | 乙（本文件） | 甲 | 主代理 | 状态 |
|---|---|---|---|---|
| S1 CSPRNG + 提前守卫（D5） | 确认 | 确认 | 裁决 | 一致 |
| S5 只拒下界（D2） | 确认 | 确认 | 裁决 | 一致 |
| S6 `min` 不 `clamp`（D1） | 确认 | 确认 | 裁决 | 一致 |
| S11 server→client 密钥（D4） | 确认 | 确认 | 裁决 | 一致 |
| S18 `BuildStep3` 守卫（D3） | 确认 | 确认 | 裁决 | 一致 |
| D6 errorCode 优先 | 确认 | 确认 | 裁决 | 一致 |
| R1 N-B1 并入批 1 | 提出 | 回签同意 | 裁决采纳 | 一致 |
| R2 落点收窄（D2+D1 同分支） | 提出 | 回签同意 | 裁决采纳 | 一致 |
| R4 preflight 正则加强 | 提出 | 加强并回签 | 落地 | 一致 |
| `client_challenge` 不改 | 判定 | 同意 + 补 `:1357`/`:1041` 依据 | 确认 | 一致 |
| **状态码 = 新增 `kInternal`** | 本文件 §9.9 | 提出决定性论据 | 裁决 | **一致（最终）** |
| 工具链两处缺陷（§9.10） | 新发现 | 未涉及 | 待处置 | 建议 P3 |

**乙方签署**：批 1 定案（S1/S5/S6/S11/S18 + N-B1 + R2）**无剩余异议**，
执行前置条件已全部写明（§9.9.5 枚举先行、§9.5 明确不改的两处、§9.4 preflight 语义）。

### 9.12 方案 C 确认（乙签署）+ 我在核签时发现的 3 处**文档/任务书**缺陷

> 主代理要求我在确认方案 C 前核三点，不要盲签。以下是我逐点的实测结果。
> 结论：**方案 C 我确认，可编译、映射正确、前置条件已写明**。
> 但核签过程中在**任务书与规范文档**里发现 3 处会误导执行 AI 的缺陷（P2/P3），
> 建议**派发前**修掉。**本轮未改工程代码，未启动 exe。**

#### 9.12.1 三点核签（逐点实测）

**① `ts_request.h` 加 `kInternal` 后能编译（类型匹配）—— 成立**

- `[READ:include/rtsc/credssp/credssp.h:85]`：`Error Fail(Status status, std::string message, int32_t native_code = 0);`
  —— 形参类型是 **`credssp::Status`**（同文件 `:11 namespace rtsc::credssp`，`Status` 来自 `ts_request.h`）。
- 加了 `kInternal` 之后，`Status::kInternal` **就是** `credssp::Status` 的枚举值 → 类型匹配。
- 底层类型 `uint8_t`（`[READ:include/rtsc/credssp/ts_request.h:21]`），5 个值远未超限。
- **不会触发 `/W4 /WX`**：我全扫 216 个源文件，
  `switch(...status...)` = **0 处**、`static_cast<int>(...status)` = **0 处**、
  `status == <数字>` = **0 处**、`arr[status]` = **0 处**、
  `credssp::Status` 的 `to_string`/`ToString`/`operator<<` = **0 处**、
  `status` 的大小比较（`>`/`<`）= **0 处**、`static_assert` 涉及 Status = **0 处**。
  唯一 7 处 `case Status::` 全在 `[READ:src/proto/byte_order.cpp:7-13]`，那是 **`rtsc::proto::Status`**，不同枚举。

**② `security-integration.audit-a.md:605` 的映射行存在且语义正确 —— 成立**

`[READ:docs/spec/security-integration.audit-a.md:605]`：

```
| `credssp::Error` | `status == kInternal` | `kInternal` | `kNone` | 批 1 新增枚举值（见 §19.3.2 批 1 说明） |
```

语义核对：`Kind::kInternal` 的定义是「local bug or environment failure」
（`[READ:docs/spec/security-integration.audit-a.md:1161]`），`native_space = kNone`
（`[READ:docs/spec/security-integration.audit-a.md:1173]` 的 `kLocal` 未用在此行，
但 `kNone` 也表示「无外部码」，与 CSPRNG 失败 `native_code=0` 自洽）。
**映射正确**：本地环境故障 → `kind=kInternal`，不会被误报成 `kProtocolViolation`。
与 `tls::Status::kInternal → kInternal`（`:597`）同构。

**③ 我的 §9.2 已注明前置条件 —— 成立**

`[READ:F:\rtsc\docs\spec\batch1-audit-b.md:1224-1228]`（§9.2 开头引用块）已写明：
「`credssp::Status` 目前只有 4 个值……执行 AI 必须**先**在 `ts_request.h:21-26` 追加
`kInternal, ...`，再写下面的 `Fail(Status::kInternal, ...)`」。

#### 9.12.2 缺陷 A（P2，会误导执行 AI）：任务书 §2.0 自己和自己矛盾

`[READ:docs/spec/batch1-execution-brief.md:65]`：

> 传进 `credssp::Fail()` 类型不匹配，**编译不过**。**审计乙的稿子里写了 `kInternal`，是笔误。**

而同一节 `[READ:docs/spec/batch1-execution-brief.md:67-85]`：

> **定案（第三次裁决，前两次被审计甲用证据推翻）：批 1 新增 `credssp::Status::kInternal`。**
> ```cpp
> kInternal,        // local environment failure (CSPRNG unavailable, etc.)
> ```
> ```cpp
> return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
> ```

**同一节第 65 行说「是笔误」，第 67-85 行说「就按这个做」。**
执行 AI 从上往下读，第 65 行会先建立一个错误印象：「kInternal 是审计乙写错了」。
若它据此改成 `kUnsupported` 或 `kMalformed`，就会撞上 §9.9.2 的两个问题
（批 3 映射误报协议违规 / 与版本不支持无法区分），而**任务书的测试判据抓不到**
（`client_nonce_does_not_disclose_session_key` 只断言 key 不等于 nonce 窗口，
不检查失败分支的 status）。

**建议改法（1 行）**：把 `:65` 那句改成

> `tls::Status::kInternal` 在 `rtsc::net` 命名空间，传进 `credssp::Fail()` 类型不匹配，**编译不过**。
> 正确做法不是改状态码，而是**给 `credssp::Status` 补上 `kInternal`**（见下）。

**为什么这不是小事**：本批的验收判据是「测试全绿」。这条缺陷**不会让任何测试变红**，
所以它会一路通过到批 3 才暴露（用户看到「服务器违反协议」）。

#### 9.12.3 缺陷 B（P3，悬空引用）：`security-integration.audit-a.md:605` 指向一个不存在说明的章节

`:605` 的证据列写「见 §19.3.2 批 1 说明」。我核了 `§19.3.2` 的范围
（`[READ:docs/spec/security-integration.audit-a.md:3765-3800]`）：

- `kInternal` 出现次数：**0**
- 「枚举」出现次数：**0**
- 该节只列了 5 条红证配方（S1/S5/S6/S11/S18），**完全没有提「新增枚举值」这件事**

→ 引用悬空。读者按图索骥会找不到任何说明。
**建议**：在 §19.3.2 末尾补一段（3-5 行）说明「N-B1 的失败分支需要新增
`credssp::Status::kInternal`，成本与证明见批 1 审计 §9.9」，或把 `:605` 的证据列改成
指向审计报告。

#### 9.12.4 缺陷 C（P2，测试覆盖缺口）：任务书没有 `error_code_wins_over_bad_version`

任务书 §3 列了 **7** 条新用例（`[READ:docs/spec/batch1-execution-brief.md:165-171]`），
标题却写「**六条**要新增的用例」（`:161`，数量笔误，P3）。
但真正的问题是：**D6 的顺序不变量没有任何测试锁住**。

我逐条核了现有 15 条 + 7 条新用例，能否抓住「把版本下界检查挪到 errorCode 分支之前」：

| 用例 | 能否抓 D6 回归 | 原因 |
|---|---|---|
| `version_below_min_is_rejected_with_valid_challenge` | **不能** | 该用例没有 errorCode，挪到前面也照样 `kUnsupported` |
| `error_code_aborts_with_server_status`（`t:354`） | **不能** | 它发的 `err.version = 6`（合法），版本检查不会触发 |
| `error_code_is_checked_before_any_token_processing`（`t:375`） | **不能** | 同上，version=6 |
| `client_nonce_does_not_disclose_session_key` | **不能** | 只看 key 与 nonce 的关系 |
| 其余 11 条 | **不能** | 都发合法 version |

→ **D6 完全没有回归保护。** 甲早已写出 `error_code_wins_over_bad_version`
（`[READ:evidence/exec/batch1-a-new-tests-reference.cpp:709-731]`，`err.version = 1` +
`has_error_code` + 断言 `native_code == 0xC000006D`），任务书却把它漏了。

**建议**：把 `error_code_wins_over_bad_version` 加进 §3 表（第 8 条），
验收阈值 `rtsc_credssp_sm_tests >= 23`（原 15 + 新增 8）。
**这是本批唯一「不加就一定会在未来被改坏」的用例** —— 因为 D6 是唯一
「顺序错了功能仍正常、只有诊断信息丢失」的约束。

#### 9.12.5 乙方最终签署

| 核签项 | 结果 |
|---|---|
| ① 类型匹配可编译 | **成立**（`Fail` 形参即 `credssp::Status`；全仓 0 处 switch/转换） |
| ② `:605` 映射行存在且语义正确 | **成立**（`kInternal` + `kNone`，与 `:597` 同构） |
| ③ §9.2 已注明前置条件 | **成立**（`:1224-1228`） |
| 方案 C 本身 | **确认，无异议** |

**批 1 定案（S1 / S5 / S6 / S11 / S18 + N-B1 + R2 + 新增 `Status::kInternal`）乙方签署通过。**

派发前建议修 3 处（都在文档/任务书，不涉工程代码）：
- **P2** 任务书 `:65` 的「是笔误」与 `:67-85` 的定案自相矛盾；
- **P2** 任务书缺 `error_code_wins_over_bad_version`（D6 零回归保护）；
- **P3** `security-integration.audit-a.md:605` 的「见 §19.3.2」是悬空引用（该节 0 次提及 kInternal）；
  另 `batch1-execution-brief.md:161` 写「六条」实为 7 条（加 error_code 后为 8 条）。

### 9.13 派发前最后一遍：任务书 §6.2 与 §9.5 的形态不一致（我核出的第 4 处）

> 这条是我在核签时顺手比对「我的 §9.5 清单」与「任务书 §6.2」发现的，
> **不是新缺陷，而是两份文档对同一个文件给出两种形态**，执行 AI 会二选一。

| 项 | 我的 §9.5（原文） | 任务书 §6.2（`[READ:docs/spec/batch1-execution-brief.md:309-317]`） |
|---|---|---|
| 文件 | 单个 `src/crypto/random.cpp` | **`random_win.cpp` + `random_posix.cpp` 分文件** |
| CMake | 把 `random.cpp` 加进 `add_library(rtsc_crypto STATIC ...)` | 保留 `add_library(... hash.cpp)`，用 `target_sources` 按平台追加 |
| 头文件签名 | `bool RandomBytes(Bytes&, size_t)` | **两个重载**：`bool RandomBytes(uint8_t*, size_t)` + `bool RandomBytes(Bytes&, size_t)` |

**判定：任务书的形态更对，我已按它改了 §9.5。** 理由（我独立核过）：

1. `[READ:scripts/linux-build-gate.sh:58]`：`WINDOWS_H_COUNT=$(grep -c 'windows\.h' "$BUILD_LOG")`，
   `:67` 在 `WINDOWS_H_COUNT != 0` 时 `LINUX GATE FAIL`。
   **若 `random.cpp` 单文件里无条件 `#include <windows.h>`，Linux 构建日志必然命中 → 门禁红。**
   任务书 §6.2 的分文件方案从结构上避免这一点（`:289-290` 的硬约束正是这个）。
2. `[READ:scripts/linux-build-gate.sh:67]` 同时检查 `FAILED_COUNT`，所以「Linux 上 bcrypt 链接失败」
   也会被抓 —— 这印证了任务书 `:332`「禁止把 bcrypt 无条件链进 rtsc_crypto」。
3. 头文件两个重载：`uint8_t*` 版是平台层的实现入口，`Bytes&` 版是 `credssp.cpp` 的调用形态；
   两者都要，否则 `credssp.cpp` 里 `RandomBytes(exported_session_key_, 16)`（`vector` 版）
   与 `RandomBytes(nonce_.data(), nonce_.size())`（指针版，doc:4003 的写法）会有一个编不过。

**我原先的单文件形态在 Windows 上能过、在 Linux 上必红** —— 这是一个只有跑
`verify.ps1 -LinuxBuild` 才会暴露的问题，而任务书把它提前写清楚了。**采纳任务书。**

### 9.14 派发前待修清单（4 条，全部在文档/任务书，不涉工程代码）

| # | 级别 | 位置 | 问题 | 建议 |
|---|---|---|---|---|
| 1 | **P2** | `batch1-execution-brief.md:65` | 「审计乙的稿子里写了 `kInternal`，**是笔误**」与同节 `:67-85` 的定案（新增 `kInternal`）**自相矛盾**。执行 AI 从上往下读会先建立错误印象，若据此改成 `kUnsupported`/`kMalformed`，**没有任何测试会变红**（§9.12.4 已证 D6 与 N-B1 的 status 都不被断言），错误会一路活到批 3 | 改成「类型不匹配，编译不过 → 正确做法是给 `credssp::Status` 补 `kInternal`」 |
| 2 | **P2** | `batch1-execution-brief.md` §3（`:161-171`） | 缺 `error_code_wins_over_bad_version`。我逐条核过：现有 15 条 + 7 条新用例**没有一条**能抓「版本检查挪到 errorCode 之前」——`t:362`/`t:384` 都发 `version=6`，`version_below_min...` 没有 errorCode | 加为第 8 条；验收 `rtsc_credssp_sm_tests >= 23` |
| 3 | P3 | `security-integration.audit-a.md:605` | 证据列写「见 §19.3.2 批 1 说明」，但 `[READ:docs/spec/security-integration.audit-a.md:3765-3800]` 该节 **0 次**提及 `kInternal`/枚举（只列 5 条红证配方） | 在 §19.3.2 补 3-5 行，或把证据列指向审计报告 §9.9 |
| 4 | P3 | `batch1-execution-brief.md:161` | 标题「**六条**要新增的用例」，表里实为 **7** 条（加 error_code 后 8 条） | 改数字 |

**这 4 条都不阻塞「方案 C 确认」**，但第 1、2 条建议**派发前**修：
第 1 条会把执行 AI 引向已被三方否决的状态码；第 2 条会让 D6 永远没有回归保护。

### 9.15 乙方盖章（最终，无保留）

| 项 | 结论 |
|---|---|
| 方案 C（新增 `credssp::Status::kInternal`） | **确认**。类型匹配（`Fail` 形参即 `credssp::Status`）、映射正确（`:605` → `kind=kInternal`）、成本为零（全仓 0 处 switch/转换/文本化）、前置条件已写入 §9.2 |
| D1 / D2 / D3 / D4 / D5 / D6 | 确认（逐条证据见 §2、§4、§8、§9.9） |
| R1 N-B1 并入批 1 | 确认 |
| R2 落点收窄（D2+D1 同收窄进 `kAwaitChallenge`） | 确认 |
| `client_challenge`（`c:176`）/ 无 KEY_EXCH 分支（`c:193`）不改 | 确认 |
| N-B1 preflight 门禁（`want=True` + 加强正则） | 确认 |
| 工具链 2 处缺陷（§9.10） | 已报告，建议 P3 处置，**不阻塞** |
| 派发前文档 4 处待修（§9.14） | 已报告；**第 1、2 条建议派发前修** |

**批 1 定案双方盖章：乙方（本文件）通过。** 甲方已于 `batch1-audit-a.md` §15.6/§15.7 签署方案 C。
**乙方对批 1 的执行无剩余异议。**

### 9.16 【P1，派发前必须裁决】修好 exit code 之后，`verify.ps1 -DocCite` 在批 1 落地后**必然失败**

> 这一条是我在**验证主代理的两处工具链修复**时发现的副作用。
> 两处修复本身都对（`raise SystemExit` + `_code_only`），但它们把
> 「preflight 打印 BAD 但 exit 0」变成了「preflight 打印 BAD 且 exit 1」，
> 而 `verify.ps1` 正是靠 exit code 判定的。
> **结果：任务书要求执行 AI 跑的验收项，落地后 100% 是红的。**

#### 9.16.1 事实链（全部实测，未改工作树）

1. `[READ:verify.ps1:331-332]`：

```powershell
& $py $pf1
if ($LASTEXITCODE -ne 0) { Write-Error "batch-1 anchor pre-flight failed"; exit 1 }
```

2. `[READ:evidence/exec/batch1_preflight.py:174]`（主代理本轮新加）：
   `raise SystemExit(0 if ok else 1)` —— 现在 exit code 真的会非 0。

3. 脚本里 6 行的 `want` 是**修复前语义**（`[READ:evidence/exec/batch1_preflight.py:88-119]`）：

| 行 | 正则匹配的形态 | `want` | 修复后状态 | 结果 |
|---|---|---|---|---|
| `S1` | **缺陷**（`nonce_.assign(kNonceSize, 0)`） | `True` | ABSENT | **BAD** |
| `S5` | 构造器 bounds（修复前后都在） | `True` | PRESENT | OK |
| `S5b` | **修复后**形态（`req.version <`） | `False` | PRESENT | **BAD** |
| `S6` | **修复后**形态（`std::min`） | `False` | PRESENT | **BAD** |
| `S18` | **修复后**形态（`.empty()`） | `False` | PRESENT | **BAD** |
| `N-B1` | **缺陷**（`assign(nonce_`） | `True` | ABSENT | **BAD** |

4. 我用**批 1 定案后的源码形态**（含 `kInternal`、R2 收窄、N-B1 独立随机、
   S11 server→client MAC）与**8 条新用例名**做了完整仿真
   （`[BASH:python .tmp\audit-b1\sim_postfix_full.py]`，把 `SRC`/`TESTFILES` 指到
   `.tmp` 里的影子文件，**不动工作树**）：

```
=== full post-fix simulation (src + tests both flipped) ===
   S1   ABSENT  BAD  deterministic nonce -> fix randomizes it
   S5   PRESENT OK   bounds exist in ctor; fix must apply them to the SERVER version
   S5b  PRESENT BAD  no server-version bound check after Decode (defect)
   S6   PRESENT BAD  server version never written back (defect)
   S18  PRESENT BAD  no production write/guard on server_public_key_ (defect)
   N-B1 ABSENT  BAD  exported session key derived from the (cleartext) client nonce
   RESULT: BLOCKED
  exit code = 1
  BAD rows  = 5
```

**5 行 BAD → exit 1 → `verify.ps1:332` 执行 `exit 1` → 整个 `-DocCite` 门禁失败。**

#### 9.16.2 为什么这是 P1（会逼执行 AI 做错事）

任务书**两处**要求执行 AI 用这个判据：

- `[READ:docs/spec/batch1-execution-brief.md:237]`：
  「落地后应改跑 `verify.ps1 -DocCite` + 上面三套件。」
- `[READ:docs/spec/batch1-execution-brief.md:599]`：
  报告项 5「`verify.ps1 -DocCite` 的 exit code」

执行 AI 面对一个**必然失败**的验收项，只有三条路，**全是坏的**：

| 选择 | 后果 |
|---|---|
| 如实报告 `exit 1` | 看起来像批 1 失败；主代理可能据此要求回退 |
| 改 `batch1_preflight.py` 让门禁变绿 | **篡改门禁**（比改测试更严重，且 doc:4201 N2 的同类禁令精神） |
| 回退修复让 preflight 变绿 | 正是任务书 `:236` 明令禁止的 |

**这是「门禁设计与交付时点错配」**：`batch1_preflight.py` 的语义是
「**批 1 尚未执行**时，缺陷必须还在」。批 1 一旦落地，它的**全部断言都应当翻转**，
但脚本没有 phase 开关，`verify.ps1` 也无条件调用它。

#### 9.16.3 三个可选修法（建议 A）

**A（最小、最安全，建议）**：批 1 落地后**从 `verify.ps1 -DocCite` 里移除这一段**
（`:325-332`），或加一个 `-PreBatch1` 开关，默认不跑。
理由：批 2 的 preflight（`batch2_preflight.py`）语义是「锚点是否仍可定位」，
**与阶段无关**，可以长期保留；而批 1 的 preflight 是**一次性**的，落地即失效。
这与 `verify.ps1:328` 自己的注释一致：「Re-run it AFTER batch 1 lands: S5b/S6/S18 must flip to PRESENT」
—— 作者本意就是「落地后要翻转」，但代码没实现翻转。

**B**：给脚本加 `--phase=pre|post`，post 模式下把 6 行的 `want` 全部取反。
成本略高，但保留长期价值（未来若有人回退 S1/N-B1，post 模式能抓）。
注意：`S5`（构造器 bounds）**修复前后都 PRESENT**，取反会误报 —— 需要单独标 `want=None`（跳过）。

**C**：让 `verify.ps1` 对这一段**只告警不失败**（`Write-Warning` 代替 `exit 1`）。
最省事，但等于又退回「门禁不能失败」，与主代理本轮修 exit code 的初衷相反。**不建议。**

#### 9.16.4 我建议的最终形态（A + 一条保留）

```powershell
# 5b) batch-1 pre-flight. One-shot: it asserts the PRE-fix defects still exist.
#     After batch 1 lands every row is expected to flip, so running it again is
#     meaningless. Kept behind an explicit switch for the next pre-fix audit.
if ($PreBatch1) {
    $pf1 = Join-Path $root "evidence\exec\batch1_preflight.py"
    if (-not (Test-Path $pf1)) { Write-Error "missing $pf1"; exit 1 }
    & $py $pf1
    if ($LASTEXITCODE -ne 0) { Write-Error "batch-1 anchor pre-flight failed"; exit 1 }
}
```

并在任务书 `:237` / `:599` 改成：
**「批 1 落地后不跑 `-DocCite` 里的 batch-1 preflight（它是一次性的修复前门禁）；
判据 = 三套件 + `-DocCite` 的其余门禁（citations/anchors/N6）」**。

#### 9.16.5 附带发现：N6 门禁在批 1 之后**不再覆盖真正的 RNG 代码**

`[READ:verify.ps1:339-346]`：

```powershell
$cc = Join-Path $root "src\credssp\credssp.cpp"
$weak = Select-String -LiteralPath $cc -Pattern '\brand\(|\bsrand\(|std::random_device|mt19937'
```

**只扫 `credssp.cpp` 一个文件。** 但批 1 之后，CSPRNG 的**实现**在
`src/crypto/random_win.cpp` / `src/crypto/random_posix.cpp`（任务书 §6.2 定的分文件形态），
`credssp.cpp` 里只剩一行 `crypto::RandomBytes(...)` 调用。

我实测确认：

```
scans credssp.cpp          : True
scans random_win.cpp       : False
scans random_posix.cpp     : False
scans src\crypto\random   : False
```

→ 若执行 AI 在 `random_win.cpp` 里写 `rand()`（或 `random_posix.cpp` 里写 `std::random_device`），
**N6 门禁完全抓不到**，而 `two_constructions_have_different_nonces` 也抓不到（doc:4006-4008 已说明
「弱 RNG → 该测试仍然绿」）。

**建议（2 行）**：把门禁改成扫目录：

```powershell
$weak = Select-String -Path (Join-Path $root "src\crypto\random_*.cpp"), $cc `
                      -Pattern '\brand\(|\bsrand\(|std::random_device|mt19937'
```

**这条与 9.16.1 独立**：即使采用修法 A（移除一次性 preflight），N6 覆盖漏洞仍然存在。

#### 9.16.6 另一处：`_code_only` 的两个边界（P3，当前无害）

主代理本轮把 `present()` 改成 `rx.search(_code_only(s))`，`_code_only` 用
`//.*$` + `/\*.*?\*/` 逐行剥注释（`[READ:evidence/exec/batch1_preflight.py:52-68]`）。
我实测两个边界（`[BASH:python .tmp\audit-b1\code_only_gaps.py]`）：

| 场景 | 结果 |
|---|---|
| **多行块注释**（`/* ... */` 跨行） | 逐行剥不掉中间行 → 中间行里的旧写法仍被当成代码 → **假 PRESENT** |
| **字符串里含 `//`**（如 `"http://..."`） | 该行在 `//` 处被截断 → `//` 之后的真实代码被丢弃 → **假 ABSENT** |

**当前无害（我实测）**：`credssp.cpp` 里 `/*` 出现 **0** 次；全仓 `src/` + `include/`
的 `/*` 也是 **0** 次；含 `//` 的字符串字面量 **0** 处。
所以这两个边界今天不会误判。**标 P3，不需要在批 1 修**，但如果门禁要跨批长期用，值得记住。

### 9.17 本轮乙方的最终状态

| 项 | 状态 |
|---|---|
| 方案 C（`Status::kInternal`） | **已确认并签署**（§9.12.1 / §9.15） |
| 批 1 定案（S1/S5/S6/S11/S18 + N-B1 + R2） | **双方一致，乙方盖章**（§9.15） |
| 我上轮报的 4 处文档缺陷 | 主代理已全部修好，我复验：`:65` 已改（`[READ:docs/spec/batch1-execution-brief.md:67-71]`）、§3 已有第 8 条 `error_code_wins_over_bad_version`（`:182`）、门槛 `>= 23`（`:219`）、§19.3.2 已补 kInternal 说明（`[READ:docs/spec/security-integration.audit-a.md:3802-3813]`）、标题「八条」（`:171`） |
| 我上轮报的 2 处工具链缺陷 | 主代理已修（`raise SystemExit` + `_code_only`），我复验通过（`batch1_preflight.py` 真实 exit=0；`_code_only` 生效） |
| **本轮新报 3 处** | **P1**：`verify.ps1 -DocCite` 落地后必然 exit 1（§9.16.1–9.16.4，**派发前必须裁决**）；**P2**：N6 门禁不再覆盖 `random_*.cpp`（§9.16.5）；**P3**：`_code_only` 两个边界（§9.16.6，当前无害） |
| 纪律 | 本轮**未启动 exe、未编译、未改工程/测试代码**；所有仿真都在 `.tmp` 内用影子文件完成 |

**乙方对批 1 代码定案无异议。** 唯一要求在派发前裁决的是 §9.16.4：
**执行 AI 落地后到底跑不跑 `-DocCite` 里的 batch-1 preflight** —— 不裁决，执行 AI 会撞上一个必然红的验收项。

---
## 10. 批 1 交付验证（乙：跨平台 / 边界 / 攻击面）

> 甲攻红证与实现正确性；本节只做跨平台实跑、边界、攻击面。**未改工程/测试代码**，Linux 实验全在
> WSL `.tmp/audit-b1/linux/shadow*` 影子树。我独立实测 `23/205/0`、`27/136/0`、`23/69/0`、`25/66/0`(crypto)，
> `build_tls.bat` exit=0 —— 与执行 AI 逐项一致。

### 10.1 `random_posix.cpp`（Linux 实跑，29 checks 全绿）

方法：不改源文件，用宏把 `getrandom/open/read/close` 重命名后 `#include "src/crypto/random_posix.cpp"`，
换脚本化假实现（`.tmp/audit-b1/linux/probe_posix.cpp`）。四个边界全部**正确**：

- **`EINVAL`（非 ENOSYS）不误降级**：`ok=0`、`open_calls=0`、缓冲区未触碰（`random_posix.cpp:93`）。
- **`got == 0` → false 正确**（`:57`）：`getrandom_calls=1`，不 spin、不降级；`n>0` 返回 0 属异常。
- **无 fd 泄漏**：read 失败（`:76`）/ read=0（`:80`）/ 成功（`:85`）三路都 `close(fd)`。
- **`open` 的 `EINTR` 重试必要且正确**：`open(2)` ERRORS 明列 `EINTR`；实测 2×EINTR 后成功、fd 关闭。

另通过：EINTR 重试、部分读取循环（32B / 每次 5 → 7 次）、`n==0` 无系统调用、
`out==nullptr && n>0` → false、vector 版失败清空。
**P3**：`:36-38` 的 `__has_include(<sys/random.h>)` 对 macOS 成立但该头只声明 `getentropy` →
编译过、链接失败。`security-layer.md:1380` 目标是「Windows + Linux」故**当前非缺陷**，但
`ntlm.h:8`/`CMakeLists.txt:134` 的「compiles unchanged on … macOS」对该文件不成立。

### 10.2 `random_win.cpp`（读码核）

- `status < 0` **覆盖全部错误**（`NTSTATUS` 是 `LONG`，`NT_SUCCESS(x)` 即 `x >= 0`，`:35`）。
- 分块**不溢出**：`chunk = min(n - done, 0x10000000)`（`:31-32`），恒有 `done + chunk <= n`。
- `:50` 逐字节拷贝与 `memcpy` 等价 → **C7 过度，P3**；`n==0` 返回 true **合理**（调用方常量 32/16，不经此分支）。

### 10.3 攻击面

`.tmp/audit-b1/linux/probe_oracle.cpp` 直连**未修改**的库：

```
mode=step3-ok       ok=1 status=kOk          message=''
mode=seq-tamper     ok=0 status=kMalformed   message='sealed field out of sequence'
mode=mac-tamper     ok=0 status=kMalformed   message='sealed field MAC mismatch'
mode=both           ok=0 status=kMalformed   message='sealed field out of sequence'
mode=version-tamper ok=0 status=kMalformed   message='sealed field unsupported version'
```

**C-1 seq 先于 MAC：不是 oracle。** 两种 message 可区分，但未持密钥的对端学不到信息：
(a) `recv_seq_` 初值 0（`credssp.h:128`），整个握手**只收一条** sealed 消息（`OpenReceive`
唯一调用点 `credssp.cpp:304`）；(b) 对端本就能从自己构造的报文读 `field[12..16)`；
(c) `Fail()` 置 `kFailed`（`:60`），`:89` 的早退让后续调用直接返回旧错误 → **每次握手仅一次探测、失败即断链**。
**仍建议改「先 MAC 后 seq」**（认证前不比未认证输入），0 成本，**P3**。

**C-2 非常量时间比较：违反明文规格（P2）。** `security-layer.md:1392/1807` 要求
「常量时间比较 | 是 | **pubKeyAuth 校验**」；而 `credssp.cpp:329` `if (plain != expected)` 与
`:440` `if (checksum != expected_mac)` 都是 `std::vector::operator!=` 的**逐字节短路**，
全仓无常量时间辅助（grep `constant_time|TimingSafe|CRYPTO_memcmp|volatile uint8_t` → 0）。
**可利用性：理论存在、实际不可用** —— 短路确实给出前缀匹配信号，但每次握手仅一次尝试、
每次需重跑完整 TLS+CredSSP、HMAC 单向无法据前缀恢复密钥。**P2 记账，不阻塞**（约 16 行修复）。

**C-3 `kInternal` 的 message 不泄露**：`credssp.cpp:236` 只描述本地故障，不含密钥/nonce/seq/对端可控量；
`tls.h:60` 的「message 不驱动控制流」满足（全仓 `Error.message` 参与分支判断 **0 处**）。

### 10.4 真实覆盖缺口（P2，可测但未测）

**三条新增安全检查，删掉后 23 条测试仍全绿**（影子树逐条变异实测）：
D5 提前 nonce 守卫（`credssp.cpp:153-155`）、`seq != recv_seq_`（`:423-426`）、
`field[0..4) != 01,00,00,00`（`:415-418`）—— 删任一条都得 `23 tests, 205 checks, 0 failing`。

根因：**没有测试给过非 32 字节 nonce、非 0 seq、非 1 version**（23 条 `SetNonceForTest` 实参一律 32 字节）。
三条都可用公开 API 触发，我实测了 D5 完整矩阵：

```
nonce=0   ok=0 status=kUnsupported msg='nonce must be 32 bytes'
nonce=24  ok=0 status=kUnsupported      nonce=31  ok=0 status=kUnsupported
nonce=32  ok=1 status=kOk          step3=389
nonce=33  ok=0 status=kUnsupported
```

→ **D5 行为正确，只是没有回归保护**。建议补 `short_nonce_is_rejected_not_crashed`、
`replayed_echo_with_stale_seq_is_rejected`（`MakeServerEchoForTest()` 两次、seq 都 0）、
`sealed_field_with_bad_version_is_rejected`（`echo[0]=0x02`），各 5-8 行。

### 10.5 判定：**批 1 通过**

1. 三套件 + crypto 全绿，`build_tls.bat` exit=0，与我独立实测逐项一致；
2. Linux 实跑 23/205/0（WSL g++ 13.3 独立编译，非采信），posix 四边界全对；
3. `random_win.cpp` 无缺陷；4. 攻击面**无可用攻击**；5. 红证 8/8 RED，D6/R2 各仅 1 条能抓。

**记账（不阻塞，建议单列「批 1 后清理」）**：P2 常量时间比较（C-2）；P2 三处新检查零回归保护（10.4）；
P3 `memcpy`（10.2）；P3 macOS 承诺（10.1）；P3 先 MAC 后 seq（C-1）。

**复核答复**：R2 落点 ✅（step 4 只有 `return BuildStep5`，`credssp.cpp:133-135`）；N-B1 `else`
分支 ✅ 原样（`:238-240`）；posix 的 EINTR/部分读取/仅 ENOSYS 降级 ✅（10.1）；S1 断言 ✅ 满足
我 §9.2 三条（`t:754` `n.size()==32`、`t:756` `k.size()==16`、`t:760-762` 任一窗口不等），
**并额外加了「非全零」「两两不同」—— 比我要求的更强**。
## 11. 三条补测复核（乙：独立复跑 + 变异 + 断言强度）

> 未改工程代码；变异全在 WSL 影子树 `.tmp/audit-b1/linux/mut`。手法同 §10.1：**整块删除**守卫
> （不加 `if(false)`，避免 C4189 掩盖结果）。g++ 13.3.0 `-std=c++20 -Wall -Wextra -Werror -Wpedantic`。

### 11.0 先纠正一个数字：你的 `vfy_b2` 是**旧版测试文件**
`vfy_b2/tests/test_credssp_sm.cpp` = 1005 行（sha `6a187032`），真实树 = 1042 行（sha `39453a54`）；
`vfy_b2/src/credssp/credssp.cpp` 与真实树**逐字节相同**（sha `abb7313e`）。差异只在测试：
旧版 `bad_sizes={0,24,31,33}`、只跑 version 6；现版 `{0,1,8,16,24,31,33,64}` + **v4 循环**。
所以 **`26/258` 与「D5 删除→0xC0000409」都来自旧文件**；现文件实测 **`26/312/0`**（Linux 与
Windows `build\verify` 一致）。312 = 205 + 107（新 3 例含循环展开）。**交付物本身没问题，是你的快照旧了。**

### 11.1 复核 1：独立复跑 → 26/312/0（双平台）

### 11.2 复核 2：逐条整块删除 → 只红自己，其余 25 条全绿

| 变异 | 结果 | 失败断言 |
|---|---|---|
| 删 D5 `c:153-155` | `1 failing / 24 failed checks` | `t:885/886/887`（= 8 尺寸 × 3） |
| 删 seq `c:423-426`（连 `seq` 声明） | `1 failing / 5 failed checks` | `t:962/963/965/966/967` |
| 删 version `c:415-418` | `1 failing / 5 failed checks` | `t:1018-1022` |

D5 的 24 个失败**全部来自 v4 循环**；v6 循环与两条对照仍绿 —— 证明判别力确实由 v4 循环提供，
与用例注释一致。**无 collateral**。

### 11.3 复核 3：断言强度足够；且不阻碍 §10.3 C-1 的重排建议

我实测「删 seq 检查 → 该报文**被接受**」（`ok=1`、`step5` 非空），故 `t:962 !e.ok()` 直接红：
用例验的是「删除即接受」，不是「换个错误」。**这比只断 status 更强**，符合 §10.4 要求。
额外做两个**重排变异**（检查挪到 MAC 之后）：`seq_nomac`、`ver_nomac` **均全绿** ——
说明用例没把「seq/version 必须先于 MAC」写成硬约束，故 P3 重排**不会**被这三条挡住。

### 11.4 复核 4：Linux g++ 13.3 全量 26/312/0，三条新用例跨平台同样通过。

### 11.5 特检 A：**你的「24 是唯一危险尺寸」模型错了**（重要）
全文件**只有一处** nonce 切片：`c:215 in.client_challenge.assign(nonce_.begin(), nonce_.begin()+8)`
—— 8 字节，**不存在 `[8..24)` 切片**。故危险尺寸是 **`n < 8`**，与 24 无关。
`_GLIBCXX_DEBUG`（≈ MSVC 迭代器调试）在 D5 已删的树上逐尺寸实测：

```
v4/v6 n=0,1,4,7 -> Aborted: "attempt to advance a past-the-end iterator 8 steps"
v4/v6 n=8,24,32 -> 正常返回（24 不崩）
```

现集合 `{0,1,8,16,24,31,33,64}` **已覆盖危险区**（0、1），覆盖充分；可选再加 `4`、`7`（危险区边界）。
另：`t:862` 注释「nonce = 0 and nonce = 4 aborted」**正确**，与我实测一致。

### 11.6 特检 B：确认「seq 错但 MAC 对」，seq 是**唯一**防线
`c:427-431` 的 MAC 输入用 `recv_seq_`（恒 0），不读 `field[12..16)`。改 `field[12]=1` 后 MAC 仍匹配 →
删 `c:423-426` 后报文**被接受**（实测 `ok=1`）。**不是「落到 MAC 失败」，而是唯一拦截点** —— 用例设计正确且必要。

### 11.7 特检 C：version 用例**有**对照组（`t:1024-1039`），与 seq 的 `t:969-984` 结构对称。
你的担忧不成立。

### 11.8 两条附带发现（P3，不阻塞）
1. **`c:275-277` 已是死代码**：D5 提前守卫后该分支内同款检查不可达（整块删除 → 仍 `26/312/0`）。
   保留作纵深防御可以，但需注释说明不可达，否则将来会被误认成唯一防线。
2. **D5 在 Linux release 下删除不崩溃，而是静默接受**：`nonce_` 容量仍 32（构造期分配），
   `begin()+8` 落在已分配区内 → 读到陈旧字节，`ok=1 step3=329`。故 D5 **同时是正确性守卫**
   （否则短 nonce 产出「能用但语义错」的 step 3），不止你说的内存安全边界。两种平台都能抓到
   （MSVC：abort；Linux release：status 不符）。

### 11.9 判定：三条补测**通过**
双平台 26/312/0；三条各自「整块删除→只红自己」无 collateral；断言强度达标（status+message+可判别性）；
三条都有对照组；两处**更正**（258→312 系你的旧快照；「24 危险」→ 实为 `n<8`）；两条 P3 记账。

