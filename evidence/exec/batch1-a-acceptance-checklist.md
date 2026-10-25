## 12. 执行 AI 验收清单（定案版）

> 本节的用途：执行 AI 改完后**逐条自检**，审计用同一份清单**复验**。
> 每条给：验收断言（给定-当-则 + 期望值）、变异后预期失败文本、易错点。
> **所有行号是改动前的行号**，以 §8.8 的文本锚点为准。

### 12.0 开工前必读（三条铁律）

1. **先写测试，再写实现**（doc:3262 的 8 步）。写完后必须**看到红**并记录输出，否则回到第 1 步。
2. **不许改现有 15 条测试**（H7 / doc:4201 N2）。特别是 `t:128` 那条名字带 `rejects_..._above_our_max` 的——它的实际断言只检查 `!e.ok()`，本次改动**不会**让它变红，**不要动它**。
3. **不许用 `clamp`**（doc:1794 已修正为 `min`）。若你写出 `std::clamp(req.version, ...)`，`server_version_is_echoed_back` 的第二组断言必红。

---

### 12.1 S1 —— `two_constructions_have_different_nonces`

**给定**
- 一个合法 CHALLENGE：`TsRequest{version=6, nego_token=ServerChallengeMessage()}`（`t:75-97` 的 fixture 可直接复用）
- 4 个独立的 `CredsspClient(TestCreds(), 6)`
- **不调用** `SetNonceForTest`（这是关键：生产路径必须是随机的）
- 调 `SetServerPublicKeyForTest(spk)`（避免 S18 守卫干扰）

**当**：每个 client 都 `Start` + `OnServerResponse(challenge)` 走到第 3 步

**则**（4 条断言，缺一不可）

| # | 断言 | 期望值 | 为什么需要 |
|---|---|---|---|
| 1 | `ExportedSessionKeyForTest().size()` | `== 16` | 尺寸正确性 |
| 2 | `Hex(k) != Hex(Bytes(16, 0))` | 真 | 抓「全零」（修复前签名） |
| 3 | 第 2~4 次构造的 `Hex(k) != Hex(prev)` | 真 | 抓「固定非零常量」或「只播种一次」 |
| 4 | 循环 4 次 | 全部通过 | 单次采样不足以排除碰撞 |

**变异后预期失败**

```
[ FAIL ] two_constructions_have_different_nonces
  FAIL test_credssp_batch1.cpp:531  Hex(k) != Hex(Bytes(16, 0))
  FAIL test_credssp_batch1.cpp:535  Hex(k) != Hex(prev)
20 tests, 155 checks, 1 failing tests, 7 failed checks
```

**易错点**
- ❌ 只断言「≠全零」→ 用 `i` 填充的固定序列能通过（我实测 `s1_rand_like` 变体，只挂 `Hex(k) != Hex(prev)`）。**必须两组都有**。
- ❌ 用 `rand()` / `std::random_device` / `mt19937`（doc:4205 N6 明令禁止）。必须 `BCryptGenRandom`（Win）/ `getrandom`（POSIX），并**检查返回值**。
- ❌ 把 `RandomBytes` 失败静默成 `nonce_.assign(kNonceSize, 0)` → 回到原缺陷。必须 `nonce_.clear()` + 让 D5 守卫拒绝。

---

### 12.2 S5 —— `version_below_min_is_rejected_with_valid_challenge`

**给定**
- `CredsspClient(TestCreds(), 6)`，`SetNonceForTest(FixedNonce())`，`SetServerPublicKeyForTest(spk)`
- `Start` 成功
- `TsRequest{version=1, nego_token=ServerChallengeMessage()}` ← **合法 CHALLENGE**，这是关键

**当**：`OnServerResponse`

**则**

| # | 断言 | 期望值 |
|---|---|---|
| 1 | `e.ok()` | `false` |
| 2 | `e.status` | `Status::kUnsupported` |
| 3 | `step3.empty()` | `true` |
| 4 | `c.complete()` | `false` |
| 5 | **控制组**：新 client 用 `version=6` 同一 CHALLENGE | `ok() == true` |

**为什么断言 5 必需**：排除「fixture 本身非法」导致假红。

**变异后预期失败**

```
[ FAIL ] version_below_min_is_rejected_with_valid_challenge
  FAIL :558  !e.ok()
  FAIL :559  e.status == Status::kUnsupported
  FAIL :560  step3.empty()
20 tests, 155 checks, 1 failing tests, 3 failed checks
```

**易错点**
- ❌ 用 `nego_token = FromHex("0011")`（像 `t:134` 那样）→ 失败点在 CHALLENGE 解析，**不是版本检查**，测试是假绿。必须用合法 CHALLENGE。
- ❌ 控制组复用**同一个 client**：`Fail()` 会把 `step_` 置 `kFailed`（`c:54`），第二次调用直接返回旧错误 → 控制组必假红。**必须用新 client**（我踩过这个坑）。
- ❌ 把检查写成 `req.version < kMinVersion || req.version > kMaxVersion` → 与 D2 定案冲突（会误杀 v7/v8）。**只拒下界**。

---

### 12.3 S6 —— `server_version_is_echoed_back`（**必须两组**）

**给定 A（服务器降版）**
- `CredsspClient(TestCreds(), 6)`，`SetNonceForTest(FixedNonce())`，`SetServerPublicKeyForTest(spk)`
- CHALLENGE `version=3`（合法 token）

**则 A**

| # | 断言 | 期望值 | 说明 |
|---|---|---|---|
| 1 | `req.version` | `== 3` | 回写生效 |
| 2 | `req.client_nonce.empty()` | `true` | v3 不发 nonce（`c:244` 的 `>= kFirstHashVersion` 为假） |
| 3 | `req.pub_key_auth.size()` | `== 16 + spk.size()` = **24**（spk 8 字节） | v3 走裸公钥路径（`c:234`） |
| 4 | `c.version()` | `== 3` | 公开 getter 同步 |

**给定 B（服务器版本高于客户端，唯一能区分 min/clamp 的方向）**
- `CredsspClient(TestCreds(), 4)`，CHALLENGE `version=6`

**则 B**

| # | 断言 | 期望值 | 说明 |
|---|---|---|---|
| 1 | `req.version` | `== 4` | **不能升级** ← clamp 在此得 6，必红 |
| 2 | `req.client_nonce.empty()` | `true` | v4 不发 nonce |
| 3 | `req.pub_key_auth.size()` | `== 16 + 8` = **24** | v4 走裸公钥 |
| 4 | `c.version()` | `== 4` | |

**变异后预期失败**

```
=== 删掉 version_ = std::min(...) ===
[ FAIL ] server_version_is_echoed_back
  FAIL :601  req.version == 3
  FAIL :602  req.client_nonce.empty()
  FAIL :603  req.pub_key_auth.size() == 16 + spk.size()
  FAIL :604  c.version() == 3
20 tests, 155 checks, 1 failing tests, 4 failed checks

=== 换成 std::clamp(req.version, kMin, kMax)（文档旧配方）===
[ FAIL ] server_version_is_echoed_back
  FAIL :622  req.version == 4
  FAIL :623  req.client_nonce.empty()
  FAIL :624  req.pub_key_auth.size() == 16 + spk.size()
  FAIL :625  c.version() == 4
20 tests, 155 checks, 1 failing tests, 4 failed checks
```

**注意**：`min` 变异红的是**第一组**（A），`clamp` 变异红的是**第二组**（B）。两组必须都在，否则区分不了「不回写」与「回写成错值」。

**易错点**
- ❌ 只写 A 组 → `clamp` 也能通过，测不出升级缺陷。
- ❌ 期望 `pka == 48`（v5+ 尺寸）→ v3/v4 路径是 `16 + len(spk)`。
- ❌ 用 `version_4_pubkeyauth_is_encrypted_public_key_not_hash`（`t:478`）代替 B 组 → 那条测试的 CHALLENGE 也是 `version=4`（`t:487`），客户端 4 + 服务器 4，`min` 和 `clamp` 都得 4，**区分不了**。必须客户端 4 + 服务器 **6**。

---

### 12.4 S11 —— `tampered_signature_checksum_is_rejected`

**给定**
- 正常走到第 3 步（client 6 + 合法 CHALLENGE）
- `echo = c.MakeServerEchoForTest()`
- **`echo[4] ^= 0xFF;`** ← 只翻转 signature 的 checksum 首字节（`field[4..12)` 是 checksum）

**当**：把篡改后的 echo 作为 `step4.pub_key_auth`，调 `OnServerResponse`

**则**

| # | 断言 | 期望值 |
|---|---|---|
| 1 | `e.ok()` | `false` |
| 2 | `e.status` | `Status::kMalformed` |
| 3 | `step5.empty()` | `true` |
| 4 | `c.complete()` | `false` |
| 5 | **控制组**：新 client 用**未篡改**的 echo | `ok() == true` 且 `complete() == true` |

**为什么必须篡改 checksum 而不是密文**：篡改密文会改变明文 → 第 4 步的回显比对（`c:283`）本来就会拒绝。那样测的是「回显比对」而非「MAC 校验」。只有篡改 checksum（明文不变 → 回显仍匹配）才能隔离出 MAC 缺失。

**变异后预期失败**

```
[ FAIL ] tampered_signature_checksum_is_rejected
  FAIL :656  !e.ok()
  FAIL :657  e.status == Status::kMalformed
  FAIL :658  step5.empty()
  FAIL :659  !c.complete()
20 tests, 155 checks, 1 failing tests, 4 failed checks
```

**易错点（这条最容易做错）**
- ❌ **用 `signing_key_` 算 MAC**（doc:1799 的字面意思）→ **所有** step5 用例全红。接收方向必须 `DeriveSigningKey(exported_session_key_, true)`。我按文档实现时实测红了两条：`step5_sends_authinfo_only`、`authinfo_plaintext_is_tscredentials_with_credentials`。
- ❌ **先解 checksum 再解消息**（顺序反了）→ RC4 流错位，正常 echo 也被拒。必须与 `SealSend`（`c:318-329`）对称：**先解消息密文，再用同一流解 checksum**。
- ❌ 用**新的 RC4 实例**解 checksum → `ntlm.cpp:404-406` 的注释明确警告过这是最常见的实现错误。
- ❌ 忘了把 `++recv_seq_` 移到校验之后 → 校验失败时序列号已被推进（语义错误，虽不影响当前用例）。
- ❌ 篡改 `echo[20]`（像 `t:338` 那样）→ 那是密文，被回显比对拦住，测不出 MAC。

---

### 12.5 S18 —— `start_without_public_key_fails`

**给定**
- `CredsspClient(TestCreds(), 6)`，`SetNonceForTest(FixedNonce())`
- **不调用任何公钥 setter**
- `Start` 后喂合法 CHALLENGE

**则**

| # | 断言 | 期望值 |
|---|---|---|
| 1 | 若 `Start` 失败：`se.status == kUnsupported` 且 `out.empty()` | 允许（实现可选在 Start 拒绝） |
| 2 | 否则 `OnServerResponse` 返回 `!ok()` | 必须 |
| 3 | `e.status` | `Status::kUnsupported` |
| 4 | `step3.empty()` | `true` |
| 5 | `c.complete()` | `false` |

**断言 1 的写法说明**：定案是「`BuildStep3` 入口检查」，所以正常情况下 `Start` 会成功、`OnServerResponse` 失败。但为了不把实现绑死在一个位置，测试写成「任一处失败且状态正确」即可。**但绝不允许两处都成功。**

**变异后预期失败**

```
[ FAIL ] start_without_public_key_fails
  FAIL :702  !e.ok()
  FAIL :703  e.status == Status::kUnsupported
  FAIL :704  step3.empty()
20 tests, 155 checks, 1 failing tests, 3 failed checks
```

**易错点**
- ❌ **把守卫放进 `Start()`**（doc:1806 旧写法）→ 原 15 条里 3 条（`t:110`、`t:359`、`t:381`）会红，且进程 `exit 0xC0000409`（我实测）。必须放 `BuildStep3`。
- ❌ 只加 setter 不加守卫 → 缺陷仍在（空公钥静默产生 `SHA256(magic‖nonce‖"")`）。
- ❌ 把 `SetServerPublicKeyForTest` 删掉 → 原 15 条里 10 处调用会编译失败。**两个 setter 都要留**。
- ❌ 用 `if (server_public_key_.size() == 0)` 之外的条件（比如校验长度）→ 过度约束，`t:149` 用的是 8 字节假 SPK。

---

### 12.6 D1–D6 同场交叉验证（**这是最容易漏的部分**）

以下是我静态推演出的相互影响，执行 AI 必须逐条确认。

#### 交叉 1：D1 的 `min` 在**第 4 步也会执行**（重要）

`OnServerResponse` 是第 2 步和第 4 步共用的入口（`c:107-112` 按 `step_` 分派）。所以版本回写代码在第 4 步会**再跑一次**。

**推演结果（`min` 幂等）**：

| client | 第2步 req.version | 第4步 req.version | 第2步后 `version_` | 第4步后 `version_` | 结论 |
|---|---|---|---|---|---|
| 6 | 3 | 6 | 3 | **3** | 幂等，安全 |
| 6 | 3 | 3 | 3 | 3 | 幂等 |
| 4 | 6 | 6 | 4 | 4 | 幂等 |
| 6 | 7 | 7 | 6 | 6 | 幂等 |

**结论**：`min` 天然幂等，第 4 步重复回写**无害**。这是 `min` 优于 `clamp` 的又一个理由（`clamp` 在第 4 步会把 v3 拉回…不会，clamp(3,2,6)=3，也幂等；但 clamp 在「客户端 4 + 服务器 6」场景第 2 步就错了）。

**但**：D2 的下界检查在第 4 步也会执行，**新增一个拒绝点**：

| 场景 | 修复前 | 定案后 |
|---|---|---|
| 第 4 步 req.version=1 | 继续（无检查） | **`kUnsupported` 拒绝** |

**验收**：这是**行为变更**，但没有现有测试覆盖第 4 步的低版本。建议执行 AI 确认 `step5_sends_authinfo_only`（`t:283`）用的 `step4.version = 6`（`t:300`）→ 不受影响。

#### 交叉 2：D6 的顺序 vs D5 的守卫位置

两处守卫在**不同函数**，不冲突：

| 检查 | 位置 | 顺序约束 |
|---|---|---|
| errorCode（`c:97`） | `OnServerResponse` | 必须在版本检查**之前** |
| D2 下界 | `OnServerResponse` | 在 errorCode **之后**、分派之前 |
| D1 `min` 回写 | `OnServerResponse` | 紧接 D2 之后 |
| S18 公钥 | `BuildStep3` 入口 | 在 D5 **之前** |
| D5 nonce 尺寸 | `BuildStep3` 入口 | 在 S18 之后、`nego_token.empty()` 之前 |

**为什么 S18 在 D5 之前**：公钥缺失是配置错误（更根本），nonce 尺寸是内部不变量。先报配置错误更易诊断。**顺序不影响正确性，但影响错误信息质量**。

#### 交叉 3：D5 的提前守卫 vs S5 的版本检查

**不冲突**，但在「短 nonce + 低版本」同时出现时，**先报哪个错**：

- 版本检查在 `OnServerResponse`（早）
- nonce 检查在 `BuildStep3`（晚）

→ 低版本 + 短 nonce → 报 `unsupported TSRequest version`。合理（版本是外部输入，优先）。

**但注意**：`c:229` 的原有 nonce 检查**保留**（在 `version_ >= kFirstHashVersion` 分支内）。D5 的新守卫在它之前，所以 v2/3/4 路径也受保护（原来完全没保护，因为 `c:229` 在 `if` 里）。

**验收**：`version_4_pubkeyauth_is_encrypted_public_key_not_hash`（`t:478`，客户端 4）必须仍绿——它用 32 字节 nonce，D5 守卫不触发。

#### 交叉 4：S11 的 `recv_seq_` vs `MakeServerEchoForTest`

`MakeServerEchoForTest`（`c:387`）用 `recv_seq_` 签名，`OpenReceive` 校验 `field[12..16)` 是否 `== recv_seq_`，通过后 `++recv_seq_`。

**自洽性**：echo 用 seq=0 签 → `OpenReceive` 期望 0 → 通过 → `recv_seq_` 变 1。若后续还有第 4 步消息（协议上没有），期望 1。**一致**。

**验收**：`step5_sends_authinfo_only` 与 `authinfo_plaintext_...` 必须绿。若红，先查签名密钥方向（D4）和 RC4 流顺序。

#### 交叉 5：S1 的随机 nonce vs S11 的密钥派生

`nonce_[8..24)` → `exported_session_key_`（`c:191`）→ `recv_signing_key`（S11）。

**无冲突**：nonce 随机化后，所有派生密钥都随机，S11 的 MAC 校验照常工作。

**但**：`two_constructions_have_different_nonces` 与 `tampered_signature_checksum_is_rejected` 都用 `SetNonceForTest(FixedNonce())`，所以**互不干扰**。

---

### 12.7 执行 AI 容易做错的地方（汇总）

| # | 错误 | 后果 | 正确做法 |
|---|---|---|---|
| 1 | 用 `std::clamp(req.version, ...)` | `server_version_is_echoed_back` B 组红 | `std::min(version_, req.version)` |
| 2 | 版本检查写成双边 | 误杀 v7/v8；与 D2 冲突 | 只 `< kMinVersion` |
| 3 | 公钥守卫放 `Start()` | 3 条原测试红 + `0xC0000409` 崩溃 | 放 `BuildStep3` |
| 4 | S11 用 `signing_key_` | 所有 step5 用例红 | `DeriveSigningKey(..., true)` |
| 5 | S11 先解 checksum 再解消息 | 正常 echo 被拒 | 与 `SealSend` 对称 |
| 6 | S11 用新 RC4 实例解 checksum | 同上 | 复用 `recv_rc4_` |
| 7 | 篡改密文而非 checksum 做红证 | 测的是回显比对，假红 | 篡改 `field[4]` |
| 8 | 版本检查放在 errorCode 之前 | `native_code` 丢成 0 | errorCode 优先 |
| 9 | 用 `nego_token="0011"` 测 S5 | 假绿（失败在 token 解析） | 合法 CHALLENGE |
| 10 | 控制组复用同一个 client | 假红（`Fail` 会锁死状态机） | 新 client |
| 11 | 只测「≠全零」 | 固定非零常量能通过 | 加「两两不同」 |
| 12 | 用 `rand()`/`random_device` | 违反 doc:4205 N6 | `BCryptGenRandom`/`getrandom` |
| 13 | `RandomBytes` 失败时填零 | 回到原缺陷 | `nonce_.clear()` + D5 守卫 |
| 14 | 删掉 `SetServerPublicKeyForTest` | 原 15 条编译失败 | 两个 setter 都留 |
| 15 | 改 `t:128` 那条测试 | 违反 H7 | 不动它，新增用例 |
| 16 | 只写 S6 的 A 组 | `clamp` 也能过 | 必须加 B 组（client 4 + server 6） |
| 17 | 忘加 `#include <utility>`（`std::move`） | `/W4 /WX` 下编译失败 | 加到 `credssp.h` |
| 18 | 忘在 CMake 加 `src/crypto/random.cpp` | 链接失败 | 改 `rtsc_crypto` 源列表 + `bcrypt` |

---

### 12.8 最终验收门禁（执行 AI 自检 + 审计复验）

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
cmd /c F:\rtsc\.tmp\build_tls.bat
if ($LASTEXITCODE -ne 0) { throw "BUILD FAILED" }     # /W4 /WX 零警告

$suites = @{ 'rtsc_credssp_sm_tests'=20; 'rtsc_ntlm_tests'=27; 'rtsc_credssp_tests'=23 }
foreach ($k in $suites.Keys) {
    $o = (& "F:\rtsc\build\verify\$k.exe" | Out-String)
    if ($o -notmatch '0 failing tests, 0 failed checks') { throw "$k FAILED:`n$o" }
    $n = [int]([regex]::Match($o,'(\d+) tests').Groups[1].Value)
    if ($n -lt $suites[$k]) { throw "$k ONLY $n TESTS" }
    Write-Output "$k = $n tests (>= $($suites[$k]))"
}
```

**判据**

| 套件 | 门槛 | 说明 |
|---|---|---|
| `rtsc_credssp_sm_tests` | **≥ 20**（15 原 + 5 新） | 若加了 §4.6 的 2 条则 ≥ 22 |
| `rtsc_ntlm_tests` | **= 27** | 零改动，数字必须不变 |
| `rtsc_credssp_tests` | **= 23** | 零改动，数字必须不变 |

**红证留档要求**：5 条变异逐条做，每条记录「用例名 + 断言文本 + 实际读数」，格式见 doc:3272-3275。**不接受「大概会失败」**（doc:3277）。

---

### 12.9 与 §8 的对应关系

| 验收项 | 对应定案 |
|---|---|
| §12.1 | §8.6（D5）+ §3.1（S1） |
| §12.2 | §8.3（D2）+ §8.6（D6） |
| §12.3 | §8.2（D1） |
| §12.4 | §8.5（D4） |
| §12.5 | §8.4（D3） |
| §12.6 | 交叉验证（本节新增） |
| §12.7 | 易错点汇总（本节新增） |
