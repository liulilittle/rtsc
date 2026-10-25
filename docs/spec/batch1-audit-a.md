# 批 1 组 · 审计甲独立审计报告（Phase 1 + 定案）

**审计 AI**: 甲（audit A）  
**搭档**: `ses_e9806f3f9ffeG7HMFgYVsLD2uC`（乙，阶段 2 互审中）  
**工程**: `F:\rtsc` · C++17 · MSVC 14.44 · Ninja · `/W4 /WX`  
**批次范围**: S1 S5 S6 S11 S18（doc:3764-3798）  
**规范**: `docs/spec/security-integration.audit-a.md`  
**方法**: 只读 + 影子树（`F:\rtsc\.tmp\audit-batch1`）。**未修改任何生产或测试文件。**  
**状态**: 阶段 1 已收讫；D1–D6 已由主代理裁决，见 **§8 定案**。

---

## 0. 结论摘要

| 缺陷 | 真实？ | 证据类型 | 我的推荐 | 红证 |
|---|---|---|---|---|
| **S1** nonce 恒零 | **真实** | 探针 P1 + 变异 | 方案 B（`RandomBytes` + 提前尺寸守卫） | ✅ 7 failed checks |
| **S5** 版本不校验 | **真实** | 探针 P2 + 变异 | 只拒绝**下界**（**D2 定案**） | ✅ 5 failed checks |
| **S6** 版本不回写 | **真实** | 探针 P3 + 变异 | `std::min`（**D1 定案**），**收窄到 `kAwaitChallenge`** | ✅ 4 failed checks |
| **S11** 不验 MAC | **真实** | 探针 P4 + 变异 | **server-to-client** 签名密钥（**D4 定案**） | ✅ 4 failed checks |
| **S18** 无生产公钥 | **真实** | 探针 P5 + TLS 实测 | 生产 setter + `BuildStep3` 入口 fail-closed（**D3 定案**） | ✅ 3 failed checks |
| **N-B1** nonce 泄露会话密钥 | **真实**（乙报，我核实） | 代码链 + 规范 | exported key 独立随机（**主代理裁决并入批 1**） | 见 §12.1b |

**与主代理预检的差异**：预检 5 条全部复验通过。但我发现**文档给的 S5/S6 配方本身有 2 个缺陷**（见 §3.2、§3.3），且**S1 的修复会引入栈溢出崩溃**（见 §3.1）。这三点均已由主代理裁决采纳（§8）。

**阶段 2 增量**（见 §13）：乙报出 **N-B1（P0）**——`exported_session_key_` 取自 `nonce[8..24)`，而整个 nonce 明文发出，导致口令可被解密。我独立核实**成立且比乙描述的更严重**（被动窃听即可，不需 MITM）。主代理已裁决并入批 1。

---

## 1. 基线复验（不采信主代理）

```
$ python F:\rtsc\evidence\exec\batch1_preflight.py
S1   PRESENT c:46   'nonce_.assign(kNonceSize, 0);'
S5   PRESENT c:42/43 版本边界只在构造函数
S5b  ABSENT  无 server-version 校验
S6   ABSENT  server version 从不回写 version_
S18  ABSENT  无生产路径写 server_public_key_
RESULT: batch 1 is executable
```

三个基线套件（**修复前**）：

```
rtsc_credssp_sm_tests => 15 tests, 92 checks, 0 failing
rtsc_ntlm_tests       => 27 tests, 136 checks, 0 failing
rtsc_credssp_tests    => 23 tests, 69 checks, 0 failing
```

证据：`evidence/exec/batch1-a-audit-probe.txt`、`batch1-a-audit-orig15-green.txt`

---

## 2. 缺陷逐条：真实性与根因

### 2.1 S1 —— nonce 恒零（P0）

**代码**（`src/credssp/credssp.cpp:44-46`）：

```cpp
    // A deterministic-looking default keeps the nonce length valid even if the
    // caller forgets to set one; production code always overrides it.
    nonce_.assign(kNonceSize, 0);
```

注释声称「production code always overrides it」——**全仓无任何生产代码调用 `SetNonceForTest`**（grep 只命中 `tests/test_credssp_sm.cpp` 的 12 处）。所以该注释是空头承诺。

**为什么是缺陷（不只看文档）**：`nonce_` 被两处消费，且都在安全关键路径上：

- `c:176` `in.client_challenge.assign(nonce_.begin(), nonce_.begin() + 8);` → NTLMv2 ClientChallenge
- `c:191` `exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);` → 会话密钥

全零 → ClientChallenge 与 ExportedSessionKey 双双固定 → 派生出的 SigningKey/SealingKey 固定。

**探针实测**（`batch1-a-audit-probe.txt`）：

```
P1/S1 exported_key_1=00000000000000000000000000000000
P1/S1 exported_key_2=00000000000000000000000000000000
P1/S1 identical=YES(defect)
```

**注意**：握手确实「成功」——这正是危险点（静默失去机密性，无任何错误信号）。与 doc:1874 一致，我实测确认。

---

### 2.2 S5 —— 服务端版本从不校验（P1）

**代码**（`c:91-113`）：`req.Decode` 成功后直接进 `BuildStep3`，`req.version` 从未被读取。

**为什么现有「拒绝 version 1」测试是假绿**（`tests/test_credssp_sm.cpp:128-140`）：

```cpp
    TsRequest bad;
    bad.version = 1;
    bad.nego_token = FromHex("0011");     // ← 非法 CHALLENGE
```

失败点在 `BuildStep3` 的 `msg.Decode`（`c:123`），**不是**版本检查。

**探针实测**（合法 CHALLENGE + version=1）：

```
P2/S5 version=1 ok=1 status=0 msg= step3=389     ← 完全通过，缺陷确认
```

**上界实测**（`batch1-a-audit-version-range.txt`，修复前）：

```
peer_version=0    ok=1  step3_version=6
peer_version=1    ok=1  step3_version=6
peer_version=7    ok=1  step3_version=6
peer_version=100  ok=1  step3_version=6
```

**← 这里有个必须裁决的矛盾**：现有测试**名字**叫 `step1_rejects_server_version_above_our_max`（`t:128`），但同一处**注释**写「A peer claiming a newer version must be treated as the highest we understand, **not rejected**」（`t:129-130`）。名字与注释互相矛盾，且**当前实现两条都没做**（既不拒绝也不钳制，直接忽略）。

---

### 2.3 S6 —— 服务端版本不回写（P1）

**代码**：`c:241` 和 `c:300` 都是 `req.version = version_;`，而 `version_` 只在构造器赋值（`c:41`）。全文件**无** `version_ = req.version`。

**探针实测**（`batch1-a-audit-probe.txt`）：

```
P3/S6 ok=1 decoded=1 step3_version=6 client_nonce_len=32 pub_key_auth_len=48 client_version_after=6
```

服务器回 version=3，客户端仍发 version=6 + 32 字节 nonce + 48 字节 pubKeyAuth（v5+ 路径）。**应为** version=3 + 无 nonce + 24 字节（`16 + len(spk)`）。

**下游影响**：`:241`/`:300` 两处自动跟随；`MakeServerEchoForTest`（`c:364`）也用 `version_`，所以测试侧会同步变化。第 3/5 步的 `clientNonce` 是否发送由 `c:244` 的 `version_ >= kFirstHashVersion` 决定——这是行为分叉点。

---

### 2.4 S11 —— OpenReceive 只解密不验 MAC（P1）

**代码**（`c:347-362`）：

```cpp
    const Bytes ciphertext(field.begin() + static_cast<ptrdiff_t>(kSignatureSize),
                           field.end());
    plaintext = recv_rc4_.Apply(ciphertext);
    ++recv_seq_;
    return Ok();          // ← signature[0..16) 从未被读取
```

对照发送侧 `SealSend`（`c:318-343`）确实写了完整 16 字节签名：`Version(4) | Checksum(8) | SeqNum(4)`。接收侧把这 16 字节整个跳过。

**探针实测**（只翻转 checksum 字节 `field[4]`，密文不动）：

```
P4/S11 tampered_checksum ok=1 status=0 msg= complete=1 step5=88    ← 完全察觉不到
```

**为什么必须篡改 checksum 而非密文**（关键设计点）：doc:1799 自己也点明了——篡改密文会被第 4 步的**回显比对**（`c:283`）拦住，因此那样的用例无法区分「MAC 校验」与「回显比对」。只有篡改 checksum（回显明文不变）才能隔离出 MAC 缺失。

**我的额外发现（文档没说）**：接收方向必须用 **server-to-client** 签名密钥。`signing_key_`（`c:196`）是 client-to-server，直接复用会让**所有正常 echo 被拒**。我用变异实测确认了这一点（见 §3.4）。

---

### 2.5 S18 —— 生产路径永远拿不到公钥（P0）

**代码**：`server_public_key_` 的**唯一**写入点是 `credssp.h:61`：

```cpp
    void SetServerPublicKeyForTest(const Bytes& spk) { server_public_key_ = spk; }
```

grep 全仓 `server_public_key_`：读点 7 处（`c:232/234/267/269/369/371/410`），写点 1 处（测试钩子）。

**探针实测**（完全不调 setter）：

```
P5/S18 start_ok=1 step3_ok=1 status=0 msg= pub_key_auth_len=48
P5/S18 plaintext==SHA256(magic||nonce||EMPTY)=YES(defect)
```

即 `pubKeyAuth = SHA256(magic ‖ nonce ‖ "")`，且**不报错**。

#### S18 核心问题：生产路径的公钥从哪里来？

**答案：TLS 层已有现成接口，且返回的字节正是 CredSSP 需要的。**

接口签名（`include/rtsc/net/tls.h:170`）：

```cpp
    // SubjectPublicKey only, taken straight from CERT_PUBLIC_KEY_INFO.PublicKey.
    // Never slice it out of the SPKI at a fixed offset: the offset differs
    // between key sizes (measured 24 for RSA-2048, 22 for RSA-1024).
    virtual Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const = 0;
```

实现（`src/net/tls_schannel.cpp:371-384`）直接取 `cert->pCertInfo->SubjectPublicKeyInfo.PublicKey` 的 `pbData/cbData`。

**我实测验证了字节语义**（`batch1-a-audit-spk.txt`，真实 SChannel 回环握手）：

```
handshake_complete=1
spki   : 162 bytes  first12=30819f300d06092a864886f7
pubkey : 140 bytes  first12=30818902818100bc163c6095
der: spki_len=159 bit_len=141 unused_bits=0 have_bit=1
bitstring_contents: 140 bytes  first12=30818902818100bc163c6095
pubkey == bitstring_contents : YES
pubkey begins_with_unused_bits_octet: NO
pubkey found verbatim inside spki: YES
pubkey offset in spki = 22
```

**结论（可执行的）**：

1. `PeerSubjectPublicKey()` 返回 **140 字节**，与 DER 里 BIT STRING 去掉 unused-bits 字节后的内容**逐字节相等** → 正是 `security-layer.md:699-703` 要求的 `RSAPublicKey` DER（以 `30 81 89` 开头）。
2. **没有**多带 unused-bits 字节（首字节是 `0x30` 而非 `0x00`）→ 不需要额外切片。
3. 在 SPKI 内偏移 **22**（RSA-1024 场景），与 `tls.h:168-169` 注释「measured 24 for RSA-2048, 22 for RSA-1024」一致 → 印证了「不可用固定偏移」的警告。

**谁实现接线**：批 3 的 `SecurityLayer`（doc:2478-2485）。接口已存在，缺的只是调用点。批 1 只需提供生产 setter + fail-closed 检查。

---

## 3. 修复方案（每条 ≥2 候选 + 实测取舍）

> 所有实验都在 `F:\rtsc\.tmp\audit-batch1\shadow` 完成；参考实现已导出到 `evidence/exec/batch1-a-fixed-credssp-reference.cpp`。

### 3.1 S1：随机 nonce

**方案 A（最小）**：

```cpp
// credssp.cpp:46 替换
if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();
```

新增 `include/rtsc/crypto/random.h` + `src/crypto/random.cpp`（放 `rtsc_crypto`，**不能放 `rtsc_security`**，否则 `rtsc_credssp` 反向依赖；doc:1789 已注明）。实现 `BCryptGenRandom` / `getrandom`，失败返回 false。

**方案 B（推荐 = A + 提前守卫）**：

```cpp
// BuildStep3 开头，所有切片之前
if (nonce_.size() != kNonceSize) {
    return Fail(Status::kUnsupported, "nonce must be 32 bytes");
}
```

#### 为什么必须有 B —— 我实测到一个崩溃（文档未提）

现有唯一尺寸检查在 `c:229`，位于 `BuildStep3` 中段，且**在 `c:176`/`c:191` 的切片之后**，还嵌在 `version_ >= kFirstHashVersion` 分支里。所以短 nonce 会先越界。

实测（`batch1-a-audit-short-nonce.txt`，未修复的库）：

```
nonce=0   exit=-1073740791   ← 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN, /GS)
nonce=4   exit=-1073740791   ← 0xC0000409
nonce=16  exit=3             ← 0x80000003 (断点/调试断言)
nonce=23  exit=3
nonce=24  exit=0  step3_ok=0 status=3 msg='nonce must be 32 bytes'
nonce=31  exit=0  step3_ok=0 status=3 msg='nonce must be 32 bytes'
nonce=32  exit=0  step3_ok=1 status=0 out=389
```

**这意味着**：如果只做方案 A，一旦 CSPRNG 失败（`nonce_.clear()` → size 0），进程**不是优雅失败而是直接崩溃**。方案 B 把这个失败变成可诊断的 `kUnsupported`。

**对下游的影响**：
- 原 15 条测试全部先调 `SetNonceForTest(FixedNonce())`（32 字节）→ 不受影响。实测：**15/92 全绿**（`batch1-a-audit-orig15-green.txt`）。
- `nonce=40` 等非 32 值：修复前走 `c:229` 拒绝，修复后走新守卫拒绝，行为等价（状态码都是 `kUnsupported`）。

---

### 3.2 S5：版本校验 —— **只拒下界**（**D2 已定案**，见 §8.3）

**文档方案（doc:1793）**：`if (req.version < kMinVersion || req.version > kMaxVersion) return Fail(kUnsupported, ...)`

**问题**：这会拒绝 version=7/8 的服务器。而 `security-layer.md:236` 实测「客户端发 1..8，服务器始终回 6」——说明**现实中 peer 可能声明高于我们的版本**，此时按 `[MS-CSSP]` 应「按我们理解的最高版本处理」，而非拒绝。现有测试 `t:129-130` 的注释也正是这个意思。

**我的方案**：

```cpp
if (req.version < kMinVersion) {
    return Fail(Status::kUnsupported, "unsupported TSRequest version");
}
version_ = std::min(version_, req.version);   // S6，上界在此自然被吸收
```

**两种策略的实测对比**（`batch1-a-audit-version-range.txt` + 影子探针）：

| peer_version | 文档策略（拒双边） | 我的策略（只拒下界） | 判定 |
|---|---|---|---|
| 0, 1 | `kUnsupported` | `kUnsupported` | 一致 |
| 2 | 用 v2（pka=24） | 用 v2（pka=24） | 一致 |
| 4 | 用 v4（pka=24） | 用 v4（pka=24） | 一致 |
| 6 | 用 v6（pka=48） | 用 v6（pka=48） | 一致 |
| **7, 8, 100** | **拒绝** | **按 6 处理**（pka=48） | **分歧** |

**裁决建议：采纳「只拒下界」**。理由：
1. 前向兼容——新服务器声明 v7 时不应让客户端直接失败；
2. 与 `t:129-130` 的既有注释一致；
3. 与 `[MS-CSSP]` 的版本协商语义一致（`version` 是 peer 的最高支持版本，不是命令）。

**代价（必须承认）**：现有测试名 `step1_rejects_server_version_above_our_max` 会名不副实。按 H7/N2 **不许改测试让它通过**，所以**不改这条测试**，而是新增 `version_above_max_is_capped_not_rejected` 明确锁定新语义。原测试本身不断言上界（它用 `nego_token="0011"`，失败在 token 解析），所以**改实现不会让它变红**——实测确认 15/92 仍全绿。

---

### 3.3 S6：版本回写 —— **`min` 不是 `clamp`**（**D1 已定案**，见 §8.2）

**文档方案（doc:1794）**：`version_ = std::clamp(req.version, kMinVersion, kMaxVersion);`

**实测证明 clamp 会引入新缺陷**（我在影子树里把 `min` 换成 `clamp`）：

```
[ FAIL ] server_version_is_echoed_back
  FAIL test_credssp_batch1.cpp:622  req.version == 4
  FAIL test_credssp_batch1.cpp:623  req.client_nonce.empty()
  FAIL test_credssp_batch1.cpp:624  req.pub_key_auth.size() == 16 + spk.size()
  FAIL test_credssp_batch1.cpp:625  c.version() == 4
20 tests, 155 checks, 1 failing tests, 4 failed checks
```

**根因**：`clamp` 取的是**服务器版本**，会把客户端**升级**。构造时 `CredsspClient(creds, 4)`（用户显式要 v4），服务器回 6，clamp 得到 6 → 客户端改用 v5+ 的哈希路径 + 发 clientNonce。这违背了调用者的显式选择。

**我的方案**：

```cpp
version_ = std::min(version_, req.version);
```

即「协商版本 = min(客户端版本, 服务器版本)」——这是 CredSSP 的正确语义，且**永不升级**。

**实测覆盖**（`server_version_is_echoed_back` 两个方向）：

| 客户端 | 服务器 | 期望 step3 version | 期望 nonce | 期望 pka | min 结果 |
|---|---|---|---|---|---|
| 6 | 3 | 3 | 空 | 16+8=24 | ✅ |
| 4 | 6 | **4** | 空 | 16+8=24 | ✅（clamp 在此失败） |

**对下游的影响**：`c:241`、`c:300`、`c:244`、`c:228`、`c:266`、`MakeServerEchoForTest`（`c:368`）全部自动跟随，无需逐个改。

---

### 3.4 S11：MAC 校验 —— 必须用 server-to-client 密钥

**方案 A（文档 doc:1799 的字面意思）**：用 `signing_key_` 重算 HMAC。

**实测结果：错误。** 我最初按文档实现，结果**所有正常用例全红**：

```
[ FAIL ] step5_sends_authinfo_only
[ FAIL ] authinfo_plaintext_is_tscredentials_with_credentials
```

**根因**：`signing_key_ = DeriveSigningKey(exported_session_key_, false)`（`c:196`）是 **client-to-server** 方向。第 4 步是**服务器发来**的消息，签名用的是 server-to-client 密钥。

**方案 B（推荐，已实测绿）**：

```cpp
// OpenReceive，解密文之后
const Bytes checksum = recv_rc4_.Apply(Bytes(field.begin() + 4, field.begin() + 12));
if (field[0] != 0x01 || field[1] != 0x00 || field[2] != 0x00 || field[3] != 0x00) {
    return Fail(Status::kMalformed, "sealed field unsupported version");
}
const uint32_t seq = ...field[12..16) little-endian...;
if (seq != recv_seq_) {
    return Fail(Status::kMalformed, "sealed field out of sequence");
}
// 接收方向签名密钥
const Bytes recv_signing_key = DeriveSigningKey(exported_session_key_, true);
const auto hmac = crypto::HmacMd5(recv_signing_key.data(), recv_signing_key.size(),
                                  mac_input.data(), mac_input.size());
if (checksum != Bytes(hmac.begin(), hmac.begin() + 8)) {
    plaintext.clear();
    return Fail(Status::kMalformed, "sealed field MAC mismatch");
}
```

**顺序必须与 `SealSend` 对称**（`c:318-329`）：先解消息密文，再用**同一 RC4 流**解 checksum。`ntlm.cpp:404-416` 的 `Seal` 注释明确警告过「fresh RC4 instance for the checksum is the single most common implementation mistake」。

**额外收益**：顺带加了 version 与 seq 校验。`recv_seq_` 原本只 `++` 从不校验（`c:360`），意味着重放/乱序完全不被发现。

**对下游的影响**：`step5_sends_authinfo_only` 等依赖 `MakeServerEchoForTest()`（它用 `Seal(seal, sign, ...)`，`c:384-387` 的 `sign = DeriveSigningKey(..., true)`）→ 天然带正确 MAC。实测 **21/164 全绿**。

---

### 3.5 S18：公钥注入 —— 位置决定成败

**方案 A（文档 doc:1806 允许的两种位置之一）：`Start()` 入口检查**

**实测：不可行。** 我把它放进 `Start()`：

```
[ RUN  ] step1_emits_version_and_negotiate_token_only
  FAIL test_credssp_sm.cpp:110  client.Start(out).ok()
  FAIL test_credssp_sm.cpp:113  req.Decode(...).ok()
  FAIL test_credssp_sm.cpp:115  !req.nego_token.empty()
  FAIL test_credssp_sm.cpp:117  req.nego_token.size() == 40
→ 进程崩溃 (exit 0xC0000409)，后续 14 条测试从未运行
```

**根因**：原 15 条测试中有 **3 条**调用 `Start()` 但从不设置公钥：

| 测试 | 行 | 为什么不设公钥 |
|---|---|---|
| `step1_emits_version_and_negotiate_token_only` | `t:110` | 第 1 步不涉及公钥 |
| `error_code_aborts_with_server_status` | `t:359` | 测 errorCode 分支，不需要公钥 |
| `error_code_is_checked_before_any_token_processing` | `t:381` | 同上 |

按 H7/N2 **不能改这 3 条测试**。所以 `Start()` 检查会直接违反「15 条全绿」的验收判据。

**方案 B（推荐）：`BuildStep3` 入口检查** —— 实测 **15/92 全绿**，且 `start_without_public_key_fails` 能红。

```cpp
Error CredsspClient::BuildStep3(const TsRequest& challenge, Bytes& out) {
    if (server_public_key_.empty()) {
        return Fail(Status::kUnsupported, "server public key not set");
    }
    if (challenge.nego_token.empty()) { ... }
```

**为什么语义上也更对**：公钥来自 TLS 握手，在 `Start()`（发第 1 步）时**确实还没有**；直到收到第 2 步（CHALLENGE）后才需要它。`Start()` 只是发 NEGOTIATE，不消费公钥。在 `BuildStep3` 检查是「首次使用点」，符合 fail-closed 且不误伤。

**新增生产 setter**（`credssp.h`，`SetServerPublicKeyForTest` 之上）：

```cpp
    // Production injection point (S18). The owner of the TLS transport must pass
    // TlsTransport::PeerSubjectPublicKey() here immediately after the handshake
    // completes. Deliberately not optional: BuildStep3 fails closed when unset,
    // because an empty key silently reduces pubKeyAuth to SHA256(magic||nonce||"").
    void SetServerPublicKey(Bytes spk) { server_public_key_ = std::move(spk); }
```

需在 `credssp.h` 增加 `#include <utility>`（为 `std::move`）。

**接线点（批 3 的 SecurityLayer）**：

```cpp
// TLS 握手完成后，创建 CredsspClient 之前
std::vector<uint8_t> spk;
Error e = tls->PeerSubjectPublicKey(spk);          // include/rtsc/net/tls.h:170
if (!e.ok()) return /* kUnsupported + 原因 */;
credssp.SetServerPublicKey(std::move(spk));
```

**为什么不需要额外解析**：实测已证明 `PeerSubjectPublicKey()` 返回的就是 BIT STRING 内容（§2.5），无需自己解 ASN.1。

---

## 4. 测试方案（严格用 doc:3794-3798 的 5 个名字）

参考实现：`evidence/exec/batch1-a-new-tests-reference.cpp`（可直接对照，但**执行 AI 必须自己先写测试并观察红**）。

### 4.1 `two_constructions_have_different_nonces`（S1）

- **给定**：同一个合法 CHALLENGE，4 个独立 `CredsspClient`，均不调 `SetNonceForTest`
- **当**：各自 `Start` + `OnServerResponse` 走到第 3 步
- **则**：每次 `ExportedSessionKeyForTest()` 都 ≠ 全零，且两两不同
- **为什么能抓**：全零是修复前签名；固定填充（`s1_rand_like` 变体）只能通过「≠全零」但过不了「两两不同」。**双重断言**才堵住「用固定非零常量糊弄」这条假绿路径（对应 doc:4205 N6 的陷阱）。

### 4.2 `version_below_min_is_rejected_with_valid_challenge`（S5）

- **给定**：合法 `ServerChallengeMessage()` + `version=1`
- **当**：`OnServerResponse`
- **则**：`!ok()`、`status==kUnsupported`、`step3.empty()`、`!complete()`
- **控制组**：**新客户端**在 version=6 下接受同一 CHALLENGE（证明失败是版本导致，不是 fixture 问题）
- **为什么能抓**：用合法 token 排除了「token 解析失败」这条假绿路径
- **踩坑记录**：控制组必须用**新 client**。第一次我用同一个 `c` 继续，结果失败——因为 `Fail()` 会把 `step_` 置 `kFailed`（`c:54`），后续调用直接返回旧错误。这是「测试自身缺陷」，不是实现缺陷。

### 4.3 `server_version_is_echoed_back`（S6）

- **给定 A**：客户端 6，服务器回 3
- **则 A**：`req.version==3`、`client_nonce.empty()`、`pub_key_auth.size()==16+len(spk)`、`version()==3`
- **给定 B**：客户端 4，服务器回 6（**关键：覆盖 clamp 缺陷**）
- **则 B**：`req.version==4`、`client_nonce.empty()`、`pub_key_auth.size()==16+len(spk)`、`version()==4`
- **为什么能抓**：A 抓「不回写」；B 抓「用 clamp 导致升级」。只有 min 能同时过两条。实测 clamp 在 B 上失败。

### 4.4 `tampered_signature_checksum_is_rejected`（S11）

- **给定**：正常走到第 3 步，`MakeServerEchoForTest()` 后翻转 **`echo[4]`**（checksum 首字节，密文不动）
- **则**：`!ok()`、`status==kMalformed`、`step5.empty()`、`!complete()`
- **控制组**：未篡改的 echo 仍被接受且 `complete()`
- **为什么能抓**：密文不动 → 回显明文不变 → 回显比对（`c:283`）必然通过 → 唯一能拒绝它的就是 MAC 校验。这精确隔离了「MAC 校验」与「回显比对」。

### 4.5 `start_without_public_key_fails`（S18）

- **给定**：不调任何 setter，但调 `SetNonceForTest`（避免 S1 干扰）
- **当**：`Start` 后喂合法 CHALLENGE
- **则**：`!ok()`、`status==kUnsupported`、`step3.empty()`、`!complete()`
- **为什么能抓**：修复前会「成功」并产出 48 字节 `pubKeyAuth`（内容 = `SHA256(magic‖nonce‖"")`），探针 P5 已实测。

### 4.6 额外建议（超出 5 条，用于锁死我发现的缺陷）

| 测试名 | 抓什么 | 必要性 |
|---|---|---|
| `error_code_wins_over_bad_version` | 保证 S5 检查放在 errorCode 之后 | **建议**：否则服务器报 `STATUS_LOGON_FAILURE` + 异常版本时，错误码被吞成 `native_code=0` |
| `version_above_max_is_capped_not_rejected` | 锁死「只拒下界」策略 | **建议**：否则后人会「修正」成文档的拒双边 |
| `short_nonce_is_rejected_not_crashed` | 锁死 S1 提前守卫 | **建议**：否则 RNG 失败时进程崩 |

我已实现前 2 条并在影子树验证（21 tests / 164 checks 全绿）。第 3 条无法用现有公开 API 触发（`SetNonceForTest` 是唯一入口，测试里给短 nonce 就能触发），可加。

---

## 5. 红证汇总（全部实测）

变异脚本：`F:\rtsc\.tmp\audit-batch1\run_mutations.py`，输出 `evidence/exec/batch1-a-audit-mutations.txt`。

```
=== S1  nonce back to 32 zero bytes (pre-fix)  -> RED(OK) ===
    [ FAIL ] two_constructions_have_different_nonces
    21 tests, 164 checks, 1 failing tests, 7 failed checks

=== S5  delete the peer-version range check  -> RED(OK) ===
    [ FAIL ] version_below_min_is_rejected_with_valid_challenge
    [ FAIL ] error_code_wins_over_bad_version
    21 tests, 164 checks, 2 failing tests, 5 failed checks

=== S6  delete the negotiated-version write-back  -> RED(OK) ===
    [ FAIL ] server_version_is_echoed_back
    21 tests, 164 checks, 1 failing tests, 4 failed checks

=== S11  stop verifying the seal MAC (decrypt only, pre-fix)  -> RED(OK) ===
    [ FAIL ] tampered_signature_checksum_is_rejected
    21 tests, 164 checks, 1 failing tests, 4 failed checks

=== S18  delete the empty-public-key guard  -> RED(OK) ===
    [ FAIL ] start_without_public_key_fails
    21 tests, 164 checks, 1 failing tests, 3 failed checks
```

**每条变异只打红它对应的用例**（S5 变异额外打红 ordering 用例，属预期：删掉版本检查会让 ordering 的控制组失效）。无串味。

**修复前 vs 修复后**（同一份 21 用例文件）：

| 构建对象 | 结果 | 证据 |
|---|---|---|
| 未修改的生产代码（修复前） | **5 failing tests, 21 failed checks** | 见 §1 探针 + `pre.exe` |
| 影子树修复版 | **0 failing tests, 164 checks** | `batch1-a-audit-final-green.txt` |
| 影子树修复版 + 原 15 条测试 | **15 tests, 92 checks, 0 failing** | `batch1-a-audit-orig15-green.txt` |

### 5.1 定案后参考实现与「已跑绿版本」的差异（必须如实标注）

**重要**：上面 21/164 的绿证跑的是**阶段 1 的参考实现**，它与我后来按 D1–D6 定案修正后的 `evidence/exec/batch1-a-fixed-credssp-reference.cpp` **不是同一份**。差异如下：

| 项 | 跑绿时的版本 | 定案后（当前 reference 文件） | 是否重新跑过 |
|---|---|---|---|
| S1 随机化 | ✅ | ✅ | 是 |
| S1/D5 提前 nonce 守卫 | ❌ **缺失** | ✅ 已加 | **否**（仅静态检查 + 单独变体 20/155 跑绿） |
| S5 上界策略 | ❌ 拒双边 | ✅ 只拒下界（D2） | **否**（用独立探针 `probe_ver` 验证过行为，但**未**重跑 21 用例套件） |
| **S5+S6 收窄到 `kAwaitChallenge`** | ❌ 在分派之前 | ✅ 已收窄 | **否**（主代理裁决后新增，未编译未跑） |
| S6 `std::min` | ✅ | ✅ | 是 |
| S11 server-to-client 密钥 | ✅ | ✅ | 是 |
| S18 `BuildStep3` 守卫 | ✅ | ✅ | 是 |
| **N-B1 exported 独立随机** | ❌ **缺失**（取自 nonce） | ✅ 已改 | **否**（主代理裁决后新增，未编译未跑） |

**已验证的部分**：
- D5 守卫：用 `variant2.py` 加到同一份实现上跑过 **20 tests / 155 checks / 0 failing**（`early_nonce_guard` 变体）。之后参考实现又加了 ordering 用例，所以不是 21/164。
- D2 只拒下界：用 `probe_ver` 独立探针跑过 8 组 `peer_version`（0/1/2/4/6/7/8/100），确认 v7/v8/100 被 cap 到 6 而非拒绝。

**未验证的部分（诚实声明）**：
- 「D5 + D2 收窄 + N-B1 + ordering 用例」全部同场的套件**未重跑**（受「禁止启动 exe」约束）。
- 当前 reference 文件已通过**静态检查**（`static_check.py`：括号平衡 + **25 项**结构断言全 PASS，含 N-B1 与收窄验证），但**未经编译器与测试验证**。

**执行 AI 必须以自己的红→绿为准**，不要引用上表的 21/164 作为「定案实现已通过」的证据。

---

## 6. 完整推荐改动清单

### 6.1 新增文件

**`include/rtsc/crypto/random.h`**

```cpp
#pragma once
#include <cstddef>
#include "rtsc/crypto/hash.h"
namespace rtsc::crypto {
// Fills `out` with `size` bytes from the platform CSPRNG. On failure `out` is
// left empty so callers fail closed. Never rand()/random_device (doc:4205 N6).
bool RandomBytes(Bytes& out, size_t size);
}  // namespace rtsc::crypto
```

**`src/crypto/random.cpp`** — Win: `BCryptGenRandom(nullptr, ..., BCRYPT_USE_SYSTEM_PREFERRED_RNG)`；POSIX: `getrandom` 带 `EINTR` 重试。

**CMake**：`add_library(rtsc_crypto STATIC src/crypto/hash.cpp src/crypto/random.cpp)`，Windows 上 `target_link_libraries(rtsc_crypto PUBLIC bcrypt)`。

### 6.2 `include/rtsc/credssp/credssp.h`

```diff
 #include <string>
+#include <utility>
 #include <vector>

-    // ---- test hooks -------------------------------------------------------
-    // The production path generates the nonce with a CSPRNG. Tests inject a
-    // fixed one so the binding hash is reproducible; the hook is explicit so a
-    // missing call in production is a visible omission, not a silent default.
+    // ---- nonce / peer key injection ---------------------------------------
+    // The constructor already fills the nonce from the CSPRNG (S1). Tests inject
+    // a fixed one so the binding hash is reproducible.
     void SetNonceForTest(const Bytes& nonce) { nonce_ = nonce; }
+
+    // Production injection point (S18). Pass TlsTransport::PeerSubjectPublicKey()
+    // here right after the TLS handshake. Not optional: BuildStep3 fails closed
+    // when unset, because an empty key silently turns pubKeyAuth into
+    // SHA256(magic || nonce || "") and the MITM protection is gone.
+    void SetServerPublicKey(Bytes spk) { server_public_key_ = std::move(spk); }
+
+    // Test hook: same field, kept so the existing behaviour tests are unchanged.
     void SetServerPublicKeyForTest(const Bytes& spk) { server_public_key_ = spk; }
```

### 6.3 `src/credssp/credssp.cpp`

| 位置 | 改动 |
|---|---|
| `:7` 后 | `#include "rtsc/crypto/random.h"` |
| `:44-46` | 换成 `if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();` |
| `:105` 与 `:107` 之间（errorCode 分支**之后**） | `if (req.version < kMinVersion) return Fail(kUnsupported, "unsupported TSRequest version");` 然后 `version_ = std::min(version_, req.version);` |
| `BuildStep3` 开头（`:117` 之前） | `if (server_public_key_.empty()) return Fail(kUnsupported, "server public key not set");` 再 `if (nonce_.size() != kNonceSize) return Fail(kUnsupported, "nonce must be 32 bytes");` |
| `OpenReceive` `:359` 后 | MAC 校验（server-to-client 密钥 + version + seq），详见 §3.4 / §8.5 |

> **锚点以 §8.8 为准**（含唯一文本锚点，防行号漂移）。

**顺序很关键**：errorCode 分支（`c:97-105`）必须在新版本检查**之前**。否则服务器报 `STATUS_LOGON_FAILURE` 且版本异常时，`native_code` 会丢成 0。我专门加了 `error_code_wins_over_bad_version` 锁住这一点。

---

## 7. 影响范围与回归矩阵（执行 AI 必读）

| 改动 | 影响的套件 | 预期 | 实测 |
|---|---|---|---|
| S1 nonce | `rtsc_credssp_sm_tests`（12 处 `SetNonceForTest`） | 不变 | ✅ 15/92 |
| S5+S6 版本 | `rtsc_credssp_sm_tests`（version_4 用例） | 不变 | ✅ 15/92 |
| S11 MAC | `rtsc_credssp_sm_tests`（step5 系列） | 不变 | ✅ 15/92 |
| S18 setter + guard | `rtsc_credssp_sm_tests`（3 条无公钥用例） | **必须不变** | ✅ 15/92 |
| 新增 random.cpp | `rtsc_crypto` 链接（`bcrypt.lib`） | 新增依赖 | 编译通过 |
| 全部 | `rtsc_ntlm_tests` / `rtsc_credssp_tests` | 不变 | ✅ 27/136、23/69 |

**不需要跑**：`rtsc_tls_tests`、`rtsc_proto` 系列、`rtsc_framing_tests`（零文件交集）。但 `CMakeLists.txt` 改了 `rtsc_crypto` 的源列表，**建议至少确认全量 build 成功**（`/W4 /WX` 零警告）。

---

## 8. 定案（主代理裁决，D1–D6 全部采纳）

> **本节覆盖 §3 各小节里的「需裁决」措辞与 §0 的「与文档不同」表述。**
> 裁决来源：主代理 `ses_e9de05f37ffeceMUNAaRnKMy8c`，2026-10-23。
> 我（审计甲）的原始分歧提议保留在 §8.7 作溯源，但**执行以本节为准**。

### 8.1 裁决总表

| # | 争议点 | 文档原方案 | **定案（主代理裁决）** | 理由 |
|---|---|---|---|---|
| **D1** | S6 版本回写 | doc:1794 `std::clamp` | **`version_ = std::min(version_, req.version)`** | clamp 会把客户端 v4 升级到 v6，与第 1 步已声明的 v4 矛盾；实测 `server_version_is_echoed_back` 红 4 条。**服务端回高版本时，客户端只能降不能升** |
| **D2** | S5 版本边界 | doc:1793 拒双边 | **只拒下界**（`< kMinVersion`） | `security-layer.md:236` 实测服务器可声明更高版本；双边拒绝会误杀 v7/v8 |
| **D3** | S18 检查位置 | doc:1806 `Start` 或 `BuildStep3` | **`BuildStep3` 入口** | 放 `Start` 会让 3 条原测试（`t:110/359/381`）失败并**崩溃 0xC0000409**。崩溃不可接受 |
| **D4** | S11 签名密钥 | doc:1799 `signing_key_` | **`DeriveSigningKey(exported_session_key_, true)`** | `signing_key_` 是 client→server；复用会让所有 step5 用例红 |
| **D5** | S1 尺寸守卫 | 文档未提 | **必须加提前守卫** | 短 nonce 在 `c:229` 检查之前就于 `c:176/191` 越界 → 崩溃 |
| **D6** | 版本检查 vs errorCode 顺序 | 文档未提 | **errorCode 优先** | 否则 `native_code` 丢成 0 |

### 8.2 D1 定案细则（S6）—— **已按 §13.2 修订：`min` 与 D2 都只在协商点执行**

> **修订记录（阶段 2 互审 + 主代理裁决）**：乙指出原定案把 `min` 放在所有步骤，会导致第 4 步 `req.version=4` 把已协商的 6 降成 4，第 5 步与第 3 步版本不一致。
> 我核实成立。**主代理裁决进一步：把 D2 的下界检查也一并收进 `kAwaitChallenge` 分支**（不只是 `min`）。
> 这样第 4 步**完全不碰版本**——既不回写、也不新增拒绝点，行为与修复前一致。详见 §13.2 / §13.6。

```cpp
// src/credssp/credssp.cpp：OnServerResponse，errorCode 分支之后
if (step_ == Step::kAwaitChallenge) {
    // S5 + S6 都收窄到这里：第 2 步（CHALLENGE）是唯一的版本协商点。
    if (req.version < kMinVersion) {
        return Fail(Status::kUnsupported, "unsupported TSRequest version");
    }
    version_ = std::min(version_, req.version);   // 只能降，不能升
    return BuildStep3(req, out);
}
if (step_ == Step::kAwaitServerEcho) {
    return BuildStep5(req, out);                  // 第 4 步不检查、不回写版本
}
return Fail(Status::kMalformed, "unexpected state");
```

**为什么第 4 步既不检查也不回写**：

1. 第 2 步（CHALLENGE）才是版本协商点（`security-layer.md:673`）；第 4 步的 `version` 在协议上不承担协商语义（`security-layer.md:674` 只规定它带 `pubKeyAuth`）。
2. 回写会造成 step3/step5 版本不一致（第 3 步已按 6 发哈希 + nonce，第 5 步却发 4）。
3. 在分支外做下界检查会给第 4 步**新增一个拒绝点**（修复前第 4 步 `version=1` 会继续），这是不必要的行为变更。

**行为矩阵（最终定案）**：

| 客户端构造版本 | 第2步 req.version | 第4步 req.version | 定案后 `version_` | step3 路径 | step5 version | 第4步是否拒绝 |
|---|---|---|---|---|---|---|
| 6 | 3 | 6 | 3 | 裸公钥（无 nonce） | 3 | 否（不检查） |
| 6 | 6 | 6 | 6 | SHA-256 绑定哈希 + nonce | 6 | 否 |
| **4** | **6** | 6 | **4** | **裸公钥（不升级）** ← clamp 在此错 | 4 | 否 |
| 6 | 7 | 7 | 6 | SHA-256 绑定哈希（cap 到 6） | 6 | 否 |
| 6 | 1 | — | — | `kUnsupported`（第 2 步拒绝） | — | — |
| **6** | **6** | **4** | **6** | 哈希 + nonce | **6** ← 收窄后正确；未收窄会变 4 | 否 |
| 6 | 6 | **1** | 6 | 哈希 + nonce | 6 | **否** ← 收窄前会拒绝 |

**新增用例**：`server_echo_version_does_not_downgrade`（见 §12.3b）

**副作用（已确认无害）**：`c:241`、`c:300` 的 `req.version = version_` 自动跟随；`c:228`/`c:244`/`c:266` 的版本分叉自动生效；`MakeServerEchoForTest`（`c:368`）同步变化，测试侧天然一致。

**需同步修正的文档**（**由主代理执行，我不改**）：`docs/spec/security-integration.audit-a.md:1794` 的红证配方把 `clamp` 改成 `min`，并注明「**连同 D2 下界检查一起放进 `kAwaitChallenge` 分支内**」。

### 8.3 D2 定案细则（S5）—— **已收窄：只在 `kAwaitChallenge` 分支内**

```cpp
// OnServerResponse，errorCode 分支之后
if (step_ == Step::kAwaitChallenge) {
    // 只拒下界；上界由 D1 的 min() 自然吸收
    if (req.version < kMinVersion) {
        return Fail(Status::kUnsupported, "unsupported TSRequest version");
    }
    version_ = std::min(version_, req.version);
    return BuildStep3(req, out);
}
```

> **收窄的理由**（主代理裁决）：第 4 步（`kAwaitServerEcho`）的 `req.version` 不是协商输入，对它做范围检查既无协议依据，又会新增一个修复前不存在的拒绝点。收窄后第 4 步行为**与修复前完全一致**。

**测试名不匹配的处理**：现有 `step1_rejects_server_version_above_our_max`（`t:128`）名字与定案语义不符，但其**实际断言**只检查 `!e.ok()` 且用的是非法 token（`"0011"`），失败点在 token 解析，**不会因本次改动变红**（实测 15/92 仍全绿）。按 H7/N2 **不改这条测试**；新增 `version_above_max_is_capped_not_rejected` 锁定新语义。

### 8.4 D3 定案细则（S18）

```cpp
Error CredsspClient::BuildStep3(const TsRequest& challenge, Bytes& out) {
    // S18: fail closed. An empty key reduces pubKeyAuth to
    // SHA256(magic || nonce || "") and the MITM protection is silently gone.
    if (server_public_key_.empty()) {
        return Fail(Status::kUnsupported, "server public key not set");
    }
    if (challenge.nego_token.empty()) { ... }   // 原有检查
```

**为什么不是 `Start()`（实测）**：3 条原测试调 `Start()` 但不设公钥——

| 测试 | 行 | 不设公钥的原因 |
|---|---|---|
| `step1_emits_version_and_negotiate_token_only` | `t:110` | 第 1 步不涉及公钥 |
| `error_code_aborts_with_server_status` | `t:359` | 测 errorCode 分支 |
| `error_code_is_checked_before_any_token_processing` | `t:381` | 同上 |

放 `Start()` 的结果：第一条测试就 FAIL 4 条断言，随后进程 `exit 0xC0000409`，后 14 条从未运行（证据 `batch1-a-audit-guard-in-start.txt`）。

**语义佐证**：公钥来自 TLS 握手，`Start()` 时确实还没有；直到第 2 步（CHALLENGE）后才需要。`BuildStep3` 是首次使用点，fail-closed 且不误伤。

**新增生产 setter**（`credssp.h`，放在 `SetServerPublicKeyForTest` **之前**）：

```cpp
    void SetServerPublicKey(Bytes spk) { server_public_key_ = std::move(spk); }
```

需在 `credssp.h` 增加 `#include <utility>`（`std::move`）。

**接线点（批 3，不在批 1 范围）**：

```cpp
std::vector<uint8_t> spk;
Error e = tls->PeerSubjectPublicKey(spk);   // include/rtsc/net/tls.h:170
if (!e.ok()) return /* kUnsupported */;
credssp.SetServerPublicKey(std::move(spk));
```

实测确认返回的就是 `RSAPublicKey` DER（BIT STRING 去掉 unused-bits 字节），无需额外 ASN.1 解析（`batch1-a-audit-spk.txt`）。

### 8.5 D4 定案细则（S11）

```cpp
// OpenReceive：先解消息密文，再用同一 RC4 流解 checksum（与 SealSend c:318-343 对称）
const Bytes checksum = recv_rc4_.Apply(Bytes(field.begin() + 4, field.begin() + 12));
if (field[0] != 0x01 || field[1] != 0x00 || field[2] != 0x00 || field[3] != 0x00) {
    return Fail(Status::kMalformed, "sealed field unsupported version");
}
const uint32_t seq = field[12] | (field[13] << 8) | (field[14] << 16) | (field[15] << 24);
if (seq != recv_seq_) {
    return Fail(Status::kMalformed, "sealed field out of sequence");
}
Bytes mac_input(4, 0);                       // seq_le32
mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
const Bytes recv_signing_key = DeriveSigningKey(exported_session_key_, true);  // ← D4 关键
const auto hmac = crypto::HmacMd5(recv_signing_key.data(), recv_signing_key.size(),
                                  mac_input.data(), mac_input.size());
if (checksum != Bytes(hmac.begin(), hmac.begin() + 8)) {
    plaintext.clear();
    return Fail(Status::kMalformed, "sealed field MAC mismatch");
}
++recv_seq_;
```

**D4 的证据**：按 doc:1799 用 `signing_key_` 实现后，`step5_sends_authinfo_only` 与 `authinfo_plaintext_is_tscredentials_with_credentials` 全红——因为 `MakeServerEchoForTest`（`c:384`）用 `DeriveSigningKey(..., true)` 签名。改用 server-to-client 后 21/164 全绿。

**顺带收益**：`recv_seq_` 原本只 `++` 从不校验（`c:360`），现补上 version + seq 检查，堵住重放/乱序。

### 8.6 D5 + D6 定案细则

**D5（S1）**：`c:46` 改随机填充 + `BuildStep3` 入口加尺寸守卫。

```cpp
// c:46
if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();

// BuildStep3 入口（在 server_public_key_ 检查之后、任何切片之前）
if (nonce_.size() != kNonceSize) {
    return Fail(Status::kUnsupported, "nonce must be 32 bytes");
}
```

实测崩溃矩阵（未修复库，`batch1-a-audit-short-nonce.txt`）：

```
nonce=0   exit=-1073740791  (0xC0000409 STATUS_STACK_BUFFER_OVERRUN)
nonce=4   exit=-1073740791
nonce=16  exit=3
nonce=23  exit=3
nonce=24  exit=0  status=3 "nonce must be 32 bytes"   ← c:229 的检查从这里才生效
nonce=32  exit=0  ok=1
```

**D6（顺序）**：`OnServerResponse` 的检查顺序固定为：

1. `req.Decode` 失败 → 返回解码错误（`c:93`）
2. **errorCode 分支**（`c:97-105`）← 必须在前
3. **版本下界检查**（D2）
4. **版本回写**（D1）
5. 状态机分派（`BuildStep3` / `BuildStep5`）

若把 3 提到 2 之前，服务器报 `STATUS_LOGON_FAILURE` 且版本异常时，`native_code` 会丢成 0。锁死用例：`error_code_wins_over_bad_version`。

### 8.7 原始分歧记录（溯源用，已被本节覆盖）

| # | 我阶段 1 的提议 | 主代理裁决 | 是否一致 |
|---|---|---|---|
| D1 | `min` | `min` | ✅ |
| D2 | 只拒下界 | 只拒下界 | ✅ |
| D3 | `BuildStep3` | `BuildStep3` | ✅ |
| D4 | `DeriveSigningKey(..., true)` | 同 | ✅ |
| D5 | 提前守卫 | 同 | ✅ |
| D6 | errorCode 优先 | 同 | ✅ |

主代理裁决与我的阶段 1 提议**全部一致**。唯一需要主代理另行处理的动作是修正 `doc:1794` 的 `clamp` → `min`（按指令我不改文档）。

### 8.8 执行锚点表（按文本锚点定位，不按行号）

> doc:2050 的 N10 警告过：批 1 改 `credssp.cpp` 后行号会漂移。所以下表给**当前行号 + 唯一文本锚点**，执行时以文本为准。

| 改动 | 当前行 | 唯一文本锚点（改动前） | 操作 |
|---|---|---|---|
| **S1** include | `:7` 后 | `#include <algorithm>` | 其后插入 `#include "rtsc/crypto/random.h"` |
| **S1** 随机化 | `:44-46` | `// A deterministic-looking default keeps the nonce length valid even if the` | 三行（注释 2 + `nonce_.assign(kNonceSize, 0);`）整体替换为 `if (!crypto::RandomBytes(nonce_, kNonceSize)) nonce_.clear();` |
| **N-B1** exported key | `:190-194` | `        exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);` | 该行替换为 `if (!crypto::RandomBytes(exported_session_key_, 16)) return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");`；**保留 `else` 分支**（`exported_session_key_ = session_base_key_;`）。**前置条件**：先在 `ts_request.h` 加 `Status::kInternal`（见 §14.1.1） |
| **S5+S6** 版本 | `:107` 分支内 | `    if (step_ == Step::kAwaitChallenge) {` | 在该分支**内第一行**插入 D2 下界检查，随后 `version_ = std::min(version_, req.version);`。**不在分派之前**（收窄，见 §8.2 / §8.3） |
| **S18+D5** 守卫 | `:117` 之前 | `    if (challenge.nego_token.empty()) {` | 在此行**之前**插入公钥检查（S18）+ nonce 尺寸检查（D5） |
| **S11** MAC | `:359` 与 `:360` 之间 | `    plaintext = recv_rc4_.Apply(ciphertext);` | 其后插入 version/seq/checksum 校验；把 `++recv_seq_;` 移到校验通过之后 |
| **S18** setter | `credssp.h:61` 之前 | `    void SetServerPublicKeyForTest(const Bytes& spk) { server_public_key_ = spk; }` | 其前插入 `SetServerPublicKey`，并加 `#include <utility>` |

**插入顺序要求（同一插入点内）**：

1. `OnServerResponse`：先 errorCode（`:97-105`，已存在）→ 再 D2 下界检查（**对所有步骤生效**）→ 然后按 `step_` 分派。
2. **D1 的 `min` 回写必须在 `kAwaitChallenge` 分支内**，不在分派之前（收窄，见 §8.2 修订 / §12.3b）。
3. `BuildStep3` 入口：先 S18 公钥 → 再 D5 nonce 尺寸。两者都在 `challenge.nego_token.empty()` 之前。

**为什么 S11 要把 `++recv_seq_` 后移**：原代码在解密后立刻自增（`:360`），若校验失败则序列号已被推进，后续消息全部错位。校验失败应保持 `recv_seq_` 不变（该连接已 `kFailed`，但语义上更正确）。**注意：该 seq 校验在当前状态机下不可达**（`OpenReceive` 唯一调用点是 `c:258`，成功后立刻 `kDone`，第二次调用被 `c:84` 拦住），故批 1 不写 seq 用例（详见 §13.4）。

### 8.9 阶段 2 互审结果（已闭环）

按协作规则，D1/D3 是硬分歧，需**双方独立复验后一致**。

**结论：双方一致**（乙的独立复验见 `batch1-audit-b.md` §8，我的核实见本文 §13）。

| 项 | 状态 |
|---|---|
| D1 / D3 一致 | ✅ 双方独立复验，结论相同 |
| D2 / D4 / D5 / D6 | ✅ 无分歧 |
| 乙的「落点收窄」异议 | ✅ **采纳**，§8.2 已修订 |
| N-B1（乙报 P0） | ✅ **主代理裁决并入批 1**，见 §12.1b |
| 乙的 `recv_seq_` 用例建议 | ❌ 我否决（被 `c:84` 拦），见 §13.4 |
| `doc:1789` 红证式样坏 | ✅ 成立，见 §13.5.1 |
| preflight 正则误报 | ✅ 成立（我实测 MISS），需主代理修脚本 |
| N6 门禁未落地 | ✅ 成立（`verify.ps1` 零命中），需主代理加门禁 |

### 8.10 新增枚举 `credssp::Status::kInternal`（批 1 第 6 处改动）

> 来源：N-B1 的 CSPRNG 失败分支需要一个「本地故障」状态。主代理先裁 `kMalformed`，我用三条证据反驳（§15），主代理采纳方案 C。

**改动 1：`include/rtsc/credssp/ts_request.h:21-26`**

```diff
 enum class Status : uint8_t {
     kOk = 0,
     kTruncated,       // input ended inside a TLV
     kMalformed,       // tag/length/structure violation
     kUnsupported,     // valid structure, value this implementation rejects
+    kInternal,        // local environment failure (CSPRNG unavailable, etc.)
 };
```

**改动 2：`src/credssp/credssp.cpp` 的 N-B1 失败分支**

```cpp
if (!crypto::RandomBytes(exported_session_key_, 16)) {
    return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
}
```

**改动 3（批 3，不在批 1）：`doc:605` 的映射表加一行**

| 来源 | 判据 | `kind` | `native_space` |
|---|---|---|---|
| `credssp::Error` | `status == kInternal` | `kInternal` | `kNone` |

**为什么必须加这一行**：`doc:603` 的兜底是 `native_code == 0 && status == kMalformed/kTruncated → kProtocolViolation`。`kInternal` 不在其中，但若批 3 写成 `else → kProtocolViolation`，本地 CSPRNG 故障又会被报成「服务器违规」。**必须显式映射**。

**为什么不用 `kUnsupported` / `kMalformed`**：见 §14.1.1 与 §15.4。

**成本实测（主代理已独立复验）**：

| 检查项 | 结果 |
|---|---|
| `credssp::Status` 上的 `switch/case` 穷举 | 0（`credssp.cpp`/`ntlm.cpp` switch=0；`ts_request.cpp` 唯一 switch 是 DER tag） |
| `static_cast<int>(status)` | 0 |
| `status == <数字>` | 0 |
| `arr[status]` | 0 |
| 是否会触发 `/W4 /WX` 未处理枚举警告 | **否** |

**对现有测试的影响**：无。新增枚举值不改变任何既有分支（没有任何代码对 `Status` 做穷举或转换）。

## 9. 未验证项（诚实声明）

| 项 | 状态 | 验证方法 |
|---|---|---|
| `BCryptGenRandom` 在真实 Windows 上的返回值 | **未验证**（影子树用的是同一 API，但只测了成功路径） | 断点/注入失败，确认 `nonce_.clear()` → 新守卫返回 `kUnsupported` 而非崩溃 |
| 真实 RDP 服务器对 v2/3/4 路径的接受度 | **未验证** | `security-layer.md:1712` 同样标注未验证；需老服务器（2008/2012） |
| 真实服务器对 version=7 的响应 | **未验证** | 需构造非法版本请求；本仓库无该测试工具 |
| 批 3 `SecurityLayer` 接线后端到端 | **未验证**（批 1 范围外） | 批 3 的 T1 用例 |
| `PeerSubjectPublicKey` 在 RSA-2048 真实服务器上的字节 | 部分验证：本机回环是 RSA-1024（140B），证据 `schannel-spki-probe.txt` 的 RSA-2048 是 270B | 对 `192.168.1.7` 跑一次 spk 探针 |

---

## 10. 交付物索引

| 路径 | 内容 |
|---|---|
| `docs/spec/batch1-audit-a.md` | 本报告 |
| `evidence/exec/batch1-a-audit-probe.txt` | 5 条缺陷探针输出 |
| `evidence/exec/batch1-a-audit-spk.txt` | S18 公钥字节实测 |
| `evidence/exec/batch1-a-audit-short-nonce.txt` | 短 nonce 崩溃矩阵 |
| `evidence/exec/batch1-a-audit-version-range.txt` | 版本范围 8 组 |
| `evidence/exec/batch1-a-audit-mutations.txt` | 5 条变异红证 |
| `evidence/exec/batch1-a-audit-final-green.txt` | 修复版 21/164 全绿 |
| `evidence/exec/batch1-a-audit-orig15-green.txt` | 修复版 + 原 15 条 → 15/92 |
| `evidence/exec/batch1-a-audit-guard-in-start.txt` | 方案 A（Start 检查）崩溃证据 |
| `evidence/exec/batch1-a-audit-static-check.txt` | 定案参考实现的静态结构检查（17 项全 PASS，**非编译验证**） |
| `evidence/exec/batch1-a-audit-static-check.py` | 上述检查脚本（可复跑） |
| `evidence/exec/batch1-a-fixed-credssp-reference.cpp` | 定案参考实现（D1–D6 全部落地，静态检查通过，**未经编译/测试**） |
| `evidence/exec/batch1-a-new-tests-reference.cpp` | 参考测试（同上） |
| `evidence/exec/batch1-a-acceptance-checklist.md` | **§12 验收清单独立副本**（执行 AI 自检 + 审计复验用） |
| `evidence/exec/batch1-a-audit-citations.txt` | 报告内所有 `c:`/`t:`/`h:` 行号引用的逐条核对（33 处，全部存在且内容吻合） |
| `evidence/exec/batch1-a-audit-check-citations.py` | 上述核对脚本（可复跑） |
| `F:\rtsc\.tmp\audit-batch1\` | 全部探针源码、影子树、变异脚本 |

---

## 11. 完成声明

- ✅ 5 条缺陷全部独立复验（**可执行探针**，不采信主代理输出）
- ✅ 每条 ≥2 方案，且**用实测淘汰**了文档给的 2 个配方（clamp、signing_key_）
- ✅ 5 条变异全部拿到红证，且互不串味
- ✅ 修复版 21/164 全绿 + 原 15/92 全绿 + 上游 27/136、23/69 全绿
- ✅ 发现 3 个文档未记录的缺陷（短 nonce 崩溃、clamp 升级、MAC 密钥方向）
- ✅ **D1–D6 已定案并写入 §8**（主代理裁决，与我的提议全部一致）
- ⏳ **待乙独立复验 D1/D3**（硬分歧，双方一致才算通过）

### 11.1 唯一执行口径

执行 AI 只读 **§8 定案**（覆盖 §3 的「需裁决」措辞）。§3 保留为推导过程与实测记录，用于解释「为什么不是文档的写法」，不作为改动依据。

**给执行 AI 的一句话**：按 §8.2–§8.6 改 5 处；5 个测试名用 §4；红证变异步骤用 §5；改完跑 `rtsc_credssp_sm_tests`（应 ≥20）、`rtsc_ntlm_tests`（27）、`rtsc_credssp_tests`（23）。

### 11.2 证据等级声明（执行前必读）

| 证据 | 等级 | 说明 |
|---|---|---|
| 5 条缺陷存在性 | **实测** | 探针直连未修改库，输出见 `batch1-a-audit-probe.txt` |
| 5 条变异红证 | **实测** | 影子树编译并运行，见 `batch1-a-audit-mutations.txt` |
| 阶段 1 参考实现 21/164 绿 | **实测** | 但**不含** D5 守卫与 D2 只拒下界，见 §5.1 |
| D5 守卫不破用例 | **实测（20/155）** | `variant2.py` 的 `early_nonce_guard` 变体 |
| D2 只拒下界行为 | **实测（独立探针）** | `probe_ver` 8 组版本，v7/v8/100 被 cap 到 6 |
| 定案后完整 reference（D1–D6 同场） | **静态检查通过，未编译未跑测** | `batch1-a-audit-static-check.txt` |
| `PeerSubjectPublicKey` 字节语义 | **实测** | 真实 SChannel 回环，`batch1-a-audit-spk.txt` |

**结论**：缺陷存在性与变异红证是硬证据；定案后的**完整实现组合**尚未编译验证，**执行 AI 必须自己走一遍红→绿**，不得以我的静态检查代替。

---

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
- ❌ **只修 S1 不修 N-B1** → nonce 随机了，但 `exported_session_key_` 仍是 `nonce[8..24)`，而整个 nonce 明文发出 → 口令仍可被解密。**S1 与 N-B1 必须同批**（见 §12.10）。

---

### 12.1b N-B1 —— `client_nonce_does_not_disclose_session_key`（**P0，主代理裁决并入批 1**）

**缺陷**：`c:191` 让 `exported_session_key_ = nonce[8..24)`，而 `c:244` 把**整个** `nonce_` 明文放进 `client_nonce` 发出（`ts:263-267` 的 `WriteOctetString` 不加密）。于是对端可从 clientNonce 直接切出 exported key → 派生 sealing key（`ntlm.cpp:389-394`，纯 MD5，无需口令）→ 解出第 5 步 authInfo 里的**明文口令**（`c:287-296`）。

**规范依据**：`security-layer.md:829-830`「ExportedSessionKey = … **16 字节随机数**」；`security-layer.md:611`「clientNonce … 32 字节密码学随机数」。两者是**独立的**随机值，实现把它们合并了。

**给定**
- `CredsspClient(TestCreds(), 6)`，`SetNonceForTest(FixedNonce())`，`SetServerPublicKeyForTest(spk)`
- **必须驱动到第 3 步**（`Start` + `OnServerResponse(challenge)`）——`exported_session_key_` 只在 `BuildStep3` 内赋值（`c:184-194`），**只构造不驱动时它是空 vector**，那样的断言毫无意义（这正是 doc:1789 红证式样的错误）

**当**：解析 step3 得到 `req.client_nonce`，并读 `c.ExportedSessionKeyForTest()`

**则**

| # | 断言 | 期望值 | 为什么需要 |
|---|---|---|---|
| 1 | `exported.size()` | `== 16` | 尺寸正确 |
| 2 | `req.client_nonce.size()` | `== 32` | clientNonce 仍是 32 字节（`t:175` 依赖） |
| 3 | **`std::search(client_nonce.begin(), client_nonce.end(), exported.begin(), exported.end()) == client_nonce.end()`** | 真 | **核心断言**：exported 不是 clientNonce 的**任何偏移**上的连续子串（等价于乙的「任一 16 字节窗口 `o=0..16`」，比只比 `[8..24)` 更强——能抓「换个偏移继续派生」） |
| 4 | `Hex(exported) != Hex(Bytes(16, 0))` | 真 | 排除「填零当随机」 |
| 5 | 两次独立构造的 `exported` 不同 | 真 | 排除固定常量 |

**断言 3 的等价性证明**：32 字节 nonce、16 字节 needle → 窗口偏移 `o ∈ [0, 16]` 共 **17** 个。`std::search` 命中当且仅当存在某个 `o` 使 `nonce[o..o+16) == exported`。修复前 `exported == nonce[8..24)` → `o=8` 命中 → 必红。修复后 exported 独立随机 → 误报概率 `17 × 2⁻¹²⁸ ≈ 5e-38`，统计上不可能。

**变异后预期失败**（当前实现）

```
[ FAIL ] client_nonce_does_not_disclose_session_key
  FAIL :xxx  std::search(...) == client_nonce.end()
      (got: found at offset 8, want: not found)
```

**修复代码**（`c:190-194`）

```cpp
if ((msg.flags & ntlm_flag::kKeyExch) != 0) {
    // KEY_EXCH: ExportedSessionKey MUST be an independent 16-byte random value
    // (security-layer.md:829-830). Taking it from nonce_ would publish it: the
    // whole nonce travels in cleartext as TSRequest.clientNonce (c:244,
    // ts:263-267), so a passive observer could derive the sealing key and
    // decrypt the password sent at step 5. Never derive one from the other.
    if (!crypto::RandomBytes(exported_session_key_, 16)) {
        return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
    }
} else {
    exported_session_key_ = session_base_key_;
}
```

**对现有 15 条的影响（我逐条核对，全部不受影响）**

| 测试 | 依据 |
|---|---|
| `step3_authenticate_carries_a_nonzero_mic`（`t:179`） | `t:205` 用实际 `ExportedSessionKeyForTest()` 复算 MIC，不假设它等于 nonce |
| `step3_pubkeyauth_hash_matches_independent_computation`（`t:211`） | `t:241` 走 `DecryptPubKeyAuthForTest`，内部用 `sealing_key_`（`c:399`），自洽 |
| `step5_sends_authinfo_only`（`t:283`） | `MakeServerEchoForTest`（`c:384-387`）用 `exported_session_key_` 派生，自洽 |
| `step5_rejects_wrong_server_echo`（`t:317`） | 同上 |
| `authinfo_plaintext_is_tscredentials_with_credentials`（`t:441`） | `DecryptAuthInfoForTest`（`c:403-412`）用 `sealing_key_` + `Skip`，自洽 |
| `version_4_pubkeyauth_is_encrypted_public_key_not_hash`（`t:478`） | v4 走 `plain = server_public_key_`（`c:234`），不用 exported 切片 |
| 其余 9 条 | 不触及 exported key |

**关键**：`t:175` 的 `CHECK(req.client_nonce == FixedNonce())` **仍然成立**——修复只改 exported 的来源，不改 clientNonce 的内容。**这条断言不会红**，符合 H7。

**易错点**
- ❌ 只构造不驱动就断言（doc:1789 的坏式样）→ 两个空 vector 恒相等，修复后仍红。
- ❌ 断言 `exported != nonce[8..24)` 用 `memcmp` 只比首字节 → 必须比完整 16 字节，或用 `std::search` 覆盖「出现在任何偏移」。
- ❌ 忘了 `KEY_EXCH` 的 else 分支（`c:193`）→ 未协商 KEY_EXCH 时 exported 应等于 `session_base_key_`，不能改成随机。

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

### 12.3 S6 —— `server_version_is_echoed_back`（**必须两组 + 一条第 4 步用例**）

> **收窄后（§13.2 / §8.2 修订）**：`min` 回写只在 `kAwaitChallenge` 分支执行。A/B 两组仍有效（都走第 2 步），另需 §12.3b 的用例锁住「第 4 步不回写」。

**给定 A（服务器降版，走第 2 步）**
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

### 12.3b S6 收窄 —— `server_echo_version_does_not_downgrade`（**主代理裁决新增**）

**为什么需要**：`OnServerResponse` 是第 2 步和第 4 步的**共用入口**（`c:107-112` 按 `step_` 分派）。若 `min` 回写不限定在 `kAwaitChallenge`，第 4 步的 `req.version` 也会改写 `version_`：第 2 步 6 → 第 4 步 4 → `version_` 变 4 → 第 5 步（`c:300`）发 4，而第 3 步已按 6 发了哈希 + nonce，**协议状态不一致**。

**给定**
- `CredsspClient(TestCreds(), 6)`，`SetNonceForTest(FixedNonce())`，`SetServerPublicKeyForTest(spk)`
- 第 2 步：CHALLENGE `version=6`
- 第 4 步：`TsRequest{version=4, pub_key_auth=MakeServerEchoForTest()}`

**当**：走完 step3 → step4 → step5

**则**

| # | 断言 | 期望值 | 为什么 |
|---|---|---|---|
| 1 | step5 的 `req.version` | `== 6` | **核心**：第 4 步不得降版 |
| 2 | `c.version()` | `== 6` | getter 不得被第 4 步篡改 |
| 3 | `c.complete()` | `true` | 流程正常完成（不是靠拒绝通过） |
| 4 | `req.auth_info` 非空 | 真 | 第 5 步确实发出 |

**变异后预期失败**（未收窄的实现）

```
[ FAIL ] server_echo_version_does_not_downgrade
  FAIL :xxx  req5.version == 6        (got 4, want 6)
  FAIL :xxx  c.version() == 6         (got 4, want 6)
```

**易错点**
- ❌ 第 4 步也用 `version=6` → 收窄与不收窄都通过，**测不出**。必须第 4 步故意发 4。
- ❌ 只断言 `c.version()` 不断言 step5 的 `req.version` → 漏掉真正发出去的字段。
- ❌ 断言 `!ok()`（以为降版应拒绝）→ 定案是「不降版、正常完成」，不是拒绝。第 4 步的 `version=4` 仍通过 D2 下界检查（4 >= 2）。

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
- ❌ 把 `SetServerPublicKeyForTest` 删掉 → 原 15 条里 8 处调用会编译失败。**两个 setter 都要留**。
- ❌ 用 `if (server_public_key_.size() == 0)` 之外的条件（比如校验长度）→ 过度约束，`t:149` 用的是 8 字节假 SPK。

---

### 12.6 D1–D6 同场交叉验证（**这是最容易漏的部分**）

以下是我静态推演出的相互影响，执行 AI 必须逐条确认。

#### 交叉 1：D1 的 `min` 在**第 4 步也会执行**（重要 —— **已被收窄方案消除**）

`OnServerResponse` 是第 2 步和第 4 步共用的入口（`c:107-112` 按 `step_` 分派）。所以**如果**版本回写代码放在分派之前，第 4 步会**再跑一次**。

**收窄前（原定案）的风险推演**：

| client | 第2步 req.version | 第4步 req.version | 第2步后 `version_` | 第4步后 `version_` | 结论 |
|---|---|---|---|---|---|
| 6 | 3 | 6 | 3 | **3** | 幂等，安全 |
| 6 | 3 | 3 | 3 | 3 | 幂等 |
| 4 | 6 | 6 | 4 | 4 | 幂等 |
| 6 | 7 | 7 | 6 | 6 | 幂等 |
| **6** | **6** | **4** | 6 | **4** | ❌ **降版，协议状态不一致** |

**我原来的结论「`min` 幂等所以无害」不成立**——幂等性只在「第 4 步版本 ≥ 已协商版本」时成立。乙找到的 **6→4** 场景打破了这个前提：第 3 步已按 6 发了哈希 + nonce，第 5 步却发 4。

**收窄后（最终定案）**：D2 下界检查与 D1 `min` 回写**都**在 `kAwaitChallenge` 分支内，第 4 步**完全不碰版本**：

| 场景 | 收窄前 | **收窄后（定案）** |
|---|---|---|
| 第 4 步 `req.version=4`（已协商 6） | `version_` 变 4，step5 发 4 | `version_` 保持 6，step5 发 6 ✅ |
| 第 4 步 `req.version=1` | 被下界检查拒绝（**行为变更**） | **继续**（第 4 步不检查版本）→ **与修复前完全一致** ✅ |
| `c.version()` 被第 4 步篡改 | 会 | **不会** ✅ |

**结论修正（相对我 §12.6 的初版）**：
- 我初版说「第 4 步新增拒绝点是行为变更，需知悉」→ **收窄后这个变更彻底消失**。主代理裁决把 D2 也收窄，正是为此。
- 取而代之的是 `server_echo_version_does_not_downgrade`（§12.3b）锁住「第 4 步不回写」。

**验收**：`step5_sends_authinfo_only`（`t:283`）的 `step4.version = 6`（`t:300`）→ 收窄前后都不受影响（6 不降）。

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
| **19** | **`min` 回写不限定在 `kAwaitChallenge`** | 第 4 步把已协商版本降掉 → step5 版本与 step3 不一致（§12.3b 必红） | 收窄到 `kAwaitChallenge` 分支内 |
| **20** | **`exported_session_key_` 继续取自 `nonce[8..24)`** | clientNonce 明文发出 → 对端解出口令（N-B1，§12.1b 必红） | 独立 `RandomBytes(..., 16)` |
| **21** | **N-B1 只改 exported 却忘了 `else` 分支** | 未协商 KEY_EXCH 时应等于 `session_base_key_`（`c:193`），改错会破坏 v2/3/4 | 保留 `else` 原逻辑 |
| **22** | **照抄 doc:1789 的 S1 红证式样（只构造不驱动）** | 两个空 vector 恒相等 → 修复后仍红 | 必须驱动到第 3 步（§4.1 / §12.1） |

---

### 12.8 最终验收门禁（执行 AI 自检 + 审计复验）

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
cmd /c F:\rtsc\.tmp\build_tls.bat
if ($LASTEXITCODE -ne 0) { throw "BUILD FAILED" }     # /W4 /WX 零警告

$suites = @{ 'rtsc_credssp_sm_tests'=21; 'rtsc_ntlm_tests'=27; 'rtsc_credssp_tests'=23 }
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
| `rtsc_credssp_sm_tests` | **≥ 21**（15 原 + 5 名指定 + N-B1） | 若再加 §12.3b 的 `server_echo_version_does_not_downgrade` 与 §4.6 的 2 条，则 ≥ 24 |
| `rtsc_ntlm_tests` | **= 27** | 零改动，数字必须不变 |
| `rtsc_credssp_tests` | **= 23** | 零改动，数字必须不变 |

**红证留档要求**：变异逐条做，每条记录「用例名 + 断言文本 + 实际读数」，格式见 doc:3272-3275。**不接受「大概会失败」**（doc:3277）。

**批 1 变异清单（6 条，比原 5 条多 N-B1）**

| # | 缺陷 | 变异（改回修复前） | 预期红 |
|---|---|---|---|
| 1 | S1 | `nonce_.assign(kNonceSize, 0);` | `two_constructions_have_different_nonces` |
| 2 | S5 | 删掉下界检查 | `version_below_min_is_rejected_with_valid_challenge` |
| 3 | S6 | 删掉 `min` 回写 | `server_version_is_echoed_back`（A 组） |
| 4 | S6 收窄 | 把 `min` 移出 `kAwaitChallenge` | `server_echo_version_does_not_downgrade` |
| 5 | S11 | 停止 MAC 校验 | `tampered_signature_checksum_is_rejected` |
| 6 | S18 | 删掉空公钥守卫 | `start_without_public_key_fails` |
| **7** | **N-B1** | **`exported_session_key_.assign(nonce_.begin()+8, nonce_.begin()+24)`** | **`client_nonce_does_not_disclose_session_key`** |

---

### 12.9 与 §8 的对应关系

| 验收项 | 对应定案 |
|---|---|
| §12.1 | §8.6（D5）+ §3.1（S1） |
| **§12.1b** | **N-B1（主代理裁决，并入批 1）** |
| §12.2 | §8.3（D2）+ §8.6（D6） |
| §12.3 | §8.2（D1） |
| **§12.3b** | **§8.2 修订（收窄到 `kAwaitChallenge`）** |
| §12.4 | §8.5（D4） |
| §12.5 | §8.4（D3） |
| §12.6 | 交叉验证（交叉 1 已按收窄修订） |
| §12.7 | 易错点汇总（22 条） |

---

## 13. 阶段 2 互审：乙的发现与我的独立核实

> 乙（`ses_e9806f3f9ffeG7HMFgYVsLD2uC`）在 `batch1-audit-b.md` §8 提出 7 项。
> 我**逐条独立核实**（源码 + 规范 + 静态推演，零 exe），结论如下。

### 13.1 D1 / D3 —— 双方一致 ✅

| 项 | 乙的结论 | 我的结论 | 一致 |
|---|---|---|---|
| D1 `min` vs `clamp` | min 对，clamp 错 | 同（我实测 clamp 红 4 条） | ✅ |
| D3 guard 位置 | `BuildStep3` | 同（我实测 `Start` 崩溃 `0xC0000409`） | ✅ |

乙补充的 D3 **机制**比我给的更完整，我接受：

> `t:112-120` 在 `Start()` 后无条件做 `req.nego_token.begin() + 8`（`t:118`）和 `req.nego_token[8]`（`t:120`）。Start 提前失败 → `out` 为空 → `Decode` 失败 → `nego_token` 是空 vector → `begin() + 8` 触发 "cannot seek value-initialized vector iterator"。

我核对了 `t:112-120`，**确认属实**。这解释了为什么崩溃点在测试而不是实现，也解释了为什么 H7「不许改测试」直接排除了 `Start()` 方案。

### 13.2 乙的唯一实质异议（P2）：`min` 落点要收窄 —— **我部分接受，但结论不同**

**乙的主张**：`min` 应只在 `kAwaitChallenge` 分支内执行，不要在 `kAwaitServerEcho` 分支执行；并配 `server_echo_version_does_not_downgrade`（6→6→4，断言 step5 version==6）。

**我的核实**：

1. **乙描述的风险真实存在**：若第 2 步 `req.version=6`、第 4 步 `req.version=4`，当前定案的 `min` 会让 `version_` 从 6 变 4，第 5 步（`c:300`）发 4，而第 3 步已按 6 发了哈希 + nonce。**版本不一致，属实**。

2. **但乙的测试用例设计有缺陷**：`server_echo_version_does_not_downgrade` 用「6→6→4」，断言 step5 的 `version==6`。问题是——**第 4 步的 `req.version=4` 会先被 D2 的下界检查放行（4 >= 2），然后 `min(6,4)=4`**。乙的方案（收窄到只在 `kAwaitChallenge` 执行）确实能保持 6。**这个用例能区分两种实现**，设计有效。

3. **我的判断：接受乙的收窄方案，但理由与乙不同**。

   乙的理由是「版本不一致」。我的理由是**更根本的**：第 4 步的 `req.version` 在协议上**没有语义**——`security-layer.md:674` 规定第 4 步是 `version` + `pubKeyAuth`，但服务器在第 4 步回什么版本，客户端**不应据此改变已协商的版本**。第 2 步才是协商点（`[MS-CSSP]` 的版本协商发生在 CHALLENGE）。所以在第 4 步回写是**概念错误**，不只是「可能不一致」。

**结论**：**采纳乙的收窄**，定案 §8.2 需修订。

```cpp
// OnServerResponse：D2 下界检查对所有步骤生效（fail-closed 合理）
if (req.version < kMinVersion) {
    return Fail(Status::kUnsupported, "unsupported TSRequest version");
}
if (step_ == Step::kAwaitChallenge) {
    version_ = std::min(version_, req.version);   // 只在协商点回写
    return BuildStep3(req, out);
}
if (step_ == Step::kAwaitServerEcho) {
    return BuildStep5(req, out);                  // 第 4 步不改 version_
}
```

**这同时修正了我 §12.6 交叉 1 的结论**：我之前说「`min` 幂等所以无害」——幂等性成立（`min` 重复应用结果不变），但**前提是第 4 步的版本不低于已协商版本**。乙找到的 6→4 场景打破了这个前提。所以「幂等 ⇒ 无害」的推理**不充分**，我修正。

### 13.3 乙的 N-B1（P0）：clientNonce 泄露 exported session key —— **成立，且比乙描述的更严重**

#### 13.3.1 缺陷确认（我独立核实）

代码链（全部实测读取）：

| 行 | 内容 | 作用 |
|---|---|---|
| `c:191` | `exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);` | **exported key = nonce[8..24)** |
| `c:244` | `if (version_ >= kFirstHashVersion) req.client_nonce = nonce_;` | **整个 nonce 明文发出** |
| `ts:263-267` | `WriteOctetString(s, client_nonce.data(), ...)` | clientNonce 是**明文 OCTET STRING**，无加密 |
| `c:196` | `signing_key_ = DeriveSigningKey(exported_session_key_, false);` | 由 exported 派生 |
| `c:197` | `sealing_key_ = DeriveSealingKey(exported_session_key_, ...);` | 由 exported 派生 |
| `c:296` | `SealSend(creds_der, sealed)` | 用 `sealing_key_` 加密**明文口令** |
| `ntlm.cpp:389-394` | `DeriveSealingKey` = `MD5(exported ‖ magic)` | **纯函数，无需口令** |

**攻击链（被动窃听即可，无需中间人改写）**：

```
观察 step 3 的 TSRequest（TLS 内，但 kInsecure 下 TLS 对端就是攻击者）
  → 取 clientNonce[5] 字段的 32 字节明文
  → exported_session_key_ = clientNonce[8..24)
  → sealing_key_ = MD5(exported ‖ "session key to client-to-server sealing key magic constant\0")
  → 解 step 5 的 authInfo → 得到 TSCredentials 明文 → 域\用户名 + 明文口令
```

**关键点：全程不需要口令、不需要破解 NTLM**。因为 `KEY_EXCH` 已协商（`t:80` 的 `kKeyExch`），exported key 按规范应是**独立随机的 16 字节**（`security-layer.md:829-830`：「16 字节随机数；EncryptedRandomSessionKey = RC4(KeyExchangeKey, ExportedSessionKey)」），而实现偷懒复用了 nonce 的后 16 字节。

#### 13.3.2 比乙描述更严重的地方（我的增量）

乙说「TLS 对端（MITM）能拿到」。我核实后认为**范围更大**：

1. **不需要 MITM，被动窃听也成立**——只要能看到 step 3 的明文（kInsecure / 任何 TLS 被解的场景）。乙说「MITM」，实际是「任何能看到明文的一方」。
2. **不需要第 4 步伪造**——乙说「还能伪造第 4 步回显」。实际上第 4 步的期望值 `expected = ServerToClientBindingHash(server_public_key_, nonce_)`（`c:267`）只依赖**公钥 + nonce**，两者都是公开的（公钥来自证书，nonce 明文发送）。**即使不泄露 exported key，第 4 步回显本来就可伪造**。所以「伪造第 4 步」不是 N-B1 的增量风险，是独立的既有问题（S11 的 MAC 校验只能防篡改，防不了「攻击者自己算对了再签」——但攻击者没有 server-to-client signing key，所以 S11 修复后伪造确实被堵住）。
   
   **修正**：S11 修复后，攻击者**无法**伪造第 4 步（没有 server-to-client signing key）。乙的这句话在 S11 修复后**不成立**。但 N-B1 的**口令泄露**独立成立，且更严重。
3. **S1 修复后 N-B1 原样存在**——乙这点完全正确。随机化 nonce 不改变「nonce 明文发送 + exported 取自 nonce」这个结构。

#### 13.3.3 修复方案

```cpp
// c:190-194 替换
if ((msg.flags & ntlm_flag::kKeyExch) != 0) {
    // KEY_EXCH: ExportedSessionKey MUST be an independent 16-byte random value
    // (security-layer.md:829-830). Reusing the client nonce's tail would publish
    // it: the whole nonce travels in cleartext as TSRequest.clientNonce (c:244,
    // ts:263-267), so anyone who can read step 3 could derive the sealing key and
    // decrypt the password in step 5. Do NOT take it from nonce_.
    if (!crypto::RandomBytes(exported_session_key_, 16)) {
        return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
    }
} else {
    exported_session_key_ = session_base_key_;
}
```

**测试**：`client_nonce_does_not_disclose_session_key`

- 给定：正常走到第 3 步（client 6 + 合法 CHALLENGE）
- 当：取 `req.client_nonce` 与 `c.ExportedSessionKeyForTest()`
- 则：
  1. `exported.size() == 16`
  2. **`std::search(client_nonce.begin(), client_nonce.end(), exported.begin(), exported.end()) == client_nonce.end()`**（exported 不是 nonce 的任何子串）
  3. 对照组：`exported != Bytes(16, 0)`
- **为什么能抓**：修复前 `exported` 恰好等于 `client_nonce[8..24)`，`std::search` 必命中 → 断言 2 红。

**对现有 15 条的影响（我逐条核对）**：

| 测试 | 是否受影响 | 依据 |
|---|---|---|
| `step3_authenticate_carries_a_nonzero_mic`（`t:179`） | **否** | `t:205` 用 `ExportedSessionKeyForTest()` 复算 MIC，用的是实际值，不假设它等于 nonce |
| `step3_pubkeyauth_hash_matches_independent_computation`（`t:211`） | **否** | `t:241` 用 `DecryptPubKeyAuthForTest`，内部用 `sealing_key_`（`c:399`），自洽 |
| `step5_sends_authinfo_only`（`t:283`） | **否** | `MakeServerEchoForTest`（`c:384-387`）用 `exported_session_key_` 派生，自洽 |
| `step5_rejects_wrong_server_echo`（`t:317`） | **否** | 同上 |
| `authinfo_plaintext_is_tscredentials_with_credentials`（`t:441`） | **否** | `DecryptAuthInfoForTest`（`c:403-412`）用 `sealing_key_` + `Skip`，自洽 |
| `version_4_pubkeyauth_is_encrypted_public_key_not_hash`（`t:478`） | **否** | v4 走 `plain = server_public_key_`（`c:234`），不用 exported 切片 |
| 其余 9 条 | **否** | 不触及 exported key |

**关键**：`t:175` 的 `CHECK(req.client_nonce == FixedNonce())` **仍然成立**——修复只改 exported 的来源，不改 clientNonce 的内容。**这条断言不会红**，符合 H7。

#### 13.3.4 我的裁决建议

**N-B1 应并入批 1**（P0，且与 S1 硬绑定）：

- **只修 S1 不修 N-B1** → nonce 随机了，但 exported 仍是 nonce 的后半 → **口令仍可被解密**。S1 的「安全收益」被 N-B1 完全抵消。
- **只修 N-B1 不修 S1** → exported 独立随机了，但 ClientChallenge（`c:176` 用 nonce[0..8)）仍可预测 → NTLMv2 的 client challenge 弱化。
- **两者必须同批**：都改 `c:176/191` 附近的密钥材料来源。

### 13.4 乙的第 6 点（`recv_seq_` 可观测用例）—— **不成立，我核实后否决**

乙建议：

> `MakeServerEchoForTest()` 是 const，不推进 `recv_seq_`，两次调用 seq 都是 0。先接受第一条（recv_seq_→1），再喂第二条 → 修后 seq 0 != 1 必 `kMalformed`。

**问题**：接受第一条 echo 后，`BuildStep5` 会执行 `step_ = Step::kDone`（`c:305`）。第二次调 `OnServerResponse` 时，**在进入 `BuildStep5` 之前**就被 `c:84-86` 拦住：

```cpp
if (step_ == Step::kDone) {
    return Fail(Status::kMalformed, "response after completion");
}
```

所以返回的是 `"response after completion"`，**不是** `"sealed field out of sequence"`。乙的用例**无法区分**「seq 校验生效」与「状态机已 Done」。

**我的修正建议**：若要测 seq 校验，必须让 `OpenReceive` 在一个**非 Done** 状态下被调用两次——但当前状态机只有 `kAwaitServerEcho` 会调 `OpenReceive`（`c:258` 是唯一调用点），而它成功后立刻变 `kDone`。**所以在现有状态机上无法构造该用例**。

**结论**：
- 乙的用例**不成立**，不要写。
- `recv_seq_` 的 seq 校验仍然值得加（防御性，且真实服务器若重放会被拒），但**无法用公开 API 测**。应如实标注为「实现有、测试不可达」，或**不加 seq 校验**（避免引入无法验证的代码）。

**我的建议：保留 seq 校验（它与 MAC 校验在同一处，成本为零），但不在批 1 写测试，在注释里说明「当前状态机下不可达，为未来重协商预留」**。

### 13.5 乙的第 7 点：三条执行层面的坑 —— **全部核实成立**

#### 13.5.1 `doc:1789` 的 S1 红证式样是坏的 ✅ 成立

doc:1789 写：「断言 `CredsspClient(c,6)` 两次的 `ExportedSessionKeyForTest()` 不同 → 当前必失败（都全零）」。

**问题**：只构造不驱动时，`exported_session_key_` 是**空 vector**（`c:191`/`c:193` 只在 `BuildStep3` 里赋值）。两个空 vector **恒相等**。所以：
- 修复前：两个空 vector 相等 → 断言「不同」失败 → 红 ✅（碰巧对了）
- 修复后：仍然两个空 vector 相等 → **仍然红** ❌

**即：按 doc:1789 写，修复后测试还是红的**，执行 AI 会以为没修好。

**我的 §4.1 是驱动式样**（必须 `Start` + `OnServerResponse` 走到第 3 步），**正确**。必须提醒执行 AI 别照抄 doc。

#### 13.5.2 `batch1_preflight.py` 修复后会误报 BAD ✅ 成立（我已独立验证）

我实测了正则：

```
S6   pattern=version_\s*=\s*(?:std::clamp|req\.version)
     line   =version_ = std::min(version_, req.version);        -> MISS
S18  pattern=server_public_key_\s*=[^=]
     line   =if (server_public_key_.empty()) {                  -> MISS
S5b  pattern=version\s*=\s*req\.version|req\.version\s*[<>]
     line   =if (req.version < kMinVersion) {                   -> MATCH
```

**风险**：执行 AI 修完后跑 preflight，看到 `S6 ABSENT BAD` / `S18 ABSENT BAD`，可能**为了「变绿」把正确的 `min` 改回 `clamp`**。这是**极其危险**的误导。

**必须修正 preflight 的正则**（或在该脚本里加注释说明「Q1 只对修复前有意义」）。这不是我能改的（脚本属主代理），**建议主代理修正**。

#### 13.5.3 N6 的 `Select-String` 门禁没进 `verify.ps1` ✅ 成立（我已独立验证）

- `doc:4011` 给了命令：`Select-String -LiteralPath ...credssp.cpp -Pattern '\brand\(|\bsrand\(|std::random_device|mt19937'`
- 我实测 `verify.ps1`（366 行）中 `rand(`/`srand`/`random_device`/`mt19937`/`BCryptGenRandom`/`getrandom` 命中 **0 处**
- `verify.ps1:273` 有 `if ($DocCite) {` 分支，但里面不含 rand 检查

**结论**：doc:4010-4012 要求的门禁**只写在文档里，没落地**。执行 AI 若用 `rand()` 不会被任何门禁拦住。

**建议**：主代理把这条加进 `verify.ps1` 的 `-DocCite` 分支（或新增 `-NoRand`）。

### 13.6 我对乙的第 3 点（`min` 落点）的最终表态

**采纳收窄**，并修订 §8.2 与 §12.6 交叉 1：

| 项 | 原定案 | 修订后 |
|---|---|---|
| `min` 执行位置 | 所有步骤（errorCode 之后） | **仅 `kAwaitChallenge`** |
| 第 4 步 `req.version` | 参与回写 | **不参与回写**，但下界检查仍生效 |
| 新增测试 | — | `server_echo_version_does_not_downgrade`（6→6→4，断言 step5 version==6） |

**新增用例设计**（我补充乙没给的细节）：

- 给定：client 6，第 2 步 CHALLENGE `version=6`，第 4 步 echo `version=4`
- 当：走完 step3 → step4 → step5
- 则：
  1. `req5.version == 6`（不是 4）
  2. `c.version() == 6`
  3. step5 的 `auth_info` 非空（正常完成）
- **为什么能抓**：修复前（未收窄）`min(6,4)=4` → 断言 1 红。

### 13.7 汇总：阶段 2 互审结论

| 乙的项 | 我的核实 | 处置 |
|---|---|---|
| D1 一致 | ✅ 同意 | 盖章 |
| D3 一致 | ✅ 同意，且机制解释更完整 | 盖章 |
| §8.8 落点收窄（P2） | ✅ **采纳** | 修订 §8.2 / §12.6，加新用例 |
| N-B1（P0） | ✅ **成立，比乙说的更严重** | **并入批 1**，与 S1 硬绑定 |
| 第 6 点 recv_seq 用例 | ❌ **不成立**（被 `c:84` 拦） | 不写该用例；保留 seq 校验但不测 |
| doc:1789 红证式样坏 | ✅ 成立 | 提醒执行 AI 用 §4.1 驱动式样 |
| preflight 正则误报 | ✅ 成立（我实测 MISS） | 报主代理修正脚本 |
| N6 门禁未落地 | ✅ 成立（verify.ps1 零命中） | 报主代理加门禁 |

**双方一致项**：D1、D3、D2、D4、D5、D6（6/6 全部一致）。
**新增项**：N-B1（P0，需主代理裁决是否扩批 1 范围）。
**否决项**：乙的第 6 点用例。


---

## 14. 对乙 R1 / R2 / R4 的回签（阶段 2 收尾）

> 乙在 `batch1-audit-b.md` §9 提出 R1（N-B1）、R2（落点收窄）、R4（preflight 正则），并问三件事。
> 本节逐条回签。**本轮零 exe、零工程代码改动。**

### 14.1 R1 回签：N-B1 —— **同意，全部接受**

| 项 | 我的回签 |
|---|---|
| N-B1 并入批 1 | ✅ **同意**。理由比「机密性」更硬：S1 修完后 N-B1 原样存在，只修 S1 等于**做了一半**，批 1 无法诚实宣称机密性已恢复 |
| 定案改法（独立 16 字节 `RandomBytes`） | ✅ 同意。已在 §12.1b 与参考实现落地 |
| 失败语义 | ⚠️ **一处分歧**：乙写 `Fail(kInternal, ...)`，我写 `Fail(kUnsupported, ...)`。见 §14.1.1 |
| 用例 `client_nonce_does_not_disclose_session_key` | ✅ 同意，且**采纳乙的「任一 16 字节窗口」加强版**。见 §14.1.2 |
| 「不破现有 15 条」 | ✅ **独立认可**。见 §14.1.3 |

#### 14.1.1 已定案：`credssp::Status::kInternal`（主代理最终裁决，方案 C）

> **演变过程（留档）**：乙原写 `kInternal` → 我发现 `credssp::Status` 里没有该枚举，判为笔误并建议 `kUnsupported` → 主代理裁决 `kMalformed` → 我以三条证据反驳（见 §15）→ **主代理采纳方案 C：新增 `credssp::Status::kInternal`**。

**最终定案**：

```cpp
// include/rtsc/credssp/ts_request.h
enum class Status : uint8_t {
    kOk = 0,
    kTruncated,       // input ended inside a TLV
    kMalformed,       // tag/length/structure violation
    kUnsupported,     // valid structure, value this implementation rejects
    kInternal,        // local environment failure (CSPRNG unavailable, etc.)
};
```

```cpp
// src/credssp/credssp.cpp，N-B1 失败分支
if (!crypto::RandomBytes(exported_session_key_, 16)) {
    return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
}
```

**为什么不是 `kUnsupported`**：`kUnsupported` 的语义是「输入合法但我不支持」，用于协议版本、算法这类**对端协商项**。CSPRNG 不可用是本地环境故障，不是对端的值有问题。

**为什么不是 `kMalformed`**（我反驳的主因，见 §15.4）：批 3 的映射表（`doc:603`）规定 `native_code == 0 && status == kMalformed` → `kind = kProtocolViolation`，会把本地 CSPRNG 故障**误报成「服务器违反协议」**。

**批 3 需同步加一行映射**（主代理已改，`doc:605`）：

| 来源 | 判据 | `kind` | `native_space` |
|---|---|---|---|
| `credssp::Error` | `status == kInternal` | `kInternal` | `kNone` |

**没有这一行**，`kInternal` 会落到 `doc:603` 的兜底（`kMalformed/kTruncated` 那条不匹配，但可能落到「其他」分支）→ 必须显式加。

**成本实测（零风险，主代理已复验）**：
- `credssp::Status` 上无 `switch/case` 穷举（`credssp.cpp`/`ntlm.cpp` switch=0；`ts_request.cpp` 唯一 switch 是 DER tag）
- 无 `static_cast<int>(status)`、无 `status == <数字>`、无 `arr[status]`
- 加枚举值**不触发** `/W4 /WX` 未处理枚举警告

**与 `tls::Status::kInternal` 对齐**：`doc:597` 已映射 `tls::Status::kInternal → kind=kInternal`，两个库语义一致。

#### 14.1.2 采纳乙的加强断言（我原版较弱）

乙要求断言 exported **不是 clientNonce 的任一 16 字节窗口**（`o=0..16`）。我原版只写了 `std::search`，语义上等价但没说明为什么等价。**已补证明**（§12.1b）：

- 32 字节 nonce、16 字节 needle → 窗口偏移 `o ∈ [0, 16]` 共 **17** 个
- `std::search` 命中 ⟺ 存在 `o` 使 `nonce[o..o+16) == exported`
- 修复前 `exported == nonce[8..24)` → `o=8` 命中 → 必红
- 修复后独立随机 → 误报概率 `17 × 2⁻¹²⁸ ≈ 5e-38`，统计上不可能

**这个加强是对的**：只比 `[8..24)` 会漏掉「实现改成从 `nonce[0..16)` 派生」这种半修复。

#### 14.1.3 「不破现有 15 条」—— 我独立认可，依据如下

我把 `exported_session_key_` 的**全部消费点**列出来核对（`c:191/193/196/197/208/215/312/353/384/385`）：

| 消费点 | 用法 | 改来源后是否受影响 |
|---|---|---|
| `c:196` `DeriveSigningKey(exported, false)` | 从 exported 派生 | 否（自洽） |
| `c:197` `DeriveSealingKey(exported, ...)` | 从 exported 派生 | 否（自洽） |
| `c:208` `Rc4Crypt(session_base_key_, exported)` | 用 exported 作为明文 | 否（值变了但协议语义不变） |
| `c:215` `ComputeMic(exported, ...)` | 用 exported 算 MIC | 否（对端也用收到的同一个值） |
| `c:312/353` `DeriveSealingKey(exported, ..., true)` | 派生接收密钥 | 否（自洽） |
| `c:384/385` `MakeServerEchoForTest` | 派生测试用签名/加密密钥 | 否（自洽） |

**全仓无任何测试断言 `exported == nonce 子串`**：
- `t:205` 只把 exported 当 `ComputeMic` 的输入，不假设它的值
- `t:241`/`t:466`/`t:501` 走 `Decrypt*ForTest`，内部用 `sealing_key_`，自洽
- `t:301`/`t:337`/`t:458` 走 `MakeServerEchoForTest`，内部从 exported 派生，自洽

**结论**：乙的 `[未验证-需影子树确认]` 标注可以降级为「**静态推导已确认，仍建议执行 AI 用红→绿实测兜底**」。

#### 14.1.4 关于 `client_challenge = nonce[0..8)`（`c:176`）—— **同意保留不改**

乙判「非必需」，我**同意**，理由比乙更明确：

1. **ClientChallenge 不是秘密**：`security-layer.md:1357` 明确 `ChallengeFromClient = ClientChallenge`，它**明文出现在 NTLMv2 响应里**（`security-layer.md:1041` 的 `LMv2_RESPONSE` 结构含 ClientChallenge）。既然本来就要发出去，用 nonce 的前 8 字节不构成额外泄露。
2. **安全性只取决于不可预测性**：`security-layer.md:1143`「ClientChallenge：8 字节随机」。S1 修完后 `nonce_` 是 CSPRNG，其前 8 字节同样是 8 字节随机，满足要求。
3. **改成独立 8 字节是可选卫生项，但有代价**：会多消耗一次 CSPRNG 调用，且与 N-B1 不同——N-B1 的泄露是**密钥**，这里的「泄露」是**本来就要公开的 nonce 值**，性质完全不同。

**结论：`c:176` 保持不改。** 若未来要统一「所有随机材料独立生成」的风格，可作为 P3 卫生项单独立项，不进批 1。

### 14.2 R2 回签：落点收窄 —— **同意，且我已按「D2 也收窄」修正**

乙指出主代理裁决比乙的方案更进一步：**D2 下界检查也收进 `kAwaitChallenge` 分支**。

我核对了自己的文档，发现**我原稿确实不一致**：
- §8.2 代码把 `if (req.version < kMinVersion)` 放在分支**外**（只收窄了 `min`）
- §12.6 交叉 1 又说「第 4 步新增拒绝点是行为变更」

**这两处自相矛盾**。已修正为最终形态（§8.2 / §8.3）：

```cpp
if (step_ == Step::kAwaitChallenge) {
    if (req.version < kMinVersion) {
        return Fail(Status::kUnsupported, "unsupported TSRequest version");
    }
    version_ = std::min(version_, req.version);
    return BuildStep3(req, out);
}
if (step_ == Step::kAwaitServerEcho) {
    return BuildStep5(req, out);   // 第 4 步不检查、不回写版本
}
```

**修正清单（本轮已改）**：

| 位置 | 原内容 | 现内容 |
|---|---|---|
| §8.2 代码 | D2 在分支外 | D2 + `min` 都在分支内 |
| §8.2 行为矩阵 | 5 行 | 7 行（加「第 4 步 version=1 不拒绝」） |
| §8.3 | 只有 D2，未标收窄 | 标注「已收窄：只在 `kAwaitChallenge` 分支内」 |
| §8.8 锚点 | 「`:105` 与 `:107` 之间插入」 | 「在该分支**内第一行**插入 D2，随后 `min`」 |
| §12.6 交叉 1 | 「新增拒绝点是行为变更」 | 「**收窄后这个变更彻底消失**」+ 三格对比表 |
| §12.7 第 19 条 | 只提 `min` 收窄 | 已含 |
| 参考实现 | `min` 在分支内、D2 在分支外 | 两者都在分支内（静态检查 PASS） |

**乙的行为矩阵我逐格核对，两格关键结论一致**：
- 客户端 4 / 步2=6 / 步4=6 → `version_` 终值 **4**，步3 v4 无 nonce，步5 v4 ✅
- 客户端 6 / 步2=6 / 步4=4 → `version_` 终值 **6**，步5 **v6** ✅（R2 新锁）

**`server_echo_version_does_not_downgrade` 我采纳**，但补了乙没给的细节（§12.3b）：必须断言 **step5 的 `req.version`**（不只是 `c.version()`），因为真正发出去的字段才是协议事实；并明确「第 4 步 `version=4` 仍通过 D2（4>=2），所以是**不降版正常完成**，不是拒绝」。

### 14.3 R4 回签：preflight 正则 —— **乙的修法可用，但正则我建议加强**

乙提议：

```python
present('N-B1', r'exported_session_key_\.assign\(nonce_', False, 'exported key derived from nonce')
```

**我实测了这个正则对定案代码的判定**：

| 输入 | 乙的正则 |
|---|---|
| 修复前 `exported_session_key_.assign(nonce_.begin() + 8, ...)` | **MATCH** ✅ |
| 定案后 `if (!crypto::RandomBytes(exported_session_key_, 16))` | **MISS** ✅ |
| 定案后 `else { exported_session_key_ = session_base_key_; }` | MISS ✅ |

**结论：乙的正则对定案代码不会误报，可用。**

**但我建议加强**（同样实测）：

| 输入 | 乙的正则 | 加强版 |
|---|---|---|
| `exported_session_key_ = Bytes(nonce_.begin()+8, nonce_.begin()+24);`（等号写法） | **MISS** ❌ | **MATCH** ✅ |
| `exported_session_key_.assign(nonce_.data()+8, ...)`（`.data()` 写法） | MATCH ✅ | MATCH ✅ |
| 定案后两种写法 | MISS | MISS |

加强版正则：

```python
present('N-B1', r'exported_session_key_\s*(?:\.assign|=)\s*[^;]*nonce_', False,
        'exported key derived from nonce')
```

**理由**：乙的正则只匹配 `.assign(nonce_`，如果执行 AI 写成 `exported_session_key_ = Bytes(nonce_...)` 或把 `nonce_.begin()` 换成 `nonce_.data()`，门禁会漏。加强版覆盖三种写法，且对定案代码仍 MISS。

**同时确认乙对 `S5b` 的提醒正确**：脚本里 `S5b` 的 `want=False`，修复后跑 preflight 仍打印 BAD —— 这是 pre-flight 的固有语义（它验证「修复前缺陷存在」）。**修复后的判据是测试套件 + 新增用例，不是 preflight 的 RESULT。** 这一点必须写进执行任务，否则执行 AI 会困惑。

### 14.4 乙问的第三件事：还有没有新缺陷？

**我这一轮又核了一遍，没有新的 P0/P1。** 但发现 1 个 **P3 卫生项**（不进批 1）：

#### P3：`DeriveSealingKey(...).data()` 传临时对象给 `Rc4::Init`

`c:312-313` 和 `c:353-354`：

```cpp
recv_rc4_.Init(DeriveSealingKey(exported_session_key_, use_56_bit_key_, true).data(),
               sealing_key_.size());
```

`DeriveSealingKey` 返回 `Bytes`（临时对象），`.data()` 指向它的缓冲区。**在当前代码里是安全的**，因为 `Rc4::Init`（`hash.cpp:342-355`）在调用内**立即读完全部 key 字节**，不保存指针；临时对象在整个完整表达式结束前不会析构。

**但这是脆弱写法**：若将来有人把 `Init` 改成「保存 key 指针延迟初始化」，就会悬垂。**建议**（非必须）：

```cpp
const Bytes recv_sealing_key = DeriveSealingKey(exported_session_key_, use_56_bit_key_, true);
recv_rc4_.Init(recv_sealing_key.data(), recv_sealing_key.size());
```

**第二个参数 `sealing_key_.size()` 是错的语义**：`DeriveSealingKey` 返回的总是 16 字节（MD5 输出），而 `sealing_key_.size()` 也是 16（同样是 MD5）。**当前恰好相等所以无害**，但用 `sealing_key_.size()` 表示「接收密钥长度」是误导。建议用 `recv_sealing_key.size()`。

**定性：P3（可读性/健壮性），不进批 1**，记录待批 3 或后续清理。

### 14.5 盖章状态

| 项 | 状态 |
|---|---|
| D1 / D2 / D3 / D4 / D5 / D6 | ✅ 双方一致 |
| R1 N-B1 | ✅ 我同意；失败状态已定案 `credssp::Status::kInternal`（方案 C，见 §14.1.1） |
| R2 落点收窄（含 D2 也收窄） | ✅ 我同意，且已修正文档自相矛盾 |
| R4 preflight 正则 | ✅ 同意乙的修法，建议加强版 |
| 乙的 `client_challenge` 保留判断 | ✅ 同意 |
| 新缺陷 | 无 P0/P1；1 个 P3 卫生项（§14.4） |

**已闭环**：`kInternal` 的最终形态由主代理裁决为**方案 C（新增枚举值）**（见 §14.1.1、§15）。乙的原始写法在「存在 `kInternal`」这点上是对的，只是当时该枚举尚未定义；我的「笔误」判断在「当前枚举没有该值」这点上是对的。两者合起来指向方案 C。

**批 1 定案：双方盖章条件已满足**（D1–D6 一致、R1/R2/R4 一致、status 定案）。


---

## 15. 对 `kMalformed` 裁决的反驳（附证据）—— **已被主代理采纳，定案改为方案 C**

> **结果：本节的三条论据全部被主代理独立验证成立，`kMalformed` 裁决被推翻，定案改为方案 C（新增 `credssp::Status::kInternal`）。**
> 留档原因：它记录了「为什么不是 `kMalformed`」的完整证据链，避免后续批次重复踩坑。
>
> 原始背景：主代理曾裁决 `Fail(Status::kMalformed, "CSPRNG unavailable ...")` 并邀请反驳。
> 我当时**接受 `kInternal` 是乙的笔误**，但**反对 `kMalformed`**，也**不坚持 `kUnsupported`**；结论在 §15.5：三个候选都不对，正确做法是**给 `credssp::Status` 加 `kInternal`**。

### 15.1 先认错：`want` 我写错了

主代理指出我给的正则里 `want=False` 是错的。**确实是我错**。按 `present()` 的实现（`batch1_preflight.py:57`）：

```python
good = (state == 'PRESENT') == want
```

N-B1 是「缺陷当前存在」类（和 S1/S5 一样），修复前 `state == 'PRESENT'`，要 `good == True` 就必须 `want=True`。
我写 `want=False` 会让**修复前就报 BAD**，语义完全反了。**采纳主代理的 `want=True`。**

### 15.2 主代理的语义论证有事实错误

主代理的理由是：

> `kUnsupported` 的语义是「输入合法但我不支持」……**但 RNG 失败不是对端的问题**，是本地 CSPRNG 不可用。语义上更接近「无法构造合法结构」→ `kMalformed`。

**前半段我同意**（RNG 失败不是对端问题）。**后半段「无法构造合法结构 → kMalformed」在代码里找不到依据**，因为 `credssp.cpp` 里的 `kMalformed` 实际用法与「结构违规」无关：

| 行 | 内容 | 是「结构违规」吗 |
|---|---|---|
| `c:61` | `Fail(kMalformed, "Start called twice")` | ❌ 是**状态机误用** |
| `c:85` | `Fail(kMalformed, "response after completion")` | ❌ 状态机误用 |
| `c:88` | `Fail(kMalformed, "response before Start")` | ❌ 状态机误用 |
| `c:99` | `err.status = kMalformed`（服务器 errorCode 分支） | ❌ **对端报错**，不是本地结构问题 |
| `c:113` | `Fail(kMalformed, "unexpected state")` | ❌ 状态机误用 |
| `c:254` | `Fail(kMalformed, "step 4 without pubKeyAuth")` | ✅ 协议结构 |
| `c:284` | `Fail(kMalformed, "server echo mismatch")` | ❌ **密码学校验失败** |

**统计**（我实测，3 个源文件）：

```
kMalformed     41 次
kTruncated     13 次
kUnsupported    8 次
```

`kMalformed` 已经是「**其他一切**」的兜底桶（41 次，含状态机误用、对端报错、密码学校验失败）。再加一个「RNG 失败」进去，**不增加任何语义信息，只增加桶的混乱度**。

**所以「语义上更接近 kMalformed」这个论断不成立**——在现有代码里 `kMalformed` 的语义已经被稀释成「非 kTruncated、非 kUnsupported 的失败」。

### 15.3 主代理的「可诊断性」理由，被仓库自身的契约否证

主代理的第二条理由：

> 如果 RNG 失败也返回 `kUnsupported`，调用方无法区分「服务器版本 v1 不支持」和「本地 BCryptGenRandom 失败」。**同一个 status 承担两种完全不同的处置**。
> 所以 message 必须写明是 CSPRNG，让调用方靠 message 区分。

**「靠 message 区分」违反仓库的明文契约**：

1. `include/rtsc/net/tls.h:60`（逐字）：
   ```cpp
   std::string message;      // human readable only; never drives control flow
   ```
2. `include/rtsc/credssp/ts_request.h:31-33` 对 `native_code` 的注释强调「Callers must be able to surface it verbatim **instead of guessing from the text**」——即明确反对从文本推断。
3. `docs/spec/security-integration.audit-a.md:614`（批 3 的硬规则 2）：
   > **`detail` 只给人看。** 任何控制流分支都不许 `strstr(detail, "...")`

4. **实测**：全仓 `Error.message` 的**分支判断为 0 处**（我 grep 了 `\.message\s*(==|!=|\.find|\.compare|\.substr|\.rfind)` 和 `message\(\)\s*(==|!=)`，四个目录全部零命中）。

**结论**：主代理的「靠 message 区分」在**当前仓库里没有任何实现基础**，而且与三处明文契约冲突。这条理由不能成立。

### 15.4 决定性的证据：批 3 的错误映射表会让 `kMalformed` 变成「协议违规」

`docs/spec/security-integration.audit-a.md:603-604` 是批 3 `SecurityLayer` 的**已定案映射规则**：

| 来源 | 判据 | `kind` |
|---|---|---|
| `credssp::Error` | `native_code == 0` 且 `status == kMalformed/kTruncated` | **`kProtocolViolation`** |
| `credssp::Error` | `status == kUnsupported` | **`kUnsupported`** |

**若 RNG 失败返回 `kMalformed`**：

```
BCryptGenRandom 失败
  → Fail(kMalformed, "CSPRNG unavailable")
  → native_code == 0
  → 批 3 映射为 kind = kProtocolViolation
  → 上层告诉用户：「服务器违反协议」
```

**这是错误的诊断**——用户会去查服务器/网络，而真正原因是本地加密服务异常。这**正是主代理自己担心的「同一 status 承担两种处置」**，只是方向相反：`kMalformed` 把它**误分类成对端的问题**。

**若返回 `kUnsupported`**：

```
BCryptGenRandom 失败
  → Fail(kUnsupported, "CSPRNG unavailable")
  → 批 3 映射为 kind = kUnsupported
  → 上层告诉用户：「此实现不支持该配置」
```

虽然也不精确，但至少**不误导为服务器问题**。

### 15.5 我的结论：三个候选都不理想，建议二选一

| 方案 | 优点 | 缺点 | 我的评级 |
|---|---|---|---|
| **A. `kMalformed`**（主代理裁决） | 无需改枚举 | **批 3 会映射成 `kProtocolViolation`**，误导为服务器问题；且 `kMalformed` 已是 41 次兜底桶 | ❌ 反对 |
| **B. `kUnsupported`**（我原提议） | 不改枚举；批 3 映射为 `kUnsupported`，不误导 | 语义上「值不支持」也不准（RNG 失败不是值的问题） | ⚠️ 次优 |
| **C. 给 `credssp::Status` 加 `kInternal`** | 语义精确；批 3 可映射为 `kInternal`（`doc:597` 已有 `tls::Status::kInternal → kind=kInternal` 的先例） | 需要改 `ts_request.h` + 检查所有消费点 | ✅ **最优，但需评估成本** |
| **D. 把 RNG 失败改成构造期前置条件**（不在 `BuildStep3` 里随机） | 失败在构造时就暴露，不需要在协议层表达「本地环境故障」 | 构造器没有返回 `Error` 的通道（`credssp.h:42` 是普通构造器） | ❌ 需改 API 形状 |

**方案 C 的成本（我实测）**：

- `credssp::Status` 上**没有** `switch/case` 穷举（`credssp.cpp`/`ntlm.cpp` 的 switch 数为 0；`ts_request.cpp` 唯一那个 switch 是 `kTagVersion` 等 DER tag，不是 `Status`）。**加枚举值不会触发 `/W4 /WX` 的未处理枚举警告。**
- 没有 `static_cast<int>(status)`、没有 `status[...]` 数组索引、没有 `== 数字` 比较（我 grep 了 4 种模式，全部零命中）。
- 只需在 `ts_request.h:21-26` 加一行 `kInternal,  // local failure (CSPRNG, allocation), not the peer's fault`，并在批 3 映射表加一行 `kInternal → kind=kInternal`。

**成本极低，语义正确。**

### 15.6 我的建议

**优先方案 C**（加 `kInternal`），理由：
1. 语义精确：本地故障 vs 对端问题，是**两类完全不同的处置**；
2. 批 3 的 `ErrorKind` 已有 `kInternal`（`doc:597` 映射 `tls::Status::kInternal`），**两个库的枚举对齐**；
3. 成本实测为零风险（无穷举 switch、无整数转换）。

**若主代理认为批 1 不宜改枚举**（怕扩大 diff），则**退到方案 B（`kUnsupported`）**，但**必须在批 3 的映射表加一条例外**：

```cpp
// 批 3 SecurityLayer：native_code==0 时不能只看 status
if (e.status == credssp::Status::kUnsupported && e.native_code == 0 &&
    e.message.find("CSPRNG") != std::string::npos) { /* 违反 doc:614 */ }
```

——不行，这违反 `doc:614`「不许 strstr(detail)」。

**所以如果只能在这两个里选，我选 B（`kUnsupported`）**，因为它的批 3 映射（`kind=kUnsupported`）**至少不把本地故障说成服务器违规**。主代理担心的「无法区分服务器版本 vs RNG」是真实的，但 `kMalformed` 把问题**恶化**成「服务器违规」，比「不精确」更糟。

### 15.7 一句话

- `want=False` → **我错，采纳 `want=True`**。
- `kInternal` 不存在 → **主代理对，是乙的笔误**。
- `kMalformed` → **反对**。决定性理由：`doc:603` 的批 3 映射会把 `native_code==0 && kMalformed` 变成 `kind=kProtocolViolation`，即**把本地 CSPRNG 故障报成「服务器违反协议」**，正是主代理自己反对的「同一 status 承担两种处置」，只是方向反了。
- 建议 **方案 C（加 `kInternal`）**，成本实测为零风险；退路是 `kUnsupported`（批 3 映射为 `kUnsupported`，不误导），**但不是 `kMalformed`**。

**若主代理坚持 `kMalformed`**，我要求同时在 `doc:603` 的映射表加一条前置判据（例如 `message` 前缀约定或新增 `native_code` 专用值），否则批 3 必然误分类。**但这会违反 `doc:614`，所以更干净的做法还是加 `kInternal`。**


---

## 16. 核对主代理的 CSPRNG 跨平台定案（三问答复）

> 主代理已在任务书 §6.2 定案「分文件 + CMake 按平台选源」。我逐条核实。
> **结论：分文件正确（Q1 同意）；但 Q2 的 `getrandom` 有一个真实的可移植性风险，主代理和我此前都没注意；Q3 确认数值与位置。**

### 16.1 先确认主代理的自我更正：正确

主代理说：

> `WINDOWS_H_COUNT` 统计的是构建日志（`$BUILD_LOG`），不是源码文本。所以 `#ifdef _WIN32` 包住 `#include <windows.h>` 时，Linux 上该分支不编译、不进日志，**不触发门禁**。

**我核实成立**：

- `linux-build-gate.sh:53`：`cmake --build "$BUILD_DIR" >"$BUILD_LOG" 2>&1`
- `linux-build-gate.sh:58`：`WINDOWS_H_COUNT=$(grep -c 'windows\.h' "$BUILD_LOG")`

它 grep 的是**构建日志**。Linux 上 `#ifdef _WIN32` 分支不参与编译，`windows.h` 不会出现在日志里 → 不触发门禁。

**但这条自我更正有一个重要含义**（主代理没提）：既然门禁只查日志，**单文件和分文件在「不触发门禁」上是等价的**。所以选分文件的理由不能是「为了过门禁」，只能是可读性/可维护性。

### 16.2 Q1：分文件 vs 单文件 `#ifdef` —— **我同意分文件**

**理由（按强度排序）**：

1. **仓库既有模式是两种都有，但「库内平台差异」用单文件、「跨平台库选择」用分文件**：
   - `src/util/crash_guard.cpp`：**单文件 `#ifdef _WIN32`**（`:8` / `:267` / `:277`），Windows 分支 260 行、非 Windows 分支 8 行
   - `src/net/tls_factory.cpp`：**单文件 `#if defined(_WIN32)`**（`:28` / `:44`），每处 3-4 行
   - `CMakeLists.txt:56-60`：`tls_schannel.cpp` 是**分文件 + `if(WIN32)`**，但那是「整个后端只有 Windows 实现」的库级选择，不是同一功能的两个实现

2. **`random` 的情况更接近「同一功能的两个完整实现」**：
   - Windows 分支：`<windows.h>` + `<bcrypt.h>`，约 10 行
   - POSIX 分支：`<sys/random.h>` 或 `<fcntl.h>`+`<unistd.h>`，约 15-25 行（含 ENOSYS 回退）
   - **两个分支都需要各自的系统头**，混在一个 TU 里会让 include 顺序变得敏感（`<windows.h>` 的宏污染是有名的）

3. **`-Werror -Wpedantic` 下更安全**：分文件时每个 TU 只见到自己的平台头，不会出现「Windows 头在 Linux 上被解析到一半」这种意外。

**所以我同意分文件**，但**理由是可维护性，不是门禁**。

**CMake 写法我同意主代理的版本**，但补一条：`target_sources` 需要 CMake ≥ 3.1（本项目 `cmake_minimum_required(VERSION 3.25)`，满足）。

```cmake
add_library(rtsc_crypto STATIC src/crypto/hash.cpp)
target_include_directories(rtsc_crypto PUBLIC include)
if(WIN32)
    target_sources(rtsc_crypto PRIVATE src/crypto/random_win.cpp)
    target_link_libraries(rtsc_crypto PUBLIC bcrypt)
else()
    target_sources(rtsc_crypto PRIVATE src/crypto/random_posix.cpp)
endif()
```

**注意 `PUBLIC` vs `PRIVATE`**：`bcrypt` 用 `PUBLIC` 意味着所有链接 `rtsc_crypto` 的目标都会传递 `bcrypt`。这**正确**，因为 `BCryptGenRandom` 的符号在 `rtsc_crypto` 里，静态库不会自动带出依赖。**主代理的 `PUBLIC` 是对的。**

（对照 `CMakeLists.txt:44-46` 的 `rtsc_util` → `dbghelp` 也是 `PUBLIC`，一致。）

### 16.3 Q2：`getrandom()` 够不够 —— **我上一轮的断言被自己的实验证伪，已更正**

> **本节是自我更正。** 我上一轮报告主代理「`-std=c++20` 会让 glibc 隐藏 `getrandom` 声明，Linux 门禁必红」。
> 我用 WSL 实测后**证伪了自己**。以下是实测记录，以及仍然成立的结论。

#### 16.3.1 实测环境（真实运行，不是推理）

```
WSL Ubuntu-24.04
g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39
Linux LIULILTE 6.18.33.2-microsoft-standard-WSL2 x86_64
```

#### 16.3.2 我的断言：错

我断言「`-std=c++20` → `__STRICT_ANSI__` → glibc 隐藏 `_DEFAULT_SOURCE` → `getrandom` 未声明」。

**实测（`evidence/exec/batch1-a-csprng-glibc-probe.txt`）**：

```
=== TEST A: -std=c++20 -Wall -Wextra -Werror -Wpedantic ===
exitA=0
=== TEST B: -std=gnu++20 ===
exitB=0
=== TEST C: -std=c++20 + -D_DEFAULT_SOURCE ===
exitC=0
```

**三个都通过。`getrandom` 在 `-std=c++20` 下完全可见。**

#### 16.3.3 真实机制（我查清了根因）

`__STRICT_ANSI__` 确实被定义，但**不起作用**，因为：

1. **g++ 在 Linux 上无条件预定义 `_GNU_SOURCE`**：
   ```
   g++ -std=c++20 -dM -E -x c++ /dev/null | grep GNU_SOURCE
     #define _GNU_SOURCE 1
   ```
   来源是 libstdc++ 的 `os_defines.h:43-44`（`#if __GLIBC_PREREQ(2,15) && defined(_GNU_SOURCE)` 那段的上文），不是用户代码。

2. **glibc `features.h:231-238`**：
   ```c
   #if (defined _DEFAULT_SOURCE                     \
        || (!defined __STRICT_ANSI__                \
            && !defined _ISOC99_SOURCE && ...))
   # undef  _DEFAULT_SOURCE
   # define _DEFAULT_SOURCE 1
   #endif
   ```
   `_GNU_SOURCE` 会先在第 221-222 行置 `_DEFAULT_SOURCE=1`，所以第 231 行的 `__STRICT_ANSI__` 分支根本不会被求值。

3. 实测确认两者**共存**：
   ```
   STRICT_ANSI=yes
   DEFAULT_SOURCE=yes
   ```

4. **`<sys/random.h>` 里 `getrandom` 没有 `__USE_MISC` 守卫**（glibc 2.39）：
   ```c
   __BEGIN_DECLS
   ssize_t getrandom (void *__buffer, size_t __length,
                      unsigned int __flags) __wur
                      __attr_access ((__write_only__, 1, 2));
   ```
   `:34` 是无条件声明。

**结论：`_DEFAULT_SOURCE` 显式定义不是必需的。**

#### 16.3.4 但 `doc:3995-3999` 的草稿仍有两个真问题

**问题 1：没有 EINTR 重试（真实缺陷）**

`doc:3996` 是 `if (r < 0) return false;`。`getrandom(2)` 可以被信号中断返回 `-1/EINTR`。实测草稿编译通过（`exit=0`）但 `grep EINTR` 零命中：

```
=== doc:3995-3999 verbatim, project flags ===
exit=0
=== does it handle EINTR? (inspect) ===
NO_EINTR_HANDLING
```

**后果**：进程收到任何信号（`SIGCHLD`、`SIGWINCH` 等）恰好落在 `getrandom` 期间 → `RandomBytes` 误报失败 → `CredsspClient::Start` 返回 `kInternal` → 握手随机失败。这是**难以复现的间歇性故障**，比编译错误更危险。

**问题 2：没有 `ENOSYS` 兜底（真实但低概率）**

`getrandom(2)` 需要 Linux ≥ 3.17。`ENOSYS` 时草稿直接 `return false`。虽然目标环境（WSL 6.18）不会遇到，但 `/dev/urandom` 兜底是标准做法，成本极低。

#### 16.3.5 修正后的实现（已实测）

```cpp
#if defined(__linux__)
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#endif

#include "rtsc/crypto/random.h"

#include <cerrno>
#include <cstddef>

#if defined(__has_include)
#if __has_include(<sys/random.h>)
#include <sys/random.h>
#define RTSC_HAVE_GETRANDOM 1
#endif
#endif

#include <fcntl.h>
#include <unistd.h>

namespace rtsc::crypto {

namespace {

bool ReadFromDevUrandom(uint8_t* out, size_t size, size_t& done) {
    const int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    while (done < size) {
        const ssize_t n = read(fd, out + done, size - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        if (n == 0) {
            close(fd);
            return false;
        }
        done += static_cast<size_t>(n);
    }
    close(fd);
    return true;
}

}

bool RandomBytes(uint8_t* out, size_t size) {
    if (out == nullptr && size != 0) return false;
    if (size == 0) return true;
    size_t done = 0;
#if defined(RTSC_HAVE_GETRANDOM)
    while (done < size) {
        const ssize_t n = getrandom(out + done, size - done, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) break;
            return false;
        }
        done += static_cast<size_t>(n);
    }
    if (done == size) return true;
#endif
    return ReadFromDevUrandom(out, size, done);
}

}
```

**注意 `#include <fcntl.h>` / `<unistd.h>` 必须无条件**——我第一版把它们放进了 `#if !RTSC_HAVE_GETRANDOM`，结果 ENOSYS 兜底路径调用 `open/read/close` 时未声明，实测报错：

```
error: 'O_RDONLY' was not declared in this scope
error: 'open' was not declared in this scope
error: 'read' was not declared in this scope
error: 'close' was not declared in this scope
```

**这是我自己写的代码里的 bug，已修。** 修后实测矩阵（`-Wall -Wextra -Werror -Wpedantic` 全开）：

| 变体 | 结果 |
|---|---|
| A 完整 getrandom 路径，`-std=c++20` | exit 0，`nonzero=YES differ=YES` |
| B2 `/dev/urandom` 独占路径（守卫强制 0） | exit 0，`nonzero=YES differ=YES` |
| C `-std=c++17` | exit 0 |
| D `-O2` | exit 0 |
| E `-fsanitize=address,undefined` | exit 0，`nonzero=YES differ=YES` |

#### 16.3.6 保留 `#define _DEFAULT_SOURCE` 吗？

**保留，但降级为「防御性」而非「必需」**：

- libstdc++ 保证 `_GNU_SOURCE`（实测），所以**当前工具链下不需要**；
- 但若将来换 libc++ 或非 GNU 工具链，`_GNU_SOURCE` 不保证存在，那时 `_DEFAULT_SOURCE` 就是必需的；
- 显式定义**无副作用**（glibc 会 `#undef` 后重定义，不产生重定义警告——实测 exitC=0）。

**任务书措辞建议**：不要说「不加会编译失败」，而说「显式声明所需的 feature-test 宏，避免依赖 libstdc++ 隐式提供的 `_GNU_SOURCE`」。

#### 16.3.7 回答主代理的三小问（修正版）

1. **要不要 `__has_include` 探测？** **要**，但理由不是 Linux，而是 **macOS**：macOS 没有 `<sys/random.h>`（用 `arc4random_buf`）。当前仓库只跑 Windows + Linux，**若明确不打算支持 macOS，可以省略**，此时直接 `#include <sys/random.h>` 即可（Linux 实测可用）。
2. **`ENOSYS` 退回 `/dev/urandom` 够不够？** **够**。但**优先级应降低**：目标内核 6.18，`ENOSYS` 不会发生。保留它是因为成本 3 行、能覆盖容器/老内核。**不是阻断项。**
3. **现在做会不会过早？** **不过早**（理由见 16.3.8），但**比我上一轮说的容易**——没有 `_DEFAULT_SOURCE` 障碍。

#### 16.3.8 Linux 门禁确实会跑到这个文件（这条仍成立，已实测）

```
$ bash scripts/linux-build-gate.sh
CONFIGURE_EXIT=0
BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_COUNT=0
LIB_BYTES=254140
FACTORY_SYMBOL=present
CTEST_EXIT=0
100% tests passed, 0 tests failed out of 15
LINUX GATE PASS
```

**基线（修复前）Linux 门禁 PASS，15 个测试全绿**。这与 Windows 基线 15/92 的数量一致，证明 `rtsc_credssp_sm_tests` 在 Linux 下**确实构建并运行**。

`CMakeLists.txt:142/172` 无 `WIN32` 守卫，`linux-build-gate.sh:53` 全量构建、`:90` 跑全部 ctest —— **`random_posix.cpp` 批 1 就必须在 Linux 编译通过并通过测试**。这条**没有被证伪，反而被实测确认**。

### 16.4 Q3：`kExportedKeySize` —— **确认新增，数值 16，放 `credssp.cpp:16` 旁**

**核实**：

- `src/credssp/credssp.cpp:16`：`constexpr size_t kNonceSize = 32;`
- `src/credssp/credssp.cpp:17`：`constexpr size_t kSignatureSize = 16;`
- 全文件**无** `kExportedKeySize`

**规范依据**：`docs/spec/security-layer.md:829-830`

```
ExportedSessionKey = 若协商了 KEY_EXCH 且(SIGN 或 SEAL)：
                       16 字节随机数；EncryptedRandomSessionKey = RC4(KeyExchangeKey, ExportedSessionKey)
```

**确认**：

```cpp
// src/credssp/credssp.cpp，在 :17 之后
constexpr size_t kExportedKeySize = 16;   // security-layer.md:830 "16 字节随机数"
```

**放置位置**：与 `kNonceSize` / `kSignatureSize` 同处匿名 namespace（`c:12-30`）。理由：三者都是 CredSSP 的线格式常量，放在一起便于对照规范。

**注意**：`kSignatureSize = 16` 也是 16，但**语义不同**（签名头长度 vs 会话密钥长度），**不能复用**。必须单独定义，否则将来若签名格式变成 20 字节会连带改错密钥长度。

**是否放 `credssp.h` 暴露给调用方？** **不要**。它是实现细节，调用方不需要知道导出密钥是 16 字节。放 `.cpp` 的匿名 namespace 即可。

### 16.5 汇总：三问答复

| 问题 | 主代理的定案 | 我的核对结论 |
|---|---|---|
| **Q1** 分文件 vs 单文件 | 分文件 | ✅ **同意**（理由是可维护性/宏隔离，**不是**门禁——门禁只查日志，两者都能过） |
| **Q2** `getrandom` 够不够 | `getrandom` + ENOSYS 退 `/dev/urandom` | ✅ **同意，且比我上一轮说的更容易**。我上一轮断言「`-std=c++20` 会隐藏 `getrandom`」**已被 WSL 实测证伪**（libstdc++ 预定义 `_GNU_SOURCE` → `_DEFAULT_SOURCE` → `__USE_MISC`，实测 exitA=0）。**真实缺陷只有一个**：`doc:3996` 无 EINTR 重试 → 信号打断时误报失败。必须加 EINTR 重试 + `<fcntl.h>`/`<unistd.h>` 无条件包含 |
| **Q3** `kExportedKeySize` | 新增 16，放 `credssp.cpp:16` 旁 | ✅ **确认**。数值 16（`security-layer.md:830`），放匿名 namespace，**不要**与 `kSignatureSize` 复用 |

### 16.6 必须补进任务书的一条（我的增量，已实测确认）

**Linux 门禁会跑批 1 的新测试**：

```
CMakeLists.txt:142  add_executable(rtsc_credssp_sm_tests ...)   <- 无 WIN32 守卫
CMakeLists.txt:172  add_test(NAME credssp_sm ...)               <- 无 WIN32 守卫
linux-build-gate.sh:53  cmake --build "$BUILD_DIR"              <- 构建全部
linux-build-gate.sh:90  ctest --output-on-failure               <- 跑全部
```

**实测基线（修复前，干净树）** —— `evidence/exec/batch1-a-linux-gate-baseline.txt`：

```
CONFIGURE_EXIT=0
BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_COUNT=0
LIB_BYTES=254140
FACTORY_SYMBOL=present
CTEST_EXIT=0
100% tests passed, 0 tests failed out of 15
LINUX GATE PASS
```

**15 个测试**，与 Windows 基线的 `credssp_sm` 15 条一致 —— 证明 `rtsc_credssp_sm_tests` 在 Linux 下**确实构建并运行**，不是被跳过。

**所以**：`random_posix.cpp` 不是「第二阶段的事」，**批 1 就必须在 Linux 上编译通过并让新测试绿**。

**建议任务书明确写**：

> 批 1 的验收包含 `verify.ps1 -LinuxBuild`。`random_posix.cpp` 必须现在就能编译（`-std=c++20` + `-Werror -Wpedantic`）并通过 `ctest`。若 Linux 环境缺失（无 WSL），按 `verify.ps1:359` 的规定**视为 FAIL**，不是 skip。

### 16.7 自我更正记录（审计诚信）

本轮我向主代理发过一个**错误结论**，现记录更正过程：

| 项 | 我上一轮的说法 | 实测结论 | 状态 |
|---|---|---|---|
| `-std=c++20` 隐藏 `getrandom` | 「Linux 门禁**必红**，必须加 `_DEFAULT_SOURCE`」 | **错**。libstdc++ 预定义 `_GNU_SOURCE`，`getrandom` 可见，`exitA=0` | **已撤回** |
| `doc:3996` 缺 EINTR | 「必须加」 | **对**。实测草稿 `NO_EINTR_HANDLING` | **保留** |
| `ENOSYS` 兜底 | 「必须」 | **降级为可选**。目标内核 6.18 不会触发 | **降级** |
| Linux 门禁会跑新测试 | 「`random_posix.cpp` 批 1 必须可编译」 | **对**。实测基线 15 tests PASS | **保留** |
| 我自己的实现 | （第一版） | **有 bug**：`<fcntl.h>/<unistd.h>` 放在条件块内，ENOSYS 路径未声明 `open/read/close` | **已修并实测** |

**教训**：这是「推理代替验证」的典型错误。我在没有 Linux 环境时凭 glibc 行为记忆下断言，且用了「必红」这种强措辞。**审计结论必须先有可执行证据。** 本轮已补上 WSL 实测（`evidence/exec/batch1-a-csprng-glibc-probe.txt`、`batch1-a-csprng-portability-probe.txt`、`batch1-a-linux-gate-baseline.txt`）。

---

## 17. 批 1 交付验证（审计甲独立复核）

> 执行 AI 已交付。以下全部为**独立复跑**，不采信其报告读数。
> 证据：`evidence/exec/batch1-a-redproof-a.txt`、`batch1-a-linux-verify-a.txt`、
> `batch1-a-verify-delivery.py`（30 项）、`batch1-a-positive-control.py`。

### 17.1 A. 红证复现 —— **8/8 RED，隔离影子树**

执行 AI 报告「8/8 RED」。我用**私有影子树**（`F:\rtsc\.tmp\redproof_tree`）重做，
避免污染共享工作树（执行 AI 报告 19:35/19:36 verify 撞到变异版，那正是我早期
版本直接改真实树造成的；已改为影子树）。

| 变异 | 预期红用例 | 结果 |
|---|---|---|
| S1 nonce 改回常量 | `two_constructions_have_different_nonces` | **RED-OK** |
| S5 删下界检查 | `version_below_min_is_rejected_with_valid_challenge` | **RED-OK** |
| S6 删 `std::min` 回写 | `server_version_is_echoed_back` | **RED-OK** |
| N-B1 改回 `nonce[8..24)` | `client_nonce_does_not_disclose_session_key` | **RED-OK** |
| S11 删 MAC 比对 | `tampered_signature_checksum_is_rejected` | **RED-OK** |
| S18 删公钥守卫 | `start_without_public_key_fails` | **RED-OK** |
| R2 step4 回写版本 | `server_echo_version_does_not_downgrade` | **RED-OK** |
| D6 版本检查前移 | `error_code_wins_over_bad_version` | **RED-OK** |

**基线**（未变异影子树）：`23 tests, 205 checks, 0 failing`。
**恢复后**：`23 tests, 205 checks, 0 failing`。
**真实树 SHA256 前后一致**：`abb7313e47afd42f...ce428b`（`real tree untouched = True`）。

**变异方式修正**：我第一版用 `if (false && ...)` 触发 MSVC **C4127**（常量条件，
`/W4 /WX` 下是错误）→ 3 条变异 `BUILD-FAIL`。改为**删除修复代码**（还原修复前
行为）后 8/8 通过。这不是被测代码的问题，是我的变异手法问题。

### 17.2 B. 实现正确性 —— **通过**

| 审查点 | 结论 | 依据 |
|---|---|---|
| `FillBuffer` 不吞真实错误 | ✅ | `random_posix.cpp:92-93`：`getrandom` 失败且 `!unsupported` 时 `return false`，只有 `ENOSYS` 才退 `/dev/urandom` |
| `RandomBytes` 失败不留脏数据 | ✅ | scratch buffer + 失败 `out.clear()`；实测 `null,n=4 → ret=0`、`n=0 → ret=1 size=0` |
| `nonce_.clear()` 冗余 | ✅ 无害 | `RandomBytes(v,n)` 失败已 `clear()`，调用方再 `clear()` 是幂等空操作；**保留更安全**（防将来换实现） |
| `c:423` seq 校验先于 MAC = oracle？ | ✅ 否 | 两条失败路径都 `Fail(kMalformed)` 并中止，对端不可区分；`message` 按 `tls.h:60` 不驱动控制流 |
| `kInternal` 是否滥用 | ✅ 否 | `credssp.cpp` 仅 `:236` 一处（CSPRNG 失败）；`doc:605` 已登记映射 |
| Windows `ULONG` 截断 | ✅ 已防 | `random_win.cpp:27-30` 按 `0x10000000` 分块 |
| CMake 平台隔离 | ✅ | `CMakeLists.txt:44-49`：`if(WIN32)` 内 `bcrypt`，`else()` 用 posix |

### 17.3 C. 8 条用例是否真断言 —— **通过**

| 用例 | 关键要求 | 实测 |
|---|---|---|
| `two_constructions_have_different_nonces` | 驱动到第 3 步 | ✅ `t:537` 调 `OnServerResponse`；比较 `client_nonce`（`t:541-544`）+ 4 次循环两两不同（`t:552-555`） |
| `client_nonce_does_not_disclose_session_key` | 查全部 17 窗口 | ✅ `t:760-762` 用 `std::search` 全文搜索（等价 17 窗口），另加 `exported[0]!=exported[1]`（`t:767`） |
| `error_code_wins_over_bad_version` | 有对照组 | ✅ `t:829-844` 独立客户端 `d`，`version=1` 无 errorCode → `kUnsupported` |
| `server_version_is_echoed_back` | 两组 A/B | ✅ A 组 6→3（`t:608-627`）、B 组 4→4 防 clamp（`t:629+`） |

### 17.4 D. 门禁与套件（独立复跑）

```
rtsc_credssp_sm_tests : 23 tests, 205 checks, 0 failing
rtsc_ntlm_tests       : 27 tests, 136 checks, 0 failing
rtsc_credssp_tests    : 23 tests,  69 checks, 0 failing
verify.ps1 -DocCite   : exit=0（43/43 citations）
verify.ps1 -LinuxBuild: exit=0（LINUX GATE PASS，Windows ctest 16/16，Linux 15/15）
Linux 独立构建         : 23/205/0，ERRORS=0，WINDOWS_H=0，random_posix.cpp 已链接
N6 门禁实测           : 写入 random_probe_mutant.cpp 的 rand() 被抓到，已清理
```

### 17.5 判定：**批 1 通过**

八条缺陷全部落地、红证可独立复现、实现无安全缺陷、用例真断言、双平台门禁全绿。

**一条范围说明（不是缺陷）**：`SetServerPublicKey` 生产 setter 已实现，但**尚无生产调用点**
（`CredsspClient` 目前只被测试构造）。这是**正确**的——`doc:1807` 规定调用点在
**新增 `src/sec/security_layer.cpp`**，而该文件属于 **S2/批 2**（`src/sec/` 当前不存在）。
批 1 的边界是「setter + 入口守卫」，调用点随批 2 落地。

> **给批 2 实现者的显式警告**：批 1 之后，若构造 `CredsspClient` 而不调
> `SetServerPublicKey`，`BuildStep3` 会 `Fail(Status::kUnsupported, "server public key not set")`。
> **这是 fail-closed 的设计意图，不是回归，不要去「修」它。**
> 空公钥会让 `pubKeyAuth` 退化成 `SHA256(magic || nonce || "")`，服务器若校验则第 4 步必败；
> 更糟的是某些实现对空绑定不报错，客户端会**静默失去唯一的 MITM 防护**。
> 因此 `credssp.cpp:146-148` 的守卫必须保留，正确做法是批 2 在 `SecurityLayer` 里
> 从 `TlsTransport::PeerSubjectPublicKey()` 取值后调用 `SetServerPublicKey`。

### 17.6 审计过程中我自己犯的错（记录）

1. **早期直接改真实树做变异** → 撞到执行 AI 的 verify（其报告 §7 坑 #2）。已改影子树。
2. **`if (false && ...)` 变异触发 C4127** → 3 条 BUILD-FAIL。改为删除式变异。
3. **检测器 4 个假阳/假阴**（D5 只查存在不查顺序、D4 混淆收发方向、D6 锚点撞构造器）
   → 靠正向对照（参考实现）发现并修正。**没有正向对照，D5/D4 会把错判成对。**

---

## 18. 批 2 审计框架预研（只读，S7 S8 S9 S10 S19 S22 S23 S24）

> 范围 `security-integration.audit-a.md:3815`（§19.3.3）。**未改 `src/`/`include/`/`tests/`，未跑变异，未构建。** 冲突处以此为准。

### 18.1 A. 锚点

独立复跑 `tls_schannel.cpp`（748 行）：S24-a `:411`、S24-c `:413`、S24-b `:431`、S22 `:435`、S19 `:473`、S23 `:301`、S10 `:169` 均唯一；S9 命中 `:106`/`:209`/`:232`。

**S9 消歧规则成立但脆弱**：`Receive` 签名 `:230`，其后第一处是 `:232`。若在两者之间插入另一处 `closed_` 检查，或签名被改写（命中 0/2 次），规则失效。**建议改用函数体内唯一语句锚点 `if (terminal_) return last_error_;`（`:233`）。** **⚠️ 此建议已被实测推翻，见 §18.7 勘误 1。**

**S23 锚点与变异点不同行**：`:301` 只定位上下文，**变异改 `:305` 的 `MakeError(Status::kClosed, st, ...)` 第二个实参**。§19.3.3 未说改哪行，执行 AI 会改错。

### 18.2 B. 红证可构造性 —— 6 条用例缺失（复跑确认）

26 个 `RTSC_TEST` 中只有 `shutdown_is_idempotent`(`t:848`)、`send_splits_oversized_payload_instead_of_failing` 存在，其余 6 条全缺。

**问题 1：S24-a / S24-c 都无法变红（比主代理说的更严重）**

`t:848-862` 仅 4 条断言，全文件 `first[0]`/`==21`/`0x15` 零命中：
- **S24-a**（token 改回空）→ 基线 `out=201`（重协商记录）仍非空 → `!first.empty()` 成立 → **STILL GREEN**
- **S24-c**（去掉返回值检查）→ `:413` 是**裸调用**，**没有可删的检查** → **变异无法构造**

**答三问**：
1. **新写 `shutdown_emits_close_notify_alert`**，不补强。`shutdown_is_idempotent` 测"重复无副作用"，与"发 alert 还是重协商"正交；合并会让两种失败无法区分。断言 `CHECK_EQ(Opaque(first[0]), Opaque(0x15));`（`Opaque()` 在 `t:237`，专避 C4127）。
2. **S24-a 靠 `first[0]==0x15`；S24-c 靠规则级断言**——抽 `status→Status` 映射函数，断言 `MapShutdownStatus(SEC_E_UNSUPPORTED_FUNCTION) != kOk`（`s24b-red-correction.md` 已验证）。**共用一条用例不叫互相验证，叫共用兜底。**
3. **S24-c 缺陷存在**（`doc:2762` 记 `:413` 丢弃返回值），但**修复是"加检查"不是"删检查"**。§19.3.3 的"变异=去掉检查"**只有修完后才可构造**。

**问题 2：S19 现有用例假绿**

`t:868-889` 已覆盖"只要 1.3"，但 `if (!started) { CHECK(!why.empty()); return; }`：S19 未修时 `AcquireCredentialsHandle` 返回 `SEC_E_ALGORITHM_MISMATCH` → `started==false` → 断言通过 → **return，绿**。新用例必须 `CHECK(started);`。**`t:868` 不要改**——它测"不许静默降级"，语义不同。

**问题 3：S22 是两处，方向相反**

| 位置 | 缺陷 | 修复 |
|---|---|---|
| `:407-410` 未握手 | 返回 `kOk` 但不拒绝 | 改 `Fail(kProtocolError)`（`doc:3851`） |
| `:435` ISC 失败 | 返回 `kOk` 但不置 `closed_` | 置 `closed_ = true`（`doc:2092`） |

**§19.3.3 只写 `:435`**；只修它，`shutdown_before_handshake_is_rejected` 仍红。

| 缺陷 | 用例 | 变异 | 风险 |
|---|---|---|---|
| S24-a | 需新写 | ✅ | 与 S24-c 共用旧用例互相掩盖 |
| S24-c | 需规则级断言 | ⚠️ 修复前不可构造 | 必须抽映射函数 |
| S24-b | 需新写 | ✅ | 已有三条红证 |
| S22 | 需新写 | ✅ 两处分别删 | `:407`/`:435` 方向相反易漏 |
| S9 | 需新写 | ✅ | 与 S24-a 干扰 |
| S19 | 需新写 | ✅ | 现有 `t:868` 假绿 |
| S23 | 需新写 | ✅ 改 `:305` | 锚点≠变异点 |
| S10 | 需新写 | ✅ | **需真实 EXTRA，构造难度未验证** |

### 18.3 C. 互相干扰

`Shutdown`(`:404-436`) 内含 S24-a/S24-c/S24-b/S22(`:435`)/S9。

| 干扰对 | 机制 | 处置 |
|---|---|---|
| **S24-a ↔ S9** | S24-a 未修时 `closed_` 仍置 true(`:432`)，S9 用例照样红——**红因不同** | S9 用例须**同时断言** `first[0]==0x15` 与 `Receive` 仍取到数据 |
| **S24-a ↔ S24-c** | 共用旧用例互相掩盖 | 各自专属判据 |
| **S24-b ↔ S22** | 同在 `:431-435`，变异都影响 `closed_` | 分别断言 `status` 与 `closed()` |
| **S19 ↔ `t:868`** | 现有用例假绿 | 新用例断言 `started==true` |

**跨函数**：S7（`kPeerAlert` 从不产生）**不在批 2 的 8 条内**；修 S23 时若顺手加 alert 解析会**部分实现 S7 而不自知**，建议明确"只做 `SEC_I_CONTEXT_EXPIRED` 映射"。S10↔S9 不同函数无干扰，但都动 `rx_buffer_` EXTRA(`:324-331`)，**S9 用例不要依赖 `extra_len`**。

### 18.4 D. 对 §19.3.3 的 5 条修改

1. S24-c「去掉返回值检查」当前无可删 → 改「修复=加检查；红证=抽映射函数断言规则」
2. S24-a/S24-c 共用 `shutdown_is_idempotent` → 新增 `shutdown_emits_close_notify_alert`
3. S22 只写 `:435` → 明确含 `:407` + `:435`，方向相反
4. S23 锚点 `:301` ≠ 变异点 → 写明改 `:305` 的 `st` 实参
5. S19 未强调 `started==true` → 否则 `t:868` 模式假绿

### 18.5 TDD 顺序与门槛

```
1. 写 6 条新用例 + 1 条 shutdown_emits_close_notify_alert → 期望 7 条红
2. 修 8 处（S24×3 + S22×2 + S9 + S19 + S23 + S10）
3. 跑：7 条绿，既有 26 条不回归
4. 8 条变异逐条红（S24-c 用规则级断言）
```
门槛：`>= 32 tests`（26+6）应改 **`>= 33`**；checks `>= 139` 需重算。

### 18.6 局限

未实测任何变异（只读约束），"可构造"是静态推断。**S10 的"未验证"已被推翻——实测可构造，见 §18.7 勘误 2。** S24-b 方法引自他人证据，**未复跑**。

### 18.7 勘误（两处原判断被推翻，保留原文留痕）

> 以下两条是**我（审计甲）在 §18.1 / §18.6 里写错的判断**。原文不删，在此更正。
> 保留的理由：下一个人读到 §18 时，应看到"这里曾经错在哪"，而不是只看到正确结论。

#### 勘误 1：S9 的替代锚点 —— **我建议的文本命中 3 次，与原锚点同病**

**我在 §18.1 写的（错误）**：
> 建议改用函数体内唯一语句锚点 `if (terminal_) return last_error_;`（`:233`）。

**实测**：
```
105: if (terminal_) return last_error_;
208: if (terminal_) return last_error_;
233: if (terminal_) return last_error_;
```
**命中 3 次**，与被我批评的原锚点（`closed_` 守卫，也是 `:106`/`:209`/`:232` 三次）**完全一样的病**。
**我批评别人时犯了同一个错。**

**正确做法（主代理提出，我复跑确认）—— 双边界区间锚点**：

```
上界（唯一）：Error Receive\(const uint8_t\* ciphertext      -> :230
下界（唯一）：size_t progressed = 0;                          -> :239
规则：取区间 (230, 239) 内的 if (closed_) 守卫 -> 恰好 1 处，即 :232
```

实测区间内容：
```
231:     std::vector<uint8_t>& plaintext, size_t max_out) override {
232:         if (closed_) return MakeError(Status::kClosed, 0, "already closed");   <== 唯一
233:         if (terminal_) return last_error_;
234: (blank)
235:         if (size != 0 && ciphertext != nullptr) {
236:             rx_buffer_.insert(rx_buffer_.end(), ciphertext, ciphertext + size);
237:         }
238: (blank)
```

**为什么区间规则更强**：它不依赖"相对位置"也不依赖"唯一文本"，而是**上下界都唯一 + 区间内计数必须为 1**。
若将来在 `:230-239` 之间插入第二处 `closed_` 守卫，区间内命中数变 2 → **脚本报错而不是静默选错**。
这正是我原本想要、但给错方案没能做到的性质。

**我另外查了 4 个可能的坑，均不成立**：
| 坑 | 结果 |
|---|---|
| 区间内有注释提到 `closed_` 干扰匹配 | **无**（零命中） |
| `Receive` 有重载导致签名锚点歧义 | **无**（`:230` 唯一实现；`:108`/`:341` 是注释；`tls.h:161` 在别的文件） |
| `size_t progressed = 0;` 在别处出现 | **唯一**（`:245`/`:260`/`:273` 是使用点，非声明） |
| 空行会被误认作插入点 | 有 2 个空行（234/238），但**都不含 `closed_`** |

**教训**：我提出的"唯一锚点"没有实测唯一性。**提替代方案前必须先跑一遍命中数**——否则只是把旧问题换了个文本。

#### 勘误 2：S10 的红证 —— **可构造，且早已实测；我的"未验证"是错的**

**我在 §18.6 写的（错误）**：
> S10 的 EXTRA 构造难度**未验证**……这条可能不可构造。

**证据链完整存在（我逐份读过）**：

| 文件 | 大小 | 内容 |
|---|---|---|
| `evidence/s10/probe_s10.out.txt` | 2160 B | M1–M5（含 M3 `consumed=98/98`、M4 `buffered_input=0`） |
| `evidence/s10/probe_s10b.out.txt` | 1180 B | M6/M7/**M8 `total recovered = 0 bytes`** |
| `evidence/s10/probe_s10c.out.txt` | 552 B | TLS 1.3 ticket 合段 |
| `evidence/s10/probe_s10d.out.txt` | 813 B | F1–F4（切片器修复验证） |
| `evidence/s10/probe_s10e.out.txt` | 891 B | **G1–G4（`recovered 18 bytes`）** |
| `evidence/tls/s10-measurement.md` | 5039 B | 机制分析与修复方向 |
| `.tmp/probe_s10/probe_s10e.cpp` | 16698 B | 源码仍在 |

**"未修 0 字节 / 修后 18 字节"对照成立**（同一场景：98 = 51 Finished + 47 app）：

未修（`probe_s10b` M8）：
```
Handshake(98) -> status=0 consumed=98 complete=1
Receive#0 -> status=1 plaintext=0 buffered_input=0
total recovered from transport alone = 0 bytes
M8 VERDICT: app data LOST (transport claims 98 consumed, keeps 0)
```

修后（`probe_s10e` G1/G2）：
```
Handshake(98) -> status=0 consumed=98 complete=1 buffered=47
Receive#0 -> status=0 plaintext=18 buffered=0
recovered 18 bytes: "S10-PAYLOAD-MARKER"
G2 VERDICT: app data after fix = RECOVERED (fix works)
```

**我错在哪**：我只读了 `tls_schannel.cpp:166-169` 的注释：
```
// Handshake input is fully absorbed: SChannel's stream handshake does
// not report EXTRA, and leaving bytes unconsumed would make the caller
// replay them forever.
consumed = in_size;
```
看到"SChannel 不报 EXTRA"就推断"那确实没有 EXTRA，所以不可构造"。

**这句注释描述的是事实，但结论是错的**：不报 EXTRA 意味着**必须自己切片**，不是可以忽略。
更关键的是我漏了 `s10-measurement.md` §4 第 3 点：
> `DecryptMessage(app record alone)` 返回 `SEC_E_OK, plain=7` —— 说明 SChannel **没有**把那条
> 应用记录当握手数据处理掉，**密文仍然可解，只是调用方手里已经没有了**

这条直接证明"修复可行"（密文还在，自己切片就能捞回来），也就证明红证可构造。

**教训**：读代码注释时要警惕"注释在描述缺陷而不是事实"。我读了注释，但没读同一问题的**实测结论文档**。
**现象（probe 输出）和机理（measurement.md 的推论）是两份材料，缺一不可。**

**补一条严重度**：`s10-measurement.md` §11.3 记明 S10 在**真实 RDP 时序下不可达**
（服务器不会在 Finished 后立刻塞应用数据），严重度 **P1 → P2 防御性**。
所以红证虽可构造，**优先级可排最后**。
