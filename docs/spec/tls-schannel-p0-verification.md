# P0：SChannel TLS 后端对 kStrict/kTofu 均不做任何证书校验

**发现者**：审计乙 `ses_e716db855ffeRMsQQ9mKXRozwe`（阶段 2 交付复核）。
**核实者**：父代理（本节所有 `[READ]` 均由父代理独立复查）。
**级别**：P0（安全）。**非本批引入**（既有缺陷），但使阶段 2 的 D-A3 修复在 Windows 上失效。

---

## 1. 缺陷事实

`src/net/tls_schannel.cpp:140-155`：

```cpp
DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
            ISC_REQ_STREAM;
switch (config_.cert_policy) {
    case CertPolicy::kInsecure:
        req |= ISC_REQ_MANUAL_CRED_VALIDATION;
        break;
    case CertPolicy::kStrict:
        // DEFERRED lets the chain result be queried afterwards; MANUAL
        // would make kStrict indistinguishable from kInsecure.
        req |= ISC_REQ_MANUAL_CRED_VALIDATION;   // ← 注释与代码自相矛盾
        break;
    case CertPolicy::kTofu:
        req |= ISC_REQ_MANUAL_CRED_VALIDATION;
        break;
}
```

**三种策略全部**使用 `ISC_REQ_MANUAL_CRED_VALIDATION`（= "由调用方自行校验"），
而调用方**从未校验**：

- `:663-677` 握手完成后只查询 `SECPKG_ATTR_STREAM_SIZES`，无 `CertGetCertificateChain`、
  无 `SECPKG_ATTR_CERT_CHECK_RESULT`、无主机名比对。
- `:437-473` 虽有 `PeerSubjectPublicKeyInfo()`，但**没有任何地方**把它与
  `config_.pinned_spki_sha256` 比较（全文件 grep 无 memcmp / SHA-256）。
- 注释 `:148-149` 明写"MANUAL would make kStrict indistinguishable from kInsecure"，
  却仍然写了 MANUAL —— 注释是正确意图，代码是错误实现。

## 2. 影响面（为何是本项目最严重的安全缺陷）

`src/net/tls_factory.cpp:36-42`：

```cpp
#if defined(_WIN32)
    if (want_default || backend == "schannel") {
        return CreateSchannelTransport(config, why);   // Windows 唯一后端
    }
```
OpenSSL 后端仅在 `#else` / `RTSC_TLS_OPENSSL` 下存在。

**结论**：在本机（Windows），**所有 TLS 连接都是零证书校验**，包括：

1. 直连 RDP 的 CredSSP（`credssp.cpp` 的 step5 密码密封只依赖会话密钥）→
   中间人可解出**明文密码**。
2. 阶段 2 新增的网关外层 TLS → 同上。
3. `--gateway-trust=<spki>` 的 pin **纯装饰**（SChannel 从不比较）。

阶段 2 的 D-A3 把 `main.cpp` 默认值从 `kInsecure` 改成 `kStrict`，看起来修好了，
但在 Windows 上**行为完全不变**——这正是"测试绿灯掩盖真实缺陷"的又一例。

## 3. 对照：OpenSSL 后端是正确实现

`src/net/tls_openssl.cpp:118-126`：

```cpp
switch (config_.cert_policy) {
    case CertPolicy::kInsecure:
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        break;
    case CertPolicy::kTofu:
    case CertPolicy::kStrict:
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);   // 两者都做链校验
        break;
}
```
- `:151-153`：仅 `kStrict` 额外 `SSL_set1_host(sni)`（主机名校验）。
- `:427-445`：`kTofu` + `pin_is_set` 时做 `EVP_Digest(SPKI, SHA-256)` 并与
  `pinned_spki_sha256` 做 `memcmp`。

即 OpenSSL 的语义是：**kTofu = 链校验 + 可选 pin；kStrict = 链校验 + 主机名**。
SChannel 需镜像这个语义。

## 4. 测试盲区（为何没被测出来）

`tests/test_tls.cpp:246-251`：

```cpp
Config InsecureConfig() {
    Config c;
    c.peer_host = "localhost";
    c.cert_policy = CertPolicy::kInsecure;   // ← 全部用例都用这个
    return c;
}
```

全部 TLS 用例只跑 `kInsecure`，**没有任何 kStrict / kTofu 用例**，
因此后端不实现校验也不会有测试变红。

## 5. 修复指令（F1，P0）

1. `src/net/tls_schannel.cpp:143-155`：`kStrict` 与 `kTofu` 改用
   `ISC_REQ_DEFERRED_CRED_VALIDATION`（`kInsecure` 保留 MANUAL）。
2. `InitializeSecurityContextW` 返回 `SEC_E_OK` 后、`handshake_complete_ = true` 之前：
   - **kTofu + `pin_is_set`**：取 `PeerSubjectPublicKeyInfo()` →
     SHA-256 → 与 `pinned_spki_sha256` 逐字节比较，不等则
     `Fail(Status::kCertRejected, "SPKI pin mismatch")`（镜像
     `tls_openssl.cpp:427-445`）。
   - **kStrict**：`QueryContextAttributesW(SECPKG_ATTR_CERT_CHECK_RESULT)` 取链结果，
     `CertGetCertificateChain` 校验链 + 主机名对照 `peer_host`/`sni`，
     失败则 `Fail(Status::kCertRejected, ...)` 并给出可报告原因。
   - **kInsecure**：不变（MANUAL，不校验）。
3. `tests/test_tls.cpp`：新增 SChannel 侧用例
   - `schannel_kstrict_rejects_self_signed_peer`（loopback 自签证书在 kStrict 下必须握手失败）
   - `schannel_ktofu_pin_mismatch_is_rejected`（错误 pin 必须失败）
   - `schannel_kinsecure_still_accepts_self_signed`（回归：kInsecure 仍可用）
   - 保留现有 `InsecureConfig()` 用例不变（它们测的是记录层，不是校验层）。
4. 变异红证：把 `kStrict` 改回 MANUAL → kStrict 拒绝用例必须转红。

## 6. 不修的风险（明确写出）

若不修，阶段 2 的 `--gateway` / `--gateway-trust` / 默认 `kStrict` 全部是安全剧场，
且直连 CredSSP 也暴露明文密码。故 F1 为阶段 2 的**签署前置条件**。

## 7. 连带项（F2，独立提交）

`tools/rtsc_connect/main.cpp:109` 仍写死 `CertPolicy::kInsecure`。
必须在 F1 之后、作为独立提交修复（默认改 kStrict + 新增 `--tls-insecure` 逃生开关），
理由：同类风险（CredSSP step5 明文），但改动面与阶段 2 无关，混入会使阶段 2 的
冻结 SHA 作废。

---

## 8. 父代理修复指令的 API 错误（执行 AI 探针纠正，2026-10-31）

执行 AI `ses_e70fdf498ffeYs1dPwL4nS6qr3` 用本机探针证明：**第 5 节的两处 API 用法是错的**。
父代理已在 SDK 头文件中独立复核并确认。

### 8.1 `ISC_REQ_DEFERRED_CRED_VALIDATION` 不能用（会被截断为 0）

`[READ: C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared\sspi.h:612]`
```c
#define ISC_REQ_DEFERRED_CRED_VALIDATION 0x0000000200000000
```
`[READ: sspi.h:1716]` `InitializeSecurityContextW(..., _In_ unsigned long fContextReq, ...)`
—— `fContextReq` 是 **32 位 `unsigned long`**，`0x0000000200000000` OR 进去会被截断成 **0**，
等于什么都没做。**这条指令若被盲目执行，修复会静默失效**——正是本项目反复出现的缺陷类型。

### 8.2 正确机制是**凭据级** `SCH_CRED_DEFERRED_CRED_VALIDATION`

`[READ: ...\um\schannel.h:678]`
```c
#define SCH_CRED_DEFERRED_CRED_VALIDATION            0x04000000
```
须在 `AcquireCredentialsHandle` 的 `SCHANNEL_CRED.dwFlags` 中置位（客户端凭据），
而不是在 `ISC_REQ_*` 里。

### 8.3 `SECPKG_ATTR_CERT_CHECK_RESULT` 的结构体字段名

`[READ: ...\um\schannel.h]`
```c
typedef struct _SecPkgContext_CertificateValidationResult {
    DWORD   dwChainErrorStatus;    // CertGetCertificateChain error flags
    HRESULT hrVerifyChainStatus;   // CertVerifyCertificateChainPolicy result
} SecPkgContext_CertificateValidationResult;
```
父代理原写的 `CertChainErrorStatus` 字段**不存在**。接受判据应为：
`dwChainErrorStatus == 0 && SUCCEEDED(hrVerifyChainStatus)`。

### 8.4 执行 AI 的探针实测（本机，可作为行为证据）

| 场景 | 结果 |
|---|---|
| 凭据 DEFERRED + 自签 | 握手 `SEC_E_OK` 完成；`dwChainErrorStatus=0x20`(UNTRUSTED_ROOT)、`hrVerifyChainStatus=0x800B0109`(CERT_E_UNTRUSTEDROOT) |
| 凭据 DEFERRED + `ISC_REQ_MANUAL_CRED_VALIDATION` | `SEC_E_INVALID_PARAMETER`(0x8009035D)，**禁止组合** |
| DEFERRED 模式 + 主机名不匹配 | 只报链错误，**不做主机名比对** → 主机名必须自查 |
| MANUAL 模式（凭据 AUTO）查询 CERT_CHECK_RESULT | `SEC_E_INVALID_HANDLE`(0x80090301) |

**结论**：DEFERRED 只解决"链结果可查询"，主机名校验必须由客户端自己实现
（用 `CertGetNameStringW` 取 CN、`CryptDecodeObjectEx` 枚举 dNSName SAN、SAN 存在时忽略 CN）。

### 8.5 教训（同型家族第 6 例）

**"没有实测的修复指令本身就是缺陷来源"**。父代理凭记忆写下 `ISC_REQ_DEFERRED_CRED_VALIDATION`，
若执行方照做，结果是一个"看起来改了、实际截断为 0"的空修复，而所有测试可能仍然通过
（因为 kStrict 本来就放行）。修复指令涉及平台 API 时，必须先在目标平台写最小探针验证签名与行为。
