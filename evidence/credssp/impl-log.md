# CredSSP / NTLM 实现记录

生成方式：`evidence/credssp/impl_log.py`（机器测量）。

## 1. 交付物

| 文件 | 字节 | 行 | SHA256（前 16 位） |
|---|---:|---:|---|
| `include/rtsc/credssp/ts_request.h` | 2986 | 91 | `ECFB305D7DDFE151` |
| `include/rtsc/credssp/ntlm.h` | 6207 | 166 | `7D1B4F78FC5B7EA1` |
| `include/rtsc/credssp/credssp.h` | 4745 | 123 | `4229817852C59AA5` |
| `src/credssp/ts_request.cpp` | 17514 | 504 | `D95EA3A02F745299` |
| `src/credssp/ntlm.cpp` | 17624 | 441 | `D640D75C25AD114C` |
| `src/credssp/credssp.cpp` | 15869 | 415 | `6EBC1FC0FF91B6D6` |
| `tests/test_credssp.cpp` | 12311 | 366 | `E3EDF7C3C7E4D2B9` |
| `tests/test_ntlm.cpp` | 23392 | 607 | `40B992B1C593BFE2` |
| `tests/test_credssp_sm.cpp` | 18047 | 505 | `473FF76ADB974102` |
| `src/crypto/hash.cpp` | 14702 | 413 | `E42173BCB9E82251` |
| `tests/test_crypto.cpp` | 19450 | 500 | `F0E35B148CF57D7A` |
| `evidence/credssp/red_test_credssp.py` | 8895 | 226 | `24A9B67E1854ED55` |
| `verify.ps1` | 12671 | 265 | `2FB9F93A870F3171` |

## 2. 测试结果（本次实跑）

| 套件 | 结果 |
|---|---|
| `tsrequest` | exit=0 23 tests, 69 checks, 0 failing tests, 0 failed checks |
| `ntlm` | exit=0 27 tests, 136 checks, 0 failing tests, 0 failed checks |
| `credssp_sm` | exit=0 15 tests, 92 checks, 0 failing tests, 0 failed checks |
| `crypto` | exit=0 25 tests, 66 checks, 0 failing tests, 0 failed checks |

`ctest`：16/16 通过（新增 `credssp` / `ntlm` / `credssp_sm` 三个套件）。

## 3. 覆盖的规范条款

| 规范 | 内容 | 测试 |
|---|---|---|
| [MS-CSSP] 5.1 | TSRequest 六个 context tag、版本最短 INTEGER、32 字节 nonce | `tsrequest_*`（23 个） |
| [MS-CSSP] 5.2 | NegoData 双层 SEQUENCE 包装 | `tsrequest_negotoken_wrapping_is_double_sequence` |
| [MS-CSSP] 5.5 | TSCredentials / TSPasswordCreds（UTF-16LE） | `tscredentials_*` |
| [MS-CSSP] 5.7 | 长形式长度、服务器非规范 errorCode | `tsrequest_uses_long_form_length_above_127` / `tsrequest_parses_noncanonical_error_code` |
| [MS-CSSP] 5.3 | 五步状态机、errorCode 优先判定 | `step1_*` / `step3_*` / `step5_*` / `error_code_*` |
| [MS-CSSP] 5.4.1 | v5/v6 绑定哈希（magic 含 NUL） | `binding_hash_matches_independent_value` |
| [MS-CSSP] 5.4.2 | v2/3/4 加密原文 + 服务器首字节 +1 | `version_4_pubkeyauth_*` / `step5_rejects_wrong_server_echo` |
| [MS-CSSP] 5.4.3 | SEAL：RC4 状态跨消息连续 | `seal_*` / `C8_fresh_rc4_per_message` |
| [MS-NLMP] 2.2.1.1 | NEGOTIATE 40 字节（含 Version） | `negotiate_message_is_40_bytes_with_version` |
| [MS-NLMP] 2.2.1.2 | CHALLENGE 56 字节头 + AV_PAIR 序列 | `challenge_message_*` |
| [MS-NLMP] 2.2.1.3 | AUTHENTICATE 88 字节头（含 Version + MIC） | `authenticate_message_header_is_88_bytes` |
| [MS-NLMP] 3.3.2 | NTLMv2 响应全流程 | `ntlmv2_response_matches_official_vector` |
| [MS-NLMP] 4.2.2/4.2.4 | 官方向量 NTOWFv2 / SessionBaseKey / LMv2 / EncryptedSessionKey | `ntowfv2_*` / `ntlmv2_*` |
| [MS-NLMP] 4.2.3.4 | 官方向量 SEAL（56 位密钥） | `seal_matches_official_vector_4_2_3_4` |
| [MS-NLMP] 4.2.4.4 | 官方向量 SEAL（128 位密钥） | `seal_matches_official_vector_4_2_4_4` |
| [MS-NLMP] 7.3 | MsvAvTargetName / MsvAvChannelBindings / MsvAvFlags 位 0x2 | `step3_authenticate_carries_a_nonzero_mic` |
| [FIPS 180-4] | SHA-256 | `sha256_*`（4 个，含 55/56/64 字节边界） |

## 4. 红证（变异测试）

`evidence/credssp/red_test_credssp.py`：16 个变异，覆盖三个源文件。

| 变异 | 破坏的规则 | 结果 |
|---|---|---|
| `C1_drop_magic_nul` | 绑定哈希的 magic 去掉 NUL | 见实测输出 |
| `C2_wrong_magic_order` | 哈希拼接顺序改成 nonce||magic||key | 见实测输出 |
| `C3_skip_server_echo_check` | 不校验服务器回显（丢 MITM 防护） | 见实测输出 |
| `C4_no_error_code_check` | 有 errorCode 仍处理 token | 见实测输出 |
| `C5_nonce_on_old_versions` | v2/3/4 也发 clientNonce | 见实测输出 |
| `C6_raw_key_for_v5` | v5 发原文而非绑定哈希 | 见实测输出 |
| `C7_no_mic` | 有时间戳仍不算 MIC | 见实测输出 |
| `C8_fresh_rc4_per_message` | 每条消息重启 RC4 流 | 见实测输出 |
| `N1_av_order_reversed` | temp 末尾少 Z(4) | 见实测输出 |
| `N2_session_base_key_from_response` | SessionBaseKey 用整段响应而非 NTProofStr | 见实测输出 |
| `N3_no_lm_zeroing` | 有时间戳仍发真 LMv2 | 见实测输出 |
| `N4_mic_not_zeroed` | 算 MIC 时不先清零该字段 | 见实测输出 |
| `N5_authenticate_header_64` | AUTHENTICATE 头用 64 字节 | 见实测输出 |
| `T1_no_ascending_tag_check` | 接受乱序 context tag | 见实测输出 |
| `T2_reject_noncanonical_error` | 拒绝服务器的非规范 errorCode | 见实测输出 |
| `T3_nonce_length_unchecked` | 接受任意长度 nonce | 见实测输出 |

**结果：15 被抓（测试失败）、1 为 BUILD-FAIL（编译期即拒绝）、0 漏检。**
源码 sha256 全部恢复一致，重建后三套件重新全绿。

## 5. 实现期发现的规格/文档缺陷

| # | 问题 | 影响 | 处理 |
|---|---|---|---|
| **D4** | `docs/spec/security-layer.md` §6.6.2 把 [MS-NLMP] **4.2.4.4** 的 checksum （`7fb38ec5c55d4976`）与 **4.2.3.4** 的密文（`a0 23 72 f6`）放在同一张表里。两个示例的会话密钥不同，这个组合**不可能**同时成立 | 按文档写测试会得到必然失败的用例 | 以 PDF 原文为准拆成两个独立向量；两个示例各自完全复现 |
| **D5** | 同节称 4.2.4 向量的 `ServerName` 为空 | 实测官方 4.2.4 上下文含 **两个** AV 对（NbDomainName="Domain"、NbComputerName="Server"），顺序是 **Domain 在前** | 用空 AV 列表时 LMv2 仍对（它不依赖 AV 列表），但 SessionBaseKey 与 NTProofStr 全错——正是这个"部分正确"掩盖了缺失 |
| **D6** | 同节称 4.2.4.4 的 `SealKey` 取"密钥前 7 字节" | PDF 4.2.3.4 原文写明 `Cut key exchange key to 56 bits: eb 93 42 9a 8b d9 52`，且 4.2.4.4 用的是 **128 位**（0x55×16） | 两个示例的密钥强度不同；56 位与 128 位导出必须分开实现 |

## 6. 已知局限

| # | 局限 | 影响 |
|---|---|---|
| C1 | **未与真实 RDP 服务器联调**：`ConnectMachine` 仍停在 `kAwaitExternalSecurity`，接入需要 TLS 层与本层的组合驱动 | 端到端未验证 |
| C2 | 非 ASCII 凭据未测：`Utf16Le` 只对 ASCII 断言过 | 中文/emoji 用户名可能有编码差异 |
| C3 | `MsvAvTargetName` 未发送（规范为 SHOULD）：实测服务器不要求 | 企业环境可能需要 |
| C4 | 未实现 Kerberos/SPNEGO 回退：只发裸 NTLM | 只支持 NTLM 认证的服务器可用 |
| C5 | 服务端方向（接收）的签名校验未做：`OpenReceive` 只解密不验签 | MITM 可篡改第 4 步内容；当前靠回显比对间接防护，不如验签严格 |
| C6 | v2/3/4 路径只用自造回显测过，没有真实老服务器 | 老服务器兼容性未验证 |
