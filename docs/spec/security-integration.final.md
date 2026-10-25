# 安全层接入：审计定稿（W11 ③）

日期：2026-10-23
状态：**审计阶段盖章，进入执行**

## 1. 参与方与产物

| 角色 | 会话 | 产物 | 规模 |
|---|---|---|---|
| 审计 AI 甲 | `ses_e9a488e95ffeRAGF2jsornJq1O` | `docs/spec/security-integration.audit-a.md` | 306566 B / 4196 行 |
| 审计 AI 乙 | `ses_e9a483702ffeFFSQdhag8t1SpI` | `docs/spec/security-integration.audit-b.md` | 132443 B / 2101 行 |
| 主代理 | — | 本文 + `evidence/tls/{s10,s19,s24,s25,n6,merge-table-check}*.md` | 6 份实测证据 |

两份文档 FFFD=0、无 BOM。产品代码零改动（`src`/`include`/`tests` 今日 07:20 后无写入，实测为空）。

## 2. 收敛过程（双向互审，各让一步）

| 轮次 | 甲 | 乙 |
|---|---|---|
| ① 独立出方案 | 17 缺陷，推荐方案 B（单入口 `Step`） | 23 缺陷，推荐方案 C（门面组合） |
| ② 互审 | 确认乙 4 处指控全部属实；接受 6 条硬条件 6/6；新增 S22/S23/S24 | 撤回 4 个判断；承认遗漏 11 条 + 1 条新漏；接受甲的 S10 P2 定级与三层拆分 |
| ③ 定稿 | 24 条 S（S1–S24）+ §19 交接包 | 38 条 M（M01–M38）+ 双向映射 |

**关键让步（双方各自承认的实质错误）**：
- 甲：§15.1 的 S7 原改法是错的（U4 实测推翻了「解析 alert」的可行性）；§13 草案 `Step({kNone})` 消歧有实质缺陷；N1 的问题设定前提就错（`boundary1/3/10` 根本不含 `Handshake`）。
- 乙：§2.2.3 整节撤回；「钩子签名不够」判断错误；「S10 应升 P1」高估；「解析 alert」修法比甲错得更彻底；10 处引文是转述而非逐字（已脚本替换）。

## 3. 主代理独立实测（不采信任何一方）

| 编号 | 我做了什么 | 结论 |
|---|---|---|
| **S10** | 自写探针，真实 SChannel + 真实 `EncryptMessage` 记录（hdr=13/trl=16），87B 合段 | **成立**。且比审计更精确：`consumed = in_size - Σ(EXTRA)` 也算出 `in_size`（Σ(EXTRA)=0），**是设计公式本身失效，不是实现违约** |
| **S19** | 自写探针，按 `ProtocolMask()` 的掩码直调 `AcquireCredentialsHandleW` | **成立**。`tls1.3 only → 0x80090331`；且定位到测试掩盖机制（`test_tls.cpp:879-885` 的 `if (!started) return`） |
| **N6** | 算术验算 | **成立**。`TpktStream` 上限 65531 vs `WrapTpkt` 65528，3 字节缝隙 |
| **S24** | **链接真实产品库** `rtsc_tls.lib` | **成立**。`out=201, type=22`（重协商请求而非 close_notify）。**并多发现一点**：`native_code=0x00090312` 但 `status=kOk` |
| **S25** | 探针 A 段链接产品库、C 段手写上下文 | **裁决：S24-b 不单列**。正确 token 下 `act==SEC_E_OK && st==SEC_E_OK && type==21`，无可复现的独立状态 |
| **合并表** | 逐行读表 | 38 行，归属 14/13/11，与声明一致（我最初误判为算术错误，实为 2 处一对多映射） |

## 4. 我纠正自己的三处

1. **合并表算术**：我按归属列算出「多 1」，一度判断是算术错误。逐行读表后发现是 `S20→M25+M27`、`B17→M26+M36` 两处一对多映射。**表是对的，我错了。**
2. **S24 第一版探针**：手写两种调用形状（不链接产品库）得到 `out=0`，与甲的 `out=201` 矛盾。原因：手写上下文与产品上下文内部状态不同。**被测对象是产品代码时必须链接产品库。**
3. **「错误码被丢掉」的措辞**：甲指出我只对了一半——`ApplyControlToken` 的码确实丢了，但 `ISC` 的码在 `native_code` 里，错的是 `status=kOk` 把它遮蔽了。**这两种形态修复点完全不同。**

## 5. 缺陷清单最终形态

- **24 条 S**（甲编号，S1–S24），含 S21=乙的 B19、S22=乙的 B13、S23/S24 为 U4 实测新发现。
- **38 条 M**（乙编号，M01–M38），双向映射无悬空：23 个 M→S，12 个判定「无 S」并逐条给理由，1 个 M→契约项 C6。
- 严重度：**P0 × 6**（M01 M02 M03 M04 M18 M28）/ **P1 × 12** / **P2 × 19** / 作废 × 1。

## 6. 最终方案

**甲方案 B（单入口 `Step`）+ 乙的错误类型 + B19/B01 前置**，乙排第 1 名。

核心决策：
1. **EUAR 在安全层消费**，`rtsc_proto` 零改动。理由：EUAR 的字节边界只有安全层知道（取决于 CredSSP 最后一条消息在明文流何处结束）。
2. **S10 修复放后端**：`Handshake` 按 5 字节 record 头预切片，只喂 `ContentType ∈ {20,21,22}`，`ContentType=23` 移入 `rx_buffer_`。**不放安全层**，因为 OpenSSL 的 `SSL_do_handshake` 自己处理 record 层。
3. **批 0 用 CMake 条件编译，不加 `#ifdef`**。理由：被 `#ifdef` 掏空的 TU 会产出空目标文件，静态库照常链接成功，把编译期错误变成运行期迷雾。

## 7. 执行批次（6 批，24 条 S 全覆盖）

| 批 | 成员 | 库 |
|---|---|---|
| 批 0 | S21 | CMake + `tls_schannel.cpp` 工厂拆分 |
| 批 1 | S1 S5 S6 S11 S18 | `rtsc_credssp` |
| 批 2 | S7 S8 S9 S10 S19 S22 S23 S24 | `rtsc_tls` |
| 批 3 | S2 S3 S4 S15 S16 | 新建 `rtsc_security` |
| 批 4 | S12 S13 S14 S17 S20 | `rtsc_proto` |
| 批 5 | 无新缺陷 | 真机联调（BLOCKED: needs credentials） |

**批 0 必须最先**（否则 `rtsc_security` 一建就编不过非 Windows）。批 1 与批 2 可并行。

## 8. 红基线（可复现，实测）

**S21 红证**（WSL Ubuntu 24.04 + cmake 3.28.3 + ninja + g++ 13.3.0）：
```
/mnt/f/rtsc/src/net/tls_schannel.cpp:29:10: fatal error: windows.h: No such file or directory
BUILD_EXIT=1
```
证据：`evidence/u4/s21-configure.out.txt`、`s21-red.out.txt`。

**测试基线**（验收脚本的 `-lt` 阈值）：
```
rtsc_tls_tests             26 tests, 139 checks
rtsc_credssp_sm_tests      15 tests,  92 checks
rtsc_ntlm_tests            27 tests, 136 checks
rtsc_credssp_tests         23 tests,  69 checks
rtsc_framing_tests         11 tests,  47 checks
rtsc_connect_machine_tests 26 tests, 115 checks
```

## 9. 交付给执行 AI

`docs/spec/security-integration.audit-a.md` **§19 执行交接包**（53739 B / 993 行，7 小节）：
- §19.1 必读三件事（背景 / 硬约束 / TDD 顺序）
- §19.2 批 0 的 8 步操作清单（每步含验证命令 + 预期输出 + 失败怎么办）
- §19.3 六批验收脚本（15 个 PowerShell 块，全部 ASCII）
- §19.4 三处最易做错的陷阱
- §19.5 DoD 18 条（代码级 8 / 协议级 5 / 端到端 3 BLOCKED / 元判据 2）
- §19.6 禁止事项
- §19.7 证据索引

## 10. 未验证项（不隐瞒）

| # | 未验证 | 原因 | 谁来验证 |
|---|---|---|---|
| U3 | `pubKeyAuth` 拼接顺序（`magic‖nonce‖SPK`） | 无凭据；且 `MakeServerEchoForTest` 用同一套逻辑，**任何本地测试都发现不了** | 批 5（需凭据） |
| U6 | 第 5 步后服务器发 alert 还是 errorCode | 无凭据 | 批 5 |
| U-N4 | S7-a 是否够用 | 依赖 U6 | 批 5 |
| S21 绿证 | 批 0 改后 Linux 能 `BUILD_EXIT=0` | 甲只建立了红基线 | 执行 AI（批 0 步骤 S0.8） |
| U-N1 | `boundary2/9/12`、`extra_is_zero`、`max_out_is_soft` 在 D1 下未回放 | 甲只回放了 boundary1/3/10 | 执行 AI（批 2 跑全 26 条） |
| E1–E3 | 端到端三条 | 无凭据 | 批 5 |

## 11. 盖章

两名审计一致同意：
- 甲：「审计阶段可盖章，按 §17.4 批 0–批 5 进入执行；批 0 必须最先。」
- 乙：「双方已收敛，审计阶段可盖章。」

**主代理裁决：盖章，进入执行阶段（W11 ④）。**
