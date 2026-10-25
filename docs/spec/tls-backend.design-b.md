# TLS 后端方案审计（乙）：风险、可验证性、长期可维护性

> 审计对象：`docs/spec/security-layer.md` §4 / §8，`include/rtsc/proto/connect_machine.h` 的
> `kAwaitExternalSecurity` 钩子，`CMakeLists.txt` 的零依赖构建约束。
> 立场：本文不重复"方案 A/B 对比"，只回答三个问题——**选错了会怎样、怎么尽早发现选错了、
> 三个月后换后端要付多少代价**。
>
> 证据等级约定：**[READ]** = 只读源码/文档定位；**[BASH]** = 本机可复现命令输出（红证）；
> **[DOC]** = 官方文档原文；**[未验证]** = 无证据，明确标注。
> 所有探针源码位于 `F:\rtsc\.tmp\tlsprobe\*.cpp`（一次性诊断程序，不属于产品构建，
> 不写入 `src/`，不改 `CMakeLists.txt`）。全部用
> `cl /std:c++20 /W4 /permissive- /utf-8` 单独编译，仅链接 SDK 自带
> `secur32.lib crypt32.lib ncrypt.lib ws2_32.lib bcrypt.lib`。

---

## §0 结论摘要

1. **"零依赖 SChannel 后端"在 Windows 上今天就能跑通 TLS，但不是"少写代码"，而是"多写语义"。**
   本机已对真实服务器 `192.168.1.7:3389` 完成 TLS1.2 与 TLS1.3 握手、取到 742 字节证书、
   294 字节 SPKI，并测出 5 个会直接让实现静默出错的 API 契约（4 个 SecBuffer 下限、
   EXTRA 指针别名、TLS1.3 把 NewSessionTicket 报成 `SEC_I_RENEGOTIATE`、
   `cbTrailer` 是上界不是实际值、关闭通知必须带 `ISC_REQ_ALLOCATE_MEMORY`）。
   这些契约在任何"只设计一个 `TlsTransport` 抽象类"的方案里都不会被写出来，
   也**不会**被现有 12 个测试套件中的任何一个发现。
2. **"引入 OpenSSL" 在本机今天不可行**（不是"不推荐"，是"构建不出来"）：
   `find_package(OpenSSL 3.0 REQUIRED)` 在本机直接失败；源码构建需要 perl + nasm，两者都不存在；
   vcpkg 不存在。同时 OpenSSL 3.4 分支的 EOL 日期是 **2026-10-22（今天）**，
   意味着任何"先装个 3.4 试试"的做法从落地第一天起就是过期依赖。
3. **§8 的推荐结论（方案 A = OpenSSL）与本项目的硬约束（零第三方依赖）自相矛盾，
   且矛盾没有被任何一节承认**。§8 的 16 条缺陷见 §5，其中 4 条是事实性错误
   （"跨平台唯一解"、"官方预编译安装包"、"构建可控"、"MD4 有官方兜底可省自研"）。
4. **最大风险（一句话）**：记录层语义陷阱会让一个"握手成功、测试全绿"的实现
   在真实链路上静默丢帧或永久卡死——TLS1.3 的 NewSessionTicket 伪装成
   `SEC_I_RENEGOTIATE`、`EXTRA` 指针指在调用方缓冲区内部、`cbTrailer` 与实际尾长差 27 字节，
   三者任一处写错都不会报错，只会让 RDP 层收到错位字节。
5. **对"今天能否落地"的独立结论**：
   - **能落地**：Windows 单平台 `PROTOCOL_SSL` 的 TLS 传输层 + 可测试接口 + 真机冒烟
     （本机 43 个探针、约 7.6k 行一次性诊断代码已证明握手、SPKI、分帧、关闭通知全通）。
   - **不能落地**：跨平台单一后端（Linux 无 SChannel，OpenSSL 装不上）、
     以及"接上 TLS 就能连上 192.168.1.7"这个期望——该服务器选的是
     `PROTOCOL_HYBRID_EX (0x08)` `[READ:F:\rtsc\evidence\handshake-001.md:41]`，
     TLS 之后还有 CredSSP + EUAR，`ConnectMachine` 会停在 `kAwaitExternalSecurity`
     `[READ:F:\rtsc\src\proto\connect_machine.cpp:217]`。
     所以 TLS 层是**前置件**，不是可交付连接。

---

## §1 SChannel 最坏情况分析

### 1.1 版本矩阵：哪些组合会直接连不上

| 平台 | TLS1.2 客户端 | TLS1.3 客户端 | `SCH_CREDENTIALS`（v5） | 后果 |
|---|---|---|---|---|
| Win7 / 2008R2 | **默认 Disabled** | 无 | 无 | 默认 `min=1.2` 直接失败，需改注册表 |
| Win8.1 / 2012R2 | Enabled | 无 | 无 | 只能 `SCHANNEL_CRED`，无法表达 TLS1.3 |
| Win10 1507–1803 | Enabled | 无 | 无（1809 起才有） | 用 v5 结构 → `AcquireCredentialsHandle` 失败 |
| Win10 1809–22H2 | Enabled | **无** | 有 | 配 `min=1.3` → 静默降到 1.2（见 1.2） |
| Win11 / Server2022+ | Enabled | Enabled | 有 | 全功能（本机实测） |

- TLS1.3 只在 Win11 / Server2022 起可用；`SCH_CREDENTIALS` 的
  `req.target-min-winverclnt` 是 **Windows 10 1809** `[DOC:learn.microsoft.com/.../ns-schannel-sch_credentials]`。
- 本机 `OSVersion=10.0.26200`、`CurrentBuild=26200`（= Win11 25H2 内核号），
  所以本机能跑 TLS1.3 **不代表** Win10 22H2 能跑。这是最容易误判的一条：
  开发机测试全绿，客户 Win10 现场连不上。
- 表中"Win10 1507–1803 用 v5 结构 → 凭证失败"是**推断（C）**，未在多版本机器上实测
  （见 §7 U2/U9）；其余单元格的版本可用性来自 MS 官方版本表 `[DOC]`。

### 1.2 TLS1.3 与"最小版本"的表达陷阱（红证）

- 用 legacy `SCHANNEL_CRED` 只给 `SP_PROT_TLS1_3_CLIENT`：
  `AcquireCredentialsHandle -> 0x80090331`（`SEC_E_ALGORITHM_MISMATCH`），**凭证阶段就失败**。
- 用 legacy `SCHANNEL_CRED` 给 `TLS1_2|TLS1_3`：凭证成功、握手成功，但 ClientHello
  **不含 `supported_versions` 扩展**，`CHver=0303`，协商结果 `proto=0x0800`。
  `[BASH:probe9.exe → "TLS1.2|1.3 (legacy cred) ... proto=0x0800"; probe16.exe 同]`
  → **静默降级**，没有任何错误码。
- 用 `SCH_CREDENTIALS` + `grbitDisabledProtocols` 才能真正表达下限：
  只留 1.2 → `proto=0x0800 suite=0x009D`；只留 1.3 → `proto=0x2000 suite=0x1302`；
  全部 disable → 凭证 `0x80090331`（fail-fast，行为正确）
  `[BASH:probe31.exe]`。未知位（`0x80000000`、`0x00000001`）被忽略，向前兼容。
- **接口结论**：`min_version` 不能映射成"不 disable 低版本"，必须
  ①用 `grbitDisabledProtocols` 表达，②握手后再断言
  `SECPKG_ATTR_CONNECTION_INFO.dwProtocol >= min`，否则降级不可见。
  这一条如果不写进接口契约，测试永远发现不了。

### 1.3 密码套件策略差异（会改变缓冲尺寸，不只是"安全等级"）

- 本机对同一服务器的 TLS1.2 默认协商结果是 **`0x009D TLS_RSA_WITH_AES_256_GCM_SHA384`
  （RSA 密钥传输，无前向保密）**，不是 ECDHE：
  `[BASH:probe29.exe → "TLS1.2 only ... suite=0x009D TLS_RSA_WITH_AES_256_GCM_SHA384"]`。
  显式禁掉 RSA 密钥交换后变为 `0xC030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  `[BASH:probe38.exe → "disable RSA key exchange ... suite=0xC030"]`。
- 注意 `SecPkgContext_ConnectionInfo.aiCipher = 0x6610` 是 **CALG_AES_256**
  （`3<<13 | 3<<9 | 16`），**不是密码套件号**。真实套件号只能从
  `SECPKG_ATTR_CIPHER_INFO.dwCipherSuite` 取（本机 `QueryContextAttributesW` 可用，
  不需要 `QueryContextAttributesExW`）。
  → 任务方转述的 "`cipher=0x6610`（ECDHE-RSA-AES256-GCM-SHA384）" **两处都错**
  （0x6610 不是套件号；实际套件是 0x009D 且非 ECDHE）。证据文件本身只写了
  `cipher=0x00006610`（`[READ:F:\rtsc\evidence\schannel-probe.txt:11]`），
  与 `security-layer.md:505` 的正确描述（RSA 密钥传输、非 ECDHE）一致，见 §5 D13。
- 管理员策略（`HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002`）
  可整体改写套件顺序；客户端无法预测最终套件，因此**任何"按套件号硬编码缓冲/行为"的实现都是错的**。
  本机客户端可用套件列表 28 条，含 `TLS_RSA_WITH_NULL_SHA`（`[BASH:Get-TlsCipherSuite]`）——
  说明"系统默认"并不等于"安全默认"，`SCH_USE_STRONG_CRYPTO` 必须显式给。

### 1.4 `SCH_CRED_MANUAL_CRED_VALIDATION` 的可用性与副作用

- 该标志从 NT5 起存在，头文件注释明写"ignored by non-NT5 versions"
  `[READ:C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\schannel.h:552-559]`。
  版本可用性不是风险。
- 但注释同时写明：`SCH_CRED_NO_SERVERNAME_CHECK` **在 MANUAL 生效时被忽略**
  `[READ:...\schannel.h:544-550]`。实测确认：`target=example.com` + MANUAL only
  → 握手成功 `[BASH:probe15.exe → "target=wrong name, manual only ... OK"]`。
  → **主机名校验在 MANUAL 模式下完全不做**。`security-layer.md:532-534` 说"主机名校验必须可关闭"，
  但没说"MANUAL 下它自动就是关的"，于是"strict 模式"若只依赖 SChannel 会变成
  "看起来在验、其实没验"。必须在应用层自己算。
- 三种策略实测（同一台自签名服务器）：

| 策略 | 握手 | 可查链结果 |
|---|---|---|
| 无任何 manual 标志 | **失败** `0x80090325 SEC_E_UNTRUSTED_ROOT` | — |
| `SCH_CRED_MANUAL_CRED_VALIDATION` | 成功 | `SECPKG_ATTR_CERT_CHECK_RESULT → 0x80090301`（无效句柄，无结果） |
| `SCH_CRED_DEFERRED_CRED_VALIDATION` | 成功 | `CERT_CHECK_RESULT → 0x00000000, hr=0x800B0109 (CERT_E_UNTRUSTEDROOT)` |
| `ISC_REQ_MANUAL_CRED_VALIDATION`（只给 ISC） | 成功 | 同上（无结果） |

`[BASH:probe5.exe]` → **tofu/strict 需要"链结果"时只能选 DEFERRED**；选 MANUAL 就
必须自己做全部校验（含主机名、有效期、EKU），否则"strict"是空话。

### 1.5 FIPS 模式

- 本机 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled = 0`
  `[BASH:Get-ItemProperty]`，**无法在本次审计中开启验证**（改系统策略需要重启，超出授权）。
  **未验证。**
- 可推断的影响面（标 C，需实测确认）：FIPS 策略作用于 **SChannel 的算法白名单**，
  即 TLS 只能用 FIPS 批准套件（AES-GCM/SHA-2 仍在列，RC4/3DES/MD5 被踢）。
  对本项目 TLS 层影响有限（默认走 AES256-GCM-SHA384）。
- 关键区分：**CredSSP 的 MD4/MD5/RC4 是本项目自己实现的**
  `[READ:F:\rtsc\include\rtsc\crypto\hash.h:16,34,43]`，
  不受 OS FIPS 策略管辖——所以 FIPS 模式下 CredSSP 仍能"跑"，但审计上不可接受。
  这一点 §8.2/§8.5 完全没提（见 §5 D14）。
- 设计动作：启动时读 `FipsAlgorithmPolicy`，命中则输出明确诊断（不静默降级）。

### 1.6 CredSSP 相关的 `ISC_REQ_USE_SUPPLIED_CREDS` 行为差异

- CredSSP 的 TLS 腿**不需要客户端证书**：`[MS-CSSP]` 明写服务器不请求客户端证书
  `[READ:F:\rtsc\docs\spec\security-layer.md:519]`，实测服务器 `No client certificate CA names sent`
  `[READ:...:519 引用 E 级证据]`。所以 `ISC_REQ_USE_SUPPLIED_CREDS` 在正常路径上**用不到**。
- 但如果服务器真的发了 CertificateRequest（企业策略、双向 TLS），实测：
  `ASC_REQ_MUTUAL_AUTH` 回环 → 客户端 `ISC` 返回 `0x00090320 SEC_I_INCOMPLETE_CREDENTIALS`
  `[BASH:probe32.exe → "mutual-auth handshake ok=0 reason=0x00090320"]`。
  对已建立上下文再补 `ISC_REQ_USE_SUPPLIED_CREDS` → `0x80090300`
  `[BASH:probe6.exe → "ISC(+USE_SUPPLIED_CREDS) on established ctx -> 0x80090300"]`（该码无诊断意义）。
- 结论：`SEC_I_INCOMPLETE_CREDENTIALS` 必须当**致命错误**处理并给出可读原因；
  绝不能"顺手把用户凭据塞进 TLS"——那会把 NTLM 凭据泄露到证书请求路径上。
- 版本差异（Win7 vs Win11 对 `CREDSSP_CRED` 的支持细节）：**未验证**（无多版本机器）。
  已知本机 `AcquireCredentialsHandle("CredSSP", null authdata) -> 0x00000000`
  `[BASH:probe6.exe]`，且 `CREDSSP_CRED` 存在（sizeof=24）。

### 1.7 会"直接导致连不上"的清单（按发生概率排序）

| # | 触发条件 | 现象 | 证据 |
|---|---|---|---|
| 1 | 自签名证书 + 未给任何 manual 标志 | `0x80090325`，握手失败 | [BASH:probe5] |
| 2 | Win10（<1809）用 `SCH_CREDENTIALS` | 凭证失败 `0x80090331` | [DOC] + 推断 |
| 3 | Win10（无 TLS1.3）配 `min=1.3` | 静默降到 1.2（"以为连上了"） | [BASH:probe9] |
| 4 | Win7 默认策略 + `min=1.2` | TLS 层直接断（RDP 层无 NEG_FAILURE） | [DOC] 版本表 |
| 5 | 服务器只支持 TLS1.0 + `SCH_USE_STRONG_CRYPTO` | 同上 | [DOC] |
| 6 | `DecryptMessage` 只给 1–3 个 SecBuffer | 每条记录都 `0x80090308` | [BASH:probe20/probe27] |
| 7 | 只喂"剩余字节"而不喂累计缓冲 | `0x80090308`（永远拼不起来） | [BASH:probe11] |
| 8 | 丢掉 `SECBUFFER_EXTRA` 后继续读 | 后续每条记录 `0x80090330` | [BASH:probe18-A] |
| 9 | TLS1.3 忽略 `SEC_I_RENEGOTIATE`（票据） | 后续记录 `0x80090330`，上下文废 | [BASH:probe39] |
| 10 | 用 `cbTrailer` 当实际尾长推进写缓冲 | 多发 27 字节垃圾（TLS1.3） | [BASH:probe21] |
| 11 | 关闭通知不给 `ISC_REQ_ALLOCATE_MEMORY` | `0x80090300`，发不出 close_notify | [BASH:probe3/probe6] |
| 12 | FIPS 策略 + 服务器只留非 FIPS 套件 | 握手失败（**未验证**） | — |

---

## §2 引入 OpenSSL 的最坏情况分析

### 2.1 本机可构建性（这是决定性的，不是偏好问题）

```
[BASH] cmake -S . -B b -G Ninja  (CMakeLists 含 find_package(OpenSSL 3.0 REQUIRED))
CMake Error: Could NOT find OpenSSL, try to set the path ... 
  (missing: OPENSSL_CRYPTO_LIBRARY OPENSSL_INCLUDE_DIR) (Required is at least version "3.0")
```
- 源码构建路径需要 **perl + nasm**：`where perl` / `where nasm` 均无输出
  `[BASH:where.exe perl; where.exe nasm]`；`where vcpkg` 亦无。
  OpenSSL `NOTES-WINDOWS.md` 明写"Install Perl / Install NASM / both on %PATH%"
  `[DOC:github.com/openssl/openssl/blob/master/NOTES-WINDOWS.md]`。
- 也就是说：**今天在这个环境里，OpenSSL 既装不到也编不出**。
  §8.5 的"构建可控"（`security-layer.md:1448-1449`）与事实相反。

### 2.2 许可证传染性

- OpenSSL 3.x = Apache-2.0 `[DOC:openssl.org/source/ → "Since 3.0 ... Apache License v2"]`，
  **无 GPL 传染**，静态/动态链接闭源产品均可行。
- 但有两条容易漏的义务：①静态链接必须随产物附带 `NOTICE`/许可证文本；
  ②若回退到 1.1.1（老系统兼容场景），许可证是 OpenSSL/SSLeay 双许可（含广告条款），
  与 3.x 不同。任何"版本自适应"的构建脚本都要把这两套许可分开记。
- 对比：SChannel 的许可证义务 = 0（OS 组件）。

### 2.3 DLL 分发与 CVE 响应责任

- 动态链接需分发 `libssl-3-x64.dll` + `libcrypto-3-x64.dll`，
  **外加 legacy provider DLL 与 `providers` 目录布局**；`OSSL_PROVIDER_load(NULL,"legacy")`
  在找不到模块时**运行期**返回 NULL（不是链接期错误）→ 现场才炸，CI 全绿。
- 静态链接则每个 CVE 都要重新出包；本项目"零依赖"的卖点之一正是"安全更新由 OS 负责"。
- 具体节奏风险：OpenSSL 3.4 分支 **EOL = 2026-10-22（今天）**；3.6 EOL = 2026-11-01；
  唯一长期分支是 3.5 LTS（EOL 2030-04-08）`[DOC:openssl.org/source/ 版本表]`。
  选 3.4 等于落地即过期；选 3.5 等于把自己绑到一个 4 年维护窗口上。

### 2.4 legacy provider 在某些构建缺失

- MD4/RC4 只在 legacy provider `[DOC:docs.openssl.org/.../OSSL_PROVIDER-legacy/]`。
  该 provider 在部分发行版被拆包（`openssl-legacy`）、FIPS 构建中不存在、
  静态构建时默认不编入（需 `enable-legacy`）。
- 更要紧的是：**本项目根本不需要它**。`src/crypto/hash.cpp` 已自带
  MD4/MD5/SHA1/HMAC-MD5/RC4，且有 RFC 1320/1321/3174/2202 向量测试（21 个用例）
  `[READ:F:\rtsc\tests\test_crypto.cpp:65,94,105,114]`。
  再引一个"可能加载失败"的 provider 是**净增风险**。§8.5 把它写成"官方兜底"（`security-layer.md:1443`）
  是把已解决的问题重新变成问题。

### 2.5 `/W4 /WX` 编译第三方头会不会炸

- 会炸，但可修。构造一个含 `C4456`（变量遮蔽）+ `C4189` 的头：
  ```
  [BASH] cl /W4 /WX /permissive- /I thirdparty main.cpp
  thirdparty\noisy.h(5): error C2220: 以下警告被视为错误
  thirdparty\noisy.h(5): warning C4456: "shadow" 的声明隐藏了上一个局部声明
  ```
- 加 `/external:I thirdparty /external:W0 /external:anglebrackets` 后通过
  `[BASH:cl ... /external:I ... → 编译成功]`。
- CMake 侧只要用 `target_include_directories(... SYSTEM ...)`，CMake 3.31 会自动翻译成
  `-external:IF:/... -external:W0`（实测生成命令行里确实如此），**构建通过**
  `[BASH:cmake --build F:\rtsc\.tmp\cmtest\b → 4/4 成功]`。
- 残余风险：`/permissive-` 对某些 C 头里的老式构造（隐式函数指针转换、`register`）仍会报错，
  且 OpenSSL 头大量使用宏展开——**未验证**（本机无 OpenSSL 头）。

### 2.6 无 vcpkg 环境下 `find_package` 怎么满足

只有三条路，全部有硬成本：

| 路径 | 前提 | 本机可行性 |
|---|---|---|
| vcpkg / 预编译安装包 | 有 vcpkg 或第三方安装器 | **不可行**（无 vcpkg；OpenSSL 官方不发布 Windows 二进制） |
| 源码 + `perl Configure VC-WIN64A` + `nmake` | perl + nasm | **不可行**（两者皆无） |
| FetchContent 源码 + `no-asm` | 仍需 perl 生成 Makefile | **不可行** |
| 提交预编译二进制到仓库 | 需要可信来源 + 供应链审计 | 与"零依赖"目标直接冲突 |

`security-layer.md:1404` 列的"② 官方预编译安装包"是**事实错误**：
openssl.org 只提供源码 tarball 与 PGP/SHA 校验和 `[DOC:openssl.org/source/]`，
Windows 二进制由第三方（Shining Light 等）提供，不属于"官方"。

### 2.7 跨平台二进制体积与构建矩阵

- 静态 `libcrypto` 单平台约 3–4 MB 量级（**未在本机测量**，无库可测）；
  两平台 × 两种链接方式 = 4 套构建组合，加上 FIPS/非 FIPS 变体。
- SChannel 方案：新增二进制体积 ≈ 0（系统 DLL），构建组合 = 1（Windows）。

### 2.8 OpenSSL 最坏情况小结

真正的最坏情况不是"许可证"或"CVE"，而是：
**为了一个在 Windows 上本来由 OS 免费提供的能力，引入一个必须在两个平台上分别构建、
分别打补丁、分别验证套件策略、并且在当前环境根本构建不出来的依赖。**
如果坚持跨平台优先，正确的对比对象是"自带 TLS 或 vendored 精简 TLS"，不是"OpenSSL vs SChannel"。

---

## §3 接口可测试性审计

### 3.1 只设计 `TlsTransport` 抽象类为什么不够

一个纯虚类（`Handshake/Write/Read/Close`）只能证明"调用顺序对"，证明不了：

- 握手后的**不变量**是否成立（协商版本 ≥ 下限、套件未被降级、SPKI 与证书一致）；
- **分帧**是否正确（`EXTRA` 是否被完整消费、`cbTrailer` 是否被误当实际长度）；
- **异常状态**是否被正确处理（票据、关闭通知、半记录、篡改记录）。

因为这些都是"后端内部语义"，抽象类把它们藏起来了。可测试性的前提是：
**把后端语义变成可注入的契约**，而不是把后端藏在一个虚函数后面。

### 3.2 五类测试（每类必须写清"能发现什么/发现不了什么"）

#### A. 确定性向量测试（KAT，无网络、无加密库）

- 内容：
  1. 从固定证书 DER（742 字节，`F:\rtsc\evidence\schannel-spki-probe.txt` 里逐字节给出）
     提取 SubjectPublicKey（270 字节，`30 82 01 0a ...`）与 SPKI（294 字节，
     `30 82 01 22 ...`），断言 `SHA256(SPKI) = 78b5f26b...0f3a`
     `[BASH:PowerShell 解析该证据文件 → SPKI sha256=78b5f26b0941d4fd...0f3a, spk len=270]`。
  2. pubKeyAuth v5 绑定哈希：`SHA256(magic||nonce||SPK)` 的固定向量
     （magic 含结尾 `\0`，38 字节，`security-layer.md:761-764` 已给逐字节）。
  3. TSRequest / NegoData 的 DER 逐字节编码（含 `security-layer.md:641-658` 的 91 字节实测样本）。
  4. 记录层**分帧器**的纯字节向量：给定"两条记录粘在一起"的字节流与一个假后端，
     断言消费偏移与输出拼接结果。
- 能发现：ASN.1 顺序错、`\0` 漏掉、SPKI 取错层（整个证书 / 整个 SPKI / BIT STRING 内容）、
  DER 长度编码错、分帧偏移错。
- 发现不了：真实握手、真实密钥、任何 SChannel/OpenSSL 语义。

#### B. 进程内回环（loopback，无 socket、无真实服务器）

- 内容：客户端 `InitializeSecurityContext` ↔ 服务端 `AcceptSecurityContext` 在同一进程互喂 token，
  服务端证书用 `CertCreateSelfSignCertificate` 现造。
  本机已用它测出：TLS1.2/1.3 均能握手、`STREAM_SIZES` 差异、4-buffer 下限、
  `EXTRA` 链式消费、篡改记录行为、零长明文、16 KB 分片。
  `[BASH:probe10/probe12/probe17/probe27/probe36]`
- 能发现：握手循环写错（少喂一次/多喂一次）、buffer 数量错、`EXTRA` 未循环、
  分片/合并错、`maxmsg` 超限、关闭通知流程错。
- 发现不了：**操作系统版本矩阵**（loopback 永远用本机 SChannel）、
  真实服务器策略（套件顺序、是否发票据、是否要求客户端证书）、
  以及"票据"这种只有真服务器才发的消息（回环里 SChannel 服务端不发 NewSessionTicket）。

#### C. 故障注入（在"传输接缝"上注入脚本化状态）

- 内容：定义 `TlsBackend` 的**可替换实现** `ScriptedBackend`，按脚本返回
  `SEC_I_RENEGOTIATE` / `SEC_E_INCOMPLETE_MESSAGE` / `EXTRA` / `SEC_I_CONTEXT_EXPIRED` /
  `SEC_E_DECRYPT_FAILURE`，并脚本化"每次只喂 1 字节 / 一次喂 3 条记录 / 零长明文 / 尾字节翻转"。
  本机已证明这些脚本是**可复现的**：1 字节喂法在真实 SChannel 上逐步
  `MISSING` 递减、13 字节后跳到全记录长度 `[BASH:probe36.exe]`；
  尾字节翻转在 TLS1.2 上 10/10 使上下文永久失效、TLS1.3 上 10/10 可继续
  `[BASH:probe25.exe → proto=0x0800 poisoned=10; proto=0x2000 recovered=10]`。
- 能发现：状态机分支漏写、把"可恢复"当"致命"（或反之）、
  失败时误用 `DATA` 缓冲（实测失败时 `DATA.cbBuffer` 等于整条记录长度 77，
  内容是密文而非明文 `[BASH:probe27.exe]`）。
- 发现不了：密码学正确性、真实网络时序。

#### D. 差分测试（两个独立实现对同一输入）

- 内容：
  1. 自研 MD4/RC4/HMAC-MD5 vs **BCrypt**：实测本机 `BCrypt` 支持
     MD4 / MD5 / SHA1 / SHA256 / RC4 / AES / 3DES / ECDH_P256 / RSA，
     且 HMAC-MD5 需用 `BCRYPT_ALG_HANDLE_HMAC_FLAG` + MD5（`"HMAC-MD5"` 直接开会
     `0xC0000225`）`[BASH:probe19.exe]`。→ 免费的独立预言机，可做随机差分。
  2. 若将来引入 OpenSSL，则"OpenSSL 后端 vs SChannel 后端"对同一明文做
     加解密对照（注意二者线格式不同，只能对照**明文/密文往返**与**协商参数**，不能对照字节）。
- 能发现：原语实现错（本项目最容易错的是 RC4 状态连续性、HMAC key padding）。
- 发现不了：协议层语义、分帧。

#### E. 真机冒烟（opt-in，不进 ctest）

- 内容：连 `192.168.1.7:3389`，断言：握手成功、`dwProtocol ∈ {0x0800,0x2000}`、
  `SHA256(SPKI) == 78b5f2...0f3a`、`STREAM_SIZES` 自洽
  （TLS1.2 `13/16`，TLS1.3 `5/44`）、65528 字节 TPKT 往返 4 条记录且明文一致。
  本机已全部通过 `[BASH:probe27.exe → "65528-byte PDU -> 4 records ... match=1"]`。
- 能发现：环境漂移（服务器换证书、禁用套件、升级到只支持 1.3）。
- 发现不了：其他客户环境（只能靠版本矩阵 + 配置项覆盖）。

### 3.3 写测试之前必须先冻结的契约（否则 A–E 都写不出来）

1. `Read` 的返回值必须能表达"本次消费了多少输入字节"（不能只返回明文），
   否则 `EXTRA` 语义无法被测试观察。
2. 必须能查询"单次可写最大明文"（`cbMaximumMessage`），而不是常量 16384。
3. 必须能查询"实际线长"与"容量上界"两个不同概念（见 §4.2）。
4. 必须能取到"协商结果"（版本、套件号、SPKI），否则 E 类断言无从下手。
5. 必须能注入"时间/随机数"（pubKeyAuth nonce、ClientChallenge），否则 A 类向量不可复现。

### 3.4 现有资产盘点

- 可复用：`tests/test_framework.h` 的 `RTSC_TEST/CHECK/CHECK_BYTES` 宏、
  `tests/test_crypto.cpp` 的 RFC 向量骨架、`evidence/schannel-spki-probe.txt` 的
  逐字节 SPKI/证书（天然的 KAT 输入）。
- 缺口：**没有任何传输层测试**（12 个套件全是纯协议编解码）；
  `tests/test_framing.cpp` 只测 TPKT，不测"TPKT 之上的 TLS"。
- 建议：新增 `rtsc_tls_tests`（A+C 类，零网络）+ `rtsc_tls_loopback_tests`（B 类，仅 Windows）
  + `rtsc_tls_probe`（E 类，手工）。C 类必须能在 Linux 上跑（假后端），
  这样跨平台接口的正确性在 Windows 之外也能被验证。

---

## §4 记录层分帧风险清单

### 4.1 每个状态码的正确处置（全部本机实测）

| 返回 | 值 | 正确处置 | 错误处置的后果 | 证据 |
|---|---|---|---|---|
| `SEC_E_OK` | 0 | 取 `DATA`（可能 0 字节）+ 循环消费 `EXTRA` | 丢记录 | probe12 |
| `SEC_I_CONTINUE_NEEDED` | 0x00090312 | 仅出现在握手循环 | — | probe4 |
| `SEC_E_INCOMPLETE_MESSAGE` | 0x80090318 | **保留累计缓冲**，再 `recv`，重喂全量 | 只喂剩余 → `0x80090308` | probe11 |
| `SECBUFFER_EXTRA` | type 5 | 指向**输入缓冲内部**；下次调用用它作输入；**先复制再复用缓冲** | 悬垂指针/静默错位 | probe37 |
| `SEC_I_CONTEXT_EXPIRED` | 0x00090317 | 对端 close_notify，正常 EOF；本地 `EncryptMessage` 之后返回 `SEC_E_CONTEXT_EXPIRED` | 当错误重连 | probe4-D |
| `SEC_I_RENEGOTIATE` | 0x00090321 | **按协商版本分叉**：1.2 = 重协商（多轮 ISC/ASC）；1.3 = NewSessionTicket（0 数据，`EXTRA` 是裸 handshake 记录） | 上下文废掉 | probe34/probe39 |
| `SEC_I_NO_RENEGOTIATION` | 0x00090360 | TLS1.3 下服务端拒绝重协商，视为正常 | 误判为错误 | probe24 |
| `SEC_E_DECRYPT_FAILURE` | 0x80090330 | **致命**：1.2 上下文不可恢复；1.3 实测可继续，但不能依赖 | 继续用坏上下文 | probe25 |
| `SEC_E_ENCRYPT_FAILURE` | 0x80090329 | 明文 > `cbMaximumMessage` 或缓冲不足 | 静默丢包 | probe9-F |
| `SEC_E_INVALID_TOKEN` | 0x80090308 | 多半是 SecBuffer 数量 < 4 或喂了非累计数据 | 每条记录都失败 | probe20 |
| `SEC_E_INSUFFICIENT_MEMORY` | 0x80090300 | 关连接时忘了 `ISC_REQ_ALLOCATE_MEMORY`（`SCHANNEL_SHUTDOWN` 之后唯一必需的标志） | close_notify 发不出 | probe3 / probe40 |
| `SEC_I_INCOMPLETE_CREDENTIALS` | 0x00090320 | 服务器要客户端证书 → 致命 | 可能泄露凭据 | probe32 |
| `SEC_E_UNTRUSTED_ROOT` | 0x80090325 | 未给 manual 标志 | 自签名服务器全连不上 | probe5 |

### 4.2 缓冲与尺寸陷阱（实测数字，必须写进接口注释）

1. **`DecryptMessage` 至少需要 4 个 `SecBuffer`。**
   给 1/2/3 个 → `0x80090308`；给 4/5/6 个 → 成功。
   `[BASH:probe20.exe → nbuf=1..3 全部 0x80090308; nbuf=4 OK]`（TLS1.2 与 1.3 一致）。
   这是**未在 `DecryptMessage` 文档中明示**的 SChannel 契约；只写 2 个 buffer 的代码
   在文档层面"看起来对"，在 SChannel 上 100% 失败。
2. **`cbTrailer` 是上界，不是实际尾长。**
   TLS1.2（`0x009D`，AES-GCM）：`hdr=13 trl=16`，实际尾长 16，`hdr+len+trl == 实际线长`。
   TLS1.3（`0x1302`）：`hdr=5 trl=44`，实际尾长 **17**，`hdr+len+trl` 比实际线长多 **27**。
   `[BASH:probe21.exe → TLS1.3 payload=16 wire=38, hdr+len+trl=65]`
   → 发送缓冲按 `hdr+len+trl` **分配**是对的；但"实际写了多少"必须用
   `bs[0].cbBuffer+bs[1].cbBuffer+bs[2].cbBuffer`（=38），用 `hdr+len+trl`（=65）会多发 27 字节垃圾。
3. **`SECBUFFER_MISSING` 是"还需要多少字节"，不是"整条记录多长"。**
   只有 5 字节头到齐后 `avail+MISSING` 才等于整条记录长度：
   TLS1.2 在 1 字节时 `MISSING=12`（1+12=13，只到 `cbHeader`），13 字节时 `MISSING=32`（13+32=45）。
   `[BASH:probe36.exe]` → 用它做"读多少"的提示，不能当总长。
4. **`EXTRA` 指针在调用方缓冲区内部。** 实测 `EXTRA` 的 `pvBuffer` 偏移 37、输入范围 `[0,74)`：
   `[BASH:probe37.exe → buf[3] type=5 cb=37 offsetFromStart=37 inInputRange=1]`
   → 若随后 `std::vector` 扩容/`memmove`/`free`，`EXTRA` 立即悬垂。
   接口必须要求"先复制 `EXTRA` 再复用缓冲"，或者干脆由后端内部持有剩余字节。
5. **一次 `DecryptMessage` 只解一条记录**，多条记录全部堆在 `EXTRA`（3 条 → `EXTRA=90`，
   再 drain 一次 → `EXTRA=45`，再一次 → 0）`[BASH:probe12.exe → messages=3]`。
6. **零长明文是合法的**：`EncryptMessage(0)` → `h=13 d=0 t=16`（TLS1.2）/`5/0/17`（TLS1.3），
   对端解出 `data=0` 且 `SEC_E_OK` `[BASH:probe32.exe]`。
   → 读循环不能把"0 字节明文"当 EOF，否则遇到空记录就误判断链。
7. **写侧必须按 `cbMaximumMessage` 切片**：`EncryptMessage(maxmsg+1)` → `0x80090329`；
   65528 字节 TPKT 必须切 4 条记录，回读明文一致 `[BASH:probe27.exe]`。

### 4.3 把 TPKT 分帧与 TLS 记录分帧混在一起会导致的具体 bug

前提事实：`TpktStream` 是**无状态校验的重同步型**分帧器
`[READ:F:\rtsc\src\proto\framing.cpp:37-54]`：一旦首字节不是 `0x03`，它会逐字节前扫，
把跳过的字节记进 `dropped_bytes()` 然后**继续工作**。

| # | 错误写法 | 具体后果 | 证据 |
|---|---|---|---|
| B1 | 把 `recv` 到的密文直接喂 `TpktStream` | 静默丢 2 字节，然后认为"从偏移 2 开始有一个 768 字节的 TPKT 帧"，永久 `NeedMoreData` | `[BASH:tpkt_tls3.exe → Next -> status=1 dropped=2]` |
| B2 | 同上，且密文里恰好出现 `03 00 00 xx` | **把密文当 PDU 接受**（构造样本：`03 00 00 08 de ad be ef` 被当作合法帧） | `[BASH:tpkt_tls2.exe 设计样本]` |
| B3 | 假设"一条 TLS 记录 = 一个 PDU" | 65528 字节 TPKT 被切成 4 条记录 → 每条都被当成半个 PDU 解析失败 | probe27 |
| B4 | 假设"一个 TPKT 帧 = 一条 TLS 记录" | 两条 TPKT 挤在一条记录里时，第二条被丢（`EXTRA` 未消费） | probe18-A |
| B5 | 两层共用一个 `std::vector` 且不复制 `EXTRA` | `TpktStream::Append` 的 `Compact()` 做 `erase` → `EXTRA` 悬垂 | framing.cpp:31-33 + probe37 |
| B6 | 把 TPKT 的 16 位长度（最大 65535）传给 TLS 层 | TLS 单记录上限 16384+overhead → `0x80090329` | probe9-F |
| B7 | 用 `dropped_bytes()` 当"链路丢包计数" | 它只统计 TPKT 重同步；TLS 层丢的记录完全不可见 → 两个独立计数器缺失 | framing.cpp:52 |
| B8 | EUAR 的"裸 4 字节"读取与记录边界共用缓冲 | EUAR 出现在 CredSSP 之后、MCS 之前（`security-layer.md:564-565`），此时若缓冲里还有 `EXTRA`，4 字节读取会吃掉下一条 TLS 记录的头 | 设计推导（C）+ probe37 |
| B9 | 客户端最后一个握手 flight 按记录拆开发 | 规范要求 `ClientKeyExchange+CCS+Finished` 同一帧发出（`security-layer.md:566-569`）；SChannel 实测把三条记录（16/14/16）打包成 **318 字节一个 token** `[BASH:probe22.exe → flight 1 (318 bytes): [rec0 0x16 len=262] [rec1 0x14 len=1] [rec2 0x16 len=40]]` → 只要"一个 token 一次 write"就满足；按记录拆写就违反 | probe22 |
| B10 | 把"空 TPKT（length=4）"与"零长 TLS 明文"都映射成"空读" | `framing.cpp:12` 允许 length==4；TLS 零长明文也返回 0 字节 → 读循环无法区分"keepalive"与"空记录"，容易写成忙等或提前 EOF | framing.cpp:12 + probe32 |

**结论**：两层必须**各自持有独立缓冲、独立错误计数、独立"需要更多数据"信号**，
且 TLS 层必须在 TPKT 层**之前**完成"密文 → 明文"的完整重组。
接口上禁止出现"把 socket 读到的字节同时喂给两层"这种写法。

---

## §5 `security-layer.md` §8 的缺陷（逐条给行号）

> 只列 §8（1375–1470）及其直接依赖的 §4 条目。每条给行号 + 性质 + 后果。

| # | 行号 | 缺陷 | 性质 | 后果 |
|---|---|---|---|---|
| D1 | 1379 | 把"零第三方依赖"写成现状描述，但 §8.5（1436–1449）推荐引入 OpenSSL，**全文未承认这是对硬约束的破坏** | 自相矛盾 | 决策层按 §8.5 执行即违反项目约束 |
| D2 | 1440 | "只有 OpenSSL 在 Windows 与 Linux 上都是成熟一等公民" → 推论"跨平台唯一解" | **事实错误** | mbedTLS/wolfSSL/BoringSSL 均跨平台；"唯一解"排除了真正的零依赖选项 |
| D3 | 1404 | "② 官方预编译安装包" | **事实错误** | openssl.org 只发源码；官方无 Windows 二进制（`[DOC:openssl.org/source/]`） |
| D4 | 1448–1449 | "构建可控 … 不需要改现有 CMake 结构太多" | **事实错误（本机红证）** | 本机 `find_package` 直接失败；perl/nasm/vcpkg 全无（§2.1） |
| D5 | 1407 / 1443 / 1460 | "MD4 走 legacy provider，避免自己实现原语" | 冗余且增风险 | 项目已有 MD4 + RFC 向量（`hash.h:16`，`test_crypto.cpp:65`）；provider 加载失败是**运行期**故障 |
| D6 | 1412 | 把 legacy provider 缺失写成"某些发行版拆包"这一句带过 | 低估 | 静态构建默认不含 legacy；FIPS 构建不含；失败点在运行期而非链接期 |
| D7 | 1418 | 依赖只列 `secur32.dll` + `crypt32.dll` | 不完整 | 实测还需 `bcrypt.dll`（若用 BCrypt 做 HMAC/随机）与 `sspicli.dll`（`QueryContextAttributesExW` **不在** `secur32.lib` 中，链接直接 `LNK2019` `[BASH:probe7 首次链接失败]`） |
| D8 | 1421 / 1424 | "SChannel 仅 Windows / 无法在 Linux 复用" | 正确但**未给出结论** | 承认了硬约束冲突，却在 1436 仍推荐 Windows 上不可用的方案组合 |
| D9 | 1425 | "TLS 部分 ≈500 行" | 估算误导 | 真正的成本不是行数，是 5 个语义陷阱（§4.2）；按行数排期必然低估 |
| D10 | 1455 | `find_package(OpenSSL 3.0 REQUIRED)` 作为"具体落地建议" | 未验证可行性 | 本机不可行（D4）；且未给 `OPENSSL_ROOT_DIR`/fallback 策略 |
| D11 | 1456 | `min=TLS1_2, max=TLS1_3` 一句带过 | 掩盖后端阻抗失配 | SChannel 只能表达"disable 掩码"，且 legacy cred 下 1.2\|1.3 会**静默降级**到 1.2（§1.2 红证） |
| D12 | 1457 | `SSL_VERIFY_NONE` + 应用层 tofu | 与 §1.4 事实冲突 | SChannel 侧 `MANUAL` 会**同时**关掉主机名校验（`schannel.h:544-550`），"strict"会变成空壳 |
| D13 | 505 与 `evidence/schannel-probe.txt:11` | §4.2（505 行）正确写了"RSA 密钥传输，非 ECDHE"，但证据文件只记 `cipher=0x00006610` 而未记套件号；`0x6610` 是 `CALG_AES_256`，**不能**推出 `ECDHE-RSA-AES256-GCM-SHA384`（本次实测该值是 `0x009D TLS_RSA_WITH_AES_256_GCM_SHA384`，§1.3） | 证据字段含义错位 | 任何按"`0x6610` = ECDHE 套件"写的断言/文档都会与实测冲突；套件号只能取 `SECPKG_ATTR_CIPHER_INFO.dwCipherSuite` |
| D14 | 1412 | "FIPS 模式下不可用（本项目不需要 FIPS）" | 遗漏 | 本项目自研 MD4/MD5/RC4 才是 FIPS 的真正问题；且未给"检测并诊断"的动作 |
| D15 | 1463 | "实测服务器发的 `errorCode` 就不符合严格 DER" | 未验证且与代码冲突 | `BerReader::read_header` 明确拒绝非最小长度编码（`ber.cpp:125-130`）→ 若该断言为真，现有 BER 读取器会在 CredSSP 第 2 步就失败。**必须补一次真实 errorCode 抓包** |
| D16 | 1385–1394 | 能力表只列"TLS 1.2/1.3、取 SPKI、MD4…" | 选型标准不完整 | 缺 6 项实测必需能力：记录重组/`EXTRA` 消费、4-buffer 契约、post-handshake 消息、按查询取缓冲尺寸、零长明文、按 `cbMaximumMessage` 切片。缺这些 → 选型无法比较 |

补充（非 §8 但影响选型）：
- `security-layer.md:483-484` 的版本表把"产品可用性"写成"TLS 1.3 不在 …10/…2019"，
  但没有写"Win10 1809+ 有 `SCH_CREDENTIALS` 却没有 TLS1.3"这个**组合陷阱**（§1.1）。
- `security-layer.md:1467-1469` 用"用系统 CredSSP 会跳过 pubKeyAuth/NTLM，与项目目标冲突"
  来否定 SChannel——这个论证只否定"用 CredSSP 包"，**不否定"用 SChannel 只做 TLS"**。
  §8 把两者混为一谈，导致"零依赖 TLS"这个真正可行的选项从未被评估。

---

## §6 决策可逆性约束（三个月后零成本换后端）

### 6.1 接口硬约束（12 条，缺一条就会让切换变贵）

| # | 约束 | 为什么（对应本文哪条证据） |
|---|---|---|
| R1 | 公共头文件**不得**包含任何平台/第三方头（无 `windows.h`/`schannel.h`/`openssl/*.h`） | 否则 `TlsTransport` 的用户被迫依赖后端；换后端要改所有调用点 |
| R2 | 状态用**封闭枚举**（`Ok/NeedMoreData/Closed/WouldBlock/Fatal`），HRESULT/errno 只放在 `raw_error` 字段 | SChannel 返回 `0x800903xx`、OpenSSL 返回 `SSL_ERROR_*`；调用方不该感知 |
| R3 | `Read` 必须返回**消费字节数**与**产出明文**两个量，且允许"消费 > 0、产出 = 0" | `EXTRA`/票据/空记录三种情况都会出现（§4.2-5、4.2-6、probe34） |
| R4 | 明文缓冲由调用方提供（span），后端不得返回指向自身内部状态的指针 | `EXTRA` 别名陷阱（probe37） |
| R5 | 所有尺寸来自运行时查询（`max_plaintext_chunk()`、`wire_overhead_upper()`），**禁止** 16384/13/16 这类常量出现在调用方 | TLS1.2 与 1.3 的 `hdr/trl` 不同（13/16 vs 5/44，probe21） |
| R6 | 证书以**值类型**暴露（`der` + `spki` + `spki_sha256`），不暴露 `PCCERT_CONTEXT`/`X509*` | CredSSP 只需要 SPKI（probe35 证明 `PublicKey.pbData` 就是 270 字节 SubjectPublicKey，无需 ASN.1 解析） |
| R7 | 协商结果可查询（`negotiated_version`、`cipher_suite_id`、`cipher_suite_name`），且 `min_version` 在握手后**强制断言** | 静默降级（§1.2）；`aiCipher` 是 CALG 不是套件（§1.3） |
| R8 | 生命周期按实例管理，无全局 init/cleanup；析构必须幂等 | OpenSSL 有 `OPENSSL_init_ssl`/`atexit`，SChannel 有 `FreeCredentialsHandle`；调用方不该知道 |
| R9 | 关闭语义显式两段：`Shutdown()`（发 close_notify）→ `Closed`；`Abort()`（不发） | SChannel 需要 `ApplyControlToken(SCHANNEL_SHUTDOWN)` + `ISC(ALLOCATE_MEMORY)`（probe4-D） |
| R10 | "可恢复错误"必须由后端归一化，**不允许**把 `SEC_I_RENEGOTIATE` 这类后端私码透出 | TLS1.3 票据伪装成 RENEGOTIATE（probe34/probe39），调用方不可能正确处理 |
| R11 | 后端选择由**配置字符串**决定，不是编译期 `#ifdef`；同一二进制内可同时注册多个后端 | 三个月后要"换"，不是"重编"；也让 A/C 类测试可以注入假后端 |
| R12 | 测试钩子：可注入随机数源与"时钟"（仅测试构建启用） | pubKeyAuth nonce/ClientChallenge 需要确定性（§3.2-A） |

### 6.2 会让切换变贵的反模式（明确禁止）

- 在 `connect_machine.h` 里加 `#include <windows.h>` 或 `CtxtHandle` 成员
  —— 现有 `kAwaitExternalSecurity` 钩子设计是对的（纯字节 in/out，
  `[READ:F:\rtsc\include\rtsc\proto\connect_machine.h:74-84]`），不要破坏它。
- 让 `TlsTransport::Read` 直接返回"一条记录" —— 把"记录"概念泄漏给上层，
  换到 OpenSSL（无记录 API）时无法实现。
- 让上层自己处理 `EXTRA`/`SECBUFFER_MISSING` —— 换后端时全部逻辑作废。
- 用 `std::function` 回调把后端事件（如"证书到达"）散播到多处 —— 事件集合会被后端绑定，
  应改为一次性查询 + 少量状态转移。
- 把 `SHA256(SPKI)` 的 pin 逻辑写进 TLS 后端 —— 它是**策略层**，必须在后端之外，
  否则换后端时 pin 语义会跟着变（SChannel 的 `CERT_CHECK_RESULT` 与 OpenSSL 的
  `X509_STORE_CTX_get_error` 不是同一套语义）。

### 6.3 "三个月后换后端"的演练（可执行）

1. 新增一个 `ScriptedBackend`（不依赖任何 TLS 库），实现同一接口；
   若 A+C 类测试在它上面全绿，说明接口没有泄漏后端语义。
2. 用 `TlsBackendRegistry` 注册 `schannel` 与 `scripted`，用配置切换；
   若切换只需改一行配置，R11 达标。
3. 编译一个**不链接 secur32/crypt32** 的构建（仅 scripted 后端）：
   若整个 `rtsc_proto` 仍能编译，R1 达标。
4. 在 Linux 上编译同一份 `rtsc_proto` + scripted 后端：
   若通过，跨平台接口边界正确（真后端另说）。
5. 把 `SEC_I_RENEGOTIATE`/`0x80090330` 等私码从公共头里 grep 一遍，命中即 R2/R10 未达标。

---

## §7 未验证项

| # | 项 | 为什么没验证 | 怎么验证 |
|---|---|---|---|
| U1 | FIPS 模式下的 SChannel 行为 | 改 `FipsAlgorithmPolicy` 需重启且属系统级变更，超出本次授权 | 在测试机置 `Enabled=1` 重启，跑 probe29/probe31，记录 `AcquireCredentialsHandle` 与套件 |
| U2 | Win7 / Win8.1 / Server2012 / Win10 22H2 的实际行为 | 只有一台 Win11 25H2（build 26200） | 在 VM 上跑同一组探针；重点看 `SCH_CREDENTIALS` 是否 `0x80090331`、`TLS1_3` 是否被接受 |
| U3 | 管理员套件策略禁用 AES256 后的表现 | 未改系统策略（只做了客户端侧 `cDisabledCrypto` 黑名单） | 改 `...\SSL\00010002\Functions` 后跑 probe29 |
| U4 | `errorCode` 是否真的非严格 DER（D15） | 需要正确凭据走到 CredSSP 失败分支 | 用错误密码抓第 2/3 步 TSRequest，逐字节比对 `ber.cpp` 的拒绝规则 |
| U5 | TLS1.3 服务端 NewSessionTicket 的条数与时机是否稳定 | 只观察到 1 次（103 字节，1 条票据） | 连续 50 次连接统计；确认"每次握手后必有一条"才能写进状态机 |
| U6 | 服务端发起 TLS1.2 重协商后，CredSSP 的 SPKI 绑定是否失效 | 未实现 CredSSP，无法验证端到端 | 实现后用"重协商前后 SPKI 是否变化"做断言；预期必须变化则拒绝重协商 |
| U7 | OpenSSL 头在 `/W4 /WX /permissive-` 下的具体告警集 | 本机无 OpenSSL 头 | 拿到库后单独编一个 TU，统计告警并按 §2.5 的 `SYSTEM` 方案处理 |
| U8 | OpenSSL 静态库在 Windows/Linux 的实际体积 | 无库可测 | 构建后 `dumpbin /headers` / `size` 测量 |
| U9 | `SCH_CREDENTIALS` 在 Win10 1809–22H2 上 `cTlsParameters` 是否被完全支持 | 无该版本机器 | 同 U2 |
| U10 | 服务器是否会在 TLS1.3 下要求客户端证书 | 本服务器不要求 | 企业环境实测 |
| U11 | 真实 RDP 服务器在 TLS 建立后、MCS 之前是否会发非票据的 post-handshake 消息 | 只观察到 NewSessionTicket | 抓 50 次握手的首个 `recv`，分类统计 |
| U12 | `security-layer.md:1463` 关于 `errorCode` 非严格 DER 的原始抓包 | 该文档未给字节样本 | 需文档作者补证据，或按 U4 自采 |

---

## 附：本文引用的探针与关键输出（可复现）

| 探针 | 证明什么 | 关键输出 |
|---|---|---|
| `.tmp/tlsprobe/probe5.cpp` | 证书策略矩阵 | 无 manual → `0x80090325`；MANUAL → 成功但 `CERT_CHECK_RESULT=0x80090301`；DEFERRED → `hr=0x800B0109` |
| `probe9.cpp` / `probe16.cpp` | TLS1.3 与 legacy cred | `SP_PROT_TLS1_3_CLIENT` → cred `0x80090331`；`1.2\|1.3` → `proto=0x0800`（静默降级） |
| `probe20.cpp` / `probe27.cpp` | 4-SecBuffer 下限 | nbuf=1..3 → `0x80090308`；nbuf=4 → OK |
| `probe21.cpp` | `cbTrailer` 是上界 | TLS1.3 `hdr=5 trl=44` 但 `payload=16` 时实际线长 38 |
| `probe36.cpp` | `MISSING` 语义 | 1 字节时 `MISSING=12`；13 字节时 `MISSING=32`（总数 45） |
| `probe37.cpp` | `EXTRA` 别名 | `buf[3] type=5 cb=37 offsetFromStart=37 inInputRange=1` |
| `probe11.cpp` | 累计缓冲 | 只喂剩余 → `0x80090308`；喂累计 → OK |
| `probe18.cpp` | 丢 `EXTRA` | 后续记录 `0x80090330`（TLS1.2/1.3 均如此） |
| `probe25.cpp` / `probe26.cpp` | 篡改记录 | TLS1.2 poisoned 10/10；TLS1.3 recovered 10/10 |
| `probe34.cpp` / `probe39.cpp` | TLS1.3 票据 | `SEC_I_RENEGOTIATE` + `EXTRA=103`（`16 03 03 00 62 04 ...` = NewSessionTicket）；`ISC` 后必须视为已消费 |
| `probe24.cpp` | 重协商 | TLS1.2 `SEC_I_RENEGOTIATE` → 197/822/206 字节多轮；TLS1.3 → `0x00090360` |
| `probe4.cpp` | close_notify | 无 `ALLOCATE_MEMORY` → `0x80090300`；有 → 24 字节，对端 `0x00090317` |
| `probe29.cpp` / `probe38.cpp` | 真实套件 | TLS1.2 = `0x009D TLS_RSA_WITH_AES_256_GCM_SHA384`；禁 RSA kex → `0xC030` |
| `probe35.cpp` | SPKI 提取 | `PublicKey.pbData` 270 字节，verbatim 在 SPKI 偏移 24、证书偏移 134 |
| `probe19.cpp` | 差分预言机 | BCrypt 支持 MD4/RC4/MD5/SHA*/AES/3DES/ECDH_P256；HMAC-MD5 需 `HMAC_FLAG` |
| `tpkt_tls3.cpp` / `tpkt_tls2.cpp` | 两层混用 | 密文喂 `TpktStream` → `NeedMoreData` + `dropped=2`；构造密文可被当作合法 PDU |
| `probe27.cpp` | 分片 | 65528 字节 → 4 条记录，回读 `match=1` |
| `probe32.cpp` | 零长/双向认证 | `EncryptMessage(0)` OK；`ASC_REQ_MUTUAL_AUTH` → `0x00090320` |
| `probe40.cpp` | close_notify 标志隔离 | 只给 `ISC_REQ_STREAM`（无论 null 还是空 desc）→ `0x80090300`；加 `ISC_REQ_ALLOCATE_MEMORY` → `0x00000000 out=24` |
