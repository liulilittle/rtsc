# TLS 后端方案设计与缺陷审计（审计甲）

- 角色：TLS 后端方案审计 AI（甲）；只做方案设计与缺陷审计，不写生产代码、不改现有文件。
- 日期：2026-10-22
- 证据基线（只读）：
  - `F:\rtsc\evidence\schannel-probe.txt`（SChannel 对真实服务器 TLS 1.2 握手）
  - `F:\rtsc\evidence\schannel-spki-probe.txt`（SPKI DER 导出与逐字节比对）
  - `F:\rtsc\evidence\schannel-tls-backend.md`（探针复现命令与结论）
  - `F:\rtsc\docs\spec\security-layer.md`（§4 / §5.4.0 / §8）
  - `F:\rtsc\include\rtsc\proto\connect_machine.h`（接入钩子）
  - `F:\rtsc\CMakeLists.txt`（库划分）
- 环境实测（本次会话，`$env:TEMP='F:\rtsc\.tmp'`）：
  - `openssl` / `perl` / `nasm` / `vcpkg` / `go` / `rustc` → 全部 `NOT FOUND`
  - `python` → `C:\Python314\python.exe`，`3.14.7`，内置 `OpenSSL 3.5.7`，`HAS_TLSv1_3=True`
  - `node` → `C:\Program Files\nodejs\node.exe`；`dotnet` → SDK `9.0.318`
  - OS `10.0.26200.0`（Win11），`TermService=Stopped`，`3389` 无监听
  - SDK `10.0.26100.0`：`um\schannel.h`、`shared\sspi.h`、`shared\security.h`、`secur32.lib`、`crypt32.lib`、`ncrypt.lib` 均存在

---

## §0 结论摘要

| 问题 | 结论 |
|---|---|
| 今天能否落地 | **能**。Windows 上零依赖 SChannel 后端已完成真实服务器 TLS 1.2 握手与 SPKI 导出（E 级实测），今天即可进入实现。 |
| 推荐形态 | **双后端 + 后端无关接口**：Windows=SChannel（今天），Linux=OpenSSL（后续，CMake 可选开启）。 |
| 是否引入第三方 | **Windows 路径不引入**；Linux 路径引入 OpenSSL 3.x（Apache-2.0）。零依赖约束在 Windows 侧完全保持。 |
| NTLM / CredSSP | **永远自研**。不得使用系统 `CredSSP` SSP（会把 `security-layer.md` 的 §5.4 pubKeyAuth 与 §6 NTLM 整个黑盒化，与本项目目标冲突）。 |
| 现有 §8 结论 | **不成立**。我方原列 11 条；与 consult-b 的 16 条合并去重后 **20 条**（§4；D14 经乙自我复核撤回、降为条件性风险）。核心是「跨平台唯一解」的前提被实测推翻，且三条 Windows 集成路径在当前环境全部不可用；另新增 3 条 SChannel 专有语义约束（≥4 buffer / EXTRA 算术定位 / TLS1.3 票据必须消费）。 |
| 红证可行性 | **可全自动化，且主路径已实跑通过（E 级）**：进程内 SChannel 回环 `RESULT=PASS`（握手 2 轮 + 双向应用数据 + 双记录 EXTRA + 截断 0x80090318，见 §5 T1），另加 Python/OpenSSL 独立实现交叉验证 + 固定字节向量 + 负向向量。不依赖 Linux / 第二台 RDP 服务器。 |

三条必须先说清的事实：

1. SChannel 只作为 **TLS 传输** 使用时，不涉及任何 CredSSP 黑盒——它只提供加密通道与对端证书，
   握手驱动、记录层、SPKI 全部可观测。探针代码里 `AcquireCredentialsHandleW` 的包名是
   `UNISP_NAME_W`（"Microsoft Unified Security Protocol Provider"），**不是** `"CredSSP"`
   [READ:F:\rtsc\.tmp\tlsprobe\probe.cpp:61]。注意：项目内的权威证据
   [READ:F:\rtsc\evidence\schannel-tls-backend.md:25] 只写了 "AcquireCredentialsHandle OK"，
   未记录包名——**这一点属于我的本地探针观察，未进项目证据库，标注为 C 级**。
   但这不影响结论：`schannel-tls-backend.md:5-7` 明确该握手是「Windows 自带的 SChannel」，
   且 `schannel-probe.txt` 里没有任何 CredSSP/TSRequest 字节，只有纯 TLS 记录。
2. SPKI 有**两个**必须区分的长度：`SubjectPublicKeyInfo` DER = **294 字节**，其内部
   `SubjectPublicKey`（BIT STRING 内容）= **270 字节**。CredSSP 加密的是 **270** 那个
   [READ:F:\rtsc\evidence\schannel-spki-probe.txt:3] + [READ:F:\rtsc\docs\spec\security-layer.md:708-709]。
   接口必须两个都能给，否则 CredSSP 会拿错字节。
3. TLS 记录开销是**可查询的运行时量**，不是常量：本目标 `header=13 trailer=16 maxmsg=16384`
   [READ:F:\rtsc\evidence\schannel-probe.txt:12]。13 = 记录头 5 + GCM 显式 nonce 8；
   换版本/套件会变（TLS1.3 的 AES-GCM 总开销是 5 + 1 内层 content-type + 16 tag = 22 字节，
   但后端如何把它拆成 `cbHeader`/`cbTrailer` **未实测**，见 §6 U1）。

---

## §1 方案对比

维度固定为：构建成本 / 许可 / 跨平台性 / 能否取 SPKI / 能否关闭证书链校验 /
能否暴露记录开销 / 失败模式 / 对 `/W4 /WX` 的影响。

### 1.1 总表

| 维度 | A. SChannel（零依赖） | B. OpenSSL 3.x | C. BoringSSL | D. mbedTLS 3.6 | E. 自研最小 TLS |
|---|---|---|---|---|---|
| 构建成本（本机） | **0**：只链 `secur32/crypt32/ncrypt` | **今天不可行**（无 perl/nasm/vcpkg） | **今天不可行**（需 Go，实测 `go NOT FOUND`） | 中：源码 + CMake + Python（Python 有） | 极高：ECDHE/X25519 + AES-GCM + SHA256 + DER + bignum ≈ 6–10k 行 |
| 许可 | OS 组件，无额外负担 | Apache-2.0（3.0+） | Apache-2.0 | Apache-2.0 **OR** GPL-2.0 | 自有 |
| 跨平台 | **仅 Windows** | Windows + Linux 一等公民 | 两者皆可 | 两者皆可 | 两者皆可 |
| 取 SPKI | **能**，`CryptEncodeObjectEx(X509_PUBLIC_KEY_INFO)`，294B，已实测 | 能，`i2d_PublicKey` 给 **270B**（非 294B，需自行补 SEQUENCE 头） | 能，`i2d_RSAPublicKey` 同上 | 能，`mbedtls_pk_write_pubkey_der` 给 SPKI | 要自己写 DER 解析 |
| 关证书链校验 | **能**，`SCH_CRED_MANUAL_CRED_VALIDATION`（0x8）+ `SCH_CRED_NO_SERVERNAME_CHECK`（0x4） | 能，`SSL_VERIFY_NONE` | 能，自定义 verify callback | 能，`MBEDTLS_SSL_VERIFY_NONE` | 天然（自己决定） |
| 暴露记录开销 | **能**，`SECPKG_ATTR_STREAM_SIZES` → `{cbHeader=13,cbTrailer=16,cbMaximumMessage=16384}` | 半能：无直接 API，需按套件公式推算 | 半能：需读内部常量 | 半能：`MBEDTLS_SSL_HEADER_LEN` + 套件推算 | 能（自己定的） |
| 主要失败模式 | SSPI 状态码族（见 1.2） | 无 perl 无法构建；legacy provider 缺失 | 无 Go 无法构建；API 随 master 漂移 | 默认配置裁剪导致套件缺失；需自带 MD4/RC4（已有） | 密码学实现错误 → 静默不安全 |
| `/W4 /WX` 影响 | 中：`windows.h` 宏污染（min/max）、`sspi.h` 需 `SECURITY_WIN32`、`UNISP_NAME_W` 的 `const_cast` | 低（头文件干净），但 `find_package(OpenSSL REQUIRED)` 缺失会让**整个工程 configure 失败** | 低 | 低 | 高（自己写的一切都要过 /W4） |
| 今天可落地 | **是** | 否 | 否 | 可（但破坏零依赖） | 否（工期不可接受） |

### 1.2 各方案失败模式细化

**A. SChannel** — 失败模式是 SSPI `SECURITY_STATUS`，必须逐值映射，不能只判 `!= SEC_E_OK`：

下表的数值**逐个取自 `shared\winerror.h`**（`Select-String` 实测），不是凭记忆：

| 状态码 | 名称 | 语义 | 接口应映射为 |
|---|---|---|---|
| `0x00000000` | `SEC_E_OK` | 握手完成 / 操作成功 | `kOk`，`handshake_complete=true` |
| `0x00090312` | `SEC_I_CONTINUE_NEEDED` | 需要继续握手（本轮产生了输出 token） | `kOk`（带 out）+ 继续驱动 |
| `0x00090320` | `SEC_I_INCOMPLETE_CREDENTIALS` | 服务器要求客户端证书 | `kUnsupported`（RDP 不要求客户端证书） |
| `0x00090321` | `SEC_I_RENEGOTIATE` | **双语义**：TLS1.2=对端重协商；**TLS1.3=NewSessionTicket**（实测 `[BASH:verify_t3.exe]`：`DecryptMessage(pending) -> 0x00090321 data=0 extra=103`） | 见 §3.2/§3.3：**不得**外泄给 `Receive` 调用方；后端内部消化（`> [consult-b 修正 1]`） |
| `0x00090317` | `SEC_I_CONTEXT_EXPIRED` | 收到 close_notify（**I** 前缀） | `kClosed` |
| `0x80090317` | `SEC_E_CONTEXT_EXPIRED` | 上下文已过期（**E** 前缀，易与上一条混淆） | `kClosed` |
| `0x80090318` | `SEC_E_INCOMPLETE_MESSAGE` | 记录不完整（**正常**，需再读） | `kNeedMoreInput` |
| `0x8009030F` | `SEC_E_MESSAGE_ALTERED` | 记录被篡改 / 解密失败（`kDecryptFailed` 的**唯一**来源） | `kDecryptFailed` |
| `0x80090330` | `SEC_E_DECRYPT_FAILURE` | 解密失败（**另一个**来源，与上一条不同码） | `kDecryptFailed` |
| `0x80090329` | `SEC_E_ENCRYPT_FAILURE` | 明文超 `cbMaximumMessage` / 缓冲不足 | `kInternal`（后端应自行切片，不应到达此态） |
| `0x80090300` | `SEC_E_INSUFFICIENT_MEMORY` | `Shutdown` 忘了 `ISC_REQ_ALLOCATE_MEMORY`（实测 `[BASH:verify_traps.exe]`：`alloc=0 -> out=0`，`alloc=1 -> out=31 first=15`） | `kInternal` |
| `0x80090360` | `SEC_I_NO_RENEGOTIATION` | TLS1.3 服务端拒绝重协商，**正常** | `kOk`（忽略） |
| `0x80090326` | `SEC_E_ILLEGAL_MESSAGE` | 对端消息非法 | `kProtocolError` |
| `0x80090327` | `SEC_E_CERT_UNKNOWN` | 证书无法验证（链校验开启时） | `kCertRejected` |
| `0x80090304` | `SEC_E_INTERNAL_ERROR` | 内部错误 | `kInternal` |
| `0x80090308` | `SEC_E_INVALID_TOKEN` | 对端数据非法 | `kProtocolError` |
| `0x8009030E` | `SEC_E_NO_CREDENTIALS` | 凭据句柄失效 | `kInternal` |
| `0x80090331` | `SEC_E_ALGORITHM_MISMATCH` | 无共同算法 | `kProtocolError` |

> 审计发现（自查）：初稿把 `SEC_I_CONTEXT_EXPIRED` 写成 `0x00090315`、把
> `SEC_I_INCOMPLETE_CREDENTIALS`/`SEC_I_RENEGOTIATE` 都写成 `0x0009031A`、把
> `SEC_E_MESSAGE_ALTERED` 与 `SEC_E_INCOMPLETE_MESSAGE` 的码互换（写成 `0x80090326`/`0x80090327`，
> 而这两个码实际是 `SEC_E_ILLEGAL_MESSAGE`/`SEC_E_CERT_UNKNOWN`）。已按 `winerror.h` 全部更正。
> **教训：SSPI 状态码必须从 SDK 头文件抄，不能凭记忆；实现阶段应加静态断言**
> `static_assert(SEC_I_CONTEXT_EXPIRED == 0x00090317L)` 之类，让抄错在编译期暴露。

`SEC_E_INCOMPLETE_MESSAGE` 是 SChannel 记录层分帧的**核心机制**：`DecryptMessage` 在缓冲区不足时
返回它，且**不消费**任何字节；成功时通过 `SECBUFFER_EXTRA` 指出剩余未消费字节（可能包含下一条
记录的完整内容）。因此后端必须持有 `rx_buffer_`，不能把「一次 recv = 一条记录」当假设。

**B. OpenSSL** — 失败模式：① 构建期（缺 perl → `Configure` 直接失败）；② 运行期
`SSL_ERROR_WANT_READ/WRITE`（用内存 BIO 时必须区分「需要更多对端字节」与「有字节要发出」）；
③ `SSL_ERROR_SSL` + `ERR_get_error()` 队列（必须 drain，否则下一次错误被污染）；
④ `X509_V_ERR_*` 在校验回调里（默认关闭校验后不会出现，但 TOFU 计算必须自己取 `SSL_get1_peer_certificate`）。

**C. BoringSSL** — 失败模式主要是**供应链**：无版本化发布、无 ABI 承诺、`BORINGSSL_API_VERSION`
随 master 变动；构建需 Go + CMake + 汇编器。今天 `go NOT FOUND` → 直接出局。

**D. mbedTLS** — 失败模式：`mbedtls_config.h` 默认裁剪（`MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED`
等需显式开启）；3.x 已移除 MD4/RC4（本项目已有，无影响）；`mbedtls_ssl_read` 返回
`MBEDTLS_ERR_SSL_WANT_READ` 与 `MBEDTLS_ERR_SSL_CLIENT_RECONNECT` 需分别处理。

**E. 自研** — 失败模式是**不可审计的正确性**：GCM 的 GHASH 常量时间实现、P-256 点运算的侧信道、
证书链解析的越界，任何一处错误都可能是「握手成功但不安全」。且要额外实现 bignum/ECC，
与「零依赖」的字面要求冲突（自己写 10k 行比引一个库风险更高）。**否决**。

---

## §2 推荐方案与理由

### 2.1 结论

> **Windows 主后端 = SChannel（零依赖，今天落地）；Linux 主后端 = OpenSSL 3.x（CMake 选项
> `RTSC_TLS_OPENSSL=ON` 时才 `find_package`，默认 OFF）；两者共用 `TlsTransport` 抽象。
> NTLM/CredSSP 一律自研，禁止走系统 `CredSSP` SSP。**

### 2.2 理由

1. **硬约束 #2（零依赖）在 Windows 侧被严格满足**：SChannel 是 OS 组件，链接 `secur32.lib`
   不引入任何可分发第三方代码，`/W4 /WX` 可控（见 3.6 的警告抑制策略）。
2. **硬约束 #3（跨平台、接口可换后端）被接口层满足**：后端无关接口 + 工厂函数，
   Linux 侧只需实现同一接口，不改协议层与测试。
3. **实测已证明能力完备**：握手两轮完成、`protocol=0x0800`、`cipher=0x6610`、SPKI 294B 与证书
   DER 偏移 134 逐字节一致 [READ:F:\rtsc\evidence\schannel-probe.txt:6-12] +
   [READ:F:\rtsc\evidence\schannel-spki-probe.txt:4-6]。**没有一项 CredSSP 前置能力缺失。**
4. **不黑盒化协议**：只用 TLS 传输；pubKeyAuth / NTLM 仍由 `rtsc_crypto`（已有 MD4/MD5/RC4/SHA-1，
   `include\rtsc\crypto\hash.h:16,22,28,43`）自研实现，符合「逆向 mstsc 协议栈」的工程目标。
5. **风险可隔离**：Linux 后端缺失时，`CreatePlatformTlsTransport` 返回 `kUnsupported` 并在
   `why` 里给出可读原因；协议层与 12 个既有套件不受影响（不引入 `find_package(OpenSSL REQUIRED)`
   这种全局硬依赖）。

### 2.3 明确否决的两条捷径

| 否决项 | 理由 |
|---|---|
| 用 `AcquireCredentialsHandle(NULL, "CredSSP", ...)` 一把梭 | 会把 §5.4（pubKeyAuth）与 §6（NTLM）整体跳过，项目失去核心价值；且 Linux 不可用；中间状态不可观测 [READ:F:\rtsc\docs\spec\security-layer.md:1424] |
| 现在就把 OpenSSL 设为唯一/必需依赖 | 本机三条集成路径全断（无 vcpkg / 无 perl / 未发现任何 openssl 安装）；会让 `verify.ps1` 从「12 套全绿」变成「configure 即失败」 |

### 2.4 与 `ConnectMachine` 的接入点

`ConnectPhase::kAwaitExternalSecurity` → 调用方驱动 `TlsTransport::Handshake` 直到
`handshake_complete()` → 调用 `ConnectMachine::OnExternalSecurityComplete()`
[READ:F:\rtsc\include\rtsc\proto\connect_machine.h:25,113-115]。
此后 `ConnectMachine::OnData` 收到的字节**必须**是 TLS 解密后的明文；发出的 `ConnectStep::output`
**必须**先经 `TlsTransport::Send` 再落到 socket。协议层对 TLS 完全无感知——这是既有设计，
接口设计必须保持这一点（TLS 不进入 `rtsc_proto`，单独一个 `rtsc_tls` 库）。

**与 consult-b 主张 5 的核对（结论：一致，但需补充一层调用方编排）**：

- consult-b 说「`ConnectMachine` 会停在 `kAwaitExternalSecurity`（`connect_machine.cpp:217`），
  TLS 之后还有 CredSSP + EUAR」。**代码核对：成立。**
  - `connect_machine.cpp:213-217`：协商结果非 `kProtocolRdp` 时 `return Step(kAwaitExternalSecurity)`。
  - `connect_machine.cpp:220-226`：该相位下收到任何数据都 `Fail("unexpected data ...")`，
    即协议层**确实**把控制权完全交给调用方。
  - `connect_machine.cpp:352-359`：`OnExternalSecurityComplete()` 直接
    `return SendConnectInitial()` —— 它**不知道** CredSSP 与 EUAR 的存在。
- **但对 `TlsTransport` 的接口设计有一个后果，consult-b 没点明**：
  `OnExternalSecurityComplete()` 的语义是"外部安全**整体**完成"，而 TLS 只是其中第一段。
  因此调用方编排必须是：

  ```
  ConnectMachine: kAwaitExternalSecurity
    → TlsTransport.Handshake() 完成            ← 本设计范围（TLS 层）
    → CredSSP 握手（TSRequest 走 TlsTransport.Send/Receive）  ← 不在本设计范围
    → 读 EUAR 裸 4 字节（HYBRID_EX 才有，也走 TlsTransport.Receive）  ← 不在本设计范围
    → ConnectMachine.OnExternalSecurityComplete()   ← 此时才调用
  ```

  **关键约束**：`TlsTransport` 必须在整个 CredSSP + EUAR 期间保持同一个上下文，
  且 `Receive` 的明文流在这三段之间是**连续**的（没有"重新开始组帧"的机会）。
  这正是 consult-b 修正 1（票据不得外泄）与修正 6（失败时明文未定义）为何是致命级：
  任何一次误判都会把 CredSSP 的 TSRequest 字节流截断。
  本设计的 `TlsTransport` 接口对此是**充分**的（它不关心明文语义，只保证字节流连续），
  但 §5 的测试必须补一条"TLS 握手 → 送 5 个 TSRequest 往返 → 读 4 字节 EUAR"的编排级用例，
  见 §5 T1 绿证断言 9。

---

## §3 `TlsTransport` 接口设计

### 3.1 设计原则

1. **纯虚类 + 工厂函数**（不是结构体+函数指针）：后端需要持有状态（`CtxtHandle` / `SSL*`），
   函数指针表反而要手工传 `void*`，`/permissive-` 下更易出错。
2. **不抛异常**：全工程现无异常使用痕迹，统一用 `Status` + `Error` 返回。
3. **后端持有接收缓冲**：调用方永远「把刚读到的密文全给它」，不用自己拼记录。
4. **明文/密文严格分离**：`Send` 输入明文输出密文；`Receive` 输入密文输出明文。不做隐式转换。
5. **两个 SPKI 都给**：`SubjectPublicKeyInfo`（294B）与 `SubjectPublicKey`（270B）分开命名，
   避免 CredSSP 取错。

### 3.2 类型定义

> **本节已按 consult-b 的 12 处修正重写**（2026-10-22 第②轮磋商）。每处改动标注
> `> [consult-b 修正 N]`，便于追溯。原稿的类型定义保留在 §3.2.0「已废止版本」里供对照。

#### 3.2.0 已废止的原稿（仅供追溯，勿实现）

```cpp
// ❌ 已废止：Status 含 kRenegotiate / kNeedMoreOutput；RecordSizes 把 trailer 当实际尾长；
// ❌ Config 用 bool 表达证书策略；工厂不接受后端名。
```

废止理由见 §3.2.1–§3.2.5 各自的 `[consult-b 修正 N]` 标注。

#### 3.2.1 `Status` / `Error`

```cpp
namespace rtsc::tls {

enum class Status : uint8_t {
  kOk = 0,             // 成功；可能同时带输出，调用方必须检查 out 是否非空
  kNeedMoreInput,      // 需要更多对端字节；当前输入已全部吸收，不得重放
  // ---- 以下六个是**终止性**状态：一旦返回，后端必须置 terminal_ 闩锁，
  //      后续任何调用立即返回同一个错误，不得再触碰上下文（N7 + B5）。
  kPeerAlert,          // 收到 TLS fatal alert；native_code = alert 描述码
  kDecryptFailed,      // 记录认证失败（GCM tag 不匹配 / 被篡改）
  kCertRejected,       // 证书策略拒绝（strict 模式且校验失败 / TOFU pin 不匹配）
  kProtocolError,      // 对端数据违反协议，或版本越出 [min_version,max_version]
  kUnsupported,        // 本后端不支持该配置（Linux 无后端 / 要求客户端证书）
                       //   > [父会话 第⑦步 B8] 归入终止性：配置级不可恢复，
                       //   Handshake 返回它即意味着整条连接没有后续；
                       //   若之后 Receive 还能返回 kNeedMoreInput 就是幽灵状态。
  kInternal,           // 后端内部错误（句柄失效、分配失败、契约自检失败）
                       //   > [父会话 第⑦步 B5] 归入终止性：上下文不可信。
  // ---- 正常终止（不是错误，不闩锁为错误态，但后续调用恒返回 kClosed）----
  kClosed,             // 对端 close_notify（或本地已关闭）
  // ---- 注：原 kIoError 已删除 ----
  //   > [父会话 第⑦步 B8] Receive 的入参是调用方提供的 ciphertext 缓冲，
  //   socket 读写完全由调用方负责，后端没有任何合法的产生点。
  //   保留它等于留一个"谁也不知道什么时候返回"的值。若将来后端自己做 I/O，
  //   应新增独立的 IoTransport 层，而不是在 TlsTransport 里混入。
};
```

> `> [consult-b 修正 1]` **删除 `kRenegotiate`**：TLS1.3 的 NewSessionTicket 会以
> `SEC_I_RENEGOTIATE` 出现（本会话实测 `verify_t3.out.txt`：
> `DecryptMessage(pending) -> 0x00090321 data=0 extra=103`），若把它做成对外状态码，
> 调用方（CredSSP/MCS）没有任何合法处置方式，且 RDP 不允许重协商
> （`security-layer.md:520`「TLS session resumption is not supported」）。
> 后端必须在内部消化：TLS1.3 → 把 EXTRA 喂回 ISC 一次并丢弃产出；TLS1.2 → `kProtocolError`。
>
> `> [consult-b 修正 11]` **删除 `kNeedMoreOutput`**：本接口用 `std::vector` 输出，
> 不存在"调用方缓冲不足"，保留它等于要求每个后端处理一个不可能分支。
>
> `> [consult-b 第⑥步 随修 4]` 上一版只对 `kClosed` 承诺了"后续调用恒返回 kClosed"，
> 对 `kDecryptFailed` / `kProtocolError` / `kCertRejected` / `kPeerAlert` 没有任何承诺。
> 实测依据：TLS1.3 上下文在解密失败后**会自动恢复**（consult-b `probe26`：
> `tamper -> 0x80090330; next record -> 0x00000000 plaintext_ok=1`），TLS1.2 则毒化
> （`probe25`：10/10 poisoned）。两种行为都不能让调用方"接着用"，因此必须由后端
> 提供**幂等终止语义**：终止性状态一律置 `terminal_`，入口直接返回 `last_error_`。
> 这样调用方的错误处理只剩一条路径，不必区分 TLS 版本。
>
> `> [父会话 第⑦步 B5]` **三处必须一致**：§3.2.1 的枚举分组、`Error::terminal()`、
> §3.4.1 的 `Fail()` 注释。上一版只在前两处列了 4 个状态、第三处列了 4 个，
> 而 §3.3 契约表说 `kInternal` 也要"终止"——同一个状态给了两种答案。
> 现统一为 **6 个终止态**：`kPeerAlert` / `kDecryptFailed` / `kCertRejected` /
> `kProtocolError` / `kUnsupported` / `kInternal`。
> `kClosed` 是**正常终止**，单独一类（幂等但不算错误）。

```cpp
struct Error {
  Status status = Status::kOk;
  int32_t native_code = 0;    // SSPI SECURITY_STATUS / OpenSSL SSL_ERROR_* / errno
  std::string message;        // 人类可读；不参与控制流
  bool ok() const noexcept { return status == Status::kOk; }
  // 终止性：true 表示该错误不可恢复，调用方必须关闭连接。
  // > [父会话 第⑦步 B5] 必须含 kInternal：内部错误（句柄失效、分配失败、
  //   契约自检失败）之后上下文不可信，继续用等于赌博。三处（§3.2.1 分组、
  //   本函数、§3.4.1 Fail()）必须给出同一个答案。
  bool terminal() const noexcept {
    return status == Status::kPeerAlert || status == Status::kDecryptFailed ||
           status == Status::kCertRejected || status == Status::kProtocolError ||
           status == Status::kInternal || status == Status::kUnsupported;
  }
};
```

#### 3.2.2 `RecordSizes`（区分上界与实际）

```cpp
struct RecordSizes {
  uint32_t header = 0;            // 明文之前的字节（TLS1.2 GCM=13；TLS1.3=5）
  uint32_t max_plaintext = 0;     // 单次 EncryptMessage 上限（实测 16384）
  uint32_t overhead_upper = 0;    // 明文之后的上界（TLS1.2=16；TLS1.3=44）
  uint32_t overhead_actual = 0;   // 实测实际尾长（TLS1.2=16；TLS1.3=17）★新增
  uint32_t block_size = 0;        // 实测 16（不是 1）
  // 分配上界：只用于 preallocate，禁止用于推进写游标或断言实际长度。
  uint32_t alloc_upper_bound() const noexcept {
    return header + max_plaintext + overhead_upper;
  }
};
```

> `> [consult-b 修正 3]` 原 `max_record() = header+max_plaintext+trailer` 在 TLS1.3 下
> 多算 27 字节（实测 `[BASH:verify_traps.exe]`：`alloc=83 wire=56 (hdr=5 data=34 trl=17) delta=27`）。
> 若测试写 `CHECK(Send(16384).size() == max_record())` 在 TLS1.3 必失败。
> 改名 `alloc_upper_bound()` 并在契约里禁止用它断言实际长度；实际长度只能取 `out.size()`。
> `block_size` 原注释"GCM/流模式 = 1"与实测相反（TLS1.2 GCM 实测 16），已更正。

#### 3.2.3 `Config`（证书策略改成枚举 + pin）

```cpp
enum class CertPolicy : uint8_t {
  kInsecure,   // 完全不校验（仅记录），用于隔离环境
  kTofu,       // 首次信任 + pin SPKI SHA-256（默认）
  kStrict,     // 严格：链校验 + 主机名，必须可诊断失败原因
};

struct Config {
  std::string peer_host;        // 目标地址，用于 SNI 与日志；可为空
  std::string sni;              // 显式 SNI；空 = 用 peer_host；两者皆空 = 不发 SNI
  bool send_sni = true;

  CertPolicy cert_policy = CertPolicy::kTofu;
  std::array<uint8_t, 32> pinned_spki_sha256{};  // 非全 0 时强制匹配
  bool pin_is_set = false;

  // 版本下限/上限：仅表达"意愿"，强制点在 Handshake 的自检里（见 §3.3）。
  bool allow_tls10 = false;
  bool allow_tls13 = true;
  uint16_t min_version = 0x0302;  // TLS1.2
  uint16_t max_version = 0x0304;  // TLS1.3

  size_t max_chunk = 0;           // 0 = 用后端 max_plaintext；>0 则更小者生效
};
```

> `> [consult-b 修正 7]` 原 `verify_chain`/`verify_hostname`/`manual_cert_validation`
> 三个 bool 有两个硬问题：① `SCH_CRED_MANUAL_CRED_VALIDATION` 会**同时**关掉主机名校验
> （SDK 原文 `schannel.h:544-550`："This flag is also ignored if the
> SCH_CRED_MANUAL_CRED_VALIDATION flag is set"），所以
> `manual_cert_validation=true` + `verify_hostname=true` 是自相矛盾的合法配置；
> ② MANUAL 模式下拿不到链校验结果，`kStrict` 会变成"永远通过"的空壳。
> 改为单一 `CertPolicy` 枚举 + 显式 pin，消除不可表达/自相矛盾的组合。
> `kStrict` 的 SChannel 实现必须用 `SCH_CRED_DEFERRED_CRED_VALIDATION`（能取到
> `CERT_CHECK_RESULT`），**禁止**用 MANUAL。
>
> `> [consult-b 修正 9]` `min_version` 默认值由 0x0301 改为 0x0302（§4.1 本就要求默认 TLS1.2）；
> 并新增强制点：`Handshake` 返回成功前必须自检 `negotiated().tls_version` 落在
> `[min_version, max_version]`，越界 → `kProtocolError`。原因：SChannel 的 legacy
> `SCHANNEL_CRED.grbitEnabledProtocols` 无法表达"下限"，给 `TLS1_2|TLS1_3` 会**静默降级**到 1.2
> 且无错误码，只有握手后断言才能发现。

#### 3.2.4 `TlsTransport` 方法签名

```cpp
struct NegotiatedInfo {
  uint16_t tls_version = 0;        // 0x0303 / 0x0304
  uint16_t cipher_suite = 0;       // ★ 来自 SECPKG_ATTR_CIPHER_INFO.dwCipherSuite
  char cipher_suite_name[64] = {}; // "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
};

class TlsTransport {
 public:
  virtual ~TlsTransport() = default;

  // ---- 握手：可多次往返 ------------------------------------------------
  // consumed 的唯一正确算法：consumed = in_size - Σ(EXTRA.cbBuffer)
  //   EXTRA 的 pvBuffer 可能为 NULL（实测），只允许读 cbBuffer，禁止解引用。
  // 自检：consumed + Σ(EXTRA) == in_size，否则 kInternal。
  virtual Error Handshake(const uint8_t* in, size_t in_size,
                          size_t& consumed, std::vector<uint8_t>& out) = 0;

  // ---- 发送应用数据 ----------------------------------------------------
  // 明文超过 max_chunk 时后端必须内部切分，不允许返回错误。
  // 实际写出的密文长度只能取 out.size()，禁止用 RecordSizes::alloc_upper_bound()。
  virtual Error Send(const uint8_t* plaintext, size_t size,
                     size_t& consumed, std::vector<uint8_t>& out) = 0;

  // ---- 接收应用数据 ----------------------------------------------------
  // 后端内部消化所有 post-handshake 消息（TLS1.3 票据）；绝不外泄成状态码。
  // 返回 kRenegotiate 属于实现 bug（该值已从 Status 删除）。
  //
  // plaintext 是**追加写**（调用方传入的已有内容会被保留并续写），
  //   一次调用可能追加**多条**记录的明文（见 §3.4.2 边界 2/9）。
  // 当返回 != kOk 且 != kClosed 时，plaintext 内容与长度均未定义，
  //   后端必须在此之前 plaintext.clear()（整批丢弃，含错误前已解出的记录），
  //   调用方必须丢弃。
  //
  // max_out 是**软阈值**（> [consult-b 第⑥步 随修 1]）：
  //   * 语义为"至少产出这么多就可以返回"，不是硬上限；
  //   * 实际追加量**可以超出** max_out，最多超出一条记录（<= max_plaintext）；
  //   * 调用方**不得**假设 plaintext.size() <= max_out；
  //   * max_out == 0 表示不限。
  //   * **排空义务**（> [父会话 第⑦步 B9]）：达到 max_out 提前返回时，rx_buffer_
  //     里可能还有完整记录。调用方**必须继续调用 Receive（可传 size=0）直到
  //     buffered_input()==0**，否则明文滞留在后端，上层永远收不到。
  //     这是软阈值的必要配套——否则"软"就变成了"丢"。
  //   选择软阈值的原因：硬上限需要后端持有"半条记录已解出的明文"状态
  //   （记录边界与 max_out 边界不对齐），复杂度和出错面显著上升。
  //   调用方（TPKT 组帧层）本来就要按长度字段切分，软阈值不会造成实际困难。
  virtual Error Receive(const uint8_t* ciphertext, size_t size,
                        std::vector<uint8_t>& plaintext, size_t max_out) = 0;

  // ---- 对端公钥 --------------------------------------------------------
  // SubjectPublicKeyInfo 整段 DER（RSA-2048 实测 294B；RSA-1024 实测 162B）
  virtual Error PeerSubjectPublicKeyInfo(std::vector<uint8_t>& out) const = 0;
  // SubjectPublicKey：直接取 CERT_PUBLIC_KEY_INFO.PublicKey.pbData/cbData。
  // ★ 禁止用固定偏移从 SPKI 里切（实测 RSA-2048 偏移 24、RSA-1024 偏移 22）。
  virtual Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const = 0;
  // 整张叶子证书 DER（TOFU pin 用；本目标 742 字节）
  virtual Error PeerCertificateDer(std::vector<uint8_t>& out) const = 0;

  // ---- 协商结果 --------------------------------------------------------
  virtual Error negotiated(NegotiatedInfo& out) const = 0;
  virtual RecordSizes record_sizes() const = 0;

  // ---- 优雅关闭 --------------------------------------------------------
  // SChannel：ApplyControlToken(SCHANNEL_SHUTDOWN) → ISC_REQ_STREAM |
  //   ISC_REQ_ALLOCATE_MEMORY，输入描述符 nullptr，输出 pvBuffer 必须 nullptr
  //   （由 SChannel 分配，随后 FreeContextBuffer）。
  // 幂等：重复调用返回 kOk 且 out 为空。
  virtual Error Shutdown(std::vector<uint8_t>& out) = 0;

  // ---- 状态 ------------------------------------------------------------
  virtual bool handshake_complete() const noexcept = 0;
  virtual bool closed() const noexcept = 0;
  virtual size_t buffered_input() const noexcept = 0;
  virtual const Error& last_error() const noexcept = 0;
  virtual const char* backend_name() const noexcept = 0;
};
```

> `> [consult-b 修正 4]` 原 §3.5 写"剥 24 字节头得到 270B"只对 RSA-2048 + long-form 长度成立；
> 同一台机器生成的 RSA-1024 自签证书是 SPKI=162 / SubjectPublicKey=140 / 偏移 22。
> 正确做法是根本不要剥：`CERT_PUBLIC_KEY_INFO` 已经把 `AlgorithmIdentifier` 与
> `PublicKey`（BIT STRING 内容）分开了，直接取 `PublicKey.pbData/cbData`。
>
> `> [consult-b 修正 6]` `Receive` 契约补"失败时 plaintext 未定义"：实测篡改记录时
> `SECBUFFER_DATA` 仍带长度且内容是密文，若按"先遍历追加明文、后看状态"的写法
> （我自己的 `loopback_schannel.cpp` 就是那个顺序）会把密文当明文交给 `ConnectMachine`。
>
> `> [consult-b 修正 8]` 新增 `negotiated()`：`aiCipher` 是 CALG（`0x6610` = `CALG_AES_256`），
> **不是**密码套件号；`CONNECTION_INFO_EX` 只给算法名不给套件号；唯一能拿套件号的是
> `SECPKG_ATTR_CIPHER_INFO`。原稿把 `CONNECTION_INFO_EX` 当作 TLS1.3 的套件来源，是错的。

#### 3.2.5 工厂与后端注入

```cpp
struct BackendInfo {
  const char* name;     // "schannel" / "openssl" / "scripted"(测试)
  bool available;
  const char* reason;   // 不可用原因
};

// 按名字创建；backend 为空 = 平台默认。
std::unique_ptr<TlsTransport> CreateTlsTransport(std::string_view backend,
                                                 const Config& config,
                                                 std::string& why);
std::vector<BackendInfo> EnumerateTlsBackends();

inline std::unique_ptr<TlsTransport> CreatePlatformTlsTransport(const Config& c,
                                                                std::string& w) {
  return CreateTlsTransport(std::string_view{}, c, w);
}

}  // namespace rtsc::tls
```

> `> [consult-b 修正 10]` 原工厂不接受后端名，测试无法注入 `ScriptedBackend`，
> 导致 consult-b 的 C 类（故障注入）与 D 类（差分）测试写不出来。
> 新增按名创建的重载，`CreatePlatformTlsTransport` 退化为一行内联包装（API 兼容）。
>
> `> [consult-b 修正 12]` 随机源注入为**前瞻、非阻塞**，不进本轮签名：
> 它服务于 CredSSP 层的 nonce/ClientChallenge，不属于 `TlsTransport`；
> 且实测 `SECPKG_ATTR_KEYING_MATERIAL` 不可用（返回无效句柄），TLS 层目前无需导出密钥材料。
> 若将来需要，在测试构建里加 `set_test_rng()`，产品路径不暴露。记录于 §6 U11。

### 3.3 每步错误返回语义（调用方契约）

| 调用 | 返回 | 调用方必须做什么 |
|---|---|---|
| `Handshake` | `kOk` + `handshake_complete()==false` | 把 `out` 发出去，继续读对端字节再调 `Handshake` |
| `Handshake` | `kOk` + `handshake_complete()==true` | 把 `out` 发出去（**SChannel 天然把 ClientKeyExchange+CCS+Finished 放在同一 `out` 里**，满足 `security-layer.md` §4.5 的「同一帧」要求），然后转 `Send/Receive`。后端在此前已自检版本区间（§3.2.3 修正 9） |
| `Handshake` | `kNeedMoreInput` | 把 `out`（若有）发出，再从 socket 读；**只**丢弃前 `consumed` 字节，剩余 `in_size-consumed` 必须保留到下一轮 |
| ~~`Handshake`~~ | ~~`kRenegotiate`~~ | **该值已删除**（§3.2.1 修正 1）。重协商在 RDP 场景一律 `kProtocolError` |
| `Handshake` | `kUnsupported` | 终止连接，报配置不支持（如 `SEC_I_INCOMPLETE_CREDENTIALS`） |
| `Handshake` | `kProtocolError` / `kPeerAlert` | 终止连接；`native_code` 记录原始码用于诊断 |
| `Send` | `kOk` + `consumed == size` | 把 `out` 整体写出 |
| `Send` | `kOk` + `consumed < size` | 把 `out` 写出，用剩余明文再调 `Send` |
| `Send` | `kClosed` | 不得再发；走关闭流程 |
| `Receive` | `kOk` + `plaintext` 非空 | 交给 `ConnectMachine::OnData`（**一次 `Receive` 可能给出多帧，也可能只给半帧**，由 TPKT 长度字段再组帧）。**多帧时是所有帧按序拼接**，不得只剩最后一帧（§3.4.2 边界 9） |
| `Receive` | `kOk` + `plaintext` 为空 | 正常（零长度应用数据，或仅消化了 post-handshake 票据）；继续读，**不得**当 `kClosed`。票据路径靠 `progressed` 判定，见 §3.4 N8 |
| `Receive` | `kNeedMoreInput` | 继续从 socket 读。**此时 `buffered_input()` 可以为 0**（缓冲已清空且本轮无进展）；若本轮已消费过记录或已产出明文，后端必须返回 `kOk` 而不是 `kNeedMoreInput`（§3.4 N2/N8） |
| `Receive` | `kClosed` | 对端 close_notify；正常结束，不算错误。后续调用恒返回 `kClosed` |
| `Receive` | `kDecryptFailed` | **立即终止**，不得继续（可能被篡改）；`plaintext` 必须已清空。**后续调用必须恒返回同一个 `kDecryptFailed`**（终止闩锁，§3.4 N7） |
| `Receive` | `kProtocolError` / `kPeerAlert` / `kCertRejected` | 终止连接（`Error::terminal()==true`）；后续调用幂等返回同一错误 |
| `Receive` | 任何 `!= kOk && != kClosed` | `plaintext` 的内容与长度**未定义**，调用方必须丢弃（§3.2.4 修正 6） |
| `Receive` | `max_out` 语义 | **软阈值**：实际追加量可超出至多一条记录，调用方**不得**假设 `plaintext.size() <= max_out`（§3.2.4 随修 1）。**达到 `max_out` 提前返回后，调用方必须继续调用 `Receive`（可传 `size=0`）直到 `buffered_input()==0`**，否则已解出的剩余记录会滞留在后端缓冲里（`> [父会话 第⑦步 B9]`） |
| `Shutdown` | `kOk` | 把 `out` 写出后关闭 socket；重复调用 `out` 为空 |
| 任意 | `kInternal` | 记录 `native_code` + `message`，终止；这是 bug 或环境问题（含 `consumed + Σ(EXTRA) != in_size` 的契约自检失败） |

> `> [consult-b 修正 2]` `consumed` 不再是 `in_size`：SChannel 会在握手输入上返回
> `SECBUFFER_EXTRA`，且 `pvBuffer` 可能为 `NULL`（只给长度）。原稿 §3.5 写
> `consumed = in_size` 会丢掉尾部字节（可能是下一条记录的开头）。
> 唯一正确算法：`consumed = in_size - Σ(EXTRA.cbBuffer)`，并断言
> `consumed + Σ(EXTRA) == in_size`；`Σ(EXTRA) > in_size` 或 EXTRA 多于一个 → `kInternal`。
>
> `> [consult-b 第⑤步 复核 1]` 上句"`pvBuffer` 可能为 `NULL`"的依据要分清：
> 本审计**自测**只能证明 `DecryptMessage` 路径的 `EXTRA.pvBuffer` **指向调用方缓冲内部**
> （`offset=63 inCallerRange=1`），**证不出 NULL**；`ISC` 路径为 `NULL` 是采信
> consult-b `probe44`（标 C 级）。但**结论不变且更稳**：两条路径都不碰 `pvBuffer`，
> 只用算术定位 `tail_off = in_size - cbBuffer`。
>
> `> [consult-b 修正 1]` `Receive` 值域里**没有** `kRenegotiate`。TLS1.3 票据会被后端在内部消化：
> 把 EXTRA 喂回 ISC 一次、丢弃产出；若协商为 TLS1.2 却收到重协商 → `kProtocolError`。
> 后端返回 `kRenegotiate` 属于实现 bug（编译期已不可能，因为枚举里没有这个值）。
> **注意**：仅"不外泄"不够，必须同时保证"记录被消费"，否则 TLS1.3 默认路径必断（§3.4 N1）。

### 3.4 记录分帧与缓冲算法（后端实现契约）

> **第⑤步修订（N1/N2/N3）**：原伪代码有 3 个阻断/中级缺陷，已按「取出即消费」重写。
> 原稿错误见 §3.4.0，改后见 §3.4.1。

#### 3.4.0 原稿的错误（已废止，仅供追溯）

```
474     if rx_buffer_.size() < 5: return kNeedMoreInput        ← N2：此时 buffered_input()==0
...
479     record = rx_buffer_[0 .. 5+len]                        ← 视图，非独立副本（N3 前提未写明）
486         feed EXTRA back to ISC once; discard output; continue   ← N1：跳过 493 的 erase
489     if st == NO_RENEGOTIATION: continue                    ← N1：同样跳过 erase
493     erase rx_buffer_[0 .. 5+len]
495     if extra_len: rx_buffer_ = copy(EXTRA 区域)             ← N3：copy 在 erase 之后
```

| # | 缺陷 | 后果 |
|---|---|---|
| **N1** | 486/489 的 `continue` 在 493 的 `erase` **之前** | 103B 的 NewSessionTicket **从未被消费**；下一轮重新解析同一记录 → 再次解密 → `0x80090330`。**TLS1.3 默认路径在首张票据上必然断**（consult-b `probe39`：`iter0=0x00090321, iter1=0x80090330`）。我只修了"外泄状态码"的症状，没修"记录未消费"的根因 |
| **N2** | 474 返回 `kNeedMoreInput`，而 §3.3 契约说"此时 `buffered_input() > 0`" | 恰在"解完所有记录、缓冲已清空"时 `buffered_input()==0` → 契约自相矛盾 |
| **N3** | 495 的 `copy(EXTRA)` 在 493 的 `erase` **之后** | 若 `record` 是 `rx_buffer_` 的视图，`erase` 后 EXTRA 指针悬垂 → 复制到错位字节 → **静默丢帧，无错误码** |

#### 3.4.1 修订后的伪代码（唯一正确写法）

> **第⑥步修订（N5/N6/N7/N8）**：上一版仍含 4 个阻断缺陷，已重写。
> 关键变化：①每次迭代用临时缓冲 `tmp`，成功才累加（N5）；②`INCOMPLETE` 在
> `5+len` 已到齐时是**可达**的，必须判 `kProtocolError`（N6）；③新增 `terminal_`
> 终止闩锁（N7）；④`progressed` 与 `produced` 双计数，不可合并（N8）。
>
> **第⑦步修订（B1/B2/B3/B6）**：上一版伪代码**语义对但跑不起来**——三处结构性缺陷：
> ①成功路径**没有回边**（B1，最严重，一次 `Receive` 只能解一条记录）；
> ②`extra_len` **从未定义**（B2）；③`closed_` 未在入口检查，与「后续恒返回 `kClosed`」矛盾（B3）；
> ④`tmp` 未声明（B6）。**这三条全部通过了第⑥步的文本检查**，因为它们是控制流结构错误，
> 不是文本错误。教训见 §3.4.3。

```
Receive(ciphertext, size, max_out):
  # ---- 入口：两种终止态都必须幂等 ----
  if closed_:                                     # B3：正常终止（close_notify 之后）
      return kClosed                              #     必须恒返回 kClosed（§3.3 契约）
  if terminal_:                                   # N7：错误终止闩锁
      return last_error_

  rx_buffer_ += ciphertext                        # 无条件吸收
  progressed = 0                                  # N8：已消费的记录条数（判空转）
  produced   = 0                                  # N8：已产出的明文字节数（判 max_out）
  tmp        = std::vector<uint8_t>{}             # B6：每轮复用的临时缓冲，必须显式声明

  loop:
    if rx_buffer_.size() < 5:
        return (progressed || produced) ? kOk : kNeedMoreInput   # N2/N8
    (type, ver_major, ver_minor, len) = parse_header(rx_buffer_[0..5])
    if type not in {20,21,22,23}:
        return Fail(kProtocolError)               # Fail() 置 terminal_
    if len > 16384 + 256:
        return Fail(kProtocolError)               # N4
    if rx_buffer_.size() < 5 + len:
        return (progressed || produced) ? kOk : kNeedMoreInput   # N2/N8

    # ---- N1：取出即消费，先摘出再解密 ----
    record = take_front(rx_buffer_, 5 + len)      # 摘出 == 同时从缓冲移除；独立副本
    progressed += 1                               # N8：记录已消费，算一次进展

    # ---- N5：每次迭代用临时缓冲，绝不清空调用方的 plaintext_out ----
    tmp.clear()
    st, extra_len = backend_decrypt(record, tmp)  # B2：extra_len = Σ(EXTRA.cbBuffer)
                                                  #     内部必须自检
                                                  #     consumed + Σ(EXTRA) == record.size()，
                                                  #     不自洽 -> kInternal

    if st == INCOMPLETE:
        # N6：5+len 已到齐仍报 INCOMPLETE，说明不是"字节不够"而是记录非法
        #     （实测 HelloRequest in=9 且 5+len==9 也会返回 0x80090318）
        #     放回会让该记录永不消费、rx_buffer_ 无界增长 → 必须终止
        return Fail(kProtocolError)

    if st == RENEGOTIATE:
        if negotiated.tls_version == 0x0304:
            feed EXTRA back to ISC once; discard output
            continue                              # 记录已消费；progressed 已 +1
        else:
            return Fail(kProtocolError)           # RDP 不允许重协商

    if st == NO_RENEGOTIATION:
        continue                                  # 记录已消费；progressed 已 +1

    if st == CONTEXT_EXPIRED:
        closed_ = true; return kClosed            # 正常 EOF，不置 terminal_

    if st in {ALTERED, DECRYPT_FAILURE}:
        plaintext_out.clear()                     # 错误前已解出的记录一并丢弃
        return Fail(kDecryptFailed)               # N7：置 terminal_，TLS1.3 也不会"自动恢复"

    if st == PEER_ALERT:
        plaintext_out.clear()
        return Fail(kPeerAlert)

    if st == INTERNAL:
        plaintext_out.clear()
        return Fail(kInternal)                    # B5：内部错误同样终止

    # ---- N3：EXTRA 用算术定位，不碰 pvBuffer ----
    if extra_len:
        tail_off = record.size() - extra_len      # 记录内部偏移，与 pvBuffer 无关
        rx_buffer_ = record[tail_off ..] + rx_buffer_

    # ---- N5：成功才累加 ----
    plaintext_out += tmp
    produced += tmp.size()
    if max_out && produced >= max_out:
        return kOk                                # max_out 是软阈值（可超出至多一条记录）
                                                  # 调用方必须继续调用直到 buffered_input()==0（B9）
    continue                                      # B1：回到 loop，继续解缓冲里的下一条

Fail(status):
  last_error_ = {status, native_code, message}
  terminal_ = true                                # B5：kProtocolError / kDecryptFailed /
                                                  #     kCertRejected / kPeerAlert / kInternal
                                                  #     均置位（见 §3.2.1 分组）
  return last_error_
```

**六条不可违反的规则**（写进实现注释）：

1. **`record` 必须是独立副本**（`std::vector` 拷贝或等价的拥有型视图），
   不得是 `rx_buffer_` 的指针/`span` 视图。这是 N3 的前提，必须写明而不是默认。
2. **每个 `continue` / `return` 之前，当前记录必须已被消费**（N1）。
   `INCOMPLETE` 不再是例外——它直接终止（N6）。
3. **`EXTRA` 的位置只用算术定位**：`tail_off = record.size() - extra_len`。
   `DecryptMessage` 路径的 `pvBuffer` 有效但指向调用方缓冲内部；
   `ISC` 路径的 `pvBuffer` 是 `NULL`。**统一不碰 `pvBuffer`**，只读 `cbBuffer`（N3 + 复核 1）。
   `extra_len` **必须由 `backend_decrypt` 显式返回**（B2），不能靠隐式全局状态。
4. **`plaintext_out` 只能在成功路径累加**（N5）。循环体内**禁止** `plaintext_out.clear()`；
   每次迭代必须用独立的 `tmp`。只有错误分支才允许 `plaintext_out.clear()`（表示整批丢弃）。
5. **终止性错误必须闩锁**（N7）。`terminal_` 一旦置位，后续任何调用立即返回
   `last_error_`，不得再触碰上下文——因为 TLS1.3 的上下文在解密失败后**仍能解出下一条**
   （实测 `probe26`：`tamper -> 0x80090330; next record -> 0x00000000 plaintext_ok=1`），
   而 TLS1.2 会毒化（`probe25`：10/10 poisoned）。两种行为都**不允许**调用方继续。
6. **每个循环体末尾必须有显式回边**（B1）。成功路径不能"掉出"循环——
   否则一次 `Receive` 只解一条记录，且会落进下一个函数定义（未定义行为）。
   **这是本轮最严重的结构性缺陷**：语义注释写得再对，没有 `continue` 就执行不到。

> `> [consult-b 第⑤步 N1]` `take_front()` 把 `erase` 提前到解密之前，两个 `continue`
> 都不再跳过消费。consult-b 实测：原写法 `iter0=0x00090321, iter1=0x80090330`
> （同一记录被解密两次 → 认证失败）；改后 iter1 进入下一条记录。
>
> `> [consult-b 第⑤步 N2]` `size < 5` 或 `size < 5+len` 时，若本轮已有进展则返回 `kOk`。
>
> `> [consult-b 第⑤步 N3]` `copy(EXTRA)` 改为从 `record`（独立副本）内部按
> `record.size() - extra_len` 算术切片，不依赖 `erase` 后的指针。
>
> `> [consult-b 第⑤步 N4]` 记录长度上界 `16384 + 256`（RFC 8446 §5.2）。
>
> `> [consult-b 第⑥步 N5]` **上一版是错的**：把 `plaintext_out.clear()` 放在循环体开头，
> 喂 2 条记录时 iter2 会清掉 iter1 的明文 → 返回只剩最后一条，而 `produced` 累加了 200
> （自相矛盾）。这直接违反 §3.4.2 边界 2/3 与 §3.3「一次 Receive 可能给出多帧」，
> 后果是 TPKT 层静默卡死、无错误码。现改为每次迭代用 `tmp`，成功才 `plaintext_out += tmp`。
> 这条的原始要求是父会话第⑤步提的（"循环开头加 clear"），描述不精确，责任不在执行方。
>
> `> [consult-b 第⑥步 N6]` 上一版注释「`5+len` 到齐 → 不应发生」是**假的**。
> consult-b `probe7` 实测 `HelloRequest in=9 -> 0x80090318`——9 字节记录 `5+len` 完全到齐、
> type/len 全合法，仍返回 `SEC_E_INCOMPLETE_MESSAGE`。若按上一版"放回 + 返回 kNeedMoreInput"，
> 下轮又摘出同一条、又放回 → **该记录永不消费，新字节不断累积 → `rx_buffer_` 无界增长至 OOM**。
> 现改为 `kProtocolError` 并置 `terminal_`。
>
> `> [consult-b 第⑥步 N7]` 上一版在 `kDecryptFailed` 后无终态闩锁。实测 TLS1.3 上下文
> **会自动恢复**（`probe26`：篡改后下一条仍能正常解出），TLS1.2 则毒化（`probe25`：10/10）。
> 不闩锁等于把"篡改必须停"完全外包给调用方，而调用方（CredSSP）无法区分
> "上下文已坏"与"网络抖动"。现加 `terminal_`，对 `kProtocolError` / `kDecryptFailed` /
> `kCertRejected` / `kPeerAlert` 一律置位。
>
> `> [consult-b 第⑥步 N8]` 上一版只有 `produced`，票据路径 `produced==0` → 返回
> `kNeedMoreInput`，与 §3.3「票据后返回 `kOk`」和 §5 绿证 8 直接冲突（三者不可能同时为真）。
> 现改为双计数：`progressed`（消费过的记录数，判是否空转）+ `produced`（明文字节数，判 `max_out`），
> 返回逻辑 `(progressed || produced) ? kOk : kNeedMoreInput`。二者语义不同，**不可合并**。

#### 3.4.3 控制流自检（B1 的直接教训）

> `> [父会话 第⑦步 要求]` 第⑥步的文本级检查（doc-lint、残留扫描）**全部通过**，
> 但 B1/B2/B3 三个阻断是**控制流结构错误**，不是文本错误——它们天然逃过一切正则检查。
> 因此本节把"把伪代码当程序读一遍"固化成方法，后续任何伪代码改动都必须走一遍。

**方法：逐出口走查**

1. **列出所有 `return` / `continue` / 落空（fall-through）**
2. 对每个出口断言三件事：
   - 当前记录是否已消费（`take_front` 是否已执行）
   - `plaintext_out` 是否已正确累加（成功路径）或已清空（错误路径）
   - 该出口是否与 §3.3 契约表的那一行**逐字一致**
3. **特别检查每个循环体末尾有没有回边**——B1 的直接教训：
   成功路径末尾缺 `continue` 会让控制流掉出循环，落进下一个函数定义。

**当前 §3.4.1 的出口清单（改动伪代码后必须同步更新）**

| # | 出口 | 记录已消费 | plaintext_out | 与契约一致 |
|---|---|---|---|---|
| E1 | `closed_` → `kClosed` | 否（未进入循环） | 未触碰 | ✓ 幂等 |
| E2 | `terminal_` → `last_error_` | 否 | 未触碰 | ✓ 幂等 |
| E3 | `size < 5` → `kOk`/`kNeedMoreInput` | 否 | 保留已累加内容 | ✓ |
| E4 | `type` 非法 → `Fail(kProtocolError)` | 否 | 未触碰（可能已有明文，但错误优先） | ✓ terminal |
| E5 | `len` 超上界 → `Fail(kProtocolError)` | 否 | 同上 | ✓ terminal |
| E6 | `size < 5+len` → `kOk`/`kNeedMoreInput` | 否 | 保留已累加内容 | ✓ |
| E7 | `INCOMPLETE` → `Fail(kProtocolError)` | **是** | 未累加（`tmp` 丢弃） | ✓ terminal |
| E8 | `RENEGOTIATE`(1.3) → `continue` | 是 | 未累加（票据 0 明文） | ✓ 回到 E3 |
| E9 | `RENEGOTIATE`(1.2) → `Fail(kProtocolError)` | 是 | 未累加 | ✓ terminal |
| E10 | `NO_RENEGOTIATION` → `continue` | 是 | 未累加 | ✓ 回到 E3 |
| E11 | `CONTEXT_EXPIRED` → `kClosed` | 是 | **保留已累加内容**（B3 后仍返回 kClosed，调用方应先取走明文再关） | ✓ 需在 §3.3 注明 |
| E12 | `ALTERED`/`DECRYPT_FAILURE` → `Fail(kDecryptFailed)` | 是 | **已 clear**（整批丢弃） | ✓ terminal |
| E13 | `PEER_ALERT` → `Fail(kPeerAlert)` | 是 | **已 clear** | ✓ terminal |
| E14 | `INTERNAL` → `Fail(kInternal)` | 是 | **已 clear** | ✓ terminal（B5 修正后） |
| E15 | `max_out` 达成 → `kOk` | 是 | 已累加 | ✓ 但缓冲可能有剩余，见 B9 |
| E16 | **成功路径末尾 → `continue`** | 是 | 已累加 | ✓ **B1 修复点** |

**B1 的最小复现手法（乙用它抓到 N5，同样适用于 B1）**

> 模拟 2 条记录，逐迭代走：
> - iter1：`take_front` → `progressed=1` → `decrypt` → `plaintext_out += tmp`（100B）
>   → `produced=100` → `max_out==0` 不返回 → **没有 `continue`** → 掉出循环
> - 结论：第 2 条**永远解不到**，`plaintext_out` 只有 100B。
>
> 修复前：边界 2/9 与绿证 9（3×100B → 300B）**必红**。
> 修复后：`continue` 回到 loop，iter2/iter3 继续，`plaintext_out==300B`。

**教训（写进工程纪律）**

- 文本检查（正则、lint、残留扫描）**只能发现"说了什么"的错误**，
  不能发现"写了但执行不到"的错误。
- 伪代码类文档必须额外做**控制流走查**：出口清单 + 回边检查 + 2 条记录逐迭代模拟。
- B1 之所以危险，是因为**注释写得完全正确**（"max_out 是软阈值"、"成功才累加"），
  读者会以为行为已实现；但缺一个 `continue` 就全盘失效。

#### 3.4.2 必须覆盖的十二个边界（都进 §5 的测试）

> `> [consult-b 第⑤步 D-a]` 标题原写「**四个**边界」但下面列了 7 条；第⑤步 N2 补到 8 条；
> `> [consult-b 第⑥步 N5/N6]` 又补 2 条（多记录累加、INCOMPLETE 终止）→ 10 条；
> `> [consult-b 第⑥步 N7/N8]` 再补 2 条（终止闩锁、双计数）→ **12 条**。
> `> [父会话 第⑦步 B4]` **本条缺陷复发**：上一版标题与留痕都停在「十个」，而实际列表已到 12。
> 这与第⑤步修掉的 D-a（标题「四个」实列 7 条）是同一错误——**改列表时必须同步改标题与留痕注**。
> 现已同步为「十二个」。

1. **一条记录切成 N 次喂入** → 前 N-1 次 `kNeedMoreInput`，第 N 次 `kOk`。
2. **一次喂入两条记录** → 一次调用返回**两条明文拼接**（不得只剩最后一条）`> [consult-b 第⑥步 N5]`。
3. **一条记录 + 下一条记录的前 3 字节** → 返回第一条明文，`buffered_input()==3`。
4. **零长度应用数据**（TLS 允许）→ 返回 `kOk` 且 `plaintext` 为空，**不得**被当成 `kClosed`。
5. **`> [consult-b 修正 1]` post-handshake 票据**：TLS1.3 握手后 `DecryptMessage` 可能返回
   `SEC_I_RENEGOTIATE` 且 `data=0`、`EXTRA` 是裸 handshake 记录。后端必须内部消化，
   **不得**返回任何错误，也**不得**把票据字节当明文交给调用方；
   且**必须消费掉该记录**（N1），否则下一次解密同一记录会得到 `0x80090330`。
   **返回值必须是 `kOk`**（靠 `progressed` 而非 `produced`，见 N8）。
6. **`> [consult-b 第⑤步 复核 1]` EXTRA 的定位方式**：
   `DecryptMessage` 路径 `pvBuffer` 有效但**指向调用方缓冲内部**
   （实测 `offset=63 inCallerRange=1 input=126`）；`ISC` 路径 `pvBuffer == NULL`。
   两条路径统一用**算术定位** `tail_off = record.size() - extra_len`，
   **禁止解引用 `pvBuffer`**。本审计的自测只能证明"指针在调用方缓冲内部"，
   证不出"可能为 NULL"——后者采信 consult-b `probe44`（标 C）。
7. **`> [consult-b 修正 6]` 失败路径的明文**：任何 `!= kOk` 的返回之前必须 `plaintext.clear()`。
   实测篡改记录时 `SECBUFFER_DATA` 仍带长度且内容是密文。
8. **`> [consult-b 第⑤步 N2]` 空缓冲的返回码**：喂完最后一条完整记录后，
   缓冲为空且无剩余字节 → 必须返回 `kOk`（有进展），**不得**返回 `kNeedMoreInput`。
   若连续调用且缓冲始终为空 → 才返回 `kNeedMoreInput`，此时 `buffered_input()==0` 是合法的。
9. **`> [consult-b 第⑥步 N5]` 多记录累加**：喂入 3 条记录（各 100B 明文），
   一次 `Receive` 的 `plaintext.size() == 300`，且内容 = 三条按序拼接。
   这是上一版 `plaintext_out.clear()` 在循环体内的**直接反例**：
   上一版会返回 100B（只剩最后一条）而 `produced == 300`，自相矛盾。
10. **`> [consult-b 第⑥步 N6]` `5+len` 到齐仍 `INCOMPLETE`**：
    构造一条 9 字节合法记录（`5+len == 9`，type=22 握手 HelloRequest），
    后端必须返回 `kProtocolError` 且 `terminal_` 置位、`buffered_input()==0`（记录已消费）。
    **不得**放回缓冲、**不得**返回 `kNeedMoreInput`——那会导致 `rx_buffer_` 无界增长。
    实测依据：consult-b `probe7` `HelloRequest in=9 -> 0x80090318`。
11. **`> [consult-b 第⑥步 N7]` 终止闩锁**：`kDecryptFailed` 之后再调 `Receive`，
    必须立即返回同一个 `kDecryptFailed`（幂等），**不得**继续解密、**不得**返回 `kOk`。
    即使底层是 TLS1.3（上下文会自动恢复、下一条仍可解出），也必须闩锁。
12. **`> [consult-b 第⑥步 N8]` 双计数**：票据记录（0 明文）后紧跟一条 8B 应用数据，
    一次 `Receive` 必须返回 `kOk` 且 `plaintext.size()==8`；
    仅票据、无应用数据时也必须返回 `kOk`（`progressed==1, produced==0`）。
    若实现把两个计数合并成一个，本条必红。

### 3.5 SChannel 后端映射要点

| 接口方法 | SChannel 实现要点 |
|---|---|
| `Handshake` | `InitializeSecurityContextW`；**`consumed = in_size - Σ(EXTRA.cbBuffer)`**，EXTRA 的 `pvBuffer` 可能为 NULL，只读 `cbBuffer`；断言 `consumed + Σ(EXTRA) == in_size`。`out` 由 `SecBuffer` 拷贝 |
| `Send` | `EncryptMessage` 一次最多 `cbMaximumMessage` 明文，超出则循环切分；输出布局 = `[cbHeader][ciphertext][cbTrailer]`；**实际写出长度 = 三个 `cbBuffer` 之和**，不是 `header+len+trailer` |
| `Receive` | `DecryptMessage` 需要 **≥4 个 `SecBuffer`**（实测 1/2/3 全部 `0x80090308`，4/5 成功）；`sb[0]` 必须是 `SECBUFFER_DATA` + 完整记录（含 5B 头）；`SECBUFFER_DATA` 出明文，`SECBUFFER_EXTRA` 出剩余；`SEC_E_INCOMPLETE_MESSAGE` → `kNeedMoreInput`；`SEC_I_RENEGOTIATE` 在 TLS1.3 是票据、必须内部消化 |
| `PeerSubjectPublicKeyInfo` | `QueryContextAttributesW(SECPKG_ATTR_REMOTE_CERT_CONTEXT)` → `CryptEncodeObjectEx(X509_PUBLIC_KEY_INFO, &cert->pCertInfo->SubjectPublicKeyInfo)`。**禁止**把整张证书喂给 `CryptDecodeObjectEx`（实测 0xC0000005）[READ:F:\rtsc\evidence\schannel-tls-backend.md:72-74] |
| `PeerSubjectPublicKey` | **直接取 `cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData/cbData`**。禁止剥固定偏移（RSA-2048 偏移 24 → 270B；RSA-1024 偏移 22 → 140B） |
| `record_sizes` | `SECPKG_ATTR_STREAM_SIZES` → `SecPkgContext_StreamSizes{cbHeader,cbTrailer,cbMaximumMessage,cBuffers,cbBlockSize}`（`shared\sspi.h:934-941`）。`cbTrailer` 是**上界**（TLS1.3 实测 44，实际 17）；`cbBlockSize` 实测 16 |
| `negotiated` | 版本：`SECPKG_ATTR_CONNECTION_INFO.dwProtocol`（TLS1.2/1.3 都可用，无需 EX）；**套件号：`SECPKG_ATTR_CIPHER_INFO.dwCipherSuite`**（`aiCipher` 是 CALG 不是套件号；`CONNECTION_INFO_EX` 只给算法名） |
| `Shutdown` | `ApplyControlToken(SCHANNEL_SHUTDOWN)` → `InitializeSecurityContextW`，flags = `ISC_REQ_STREAM \| ISC_REQ_ALLOCATE_MEMORY`，**输入描述符 nullptr，输出 `pvBuffer = nullptr`**（由 SChannel 分配，随后 `FreeContextBuffer`）。缺 `ALLOCATE_MEMORY` 实测 `0x80090300` 且 `out=0`（close_notify 发不出） |

### 3.6 `/W4 /WX` 具体风险与处置

| 风险 | 处置 |
|---|---|
| `windows.h` 的 `min`/`max` 宏与 STL 冲突 | 翻译单元顶部 `#define WIN32_LEAN_AND_MEAN` + `#define NOMINMAX`，且**只在该后端 .cpp** 里包含，头文件不暴露任何 Windows 类型 |
| `sspi.h` 需要 `SECURITY_WIN32` | 同 TU 内先定义再包含 |
| `UNISP_NAME_W` 是 `const SEC_WCHAR*` 但 `AcquireCredentialsHandleW` 取非 const | 用 `const_cast<SEC_WCHAR*>`（探针写法，`/W4` 干净）[READ:F:\rtsc\.tmp\tlsprobe\probe.cpp:61] |
| `sprintf_s` / `%08lX` 与 `SECURITY_STATUS` 类型宽度 | 统一转 `unsigned long` 再打印 |
| 未使用参数（SSPI 回调/保留位） | `[[maybe_unused]]` 或省略形参名 |
| `SCHANNEL_CRED` 在新 SDK 被 `SCH_CREDENTIALS` 取代 | **必须**用 `SCH_CREDENTIALS`（`um\schannel.h:455`）：legacy `SCHANNEL_CRED` 无法表达版本下限（会静默降级，§3.2.3 修正 9）。`SCHANNEL_CRED` 只允许在"必须兼容老系统"的分支出现，且要标注 |
| `SCH_CREDENTIALS` / `TLS_PARAMETERS` 编译不出来 | 它们在 `um\schannel.h:409` 的 `#ifdef SCHANNEL_USE_BLACKLISTS` 里，且需要 `UNICODE_STRING`。**本审计实测**：`#include <winternl.h>` + `#define SCHANNEL_USE_BLACKLISTS` 后可用；否则报 `C2065: TLS_PARAMETERS 未定义`。这个坑不在任何文档里 |
| 链接库 | 用 CMake `target_link_libraries(rtsc_tls PRIVATE secur32 crypt32 ncrypt)`，**不用** `#pragma comment(lib,...)`（与既有 CMake 风格一致，`CMakeLists.txt:44-46`）。本审计两次探针用 `secur32 crypt32 advapi32` 链接一次通过。`> [consult-b 第⑤步 D-c]` **更正原稿错误理由**：`CertCreateSelfSignCertificate` 在 **`crypt32.lib`**（本审计探针确实链接了 crypt32），不是 `advapi32`；`advapi32.lib` 只提供 `CryptAcquireContextW`/`RegOpenKeyExW` 一类。原稿把 `advapi32` 的理由写成"证书存储路径"是错的——链接项本身无害（探针里保留它是因为 `CertCreateSelfSignCertificate` 的 CSP 路径可能间接需要），但**理由必须写对** |
| `QueryContextAttributesExW` 的链接位置 | `Secur32.Lib` 导出 `QueryContextAttributesW`，**不导出** `QueryContextAttributesExW`（后者在 `sspicli.dll`）。→ **若用 `Ex` 变体，只链 `secur32` 会 `LNK2019`**；用 `W` 变体则无此问题。本审计全部探针只用 `W`，两次链接均一次通过，**未复现** LNK2019。`> [consult-b 第⑤步 复核 2]` 此项已从缺陷降为**条件性风险**（见 §4.4） |

---

## §4 现有 §8 缺陷清单（我方原有 11 条，合并后 **20 条**）

> **合并结论（裁定 consult-b 的算式）**：
> consult-b 说「合并后 17 条 = 它的 16 + 甲 D10；甲独有 1 条，它独有 8 条，重叠 8 组」。
> 核对结果：**算式自洽**（16 + 1 = 17；8 组重叠 + 8 条它独有 + 1 条甲独有 = 17 ✓）。
> 但**总数不止 17**：本轮裁定它的 12 处接口修正时，发现其中 3 条同时是
> `security-layer.md §8` 的文档缺陷（原本只被它当作"接口问题"），加上我新查出的 2 条，
> 最初算得 21 条；第⑤步复核后 **D14 经乙自我复核撤回、降为 §4.4 条件性风险**，
> 故最终 **20 条**。清单见 §4.3。
>
> `> [父会话一致性修正]` 本行原写「最终 **21 条**」，与 §4.3 结论行（`**最终条数：20 条**`）
> 及本节标题（`合并后 **20 条**`）矛盾。根因：D14 降级时只改了标题与结论行，漏改本导语。
> 现已同步为 20 条，并在此留痕以便审计追溯。

### 4.1 我方原有 11 条（D1–D11，全部保持成立）

| # | 位置 | 缺陷 | 证据 | 修法 |
|---|---|---|---|---|
| D1 | `security-layer.md:1440` | 断言「跨平台唯一解：只有 OpenSSL 在 Windows 与 Linux 上都是成熟一等公民」，前提被实测推翻 | SChannel 已对真实服务器完成 TLS1.2 握手 [READ:F:\rtsc\evidence\schannel-probe.txt:6-12] | 改为「Windows 有 OS 原生解；跨平台靠后端抽象，不靠单一库」 |
| D2 | `security-layer.md:1448` | 「项目已用 CMake + vcpkg 生态可用（W4）」——本机无 vcpkg | `Get-Command vcpkg` → `NOT FOUND`（本次实测） | 删除该前提，或标注「需先自举 vcpkg（网络 + 10 分钟级）」 |
| D3 | `security-layer.md:1404` | Windows 三条集成路径全断：①vcpkg 不存在；②未发现任何 openssl 安装；③`perl Configure VC-WIN64A` 无 perl（且 OpenSSL 3.x 默认还需要 nasm） | `openssl/perl/nasm/vcpkg` 全部 `NOT FOUND` | 三条路径逐条标注「本机不可用」，并补第四条「SChannel」 |
| D4 | `security-layer.md:1404` | 「官方预编译安装包」**事实错误**：官方只发源码 | 联网核实 `openssl-library.org/source/`：下载表只有 `*.tar.gz`，无 Windows 二进制 | 删除该条（或写明第三方来源+版本+校验和） |
| D5 | `security-layer.md:1449` | 「不需要改现有 CMake 结构太多（加 `find_package(OpenSSL REQUIRED)`）」——`REQUIRED` 会让**整个工程 configure 失败**，12 个既有套件全灭 | `CMakeLists.txt:1-131` 当前无任何 `find_package` | 改为 `option(RTSC_TLS_OPENSSL OFF)` + 条件 `find_package(... QUIET)` |
| D6 | `security-layer.md:1414,1421,1424` | 把「SChannel 作为 TLS 传输」与「系统 CredSSP SSP」混为一谈，用后者的黑盒化代价否掉前者 | `security-layer.md:1423` 全段只论证 `"CredSSP"` 包；`schannel-probe.txt` 全程只有纯 TLS 记录（无 TSRequest 字节） | §8.3 拆成 B1（TLS 传输，推荐）/ B2（CredSSP SSP，否决） |
| D7 | `security-layer.md:1425` | 估计「SChannel TLS ≈500 行」但未计入 `EXTRA` 重组、`SEC_E_INCOMPLETE_MESSAGE`、`SEC_I_RENEGOTIATE`（TLS1.3 票据）、close_notify 四类分支 | `shared\sspi.h:934-941` + 探针里已出现的状态码族 | 估计上调到 900–1200 行（本轮又发现 3 个新陷阱，见 §4.3），并列出分支清单 |
| D8 | `security-layer.md:1383-1394` | §8.1 能力表**缺失**三项必需能力：①记录层开销/最大明文块；②握手可多次往返的非阻塞驱动；③优雅关闭 | 表格只有 TLS1.2/1.3、自签名、SPKI、MD4、HMAC-MD5、RC4、SHA-256、常量时间、DER、随机数 | 补三行；本轮再补 3 行（见 §4.3 **D20**） |
| D9 | `security-layer.md:1396` | 「MD4 与 RC4 …是选型的核心风险点」——分类错误：它们属 NTLM/CredSSP，与 TLS 选型无关；项目已有自研实现 | `include\rtsc\crypto\hash.h:16,22,43`；`src\crypto\hash.cpp:107,267` | 删掉该句，改为「密码学原语已自研，TLS 选型只需 TLS 能力」 |
| D10 | `security-layer.md:1409` | 「`i2d_PublicKey()`」与 §5.4.0 要的字节不一致：`i2d_PublicKey` 给 **270B** 的 `RSAPublicKey`，实测 SPKI DER 是 **294B**；文档没写清关系 | `schannel-spki-probe.txt:3` 的 294B 与 `security-layer.md:708-709` 的 270B 并存 | 明确：CredSSP 用 270B（`CERT_PUBLIC_KEY_INFO.PublicKey`），SPKI 是 294B；**两者差值不是常量**（RSA-1024 差 22） |
| D11 | `security-layer.md:1467-1469` | 「为什么不用 SChannel 作为主方案」的论证对象是 CredSSP SSP，不是 TLS；未考虑「双后端」形态 | 同 D6 | 改写为「TLS 层用 SChannel，CredSSP 层自研」 |

### 4.2 consult-b 独有缺陷（8 条中采纳 7 条，D12–D19 编号沿用合并后的位置）

> `> [consult-b 第⑥步 随修 3]` 标题原写「采纳 8 条」，但 D14 已经乙自我复核**撤回**
> （降为 §4.4 条件性风险 R1），故实际采纳 **7 条**。编号仍保留 D14 占位以便追溯。

| # | 来源 | 位置 | 缺陷 | 裁定 |
|---|---|---|---|---|
| D12 | consult-b D1 | `security-layer.md:1379` vs `1436-1449` | 把「零第三方依赖」写成现状描述，却在 §8.5 推荐引入 OpenSSL，**全文未承认这是对硬约束的破坏** | **成立**。我方 D5 只谈"configure 会失败"的技术后果，没指出这是**约束违背**。采纳 |
| D13 | consult-b D6 | `security-layer.md:1412` | legacy provider 缺失被写成「某些发行版拆包」一句带过；实际静态构建/FIPS 构建默认不含，且失败在**运行期** | **成立**。与 D9 不同维度（D9 说"没必要用"，本条说"用了会在现场炸"）。采纳 |
| ~~D14~~ | consult-b D7（**已撤回**） | `security-layer.md:1418` | 依赖只列 `secur32.dll` + `crypt32.dll`，漏 `sspicli.dll` | **降级为条件性风险，不计入缺陷数**（§4.4）。`> [consult-b 第⑤步 复核 2]` consult-b **收回了**"必然 LNK2019"的主张，并承认 `design-b.md:457` 的 `[BASH:probe7 首次链接失败]` 引用**失实**（probe7.cpp 只调 `QueryContextAttributesW`，全盘无 LNK2019/LNK2001 记录）。底层事实仍成立：`Secur32.Lib` 有 `W` 无 `ExW`，`sspicli.dll` 导出 `ExW/ExA` → "若用 Ex 则 secur32 不足"成立，"当前清单必然 LNK2019"不成立 |
| D15 | consult-b D11 | `security-layer.md:1456` | `min=TLS1_2, max=TLS1_3` 一句带过，掩盖后端阻抗失配：SChannel legacy cred 下 1.2\|1.3 会**静默降级**到 1.2 且无错误码 | **成立**。已据此改 §3.2.3（修正 9）与 §5 绿证断言 7 |
| D16 | consult-b D12 | `security-layer.md:1457` | `SSL_VERIFY_NONE` + 应用层 tofu 与 SChannel 事实冲突：`MANUAL` 会**同时**关掉主机名校验（`schannel.h:544-550` 原文） | **成立**。已据此改 §3.2.3（修正 7，改 `CertPolicy` 枚举） |
| D17 | consult-b D13 | `security-layer.md:505` + `evidence\schannel-tls-backend.md:44` | 把 `cipher=0x6610` 当成套件号并推出 `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`；`0x6610` 实际是 `CALG_AES_256`（`ALG_CLASS_DATA_ENCRYPT\|ALG_TYPE_BLOCK\|ALG_SID_AES_256` = `(3<<13)\|(3<<9)\|16` = 0x6610，本轮用 `wincrypt.h` 逐项算出） | **成立**。套件号只能取 `SECPKG_ATTR_CIPHER_INFO.dwCipherSuite`。注意：consult-b 说该服务器实际是 `0x009D TLS_RSA_WITH_AES_256_GCM_SHA384`，本审计**未独立复现**（对真实服务器的 `CIPHER_INFO` 未跑），标 C 级 |
| D18 | consult-b D14 | `security-layer.md:1412` | 「FIPS 模式下不可用（本项目不需要 FIPS）」遗漏了真正问题：**自研 MD4/MD5/RC4 才是 FIPS 的阻断点** | **成立**。与 D9/D13 都不同：D9 说"不必用库的 MD4"，本条说"自研原语本身在 FIPS 环境下不合法" |
| D19 | consult-b D15 | `security-layer.md:1463` | 「实测服务器发的 `errorCode` 就不符合严格 DER」与 `BerReader` 代码冲突：`ber.cpp:125-130` 明确拒绝非最小长度编码 | **成立（作为"待证断言"）**。若 §8 的断言为真，现有 BER 读取器在 CredSSP 第 2 步就会失败。本轮无法证伪（需真实 errorCode 抓包），但"文档断言与代码行为冲突"这一**事实**成立 |

### 4.3 本轮新增的 2 条（我方在裁定接口修正时发现）

| # | 位置 | 缺陷 | 证据 | 修法 |
|---|---|---|---|---|
| D20 | `security-layer.md:1385-1394`（§8.1 能力表） | 还缺 3 项**实测必需**能力：①`DecryptMessage` 的 ≥4 buffer 契约；②`EXTRA` 指针别名（不得跨调用持有）；③TLS1.3 post-handshake 票据必须内部消化。缺这些 → 选型表无法比较（因为 OpenSSL 侧没有这些约束，SChannel 侧有，选型会系统性偏向 OpenSSL） | 本轮实测：`nbuf=1/2/3 -> 0x80090308`、`extra=63 offset=63 inCallerRange=1`、`DecryptMessage(pending) -> 0x00090321 extra=103`（`evidence\tls\verify_traps.out.txt`、`verify_t3.out.txt`） | 在 §8.1 表格补 3 行，并标注"仅 SChannel 后端有此约束" |
| D21 | `security-layer.md:505` | 「TLS 1.2 默认协商到 `AES256-GCM-SHA384`（**RSA 密钥传输，非 ECDHE**）」——同段又说「显式指定 `ECDHE-RSA-AES128-GCM-SHA256` 也能成功」。这两句把"协商到的套件"与"服务器支持的套件"混在一段，且未给套件号，导致 D17 的错误得以传播 | `evidence\schannel-probe.txt:11` 只有 `cipher=0x00006610`，无套件号；`evidence\schannel-tls-backend.md:44` 把它解释成 ECDHE | 套件结论必须附 `SECPKG_ATTR_CIPHER_INFO` 的 `dwCipherSuite` + `szCipherSuite` 原文，不能从 CALG 反推 |

**最终条数：20 条**（D1–D21，其中 **D14 已降级、不计入**，编号保留不重排以便追溯）。

> `> [consult-b 第⑤步 复核 2]` **D14 降级说明**：原 21 条中的 D14（"依赖清单漏
> `sspicli.dll` → 必然 `LNK2019`"）经 consult-b 自己复核后**撤回**——它承认
> `design-b.md:457` 的 `[BASH:probe7 首次链接失败]` 引用失实（probe7.cpp 只调
> `QueryContextAttributesW`，全盘无 LNK2019/LNK2001 记录）。本审计亦未复现。
> 底层事实（`Secur32.Lib` 有 `W` 无 `ExW`）仍成立，但它是**条件性风险**而非文档缺陷，
> 移入 §4.4。因此 **21 − 1 = 20 条**。
>
> 编号策略：**不重排**。D14 保留占位并标删除线，避免与已发给乙的 D15–D21 编号错位。
>
> 算式复核：我方 11（D1–D11）+ consult-b 独有 8（D12–D19，其中 **D14 降级**）
> + 本轮新增 2（D20–D21）= 21 − 1 = **20**。
> consult-b 的 "17 条" 算式在它自己的口径下自洽（16+1），但它把 D16/D15/D20 类的
> "接口阻抗失配"归到 §1 接口章节，未计入 §8 缺陷；本审计认为它们**同时是文档缺陷**
> （因为 `security-layer.md §8` 正是这些接口决策的来源），故合并计入。

### 4.4 条件性风险（不计入缺陷数）

| # | 内容 | 触发条件 | 现状 |
|---|---|---|---|
| R1 | `QueryContextAttributesExW` 不在 `Secur32.Lib`，在 `sspicli.dll` | **仅当**实现改用 `Ex` 变体（如需要 `SecPkgContext_ConnectionInfoEx` 的算法名） | 当前设计用 `SECPKG_ATTR_CIPHER_INFO` + `CONNECTION_INFO`（都是 `W` 变体），**不触发**。若将来要用 `Ex`，链接需加 `sspicli.lib` |
| R2 | `advapi32.lib` 是否必需 | 探针里链接了它但未直接调用其符号 | 无害；产品代码若确认不需要可去掉。`CertCreateSelfSignCertificate` 属 `crypt32.lib` |
| R3 | TLS1.3 `overhead_actual` 是否恒为 17 | 若随明文长度变化 | consult-b 测 6 个长度全部 17（标 C）；实现期参数化测试覆盖 `{1, 16383, 16384}`（§6 U12） |

补充（不计入条数，属一致性提示）：`security-layer.md:1456` 说 `min=TLS1_2` 可配置降到 1.0，
但 §8 未定义承载该配置的结构体；本设计的 `Config{allow_tls10,min_version,max_version}` 补上这个缺口。

---

## §5 红证计划（无 Linux、无第二台 RDP 服务器）

核心思路：**把「TLS 是否正确」拆成四层可独立自动化的证据**，每层都能先红后绿。

### T0 编译期红证（先红）

新增 `tests/test_tls.cpp` 后、实现前，`verify.ps1` 必须**失败**（链接错误 `unresolved external
symbol rtsc::tls::CreatePlatformTlsTransport`）。这就是第一条红证：证明测试真的在测东西，
而不是被空实现「通过」。

### T1 进程内 SChannel 回环（主证据，零依赖、零网络、零端口）——**已验证可运行（E 级）**

**结论先行**：本方案已实跑通过，`RESULT=PASS`。探针
`F:\rtsc\evidence\tls\loopback_schannel.cpp`（270 行）+ 输出
`F:\rtsc\evidence\tls\loopback_schannel.out.txt`。全程**不监听端口、不联网**，
单次运行 < 1 秒（用 `WaitForExit(10000)` 兜底，未触发）。

实测输出（原文，2026-10-22）：

```
self-signed cert: 439 bytes DER
  AcquireCredentialsHandle(client, mask=0x800) -> 0x00000000
  AcquireCredentialsHandle(server, mask=0x400) -> 0x00000000
  round 1: client -> 0x00090312, 169 bytes
  round 1: server -> 0x00090312, 780 bytes
  round 1: client -> 0x00090312, 158 bytes
  round 2: server -> 0x00000000, 51 bytes
  round 2: client -> 0x00000000, 0 bytes
handshake OK, rounds=2
-- negotiated --
  client: protocol=0x00000800 cipher=0x6610 bits=256
  client: stream sizes header=13 trailer=16 maxmsg=16384 block=16
  server: protocol=0x00000400 cipher=0x6610 bits=256
  server: stream sizes header=13 trailer=16 maxmsg=16384 block=16
-- peer cert --
  client REMOTE_CERT_CONTEXT -> 0x00000000
  client sees server cert: 439 bytes, equals local=1
  server REMOTE_CERT_CONTEXT -> 0x8009030E (no client cert expected)
-- app data --
  client EncryptMessage(36) -> 0x00000000, record=65
  server DecryptMessage -> 0x00000000 plain=36 extra=0 match=1
  server EncryptMessage(36) -> 0x00000000, record=65
  client DecryptMessage -> 0x00000000 plain=36 extra=0 match=1
  server DecryptMessage(2 records, 130 B) -> 0x00000000 extra=65
  server DecryptMessage(truncated 10 B) -> 0x80090318 (want 0x80090318) OK
RESULT=PASS
```

编译 + 运行命令（一次通过，`/W4 /WX` 零警告）：

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
$vs='C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
cmd /c "call `"$vs`" >nul 2>&1 && cd /d F:\rtsc\evidence\tls && cl /nologo /W4 /WX /EHsc /std:c++20 /utf-8 loopback_schannel.cpp /Fe:loopback_schannel.exe /link secur32.lib crypt32.lib advapi32.lib >build.log 2>&1"
F:\rtsc\evidence\tls\loopback_schannel.exe > F:\rtsc\evidence\tls\loopback_schannel.out.txt 2>&1
```

**已由实测确认的六条事实**（可直接作为实现契约）：

| # | 事实 | 证据 |
|---|---|---|
| 1 | 进程内 INBOUND/OUTBOUND 双上下文可完成握手，**2 轮** | 输出 `handshake OK, rounds=2` |
| 2 | 服务端 mask 用 `SP_PROT_TLS1_2_SERVER`(0x400) 即可，**不需要** `SERVER|CLIENT` | `AcquireCredentialsHandle(server, mask=0x400) -> 0` |
| 3 | 双方 `cipher=0x6610`、`header=13 trailer=16 maxmsg=16384 block=16`，与真实服务器**逐项一致** | 对比 `schannel-probe.txt:12` |
| 4 | 客户端侧 `SECPKG_ATTR_REMOTE_CERT_CONTEXT` 能取到服务端证书，且 `CertCompareCertificate` 判定与本地证书相同 | `equals local=1` |
| 5 | 服务端侧取对端证书返回 `0x8009030E`（`SEC_E_NO_CREDENTIALS`）属**正常**（无客户端证书） | 输出该行 |
| 6 | 双记录粘包 → `SECBUFFER_EXTRA=65`（正好是第二条记录长度）；截断 10B → `0x80090318` | 最后两行 |

**必须避免的六个坑（本审计与 consult-b 实测共同确认，均为 0x80090308/0x80090331/0x80090300 级故障）**：

| 坑 | 症状 | 正解 |
|---|---|---|
| `DecryptMessage` 的 `sb[0].BufferType` 用 `SECBUFFER_STREAM` | `server DecryptMessage -> 0x80090308`（`SEC_E_INVALID_TOKEN`） | 流上下文必须用 **`SECBUFFER_DATA`** + 完整记录（含 5B 头）；`SECBUFFER_STREAM` 是 datagram 上下文用法 |
| `DecryptMessage` 只给 1–3 个 `SecBuffer` | 同样 `0x80090308`，且**看起来**像"数据有问题" | 必须 **≥4 个**（实测 1/2/3 全失败、4/5 成功；失败时未消费任何字节）`> [consult-b 修正 3 关联]` |
| `InitializeSecurityContextW` 传 `ISC_REQ_ALLOCATE_MEMORY` 同时又给预分配缓冲 | 服务端收到 169 字节垃圾 → `0x80090331`（`SEC_E_ALGORITHM_MISMATCH`） | **握手/发送**二选一：要么只给 `pvBuffer=nullptr` 让 SChannel 分配，要么**不传** `ALLOCATE_MEMORY` 自己管缓冲 |
| `Shutdown` 不传 `ISC_REQ_ALLOCATE_MEMORY` | `0x80090300`（`SEC_E_INSUFFICIENT_MEMORY`）且 `out=0`，close_notify **发不出去** | **关闭**是唯一必须 `ALLOCATE_MEMORY` 的场景：没有输入 token，谈不上"二选一"`> [consult-b 修正 5]` |
| 每轮复用同一个 `out` vector 不清空 | 客户端把 ClientHello 回喂给自己 → 假 `0x80090308` | 每步 `out.clear()`，token 单向流动 |
| 先遍历 `SecBuffer` 追加明文、后看 `DecryptMessage` 状态 | 篡改记录时把**密文**当明文交给 `ConnectMachine` | 先看状态，`!= kOk` 时 `plaintext.clear()` 并丢弃 `> [consult-b 修正 6]` |

> **自相矛盾已修正**：原稿 §3.5 说"`Shutdown` 用 ISC 产出 close_notify"（未提 flag），
> 而 §5 坑表说"`ALLOCATE_MEMORY` 与预分配缓冲冲突，二选一"——两条并列会让实现者
> 对 `Shutdown` 也不传 flag，结果 close_notify 静默发不出。
> `> [consult-b 修正 5]` 现明确：**握手/发送**不用 `ALLOCATE_MEMORY`（自己管缓冲），
> **`Shutdown` 必须用**（由 SChannel 分配，`pvBuffer` 初始为 `nullptr`）。
> 两者不是同一场景，"二选一"只适用于前者。

因此 T1 从「C 级推导」升级为 **E 级实测**，§5 红证计划主路径成立，无需换轨到 T2。
绿证断言（实现阶段写进 `tests/test_tls.cpp`）：

1. 握手 ≤4 轮完成（实测 2 轮）。
2. `record_sizes()` == `{header=13, overhead_upper=16, overhead_actual=16, max_plaintext=16384, block_size=16}`（TLS1.2 GCM）。
3. `Send` 36B → `out.size() == 65`（== 13+36+16，且等于三个 `cbBuffer` 之和）。
4. 双记录粘包 → 第二条经 `SECBUFFER_EXTRA` 暴露，不得丢帧；`EXTRA` 只读 `cbBuffer`。
5. `PeerSubjectPublicKeyInfo` 294B / `PeerSubjectPublicKey` 270B（RSA-2048）；**不得**用固定偏移断言，改为断言"前者包含后者为子串"。
6. `Shutdown` 产出：`out.size() ∈ {24, 31}` 且 **`out[0] == (TLS1.2 ? 0x15 : 0x17)`**，`closed()==true`。
   `> [consult-b 修正 5]` 原断言写死 `0x15`，在 **TLS1.3 下必失败**：TLS1.3 的 close_notify 是
   `application_data`（`0x17`）包裹的加密 alert（consult-b `probe4-D`：`17 03 03 00 13 ...`）。
   本审计的 T1 探针跑的是 TLS1.2，实测 `out=31 first=15`，只覆盖了 1.2 分支。
7. 版本自检：`negotiated().tls_version ∈ [min_version, max_version]`，否则握手视为失败
   （`> [consult-b 修正 9]`，防 legacy cred 静默降级）。
8. `> [consult-b 第⑤步 N1 / 第⑥步 N8]` **票据必须被消费且不外泄**（N1 的验收点）：
   TLS1.3 握手后收到票据时，`Receive` 必须返回 `kOk`（`plaintext` 可为空，
   靠 `progressed` 判定而非 `produced`），**且下一次 `Receive` 必须能正常解出后续应用数据**
   （不得返回 `kDecryptFailed`）。
   - 本条断言写成**两步**：`iter0` 返回 `kOk` **且** `iter1`（喂入真实应用数据）
     返回 `kOk` 且明文正确。
   - **理由（已更正）**：`> [consult-b 第⑥步 更正]` 我在第⑤步曾说"只断言 `kOk` 在原伪代码下
     也会通过（`continue` 后缓冲已空）"——**这个分析是错的**。原伪代码 `continue` 回循环顶时，
     `rx_buffer_` 里**仍保留那 103 字节票据**（未 `erase`），会在**同一次调用内**再次
     `take_front` + 再次 `decrypt` → 直接返回 `kDecryptFailed`。consult-b `probe39` 的
     `iter0=0x00090321, iter1=0x80090330` 就是同一循环内的两次解密。
     所以"只断言 `kOk`"在原伪代码下**本来就是红的**，不是"也能通过"。
   - 两步断言仍然更好，但理由是**另一个**：它能抓到「消费了记录、但把上下文弄坏」的实现
     ——例如 EXTRA 错喂给 ISC、`take_front` 长度算错。这类 bug 会让 `iter0 == kOk`
     而 `iter1` 失败，单步断言抓不到。
9. `> [consult-b 第⑥步 N5]` **多记录累加**：一次 `Receive` 喂入 3 条记录（各 100B 明文），
   断言 `plaintext.size() == 300` 且内容为三条按序拼接。上一版在循环体内 `clear()`，
   会返回 100B 而 `produced == 300`（自相矛盾），本条**必红**。
10. `> [consult-b 第⑥步 N6]` **`5+len` 到齐仍 `INCOMPLETE` 必须终止**：
    构造 9 字节合法记录（type=22 HelloRequest，`5+len==9`），断言返回 `kProtocolError`、
    `terminal()` 为真、`buffered_input()==0`；**不得**返回 `kNeedMoreInput`
    （否则 `rx_buffer_` 无界增长）。
11. `> [consult-b 第⑥步 N7]` **终止闩锁幂等**：`kDecryptFailed` 之后再调 `Receive` 两次，
    必须都返回同一个 `kDecryptFailed`，且不得触碰上下文（TLS1.3 下底层其实能继续解出，
    但接口层必须拒绝）。
12. `> [consult-b 主张 5 关联]` **编排级用例**：TLS 握手 → 5 个 TSRequest 往返（用固定字节当
    payload）→ 读裸 4 字节 EUAR，全程同一个 `TlsTransport` 上下文、明文流连续。
    断言每一步的 `plaintext` 拼接后与发送序列逐字节相同（证明没有票据/EXTRA 造成错位）。
13. `> [consult-b 第⑤步 N2 / 第⑥步 N8]` **空缓冲返回码**：喂完最后一条完整记录后
    （缓冲已空、本轮有进展）必须返回 `kOk`；只有"缓冲空且本轮无进展"才返回 `kNeedMoreInput`。
    "进展" = `progressed>0 || produced>0`，不是单看 `produced`（N8）。

红证（负向，必须全部通过才算「测到了」）：

- 翻转 GCM tag 的 1 bit → `Receive` 必须返回 `kDecryptFailed`，**不得**返回 `kOk`，
  且 `plaintext` 必须为空（`> [consult-b 修正 6]`）。
- 截断记录 → 必须 `kNeedMoreInput`（底层 `0x80090318`），`buffered_input()` 等于剩余字节。
- `> [父会话 第⑦步 B7]` 伪造 `0x17 0x03 0x03 0xFF 0xFF`（声称 65535 字节）→
  必须 **`kProtocolError`**，**不得**分配 64KB 以上或崩溃。
  **删掉原稿的"或 `kNeedMoreInput`"**：伪代码已定死 `len > 16384+256 → Fail(kProtocolError)`，
  65535 > 16640，只可能是 `kProtocolError`。允许"或"会让一个"返回 `kNeedMoreInput`
  且永不推进"的实现（N6 那个 bug 的变体）也通过——这正是判别力被削弱的方式。
- 把 `expected header=13` 改成 `14` 做一次变异 → 断言必须失败（证明断言有效）。
- `> [consult-b 修正 3]` **`SecBuffer` 数量下限**：用 3 个 buffer 调 `DecryptMessage` 必须
  得到 `0x80090308`；用 4 个必须成功。这条测试防"文档看起来对、SChannel 上 100% 失败"。
- `> [consult-b 修正 5]` **`Shutdown` 缺 flag**：不传 `ALLOCATE_MEMORY` 必须得到
  `0x80090300` 且 `out` 为空；传了必须得到非空 `out`。这条测试防 close_notify 静默丢失。
- `> [consult-b 修正 2]` **`consumed` 公式**：构造"完整记录 + 半条记录"的输入，
  断言 `consumed + buffered_input() == in_size`，且剩余字节能在下一轮被正确解密。
- `> [consult-b 第⑤步 N1]` **重复消费检测**（这是 N1 的**红证**，比绿证 8 更早失败）：
  喂入「票据记录 + 一条应用数据记录」，断言两条都被消费（`buffered_input()==0`）
  且第二次解密不返回 `0x80090330`。原伪代码在这条上必红。
- `> [consult-b 第⑤步 N3]` **EXTRA 悬垂检测**：在 `DecryptMessage` 返回 EXTRA 后，
  主动对输入缓冲做一次扩容/重排（模拟 `std::vector` realloc），再读 EXTRA 数据；
  若实现解引用了 `pvBuffer` 则会读到错位字节 → 断言失败。用算术定位则必须通过。
- `> [consult-b 第⑤步 N4]` **超大记录上界**：伪造 `len = 16384 + 300`（介于 256 与 2048 之间）
  → 必须 `kProtocolError`（原上界 `+2048` 会放过它）。
- `> [consult-b 修正 1]` **票据不外泄**：TLS1.3 握手后若服务端发票据，`Receive` 必须返回
  `kOk` 而不是错误；`Status` 枚举里已无 `kRenegotiate`，该断言在编译期即被强制。
- `> [consult-b 第⑥步 N5]` **明文被覆盖检测**：喂 2 条记录，断言 `plaintext` 里
  **同时**含有第 1 条和第 2 条的特征字节。上一版 `clear()` 在循环体内会让第 1 条消失，
  但 `produced` 仍是 200 —— 本条专抓这种"计数与内容不一致"。
- `> [consult-b 第⑥步 N6]` **INCOMPLETE 死循环检测**：连续 3 次喂同一条 9 字节记录
  （`5+len` 到齐），断言 `buffered_input()` **不增长**且第一次就返回 `kProtocolError`。
  上一版会"放回 + kNeedMoreInput"，三次后 `rx_buffer_` 达 27 字节并持续增长。
- `> [consult-b 第⑥步 N7]` **TLS1.3 自动恢复不得外泄**：篡改一条记录使其 `kDecryptFailed`，
  再喂一条**合法**记录；断言仍返回 `kDecryptFailed`（闩锁），**不得**返回 `kOk`。
  这是最容易被"优化掉"的一条——因为底层确实能解出明文（consult-b `probe26`）。

> 探针源码 270 行（任务建议 ≤250）。超出部分全部是注释与打印语句，无逻辑冗余；
> 为不破坏「一次编译通过」的已验证状态，未再压缩。若需严格 ≤250，删注释即可，不影响结论。
> 本轮新增的验证探针 `evidence\tls\verify_traps.cpp`（291 行）与
> `evidence\tls\verify_t3.cpp`（181 行）同样只编译一次即通过。

### T2 独立实现交叉验证（防「自己和自己对」）

用 **Python 3.14 内置 OpenSSL 3.5.7** 起一个真 TCP TLS 服务端（本机已实测通过）：

```
client_version = TLSv1.2
client_cipher  = ECDHE-RSA-AES256-GCM-SHA384
echo_match     = True  bytes = 2048
cert_der_len   = 709
```

（本次运行结果，脚本 `F:\rtsc\.tmp\tlsprobe\loop.py`。）
让 `rtsc` 的 SChannel 后端连这个 Python 服务端 → 同一份明文在**两个独立 TLS 实现**之间往返，
这比「SChannel 自己连自己」强得多。端口用 `127.0.0.1:0` 动态分配，避免冲突。
注意：Python 只是**测试可选依赖**，只在 `verify.ps1 -TlsCheck` 时启用；缺失则打印
`[skip] python not found` 并继续（不 fail），保证没有 Python 的机器仍能跑 T1/T3/T5。

### T3 固定字节向量（回归锚点）

把 T1 里产生的一次完整会话固化成 golden：

| 向量 | 内容 | 断言 |
|---|---|---|
| V1 | ClientHello 前 11 字节 | `16 03 03 00 8e 01 00 00 8a 03 03`——`0x16` handshake、记录层版本 `03 03`、长度 `0x008e`=142、`0x01` ClientHello、握手长度 `0x00008a`=138、`03 03`。**实测值** [READ:F:\rtsc\evidence\schannel-probe.txt:5]（注意：记录层版本是 `03 03` 不是 `03 01`；这条易错点必须由测试锚定） |
| V2 | 应用数据记录头 | 5 字节 `17 03 03 <len_hi> <len_lo>`，`len == 8 + 2048 + 16` |
| V3 | close_notify | **按版本分叉**：TLS1.2 → 首字节 `0x15`（alert），第 2-3 字节 `03 03`，本审计实测 `out=31 first=15`；TLS1.3 → 首字节 `0x17`（application_data 包裹的加密 alert），consult-b `probe4-D` 实测 `17 03 03 00 13 ...`。**禁止写死 `0x15`** `> [consult-b 修正 5]` |
| V4 | SPKI 前缀 | `30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00`（RSA-2048 专属；RSA-1024 是 `30 81 9f ...`，长度 162）。**只能当"本机自签 RSA-2048 证书"的 KAT，不能当通用常量** `> [consult-b 修正 4]` |
| V5 | 真实服务器 SPKI 的 SHA256 | `78b5f26b0941d4fd9789002530f1eb319580b06a953eef6362ef020591000f3a`（网络门控，仅 `-TlsLive` 跑）[READ:F:\rtsc\evidence\schannel-spki-probe.txt:6] |

V5 是唯一需要真实服务器的用例，默认**跳过**，用环境变量 `RTSC_TLS_LIVE=192.168.1.7:3389` 开启。

### T4 真实服务器冒烟（可选、门控）

`verify.ps1 -TlsLive` → 连 `192.168.1.7:3389`，断言：
`record_sizes()=={13,16,16384}`、`SHA256(PeerSubjectPublicKeyInfo)==78b5f26b...`、
`PeerCertificateDer().size()==742`。这三条与既有证据逐字节一致
[READ:F:\rtsc\evidence\schannel-probe.txt:12,14] + [READ:F:\rtsc\evidence\schannel-spki-probe.txt:6]。
**门控原因**：CI/他人机器无此服务器，硬依赖会让套件不可移植。

### T5 后端无关性验证（Linux 缺位的替代）

在没有 Linux 的前提下，用「假后端」证明接口真的后端无关：

- 实现一个 `NullTlsTransport`（明文直通），只用于测试。
- 断言：把 `ConnectMachine` + `NullTlsTransport` 跑完整连接序列（现有
  `tests\test_connect_machine.cpp:185-221` 已覆盖 `kAwaitExternalSecurity` 与
  `OnExternalSecurityComplete()` 两个接入点），与「不接 TLS」的结果**逐字节相同**。
  这证明 `TlsTransport` 的接入点没有把 TLS 语义泄漏进协议层——即 Linux 后端替换时
  协议层零改动。

### T6 `verify.ps1` 集成片段（可直接粘贴）

```powershell
param([switch]$Clean, [switch]$CrashCheck, [switch]$TlsCheck, [switch]$TlsLive)

# ... 既有 configure/build/ctest 不变 ...

if ($TlsCheck) {
    Write-Host "== tls backend =="
    $tlsExe = Join-Path $buildDir "rtsc_tls_tests.exe"
    if (-not (Test-Path $tlsExe)) { Write-Error "rtsc_tls_tests.exe not built"; exit 1 }
    & $tlsExe
    if ($LASTEXITCODE -ne 0) { Write-Error "tls tests failed"; exit 1 }

    # 独立实现交叉验证（可选依赖：python 存在才跑）
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($py) {
        $env:TEMP = Join-Path $root ".tmp"; $env:TMP = $env:TEMP
        & $py (Join-Path $root "tests\tls\loopback_server.py")
        if ($LASTEXITCODE -ne 0) { Write-Error "tls cross-check failed"; exit 1 }
    } else {
        Write-Host "  [skip] python not found: cross-check skipped"
    }
}

if ($TlsLive) {
    if (-not $env:RTSC_TLS_LIVE) { Write-Error "set RTSC_TLS_LIVE=host:port"; exit 1 }
    & (Join-Path $buildDir "rtsc_tls_tests.exe") --live $env:RTSC_TLS_LIVE
    if ($LASTEXITCODE -ne 0) { Write-Error "tls live smoke failed"; exit 1 }
}
```

### T7 为什么这套方案够

| 担心 | 回应 |
|---|---|
| 没有 Linux，Linux 后端怎么测？ | 后端无关性由 T5 证明；Linux 后端本身是「同一接口的另一个实现」，其正确性由 OpenSSL 官方测试保证，本地无法也不必验证。**明确列入 §6 未验证。** |
| 没有第二台 RDP 服务器 | 不需要 RDP：TLS 层与 RDP 解耦。T1/T2/T3 全部本地；T4 用现有那台做一次冒烟。 |
| 会不会「自己测自己」 | T2 用 OpenSSL 3.5.7 做对端，与 SChannel 完全异构。 |
| 能不能落进 CI | 全部是进程内 + 本地回环，无外网、无特权、无端口冲突（动态端口）。 |

---

## §6 未验证项（明确标注）

| # | 未验证内容 | 影响 | 建议验证方式 |
|---|---|---|---|
| ~~U1~~ | ~~TLS **1.3** 在 SChannel 下的 `record_sizes`~~ **已关闭（E 级实测，consult-b 提供 + 本审计复核）** | — | 实测 `proto=0x00002000 cipher=0x6610 hdr=5 trl=44 maxmsg=16384`；`Send(34B)` → `alloc=83 wire=56 (hdr=5 data=34 trl=17) delta=27`。证据：`evidence\tls\verify_traps.out.txt`（本审计自己跑出的输出）。注意 `aiCipher` 仍是 `0x6610`（CALG_AES_256），套件号必须取 `SECPKG_ATTR_CIPHER_INFO`（consult-b `probe41` → `0x1302 TLS_AES_256_GCM_SHA384`） |
| ~~U2~~ | ~~`SEC_I_RENEGOTIATE` 实际触发路径~~ **已关闭（E 级实测）** | — | TLS1.3 握手后 pending 记录：`DecryptMessage -> 0x00090321 data=0 extra=103`，`pending` 首字节 `17 03 03 00 62`（application_data 包裹的 NewSessionTicket）。证据：`evidence\tls\verify_t3.out.txt`。**`SEC_I_CONTEXT_EXPIRED` 仍未实测**，保留为 U2b |
| U2b | `SEC_I_CONTEXT_EXPIRED`(0x00090317) / `SEC_E_CONTEXT_EXPIRED`(0x80090317) 的实测触发 | 两个码只差 I/E 前缀，处置不同（前者正常 EOF、后者上下文已死） | T1 负向用例：对端主动 close_notify 后连续两次 `Receive`，断言第一次 `kClosed`、第二次仍 `kClosed` 且不崩 |
| U3 | Linux 侧任何后端（OpenSSL/mbedTLS） | 跨平台目标未闭环 | 需 Linux 环境；接口已隔离，风险限于单个 .cpp |
| U4 | SChannel 在 FIPS 模式下的行为 | FIPS 下 `SCH_USE_STRONG_CRYPTO` 可能禁用某些套件 | 非本阶段目标，记录即可 |
| ~~U5~~ | ~~`openssl.org` 是否仍提供 3.x 官方 Windows 二进制~~ **已关闭（联网核实 1 次）** | — | `https://openssl-library.org/source/` 的下载表只列 `*.tar.gz` 源码包（3.4/3.5/3.6/4.0/4.1），**无任何 Windows 二进制**。同时确认分支 EOL：3.4 = 22 Oct 2026（今天）、3.6 = 01 Nov 2026、3.5 LTS = 08 Apr 2030、4.0 = 14 May 2027。→ §8 的"官方预编译安装包"确属事实错误（缺陷 D3/M2 成立） |
| U6 | mbedTLS 3.6 在本机（CMake+Python）的实际构建时间 | 只影响备选方案的工期估计 | 若考虑备选，先跑一次 `cmake -S . -B build` |
| U7 | 真实服务器对 TLS 1.0 的接受度（老服务器兼容路径） | `allow_tls10` 分支无实测 | 需一台老 Windows Server |
| ~~U8~~ | ~~证书链校验「打开」时的行为~~ **部分关闭（consult-b 实测）** | — | consult-b 实测：MANUAL 模式下 `CERT_CHECK_RESULT -> 0x80090301`（拿不到结果）；`DEFERRED` 模式下可得 `0x800B0109 CERT_E_UNTRUSTEDROOT`。→ `kStrict` 必须用 DEFERRED（已写进 §3.2.3）。**本审计未独立复现**，标 C 级 |
| ~~U9~~ | ~~进程内 SChannel 回环是否真能跑通~~ **已解决（E 级实测）** | — | 已跑通：`RESULT=PASS`，握手 2 轮，双向应用数据 + 双记录 `SECBUFFER_EXTRA=65` + 截断 `0x80090318` 全部符合预期。证据：`evidence\tls\loopback_schannel.cpp` + `loopback_schannel.out.txt`，详见 §5 T1 |
| ~~U10~~ | ~~`SEC_E_*` / `SEC_I_*` 常量是否与 `winerror.h` 逐值一致~~ **已关闭** | — | 本审计已用 `Select-String` 对 `shared\winerror.h` 逐值核对 14 个码；并已修正初稿 5 处抄错。实现期仍要求 `static_assert`（成本为零） |
| U11 | `TlsTransport` 是否需要随机源注入（consult-b 修正 12） | 仅影响 CredSSP 层 KAT 可复现性，不影响 TLS 层 | 暂不做：`SECPKG_ATTR_KEYING_MATERIAL` 实测不可用（consult-b `probe7` → 无效句柄），TLS 层当前无需导出密钥材料。若将来需要，测试构建加 `set_test_rng()` |
| U12 | `overhead_actual` 在 TLS1.3 下是否恒为 17 | 若随明文长度变化，`Send` 的长度断言不能用固定值 | consult-b 测了 payload ∈ {1,2,16,100,1000,16384} 全部 17（标 C）；建议实现期用参数化测试覆盖 {1, 16383, 16384} 三个边界 |

---

## §7 可复现命令

以下命令按「本次审计是否实跑」分两类，**不混报**：

- **实跑过**（本会话亲自执行并看到输出）：7.1 环境核对、7.2 SDK 存在性、7.5 Python 回环。
- **未实跑**（引用项目既有证据，给的是复现方式而非本次输出）：7.3 SChannel 握手、7.4 SPKI 导出、
  7.6 工程回归、7.7 新增入口（尚未实现）。

统一前置：`$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'`，未在 C 盘写任何工作文件。

### 7.1 环境事实核对

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
foreach ($c in 'openssl','perl','nasm','vcpkg','go','rustc','python','dotnet','node') {
    $p = Get-Command $c -ErrorAction SilentlyContinue
    if ($p) { "$c -> $($p.Source)" } else { "$c -> NOT FOUND" }
}
```

实测输出（摘要）：`openssl/perl/nasm/vcpkg/go/rustc -> NOT FOUND`；
`python -> C:\Python314\python.exe`；`dotnet` SDK `9.0.318`；`node` 存在。

```powershell
& python -c "import sys,ssl; print(sys.version); print(ssl.OPENSSL_VERSION); print(ssl.HAS_TLSv1_3)"
# -> 3.14.7 ... / OpenSSL 3.5.7 9 Jun 2026 / True
```

### 7.2 SDK / 库存在性

```powershell
$sk='C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0'
Test-Path "$sk\um\schannel.h"; Test-Path "$sk\shared\sspi.h"; Test-Path "$sk\shared\security.h"
Test-Path 'C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64\secur32.lib'
Test-Path 'C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64\crypt32.lib'
```

### 7.3 复现 SChannel 握手（真实服务器）——未实跑，引用证据

```powershell
$vs='C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
cmd /c "call `"$vs`" >nul 2>&1 && cd /d F:\rtsc\.tmp\schprobe && cl /nologo /W4 /EHsc /std:c++20 /utf-8 main.cpp /Fe:schprobe.exe /link ws2_32.lib secur32.lib crypt32.lib && schprobe.exe"
# 期望：TLS handshake complete after 2 rounds / protocol=0x00000800 cipher=0x00006610
#       stream sizes: header=13 trailer=16 maxmsg=16384
```

### 7.4 复现 SPKI 导出——未实跑，引用证据

```powershell
cmd /c "call `"$vs`" >nul 2>&1 && cd /d F:\rtsc\.tmp\schprobe && cl /nologo /W4 /EHsc /std:c++20 /utf-8 spki.cpp /Fe:spki.exe /link ws2_32.lib secur32.lib crypt32.lib && spki.exe"
# 期望：SubjectPublicKeyInfo DER (294 bytes) ... / SPKI found in certificate at offset 134
```

### 7.5 本地 TLS 回环（独立实现交叉验证）——本次实跑

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
& python F:\rtsc\.tmp\tlsprobe\loop.py
# 实测输出：
#   client_version = TLSv1.2
#   client_cipher  = ECDHE-RSA-AES256-GCM-SHA384
#   echo_match     = True  bytes = 2048
#   cert_der_len   = 709
#   cert_sha256    = A9F1DE3AFE729B2F03623769F74AC73943DAB80D61E86AEF4737CD1D5A0AD121
```

### 7.5b 进程内 SChannel 回环（§5 T1 主证据）——本次实跑，`RESULT=PASS`

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
$vs='C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
cmd /c "call `"$vs`" >nul 2>&1 && cd /d F:\rtsc\evidence\tls && cl /nologo /W4 /WX /EHsc /std:c++20 /utf-8 loopback_schannel.cpp /Fe:loopback_schannel.exe /link secur32.lib crypt32.lib advapi32.lib >build.log 2>&1"
F:\rtsc\evidence\tls\loopback_schannel.exe > F:\rtsc\evidence\tls\loopback_schannel.out.txt 2>&1
Get-Content F:\rtsc\evidence\tls\loopback_schannel.out.txt
# 期望末行：RESULT=PASS
# 关键行：handshake OK, rounds=2
#         cipher=0x6610 header=13 trailer=16 maxmsg=16384 block=16（双方一致）
#         client sees server cert: 439 bytes, equals local=1
#         server DecryptMessage(2 records, 130 B) -> 0x00000000 extra=65
#         server DecryptMessage(truncated 10 B) -> 0x80090318 (want 0x80090318) OK
```

### 7.6 既有工程回归（改动后必须仍全绿）

```powershell
pwsh F:\rtsc\verify.ps1
# 期望：12 个 ctest 全过；本设计不触碰任何现有文件，故应保持全绿。
# 注意：本次审计**未执行**该命令（只读审计，不构建），此条为实现阶段的回归要求，非本报告的证据。
```

### 7.7 建议的新增验证入口（实现阶段加）

```powershell
pwsh F:\rtsc\verify.ps1 -TlsCheck              # T1 + T3 + T5（默认，无网络）
pwsh F:\rtsc\verify.ps1 -TlsCheck -TlsLive     # 追加 T4（需 RTSC_TLS_LIVE）
```

---

## §8 第②轮磋商裁定（consult-b 的 12 处接口修正）

> 本节是本轮（2026-10-22 第②轮）的裁定记录。裁定依据分两类：
> **【自测】** = 本审计自己写探针跑出来的输出（`evidence\tls\verify_traps.out.txt`、
> `verify_t3.out.txt`）；**【采信】** = consult-b 的实测输出，本审计未独立复现，标 C 级。

| # | consult-b 的修正 | 裁定 | 依据 | 对 design-a 的改动 |
|---|---|---|---|---|
| 1 | `Receive` 不得返回 `kRenegotiate`（TLS1.3 票据走这条路） | **成立（致命）** | 【自测】`verify_t3.out.txt`：`DecryptMessage(pending) -> 0x00090321 data=0 extra=103`，`pending` 首字节 `17 03 03 00 62` | §3.2.1 删除 `kRenegotiate`；§3.3 划掉该行并补"票据内部消化"；§3.4 伪代码按版本分叉；§5 绿证 8 + 红证"票据不外泄" |
| 2 | `Handshake` 的 `consumed != in_size`，须减 EXTRA；EXTRA 的 `pvBuffer` 可能为 NULL | **成立（致命）** | 【采信】consult-b `probe44`：`in[1] type=EXTRA cb=64 ptr=0000000000000000`（本审计未复现 NULL 指针这一细节，但**已自测** `DecryptMessage` 侧 EXTRA 指向调用方缓冲内部：`offset=63 inCallerRange=1`） | §3.3 改 `consumed` 算法并加自检；§3.4 补边界 6；§3.5 改写 `Handshake` 行；§5 红证补 `consumed` 公式测试 |
| 3 | `RecordSizes::max_record()` 是分配上界；`block_size` 实测 16 不是 1 | **成立（严重）** | 【自测】`verify_traps.out.txt`：TLS1.2 `hdr=13 trl=16 block=16`；TLS1.3 `alloc=83 wire=56 (hdr=5 data=34 trl=17) delta=27` | §3.2.2 改名 `alloc_upper_bound()` + 新增 `overhead_actual`；§5 绿证 2/3 改用实测值 |
| 4 | `PeerSubjectPublicKey` 禁止剥固定 24 字节头 | **成立（严重）** | 【采信】consult-b `probe41`：RSA-1024 → `SPKI=162 PublicKey=140 strip-offset=22`。本审计只测过 RSA-2048（294/270/24），**无法证伪** | §3.2.4 注释改为"直接取 `CERT_PUBLIC_KEY_INFO.PublicKey`"；§3.5 改该行；§5 绿证 5 改为"前者包含后者为子串" |
| 5 | `Shutdown` 必须 `ISC_REQ_ALLOCATE_MEMORY`；T1 首字节在 TLS1.3 是 `0x17` | **成立（严重，且我方原文自相矛盾）** | 【自测】`verify_traps.out.txt`：`alloc=0: isc=0x00000000 out=0 first=00`；`alloc=1: out=31 first=15`。TLS1.3 的 `0x17` 为【采信】consult-b `probe4-D` | §3.5 改写 `Shutdown` 行；§5 坑表拆成"握手/发送"与"关闭"两行并显式消解矛盾；§5 绿证 6 改为按版本分叉；§5 V3 向量按版本分叉 |
| 6 | `Receive` 必须声明"失败时 plaintext 未定义" | **成立（严重）** | 【采信】consult-b `probe27`：篡改后 `DATA cbBuffer=77`（== 记录长），内容是密文。本审计**自己的探针就是这个错误顺序**（先追加明文、后看状态） | §3.2.4 注释 + §3.3 新增一行 + §3.4 循环开头 `plaintext_out.clear()` + §5 红证"篡改后 plaintext 必须为空" |
| 7 | `Config` 的 bool 无法表达 TOFU；`strict` 用错标志 | **成立（中）** | 【采信 + SDK 原文】`schannel.h:544-550`（本审计已读原文，确认 MANUAL 会忽略 NO_SERVERNAME_CHECK）；`CERT_CHECK_RESULT` 行为为【采信】 | §3.2.3 改为 `CertPolicy` 枚举 + `pinned_spki_sha256`；§3.6 注明 `kStrict` 必须用 `DEFERRED` |
| 8 | 套件号取错字段（`aiCipher` 是 CALG） | **成立（中）** | 【自测】`verify_traps.out.txt` 显示 `cipher=0x6610` 在 TLS1.2/1.3 下**完全相同**，而两个版本的套件必然不同（`0xC030` vs `0x1302`）→ 证明 `aiCipher` 不可能是套件号。另用 `wincrypt.h` 算出 `CALG_AES_256 = (3<<13)\|(3<<9)\|16 = 0x6610` | §3.2.4 新增 `NegotiatedInfo` + `negotiated()`；§3.5 改"版本/套件查询"行 |
| 9 | `min_version/max_version` 只是意愿，没有强制点 | **成立（中）** | 【采信】consult-b `probe9/probe16`：legacy cred 给 `1.2\|1.3` → ClientHello 无 `supported_versions`、协商 `0x0800`、无错误码。本审计未复现（探针只做单一版本） | §3.2.3 默认改 0x0302 + §3.3 加版本自检 + §5 绿证 7 |
| 10 | 工厂无法注入假后端 | **成立（中）** | 代码事实：原签名 `CreatePlatformTlsTransport(const Config&, std::string&)` 无后端名参数 | §3.2.5 新增 `CreateTlsTransport(backend, ...)`，旧函数退化为内联包装 |
| 11 | `kNeedMoreOutput` / `kRenegotiate` 值域冗余 | **成立（轻）** | 逻辑事实：本接口用 `std::vector` 输出，不存在"调用方缓冲不足" | §3.2.1 删除 `kNeedMoreOutput` |
| 12 | 缺随机源注入 → A 类 KAT 不可复现 | **部分成立（前瞻，非阻塞）** | 逻辑成立，但服务对象是 CredSSP 层而非 TLS 层；且 `SECPKG_ATTR_KEYING_MATERIAL` 不可用（【采信】consult-b `probe7`） | 不进本轮签名，记入 §6 U11 |

**裁定统计：10 条成立、1 条部分成立（修正 12）、0 条不成立。**

其中 **5 条致命/严重**（1/2/3/4/5/6 里除 4 为"采信"外均含自测证据），
共导致 **9 处接口签名级改动**：`Status` 删 2 值、`RecordSizes` 增 1 字段改名 1 方法、
`Config` 换 3 bool 为 1 枚举 + 2 字段、新增 `NegotiatedInfo` + `negotiated()`、
新增 `CreateTlsTransport` 重载、`PeerSubjectPublicKey` 语义改写、`Shutdown` 契约改写、
`Receive` 契约加失败语义、`Handshake` 契约改 `consumed` 公式。

**我方不同意的点（1 条）**：consult-b 修正 12 的"缺随机源注入"不应进 `TlsTransport` 签名。
理由：① 它服务于 CredSSP 的 nonce/ClientChallenge，属上层；② 若为它开洞，等于让 TLS 层
暴露"可预测随机数"的能力，是安全负资产；③ 实测 `SECPKG_ATTR_KEYING_MATERIAL` 不可用，
TLS 层当前没有任何需要注入随机源的导出接口。降级为 §6 U11 的前瞻项。

### 8.1 第⑤步复核（consult-b 判"不盖章"，理由成立）

consult-b 第⑤步裁定**不盖章**，指出 3 个阻断/中级缺陷 + 3 个文档级问题 + 1 个上界问题。
本审计逐条核对伪代码后**全部认同**，已修：

| # | 级别 | 缺陷 | 本审计核对 | 修法 |
|---|---|---|---|---|
| **N1** | **阻断** | `continue`（486/489 行）在 `erase`（493 行）之前 → 票据记录**从未被消费** → 下一轮重解同一记录 → `0x80090330`。**TLS1.3 默认路径在首张票据上必断** | **成立**。原 §3.4.0 伪代码确认：486 `continue`、489 `continue` 都跳过 493 的 `erase`。我只修了"外泄状态码"的症状，没修"记录未消费"的根因 | §3.4.1 改为「取出即消费」：`take_front()` 提前到解密之前；两个 `continue` 之前记录已消费。新增规则 2「每个 continue/return 之前记录必须已消费，唯一例外 INCOMPLETE 要放回」 |
| **N2** | **阻断** | 474 行 `size<5 → kNeedMoreInput`，而 §3.3 契约说此时 `buffered_input()>0`；恰在"解完所有记录、缓冲清空"时两者矛盾 | **成立** | 采用乙推荐的**选 A**：`produced` 计数，有产出就返回 `kOk`；§3.3 契约行改写为"此时 `buffered_input()` 可以为 0" |
| **N3** | 中 | `erase`（493）在 `copy(EXTRA)`（495）之前，与注释"先复制再复用缓冲"相反；依赖"`record` 是独立副本"这一**未写明前提**；若直传 `rx_buffer_.data()` → 悬垂 → **静默丢帧** | **成立** | §3.4.1 改为**算术定位**：`tail_off = record.size() - extra_len`；并新增规则 1「`record` 必须是独立副本，不得是视图」 |
| **N4** | 轻 | 上界 `16384 + 2048` 过宽；TLS1.3 规范是 `2^14 + 256` | **成立** | 改为 `16384 + 256`（RFC 8446 §5.2） |
| D-a | 文档 | 「必须覆盖的**四个**边界」下面列了 7 条 | **成立** | 改为「**七个**边界」（实际已列 8 条，见 §3.4.2） |
| D-b | 文档 | D8 行「见 §4.3 D17」——§4.3 只有 D20/D21，D17 在 §4.2 | **成立** | 改为「见 §4.3 **D20**」 |
| D-c | 文档 | `advapi32` 的理由写成"`CertCreateSelfSignCertificate` 的存储路径"；该符号实际在 `crypt32.lib` | **成立**。`advapi32.lib` 只有 `CryptAcquireContextW`/`RegOpenKeyExW` 一类 | §3.6 更正理由，并把链接项从必需列表降为"探针遗留、无害" |

**复核 1（EXTRA.pvBuffer == NULL 的理由）**：consult-b 复核 probe37/probe44 指出
`DecryptMessage` 路径指针**有效**（`offsetFromStart=37, inInputRange=1`），
`ISC` 路径才 `ptr=0000000000000000`。本审计的自测（`extra=63 offset=63 inCallerRange=1`）
**只能证明"指针在调用方缓冲内部"，证不出"可能为 NULL"**。
→ 结论保留（两条路径都不能解引用），但**理由改为算术定位**：
`tail_off = in_size - cbBuffer`，不碰 `pvBuffer`。已写入 §3.3 复核 1 注释、§3.4 规则 3、
§3.4.2 边界 6。

**复核 2（D14 降级）**：consult-b 收回"必然 LNK2019"主张，并承认
`design-b.md:457` 的 `[BASH:probe7 首次链接失败]` 引用**失实**（probe7.cpp 只调
`QueryContextAttributesW`，全盘无 LNK2019/LNK2001）。
→ D14 从缺陷清单**降级为条件性风险**（§4.4 R1），缺陷总数 **21 → 20**。
编号不重排（D14 保留占位、标删除线），避免与已发出的 D15–D21 错位。

**对"修 N1 才能让绿证第 8 条从必红变必绿"的判断**：**认同"修 N1 是必要的"，但理由已更正**。

`> [consult-b 第⑥步 更正]` 我在第⑤步写过：
> 绿证第 8 条如果只断言"`Receive` 返回 `kOk`"，在 N1 未修时**也会通过**
> （因为 `continue` 后缓冲已空，循环退出返回 `kOk`）。

**这个分析是错的**，乙指出并给出了证据：
- 原伪代码 `continue` 回到循环顶时，`rx_buffer_` 里**仍保留那 103 字节票据**（未 `erase`）；
- 于是**在同一次 `Receive` 调用内**再次 `take_front` + 再次 `decrypt` → 返回 `kDecryptFailed`；
- consult-b `probe39` 的 `iter0=0x00090321, iter1=0x80090330` 就是同一循环内的两次解密。

所以「只断言 `kOk`」在原伪代码下**本来就是红的**，不是"也能通过"。

**两步断言仍然更好，但理由是另一个**：它能抓到「消费了记录、但把上下文弄坏」的实现
——例如 EXTRA 错喂给 ISC、`take_front` 长度算错。这类 bug 会让 `iter0 == kOk` 而
`iter1` 失败，单步断言抓不到。已按此改写 §5 绿证 8 的理由。

### 8.2 第⑥步复核（consult-b 判"不盖章"，4 条阻断全部成立）

| # | 级别 | 缺陷 | 本审计核对 | 修法 |
|---|---|---|---|---|
| **N5** | **阻断** | `plaintext_out.clear()` 在**循环体内** → 喂 2 条记录时 iter2 清掉 iter1 的明文，返回只剩最后一条，而 `produced` 仍累加 200（自相矛盾）。违反 §3.4.2 边界 2/3 与 §3.3「一次 Receive 可能给出多帧」，后果是 TPKT 层静默卡死、无错误码 | **成立**。伪代码第 515 行确认在循环内 | §3.4.1 改为每次迭代 `tmp.clear()` + `decrypt(record, tmp)`，成功才 `plaintext_out += tmp`；新增规则 4「循环体内禁止 clear 调用方缓冲」；§3.4.2 边界 2/9；§5 绿证 9 + 红证"明文被覆盖检测" |
| **N6** | **阻断** | `:519` 注释「`5+len` 到齐 → 不应发生」是假的。实测 `HelloRequest in=9 -> 0x80090318`（9B 记录完全到齐、type/len 合法）。按"放回 + kNeedMoreInput"会让该记录**永不消费**、`rx_buffer_` 无界增长至 OOM | **成立** | §3.4.1 改为 `5+len` 到齐仍 `INCOMPLETE` → `Fail(kProtocolError)`；注释改为「可达，必须防御」；§3.4.2 边界 10；§5 绿证 10 + 红证"INCOMPLETE 死循环检测" |
| **N7** | **阻断** | `kDecryptFailed` 后**无终态闩锁**，而 TLS1.3 上下文**会自动恢复**（`probe26`：篡改后下一条仍能解出），TLS1.2 则毒化（`probe25` 10/10）。不闩锁 = 把"篡改必须停"完全外包给调用方 | **成立** | §3.2.1 加 `Error::terminal()` + `Status` 分组注释；§3.4.1 加 `terminal_` 闩锁与 `Fail()`；§3.3 补幂等语义；§3.4.2 边界 11；§5 绿证 11 + 红证"TLS1.3 自动恢复不得外泄" |
| **N8** | **阻断** | 票据路径 `produced==0` → 返回 `kNeedMoreInput`，与 §3.3「票据后返回 kOk」和 §5 绿证 8 三者不可能同时为真 | **成立** | §3.4.1 改**双计数** `progressed`（记录数）+ `produced`（明文字节数），返回 `(progressed \|\| produced) ? kOk : kNeedMoreInput`；§3.4.2 边界 12 |

**随修 4 处**（全部落地）：

| # | 内容 | 落地位置 |
|---|---|---|
| 1 | `max_out` 写死为**软阈值**语义 | §3.2.4 `Receive` 注释（5 条要点）+ §3.3 契约表新增一行 |
| 2 | `Receive` 签名注释补 `max_out` 说明（原来完全没有） | §3.2.4（同上） |
| 3 | §4.2 标题「采纳 8 条」→「8 条中采纳 7 条」 | §4.2 标题 + 留痕注 |
| 4 | 终止性错误补同类语义（原来只对 `kClosed` 有承诺） | §3.2.1 `Status` 分组 + `Error::terminal()` + §3.3 两行 |

**对"N5 是父会话造成的"是否认同**：**认同**。第⑤步的指令原文是
「§3.4 循环开头加 `plaintext_out.clear()`」，只说"循环开头"、没说"每次迭代用临时缓冲"，
也没说"成功才累加"。在循环体内 clear 的后果（多记录互相覆盖）没有在指令里被排除，
所以这是指令描述不精确导致的，不是执行方的理解错误。
**教训**：凡是"在循环里做什么"的指令，必须同时给出"跨迭代要保留什么"，
否则默认会被理解成"每轮重置"。

### 8.3 第⑦步复核（父会话逐行核实伪代码，3 条阻断 + 5 条严重/一般）

**核心发现**：第⑥步的 N5/N6/N7/N8 **意图全部落地**，但伪代码**跑不起来**——
3 个结构性缺陷让描述的行为**执行不到**。这是"语义对、控制流错"的一类缺陷。

| # | 级别 | 缺陷 | 核对 | 修法 |
|---|---|---|---|---|
| **B1** | **阻断（最严重）** | 成功路径**没有回边**：`if max_out && produced >= max_out: return kOk` 之后直接落到 `Fail(status):`（下一个函数定义）。若 `max_out==0` 或 `produced<max_out`，控制流**掉出循环** | **成立**。伪代码第 599 行后确实无 `continue` | 成功路径末尾补 `continue`；新增**规则 6**「每个循环体末尾必须有显式回边」；§3.4.3 固化控制流走查方法 |
| **B2** | **阻断** | `extra_len` **从未定义**：`backend_decrypt` 只返回状态，`if extra_len:` 无来源。N3（EXTRA 算术定位）的输入悬空 | **成立** | 改为 `st, extra_len = backend_decrypt(record, tmp)`，并注明 `extra_len = Σ(EXTRA.cbBuffer)`、内部必须自检 `consumed + Σ(EXTRA) == record.size()` |
| **B3** | **阻断** | `kClosed` 契约与入口检查**互相矛盾**：入口只查 `terminal_`，而 `CONTEXT_EXPIRED` 明确不置 `terminal_` → `kClosed` 后再调 `Receive` 会走 `size<5` 分支返回 `kNeedMoreInput`，违反「后续恒返回 `kClosed`」 | **成立** | 入口补 `if closed_: return kClosed`（正常终止同样幂等） |
| **B4** | 严重 | §3.4.2 标题「十个边界」实列 **12 条**——第⑤步修过的 D-a **复发** | **成立**（脚本点数确认 1..12） | 标题改「十二个」+ 留痕注补全演变链 |
| **B5** | 严重 | `kInternal` 终止语义**三处不一致**：§3.3 说"终止"、`terminal()` 不含、`Fail()` 注释只列 4 个 | **成立** | 统一为 **6 个终止态**（+`kInternal`、+`kUnsupported`），三处同步 |
| **B6** | 严重 | `tmp` **从未声明** | **成立** | 显式 `tmp = std::vector<uint8_t>{}` |
| **B7** | 一般 | 红证「必须 `kProtocolError` **或** `kNeedMoreInput`」削弱判别力：65535 > 16640，只可能 `kProtocolError` | **成立** | 删掉「或」，并说明"允许或会让 N6 变体通过" |
| **B8** | 一般 | `kUnsupported` / `kIoError` 无契约行；`kIoError` 无合法产生点 | **成立** | `kUnsupported` 归入终止态；**删除 `kIoError`**（见下） |
| **B9** | 一般 | 软阈值提前返回后未写明**排空义务** | **成立** | §3.2.4 注释 + §3.3 契约表补「必须继续调用直到 `buffered_input()==0`」 |

**`kUnsupported` / `kIoError` 的处置（回应父会话提问）**

- **`kUnsupported` → 归入终止性**。理由与父会话一致：它是**配置级**不可恢复错误，
  `Handshake` 返回它即意味着整条连接没有后续；若之后 `Receive` 还能返回
  `kNeedMoreInput` 就是幽灵状态。已加入 `terminal()`。
- **`kIoError` → 删除**。理由：`Receive` 的入参是调用方提供的 `ciphertext` 缓冲，
  socket 读写完全由调用方负责，后端**没有任何合法的产生点**。保留它等于留一个
  "谁也不知道什么时候返回"的值，会污染错误处理分支（每个调用方都要处理一个不可能的分支）。
  若将来后端自己做 I/O，应新增独立的 `IoTransport` 层，而不是在 `TlsTransport` 里混入。
  已在枚举处留注说明删除原因。

**对"文本检查无法发现控制流缺陷"是否认同**：**完全认同**，这是本轮最重要的方法论收获。

- 我做的 doc-lint（12 文档 fail=0）与残留扫描（`不应发生` / `也会通过`）**全部通过**，
  而 B1/B2/B3 三个阻断**全部逃过**——因为它们不是文本错误，是**控制流结构错误**。
- 正则检查的本质是"模式是否出现"，而 B1 的缺陷恰恰是"**某个模式没出现**"（缺 `continue`）。
  用文本检查找"缺失的控制流"在原理上不可能。
- 已把方法固化进 **§3.4.3**：①列出所有 `return`/`continue`/落空；②对每个出口断言
  三件事（记录是否已消费、`plaintext_out` 是否正确、是否与契约表逐字一致）；
  ③**特别检查循环体末尾有无回边**；④用"2 条记录逐迭代模拟"做最小复现。
- 也承认：这类走查**目前只能人工做**，无法自动化。如果将来要自动化，
  需要把伪代码写成可执行的 Python 参考实现并跑单测——那是实现阶段的产物，
  不是文档阶段能解决的。

---

## 附：一句话给主代理

今天就能落地，路径是 **Windows 零依赖 SChannel + 后端无关 `TlsTransport` 接口**；
OpenSSL 只作为 Linux 侧的后续后端，且必须 CMake 可选（`RTSC_TLS_OPENSSL=OFF` 默认），
否则会立刻违反零依赖硬约束并让 12 个既有套件 configure 失败。
第②轮磋商后接口已按 consult-b 的 12 处修正重写（10 成立 / 1 部分 / 0 不成立）；
第⑤步复核修掉 3 个阻断/中级伪代码缺陷（N1/N2/N3）+ N4 + 3 个文档级问题；
第⑥步复核再修掉 4 个**阻断**缺陷（N5 明文被覆盖 / N6 INCOMPLETE 死循环 /
N7 无终止闩锁 / N8 单计数导致票据路径返回码错误）+ 4 处随修；
第⑦步复核修掉 3 个**结构性阻断**（B1 成功路径无回边 / B2 `extra_len` 无来源 /
B3 `kClosed` 非幂等）+ B4–B9，并新增 §3.4.3 控制流走查方法；
§8 缺陷清单由 11 条合并为 **20 条**（D14 经乙自我复核撤回、降为条件性风险）。
