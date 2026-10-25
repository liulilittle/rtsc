# TLS + CredSSP + EUAR 接入连接流程 —— 方案与缺陷审计（乙）

> 角色：审计 AI（乙）。本文件只做分析与设计，**不含任何工程代码改动**。
> 唯一一次「写代码」是 `F:\rtsc\.tmp\secprobe\*.cpp` 下的五个一次性红证探针
> （不在 `src/`、不进 `CMakeLists.txt`、不参与构建）。
>
> 证据等级：
> - **[READ:path:line]** 只读源码/文档定位
> - **[BASH:cmd]** 可复现命令及其输出（红证）
> - **[推导]** 由前述证据推出，标注推导链
> - **[未验证]** 无证据，不得作为结论使用
>
> 审计基线（本文件写作时的实测状态，未改动任何产品代码）：
> `ctest --test-dir F:\rtsc\build\verify` → **16/16 passed**；
> `cmd /c F:\rtsc\.tmp\build_tls.bat` → `ninja: no work to do.`

---

## 0. 结论摘要（先给答案）

| # | 问题 | 结论 |
|---|---|---|
| 1 | 依赖方向 | **可以做到 `rtsc_proto` 的 `target_link_libraries` 一字不改**。最省事的是把编排层放在三个库**之上**（方案 A/C）；需要机器自己驱动握手时用接口反转（方案 B，新增一个零依赖 INTERFACE 目标，仍不引入平台库）。**但**：`rtsc_tls` 目前**根本不是跨平台的**（唯一 TU 无条件 `#include <windows.h>`），这是三个方案共同的前置阻塞项，必须先修。 |
| 2 | `OnExternalSecurityComplete()` 签名 | **不够**。它无输入、无失败通道、无「还需读多少」的表达；HYBRID_EX 下它把状态机推进到 `kAwaitConnectResponse`，随后到达的 EUAR 被判为 *malformed MCS Connect Response*（已红证）。~~最小改动 = 新增两个成员 + 一个新阶段~~ **【已被 §9.2 撤回】定案结论：EUAR 由安全层消费，`connect_machine.h` 零改动；只需把 `connect_machine.cpp:355` 的静默 no-op 改成 `Fail`。**全仓生产调用点 0 处、测试调用点 1 处。 |
| 3 | framing 归属 | `TpktStream` **概念上适用于** TLS 明文层（同样是 TPKT 字节流），**但当前 API 不能直接用**：它剥掉 4 字节头，而 `ConnectMachine::OnData` 要求带头（已红证）；且它的「重同步」会把 EUAR 的 4 字节**静默吞掉**（已红证）。必须新增/改造一层，且该层**属于 `rtsc_proto`**（TPKT 知识已在 `rtsc_proto`，且无平台依赖）。 |
| 4 | 重协商 / 关闭 / 中断 | `step_` 与 `closed()` **没有 1:1 配对**：`TlsTransport` 有 `last_error()`，`CredsspClient` 没有；`kClosed` 在 CredSSP 侧没有任何落点，`complete()` 还会由 true 翻回 false（已红证）。`SEC_I_RENEGOTIATE` 的 `ISC` 返回值被**丢弃**，真重协商不会被发现。 |
| 5 | 凭据生命周期 | **构成违反**。同一口令至少 8 份拷贝、无单一权威写者、全仓零清零；且 NLA 下 `Client Info` 仍回填明文口令，等于把已由 CredSSP 封装的凭据再发一遍。 |
| 6 | 缺陷清单 | **23 条**，其中 **9 条会直接导致接入失败/无法收敛**（B01/B03/B05/B06/B07/B08/B09/B10/B19）。 |

**最关键的 3 条**：

1. **B01 + B02**：`CredsspClient` 在生产路径上**既拿不到服务器公钥、也拿不到随机数**——两个 setter 都叫 `...ForTest`。按现有 API 直接接入，`pubKeyAuth` 是「空公钥的哈希」，真实服务器必拒。这不是接线问题，是**能力缺口**。
2. **B03 + B05 + B08**：EUAR 在现有两层里**都没有合法落点**——喂给状态机是「MCS 解析失败」，喂给 `TpktStream` 是被静默丢弃。HYBRID_EX 的整条路径无法收敛。
3. **B19**：`rtsc_tls` 的唯一 TU 无条件包含 `windows.h`，CMake 也无条件编译它。所谓「协议层跨平台」成立，但**安全层不跨平台**——任何新库只要依赖 `rtsc_tls` 就一起变成 Windows-only。

---

## 1. 事实基线（只列与本任务相关的）

### 1.1 现有 CMake 目标图（实测）

```
rtsc_crypto    : src/crypto/hash.cpp                    无外部依赖
rtsc_proto     : 15 个 src/proto/*.cpp                  -> rtsc_crypto          [READ:CMakeLists.txt:36]
rtsc_credssp   : 3 个 src/credssp/*.cpp                 -> rtsc_crypto          [READ:CMakeLists.txt:117]
rtsc_tls       : src/net/tls_schannel.cpp               -> (WIN32) secur32 crypt32 [READ:CMakeLists.txt:51-55]
rtsc_util      : src/util/crash_guard.cpp               -> (MSVC) dbghelp       [READ:CMakeLists.txt:44-46]
```

三个库都 `target_include_directories(... PUBLIC include)`
[READ:CMakeLists.txt:35,40,43,52,116]，**共用同一个头文件根**。
`rtsc_tls` 与 `rtsc_credssp` 互不依赖，二者也都不依赖 `rtsc_proto`。

### 1.2 `rtsc_proto` 确实没有安全层依赖

```
[BASH: Select-String -Path F:\rtsc\include\rtsc\proto\*.h,F:\rtsc\src\proto\*.cpp
       -Pattern "rtsc/net/tls.h|rtsc/credssp"]
→ （无输出）
```

### 1.3 `rtsc_tls` 不是跨平台的（**新发现，与本任务强相关**）

`CMakeLists.txt` 的注释宣称「只有后端 TU 是 Windows 相关，其它平台换后端即可」
[READ:CMakeLists.txt:48-50]，但实际：

- `add_library(rtsc_tls STATIC src/net/tls_schannel.cpp)` **无条件**执行
  [READ:CMakeLists.txt:51]，`if(WIN32)` 只包住了 `target_link_libraries`
  [READ:CMakeLists.txt:53-55]。
- 该 TU 里 **`#if`/`#ifdef`/`#ifndef` 条件编译指令数为 0**（实测），开头无条件
  `#include <windows.h>` / `<schannel.h>` / `<sspi.h>` / `<wincrypt.h>`
  [READ:src/net/tls_schannel.cpp:25-32]。
- 测试 TU 同样无条件包含 Windows 头 [READ:tests/test_tls.cpp:20-23]，
  `rtsc_tls_tests` 也无平台守卫 [READ:CMakeLists.txt:105-107]。

> **结论**：在 Linux 上 `cmake --build` 会在编译 `rtsc_tls` 这一步失败。
> 「协议层跨平台」成立（`rtsc_proto` 无平台依赖），「安全层跨平台」**不成立**。
> 这是任务前提「rtsc_proto 不能依赖 rtsc_tls，否则 Linux 无 SChannel 就编译不过」的
> **更强版本**：不是「链接不到 SChannel」，而是**编译期就过不去**。

### 1.4 现有接口形状（本任务要用的全部入口）

```cpp
// TlsTransport  [READ:include/rtsc/net/tls.h:124-188]
Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed, std::vector<uint8_t>& out);
Error Send(const uint8_t* plaintext, size_t size, size_t& consumed, std::vector<uint8_t>& out);
Error Receive(const uint8_t* ciphertext, size_t size, std::vector<uint8_t>& plaintext, size_t max_out);
bool  handshake_complete() const noexcept;
bool  closed() const noexcept;
size_t buffered_input() const noexcept;
const Error& last_error() const noexcept;

// CredsspClient  [READ:include/rtsc/credssp/credssp.h:40-71]
CredsspClient(Credentials, uint32_t version);
Error Start(Bytes& out);
Error OnServerResponse(const uint8_t* data, size_t size, Bytes& out);
bool  complete() const noexcept;      // == (step_ == kDone)
uint32_t version() const noexcept;
// 生产 setter：无。只有 SetNonceForTest / SetServerPublicKeyForTest

// ConnectMachine  [READ:include/rtsc/proto/connect_machine.h:107-119]
ConnectStep Start();
ConnectStep OnData(const uint8_t* data, size_t size);   // 要求「完整 PDU」
ConnectStep OnExternalSecurityComplete();               // 无输入、无失败通道
```

---

## 2. 六个关注点的结论（含红证）

### 2.1 关注点 1：依赖方向与 CMake 目标图

#### 2.1.1 硬约束的准确表述

约束不是「`rtsc_proto` 不能用 TLS 概念」，而是：

> **`rtsc_proto` 的依赖闭包里不得出现任何平台库（secur32/crypt32/...），
> 也不得出现「只存在于 Windows 的实现 TU」。**

由 §1.3，`rtsc_tls` 当前满足「只存在于 Windows 的实现 TU」，所以
`rtsc_proto -> rtsc_tls` **在任何平台都会把 Windows 头拖进来**。

#### 2.1.2 三个方案的依赖图与无环证明

**方案 A（编排层在协议层之上，最小改动路径）**

```
        ┌──────────────┐
        │  apps/tests  │
        └──────┬───────┘
               │
        ┌──────▼───────┐
        │ rtsc_session │  (新) 只做「谁读谁写」的循环
        └──┬────┬────┬─┘
           │    │    │
   ┌───────▼┐ ┌─▼─────────┐ ┌▼──────────┐
   │rtsc_proto│ │rtsc_tls  │ │rtsc_credssp│
   └────┬────┘ └─┬─────────┘ └┬──────────┘
        │        │(WIN32)      │
   ┌────▼────┐ ┌─▼──────────┐ ┌▼─────────┐
   │rtsc_crypto│ │secur32    │ │rtsc_crypto│
   └─────────┘ │crypt32    │ └──────────┘
               └───────────┘
```

[READ:audit-a.md:912-935]（以下为逐字摘录，含甲的原始注释）
```cmake
# 1) 纯接口：平台中立，永远可构建（header-only）
add_library(rtsc_tls_api INTERFACE)
target_include_directories(rtsc_tls_api INTERFACE include)

# 2) 后端：仅 Windows
if(WIN32)
    add_library(rtsc_tls_schannel STATIC src/net/tls_schannel.cpp)
    target_link_libraries(rtsc_tls_schannel PUBLIC rtsc_tls_api secur32 crypt32)
endif()

# 3) 门面：任何平台都存在；非 Windows 时退化为「无可用后端」
add_library(rtsc_tls STATIC src/net/tls_factory.cpp)   # 新增：只含 CreateTlsTransport 分发
target_link_libraries(rtsc_tls PUBLIC rtsc_tls_api)
if(WIN32)
    target_link_libraries(rtsc_tls PUBLIC rtsc_tls_schannel)
else()
    target_link_libraries(rtsc_tls PUBLIC rtsc_tls_unavailable)  # 返回 nullptr + reason
endif()

# 4) 安全层：汇合点
add_library(rtsc_security STATIC src/sec/security_layer.cpp src/sec/random.cpp)
target_link_libraries(rtsc_security PUBLIC rtsc_tls rtsc_credssp rtsc_proto)
```

- **无环证明**：所有新增边都指向 `{rtsc_proto, rtsc_tls, rtsc_credssp}`，
  这三个目标**没有任何一条出边指向 `rtsc_session`**（它们的
  `target_link_libraries` 分别是 `rtsc_crypto` / `secur32 crypt32` /
  `rtsc_crypto`，见 §1.1）。因此新图的强连通分量都是单点，图是 DAG。
- **`rtsc_proto` 不变**：`target_link_libraries(rtsc_proto PUBLIC rtsc_crypto)`
  [READ:CMakeLists.txt:36] 保持原样，既不加库也不加平台依赖。

**方案 B（接口反转：抽象在 `rtsc_proto` 侧，实现下沉）**

```
rtsc_secapi (INTERFACE, 仅头文件, 零依赖)     ← 新
   ▲                        ▲
   │                        │
rtsc_proto              rtsc_security (新)
   │                        │
rtsc_crypto          rtsc_tls  rtsc_credssp
```

```cmake
add_library(rtsc_secapi INTERFACE)
target_include_directories(rtsc_secapi INTERFACE include)
# INTERFACE 目标不产生 .lib，也不传递任何平台库

target_link_libraries(rtsc_proto PUBLIC rtsc_crypto rtsc_secapi)   # 只增，零平台库
add_library(rtsc_security STATIC src/security/security_channel.cpp)
target_link_libraries(rtsc_security PUBLIC rtsc_secapi rtsc_tls rtsc_credssp)
```

- **无环证明**：`rtsc_secapi` 是无出边的 INTERFACE 目标；`rtsc_proto` 只多了一条
  指向它的边；`rtsc_security` 指向 `rtsc_secapi`。`rtsc_proto` 与
  `rtsc_security` 之间**没有边**（方向是「都依赖 secapi」，不是互相依赖）。
- **`rtsc_proto` 变化**：只增一个零依赖 INTERFACE 目标，**不引入任何平台库**。
- 这是「接口反转」的标准形态：抽象归被依赖方（proto），实现归依赖方（security）。

**方案 C（门面组合，`rtsc_proto` 零 diff）**

```
rtsc_security (新) -> rtsc_tls, rtsc_credssp, rtsc_crypto      ← 不认识 rtsc_proto
rtsc_session  (新) -> rtsc_security, rtsc_proto
```

- **无环证明**：`rtsc_security` 完全不引用 `rtsc_proto`（连头文件都不 include），
  两者是**并列**关系，由 `rtsc_session` 汇聚。汇聚点只有一个，不可能成环。
- **`rtsc_proto` 变化**：**零**。

#### 2.1.3 一个必须点明的陷阱：头文件根是共享的

五个库都是 `PUBLIC include` [READ:CMakeLists.txt:35,40,43,52,116]。
这意味着从 `src/proto/*.cpp` 里写 `#include "rtsc/net/tls.h"`
**在 Windows 上能编过、也能链过**（因为 `rtsc_tls` 迟早被别的目标拉进来）。
也就是说：**分层约束在编译器和链接器层面都不可靠**。

建议补一条 CI 守卫（`verify.ps1` 里加一个 grep 步骤即可，不进构建图）：

```
禁止 src/proto/** 与 include/rtsc/proto/** 出现
  rtsc/net/tls.h | rtsc/credssp/ | secur32 | windows.h
```

这条守卫的价值：方案 A/C 都依赖「proto 永远不认识 tls」这个不变量，
而该不变量目前**没有任何机制保障**。

#### 2.1.4 结论

三个方案都能满足硬约束。**排序建议**：

- 要「改动最小、可先跑通」→ **方案 C**（proto 零 diff，security 也不认识 proto）
- 要「状态机自洽、调用方不会忘调钩子」→ **方案 B**
- 要「最贴近现有两段式字节流风格、测试最省事」→ **方案 A**

三者都**必须先修 §1.3 的 `rtsc_tls` 平台守卫**，否则跨平台前提不成立。

---

### 2.2 关注点 2：`OnExternalSecurityComplete()` 的语义缺口

#### 2.2.1 全仓调用点（`grep` 结果，逐个给行号）

| 类型 | 位置 | 说明 |
|---|---|---|
| 声明 | `include/rtsc/proto/connect_machine.h:115` | `ConnectStep OnExternalSecurityComplete();` |
| 注释契约 | `include/rtsc/proto/connect_machine.h:113-114` | 「handshake 成功后调用，仅在 kAwaitExternalSecurity 有效」 |
| 定义 | `src/proto/connect_machine.cpp:352-359` | 只做「阶段检查 + `SendConnectInitial()`」 |
| 唯一测试调用 | `tests/test_connect_machine.cpp:208` | 断言调用后直接进入 `kAwaitConnectResponse` |
| 同测试的语义固化 | `tests/test_connect_machine.cpp:200-213` | 把「钩子 → 立刻发 Connect Initial」写成期望 |
| 反例测试 | `tests/test_connect_machine.cpp:215-224` | 断言该阶段收任何数据都 `Fail` |
| 文档引用 | `docs/spec/tls-backend.design-a.md:161,174,177,185,1268` | 只描述 TLS 段，未处理 EUAR |
| 计划 | `.opencode/plan.md:64` | 待接入项 |
| 过程记录 | `.opencode/process.md:1032,1086,1099` | 已知缺口 |

**生产代码调用点：0 个。**（`tools/` 里也没有）
→ 因此改签名的成本是 **1 处测试调用**，可以放心改。

#### 2.2.2 缺口是什么（不是「参数不够」，是「语义装不下」）

现有签名 `ConnectStep OnExternalSecurityComplete()` 的输出结构是
`{std::vector<uint8_t> output; bool needs_input;}` [READ:include/rtsc/proto/connect_machine.h:38-41]。
它能表达的信息只有「要发什么」和「要不要继续读」。而 HYBRID_EX 需要表达三件事：

1. **「安全层成功了，但服务器还欠我 4 字节 EUAR，先别发 MCS」**
   —— 没有字段能表达。
2. **「安全层失败了（CredSSP 返回 errorCode / TLS fatal alert），进 kFailed」**
   —— 没有入参，`Fail()` 是 private [READ:include/rtsc/proto/connect_machine.h:122]，
   调用方**无法**把失败告诉状态机，只能直接丢弃对象。
3. **「EUAR 的结果是 AUTHZ_ACCESS_DENIED，必须断开」**
   —— 状态机里没有 EUAR 概念，`ConnectPhase` 也没有对应阶段
   [READ:include/rtsc/proto/connect_machine.h:22-32]。

**红证（直接后果）**：

```
[BASH: F:\rtsc\.tmp\secprobe\p_connect.exe]
A1 phase after CCF          = await-external-security
A1 negotiated_protocol      = 0x00000008
A2 after hook: phase=await-connect-response out=404 bytes
A3 fed EUAR(denied): failed=1 phase=failed error='malformed MCS Connect Response'
A3 verdict: EUAR after the hook is misdiagnosed as a malformed MCS Connect Response
```

推导链：真实服务器 CCF `selectedProtocol=0x08` [READ:evidence/handshake-001.md:41] →
`connect_machine.cpp:213-217` 进入 `kAwaitExternalSecurity` →
钩子 `connect_machine.cpp:358` 直接 `SendConnectInitial()` →
服务器先发 4 字节 EUAR（`security-layer.md:288` 时序图、`:564-565`「唯一例外是 EUAR…裸 4 字节」）→
`OnData` 把它交给 `McsConnectResponse::parse` → `mcs.cpp:124-129` 长度不符 →
报错信息指向**错误的层**。

> 这条错误的实际危害：**AUTHZ_ACCESS_DENIED 被报成「MCS 协议错误」**。
> 用户看到的是「协议实现有问题」，而不是「你没有远程登录权限」。
> 而如果 AUTHZ_SUCCESS 被吞掉，客户端会在服务器已判定无权时继续发 MCS，
> 之后只能收到一个无解释的断连。

#### 2.2.3 ~~最小改动方案（不改现有签名）~~ 【本节结论已被 §9.2 撤回，保留原文仅供对照】

> **撤回理由（摘要）**：本节把 EUAR 放进 `rtsc_proto`，与 §3 方案 C（EUAR 在安全层）自相矛盾。
> `TlsTransport::Receive` 可能一次给出 4+N 字节（`tls.h:146-147` 契约），N 字节只能由持有
> 缓冲的一方保管，即安全层。若 proto 要"读 4 字节"，必然与安全层抢缓冲，产生
> `audit-a.md:115-117` 描述的 split-brain。**完整裁决见 §9.2。**
> 下文所有 `kAwaitEarlyUserAuth` / `OnEarlyUserAuthResult` / `OnExternalSecurityFailed`
> 均**不再采纳**；`connect_machine.h` 零改动。

**核心判断：EUAR 是纯 4 字节定长 PDU，属于协议层知识，应该由 `rtsc_proto` 自己消费，
不应该让安全层代读。** 这样既不需要 `rtsc_proto` 认识 TLS，也不需要安全层认识 MCS。

新增 3 个东西（全部在 `rtsc_proto` 内，零新依赖）：

```cpp
// connect_machine.h —— 新增阶段（放在 kAwaitExternalSecurity 之后）
enum class ConnectPhase : uint8_t {
    ...
    kAwaitExternalSecurity,
    kAwaitEarlyUserAuth,      // 新：HYBRID_EX 下等 4 字节 EUAR
    kAwaitConnectResponse,
    ...
};

// 新增两个成员函数（现有 OnExternalSecurityComplete() 保持原样）
// 1) 安全层失败：唯一能把失败灌进状态机的入口
ConnectStep OnExternalSecurityFailed(const char* reason);
// 2) EUAR 结果：状态机自己判定 AUTHZ_SUCCESS / AUTHZ_ACCESS_DENIED
ConnectStep OnEarlyUserAuthResult(uint32_t authorization_result);
```

行为约定（**这三条就是签名缺口的形式化补丁**）：

| 情形 | 行为 |
|---|---|
| `OnExternalSecurityComplete()` 且 `negotiated_protocol & kProtocolHybridEx` | 进入 `kAwaitEarlyUserAuth`，`output` 空，`needs_input=true`。**不发 MCS** |
| `OnExternalSecurityComplete()` 且非 HYBRID_EX | 保持今天的行为（`SendConnectInitial()`） |
| `kAwaitEarlyUserAuth` 下 `OnData` | 自己缓冲，累计到 4 字节才动作（**必须支持半包**）；`>4` 字节视为协议错误（证明 EUAR 后没有粘连数据） |
| `authorizationResult == 0x00000000` (AUTHZ_SUCCESS) | 发 MCS Connect Initial（等价于今天的 `SendConnectInitial()`） |
| `authorizationResult == 0x00000005` (AUTHZ_ACCESS_DENIED) | `Fail("early user authorization denied")`，`needs_input=false`，调用方必须断连 |
| 其它值 | `Fail("unknown early user authorization result")`（`security-layer.md:401` 明确规范未定义，实现应按失败处理） |

取值依据：[READ:docs/spec/security-layer.md:385-386]（AUTHZ_SUCCESS=0 / ACCESS_DENIED=5）、
[READ:docs/spec/security-layer.md:400]（denied 时 SHOULD drop the connection）。

**为什么用 `OnEarlyUserAuthResult(uint32_t)` 而不是让 `OnData` 直接吃 4 字节？**
两种都行，但显式函数有 3 个好处：

1. 调用方**不可能忘记**语义（编译期强制：EUAR 只有这一条路能推进状态机）；
2. 测试可以只调这一个函数，不需要构造 4 字节缓冲；
3. `OnData` 保持「完整 PDU」的既有契约，不需要为 4 字节破例。

同时建议保留 `OnData` 在 `kAwaitEarlyUserAuth` 下的**兜底**（收满 4 字节自动调用
`OnEarlyUserAuthResult`），这样「字节流驱动」和「事件驱动」两种调用风格都能用。

#### 2.2.4 顺带发现的签名缺陷（同一处，必须一起改）

```
[BASH: F:\rtsc\.tmp\secprobe\p_connect.exe]
B1 first call:  phase=await-connect-response out=404 needs_input=1
B2 second call: phase=await-connect-response out=0 needs_input=0 failed=0
B2 verdict: misuse is silent (empty output, needs_input=false, no failure)
```

重复调用**既不报错也不推进**，返回一个「什么都不用做」的 `ConnectStep`。
调用方若把 `needs_input=false` 理解为「结束了」，就会静默卡死。
建议：第二次调用 → `Fail("OnExternalSecurityComplete called twice")`。

> **【§9.2 定案】** 这一条**仍然有效**，且是 proto 侧唯一需要改的地方。它不涉及签名变更，只是把 `connect_machine.cpp:355` 的
> 静默返回改成 `Fail`。合并编号 **M06**。

---

### 2.3 关注点 3：TLS 明文流与 PDU 流的粘包/半包

#### 2.3.1 `TpktStream` 到底是哪一层的

证据（全部指向「TCP 层」，但机制对 TLS 明文层同样成立）：

| 证据 | 内容 |
|---|---|
| `include/rtsc/proto/framing.h:12-16` | 注释明确写 **「TCP is a byte stream: a single recv() can return half a PDU, or three PDUs glued together」**，定位是 **TCP 层**分帧器 |
| `include/rtsc/proto/framing.h:15-16` | 「hands back exactly one complete PDU **payload** at a time（**the 4-byte TPKT header is stripped**）」 |
| `src/proto/framing.cpp:86-88` | `payload.assign(...+read_+4, ...+read_+length)` —— 实证剥头 |
| `src/proto/framing.cpp:37-54` | `SkipToNextCandidate()`：**逐字节扫描 + 丢弃**，`dropped_` 计数 |
| `src/proto/framing.cpp:61-68` | 失步后强制前进 1 字节并 `++dropped_` |
| `src/proto/framing.cpp:12` | `kMinTpktLength = kTpktHeaderSize`（=4），即「header only」也被接受 |
| 全仓使用点 | 只有 `tests/test_framing.cpp` 和 `evidence/tls/probes/*.cpp`。**生产代码 0 处使用** |

#### 2.3.2 判定：概念适用，API 不适用

**（a）概念上适用**——TLS 解密后的明文确实还是 TPKT 字节流。
而且**必须**再分一层，理由来自 `TlsTransport::Receive` 的契约本身：

```
[READ:include/rtsc/net/tls.h:146-147]
// `plaintext` is append-only: existing content is preserved and new bytes are
// appended. One call may append plaintext from several records.
[READ:include/rtsc/net/tls.h:152-156]
// `max_out` is a soft threshold ... the actual append may exceed it by up to one record
```

即：**一次 `Receive` 可能给出 0.5 个 PDU、1 个 PDU、或 N 个 PDU**。
实现侧也证实这一点：`tls_schannel.cpp:241-342` 是 `for(;;)` 循环，
把 `rx_buffer_` 里所有完整记录一次性解密并 `plaintext.insert(...)` 追加
[READ:src/net/tls_schannel.cpp:332]。所以「一次 Receive = 一个 PDU」是**错的假设**。

**（b）API 上不适用**——两条硬冲突，都已红证：

**冲突 1：剥头 vs 要头**

```
[BASH: F:\rtsc\.tmp\secprobe\p_framing.exe]
A1 raw TPKT(19 B): failed=0 phase=await-external-security
B1 TpktStream::Next=Ok payload=15 (header stripped)
B2 feeding that payload to OnData: failed=1 error='malformed X.224 Connection Confirm'
B2 verdict: TpktStream strips the 4-byte TPKT header but OnData parses it
            -> the two cannot be composed
```

`OnData` 的各个解析器都要求带头：
`X224ConnectionConfirm::parse` 第一步就是 `TpktHeader::parse`
[READ:src/proto/connection_initiation.cpp:56]，
`McsConnectResponse::parse` 走 `read_tpkt`，后者要求
`tpkt.length == size`（严格等长）[READ:src/proto/mcs.cpp:124-129]。

**冲突 2：静默重同步 vs 必须报错**

```
[BASH: F:\rtsc\.tmp\secprobe\p_connect.exe]
C1 Next=Ok payload=4 dropped=4
C2 verdict: the 4 EUAR bytes were dropped silently;
            AUTHZ_ACCESS_DENIED never reaches the caller
```

把「EUAR(4B) + 合法 MCS PDU」一起喂给 `TpktStream`：
它把 `00 00 00 00` 当垃圾丢掉（`dropped_bytes()==4`），
**`AUTHZ_ACCESS_DENIED` 永远到不了调用方**。

这个行为对 TCP 层是**特性**（丢垃圾能恢复），对 TLS 明文层是**灾难**
（明文是经过认证的，出现非法字节就意味着实现错了，必须 fail-fast）。

**（c）顺带：`OnData` 自己的边界契约还不自洽**

```
[BASH: F:\rtsc\.tmp\secprobe\p_boundary.exe]
A1 CCF+extra(30 B in): failed=0 phase=await-connect-response out=404
A2 verdict: the trailing 11 bytes were accepted and silently discarded
B1 MCS+1 byte: failed=1 phase=failed out=0 error='malformed MCS Connect Response'
B2 verdict: the SAME coalescing is fatal here -> two phases disagree
```

- `kAwaitNegotiation`：`X224ConnectionConfirm::parse` 只看 `tpkt.length`，
  **不校验 `size == length`** [READ:src/proto/connection_initiation.cpp:56-70]，
  尾随字节被静默丢弃；
- `kAwaitConnectResponse`：`read_tpkt` 要求严格等长
  [READ:src/proto/mcs.cpp:128]，同样形状直接判死。

同一个「多 PDU 粘在一起」的输入，一个阶段放过、一个阶段判死。
**这是接入后必然踩到的坑**：TLS 明文很容易一次给出 CCF + 后续数据。

#### 2.3.3 该新增什么、放在哪个库

**结论：放在 `rtsc_proto`，与 `framing.h` 同址，不新建库。**

理由：

1. TPKT 结构定义已经在 `rtsc_proto`（`include/rtsc/proto/tpkt.h`）；
2. `framing.h` 已在 `rtsc_proto` 且**零平台依赖**（只 include `byte_order.h` + `tpkt.h`
   [READ:include/rtsc/proto/framing.h:7-8]）；
3. 若放到 `rtsc_security`/`rtsc_session`，就变成「安全层也要懂 TPKT」，
   与方案 C 的「security 不认识 proto」相冲突。

**最小改造（二选一，推荐第一种）**：

| 方案 | 改动 | 优点 | 缺点 |
|---|---|---|---|
| **3-i 加严格模式** | `TpktStream` 增加 `enum class Mode { kResync, kStrict };`，`kStrict` 下：① 首字节不是 `0x03 0x00` 立即返回 `Status::InvalidVersion`（**不扫描、不丢字节**）；② 新增 `Status NextPdu(std::vector<uint8_t>& pdu)` 返回**含 4 字节头的完整 PDU** | 复用现有缓冲/Compact 逻辑；两个模式各自可测；`OnData` 不用改 | `TpktStream` 承担两种语义，需要测试矩阵覆盖两个模式 |
| **3-ii 新增独立类** | 新增 `class StrictTpktFramer`（`include/rtsc/proto/strict_framing.h`），只做「累计 → 出完整 PDU」，任何非法字节 → `InvalidVersion` | 语义单一、不可能误用；`TpktStream` 原样不动 | 代码重复（缓冲/Compact 要再写一遍），约 +80 行 |

**无论选哪个，都必须满足的 3 条不变量**（这是本关注点的交付物）：

1. **输出含 TPKT 头**（否则不能喂 `OnData`）；
2. **绝不重同步**：任何非法字节 → 立即 `Fail`，且**不得消耗**（便于抓包定位）；
3. **EUAR 必须先于该层被消费**：4 字节裸数据在 `kAwaitEarlyUserAuth` 由状态机读掉，
   **不允许**流到 TPKT 分帧器（否则就是 §2.3.2 冲突 2 的重演）。

> 第 3 条是接入顺序的**硬性要求**，建议在分帧器里加一条自检：
> 若在 `kAwaitEarlyUserAuth` 之外的时间看到「首字节不是 0x03」，报错信息里
> 明确写「可能是未消费的 EUAR」，避免又出现「malformed MCS」这种误导性诊断。

---

### 2.4 关注点 4：重协商 / 关闭 / 中断

#### 2.4.1 `SEC_I_RENEGOTIATE` 的实际处理

`tls_schannel.cpp` 的注释与实现：

| 位置 | 内容 |
|---|---|
| `src/net/tls_schannel.cpp:17-18` | 「TLS 1.3 reports a NewSessionTicket as `SEC_I_RENEGOTIATE (0x00090321)` with data=0 and the raw handshake record in EXTRA」 |
| `src/net/tls_schannel.cpp:283-292` | TLS1.3 → `FeedExtraOnce()` 后 `continue`（丢弃输出）；TLS1.2 → `Fail(kProtocolError)` |
| `src/net/tls_schannel.cpp:293-298` | `SEC_I_NO_RENEGOTIATION`：TLS1.3 `continue`，TLS1.2 `Fail` |
| `src/net/tls_schannel.cpp:645-666` | `FeedExtraOnce()`：`ISC` 的返回值**在第 660 行被完全丢弃** |

**问题**：`FeedExtraOnce` 里

```cpp
InitializeSecurityContextW(&cred_, &ctx_, nullptr, req, 0, SECURITY_NATIVE_DREP,
                           &ibd, 0, &ctx_, &obd, &flags, nullptr);   // :660 返回值未接收
if (ob.cbBuffer > 0 && ob.pvBuffer != nullptr) FreeContextBuffer(ob.pvBuffer);  // :662-664
```

- 返回值不检查 → 若 `ISC` 返回 `SEC_E_*`，**上下文可能已损坏而调用方不知道**；
- 输出 token 直接 `Free` 掉 → 若服务器**真的**发起重协商（`HelloRequest`），
  我们既不回应也不报错，握手状态就此错位。

`evidence/tls/impl-log.md:95`（I1）已承认 TLS1.3 路径未被覆盖；
`impl-log.md:99`（I5）承认未接真实服务器。所以这条是**已知未验证区**里最危险的一条。

**建议**：`FeedExtraOnce` 返回 `Error`，调用方在 `SEC_I_RENEGOTIATE` 分支里：

- TLS1.3 + `EXTRA` 是 handshake 记录且类型是 `NewSessionTicket(4)` → 丢弃（正常）；
- 其它任何情况 → `Fail(kProtocolError)`（RDP 不允许重协商，见
  `tls-backend.design-b.md:492` R10）。

#### 2.4.2 CredSSP 五步中途收到 `kClosed`：缺配对

**三个对象各自的状态信号（1:1 对照表）**

| 概念 | `TlsTransport` | `CredsspClient` | `ConnectMachine` |
|---|---|---|---|
| 「对端正常关闭」 | `Status::kClosed` [READ:include/rtsc/net/tls.h:50]；`closed()` [READ:include/rtsc/net/tls.h:184] | **无** | **无** |
| 「本端已关闭」 | `closed()` / `Shutdown()` [READ:include/rtsc/net/tls.h:180] | **无** | **无** |
| 「失败原因」 | `last_error()` [READ:include/rtsc/net/tls.h:186] | **无**（`last_error_` 是 private，见 `credssp.h:95`） | `state().error` [READ:include/rtsc/proto/connect_machine.h:57] |
| 「是否完成」 | `handshake_complete()` [READ:include/rtsc/net/tls.h:183] | `complete()` [READ:include/rtsc/credssp/credssp.h:53] | `done()` [READ:include/rtsc/proto/connect_machine.h:119] |
| 「失败态」 | `Error::terminal()` [READ:include/rtsc/net/tls.h:67-71] | `Step::kFailed`（**private，无访问器**）[READ:include/rtsc/credssp/credssp.h:75-81] | `failed()` [READ:include/rtsc/proto/connect_machine.h:118] |

**结论：不满足 1:1。** 具体三处：

1. **`last_error()` 只有 TLS 有**。CredSSP 的 `last_error_` 是私有成员
   [READ:include/rtsc/credssp/credssp.h:95]，
   `OnServerResponse` 返回的 `Error` 是**一次性**的——调用方若不立即保存，
   失败原因就永久丢失。而 `TlsTransport` 提供了持久化的 `last_error()`
   [READ:include/rtsc/net/tls.h:186]。**同一概念，一边有、一边没有**。

2. **`kClosed` 在 CredSSP 侧没有落点**。设想：第 3 步发出后服务器直接
   `close_notify`（TLS 层正常关闭）。此时
   - `TlsTransport::Receive` 返回 `kClosed` [READ:src/net/tls_schannel.cpp:299-303]；
   - `CredsspClient::step_` 仍停在 `kAwaitServerEcho` [READ:include/rtsc/credssp/credssp.h:78]；
   - `complete()` 返回 `false`；
   - **没有任何 API 能把「永远不会再收到响应」这件事告诉 CredSSP**。

   调用方只能自己记住「TLS 关了」这个外部事实，并在外层另建一个状态。

3. **`complete()` 非单调**（红证）：

   ```
   [BASH: F:\rtsc\.tmp\secprobe\p_credssp.exe]
   C1 after step4: ok=1 complete=1
   C2 after stray input: ok=0 complete=0 status=2
   C2 verdict: a post-completion byte flips complete() true->false;
               there is no latch separating kDone from kFailed
   ```

   推导：`credssp.cpp:84-86`

   ```cpp
   if (step_ == Step::kDone) {
       return Fail(Status::kMalformed, "response after completion");
   }
   ```

   `Fail()` 会把 `step_` 置成 `kFailed` [READ:src/credssp/credssp.cpp:54]，
   于是 `complete()` 从 true 变 false。

   **后果**：一个「已经完成」的握手，被一个多余字节（比如 EUAR 被错误路由过来）
   打回「未完成且失败」，而 `kDone` 这个事实被抹掉了。

**建议的最小配对补丁（三处，全部是「补齐同类概念」而不是新增语义）**：

```cpp
// credssp.h —— 与 TlsTransport 对齐
bool failed() const noexcept { return step_ == Step::kFailed; }
const Error& last_error() const noexcept { return last_error_; }
void Abort(Status status, std::string message);   // 外部（传输关闭/超时）驱动到终态
```

```cpp
// connect_machine.h —— 传输关闭也要能进 kFailed
ConnectStep OnTransportClosed(const char* reason);
```

并在 `Complete` 之后**加锁存**：一旦进入 `kDone`，后续 `OnServerResponse`
返回错误但**不改变** `step_`（`complete()` 保持 true，`failed()` 也置位，
调用方据此知道「完成了，但之后有异常字节」）。

#### 2.4.3 关闭路径上另外三个实现缺陷

**（a）`Shutdown()` 的 `closed()` 会说谎**

```
[READ:src/net/tls_schannel.cpp:423-433]
423:  shutdown_sent_ = true;
429:  if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
430:      closed_ = true;
431:      return MakeError(Status::kOk, st, "");
432:  }
433:  return MakeError(Status::kOk, st, "shutdown best effort");
```

第 433 行：返回 `kOk`，但**不置 `closed_`**。于是 `closed()` [READ:src/net/tls_schannel.cpp:438]
返回 false，调用方会认为「还能继续用」，而实际上 `close_notify` 没发成功。

**（b）`kClosed` 之后无法履行 drain 契约**

```
[READ:include/rtsc/net/tls.h:157-160]
// Drain obligation: when returning early because max_out was reached,
// complete records may still be buffered. The caller must keep calling
// Receive (size may be 0) until buffered_input() == 0 ...
[READ:src/net/tls_schannel.cpp:230]
230:  if (closed_) return MakeError(Status::kClosed, 0, "already closed");
[READ:src/net/tls_schannel.cpp:439]
439:  size_t buffered_input() const noexcept override { return rx_buffer_.size(); }
```

一旦 `closed_` 置位，`Receive` 立即返回 `kClosed`，**再也不可能把 `rx_buffer_` 排空**。
若 `buffered_input() != 0`（例如同一 TCP 段里 `close_notify` 后面还跟了字节），
调用方就会陷入「契约要求我 drain，但 API 不允许我 drain」的死循环。

**（c）`plaintext` 契约自相矛盾（低 severity，但会让调用方写错）**

```
[READ:include/rtsc/net/tls.h:146-147]  plaintext is append-only: existing content is preserved
[READ:include/rtsc/net/tls.h:148]      On any return other than kOk and kClosed, plaintext is guaranteed empty
```

若调用方传入非空 vector 再收到失败，「append-only」与「guaranteed empty」不可能同时成立。
实现侧也确实不清空 [READ:src/net/tls_schannel.cpp:250-251,276-281,305-310]。
建议改为「失败时不追加任何字节，调用方原有内容保持不变」。

---

### 2.5 关注点 5：凭据生命周期（C9 / D1）

#### 2.5.1 现状：同一口令至少 8 份拷贝

| # | 位置 | 形态 |
|---|---|---|
| 1 | `ConnectMachine::Credentials::password` [READ:include/rtsc/proto/connect_machine.h:98] | `std::string`，随 `ConnectMachine` 存活整个连接 |
| 2 | `ConnectMachine::credentials_`（成员拷贝）[READ:include/rtsc/proto/connect_machine.h:128] | 构造时按值拷贝 [READ:src/proto/connect_machine.cpp:119-120] |
| 3 | `credssp::Credentials::password` [READ:include/rtsc/credssp/credssp.h:26] | 另一份独立类型 |
| 4 | `CredsspClient::credentials_` [READ:include/rtsc/credssp/credssp.h:92] | 再拷贝一次（`std::move` 进去，但仍是独立对象） |
| 5 | `NtlmV2Inputs::password` [READ:src/credssp/credssp.cpp:172] | 第 3 步临时拷贝 |
| 6 | `PasswordCredentials::password` [READ:src/credssp/credssp.cpp:290] | 第 5 步再拷贝 |
| 7 | `crypto::Utf16Le(password)` [READ:src/credssp/ntlm.cpp:289] | UTF-16 中间缓冲 |
| 8 | `crypto::Utf16Le(password)` [READ:src/credssp/ts_request.cpp:382] | TSCredentials 编码时的又一份 |

**全仓零清零**：

```
[BASH: Select-String -Path F:\rtsc\src\*.cpp,F:\rtsc\src\*\*.cpp,F:\rtsc\include\*\*\*.h
       -Pattern "SecureZeroMemory|memset_s|ZeroMemory|explicit_bzero"]
→ （无输出）
```

#### 2.5.2 是否违反「同一数据必须同名 / 单一权威写者」（C9、D1）

**违反。** 三条独立证据：

1. **不同名（同名不同义）**：`ConnectMachine::Credentials::password` vs
   `credssp::Credentials::password` [READ:include/rtsc/proto/connect_machine.h:98 vs
   include/rtsc/credssp/credssp.h:26]。字段名恰好都叫 `password`，但**类型不同、
   语义不同**（一个是 Client Info 的 `TS_INFO_PACKET.Password`，一个是 CredSSP
   `TSPasswordCreds.password`），且**没有任何一处**声明「这两个必须是同一个值」。
   更糟的是两者**可能合法地不同**：NLA 场景下 Client Info 的 password 规范上应为空
   （见 §2.5.3），而 CredSSP 的必须非空——**同名不同义**，正是 C9 要防的形态。

2. **无单一权威写者**：`ConnectMachine` 的 `credentials_` 是 **const 构造后不可变**
   [READ:include/rtsc/proto/connect_machine.h:104]，
   `CredsspClient::credentials_` 也是构造后不可变 [READ:include/rtsc/credssp/credssp.h:42]。
   于是**编排层必须同时持有原始口令，并分别构造两个对象**——
   编排层成了事实上的「第 0 份」，而它没有任何类型约束保证两次构造用的是同一个值。
   调用方写 `ConnectMachine(cfg, {.password = a})` 和
   `CredsspClient({.password = b}, 6)` 时，编译器**不会**提示 `a != b`。

3. **无生命周期终点**：口令的每一份拷贝都活到对象析构，且析构时不清零
   （`std::string` 的 SSO 小字符串甚至可能留在栈上）。
   `NtlmV2Inputs`/`PasswordCredentials` 是栈上临时对象，
   离开作用域后内容仍在栈内存里。

#### 2.5.3 额外发现：NLA 下 Client Info 仍回填明文口令

```
[READ:src/proto/connect_machine.cpp:168]
168:  pdu.info.password = credentials_.password;
```

该行在 `SendChannelJoin()` 的「所有通道已 join」分支里，**不区分协商结果**。
而规范对 `TS_INFO_PACKET.Password` 的约束是
[READ:docs/spec/mcs-domain.md:1107]（`cbPassword` / `Password` 字段定义），
且 `INFO_AUTOLOGON` 才是「使用用户/域/密码自动登录」的开关
[READ:docs/spec/mcs-domain.md:1132]；`autologon` 默认 false
[READ:include/rtsc/proto/connect_machine.h:101]。

**推导**：HYBRID_EX 下用户已在 CredSSP 第 5 步通过 `TSCredentials` 认证，
Client Info 再带明文口令意味着
（a）同一凭据在**同一条 TLS 通道内被发送两次**（一次 SEAL 封装、一次明文），
（b）若服务器把它当作二次登录输入，可能触发一次**多余的登录尝试**（甚至锁定计数）。

**这条标为「推导，未实测」**——见 §6 未验证项 U-03。
但即便服务器忽略它，把口令多送一遍也没有任何收益，属于应删的暴露面。

#### 2.5.4 建议（具体到可执行）

| 建议 | 说明 |
|---|---|
| **S1 单一权威** | 引入 `struct rtsc::sec::UserCredential { std::string domain, user, password; }`，作为**唯一**口令载体。`ConnectMachine::Credentials` 与 `credssp::Credentials` 改为**引用/指针**或干脆从构造参数里移除，由编排层注入。 |
| **S2 同名同义或强制改名** | 若必须保留两份，把 Client Info 的那个改名为 `client_info_password`（并在注释里写「NLA 下应为空」），让「同名不同义」在类型层面不可能发生。 |
| **S3 NLA 下置空** | `SendChannelJoin()` 里按 `negotiated_protocol` 分支：非 `kProtocolRdp` 时 `pdu.info.password.clear()`，并置 `INFO_AUTOLOGON` 为 false。 |
| **S4 清零** | 为 `UserCredential` 提供析构清零（`SecureZeroMemory` / `volatile` 写），并把 `Utf16Le` 的中间缓冲也纳入（`crypto::Utf16Le` 目前返回 `Bytes`，调用方负责清）。 |
| **S5 不落日志** | 当前无日志系统，但 `Error::message` 会带上下文；接入后必须确保 `native_code`/`message` 不含口令。 |

---

### 2.6 关注点 6：缺陷清单

见 §4（单独成表，便于与甲交叉核对编号）。

---

## 3. 三个可行方案

三个方案共享同一套**前置修复**（否则都跑不通）：

| 前置 | 内容 | 依据 |
|---|---|---|
| P1 | `rtsc_tls` 平台守卫：`if(WIN32) ... else() add_library(rtsc_tls STATIC src/net/tls_stub.cpp)`；`tls_schannel.cpp` 加 `#ifdef _WIN32` 或整体移出非 Windows 构建 | §1.3、B19 |
| P2 | `CredsspClient` 补生产入口：`SetServerPublicKey()`（或构造参数）、`SetNonceFromCsprng()`（或注入 RNG） | B01、B02 |
| P3 | `CredsspClient` 补 `failed()` / `last_error()` / `Abort()` | B10、B11 |
| P4 | `TpktStream` 严格模式（或新增 `StrictTpktFramer`） | B05、B06 |
| P5 | `ConnectMachine` 补 `kAwaitEarlyUserAuth` + `OnEarlyUserAuthResult()` + `OnExternalSecurityFailed()` + `OnTransportClosed()` | B03、B04、B21 |

---

### 方案 A：编排层（`rtsc_session`）在协议层之上

**推导起点**

现有两个机器（`ConnectMachine`、`CredsspClient`）都是「喂字节 → 吐字节」的纯状态机，
`TlsTransport` 也是。三者形状一致，最自然的组合方式就是**再加一个同形状的编排器**，
把「谁该读、谁该写」的判断集中到一处。这个判断**本来就不属于任何一层**
（协议层不该知道 TLS 握手，TLS 层不该知道 MCS）。

**数据流**

```
socket ──recv──▶ TlsTransport::Handshake/Receive ──plaintext──▶
                     │                                          │
                     │  阶段 1: TLS 握手                        │
                     │  阶段 2: CredSSP 5 步 (Send/Receive)     │
                     │  阶段 3: EUAR 4B (Receive 精确读)        │
                     ▼                                          ▼
              ConnectMachine::OnData / OnEarlyUserAuthResult
                     │
                     └──output──▶ TlsTransport::Send ──ciphertext──▶ socket
```

**阶段机（编排层持有，5 个状态）**

```
kNegotiating → kTlsHandshake → kCredssp → kEarlyUserAuth → kRdpPdu
                    │              │            │
                    └──────────────┴────────────┴──▶ kFailed
```

**所有权**

| 资源 | 所有者 |
|---|---|
| `TlsTransport` | `rtsc_session::ConnectSession`（`unique_ptr`，**全程同一个实例**，`security-layer.md` 要求 CredSSP + EUAR 期间保持同一上下文 [READ:docs/spec/tls-backend.design-a.md:188]） |
| `CredsspClient` | 同上 |
| `ConnectMachine` | 同上 |
| TCP socket | **不归 session**（session 只收发字节，便于用内存管道测试） |
| 凭据 | 归调用方；session 只持有引用（配合 S1） |

**CMake 依赖图**

```
rtsc_session (新) -> rtsc_proto, rtsc_tls, rtsc_credssp
                      │           │        │
                   rtsc_crypto  secur32  rtsc_crypto
                                crypt32
```

无环证明见 §2.1.2。`rtsc_proto` 的 `target_link_libraries` **不变**。

**错误路径（逐阶段）**

| 阶段 | 错误源 | 处理 |
|---|---|---|
| kTlsHandshake | `Handshake()` 返回 `terminal()` | session → `ConnectMachine::OnExternalSecurityFailed()` → `kFailed`，并 `Shutdown()` 后关闭 socket |
| kCredssp | `OnServerResponse()` 返回 error（含 `native_code` = NTSTATUS） | 同上；**必须保留 `native_code`**（`credssp.h:31-34` 明确要求） |
| kCredssp | `TlsTransport::closed()` | 调 `CredsspClient::Abort()`（P3）→ `kFailed`，错误文案「对端在 CredSSP 第 N 步关闭连接」 |
| kEarlyUserAuth | 收到 `AUTHZ_ACCESS_DENIED` | `OnEarlyUserAuthResult()` → `kFailed`，**立即断连**，不发 MCS |
| kEarlyUserAuth | 4 字节之外还有数据 | 协议错误：`kFailed`（EUAR 后不允许有粘连） |
| kRdpPdu | 分帧器 `InvalidVersion` | `kFailed`，错误里带 `dropped=0` 保证（严格模式不丢字节） |

**可测性**

- **不需要 SChannel**：`TlsTransport` 是纯虚接口 [READ:include/rtsc/net/tls.h:124-188]，
  写一个 `ScriptedTls`（内存对）就能覆盖全部 5 个阶段。
  现有 `tests/test_tls.cpp:162-222` 的 `Loopback` 已证明「用真 SChannel 做端到端」可行，
  但单测不需要它。
- **不需要真实服务器**：`CredsspClient::MakeServerEchoForTest()` 已能产出合法的第 4 步
  [READ:include/rtsc/credssp/credssp.h:64]，可拼出完整五步。
- 关键用例（必须先红后绿）：
  1. `euar_denied_stops_before_mcs`
  2. `euar_split_across_two_receives`
  3. `euar_success_then_connect_initial_bytes_match_baseline`
  4. `tls_closed_during_credssp_step3_reports_step_number`
  5. `two_pdus_in_one_receive_are_both_consumed`
  6. `partial_pdu_is_buffered_not_dropped`

**缺点**

1. **调用方仍可能忘记调用钩子**——编排层虽然封装了，但 `ConnectMachine` 的
   `OnExternalSecurityComplete()` 依旧是 public，误用路径仍然存在（B04）。
2. **多一层缓冲**：session 要维护「TLS 明文残留」，而 `TlsTransport` 内部已有
   `rx_buffer_`。两层缓冲的排空顺序必须写清楚（先 drain TLS，再喂分帧器）。
3. `rtsc_session` 同时认识 proto 和 tls，是新的「知道太多」的目标；
   若将来要换 TLS 后端，改动面在这里而不是后端。
4. 跨平台性依赖 P1（`rtsc_tls` 守卫），否则整个 session 一起变 Windows-only。

---

### 方案 B：接口反转（`SecurityChannel` 抽象归 `rtsc_proto`，实现下沉）

**推导起点**

方案 A 的「调用方必须记得调钩子」是设计味道。既然 `ConnectMachine` 已经有
`kAwaitExternalSecurity` 这个「我要外部帮忙」的阶段，不如让它**自己**驱动外部——
但 `rtsc_proto` 不能依赖 `rtsc_tls`。解法是经典的依赖反转：
**抽象放在被依赖方，实现放在依赖方**。

**数据流**

```
ConnectMachine::Start()
   └─ output ─▶ caller ─▶ socket
socket ─▶ caller ─▶ ConnectMachine::OnData(raw)
                        │
                        ├─ 阶段 < kAwaitExternalSecurity: 自己解析
                        └─ 阶段 == kAwaitExternalSecurity:
                              channel_->Feed(raw)   // 纯虚，由 rtsc_security 实现
                                 │
                                 └─▶ StepResult{ output, needs_input, state }
```

**抽象（新增 `include/rtsc/proto/security_channel.h`，零依赖）**

```cpp
namespace rtsc::proto {
enum class SecState : uint8_t { kHandshaking, kNeedEuar, kReady, kFailed, kClosed };
struct SecStep {
    std::vector<uint8_t> output;   // 要写回 socket 的密文
    bool needs_input = false;
    SecState state = SecState::kHandshaking;
    std::string error;             // state == kFailed 时有效
    int32_t native_code = 0;       // TLS SECURITY_STATUS / CredSSP NTSTATUS
};
class SecurityChannel {
 public:
    virtual ~SecurityChannel() = default;
    virtual SecStep Start() = 0;                                   // 发 ClientHello
    virtual SecStep Feed(const uint8_t* data, size_t size) = 0;     // 收密文
    virtual SecStep SendPlain(const uint8_t* data, size_t size) = 0;// 发明文（MCS）
    virtual SecStep TakePlain() = 0;                                // 取明文（MCS 响应）
    virtual bool ready() const noexcept = 0;
    virtual bool closed() const noexcept = 0;
};
}
```

> 关键：这个头文件**不 include 任何 tls/credssp 头**，也不含平台类型。
> `rtsc_security` 用一个 `SchannelCredsspChannel : SecurityChannel` 实现它。

**所有权**

| 资源 | 所有者 |
|---|---|
| `SecurityChannel` 实例 | 调用方创建（`rtsc_security::CreateChannel(cfg, cred)`），`ConnectMachine` 只持 `SecurityChannel*`（**不拥有**） |
| `TlsTransport` / `CredsspClient` | 藏在 `SecurityChannel` 实现内部 |
| `ConnectMachine` | 调用方 |

生命周期规则必须写死：`ConnectMachine` 不得比 `SecurityChannel` 活得久
（建议 `ConnectMachine::SetSecurityChannel()` 里加断言，或改成 `std::shared_ptr` 弱引用）。

**CMake 依赖图**

```
rtsc_secapi (INTERFACE, 零依赖)
   ▲                    ▲
rtsc_proto          rtsc_security (新)
   │                    │
rtsc_crypto      rtsc_tls  rtsc_credssp
```

`rtsc_proto` 的链接行：`PUBLIC rtsc_crypto rtsc_secapi` —— **只增，且新增项零平台库**。
无环证明见 §2.1.2。

**错误路径**

| 情形 | 行为 |
|---|---|
| `Feed()` 返回 `SecState::kFailed` | `ConnectMachine` 直接 `Fail(step.error.c_str())` 并保留 `native_code`（需给 `ConnectState` 加 `int32_t native_code`） |
| `SecState::kClosed` | `Fail("security channel closed during handshake")`，**带阶段名** |
| `kNeedEuar` | 状态机进入 `kAwaitEarlyUserAuth`，由 `OnData` 读 4 字节（§2.2.3） |
| `kReady` | 自动 `SendConnectInitial()`，**不需要外部调钩子** |
| 握手完成后 `Feed()` 仍被调用 | 视为编程错误：断言 + `Fail` |

**可测性**

- **`rtsc_proto` 的单测可以完全脱离 SChannel**：写一个
  `FakeSecurityChannel`（脚本化状态迁移）放在 `tests/test_connect_machine.cpp`，
  就能测「kNeedEuar → 4 字节 → Connect Initial」的完整分支。
  这是本方案最大的测试优势：**EUAR 逻辑进入 `rtsc_proto` 的测试覆盖**，
  而方案 A 里它只能被测在 session 层。
- 但 `FakeSecurityChannel` 本身要能模拟 `SecState` 的全部 5 个值，
  测试矩阵比方案 A 多一维（状态 × 输入）。

**缺点**

1. **抽象泄漏**：`rtsc_proto` 的头文件里出现了「密文/明文」这种传输层概念，
   与「proto 只懂协议字节」的既有定位有张力
   （`connect_machine.h:16-21` 明确写「The machine is transport agnostic」）。
2. **两个读循环的诱惑**：`ConnectMachine` 在 `kAwaitExternalSecurity` 之后要同时
   管 channel 的明文和 MCS 的 PDU，边界容易写错（例如把 EUAR 又喂给 channel）。
3. **生命周期风险**：裸指针 + 非拥有，`ConnectMachine` 逃逸出作用域就是悬垂。
   需要 `shared_ptr` 或明确文档约束。
4. 新增一个 INTERFACE 目标，CMake 图多一个节点（虽然零成本）。

---

### 方案 C：门面组合（`rtsc_security` 完全不认识 `rtsc_proto`）

**推导起点**

`security-layer.md` 描述的外部安全是一个**自包含**的过程：TLS → CredSSP 五步 → EUAR。
它的输入是密文字节、输出是明文字节（外加 EUAR 这一个 4 字节特例），
**不需要知道 MCS 的任何结构**。既然如此，就把它做成一个和 `ConnectMachine`
**并列**的字节机器，再写一个极薄的 `ConnectSession` 把两台机器串起来。

**数据流**

```
        ┌──────────────── rtsc_security::SecurityHandshake ────────────────┐
socket ─▶ Start() / Feed(ciphertext) ─▶ output(ciphertext) ─▶ socket        │
        │            │                                                   │
        │            ├─ phase kTls        : TlsTransport::Handshake        │
        │            ├─ phase kCredssp    : TlsTransport::Send/Receive     │
        │            │                     + CredsspClient::Start/OnServer │
        │            ├─ phase kEuar       : TlsTransport::Receive 精确 4B  │
        │            └─ phase kStream     : 直通（明文进出）                │
        └────────────────────────────────┬────────────────────────────────┘
                                         │ plaintext
                              ┌──────────▼──────────┐
                              │ rtsc_session        │  ← 唯一的「知道两边」
                              │ StrictTpktFramer    │
                              │ ConnectMachine      │
                              └─────────────────────┘
```

**关键设计点**：`SecurityHandshake` 的公开 API **形状与 `ConnectMachine` 完全同构**：

```cpp
struct SecHandshakeStep {
    std::vector<uint8_t> output;   // 密文，写回 socket
    bool needs_input = false;
};
class SecurityHandshake {
 public:
    SecHandshakeStep Start();
    SecHandshakeStep OnData(const uint8_t* ciphertext, size_t size);
    bool ready() const;            // 握手 + CredSSP + EUAR 全部完成
    bool failed() const;
    const char* error() const;
    int32_t native_code() const;
    // 就绪后：
    SecHandshakeStep SendPlain(const uint8_t* pdu, size_t size);   // MCS PDU → 密文
    SecHandshakeStep TakePlain(std::vector<uint8_t>& plaintext);   // 密文 → MCS 明文
};
```

于是 `ConnectSession` 的循环几乎是机械的：

```
if (!sec.ready()) { 把密文喂 sec；把 sec.output 写 socket }
else              { 把 sec 的明文喂 framer → ConnectMachine；把 machine.output 喂 sec.SendPlain }
```

**所有权**

| 资源 | 所有者 |
|---|---|
| `TlsTransport` | `SecurityHandshake`（内部 `unique_ptr`，全程唯一实例） |
| `CredsspClient` | `SecurityHandshake` |
| 明文残留缓冲 | `SecurityHandshake`（**只有一处**，避免方案 A 的双层缓冲） |
| `ConnectMachine` | `ConnectSession` |
| 凭据 | 调用方 → `SecurityHandshake` 构造参数（配合 S1 的单一载体） |

**CMake 依赖图**

```
rtsc_security (新) -> rtsc_tls, rtsc_credssp, rtsc_crypto      ← 不认识 rtsc_proto
rtsc_session  (新) -> rtsc_security, rtsc_proto
```

无环证明：`rtsc_security` 与 `rtsc_proto` **无任何边**（并列），
唯一汇聚点是 `rtsc_session`，单汇聚点不可能成环。
`rtsc_proto` 的 `target_link_libraries` **零 diff**——这是三个方案里唯一做到的。

**错误路径**

| 阶段 | 错误 | 传播 |
|---|---|---|
| kTls | `terminal()` | `SecurityHandshake::failed()=true`，`error()` 含 `backend_name()` + `native_code` |
| kCredssp | `OnServerResponse` error | 同上，`native_code` = NTSTATUS（`STATUS_LOGON_FAILURE` 等可直接上报） |
| kCredssp | TLS `kClosed` | 内部直接 `Abort()`（P3），`error()` 写明「closed during CredSSP step N」 |
| kEuar | 4 字节 ≠ 0 | `failed()=true`，**且 `ready()` 永远保持 false**（不允许上层继续） |
| kStream | `Send` 失败 | `failed()=true`；上层据此断开 |
| 任意 | 重复 `Start()` | 断言 + `failed()` |

**可测性**

- `SecurityHandshake` **完全不需要 `rtsc_proto`**：单测可以只给密文字节，
  验证「五步 TSRequest 的字节序列 + EUAR 4 字节」。这与现有
  `tests/test_credssp_sm.cpp` 的风格一致（它已经是纯字节断言）。
- 需要 3 个测试替身：
  1. `ScriptedTls`（实现 `TlsTransport`，内存对）；
  2. 服务器侧 CredSSP 脚本（用 `MakeServerEchoForTest` + `ChallengeMessage` 拼）；
  3. `FakeSocket`（`std::vector` 双向队列）。
- 关键用例：
  1. `handshake_emits_five_tsrequests_in_order`
  2. `euar_denied_sets_failed_and_never_ready`
  3. `euar_split_two_feeds_still_reads_four_bytes`
  4. `tsrequest_split_across_feeds_is_buffered`（**这条现在必红**，见 B09）
  5. `tls_closed_mid_credssp_sets_error_with_step`
  6. `send_plain_after_ready_produces_ciphertext`

**缺点**

1. **EUAR 落在 `rtsc_security` 而不是 `rtsc_proto`**：从协议归属看，
   EUAR 是 `[MS-RDPBCGR]` 的 PDU，理论上属于 proto。放在 security 里的代价是
   `rtsc_proto` 的单测覆盖不到它（只能测到「ready 之后发 Connect Initial」）。
   —— 这是本方案最主要的架构让步，必须在文档里写清楚。
2. **`ConnectSession` 是新增的第三个概念**（security / framer / machine），
   调试时要跨三个对象定位问题。
3. `SecurityHandshake` 的 `kEuar` 阶段需要「精确读 4 字节」，
   而 `TlsTransport::Receive` 的 `max_out` 是**软阈值**
   [READ:include/rtsc/net/tls.h:152-156]，可能一次给出 >4 字节。
   必须自己截留余量并保证不丢（这正是它内部要维护明文残留缓冲的原因）。
4. 跨平台同样依赖 P1。

---

### 方案 D（**否决**）：把 `rtsc_tls`/`rtsc_credssp` 直接链进 `rtsc_proto`

**为什么看起来诱人**：`ConnectMachine` 可以直接持有 `TlsTransport`，
钩子变成内部调用，代码最短。

**为什么不成立**（硬证据）：

1. `rtsc_proto -> rtsc_tls` 会把 `src/net/tls_schannel.cpp` 拉进依赖闭包，
   而该 TU **无条件** `#include <windows.h>` [READ:src/net/tls_schannel.cpp:29-32]，
   且零条件编译（实测 `#if*` 计数 = 0）→ **Linux 上编译期失败**（§1.3）。
2. 即使把 TU 加上 `#ifdef _WIN32`，`rtsc_proto` 的依赖闭包里仍会出现
   `secur32`/`crypt32` 这类**平台库**（通过 `PUBLIC` 传递
   [READ:CMakeLists.txt:54]），违反「`rtsc_proto` 只增不依赖平台库」。
3. 与 `connect_machine.h:16-21` 的既有设计声明直接冲突：
   「The machine is transport agnostic ... Crypto (TLS, CredSSP, RC4) is deliberately outside」。

**结论**：否决。列在这里是为了让交叉审计能明确看到「这条被考虑过并有证据否决」。

---

### 方案对比表

| 维度 | A（编排层） | B（接口反转） | C（门面组合） |
|---|---|---|---|
| `rtsc_proto` 链接行改动 | 不变 | 只增零依赖 INTERFACE | **零 diff** |
| 新库数 | 1 | 2（1 INTERFACE + 1 STATIC） | 2 |
| 新增抽象概念 | 1（ConnectSession） | 1（SecurityChannel） | 2（SecurityHandshake + ConnectSession） |
| EUAR 归属 | `rtsc_proto` | `rtsc_proto` | `rtsc_security` |
| 调用方会忘记钩子？ | **会**（钩子仍 public） | 不会 | 不会 |
| 单测能否脱离 SChannel | 能 | 能 | 能 |
| 单测能否覆盖 EUAR 分支 | 能（在 session 层） | **能（在 proto 层）** | 只能在 security 层 |
| 缓冲层数 | 2（TLS + session） | 2（TLS + channel） | **1（security 内部）** |
| 跨平台 | 依赖 P1 | 依赖 P1 | 依赖 P1 |
| 与现有代码风格契合度 | 高（三个同形状字节机器） | 中（引入纯虚 + 裸指针） | **最高**（`SecurityHandshake` 与 `ConnectMachine` 同构） |
| 推荐度 | 中 | 高（若要让状态机自洽） | **最高（改动最可控）** |

**建议**：先做 **C**（proto 零 diff、缓冲单点、可独立验证安全层），
若后续发现「调用方忘记切阶段」的误用率高，再演进到 **B**（把 EUAR 收回 proto）。

---

## 4. 缺陷清单

> 影响等级：**阻断** = 接入必失败/不收敛；**高** = 会造成错误诊断或安全缺陷；
> **中** = 特定输入下出错；**低** = 契约/可读性问题。

| 编号 | 症状 | 证据 | 影响 | 建议 |
|---|---|---|---|---|
| **B01** | `CredsspClient` 生产路径**拿不到服务器公钥**，`pubKeyAuth = hash(空 SPK)`，真实服务器必拒第 3 步 | `credssp.h:60-61` 只有 `SetServerPublicKeyForTest`；`credssp.cpp:232` 用 `server_public_key_`（默认空）；红证 `p_credssp.exe` A2「plain == hash(SPK='', nonce=0x00*32) = 1」 | **阻断** | 加 `SetServerPublicKey(Bytes)`（非 ForTest），或改为构造参数；编排层在 TLS 握手完成后立即 `PeerSubjectPublicKey()` 注入 |
| **B02** | 生产 nonce 恒为 32 个 0，导出会话密钥全 0；全仓无 CSPRNG | `credssp.cpp:44-46`（`nonce_.assign(kNonceSize, 0)`）；`credssp.h:57-60` 注释称「production 总是覆盖」但无 API；红证 `p_credssp.exe` B1/B2；全仓 `BCryptGenRandom\|RtlGenRandom\|std::random` 检索 = 0 命中 | **高**（安全，不断连） | 加 `SetNonceFromCsprng()` 或注入 `std::function<Bytes(size_t)>`；在 `rtsc_crypto` 提供平台随机源（Windows: `BCryptGenRandom`，其它: `/dev/urandom`） |
| **B03** | HYBRID_EX 下 EUAR 无合法落点：走 `OnData` 被判 *malformed MCS Connect Response*，走 `TpktStream` 被静默吞掉 | `connect_machine.cpp:352-359`；`connect_machine.cpp:220-226`；`mcs.cpp:124-129`；红证 `p_connect.exe` A3 | **阻断** | **【§9.2 修订】** 由安全层 `kAwaitEuar` 恰取 4 字节消费（与甲 S2 合并为 M02）；~~新增 proto 阶段~~ 已撤回 |
| **B04** | 钩子无失败通道；重复调用静默返回空 `ConnectStep`（`needs_input=false`） | `connect_machine.cpp:352-357`；红证 `p_connect.exe` B2「out=0 needs_input=0 failed=0」 | 高 | 加 `OnExternalSecurityFailed(const char*)`；第二次调用 → `Fail` |
| **B05** | `TpktStream` 把 4 字节 EUAR 当垃圾**静默丢弃** | `framing.cpp:37-54`（`SkipToNextCandidate`）、`framing.cpp:61-68`；红证 `p_connect.exe` C1「dropped=4」 | **阻断** | 严格模式：非法首字节 → `InvalidVersion`，**不丢字节**（§2.3.3） |
| **B06** | `TpktStream::Next` 剥掉 4 字节 TPKT 头，输出**不能**喂 `OnData` | `framing.h:15-16`；`framing.cpp:86-88`；`connection_initiation.cpp:56`；红证 `p_framing.exe` B2 | **阻断** | 新增 `NextPdu()` 返回含头完整 PDU（§2.3.3 方案 3-i） |
| **B07** | 边界契约前后矛盾：协商阶段**静默丢弃**尾随字节，MCS 阶段**判死** | `connection_initiation.cpp:56-70`（只用 `tpkt.length`）vs `mcs.cpp:128`（`tpkt.length != size` → `InvalidLength`）；红证 `p_boundary.exe` A2/B2 | **阻断** | 统一为「一次只吃一个完整 PDU，剩余字节留给下一次」；`OnData` 增加 `size_t& consumed` 出参 |
| **B08** | TLS 明文流是多记录拼接，**没有任何上层分帧**；`Receive` 契约明确「一次可追加多条记录」 | `tls.h:146-147`、`tls.h:152-156`；`tls_schannel.cpp:332`（`plaintext.insert`）、`:241-342`（`for(;;)`） | **阻断** | 必须新增 TPKT 分帧层（§2.3.3），且放在 `rtsc_proto` |
| **B09** | TSRequest **半包=终态**、**粘包=终态**；仓库无 DER 长度分帧器 | `credssp.cpp:91-93`（`Decode` 失败即 `Fail`）；`ts_request.cpp:283`（`trailing bytes`）；红证 `p_partial.exe` A3/B2 | **阻断** | 在 `rtsc_security` 内加「DER 长度前缀分帧」：先读 `30 len`，凑齐再调 `OnServerResponse` |
| **B10** | `CredsspClient` 无 `failed()` / `last_error()` / `Abort()`，与 `TlsTransport` 不对称；`kClosed` 无落点 | `credssp.h:53-54`（只有 `complete`/`version`）、`credssp.h:75-81`（`kFailed` 私有）、`credssp.h:95`（`last_error_` 私有）vs `tls.h:186` | **阻断** | 补齐三个访问器 + `Abort()`，见 §2.4.2 |
| **B11** | `complete()` **非单调**：完成后收到任意字节 → `kFailed`，`complete()` 由 true 翻 false | `credssp.cpp:84-86` + `credssp.cpp:54`；红证 `p_credssp.exe` C2 | 高 | `kDone` 加锁存：后续错误不改 `step_`，另置 `post_done_error_` |
| **B12** | `SEC_I_RENEGOTIATE` 分支里 `ISC` 返回值**被丢弃**，真重协商不会被发现 | `tls_schannel.cpp:660`（返回值未接收）、`:662-664`（输出 token 直接 `Free`）、`:283-292` | 中 | `FeedExtraOnce` 返回 `Error`；仅 `NewSessionTicket(4)` 放行，其余 `Fail(kProtocolError)` |
| **B13** | `Shutdown()` 非 OK 时返回 `kOk` 但**不置 `closed_`**，`closed()` 说谎 | `tls_schannel.cpp:423-433`（433 行 `return kOk` 无 `closed_ = true`）、`:438` | 中 | 失败路径也置 `closed_ = true`（或引入 `shutdown_failed_` 并让 `closed()` 反映） |
| **B14** | `kClosed` 后 `Receive` 立即返回，**无法**履行「drain 到 `buffered_input()==0`」 | `tls.h:157-160`（契约）vs `tls_schannel.cpp:230`（早退）、`:439` | 低-中 | `closed_` 时先排空 `rx_buffer_` 再返回 `kClosed`；或改契约 |
| **B15** | `plaintext` 契约自相矛盾（append-only vs 失败必空），失败路径不清空调用方已填内容 | `tls.h:146-148`；`tls_schannel.cpp:250-251,276-281,305-310` | 低 | 改为「失败不追加，原内容不变」 |
| **B16** | 口令 ≥8 份拷贝、无单一权威写者、全仓**零清零** | `connect_machine.h:98,128`；`credssp.h:26,92`；`connect_machine.cpp:168`；`credssp.cpp:172,290`；`ntlm.cpp:289`；`ts_request.cpp:382`；清零检索 = 0 命中 | 高（安全） | S1~S5，见 §2.5.4 |
| **B17** | HYBRID_EX 下仍发 `CS_SEC.encryptionMethods = 0x1B`，且只有 `kProtocolRdp` 分支校验该字段 | `connect_machine.h:91`（默认 0x1B）；`connect_machine.cpp:155-161`（只判 `kProtocolRdp`）；红证 `p_connect.exe` E2「encryptionMethods=0x0000001B」 | 中（未实测服务器反应） | 非 `kProtocolRdp` 时置 0；见 U-02 |
| **B18** | NLA 下 `Client Info` 仍回填明文口令（同一凭据在 TLS 内发两遍） | `connect_machine.cpp:168`；`mcs-domain.md:1107`（`Password` 字段）、`:1132`（`INFO_AUTOLOGON`）；`connect_machine.h:101`（`autologon=false`） | 中（推导，未实测） | 非 `kProtocolRdp` 时 `pdu.info.password.clear()`；见 U-03 |
| **B19** | `rtsc_tls` **不是跨平台的**：唯一 TU 无条件 include `windows.h`，CMake 无条件编译 | `CMakeLists.txt:51-55`（`if(WIN32)` 只包链接）；`tls_schannel.cpp:29-32`；`tests/test_tls.cpp:20-23`；条件编译指令计数 = 0 | **阻断**（阻塞 A/B/C 的跨平台前提） | `if(WIN32) ... else() add_library(rtsc_tls STATIC src/net/tls_stub.cpp)`；测试目标同样加守卫 |
| **B20** | 五个库共用 `PUBLIC include`，分层约束**编译器/链接器都拦不住** | `CMakeLists.txt:35,40,43,52,116` | 中 | `verify.ps1` 加 grep 守卫：`src/proto/**` 禁止出现 `rtsc/net/tls.h`/`rtsc/credssp/`/`windows.h` |
| **B21** | `ConnectMachine` 无「传输关闭」入口；`kAwaitExternalSecurity` 下 `OnData` 用误导性诊断 | `connect_machine.cpp:220-226`（`"unexpected data while waiting for the external security handshake"`）；`connect_machine.h` 无 `OnTransportClosed` | 中 | 加 `OnTransportClosed(const char*)`，错误文案区分「关闭」与「协议违例」 |
| **B22** | ~~现有测试固化了错误语义，修 B03 必然要改测试~~ **【§9.2 作废】** | `tests/test_connect_machine.cpp:200-213` | ~~中~~ **不成立** | 定案不改 proto，测试无需改语义（合并编号 M31，按"自动消解"处理） |
| **B23** | `done()` 在**发送** Client Info 后即返回 true（名为 ack，实为 sent） | `connect_machine.h:119`；`connect_machine.cpp:176`（`phase = kAwaitClientInfoAck` 在 `SendChannelJoin` 里设置） | 低 | 改名 `client_info_sent()`，或补真正的 ack 阶段 |

**统计**：23 条。**阻断 9 条**（B01、B03、B05、B06、B07、B08、B09、B10、B19）；
**高 4 条**（B02、B04、B11、B16）；**中 7 条**（B12、B13、B17、B18、B20、B21、B22）；
**低 3 条**（B14 计低-中、B15、B23）。

按等级精确统计：

| 等级 | 条数 | 编号 |
|---|---:|---|
| 阻断 | 9 | B01 B03 B05 B06 B07 B08 B09 B10 B19 |
| 高 | 4 | B02 B04 B11 B16 |
| 中 | 7 | B12 B13 B17 B18 B20 B21 B22 |
| 低 | 3 | B14 B15 B23 |
| 合计 | **23** | |

---

## 5. 红证复现（可执行）

五个探针，全部只读产品代码，源码在 `F:\rtsc\.tmp\secprobe\`。

### 5.1 构建方式（MSVC，与产品库同 ABI）

```bat
call "<VS>\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /std:c++20 /W4 /permissive- /utf-8 /EHsc /MDd ^
   /I F:\rtsc\include ^
   /Fe:F:\rtsc\.tmp\secprobe\p_connect.exe /Fo:F:\rtsc\.tmp\secprobe\ ^
   F:\rtsc\.tmp\secprobe\p_connect.cpp ^
   F:\rtsc\build\verify\rtsc_proto.lib F:\rtsc\build\verify\rtsc_crypto.lib
```

> 注意 `/MDd`：`build\verify` 是 Debug 配置，用默认的 `/MT` 会触发
> `LNK2038 RuntimeLibrary 不匹配（MDd_DynamicDebug vs MT_StaticRelease）`
> —— 已实测踩到，记录在此避免复现者重复。

### 5.2 五个探针的实测输出

**p_connect.exe**（EUAR / 钩子 / TpktStream 吞字节 / Connect Initial 内容）

```
A1 phase after CCF          = await-external-security
A1 negotiated_protocol      = 0x00000008
A2 after hook: phase=await-connect-response out=404 bytes
A3 fed EUAR(denied): failed=1 phase=failed error='malformed MCS Connect Response'
A3 verdict: EUAR after the hook is misdiagnosed as a malformed MCS Connect Response
B1 first call:  phase=await-connect-response out=404 needs_input=1
B2 second call: phase=await-connect-response out=0 needs_input=0 failed=0
B2 verdict: misuse is silent (empty output, needs_input=false, no failure)
C1 Next=Ok payload=4 dropped=4
C2 verdict: the 4 EUAR bytes were dropped silently; AUTHZ_ACCESS_DENIED never reaches the caller
D1 half header -> NeedMoreData buffered=3
D2 rest       -> Ok payload=4 dropped=0
E1 Connect Initial parse=Ok size=404
E2 CS_SEC at offset 348: encryptionMethods=0x0000001B ext=0x00000000
E3 CS_CORE at offset 132, serverSelectedProtocol=0x00000008

red checks triggered: 3
EXIT=1
```

**p_credssp.exe**（公钥缺失 / nonce 全零 / complete 非单调）

```
A1 Start ok=1 step3 ok=1 step3=389 bytes
A2 pubKeyAuth plain=32 bytes, equals hash(SPK='', nonce=0x00*32) = 1
A2 verdict: with no production setter for the server public key, pubKeyAuth is a hash of an EMPTY key -> every real server rejects step 3
B1 clientNonce size=32 all-zero=1
B2 ExportedSessionKey size=16 all-zero=1
B2 verdict: no CSPRNG exists in the repo; the only nonce setter is SetNonceForTest, so the SEAL key is all zeros
C1 after step4: ok=1 complete=1
C2 after stray input: ok=0 complete=0 status=2
C2 verdict: a post-completion byte flips complete() true->false; there is no latch separating kDone from kFailed

red checks triggered: 3
EXIT=1
```

**p_boundary.exe**（两阶段边界契约不一致）

```
A1 CCF+extra(30 B in): failed=0 phase=await-connect-response out=404
A2 verdict: the trailing 11 bytes were accepted and silently discarded (X224ConnectionConfirm::parse uses tpkt.length only)
B1 MCS+1 byte: failed=1 phase=failed out=0 error='malformed MCS Connect Response'
B2 verdict: the SAME coalescing is fatal here (read_tpkt demands tpkt.length == size) -> two phases disagree on the boundary contract
C1 Next#1=Ok payload=15  Next#2=Ok payload=7 buffered=0

red checks triggered: 2
EXIT=1
```

**p_partial.exe**（TSRequest 半包 / 粘包）

```
A1 step-4 TSRequest is 59 bytes on the wire
A2 first half (29 B): ok=0 status=1 complete=0
A3 second half: ok=0 status=1 complete=0 out=0
A3 verdict: a half-delivered TSRequest is terminal (kFailed); the rest can never be processed -> handshake dead even though every byte eventually arrived
B1 two coalesced TSRequests: ok=0 status=2 msg='cannot decode TSRequest'
B2 verdict: coalescing two TSRequests is fatal ('trailing bytes'), so the driver MUST split DER messages itself - nothing in the repo does

red checks triggered: 2
EXIT=1
```

**p_framing.exe**（TpktStream 输出不能喂 OnData）

```
A1 raw TPKT(19 B): failed=0 phase=await-external-security
B1 TpktStream::Next=Ok payload=15 (header stripped)
B2 feeding that payload to OnData: failed=1 error='malformed X.224 Connection Confirm'
B2 verdict: TpktStream strips the 4-byte TPKT header but OnData parses it -> the two cannot be composed
EXIT=0
```

### 5.3 红证与缺陷的对应关系

| 探针 | 覆盖缺陷 |
|---|---|
| `p_connect.exe` | B03（A3）、B04（B2）、B05（C1）、B17（E2） |
| `p_credssp.exe` | B01（A2）、B02（B1/B2）、B11（C2） |
| `p_boundary.exe` | B07（A2/B2） |
| `p_partial.exe` | B09（A3/B2） |
| `p_framing.exe` | B06（B2） |

**未被红证覆盖的缺陷**（只靠代码索引）：B08、B10、B12、B13、B14、B15、B16、
B18、B19、B20、B21、B22、B23。其中 B19 有实测计数（条件编译指令 = 0）作为
准红证；B10 的「缺失」是纯结构事实（`grep` 不到即不存在），可直接复核。

---

## 6. 未验证项

> 以下**没有**证据，任何方案都不得把它们当作已成立的假设。

| 编号 | 未验证项 | 为什么重要 | 验证方法 |
|---|---|---|---|
| **U-01** | EUAR **真的**不带 TPKT（4 字节裸数据） | 决定**安全层 `kAwaitEuar`** 的实现形态（§9.2 定案后不再影响 proto）。`security-layer.md:1705` 自认「C 级推导，未抓到包验证」 | 拿到正确凭据后，在第 5 步 `authInfo` 发出后抓服务器→客户端第一个字节流，看是否以 `00 00 00 00` 开头且总长恰 4 |
| **U-02** | 真实服务器对 `CS_SEC.encryptionMethods = 0x1B` 的反应（B17） | 若服务器据此认为客户端要求 Standard RDP Security，可能拒绝或走错分支 | 同一抓包里看 Connect Initial 的 CS_SEC 块；或做 A/B：置 0 与 0x1B 各连一次 |
| **U-03** | NLA 下 Client Info 的 `Password` 是否**必须为空**（B18） | 决定是否删掉 `connect_machine.cpp:168` 的回填 | 抓 mstsc 在 HYBRID_EX 下的 Client Info，看 `cbPassword` 是否为 0 |
| **U-04** | 真实服务器在 TLS1.3 下是否发 `NewSessionTicket`、`Receive` 的丢弃路径是否正确（B12） | `impl-log.md:95`（I1）承认 TLS1.3 未覆盖；`evidence/tls/probes/` 里 probe34/probe39 只有 loopback 证据，且 `probe39.out.txt` **不存在**（实测 `Test-Path` = False） | 对 192.168.1.7 跑一次真 TLS1.3，抓 `DecryptMessage` 的 `SEC_I_RENEGOTIATE` + `EXTRA` |
| **U-05** | 服务器实际协商的 CredSSP 版本（我们固定发 6） | `credssp.cpp:42-43` 把版本钳到 [2,6]；若服务器要求 ≤4，pubKeyAuth 语义完全不同（raw key vs hash） | 抓服务器第 2 步 TSRequest 的 `version` 字段 |
| **U-06** | 服务器是否在收到第 5 步后**立即**发 EUAR（不等客户端） | 决定 session 的读循环能否「发完就阻塞等」 | 同一抓包看时序 |
| **U-07** | `kTofu` / `kStrict` 证书策略是否可用 | `impl-log.md` I3：只实测了 `kInsecure`，pin 未实现；`tls_schannel.cpp:135-147` 三个分支**都**走 `ISC_REQ_MANUAL_CRED_VALIDATION`，等价于「完全不校验证书链」 | 读 `tls_schannel.cpp:135-147` 可见三分支同构；需实测「错主机名/错 CA 是否被拒」 |
| **U-08** | `TlsTransport::Receive` 在 `max_out=4` 时是否真的只给 4 字节 | 方案 C 的 `kEuar` 阶段依赖「精确读 4 字节」；契约明确说 `max_out` 是软阈值 [READ:tls.h:152-156] | 用 `tests/test_tls.cpp` 的 `Loopback` 发 8 字节明文，`Receive(..., max_out=4)`，看返回长度 |
| **U-09** | `NtlmV2Inputs::timestamp` 为 0 时服务器是否接受 | `credssp.cpp:177` 在无 `MsvAvTimestamp` 时填 8 个 0；真实 AD 可能要求有效时间戳 | 抓真实服务器的 CHALLENGE 是否带 `MsvAvTimestamp` |
| **U-10** | 服务器在 `AUTHZ_ACCESS_DENIED` 后是否立即关 TCP | 决定客户端「读 EUAR 后是否还需要等 FIN」 | 用错误权限的账号实测 |
| **U-11** | 方案 A/B/C 的 CMake 图在本机 configure 通过 | 本文只做**文本推导 + 无环证明**，未实际 `add_subdirectory` 验证 | 在 `.tmp` 下建一个最小 CMake 工程，把三套图各 configure 一次 |
| **U-12** | `StrictTpktFramer` 与 `OnData` 的 `consumed` 出参改法对现有测试的影响面 | 改 `OnData` 签名会触及 `tests/test_connect_machine.cpp` 的 **63 处 `Feed()` 调用**（实测 `Feed(` 计数 63，`OnData(` 直接调用仅 1 处 [READ:tests/test_connect_machine.cpp:104]）；若保留旧签名转调新签名，则改动面收敛到 `Feed()` 这 1 个辅助函数 | 先加带 `consumed` 的重载，旧签名转调新签名，跑 `ctest -R connect_machine` |

---

## 7. 与审计甲（`ses_e9a488e95ffeRAGF2jsornJq1O`）的交叉核对清单

> **【已结案】** 本节 10 条锚点已在 **§9** 全部结案，保留仅作追溯。
> 最终裁决、合并缺陷表（32 条）、方案排序与最低条件均见 §9。

| 待核对项 | 我的结论 | 需要甲确认的点 |
|---|---|---|
| C-01 | 方案必须解决 `rtsc_proto` 不得依赖 `rtsc_tls` | 甲是否也把「`rtsc_tls` 无条件 include `windows.h`」当成前置阻塞（B19）？若甲的方案把安全层放在 proto 之上，是否也依赖 P1？ |
| C-02 | EUAR 应归 `rtsc_proto`（方案 A/B） | 甲若把 EUAR 放在安全层（同方案 C），是否给出了「proto 单测覆盖不到 EUAR」的补偿措施？ |
| C-03 | `TpktStream` 必须加严格模式，且输出含头 | 甲是否注意到「剥头 vs 要头」（B06）与「静默吞 EUAR」（B05）是两个独立缺陷？ |
| C-04 | `CredsspClient` 缺生产入口（B01/B02） | 甲是否把「`...ForTest` 是唯一 setter」识别为**能力缺口**而非「接线时补一行」？ |
| C-05 | `complete()` 非单调（B11） | 甲的状态机设计是否假定 `complete()` 单调？若是，则该假定已被红证推翻 |
| C-06 | 凭据 8 份拷贝 + 零清零（B16） | 甲的方案是否引入单一凭据载体？若否，是否至少给出了 NLA 下 Client Info 置空的处理？ |
| C-07 | 三阶段边界契约不一致（B07） | 甲是否提出 `OnData` 加 `consumed` 出参？若甲选了别的解法，两边必须收敛到同一种 |
| C-08 | `Shutdown()` / `kClosed` drain 缺陷（B13/B14） | 甲是否覆盖关闭路径？若甲的方案只讲「成功路径」，则需补 |
| C-09 | 方案 C 的「`max_out` 是软阈值」（U-08） | 甲若也做「精确读 4 字节」，必须同样处理「一次给多了」的截留 |
| C-10 | 23 条缺陷编号 | 甲的编号体系不同，合并时需建立映射表，避免同一缺陷被计两次或漏计 |

---

## 8. 附：本文档的证据自查

| 断言类型 | 数量 | 全部附证据？ |
|---|---:|---|
| 代码行引用 | 60+ | 是（`[READ:path:line]`） |
| 可执行红证 | 5 个探针 / 11 条触发 | 是（`[BASH:...]` + 完整输出） |
| 纯推导 | 4 条（B18、U-01、U-02、U-03 相关） | 是（明确标 `[推导]` / `[未验证]`） |
| 未验证项 | 12 条 | 是（§6 逐条给验证方法） |

**没有使用**「应该可以」「大概」「估计」这类无证据措辞作为结论；
凡无法证实的均进 §6。

---

*本文档由审计 AI（乙）生成，未修改任何产品代码。*
*写作期间唯一改动：`F:\rtsc\.tmp\secprobe\` 下新增 5 个一次性探针（不在构建图内）。*


## 9. 对甲报告的互审（第二轮 · 冲突裁决与合并表）

> 父代理要求编号为「§8」；本文档 §8 已被「证据自查」占用，故顺延为 §9，内容不变。
> 本节**取代** §7 的「待核对锚点」（那 10 条已在此全部结案）。
>
> **引用约定**：本节所有 `§X.Y` 未注明者指**本文档**章节；
> 指甲的报告时一律写作「甲 §X.Y」。代码引用写作 `文件:行`。
>
> **被审对象在持续增长（本节的引用基线必须记住）**
>
> | 时点 | `audit-a.md` | 新增内容 | 本节如何应对 |
> |---|---|---|---|
> | 我第一次拿到它 | 812 行 | §0–§10 | 第一轮互审（已作废，见 §9.2.3） |
> | 我写 §9 时 | **2052 行 / 168591 B** | §11 S10 实测、§12 交叉预判、§13 接口草案、§14 consumed 裁决、§15 修复清单 | §9.1–§9.10 全部按此版 |
> | 我完成 §9 后 | **2835 行 / 220964 B** | §16 实测、**§17 反向互审（逐条回应我的 §9）** | **§9.9**（新增） |
>
> **因此本节的引用分两类**：§9.1–§9.10 引用 2052 行版（行号在该版内稳定，
> 因为 §16/§17 是**追加**在文件末尾，不移动前面的行）；§9.9 引用 2835 行版。
> 甲引用我的文档时用的是 `audit-b.md:行号`，那些行号会随我本次修订漂移——
> 定案时以**本节 §9.9 的合并表**为准，不以行号为准。

### 9.0 互审方法

对甲的每一条缺陷都做了**反向验证**：不看甲的结论，先自己 grep/读码，再比对。
对甲的每一条「代码断言」都实际 `Select-String` 复核了行号。

**结论先说：**
- 甲的 24 条（S1–S24）里，我逐条复核后 **0 条与代码不符**（§9.6 列出 4 处：1 处文档内部不一致、2 处行号精度、1 处甲已自订正；**0 条结论性错误**）。
- 甲在我提交 §9 后做了**反向互审**（甲 §17），**确认了我全部 4 处指控与全部 6 条硬条件**，
  并新增 3 条缺陷（S22=我的 B13、S23、S24）。见 **§9.9**。
- 甲已**主动采纳**我的 B19（编为 S21）、B01（编为 S18）、B16/B18（编为 S20）。
- 甲**推翻了我两个判断**，且都成立：
  1. EUAR 必须留在安全层（我撤回 §2.2.3，见 §9.2）；
  2. `TpktStream` 不必加严格模式，用 `WrapTpkt` 还原即可（见 §9.7 末段）。
- 我**漏了甲 10 条、并把 1 条确定缺陷错降为「未验证项」**（§9.5，共 11 条）。

---

### 9.1 冲突 1：EUAR 归属（甲的方案 B vs 我的方案 C）

#### 9.1.1 裁决：**父代理的判断正确 —— 两者在 EUAR 归属上是同一个选择**

**确认**：甲的方案 B（`SecurityLayer::Step()` 内含 `kAwaitEuar`，从 `plain_` 恰取 4 字节
[READ:audit-a.md:146]、`:428-435`）与我的方案 C（`SecurityHandshake` 内部 `phase kEuar`）
**都把 EUAR 放在安全层**。分歧只在接口形状。

甲在 `:1059-1060` 把这一点明确成唯一结论，并且**逐条反驳了我的方案**：

```
[READ:audit-a.md:1062-1069]（以下为逐字摘录）
**理由 1（决定性）：EUAR 的字节边界只有安全层知道，所以安全层无论如何都要有这个阶段。**
「哪 4 个字节是 EUAR」取决于「CredSSP 最后一条消息在明文流的哪个字节结束」。
只有安全层持有 `plain_` 与 `phase_`（§3.1）。
所以即便采用乙的方案，安全层仍必须有一个 `kAwaitEuar` 阶段来**停在正确的偏移**，
再把那 4 字节**上抛**给 proto。
→ 乙的方案不是「把 EUAR 移到 proto」，而是「安全层算边界 + proto 做解释」，
即**两个对象都知道 EUAR 的存在**。这正好是我在 §3.1 论证要避免的 split-brain：
「谁决定消费几个字节」与「谁解释这几个字节」被拆开了。
```

**这个反驳成立，我接受。** 我原来的 §2.2.3 说「EUAR 归 proto」，
但 proto 拿到的那 4 字节必须是安全层从 `plain_` 里精确切出来的——
**边界权在安全层、解释权在 proto，正是 split-brain**。甲说得对。

甲还补了一条我没想到的反证（`:1071-1079`）：

```
[READ:audit-a.md:1071-1079]（以下为逐字摘录）
**理由 2：proto 的输入契约根本装不下 EUAR。**
`ConnectMachine::OnData` 要求**完整 TPKT 帧**：
`src/proto/connect_machine.cpp:196` → `src/proto/connection_initiation.cpp:55-58`；
MCS 侧 `src/proto/mcs.cpp:128`、`src/proto/mcs_domain.cpp:67` 都要求 `tpkt.length == size`。
4 字节 `00 00 00 00` 喂进去，`TpktHeader::parse` 在 `src/proto/tpkt.cpp:7` 就返回 `InvalidVersion`。
→ 乙必须新增**第二个输入入口** `OnEarlyUserAuthResult(uint32_t)`，
于是 `ConnectMachine` 有了两套不同分帧规则的输入 API，
调用方必须自己判断「现在该调哪个」—— 这正是方案 A 被我列为缺点、方案 B 用 `Want` 消除的问题，
只是被下推到了 proto 层。
```

这条也对。我原本把「新增第二个入口」当成「最小改动」，
实际上它是**把方案 A 的缺点复制到 proto 层**。**我的 §2.2.3 整节作废。**

#### 9.1.2 实质差异（不是"同一个东西"，但差异在别处）

| 维度 | 甲的方案 B | 我的方案 C |
|---|---|---|
| EUAR 归属 | 安全层 | 安全层（**同**） |
| TPKT 分帧归属 | **安全层**（用 `TpktStream`，`:311` 依赖 `rtsc_proto`） | **session 层**（安全层不认识 proto） |
| 接口形状 | 单入口 `Step(Input)` + `Want` 枚举 [READ:audit-a.md:196-204] | `Start/OnData/SendPlain/TakePlain` 四方法，与 `ConnectMachine` 同构 |
| 错误类型 | `SecurityError{kind, stage, native_space, native_code, detail}` [READ:audit-a.md:578-584] | `failed()/error()/native_code()` 三访问器 |
| 明文缓冲所有权 | 安全层（`plain_`） | 安全层（`plain_`）（**同**） |

**所以真正的分歧是「TPKT 分帧在安全层内还是外」，不是「EUAR 在里还是外」。**

#### 9.1.3 可测性与错误传播的实质差异（含具体反例）

**差异 1：原子性断言 —— 甲能写、我不能写**

甲的 `Output` 同时含 `to_wire`、`pdus`、`euar` [READ:audit-a.md:197-203]，
因此下面这条测试在甲的设计里是**一句话**：

```cpp
// 断言「EUAR 的判定」与「首帧 PDU 的产出」来自同一次喂入
auto out = layer.Step({kCiphertext, euar_and_connect_response});
CHECK(out.euar.has_value());
CHECK(out.euar->authorized == true);
CHECK(out.pdus.size() == 1);          // 同一次 Step 里两件事都发生了
```

我的方案 C 里 `OnData` 只返回密文，明文必须再调 `TakePlain` 取，
于是只能写成「`OnData` 后紧接着 `TakePlain` 非空」——**等价但更弱**：
它证明不了两者来自同一次喂入（中间可能插了别的调用）。

**差异 2：重复启动检测 —— 我能写、甲不能写**

我的 `Start()` 是独立方法，调两次可以明确报错。
甲的 `Step({kNone})` **同时承担「启动」和「写出后继续 pump」两种语义**
（`:221` 示例里 `Step({kNone}) -> want=kRead` 既是首调也是后续调），
所以「重复 Start」在甲的接口里**不可表达**——只能靠内部状态额外区分。

这不是致命的，但它说明：**单入口换来了原子性，代价是把「意图」也压进了状态**。
真实权衡，不是谁更"正确"。→ 已列为我对方案 B 的**接受条件 C3**（§9.8）。

**差异 3：错误传播 —— 甲明显更好，我应当采纳**

甲的 `SecurityError` 解决了三个库 `native_code` 同名字段互相覆盖的问题
（`:542-550` 论证：`0x80090308` 既是 SSPI 的 `SEC_E_INVALID_TOKEN`
也可能是 CredSSP 的 NTSTATUS）。我的 `native_code()` 单值设计**无法表达这个区分**。
→ **采纳甲的设计**，我的方案 C 应改为返回 `SecurityError`。

> **更正（甲 §17.2.1 提出，我接受）**：我写「四元组」不准确——甲的结构是
> **5 个字段**（`kind` / `stage` / `native_space` / `native_code` / `detail`），
> 我把 `kind` 当成了「类型」而不是「成员」。另外我把字段名记作 `native_space`，
> 甲原草案写的是 `space`；**甲反而采纳了我的 `native_space` 命名**（与 `native_code` 成对）。
> 这不是「我的设计更好」，只是命名更自解释。

#### 9.1.4 裁决结论

1. EUAR 归属：**安全层**（甲对，我撤回 proto 方案）。
2. 接口形状：两者都可接受；**甲的单入口在"原子性测试"上更强**，
   我的四方法在"意图显式化"上更强。**不构成定案阻塞**（但见接受条件 C3）。
3. 错误类型：**用甲的 `SecurityError`**。
4. 真正的架构分歧是 **TPKT 分帧放哪**：甲放安全层（`:311`），我放 session。
   甲的 §3.1 论证支持放里面（缓冲区唯一），且甲在 `:1105-1106` 给出了
   「`plain_` 已 `remove_prefix(4)`，`TpktStream` 永远看不到那 4 字节，
   `dropped_bytes()` 恒为 0」的具体机制——**这消除了我担心的"吞 EUAR"**。
   **两者都成立，甲的更省一个对象。**

---

### 9.2 冲突 2：`OnExternalSecurityComplete()` 要不要改签名

#### 9.2.1 甲的最终立场（已从"签名不够"改为"成功路径不缺"）

父代理转述的「无输入、不返回还要读几字节」是甲**早期 relay 里的口头结论**，
甲在最新版里**已自行修正**：

```
[READ:audit-a.md:964-964]（以下为逐字摘录）
乙认为它「无输入、不返回还要读几字节」是缺口。**我的判断：成功路径上不是缺口；失败路径上确实缺一个入口。**
```

甲给了三段论证明「成功路径不缺」（`:968-978`）：

```
[READ:audit-a.md:968-978]（以下为逐字摘录）
> **调用 `OnExternalSecurityComplete()` 的那一刻，安全层的明文缓冲必然为空。**

证明（三段，全部有据）：
1. CredSSP 第 5 步是**客户端发出的最后一条** CredSSP 消息（`docs/spec/security-layer.md:675`），
   发出前第 4 步的完整 TSRequest 已被消费（`src/credssp/credssp.cpp:252-307`）。
2. EUAR 是服务器紧接着发的**唯一**内容，且 `MUST be sent before any post-handshake PDUs`
   （`docs/spec/security-layer.md:365-366`、`:369-370`）—— 已被 `kAwaitEuar` 恰取 4 字节。
3. 其后的 `MCS Connect Response` **必须**等客户端先发 `MCS Connect Initial`
   （`docs/spec/security-layer.md:290-291` 的箭头方向）。服务器不可能抢跑。

∴ 交还控制权时 `plain_` 为空，**没有任何字节需要交接**。签名无输入是**正确的最小接口**，不是缺口。
```

**这个证明我复核后成立**（关键前提「EUAR 是唯一 post-handshake 数据」有
`security-layer.md:365-366` 的 MUST 支撑）。**我原来说"签名不够"是错的。**

#### 9.2.2 裁决：**不改签名，也不加阶段；但补一个失败入口**

**唯一结论**：EUAR 在安全层消费 → `rtsc_proto` 对 EUAR **完全无感** →
`connect_machine.h` 的**函数签名零改动**。

但甲同时指出失败路径确实缺一个入口（`:980-987`）：

```
[READ:audit-a.md:980-985]（以下为逐字摘录）
**真正缺的是失败入口**：现在安全层失败后，`ConnectMachine` 只能被丢弃，
`state_.error` 永远是空的（`include/rtsc/proto/connect_machine.h:57` 只在 `Fail()` 里写，
而 `Fail()` 只有 `OnData` 路径会调）。这与我的 S12（错误阶段静默 no-op）是同一处病灶。

**建议（P2，不阻塞）**：加一个 `void OnExternalSecurityFailed(const char* reason)`，
只做 `Fail(reason)`；或者接受「丢弃对象」的语义，但必须在 `connect_machine.h` 注释里写明。
```

**裁决**：采纳甲的分层——
- **`OnExternalSecurityComplete()` 签名不动**（成功路径）；
- **新增 `OnExternalSecurityFailed(const char*)`**（失败路径，P2，可选但推荐）。

这与甲 `:984-987` 的结论一致，也与我的 B04 后半一致。**两边已收敛。**

#### 9.2.3 我撤回的内容

| 位置 | 原内容 | 处置 |
|---|---|---|
| §0 结论表第 2 行 | 「最小改动 = 新增两个成员 + 一个新阶段」 | **作废** |
| §2.2.3 全节 | `kAwaitEarlyUserAuth` + `OnEarlyUserAuthResult` + 行为约定表 | **作废**（整节已标记撤回） |
| §3 方案 A 的「阶段机」 | 含 `kEarlyUserAuth` 状态 | 保留（那是 **session 自己的**阶段机，不是 proto 的 `ConnectPhase`） |
| §3 方案 B 的 `SecState::kNeedEuar` | 同上 | 保留（安全层自己的状态） |
| B03 | 「新增 `kAwaitEarlyUserAuth`」 | **改为**「安全层消费 EUAR + `WrapTpkt` 还原」，与甲 S2/S3 合并 |
| B22 | 「HYBRID_EX 用例改为 `kAwaitEarlyUserAuth`」 | **作废**（不改 proto，测试无需改语义） |
| §6 U-01 | 「决定 §2.2.3 的实现形态」 | 改为「决定安全层 `kAwaitEuar` 的实现形态」 |

---

### 9.3 冲突 3：甲未提 B19（跨平台编译期阻塞）

#### 9.3.1 裁决：**甲已采纳并给出完整修复方案；B19 阻塞成立，但甲已不再被它阻塞**

**甲第一版确实完全没提**（我第一轮互审时的核对：`windows.h` 0 命中、`_WIN32` 0 命中）。
但甲在 §11 之后**主动复核并确认了我的结论**：

```
[READ:audit-a.md:892-893]（以下为逐字摘录）
**先承认我第一版的遗漏**：我在 §5.1 只论证了「`rtsc_proto` 不应依赖 `rtsc_tls`」这个**方向**，
却**没有检查 `rtsc_tls` 自己能不能在 Linux 上编译**。乙的 B19 是对的，我复核如下：
```

**并且甲给了比我更完整的修复方案**（`:912-935`，三层拆分）：

```cmake
add_library(rtsc_tls_api INTERFACE)
target_include_directories(rtsc_tls_api INTERFACE include)

if(WIN32)
    add_library(rtsc_tls_schannel STATIC src/net/tls_schannel.cpp)
    target_link_libraries(rtsc_tls_schannel PUBLIC rtsc_tls_api secur32 crypt32)
endif()

add_library(rtsc_tls STATIC src/net/tls_factory.cpp)   # 门面：CreateTlsTransport
target_link_libraries(rtsc_tls PUBLIC rtsc_tls_api)
if(WIN32)
    target_link_libraries(rtsc_tls PUBLIC rtsc_tls_schannel)
else()
    target_link_libraries(rtsc_tls PUBLIC rtsc_tls_unavailable)  # 返回 nullptr + reason
endif()

add_library(rtsc_security STATIC src/sec/security_layer.cpp src/sec/random.cpp)
target_link_libraries(rtsc_security PUBLIC rtsc_tls rtsc_credssp rtsc_proto)
```

**这个方案比我的 P1 更好，我采纳。** 差异：

| 维度 | 我的 P1 | 甲的 §12.1 三层拆分 |
|---|---|---|
| 非 Windows 行为 | `add_library(rtsc_tls STATIC src/net/tls_stub.cpp)` | 门面 + `rtsc_tls_unavailable`，`Create()` 返回 `kUnsupported` |
| 是否加 `#ifdef` | 「加 `#ifdef _WIN32` 或整体移出」 | **明确不加 `#ifdef`**，理由是「会造出空 TU 静态库这种隐性失败」（`:957-960`） |
| 接口头隔离 | 未提 | 抽出 `rtsc_tls_api` INTERFACE，**从结构上保证**头文件平台中立 |
| 无环证明 | 有 | 有（`:937-948`） |

甲的理由「`#ifdef` 会造出空 TU 静态库这种隐性失败」是对的——
空的 `.cpp` 编译成 `.lib` 后链接成功但符号缺失，错误延迟到链接期且难归因。
**我接受甲的方案，我的 P1 降为"甲方案的简化版"。**

#### 9.3.2 甲第一版的那句错误论断（已由甲自己订正）

我第一轮抓到的是 `:654-655`：

```
[READ:audit-a.md:654-655]（以下为逐字摘录）
**这一级的价值**：可以在**没有任何 SSPI** 的环境（Linux/Android 构建）跑完整的安全层测试，
与 `rtsc_credssp` 的「平台无关」定位一致（`CMakeLists.txt:109`）。
```

**这句话在甲最新版里仍然存在**（行号未变），但甲在 `:1036-1037` 加了限定：

```
[READ:audit-a.md:1036-1037]（以下为逐字摘录）
- Linux 上 `rtsc_security` 也能编译，`Create()` 返回 `kUnsupported`（运行期不可用，非编译失败）——
  前提是先修 B19（§12.1 的三层拆分）。
```

→ **原文的绝对断言（"可以跑"）与限定后的正确表述（"修 B19 后才能跑"）并存于同一文档**。
这是**文档内部不一致**，不是事实错误（因为甲已补了前提）。建议执行时以 `:1036-1037` 为准，
并把 `:654-655` 改为「修 B19 后可以在无 SSPI 环境跑」。

#### 9.3.3 B19 对方案 B 的阻塞是否解除

**解除。** 因为：
1. 甲明确把 `SecurityLayer` 放 `rtsc_security`（`:311`、`:1031`），**不进 `rtsc_proto`**；
2. 甲给出三层拆分（`:912-935`），非 Windows 上门面返回 `kUnsupported` 而非编译失败；
3. `rtsc_proto` 的出边保持只有 `rtsc_crypto`（`:945`），我复核 `CMakeLists.txt:36` 确认。

**但有一个执行顺序约束**：B19/S21 必须在 `rtsc_security` 建立**之前**完成，
否则新库一建就编不过 Linux。甲自己也说「建议最先做」（`:1842`、`:1853` 批 0）。

---

### 9.4 冲突 4：甲的 S10 vs 我的 B04

#### 9.4.1 裁决：**不是同一个问题，不能合并**

| | 甲的 S10 | 我的 B04 |
|---|---|---|
| 层 | TLS 握手消费量记账 | `ConnectMachine` 钩子语义 |
| 症状 | `Handshake` 的 `consumed` 在「握手记录+应用记录合段」时多报 | 错误阶段调用静默 no-op；无失败通道 |
| 证据 | `tls_schannel.cpp:167`（`consumed = in_size`） | `connect_machine.cpp:352-357` |
| 后果 | 服务器若把 `Finished` 与 CredSSP step2 合并发送 → 那部分字节丢失 → 客户端死等 step2 | 调用方误判「结束了」→ 静默卡死 |
| 甲的最终定级 | **P2**（真实 RDP 时序下不可达，见 `:863`、`:1880`） | P2 |

两者在**代码位置、失败模式、修复点**上都没有交集。**不合并。**

#### 9.4.2 我的 B04 应合并到甲的 S12

**合并到 S12**（同一个 `connect_machine.cpp:352-357` 的 no-op）。已在 §9.2.2 确认。

#### 9.4.3 S10 已被甲实测裁决（我必须更新）

甲跑了 8 组 SChannel 探针（`:845-855`），给出**关键实测**：

```
[READ:audit-a.md:846-850]（以下为逐字摘录）
| **M3** | `Handshake(combined 98B)`（=51B Finished + 47B app） | `status=kOk(0), consumed=98/98, handshake_complete=1, out=0` → **消费量多报 47 字节** | `probe_s10.out.txt` |
| **M4** | 紧接 M3 调 `Receive(nullptr,0)`（履行 `tls.h:157` 的排空义务） | `status=kNeedMoreInput(1), plaintext=0, buffered_input=0` → **传输层自己一个字节也没留** | `probe_s10.out.txt` |
| **M8** | 同上，循环 8 轮排空 | `total recovered = 0 bytes` → **app data LOST** | `probe_s10b.out.txt` |
| **M1** | 裸 SSPI：`ISC(combined 98B)` 后读 `in_bufs[0].cbBuffer` | `0x00000000`；`cbBuffer: before=98 after=98`（**不变**）→ **SSPI 不报 EXTRA** | `probe_s10.out.txt` |
| **M2** | 裸 SSPI：对同一上下文的 47B 尾部单独 `DecryptMessage` | `0x00000000`, 18 字节, `match=1` → **尾部从未被 ISC 处理过**，仍是原始密文 | `probe_s10.out.txt` |
```

**这组实测比我第一轮引用的"待测"强得多**，且甲的结论（`:825-832`）是：

> 暗示 SChannel 会**报告** `SECBUFFER_EXTRA` 而我们没读。实测证明：
> **SChannel 在流式（`ISC_REQ_STREAM`）模式下根本不报告 EXTRA，也不校验尾随字节。**
> 它把 `Finished` 之后的字节**静默丢弃**（更准确地说：静默忽略、不消费、不报错、不回吐）。
> 于是 `consumed = in_size`（`src/net/tls_schannel.cpp:167`）**多报了**消费量，
> 调用方按契约丢掉尾部 → 应用数据永久丢失。

**并且甲发现了我没发现的一层**：`tls.h:129-132` 的接口注释
`consumed = in_size - sum(EXTRA.cbBuffer)` **在合段场景下本身失效**
（`sum(EXTRA)==0` → 退化为 `in_size`）。甲在 `:1599` 明确订正了自己：

```
[READ:audit-a.md:1599-1599]（以下为逐字摘录）
| 「读 `in_bufs[0].cbBuffer` 算真实消费量」这个修法 | 主代理指出：`in_size - Σ(EXTRA) = in_size - 0 = in_size`，**算术修正救不了** | **订正**：`design-a.md:513` 的算术修正（对应 `include/rtsc/net/tls.h:129-132` 的接口注释）在这个场景下**必然失效**。这不是「实现没按设计做」，而是**设计本身在此场景无效**。我 §11.1 说「读 cbBuffer 毫无用处」方向对，但没点明「接口注释 `tls.h:129-132` 给出的唯一正确公式也是错的」 |
```

**这是甲的一个真实贡献，我第一轮没看到这一层。** 我的 §9.4.3（第一轮版）说
「实现违反了自家接口契约，严重度应升为 P1 确定」——**这个判断是错的**：
不是实现违反契约，而是**契约本身错了**。必须改契约（甲 `:1631-1652` 给了替换文本）。

#### 9.4.4 我漏了 S10 —— 承认，并接受甲的四组红证

我的 23 条里**没有任何一条**覆盖 `Handshake` 的 `consumed` 记账。逐条核对：
- B12 是 `SEC_I_RENEGOTIATE` 分支里 `ISC` 返回值丢弃（`:660`），**不是** `consumed`；
- B14 是 `kClosed` 后无法 drain，**不是**握手消费量；
- 其余均不相关。

**这是一条真实遗漏，接受甲的 S10 作为合并缺陷（M12）。**

我复核了甲的核心证据，成立：

```
[BASH: Select-String -Path src\net\tls_schannel.cpp -Pattern "in_bufs"]
114: SecBuffer in_bufs[1]{};
123:     in_bufs[0].BufferType = SECBUFFER_TOKEN;
124:     in_bufs[0].cbBuffer = static_cast<unsigned long>(token.size());
125:     in_bufs[0].pvBuffer = token.data();
128:     in_desc.pBuffers = in_bufs;
→ :124 之后再无读取，:167 直接 consumed = in_size。
```

**严重度我接受甲的 P2（不是 P1）**：因为真实 RDP 时序下服务器不会在 `Finished` 后
立刻发应用数据（甲 `:859-861` 引 `security-layer.md:280-281`：
客户端先发 step1，服务器才回 step2）。我第一轮定 P1 是**高估了**。

但甲 `:1600` 的补充我同意：**必须修**，因为它是 EUAR 边界正确性的前提
（D1 预切片 = 精确知道握手在哪字节结束）。

---

### 9.5 自查：我漏掉了甲的哪些（诚实清单）

**结论：甲 21 条里，我完全遗漏 10 条（S5/S6/S7/S10/S11/S13/S14/S15/S16/S19），
另把 1 条确定缺陷错降为「未验证项」（S8 → 我的 U-07）。合计 11 条。**

| 甲编号 | 内容 | 我的状态 | 复核结果 |
|---|---|---|---|
| S5 | 服务端 `TSRequest.version` 从不校验 | **完全遗漏** | 成立。`credssp.cpp:91-113` 只查 `has_error_code`，无 `req.version` 校验 |
| S6 | 服务端版本不回写 `version_` | **完全遗漏** | 成立。grep `version_ =` 只有 `:42-43`（构造钳制）；`req.version = version_` 在 `:72/:241/:300`，无反向赋值 |
| S7 | `kPeerAlert` 从不产生 | **完全遗漏** | 成立。`src/net/tls_schannel.cpp` 全文 `kPeerAlert` = **0 命中**；`tls.h:42` 有声明 |
| S8 | `kStrict`/`kTofu` 未实现、pin 零使用 | **降级为「未验证 U-07」** | **分类错误**。`pin_is_set`/`pinned_spki_sha256` 全仓仅 `tls.h:104-105` 两处定义，**零使用**；三分支代码同构（`:137/:142/:145`）。确定缺陷，不是未验证项 |
| S10 | `Handshake` 无条件 `consumed = in_size` | **完全遗漏** | 成立（见 §9.4.4）；且甲实测出「契约本身失效」这一层，比我原判断深 |
| S11 | 第 4 步签名不校验 | **完全遗漏** | 成立。`credssp.cpp:347-362` `OpenReceive` 只解密 + `++recv_seq_`，无 HMAC 比对 |
| S13 | `OnData` 一进二出（Erect + Attach） | **完全遗漏** | 成立。`connect_machine.cpp:268-269` 两次 `Append` |
| S14 | `state_.error` 是 `std::string` 无错误码 | **完全遗漏** | 成立。`connect_machine.h:57` |
| S15 | 仓库无 socket 驱动 | **完全遗漏** | 成立（对 `src/**`）。`src/**` 无真实网络调用；`tools/rtsc_probe/main.cpp:164-226` 有 |
| S16 | `Send` 可能把一条 TSRequest 拆成多 record | **完全遗漏** | 成立。`tls_schannel.cpp:215-222` 按 `MaxChunk()` 循环切 |
| S19 | `min_version=0x0304` 时 `AcquireCredentialsHandle` 失败（0x80090331） | **完全遗漏** | 成立。`tls_schannel.cpp:467-472` `ProtocolMask()`；甲有实测 `tls13check2.exe` |

**归因分析（给下一轮审计的启示）：**

我的 23 条集中在**接入路径**（EUAR/framing/依赖图/凭据生命周期），
甲的 21 条集中在**既有实现的内部正确性**（TLS 后端消费记账、CredSSP 版本/签名、
proto 的错误模型）。两类互补性很强：

- 我漏/降级的 11 条里，**8 条在 `rtsc_tls`/`rtsc_credssp` 的内部实现**
  （S5/S6/S7/S8/S10/S11/S16/S19）+ **2 条在 proto**（S13/S14）+ **1 条工程缺口**（S15）。
  原因：我把这两个库当作「已完成、已验证（26 tests / 139 checks、23/27/15 tests）」
  的黑盒，只检查它们的**接口能否被接入**，没有逐行走实现。
  **这是我的方法论缺陷**：测试通过 ≠ 契约兑现（S7/S8 正是"声明了但没实现"）。
- 反过来，甲第一版（S1–S17）只覆盖了我 23 条中的 8 条（B02 B03 B05 B06 B09 B11 B14 + B04 的一半），其余 15 条未提。
  其中 **4 条是接入路径的硬阻断**
  （B01 公钥 setter、B16 凭据、B17 encryptionMethods、B18 ClientInfo 口令）
  + **B19 跨平台** + B07 边界契约。
  原因：甲以「`SecurityLayer` 在中间」为前提做自上而下设计，
  没有反向问「安全层要用到的每个输入，现有 API 给不给得了」——
  B01 就是这一问的答案：**给不了**。

**甲已承认这一点**（`:1049-1055`）：

```
[READ:audit-a.md:1049-1055]（以下为逐字摘录）
**为什么漏**：我检查了 `CredsspClient` 内部对 `server_public_key_` 的**使用**
（`src/credssp/credssp.cpp:232`、`:267`、`:369`），
也在 §5.6 的可测性里写了「假传输返回固定 SPKI」，
但**没有反向检查「谁在生产路径上写它」**。这是一次真实的审计疏漏，不是范围问题——
它就在「接入」的正中心：安全层必须把 `tls.PeerSubjectPublicKey()` 接到
`CredsspClient::SetServerPublicKey()` 上，而后者目前**只以 `ForTest` 形式存在**。
把它说成「范围之外」是不诚实的；正确说法是**我漏了**。
```

---

### 9.6 甲的事实错误（逐条，附证据）

> 我按要求「不为和睦而放过」。共 4 处：**1 处文档内部不一致 + 3 处引用精度**。
> **0 处结论性错误**（甲的 21 条缺陷我全部复核成立）。

| # | 位置 | 甲的说法 | 实际 | 性质 |
|---|---|---|---|---|
| A-E1 | `audit-a.md:654-655` vs `:1036-1037` | 前者说「可以在没有任何 SSPI 的环境（Linux/Android 构建）跑完整的安全层测试」；后者说「前提是先修 B19」 | 两句**并存于同一文档**，前者是无限定断言 | **文档内部不一致**。建议以 `:1036-1037` 为准，改写 `:654-655` |
| A-E2 | `audit-a.md:724`（S9 证据列） | 原文：`src/net/tls_schannel.cpp:429`（Shutdown 置 `closed_`） | `:429` 是 `if (st == SEC_E_OK \|\| st == SEC_I_CONTINUE_NEEDED)`；赋值在 `:430`；且**失败路径不置**（`:433` 直接 `return kOk`） | 精度问题。S9 结论不变，但漏了互补缺陷（我的 B13） |
| A-E3 | `audit-a.md:64` | 引 `include/rtsc/net/tls.h:142` 作为「Receive 是 append-only」的证据 | `:142` 是分节注释 `// ---- receive application data ----`；真正的句子在 `:146-147` | 引用漂移（指向节标题），不影响结论 |
| A-E4 | `audit-a.md:1739-1740` | 原文 `:1739`「P1 × 8（S5/S6/S7/S8/S9/S11/S20 + S10 由 P1 降为 P2 后此处不变）」与 `:1740`「P2 × 7（…→ 实为 8 条…）」两句互相矛盾 | 甲在 `:1744-1749` 的最终表已修正为 P1 × 7 / P2 × 8 | **甲自己已订正**，仅留痕。不需要行动 |

**另有一处设计立场上的不一致（不算事实错误）：**

甲在 `:372` 称 `rtsc_proto` 是「**已冻结的稳定层**」，据此推荐用 `WrapTpkt` 还原
而不是给 `TpktStream` 加 `NextFrame()`。但同一份报告里 S13/S14 又要求改
`ConnectState` 的结构（加 `error_code`）——那也是改 `rtsc_proto` 的头文件。
**"冻结"这个前提在甲自己的建议清单里就不成立。**

**我接受甲的 `WrapTpkt` 方案（不要求加严格模式），理由见 §9.7 末段**，
但这不改变「甲的理由不成立」这个事实判断。

---

### 9.7 合并缺陷表（定案基线，38 行）

> 归属：**双方** = 甲、乙都提到（可能表述不同）；**甲** = 仅甲；**乙** = 仅乙。
> 严重度用统一标尺：**P0** 阻断接入/静默不安全；**P1** 特定场景失败或错误不可诊断；
> **P2** 契约/可维护性。
> 合并编号 `M01..M36` 供定案引用。

| 合并 | 甲 | 乙 | 症状 | 归属 | 严重度 | 定案处置 |
|---|---|---|---|---|---|---|
| **M01** | S1 | B02 | `CredsspClient` nonce 恒为 32 个 0；全仓无 CSPRNG | 双方 | **P0** | `RandomBytes()`（Win `BCryptGenRandom` / POSIX `getrandom`）放 `rtsc_crypto`（**不能放 `rtsc_security`**，否则 `rtsc_credssp` 反向依赖——甲 `:1789` 已指出）；构造即填充 |
| **M02** | S2 | B03+B05 | EUAR 无读取器；`TpktStream` 静默丢弃 4 字节；若走 `OnData` 则误判 malformed MCS | 双方 | **P0** | 安全层 `kAwaitEuar` 恰取 4 字节 + `remove_prefix(4)`（甲 `:428-435`、`:1105-1106`）；`proto` **零改动** |
| **M03** | S3 | B06 | `TpktStream` 剥 4 字节头，`OnData` 要头，直接对接 100% 失败 | 双方 | **P0** | **用 `WrapTpkt` 还原**（甲 `:366-373`、`:1791`）；必须检查返回空（`size > 65528`，甲 N6 `:2046`） |
| **M04** | S4 | B09 | 无 DER 分帧器：TSRequest 半包→终态、粘包→终态 | 双方 | **P0** | 安全层实现 DER TLV 累积（`30` + 长度，长形式 ≤4 字节） |
| **M05** | S9 | B14 | `closed_` 置位后 `Receive` 立即返回，`rx_buffer_` 无法排空 | 双方 | P1 | `:230` 改 `if (closed_ && rx_buffer_.empty())`（甲 `:1797` 给了精确改法） |
| **M06** | S12 | B04(b) | 钩子错误阶段静默 no-op | 双方 | P2 | `connect_machine.cpp:355` 改 `Fail(...)`；**不动头文件** |
| **M07** | S17 | B11 | `complete()` 不可靠：第 5 步发出即 true（早于服务器确认）+ 收到杂字节翻回 false | 双方 | P1 | 不以 `complete()` 作就绪判据（甲 `:1805` 只加注释）；`kDone` 加锁存（我的 B11 补充） |
| **M08** | S8 | U-07 | `kStrict`/`kTofu` 未实现；`pin_is_set` 零使用；三分支同构 | 双方（乙曾降级） | P1 | `SCH_CRED_DEFERRED_CRED_VALIDATION` + `CertGetCertificateChain` + SPKI pin 比对 |
| **M09** | S5 | — | 服务端 `TSRequest.version` 从不校验 | 甲 | P1 | `OnServerResponse` 校验 `req.version ∈ [2,6]` |
| **M10** | S6 | — | 服务端版本不回写 `version_` | 甲 | P1 | 收到第 2 步后 `version_ = clamp(req.version)` |
| **M11** | S7 | — | `kPeerAlert` 声明了但从不产生；alert 49 被归为 `kProtocolError` | 甲 | **P2**（甲 §17.6.3 由 P1 降级） | **不再解析 alert**（U4 实测证明拿不到 description）：按甲 S7-a 改写 `tls.h:42` 注释为「`native_code` = 承载 alert 的 `SECURITY_STATUS`」，凭据/授权的区分上移到 CredSSP 的 `errorCode`（`credssp.cpp:97-105`）；详见 M37 |
| **M12** | S10 | — | `Handshake` 的 `consumed` 在合段时多报；**根因是 `tls.h:129-132` 的公式本身失效**（甲实测订正 `:1599`） | 甲 | P2（必须修） | D1：后端按 record 头预切片 + 吸收尾部进 `rx_buffer_`；改写 `tls.h:129-132` 契约（甲 `:1631-1652` 给了全文） |
| **M13** | S11 | — | `OpenReceive` 只解密不验 HMAC（第 4 步可被 MITM 篡改） | 甲 | P1 | 校验 `signature[4..12)`；RC4 流序与 `SealSend` 对称 |
| **M14** | S13 | — | `OnData` 在 `kAwaitConnectResponse` 一次返回 Erect + Attach 两条 PDU | 甲 | P2 | 改 `ConnectStep` 注释（甲 `:1801` 建议只改文档，我同意） |
| **M15** | S14 | — | `ConnectState::error` 是 `std::string`，无错误码 | 甲 | P2 | 加 `int32_t error_code`；字符串降级为 detail |
| **M16** | S15 | — | 仓库无 socket 驱动（`src/**` 零网络代码） | 甲 | P2 | 最小驱动（甲 `:1803` 给了 `rtsc_probe --full` 的具体做法） |
| **M17** | S16 | — | `Send` 可能把一条 TSRequest 拆成多 record | 甲 | P2 | CredSSP 阶段每条消息只调一次 `Send`，断言 `size <= max_plaintext` |
| **M18** | S18 | B01 | `CredsspClient` 无生产 SPK setter → `pubKeyAuth = hash(空 SPK)`，真实服务器必拒第 3 步 | 双方（甲第二轮补） | **P0** | 加 `SetServerPublicKey(Bytes)`（**非 ForTest**）+ 空则 `Fail(kUnsupported)`（甲 `:1806` 给了精确改法） |
| **M19** | — | B07 | 两阶段边界契约不一致：协商阶段静默丢尾随字节，MCS 阶段判死 | 乙 | P1 | 统一为「一次只吃一个完整 PDU，剩余留给下次」 |
| **M20** | — | B08 | 明文流缺 TPKT 分帧层（`Receive` 契约允许一次给多条记录） | 乙 | P1 | 与 M02/M03 同批；**层归属定为安全层**（甲 §3.1 论证成立） |
| **M21** | — | B10 | `CredsspClient` 无 `failed()`/`last_error()`/`Abort()`，与 `TlsTransport` 不对称 | 乙 | P1 | 补齐三访问器 + `Abort()`；与 M07 同批 |
| **M22** | — | B12 | `SEC_I_RENEGOTIATE` 分支里 `ISC` 返回值被丢弃，真重协商不会被发现 | 乙 | P2 | `FeedExtraOnce` 返回 `Error`；仅 `NewSessionTicket(4)` 放行 |
| **M23** | S22 | B13 | `Shutdown()` 非 OK 时返回 `kOk` 但不置 `closed_`，`closed()` 说谎 | **双方**（甲 §17.1.1 收编为 S22） | P2 | 失败路径也置 `closed_`（或引入 `shutdown_failed_`）；甲给的改法：`:433` 改 `closed_ = true; return ...` |
| **M24** | — | B15 | `plaintext` 契约自相矛盾（append-only vs 失败必空） | 乙 | P2 | 改为「失败不追加，调用方原内容不变」 |
| **M25** | S20 | B16 | 口令多份、同名不同义、无单一权威写者、全仓零清零 | 双方（甲第二轮补） | P1 | **甲 `:1952-1977` 的分支改法**（`!enhanced \|\| autologon`）+ 单一载体作为 S20b（不阻塞） |
| **M26** | — | B17 | HYBRID_EX 下仍发 `CS_SEC.encryptionMethods = 0x1B` | 乙 | P2 | 非 `kProtocolRdp` 时置 0（待 U-02 实测） |
| **M27** | S20(部分) | B18 | NLA 下 Client Info 仍回填明文口令 | 双方（甲合入 S20） | P1 | 同 M25（甲已合并，不再单列） |
| **M28** | S21 | B19 | `rtsc_tls` 非跨平台：唯一 TU 无条件 `windows.h`，CMake 无条件编译 | 双方（甲第二轮补） | **P0**（跨平台前提） | **甲的 §12.1 三层拆分**（`:912-935`），**不加 `#ifdef`** |
| **M29** | — | B20 | 五库共用 `PUBLIC include`，分层约束编译器/链接器都拦不住 | 乙 | P2 | `verify.ps1` 加 grep 守卫；甲的三层拆分已部分解决（抽出 `rtsc_tls_api`） |
| **M30** | — | B21 | 无「传输关闭」入口；`kAwaitExternalSecurity` 下 `OnData` 诊断误导 | 乙 | P2 | 加 `OnTransportClosed(const char*)`（与 M06 同批，可合并为 `OnExternalSecurityFailed`） |
| **M31** | — | B22 | 现有测试固化「钩子→直接 kAwaitConnectResponse」语义 | 乙 | — | **【§9.2 裁决后自动消解】**，测试无需改 |
| **M32** | — | B23 | `done()` 在**发送** Client Info 后即 true（名为 ack 实为 sent） | 乙 | P2 | 改名 `client_info_sent()` 或补真正 ack 阶段 |
| **M33** | S19 | — | `min_version=0x0304` 时 `ProtocolMask()` 只置 1.3 → `AcquireCredentialsHandle` 返回 `0x80090331` | 甲 | P2 | 1.3 时也带 1.2（甲 `:1807`）；真实窗口由 `EnforceVersionWindow` 保证 |
| **M34** | §12.2 | B04(a) | 钩子无失败通道（`state_.error` 永远为空） | 双方（甲 `:984-987`） | P2 | 加 `OnExternalSecurityFailed(const char*)`；与 M06 同批 |
| **M35** | N6 | — | `WrapTpkt` 对 `size > 65528` 返回空，与 `TpktStream` 上限 65531 之间有 3 字节缝隙 | 甲 | P2 | 安全层检查 `WrapTpkt` 返回值，空则 `kProtocolViolation` + 尺寸 |
| **M36** | — | B17 补充 | `CS_SEC` 的 `extEncryptionMethods` 在非 RDP 下也应置 0（与 M26 同批） | 乙 | P2 | 与 M26 一起改 |
| **M37** | S23 | — | `tls.h:42` 承诺 `native_code = alert description`，实测**无法兑现**（SChannel 只给 `SEC_I_CONTEXT_EXPIRED`，明文里 `plaintext[0..2]` 是 record 头 `0x15 0x03` 不是 alert 语义） | 甲（U4 实测新发现） | P2 | 改写 `tls.h:42` 注释；把「凭据错误 vs 协议违规」上移到 CredSSP `errorCode`；`kPeerAlert` 保留给未来后端 |
| **M38** | S24 | — | **`Shutdown()` 发出的是 renegotiation request（record type 22），不是 close_notify（type 21）**：`:409` 传 `SecBuffer{0, TOKEN, nullptr}`，`:411` 丢弃 `ApplyControlToken` 返回值 | 甲（U4 实测新发现，**双方此前均漏**） | **P1** | 改 `DWORD type = SCHANNEL_SHUTDOWN; SecBuffer token{sizeof(type), SECBUFFER_TOKEN, &type};`，**检查** `ApplyControlToken` 返回值；`tests/test_tls.cpp:848` 补断言 `out[0] == 0x15` |

**统计**（按归属、按严重度）：


| 归属 | 编号 | 行数 |
|---|---|---:|
| 双方 | M01 M02 M03 M04 M05 M06 M07 M08 M18 M23 M25 M27 M28 M34 | **14** |
| 仅甲 | M09 M10 M11 M12 M13 M14 M15 M16 M17 M33 M35 M37 M38 | **13** |
| 仅乙 | M19 M20 M21 M22 M24 M26 M29 M30 M31 M32 M36 | **11** |
| **合计** | | **38** |

| 严重度 | 条数 | 编号 |
|---|---:|---|
| P0 | 6 | M01 M02 M03 M04 M18 M28 |
| P1 | 12 | M05 M07 M08 M09 M10 M13 M19 M20 M21 M25 M27 M38 |
| P2 | 19 | M06 M11 M12 M14 M15 M16 M17 M22 M23 M24 M26 M29 M30 M32 M33 M34 M35 M36 M37 |
| 作废 | 1 | M31（随 M02 裁决自动消解，仍占行留痕） |
| **合计** | **38** | |

> **与甲乙各自统计的关系（逐条可验算，按 38 行版）**
>
> **甲 24 条（S1–S24）的落点**
> · 双方行含 **12 个不同 S 编号**：S1 S2 S3 S4 S8 S9 S12 S17 S18 S20 S21 **S22**
> · 仅甲行含 **12 个不同 S 编号**：S5 S6 S7 S10 S11 S13 S14 S15 S16 S19 **S23 S24**
> · **12 + 12 = 24 ✓**
> · 甲另有 **N6**（不在 S1–S24 编号内，是甲 §15.5 的未验证项）→ 独立成 **M35**，不计入 24。
>
> **乙 23 条（B01–B23）的落点**
> · 双方行 13 条：B01 B02 B03 B04 B05 B06 B09 B11 B13 B14 B16 B18 B19
> · 仅乙行 10 条：B07 B08 B10 B12 B15 B17 B20 B21 B22 B23
> · **13 + 10 = 23 ✓**
>
> **38 行的构成 = 35 个概念 + 3 个次生行**
> · 双方 14 行 → 12 个概念（扣 M27、M34 两个次生行）
> · 仅甲 13 行 → **13 个概念**（无次生行；M35=N6 是独立概念）
> · 仅乙 11 行 → 10 个概念（扣 M36 一个次生行）
> · 概念合计 **12 + 13 + 10 = 35**
> · 次生行 3：**M27**（S20 的第二落点，B18 已在 M25 计）·
>   **M34**（B04 的另一半 `(a)`，B04 已在 M06 计）·
>   **M36**（B17 的补充字段，B17 已在 M26 计）
> · **35 + 3 = 38 ✓**
>
> ⚠️ 两个口径必须分开看，否则会与上面的归属表冲突：
> · **归属表按「行」数**：双方 14 + 仅甲 13 + 仅乙 11 = **38**
> · **概念按「去重」数**：双方 12（14 − M27 − M34）+ 仅甲 13 + 仅乙 10（11 − M36）= **35** ✓
> 差别就是那 3 个次生行。两个口径都对。
>
> **按归属列求和**：双方 14 + 仅甲 13 + 仅乙 11 = **38 ✓**
> （M31 源于乙的 B22，故归「仅乙」；作废不改变归属）
>
> **一处必须说清的口径**：M02 一行覆盖 3 个条目（S2 + B03 + B05），
> 这是「乙把同一现象拆成两条、甲合成一条」的结果，不是重复计数。
> 同理 S20 一行覆盖 B16 + B18。合并表按**可执行修复动作**分行，
> 不按「原报告条数」分行，故行数与条目数不相等。
>
> **§17 新增的 3 条如何进表**（甲在反向互审后补的）：
> · **S22**（= 我的 B13）→ 并入 M23，**归属从「乙」改为「双方」**
> · **S23**（`tls.h:42` 承诺无法兑现）→ **新增 M37**，仅甲
> · **S24**（`Shutdown()` 发重协商而非 close_notify）→ **新增 M38**，仅甲，**P1**
> · 同时 S7 因 U4 实测**降级 P1 → P2**（M11）

---

### 9.8 我对方案 A/B/C 的最终排序

> **先纠正一个沟通陷阱**：甲乙各有一套 A/B/C，**字母所指不同**：
>
> | 字母 | 甲的含义 | 乙的含义 |
> |---|---|---|
> | A | `SecurityLayer` 双入口（`OnCiphertext`/`SendPdu`） | `rtsc_session` 编排层在协议层之上 |
> | B | `SecurityLayer` 单入口 `Step(Input)` | 接口反转（`SecurityChannel` 抽象归 proto） |
> | C | 职责链装饰器（`IPduChannel` 串联） | 门面组合（`rtsc_security` 不认识 proto） |
>
> 定案时必须用**描述性名字**，否则会拿甲的 B 去比乙的 B，得出荒谬结论。

按描述性名字排序：

| 排名 | 方案 | 理由 |
|---|---|---|
| **1** | **甲的 B（单入口 `Step`）+ 乙的错误类型 + 乙的 B19/B01 前置** | 单入口解决「调用节奏」契约化；`plain_` 唯一缓冲满足甲 §3.1；`SecurityError` 四元组最完整；原子性测试可写；甲已给出 §13 的接口草案（`:1113+`）与 §14 的 D1 修复方案。**硬伤只剩 B19/B01 未补，两者都是加法不是返工** |
| **2** | **乙的 C（门面组合，security 不认识 proto）** | 库边界最干净（proto 零 diff）；`ready()` 后阶段固定，不存在 split-brain；缺点是把 TPKT 分帧推给上层，丢掉原子性断言，且错误类型不如甲 |
| **3** | **甲的 A（双入口）** | 「只 pump 不喂数据」要靠 `OnCiphertext(nullptr,0)` 约定（甲 `:181-182` 自认），是隐性契约 |
| **4** | **乙的 A（session 编排层）** | 钩子仍 public 可误用；多一层缓冲；对象数最多 |
| **5** | **甲的 C（装饰器链）** | 甲自己 `:264-267` 论证它违反甲 §3.1，我同意 |

#### 若甲坚持方案 B，我能接受的最低条件

**必须改（否则方案不成立，不是"建议"）：**

| # | 条件 | 不满足的后果 |
|---|---|---|
| C1 | **先修 M28/S21**（`rtsc_tls` 三层拆分） | Linux 编不过；甲的 `:654-655` 断言不成立 |
| C2 | **先补 M18/S18**（`CredsspClient` 生产 SPK setter） | 甲的 T1 测试写不出来；生产路径仍不可用；真机走不到 EUAR |
| C3 | **`Step({kNone})` 必须消歧**（加 `kStart` 或独立 `Start()`） | 「重复启动」不可检测；`kNone` 同时表示"启动"和"pump"，实现里必然有隐含状态 |
| C4 | **M02 必须按「安全层消费 EUAR」实现**，不得把 `kAwaitEuar` 下推到 proto | 一旦下推，就落进甲自己在 `:1062-1069` 描述的 split-brain |
| C5 | **采纳 `SecurityError` 四元组** | 三个库的 `native_code` 同名字段会互相覆盖，错误不可诊断 |
| C6 | **M03 必须检查 `WrapTpkt` 返回空**（甲的 N6 `:2046`） | 65529–65531 字节的 PDU 会静默变成空帧 |

**强烈建议（可延后但必须记录为已知风险）：**

| # | 条件 | 理由 |
|---|---|---|
| S1 | M12/S10 按甲的 D1 实现，并**重跑 `probe_s10e` 四场景**（甲 N2 `:2042`） | 包装器能工作 ≠ 搬进后端能工作 |
| S2 | M11/S7 先做 U4 实测（甲 N3 `:2043` 自认「S7 的改法是推测」） | 不同 `SECURITY_STATUS` 对应完全不同的改法 |
| S3 | M25/S20 按甲 `:1979-1983` 的 `!enhanced \|\| autologon` 判据 | 只用 `!enhanced` 会让显式 autologon 静默失效 |
| S4 | M33/S19 修完必须改 `tests/test_tls.cpp:879-885` | 现在那条用例用 `!started` 也算通过，是在掩盖 bug |
| S5 | M26/B17 在 U-02 实测前按"置 0"实现 | 置 0 是规范安全侧 |

**我可以接受的让步**：TPKT 分帧放安全层（甲 `:311` 依赖 `rtsc_proto`）——
甲的 §3.1 论证成立，且 `:1105-1106` 给出了「`remove_prefix(4)` 后
`dropped_bytes()` 恒为 0」的机制。**我放弃"加严格模式"的要求**：
`WrapTpkt` 还原 + 断言 `dropped_bytes()==0` 已足够，且不改 `rtsc_proto`。

我唯一坚持的是 **M02 的 EUAR 归属不可下推到 proto**。

---

---

### 9.9 甲的反向互审（甲 §17）与我的最终回应

> 基线：`audit-a.md` **2835 行 / 220964 B**（`LastWriteTime` 2026-10-23 08:18）。
> 甲新增 §16（实测，内容已并入 §17）与 §17（反向互审 + 定案材料）。
> 本节只记「甲对我的回应」与「我的处置」，不重复 §9.1–§9.10 的论证。

#### 9.9.1 甲对我 4 处指控的回应：**全部确认，无一条反驳**

| 我的编号 | 甲的结论（甲 §17.1） | 我的处置 |
|---|---|---|
| A-E1（`:654-655` 与 `:1036-1037` 矛盾） | **确认（乙对）**，并给出改写后的完整文本 | 结案。甲的改写文本采纳 |
| A-E2（S9 引 `:429` 精度） | **确认（乙对，且我漏了 B13）**，新增 **S22** | 结案，见 M23 |
| A-E3（`:64` 引 `tls.h:142` 漂移） | **确认（乙对）**，并列出 4 处需同步改的引用 | 结案 |
| A-E4（`:1740` P1×8 自相矛盾） | **确认（乙对，已在 `:1744-1749` 订正）**，留痕说明 `:1740` 是中间稿 | 结案 |

**这是本轮最重要的确认**：我指出的 4 处**全部成立**，甲没有一处辩解。
且 A-E2 直接产出了一条新缺陷 S22（= 我的 B13）——**我的指控有产出，不是挑字眼**。

#### 9.9.2 甲对我 6 条硬条件的回应：**6/6 全部接受**

| 条件 | 甲的结论 | 落地位置 |
|---|---|---|
| **C1** 先修 B19/S21 | **完全接受** | 批 0（甲 §17.4） |
| **C2** 先补 B01/S18 | **完全接受** | 批 1 |
| **C3** `Step({kNone})` 消歧（加 `kStart`） | **接受，并承认「这是我草案的实质缺陷，不是风格问题」** | 甲 §17.3.3 给出 `kStart` 方案 |
| **C4** EUAR 不得下推 proto | **完全接受** | 已在甲 §13.3.2 落地 |
| **C5** 采纳 `SecurityError` | **接受，但指出我「四元组」的计数口径错了** | 甲 §17.2.1 逐字对照 |
| **C6** `WrapTpkt` 空返回必须检查 | **完全接受**，并升级为接口契约的一部分 | 甲 §17.3 的 `kProtocolViolation` 分支 |

**C3 值得单独记**：甲原话是「乙举的反例成立……**这是我草案的实质缺陷**，不是风格问题」。
这说明我 §9.1.3「差异 2」的判断（单入口把「意图」压进状态，导致重复启动不可检测）
**被甲独立认可为设计缺陷**，不只是偏好差异。

**C5 我必须承认自己错了**：我写「四元组」，甲的结构是 **5 个字段**
（`kind`/`stage`/`native_space`/`native_code`/`detail`）。我把 `kind` 当成了「类型」而非「成员」。
甲在 §17.2.1 逐字对照后指出「不存在『乙的形状更好』这回事」——**这个批评成立**，
我当时写「采纳甲的设计」确实没有提出自己的形状。已在 §9.1.3 加更正。

#### 9.9.3 甲新增的 3 条缺陷：我逐条复核

##### S22（= 我的 B13）—— 已并入 M23，归属改「双方」

甲在回应 A-E2 时自己发现 `:433` 失败路径不置 `closed_`。这**本来就是我 B13 的内容**，
甲明确标注「新增 S22 = 乙的 B13」。→ **M23 归属从「乙」改为「双方」**。

##### S23（`tls.h:42` 的承诺无法兑现）—— 复核成立，新增 M37

甲用 6 个 U4 探针实测，结论是 `SEC_E_ILLEGAL_MESSAGE` **零出现**，
且 `DecryptMessage` 成功时 `plaintext` 是整条 alert 记录的**密文包装**，
`plaintext[0..2]` 是 `0x15 0x03`（record type + version），**不是 alert 的 level/description**。

我复核了关键点：`tls.h:42` 确实写着 `native_code = alert description`
（[READ:include/rtsc/net/tls.h:42]），而 `tls_schannel.cpp` 全文 `kPeerAlert` = **0 命中**（我 §9.5 已验）。
**甲的实测把「未实现」升级为「在 SChannel 上不可实现」**——这是比我更硬的结论。
→ 采纳，新增 **M37**，同时 **M11（S7）从 P1 降为 P2**，修法从「解析 alert」改为「改写注释 + 上移区分」。

> 我原来在 §9.8 的 S2 里写「M11/S7 先做 U4 实测」——甲做了，结果**否掉了我的修法**。
> 我的修法（解析 `15 03 03 00 02 <lvl> <desc>`）在 TLS 1.2 下**根本走不通**，
> 因为明文 alert 不被接受（甲 T5/R4：`SEC_E_INCOMPLETE_MESSAGE`）。**这条我错得比甲更彻底。**

##### S24（`Shutdown()` 发重协商而非 close_notify）—— **复核成立，双方此前均漏**

这是甲本轮最重要的发现，也是**我和甲都漏掉的 P1**。我独立复核了代码：

```
[READ:src/net/tls_schannel.cpp:409-411]
409         SecBuffer token{0, SECBUFFER_TOKEN, nullptr};
410         SecBufferDesc desc{SECBUFFER_VERSION, 1, &token};
411         ApplyControlToken(&ctx_, &desc);
```

- `token.cbBuffer = 0`、`token.pvBuffer = nullptr` → 传给 `ApplyControlToken` 的是**空 token**；
- `:411` 的返回值**被丢弃**，没有检查；
- 正确做法是 `DWORD type = SCHANNEL_SHUTDOWN; SecBuffer token{sizeof(type), SECBUFFER_TOKEN, &type};`。

甲的实测（`probe_u4d.out.txt` S3）：产品 `Shutdown()` 输出 **201 字节，record type = 22 (Handshake)**
= **renegotiation request**；而正确路径（`probe_u4e.out.txt` T1）输出 **31 字节，type = 21 (Alert)**
= **close_notify**。

**为什么一直没被发现**：`tests/test_tls.cpp:848` 的 `shutdown_is_idempotent`
只断言「`first` 非空、`second` 为空」，**没有断言 record type**。
→ 我复核了该断言的存在性（甲 `:848-862` 的行号引用），**成立**。

**严重度我认同 P1**：`tls.h:178-180` 声称 graceful close，实际发重协商请求；
而本后端自己把重协商判为 `kProtocolError`（`:291`、`:317`）——
**自己发的东西，自己的接收侧会拒绝**。这是自相矛盾的协议行为，不只是「关得不优雅」。

→ 新增 **M38**，P1，仅甲。

#### 9.9.4 甲对我方案排序的回应

甲在 §17.2 全部接受 C1–C6 后，在 §17.3 给出了**唯一一份**接口（取代 §13 草案），
包含 `kStart` 消歧、`native_space` 改名、`WrapTpkt` 空返回分支。
**这意味着我 §9.8 的「排名 1 = 甲的 B + 我的条件」已经落地为具体接口**，不再是纸面排序。

#### 9.9.5 我仍需坚持的三点（甲未覆盖或我不完全同意）

| # | 事项 | 状态 |
|---|---|---|
| P-1 | **M38（S24）必须与 M05/M12（S9/S10）同批** | 甲把 S24 放在批 2（TLS 后端），S9/S10 也在批 2 → **一致**，无分歧 |
| P-2 | **U-N1 未消除**：甲只回放了 boundary1/3/10，未回放 boundary2/9/12、`extra_is_zero`、`max_out_is_soft` | 甲自己列为 U-N1（`audit-a.md:2829`）。**我同意这是执行时必须补的**：`max_out_is_soft` 与 D1 的「尾部预注入」确实可能交互。建议批 2 直接跑全 26 条 |
| P-3 | **U-N4（S7-a 是否够用）依赖 U6**，而 U6 需要凭据 | 甲列为未验证（`:2832`）。**这是真实的外部阻塞**，不是设计缺陷。定案时应写明「S7 的最终形态在拿到凭据前只能定到 S7-a」 |

**没有新的分歧**。甲在 §17 里对我的每一条都做了正面回应，且 6/6 接受。

#### 9.9.6 双方是否已收敛（盖章条件核对）

| 条件 | 状态 | 证据 |
|---|---|---|
| 缺陷清单合并完成 | ✅ | 38 行（M01–M38），双方条目 100% 有落点（§9.7 交叉校验） |
| 严重度分歧已消除 | ✅ | 仅 S7 有调整（P1→P2），由甲的 U4 实测裁决，我接受 |
| 架构方案已定 | ✅ | 甲的方案 B + `kStart` + `SecurityError`（甲 §17.3 唯一接口） |
| 6 条硬条件 | ✅ | 甲 6/6 接受（甲 §17.2） |
| 4 处指控 | ✅ | 甲 4/4 确认（甲 §17.1） |
| 红证可复现 | ✅ | 我的 5 个探针（11 条触发）+ 甲的 6 个 U4 探针 + S10 探针，均实跑 |
| 未验证项已列明 | ✅ | 我的 U-01..U-12 + 甲的 U-N1..U-N6 + U3/U6 |
| **执行顺序已定** | ✅ | 甲 §17.4 批 0–批 5，与我的 C1（批 0 先做 B19）一致 |

**结论：审计阶段可以盖章，进入执行。** 唯一保留的是 3 个**外部**未知
（凭据缺失 → U3/U6/U-N4 无法裁决；Linux 工具链未实测；真实服务器行为），
它们不是设计缺陷，执行时按甲 §17.4 的批次推进即可。

---

### 9.10 本节（第二轮）的最终自检

| 检查项 | 结果 |
|---|---|
| 被审对象版本 | 第一轮 812 行 → §9.1–§9.10 用 **2052 行版** → §9.9 用 **2835 行版** |
| 是否读了甲的全部新增章节 | 是（§11 S10 实测 / §12 交叉预判 / §13 接口 / §14 consumed / §15 修复清单 / §16 实测 / §17 反向互审） |
| 是否逐条复核甲的代码断言 | 是。S5/S6/S7/S8/S10/S11/S13/S14/S15/S16/S19/S22/S23/S24 全部实读代码或实跑 |
| 引文是否逐字 | **本轮修正**：10 处 `[READ:audit-a.md:...]` 块已用脚本从甲原文**逐字替换**（此前是转述，属伪造风险，已自查纠正） |
| 是否修改了工程代码 | 否 |
| 是否在 C 盘创建文件 | 否 |
| 撤回条目数 | **5**（§2.2.3 全节 / 「签名不够」/ 「应加严格模式」/ 「S10 应升 P1」/ **「解析 alert」修法（被 U4 否掉）**） |
| 承认遗漏数 | **11**（S5/S6/S7/S8/S10/S11/S13/S14/S15/S16/S19）+ **1 新漏**（S24，双方均漏，甲先发现） |
| 指出的甲错误数 | **4**（甲 4/4 全部确认） |
| 甲指出我的错误数 | **2**（「四元组」计数口径、`kNone` 草案缺陷——后者甲自己承认是他的问题） |
| 合并缺陷数 | **38**（M01–M38，含 1 条作废 M31） |
| 双方是否收敛 | **是**，8/8 盖章条件满足（§9.9.6） |
| 是否有「为了和睦而放过」 | 否（4 处指控全部坚持；C1–C6 全部要求；仅在被实测否证时撤回） |

*第二轮互审完成。产品代码零改动；`ctest` 仍 16/16。*

---

## 10. 批 0 审计验证（乙 · 独立验证）

> **验证对象**：执行 AI `ses_e99c24117ffeWAQpIkIbFYCNoc`，批 0（S21 跨平台拆分 + S0.9）。
> **证据目录**：`F:\rtsc\evidence\exec\`（26 个文件）。
> **影子实验目录**：`F:\rtsc\.tmp\audit-b0-b\`（6 个影子树，全部在 .tmp 内）。
> **本轮未修改任何工程代码**（`src/`、`include/`、`tests/`、`tools/`、`CMakeLists.txt` 零写入；
> 所有实验在 `.tmp\audit-b0-b\` 的副本上做）。
>
> **方法**：不复述执行 AI 的报告。每个 W 项都自己跑命令或读代码，
> 结论以 `[BASH:命令:输出]` / `[READ:文件:行]` 形式给出。
> 主代理已复核的四项（Windows ninja / Linux 全量 / S0.9 四行 / S24-b）我**重新独立跑了一遍**，
> 结果一致，但不作为我通过的依据——我的依据是 W1–W7。

### 10.0 结论先行

| W | 主题 | 结论 | 级别 |
|---|---|---|---|
| **W1** | CMake 三库结构可维护性 | **最小正确**，但 `rtsc_tls_api` 当前是**纯冗余**（与 `:63` 重复） | P2 |
| **W2** | 门禁缺口 | **确认缺口**：`verify.ps1` 无 `-LinuxBuild`，Linux 绿色**只在本轮手动验证过** | **P1** |
| **W3** | S0.9 `[[maybe_unused]]` | **不是正确修法**。三个 helper 是复制粘贴遗留，应**删除**（我实测删除后全绿） | P2 |
| **W4** | 自查修正诚实性 | **两处均属实**，且是**主动暴露**（时间戳与文件内容都支持） | — |
| **W5** | 数字相同是否掩盖断言变弱 | **未掩盖**：全文件 diff 仅 3 行，断言零改动；第 23 轮改动**完好** | — |
| **W6** | 独立红证 | **2/2 重现**（`windows.h` + `std::terminate`） | — |
| **W7** | 技术债 | 内部头**非必要但可接受**；`_WIN32` 3 处可降到 2 但**不值得** | P2 |

**批 0 判定：审计通过（PASS），但附 2 项必修 + 3 项建议。**

- **P1（必修，不阻塞批 0 交付但阻塞「S21 不复发」）**：W2 的 Linux 构建门禁。
- **P2（建议，批 1 顺手做）**：W1 的 `rtsc_tls_api` 冗余、W3 的删除 helper、W7 的注释说明。
- **批 0 本身的目标（S21 修复 + Windows 不变）成立**，红证可复现，无回归。

---

### 10.1 W1：CMake 拆分是否真的可维护

#### 10.1.1 当前结构（`CMakeLists.txt:48-68`）

```
[READ:CMakeLists.txt:53-68]
53  add_library(rtsc_tls_api INTERFACE)
54  target_include_directories(rtsc_tls_api INTERFACE include)
55
56  if(WIN32)
57      add_library(rtsc_tls_schannel STATIC src/net/tls_schannel.cpp)
58      target_link_libraries(rtsc_tls_schannel PUBLIC rtsc_tls_api)
59      target_link_libraries(rtsc_tls_schannel PUBLIC secur32 crypt32)
60  endif()
61
62  add_library(rtsc_tls STATIC src/net/tls_factory.cpp)
63  target_include_directories(rtsc_tls PUBLIC include)
64  target_link_libraries(rtsc_tls PUBLIC rtsc_tls_api)
65  target_include_directories(rtsc_tls PRIVATE src/net)
66  if(WIN32)
67      target_link_libraries(rtsc_tls PUBLIC rtsc_tls_schannel)
68  endif()
```

**判断：结构正确，是「最小正确」，不是过度设计。**

理由：三层各司其职且职责单一——
- `rtsc_tls_api`：头文件契约（平台中立）
- `rtsc_tls_schannel`：唯一 Windows TU
- `rtsc_tls`：门面，任何平台都存在

这正好对应 §12.1 的三层拆分，且 `if(WIN32)` 只包住「加哪个后端」，没有包住门面本身。

#### 10.1.2 「明天给 Linux 加 OpenSSL 后端」——我实测了

在 `F:\rtsc\.tmp\audit-b0-b\shadow-openssl\` 里加了一个假 OpenSSL 后端，**改动只有 2 处**：

1. **CMake 加 1 个 target + 1 个 `else()` 分支**：
```cmake
add_library(rtsc_tls_openssl STATIC src/net/tls_openssl.cpp)
target_link_libraries(rtsc_tls_openssl PUBLIC rtsc_tls_api)
# ...
else()
    target_link_libraries(rtsc_tls PUBLIC rtsc_tls_openssl)
endif()
```

2. **`tls_factory.cpp` 加 3 处小改**（1 处前置声明 + 2 处 `#else` 分支体）

**结果**：
```
[BASH: wsl bash build_openssl.sh]
CONFIGURE_EXIT=0
TLS_BUILD_EXIT=0
-rwxrwxrwx 1 jay jay 295170 Oct 23 09:44 bl/librtsc_tls.a
```

**结论：这个结构支持加后端，改动量小（2 处，约 8 行）。** 不需要重构。

#### 10.1.3 「有人误把 `tls_schannel.cpp` 加进 `rtsc_tls`」——我实测了

在 `shadow-regress\` 里把 `src/net/tls_schannel.cpp` 加回 `rtsc_tls` 的源文件列表（这正是 S21 的原始形态）：

```
[BASH: wsl bash build_regress.sh]
CONFIGURE_EXIT=0
TLS_BUILD_EXIT=1
2
4:/mnt/.../src/net/tls_schannel.cpp:29:10: fatal error: windows.h: No such file or directory
```

**结论：会立刻编译失败（响亮的错误，不是静默的）—— 这一点是好的。**
**但没有任何脚本会主动拦住它**：CMake 不做结构校验，`verify.ps1` 也不检查。
只有在**有人真的跑 Linux 构建**时才会暴露。→ 这就是 W2 的缺口。

#### 10.1.4 `rtsc_tls_api` 是否必要？—— **当前是纯冗余**

```
[READ:CMakeLists.txt:54]  target_include_directories(rtsc_tls_api INTERFACE include)
[READ:CMakeLists.txt:63]  target_include_directories(rtsc_tls PUBLIC include)
[READ:CMakeLists.txt:64]  target_link_libraries(rtsc_tls PUBLIC rtsc_tls_api)
```

`:63` 已经把 `include` 设为 PUBLIC，`:64` 再链 `rtsc_tls_api`（其唯一内容也是 `INTERFACE include`）——
**两者完全重复**。`rtsc_tls_api` 目前提供的唯一东西，`rtsc_tls` 自己已经提供了。

**但它对 `rtsc_tls_schannel` 仍有意义**（`:58`），因为后端不直接暴露 `include`。
所以 `rtsc_tls_api` **不是完全无用，只是 `rtsc_tls` 那一行冗余**。

**建议（P2，不阻塞）**：删掉 `:63`（`rtsc_tls` 的 `target_include_directories`），
让 `include` 只经 `rtsc_tls_api` 传递。这样「头文件来源唯一」，且与设计意图一致。
**风险**：`rtsc_tls` 的消费者（`rtsc_tls_tests`）已经通过 `rtsc_tls` 拿到 include，
删 `:63` 后仍能通过 `:64` 的 `rtsc_tls_api` 拿到——行为不变。**需在批 1 验证一次 Windows + Linux 构建。**

#### 10.1.5 W1 判定

**「最小正确」**。不是过度设计（三层各有明确职责，且我实测加后端只需 2 处改动），
也不是「仍不足」（唯一不足是 `:63` 冗余，属 P2 整洁性问题）。

---

### 10.2 W2：门禁缺口——S21 会复发吗

#### 10.2.1 事实：`verify.ps1` 没有 Linux 门禁

```
[READ:verify.ps1:23-24]
23  param([switch]$Clean, [switch]$CrashCheck, [switch]$DocLint, [switch]$PseudoLint,
24        [switch]$TlsRedTest, [switch]$CredsspRedTest)

[BASH: Select-String -Path F:\rtsc\verify.ps1 -Pattern 'Linux|WSL|wsl|windows\.h']
(零命中)
```

**6 个开关，没有 `-LinuxBuild`。全文 `Linux` / `WSL` / `windows.h` 零命中。**

#### 10.2.2 后果：Linux 绿色是「一次性」的

批 0 的 Linux 绿证存在于 `evidence/exec/b0-green-full.txt`，但那是**手工跑的一次**。
下一轮任何人改 `CMakeLists.txt`（比如加 `rtsc_security`、加 OpenSSL 后端），
**没有任何自动化会在 Windows 侧提示「你刚把 Linux 弄坏了」**。

我在 §10.1.3 已实测：误加 `tls_schannel.cpp` 回 `rtsc_tls` → Linux 编译失败。
这个错误在 Windows 上**完全看不见**（Windows 有 `windows.h`），
`verify.ps1` 会全绿通过。**这就是「静默退化」的确切路径。**

#### 10.2.3 另外两个缺口（我在核查中发现的）

**缺口 A：`b0-main-review.md` 引用了不存在的脚本**

```
[READ:evidence/exec/b0-main-review.md:17]
脚本 `F:\rtsc\.tmp\verify_linux.sh`（`rm -rf .tmp/bl-verify` 全新配置）

[BASH: Test-Path 'F:\rtsc\.tmp\verify_linux.sh']
False
[BASH: Get-ChildItem F:\rtsc -Filter '*verify*linux*' -Recurse -File]
(无输出)
```

**该脚本不存在。** 主代理的复核报告引用了它作为「Linux 全量验证」的依据，
但脚本本身没有留存 → **Linux 绿证不可重放**（只能靠 `b0-green-full.txt` 的输出文本，
而那段文本是执行 AI 生成的，无法独立重跑同一脚本）。

> **这不是执行 AI 的错**（`b0-main-review.md` 是主代理 09:34 写的），
> 但它是**证据链缺陷**：判据 D5 要求「Linux 全量构建成功」，
> 而当前留存的证据只有「一段输出文本」，没有「可重跑的命令」。

**缺口 B：批 0 从未实际运行 `-CrashCheck`**

```
[BASH: grep 'reason=terminate|\.dmp|crash guard check' evidence/exec/*]
(零命中)
```

执行 AI 只证明了 `crashtest` **能编译**（Linux 全量构建包含它），
**没有证明它运行时仍能捕获 `std::terminate`**。
S0.9 恰好改了这个文件的 `#include`，所以「改完还能正常工作」是应当验证的。

**我替它补了这一步**（见 §10.4.3）：Windows 上实跑 `terminate` 模式 →
`exitcode=3`、`reason=std::terminate`、`.dmp` 122412 B、9 层栈帧。**功能正常。**

#### 10.2.4 具体建议：加 `-LinuxBuild` 门禁

**加在 `verify.ps1` 的 `param()` 里，作为一个 switch**，实现要点：

```powershell
# 1) param 增加
[switch]$LinuxBuild

# 2) 主体（放在 ctest 之后、CrashCheck 之前）
if ($LinuxBuild) {
    Write-Host "== linux build gate =="
    $wsl = (Get-Command wsl -ErrorAction SilentlyContinue)
    if (-not $wsl) {
        # 环境缺失必须 FAIL，不能静默跳过（对齐 PseudoLint 的 G9 教训：
        # "deleting a checker used to disable it silently"）
        Write-Error "wsl not found: -LinuxBuild cannot run (environment issue, NOT a pass)"
        exit 1
    }
    # 用全新目录，避免复用陈旧缓存（D5 明确要求「从零 configure」）
    $stamp2 = Get-Date -Format "yyyyMMddHHmmss"
    $linBuild = "/mnt/f/rtsc/.tmp/bl-gate-$stamp2"
    $script = @"
set -e
cd /mnt/f/rtsc
rm -rf $linBuild
cmake -S . -B $linBuild -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build $linBuild -j4
ctest --test-dir $linBuild --output-on-failure
"@
    $out = wsl -e bash -lc $script 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { Write-Host "  $_" }
    if ($code -ne 0) { Write-Error "linux build gate failed (exit $code)"; exit 1 }

    # 三条断言：不只信退出码
    $failed = @($out | Where-Object { $_ -match '^FAILED:' }).Count
    if ($failed -ne 0) { Write-Error "linux gate: $failed FAILED lines"; exit 1 }
    # windows.h 必须零出现（S21 的直接判据）；排除表头行
    $hits = @($out | Where-Object { $_ -match 'windows\.h' -and $_ -notmatch '^===' }).Count
    if ($hits -ne 0) { Write-Error "linux gate: windows.h appeared ($hits)"; exit 1 }
    Write-Host "  linux build gate passed (0 FAILED, 0 windows.h, ctest ok)"
}
```

**为什么这样写（三条设计约束）：**

| 约束 | 做法 | 依据 |
|---|---|---|
| 环境缺失必须 FAIL 不能跳过 | `wsl` 不存在 → `exit 1` | 对齐 `verify.ps1:160-164` 的 G9 教训（删掉检查器曾导致静默禁用） |
| 必须从零 configure | `rm -rf` + 时间戳目录 | §19.5.1 D5 原文「从零 configure」 |
| 不能只信退出码 | 额外断言 `FAILED:` 计数 = 0 且 `windows.h` = 0 | 执行 AI 自己的 W4 教训：表头文字会让 grep 误报 |

**同时建议**（P2）：把 `b0-green-full.txt` 的生成脚本**固化到 `evidence/exec/` 或 `.tmp` 并纳入备份**，
否则 D5 的绿证永远不可重放（见缺口 A）。

#### 10.2.5 W2 判定

**P1 缺口成立。** 不是「批 0 做错了」，而是「批 0 的成果没有被固化」。
建议在批 1 开始前先加 `-LinuxBuild`，否则批 1/2/3 每加一个 CMake target 都在裸奔。

---

### 10.3 W3：S0.9 的 `[[maybe_unused]]` 是不是正确修法

#### 10.3.1 三个 helper 的实际状态

```
[BASH: Select-String -Path tests\test_credssp.cpp -Pattern '\bStr\s*\(']
50: [[maybe_unused]] Bytes Str(const char* s) { ... }

[BASH: Select-String -Path tests\test_licensing.cpp -Pattern '\b(ToHex|AnsiBytes)\s*\(']
37: [[maybe_unused]] std::vector<uint8_t> AnsiBytes(const std::string& s) {
60: [[maybe_unused]] std::string ToHex(const std::vector<uint8_t>& v) {
```

**三个都只有定义，零调用。**

#### 10.3.2 关键证据：它们在别的文件里有「同名的活版本」

```
[READ:tests/test_crypto.cpp:36-38]
36  Bytes Str(const char* s) {
37      return Bytes(s, s + std::char_traits<char>::length(s));
38  }
```

**与 `test_credssp.cpp:50` 逐字相同**（连实现体都一样）。

```
[READ:tests/test_crypto.cpp:40-48]
40  std::string ToHex(const uint8_t* p, size_t n) {
41      static const char* kHex = "0123456789abcdef";
...
48  }
```

**与 `test_licensing.cpp:60-68` 逻辑相同**（同样的 `kHex` 表、同样的移位/掩码）。

而且 `test_crypto.cpp` 里的这两个**被大量使用**：
```
[BASH: Select-String -Path tests\test_crypto.cpp -Pattern 'ToHex\(']
→ 30+ 处命中（:67, :69, :71, :73, :79, :95, :96, ...）
```

#### 10.3.3 判断：是「遗留物」还是「本该用但漏了」

逐条排除：

| helper | 该文件是否需要这个能力 | 有没有等价的手写实现 | 结论 |
|---|---|---|---|
| `Str`（test_credssp.cpp） | 需要「字符串→Bytes」。但 23 个用例**全部用 `FromHex`**（26 处），**零处**需要从字符串字面量构造 | 无（也不需要） | **遗留物** |
| `ToHex`（test_licensing.cpp） | 需要「bytes→hex 比较」。但该文件的强断言是 **`vector == vector`** 全字节比对（`:189` `re.data() == w.data()`、`:423` `d.encode() == bytes`、`:556`、`:653`） | 无（也不需要，因为用 `==` 更强） | **遗留物** |
| `AnsiBytes`（test_licensing.cpp） | 需要「ANSI + NUL 结尾」。该文件有 `MicrosoftCorp()`（`:44-52`）做同样的事 | **有**：`:264-265` 和 `:534-535` 都是手写 `for (char c : scope) w.u8(c); w.u8(0);` | **遗留物**（且已手写替代） |

**没有一处「本该用却漏了」**。特别是 `AnsiBytes`：它的功能在 `:264` 和 `:534` 被手写了两次，
如果 `AnsiBytes` 真该用，这两处就该调它——但它们是写 `ByteWriter`（输出到 wire），
而 `AnsiBytes` 返回 `vector`，**类型不匹配**。所以 `AnsiBytes` 从一开始就不是为这两处设计的。

#### 10.3.4 决定性实验：删除后全绿

我在 `shadow-del-helper\` 里删掉这 3 个 helper（不是加 `[[maybe_unused]]`，是**整段删除**）：

```
[BASH: wsl bash build_del_helper.sh]
CONFIGURE_EXIT=0
FULL_BUILD_EXIT=0
FAILED_COUNT=0
23 tests, 69 checks, 0 failing tests, 0 failed checks      ← credssp
47 tests, 175 checks, 0 failing tests, 0 failed checks     ← licensing
```

**与基线（`b0-win-regression.txt`：credssp 23/69、licensing 47/175）逐项相同。**

#### 10.3.5 W3 判定：**应删除，不应 `[[maybe_unused]]`**

| 选项 | 评价 |
|---|---|
| **删除（推荐）** | 我实测全绿，且消除 3 处死代码。要删的就是 3 个函数的**完整定义**：<br>`tests/test_credssp.cpp:50`（1 行）<br>`tests/test_licensing.cpp:37-41`（AnsiBytes，5 行）<br>`tests/test_licensing.cpp:60-68`（ToHex，9 行） |
| `[[maybe_unused]]`（现状） | **能编过，但保留了死代码**。且 `[[maybe_unused]]` 的语义是「我知道它没被用，但保留是有意的」——这里**不是有意的**，是复制粘贴遗留 |
| 用起来 | 不成立：没有一处需要它们（见 §10.3.3），强行用会**削弱**断言（`ToHex` 比较弱于 `vector==vector`） |

**为什么执行 AI 选错了**：它的报告里写「这些是真实 Linux 构建失败，修法是加 `[[maybe_unused]]`」——
**这只回答了「怎么让它编过」，没回答「它该不该存在」**。
`[[maybe_unused]]` 是「消除警告」，不是「消除问题」。

> **但我要说清：这不算执行 AI 的失职。** S0.9 是主代理 adjudicate 后批准的「4 行最小修复」，
> 目标是让 Linux 全量构建绿，`[[maybe_unused]]` 确实达成了这个目标。
> **我的结论是「修法可以更彻底」，不是「修错了」。** 级别 P2。

---

### 10.4 W4：执行 AI 的「自查修正」是否诚实

#### 10.4.1 第一处：`WINDOWS_H_COUNT` 算成 1

执行 AI 声称：第一版脚本把 `WINDOWS_H_COUNT` 算成 1（因为表头文字含 "windows.h"），
改为只统计构建输出区段 → 真值 0。

**我独立验证**：
```
[BASH: 全文 grep 'windows.h' b0-green-full.txt]
whole_file_matches=1
[BASH: 只看构建区段（第 21-82 行）]
build_region_matches=0
[BASH: 那 1 处在哪]
87 : === STEP 4: windows.h occurrences (want 0; this was the S21 red) ===
```

**属实**。全文唯一命中就是**第 87 行那句表头说明文字本身**，构建输出区段 0 命中。
执行 AI 的说法（「表头文字导致算成 1」）与事实**逐字吻合**。

#### 10.4.2 第二处：负对照失败会删掉 `probe_s24b.exe`

**我独立验证**：
```
[READ:evidence/exec/b0-s24b-red-baseline.txt:202-203]
202  Note it DELETES probe_s24b.exe when it fails, so re-run build.bat afterwards;
203  the probe output above was captured after exactly such a rebuild.
```

**属实且记录在案**。而且该文件 `:111` 与 `:188` 两次出现 `LNK2019`，
`:155` 记录了 exe 的时间戳 `2026-10-23 09:28:32 114688 B` —— 说明确实是「重建后再捕获」。

#### 10.4.3 更重要的判断：是主动暴露还是被逼出来的

**证据指向「主动暴露」**：

| 证据 | 说明 |
|---|---|
| `b0-change-manifest.txt` 有 `DISC-1` 到 `DISC-5` | **5 处规范自相矛盾**，全部主动列出（如「S0.2 说 grep 'windows' 应无输出，但同一段要求的文件内容里有注释含 Windows」） |
| `b0-green.txt:11-13` | 主动写「(B) the full-tree build : **STILL FAILS**」——在自己交报告的文件里明写失败 |
| `b0-green.txt:146-150` | 主动写「Linux full-tree build: **RED AT THE TIME THIS FILE WAS WRITTEN**」 |
| `b0-green.txt:153` | 主动写「**SUPERSEDED BY S0.9**」，并说明是主代理裁决后才修的 |
| 时间戳 | `b0-green.txt` 写于 **09:30**，晚于 `b0-green-full.txt`（09:25 绿）——**在已经绿了之后，仍然回去把「曾经红过」写清楚** |

**第 5 条最有说服力**：如果目的是粉饰，09:25 拿到绿之后直接交绿证即可，
没必要在 09:30 再写一份包含「曾经红、红在哪、为什么红」的文件。

**结论：诚实。** 两处自查修正都属实，且整体呈现「主动暴露问题」的模式，不是被逼。

#### 10.4.4 但我发现一个执行 AI 没暴露的缺口

**批 0 从未运行 `-CrashCheck`**（见 §10.2.3 缺口 B）。
S0.9 改了 `tools/rtsc_crashtest/main.cpp`，理应验证「改完还能正常工作」，
但证据里没有任何 `.dmp` / `reason=terminate` / 「crash guard check」字样。

**我替它补了**（Windows 实跑）：
```
[BASH: Start-Process rtsc_crashtest.exe terminate]
[crash] rtsc_crashtest: std::terminate
  dump: ...rtsc_crashtest-20261023-095732-22828.dmp
  text: ...rtsc_crashtest-20261023-095732-22828.txt
exitcode=3
dmp=122412 B   txt=452 B

[BASH: Get-Content 那个 .txt]
app=rtsc_crashtest
reason=std::terminate
frames=9
  #0 ... terminate+0x2E
  #1 ... CrashTerminate+0xC
  #2 ... main+0xCE
```

**功能正常。** 所以这是「证据缺口」而非「功能缺陷」——P2。

---

### 10.5 W5：数字相同是否掩盖了「断言变弱」

#### 10.5.1 全文件 diff（不只看数字）

```
[BASH: Compare-Object (backup 20261023-092309) vs (current)]
--- test_credssp : 2 differing lines ---
=> [[maybe_unused]] Bytes Str(const char* s) { ... }
<= Bytes Str(const char* s) { ... }
--- test_licensing : 4 differing lines ---
=> [[maybe_unused]] std::vector<uint8_t> AnsiBytes(const std::string& s) {
=> [[maybe_unused]] std::string ToHex(const std::vector<uint8_t>& v) {
<= std::vector<uint8_t> AnsiBytes(const std::string& s) {
<= std::string ToHex(const std::vector<uint8_t>& v) {
```

**逐行 diff 只有 3 处实际改动（每处是「同一行加前缀」），零行删除、零行新增。**
`crashtest` 是 `#include <exception>` 纯新增 1 行。

#### 10.5.2 断言计数与文本

```
[BASH: CHECK/CHECK_EQ 计数]
test_credssp : orig=57 now=57 delta=0
test_licensing : orig=168 now=168 delta=0
```

**断言数量完全不变。** 结合 §10.5.1 的逐行 diff（唯一改动是给函数定义加前缀），
可以确定：**没有任何断言被删除、放宽或改写**。D8 通过。

#### 10.5.3 第 23 轮的测试改动是否还在 —— **关键检查**

主代理说「我在第 23 轮修改过 `test_credssp.cpp`」。**实际位置是 `test_credssp_sm.cpp`**
（不是 `test_credssp.cpp`），三项改动：

```
[BASH: 全仓 grep]
F:\rtsc\tests\test_credssp_sm.cpp : 179 : RTSC_TEST(step3_authenticate_carries_a_nonzero_mic) {
F:\rtsc\tests\test_credssp_sm.cpp : 245 : RTSC_TEST(binding_hash_matches_independent_value) {
```

**两项都在**，且内容完整：

```
[READ:tests/test_credssp_sm.cpp:245-258]
245  RTSC_TEST(binding_hash_matches_independent_value) {
246      // Expected values computed outside this codebase with SHA256(magic ||
247      // 0x00 || nonce || SubjectPublicKey). Comparing the implementation against
248      // itself (as an earlier version of this test did) cannot detect a wrong
249      // magic, a missing NUL, or a swapped order.
...
254      CHECK(Hex(ClientToServerBindingHash(spk, nonce)) ==
255            "38e6b5801b2a07e738371fa8056aa7f5f4e6cb72c5b663add8eac3efb7ada78e");
```

**独立十六进制常量仍在**（`38e6b580...` / `d791087c...`），自指比较已消除。

```
[READ:tests/test_credssp_sm.cpp:179-209]
179  RTSC_TEST(step3_authenticate_carries_a_nonzero_mic) {
...
201      CHECK(Hex(mic) != Hex(Bytes(16, 0)));
...
208      CHECK(Hex(Bytes(mic_arr.begin(), mic_arr.end())) == Hex(mic));
```

**MIC 非零断言 + 三消息重算断言都在。**

**为什么没被 S0.9 覆盖**：
```
[BASH: Get-Item tests\test_credssp_sm.cpp]
10/23/2026 05:59:44 18047 B      ← 早于 S0.9 的 09:23
[BASH: Test-Path .opencode\backups\tests_test_credssp_sm.cpp.20261023-092309]
False                             ← S0.9 的备份集里没有这个文件，说明没碰它
```

**三重证据（内容在 + mtime 早于 S0.9 + 不在 S0.9 备份集）确认：第 23 轮改动完好无损。**

#### 10.5.4 W5 判定

**「数字相同」这次没有掩盖问题**，因为：
1. 数字相同 + **逐行 diff 只有 3 行前缀改动** → 断言不可能变弱（没有删改的空间）
2. 第 23 轮的关键测试**经三重证据确认完好**

**但我要指出方法上的局限**（回应主代理的提醒）：**光看数字确实不够**。
如果这次 S0.9 顺手删了一行 `CHECK`，数字会从 69 掉到 68 —— 能被发现。
但如果它把 `CHECK(a == b)` 改成 `CHECK(a.size() == b.size())`，**数字完全不变**。
所以「数字相同」必须配「逐行 diff」才有意义。我这次做了 diff，结论可信。

---

### 10.6 W6：我自己的独立红证

#### 10.6.1 红证 1：还原批 0 前的 CMake → `windows.h` 错误重现

用备份 `CMakeLists.txt.20261023-085223`（7514 B，批 0 前的原始版本）还原到影子树，
**源码用当前的**（只回退 CMake，不动代码），在 WSL 构建：

```
[BASH: wsl bash build_prebatch0]
CONFIGURE_EXIT=0                      ← 配置成功（证明失败在编译期，不在配置期）
-- Configuring done (3.7s)
-- Generating done (2.2s)

[BASH: wsl bash -c 'cmake --build bl']
BUILD_EXIT=1
2
4:/mnt/.../shadow-prebatch0/src/net/tls_schannel.cpp:29:10: fatal error: windows.h: No such file or directory
5:   29 | #include <windows.h>
```

**红证成立**：批 0 前的 CMake 确实在 Linux 上编译失败，错误就是 `tls_schannel.cpp:29` 的 `windows.h`。
**这证明 S21 是真缺陷，不是纸面问题。**

#### 10.6.2 红证 2：去掉 `#include <exception>` → `std::terminate` 错误重现

用 S0.9 的备份 `tools_rtsc_crashtest_main.cpp.20261023-092309`（1233 B，**没有** `#include <exception>`），
在 WSL 单独编译：

```
[BASH: wsl bash build_noexc.sh]
EXIT=1
main.cpp: In function 'void {anonymous}::CrashTerminate()':
main.cpp:30:43: error: 'terminate' is not a member of 'std'
   30 | [[noreturn]] void CrashTerminate() { std::terminate(); }
      |                                           ^~~~~~~~~
main.cpp:12:1: note: 'std::terminate' is defined in header '<exception>'; did you forget to '#include <exception>'?
  +++ |+#include <exception>
main.cpp:30:56: error: 'noreturn' function does return [-Werror]
```

**红证成立，且编译器自己就指出了缺哪一行**：
`note: 'std::terminate' is defined in header '<exception>'; did you forget to '#include <exception>'?`

**结论：`#include <exception>` 是必要的，不是凑数。** 这行修的是真实缺陷。

> **补充说明**：这条红证也证明「MSVC 的 `<string>` 传递包含 `<exception>`，libstdc++ 不包含」——
> 这正是 S0.9 只在 Linux 暴露的原因。**这不是执行 AI 引入的，是既有的可移植性缺陷。**

#### 10.6.3 我的独立 Linux 全量构建（不复用执行 AI 的产物）

在 `shadow-current\`（当前代码的完整副本）里从零 configure + build：

```
[BASH: wsl bash build_current.sh]
CONFIGURE_EXIT=0
FULL_BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_IN_BUILD=0
-rwxrwxrwx 1 jay jay 254268 Oct 23 09:55 bl/librtsc_tls.a
100% tests passed, 0 tests failed out of 15
```

**与执行 AI 的 `b0-green-full.txt` 一致**（`FAILED_COUNT=0`、`WINDOWS_H_COUNT=0`、ctest 15/15）。
`librtsc_tls.a` 254268 B vs 执行 AI 的 254132 B，**差 136 B** —— 这是不同的绝对路径长度
导致的调试信息差异（`/mnt/f/rtsc/.tmp/audit-b0-b/shadow-current` 比 `/mnt/f/rtsc/.tmp/bl-green` 长），
**不是缺陷**。

#### 10.6.4 W6 判定

**2/2 红证独立重现，1 次全量构建独立复现。** 批 0 的核心主张（S21 是真缺陷、修复有效）**成立**。

---

### 10.7 W7：批 0 有没有留下技术债

#### 10.7.1 `tls_schannel_internal.h`（559 B）是否必要

**事实**：
```
[BASH: grep 'tls_schannel_internal']
src/net/tls_factory.cpp : 13 : #include "tls_schannel_internal.h"
src/net/tls_schannel.cpp : 42 : #include "tls_schannel_internal.h"
```

**被 2 个文件包含**（不只是 1 个）。内容只有 1 个函数声明。

**我实测了「能不能省掉这个文件」**（`shadow-nointernal\`：删头文件，两处改为内联前置声明）：

```
[BASH: wsl bash build_nointernal.sh]
CONFIGURE_EXIT=0
TLS_BUILD_EXIT=0
-rwxrwxrwx 1 jay jay 254284 Oct 23 09:48 bl/librtsc_tls.a
```

**能省掉，编译通过。**

**但判断：不该省。** 理由：
- 省掉后，`CreateSchannelTransport` 的声明要在 **2 个文件里各写一遍**（factory + schannel）
- 两处声明一旦签名漂移（比如加参数），编译器**不会报错**（各自独立编译），
  只在链接期出现 `LNK2019`——正是批 0 里 `probe_s24b` 踩过的坑
- 559 B 的头文件换来「声明唯一」，这是**正确的最小设计**

**结论：不是技术债。** 保留。

#### 10.7.2 `#if defined(_WIN32)` 3 处能否减少

**现状**（`tls_factory.cpp`）：`:12`（include）、`:24`（CreateTlsTransport 分支）、`:40`（EnumerateTlsBackends 分支）。

**我实测了降到 2 处**（`shadow-1ifdef\`：把「默认后端 + 枚举」合并进一个 `PlatformPolicy` 结构 + lambda）：

```
[BASH: wsl bash build_1ifdef.sh]
CONFIGURE_EXIT=0
TLS_BUILD_EXIT=0
--- 实际 #if defined(_WIN32) 指令数 ---
13: #if defined(_WIN32)
29: #if defined(_WIN32)
```

**能降到 2 处，编译通过。** 但代价：
- 代码从 47 行涨到 **68 行**
- 引入 `struct PlatformPolicy` + 静态 lambda + 函数指针成员
- `librtsc_tls.a` 从 254268 B 涨到 **320596 B**（多了 66 KB，因为 lambda 生成了额外的代码）

**结论：不值得。** 3 处 `#if` 直白、零抽象成本、每个分支都能一眼看懂。
为了「少一个 `#if`」引入一个结构体 + lambda，是**过度设计**。

**建议（P2，可选）**：在 `tls_factory.cpp` 顶部加一行注释说明「这 3 处 `#if` 是刻意的，
不要为了减少数量而抽象」——防止未来有人做我刚才那个实验。

#### 10.7.3 其他潜在技术债

| 项 | 判断 |
|---|---|
| `tls_schannel.cpp` 从 `CreateTlsTransport` 改名为 `CreateSchannelTransport` | **正确**。门面接管公共名，后端用内部名。符号验证：`b0-win-symbols.txt` 已证明「facade External CreateTlsTransport = 1，backend mentions CreateTlsTransport = 0」 |
| `rtsc_tls` 的 `target_include_directories(... PUBLIC include)`（`:63`）与 `rtsc_tls_api` 重复 | **P2 冗余**（见 §10.1.4） |
| `src/net/tls_factory.cpp` 的 `(void)config;` 在非 Windows 分支 | **已不存在**（当前版本用 `#else` 分支返回前不引用 config，但 `-Werror` 下若未使用会报错——我实测全量构建 `FAILED_COUNT=0`，说明当前写法安全） |

#### 10.7.4 W7 判定

**没有实质性技术债。** 内部头保留是对的，`#if` 3 处不抽象是对的。
唯一可优化项是 `:63` 的冗余（P2）。

---

### 10.8 缺陷与缺口清单（本轮发现）

| # | 级别 | 项 | 说明 | 建议 |
|---|---|---|---|---|
| **B0-01** | **P1** | `verify.ps1` 无 `-LinuxBuild` 门禁 | Linux 绿色只在本轮手动验证过；下一轮改 CMake 会静默退化。我实测「误加 `tls_schannel.cpp` 回 `rtsc_tls`」在 Windows 上完全看不见 | 按 §10.2.4 加 `-LinuxBuild`（含 3 条断言 + 环境缺失必 FAIL） |
| **B0-02** | **P1** | D5 绿证不可重放：`b0-main-review.md:17` 引用的 `F:\rtsc\.tmp\verify_linux.sh` **不存在** | 只有输出文本，没有可重跑脚本 | 固化 Linux 验证脚本并纳入备份 |
| **B0-03** | P2 | S0.9 用 `[[maybe_unused]]` 保留 3 个死代码 helper | 实测删除后全绿（credssp 23/69、licensing 47/175 与基线逐项相同）；三个 helper 在 `test_crypto.cpp` 有同名活版本 | 删除 `test_credssp.cpp:50`、`test_licensing.cpp:37-41`、`:60-68` |
| **B0-04** | P2 | 批 0 未运行 `-CrashCheck` | S0.9 改了 crashtest 的 include，却只验证「能编译」。我补跑确认功能正常（`exitcode=3`、`reason=std::terminate`、`.dmp` 122412 B） | 批 0 的验收清单里加「`verify.ps1 -CrashCheck` 通过」 |
| **B0-05** | P2 | `CMakeLists.txt:63` 与 `:64` 重复提供 `include` | `rtsc_tls_api` 的唯一内容也是 `INTERFACE include` | 删 `:63`，让 include 只经 `rtsc_tls_api` 传递；批 1 验证一次双平台构建 |
| **B0-06** | P2 | `tls_factory.cpp` 的 3 处 `#if` 没有「不要抽象」的注释 | 我实测可降到 2 处但代码涨 45%、产物涨 66 KB | 加一行注释说明刻意保留 |

**统计：P0 × 0，P1 × 2，P2 × 4，合计 6 条。**

> **没有 P0。** 批 0 的核心目标（S21 修复 + Windows 行为不变）**已达成且有红证**。

---

### 10.9 对主代理已复核四项的独立确认

主代理说「你可不重复」，但按「禁止采信自述」的要求，我仍独立跑了一遍：

| 项 | 主代理结论 | 我的独立结果 | 一致？ |
|---|---|---|---|
| Windows `ninja: no work to do` | — | `[BASH: ctest --test-dir build\verify]` → `100% tests passed, 0 failed out of 16` | ✅ |
| Linux 全量（从零 configure） | `BUILD_EXIT=0` / `FAILED_COUNT=0` / `WINDOWS_H_COUNT=0` / `LIB_BYTES=254132` / ctest 15/15 | `FULL_BUILD_EXIT=0` / `FAILED_COUNT=0` / `WINDOWS_H_IN_BUILD=0` / `LIB=254268` / ctest 15/15 | ✅（LIB 差 136 B，路径长度差异） |
| S0.9 四行 | 均已就位 | 逐行 diff 确认：`test_credssp.cpp:50`、`test_licensing.cpp:37`、`:60`、`crashtest:9` | ✅ |
| S24-b 未触碰 | `tls_schannel.cpp:431` 原样 | `[READ:tls_schannel.cpp:411-413]` 空 token + 丢弃返回值，与批 0 前一致 | ✅ |

---

### 10.10 最终判定

> ### 批 0 审计通过（PASS）

**依据（全部可复现）**：

| 判据 | 结果 | 证据 |
|---|---|---|
| S21 是真缺陷（红证） | ✅ | §10.6.1：还原批 0 前 CMake → `fatal error: windows.h: No such file or directory` |
| S21 已修复（绿证） | ✅ | §10.6.3：独立从零构建 `FULL_BUILD_EXIT=0`、`WINDOWS_H_IN_BUILD=0` |
| 修复是必要的（不是凑数） | ✅ | §10.6.2：去掉 `#include <exception>` → `'terminate' is not a member of 'std'` |
| Windows 行为未变 | ✅ | §10.9：ctest 16/16；§10.5：逐行 diff 仅 3 行前缀改动、断言计数零变化 |
| 第 23 轮改动未被覆盖 | ✅ | §10.5.3：三重证据（内容在 + mtime 早于 S0.9 + 不在 S0.9 备份集） |
| 无断言变弱 | ✅ | §10.5.1-2：全文件 diff 只有 3 行，CHECK 计数 57/168 完全不变 |
| 执行 AI 的自述可信 | ✅ | §10.4：两处自查修正均属实，且是主动暴露（时间戳 + DISC-1..5） |

**附带的 6 条改进项（P1×2 / P2×4）不构成阻断**：
- **B0-01（P1）** 应在**批 1 开始前**处理——否则批 1 每加一个 target 都在裸奔
- **B0-02（P1）** 建议与 B0-01 一起做（同属「Linux 验证可重放」）
- **B0-03~06（P2）** 可在批 1 顺手做

**我不认可的地方（明确记录）**：
1. **S0.9 的修法选择**：`[[maybe_unused]]` 能编过但不是正确修法，应删除（§10.3.5）。这是 P2，不阻塞。
2. **`b0-main-review.md` 引用不存在的脚本**：这是证据链缺陷，不是执行 AI 的责任，但必须记录（B0-02）。

**没有发现 P0，没有发现行为回归，没有发现断言变弱，没有发现伪造。**

*批 0 审计验证完成。产品代码零改动（所有实验在 `.tmp\audit-b0-b\` 副本上进行）。*

---

## 11. 与甲 §21 的交叉验证（W11⑤ 收敛轮）

> **背景**：我把 §10 的 4 处分歧 relay 给甲，甲在 `audit-a.md` §21 做了独立复核并**推翻我两处判断**。
> 本节是我对甲结论的**独立复现**，不是采信。
>
> **基线**：`audit-a.md` **351214 B / 4985 行**（甲 §21）。
> 我的实验全部在 `F:\rtsc\.tmp\audit-b0-b\` 的独立影子树上做，**产品代码零改动**。

### 11.0 结论先行：我错了两处，甲对

| 分歧 | 我的原判 | 甲的反驳 | 我独立复现后的结论 |
|---|---|---|---|
| **1. W2 门禁** | P1 | 同意 P1，并补「Windows 侧零信号」实测 | **一致，P1** |
| **2. W3 删除 helper** | 应删除 | 同意删除，认可我的证据更强 | **一致，删除** |
| **3. `:63`/`:64` 冗余** | 删 `:63` | 两条都是「充分不必要」，删任一条都安全；**建议保留作防御** | **甲对**：我实测删 `:64` 也编译通过，我的「只删 `:63`」判断不完整 |
| **4. `#if` 3→2** | **不值得**（+66 KB） | **零体积增长**，且**能堵住一个静默空白** | **甲对，我错**：+66 KB 是**我那套写法**的代价，不是「降到 2 处」的代价 |

**净结果：我的 W7 结论（`#if` 不值得降）必须推翻，改为「应降，低优先级」。**

---

### 11.1 分歧 4 反转一：体积——**我错，甲对**

#### 11.1.1 我的原实验（错误归因）

我先前用 `PlatformPolicy` 结构 + 静态 lambda 把 3 处降到 2 处，测得：

```
[BASH: 我的 shadow-1ifdef]
_librtsc_tls.a 320596 B      ← 比现状 254268 B 大 66 KB
```

我据此判定「降到 2 处代价太大」。**这个归因是错的**：66 KB 来自我引入的
`struct PlatformPolicy` + lambda + 函数指针成员，**不是**「减少 `#if`」本身。

#### 11.1.2 甲的改法（只把 include 移出 `#if`）

甲的思路是：`tls_schannel_internal.h` **本身平台中立**（只有 `#pragma once` + 一个声明，
无 Windows 头），所以可以**无条件 include**。这样 `:12` 的 `#if` 就不需要了：

```cpp
// 改前（3 处 #if）
#if defined(_WIN32)
#include "tls_schannel_internal.h"
#endif

// 改后（2 处 #if）
#include "tls_schannel_internal.h"
```

#### 11.1.3 我独立复现

```
[BASH: wsl bash build_q4.sh]   ← 我在 w7-q4 影子树上施加甲的改法
CONFIGURE_EXIT=0
TLS_BUILD_EXIT=0
-rwxrwxrwx 1 jay jay 254220 B   ← 254220 B

对比：
current(3 #if)  254268 B
q4(2 #if)       254220 B   ← 比现状还小 48 B
我的 68 行写法  320596 B   ← +66 KB
```

**甲完全正确**：他的改法（50 行）**比现状还小 48 B**，而我的写法（68 行）才 +66 KB。
`#if` 数量与产物体积**没有因果关系**，我混淆了「改法」与「目标」。

---

### 11.2 分歧 4 反转二：3→2 堵住一个静默空白（**这是甲本轮最重要的发现**）

#### 11.2.1 甲的论断

甲说：当前 3 处 `#if` 下，如果**有人往 `tls_schannel_internal.h` 里加 `<windows.h>`**，
Linux 构建**会静默成功**（因为该头只在 `#if defined(_WIN32)` 里被 include，Linux 根本不解析它）。
降到 2 处（无条件 include）后，同样的注入会让 Linux **立刻报错**。

#### 11.2.2 我独立复现（两个方向都做了）

**实验 A：当前 3 处 `#if` + 向 internal header 注入 `<windows.h>`**

```
[BASH: 向 q4-a 的 tls_schannel_internal.h 注入 #include <windows.h>]
[BASH: wsl bash build_q4a.sh]
CONFIGURE_EXIT=0
TLS_BUILD_EXIT=0        ← 静默成功！
--- windows.h errors ---
0
```

**确认甲的论断**：3 处版本下，Linux 构建**完全察觉不到** internal header 被污染。

**实验 B：甲的 2 处改法 + 同样注入**

```
[BASH: 向 q4-b 的 tls_schannel_internal.h 注入 #include <windows.h>]
[BASH: wsl bash build_q4b.sh]
CONFIGURE_EXIT=0
TLS_BUILD_EXIT=1        ← 立刻失败
--- windows.h errors ---
2
5:/mnt/.../q4-b/src/net/tls_schannel_internal.h:5:10: fatal error: windows.h: No such file or directory
6:    5 | #include <windows.h>
```

**确认**：2 处版本下，同样的污染**立刻暴露**，且错误精确指向 `tls_schannel_internal.h:5`。

#### 11.2.3 与甲证据的对拍

甲的证据文件 `evidence/u4/q4c-linux.txt`（3 处，静默）与 `q4b-linux.txt`（2 处，报错）：

```
[READ:evidence/u4/q4c-linux.txt]
[1/2] Building CXX object CMakeFiles/rtsc_tls.dir/src/net/tls_factory.cpp.o
[2/2] Linking CXX static library librtsc_tls.a          ← 无 error

[READ:evidence/u4/q4b-linux.txt]
FAILED: CMakeFiles/rtsc_tls.dir/src/net/tls_factory.cpp.o
/mnt/f/rtsc/.tmp/audit-w1/q4b/src/net/tls_schannel_internal.h:5:10:
    fatal error: windows.h: No such file or directory
```

**与我自己的 q4-a / q4-b 结果逐条吻合。甲的实验可信。**

#### 11.2.4 为什么这条重要

这不是「少一个 `#if`」的美学问题，而是**把一类跨平台退化从「静默」变成「响亮」**：

| 场景 | 3 处（现状） | 2 处（甲的改法） |
|---|---|---|
| 有人往 internal header 加 `<windows.h>` | Linux 静默通过 | **Linux 立刻报错** |
| 有人往 internal header 加 `<winsock2.h>` | 同上 | **同上** |
| 有人往 internal header 加 `<rtsc/net/tls.h>` 之外的平台头 | 同上 | **同上** |

**这与 B0-01（门禁缺口）是同一类问题**：都是「让跨平台退化尽早暴露」。
区别是：B0-01 靠外部脚本门禁，这个靠**代码结构本身**——后者更可靠（不依赖有人记得跑）。

---

### 11.3 分歧 3：`:63`/`:64` —— **甲对，我判断不完整**

#### 11.3.1 甲的说法

甲实测：删 `:63` 和删 `:64` **都能编译**（include 传播都是 38 次），
所以两条是「充分不必要」，**删任一条都安全**。

#### 11.3.2 我原先只测了一个方向

我在 §10.1.4 只分析了「删 `:63`」的情况，**没有实测删 `:64`**。

#### 11.3.3 我补做实验：删 `:64`（保留 `:63`）

```
[BASH: 注释掉 CMakeLists.txt:64 的 target_link_libraries(rtsc_tls PUBLIC rtsc_tls_api)]
[BASH: wsl bash build_w1no64.sh]
CONFIGURE_EXIT=0
TLS_BUILD_EXIT=0        ← 编译通过

[BASH: 检查 rtsc_tls_tests 的 include 路径]
INCLUDES = -I/mnt/f/rtsc/.tmp/audit-b0-b/w1-no64/include    ← 仍能拿到
```

**确认甲正确**：删 `:64` 后，`include` 经 `:63` 的 `target_include_directories(rtsc_tls PUBLIC include)`
继续传播，消费者仍能拿到头文件。**我原判断「只删 `:63` 安全」是不完整的。**

#### 11.3.4 但处置上我接受甲的建议：**保留，不删**

甲的理由（我认同）：`rtsc_tls_api` 现在有 2 个消费者（`:58` 后端、`:64` 门面）。
若删 `:63` 只留 `:64`，`rtsc_tls` 的 include 就**依赖另一个 target 的存活**；
将来若有人把 `rtsc_tls_api` 内联掉（它只有 2 行），`:63` 已没了 → include 断 →
**只在 Linux 表现为「找不到 rtsc/net/tls.h」**，又是一次跨平台不一致。

**冗余在这里是廉价防御**：多 1 行、零产物（INTERFACE 库不生成文件）。

**我改判：B0-05 从「P2 应删」改为「P2 保留，加注释说明这是刻意冗余」。**

---

### 11.4 分歧 1：W2 门禁 —— 一致 P1，甲的证据更直接

甲补了我没做的一个实验：**同一份错误 CMake，Windows 侧全绿**。

```
[READ:甲 §21 的 w2a 实验]
Linux   : BUILD=1, tls_schannel.cpp:29: fatal error: windows.h
Windows : W2_WIN_BUILD=0（构建成功，零警告）
Windows : 26 tests, 139 checks, 0 failing（全绿）
```

我只证明了「Linux 会失败」，甲证明了「**Windows 完全无信号**」——后者才是「静默」的定义。
**我采纳这个更强的表述。**

甲给的「它已经咬过一次」也成立：S0.9 那 3 个缺陷（`Str`/`AnsiBytes`/`ToHex`/`<exception>`）
**全是 Linux 独有、Windows 不可见**。若不是有人手动跑 WSL，批 0 会以「Windows 全绿」
交付一棵 Linux 编译不过的树。**这不是假设，是刚发生的事实。**

---

### 11.5 分歧 2：W3 删除 —— 一致，甲认可我的证据更强

甲原话：「你的证据更有力……**这证明来源是复制粘贴遗留，不只是「碰巧没用到」**——比我
「删掉后能编译」的论证强一档。我采纳。」

甲补充了活调用的具体行号（我复核成立）：
```
[READ:tests/test_crypto.cpp:36]  Bytes Str(const char* s) {      ← 逐字相同的活版本
[READ:tests/test_crypto.cpp:68]  const auto abc = Md4(Str("abc"));   ← 活调用
[READ:tests/test_crypto.cpp:69]  CheckHash(ToHex(abc), "a448017a..."); ← 活调用
```

**一致：应删除，不是保留。**

---

### 11.6 甲提出、我未提的 2 条（我复核后接受）

#### 11.6.1 A20-1：批 0 使 `tls_schannel.cpp` 行号 +2，§19 红证锚点全部失效（**P1**）

甲说 §19 里的行号引用全部偏移 +2，批 2 照抄会改错位置。**我独立复核**：

```
[BASH: 当前 tls_schannel.cpp 实际行号]
if (closed_) return ...                    → :232   （甲说 :232，§19 写 :230）
consumed = in_size;                        → :169   （甲说 :169，§19 写 :167）
SecBuffer token{0, SECBUFFER_TOKEN, ...};  → :411   （甲说 :411，§19 写 :409）
if (st == SEC_E_OK || SEC_I_CONTINUE_...)  → :431   （甲说 :431，§19 写 :429）
```

**四条全部 +2，甲完全正确。**

严重性我认同 P1：若执行 AI 照 §19 的 `:429` 去改，改到的是 `:429` 现在的内容。
我核对了 `:429` 当前是什么：
```
[READ:tls_schannel.cpp:429]  FreeContextBuffer(out_buf.pvBuffer);
```
**改到这里 = 内存泄漏 + 红证无效**（S24 的修复没做，还引入泄漏）。**批 2 一定中招。**

#### 11.6.2 A20-2：`b0-s24b-red-baseline.txt` 的「verbatim」不成立（**P2，已修复**）

甲说该文件声称 `MapShutdownStatus()` 是产品的 verbatim 拷贝，实际不是。
**我复核**：

```
[READ:evidence/exec/b0-s24b-red-baseline.txt:72-81]
72  CORRECTION (audit A20-2, 2026-10-23): MapShutdownStatus() is NOT a verbatim
73  copy of the product. Its else-branch returns kProtocolError, whereas the real
74  product fallthrough (the "shutdown best effort" line) returns kOk.
...
80  But the earlier wording "verbatim" was inaccurate and is retracted here.
```

**执行 AI 已主动加了 CORRECTION 并撤回该措辞**（文件内明确标注 `audit A20-2`）。
所以这是**已被处理**的项，不是未决缺陷。定 P2 且标注「已修复」。

#### 11.6.3 B0-02 的补充：不影响 D5 结论正确性

甲说：「不影响 D5 结论的正确性——我已用完全独立路径复现绿灯……所以是『不可重放』，
不是『结论错误』。定级 P1 合理，但不阻塞批 1——门禁（B0-01）落地后可重放性就由门禁本身保证。」

**我接受这个精确化**：B0-02 的性质是「证据不可重放」，不是「证据错误」。
且甲的论证成立：一旦 B0-01 的门禁存在，重放性由门禁保证，B0-02 自然消解。

---

### 11.7 合并后的批 0 缺陷清单（双方定稿）

| 编号 | 级别 | 内容 | 提出方 | 我的复核 |
|---|---|---|---|---|
| **B0-01** | **P1** | `verify.ps1` 无 `-LinuxBuild`；跨平台退化在 Windows 侧零信号（甲实测 Windows 构建成功 + 26/139 全绿） | 乙 | ✅ 采纳甲的更强表述 |
| **B0-02** | **P1** | `verify_linux.sh` 不存在 → D5 不可重放（非结论错误） | 乙 | ✅ 采纳甲的精确化 |
| **A20-1** | **P1** | §19 红证行号 +2 偏移；照抄 `:429` 会改到 `FreeContextBuffer` → 泄漏 | **甲** | ✅ 四条锚点全部核实 |
| **A20-3 / B0-04** | P2 | `crashtest` 运行未验证（双方各补跑，均正常；dump 大小 119808 vs 122412 B 属内存布局差异） | 双方独立 | ✅ |
| **A20-2** | P2 | 「verbatim」措辞不成立（**执行 AI 已加 CORRECTION 修复**） | **甲** | ✅ 已修复 |
| **A20-4 / W3** | P2 | `[[maybe_unused]]` 应删除 | 双方一致 | ✅ |
| **B0-05 / W1** | P2 | `:63`/`:64` 冗余（删任一条都安全；**建议保留作防御**） | 乙 | ✅ 改判为「保留」 |
| **U20-5 / W7** | P2 | internal header 漂移在 3 处下不可发现；**降 2 处可堵住**（我实测确认） | **甲**，本轮升级为可修 | ✅ **改判为「应做，低优先级」** |

**合计：P0 × 0 / P1 × 3 / P2 × 5。**

---

### 11.8 我的两处改判（诚实记录）

| 项 | 原判 | 改判 | 依据 |
|---|---|---|---|
| **W7 `#if` 3→2** | **「不值得」**（+66 KB） | **「应做，低优先级」** | ① 甲的改法零体积增长（我实测 254220 B，比现状小 48 B）；② 3 处下 internal header 污染**静默通过**（我实测 `TLS_BUILD_EXIT=0`），2 处下**立刻报错**（我实测 `EXIT=1`） |
| **W1 `:63` 删不删** | 「删 `:63`」 | **「保留，加注释」** | 我实测删 `:64` 也编译通过 → 两条都是充分不必要 → 甲的「保留作防御」更稳妥 |

**这两处都是「甲做了我没做的实验」，而不是「甲的逻辑比我的强」。**
我的错误模式是：**用一个实现（PlatformPolicy）的结果去否定一个目标（减少 `#if`）**，
以及**只测了一个方向就下结论**。这是本轮我应当记住的教训。

---

### 11.9 门禁落地验证：B0-01 / B0-02 已被处理，我实测确认有效

> **时间线**：我在 10:0x relay 了 §10（B0-01/B0-02 均为 P1），
> `verify.ps1` 在 **10:07:14** 被修改（`scripts/linux-build-gate.sh` 同时新增）。
> 所以这不是「我说了但没人做」，而是**已经落地**。本节验证它是否真的有效——
> **不是看它存在，是看它能不能抓到 S21 复发。**

#### 11.9.1 落地内容

```
[READ:verify.ps1:30]
30  [switch]$TlsRedTest, [switch]$CredsspRedTest, [switch]$LinuxBuild)

[READ:verify.ps1:271-289]
271  if ($LinuxBuild) {
273      $gate = Join-Path $root "scripts\linux-build-gate.sh"
274      if (-not (Test-Path $gate)) { Write-Error "missing $gate"; exit 1 }
275      $wsl = Get-Command wsl -ErrorAction SilentlyContinue
276      if (-not $wsl) {
279          Write-Error "wsl not found: cannot verify the Linux build (environment missing, treated as FAIL)"
280          exit 1
281      }
286      & wsl -e bash $gateWsl
287      if ($LASTEXITCODE -ne 0) { Write-Error "linux build gate failed"; exit 1 }
```

新增 `scripts/linux-build-gate.sh`（约 110 行），脚本头部明确写了它的三条契约：

```
[READ:scripts/linux-build-gate.sh:6-16]
  # Why this file exists (audit B0-02): the batch-0 Linux green certificate was
  # produced by an ad-hoc script that was deleted afterwards, so the result could
  # not be replayed. This script is the permanent, re-runnable form.
  #
  # Contract (aligned with verify.ps1's G9 rule: a missing environment must FAIL,
  # not silently skip):
  #   * exit 0  -> Linux build succeeded, zero warnings, ctest green
  #   * exit 1  -> a real defect: compile error, -Werror, failing test
  #   * exit 2  -> environment missing (no cmake / no ninja / no compiler)
```

**B0-02 直接解决**：脚本固化在 `scripts/`（不是 `.tmp`），可重放。

#### 11.9.2 验证 1：正常树上必须 PASS

```
[BASH: wsl bash scripts/linux-build-gate.sh .tmp/audit-b0-b/gate-current]
CONFIGURE_EXIT=0
BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_COUNT=0
LIB_BYTES=254164
FACTORY_SYMBOL=present
CTEST_EXIT=0
100% tests passed, 0 tests failed out of 15
LINUX GATE PASS
```

**通过。** 且脚本额外断言了三件退出码证明不了的事：
`FAILED_COUNT==0`、`WINDOWS_H_COUNT==0`、`CreateTlsTransport` 符号存在。

#### 11.9.3 验证 2（**最关键**）：注入 S21 回归后必须 FAIL

这是「门禁是否有效」的唯一判据——**一个只会 PASS 的门禁等于没有**。

我在影子树 `gate-red\` 里把 `tls_schannel.cpp` 加回 `rtsc_tls` 的源文件列表
（**正是 S21 的原始形态**），然后跑同一个门禁脚本：

```
[BASH: wsl bash run_gate_red.sh]
[34/61] Building CXX object CMakeFiles/rtsc_capabilities_tests.dir/...
ninja: build stopped: subcommand failed.
LINUX GATE FAIL: FAILED=1 WINDOWS_H=2
GATE_EXIT=1
```

**门禁抓到了。** `FAILED=1`（1 个 TU 失败）+ `WINDOWS_H=2`（2 处 `windows.h` 报错）+ `exit 1`。

**这条红证的意义**：`verify.ps1 -LinuxBuild` 不是「加了一个开关」，
而是**真的会在 S21 复发时让整个 verify 失败**。

#### 11.9.4 验证 3：环境缺失必须 FAIL（exit 2），不能静默跳过

我抽取脚本里的守卫代码（`:25-32` 逐字）在无 cmake 的 PATH 下执行：

```
[BASH: wsl bash test_guard_logic.sh]
=== extracted guard lines (verbatim) ===
fail_env() {
    echo "LINUX GATE ENV: $1" >&2
    exit 2
}
command -v cmake >/dev/null 2>&1 || fail_env "cmake not found"
...
=== run guard with cmake absent from PATH ===
GUARD_EXIT=2
LINUX GATE ENV: cmake not found
```

**确认**：环境缺失走 `exit 2` + 明确错误信息，**不是 skip**。
且 `verify.ps1:276-281` 对「没有 wsl」也单独 `exit 1`——两层都堵住了。

#### 11.9.5 但有一个**残留缺口**（我新发现，P2）

`verify.ps1:287` 只看 `$LASTEXITCODE`。而门禁脚本自己在**输出里**断言了
`FAILED_COUNT` / `WINDOWS_H_COUNT`——这些断言通过 `exit 1` 传递，所以**目前是安全的**。

**但**：如果将来有人改动 `linux-build-gate.sh`，让它在 `FAILED_COUNT != 0` 时
**打印警告但不 exit 1**，`verify.ps1` 会认为通过（因为退出码是 0）。
这正是甲提醒我的「**不能只信退出码**」的同类风险——只是这次风险在**门禁脚本自身**，
而不是在 `verify.ps1`。

**建议（P2，非阻塞）**：`verify.ps1` 在 `:286` 之后额外 grep 输出，
断言 `LINUX GATE PASS` 出现（**正向断言**，而不是只断言退出码）。
这与 `b0-acceptance-19.3.1.txt` 的教训同源（那里是 `^` 锚点导致假 FAIL，这里是
「只看退出码」可能导致假 PASS）。

#### 11.9.6 门禁的独立红证（我做的，不是采信）

| 场景 | 期望 | 实测 | 结论 |
|---|---|---|---|
| 正常树 | PASS | `LINUX GATE PASS`、exit 0 | ✅ |
| 注入 S21 回归 | FAIL | `LINUX GATE FAIL: FAILED=1 WINDOWS_H=2`、exit 1 | ✅ |
| 缺 cmake | exit 2 | `GUARD_EXIT=2` + `cmake not found` | ✅ |
| 缺 wsl（`verify.ps1` 层） | exit 1 | `:276-281` 代码路径确认 | ✅（未实跑，无 wsl 不可模拟） |

**B0-01 / B0-02 从「P1 未处理」改为「P1 已处理且经我红证验证有效」。**

#### 11.9.7 我保留的一条意见

门禁脚本把 `WINDOWS_H_COUNT` 定义为 `grep -c 'windows\.h' "$BUILD_LOG"`（`:63`）。
**这正是执行 AI 在 W4 里踩过的坑**（表头文字导致误计 1）。

我验证了当前脚本**不会踩这个坑**，因为它的 `BUILD_LOG` 是 `cmake --build` 的**纯输出**
（不含自己写的表头）：
```
[BASH: 检查 BUILD_LOG 内容]
→ 只有 ninja 的 [N/M] 行和错误行，无脚本自写的 "windows.h occurrences" 表头
```
**当前安全。** 但如果将来有人把 `echo "=== windows.h occurrences ==="` 加进
`BUILD_LOG` 的重定向范围，就会重演 W4 的误计。**建议加一行注释说明这一点（P2）。**

---

### 11.10 最终判定

> ### 批 0 审计通过（PASS）—— 双方一致

**甲的判定理由**（我认同）：
> S21 修到根因（三层影子树证明「只回滚 `CMakeLists.txt` 就足以重现」，
> 且当前树 `CMakeFiles/` 里没有 `rtsc_tls_schannel.dir`）；
> Windows 15 套件 tests/checks 在 S0.9 前后逐项相同；
> S0.9 的 4 行经删除实验证明是死代码标记而非掩盖。
> 无行为回归、无断言变弱、无伪造。

#### 11.10.1 缺陷状态的最终快照

| 编号 | 级别 | 内容 | 状态 |
|---|---|---|---|
| **B0-01** | P1 | `verify.ps1` 无 `-LinuxBuild` | **✅ 已处理**（`verify.ps1:30,271-289` + `scripts/linux-build-gate.sh`），**经我红证验证有效**（§11.9.3：注入 S21 → `GATE_EXIT=1`、`FAILED=1 WINDOWS_H=2`） |
| **B0-02** | P1 | D5 绿证不可重放 | **✅ 已处理**（门禁脚本固化在 `scripts/`，非 `.tmp`），我实测可重放（§11.9.2） |
| **A20-1** | P1 | §19 红证行号 +2 偏移 | **⏳ 待处理**（批 1 前必须做） |
| **A20-3 / B0-04** | P2 | `crashtest` 运行未验证 | 双方各补跑，功能正常（我：`exitcode=3`、`reason=std::terminate`、`.dmp` 122412 B） |
| **A20-2** | P2 | 「verbatim」措辞不成立 | **✅ 已修复**（执行 AI 已加 CORRECTION，`b0-s24b-red-baseline.txt:72-81`） |
| **A20-4 / W3** | P2 | `[[maybe_unused]]` 应删除 | ⏳ 待做（批 1 顺手） |
| **B0-05 / W1** | P2 | `:63`/`:64` 冗余 | **改判为「保留，加注释」**（§11.3.4） |
| **U20-5 / W7** | P2 | internal header 漂移在 3 处下不可发现 | **改判为「应做」**（§11.2：我实测 3 处静默通过、2 处立刻报错） |
| **B0-07**（新增） | P2 | `verify.ps1:287` 只看 `$LASTEXITCODE`，未正向断言 `LINUX GATE PASS` | 建议加正向断言（§11.9.5） |

**P0 × 0 / P1 × 3（其中 2 条已处理）/ P2 × 6。**

#### 11.10.2 批 1 开工前的必做项（更新后只剩 1 条）

**A20-1**：把 §19 红证里的硬编码行号改为**锚点文本 + `Select-String` 定位**。

理由（我独立复核）。**先订正甲一处行数方向**：甲说「从 754 → 756 行」，
实测是 **755 → 749 行（净删 6 行）**——因为批 0 删掉了
`CreateTlsTransport` 的 backend 分发（4 行）和 `EnumerateTlsBackends`（3 行），
只新增了 2 行（`#include "tls_schannel_internal.h"` + 空行）。

**但「关键行 +2」的结论完全正确**，因为那 2 行新 include 插在 **`:41-42`**（`Receive` 之前），
使 `:41` 之后的所有行整体下移 2 行：

| 锚点 | §19 写的 | 批 0 后实际 | 差 |
|---|---|---|---|
| `Receive` 的 `if (closed_)` | `:230` | **`:232`** | +2 |
| `consumed = in_size` | `:167` | **`:169`** | +2 |
| `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}` | `:409` | **`:411`** | +2 |
| `if (st == SEC_E_OK \|\| st == SEC_I_CONTINUE_NEEDED)` | `:429` | **`:431`** | +2 |

若照 §19 的 `:429` 去改，改到的是 `FreeContextBuffer(out_buf.pvBuffer);`（我核实 `:429` 当前内容）
→ **内存泄漏 + S24 修复未生效**。**批 2 一定中招。**

#### 11.10.3 可选同批做

- **U20-5**：`#if` 3→2（零体积增长 + 堵住静默空白，我实测确认）
- **A20-4 / W3**：删除 3 个死代码 helper
- **B0-05**：给 `:63` 加「刻意冗余」注释
- **B0-07**：`verify.ps1` 加 `LINUX GATE PASS` 正向断言

#### 11.10.4 双方盖章

**审计阶段（批 0）结束。** 我（乙）与甲（`ses_e9a488e95ffeRAGF2jsornJq1O`）**一致判定 PASS**。

*本轮全部实验在 `.tmp\audit-b0-b\` 独立影子树上进行。产品代码零改动，`ctest` 16/16。*

---

## 12. 批 0 最终盖章（V-a..V-e）

> **范围**：只验证主代理本轮修复的 3 项（B0-07 / U20-5 / A20-4），**不重做批 0 审计**。
> **基线**：`scripts/linux-build-gate.sh` SHA256 `5CA09A3E...`、3078 B；`verify.ps1` 14773 B。
> **产品代码零改动**（唯一例外：V-a 的红证临时替换了门禁脚本，已恢复并哈希验证）。
> 全部影子实验在 `F:\rtsc\.tmp\audit-b0-final\`。

### 12.0 结论先行

| 项 | 结论 |
|---|---|
| **V-a** B0-07 正向断言 | **有效**。我自建红证：桩门禁 → `exit=1` + 精确错误；恢复后 `exit=0` |
| **V-b** U20-5 `#if` 3→2 | **无副作用**。`#if` 计数 = 2；Linux 产物中 `CreateSchannelTransport` **零符号** |
| **V-c** 删除 3 个 helper | **未削弱测试**。`RTSC_TEST` 23/47 不变、`CHECK` 57/168 不变、结果 23/69 与 47/175 不变 |
| **V-d** 新引入问题 | **1 条 P2 理论弱点**（`-notmatch` 子串匹配），当前实现下**不可达**；其余无违规 |
| **V-e** 最终判定 | **批 0 最终盖章通过** |

---

### 12.1 V-a：B0-07 的正向断言真的有效

#### 12.1.1 四项断言都在（`:286-301`）

```
[READ:verify.ps1:289-301]
289      $gateOut = (& wsl -e bash $gateWsl 2>&1 | Out-String)
290      Write-Host $gateOut
291      if ($LASTEXITCODE -ne 0) { Write-Error "linux build gate failed"; exit 1 }
292      if ($gateOut -notmatch 'LINUX GATE PASS') {
293          Write-Error "linux build gate exited 0 but never printed LINUX GATE PASS (gate is not doing its job)"
294          exit 1
295      }
296      foreach ($needle in @('FAILED_COUNT=0', 'WINDOWS_H_COUNT=0', 'FACTORY_SYMBOL=present')) {
297          if ($gateOut -notmatch [regex]::Escape($needle)) {
298              Write-Error "linux build gate output missing '$needle'"
299              exit 1
300          }
301      }
```

**四项断言齐全**：`LINUX GATE PASS`（`:292`）+ 三个 needle（`:296`）。

#### 12.1.2 我自建的红证（不是采信主代理）

**改前先留哈希**：`5CA09A3E...` / 3078 B。

**把门禁替换成桩**（32 B，比主代理的 `echo NEUTERED` 少一个换行）：
```
#!/bin/bash
echo NEUTERED
exit 0
```

**跑 `verify.ps1 -LinuxBuild`**：
```
[BASH: powershell -File verify.ps1 -LinuxBuild]
== linux build gate ==
NEUTERED

powershell : F:\rtsc\verify.ps1 : linux build gate exited 0 but never printed
             LINUX GATE PASS (gate is not doing its job)
RED_EXIT=1
```

**红证成立**：退出码 **1**（不是 0），错误信息精确指向「never printed LINUX GATE PASS」。

**关键点**：如果没有 B0-07 的修复，这个场景会得到 `exit=0` + "linux build gate passed"——
**一个假的绿灯**。修复把它变成了硬失败。

#### 12.1.3 恢复并验证恢复成功（硬约束）

```
[BASH: Copy-Item gate.orig.sh -> scripts/linux-build-gate.sh]
RESTORED_HASH=5CA09A3E4A500D6CADC69F7BA207BC3DA2D87E45399C1FA0D3E7CFBEC608CC7E
RESTORED_SIZE=3078
BASELINE     =5CA09A3E4A500D6CADC69F7BA207BC3DA2D87E45399C1FA0D3E7CFBEC608CC7E 3078
RESTORE_VERIFIED=YES
```

**哈希逐字一致**（不是「看起来恢复了」，是字节级一致）。

#### 12.1.4 恢复后绿证

```
[BASH: powershell -File verify.ps1 -LinuxBuild]
CONFIGURE_EXIT=0
BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_COUNT=0
LIB_BYTES=254140
FACTORY_SYMBOL=present
CTEST_EXIT=0
100% tests passed, 0 tests failed out of 15
LINUX GATE PASS

  linux build gate passed
GREEN_EXIT=0
```

**V-a 通过。**

---

### 12.2 V-b：U20-5 的 `#if` 3→2 没有副作用

#### 12.2.1 结构确认

```
[BASH: Select-String -Pattern '^\s*#if defined\(_WIN32\)' tls_factory.cpp]
if_count=2

[READ:src/net/tls_factory.cpp:12-18]
12  // Included unconditionally, even though CreateSchannelTransport is only CALLED
13  // on Windows (U20-5). The header declares a platform-neutral function, so it
14  // compiles everywhere; keeping the include outside #if means that if someone
15  // ever adds a Windows-only include to it, the Linux build fails immediately
16  // instead of silently passing. Measured: with the include inside #if, injecting
17  // <windows.h> into the internal header left the Linux build green.
18  #include "tls_schannel_internal.h"
```

**`#if` 计数 = 2**（原 3），include 在 `:18` **无任何 `#if` 包裹**。注释还引用了我的实测结论，准确。

#### 12.2.2 Linux 上不会产生未定义引用的推理

**唯一的调用点在 `:29`，位于 `#if defined(_WIN32)`（`:28`）内**：
```
[READ:src/net/tls_factory.cpp:28-40]
28  #if defined(_WIN32)
29      if (want_default) return CreateSchannelTransport(config, why);
30      why = "unknown TLS backend: " + std::string(backend);
31      return nullptr;
32  #else
33      (void)config;
34      if (want_default) {
35          why = "no TLS backend for this platform (SChannel is Windows only)";
36          return nullptr;
37      }
38      why = "unknown TLS backend: " + std::string(backend);
39      return nullptr;
40  #endif
```

`#else` 分支（Linux 走这里）**不引用** `CreateSchannelTransport`。
include 只是让**声明**可见，声明不产生符号引用。

#### 12.2.3 实测证明（比推理更硬）

```
[BASH: nm -C librtsc_tls.a | grep -i schannel]
（零命中）

[BASH: nm -C librtsc_tls.a | grep ' U ']
U _Unwind_Resume
U std::__cxx11::basic_string<...>::_M_replace_cold(...)
U std::__throw_bad_alloc()
...
（全部是 libstdc++ 运行时符号，无 CreateSchannelTransport）
```

**Linux 产物 `librtsc_tls.a` 里 `CreateSchannelTransport` 既无定义也无未定义引用。**
这是「无条件 include 不会引入链接依赖」的决定性证据——比「编译通过」强，
因为编译通过只能证明语法对，符号表能证明**没有悬空引用**。

#### 12.2.4 门禁绿

```
[BASH: wsl bash scripts/linux-build-gate.sh]
CONFIGURE_EXIT=0 / BUILD_EXIT=0 / FAILED_COUNT=0 / WINDOWS_H_COUNT=0
LIB_BYTES=254148 / FACTORY_SYMBOL=present / CTEST_EXIT=0
100% tests passed, 0 tests failed out of 15
LINUX GATE PASS
```

#### 12.2.5 红证：U20-5 确实堵住了静默空白

我在影子树 `shadow-inject\` 里向 `tls_schannel_internal.h` 注入 `#include <windows.h>`
（**先校验门禁脚本哈希与源一致**，避免重演甲遇到的「桩替换」事故）：

```
[BASH: 哈希校验]
shadow: 5CA09A3E...  ==  source: 5CA09A3E...   ✓

[BASH: wsl bash scripts/linux-build-gate.sh]
ninja: build stopped: subcommand failed.
LINUX GATE FAIL: FAILED=1 WINDOWS_H=2
```

**这正是 U20-5 的价值**：同样注入在 3 处版本下 `TLS_BUILD_EXIT=0`（静默通过），
2 处版本下被门禁抓到 `WINDOWS_H=2`。

**V-b 通过。**

---

### 12.3 V-c：删除 3 个 helper 没有削弱测试

#### 12.3.1 diff 只删了这 3 个函数

用最新备份（`20261023-092309`，即 S0.9 加了 `[[maybe_unused]]` 的版本）做 `difflib` 逐行对比：

```
[BASH: python difflib]
===== credssp : before=367 after=365 =====
@@ -49,4 +49,2 @@
 
-Bytes Str(const char* s) { return Bytes(s, s + std::char_traits<char>::length(s)); }
-
 }  // namespace

===== licensing : before=803 after=787 =====
@@ -36,8 +36,2 @@
 
-std::vector<uint8_t> AnsiBytes(const std::string& s) {
-    std::vector<uint8_t> out(s.begin(), s.end());
-    out.push_back(0);
-    return out;
-}
-
 // "Microsoft Corporation\0" in UTF-16LE (44 bytes).
@@ -57,12 +51,2 @@
     return {0x41, 0x00, 0x30, 0x00, 0x32, 0x00, 0x00, 0x00};
-}
-
-std::string ToHex(const std::vector<uint8_t>& v) {
-    static const char* kHex = "0123456789abcdef";
-    std::string out;
-    for (uint8_t b : v) {
-        out.push_back(kHex[b >> 4]);
-        out.push_back(kHex[b & 0xF]);
-    }
-    return out;
 }
```

**删除量**：credssp 2 行（`Str` + 空行）、licensing 16 行（`AnsiBytes` 5+1、`ToHex` 9+1）。

> **一处需要澄清**：第二个 hunk 里 `}` 被显示为「删除后又保留」——
> 这是 `difflib` 的**对齐假象**：`ToHex` 的闭合 `}` 与 `A02()` 的闭合 `}` 文本相同，
> 算法把它们配对了。我实测确认 `A02()` 完整：
> ```
> [READ:tests/test_licensing.cpp:50-52]
> 50  std::vector<uint8_t> A02() {
> 51      return {0x41, 0x00, 0x30, 0x00, 0x32, 0x00, 0x00, 0x00};
> 52  }
> ```
> **没有误删。**

#### 12.3.2 测试结构完全不变

```
[BASH: RTSC_TEST / CHECK 计数对比]
credssp   : RTSC_TEST before=23 after=23 | CHECK before=57 after=57
licensing : RTSC_TEST before=47 after=47 | CHECK before=168 after=168
```

**`RTSC_TEST` 数量零变化，`CHECK` 数量零变化。** 这正是主代理要求的「特别检查」。

#### 12.3.3 3 个 helper 已彻底消失

```
[BASH: grep '\bStr\s*\(' test_credssp.cpp]
（零命中）
[BASH: grep '\b(ToHex|AnsiBytes)\s*\(' test_licensing.cpp]
（零命中）
[BASH: grep 'maybe_unused' 两文件]
0
```

**`maybe_unused` 归零**（不只是删了函数，标记也一并消失）。

#### 12.3.4 实际运行结果与删除前一致

```
[BASH: rtsc_credssp_tests.exe]    23 tests, 69 checks, 0 failing tests, 0 failed checks
[BASH: rtsc_licensing_tests.exe]  47 tests, 175 checks, 0 failing tests, 0 failed checks
```

**与删除前的基线（23/69、47/175）逐项相同。**

**V-c 通过。**

---

### 12.4 V-d：主代理有没有引入新问题

#### 12.4.1 `verify.ps1` 纯 ASCII —— 确认

```
[BASH: 逐字节检查]
non_ascii_bytes=0
[BASH: 逐行检查]
（零行含非 ASCII）
```

**0 个非 ASCII 字节。** 符合 §19.6 N12（禁止用 PS 写非 ASCII 内容）的精神。

#### 12.4.2 `-notmatch` + `[regex]::Escape` 用法 —— **正确，但有一个理论弱点**

**先确认 `[regex]::Escape` 是否必要**：
```
needle='FAILED_COUNT=0'      escaped='FAILED_COUNT=0'      （无变化）
needle='WINDOWS_H_COUNT=0'   escaped='WINDOWS_H_COUNT=0'   （无变化）
needle='FACTORY_SYMBOL=present' escaped='FACTORY_SYMBOL=present' （无变化）
needle='LINUX GATE PASS'     escaped='LINUX\ GATE\ PASS'   （转义了空格）
```

**三个 needle 里没有正则元字符**（`=`、`_`、字母数字都不是元字符），
所以 `[regex]::Escape` 对它们**是空操作**。主代理的担心（「`=` 需要处理」）**不成立**——
`=` 不是正则元字符。

**但 `[regex]::Escape` 在这里仍然是对的**：它是**防御性写法**。
若将来有人把 needle 改成 `FAILED_COUNT=(0)` 或 `a.b`，没有 Escape 就会误匹配。
**保留它是对的，尽管当前是空操作。**

**真正的弱点（P2，理论）**：`-notmatch` 是**子串正则匹配**，不是精确匹配。
```
[BASH: 构造反例]
输出含 'FAILED_COUNT=01'（实际失败 1 个）
→ 断言 'FAILED_COUNT=0' 命中（因为 'FAILED_COUNT=0' 是 'FAILED_COUNT=01' 的前缀）
→ 误判为通过
```

**但当前不可达**：门禁用 `FAILED_COUNT=$(grep -cE '^FAILED:' "$BUILD_LOG")`，
`grep -c` 只输出**规范整数**（我实测：`0`、`1`、`2`…，**不会输出 `01`**）。
所以「`FAILED_COUNT=01`」这个反例在当前实现下**产生不出来**。

**判定**：**理论弱点，当前不可达，P2**。若要彻底消除，可改为
`$gateOut -match "(?m)^FAILED_COUNT=0$"`（锚定行首尾）。**不阻塞。**

#### 12.4.3 §19.6 禁止事项逐条核对

| 禁止项 | 检查命令 | 结果 |
|---|---|---|
| **N9** `#pragma warning(disable)` / `#pragma GCC diagnostic ignored` | grep 5 个改动文件 | **零命中** ✅ |
| **N6** `rand()` / `srand()` / `random_device` / `mt19937` | grep 5 个改动文件 | **零命中** ✅ |
| **N4** `rtsc_proto` 不得 include `rtsc/net/tls.h` | grep `src/proto/*.cpp` | **零命中** ✅ |
| **N2** 不得改测试让它通过 | `CHECK` 计数 57/168 不变、`RTSC_TEST` 23/47 不变 | ✅（V-c 已证） |
| **N12** 不得用 PS 写非 ASCII | `verify.ps1` 0 个非 ASCII 字节 | ✅ |
| **N10** 不得新建 build 目录/改生成器 | 本轮未见（Linux 门禁用 `.tmp/` 下独立目录，符合约定） | ✅ |

#### 12.4.4 新引入的死代码/重复 —— 无

```
[BASH: grep CreateSchannelTransport 全仓]
tls_schannel_internal.h:14  声明（唯一）
tls_schannel.cpp:740        定义（唯一）
tls_factory.cpp:29          调用（唯一，在 #if 内）
tls_factory.cpp:12          注释
```

**声明唯一、定义唯一、调用唯一。** 无条件 include 没有造成重复声明。

#### 12.4.5 15 套件全量回归 —— 全部与基线一致

```
[BASH: ctest --test-dir build\verify]
100% tests passed, 0 tests failed out of 16

[BASH: 逐个跑 15 个套件]
rtsc_ber_tests               32/166    rtsc_mcs_domain_tests   39/151
rtsc_capabilities_tests      35/218    rtsc_mcs_tests          35/182
rtsc_client_info_tests       30/120    rtsc_ntlm_tests         27/136
rtsc_connect_machine_tests   26/115    rtsc_share_tests        34/171
rtsc_credssp_sm_tests        15/92     rtsc_tls_tests          26/139
rtsc_credssp_tests           23/69     rtsc_crypto_tests       25/66
rtsc_finalization_tests      19/80     rtsc_framing_tests      11/47
rtsc_licensing_tests         47/175
```

**15 套件全部 0 failing / 0 failed，与 §19.5.1 D2 的基线逐项相同。**

**V-d 通过（1 条 P2 理论弱点，不可达）。**

---

### 12.5 V-e：最终判定

> ### 批 0 最终盖章通过

**依据**：

| 验证项 | 结论 | 证据类型 |
|---|---|---|
| V-a B0-07 正向断言 | 有效 | **自建红证**（桩门禁 → `exit=1`）+ 恢复哈希逐字一致 + 绿证 `exit=0` |
| V-b U20-5 `#if` 3→2 | 无副作用 | `#if`=2；`nm` 证明 Linux 产物**零** `CreateSchannelTransport` 符号；门禁绿 |
| V-c 删除 3 helper | 未削弱测试 | `RTSC_TEST` 23/47、`CHECK` 57/168 **零变化**；结果 23/69、47/175 不变 |
| V-d 新问题 | 无（1 条 P2 理论弱点） | 纯 ASCII；§19.6 六项零违规；15 套件全绿 |
| 红线约束 | 遵守 | 门禁脚本改后**哈希级恢复验证**；产品代码零改动 |

**新增 1 条 P2（不阻塞）**：
- **B0-08**：`verify.ps1:296-301` 用 `-notmatch` 做**子串**匹配而非行锚定。
  当前不可达（`grep -c` 只输出规范整数），但若门禁脚本将来改用其他计数方式，
  `FAILED_COUNT=01` 会让断言误判通过。建议改 `(?m)^FAILED_COUNT=0$`。

**批 0 收尾确认**：

| 项 | 状态 |
|---|---|
| B0-01（Linux 门禁） | ✅ 已修复并经验证 |
| B0-02（绿证可重放） | ✅ 已修复（脚本固化在 `scripts/`） |
| B0-07（正向断言） | ✅ 已修复，本轮 V-a 自建红证验证有效 |
| U20-5（`#if` 3→2） | ✅ 已修复，本轮 V-b 验证无副作用 + 红证有效 |
| A20-4 / W3（删 helper） | ✅ 已修复，本轮 V-c 验证未削弱测试 |
| A20-2（verbatim 措辞） | ✅ 已修复（CORRECTION） |
| A20-3 / B0-04（crashtest 运行） | ✅ 双方补跑，功能正常 |
| W1 / B0-05（`:63`/`:64`） | ✅ 已定案「保留 + 注释」 |
| **A20-1（§19 红证行号 +2）** | **❌ 未修复** |

#### 12.5.1 A20-1 仍未解决（我必须如实指出）

主代理本轮只声明修了 3 项（B0-07 / U20-5 / A20-4），**没有声称修 A20-1**。
我核查了 `audit-a.md`，**旧行号仍然遍布全文**：

```
[BASH: grep 旧行号]
tls_schannel.cpp:429   -> 6 处
tls_schannel.cpp:230   -> 2 处
tls_schannel.cpp:167   -> 2 处
tls_schannel.cpp:409   -> 3 处
`t:429`                -> 2 处
`t:230`                -> 4 处
`t:167`                -> 1 处
`t:409`                -> 2 处
`:429-431`             -> 1 处
`:409-411`             -> 3 处
TOTAL_STALE_REFS = 26
```

**这些行号全部比实际少 2**（实际是 `:431`/`:232`/`:169`/`:411`）。
最危险的是 §15.1 的 S24 修复指令（`:2761`）写的 `:409-411`，而实际是 `:411-413`。

**缓解措施存在但不完整**：§20 的 N10 已写明
> 「§15.1 的行号在多次修复后必然漂移……执行 AI 每次改前 `Select-String` 重新定位锚点
> （用代码片段对齐行号，不信任行号），改完再确认改的是预期那一行。」

**这是「流程性缓解」，不是「数据性修复」**：文档里的数字仍然是错的，
只能靠执行 AI 每次都记得重新定位。**一旦有人图省事直接照抄行号，就会改错位置。**

**判定**：**A20-1 是 P1，仍未修复。** 不阻塞批 0 的「代码正确性」
（代码本身没问题），但**阻塞批 2 的「执行安全」**——批 2 要改的正是
`tls_schannel.cpp:409-411`（S24）、`:429-433`（S22）、`:230`（S9）这几处。

**建议（批 1 前必做）**：把 `audit-a.md` 里的 26 处旧行号统一替换为锚点文本，
或在 §15.1/§19 的表格里加一列「锚点代码片段」，让行号只作提示不作依据。

**最终计数**：**P0 × 0 / P1 × 1（A20-1 未修复）/ P2 × 1 新增（B0-08）**

*本轮所有影子实验在 `F:\rtsc\.tmp\audit-b0-final\`。门禁脚本已恢复并经 SHA256 验证。*
*产品代码零改动（V-a 的临时替换已完全回滚）。*

---

## 13. A20-1 复核（R-1 / R-2 / R-3）

> **范围**：只复核主代理本轮声称修好的两项（A20-1 行号、A20-6/B0-08 整行锚定）。**不重做批 0 审计。**
> **基线**：`audit-a.md` 376639 B / mtime 2026-10-23 10:54:11。
> **产品代码零改动**（本轮只读 + `.tmp\audit-b0-final\` 内的 PowerShell 逻辑测试）。

### 13.0 结论先行

| 项 | 结论 |
|---|---|
| **R-1** A20-1 是否彻底 | **否**。单点行号已全部归零，但 **5 处范围引用仍是旧值**（详见 §13.1.3） |
| **R-2** A20-6 整行锚定 | **通过**。4 个场景全部符合预期，且对照证明旧写法确实会误接受 |
| **R-3** 最终判定 | **批 0 盖章通过，但 A20-1 未闭环（P1 保留）** |

---

### 13.1 R-1：A20-1 是否真的彻底

#### 13.1.1 单点行号：全部归零 ✅

用我上一轮**完全相同的 10 个模式**重扫（保证可比）：

```
[BASH: 同样的 10 个模式]
tls_schannel.cpp:429 -> 0     `t:429`    -> 0
tls_schannel.cpp:230 -> 0     `t:230`    -> 0
tls_schannel.cpp:167 -> 0     `t:167`    -> 0
tls_schannel.cpp:409 -> 0     `t:409`    -> 0
`:429-431`           -> 0     `:409-411` -> 0
TOTAL_SAME_PATTERNS = 0   (上一轮为 26)
```

**主代理的单点替换是有效的。**

扩大扫描（所有 `tls_schannel.cpp:NNN`，共 70 处），**旧值 `167`/`230`/`409`/`429` 已完全消失**，
只剩新值 `169`/`232`/`411`/`431`：

```
:29->10  :46->1  :66->1  :99->3  :114->1  :135->3  :169->2  :177->1
:179->3  :184->2 :185->1 :192->3  :215->4  :232->2  :241->2  :242->4
:299->1  :369->3 :411->4 :430->1  :431->7  :433->2  :435->1  :462->1
:467->2  :735->5
```

#### 13.1.2 抽查 5 处新行号 —— 全部与真实文件一致 ✅

```
[BASH: Get-Content tls_schannel.cpp 逐行核对]
:169 -> consumed = in_size;                                              ✓
:232 -> if (closed_) return MakeError(Status::kClosed, 0, "already closed");  ✓
:411 -> SecBuffer token{0, SECBUFFER_TOKEN, nullptr};                     ✓
:431 -> if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {              ✓
:433 -> return MakeError(Status::kOk, st, "");                            ✓
```

**5/5 正确。**

#### 13.1.3 但范围引用仍是旧值 —— **5 处真实残留**

我上一轮只扫了单点，漏了**范围**（`A-B` 形式）。这次补扫，发现主代理的两遍脚本
都只处理了 `:NNN` 单点，**没有处理 `:NNN-MMM` 范围**：

| 文档位置 | 文档写的 | 真实位置 | 偏差 |
|---|---|---|---|
| `audit-a.md:2473` | `src/net/tls_schannel.cpp:99-199`(S10) + `:230`(S9) | Handshake `:101-201`、Receive 守卫 `:232` | **+2** |
| `audit-a.md:2814` | `t:99-199` + `t:228-343` | `:101-201`、Receive 体 `:230-345` | **+2** |
| `audit-a.md:2882` | `t:409-433` | Shutdown 体 `:411-435` | **+2** |
| `audit-a.md:2943` | `t:409-411` | token 块 `:411-413` | **+2** |
| `audit-a.md:3075` | `:230`(S9) + `:99-199`(S10 D1) | `:232`、`:101-201` | **+2** |

**证据（真实文件边界）**：
```
[READ:src/net/tls_schannel.cpp:101]  Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,
[READ:src/net/tls_schannel.cpp:201]      }              ← Handshake 结束
[READ:src/net/tls_schannel.cpp:230]  Error Receive(const uint8_t* ciphertext, size_t size,
[READ:src/net/tls_schannel.cpp:345]      }              ← Receive 结束
[READ:src/net/tls_schannel.cpp:411]  SecBuffer token{0, SECBUFFER_TOKEN, nullptr};
[READ:src/net/tls_schannel.cpp:413]  ApplyControlToken(&ctx_, &desc);
[READ:src/net/tls_schannel.cpp:435]  return MakeError(Status::kOk, st, "shutdown best effort");
```

**这些范围引用指向的仍是被批 0 移动过的区域**，偏差与单点一致（+2）。

#### 13.1.4 严重性评估：比单点残留轻，但不是零

**为什么比单点轻**：
- 范围引用（`99-199`）的**容错性**比单点高：执行 AI 在这个范围内 `Select-String` 找锚点，
  即使边界偏 2 行，**仍然能落在正确的函数体内**（`:99` 与 `:101` 都在 Handshake 前的注释区）。
- 单点引用（`:429`）指向的是**精确一行**，偏 2 行就完全改错（`:429` 现在是 `FreeContextBuffer`）。

**为什么仍要修**：
- `audit-a.md:3075` 的 `:230`(S9) 是**单点**，且它就在「批 2 的改动清单」表里——
  **执行 AI 照抄 `:230` 会改到 `Receive` 的签名行**（`:230` 现在是 `Error Receive(...)`），
  不是 `if (closed_)`（`:232`）。这仍是**会改错位置**的 P1 风险。

#### 13.1.5 锚点唯一性（主代理说 S9 命中 3 次，确认）

```
[BASH: Select-String -Pattern 'if \(closed_\)']
:106  if (closed_) return MakeError(Status::kClosed, 0, "already closed");
:209  if (closed_) return MakeError(Status::kClosed, 0, "already closed");
:232  if (closed_) return MakeError(Status::kClosed, 0, "already closed");
count = 3
```

**确认 3 次命中**（`:106` Handshake、`:209` Send、`:232` Receive）。

**主代理的消歧做法正确**：他在文档里写
`src/net/tls_schannel.cpp:232`（0 处锚点 `if (closed_) return MakeError(Status::kClosed` **(inside Receive)**）
—— 加了 `(inside Receive)` 限定。**这解决了歧义，我认可。**

---

### 13.2 R-2：A20-6 / B0-08 的整行锚定

#### 13.2.1 代码确认

```
[READ:verify.ps1:296-305]
296      # Line-anchored, not substring (audit A20-6). A substring test would accept
297      # "FAILED_COUNT=01" or a future "FAILED_COUNT=0 (tolerated 1 warning)", i.e.
298      # exactly the class of weak-signal bug B0-07 was about.
299      foreach ($needle in @('FAILED_COUNT=0', 'WINDOWS_H_COUNT=0', 'FACTORY_SYMBOL=present')) {
300          $anchored = '(?m)^' + [regex]::Escape($needle) + '\r?$'
301          if ($gateOut -notmatch $anchored) {
302              Write-Error "linux build gate output missing an exact '$needle' line"
303              exit 1
304          }
305      }
```

**`(?m)^...\r?$` 整行锚定已就位**（`:300`）。`\r?` 还兼容了 Windows 的 CRLF。

#### 13.2.2 我自建的四种输入验证

**不采信主代理的自述**，我在 `F:\rtsc\.tmp\audit-b0-final\r2_test.ps1` 里
**逐字复现 `:300` 的表达式**，喂 4 种输入：

```
[BASH: powershell -File r2_test.ps1]
case1 normal              -> ACCEPT
case2 FAILED_COUNT=01     -> REJECT(missing: FAILED_COUNT=0)
case3 trailing text       -> REJECT(missing: FAILED_COUNT=0)
case4 CRLF line endings   -> ACCEPT
```

**全部符合预期**：
- **case1**（正常值）→ 接受 ✓
- **case2**（`FAILED_COUNT=01`，即实际失败 1 个）→ **拒绝** ✓（旧写法会接受）
- **case3**（`FAILED_COUNT=0 (tolerated 1 warning)`）→ **拒绝** ✓（旧写法会接受）
- **case4**（CRLF 行尾，Windows 管道的实际形态）→ 接受 ✓（`\r?` 生效）

**对照实验（证明这个修复是必要的）**：
```
OLD substring would accept case2? True   (bug)
OLD substring would accept case3? True   (bug)
```
**旧的子串写法确实会把 case2/case3 误判为通过。** B0-08 是真实缺陷，修复有效。

#### 13.2.3 正常路径未被破坏

```
[BASH: powershell -File verify.ps1 -LinuxBuild]
CONFIGURE_EXIT=0
BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_COUNT=0
LIB_BYTES=254140
FACTORY_SYMBOL=present
CTEST_EXIT=0
100% tests passed, 0 tests failed out of 15
LINUX GATE PASS

  linux build gate passed
GREEN_EXIT=0
```

**新正则没有破坏正常路径。**

---

### 13.3 R-3：最终判定

> ### 批 0 最终盖章通过（但 A20-1 未闭环，P1 保留）

#### 13.3.1 为什么仍判「通过」

批 0 的**代码正确性**与**门禁有效性**均已独立验证：

| 维度 | 状态 |
|---|---|
| S21 修复（跨平台） | ✅ 红证 + 绿证 + `nm` 符号级证据 |
| Windows 行为不变 | ✅ 15 套件逐项与基线相同 |
| S0.9 四行 | ✅ 删除实验证明是死代码标记 |
| Linux 门禁（B0-01/02） | ✅ 红绿双验有效 |
| B0-07 正向断言 | ✅ 我自建红证（桩门禁 → exit=1） |
| A20-6 整行锚定 | ✅ 4 场景验证，旧写法确会误接受 |
| U20-5 `#if` 3→2 | ✅ `nm` 证明零符号污染 + 红证 |

**A20-1 是「文档数据缺陷」，不是「代码缺陷」**——它不影响批 0 的交付物正确性。

#### 13.3.2 但 A20-1 必须记为未闭环

**5 处范围引用仍是旧行号**（§13.1.3）。其中 `audit-a.md:3075` 的 `:230`(S9) 是**单点**，
且位于「批 2 改动清单」表内 —— 照抄会改到 `Error Receive(...)` 签名行而非 `if (closed_)`。

**建议（批 2 开工前）**：
1. 用同一套脚本补处理 `:NNN-MMM` 范围形式（主代理的两遍脚本只处理了单点）；
2. 或直接在 §15.1 / §19 / §18 的表格里，把「文件:行」列改为「锚点代码片段」列，
   行号只作提示。

**最终计数：P0 × 0 / P1 × 1（A20-1 未闭环）/ P2 × 0（B0-08 已修复）**

*本轮只读；唯一写入是 `F:\rtsc\.tmp\audit-b0-final\r2_test.ps1`（逻辑测试脚本，不进构建）。*
*`ctest` 16/16；`verify.ps1 -LinuxBuild` exit=0。*

---

## 14. A20-1 最终修复复核（R-1 / R-2 / R-3）

> **范围**：只复核主代理本轮声称的「语义判据」修复。不重做批 0 审计。
> **基线**：`audit-a.md` 389540 B / mtime 2026-10-23 11:11:43。
> **产品代码零改动**（只读 + `.tmp\audit-b0-final\` 的 Python 校验脚本）。

### 14.0 结论先行

| 项 | 结论 |
|---|---|
| **R-1** 59 处带锚点引用 | **全部正确**（0 mismatch）。`:432` 指向 Shutdown 内那个 `closed_ = true;`，**主代理对我错** |
| **R-2** 我上轮 5 处范围发现 | **3 处已修**，**2 处仍是旧值**（`L2814`、`L2943`）；且我上轮**确实没覆盖「原引用本身差 1」这一类** |
| **R-3** 最终判定 | **A20-1 仍未闭环（P1 保留），但批 0 代码交付可盖章** |

---

### 14.1 先承认：我上轮抽查 `:431` 是循环论证

主代理指出我用**他给的锚点**去验证**他的行号**，这是自我印证，不是独立验证。**这个批评成立。**

我上轮写「`:431` → `if (st == SEC_E_OK || SEC_I_CONTINUE_NEEDED) {` ✓ 与真实文件一致」——
**行号确实对上了，但文档语义是「`Shutdown()` 也会置 `closed_=true`」，应该指向 `:432`（赋值行）而不是 `:431`（if 行）。**

**这次改用语义判据**：先从文档散文读出「它指的是哪个构造」，再到源码定位，最后比对。

### 14.2 R-1：59 处带锚点引用全部正确

#### 14.2.1 独立重扫

```
[BASH: python r1_final.py]
anchored=59 mismatch=0
```

我的脚本做三件事：
1. 用正则 `(?:src/net/)?(tls_schannel|tls_factory)\.cpp:(\d+)(?:-(\d+))?[^|]{0,40}?锚点\s*`...`` 提取全部「引用 + 锚点」对；
2. 到**对应源文件**（`tls_schannel.cpp` 或 `tls_factory.cpp`）取该行/区间；
3. 断言锚点文本（规范化空白后）出现在区间内。支持三种锚点形态：
   单片段、`X .. Y` 范围、`X (in Func)` 消歧。

**59 处，0 mismatch。**

#### 14.2.2 特别核实 `:432`（主代理要求）

```
[BASH: Select-String -Pattern '^\s*closed_ = true;']
LineNumber=304 : closed_ = true;
LineNumber=432 : closed_ = true;

[BASH: 找各自所属函数]
:304  enclosed by -> Error Receive(const uint8_t* ciphertext, size_t size,
:432  enclosed by -> Error Shutdown(std::vector<uint8_t>& out) override {
```

**`:432` 属于 `Shutdown`，`:304` 属于 `Receive`。**
文档说「`Shutdown()` 也会置 `closed_=true`」→ **必须指 `:432`**。

```
[READ:audit-a.md:527]
| `Shutdown()` 也会置 `closed_=true` | `src/net/tls_schannel.cpp:432`，锚点 `closed_ = true;  (in Shutdown)` |
```

**主代理修对了，我上轮的 `:431` 判断是错的。**
（`:431` 是 `if (st == SEC_E_OK || SEC_I_CONTINUE_NEEDED) {`，`:432` 才是赋值。）

#### 14.2.3 抽查 8 处（语义驱动，不采信锚点）

我抽了不同章节的 8 处，逐条读散文 → 定位 → 比对：

| 文档行 | 引用 | 文档语义 | 实际内容 | 判定 |
|---|---|---|---|---|
| `:66` | `:217` | `Send` 内按 `max_chunk` 切分 | `const size_t chunk = MaxChunk();` | ✅ |
| `:100` | `:252` | `TlsTransport::Receive` 内的 record 头解析 | `if (!ParseRecordHeader(...))` | ✅ |
| `:161` | `:185` | `kNeedMoreInput`（握手不完整） | `return MakeError(Status::kNeedMoreInput, st, "incomplete handshake");` | ✅ |
| `:162` | `:192` | `kCertRejected` 映射 | `case SEC_E_UNKNOWN_CREDENTIALS:` | ✅ |
| `:163` | `:179` | `kUnsupported`（要求客户端证书） | `case SEC_I_CONTINUE_NEEDED:` | ✅ |
| `:527` | `:432` | `Shutdown` 置 `closed_=true` | `closed_ = true;`（in Shutdown） | ✅ |
| `:897` | `:29-32` | 四个 Windows 头无条件 include | `:29 #include <windows.h>` … `:32 #include <wincrypt.h>` | ✅ |
| `:1834` | `:469` | `ProtocolMask` 的 1.2 判断 | `if (config_.min_version <= kTls12` | ✅ |

**8/8 正确。**

#### 14.2.4 12 处无锚点的引用：逐一分类

```
[BASH: 提取无锚点的 tls_schannel.cpp:NNN]
total_refs=69 with_anchor=57 without=12
```

| 位置 | 引用 | 性质 | 判定 |
|---|---|---|---|
| `L3295`/`L3683`/`L3746`/`L4205`/`L4612`/`L4623`/`L4771`/`L5098` | `:29` | **编译器错误信息原文**（`tls_schannel.cpp:29:10: fatal error: windows.h`） | ✅ 不需锚点（`:29` 就是 `#include <windows.h>`，从未移动） |
| `L4463` | `:431-435` | 探针注释「copied verbatim from」 | ✅ 区间正确（`:431` if … `:435` return best effort） |
| `L5504`/`L5507` | `:735-752` | **甲自己的诊断输出**（记录「旧引用 735-752 已失效、内容已搬到 factory」） | ✅ 是证据，不是待修引用 |

**12 处全部合理，无需修。**

#### 14.2.5 R-1 判定

**59 处带锚点引用 0 mismatch；12 处无锚点引用全部是「编译器输出 / 探针注释 / 诊断证据」，不需要锚点。**
**R-1 通过。**

---

### 14.3 R-2：我上轮的 5 处范围发现，只修了 3 处

#### 14.3.1 我上轮报的 5 处（现在是 `t:NNN` 裸形式，主代理的锚点扫描正则未覆盖）

```
[BASH: python r2_trefs.py]
total bare t: refs = 32
suspicious (start/end at an OLD value) = 7
```

**关键**：主代理的锚点扫描只匹配 `tls_schannel.cpp:NNN`（带 `.cpp` 前缀），
**裸 `t:NNN` 形式不在扫描范围内**——所以 59 处的「0 mismatch」**不覆盖**这 32 处。

逐一分类这 7 处：

| 位置 | 引用 | 实际内容 | 性质 | 判定 |
|---|---|---|---|---|
| `L2814` | `t:99-199` | `:99` 是空行（Handshake 实为 `:101-201`） | **规格引用**（§17.7.3「D1 只改 Handshake…不动 Receive」） | ❌ **仍是旧值** |
| `L2814` | `t:228-343` | `:228` 是空行（Receive 实为 `:230-345`） | 同上 | ❌ **仍是旧值** |
| `L2943` | `t:405` | `:405` = `out.clear();`（`have_ctx_` 在 `:407`） | **规格引用**（§18.0.5 失败路径分析） | ❌ **仍是旧值** |
| `L2943` | `t:409-411` | `:409` = `return MakeError(Status::kOk, 0, "");`（token 在 `:411-413`） | 同上 | ❌ **仍是旧值** |
| `L2882` | `t:409-433` | `:409` 同上 | **叙述**（「行号已经移动了，逐字核对…」），同段 `:2886-2887` 已用新值 `:413`/`:431`/`:435` | ✅ 是证据 |
| `L5452` | `t:429` | `:429` = `FreeContextBuffer(...)` | **我的扫描报告文本**（「6 处 `t:429` 2 处，我复扫得 **0**」） | ✅ 是证据 |
| `L5463` | `t:409-411` | 同上 | **我的文本**（「范围 `t:NNN-MMM`，如 `t:489-507`、`t:409-411`」） | ✅ 是证据 |

#### 14.3.2 我上轮的 5 处现在状态

| 我上轮报的 | 现在 | 状态 |
|---|---|---|
| `L2473` `:99-199`(S10) + `:230`(S9) | 范围已改为 `:101-201`（带锚点），但**同行 `:230`(S9) 仍是旧值** | ⚠️ **部分修复** |
| `L2814` `t:99-199` + `t:228-343` | **仍是 `t:99-199` + `t:228-343`** | ❌ **未修** |
| `L2882` `t:409-433` | 仍是（但属证据叙述，同段已用新值） | ✅ 不需修 |
| `L2943` `t:409-411` | **仍是 `t:409-411`**（且 `t:405` 也错） | ❌ **未修** |
| `L3075` `:230`(S9) + `:99-199`(S10 D1) | 同行前半已用新值（`:411`/`:431-435`），但**后半仍是 `:230` 和 `:99-199`** | ⚠️ **部分未修** |

**实测确认**（`Select-String` 逐行匹配）：
```
[L2473] :101-201 -> True   :99-199 -> False   :230 -> True    :232 -> False
[L3075] :411     -> True   :431-435-> True    :230 -> True    :99-199 -> True
```

**核实 `L3075` 当前内容**：
```
[READ:audit-a.md:3075]
| **批2** TLS 后端 | ... | `src/net/tls_schannel.cpp:411`，锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`，(S24-a)、
`:411`(S24-c)、`:431-435`，锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`，(S24-b+S22)、
`:230`(S9)、`:99-199`(S10 D1)、`tls.h:1...
```

**同一行内混合了新值（`:411`/`:431-435`）和旧值（`:230`/`:99-199`）。**

#### 14.3.3 我必须承认的方法缺陷（主代理指出，成立）

主代理说：「你的发现是对的，但**只覆盖了范围引用，没覆盖「原引用本身差 1」这一类**。」

**这个批评成立。** 我上轮的判据是「文档行号 vs 真实行号」的**机械比对**，
它只能发现「整批 +2 没跟上」，**发现不了**：
- **原引用本身语义就错**（`:429` 说「置 `closed_=true`」但 `:429` 是 if 行，正确是 `:430`）
- **内容搬迁**（工厂函数从 `tls_schannel.cpp` 搬到 `tls_factory.cpp`）
- **裸 `t:NNN` 形式**（我的 10 个模式全带 `.cpp` 前缀或反引号，漏了裸形式）

我上轮报「26 → 0」时，**统计口径本身就窄**。这是真实的方法缺陷。

#### 14.3.4 R-2 判定

**我上轮 5 处中：1 处已修（`L2473`）、1 处部分修（`L3075`）、2 处未修（`L2814`、`L2943`）、1 处不需修（`L2882`）。**
**且 `L2943` 还多出一处我上轮没发现的 `t:405`（应为 `:407`）。**

**A20-1 未闭环。**

---

### 14.4 R-3：最终判定

> ### 批 0 代码交付可盖章，但 A20-1 仍未闭环（P1 保留）

#### 14.4.1 批 0 交付物本身（代码 + 门禁）—— 全部通过

| 维度 | 状态 | 证据来源 |
|---|---|---|
| S21 跨平台修复 | ✅ | 红证（还原 CMake → `windows.h` 错误）+ 绿证 + `nm` 零符号 |
| Windows 行为不变 | ✅ | 15 套件逐项与基线相同 |
| S0.9 四行 | ✅ | 删除实验（23/69、47/175 不变） |
| Linux 门禁 | ✅ | 红绿双验（桩门禁 → exit=1；S21 注入 → `WINDOWS_H=2`） |
| B0-07 正向断言 | ✅ | 4 场景验证 |
| A20-6 整行锚定 | ✅ | 4 场景验证 + 对照证明旧写法误接受 |
| U20-5 `#if` 3→2 | ✅ | `nm` 零符号 + 注入红证 |
| **A20-1 文档行号** | ❌ | **本 §14.3** |

**代码层面零缺陷。** A20-1 是**文档数据缺陷**，不改变任何代码行为。

#### 14.4.2 但 A20-1 必须记为未闭环 —— 具体残留清单

| # | 位置 | 现状 | 应为 | 风险 |
|---|---|---|---|---|
| 1 | `audit-a.md:2814` | `t:99-199` | `t:101-201` | 中（范围，容错高） |
| 2 | `audit-a.md:2814` | `t:228-343` | `t:230-345` | 中 |
| 3 | `audit-a.md:2943` | `t:405` | `t:407` | **高**（单点，`:405` 是 `out.clear()`） |
| 4 | `audit-a.md:2943` | `t:409-411` | `t:411-413` | **高**（`:409` 是 `return kOk`） |
| 5 | `audit-a.md:3075` | `:230`(S9) | `:232` | **高**（在批 2 改动清单内，`:230` 是 `Error Receive(` 签名） |
| 6 | `audit-a.md:3075` | `:99-199`(S10 D1) | `:101-201` | 中 |

**第 3/4/5 条是单点引用且指向错误构造，与 A20-1 原始风险同性质。**

#### 14.4.3 建议（批 2 开工前必做）

1. **扩展扫描正则**：主代理的 `verify_a201.py` 只匹配 `tls_schannel.cpp:NNN`，
   需增加 `` `t:NNN` `` / `` `t:NNN-MMM` `` 两种裸形式（共 32 处，其中 7 处可疑）；
2. **区分「规格引用」与「证据叙述」**：`L2882`/`L5452`/`L5463` 描述的是「旧状态」，
   不应机械替换（否则会把证据改成假话）；
3. **保留锚点机制**：59 处带锚点的做法是对的，建议给裸 `t:NNN` 也补锚点。

#### 14.4.4 最终计数

**P0 × 0 / P1 × 1（A20-1 未闭环，6 处残留）/ P2 × 0**

*本轮只读。校验脚本在 `F:\rtsc\.tmp\audit-b0-final\`（`r1_final.py` / `r2_trefs.py`），不进构建。*
*`ctest` 16/16；`verify.ps1 -LinuxBuild` exit=0（上一轮已验，本轮未改动任何工程文件）。*

---

## 15. A20-1 二次复核（父代理指正后的独立验证）

> **基线**：`audit-a.md` 407534 B / mtime 2026-10-23 11:34:52 / 5962 行。
> **触发**：父代理指我「类别对、数量低估、且混淆 §18 与 §19」。
> **方法**：全部自行实测，不采信父代理贴的输出。

### 15.0 结论先行

| 项 | 父代理主张 | 我的独立结论 |
|---|---|---|
| **R-1** 6 处所在章节 | 全在 §18 及之前，不在 §19 | **✅ 成立**（实测在 §17.7.3 / §18.0.5 / §18.2.1）；**我的 P1 判定错误，降为 P3** |
| **R-2** §19.4 有 8 处旧行号 | `:409`/`:429`/`:178`/`:230`/`:430` | **❌ 不成立**（当前文档已是正确值）；**但父代理的扫描快照 11:31:08 确实含旧值，文档在 11:34:52 被改** |
| **R-2 附** `doc:4021 :178` 批 0 前就错 | 差 2 不是 +2 | **❌ 不成立**（备份 `:178` = `return MakeError(Status::kNeedMoreInput, 0, "")`，批 0 前就是对的） |
| **R-3** v3 验证器有区分力 | 有 | **✅ 成立**（我自造 4 个红证全部检出，绿证 16/0） |
| **R-3 附** v3 无硬编码 | 声称已修 | **❌ 仍有 `EXPECT` 字面量表**（`:35-48`），与它批评的 v2 同病 |
| **R-4** 最终判定 | A20-1 已闭环 | **§19 零过期导航引用成立**（27 处人工核：22 OK / 5 历史步骤 / **0 STALE**） |

---

### 15.1 R-1：我的 P1 判定错误，应为 P3

#### 15.1.1 实测章节归属

```
[BASH: python 逐行回溯最近的 # 标题]
  doc:2814 -> §17 (header at 2808): #### 17.7.3 结论
  doc:2943 -> §18 (header at 2935): #### 18.0.5 顺序：S22 加…
  doc:3075 -> §18 (header at 3069): #### 18.2.1 修订后…
```

§19 实际边界（实测）：**3205（`## 19. 执行交接包`）到 4213**（`## 20. 批 0 审计验证` 起于 4214）。

**我上轮报的 3 处（含 6 个错引用）全在 §17/§18，一处都不在 §19。**
我甚至在 §14 里自己写出过「§17.7.3」却仍判 P1 —— **这是级别判定错误，不是数据错误。**

#### 15.1.2 我接受父代理的级别论证

| 位置 | 读者 | 后果 | 级别 |
|---|---|---|---|
| §19 执行交接包 | 执行 AI | **直接改错代码行** | P1 |
| §17/§18 缺陷分析 | 后续复核者 | 定位困难，不会直接改错 | **P3** |

**我明确写进报告：我的 P1 判定错误，应为 P3。**

#### 15.1.3 但我要指出父代理的一处口径问题

父代理说「你报的 6 处全在 §18」。**实测 §17.7.3 那处在 §17，不是 §18。**
不影响级别结论（§17 同样非执行包），但「全在 §18」这个表述不准确。

---

### 15.2 R-2：§19.4 的 8 处 —— 父代理结论与当前文档不符

#### 15.2.1 当前文档实测：8 处全部是正确值

```
[BASH: 读 doc:4002/4007/4021/4030/4053/4054/4123 原文 + 读源码对应行]

doc:4002  #### 陷阱 2：S24 只改 `:411`（token）不改 `:431`（成功判定）
  cur:411 = SecBuffer token{0, SECBUFFER_TOKEN, nullptr};        ✅
  cur:431 = if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {  ✅

doc:4007  // 只把 token 改对，:431 原样留着
  cur:431 ✅

doc:4021  …（`:180` 就把它当 `kNeedMoreInput`）
  cur:180 = return MakeError(Status::kNeedMoreInput, 0, "");     ✅

doc:4030  …`Receive` 在 `:232` 短路…
  cur:232 = if (closed_) return MakeError(Status::kClosed, …     ✅

doc:4053  …没有任何测试能抓到 `:431`…                             ✅
doc:4054  …必须贴出 `:431` 附近的 diff…                           ✅

doc:4123  …只改 `:232`…但 `:432` 仍无条件 `closed_=true`
  cur:232 ✅   cur:432 = closed_ = true;                          ✅
```

**8 处引用、0 处错。** 父代理给的「正确值」（`:411`/`:431`/`:180`/`:232`/`:432`）正是**当前文档里已经写着的值**。

#### 15.2.2 为什么父代理会看到旧值 —— 时间线证据

```
[BASH: Get-Item 时间戳]
  11:31:08   6982 B  .tmp\sec19.txt          ← 父代理扫描快照（含 :409/:429/:178/:230/:430）
  11:31:39  17374 B  .tmp\sec19_full.txt     ← 同上
  11:34:52 407534 B  docs\...audit-a.md      ← 文档被改（旧值 → 新值）
  11:37:14   2776 B  .tmp\sec19_redtest.py   ← 父代理红证脚本
  11:42:03   4643 B  evidence\exec\verify_sec19.py
```

父代理的 `sec19.txt`（11:31:08）确实含 `:409`/`:429`/`:178`/`:230`/`:430`。
**但 `audit-a.md` 在 11:34:52 被修改，这 8 处已被改成正确值。**
父代理在 11:42 跑验证器得到 16/0 时，读的是**已修好的**文档 —— 他的红证脚本（11:37）也是修好之后跑的。

**结论：父代理报的 8 处「真 P1」在他发消息时已经不存在了。** 这是并发写入导致的陈旧结论，不是我的漏检。

#### 15.2.3 `doc:4021 :178` 的「批 0 前就错」论断不成立

```
[BASH: 读备份 src_net_tls_schannel.cpp.20261023-085223]
  bak:177 = case SEC_I_CONTINUE_NEEDED:
  bak:178 = return MakeError(Status::kNeedMoreInput, 0, "");   ← 正是目标构造
  bak:179 = case SEC_I_INCOMPLETE_CREDENTIALS:
```

**批 0 前 `:178` 就是 `kNeedMoreInput` 返回，引用是对的。**
父代理说「批 0 前 `:178` 是 `case SEC_I_CONTINUE_NEEDED:`，`:180` 才是返回，原引用差 2」—— **与备份不符**。
（批 0 后 `:178` 变成 `return MakeError(Status::kOk, 0, "")`，`:180` 才是 `kNeedMoreInput`，那是 **+2 位移**，不是「原引用差 2」。）

#### 15.2.4 我另外发现：§19 里确有 4 处过期引用，但属历史步骤

我全量扫 §19（3205-4213）**全部 27 处引用**，除父代理那 8 处外，发现 §19.2.2 有 4 处 CMakeLists 引用：

| doc 行 | 引用 | 备份 CMakeLists | 当前 CMakeLists |
|---|---|---|---|
| 3499 | `:48-55` | `# TLS transport.` + `add_library(rtsc_tls STATIC src/net/tls_schannel.cpp)` | `# TLS transport, three layers (S21 / M28).` + `add_library(rtsc_tls_api INTERFACE)` |
| 3528 | `:105-107` | `add_executable(rtsc_tls_tests tests/test_tls.cpp)` | `add_executable(rtsc_licensing_tests …)` |
| 3538 | `:152` | `add_test(NAME tls COMMAND rtsc_tls_tests)` | `target_link_libraries(rtsc_crashtest …)` |
| 3546 | `:170` | `target_compile_options(rtsc_tls_tests PRIVATE /W4 /WX)` | `add_test(NAME credssp …)` |

**但这 4 处不是导航缺陷**，理由是散文语义明确：

```
doc:3497  **步骤 S0.5 —— 改 CMakeLists.txt 三处**
doc:3499  **(a) 替换 `:48-55`**（原来的注释 + `add_library` 整段）为：
doc:3528  **(b) 把 `:105-107` 包进 `if(WIN32)`**：
```

「**替换** `:48-55`」「**原来的**注释」—— 描述的是**批 0 执行前**的现状，属历史步骤记录。
且批 0 已完成并验证：

```
[BASH: 检查 CMakeLists.txt]
  add_library(rtsc_tls_api INTERFACE)                      True   ← (a) 已落地
  add_library(rtsc_tls_schannel STATIC)                    True   ← (a) 已落地
  add_library(rtsc_tls STATIC src/net/tls_factory.cpp)     True   ← (a) 已落地
  add_test(NAME tls COMMAND rtsc_tls_tests)                True   ← (c) 已落地
  target_compile_options(rtsc_tls_tests PRIVATE /W4 /WX)   True   ← (d) 已落地
```

同类：`doc:3375` 的 `:733-754`（「步骤 S0.3 —— 改 tls_schannel.cpp 的尾部」「现状（`:733-754`）」）
描述的也是批 0 前的旧尾部（`CreateTlsTransport` 在 `tls_schannel.cpp`），批 0 已把它搬到
`tls_factory.cpp` 并改名 `CreateSchannelTransport`。**历史记录，非导航。**

**建议（P3）**：给这类「步骤 X —— 改 Y 的 `:NNN`」加一句「（批 0 已执行，行号为执行前）」，
避免后续读者把它当当前导航。

---

### 15.3 R-3：v3 验证器有区分力，但仍有硬编码

#### 15.3.1 我自造红证（影子文档，真实文档零改动）

```
[BASH: python r3_redtest.py]
case                                       exit  OK   MISM   verdict
GREEN untouched                            0     16   0      PASS
RED doc:4002 :411 -> :409                  1     15   1      DETECTED
RED doc:4021 :180 -> :178                  1     15   1      DETECTED
RED doc:4030 :232 -> :230                  1     15   1      DETECTED
RED doc:4123 :432 -> :430                  1     15   1      DETECTED

red cases detected: 4/4
green baseline     : PASS
real doc unchanged : True
```

做法：把 `audit-a.md` 复制到 `.tmp\audit-b0-final\redshadow\`，把验证器的 `DOC` 路径重指向影子副本，
逐条把引用改回批 0 旧值，跑验证器。**4/4 全部报 MISMATCH + exit=1**，绿证 16/0 exit=0，
真实文档字节不变（`real doc unchanged : True`）。

**结论：v3 有真实区分力，不是自证。**

#### 15.3.2 但 v3 仍有硬编码表 —— 父代理自己的判据不满足

父代理在消息里给了一条判据：

> **判据：验证器里出现「预期行号」字面量，就说明它测的是自己的记忆。**

`verify_sec19.py:35-48` 正是这样一张表：

```python
EXPECT = {
    3421: ('tls', '#include "rtsc/net/tls.h"'),
    ...
    4002: ('tls', 'SecBuffer token{0, SECBUFFER_TOKEN, nullptr};'),
    ...
}
```

它没有「预期**行号**」字面量（用 doc 行做 key 是合理的），但**有「预期构造」字面量表**。
这比 v2 好（v2 是「行号 → 行号」），但仍是「人工维护的期望表」：
**若文档某条引用改对了构造但换了位置，表不会自动跟上；若表本身写错，验证器会把错的判成对。**

真正无记忆的判据应是：**从散文里抽锚点文本**（不是硬编码），再到源码定位。
父代理要求我做的这件事（§14.2 我做过：`r1_final.py` 从文档抽 `锚点` 后面的反引号内容）才是无记忆版本。

**这是 P3 建议，不影响 v3 的区分力结论。**

#### 15.3.3 我复核父代理的 v1/v2 缺陷描述

父代理说 v1「只查行号 ≤ 文件行数」、v2「硬编码 EXPECT 表所以不读文档」。
**v2 的缺陷描述准确**（确实有 EXPECT 表且表里的 needle 是常量）；v1 我无副本可查，不做判断。

---

### 15.4 §19 全量扫描（我的补充，父代理未做）

```
[BASH: python sec19_all.py]
TOTAL citations in 3205..4213 = 27
```

27 处逐条人工核完，分类：

| 类别 | 数量 | 判定 |
|---|---|---|
| `tls_schannel.cpp:29`（编译器错误原文） | 4 | ✅ 正确（`:29` 是 `#include <windows.h>`，从未移动） |
| 陷阱 2 的 `:411`/`:431`（doc:4002/4007/4053/4054） | 5 | ✅ 正确 |
| `:180`（doc:4021）、`:232`/`:432`（doc:4030/4123） | 4 | ✅ 正确 |
| `:232` + 旧 `:429`（doc:3805，**叙述旧行号**「实测旧 `:429` 现在指向」） | 2 | ✅ 正确（叙述） |
| CMakeLists 步骤 (a)(b)(c)(d)（doc:3499/3528/3538/3546） | 4 | ✅ 历史步骤（见 15.2.4） |
| `:733-754`（doc:3375，S0.3 现状） | 1 | ✅ 历史步骤 |
| `:40`（doc:3421，`#include "rtsc/net/tls.h"` 之后） | 1 | ✅ 正确（`:40` 确实是该 include） |
| `:93-94`（doc:3780，credssp.cpp S5） | 1 | ✅ 正确（`:93` = `if (!e.ok()) return Fail(...)`） |
| `:357-360`（doc:3782，credssp.cpp S11） | 1 | ✅ 正确（`ciphertext` 在 `:357`） |
| `:168`（doc:3884，**connect_machine.cpp** S20） | 1 | ✅ 正确（`connect_machine.cpp:168` = `pdu.info.password = credentials_.password;`）。**我上一稿误归到 credssp.cpp，已更正** |
| `:191`（doc:3958，credssp.cpp S1 nonce） | 1 | ✅ 正确（`nonce_.begin() + 8` 在 `:191`） |
| `:745`/`:792`（doc:4102，tests/test_tls.cpp） | 2 | ✅ 正确（都在 `Send` 上下文） |

**§19 内 0 处真过期。**

#### 15.4.1 我上一稿在这里犯了一个错，必须记录

我最初把 `doc:3884` 的 `:168` 归到 `credssp.cpp`，判它「指向空行、真过期」。
**实测该引用属 `connect_machine.cpp`：**

```
[BASH: 读 src/proto/connect_machine.cpp]
  :165 if (credentials_.autologon) pdu.info.flags |= info::kAutoLogon;
  :166 pdu.info.domain = credentials_.domain;
  :167 pdu.info.user_name = credentials_.user_name;
  :168 pdu.info.password = credentials_.password;      ← 正是 S20 说的「无条件回填 password」
  :169 pdu.info.alternate_shell = credentials_.alternate_shell;
```

**`:168` 完全正确。** 我的错因：用「裸 `:NNN` → 最近的文件名 token」做归属，
而该行散文里没有文件名，脚本回溯时抓到了错误的祖先文件名（credssp）。
这与 §15.3.2 我批评父代理「硬编码期望表」是同一类问题：**归属靠启发式，就会错。**

**修正后的做法**：§19 的 27 处引用**逐条人工读散文判定归属与语义**（脚本只做行号取值，不做归属推断）。

#### 15.4.2 27 处最终人工判定

| 判定 | 数量 | 说明 |
|---|---|---|
| **OK** | **22** | 引用行号与散文所指构造一致 |
| **历史步骤** | **5** | 批 0 的「改之前现状」描述，批 0 已执行（见 15.2.4） |
| **STALE** | **0** | — |

明细（脚本 `hand19.py`，逐条打印实际源码行供核对）：

```
OK   doc:3295  tls_schannel.cpp     :29   '#include <windows.h>'
HIST doc:3375  tls_schannel.cpp     :733  step S0.3 "现状"（批 0 前尾部）
OK   doc:3421  tls_schannel.cpp     :40   '#include "rtsc/net/tls.h"'
HIST doc:3499  CMakeLists.txt       :48   step S0.5(a)（批 0 前块）
HIST doc:3528  CMakeLists.txt       :105  step S0.5(b)（批 0 前块）
HIST doc:3538  CMakeLists.txt       :152  step S0.5(c)（批 0 前 add_test）
HIST doc:3546  CMakeLists.txt       :170  step S0.5(d)（批 0 前 /WX）
OK   doc:3683  tls_schannel.cpp     :29
OK   doc:3746  tls_schannel.cpp     :29
OK   doc:3780  credssp.cpp          :93   'if (!e.ok()) return Fail(...)'
OK   doc:3782  credssp.cpp          :357  'const Bytes ciphertext(...'
OK   doc:3805  tls_schannel.cpp     :232  closed_ 守卫（新值，正确）
OK   doc:3805  tls_schannel.cpp     :429  叙述「实测旧 :429 现在指向 FreeContextBuffer」
OK   doc:3884  connect_machine.cpp  :168  'pdu.info.password = credentials_.password;'
OK   doc:3958  credssp.cpp          :191  'nonce_.begin() + 8'
OK   doc:4002  tls_schannel.cpp     :411  'SecBuffer token{...}'
OK   doc:4002  tls_schannel.cpp     :431  'if (st == SEC_E_OK || ...'
OK   doc:4007  tls_schannel.cpp     :431
OK   doc:4021  tls_schannel.cpp     :180  'return MakeError(Status::kNeedMoreInput, 0, "")'
OK   doc:4030  tls_schannel.cpp     :232
OK   doc:4053  tls_schannel.cpp     :431
OK   doc:4054  tls_schannel.cpp     :431
OK   doc:4102  test_tls.cpp         :745  'CHECK_EQ(consumed, pt.size());'
OK   doc:4102  test_tls.cpp         :792  'CHECK_EQ(consumed, pt.size());'
OK   doc:4123  tls_schannel.cpp     :232
OK   doc:4123  tls_schannel.cpp     :432  'closed_ = true;'
OK   doc:4205  tls_schannel.cpp     :29
```

#### 15.4.3 关于「§19.4 的 8 处」

父代理列的 8 处（`doc:4002/4007/4021/4030/4053/4054/4123`）在当前文档中**全部正确**（见上表）。
他的扫描快照 `sec19.txt`（11:31:08）里确实是旧值，但文档在 **11:34:52** 被改成新值（见 15.2.2 时间线）。

---

### 15.5 R-4：最终判定

> ### A20-1 的 §19 执行交接包：**零过期导航引用成立**（27 处人工核，0 STALE）
> ### 但「全文闭环」需加限定：§17/§18 仍有 6 处过期引用（P3）

#### 15.5.1 逐项定论

| 项 | 判定 | 依据 |
|---|---|---|
| **§19 导航引用是否会让批 2 改错代码** | **不会** | 27 处逐条人工核：22 OK / 5 历史步骤 / 0 STALE |
| **父代理报的 §19.4 八处** | **在我核实时已不存在** | 文档 11:34:52 被改；父代理快照 11:31:08 |
| **我的 6 处 P1 判定** | **错误，应为 P3** | 全在 §17/§18，不在 §19 |
| **v3 验证器区分力** | **真实**（4/4 红证检出） | 我自造影子红证 |
| **v3 是否无记忆** | **否**（仍有 EXPECT 表） | `verify_sec19.py:35-48` |
| **`doc:3884 :168`** | **正确**（我上一稿误判） | 属 `connect_machine.cpp`，`:168` = `pdu.info.password = credentials_.password;` |

#### 15.5.2 为什么不给「完全闭环」

「闭环」若指「§19 无任何会让执行 AI 改错位置的引用」—— **成立**：27 处人工核，22 OK / 5 历史步骤 / **0 STALE**。

「闭环」若指「全文行号引用 100% 正确」—— **不成立**：§17/§18 尚有 6 处（P3）。
这 6 处不在执行包内，读者是后续复核者，不会直接导致改错代码。

**我的判定：A20-1 的 P1 风险已消除（§19 导航 0 STALE），§17/§18 残留 6 处记 P3。**

#### 15.5.3 计数

**P0 × 0 / P1 × 0（A20-1 的 P1 风险已消除）/ P3 × 6**

六处全在 §17/§18：`doc:2814`×2（`t:99-199`、`t:228-343`）、`doc:2943`×2（`t:405`、`t:409-411`）、`doc:3075`×2（`:230`、`:99-199`）——
我上轮报的就是这六处，**级别从 P1 降 P3**（章节归属论证见 15.1）。

#### 15.5.4 我本轮的三处自我更正

1. **级别错误**：6 处判 P1 → 应为 P3（不在 §19 执行包）。
2. **文件归属错误**：`doc:3884 :168` 我归到 `credssp.cpp` 判「真过期」→ 实属 `connect_machine.cpp`，且**完全正确**。
3. **计数口径错误**：我上轮「59 处」不含裸 `t:NNN`（44 处）与裸 `:NNN`；本轮的 27 处是 §19 范围内的人工全量。

**这三处都是「用脚本启发式代替人工读散文」造成的。** 教训：行号引用审计的归属与语义判定必须人工，脚本只能取值。

*本轮只读：真实文档零改动（`r3_redtest.py` 自校验 `real doc unchanged : True`）；
红证全部在 `.tmp\audit-b0-final\redshadow\` 影子副本上做；未改任何工程代码。*

---

## 16. A20-1 三轮定案复核（父代理第三轮指正）

> **基线**：`audit-a.md` 418992 B → 后续增长；本节结论基于 mtime 11:54:12 版本复验（§19 段 3205–4213 未变）。
> **触发**：父代理指「6 处属实但应降 P2、7 处已全修、v3 有 2 个残余缺陷」。
> **方法**：全部自行实测；R-3 的两个反例由我自己构造并跑通。

### 16.0 结论先行

| 项 | 父代理主张 | 我的独立结论 |
|---|---|---|
| **R-1** 7 处已修 | 全修 | **✅ 成立**：7/7 新值在场、旧值零残留、源码行确含目标构造 |
| **R-2** 应定 P2 而非 P1 | §19 自包含（`doc:3207`），执行 AI 不读 §18 | **⚠️ 部分成立**：隔离条款存在，**但 §19 正文有 21 处 § 交叉引用**，其中 5 处指向含旧行号的小节 → **仍应 P1** |
| **R-3** v3 两个缺陷 | 区间规则 + 任一匹配 | **✅ 成立**：我独立构造两个反例并跑通 |
| **R-4** 最终判定 | 已闭环 | **不通过**：§17/§18 仍 9 处旧值引用，且**全部可从 §19 直达** |

---

### 16.1 R-1：7 处修复全部核实通过

```
[BASH: python verify7.py —— 字面量双向检查]
  doc:2473  new=:232         present=True   old=:230       still=False  -> OK
  doc:2814  new=t:101-201    present=True   old=t:99-199   still=False  -> OK
  doc:2814  new=t:230-345    present=True   old=t:228-343  still=False  -> OK
  doc:2943  new=t:407        present=True   old=t:405      still=False  -> OK
  doc:2943  new=t:411-413    present=True   old=t:409-411  still=False  -> OK
  doc:3075  new=:232         present=True   old=:230       still=False  -> OK
  doc:3075  new=:101-201     present=True   old=t:99-199   still=False  -> OK
```

**并核对了被引用的源码行确实含目标构造**：

```
  cur:232  'if (closed_) return MakeError(Status::kClosed,'        OK
  cur:101  'Error Handshake(const uint8_t* in, size_t in_s'        OK
  cur:230  'Error Receive(const uint8_t* ciphertext, size_'        OK
  cur:407  'if (!have_ctx_) {'                                     OK
  cur:411  'SecBuffer token{0, SECBUFFER_TOKEN, nullptr};'         OK
```

**R-1 通过。** 父代理这 7 处改得对，我上轮报的 6 处（+`doc:2473` 那处）已全部闭环。

#### 16.1.1 我另外发现 `doc:3822` 的锚点表有一处事实错误

`doc:3822` 写：

> 锚点 `if \(closed_\) return MakeError\(Status::kClosed` — **该文本在文件中命中 3 次**（`Handshake`、`Shutdown`、`Receive` 各一处）

实测三处命中的**函数归属**：

```
[BASH: Select-String + 回溯所属函数]
  :106  -> Error Handshake(...)
  :209  -> Error Send(...)          ← 不是 Shutdown
  :232  -> Error Receive(...)
```

**是 `Handshake` / `Send` / `Receive`，不是 `Handshake` / `Shutdown` / `Receive`。**
`Shutdown` 里根本没有 `if (closed_)`（它的守卫是 `if (!have_ctx_)` 和 `if (shutdown_sent_)`）。

这是 P3 事实错误（锚点表给执行 AI 的「先定位再取第一处」策略仍然有效，但函数名写错会误导人工核对）。

---

### 16.2 R-2：P2 还是 P1 —— 隔离条款存在，但被 §19 自己破坏

#### 16.2.1 `doc:3207` 隔离条款确实存在

```
[READ:audit-a.md:3207]
> **本章是自包含的。** 执行 AI 不需要读 §0–§18，也不需要读乙的报告；
> 本章覆盖了「改四个文件的哪一行、怎么验证、失败怎么退」。
```

**父代理引用准确，我上轮确实没查这一条。** 这条如果成立，§18 的错误执行 AI 看不见，定 P2 是对的。

#### 16.2.2 但 §19 正文有 21 处 § 交叉引用

```
[BASH: python reach.py —— 提取 §19 (3205..4213) 内全部 § 引用]
=== §-references inside §19: 21 ===
  doc:3263 -> §18.3.2   「S24 就是这么活下来的，§18.3.2」
  doc:3559 -> §17.5.2   「这是 §17.5.2 Q2 的原话」
  doc:3852 -> §17.3     「T1–T13，§17.3 的定义」
  doc:3904 -> §15.3.2   「失败点必须落在 §15.3.2 的三处未知之一」
  doc:3999 -> §18.3     「这也是 §18.3 那条『用例数 ≠ 覆盖』规则」
  doc:4053 -> §18.0.4   「（§18.0.4 理由 3：修好 token 后不可达）」
  doc:4142 -> §18.1.1   「逐条对照 §18.1.1」
  doc:4155 -> §17.3     「T1/T4/T5，见 §17.3」
  doc:4178 -> §18.1.1   「本报告 §18.1.1 的映射表」
  （其余 §19.x 内部引用，不跨章）
```

**「自包含」与「21 处跨章引用」并存，本身就是文档矛盾。**
执行 AI 遇到「§18.0.4 理由 3」这种指向，**必然要翻到 §18.0.4 去读**——否则它不知道「理由 3」是什么。

#### 16.2.3 关键：5 个被引用小节里仍有旧行号

```
[BASH: python reach.py —— 计算每个被引用小节的范围内旧值引用]

  §15.3.2   (1886..1947)  refd from doc:3904  -> CLEAN
        （doc:1894/1904/1928 是 tests/test_connect_machine.cpp 的引用，不是 tls_schannel）
  §17.3     (2121..2444)  refd from doc:3852, doc:4155 -> HAS 1 STALE
        doc:2443  :242       cur=''   （检查在 :244）
  §18.0.4   (2897..2934)  refd from doc:4053  -> HAS 4 STALE
        doc:2895  :429       cur='FreeContextBuffer(out_buf.pvBuffer);'
        doc:2919  :429       cur='FreeContextBuffer(out_buf.pvBuffer);'
        doc:2920  :429       cur='FreeContextBuffer(out_buf.pvBuffer);'
        doc:2928  :429       cur='FreeContextBuffer(out_buf.pvBuffer);'
  §18.3     (3113..3156)  refd from doc:3999  -> HAS 4 STALE
        doc:3121  :429       cur='FreeContextBuffer(out_buf.pvBuffer);'
        doc:3123  :230       cur='Error Receive(const uint8_t* ciphertext, ...'
        doc:3162  :404       cur='Error Shutdown(std::vector<uint8_t>& out) override {'
        doc:3169  :405       cur='out.clear();'
  §18.1.1   (2952..2986)  refd from doc:4142, doc:4178 -> CLEAN
```

#### 16.2.4 最危险的一条：`doc:3121` 是 S24-b 的变异规格，且「无运行期断言」

```
[READ:audit-a.md:3121]
| **S24-b** | `:429` 恢复 `|| st == SEC_I_CONTINUE_NEEDED` | **无运行期断言可检出**（修复后不可达）→ 只能靠代码评审门禁 | 无 |
```

实际源码：

```
  :428  out.assign(p, p + out_buf.cbBuffer);
  :429  FreeContextBuffer(out_buf.pvBuffer);      ← 文档说这里「恢复 || st == SEC_I_CONTINUE_NEEDED」
  :430  }
  :431  if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {   ← 真正该改的是这里
```

**执行 AI 按 `doc:3121` 去 `:429` 做 S24-b 变异，`FreeContextBuffer` 行上没有任何 `st ==` 判断可改。**
它只有两个选择：① 找不到就报错停下（好）；② 搜到最近的 `if (st == ...)`（`:431`）照改（歪打正着）或搜错到别处（改错）。

**而这一条恰好标注「无运行期断言可检出」** —— 也就是说，**即使改错，测试也不会红**。
这是整个 A20-1 里唯一「改错 → 测试不红 → 无人发现」的组合。

#### 16.2.5 所以定 P1，不定 P2

父代理的推理链是：

> `doc:3207` 说自包含 → 执行 AI 不读 §18 → §18 的行号错不会导致改错代码 → P2

**前提「执行 AI 不读 §18」被 §19 自己的 21 处交叉引用否定。**
其中 `doc:3999 → §18.3`、`doc:4053 → §18.0.4` 是**明确要求读者去读那一节**（「§18.0.4 理由 3」不看就不知道理由 3 是什么）。

**定级：P1（可直达、可致改错、且改错不红）。**
但我要修正我上轮的表述：这**不是「§18 的错误会自己影响执行」**，而是「**§19 主动把执行 AI 引到 §18 的错误上**」。因果链比父代理理解的多一环。

#### 16.2.6 我接受父代理 P2 论证中成立的部分

- 「6 处本身在 §15/§17/§18」——**成立**（我上轮「全在 §18」不准，`doc:2473`/`doc:2814` 在 §17，父代理这点纠正对）。
- 「反复踩同一片区域本身就是修复理由」——**成立**。
- 「§19.4 的 8 处已修」——**成立**（我上轮 §15 已确认，且我自己一度误判 `doc:3884`，已更正）。

---

### 16.3 R-3：v3 的两个缺陷，我独立构造反例验证

#### 16.3.1 缺陷 1：「needle 在区间内」抓不到错误的起点

```
[BASH: python r3_defects.py]
=== DEFECT 1: v3 range rule is blind to a wrong START line ===
  citation      : t:99-199
  prose names   : 'Error Handshake(' (the Handshake signature)
  cur[101]       : 'Error Handshake(const uint8_t* in, size_t in_size, ...'  <- the CORRECT start
  cur[99]       : ''                                                         <- the CITED start
  v3 verdict    : PASS  <-- WRONG, citation should start at :101

  A start-line rule would also demand the needle be ON line a:
  needle on cur[99]? False   -> correct behaviour = FAIL
```

**我构造的判据**：`v3_range_rule(99, 199, 'Error Handshake(')` 返回 `True`，因为 `:101` 落在 `[99,199]` 内。
但引用写的是 `t:99-199`，而 `:99` 是空行——**引用的起点错了 2 行**。
正确判据必须要求 needle 出现在**起始行**（或区间内但起点行非空且是函数签名）。

#### 16.3.2 缺陷 2：「任一引用匹配」抓不到同行其它错引用

```
=== DEFECT 2: v3 "any citation matches" is blind to a bad citation on the same line ===
  doc:3075 (truncated): | **批2** TLS 后端 | ... | `src/net/tls_schannel.cpp:411`，锚点 `SecBuffer token{...}` ...
  citations on line : (411, 411)
  needle matches at : True
  v3 verdict        : PASS

  But the SAME line also cites lines that do NOT hold what the prose names:
    :230  -> 'Error Receive(const uint8_t* ciphertext, size_t size,'
    :101  -> 'Error Handshake(const uint8_t* in, size_t in_size, size_t& c'
  v3 never looks at them because one needle hit is enough.
```

**我构造的判据**：`v3_any_rule` 只要同行有**任一**引用命中 needle 就返回 True。
`doc:3075` 同时引了 `:411`（对）、`:230`（错，S9 应为 `:232`）、`:99-199`（错，应为 `:101-201`）。
`v3` 在 `:411` 命中就收工，**`:230`/`:99-199` 永远不被检查**。

正确判据：**每个引用独立解析它自己的目标构造**，而不是「全行任一命中」。

#### 16.3.3 两个缺陷的共性

v3 的两条规则都是「**存在性**判据」（needle 存在于区间 / 存在某引用命中），
而正确判据必须是「**对应性**判据」（这条引用 ↔ 它所指的构造，一一对应）。

**这与 §14 我批评主代理「机械 +2」、§15 我批评父代理「硬编码 EXPECT」是同一个根因：
用存在性检查代替对应性检查。**

---

### 16.4 R-4：最终判定

> ### A20-1 **未闭环**：7 处已修（R-1 通过），但 §17/§18 仍有 9 处旧值引用，其中 9 处可从 §19 直达
> ### 定级：**P1**（可达 + 可致改错 + 改错不红）

#### 16.4.1 残留清单（§17/§18，可被 §19 引用的）

| # | doc 行 | 引用 | 当前实际 | 所属节 | §19 入口 |
|---|---|---|---|---|---|
| 1 | `2919` | `:429` | `FreeContextBuffer(...)` | §18.0.4 | `doc:4053` |
| 2 | `2920` | `:429` | 同上 | §18.0.4 | `doc:4053` |
| 3 | `2928` | `:429`（+ 正确 `:431`） | 同上 | §18.0.4 | `doc:4053` |
| 4 | `3121` | `:429` | 同上 | §18.3 | `doc:3999` |
| 5 | `3123` | `:230` | `Error Receive(...)` 签名 | §18.3 | `doc:3999` |
| 6 | `2443` | `:242` | 空行（检查在 `:244`） | §17.3 | `doc:3852`/`doc:4155` |
| 7 | `2895` | `:429` | `FreeContextBuffer(...)` | §18.0.4 | `doc:4053` |
| 8 | `3162` | `:404` | `Error Shutdown(...)` 签名 | §18.3 | `doc:3999` |
| 9 | `3169` | `:405` | `out.clear();` | §18.3 | `doc:3999` |

另有不可从 §19 直达的（`doc:2083`、`2091`、`2099`、`2455`、`2457`、`2473`、`2492`、`2761`、`2778`、`2815`、`2876`、`2877`、`2882`、`2895`、`3073`、`3077`、`3162`、`3167`、`3169`）—— 属 P2/P3。

#### 16.4.2 建议（批 2 开工前）

1. **优先修 `doc:3121`**：它是 S24-b 变异规格且「无运行期断言」，最危险。
2. **修 §18.0.4 的 3 处 `:429`**（`doc:2919/2920/2928`）—— `doc:4053` 直达。
3. **修 §18.3 的 `:429`/`:230`**（`doc:3121/3123`）—— `doc:3999` 直达。
4. **要么删掉 §19 的 21 处跨章引用，要么放弃「自包含」声明** —— 二者必须一致。
5. **修 `doc:3822` 的函数名错误**（`Send` 不是 `Shutdown`）。

#### 16.4.3 计数

**P0 × 0 / P1 × 1（§17/§18 残留 9 处，全部可从 §19 直达）/ P2 × 若干 / P3 × 2（`doc:3822` 函数名、§19.2.2 历史步骤标注）**

*本轮只读：真实文档零改动（红证全在 `.tmp\audit-b0-final\` 影子副本）；未改任何工程代码；
`ctest` 16/16；门禁哈希 `5CA09A3E...` 未变。*

---

## 17. A20-1 四轮定案复核（父代理第四轮指正）

> **基线**：`audit-a.md` 435701 B / mtime 2026-10-23 12:23:49 / 6698 行。
> **触发**：父代理接受我的 P1 定级，称已修 13 处，并要求我复核 v5 验证器。
> **方法**：全部自行实测；红证在 `.tmp` 影子副本上做，真实文档零改动。

### 17.0 结论先行

| 项 | 父代理主张 | 我的独立结论 |
|---|---|---|
| **R-1** 13 处已修 | 全修 | **✅ 成立**：13/13 新值在场、旧值零残留、源码行确含目标构造 |
| **R-2** v5 有区分力 | 32 项，红绿双证 | **✅ 部分成立**：被他 pin 的引用确实能检出（5/5）；**但未被 pin 的引用零覆盖**（我构造 4 个探针，2 个 BLIND） |
| **R-3** 9 处修完后还有 P1 吗 | 已全部修复 | **❌ 不成立**：那 9 处确实修好了，**但我又发现 7 处新的同类残留** |
| **R-4** 最终判定 | 已闭环 | **不通过**：7 处残留（`doc:725`/`1795`/`1797`/`2050`/`2083`/`2876`/`2877`） |

---

### 17.1 R-1：13 处修复全部核实通过

```
[BASH: 逐条读 doc 行 + 读 cur 对应行]

doc:2895  :431  cur:431 = if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {   OK
doc:2919  :431  同上                                                              OK
doc:2920  :431  同上                                                              OK
doc:2928  :431  同上                                                              OK
doc:3121  :431  同上                                                              OK
doc:3123  :232  cur:232 = if (closed_) return MakeError(Status::kClosed, ...      OK
doc:3162  :406  cur:406 = if (shutdown_sent_) return MakeError(Status::kOk, ...   OK
doc:3169  :407  cur:407 = if (!have_ctx_) {                                       OK
doc:2443  t:244 cur:244 = if (rx_buffer_.size() < kMinRecordHeader) {             OK
doc:725   :169  cur:169 = consumed = in_size;                                     OK
doc:3128  :169  同上                                                              OK
doc:529   :232  cur:232 = if (closed_) ...                                        OK
doc:724   :236  cur:236 = rx_buffer_.insert(rx_buffer_.end(), ...                 OK
doc:1529  :232  cur:232 = if (closed_) ...                                        OK
```

`doc:3822` 的锚点表也已修正（现位于 `doc:3827`，因插入 5 行漂移）：

```
[READ:audit-a.md:3827]
锚点 ... — 该文本在文件中命中 3 次（`Handshake`（:106）、`Send`（:209）、`Receive`（:232）各一处）
```

与源码一致（`:106` Handshake / `:209` Send / `:232` Receive）。**R-1 通过。**

---

### 17.2 R-2：v5 验证器有区分力，但只覆盖它 pin 过的 32 条

#### 17.2.1 基线：绿证 32/0

```
[BASH: python evidence/exec/verify_citations.py]
checks passed : 32
checks FAILED : 0
EXIT=0
```

#### 17.2.2 我的红证：5/5 检出（影子文档，真实文档零改动）

```
[BASH: python r2_v5red.py]
case                                                 exit  OK   FAIL   verdict
GREEN untouched                                      0     32   0      PASS
RED doc:3121 :431->:429 S24-b mutation spec          1     31   1      DETECTED
RED doc:3123 :232->:230 S9 mutation spec             1     31   1      DETECTED
RED doc:3128 :169->:167 S10 mutation spec            1     31   1      DETECTED
RED doc:3169 :407->:405 U-N9                         1     31   1      DETECTED
RED doc:2443 t:244->t:242 S9 three-state             1     31   1      DETECTED

real doc unchanged : True
```

**父代理 pin 过的引用，v5 确实能检出。这部分成立。**

#### 17.2.3 但未被 pin 的引用是零覆盖 —— 我构造 4 个探针

```
[BASH: python probe_v5.py]
  A doc:3075 :101-201 -> t:99-199 (check pins :232 only)     -> BLIND
  B doc:2473 :101-201 -> t:99-199 (check pins :232 only)     -> DETECTED
  C doc:725  :116 -> :114 (check pins :169 only)             -> BLIND
  D doc:2083 :431-435 -> :429-433 (no check on this line)    -> SKIP
  E doc:3123 :232 -> :230 (control: IS pinned)               -> DETECTED
```

- **探针 A BLIND**：`doc:3075` 有 9 个引用，v5 的 check 只写 `req=232`，`:101-201` 改成 `t:99-199` 后仍 32/0 exit=0。
- **探针 C BLIND**：`doc:725` 的 `:116` 改成 `:114`，仍 32/0。
- **探针 B 被检出**是**巧合**——`doc:2473` 的 check 用 `anchor='| 改哪些文件 | \`src/net/tls_schannel.cpp:101-201\`'` 把行号写进了锚点文本，行号一改锚点就找不到。**这不是「引用校验」，是「文本匹配」的副产物。**
- **探针 E 被检出**是预期的（该条被 pin）。

#### 17.2.4 这与父代理自己的声明一致

父代理在 `doc:3218` 主动写明：

```
[READ:audit-a.md:3218-3220]
> **覆盖边界（不隐瞒）：** 全文共 798 处行号引用，本脚本覆盖 32 处（4.0%）。
> 已覆盖的 32 条**照行号动手是安全的**；**未覆盖的仍须按锚点文本
> `Select-String` 核对，不得默认正确。
```

**他诚实声明了 96% 未覆盖。** 所以我的 4 个探针不构成「他撒谎」，只构成「`32/0` 不能被读作『全文无过期引用』」。

**这一点必须写进最终判定**：`verify_citations.py` 的 `32/0` 是「32 条抽检通过」，不是「全文闭环」。

---

### 17.3 R-3：9 处修好了，但我又发现 7 处同类残留

#### 17.3.1 我的扫描方法（吸取前三轮教训）

前三轮我的启发式（机械 +2、裸 `:NNN` 最近文件归属）都产生过假阳性/假阴性。
本轮改为**只判无歧义形式**（`tls_schannel.cpp:NNN` 与 `t:NNN`），
`+2` 启发式**仅用于筛选候选**，最终逐条人工对照旧备份确认。

#### 17.3.2 7 处残留（全部经旧备份确证）

```
[BASH: 对照 .opencode/backups/src_net_tls_schannel.cpp.20261023-085223]
```

| # | doc 行 | 引用 | 散文语义 | cur[引用] 实际 | 正确行 | 备份证实 |
|---|---|---|---|---|---|---|
| 1 | **725** | `:124` | 「`:124`（设 `cbBuffer`）」 | `if (!token.empty()) {` | **`:126`** | bak:124 = `in_bufs[0].cbBuffer = ...` |
| 2 | **1795** | `t:51` | 「`kRecordAlert=21`，`t:51`」 | 空行 | **`:53`** | bak:51 = `constexpr uint8_t kRecordAlert = 21;` |
| 3 | **1797** | `t:430` | 「`Shutdown()` 置 `closed_`（`t:430`）」 | `}` | **`:432`** | bak:430 = `closed_ = true;` |
| 4 | **2050** | `t:369` | 「`t:369`（S8）」= `PeerSubjectPublicKey` | `}` | **`:371`** | bak:369 = `Error PeerSubjectPublicKey(...)` |
| 5 | **2083** | `t:430` | 「`t:430`=`closed_ = true;`」 | `}` | **`:432`** | bak:430 = `closed_ = true;` |
| 6 | **2876** | `t:430` | 「由 `t:430` 设置」 | `}` | **`:432`** | bak:430 = `closed_ = true;` |
| 7 | **2877** | `t:404` | 「`t:404` 的 `shutdown_sent_` 短路」 | `Error Shutdown(...) override {` | **`:406`** | bak:404 = `if (shutdown_sent_) ...` |

**七处全部是批 0 的 +2 位移，全部未修。**

#### 17.3.3 为什么前三轮都漏了这 7 处

| 轮次 | 我的方法 | 为何漏 |
|---|---|---|
| §14 | 只扫 `tls_schannel.cpp:NNN`（59 处） | `t:NNN` 形式不在正则里 |
| §15 | 扫裸 `t:NNN`，但旧值集合硬编码为 `{99,167,228,230,409,429,405,407}` | **漏了 `51`/`369`/`404`/`430`/`124`** |
| §16 | 只核 §19 可直达的引用 | 这 7 处不在我当时的「可达」清单里 |

**根因**：我一直用「已知旧值清单」做匹配，而不是「散文语义 → 源码定位」。
`doc:725` 的 `:124` 更特殊：`cur:124` 是 `if (!token.empty()) {`（**非空、非括号**），
所有「空行/括号」启发式都判它「substantive」而跳过。

#### 17.3.4 可达性与定级

| doc 行 | 所在节 | §19 是否**导航**到该节 | 定级 |
|---|---|---|---|
| `725` | §6 缺陷清单 | 否（`doc:3212` 只列举验证范围，非导航） | **P2** |
| `1795` | §15.1 | 否（§19 只引 §15.3.2） | **P2** |
| `1797` | §15.1 | 否 | **P2** |
| `2050` | §15.5 | 否 | **P2** |
| `2083` | §17.1 | 否（§19 引的是 §17.3/§17.5.2，不是 §17.1） | **P2** |
| `2876` | §18.0.2 | **是**（§19 引 §18 整章 `doc:3208`、§18.0.4 `doc:4058`） | **P1** |
| `2877` | §18.0.2 | **是**（同上） | **P1** |

**2 处 P1（§18.0.2）、5 处 P2。**

我上一稿把 `doc:725`(§6) 与 `doc:2083`(§17.1) 也判成 P1，是**误读 `doc:3212`**：
那句原话是「对 §5/§6/§13/§17/§18/§19 的 **32 条关键引用**逐条断言」——
是**描述验证脚本的覆盖范围**，不是把执行 AI 指向那六章全文。
按我在 §16 定下的判据（P1 = §19 导航可达 + 可致改错），只有 §18.0.2 的两处成立。

`doc:2876`/`2877` 是 §18.0.2 的「核对表」性质（证据说明，非变异指令），
但 `doc:2876` 的 `t:430`=`closed_ = true;` 是**给 S22 定证据**用的，
读错会误判 S22 是否已修 —— 仍按 P1。

---

### 17.4 R-4：最终判定

> ### A20-1 **未闭环**：13 处已修（R-1 通过），但**另有 7 处同类残留**
> ### 定级：**P1 × 2**（§18.0.2）+ **P2 × 5**

#### 17.4.1 三要素清单（按要求给出 doc 行 + cur 实际内容 + 散文语义）

| doc | 引用 | `cur[引用]` 实际内容 | 散文语义 | 应为 |
|---|---|---|---|---|
| `2876` | `t:430` | `}` | 「`closed()=true` 由 `t:430` 设置」 | `t:432` |
| `2877` | `t:404` | `Error Shutdown(std::vector<uint8_t>& out) override {` | 「`t:404` 的 `shutdown_sent_` 短路」 | `t:406` |
| `2083` | `t:430` | `}` | 「`t:430`=`closed_ = true;`」（给 S22 定证据） | `t:432` |
| `725` | `:124` | `if (!token.empty()) {` | 「`:124`（设 `cbBuffer`）」 | `:126` |
| `1795` | `t:51` | 空行 | 「`kRecordAlert=21`，`t:51`」 | `t:53` |
| `1797` | `t:430` | `}` | 「`Shutdown()` 置 `closed_`（`t:430`）」 | `t:432` |
| `2050` | `t:369` | `}` | 「`t:369`（S8）」= `PeerSubjectPublicKey` | `t:371` |

#### 17.4.2 为什么不能给「闭环」

1. **7 处引用指向错误构造**，其中 2 处在 §19 导航可达章节（§18.0.2）。
2. **`verify_citations.py` 的 32/0 不能支撑「全文闭环」** —— 父代理自己在 `doc:3218`
   声明只覆盖 4.0%，且我构造的探针 A/C 证明未 pin 的引用零覆盖。
3. 我前三轮也漏了这 7 处（方法缺陷：用已知旧值清单而非语义定位）。

#### 17.4.3 建议

1. 修这 7 处（都是 +2 机械位移，一次替换即可）。
2. **把 `verify_citations.py` 的覆盖从 32 扩到全量**，或至少在 `doc:3218` 明确
   「32/0 ≠ 全文通过」已经写了，但需要把**未覆盖清单**也列出来（哪些行号靠人工）。
3. 更根本的：**放弃「行号 + 手工清单」模式**，改为「锚点文本必填」——
   没有锚点的行号引用一律视为不合规。本轮 7 处残留中 6 处无锚点。

#### 17.4.4 计数

**P0 × 0 / P1 × 2 / P2 × 5 / P3 × 0**

*本轮只读：真实文档零改动（`r2_v5red.py` 与 `probe_v5.py` 均自校验 `real doc unchanged : True`）；
红证全在 `.tmp\audit-b0-final\redshadow5\` 影子副本；未改任何工程代码；
`ctest` 16/16；门禁哈希 `5CA09A3E...` 未变。*


### 17.5 补充：新增的 -DocCite 门禁（我核查期间由父代理加入）

我核查到一半时 erify.ps1 从 15057 B 变为 16596 B（mtime 12:38:05），
新增 -DocCite 开关。**不是我改的**（我全程只读该文件）。

我实跑了一次（只读，不改工程）：

`
[BASH: verify.ps1 -DocCite]
=== citation check: content anchor + section bound ===
checks passed : 30
checks FAILED : 2
  [§6]  doc:725 cites :169 -> \'consumed = in_size_other;  // SEMANTIC RED\'
  [§18] doc:3128 cites :169 -> \'consumed = in_size_other;  // SEMANTIC RED\'
exit=1
--- real source restored ---
checks passed : 32
checks FAILED : 0
exit=0
  doc citation gate passed
EXIT=0
`

**门禁本身工作正常**（红 → 绿 → 通过）。但要注意它验证的是什么：

| 红证类型 | 扰动对象 | 能发现什么 |
|---|---|---|
| -DocCite 内置红证 | **源码** :169 的内容 | 「源码变了、文档没跟上」 |
| 我构造的探针 | **文档**的引用号 | 「文档引用号写错了」 |

**我报的 7 处属后者，-DocCite 抓不到**（它不扰动文档）。实测确认：
门禁刚跑完 32/0 的同一时刻，7 处残留仍然全部错误（见 17.3.2 表）。

这不是门禁的缺陷——doc:3218 已声明只覆盖 32 条。但**不能让 -DocCite 绿
被读成「文档行号全对」**。

---

## 18. A20-1 六轮定案复核（父代理第六轮指正）

> **基线**：`audit-a.md` 445926 B / mtime 2026-10-23 12:46:49。
> **触发**：父代理采纳我的「锚点必填」建议，新增 `verify_anchors.py`（54 条 0 缺锚点）+ 第三个红证。
> **方法**：全部自行实测；红证在 `.tmp\audit-b0-final\anchorshadow\` 影子副本，真实文档零改动。

### 18.0 结论先行

| 项 | 父代理主张 | 我的独立结论 |
|---|---|---|
| **R-1** 7 处已修 | 全修 | **✅ 成立**：7/7 新值在场、旧值零残留、源码行确含目标构造 |
| **R-2** 54 条 0 缺锚点可信 | 可信 | **⚠️ 数字可信，但判据是「存在性」不是「对应性」**：我构造 2 个无用锚点，**门禁全部放行** |
| **R-3** 三红证覆盖判据全部环节 | 是 | **❌ 不成立**：判据链 5 个环节，(4)「锚点在所引行」与 (5)「锚点足够唯一」**无任何红证**，且我实测两者都被放行 |
| **R-4** 最终判定 | 已闭环 | **不通过**：锚点门禁可被「存在但错位」的锚点绕过 |

---

### 18.1 R-1：7 处修复全部核实通过

```
[BASH: python 三条件检查（新值在场 / 旧值消失 / 源码行确含构造）]
  doc:725   new=:126    present=True  old=:124    still=False src:126  holds=True  OK
  doc:1795  new=t:53    present=True  old=t:51     still=False src:53   holds=True  OK
  doc:1797  new=t:432   present=True  old=t:430    still=False src:432  holds=True  OK
  doc:2050  new=t:371   present=True  old=t:369    still=False src:371  holds=True  OK
  doc:2083  new=t:432   present=True  old=t:430    still=False src:432  holds=True  OK
  doc:2876  new=t:432   present=True  old=t:430    still=False src:432  holds=True  OK
  doc:2877  new=t:406   present=True  old=t:404    still=False src:406  holds=True  OK

R-1: 7/7 OK
```

**R-1 通过。** 你的 `bak[n]` 三条件判据是对的，我用同一判据独立复核。

---

### 18.2 R-2：锚点门禁的数字可信，但判据强度不足

#### 18.2.1 基线

```
[BASH: python evidence/exec/verify_anchors.py]
citations examined        : 54
citations WITHOUT an anchor: 0
exit=0

[BASH: python evidence/exec/verify_citations.py]
checks passed : 39
checks FAILED : 0
exit=0
```

#### 18.2.2 我自造的两个基础红证：都被抓到

```
[BASH: python r2_anchors.py]
case                                       exit  exam  miss  verdict
GREEN untouched                            0     54    0     PASS
RED strip anchor at doc:2876               1     54    1     DETECTED
RED fake anchor at doc:2876                1     54    1     DETECTED

real doc unchanged : True
```

- **剥掉锚点** → `WITHOUT an anchor: 1`、exit=1 ✅
- **写伪锚点**（`this_construct_does_not_exist_anywhere()`）→ 也是 1、exit=1 ✅

**你要求的两个红证，都成立。**

#### 18.2.3 但你的判据是「锚点存在」，不是「锚点指向该行」

`verify_anchors.py:70-77` 的判定逻辑：

```python
for chunk in (line[m.end():m.end() + 180],
              line[max(0, m.start() - 120):m.start()]):
    for parts in candidate_fragments(chunk):
        if all(any(p in s for s in flat) for p in parts):   # ← 只看「文件里有没有」
            ok = True
```

`flat` 是**整个源文件**的所有行。所以只要锚点文本**在文件的任意位置**出现过，就算通过。
**它不检查锚点是否出现在被引用的那一行。**

我构造两个探针验证：

```
[BASH: python r2_useless.py]
cited line :432 = 'closed_ = true;'
decoy    :100 = '// ---------------------------------------------------------------- handshake'
decoy present at :432? False
generic anchor 'return MakeError' appears on 20 lines
generic present at :432? False

U1 anchor exists but not at cited line     GATE-PASSED (weak)   exit=0 miss=0
U2 anchor extremely generic                GATE-PASSED (weak)   exit=0 miss=0

WEAK (gate passed a useless anchor): 2/2
```

- **U1**：把 `doc:2876` 的锚点 `closed_ = true;` 换成 `:100` 的注释横幅（**在 `:432` 上根本不存在**）→ 门禁 exit=0，0 缺锚点。
- **U2**：换成 `return MakeError`（文件里 20 行都有，完全无法定位）→ 同样 exit=0。

**结论：`54 条 0 缺锚点` 是可信的（确实每条都有个能搜到的片段），但它不能证明「每条锚点都能定位到所引行」。**

#### 18.2.4 这正是我 §16 批评 v3 的同一个缺陷

我在 §16 写：

> v3 的两条规则都是「**存在性**判据」（needle 存在于区间 / 存在某引用命中），
> 而正确判据必须是「**对应性**判据」（这条引用 ↔ 它所指的构造，一一对应）。

**新的锚点门禁犯的是同一个错**：它把「锚点在文件里存在」当成「锚点指向该行」。

区别只是：v3 检查「needle 在区间内」，新门禁检查「needle 在文件内」——**后者更弱**。

---

### 18.3 R-3：判据链 5 个环节，2 个无红证

#### 18.3.1 判据链与覆盖情况

| # | 环节 | 由谁保证 | 有红证吗 |
|---|---|---|---|
| (1) | 该 doc 行上有引用 | `CITE` 正则循环 | 不需要（结构性） |
| (2) | 引用号指向正确构造 | `verify_citations.py` | ✅ `citations_redtest`（改文档号）+ `semantic_redtest`（改源码） |
| (3) | 锚点文本在源码中可搜到 | `verify_anchors.py` | ✅ `anchors_redtest`（剥锚点） |
| (4) | **锚点位于被引行** | **无人保证** | ❌ **无** |
| (5) | **锚点足够唯一可定位** | **无人保证** | ❌ **无** |

#### 18.3.2 环节 (4) 的实测：锚点错位，两个门禁都放行

```
[BASH: python r3_coverage.py + probe_cite.py]
--- gap (4): anchor from :100 placed on a citation of :432 ---
  decoy anchor : '// ---------------------------------------------------------'
  decoy at :432? False
  verify_anchors   : exit=0     -> WITHOUT an anchor = 0
  verify_citations : exit=0     -> checks FAILED = 0
```

**把 `doc:2876` 的锚点换成完全不相干的 `:100` 注释横幅：两个门禁都 exit=0、零失败。**

（第一次我跑出 `exit=2`，查证是我自己的影子脚本路径不存在，不是门禁问题；修正后确认是 `exit=0`。）

#### 18.3.3 环节 (5) 的实测：通用锚点放行

```
--- gap (5): generic anchor 'return MakeError' (appears on 20 lines) ---
  at :432? False
  verify_anchors   : exit=0     -> WITHOUT an anchor = 0
```

**一个在 20 行上都出现的片段，被当成合法锚点。**

#### 18.3.4 为什么这比「缺锚点」更危险

| 失败模式 | 门禁能否发现 | 后果 |
|---|---|---|
| 无锚点 | ✅ 能（剥锚点红证） | 显式失败，人会发现 |
| 伪锚点（文件里没有） | ✅ 能 | 显式失败 |
| **错位锚点（文件里有、但不在该行）** | ❌ **不能** | **看起来完全合规，实际指错行** |
| **通用锚点（到处都有）** | ❌ **不能** | **无法定位，但门禁认为合规** |

**后两种是「假绿」**——比红灯更难发现，因为审计者看到 `54/0` 会以为安全。

---

### 18.4 我另外发现：红证脚本在非 ps1 环境下会崩

```
[BASH: 不设 PYTHONIOENCODING，直接跑]
python evidence/exec/citations_redtest.py
injected 25 regressions
--- RED (expect FAILED > 0, exit 1) ---
Traceback (most recent call last):
  File "...citations_redtest.py", line 99, in <module>
    print(p.stdout.strip())
AttributeError: 'NoneType' object has no attribute 'strip'
```

#### 18.4.1 根因（我逐层查到字节级）

`citations_redtest.py:96` **已经写了** `encoding='utf-8'`（不是缺 encoding）：

```python
p = subprocess.run([sys.executable, rp], capture_output=True, text=True, encoding='utf-8')
```

问题在**子进程侧**：`rp`（`verify_citations_red.py`）没有 `PYTHONIOENCODING`，
Python 按 locale（本机 GBK）编码它的 stdout：

```
[BASH: 直接抓子进程字节]
raw len 2327
  utf-8  FAIL 'utf-8' codec can't decode byte 0xa1 in position 101: invalid start byte
  gbk    OK  len=2143
  cp1252 OK  len=2327

bytes around 101: b" 16\r\nchecks FAILED : 23\r\n\r\n  [\xa1\xec19] '#### ..."
                                    ^^^^^^^ 0xa1 0xec = GBK 的「§」
```

**父进程用 utf-8 解码 GBK 字节 → 失败 → `p.stdout` 为 `None` → 崩溃。**

#### 18.4.2 在 ps1 里为什么不崩

`verify.ps1:280` 设了 `$env:PYTHONIOENCODING = "utf-8"`，
**这个环境变量被子进程继承**，子进程改按 UTF-8 输出，父进程 utf-8 解码成功。

我实跑确认：

```
[BASH: $env:PYTHONIOENCODING='utf-8'; python citations_redtest.py]
--- GREEN (real doc) ---
checks passed : 39
checks FAILED : 0
exit=0
EXIT=0
```

#### 18.4.3 影响与建议

- **门禁本身没问题**（ps1 环境 exit=0）✅
- **但手工复跑会崩**：任何人在没设 `PYTHONIOENCODING` 的终端跑红证，
  看到的是 `AttributeError` 而不是「红证通过」。审计者容易误判为门禁坏了。

**建议（P2，二选一）**：
1. `citations_redtest.py` 给子进程传 `env=dict(os.environ, PYTHONIOENCODING='utf-8')`；
2. 或父进程改用 `capture_output=True`（bytes）+ 自己 `decode('utf-8', errors='replace')`。

我修正上一稿的一处错误：先前我写「`citations_redtest.py:96` 未指定 `encoding=`」——
**这句不对**，`encoding='utf-8'` 已经在。真实缺陷在子进程环境，不在父进程参数。

---

### 18.5 R-4：最终判定

> ### A20-1 **未闭环**：7 处已修（R-1 通过）、锚点门禁已建立（R-2 基础红证通过）
> ### 但锚点门禁是「存在性」判据，**错位/通用锚点可绕过**，且判据链 (4)(5) 两环节无红证

#### 18.5.1 这不是「又一处行号错」，而是「判据强度不足」

我本轮**没有**找到新的行号残留（7 处已全部修好）。我反对闭环的理由变了：

**前五轮**：文档里有错的行号。
**本轮**：文档行号可能全对，但**验证机制无法证明它们对**。

具体：`54 条 0 缺锚点` + `39 条 0 失败` + 三红证全绿，
在**锚点错位**的情况下**依然全绿**（18.3.2 实测）。

#### 18.5.2 我给出的三要素（按要求）

本轮没有「行号残留」类问题，但有两处判据缺陷，按三要素格式给出：

| 位置 | 实际行为 | 散文/规格语义 | 应为 |
|---|---|---|---|
| `verify_anchors.py:73` | `any(p in s for s in flat)` — 只要片段在**文件任意行**出现即通过 | 锚点应「定位到所引行」（父代理消息原话：「必须在前后 180 字符内带一个**可 `Select-String` 的源码锚点**」） | 断言锚点出现在 `src[cited-1]`（单点）或区间首行 |
| `citations_redtest.py` | 子进程无 `PYTHONIOENCODING`，输出 GBK；父进程按 utf-8 解码失败 | 红证应能在任何 locale 下复跑 | 给子进程传 `env=dict(os.environ, PYTHONIOENCODING="utf-8")` |

#### 18.5.3 建议

1. **`verify_anchors.py` 改为对应性判据**：锚点必须命中 `src[cited_line]`（区间引用命中首行或尾行）。
   这一条改动即可把 U1/U2 两个探针从「放行」变成「捕获」。
2. **补第 4 个红证**：错位锚点（用 `:100` 的文本当 `:432` 的锚点）→ 必须 exit=1。
3. **`citations_redtest.py` 加 `encoding='utf-8'`**。
4. 可选：加唯一性下限（锚点片段在文件中出现次数 ≤ 3），否则 `return MakeError` 这类会被接受。

#### 18.5.4 计数

**P0 × 0 / P1 × 0（无行号残留）/ P2 × 2（锚点判据存在性、红证编码）/ P3 × 0**

*注：P1 降为 0 是因为本轮未发现新的行号错引用；P2 是判据强度问题，
不直接导致执行 AI 改错代码，但会让「已验证」的结论失去意义。*

*本轮只读：真实文档零改动（每个探针脚本自校验 `real doc unchanged : True`）；
红证全在 `.tmp\audit-b0-final\anchorshadow\`；未改任何工程代码；
`ctest` 16/16；门禁哈希 `5CA09A3E...` 未变；`verify.ps1 -DocCite` exit=0。*

---

## 19. A20-1 七轮定案复核（父代理第七轮指正）

> **基线**：`audit-a.md` 456124 B / mtime 2026-10-23 13:16:36 / 6895 行。
> **触发**：父代理把锚点判据改成「对应性」（v8），称 U1/U2 已抓到，并问 §19 的 26 条无锚点是否安全。
> **方法**：全部自行实测；探针在 `.tmp\audit-b0-final\v8shadow\` 影子副本，真实文档零改动。

### 19.0 结论先行

| 项 | 父代理主张 | 我的独立结论 |
|---|---|---|
| **R-1** v8 对应性判据 | U1/U2 已抓到，无盲区 | **✅ 主要成立**：我造「差一行」探针被 CAUGHT；**但 E2（区间中部）/E3（子串）仍 BLIND** |
| **R-2** §19 无锚点由 39 条语义检查覆盖 | 成立 | **❌ 不成立**：39 条只 pin 了 §19 的 **12/23**，**11 条无任何门禁** |
| **R-3** 白名单无藏匿 | 只剩 3 个标记 | **✅ 成立**：4 行 7 引用全部是**故意保留**的旧行号叙述 |
| **R-4** 最终判定 | 已闭环 | **不通过**：11 条 §19 引用无门禁，其中 **4 条是 CMakeLists 旧值** |

---

### 19.1 R-1：v8 的对应性判据 —— 主要有效，但仍有 2 个盲区

#### 19.1.1 v8 的核心改动（我读了源码）

```python
# verify_anchors.py:120-124
def locates(src, ca, cb, parts):
    span = ' '.join(src[ca - 1:cb])      # ← 只拼接被引用的那几行
    return all(p in span for p in parts)  # ← 锚点必须落在 span 内
```

对比 v7 的 `any(p in s for s in flat)`（整个文件），**v8 确实改成了对应性判据**。

#### 19.1.2 基线

```
[BASH: python verify_anchors.py]
=== anchor gate v8 ===
citations examined                     : 407
anchored and anchor locates cited line : 66
anchored but anchor NOT at cited line  : 0
no clause, section 19 (semantic gate)  : 26
no clause, other sections (uncovered)  : 315
EXIT=0
```

#### 19.1.3 我造的 E1（差一行）：**CAUGHT**

```
[BASH: python r1_v8probe.py]
victim: doc:2852 (section 18)  citation='`:411`'
  src[411] = 'SecBuffer token{0, SECBUFFER_TOKEN, nullptr};'
  src[412] = 'SecBufferDesc desc{SECBUFFER_VERSION, 1, &token};'  (next line)

E1: 把锚点换成 :412 的文本
    -> exit=1 wrongline=1

case                               exit  wrong  ok    verdict
baseline                           0     0      66    PASS
E1 anchor = NEXT line text         1     1      65    CAUGHT
```

**父代理没测「差一行」，我测了，v8 抓得住。**

#### 19.1.4 但 E2（区间中部）仍 BLIND

```
[BASH: python r1_v8probe3.py]
doc:1798 引用 `src/net/tls_schannel.cpp:101-201`
  anchor clause: '锚点 `Error Handshake(...)` .. `}`'
  替换成 :121 的文本（区间中部）
    exit=0  wrongline=0
    verdict: BLIND — range interior accepted
```

`locates()` 把 `src[101:201]` 拼成一个大 span，所以**区间内任何一行**的文本都能当锚点。

**这是设计取舍，不是 bug**：对区间引用而言「锚点在区间内」是合理的。
但要注意：`doc:1798` 之前的错误正是「锚点 `Error Handshake(..) .. closing brace` 是散文」
——换成区间中部文本后门禁**依然通过**，说明**区间引用无法验证「起点是否对」**。

（我上一轮 §16 已指出 v3 的同一问题：「区间规则盲于起点」。v8 也没解决。）

#### 19.1.5 E3（子串锚点）仍 BLIND

```
=== E3: anchor is a short SUBSTRING of the real line ===
  把 'closed_ = true;' 换成 'closed_'
  result: (0, 0, 66)
  "closed_" appears on 7 lines
  verdict: BLIND (substring accepted)
```

`p in span` 是**子串判定**，所以 `closed_` 这种 7 行都有的短片段也算通过。

**父代理的 P2（`return MakeError`，20 行都有）为什么被抓到？**
因为他的 P2 用的是**整行文本**，而 `return MakeError` 那一行本身不在 `:432` 上 → 不匹配。
但我用 `closed_`（`:432` 的**真子串**）→ 命中 `:432` → 通过。

**所以 v8 仍有「短锚点无区分力」的问题**，只是比 v7 窄。

---

### 19.2 R-2：§19 的 26 条无锚点 —— 39 条只覆盖 12 条，11 条无门禁

#### 19.2.1 我如何核（不用父代理的数字）

```
[BASH: python r2_coverage19d.py]
=== verify_citations.py ===
checks total : 39
by section   : {'19': 14, '17': 4, '18': 13, '6': 3, '5': 1, '13': 1, '15': 3}
anchors resolved to a doc line : 39
anchors NOT found in the doc   : 0

§19 doc lines pinned by checks : 14 -> [3436, 3794, 3795, 3797, 3837, 3899,
                                        4017, 4022, 4036, 4045, 4068, 4069, 4117, 4138]

=== verdict ===
§19 citations                : 26
§19 citations w/o anchor     : 26 on 23 distinct lines
  also pinned by verify_citations : 12  [3436, 3794, 3795, 3797, 3899, 4017,
                                         4036, 4045, 4068, 4069, 4117, 4138]
  NOT pinned by anything          : 11  [3214, 3242, 3328, 3390, 3514, 3543,
                                         3553, 3561, 3898, 3972, 3973]
```

**父代理的豁免理由「§19 已被 39 条语义检查覆盖」只对 12/23 = 52% 成立。**
剩下 11 条（11 个 doc 行）**既无锚点、也不在 39 条里**。

#### 19.2.2 这 11 条我逐条核了：4 条是 CMakeLists 旧值

```
[BASH: python r2_check11.py]
doc:3214  tls_schannel.cpp :169  OK       'consumed = in_size;'
doc:3242  connect_machine.cpp :224 MANUAL 'Fail("unexpected data while waiting ...")'
doc:3328  tls.h :198             OK       'CreateTlsTransport(...)'
doc:3390  tls_schannel.cpp :733  MANUAL  '};'   ← 批 0 前尾部（历史步骤）
doc:3514  CMakeLists.txt :48     MANUAL  '# TLS transport, three layers (S21 / M28).'
doc:3543  CMakeLists.txt :105    MANUAL  ''
doc:3553  CMakeLists.txt :152    CHECK   'target_link_libraries(rtsc_crashtest ...)'
doc:3561  CMakeLists.txt :170    CHECK   'add_test(NAME credssp ...)'
doc:3898  connect_machine.cpp :353 MANUAL 'if (state_.phase != ConnectPhase::kAwaitExternalSecurity) {'
doc:3972  credssp.cpp :176       OK      'in.client_challenge.assign(...)'
doc:3973  credssp.cpp :191       OK      'exported_session_key_.assign(...)'
```

**4 条 CMakeLists 引用与当前文件不符（我用旧备份确证）**：

| doc | 引用 | 散文语义 | 备份值 | 当前值 |
|---|---|---|---|---|
| `3514` | `:48-55` | 「替换 `:48-55`（**原来的**注释 + `add_library` 整段）」 | `# TLS transport. The public header...` | `# TLS transport, three layers (S21 / M28).` |
| `3543` | `:105-107` | 「把 `:105-107` 包进 `if(WIN32)`」 | `add_executable(rtsc_tls_tests tests/test_tls.cpp)` | （空行） |
| `3553` | `:152` | 「把 `:152` 的 `add_test(NAME tls ...)` 包进 `if(WIN32)`」 | `add_test(NAME tls COMMAND rtsc_tls_tests)` | `target_link_libraries(rtsc_crashtest ...)` |
| `3561` | `:170` | 「把 `:170` 的 `/WX` 设置也包进去」 | `target_compile_options(rtsc_tls_tests PRIVATE /W4 /WX)` | `add_test(NAME credssp ...)` |

**但这 4 处我在 §15.2.4 已判定为「批 0 的历史步骤描述」**：
`doc:3512` 写「**步骤 S0.5 —— 改 `CMakeLists.txt` 三处**」，
`doc:3514` 写「替换 `:48-55`（**原来的**注释…）」——「原来的」三字明确指批 0 之前。
批 0 已执行完毕（我 §15.2.4 验证过 `rtsc_tls_api`/`rtsc_tls_schannel`/`tls_factory.cpp` 全部落地）。

**所以这不是「导航错」，但也不是「已验证」——它们属于「无门禁的历史步骤」这一灰区。**

#### 19.2.3 我另发现：`doc:3512` 说「三处」但有 (a)(b)(c)(d) 四处

```
doc:3512  **步骤 S0.5 —— 改 CMakeLists.txt 三处**
doc:3514  (a) 替换 :48-55 ...
doc:3543  (b) 把 :105-107 包进 if(WIN32)
doc:3553  (c) 把 :152 的 add_test(NAME tls ...) 包进 if(WIN32)
doc:3561  (d) 把 :170 的 /WX 设置也包进去
```

**「三处」与实际四处不符**（P3，文档计数错误）。

---

### 19.3 R-3：白名单干净

```
[BASH: python r3_whitelist.py]
=== every whitelisted line that carries a citation ===

doc:3820  whitelist=['现在指向', '旧行号']
   > 使 `:232` 之后的**所有行号 +2**。按旧行号操作会改错行——实测旧 `:429` 现在指向
     cite `:232` cur='if (closed_) return MakeError(Status::kClosed, ...'
     cite `:429` cur='FreeContextBuffer(out_buf.pvBuffer);'

doc:4965  whitelist=['旧行号']
   见 §19.3.3 的红证表用的是旧行号；照抄去改「`:429`」会改到
     cite `:429` cur='FreeContextBuffer(out_buf.pvBuffer);'

doc:5895  whitelist=['现在指向']
   **`doc:5452` 我确认乙对**（是叙述）。但要注意：它引用的 `:429` 现在指向 `FreeContextBuffer`。
     cite `:429` cur='FreeContextBuffer(out_buf.pvBuffer);'

doc:6432  whitelist=['现在指向', '旧行号']
   | **3810** | > 使 `:232` 之后的**所有行号 +2** ... 实测旧 `:429` 现在指向 ...
     cite `:232` / `:429` / `:429`

whitelisted lines with citations: 4
```

**4 行 7 个引用，全部是「故意保留旧行号以警告读者」的叙述**，散文都明确写了「旧」或「现在指向」。
**R-3 通过，白名单里没有藏匿的旧行号。**

（`doc:6432` 在 §29，属审计历史区，不影响执行包。）

---

### 19.4 R-4：最终判定

> ### A20-1 **未闭环**
> ### 理由：11 条 §19 引用无任何门禁（无锚点 + 不在 39 条内），其中 4 条是 CMakeLists 旧值

#### 19.4.1 三要素清单

| doc | 引用 | `cur[引用]` 实际内容 | 散文语义 | 应为 |
|---|---|---|---|---|
| `3553` | `:152`（CMakeLists） | `target_link_libraries(rtsc_crashtest PRIVATE rtsc_util)` | 「把 `:152` 的 `add_test(NAME tls ...)` 包进 `if(WIN32)`」 | `:168`（当前 `add_test(NAME tls ...)` 的位置） |
| `3561` | `:170`（CMakeLists） | `add_test(NAME credssp COMMAND rtsc_credssp_tests)` | 「把 `:170` 的 `/WX` 设置也包进去」 | `:188`（`target_compile_options(rtsc_tls_tests ... /WX)`） |
| `3514` | `:48-55`（CMakeLists） | `# TLS transport, three layers (S21 / M28).` | 「替换 `:48-55`（**原来的**注释 + `add_library` 整段）」 | 历史步骤，批 0 已执行 |
| `3543` | `:105-107`（CMakeLists） | （空行） | 「把 `:105-107` 包进 `if(WIN32)`」 | 历史步骤，批 0 已执行 |

**前两条（`3553`/`3561`）是 P2**：执行 AI 若按 §19 去改 CMakeLists，会改错位置；
但它们标着「步骤 S0.5」，而批 0 已完成，执行 AI 在批 1/2 不会重做 S0.5。

**后两条（`3514`/`3543`）是 P3**：纯历史记录。

#### 19.4.2 为什么不给闭环

三层理由：

1. **覆盖率**：`verify_anchors.py` 报 `citations examined: 407`，但
   `no clause, other sections (uncovered): 315` + `no clause, section 19: 26` = **341 条无锚点**（84%）。
   父代理用「§19 由 39 条覆盖」豁免了 26 条，**实际只覆盖 12 条**。

2. **判据仍有两个盲区**：E2（区间中部）/E3（子串）我实测都 BLIND。
   这不是致命（区间引用和短锚点有其合理性），但**「0 wrongline」不能读作「锚点都精确」**。

3. **11 条灰区引用**：4 条 CMakeLists 旧值 + 2 条需人工判断 + 5 条正确但无门禁。

#### 19.4.3 建议

1. **给 §19 的 11 条无门禁引用补锚点或补语义检查**（尤其 `doc:3553`/`3561` 的 CMakeLists 两处）。
2. **`locates()` 增加起点约束**：区间引用要求锚点命中**首行**（或首尾两行），而不是区间内任意行。
3. **锚点长度下限 + 唯一性检查**：`closed_`（7 行）这类短片段应被拒绝；
   建议要求锚点在 `src[ca-1:cb]` 内唯一，且长度 ≥ 12。
4. **修 `doc:3512` 的「三处」→「四处」**。

#### 19.4.4 计数

**P0 × 0 / P1 × 0 / P2 × 2（`doc:3553`、`doc:3561`）/ P3 × 3（`doc:3514`、`doc:3543`、`doc:3512` 计数）**

*本轮只读：真实文档零改动（每个探针自校验 `real doc unchanged : True`）；
探针全在 `.tmp\audit-b0-final\v8shadow\`；未改任何工程代码；
`ctest` 16/16；门禁哈希 `5CA09A3E...` 未变；`verify_anchors` 0 wrongline / `verify_citations` 39/0。*

---

## 20. A20-1 八轮定案复核（父代理第八轮指正）

> **基线**：`audit-a.md` 456124 B → 现版本；`verify_anchors.py` 10977 B / 13:47:07（v9）；`verify_citations.py` 9726 B / 13:54:21（43 项）。
> **方法**：全部自行实测；探针在 `.tmp\audit-b0-final\v9shadow\` 影子副本，真实文档零改动。

### 20.0 结论先行

| 项 | 父代理主张 | 我的独立结论 |
|---|---|---|
| **R-1** A6 探针（`:432`→`:304`）已被抓 | 已抓 | **✅ 成立**（我实跑确认）；**但 A6 不是我做的**（见 20.1.1） |
| **R-2** I1 区间起点 | 首片段必须在 `cur[A]` | **⚠️ 部分成立**：单片段路径合理；**多片段锚点若末片段过短会退化，起点约束失效**（实测 BLIND） |
| **R-3** `(in Func)` 例外安全 | 只用于消歧 | **✅ 成立**：我造「相邻行 + `(in Shutdown)`」→ CAUGHT |
| **R-4** §19 剩 7 条无门禁 | 全是散文/历史 | **⚠️ 数字不准**：实为 **10 条**；其中 7 条 SAFE、3 条 HIST，**但 `doc:3514` 有真实歧义** |
| **R-5** 最终判定 | 已闭环 | **不通过**：I1 有退化路径 + `doc:3514` 散文与源码矛盾 |

---

### 20.1 R-1：A6 探针确实被抓，但它不是我做的

#### 20.1.1 先纠正归因

父代理写「**你的 A6 探针**（`:432`→`:304`，锚点不动）是本轮最重要的发现」。

**我 §19 只做过 E1（差一行）、E2（区间中部）、E3（子串）三个探针，没有做过 A6。**
`audit-b.md` 里 `:304` 的两次出现都在 §14，是「`closed_ = true;` 在 `:304`(Receive) 与 `:432`(Shutdown)」的**归属说明**，不是探针。

```
[BASH: Select-String -Path audit-b.md -Pattern 'A6|:304']
  L4049: :304  enclosed by -> Error Receive(...)
  L4053: **`:432` 属于 `Shutdown`，`:304` 属于 `Receive`。**
```

**A6 应该是甲做的，或者父代理记混了。** 归因错误不影响技术结论，但影响「谁发现了什么」的记录。

#### 20.1.2 我独立实跑 A6：CAUGHT

```
[BASH: python r123_v9.py]
=== R-1: A6 (cite number wrong, anchor untouched) ===
  src[304] = 'closed_ = true;'
  src[432] = 'closed_ = true;'
  both identical? True
  doc:2876 t:432 -> t:304 : exit=1 WRONGLINE=1

  [WRONGLINE] [§18] doc:2876  `t:304`
    anchor not unique and (in Shutdown) does not enclose cur[304] (enclosing=Receive)
```

**错误信息质量很高**：不仅报「不唯一」，还指出 `(in Shutdown)` 与 `enclosing=Receive` 矛盾。
这是 v9 的实质进步——v8 对同一探针会放行（因为 `closed_ = true;` 在 `:304` 上也存在）。

---

### 20.2 R-2：I1 的区间起点 —— 单片段合理，多片段有退化路径

#### 20.2.1 我读了 `range_matches()`

```python
# verify_anchors.py:155-168
def range_matches(src, ca, cb, parts):
    if len(parts) == 1:
        return any(parts[0] in s for s in src[ca - 1:cb])   # 单片段：区间内存在
    return parts[0] in src[ca - 1] and parts[-1] in src[cb - 1]  # 多片段：首尾锚定
```

#### 20.2.2 三种情形实测

```
[BASH: python r23_v9.py]
doc:1798 引用 `src/net/tls_schannel.cpp:101-201`
  clause = '锚点 `Error Handshake(...)` .. `}`'
  cur[101] = 'Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,'
  cur[201] = '}'

  (a) first frag -> cur[102] (off by one) : exit=0 wrongline=0 -> BLIND
  (b) first frag -> cur[101] (correct)    : exit=0 wrongline=0 -> PASS
  (c) single frag cur[117] (middle)       : exit=0 wrongline=0 -> PASS(single=range-interior)
```

- **(b) 正确锚点通过** ✅
- **(c) 单片段中部通过** —— 这符合 `range_matches` 的设计（单片段=「区间内存在」语义），**合理**
- **(a) 差一行 → BLIND** ❌

#### 20.2.3 (a) 为什么 BLIND —— 我查到了根因

我把首片段换成 `cur[102]` 时，第一次用的是 `'std::vector<uint8_t>& out) override {'`（37 字符），
结果 `parts` 只剩 **1 个**（因为 `split_anchor` 要求 `len(p) >= 6`，而末片段 `}` 只有 1 字符被丢弃）：

```
[BASH: 复现 split_anchor]
frags = ['if (closed_) return MakeError(Status::kC', '}']
  frag -> parts: ['if (closed_) return MakeError(Status::kClosed']   <- 只有 1 个
  frag -> parts: []                                                   <- '}' 被 len>=6 过滤
```

**只要锚点的末片段短于 6 字符（如 `}`），多片段锚点就退化成单片段锚点，I1 的起点约束完全失效。**

我用 68 字符的 `cur[106]` 重试，仍是 BLIND：

```
[BASH: python r2a_retry.py]
range 101..201
cur[101] = 'Error Handshake(...)'
cur[106] = 'if (closed_) return MakeError(Status::kClosed, 0, "already closed");'   <- off-by-5 target
cur[201] = '}'
new clause: '（锚点 `if (closed_) ... already closed");` .. `}`）'
exit=0 wrongline=0 -> BLIND
```

**结论：`doc:1798` 这类「签名 .. `}`」锚点，首片段可以随便写区间内任何一行，I1 形同虚设。**

#### 20.2.4 这是设计取舍还是缺陷

**是缺陷**，理由：
- 父代理的原话是「区间引用的**首片段必须在 `cur[A]`**、末片段在 `cur[B]`」
- 但 `len(p) >= 6` 的过滤让 `}` 这类常见收尾片段消失，**代码退回到「单片段」分支**
- 而单片段分支的语义是「区间内存在即可」——**恰好是父代理要禁掉的那个弱判据**

**修法（最小）**：`parts` 为空但原锚点含 `..` 时，应判 FAIL（而不是退回单片段）。

---

### 20.3 R-3：`(in Func)` 例外安全

```
[BASH: python r23_v9.py]
=== R-3: (in Func) must not excuse a wrong line ===
  citation : `t:432`  (line 432)
  cur[432] = 'closed_ = true;'  (cited)
  cur[431] = 'if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {'  (previous)

  anchor -> cur[431] + "  (in Shutdown)" : exit=1 wrongline=1 -> CAUGHT
```

**我造的探针：锚点取相邻行 `cur[431]` + `(in Shutdown)`** —— 被 CAUGHT。

原因（读源码 `:248-252`）：

```python
# The anchor text MUST be on the cited line. `(in Func)` never
# substitutes for this: A1/A2 proved that accepting a bare function
# check lets an anchor taken from the neighbouring line through.
if ca not in hits:
    wrongline.append(... 'anchor not at cur[%d] (hits %s)')
```

**`(in Func)` 只在 `ca in hits` 之后才用于消歧**（`:260-267`）。顺序正确，**R-3 通过**。

---

### 20.4 R-4：§19 剩 10 条（不是 7 条），7 SAFE / 3 HIST

#### 20.4.1 我重算的清单

```
[BASH: python r2_coverage19d.py]
§19 引用: 26 条 / 23 个不同行
  被 43 条覆盖 : 13  [3436,3794,3795,3797,3898,3899,4017,4036,4045,4068,4069,4117,4138]
  无任何门禁   : 10  [3213,3242,3328,3390,3514,3543,3553,3561,3972,3973]
```

父代理说「剩余 7 条」，**实测 10 条**。（差异可能因为我把 `3213`（`doc:3214` 上一行）也算进来了，
且 `3837`/`4022` 被 pin 但不在无锚点清单里。）

**`3553`/`3561` 已修为 `:168`/`:188`，我核实正确**：

```
cur:168 = 'add_test(NAME tls COMMAND rtsc_tls_tests)'              ✅
cur:188 = 'target_compile_options(rtsc_tls_tests PRIVATE /W4 /WX)' ✅
```

#### 20.4.2 逐条判定

```
[BASH: python r4_judge.py]
doc:3213  tls_schannel.cpp :169  SAFE   'consumed = in_size;'
doc:3242  connect_machine.cpp :224 SAFE 'Fail("unexpected data while waiting ...")'
doc:3328  tls.h :198             SAFE   'CreateTlsTransport(...)'
doc:3390  tls_schannel.cpp :733  HIST   '};'   （批 0 前尾部）
doc:3514  CMakeLists.txt :48     HIST   '# TLS transport, three layers (S21 / M28).'
doc:3543  CMakeLists.txt :105    HIST   ''      （空行）
doc:3553  CMakeLists.txt :168    SAFE   'add_test(NAME tls ...)'
doc:3561  CMakeLists.txt :188    SAFE   'target_compile_options(rtsc_tls_tests ... /WX)'
doc:3972  credssp.cpp :176       SAFE   'in.client_challenge.assign(...)'
doc:3973  credssp.cpp :191       SAFE   'exported_session_key_.assign(...)'
```

**7 SAFE / 3 HIST，与父代理的「散文/历史步骤」判断基本一致。**

#### 20.4.3 但 `doc:3514` 有真实歧义（我要单列）

```
[READ:audit-a.md:3514]
**(a) 替换 `:48-55`**（原来的注释 + `add_library` 整段）为：
```

`cur:48` = `# TLS transport, three layers (S21 / M28).` —— 这是**替换后**的新注释。

散文说「替换 `:48-55`（**原来的**注释…）」，暗示 `:48` 处应是**旧**注释
（`# TLS transport. The public header is platform neutral; ...`，见备份）。
**现在 `:48` 已经是新的**，读者按「原来的注释」去 `:48` 找会找不到。

**这是 HIST 类里唯一有真实误导的**：不是「改错代码」，而是「找不到它说的东西」。
建议加一句「（批 0 已执行，行号为执行前）」。

---

### 20.5 R-5：最终判定

> ### A20-1 **未闭环**
> ### 理由 1：I1 区间起点存在退化路径（末片段 < 6 字符时起点约束失效，实测 BLIND）
> ### 理由 2：`doc:3514` 散文说「原来的注释」，但 `cur:48` 已是新注释

#### 20.5.1 三要素

| doc | 引用 | `cur[引用]` 实际内容 | 散文语义 | 应为 |
|---|---|---|---|---|
| `1798` | `t:101-201` + 锚点 `X .. \`}\`` | 首片段可任意落在区间内（实测 `cur[106]` 通过） | 父代理规格：「首片段必须在 `cur[A]`」 | `parts` 为空但含 `..` 时判 FAIL |
| `3514` | `:48-55`（CMakeLists） | `# TLS transport, three layers (S21 / M28).` | 「替换 `:48-55`（**原来的**注释…）」 | 加注「批 0 已执行，行号为执行前」 |

#### 20.5.2 我本轮的三处自我更正

1. **A6 归因**：父代理说「你的 A6 探针」，实际不是我做的（我做过 E1/E2/E3）。**我明确纠正。**
2. **R-2(a) 首次探针无效**：我第一次替换的片段太短（37 字符），导致 `parts` 退化为 1 个，
   我一度误以为「I1 完全不工作」。**用 68 字符的 `cur[106]` 重试后确认仍是 BLIND**，结论不变但依据更硬。
3. **§19 数量**：父代理说剩 7 条，我实测 10 条。差异我列出清单，不掩饰。

#### 20.5.3 建议

1. **`range_matches` 修退化路径**：若原锚点含 `\s\.\.\s` 但 `len(parts) < 2`，判 FAIL。
2. **`doc:3514` 加历史标注**。
3. 可选：`len(p) >= 6` 对末片段放宽到 `>= 1`，但需同时保证「含 `..` 时 parts 必须 ≥ 2」。

#### 20.5.4 计数

**P0 × 0 / P1 × 0 / P2 × 1（I1 退化路径）/ P3 × 1（`doc:3514` 散文歧义）**

*本轮只读：真实文档零改动（每个探针自校验 `real doc unchanged : True`）；
探针全在 `.tmp\audit-b0-final\v9shadow\`；未改任何工程代码；
`ctest` 16/16；门禁哈希 `5CA09A3E...` 未变；`verify_anchors` 0 WRONGLINE / `verify_citations` 43/0。*

---

## 21. 第九轮复核（A20-1 九轮定案）

> **基线**：`audit-a.md` 477657 B / mtime 14:29:12；`verify_anchors.py` 13230 B / 14:27:00（v10）；`anchors_redtest.py` 4864 B / 14:28:18。
> **方法**：全部自行实测；探针在 `.tmp\audit-b0-final\v10shadow\` 影子副本，真实文档零改动。

### 21.0 结论先行

| 项 | 父代理主张 | 我的独立结论 |
|---|---|---|
| **R-1** S22 8 处已修为 `:435` | 已修 | **✅ 成立**（`bak:433` 确证）；**但 `doc:2091` 另有 2 处旧值**（`:423`→`:425`、`:404`→`:406`），P2 |
| **R-2** 我的 `sig .. }` 探针现被抓 | 已修 | **✅ 成立**：精确探针 exit=1 CAUGHT；正确锚点 PASS。**但我的旧探针脚本有 bug**（见 21.2.2） |
| **R-3** 攻击 `brace_balanced` | （要我找盲区） | **⚠️ 找到 2 个**：(a) `depth==0` 也接受 → 非块起始行可通过；(b) 重复行可让两个不同区间同时通过。**但当前文档不可利用** |
| **R-4** 11 探针全绿 | 是 | **✅ 成立**：我独立跑 11/11 全 OK，exit=0 |
| **R-5** 最终判定 | 已闭环 | **不通过（P3）**：`brace_balanced` 有结构性盲区，虽当前不可利用 |

---

### 21.1 R-1：S22 的 8 处已全部修为 `:435`

#### 21.1.1 先用 `bak[n]` 确证「`:435` 才是失败路径」

```
[BASH: 读 cur 与 bak 的 Shutdown 尾部]
=== current :426-436 ===
  :431 if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
  :432     closed_ = true;
  :433     return MakeError(Status::kOk, st, "");        <- 成功分支
  :434 }
  :435 return MakeError(Status::kOk, st, "shutdown best effort");   <- S22 失败路径
  :436 }

=== backup :424-434 (批 0 前) ===
  bak:429 if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
  bak:430     closed_ = true;
  bak:431     return MakeError(Status::kOk, st, "");
  bak:432 }
  bak:433 return MakeError(Status::kOk, st, "shutdown best effort");   <- 批 0 前就是 :433
```

**`bak:433` = `return MakeError(Status::kOk, st, "shutdown best effort");`** —— 父代理的论断成立：
批 0 前 S22 在 `:433`，批 0 后 +2 到 `:435`。

#### 21.1.2 S22 的修复点已改为 `:435`，但 `doc:2091` 另有 2 处旧值

**S22 本身**（失败路径引用）已全部改为 `:435`：

```
[BASH: 提取 6 个 doc 行的引用号]
doc:2083  cites=[432, 431, 432, 435, 431, 432, 435, 432, 431]
doc:2091  cites=[431, 432, 435, 423, 404, 435]
doc:2464  cites=[357-360, 435]
doc:3065  cites=[435]
doc:3122  cites=[435]
doc:3169  cites=[435, 407, 208-209]
```

**全文检索「S22 + `:433`」：零命中**（`doc:7123` 在 §30+ 审计历史区，是引述旧叙述）。

**但 `doc:2091` 同一行里还有 2 处旧值**（不是 S22 的修复点，是同一行的旁证）：

| 引用 | 散文语义 | `cur[引用]` 实际 | 应为 | `bak` 确证 |
|---|---|---|---|---|
| `:423` | 「`shutdown_sent_` 已为真（`:423`）」 | `SECURITY_NATIVE_DREP, nullptr, 0, &ctx_,` | **`:425`** | `bak:423 = shutdown_sent_ = true;` |
| `:404` | 「再次 `Shutdown()` 在 `:404` 返回空」 | `Error Shutdown(std::vector<uint8_t>& out) override {` | **`:406`** | `bak:404 = if (shutdown_sent_) return MakeError(...)` |

```
[BASH: 逐行核实]
  doc:2091 prose: 「shutdown_sent_ 已为真（:423）」
    cur:423 = 'SECURITY_NATIVE_DREP, nullptr, 0, &ctx_,'
    cur:425 = 'shutdown_sent_ = true;'          <- 正确目标
  doc:2091 prose: 「再次 Shutdown() 在 :404 返回空」
    cur:404 = 'Error Shutdown(std::vector<uint8_t>& out) override {'
    cur:406 = 'if (shutdown_sent_) return MakeError(Status::kOk, 0, "");'  <- 正确目标
```

**S22 的 8 处修复点通过；但 `doc:2091` 的另外 2 处旁证仍是旧值（P2）。**

**这也印证父代理自己的观察**：「分章审查会漏跨章成组错误」——
我只核了 S22 的修复点（`:435`），没核同一行里的其他引用。

#### 21.1.3 我同意父代理对「为什么最危险」的判断

`:433` 和 `:435` **都返回 `kOk`**，只有 `:435` 不置 `closed_`。
执行 AI 按 `:433` 改会让红证用例变绿而真缺陷仍在 —— 这是「假绿」，比红灯难发现。

---

### 21.2 R-2：我的 `sig .. }` 探针现在确实被抓 —— 但我的旧脚本有 bug

#### 21.2.1 精确探针：CAUGHT

```
[BASH: python dbg_off5.py —— 精确替换 clause 内的首片段]
clause = '锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`'
new clause = '锚点 `if (closed_) return MakeError(Status::kClosed, 0, "already closed");` .. `}`'
changed? True

exit 1
  anchored, unique, start-correct        : 66
  WRONGLINE                              : 1
  [WRONGLINE] [§15] doc:1798  `src/net/tls_schannel.cpp:101-201`
    range anchor misplaced: 'if (closed_) return MakeError('..'}' not at
    cur[101]='Error Handshake(const uint8_t* in, s' / cur[201]='}'
```

**v10 正确拒绝了 off-by-5 的首片段。** 错误信息还给出了两侧实际内容，可读性好。

#### 21.2.2 我必须承认：我的旧探针脚本 `r2a_retry.py` 是坏的

我 §20 用 `r2a_retry.py` 得出「仍 BLIND」，**那个结论是错的**。
原因：该脚本用 `span` 计算 clause 边界时把 `锚点` 之后的内容切错了位置，
导致「替换」实际没落到锚点文本上，于是门禁看到的是**未修改的文档** → exit=0。

```
[BASH: r2a_retry.py 的输出（错误）]
new clause: '（锚点 `if (closed_) ... already closed");` .. `}`）'
exit=0 wrongline=0 -> BLIND
```

**这与我在 §18.4 批评父代理红证「只看描述不验证」是同一类错误——我自己的探针没有自校验。**
修正后的 `dbg_off5.py` 增加了 `changed? True` 和 `patched line contains cur[106] text? True` 两道自检。

**结论修正：v10 已修复该盲区，我 §20 的「P2 I1 退化路径」应撤回。**

---

### 21.3 R-3：攻击 `brace_balanced` —— 找到 2 个结构性盲区

#### 21.3.1 先看规则本身

```python
# verify_anchors.py
def brace_balanced(src, ca, cb):
    depth = 0
    for i in range(ca, cb):
        s = src[i - 1]
        depth += s.count('{') - s.count('}')
        if depth < 0:
            return False
    if depth not in (0, 1):        # ← 接受 0 也接受 1
        return False
    s = src[cb - 1]
    return '}' in s and depth + s.count('{') - s.count('}') == 0
```

#### 21.3.2 盲区 A：`depth == 0` 也接受 —— 非块起始行能通过

```
[BASH: python r3_attack.py]
=== Attack 1: ranges that pass brace_balanced but start mid-function ===
  PASS but start has no "{": 47..64
     cur[47] = 'constexpr size_t kMinRecordHeader = 5;'
     cur[64] = '}'
  PASS but start has no "{": 48..64
     cur[48] = 'constexpr uint32_t kMaxRecordPayload = 16384;'
     cur[64] = '}'
  ... (共 8+ 例)
```

`cur:47` 是 `constexpr` 常量定义，**根本不开启块**；`cur:64` 是某个函数的闭合 `}`。
`depth` 在 `47..63` 上是 0，`64` 把它带回 0 —— 规则通过，但**这个区间不是「块」**。

**根因**：`depth not in (0, 1)` 里的 `0` 允许「自包含区间」（不净开块）。
而 `sig .. \`}\`` 这种锚点的语义是「从签名开始、到块结束」，**必须 `depth == 1`**。

#### 21.3.3 盲区 B：重复行让两个不同区间同时通过

```
[BASH: python r3_exploit.py]
=== duplicated substantive lines (>=12 chars): 42 ===
  lines [103, 206]  'consumed = 0;'
  lines [105, 208, 233] 'if (terminal_) return last_error_;'
  lines [106, 209, 232] 'if (closed_) return MakeError(Status::kClosed, 0, "already closed");'

=== can a duplicated opener make TWO different ranges both pass? ===
  BOTH pass: [103..111] and [206..212]  first text 'consumed = 0;'
  BOTH pass: [103..111] and [206..216]  first text 'consumed = 0;'
  BOTH pass: [103..131] and [206..212]  first text 'consumed = 0;'
  ... (6 例)
```

`consumed = 0;` 在 `:103`（Handshake）和 `:206`（Send）各出现一次。
**`[103..111]` 和 `[206..212]` 都通过 `brace_balanced`** —— 因为两处的块结构相似。

如果文档把 `t:103-111` 误写成 `t:206-212`，锚点文本 `consumed = 0;` 依然命中，
brace 配平依然通过 → **门禁看不见**。

#### 21.3.4 但两个盲区当前都不可利用

我用真实文档做了 exploit 尝试：

```
[BASH: python r3_exploit2.py]
=== searching for a real doc range citation whose start text is duplicated ===
  no exploitable doc line found in section 19
  no exploit target found
```

**原因**：文档里所有 `sig .. \`}\`` 区间引用的首行文本（`Error Handshake(...)`、
`Error Receive(...)`、`Error PeerSubjectPublicKey(...)` 等）**都是唯一的**，
不存在「换个区间首行文本仍命中」的情况。

**所以：这是「结构性风险」而非「现存缺陷」。**

#### 21.3.5 父代理特别问的两条：文本分支正确

```
[BASH: python r3_textbranch.py]
=== doc:2882  t:411-435 (last fragment is a return, text branch) ===
  first frag : 'SecBuffer token{0, SECBUFFER_TOKEN, nullptr};'
  cur[411]   : 'SecBuffer token{0, SECBUFFER_TOKEN, nullptr};'      first on 411? True
  last frag  : 'return MakeError(Status::kOk, st, "shutdown best effort");'
  cur[435]   : 'return MakeError(Status::kOk, st, "shutdown best effort");'  last on 435? True
  verdict: both boundary fragments land -> text branch PASS (correct)
```

**位移测试**：

```
  t:411-435 shift -2 -> 409..433 : first=False last=False -> fail(good)
  t:411-435 shift -1 -> 410..434 : first=False last=False -> fail(good)
  t:411-435 shift +1 -> 412..436 : first=False last=False -> fail(good)
  t:411-435 shift +2 -> 413..437 : first=False last=False -> fail(good)
  t:431-435 shift -2 -> 429..433 : first=False last=False -> fail(good)
  ... (全部 fail)
```

**这两条走文本分支是合理的**：末片段 `return MakeError(... "shutdown best effort")`
是唯一文本，±2 位移后两侧都对不上 → 正确拒绝。**不需要 brace 检查。**

#### 21.3.6 `#if` / 宏 / lambda / 初始化列表的干扰

```
[BASH: python r3_brace.py]
=== lines containing braces inside literals/comments ===
  total: 0
=== are any of those lines inside a cited range? ===
  cited ranges in doc: 73
  overlaps: 0
```

**本文件里没有「大括号出现在字符串/注释内」的行**，所以 `count('{')` 的字面量盲区不可利用。
但这是**本文件的巧合**，不是规则的正确性 —— 若将来有人写 `if (c == '{')`，`brace_balanced` 会算错。

---

### 21.4 R-4：11 探针我独立跑，11/11 全绿

```
[BASH: python evidence/exec/anchors_redtest.py]
baseline unchanged                     exit=0 expect=0  OK
A1 anchor from cur[431]                exit=1 expect=1  OK
A2 anchor from cur[433]                exit=1 expect=1  OK
A6 :432 -> :304 anchor untouched       exit=1 expect=1  OK
B1 anchor exists elsewhere             exit=1 expect=1  OK
B2 anchor very common                  exit=1 expect=1  OK
B3 anchor does not exist               exit=1 expect=1  OK
C1 "sig .. }" range -2                 exit=1 expect=1  OK
C2 "sig .. }" range end +2             exit=1 expect=1  OK
C3 "sig .. }" start +1                 exit=1 expect=1  OK
C4 single-frag midrange -2             exit=1 expect=1  OK
EXIT=0
```

**我独立执行（未采信父代理贴的输出），11/11 与预期一致。** R-4 通过。

---

### 21.5 R-5：最终判定

> ### A20-1 **未闭环**：`doc:2091` 有 2 处旧值（P2），`brace_balanced` 有 1 个结构盲区（P3）

#### 21.5.1 本轮我修正了自己上一轮的两个错误

1. **撤回 §20 的「P2 I1 退化路径」**：我的探针脚本有 bug（替换没落到锚点上），
   v10 实际已修复。这是**我的假阳性**，我主动撤回。
2. **接受父代理对 R-2(c) 的推翻**：我 §20 说「单片段=区间内存在，合理」，
   父代理指出这对区间引用没有区分力（任何落在区间内的锚点都能过），
   v10 已改为「首片段必须在 `cur[ca]`」。**父代理对，我错。**

#### 21.5.2 唯一残留：`brace_balanced` 的 `depth==0`（P3）

| 位置 | 实际行为 | 规格语义 | 应为 |
|---|---|---|---|
| `verify_anchors.py` `brace_balanced` | `if depth not in (0, 1)` —— 接受 `depth==0`（自包含区间） | `sig .. \`}\`` 锚点语义是「从签名开始到块结束」，必须净开一个块 | `if depth != 1` |

**为什么是 P3 而不是 P1/P2**：
- 当前文档**没有**可利用的实例（我实测 `r3_exploit2.py` 找不到目标）
- 不导致执行 AI 改错代码
- 但它是「规则本身不严格」，将来加新区间引用时可能被踩

#### 21.5.3 关于「能否放行」

| 层面 | 状态 |
|---|---|
| 产品代码（S21/S0.9） | ✅ 可盖章（`ctest` 16/16、门禁哈希未变、`nm` 零符号——前几轮已验） |
| §19 执行包行号 | ✅ 26 条引用全部有门禁或人工判定（10 条 SAFE/HIST 已核） |
| S22 成组引用 | ✅ 8 处已修为 `:435`，`bak:433` 确证 |
| 验证机制 | ⚠️ `brace_balanced` 有 P3 结构盲区，当前不可利用 |

**我的判定：`doc:2091` 的 2 处旧值需修（P2）；`brace_balanced` 的 `depth==0` 记 P3。**
修完这 2 处后，§19 与 §17/§18 的引用即全部有门禁或人工确证。

#### 21.5.4 计数

**P0 × 0 / P1 × 0 / P2 × 2（`doc:2091` 的 `:423`、`:404`）/ P3 × 1（`brace_balanced` 接受 `depth==0`）**

#### 21.5.5 我的方法反思

本轮我用 `+2` 启发式扫描 §5–§19 得到 **65 个「SHIFTED candidates」**，
但逐条看，**绝大多数是已被正确更新的引用**（内容确实从 `a` 移到 `a+2`，那是批 0 的正常位移）。

**这个启发式零区分力**——我在 §16 已经批评过父代理的同一做法，这轮我自己又用了一遍。

**真正有效的方法是「散文语义 → 源码定位」**（我在 §21.1.2 用的），
它才找出了 `doc:2091` 那 2 处。**启发式只能用来筛候选，判定必须人工。**

*本轮只读：真实文档零改动（每个探针自校验 `real doc unchanged : True`）；
探针全在 `.tmp\audit-b0-final\v10shadow\`；未改任何工程代码；
`ctest` 16/16；门禁哈希 `5CA09A3E...` 未变；`verify_anchors` 0 WRONGLINE / `verify_citations` 43/0；
`anchors_redtest` 11/11。*

---

## 22. 第十轮复核（A20-1 十轮定案）

> **基线**：`audit-a.md` 7691 行 / mtime 15:0x；`verify_anchors.py` 14295 B / 14:55:42（v11）；`anchors_redtest.py` 5724 B / 14:57:37（13 探针）。
> **方法**：每个探针**内置自校验**（替换是否落地 / 新句是否存在 / 旧句计数是否恰好 -1），不落地即 ABORT，绝不在未修改的基线上测出假结论。

### 22.0 结论先行

| 项 | 父代理主张 | 我的独立结论 |
|---|---|---|
| **R-1** `doc:2091` 已改 `:425`/`:406` | 已修 | **✅ 通过**：`cur:425 = shutdown_sent_ = true;`、`cur:406 = if (shutdown_sent_) return ...`，散文对得上 |
| **R-2** `starts_a_function`（I6） | 修法正确 | **⚠️ 盲区 1 个（P2）**：SIG 正则漏判 **5/24 真函数** → **正确引用会被误拒**，且错误信息谎称 `misplaced` |
| **R-3** `depth != 1` | 已收紧 | **✅ 通过**：3 个 depth==0 区间全 `exit=1`；4 个真实 depth=1 区间全 `exit=0` |
| **R-4** 13 探针 | 全绿 | **✅ 通过**：我独立跑 **13/13 OK**，基线 exit=0 |
| **R-5** 最终判定 | 已闭环 | **不通过（P2×4）**：SIG 正则漏判 + 我上轮追加的 3 处 §17 旧值仍未修 |

---

### 22.1 R-1：`doc:2091` 的 2 处旧值已修 —— 通过

```
[BASH: 读 doc:2091 + cur]
doc:2091 prose: 「shutdown_sent_ 已为真（:425）」→ 再次 Shutdown() 在 :406 返回空
  cur:425 = 'shutdown_sent_ = true;'                              ✓ 对散文
  cur:406 = 'if (shutdown_sent_) return MakeError(Status::kOk, 0, "");'  ✓ 对散文
```

`bak` 确证这两处各 +2：`bak:423 → cur:425`、`bak:404 → cur:406`。**修得对。**

---

### 22.2 R-2：`starts_a_function` 的 SIG 正则漏判 5/24 真函数（P2）

#### 22.2.1 穷举：24 个真函数定义，SIG 漏判 6 个

判定标准（可审计，杜绝"看结果编标准"）：开块行不是控制关键字（`if/for/while/switch/else/do/try/catch`）、
不是 `namespace/class/struct/union/enum`、不以 `;` 结尾、不是聚合初始化、且 `brace_balanced()` 通过。

```
[BASH: python r2_sig2.py]
=== REAL function definitions detected: 24 ===
  OK   :60  ..64    std::string FormatCode(long code) {
  MISS :89  ..93    ~SchannelTransport() override {
  OK   :95  ..98    bool Start(std::string& why) {
  OK   :348 ..369   Error PeerSubjectPublicKeyInfo(std::vector<uint8_t>& out) const override {
  OK   :371 ..384   Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {
  OK   :386 ..392   Error PeerCertificateDer(std::vector<uint8_t>& out) const override {
  OK   :395 ..399   Error negotiated(NegotiatedInfo& out) const override {
  OK   :404 ..436   Error Shutdown(std::vector<uint8_t>& out) override {
  OK   :447 ..462   bool AcquireCredentials(std::string& why) {
  OK   :464 ..477   DWORD ProtocolMask() const {
  OK   :479 ..488   std::wstring TargetName() const {
  OK   :491 ..509   bool FinishHandshake(std::string& why) {
  MISS :517 ..519   uint32_t ExpectedActualOverhead() const {
  OK   :521 ..531   void LearnActualOverhead(size_t plaintext_size, size_t record_size) {
  OK   :533 ..559   bool QueryNegotiated(std::string& why) {
  MISS :561 ..568   static uint16_t WireVersionFromProtocolMask(DWORD mask) {
  OK   :570 ..577   bool EnforceVersionWindow(std::string& why) {
  OK   :582 ..587   size_t MaxChunk() const {
  MISS :653 ..654   SecBuffer ib{...}                       <- 聚合初始化，非函数（分类瑕疵）
  MISS :671 ..684   PCCERT_CONTEXT PeerCert() const {
  OK   :686 ..688   Error NotHandshaken() const {
  MISS :690 ..696   static Error ConstError(Status s, int32_t code, const char* msg) {
  OK   :698 ..704   Error MakeError(Status s, long code, std::string msg) const {
  OK   :708 ..712   Error Fail(Status s, long code) {
```

**真函数漏判 5 个**（`653-654` 是我的分类器把聚合初始化误收，不是函数）：

| 行 | 签名 | SIG 为何不中 |
|---|---|---|
| `:89` | `~SchannelTransport() override {` | 析构函数：无返回类型 |
| `:517` | `uint32_t ExpectedActualOverhead() const {` | 返回类型 `uint32_t` 不在白名单 |
| `:561` | `static uint16_t WireVersionFromProtocolMask(DWORD mask) {` | `static` 前缀，且 `uint16_t` 不在白名单 |
| `:671` | `PCCERT_CONTEXT PeerCert() const {` | 返回类型 `PCCERT_CONTEXT` 不在白名单 |
| `:690` | `static Error ConstError(Status s, int32_t code, const char* msg) {` | `static` 前缀 |

#### 22.2.2 红证：**正确**的引用被误拒

每个探针自校验 `old=2,new=1`（替换落地、旧句恰好消耗一次）：

```
[BASH: python r2_probe.py]
BASE occurrences in real doc: 3

case                                               self-check         result
--------------------------------------------------------------------------------
baseline unchanged                                 baseline           PASS
S1 correct cite of PeerCert()                      ok(old=2,new=1)    *** FALSE ALARM ***
S2 correct cite of ExpectedActualOverhead()        ok(old=2,new=1)    *** FALSE ALARM ***
S3 correct cite of WireVersionFromProtocolMask()   ok(old=2,new=1)    *** FALSE ALARM ***
S4 correct cite of ConstError()                    ok(old=2,new=1)    *** FALSE ALARM ***
S5 correct cite of destructor                      ok(old=2,new=1)    *** FALSE ALARM ***
S6 control: PeerSubjectPublicKey() passes          ok(old=2,new=2)    PASS
P1 inner if block                                  ok(old=2,new=1)    PASS
P2 aggregate-init block                            ok(old=2,new=1)    PASS
P3 namespace block                                 ok(old=2,new=1)    PASS
P4 struct block                                    ok(old=2,new=1)    PASS
--------------------------------------------------------------------------------
failures: 5
```

**5/5 正确引用全部被拒**。错误信息还**自相矛盾**：

```
[BASH: python r2b.py]
=== S1 PeerCert ===
  exit=1
  [WRONGLINE] [§15] doc:1798  `src/net/tls_schannel.cpp:671-684`
    range anchor misplaced: 'PCCERT_CONTEXT PeerCert() cons'..'}'
    not at cur[671]='PCCERT_CONTEXT PeerCert() const {' / cur[684]='}'

=== S5 dtor ===
  [WRONGLINE] [§15] doc:1798  `src/net/tls_schannel.cpp:89-93`
    range anchor misplaced: '~SchannelTransport() override '..'}'
    not at cur[89]='~SchannelTransport() override {' / cur[93]='}'
```

**注意 `not at cur[671]='PCCERT_CONTEXT PeerCert() const {'` —— 文本明明就在那一行。**
门禁说「misplaced」，真实原因是 `starts_a_function` 返回 False。
**这条错误信息会把修文档的人引向完全错误的方向。**

#### 22.2.3 为什么是 P2 而不是 P1

5 个漏判函数**当前文档零引用**：

```
[BASH: python r1_recheck.py]
  cur[89]  = '~SchannelTransport() override {'              -> 0 doc citations
  cur[517] = 'uint32_t ExpectedActualOverhead() const {'     -> 0 doc citations
  cur[561] = 'static uint16_t WireVersionFromProtocolMask(...) {' -> 0 doc citations
  cur[671] = 'PCCERT_CONTEXT PeerCert() const {'             -> 0 doc citations
  cur[690] = 'static Error ConstError(...) {'                -> 0 doc citations
```

**当前零误报**（`verify_anchors.py` exit=0、WRONGLINE=0），但**批 2 要改 S24 / S7 / S18，
极可能引用 `ConstError` / `PeerCert` / 析构函数**——那时门禁会拒绝**正确**的引用，
执行 AI 会以为文档写错而反复改，或干脆绕过门禁。**这是「将来会咬人」的缺陷 → P2。**

#### 22.2.4 修法建议

```python
SIG = re.compile(
    r'^\s{0,8}'
    r'(?:static\s+)?'                                  # static 前缀
    r'(?:~?[A-Za-z_]\w*(?:::\w+)?'                      # 返回类型 或 ~Dtor
    r'(?:\s*<[^>]*>)?'                                 # 模板参数
    r'(?:\s*[*&])?)'                                   # 指针/引用
    r'\s+([A-Za-z_]\w*)\s*\(')                         # 函数名(
```

或更稳的做法：**放弃"像不像函数签名"，改判「开块行的花括号是否使 depth 从 0 变 1 且该行不是控制/声明关键字」**。
`starts_a_function` 的**目的**只是排除「内层块冒充函数体」，用「块的开块行必须不是 `if/for/while/switch/else/do/try/catch/struct/class/namespace/enum`」
就足以达到目的，且**不依赖返回类型白名单**（白名单永远漏）。

---

### 22.3 R-3：`depth != 1` 已收紧 —— 通过

```
[BASH: python r3_probe2.py]
=== candidate depth==0 ranges ===
  96..98   start='if (!AcquireCredentials(why)) return false;'
  103..116 start='consumed = 0;'   end='SecBuffer in_bufs[1]{};'
  104..116 start='out.clear();'
  105..116 start='if (terminal_) return last_error_;'

=== real depth==1 targets ===
  R2 Receive 230-345               depth=1
  R3 PeerSubjectPublicKey 371-384  depth=1
  R4 FinishHandshake 491-509       depth=1
  R5 Shutdown 404-436              depth=1

case                                      self-check   result
------------------------------------------------------------------
baseline unchanged                        baseline     exit=0 PASS
D0 depth==0 103..116                      ok           exit=1 PASS
D0 depth==0 104..116                      ok           exit=1 PASS
D0 depth==0 105..116                      ok           exit=1 PASS
R2 Receive 230-345                        ok           exit=0 PASS
R3 PeerSubjectPublicKey 371-384           ok           exit=0 PASS
R4 FinishHandshake 491-509                ok           exit=0 PASS
R5 Shutdown 404-436                       ok           exit=0 PASS
------------------------------------------------------------------
failures: 0
```

**depth==0 全拒绝、真实 depth=1 全通过。R-3 通过。**

#### 22.3.1 我上轮 P3 的例子确实错了（父代理指正正确）

我上轮说 `cur:47..64` 是 `depth==0`。**实测 `depth==1`**：

```
[BASH: 逐行累加 47..63]
  after :47 depth=0  constexpr size_t kMinRecordHeader = 5;
  ...
  after :59 depth=0
  after :60 depth=1  std::string FormatCode(long code) {   <- 我漏了这一行
  after :63 depth=1  return buf;
```

`cur:60` 是 `FormatCode` 的签名，`cur:64` 是它的 `}`。**`47..64` 恰好完整包住 `FormatCode`，
depth=1，不是 depth=0。** 我在 §21.3.2 举的例子是错的。

**结论（接受 `depth==0` 确实被放行）对，例子错。** 父代理用 `t:103-116` / `t:103-120` 才是真 depth==0。
→ 教训：**举例前必须把 depth 逐行算出来，不能凭「首行没有 `{`」推断 depth==0**。

---

### 22.4 R-4：13 探针我独立跑，13/13 全绿

```
[BASH: python evidence/exec/anchors_redtest.py]
baseline unchanged                     exit=0 expect=0  OK
A1 anchor from cur[431]                exit=1 expect=1  OK
A2 anchor from cur[433]                exit=1 expect=1  OK
A6 :432 -> :304 anchor untouched       exit=1 expect=1  OK
B1 anchor exists elsewhere             exit=1 expect=1  OK
B2 anchor very common                  exit=1 expect=1  OK
B3 anchor does not exist               exit=1 expect=1  OK
C1 "sig .. }" range -2                 exit=1 expect=1  OK
C2 "sig .. }" range end +2             exit=1 expect=1  OK
C3 "sig .. }" start +1                 exit=1 expect=1  OK
C4 single-frag midrange -2             exit=1 expect=1  OK
C5 inner block as function body        exit=1 expect=1  OK
C6 depth==0 range accepted             exit=1 expect=1  OK
```

**13/13 OK，exit=0。**（该脚本自带 `if old not in orig: SKIP + fail` 自校验，无假绿风险。）

---

### 22.5 R-5：最终判定 —— 不通过（P2×1）

> ### A20-1 **未闭环**（P2×4）：
> ### ① `starts_a_function` 的 SIG 白名单漏判 5/24 真函数，正确的 `sig .. }` 引用会被误拒，且错误信息谎称 `misplaced`
> ### ② `doc:2443` / `doc:2815` / `doc:2830` 三处 §17 bare 引用仍指向旧行号（我上轮追加报告，未修）

#### 22.5.1 修复优先级

| 项 | 级别 | 理由 |
|---|---|---|
| SIG 正则漏判 5 类真函数 | **P2** | 当前零引用故零误报；但批 2 改 S24/S7/S18 很可能引用 `ConstError`/`PeerCert`/析构函数 → 会拒绝正确引用 |
| 错误信息 `misplaced` 误导 | **P3** | 同一条根因；建议在 `starts_a_function` 返回 False 时单独报 `not a function signature` |
| `depth == 0` 放行 | **已修** | `depth != 1` 已生效，3 红证全拒绝 |

#### 22.5.2 我本轮的另一处自我更正

**接受父代理对我 P3 例子的指正**：`cur:47..64` 的 depth 是 **1** 不是 0（`:60` `FormatCode` 开块）。
我的结论（`depth==0` 被放行）对，但**证据举错了**。
**这正是父代理 memory 规则 100「例子与结论必须分开核」** —— 我核了结论没核例子。

#### 22.5.3 我上轮追加发现的 3 处 §17 旧值 —— **仍未修**

上一轮报告后我继续扫，又发现 §17 三处 bare 引用（无锚点 → 门禁不看）指错行。
**父代理本轮只修了 `doc:2091`，这 3 处仍在：**

```
[BASH: 当前文档引用号]
doc:2443 cites=['t:244', 'tls_schannel.cpp:232']
doc:2815 cites=['t:233']
doc:2830 cites=['t:402-434', 'tls_schannel.cpp:411-413']
```

| doc | 引用 | 散文语义 | `cur[引用]` 实际 | 应为 | bak 确证 |
|---|---|---|---|---|---|
| `2443` | `t:244` | 「<5 字节返回 kOk」 | `if (rx_buffer_.size() < kMinRecordHeader) {` | **`t:246`** | `bak:244 = ? MakeError(Status::kOk, 0, "");` |
| `2815` | `t:233` | 「`Receive` 正是从 `rx_buffer_` 消费」 | `if (terminal_) return last_error_;` | **`t:271`** | `bak:233 = if (size != 0 && ciphertext != nullptr) {` |
| `2830` | `t:402-434` | 「`SchannelTransport::Shutdown`」 | `cur:402` = 空行、`cur:434` = 内层 if 的 `}` | **`t:404-436`** | `bak:402 = Error Shutdown(...) {`、`bak:434 = }` |

```
[BASH: python r1_recheck.py]
=== doc:2830  t:402-434 (prose: SchannelTransport::Shutdown) ===
  cur:402 = ''                                    <-- cited START（空行）
  cur:404 = 'Error Shutdown(std::vector<uint8_t>& out) override {'
  cur:434 = '        }'                           <-- cited END（内层 if 的闭合）
  cur:436 = '    }'
  depth(402..434) = 2
  depth(404..436) = 1
  bak:402 = 'Error Shutdown(...) override {'      (批 0 前就是 :402)

=== doc:2443  t:244 (prose: "<5 bytes returns kOk") ===
  cur:244 = 'if (rx_buffer_.size() < kMinRecordHeader) {'
  cur:246 = '? MakeError(Status::kOk, 0, "")'      <- 散文指的就是这行
  bak:244 = '? MakeError(Status::kOk, 0, "")'      <- 批 0 前在 :244，+2 位移

=== doc:2815  t:233 (prose: "Receive consumes from rx_buffer_") ===
  cur:233 = 'if (terminal_) return last_error_;'
  cur:271 = 'rx_buffer_.erase(rx_buffer_.begin(),'  <- 唯一消费点
  bak:233 = 'if (size != 0 && ciphertext != nullptr) {'
```

**为什么门禁没抓到**：这 3 处都是 **bare 引用（无锚点）**，
`verify_anchors.py` 把它们归入「no clause」，只计数不校验。

**为什么最关键的是 `doc:2830`**：`t:402-434` 的 `cur:402` 是**空行**，
`depth=2` —— 即使补上锚点 `sig .. }`，`brace_balanced` 也会拒绝（`depth != 1`）。
**这条引用现在指向一个空行到内层 `if` 闭合的区间，与散文「SchannelTransport::Shutdown」完全不符。**

#### 22.5.4 计数

**P0 × 0 / P1 × 0 / P2 × 3（`doc:2443`、`doc:2815`、`doc:2830`）+ P2 × 1（SIG 白名单漏判） / P3 × 1（`misplaced` 错误信息误导）**

#### 22.5.5 放行建议

**需修 4 项**：
1. `doc:2443` `t:244` → `t:246`
2. `doc:2815` `t:233` → `t:271`
3. `doc:2830` `t:402-434` → `t:404-436`
4. SIG 正则扩展（见 22.2.4）

修完后即可闭环。其余（S22 8 处、`doc:2091` 2 处、`depth!=1`、13 探针）全部通过。

*本轮只读：真实文档零改动（探针自带 `old=/new=` 计数自校验，全部 `ok`）；
探针全在 `.tmp\audit-b0-final\r2_probe.md` / `r3_probe.md` 影子副本；
未改任何工程代码；`ctest` 16/16；门禁哈希 `5CA09A3E...` 未变；
`verify_anchors` 0 WRONGLINE / `verify_citations` 43/0；`anchors_redtest` 13/13。*

---

## 36. 第十二轮复核（v13 `CLOSING_PREFIX`）

> 基线：`verify_anchors.py` 16845 B / 15:57:00（SHA256 `AC617230…`）；`anchors_redtest.py` 7941 B / 16:01:53（19 例）。方法：exec 模块头部取门禁**自己的** `starts_a_function` / `brace_balanced` / `SRC`（`SRC` 已 `' '.join(split())` 归一化），端到端探针全部自校验（`old` 计数恰好 -1）。

### 36.1 Q-1 守卫过宽？—— 否，本文件零误杀

```
[BASH: q12.py]  tls_schannel.cpp 中以 `}` 开头且净开块的行: 1
   :315  '} else if (st == SEC_I_CONTINUE_NEEDED) {'   ← 不是函数
[BASH: q12.py]  src/ + include/ 全树扫描（raw 行，净开块，`(` 且以 `{` 结尾，
                 排除 else/while/catch/if/for/do）: 0 个候选
```

**结论：无真函数被 `CLOSING_PREFIX` 误杀。** `};`/`}` 类行本来就不是函数起点。

### 36.2 Q-2 守卫过窄？—— 是，但**缺口不在 `}` 前缀**

逐类普查（`tls_schannel.cpp`，归一化后）：

| 形态 | 出现 | 门禁判定 |
|---|---|---|
| `} else if (...) {` | `:315` | notfn（`CLOSING_PREFIX`） |
| `} else {` | `:315/:320/:555` | notfn |
| `} while` / `} catch` / `,` 续行 / `&&` / `\|\|` / `->` | **0** | — |
| `?` / `:` 三元续行 | `:246/:247/:261/:262` | FUNC（但 `brace_balanced` 全拒） |
| `}` 单独 | 82 行 | 全部 notfn |

**`}` 前缀一类已覆盖干净。但 Q-1 的穷举暴露了更严重的漏洞 —— 守卫对「根本不是函数签名」的行判 True：**

```
[BASH: q2_e2e.py]  （端到端过真实门禁，每例自校验 old 3→2）
case                           selfchk  gate
comment line as function       ok       exit=0 ACCEPTED   cur[9]='// other platforms ...'
statement + inner if           ok       exit=0 ACCEPTED   cur[349]='out.clear();'
statement run                  ok       exit=0 ACCEPTED   cur[372]='out.clear();'
aggregate init                 ok       exit=0 ACCEPTED   cur[595]='sb[1] = {...}'
aggregate init 2               ok       exit=0 ACCEPTED   cur[653]='SecBuffer ib{...}'
real function (control)        ok       exit=0 ACCEPTED   cur[371]='Error PeerSubjectPublicKey(...'
```

`cur[9]` 是**注释行**，`:349`/`:372` 是**普通语句**，`:595`/`:653` 是**聚合初始化**；`starts_a_function` 对它们全返回 True，`brace_balanced` 也通过，**`sig .. }` 引用被接受**。

根因：`starts_a_function` 只做「无 `(` → False」「行首关键字 → False」，其余一律 True。`head = line.split('(')[0]` 对 `out.clear` / `sb[1] = ` / `// other platforms` 都能匹配到标识符。
→ **P2**：I6 的实际判别力远低于其注释宣称（注释说"排除内层块冒充函数体"，实测连语句和注释都放行）。建议改为「开块行必须是 `Type Name(` 形态且不含 `=`、不以 `//` 开头」。

### 36.3 Q-3 E1 是假红证 —— 已用变异测试证明

```
[BASH: q3b.py]  对照/变异都指向同一 shadow doc（E1 替换自校验 old 3→2）
CONTROL (guard intact, shadow doc with E1): exit=1  (expect 1)
MUTANT  (guard removed, same shadow doc) : exit=1  (expect 0 if E1 is real)
=> NOT DISCRIMINATING
```

原因（`q3c_why.py`）：`:315-321` 的 `depth` 走查全程为 **0**，`brace_balanced` 本就返回 False。

```
  after :315 depth=0 … after :320 depth=0
  brace_balanced(315, 321) = False   (needs depth==1)
  => :315 被 brace_balanced 拒绝，不是被 CLOSING_PREFIX 拒绝
```

更进一步：**`CLOSING_PREFIX` 在本文件中不可达** —— 没有任何以 `}` 开头的行能配平（`reachable: NONE`），删掉守卫后 `starts_a_function` 只在 `:315` 一处变化，且**没有任何 (ca,cb) 的接受状态依赖它**（`accepted pairs that depend on the guard: none`）。

**结论：E1 的 exit=1 由 `brace_balanced` 提供，守卫本身零贡献；E1 无法证明守卫有效（假红证）。** 这与主代理注释「relying on two rules accidentally covering for each other is not a design」恰好相反——守卫正是靠 `brace_balanced` 兜底。

### 36.4 Q-4 独立复跑

```
verify_anchors.py    exit=0  citations 407 / anchored 70 / WRONGLINE 0 /
                             §19 no-clause 26 / 其他 no-clause 311
anchors_redtest.py   exit=0  19/19 OK（A1-A6 B1-B3 C1-C6 D1-D5 E1）
verify_citations.py  exit=0  checks passed 43 / FAILED 0
batch1_preflight.py  exit=0  RESULT: batch 1 is executable
```

### 36.5 判定 —— 不通过（P2×1）

| 项 | 级别 | 说明 |
|---|---|---|
| `starts_a_function` 对注释/语句/聚合初始化返回 True | **P2** | 端到端 5/5 ACCEPTED（36.2），I6 形同虚设 |
| E1 为假红证 | **P2** | 变异测试不区分（36.3），守卫零覆盖 |
| `CLOSING_PREFIX` 误杀真函数 | 无 | 全树 0 候选（36.1） |

**建议**：①`starts_a_function` 增加「不含 `=`、不以 `//` 开头、`head` 须以标识符结尾」；②E1 改用真正依赖守卫的样例（当前文件不存在，需先造一个 `}` 开头且能配平的行），否则删除 E1 或标注其为 `brace_balanced` 回归测试而非守卫红证。

*红线：`verify_anchors.py` 变异前后 SHA256 均为 `AC617230…`（**已恢复，diff 为空**）；变异体只写 `.tmp\audit-b0-final\verify_mut_noclose.py`；未改 `src/`、`tests/`；`docs/audit-a.md` 的 16:57:44 变更为审计甲所写，非本会话。*

---

## 37. 第十二轮复裁（v13 判据）

> 基线：`verify_anchors.py` 20308 B / 17:04:53，SHA256 `EFE51301A042C2BAEB6A2E1F3A39C8C886CECD766A66571393EC093D66C76CFB`；`anchors_redtest.py` 9273 B / 17:06:41（21 例）。全部判定调用门禁**自己的** `starts_a_function` / `brace_balanced` / 归一化 `SRC`。

### 37.1 A-1 新的非函数误收路径 —— 找到 1 类（P2）

分类合成测试（归一化行，直接喂 `starts_a_function`）：

| 形态 | 合成行 | 判定 |
|---|---|---|
| `#define FUNC() {` | `#define FUNC() {` | **FUNC（误收）** |
| 模板特化 | `template<> void foo() {` | **FUNC（误收）** |
| lambda 赋值 | `auto f = [](int x) {` / `auto f = [&](int x) {` | **FUNC（误收）** |
| 构造函数初始化列表 | `Foo::Foo() : base{x} {}` | **FUNC（误收）** |
| `operator()` | `int operator()(int x) {` | **FUNC（误收）** |
| 聚合初始化（`=`） | `sb[1] = {static_cast<...>(size), ...` | notfn ✅ |
| 聚合初始化（花括号） | `SecBuffer ib{static_cast<...>(token.size())...` | notfn ✅ |
| 普通语句 | `out.clear();` | notfn ✅ |
| 注释 | `// other platforms (which...)` | notfn ✅ |

**全树普查（`src/` + `include/` + `tools/`，44 个文件）→ 真正开块且 `saf()==True` 的非函数只有 1 处：**

```
[BASH: a1_tree.py]
lambda opens block   ntlm.cpp :239   gain=+1 saf=True
    'auto emit = [&](const Bytes& v, size_t field) {'
```

其余类别：`#define` 0、`operator()` 0、`template<` 0、`if constexpr` 0；构造函数初始化列表 4 处但 `gain=+0`（不构成可引用的块）；`hash.cpp` 的 3 个 lambda `gain=+0`。

**为什么是 P2 而非 P1**：`ntlm.cpp` **不在** 门禁的 `FILES` 白名单（只有 `tls_schannel.cpp` / `tls.h` / `credssp.h` / `credssp.cpp` / `ts_request.cpp` / `connect_machine.cpp` / `test_tls.cpp` / `test_credssp_sm.cpp`），当前门禁不可能读到它。但**批 2/3 若把 ntlm 纳入门禁**，这个 lambda 会被当成函数体接受。

### 37.2 A-2 折行条件保护不够 —— 找到 1 处真实误收（P2）

新判据「`{` 必须在最后一个 `)` 之后」并不能区分「折行条件尾部」与「函数签名」，它只区分「聚合初始化」。**本文件已存在活体误收：**

```
[BASH: a2_e2e.py]  端到端过真实门禁，自校验 old 3→2
folded cond tail :362-366      ok  exit=0 ACCEPTED   'out.data(), &size)) {'
        balanced=True starts_fn=True
        *** FALSE ACCEPT: an inner if-body cited as a function ***
folded cond :355-358           ok  exit=1 rejected   'nullptr, &size)) {'
```

源码上下文证明 `:362` 是 `if` 的折行条件末尾，不是函数：

```
:360  'if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,'
:361  '&cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr,'
:362  'out.data(), &size)) {'        ← 被接受为「函数体起点」
:363  'out.clear();'
:364  'return ConstError(...);'
:365  '"CryptEncodeObjectEx(data) failed");'
:366  '}'
```

**接收条件纯属巧合**：`:362` 恰好含一个 `(`（`out.data(`），使括号计数 1/3 不平衡、`brace(20) > paren(18)` 成立。同类 `:355 'nullptr, &size)) {'` 因不含 `(` 被正确拒绝；`:679 'SEC_E_OK) {'`、`:572 '...max_version) {'` 也因不含 `(` 被拒。

**即：折行条件只要恰好带一个函数调用括号，就会被判成函数。这是 A-2 的正面答案——保护不够，且已可复现。** 这与 I6 要防的 X1（内层块冒充函数体）是同一缺陷。

### 37.3 A-3 E2/E3 是真红证 —— 通过；E1 不是

变异测试：按标记切掉新判据（`brace = line.rfind('{')` … `head = line.split('(')[0]` 前，889 字符 / 17 行），red test 只重定向 `VER`，其余路径保持原样。

```
[BASH: a3c.py]
=== MUTANT (v13 判据移除) ===        === REAL (v13 判据在位) ===
E1  exit=1 expect=1  OK              E1  exit=1 expect=1  OK
E2  exit=0 expect=1  *** WRONG ***   E2  exit=1 expect=1  OK
E3  exit=0 expect=1  *** WRONG ***   E3  exit=1 expect=1  OK
script exit=1                        script exit=0
其余 A1–A6/B1–B3/C1–C6/D1–D5 两种情形结果一致
```

**E2/E3 是真红证**：判据移除 → exit=0；判据 restore → exit=1。
**E1 不是**（父代理已自行标注为 `bb regression`，与 §36.3 一致）。

> 方法记录：第一次尝试我把 red test 的 `SHADOW` 改了名却未同步它注入的路径，验证器读到空文档使全部用例假绿（exit=0）。该结果是**测试脚手架的 bug**，不是门禁结论；`a3c.py` 只重定向 `VER` 后结论反转，与此前一致。

### 37.4 A-4 完整门禁复跑

```
verify_anchors.py    exit=0  citations 407 / anchored 70 / WRONGLINE 0
                             §19 no-clause 26 / 其他 no-clause 311
anchors_redtest.py   exit=0  21/21 OK（A1-A6 B1-B3 C1-C6 D1-D5 E1-E3）
verify_citations.py  exit=0  checks passed 43 / FAILED 0
batch1_preflight.py  exit=0  RESULT: batch 1 is executable
```

### 37.5 判定 —— 不通过（P2×2）

| 项 | 级别 | 证据 |
|---|---|---|
| 折行条件尾部 `:362-366` 被当函数体接受 | **P2** | 端到端 exit=0；同类 `:355` 因不含 `(` 侥幸被拒（37.2） |
| lambda 开块 `ntlm.cpp:239` 被判函数 | **P2** | 全树唯一；`ntlm.cpp` 暂不在 `FILES` 白名单，属潜在（37.1） |
| E2/E3 红证有效性 | 通过 | 变异前后 exit 0↔1（37.3） |
| E1 | 通过（已降级标注） | 不区分判据（§36.3 + 37.3） |
| 门禁/引用/预检 | 通过 | 37.4 四项全绿 |

**建议**：折行条件的判别不能靠「有无括号」。可行做法——把 `if`/`for`/`while`/`switch` 的**起始行**向下追踪到其 `)` 闭合行并标记为「条件尾部」，`starts_a_function` 对这类行返回 False；或要求开块行 `head` 里必须出现「类型 + 标识符」两段（`out.data` 只有一段且含 `.`）。lambda 需排除 `[` 捕获列表 + `=` 赋值。

*红线：`verify_anchors.py` SHA256 前后均为 `EFE51301…`（**未改动，diff 为空**）；变异体仅写 `.tmp\audit-b0-final\verify_mut_v12.py` 与 `redtest_mut_v12.py`；未改 `src/`、`tests/`、`docs/`；门禁 `5CA09A3E…` 未变。*

---

## 38. 第十三轮复核（v15 + `_strip_comments`）

> 基线：`verify_anchors.py` 22737 B / 18:03:17，SHA256 `73A31460…0561`（复核期间由 17:21 版 `12D2DF3D…` 更新，**本节全部基于 18:03 版**）；`anchors_redtest.py` 12773 B / 18:04:40（30 例）。未启动任何 exe。

**B-1 `statement_head`：注释已堵，字符串字面量仍可逃逸（P3）**

注释逃逸已修（`_strip_comments`）：`// note (x` 作中继行 → `head=1 saf=False`；`// (` 在 brace 行 → `saf=False`；折行签名内含注释 → `saf(1)=True bb(1,5)=True`（未误杀）。

未修：字符串字面量的 `(` 仍截断回溯。

```
ESC = ['if (a &&', '    s = "(";', '    c) && fn(d)) {', '    x();', '}']
shead(3)=2  head='    s = "(";'  INNER=False  saf(3)=True  bb(3,5)=True   → ESCAPE
```

反向 `')'` 被正确拒绝（`shead(3)=1 saf=False`）——不对称。

**当前不可达**：门禁 8 文件中含括号的字符串字面量 3 处（`connect_machine.cpp:203`、`tls_schannel.cpp:357/365`），均不在折行语句的不平衡中继位上；`reachable holes: 0`。

其余形态全部正确拒绝：`if (a) { b(); } else {` / `do {` / `try {` / `for (;;)` / `else {` 均 `INNER=True saf=False`；真实文件「关键字起始却被接受」0 条。

**B-2 lambda / 属性 / operator：正确；但「`[[...]]` 0 次」不准确**

```
lambda / lambda capture          saf=False ✅      [[nodiscard]] auto f()   saf=True ✅
operator[] / operator()          saf=True  ✅      [[deprecated("x")]] f()  saf=True ✅
[[nodiscard]] auto f = [](int){  saf=False ✅      void f(int a[DIM])       saf=True ✅
```

`[[...]]` 全树 **3 次**（非 0）：`tools/…/main.cpp:23/29/31` 的 `[[noreturn]]`。`:23 [[noreturn]] void CrashNullWrite() {` 是真函数且 `saf=True`（**未误杀**）；`:29/:31` 单行体 `gain=0` 不构成可引用块。`main.cpp` 不在 `FILES` 白名单。原因：`\[[^\]]*\]\s*\(` 要求 `]` 后紧跟 `(`，属性后是空格+类型名，不匹配。

**B-3 E4 是真红证 —— 通过**

```
                MUTANT(删两行)          REAL
E4              exit=0 expect=1 ✗       exit=1 expect=1 OK
script exit     1                       0
```

E4 判据移除→0，恢复→1。变异只写 `.tmp`；18:03 的文件变更来自父代理，非本会话。

**B-4 完整复跑（18:03 版）**

```
verify_anchors.py    exit=0  citations 407 / anchored 70 / WRONGLINE 0 / §19 26 / 其他 311
anchors_redtest.py   exit=0  30/30 OK（A1-A6 B1-B3 C1-C6 D1-D5 E1-E4 S1-S10）
verify_citations.py  exit=0  checks passed 43 / FAILED 0
batch1_preflight.py  exit=0  RESULT: batch 1 is executable
```

**判定：通过（P3×1）**

| 项 | 级别 | 说明 |
|---|---|---|
| 字符串字面量 `(` 截断回溯 | **P3** | 合成可复现；门禁 8 文件 0 命中 |
| 注释逃逸 / 折行签名误杀 | 已修 | `_strip_comments` |
| lambda / `[[...]]` / operator | 无缺陷 | 10 组合成全对；`[[noreturn]]` 3 处未误杀 |
| E4 红证 / 四脚本 | 通过 | 0↔1；全绿 |

**A20-1 门禁部分可盖章（P3 记录在案，不阻断）。** 修法：`_strip_comments` 同时剥离字符串/字符字面量。

*红线：未改工程代码；变异体仅写 `.tmp\audit-b0-final\`；未启动 exe；未改 `src/`、`tests/`、`docs/`；门禁 `5CA09A3E…` 未变。*
