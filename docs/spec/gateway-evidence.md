# RD Gateway (RDGSP) — 二进制证据

目标：`C:\Windows\System32\mstscax.dll`
SHA-256：`d73c76d65721043cc96484e3483bdd1aab4357a8bfa924465adc572ced0eda05`
版本：10.0.26100.8875（9,166,848 B）
取证工具：REA（`open_binary` + `search_strings`），只读，未执行目标。

> 本文件的每条断言都附 `地址=字符串` 形式的**出厂产物证据**。规范（[MS-TSGU]）只作下限；
> 与规范冲突处以本证据为准。

## 1. 双通道模型（RDGSP IN / OUT）

mstscax 明确实现**两条独立 HTTP 通道**，各有独立连接对象与状态机：

| 证据地址 | 字符串 |
|---|---|
| `0x1806ce858` | `RDG_IN_DATA` |
| `0x1806ce708` | `RDG_OUT_DATA` |
| `0x1806ce7c0` | `pSession->CreateConnection (IN channel) failed` |
| `0x1806ce6a0` | `pSession->CreateConnection (OUT channel) failed` |
| `0x1806cea80` | `Channel not ready to Send data, in channel state(%d), out channel state(%d)` |
| `0x1806cec80` | `Channel not ready to read data, in channel state(%d), out channel state(%d) error...` |
| `0x1806ced40` | `Out channel closing/closed errorCode=0x%x` |

**结论**：
- IN 通道 = 服务器→客户端数据流（客户端读）；OUT 通道 = 客户端→服务器（客户端写）。
- 两条通道各有独立状态（`in channel state(%d), out channel state(%d)`），**不是单条双向流**。
- 我方当前实现（`src/net/gateway_transport.cpp:197 PerformHandshake`）是 **单条 HTTP CONNECT 隧道**，
  与出厂实现的 RDGSP 双通道模型不同 → 缺失功能，不是缺陷（mstsc 在 gateway 模式下不用 CONNECT）。

## 2. 每通道的 HTTP 请求头（出厂证据全集）

| 证据地址 | 字符串 |
|---|---|
| `0x1806d0c00` | `AddRequestHeaders Connection: Keep-Alive) for IN channel failed` |
| `0x1806d0c80` | `AddRequestHeaders transfer-encoding: chunked) for IN channel failed` |
| `0x1806d0fd0` | `AddRequestHeaders Connection: remotappRetryMode) for IN channel failed` |
| `0x1806d0950` | `AddRequestHeader (rdg-connection-id) for IN or OUT channel failed` |
| `0x1806d09d8` | `RDG-Connection-Id` |
| `0x1806d0d30` | `AddRequestHeader (rdg-correlation-id) for OUT channel failed` |
| `0x1806d0db0` | `RDG-Correlation-Id` |
| `0x1806d0de0` | `AddRequestHeader (rdg-diagnostic-info) for IN or OUT channel failed` |
| `0x1806d0e68` | `RDG-Diagnostics-Info` |
| `0x1806d1130` | `RDG-User-Id` |
| `0x1806d12c0` | `AddRequestHeader (rdg-user-id) for OUT channel failed` |
| `0x1806d13e0` | `RDG-Client-AppBuild` |
| `0x1807c82a0` | `AddRequestHeader (RDG-Client-AppBuild) failed` |
| `0x1806d1410` | `AddRequestHeader (RDG-Client-Generation) for OUT channel failed` |
| `0x1806cf448` | `RDG-ChannelBind-Info` |
| `0x1806d02b0` | `RDG-Auth-Scheme` |
| `0x1806d03a0` | `AddRequestHeader (RDG-AuthScheme) for failed` |
| `0x1806d0a00` | `AddRequestHeader (Load Balancer Cookie) for OUT channel failed` |
| `0x1806d0bd8` | `Keep-Alive` |
| `0x1806d0bf0` | `chunked` |

**结论**：
- 头部集合远比 [MS-TSGU] 2.2.3 列出的多：出厂实现还发 `RDG-Diagnostics-Info`、
  `RDG-Client-AppBuild`、`RDG-Client-Generation`、`RDG-ChannelBind-Info`、`RDG-Auth-Scheme`、
  `Load Balancer Cookie`。
- 方向性：`rdg-user-id`、`rdg-correlation-id`、`RDG-Client-Generation`、`Load Balancer Cookie`
  的错误文本**只提 OUT channel** → 这些头只出现在 OUT 通道。
  `rdg-connection-id`、`rdg-diagnostic-info` 文本提 **IN 或 OUT** → 两条都发。
- IN 通道使用 `transfer-encoding: chunked`；非 chunked 模式使用 `Connection: Keep-Alive`。
- `Connection: remotappRetryMode` 是 RemoteApp（RAIL）直达模式下的特例。

**我方差距**（`src/proto/gateway.cpp:248-276 BuildRdgChannelRequest`）：
只发 `Host/User-Agent/Accept/Cache-Control/Connection: Keep-Alive/Content-Length: 0/
RDG-Connection-Id/[RDG-Correlation-Id]/[RDG-User-Id]`；
缺 `RDG-Diagnostics-Info`、`RDG-Client-AppBuild`、`RDG-Client-Generation`、
`RDG-ChannelBind-Info`、`RDG-Auth-Scheme`、`Load Balancer Cookie`、
`transfer-encoding: chunked`、`Connection: remotappRetryMode`。
且 `RDG-Correlation-Id`/`RDG-User-Id` 未按方向区分（应在 OUT-only 集合内）。

## 3. 重试与错误处理语义（出厂证据）

| 证据地址 | 字符串 |
|---|---|
| `0x1806cf240` | `Connected RDG-IN channel in Retry modes. errorCode=0x%x` |
| `0x1806cf8c0` | `In channel retry mode mode %dth retry. errorCode=0x%x hrFromStatusCode=0x%x` |
| `0x1806d0f60` | `RDG-INCHANNEL-RETRYMODE` |
| `0x1806cf6c0` | `Out Channel SendHttpRequest RETRY failed` |
| `0x1806cf1a0` | `Out Channel SendHttpRequest failed` |
| `0x1806cf630` | `Proxy returned access denied for IN or OUT channel. statusCode=0x%x` |
| `0x1806cf4b0` | `Server returned access denied for IN channel. errorCode=0x%x` |
| `0x1806cf530` | `Server returned switch protocols for IN channel. errorCode=0x%x` |
| `0x1806cefd0` | `In Channel SendHttpRequest failed` |
| `0x1806cf1f0` | `real In Channel SendHttpRequest failed` |
| `0x1806ceb20` | `Reporting connection failure for IN channel errorCode=0x%x` |
| `0x1806d0110` | `Reporting connection failure for IN channel. errorCode=0x%x` |
| `0x1806cdf40` | `SendHttpRequest failed - OUT channel` |

**结论**：
- 存在 **IN 通道专用重试模式**（`RDG-INCHANNEL-RETRYMODE` 头），带计数器（`%dth retry`）。
- 两种失败来源要区分：**代理拒绝**（`Proxy returned access denied`，statusCode）与
  **服务器拒绝**（`Server returned access denied`，errorCode）。
- 服务器可回 **switch protocols**（IN 通道协议切换）—— 我方未处理。
- 我方 `PerformHandshake`（`gateway_transport.cpp:227-231`）对非 200 一律报
  `gateway refused the tunnel (HTTP <code>)`，**无重试、无拒绝来源区分、无协议切换**。

## 4. 认证（tunnel 层）

| 证据地址 | 字符串 |
|---|---|
| `0x1807939a8` | `AAStateAuthenticatingTunnel` |
| `0x1807939e0` | `AAStateAuthorizingTunnel` |
| `0x180793ab8` | `AAStateInitializingTunnel` |
| `0x180793e10` | `AAEventTunnelInitialized` |
| `0x180793e48` | `AAEventOnInitTunnelFailed` |
| `0x180793e80` | `AAEventTunnelOnConnectedFailed` |
| `0x180793fb8` | `AAEventTunnelAuthenticated` |
| `0x180793ff0` | `AAEventTunnelAuthenticatedFailed` |
| `0x18079ce00` | `NTLM` |
| `0x1807b1348` | `RDGClientForceNtlm` |
| `0x1806cc840` | `spAadNonceRequest->AcquireNonceValue failed` |
| `0x1807940b0` | `UdpAAEventTunnelAuthenticationFailed` |
| `0x180794278` | `UdpAAEventTunnelAuthorized` |

**结论**：
- 隧道认证是**显式状态机**：`InitializingTunnel → AuthenticatingTunnel → AuthorizingTunnel`。
- 支持 NTLM（可强制 `RDGClientForceNtlm`）与 Azure AD nonce 流程。
- UDP 通道有**独立的认证状态机**（`UdpAAEvent*`），不是复用 TCP 隧道的认证。

## 5. 我方差距总表

| 能力 | 出厂证据 | 我方现状 | 差距 |
|---|---|---|---|
| RDGSP 双通道 IN/OUT | `0x1806ce858`/`0x1806ce708` | 单条 CONNECT 隧道（`gateway_transport.cpp:197`） | **缺整条链路** |
| chunked 读 | `0x1806d0bf0`/`0x1806d0c80` | 无 | 缺 |
| IN 通道重试模式 | `0x1806d0f60`/`0x1806cf8c0` | 无重试 | 缺 |
| 拒绝来源区分（proxy/server） | `0x1806cf630`/`0x1806cf4b0` | 统一报错 | 缺 |
| switch protocols | `0x1806cf530` | 无 | 缺 |
| 附加头部（Diagnostics/AppBuild/Generation/ChannelBind/Auth-Scheme/LB cookie） | 见 §2 | 全缺 | 缺 |
| 头部方向性（OUT-only 集合） | §2 | 未区分 | 缺 |
| 隧道认证状态机 | `0x1807939a8`… | 依赖外部 `authorization` 头注入 | 缺 |
| UDP 独立认证 | `0x1807940b0`… | UDP 传输已实现（`UdpTransport`），无认证 | 缺 |

## 6. 证据限制

- 仅字符串级证据（REA `search_strings`）；**未反汇编**状态机内部逻辑，故：
  - 通道状态枚举的**数值**未取证（`(%d)` 运行期值）；
  - `RDG-INCHANNEL-RETRYMODE` 头的**取值**未取证；
  - chunked 分块**大小策略**未取证；
  - `switch protocols` 的**目标协议**未取证。
- 上述未取证项在实现时必须继续取证（`search_bytes`/反编译 `FUN_*`），禁止臆测。
- 真机 gateway 抓包未做（本机无 RD Gateway 实例）。

## 7. 复现命令

```
REA open_binary C:\Windows\System32\mstscax.dll
REA search_strings "rdg-"
REA search_strings "IN channel"
REA search_strings "OUT channel"
REA search_strings "chunked"
REA search_strings "RDG-INCHANNEL-RETRYMODE"
REA search_strings "AAState"
```
