# RDGSP 阶段 2 定案（双审双章）

证据基线：`docs/spec/gateway-stage2-evidence.md`（含 §10 双连接拓扑裁定）。
审计：甲 `ses_e716dd16effeaNoGGFZSU0DtSb`、乙 `ses_e716db855ffeRMsQQ9mKXRozwe`，双章一致。
主代理已独立复核甲的关键取证（`FUN_1801c235c` 的 `0xd3c`/`0xd40`、`Claims:` 特判、`FUN_1801c6b44` 超时表、UA 串）。

---

## 1. 路线定案：A'（单 Transport 外观 + 内部双连接）

```
Client / Pump / SendPdu  ──吃单个 net::Transport&──▶  RdgspTransport
                                                       ├── OUT 连接（下行）：网关→客户端
                                                       │    200 → chunked 解码
                                                       │    101 → 裸双工（RFC6455 帧）
                                                       └── IN  连接（上行）：客户端→网关
                                                            RDG_IN_DATA，请求体 chunked 持续写
```

- 上层 `Client::Connect/Pump/SendPdu` **零改动**（`client.cpp:120-191,252-265`）。
- 双连接是 `RdgspTransport` 的内部细节。
- **排除** 单连接多路复用（HTTP/1.1 禁响应体进行中 pipeline + 写等读死锁 + 与出厂结构不符）。
- **排除** 上层双 `Transport`（要改 Client 签名、破坏 server 复用与既有用例）。

## 2. 出厂证据（阶段 2 全部关键事实）

| 事实 | 证据 |
|---|---|
| IN 方法硬编码 `RDG_IN_DATA` | `FUN_1801bc14c:32` |
| OUT 方法由 `*(+0x1440)` 选：0/其它→`GET`、1→`RDG_OUT_DATA`、2→`POST` | `FUN_1801bc3c4:23-34` |
| URL `%s://%s:%hu%s`，默认 `/remoteDesktopGateway/`，`+0x6a8==0` → `http` | `FUN_1801bd574` |
| **双连接**：IN 端口 `+0x6a6`、OUT 端口 `+0x6a4`，各自 `CreateConnection` | `FUN_1801bc14c:26-27` / `FUN_1801bc3c4:19-20`；§10 |
| 101 **只对 OUT**；IN 收 101 报 `Server returned switch protocols for IN channel` | `FUN_1801bfd60:158-170` |
| 101 后 `0xd20=4`、`0xd24=1`、`0xd1c=0xb`、`0xd38=0` | `FUN_1801bfd60:181-186` |
| 升级后走 WinHTTP WebSocket，**payload 直通**（帧由 WinHTTP 消解） | `FUN_1802b1680` `WinHttpSetOption(0x72=UPGRADE_TO_WEB_SOCKET)`；`FUN_1802b249c` `WinHttpWebSocketCompleteUpgrade`；`FUN_1802b0930` streamType==3 → `WinHttpWebSocketReceive` |
| 401 重试计数 `+0xd40`，上限字段 `+0xd3c`（外部配置，**无代码立即数**） | `FUN_1801c235c:60-70` |
| 401 内只特判 `Claims:`（`wcsncmp(_Str1,L"Claims:",7)`），非 Claims 走原生认证 | `FUN_1801c235c:165` |
| 原生认证走 `SetNativeAuthInfo` → WinHTTP/SSPI 自动登录（**无 NTLM-vs-Negotiate 优先级逻辑**） | `FUN_1801c54a0` |
| 超时表 120000/60000/30000/90000/30000 ms | `FUN_1801c6b44:21,24,26,28,30` |
| UA = `MS-RDGateway/1.0` | 串 `0x1806ce4b0` |

## 3. 握手状态机 H0–H8

```
H0  TCP+TLS 连网关（先建 OUT 连接）
H1  发 OUT 请求（method 由 transport_mode 决定，默认 RDG_OUT_DATA）
H2  读响应：
     401 → 认证流程 → 回 H1（计数 +1，超 max_auth_retries → 0x80070005）
     200 → H3
     101 → H4
     其它 → 按 MapGatewayStatusToHresult 失败
H3  OUT 就绪（mode=kChunked）→ H5
H4  OUT 升级（mode=kUpgraded，RFC6455 帧编解码）→ H5
H5  建 IN 连接，发 IN 请求（RDG_IN_DATA + Transfer-Encoding: chunked）
H6  IN 401 → 用已认证 Authorization 重发（独立计数，超限报错）
    IN 101 → **硬错** "Server returned switch protocols for IN channel"
H7  IN 200 → 双通道 ready → Connect() 成功
H8  任一失败 → 关双连接 + error + HRESULT
```

**认证分支**：
- **NTLM（默认）**：RFC4559 三腿（type1 → 401 + type2 → type3）。消息层复用 `src/credssp/ntlm.h:23-143`（type1/2/3 + NTLMv2），但**禁止复用 `CredsspClient` 状态机**（含 TSRequest / TLS channel binding）。
- **Basic**：策略开关，默认支持（kStrict 下等价于 HTTPS Basic），须文档标注。
- **Negotiate(SPNEGO)**：显式失败 `0x80004001`，**不静默跳过**。
- **Claims**：显式失败 `0x80004001`（本批不做；出厂 URL `/v1/connections`，`FUN_1801bae40`）。

## 4. 数据面路由

`RdgspTransport` 维护 `mode ∈ {kChunked, kUpgraded}`：

| mode | Write | Read |
|---|---|---|
| `kChunked` | IN 连接，chunked 编码 | OUT 连接，chunked 解码（+ plain 回退） |
| `kUpgraded` | OUT 连接，裸流（RFC6455 client 帧：mask-on，FIN/opcode/126/127） | OUT 连接，解帧取 payload |

配置开关 `upgrade_steals_write`（默认 `true`）允许在 kUpgraded 时仍走 IN 写。
**理由**：出厂 IN 侧是否仍有管理流 = `UNVERIFIED`；开关保兼容。

## 5. 必须修复的既有缺陷（带红证）

| ID | 级 | 缺陷 | 证据 |
|---|---|---|---|
| D-A1 | P1 | builder 返回空 vector 后 `inner_.Write(data, 0)` 静默 → 报 "timed out" 而非指向配置错误 | `[READ:src/net/gateway_transport.cpp:268-272]` |
| D-A2 | P1 | `WinsockTransport::Write` 无 `SO_SNDTIMEO`，阻塞 send 循环 | `[READ:src/net/winsock_transport.cpp:52-62]`（全库 grep 为空） |
| D-A3 | P1 | GUI 内层 TLS 写死 `CertPolicy::kInsecure` → CredSSP step5 密码可被 MITM 读明文 | `[READ:tools/rtsc_gui/main.cpp:264-265]`、`[READ:src/credssp/credssp.cpp:388-404]` |
| D-A5 | P2 | `ConnectionDriver` 状态机不可重入 → 断线无法重建 | `[READ:src/security/connection_driver.cpp:35-41]` |
| D-A6 | P2 | UI 同步握手会冻结消息泵 | `[READ:tools/rtsc_gui/main.cpp:552]` |
| D-A8 | P2 | `MaxRetryCount` 默认值无出厂立即数 | `FUN_1801c235c` 字段 `+0xd3c`，`UNVERIFIED` |

## 6. TLS 双层策略（各默认严格）

- **外层网关 TLS**：`kStrict`（hostname 校验）。自签场景仅允许 CLI 显式 `--gateway-trust=<pinned-spki>`（`pinned_spki`，`tls.h:118-121`）或 `--gateway-insecure`。
- **内层 RDP TLS/CredSSP**：默认改 `kStrict`（修 D-A3），`--tls-insecure` 显式开关。
- **桩测试**：用 `http` 明文（`+0x6a8==0` 出厂内建），完全绕过 TLS。

## 7. 失败路径

| 场景 | 行为 | HRESULT |
|---|---|---|
| 401 超 `max_auth_retries` | 停止重试 | `0x80070005` |
| 403 | 数值映射 | `0x80190000\|403` |
| 407 | 代理拒绝 | `0x800706C1` |
| 502/504 | 网关不可用 | `0x800706BA` |
| 307 | **零跟随**（防 SSRF，跨 host 绝不跟随） | `0x80190000\|307` |
| IN 101 | 硬错 | `0x80190000\|101` |
| chunked 中途 EOF | Read 返回 -1 + 明确错误 | `kTruncated` |
| 双通道建立失败 | 关双连接 | `0x800706BA` |
| 不支持的认证 scheme | 显式报错 | `0x80004001` |
| TLS 失败 | 证书错误详情（不泄密码） | — |
| 密码过期 | 报过期 | `0x80070532` |

## 8. 文件级清单

| 文件 | 改动 |
|---|---|
| `include/rtsc/proto/gateway.h` | `RdgChannelRequestOptions` 增 `transport_mode`；新增 RFC6455 帧编解码声明 |
| `src/proto/gateway.cpp` | RFC6455 client 帧编/解码纯函数；新字段并入 CRLF 校验链 |
| `include/rtsc/net/gateway_transport.h` | `RdgspTransport` + `RdgspConfig{host,port,connection_id,user_agent="MS-RDGateway/1.0",auth_scheme=kNtlm,max_auth_retries=3,upgrade_steals_write=true,deadlines(120/60/30/90/30s),tls policy,connection factory seam}` |
| `src/net/gateway_transport.cpp` | H0–H8 + In/OutChannel + NTLM 三腿 + chunked/WebSocket 路由 + **空请求显式报错** |
| `tools/rtsc_gui/main.cpp` | `--gateway=host:port` + `RTSC_GATEWAY`；TLS 双层；**默认不再 kInsecure** |
| `src/client/session_info.cpp:137-141` | gateway 字段代入真实值 |
| `tests/test_gateway.cpp` | RFC6455/NTLM/重试上限纯协议用例 + StubGateway（双 accept + 明文 http）端到端 |
| `src/security/connection_driver.cpp` | 零改动 |

## 9. 验收判据

1. C0：`/W4 /WX` 零错零警；`ctest -R gateway` 全绿，既有 72 tests/333 checks 保绿。
2. 新用例先红后绿。
3. StubGateway S1 双连接端到端字节往返一致；**双写双读无死锁**（超时门禁）。
4. NTLM 三腿：401 → type1 → 401+type2 → type3 → 200。
5. `max_auth_retries`（默认 3）超限 → `0x80070005`；与 IN 通道 `+0xd38` 分开建模。
6. IN 101 → 显式错误；307 零跟随；**空请求显式错误**（不被 30s 超时吞）。
7. TLS：GUI 默认不再 `kInsecure`（grep 验证）；`--gateway`/`RTSC_GATEWAY` 解析层也拒 CRLF/NUL。
8. 变异红证：空请求检查 / IN 101 硬错 / 重试上限 / 双连接（改回单连接应死锁或测试红）。

## 10. 风险分级

| 级 | 风险 |
|---|---|
| **P0** | TLS 默认 `kInsecure` 未消除（直连 + 网关双路径）→ 密码明文 |
| P1 | 双连接实现偏差（残留单连接）→ 死锁；RFC6455 帧实现错误；NTLM type3 密钥派生/AV 顺序错误；握手内嵌阻塞读；OUT 饱和仍可能阻塞 Write |
| P2 | UI 同步握手冻结消息泵；OUT 长静默假死；Claims/Negotiate/异端口不支持 |
| P3 | CLI 参数层未前置拒 CRLF；307 映射缺测试；`--gateway` 与 `RTSC_GATEWAY` 优先级 |

## 11. UNVERIFIED

- `MaxRetryCount` 默认值（`+0xd3c` 外部配置，无立即数）。
- IN 通道在 kUpgraded 模式下是否仍有管理流（故留 `upgrade_steals_write` 开关）。
- 真机 101 升级的帧互通（需真实 RD Gateway）。
- `+0x6a4` 与 `+0x6a6` 正常配置下是否同值（`ConnectToServer` 默认设同值，但字段分离）。
- 双连接是否共享 TLS 会话（resumption）。
