# RD Gateway RDGSP 实现 — 定案（双审盖章 + 探针红证）

证据基线：`docs/spec/gateway-evidence.md`（出厂 mstscax.dll sha256 `d73c76d6…`）。
探针红证：`evidence/gateway-probe-rerun.txt`（运行期 8/9 FAIL）、`evidence/gateway-factory-probe.txt`。
审计：甲 `ses_e720e33feffetEgPbh0YL3q4uW`（证据/架构侧）、乙 `ses_e720e1cd7ffeatC4G2zMInZ99R`（正确性/安全/UDP 侧），双章一致。

---

## 1. 缺陷清单（全部有红证）

| ID | 级 | 缺陷 | 红证 |
|---|---|---|---|
| D1 | P1 | `Host: /remoteDesktopGateway/`（路径当 authority） | `[FAIL] host header is an authority` / `[READ:src/proto/gateway.cpp:263]` |
| D2 | P1 | `Content-Length: 0` 与流式体互斥 | `[FAIL] no Content-Length: 0` / `[READ:gateway.cpp:268]` |
| D3 | P1 | 缺 `Transfer-Encoding: chunked`（上行编码） | `[FAIL] carries Transfer-Encoding` / 出厂 `0x1806d0c80` |
| D4 | P1 | 缺 chunked **解码**（下行） | `[READ:src/net/gateway_transport.cpp:279-293]` 原样泄流 |
| D5 | P1 | 头部缺 5 项 + 方向性错 | `[FAIL] RDG-Diagnostics-Info/Client-AppBuild/Client-Generation/Auth-Scheme/INCHANNEL-RETRYMODE` |
| D6 | P1 | 无 101/WebSocket 升级直通 | 出厂 `WinHttpWebSocketCompleteUpgrade` 2 命中、`CreateOutChannelOrWebSocketRequest` 2 命中 |
| D7 | P1 | 无状态码→HRESULT 映射、无 IN 重试 | 出厂 `ProcessResponse401 CurrentRetryCount=%d is larger than MaxRetryCount=%d`、`IN_CHANNEL_RETRY_COUNT_%d` |
| D8 | P1 | UDP 单槽 stash 覆盖 + 抢占 ACK → 永久丢帧 | `[READ:gateway_transport.cpp:103-111,126-128]` |
| D9 | P1 | ACK 与读超时同返 0 → 正常 ACK 误报超时 | `[READ:gateway_transport.cpp:28-31,91-98]` |
| D10 | P2 | `method` 无默认值 → 空方法请求行 | `[READ:include/rtsc/proto/gateway.h:143]` |
| D11 | P2 | `parse_www_authenticate` 不支持多挑战 | `[READ:gateway.cpp:280-302]` |
| D12 | P2 | UDP 序号 2^32 回绕误判 | `[READ:gateway_transport.cpp:72-73,104]` |
| D13 | P3 | 畸形 datagram → 立即断连 | `[READ:gateway_transport.cpp:113-114,78]` |
| D14 | P3 | FEC 位帧 / FIN 帧未处理 | `[READ:gateway.cpp:391]` |

**不作缺陷**（无二进制证据，标 UNVERIFIED）：SOAP `<CreateTunnel>` 包装（`application/soap+xml`、`s:Envelope`、`SOAPAction` 全 0 命中；出厂走 `Content-Type: application/json` + RPC `TsProxyCreateTunnel`）。

## 2. 方向模型（出厂证据）

- 上行 = IN 请求体，**stream-mode `Transfer-Encoding: chunked`**
- 下行 = OUT 响应体，**chunked 解码 + plain 回退**双模
- 101 / WebSocket 升级成功 → 同一连接转为**原始双工 RDP 字节流**
- 二者二选一：`CreateOutChannelOrWebSocketRequest`（升级失败退回 OUT channel）

## 3. 方案（路线 A，双审推荐）

新增 `RdgspTransport : public net::Transport`，装饰 gateway 的单条 TCP/TLS 字节流：

```
Write(bytes)  →  IN 请求体（chunked 编码：<hex-len>\r\n<data>\r\n）
Read(buf)     →  OUT 响应体（chunked 解码；检测到非 chunked 则 plain 回退）
构造期         →  握手：401 → NTLM → 200（或 101 升级 → 直通）
```

- 上层 `Client` / `ConnectionDriver` **零改动**（`[READ:include/rtsc/net/transport.h:52-67]` 接缝已存在）
- `kReadTimeout`（`-2`）语义保留：OUT 通道无数据时返回 `kReadTimeoutMs`，上层轮询不误判断连
- 握手自持 deadline（**不借** `Client::Connect` 的 30s 墙钟）
- `GatewayTunnel`（CONNECT）保留作泛型代理，二者并存

### 3.1 文件级改动

| 文件 | 改动 |
|---|---|
| `include/rtsc/proto/gateway.h` | `RdgChannelRequestOptions` 增 `app_build`/`client_generation`/`auth_scheme`/`retry_count`/`diagnostics_info`；`method` 默认 `kRdgInData`；新增 `RdgChannelDirection { kIn, kOut }` |
| `src/proto/gateway.cpp` | D1 Host=authority；D2/D3 流式体（去掉 CL:0，加 `Transfer-Encoding: chunked`）；D5 头部全集 + 方向性；新增 chunked 编码/解码纯函数；新增 `MapGatewayStatusToHresult`；D11 多挑战解析 |
| `include/rtsc/net/gateway_transport.h` | 新增 `RdgspTransport` 声明 + `RdgspConfig`（host/port/connection_id/auth_scheme/retry 上限/deadline） |
| `src/net/gateway_transport.cpp` | `RdgspTransport` 实现（握手状态机 + 双通道 chunked 编解码 + 升级分支）；D8 有界 FIFO + **入队即 ACK**；D9 ACK/超时区分；D12 序号 wrap；D13 脏包计数不立即断连 |
| `tests/test_gateway.cpp` | 纯协议层红→绿用例 + `StubGateway`（TCP 线程）端到端 + UDP wrap/丢帧探针 |
| `tools/rtsc_gui/main.cpp` | `--gateway=host:port` + `RTSC_GATEWAY` 环境变量；TLS 策略独立（禁默认 `kInsecure`） |
| `src/client/session_info.cpp` | gateway 字段代入真实值 |

### 3.2 分阶段

- **阶段 1（本批）**：协议层纯函数 + UDP 三项修复 + 纯协议测试。**不接线**，`rtsc_gui` 行为不变。
- **阶段 2（后续）**：`RdgspTransport` 接线 + GUI 参数 + StubGateway 端到端 + session_info。

## 4. 验收判据（阶段 1）

1. **C0**：`/W4 /WX` 零错零警；定向子集全绿（**禁跑 gateway 全量套件**，只跑 `-R gateway`）。
2. **探针红转绿**：`probe_gw.exe`（按 `gateway-header-direction-ruling.md` 的头部方向表重写后）与 `probe_defects.exe`（chunked 文法 + CRLF 注入 6 项）均 `failures=0`。
3. chunked 编解码往返：给定字节串 → decode → 断言字段；encode → 逐字节比对（**布局取自规范/出厂证据，不取自实现**）。
4. **UDP（D8 定案：入队即 ACK）**：
   - 有界 FIFO（上界 = `receive_window_size`），两帧连发不丢；
   - **ACK 在帧入队时发出**（`sourceAck` = 已入缓冲区间的右沿，即"已收到"而非"已消费"——对齐 [MS-RDPEUDP] 的 sourceAck 语义）；
   - 队列满时丢帧**且不 ACK**，发送方重传；消费腾出空间后重传的帧必须成功入队并被消费（防止静默永久丢弃）；
   - 重复帧收到即补 ACK（防重传死等）；
   - ACK 到达时 `Read` 不得返回 `kReadTimeout`；序号 wrap 用例。
   - **理由**：ACK-on-consume 在"双侧同时 Write、无中间 Read"时双侧互等至超时（实测 RED），属 P1 死锁回归，故不采用。
5. 状态映射：401→`0x80070005`、407→`0x800706c1`、502/504→`0x800706ba`、PasswordExpired→`0x80070532`。
6. 变异红证：逐条回退 D1..D12 的修复，对应用例必须转红。
7. **头部值安全**：任何头值（含 `gateway_host`/`connection_id`/`user_agent`/`correlation_id`/`user_id`/`client_generation`/`load_balancer_cookie`/`app_build`/`auth_scheme`/`diagnostics_info`）含 `\r`/`\n`/`\0` 时必须被拒绝**且调用方可感知失败**（不可静默丢头）。实测漏洞：`connection_id="CID\r\nX-Injected: 1"` 可注入独立头。
8. **chunked 文法严格性**：拒绝前导空白、`0x` 前缀、`+` 号、十六进制后的尾随垃圾、裸 LF 行尾；仅 `;` 后允许 chunk 扩展。实测 `Feed("0x10\r\n...")` 会被当作终止块并静默截断数据（`finished=1, failed=0`）。

## 5. 风险

| 级 | 风险 |
|---|---|
| P1 | 单连接双请求多路复用（IN 写 + OUT 读交错，死锁风险）→ 阶段 2 |
| P1 | TLS 默认策略：gateway 自签证书下 `kTofu` 首连有 MITM 窗口；`kInsecure` 使 CredSSP step5 明文密码。**禁止默认 `kInsecure`** |
| P2 | UI 异步握手（阻塞会冻结消息泵） |
| P2 | UDP 侧通道（multitransport + 独立认证）本批不做 |

## 6. UNVERIFIED（需真机）

- `RDG-Client-AppBuild` 取值格式（出厂出自内部对象）
- SOAP 包装是否存在（出厂无证据，走 JSON/RPC）
- 单 socket 双请求 vs 双 socket（静态证据不足）
- OUT 响应是否 chunked（仅 IN 侧有证据）
- IN 通道初始/终态枚举数值
