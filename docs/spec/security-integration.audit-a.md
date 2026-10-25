# TLS + CredSSP + EUAR 接入连接流程：多方案设计与缺陷审计（审计 AI 甲）

- 审计对象：`F:\rtsc`（C++20 跨平台 RDP 客户端重写）
- 审计范围：把已完成的 `rtsc_tls` / `rtsc_credssp` 接进 `ConnectMachine` 的连接流程
- 审计性质：**只做分析与设计**，未修改任何工程代码、未新增任何工程源文件
- 证据基线（本轮实际执行，非引用历史结论）：
  - `rtsc_tls_tests.exe` → `26 tests, 139 checks, 0 failing`，`exit=0`
  - `rtsc_credssp_sm_tests.exe` → `15 tests, 92 checks, 0 failing`，`exit=0`
  - `rtsc_framing_tests.exe` → `11 tests, 47 checks, 0 failing`，`exit=0`
  - `rtsc_connect_machine_tests.exe` → `26 tests, 115 checks, 0 failing`，`exit=0`

> 说明：本文件中的每条代码断言都带 `路径:行号`，且该行号来自本轮实际读取的文件内容。
> 凡标「未验证」的，一律在 §8 列出并给出可执行的验证方法，不做「应该可以」式断言。

---

## 0. 结论先行

1. **必须新增一个持有「阶段」的对象，且阶段必须与明文缓冲区同属一个所有者。**
   理由不是「分层好看」，而是**分帧规则本身随阶段变化**：CredSSP 阶段是 DER 自定界，
   EUAR 阶段是固定 4 字节，MCS 阶段是 TPKT 长度字段。三种规则共存于同一条明文流上，
   谁能决定「从缓冲区头部消费几个字节」，谁就必须同时知道「现在是什么阶段」。
   把这两件事拆到两个对象里（方案 C、以及题目候选 (b)(c)）必然产生 split-brain。
   → 推荐**方案 B（单入口 `Step(Input)` 的可重入状态机）**，方案 A 是其可接受的退化形式。

2. **现有 `TpktStream` 不能直接复用**：它**剥掉** TPKT 头返回 payload
   （`src/proto/framing.cpp:86`，接口注释 `include/rtsc/proto/framing.h:16`），
   而 `ConnectMachine::OnData` 要求**带 TPKT 头的完整帧**
   （`src/proto/connect_machine.cpp:196` → `src/proto/connection_initiation.cpp:55`；
   MCS 侧 `src/proto/mcs.cpp:128` 直接要求 `tpkt.length == size`）。
   直接对接会 100% 失败。必须「保留帧」或「用 `WrapTpkt` 还原」。

3. **EUAR 不会被「误当 MCS」——它会被「静默吞掉」**，这比误判更危险。
   `TpktStream::Next` 在头部不是 `03 00` 时会逐字节前扫并计数丢弃
   （`src/proto/framing.cpp:37`、`:61`）。`00 00 00 00`（AUTHZ_SUCCESS）与
   `05 00 00 00`（AUTHZ_ACCESS_DENIED）都会被当作垃圾丢掉，然后正常返回后面的 MCS PDU。
   结果：**授权被拒也「看起来连上了」**。必须有一个显式的「恰读 4 字节」阶段。

4. **当前代码里存在 4 个 P0 级问题**，会直接导致接入失败或静默不安全：
   非随机 nonce（会话密钥可预测）、无 EUAR 读取器、`TpktStream` 剥头不匹配、
   无 DER 分帧器（跨 record 的 TSRequest 无法重组）。详见 §6 的 S1 / S2 / S3 / S4。

---

## 1. 审计方法与证据等级

| 等级 | 含义 | 本文用法 |
|---|---|---|
| A | 规范原文 / 本项目 spec 文档已固化并注明来源 | 引用 `docs/spec/security-layer.md` 行号 |
| B | 代码结构可直接读出（含接口注释契约） | 引用 `路径:行号` |
| C | 从 A+B 推导，未实测 | 明确标「推导」 |
| E | 本轮实跑命令输出 | 见文首基线与 §7 |

本轮**未**做的事（避免越权）：未连真实服务器、未新增探针、未改任何 `.cpp/.h/CMakeLists.txt`。

---

## 2. 现状事实核对（只列与接入直接相关的）

### 2.1 三层现有的契约边界

| 层 | 头文件 | 关键契约 | 证据 |
|---|---|---|---|
| TLS | `include/rtsc/net/tls.h` | `Receive` 是 **append-only**，一次可吐多条 record 的明文；`kClosed` 时**保留**已解出的明文，调用方必须先排空 | `include/rtsc/net/tls.h:142` |
| TLS | 同上 | `kClosed` 是「正常终止」，`Error::ok()==false` 但 `terminal()==false` | `include/rtsc/net/tls.h:50`、`:67` |
| TLS | 同上 | `Send` 内部会**自行切分**超过 `max_chunk` 的明文，不报错 | `include/rtsc/net/tls.h:136`、`src/net/tls_schannel.cpp:217`（锚点 `const size_t chunk = MaxChunk();`） |
| CredSSP | `include/rtsc/credssp/credssp.h` | **无传输**的五步状态机：`Start` → `OnServerResponse` → `complete()` | `include/rtsc/credssp/credssp.h:45`、`:51`、`:53` |
| CredSSP | 同上 | 输入是**一整个 TSRequest 的字节**（DER 自定界），不是流 | `src/credssp/ts_request.cpp:275`（要求 `SEQUENCE` 且**不允许尾随字节**，见 `:283`） |
| Proto | `include/rtsc/proto/connect_machine.h` | `OnData` 消费**一条完整 PDU**；`kAwaitExternalSecurity` 阶段收到任何数据即 `Fail` | `include/rtsc/proto/connect_machine.h:111`、`src/proto/connect_machine.cpp:224` |
| Proto | 同上 | 只有 `OnExternalSecurityComplete()` 一个外部握手完成钩子 | `include/rtsc/proto/connect_machine.h:115`、`src/proto/connect_machine.cpp:352` |
| Proto | `include/rtsc/proto/framing.h` | `TpktStream` 只做 TPKT 再分帧，**剥掉 4 字节头** | `include/rtsc/proto/framing.h:16`、`src/proto/framing.cpp:86` |

### 2.2 依赖图现状（决定了方案能不能「只加不改」）

`CMakeLists.txt:18`：`rtsc_proto` 依赖 `rtsc_crypto`（`CMakeLists.txt:36`）。
`CMakeLists.txt:51`：`rtsc_tls` 只依赖系统库 `secur32 crypt32`（`CMakeLists.txt:54`）。
`CMakeLists.txt:111`：`rtsc_credssp` 只依赖 `rtsc_crypto`（`CMakeLists.txt:117`）。
三者互不依赖 —— 这是当前设计的优点，**新增安全层不应破坏它**：
安全层可以依赖三者，但 `rtsc_proto` **不能**反过来依赖 `rtsc_tls`。

### 2.3 真实服务器实测事实（前提，不再重复验证）

- `selectedProtocol = 0x08`（PROTOCOL_HYBRID_EX）：`evidence/handshake-001.md:41`
- 服务端 CCF 后立刻进入 TLS：`evidence/schannel-tls-backend.md`（`round 1: 846 bytes`，`round 2: 51 bytes`，TLS1.2 + AES256-GCM，`header=13 trailer=16 maxmsg=16384`）
- 服务器证书是自签名、`CN=DESKTOP-5BFDKO3`、无 SAN：`docs/spec/security-layer.md:532`
- `SubjectPublicKey`（BIT STRING 内容）270 字节，SPKI 294 字节：`docs/spec/security-layer.md:708`、`evidence/schannel-spki-probe.txt`

---

## 3. 第一性原理推导：为什么「阶段」必须与「缓冲区」同属一个所有者

### 3.1 推导起点

从「一个字节从 socket 到 `ConnectMachine::OnData` 要经过几次『切分』」开始，不预设任何类结构。

一条 TCP 字节流在连接建立期要依次被切成**四种不同的单位**：

| 域 | 切分依据 | 谁做 | 证据 |
|---|---|---|---|
| **R0** TLS record | record 头 5 字节 + 长度 | `TlsTransport::Receive` 内部 | `src/net/tls_schannel.cpp:252`（锚点 `ParseRecordHeader  (in Receive)`） |
| **R1** TSRequest | DER `30 <len>` 自定界 | **当前无人做** | `src/credssp/ts_request.cpp:281` 要求恰好一条 |
| **R2** EUAR | **固定 4 字节，无任何前缀** | **当前无人做** | `docs/spec/security-layer.md:375` |
| **R3** RDP PDU | TPKT `03 00 <len16be>` | `TpktStream` | `src/proto/tpkt.cpp:5`、`src/proto/framing.cpp:76` |

**关键观察**：R1/R2/R3 **共用同一条明文流**，且**按时间顺序切换**。
规范给的时间顺序是死的：`TCP → 明文 X.224 → TLS → CredSSP(R1) → EUAR(R2) → MCS(R3)`
（`docs/spec/security-layer.md:265`，尤其 `:288` 的 EUAR 位置）。

于是产生一个不可回避的约束：

> **「现在该按哪种规则切」这个状态，和「已经收到但还没切完的字节」这个缓冲区，
> 必须由同一个对象持有。** 否则一方切了、另一方还以为没切，或者两方各切一次。

这不是审美问题，是可以构造出具体故障的：
- 若「阶段」在调用方、「缓冲区」在安全层：调用方在 `kAwaitEuar` 阶段调用「读 4 字节」，
  但安全层缓冲区里已经攒了 6 字节（4 EUAR + 2 字节半个 TPKT 头），
  安全层不知道剩下 2 字节该留着还是该丢 —— **缓冲区所有者缺阶段信息，必然出错**。
- 若「阶段」在安全层、「缓冲区」在调用方：调用方拿到一段明文，不知道该喂给谁。

**这就是「第一性原理推导起点」：分帧规则是阶段的函数，阶段与缓冲区不可分离。**

### 3.2 由此推出的四条硬性设计要求

| # | 要求 | 直接来源 |
|---|---|---|
| Q1 | 安全层必须**独占**一份明文累积缓冲 `plain_`，任何阶段都只从 `plain_` 头部消费 | §3.1 |
| Q2 | 阶段推进必须由**协议事件**触发（CredSSP `complete()`、EUAR 读满 4 字节），不能由「缓冲区里有没有数据」触发 | `include/rtsc/credssp/credssp.h:53`、`docs/spec/security-layer.md:399` |
| Q3 | 阶段切换点必须**断言缓冲区剩余量**（见 §5.3.3 的 `plain_` 必须为空的论证） | 推导 |
| Q4 | 安全层对外只暴露「密文进 / 明文 PDU 出 / 待发密文出 / 错误」，**不暴露阶段细节给 `ConnectMachine`** | `src/proto/connect_machine.cpp:224` 一旦收到数据就 Fail，说明它不该看见 CredSSP 字节 |

---

## 4. 三个可行方案

### 方案 A：`SecurityLayer` 双入口（`OnCiphertext` / `SendPdu`）

**推导起点**：把 §3.1 的「一个缓冲区 + 一个阶段」封装成一个类，对外提供两个方向的方法。
这是题目候选 (a) 的直接实现。

**数据流**

```
socket ──密文──> SecurityLayer::OnCiphertext()
                    ├─ phase==kTlsHandshake → TlsTransport::Handshake()   → to_wire
                    ├─ phase==kCredssp     → TlsTransport::Receive() → DER 分帧 → CredsspClient::OnServerResponse() → to_wire
                    ├─ phase==kAwaitEuar   → 从 plain_ 恰取 4 字节 → 判 AUTHZ → phase=kMcs
                    └─ phase==kMcs         → TpktStream::Append/Next → out.pdus
socket <──密文── SecurityLayer::to_wire
ConnectMachine <──完整 TPKT 帧── out.pdus
ConnectMachine ──完整 TPKT 帧──> SecurityLayer::SendPdu() → TlsTransport::Send() → to_wire
```

**所有权**：`SecurityLayer` 持有 `unique_ptr<TlsTransport>`、`CredsspClient`（值成员）、
`plain_`（明文累积）、`TpktStream`（仅在 `kMcs` 阶段启用）、`phase_`。
`ConnectMachine` 完全不知道 TLS/CredSSP 存在。

**错误路径（逐条）**

| 场景 | 行为 | 依据 |
|---|---|---|
| TLS 握手 `kNeedMoreInput` | 把 `out` 交出，`want=kRead` | `src/net/tls_schannel.cpp:185`（锚点 `return MakeError(Status::kNeedMoreInput, st, "incomplete handshake")`） |
| TLS 握手 `kCertRejected` | `ErrorKind::kCertificateRejected`，不重试 | `src/net/tls_schannel.cpp:192`（锚点 `case SEC_E_UNKNOWN_CREDENTIALS`） |
| TLS 握手 `kUnsupported`（服务器要客户端证书） | 终止，报「配置不支持」 | `src/net/tls_schannel.cpp:179`（锚点 `case SEC_I_CONTINUE_NEEDED`） |
| CredSSP 第 2 步解不出 TSRequest | `kProtocolViolation`（说明根本不是 TSRequest，可能是服务器没走 HYBRID） | `src/credssp/credssp.cpp:92` |
| 服务器回 `errorCode` | `kCredentialRejected` + `native_space=kNtstatus` + 原码 | `src/credssp/credssp.cpp:97` |
| 第 4 步 pubKeyAuth 不匹配 | `kProtocolViolation`（MITM 或拼接顺序错） | `src/credssp/credssp.cpp:283` |
| 第 5 步发出后收到 TLS alert 49 | 若后端能给出 alert 码 → `kCredentialRejected`；否则只能 `kProtocolViolation`（**见 S7**） | 缺陷 S7 |
| EUAR `0x05` | `kAuthorizationDenied`，不发 MCS | `docs/spec/security-layer.md:400` |
| EUAR 其他值 | `kProtocolViolation` | `docs/spec/security-layer.md:401` |
| EUAR 缺失（首字节是 `03`） | `kProtocolViolation`（严格）；可选配置放宽为「跳过 EUAR」 | 推导，见 §5.3.5 |
| TLS `kClosed` 但 `plain_` 里还有完整帧 | 先派发再关；**只要还有半个单位就报 `kTruncated`** | `include/rtsc/net/tls.h:148` |
| `ConnectMachine` 失败 | 直接把 `state_.error` 包成 `kProtocolViolation` 上报（见 S14） | `include/rtsc/proto/connect_machine.h:57` |

**可测性**：`SecurityLayer` 的输入只有「密文字节」和「明文字节」两个纯函数入口，
可以注入一个 `ScriptedTlsTransport`（实现 `TlsTransport` 纯虚接口，`include/rtsc/net/tls.h:124`）
完全离线跑；也可以用真实 SChannel 回环（`tests/test_tls.cpp:162`）跑「真 record + 假 CredSSP」。

**缺点**
1. 双入口意味着**调用方仍需知道「现在该调哪个」**：`OnCiphertext` 里 `kCredssp` 阶段可能产出
   `to_wire`，调用方必须记得写出去再读；漏写一次就死锁。阶段信息虽然私有，但**调用节奏仍被隐式要求**。
2. 「只 pump 不喂新数据」这件事没有自然的表达方式（要靠 `OnCiphertext(nullptr, 0)` 约定），
   而 `Receive` 的排空义务要求必须能这样调（`include/rtsc/net/tls.h:157`）。

---

### 方案 B（推荐）：`SecurityLayer` 单入口 `Step(Input)` 的可重入状态机

**推导起点**：方案 A 的缺点 1/2 都来自「入口分裂」。把入口收敛为一个函数，
返回值显式告诉调用方「我现在想要读还是想写」，就能把「调用节奏」也变成契约的一部分，
而不是靠文档约束。这与现有 `TlsTransport` 的设计哲学一致 ——
`TlsTransport` 每个方法都返回 `Error` 让调用方决定下一步，而不是自己阻塞。

**数据流**

```
struct Input  { Kind kind; const uint8_t* data; size_t size; };   // kCiphertext / kPdu / kNone
struct Output {
    std::vector<uint8_t> to_wire;                 // 需要写出的密文（可能为空）
    std::vector<std::vector<uint8_t>> pdus;       // 完整 TPKT 帧（含 4 字节头）
    std::optional<EuarResult> euar;               // 只在跨过 EUAR 的那一步出现
    Want want;                                    // kRead / kWrite / kDone / kFail
    SecurityError error;                          // kind==kNone 表示成功
};
Output Step(const Input& in);
```

`Step` 是**纯可重入**的：不阻塞、不开线程、不 sleep。
`want==kWrite` 表示「`to_wire` 非空，先写出去再回来」；`want==kRead` 表示「给我更多密文」。

**所有权**：与方案 A 相同（`TlsTransport` + `CredsspClient` + `plain_` + `TpktStream` + `phase_`），
但阶段**同时**体现在内部 `phase_` 和返回的 `Want` 上，二者由同一处代码更新，不会漂移。

**错误路径**：与方案 A 表完全一致（同一套映射，见 §5.5），差别只在「怎么把错误交出去」——
方案 B 把错误放在 `Output` 里，`Step` 本身不抛不返回码，调用方只需要 `if (out.error.kind != kNone)`。

**可测性**：**最好**。因为 `Step` 是确定性的纯状态转移，测试可以直接写成
「给定一串 `Input`，断言 `Output` 序列」，不需要线程、不需要 socket、不需要真 TLS：

```
Step({kCiphertext, server_flight_1}) -> want=kWrite, to_wire=ClientHello
Step({kNone})                        -> want=kRead
...
Step({kCiphertext, euar_and_mcs})    -> pdus={ConnectResponse...}, euar=SUCCESS
```

而且可以**逐字节喂**（`size=1`）验证「EUAR 跨 record 时仍恰取 4 字节」这类边界，
这在方案 A 的双入口下要绕。

**缺点**
1. `Input` 是个 tagged union，比两个方法多一层概念；对只想「连上」的调用方略重。
2. `Step` 返回 `want=kWrite` 时，调用方**必须**把 `to_wire` 写完再调 `Step({kNone})`；
   若忘记，会重复产生同一批字节（实现上应「交出即清空」，从而把「忘记写」降级为「连接卡住」而非「重复发送」）。
3. 需要明确「一次 `Step` 最多推进多少」的语义（建议：推进到下一个 `want` 变化点为止，不做无限循环）。

---

### 方案 C：职责链装饰器（`IPduChannel` 串联）

**推导起点**：把 §3.1 的四个域各做成一个「字节进/字节出」的小 stage，
由调用方按 `TlsRecordLayer → TsRequestFramer → EuarStage → TpktFramer` 串联。
这是题目候选 (c) 的强化版：库提供零件，编排在调用方。

**数据流**

```
socket → TlsRecordLayer ──明文──> TsRequestFramer ──完整 TSRequest──> CredsspStage
                                      │（阶段结束后透传）
                                      └──> EuarStage ──4 字节──> 判定
                                                │（透传剩余）
                                                └──> TpktFramer ──完整帧──> ConnectMachine
```

**所有权**：每个 stage 持有自己的缓冲；**阶段由 stage 之间的连接关系隐式表达**（连上就是该阶段）。

**错误路径**：每个 stage 各自返回自己的错误类型，需要在链顶做一次聚合映射
（比 A/B 多一层「谁的错误」的信息，容易在聚合处丢 `native_code`）。

**可测性**：每个 stage 可以独立单测，**单元级最好**；但**集成级最差**——
「EUAR 和第一条 MCS 粘在同一个 record 里」这种场景要求 `EuarStage` 把剩余字节
交给 `TpktFramer`，而这个「剩余」在装饰器模型里必须显式传递，
一旦某个 stage 选择自己缓存剩余，链上就出现两个缓冲区（违反 §3.1 的约束）。

**缺点**
1. **违反 §3.1 的核心约束**：链上每个 stage 都有自己的缓冲，「阶段」被编码进拓扑结构，
   而拓扑是静态的 —— 无法表达「同一批字节里先 4 字节 EUAR、再 N 字节 TPKT」这种
   **在一条流内部切换规则**的场景，除非 `EuarStage` 把剩余字节显式上抛，
   这就等价于把方案 B 的 `plain_` 又实现了一遍。
2. 调用方要负责装配顺序，装配错（比如把 `EuarStage` 放在 `TpktFramer` 之后）不会编译报错，
   只会在运行时表现为「EUAR 被吞」—— 正是 S2 那个故障。
3. 对「TLS 关闭时先排空」的语义，链上每一级都要实现一遍 drain，重复度高。

---

### 4.4 被否决的两个候选（题目 (b) 与 (c) 的原始形态）

#### (b) 让 `ConnectMachine` 直接持有 `TlsTransport*` 并内联驱动 —— **否决**

| 否决理由 | 证据 |
|---|---|
| 破坏依赖图：`rtsc_proto` 将被迫依赖 `rtsc_tls`，而当前 `rtsc_proto` 只依赖 `rtsc_crypto` | `CMakeLists.txt:36`、`CMakeLists.txt:51` |
| `ConnectMachine` 的头文件明确声明「transport agnostic」「Crypto (TLS, CredSSP, RC4) is deliberately outside」 | `include/rtsc/proto/connect_machine.h:19` |
| `kAwaitExternalSecurity` 阶段收到数据即 `Fail`，这条规则存在的**前提**就是「外部握手不在这里跑」；内联驱动必须删掉它，等于推翻现有测试 | `src/proto/connect_machine.cpp:224`、`tests/test_connect_machine.cpp:215` |
| `ConnectMachine` 现有测试全部喂**明文 PDU**，内联 TLS 后这些测试要么全改，要么要造一个「假 TLS」—— 而假 TLS 的复杂度等于方案 B 的 `ScriptedTlsTransport`，却把安全逻辑和协议逻辑耦合在一起 | `tests/test_connect_machine.cpp:104` |
| 未来 `PROTOCOL_RDSTLS` / `RDSAAD` 也要在同一位置插入，内联会让 `ConnectMachine` 变成安全协议杂物间 | `include/rtsc/proto/rdp_neg.h:19` |

#### (c) 由调用方（未来 socket 循环）编排，库只提供两个独立状态机 —— **否决**

| 否决理由 | 证据 |
|---|---|
| 「谁消费 EUAR 那 4 字节」没有归属：`TpktStream` 会把它当垃圾丢掉，调用方若不额外写一个 4 字节读取器就永远拿不到 `AUTHZ_ACCESS_DENIED` | `src/proto/framing.cpp:37`；`docs/spec/security-layer.md:399` |
| 阶段与缓冲区分离，直接违反 §3.1 的约束（这是可构造故障，不是理论洁癖） | §3.1 |
| 每个调用方（socket 循环、`rtsc_probe`、测试夹具）都要把同一套五步 + EUAR + 排空逻辑重写一遍，三份实现必然漂移 | `tools/rtsc_probe/main.cpp`（当前只到 CCF） |
| 与现有工程习惯不符：`TlsTransport` 自己就管 record 边界，`CredsspClient` 自己就管五步 —— 它们都不是「裸状态机 + 调用方编排」 | `include/rtsc/net/tls.h:142`、`include/rtsc/credssp/credssp.h:45` |

---

### 4.5 推荐

**推荐方案 B。** 若实现资源紧张，**方案 A 可作为第一阶段**，但必须满足两条附加约束：
1. 把 `Want` 放进返回值（否则调用方无法知道「现在该读还是该写」）；
2. 明确文档化「`OnCiphertext(nullptr, 0)` 表示只 pump」，并在实现里断言该路径不会推进阶段。

方案 C 只在「未来需要把安全层拆到独立进程 / 独立线程」时才值得考虑，当前不需要。

---

## 5. 七个设计问题的逐条结论

### 5.1 分层与所有权

**结论：新增 `SecurityLayer`（方案 B 形态），放在新库 `rtsc_security`，依赖 `rtsc_tls` + `rtsc_credssp` + `rtsc_proto`；`rtsc_proto` 的依赖图不变。**

理由链：
1. `ConnectMachine` 的注释已经把这个位置留好了：「when the negotiated protocol is not
   PROTOCOL_RDP the caller must run the external security handshake before feeding MCS PDUs in」
   （`include/rtsc/proto/connect_machine.h:19`）。
2. `kAwaitExternalSecurity` + `OnExternalSecurityComplete()` 这一对钩子，
   语义上就是「安全层完成后交还控制权」（`src/proto/connect_machine.cpp:352`）。
   安全层要做的正是：**在这个钩子被调用之前，把 `PROTOCOL_HYBRID_EX` 要求的一切做完**。
3. 依赖方向：`rtsc_security` → {`rtsc_tls`, `rtsc_credssp`, `rtsc_proto`}，
   与现有 `CMakeLists.txt:18` / `:51` / `:111` 的既有方向一致，无环。

**交还控制权的精确时机**（这一点必须写死，否则 EUAR 会被漏）：

```
ConnectMachine::Start()          → 明文 CRQ，直接 send（不经 TLS）
socket recv                       → 明文 CCF
ConnectMachine::OnData(ccf)       → phase = kAwaitExternalSecurity（connect_machine.cpp:217）
SecurityLayer::Create(cfg)        → phase = kTlsHandshake
  ... TLS 握手 ...
  ... CredSSP 五步 ...
  ... EUAR 4 字节，判 AUTHZ ...
ConnectMachine::OnExternalSecurityComplete()   → 产出 MCS Connect Initial（明文）
SecurityLayer::SendPdu(connect_initial)        → TLS 加密后 send
  ... 之后全部 PDU 双向都经 SecurityLayer ...
```

注意 `ConnectMachine::Start()` 的输出是**明文**，不能进 TLS ——
因为 TLS 握手必须在收到 CCF **之后**才开始（`docs/spec/security-layer.md:270`）。
安全层因此**不负责**连接最开始的那一次明文收发，这是它的生命周期起点定义。

---

### 5.2 字节流边界：`TpktStream` 能否复用

**结论：能复用，但必须解决「剥头」问题；且 `TpktStream` 只覆盖四个域中的 R3，R1/R2 需要新增。**

**证据链（这是本节的核心）**

1. `TpktStream` 的契约明确写着「the 4-byte TPKT header is **stripped**」：
   `include/rtsc/proto/framing.h:16`，实现见 `src/proto/framing.cpp:86`：
   ```cpp
   payload.assign(buf_.begin() + (read_ + kTpktHeaderSize),   // 从 +4 开始
                  buf_.begin() + (read_ + length));
   ```
2. `ConnectMachine::OnData` 要求**带头的完整帧**：
   `src/proto/connect_machine.cpp:196` 调 `X224ConnectionConfirm::parse(data, size, ccf)`；
   `src/proto/connection_initiation.cpp:55` 第一件事就是 `TpktHeader::parse(data, size, tpkt)`。
   MCS 侧更严格：`src/proto/mcs.cpp:128`
   ```cpp
   if (tpkt.length != size) return Status::InvalidLength;   // 要求整帧、且无尾随
   ```
   同样的严格检查在 `src/proto/mcs_domain.cpp:67`。
3. 因此 `TpktStream::Next()` 的输出**不能**直接喂给 `OnData`。
   两种修法：
   - **(a) 在安全层里还原头部**：`TpktStream::Next` 拿到 payload 后调 `WrapTpkt(payload.data(), payload.size())`
     （`include/rtsc/proto/framing.h:54`，实现 `src/proto/framing.cpp:99`）。
     代价：一次多余的拷贝；且 `WrapTpkt` 对 `size > kMaxPayload` 返回空
     （`src/proto/framing.cpp:100`），需要把它当协议错误处理。
   - **(b) 给 `TpktStream` 加一个 `NextFrame()`**：返回含头的整帧（内部 `read_` 推进同样的量）。
     代价：改 `rtsc_proto`（低风险，纯新增），但会扩大改动面。
   - 推荐 **(a)**，因为 `rtsc_proto` 当前是「已冻结的稳定层」，且 `WrapTpkt` 已经存在且有测试
     （`tests/test_framing.cpp:150`）。

**职责边界怎么划**

| 层 | 负责 | 不负责 | 证据 |
|---|---|---|---|
| `TlsTransport` | TLS record 边界、解密、关闭语义 | 任何 RDP 帧格式 | `include/rtsc/net/tls.h:142` |
| `SecurityLayer` | **当前处于哪个域**、域之间的切换、明文累积缓冲、EUAR 消费、跨 record 的 TSRequest 重组 | 解析 PDU 内容 | 本文 §3.1 |
| `TpktStream` | R3（TPKT 长度）再分帧 | 不知道 TLS 存在 | `include/rtsc/proto/framing.h:12` |
| `ConnectMachine` / `Mcs*::parse` | 校验帧内容是否合法 | 不知道字节从哪来 | `src/proto/mcs.cpp:257` |

**必须修改的 `TpktStream` 使用方式（重要）**

`TpktStream` 有「失步后逐字节前扫并丢弃」的自我修复逻辑：
`src/proto/framing.cpp:37`（`SkipToNextCandidate`）与 `:61`。
这在**明文 TCP** 上是合理的（`include/rtsc/proto/framing.h:18` 明说了理由）。
但在 **TLS 之内**，失步只可能是协议错误或实现 bug，静默丢弃会掩盖故障，
更糟的是会**吃掉 EUAR**（见 §5.3.2）。建议安全层使用时：
- 进入 `kMcs` 阶段前断言 `dropped_bytes()==0` 且保持为 0；
- 一旦 `Next()` 返回 `Status::InvalidLength` 或 `dropped_bytes()>0`，直接 `kProtocolViolation`。

---

### 5.3 EUAR 的读取

**结论：EUAR 不会与 MCS 混淆（首字节不同），但会被 `TpktStream` 静默吞掉；必须用「恰取 4 字节」的独立阶段，且该阶段必须能从同一条明文流里切出「4 字节 + 剩余 N 字节」。**

#### 5.3.1 为什么不会「误当 MCS」

| 字节序列 | 解释 | 会不会被 TPKT 解析器接受 |
|---|---|---|
| `00 00 00 00` | EUAR AUTHZ_SUCCESS | 否（`p[0]!=3`，`src/proto/tpkt.cpp:7`） |
| `05 00 00 00` | EUAR AUTHZ_ACCESS_DENIED | 否 |
| `03 00 xx xx` | TPKT 头 | 是 |

数值来自 `docs/spec/security-layer.md:381`。两种 EUAR 值的首字节都不是 `0x03`，
所以**不存在「EUAR 被当成 TPKT 头」的可能**。

#### 5.3.2 真正的问题：被静默吞掉

`TpktStream::Next` 对 `00 00 00 00` 的处理轨迹（按 `src/proto/framing.cpp:56` 推演）：

1. `buffered() >= 4`，取 `p = buf_.data()+read_`，`p[0]==0x00 != kVersion(3)` → 进入失步分支（`:61`）。
2. `SkipToNextCandidate()`（`:37`）逐字节前扫：位置 0..3 的 `p[0]` 都是 `0x00`，全部 `++read_`，`skipped=4`。
3. 扫到真正的 TPKT 头（`03 00 ...`）时 `break`，`dropped_ += 4`。
4. 返回那条 MCS PDU 的 payload。

**结果：授权被拒（`0x05`）和授权通过（`0x00`）在 `TpktStream` 眼里完全一样，都是「4 字节垃圾」。**
客户端会继续发 MCS Connect Initial，然后收到服务器的断开 —— 表现为「连上了但立刻掉线」，
而真正的错误码（`AUTHZ_ACCESS_DENIED`）已经永久丢失。

这不是理论推演：`SkipToNextCandidate` 的判定条件是
`p[0] == TpktHeader::kVersion && p[1] == 0 && len >= kMinTpktLength`（`:46`），
四个 `0x00`/`0x05` 一个都不满足，必然被跳。

#### 5.3.3 正确做法：显式的 `kAwaitEuar` 阶段

```
进入条件：CredsspClient::complete() == true（即第 5 步 authInfo 已发出）
          —— 证据 include/rtsc/credssp/credssp.h:53、src/credssp/credssp.cpp:305
退出条件：从 plain_ 头部恰取 4 字节，拼成 uint32 LE
          —— 证据 docs/spec/security-layer.md:375
```

关键不变量（必须在实现里 `assert`）：

> **进入 `kAwaitEuar` 的那一刻，`plain_` 必须为空。**

论证：第 5 步是**客户端发出的最后一条** CredSSP 消息（`docs/spec/security-layer.md:675`），
在它发出之前，客户端已经消费了第 4 步的完整 TSRequest（`src/credssp/credssp.cpp:252`）。
如果此刻 `plain_` 非空，说明服务器在第 4 步之后还发了额外数据 —— 那是协议违规，
而不是「EUAR 提前到了」。把这条写成断言，可以在 S2 类故障发生时立刻定位。

#### 5.3.4 「EUAR 和第一条 MCS PDU 粘在同一个 TLS record 里」怎么办

这是**必然会发生**的情况，因为 TLS record 只是传输层分片，服务器完全可以把
「EUAR + MCS Connect Initial」写进同一次 `send()`（甚至同一个 TLS record）。
现有契约已经明确这一点：`docs/spec/security-layer.md:562`
（「一个 TLS record 可装多个 TPKT 帧」）。

正确做法：**`plain_` 是唯一缓冲区，阶段决定从头部消费几个字节。**

```
plain_ = [00 00 00 00] [03 00 01 51 ... ConnectResponse ...]
         └─ 4 字节 ─┘  └────── 归 TpktStream ──────┘
kAwaitEuar 阶段：取头 4 字节 → 判 AUTHZ → phase=kMcs
kMcs 阶段：把 plain_ 剩余部分（此时 plain_ 已 remove_prefix(4)）Append 给 TpktStream
```

因为 `TpktStream::Append` 是纯追加（`src/proto/framing.cpp:16`），
把「剩余部分」喂进去即可，不需要特殊处理。**这正是「阶段与缓冲区同属一个所有者」的直接收益**：
如果 EUAR 读取器和 `TpktStream` 各有一份缓冲（方案 C），就必须在两者之间传递「剩余」，
而 `TpktStream` 的接口没有任何地方能接收「别人剩下的字节」。

#### 5.3.5 EUAR 缺失怎么办

若 `selectedProtocol & PROTOCOL_HYBRID_EX` 却收到首字节 `0x03`，有两种处理：

| 策略 | 行为 | 评价 |
|---|---|---|
| **严格（推荐）** | `kProtocolViolation`，detail 记「HYBRID_EX negotiated but no EUAR」 | 规范说 MUST 发（`docs/spec/security-layer.md:365`），违反就是服务器 bug；静默容忍会让真实故障变成「随机连不上」 |
| 容忍（可选配置 `euar_optional`） | 把已读的 4 字节回填 `plain_`，直接进 `kMcs` | 只在对接非微软实现时需要；必须默认关闭 |

注意：**不要用「读到的值是不是 0 或 5」来判断有没有 EUAR**。
`0x00000003` 这种值虽然不在规范里，但它不是合法 TPKT 头，仍然应该报协议错误，
而不是「猜测服务器没发 EUAR」。判据必须是「首字节是否为 0x03」。

---

### 5.4 TLS 关闭语义

**结论：安全层必须实现「先排空再传播」的三态关闭，并把「已关闭且有残留半帧」判为 `kTruncated` 而不是正常关闭。**

#### 5.4.1 现有后端的行为（证据）

| 行为 | 证据 |
|---|---|
| `kClosed` 时**保留**已解出的明文（契约） | `include/rtsc/net/tls.h:148` |
| `SEC_I_CONTEXT_EXPIRED` 时置 `closed_=true` 并**立即返回** `kClosed`，此时 `plaintext` 里已有本轮解出的数据 | `src/net/tls_schannel.cpp:301`（锚点 `SEC_I_CONTEXT_EXPIRED`） |
| 一旦 `closed_` 为真，后续 `Receive` **直接**返回 `kClosed`，不再看 `rx_buffer_` | `src/net/tls_schannel.cpp:232`（锚点 `if (closed_) return MakeError(Status::kClosed  (in Receive)`） |
| `rx_buffer_` 里可能残留 1..4 字节（不足一个 record 头） | `src/net/tls_schannel.cpp:244`（锚点 `rx_buffer_.size() < kMinRecordHeader`） |
| `Shutdown()` 也会置 `closed_=true` | `src/net/tls_schannel.cpp:432`（锚点 `closed_ = true;  (in Shutdown)`） |

#### 5.4.2 三种关闭状态的区分

安全层应把关闭细分为：

| 状态 | 判定 | 处理 |
|---|---|---|
| **正常关闭（已排空）** | `kClosed` 且 `plain_` 为空 且 `buffered_input()==0` 且当前阶段恰好在一个单位边界 | `kClosedByPeer`，正常结束 |
| **关闭但有完整帧** | `kClosed` 且 `plain_` 里还有**完整**单位（完整 TPKT / 完整 TSRequest） | **先派发这些单位**，再报 `kClosedByPeer` |
| **关闭且残留半帧** | `kClosed` 且 `buffered_input()>0`（1..4 字节残缺 record）**或** `plain_` 里有不完整单位 | `kTruncated`（**不是**正常关闭） |

第三条是重点：`src/net/tls_schannel.cpp:244`（锚点 `rx_buffer_.size() < kMinRecordHeader`） 在 `rx_buffer_.size() < 5` 时返回
`kOk`/`kNeedMoreInput`，如果紧接着对端 `close_notify`，`closed_` 变真，
那 1..4 字节就**永远**留在 `rx_buffer_` 里。若安全层把它当正常关闭，就是**静默丢数据**。

#### 5.4.3 排空算法（必须做，不能省）

```
on kClosed:
  loop:
    out = tls.Receive(nullptr, 0, plain_, 0)     // 只为把内部已解出的 record 追加到 plain_
    feed(plain_)                                  // 按当前阶段尽量切出完整单位并派发
    if tls.buffered_input() == 0: break
    if 本轮没有任何进展: break                    // 防死循环
  if plain_ 非空（有半帧）: return kTruncated
  return kClosedByPeer
```

契约依据：`include/rtsc/net/tls.h:157`（drain obligation）。

#### 5.4.4 必须修的缺陷：`Shutdown()` 早于排空

`Shutdown()` 在 `src/net/tls_schannel.cpp:432`（锚点 `closed_ = true;  (in Shutdown)`） 置 `closed_=true`。
如果调用方在 `rx_buffer_` 还有未处理的 record 时调 `Shutdown()`，
后续 `Receive` 会在 `:232` 直接返回 `kClosed`，那些 record 被永久丢弃。

**规避（在安全层侧）**：只有在 `Receive` 已经返回过 `kClosed`（对端先关）之后，
或业务层明确要求断开时才调 `Shutdown()`；且调之前先做一次 §5.4.3 的排空。
**根治（在后端侧）**：`Shutdown()` 不应置 `closed_` 影响 `Receive` 的入队能力，
或 `Receive` 在 `closed_` 且 `rx_buffer_` 非空时仍应继续解密。这属于 `rtsc_tls` 的后续修复项（S9）。

---

### 5.5 错误传播：单一错误类型

**结论：新增 `rtsc::net::SecurityError`，用「`kind`（语义）+ `stage`（阶段）+ `native_space` + `native_code`（原码）」四元组，禁止把三个库的错误类型直接上抛。**

#### 5.5.1 为什么不能只用一个 `int32_t native_code`

同一个数值在不同命名空间下含义完全不同：
- `0x80090308` 是 SSPI 的 `SEC_E_INVALID_TOKEN`（`src/net/tls_schannel.cpp:187`（锚点 `case SEC_E_INVALID_TOKEN`）（锚点 `case SEC_E_INVALID_TOKEN`） 的映射对象）；
- 但它也可能是 CredSSP `errorCode` 字段里的一个 NTSTATUS 值（`src/credssp/credssp.cpp:101` 把
  `req.error_code` 原样塞进 `native_code`）。
- 更麻烦的是 `rtsc::credssp::Error` 和 `rtsc::tls::Error` **都有一个叫 `native_code` 的 `int32_t`**
  （`include/rtsc/credssp/ts_request.h:34`、`include/rtsc/net/tls.h:59`），
  直接合并会丢失「这个码是谁的」这一信息。

#### 5.5.2 类型设计（契约，非实现）

```cpp
namespace rtsc::net {

enum class ErrorStage : uint8_t {
    kTlsHandshake, kCredssp, kEuar, kProtocol, kTransport, kClose
};

enum class ErrorKind : uint8_t {
    kNone = 0,
    kWouldBlock,             // 非错误：需要更多输入
    kCertificateRejected,    // 证书策略拒绝
    kCredentialRejected,     // 密码/账号错误（NTSTATUS / alert 49）
    kAuthorizationDenied,    // EUAR 0x05，或 STATUS_LOGON_TYPE_NOT_GRANTED
    kProtocolViolation,      // 对端违反协议
    kUnsupported,            // 本实现不支持（如服务器要客户端证书）
    kInternal,               // 本地 bug / 环境问题
    kClosedByPeer,           // 正常关闭
    kTruncated,              // 关闭时残留半帧
};

enum class NativeSpace : uint8_t {
    kNone, kSspiSecurityStatus, kNtstatus, kCredsspErrorCode, kWin32, kTlsAlert
};

struct SecurityError {
    ErrorKind   kind        = ErrorKind::kNone;
    ErrorStage  stage       = ErrorStage::kTlsHandshake;
    NativeSpace native_space= NativeSpace::kNone;
    int32_t     native_code = 0;
    std::string detail;     // 只用于人读，不参与控制流
};

}  // namespace rtsc::net
```

#### 5.5.3 映射规则（逐条，全部有证据）

| 来源 | 判据 | `kind` | `native_space` | 证据 |
|---|---|---|---|---|
| `tls::Error` | `status == kCertRejected` | `kCertificateRejected` | `kSspiSecurityStatus` | `include/rtsc/net/tls.h:44`、`src/net/tls_schannel.cpp:192`（锚点 `case SEC_E_UNKNOWN_CREDENTIALS`） |
| `tls::Error` | `status == kPeerAlert` | `kCredentialRejected` if `native_code==49`，否则 `kProtocolViolation` | `kTlsAlert` | `docs/spec/security-layer.md:582` |
| `tls::Error` | `status == kDecryptFailed` / `kProtocolError` | `kProtocolViolation` | `kSspiSecurityStatus` | `include/rtsc/net/tls.h:43` |
| `tls::Error` | `status == kUnsupported` | `kUnsupported` | `kSspiSecurityStatus` | `src/net/tls_schannel.cpp:179`（锚点 `case SEC_I_CONTINUE_NEEDED`） |
| `tls::Error` | `status == kInternal` | `kInternal` | `kSspiSecurityStatus` | `include/rtsc/net/tls.h:47` |
| `tls::Error` | `status == kClosed` | `kClosedByPeer` | `kNone` | `include/rtsc/net/tls.h:50` |
| `credssp::Error` | `native_code ∈ {0xC000006D, 0xC000006A, 0xC0000064}` | `kCredentialRejected` | `kNtstatus` | `src/credssp/credssp.cpp:97` |
| `credssp::Error` | `native_code == 0x8009030C`（`SEC_E_LOGON_DENIED`） | `kCredentialRejected` | `kNtstatus` | 同上 |
| `credssp::Error` | `native_code == 0xC000015B`（`STATUS_LOGON_TYPE_NOT_GRANTED`） | `kAuthorizationDenied` | `kNtstatus` | 同上 |
| `credssp::Error` | 其他非零 `native_code` | `kCredentialRejected`（保守，保留原码供上层细化） | `kNtstatus` | 推导 |
| `credssp::Error` | `native_code == 0` 且 `status==kMalformed/kTruncated` | `kProtocolViolation` | `kNone` | `include/rtsc/credssp/ts_request.h:22` |
| `credssp::Error` | `status == kUnsupported` | `kUnsupported` | `kNone` | 同上 |
| `credssp::Error` | `status == kInternal` | `kInternal` | `kNone` | 批 1 新增枚举值（见 §19.3.2 批 1 说明） |
| EUAR | 值 `0x05` | `kAuthorizationDenied` | `kCredsspErrorCode` | `docs/spec/security-layer.md:386` |
| EUAR | 值 `0x00` | `kNone` | `kNone` | `docs/spec/security-layer.md:385` |
| EUAR | 其他值 | `kProtocolViolation` | `kCredsspErrorCode` | `docs/spec/security-layer.md:401` |
| `ConnectMachine` | `failed()==true` | `kProtocolViolation` | `kNone`，`detail=state_.error` | `include/rtsc/proto/connect_machine.h:57`、`:118` |

#### 5.5.4 两条硬规则

1. **`native_code` 永不丢弃，永不重编码。** 原始 `int32_t` 按位搬运，只附加 `native_space`
   说明它属于哪个命名空间。禁止「映射成自己的枚举码后丢掉原码」。
2. **`detail` 只给人看。** 任何控制流分支都不许 `strstr(detail, "...")` ——
   现有 `ConnectMachine::state_.error` 是 `std::string`（`include/rtsc/proto/connect_machine.h:57`），
   这正是**不能**让它参与错误分类的原因（S14）。安全层应把它降级为 `detail`，
   同时用自己的 `kind` 表达语义。

#### 5.5.5 「证书被拒」和「密码错误」的区分前提

要真正区分，必须先修 S7（后端从不产生 `kPeerAlert`）和 S8（`kStrict` 未实现）。
在两者修复前：
- 「证书被拒」只可能来自 `kCertRejected`，而当前**没有任何代码路径**会产生它
  （`src/net/tls_schannel.cpp` 全文无链校验、无 pin 比对）；
- 「密码错误」会以 `errorCode`（NTSTATUS）形式出现（`src/credssp/credssp.cpp:97`），
  这条路径是通的；
- 所以**在 S7/S8 修复前，`kCertificateRejected` 这个分支是死代码**，必须在文档里写明。

---

### 5.6 可测性：假服务器要伪造什么

**结论：分两级造假——① `ScriptedTlsTransport`（纯离线，覆盖全部故障注入）；② 真实 SChannel 回环 + 假 CredSSP 服务端（覆盖真实 record 分片）。CredSSP 服务端可以用现有 NTLM 原语真实构造，不需要第二个实现。**

#### 5.6.1 第一级：`ScriptedTlsTransport`

`TlsTransport` 是纯虚接口（`include/rtsc/net/tls.h:124`），且 `BackendInfo` 的注释里
已经预留了 `"scripted"` 这个名字（`include/rtsc/net/tls.h:191`）—— 说明设计时就想到了这条路。

需要伪造的**全部**东西（对照纯虚函数逐个列）：

| 成员 | 伪造方式 | 为什么必须能伪造 |
|---|---|---|
| `Handshake` | 预置 server flight 队列；每次调用弹出下一个，`consumed=in_size` | 覆盖多轮握手 |
| `Send` | 记录明文（供断言），产出可配置的「伪密文」 | 断言 CredSSP 消息的字节内容 |
| `Receive` | 按脚本吐出明文；可配置**分片粒度**（1 字节 / 整段）与**合并**（多条消息一次吐出） | 这是 EUAR 跨 record 场景的唯一可测手段 |
| `PeerSubjectPublicKey` | 返回固定的 270 字节 SPKI BIT STRING 内容 | CredSSP 第 3 步需要它 |
| `negotiated` | 返回 `{0x0303, ...}` | 断言版本窗口 |
| `record_sizes` | 返回 `{13,16384,16,16,16}`（实测值，`evidence/schannel-tls-backend.md`） | 断言分片逻辑 |
| `Shutdown` | 可配置「成功」/「失败」 | 覆盖关闭路径 |
| `closed()` / `buffered_input()` | **关键**：能构造 `closed()==true && buffered_input()>0` | 覆盖 §5.4.2 的 `kTruncated` 判定 |
| 故障注入 | `kClosed` 带明文、`kDecryptFailed`、`kPeerAlert(49)`、`kCertRejected` | 覆盖全部错误分支 |

**这一级的价值**：可以在**没有任何 SSPI** 的环境（Linux/Android 构建）跑完整的安全层测试，
与 `rtsc_credssp` 的「平台无关」定位一致（`CMakeLists.txt:109`）。

#### 5.6.2 第二级：真实 SChannel 回环 + 假 CredSSP 服务端

`tests/test_tls.cpp:50` 的 `RawServer` 已经是一个**真实 SSPI 服务端**：
- `Start()` 用自签名证书 + `SP_PROT_TLS1_2_SERVER`（`:58`）
- `Step()` 驱动 `AcceptSecurityContext`（`:73`）
- `Encrypt()` / `Decrypt()` 直接产/消真实 TLS record（`:95`）

`Loopback`（`:162`）已经把「客户端 + 真实 record 收发」跑通了。
所以第二级**几乎不需要新的 SSPI 代码**，只要把 `Loopback::ServerToClient`
（`:211`）换成「先 Encrypt 一个 CredSSP 响应，再 Encrypt 一个 EUAR+MCS」。

#### 5.6.3 CredSSP 假服务端：需要构造什么，能不能构造

| 步骤 | 假服务端要做什么 | 用什么现有能力 | 能否做到 |
|---|---|---|---|
| 解第 1 步 | `TsRequest::Decode` 拿到 `nego_token`，校验是 40 字节裸 NTLM NEGOTIATE | `src/credssp/ts_request.cpp:275` | ✅ 真实实现 |
| 发第 2 步 CHALLENGE | 造 `ChallengeMessage`：flags + 8 字节 server challenge + AV pairs（含 Timestamp） | `include/rtsc/credssp/ntlm.h:83`；现成配方见 `tests/test_credssp_sm.cpp:75` | ✅ |
| 校验第 3 步 AUTHENTICATE | 用已知密码重算 `Ntowfv2` + `ComputeNtlmV2`，比对 `NTProofStr`；用 `ComputeMic` 校验 MIC | `include/rtsc/credssp/ntlm.h:134`、`:158`；客户端侧消息可用 `NegotiateMessageForTest`/`ChallengeMessageForTest`（`include/rtsc/credssp/credssp.h:71`） | ✅ |
| 发第 4 步 pubKeyAuth | `CredsspClient::MakeServerEchoForTest()` 直接产出客户端会接受的 echo | `include/rtsc/credssp/credssp.h:64`、`src/credssp/credssp.cpp:364` | ✅（有局限，见下） |
| 校验第 5 步 authInfo | `DecryptAuthInfoForTest` 解出 TSCredentials，再 `PasswordCredentials::Decode` | `include/rtsc/credssp/credssp.h:67`、`src/credssp/ts_request.cpp:422` | ✅ |
| 发 EUAR | 4 字节 `00 00 00 00` / `05 00 00 00` | 无现有类型，需新增一个 4 字节常量 | ✅ 极简 |
| 发 MCS Connect Response | 现成的 337 字节 dump | `tests/test_connect_machine.cpp:70`（`kConnectResponseHex`） | ✅ |

**必须说清的局限（不能掩盖）**：
`MakeServerEchoForTest()` 和 `DecryptAuthInfoForTest()` 用的是**客户端自己的密钥**
（`src/credssp/credssp.cpp:384` 用 `exported_session_key_` 派生服务端方向密钥）。
所以这类测试**只能验证「协议流程正确」，不能验证「密钥派生正确」**——
如果 `DeriveSigningKey`/`DeriveSealingKey` 整体写反，假服务端会跟着一起反，测试照样绿。
密钥派生的正确性只能靠**官方向量**（`tests/test_ntlm.cpp` 的 4.2.3.4 / 4.2.4.4），
这是既有事实（`evidence/credssp/impl-log.md:51`）。集成测试里必须写一句注释说明这一点，
否则未来有人会误以为集成测试覆盖了密码学正确性。

#### 5.6.4 建议的测试矩阵

| # | 夹具 | 覆盖点 |
|---|---|---|
| T1 | `ScriptedTlsTransport` | 五步正常流 + EUAR SUCCESS |
| T2 | 同上 | EUAR 分两片到达（2+2） |
| T3 | 同上 | EUAR 与 Connect Response 粘在同一个 `Receive` 输出里 |
| T4 | 同上 | EUAR = `05` → `kAuthorizationDenied` 且**不产生** MCS 输出 |
| T5 | 同上 | EUAR 缺失（首字节 `03`）→ `kProtocolViolation` |
| T6 | 同上 | TSRequest 跨两个 `Receive` 到达 → 正确重组（S4 回归） |
| T7 | 同上 | `kClosed` + 完整帧 → 先派发后关闭 |
| T8 | 同上 | `kClosed` + 半帧 → `kTruncated` |
| T9 | 同上 | `kPeerAlert(49)` → `kCredentialRejected` + `native_space==kTlsAlert` |
| T10 | 同上 | `errorCode=0xC000006D` → `kCredentialRejected` + `native_space==kNtstatus` |
| T11 | 真实 SChannel 回环 | 真 record 上跑完整流（证明分帧在真实分片上成立） |
| T12 | 真实 SChannel 回环 | 服务器把 EUAR+MCS 塞进一个 record |
| T13 | `ScriptedTlsTransport` | `Shutdown` 后仍有 `buffered_input()` → `kTruncated`（S9 回归） |

---

## 6. 缺陷清单

> 严重度：**P0** = 直接导致接入失败或静默不安全；**P1** = 特定场景下失败或错误不可诊断；
> **P2** = 契约/可维护性问题，会在集成期制造返工。

| 编号 | 症状 | 证据 | 影响 | 建议 |
|---|---|---|---|---|
| **S1** | **nonce 从不随机**：`CredsspClient` 构造时把 `nonce_` 填成 32 个 0；全仓库无任何 CSPRNG 调用（grep `random` 只命中注释与 NTLM 字段名） | `src/credssp/credssp.cpp:46`（`nonce_.assign(kNonceSize, 0)`）；`include/rtsc/credssp/credssp.h:57` 的注释自称「production path generates the nonce with a CSPRNG」但无实现；`src/credssp/credssp.cpp:176`（client challenge 取 `nonce_[0..8)`）、`:191`（exported session key 取 `nonce_[8..24)`） | **P0**。默认配置下 client challenge 与 exported session key 全为 0，NTLM 会话密钥可预测，MIC/SEAL 全部失去意义；而且**握手会成功**，不会报错 | 在 `rtsc_security`（或 `rtsc_crypto`）加 `RandomBytes()`（Windows `BCryptGenRandom`/`RtlGenRandom`，其他平台 `getrandom`/`arc4random`）；`CredsspClient` 构造时即填充，删除「默认全 0」；`SetNonceForTest` 保留但改为显式测试专用工厂。**必须加一条红证测试**：两次构造的 nonce 不相等 |
| **S2** | **EUAR 无任何读取器**，且 `TpktStream` 会把 4 字节 EUAR 当垃圾静默丢弃（见 §5.3.2 推演） | 全仓 grep `AUTHZ`/`authorizationResult`/`EarlyUser` → **0 命中**；`src/proto/framing.cpp:37`（`SkipToNextCandidate`）、`:61`（失步分支）、`:52`（`dropped_ += skipped`） | **P0**。`AUTHZ_ACCESS_DENIED` 永久丢失，客户端在被拒后仍发 MCS，表现为「连上即掉线」且无错误码 | 新增 `kAwaitEuar` 阶段（§5.3.3），恰取 4 字节；把 `dropped_bytes()>0` 在 TLS 内判为协议错误 |
| **S3** | **`TpktStream` 剥头，`ConnectMachine` 要头**，直接对接 100% 失败 | `include/rtsc/proto/framing.h:16`、`src/proto/framing.cpp:86` vs `src/proto/connect_machine.cpp:196`、`src/proto/connection_initiation.cpp:55`、`src/proto/mcs.cpp:128` | **P0**。第一帧 MCS Connect Response 就会 `InvalidVersion` | 安全层用 `WrapTpkt` 还原（`include/rtsc/proto/framing.h:54`、`src/proto/framing.cpp:99`），或给 `TpktStream` 加 `NextFrame()` |
| **S4** | **无 DER 分帧器**：CredSSP 消息被当作「一次 `Receive` 的整块明文」；跨 TLS record 的 TSRequest 无法重组 | `src/credssp/ts_request.cpp:275`（要求恰好一条 `SEQUENCE`）、`:283`（**拒绝尾随字节**）；`include/rtsc/credssp/credssp.h:51` 的签名是 `(data, size)` 无状态；全仓无任何 DER 长度累积器 | **P0**。服务器若把一条 TSRequest 拆进两个 TLS record（TLS 完全允许，`docs/spec/security-layer.md:562`），客户端会 `kTruncated` 失败；若把两条消息塞进一次 `Receive`，会因「trailing bytes」失败 | 在安全层实现 DER TLV 头读取（`30` + 长度，长形式 ≤4 字节），累积到完整再调 `OnServerResponse`。长度解析规则可照 `src/credssp/ts_request.cpp:52`（注意 `Reader` 是文件内私有类，需重写或提取） |
| **S5** | **服务端 TSRequest.version 从不校验**；声称「拒绝 version 1」的测试其实是靠 token 解析失败通过的 | `src/credssp/credssp.cpp:91`（`req.Decode` 后直接进 `BuildStep3`，无 `req.version` 检查）；`tests/test_credssp_sm.cpp:128` 用 `nego_token="0011"`，失败点是 `BuildStep3` 的 `ChallengeMessage::Decode`（`src/credssp/credssp.cpp:122`），不是版本 | **P1**。服务器若回 version=3，客户端仍按 v6 算绑定哈希并发 `clientNonce`，第 4 步必然不匹配，错误表现为「pubKeyAuth mismatch」而非「版本不支持」，误导排查 | 在 `OnServerResponse` 里校验 `req.version ∈ [kMinVersion, kMaxVersion]`，并在测试里用**合法的** CHALLENGE 配 version=1 来证明是版本被拒 |
| **S6** | **服务端版本不回写 `version_`**：第 3/5 步仍用客户端自己的版本 | `src/credssp/credssp.cpp:241`、`:300` 都写 `req.version = version_`；全文件无 `version_ = req.version` 赋值 | **P1**。同上，服务器降版时会走错哈希路径 | 收到第 2 步后 `version_ = clamp(req.version)`，并据此决定 step3/5 的编码；同时把该值暴露给上层（错误分类需要） |
| **S7** | **`kPeerAlert` 从不产生**：后端没有任何 alert 解析路径，`native_code` 拿不到 alert 描述 | `include/rtsc/net/tls.h:42` 声明 `native_code = alert description`；`src/net/tls_schannel.cpp` 全文无 `kPeerAlert` 的产出点，只有 `:305`（`MESSAGE_ALTERED`/`DECRYPT_FAILURE`→`kDecryptFailed`）、`:308`（`INVALID_TOKEN`/`ILLEGAL_MESSAGE`→`kProtocolError`）；`docs/spec/security-layer.md:1765` 的检查项要求「能解析 TLS fatal alert 并映射为可读错误」 | **P1**。TLS alert 49（`ACCESS_DENIED`，即凭据无效，`docs/spec/security-layer.md:582`）会变成 `kProtocolError`，**「密码错误」与「协议违规」无法区分**，直接破坏 §5.5 的分类要求 | 在 `Receive` 里对 `SEC_E_ILLEGAL_MESSAGE` 等状态尝试从明文 record 里提取 alert（TLS1.2 下 alert 是 `15 03 03 00 02 <level> <desc>`）；拿不到时至少把 `kProtocolError` 的 `detail` 标注「可能是 fatal alert」。**需实测 SChannel 的实际返回值**（见 §8 U4） |
| **S8** | **`kStrict` / `kTofu` 未实现**：三种策略都只是置 `ISC_REQ_MANUAL_CRED_VALIDATION`，之后既不查链也不比 pin | `src/net/tls_schannel.cpp:137`（锚点 `switch (config_.cert_policy)`）（switch 三分支）、`:139`/`:144`/`:147` 全部同一句 `req |= ISC_REQ_MANUAL_CRED_VALIDATION`，`:142` 的注释自称 DEFERRED 但代码不是；`include/rtsc/net/tls.h:104` 的 `pinned_spki_sha256`/`pin_is_set` 全仓**零使用**（grep 无命中） | **P1**。`kStrict` 实际等于 `kInsecure`；`kCertificateRejected` 分支是死代码（`src/net/tls_schannel.cpp:192`（锚点 `case SEC_E_UNKNOWN_CREDENTIALS`） 只在 SChannel 自己拒绝时触发，而 MANUAL 模式把决定权交给了我们，我们却什么也没做） | 用 `SCH_CRED_DEFERRED_CRED_VALIDATION`（而非 MANUAL）+ 握手后 `QueryContextAttributes(SECPKG_ATTR_REMOTE_CERT_CONTEXT)` + `CertGetCertificateChain` 做链校验；`kTofu` 比对 `SHA256(SPKI)` 与 `pinned_spki_sha256`（SPKI 提取已有：`src/net/tls_schannel.cpp:371`（锚点 `Error PeerSubjectPublicKey(`）） |
| **S9** | **`Shutdown()` 后 `Receive` 短路**：`closed_=true` 会让后续 `Receive` 在入口直接返回，`rx_buffer_` 里的 record 永远丢失 | `src/net/tls_schannel.cpp:432`（锚点 `closed_ = true;  (in Shutdown)`）（Shutdown 置 `closed_`）与 `:232`（Receive 入口 `if (closed_) return kClosed`）；`rx_buffer_` 的入队/消费在 `:236` | **P1**。正常关闭流程（业务层决定断开 → Shutdown → 还想读完）会丢数据；在 RDP 里意味着最后一个 PDU（如 `Set Error Info`）可能被吞 | 安全层侧：只在已收到对端 `kClosed` 后才调 `Shutdown`，且先排空（§5.4.3）。后端侧：`Shutdown` 不应阻止 `Receive` 消费 `rx_buffer_` |
| **S10** | **`Handshake` 无条件 `consumed = in_size`**，忽略输入 buffer 被 SChannel 消费后剩下的 `EXTRA` | `src/net/tls_schannel.cpp:116`（锚点 `SecBuffer in_bufs[1]`）（声明 `in_bufs`）、`:126`（设 `cbBuffer`）之后**再未读取** `in_bufs[0].cbBuffer`；`:169`（注释断言「SChannel's stream handshake does not report EXTRA」并直接 `consumed = in_size`） | **P1（风险，未实测）**。若服务器把 `Finished` 与第一条应用数据（CredSSP step 2 的 TSRequest）合并在同一 TCP 段，那部分字节会被当作「已消费」而丢失 → 客户端死等 step 2 | 改为按 `in_bufs[0].cbBuffer` 计算真实消费量，或握手完成后把未消费尾部交给 `Receive`。**必须先按 §8 U1 实测**，不能凭注释断言 |
| **S11** | **第 4 步签名不校验**：`OpenReceive` 只解密，不验 HMAC | `src/credssp/credssp.cpp:347`（`recv_rc4_.Apply` 后直接 `++recv_seq_` 返回，无 MAC 比对，见 `:359`）；`evidence/credssp/impl-log.md:98`（自认 C5 局限） | **P1**。MITM 可篡改第 4 步内容；当前只靠「回显值等于期望值」间接防护（`src/credssp/credssp.cpp:283`），比验签弱 | 在 `OpenReceive` 里按 `[MS-NLMP] 3.4.5` 校验 `signature[4..12)`（用 `signing_key_` + `recv_seq_` 重算 HMAC，再在 recv RC4 流上解 checksum）。注意 RC4 流顺序：必须先解密文再解 checksum，与 `SealSend`（`:318`→`:329`）对称 |
| **S12** | **`OnExternalSecurityComplete()` 在错误阶段静默 no-op**：返回 `needs_input=false` 且不改状态、不置错 | `src/proto/connect_machine.cpp:352`（`if (phase != kAwaitExternalSecurity) { s.needs_input=false; return s; }`，`:355`） | **P2**。驱动层若在错误时机调用（例如安全层失败后误调），会得到「既不前进也不报错」的静默卡死，最难排查 | 改为 `Fail("OnExternalSecurityComplete in wrong phase")`，或返回带错误码的结果。现有测试 `tests/test_connect_machine.cpp:200` 不会受影响 |
| **S13** | **`OnData` 一进二出**：`kAwaitConnectResponse` 一次返回 `Erect Domain + Attach User` 两条 PDU | `src/proto/connect_machine.cpp:268`（`Append(out, McsErectDomainRequest::build())`）、`:269`（`Append(out, McsAttachUserRequest::build())`） | **P2**。驱动层若按「一次 `OnData` → 一条 `Send`」实现，语义上没错（`TlsTransport::Send` 会整体加密），但若按「一条 PDU 一次 `Send`」实现，就会把两条粘在一起发 —— 多数服务器能接受，但与 `docs/spec/security-layer.md:934`「一条 TSRequest 一次 write」的严格要求容易混淆 | 在 `ConnectStep` 文档里写明「`output` 可能含多条 PDU，必须整体一次 `Send`」；或改为逐条返回 |
| **S14** | **`state_.error` 是 `std::string`，无错误码** | `include/rtsc/proto/connect_machine.h:57`；`src/proto/connect_machine.cpp:122`（`Fail(const char* reason)` 只存字符串） | **P2**。无法参与 §5.5 的统一错误分类，上层只能靠字符串匹配（而字符串是给人读的，随时会改） | 给 `ConnectState` 加 `ErrorKind kind` + `int32_t native_code`（默认 `kNone/0`），`Fail` 增加重载；字符串保留为 `detail`。这是纯新增，不破坏现有测试 |
| **S15** | **仓库内没有任何 socket 驱动**：「接入连接流程」目前没有调用方 | 全 `src/**` grep `recv(`/`send(`/`socket(`/`WSAStartup` → 仅命中 `SealSend`/`TlsTransport::Send` 这类同名函数，无真实网络代码；`tools/rtsc_probe/main.cpp` 只做到 CCF（`evidence/handshake-001.md:44`） | **P2**。安全层设计完仍无法端到端跑；且「谁负责 `select`/阻塞、谁负责重连」没有契约 | 本轮设计必须同时给出驱动契约（§5.1 的时序图 + 方案 B 的 `Want`），并在实现阶段先做一个最小阻塞式驱动，再接安全层 |
| **S16** | **`Send` 可能把一个明文拆成多条 TLS record**，与「整条 TSRequest 一个 fragment」冲突 | `src/net/tls_schannel.cpp:219`（锚点 `while (done < size)`）（`while (done < size)` 按 `MaxChunk()` 切，`:219`）；`docs/spec/security-layer.md:934`（服务器要求「a TLS encrypted message fragment contain an entire ASN.1 message」「without fragmentation」） | **P2**。正常 TSRequest 远小于 16384，不会触发；但一旦触发（超大 `authInfo` + 证书链），服务器会拒绝，且错误难以归因 | 安全层在 CredSSP 阶段**每条消息只调一次 `Send`**，并在 `Send` 前断言 `size <= record_sizes().max_plaintext`，否则报 `kUnsupported` |
| **S17** | **`CredsspClient::complete()` 早于服务器确认**，容易被误当「已授权」 | `src/credssp/credssp.cpp:305`（第 5 步发出后立刻 `step_ = kDone`）；`include/rtsc/credssp/credssp.h:53` | **P2**。若安全层把 `complete()` 当作「安全层完成」并直接调 `OnExternalSecurityComplete()`，就会跳过 EUAR —— 正是 S2 的另一种触发方式 | 安全层的「完成」判据必须是 **`kEuarDone` 且 `AUTHZ_SUCCESS`**，绝不能是 `CredsspClient::complete()`。在 `CredsspClient` 头注释里加一句警告 |

**统计：17 条（P0 × 4，P1 × 7，P2 × 6）。**

---

## 7. 推荐落地顺序（不写代码，只给验收点）

> 本轮只做设计与审计，以下为交给执行 AI 的顺序建议。每步都必须「先红后绿」。

| 步 | 内容 | 红证（先失败） | 验收 |
|---|---|---|---|
| 1 | 修 S1：引入 CSPRNG，`CredsspClient` 默认随机 nonce | 测试「两次构造 nonce 相等」→ 当前必失败 | 两次 nonce 不等；现有 15 个 `credssp_sm` 测试仍绿（`SetNonceForTest` 保留） |
| 2 | 修 S5/S6：校验并回写 `version_` | 用**合法 CHALLENGE** + `version=1` 构造，当前必「通过」（错） | 该用例变红→修后变绿；`version=3` 时第 3 步不带 `clientNonce` |
| 3 | 新增 `ScriptedTlsTransport`（仅测试用） | 先写 T1/T4/T5 三条用例，无实现必编译失败 | 三条用例全绿，且不链接 `secur32` |
| 4 | 新增 `SecurityLayer`（方案 B），先只做 TLS + EUAR 骨架 | T2/T3（EUAR 跨片/粘连）先红 | 全绿；`plain_` 唯一缓冲 |
| 5 | 接 CredSSP + DER 分帧（S4） | T6（TSRequest 跨 record）先红 | 全绿 |
| 6 | 接 `ConnectMachine`（S3：`WrapTpkt` 还原） | T11/T12（真实回环）先红 | 全绿，且 `rtsc_connect_machine_tests` 26 条不受影响 |
| 7 | 统一错误类型（§5.5）+ S14 | T9/T10 先红 | 全绿；`native_space`/`native_code` 可断言 |
| 8 | 修 S7/S8（alert + 证书策略） | 需要先做 §8 U4 的实测 | T9 变绿；`kStrict` 拒绝自签名 |
| 9 | 最小 socket 驱动（S15），真机联调 | 无 | 能过 CCF → TLS → CredSSP → EUAR → MCS Connect Response |

**影响范围测试策略（给执行 AI）**：
- 改 `rtsc_credssp` → 跑 `rtsc_credssp_tests` / `rtsc_ntlm_tests` / `rtsc_credssp_sm_tests`；
- 改 `rtsc_proto/framing` 或 `connect_machine` → 跑 `rtsc_framing_tests` / `rtsc_connect_machine_tests` / `rtsc_mcs_tests`；
- 改 `rtsc_tls` → 跑 `rtsc_tls_tests`；
- 新增 `rtsc_security` → 新增套件 + 上述全部（因为它是三者的汇合点）。

**禁止全量 `ctest` 代替影响面分析**，但**新增库的首次集成必须跑一次全量**以确认无链接冲突。

---

## 8. 未验证项

> 以下每一项都无法从当前代码或规范确认。每项给出**为什么没验证**与**如何验证**。
> 不含任何推断性填充。

| # | 未验证项 | 为什么没验证 | 如何验证 |
|---|---|---|---|
| **U1** | `InitializeSecurityContext` 在流式模式下是否报告 `SECBUFFER_EXTRA`（S10 的真伪） | 现有 `tests/test_tls.cpp` 的 `RawServer` 每次只发一个 flight（`tests/test_tls.cpp:181` 的握手循环），从未构造「Finished + 应用数据」同段到达 | 在 `tests/test_tls.cpp` 的 `Loopback` 上加一个用例：`server_.Step()` 之后立刻 `server_.Encrypt(credssp_step2)`，把两段拼成**一个** buffer 喂给 `client_->Handshake`，然后断言 `consumed < in_size` 或断言后续 `Receive` 能拿到那段明文 |
| **U2** | EUAR 的真实字节与是否真无 TPKT | 无正确凭据，从未走到第 5 步之后。规范侧只有字段图 + FreeRDP 旁证（`docs/spec/security-layer.md:1705` 自认 C 级） | 拿到可登录凭据后，在第 5 步 `authInfo` 发出后 dump 服务器→客户端的**第一个**明文块，断言「前 4 字节是 `00 00 00 00` 且总长恰好 4」；再断言紧随其后的 4 字节是 `03 00` |
| **U3** | `pubKeyAuth` v5/6 的拼接顺序（`magic‖nonce‖SPK` vs `SPK‖magic‖nonce`） | 同上，从未收到第 4 步（`docs/spec/security-layer.md:1706`） | 同 U2 的凭据；若第 4 步失败且 `errorCode` 不是凭据类错误，则换另一种顺序重试 |
| **U4** | SChannel 收到 TLS fatal alert 时的具体 `SECURITY_STATUS`，以及 alert 码是否还能取到 | 未构造过「服务器主动发 alert」的场景；现有测试只测了篡改密文（`tests/test_tls.cpp:526`） | 用 `RawServer` 的 `ApplyControlToken` 主动发一个 alert（如 `access_denied`），观察 `client_->Receive` 返回的 `status` 与 `native_code`；若 `native_code` 不含 alert 码，则 S7 的修复方案需改为「从 `SECBUFFER_DATA` 里解析 `15 03 03 00 02`」 |
| **U5** | 真实服务器是否把 EUAR 与 MCS Connect Initial 粘在同一次 `send()` | 未走到该阶段 | 同 U2；抓包看 TCP 段边界，或用 §5.6 的假服务端主动构造该场景验证安全层（这部分**可以**离线验证，与「真实服务器是否这样」是两件事） |
| **U6** | 真实服务器在第 5 步之后是否可能先发 TLS alert 49 再断开（而非发 `errorCode`） | 未用正确/错误凭据分别观察 | 用**错误**密码跑完整五步，dump 服务器在 `authInfo` 之后的原始字节：是 `15 03 03 ...`（alert）还是 `30 ...`（TSRequest with errorCode）。这直接决定 S7 的严重度 |
| **U7** | `TpktStream` 在 TLS 之内是否需要「失步自愈」 | 未在真实 TLS 流上遇到失步 | 一旦 U2 打通，观察 `dropped_bytes()` 是否恒为 0；若恒为 0，则安全层可直接断言 `dropped_bytes()==0` |
| **U8** | 服务器是否接受「EUAR 之后 MCS Connect Initial 与 Attach User 在同一次 `Send`」（S13） | 未联调 | 真机联调时先按「整体一次 `Send`」实现，观察 MCS Connect Response 是否正常；若服务器拒绝再改逐条 |
| **U9** | `CredsspClient` 的 `nonce_` 随机化后，现有 15 个 `credssp_sm` 测试是否全部仍绿 | 未改代码（本轮禁改） | 执行 AI 在修 S1 后跑 `rtsc_credssp_sm_tests`：所有用例都调了 `SetNonceForTest`（`tests/test_credssp_sm.cpp:107` 等），理论上不受影响；但 `step3_authenticate_carries_a_nonzero_mic`（`:179`）依赖「nonce 前 8 字节作为 client challenge」，随机化后仍非零，应仍绿 —— **必须实跑确认** |
| **U10** | 本设计对 `PROTOCOL_SSL`（纯 TLS，无 CredSSP）与 `PROTOCOL_RDSTLS` 的兼容性 | 本轮只针对 `PROTOCOL_HYBRID_EX`；`rdp_neg.h:19` 列出了 6 种协议标志 | 设计上安全层的阶段机是「可裁剪」的（`kCredssp`/`kAwaitEuar` 阶段按 `negotiated_protocol` 跳过），但**未验证**纯 TLS 路径下 `ConnectMachine::OnExternalSecurityComplete()` 的调用时机是否仍然正确（此时无 CredSSP、无 EUAR，TLS 握手完成即可交还）。需要单独一组 T14 用例 |
| **U11** | `SEC_I_INCOMPLETE_CREDENTIALS` 在真实 RDP 服务器上是否会出现 | `docs/spec/security-layer.md:519` 说服务器不请求客户端证书，实测 `No client certificate CA names sent`；但这是 openssl 的观察，SChannel 侧未实测 | 联调时观察是否命中 `src/net/tls_schannel.cpp:179`（锚点 `case SEC_I_CONTINUE_NEEDED`） 分支；若命中，说明 `kUnsupported` 的错误文案需要更明确（「服务器要求客户端证书」而非「不支持」） |
| **U12** | 单条 TLS record 的最大明文（16384）是否足够容纳本项目的 MCS Connect Initial | `src/net/tls_schannel.cpp:48`（锚点 `kMaxRecordPayload`） 的 `kMaxRecordPayload = 16384`；本项目的 Connect Initial 在 `tests/test_connect_machine.cpp` 中约 300-400 字节（`ConnectInitial.bin` 为 416 字节，见 `.tmp` 清单） | 在安全层的 `SendPdu` 里断言 `pdu.size() <= record_sizes().max_plaintext`；若未来加入大量虚拟通道导致超限，需要分片 —— 但 MCS Connect Initial 的 TPKT 长度上限是 65535（`include/rtsc/proto/tpkt.h:15`），两者不匹配，**必须显式处理**。当前通道数（3）下不会触发 |

---

## 9. 与既有 spec 文档的交叉引用索引

| 本文结论 | 对应 spec 章节 | 备注 |
|---|---|---|
| §5.1 时序 | `docs/spec/security-layer.md` §1.1（`:265`） | 一致 |
| §5.3 EUAR 结构 | 同上 §2.3（`:375`） | 一致；本文补充「被 TpktStream 吞掉」这一实现风险 |
| §5.3.5 EUAR 缺失 | 同上 §2.4（`:395`） | spec 未覆盖「HYBRID_EX 但无 EUAR」，本文新增 |
| §5.4 关闭语义 | 同上 §4.5（`:552`） | spec 只说「必须按 TPKT 重组」，本文补充关闭三态 |
| §5.5 错误分类 | 同上 §4.6（`:571`） | spec 只列 alert 码表，本文给出类型设计 |
| §5.6 可测性 | `docs/spec/tls-backend.design-a.md` §3.4.3 | 复用其回环夹具 |
| S10（`consumed` 无条件全消费） | `docs/spec/tls-backend.design-a.md` §3.2.4（`:513`）声称「只丢弃前 `consumed` 字节」 | **与该文档的契约描述不完全一致**：文档要求按 `consumed` 丢弃，实现却恒等于 `in_size`。这是文档与实现的偏差，需实测裁决（U1） |
| S7（无 `kPeerAlert`） | `docs/spec/tls-backend.design-a.md`（`:516`、`:525`）把 `kPeerAlert` 列为 `Handshake`/`Receive` 的终止态 | **实现未兑现**：设计文档有、代码无。属于「设计已定、实现缺失」 |
| S8（证书策略） | `docs/spec/tls-backend.design-a.md`（`:516`）明确 `kCertRejected` 由 DEFERRED 回调产生 | **实现未兑现**：代码用 MANUAL 且无回调 |

---

## 10. 本轮自检

| 检查项 | 结果 |
|---|---|
| 是否修改了任何工程代码 | 否（只写了本文件） |
| 是否在 C 盘创建文件 | 否（所有写入都在 `F:\rtsc`） |
| 是否伪造输出 | 否（文首 4 条测试输出为本轮实跑，命令为 `F:\rtsc\build\verify\rtsc_*_tests.exe`） |
| 代码引用是否都实际读过 | 是（每个 `路径:行号` 均来自本轮 Read/Select-String 输出） |
| 是否有「应该可以」式断言 | 否（未验证项全部进 §8） |
| 方案数 | 3 个（A / B / C），另否决 2 个候选（(b)/(c) 原始形态） |
| 缺陷数 | 17（P0×4，P1×7，P2×6） |

---

## 11. S10 实测裁决（第二阶段，真实 SChannel 回环）

> 探针源码与输出留在 `F:\rtsc\.tmp\probe_s10\`（4 个独立可执行文件，均用 `cl.exe` 单独编译，
> 链接 `secur32.lib crypt32.lib` + `F:\rtsc\build\verify\rtsc_tls.lib`，无 socket、无端口，
> 进程内 SSPI 回环）。输出副本在 `F:\rtsc\evidence\s10\*.out.txt`。
> 构建脚本：`build.bat` / `build_b.bat` / `build_c.bat` / `build_d.bat`。

### 11.1 结论

**S10 成立（CONFIRMED），但成因与我在 §6 的表述相反 —— 必须订正。**

我在 S10 里写的是「忽略输入 buffer 被 SChannel 消费后剩下的 `EXTRA`」，
暗示 SChannel 会**报告** `SECBUFFER_EXTRA` 而我们没读。实测证明：
**SChannel 在流式（`ISC_REQ_STREAM`）模式下根本不报告 EXTRA，也不校验尾随字节。**
它把 `Finished` 之后的字节**静默丢弃**（更准确地说：静默忽略、不消费、不报错、不回吐）。
于是 `consumed = in_size`（`src/net/tls_schannel.cpp:169`（锚点 `consumed = in_size;`））**多报了**消费量，
调用方按契约丢掉尾部 → 应用数据永久丢失。

**两种表述的工程后果不同，修复方案也不同**：
- 若「SChannel 报 EXTRA 而我们没读」→ 修法是读 `in_bufs[0].cbBuffer` 算真实消费量。
- 若「SChannel 不报也不校验」→ 读 `cbBuffer` **毫无用处**（实测 98→98 不变），
  必须**自己按 TLS record 头预切片**，让每次 `Handshake` 调用最多只覆盖一条 record。

实测支持后者。这是本轮最重要的订正。

### 11.2 关键数字（逐条可复现）

| 编号 | 测量 | 结果 | 输出文件 |
|---|---|---|---|
| **M5** | 控制组：`Handshake(finished 51B)` 后 `Receive(app 47B)` | `status=kOk, consumed=51, complete=1`；`Receive` 解出 18 字节 `"S10-PAYLOAD-MARKER"` → **正常路径 WORKS** | `probe_s10.out.txt` |
| **M3** | `Handshake(combined 98B)`（=51B Finished + 47B app） | `status=kOk(0), consumed=98/98, handshake_complete=1, out=0` → **消费量多报 47 字节** | `probe_s10.out.txt` |
| **M4** | 紧接 M3 调 `Receive(nullptr,0)`（履行 `tls.h:157` 的排空义务） | `status=kNeedMoreInput(1), plaintext=0, buffered_input=0` → **传输层自己一个字节也没留** | `probe_s10.out.txt` |
| **M8** | 同上，循环 8 轮排空 | `total recovered = 0 bytes` → **app data LOST** | `probe_s10b.out.txt` |
| **M1** | 裸 SSPI：`ISC(combined 98B)` 后读 `in_bufs[0].cbBuffer` | `0x00000000`；`cbBuffer: before=98 after=98`（**不变**）→ **SSPI 不报 EXTRA** | `probe_s10.out.txt` |
| **M2** | 裸 SSPI：对同一上下文的 47B 尾部单独 `DecryptMessage` | `0x00000000`, 18 字节, `match=1` → **尾部从未被 ISC 处理过**，仍是原始密文 | `probe_s10.out.txt` |
| **M7** | `ISC(finished 51B + 20 字节 0xAA 垃圾)` | `0x00000000`；`cbBuffer 71→71` → **尾随垃圾被静默忽略，无任何校验** | `probe_s10b.out.txt` |
| **M6** | 按 5 字节 record 头预切片，逐 record 喂 | 3 条 record：`[20 CCS len=6] [22 Handshake len=45] [23 AppData len=47]`；喂完第 2 条即 `0x00000000` → **握手边界恰为 51 字节**；剩余 47B 可解密 | `probe_s10b.out.txt` |
| **F1/F2** | 把 M6 的切片器套在**真实 `TlsTransport`** 上 | `used=51/98`（**精确**），`remaining=47`；随后 `Receive(tail)` 解出 `"S10-PAYLOAD-MARKER"` → **修复有效** | `probe_s10d.out.txt` |
| **F3** | 同一 98B 逐字节喂（`size=1`） | `used=51`, `remaining=47`, 解密成功 → **流式输入下仍精确** | `probe_s10d.out.txt` |
| **F4** | 切片器 + 正常分开发送 | `used=51, complete=1, remaining=0`；后续 `Receive` 成功 → **不破坏正常路径** | `probe_s10d.out.txt` |

### 11.3 真实 RDP 流程下 S10 的可达性（必须如实说明）

S10 在**协议层**是真的，但在**当前 RDP 时序**下**不可达**，原因：
`docs/spec/security-layer.md:280-281` 规定 TLS 握手完成后**客户端先发** `TSRequest(step1)`，
服务器才回 `step2`。服务器不会在 `Finished` 之后立刻塞应用数据。

因此 S10 的**真实严重度应从 P1 下调为 P2**（防御性），但**仍必须修**，因为：
1. **TLS 1.3 的 `NewSessionTicket` 会紧跟服务器 `Finished`**，中间无客户端消息。
   若票据与 `Finished` 合段，尾部会被吞。RDP 不使用会话恢复（`docs/spec/security-layer.md:520`），
   所以**丢票据无功能影响**，但会让 `consumed` 长期多报 —— 掩盖真实 bug。
2. 服务器实现可以合法地把「`Finished` + 任意 post-handshake 消息」合并写入；
   客户端不能假设对端时序。
3. 修复成本极低（F1/F4 已证明），且**顺带解决**一个更严重的问题：见 §11.4 的 S19。

### 11.4 本轮探针的额外发现（新增缺陷）

| 编号 | 症状 | 证据 | 影响 | 建议 |
|---|---|---|---|---|
| **S18** | **生产路径永远拿不到服务器公钥**：`server_public_key_` 的唯一写入点是测试钩子 | `include/rtsc/credssp/credssp.h:61`（`SetServerPublicKeyForTest` 是唯一赋值点）；全仓 grep `PeerSubjectPublicKey` 只命中 `src/net/tls_schannel.cpp:348`（锚点 `PeerSubjectPublicKey`）（定义）、`tests/test_tls.cpp:826`（测试）；`src/credssp/credssp.cpp:232/267` 直接使用空的 `server_public_key_` | **P0**。`pubKeyAuth = SHA256(magic‖nonce‖"")`，CredSSP 唯一的 MITM 防护失效；服务器若校验则第 4 步必失败，若不校验则**静默失去防护**（比失败更糟） | `SecurityLayer` 在 TLS 握手完成后必须 `tls.PeerSubjectPublicKey(spk)` → `credssp.SetServerPublicKey(spk)`；`CredsspClient` 需要**生产用** setter（不能只留 `ForTest`），并对空公钥 `Fail(kUnsupported, "server public key unavailable")` |
| **S19** | **`min_version=0x0304`（只要 TLS 1.3）时 `CreateTlsTransport` 直接失败** | `src/net/tls_schannel.cpp:464-478`（锚点 `DWORD ProtocolMask() const`） 的 `ProtocolMask()`：`min_version=0x0304` 使 `:467` 的 `min_version <= kTls12` 为假 → 只置 `SP_PROT_TLS1_3_CLIENT` → `AcquireCredentialsHandle` 返回 `0x80090331`（`SEC_E_ALGORITHM_MISMATCH`）。实测：`tls13check2.exe` 输出 `cli TLS1_3 only -> 0x80090331 FAIL`；`cli 1_2|1_3 -> 0x00000000 OK` | **P2**。`Config::min_version` 这个旋钮在「只要 1.3」时不生效，且失败信息是「算法不匹配」，与「版本窗口」无关，误导排查。现有测试 `tests/test_tls.cpp:879-885` 用「`!started` 也算通过」把它掩盖了 | `ProtocolMask()` 在只请求 1.3 时补上 `SP_PROT_TLS1_2_CLIENT`（SChannel 不支持 1.3-only 凭据），再由 `EnforceVersionWindow()`（`:568`）做真实窗口校验；测试改为断言「要么成功且协商到 1.3，要么给出明确原因」，不接受「静默降级到 1.2 却报成功」 |

**缺陷总数更新：17 → 19 条（P0 × 5，P1 × 7，P2 × 7）。**

> 诚实说明：S18 是乙（`audit-b.md`）的 B01，我第一版**漏了**；
> S19 是本轮探针新发现，甲乙双方此前都没有。
> S10 的成因表述在 §6 里是错的，已在 §11.1 订正（严重度 P1 → P2，机制从「漏读 EXTRA」改为「SChannel 不报也不校验，必须自行切片」）。

---

## 12. 交叉预判（供磋商）

> 本章只给判断与证据，不改代码。凡与乙（`security-integration.audit-b.md`）不一致处，明确写出分歧点与裁决理由。

### 12.1 (a) CMake 依赖图：`rtsc_proto` 是否会被污染

**先承认我第一版的遗漏**：我在 §5.1 只论证了「`rtsc_proto` 不应依赖 `rtsc_tls`」这个**方向**，
却**没有检查 `rtsc_tls` 自己能不能在 Linux 上编译**。乙的 B19 是对的，我复核如下：

| 事实 | 证据 |
|---|---|
| `tls_schannel.cpp` 无条件 `#include <windows.h>` / `<schannel.h>` / `<sspi.h>` / `<wincrypt.h>` | `src/net/tls_schannel.cpp:29-32`（锚点 `#include <windows.h>` .. `#include <wincrypt.h>`） |
| 全文件 `#if` / `#ifdef` / `#ifndef` 计数 = **0 / 0 / 0**（本轮实测） | `Select-String` 于 `src/net/tls_schannel.cpp` |
| `add_library(rtsc_tls STATIC src/net/tls_schannel.cpp)` **无条件** | `CMakeLists.txt:51` |
| `if(WIN32)` 只包住链接库 | `CMakeLists.txt:53-55` |
| 但**接口头是平台中立的**（只含 7 个 std 头，无 Windows 类型） | `include/rtsc/net/tls.h:26-32` |

**裁决：B19 是独立缺陷，同时是方案 B「跨平台」主张的前置条件。**

- **它是独立缺陷**：`rtsc_tls` 这个 target 在非 Windows 上必然编译失败，与我的设计无关，
  是既有代码的状态。按项目「C++20 跨平台」的定位，这本身就是 bug。
- **它是方案 B 的前置条件（仅限跨平台主张）**：方案 B 在 **Windows 上正确性不受影响**；
  但若要把 `SecurityLayer` 做成跨平台可编译，就必须先修 B19。

**我推荐的 CMake 依赖图（三层拆分，无环）**

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

**无环证明**（依赖边方向）：

```
rtsc_crypto  <-  rtsc_proto      <-  rtsc_security
rtsc_crypto  <-  rtsc_credssp    <-  rtsc_security
rtsc_tls_api <-  rtsc_tls        <-  rtsc_security
```

- `rtsc_proto` 的出边只有 `rtsc_crypto`（`CMakeLists.txt:36`）—— **不新增任何出边**。
- `rtsc_security` 是唯一的汇合点，**只进不出**（没有别的 target 依赖它）。
- `rtsc_tls` 不依赖 `rtsc_proto`（现在也不依赖，`CMakeLists.txt:51-55` 只有系统库）。
- 无环。

**Linux 上 `rtsc_proto` 仍能编译**：因为 `rtsc_proto` 的编译单元一个都不 `#include` `rtsc/net/tls.h`
（本轮 grep：`src/proto/**` 无 `tls.h` 引用），其依赖闭包只有 `rtsc_crypto`。
方案 B 的 `SecurityLayer` 在 `rtsc_security`，**不进入** `rtsc_proto` 的闭包。
Linux 上 `rtsc_security` 也能编译（`rtsc_tls` 退化为「无后端」），
`SecurityLayer::Create()` 返回 `kUnsupported` + `detail="no TLS backend for this platform"` ——
这是**运行期**不可用，不是编译期失败。

**是否要把 `#ifdef _WIN32` 加进 `tls_schannel.cpp`？** 不必。按上面第 (2) 项，
该文件只在 `if(WIN32)` 分支里参与编译，源文件里不需要任何平台守卫。
加 `#ifdef` 反而会造出「一个空 TU 的静态库」这种隐性失败。
→ **推荐 CMake 条件编译，不推荐源文件 `#ifdef`。**

### 12.2 (b) `OnExternalSecurityComplete()` 的签名缺口

乙认为它「无输入、不返回还要读几字节」是缺口。**我的判断：成功路径上不是缺口；失败路径上确实缺一个入口。**

**为什么成功路径不需要参数（关键不变量）**

> **调用 `OnExternalSecurityComplete()` 的那一刻，安全层的明文缓冲必然为空。**

证明（三段，全部有据）：
1. CredSSP 第 5 步是**客户端发出的最后一条** CredSSP 消息（`docs/spec/security-layer.md:675`），
   发出前第 4 步的完整 TSRequest 已被消费（`src/credssp/credssp.cpp:252-307`）。
2. EUAR 是服务器紧接着发的**唯一**内容，且 `MUST be sent before any post-handshake PDUs`
   （`docs/spec/security-layer.md:365-366`、`:369-370`）—— 已被 `kAwaitEuar` 恰取 4 字节。
3. 其后的 `MCS Connect Response` **必须**等客户端先发 `MCS Connect Initial`
   （`docs/spec/security-layer.md:290-291` 的箭头方向）。服务器不可能抢跑。

∴ 交还控制权时 `plain_` 为空，**没有任何字节需要交接**。签名无输入是**正确的最小接口**，不是缺口。

**真正缺的是失败入口**：现在安全层失败后，`ConnectMachine` 只能被丢弃，
`state_.error` 永远是空的（`include/rtsc/proto/connect_machine.h:57` 只在 `Fail()` 里写，
而 `Fail()` 只有 `OnData` 路径会调）。这与我的 S12（错误阶段静默 no-op）是同一处病灶。

**建议（P2，不阻塞）**：加一个 `void OnExternalSecurityFailed(const char* reason)`，
只做 `Fail(reason)`；或者接受「丢弃对象」的语义，但必须在 `connect_machine.h` 注释里写明。
**不建议**改 `OnExternalSecurityComplete()` 的签名 —— 那会把「不需要的信息」塞进接口，
违反最小接口原则，且会诱导实现去处理一个恒为空的缓冲区。

### 12.3 (c) 密码双份持有（C9 / D1）

**我的判断：乙指出的风险成立，属真实缺陷（P1）；但「违反 C9」的表述不准确，需要修正依据。**

**先修正依据**：C9 是 `[MS-CSSP] 3.1.1 Abstract Data Model`（`docs/spec/security-layer.md:96`），
它是**协议层的数据模型**（CredSSP 客户端持有哪些状态），**不是代码架构规则**。
把它当成「同一数据必须单一权威写者」的依据是**类比**，不是原文。
真正站得住的依据有两条，都更硬：
1. **两个 `password` 语义不同**（这是协议事实，不是风格问题）：
   `ConnectMachine::Credentials::password` → `TS_INFO_PACKET.Password`（`src/proto/connect_machine.cpp:168`）；
   `credssp::Credentials::password` → `TSPasswordCreds.password`（`src/credssp/credssp.cpp:287-290`）。
   规范里这是**两个不同的字段**，出现在**两个不同的阶段**，用途不同。
2. **当前实现无条件回填**：`src/proto/connect_machine.cpp:168` 在 `SendChannelJoin()` 里
   **不按协商结果分支**（对比 `:155` 的 `kProtocolRdp` 分支是有的）。

**规范/实测支持「NLA 下该为空」**：
- `TS_INFO_PACKET.Password` 只在 `INFO_AUTOLOGON` 置位时有意义
  （`docs/spec/mcs-domain.md:1132`），而 `autologon` 默认 `false`
  （`include/rtsc/proto/connect_machine.h:101`）。
- 权威样例里该字段就是空的：`docs/spec/mcs-domain.md:2057`（`cbPassword = 0 bytes`）、
  `:2064`（`Password = ""`）—— 而同一 dump 的 Domain/UserName 是填了的。
- 也就是说：**默认配置下我们发的是一个规范样例里为空的字段的非空值**。

**我同意乙的三条建议中的两条半**：
- ✅ 单一权威载体（`struct UserCredential`，由编排层注入两份引用）—— 这是接入层必须定的契约，
  否则「两个 password 是否同源」只能靠调用方自觉。
- ✅ NLA 下 `pdu.info.password.clear()` 且 `autologon=false`。
- ⚠️ 「析构清零」我**同意但降级为 P2**：它不解决「两份」的问题，只缩小窗口；
  且 `std::string` 的 SSO 拷贝无法可靠清零（栈上残留）。真正的修法是**减少份数**，不是清零。
- ❌ 「把 Client Info 的改名为 `client_info_password`」—— 改名不改变语义，只是让不一致更显眼；
  单一权威 + NLA 置空已经消除了不一致的可能，改名是冗余动作。

**与我的 17 条的对应关系**：我第一版**没有**这条（属遗漏）。它与我的 S18（公钥拿不到）
同属「接入层没把两条已有的线接起来」这一类，但性质不同：S18 是**功能缺失**，这条是**暴露面/语义混淆**。
→ 新增为 **S20**（P1）。缺陷总数 **19 → 20**（P0 × 5，P1 × 8，P2 × 7）。

| 编号 | 症状 | 证据 | 影响 | 建议 |
|---|---|---|---|---|
| **S20** | **口令两份、同名不同义、无条件回填 Client Info** | `include/rtsc/proto/connect_machine.h:98` vs `include/rtsc/credssp/credssp.h:26`（两个独立 `std::string password`）；`src/proto/connect_machine.cpp:168` 无条件 `pdu.info.password = credentials_.password`（对比 `:155` 有协议分支）；`docs/spec/mcs-domain.md:1132`（仅 `INFO_AUTOLOGON` 时有效）、`:2057`/`:2064`（权威样例为空）、`include/rtsc/proto/connect_machine.h:101`（`autologon` 默认 false）；全仓 grep `SecureZeroMemory|memset_s|ZeroMemory|explicit_bzero` → 0 命中 | **P1**。同一凭据在同一条 TLS 通道内被发两次（一次 SEAL、一次明文），暴露面翻倍；默认配置下发送一个规范样例中为空的字段的非空值。是否触发二次登录尝试**未实测**（见 U13） | 引入 `rtsc::sec::UserCredential` 作唯一载体；`SendChannelJoin()` 按 `negotiated_protocol` 分支，非 `kProtocolRdp` 时清空 password 且不置 `INFO_AUTOLOGON`；把 `Utf16Le` 中间缓冲纳入清零范围（P2） |

### 12.4 裁决 1：`SecurityLayer` 放在哪个库

**放在新库 `rtsc_security`（`src/sec/`），依赖 `rtsc_tls` + `rtsc_credssp` + `rtsc_proto`。**
依赖图与无环证明见 §12.1。要点复述：
- `rtsc_proto` 的出边**保持只有** `rtsc_crypto`（`CMakeLists.txt:36`），不新增。
- `rtsc_security` 是汇合点，只进不出。
- Linux 上 `rtsc_proto` 编译不受影响（`src/proto/**` 不引用 `tls.h`，本轮 grep 确认）。
- Linux 上 `rtsc_security` 也能编译，`Create()` 返回 `kUnsupported`（运行期不可用，非编译失败）——
  前提是先修 B19（§12.1 的三层拆分）。

**方案 B 是否满足 (a)？** —— **满足**，条件是 `SecurityLayer` 不进 `rtsc_proto`（本方案正是如此）。
但**方案 B 自身不能修好 B19**；B19 必须单独修。二者关系：B19 是独立缺陷 + 方案 B 跨平台主张的前置条件。

### 12.5 裁决 2：B01 / B02 是否在我的清单里

| 乙的编号 | 内容 | 我第一版 | 处置 |
|---|---|---|---|
| **B02** | nonce 生产路径拿不到随机数 | **有**，我的 **S1**（P0） | 保留 |
| **B01** | 生产路径拿不到服务器公钥 | **漏了** | 新增 **S18**（P0），见 §11.4 |

**为什么漏**：我检查了 `CredsspClient` 内部对 `server_public_key_` 的**使用**
（`src/credssp/credssp.cpp:232`、`:267`、`:369`），
也在 §5.6 的可测性里写了「假传输返回固定 SPKI」，
但**没有反向检查「谁在生产路径上写它」**。这是一次真实的审计疏漏，不是范围问题——
它就在「接入」的正中心：安全层必须把 `tls.PeerSubjectPublicKey()` 接到
`CredsspClient::SetServerPublicKey()` 上，而后者目前**只以 `ForTest` 形式存在**。
把它说成「范围之外」是不诚实的；正确说法是**我漏了**。

### 12.6 裁决 3：EUAR 在哪一层消费（唯一结论）

**结论：EUAR 必须在 `SecurityLayer` 消费（`kAwaitEuar` 阶段），`ConnectMachine` 完全无感。
不新增 `ConnectPhase::kAwaitEarlyUserAuth`，不改 `connect_machine.h`。**

**理由 1（决定性）：EUAR 的字节边界只有安全层知道，所以安全层无论如何都要有这个阶段。**
「哪 4 个字节是 EUAR」取决于「CredSSP 最后一条消息在明文流的哪个字节结束」。
只有安全层持有 `plain_` 与 `phase_`（§3.1）。
所以即便采用乙的方案，安全层仍必须有一个 `kAwaitEuar` 阶段来**停在正确的偏移**，
再把那 4 字节**上抛**给 proto。
→ 乙的方案不是「把 EUAR 移到 proto」，而是「安全层算边界 + proto 做解释」，
即**两个对象都知道 EUAR 的存在**。这正好是我在 §3.1 论证要避免的 split-brain：
「谁决定消费几个字节」与「谁解释这几个字节」被拆开了。

**理由 2：proto 的输入契约根本装不下 EUAR。**
`ConnectMachine::OnData` 要求**完整 TPKT 帧**：
`src/proto/connect_machine.cpp:196` → `src/proto/connection_initiation.cpp:55-58`；
MCS 侧 `src/proto/mcs.cpp:128`、`src/proto/mcs_domain.cpp:67` 都要求 `tpkt.length == size`。
4 字节 `00 00 00 00` 喂进去，`TpktHeader::parse` 在 `src/proto/tpkt.cpp:7` 就返回 `InvalidVersion`。
→ 乙必须新增**第二个输入入口** `OnEarlyUserAuthResult(uint32_t)`，
于是 `ConnectMachine` 有了两套不同分帧规则的输入 API，
调用方必须自己判断「现在该调哪个」—— 这正是方案 A 被我列为缺点、方案 B 用 `Want` 消除的问题，
只是被下推到了 proto 层。

**理由 3：功能上不需要 proto 知道。**
授权被拒时的正确行为是「**不发** MCS Connect Initial」（`docs/spec/security-layer.md:400`）。
安全层返回 `kAuthorizationDenied` 后，调用方**不调用** `OnExternalSecurityComplete()` 即可，
`ConnectMachine` 停在 `kAwaitExternalSecurity`（`src/proto/connect_machine.cpp:217`）后被销毁。
对外可观测行为与乙的方案**完全相同**：没有 MCS 发出。
而诊断信息反而**更强**：调用方手里的 `SecurityError{kind=kAuthorizationDenied, native_space=kCredsspErrorCode, native_code=0x00000005}`
比 `ConnectState` 的一个 `uint32_t` 信息量大。

**理由 4：保持 `rtsc_proto` 的既有定位。**
`include/rtsc/proto/connect_machine.h:19-21` 明确写「Crypto (TLS, CredSSP, RC4) is deliberately outside」。
EUAR 是 `PROTOCOL_HYBRID_EX` 的产物，属于外部安全协商的一部分
（`docs/spec/security-layer.md:347` 把它定义在 `PROTOCOL_HYBRID_EX` 这个安全标志下）。
把它放进 proto 会破坏这条边界。

**乙的诊断对、药方错**：
乙说「security 层不能吞那 4 字节」——**这句必须反驳**。
安全层**不是「吞」**，而是**解释并上报**：
`Output.euar_consumed=true` + `Output.euar_result=0x00000005` +
`error.kind=kAuthorizationDenied`。这三样都在 `Step()` 的返回值里，**完全可观测**。
真正的「吞」是 `TpktStream` 在 `src/proto/framing.cpp:52` 的 `dropped_ += skipped` —— 那是**静默**丢弃，无任何上报。
我的 S2 针对的正是后者。所以「透传给 proto」与「安全层解释」的区别不是「吞不吞」，
而是「谁解释」；而按理由 1，边界计算已经在安全层，再拆解释权只会多一处状态。

**正面回答「矛盾怎么解」**：
- 若在 security 层消费 → 不存在矛盾。`TpktStream` 只从 `plain_` 的**剩余部分**开始
  （`plain_` 已 `remove_prefix(4)`），永远看不到那 4 字节，`dropped_bytes()` 恒为 0。
- 若在 proto 层消费 → 矛盾**无法解**：安全层若把 4 字节放进 `pdus`，它就不是 TPKT 帧，
  调用方或 `TpktStream` 会丢弃（`framing.cpp:52`）；若放进第二通道，
  等于把「解释权」和「边界权」拆开（理由 1）。**这就是我选 security 层的根本原因。**

---

## 13. 方案 B 接口草案

> 本章是**头文件级声明 + 契约注释**，不是实现，也不进入构建。
> 目的：把 §12.6 的三个待定问题（`want` 如何表达并发读写、EUAR 与 MCS 同 record 的切分点、
> `kClosed` + 剩余明文的返回值）落成可编译的形状。
> 全部声明都以现有接口为基（`include/rtsc/net/tls.h:124-188`、`include/rtsc/credssp/credssp.h:40-72`、
> `include/rtsc/proto/connect_machine.h:104-119`），不臆造新能力。

### 13.1 `include/rtsc/sec/security_error.h`

```cpp
// Unified error surface for the external security layer.
//
// Reference: docs/spec/security-integration.audit-a.md sections 5.5 and 13.
//
// Design rules (both are load-bearing):
//   1. native_code is copied bit-for-bit from the originating library and is
//      never re-encoded. `space` says which library it came from, because the
//      same int32_t means different things in each (tls.h:59 vs ts_request.h:34).
//   2. `detail` is for humans only. No control flow may branch on it.
//      ConnectMachine::state_.error is a std::string (connect_machine.h:57);
//      that is exactly why it must not be used for classification.
#pragma once

#include <cstdint>
#include <string>

namespace rtsc::sec {

// Where the failure happened. Chosen so that every error has exactly one stage.
enum class Stage : uint8_t {
    kTlsHandshake = 0,  // TlsTransport::Handshake
    kCredssp,           // CredsspClient::Start / OnServerResponse
    kEuar,              // the 4-byte Early User Authorization Result
    kTlsIo,             // TlsTransport::Receive / Send
    kClose,             // shutdown / drain
};

// Semantic class. Upper layers switch on this, never on `detail`.
enum class Kind : uint8_t {
    kNone = 0,
    kWouldBlock,           // not an error: more input is needed
    kCertificateRejected,  // local policy rejected the peer certificate
    kCredentialRejected,   // wrong user/password (NTSTATUS or TLS alert 49)
    kAuthorizationDenied,  // EUAR 0x05, or STATUS_LOGON_TYPE_NOT_GRANTED
    kProtocolViolation,    // peer violated the protocol
    kUnsupported,          // this build/platform cannot serve the request
    kInternal,             // local bug or environment failure
    kClosedByPeer,         // clean close, everything drained
    kTruncated,            // peer closed mid-unit (半帧)
};

// Namespace of `native_code`. Without this the code is ambiguous.
enum class Space : uint8_t {
    kNone = 0,
    kSspi,      // SECURITY_STATUS from SChannel (tls.h:59)
    kNtstatus,  // CredSSP errorCode field (credssp.cpp:101)
    kTlsAlert,  // TLS alert description byte (tls.h:42)
    kWin32,     // GetLastError
    kLocal,     // produced by this layer (no external code)
};

struct Error {
    Kind kind = Kind::kNone;
    Stage stage = Stage::kTlsHandshake;
    Space space = Space::kNone;
    int32_t native_code = 0;   // verbatim; never remapped
    std::string detail;        // human readable; never drives control flow

    bool ok() const noexcept { return kind == Kind::kNone; }
    // True when the connection must be dropped. kWouldBlock/kClosedByPeer are not.
    bool fatal() const noexcept {
        return kind != Kind::kNone && kind != Kind::kWouldBlock &&
               kind != Kind::kClosedByPeer;
    }
};

}  // namespace rtsc::sec
```

### 13.2 `include/rtsc/sec/security_layer.h`

```cpp
// External security layer: TLS handshake -> CredSSP five steps -> EUAR -> MCS.
//
// Reference: docs/spec/security-integration.audit-a.md sections 3, 4 (plan B),
// 5.3 (EUAR), 5.4 (close semantics), 13.
//
// WHY THIS CLASS EXISTS
//   The plaintext stream is cut by four different rules in sequence
//   (TLS record / DER TSRequest / fixed 4-byte EUAR / TPKT). The rule in force
//   is a function of the phase, so the phase and the plaintext buffer MUST have
//   the same owner. That is the whole reason this class is not just a bag of
//   helpers. See audit-a section 3.1.
//
// THREADING
//   Not thread safe. One instance, one thread, one connection.
//
// LIFETIME
//   Created AFTER ConnectMachine::OnData(CCF) has returned
//   phase == kAwaitExternalSecurity (connect_machine.cpp:217). The plaintext
//   X.224 exchange before that point is NOT this class's responsibility.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "rtsc/credssp/credssp.h"
#include "rtsc/net/tls.h"
#include "rtsc/proto/framing.h"
#include "rtsc/sec/security_error.h"

namespace rtsc::sec {

using Bytes = std::vector<uint8_t>;

struct Config {
    // ---- TLS ----
    std::string peer_host;
    std::string sni;
    rtsc::tls::CertPolicy cert_policy = rtsc::tls::CertPolicy::kTofu;
    uint16_t min_version = 0x0302;  // TLS1.2
    uint16_t max_version = 0x0304;  // TLS1.3
    std::array<uint8_t, 32> pinned_spki_sha256{};
    bool pin_is_set = false;

    // ---- CredSSP ----
    credssp::Credentials credentials;
    uint32_t credssp_version = credssp::kMaxVersion;

    // ---- EUAR ----
    // True when RDP_NEG_RSP.selectedProtocol has PROTOCOL_HYBRID_EX (0x08).
    // Set by the caller from ConnectState::negotiated_protocol
    // (connect_machine.h:46). When false the kAwaitEuar phase is skipped
    // entirely, which is what PROTOCOL_SSL / PROTOCOL_HYBRID need.
    bool expect_euar = false;

    // Escape hatch for non-Microsoft servers that omit the EUAR despite
    // negotiating HYBRID_EX. Default false: the spec says MUST
    // (security-layer.md:365-366), so tolerating it silently would turn a
    // server bug into "randomly cannot connect".
    bool euar_optional = false;

    // ---- limits ----
    // Upper bound for the DER frame we are willing to accumulate. A real
    // TSRequest is a few hundred bytes; 64 KiB is far above anything legal
    // while still bounding memory against a hostile peer.
    size_t max_ts_request = 65536;
    // Upper bound for the plaintext accumulation buffer (EUAR + TPKT).
    size_t max_plaintext_buffer = 1u << 20;
};

// What the caller should do next. This is the contract that replaces the
// implicit "call the right method at the right time" of a two-entry design.
enum class Want : uint8_t {
    // Call Step({kNone}) again with no new bytes. Produced when the layer still
    // has work buffered (a complete PDU, a pending drain).
    kPump = 0,
    // Write `to_wire` to the socket (if non-empty), then call Step with more
    // ciphertext. `to_wire` is cleared when handed out, so forgetting to write
    // it stalls the connection instead of duplicating bytes.
    kWrite,
    // Read more bytes from the socket and feed them as {kCiphertext}.
    kRead,
    // Everything done. No further calls are valid.
    kDone,
    // Terminal failure; `error` says why. No further calls are valid.
    kFail,
};

struct Input {
    enum class Kind : uint8_t { kNone, kCiphertext, kPdu };
    Kind kind = Kind::kNone;
    const uint8_t* data = nullptr;
    size_t size = 0;

    static Input None() { return {}; }
    static Input Ciphertext(const uint8_t* p, size_t n) {
        return {Kind::kCiphertext, p, n};
    }
    static Input Pdu(const uint8_t* p, size_t n) { return {Kind::kPdu, p, n}; }
};

struct Output {
    // Ciphertext to put on the wire. Valid when want == kWrite.
    // Handed out once: the internal copy is cleared on return.
    Bytes to_wire;

    // Complete TPKT frames, 4-byte header INCLUDED, in arrival order.
    // Header included because ConnectMachine::OnData requires it
    // (connect_machine.cpp:196 -> connection_initiation.cpp:55-58) while
    // TpktStream::Next strips it (framing.cpp:86). The layer re-wraps with
    // WrapTpkt (framing.cpp:99) so the boundary stays visible here.
    std::vector<Bytes> pdus;

    // Set exactly once, on the Step that crosses the EUAR. Absent otherwise.
    // Present == consumed and interpreted; the 4 bytes are NOT in `pdus`.
    std::optional<uint32_t> euar_result;

    Want want = Want::kRead;
    Error error;
};

// Human readable phase, for logs and tests. Never drives control flow.
enum class Phase : uint8_t {
    kNotStarted = 0,
    kTlsHandshake,
    kCredssp,
    kAwaitEuar,
    kMcs,
    kDraining,
    kClosed,
    kFailed,
};

const char* to_string(Phase p);

class SecurityLayer {
public:
    // Creates the TLS backend and prepares the CredSSP client. Does not touch
    // the network. Returns nullptr on configuration/backend failure and fills
    // `error` (kind == kUnsupported or kInternal).
    static std::unique_ptr<SecurityLayer> Create(const Config& config, Error& error);

    // Injection point for tests: takes ownership of a scripted transport.
    // `config.expect_euar` / `credentials` are still honoured.
    static std::unique_ptr<SecurityLayer> CreateWithTransport(
        const Config& config, std::unique_ptr<rtsc::tls::TlsTransport> transport,
        Error& error);

    ~SecurityLayer();
    SecurityLayer(const SecurityLayer&) = delete;
    SecurityLayer& operator=(const SecurityLayer&) = delete;

    // ------------------------------------------------------------------ drive
    //
    // Single entry point. Pure and re-entrant: no blocking, no threads, no
    // sleeping. All state lives in the instance.
    //
    // PRECONDITION
    //   * want != kDone && want != kFail on the previous call.
    //   * in.kind == kCiphertext requires in.data != nullptr && in.size > 0.
    //   * in.kind == kPdu is only valid once `complete()` is true; before that
    //     it returns kProtocolViolation (sending an MCS PDU before the security
    //     handshake is a caller bug).
    //
    // POSTCONDITION
    //   * out.want is always one of the five values.
    //   * out.want == kWrite implies out.to_wire is non-empty.
    //   * out.want == kRead implies out.to_wire is empty and the layer has
    //     absorbed all of `in` (nothing is silently dropped).
    //   * out.want == kFail implies out.error.fatal() and `phase()==kFailed`;
    //     every later call returns the same error without touching state
    //     (mirrors the TLS latch, tls.h:40-42).
    //   * out.pdus and out.to_wire are fresh vectors on every call; nothing is
    //     carried over except what is explicitly documented.
    //   * in.size bytes are either consumed, or accounted for in an internal
    //     buffer whose size is observable through buffered_ciphertext().
    Output Step(const Input& in);

    // ------------------------------------------------------------------ state
    bool complete() const noexcept;   // phase() == kMcs
    bool closed() const noexcept;     // phase() == kClosed
    Phase phase() const noexcept;
    const Error& last_error() const noexcept;

    // Ciphertext held because it did not form a whole TLS record yet.
    // Mirrors TlsTransport::buffered_input (tls.h:185) plus our own pre-slice.
    size_t buffered_ciphertext() const noexcept;
    // Plaintext held because it did not form a whole unit yet (半帧 / 半个
    // TSRequest). Zero is the normal steady state between units.
    size_t buffered_plaintext() const noexcept;

    // Negotiated TLS parameters, for logging/telemetry. Only valid after the
    // handshake completed.
    bool negotiated(rtsc::tls::NegotiatedInfo& out) const;

private:
    SecurityLayer(const Config& config, std::unique_ptr<rtsc::tls::TlsTransport> tls);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rtsc::sec
```

### 13.3 三个待定问题的正面回答

#### 13.3.1 「TLS 握手期需要同时写出且继续读」—— `want` 如何表达

这是我在 §4 说「没有红证」的那一点。实测（§11.2 的 M5/M3 输出）给出了确切形状：

```
client ISC #1 -> kNeedMoreInput, out=165      <- 有字节要写，同时还没握手完
server ASC #1 -> SEC_I_CONTINUE_NEEDED, out=782
client ISC #2 -> status=kNeedMoreInput, out=158 <- 又是「要写 + 没完」
server ASC #2 -> SEC_E_OK, out=51
client ISC #3 -> status=kOk, complete=1, out=0  <- 完成，无输出
```

**关键事实：`TlsTransport::Handshake` 每次调用要么产出 `out` 要么不产出，
而「是否完成」由 `handshake_complete()` 单独给出（`include/rtsc/net/tls.h:183`）。
两者正交。** 所以「同时要写且要继续读」不是矛盾，而是**一个 `Want` 装不下两个维度**的问题。

三种表达方式，我选第三种：

| 表达 | 形状 | 评价 |
|---|---|---|
| (i) `want=kWrite`，写完再调 `Step({kNone})` 拿 `kRead` | 两拍 | **推荐**。`to_wire` 交出即清空，忘记写只会卡住不会重发；且 `Step({kNone})` 是幂等的（没有新字节时只推进内部缓冲） |
| (ii) 位掩码 `want = kWrite\|kRead` | 一拍 | 调用方必须自己决定「先写还是先读」，把顺序判断又推回调用方 —— 正是方案 A 的缺点 |
| (iii) 让 `Step` 自己 loop 直到 `to_wire` 非空**且**需要输入 | 一拍 | 隐藏了「必须先写出去对端才会回」的因果，且无法表达「写失败」 |

**所以 `kWrite` 与 `kRead` 是互斥的、按拍推进的**，`kPump` 是第三拍（内部还有活）。

具体到握手期的时序（`Step` 内部行为，写在契约里）：

```
Step({kNone})                      -> want=kWrite, to_wire=ClientHello(165B)
  [调用方写出 165B]
Step({kNone})                      -> want=kRead                 <- 无新字节，内部无活
  [调用方 recv 782B]
Step({kCiphertext, 782B})          -> want=kWrite, to_wire=158B  <- 逐 record 喂完
  [调用方写出 158B]
Step({kNone})                      -> want=kRead
  [调用方 recv 51B]
Step({kCiphertext, 51B})           -> want=kWrite, to_wire=<TSRequest step1>
  [调用方写出]
Step({kNone})                      -> want=kRead                 <- 等 step2
```

**为什么必须是两拍而不是一拍**：`Step` 不阻塞（契约第 2 条），
所以它在「需要写」时必须立刻返回，不能替调用方写。而「写完还要继续读」这件事
由下一次 `Step({kNone})` 自然表达 —— 此时内部没有待办，返回 `kRead`。
**这就是红证**：M5 的实测序列 `kNeedMoreInput, out=165` → `kNeedMoreInput, out=158` → `kOk, out=0`
证明「有输出」与「未完成」在同一状态上共存，而 `want` 只需要编码「此刻该做什么」，
不需要编码「是否完成」（那是 `complete()`）。

#### 13.3.2 EUAR 4 字节与后续 MCS PDU 同处一个 TLS record —— 切分点

**切分点定义（唯一）**：

> `plain_` 的前 4 字节被解释为 `uint32_t LE` 的充要条件是
> **`phase_ == kAwaitEuar`**。该阶段一进入就断言 `plain_` 为空（§5.3.3），
> 因此「前 4 字节」必然是本阶段新到的字节，不可能与 CredSSP 残余混淆。
> 消费后 `plain_` 立即 `remove_prefix(4)`，`phase_` 转 `kMcs`，
> 剩余字节**原样**留在 `plain_` 里供 `TpktStream` 使用。

用实测的 98 字节场景（§11.2 M6 的真实 record 切分）举例，
假设 EUAR 与 Connect Response 粘在一个 record 里：

```
TLS record (type=23, len=N)
  plaintext:  [00 00 00 00] [03 00 01 51 02 f0 80 7f 66 ... ConnectResponse ...]
              └── 4 字节 ──┘ └──────────── 归 TpktStream ────────────┘
              kAwaitEuar 消费         phase=kMcs 后 TpktStream::Append 的输入
```

`Step` 的具体行为（契约）：

```
Step({kCiphertext, record})  where record decrypts to "00000000" + ConnectResponse
  -> out.euar_result = 0x00000000        (SUCCESS; 不是「吞掉」，是上报)
  -> out.pdus        = { <完整 ConnectResponse 帧，含 TPKT 头> }   (若已凑齐)
  -> out.want        = kPump             (可能还有更多 pdus 可切)
  -> out.error.kind  = kNone
```

**若 `euar_result == 0x00000005`**：

```
  -> out.euar_result = 0x00000005
  -> out.pdus        = {}                (空：绝不产生 MCS 输出)
  -> out.want        = kFail
  -> out.error       = { kind=kAuthorizationDenied, stage=kEuar,
                         space=kLocal, native_code=0x00000005,
                         detail="EUAR AUTHZ_ACCESS_DENIED" }
```

**若 `expect_euar==true` 但首字节是 `0x03`（TPKT）**：

```
  -> out.euar_result = nullopt
  -> out.want        = kFail
  -> out.error       = { kind=kProtocolViolation, stage=kEuar, space=kLocal,
                         native_code=0,
                         detail="HYBRID_EX negotiated but EUAR missing" }
```
（`config.euar_optional==true` 时改为：不消费，直接转 `kMcs`，把 4 字节留给 `TpktStream`。）

**为什么不会误判**：判据是**阶段**，不是**值**。
即使 EUAR 值恰好是 `0x00000003`（规范未定义），也不会被当成 TPKT 头 ——
因为 `kAwaitEuar` 阶段无条件取 4 字节，然后按值域判定 `0x00`/`0x05`/其他。
反过来，`kMcs` 阶段永远不看 EUAR，所以 `00 00 00 00` 不可能在那里出现。

#### 13.3.3 `kClosed` + 剩余明文 > 0 的返回值

三种情况必须给出**三种不同的返回值**（§5.4.2 的三态）：

| 情形 | `plain_` 状态 | 返回值 |
|---|---|---|
| **A. 干净关闭** | 空 | `want=kDone`, `error={kind=kClosedByPeer, stage=kClose}` |
| **B. 关闭但有完整帧** | 含 ≥1 个完整单位 | **先派发**：`want=kPump`, `pdus={完整帧...}`, `error.kind=kNone`；下一次 `Step({kNone})` 在 `plain_` 空后返回情形 A |
| **C. 关闭且残留半帧** | 含不完整单位 | `want=kFail`, `error={kind=kTruncated, stage=kClose, space=kLocal, native_code=0, detail="peer closed mid-PDU: N bytes stranded"}` |

**情形 C 的判据（必须写进实现，不能靠猜）**：

```
is_truncated = (tls.buffered_input() > 0)              // 残缺 TLS record (tls_schannel.cpp:244)
            || (plain_.size() > 0 && !forms_complete_unit(plain_, phase_))
```

第一项来自实测：`src/net/tls_schannel.cpp:244`（锚点 `rx_buffer_.size() < kMinRecordHeader`） 在 `rx_buffer_.size() < 5` 时返回
`kOk`/`kNeedMoreInput`，若紧接着 `close_notify`，那 1..4 字节**永远**留在
`rx_buffer_` 里（`closed_` 在 `:232` 直接短路 `Receive`）。
若安全层把它当正常关闭，就是静默丢数据。

第二项按阶段定义 `forms_complete_unit`：

| 阶段 | 完整单位 | 不完整 → kTruncated |
|---|---|---|
| `kCredssp` | 一条完整 DER `30 <len>` | 长度字段声明的字节数不足 |
| `kAwaitEuar` | 4 字节 | 1..3 字节 |
| `kMcs` | `03 00 <len16be>` 且 `size >= len` | 头不足 4 字节，或 `size < len` |

**排空算法（契约，必须实现）**：

```cpp
// On tls.Receive returning kClosed (tls.h:148-150 keeps the plaintext):
//   1. append whatever plaintext the kClosed call produced to plain_
//   2. loop: feed(plain_) until no complete unit remains
//            if tls.buffered_input() == 0 break
//            call tls.Receive(nullptr, 0, plain_, 0)   // drain obligation, tls.h:157
//            if no progress in this round -> break      // anti-infinite-loop
//   3. if plain_ still holds a partial unit, or tls.buffered_input() > 0
//        -> want=kFail, kind=kTruncated   (情形 C)
//      else
//        -> want=kDone, kind=kClosedByPeer (情形 A)
```

**为什么不能把「kClosed 且有明文」直接报成 `kClosedByPeer`**：
`tls.h:148-150` 明确承诺 `kClosed` 时**保留**明文，并要求调用方**先排空**。
若安全层把「有明文」和「无明文」合并成一个返回值，
调用方就无法区分「对端正常道别」与「对端在半个 PDU 中间断了」——
前者是正常结束，后者是协议错误，两者的重连策略和日志级别都不同。
这正是我在 S9 里指出的 `Shutdown()` 短路问题的可观测面。

### 13.4 与既有接口的对接点（一一对应，无新增能力）

| 草案成员 | 依赖的既有契约 | 证据 |
|---|---|---|
| `Step` 内部调 `Handshake` | 逐 record 预切片，避免 `consumed=in_size` 多报 | `src/net/tls_schannel.cpp:169`（锚点 `consumed = in_size;`）；§11.2 F1/F2 |
| `Step` 内部调 `Receive` | append-only + 排空义务 | `include/rtsc/net/tls.h:142`、`:157` |
| `Step` 内部调 `Send` | 一条消息一次 `Send`，避免拆 record | `src/net/tls_schannel.cpp:217`（锚点 `const size_t chunk = MaxChunk();`）；§6 S16 |
| `SetServerPublicKey` | 必须新增生产 setter（现在只有 `ForTest`） | `include/rtsc/credssp/credssp.h:61`；§11.4 S18 |
| nonce 随机化 | 必须新增 CSPRNG（现在默认全零） | `src/credssp/credssp.cpp:46`；§6 S1 |
| `pdus` 含 TPKT 头 | `OnData` 要求带头，`TpktStream` 剥头 | `src/proto/connect_machine.cpp:196`、`src/proto/framing.cpp:86`；§6 S3 |
| EUAR 在 security 层 | `TpktStream` 会静默丢弃非 TPKT 字节 | `src/proto/framing.cpp:52`；§12.6 |
| `error.space` 区分命名空间 | 两个库都有同名 `native_code` | `include/rtsc/net/tls.h:59`、`include/rtsc/credssp/ts_request.h:34`；§5.5.1 |

### 13.5 本章自检

| 检查项 | 结果 |
|---|---|
| 是否写了实现 | 否，只有声明与契约注释 |
| 是否新增了既有接口没有的能力 | 否（`SetServerPublicKey` 是**要求**新增的，已标为前置缺陷 S18） |
| 是否回答了「同时写出且继续读」 | 是，§13.3.1，并给出实测序列作红证 |
| 是否回答了 EUAR 与 MCS 同 record 的切分点 | 是，§13.3.2，判据是阶段不是值 |
| 是否回答了 `kClosed` + 剩余明文 | 是，§13.3.3，三态返回值 + 可执行判据 |
| 是否与 §12.6 的裁决一致 | 是（EUAR 在 security 层，`ConnectMachine` 无感） |

---

## 14. `Handshake` 的 `consumed` 不可信：唯一结论

> 本章回应主代理 `evidence/tls/s10-measurement.md` 的裁决，并订正我 §11 里两处不够准确的表述。
> 新增实测证据：`F:\rtsc\.tmp\probe_s10\probe_s10e.cpp` → `evidence/s10/probe_s10e.out.txt`
> （在真实 `TlsTransport` 外面套一层「后端吸收尾部」的包装器，验证修复形态）。

### 14.1 先订正我自己 §11 的两处表述

| §11 的说法 | 实测/裁决 | 订正 |
|---|---|---|
| 「SChannel 在流式模式下根本不报告 EXTRA，也不校验尾随字节」 | 主代理探针与我的 M1/M7 一致：`extra=0`、`cbBuffer 98→98`、`71→71` 接受垃圾 | **成立，保留** |
| 「读 `in_bufs[0].cbBuffer` 算真实消费量」这个修法 | 主代理指出：`in_size - Σ(EXTRA) = in_size - 0 = in_size`，**算术修正救不了** | **订正**：`design-a.md:513` 的算术修正（对应 `include/rtsc/net/tls.h:129-132` 的接口注释）在这个场景下**必然失效**。这不是「实现没按设计做」，而是**设计本身在此场景无效**。我 §11.1 说「读 cbBuffer 毫无用处」方向对，但没点明「接口注释 `tls.h:129-132` 给出的唯一正确公式也是错的」 |
| S10 严重度 P1 → P2（因真实 RDP 时序不可达） | 主代理未反对，但强调「TLS 1.2 下服务端在 Finished 之后立即发应用数据是合法的」 | **维持 P2，但升级为「必须修」**：因为修复同时是 S3/EUAR 边界正确性的前提（见 §14.4） |

### 14.2 唯一结论：修复放在 TLS 后端内部，`TlsTransport` 契约必须改一句

**结论：修复必须在 `src/net/tls_schannel.cpp::Handshake` 内部完成，安全层不得承担 TLS 记录解析。
`include/rtsc/net/tls.h:129-132` 那三行注释必须改写。**

三条候选路径的裁决：

| 路径 | 做法 | 裁决 | 理由 |
|---|---|---|---|
| **D1（推荐）后端吸收尾部** | `Handshake` 自己按 record 头预切片，只把 `ContentType ∈ {20,21,22}` 的完整记录喂 ISC；握手完成时把剩余字节（`ContentType=23`）**移入自己的 `rx_buffer_`**，`consumed` 报「后端已接管」= `in_size` | ✅ **采纳** | 与 `Receive` 已有的能力同构（`src/net/tls_schannel.cpp:252-334`（锚点 `DecryptRecord .. plaintext.insert`） 就是按 `record_size` 精确切分），实现复用同一套 `ParseRecordHeader`（`:66-73`）；调用方无需知道 TLS 记录格式 |
| D2 后端报告精确 `consumed` | 只喂握手记录，`consumed` 只报真正喂进去的长度，尾部由调用方保存并回灌 | ⚠️ 可行但更差 | 调用方必须保存一段「不属于自己语义」的 TLS 密文并记得回灌；`Step` 契约里要多一个 `pending_ciphertext` 缓冲区，与 `TlsTransport::buffered_input()`（`tls.h:185`）职责重叠 —— 两个缓冲区又回来了 |
| D3 安全层解析 TLS 记录头 | 安全层读 `p[0]` 判 `ContentType` | ❌ **否决** | 见 §14.3 |

**`TlsTransport` 接口契约的修改（唯一一处，三行注释）**

现状（`include/rtsc/net/tls.h:129-132`）：

```cpp
    // The only correct way to compute `consumed` is
    //     consumed = in_size - sum(EXTRA.cbBuffer)
    // EXTRA.pvBuffer may be NULL (measured), so only cbBuffer may be read.
    // Self-check: consumed + sum(EXTRA) == in_size, otherwise kInternal.
```

**问题**：`sum(EXTRA) == 0` 时该公式退化为 `consumed = in_size`，与实测的「ISC 静默忽略尾部」冲突。
即「唯一正确的公式」在合段场景下给出错误答案，且无法与「真的全消费了」区分。

**改为**（语义从「算出来的消费量」改为「后端已接管的字节数」）：

```cpp
    // `consumed` is the number of leading input bytes the backend has TAKEN
    // OWNERSHIP of. The caller must not replay them.
    //
    // It is NOT "bytes SChannel decrypted": SChannel's stream handshake
    // silently ignores anything after its final handshake record and reports
    // no SECBUFFER_EXTRA (measured: cbBuffer unchanged, in_size - 0 == in_size,
    // see evidence/tls/s10-measurement.md and evidence/s10/probe_s10e.out.txt).
    // A backend therefore MUST either
    //   (a) retain any post-handshake bytes itself and expose them through
    //       Receive, or
    //   (b) report a `consumed` that stops at the handshake boundary.
    // This backend does (a): it pre-slices by the 5-byte TLS record header,
    // feeds only complete handshake records to SChannel, and moves the rest
    // into its own input buffer. Consequently consumed == in_size is correct
    // here and the old `consumed = in_size - sum(EXTRA.cbBuffer)` formula must
    // NOT be used to validate it.
    //
    // Post-condition the caller may rely on either way:
    //   consumed == in_size, OR buffered_input() > 0 after the call.
    // Both mean "do not replay".
```

**只改这一段，不改任何函数签名。** 因此：
- `tests/test_tls.cpp` 的 26 个用例全部不受影响（它们都不检查 `consumed` 的具体值；
  握手循环在 `tests/test_tls.cpp:181-202` 只用 `consumed` 做局部变量，不参与断言）。
- `rtsc_security` 的 `Step` 可以简单地按「`consumed` 即已接管」处理，无需额外缓冲。

### 14.3 为什么不把修复放在安全层（拒绝 D3）

**理由 1：会把安全层与 TLS 记录格式耦合，且是**两处**重复实现。**
`ParseRecordHeader` 已经存在于 `src/net/tls_schannel.cpp:68-260`（锚点 `ParseRecordHeader .. record_size = kMinRecordHeader + length`），
`Receive` 的切分循环在 `:241-270`。
若安全层也解析 record 头，就有**两份**记录解析逻辑（一份在 Windows 后端、一份在平台中立的安全层），
将来加 OpenSSL/BoringSSL 后端（`include/rtsc/net/tls.h:191` 的注释已经预留）时，
安全层那份会与后端那份**各自演化**，产生「安全层认为是应用记录、后端认为是握手记录」这类最难查的分歧。

**理由 2：安全层做这件事在架构上是错的层。**
安全层的职责边界是「**明文**分帧 + 阶段切换」（§5.2 的职责表）。
TLS 记录是**密文**分帧，属 `TlsTransport` 的契约（`include/rtsc/net/tls.h:142` 的标题就是
`---- receive application data ----`）。
让安全层读密文头，等于让「明文旅程」的组件去处理「密文旅程」的字节 —— 越界。

**理由 3：跨平台成本。**
`ContentType` 在 offset 0、长度在 offset 3-4 是 TLS 1.2/1.3 共有的（RFC 5246 §6.2.1 / RFC 8446 §5.1），
所以**技术上**安全层解析它是可行的，不构成真正的版本耦合。
但「可行」不等于「该做」：安全层一旦解析密文，就必须知道
「握手期只有 20/21/22 能喂 ISC」这条**后端实现细节**（ISC vs SSL_do_handshake 的差异），
而这条在 OpenSSL 后端上是**不成立**的（OpenSSL 的 `SSL_do_handshake` 会自己处理 record 层）。
→ **拒绝 D3 的核心理由是「这条规则属于后端，不属于安全层」，不是「做不到」。**

**唯一例外（必须写进契约）**：安全层仍需要 `buffered_input()`（`tls.h:185`）来判 §13.3.3 的
`kTruncated`。这是**长度**，不是**内容**，不构成耦合。

### 14.4 修复的红证（真实 SChannel，`probe_s10e`）

把 D1 的语义实现为一个包装在真实 `TlsTransport` 外的 `FixedBackend`
（源码 `F:\rtsc\.tmp\probe_s10\probe_s10e.cpp`，输出 `evidence/s10/probe_s10e.out.txt`）：

```
=== G3: normal path (separate) ===
  Handshake(finished 51) -> status=0 consumed=51 complete=1
  Receive(app 47) -> status=0 "S10-PAYLOAD-MARKER"
  G3 VERDICT: normal path UNCHANGED

=== G1/G2: coalesced 98B ===
  combined = 51 (finished) + 47 (app) = 98
  Handshake(98) -> status=0 consumed=98 complete=1 buffered=47
  G1 VERDICT: consumed=98 (all absorbed, caller need not replay) -> PASS
  Receive#0 -> status=0 plaintext=18 buffered=0
  Receive#1 -> status=1 plaintext=0 buffered=0
  recovered 18 bytes: "S10-PAYLOAD-MARKER"
  G2 VERDICT: app data after fix = RECOVERED (fix works)

=== G4: coalesced blob fed 1 byte at a time ===
  after 98 bytes: consumed_total=98 complete=1
  recovered "S10-PAYLOAD-MARKER"
  G4 VERDICT: streaming input OK
```

**四组对照，缺一不可**：
- G3 证明**不破坏正常路径**（当前 26 个 TLS 测试覆盖的正是这条）。
- G1/G2 证明**修好了目标 bug**（`consumed` 报满，且数据从 `Receive` 出得来）。
- G4 证明**流式输入下仍成立**（真实 socket 的 `recv` 不会按 record 对齐）。
- 反向对照是 §11.2 的 M8（**未修**时 `total recovered = 0`）——
  同一份 blob、同一个断言，修复前 0 字节、修复后 18 字节。这是完整的先红后绿。

### 14.5 对方案 B `Step` 契约的影响（落到 §13 的具体修订）

| §13 的位置 | 原表述 | 修订 |
|---|---|---|
| `Step` 的 POSTCONDITION | 「`in.size` 字节要么被消费，要么记入内部缓冲，其大小可通过 `buffered_ciphertext()` 观测」 | **保留**，但现在有后端保证：`consumed == in_size` 或 `buffered_input() > 0`，二者必居其一（§14.2 的 post-condition） |
| `buffered_ciphertext()` 注释 | 「镜像 `TlsTransport::buffered_input` 加上我们自己的预切片」 | **改为**：只镜像 `TlsTransport::buffered_input()`（`tls.h:185`）。**安全层不再做任何密文预切片**（D1 之后不需要） |
| §13.4 对接表 | 「`Step` 内部调 `Handshake`：逐 record 预切片，避免 `consumed=in_size` 多报」 | **改为**：「依赖后端契约：`consumed` 表示已接管；后端已按 record 预切片并把尾部交给 `Receive`（`tls.h:129-137` 修订后）」 |
| §13.3.1 的握手时序 | 未变 | **不变**。`want` 的 `kWrite`/`kRead` 按拍推进的结论不受影响 —— 因为 `Handshake` 的「有输出」与「是否完成」仍正交（`tls.h:183` 的 `handshake_complete()` 独立于 `out`） |

**方案 B 因此变得更简单，不是更复杂**：
安全层不再需要自己维护密文缓冲，`Step` 的 `kCiphertext` 输入可以直接转交
`tls.Handshake()` / `tls.Receive()`。这也消除了我在 §13 里
`buffered_ciphertext()` 与 `buffered_input()` 两个观测点并存的冗余。

### 14.6 缺陷编号更新

| 编号 | 变更 |
|---|---|
| **S10** | 保留（P2），但**症状描述订正**为：「`Handshake` 的 `consumed` 在『握手记录+应用记录合段』时多报；根因是 SChannel 流式握手不报 EXTRA 且不校验尾随字节，而 `tls.h:129-132` 给出的唯一公式 `in_size - Σ(EXTRA)` 在此场景退化为 `in_size`，**设计本身失效**」。修复 = D1（后端预切片 + 吸收尾部）+ 改写 `tls.h:129-132` 的契约注释 |

**缺陷总数仍为 20 条**（S10 是订正，不是新增）。
P0 × 5（S1/S2/S3/S4/S18），P1 × 8（S5/S6/S7/S8/S9/S11/S20 + S10 由 P1 降为 P2 后此处不变），
P2 × 7（S10/S12/S13/S14/S15/S16/S17/S19 → 实为 8 条，其中 S17 归入 S13 的同类；**精确统计见下表**）。

**最终统计（订正后）**：

| 级别 | 编号 | 条数 |
|---|---|---|
| **P0** | S1, S2, S3, S4, S18 | **5** |
| **P1** | S5, S6, S7, S8, S9, S11, S20 | **7** |
| **P2** | S10, S12, S13, S14, S15, S16, S17, S19 | **8** |
| **合计** | | **20** |

### 14.7 本章自检

| 检查项 | 结果 |
|---|---|
| 是否给出唯一结论 | 是：D1（后端内部修复），拒绝 D3（安全层解析记录） |
| 是否说明接口契约改哪一句 | 是：`include/rtsc/net/tls.h:129-132`，给出替换文本 |
| 是否回答「安全层与 TLS 版本耦合」 | 是：技术上不耦合（ContentType/长度在 1.2/1.3 相同），但**架构上不该做**，核心理由是「该规则属于后端」 |
| 修复是否有红证 | 是：`probe_s10e` G1–G4，含「未修 0 字节 / 修后 18 字节」的对照 |
| 是否改了工程代码 | 否（包装器在 `.tmp`，不进入构建） |
| 是否订正了自己的错误 | 是，§14.1 两处 |

---

## 15. 修复清单（供定案）

> **行号基线**：本章所有行号均为本轮**重新读取**的当前行号（文件 `LastWriteTime` 已核对，
> 与 §1–§14 撰写时相比 `src/credssp/*`、`include/rtsc/credssp/*`、`src/net/tls_schannel.cpp`、
> `include/rtsc/net/tls.h`、`CMakeLists.txt` 均有更新，故不沿用旧行号）。
> 核对方式：逐文件 `(Get-Content).Count` 比对总行数 + 逐条 `Select-String` 定位。
>
> 本章**不含任何工程代码改动**，只描述改动点。

### 15.0 编号说明（必须先读）

我的缺陷编号是 **S1–S20（20 条）**。乙的 **B19（跨平台编译阻塞）** 经我复核**属实**，
但它**不在我的 S 编号里**（我第一版漏了，第二阶段才补进 §12.1 的讨论）。
为避免清单不完整，本章把它编为 **S21** 并明确标注来源为乙的 B19。

**因此本章覆盖 21 个修复点：S1–S20（我的 20 条）+ S21（乙的 B19）。**

### 15.1 逐条修复点

> 「改哪个文件:行」列中，`新增` 表示该行号尚不存在，需新建文件；
> 所有「新增」路径都写明完整相对路径。
> 「依赖」列只列**硬依赖**（不修则本条的验证必然失败）。

| 编号 | 级别 | 缺陷一句话 | 改哪个文件:行 | 改什么（最小改动） | 怎么验证（红证/绿证） | 依赖 |
|---|---|---|---|---|---|---|
| **S1** | P0 | `nonce_` 恒为 32 个 0，client challenge 与 exported session key 可预测；握手仍成功 | `src/credssp/credssp.cpp:46`（`nonce_.assign(kNonceSize, 0);`）；`include/rtsc/credssp/credssp.h:57-59`（空头承诺注释）；新增 `src/sec/random.cpp` + `include/rtsc/sec/random.h` | `:46` 改为调用新增的 `sec::RandomBytes(nonce_)`；`credssp.h:57-59` 注释改为「构造时已用 CSPRNG 填充，`SetNonceForTest` 仅测试用」；新增 `RandomBytes(Bytes&)`（Win: `BCryptGenRandom`，POSIX: `getrandom`/`arc4random_buf`）。**注意**：`rtsc_credssp` 不能依赖 `rtsc_tls`，故 RNG 放 `rtsc_crypto` 或新 `rtsc_sec_util`，不能放 `rtsc_security`（否则 `rtsc_credssp` 反向依赖） | **红证**：新增测试 `two_constructions_have_different_nonces`，断言 `CredsspClient(c,6)` 两次的 `ExportedSessionKeyForTest()` 不同 → 当前必失败（都全零）。**绿证**：`rtsc_credssp_sm_tests` 15 条仍全绿（所有用例都先调 `SetNonceForTest`，见 `tests/test_credssp_sm.cpp:107`） | 无 |
| **S2** | P0 | EUAR 无读取器；`TpktStream` 把 4 字节 EUAR 当垃圾静默丢弃（`dropped_ += skipped`） | 新增 `include/rtsc/sec/security_layer.h` + `src/sec/security_layer.cpp`（`kAwaitEuar` 阶段）；不改 `src/proto/framing.cpp` | 在 `SecurityLayer` 里新增 `kAwaitEuar` 阶段：`plain_` 头部恰取 4 字节 → `uint32 LE` → `0x00` 转 `kMcs`，`0x05` 返回 `kAuthorizationDenied`，其他 `kProtocolViolation`。**`plain_` 消费后 `remove_prefix(4)`**，剩余字节才喂 `TpktStream`。`framing.cpp:52` 的 `dropped_ += skipped` **不改**（它在明文 TCP 场景仍是对的），改为在安全层断言 `dropped_bytes()==0` | **红证**：T4 用例「EUAR=0x05 → `kAuthorizationDenied` 且 `pdus` 为空」→ 当前无安全层，用例无法编译（先红）。T5「EUAR 缺失（首字节 0x03）→ `kProtocolViolation`」。**绿证**：T1（EUAR SUCCESS + 后续 MCS 正常切分） | S18（需要公钥才能走到第 5 步之后） |
| **S3** | P0 | `TpktStream` 剥掉 4 字节 TPKT 头，而 `ConnectMachine::OnData` 要求带头的完整帧 → 第一帧即 `InvalidVersion` | 新增 `src/sec/security_layer.cpp`（`kMcs` 阶段）；不改 `src/proto/framing.cpp:86` | 安全层拿到 `TpktStream::Next()` 的 payload 后调 `WrapTpkt(payload.data(), payload.size())`（`include/rtsc/proto/framing.h:54`、实现 `src/proto/framing.cpp:99`）还原头部，再放进 `Output.pdus`。**不修改 `TpktStream` 本身**（`src/proto/framing.cpp:86-87` 保持剥头语义，它有自己的 11 个测试） | **红证**：T3'「把 `TpktStream` 输出直接喂 `ConnectMachine::OnData` → 必须 `failed()`」→ 证明不还原就必挂。**绿证**：T11（真实回环跑完整流到 Connect Response），且 `rtsc_framing_tests` 11 条不变 | S2（阶段机存在） |
| **S4** | P0 | 无 DER 分帧器：`TsRequest::Decode` 要求恰好一条 SEQUENCE 且拒绝尾随字节（`:283`），跨 TLS record 的 TSRequest 无法重组 | 新增 `src/sec/security_layer.cpp`（`kCredssp` 阶段的 DER TLV 累积） | 安全层在 `plain_` 上做 DER 头解析：读 `30` + 长度（短形式 / `0x81` / `0x82`，与 `src/credssp/ts_request.cpp:52-70` 的 `ReadLength` 规则一致），凑满 `5+len` 才调 `CredsspClient::OnServerResponse`。**不改 `ts_request.cpp`**（它的「拒绝尾随字节」是正确契约，由安全层保证每次只喂一条） | **红证**：T6「TSRequest 拆成两个 `Receive` 到达 → 当前直接喂会 `kTruncated`」。**绿证**：T6 修复后 `complete()` 达成 | S2 |
| **S5** | P1 | 服务端 `TSRequest.version` 从不校验；「拒绝 version 1」的测试其实是靠 token 解析失败通过 | `src/credssp/credssp.cpp:93`（`if (!e.ok()) return Fail(...)` 之后、`:95` 之前插入） | 在 `:93` 与 `:95` 之间加：`if (req.version < kMinVersion \|\| req.version > kMaxVersion) return Fail(Status::kUnsupported, "unsupported TSRequest version");`（`kMinVersion=2`/`kMaxVersion=6` 见 `include/rtsc/credssp/credssp.h:31-32`） | **红证**：改写 `tests/test_credssp_sm.cpp:128-140`，用**合法 CHALLENGE**（`ServerChallengeMessage()`，`:75`）+ `version=1` → 当前会「通过」（因为走的是 `BuildStep3` 的 token 解析）→ 修后必须 `!ok()` 且 `status==kUnsupported` | 无 |
| **S6** | P1 | 服务端版本不回写 `version_`，第 3/5 步仍用客户端自己的版本（`c:241`、`c:300`） | `src/credssp/credssp.cpp:93-94` 之间（同一插入点，紧随 S5） | 插入：`version_ = std::clamp(req.version, kMinVersion, kMaxVersion);`（`<algorithm>` 已在 `:7` 引入）。这样 `:241`、`:300` 的 `req.version = version_` 自动跟随服务器版本 | **红证**：新增用例「服务器回 version=3（带合法 CHALLENGE）→ 第 3 步 `pub_key_auth` 长度应为 `16 + len(SPK)`（v2/3/4 路径）而非 `16+32`，且 `client_nonce` 必须为空」→ 当前会发 `16+32` 且带 nonce → 必失败 | S5 |
| **S7** | P1 | `kPeerAlert` 从不产生；TLS alert 49（凭据无效）退化为 `kProtocolError`，与协议违规无法区分 | `src/net/tls_schannel.cpp:185`（锚点 `return MakeError(Status::kNeedMoreInput, st, "incomplete handshake")`）（`SEC_E_ILLEGAL_MESSAGE`/`SEC_E_INVALID_TOKEN` 分支） | 在 `:184` 之前插入对 `SEC_E_ILLEGAL_MESSAGE` 的 alert 提取：`Receive` 路径的明文 record 里 alert 是 `15 03 03 00 02 <level> <desc>`（`kRecordAlert=21`，`t:53`）。`Handshake` 路径拿不到明文时，至少把 `detail` 标注「可能是 fatal alert」。**必须先做 U4 实测**（SChannel 在 alert 场景返回哪个 status），否则改动是猜测 | **红证**：`RawServer` 主动发 `access_denied` alert → 当前得到 `kProtocolError` 且 `native_code` 不含 49 → 修后 `status==kPeerAlert && native_code==49`。**绿证**：现有 `boundary7`（`tests/test_tls.cpp:526`）仍得 `kDecryptFailed` | U4（未验证项） |
| **S8** | P1 | `kStrict`/`kTofu` 未实现：三分支都只 `ISC_REQ_MANUAL_CRED_VALIDATION`；`pinned_spki_sha256`/`pin_is_set` 零使用 | `src/net/tls_schannel.cpp:137-147`（锚点 `switch (config_.cert_policy) {` .. `ISC_REQ_MANUAL_CRED_VALIDATION`）（switch）；新增 `src/net/tls_cert_policy.cpp` 或在 `tls_schannel.cpp` 内加私有方法 | `:141-145` 的 `kStrict` 分支改用 `SCH_CRED_DEFERRED_CRED_VALIDATION`（而非 MANUAL）；`FinishHandshake`（`t:491-509`）在 `:506` 之后加证书链校验 `CertGetCertificateChain` + 主机名（可配）；`kTofu` 比对 `SHA256(SPKI)` 与 `pinned_spki_sha256`（SPKI 已有 `t:371-384`）。**注意**：`kInsecure` 保持现状（本目标服务器自签名，见 `docs/spec/security-layer.md:532-534`） | **红证**：新增用例「`kStrict` + 自签证书 → 必须 `kCertRejected`」→ 当前必「成功」（MANUAL 模式下没人校验）。**绿证**：`InsecureConfig()`（`tests/test_tls.cpp:224-229`）的 24 条仍全绿；`peer_keys_are_consistent...`（`:817`）不变 | 无（但 S7 与它同批更省事） |
| **S9** | P1 | `Shutdown()` 置 `closed_`（`t:432`）后 `Receive` 在 `src/net/tls_schannel.cpp:232`（锚点 `if (closed_) return MakeError(Status::kClosed, 0, "already closed");  (in Receive)`） 入口短路，`rx_buffer_` 残余永久丢失 | `src/net/tls_schannel.cpp:232`（锚点 `if (closed_) return MakeError(Status::kClosed  (in Receive)`） | `if (closed_)` 改为 `if (closed_ && rx_buffer_.empty())`，让「已关闭但还有缓冲」仍能走解密循环；`:431-433`（批 0 后；锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`） 的 `closed_ = true` 保留 | **红证**：T13「`Shutdown()` 后 `buffered_input()>0` 仍能 `Receive` 出明文」→ 当前返回 `kClosed` 且明文 0。**绿证**：`shutdown_is_idempotent`（`tests/test_tls.cpp:848`）仍绿 | 无（**必须与 S10 同批**，见 §15.2） |
| **S10** | P2 | `Handshake` 的 `consumed = in_size`（`:169`（批 0 后；锚点 `consumed = in_size;`））在「握手记录+应用记录合段」时多报；根因是 SChannel 不报 EXTRA 且不校验尾随，`tls.h:129-132` 的公式本身失效 | `src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`）（`Handshake` 主体）；`include/rtsc/net/tls.h:129-132`（契约注释） | 按 §14.2 的 D1：`Handshake` 内部维护 `hs_buffer_`，只把 `ContentType ∈ {20,21,22}` 的**完整**记录（5 字节头 + 长度，复用 `ParseRecordHeader` `t:68-75`）喂 ISC；握手完成后把剩余记录**移入 `rx_buffer_`**，`consumed` 报「已接管」= `in_size`。`tls.h:129-132` 注释按 §14.2 给出的替换文本改写（语义从「算出的消费量」改为「后端已接管」） | **红证**：`probe_s10` M8（未修：`total recovered = 0`）。**绿证**：`probe_s10e` G1–G4（修后：`consumed=98`、`Receive` 解出 18 字节、逐字节喂也成立、正常路径不变）。**回归**：`tests/test_tls.cpp` 无任何 `consumed` 断言（仅 `:175`/`:192` 局部变量，`:745`/`:792` 是 `Send` 的）→ 26 条不受影响 | 无（**必须与 S9 同批**） |
| **S11** | P1 | `OpenReceive` 只解密不验 HMAC（`c:347-362`），第 4 步可被篡改 | `src/credssp/credssp.cpp:357-360` | 在 `:357` 之前解析 `field[0..16)` 的 signature：取 `field[4..12)` 为 checksum、`field[12..16)` 为 seq；用 `signing_key_` + 该 seq 重算 `HMAC_MD5(seq_le32 \|\| plaintext)` 的前 8 字节，在 `recv_rc4_` 流上解出 checksum 后比对。**顺序必须与 `SealSend`（`c:318-329`）对称**：先解密文、再解 checksum。不匹配返回 `Fail(Status::kMalformed, "sealed field MAC mismatch")` | **红证**：新增用例「篡改第 4 步 `pub_key_auth` 的密文 1 字节 → 当前仍能走到 step5（因为只比回显值，而篡改会改变回显 → 其实会失败）」。**必须设计一个能区分「回显比对失败」与「MAC 校验失败」的用例**：篡改 signature 的 checksum 字节（不动密文）→ 当前**完全察觉不到**（回显仍匹配）→ 修后必须 `kMalformed`。**绿证**：`step5_sends_authinfo_only`（`tests/test_credssp_sm.cpp:283`）仍绿（`MakeServerEchoForTest` 产的是带正确 MAC 的） | 无 |
| **S12** | P2 | `OnExternalSecurityComplete()` 在错误阶段静默 no-op（`cm:353-357`） | `src/proto/connect_machine.cpp:353-357` | `:354-356` 改为 `Fail("OnExternalSecurityComplete called in the wrong phase"); s.needs_input=false; return s;` | **红证**：新增用例「`kAwaitNegotiation` 阶段调 `OnExternalSecurityComplete()` → 当前 `!failed()`（静默）→ 修后 `failed()`」。**绿证**：`machine_external_security_completion_continues_sequence`（`tests/test_connect_machine.cpp:200`）仍绿 | 无 |
| **S13** | P2 | `OnData` 一次返回两条 PDU（`cm:268-269`：Erect Domain + Attach User） | `src/proto/connect_machine.cpp:268-269`（或只改文档） | **最小改动 = 不改代码，改文档**：在 `include/rtsc/proto/connect_machine.h:38-41`（`ConnectStep` 定义处）的注释里写明「`output` 可能含**多条** PDU，必须整体一次 `Send`」。若要求强约束，则改为「返回第一条、把第二条存起来下次返回」——但会改变 `tests/test_connect_machine.cpp:228` 的既有断言，**不建议** | **绿证**：无需红证（不是 bug，是契约不清）。新增一条断言「`step.output` 里含 2 个 TPKT 帧」即可锁定契约 | 无 |
| **S14** | P2 | `state_.error` 是 `std::string`，无错误码（`h:57`、`cm:122-125`） | `include/rtsc/proto/connect_machine.h:57`；`src/proto/connect_machine.cpp:122-125` | `h:57` 后新增 `int32_t error_code = 0;`（或 `uint32_t`，与 NTSTATUS 对齐）；`cm:124` 后加 `state_.error_code = 0;`（`Fail` 只有 `const char*` 一个重载，先保持），并新增 `Fail(const char* reason, int32_t code)` 重载供未来用。**纯新增字段，不破坏现有测试** | **绿证**：`rtsc_connect_machine_tests` 26 条不变（新字段默认 0）。**无红证**（这是可扩展性改进，不是可观测 bug） | 无 |
| **S15** | P2 | 仓库内无 socket 驱动；`rtsc_probe` 只到 CCF（`tools/rtsc_probe/main.cpp:205-228`） | 新增 `src/sec/socket_driver.cpp` + `include/rtsc/sec/socket_driver.h`（或先只在 `tools/rtsc_probe/main.cpp` 扩一个 `--full` 分支） | 最小可用：在 `rtsc_probe` 的 `connect_and_negotiate`（`p:194` 附近）之后接上 `SecurityLayer::Step` 循环：`recv` → `Step({kCiphertext})` → 写 `to_wire` → 把 `pdus` 喂 `ConnectMachine::OnData`。**不改 `rtsc_proto`** | **红证**：无（新功能）。**绿证**：`rtsc_probe --connect 192.168.1.7 3389 <cookie>` 能打印 `phase=await-connect-response` 且 `pdus` 含 Connect Response | S1, S2, S3, S4, S18, S21(仅跨平台) |
| **S16** | P2 | `Send` 可能把一条明文拆成多条 TLS record（`t:215-222`），与「整条 TSRequest 一个 fragment」冲突 | 新增 `src/sec/security_layer.cpp`（`SendPdu` 前断言）；不改 `src/net/tls_schannel.cpp:217-219`（锚点 `const size_t chunk = MaxChunk();` .. `while (done < size) {`） | 安全层在 CredSSP 阶段调 `Send` 前断言 `size <= record_sizes().max_plaintext`（`include/rtsc/net/tls.h:176`），超限返回 `kUnsupported` + `detail`。**不修改 `Send` 的切分逻辑**（`tests/test_tls.cpp:772` 的 `send_splits_oversized_payload_instead_of_failing` 依赖它） | **绿证**：现有 `send_splits_oversized...`（`:772`）仍绿；新增断言用例覆盖「CredSSP 消息超 16384 → `kUnsupported`」 | S2 |
| **S17** | P2 | `CredsspClient::complete()` 在第 5 步**发出后**立刻为真（`c:305`），易被误当「已授权」 | `include/rtsc/credssp/credssp.h:51-53`（注释） | 在 `:52` 的注释里加一句：`// WARNING: complete() means "step 5 sent", NOT "server accepted". Authorization is only known after the EUAR (HYBRID_EX) or the first post-handshake PDU.` **不改代码**（`kDone` 的语义本身是对的，只是易误用） | **绿证**：无需（文档级）。**可选**：安全层加静态断言/测试「`complete()` 后仍必须走 `kAwaitEuar`」 | 无 |
| **S18** | P0 | 生产路径永远拿不到服务器公钥：`server_public_key_` 唯一写入点是 `SetServerPublicKeyForTest`（`credssp.h:61`） | `include/rtsc/credssp/credssp.h:60-61`（新增生产 setter）；新增 `src/sec/security_layer.cpp`（调用点） | `credssp.h` 在 `:61` 后新增 `void SetServerPublicKey(Bytes spk) { server_public_key_ = std::move(spk); }`（**不带 ForTest**，语义为生产注入）；`CredsspClient::Start`（`c:58`）或 `BuildStep3`（`c:116`）入口加 `if (server_public_key_.empty()) return Fail(Status::kUnsupported, "server public key not set");`；安全层在 TLS 握手完成后 `tls.PeerSubjectPublicKey(spk)`（`include/rtsc/net/tls.h:170`）→ `SetServerPublicKey(spk)` | **红证**：`probe`/新用例「不调 setter 直接 `Start` + 喂合法 CHALLENGE → 当前会产出 `pubKeyAuth = SHA256(magic‖0*32‖"")`（不报错）→ 修后必须 `kUnsupported`」。**绿证**：`rtsc_credssp_sm_tests` 15 条全绿（它们都调 `SetServerPublicKeyForTest`，`:61` 保留） | 无（但 S2 需要它才能走到第 5 步后） |
| **S19** | P2 | `min_version=0x0304` 时 `ProtocolMask()` 只置 `SP_PROT_TLS1_3_CLIENT` → `AcquireCredentialsHandle` 返回 `0x80090331` | `src/net/tls_schannel.cpp:469`（锚点 `if (config_.min_version <= kTls12`） | `:467` 改为 `if (config_.min_version <= kTls13 && config_.max_version >= kTls12)` 之类**保证 1.3 时也带上 1.2**；或更简单：`:470-472` 的 1.3 分支里同时 `mask |= SP_PROT_TLS1_2_CLIENT;`（SChannel 不支持 1.3-only 凭据，实测 `0x80090331`）。真实窗口仍由 `EnforceVersionWindow`（`t:570-577`）保证 | **红证**：`probe_s19`（主代理已跑）：`tls1.3 only mask=0x00002000 -> 0x80090331 FAIL`。**绿证**：`min_version=0x0304` 时 `CreateTlsTransport` 成功，且 `EnforceVersionWindow` 在服务器只支持 1.2 时返回 `kInternal`（而非静默降级）。**同时修测试**：`tests/test_tls.cpp:879-885` 的 `if (!started) { CHECK(!why.empty()); return; }` 必须改为断言「要么协商到 1.3，要么明确报版本窗口错误」 | 无 |
| **S20** | P1 | 口令两份、同名不同义、NLA 下仍无条件回填 Client Info（`cm:168`） | `src/proto/connect_machine.cpp:165-168`（分支）；`include/rtsc/proto/connect_machine.h:98`（注释）；详见 §15.4 | 见 §15.4 的完整改法（含非 NLA 路径如何不丢密码） | **红证**：新增用例「`negotiated_protocol=0x08` 且 `autologon=false` → `pdu.info.password` 必须为空」→ 当前非空。**绿证**：`machine_client_info_autologon_flag_follows_credentials`（`tests/test_connect_machine.cpp:438`）与 `machine_client_info_payload_decodes_back`（`:393`）仍绿 | 无 |
| **S21** | P1 | （乙的 B19）`tls_schannel.cpp` 无条件 include Windows 头、`CMakeLists.txt:51` 无条件 `add_library` → Linux 编译期失败 | `CMakeLists.txt:51-55`；`src/net/tls_schannel.cpp:29-32`（锚点 `#include <windows.h>` .. `#include <wincrypt.h>`）（不改，靠 CMake 排除） | 按 §12.1 三层拆分：`rtsc_tls_api`（INTERFACE）+ `if(WIN32) rtsc_tls_schannel` + 门面 `rtsc_tls`（非 Windows 退化）。**不在 `tls_schannel.cpp` 加 `#ifdef`**（会造出空 TU 静态库这种隐性失败） | **红证**：`cmake -DCMAKE_SYSTEM_NAME=Linux` 配置 + 编译 `rtsc_tls` → 当前必然失败（找不到 `windows.h`）。**绿证**：同一命令成功，且 `rtsc_proto`/`rtsc_credssp` 仍能编（它们不引用 `tls.h`） | 无（独立） |

### 15.2 修复顺序与分组

#### 15.2.1 必须同批修的

| 组 | 成员 | 为什么必须同批 |
|---|---|---|
| **G-A** | **S9 + S10** | 两者都动 `tls_schannel.cpp` 的「缓冲归属」。S10 把尾部移入 `rx_buffer_`，S9 决定 `closed_` 是否阻断 `rx_buffer_`。**只修 S10 不修 S9**：尾部进了 `rx_buffer_`，但一旦 `Shutdown()` 置 `closed_`，`:232`（批 0 后；锚点 `if (closed_) return MakeError(Status::kClosed   (inside Receive)`） 又把它挡住 → S10 的修复被 S9 抵消，症状从「握手期丢」变成「关闭期丢」。**只修 S9 不修 S10**：握手期仍丢。二者是同一个不变量的两半：「`rx_buffer_` 里的字节必须在 `closed_` 后仍可消费」 |
| **G-B** | **S5 + S6** | S5 校验 `req.version`、S6 回写 `version_`，**同一插入点**（`c:93` 之后）。分开改会互相踩行号；且只修 S5 不修 S6 会让「校验通过但用错版本」继续存在（比不校验更隐蔽） |
| **G-C** | **S1 + S18** | 二者都是「`CredsspClient` 的生产注入路径缺失」，且都在 `credssp.h:56-61` 的 test-hook 区块。同批改可一次性把该区块重构成「生产 setter + 测试 setter」两组，避免两次改动同一段注释。**不是硬依赖**（可以分开），但同批成本最低 |
| **G-D** | **S2 + S3 + S4** | 三者都在新增的 `SecurityLayer` 里，且构成同一条流水线（EUAR 阶段 → TPKT 还原 → DER 累积）。分三次建文件等于把同一个类写三遍。**S4 依赖 S2 的阶段机**，S3 依赖 S2 的 `pdus` 输出通道 |
| **G-E** | **S16 + S2** | S16 的断言点在 `SendPdu`，属 S2 的类。可延后，但不应单独建文件 |

#### 15.2.2 可独立修的

| 编号 | 独立性说明 |
|---|---|
| **S7** | 只动 `src/net/tls_schannel.cpp:187`（锚点 `case SEC_E_INVALID_TOKEN`）（锚点 `case SEC_I_CONTINUE_NEEDED` 之后的分支） 一个分支，与 G-A 不冲突（不同函数：`Handshake` vs `Receive`）。**但需要 U4 实测先给出 SChannel 的实际返回码**，否则改动是猜测 |
| **S8** | 只动 `src/net/tls_schannel.cpp:137-147`（锚点 `switch (config_.cert_policy) {` .. `ISC_REQ_MANUAL_CRED_VALIDATION`） + `FinishHandshake`（`t:491-509`）。与 G-A 不冲突（不同函数）。可独立验证（`kStrict` + 自签 → `kCertRejected`） |
| **S11** | 只动 `credssp.cpp:357`。与 G-B 不冲突（`OpenReceive` 是另一个函数）。独立用例可验证（篡改 checksum 字节） |
| **S12** | 只动 `connect_machine.cpp:353-357`。纯 `rtsc_proto`，与所有 TLS/CredSSP 改动解耦 |
| **S13** | **只改注释**，零代码风险 |
| **S14** | 纯新增字段，`connect_machine.h:57` 后加一行 |
| **S17** | **只改注释** |
| **S19** | 只动 `src/net/tls_schannel.cpp:469`（锚点 `if (config_.min_version <= kTls12`）。与 G-A 不冲突（`ProtocolMask` 是另一个函数）。可独立验证（`probe_s19` 已给出红证） |
| **S20** | 只动 `connect_machine.cpp:165-168`。纯 `rtsc_proto`，与 TLS/CredSSP 解耦 |
| **S21** | 只动 `CMakeLists.txt`。与所有源文件改动解耦（但会影响所有 target 的可见性，建议**最先做**，见下） |

#### 15.2.3 前置条件（阻塞关系）

| 修复 | 是哪些的前置 | 说明 |
|---|---|---|
| **S21**（跨平台） | **不阻塞** Windows 上的任何修复 | 它只在「声称跨平台」时才成为前置。**但建议最先做**：它改 `CMakeLists.txt` 的 target 结构，越晚做、与其它 CMake 改动（新增 `rtsc_security` target）冲突越大 |
| **S18**（公钥） | **S2 的端到端验证** | 没有公钥，`pubKeyAuth` 是 `SHA256(magic‖nonce‖"")`；服务器若校验则第 4 步必失败，**走不到第 5 步之后**，因此 EUAR 阶段永远进不去。**S2 的单元测试可以用 `SetServerPublicKeyForTest` 绕过，但真机验证绕不过** |
| **S1**（随机 nonce） | **无**（不阻塞任何其它修复） | 见 §15.3 的重要区分：nonce 全零时握手**仍然成功**（服务器用客户端发来的 nonce 算同一个哈希） |
| **S19**（TLS1.3-only） | **无** | 默认 `min_version=0x0302`（`include/rtsc/net/tls.h:112`），不触发该分支。只在用户显式配 `0x0304` 时暴露 |
| **S2**（安全层） | **S15**（驱动） | 驱动要有 `Step` 才能接 |
| **U4**（SChannel alert 实测） | **S7** | 见 §15.5 |

#### 15.2.4 建议批次

| 批次 | 内容 | 理由 |
|---|---|---|
| **批 0** | S21（CMake 拆分） | 先稳定 target 结构，后续新增 `rtsc_security` 不会与它打架 |
| **批 1** | G-C（S1+S18）、G-B（S5+S6）、S11 | 全部在 `rtsc_credssp`，互不冲突；`rtsc_credssp_sm_tests` 一次回归 |
| **批 2** | G-A（S9+S10）、S19、S8、S7（若 U4 已完成） | 全部在 `rtsc_tls`，`rtsc_tls_tests` 一次回归 |
| **批 3** | G-D（S2+S3+S4+S16） + 新建 `rtsc_security` | 新库，依赖批 1/2 的成果 |
| **批 4** | S20、S12、S13、S14、S17 | `rtsc_proto`，纯独立 |
| **批 5** | S15（socket 驱动）+ 真机联调 | 最后 |

**批 1 与批 2 可以并行**（不同库，无共享文件）。批 3 必须等批 1/2。

### 15.3 最小可交付子集

#### 15.3.1 最小集合（6 项）

> 目标：「安全层能跑通真实服务器 `192.168.1.7:3389`（HYBRID_EX）到 MCS Connect Initial」。

| # | 编号 | 为什么在最小集里 | 不做的具体可观测失败 |
|---|---|---|---|
| 1 | **S18** | 没有服务器公钥，`pubKeyAuth` 算的是 `SHA256(magic‖nonce‖"")` | **具体失败**：服务器校验 `pubKeyAuth` 时哈希不匹配 → 回 `errorCode`（`STATUS_LOGON_FAILURE` 或 `SEC_E_INVALID_TOKEN` 类）或直接 TLS alert → 客户端在**第 4 步**失败，**永远到不了第 5 步，也永远看不到 EUAR**。错误表现为「CredSSP 第 4 步 pubKeyAuth 不匹配」，而不是「缺公钥」——极易误判为「拼接顺序错」（U3） |
| 2 | **S3** | `TpktStream` 剥头 vs `OnData` 要头 | **具体失败**：第一帧 MCS Connect Response 到达后，`OnData` → `X224ConnectionConfirm::parse` → `TpktHeader::parse` 读到的是 MCS 的第一个字节（`0x7f` 或 `0x0a`）而非 `0x03` → 返回 `Status::InvalidVersion` → `Fail("malformed MCS Connect Response")`。**在 TLS 之后立刻失败**，日志看起来像「服务器发的东西不对」，实际是本地的帧契约错配 |
| 3 | **S4** | 无 DER 分帧器 | **具体失败**（**推理**，依赖服务器是否拆包）：若服务器把一条 TSRequest 拆进两个 TLS record，安全层拿到半个 DER → `TsRequest::Decode` 返回 `kTruncated`（`ts_request.cpp:81` 的 `remaining() < length`）→ `Fail("cannot decode TSRequest")`。若服务器一条消息一个 record（本目标很可能如此，见 `docs/spec/security-layer.md:934-936` 要求客户端不分片），则**不触发**。**所以这条是「保险」而非「确定的阻塞」**——但成本极低（一个 TLV 累积器），不做就要赌服务器实现 |
| 4 | **S2** | EUAR 阶段 | **具体失败**（**推理**）：若 EUAR=`0x00000000`（SUCCESS），`TpktStream` 会把 4 字节当垃圾跳过（`framing.cpp:52`，`dropped_=4`），然后**正常解析**后续 MCS PDU → **能跑通**，只是 `dropped_bytes()` 非零。若 EUAR=`0x05`（DENIED），同样跳过 → 客户端继续发 MCS Connect Initial → 服务器断开 → 表现为「连上后立刻掉线，无错误码」。**所以 S2 不阻塞成功路径，只丢失拒绝信息**。仍列入最小集，因为：不做就**无法区分「成功」与「被拒」**，联调时会浪费大量时间在「为什么掉线」上 |
| 5 | **S1** | nonce 随机 | **不阻塞连通性**（重要区分）：nonce 全零时，客户端发 `clientNonce = 0*32`，服务器用**收到的**这个 nonce 算 `ServerToClientBindingHash` → 与客户端的期望值**匹配** → 第 4 步通过。所以握手**成功**。**失败表现**：无。**风险表现**：`exported_session_key = nonce[8..24) = 0*16`，双方用全零 key 派生 SEAL/MIC 密钥 → 所有 CredSSP 机密性归零，且**无任何错误信号**。列入最小集是因为它是「静默不安全」，但**必须明确：它不是连通性阻塞** |
| 6 | **S15**（最小驱动） | 没有驱动，以上全部无法执行 | **具体失败**：`rtsc_probe` 在打印 CCF 后就 `closesocket`（`tools/rtsc_probe/main.cpp:226`），根本不会启动 TLS。表现为「工具只输出 CCF 就退出」 |

**最小集 = {S18, S3, S4, S2, S1, S15}，6 项。**

**明确排除在最小集之外的**（不阻塞真机连通）：
- S9/S10（真实时序下服务器不会在 Finished 后立刻发应用数据，见 §11.3）
- S5/S6（本服务器恒回 version=6，见 `docs/spec/security-layer.md:684`）
- S7/S8（只影响错误分类与证书策略，不影响 `kInsecure` 下的连通）
- S11（只影响 MITM 防护）
- S12/S13/S14/S16/S17/S19/S20/S21（诊断性/跨平台/暴露面）

#### 15.3.2 「能否跑通到 MCS Connect Initial」的推理链

**结论：未知（不能断言「能」）。** 理由是存在**两个已确认的、无法用代码修复的未知**，
以及一个环境缺失。下面逐环节标注证据等级。

| 环节 | 状态 | 依据 |
|---|---|---|
| 1. TCP 连接 `192.168.1.7:3389` | **已验证** | `evidence/handshake-001.md:5-6`（`rtsc_probe --connect` 实跑） |
| 2. 发 CRQ（`0x0B`）→ 收 CCF（`selectedProtocol=0x08`） | **已验证** | `evidence/handshake-001.md:26-41`；`tests/test_connect_machine.cpp:172-187` |
| 3. TLS 握手（TLS1.2，AES256-GCM） | **已验证** | `evidence/schannel-tls-backend.md`（`round 1: 846 bytes` / `round 2: 51 bytes`，`header=13 trailer=16 maxmsg=16384`）；`tests/test_tls.cpp` 26 条 |
| 4. 取服务器公钥（S18 修后） | **已验证可行**（能力存在，接线缺失） | `src/net/tls_schannel.cpp:371-384`（锚点 `Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {` .. `}`） 实现存在；`tests/test_tls.cpp:826` 证明能取到；缺的只是调用点（S18） |
| 5. CredSSP 第 1 步（裸 NTLM NEGOTIATE） | **已验证**（离线，字节级） | `tests/test_credssp_sm.cpp:105-126`（40 字节、签名、type=1） |
| 6. CredSSP 第 2 步（收 CHALLENGE） | **未验证（真机）** | 需要正确凭据才能走到；`docs/spec/security-layer.md:1728-1737` 明确列为本项目未验证 |
| 7. CredSSP 第 3 步（AUTHENTICATE + pubKeyAuth） | **未验证（真机）**，且**拼接顺序 U3 未验证** | `docs/spec/security-layer.md:1706` 自认「C 级推导，未通过服务器接受验证」。**这是最大风险点**：若顺序错，第 4 步必失败，且错误码看起来像凭据错 |
| 8. CredSSP 第 4 步（pubKeyAuth 回显） | **未验证（真机）** | `docs/spec/security-layer.md:1732` |
| 9. CredSSP 第 5 步（authInfo） | **未验证（真机）**，SEAL seq=1 假设未验证 | `docs/spec/security-layer.md:1713`、`:1737` |
| 10. EUAR 4 字节 | **未验证（真机）** | `docs/spec/security-layer.md:1705`（「C 级推导，未抓到包验证」） |
| 11. MCS Connect Initial（TLS 内） | **已验证**（字节级，离线） | `tests/test_connect_machine.cpp:162-170`（roundtrip 通过解析器） |
| 12. 收 MCS Connect Response | **已验证**（离线，用官方 dump） | `tests/test_connect_machine.cpp:70-92`、`:228-241` |

**推理链（明确标注推理部分）**：

```
[已验证] 1-3 能到 TLS 握手完成
   ↓
[S18 修后] 公钥可得（能力已验证，接线是本次新增）
   ↓
[推理] 第 1-2 步能通 —— 因为第 1 步的字节已被离线测试锁定（:105-126），
       第 2 步只是「收一条 DER」，S4 的 TLV 累积器覆盖它
   ↓
[未知] 第 3 步能否被服务器接受 —— 取决于 U3（pubKeyAuth 拼接顺序）。
       若顺序错：服务器回 errorCode，第 4 步失败，整个流程止步于此。
       这不是代码能修的，是「规范有歧义、需实测裁决」的问题。
   ↓
[未知] 第 4-5 步 —— 依赖第 3 步成功，且 SEAL seq 假设（U8）成立
   ↓
[未知] EUAR 真实字节 —— 依赖第 5 步成功，且需正确凭据
   ↓
[S2/S3 修后 + 推理] EUAR 之后能到 MCS Connect Initial：
       S3 保证帧契约（已由 tests/test_connect_machine.cpp:162 离线证明）
       S2 保证 4 字节被正确消费（新代码，需 T1/T3 绿证）
   ↓
[已验证离线] 收 Connect Response 后能继续（:228-241）
```

**必须说清的三个「不能断言」**：

1. **缺凭据**。`docs/spec/security-layer.md:1728-1737` 明确记录：本项目**从未**用能登录的账号跑过第 4/5 步。
   没有凭据，第 6–10 环节全部无法验证。主代理在本轮任务中未提供凭据。
2. **U3（pubKeyAuth 拼接顺序）未裁决**。规范伪代码与散文矛盾（`docs/spec/security-layer.md:750-756`），
   实现选了 `magic‖nonce‖SPK`（`src/credssp/credssp.cpp:19-28` 的 `HashWithMagic`）。
   **若服务器要求另一种顺序，第 3 步必被拒**。这是「代码正确但可能不符合服务器期望」的情形，
   无法通过任何本地测试发现（`MakeServerEchoForTest` 用同一套逻辑，会一起错，见 §5.6.3 的局限说明）。
3. **U6（服务器在第 5 步后发 alert 还是 errorCode）未验证**，影响 S7 的必要性判断，不影响连通性本身。

**因此对「能否跑通」的回答是：**

> **代码层面的已知阻塞可以在最小集（6 项）内全部消除；
> 但端到端能否跑通取决于 U3 的裁决结果与是否有可用凭据，二者当前都未知。
> 我不能断言「能跑通」，只能断言「消除 6 项后，失败点将只可能落在 U3 / 凭据 / 服务器策略这三处，
> 且每一处都会产生可归因的错误码」。**

### 15.4 对 S20（密码双份）的最终建议

#### 15.4.1 具体改动（三处）

**改动 1：`src/proto/connect_machine.cpp:165-168` —— 按协商结果分支**

现状（`:165-168`）：
```cpp
        if (credentials_.autologon) pdu.info.flags |= info::kAutoLogon;
        pdu.info.domain = credentials_.domain;
        pdu.info.user_name = credentials_.user_name;
        pdu.info.password = credentials_.password;
```

改为：
```cpp
        // Enhanced RDP Security (TLS/CredSSP): the user was already
        // authenticated by CredSSP's TSCredentials (security-layer.md 5.5), so
        // TS_INFO_PACKET.Password is only meaningful for autologon
        // (mcs-domain.md:1132) and the reference dump sends it empty
        // (mcs-domain.md:2057, :2064). Sending it again doubles the exposure.
        const bool enhanced = state_.negotiated_protocol != kProtocolRdp;
        const bool send_password = !enhanced || credentials_.autologon;
        if (credentials_.autologon) pdu.info.flags |= info::kAutoLogon;
        pdu.info.domain = credentials_.domain;
        pdu.info.user_name = credentials_.user_name;
        pdu.info.password = send_password ? credentials_.password : std::string();
        pdu.info.alternate_shell = credentials_.alternate_shell;
        pdu.info.working_dir = credentials_.working_dir;
```

**为什么用 `!enhanced || autologon` 而不是 `!enhanced`**：
`INFO_AUTOLOGON`（`mcs-domain.md:1132`）的语义是「使用用户名/域/密码自动登录」。
若调用方**显式**要求 autologon（`credentials_.autologon == true`），则密码是这个功能的必要输入，
清空它会让 autologon **静默失效**（服务器看到空密码 + AUTOLOGON 标志 → 登录失败或走交互登录）。
所以判据必须是「增强安全 **且** 未要求 autologon」才清空。

#### 15.4.2 非 NLA（`PROTOCOL_RDP`）路径如何保证不丢密码

| 场景 | `negotiated_protocol` | `autologon` | `send_password` | 结果 |
|---|---|---|---|---|
| 标准 RDP 安全（无 TLS） | `0x00000000` | 任意 | `true` | 密码**照常发送**（`!enhanced == true`）→ **不丢** |
| NLA/CredSSP，默认 | `0x08` | `false` | `false` | 密码清空（符合 `mcs-domain.md:2057` 的权威 dump） |
| NLA/CredSSP，显式 autologon | `0x08` | `true` | `true` | 密码发送（尊重调用方意图） |

**自洽性检查（这是本条的关键）**：

1. **标准 RDP 路径不受影响**。`state_.negotiated_protocol` 在 `PROTOCOL_RDP` 时等于
   `kProtocolRdp`（`0x00000000`，`src/proto/connect_machine.cpp:211` 的 `else` 分支赋这个值；
   且 `kProtocolRdp` 的枚举值是 0，见 `include/rtsc/proto/rdp_neg.h:20`）。
   `!enhanced` 为真 → `send_password` 恒真 → **行为与现在完全一致**。
2. **`autologon` 路径不受影响**。显式要求 autologon 时仍发密码。
3. **唯一行为变化**：`negotiated_protocol != 0` 且 `autologon == false` 时清空。
   这正是规范样例的形态，且**该字段在此配置下本来就无意义**（`mcs-domain.md:1132`）。
4. **不会引入新缺陷**：`pdu.info.password` 是 `std::string`（`include/rtsc/proto/client_info.h` 的
   `TSInfoPacket`），清空后 `build()` 会写 `cbPassword = 0`（`src/proto/client_info.cpp` 按
   `password.size()` 计算长度），与权威 dump 的 `00 00`（`mcs-domain.md:2057`）一致。
   **不需要额外处理 NULL 终止**（现有编码逻辑已处理，`tests/test_client_info.cpp` 覆盖）。

#### 15.4.3 我**不**建议做的（并说明理由）

| 建议（乙的或常见的） | 我不建议的理由 |
|---|---|
| 把 `ConnectMachine::Credentials::password` 改名为 `client_info_password` | **不改语义**，只是让不一致更显眼。§15.4.1 的分支已经消除了「无条件发送」这个真正的缺陷。改名会让 `tests/test_connect_machine.cpp:438` 等 4 处调用点全改，收益为零 |
| 引入 `struct rtsc::sec::UserCredential` 作唯一载体 | **方向对，但不属最小集**。它是架构改进（消除「编排层成为第 0 份」的问题），需要改 `ConnectMachine` 与 `CredsspClient` 两个构造函数签名 + 所有调用点。**建议作为 S20 的后续（记为 S20b），不阻塞接入**。当前 `S20` 的分支修复已消除「NLA 下多送一份」这个**可观测**的缺陷 |
| 析构清零（`SecureZeroMemory`） | **降为 P2，且不解决份数问题**。`std::string` 的 SSO（≤15 字节）拷贝在栈上，无法可靠清零；真正的修法是**减少份数**（S20b），不是清零。若要做，应做成独立的 `SecureString` 类型，属另一个工作项 |
| 把 `credssp::Credentials` 改成引用 `ConnectMachine::Credentials` | **会造成新缺陷**：两者字段名不同（`user_name` vs `user`，`connect_machine.h:97` vs `credssp.h:25`），字段集也不同（`ConnectMachine::Credentials` 有 `alternate_shell`/`working_dir`/`autologon`）。强行合并会让 CredSSP 依赖 proto 的 UI 字段，违反依赖方向 |

#### 15.4.4 S20 的验证

**红证**：新增 `tests/test_connect_machine.cpp` 用例：
```
machine_client_info_password_is_empty_under_enhanced_security:
  cfg.requested_protocols = kProtocolHybridEx
  credentials.autologon = false
  credentials.password = "secret"
  → 走完 join 序列，取 ClientInfoPdu，断言 pdu.info.password.empty()
当前：非空 → 必失败
```

**绿证**（三条同时成立才算修好）：
1. 上述用例变绿；
2. `machine_client_info_autologon_flag_follows_credentials`（`tests/test_connect_machine.cpp:438`）仍绿
   （它测 autologon 标志，与本改动正交）；
3. `machine_client_info_payload_decodes_back`（`:393`）仍绿（它用 `PROTOCOL_RDP` 路径，
   本改动不触碰）。

### 15.5 我仍不确定的

> 以下每一条都是我在写清单时**发现自己无法确定**的。不假装确定。

| # | 不确定项 | 为什么不确定 | 如何消除 |
|---|---|---|---|
| **N1** | **S10 的修复会不会破坏现有 26 个 TLS 用例** | 我核对了 `tests/test_tls.cpp` 全文：**没有任何 `consumed` 断言**（`Select-String 'consumed'` 只命中 `:175`/`:192` 局部变量，`:745`/`:792` 是 `Send` 的）。但 `boundary1_record_split_into_feeds_yields_needmoreinput_then_ok`（`:369`）、`boundary3`（`:453`）、`boundary10`（`:589`）会经过 `Handshake`。**D1 改变了「一次调用喂多少」的粒度**（从「全部」变成「一条 record」），可能改变这些用例观察到的 `status` 序列。**我只能说「断言层面不冲突」，不能说「行为层面不冲突」** | 执行时先只改 `Handshake`，跑 `rtsc_tls_tests`，若 `boundary1/3/10` 变红，逐个看它们的期望是否仍然合理（它们测的是「分片喂入」而非「一次喂多少」，理论上应仍绿，但**未实测**） |
| **N2** | **S10 修复后 `consumed` 的语义与 `probe_s10e` 的包装器是否完全等价** | `probe_s10e` 的 `FixedBackend` 是**包装器**，它把 `inner_->Handshake` 的返回值原样透传，只在 `handshake_complete()` 后把 `pending_` 尾部转给 `Receive`。真实改法是把这个逻辑**搬进** `SchannelTransport`，涉及成员变量（`hs_buffer_`）与 `Receive` 的交互（`t:233` 的 `rx_buffer_` 插入点）。**「包装器能工作」不等于「搬进去能工作」**：包装器里 `inner_->Receive` 和 `tail_` 是两个独立缓冲，搬进去后要合并成一个 `rx_buffer_`，顺序（尾部在前还是后）会影响解密顺序 | 执行时按 §14.2 的 D1 实现后，**必须重跑 `probe_s10e` 的四个场景（G1–G4）作为独立探针**，而不只依赖单元测试 |
| **N3** | **S7 的修复形态完全依赖 U4，而 U4 未做** | 我在 §6 S7 里写「在 `Receive` 里对 `SEC_E_ILLEGAL_MESSAGE` 等状态尝试提取 alert」，但**不知道 SChannel 在服务器发 alert 时到底返回哪个 status**（可能是 `SEC_E_ILLEGAL_MESSAGE`，也可能是 `SEC_I_CONTEXT_EXPIRED` 前先给 `SEC_E_OK` + 明文 alert record）。**不同返回值对应完全不同的改法** | 先做 U4：用 `RawServer` 的 `ApplyControlToken` 主动发 `access_denied`，观察 `client_->Receive` 的 `status` 与 `plaintext`。**U4 未完成前，S7 的「改什么」列是推测** |
| **N4** | **S19 的修复是否会引入「静默降级」** | 修法「1.3 时也带 1.2」会让 `AcquireCredentialsHandle` 成功，但若服务器只支持 1.2，握手会**降级到 1.2 并成功**，然后 `EnforceVersionWindow`（`t:568-575`）返回 `kInternal`。**这时的错误是 `kInternal`（「环境问题」）而非 `kUnsupported`/`kProtocolError`**，语义不准。是否要把 `EnforceVersionWindow` 的失败也映射为 `kUnsupported`？我不确定哪个更合适 | 定案时决定；我倾向 `kUnsupported`（「本配置无法满足」比「内部错误」准确），但这会改 `t:172` 的既有映射，需评估 `tests/test_tls.cpp:868` 的期望 |
| **N5** | **S20 的 `send_password` 判据在「RDSAAD / RDSTLS」下是否正确** | 我只验证了 `PROTOCOL_RDP` 与 `PROTOCOL_HYBRID_EX` 两端。`kProtocolRdstls`（`0x04`）与 `kProtocolRdsaad`（`0x10`）（`include/rtsc/proto/rdp_neg.h:23-25`）也属「非 RDP」，按我的判据会清空密码。**但 RDSTLS 是重定向场景，密码语义可能不同**（`docs/spec/security-layer.md` 未覆盖 RDSTLS 的 Client Info 密码要求） | 本轮不支持 RDSTLS/RDSAAD，但**必须在 `:165` 的注释里写明「判据是 `!= kProtocolRdp`，RDSTLS/RDSAAD 未验证」**，避免未来误以为已覆盖 |
| **N6** | **S3 用 `WrapTpkt` 还原是否会在超大 PDU 上静默失败** | `WrapTpkt` 对 `size > kMaxPayload`（65528，`include/rtsc/proto/tpkt.h:18`）返回**空 vector**（`src/proto/framing.cpp:100`）。而 `TpktStream` 能接受的最大 payload 是 `0xFFFF - 4 = 65531`（因为 `TpktHeader::kMaxLength = 0xFFFF`，`tpkt.h:15`）。**存在 3 字节的缝隙**：65529–65531 的 payload 能被 `TpktStream` 取出，但 `WrapTpkt` 拒绝。**我不确定 RDP 是否可能产生这个尺寸的 PDU**（MCS Connect Response 是 337 字节，但未来 Share Data 可能更大） | 安全层必须检查 `WrapTpkt` 的返回值是否为空，为空则 `kProtocolViolation` + `detail` 带尺寸。**这是必须写进实现的分支，不能假设「不会发生」** |
| **N7** | **S2 的 `euar_optional` 配置在真实服务器上是否需要** | 本目标（`192.168.1.7`）协商 `0x08`，按规范 MUST 发 EUAR。但 U2（EUAR 真实字节）未验证——**如果服务器实际上不发**（比如它把 `0x08` 当作 `0x02` 处理），严格模式会让连接**在正确凭据下也失败**。我不知道是否需要默认放宽 | 保持默认严格（符合规范），但**在 U2 完成前，联调失败时必须先试 `euar_optional=true` 排除这一项**。这应写进联调 checklist |
| **N8** | **S18 的「空公钥即失败」会不会误伤 v2/3/4 路径** | `BuildStep3`（`c:228-235`）在 `version_ < kFirstHashVersion` 时直接用 `server_public_key_` 原文。若公钥为空，v2/3/4 会发空 `pubKeyAuth` → 服务器必拒。**我的「空则 Fail」建议在两条路径上都正确**，但我不确定是否有合法的「空公钥」场景（例如某种受限管理员模式）。`docs/spec/security-layer.md` 未提及 | 保守：空则 `kUnsupported` + `detail="server public key not set"`。若未来发现合法场景，再加开关 |
| **N9** | **S11 的 MAC 校验会不会破坏 `MakeServerEchoForTest`** | `MakeServerEchoForTest`（`c:364-391`）用 `Seal(seal, sign, recv_seq_, plain, s)` 产出带正确 MAC 的 echo（`recv_seq_` 当时为 0）。S11 加上校验后，`OpenReceive` 会用 `recv_seq_` 重算——**理论上匹配**，但 `MakeServerEchoForTest` 是 `const` 方法且不推进 `recv_seq_`，而 `OpenReceive` 会 `++recv_seq_`（`c:360`）。**我不确定多次调用 `MakeServerEchoForTest` 是否会产生「同一 seq 的多个 echo」这种不真实场景** | 加校验后跑 `rtsc_credssp_sm_tests` 的 5 个用到 echo 的用例（`:283`、`:317`、`:441`、`:478`、以及 `:179` 的 MIC 用例）。若变红，说明测试夹具需要更新（用递增 seq 生成 echo），而不是修复本身错 |
| **N10** | **§15.1 的行号在多项修复后必然漂移** | 本章所有行号是**当前**行号。批 1 改 `credssp.cpp` 后，`c:241`/`c:300`（S6 的依赖行）会下移；批 2 改 `src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`） 后，`:232`（批 0 后；锚点 `if (closed_) return MakeError(Status::kClosed   (inside Receive)`）（S9）、`t:371`（S8）会下移。**执行时必须重新定位，不能照抄本章行号** | 执行 AI 每次改前 `Select-String` 重新定位锚点（用代码片段而非行号）。本章行号仅用于「定案时确认改的是哪一处」 |
| **N11** | **S21 的三层拆分是否会影响 `verify.ps1` 的 16 个 ctest** | `verify.ps1` 用 `add_test` 注册的 16 个套件名（`CMakeLists.txt:140-155`）不变，但 `rtsc_tls` 从「单一 target」变成「门面 + 后端」，`rtsc_tls_tests` 链接的是 `rtsc_tls`（`CMakeLists.txt:106`）→ 门面会传递链接到后端，**理论上透明**。但非 Windows 上 `rtsc_tls_tests` 会因为「无后端」而全部失败（`CreateTlsTransport` 返回 nullptr）→ **`verify.ps1` 在 Linux 上会红** | 需要在 `CMakeLists.txt` 里把 `rtsc_tls_tests` 也包进 `if(WIN32)`，或在测试里跳过。**我不确定项目是否要求 Linux 上 16 套件全绿**（`verify.ps1` 是 PowerShell，明显是 Windows 专用） |

---

## 16. U4 / N1 / S21 实测（内容已并入 §17）

> 本节原计划独立成章，但实测与反向互审是同一轮工作、共用同一批探针，
> 故正文合并到 §17，此处只留索引，避免读者找不到：
>
> | 原 §16 任务 | 实际位置 | 结论一句话 |
> |---|---|---|
> | **任务 A：U4（SChannel 对 TLS alert 的返回）** | **§17.6** | `DecryptMessage` 报 `SEC_I_CONTEXT_EXPIRED (0x00090317)`；alert 的 level/description **不可读**；`SEC_E_ILLEGAL_MESSAGE` 零出现 |
> | **任务 B：N1（D1 对 26 个 TLS 用例的行为影响）** | **§17.7** | **不破坏** `boundary1/3/10`（36 checks / 0 failures，baseline 与 D1 完全一致） |
> | **任务 C：S21 的 Linux 可验证性 + 具体 CMake 改动** | **§17.5** | 三层拆分；`rtsc_proto` 链接行逐字不变；`rtsc_tls_tests` 连同 `add_test` 一起进 `if(WIN32)`；`rtsc_security` 在非 Windows 上是**完整实现**（运行期 `kUnsupported`），不是空实现 |
>
> 探针：`F:\rtsc\.tmp\probe_u4\`（`probe_u4.cpp`…`probe_u4f.cpp`、`probe_n1.cpp`）。
> 输出：`F:\rtsc\evidence\u4\*.out.txt`（7 个文件）。

---

## 17. 反向互审 + 定案材料

> **行号基线**：本章所有行号均为本轮重新读取（`audit-a.md` 已 2052 行；
> `tls_schannel.cpp` 748 行、`tls.h` 208 行、`test_tls.cpp` 893 行、`CMakeLists.txt` 193 行）。
> 探针与输出：`F:\rtsc\.tmp\probe_u4\`（7 个可执行）+ `F:\rtsc\evidence\u4\*.out.txt`。
> **未改任何工程代码。**

### 17.1 逐条回应乙的 4 处错误

| # | 乙的指控 | 我的结论 | 证据 | 订正后的文本 |
|---|---|---|---|---|
| **A-E1** | 我 `:654-655` 说「可以在没有任何 SSPI 的环境（Linux/Android 构建）跑完整的安全层测试」，与 `:1036-1037` 的「前提是先修 B19」矛盾 | **确认（乙对）** | `audit-a.md:654`（`这一级的价值：可以在没有任何 SSPI 的环境…跑完整的安全层测试`）与 `:1036`（`前提是先修 B19（§12.1 的三层拆分）`）并存 | `:654-655` 改为：**「这一级的价值：在 `rtsc_tls` 完成 §12.1 三层拆分之后，可以在没有 SSPI 的环境（Linux/Android 构建）跑完整的安全层测试——因为 `ScriptedTlsTransport` 实现的是 `tls.h:124` 的平台中立接口，不需要任何 SChannel。拆分之前，`rtsc_tls` 这个 target 本身在非 Windows 上编译不过（S21），所以那时连脚本传输都链接不起来。」** |
| **A-E2** | 我 S9 引 `src/net/tls_schannel.cpp:432`（锚点 `closed_ = true;  (in Shutdown)`）（锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`） 说「`Shutdown()` 也会置 `closed_=true`」，实际 `:431` 是 `if` 条件，赋值在 `:432`，且**失败路径（`:435`）不置** | **确认（乙对，且我漏了 B13）** | `:431`（批 0 后；锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`）=`if (st == SEC_E_OK \|\| st == SEC_I_CONTINUE_NEEDED) {`；`t:432`=`closed_ = true;`；`:435`（批 0 后；锚点 `return MakeError(Status::kOk, st, "shutdown best effort");`）=`return MakeError(Status::kOk, st, "shutdown best effort");`（**无 `closed_` 赋值**） | S9 的证据列改为 **`src/net/tls_schannel.cpp:432`（锚点 `closed_ = true;  (in Shutdown)`）（`closed_ = true`，仅在 `:431` 的成功分支）**；并**新增 S22 = 乙的 B13**（见下） |
| **A-E3** | 我 `:64` 引 `tls.h:142` 作「append-only」证据，实际 `:142` 是分节注释，真句在 `:146-147` | **确认（乙对）** | `tls.h:142`=`// ---- receive application data -------------------------------------------`；`tls.h:146-147`=`` // `plaintext` is append-only: existing content is preserved and new bytes are `` / `` // appended. One call may append plaintext from several records. `` | `:64` 的证据改为 **`include/rtsc/net/tls.h:146-147`**（并在 `:148-150` 补「`kClosed` 保留明文、调用方先排空」）。`:293`、`:379`、`:1567`、`:1670` 同引用需同步改为 `:146-147`（其中 `:1670` 说「`:142` 的标题就是 receive application data」——这句**本身正确**，因为 `:142` 确实就是那个标题，保留） |
| **A-E4** | 我 `:1740` 写「P1 × 8（… + S10 由 P1 降为 P2 后此处不变）」自相矛盾 | **确认（乙对，且我已在 `:1744-1749` 订正）** | `audit-a.md:1740` 原文确为矛盾表述；`:1744-1749` 的最终表已改为 P1 × 7 | 已在 `:1744-1749` 修正，无需再动。**此处留痕：`:1740` 是中间稿残留，以 `:1744-1749` 为准** |

#### 17.1.1 由 A-E2 引出的新缺陷 S22（乙的 B13）

| 编号 | 级别 | 症状 | 证据 | 影响 | 建议 |
|---|---|---|---|---|---|
| **S22** | P2 | `Shutdown()` 在非 `SEC_E_OK`/`SEC_I_CONTINUE_NEEDED` 路径返回 `kOk` 但**不置 `closed_`** → `closed()` 说谎 | `src/net/tls_schannel.cpp:431`（锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`）（成功分支才置）、`:432`（赋值）、`:435`（批 0 后；锚点 `return MakeError(Status::kOk, st, "shutdown best effort");`）（失败路径直接返回，`closed_` 保持 false） | 调用方见 `closed()==false` 会以为还能继续用，但 `shutdown_sent_` 已为真（`:425`）→ 再次 `Shutdown()` 在 `:406` 返回空且**永不重试**；`Receive` 也仍可进入（`closed_` 为假）。状态机出现「已发关闭但未标记关闭」的第三态 | `:435` 改为 `closed_ = true; return MakeError(Status::kOk, st, "shutdown best effort");`，或引入 `shutdown_failed_` 并让 `closed()` 返回 `closed_ \|\| shutdown_failed_` |

**缺陷总数：20 → 22**（S1–S22；其中 S21=乙的 B19、S22=乙的 B13）。

### 17.2 逐条回应乙的 6 条硬条件

| 条件 | 结论 | 理由 | 落到哪里 |
|---|---|---|---|
| **C1** 先修 B19/S21 | **完全接受** | 我 §12.1 已独立得出同一结论；乙的补充「不是链接不到 SChannel，而是编译期过不去」是对的（`t:29-32`（锚点 `#include <windows.h>` .. `#include <wincrypt.h>`）无条件 include，`#if/#ifdef/#ifndef` 计数 0/0/0，`CMakeLists.txt:51` 无条件 `add_library`） | **批 0 = S21**（§17.4） |
| **C2** 先补 B01/S18 | **完全接受** | 我 §11.4 已补为 S18（P0）；没有它 `pubKeyAuth = SHA256(magic‖nonce‖"")`，第 4 步必失败，**走不到 EUAR** | **批 1 = S18**（与 S1 同批） |
| **C3** `Step({kNone})` 必须消歧（加 `kStart`） | **接受（乙对，我 §13 的草案确实有这个缺陷）** | 乙举的反例成立：`Step({kNone})` 既表示「启动」又表示「pump」，重复启动无法检出。我 §13 草案里没有 `kStart`，只有 `Input::Kind::kNone`——**这是我草案的实质缺陷**，不是风格问题。详见 §17.3 的 `kStart` 方案 | **§17.3 接口**：`Input::Kind` 增加 `kStart`，首调必须是 `kStart`，重复 `kStart` → `kProtocolViolation` |
| **C4** EUAR 不得下推 proto | **完全接受** | 我 §12.6 已论证四条理由；乙已撤回 proto 方案（`audit-b.md:1430`「EUAR 归属：安全层（甲对，我撤回 proto 方案）」） | 无需改动，已在 §13.3.2 落地 |
| **C5** 采纳 `SecurityError` 四元组 | **接受，但要说清「四元组」是乙的概括、我的实际是五字段** | 见 §17.2.1 的逐字对照。**乙没有提出自己的形状**（`audit-b.md:1426` 明确「采纳甲的设计」），所以不存在「乙的更好」这一情形。我的形状保留，但按乙的提醒**补一条构造器**避免调用点漏填 `space` | **§17.3 接口** |
| **C6** `WrapTpkt` 返回空必须检查（我的 N6） | **完全接受** | 主代理已独立验算 65529/65530/65531 三档全部 MISMATCH。我 §15.5 N6 已列；这里升级为**接口契约的一部分**（`Output` 的错误路径必须覆盖） | **§17.3 接口**的 `kProtocolViolation` 分支 + §17.4 批 3 的红证 |

#### 17.2.1 C5 的逐字对照（乙说「四元组」，我实际是五字段）

| 字段 | 我的 §13 草案（`audit-a.md:552-585`） | 乙的概括（`audit-b.md:1387`） | 差异 |
|---|---|---|---|
| `kind` | `ErrorKind`，9 个值 | `kind` | 一致 |
| `stage` | `ErrorStage`，5 个值 | `stage` | 一致 |
| `space` | `NativeSpace`，6 个值 | `native_space` | **仅命名差异**（我写 `space`，乙写 `native_space`） |
| `native_code` | `int32_t` | `native_code` | 一致 |
| `detail` | `std::string` | `detail` | 一致 |

**结论：不存在「乙的形状更好」这回事** —— 乙明确写的是「采纳甲的设计」（`audit-b.md:1426`），
他的「四元组」是对我五个字段的**计数口径**（把 `kind` 当作「类型」而非「元组成员」）。
**我采纳他的命名 `native_space`**（更自解释，且与 `native_code` 成对），其余不变。
另按 C5 的意图补一个**带 `space` 的工厂**，从类型层面阻止「填了码没填命名空间」。

### 17.3 定案材料 A：接口最终形态

> 合并来源：§13 草案 + C1–C6 + `native_space` 改名 + `kStart` 消歧 + D1 的 `consumed` 语义 + N6 的 `WrapTpkt` 空返回。
> 这是**唯一一份**，取代 §13.1/§13.2 的草案（§13 保留作历史）。

#### 17.3.1 `include/rtsc/sec/security_error.h`

```cpp
// Unified error surface for the external security layer.
// Reference: docs/spec/security-integration.audit-a.md sections 5.5, 13, 17.3.
//
// RULE 1  native_code is copied bit-for-bit and never re-encoded.
//         `native_space` says which library produced it, because the same
//         int32_t means different things in each: 0x80090308 is SChannel's
//         SEC_E_INVALID_TOKEN (tls.h:59) but could also be a CredSSP errorCode
//         NTSTATUS (credssp.cpp:101).
// RULE 2  `detail` is for humans only. No branch may inspect it.
//         ConnectState::error is a std::string (connect_machine.h:57); that is
//         exactly why it cannot drive classification.
#pragma once

#include <cstdint>
#include <string>

namespace rtsc::sec {

enum class Stage : uint8_t {
    kTlsHandshake = 0,  // TlsTransport::Handshake
    kCredssp,           // CredsspClient::Start / OnServerResponse
    kEuar,              // the 4-byte Early User Authorization Result
    kTlsIo,             // TlsTransport::Receive / Send
    kClose,             // shutdown / drain
};

enum class Kind : uint8_t {
    kNone = 0,
    kWouldBlock,           // not an error: more input needed
    kCertificateRejected,  // local policy rejected the peer certificate
    kCredentialRejected,   // wrong user/password (NTSTATUS, or TLS alert 49)
    kAuthorizationDenied,  // EUAR 0x05, or STATUS_LOGON_TYPE_NOT_GRANTED
    kProtocolViolation,    // peer violated the protocol
    kUnsupported,          // this build/platform cannot serve the request
    kInternal,             // local bug or environment failure
    kClosedByPeer,         // clean close, fully drained
    kTruncated,            // peer closed mid-unit (半帧)
};

// Namespace of native_code. Renamed from §13's `Space` per audit-b C5.
enum class NativeSpace : uint8_t {
    kNone = 0,
    kSspi,         // SECURITY_STATUS (tls.h:59)
    kNtstatus,     // CredSSP errorCode (credssp.cpp:101)
    kTlsAlert,     // TLS alert description byte
    kWin32,        // GetLastError
    kLocal,        // produced by this layer
};

struct Error {
    Kind kind = Kind::kNone;
    Stage stage = Stage::kTlsHandshake;
    NativeSpace native_space = NativeSpace::kNone;
    int32_t native_code = 0;   // verbatim; never remapped
    std::string detail;        // human readable only

    bool ok() const noexcept { return kind == Kind::kNone; }
    bool fatal() const noexcept {
        return kind != Kind::kNone && kind != Kind::kWouldBlock &&
               kind != Kind::kClosedByPeer;
    }

    // Factory that makes it impossible to set a code without its namespace.
    static Error Make(Kind k, Stage s, NativeSpace ns, int32_t code,
                      std::string detail = {}) {
        Error e;
        e.kind = k;
        e.stage = s;
        e.native_space = ns;
        e.native_code = code;
        e.detail = std::move(detail);
        return e;
    }
};

}  // namespace rtsc::sec
```

#### 17.3.2 `include/rtsc/sec/security_layer.h`

```cpp
// External security layer: TLS handshake -> CredSSP five steps -> EUAR -> MCS.
// Reference: docs/spec/security-integration.audit-a.md sections 3, 5.3, 5.4,
// 13, 14 (D1), 17.3.
//
// WHY A SINGLE OWNER: the plaintext stream is cut by four rules in sequence
// (TLS record / DER TSRequest / fixed 4-byte EUAR / TPKT). The rule in force is
// a function of the phase, so phase and plaintext buffer MUST share an owner
// (section 3.1).
//
// THREADING: not thread safe. One instance, one connection, one thread.
// LIFETIME: created AFTER ConnectMachine::OnData(CCF) returned
//   phase == kAwaitExternalSecurity (connect_machine.cpp:217). The plaintext
//   X.224 exchange before that is NOT this class's responsibility.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "rtsc/credssp/credssp.h"
#include "rtsc/net/tls.h"
#include "rtsc/proto/framing.h"
#include "rtsc/sec/security_error.h"

namespace rtsc::sec {

using Bytes = std::vector<uint8_t>;

struct Config {
    // ---- TLS ----
    std::string peer_host;
    std::string sni;
    rtsc::tls::CertPolicy cert_policy = rtsc::tls::CertPolicy::kTofu;
    uint16_t min_version = 0x0302;   // TLS1.2
    uint16_t max_version = 0x0304;   // TLS1.3
    std::array<uint8_t, 32> pinned_spki_sha256{};
    bool pin_is_set = false;

    // ---- CredSSP ----
    credssp::Credentials credentials;
    uint32_t credssp_version = credssp::kMaxVersion;

    // ---- EUAR ----
    // True iff RDP_NEG_RSP.selectedProtocol has PROTOCOL_HYBRID_EX (0x08).
    // Caller derives it from ConnectState::negotiated_protocol
    // (connect_machine.h:46). False skips kAwaitEuar entirely (SSL / HYBRID).
    bool expect_euar = false;
    // Escape hatch for non-Microsoft servers that omit the EUAR despite
    // negotiating HYBRID_EX. Default false: the spec says MUST
    // (security-layer.md:365-366).
    bool euar_optional = false;

    // ---- limits ----
    size_t max_ts_request = 65536;      // bound on one DER frame
    size_t max_plaintext_buffer = 1u << 20;
};

// What the caller must do next. Mutually exclusive, one per Step.
enum class Want : uint8_t {
    // Call Step({kNone}) again with no new bytes: work is still buffered.
    kPump = 0,
    // Write `to_wire` (non-empty), then call Step again. `to_wire` is cleared
    // when handed out, so forgetting to write stalls rather than duplicates.
    kWrite,
    // Read more ciphertext and feed it as {kCiphertext}.
    kRead,
    // Finished. No further calls are valid.
    kDone,
    // Terminal failure; `error` says why. No further calls are valid.
    kFail,
};

struct Input {
    enum class Kind : uint8_t {
        kStart = 0,  // FIRST call only (C3). Repeat -> kProtocolViolation.
        kNone,       // pump: no new bytes
        kCiphertext, // peer bytes from the socket
        kPdu,        // a plaintext TPKT frame to send (only after complete())
    };
    Kind kind = Kind::kNone;
    const uint8_t* data = nullptr;
    size_t size = 0;

    static Input Start() { return {Kind::kStart, nullptr, 0}; }
    static Input None() { return {Kind::kNone, nullptr, 0}; }
    static Input Ciphertext(const uint8_t* p, size_t n) {
        return {Kind::kCiphertext, p, n};
    }
    static Input Pdu(const uint8_t* p, size_t n) { return {Kind::kPdu, p, n}; }
};

struct Output {
    // Ciphertext for the socket. Valid when want == kWrite.
    Bytes to_wire;

    // Complete TPKT frames, 4-byte header INCLUDED, in arrival order.
    // Header included because ConnectMachine::OnData requires it
    // (connect_machine.cpp:196 -> connection_initiation.cpp:55-58) while
    // TpktStream::Next strips it (framing.cpp:86). The layer re-wraps with
    // WrapTpkt (framing.cpp:99) and MUST check for an empty result (N6/M35:
    // payload > 65528 -> empty, while TpktStream accepts up to 65531).
    std::vector<Bytes> pdus;

    // Present exactly once: on the Step that crosses the EUAR.
    // Field name/type per C4: the raw UINT32 LE authorizationResult
    // (security-layer.md:375-386). Absent on every other Step.
    std::optional<uint32_t> euar_result;

    Want want = Want::kRead;
    Error error;
};

enum class Phase : uint8_t {
    kNotStarted = 0,
    kTlsHandshake,
    kCredssp,
    kAwaitEuar,
    kMcs,
    kDraining,
    kClosed,
    kFailed,
};

const char* to_string(Phase p);

class SecurityLayer {
public:
    // Creates the TLS backend and the CredSSP client. Does not touch the
    // network. Returns nullptr with `error` filled (kUnsupported / kInternal).
    static std::unique_ptr<SecurityLayer> Create(const Config& config, Error& error);

    // Test injection: takes ownership of a scripted transport.
    static std::unique_ptr<SecurityLayer> CreateWithTransport(
        const Config& config, std::unique_ptr<rtsc::tls::TlsTransport> transport,
        Error& error);

    ~SecurityLayer();
    SecurityLayer(const SecurityLayer&) = delete;
    SecurityLayer& operator=(const SecurityLayer&) = delete;

    // ------------------------------------------------------------------ Step
    //
    // Single entry point. Pure and re-entrant: no blocking, no threads, no
    // sleeping. All state lives in the instance.
    //
    // PRECONDITIONS
    //   P1  The first call MUST pass Input::Kind::kStart. Any other kind
    //       returns kFail with kind=kProtocolViolation (stage=kTlsHandshake,
    //       native_space=kLocal), because the layer has not produced a
    //       ClientHello yet. (C3)
    //   P2  A second kStart, at any time, returns the same kProtocolViolation.
    //       This is what makes "repeated Start" detectable, which the §13 draft
    //       could not express.
    //   P3  kCiphertext requires data != nullptr && size > 0.
    //   P4  kPdu is only valid once complete() is true; before that it returns
    //       kProtocolViolation (sending an MCS PDU before the handshake is a
    //       caller bug).
    //   P5  No call is valid after want == kDone or want == kFail.
    //
    // POSTCONDITIONS
    //   Q1  want is always one of the five values.
    //   Q2  want == kWrite implies !to_wire.empty().
    //   Q3  want == kRead implies to_wire.empty() and all of `in` was absorbed
    //       (nothing silently dropped).
    //   Q4  want == kFail implies error.fatal() && phase() == kFailed; every
    //       later call returns the same error without touching state
    //       (mirrors the TLS latch, tls.h:40-42).
    //   Q5  to_wire and pdus are fresh on every call; nothing carries over
    //       except what buffered_*() exposes.
    //   Q6  consumed semantics (D1, section 14.2): the TLS backend reports
    //       "bytes it took ownership of", so `in` may be fully absorbed even
    //       when the handshake boundary is mid-buffer. The layer never needs
    //       to replay: after any Step, either the input was absorbed or it is
    //       visible via buffered_ciphertext().
    //   Q7  If WrapTpkt returns empty for a completed frame (payload > 65528,
    //       framing.cpp:100), Step returns kFail with
    //       kind=kProtocolViolation, stage=kProtocol->kMcs, and detail carrying
    //       the size. It MUST NOT drop the frame silently. (C6 / N6 / M35)
    Output Step(const Input& in);

    // ------------------------------------------------------------------ state
    bool complete() const noexcept;   // phase() == kMcs
    bool closed() const noexcept;     // phase() == kClosed
    Phase phase() const noexcept;
    const Error& last_error() const noexcept;

    // Ciphertext held by the TLS backend (tls.h:185) plus anything the layer
    // could not yet hand to it. Zero in the steady state between units.
    size_t buffered_ciphertext() const noexcept;
    // Plaintext held because it does not form a whole unit yet (半帧 / 半个
    // TSRequest). Zero is normal between units.
    size_t buffered_plaintext() const noexcept;

    bool negotiated(rtsc::tls::NegotiatedInfo& out) const;

private:
    SecurityLayer(const Config& config, std::unique_ptr<rtsc::tls::TlsTransport> tls);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rtsc::sec
```

#### 17.3.3 C3 的 `kStart` 消歧（正面回答）

**方案：`Input::Kind` 的第一项就是 `kStart`，且它是唯一合法的首调。**

| 场景 | 调用 | 返回 |
|---|---|---|
| 首次 | `Step(Input::Start())` | `want=kWrite`，`to_wire`=ClientHello（实测 165 字节，`evidence/s10/probe_s10.out.txt`） |
| 重复启动 | 再调 `Step(Input::Start())` | `want=kFail`，`error={kind=kProtocolViolation, stage=kTlsHandshake, native_space=kLocal, detail="Step(kStart) called twice"}` |
| 未启动就喂数据 | `Step(Input::Ciphertext(...))` | `want=kFail`，`kind=kProtocolViolation`，`detail="ciphertext before kStart"` |
| 正常 pump | `Step(Input::None())` | `want=kRead` 或 `kWrite` 或 `kPump` |

**为什么这不破坏「单入口」的优点**：
`kStart` 只是 `Input` 的一个**取值**，不是第二个方法。
调用方仍然只有一个函数要调；而「意图」被显式编码进参数，
所以「重复启动」从「不可表达」（乙对 §13 的批评）变成「可检出」。
这同时满足乙的 C3 和我 §4 对「入口收敛」的要求。

**与 `kNone` 的区别**：`kNone` 表示「我没有新字节，你继续」；`kStart` 表示「开始」。
二者语义正交，实现里用一个 `bool started_` 就能判定 P1/P2，不需要额外状态机。

#### 17.3.4 三个待定问题的最终答案（取代 §13.3）

| 问题 | 最终答案 | 证据 |
|---|---|---|
| **TLS 握手期「同时要写且要继续读」** | `want` 按拍推进：`kWrite`（写出 `to_wire`）→ 下次 `Step(kNone)` → `kRead`。**`want` 不编码「是否完成」**（那是 `complete()` / `handshake_complete()`，`tls.h:183`）。实测序列：`kNeedMoreInput out=165` → `kNeedMoreInput out=158` → `kOk out=0`（`evidence/s10/probe_s10.out.txt`），证明「有输出」与「未完成」在同一状态共存，故一拍装不下两个维度 | `probe_s10` M5 |
| **EUAR 4 字节与 MCS 同 record 的切分点** | 判据是**阶段**不是**值**：`phase_==kAwaitEuar` 时无条件取 `plain_` 头部 4 字节为 `uint32 LE`，然后 `remove_prefix(4)`；`0x00`→`kMcs`，`0x05`→`kFail(kAuthorizationDenied)`，其他→`kFail(kProtocolViolation)`。剩余字节留给 `TpktStream`。**即使 EUAR 值恰好是 `0x00000003` 也不会被当 TPKT 头**，因为该阶段不看值域以外的东西 | `docs/spec/security-layer.md:375-386`、`:399-401` |
| **`kClosed` + 剩余明文 > 0** | 三态：**A** `plain_` 空 → `want=kDone, kind=kClosedByPeer`；**B** 含完整单位 → 先 `want=kPump` 派发，下一拍再 A；**C** 含不完整单位**或** `tls.buffered_input()>0` → `want=kFail, kind=kTruncated`（**不是**正常关闭）。判据：`is_truncated = (tls.buffered_input() > 0) \|\| (plain_ 非空 && !forms_complete_unit(plain_, phase_))` | `tls.h:148-150`（kClosed 保留明文）、`t:245-247`（批 0 后；锚点 `return (progressed != 0 || produced != 0)` .. `: MakeError(Status::kNeedMoreInput, 0, "");`）（<5 字节返回 kOk）、`src/net/tls_schannel.cpp:232`（锚点 `if (closed_) return MakeError(Status::kClosed, 0, "already closed");  (in Receive)`）（closed_ 短路） |

### 17.4 定案材料 B：批次与验收判据

> 合并 §15.2 的批次与乙的 36 行 M 表。**M 编号 → S 编号的映射见 `audit-b.md:1761-1798`**。
> 每批都给出可执行的验收判据与红证。

#### 批 0：跨平台（S21 / M28）

| 项 | 内容 |
|---|---|
| 成员 | **S21** |
| 改哪些文件 | `CMakeLists.txt:51-55`（拆成三层）；新增 `src/net/tls_factory.cpp`、`src/net/tls_unavailable.cpp`（或合并为一个文件内 `#ifdef` 分支——见 §17.5 的取舍） |
| 验收判据 | ① Windows：`cmake --build` 成功，`rtsc_tls_tests` **26 用例全绿**；② Linux：`cmake -S . -B build-linux && cmake --build build-linux` **成功**（这是 B19 的定义）；③ Linux `ctest` 除 TLS 套件外全绿 |
| 红证 | 变异：把 `CMakeLists.txt:51` 恢复为无条件 `add_library(rtsc_tls STATIC src/net/tls_schannel.cpp)` → Linux `cmake --build` 必须报「找不到 windows.h」而失败。预期失败点：编译 `tls_schannel.cpp` 的第一行 include |

#### 批 1：CredSSP 生产注入（S1 + S18 + S5 + S6 + S11 + S22）

| 项 | 内容 |
|---|---|
| 成员 | **S1**(M01) · **S18**(M18) · **S5**(M09) · **S6**(M10) · **S11**(M13) · **S22**(M23) |
| 改哪些文件 | `src/credssp/credssp.cpp:46`(S1) · `:93` 后插入(S5+S6) · `:357-360`(S11) · `include/rtsc/credssp/credssp.h:60-61`(S18 生产 setter) · `src/net/tls_schannel.cpp:435`（锚点 `return MakeError(Status::kOk, st, "shutdown best effort");`）(S22) · 新增 `src/crypto/random.cpp` + `include/rtsc/crypto/random.h`（**放 `rtsc_crypto`，不能放 `rtsc_security`**，否则 `rtsc_credssp` 反向依赖） |
| 验收判据 | `rtsc_credssp_sm_tests` **15 用例全绿** + `rtsc_ntlm_tests` **27 用例全绿** + `rtsc_credssp_tests` **23 用例全绿** + `rtsc_tls_tests` **26 用例全绿**（S22 在 TLS 侧）。新增用例：`two_constructions_have_different_nonces`(S1)、`start_without_public_key_fails`(S18)、`version_below_min_is_rejected_with_valid_challenge`(S5)、`server_version_is_echoed_back`(S6)、`tampered_signature_checksum_is_rejected`(S11)、`shutdown_failure_still_marks_closed`(S22) |
| 红证 | 变异：`credssp.cpp:46` 改回 `nonce_.assign(kNonceSize, 0)` → `two_constructions_have_different_nonces` 必须失败。变异：删掉 S18 的空公钥检查 → `start_without_public_key_fails` 必须失败（因为会产出 `pubKeyAuth` 而不报错） |

#### 批 2：TLS 后端（S9 + S10 + S19 + S8 + S7）

| 项 | 内容 |
|---|---|
| 成员 | **S9**(M05) · **S10**(M12) · **S19**(M33) · **S8**(M08) · **S7**(M11) |
| 改哪些文件 | `src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,` .. `}`）(S10, D1) · `:232`(S9) · `:467-472`(S19) · `:135-147`+`:491-509`(S8) · `:184-187`(S7) · `include/rtsc/net/tls.h:129-132`(S10 契约) · `tests/test_tls.cpp:879-885`(S19 测试修正) |
| 验收判据 | `rtsc_tls_tests` **26 用例全绿**（`probe_n1` 已证明 D1 不破坏 boundary1/3/10：36 checks, 0 failures）。新增用例：`coalesced_finished_and_app_data_are_both_delivered`(S10)、`shutdown_then_receive_still_drains`(S9)、`tls13_only_config_does_not_fail_acquire`(S19)、`strict_policy_rejects_self_signed`(S8)、`fatal_alert_maps_to_peer_alert`(S7) |
| 红证 | 变异：把 `Handshake` 改回 `consumed = in_size` 且不吸收尾部 → `coalesced_finished_and_app_data_are_both_delivered` 必须失败（实测：`probe_s10` M8 `total recovered = 0`）。变异：`ProtocolMask()` 恢复只置 1.3 → `tls13_only_config_does_not_fail_acquire` 必须失败（实测 `0x80090331`） |
| 注意 | **S7 的改法必须按 §17.6 的 U4 实测结论，不能用原计划的「解析 `15 03 03 00 02 <lvl> <desc>`」** —— 实测证明那条路径读不到 description |

#### 批 3：安全层（S2 + S3 + S4 + S16 + S15）

| 项 | 内容 |
|---|---|
| 成员 | **S2**(M02) · **S3**(M03) · **S4**(M04) · **S16**(M17) · **S15**(M16) |
| 改哪些文件 | 新增 `include/rtsc/sec/security_layer.h`（§17.3.2）、`include/rtsc/sec/security_error.h`（§17.3.1）、`src/sec/security_layer.cpp`；`CMakeLists.txt` 加 `rtsc_security`；`tools/rtsc_probe/main.cpp` 扩 `--full`（S15 最小驱动） |
| 验收判据 | 新套件 `rtsc_security_tests`：T1–T13（§5.6.4）全绿 + `rtsc_framing_tests` **11 用例** + `rtsc_connect_machine_tests` **26 用例** 不变。关键用例：`euar_success_then_connect_response`(T1)、`euar_split_across_two_receives`(T2)、`euar_and_mcs_in_one_record`(T3)、`euar_denied_emits_no_pdus`(T4)、`euar_missing_is_protocol_violation`(T5)、`tsrequest_split_across_records`(T6)、`wraptpkt_overflow_is_reported`(C6/N6) |
| 红证 | 变异：让 `kAwaitEuar` 阶段改为「直接把 plain_ 交给 TpktStream」→ `euar_denied_emits_no_pdus` 必须失败（EUAR 被当垃圾跳过，仍产出 MCS）。变异：删掉 `WrapTpkt` 返回空检查 → `wraptpkt_overflow_is_reported` 必须失败（静默丢帧） |

#### 批 4：协议层小修（S12 + S13 + S14 + S17 + S20）

| 项 | 内容 |
|---|---|
| 成员 | **S12**(M06) · **S13**(M14) · **S14**(M15) · **S17**(M07) · **S20**(M25+M27) |
| 改哪些文件 | `src/proto/connect_machine.cpp:353-357`(S12) · `include/rtsc/proto/connect_machine.h:38-41` 注释(S13) · `connect_machine.h:57`+`connect_machine.cpp:122-125`(S14) · `include/rtsc/credssp/credssp.h:51-53` 注释(S17) · `src/proto/connect_machine.cpp:165-168`(S20) |
| 验收判据 | `rtsc_connect_machine_tests` **26 用例全绿**（含 `machine_client_info_autologon_flag_follows_credentials` `:438`、`machine_client_info_payload_decodes_back` `:393`）。新增：`wrong_phase_external_security_complete_fails`(S12)、`client_info_password_empty_under_enhanced_security`(S20)、`client_info_password_present_for_standard_rdp`(S20 非 NLA 路径) |
| 红证 | 变异：`connect_machine.cpp:168` 改回无条件 `pdu.info.password = credentials_.password` → `client_info_password_empty_under_enhanced_security` 必须失败 |

#### 批 5：真机联调（依赖批 0–4）

| 项 | 内容 |
|---|---|
| 成员 | 无新缺陷；验证 §15.3 的推理链 |
| 验收判据 | `rtsc_probe --full 192.168.1.7 3389 <cookie>` 能打印到 `phase=await-connect-response` 且 `pdus` 含 Connect Response |
| 红证 | 不适用（这是集成验证，不是变异测试）。**若失败，失败点必须落在 §15.3.2 标注的三处未知之一**（U3 拼接顺序 / 凭据 / 服务器策略），否则说明有未发现的缺陷 |

#### 17.4.1 批次依赖图

```
批0 (S21 跨平台)
  |
  +--> 批1 (CredSSP) ---+
  |                     |
  +--> 批2 (TLS) -------+--> 批3 (安全层) --> 批5 (真机)
                        |
                        +--> 批4 (proto)
```

- **批 1 与批 2 可并行**（不同库，无共享文件；唯一的交集是 `credssp.h`/`tls.h` 都是只读依赖）。
- **批 3 必须等批 1+2**：它同时调用 `PeerSubjectPublicKey`（批1 的 S18）和 D1 的 `consumed` 语义（批2 的 S10）。
- **批 4 可独立**，但放在批 3 之后是因为它不影响安全层，最后做能减少 rebase。

### 17.5 定案材料 C：`rtsc_security` 的完整 CMake 片段

#### 17.5.1 可直接粘贴的片段

```cmake
# ============================================================================
# TLS transport, three layers (audit-a §12.1 / S21 / M28).
#
#   1) rtsc_tls_api        INTERFACE, platform neutral. Always buildable.
#   2) rtsc_tls_schannel   STATIC, Windows only.
#   3) rtsc_tls            STATIC facade. Exists on EVERY platform; on
#                          non-Windows it returns nullptr + a reason, so the
#                          failure is a runtime kUnsupported, not a build break.
#
# Why not #ifdef inside tls_schannel.cpp: an all-#ifdef'd-out translation unit
# still has to compile, and the resulting empty static library links silently,
# turning a build error into a mysterious runtime nullptr. Keeping the file out
# of the build on non-Windows makes the situation explicit.
# ============================================================================

add_library(rtsc_tls_api INTERFACE)
target_include_directories(rtsc_tls_api INTERFACE include)

if(WIN32)
    add_library(rtsc_tls_schannel STATIC src/net/tls_schannel.cpp)
    target_link_libraries(rtsc_tls_schannel PUBLIC rtsc_tls_api secur32 crypt32)
endif()

# The facade owns CreateTlsTransport / EnumerateTlsBackends. It is the ONLY
# target other code links against, so the platform split stays local to this
# file.
add_library(rtsc_tls STATIC src/net/tls_factory.cpp)
target_include_directories(rtsc_tls PUBLIC include)
target_link_libraries(rtsc_tls PUBLIC rtsc_tls_api)
if(WIN32)
    target_link_libraries(rtsc_tls PUBLIC rtsc_tls_schannel)
endif()

# ============================================================================
# Security layer (audit-a §17.3). Depends on all three lower layers.
# Nothing depends on it, so it is a pure sink: the dependency graph stays
# acyclic and rtsc_proto keeps its single outgoing edge (rtsc_crypto).
# ============================================================================

add_library(rtsc_security STATIC
    src/sec/security_layer.cpp
)
target_include_directories(rtsc_security PUBLIC include)
target_link_libraries(rtsc_security PUBLIC rtsc_tls rtsc_credssp rtsc_proto rtsc_crypto)

# ============================================================================
# Tests
# ============================================================================

# The TLS backend suite needs a real SChannel peer, so it is Windows only.
# This is the ONLY suite that is skipped on other platforms (audit-a §17.5.3).
if(WIN32)
    add_executable(rtsc_tls_tests tests/test_tls.cpp)
    target_link_libraries(rtsc_tls_tests PRIVATE rtsc_tls rtsc_util)
    target_include_directories(rtsc_tls_tests PRIVATE tests)
    add_test(NAME tls COMMAND rtsc_tls_tests)
endif()

# The security layer suite runs everywhere: it drives a scripted transport
# (ScriptedTlsTransport implements the platform-neutral tls.h:124 interface),
# so it needs no SSPI at all.
add_executable(rtsc_security_tests tests/test_security_layer.cpp)
target_link_libraries(rtsc_security_tests PRIVATE rtsc_security rtsc_util)
target_include_directories(rtsc_security_tests PRIVATE tests)
add_test(NAME security COMMAND rtsc_security_tests)

if(MSVC)
    target_compile_options(rtsc_security_tests PRIVATE /W4 /WX)
    if(WIN32)
        target_compile_options(rtsc_tls_tests PRIVATE /W4 /WX)
    endif()
endif()
```

#### 17.5.2 逐条回答主代理的三个问题

**Q1：非 Windows 上 `rtsc_proto` 的 `target_link_libraries` 是否仍只含 `rtsc_crypto`？**

**是，逐字不变。** 现有 `CMakeLists.txt:36` 是：

```cmake
target_link_libraries(rtsc_proto PUBLIC rtsc_crypto)
```

这段**在片段里完全没有出现**，即保持原样。理由：
- `src/proto/**` 的 15 个编译单元没有一个 `#include "rtsc/net/tls.h"`（本轮 grep 确认，见 §12.1）；
- `rtsc_security` 依赖 `rtsc_proto` 是**单向**的，不会反向注入。

**Q2：`rtsc_tls_tests` 怎么处理（乙 N11 提的 Linux 变红）？**

**包进 `if(WIN32)`，且 `add_test` 也包进去。** 关键点是**两处都要包**：
只包 `add_executable` 而漏 `add_test`，`ctest` 会报「找不到测试可执行文件」；
只包 `add_test` 而漏 `add_executable`，构建仍会失败。
片段里两处都在 `if(WIN32)` 内（见上面的 `# The TLS backend suite ...` 段）。

**为什么不改成「在测试里跳过」**：`tests/test_tls.cpp` 的 `main()` 直接
`return ::rtsc::test::run_all("rtsc_tls_tests")`（`:893`），
26 个用例全部依赖 `RawServer`（`:50`），而 `RawServer` 无条件 `#include <schannel.h>`（`:21`）。
「跳过」要么改 26 个用例，要么在 `main` 里加平台判断——都比 CMake 条件更侵入。

**Q3：`rtsc_security`（批 3 新建）在非 Windows 上如何存在（空实现？不建？）？**

**建，且是完整实现，不是空实现。** 理由：
1. `SecurityLayer` 的代码本身是平台中立的（只依赖 `tls.h` 的平台中立接口、`credssp.h`、`framing.h`）；
2. 它调 `CreateTlsTransport`（`tls.h:198`）拿到 `nullptr` + `why`，
   `SecurityLayer::Create` 把它映射为 `Error{kind=kUnsupported, native_space=kLocal, detail=why}`；
3. 所以非 Windows 上它是**运行期不可用**，不是**编译期缺失**——
   这正好符合「Linux 上 `cmake --build` 必须成功」的要求。

**唯一需要非 Windows 分支的地方**是 `src/net/tls_factory.cpp`（新增文件），
它必须提供一个「无后端」的 `CreateTlsTransport`：

```cpp
// src/net/tls_factory.cpp  (sketch; NOT to be written this round)
#include "rtsc/net/tls.h"

#if defined(_WIN32)
// Declared in tls_schannel.cpp's translation unit via a small internal header.
std::unique_ptr<rtsc::tls::TlsTransport> CreateSchannelTransport(
    const rtsc::tls::Config&, std::string& why);
#endif

namespace rtsc::tls {

std::unique_ptr<TlsTransport> CreateTlsTransport(std::string_view backend,
                                                const Config& config,
                                                std::string& why) {
#if defined(_WIN32)
    if (backend.empty() || backend == "schannel" || backend == "default")
        return CreateSchannelTransport(config, why);
    why = "unknown TLS backend: " + std::string(backend);
    return nullptr;
#else
    (void)backend;
    (void)config;
    why = "no TLS backend for this platform (SChannel is Windows only)";
    return nullptr;
#endif
}

std::vector<BackendInfo> EnumerateTlsBackends() {
#if defined(_WIN32)
    return {{"schannel", true, ""}};
#else
    return {};
#endif
}

}  // namespace rtsc::tls
```

**注意**：这要求把现有 `src/net/tls_factory.cpp`（批 0 搬迁：CreateTlsTransport / EnumerateTlsBackends） 的 `CreateTlsTransport`/`EnumerateTlsBackends`
改成 `CreateSchannelTransport` 并移出（或保留为内部符号）。
这是**批 0 的实际工作量**，不是零成本。

#### 17.5.3 为什么这段粘进去后 `cmake --build` 在 Linux 上能过

逐条给出机制，不是「应该能过」：

| 步骤 | 为什么成立 | 依据 |
|---|---|---|
| 1. `rtsc_tls_api` 配置成功 | `INTERFACE` 库没有源文件，`target_include_directories(INTERFACE include)` 不需要编译器 | CMake 语义；`include/rtsc/net/tls.h:26-32` 只含 7 个 std 头，无 Windows 类型 |
| 2. `rtsc_tls_schannel` 不参与构建 | `if(WIN32)` 为假，`add_library` 整段跳过，`src/net/tls_schannel.cpp` **不被任何 target 引用** | 片段第 1 段 |
| 3. `rtsc_tls` 编译成功 | 唯一源文件 `src/net/tls_factory.cpp` 的非 Windows 分支只调用 `std::string` 与返回 `nullptr`，不引用任何 Windows 符号 | §17.5.2 的 sketch |
| 4. `rtsc_proto` 编译成功 | 出边仍只有 `rtsc_crypto`（`CMakeLists.txt:36` 未改）；`src/proto/**` 无 `tls.h` 引用 | §12.1 的 grep 结果 |
| 5. `rtsc_credssp` 编译成功 | 只依赖 `rtsc_crypto`（`CMakeLists.txt:117` 未改）；三个源文件无平台 API | `CMakeLists.txt:109-110` 的注释已声明平台中立 |
| 6. `rtsc_security` 编译成功 | 只含 `src/sec/security_layer.cpp`，它 include 的三个头都是平台中立接口 | §17.3.2 的 include 列表 |
| 7. `rtsc_security_tests` 编译成功 | 用 `ScriptedTlsTransport`（实现 `tls.h:124` 的纯虚接口），不链接 `secur32` | 片段末尾 |
| 8. `ctest` 除 TLS 外全绿 | `rtsc_tls_tests` 的 `add_executable` 与 `add_test` **都在** `if(WIN32)` 内，Linux 上不注册 | 片段 `# The TLS backend suite ...` 段 |
| 9. 运行期行为明确 | `CreateTlsTransport` 返回 `nullptr` + `why="no TLS backend for this platform..."`；`SecurityLayer::Create` 映射为 `kUnsupported` | §17.5.2 Q3 |

**唯一不能保证的一步**：第 3 步要求把 `src/net/tls_factory.cpp`（批 0 搬迁：CreateTlsTransport / EnumerateTlsBackends） 的工厂函数拆出去。
**如果执行时漏了这一步**，`rtsc_tls` 会有两个定义（`tls_factory.cpp` 与 `tls_schannel.cpp` 各一份），
Windows 上链接期报重复符号、Linux 上 `tls_schannel.cpp` 仍被编译而失败。
这是**批 0 必须一起做的**，不能只改 `CMakeLists.txt`。

### 17.6 U4 实测结论（消除 N3）

> 探针：`F:\rtsc\.tmp\probe_u4\probe_u4.cpp` … `probe_u4f.cpp`（6 个）。
> 输出：`F:\rtsc\evidence\u4\probe_u4*.out.txt`。
> 真实 SChannel 双端 + 真实自签证书 + 真实 `EncryptMessage` 记录，无 socket。

#### 17.6.1 结论（一句话）

**SChannel 在 `DecryptMessage` 路径上把对端 alert 报为 `SEC_I_CONTEXT_EXPIRED (0x00090317)`，
且 alert 的 level/description 字节不可从任何 SecBuffer 的明文位置读到 ——
`tls.h:42` 承诺的「`native_code = alert description`」在当前 API 下无法兑现。**

#### 17.6.2 逐项测量

| 编号 | 场景 | `SECURITY_STATUS` | 明文可读性 | 输出文件 |
|---|---|---|---|---|
| **T1** | 正确的 `ApplyControlToken(SCHANNEL_SHUTDOWN)`（token 指向 `DWORD=1`）→ 记录 | `SEC_E_OK`，out=**31 字节**，type=**21 (Alert)** | — | `probe_u4e.out.txt` |
| **T2** | 对端 `DecryptMessage`(那条 alert) | **`SEC_I_CONTEXT_EXPIRED (0x00090317)`** | `plaintext=31`，但内容以 `15 03 03 00 1A ...` 开头 —— **是整条 alert 记录的密文包装**，`plaintext[0]=0x15` 是 record type，**不是** level | `probe_u4e.out.txt` |
| **T3** | 从明文里取 level/description | — | **取到的是 `level=21, description=3`**，即 `0x15, 0x03` —— 这是 record 头的前两字节，**不是 alert 语义** | `probe_u4e.out.txt` |
| **T4** | **错误**的 `ApplyControlToken`（空 token，即产品当前做法） | **`SEC_E_UNSUPPORTED_FUNCTION (0x80090302)`**，out=**0 字节** | — | `probe_u4e.out.txt` |
| **S3** | 产品 `TlsTransport::Shutdown()` | `kOk`，out=**201 字节**，type=**22 (Handshake)** | **不是 close_notify，是 renegotiation request** | `probe_u4d.out.txt` |
| **S5/R4** | 握手后手写明文 alert `15 03 03 00 02 02 31` 喂 `Receive` | **`kProtocolError`**，`native_code=0x80090318 (SEC_E_INCOMPLETE_MESSAGE)` | 不可读（TLS1.2 要求 alert 加密） | `probe_u4.out.txt` |
| **Q7** | 真实加密记录把外层 type 23→21 | `SEC_E_DECRYPT_FAILURE (0x80090330)` | — | `probe_u4b.out.txt` |
| **Q8** | 全长度 type-21 + 垃圾 | `SEC_E_DECRYPT_FAILURE (0x80090330)` | — | `probe_u4b.out.txt` |
| **Q9** | 握手后把 alert 喂给 `ISC` | `SEC_I_CONTINUE_NEEDED`，out=**183 字节**，`out[0]=0x16`（**发起重协商**） | — | `probe_u4b.out.txt` |
| **Q1** | 握手后明文 alert（close_notify 形态） | `kProtocolError`，`native_code=0x80090318` | 不可读 | `probe_u4.out.txt` |

**`SEC_E_ILLEGAL_MESSAGE (0x80090326)` 在所有场景中一次都没出现。**

#### 17.6.3 对 S7 的裁决（必须改）

**原 S7 的改法（我 §15.1 写的）是错的**：我写「在 `Receive` 里对 `SEC_E_ILLEGAL_MESSAGE` 等状态
尝试从明文 record 里提取 alert（`15 03 03 00 02 <level> <desc>`）」。
实测证明：
1. `SEC_E_ILLEGAL_MESSAGE` **不产生**；
2. 明文里**没有** `<level> <desc>` 可读（T2/T3 证明 `plaintext` 是整条 alert 记录的密文包装，
   其前两字节 `0x15 0x03` 是 record type + version，不是 alert 语义）；
3. 明文 alert **不被接受**（TLS1.2 要求加密），所以「从明文 record 提取」这条路根本不存在。

**S7 的最终形态（三条，按可靠性排序）**：

| 方案 | 做法 | 能给出什么 | 评价 |
|---|---|---|---|
| **S7-a（推荐）** | 承认 `TlsTransport` 层**拿不到** alert description。把 `tls.h:42` 的注释改为 `native_code = the SECURITY_STATUS that carried the alert (SEC_I_CONTEXT_EXPIRED)`；把「凭据错误 vs 协议违规」的区分**上移到 CredSSP 层**（那里有 `errorCode`，`credssp.cpp:97-105` 已经能给出 NTSTATUS） | `kClosedByPeer` vs `kCredentialRejected`（凭据类由 CredSSP `errorCode` 判定） | **推荐**。不改 API，只改注释与映射表；`kPeerAlert` 保留给「后端能识别 alert」的未来后端（OpenSSL 的 `SSL_ERROR_SSL` + `SSL_get_error` 能给 `SSL_AD_*`） |
| S7-b | 在 `Receive` 里保存**最近一次** `SEC_I_CONTEXT_EXPIRED` 前的**原始密文 record**，交给上层用 `DecryptMessage` 的明文（`15 03 03 ...`）做**启发式**判断 | 仍拿不到 description（密文已解但 payload 是加密的） | **不可行**，T2/T3 已证明 |
| S7-c | 用 `QueryContextAttributes(SECPKG_ATTR_REMOTE_CERT_CONTEXT)` + 在**第 5 步后**主动探测（发一条零长度 app data，看是否立刻 `SEC_I_CONTEXT_EXPIRED`） | 只能区分「立刻断」与「继续」，不能给码 | 过度设计，不推荐 |

**因此 S7 从「P1，解析 alert」降级为「P2，改注释 + 映射」**，
且**新增一条 P2 缺陷 S23**：`tls.h:42` 的承诺无法兑现（文档与实现能力不符）。

| 编号 | 级别 | 症状 | 证据 | 影响 | 建议 |
|---|---|---|---|---|---|
| **S23** | P2 | `tls.h:42` 承诺 `native_code = alert description`，但实测 alert 的 level/description **不可从任何 SecBuffer 读到**；`DecryptMessage` 只给 `SEC_I_CONTEXT_EXPIRED` | `include/rtsc/net/tls.h:42`；实测 `evidence/u4/probe_u4e.out.txt`（T2/T3：`plaintext=31` 以 `15 03 03 00 1A` 开头，前两字节是 record type/version）；`probe_u4.out.txt`（`SEC_E_ILLEGAL_MESSAGE` 零出现） | **P2**。基于该承诺设计的错误分类（「alert 49 → 凭据错误」）无法实现，会导致 S7 的实现走错方向（我 §15.1 就是实例） | 改写 `tls.h:42` 的注释为「`native_code` = 承载 alert 的 `SECURITY_STATUS`」；把凭据/授权的区分上移到 CredSSP 的 `errorCode` |

#### 17.6.4 顺带发现的 P1 缺陷 S24（`Shutdown()` 发错记录类型）

**这是本轮最重要的意外发现，不在任何人的清单里。**

| 编号 | 级别 | 症状 | 证据 | 影响 | 建议 |
|---|---|---|---|---|---|
| **S24** | P1 | **`Shutdown()` 发出的是 renegotiation request（type 22），不是 close_notify（type 21）** | `src/net/tls_schannel.cpp:411`（锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`）（`SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`，`cbBuffer=0`、`pvBuffer=nullptr`）、`:411`（`ApplyControlToken` 返回值**被丢弃**）；实测 `evidence/u4/probe_u4d.out.txt`（S3：`Shutdown -> out=201`，`record: type=22 (Handshake)`）；对照 `probe_u4e.out.txt`（T1：正确的 `DWORD type=SCHANNEL_SHUTDOWN` → `type=21 (Alert)`，31 字节） | **P1**。`Shutdown()` 声称「graceful close」（`tls.h:178-180`），实际发的是**重协商请求**。对端会当成 renegotiation，而 RDP 场景禁止重协商（`t:293`、`:319` 都把它判为 `kProtocolError`）→ **对端可能直接报协议错误并断开**，而不是优雅关闭。`tests/test_tls.cpp:848` 的 `shutdown_is_idempotent` 只断言「`out` 非空」，**没有断言 record type**，所以这个 bug 一直没被发现 | `src/net/tls_schannel.cpp:411-413`（批 0 后；锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`） 改为 `DWORD type = SCHANNEL_SHUTDOWN; SecBuffer token{sizeof(type), SECBUFFER_TOKEN, &type};` 并**检查** `ApplyControlToken` 的返回值（`:411` 当前丢弃）。测试补一条断言：`out[0] == 0x15`（Alert） |

**缺陷总数：22 → 24**（S1–S24）。

### 17.7 N1 实测结论（消除 N1）

> 探针：`F:\rtsc\.tmp\probe_u4\probe_n1.cpp`；输出 `F:\rtsc\evidence\u4\probe_n1.out.txt`。
> 方法：实现一个 `D1Wrapper`（record 预切片 + 吸收尾部），
> 用它和真实 transport 分别跑 `Loopback::Start` 的**逐行复制**（`tests/test_tls.cpp:162-205`），
> 然后回放 boundary1 / boundary3 / boundary10 的**完整输入序列与断言**。

#### 17.7.1 先纠正我 §15.5 N1 的问题设定

我 N1 写的是「D1 可能影响 `boundary1/3/10`」。**读代码后发现这三个用例根本不含 `Handshake` 调用**：

| 用例 | 行号 | 是否调用 `Handshake` | 实际调用 |
|---|---|---|---|
| `boundary1_record_split_into_feeds_yields_needmoreinput_then_ok` | `:369-392` | **否** | 只有 `Receive`（`:382`、`:388`） |
| `boundary3_trailing_partial_record_stays_buffered` | `:453-480` | **否** | 只有 `Receive`（`:469`、`:476`） |
| `boundary10_complete_record_reported_incomplete_is_protocol_error` | `:589-608` | **否** | 只有 `Receive`（`:602`） |

`Handshake` 只出现在夹具 `Loopback::Start`（`:162-205`，循环在 `:181-202`）。
所以**正确的问题**是：D1 之后 `Loopback::Start` 还能不能收敛？
（我 §15.5 N1 把问题设成「D1 会改变这三个用例的哪个输入序列」，
前提就错了——它们没有 Handshake 输入序列可改。**这是我的表述错误，如实订正。**）

#### 17.7.2 实测结果

```
=== baseline (current Handshake) ===
  handshake converged in 2 rounds
  [baseline] boundary1
  [baseline] boundary3
  [baseline] boundary10

=== D1 wrapper ===
  handshake converged in 2 rounds
  [D1] boundary1
  [D1] boundary3
  [D1] boundary10

checks=36 failures=0
RESULT: D1 PRESERVES boundary1/3 behaviour
```

**36 个断言（3 个用例 × 12 个 CHECK）在 baseline 与 D1 下结果完全一致，0 失败。**

#### 17.7.3 结论

**D1 不会破坏 `boundary1` / `boundary3` / `boundary10`。不需要同步修改任何断言。**

理由（机制层面，不只是「跑过了」）：
1. 这三个用例只在握手**完成后**调 `Receive`（见 §17.7.1 的行号）；
2. D1 只改 `Handshake`（`t:101-201`）与 `tls.h:129-132` 的注释，**不改 `Receive`**（`t:230-345`）；
3. D1 的尾部吸收把字节放进 `rx_buffer_`，而 `Receive` 正是从 `rx_buffer_` 消费（`t:271`（批 0 后；锚点 `rx_buffer_.erase(rx_buffer_.begin(),`））——
   所以「吸收」与「消费」用的是同一个缓冲，不存在两套。

**仍需注意的残留风险（不掩盖）**：
- `boundary2`（`:398`）、`boundary9`（`:422`）、`boundary12`（`:669`）、
  `extra_is_zero_because_records_are_pre_sliced`（`:637`）也只用 `Receive`，按同样理由不受影响，
  但**我没有逐条回放**（只回放了 1/3/10）。这是 §17.8 的 U-N1。
- `max_out_is_soft_and_caller_can_drain`（`:694`）用 `max_out=1` 反复 `Receive`，
  与 D1 的尾部吸收可能交互（尾部预注入 + `max_out`），**未回放**。同为 U-N1。

### 17.8 我仍不确定的（§17 新增）

| # | 不确定项 | 为什么不确定 | 如何消除 |
|---|---|---|---|
| **U-N1** | `boundary2/9/12`、`extra_is_zero...`、`max_out...` 这 5 个用例在 D1 下是否仍绿 | 我只回放了 boundary1/3/10（`probe_n1`）。这 5 个也只用 `Receive`，按 §17.7.3 的机制应不受影响，但 `max_out_is_soft_and_caller_can_drain`（`:694-727`）会与 D1 的「尾部预注入 + `max_out` 软阈值」交互，**我没测** | 把 `probe_n1.cpp` 扩成回放全部 5 个；或在批 2 执行时直接跑 `rtsc_tls_tests` 全 26 条 |
| **U-N2** | S24 的修复会不会破坏 `shutdown_is_idempotent`（`tests/test_tls.cpp:848-862`） | 该用例断言 `first` 非空、`second` 空。改成正确的 `SCHANNEL_SHUTDOWN` 后 `first` 仍是 31 字节非空（`probe_u4e` T5），**理论上仍绿**，但 `probe_u4e` 用的是**裸 client 上下文**，产品走的是 `SchannelTransport::Shutdown`（`t:404-436`（批 0 后；锚点 `Error Shutdown(std::vector<uint8_t>& out) override {` .. `}`）），路径不完全相同（产品还有 `shutdown_sent_` 与 `have_ctx_` 检查） | 批 2 执行时先只改 `src/net/tls_schannel.cpp:411-413`（批 0 后；锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`），跑 `rtsc_tls_tests`；若 `shutdown_is_idempotent` 变红，看它是否只是「`out` 从 201 变 31 字节」——那说明断言仍然成立 |
| **U-N3** | S24 修复后，对端（真实 RDP 服务器）收到真正的 close_notify 会不会改变断开时序 | 我只测了「生成正确记录」与「对端能解密」，**没测真实服务器的反应**。RDP 服务器可能期望先收 `McsDisconnectProviderUltimatum` 再关 TLS | 联调时观察：修 S24 后 `closesocket` 是否仍在收到服务器 FIN 之前；若是，可能需要保留「先发 MCS 断开再 TLS shutdown」的顺序（这属 S15 驱动的职责） |
| **U-N4** | S7 的最终形态（S7-a：把区分上移到 CredSSP）是否够用 | `credssp.cpp:97-105` 只在服务器**主动回 TSRequest.errorCode** 时给 NTSTATUS；若服务器直接发 TLS alert 而不回 errorCode（我 §15.5 U6 未验证），则 CredSSP 层也拿不到码 → 只剩 `SEC_I_CONTEXT_EXPIRED`，无法区分「凭据错」与「服务器故障」 | 需要 U6：用**错误密码**跑完整五步，看服务器在 `authInfo` 之后回 `15 03 03 ...`（alert）还是 `30 ...`（TSRequest with errorCode）。这需要凭据，当前不具备 |
| **U-N5** | 批 0 拆分 `CreateTlsTransport` 时，`src/net/tls_factory.cpp`（批 0 搬迁：CreateTlsTransport / EnumerateTlsBackends） 的两个符号怎么处理最稳 | 三个选项：① 改成 `CreateSchannelTransport` 并在内部头声明；② 保留原名但用 `#ifdef` 包住；③ 把工厂整体移到 `tls_factory.cpp` 并把 `SchannelTransport` 类暴露到内部头。**① 最干净但要求新增内部头**，③ 改动最大。我没实测哪个在 MSVC 的 `/W4 /WX` 下不产生未使用符号警告 | 批 0 执行时先试 ①，若 `/WX` 报未使用函数则改 ③ |
| **U-N6** | §17.6.2 的 T3 里「`level=21, description=3`」这个读数是否会被误读为「拿到了 alert」 | 我的探针打印的是 `plain[0]`/`plain[1]`，实测值 `21/3` 恰好等于 `0x15`/`0x03`（record type + version 高字节）。**这是巧合造成的陷阱**：如果实现按「`plain[0]` 是 level」去读，会得到 `21`（非法 level，合法只有 1/2），从而误判 | 已在 §17.6.2 显式标注。实现侧必须断言 `level ∈ {1,2}` 才能确认拿到的是 alert 语义——而实测拿不到，故 S7-a |

---

## 18. 并入 S22–S24 后的定案材料修订

> **行号基线**：本轮重新读取。`tls_schannel.cpp` 748 行、`tls.h` 208 行、
> `tests/test_tls.cpp` 893 行、`test_framework.h` 82 行、`CMakeLists.txt` 193 行。
> **新增探针**：`F:\rtsc\.tmp\probe_u4\probe_s25.cpp`（链接 `build\verify\rtsc_tls.lib`，
> A/B 两段走**产品代码**）；输出 `F:\rtsc\evidence\u4\probe_s25.out.txt`。
> **未改任何工程代码。**

### 18.0 先给本轮新实测（证据在前，结论在后）

#### 18.0.1 六格矩阵（这是本轮最关键的一张表）

| 格 | 上下文 | `ApplyControlToken` 的 token | `ApplyControlToken` 返回 | `InitializeSecurityContext` 返回 | `out` | 记录类型 | 来源 |
|---|---|---|---|---|---|---|---|
| **A** | **产品**，握手**未完成** | 空（`:411`（批 0 后；锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`）） | *被丢弃*（`:413`（批 0 后；锚点 `ApplyControlToken(&ctx_, &desc)`）） | `0x80090318` `SEC_E_INCOMPLETE_MESSAGE` | **0** | 无 | `probe_s25` A |
| **B** | **产品**，握手**已完成** | 空（`:411`（批 0 后；锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`）） | *被丢弃*（`:413`（批 0 后；锚点 `ApplyControlToken(&ctx_, &desc)`）） | **`0x00090312` `SEC_I_CONTINUE_NEEDED`** | **201** | **22 Handshake** | `probe_s25` B |
| **C** | 裸客户端，握手未完成 | **正确** `DWORD=SCHANNEL_SHUTDOWN` | `SEC_E_OK` | `SEC_E_OK` | **31** | **21 Alert** | `probe_s25` C |
| **D** | 裸客户端，握手未完成 | 空 | **`0x80090302` `SEC_E_UNSUPPORTED_FUNCTION`** | `0x80090318` | 0 | 无 | `probe_s25` D |
| **E** | 裸客户端，握手已完成 | **正确** | `SEC_E_OK` | `SEC_E_OK` | **31** | **21 Alert** | `probe_s25` E |
| **F** | 裸客户端，握手已完成 | 空 | **`0x80090302` `SEC_E_UNSUPPORTED_FUNCTION`** | **`0x00090312`** | **183** | **22 Handshake** | `probe_s25` F |

**这张表的读法（C/D/E/F 是 2×2，A/B 是产品侧的同一 2×2）**：

|  | token 正确 | token 为空 |
|---|---|---|
| **握手未完成** | **C**：`SEC_E_OK` / 31 B / type 21 ✅ | **D**：`ctl=0x80090302` → `ISC=0x80090318` / 0 B |
| **握手已完成** | **E**：`SEC_E_OK` / 31 B / type 21 ✅ | **F**：`ctl=0x80090302` → `ISC=0x00090312` / 183 B / type 22 |

**决定性结论：`out` 是 31 字节 type=21 还是 201/183 字节 type=22，只由 token 决定；
上下文状态只决定「token 为空时走哪条失败路径」（握手未完成 → `SEC_E_INCOMPLETE_MESSAGE`；
握手已完成 → `SEC_I_CONTINUE_NEEDED` + 重协商 ClientHello）。**

#### 18.0.2 对父代理实测的核对

| 父代理的说法 | 核对结果 |
|---|---|
| `Shutdown -> status=0 native=0x00090312 out=201 bytes` | **完全一致**（`probe_s25` B：`status=0 native=0x00090312 out=201`） |
| `record type = 22 (Handshake), version = 0303, length = 196` | **完全一致**（B：`type=22 ver=0303 bodylen=196 total=201`；我 §17.6.2 的 out=201/type=22 也一致） |
| `closed() = true` | **一致**（B 段 `closed=true`；由 `t:432`（锚点 `closed_ = true;  (in Shutdown)`）设置） |
| `Shutdown again -> status=0 out=0 bytes` | **一致**（B 第二次：`status=0 native=SEC_E_OK out=0`；由 `t:406` 的 `shutdown_sent_` 短路） |
| **「这个错误连错误码都被丢掉了」** | **需要分两半，一半对一半不对**，见 18.0.3 |

#### 18.0.3 订正父代理的一处措辞（码没全丢，丢的是两个不同的码）

父代理写「这个错误连错误码都被丢掉了」。逐字核对 `t:411-435`（锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr};` .. `return MakeError(Status::kOk, st, "shutdown best effort");`）与 B/F 两格：

| 码 | 归属 | 实际命运 | 证据 |
|---|---|---|---|
| **`0x80090302` `SEC_E_UNSUPPORTED_FUNCTION`** | **`ApplyControlToken`** 的返回 | **确实被完全丢弃**：`:413`（批 0 后；锚点 `ApplyControlToken(&ctx_, &desc)`） 是裸调用，返回值既没赋值也没比较 | F：`ctl=0x80090302`；产品侧无法观测到它 |
| **`0x00090312` `SEC_I_CONTINUE_NEEDED`** | **`InitializeSecurityContext`** 的返回 | **没有丢**：`t:431`/`:435`（批 0 后；锚点 `return MakeError(Status::kOk, st, "shutdown best effort");`） 把它作为 `code` 传进 `MakeError`，最终落到 `Error::native_code` | B：`native=0x00090312`（父代理自己的输出也如此） |

所以准确表述是：**真正被丢掉的是 `ApplyControlToken` 的 `0x80090302`；
`ISC` 的 `0x00090312` 留在 `native_code` 里，但被 `status=kOk` 包住 ——
调用方按 `Error::ok()`（`tls.h:62`）短路后永远看不到它。**

这个区别不是抠字眼，它决定修复位置：
- 若认为「码丢了」→ 会去改 `:431` 让它别丢码 → **改了也没用**，`t:431` 的 `st` 本来就在 `native_code` 里；
- 若认清「`ctl` 的码丢了 + `ISC` 的码被成功状态包住」→ 会去改 **`:411`（检查 ctl）** 与 **`:431`（别把 CONTINUE_NEEDED 当成功）**，这才是根因所在。

#### 18.0.4 裁决：不单列 S25，归入 **S24-b**

父代理要求判断「这是 S24 的一部分，还是应该单列 S25」。**我判定：S24 的一部分，记为 S24-b，不单列 S25。** 四条理由：

1. **根因同一，且已被 2×2 矩阵证实是单一开关。**
   C/D/E/F 四格只改了 token 一个变量，输出就从「31 B type 21 / SEC_E_OK」翻到
   「183 B type 22 / 0x00090312」再翻回来。没有第二个自变量。
   （`probe_s25.out.txt` 全文；矩阵见 18.0.1）

2. **修好 S24-a（token）之后，S24-b 的症状在**所有实测状态**下自动消失，不是碰巧。**
   C 与 E 覆盖「握手未完成」与「握手已完成」两个状态，`ISC` 都是 `SEC_E_OK`，
   因此 `native_code` 必为 0，`0x00090312` 不再出现。
   → S25 若单列，将**不存在一个「S24 已修、S25 未修」的可复现状态**，
   拿不到红证，违反「先红后绿、禁止伪造红证」。

3. **红证不可构造，就不该占独立编号。**
   我的缺陷编号规则是「一个编号 = 一个可用失败用例复现的观察」。
   我给不出这样的用例（试过了：C/E 两格就是反例）。
   硬凑一个「防御性缺陷」编号，会让清单出现无法验收的条目。

4. **但它必须作为 S24 的显式子项被记录，因为 S24-a 的断言抓不到它。**
   `CHECK_EQ(first[0], 21)`（18.2.2）只能证明「发的是 alert」，
   证明不了「`:431` 不再把 CONTINUE_NEEDED 当成功」。
   所以 S24 的修复范围必须**同时**包含 `:431`，且要在文档里写明这一点；
   否则下一个后端/下一个 TLS 版本会让它复活。

**S24 的完整定义（修订后）**：

| 子项 | 内容 | 修哪里 | 有无独立红证 |
|---|---|---|---|
| **S24-a** | 空 control token → 发出 type=22 重协商请求而非 type=21 close_notify | `src/net/tls_schannel.cpp:411`（锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`） | **有**：`probe_s25` B（out=201, type=22） |
| **S24-b** | `:431` 把 `SEC_I_CONTINUE_NEEDED`（「还需要继续」）与 `SEC_E_OK` 并列判成功，并置 `closed_=true` | `src/net/tls_schannel.cpp:431`（锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`） | **无**（S24-a 修复后不可达；C/E 为反证）→ 记为防御性改动 |
| **S24-c** | `ApplyControlToken` 的返回值被丢弃（`0x80090302` 无人看见） | `src/net/tls_schannel.cpp:411`（锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`） | **有（间接）**：F 格 `ctl=0x80090302`；产品侧不可见即证据 |

**如果你（父代理）出于跟踪需要坚持要一个独立编号**，那么唯一在语义上独立的是 S24-b，
但它必须被标注为「**防御性，无独立红证，不得计入验收覆盖率**」。
我不建议这么做：它会造成「24 个缺陷里有一个永远无法验收」的记录。

#### 18.0.5 顺带把 S22 从「代码推理」升级为「实测可复现」

`probe_s25` **A 格**是本轮第二个意外收获。产品 `Shutdown()` 在**握手未完成**时：

```
status=0 (kOk)  native=0x80090318 (SEC_E_INCOMPLETE_MESSAGE)  out=0  closed=false
```

走的是 `t:407`（`have_ctx_` 已为真，不短路）→ `t:411-413`（空 token，ctl 失败被丢弃）
→ `t:419-422`（ISC 返回 `0x80090318`）→ `:431`（批 0 后；锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`）（不匹配）→ **`:435`（批 0 后；锚点 `return MakeError(Status::kOk, st, "shutdown best effort");`）「shutdown best effort」**
→ 返回 `kOk`，`closed_` 保持 false。

**这正好是 S22 的可执行复现**：调用方得到「成功」，但一个字节的 close_notify 都没发，
且 `closed()` 说「没关闭」。S22 由此从「读代码推断」升级为「有触发路径、有输出」。

### 18.1 缺陷清单最终版（S1–S24）

#### 18.1.1 主表

| 编号 | 级别 | 一句话 | 归属 | 批次 |
|---|---|---|---|---|
| **S1** | P0 | `nonce_` 恒为 32 个 0，client challenge 与 exported session key 可预测 | 甲 | 批1 |
| **S2** | P0 | EUAR 无读取器；`TpktStream` 把 4 字节 EUAR 当垃圾静默丢弃 | 双方 | 批3 |
| **S3** | P0 | `TpktStream` 剥掉 TPKT 头，而 `OnData` 要求带头完整帧 → 第一帧即 `InvalidVersion` | 双方 | 批3 |
| **S4** | P0 | 无 DER 分帧器；跨 TLS record 的 TSRequest 无法重组 | 双方 | 批3 |
| **S5** | P1 | 服务端 `TSRequest.version` 从不校验 | 甲 | 批1 |
| **S6** | P1 | 服务端版本不回写 `version_`，第 3/5 步仍用客户端版本 | 甲 | 批1 |
| **S7** | P1 | `kPeerAlert` 从不产生；alert 49 退化为 `kProtocolError` | 甲 | 批2 |
| **S8** | P1 | `kStrict`/`kTofu` 未实现；`pinned_spki_sha256`/`pin_is_set` 零使用 | 双方 | 批2 |
| **S9** | P1 | `Shutdown()` 置 `closed_` 后 `Receive` 入口短路，`rx_buffer_` 残余永久丢失 | 双方 | 批2 |
| **S10** | P2 | `Handshake` 的 `consumed = in_size` 在合段时多报；`tls.h:129-132` 公式失效 | 甲 | 批2 |
| **S11** | P1 | `OpenReceive` 只解密不验 HMAC，第 4 步可被篡改 | 甲 | 批1 |
| **S12** | P2 | `OnExternalSecurityComplete()` 在错误阶段静默 no-op | 甲 | 批4 |
| **S13** | P2 | `OnData` 一次返回两条 PDU（Erect Domain + Attach User） | 甲 | 批4 |
| **S14** | P2 | `state_.error` 是 `std::string`，无错误码 | 甲 | 批4 |
| **S15** | P2 | 仓库内无 socket 驱动；`rtsc_probe` 只到 CCF | 甲 | 批3 |
| **S16** | P2 | `Send` 可能把一条明文拆成多条 TLS record | 甲 | 批3 |
| **S17** | P2 | `CredsspClient::complete()` 在第 5 步发出后立刻为真 | 甲 | 批4 |
| **S18** | P0 | 生产路径永远拿不到服务器公钥 → `pubKeyAuth` 用空串哈希，第 4 步必失败 | 双方 | 批1 |
| **S19** | P2 | `min_version=0x0304` 时 `ProtocolMask()` 只置 1.3 → `0x80090331` | 甲 | 批2 |
| **S20** | P1 | 口令两份、同名不同义、NLA 下仍无条件回填 Client Info | 双方 | 批4 |
| **S21** | P1 | （=乙 B19）`tls_schannel.cpp` 无条件 include Windows 头 → Linux 编译期失败 | 乙 | 批0 |
| **S22** | P2 | `Shutdown()` 失败路径（`:435`（批 0 后；锚点 `return MakeError(Status::kOk, st, "shutdown best effort");`））返回 `kOk` 且不置 `closed_`，`closed()` 说谎 | 乙（=B13） | 批2 |
| **S23** | P2 | `tls.h:42` 承诺 `native_code = alert description`，实测**无法兑现** | 甲 | 批2 |
| **S24** | **P1** | `Shutdown()` 空 control token → 发出 **type=22 重协商**而非 type=21 close_notify | 甲 | 批2 |

**级别汇总：P0 × 5（S1,S2,S3,S4,S18）· P1 × 9（S5,S6,S7,S8,S9,S11,S20,S21,S24）· P2 × 10（S10,S12,S13,S14,S15,S16,S17,S19,S22,S23）= 24。**

**归属汇总：甲独有 14（S1,S5,S6,S7,S10,S11,S12,S13,S14,S15,S16,S17,S23,S24）· 乙独有 2（S21,S22）· 双方独立发现 8（S2,S3,S4,S8,S9,S18,S19,S20）。**
其中 S19 乙归为「甲」（M33 的来源列写「甲」），此处按**我先提出**归「甲」；
乙的贡献是把它并入 M 表并给了 `EnforceVersionWindow` 的补充判据，已在 §17.4 采纳。

#### 18.1.2 S → M 双向映射（第一方向）

| S | 对应的 M | 备注 |
|---|---|---|
| S1 | **M01** | 一对一 |
| S2 | **M02** | M02 同时吸收乙的 B03+B05 |
| S3 | **M03** | M03 同时吸收乙的 B06 |
| S4 | **M04** | 一对一 |
| S5 | **M09** | 一对一 |
| S6 | **M10** | 一对一 |
| S7 | **M11** | M11 的修复方案（解析 `15 03 03 00 02 <lvl> <desc>`）**已被 U4 实测推翻**，见 S23 |
| S8 | **M08** | 一对一 |
| S9 | **M05** | 一对一 |
| S10 | **M12** | 一对一 |
| S11 | **M13** | 一对一 |
| S12 | **M06** | 一对一 |
| S13 | **M14** | 一对一 |
| S14 | **M15** | 一对一 |
| S15 | **M16** | 一对一 |
| S16 | **M17** | 一对一 |
| S17 | **M07** | 一对一 |
| S18 | **M18** | M18 同时吸收乙的 B01 |
| S19 | **M33** | 一对一 |
| S20 | **M25 + M27** | **一对二**：M25=演进出口双方同名不同义；M27=NLA 下 Client Info 无条件回填。二者同一根因、同一修复点（`cm:165-168`），故合并为 S20 |
| S21 | **M28** | M28 同时吸收乙的 B19 |
| S22 | **M23** | M23 同时吸收乙的 B13 |
| S23 | **（无）** | M 表未收录；乙的 M11 间接依赖了被打翻的前提 |
| S24 | **（无）** | M 表未收录；乙的 M22（`SEC_I_RENEGOTIATE` 未处理）与它相邻但不同 |

**另有一条「不是 S 的 S」**：N6（`WrapTpkt` 的 65528/65531 三字节缝隙）= **M35**。
它不是独立缺陷，已作为 **C6** 并入 S2/S3 的接口契约（§17.3.2 的 Q7）。

#### 18.1.3 M → S 双向映射（第二方向，含 12 条无 S 的处置）

| M | 对应的 S | 若无 S，为什么不单列 |
|---|---|---|
| M01 | S1 | — |
| M02 | S2 | — |
| M03 | S3 | — |
| M04 | S4 | — |
| M05 | S9 | — |
| M06 | S12 | — |
| M07 | S17 | — |
| M08 | S8 | — |
| M09 | S5 | — |
| M10 | S6 | — |
| M11 | S7 | 但**其修复方案被 U4 推翻**，见 S23 |
| M12 | S10 | — |
| M13 | S11 | — |
| M14 | S13 | — |
| M15 | S14 | — |
| M16 | S15 | — |
| M17 | S16 | — |
| M18 | S18 | — |
| **M19** | **无** | 「切分边界约束不一致」是 S2+S3 的另一种表述：安全层拥有切分权后自然统一。已由 §3.1「阶段与缓冲区必须同属一个所有者」覆盖 |
| **M20** | **无** | 「缺 TPKT 分帧层」与 S2/S3 同源；安全层内部做 `TpktStream` 后不再缺 |
| **M21** | **无** | `CredsspClient` 缺 `failed()`/`last_error()`/`Abort()`：API 完整性建议，非可观察 bug。若采纳 `SecurityError` 则 `Abort` 可选加入批1 |
| **M22** | **无** | `SEC_I_RENEGOTIATE` 未映射。我**未能构造出独立于 S24 的重协商触发**（`probe_s25` B/F 的重协商都是 S24 造成的）。S24 修好后对端主动重协商是否可达 → 见 U-N11 |
| M23 | S22 | — |
| **M24** | **无** | `plaintext` 契约自相矛盾（append-only vs 失败必清空）：文档级，随 S10 的 D1 一并改写 `tls.h:146-150` |
| M25 | S20 | — |
| **M26** | **无** | `CS_SEC.encryptionMethods = 0x1B`：属 HYBRID_EX 能力协商，与 S20 同批可选；需 U-02 实测才能定论 |
| M27 | S20 | — |
| M28 | S21 | — |
| **M29** | **无** | 「PUBLIC include 扩散」：构建卫生，批0 的三层拆分顺带解决（`rtsc_tls_api` 只暴露 `include/`） |
| **M30** | **无** | 「无『连接被关闭』入口」：与 S12 同批，作为 `OnExternalSecurityFailed` 的可选扩展；非必需 |
| **M31** | **无** | 乙自己标注「不占缺陷名额」（`audit-b.md:1794`） |
| **M32** | **无** | `done()` 语义：与 S17 同类（「完成」的含义），随 S17 的同批注释修订 |
| M33 | S19 | — |
| **M34** | **无** | 外部安全失败通道：同 M30，归入 S12 的可选扩展 |
| M35 | **N6**（并入 S2/S3 的 C6） | 不单列 |
| **M36** | **无** | `CS_SEC.extEncryptionMethods`：与 M26 同类，同批可选 |

**统计：36 个 M 中，23 个映射到 S（其中 M25/M27 共同映射到 S20，故落在 22 个 S 上：S1–S22），12 个判定为「无 S」并给出理由，1 个（M35）转成契约项 C6。 23 + 12 + 1 = 36。**

### 18.2 批次修订（仍为 6 批，成员重新分配）

> **§17.4 的一处错误必须订正**：我把 **S22 放在了批 1（CredSSP）**，
> 但 S22 的修复点在 `src/net/tls_schannel.cpp:435`（锚点 `return MakeError(Status::kOk, st, "shutdown best effort");`），验收套件是 `rtsc_tls_tests`。
> 放在批 1 会迫使批 1 同时改 TLS 后端，破坏「批 1 与批 2 可并行」的前提。
> **S22 归批 2。**

#### 18.2.1 修订后的完整批次表

| 批 | 成员（S） | 成员（M） | 改哪些文件:行 | 验收判据 | 该批新断言能检出的变异 |
|---|---|---|---|---|---|
| **批0**<br>跨平台 | **S21** | M28 | `CMakeLists.txt:51-55`；新增 `src/net/tls_factory.cpp`；`src/net/tls_factory.cpp`（批 0 搬迁：CreateTlsTransport / EnumerateTlsBackends）（工厂搬出） | Windows `cmake --build` 成功 + `rtsc_tls_tests` 26 绿；Linux `cmake --build` **成功**；Linux `ctest` 除 TLS 外全绿 | 恢复 `CMakeLists.txt:51` 的无条件 `add_library(rtsc_tls STATIC src/net/tls_schannel.cpp)` → Linux 编译报「找不到 windows.h」 |
| **批1**<br>CredSSP 生产注入 | **S1 S5 S6 S11 S18** | M01 M09 M10 M13 M18 | `src/credssp/credssp.cpp:46`(S1)、`:93-94` 之间(S5+S6)、`:357-360`(S11)；`include/rtsc/credssp/credssp.h:60-61`(S18)；新增 `src/crypto/random.cpp` + `include/rtsc/crypto/random.h` | `rtsc_credssp_sm_tests` 15 绿 + `rtsc_ntlm_tests` 27 绿 + `rtsc_credssp_tests` 23 绿 | ① `:46` 恢复 `nonce_.assign(kNonceSize,0)` → `two_constructions_have_different_nonces` 失败；② 删 S18 的空公钥检查 → `start_without_public_key_fails` 失败；③ `:357-360` 恢复不验 MAC → `tampered_signature_checksum_is_rejected` 失败；④ 删 S5 的版本校验 → `version_below_min_is_rejected_with_valid_challenge` 失败 |
| **批2**<br>TLS 后端 | **S7 S8 S9 S10 S19 S22 S23 S24** | M05 M08 M11 M12 M23 M33（S23/S24 无 M） | `src/net/tls_schannel.cpp:411`（锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`）(S24-a)、`:411`(S24-c)、`:431-435`（批 0 后；锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`）(S24-b+S22)、`:232`(S9)、`:101-201`(S10 D1)、`tls.h:129-132`(S10 契约)、`tls.h:42`(S23)、`:184-187`(S7)、`:135-147`+`:491-509`(S8)、`:467-472`(S19)；`tests/test_tls.cpp:848-862`（S24 新断言）、`:879-885`（S19 测试修正） | `rtsc_tls_tests` **26 绿 + 新增 ≥5 条**（S24、S22、S9、S19、S8） | 见 18.3.1 的逐条变异表 |
| **批3**<br>安全层 | **S2 S3 S4 S15 S16** | M02 M03 M04 M16 M17 + C6/M35 | 新增 `include/rtsc/sec/security_layer.h`（§17.3.2）、`include/rtsc/sec/security_error.h`（§17.3.1）、`src/sec/security_layer.cpp`、`src/sec/socket_driver.cpp`；`CMakeLists.txt` 加 `rtsc_security`；`tools/rtsc_probe/main.cpp`（`--full`） | 新套件 `rtsc_security_tests` T1–T13 绿 + `rtsc_framing_tests` 11 绿 + `rtsc_connect_machine_tests` 26 绿 | ① `kAwaitEuar` 改为把 `plain_` 直接交给 `TpktStream` → `euar_denied_emits_no_pdus` 失败；② 删 `WrapTpkt` 空返回检查 → `wraptpkt_overflow_is_reported` 失败；③ 去掉 4 字节 `remove_prefix(4)` → `euar_and_mcs_in_one_record` 失败 |
| **批4**<br>协议层小修 | **S12 S13 S14 S17 S20** | M06 M07 M14 M15 M25 M27 | `connect_machine.cpp:353-357`(S12)、`connect_machine.h:38-41` 注释(S13)、`connect_machine.h:57`+`cp:122-125`(S14)、`credssp.h:51-53` 注释(S17)、`connect_machine.cpp:165-168`(S20) | `rtsc_connect_machine_tests` 26 绿 + 新增 3 条 | ① `:168` 恢复无条件回填 password → `client_info_password_empty_under_enhanced_security` 失败；② `:353-357` 恢复 no-op → `wrong_phase_external_security_complete_fails` 失败 |
| **批5**<br>真机联调 | 无新缺陷 | — | — | `rtsc_probe --full <host> 3389 <cookie>` 打印 `phase=await-connect-response` 且 `pdus` 含 Connect Response | 不适用（集成验证）。**若失败，失败点必须落在 §15.3.2 的三处未知之一**，否则说明还有未发现的缺陷 |

**总计：批0(1) + 批1(5) + 批2(8) + 批3(5) + 批4(5) = 24 个 S，全覆盖，无遗漏、无重复。**

#### 18.2.2 S24 的新断言（可直接粘贴）

在 `tests/test_tls.cpp:848` 的 `shutdown_is_idempotent` 里，
把 `:857` 的 `CHECK(!first.empty());  // close_notify must be emitted` 替换为：

```cpp
    CHECK(!first.empty());
    // S24: the record must be an ALERT (21), not a HANDSHAKE (22). The old
    // assertion only checked "non-empty", which a 201-byte renegotiation
    // ClientHello satisfies just as well as a 31-byte close_notify.
    CHECK_EQ(static_cast<int>(first[0]), 21);   // 21 = Alert, 22 = Handshake
    CHECK_EQ(first.size(), static_cast<size_t>(31));  // close_notify body = 26
```

**为什么这行能区分**：`first[0]` 是 TLS record 的 `ContentType`。
- 修复前（S24 存在）：`first[0] == 0x16 == 22`（Handshake），`first.size() == 201`；
- 修复后：`first[0] == 0x15 == 21`（Alert），`first.size() == 31`。
两者都是非空，所以旧断言必绿；新断言的第一个就红。实测依据：`probe_s25` B（22/201）vs E（21/31）。

**再加一条服务端确认（可选，成本几乎为零）**，因为 `RawServer::Decrypt` 已经存在：

```cpp
    // The peer must decode it as "context expired", not as a renegotiation.
    Bytes peer_pt;
    size_t peer_extra = 0;
    CHECK(lb.server().Decrypt(first, peer_pt, peer_extra) == SEC_I_CONTEXT_EXPIRED);
```

依据：`RawServer::Decrypt` 在 `tests/test_tls.cpp:114`，返回原始 `SECURITY_STATUS`；
`lb.server()` 在 `:208` 已公开。修复前这条会是 `SEC_I_RENEGOTIATE`（实测 `probe_u4b` Q9）。

### 18.3 验收判据的「门禁」修订：从「用例数」到「能检出什么变异」

#### 18.3.1 批 2 的逐条变异表（S24 暴露的问题在批 2 最集中）

| S | 变异（把实现改回修复前） | 会失败的新断言 | 失败时的实际读数 |
|---|---|---|---|
| **S24-a** | `src/net/tls_schannel.cpp:411-413`（批 0 后；锚点 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}`） 恢复 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}` | `CHECK_EQ(static_cast<int>(first[0]), 21)` | 得 22（Handshake）；`first.size()` 得 201 |
| **S24-c** | `:411` 恢复不检查返回值 | 与 S24-a 同一条（ctl 失败必导致 token 未生效） | 得 22 |
| **S24-b** | `:431` 恢复 `\|\| st == SEC_I_CONTINUE_NEEDED` | **无运行期断言可检出**（修复后不可达）→ 只能靠代码评审门禁 | 无 |
| **S22** | `:435` 恢复为不置 `closed_` | `CHECK(lb.client().closed())`（新增用例：`Shutdown()` 于握手未完成时不得报成功） | `closed=false` 而 `status=kOk`（实测 A 格） |
| **S9** | `:232` 恢复 `if (closed_) return kClosed` | `shutdown_then_receive_still_drains` | `Receive` 返回 `kClosed` 且 plaintext 为空，`buffered_input()>0` |
| **S19** | `:467-472` 恢复只置 1.3 | `CHECK_EQ(static_cast<int>(e.status), kOk)` on `CreateTlsTransport` | `0x80090331`（实测 `probe_s19`） |
| **S23** | 把 `:184` 之前的实现改成「读 `plain[0]` 当 alert description」 | `CHECK_EQ(e.native_code, 0x00090317)` | 得 21（`0x15`），而不是 `0x00090317`（实测 `probe_u4e` T3） |
| **S7** | 保持 `kPeerAlert` 不产出 | `CHECK_EQ(e.status, Status::kPeerAlert)`（若批2 决定实现） | `kProtocolError` + `native_code=0x80090318` |
| **S8** | `:139-143` 恢复 `kStrict` 用 MANUAL | `strict_policy_rejects_self_signed` | 握手成功（自签证书被接受） |
| **S10** | `:169` 恢复 `consumed = in_size` 且不吸收尾部 | `coalesced_finished_and_app_data_are_both_delivered` | `total recovered = 0`（实测 `probe_s10` M8） |

#### 18.3.2 为什么 `shutdown_is_idempotent` 检不出 S24（缺口解剖）

| 层面 | 现状 | 后果 |
|---|---|---|
| **注释** | `:857` 写 `// close_notify must be emitted` | 注释不是断言，测试框架不执行它 |
| **断言** | `:857` 只有 `CHECK(!first.empty())` | 201 字节的重协商 ClientHello 也「非空」→ 必绿 |
| **缺维度** | 没有任何断言检查 `first[0]`（record type） | type 21 与 22 在测试眼里完全等价 |
| **缺负向对照** | 没有「必须是 Alert，不能是 Handshake」的对照 | 无法区分「对的记录」与「另一种合法但错误的记录」 |
| **缺对端视角** | 未调用 `lb.server().Decrypt(first, ...)`（`:114` 已具备） | 无法验证对端是否把它解读为 close_notify |
| **名称误导** | 测试名叫 `shutdown_is_idempotent`，只测幂等 | 名字暗示「关闭正确」，实际只测「第二次不再产出」 |

**推广成一条门禁规则**（建议写进 `AGENTS.md`）：
> **凡是「发了什么」的契约，断言必须锚定在线格式的第一个判别字节上，
> 不能只断言「非空」。** 「非空」是必要条件，永远不是充分条件。
> 对 TLS：`record[0]`；对 TPKT：`frame[0]==0x03 && frame[1]==0x00`；
> 对 TSRequest：`der[0]==0x30`。

#### 18.3.3 三处同类缺口（同一病根，不止 S24）

| 位置 | 「注释声明 A、断言只验 B」 | 检出能力 |
|---|---|---|
| `tests/test_tls.cpp:857` | 注释 close_notify，断言非空 | **零**（S24 存活至今） |
| `tests/test_tls.cpp:879-885` | `version_bounds_are_enforced_after_handshake` 的 `if (!started) { CHECK(!why.empty()); return; }` | **零**：`CreateTlsTransport` 直接失败也算通过，把 S19 的 `0x80090331` 洗成绿色 |
| `tests/test_tls.cpp:868-889` 整体 | 名字说「enforced」，但「提前失败」与「成功但版本错」都算通过 | 只能保证「不会静默用 1.2」，不能保证「用了 1.3」 |

**这三处必须同时修**，否则批 2 的「26 绿」仍然是虚假覆盖率。

### 18.4 我仍不确定的（§17.8 更新）

| # | 状态 | 内容 |
|---|---|---|
| **U-N1** | **仍未消除（降级为可控）** | `boundary2/9/12`、`extra_is_zero`、`max_out_is_soft_and_caller_can_drain`（`:694-727`）这 5 个用例在 D1 下**未回放**。机制论证同 §17.7.3（都只用 `Receive`，D1 只改 `Handshake`），但 `max_out` 会与「尾部预注入 + 软阈值」交互。**消除方式**：批 2 执行时直接跑全 26 条；若 `max_out` 变红，先看 `buffered_input()` 是否因尾部预注入非零 |
| **U-N2** | **已消除** | S24 修复后 `shutdown_is_idempotent` 仍绿：`probe_s25` E 给出 `SEC_E_OK` + **31 字节非空** → `CHECK(!first.empty())` 成立；`t:406` 的 `shutdown_sent_` 使第二次返回空 → `second.empty()` 成立。**但必须同时加 18.2.2 的 type 断言**，否则测试仍检不出回归 |
| **U-N3** | **未消除** | S24 修复后真实 RDP 服务器收到**真 close_notify** 是否会改变断开时序。RDP 通常先发 `McsDisconnectProviderUltimatum` 再关 TLS；若 S24 先发 close_notify，服务器可能在 MCS 断开前就关 socket。**新增 U-N7** 单列 |
| **U-N4** | **未消除** | S7/S23 的最终形态是否够用：若服务器用**错误密码**时不回 TSRequest `errorCode` 而直接发 TLS alert，则 CredSSP 层也拿不到 NTSTATUS，只剩 `SEC_I_CONTEXT_EXPIRED`。需要 U6 实测（需有效凭据） |
| **U-N5** | **未消除** | 批 0 拆分 `CreateTlsTransport` 时，`src/net/tls_factory.cpp`（批 0 搬迁：CreateTlsTransport / EnumerateTlsBackends） 的两个符号怎么处理最稳（① 改名为 `CreateSchannelTransport` + 内部头；② 保留原名 `#ifdef` 包住；③ 整体移到 `tls_factory.cpp`）。① 最干净但需新增内部头；③ 改动最大；我没实测哪个在 `/W4 /WX` 下不产生未使用符号警告 |
| **U-N6** | **已消除** | `plain[0]=21, plain[1]=3` 不是 alert 语义：`0x15`=record type Alert、`0x03`=version 高字节。`probe_u4e` T3 的读数已解释；实现若要「确认拿到 alert」，必须断言 `level ∈ {1,2}`——而实测拿不到 |
| **U-N7** | **新增** | S24 修复后的关闭顺序：close_notify 应在 `McsDisconnectProviderUltimatum` 之后发，还是可以独立发？现有 `tls.h:178-180` 只说「graceful close」。若不定义顺序，S15 的 socket 驱动可能在 MCS 断开前就关 TLS，导致服务器记录异常。**建议**：`SecurityLayer` 的 `kDraining` 阶段先排空 MCS 断开 PDU，再调 `Shutdown()` |
| **U-N8** | **新增** | `0x00090312` 与 `0x80090302` 只在**本机**（Windows 10/11 + 当前 SChannel）测得。Server 2019/2022 的 SChannel 对空 token 的返回值、以及对 `SCHANNEL_SHUTDOWN` 的响应是否一致，**未验证**。若不一致，S24 的 type 断言在 CI 的另一台机器上可能给出不同读数 |
| **U-N9** | **新增** | S22 的两种修法互斥且都有代价：① `:435` 置 `closed_=true` 并返回真实状态 → 中途 `Shutdown()` 的调用方会看到 `closed()==true` 但没发出 close_notify；② 在 `:407` 前加 `if (!handshake_complete_) return kProtocolError` → 与 `Send`（`:208-209`）一致，但会**改变行为**（现在中途 Shutdown 是 `kOk`），可能破坏 S15 的「提前中止」用法。我倾向 ②，但没有调用方代码可查（`SecurityLayer` 尚未写） |
| **U-N10** | **新增** | S23 修复后 `tls.h:42` 的注释该怎么写才不误导。**建议原文**：`kPeerAlert, // Backend surfaced a fatal alert. NOTE: SChannel cannot fill native_code with the alert description — TLS 1.2/1.3 encrypt alerts, so DecryptMessage reports SEC_I_CONTEXT_EXPIRED (0x00090317) and no SecBuffer exposes level/description (measured: evidence/u4/probe_u4e.out.txt). Kept for backends that can (OpenSSL SSL_AD_*). Never interpret native_code as an alert description byte.` |
| **U-N11** | **新增** | **对端主动发起重协商**是否可达（乙的 M22）。`probe_s25` 的 B/F 两格都是**我们自己**造成的重协商；一个恶意服务器在握手后发 `type=22` 的 ClientHello 会怎样？`Receive` 的 `:305/:308` 映射未覆盖这条路径，我也没构造出用例。若可达，M22 应升级为独立缺陷（但那将是 S25，不是现在这个） |

### 18.5 自查：「手写副本代替产品」的排查结果

父代理的教训对我适用，逐项自查本轮及此前全部探针：

| 探针 | 是否链接 `rtsc_tls.lib` | 被测对象 | 结论 |
|---|---|---|---|
| `probe_s10`（M5/M8/G1–G4） | **是**（`build.bat` 链接 `rtsc_tls.lib`） | 产品 `Handshake`/`Receive` | ✅ 合规 |
| `probe_u4` / `u4b` / `u4c` | 否（裸 SSPI 双端） | **SChannel API 语义** | ✅ 合规（问题本就是「SChannel 返回什么」，不是「产品做什么」） |
| `probe_u4d`（S3：产品 Shutdown 记录形状） | **是**（`build_d.bat` 链接 `rtsc_tls.lib`；`probe_u4d.cpp:313` 调 `CreateTlsTransport`） | **产品** `Shutdown` | ✅ **S24 的核心证据（out=201/type=22）来自产品代码，不是手写副本** |
| `probe_u4e`（T1–T5） | 否（裸 SSPI） | **API 语义**（正确 token 产出什么） | ⚠️ **但 §17.6.2 的 T4 行写错了**，见下 |
| `probe_u4f` | 否 | API 语义 | ✅ 合规 |
| `probe_n1`（N1/D1） | **是**（`build_n1.bat` 链接 `rtsc_tls.lib`，用 `D1Wrapper` 包真实 transport） | **产品** `Handshake`/`Receive` | ✅ 合规 |
| `probe_s25`（本轮） | **A/B 段是**（链接产品库）；C/D/E/F 段是裸 SSPI | A/B=产品；C–F=API 语义 | ✅ 合规（用途已在输出里分段标注） |

**必须订正的一处（§17.6.2 的 T4 行）**：
我写「**错误的** `ApplyControlToken`（空 token，即产品当前做法）→ `SEC_E_UNSUPPORTED_FUNCTION`」。
这句话把**裸服务端上下文**的读数写成了「产品当前做法」的结果。
实情是：
- 空 token 在**裸上下文**上确实返回 `0x80090302`（`probe_s25` D/F 两格复核）；
- 但**产品**的空 token 调用把返回值丢弃了，所以产品侧看到的是 `out=201` / `type=22`（B 格）。
**「产品当前做法」的正确读数只有 B 格（201/22），不是 `SEC_E_UNSUPPORTED_FUNCTION`。**
订正后的 §17.6.2 T4 行应为：「错误的 `ApplyControlToken`（空 token）在**裸上下文**返回 `SEC_E_UNSUPPORTED_FUNCTION`（D/F）；产品因为丢弃返回值（`:413`（批 0 后；锚点 `ApplyControlToken(&ctx_, &desc)`）），把这个失败变成了『ISC 继续握手』，最终发出 type=22（B）。」

**另一处值得记录的方法论细节**：同样是「空 token + 握手已完成」，
裸客户端给出 **183 字节**（F），产品给出 **201 字节**（B）。
原因是我手写的 `RawClient` 与产品的 ISC 参数/凭据形状不同（产品走 `ISC_REQ_ALLOCATE_MEMORY` 与自有证书策略）。
**这正好独立印证了父代理的教训**：同一 API 序列在不同上下文里字节数可以不同，
所以「手写副本测出的具体数值」不能当成产品读数——**只有 record type 这种结构性结论可以跨上下文迁移**。
S24 的结论之所以成立，是因为我引用的是 B 格（产品，201/22），不是 F 格（裸，183/22）。

---

## 19. 执行交接包

> **本章的执行信息是自包含的。** 执行 AI 不需要为了「改哪个文件、改成什么、
> 怎么验证、失败怎么退」去读 §0–§18，也不需要读乙的报告。
> 本章括号里的 §编号是**可选的背景追溯**，不是执行前提。
> **判据一（语义）：** `evidence/exec/verify_citations.py`（**43 项**，内容锚点 +
> 动态章节边界）对 §5/§6/§13/§15/§17/§18/§19 的 43 条关键引用逐条断言
> 「散文所述构造确实在该行号上」。绿 `43 passed / 0 failed`。
> 红证 B（文档一字不改、只把源码 `:169` 改成 `consumed = in_size_other;`）
> 仍报失败 —— 证明**语义比对独立生效**，不是只查锚点能否找到。
>
> **判据二（结构）：** `evidence/exec/verify_anchors.py` 对上述七章的 407 条
> 行号引用逐条检查：凡带 `（锚点 ...）` 的，锚点必须**唯一地**落在被引用行；
> 区间引用（`t:A-B`）要求首片段在 `cur[A]`、末片段在 `cur[B]`。
> 当前 `66 条锚点全部定位唯一且正确 / WRONGLINE 0`。
>
> **覆盖边界（不隐瞒）：** 判据一覆盖 43 条，判据二覆盖 407 条中被引用到
> 源文件的全部；**无锚点条款的引用（§19 有 26 条）由判据一负责**，
> 不在判据二内。**§20 之后的审计历史章节不在两条判据内**，
> 仍须按锚点文本 `Select-String` 核对，不得默认正确。
>
> **本章的每一条都是可执行的。** 凡我实测过的，标注 `[实测]` 并给出输出文件；
> 凡我**没有**实测的，标注 `[未验证]` 并说明需要什么条件。禁止把 `[未验证]` 当成已通过。
>
> 行号基线：`CMakeLists.txt` 193 行、`src/net/tls_schannel.cpp` 748 行、
> `include/rtsc/net/tls.h` 208 行、`tests/test_tls.cpp` 893 行、`tests/test_framework.h` 82 行。

### 19.1 执行 AI 必读的三件事

#### 19.1.1 项目背景（一段话）

`F:\rtsc` 是一个**从 mstsc 逆向出来的 RDP 客户端协议栈**（C++20，CMake + Ninja，MSVC）。
目前已完成：X.224 连接初始化、RDP 协商、MCS、Client Info、Licensing、Capabilities、Share 等，
共 17 个测试可执行文件。**尚未完成的是「外部安全层」**——即
`TLS 握手 → CredSSP 五步 → EUAR 4 字节 → MCS` 这条链路。
现状是：`rtsc_tls`（SChannel 后端）与 `rtsc_credssp`（CredSSP 消息层）各自能单独工作，
**但没有任何代码把它们串起来**，`ConnectMachine` 在 `kAwaitExternalSecurity` 阶段会
把数据当错误（`src/proto/connect_machine.cpp:224`），`tools/rtsc_probe` 只到 CCF 就关 socket。
本交接包要做的事就是：**修掉 24 个缺陷，并把这条链路的三个缓冲区所有权统一到一个 `SecurityLayer` 里**。

#### 19.1.2 硬约束（违反任一 = 本批不通过）

| # | 约束 | 说明 |
|---|---|---|
| **H1** | 所有产物只写 `F:\rtsc` 内 | 临时文件放 `F:\rtsc\.tmp`；**禁止写 C 盘**（会污染系统且可能无权限） |
| **H2** | 每次编译前设置临时目录 | PowerShell 里先执行 `$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'` |
| **H3** | 构建入口只有一条 | `cmd /c F:\rtsc\.tmp\build_tls.bat`（内部调 vcvars64 + `cmake --build F:\rtsc\build\verify`）。**不要新建 build 目录、不要换生成器**（现有是 Ninja） |
| **H4** | 警告即错误 | `CMakeLists.txt:13` 已有全局 `/W4 /WX`（MSVC）与 `-Wall -Wextra -Werror -Wpedantic`（GCC）。**不要为了过编译加 `#pragma warning(disable)`** |
| **H5** | `.ps1` / `.bat` 只能是 ASCII | 任何非 ASCII 字符（含中文注释）都会让 PowerShell 5.1 按 ANSI 解析而报错。脚本里的中文一律改成英文注释 |
| **H6** | 不许用 PowerShell 写中文 | 用 `write` 工具或 Python `io.open(..., encoding='utf-8', newline='')`。`Set-Content`/`Out-File` 会写 BOM 或转码 |
| **H7** | 不许改测试让它通过 | 见 §19.6 |

#### 19.1.3 TDD 顺序（强制）

**每一批、每一个缺陷，都必须按这个顺序**：

```
1. 写测试（或改测试） -> 2. 编译            -> 3. 运行，确认【失败】并记录失败输出（红证）
                                            |
                                            +--> 若第 3 步是【通过】：说明测试没抓到问题，
                                                 回到第 1 步重写测试。不许继续。
4. 写最小实现 -> 5. 编译 -> 6. 运行，确认【通过】（绿证）
7. 重构（可选） -> 8. 重跑该批全部套件 + 上游套件
```

**红证的标准**：必须是**具体用例名 + 具体断言文本 + 实际读数**，例如

```
[FAIL] shutdown_is_idempotent
  first[0] == 21 (got 22, want 21)
```

**不接受**：「原本就不通过」「大概会失败」「理论上应该红」。
**禁止先写实现再补测试**——那样你无法证明测试真的能抓到问题（S24 就是这么活下来的，§18.3.2）。

### 19.2 批次 0（跨平台拆分）的完整操作步骤

> 批 0 是其余五批的**前置**，也是唯一动了构建系统的批次。
> 它的目标只有一个：**让 `F:\rtsc` 在 Linux 上能 `cmake --build` 成功**，
> 同时 Windows 行为**逐字节不变**（`rtsc_tls_tests` 26 条仍全绿）。

#### 19.2.0 现状与红基线 `[实测]`

现状（三处必须改）：

| 位置 | 现状 | 问题 |
|---|---|---|
| `CMakeLists.txt:51` | `add_library(rtsc_tls STATIC src/net/tls_schannel.cpp)` | 无条件编译 Windows TU |
| `CMakeLists.txt:105-107` | `add_executable(rtsc_tls_tests ...)` 无条件 | Linux 会连带失败 |
| `CMakeLists.txt:152` | `add_test(NAME tls COMMAND rtsc_tls_tests)` 无条件 | Linux `ctest` 找不到可执行文件 |

**红基线（我已实跑，你可以直接复现）**：

```bash
# 在 WSL 里执行（本机 WSL 有 cmake 3.28.3 / ninja / g++ 13.3.0 [实测]）
cd /mnt/f/rtsc
cmake -S . -B .tmp/bl-red -G Ninja -DCMAKE_BUILD_TYPE=Debug   # 配置成功
cmake --build .tmp/bl-red --target rtsc_tls                    # 编译失败
```

实际输出（`F:\rtsc\evidence\u4\s21-red.out.txt`）：
```
[1/2] Building CXX object CMakeFiles/rtsc_tls.dir/src/net/tls_schannel.cpp.o
FAILED: CMakeFiles/rtsc_tls.dir/src/net/tls_schannel.cpp.o
/usr/bin/c++ ... -c /mnt/f/rtsc/src/net/tls_schannel.cpp
/mnt/f/rtsc/src/net/tls_schannel.cpp:29:10: fatal error: windows.h: No such file or directory
   29 | #include <windows.h>
      |          ^~~~~~~~~~~
compilation terminated.
ninja: build stopped: subcommand failed.
BUILD_EXIT=1
```

**这就是 S21 的红证。修完批 0 之后，同一条命令必须变成 `BUILD_EXIT=0`。**

#### 19.2.1 目标结构（改完长这样）

```
rtsc_tls_api        INTERFACE   平台中立，只带 include/            （任何平台都建）
rtsc_tls_schannel   STATIC      仅 Windows：src/net/tls_schannel.cpp （if(WIN32)）
rtsc_tls            STATIC      门面：src/net/tls_factory.cpp        （任何平台都建）
```

**为什么门面必须单独存在**：`CreateTlsTransport`（`tls.h:198`）是**平台中立接口的一部分**，
所有上层代码都调它。若把门面留在 `tls_schannel.cpp` 里，Linux 上就没有这个符号，
`rtsc_security` 链接失败——那就把「编译错误」变成了「链接错误」，没有解决问题。

**为什么不在 `tls_schannel.cpp` 里用 `#ifdef _WIN32` 包住整个文件**：
被 `#ifdef` 掏空的 TU 仍然要参与编译，产出一个**空的目标文件**，然后静态库照常链接成功，
直到运行期 `CreateTlsTransport` 返回 `nullptr` 才暴露。**这会把一个编译期错误变成运行期迷雾。**
用 CMake 条件排除文件，情况是显式的。（§19.6 的 N3 明令禁止）

#### 19.2.2 逐步操作清单（8 步）

> **每一步之后都有「验证」与「失败怎么办」。** 不要跳步，不要合并步骤。

---

**步骤 S0.1 —— 备份（不备份不许动手）**

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$bk = 'F:\rtsc\.opencode\backups'
foreach ($f in @('CMakeLists.txt','src\net\tls_schannel.cpp','tests\test_tls.cpp')) {
    $name = ($f -replace '\\','_')
    Copy-Item -LiteralPath "F:\rtsc\$f" -Destination "$bk\$name.$ts"
}
Get-ChildItem $bk | Where-Object { $_.Name -like "*.$ts" } | Select-Object Name
```

**验证**：最后一条命令必须列出 **3 个**文件。
**备份命名规则**：`<原路径把 \ 换成 _>.<yyyyMMdd-HHmmss>`，与 `F:\rtsc\.opencode\backups\` 里
已有的 `discover.md.20261022-141336` 同风格 `[实测：该目录已存在且按此命名]`。

---

**步骤 S0.2 —— 新增内部头 `src/net/tls_schannel_internal.h`**

```cpp
// Internal seam between the SChannel backend and the platform-neutral facade.
// NOT part of the public API: only src/net/tls_factory.cpp includes this.
#pragma once

#include <memory>
#include <string>

#include "rtsc/net/tls.h"

namespace rtsc::tls {

// Defined in tls_schannel.cpp (Windows only). Returns nullptr and fills `why`
// when SChannel cannot serve the configuration.
std::unique_ptr<TlsTransport> CreateSchannelTransport(const Config& config,
                                                      std::string& why);

}  // namespace rtsc::tls
```

**验证**：文件存在，且**没有任何 `#include <windows.h>`**（`Select-String -Pattern 'windows'` 应无输出）。

---

**步骤 S0.3 —— 改 `src/net/tls_schannel.cpp` 的尾部（这是最容易出错的一步）**

现状（`:733-754`）：

```cpp
}  // namespace            // 733：匿名 namespace 关闭
                            // 734：空行
std::unique_ptr<TlsTransport> CreateTlsTransport(std::string_view backend,   // 735
                                                const Config& config,       // 736
                                                std::string& why) {         // 737
    why.clear();                                                        // 738
    const bool want_schannel =                                          // 739
        backend.empty() || backend == "schannel" || backend == "default";// 740
    if (!want_schannel) {                                               // 741
        why = "unknown TLS backend: " + std::string(backend);           // 742
        return nullptr;                                                 // 743
    }                                                                   // 744
    auto transport = std::make_unique<SchannelTransport>(config);       // 745
    if (!transport->Start(why)) return nullptr;                         // 746
    return transport;                                                   // 747
}                                                                       // 748
                                                                        // 749
std::vector<BackendInfo> EnumerateTlsBackends() {                       // 750
    return {{"schannel", true, ""}};                                    // 751
}                                                                       // 752
                                                                        // 753
}  // namespace rtsc::tls                                                // 754
```

**改成**（`SchannelTransport` 仍在匿名 namespace 内，不动）：

```cpp
}  // namespace

// Renamed from CreateTlsTransport (S21): the facade owns the public name so
// that non-Windows builds still define it. See src/net/tls_factory.cpp.
std::unique_ptr<TlsTransport> CreateSchannelTransport(const Config& config,
                                                      std::string& why) {
    why.clear();
    auto transport = std::make_unique<SchannelTransport>(config);
    if (!transport->Start(why)) return nullptr;
    return transport;
}

}  // namespace rtsc::tls
```

同时：
- 在 `:40`（`#include "rtsc/net/tls.h"` 之后）加 `#include "tls_schannel_internal.h"`；
- **删除** `EnumerateTlsBackends`（它搬到门面）；
- **删除** `backend` 参数与 `want_schannel` 判断（后端选择搬到门面）。

**验证（本步单独可验）**：
```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
Select-String -LiteralPath F:\rtsc\src\net\tls_schannel.cpp -Pattern 'CreateTlsTransport'
```
**预期：无输出**（旧名已不存在）。若仍有输出，说明你漏改了，**不要进入下一步**。

**失败怎么办**：本步只改了 `tls_schannel.cpp`，从备份恢复：
```powershell
Copy-Item -LiteralPath "F:\rtsc\.opencode\backups\src_net_tls_schannel.cpp.<ts>" -Destination F:\rtsc\src\net\tls_schannel.cpp -Force
```

---

**步骤 S0.4 —— 新增门面 `src/net/tls_factory.cpp`**

```cpp
// Platform-neutral TLS backend factory. This is the ONLY definition of
// CreateTlsTransport / EnumerateTlsBackends (S21): keeping them here means
// every platform links rtsc_tls successfully, and "no backend" is a runtime
// kUnsupported rather than a build break.
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "rtsc/net/tls.h"

#if defined(_WIN32)
#include "tls_schannel_internal.h"
#endif

namespace rtsc::tls {

std::unique_ptr<TlsTransport> CreateTlsTransport(std::string_view backend,
                                                const Config& config,
                                                std::string& why) {
    why.clear();
    const bool want_default =
        backend.empty() || backend == "schannel" || backend == "default";
#if defined(_WIN32)
    if (want_default) return CreateSchannelTransport(config, why);
    why = "unknown TLS backend: " + std::string(backend);
    return nullptr;
#else
    (void)config;
    if (want_default) {
        why = "no TLS backend for this platform (SChannel is Windows only)";
        return nullptr;
    }
    why = "unknown TLS backend: " + std::string(backend);
    return nullptr;
#endif
}

std::vector<BackendInfo> EnumerateTlsBackends() {
#if defined(_WIN32)
    return {{"schannel", true, ""}};
#else
    return {};
#endif
}

}  // namespace rtsc::tls
```

**验证**：
- `Select-String -LiteralPath F:\rtsc\src\net\tls_factory.cpp -Pattern 'windows\.h'` → **无输出**（这个文件必须平台中立）；
- `Select-String -LiteralPath F:\rtsc\src\net\tls_factory.cpp -Pattern '_WIN32'` → **恰好 2 处**（两个 `#if defined(_WIN32)`）。

---

**步骤 S0.5 —— 改 `CMakeLists.txt` 四处**

**(a) 替换 `:48-55`**（**批 0 已执行**；下面说的「原来的注释 + `add_library` 整段」指执行**前**的内容，当前 `cur:48` 已是替换后的新注释。此步骤仅作历史追溯）为：

```cmake
# TLS transport, three layers (S21 / M28).
#   rtsc_tls_api       INTERFACE, platform neutral, header only.
#   rtsc_tls_schannel  Windows only: the SChannel translation unit.
#   rtsc_tls           facade with the public CreateTlsTransport; always built,
#                      returns nullptr + reason on platforms with no backend.
add_library(rtsc_tls_api INTERFACE)
target_include_directories(rtsc_tls_api INTERFACE include)

if(WIN32)
    add_library(rtsc_tls_schannel STATIC src/net/tls_schannel.cpp)
    target_link_libraries(rtsc_tls_schannel PUBLIC rtsc_tls_api)
    target_link_libraries(rtsc_tls_schannel PUBLIC secur32 crypt32)
endif()

add_library(rtsc_tls STATIC src/net/tls_factory.cpp)
target_include_directories(rtsc_tls PUBLIC include)
target_link_libraries(rtsc_tls PUBLIC rtsc_tls_api)
target_include_directories(rtsc_tls PRIVATE src/net)
if(WIN32)
    target_link_libraries(rtsc_tls PUBLIC rtsc_tls_schannel)
endif()
```

> `target_include_directories(rtsc_tls PRIVATE src/net)` 是给 `tls_schannel_internal.h` 用的；
> 它是 `PRIVATE`，所以不会泄漏到公共头搜索路径。

**(b) 把 `:105-107` 包进 `if(WIN32)`**：

```cmake
if(WIN32)
    add_executable(rtsc_tls_tests tests/test_tls.cpp)
    target_link_libraries(rtsc_tls_tests PRIVATE rtsc_tls rtsc_util)
    target_include_directories(rtsc_tls_tests PRIVATE tests)
endif()
```

**(c) 把 `:168` 的 `add_test(NAME tls ...)` 包进 `if(WIN32)`**：

```cmake
if(WIN32)
    add_test(NAME tls COMMAND rtsc_tls_tests)
endif()
```

**(d) 把 `:188` 的 `/WX` 设置也包进去**（否则 MSVC 分支引用不存在的 target 会报错）：

```cmake
if(MSVC)
    ...
    if(WIN32)
        target_compile_options(rtsc_tls_tests PRIVATE /W4 /WX)
    endif()
endif()
```

> **⚠️ (b) 与 (c) 必须成对改。** 只包 `add_executable` 漏 `add_test` → Linux `ctest`
> 报「找不到测试可执行文件」；只包 `add_test` 漏 `add_executable` → Linux 构建直接失败。
> 这是 §17.5.2 Q2 的原话，已被 S21 的红基线证明会真实发生。

**验证**：`Select-String -LiteralPath F:\rtsc\CMakeLists.txt -Pattern 'rtsc_tls_tests'` 应命中 **3 处**
（`add_executable`、`target_link_libraries`、`target_include_directories`）**外加** `target_compile_options` 与 `add_test`，
且它们都在 `if(WIN32)`/`if(MSVC)` 块内。

---

**步骤 S0.6 —— Windows 验证 `[必须全绿]`**

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
cmd /c F:\rtsc\.tmp\build_tls.bat
if ($LASTEXITCODE -ne 0) { throw "WIN BUILD FAILED: $LASTEXITCODE" }
& F:\rtsc\build\verify\rtsc_tls_tests.exe
if ($LASTEXITCODE -ne 0) { throw "TLS TESTS FAILED" }
```

**预期输出（逐字）** `[实测基线]`：
```
26 tests, 139 checks, 0 failing tests, 0 failed checks
```
**行为不变性判据**：用例数必须仍为 **26**，checks 必须仍为 **139**。
若 checks 变少，说明你把某个断言改坏了；若用例数变了，说明你动了 `test_tls.cpp`（本批不该动它）。

**失败怎么办**：
1. 若是 CMake 配置错误 → 恢复 `CMakeLists.txt` 备份，删除 `F:\rtsc\build\verify\CMakeCache.txt` 之外的产物不需要动，重跑 `build_tls.bat` 让它重新生成；
2. 若是链接错误 `LNK2019 unresolved CreateSchannelTransport` → 你把 `tls_schannel_internal.h` 的声明和 `tls_schannel.cpp` 的定义签名写得不一致（最常见：忘了删 `std::string_view backend` 参数）；
3. 若是 `LNK2005 already defined` → 见 S0.7。

---

**步骤 S0.7 —— 「没有重复符号」的**具体**验证方法**

> 这是本批最容易埋雷的地方。重复定义的后果在 Linux 上是编译失败，
> 在 Windows 上要等到**可执行文件链接**时才报 `LNK2005`；而静态库阶段**不会报错**
> （静态库允许同名符号，链接器只在你把它们一起拉进来时才挑一个）。

**做法：不靠「链接过了」推断，直接查符号表。** 符号表能区分「哪个库定义了哪个名字」。

> **必须先过滤 `External`。** `dumpbin /symbols` 对一个函数会输出 20 行以上——
> 定义本体是 `External`，而 `dtor$0` / `$unwind$` / `$pdata$` / `$rtcName$0` 等
> 编译器生成物全是 `Static`。**只按函数名 grep 会被噪音淹没，判据必须锚在 `External` 上。**
> 这不是推测，是我在现有 `rtsc_tls.lib` 上实测的结果（见本节末的基线输出）。

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
$vs = 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
# Precondition: both libs must exist. Without this check a missing lib makes
# dumpbin print LNK1181 and the counts silently read as 0, which looks like a
# symbol problem when the real problem is "you have not built it yet".
foreach ($lib in @('rtsc_tls.lib','rtsc_tls_schannel.lib')) {
    if (-not (Test-Path "F:\rtsc\build\verify\$lib")) {
        throw "S0.7 PRECONDITION FAIL: $lib not found - run build_tls.bat first"
    }
}
# External definition of the facade symbol in the facade lib (expect exactly 1)
cmd /c "call ""$vs"" >nul 2>&1 && dumpbin /symbols F:\rtsc\build\verify\rtsc_tls.lib | findstr /C:""CreateTlsTransport"" | findstr /C:""External"" > F:\rtsc\.tmp\sym-facade.txt"
# External definition of the backend symbol in the backend lib (expect exactly 1)
cmd /c "call ""$vs"" >nul 2>&1 && dumpbin /symbols F:\rtsc\build\verify\rtsc_tls_schannel.lib | findstr /C:""CreateSchannelTransport"" | findstr /C:""External"" > F:\rtsc\.tmp\sym-backend.txt"
# The backend lib must NOT contain the facade name at all (expect empty)
cmd /c "call ""$vs"" >nul 2>&1 && dumpbin /symbols F:\rtsc\build\verify\rtsc_tls_schannel.lib | findstr /C:""CreateTlsTransport"" > F:\rtsc\.tmp\sym-backend-bad.txt"
$nFacade  = @(Get-Content F:\rtsc\.tmp\sym-facade.txt  -ErrorAction SilentlyContinue).Count
$nBackend = @(Get-Content F:\rtsc\.tmp\sym-backend.txt -ErrorAction SilentlyContinue).Count
$nBad     = @(Get-Content F:\rtsc\.tmp\sym-backend-bad.txt -ErrorAction SilentlyContinue).Count
Write-Output "facade External CreateTlsTransport        = $nFacade  (want 1)"
Write-Output "backend External CreateSchannelTransport  = $nBackend (want 1)"
Write-Output "backend mentions CreateTlsTransport       = $nBad     (want 0)"
if ($nFacade -ne 1)  { throw "S0.7 FAIL: facade does not define CreateTlsTransport exactly once" }
if ($nBackend -ne 1) { throw "S0.7 FAIL: backend does not define CreateSchannelTransport exactly once" }
if ($nBad -ne 0)     { throw "S0.7 FAIL: backend still defines CreateTlsTransport -> duplicate symbol" }
Write-Output "S0.7 PASS"
```

**通过判据（三条同时成立，脚本已内置）**：
1. `rtsc_tls.lib` 里 `CreateTlsTransport` 的 **`External`** 行**恰好 1 行**；
2. `rtsc_tls_schannel.lib` 里 `CreateSchannelTransport` 的 **`External`** 行**恰好 1 行**；
3. `rtsc_tls_schannel.lib` 里**完全不出现** `CreateTlsTransport`（任何类型都不许）。
   第 3 条是关键：**如果它非空，说明你没删干净旧函数，重复符号已经埋下。**

**基线（改前，在现有 `rtsc_tls.lib` 上实测）**——证明这个判据真的能读出来：

```
7AC 00000000 SECT6  notype ()    External     | ?CreateTlsTransport@tls@rtsc@@YA?AV?$unique_ptr@...
7AD 000003C0 SECT6  notype ()    External     | ?EnumerateTlsBackends@tls@rtsc@@YA?AV?$vector@...
902 00000000 SECT7  notype ()    Static       | ?dtor$0@?0??CreateTlsTransport@...
921 00000023 SECT7  notype ()    Static       | ?dtor$3@?0??CreateTlsTransport@...
F0E 000000C8 SECT4  notype       Static       | ?CreateTlsTransport@...$rtcName$0
F0F 000000E0 SECT4  notype       Static       | ?CreateTlsTransport@...$rtcVarDesc
F10 00000120 SECT4  notype       Static       | ?CreateTlsTransport@...$rtcFrameData
F13 ... $unwind$?CreateTlsTransport@...        Static
F16 ... $pdata$?CreateTlsTransport@...         Static
F17 ... $cppxdata$?CreateTlsTransport@...      Static
F18 ... $stateUnwindMap$?CreateTlsTransport@... Static
F19 ... $ip2state$?CreateTlsTransport@...      Static
F1A ... $unwind$?dtor$0@?0??CreateTlsTransport@... Static
F1D ... $pdata$?dtor$0@?0??CreateTlsTransport@...  Static
F1E ... $unwind$?dtor$3@?0??CreateTlsTransport@... Static
F1F ... $pdata$?dtor$3@?0??CreateTlsTransport@...  Static
F27 ... $unwind$?EnumerateTlsBackends@...      Static
F28 ... $pdata$?EnumerateTlsBackends@...       Static
```

**17 行里有 15 行是 `Static` 噪音，只有 2 行是 `External` 定义。**
这就是为什么必须过滤 `External`：**不过滤的话，`$nFacade` 会是 15 而不是 1，判据必然误报。**

**补充证明（端到端）**：`rtsc_tls_tests.exe` 能链接并运行，本身就是「没有重复符号」的必要条件
（有 `LNK2005` 就出不来 exe）。但**不要只用这一条**——静态库场景下，如果两个定义分别在不被同时拉取的
obj 里，`LNK2005` 可能不出现，直到某个调用组合才炸。

---

**步骤 S0.8 —— Linux 验证 `[实测基线已建立]`**

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
wsl -e bash -lc 'cd /mnt/f/rtsc && rm -rf .tmp/bl-green && cmake -S . -B .tmp/bl-green -G Ninja -DCMAKE_BUILD_TYPE=Debug >/mnt/f/rtsc/evidence/u4/s21-green-configure.txt 2>&1 && cmake --build .tmp/bl-green >/mnt/f/rtsc/evidence/u4/s21-green-build.txt 2>&1; echo GREEN_BUILD_EXIT=$?'
```

**通过判据**：`GREEN_BUILD_EXIT=0`。

**如果失败，必须先分类再动手**（这是本批唯一可能牵连无关代码的地方）：
| 失败文本 | 判定 | 处理 |
|---|---|---|
| `tls_schannel.cpp:29: fatal error: windows.h` | **批 0 没改对** | 回 S0.3/S0.5 |
| `undefined reference to rtsc::tls::CreateTlsTransport` | 门面没被编进去 | 查 S0.5 的 `rtsc_tls` 源文件列表 |
| 其他文件（`src/proto/**`、`src/credssp/**`）报 `-Werror` | **与批 0 无关的既有问题** | **停下来上报**，不要顺手改；这是新发现的缺陷 |
| `cmake_minimum_required` 版本不足 | WSL 的 cmake 太旧 | 用 `[实测]` 的 cmake 3.28.3；若更低，升级 |

**预期**：本机 WSL 为 Ubuntu 24.04 + cmake 3.28.3 + g++ 13.3.0 `[实测]`，项目要求 3.25。
**但我没有跑过「改完之后」的 Linux 全量构建**，所以这一步的绿灯必须由执行 AI 亲手取得 `[未验证]`。

> **注意**：Linux 构建产物在 `.tmp/bl-green`（已在 `F:\rtsc` 内），**不要**写进 `build/verify`，
> 否则会污染 Windows 的 Ninja 构建目录。

#### 19.2.3 批 0 的回滚规则（任何一步失败都适用）

本仓库 **不是 git 仓库**（`git status` 不可用），所以回滚只能靠备份：

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
$ts = '<timestamp recorded in S0.1>'
$bk = 'F:\rtsc\.opencode\backups'
Copy-Item -LiteralPath "$bk\CMakeLists.txt.$ts"          -Destination F:\rtsc\CMakeLists.txt -Force
Copy-Item -LiteralPath "$bk\src_net_tls_schannel.cpp.$ts" -Destination F:\rtsc\src\net\tls_schannel.cpp -Force
Copy-Item -LiteralPath "$bk\tests_test_tls.cpp.$ts"       -Destination F:\rtsc\tests\test_tls.cpp -Force
# the two NEW files are not in the backup, delete them
Remove-Item -LiteralPath F:\rtsc\src\net\tls_factory.cpp -ErrorAction SilentlyContinue
Remove-Item -LiteralPath F:\rtsc\src\net\tls_schannel_internal.h -ErrorAction SilentlyContinue
cmd /c F:\rtsc\.tmp\build_tls.bat
```

**禁止**使用 `git checkout` / `git restore` / `git reset` / `git stash` / `git clean -f` /
`git revert` / `git switch` / `git rebase` / `git cherry-pick` / `git pull` / `git merge` /
`git push --force` / `git commit --amend`——即使仓库某天变成 git 仓库也不行（§19.6 N1）。

### 19.3 六批的验收脚本

> 全部为 **ASCII PowerShell**（H5）。每段都可直接粘贴。
> 每段做三件事：**编译（H3）→ 跑套件并核对具体用例数 → 说明红证怎么跑**。
> 红证需要**临时改源码**，所以脚本只给「配方」，不自动执行变异——
> 自动改源码的脚本太容易在失败时留下脏状态。

#### 通用前置（每段的第一行都重复一次，防止忘记）

```powershell
$ErrorActionPreference='Stop'; $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
```

#### 19.3.1 批 0：跨平台拆分（S21）

```powershell
$ErrorActionPreference='Stop'; $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
cmd /c F:\rtsc\.tmp\build_tls.bat
if ($LASTEXITCODE -ne 0) { throw "BATCH0 WIN BUILD FAILED" }
$o = (& F:\rtsc\build\verify\rtsc_tls_tests.exe | Out-String)
if ($o -notmatch '^26 tests, 139 checks, 0 failing tests, 0 failed checks') {
    throw "BATCH0 TLS SUITE MISMATCH:`n$o"
}
wsl -e bash -lc 'cd /mnt/f/rtsc && rm -rf .tmp/bl-green && cmake -S . -B .tmp/bl-green -G Ninja -DCMAKE_BUILD_TYPE=Debug >/dev/null 2>&1 && cmake --build .tmp/bl-green >/dev/null 2>&1; exit $?'
if ($LASTEXITCODE -ne 0) { throw "BATCH0 LINUX BUILD FAILED" }
Write-Output "BATCH0 PASS"
```

**红证配方**：把 `CMakeLists.txt` 的 `rtsc_tls` 源文件从 `src/net/tls_factory.cpp` 改回
`src/net/tls_schannel.cpp`（即恢复单库），然后跑上面的 Linux 命令。
**预期**：`BATCH0 LINUX BUILD FAILED`，`s21-green-build.txt` 里出现
`tls_schannel.cpp:29:10: fatal error: windows.h: No such file or directory`。
**恢复**：改回 `src/net/tls_factory.cpp`，重跑。

#### 19.3.2 批 1：CredSSP 生产注入（S1 S5 S6 S11 S18）

```powershell
$ErrorActionPreference='Stop'; $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
cmd /c F:\rtsc\.tmp\build_tls.bat
if ($LASTEXITCODE -ne 0) { throw "BATCH1 BUILD FAILED" }
$suites = @{
  'rtsc_credssp_sm_tests' = 15
  'rtsc_ntlm_tests'       = 27
  'rtsc_credssp_tests'    = 23
}
foreach ($k in $suites.Keys) {
    $o = (& "F:\rtsc\build\verify\$k.exe" | Out-String)
    if ($o -notmatch '0 failing tests, 0 failed checks') { throw "$k FAILED:`n$o" }
    if ($o -notmatch "(\d+) tests") { throw "$k NO SUMMARY`n$o" }
    $n = [int]$Matches[1]
    if ($n -lt $suites[$k]) { throw "$k ONLY $n TESTS, EXPECT >= $($suites[$k])" }
    Write-Output "$k = $n tests (expected >= $($suites[$k]))"
}
Write-Output "BATCH1 PASS"
```

> 用 `-lt`（不少于）而不是 `-eq`，因为本批**新增了用例**（S1/S5/S6/S11/S18 各至少 1 条）。
> 基线 `[实测]`：`rtsc_credssp_sm_tests 15 tests / 92 checks`、`rtsc_ntlm_tests 27 / 136`、
> `rtsc_credssp_tests 23 / 69`。

**红证配方（5 条，逐条跑，每条都要先红后绿）**：

| 缺陷 | 变异（改回修复前） | 预期失败的用例 | 恢复 |
|---|---|---|---|
| **S1** | `credssp.cpp:52` 改回 `nonce_.assign(kNonceSize, 0);` | `two_constructions_have_different_nonces` | 恢复为随机填充 |
| **S5** | 删掉 `credssp.cpp:127-129` 的版本下界校验 | `version_below_min_is_rejected_with_valid_challenge` | 恢复校验 |
| **S6** | 删掉 `version_ = std::clamp(...)` | `server_version_is_echoed_back` | 恢复回写 |
| **S11** | 删掉 `credssp.cpp:423-443` 的 seq 校验与 MAC 比对 | `tampered_signature_checksum_is_rejected` | 恢复校验 |
| **S18** | 删掉 `Start`/`BuildStep3` 的空公钥检查 | `start_without_public_key_fails` | 恢复检查 |
| **N-B1** | `credssp.cpp:191` 改回 `exported_session_key_.assign(nonce_.begin() + 8, nonce_.begin() + 24);` | `client_nonce_does_not_disclose_session_key` | 恢复 `RandomBytes` |

**批 1 新增枚举值 `credssp::Status::kInternal`**（详见 `docs/spec/batch1-execution-brief.md` §2.0）：

N-B1 的 CSPRNG 失败分支不能复用 `kUnsupported` 或 `kMalformed`：

- `kMalformed` + `native_code == 0` 会被本文件 `:603` 的映射判成 `kProtocolViolation`
  —— **把本地 CSPRNG 故障误报成「服务器违反协议」**，用户会去查服务器。
- `kUnsupported` 无法与「服务器版本太低」区分。

因此批 1 在 `include/rtsc/credssp/ts_request.h:21-26` 追加 `kInternal`，
并在 `:605` 增加映射行 `status == kInternal -> kInternal`。
`kInternal` 与 `tls::Status::kInternal`（`:597`）语义对齐。
**批 3 实现映射时必须照 `:605` 那行走**，否则 `kInternal` 会落到 `:603` 兜底被误分类。

#### 19.3.3 批 2：TLS 后端（S7 S8 S9 S10 S19 S22 S23 S24）

> **【A20-3 / A20-4 订正 · 批 1 收尾时实测】** 本节原稿有 **7 处不可执行或方向错误**，已全部修正。
> 订正依据：`tests/test_tls.cpp` 实测 26 个 `RTSC_TEST`、
> `evidence/s10/probe_s10.out.txt` 的 M1 实测、`evidence/tls/s24b-red-correction.md`、
> `evidence/u4/probe_u4e.out.txt` 的 T1/T2 实测。
> **执行 AI 必须先读完本节全部 7 条订正，再动手。**
>
> **开工前必做（审计甲 A20-4 建议）**：对**每一条**缺陷先跑一次「现状观测」，
> 把实测值写进用例注释，再写断言。**不要照着一个未验证的预期值写断言**——
> 批 1 收尾时主代理与审计甲各因「先下结论后取证」返工一次。

```powershell
$ErrorActionPreference='Stop'; $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
cmd /c F:\rtsc\.tmp\build_tls.bat
if ($LASTEXITCODE -ne 0) { throw "BATCH2 BUILD FAILED" }
$o = (& F:\rtsc\build\verify\rtsc_tls_tests.exe | Out-String)
if ($o -notmatch '0 failing tests, 0 failed checks') { throw "BATCH2 TLS FAILED:`n$o" }
if ($o -notmatch '(\d+) tests') { throw "BATCH2 NO SUMMARY" }
$n = [int]$Matches[1]
if ($n -lt 34) { throw "BATCH2 ONLY $n TESTS, EXPECT >= 34 (26 baseline + 8 new)" }
$c = if ($o -match '(\d+) checks') { [int]$Matches[1] } else { 0 }
if ($c -lt 150) { throw "BATCH2 ONLY $c CHECKS, EXPECT >= 150 (139 baseline + ~11)" }
Write-Output "BATCH2 PASS: $n tests, $c checks"

# The count alone cannot prove every required case exists (delete one, add a
# filler, and 34 still passes). This gate checks the 8 names individually AND
# the S23 contract (tls.h kPeerAlert comment must not promise an alert
# description, and must state that no backend produces it today).
python F:\rtsc\evidence\exec\batch2_gate.py
if ($LASTEXITCODE -ne 0) { throw "BATCH2 GATE FAILED" }
```

> **门槛订正**：原写 `>= 32 tests`（26+6）。实际需新增 **8 条**（见订正 2），故 `>= 34`。
> `checks` 原写 `>= 139`（26 条时的基线）。7 条新用例预计增加 ~11 个 CHECK，故 `>= 150`；
> **执行 AI 实测后若实际值不同，以实测为准并在报告中说明**，但不得低于 150。

**TDD 顺序（必须照此执行，不可跳过）**：

```
1. 写 8 条新用例（逐条对应 S24-a/b/c、S22、S9、S19、S23、S10）
   → 观察 8 条红（缺陷态必须红；若某条写完就绿，说明它没测到缺陷，停下来报告）
2. 修 8 处代码（S24-a/S24-b/S24-c + S22×2 + S9 + S19 + S10）+ 1 处注释（S23 的 `tls.h:42`）
3. 跑：8 条绿，既有 26 条不回归
4. 8 条变异逐条红（S24-c 用规则级断言）
```

**红证配方（8 条）**：

> **行号警告（A20-1，批 0 之后实测）**：本节原稿给的是批 0 **之前**的行号，
> 批 0 在 `tls_schannel.cpp` 头部插入 2 行（`#include "tls_schannel_internal.h"` 及其空行），
> 使 `:232` 之后的**所有行号 +2**。按旧行号操作会改错行——实测旧 `:429` 现在指向
> `FreeContextBuffer(out_buf.pvBuffer);`，照抄会删掉内存释放。
> **因此下表一律用「锚点文本 + `Select-String` 定位」，不再给行号。**
> 定位命令模板：
> ```powershell
> $f = 'F:\rtsc\src\net\tls_schannel.cpp'
> Select-String -Path $f -Pattern '<锚点正则>' | Select-Object LineNumber, Line
> ```
> 改前必须确认命中**恰好 1 行**；命中 0 行或 >1 行都要停下来报告。

| 缺陷 | 变异（按锚点文本定位） | 预期失败 | 恢复 |
|---|---|---|---|
| **S24-a** | 把 `SecBuffer token\{sizeof\(type\), SECBUFFER_TOKEN, &type\}` 改回 `SecBuffer token{0, SECBUFFER_TOKEN, nullptr}` | **`shutdown_emits_close_notify_alert`**（`first[0] == 0x15`，Alert record type） | 恢复 `sizeof(type)` + `&type` |
| **S24-c** | 把 `MapShutdownStatus` 的 `SEC_E_UNSUPPORTED_FUNCTION` 分支改回返回 `kOk` | **`shutdown_maps_failure_status_to_error`**（规则级断言，见订正 3） | 恢复映射 |
| **S24-b** | 锚点 `if \(st == SEC_E_OK \|\| st == SEC_I_CONTINUE_NEEDED\)` 里删掉 `\|\|` 分支 | `shutdown_reports_continue_needed_as_failure`（新增） | 恢复 `\|\|` |
| **S22** | **两处，方向相反**：① `if \(!have_ctx_\)` 块内 `return MakeError\(Status::kOk, 0, ""\);` 改回 `kOk`；② `return MakeError\(Status::kOk, st, "shutdown best effort"\);` 不置 `closed_` | `shutdown_before_handshake_is_rejected`（新增） | ① 改 `Fail(Status::kProtocolError)`；② 置 `closed_ = true` |
| **S9** | 取 `Receive` 签名（锚点 `Error Receive\(const uint8_t\* ciphertext`）之后、`size_t progressed = 0;` **之前**的第一处 `if \(closed_\)` 守卫，改回无条件拒绝。**该守卫文本在文件中命中 3 次**：`Handshake`（:106）、`Send`（:209）、`Receive`（:232）各一处 | `shutdown_then_receive_still_drains`（新增） | 改为 `closed_ && rx_buffer_.empty()` |
| **S19** | 锚点 `mask \|= SP_PROT_TLS1_3_CLIENT` 所在条件块，只请求 1.3 时不置 1.2 | `tls13_only_config_does_not_fail_acquire`（新增，**必须 `CHECK(started)`**） | 只请求 1.3 时同时置 1.2 |
| **S23**（契约缺陷） | **改写 `tls.h:42` 的注释**：把「`native_code = alert description`」改成「SChannel 无法填充 alert description」（见订正 5）。**产品代码行为本来就对**（`c:301-305` 已映射 `SEC_I_CONTEXT_EXPIRED` → `kClosed`），所以这是**纯注释缺陷**，不改一行代码 | `peer_alert_native_code_is_not_an_alert_description`（断言 `native_code == 0x00090317` 且 `native_code != 0x15`，即「不是 record type，也不是 alert description」） | 恢复原注释 |
| **S10** | 锚点 `consumed = in_size;` 且不吸收尾部（删掉 D1 的预切片 + `hs_buffer_` 吸收） | `coalesced_finished_and_app_data_are_both_delivered`（新增） | 恢复 D1 |

#### 7 条订正（A20-3 + A20-4）

**订正 1：S24-a 的原预期用例抓不到它。**
原稿写预期失败 = `shutdown_is_idempotent`，理由是「`first[0] == 21`，实际得到 22」。
**但 `shutdown_is_idempotent`（`tests/test_tls.cpp:853-861`）的断言只有**：
```cpp
CHECK(lb.client().Shutdown(first).ok());
CHECK(!first.empty());      // close_notify must be emitted
CHECK(lb.client().Shutdown(second).ok());
CHECK(second.empty());
```
全文件 grep `first[0]` / `== 21` / `0x15` → **零命中**。
S24-a 变异后 `first` 仍非空（只是内容变了），`CHECK(!first.empty())` **照样通过 → STILL GREEN**。
**修法**：新增 `shutdown_emits_close_notify_alert`，断言 `CHECK_EQ(Opaque(first[0]), Opaque(0x15));`
（`Opaque()` 在 `tests/test_tls.cpp:237`，专为躲开 C4127 而设）。
`shutdown_is_idempotent` 保持原样——它测「重复调用无副作用」，与「发的是 alert 还是重协商」正交。

**订正 2：8 条里 6 条的预期失败用例尚不存在。**
实测 `tests/test_tls.cpp` 共 26 个 `RTSC_TEST`：
```
shutdown_is_idempotent                            EXISTS
send_splits_oversized_payload_instead_of_failing  EXISTS
shutdown_reports_continue_needed_as_failure       MISSING  (S24-b)
shutdown_before_handshake_is_rejected             MISSING  (S22)
shutdown_then_receive_still_drains                MISSING  (S9)
tls13_only_config_does_not_fail_acquire           MISSING  (S19)
peer_alert_native_code_is_not_an_alert_description         MISSING  (S23)
coalesced_finished_and_app_data_are_both_delivered MISSING (S10)
```
逐条对应 8 条缺陷，**共需新增 8 条**（S24-a/b/c、S22、S9、S19、S23、S10 各一条）：
```
shutdown_emits_close_notify_alert                  (S24-a)
shutdown_reports_continue_needed_as_failure        (S24-b)
shutdown_maps_failure_status_to_error              (S24-c)
shutdown_before_handshake_is_rejected              (S22)
shutdown_then_receive_still_drains                 (S9)
tls13_only_config_does_not_fail_acquire            (S19)
peer_alert_native_code_is_not_an_alert_description          (S23)
coalesced_finished_and_app_data_are_both_delivered (S10)
```
**实测确认**：这 8 个名字在 `tests/test_tls.cpp` 中全部 MISSING（现有 26 条）。
门槛因此为 26 + 8 = **34**。

> **门槛不能只靠总数**：S10 排在最后，若前面 7 条做完就收工，`>= 34` 会拦住，
> 但若有人删掉一条又加一条凑数，总数仍够。**必须逐条 grep 8 个用例名**
> （见 `evidence/exec/batch2_gate.py`）。

**订正 3：S24-c 在修复前物理上不可构造。**
原稿写「变异 = 去掉返回值检查」。但 `:413` 现在是
```cpp
ApplyControlToken(&ctx_, &desc);   // 裸调用，无赋值、无 if
```
**根本没有检查可去。** 这是 TDD 顺序问题：批 2 的修复是「**加上**检查」，不是「删掉」。
**修法**：把 `status -> Status` 的映射抽成 `MapShutdownStatus(SECURITY_STATUS)`，
修复后断言 `MapShutdownStatus(SEC_E_UNSUPPORTED_FUNCTION) != kOk`。
红证 = 把该分支改回返回 `kOk`。
可行性已由 `evidence/tls/s24b-red-correction.md` 证明（同法用于 S24-b）：
```
MapShutdownStatus(SEC_I_CONTINUE_NEEDED)      = 0    ← 当前缺陷
MapShutdownStatus(SEC_E_UNSUPPORTED_FUNCTION) = 5
ASSERTION C: MapShutdownStatus(CONTINUE_NEEDED) != kOk ?  FAIL  <-- RED today
```


**实现细节（必须照此写，否则编译失败）**：
```cpp
// include/rtsc/net/tls.h  —— 零平台依赖，只用 int32_t
// 不能出现 SECURITY_STATUS（Windows 类型）；tls.h:5-8 明写该约束。
Status MapShutdownStatusForTest(int32_t native_status);

// src/net/tls_schannel.cpp  —— Windows only
namespace rtsc::tls {
namespace {
Status MapShutdownStatus(SECURITY_STATUS st) { /* 规则本体 */ }
}  // namespace
// 包装函数必须在匿名 namespace 结束之后，否则看不见上面的规则函数。
Status MapShutdownStatusForTest(int32_t s) {
    return MapShutdownStatus(static_cast<SECURITY_STATUS>(s));
}
}  // namespace rtsc::tls
```

- **不要加 `__declspec(dllexport)`**：`rtsc_tls` 是 `STATIC` 库（`CMakeLists.txt:71`），
  现有 `CreateTlsTransport` / `EnumerateTlsBackends` 都没有导出宏。
- **Linux 不受影响**：`rtsc_tls_schannel`（`CMakeLists.txt:65-69`）与
  `rtsc_tls_tests`（`:127-131`）都在 `if(WIN32)` 内，Linux 既不编译也不链接。
  声明一个只有 Windows 有定义的函数是安全的（与 `CreateSchannelTransport` 同模式）。

**订正 4：S22 是两处，方向相反。**
原稿只写 `:435`。实测：
```
:407-410  if (!have_ctx_) { shutdown_sent_ = true; return MakeError(Status::kOk, 0, ""); }
          ← 未握手时不拒绝，返回 kOk（缺陷 A）
:435      return MakeError(Status::kOk, st, "shutdown best effort");
          ← ISC 失败时返回 kOk 但不置 closed_（缺陷 B）
```
只修 `:435`，`shutdown_before_handshake_is_rejected` **仍然红**。

**订正 5：S23 是「契约缺陷」——产品行为本来就对，错的是 `tls.h:42` 对 `kPeerAlert` 的承诺。**

原稿写「把 `:305` 的 `st` 实参改成读 `plain[0]` 当 alert description」。
**这个方向彻底错了**，它会让代码把 `0x15`（record type）当成 alert description，
**制造一个新缺陷**。

### 产品的实际行为（正确）

`src/net/tls_schannel.cpp:301-305`：
```cpp
if (st == SEC_I_CONTEXT_EXPIRED) {
    // Normal end of stream. Keep the plaintext decoded so far: the
    // peer may have sent application data right before close_notify.
    closed_ = true;
    return MakeError(Status::kClosed, st, "peer closed");
}
```
`native_code` 就是 `st`，即 **`0x00090317`（SEC_I_CONTEXT_EXPIRED）**。
**这是正确行为，不需要改。**

### 错在哪：`tls.h:42` 的注释

```cpp
kPeerAlert,       // TLS fatal alert received; native_code = alert description
```
**这句承诺是假的。** `native_code` 是 `SEC_I_CONTEXT_EXPIRED`，不是 alert description。

### 为什么读不到 alert description（实测）

`evidence/u4/probe_u4e.out.txt` 的 T2/T3（**加密的** close_notify）：
```
T1 RECORD: type=21 (Alert) len=26 total=31
T2 client DecryptMessage -> 0x00090317 (SEC_I_CONTEXT_EXPIRED)
  plaintext=31 [15 03 03 00 1A 00 00 00 ...]
T3 ALERT BYTES: level=21 description=3
```
**T3 的 `level=21, description=3` 是探针的误标**——`0x15, 0x03` 是
**record 头的前两字节**（type=21, version 高字节=3），**不是 alert 语义**。
审计文档 §U4 表格对此已有正确解读：
> `plaintext[0]=0x15` 是 record type，**不是** level

`evidence/u4/probe_u4.out.txt`（**明文裸 alert**，TLS1.2 要求加密故被拒）：
```
Q1 Receive(alert 7B) -> status=5 (kProtocolError) native_code=0x80090318
  description byte 0 reachable via native_code: NO
```
**两个场景都读不到 description**：加密时拿到的是整条 record 的包装，明文时直接被拒。

### 正确修复（U-N10 原文）

改写 `include/rtsc/net/tls.h:42`（**审计甲 A20-4 订正：U-N10 原文仍不准确**）：
```cpp
kPeerAlert,  // Reserved for backends that can report a peer fatal alert with its
             // description (OpenSSL SSL_AD_*). NO backend produces this today:
             // SChannel reports close_notify as kClosed and encrypted alerts as
             // kProtocolError, and cannot expose level/description at all
             // (measured: evidence/u4/probe_u4e.out.txt). Never interpret
             // native_code as an alert description byte.
```

> **为什么 U-N10 原文不够**：它说「Backend surfaced a fatal alert」，
> 但实测 `kPeerAlert` **在全仓从未被任何代码产生**——
> `tls.h:42` 定义、`tls.h:68` 的 `terminal()` 判断、`test_tls.cpp:249` 的枚举列举，
> **`src/` 零命中**。SChannel 收到 close_notify → `kClosed`，收到加密 alert → `kProtocolError`。
> 且 `doc:3127` 已定「S7 保持 `kPeerAlert` 不产出」。
> 所以 U-N10 版会让读者以为它某种情况下会产生——**换了个说法的同类错误**。

### 红证怎么设计（S23 是唯一一条「契约缺陷」）

**代码行为不变 → 纯行为型用例对它没有判别力**（注释改回去它照样绿）。
审计甲 A20-4 裁定：**A（文档断言）+ C（行为型），否决 B（`native_code != 0x15` 观测型）**，
理由：B 自己承认「注释改回去它不会红」，那就不成立为红证。

#### A. 文档断言（锁「注释不许撒谎」）

并进 `evidence/exec/batch2_gate.py` 的**独立函数** `check_tls_header_contract()`
（与 `check_tests_present()` 分开，否则失败信息无法区分「缺用例」与「注释回退」）。

**必须是「正向三要素 + 负向排除」双断言**——纯负向很脆：
有人写 `native_code != alert description` 或 `native_code is not the alert description`，
字面检查就失效。

```python
must_contain = ['kPeerAlert', 'cannot', 'no backend produces']   # 大小写归一后比较
must_not_contain = ['native_code = alert description']
```

**实测三版注释的判别力**：

| 注释版本 | 负向（不含旧文案） | 正向三要素 | 判定 |
|---|---|---|---|
| 旧文案 | 命中 → 红 | 缺 `cannot` → 红 | ✅ 红 |
| U-N10 原文 | 不含 → 绿 | 含 `cannot`，**缺 `no backend produces`** → 红 | ✅ 红（正确捕获） |
| 甲 A20-4 版 | 不含 → 绿 | 三要素齐 → 绿 | ✅ 绿 |

#### C. 行为型用例（锁「代码不许按错误注释去改」）

`peer_alert_native_code_is_not_an_alert_description`：
断言 `Receive(加密 close_notify)` 的 `native_code == 0x00090317` 且 `!= 0x15`。
它锁的是 `doc:3126` 那个错误变异（改读 `plain[0]` → 得 `0x15`）——
**这正是原稿犯的错，值得钉死。**

#### 构造对端 alert：`RawServer::CloseNotify()`

**该加，不算改产品代码**：`RawServer`（`t:50`）是测试夹具，已有 `Step`/`Encrypt`/`Decrypt`
三个 SSPI 封装，加 `CloseNotify` 是同一层次第四个。
且它是 `SECPKG_CRED_INBOUND`（`t:68`），与 `probe_u4e` T1 场景完全一致。

实现要点（约 15 行）：
```cpp
DWORD type = SCHANNEL_SHUTDOWN;
SecBuffer tok{sizeof(type), SECBUFFER_TOKEN, &type};
SecBufferDesc td{SECBUFFER_VERSION, 1, &tok};
if (ApplyControlToken(&ctx_, &td) != SEC_E_OK) return SEC_E_UNSUPPORTED_FUNCTION;
// 然后 ISC(空输入) 产出 31 字节 alert record (type=21)
```

**订正 6：S19 的原预期用例会假绿。**
`version_bounds_are_enforced_after_handshake`（`tests/test_tls.cpp:868-889`）已经覆盖「只要 TLS 1.3」：
```cpp
const bool started = lb.Start(cfg, why);
if (!started) {
    CHECK(!why.empty());
    return;        // ← S19 未修时 started==false，从这里 return，测试绿
}
```
**S19 未修时 `AcquireCredentialsHandle` 返回 `SEC_E_ALGORITHM_MISMATCH`
→ `started == false` → `CHECK(!why.empty())` 通过 → return → 绿。**
新用例 `tls13_only_config_does_not_fail_acquire` **必须 `CHECK(started);`**，
不接受「失败但有原因」。
**`t:868` 那条不要改**——它测「不许静默降级」，语义不同，两条不能互相替代。

#### 范围钉死（防越界）

> **批 2 只做 `SEC_I_CONTEXT_EXPIRED` 映射，不碰 `kPeerAlert`。**
> S7（`kPeerAlert` 从不产生）**不在批 2 的 8 条里**。
> 修 S23 时若顺手加了 alert 解析，会**部分实现 S7 而不自知**，且没有用例覆盖。
> 执行 AI 若发现必须动 `kPeerAlert` 才能让某条用例绿，**停下来报告**，不要自行扩大范围。

#### S10 的可构造性（原「未验证」已证伪）

原稿表里 S10 只是「恢复 D1」，未说清可构造性。**实测证据已存在**：
`evidence/s10/probe_s10.out.txt` 的 M1 段：
```
M1 raw ISC(combined) -> 0x00000000
M1 in_bufs[0].cbBuffer: before=98 after=98 (in_size=98)
M1 VERDICT: SSPI reports EXTRA=NO (cbBuffer unchanged)
```
SChannel 吃下 98 字节合段时 `cbBuffer` **不变**（98→98），说明它把应用数据一并吞了、不报 EXTRA。
`evidence/s10/probe_s10e.out.txt` 的 G1/G2 证明修复有效：
```
Handshake(98) -> status=0 consumed=98 complete=1 buffered=47
recovered 18 bytes: "S10-PAYLOAD-MARKER"
```
**注意**：`tls_schannel.cpp:166-169` 的注释
「SChannel's stream handshake does not report EXTRA, and leaving bytes unconsumed
would make the caller replay them forever」——**前半句是事实，后半句的结论是错的**。
不报 EXTRA 意味着**必须自己切片**，不是可以忽略。D1 修复要改写这段注释与
`include/rtsc/net/tls.h:129-132` 的契约公式。

> **S24-b 的红证是可构造的**（A20-2 订正，原稿「不可构造」是错的）。
> 正确方法：把 `status -> Status` 的映射抽成函数单独断言，或直接断言产品当前
> `status == kOk` 与 `out[0] == 22`（重协商记录）互相矛盾。
> 详见 `evidence/tls/s24b-red-correction.md` 与 `evidence/exec/b0-s24b-red-baseline.txt`。

#### 19.3.4 批 3：安全层（S2 S3 S4 S15 S16）

```powershell
$ErrorActionPreference='Stop'; $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
cmd /c F:\rtsc\.tmp\build_tls.bat
if ($LASTEXITCODE -ne 0) { throw "BATCH3 BUILD FAILED" }
$spec = @{ 'rtsc_security_tests' = 13; 'rtsc_framing_tests' = 11; 'rtsc_connect_machine_tests' = 26 }
foreach ($k in $spec.Keys) {
    $p = "F:\rtsc\build\verify\$k.exe"
    if (-not (Test-Path $p)) { throw "MISSING $k.exe (S15/S2/S3 not built?)" }
    $o = (& $p | Out-String)
    if ($o -notmatch '0 failing tests, 0 failed checks') { throw "$k FAILED:`n$o" }
    if ($o -notmatch '(\d+) tests') { throw "$k NO SUMMARY" }
    $n = [int]$Matches[1]
    if ($n -lt $spec[$k]) { throw "$k ONLY $n TESTS, EXPECT >= $($spec[$k])" }
    Write-Output "$k = $n tests (expected >= $($spec[$k]))"
}
Write-Output "BATCH3 PASS"
```

> `rtsc_security_tests` 是**新套件**（T1–T13，§17.3 的定义）。基线 `[实测]`：
> `rtsc_framing_tests 11 / 47`、`rtsc_connect_machine_tests 26 / 115`。

**红证配方（5 条）**：

| 缺陷 | 变异 | 预期失败 | 恢复 |
|---|---|---|---|
| **S2** | `kAwaitEuar` 阶段改为直接把 `plain_` 交给 `TpktStream` | `euar_denied_emits_no_pdus` | 恢复取 4 字节 |
| **S3** | `TpktStream::Next()` 的 payload **不**调 `WrapTpkt` | `first_pdu_carries_tpkt_header` | 恢复 `WrapTpkt` |
| **S4** | 每次 `Receive` 直接把 `plain_` 当一整条 TSRequest | `tsrequest_split_across_records` | 恢复 DER TLV 累积 |
| **S16** | 删掉 CredSSP 阶段的 `size <= max_plaintext` 断言 | `oversized_tsrequest_is_reported` | 恢复断言 |
| **N6/C6** | 删掉 `WrapTpkt` 返回空检查 | `wraptpkt_overflow_is_reported` | 恢复检查 |

#### 19.3.5 批 4：协议层小修（S12 S13 S14 S17 S20）

```powershell
$ErrorActionPreference='Stop'; $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
cmd /c F:\rtsc\.tmp\build_tls.bat
if ($LASTEXITCODE -ne 0) { throw "BATCH4 BUILD FAILED" }
$o = (& F:\rtsc\build\verify\rtsc_connect_machine_tests.exe | Out-String)
if ($o -notmatch '0 failing tests, 0 failed checks') { throw "BATCH4 CM FAILED:`n$o" }
if ($o -notmatch '(\d+) tests') { throw "BATCH4 NO SUMMARY" }
$n = [int]$Matches[1]
if ($n -lt 26) { throw "BATCH4 ONLY $n TESTS, EXPECT >= 26" }
Write-Output "BATCH4 PASS: $n tests"
```

**红证配方（3 条）**：

| 缺陷 | 变异 | 预期失败 | 恢复 |
|---|---|---|---|
| **S12** | `connect_machine.cpp:353-357` 恢复 no-op | `wrong_phase_external_security_complete_fails` | 恢复 `Fail(...)` |
| **S20** | `:168` 恢复无条件回填 password | `client_info_password_empty_under_enhanced_security` | 恢复分支 |
| **S14** | 删掉 `error_code` 赋值 | `state_carries_native_error_code` | 恢复赋值 |

#### 19.3.6 批 5：真机联调（无新缺陷）

```powershell
$ErrorActionPreference='Stop'; $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
cmd /c F:\rtsc\.tmp\build_tls.bat
if ($LASTEXITCODE -ne 0) { throw "BATCH5 BUILD FAILED" }
# Requires real credentials; see 19.5 E2E. Placeholders below are intentional.
$host_ = $env:RTSC_HOST; $user = $env:RTSC_USER; $pass = $env:RTSC_PASS
if (-not $host_ -or -not $user -or -not $pass) {
    Write-Output "BATCH5 SKIPPED: set RTSC_HOST / RTSC_USER / RTSC_PASS (cannot be verified in this round)"
    exit 0
}
& F:\rtsc\build\verify\rtsc_probe.exe --full $host_ 3389 --user $user --password $pass
if ($LASTEXITCODE -ne 0) { throw "BATCH5 PROBE FAILED" }
Write-Output "BATCH5 PASS"
```

> **本批的红证不存在**（集成验证）。它的判据是「失败点必须落在 §15.3.2 的三处未知之一」，
> 否则说明还有未发现的缺陷。**本轮无法验证**（无凭据），见 19.5 的 E2E 段。

#### 19.3.7 全批回归（每批结束都跑一次）

```powershell
$ErrorActionPreference='Stop'; $env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
$fail = @()
Get-ChildItem F:\rtsc\build\verify\*.exe | Where-Object { $_.Name -like 'rtsc_*_tests.exe' } | ForEach-Object {
    $o = (& $_.FullName | Out-String)
    if ($o -notmatch '0 failing tests, 0 failed checks') { $fail += $_.Name }
}
if ($fail.Count -gt 0) { throw ("REGRESSION: " + ($fail -join ', ')) }
Write-Output "ALL SUITES PASS"
```

> 这条是**影响范围测试的兜底**，不是替代：某批改了 `credssp.cpp` 就必须跑
> `rtsc_credssp*` 三个套件；改了 `tls_schannel.cpp` 就必须跑 `rtsc_tls_tests`。
> 全批回归只用来确认「没把别处弄坏」。

### 19.4 三处「最容易做错」的陷阱

> 我从 24 个 S + 36 个 M 里挑**三个**。挑选标准是两条同时成立：
> **（a）看起来完全正确；（b）现有测试抓不到。**
> 只满足 (a) 的叫「易错」，满足 (a)+(b) 的才叫「危险」。

#### 陷阱 1：S1 的 nonce 用 `rand()` / `std::random_device` 的一次调用 / 固定种子

**错法**（三种都很常见）：

```cpp
// 错法 A：C 库 rand
nonce_.resize(32);
for (auto& b : nonce_) b = static_cast<uint8_t>(std::rand());

// 错法 B：time 播种
std::srand(static_cast<unsigned>(std::time(nullptr)));
for (auto& b : nonce_) b = static_cast<uint8_t>(std::rand() & 0xFF);

// 错法 C：只播一次种子然后复用同一个引擎实例（跨连接可预测）
static std::mt19937_64 rng{std::random_device{}()};
for (auto& b : nonce_) b = static_cast<uint8_t>(rng());
```

**为什么诱人**：
- `two_constructions_have_different_nonces` **会通过**——`rand()` 两次结果确实不同；
- `std::random_device` 看起来就是「随机源」，名字很像 CSPRNG；
- 代码短，不用引入平台 API。

**为什么错**：
- `rand()` 的实现质量由 CRT 决定，MSVC 的 `rand()` 是 LCG，**32 字节里有大量可推导线**；
- `std::random_device` 在 MSVC 上底层走 `rand_s`（系统 CSPRNG），但在 MinGW / 某些
  libstdc++ 配置上会退化为确定性引擎——**标准不保证它是 CSPRNG**；
- 这个 nonce 直接决定 `client_challenge`（`credssp.cpp:176`）与 `exported_session_key`
  （`:191`），可预测 = 可离线破解 CredSSP 绑定。

**正确做法**：

```cpp
// src/crypto/random.cpp (新文件，放 rtsc_crypto，不能放 rtsc_security)
// NOTE: link bcrypt from CMake, never with #pragma comment(lib, ...):
// #pragma comment is MSVC-only and GCC rejects it under -Wall -Werror.
//   if(WIN32) target_link_libraries(rtsc_crypto PUBLIC bcrypt) endif()
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
bool RandomBytes(uint8_t* out, size_t n) {
    return BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}
#else
#include <sys/random.h>
bool RandomBytes(uint8_t* out, size_t n) {
    size_t off = 0;
    while (off < n) {
        const ssize_t r = getrandom(out + off, n - off, 0);
        if (r < 0) return false;
        off += static_cast<size_t>(r);
    }
    return true;
}
#endif
```

调用点必须**检查返回值**：`if (!RandomBytes(nonce_.data(), nonce_.size())) return Fail(kInternal, ...);`
（`GetLastError`/`errno` 进 `native_code`）。

**哪个测试能抓到**：**只有一半**。
- 抓得到：`two_constructions_have_different_nonces`（常量 → 红）；
- **抓不到**：弱 RNG（rand/time 播种）→ 这条测试**仍然绿**。

**所以必须加第二道门禁（代码评审项，不是测试项）**：
`Select-String -LiteralPath F:\rtsc\src\credssp\credssp.cpp -Pattern '\brand\(|\bsrand\(|std::random_device|mt19937'`
**必须无输出**。把这条写进 `verify` 脚本，才算真正守住 S1。

> 这也是 §18.3 那条「用例数 ≠ 覆盖」规则的第二个实例：
> **S24 是「注释声明 A、断言只验 B」；S1 是「测试只验充分性、不验质量」。**

#### 陷阱 2：S24 只改 `:411`（token）不改 `:431`（成功判定）

**错法**：

```cpp
// 只把 token 改对，:431 原样留着
DWORD type = SCHANNEL_SHUTDOWN;
SecBuffer token{sizeof(type), SECBUFFER_TOKEN, &type};
SecBufferDesc desc{SECBUFFER_VERSION, 1, &token};
ApplyControlToken(&ctx_, &desc);          // 仍然不检查返回值
...
if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {   // <-- 仍然是错的
    closed_ = true;
    return MakeError(Status::kOk, st, "");
}
```

**为什么诱人**：
- 改完 token 之后，`shutdown_is_idempotent` **立刻变绿**（`first[0]==21`、31 字节）；
- `SEC_I_CONTINUE_NEEDED` 在**握手期**确实是正常中间态（`:180` 就把它当 `kNeedMoreInput`），
  所以「它也算成功」看起来有道理；
- 编译器不会警告（`st` 是 `long`，`||` 两端类型相同）。

**为什么错**：
- 在 **Shutdown 期**，`SEC_I_CONTINUE_NEEDED` 的含义是「我开始了重协商，还要继续」——
  与「已优雅关闭」语义相反；
- 若某个后端/将来的 TLS 1.3 路径真的返回它，你会得到 `status=kOk` + `closed()==true`
  + 一堆本该丢弃的重协商字节；
- 更糟的是 `closed_=true` 会让 `Receive` 在 `:232` 短路，`rx_buffer_` 残余永久丢失（S9 叠加）。

**正确做法**：

```cpp
ApplyControlToken 的返回值必须检查：
const SECURITY_STATUS ctl = ApplyControlToken(&ctx_, &desc);
if (ctl != SEC_E_OK) {
    shutdown_sent_ = true;
    closed_ = true;                       // 上下文已不可用
    return MakeError(Status::kInternal, ctl, "ApplyControlToken(SCHANNEL_SHUTDOWN) failed");
}
...
if (st == SEC_E_OK) {
    closed_ = true;
    return MakeError(Status::kOk, st, "");
}
// SEC_I_CONTINUE_NEEDED 落到这里：不是成功
shutdown_sent_ = true;
closed_ = true;
return MakeError(Status::kInternal, st, "shutdown did not complete");
```

**哪个测试能抓到**：**没有任何测试能抓到 `:431`**（§18.0.4 理由 3：修好 token 后不可达）。
**这是纯评审项。** 执行完本批必须贴出 `:431` 附近的 diff，由审计确认。

#### 陷阱 3：S10/D1 把 `consumed` 理解成「已处理的字节数」

**错法**：

```cpp
// 错法：consumed 只报「喂给 ISC 的那些字节」
size_t used = 0;
for (each complete record in hs_buffer_) {
    inner ISC(record, used, out);
    consumed += used;          // <-- 错：这只覆盖握手记录
}
// 尾部（应用数据）吸收进 rx_buffer_ 了，但 consumed 没算它
```

或者反过来：

```cpp
// 错法：consumed 报「缓冲区里总共有多少」
consumed = hs_buffer_.size();   // <-- 错：调用方的输入可能比这更多
```

**为什么诱人**：
- `consumed` 的字面意思是「消费了多少」，直觉上应该等于「真正处理的字节数」；
- 把尾部吸收进 `rx_buffer_` 后，那部分确实「没被 ISC 处理」，所以不报它「看起来诚实」；
- `probe_n1` 的 D1Wrapper 用 `consumed = in_size` 看起来像偷懒，容易被「改进」。

**为什么错**：
契约是 **「后端已接管（took ownership）的字节数」**，不是「已解密/已处理的字节数」。
尾部被复制进 `rx_buffer_` 之后，所有权已经转移给后端，调用方**绝不能再送一遍**。
若 `consumed` 少报，调用方会重放尾部 → 同一条密文被解密两次 → `SEC_E_DECRYPT_FAILURE`
或明文重复。反之若多报（超过 `in_size`），调用方会读越界。

**正确做法**（两种合法情形，二选一，必须写清是哪一种）：

```cpp
// 情形 1：后端把所有输入都复制进了自己的缓冲（D1 的吸收设计）
consumed = in_size;   // 尾部进了 rx_buffer_，所有权已转移

// 情形 2：后端只能处理前 k 个字节，其余必须由调用方保留
//          （本设计不用这种；若将来要用，必须保证 k <= in_size 且 k 精确）
consumed = k;
```

**哪个测试能抓到**：
- `probe_n1` 的 36 个断言**不检查 `consumed`**（`[实测]`：`checks=36 failures=0`，但那是行为断言）；
- `tests/test_tls.cpp` 里**没有任何 `Handshake` 的 `consumed` 断言**
  （只有 `:745`/`:792` 的 `Send` 有）；
- **所以必须新增断言**，否则这条会和 S24 一样活下来：

```cpp
// tests/test_tls.cpp 新增
RTSC_TEST(handshake_reports_absorbed_bytes_as_consumed) {
    // ... 构造「最后一个握手 token + 一条应用数据记录」合并的输入
    size_t consumed = 0;
    Bytes out;
    const Error e = client.Handshake(merged.data(), merged.size(), consumed, out);
    CHECK(e.status == Status::kOk || e.status == Status::kNeedMoreInput);
    CHECK_EQ(consumed, merged.size());   // 全部被接管，调用方不得重放
}
```

#### 19.4.1 次级陷阱（有测试兜底，但仍容易写错）

| # | 陷阱 | 错法 | 抓到它的测试 |
|---|---|---|---|
| 1 | **S3/N6：`WrapTpkt` 返回空不检查** | `out.pdus.push_back(WrapTpkt(p, n));` 直接塞空 vector | `wraptpkt_overflow_is_reported`（若写） |
| 2 | **S3：手写 TPKT 头而不调 `WrapTpkt`** | `Bytes f{0x03,0x00,hi,lo}; f.insert(...)` —— 长度上限用 65531 而不是 65528 | 同上 |
| 3 | **S9：只改 `:232` 忘了 `Shutdown` 的 `closed_`** | 只把 `if (closed_)` 改成 `if (closed_ && rx_buffer_.empty())`，但 `:432` 仍无条件 `closed_=true` | `shutdown_then_receive_still_drains` |
| 4 | **S2：EUAR 用 `TpktStream` 去「猜」4 字节** | 把 `plain_` 整个喂 `TpktStream`，指望它跳过 4 字节 | `euar_denied_emits_no_pdus` |
| 5 | **S20：NLA 下清空 password 但连非 NLA 一起清** | `pdu.info.password.clear()` 无条件执行 | `client_info_password_present_for_standard_rdp` |

**为什么这五个不算「三大陷阱」**：它们都有（或按 §19.3 的配方会写）能直接抓到的断言，
属于「易错但易抓」；三大陷阱是「易错且抓不到」。**两者的处理方式不同**：
前者靠测试，后者靠评审 + 门禁脚本。

### 19.5 完成判据（Definition of Done）

> **三级必须分别签字，不许用「测试全绿」代替协议级和端到端级。**
> 每条都给了「怎么证明」，不给「应该可以」。

#### 19.5.1 代码级（8 条，全部可在本机验证）

| # | 判据 | 怎么证明 | 当前状态 |
|---|---|---|---|
| **D1** | `cmd /c F:\rtsc\.tmp\build_tls.bat` 退出码 0 | `if ($LASTEXITCODE -ne 0) { throw }`；`/W4 /WX` 已全局（`CMakeLists.txt:13`），有警告即编译失败 | `[实测]` 现在为 0（改前） |
| **D2** | 6 个既有套件全绿且用例数不少于基线 | 基线 `[实测]`：tls **26/139**、credssp_sm **15/92**、ntlm **27/136**、credssp **23/69**、framing **11/47**、connect_machine **26/115** | `[实测]` 全绿 |
| **D3** | 24 个 S 全部有对应测试或显式豁免 | 逐条对照 §18.1.1；S24-b 与 S23 的部分断言属「评审项」，必须列在豁免表里 | 未开始 |
| **D4** | 每一批的红证都已实际执行并留档 | 红证输出存 `F:\rtsc\evidence\redproof\<批次>-<S编号>.txt`；内容须含用例名 + 断言 + 实际读数 | 未开始 |
| **D5** | Linux 全量构建成功 | `wsl -e bash -lc 'cd /mnt/f/rtsc && cmake -S . -B .tmp/bl-green -G Ninja && cmake --build .tmp/bl-green'` → 退出码 0 | `[实测]` 改前失败（S21 红基线），改后需重取 |
| **D6** | 无重复符号 | §19.2.2 S0.7 的三条 `dumpbin` 判据 | 未开始 |
| **D7** | 新增/修改的代码无 `rand()`/`srand()`/`random_device`/`mt19937` | `Select-String` 门禁（陷阱 1） | 未开始 |
| **D8** | 未改任何测试的**既有断言**（只允许新增或替换被证明无效的） | 对 `tests/` 做行数 + 断言文本清单比对；被替换的每条必须写明「原断言为何无效」 | 未开始 |

#### 19.5.2 协议级（5 条，可在无服务器条件下验证）

| # | 判据 | 怎么证明 | 当前状态 |
|---|---|---|---|
| **P1** | `SecurityLayer` 在脚本传输下产出正确的**记录类型序列** | 用 `ScriptedTlsTransport` 回放固定字节；断言 `to_wire[0]` 序列（如 ClientHello=22、CCS=20、Finished=22） | 未开始 |
| **P2** | CredSSP 五步的每条 TSRequest 都是**恰好一个 DER SEQUENCE**，且 `version` 在 `[2,6]` | 对 `to_wire` 解密后取 DER：`der[0]==0x30`，长度字段与实际长度一致；断言 `version` 回显 | 未开始 |
| **P3** | EUAR 恰取 **4 字节**，且 `0x00`/`0x05`/其他 三种分支行为正确 | T1/T4/T5（§17.3）；断言 `pdus` 是否为空、`euar_result` 是否有值 | 未开始 |
| **P4** | 每条 `pdus` 都带 **4 字节 TPKT 头**，且 `frame[0]==0x03 && frame[1]==0x00`，长度字段 == `frame.size()` | 对每个 `Output::pdus` 断言前 4 字节；`WrapTpkt` 空返回必须变成 `kProtocolViolation`（N6） | 未开始 |
| **P5** | `Handshake` 的 `consumed` 恒等于 `in_size` 或精确的接管字节数，**绝不重放** | 新增断言（陷阱 3）；另用 `probe_n1` 的 D1Wrapper 对拍 | 未开始 |

> **协议级的证据形式**：`F:\rtsc\evidence\protocol\<用例名>.txt`，内容为**十六进制 dump + 逐字段注解**。
> 不接受「测试通过」作为协议级证据——测试通过只说明断言成立，不说明字节序列长什么样。

#### 19.5.3 端到端级（3 条，**明确标注本轮无法验证**）

| # | 判据 | 需要什么 | 本轮能否验证 |
|---|---|---|---|
| **E1** | 连真实 RDP 服务器（`192.168.1.7:3389`）能完成 TLS + CredSSP + EUAR，并进入 MCS | **有效用户名 + 口令 + 可能需要的域**；`rtsc_probe --full` | **不能**。无凭据。**禁止**用假凭据「试一下」——那会产生误导性的 `kCredentialRejected` |
| **E2** | 服务器对 `Client Info` 的 `password` 字段在 NLA 下为空的处理正确（不报错） | 同 E1 | **不能** |
| **E3** | `Shutdown()` 发出真 close_notify 后，服务器在 `McsDisconnectProviderUltimatum` 之前/之后的行为符合预期（U-N7） | 同 E1 + 抓包（Wireshark 或 `ssldump`） | **不能** |

> **这三条必须原样保留在 DoD 里，标注 `BLOCKED: needs credentials`。**
> **禁止**为了让 DoD「全绿」而删除或降级它们——它们是「安全层是否真的能用」的唯一判据。
> 本轮交付的是「代码级 + 协议级可验证」，端到端是**下一轮**的事。

#### 19.5.4 元判据（2 条）

| # | 判据 |
|---|---|
| **M1** | `docs/spec/security-integration.audit-a.md` 的 §18.1.1 表格里，24 个 S 的「批次」列与实际改动**一一对应**（没有哪个 S 被悄悄漏掉或合并） |
| **M2** | 每个红证的输出文件都存在且非空；`Get-ChildItem F:\rtsc\evidence\redproof\*.txt` 的数量 == 实际执行的红证数 |

### 19.6 给执行 AI 的「禁止事项」

| # | 禁止 | 为什么 | 正确做法 |
|---|---|---|---|
| **N1** | **任何回退类 git 操作**：`checkout` / `restore` / `reset`（含 `--hard`）/ `stash` / `clean -f` / `rm` / `revert` / `switch` / `rebase` / `cherry-pick` / `pull` / `merge` / `push --force` / `commit --amend` | 工作树是多代理共享的未提交态，回退即毁灭他人工作；且本仓库**不是 git 仓库** | 用 `F:\rtsc\.opencode\backups\` 备份 + `Copy-Item` 恢复（§19.2.3） |
| **N2** | **改测试让它通过**：删断言、放宽断言、加 `if (false)`、把 `CHECK` 改成注释、把期望值改成实际值 | 这正是 S24 存活至今的原因（`CHECK(!first.empty())` 替代了 `close_notify` 检查） | 只允许**新增**断言，或**替换被证明无效的**断言（须写明原断言为何无效，D8） |
| **N3** | **用 `#ifdef _WIN32` 包住 `tls_schannel.cpp` 整个文件** | 掏空的 TU 仍产出空 obj，静态库照常链接，把编译期错误变成运行期 `nullptr` 迷雾 | 用 CMake `if(WIN32)` 排除文件（§19.2.1） |
| **N4** | **在 `rtsc_proto` 里 `#include "rtsc/net/tls.h"`** 或链接 `rtsc_tls` | `rtsc_proto` 必须保持「只依赖 `rtsc_crypto`」（`CMakeLists.txt:36`），否则 Linux/Android 的协议层被 TLS 后端绑架，且形成 `proto → tls → proto` 环 | 安全层放在 `rtsc_security`，它依赖 proto，反向不成立 |
| **N5** | **跳过红证直接写实现** | 无法证明测试能抓到问题 | §19.1.3 的 8 步 |
| **N6** | **用 `rand()` / `srand()` / `std::random_device` / `mt19937` 生成 nonce** | 见陷阱 1；`two_constructions_have_different_nonces` **抓不到** | `BCryptGenRandom` / `getrandom`，并检查返回值 |
| **N7** | **把 `Shutdown` 的 `SEC_I_CONTINUE_NEEDED` 当成功** | 见陷阱 2 | 只判 `SEC_E_OK` |
| **N8** | **把 `consumed` 当「已处理字节数」** | 见陷阱 3 | `consumed = in_size`（接管）或精确值 |
| **N9** | **为了过编译加 `#pragma warning(disable:...)` / `#pragma GCC diagnostic ignored`** | `CMakeLists.txt:13` 的 `/W4 /WX` 是质量门禁 | 修代码 |
| **N10** | **新建 build 目录 / 换生成器 / 改 `build_tls.bat`** | 现有 `build/verify` 是 Ninja + MSVC 14.44 `[实测]`；混用会让增量构建失效 | 只用 `cmd /c F:\rtsc\.tmp\build_tls.bat` |
| **N11** | **把临时文件写到 C 盘**（含 `$env:TEMP` 未设置时的默认路径） | H1；可能无权限且污染系统 | 每次先设 `$env:TEMP='F:\rtsc\.tmp'` |
| **N12** | **用 PowerShell 的 `Set-Content`/`Out-File` 写含中文的文件** | PS 5.1 会写 BOM 或按 ANSI 转码，破坏 UTF-8 | `write` 工具或 Python `io.open(..., encoding='utf-8', newline='')` |
| **N13** | **删除或降级 §19.5.3 的三条 E2E 判据** | 它们是「安全层真能用」的唯一判据 | 保留 `BLOCKED: needs credentials` |
| **N14** | **在 `rtsc_security` 以外的层做 EUAR 解析** | EUAR 是「外部安全层」的最后一步，下推到 proto 会让 proto 依赖 TLS 阶段语义 | 安全层内部 `kAwaitEuar` 阶段（S2） |
| **N15** | **声称「应该可以」** | 本项目已因「应该可以」付出 S24/S19 两次代价 | 要么给出命令输出，要么标 `[未验证]` + 需要什么条件 |

### 19.7 附：本章引用的可执行证据索引

| 证据 | 路径 | 内容 |
|---|---|---|
| S21 红基线（g++） | `F:\rtsc\evidence\u4\s21-red.out.txt` | `tls_schannel.cpp:29 fatal error: windows.h`，`BUILD_EXIT=1` `[实测]` |
| S21 红基线（configure） | `F:\rtsc\evidence\u4\s21-configure.out.txt` | configure 成功（证明失败发生在编译而非配置） `[实测]` |
| S24/S25 2×2 矩阵 | `F:\rtsc\evidence\u4\probe_s25.out.txt` | A–F 六格，含产品侧 `out=201 type=22` 与 `31 type=21` `[实测]` |
| N1/D1 行为不变性 | `F:\rtsc\evidence\u4\probe_n1.out.txt` | `checks=36 failures=0`，baseline 与 D1 完全一致 `[实测]` |
| S15 alert 不可读 | `F:\rtsc\evidence\u4\probe_u4e.out.txt` | `SEC_I_CONTEXT_EXPIRED` + `plaintext=31` 以 `15 03 03 00 1A` 开头 `[实测]` |
| 测试基线（6 套件） | 本文 §19.5.1 D2 | 26/15/27/23/11/26，checks 139/92/136/69/47/115 `[实测]` |

---

## 20. 批 0 审计验证

> **本章是独立验证，不采信执行 AI 的自述。** 每一项都给了命令与输出；
> 凡我亲手跑的，标注 `[我实测]`；凡只读到证据文件的，标注 `[读证据]`。
> **未改任何工程代码**；所有影子实验在 `F:\rtsc\.tmp\audit-b0\` 内完成。
>
> 验证对象：执行 AI `ses_e99c24117ffeWAQpIkIbFYCNoc` 的批 0 交付。
> 证据目录 `F:\rtsc\evidence\exec\`（25 个 .txt）；我的新增证据在 `F:\rtsc\evidence\u4\v*.txt`。

### 20.0 结论

**批 0 审计通过（S21 已修到根因，Windows 行为确实不变），但发现 3 个缺陷，其中 1 个是 P1 且出在我自己的交接包里。**

| 编号 | 级别 | 一句话 | 归属 |
|---|---|---|---|
| **A20-1** | **P1** | 交接包 §19 里 S24-b/S9/S10 的红证行号是**批 0 之前的**；批 0 使 `tls_schannel.cpp` 整体 **+2 行**，照抄会改错位置 | **我的规格错误**（非执行 AI 的错） |
| **A20-2** | P2 | `b0-s24b-red-baseline.txt` 的 PART 2 声称「逐字复制 `:431-435`」，但探针的 else 分支返回 `kProtocolError`，产品 `:435` 返回 `kOk` —— **不是逐字**，且该差异被实测证明会改变结论 | 执行 AI 的证据表述 |
| **A20-3** | P2 | `rtsc_crashtest.exe` 的**运行**（`verify.ps1 -CrashCheck`）在批 0 里从未执行；25 个证据文件中无一条 `[crash] dir=` 或 `reason=` 记录 | 覆盖缺口 |

**通过理由（一句话）**：S21 的红→绿是我**自己重建影子树**跑出来的（`windows.h` 错误在还原后必现、在当前树必不现），Windows 15 套件的 tests/checks 在 S0.9 前后**逐项相同**，且 S0.9 的 `[[maybe_unused]]` 经**删除实验**证明只是死代码标记而非掩盖——这三个核心命题都成立。

---

### 20.1 V1：Windows 行为是否真的逐字节不变

#### 20.1.1 15 套件数字逐项比对 `[我实测]`

```
$a = b0-win-regression.txt  (S0.9 之前)
$b = b0-win-after-s09.txt   (S0.9 之后)
Compare-Object $a $b  ->  IDENTICAL (all 15 suites, tests+checks)
pre count=15  post count=15
```

**结论：数字层面完全不变**（15 个套件，tests 与 checks 逐项相同，`rtsc_tls_tests` 仍为 26/139）。

#### 20.1.2 但「数字相同」不等于「行为相同」——我做了删除实验 `[我实测]`

这是 V1 的核心。执行 AI 只证明了「数字不变」，**没有证明 `[[maybe_unused]]` 不改变行为**。
我的做法：在影子树里把三个 helper **整段删掉**，看能否编译、用例数是否变化。

```
影子树：F:\rtsc\.tmp\audit-b0\v3tree（复制当前树，仅删 3 个 helper）
删除：test_credssp.cpp:50 (Str, 1 行)
      test_licensing.cpp:37-41 (AnsiBytes, 5 行)
      test_licensing.cpp:60-68 (ToHex, 9 行)
```

结果（`F:\rtsc\evidence\u4\v3-delete-build.txt`）：
```
BUILD=0                     <- 删掉后仍编译通过（-Wall -Wextra -Werror）
rtsc_credssp_tests : 23 tests, 69 checks, 0 failing
rtsc_licensing_tests: 47 tests, 175 checks, 0 failing
```
**用例数与断言数完全不变（23/69、47/175）。**

**判断依据（三条，缺一不可）**：
1. **删掉后仍能编译** → 三个 helper 在整个 TU 里**零引用**，不是「本该用但忘了用」；
2. **删掉后用例数与 checks 数不变** → 没有任何测试依赖它们；
3. **若它们是「本该用却写成别的形式」，删掉后必然编译失败**（因为那些地方会缺符号）——实测 `BUILD=0` 排除了这种可能。

**进一步查证「本该用」的可能性** `[我实测]`：
- `test_credssp.cpp` 里所有字节构造都用 `Bytes(n, value)` 或 `FromHex(...)`（`:184`、`:193`、`:231`、`:244`、`:107`、`:125`），
  **没有一处需要把 `const char*` 转成 `Bytes`**（`Str` 的唯一用途）；
- `test_licensing.cpp` 的 ANSI 字符串一律写成 `std::string("microsoft.com\0", 14)`（`:214`、`:550`）或 `w.u8(0)`（`:535`），
  而 `AnsiBytes` 的作用正是「`std::string` + 尾部 `\0`」——**功能重复但调用点已用更直白的写法**；
- `ToHex` 无任何对应需求：所有字节断言都用 `CHECK_BYTES(...)`（`:112`、`:139`、`:155`、`:386`、`:421`、`:570`、`:614`）
  或 `CHECK(w.data() == bytes)`（`:219`、`:556`），**不需要十六进制字符串**。

**V1 结论**：`[[maybe_unused]]` 在此**不是掩盖问题**，是「死代码标记」。
但**它不是最优解**——正确做法应是**删除**（见 A20-4）。

#### 20.1.3 `tools/rtsc_crashtest/main.cpp` 的行为**从未被验证** `[我实测]`

执行 AI 的 25 个证据文件里，`crashtest` 只出现在**编译**上下文（`FAILED: ...main.cpp.o`）。
我检索全部证据：

```
Select-String -Pattern 'reason=std::terminate|\[crash\] dir=' F:\rtsc\evidence\exec\*.txt
-> (no output)  从未运行过
```

**这是覆盖缺口（A20-3）**。不过**我替它跑了一次** `[我实测]`：

```
$env:RTSC_CRASH_DIR='F:\rtsc\.tmp\audit-b0\crash-terminate'
rtsc_crashtest.exe terminate
-> [crash] dir=... mode=terminate
-> 产物: rtsc_crashtest-20261023-094120-36612.dmp (119808 B)
         rtsc_crashtest-20261023-094120-36612.txt (452 B)
```

报告内容：
```
app=rtsc_crashtest
reason=std::terminate
frames=9
  #0 ... terminate+0x2E
  #1 ... `anonymous namespace'::CrashTerminate+0xC
  #2 ... main+0xCE
```

**结论**：`#include <exception>` 之后 `std::terminate` 正常触发、崩溃守卫捕获到 `reason=std::terminate`、
dump 与文本报告都生成。**行为正确**——但这是**我补跑的**，不是批 0 的交付证据。

---

### 20.2 V2：S21 是否修到根因

#### 20.2.1 三库结构能否防止再犯 `[读代码 + 我实测]`

当前结构（`CMakeLists.txt:48-68`）：
```
rtsc_tls_api       INTERFACE  (:53-54)  仅 include/
rtsc_tls_schannel  STATIC     (:56-60)  if(WIN32)，仅 tls_schannel.cpp
rtsc_tls           STATIC     (:62-68)  tls_factory.cpp，任何平台
```

**能否防止再犯**：**部分能，但不完全**。分三种情形：

| 未来的错误 | 当前结构能否挡住 | 依据 |
|---|---|---|
| 有人往 `tls_factory.cpp` 加 `#include <windows.h>` | **能**：Linux 上立刻 `fatal error`，因为该文件在**所有平台**都编译 | `CMakeLists.txt:62` 无条件 `add_library` |
| 有人往 `tls_schannel.cpp` 加新 Windows API | **能**：该文件只在 `if(WIN32)` 内，非 Windows 根本不编译，不会「假装通过」 | `:56-60` |
| 有人**新建**一个 `.cpp` 并在里面 include Windows 头，然后加到 `rtsc_tls` 的源列表 | **不能**：`rtsc_tls` 是无条件 target，新文件会被所有平台编译——**但会立刻在 Linux 报错，所以仍会被发现** | `:62` |

**唯一的真空白**：若有人把 Windows 代码写进**头文件**（如 `tls_schannel_internal.h`），
而该头只在 `#if defined(_WIN32)` 内被 include，则 Linux 不会编译它 → **不会被发现**。
当前 `tls_schannel_internal.h` 是平台中立的（我核对过：无任何 `#include <windows...>`），
但**没有机制阻止**将来往里加。

#### 20.2.2 `tls_factory.cpp` 的平台中立性 `[我实测]`

```
Select-String -Pattern 'windows\.h|schannel|sspi|wincrypt|bcrypt' tls_factory.cpp
-> 仅命中字符串与符号名（"schannel"、CreateSchannelTransport、"no TLS backend for this platform..."）
   无任何 #include <windows...>
```

非 Windows 路径返回**明确错误**（`:28-35`）：
```cpp
why = "no TLS backend for this platform (SChannel is Windows only)";
return nullptr;
```
并已由执行 AI 的 `b0-linux-consumer.txt` 实测（`default_why=no TLS backend for this platform...`）`[读证据]`，
我在 V7 的绿灯树里也复现了（`ctest 15/15 passed`）`[我实测]`。

#### 20.2.3 `_WIN32` 是 3 处而非 2 处：是否必要、能否更少、有无警告

**交接包说 2 处，实际 3 处**（`:12` include、`:24` 工厂分支、`:40` 枚举分支）。执行 AI 已在
`b0-change-manifest.txt:92-101` 的 DISC-2 里如实报告，**没有静默修改规格**，这点做对了。

**3 处是否必要**：**`:12` 可以合并，`:24`/`:40` 必须分开**。

| 处 | 能否减少 | 理由 |
|---|---|---|
| `:12` `#include "tls_schannel_internal.h"` | **可以** | 把声明放进 `#if defined(_WIN32)` 的**同一段**，或干脆让 `tls_factory.cpp` 无条件 include 该头（该头本身平台中立，只是声明了一个函数）→ 可降到 2 处 |
| `:24` 工厂分支 | **不能** | Windows 要调 `CreateSchannelTransport`，非 Windows 没有该符号 |
| `:40` 枚举分支 | **不能** | Windows 返回 `{{"schannel",true,""}}`，非 Windows 返回 `{}` |

**当前写法在 Linux 上有无「未使用变量」警告** `[我实测]`：

```
wsl: cd /mnt/f/rtsc/.tmp/audit-b0/green && cmake --build . -> BUILD=0, FAILED=0
```
编译选项是 `-Wall -Wextra -Werror -Wpedantic`（`CMakeLists.txt:15`）。
`BUILD=0` 说明**零警告**。原因是 `:29` 的 `(void)config;` 显式消除了 `config` 未使用的警告，
而 `want_default` 在**两个分支里都被使用**，`backend` 在 `#else` 分支里被使用（`:26`、`:34`）。

**MSVC 侧** `[我实测]`：`b0-win-build.txt` 显示 `[1/6]...tls_factory.cpp.obj` 编译通过，
`/W4 /WX` 下零警告。

**V2 结论**：S21 **修到了根因**。三库拆分正确；`_WIN32` 用 3 处，其中 1 处可优化但非缺陷。

---

### 20.3 V3：S0.9 的 4 行修复是否最小且无副作用

#### 20.3.1 `[[maybe_unused]]` 是「消除警告」还是「掩盖问题」 `[我实测]`

**判据**：如果这些 helper 是「测试本该用但忘了用」，那么**删掉它们会导致编译失败**（因为调用点会缺符号）。
**我做了删除实验**（见 §20.1.2）：删掉后 `BUILD=0`，用例数不变。
→ **它们是纯死代码，不是「本该用」**。因此 `[[maybe_unused]]` **不是掩盖**。

#### 20.3.2 但正确修法是「删掉」，不是 `[[maybe_unused]]`（**A20-4，P2**）

| 方案 | 优点 | 缺点 |
|---|---|---|
| `[[maybe_unused]]`（执行 AI 采用） | 1 行、零风险 | **保留了 15 行死代码**；下一个人会以为「这函数某处会用」；`-Wunused-function` 从此对这些函数失效，**将来真的误删调用点时不再有警告** |
| **删除**（我建议） | 消除死代码；恢复 `-Wunused-function` 的保护力 | 需要删 15 行（1+5+9） |

**关键理由**：`[[maybe_unused]]` 的语义是「**这个实体可能不被使用，这是合法的**」。
但这里的事实是「**这个实体确实不被使用，且不需要**」——语义不匹配。
它把一条**真实的死代码信号**永久静音了。

**我的删除实验已证明删除是安全的**（`BUILD=0`，用例数不变），所以这不是「理论更好」，是**已验证可行**。

> **注意**：这不构成「批 0 不通过」。批 0 的目标是「Linux 能构建」，`[[maybe_unused]]` 达成了目标且无副作用。
> 但它是**技术债**，应在批 1 之前清掉（否则批 1 新增的 CredSSP 测试会继承这份模糊）。

#### 20.3.3 `#include <exception>` 是纯增量 `[我实测]`

`Compare-Object` 显示该文件只有 1 行新增（`=> #include <exception>`），无删除、无修改。
**无争议。**

#### 20.3.4 一处需要记录的事实：MSVC 看不到这个缺陷 `[我实测]`

我用 MSVC 单独编译了一个只 `#include <cstdio>/<cstring>/<string>` + `std::terminate()` 的文件：
```
cl /W4 /WX /EHsc /std:c++20 /utf-8 t.cpp  ->  EXIT=0
```
**MSVC 的 `<string>` 传递包含了 `<exception>`**，所以 Windows 侧从来不会报这个错。
这正是该缺陷能潜伏到批 0 才暴露的原因，也说明**「Windows 全绿」不能证明 Linux 能构建**——
这条应写进 §19 的门禁规则。

---

### 20.4 V4：S24-b 红基线是否可信

#### 20.4.1 是否明确标注「这是批 2 的输入」 `[读证据]`

`b0-s24b-red-baseline.txt:10-12`：
```
THIS IS NOT A BATCH-0 LEFTOVER.
S24-b is a batch-2 (TLS backend) defect. Batch 0 neither fixes nor worsens it.
```
**明确标注，通过。**

#### 20.4.2 是否把预期值伪装成观测值 `[读证据 + 我实测]`

文件里 PART 1 的读数标注为「Verbatim output (run 2026-10-23 after batch 0, against post-batch-0 libs)」，
且给出 `status=0 native=0x00090312 out=201 closed=true`。**我独立复现了这个读数**：

```
$ F:\rtsc\.tmp\audit-b0\v5\probe_only431.exe
  status=0 native=0x00090312 out=201 closed=false     <- 注意 closed 不同！
```

**这里发现两处问题（A20-2）**：

**(a) `closed` 不一致**：证据说 `closed=true`，我实测 `closed=false`。
原因可解释：证据跑的是**未改动的产品库**（`:432` 置 `closed_=true`），
我跑的是**只改了 `:431` 的影子库**（`st != SEC_E_OK` → 不置 `closed_`，走 `:435` 返回 `kOk`）。
两者都对，但**证据文件没有标注它的库是哪一版**，读者会误以为可复现。

**(b) PART 2 不是「逐字复制」**（**这是实质问题**）：

证据文件 `:113` 声称：
```
// The decision under test, copied verbatim from tls_schannel.cpp:431-435.
```
但探针 `probe_s24b.cpp:115-120` 是：
```cpp
Status MapShutdownStatus(SECURITY_STATUS st) {
    if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
        return Status::kOk;   // :117
    }
    return Status::kProtocolError;   // :119  <-- 产品这里是 kOk
}
```
而产品 `src/net/tls_schannel.cpp:435`（锚点 `shutdown best effort`） 是：
```cpp
return MakeError(Status::kOk, st, "shutdown best effort");
```

**不是逐字**：产品的 else 分支返回 `kOk`，探针返回 `kProtocolError`。

**这个差异重要吗？** 我用**真产品库 + 只改 `:431`** 实测（`v5-only431-real.txt`）：
```
status=0 native=0x00090312 out=201 closed=false
ASSERTION A: FAIL
ASSERTION C: MapShutdownStatus(CONTINUE_NEEDED) = 0  -> FAIL
```
**结论：不影响 S24-b 的裁决**（因为 `CONTINUE_NEEDED` 走的是 `:431` 的 if 分支，不是 else 分支；
`else` 分支的差异只影响「其他错误码是否被吞」，那是 S22/S24-c 的范围）。

**但表述必须订正**（P2）：`copied verbatim` 是**假的**。正确表述是
「copied from `:431-435`, **with the else-branch deliberately changed from `kOk` to `kProtocolError`** to make the mapping testable in isolation」。

#### 20.4.3 探针是否链接产品库 `[我实测]`

`build.bat` 实测内容：
```
cl ... probe_s24b.cpp /link /LIBPATH:F:\rtsc\build\verify
   rtsc_tls.lib rtsc_tls_schannel.lib rtsc_crypto.lib secur32.lib crypt32.lib advapi32.lib
```
**链接了产品库，且 PART 1 确实调 `rtsc::tls::CreateTlsTransport`（`probe_s24b.cpp:150`）→ 不是手写副本。通过。**

**V4 结论**：红基线**可信**（PART 1 是产品实测），但**表述有 P2 缺陷**（"verbatim" 不成立 + 库版本未标注）。

---

### 20.5 V5：执行 AI 是否越界

#### 20.5.1 N1–N15 逐条 `[我实测]`

| 禁止项 | 检查结果 |
|---|---|
| **N1** 回退类 git 操作 | 本仓库非 git；执行 AI 用 `.opencode/backups` + `Copy-Item`。**未违反** |
| **N2** 改测试让它通过 | `tests/test_tls.cpp` SHA256 `815BCFBB...E8A0B` **与备份完全相同**（我实测哈希）。三个 helper 的改动是**删除式实验的反向**（加属性而非删断言），且我证明它们零引用。**未违反 N2** |
| **N3** `#ifdef _WIN32` 包整个 `tls_schannel.cpp` | 文件内无此 pattern；用 CMake `if(WIN32)` 排除。**未违反** |
| **N4** `rtsc_proto` 引用 `tls.h` | `CMakeLists.txt:36` 仍只有 `rtsc_crypto`；`src/proto/**` 无 `tls.h`。**未违反** |
| **N5** 跳过红证 | S21 有红（`b0-red.txt`）有绿（`b0-green-full.txt`）。**未违反** |
| **N6** 用 `rand()` 等 | 未涉及（批 1 的事）。**未违反** |
| **N7** `SEC_I_CONTINUE_NEEDED` 当成功 | **`:431` 仍是 `\|\| st == SEC_I_CONTINUE_NEEDED`**（我实测）——这是**正确地没动**（属批 2）。**未违反** |
| **N8** `consumed` 语义 | `:169` 仍 `consumed = in_size`（批 2）。**未违反** |
| **N9** `#pragma warning(disable)` | 全仓无新增。**未违反** |
| **N10** 新建 build 目录/换生成器 | 用了 `.tmp/bl-red`/`.tmp/bl-green`/`.tmp/bl-pre`（临时，非 `build/verify`）。`build/verify` 仍是 Ninja + MSVC。**未违反** |
| **N11** 写 C 盘 | 全部产物在 `F:\rtsc`。**未违反** |
| **N12** PS 写中文 | 证据文件是 UTF-8；控制台里出现的 U+FFFD 是 PowerShell 5.1 的显示问题，不是文件损坏（我用 Python 按 UTF-8 读取校验过）。**未违反** |
| **N13** 删除/降级 E2E 判据 | 未改 §19.5.3。**未违反** |
| **N14** 安全层外做 EUAR 解析 | 未新建安全层。**未违反** |
| **N15** 说「应该可以」 | 执行 AI 的 DISC-1~5 **如实报告了规格错误**（含我的 `^` 锚点 bug），**没有粉饰**。**未违反** |

#### 20.5.2 特别检查：是否动了不该动的文件 `[我实测]`

| 文件 | 状态 |
|---|---|
| `tests/test_tls.cpp` | SHA256 与备份**完全相同** |
| `include/rtsc/net/tls.h` | mtime `2026-10-23 04:21`（批 0 之前）；内容未变 |
| `src/proto/connect_machine.cpp` | mtime `2026-10-22 17:53`（早于批 0）；`:168` 仍 `pdu.info.password = credentials_.password;` |
| `src/proto/framing.cpp` | mtime `2026-10-22 18:28`；`:100` 仍 `if (size > TpktHeader::kMaxPayload) return {};` |
| `src/credssp/credssp.cpp` | `:46` 仍 `nonce_.assign(kNonceSize, 0);`（S1 未修，正确） |
| `include/rtsc/credssp/credssp.h` | `:61` 仍只有 `SetServerPublicKeyForTest`（S18 未修，正确） |

**批 1–5 的 S 条目全部未触碰。通过。**

#### 20.5.3 越界的唯一一处：S0.9 是否算越界 `[读证据]`

S0.9 修了 3 个**与 S21 无关的既有缺陷**。严格说，这**超出了「批 0 = S21」的定义**。
但：
- 执行 AI **先停下来报告**（`b0-preexisting-defects.txt` 明确写 `status: NOT FIXED (out of batch-0 scope; §19.2.2 says stop and report)`）；
- **主代理裁决后才修**（`b0-change-manifest.txt:121`「approved by parent after B1 adjudication」）；
- 我 §19.2.2 的 S0.8 表格里**恰好写了**「其他文件报 `-Werror` → 停下来上报，不要顺手改；这是新发现的缺陷」。

**执行 AI 完全遵守了这条**。**不算越界**，反而是一次正确的流程执行。

---

### 20.6 V6：证据文件自洽性（抽查 8 个）`[读证据 + 我实测]`

| 文件 | 与报告一致？ | 矛盾？ |
|---|---|---|
| `b0-red.txt` | 是（`windows.h` + `BUILD_EXIT=1`） | 无 |
| `b0-green-full.txt` | 是（`CONFIGURE_EXIT=0` / `GREEN_BUILD_EXIT=0` / `FAILED_COUNT=0` / `WINDOWS_H_COUNT=0` / `ctest 15/15` / `OVERALL=PASS`） | 无 |
| `b0-win-after-s09.txt` | 是（15 套件 + `26 tests, 139 checks` + `ctest 16/16`） | 无 |
| `b0-win-regression.txt` | 与 `b0-win-after-s09.txt` **逐行相同** | 无（这是 S0.9 前后对比的基线） |
| `b0-green.txt` | **确实加了 `SUPERSEDED BY S0.9` 段**（`:153`），并明确写「本文件写成时 Linux 全量构建是 RED」 | 无（诚实） |
| `b0-preexisting-defects.txt` | 3 个缺陷的完整报错 + mtime 证据 | 无 |
| `b0-linux-consumer.txt` | `COMPILE_EXIT=0` / `LINK_EXIT=0` / `default_why=no TLS backend...` | 无 |
| `b0-acceptance-19.3.1.txt` | **记录了脚本失败**（`BATCH0 TLS SUITE MISMATCH`）但同一文件里 `26 tests, 139 checks, 0 failing` 正确 | **这不是矛盾，是我的脚本 bug**（见 A20-1） |

#### 20.6.1 `b0-green.txt` 的 SUPERSEDED 段落 `[读证据]`

`:142-178` 结构：
- `:142` `VERDICT (as of the S0.9 follow-up; see the SUPERSEDED note below)`
- `:146-150` 明确写「Linux full-tree build: **RED AT THE TIME THIS FILE WAS WRITTEN**」
- `:153` `SUPERSEDED BY S0.9 (parent adjudicated B1 = approve the fix)`
- `:178` `FINAL STATE OF BATCH 0: PASS.`

**这是诚实的证据管理**：保留了失败的历史记录，同时标明权威结论在哪。
**加分项，不是缺陷。**

#### 20.6.2 「证据说 PASS 但日志说 FAIL」的矛盾排查 `[我实测]`

`b0-acceptance-19.3.1.txt` 里同时出现：
```
BATCH0 TLS SUITE MISMATCH:      <- 脚本判定失败
26 tests, 139 checks, 0 failing tests, 0 failed checks   <- 实际输出正确
```
**这不是矛盾，是我的脚本有 bug**（A20-1 的一部分）：

```powershell
$o = (& rtsc_tls_tests.exe | Out-String)
$o -notmatch '^26 tests, 139 checks, ...'   # ^ 锚点
```
我实测：
```
match_with_anchor=False
match_no_anchor=True
first_20_chars=[ RUN  ] status_has_
```
**`^` 只能匹配字符串开头，而 `Out-String` 的结果以 `[ RUN ]` 开头，摘要行在第 60 行。**
→ 锚点永远不可能匹配。**这是我 §19.3.1 的规格 bug**，执行 AI 正确地把它识别为 DISC-3 并拒绝「改规格让它通过」。

---

### 20.7 V7：我的独立红证（影子树重建）

#### 20.7.1 方法

任务建议「把 `CMakeLists.txt` 还原成批 0 之前的版本」。我做了**更严格的两层**：

**第一层（只还原 CMake）** `F:\rtsc\.tmp\audit-b0\`：
复制当前 `include/src/tests/tools`，把 `CMakeLists.txt` 换成
`F:\rtsc\.opencode\backups\CMakeLists.txt.20261023-085223`，删除批 0 新增的两个文件。
```
结果：BUILD=1
  audit-b0/src/net/tls_schannel.cpp:29:10: fatal error: windows.h: No such file
  audit-b0/tests/test_tls.cpp:20:10: fatal error: windows.h: No such file
```
（`F:\rtsc\evidence\u4\v7-build.txt`；注意这个影子树里 `tls_schannel.cpp` 是**新版的**，
即「只回滚构建系统、不回滚源码」——仍然必现）

**第二层（源码也还原，最纯粹的前置状态）** `F:\rtsc\.tmp\audit-b0\pure\`：
额外把 `src/net/tls_schannel.cpp` 换成
`backups\src_net_tls_schannel.cpp.20261023-085223`（含旧的 `CreateTlsTransport` 工厂）。
```
BUILD=1  (target rtsc_tls)
  pure/src/net/tls_schannel.cpp:29:10: fatal error: windows.h: No such file or directory
```
（`F:\rtsc\evidence\u4\v7b-build.txt`）

**第三层（对照：当前树）** `F:\rtsc\.tmp\audit-b0\green\`：
当前 `CMakeLists.txt` + 当前源码，从零 configure。
```
CFG=0 / BUILD=0 / FAILED=0
ctest: 100% tests passed, 0 tests failed out of 15
产物: CMakeFiles/rtsc_tls.dir/src/net/tls_factory.cpp.o
      （rtsc_tls_schannel.dir 不存在 —— 该 target 在 Linux 上确实没被创建）
```

#### 20.7.2 结论

**三层的对照构成完整的红→绿证明**：

| 层 | CMakeLists | tls_schannel.cpp | 结果 |
|---|---|---|---|
| pure（批 0 之前） | 旧（单库） | 旧（含工厂） | **BUILD=1, windows.h 错误** |
| audit-b0（只回滚 CMake） | 旧（单库） | 新（工厂已拆） | **BUILD=1, windows.h 错误** |
| green（当前） | 新（三库） | 新 | **BUILD=0, ctest 15/15** |

**关键推论**：第二层证明**只回滚 `CMakeLists.txt` 就足以让缺陷重现**——
说明 S21 的根因**确实在构建系统**（无条件编译 Windows TU），不是「源码里有 Windows 代码」这个不可避免的事实。
批 0 的修复**确实修了一个真实存在的跨平台缺陷**，而不是「改了构建系统但本来就没问题」。

**并且**：`green` 树里 `CMakeFiles/` 只有 `rtsc_tls.dir`（`tls_factory.cpp.o`），
**没有 `rtsc_tls_schannel.dir`** —— 这是「Windows TU 在 Linux 上根本不参与编译」的**结构性证据**，
不是靠日志推断。

---

### 20.8 发现的缺陷清单

#### A20-1（**P1**）：交接包 §19 的红证行号在批 0 之后全部失效

**这是我最严重的发现，且出在我自己的规格里。**

批 0 在 `tls_schannel.cpp` 里新增了 2 行（`:41` 的 include + 2 行注释），
使**文件从 754 行变成 756 行，且所有 `:232` 之后的代码整体 +2**。

我实测的行号漂移：

| 锚点 | 批 0 前 | 批 0 后 | 我 §19 写的 |
|---|---|---|---|
| `Receive` 的 `if (closed_)` | `:230` | **`:232`** | `:230` ❌ |
| `Handshake` 的 `consumed = in_size` | `:167` | **`:169`** | `:167` ❌ |
| `SecBuffer token{0, ...}` | `:409` | **`:411`** | `:409` ❌ |
| `:429` 的 `if (st == SEC_E_OK \|\| ...)` | `:429` | **`:431`** | `:429` ❌ |

**后果**：执行 AI 若照抄 §19.3.3 的红证表去改「`:429`」，
**改到的是 `:429 = FreeContextBuffer(out_buf.pvBuffer);`**（我实测确认），
会把释放缓冲区的语句删掉 → 内存泄漏 + 红证完全无效。

**执行 AI 这次没有中招**，因为批 0 只需改 `CMakeLists.txt` 与工厂函数，没碰这些行。
**但批 2 一定会中招**。

**修法**：在 §19.3.3 与 §19.4 的所有 `tls_schannel.cpp:行号` 前加一句
**「行号为批 0 之后（+2 偏移）；改前先 `Select-String` 确认锚点」**，
并把 `:429` 全部改为 `:431`、`:409` 改 `:411`、`:230` 改 `:232`、`:167` 改 `:169`。
**更稳的做法**：交接包里的红证一律给**锚点文本**（如 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`），
让执行 AI 用 `Select-String` 定位，而不是给行号。

#### A20-2（P2）：`b0-s24b-red-baseline.txt` 的「copied verbatim」不成立

- `:113` 声称「copied verbatim from `:431-435`」；
- 探针 `:119` 返回 `kProtocolError`，产品 `:435` 返回 `kOk`；
- **实测证明不影响裁决**（`CONTINUE_NEEDED` 走 if 分支），但表述必须订正；
- 另外 PART 1 的 `closed=true` 是**未修产品**的读数，我的影子（只改 `:431`）给 `closed=false`——
  证据文件**未标注库版本**，读者无法复现。

**修法**：把 `copied verbatim` 改为
「copied from `:431-435` **with the else-branch changed from `kOk` to `kProtocolError`** to isolate the mapping」，
并注明「PART 1 读数来自 post-batch-0 未修产品库；PART 2 是等价映射，非产品代码」。

#### A20-3（P2）：`rtsc_crashtest` 的运行从未被验证

- 25 个证据文件中无 `[crash] dir=` / `reason=` 记录；
- `verify.ps1:57-90` 的 `-CrashCheck` 分支从未在批 0 里跑过；
- **我补跑了 `terminate` 模式**：正常触发、dump 119808 B、报告 `reason=std::terminate`、`frames=9`。
  **行为正确**，但这不改变「批 0 未验证它」这个事实。

**修法**：批 0 的 DoD 加一条「`pwsh verify.ps1 -CrashCheck` 三种模式全过」，
或在证据里明确写「crashtest 只验证编译，运行验证推迟到 X」。

#### A20-4（P2）：`[[maybe_unused]]` 优于「删除」，但删除已验证可行

见 §20.3.2。不是缺陷，是技术债。建议批 1 前清掉。

---

### 20.9 未验证项（诚实标注）

| # | 未验证 | 为什么 | 怎么消除 |
|---|---|---|---|
| **U20-1** | Linux 上 `-Wall -Wextra -Werror -Wpedantic` 之外的警告类别（如 `-Wconversion`、clang 的 `-Weverything`） | 项目只用上述四项 | 若要更严，单独加 target 试 |
| **U20-2** | Server 2019/2022 的 SChannel 行为（S24-b 的 `0x00090312` 是否一致） | 只有本机 Windows | 需另一台机器 |
| **U20-3** | `rtsc_crashtest` 的 `null` 与 `abort` 两种模式 | 我只跑了 `terminate` | `pwsh verify.ps1 -CrashCheck` |
| **U20-4** | Android/macOS 构建 | 无工具链 | 需 NDK / Xcode |
| **U20-5** | `tls_schannel_internal.h` 将来被加入 Windows 头时的防护 | 当前无机制 | 见 §20.2.1 的「唯一真空白」 |

### 20.10 对 §19 的三处自我订正

| §19 位置 | 原文 | 订正 |
|---|---|---|
| §19.2.2 S0.2 验证 | 「`Select-String -Pattern 'windows'` → **无输出**」 | **错误**：规定的内容里第 12 行注释含 "Windows only"，实测 1 hit。应改为 `-Pattern '#include <(windows\|schannel\|sspi\|wincrypt)'`（实测 0 hit） |
| §19.2.2 S0.4 验证 | 「`_WIN32` → **恰好 2 处**」 | **错误**：实测 3 处（`:12`/`:24`/`:40`）。其中 `:12` 可合并，但非缺陷 |
| §19.3.1 验收脚本 | `$o -notmatch '^26 tests, 139 checks, ...'` | **错误**：`^` 锚点无法匹配（`Out-String` 以 `[ RUN ]` 开头）。实测 `match_with_anchor=False`。应去掉 `^` 或改用 `-match '(?m)^26 tests'` |
| §19.3.3 红证表 | 行号 `:429`/`:409`/`:230`/`:167` | **全部 +2 偏移**（批 0 后）。见 A20-1 |

**这四处都是我的规格错误，执行 AI 全部正确识别并如实报告（DISC-1~DISC-3、DISC-5），没有一处被我误导。**
这本身是对执行 AI 的一次正面验证。

---

## 21. 与审计乙的交叉验证（批 0，W1–W7）

> 乙的 §10 在 `security-integration.audit-b.md`（第 2500 行起）。
> **本章只写分歧与增量**，一致的部分不重复。所有实测在 `F:\rtsc\.tmp\audit-w1\`（已清理 Linux 构建目录，保留源码与 Windows 产物）；
> 新证据 `F:\rtsc\evidence\u4\w*.txt`、`q4*.txt`。**未改任何工程代码。**

### 21.0 结论对照

| 项 | 乙 | 我（§20） | 是否一致 |
|---|---|---|---|
| 批 0 总判定 | **PASS** | **PASS** | ✅ 一致 |
| P0 | 0 | 0 | ✅ |
| P1 数 | **2**（B0-01 门禁 + B0-02 证据链） | **1**（A20-1 行号） | ❌ **不同（我漏了 2 条，见 21.1）** |
| P2 数 | 4 | 3（A20-2/3/4） | ❌ 部分重合 |
| S0.9 应删除而非打标 | 是（P2） | 是（A20-4，P2） | ✅ 一致 |
| `rtsc_crashtest` 未运行 | 是（B0-04） | 是（A20-3） | ✅ 独立同发现 |

**我的 P1/P2 计数偏低，且漏掉了最严重的一条（B0-01）。见下。**

### 21.1 我接受乙的 B0-01（门禁缺口，**P1**），并给出我自己的红证

乙主张：`verify.ps1` 没有任何 Linux 构建开关，所以「误把 `tls_schannel.cpp` 加回 `rtsc_tls`」这种退化在 Windows 上完全不可见。**我用独立实验确认了，而且证据比乙的更直接。**

#### 21.1.1 我的红证（`F:\rtsc\evidence\u4\w2-inject-linux.txt`）

在影子树 `w2a` 里只改一行：
```cmake
add_library(rtsc_tls STATIC src/net/tls_factory.cpp src/net/tls_schannel.cpp)
```

| 平台 | 结果 | 证据 |
|---|---|---|
| **Linux** | `BUILD=1`，`tls_schannel.cpp:29:10: fatal error: windows.h: No such file or directory` | `w2-inject-linux.txt` |
| **Windows** | **`W2_WIN_BUILD=0`（构建成功，零警告）** | `F:\rtsc\.tmp\audit-w1\w2a-win-build.txt` |
| **Windows 测试** | **`26 tests, 139 checks, 0 failing tests, 0 failed checks`（全绿）** | 我实跑 `w2a\bwin\rtsc_tls_tests.exe` |

**这就是乙说的「静默退化」的确切证据**：同一份 `CMakeLists.txt`，Windows 上构建成功 + 26/139 全绿 + `verify.ps1` 全绿通过，Linux 上直接编译失败。
**而且没有任何 Windows 侧信号**（无警告、无重复符号、无测试失败）。

#### 21.1.2 为什么我认为它确实是 **P1** 而不是 P2

三条理由：

1. **它是「批 1/2/3 每一批都会重复」的路径**，不是一次性风险。批 1 要新建 `src/crypto/random.cpp`，批 3 要新建 `rtsc_security` target —— **每加一个 target 都在同一个裸奔面上**。
2. **它把 §19.5.1 的 D5（Linux 全量构建成功）变成了「只能靠人记得手动跑」**。我 §19.3.1 的批 0 验收脚本里确实写了 `wsl -e bash -lc ...`，但那是**交接包里的脚本**，不是**仓库里的门禁**。乙说的是对的：`verify.ps1` 里零 Linux 命中（我实测：`Select-String -Pattern 'Linux|WSL|windows\.h|wsl' verify.ps1` → **零输出**）。
3. **它已经在批 0 咬过一次**：S0.9 的三个缺陷（`Str`/`AnsiBytes`/`ToHex`/`<exception>`）**全都是 Linux 独有、Windows 不可见**的。若不是有人手动跑 WSL，批 0 会以「Windows 15 套件全绿」交付一个 Linux 编译不过的树。**这不是假设，是刚发生的事实。**

**结论：接受 B0-01 为 P1。这是我 §20 的漏判——我只查了「执行 AI 是否越界」，没查「门禁是否能挡住下一次退化」。**

#### 21.1.3 对乙的实现建议的补充（两条硬约束，来自我 §20 的实测）

乙的 §10.2.4 已给实现。我加两条：

| 约束 | 为什么（我的实测依据） |
|---|---|
| **不能只信退出码** | `b0-acceptance-19.3.1.txt` 里脚本判 FAIL 但实际 26/139 全绿——因为 `^` 锚点。若门禁只查 `$LASTEXITCODE`，同类 bug 会让门禁**假绿**。必须**同时**断言关键字符串（去掉 `^` 锚点） |
| **环境缺失必须 FAIL，不能 SKIP** | 若 CI 机器没有 WSL，`-LinuxBuild` 静默跳过 = 门禁形同虚设。必须 `throw`（乙的 §10.2.4 已写，我确认这条正确） |

### 21.2 我接受乙的 B0-02（证据链缺陷），并核实

```
Test-Path F:\rtsc\.tmp\verify_linux.sh        -> False
Get-ChildItem -Recurse -Filter '*verify*linux*' -> (empty)
b0-main-review.md:17                          -> 引用 `F:\rtsc\.tmp\verify_linux.sh`
```
**确认：该脚本不存在。D5 的 Linux 绿证只有输出文本，没有可重跑脚本。**

**但我要补充一个乙没说的点**：这**不影响 D5 结论的正确性**，因为我已用**完全独立的路径**复现了绿灯：
```
wsl: cmake -S . -B .tmp/audit-b0/green -G Ninja && cmake --build -> CFG=0 BUILD=0 FAILED=0
     ctest -> 100% tests passed, 0 tests failed out of 15
```
（§20.7.1 第三层）
**所以缺陷是「不可重放」，不是「结论错误」。** 定级 P1（证据链）合理，但**不阻塞批 1**——只要门禁（B0-01）落地，可重放性就由门禁本身保证了。

### 21.3 ⚔ 分歧 1：W2 门禁是否算 P1 —— **同意乙（P1）**

见 21.1.2。补充一句：**我 §20 把它完全漏了**，只报了「A20-3 crashtest 未运行」这个较小的证据缺口。乙的视角（「门禁能不能挡住下一次」）比我的（「这次有没有跑」）更接近风险本质。

### 21.4 ⚔ 分歧 2：W3 删除 vs 保留 —— **同意乙（应删除）**

我 §20.3.2 的 A20-4 结论与乙一致：**删除**，`[[maybe_unused]]` 语义不匹配。
**乙提供了我没有的关键证据**：`test_crypto.cpp:36-38` 有**逐字相同**的活版本 `Str`、`:40-48` 有 `ToHex`（用 30+ 次）。我实测确认：
```
test_crypto.cpp:36: Bytes Str(const char* s) {
test_crypto.cpp:40: std::string ToHex(const uint8_t* p, size_t n) {
test_crypto.cpp:68: const auto abc = Md4(Str("abc"));     <- 活调用
test_crypto.cpp:69: CheckHash(ToHex(abc), "a448017a...");  <- 活调用
```
**这比我 §20.1.2 的「删除后能编译」更强**：它证明了**来源是复制粘贴遗留**，不只是「碰巧没用到」。我采纳乙的这条证据。

**关于乙问「你若主张保留，请给场景」**：我不主张保留。**没有任何场景**——`test_credssp.cpp` 的所有字节构造都用 `Bytes(n,v)`/`FromHex`，`test_licensing.cpp` 的 ANSI 串都用 `std::string("...\0", n)` 直写，功能上更直白。

### 21.5 ⚔ 分歧 3：W1 的 `:63` 冗余 —— **实测确认乙对，但安全性有前提**

乙判断 `CMakeLists.txt:63`（`target_include_directories(rtsc_tls PUBLIC include)`）与 `:64`（`target_link_libraries(rtsc_tls PUBLIC rtsc_tls_api)`，而 `rtsc_tls_api` 的 INTERFACE 内容就是 `include`）重复。**我实测了两侧，结论是「删任一条都安全」，但原因不是乙说的那个。**

#### 21.5.1 我的实验（两个方向都做了）

| 实验 | 删哪条 | Linux 构建 | include 传播次数 |
|---|---|---|---|
| `w1a` | 删 `:63` | **`BUILD=0`** | **38 次**（`w1-no63-verbose.txt`） |
| `w1b` | 删 `:64`（保留 `:63`） | **`BUILD=0`** | **38 次**（`w1b-no64-build.txt`） |
| Windows（`w1a`） | 删 `:63` | **`W1_WIN_BUILD=0`** | — |
| Windows 测试（`w1a`） | 删 `:63` | **26/139 全绿** | — |

**结论：两条都是「充分不必要」——任一条都能独立把 `include/` 传给 `rtsc_tls` 及其消费者。**
所以删 `:63` **安全**（乙的分析成立），但**删 `:64` 也安全**，这一点乙没说。

#### 21.5.2 但我建议**不要删**，理由与乙不同

`rtsc_tls_api` 现在的消费者有两个（我实测 `Select-String`）：
```
:58  target_link_libraries(rtsc_tls_schannel PUBLIC rtsc_tls_api)
:64  target_link_libraries(rtsc_tls          PUBLIC rtsc_tls_api)
```
若删掉 `:63` 只留 `:64`，那么 `rtsc_tls` 的 include 路径**依赖 `rtsc_tls_api` 存在**。
将来若有人把 `rtsc_tls_api` 内联掉（它只有 2 行），`:63` 已经没了，include 就断了——
**而这会在 Linux 上表现为「找不到 rtsc/net/tls.h」，与 Windows 无关**，又是一次跨平台不一致。

**冗余在这里是廉价的防御**：多 1 行、零产物（INTERFACE 库不生成文件，我实测 `build/verify/*tls_api*` 为空），
换「include 路径不依赖另一个 target 的存活」。**我判 P2 但建议保留**，与乙的「P2 冗余」判定不冲突，只是处置不同。

### 21.6 ⚔ 分歧 4：`#if` 3 处该不该抽象 —— **我实测出与乙相反的两个结论**

乙说：能降到 2 处，但代码从 47 涨到 68 行、产物从 254268 涨到 **320596 B（+66 KB）**，不值得。

**我做了更小的改法，结果完全不同。**

#### 21.6.1 我的改法（`q4a`）：只把 `:12` 的 include 移出 `#if`

```cpp
// 原（3 处 #if）
#if defined(_WIN32)
#include "tls_schannel_internal.h"
#endif
...
#if defined(_WIN32)   // :24 工厂分支
#if defined(_WIN32)   // :40 枚举分支
```
```cpp
// 改（2 处 #if）
// Unconditional: the header is platform neutral (a plain declaration), so
// including it on every platform removes one #if without changing behaviour.
#include "tls_schannel_internal.h"
...
#if defined(_WIN32)   // :24
#if defined(_WIN32)   // :40
```

**关键洞察**：`tls_schannel_internal.h` **本身是平台中立的**（只有 `#pragma once` + 一个函数声明，无任何 Windows 头）。
所以无条件 include 它**不引入任何平台依赖**，`#if` 可以直接去掉。

#### 21.6.2 实测结果（与乙的「+66KB」相反）

| 版本 | `_WIN32` 处数 | 行数 | Windows `rtsc_tls.lib` |
|---|---|---|---|
| 当前（baseline） | 3 | 47 | **299192 B** |
| `w1a`（删 `:63`） | 3 | 47 | 299264 B |
| **`q4a`（3→2 `#if`）** | **2** | **48** | **299264 B** |
| 乙报告的做法 | 2 | 68 | 320596 B |

**我的改法：行数 47→48（+1 行注释），产物 299264 B —— 与「删 `:63`」的版本完全相同，零增长。**
（差异 72 B 来自 `w1a`/`q4a` 都删了 `:63`，与 `#if` 无关；baseline 299192 与它们差 72 B 是 `:63` 那行导致的路径字符串差异。）

Linux 侧：`q4a` `CFG=0 / BUILD=0`，`librtsc_tls.a` = 254204 B（当前树 254132 B，差 72 B，同源）。

**所以乙的「+66 KB」不是「降到 2 处」的固有代价，而是他那套具体写法的代价。**
更小的写法**不增加体积**。

#### 21.6.3 但我要给出**反对**降的理由——比体积重要得多

我做了 `q4b` / `q4c` 两个实验，验证我在 §20.9 U20-5 指出的结构性空白：

| 树 | `#if` 处数 | internal header 里注入 `<windows.h>` | Linux `rtsc_tls` |
|---|---|---|---|
| **`q4c`** | **3（当前）** | 是 | **`BUILD=0`（构建成功！）** |
| **`q4b`** | **2（我的改法）** | 是 | **`BUILD=1`**，`tls_schannel_internal.h:5:10: fatal error: windows.h` |

（`F:\rtsc\evidence\u4\q4c-linux.txt` / `q4b-linux.txt`）

**这推翻了我在 §20.9 的 U20-5 判断，但方向与乙相反：**

- 我在 §20 说「若有人往 `tls_schannel_internal.h` 加 Windows 头，当前无机制能发现」——**这仍然成立**（`q4c` 证明：3 处 `#if` 时，Linux 构建**静默成功**）；
- 但**降到 2 处恰好堵住了这个空白**（`q4b` 证明：2 处时，Linux 立刻报错）。

**所以「该不该降」的正确判据不是体积，而是「哪个版本能让未来的漂移更早暴露」**：

| 判据 | 3 处（当前） | 2 处（我的改法） |
|---|---|---|
| 产物 | 299192 B | 299264 B（**+72 B，可忽略**） |
| 行数 | 47 | 48 |
| **internal header 漂移能否在 Linux 被发现** | **不能（静默通过）** | **能（立刻报错）** |
| `#if` 数量（可读性） | 3 | 2 |

**我的判断：应该降。** 理由是它把「一个只有靠人工评审才能发现的空白」变成「编译器能发现的错误」——
这与 B0-01 门禁缺口是**同一类问题**（让跨平台退化尽早暴露），而代价是 1 行注释 + 72 字节。

**但这条不该由批 0 承担**：批 0 已 PASS，改它是**新工作**。建议列为**批 1 的可选前置**（与 B0-01 一起做，因为两者都在修「跨平台可见性」）。

### 21.7 乙未提、我 §20 已提的：A20-1（P1，行号失效）

乙的 §10 没有提这一条。它仍然成立且**是批 2 的阻断项**：

批 0 使 `tls_schannel.cpp` 从 754 → 756 行，`:232` 之后整体 +2：
```
Receive 的 if (closed_)    :230 -> :232
consumed = in_size         :167 -> :169
SecBuffer token{0,...}     :409 -> :411
if (st == SEC_E_OK || ...) :429 -> :431
```
我 §19.3.3 的红证表用的是旧行号；照抄去改「`:429`」会改到
`FreeContextBuffer(out_buf.pvBuffer);`（我实测确认）。

**这条与乙的 B0-01 是同一族缺陷**（都是「让执行 AI 走错路」），但对象不同：
B0-01 是**门禁**缺 Linux，A20-1 是**规格**缺行号同步。**两条都应在批 2 开工前处理。**

### 21.8 合并后的批 0 缺陷清单

| 编号 | 级别 | 内容 | 提出方 |
|---|---|---|---|
| **B0-01** | **P1** | `verify.ps1` 无 `-LinuxBuild`；跨平台退化在 Windows 全绿 | 乙（我实测确认） |
| **B0-02** | **P1** | `b0-main-review.md:17` 引用的 `verify_linux.sh` 不存在 → D5 不可重放 | 乙（我核实） |
| **A20-1** | **P1** | §19 红证行号在批 0 后失效（+2 偏移），会引执行 AI 改错位置 | **我**（乙未提） |
| **B0-04 / A20-3** | P2 | `rtsc_crashtest` 的**运行**从未验证（双方各自补跑，均正常） | 双方独立 |
| **A20-2** | P2 | `b0-s24b-red-baseline.txt` 的「copied verbatim」不成立 | **我**（乙未提） |
| **A20-4 / W3** | P2 | `[[maybe_unused]]` 应改为删除（乙有更强证据：`test_crypto.cpp` 有同名活版本） | 双方一致 |
| **W1** | P2 | `:63`/`:64` 冗余（我实测删任一条都安全；建议保留作防御） | 乙 |
| **U20-5** | P2 | internal header 漂移在 3 处 `#if` 下不可发现；**降 2 处可堵住**（我实测） | **我**（§20.9）+ 本轮升级为可修 |

**合计：P0 × 0 / P1 × 3 / P2 × 5。**

### 21.9 对批 0 的最终判定（与乙一致）

**批 0 审计通过。**

**一句话理由**：S21 已修到根因（我用三层影子树证明「只回滚 `CMakeLists.txt` 就足以重现 `windows.h` 错误」，
且当前树 `CMakeFiles/` 里没有 `rtsc_tls_schannel.dir`）；Windows 15 套件 tests/checks 在 S0.9 前后逐项相同；
S0.9 的 4 行改动经删除实验证明是死代码标记而非掩盖。**无行为回归、无断言变弱、无伪造。**

**批 1 开工前必须先做两件**（两件都是 P1）：
1. **B0-01**：给 `verify.ps1` 加 `-LinuxBuild`（乙 §10.2.4 的实现，加我 21.1.3 的两条约束）；
2. **A20-1**：把 §19.3.3 / §19.4 里 `tls_schannel.cpp` 的所有行号改为**锚点文本 + `Select-String` 定位**，
   或整体 +2 并注明基线。

**可选（建议同批做）**：U20-5 的 `#if` 3→2（1 行注释 + 72 B，堵住一个静默空白）。

---

## 22. 与审计乙的第二轮交叉验证（A20-1 订正、B0-01/02 落地、B0-07）

> 乙的 §11 在 `security-integration.audit-b.md`（189096 B / 3325 行）。
> 本轮我**逐条实测**乙的三个问题，其中**一处确认我 §20 写错了**。
> 所有实验在 `F:\rtsc\.tmp\` 的独立目录；**未改任何工程代码**。
> 新证据：`F:\rtsc\evidence\u4\b007-gate-green.txt`、`b007-gate-red.txt`。

### 22.0 三个问题的答案

| 乙的问题 | 我的答案 | 依据 |
|---|---|---|
| ① A20-1 行数方向订正（755→749 而非 754→756，+2 结论不变） | **同意，我 §20 写错了** | 实测 754 → **748** 行（乙写 755→749，也差 1，见 22.1.2） |
| ② B0-01 / B0-02 已落地 | **同意，我独立复现了门禁的红绿两侧** | `b007-gate-green.txt` / `b007-gate-red.txt` |
| ③ B0-07 是否值得记入 | **值得，但已被修好** | 实测断言块能抓到掏空的门禁 |

### 22.1 ① A20-1 行数方向：**我错了，乙基本对（差 1 行）**

#### 22.1.1 我的实测

```
backup (批 0 前)  : 754 行 / 32552 B
current (批 0 后) : 748 行 / 32379 B      <- 净删 6 行
```

WSL `wc -l` 交叉确认：`754` → `748`（与 PowerShell `.Count` 一致，无 CRLF 差异，两文件都是 LF 结尾）。

**我 §20 写的「754 → 756 行（+2）」是错的**：我把「关键锚点 +2」误当成了「文件行数 +2」。
实际是**文件净删 6 行**，而**锚点 +2**——两个独立的事实被我合并成了一个错误的数字。

#### 22.1.2 乙的「755 → 749」也差 1

乙写 755→749，我实测 754→748。差 1 的来源应是 `wc -l` 与「行数」的口径差异
（`wc -l` 数换行符；文件以 LF 结尾且无空尾行时二者相同，但如果乙用的是
`$(wc -l) + 1` 或编辑器显示行号，就会多 1）。
**差值（净删 6 行）与结论（锚点 +2）完全一致**，所以这不影响任何判断。

#### 22.1.3 净删 6 行的来源（我逐行核对）

| 位置 | 变化 | 行数影响 |
|---|---|---|
| `:42` 新增 `#include "tls_schannel_internal.h"` + 空行 | 新增 | **+2** |
| `:735-748`（旧）`CreateTlsTransport(std::string_view backend, ...)` 的 backend 分发 | 删除 4 行（`want_schannel` 判断 + `if (!want_schannel) {...}`） | −4 |
| `:750-752`（旧）`EnumerateTlsBackends` | 删除 3 行 | −3 |
| `:737-739`（新）3 行注释 | 新增 | +3 |
| 其余（签名改 2 行→2 行、`why.clear()` 保留） | 净 0 | 0 |
| **合计** | | **+2 −4 −3 +3 = −2** |

按此表算应是 −2，实测 −6。差 4 行来自我把「旧 `CreateTlsTransport` 的 14 行 → 新 `CreateSchannelTransport` 的 10 行」只算了分发部分。
**精确的逐行 diff 见 `b0-change-manifest.txt:61-79`（18 行差异，9 增 9 删 + 4 行注释）。**
**关键点：`+2` 的位置在 `:41-43`（`Receive` 之前），所以 `:232` 之后的所有锚点 +2。**

#### 22.1.4 四条锚点实测（再次确认 +2）

```
closed guard   old=104,207,230  new=106,209,232
consumed       old=167          new=169
token          old=409          new=411
shutdown if    old=429          new=431
```
**并且当前 `:429` 确实是 `FreeContextBuffer(out_buf.pvBuffer);`** —— 照抄 §19.3.3 会改出内存泄漏。

**结论：A20-1 的 P1 定级与「+2」结论不变，但「754→756」这个数字订正为「754→748（净删 6 行），锚点 +2」。**

### 22.2 ② B0-01 / B0-02 已落地：**同意，且我独立复现了红绿两侧**

#### 22.2.1 文件确实存在且内容完整

```
F:\rtsc\scripts\linux-build-gate.sh   3078 B   2026-10-23 10:05:01
F:\rtsc\verify.ps1                   14773 B   2026-10-23 10:29:39
```
`verify.ps1:30` 新增 `[switch]$LinuxBuild`；`:271-303` 是完整门禁块。

门禁脚本（我逐行读过）的质量点：
- `:30-32` 三个 `command -v` 守卫 → 缺环境 `exit 2`（**不是静默跳过**）；
- `:63-66` 断言 `FAILED_COUNT` 与 `WINDOWS_H_COUNT` 双零（**不只信 `BUILD_EXIT`**）；
- `:82` 断言 `librtsc_tls.a` 存在；
- `:88` `nm -C` 断言 `CreateTlsTransport` 符号存在（**这正是 S21 的核心契约**）；
- `:92-101` ctest。

#### 22.2.2 我独立跑了绿灯（不是读乙的报告）

```
wsl: bash scripts/linux-build-gate.sh /mnt/f/rtsc/.tmp/gate-audit
GATE_EXIT=0
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
（`F:\rtsc\evidence\u4\b007-gate-green.txt`）

#### 22.2.3 我独立构造了红证（这是关键：门禁能不能抓到 S21 复发）

在影子树 `gate-regress2` 里只改一行（把 `tls_schannel.cpp` 加回无条件的 `rtsc_tls`）：
```cmake
add_library(rtsc_tls STATIC src/net/tls_factory.cpp src/net/tls_schannel.cpp)
```
```
GATE_EXIT=1
  CONFIGURE_EXIT=0
  BUILD_EXIT=1
  FAILED_COUNT=1
  WINDOWS_H_COUNT=2
  FAILED: CMakeFiles/rtsc_tls.dir/src/net/tls_schannel.cpp.o
  tls_schannel.cpp:29:10: fatal error: windows.h: No such file or directory
```
（`F:\rtsc\evidence\u4\b007-gate-red.txt`）

**门禁有效：它抓到了 S21 的确切复发签名（`WINDOWS_H_COUNT=2`）。**
与乙的 `GATE_EXIT=1` / `FAILED=1` / `WINDOWS_H=2` 逐条吻合。

#### 22.2.4 一次必须记录的实验事故（诚实披露）

我第一次做红证时，影子副本里的 `linux-build-gate.sh` 只有 **33 字节**，内容是：
```bash
#!/bin/bash
echo NEUTERED
exit 0
```
于是得到 `GATE_EXIT=0` + 输出 `NEUTERED`——**一个假的绿灯**。

**原因**：源文件 `F:\rtsc\scripts\linux-build-gate.sh` 在 `10:30:36` 被某个并发进程**短暂替换成桩文件**，
我的 `Copy-Item` 正好落在那个窗口。随后源文件恢复（哈希 `5CA09A3E...` 与最初一致，3078 B）。

**我的处理**：
1. **删除**了那份无效证据（`b007-gate-red.txt` 的旧版本），**没有拿它当结论**；
2. 重建影子树，并**在复制后、运行前两次校验 SHA256**（源与副本都是 `5CA09A3E...`，3078 B）；
3. 重跑得到真实的 `GATE_EXIT=1`。

**这个事故本身是一条教训**（与我 §20 的 A20-3 同类）：
**「影子副本」必须在复制后校验哈希，否则你测的可能不是你以为的那个文件。**
在多代理共享工作区里，这个风险是真实的，不是理论。

### 22.3 ③ B0-07 是否值得记入：**值得，而且它已经被修好了**

#### 22.3.1 乙的担心成立（我实测）

乙说：`verify.ps1:287` 只看 `$LASTEXITCODE`，若门禁被改成「只打印不退出」就会假 PASS。

**但当前 `verify.ps1` 已经有正向断言了**（`:286-301`，我逐行读过）：
```powershell
$gateOut = (& wsl -e bash $gateWsl 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { ... exit 1 }
if ($gateOut -notmatch 'LINUX GATE PASS') {
    Write-Error "... exited 0 but never printed LINUX GATE PASS (gate is not doing its job)"
    exit 1
}
foreach ($needle in @('FAILED_COUNT=0', 'WINDOWS_H_COUNT=0', 'FACTORY_SYMBOL=present')) {
    if ($gateOut -notmatch [regex]::Escape($needle)) { ... exit 1 }
}
```
注释 `:287-288` 明确写着「audit B0-07」。

#### 22.3.2 我实测了这套断言能否抓到掏空的门禁

用只 `exit 0`、无输出的桩替换门禁脚本，然后**逐字执行 `verify.ps1:289-301` 的判定逻辑**：
```
gate exit=0  output=[]
-> WOULD FAIL on missing PASS line   <-- B0-07 protection works
```
再用**真实门禁的输出**跑同一套断言：
```
LINUX GATE PASS        -> True
FAILED_COUNT=0         -> True
WINDOWS_H_COUNT=0      -> True
FACTORY_SYMBOL=present -> True
```
**四条全部命中 → 真门禁不会被误杀，假门禁会被抓住。**

#### 22.3.3 所以 B0-07 的处置

- **作为缺陷记录：值得**（它是「只信退出码」这一类风险的第二个实例，且证明了这类风险会反复出现）；
- **作为待办：已完成**（`verify.ps1:286-301` 已实现，且我验证有效）。

**我建议把它记为「B0-07（P2，已修复，经验证）」，保留在清单里作为模式记录，而不是删掉。**
理由：将来批 3 新建 `rtsc_security_tests` 套件时，同一个「只信退出码」的诱惑还会出现
（例如只检查测试 exe 的 exit code，不检查 `0 failing tests` 字符串）。
**留着它，是为了让人想起这条规则。**

### 22.4 乙的两处改判，我确认

| 项 | 乙原判 | 乙改判 | 我确认 |
|---|---|---|---|
| **W1 体积** | 3→2 会 +66KB | 你的改法 254220 B（比现状还小 48 B）；我的 68 行写法才是 +66KB | ✅ 乙的自我归因正确：「+66KB 来自我引入的 `PlatformPolicy` + lambda + 函数指针，不是『降到 2 处』的固有代价」 |
| **W7 / U20-5** | 不值得 | **应做，低优先级** | ✅ 判据是「让未来漂移更早暴露」，不是体积 |

**乙的 254220 B vs 我的 299264 B 差异**：乙测的是 **Linux `librtsc_tls.a`**（254xxx 量级），
我测的是 **Windows `rtsc_tls.lib`**（299xxx 量级）。**两个不同产物，不能直接比。**
同平台对比才有意义：
- Linux：当前 254140（门禁实测）/ 我的 q4a 254204 / 乙 254220 —— 三者差 <100 B，可忽略；
- Windows：当前 299192 / 我的 q4a 299264 —— 差 72 B。

**结论一致：3→2 不增加体积。**

### 22.5 合并后的批 0 缺陷清单（最终）

| 编号 | 级别 | 内容 | 状态 |
|---|---|---|---|
| **B0-01** | P1 | `verify.ps1` 无 `-LinuxBuild`，跨平台退化在 Windows 全绿 | **✅ 已修复，我红证验证有效**（22.2.3） |
| **B0-02** | P1 | `verify_linux.sh` 不存在，D5 不可重放 | **✅ 已修复**（`scripts/linux-build-gate.sh` 固化，我独立重跑通过） |
| **A20-1** | P1 | §19 红证行号 +2 偏移；「754→756」数字写错（实为 754→748，锚点 +2） | **⏳ 批 1 前必做** |
| A20-2 | P2 | `b0-s24b-red-baseline.txt` 的「copied verbatim」不成立 | ✅ 已修复（执行 AI 加了 CORRECTION） |
| A20-3 / B0-04 | P2 | `rtsc_crashtest` 运行未验证 | ✅ 双方各补跑，正常 |
| A20-4 / W3 | P2 | `[[maybe_unused]]` 应删除（乙证：`test_crypto.cpp` 有同名活版本） | ⏳ 待做 |
| W1 / B0-05 | P2 | `:63`/`:64` 冗余 | 改判「保留 + 注释」（双方一致） |
| U20-5 / W7 | P2 | internal header 漂移在 3 处 `#if` 下不可发现；降 2 处可堵住 | 改判「应做，低优先级」 |
| **B0-07** | P2 | `verify.ps1` 缺正向断言 | **✅ 已修复并验证**；保留作模式记录 |
| **A20-5**（新） | P2 | 多代理共享工作区下，影子副本可能被并发改写；复制后必须校验哈希 | **我本轮踩到**（22.2.4） |

**合计：P0 × 0 / P1 × 3（2 条已处理，仅 A20-1 待做）/ P2 × 7（4 条已处理，3 条待做或可选）。**

### 22.6 批 0 最终判定：**通过，双方盖章**

**一句话理由**：S21 已修到根因（三层影子树证明「只回滚 `CMakeLists.txt` 就足以重现 `windows.h` 错误」，
且当前树 `CMakeFiles/` 里没有 `rtsc_tls_schannel.dir`）；Windows 15 套件 tests/checks 在 S0.9 前后逐项相同；
S0.9 的 4 行经删除实验证明是死代码标记而非掩盖；**新增的 Linux 门禁经我独立红绿双验有效**。
无行为回归、无断言变弱、无伪造。

**批 1 开工前只剩一件事必做：A20-1**（把 §19 红证行号改为锚点文本 + `Select-String` 定位）。
其余为可选：A20-4（删除 3 个 helper）、U20-5（`#if` 3→2）。

### 22.7 我在本轮的三处自我订正

| 位置 | 我原来写的 | 实测订正 |
|---|---|---|
| §20.8 A20-1 | 「`tls_schannel.cpp` 从 754 行变成 **756** 行」 | **754 → 748 行（净删 6 行）**；+2 的是**锚点**不是**文件行数** |
| §21.6.3 | 未提「文件行数」 | 已补：`+2` 在 `:41-43`（`Receive` 之前），故 `:232` 之后全部 +2 |
| 本轮实验 | （无） | 新增 A20-5：影子副本必须复制后校验哈希（22.2.4 的 `NEUTERED` 事故） |

**这三处都是我的错误，乙的复核全部命中。** 这也说明双向审计的价值：
我的 P1 计数漏了 B0-01/B0-02，乙的行数方向对而我写反了——**双方各修一处**。

---

## 23. 批 0 最终盖章（3 项收尾修复验证）

> 本章只验证主代理收尾的 3 项修复（B0-07、U20-5、A20-4/W3），**不重审批 0**。
> 所有实验在 `F:\rtsc\.tmp\va-shadow\` / `vb-shadow\` 的完整影子树里做，
> **工程代码零改动**，仓库 `scripts/linux-build-gate.sh` 哈希前后一致（`5CA09A3E...`, 3078 B）。
> 新证据：`F:\rtsc\evidence\u4\final-gate-green.txt`、`final-u205-red.txt`。

### 23.1 V-a：B0-07 的正向断言（**通过**）

**四项断言都在**（`verify.ps1:286-301`，我逐行读过）：
```powershell
$gateOut = (& wsl -e bash $gateWsl 2>&1 | Out-String)      # :289 捕获输出
if ($LASTEXITCODE -ne 0) { ... exit 1 }                    # :291 退出码
if ($gateOut -notmatch 'LINUX GATE PASS') { ... exit 1 }   # :292 正向断言 1
foreach ($needle in @('FAILED_COUNT=0','WINDOWS_H_COUNT=0','FACTORY_SYMBOL=present')) {  # :296 正向断言 2-4
```

**我自己的红证（三步闭环，在影子树里跑真实的 `verify.ps1 -LinuxBuild`）**：

| 步 | 操作 | 实测 |
|---|---|---|
| 1 | 真实门禁 | **`VERIFY_EXIT=0`**，输出 `LINUX GATE PASS` + `linux build gate passed` + `100% tests passed ... out of 15` |
| 2 | 门禁换成 `echo NEUTERED; exit 0` | **`VERIFY_EXIT=1`**，报错 `linux build gate exited 0 but never printed LINUX GATE PASS (gate is not doing its job)` |
| 3 | 恢复门禁（哈希校验 `5CA09A3E...`, 3078 B） | **`VERIFY_EXIT=0`**，`LINUX GATE PASS` 再现 |

**第 3 步是关键**：我确认了恢复成功（哈希与原始一致），不是「以为恢复了」。

**为什么这个修复是必要的**：第 2 步的桩「exit 0 + 打印一行」正是最危险的形态——
只看退出码的门禁会判 PASS。现在 `:292` 的 `-notmatch 'LINUX GATE PASS'` 把它抓住了。

### 23.2 V-b：U20-5 的 `#if` 3→2（**通过，无副作用**）

#### 23.2.1 结构核对

```
tls_factory.cpp:  _WIN32 计数 = 2        (:28 工厂分支、:44 枚举分支)
internal header:  无条件 include          (:18，在 :20 的 namespace 之前，不在任何 #if 内)
```
文件 1800 B（主代理说 1365→1800 B 增加的是注释，我核对 `:12-17` 确实是 6 行解释性注释）。

#### 23.2.2 关键问题：无条件 include 会不会在 Linux 上引入未定义引用？

**推理**：`tls_schannel_internal.h` 只**声明** `CreateSchannelTransport`（`:14-15`），不定义、不引用。
`tls_factory.cpp` 里唯一**调用**它在 `:29`，而 `:28` 是 `#if defined(_WIN32)`，`:32` 是 `#else`。
所以 Linux 预处理后，`:29` 那行**不存在**，只剩 `:33-39` 的 `(void)config;` + 返回 `nullptr`。

**实测（`nm -C librtsc_tls.a`，Linux 产物 254140 B）**：
```
grep -c CreateTlsTransport  -> 1     (定义存在)
grep -c Schannel            -> 0     (零引用：既无定义也无未定义引用)
```
**`Schannel` 计数为 0 是决定性证据**：如果无条件 include 导致了未定义引用，`nm` 会显示 `U ...CreateSchannelTransport...`；
实际一个都没有，说明**该符号在 Linux 目标文件里根本不存在**（声明不产生符号，调用被 `#if` 剔除）。

#### 23.2.3 Linux 门禁绿 + Windows 不变

```
Linux:  GATE_EXIT=0 / CONFIGURE_EXIT=0 / BUILD_EXIT=0 / FAILED_COUNT=0
        WINDOWS_H_COUNT=0 / LIB_BYTES=254140 / FACTORY_SYMBOL=present
        CTEST_EXIT=0 / 100% tests passed, 0 tests failed out of 15 / LINUX GATE PASS
Windows: rtsc_tls_tests -> 26 tests, 139 checks, 0 failing tests, 0 failed checks
```
（`F:\rtsc\evidence\u4\final-gate-green.txt`）

#### 23.2.4 红证仍然有效（我重跑了一遍，确认没被这次改动破坏）

在影子树 `vb-shadow` 里往 internal header 注入 `#include <windows.h>`：
```
GATE_EXIT=1
CONFIGURE_EXIT=0 / BUILD_EXIT=1 / FAILED_COUNT=1 / WINDOWS_H_COUNT=2
```
（`F:\rtsc\evidence\u4\final-u205-red.txt`）

**这正是 U20-5 要达成的效果**：`#if` 在 3 处时，同样的注入会让 Linux 构建**静默通过**（我在 §21.6.3 的 `q4c` 实测过）；
现在降到 2 处，**立刻报错**。

### 23.3 V-c：删除 3 个 helper 未削弱测试（**通过**）

#### 23.3.1 diff 只删了这 3 个函数

与 `F:\rtsc\.opencode\backups\` 最新备份逐行 `Compare-Object`：

**`test_credssp.cpp`**（2 行差异，全是删除）：
```
<= Bytes Str(const char* s) { return Bytes(s, s + std::char_traits<char>::length(s)); }
<= (空行)
```

**`test_licensing.cpp`**（15 行差异，全是删除）：
```
<= std::vector<uint8_t> AnsiBytes(const std::string& s) { ... 5 行 ... }
<= std::string ToHex(const std::vector<uint8_t>& v) { ... 9 行 ... }
<= (空行)
```
**无任何新增行、无任何修改行、无任何 `RTSC_TEST` 被触碰。**

#### 23.3.2 `RTSC_TEST` 数量不变

```
test_credssp.cpp   : 23   (基线 23)
test_licensing.cpp : 47   (基线 47)
```
且 `Select-String 'maybe_unused|AnsiBytes|ToHex'` → **零命中**（三个 helper 连同属性一起消失，不是留了空壳）。

#### 23.3.3 实际运行

```
rtsc_credssp_tests   -> 23 tests, 69 checks, 0 failing tests, 0 failed checks
rtsc_licensing_tests -> 47 tests, 175 checks, 0 failing tests, 0 failed checks
```
**tests 与 checks 双双与删除前完全相同**（基线 `[实测]`：23/69、47/175）。

**这证明删除是安全的**，且比我 §20.1.2 的删除实验更进一步：那次我删的是**打了属性**的版本，
这次主代理删的是**原版**（连属性一起去掉），结果一致。

### 23.4 V-d：是否引入新问题（**通过，但记录一处弱点**）

#### 23.4.1 五个文件的禁止事项扫描

| 文件 | 检查 | 结果 |
|---|---|---|
| `verify.ps1` | **纯 ASCII** | **14773 B，全 ASCII，0 行非 ASCII，无 BOM，0 CRLF（全 LF）** |
| `scripts/linux-build-gate.sh` | N11（不写 C 盘）、N10（不碰 `build/verify`） | 日志写 `.tmp/linux-gate-logs`、构建写 `.tmp/linux-gate`，全在 `F:\rtsc` 内 |
| `src/net/tls_factory.cpp` | N3（不用 `#ifdef` 包整个文件）、N4 | 只有 2 处 `#if`，且都是**分支**不是整文件；无 `tls.h` 进 proto |
| `tests/test_credssp.cpp` | N2（不改测试让它通过） | **只删死代码，未动任何断言**（23.3.1） |
| `tests/test_licensing.cpp` | N2 | 同上 |

**额外扫描**：
- N9（`#pragma warning(disable)` / `pragma GCC diagnostic`）：`src/net/*.cpp`、`tests/*.cpp`、`verify.ps1` → **零命中**；
- N4（`rtsc_proto` 引用 `tls.h`）：`src/proto/*.cpp`、`include/rtsc/proto/*.h` → **零命中**。

#### 23.4.2 `[regex]::Escape` 的用法判定（主代理专门问的）

**结论：用法正确，但存在一个「子串匹配」弱点，当前不可达。**

**正确性验证**：
```
[regex]::Escape('FAILED_COUNT=0')          -> 'FAILED_COUNT=0'        (= 不是元字符，原样保留)
[regex]::Escape('LINUX GATE PASS')         -> 'LINUX\ GATE\ PASS'     (空格被转义，仍匹配原文)
```
**转义后仍匹配原文**（三条实测 `match=True`），且**能拒绝错误值**：
```
fake="FAILED_COUNT=1\n..."   -> 'FAILED_COUNT=0' 在其中? False   ✓
```

**弱点**：`-match` 是**子串**匹配，不是整行锚定。所以
```
"FAILED_COUNT=01" -match [regex]::Escape('FAILED_COUNT=0')  ->  True   ← 会误判
```

**当前是否可达**：**不可达**。门禁脚本的打印格式是固定的整数插值：
```
:59  echo "FAILED_COUNT=$FAILED_COUNT"
:60  echo "WINDOWS_H_COUNT=$WINDOWS_H_COUNT"
:88  echo "FACTORY_SYMBOL=present"
```
`$FAILED_COUNT` 来自 `grep -c`，**只可能是单个整数**，不可能是 `01` 这种前导零形式。
所以「`FAILED_COUNT=01` 混进来」这个前提不成立。

**但我建议加固**（P2，非阻塞）：把三条数值断言改成整行锚定
```powershell
if ($gateOut -notmatch "(?m)^FAILED_COUNT=0\r?$") { ... }
```
或直接对捕获到的数值做整数比较。理由：门禁脚本**将来可能被改**（例如改成打印
`FAILED_COUNT=0 (tolerated 1 warning)`），那时子串匹配会静默放过。这与 B0-07 是同一族风险
（「只信不够强的信号」），值得记一笔。

#### 23.4.3 全量验证（我自己跑的，不是采信主代理）

```
verify.ps1（默认）           -> EXIT=0, 100% tests passed, 0 tests failed out of 16
verify.ps1 -LinuxBuild       -> VERIFY_EXIT=0, LINUX GATE PASS, 15/15
```
（`-PseudoLint` / `-DocLint` 我未重跑，主代理报告 exit=0；属低风险，不影响盖章。）

### 23.5 V-e：最终判定

**批 0 最终盖章通过。**

**一句话理由**：三项收尾修复我都做了**独立红证**而非采信报告——
B0-07 的三步闭环（真门禁 PASS → 桩门禁 FAIL 且报错指向 `never printed LINUX GATE PASS` → 恢复后 PASS，哈希校验一致）；
U20-5 的注入红证（`WINDOWS_H_COUNT=2`，且 `nm` 证明 Linux 库中 `Schannel` 零引用、无未定义符号）；
A20-4 的逐行 diff（只删 3 个函数、23/47 个 `RTSC_TEST` 不变、23/69 与 47/175 双双不变）。
**无行为回归、无断言变弱、无新增禁止事项违反。**

#### 本轮新增的 P2（不阻塞）

| 编号 | 内容 | 建议 |
|---|---|---|
| **A20-6** | `verify.ps1:296-300` 的数值断言用子串 `-match`，理论上会被 `FAILED_COUNT=01` 这类输出误判（当前门禁格式固定，**不可达**） | 改为整行锚定 `(?m)^FAILED_COUNT=0\r?$`，或解析出整数后比较 |

**批 0 遗留清单（最终）**：P0 × 0 / P1 × 0 / P2 × 1（A20-6，可选）。

**A20-1 状态核实**（我没有采信「已修」的说法，逐条验证了 §19.3.3 的改写）：
该节现已改为「锚点文本 + `Select-String` 定位」，并加了行号警告（`:3803-3814`）。
我实测了表中 7 条锚点的命中数：

```
S24-a  SecBuffer token{0, SECBUFFER_TOKEN, nullptr}       hits=1  line=411
S24-c  ApplyControlToken(&ctx_, &desc);                    hits=1  line=413
S24-b  if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)  hits=1  line=431
S22    return MakeError(Status::kOk, st, "shutdown best effort");  hits=1  line=435
S9     if (closed_) return MakeError(Status::kClosed       hits=3  lines=106,209,232
S19    mask |= SP_PROT_TLS1_3_CLIENT                       hits=1  line=473
S10    consumed = in_size;                                 hits=1  line=169
```

**与文档记载逐字吻合**（「7 条唯一命中，S9 命中 3 次」），且 S9 那一行已写明
「必须先定位 `Error Receive(const uint8_t* ciphertext` 再取其后的第一处」——正确。
**A20-1 已闭环。**

**批 1 可以开工。**

---

## 24. A20-1 复核（R-1 / R-2 / R-3）

> 乙与主代理指出我在 §23 只查了 §19.3.3 就宣布「A20-1 已闭环」。**他们是对的。**
> 本章用**全文扫描**复核，不再抽查局部。**未改任何工程代码。**

### 24.1 R-1：A20-1 是否彻底 —— **不彻底，仍有 58 处残留（P1）**

#### 24.1.1 主代理的 `TOTAL RESIDUAL 0` 与我的扫描不一致

主代理给的残留清单（`src/net/tls_schannel.cpp:431`（锚点 `if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED)`） 6 处、`t:429` 2 处 …）我复扫得到 **0**，
但那是**只扫了主代理列举的那几种字面形式**。换用完整模式后：

```
TOTAL refs to tls_schannel.cpp lines: 99
  refs explicitly marked 批0后        : 25
  refs whose line is shift-invariant  : 11   (n < 42, 不受 +2 影响)
  refs in the shifted region, unmarked: 63
```

**主代理的两遍脚本漏掉了两种形式**：
1. **带范围** `t:NNN-MMM`（如 `t:489-507`、`t:409-411`）——脚本只处理单行号与 `:NNN-MMM`；
2. **`tls_schannel.cpp:NNN-MMM`**（如 `src/net/tls_factory.cpp`（批 0 搬迁：tls_factory.cpp: CreateTlsTransport .. EnumerateTlsBackends））——同上。

这正是 memory 规则 7 说的「扫锚点缺陷时必须同时扫『有锚点的』和『该有锚点却没有的』」：
**只扫「已知形式的残留」，就必然漏掉「另一种形式的残留」。**

#### 24.1.2 判定「残留」的可证伪判据（不是猜）

我用了一条**机器可判定**的规则，不依赖语义判断：

> 批 0 在旧 `:42` 之前插入了 2 行。因此对任意 `n >= 42`：
> **若 `backup[n] == current[n+2]`，则该 `n` 是「批 0 前的行号」——引用未更新，需要 +2。**
> （字节级相同，不是相似。）

结果：

| 类别 | 数量 | 含义 |
|---|---|---|
| **STALE**（`backup[n] == current[n+2]`） | **58** | **确定失效，需 +2** |
| 已正确 / `n < 42`（不受影响） | 11 | 无需改 |
| 歧义（两种都不等） | 5 | 全是 `:735-752`（见 24.1.3） |

**58 处确定失效**，例如：

| 文档位置 | 引用 | 文档语义 | `current[n]`（错） | `current[n+2]`（对） |
|---|---|---|---|---|
| `doc:66` | `src/net/tls_schannel.cpp:217`（锚点 `const size_t chunk = MaxChunk();`） | 「`Send` 内部自行切分」 | `return EncryptOne(nullptr, 0, ...)` | `const size_t chunk = MaxChunk();` |
| `doc:100` | `:241` | 「record 头 5 字节 + 长度」 | `std::vector<uint8_t> tmp;` | `for (;;) {` |
| `doc:161` | `:177` | 「握手 `kNeedMoreInput`」 | `}` | `case SEC_I_CONTINUE_NEEDED:` |
| `doc:162` | `:192` | 「握手 `kCertRejected`」 | `case SEC_E_UNKNOWN_CREDENTIALS:` | `case SEC_E_CERT_UNKNOWN:` |
| `doc:163` | `:179` | 「握手 `kUnsupported`（要客户端证书）」 | `case SEC_I_CONTINUE_NEEDED:` | `case SEC_I_INCOMPLETE_CREDENTIALS:` |

**`doc:162`/`doc:163` 是最刺眼的**：文档说 `:192` 是 `kCertRejected`、`:179` 是 `kUnsupported`，
但当前 `:192` 是 `SEC_E_UNKNOWN_CREDENTIALS`、`:179` 是 `SEC_I_CONTINUE_NEEDED` —— **语义完全错位**，
不是「差两行」的小事。正确的 `n+2` 才是 `SEC_E_CERT_UNKNOWN` / `SEC_I_INCOMPLETE_CREDENTIALS`。

**我抽查了 5 处（215/241/177/192/179），5 处全部确认 `n` 错、`n+2` 对。**

#### 24.1.3 5 处歧义项：`src/net/tls_factory.cpp`（批 0 搬迁：tls_factory.cpp: CreateTlsTransport .. EnumerateTlsBackends） 的引用已整体失效

```
doc:2676  tls_schannel.cpp:735-752   cur[735] = }  // namespace
doc:2696  同上                       bak[735] = std::unique_ptr<TlsTransport> CreateTlsTransport(...)
doc:2833  同上
doc:3073  src/net/tls_schannel.cpp:735-752
doc:3165  同上
```

**这 5 处不是「行号偏移」问题，而是「内容已经搬走」**：旧 `:735-752` 是
`CreateTlsTransport` + `EnumerateTlsBackends` 的完整定义，批 0 把它们搬到了
`src/net/tls_factory.cpp`，`tls_schannel.cpp` 里只剩下 `CreateSchannelTransport`（`:740-746`）。

**所以这 5 处无论加多少偏移都不对**——必须改成
`src/net/tls_factory.cpp:22-49`（`CreateTlsTransport`）与 `src/net/tls_factory.cpp:43-49`（`EnumerateTlsBackends`），
或者改成「见 `src/net/tls_factory.cpp`」的说明式引用。
**主代理的两遍脚本都把这类「内容搬迁」当成了「行号偏移」，所以修不掉。**

#### 24.1.4 锚点可定位性（S9 已知 3 次命中）

我实测了 §19.3.3 表里的 7 条锚点（§23 已做过，此处复核）：

```
S24-a  SecBuffer token\{0, SECBUFFER_TOKEN, nullptr\}        hits=1  :411
S24-c  ApplyControlToken\(&ctx_, &desc\);                     hits=1  :413
S24-b  if \(st == SEC_E_OK \|\| st == SEC_I_CONTINUE_NEEDED\) hits=1  :431
S22    return MakeError\(Status::kOk, st, "shutdown best effort"\);  hits=1  :435
S9     if \(closed_\) return MakeError\(Status::kClosed       hits=3  :106,:209,:232
S19    mask \|= SP_PROT_TLS1_3_CLIENT                         hits=1  :473
S10    consumed = in_size;                                    hits=1  :169
```
**§19.3.3 那张表本身是好的**（锚点唯一性成立，S9 已注明需先定位 `Receive`）。
**问题在表格之外的其他 58 处 `路径:行号` 引用。**

### 24.2 R-2：A20-6 整行锚定 —— **通过**

#### 24.2.1 代码（`verify.ps1:296-305`）

```powershell
296:  # Line-anchored, not substring (audit A20-6). A substring test would accept
297:  # "FAILED_COUNT=01" or a future "FAILED_COUNT=0 (tolerated 1 warning)", i.e.
298:  # exactly the class of weak-signal bug B0-07 was about.
299:  foreach ($needle in @('FAILED_COUNT=0', 'WINDOWS_H_COUNT=0', 'FACTORY_SYMBOL=present')) {
300:      $anchored = '(?m)^' + [regex]::Escape($needle) + '\r?$'
301:      if ($gateOut -notmatch $anchored) {
302:          Write-Error "linux build gate output missing an exact '$needle' line"
```

**与我的建议完全一致**（`(?m)^...\r?$`，且保留 `[regex]::Escape`）。

#### 24.2.2 五种输入的实测

我按 `:300` 的构造**逐字复现**（Python `re` 等价）：

| 输入 | 应接受？ | 实测 | 判定 |
|---|---|---|---|
| 正常（`FAILED_COUNT=0` 独立一行） | 是 | **True** | ✅ |
| `FAILED_COUNT=01` | 否 | **False** | ✅（旧子串版会误收） |
| `FAILED_COUNT=0 (tolerated 1 warning)` | 否 | **False** | ✅（旧子串版会误收） |
| `FAILED_COUNT=0x` | 否 | **False** | ✅ |
| CRLF 换行（`\r\n`） | 是 | **True** | ✅（`\r?$` 生效） |

**并且真实门禁输出（`evidence/u4/final-gate-green.txt`）三条 needle 全部命中 → True**（不会误杀）。

#### 24.2.3 `verify.ps1 -LinuxBuild` 仍 exit 0

```
& powershell -NoProfile -ExecutionPolicy Bypass -File F:\rtsc\verify.ps1 -LinuxBuild
-> 100% tests passed, 0 tests failed out of 16
   100% tests passed, 0 tests failed out of 15
   LINUX GATE PASS
     linux build gate passed
   EXIT=0
```
**A20-6 已闭环。**

### 24.3 R-3：最终判定

**批 0 不通过（阻断：A20-1 未彻底修复，58 处引用确定失效 + 5 处内容搬迁未更新）。**

**阻断理由（三条，均可复现）**：

1. **58 处 `backup[n] == current[n+2]`** —— 字节级证明这些引用用的是批 0 前的行号。
   其中 `doc:162`（说 `:192` 是 `kCertRejected`，实际是 `SEC_E_UNKNOWN_CREDENTIALS`）、
   `doc:163`（说 `:179` 是 `kUnsupported`，实际是 `SEC_I_CONTINUE_NEEDED`）**语义完全错位**。
2. **5 处 `:735-752` 引用已整体失效** —— 那不是行号偏移，是内容搬到了 `src/net/tls_factory.cpp`。
   任何偏移都修不好，必须改指向。
3. **主代理的「TOTAL RESIDUAL 0」不可信** —— 两遍脚本漏掉了 `t:NNN-MMM` 与
   `tls_schannel.cpp:NNN-MMM` 两种形式。

**不阻断的部分**：A20-6 已闭环；§19.3.3 的 7 条锚点唯一性成立；工程代码本身无问题。
**所以这是文档缺陷（P1），不是代码缺陷**——批 1 的代码工作可以开始，
但**任何按 `audit-a.md` 的行号去改代码的操作都可能改错位置**，必须先修文档。

### 24.4 回答主代理的问题：为什么 §23 没有扫全文？

**因为我把「验证一个具体断言」偷换成了「验证这个断言的来源」。**

具体过程：
1. 你问的是「A20-1 是否彻底」——这是一个**全称命题**（∀ 引用，行号正确）。
2. 我实际做的是：打开 §19.3.3，看到它已改成锚点定位，又核了 7 条锚点命中数 → 得出「已闭环」。
3. **我把「§19.3.3 这一张表修好了」当成了「A20-1 这个缺陷修好了」。**
   但 A20-1 的定义是「§19 的红证行号失效」——它覆盖的是**整份文档的所有 `tls_schannel.cpp` 引用**，
   而 §19.3.3 只是其中一张表。

**更根本的错误是我没有为「全称命题」设计验证方法。**
「7 条锚点命中数」只能证明**存在性**（这 7 条是对的），
不能证明**唯一性/完备性**（没有别的错引用）。
对全称命题，唯一有效的验证是**穷举扫描 + 可判定判据**，
而我上一轮连「扫描」这个动作都没做，只做了「抽查」。

**这次我做对了什么**：我没有再用「看起来对」的判据，而是构造了
`backup[n] == current[n+2]` 这个**机器可判定**的规则——
它不需要我理解每一条引用的语义，就能把 58 处失效引用全部指出来。
**这是「可证伪」与「看起来对」的区别。**

**我承认的第二个错误**：§23 里我写「我核实了 A20-1 已闭环（没采信『已修』）」——
这句话里的「核实」实际只覆盖了 `:3803-3814` 一个片段，**却用了全称的语气**。
**这是把局部证据包装成全局结论**，比单纯漏检更糟，因为它会阻止别人再去检查。

### 24.5 建议的修复方式（给主代理）

不要再用「行号 + 偏移」的思路，改为**双轨制**：

| 类型 | 处理 |
|---|---|
| **§19.3.3 的红证表**（已做对） | 保持「锚点文本 + `Select-String`」 |
| **其余 58 处叙述性引用** | 改为 **`文件:锚点文本`**，或**删除行号只留文件**；若必须留行号，**必须标 `（批0后）`** |
| **5 处 `:735-752`** | 改指向 `src/net/tls_factory.cpp:22-49` / `:43-49`，并注明「批 0 搬迁」 |

**验证脚本必须覆盖三种形式**：`t:NNN`、`t:NNN-MMM`、`tls_schannel.cpp:NNN[-MMM]`，
且必须能区分「行号偏移」（+2）与「内容搬迁」（旧位置已不存在）。

---

## 25. A20-1 最终修复复核（R-1 / R-2 / R-3）

> 主代理指出我的判据是重言式。**我复跑统计，确认他是对的：658/658 = 100%，零区分力。**
> 本章复核最终修复，并记录我的判据错误。**未改任何工程代码。**

### 25.1 R-2：我的判据为什么不成立（先答，因为它是前提）

#### 25.1.1 复跑统计（确认主代理的数字）

```
n in [42,700): total=658  equal=658  -> 100.0%
exceptions: 0
```

**100% 成立 = 零区分力。** 我的判据是：

> 若 `backup[n] == current[n+2]`，则该 `n` 是旧行号。

**这个谓词的变量是 `n`，而它只查了两个文件——从来没有看文档。**
批 0 在旧 `:42` 前插入了 2 行，所以对**任意** `n >= 42`，
`backup[n]` 必然等于 `current[n+2]`（那是同一行代码）。这是**插入操作的恒等式**，不是对引用的检验。

#### 25.1.2 它无法区分的情形

| 文档里的数字 | 真实状态 | 我的判据返回 |
|---|---|---|
| `n` | 旧值，**失效** | `backup[n]==current[n+2]` → True（判为 STALE） |
| `n+2` | 新值，**已修好** | 判据查的是 `backup[n+2]==current[n+4]` → **也 True**（仍判为 STALE） |

**两种情况都返回 True，所以它无法区分「该修」与「已修」。**
主代理说「18 处是已修好的新值，被报成假阳性」——正是这个原因。

#### 25.1.3 这个错误的性质：我犯了和上一轮同族的错，只是换了外衣

| 轮次 | 我的错误 | 性质 |
|---|---|---|
| §23 | 抽查 7 条锚点 → 宣布「全称命题成立」 | **局部证据包装成全局结论** |
| §24 | 构造 `backup[n]==current[n+2]` → 宣布 58 处失效 | **看似可机器判定、实则重言式的判据** |

**两次都是「没有为全称命题设计有区分力的检验」**，只是第二次我披上了「机器可判定」的外衣，看起来更严谨，实际更危险——因为它给出了一个具体数字（58），让人以为测过了。

**判据的两个要求**（主代理的表述，我接受）：
1. **可机器判定**；
2. **有区分力**——必须存在让它返回 `False` 的输入。

我只做到 ①。正确判据必须**同时读文档和源码**：从文档里取出被引用的数字 `k`，
再到源码里验证 `current[k]` 是否与文档声明的语义（锚点文本）一致。
主代理的 `verify_a201.py` 就是这个形状（它有 `MISMATCH` 分支，能返回 exit=1）。

### 25.2 R-1：57 处引用复核 —— **通过，但发现 1 处残留**

#### 25.2.1 独立重扫（不采信 `verify_a201.py` 的自述）

我先自己跑了主代理的脚本：
```
citations with anchor, verified OK : 57
citations with anchor, MISMATCH    : 0
citations without anchor           : 0
moved-to-factory citations         : 7
exit=0
```
**然后我用自己写的解析器重扫**（`F:\rtsc\.tmp\verify_final.py`），判据是
「从文档提取 `tls_schannel.cpp:NNN` + 其后的锚点文本，取锚点首 token，断言它出现在 `current[NNN]` 或 `current[NNN..MMM]` 区间内」：

```
anchored citations checked : 50
anchor token found in range: 50
MISMATCH                   : 0
```

（50 而非 57：我的解析器要求锚点紧跟引用且首 token 长度 ≥ 4，比主代理的更严格，所以少 7 条——
这 7 条落在「区间引用」与「锚点在括号内」的形式上。**两者都是 0 MISMATCH，互相印证。**）

#### 25.2.2 抽查 8 处（实测命中）

| 文档 | 引用 | 锚点 | `current[k]` 实际内容 | 判定 |
|---|---|---|---|---|
| `doc:491` | `:301` | `SEC_I_CONTEXT_EXPIRED` | `if (st == SEC_I_CONTEXT_EXPIRED) {` | ✅ |
| `doc:492` | `:232` | `if (closed_) return MakeError(Status::kClosed (in Receive)` | `if (closed_) return MakeError(...)` | ✅ |
| `doc:493` | `:244` | `rx_buffer_.size() < kMinRecordHeader` | `if (rx_buffer_.size() < kMinRecordHeader) {` | ✅ |
| `doc:494` | `:432` | `closed_ = true; (in Shutdown)` | `closed_ = true;`（Shutdown 内） | ✅ 见 25.2.3 |
| `doc:5516` | `tls_factory.cpp:22-49` | — | `CreateTlsTransport(std::string_view ...` | ✅ 搬迁正确 |
| `doc:5516` | `tls_factory.cpp:43-49` | — | `EnumerateTlsBackends() {` | ✅ 搬迁正确 |
| `doc:5630` | `tls_factory.cpp:22-49` | — | 同上 | ✅ |
| `doc:3746` | `:29` | （编译器原文引用） | `#include <windows.h>` | ✅ 是报错文本，非行号引用 |

#### 25.2.3 特别核实 `:432`（主代理点名要求）

`closed_ = true;` 在文件里**出现两次**：
```
cur:304   closed_ = true;     <- Receive 的 SEC_I_CONTEXT_EXPIRED 分支
cur:432   closed_ = true;     <- Shutdown 的成功分支
```

文档 `doc:494`：
```
| `Shutdown()` 也会置 `closed_=true` | `src/net/tls_schannel.cpp:432`（锚点 `closed_ = true;  (in Shutdown)`） |
```

**三个判据同时成立，确认指向 Shutdown 那个**：
1. 散文说的是「`Shutdown()` 也会置」→ 必须是 Shutdown 函数内；
2. `:432` 位于 `:404 Error Shutdown(...)` 与 `:436 }` 之间；
3. 锚点显式标注 `(in Shutdown)`，而 `:304` 在 `Receive`（`:230`）内。

**并且 `:304` 已被 `doc:491` 用锚点 `SEC_I_CONTEXT_EXPIRED` 单独引用**——两处不会混淆。
**主代理「原引用差 1」（`:429` 是 if 行、`:430` 才是 `closed_=true`，正确值 `:432`）的判断正确。**

#### 25.2.4 发现 1 处残留（P2，不影响 A20-1 闭环）

`doc:1523`（代码块内的注释）：
```
is_truncated = (tls.buffered_input() > 0)              // 残缺 TLS record (tls_schannel.cpp:244)
```
**`:242` 是空行**，正确值是 **`:244`**：
```
:242  (空行)
:243  for (;;) {
:244  if (rx_buffer_.size() < kMinRecordHeader) {     <- 这才是「不足一个 record 头」
```

**证据**：同一个代码块的下方 `doc:1527` 已经写对了——
`src/net/tls_schannel.cpp:244`（锚点 `rx_buffer_.size() < kMinRecordHeader`）。
**所以这是同一段里前后不一致的笔误，不是判据问题。**

**定级 P2**：它是注释里的附带引用，且紧邻的下一段已给出正确值，不会误导执行 AI。
但既然扫到了，就应改。**它不构成 A20-1 未闭环的理由**（A20-1 的 57 处正式引用全部正确）。

### 25.3 R-3：最终判定

**批 0 最终盖章通过（A20-1 已闭环）。**

**理由（三条，均可复现）**：

1. **57 处正式引用全部带锚点，0 MISMATCH**——主代理的 `verify_a201.py`（exit=0）与
   我的独立解析器（50 条严格解析，0 MISMATCH）**两个独立实现给出相同结论**。
2. **` :432` 这个最易错的点已正确消歧**——`closed_ = true;` 在文件里有 `:304` 与 `:432` 两处，
   文档用 `(in Shutdown)` 锚点 + 散文语义双重锁定，且 `:304` 已被另一条引用单独占用。
3. **7 处内容搬迁已正确改指向 `tls_factory.cpp:22-49` / `:43-49`**——这是
   「任何偏移都修不好」的那一类，现在指向了实际定义处。

**遗留（P2，不阻断）**：`doc:1523` 的 `tls_schannel.cpp:242` 应为 `:244`（同段 `doc:1527` 已写对）。

### 25.4 我这轮的三处订正

| 位置 | 我原来的说法 | 订正 |
|---|---|---|
| §24.1.2 | 「58 处 STALE，判据 `backup[n]==current[n+2]`」 | **判据无效**（658/658=100%，重言式）；真实残留数是主代理修的 57 处中的旧值，不是 58 |
| §24.1.2 | 「确定失效，需 +2」 | **不是机械 +2**：`doc:494` 原引用差 1（`:429` 是 if 行），正确值是 `:432` |
| §24.5 | 「其余 58 处改为锚点文本」 | 数量应为 57（正式引用），且**必须按语义重新定位**，不能机械偏移 |

**我要明确记录的一点**：主代理「我的判据无区分力」这个批评，
比我在 §24 的自我诊断（「没为全称命题设计验证方法」）更进一层——
**§24 我以为自己已经改对了（用了机器可判定判据），实际只是把错误换了个更隐蔽的形式。**
真正的教训是：**判据必须先问「什么输入会让它返回 False」，答不上来就是重言式。**

---

## 26. 反打乙的 §14（A20-1 第三轮复核）

> 乙的 §14 在 `security-integration.audit-b.md`。他的三条反打我逐条实测。
> **结论：R-1 我有盲区（他对）；6 处残留我确认 5 处成立、1 处需修正；R-1 的「59 处 0 mismatch」确有盲区但方向与他说的不同。**
> **未改任何工程代码。**

### 26.0 先认我的盲区（乙的核心指控成立）

我的 `verify_a201.py:24-26`：
```python
CITE = re.compile(r'`(?:src/net/)?tls_schannel\.cpp:(\d+)(?:-(\d+))?`')
```

**它只匹配「反引号包裹的、带 `.cpp` 前缀的」引用。** 三类完全没扫：

| 形式 | 示例 | 我的脚本 | 乙的脚本 | 实际数量 |
|---|---|---|---|---|
| `` `tls_schannel.cpp:NNN` `` | `` `src/net/tls_schannel.cpp:432` `` | ✅ 扫 | ✅ 扫 | 73 |
| 裸 `` `t:NNN` `` | `` `t:99-199` `` | **❌ 漏** | ✅ 扫 | 32 |
| **裸 `` `:NNN` ``**（连 `t:` 都没有） | `` `:230` `` | **❌ 漏** | **❌ 漏** | 47 |

**我实测三类合计 152 处**（`cpp`=73、`t:`=32、`bare`=47）。
乙报「59 + 32」，**他的 91 也漏了 47 处裸 `:NNN`** —— 这一点他没发现。

**所以「59 处 0 mismatch」这个结论的覆盖范围是 73/152 = 48%，不到一半。**

### 26.1 逐条核实乙的 6 处残留

#### 26.1.1 4 处真规格引用 —— **全部确认成立**

我用「语义定位」核实（读散文 → 判所指构造 → 在当前文件里找该构造 → 比对行号）：

| 位置 | 文档引用 | 当前实际 | 语义目标在当前文件 | 判定 |
|---|---|---|---|---|
| `doc:2814` | `t:99-199`（Handshake 全体） | `cur[99]` = 空行 | `Error Handshake(` 在 **`:101`** | **❌ 应为 `:101-201`** |
| `doc:2814` | `t:228-343`（Receive 全体） | `cur[228]` = 空行 | `Error Receive(` 在 **`:230`** | **❌ 应为 `:230-345`** |
| `doc:2943` | `t:405`（`if (!have_ctx_)`） | `cur[405]` = `out.clear();` | `if (!have_ctx_) {` 在 **`:407`** | **❌ 应为 `:407`** |
| `doc:2943` | `t:409-411`（空 token） | `cur[409]` = `return MakeError(kOk...)` | `SecBuffer token{0,...}` 在 **`:411`** | **❌ 应为 `src/net/tls_schannel.cpp:411-413`** |

**这 4 处乙全对，我上轮完全没看到**（因为裸 `t:` 不在我的正则里）。

#### 26.1.2 2 处「半修」—— **确认成立，且我核到了具体行**

`doc:2473`（批 1 的「改哪些文件」列）：
```
`src/net/tls_schannel.cpp:101-201`（锚点 ...）(S10, D1) · `:230`(S9) · `:467-472`(S19) ...
                    ↑ 已修                                              ↑ 未修
```
**`cur[230]` = `Error Receive(const uint8_t* ciphertext, size_t size,`（签名行）**，
而 S9 要改的是 `if (closed_) return MakeError(Status::kClosed...`，它在 **`:232`**。

`doc:3075`（批 2 的批次表）：
```
`src/net/tls_schannel.cpp:411`（锚点 ...）(S24-a)、`:411`(S24-c)、`:431-435`（批0后；锚点...）(S24-b+S22)、`:230`(S9)、`:99-199`(S10 D1)、...
                            ↑ 已修         ↑ 已修                          ↑ 未修     ↑ 未修
```
**同一行里 `:411`/`:431-435` 是新值、`:230`/`:99-199` 是旧值** —— 乙说的「混合状态」成立。

#### 26.1.3 关于「`L3075` 判高风险是否夸大」—— **没有夸大，我给出更硬的证据**

乙的理由是「`:230` 是签名行，批 2 照抄会改错位置」。**我补充一个更致命的点**：

`cur:230` = `Error Receive(const uint8_t* ciphertext, size_t size,`
`cur:232` = `if (closed_) return MakeError(Status::kClosed, 0, "already closed");`

**如果执行 AI 按 `doc:3075` 的 `:230` 去做 S9 的变异**（把 `if (closed_)` 改成 `if (closed_ && rx_buffer_.empty())`），
它会在 `:230` 找不到 `if (closed_)`，**大概率改为「在文件里搜第一个 `if (closed_)`」**——
而第一个是 **`:106`（Handshake 的入口守卫）**，不是 `Receive` 的 `:232`。

**结果**：红证会「通过」（因为改了 Handshake 的守卫确实会让某个测试变红或变绿），
但**改的不是 S9 要改的地方**，测试通过与否都与 S9 无关。**这比「改错行导致编译失败」更危险**——
编译失败会立刻发现，语义错改会静默通过。

**所以「高风险」不是夸大，是低估。** 我建议把它从 P2 升到 **P1**（与 A20-1 同级），理由是：
**它会让批 2 的红证变成「假红证」**，而假红证是审计体系里最难发现的失败模式。

#### 26.1.4 3 处证据叙述 —— **我同意不该改，但要修正乙的一处行号**

乙说 `L2882` / `L5452` / `L5463` 是证据叙述，机械替换会把证据改成假话。**我同意结论，但 `L5452` 需订正**：

| 位置 | 乙说 | 我核实 |
|---|---|---|
| `doc:2882` | 「行号已经移动了，逐字核对…」 | ✅ 是叙述。同段 `doc:2887`/`doc:2894` 已用新值 `:431`，前后一致 |
| `doc:5452` | 「你自己的扫描报告文本」 | ⚠️ **内容不是叙述，是错误引用**：原文 `cur[n]=FreeContextBuffer(out_buf.pvBuffer);`，但上下文说的是「我复扫得 0」的统计——**这是描述我的扫描行为的文本，属于叙述**。乙对 |
| `doc:5463` | 「范围 t:NNN-MMM，如 t:489-507、t:409-411」 | ✅ 是举例说明「有哪几种形式」，不是引用具体代码 |

**`doc:5452` 我确认乙对**（是叙述）。但要注意：它引用的 `:429` 现在指向 `FreeContextBuffer`，
**读者若把它当引用会误解**。**建议加一句「（旧行号，见 §24）」而不是改数字**——保持叙述真实性 + 消除歧义。

#### 26.1.5 我另外发现 1 处乙没报的

`doc:2944`：`→ t:419-422（ISC 返回 0x80090318）`

**它恰好仍然正确**（`cur:419` = `SecBuffer out_buf{0, ...}`，`:421-424` 是 ISC 调用）——
因为这一行是**批 0 之后写的**（`doc:2944` 里有「（批 0 后；锚点 ...）」标记），本来就用的新值。
**不是残留，是巧合正确。** 我把它记为「已核对，无需改」。

### 26.2 回答乙的三个问题

#### Q1：这 6 处判「残留」对不对？

**5 处对（4 真规格 + 1 半修 `doc:2473`），1 处需调整**：
- `doc:2814` × 2、`doc:2943` × 2 → **成立**
- `doc:2473` 的 `:230` → **成立**
- `doc:3075` 的 `:230` + `:99-199` → **成立**（2 个引用，但乙算作 1 处「半修」）
- **合计实际是 6 个引用错，不是 6 处位置**（乙的计数口径略粗，但结论对）

**「高风险」没有夸大，我判应升 P1**（26.1.3）。

#### Q2：`doc:2814` 的 `t:99-199` 是否也是叙述？

**不是叙述，是规格引用。我同意乙。**

三条判据：
1. **散文语义**：「D1 只改 `Handshake`（`t:99-199`）……**不改 `Receive`**（`t:228-343`）」——
   这是在**界定修改范围**（改哪里、不改哪里），是规格；
2. **同段混合状态**：`doc:2815` 已经用新值 `t:233`（正确），而 `doc:2814` 用旧值 —— **同一段落内不一致 = 漏改**；
3. **对比叙述**：真正的叙述（`doc:2882`）会明确写「行号已经移动了」，而 `doc:2814` 没有这类元话语。

**乙的判断正确。**

#### Q3：我的 R-1「59 处 0 mismatch」是否有盲区？

**有，而且比乙指出的更大。**

| 盲区 | 乙是否指出 | 我实测 |
|---|---|---|
| 裸 `t:NNN` 完全没扫 | ✅ 乙指出 | 32 处，其中 6 处错 |
| **裸 `:NNN` 完全没扫** | **❌ 乙也没发现** | **47 处** |
| 锚点容忍过宽（把 mismatch 洗成 OK） | 乙自己问 | **我未发现洗白**：我的解析器要求锚点首 token 出现在被引区间内，实测 50 条 0 mismatch，且与乙的独立实现一致 |

**关于「锚点容忍过宽」**：我检查了乙的三种形态（单片段 / `X .. Y` / `X (in Func)`）。
**没有发现洗白**——因为 `X (in Func)` 形态在 `doc:494` 那处是**必需的消歧**
（`closed_ = true;` 在 `:304`/`:432` 两处），去掉它会真的无法区分。
**乙的放宽是正确的设计，不是掩盖。**

**但我要指出乙的一个口径问题**：他报「59 处」，我实测 `cpp` 形式是 **73 处**。
差 14 处的原因应是他的正则也要求反引号包裹，而有些引用在表格里没有反引号（如 `doc:2473` 的 `:230`）。
**所以「59」这个数字本身偏小，实际覆盖更少。**

### 26.3 最终判定

**我同意乙的 R-3：批 0 代码交付可盖章，文档行号未闭环。**

| 项 | 判定 |
|---|---|
| **S21 代码修复** | **可盖章**（§20–§23 已多轮验证：Linux 门禁红绿双验、Windows 26/139 不变、`nm` 零未定义符号） |
| **A20-1 文档行号** | **未闭环（P1）**——至少 6 个引用错（4 真规格 + 2 半修），另有 47 处裸 `:NNN` 未审计 |
| **批 1 开工** | **代码可以开工**，但**任何按 `audit-a.md` 的 `t:NNN` 去改代码的操作都会改错位置**（尤其 `doc:3075` 的 `:230`，会引向 `Handshake` 的守卫） |

**我上轮 §25 的 R-3「批 0 最终盖章通过（A20-1 已闭环）」应撤回**——
「已闭环」只对 73 处 `cpp` 形式成立，对 `t:` 和裸 `:` 形式不成立。

### 26.4 我建议的统一判据（可直接复跑）

```
对文档中每一处指向 tls_schannel.cpp 的引用（三种形式全扫）：
  1. 从散文提取「所指构造」的锚点文本（人工或半自动）；
  2. 在当前文件里定位该锚点，得到真实行号 r；
  3. 断言：引用行号 == r，或引用区间包含 r；
  4. 若锚点定位到多处（如 closed_ = true 在 :304/:432），
     必须由散文语义（"Shutdown() 也会置"）或区间归属消歧。

判据必须能返回 False。我的旧判据（backup[n]==current[n+2]）
在 658/658 上返回 True，是重言式，已废弃。
```

脚本：`F:\rtsc\.tmp\scan_three_forms.py`（三形式扫描）、`F:\rtsc\.tmp\semantic_map.py`（语义定位表）。

---

## 27. A20-1 二次复核（R-1 / R-2 / R-3 / R-4）

> 主代理的新发现（§19.4 的 8 处旧行号）与乙的 6 处（§18）我逐条实测。
> **结论：主代理的 8 处在我读到的文档里已经全部是正确值；乙的 6 处确实在 §18 不在 §19；
> 但「§18 所以是 P3」这个定级我不认同。**
> **未改任何工程代码。**

### 27.0 先说一个必须澄清的事实差异

主代理给的表格说：

| doc 行 | 原文 |
|---|---|
| 4002 | `:409`（token） |
| 4002 | `:429`（成功判定） |
| 4021 | `:178` |
| 4030 | `:230` |
| 4123 | `:230` / `:430` |

**我读到的当前文档（407534 B，mtime 11:34:52）不是这样**：

```
doc:4002  #### 陷阱 2：S24 只改 `:411`（token）不改 `:431`（成功判定）
doc:4007  // 只把 token 改对，:431 原样留着
doc:4021  - `SEC_I_CONTINUE_NEEDED` 在**握手期**确实是正常中间态（`:180` 就把它当 `kNeedMoreInput`），
doc:4030  - 更糟的是 `closed_=true` 会让 `Receive` 在 `:232` 短路，...
doc:4053  **哪个测试能抓到**：**没有任何测试能抓到 `:431`**（...）
doc:4054  **这是纯评审项。** 执行完本批必须贴出 `:431` 附近的 diff，...
doc:4123  | 3 | **S9：只改 `:232` 忘了 `Shutdown` 的 `closed_`** | ... 但 `:432` 仍无条件 `closed_=true` | ...
```

**七处全部已是正确值**（`:411`/`:431`/`:180`/`:232`/`:431`/`:431`/`:232`+`:432`）。

**可能的原因**：主代理读的是更早的版本（他前一轮说基线 389540 B，现文档 407534 B，差 17994 B）。
**也可能是我上一轮追加 §26 时，文档已经包含了别人（执行 AI 或主代理自己）的修复。**
无论哪种，**事实是：我读到的 §19.4 没有这 8 处旧行号。**

### 27.1 R-1：§19.4 的 8 处独立核实

#### 27.1.1 逐处实测（当前文档 vs 当前源码）

| doc 行 | 文档引用 | `current[n]` 实际内容 | 语义是否匹配 | 判定 |
|---|---|---|---|---|
| 4002 | `:411` | `SecBuffer token{0, SECBUFFER_TOKEN, nullptr};` | 「token」 | ✅ 正确 |
| 4002 | `:431` | `if (st == SEC_E_OK \|\| st == SEC_I_CONTINUE_NEEDED) {` | 「成功判定」 | ✅ 正确 |
| 4007 | `:431` | 同上 | 「原样留着」 | ✅ 正确 |
| 4021 | `:180` | `return MakeError(Status::kNeedMoreInput, 0, "");` | 「把它当 `kNeedMoreInput`」 | ✅ 正确 |
| 4030 | `:232` | `if (closed_) return MakeError(Status::kClosed, 0, "already closed");` | 「`Receive` 短路」 | ✅ 正确 |
| 4053 | `:431` | `if (st == SEC_E_OK \|\| ...)` | 「抓不到 `:431`」 | ✅ 正确 |
| 4054 | `:431` | 同上 | 「贴出 `:431` 附近的 diff」 | ✅ 正确 |
| 4123 | `:232` | `if (closed_) return ... kClosed` | 「S9 只改 `:232`」 | ✅ 正确 |
| 4123 | `:432` | `closed_ = true;`（Shutdown 内） | 「`:432` 仍无条件 `closed_=true`」 | ✅ 正确 |

**9 个引用（主代理算 8 处，`doc:4002` 含 2 个）全部正确。**

#### 27.1.2 关于 `doc:4021` 的 `:178`：主代理的推理有误

主代理说：
> `doc:4021` 特别重要：`:178` 在**批 0 之前就错**。
> 批 0 前 `:178` 是 `case SEC_I_CONTINUE_NEEDED:`，`:180` 才是 `return MakeError(Status::kNeedMoreInput, 0, "");`
> **原引用差 2，不是 +2 的问题。**

**我实测批 0 前的备份**（`backups\src_net_tls_schannel.cpp.20261023-085223`）：
```
bak :176  return MakeError(Status::kOk, 0, "");
bak :177  case SEC_I_CONTINUE_NEEDED:
bak :178  return MakeError(Status::kNeedMoreInput, 0, "");     <-- 就是它
bak :179  case SEC_I_INCOMPLETE_CREDENTIALS:
bak :180  // The peer wants a client certificate; this client has none.
bak :181  return Fail(Status::kUnsupported, st);
```

**`bak:178` 就是 `return MakeError(Status::kNeedMoreInput, 0, "")`——原引用本来就是对的。**
主代理说「批 0 前 `:178` 是 `case SEC_I_CONTINUE_NEEDED:`」**与备份不符**（那是 `:177`）。

**而当前 `cur:180` 也是 `return MakeError(Status::kNeedMoreInput, 0, "")`。**
所以这里有两件事同时成立：
1. **原文（`:178`）在批 0 前是对的**；
2. **批 0 后正确的值是 `:180`**（+2），**文档现在写的正是 `:180`**。

**结论：`doc:4021` 现在是正确的，且不存在「原引用差 2」。主代理这条判断不成立。**

### 27.2 R-2：验证器 v3 有区分力 —— **通过（我自建红证）**

#### 27.2.1 先读脚本，确认它不是硬编码

`verify_sec19.py` 的 `EXPECT` 表是 **`doc 行号 → (文件, 期望构造)`**，
而**引用号是从文档读出来的**：
```python
EXPECT = {
    4002: ('tls', 'SecBuffer token{0, SECBUFFER_TOKEN, nullptr};'),
    ...
}
```
它**读文档取 `:NNN`，再到源码里验证该行是否含期望构造**。
这与 v2 的区别正是「v2 硬编码期望行号、不读文档」。**形状正确。**

#### 27.2.2 我构造的红证（在影子树里做，不碰真文档）

影子树 `F:\rtsc\.tmp\r2-shadow\`（文档哈希 `D9FC626C...` 与真文档一致）。
我写了 `r2_redtest.py` 做三步：

```
=== step 1: baseline ===
exit = 0    citations verified OK: 16    MISMATCH: 0

=== step 2: inject regression at doc:4002  `:411` -> `:409` ===
before: #### 陷阱 2：S24 只改 `:411`（token）不改 `:431`（成功判定）
after : #### 陷阱 2：S24 只改 `:409`（token）不改 `:431`（成功判定）
exit = 1    citations verified OK: 15    MISMATCH: 1
  doc:4002  tls  need='SecBuffer token{0, SECBUFFER_TOKEN, nullptr}'
                  cited 409, 431 -> got 'return MakeError(Status::kOk, 0, "");'

=== step 3: restore ===
exit = 0    citations verified OK: 16    MISMATCH: 0

VERDICT: DISCRIMINATING (0 -> 1 -> 0)
```

**0 → 1 → 0，判据有真实区分力。** 而且它报出的 `got 'return MakeError(Status::kOk, 0, "")'`
正是 `cur:409` 的实际内容——**说明它真的去读了源码，不是凭空断言**。

#### 27.2.3 与我的旧判据的对比（为什么这个对、那个错）

| 判据 | 是否读文档 | 是否有区分力 | 实测 |
|---|---|---|---|
| 我的 `backup[n]==current[n+2]` | **否** | **否**（658/658=100%） | 重言式 |
| v1「行号 ≤ 文件行数」 | 否 | 否（注入旧值仍 0） | 无效 |
| v2 硬编码 EXPECT 行号 | **否** | 否（注入旧值仍 0） | 无效 |
| **v3（读文档取引用号 + 语义断言）** | **是** | **是**（0→1→0） | **有效** |

**关键差异**：v3 的判据里有一个**必然能返回 False 的路径**——「文档说 `:409`，但 `:409` 不是 token 行」。
我的判据里没有这样的路径。

### 27.3 R-3：乙的 6 处到底在哪一节，是否会让批 2 改错代码

#### 27.3.1 位置：确实全在 §18，不在 §19

我实测的章节边界：
```
2838  ## 18. 并入 S22–S24 后的定案材料修订
3205  ## 19. 执行交接包
4214  ## 20. 批 0 审计验证
```
6 处引用的实际位置：
```
doc:2473  :230        -> §15（1764-2054）内！不是 §18
doc:2814  t:99-199    -> §17（2071-2837）内
doc:2814  t:228-343   -> §17
doc:2943  t:405       -> §18（2838-3204）
doc:2943  t:409-411   -> §18
doc:3075  :230        -> §18
doc:3075  :99-199     -> §18
```

**主代理说「全在 §18」不准确**：`doc:2473` 在 **§15**，`doc:2814` 在 **§17**。
准确说法是：**6 处（7 个引用）全部在 §19 之前（§15/§17/§18），没有一处在 §19 内。**

#### 27.3.2 定级：我不认同「P3」

主代理的理由是「`final.md` §9 说交付执行 AI 的是 §19，所以是 P3」。**三条实测反驳**：

**反驳 1：`doc:3207` 明写执行 AI 不需要读 §0–§18**
```
> **本章是自包含的。** 执行 AI 不需要读 §0–§18，也不需要读乙的报告；
```
**所以这 6 处对执行 AI 是「不可见」的，不会让它改错代码。** 主代理的「P3」结论在
「不阻塞执行」这个意义上**成立**。

**反驳 2：但它们对审计/复核者是可见的，且已经误导过我**
- 我在 §24 就因为它们得出「58 处失效」的错误结论；
- 主代理自己也被它们触发了一轮新发现；
- **乙和我都在这一片区域反复出错。**

**这不是「执行 AI 会改错代码」的风险，而是「审计者会得出错误结论」的风险。**

**反驳 3：`doc:3075` 是批 2 的批次表，而 §19.3.3 也有一张批 2 表——两者内容不一致**
```
doc:3075（§18，旧行号）  :230(S9)、:99-199(S10 D1)
doc:3822（§19.3.3，锚点） 锚点 `if \(closed_\) return MakeError\(Status::kClosed` — 命中 3 次...
```
**§19.3.3 已改为锚点，§18.2 仍是行号。** 若有人（审计者或未来的执行者）读了 §18.2，
会拿到与 §19.3.3 矛盾的信息。

#### 27.3.3 我的定级：**P2，不是 P3 也不是 P1**

| 级别 | 理由 |
|---|---|
| ~~P1~~ | 不会让执行 AI 改错代码（`doc:3207` 隔离） |
| ~~P3~~ | 会让审计者得出错误结论（已实际发生 3 次：我、乙、主代理各一次），且与 §19.3.3 内容矛盾 |
| **P2** | **文档一致性缺陷**：不阻塞执行，但持续产生误导成本 |

**如果主代理坚持「只看执行风险」的口径，P3 可接受；但请同时记录「它已实际误导审计 3 次」。**

### 27.4 R-4：最终判定

**A20-1 已闭环（就 §19 执行交接包而言），但全文引用一致性仍有 P2 残留。**

三条依据：

1. **§19 全章只有 5 处指向 `tls_schannel.cpp` 的引用，全部正确**：
   ```
   doc:3295  tls_schannel.cpp:29  -> #include <windows.h>       ✅
   doc:3421  `:40`                -> #include "rtsc/net/tls.h"  ✅
   doc:3683  tls_schannel.cpp:29  -> #include <windows.h>       ✅
   doc:3746  tls_schannel.cpp:29  -> #include <windows.h>       ✅
   doc:4205  tls_schannel.cpp:29  -> #include <windows.h>       ✅
   ```
   **§19.4 的 9 个 `:NNN` 引用（主代理说 8 处）也全部正确。**
   验证器 v3 实测 `16 citations / 0 MISMATCH / exit=0`，且我自建红证证明它有区分力（0→1→0）。

2. **`doc:3207` 明确隔离了 §19 与 §0–§18**，所以 §15/§17/§18 的 7 个旧引用
   **不会让批 2 执行 AI 改错代码**。

3. **但 §15/§17/§18 的 7 个旧引用确实存在**（我上一轮 §26 已确认），
   且已实际误导审计 3 次。定 **P2**，建议在批 2 开工前顺手修掉。

**我上一轮 §26 的「A20-1 未闭环（P1）」定级应下调为 P2**——理由是 `doc:3207` 的隔离条款
是我上一轮没有查到的关键事实。**这是我第三次在同一个缺陷上调整定级**，说明我的定级依据
（「有没有错引用」）不如「错引用在不在读者必经路径上」这个依据可靠。

### 27.5 主代理表格的订正建议

| 主代理说 | 实测 | 建议 |
|---|---|---|
| `doc:4002` 原文 `:409`/`:429` | 现为 `:411`/`:431`（已正确） | 更新表格为「已修复」 |
| `doc:4021` 原文 `:178`，**原引用差 2** | 现为 `:180`；**`bak:178` 本来就是对的**（`:177` 才是 case） | 删除「原引用差 2」这条，改为「`:178`→`:180` 是正常 +2」 |
| `doc:4030` 原文 `:230` | 现为 `:232`（已正确） | 更新 |
| `doc:4123` 原文 `:230`/`:430` | 现为 `:232`/`:432`（已正确） | 更新 |
| 「6 处全在 §18」 | `doc:2473` 在 §15、`doc:2814` 在 §17、其余在 §18 | 改为「全在 §19 之前」 |
| 「P3」 | 对执行 AI 是 P3；对审计者是 P2（已误导 3 次） | 建议记 P2 + 备注 |

---

## 28. A20-1 三轮定案复核（R-1 / R-2 / R-3 / R-4）

> 主代理的 7 处修复、v4 的两个新判据、红证对账，我逐条实测。
> **结论：7 处修复全部正确；v4 两个判据经真实注入验证都必要；红证对账的解释成立；
> 但我在全量扫描时又发现 3 处主代理未修的残留。**
> **未改任何工程代码。**

### 28.1 R-1：7 处修复 —— **全部正确，且区间边界精确**

我核对了「文档引用的数字 → `cur[n]` 的实际内容 → 是否与散文语义一致」：

| doc 行 | 文档现在写的 | `cur[n]` 实际内容 | 语义 | 判定 |
|---|---|---|---|---|
| 2473 | `:101-201` | `:101` = `Error Handshake(const uint8_t* in, size_t in_size, ...`；`:201` = `}` | Handshake 全体 | ✅ |
| 2473 | `:232`(S9) | `if (closed_) return MakeError(Status::kClosed, 0, "already closed");` | Receive 的守卫 | ✅ |
| 2814 | `t:101-201` | 同上 | 同上 | ✅ |
| 2814 | `t:230-345` | `:230` = `Error Receive(const uint8_t* ciphertext, size_t size,`；`:345` = `}` | Receive 全体 | ✅ |
| 2943 | `t:407` | `if (!have_ctx_) {` | `have_ctx_` 守卫 | ✅ |
| 2943 | `t:411-413` | `:411` = `SecBuffer token{0, SECBUFFER_TOKEN, nullptr};`；`:413` = `ApplyControlToken(&ctx_, &desc);` | 空 token + ctl 调用 | ✅ |
| 3075 | `:232`(S9) | 同 2473 | 同上 | ✅ |
| 3075 | `:101-201`(S10 D1) | 同 2473 | 同上 | ✅ |

**区间边界我特意验证了**（这是最容易「差一」的地方）：
```
:99  = ''                                                  <- 空行（旧的起点，错）
:101 = Error Handshake(...)                                <- 正确起点
:199 = return Fail(Status::kInternal, st);                 <- 旧的终点，错（不是函数尾）
:201 = }                                                   <- 正确终点（Handshake 收尾）
:228 = ''                                                  <- 空行（旧的起点，错）
:230 = Error Receive(...)                                  <- 正确起点
:343 = continue;                                           <- 旧的终点，错
:345 = }                                                   <- 正确终点（Receive 收尾）
```
**7 处（8 个引用）全部正确，区间首尾都精确落在函数边界上。**

#### 28.1.1 `doc:3075` 与 `doc:3822` 的矛盾已消除

- `doc:3075`（§18.2 批 2 表）：现在写 `:232`(S9)、`:101-201`(S10 D1)；
- `doc:3822`（§19.3.3 批 2 表）：用锚点 `if \(closed_\) return MakeError\(Status::kClosed`
  并注明「该文本在文件中命中 3 次，必须先定位 `Error Receive(...` 再取其后的第一处」。

**两者语义等价**：`doc:3822` 的锚点 + 定位规则唯一确定 `:232`，与 `doc:3075` 的行号一致。
**矛盾消除，我确认。**

### 28.2 R-2：v4 的两个新判据是否必要 —— **必要，我用真实注入验证**

#### 28.2.1 先做结构性论证（不依赖主代理的说法）

**判据 1（区间引用必须在起点行）**

| 引用 | naive「needle 在区间内」 | strict「needle 在起点行」 |
|---|---|---|
| 正确 `t:101-201` | True | **True** |
| 回退 `t:99-199` | **True**（`:101` 仍在 `[99,199]` 内） | **False** |

**naive 对两种输入都返回 True → 零区分力。** 实测输出：
```
CORRECT  t:101-201   naive_anywhere=True   strict_start=True
REVERTED t:99-199    naive_anywhere=True   strict_start=False
```
**判据 1 必要。**

**判据 2（多引用行必须钉住具体行号）**

`doc:3075` 一行有 **10 个引用**（我实测）：
```
['411', '411', '431-435', '232', '101-201', '184-187', '135-147', '489-507', '467-472', '879-885']
```
若判据是「这一行上**任一**引用能解析就算过」，那么当 `:232`(S9) 与 `:101-201`(S10) 都错、
但 `:411`(S24-a) 对时，naive 判据仍返回 True——**两个错的引用永远不会被检查**。
**判据 2 必要。**

#### 28.2.2 真实注入验证（不是模拟）

我在影子树里对**真实的 v4 脚本**做两次注入（`r2b_inject.py`）：

```
step 0  baseline                       -> exit=0   OK:21  MISMATCH:0

TEST A  doc:2814  `t:101-201` -> `t:99-199`
        -> exit=1   OK:20  MISMATCH:1
        doc:2814 tls need='Error Handshake(const uint8_t* in, size_t in'

TEST B  doc:3075  `:232`(S9) -> `:230`(S9)
        -> exit=1   OK:20  MISMATCH:1
        doc:3075 tls need='if (closed_) return MakeError(Status::kClose

restore                                -> exit=0   OK:21  MISMATCH:0
```

**TEST A 与 TEST B 都从 0 变 1，恢复后回 0。**
- TEST A 正是「区间回退但 needle 仍在区间内」的场景 → **判据 1 被真实触发**；
- TEST B 正是「多引用行里只有一个错」的场景 → **判据 2 被真实触发**。

**所以 v4 的两个修正不是理论上的洁癖，是真实可触发的必要判据。**

#### 28.2.3 我上一轮红证的覆盖范围（诚实标注）

主代理说我「只覆盖了单引用单行这一种形态」——**这是对的**。
我 §27 的红证只注入了 `doc:4002` 的 `:411`→`:409`（单引用、单行、且 needle 不在旧位置）。
它证明了「v3 不是重言式」，但**没有覆盖**：
- 区间引用（needle 落在区间内 → naive 判据失效）；
- 多引用行（一个错、一个对 → naive 判据失效）。

**这是红证覆盖不全，不是判据错误。** 我把 §27 的结论限定为
「**v3 对单引用单行有效**」，主代理的限定是准确的。

### 28.3 R-3：红证对账（14 处注入 → 13 条失败）—— **解释成立**

#### 28.3.1 `doc:2814` 确实有两个区间引用在同一行

我实测 `doc:2814` 的原文：
```
2. D1 只改 `Handshake`（`t:101-201`）与 `tls.h:129-132` 的注释，**不改 `Receive`**（`t:230-345`）；
```
正则提取：`[('101','201'), ('230','345')]` —— **2 个区间引用，同一行**。

**所以「两处修复、同属一行」成立**：注入这两个旧值（`t:99-199` 与 `t:228-343`）时，
v4 按「doc 行」为键组织失败记录，**同一 doc 行只产生 1 条失败记录**。
→ 14 处注入 − 1（`doc:2814` 的两个引用合并）= **13 条**。**解释成立。**

#### 28.3.2 但我无法从证据文件核实这组数字

```
verify_sec19.py       5896 B  11:57:39   (v4)
a201-second-review.md 7990 B  11:42:57   (早 15 分钟)
```
**md 比 v4 脚本早 15 分钟，所以 md 里记录的是 v3 的红证（`MISMATCH: 9`，8 处注入），
不是 v4 的「14 处注入 / 13 条失败」。** 我 grep `'v4'` → **False**。

**所以：13 这个数字我只能验证「合并机制成立」，无法验证「它确实是 13」**——
因为产生该数字的那次运行没有落档。**这是证据缺口（P3），建议补一份 v4 的红证输出到
`evidence/exec/`。**

### 28.4 我新发现的 3 处残留（主代理未修）

在验证 7 处修复时，我顺手扫了全文中「散文说 `Receive` 短路、引用却指向签名行」的模式，
**找到 3 处**：

| doc 行 | 原文 | `cur[230]`（引用指向） | `cur[232]`（正确） |
|---|---|---|---|
| **529** | 后续 `Receive` 会在 `:230` 直接返回 `kClosed`，那些 record 被永久丢弃。 | `Error Receive(const uint8_t* ciphertext, size_t size,`（签名行） | `if (closed_) return MakeError(Status::kClosed, ...)` |
| **724** | \| **S9** \| ... 会让后续 `Receive` 在入口直接返回 ... 与 `:230`（Receive 入口 `if (closed_) return kClosed`） | 同上 | 同上 |
| **1529** | `rx_buffer_` 里（`closed_` 在 `:230` 直接短路 `Receive`）。 | 同上 | 同上 |

**对照证据**：`doc:4030` 写的是同一件事，但已改对——
```
- 更糟的是 `closed_=true` 会让 `Receive` 在 `:232` 短路，...
```
**同一份文档里，同一句话有 3 处写 `:230`、1 处写 `:232`** —— 这是明确的漏改，不是叙述。

**定级 P2**（与主代理刚修的那批同级）：都在 §5（doc:529）、§6（doc:724）、§17（doc:1529），
**不在 §19**，所以不阻塞执行 AI；但会让审计者困惑。

**我建议把这 3 处一并改掉，A20-1 才算真正全文一致。**

### 28.5 R-4：最终判定

**A20-1 已闭环（§19 + §15/§17/§18 的 7 处已修），但全文仍有 3 处 P2 残留（§5/§6/§17）。**

| 项 | 判定 |
|---|---|
| **§19 执行交接包** | ✅ **完全一致**（v4 实测 21 引用 / 0 MISMATCH / exit=0；且 v4 经我两次真实注入验证有区分力） |
| **§15/§17/§18 的 7 处** | ✅ **已修且正确**（含区间首尾精确性） |
| **§5/§6/§17 的 3 处 `:230`** | ❌ **残留（P2）**，doc:529 / doc:724 / doc:1529 |
| **批 1/批 2 开工** | ✅ **可以**（`doc:3207` 隔离条款保证执行 AI 不读 §0–§18） |

**理由**：主代理修了乙报的 7 处（我全部核实正确），v4 的判据也经真实注入证明必要。
但「A20-1 = 全文行号一致」这个全称命题**仍未成立**——我用「散文语义 vs 引用目标」的
对照发现了 3 处同类漏改，它们与刚修的那批**病根相同**（都是 S9 的 `:230`→`:232`）。

**这 3 处不阻塞批 1/批 2**（不在 §19），所以我判 **A20-1 在「执行可开工」的意义上闭环，
在「全文一致」的意义上仍有 P2**。

### 28.6 我这轮的方法改进与残留盲区

| 项 | 状态 |
|---|---|
| 用「真实注入验证判据」而非「读代码推断」 | ✅ 本轮做到（TEST A/B 都是真实注入） |
| 承认红证覆盖不全（只测了单引用单行） | ✅ 已标注 |
| **仍存在的盲区** | 我扫「散文语义 vs 引用目标」时用的是**手工挑出的模式**（`Receive` 短路 / `consumed` / token / shutdown 判定），**不是全构造覆盖**。所以「只找到 3 处」不等于「只有 3 处」。 |

**建议**：把 `verify_sec19.py` 的 `EXPECT` 表扩展到**全文所有引用**（不只 §19 与已知的 7 处），
并用「散文里的构造名」自动匹配。这样才是真正的全称验证。
**在我做到那一步之前，「A20-1 全文闭环」这句话我不能盖章。**

---

## 29. 全文引用扫描（补齐 §28.6 的盲区）

> §28.6 我承认「只找到 3 处」是**手工挑模式**的结果，不等于全部。
> 本节用**可复跑的脚本**（`F:\rtsc\.tmp\sec19_stale.py` + `verify_doc_citations.py`）做全量扫描，
> 结论比 §28.4 更完整，也更准确。**未改任何工程代码。**

### 29.1 扫描口径（先说清，否则数字无意义）

三类引用形态全部覆盖（这是 §26 的教训——只扫一种会漏 52%）：

| 形态 | 正则 | 命中数（全文） |
|---|---|---|
| 带文件名 `tls_schannel.cpp:NNN` | `(?P<base>[A-Za-z_0-9]+\.(cpp\|h)):(\d+)` | 265 |
| 简写 `t:NNN` | `(?<![A-Za-z0-9_.])t:(\d+)` | 62 |
| 裸 `` `:NNN` `` | `` `:(\d+)` `` | 570 |
| **合计** | | **897** |

判定「残留」的标准（**必须同时满足**，这是可证伪的）：
1. 引用号属于**批 0 前的旧值**集合 `{230,167,409,429,430,433,405,242,178,228,99,199,343}`；
2. 该行**不是**在叙述历史（不含 `批 0 前`/`旧行号`/`原引用`/`回退`/`注入`/`bak:` 等标记）；
3. 引用号对应的**正确新值**在源码里确实存在且内容不同。

### 29.2 最关键的结果：**§19 执行交接包零残留**

`§19` = `doc:3205-4213`（执行 AI 唯一必读区间，`doc:3207` 隔离条款）。

**在 §19 范围内，只有 1 处引用旧行号：**

| doc 行 | 原文 | 判定 |
|---|---|---|
| **3810** | > 使 `:232` 之后的**所有行号 +2**。按旧行号操作会改错行——实测旧 `:429` 现在指向 `FreeContextBuffer(out_buf.pvBuffer);` | ✅ **正确**，这是**故意**写「旧 `:429`」来警告执行 AI |

`cur[429] = FreeContextBuffer(out_buf.pvBuffer);` —— **文档描述与源码完全一致**。
紧随其后的 `doc:3812` 明确写「**因此下表一律用锚点文本 + `Select-String` 定位，不再给行号**」。

**§15.1 修复表（`doc:1781-1810`）同样零残留。**

**所以：批 1 / 批 2 的执行安全性成立，且证据比我 §28 给的更强**——
不是「§19 恰好没错」，而是「§19 已经系统性改为锚点定位，唯一的行号是警告」。

### 29.3 真正的残留（全部在 §15 / §18，不在 §19）

| # | doc 行 | 原文引用 | 正确值 | `cur[引用]` | `cur[正确]` | 节 | 定级 |
|---|---|---|---|---|---|---|---|
| R-a | **529** | `:230` | `:232` | `Error Receive(const uint8_t* ciphertext, size_t size,` | `if (closed_) return MakeError(Status::kClosed, ...)` | §5.4 | P2 |
| R-b | **724** | `:230` | `:232` | 同上 | 同上 | §6 缺陷表 | P2 |
| R-c | **1529** | `:230` | `:232` | 同上 | 同上 | §13.3.3 | P2 |
| R-d | **725** | `:167` | `:169` | `// not report EXTRA, and leaving bytes unconsumed would make the caller` | `consumed = in_size;` | §6 缺陷表 | **P1** |
| R-e | **3128** | `:167` | `:169` | 同上 | 同上 | **§18.3.1 变异表** | **P1** |

#### 29.3.1 R-d / R-e 为什么是 P1 而不是 P2（升级理由）

§18.3.1 是**批 2 的逐条变异表**，执行 AI 会**照抄它构造红证**。它现在写：

```
| **S10** | `:167` 恢复 `consumed = in_size` 且不吸收尾部 | ... |
```

而 `cur[167]` 是**注释**，`cur[169]` 才是 `consumed = in_size;`。

**执行 AI 按 `:167` 去改，会改到注释行**——变异不成立，红证永远不红，
于是「S10 已修复」会以**假绿**通过。**这正是 A20-1 在 §19 上被修掉的同一类事故，只是漏在了 §18.3.1。**

**对照**：`doc:3123`（同表 S9 行）写的是 `:232`，**是正确的**。
**同一张表里 S9 对、S10 错**，这是漏改，不是叙述。

**升级为 P1 的理由**：它是变异表（可执行输入），不是散文（可读文本）。
按 §26.1.3 我对 `doc:3075` 的同一判据（「会让执行 AI 改错位置」），这里必须同级。

#### 29.3.2 R-a/R-b/R-c 保持 P2

三处都在 §5/§6/§13，**执行 AI 按 `doc:3207` 不读**；且 §6 缺陷表与 §5.4 的散文语义清楚
（「`Receive` 在入口短路」），执行 AI 不会拿它当行号指令。**维持 P2。**

### 29.4 我 §28 漏掉 R-d/R-e 的原因（诚实归因）

§28 我用的模式是「散文说 `Receive` 短路 + 引用指向签名行」，
**它只覆盖 `closed_` 一个构造**。`consumed = in_size`（S10）不在这个模式里，
所以 `:167` 被我漏了。

**根因与 §26 相同**：我每次只换一个模式去扫，扫到几个就报几个，
**没有一次性把「所有发生过偏移的构造」列成表再扫**。
本节用的 `STALE = {230:232, 167:169, ...}` 才是正确做法——**先枚举构造，再扫引用**。

### 29.5 修正后的最终判定

| 项 | 判定 |
|---|---|
| §19 执行交接包 | ✅ **零残留**（唯一旧行号 `doc:3810` 是故意警告，且描述准确） |
| §15.1 修复表 | ✅ **零残留** |
| **§18.3.1 变异表** | ❌ **1 处 P1**：`doc:3128` 的 `:167` → 应为 `:169` |
| §6 缺陷表 | ❌ **1 处 P1**：`doc:725` 的 `:167` → 应为 `:169` |
| §5.4 / §13.3.3 | ❌ **2 处 P2**：`doc:529`、`doc:1529` 的 `:230` → 应为 `:232` |
| §6 缺陷表（S9 行） | ❌ **1 处 P2**：`doc:724` 的 `:230` → 应为 `:232` |
| 批 1 / 批 2 开工 | ✅ **可以**（§19 零残留；但**建议先修 R-d/R-e**，否则批 2 的 S10 红证会是假绿） |

**这与我 §28 的判定有两处差异，都必须订正：**
1. §28 说「3 处残留」，**实际是 5 处**（漏了 2 处 `:167`）；
2. §28 说「3 处全是 P2」，**实际有 2 处是 P1**（在变异表与缺陷表里，是执行输入）。

**§28.5 的「A20-1 在『执行可开工』意义上闭环」这句话仍然成立**（§19 确实零残留），
但**批 2 的 S10 红证有假绿风险**，这一条 §28 没看出来。

### 29.6 复跑方式

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'; $env:PYTHONIOENCODING='utf-8'
python F:\rtsc\.tmp\sec19_stale.py      # §19 + §15.1 范围扫描
python F:\rtsc\.tmp\verify_doc_citations.py   # 全文 897 条引用 + 锚点一致性
```

`sec19_stale.py` 的输出应为：`count in §19: 1`（即 `doc:3810`，且是叙述）。
若该数字变大，说明 §19 又混入了旧行号。

---

## 30. A20-1 四轮定案复核

> 复验主代理修的 5 处 + `:236`、v5 验证器、动态章节边界。
> **R-1 通过。R-2 通过（我自己构造红证）。R-3 部分成立，父代理的表述不准确。
> R-4：不通过 —— 我在 §19 里发现一处「判据声明指向已损坏脚本」的 P1。**
> **未改任何工程代码。**

### 30.1 R-1：6 处修复 —— **全部正确**

逐条核对「文档里的号 → `cur[n]` 实际内容 → 散文语义」：

| doc | 引用 | `cur[n]` 实际内容 | 散文语义 | 判定 |
|---|---|---|---|---|
| 725 | `:169` | `consumed = in_size;` | 「直接 `consumed = in_size`」 | ✅ |
| 3128 | `:169` | `consumed = in_size;` | 「恢复 `consumed = in_size`」 | ✅ |
| 529 | `:232` | `if (closed_) return MakeError(Status::kClosed, ...)` | 「`Receive` 在 `:232` 直接返回 `kClosed`」 | ✅ |
| 724 | `:232` | 同上 | 「Receive 入口 `if (closed_) return kClosed`」 | ✅ |
| 1529 | `:232` | 同上 | 「`closed_` 在 `:232` 直接短路 `Receive`」 | ✅ |
| 724 | `:236` | `rx_buffer_.insert(rx_buffer_.end(), ciphertext, ...)` | 「`rx_buffer_` 的入队/消费在 `:236`」 | ✅ |

**`:236` 这条我特别验了**：`cur:235` 是 `if (size != 0 && ciphertext != nullptr) {`，`:236` 才是 `rx_buffer_.insert(...)`。
主代理把上轮的 `:235` 改成 `:236` **是对的**——散文说的是「入队」，而 `:235` 只是守卫条件。

**§29 报的 5 处 + `:236` 全部闭环。R-1 通过。**

### 30.2 R-2：v5 验证器有区分力 —— **通过（我自己构造红证，不采信主代理输出）**

#### 30.2.1 基线

```
verify_citations.py  ->  checks passed : 32   checks FAILED : 0   exit=0
```

#### 30.2.2 红证 A：改文档（3 次独立注入，影子树，哈希校验后使用）

| 注入 | 结果 |
|---|---|
| `doc:3128` `:169`→`:167` | **exit=1**，passed 31 / FAILED 1（`[§18] anchor not found`） |
| `doc:725` `:169`→`:167` | **exit=1**，passed 30 / FAILED 2 |
| `doc:529` `:232`→`:230` | **exit=1**，passed 29 / FAILED 3 |
| 从原始文件恢复 | **exit=0**，32/0，且恢复后 SHA256 与原文件一致 |

**0→1→0 成立。**

#### 30.2.3 红证 B：只改源码（这才是「语义判据」的真红证）

红证 A 暴露一个问题：失败原因是 `anchor not found`，**而 anchor 文本里内嵌了 `:169` 本身**。
也就是说 A 证明的是「anchor 匹配」有区分力，**没有单独证明「构造检查」有区分力**。

所以我做了 B：**文档一个字节不动**，只把影子源码的 `:169` 改成 `consumed = in_size_other;`：

```
--- RED source:169 -> exit=1 ---
  checks passed : 30   checks FAILED : 2
  [§6]  doc:725  cites :169 -> 'consumed = in_size_other;   // SEMANTIC RED'
  [§18] doc:3128 cites :169 -> 'consumed = in_size_other;   // SEMANTIC RED'
--- restored -> exit=0, 32/0 ---
```

**文档未改，只有源码变了，验证器仍然报错 → 构造检查独立生效。**
这是「语义判据」的真正证明，A 只证明了锚点定位。

**R-2 通过，且我补上了主代理没做的那一半。**

#### 30.2.4 但 v5 的覆盖范围与它的声明不匹配（见 30.4）

v5 只检查 **32 条**，而文档里有 **742 条** `tls_schannel` 引用（**4.3%**）。
按节分布：§19=14、§18=11、§17=3、§6=2、§5=1、§13=1。**§0–§4、§7–§12、§14–§16、§20–§29 全未覆盖。**

### 30.3 R-3：动态章节边界 —— **部分成立，主代理的表述不准确**

主代理的说法：「在 `doc:3207` 插入 5 行 → 硬编码边界的验证器会失效」。

#### 30.3.1 我按他说的做，**没有失效**

| 变体 | 未改动 | `doc:3207` 前插入 5 行 |
|---|---|---|
| 动态（`## N.` 现算） | exit=0 | **exit=0** |
| 硬编码（冻结成字面量） | exit=0 | **exit=0** |

**两者都通过 → 「插入 5 行会让硬编码失效」这个具体断言是错的。**

#### 30.3.2 但硬编码**确实**脆弱，只是触发条件不同

我测了全部 32 个锚点到各自章节末尾的距离，**最小是 12 行**（`doc:724` 在 §6，§6 止于 737）。

**最小反例**：在 §6 里 `doc:724` 之前插入 **14 行**（一个普通段落）：

```
dynamic   +14 lines in §6  -> exit=0  passed=32 failed=0
hardcoded +14 lines in §6  -> exit=1  passed=30 failed=2
```

**正确的表述应该是**：「当某个被检查的锚点**跨过**其冻结的章节边界时，硬编码会失效」，
而不是「插入 5 行就失效」。§19 的锚点离 §19 末尾都很远（最小 90 行），所以插 5 行不会跨。

#### 30.3.3 结论：动态边界**确实更优，但理由要改**

| 断言 | 判定 |
|---|---|
| 「插入 5 行 → 硬编码失效」 | ❌ **不成立**（我实测两者都过） |
| 「锚点跨过冻结边界 → 硬编码失效」 | ✅ **成立**（14 行反例） |
| 「动态边界更健壮」 | ✅ 成立，但**是防御性改进，不是 5 行场景的必需品** |

**这是 P3 级的表述不准确，不影响正确性**——动态计算本身是对的，我不会要求改回去。

### 30.4 R-4：最终判定 —— **不通过，发现 1 处 P1**

#### 30.4.1 P1：`doc:3211` 的判据声明指向**已损坏的脚本**

`doc:3211` 现在写：

```
> **判据（已由 `evidence/exec/verify_sec19.py` 逐条验证，21 项）：**
```

**但 `verify_sec19.py` 现在跑出来是：**

```
=== section 19 handoff package: semantic citation check ===
citations verified OK : 15
citations MISMATCH    : 16

  doc:3421  tls  no citation on this doc line
  doc:3779  credssp  no citation on this doc line
  ... (共 16 条)
exit=1
```

**三要素**：
1. **doc 行号**：`doc:3211`（§19 开头，执行 AI 必读的第一屏）；
2. **实际内容**：`verify_sec19.py` 的 exit=1、MISMATCH=16；`doc:3421` 现在**是空行**（原来那里有 include 引用）；
3. **散文语义**：`doc:3211` 声称「已由该脚本逐条验证，21 项」，而 `doc:3213` 更进一步说
   「本章内**所有** `tls_schannel.cpp:NNN` / `t:NNN` / `:NNN` 行号引用都指向当前源码的正确构造，
   且经红证证明该判据有区分力。**因此照本章的行号动手是安全的，无需另行核对。**」

**为什么是 P1 而不是 P2**：这是**执行 AI 读到的第一条判据**，而且它自己说「无需另行核对」。
执行 AI 若照做（跑 `verify_sec19.py`），会看到 **16 条 MISMATCH、exit=1**，从而：
- 要么误判「§19 有 16 处错误」（假红，浪费时间）；
- 要么认为「判据脚本坏了，那我自己判断吧」（**放弃门禁**，最危险）。

**这与 A20-1 在 §18.3.1 上的 P1 是同一类**：声明与事实不符，且位于执行路径上。

#### 30.4.2 正确的内容已经在文档里，只是没接上

父代理这轮**确实改好了 `doc:3207`**（我核了：现在是「本章的执行信息是自包含的」+ 「括号里的 §编号是可选的背景追溯」+ 判据措辞）。**这段措辞是对的。**

**但 `doc:3211` 的脚本名和数字没同步更新**：仍写 `verify_sec19.py` / 21 项，
而实际可用的是 `verify_citations.py` / 32 项。

**修法（一处）**：把 `doc:3211` 的
`evidence/exec/verify_sec19.py` → `evidence/exec/verify_citations.py`，`21 项` → `32 项`。

**并且**，因为 v5 只覆盖 32/742 条，`doc:3213` 的「本章内**所有**…都指向正确构造」
**这句话超出了 v5 的实际能力**。建议改为：

> 本章内**已纳入 `verify_citations.py` 的 32 条**引用都指向当前源码的正确构造，
> 且经红证证明该判据有区分力。**未纳入的引用请按锚点文本核对。**

#### 30.4.3 其余判定

| 项 | 判定 |
|---|---|
| R-1：5 处 + `:236` | ✅ **通过** |
| R-2：v5 有区分力 | ✅ **通过**（含我补的源码侧红证） |
| R-3：动态边界 | ⚠️ **成立但理由错**（P3，5 行不失效，14 行才失效） |
| **R-4：A20-1 全文闭环** | ❌ **不通过**：`doc:3211` 判据声明指向已损坏脚本（P1） |

**A20-1 的「行号正确性」这一层已经闭环**（§19 零残留、§15.1 零残留、我 §29 报的 5 处全修）。
**不闭环的是「判据自述」这一层**——文档说它被 21 项验证过，实际那个脚本已经坏了。

**修掉 30.4.2 那一处（脚本名 + 数字 + 限定「已纳入的 32 条」）之后，我就给全文闭环结论。**

### 30.5 我这轮的验证清单（可复跑）

| 脚本 | 作用 | 期望 |
|---|---|---|
| `F:\rtsc\.tmp\r4_summary.py` | R-1 六处 + 两个验证器的退出码 | 六处 OK；`verify_citations` exit=0；`verify_sec19` exit=1 |
| `F:\rtsc\.tmp\r4_redtest.py` | R-2 红证 A（改文档 3 次） | baseline 0 → 三次 exit=1 → 恢复 0 |
| `F:\rtsc\.tmp\r4b_semantic.py` | R-2 红证 B（只改源码） | 0 → 1 → 0，且文档字节不变 |
| `F:\rtsc\.tmp\r4d_bounds2.py` | R-3（5 行 / 跨边界） | 5 行两者都过；跨边界硬编码失败 |
| `F:\rtsc\.tmp\r4e_minimal.py` | R-3 最小反例 | 14 行：动态 0 / 硬编码 1 |

**所有影子副本均先做 SHA256 校验再使用**（§22.2.4 的 NEUTERED 事故教训）。

---

## 31. A20-1 六轮定案复核

> 复验乙的 7 处、锚点门禁、三个红证的覆盖。
> **R-1 通过。R-2 门禁的红证成立，但我找到它的两个结构性盲区，并用红证证明。
> R-3 有环节无红证。R-4：不通过 —— 2 处 P1 存活，五项门禁全部放行。**
> **未改任何工程代码。**

### 31.1 R-1：乙的 7 处 —— **全部通过，用备份独立确证**

我不看 `cur` 单独判断，而是做「`bak[n]` 有 + `cur[n]` 无 + `cur[n+2]` 有 = 机械 +2」的三方比对：

| doc | 引用 | `cur[n]` 内容 | `bak[n-2]` 内容 | 判定 |
|---|---|---|---|---|
| 725 | `:126` | `in_bufs[0].cbBuffer = static_cast<unsigned long>(token.size());` | 同（bak:124） | ✅ |
| 1795 | `:53` | `constexpr uint8_t kRecordAlert = 21;` | 同（bak:51） | ✅ |
| 1797 | `:432` | `closed_ = true;` | 同（bak:430） | ✅ |
| 2050 | `:371` | `Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {` | 同（bak:369） | ✅ |
| 2083 | `:432` | `closed_ = true;` | 同（bak:430） | ✅ |
| 2876 | `:432` | `closed_ = true;` | 同（bak:430） | ✅ |
| 2877 | `:406` | `if (shutdown_sent_) return MakeError(Status::kOk, 0, "");` | 同（bak:404） | ✅ |

**全量普查佐证**（每个构造在 bak/cur 的完整位置，全部 +2）：
```
PeerSubjectPublicKey   bak=[346, 369]   cur=[348, 371]
kRecordAlert           bak=[51, 71]     cur=[53, 73]
closed_ = true;        bak=[302, 430]   cur=[304, 432]
shutdown_sent_         bak=[404, 406, 423, 718]  cur=[406, 408, 425, 720]
```
**7 处全部正确，乙的确证方法（机械位移）我独立复现通过。**

### 31.2 R-2：锚点门禁 —— 红证成立，但有两个结构性盲区

#### 31.2.1 基线与红证（我自己做的，哈希校验后使用影子副本）

| 实验 | 结果 |
|---|---|
| baseline | `54 citations / 0 缺锚点` exit=0 |
| **剥掉 `doc:2876` 的真实锚点** | `WITHOUT an anchor: 1` **exit=1** ✅ |
| **植入不存在的伪锚点** `this_text_is_nowhere_in_the_source_xyz` | `WITHOUT an anchor: 1` **exit=1** ✅ |

**主代理说的「剥锚点会被抓」「伪锚点会被抓」，这两条我都复现了，成立。**

#### 31.2.2 盲区一：锚点存在于源码，但**不在被引用的那一行** → 门禁放行

这是父代理点名问的问题，**答案是：真实缺陷，不是理论洁癖。** 我实测：

```
STEP 3: 把 doc:2876 的锚点换成 `return Fail(Status::kProtocolError, st);`
        （这段文本在源码里确实存在，但不在 :432 —— :432 是 closed_ = true;）
        -> WITHOUT an anchor: 0    exit=0    BLIND
```

**原因**：`verify_anchors.py:73` 的判据是
```python
if all(any(p in s for s in flat) for p in parts)
```
`flat` 是**整个文件的每一行**。所以只要锚点文本在**文件任意位置**出现，就算通过——
它根本没有检查「锚点在不在被引用的那一行」。

**这不是设计取舍，是判据缺了半句。** 正确判据应是「锚点必须出现在 `cur[cited]` 所在的行/区间内」。

#### 31.2.3 盲区二：门禁对裸 `` `:NNN` `` 形式**完全不可见**

`verify_anchors.py:32` 的正则：
```python
CITE = re.compile(r'`(?:src/net/)?(?:tls_schannel\.cpp|t):(\d+)(?:-(\d+))?`')
```

**它只匹配 `tls_schannel.cpp:NNN` 和 `t:NNN`，不匹配裸 `` `:NNN` ``。** 我实测：

```
7 个目标节内：门禁可见 70 条，裸 `:NNN` 226 条
=> 锚点门禁只覆盖 24% 的引用形式
```

**这与 §26 我批评乙「只扫一种形式漏 52%」是同一个错误**，只是这次犯在门禁上。

#### 31.2.4 盲区三：白名单静默跳过 16 条

`verify_anchors.py:35` 的 `WHITELIST_MARKERS` 含 `'批 0 后'`。**7 个节里 10 行、16 条引用**因为含这个词被整行跳过：

```
[§15] doc:1797  cites=2  marker='批 0 后'
[§15] doc:1798  cites=2  marker='批 0 后'
[§15] doc:2050  cites=2  marker='批 0 后'
[§17] doc:2083  cites=3  marker='批 0 后'
[§17] doc:2443  cites=1  marker='批 0 后'
[§17] doc:2761  cites=2  marker='批 0 后'   <-- 这两条正是下面要报的 P1
[§17] doc:2830  cites=1  marker='批 0 后'
[§18] doc:2887  cites=1  marker='批 0 后'
[§18] doc:2944  cites=1  marker='批 0 后'
[§18] doc:3075  cites=1  marker='批 0 后'
```

**白名单的初衷是「批 0 后」这个短语表示行号已更新，不必再查。**
但 `doc:2761` 恰好证明了相反：**它写着「批 0 后」，引用却是旧的。**

### 31.3 R-3：三个红证 —— **有两个环节没有任何红证**

| 判据环节 | 有红证吗 | 证据 |
|---|---|---|
| 文档行号写错 → `verify_citations` 报错 | ✅ | `citations_redtest.py`：RED 16/23 → GREEN 39/0 |
| 源码被改 → `verify_citations` 报错 | ✅ | `semantic_redtest.py`：RED 37/2 → GREEN 39/0 |
| 锚点被剥掉 → `verify_anchors` 报错 | ✅ | `anchors_redtest.py`：RED 1 → GREEN 0 |
| **锚点存在但错位 → 门禁报错** | ❌ **无** | 我 §31.2.2 实测：**exit=0，放行** |
| **裸 `:NNN` 被写错 → 任何门禁报错** | ❌ **无** | 我 §31.2.3 实测：门禁正则看不见 |
| **白名单行内的引用写错 → 任何门禁报错** | ❌ **无** | 我 §31.2.4 实测：整行跳过 |

**父代理说「红证从 2 个补到 3 个（判据的每一部分都要有红证）」——这个方向对，但没补完。**
三个红证覆盖的是「锚点存在性」「文档号与源码的语义对应」，**没有覆盖「锚点的定位性」**。
而后者恰恰是本轮 7 处残留里 6 处无锚点的根因所要解决的东西。

### 31.4 R-4：**不通过** —— 2 处 P1 存活，五项门禁全部放行

#### 31.4.1 P1-a：`doc:2761` 的 `t:291` 是旧值，应为 `:293`

**三要素**：
1. **doc 行号**：`doc:2761`（§17 缺陷表 S24 行）；
2. **实际内容**：`cur[291]` = `continue;`（TLS 1.3 NewSessionTicket 分支里的 `continue`），
   `cur[293]` = `return Fail(Status::kProtocolError, st);`；`bak[291]` = `return Fail(...)`；
3. **散文语义**：「RDP 场景禁止重协商（`t:291`、`:317` 都把它判为 `kProtocolError`）」
   —— 说的是「判为 kProtocolError」，而 `cur[291]` 是 `continue;`，**判为 kProtocolError 的是 `:293`**。

**这是标准的 +2 机械位移**：`bak[291]` 有构造、`cur[291]` 没有、`cur[293]` 有。
**与乙报的 7 处同一病根，只是漏了。**

#### 31.4.2 P1-b：`doc:2761` 的 `:317` 是旧值，应为 `:319`

同一句话里的第二个引用：

| | 内容 |
|---|---|
| `cur[317]` | `// post-handshake auth request). Not supported: treat as a`（**注释**） |
| `cur[319]` | `return Fail(Status::kProtocolError, st);` |
| `bak[317]` | `return Fail(Status::kProtocolError, st);` |

**散文说「`:317` 判为 kProtocolError」，但 `cur[317]` 是注释。** 同样 +2。

**同一行两个引用同时漏，说明修复时是按「乙报的清单」逐条改，没有对该行做整体复核。**

#### 31.4.3 为什么五项门禁全部放行（这是本轮最重要的结论）

| 门禁 | 为什么没抓到 |
|---|---|
| `verify_citations.py`（39 项） | `doc:2761` 不在 `CHECKS` 里（只 pin 了 39 条） |
| `verify_anchors.py`（54 条） | **`doc:2761` 整行被 `'批 0 后'` 白名单跳过**；且 `:317` 是裸形式，正则看不见 |
| `citations_redtest.py` | 只注入「已知的 25 个旧值」，不含 291/317 |
| `semantic_redtest.py` | 只扰动 `cur:169` 一处 |
| `anchors_redtest.py` | 只剥 `doc:2876` 一个锚点 |

**「5 项门禁全绿」与「有 2 处 P1」可以同时成立。**
这正是乙那句话的严格版本：**门禁绿 ≠ 全文无过期引用**——而且现在有了一个可复现的实例。

#### 31.4.4 附：我核了但**判定不是缺陷**的 4 处（避免误报）

| doc | 引用 | 为什么不是缺陷 |
|---|---|---|
| 3111 | `:208` | 上一行 `doc:3110` 写的是 `tests/test_tls.cpp:114`，`lb.server()` 在 `test_tls.cpp:208` —— **跨文件续引** |
| 3899 | `:168` | 整行（`doc:3077`）引的是 `connect_machine.cpp:165-168`；`cm[168]` = `pdu.info.password = credentials_.password;` —— **跨文件** |
| 2049 | `:317` | 引的是 `rtsc_credssp_sm_tests` 的 5 个用例；`test_credssp_sm.cpp:317` = `RTSC_TEST(step5_rejects_wrong_server_echo)` —— **跨文件** |
| 3390 | `:733-754` | 明确标为「现状」，紧跟的代码块逐行注 `// 733:` … `// 754:`，**与 `bak[733..754]` 完全一致** —— 批前快照 |

**这 4 处暴露了门禁的另一个盲区：裸 `:NNN` 无法判断属于哪个文件。**
`verify_anchors.py` 把**所有**裸引用都当成 `tls_schannel.cpp`，所以对跨文件引用必然误判或漏判。

### 31.5 我建议的最小修复（3 条）

| # | 位置 | 改成 |
|---|---|---|
| 1 | `doc:2761` `t:291` | `t:293` |
| 2 | `doc:2761` `:317` | `:319` |
| 3 | `verify_anchors.py:73` | 判据从「锚点在文件任意行」改为「锚点在 `cur[cited_a..cited_b]` 内」 |

**第 3 条是根因**：不修它，下一个「有锚点但错位」的引用照样能通过门禁。
另外建议把 `'批 0 后'` 从白名单移除——它已经被 `doc:2761` 证明会掩盖真实缺陷。

### 31.6 判定

| 项 | 判定 |
|---|---|
| R-1：乙的 7 处 | ✅ **通过**（备份三方比对） |
| R-2：锚点门禁 | ⚠️ **红证成立，但判据有 3 个盲区**（错位放行 / 裸形式不可见 / 白名单掩盖） |
| R-3：三个红证 | ❌ **不完整**：「锚点定位性」「裸形式」「白名单行」三个环节无红证 |
| **R-4：A20-1 闭环** | ❌ **不通过**：`doc:2761` 的 `:291`/`:317` 两处 P1，五项门禁全部放行 |

**A20-1 仍未闭环。** 这轮的价值不在于又找到 2 处，而在于**证明了「门禁全绿」不能作为闭环依据**：
- `doc:2761` 同时踩中「白名单跳过」和「裸形式不可见」两个盲区；
- 即使补上锚点，`verify_anchors.py` 的「锚点在文件任意处即通过」仍会放行错位锚点。

**修复这 3 条 + 为「锚点错位」补一个红证之后，才谈得上闭环。**

---

## 32. A20-1 七轮定案复核

> 复验 `doc:2761` 两处、v8 对应性判据、白名单。
> **R-1 通过。R-2 判据仍有 1 个真实盲区（弱锚点），我用红证证明。R-3 白名单不再掩盖行号，
> 但暴露了一个更大的缺口：行数基线声明。R-4：不通过 —— 15 处旧行号存活，全部门禁放行。**
> **未改任何工程代码。**

### 32.1 R-1：`doc:2761` 两处 —— **通过**

| 引用 | `cur[n]` 实际内容 | 判定 |
|---|---|---|
| `t:293` | `return Fail(Status::kProtocolError, st);` | ✅ |
| `:319` | `return Fail(Status::kProtocolError, st);` | ✅ |

散文「`t:293`、`:319` 都把它判为 `kProtocolError`」与源码一致。**通过。**

### 32.2 R-2：v8 的对应性判据 —— **核心修好了，但仍有一个真实盲区**

#### 32.2.1 v8 修对了什么（我复现了）

| 探针（我自己造的） | 结果 |
|---|---|
| 锚点 = `cur[431]`（被引 `:432` 的**上一行**） | **exit=1，WRONGLINE=1** ✅ |
| 锚点 = `cur[433]`（被引 `:432` 的**下一行**） | **exit=1，WRONGLINE=1** ✅ |
| 区间 `101-201`，锚点取 `cur[154]`（**区间内非首行**） | exit=0 ✅ **正确**（区间语义：锚点在区间内即可） |
| 区间 `101-149`，锚点仍取 `cur[154]`（**区间外**） | **exit=1，WRONGLINE=3** ✅ |
| 陈旧 `t:291` + 锚点 `return Fail(Status::kProtocolError, st);`（该文本在 `:293`） | **exit=1，WRONGLINE=1** ✅ |
| 陈旧 `t:291` + 锚点 `kProtocolError` | **exit=1，WRONGLINE=1** ✅ |

**「锚点必须落在被引行/区间内」这一条真的生效了。** 你问的三种情形我都测了，v8 全部正确。

#### 32.2.2 但「弱锚点」能通过，这是真盲区

`locates()` 只问「锚点文本**在不在**这段区间里」，**不问「这段区间里有没有别的地方也匹配」**。
所以当锚点文本在**多行**出现、且被引行恰好在其中时，门禁放行——但它无法区分这些行。

当前有 **3 处这样的弱锚点**：

| doc | 引用 | 锚点 | 命中行 |
|---|---|---|---|
| 1797 | `:232` | `if (closed_) return MakeError(Status::kClosed` | **[106, 209, 232]** |
| 2443 | `:232` | 同上 | **[106, 209, 232]** |
| 2876 | `:432` | `closed_ = true;` | **[304, 432]** |

**我用红证证明它可以掩盖真实陈旧引用**（锚点一字不改，只改引用号）：

```
baseline                                     exit=0 WRONGLINE=0
doc:2876  :432 -> :304  (anchor untouched)   exit=0 WRONGLINE=0   BLIND
doc:1797  :232 -> :106  (anchor untouched)   exit=0 WRONGLINE=0   BLIND
```

**`:304` 和 `:432` 都是 `closed_ = true;`，`:106` 和 `:232` 都是 `closed_` 守卫。**
引用号写错，锚点照样"定位"，门禁照样绿。

**这是 v8 的最后一个判据盲区。** 修法：`locates()` 应额外要求「该锚点在 `src` 中的命中行集合 ⊆ 被引区间」，或至少要求「命中行数 == 1 或全部落在区间内」。

#### 32.2.3 我另外核了 `resolve_file`（裸引用的文件归属）

`doc:2761` 的 `t:293` 前面有 `tls.h:178-180`，`resolve_file()` 会取「同一行中引用位置之前**最后出现**的文件名」→ 会把裸 `:293` 归给 `tls.h`（只有 208 行）。
**我实测**：给 `doc:2761` 植入裸 `:293` + `tls_schannel` 的锚点 → **exit=1，WRONGLINE=1**（被正确抓到）。
说明 `resolve_file` 归错文件后，`locates()` 在 `tls.h` 里找不到锚点 → 报错。
**这是「错得安全」**（假阳性方向），但**会产生噪声**：真实正确的裸引用若前面恰好有别的文件名，会被误报。

### 32.3 R-3：白名单 —— **不再掩盖行号，但暴露了更大的缺口**

#### 32.3.1 白名单本身干净了

现在只剩 3 个标记（`行号基线` / `现在指向` / `旧行号`），全文只有 **6 行**命中：

| doc | 内容 | 判定 |
|---|---|---|
| 1766 | 「本章所有行号均为本轮重新读取」 | 纯叙述，无引用号 |
| 1768 | 「…故不沿用旧行号」 | 纯叙述 |
| 2073 | 「行号基线：…（`audit-a.md` 已 2052 行；」 | 纯叙述 |
| 2840 | 「行号基线：…`tls_schannel.cpp` 754 行、`tls.h` 208 行」 | **含行数声明** |
| 3229 | 「行号基线：`CMakeLists.txt` 193 行、…754 行」 | **含行数声明** |
| 3820 | 「旧 `:429` 现在指向 `FreeContextBuffer`」 | **故意**，且描述正确 |

**我逐条核实：这 6 行里没有藏着写错的引用行号。** `doc:3820` 的 `:232` 与 `:429` 都正确。

#### 32.3.2 但「行数基线」全错了 —— 门禁完全看不见

我实测当前真实行数：

| 文件 | 文档声称 | 实际 | |
|---|---|---|---|
| `tls_schannel.cpp` | **754** | **748** | ❌ |
| `tls.h` | 208 | 208 | ✅ |
| `CMakeLists.txt` | **174** | **193** | ❌ |
| `test_tls.cpp` | 893 | 893 | ✅ |
| `test_framework.h` | **96** | **82** | ❌ |

**逐处**：

| doc | 错误声明 |
|---|---|
| 2074 | `tls_schannel.cpp` 754 行（实际 748）、`CMakeLists.txt` 193 行（实际 193） |
| 2840 | `tls_schannel.cpp` 754 行（实际 748） |
| 2841 | `test_framework.h` 96 行（实际 82）、`CMakeLists.txt` 193 行（实际 193） |
| 3229 | `CMakeLists.txt` 193 行（实际 193）、`tls_schannel.cpp` 754 行（实际 748） |
| 3230 | `test_framework.h` 96 行（实际 82） |

**为什么门禁看不见**：`verify_anchors.py` 的 `CITE` 正则只匹配**冒号前缀**的 `:NNN`。
`754 行` 没有冒号 → **完全不可见**（全文 916 条引用里，14 条是这种行数声明，全部盲区）。

**为什么这是缺陷而不是小事**：
- `doc:3229-3230` 是 **§19 执行交接包的开头**，执行 AI 读到的第一屏；
- `754` 是**批 0 之前**的行数。执行 AI 若用它做 sanity check（「文件应该有 754 行，现在 748，是不是被改坏了？」），会得出**错误结论**；
- 这与 A20-1 的原始定义（「行号引用与当前源码不符」）**是同一类事实错误**，只是形式是行数而非行号。

**定级 P2**（不是 P1：执行 AI 不会按「行数」去改代码；但它会误导 sanity check）。
**修法**：改成 748 / 193 / 82，或干脆删掉行数、只留「以 `git`/`wc -l` 现读为准」。

### 32.4 R-4：**不通过** —— 15 处旧行号存活，五项门禁全部放行

我用「`bak[n]` 有构造 + `cur[n]` 没有 + `cur[n+2]` 有」机械确证，找到 **15 处**（`doc:1796` 的 `:139-143` 也算）：

| # | doc | 引用 | 应为 | `cur[引用]` | 散文语义 |
|---|---|---|---|---|---|
| 1 | **723** | `:137` | `:139` | `switch (config_.cert_policy) {` | 「`:137`/`:142`/`:145` 全部同一句 `req \|= ISC_REQ_MANUAL...`」 |
| 2 | **723** | `:142` | `:144` | `// DEFERRED lets the chain result...` | 同上 |
| 3 | **723** | `:145` | `:147` | `break;` | 同上 |
| 4 | **723** | `:140` | `:142` | `break;` | 「`:140` 的注释自称 DEFERRED」 |
| 5 | **1796** | `:139-143` | `:141-145` | `:139` = `req \|= ISC_REQ_MANUAL...`（这是 **kInsecure** 分支） | 「`:139-143` 的 **kStrict** 分支」 |
| 6 | **1796** | `:504` | `:506` | `<EMPTY>` | 「在 `:504` 之后加证书链校验」 |
| 7 | **1796** | `t:369-382` | `t:371-384` | `:369` = `}` | 「SPKI 已有 `t:369-382`」 |
| 8 | **1796** | `t:489-507` | `t:491-509` | `:489` = `<EMPTY>` | 「`FinishHandshake`（`t:489-507`）」 |
| 9 | **1798** | `t:66-73` | `t:68-75` | `:66` = 注释 | 「复用 `ParseRecordHeader` `t:66-73`」 |
| 10 | **1807** | `t:568-575` | `t:570-577` | `:568` = `}` | 「`EnforceVersionWindow`（`t:568-575`）」 |
| 11 | **1828** | `t:489-507` | `t:491-509` | `:489` = `<EMPTY>` | 「`FinishHandshake`（`t:489-507`）」 |
| 12 | **2473** | `:489-507` | `:491-509` | `:489` = `<EMPTY>` | 「`:135-147`+`:489-507`(S8)」 |
| 13 | **3075** | `:489-507` | `:491-509` | `:489` = `<EMPTY>` | 同上 |
| 14 | **2083** | `:430` | `:432` | `}` | 「赋值在 `:430`」 |
| 15 | **2091** | `:430` | `:432` | `}` | 「`:430`（赋值）」 |

**分布**：§6 三处、§15 六处、§17 四处、§18 一处。

#### 32.4.1 为什么门禁全放行

| 门禁 | 为什么没抓到 |
|---|---|
| `verify_anchors.py` | ① `:489-507`/`:369-382`/`:66-73`/`:568-575` 都是**区间**，锚点在区间内（`FinishHandshake` 在 491，落在 489-507 里）→ **区间语义放行**；② `doc:2083`/`2091` 的 `:430` 是**裸引用**，锚点在别处；③ `doc:723` 的 `:137` 是 `t:` 形式且锚点 `switch (config_.cert_policy)` 在 `:137` **确实存在**（`:137` 真是 switch！）→ 但 `:142`/`:145` 无锚点 |
| `verify_citations.py` | 39 条 `CHECKS` 里没有这些 doc 行 |
| `citations_redtest.py` | 只注入已知的 25 个旧值 |
| `semantic_redtest.py` | 只扰动 `cur:169` |
| `anchors_redtest.py` | 只剥 `doc:2876` |

**特别说明 `doc:723` 的 `:137`**：它**不是**「陈旧行号」而是「`doc:723` 是批前快照」——
`:137` 在**批前**是 `req |= ISC_REQ_MANUAL...`，批后变成 `switch`。
散文说「`:137`/`:142`/`:145` 全部同一句 `req |= ...`」，而 `cur[137]` 是 `switch`。
**这是同一行内 3 个引用同时错位**，与 `doc:2761` 的情况完全同型。

#### 32.4.2 「区间引用」是最大的一块

15 处里有 **6 处是区间**（`:489-507`×3、`:369-382`、`:66-73`、`:568-575`、`:139-143`）。
**区间引用的锚点只要落在区间内就通过，即使整个区间错位 +2。**

`FinishHandshake` 在 `cur[491]`，但文档写 `t:489-507`。
锚点 `FinishHandshake` 落在 489-507 内 → 放行。
**但区间起点 489 是空行、终点 507 是 `handshake_complete_ = true;`，而不是函数结尾 `cur[509] = }`。**

**这暴露了区间判据的根本弱点**：「锚点在区间内」不能证明「区间边界正确」。
正确判据应要求**区间首行**匹配锚点的第一个片段（这正是 §28 我验证 v4 时用过的 `strict_start`）。

### 32.5 判定与建议

| 项 | 判定 |
|---|---|
| R-1：`doc:2761` | ✅ **通过** |
| R-2：v8 对应性判据 | ⚠️ **核心已修好**，但「弱锚点」（3 处）和「区间边界」仍可放行错位引用 |
| R-3：白名单 | ✅ **不再掩盖行号**；但暴露 8 处行数基线错误（P2），门禁对「NNN 行」完全不可见 |
| **R-4：A20-1 闭环** | ❌ **不通过**：15 处旧行号 + 8 处行数基线错误 |

**建议的最小修复（按优先级）**：

1. **15 处旧行号**（P1）：按上表逐条改；`doc:723` 整行需重写（3 个引用同时错位）。
2. **`locates()` 加唯一性**（P1，根因）：要求锚点在 `src` 的命中行 ⊆ 被引区间，否则报 WRONGLINE。
3. **区间引用要求首行匹配**（P1，根因）：`t:A-B` 的锚点第一片段必须出现在 `cur[A]`。
4. **8 处行数基线**（P2）：748 / 193 / 82；或删掉行数只留「现读为准」。

**这轮最重要的发现是第 2、3 条**：v8 把「锚点存在性」修成了「锚点对应性」，
但**没有修「锚点唯一性」和「区间边界」**。15 处存活引用里，6 处正是靠区间语义放行的。

**A20-1 仍未闭环。**

---

## 33. A20-1 八轮定案复核

> 复验 15 处、v9 两个新判据、行数基线。
> **R-1：15/15 源码侧确证，但文档侧只修了 14 处 —— `doc:2091` 漏了。
> R-2：v9 修好了区间起点与唯一性，但「单片段区间锚点」仍可浮动，我用红证证明。
> R-3：行数基线只修了 §19 两处，§17/§18 三处仍是旧值。
> R-4：不通过。**
> **未改任何工程代码。**

### 33.1 R-1：15 处 —— **源码侧 15/15，文档侧 14/15**

#### 33.1.1 用 `bak[n]` 独立确证（不看 `cur` 单独判断）

| doc | 引用 | `cur[新]` | `bak[旧]` | |
|---|---|---|---|---|
| 723 | `:139` | `req \|= ISC_REQ_MANUAL_CRED_VALIDATION;` | bak:137 同 | ✅ |
| 723 | `:144` | 同 | bak:142 同 | ✅ |
| 723 | `:147` | 同 | bak:145 同 | ✅ |
| 723 | `:142` | `// DEFERRED lets the chain result...` | bak:140 同 | ✅ |
| 1796 | `:141-145` | `cur[141]` = `case CertPolicy::kStrict:` | bak:139 同 | ✅ |
| 1796 | `:506` | `if (!EnforceVersionWindow(why)) return false;` | bak:504 同 | ✅ |
| 1796 | `t:371-384` | `cur[371]` = `Error PeerSubjectPublicKey(...)` | bak:369 同 | ✅ |
| 1796 | `t:491-509` | `cur[491]` = `bool FinishHandshake(std::string& why) {` | bak:489 同 | ✅ |
| 1798 | `t:68-75` | `cur[68]` = `bool ParseRecordHeader(...)` | bak:66 同 | ✅ |
| 1807 | `t:570-577` | `cur[570]` = `bool EnforceVersionWindow(...)` | bak:568 同 | ✅ |
| 1828 | `t:491-509` | `bool FinishHandshake` | bak:489 同 | ✅ |
| 2473 | `:491-509` | 同 | bak:489 同 | ✅ |
| 3075 | `:491-509` | 同 | bak:489 同 | ✅ |
| 2083 | `t:432` | `closed_ = true;` | bak:430 同 | ✅ |
| **2091** | **`:432`** | — | — | ❌ **文档里仍是 `:430`** |

**`bak[n] == cur[n+2]` 15/15 MATCH。你说「15 处全部修复」——源码侧成立，文档侧差一处。**

#### 33.1.2 `doc:2091` 为什么漏了（三要素）

1. **doc 行号**：`doc:2091`（§17 S22 行）；
2. **实际内容**：文档写 `:430`（赋值），`cur[430]` = `}`；正确的是 `:432` = `closed_ = true;`；
3. **散文语义**：「`src/net/tls_schannel.cpp:431`（锚点 …）（成功分支才置）、**`:430`（赋值）**、`:433`（失败路径…）」。

**对照**：`doc:2083`（同一批、同一句话的另一处）**已改成 `t:432`**。两行写的是同一件事，一处改了一处没改。
**门禁没抓到，因为 `doc:2091` 的 `:430` 是裸引用、且 `:431` 的锚点从句被算给了 `:431`**（`anchor_candidates` 只取引用后 260 字符内的第一个从句）。

### 33.2 R-2：v9 的两个新判据 —— **区间起点与唯一性都对了，但单片段区间仍可浮动**

#### 33.2.1 你修对的（我自造探针复现）

| 探针 | 结果 |
|---|---|
| `doc:2876` `t:432` + 锚点取 `cur[431]`（上一行） | **exit=1** WRONGLINE=1 ✅ |
| `doc:2876` `t:432` + 锚点取 `cur[433]`（下一行） | **exit=1** ✅ |
| `doc:2876` `t:432` + 锚点 `closed_ = true;` 改成引用 `:304`（弱锚点） | **exit=1** ✅（v8 是 BLIND） |
| `doc:2876` `t:432` + `(in Start)`（函数名错） | **exit=1**，报 `(in Start) does not enclose cur[432] (enclosing=Shutdown)` ✅ |
| `doc:2876` `t:432` + 邻行文本 + `(in Shutdown)`（函数名对、行错） | **exit=1**，报 `anchor not at cur[432] (hits [431])` ✅ |
| `doc:2876` `t:432` + `cur[425]` 的 `shutdown_sent_ = true;` + `(in Shutdown)` | **exit=1**，报 `hits [408, 425]` ✅ |

**`enclosing_function()` 我也单独验了**：`cur[432]` → `Shutdown`(404)、`cur[232]` → `Receive`(230)、`cur[491]` → `FinishHandshake`(491)、`cur[570]` → `EnforceVersionWindow`(570)。**正确。**

**你说的「v9 第一版让 `(in Func)` 跳过行检查 → A1/A2 BLIND」这个坑，我在当前版本里测不出来——已经补好了。**

#### 33.2.2 但「单片段区间锚点」仍能浮动（红证）

`range_matches()` 第 166-167 行：

```python
if len(parts) == 1:
    return any(parts[0] in s for s in src[ca - 1:cb])
```

**单片段区间锚点只要求「在区间内某处出现」，不要求「在起点或终点」。**
所以区间边界错位时，只要锚点还在新区间内，就放行。

**实测**（`doc:1828` 的 `FinishHandshake`（`t:491-509`））：
```
B1  区间 491-509，锚点 `sizes_.overhead_actual`（在 cur[503]）   exit=0  正确
C1  区间改成 489-507（整体 -2），锚点不变                        exit=0  **BLIND**
D1  doc:1796 同样改成 489-507 + 单片段锚点                        exit=0  **BLIND**
```

**489-507 是错位的区间**（489 是空行、507 是 `handshake_complete_ = true;`，真正的函数是 491-509）。
**但因为锚点在区间中间，门禁认为没问题。**

**这恰恰是上一轮 6 处区间残留的形态**：它们能通过，是因为锚点在区间内。
v9 修了「多片段区间」（要求首片段在 `cur[A]`、末片段在 `cur[B]`），
**但单片段区间保留了旧的宽松语义** —— 同一类缺陷换了个入口。

**修法**：单片段区间也应要求「锚点在 `cur[ca]` 或 `cur[cb]`」，或强制区间锚点必须写成 `A .. B` 两片段。

#### 33.2.3 另一个设计事实（不是缺陷，但要知道）

门禁对**无锚点引用**只计数、不报错：

```
no clause, section 19 (semantic gate)  : 26
no clause, other sections (uncovered)  : 315
```

**315 条引用（占 407 的 77%）没有任何锚点、也从不检查。**
「407 examined / WRONGLINE 0」这个绿灯，**只覆盖了 66 条**。
这不是 bug（设计上把无锚点交给 `verify_citations.py` 的 39 条语义检查），
**但「门禁绿」的证明力必须按 66/407 来读，不能按 407 来读。**

### 33.3 R-3：行数基线 —— **只修了 §19，§17/§18 仍是旧值**

#### 33.3.1 我先自己量（`(Get-Content f).Count`）

| 文件 | 实测 |
|---|---|
| `src/net/tls_schannel.cpp` | **748** |
| `CMakeLists.txt` | **193** |
| `tests/test_framework.h` | **82** |
| `include/rtsc/net/tls.h` | 208 |
| `tests/test_tls.cpp` | 893 |

#### 33.3.2 你改对的两处

| doc | 内容 | |
|---|---|---|
| 3229 | `CMakeLists.txt` 193 行、`tls_schannel.cpp` 748 行 | ✅ |
| 3230 | `tls.h` 208 行、`test_tls.cpp` 893 行、`test_framework.h` 82 行 | ✅ |

#### 33.3.3 但 §17 / §18 三处仍是旧值（三要素）

| doc | 声称 | 实际 | 散文语义 |
|---|---|---|---|
| **2074** | `tls_schannel.cpp` **754** 行 | **748** | 「§17 行号基线：…`tls_schannel.cpp` 754 行、`tls.h` 208 行、`test_tls.cpp` 893 行、`CMakeLists.txt` 193 行」 |
| **2840** | `tls_schannel.cpp` **754** 行 | **748** | 「**行号基线**：本轮重新读取。`tls_schannel.cpp` 754 行、`tls.h` 208 行」 |
| **2841** | `test_framework.h` **96** 行 | **82** | 「`tests/test_tls.cpp` 893 行、`test_framework.h` 96 行、`CMakeLists.txt` 193 行」 |

**`doc:2840` 尤其讽刺**：它写着「**本轮重新读取**」，数字却是批前的。
而且它含 `行号基线` → **被白名单整行跳过**，门禁永远看不见。

**定级 P2**（不阻塞执行；`doc:2840/2841` 在 §18，执行 AI 按 `doc:3207` 不读；
`doc:2074` 在 §17 同样不读。§19 的两处已对）。

#### 33.3.4 其他「写死的数字」我查了

| 类型 | 检查 | 结果 |
|---|---|---|
| 用例数 | `RTSC_TEST(` 实测：tls 26、credssp 23、licensing 47、credssp_sm 15 | 与文档一致 ✅ |
| 行数声明 | 25 处 `NNN 行`，9 处 stale | 其中 3 处是真残留，6 处是 §32 里引用旧值的叙述 |
| 字节数 | `probe_s25` 的 183/201/31 等 | 属测量值，非源码属性，不随代码变动 |

### 33.4 R-4：**不通过**

| 项 | 判定 |
|---|---|
| R-1：15 处 | ⚠️ **源码侧 15/15**；文档侧 **14/15**（`doc:2091` 漏改） |
| R-2：v9 判据 | ⚠️ 区间起点 ✅、唯一性 ✅、`(in Func)` ✅；**单片段区间仍可浮动**（红证 C1/D1） |
| R-3：行数基线 | ❌ **§19 两处已修，§17/§18 三处仍是 754/96** |
| **R-4：A20-1 闭环** | ❌ **不通过** |

#### 33.4.1 剩余缺陷清单（4 条）

| # | 位置 | 缺陷 | 级别 |
|---|---|---|---|
| D1 | **doc:2091** | `:430` 应为 `:432`（`cur[430]`=`}`，`cur[432]`=`closed_ = true;`）；`doc:2083` 同一句已改对 | **P1** |
| D2 | **doc:2074** | `tls_schannel.cpp` 754 → 748 | P2 |
| D3 | **doc:2840** | `tls_schannel.cpp` 754 → 748（且含「本轮重新读取」，自相矛盾） | P2 |
| D4 | **doc:2841** | `test_framework.h` 96 → 82 | P2 |
| G1 | **`verify_anchors.py:166-167`** | 单片段区间锚点只要求「区间内出现」，无法钉边界 | **P1（门禁）** |

#### 33.4.2 判定理由

**A20-1 的「行号引用」这一层已经收敛**：从第一轮的 58 处 → 15 处 → 现在 **1 处**（`doc:2091`）。
**但闭环要求零残留，且门禁本身不能有已知可复现的盲区。**

- `doc:2091` 是**同一句话在 `doc:2083` 已修**的镜像位置 —— 典型的「按清单改、没按语义搜同类」；
- `verify_anchors.py` 的单片段区间判据**可以被红证稳定绕过**（C1/D1 两次 exit=0），
  这意味着**下一批区间引用写错时，门禁仍会放行**。

**修掉 D1（一行）+ G1（一个分支）+ D2/D3/D4（三个数字），我就给闭环结论。**

### 33.5 我这轮的验证清单（可复跑）

| 脚本 | 作用 |
|---|---|
| `F:\rtsc\.tmp\r7_final.py` | R-1 十五处源码侧 + 文档侧 presence + 两个门禁退出码 |
| `F:\rtsc\.tmp\r7b_probe.py` | `(in Func)` 三个探针 + `enclosing_function` 定位表 |
| `F:\rtsc\.tmp\r7c_probe.py` | 单片段区间红证（B1/C1/D1）+ `doc:2091` 在 pristine 上的 BLIND |
| `F:\rtsc\.tmp\r7_counts.py` | 全部 25 处 `NNN 行` 声明 vs 实测 |

**所有影子副本均先做 SHA256 校验再使用。**

---

## 34. 第九轮复核

> 复验 S22 的 8 处、G1 修复、`brace_balanced` 的攻击面、11 个探针。
> **R-1 通过（8/8）。R-2 G1 已修（C1 由 BLIND 变 CAUGHT）。R-3 `brace_balanced` 有一个真实盲区
> （内部块冒充函数区间）。R-4 11/11 通过。R-5：不通过 —— 门禁仍有 1 个可复现盲区。**
> **未改任何工程代码。**

### 34.1 R-1：S22 的 8 处 —— **通过**

#### 34.1.1 用 `bak` 独立确证「失败路径 = `:435`」

```
"shutdown best effort"   bak=[433]   cur=[435]     (+2)
"closed_ = true"         bak=[302,430]  cur=[304,432]   (+2)
```

**`Shutdown()` 的真实结构（`cur`）**：
```
431  if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
432      closed_ = true;
433      return MakeError(Status::kOk, st, "");          <- 成功分支
434  }
435  return MakeError(Status::kOk, st, "shutdown best effort");   <- S22 就在这
```

**你说的「`:433` 和 `:435` 都返回 `kOk`，只有 `:435` 不置 `closed_`」完全正确。**
我实测 `cur[433]` = `return MakeError(Status::kOk, st, "");`、`cur[435]` = `... "shutdown best effort");` —— 两者确实都是 `kOk`，**文本层面无法区分，只有语义（是否置 `closed_`）能区分。**

#### 34.1.2 8 处逐条

| doc | 要求 | 旧值残留 | |
|---|---|---|---|
| 2083 | `:431` `:432` `:435` | 无 | ✅ |
| 2091 | `:432` `:435` | 无 | ✅ |
| 2464 | `:435` | 无 | ✅ |
| 3065 | `:435` | 无 | ✅ |
| 3122 | `:435` | 无 | ✅ |
| 3169 | `:435` | 无 | ✅ |

**8/8 全部改对，无旧值残留。**（全文还剩一处 `:433` 在 `doc:7123`，那是我 §33 里引用旧值的叙述，不是残留。）

#### 34.1.3 你发现的这个「成组错误」比我的 D1 重要

我只报了 `doc:2091` 的 `:430`，**你顺着查出整条 S22 的 8 处全错**，而且**其中 4 处（2464/3065/3122/3169）是我上一轮完全没扫到的**——
因为我按「`:430` 是赋值」这个单点去找，没有按「S22 = 失败路径」这个语义去找。

**这正是我 §33 批评你的那句话**（「按清单改、没按语义搜同类」），我自己也犯了。
**教训一致：修一处必须按语义搜同类，不能按清单逐条改。**

### 34.2 R-2：G1 已修 —— **C1 由 BLIND 变 CAUGHT**

重跑我原来的两个探针（`doc:1828` 的 `FinishHandshake`（`t:491-509`））：

| 探针 | v9 | v10 |
|---|---|---|
| **C1** 区间改 `489-507`（-2），锚点 `sizes_.overhead_actual`（cur[503]） | **exit=0 BLIND** | **exit=1 CAUGHT** ✅ |

**`range_matches` 现在要求 `first in src[ca-1]`，单片段也被钉住了。G1 闭环。**

**但我发现 D1（区间正确 + 单片段在中间）现在也 exit=1**：

```
D1  range 491-509 (correct), mid-range frag  ->  exit=1  WRONGLINE=1
    'sizes_.overhead_actual'..'sizes_.overhead_actual' not at cur[491]
```

**这不是误报，是判据变严的正确后果**：单片段锚点现在必须**就在 `cur[ca]`**，
所以「区间 491-509 + 锚点在第 503 行」被判错。

**但这条判据会误伤一类合法写法**：如果作者写 `t:491-509`（锚点 `FinishHandshake(...)`）..
这是**两片段**，没问题；但如果只写一个片段又想指区间中段，就不行了。
**实际文档里没有这种写法**（baseline exit=0），所以**当前不构成缺陷，只是判据收窄**。

### 34.3 R-3：攻击 `brace_balanced` —— **有一个真实盲区：内部块冒充函数区间**

#### 34.3.1 你问的三个问题，逐个回答

**(1) 「深度恰好 0/1 但区间仍然错」的构造 —— 有，而且是主要盲区。**

`brace_balanced()` 只在 `[ca, cb]` 内部累计深度，**完全不知道外层作用域**。
所以**任何完整的内部 `{ }` 块都满足判据**：

```
cur 493-496   depth=1  end_closes=True  -> brace_balanced=True
cur 528-530   depth=1  end_closes=True  -> brace_balanced=True
cur 535-540   depth=1  end_closes=True  -> brace_balanced=True
cur 551-554   depth=1  end_closes=True  -> brace_balanced=True
```

**红证**：把 `doc:1828` 的 `FinishHandshake`（`t:491-509`）改成**内部 if 块** `t:493-496`：

```
X1  cite inner block 493-496 as a function range  ->  exit=0  WRONGLINE=0   BLIND
```

**散文说的是「`FinishHandshake`」，引用指向的是函数内第一个 `if (QueryContextAttributesW...)` 块 —— 门禁放行。**

**这正是你让我找的那类盲区。** 它比 C1 更隐蔽：C1 是「区间整体平移」，X1 是「区间合法但不是所声称的那个块」。

**(2) 「区间正确但配平判错」的误报 —— 我没找到。**

- `X3` 区间 `517-519`（`ExpectedActualOverhead` 完整函数体）→ **exit=0 正确**；
- 真实文档 baseline → **exit=0**；
- `cur:443` 有 `{ ... }` 同行的字符串（`"schannel"`），但 `count('{')-count('}')` 仍为 0，**不影响**。

**(3) 单行 lambda / `#if` / 宏 —— 不干扰。**

```
#if / #endif / #else   在 tls_schannel.cpp 中 0 处
#define                只在 25-27（3 行，无大括号）
含大括号的字符串字面量   只有 cur:443，且括号平衡
```

**`tls_schannel.cpp` 里没有 `#if`（批 0 把平台条件全挪到 `tls_factory.cpp` 了），所以当前无风险。**
但如果将来这个文件重新出现 `#if`/`#endif` 包住函数体，`brace_balanced` 会把它当普通代码行计数 ——
**`#if 0 ... #endif` 里的不平衡大括号会直接骗过它。这是潜在风险，不是当前缺陷。**

#### 34.3.2 为什么 `brace_balanced` 的盲区可以接受（但必须记录）

`brace_balanced` 的定位是「`}` 这个末片段文本上无区分力，改用结构验证」。
它解决的是**「末边界是否闭合」**，不是**「这个块是不是散文说的那个块」**。

**后者需要的是「锚点首片段语义」** —— 而 `first in src[ca-1]` 已经做到了：
`X1` 里首片段是 `if (QueryContextAttributesW`，它**确实在 `cur[493]`**，所以首边界检查通过。

**所以 X1 漏掉的不是 `brace_balanced`，而是「区间首片段的语义是否匹配散文」** ——
门禁从来不检查散文，只检查锚点自洽。**这是设计边界，不是 bug。**

**但必须记录**：如果执行 AI 把 `t:491-509`（FinishHandshake）误写成 `t:493-496`（内部 if），
门禁不会报错。**这类错误靠锚点门禁永远抓不到，只能靠 `verify_citations.py` 的语义检查或人审。**

### 34.4 R-4：11 个探针 —— **11/11 通过**

实跑 `anchors_redtest.py`：

```
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

**11/11 OK，脚本退出码 0。与你给的表完全一致。**

**补充**：这个脚本文件的中文在 GBK 环境下显示为乱码（锚点二字显示为乱码），但**运行正常**——
因为它用 `io.open(..., encoding='utf-8')` 读文档，源文件本身是 UTF-8。**不影响功能，但可读性受损。**

### 34.5 R-5：**不通过** —— 但只剩 1 条，且性质变了

| 项 | 判定 |
|---|---|
| R-1：S22 八处 | ✅ **通过**（8/8，`bak[433]`→`cur[435]` 机械 +2 确证） |
| R-2：G1 | ✅ **通过**（C1 由 BLIND 变 CAUGHT） |
| R-3：`brace_balanced` | ⚠️ **有 1 个盲区（内部块冒充函数区间，X1 exit=0），但属设计边界** |
| R-4：11 探针 | ✅ **11/11** |
| **R-5：A20-1 闭环** | ❌ **不通过** |

#### 34.5.1 为什么仍不通过

**行号正确性这一层已经彻底收敛**：
- 15 处（§33）→ 已修
- 8 处 S22（本轮）→ 已修
- 行数基线 5 处 → 已修（我实测 0 残留）
- 三个门禁全绿，11 个红证全过

**但 `brace_balanced` 的盲区（X1）意味着门禁仍有一条已知可复现的放行路径。**
按我前几轮一直用的标准（「门禁不能有已知可复现的盲区」），这构成不通过。

#### 34.5.2 但我建议**接受这个盲区**，理由如下

| 理由 | 说明 |
|---|---|
| **它是设计边界，不是实现 bug** | 门禁验证「锚点与引用自洽」，不验证「锚点是否符合散文语义」。后者需要理解自然语言。 |
| **修法代价高、收益低** | 要抓 X1，必须让门禁知道「散文说 `FinishHandshake`」。那就得解析中文散文 —— 超出静态检查的能力。 |
| **有更合适的兜底** | `verify_citations.py` 的 39 条语义检查正是干这个的；`doc:1828` 这种关键位置应加进它的 `CHECKS`。 |
| **X1 是人为构造，不是现存缺陷** | 真实文档 baseline exit=0，我没有找到任何现存引用犯这个错。 |

#### 34.5.3 我的最终建议

**把 A20-1 判为「行号层面闭环」，但把「门禁的语义盲区」作为一条独立的 P3 记录在案：**

> **G2（P3，设计边界）**：`verify_anchors.py` 无法发现「区间引用合法但不符合散文语义」
> （如把 `FinishHandshake` 的 `t:491-509` 写成函数内 if 块的 `t:493-496`，门禁 exit=0）。
> 兜底手段：关键区间引用必须同时进 `verify_citations.py` 的 `CHECKS`。

**如果你接受「行号层面闭环 + G2 作为设计边界记录」，我就给 A20-1 闭环结论。**
**如果你要求门禁对 X1 也报错，那就还需要一轮。**

### 34.6 我这轮的验证清单（可复跑）

| 脚本 | 作用 |
|---|---|
| `F:\rtsc\.tmp\r8_s22.py` | S22 八处 + `bak[433]`/`cur[435]` 机械确证 + 全文 `:433` 残留扫描 |
| `F:\rtsc\.tmp\r8_probe.py` | C1/D1 重跑 + A2/A4/A5 区间攻击 |
| `F:\rtsc\.tmp\r8b_probe.py` | **X1 内部块冒充函数区间（核心盲区）** + X2/X3 |
| `F:\rtsc\.tmp\r8c_probe.py` | `#if`/宏/字符串大括号干扰 + 误报排查 |
| `F:\rtsc\evidence\exec\anchors_redtest.py` | 11 探针（我实跑，11/11 OK） |

**所有影子副本均先做 SHA256 校验再使用。**

---

## 35. 第十轮复核

> 复验 I6、攻击 SIG 正则、复验 depth!=1、跑 13 探针。
> **R-1 通过（I6 抓到 X1）。R-2 发现 I6 有 5 处假阳性（真实函数不匹配 SIG），
> 这是本轮唯一的新问题。R-3 通过。R-4 13/13 通过。R-5：不通过（假阳性）。**
> **未改任何工程代码。所有探针均带自校验（断言替换真的落地）。**

### 35.1 先认我上一轮的错误

你指出：

> **`doc:1828` 的 `t:491-509` 根本没有锚点从句**……它走的是 `noanchor_other`，
> **从来没经过 `brace_balanced`**。你测到的 exit=0 不是 X1，是「无锚点引用不检查」。

**你是对的。** 我实测 `doc:1828`：

```
'... + `FinishHandshake`（`t:491-509`）。与 G-A 不冲突 ...'
```
`t:491-509` 后面**直接是 `）`**，没有 `（锚点 ...）` 从句。**我上一轮的 X1 红证测的是「无锚点不检查」，不是 `brace_balanced`。**

**更糟的是**：我的探针连「替换是否落地」都没断言——你本轮特别要求的自校验，
正是我上轮缺的那一环。本轮所有探针都补了。

### 35.2 R-1：I6 抓到 X1 —— **通过**

正确靶子必须是**有锚点从句**的 Handshake 区间引用。全文唯一一处是 `doc:1798`。

**探针（带自校验）**：
```
doc:1798  `src/net/tls_schannel.cpp:101-201`（锚点 `Error Handshake(...)` .. `}`）
        ↓ 同时改引用号和锚点
          `src/net/tls_schannel.cpp:493-496`（锚点 `if (QueryContextAttributesW(...)` .. `}`）
self-check OK: 1 line changed (doc:1798)
self-check OK: citation + anchor both landed on doc:1798
```
**结果：exit=1，WRONGLINE=1**
```
[§15] doc:1798  `src/net/tls_schannel.cpp:493-496` range anchor misplaced:
       'if (QueryContextAttributesW(&c'..'}' not at cur[493]=...
```

**对照组**（不动文档）：`exit=0`。

**关键点**：`cur[493]` 确实是 `if (QueryContextAttributesW(...)`，首片段检查**会通过**；
拦住它的是 **I6 的 `starts_a_function`** —— `cur[493]` 不是函数签名。**I6 生效。**

### 35.3 R-2：攻击 I6 —— **找到 5 处假阳性**（本轮唯一新问题）

#### 35.3.1 全量普查：27 个定义，SIG 只认 18 个

`tls_schannel.cpp` 里 `indent <= 4 且以 "{" 结尾` 的行共 **27** 个：

| 分类 | 数量 | 行号 |
|---|---|---|
| SIG 匹配 | **18** | — |
| namespace | 2 | 44, 45 |
| struct / class | 2 | 80, 86 |
| **ctor / dtor（无返回类型）** | **1** | **89** `~SchannelTransport() override {` |
| **返回类型不在 SIG 列表** | **2** | **517** `uint32_t ExpectedActualOverhead() const {`；**671** `PCCERT_CONTEXT PeerCert() const {` |
| **`static` + 非列表类型** | **2** | **561** `static uint16_t WireVersionFromProtocolMask(DWORD mask) {`；**690** `static Error ConstError(Status s, int32_t code, const char* msg) {` |

`namespace` / `struct` / `class` 不是函数，被拒是**正确**的。
**但后 5 个（89 / 517 / 561 / 671 / 690）是真函数。**

#### 35.3.2 红证：4 个真函数被误拒

用「引用它自己的函数体 + 用它自己的签名作锚点」测（这是**最合法的写法**）：

```
cite 89-93   (~SchannelTransport)              -> exit=1  WRONGLINE=1
cite 517-519 (uint32_t ExpectedActualOverhead) -> exit=1  WRONGLINE=1
cite 561-568 (static uint16_t WireVersion...)  -> exit=1  WRONGLINE=1
cite 671-684 (PCCERT_CONTEXT PeerCert)         -> exit=1  WRONGLINE=1
```

每个都带自校验（`self-check OK: 1 line changed (doc:1798), all 2 substitutions landed`）。

**误报原因**：
```python
SIG = re.compile(r'^\s{0,8}(?:Error|bool|void|DWORD|std::\w+|Status|int|size_t)\s+'
                 r'([A-Za-z_]\w*)\s*\(')
```
`SIG` 是**白名单式**的返回类型枚举。它不知道 `uint32_t`、`PCCERT_CONTEXT`，
也不接受 `~` 前缀（析构函数）、`static` 前缀。

**注意 `cur:690`（`static Error ConstError(...)`）**：它的返回类型 `Error` 在列表里，
但被 `static ` 前缀挡住 —— **`static` 也没被 SIG 处理**。（此条我没单独红证，属同类推断。）

#### 35.3.3 但**当前无实际影响**（重要）

**这 5 个函数，文档里一处都没引用。** 我核了真实文档：走 `brace_balanced` 的区间引用只有 4 条
（`doc:1798`/`1896`/`2050`/`2473`，全是 `Handshake` 101-201 与 `PeerSubjectPublicKey` 371-384），
**全部 SIG MATCH，baseline exit=0，零误报。**

**所以这是「潜在假阳性」而不是「现存缺陷」** —— 但它是**门禁正确性**问题：
只要将来有审计者引用 `PeerCert()` 或 `ExpectedActualOverhead()` 的函数体，
**就会被误判为 WRONGLINE**，从而误改或放弃门禁。

#### 35.3.4 你问的三种形态，逐条回答

| 你的问题 | 我的实测 |
|---|---|
| `constexpr` / `static` / `inline` / 模板 / `Type*` / `Type&` / `auto` / `Foo::Bar(` | **`static` 中招**（561、690）。其余在当前文件里不存在，无法测 |
| 构造函数 / 析构函数（无返回类型） | **中招**（`cur:89` `~SchannelTransport()`，红证 exit=1） |
| 运算符重载 `operator==(` | 当前文件**没有** `operator` 定义，无法测 |
| **内层块恰好以函数签名开头** | **当前文件 0 处**（`indent>=8 且 SIG 匹配且以 "{" 结尾` = 0）。最近的是 `cur:485` `std::wstring w(...)` —— 它是**变量声明**，SIG 会匹配，但它**不开启大括号**，所以 `brace_balanced(485,488)` 的 depth=0 → 被拒。**当前无此盲区** |

**所以：I6 的盲区（内层块冒充）已被堵住；新开的口子是「假阳性」。**

### 35.4 R-3：`depth != 1` —— **通过**

构造 `depth == 0` 的区间：`t:497-509`（`sizes_.header = ss.cbHeader;` .. `}`）。

```
cur[497] = 'sizes_.header = ss.cbHeader;'
cur[509] = '}'
depth over 497..508 = 0     <- 从未在 ca 开块
self-check OK: 1 line changed (doc:1798)
R-3  t:497-509 (depth==0)  ->  exit=1  WRONGLINE=1
```

**`if depth != 1: return False` 生效，depth==0 被拒。**

**真实文档 4 条区间引用全是 depth=1，仍 PASS**（baseline exit=0）：
```
doc:1798  101-201  depth=1  end=True  sig=True
doc:1896  371-384  depth=1  end=True  sig=True
doc:2050  101-201  depth=1  end=True  sig=True
doc:2473  101-201  depth=1  end=True  sig=True
```

### 35.5 R-4：13 个探针 —— **13/13 通过**

我实跑 `anchors_redtest.py`：

```
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
EXIT=0
```

**13/13 OK，脚本退出码 0，与你给的表一致。**
（C5 就是我的 X1，C6 是乙的 P3 —— 两条都已闭环。）

### 35.6 R-5：**不通过** —— 剩 1 条，但性质是「潜在假阳性」

| 项 | 判定 |
|---|---|
| R-1：I6 抓 X1 | ✅ **通过**（exit=1，且首片段检查会通过、由 `starts_a_function` 拦住） |
| R-2：攻击 I6 | ❌ **5 处假阳性**（`~SchannelTransport`、`uint32_t`、`static uint16_t`、`PCCERT_CONTEXT`、`static Error`） |
| R-3：depth!=1 | ✅ **通过** |
| R-4：13 探针 | ✅ **13/13** |
| **R-5：闭环** | ❌ **不通过** |

#### 35.6.1 为什么仍不通过

**行号层面已经彻底收敛**（我实测 0 残留，43 条语义检查全绿，13 探针全绿）。
**但 I6 的 `SIG` 是白名单，会把 5 个真实函数体判成 WRONGLINE。**

按我前几轮一直用的标准（「门禁不能有已知可复现的错误判据」），**假阳性和假阴性同等严重**：
假阴性放行错误；**假阳性会让审计者误改正确引用，或者干脆不信门禁**。

#### 35.6.2 修法（一条，很便宜）

`SIG` 从「返回类型白名单」改成「**排除法**」：

```python
# 不是 namespace / struct / class / 预处理 / if / for / while / switch 开头的，
# 且形如 <任意类型串> <名字>(  —— 就是函数定义
NOT_FUNC = re.compile(r'^\s*(?:namespace|struct|class|enum|union|if|for|while|switch|else|do|try)\b')
FUNC_LIKE = re.compile(r'^\s{0,8}[~\w][\w:<>,\s\*&]*\s[\w:~]+\s*\(')
```

或最小改动 —— 在现有白名单里补 `uint32_t|PCCERT_CONTEXT|static|~`：

```python
SIG = re.compile(r'^\s{0,8}(?:static\s+)?(?:~?\w+(?:::\w+)*|'
                 r'std::\w+)(?:[\s\*&]+)(?:[\w:]+)\s*\(')
```
**但更稳的是排除法** —— 白名单永远漏下一种返回类型。

#### 35.6.3 我的判定

**A20-1 的行号部分：闭环。**
**门禁 `verify_anchors.py`：仍有 1 个可复现的假阳性面（5 个真实函数），不通过。**

**修掉 SIG（改成排除法）+ 为「引用合法函数却被拒」补一个红证（用 `cur:517-519` 即可），我就给最终闭环。**

### 35.7 我这轮的验证清单（可复跑）

| 脚本 | 作用 | 自校验 |
|---|---|---|
| `F:\rtsc\.tmp\r9b_probe.py` | R-1（X1 真靶）+ R-3（depth==0） | ✅ 断言 1 行变化 + 新片段落地 |
| `F:\rtsc\.tmp\r9c_probe.py` | R-2 四个真函数假阳性 | ✅ 同上 |
| `F:\rtsc\.tmp\r9_census.py` | 27 个定义 × SIG 覆盖普查 | — |
| `F:\rtsc\.tmp\r9d_probe.py` | 内层块冒充 + lambda 排查 | ✅ |
| `F:\rtsc\evidence\exec\anchors_redtest.py` | 13 探针 | — |

**所有影子副本均先做 SHA256 校验再使用；所有变异均断言「恰好 1 行变化 + 新片段存在」。**

---

## 36. 第十二轮复核

> **R-1 通过（0 条误杀）。R-2 通过（7 个多行签名从签名行引用全部 PASS）。
> R-3 四脚本全 exit=0。R-4：A20-1 闭环。**
> **未改工程代码、未改测试。所有探针带自校验（本轮自校验拦下 1 条无效探针）。**

### 36.1 R-1：攻击 `CLOSING_PREFIX` —— **0 条误杀**

穷举 `src/net/tls_schannel.cpp` 全部行，匹配 `^\s{0,8}\}` 的共 **87 行**。

其中**同时满足「以 `{` 结尾且只有 1 个 `{`」**（即真的开块）的只有 **3 行**：

| cur | 原文 | 是真函数吗 |
|---|---|---|
| 315 | `} else if (st == SEC_I_CONTINUE_NEEDED) {` | ❌ 是 `else if` 续接 |
| 320 | `} else {` | ❌ 是 `else` 续接 |
| 555 | `} else {` | ❌ 是 `else` 续接 |

**三条全部是 `else` 续接，不是函数体 —— `CLOSING_PREFIX` 拒绝它们是正确的，零误杀。**

**补充**：你上轮说「之前没暴露是因为 `brace_balanced(315,321)=False` 恰好挡住」——
我实测确认。**两个规则互相兜底不是设计**，你把 `starts_a_function` 单独修对，这个判断是对的。

### 36.2 R-2：攻击「签名 `(` 必然在开块行」—— **本文件不构成缺陷**

#### 36.2.1 事实：本文件有 8 个多行签名

开块行**不含 `(`** 的共 19 行。按「上一行是什么」分类：

| 类别 | 数量 | 行号 |
|---|---|---|
| `namespace` / `struct` / `class` 开块 | 4 | 44, 45, 80, 86 |
| **条件续行**（上一行是 `if (...`） | 4 | 159, 572, 631, 679 |
| **表达式续行**（`out.data(), &size))` 等） | 3 | 355, 320, 555 |
| **函数签名续行**（上一行是签名，`(` 在其上） | **8** | **69, 102, 205, 231, 590, 618, 648, 741** |

**8 个函数签名续行对应的真实函数**：

| 签名行 | 开块行 | 函数 |
|---|---|---|
| 68 | 69 | `ParseRecordHeader` |
| 101 | 102 | `Handshake` |
| 204 | 205 | `Send` |
| 230 | 231 | `Receive` |
| 589 | 590 | `EncryptOne` |
| 616 | 618 | `DecryptRecord` |
| 647 | 648 | `FeedExtraOnce` |
| 740 | 741 | `CreateSchannelTransport` |

#### 36.2.2 但这不造成误报（红证）

**关键区别**：这 8 个函数，`(` 都在**签名行**（68/101/204/230/589/616/647/740），
而 `starts_a_function` 检查的是 `cur[ca]` —— **只要引用从签名行开始，就含 `(`，通过**。

实测（每个都带自校验）：

```
cite 68-75    (ParseRecordHeader)      exit=0  PASS
cite 204-227  (Send)                   exit=0  PASS
cite 230-345  (Receive)                exit=0  PASS
cite 589-613  (EncryptOne)             exit=0  PASS
cite 616-645  (DecryptRecord)          exit=0  PASS
cite 647-668  (FeedExtraOnce)          exit=0  PASS
cite 740-746  (CreateSchannelTransport) exit=0  PASS
```

**对照组**：若引用从**续行**开始（`t:102-201`），则 exit=1 —— **但那是错误的写法**
（散文说 `Handshake`，区间却从 `std::vector<uint8_t>& out) override {` 开始）。
**门禁拒绝它是对的。**

**结论：`(` 必须在开块行，本文件 8 个多行签名都不违反这条 —— 零误报。**

#### 36.2.3 你提示的方向，逐条核

| 你提示的写法 | 本文件是否有 | 说明 |
|---|---|---|
| `operator()` | 无 | 无 `operator` 定义 |
| 宏 | 无 | `#define` 仅 25-27，不涉及函数定义 |
| 模板特化 | 无 | 无 `template<` |
| 构造函数初始化列表 | **有**：`cur:88` `explicit SchannelTransport(const Config& config) : config_(config) {}` | **`(` 在该行**，且 `{}` 同行，`count('{')!=1` → 不走 `brace_balanced`。无影响 |
| K&R 风格 | 无 | 本文件统一 Allman/1TBS |
| `= default` | 无 | — |
| `[[nodiscard]]` 换行 | 无 | — |

**通用风险（记录，非本文件缺陷）**：若将来出现
```cpp
template<typename T>
void f(T t) {
```
`(` 在 `void f(` 行，仍在开块行之前一行，**会被拒**。
**但这也意味着引用应从 `void f(` 行开始，而不是 `{` 行 —— 与现有约定一致。**

### 36.3 R-3：四脚本独立复跑 —— **全部 exit=0**

```
python evidence\exec\verify_anchors.py       -> exit=0
    citations examined 407 / anchored, unique, start-correct 70
    WRONGLINE 0 / no clause §19 26 / other 311

python evidence\exec\anchors_redtest.py      -> exit=0
    D3 static uint16_t   exit=0 expect=0  OK
    D4 PCCERT_CONTEXT    exit=0 expect=0  OK
    D5 static Error      exit=0 expect=0  OK
    E1 "} else if"       exit=1 expect=1  OK
    （18/18 全 OK）

python evidence\exec\verify_citations.py     -> exit=0
    checks passed 43 / checks FAILED 0

python evidence\exec\batch1_preflight.py     -> exit=0
    RESULT: batch 1 is executable
```

**D1–D5 这 5 条守卫确实 exit=0**（改黑名单前是 exit=1）—— 你上轮的核心修复已验证。
**E1（`} else if` 续接）exit=1** —— 你本轮新增的守卫已验证。

### 36.4 R-4：判定 —— **A20-1 已闭环**

| 项 | 判定 | 依据 |
|---|---|---|
| R-1 `CLOSING_PREFIX` 误杀 | ✅ **0 条** | 87 个 `}` 开头行中，只有 3 行开块，全是 `else` 续接 |
| R-2 多行签名误报 | ✅ **0 条** | 8 个多行签名，从签名行引用全部 exit=0 |
| R-3 四脚本 | ✅ **全 exit=0** | 407/70/0、18/18、43/0、batch1 executable |
| 行号正确性 | ✅ **0 残留** | §33–§35 累计修复 15 + 8 + 5 + 3 处，本轮复查无新增 |

**收敛轨迹**：58 处（§24）→ 15 处（§32）→ 8 处（§33）→ 1 处（§34）→ 0 处（§35/§36）。

**门禁最终形态（v12）**：
- `verify_anchors.py`：407 引用，70 条有锚点且定位唯一正确，WRONGLINE 0；
- 判据链：锚点必在区间内 → 首片段在 `cur[ca]` → 末片段在 `cur[cb]` 或 `brace_balanced` → `depth==1` → `starts_a_function`（黑名单 + `(` 必在行 + `}` 前缀拒绝）；
- 红证：18 探针，含 5 条「正确引用必须通过」的正类守卫（D1–D5）。

**A20-1 闭环。**

### 36.5 残留风险（记录，不阻塞）

| 编号 | 内容 | 级别 |
|---|---|---|
| G3 | `starts_a_function` 依赖「`(` 在开块行」。若将来出现 `template<T>\nvoid f(T t)\n{`（`{` 单独一行），会被拒 —— 但那也是错误引用形状 | P3 |
| G4 | 311 条无锚点引用仍只计数不报错（`noanchor_other`）。设计如此，由 `verify_citations.py` 的 43 条兜底 | P3 |

---

## 37. 第十二轮复裁

> **不通过。新判别器方向正确（乙报的四类假例全部已拒），但有 1 处端到端漏网：
> `cur:362` 是折行 `if (...)` 的续行，被 `starts_a_function` 判为函数，红证 exit=0。**
> **未改工程代码，只读 + 跑脚本。所有探针带自校验。**

### 37.1 你修对的部分（我独立复现）

用**归一化源码**（与门禁同口径 `' '.join(x.split())`）逐条复测：

| 乙报的假例 | cur | 判定 |
|---|---|---|
| 注释 | 9 | **False** ✅（`comment`） |
| 语句 | 349 | **False** ✅（`balanced-no-brace`） |
| 语句 | 372 | **False** ✅（`balanced-no-brace`） |
| 聚合初始化 | 595 | **False** ✅（`brace<paren`） |
| 聚合初始化 | 653 | **False** ✅（`brace<paren`） |

| 必须接受 | cur | 判定 |
|---|---|---|
| 析构 | 89 | **True** ✅ |
| 普通函数 | 371 | **True** ✅ |
| `uint32_t` | 517 | **True** ✅ |
| `static uint16_t` | 561 | **True** ✅ |
| `PCCERT_CONTEXT` | 671 | **True** ✅ |
| `static Error` | 690 | **True** ✅ |

| 折行签名（`(` 未配平） | cur | 判定 |
|---|---|---|
| 8 个签名行 | 68/101/204/230/589/616/647/740 | **全部 True** ✅ |

| 内层块 | cur | 判定 |
|---|---|---|
| `} else if` / `} else` | 315/320/555 | False（`CLOSING`） |
| `if` / `switch` / `for` | 493/137/243 | False（`INNER`） |
| 条件续行无 `(` | 679/572 | False（`no-paren`） |

**乙的两条 P2 确已修复，你对 `CLOSING_PREFIX` 是死代码的判断我也确认**
（`}` 开头且能自行配平的行 = 0，E1 的 exit=1 由 `brace_balanced` 提供）。
**我上轮说「已闭环」是错的。**

### 37.2 漏网：`cur:362`（折行 `if` 的续行被判为函数）

```
360|         if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
361|                                  &cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr,
362|                                  out.data(), &size)) {        <- 被判为"函数"
```

**增量判别器逐条走一遍**：

| 判据 | 结果 |
|---|---|
| `INNER_BLOCK` | False（行首是 `out.data()`） |
| `CLOSING_PREFIX` | False（行首不是 `}`） |
| 注释 | False |
| `'(' in line` | **True**（`out.data()` 和 `&size)`） |
| `rfind('{')` = 20，`rfind(')')` = 18 | **brace >= paren → 通过** |
| `head = 'out.data'` 含标识符 | **True** |
| **总计** | **ACCEPT（错误）** |

**端到端红证**（带自校验）：
```
cite `src/net/tls_schannel.cpp:362-366`（锚点 `out.data(), &size)) {` .. `}`）
self-check OK
-> exit=0  WRONGLINE=0    *** BLIND ***
```
`depth over 362..365 = 1`、`cur[366] = }` → `brace_balanced` 也通过。**两层判据全过。**

**对照**：同一文件的真函数 `PeerSubjectPublicKey`（371-384）也是 exit=0 —— **门禁无法区分这两者。**

### 37.3 为什么「`{` 在最后 `)` 之后」不足以判定

`cur:362` 的 `{` 确实在最后一个 `)` 之后（`...+ &size)) {`），
**因为条件表达式的末尾也是一个 `)`**。判据的形态与真函数完全相同。

**唯一可靠的区分依据是「该行是不是一条语句的开头」** —— 必须回头看上文：
- `cur:362` 的前 2 行是 `if (!CryptEncodeObjectEx(...`，即括号深度不为 0；
- 真函数的签名行，回溯时括号深度立刻归零。

**我按此写了回溯判定（`walk_back_to_statement_start`），24 个 accepted 行里恰好揪出 1 个**：
```
cur:362  start=360  CONTINUATION  'if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO'
其余 23 行 start == 自身行号，全是真函数。
```

### 37.4 你提示的其它方向：**本文件均不适用**

| 方向 | 文件内实例 | 说明 |
|---|---|---|
| `operator==` / `operator<` | **0 处** | 合成测试中 gate 返回 True，但那是**正确**的（operator 是函数） |
| lambda `auto f = [](int x) {` | **0 处**（`= [` 零命中） | 若存在会被放行 —— 潜在 P3 |
| `#define MACRO(x) { x; }` | **0 处**（`#define` 仅 25-27，无大括号） | 潜在 P3 |
| 基类初始化列表 `Foo() : Base(x) {` | **0 处**（`cur:88` `explicit SchannelTransport(...) : config_(config) {}` 用的是 `{}`，同行故 `count('{') != 1`，不走此判据） | 合成测试 4 种形态**全部 accept**，均正确 |
| `Foo() : Base{x} {` | 0 处 | 合成测试 accept —— **这是正确的**（构造函数），你担心的方向不成立 |
| `try {` / `catch(...)` / `do {` / `if constexpr` | 0 处 | 合成测试**全部 reject** ✅ |
| `template<>` | 0 处 | reject ✅ |
| `= default` / `= delete` | 0 处 | reject ✅ |
| 折行条件 `if (a &&` | 有 4 处（159/572/631/679） | 签名行本身 reject（`INNER` 或 `no-paren`）；**但 `cur:362` 这类「续行含 `(` 且以 `{` 结尾」的形态逃逸** |

**结论**：你提示的方向里，只有一种在真实文件中存在且逃逸 —— **折行条件的第 3 行（含 `(` 且以 `{` 结尾）**，即 `cur:362`。

### 37.5 四脚本 + 21 探针

```
verify_anchors.py     exit=0   407 / 70 / WRONGLINE 0
anchors_redtest.py    exit=0   21/21
verify_citations.py   exit=0   43 passed / 0 failed
batch1_preflight.py   exit=0   RESULT: batch 1 is executable
```

**21 探针全绿 —— 但探针集里没有一条覆盖 `cur:362` 这种「折行条件第 3 行」形态。**
这正是 `citations_redtest` 的老问题重演：**探针只覆盖了想到的形态。**

### 37.6 判定：**不通过**

| 项 | 判定 |
|---|---|
| 乙的 5 个假例 | ✅ 全部已拒 |
| 你的 6 个真函数 | ✅ 全部接受 |
| 8 个折行签名 | ✅ 全部接受 |
| 8 个内层块 | ✅ 全部拒绝 |
| **折行条件第 3 行（`cur:362`）** | ❌ **exit=0，端到端放行** |
| 四脚本 + 21 探针 | ✅ 全 exit=0（但无对应探针） |

**修复建议（一行）**：`starts_a_function` 增加「回溯到语句头，若语句头匹配 `if/while/for/switch/catch` 则拒绝」。
或者更简单且不需要回溯 —— **要求 `{` 之前的那一对括号必须是「参数列表」形态**，
即 `{` 前紧邻的是 `)` 且该 `)` 匹配的 `(` 前是标识符（而非 `!CryptEncodeObjectEx(` 这种调用）。

**在补上这个判据 + 一条针对 `cur:362` 的红证之前，A20-1 不闭环。**

## 38. 第十三轮复核

> **闭环。** `statement_head` 修掉 `cur:362`；全树 967 开块行**零误杀零漏网**；E4 是**真红证**（原版 exit=1 / 删守卫后 exit=0 / 对照真函数两侧 exit=0）。未改工程代码，`verify_anchors.py` SHA256 `73A31460…0070561` 未变。

### 38.1 A-1 误杀面：20 形态 → 0 误杀

`static` 独占行 / 返回类型跨行 / `template<...>` / `template`+折行 / `extern "C"` / 宏前缀 `RTS_API` / `operator[]` `operator()` `operator==` / `[[nodiscard]]` `[[noreturn]]` / 析构 / 构造+多行初始化列表 / 折行签名+行注释含 `(` / 块注释同行 / lambda 后的真函数 / 嵌套 namespace 后 —— **全 True**。真实文件 `t:68/101/204/230/589/616/647/740` 八个折行签名的**签名行**全 True 且 `head`==自身行号；`t:89/371/517/561/671/690` 六个真函数全 True。

**先纠正我上轮的错**：你补的 `_strip_comments` 我不知道，用简化副本测出的 3 个「注释误杀」是假警报。

**P3-G5**：`Foo::Foo(int a)` + `: other_{a} {` 两行构造初始化列表无法被引用为函数体（签名行 `(` 已配平且无 `{`）。本工程唯一构造函数 `cur:88` 是单行 `{}`，**0 实例**。

### 38.2 A-1 漏收面：25 形态 → 24 拒绝

折行 `if` 尾行含 `()`（`cur:362`）/ `while` / `for` / `switch` / `catch` / 三行 `if` / `do{` `try{` `else{` / 单行 `if(a){b}else` / `for(;;)` / `if constexpr` / lambda 三种 / 裸语句 / 注释 / 聚合初始化 / `SecBuffer ib{...}` / `struct` `namespace` `enum class` `class` / `= default` —— 全拒绝。

**你担心的「注释里含 `(`」不成立**：`_strip_comments` 先剥 `//` 与 `/*...*/` 再数括号。实测 `if (!Foo(a,` + `// note ( unbalanced` + `Bar(b)) {` → head 回溯到 `if` → **False**。

**唯一逃逸 P3-G6**：`#define MACRO(x) { x; }` → True。**全树 `#define` 含 `{` = 0 处**（`tls_schannel.cpp` 仅 25-27 三个无括号宏），doc 从不引用任何 `#define` 行 → **不可达**。

### 38.3 全树普查（43 文件）与 A-2 lambda

```
openers=967   accepted=284   suspicious=0
```
284 个 accepted 全部：语句头非 `if/for/while/switch/catch/do`、非注释、head==自身行号。

`[[nodiscard]] auto f() {` → **True，不误杀**。原因（实测）：
```
'[[nodiscard]] auto f() {'              LAMBDA_HEAD = False  ('' )
'[[nodiscard]] int operator[](int i) {' LAMBDA_HEAD = True   ('[](' )
```
`]]` 后跟空格+类型而非 `(`，故不匹配；`operator[]` 的 `[](` 会匹配但被 `OPERATOR_KW` 短路救回。**`operator[]` / `operator()` 均保留（True）。** 本工程 `[[...]]` 全树 **3 处**，全在 `tools/rtsc_crashtest/main.cpp:23/29/31`，**白名单 8 文件 = 0 处**。白名单内 lambda `[...](` **1 处**：`test_credssp_sm.cpp:26` → False ✅。**P3-G7**：lambda 作默认参数会误杀，全树 17 处 `[...](` **全是 `auto NAME = [...]` 赋值**，**0 实例**。

### 38.4 A-3 E4 真红证（直接法）

我第一次用 redtest 变异体测，**脚手架坏了**（改 VER 路径后所有用例都 exit=0），已弃用。改用直接法：只替换 `DOC` 常量指向影子副本（自校验：恰好 1 行变化 + 旧片段消失 + 新片段就位）。
```
E4  t:362-366   原版 exit=1 WRONGLINE=1 CAUGHT / 变异体 exit=0（删 statement_head 两行后翻绿）
    [WRONGLINE] [§15] doc:1798  range anchor misplaced: 'out.data(), &size)) {'
对照 t:371-384  原版 exit=0 / 变异体 exit=0   ← 红证指向 statement_head，非别的守卫
E2  t:349-358   原版 exit=1 / 变异体 exit=1   ← 由 brace<paren 负责（正确）
```

### 38.5 A-4 四脚本 + 判定

```
verify_anchors.py    exit=0   407 / 70 anchored / WRONGLINE 0 / §19 semantic 26 / uncovered 311
anchors_redtest.py   exit=0   32 探针全 OK（A1-A6 B1-B3 C1-C6 D1-D5 E1-E4 S1-S10）
verify_citations.py  exit=0   43 passed / 0 failed
batch1_preflight.py  exit=0   RESULT: batch 1 is executable
```
`anchors_redtest.py` 已含 **S9/S10**（注释不偏移 head）——正是我上轮担心的方向。

**判定：闭环。** `cur:362` 被否决且删守卫后翻绿；20 形态 0 误杀；25 形态 24 拒绝（唯一逃逸 0 实例）；lambda 不误杀 `[[...]]`；`operator[]`/`operator()` 保留；967 行普查 0 suspicious；四脚本全绿。

残留 4 条 P3，**全部本工程 0 实例、当前不可达**，不阻塞：**G5** 跨行构造初始化列表 · **G6** `#define ...{...}` · **G7** lambda 作默认参数 · **G8** 跨行 `/* */` 不剥离（白名单 8 文件 0 实例）。共同性质：都是「白名单扩到新文件时可能触发」的未来风险，**不是当前漏网**。建议 batch 2/3 扩白名单时，给 G6/G8 各加一条合成红证进 `anchors_redtest.py`。
