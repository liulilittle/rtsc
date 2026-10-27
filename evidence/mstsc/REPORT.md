# mstsc ↔ rtsc_server 实网验证报告

- 日期：2026-10-26
- 被测服务器：`rtsc_server`（本项目实现的 RDP 服务器角色）
- 客户端：Windows 自带真实 `C:\Windows\System32\mstsc.exe`（10.0.26100.8875，Win11）
- 主机：`F:\rtsc`（控制台会话 1，交互桌面可用）
- 结论：**阻塞。mstsc 无法到达 active 会话**；TLS + CredSSP/NLA 全部成功，失败点在 **CredSSP 完成后的 MCS 数据面交接**。

---

## 1. 新增交付物

| 文件 | 作用 |
|---|---|
| `tools/rtsc_server/main.cpp` | 最小服务器工具 `rtsc_server_host`：从命令行构造 `ServerConfig`（端口 / `enable_enhanced_security` / `credential_lookup` / `SetDesktopSource(MakeGdiDesktopSource())`），以 GDI 桌面源对外服务 |
| `CMakeLists.txt`（+11 行） | 新增 `rtsc_server_host` 目标（`/W4 /WX`，与仓库一致）；非 Windows 平台回退到测试图案源 |
| `scripts/rdp_flight_log.py` | 日志型 TCP 代理，记录每个 TCP 读的方向/长度/时刻（TLS 为密文，仅看飞行结构），用于定位阶段 |
| `evidence/mstsc/` | .rdp 文件、服务器日志、mstsc 截图 |

`tools/rtsc_server` 之前**不存在**，已按要求新建。产品协议逻辑**未改动**（`git diff -- src/server/server.cpp src/security/server_security_layer.cpp` 为空，见 §7）。

---

## 2. 基线（证明服务器对“本机客户端”可用）

```
rtsc_server_tests          : 5 tests, 33 checks, 0 failing
rtsc_server_security_tests : 4 tests, 33 checks, 0 failing   （含 server_enhanced_security_loopback_to_active）
rtsc_connect 127.0.0.1 3390 NTDEV rtsc password
  round 6: phase=await-connect-response, protocol=0x00000002
  round 13: phase=await-client-info-ack
  DONE: Client Info PDU sent            exit=0
```

即：**X.224 / MCS / TLS / CredSSP / 许可 / 会话建立，对工程内客户端是绿的**。因此后续 mstsc 的失败是 **mstsc 专有**的，不是“服务器整体不可用”。

---

## 3. 真实 mstsc 测试（NLA，mstsc 默认）

启动：`rtsc_server_host --port 3390 --enhanced --user rtsc --domain NTDEV --password password`（GDI 桌面源）。
mstsc 通过 `mstsc-nla.rdp`（`full address:s:127.0.0.1:3390`，`username:s:rtsc`，`domain:s:NTDEV`）连接。

### 3.1 逐阶段观察（全部为真实交互，见 `shots/`）

1. **打开 .rdp 文件**：Windows Shell 弹“我了解，并允许…打开 RDP 文件”。勾选并点“确定”（已记录）。
2. **不受信证书警告**：mstsc 弹“远程桌面连接安全警告 / 未知发布者 / 远程计算机: 127.0.0.1”。点“连接(N)”接受自签证书（已记录）。
3. **NLA 凭据提示**：mstsc 弹“Windows 安全中心 / 输入你的凭据”，预填 `rtsc`、解析为 **`NTDEV\rtsc`**。输入密码 `password` 并确定（已记录）。
4. **协议错误**：mstsc 弹“**由于在客户端检测到一个协议错误(代码 0x1204)**，这个会话将被中断”。

→ **mstsc 到达了 CredSSP/NLA（凭据提示），但在其后失败，未渲染桌面。**

### 3.2 服务器端阶段日志（诊断用，已还原）

诊断期间在 `RdpSession::Run()` / `ServerSecurityLayer` 临时插桩（**验证后已完全还原**），得到单次 NLA 会话的确切阶段：

```
[rtsc-sess] Run start
[rtsc-sess] x224 ok secure_req=1 proto=0x2          # X.224 协商成功，选中 PROTOCOL_HYBRID
[rtsc-sec] credssp complete, leftover plain=0:      # CredSSP 完成，无残留明文
[rtsc-sess] secure ok credssp_req=1                 # TLS + CredSSP 均成功
[rtsc-sess] secure ReadFrame transport n=-1         # 读传输层返回 -1（连接被复位）
[rtsc-sess] connect_response: ReadFrame failed      # 读 MCS Connect Initial 失败
[rtsc-sess] FAIL connect_response                  # 会话在 DoConnectResponse 终止
```

（另一次未处理弹窗的对照运行得到 `FAIL secure:`，说明客户端在 TLS 阶段即关闭——与本结论无关。）

---

## 4. 根因分析

### 4.1 确认事实（红证）

- 客户端请求的是 **HYBRID（0x2）**，服务器也正确选中 `0x2`。
  - 证据：`server-3390-final-run.err` 的 `proto=0x2`；`include/rtsc/proto/rdp_neg.h:22` `kProtocolHybrid = 0x00000002`。
  - **注意**：`kProtocolHybridEx = 0x00000008`；`0x2` **不是** SSL，而是 HYBRID。曾出现的“选 0x2 而非 0x8”的假设**不成立**（0x2 就是 HYBRID，且 `credssp_req=1` 证明 CredSSP 确实执行）。
- TLS accept **成功**（`secure ok`），无 SChannel 失败码。
- CredSSP **成功**（`credssp complete`；mstsc 弹出凭据提示并接受 `NTDEV\rtsc`）。
- 失败点：服务器发出 **EUAR**（CredSSP 完成时的 4 字节授权结果）后，`DoConnectResponse()` 读客户端的 **MCS Connect Initial** 时传输层返回 `-1`（连接被复位）；**客户端在 CredSSP 后没有发送任何 MCS 数据**（`leftover plain=0`，且无后续读）。
- mstsc 因此报 **协议错误 0x1204**（截图 06/07）。

### 4.2 代码路径（回答“服务器 post-CredSSP 路径”）

1. `RdpSession::Run()`（`src/server/server.cpp`）在 `DoSecureHandshake()` 成功后**确实**调用 `DoConnectResponse()`。
2. `DoConnectResponse()`（`server.cpp`）通过 `ReadFrame()` 从传输层读取客户端的 **MCS Connect Initial**；`ReadFrame()` 在 `secure_` 时经 `ServerSecurityLayer::ReceivePdu()` 解密并剥 TPKT 帧。读超时/返回空时**静默 return false**。
3. 服务器在 CredSSP 期间**只先发 EUAR**（`ServerSecurityLayer::DriveCredssp()` 完成分支，`src/security/server_security_layer.cpp`），**不**预先发 MCS Connect Response——这是符合 [MS-CSSP] 的（等客户端先发 MCS Connect Initial）。
4. mstsc 侧：收到 EUAR 后应发 MCS Connect Initial。**实测它没有发，而是直接复位连接。**

### 4.3 最可能缺口（假设，需下一轮证伪）

服务器与 mstsc 的分歧发生在 **CredSSP 消息流 / EUAR 语义**：

- 工程内 `CredsspServer` 的直接交换测试（`tests/test_server_security.cpp: credssp_server_direct_exchange`）显示服务器会发出 **2 条 TSRequest（m2、m4）+ EUAR**；而 [MS-CSSP] 基线是 **1 条 TSRequest（CHALLENGE）+ EUAR**。多出的这条服务器消息很可能被 mstsc 视为协议错误。
- 另一种可能：EUAR 的发送时机/承载方式（单独 TLS record）与 mstsc 的 CredSSP 状态机不符。

→ 因工程内客户端与服务器使用**同一套** CredSSP 状态机，所以“自洽地”互通；mstsc 作为第三方实现即暴露该分歧。

### 4.4 次要观察

- `enablecredsspsupport:i:0`（SSL-only）路径同样失败，报 **0x706**“由于安全设置错误…”（截图 04/05）。该路径未单独插桩，但现象与 NLA 路径一致（都在 TLS/安全层之后失败）。

---

## 5. 结论

| 验收项 | 结果 |
|---|---|
| X.224 / MCS 协商 | ✅ 成功（HYBRID=0x2） |
| TLS | ✅ 成功 |
| CredSSP / NLA（mstsc 到达凭据提示并接受账号） | ✅ 成功 |
| 许可 | ❓ 未到达 |
| 会话建立 / 渲染桌面 | ❌ **失败** |
| **mstsc 是否可达 active** | ❌ **否** |

**阻塞点**：CredSSP 完成后的 MCS 数据面交接——服务器发 EUAR 后收不到 mstsc 的 MCS Connect Initial，mstsc 复位连接并报协议错误 0x1204。

**尚未定位到“具体哪条消息/EUAR 字节”**（需对 CredSSP 状态机与 mstsc 的差异做下一轮取证，例如用工程内 `CredsspClient` 复算/比对 TSRequest 序列，或抓包解密）。

---

## 6. 证据清单（`evidence/mstsc/`）

- `server-3390-final-run.err` — 服务器端逐阶段日志（上表）
- `server-3390-final-run.log` — 服务器 stdout（配置 + session accepted）
- `flight-3391-proxy-run.log` — 代理飞行结构（X.224 CRQ 42B → CCF 19B；用于排除“CF 后未继续”类假设）
- `mstsc-nla.rdp` / `mstsc-ssl.rdp` / `mstsc-nla-proxy.rdp` — 连接配置
- `shots/01..07-*.jpg` — Shell 提示、不受信证书警告、NLA 凭据提示（`NTDEV\rtsc`）、0x706 与 0x1204 错误详情

## 7. 还原与回归

- 临时插桩已**全部还原**：`git diff -- src/server/server.cpp src/security/server_security_layer.cpp` 为空。
- 还原后重新编译 `rtsc_server_host`：`/W4 /WX` **零错误**。
- 回归：`rtsc_server_tests`、`rtsc_server_security_tests` 全绿（见 §2）。

---

## 追加报告（2026-10-27，licensing 0x808 与黑屏修复）

- 结论：**已解除阻塞。真实 mstsc（NLA/CredSSP）到达 active 并渲染完整桌面**（截图 08/09/10）。
- 构建：cmake --build --config Release EXIT=0 零警告；ctest -C Release **51/51 全绿**；scripts/linux-build-gate.sh **PASS**（FAILED_COUNT=0, WINDOWS_H_COUNT=0, CTEST_EXIT=0, 49/49）。

### A. 根因 1：licensing 0x808（disconnectReasonLicensingFailed）

**红证链**：
1. 飞行日志 light2.log：服务器发出 364 字节 License Request 飞行后，mstsc **静默 5 秒**→ 38 字节关闭 → 断开；mstsc 弹出"由于授权协议中的一个错误"（0x808）。
2. 服务器插桩 [TEMP2]：lic: enter → cert=184 lr_body=312 → FAIL read reply → FAIL licensing（mstsc 从不回应）。
3. **Ground truth（决定性）**：经 RTSC 客户端连真实 Win11 服务器 192.168.1.7:3389 抓取其 licensing 首包：
   80 00 00 00 ff 03 10 00 07 00 00 00 02 00 00 00 04 00 00 00
   = SEC_LICENSE_PKT + ERROR_ALERT(v3) + wMsgSize=16 + **STATUS_VALID_CLIENT(7)** + **ST_NO_TRANSITION(2)** + 空 BB_ERROR_BLOB。
   真实服务器（无许可证服务器角色）**只发这一条 Error Alert，不发送 License Request**；RTSC 客户端与真实 mstsc 均接受并直达 active。

**修复**（src/server/server.cpp DoLicensing）：整段 licensing 交换（License Request/RSA premaster/平台挑战）替换为单条 ERROR_ALERT(STATUS_VALID_CLIENT + ST_NO_TRANSITION)，preamble flags=0x03（extended_error=false），与真实服务器字节级一致。

### B. 根因 2：会话 active 但桌面全黑

**红证链**：
1. [TEMP4] 帧统计：服务器发送的像素 100% 非黑（nonblack=3072/3072），mstsc 却渲染纯黑 → mstsc 在丢弃矩形。
2. 手工逐字节核对服务器 update PDU：结构与规格一致，唯独 TS_BITMAP_DATA 的 destRight/destBottom 为**排他语义**（destRight=width）；而 [MS-RDPBCGR] 2.2.9.1.1.3.1.2.2 与真实服务器（抓包矩形 704,768,767,831 = 64×64）均为**含端点语义**（destRight-destLeft+1 == width）。mstsc 校验不一致即丢弃矩形 → 黑屏。
3. TDD：test_server.cpp 新增 ect_extents_consistent 断言（destRight-destLeft+1==width && destBottom-destTop+1==height）。**[RED]**：临时恢复排他语义后 server_full_handshake_to_active 失败（rect r=64 b=48）；**[GREEN]**：含端点修复后通过（r=63 b=47）。

**修复**（BuildBitmapBand）：destRight = width-1，destBottom = dest_y+height-1。

### C. 同步修正：slow-path 位图更新的重复 updateType

服务器原在 TS_UPDATE_BITMAP_DATA 前多发一个 0x0001 词（自造"重复 updateType"形状）。规格（FreeRDP update.c/fastpath.c 实读）：slow-path body = [updateType][numberRectangles][rects]（updateType 恰一次）；fast-path body 亦以 2 字节 updateType 开头（fastpath_recv_update_common 实读）。修复：服务器去掉重复词；客户端 UpdateBitmapData::parse 对齐为 [numberRectangles][rects]；客户端 fast-path 位图分支跳过 body 开头的 2 字节 updateType（与真实服务器抓包一致）。test_output/test_graphics 夹具同步更新。

### D. 附加加固

ActiveLoop 空闲刷新（33×30ms ≈ 1s 重发整帧）：覆盖 mstsc 丢弃"Confirm Active 处理期早到帧"的首帧竞态；功能上覆盖 RefreshRect 重发整屏的需求（mstsc 激活后的 RefreshRect 在 ≤1s 内由空闲重发满足）。

### E. 还原与门禁

- 产品文件零 fprintf/printf 残留（git diff 与 grep 双重核验）；client.cpp / licensing_machine.cpp 与 HEAD 完全一致（git diff 为空）。
- mstsc 真实验证（干净构建）：server-final.log + shots/08/09/10-*.jpg——桌面完整渲染（浏览器/任务栏/托盘时钟可见，两帧间内容动态变化证明 live 更新）。
- 输入转发路径未在本轮验证（超出本任务范围，另行验证）。
- 并发说明：共享工作树含主代理的客户端修复（RAIL/INFO_RAIL 等）与同组代理对 test_session_setup.cpp 的并发修复；本任务未触碰 opencode.json 与配置文件。

**修复 diff 摘要**（本任务）：
- src/server/server.cpp：DoLicensing 单 Error Alert；BuildBitmapBand 含端点矩形 + 去重复 updateType；ActiveLoop 空闲刷新；移除临时插桩与孤儿 ReadLicensingFrame/BuildLicenseRequest。
- src/proto/output.cpp：UpdateBitmapData::parse 对齐 TS_UPDATE_BITMAP_DATA。
- src/client/graphics.cpp：fast-path 位图跳过 body updateType。
- 	ests/test_server.cpp：licensing 新期望（Error Alert 即完成）+ rect_extents_consistent 回归断言。
- 	ests/test_output.cpp、	ests/test_graphics.cpp：夹具对齐规格形状。
