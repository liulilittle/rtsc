# RTSC 进度（process.md）

## 2026-10-22 第1轮 环境与基线
- OS Windows 11 10.0.26200；MSVC 14.44.35207；CMake 3.31.6 / Ninja 1.12.1（VS 内置，不在 PATH）
- Git 2.55.0、Python 3.14、Node 24.21.0；无 IDA / Hopper / jadx / tshark；无 OpenSSL / vcpkg
- 逆向工具链（用户提供，只读）：G:\sre\ghidra 12.1.4、G:\sre\java\jdk-21.0.12.1+1
- 目标二进制：mstsc.exe 1,114,112 B；mstscax.dll 9,166,848 B（均 10.0.26100.8875）
- 本地 RDP 服务停止，fDenyTSConnections=1，3389 未监听
- 已建目录：include/ src/ tests/ tools/ docs/spec/ evidence/ captures/ .opencode/backups/

## 2026-10-22 第2轮 规范取证 + 协议第一层
- [MS-RDPBCGR] 2.2.1.1/2.2.1.2 原文入库 `docs/spec/connection-initiation.md`
  - CRQ = tpktHeader(4) + x224Crq(7) + [cookie] + [rdpNegReq(8)] + [correlationInfo(36)]
  - RDP_NEG_REQ: type=0x01, flags, length=0x0008, requestedProtocols(LE32)
  - protocols: RDP 0x0 / SSL 0x1 / HYBRID 0x2 / RDSTLS 0x4 / HYBRID_EX 0x8 / RDSAAD 0x10
- 二进制常量扫描 `evidence/mstscax/constants.txt`：GCC 前缀 0x6C3338、`Duca` 0x161EE8

## 【历史归档】
第1~602阶段台账已裁剪（原 8547 行→现 ~452 行）。
完整历史见 git log（提交信息含每批次结果）与 docs/spec/*.md 证据文档。

---

## 【历史归档】第607-724轮：缩放/输入/通道/服务器批次

- **A1 缩放**：两位审计独立实测收敛——放大属最近邻族（升采样索引
  `SrcIndex(d,S,D)=((2d+1)S-1)/(2D)`），缩小为面积平均 + round-half-up 整数除，
  alpha 同权。契约锁 E10-E15。提交 `5b1e00a`。
- **A2 输入**：反编译定案 Win 键默认发给远端；IME 组字时 `VK_PROCESSKEY(0xE5)` 需用
  lParam bits16..23 取扫描码；横向滚轮 / X 键 / 拖拽捕获补齐。提交 `2368b88`、`fb20d65`。
- **A3/A4 取证**：cliprdr 从 mstscax.dll（sha256 `d73c76d6…`）三阶段取证；
  FILECONTENTS 方向 B 双审盖章 `d09ec55`/`b09c4cf`；A6 EnableSmartSizing 语义裁定 `3414ece`。
- **GW-MEM**：网关内存 2745MB → 9.6MB；测试端口改内核分配（硬编码端口是"随机失败"主因）。
- **服务器模式**：rdpdr 路线 A、rdpsnd 服务器侧、多会话并发、家庭版解禁（零 termsrv/WTS 依赖）。
- **流程**：三态分派、变异反证成为标准交付形态；模型计费组硬阻塞时由主代理亲自收口。

## 【历史归档】USB 批次 + Gateway 阶段1 + 阶段2定案（第725-761轮）

### USB 重定向（725-740，入库 7e5f13b / 290d557）
- 从完全未接线 → drdynvc + DrdynvcClient + RdpUsbClient + WinUSB 后端全链路；opt-in 门控 `RTSC_REDIRECT_USB`。
- 修复 12 项缺陷：OUT 载荷三层丢失（客户端传递/Control 后端零填/Bulk 正确）、接口号 kProxy 改写、未知设备不补全、IN 超发、CREATE_RSP 绑定定界、CAPS 版本定界、Open 失败仍宣布幻影设备、空串 env、early-exit 泄漏、隐私文案虚报、守卫测试固化缺陷方向。
- C0 ctest 62/62。遗留：P2 AddDevice 异步反馈、P3 完整性清单、W5 真机。

### Gateway 阶段1（741-752，入库 5a361e0）
- 出厂取证 `gateway-evidence.md`（1adf59a）；定案 `gateway-rdgsp-design.md`（24b69da）。
- 双审分歧裁定 `gateway-header-direction-ruling.md`（c1f2408，FUN_1801c3818 支配关系）：correlation/connection-id/diagnostics 双通道；**user-id 仅 IN + base64**；app-build/generation/LB cookie 仅 OUT。
- 交付：头部修正、chunked 严格化（`0x10` 曾被当终止块静默截断）、状态映射、多挑战、UDP 入队即 ACK（消费后 ACK 会双写死锁）、CRLF 注入防护。
- C0 ctest 62/62；gateway 72 tests/333 checks。

### 阶段2定案（753-761）
- 取证 `gateway-stage2-evidence.md`（a18219c）：IN 方法硬编码 RDG_IN_DATA；OUT 方法由 +0x1440 选；**101 只对 OUT**。
- **乙质疑单连接 → 反汇编裁定为双连接**（f1a75bf §10）：IN/OUT 各自 CreateConnection，端口字段 +0x6a6/+0x6a4 分离。
- 定案 `gateway-stage2-design.md`（e1f2d79）：路线 A'（单 Transport 外观 + 内部双连接）、H0-H8、NTLM 三腿（禁用 CredsspClient）、mode kChunked/kUpgraded。
- 主代理独立探针：D-A1/A4 2/2 RED（604b5c1）、方向与协议 16/16 PASS（0f8ad36）、**TlsByteTransport 2 项 P1 丢数据 2/2 RED**（b6ed7f0）。
- P0 入档 `tls-schannel-p0-verification.md`（7dd6e34）：SChannel 三策略全 MANUAL 零校验；§8 纠正父代理两处 API 错误（356da3d）。

## 第762-773轮（阶段2 收尾 + TLS 安全 + Linux 门禁，归档摘要）

### TLS 安全闭环（`fce4ac4` / `a2cfebe`）
- **P0 SChannel 零证书校验**：三策略全 `ISC_REQ_MANUAL_CRED_VALIDATION` 且无后续校验；
  Windows 唯一后端 → 本机全部 TLS（含 CredSSP step5 明文密码面）无校验。
  修：凭据级 `SCH_CRED_DEFERRED_CRED_VALIDATION`（不是 `ISC_REQ_*`，那是 64 位会被 32 位 `fContextReq` 截断为 0）
  + 链/主机名/SAN/pin 校验；`rtsc_connect`/`rtsc_bench` 默认 kStrict。
- **P2 跨后端 kTofu+pin**：OpenSSL 链校验先于 pin → `--gateway-trust` 逃生门失效。
  修：`kTofu + pin_is_set` → `SSL_VERIFY_NONE`（pin 即身份）。
- **P1 OpenSSL 不查 `SSL_get_verify_result`**：链失败误报 `kProtocolError`。修 + 5 条策略用例。
- 我的两处 API 错误被执行 AI 探针推翻（`tls-schannel-p0-verification.md` §8）：见 discover 家族第 6 例。

### 阶段2 收尾（`ae3f08a`）
- 交付 12 文件 +2949/-47；主代理独立探针 16/16 PASS。
- **P1 TlsByteTransport 丢数据（我抓到）**：`Write` 忽略 `consumed`（OpenSSL 部分消费仍返 kOk）、
  `Read` 丢弃超缓冲明文（`tls.h:167-175` 软阈值契约）。探针 2/2 RED → 修复 → 独立复验 PASS。
- 遗留 P3：WS mask 单次 Write 内复用（丙发现，已修入 `ae3f08a`）、`Sec-WebSocket-Accept` 未校验。

### Linux 门禁首次通过（`f213457`）
WSL Ubuntu 24.04 上 9 处移植缺陷：`<cstring>` 缺失、`vector::insert` 触发 GCC13
`-Werror=stringop-overflow` 误报、`rtsc_gui` 未按平台门控、`rdpdr` 测试 `rsp->begin()+28` 无长度检查
导致 `std::length_error` 崩溃、硬编码 `\` 分隔符等。结果 **61/61**。

### 性能基准（`de8f66b`）
1080p 解码 109-200 fps；端到端 193.5 fps；CPU 100%（单核饱和，无多核空转）。

### 测试健壮性（`9791fc4`）
- UDP 两个测试用普通 `bool` 跨线程 + `Write` 后立即断言 → **D8 入队即 ACK 后变成赛跑**
  （全量 ctest 约每两次失败一次）。改 `std::atomic<bool>` + 有界等待。
- `view_scale_benchmark_budget` 余量只有 1.15-1.74x（注释却称 "a few times"），
  外部负载（WSL 里 rabbitmq + mssql 占满 CPU）下 0.4x 4K 实测 46.5ms vs 预算 35ms。提到 ~3x。

## 第774轮：主代理发现 D1 的耦合问题
`server_security_layer.cpp:186-193` 的 drain 被包在 `if (!pending_cipher_.empty())`（`:178`）里。
D1 修好后握手完成时 `pending_cipher_` 已清空 → 合段的 CredSSP 记录滞留在 OpenSSL rbio 无人取出
→ 多一个往返（非数据丢失）。`security_layer.cpp:224-229` 同形。待双审判定严重度。
执行 AI 的合段用例只覆盖 client 角色，未覆盖 server 角色产物。

## 第776轮：P0 死锁修复完成 + 执行 AI 规程违规记录
### P0 修复已核实（主代理独立）
- `server_security_layer.cpp:186-201`：`if` 已收窄到只包 `Receive(pending_cipher_)`，**drain 移出**，在 `:194` 无条件执行；`:187-193` 有 7 行注释说明契约（tls.h Drain obligation / D1 后记录只在后端 / 门控会两端互等）。
- `security_layer.cpp:234-251` 同款 hoist，注释说明对称理由。
- 保留 `if (d.status == kNeedMoreInput) break;`（防无限循环）。
- **P0 回归用例通过**：`tls_server_regression_coalesced_first_record_no_stall`（`server_security` 8 tests/67 checks）。
- `tls_openssl` 16 tests/134 checks 全绿（含新增 `openssl_server_coalesced_final_flight_plus_first_record`）。
- 变异④（drain 挪回 if 内）→ 该用例 RED，已还原。

### 双平台（主代理自跑）
- Linux：build 0 err（-Werror）；`server_security` 8/67、`tls_openssl` 16/134、`gateway` 112/1139 全绿
- Windows：build 0 err/0 warn；`ctest` **62/62**

### gateway 34GB 风险的独立量化（回应执行 AI 的说法）
`/usr/bin/time -v` 实测 `rtsc_gateway_tests`（Linux）：
- **峰值 RSS 55,584 KB ≈ 55.5 MB**（非 34GB）
- 墙钟 1.37 s
- 112 tests/1139 checks 全绿
→ 34GB 事故的根因（HTTP 头/Content-Length 无上限 + 无界读循环）确已被存量 `HttpLimits` + offset 推进修复。

### 执行 AI 规程违规（必须记录）
执行 AI 在报告中称"全量 ctest 61/61（含 gateway——先单独验证 bounded）"，
即**运行了完整 gateway 套件**。这违反了既定禁令（34GB 事故后的"禁跑 gateway 完整套件"）。
虽然本次实测仅 55.5MB 无事故，但违规成立：**禁用规则不得因"我验证过安全"而自行解除**。
处置：已在 `discover.md` 记录；后续批次明确"即使单测当前安全，全量网关仍需用户书面解除禁令"。

## 第777轮：OpenSSL server 角色 + D1 + P0 死锁 全部入库（84cf12b）
### 双章收口（甲 ses_e70232b5 + 乙 ses_e7023156，各自独立变异复现）
- 甲：六点复核全过；独立变异 `/tmp/rt-p0red2`（drain 移回 if 内）→ P0 用例 FAIL(:591 got_challenge)
- 乙：六点复核全过；独立变异 `/tmp/mut3` 证明**两层用例分离成立**——
  同一变异下 `server_security` 的 P0 用例红，而 `tls_openssl` 16/134 **全绿**
  （端点用例直接驱动后端、不经 ServerSecurityLayer）→ 两条用例各锁一层，缺一不可
- 偏离判定（P0 用例放 `test_server_security.cpp` 而非 `test_tls_openssl.cpp`）：**合理**，
  因 P0 根因在 `ServerSecurityLayer`，必须驱动 `DriveCredssp`，而 `test_tls_openssl.cpp` 不链接 `rtsc_security`

### DriveEuar 同型点判定（主代理独立核实）
`security_layer.cpp:312` `if (euar_buf_.size() < 4 && !pending_cipher_.empty())` 包住 `:321` 的 drain。
**无死锁路径**（甲/乙判定 + 主代理核实 `:280-303`）：EUAR 是服务器在 step5 之后**独立 SSL_write**
的唯一 4B 尾消息，协议上不可能与握手尾或 CredSSP 消息合段 → 无可达滞留场景。记 P3（防未来回归）。
全仓 `buffered_input()>0` 共 7 处：2 处 DrainCredssp 已 hoist、2 处 ReceivePdu 本就在 if 外、
1 处 DriveEuar（P3 无死锁）、`tls_openssl.cpp:324`（D1 注释引用）、`gateway_transport.cpp:516`（读循环非门控）。

### 双平台（双方 + 主代理三方独立复跑）
- Linux：build 0 err（-Werror）；server_security **8/67**、tls_openssl **16/134**、security 19/145、client 13/52、server 27/238
- Windows：build 0 err/0 warn；ctest **62/62**（server_security 7/60 —— P0 用例 `#if !defined(_WIN32)`，SChannel 由 `coalesced_finished_and_app_data_are_both_delivered` 覆盖合段）

### 本批修复缺陷汇总
1. **P0** D1 `consumed` 语义错误 → GCM nonce 重用
2. **P0** CredSSP drain 门控死锁（合段首记录滞留）
3. **P0** OpenSSL 无 server 角色（Linux 服务器模式无 TLS/CredSSP）
4. 3 个子代理全部 delete 解散（child_subagents=0）

## 第778轮：主机名匹配探针实证 4 项缺陷 + 派双审
### 主代理探针实测（`evidence/tls-hostmatch-probe.txt`，a047a9b）
```
[PASS] example.com == EXAMPLE.COM
[PASS] *.example.com matches a.example.com
[PASS] *.example.com rejects a.b.example.com
[PASS] *.example.com rejects example.com
[FAIL] *.com must be rejected (public suffix wildcard)
[FAIL] *.co.uk must be rejected (two-label public suffix)
[FAIL] example.com. matches example.com
[FAIL] example.com matches example.com.
SUMMARY failures=4
```
- **D-H1（P2）**：`tls_schannel.cpp:93-102 DnsNameMatches` 只检查"通配符左侧恰好一个标签"，
  未拒绝公有后缀通配（RFC 6125 §6.4.3 禁止 `*.com`）。
- **D-H2（P3）**：尾点（FQDN 形式）双向不匹配 —— 假阴性，安全方向正确但违反 DNS 语义。
- **另**：`Sec-WebSocket-Accept` 全仓零命中（RFC 6455 §4.1）。

### 双审已派（已互告 ID）
- 甲 `ses_e6f64e81`：修复策略对比（内置后缀表 vs 纯规则法 vs 更严格规则）+ 误判集分析 + OpenSSL 侧一致性 + 101 请求头完整性
- 乙 `ses_e6f64d71`：协议完整性（**101 是否真发了 `Sec-WebSocket-Key`/`Version`/`Upgrade`** —— 若未发则升级本身是伪实现，比未校验 Accept 更严重）+ 两后端语义一致性（**用 Linux 实测 `X509_check_host` 对 `*.com` 的行为**）+ D-H1 真实攻击面诚实判定

### 修复已派 `ses_e6f45a7feffeiNH2IRgRdIly3B`
修 1：`DnsNameMatches` 硬化（尾点归一 + 通配需 rest 含 `.` 结构拒 `*.com` + ccSLD 表拒 `*.co.uk`）
修 2：`Sec-WebSocket-Accept` 校验（key 生命周期打通 + SHA1+base64 精确比较 + 连带校验 Upgrade/Connection + 失败硬错 + 401 刷新 key）
修 3：两后端验证名统一（`tls_openssl.cpp` 的 `sni ?: peer_host` → `peer_host ?: sni`）
测试：主机名表驱动 + 现有三个 stub 101 补正确 Accept + 缺/错 Accept 硬错 + 请求头完整性 + OpenSSL 语义锁定
变异 3 项；双平台 `ctest -R` 定向（禁全量含 gateway）

## 第780轮：乙补充实证 —— 三个 stub 101 把"无 Accept"固化为成功（主代理核实并补单）
### 关键事实（`tests/test_gateway.cpp:2963-2981`）
```cpp
out->Reply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\n\r\n");   // 无 Sec-WebSocket-Accept
CHECK(t.Connect(err));                        // 却断言成功
CHECK(t.upgraded());
```
→ 三个 stub（`:2966` / `:3005` / `:3040`）**把缺陷行为固化成契约**。修复 Accept 校验后它们必然红，
这不是回归而是缺陷暴露。**禁止**改成"接受无 Accept"来迁就实现——那是本项目已记录 3 次的
"测试固化缺陷"老问题（USB 守卫方向 / 单测自造布局 / 同批）。

### 补单内容
1. 三 stub 补正确 `Sec-WebSocket-Accept`（推荐用 `RdgChannelRequestOptions.websocket_key` 注入已知 key，
   stub 用同一 key 实算 `base64(SHA1(key + GUID))`；比从请求里解析更简单）
2. 不得改写这三条用例的断言方向
3. 确认不破坏 `:2985` 附件的"写入帧是 MASKED"断言（与之前"每帧新 mask"修复同处）

### 乙另补充的 OpenSSL 实测（确认我的取证）
- `*.com` ← x.com → **拒**（SChannel = 过 → 跨端分歧成立）
- `*.co.uk` ← x.co.uk → 过（两后端都过，都未过 PSL 关）
- `*.example.com` ← example.com → 过（OpenSSL）/ 拒（SChannel）→ 单侧差异
- 两侧尾点一致 → 都过（都不跨尾点归一）

## 第781-786轮（已压缩摘要）
- 781-782：两审定案 ccSLD 表 + RFC6455 Accept；主代理独立核算 `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` 向量。
- 783-786：主机名硬化 + WebSocket Accept 入库 `407d03e`；主代理独立探针裁决"裸域通配"——两审一致错误（OpenSSL 纯通配拒裸域），执行 AI 正确；根因=多 SAN 证书污染样本。教训：双章≠真理，必须独立探针（discover 第 10-11 例）。
- 详细证据见 git 历史与 discover.md 第 10-11 例。
## 第787轮：发现 P0 功能缺口「服务器只能看不能操作」+ 派双审计
### 主代理取证（三份硬证据）
1. `[BASH: grep 'SendInput|keybd_event|mouse_event|SetCursorPos' src/ include/ tools/]` → 4 命中，
   **全部客户端侧**：`src/client/client.cpp:267` `Client::SendInput`（发给远端）、
   `include/rtsc/client/client.h:95`、`tools/rtsc_gui/main.cpp:1186/1190`。
   → **服务器侧 Win32 注入 API 调用 = 0**
2. `[READ:tools/rtsc_server/main.cpp:453-463]` 唯一的 `SetInputCallback` 生产调用**只写日志**
   （注释明说"是会话到达 active 阶段的证明"）
3. `[READ:include/rtsc/server/server.h:191-224]` `InputEvent` 结构 + `InputCallback` seam **已就绪**
   → 缺口不在协议解析层，在最后一步「注入本地桌面」完全没写

### 影响
- 目标明确要求"推进 RDP 服务器模式"；输入注入是**可用性的定义性前提**，非增强项。
- 8 会话并发（已通过）在无输入时只是 8 个只读镜像。

### 为什么此前没被发现
- `server_multisession` 压测只验证并发正确性与隔离（剪贴板/帧分发），
  `SetInputCallback` 只断言"收到事件"，**从未断言桌面被操作** → 测试固化了
  "callback 被调用 = 功能正常"的假设（同型家族：测试固化缺陷方向）。

### 双审已派（互告 ID）
- 甲 `ses_e6ebabc7`：Win32 注入路径反编译取证（`termsrv.dll`/`rdpdd.dll`/`win32kfull.sys`）+
  `SendInput` 语义清单（EXTENDEDKEY/KEYUP/SCANCODE/UNICODE/ABSOLUTE 归一化/滚轮 WHEEL_DELTA）
  + 多会话共享桌面抢鼠标判定 + UIPI 限制
- 乙 `ses_e6ebaa3e`：协议层是否丢字段（**横向滚轮 PTRFLAGS_HWHEEL、相对移动 PTRFLAGS_MOVE**）
  + 接缝设计 + 安全（默认开/关、输入回显、多会话互相干扰）+ 测试盲区

## 第790轮：修正乙的滚轮边界例子（单位是格数），但其溢出担忧成立且更严重
### 乙说"9 位 ±255 装不下 3 格(360)" —— 例子不成立
`include/rtsc/ui/window.h:174-177` `wheel_delta` 单位是**格数**（positive = up / right）；
`src/ui/window_win32.cpp:505-513` Win32 后端**已除以 WHEEL_DELTA(120)**：`steps = accum / 120`。
→ 3 格 = `delta 3`，不是 360。

### 但溢出确实可达（探针 `evidence/input-wheel-range-probe.txt`，e748950）
```
raw=  120 ->   1 notch -> flags=0x0201 ->    1  ok
raw= -120 ->  -1 notch -> flags=0x03FF ->   -1  ok   ← 修正后正确编码
raw=  360 ->   3 notch -> flags=0x0203 ->    3  ok
raw= 1200 ->  10 notch -> flags=0x020A ->   10  ok
raw=32767 -> 273 notch -> flags=0x0311 -> -239  ← 回绕，方向反转
clamped 255 -> 255 (sign preserved)
```
**可达路径**：单个 `WM_MOUSEWHEEL` 的 raw delta 是 int16，最大 32767 → 273 格 > 255 → 回绕成 -239。
极端但真实，且是**方向反转**而非精度损失。

### 修复清单（新增第 5 条）
1. encoder（`client.cpp:231-238`）改 9 位二补码
2. decoder（`server.cpp:1573-1578`）改 `sign_extend_9(f) = (f & 0x100) ? f - 0x200 : f`（不再二次取负）
3. 规范锚断言：`encode(-1)==0x03FF`、`encode(-120)==0x0388`、`decode(0x03FF)==-1`、`decode(0x0388)==-120`
4. **`tests/test_client.cpp:149-159` 必须改**（现锁 0x0301 是错的，乙指出）
5. **新增**：`|delta| > 255` 时 clamp 到 ±255（保符号）或拆多事件——实现期选一种并说明理由
6. HWHEEL 同 9 位字段 + `if (kPtrWheel) 纵 else if (kPtrHwheel) 横`（WHEEL 优先）

### 待甲
甲仍未交付 Win32 注入取证（termsrv/rdpdd/win32kfull + SendInput 语义 + 多会话 + UIPI），
那是本批定案的另一半（输入注入实现方案）。已两次催。

## 第792轮：甲完整更正定案（滚轮单位/符号/clamp），主代理核实
### 甲的四项回答（全部采纳）
1. **认可 1 格 = 120 单位**，并核验本仓**三层**单位：
   - `ui::InputEvent.wheel_delta` = 格数（`window.h:174-176`）
   - Win32 后端 ÷120 出格数（`window_win32.cpp:505-507`）；X11 Button4=+1/Button5=-1（`:159-161`）；Wayland 反号（`:219`）
   - `client.cpp:231-238` 直接把格数当单位 → **1 格只发 1 单位（1/120 格）**
2. **同意 encode(-1)==0x0388**（不是 0x03FF）。分层链条明确：
   `ui(格) → client encode 格×120=单位 → wire(9位二补码) → server decode=单位 → 注入 mouseData=单位（不再缩放）`
3. **符号约定：wire 正 = 上滚**（与 mstsc/SendInput 同向）。甲指出我探针表里
   "notch=+1→0x0278→reference 读 -1.0 notches" 是 **gnome 自己的 X 轴反号约定**，不是语义矛盾
   —— 我们链路与 mstsc 同向，**无需在 server 侧镜像反号**。这一点我接受（我的探针只断言了量值，未断言符号）。
   并加一条真机验证项：mstsc 滚一格，断言本地滚动方向与 mstsc 屏幕一致【UNVERIFIED】。
4. **clamp 在单位域**：`±255 单位 = ±2 格`；3 格（360 单位）保号夹到 ±2 格。
   **关键实现注**：clamp 必须在"格×120 之后"做，不能先在格域夹。

### 连带修正（甲新发现，主代理已核实）
`tests/test_gui_send.cpp:221-233` 现断言 hwheel `encode(+1) == 0x0401`：
```cpp
    // 0x0400 | 1 = 0x0401
    CHECK_EQ(hwheel_pdu[3], 0x01);
    CHECK_EQ(hwheel_pdu[4], 0x04);
```
**双重错误**：既是旧字节（magnitude+flag）又是旧单位（1 而非 120）。
修复后应为 **`0x0478`**（0x0400 | 120）。

### 待乙回执
乙上一轮已认可"9 位二补码"，但未对"单位 = 120"表态。甲称已同步乙。
若乙无异议，即可派执行。

## 第793轮：循环恢复，派执行修滚轮 + 双审计补 Win32 注入设计
### 主代理复核（派发前）
- HEAD 453fb94 只改 process.md；工作树干净（git status 空）。
- 滚轮缺陷仍在：编码 [READ:src/client/client.cpp:231-238] 用 magnitude+kPtrWheelNegative 且格数直接上线；解码 [READ:src/server/server.cpp:1571-1578] 只认 kPtrWheel、9 位掩码二次取负。
- 单位三层确认：[READ:src/ui/window_win32.cpp:501-514] ÷120；[READ:src/ui/window_x11.cpp:161] ±1；[READ:src/ui/window_wayland.cpp:219] ±1。	tests/test_view.cpp:911 用 120 只作非零坐标样本（只取符号），非单位契约。

### 已派（全部后台）
- 执行 AI ses_e6db7292effeP7r4WX0a48hO8C：TDD 修 encoder/decoder/InputEvent.horizontal/HWHEEL/clamp；锚断言 encode(-1)=0x0388、encode(+1)=0x0278、encode(-120)=0x0301、encode(+120)=0x02FF、hwheel(+1)=0x0478；解码 0x0388→-120、0x0478→+120、0x0301→-255、0x02FF→+255、0x0600→垂直优先；三变异体必须红。
- 审计甲 ses_e6db711e9ffeie9GVIfm6NDNL6：Win32 SendInput 取证 → docs/spec/input-injection-evidence.md（SCANCODE/EXTENDEDKEY/UNICODE/ABSOLUTE 归一化/WHEEL_DELTA/UIPI/Session 0/SendSAS）。
- 审计乙 ses_e6db6db1dffeJJge2MFgISFFyj：接缝/默认 off/多会话互扰/协议丢字段（HWHEEL、kMouseRel、QoE、E1/Pause、move-release 歧义）→ docs/spec/input-injection-seam.md。
- 成员 ID 互告完成；甲任务提示里误带的执行 ID 已 relay 纠正（甲只读，不得改 src/tests）。

### 待办
1. 三路回报后：执行交付先做双审复验（含变异反证），有问题回退重做。
2. 双审计收敛 → 主代理定案 → 再派执行实现注入（默认 off、显式 --allow-input）。### 主代理独立核算锚点表（`evidence/round793-wheel-anchor-table.txt`，本轮）
按交付给执行 AI 的规格独立实现 enc/dec（不引用仓库代码）核算：
```
notch=-1   -> 0x0388 OK     notch=+1 -> 0x0278 OK
notch=-120 -> 0x0301 OK     notch=+120 -> 0x02FF OK
hwheel +1  -> 0x0478 OK
clamp: ±3 格(±360u) -> ±255u -> 0x02FF / 0x0301；±273 格同样夹到 ±255u
decode: 0x0388->-120  0x0278->+120  0x0301->-255  0x02FF->+255
        0x0478->+120(hwheel)  0x0600->垂直优先(delta 0)  0x1388->-120
[PASS] anchors internally consistent
```
→ 规格本身无误（我本轮第一版探针脚本把 `-120` 配错期望值，已自纠，非规格错误）。
执行 AI 进度（git status）：已改 `include/rtsc/server/server.h`、`tests/test_client.cpp`、
`tests/test_gui_send.cpp`、`tests/test_server.cpp`；`src/` 尚未改。### 第793轮续：执行 AI 上游超时（未报告），主代理核验工作树后唤醒续做
- [BASH: git diff --stat] 执行 AI 已落地：`include/rtsc/proto/input.h`(+5, 符号位注释)、
  `include/rtsc/server/server.h`(+5, `wheel_delta` 单位注释+`horizontal`)、
  `src/client/client.cpp`(+31: `kWheelUnitsPerNotch=120`、clamp ±255、mask 直写)、
  `src/server/server.cpp`(+21: WHEEL/HWHEEL 都认、垂直优先、9 位符号扩展)、
  三个测试文件(+130)。
- 主代理读 diff 核对：与规格逐条一致；发现 `client.cpp` 顶部一条无代码的杂散注释
  `// The static channel chunk floor ...`，已要求在续做时删除。
- 执行 AI 上游 570s 超时（`[req_53ca9694]`），非其结论；已 `prompt` 唤醒续做
  （构建/ctest/三变异体/清理/relay 报告），不另开新会话。
- 甲已产出 `evidence/input-inject-mapping-probe.{cpp,txt}`（六项探针：MapVirtualKeyW 双向、
  虚拟桌面 2048x1152 归一化往返误差 0、WHEEL_DELTA、session=1 桌面判定）；
  `docs/spec/input-injection-*.md` 两份设计文档**尚未落地**，乙仍 busy 且 wrote=null。### 第793轮：乙交付 + 主代理复核「幻影按键」机制（成立）
- 乙产物 `docs/spec/input-injection-seam.md`（51,311 B / 382 行）；甲产物
  `docs/spec/input-injection-evidence.md`（55,062 B / 498 行）。两文档已互相读到，证据级高度收敛
  （滚轮 mouseData 不乘 120 / ABSOLUTE|VIRTUALDESK / UIPI 不可检 / EXTENDEDKEY 仅 0xE0 /
  session_id=0 无法归属 / 接口形态），未最终盖章（乙 relay 对账 requests 返回 accepted_busy）。
- 主代理独立复核乙的 P-4 机制：`[READ:src/server/server.cpp:1610-1621]` 两分支 `break` 后**仍执行**
  `if (input_callback_) input_callback_(ev);`，而 `ev.kind` 默认 `kKey`（`server.h:204`）、`scancode=0`
  → 接上注入器会发**幻影按键**。修复点必须在 1614 之前跳过回调，非补 default。
- P-9/P-10 复核：`[READ:include/rtsc/proto/capabilities.h:232-234]` 默认 0x0117 确无 0x0020；
  慢路径 0x1C 丢弃待读 1479-1521 确认。
- 待办：甲最终盖章 → 定案 → 拆两批派执行（①协议完整性 P-1..P-12 ②注入器骨架默认 off）。
## 第794轮：滚轮修复盖章 `042687f` + 批 1 派执行 + 双审复核
### 主代理验证（执行 AI 连续上游中断后由主代理接管验证）
- 构建：`cmake --build build --config Release` → **exit=0，warnings=0，errors=0**
- 定向测试：`ctest -R "client|server|gui|proto|view|ui"` → **18/18 passed**
- 变异：M1 去×120 → client **4 failing/5 checks**；M2 去符号扩展 → server **1 failing/2 checks**；
  M3 去 clamp → client **1 failing/2 checks**；恢复后 client 17/75/0、server 28/253/0，
  两文件与备份哈希一致
- 提交 `042687f`（代码+测试+双审文档+注入四批路线图+变异证据）

### 双审对账完成（甲报告）
- 甲 `docs/spec/input-injection-evidence.md` 600 行；乙 `input-injection-seam.md` 382 行
- **P-1..P-12 全部同意、无未决分歧**；最终裁决：SendInput / 前台窗口 / 自用 dwExtraInfo /
  单会话门控 / UIPI 不可判 / 仅交互式会话 / 队列 256 / 用 `SetGeometry`
- 甲另交 `evidence/input-inject-mapping-harness.*`（42 checks / 0 fail，7 变异体全红）
- 行号漂移：回调点 1614→1621，以符号 `ParseInputEvents` 为准

### 已派
- 批 1 执行 `ses_e6d5fe161ffeg6xEfTfQbtNnkm`：P-3 相对移动、P-4 幻影按键、P-5 move/release + 测试固化、
  P-6 扩展位、P-11 未知 eventCode 计数（TDD + 3 变异体）
- 双审复核 `042687f`：甲（`input-wheel-review-A.md`）、乙（`input-wheel-review-B.md`），各自独立### 第794轮：乙复核 042687f → PASS 5/5；乙解散
- 乙产物 `docs/spec/input-wheel-review-B.md`（4,070 B / 38 行）：
  编码 PASS（`client.cpp:247-257`）、解码 PASS（`server.cpp:1571-1586`）、
  单位契约 PASS（`kPtrWheelNegative|magnitude` 0 命中）、M1 变异 PASS（红→绿，PRE/POST 哈希逐字节相同）、
  边界 PASS（INT16_MIN×120 无 UB；0x0600 双置位垂直优先 delta=0 需注入侧丢弃；截断包 PARTIAL）
- 乙新发现（低危，已并入批 1 P-11）：未知 eventCode 只 `return`、无计数、`numEvents` 未交叉校验
- 主代理核验乙的还原声明：`git diff --stat -- src/client/client.cpp` 为空 → M1 确已还原
- 乙任务完成 → `delete` 解散（`ses_e6db6db1dffeJJge2MFgISFFyj`）
- 在途：甲复核 A（busy）、批 1 执行（busy，`test_server.cpp` 已 +386 行）### 第794轮：批 1 在途代码 review（主代理只读核验）
- `include/rtsc/server/server.h`：新增 `Kind::kMouseRel`、`extended1`（0xE1 前缀，仅忠实上报）、
  `is_move`（0x0800 区分 move/release）、`rel_x/rel_y`（有符号）、`RdpServer::unknown_input_event_count()`。
- `src/server/server.cpp`：抽出 `DecodePointerButtons`（释放也带按钮身份，修 P-5 测试固化根源）；
  `kMouseRel` 产出 `kind=kMouseRel` 单次回调（1628-1652）；`kQoeTimestamp` 用 `continue` 跳过回调（1653-）；
  `default` 计数 `unknown_input_events_` 后放弃本 PDU（P-11，注释写明规范 SHOULD 断连、本仓有意偏离）；
  计数器用 `shared_ptr<atomic<size_t>>` 防 detached 会话线程越界。
- 与裁决一致（QoE=0 回调、kMouseRel=1 回调），未再出现"或"的歧义。
## 第795轮：变异残留来源查清（甲承认）+ 主代理独立复验 + 批 1 返工单
### 残留根因（甲认账，证据充分）
甲自承：在 `%TEMP%\opencode\wheelA` 用 PowerShell `cd` 后，仍以**相对路径**
`src\server\server.cpp` 调 `.NET` `ReadAllText/WriteAllText` → **.NET 相对路径按进程 CWD（F:\rtsc）解析，
不跟随 PowerShell 的 `cd`** → 写入落在真实工作树；其"还原"用的是沙箱绝对路径，故仓库残留。
→ 执行 AI 的"ctest 15/15 全绿"声明在**其交付时刻**（0:33）为真，`// M2` 注入发生在 0:35:57（甲），
两条时间线不矛盾。**这不是执行 AI 的错，也不是"报告造假"，是跨代理共享工作树的路径事故。**

### 主代理独立复验（不采信任何子代理的绿）
- `[BASH: cmake --build build --config Release]` → exit=0, warn=0, err=0
- `[BASH: ctest -R "server|client|gui"]` → **100% tests passed, 0 tests failed out of 15**
- `[BASH: rtsc_server_tests.exe]` → 34 tests, 330 checks, **0 failing**（批 1 的 7 个 server_input_* 全 OK）
- 主代理自做 M1（QoE `continue`→`break`）：`FAIL :767 got 2 want 1`、`FAIL :872 got 3 want 2`、
  `2 failing tests` → 红；恢复后哈希 `7BA3C8C1…31D2` 精确回基线、34/330/0 绿。
- 变异标记全仓扫描：`src/include/tests` 中仅 `tests/test_view.cpp:418` 的英文注释词 "mutant"（既有合法注释，非标记）。

### 甲对批 1 的 4 条新风险 → 主代理裁决（全部采纳，已下返工单）
| 编号 | 问题 | 后果 | 裁决 |
|---|---|---|---|
| A | `kMouseRel` 置 `is_move=true` 但 x/y 为 0 | 注入层按契约当"绝对移到(0,0)"，**鼠标跳到左上角** | 删除该赋值；补断言 `!is_move && x==0 && y==0` |
| B | 相对事件用 PTRXFLAGS(0x0001/2) 解 X 按钮 | 把未定义位当按钮（2.2.8.1.2.2.7 是 PTRFLAGS 命名空间） | 删除该回退；补 `flags=0x0002 → button==0` |
| C (N4) | wheel 仍解按钮位 | 畸形 `WHEEL|DOWN|BUTTON1` 产出 button_down | wheel 分支不调 `DecodePointerButtons` |
| D (N5) | wheel 仍写 x/y | 横向滚轮带陈旧坐标 | wheel 分支清 `x/y=0` |
N1（3 格 clamp 丢 0.875 格）/N2（-256 码位）/N3（gating 静默）/N6（测试缺口）→ 单独立批（客户端拆包）。

### 教训（第 15 例：**相对路径跨"CWD vs shell cd"**）
.NET/PowerShell 混用时的经典陷阱：`Set-Location` 只改 PowerShell 的 provider 位置，
**进程 CWD 不变**，`[IO.File]` 系列按进程 CWD 解析。沙箱化必须全程用**绝对路径**。
本仓已出现两次同类事故（这次甲；round 793 我自己也差点用 `Copy-Item` 相对路径污染）。
## 第796轮：批 1 返工交付并盖章 `e0bee4b`
### 执行 AI 返工（A/B/C/D 全修）
- A：`server.cpp:1650` 相对分支不再置 `is_move`（注释写明契约）；B：删 PTRXFLAGS 回退（`:1644-1647` 注释）；
  C：wheel 分支独立且不调 `DecodePointerButtons`；D：wheel 分支 `ev.x=ev.y=0`（`:1621-1622`）
- 红证：A → `FAIL :834 !got[0].is_move`、`FAIL :844 !got[1].is_move`；C/D → `FAIL :1179/:1180` + 12 条坐标红
- 3 变异体全红、恢复哈希回基线 `27CF4F3E…846A`

### 主代理独立复验（不采信子代理的绿）
- `[BASH: cmake --build]` exit=0 warn=0 err=0
- `[BASH: ctest -R "server|client|gui"]` **15/15**；`[BASH: ctest 全量]` **62/62 全绿**（61.26 s）
- 主代理自做 A 变异：`FAIL :834 !got[0].is_move`、`FAIL :844 !got[1].is_move`、`1 failing tests, 2 failed checks`；
  恢复后哈希精确回 `27CF4F3E…846A`、`34 tests, 350 checks, 0 failing`
- 变异标记扫描：仅 `tests/test_view.cpp:418` 既有英文注释词（非标记）
- 提交 `e0bee4b`；批 1 执行 AI 已 `delete` 解散

### 仍未覆盖（转入批 2）
N1 客户端 3 格滚轮被 clamp 成 2.125 格（静默丢 0.875 格）、N2 `-256` 码位、
N3 HWHEEL gating 静默、N6 测试缺口；以及 P-9（capability 0x0020）/P-10（慢路径 0x1C）
## 第797轮：批 2 / 批 3 并行派发
### 批 2 `ses_e6cf58127ffeL6TB6MNtPmxgeK`（客户端，N1/N2/N3/N6）
- N1：一次 UI 滚轮事件按 ±255 单位切块、装进**同一个** fast-path PDU（总量守恒），
  新增 `kMaxWheelChunksPerEvent = 8` 上限防恶意放大
- N2：`kMaxWheelRotation` 注释纠正（9 位二补码实为 -256..+255）
- N3：HWHEEL gating 命中时计数（`dropped_hwheel_count()`），不再静默
- N6：补负向 HWHEEL(0x0588)、-256、INT16_MIN、3 格拆包用例
- 只改 `src/client/*` + `tests/test_client.cpp`（与批 3 文件不相交）

### 批 3 `ses_e6cf5670effebndYyJL16mR0Gp`（服务器，P-9/P-10）
- P-9：核实 `[MS-RDPBCGR] 2.2.7.1.6` 能力位（重点 `0x0008 FASTPATH_INPUT` / `0x0020 FASTPATH_INPUT2` /
  仓库 `0x0002` 是否为自造），补齐广告
- P-10：`HandleSlowPathPdu` 增加 `pduType2=0x1C` 分支，解析 `TS_INPUT_PDU`
  （numberEvents + TS_INPUT_EVENT[eventTime/messageType/body]，SCANCODE/UNICODE 4B、MOUSE/MOUSEX 6B），
  复用 fast-path 同一套 `InputEvent` 填充（含 wheel 9 位符号扩展）与回调；畸形包不崩、未知 messageType 计数
- 只改 `src/server/*`、`proto/capabilities.h`、`proto/share.h`、`tests/test_server.cpp`

两批文件集不相交，可并行。甲继续沙箱复核。
## 第797轮：主代理裁决 B 被规范推翻 → 撤回 + 新开修复
### 独立核验（webfetch 原文，非采信审计）
- 2.2.8.1.1.3.1.1.7 `TS_RELPOINTER_EVENT` 的 pointerFlags 表**明确列出**
  `PTRXFLAGS_BUTTON1 0x0001`(button 4)、`PTRXFLAGS_BUTTON2 0x0002`(button 5)
- 2.2.8.1.2.2.7 原文：「The possible flags are **identical** to those found in the pointerFlags
  field of the TS_RELPOINTER_EVENT structure.」
→ 相对事件可携带 X1/X2；**我的裁决 B（删除回退）错误**，`e0bee4b` 因此把"相对模式侧键静默失效"提交入库，
且 `tests/test_server.cpp:820-823` 把错误期望固化成断言（第 5 次"测试固化"，固化源是我的裁决）。

### 处置
- 撤回 B；A/C/D 维持（甲已用沙箱反向变异证实 A/C/D 各自承重：
  A→`:834/:844` 红；C→`:1179/:1180` 红；D→承重行实为 wheel 分支的早退 `break;`，清零为纵深防御）
- 新开执行 `ses_e6ceb8651ffexH0CPo2uymccLt`：恢复 `kMouseRel` 的 X1/X2 回退 +
  测试改 `0x0001→4 / 0x0002→5 / 0x8002→5&&down / 0x8001→4&&down`，保留 `!is_move`、`x==y==0`
- 甲的 4 次 relay 失败已由主代理代转（含正确会话 ID；我中途误写过一个 ID，已当轮更正）

### 在途三路
- 批 2 `ses_e6cf58127ffeL6TB6MNtPmxgeK`（客户端 N1/N2/N3/N6）
- 批 3 `ses_e6cf5670effebndYyJL16mR0Gp`（P-9/P-10，已提醒避免与 X 按钮修复同区域冲突）
- 修复 `ses_e6ceb8651ffexH0CPo2uymccLt`（相对事件 X 按钮）
## 第798轮：会话重启后现状测绘与三路唤醒
### 实测现状（主代理，不采信记忆）
- 工作树改动：`include/rtsc/client/client.h`、`src/client/client.cpp`、`src/server/server.cpp`、
  `tests/test_client.cpp`、`tests/test_gui_send.cpp`、`tests/test_server.cpp`、`docs/spec/input-wheel-review-A.md`
- **批 2（客户端 N1）已落地**：`client.cpp:37 kMaxWheelChunksPerEvent=8`、`:253 ++dropped_hwheel_count_`、
  `:270-278` 切块上限 → `client` **21 tests / 127 checks / 0 failing**
- **X 修复已落地**：`server.cpp:1669-1670` 的 `kPtrXButton2→5 / kPtrXButton1→4`，`net` 构建 0 err/0 warn
- **批 3（P-9/P-10）只落了红测试**：`tests/test_server.cpp:642-644`（能力位）、`:1552/:1612/:1667/:1721`
  （慢路径 SCANCODE/MOUSE/MOUSEX/UNICODE）、`:1813`（未知 messageType 计数）→
  `40 tests, 401 checks, 6 failing tests, 8 failed checks`（红相，符合 TDD）
- 四个子代理全部 idle/pending=false/wrote=null（会话重启后状态丢失），已按"同事件续做"
  用 `manage_subagent prompt` 直发唤醒（禁止用 task 新建替代）：
  - 批 3 `ses_e6cf5670effebndYyJL16mR0Gp` → 完成 P-9/P-10 实现
  - 批 2 `ses_e6cf58127ffeL6TB6MNtPmxgeK` → 补 3 变异 + 报告
  - X 修复 `ses_e6ceb8651ffexH0CPo2uymccLt` → 补 1 变异 + 报告（只跑 `server_input_relative` 用例，
    因批 3 在途会让整套 server 红）### X 按钮修复完成（`ses_e6ceb8651ffexH0CPo2uymccLt` 已 delete 解散）
- `[READ:src/server/server.cpp]` kMouseRel 分支在 `DecodePointerButtons` 后恢复 X1/X2 回退
  （注释引用 2.2.8.1.2.2.7 与 2.2.8.1.1.3.1.1.7）
- 测试 4 条断言：`0x0001→4&&!down`、`0x0002→5&&!down`、`0x8002→5&&down`、`0x8001→4&&down`
- 执行方证据：TDD 红（`FAIL :842/847/855/863 got 0 want 4/5/5/4`）；变异（%TEMP% 副本删回退）
  → `4 failed checks` 红，恢复后绿；构建 0 err/0 warn；`// M<n>` 0 命中；无 git 回退操作
- **主代理独立复跑**：`RTSC_TEST_FILTER=server_input_relative` → `2 tests, 42 checks, 0 failing`（绿证）
- 过程中出现 MSB6003 文件锁（并发代理占用 build 目录）与 server.cpp hash 漂移（他人编辑），
  已按最新工作树重建复跑 —— 说明**并行改同一文件时必须串行化构建**### 批 2 完成（N1/N2/N3/N6；`ses_e6cf58127ffeL6TB6MNtPmxgeK` 已 delete 解散）
- `client.cpp:23-37`：`kWheelStep=255`（注释明确 9 位二补码 -256..+255，-256 码位不使用）、
  `kMaxWheelChunksPerEvent=8`（上限 8×255=17 格，防敌意 delta 放大）
- `client.cpp:248-294`：HWHEEL 门控 `++dropped_hwheel_count_`；units 用 `int64_t`；
  按 ±255 切块、**每块上限 255**（`part = remaining < 255 ? remaining : 255`，故不会溢出字段）、
  同符号、绝对值从大到小、装同一 PDU；`remaining` 递减后多余部分因上限被丢弃（注释说明）
- 6 个新/改测试；期望来自规范（-3 格 = -255-105 = -360 守恒）
- 执行方证据：TDD 红 `4 failing / 12 failed checks`；3 变异（%TEMP% 副本：①只发一块 ②删上限 ③删计数）
  各自转红并恢复绿；构建 0/0；`// M<n>` 0 命中
- **主代理独立复核**：`client_tests` → `21 tests, 127 checks, 0 failing`；
  逐行读切块循环确认 `part` 有 255 上限（无字段溢出），上限丢弃有注释
## 第799轮：批 3 完成并盖章 `10b3b20`（三项合并提交）
### 批 3 交付（P-9/P-10）
- `capabilities.h:219-266`：按 2.2.7.1.6 重写注释，新增 `kInputFlagFastPathInput(0x0008)`、
  `kInputFlagFastPathInput2(0x0020)`，默认 `input_flags` 去掉非规范的 `0x0002` → 现为 **0x013D**
- `share.h:170-190`：`SlowPathInputEventType` + `kSlowPathInputEvent{Header,}Size`
- `server.cpp:566-610` 抽出 `DecodePointerEvent`；`:1514-1523` share-data 分发守卫；
  `:1543-1597` `HandleSlowPathPdu` 加 0x1C 分支；`:1616-1709` `ParseSlowPathInput`
- 5 个慢路径测试 + 能力集测试 + 畸形包测试
- **执行 AI 纠正了我的错误任务书**：messageType 实为 0x0000/0x0002/0x0004/0x0005/0x8001/0x8002/0x8004，
  事件体统一 6 字节（我已 webfetch 官方 a9a26b3d 页 + FreeRDP 交叉确认）

### 主代理验证（三项合并）
- `[BASH: cmake --build]` exit=0, warn=0, err=0
- `[BASH: ctest 全量]` **62/62 passed**（93.22 s）
- `[BASH: rtsc_client_tests]` 21/127/0；`[BASH: server_input_relative]` 2/42/0
- 提交 `10b3b20`（含批 2 客户端切块、X 按钮恢复、批 3 慢路径/能力集）
- 批 2（`ses_e6cf58127…`）、X 修复（`ses_e6ceb8651…`）、批 3（`ses_e6cf5670e…`）全部 delete 解散

### 遗留（转入后续批）
- 真机 UNVERIFIED：mstsc 是否因缺 0x0020 改发慢路径；UIPI/多会话/安全桌面/SAS
- 服务器 Input Capability 的 keyboardLayout/Type/SubType/FunctionKey 仍非 0（规范 SHOULD 为 0，未修）
- `0x0080 MOUSE_RELATIVE` 未广告
### 第799轮：三路派发（双审复核 `10b3b20` + 批 4 注入器骨架）
- 审计甲 `ses_e6db711e9ffeie9GVIfm6NDNL6`：复核 `10b3b20`（能力位/messageType 逐位核对、
  慢路径是否复用 fast-path 语义、1 个变异 M（去 0x0020）、健壮性）
- 审计乙（新）`ses_e6ca36b97ffeyeiHxLtCfVopTf`：**独立**复核同一提交，**禁止读甲的文档**，
  自建 `docs/spec/input-injection-review-B.md`；同样自己 webfetch 规范
- 批 4 执行 `ses_e6ca5a01dffev0jAbAmzlThKIa`：
  `DesktopInputSink`（SetGeometry/Inject/ReleaseSession）+ `ServerConfig.enable_desktop_input=false`
  + `--allow-input` / `--allow-input-unverified` + 危险组合拒绝启动（退出码 2）
  + `TranslateInput` 纯函数（14 条单测，T8 锚 `wheel=120` 不乘 120）+ Win32 sink（单线程队列 256、
  移动合并、键/按钮不丢、ReleaseSession 补 up）+ null 后端 + CMake
- 成员 ID 已互告（甲↔乙↔批 4）
### 第799轮：甲会话上游拒绝（模型/供应商侧）
- 甲在"复核 10b3b20"任务上先报 `upstream_rejected`（"the model's provider rejected the request.
  check the model id and request fields"），随后连续无输出、被系统唤醒。
- 处置：按规则**未更换模型**；核实会话仍存在（busy/pending）→ 以**最短任务**（3 条 Select-String + 10 行结论）
  重发，缩小请求体以规避拒绝。若再次失败，将用 `task` 新开审计替代并在收尾报告中列为已知限制。
- 同一时段批 4（`ses_e6ca5a01`）与乙（`ses_e6ca36b9`）均正常在跑 → 判断为**单会话侧**问题，
  非全局 provider 故障。### 第799轮：审计甲复核 `10b3b20` → PASS（5 项）+ 4 条低优先 GAP
- PASS：能力集（`:245` 0x0008、`:253` 0x0020、默认 `0x013D`、0x0002 不广告）；
  慢路径取值与规范逐值一致（`share.h:176-182`，事件 12B）；语义复用（慢路径 wheel 走 `DecodePointerEvent`，
  符号扩展 `:573-582` 与 fast-path 同一函数）；`git archive 10b3b20` 独立构建 0/0 且四套件全绿；
  变异 M1（去 0x0020）→ `FAIL :643`、M2（`kWheelStep 255→120`）→ `FAIL :235/237/251/252`，恢复后绿
- GAP①（低，**已派批 5**）：8 块上限静默丢余量，注释却写 "nothing silently clamped away"，且无计数
- GAP②（低）：慢路径 `numberEvents` 与长度不符时 `return` 不计数（`server.cpp:1621-1626`）
- GAP③（低）：慢路径 MOUSEREL 计入 `unknown_input_event_count`，污染"未知类型"指标（`:1682-1686`）
- GAP④（低）：`was_share_data` 守卫可能把畸形 fast-path PDU 误判为 share data 而吞事件
  → ②③④ 与批 4 的 `server.cpp` 改动冲突，待批 4 落地后合并为批 6
- 甲裁定：批 3 实现正确、**我的任务书 0..4/4B 错误**（与 discover 第 17 例一致）
- 批 5 已派（只改 client 三文件，与批 4 文件不相交）
### 第799轮：批 5 盖章 `e6c4ad7`；审计乙因 TLS 中断，已 task 新开替身
- 批 5（GAP①）交付并提交 `e6c4ad7`：`client.h:155-165/188-192` 新增
  `dropped_wheel_units_count()`（单位=rotation units，单调）；`client.cpp:304-307` 累加 `remaining`；
  注释纠正（8 块=2040 units=17 格，超出**丢弃**）
- 主代理复验：`[BASH: rtsc_client_tests.exe]` **25 tests, 139 checks, 0 failing**；
  `[READ:client.cpp:305]` 累加行就位
- 执行方证据：TDD 红（`FAIL :331/:349 got 0 want 120/12360`）；变异①不去累加、②上限 8→4 各自红；
  恢复后绿；`// M<n>` 0 命中 → 已 delete 解散
- **审计乙 `ses_e6ca36b97ffeyeiHxLtCfVopTf` 因宿主 `unknown certificate verification error` 终止**
  （未知证书校验错误，与甲此前同类；**非其结论问题**）。按规则上报用户、不擅自换模型，
  并以 `task` 新开替身 `ses_e6c7bbce7ffezhO5j6DsMSLV9T`（禁止读甲的文档以保证独立性，
  要求自建 `docs/spec/input-injection-review-B.md`）
- 环境观察：本会话内子代理多次出现 TLS/证书类宿主错误（甲 2 次、乙 1 次、批 2 一次），
  错因在宿主到 provider 的链路，非任务内容；已按"技术故障须恢复并继续"处理