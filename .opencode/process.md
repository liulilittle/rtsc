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

## 第774-792轮（已压缩摘要，原 200 行）
- 774/776：D1（OpenSSL drain 语义）修复 + 执行 AI 一次违规（未按门禁先取证）；84cf12b。
- 777/778：OpenSSL server 角色 + 证书主机名 4 类缺陷首次暴露；双审派发。
- 780：探针实证「服务器 stub 101 → 无 Accept」被我误记为成功；暴露"报告结论须回抄原始输出"。
- 781-786：ccSLD 447 条 + RFC6455 Accept 入库 407d03e；"裸域通配"两审一致错误，执行 AI 正确。
- 787：发现 P0「服务器只能看不能操作」；派双审（Win32 注入 / 协议丢字段）。
- 790/792：滚轮单位=120/格、9 位二补码、clamp 在单位域；甲纠正我"对称 ±255"表述。
- 证据与教训已转入 discover.md 第 780-792 轮条目与 memory.md 第 63-71 条。

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
## 第800轮：批 4 注入器骨架盖章 `afb2a69`
### 交付（执行 AI `ses_e6ca5a01dffev0jAbAmzlThKIa`，已 delete 解散）
- 新增 `desktop_input.h`（`InjectGeometry`/`DesktopInputSink`/`MakeWin32DesktopInputSink`）、
  `desktop_input_map.h` + `desktop_input_map.cpp`（`TranslateInput` 纯函数）、
  `desktop_input_win32.cpp`（单工作线程、队列 256、250Hz 移动合并、满队先丢最旧移动、
  `ReleaseSession` 补 up、`SendInput` 失败计数 + 5s 限流、`dwExtraInfo=0x52545343`）、
  `desktop_input_null.cpp`、`tests/test_desktop_input.cpp`（14 用例）
- `server.h:144` `enable_desktop_input=false`；`server.cpp:1173` SetGeometry、
  `:1720/:1848` 快/慢路径 Inject（均在 `input_callback_` 之前，且以
  `config_.enable_desktop_input && input_sink_ != nullptr` 门控）、`:2011` SetInputSink、
  `:2171/:2238` teardown 调 `ReleaseInput`（`input_released_` 幂等）
- `main.cpp`：`--allow-input`（默认 off）、`--allow-input-unverified`；
  危险组合拒绝启动（EXIT=2）

### 主代理独立复验（不采信子代理）
- `[BASH: cmake --build]` exit=0, warn=0, err=0
- `[BASH: ctest 全量]` **63/63 passed**（65.46 s；新增 desktop_input 套件）
- `[BASH: rtsc_server_host.exe --allow-input --no-enhanced]` → **EXIT=2** + 三条拒绝说明
- `[BASH: ... --allow-input --allow-any-credentials]` → **EXIT=2**
- `[BASH: 默认启动]` → `input=off`
- `[READ:server.cpp:1719-1720]` 注入门控正确；`[READ:server.cpp:695-701]` `ReleaseInput` 幂等
- `[READ:desktop_input_map.cpp]` kWheel 注释明确"**不得再乘 120**"
- 提交 `afb2a69`

### 未验证（真机才可验，如实记录）
- Win32 sink 运行时行为（250Hz 合并/满队丢移动/补 up/限流日志）—— 会动真实键鼠，未实跑
- `--monitor N` 非默认虚拟屏下的多显示器原点偏移；`InjectGeometry` 仅有 w/h
- 注入会话 id 归属无集成测试（`tests/test_server.cpp` 属其他批次）
## 第801轮：审计乙（替身）复核完成 → 无 FAIL，7 条残余发现；批 6 已派
### 乙报告（`docs/spec/input-injection-review-B.md` 418 行，独立，未读甲文档）
- 规范逐值核对（自 webfetch）：`inputFlags` 规范无 0x0002、代码默认 `0x013D` PASS；
  慢路径 7 个 messageType + 6 字节事件体（总 12B）逐值一致 PASS；
  `TS_RELPOINTER_EVENT` 的 PTRXFLAGS_BUTTON1/2 合法、代码正确 PASS
- 语义零分叉（慢路径 MOUSE/MOUSEX 与 fast-path 共用 `DecodePointerEvent`）
- 变异红证：慢路径 `0x8001→0x8003` → `test_server.cpp:1612 got 0 want 2`（40/425/1）→ 恢复 40/433/0；
  `wheel_delta*120` → 4 用例红（14/57/4）→ 恢复 14/57/0；均 SHA256 双证
  （**并如实记录：首次增量构建未重编 server.cpp，强制重编后才红，排除假绿**）
- `afb2a69`：映射/队列/安全门（EXIT=2 实测）/生命周期 PASS
- 残余：F-1 慢路径 MOUSEREL 只计数不解码（**与我的提交信息「0x8004 解码」不符**）、
  F-4 满队且无移动可驱逐时键事件可无界增长、F-5 注入计数无访问器、F-6 `last_move_sent_` 未清、
  F-7 `SetInputSink` 未注明须 Start 前调用；另有 GAP② numberEvents 不符不计数、GAP④ `was_share_data` 误判
- 乙任务完成 → delete 解散

### 批 6 已派 `ses_e6c42f2ccffeyE0TdeJePOYUxQ`（裁决 6 项）
1. F-1/GAP③：慢路径 MOUSEREL 用与 fast-path 同一套 `kMouseRel` 语义解码，**不再计入 unknown**
2. F-4：新增 `kHardQueueLimit`（4×kMaxQueue=1024），满且无可驱逐移动时**丢弃新事件并计数**（fail-closed）
   建议抽出纯函数 `DecideEnqueue` 以便单测
3. F-5：`DesktopInputSink::Stats()`（injected/dropped_queue_full/send_failures）
4. F-6：`ReleaseSession` 清除 `last_move_sent_`
5. F-7：`SetInputSink` 注释写明"必须在 Start 之前、server 不拥有 sink"
6. GAP②：`numberEvents` 不符时计数；GAP④：`was_share_data` 只对白名单 `ShareDataPduType` 置位
### 第801轮：甲2 复核文档落地 + 真机验证清单
- `docs/spec/input-injection-review-A.md`（32,733 B）已落地，含 A.1-A.8：
  映射/绝对归一化/按钮 1..5/wheel 直通/kMouseRel 空/门禁默认值/危险组合拒绝/注入门控/
  ReleaseInput 幂等/live 前释放/借用指针/id 单调/队列线程/tag/CMake；
  本地变异（`wheel_delta*120`）→ `FAIL test_desktop_input.cpp:147/159/172/207`（14/57/4）→ 恢复 14/57/0；
  另跑 `server 40/433/0`、`multisession 7/184/0`
- 主代理新增 `docs/spec/input-injection-real-machine-checklist.md`：
  把全部 UNVERIFIED 项整理为可执行清单（键盘/鼠标/UIPI/多会话/安全隐私/慢路径/设计不注入）
### 第801轮：甲2 复核完成 → 7 项全 PASS，无阻断 FAIL；已 delete 解散
- 映射/门禁实跑（`input=off` EXIT=0；`--no-enhanced` EXIT=2；`--allow-any-credentials` EXIT=2；
  `--allow-input-unverified` 启动+显著 WARNING）/门控与生命周期/线程队列/tag 全 PASS
- 独立变异：`git archive afb2a69` → `wheel_delta*120` → `FAIL test_desktop_input.cpp:147/159/172/207`
  （got 14400 want 120）→ 恢复 14/14 绿；干净构建 host EXIT=0；`server_tests 40/40`、`multisession 7/7`
- **甲2 新增残余（非阻断）**：
  ① 多显示器：`VIRTUALDESK` 但 `InjectGeometry` 只有 w/h，多屏坐标会偏 → UNVERIFIED
  ② `scancode==0` 未在映射层过滤（解码层已不产幻影 kKey）
  ⑤ 无 sink/服务器集成测试
  ⑥ 设计文档要求 `max_input_sessions=1`（单会话控制租约）**未实现**
  ③④ 与乙的 F-4/F-6 同（队列软上限、`last_move_sent_`）→ 已在批 6
- 处理：②⑤⑥ 与批 6 同文件冲突 → 排入批 7（待批 6 落地）
## 第802轮：批 6 盖章 `4eb3344`；批 7（租约）派发
### 批 6 交付（执行 AI `ses_e6c42f2ccffeyE0TdeJePOYUxQ`，已 delete 解散）
- F-1 慢路径 MOUSEREL 复用 `kMouseRel` 语义（`server.cpp:1886`，`rel_x/rel_y` 有符号）
- F-4 `DecideEnqueue` 纯策略（`desktop_input_map.cpp:102`）：`size<soft → accept`；
  `has_movable_move → evict`；`incoming_is_move → drop`；`size>=hard(1024) → drop`；否则 accept
- F-5 `DesktopInputSink::Stats`（injected/dropped/send_failures），null sink 也实现并进测试
- F-6 `ReleaseSession` 清 `last_move_sent_` + worker 锁内先 drain
- F-7 `server.h:292` 注释"必须 Start 前调用、server 不拥有 sink"
- GAP② `malformed_input_pdu_count()`（`server.h:372`/`server.cpp:2376`）
- GAP④ `IsKnownShareDataPduType`（`server.cpp:550`）白名单，`non-known` 不再吞 fast-path 输入
- 变异：MOUSEREL 收回、删硬上限、删 GAP②/GAP④ 均红；第三次变异因 Win32 时序不可测改为纯函数替代（如实记录）
### 主代理复验
- `[BASH: cmake --build]` exit=0 warn=0 err=0；`[BASH: ctest 全量]` **63/63 passed**（63.53 s）
- `[READ:server.cpp:1886]` kMouseRel 解码就位；`[READ:server.cpp:550/1627]` GAP④ 白名单就位；
  `[READ:desktop_input_map.cpp:102-109]` DecideEnqueue 逻辑与裁决一致
- 提交 `4eb3344`
### 批 7 已派 `ses_e6c0f1016ffeiljLXtRWhCoIOc`
- `max_input_sessions=1` 控制租约（默认 1，0=不限制）+ `input_lease_denied_count()`
- `TranslateInput` 过滤 `scancode==0`
- sink↔server 集成测试（不含注入真实桌面）：关=从不调用；两会话只有一个到达；
  断开后移交；`ReleaseSession` 幂等一次

## 第803轮：批 7 盖章 `3f30939`（单会话租约）+ W8 裁剪
### 主代理复验
- `[BASH: cmake --build]` exit=0 warn=0 err=0；`[BASH: ctest 全量]` **63/63 passed**（69.38 s）
- `[READ:server.cpp:806-822]` `AcquireInputLease`：`max_sessions==0` 不限、槽位空闲才授予、
  已完成租约直接 true；`:1863/:1991` 两条输入路径注入前取租约
- `[READ:desktop_input_map.cpp:38]` `scancode == 0` 返回空
- 提交 `3f30939`；执行 AI 已 delete 解散
### W8 裁剪
- `process.md`：774-792 压缩为 7 行摘要（原 ~200 行），保留 793+ 全部细节
- `discover.md`：2026-10-28..10-31 早期 240 行压缩为 9 行摘要 + 指向 memory/git
- 四个文件当前规模：process ~450 行、plan ~510 行、memory ~660 行、discover ~600 行
### 已派双审（新会话，互不读文档）
- 甲3 `ses_e6be4554cffeCGbfgAQwB7ugVJ` → `docs/spec/input-lease-review-A.md`
- 乙3 `ses_e6be441eeffe3wfWvs7rNMZx2a` → `docs/spec/input-lease-review-B.md`
- 被审：`4eb3344`（慢路径 MOUSEREL/队列硬上限/Stats/GAP②④）+ `3f30939`（租约/scancode 过滤/集成测试）
## 第804轮：双审（甲3/乙3）一致确认 4 缺陷 → 批 8 已派；批 9 排期
### 两审独立结论（互不读文档，结论一致）
| 编号 | 缺陷 | 严重度 | 两审 |
|---|---|---|---|
| F1 | 硬限丢 keyup → 永久卡键（`Inject` 先 track 后入队；硬件限 `kDrop`；teardown 的 `pressed_` 已空） | 中（必修） | 甲3 + 乙3 独立同证（含行号） |
| F4 | 未定义 `pdu_type2` 不置 handled → 回落 fast-path → 24B 畸形包产出幻影输入 | 中 | 甲3 + 乙3 独立证实 |
| F3 | 不可注入事件（kSync/kMouseRel/scancode0/unicode0）也取得租约 → 单个 SYNC 可永久占租约 | 中 | 乙3 新增 |
| F2 | `ReleaseInput` 先 erase 租约再 `ReleaseSession` → 交接窗口旧会话 up 误抬新持有者键 | 低 | 甲3 + 乙3 |
- PASS：租约加锁/单写者/无嵌套锁/无 TOCTOU、max=2 回收、teardown 同线程与 FIFO、性能量级
- 变异：删 `ReleaseInput` 的 erase → handoff 红（`test_server.cpp:3503/3505/3510/3511/3520`），
  恢复后 blob `63AF4373…` == archive 一致、`46/46` 绿；探针 `denied=10/distinct=1`、`max2 denied=0/distinct=3`
### 批 8 已派 `ses_e6bc992deffenVmgT8Erp1E1K8`（F1/F2/F3/F4 + 过时注释）
- F1 双修：`incoming_is_release` 优先 `kAccept`（释放事件有界）；`TrackPressedLocked` 改为**入队确认后**再调用
- F4：share-data 头解析成功但 `pdu_type2` 未知 → 丢弃并计数，**禁止**回落 fast-path
- F3：先 `sink->ReleaseSession` 再 erase 租约
- F4-甲3：仅"可注入事件"才申请/持有租约（不可注入事件直接回调）
### 批 9（待批 8 落地）：规范回写 + 限流/告警
- `docs/spec/input-injection-seam.md` §1.5/§2.3 回写（软 256/硬 1024、kMouseRel 已上送）
- 实现设计中的限流（单会话 400evt/s、全局 1000evt/s、`dropped_rate_limited`）+ 启动行 lease-denied 可观测
## 第805轮：宿主 TLS/证书错误反复出现 + 批 8 重派在途
### 环境问题（已按要求上报用户，不擅自换模型）
本会话累计出现 5 次宿主侧错误：`unknown certificate verification error` ×3（甲、乙、批 4 期间）
+ `upstream_rejected` ×1（批 8 原会话）+ 本回合再次 `unknown certificate verification error`。
特征：**子会话独立失败、主会话可恢复**；同一任务换新会话后通常能继续。
处置：按"技术故障必须恢复并继续"执行；新会话 + 缩短提示词是最有效的规避手段（已两次验证有效）。
### 批 8 重派进度（`ses_e6bb95522ffe6x9mgbfKberrav`）
- 已落盘：`desktop_input_map.h` 增加 `incoming_is_release`（win32.cpp:218 赋值 `IsRelease(input)`）；
  `server.cpp:817` `if (!IsInjectable(ev)) return;`（不可注入事件不取租约）；
  `server.cpp:2479` `malformed_input_pdu_count()` 访问器
- 尚未验证：`TrackPressedLocked` 位置（:125 仍先于入队？需在交付后逐行核对 F1 第二修）、
  未知 pdu_type2 是否禁止回落、`ReleaseInput` 顺序
## 第806轮：批 8 验收提交 `334d5a1`；批 8 审计 + 批 9 并行派出
### 主代理独立验收（不采信子代理数字）
- `cmake --build build --config Release` → exit=0 / warn=0 / err=0
- `ctest --test-dir build -C Release` **独占**运行 → `100% tests passed, 0 tests failed out of 63`（76.07s）
- **踩坑复现**：我在执行 AI 仍跑测试时启动全量 ctest，先后失败 `tls`、另一测试；单独重跑 `tls` 绿。
  → 并发 ctest 抢端口 = 伪失败（与既有记忆一致）。**判定绿必须独占运行**，不得与任何在途测试重叠。
### 逐行核对（W5 证据）
- F1 ①：`desktop_input_win32.cpp:124-126` 仅 `if (EnqueueLocked(...)) TrackPressedLocked(...)`；② `desktop_input_map.cpp:110-114` 注释+`incoming_is_release → kAccept`（在 `size>=hard_limit` 之前判断）✅
- F4：`server.cpp:1712-1724` 未知 type → `malformed_input_pdus_+1` + `handled=true` + `return true`，注释明确"禁止回落"✅
- F3：`server.cpp:767-778` 先 `ReleaseSession` 再锁内 erase，`input_lease_held_=false` 在 ReleaseSession **之前**置位（防重入）✅
- F4-甲3：`desktop_input_map.h:79-94` inline `IsInjectable`；`server.cpp:814-821` 未持租才判可注入并申请；持租者仍转发以保留 unsupported 统计 ✅
### 决策确认（执行 AI 提的两点）
1) `IsInjectable` 内联：接受（`rtsc_server` 不链接 map 库，CMakeLists 不在允许集；inline 不新增链接边）。
2) `kMouse` 判据取 `is_move || button != 0`：接受（与 `TranslateInput` 锁步，裸 kMouse 无动作；测试已交叉核对全 kind）。
### 已派
- 批 9 `ses_e6ab06c78ffeQTe3h03doOnxm7`：限流 400/1000（释放豁免）+ `dropped_rate_limited` + 启动行/首发拒绝 WARN + seam 文档回写（§1.5/§2.3/§2.4）
- 审计批 8 `ses_e6ab05ac0ffe2Kl0U2SjT4zrPu`：独立复核 334d5a1（release 有界性/白名单完备/IsInjectable 锁步/回归），产出 `docs/spec/input-lease-review-C.md`
## 第807轮：审计 C 判 F1 FAIL（release 恒接受 → 硬限失效）→ 已并入批 9
- 审计 C（`docs/spec/input-lease-review-C.md`）：F4/F3/F4-甲3/回归 PASS；**F1 FAIL**：
  `DecideEnqueue(size=5e6, release)` 仍 `kAccept`（探针），单条 32KB PDU ≈16,382 keyup 入队，O(N²)
- 修法（已下发给批 9 会话，同文件避免并发）：`held_release` 仅在 `pressed_` 中仍持有该键/按钮时才豁免
- 另要求：补"硬限丢 press 后 `pressed_` 不含该键"测试（遮盖 `TrackPressed` 变异缺口）；
  禁止"5000 release 全允许"断言；`server_undefined_share_data_type` 先轮询计数再断言空
- 审计 A/B 会话均已解散，其 relay 超时属正常
## 第808轮：批 9 唤醒后核查（未提交工作树）
- 已实现 `held_release`：`desktop_input_map.cpp:116`（`incoming_is_held_release → kAccept`）、`:159-164`（`AdmitInput` 传递）、`desktop_input_win32.cpp:127-128`（`IsHeldRelease` 于入队前计算）
- 已实现限流：`desktop_input_map.cpp:191-194`（`InputRateLimiter::Allow`，release 豁免）、`desktop_input_win32.cpp:34-36` 注释 400/800 + 1000/2000、`:161` 暴露 `dropped_rate_limited`
- 新测试（[BASH: Select-String tests]）：`:327` held release 接受、`:341` 非 held 硬限丢弃、`:364` held 接受且 untracked、`:387` 按钮释放豁免、`:411` unicode 释放不豁免、`:433` **硬限丢 press 不 track（补变异盲区）**、`:469-584` 6 条限流测试、`:598` IsInjectable 交叉、`:656` 启动状态/拒绝
- 待办：等批 9 relay 报告 → 主代理独占全量 ctest → 独立审计 held_release 上界与限流语义
## 第809轮：批 9 提交 `27cf199`；双审 D/E 已派
### 主代理验收
- 构建 `exit=0 warn=0 err=0`；**独占**全量 ctest `0 tests failed out of 63`（68.72s）
- 逐行核对：`desktop_input_win32.cpp:127-128` held_release 于入队前求值；`:192-204` 仅 kAccept 才 push 并 track；
  `desktop_input_map.cpp:116` held_release 才 kAccept；`:191-207` 限流拒绝时两桶都不扣；`:324` 出队后 SendInput 前限流；
  `AppendReleasesLocked` 仅遍历 `pressed`（有界）
### 我已发现、待审计 D 独立确认的疑点
`TrackInput`（`desktop_input_map.cpp:121-133`）对 **任意 scancode** 插入 `pressed.keys`：scancode 空间
`0x00-0xFFFF` + extended 位 → 最多 ~131,072 项，恶意对端可把"有界公式"从 1024 抬到 ~132k（约数 MB）。
虽非"无界"，但违背 §1.5 意图；若审计 D 同判 FAIL，修法方向：以**实际按下的 VK**（≤256）为键，
或在插入时按 VK 槽位去重（同 VK 多 scancode 只保留一个并强制释放最旧者）。
### 已派
- 审计 D `ses_e6a5ce98dfferVQXZ3ELT8rso3`：上界严格证明 + `pressed` 无界性 + 键身份互逆
- 审计 E `ses_e6a5cdca5ffeqKrf15sNRXIOrl`：限流语义/时钟/`sessions_` 增长/移动绕过/文档一致
### 环境
批 9 结束后再次 TLS 证书错误（累计第 6 次），任务已完成并已 delete。
## 第810轮：审计 E 第 1 轮结论（4 类 FAIL）→ 待与 D 交叉后定案
审计 E 报告 `docs/spec/input-rate-limit-review-E.md`（35 tests/3759 checks 基线绿，`/W4 /WX` 零错）：
| 项 | 判定 | 要点 |
|---|---|---|
| 1a/1b/1c 桶参数/steady_clock/时钟倒退 | PASS | 800=2s、2000=2s；`now<=last` 直接返回 |
| 2 拒绝不扣令牌 | PASS | 两桶任一不足即返回，不部分扣减 |
| 4 移动绕过限流 | PASS（有漂移） | `Dispatch` 先 `Allow` 再入 `pending_moves_`；`Emit` 不再过限流 |
| 5a/5b Stats 双后端 | PASS | 字段一致；两计数器不重复计数同一平台动作 |
| 7 变异真实性 | PASS | 去释放豁免 / 速率设无穷 均转红 |
| **1d sessions_ 增长** | **FAIL（E3/E4）** | 断开会话仍有排队项 → `Dispatch→Allow` 重新 `sessions_[id]` 插入，且该 id 不再被 Forget；`pending_moves_` 残留导致断开会话的过时移动仍被注入 |
| **3 释放豁免语义不一致** | **FAIL（E1/E2）** | 限流用 `IsReleaseInput`（不看是否 held）→ **100 万条未持有 up 全放行**（实测 `allowed=1000000`）；且"限流丢弃的按下仍被 `TrackInput` 记为 held" → `pressed` 可涨到 131,077，`hard_limit + 2×|pressed|` 实测上界远大于文档承诺 |
| **5c 运行期不可观测** | **FAIL（E6）** | 生产代码**从不调用** `Stats()`（全仓唯一调用在测试），`dropped_rate_limited`/`dropped_queue_full`/`send_failures` 对外不可见；`lease_denied_reported` 只打印一次，与 plan 的"周期性汇总"不符 |
| **6 文档漂移** | **FAIL（E7）** | a 上界漏 `2×`；b 漏"未注入按下的 up 仍豁免"；c 移动 250Hz 表述不实；d 失败日志无"恢复"态；e §2.3 释放豁免前提错；f "事件"口径实为"平台动作" |
- 关键量化：限流后未持有 up 仍可达 worker 满速（10^4–10^5 evt/s）→ **限流对"非 held 释放"完全失效**
- 最小修法（审计建议 A 方案）：`QueuedInput.exempt_release` 由入队决定写入（`held_release` / 合成 up = true），
  `Dispatch` 用该字段而非 `IsReleaseInput`；`IsReleaseInput` 降级为"仅用于识别释放类型"
- 下一步：等审计 D（上界证明）→ 两者交叉 → 批 10 修 E1/E2/E3/E4/E5/E6/E7
## 第811轮：审计 D 完成（上界闭合，我的疑点被驳回）→ 批 10 可派
### 审计 D 结论（`docs/spec/input-lease-review-D.md`）
| 要点 | 结论 |
|---|---|
| 1 所有 push_back 有界 | PASS（峰值口径） |
| 2 pressed 上界 | PASS = **515**（scancode 是 uint8_t，非 131k） |
| 3 键身份互逆 | PASS |
| 4 其它丢弃点 | PASS（teardown 兜底） |
| 5 变异真实性 | 目标测试必红，但 **M3/M4 存活 = 覆盖缺口 FAIL** |
- 峰值不变式：`peak(queue) ≤ 1024 + 515 = 1539`（探针 3 轮一致）；字面公式瞬时违反 774 次
- 必修：D-A 文档改峰值口径；D-B 补 2 条用例使 M3/M4 转红；D-C 抽纯函数解决 win32 零覆盖；
  E1 限流前移到 `Inject()`（已持 `mu_`，可一并消 E2）；D-G 生产代码从不调用 `Stats()`
### 与审计 E 的一致点
E1 两审独立同证 FAIL（未持有 up 全放行）。E2 被 D 降级为低（上界仍 515/1539，非 128× 膨胀）。
### 批 10 范围（合并 D+E）
D-A/D-B/D-C + E1/E2/E3/E4/E5/E6/E7，顺序：先补测试（先红）→ 限流前移 → 抽纯函数 → 回写文档 → 重跑 M1-M4 变异
## 第812轮：审计 D 已终结解散；批 10 执行在途
- 审计 D 最终报告要点（已并入第811轮记录）：峰值上界 1539 闭合 F1；pressed=515；M3/M4 变异存活；win32 零覆盖
- D 已 relay E 并已完成，按第12条 delete 解散
- 批 10 会话 `ses_e6a3704cdffeVfAuA0Txe5uDnq`：D-A/D-B/D-C + E1-E7，顺序 补测试→限流前移→抽纯函数→文档→M1-M4 变异
- 审计 E 会话 `ses_e6a5cdca5ffeqKrf15sNRXIOrl`：已令其与 D 交叉定案（D 已回），待终稿
## 第813轮：审计 E 终稿（两审交叉定案完成，双审均已解散）
### 审计 E 终稿（`docs/spec/input-rate-limit-review-E.md` 451 行）
- PASS：1a 桶参数、1b steady_clock、1c Refill 倒退封顶、2 拒绝不扣令牌、4 移动每移动只 Emit 一次（≤400/1000/s）、5a Stats 双后端、5b 两 dropped 不重复、7a 指定变异
- FAIL：1d/E3（`sessions_` 泄漏，每次高负载断连泄漏 1 桶 sizeof=48）、3/E1+E2（未持有 up 无速率上界，100 万条全放行；限流丢弃的 press 仍记 held）、5c/E6（生产代码从不读 Stats）、6/E7（上界瞬时 vs 峰值、事件 vs 平台动作口径）、7b/E8（M3/M4 变异存活）
- **审计 E 自纠**：撤回上一轮 `|pressed| ≤ 131,077`（与 D 一致为 515）；撤销 E4（`ServeOne` 无 try/catch，无红证且非本批引入）→ 降为 W5 观察
### 两审交叉定案
- 一致：E1 FAIL、E2 现象真但低、E3 低、`|pressed|=515`、峰值 1539、瞬时不变式不成立、E6、M3/M4 存活、win32 零覆盖
- 分歧已裁定：`seam.md:263-264` 归属为 `b369d75`（非 27cf199），判定不变（实现与既有文档冲突）
### 批 10 工作树复验（审计 E 独立快照）
- 已达成：E1/E2（`100000 unheld ups: accepted=0 rate_limited=100000`；held up 豁免；`rate_limited press: tracked_keys=0`）、E8（M3/M4 已转红）、win32 `cl /W4 /WX` exit=0
- **仍红**：E6 未实现（`40 tests, 9602 checks, 1 failing, 7 failed checks`，缺 main.cpp 的 Stats 打印串）
- 已向批 10 追加：E6 实现 + `seam.md:252-254` 与 map.h 注释同步（Allow 自计数，caller 不得再计）+ E7 峰值口径与"平台动作"口径 + E3 若未修必须修
### 双审会话状态
审计 D、审计 E 均已完成并 delete 解散。当前在途仅批 10 `ses_e6a3704cdffeVfAuA0Txe5uDnq`。
## 第814轮：批 10 提交 `63e3cc6`；双审 F/G 并行派出
### 主代理独立验收（不采信执行方数字）
- `cmake --build build --config Release` → exit=0 / warn=0 / err=0
- `ctest --test-dir build -C Release` **独占** → `100% tests passed, 0 tests failed out of 63`（64.46s）
### 逐行核对（W5）
- D-C：`desktop_input_map.h:204-237` `AdmitOutcome` + 模板 `AdmitAndTrack`（①held 判定 ②限流闸 ③通过后才 `AdmitInput`）；
  `desktop_input_win32.cpp:211-216` 接线，闸门 lambda 传 `held_release` ✅
- E1：`map.h:264-268` `Allow(session_id, held_release, now)`；注释明确"必须传 IsHeldRelease 而非 IsReleaseInput"、
  "拒绝由 Allow 自己计数，caller 不得重复计数" ✅
- E2：`AdmitAndTrack` 内限流先于记账 → 被限流的 press 不入 `pressed` ✅
- E3：`win32.cpp:120-127` `forget_sessions_` 命中即丢弃并计 `dropped_unsupported`，不复活 session/桶 ✅
- E6：`main.cpp:657-665` 5s 采样 Stats + 1s lease 汇总，仅计数变化才打印 ✅
### 决策记录
- 执行 AI 报告 `e6f57fd`（我的记忆提交）把其 `docs/spec/input-injection-seam.md` 改动一并入库 —— 属我 `git add -A docs` 的副作用，
  内容本身是执行方按我指令写的，无冲突；已确认代码/测试 7 文件当时仍未提交，现已随 `63e3cc6` 入库。
  **教训：`git add -A docs` 会把子代理正在写的文档一起提交，提交前应逐个文件确认归属。**
### 已派（并行）
- 审计 F `ses_e6a12ff22ffeOCGAtI9LBFGDR6`：队列/记账/生命周期侧（D-A/D-B/D-C + E2/E3/E4/E8）
- 审计 G `ses_e6a12f026ffeby215OzUpiyD2S`：限流/可观测/文档侧（E1/E5/E6/E7）
## 第815轮：审计 G 完成（E1/E5/E6 PASS；E7 低危文档漂移 4 处 + 测试缺口 E1-T）
### 审计 G 结论（`docs/spec/input-batch10-review-G.md`）
- E1 PASS：probe9 `800 presses → 5000 unheld ups allowed=0 dropped=5001`；`799 presses → 100000 held ups allowed、dropped_delta=0`；
  保留的 1 令牌仍可花；unicode up 受限；全局拒绝后 1s 会话 1 仍花 401（400+保留 1）
- E5 PASS：probe10 `10 条限流移动 dropped_delta=10`（无 caller 二次计数）；`kEvictMove` 决策 `rate_limited=0 tracked=1`
- E6 PASS（2 条低危保留）：实跑 `host --seconds 2` → `input stats (final)` 四计数=0
- 变异真实性 PASS：mutA/mutA2/mutB 各自指定测试红 → restored `40/9602/0` 绿
- **E7 FAIL（低）**：4 处文档/注释漂移（见下）
- **E1-T 测试缺口**：mutC（held up 豁免但扣令牌）40/9602/0 **存活** → "held up 不耗令牌"无用例钉住
### E7 四处（均不动产品逻辑）
1) `seam.md:137` + `win32.cpp:26-27`：peak 1539 只对"对端可入队事件"成立；`AppendReleasesLocked`（`win32.cpp:232-254`）
   无上限 push 合成 up 且 purge 保留 synthetic（`307-315`）→ 必须补"合成 up 额外 ≤ 会话数×515"
2) `desktop_input.h:41-43`：`dropped_queue_full` 定义漏"会话结束时 purge"（`win32.cpp:310`）
3) `seam.md:168`："退出前终值"须限定为正常退出（`--seconds`/`--once`）；无界模式 Ctrl+C 无 SIGINT 处理
4) `seam.md:170`："Inject 返回 false" 过期（`Inject` 是 void，`desktop_input.h:71`）
### E1-T 修法
补用例"799 presses → 100 held ups → 保留令牌仍可花"，使 mutC 转红。
### 状态
审计 G 独立稿已出，已 relay 审计 F 请求交叉验证；审计 F 仍在途。
## 第816轮：审计 G 收口中（不再等待 F 交叉）
- G 的独立稿已完成并 relay parent；其请求的 6 条反证问题因 F 仍在途无法即时答复
- 已令 G 改为「自证收口」：追加「批 11 验收判据」节（E7-a/b/c/d + E1-T 的可勾选判定句）
  + 给出 mutC 的确切变异点（改哪行、原式与新式），供执行 AI 复现
- 决策依据：两审不必然互相回执；G 的结论已被主代理采信并写入 plan.md 批 11 定案，
  继续等待交叉只会空转（G4b：无新信息必须换向）