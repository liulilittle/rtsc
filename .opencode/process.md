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


## 【归档压缩：793-805 轮（原 408 行）】

- **793** 循环恢复；执行 AI 无关工作 + 双审批判 Win32 注入设计。
- **794** `042687f` 滚轮语义修复 + 批 1 执行 + 双审复核。
- **795** 批 1 审计：生命周期、滚轮、队列、可观测性；批 1 再次派发。
- **796** 批 1 提交 `e0bee4b`。
- **797** 批 2 / 批 3 生成与派发；双审裁定 **B 方案规范胜出**（分块 + 慢路径 + 能力位），新增修改项。
- **798** 会话输入生命周期状态机路径分析。
- **799** 批 3 完成并提交 `10b3b20`（含失败回滚）。
- **800** 批 4 注入器骨架 `afb2a69`。
- **801** 双审 FAIL（7 项同源发现）→ 批 5；审计 B 报告 `docs/spec/input-injection-review-B.md` 418 行。
- **802** 批 6 `4eb3344`；批 7 单会话租约派发。
- **803** 批 7 `3f30939`（单会话租约）；W8 裁剪（774-792 压缩为 7 行摘要）。
- **804** 双审（3/3）一致确认 4 缺陷 → 批 8；批 9 派发。
  - F1 硬限 keyup / F4 未知 pdu_type2 / F3 顺序 / F2 `ReleaseInput` 中 erase 与 `ReleaseSession` 顺序
  - PASS：租约可重入/重写、无嵌锁、无 TOCTOU、max=2 无竞争、teardown 同线程 FIFO
- **805** 宿主 TLS/证书错误反复上报（用户环境/模型层面）；批 8 进行中。
## 【归档压缩】806-820 轮（输入注入：租约/限流/文档，原 192 行）

- **806** 批 8 提交 `334d5a1`（F1 卡键/F4 幻影输入/F3 顺序/不可注入不占租）；独占 ctest 63/63。
  教训：并发跑 ctest 抢端口 = 伪失败，判定绿必须独占。
- **807** 审计 C 判 **F1 FAIL**：我下的指令"release 恒接受"是**按事件类别豁免** → 硬限 1024 被绕过
  （`DecideEnqueue(size=5e6, release)=kAccept`，单条 32KB PDU ≈16k keyup 入队，O(N²)）。
- **809-811** 批 9 提交 `27cf199`（held_release 定界 + 限流 400/800、1000/2000 + `dropped_rate_limited`）。
  审计 D：峰值上界 `1024 + 515 = 1539` 成立（瞬时公式被证伪 774 次）；`pressed` 上界 **515**（scancode 是 uint8_t）。
  我"131,072"的疑点被驳回 → 第 20 例教训：值域必须追唯一写入源的实际类型。
- **813-815** 审计 E 终稿：E1（未持有 up 全放行 100 万条）、E2（限流丢弃的 press 仍记 held）、E3（`sessions_` 泄漏）、
  E6（生产不读 Stats）、E7（文档漂移）、E8（M3/M4 变异存活）。
- **814-818** 批 10/11 提交 `63e3cc6`、`b6fcaac`：限流前移 `Inject()`、`AdmitAndTrack` 纯函数、
  held-release 令牌留存用例、峰值两段式文档、真机清单补租约/限流/可观测三节。
  我另修正 `seam.md` §1.7 的过期描述（`session_id` 已非 0）。
- **819-820** 审计 F：**F-1 租约槽永久泄漏**（`ReleaseSession` 抛异常 → `holders.erase` 跳过）；
  批 12 提交 `a59a594` 修复（try/catch + 无条件 erase）→ 第 22 例：「幂等哨兵 + 可抛调用 = 永久损坏」；
  读码对异常路径系统性失明，必须用 throwing stub 测。

## 第821轮：批 12 验收提交 `a59a594`；双审 H/I 并行派出
### 主代理独立验收
- `cmake --build build --config Release` → exit=0 / warn=0 / err=0
- `rtsc_server_tests.exe` → `49 tests, 562 checks, 0 failing`
- `ctest --test-dir build -C Release` **独占** → `0 tests failed out of 63`（88.00s）
### 逐行核对（W5）
- F-1：`server.cpp:772-783` `try { ReleaseSession } catch (...) {}` 后**无条件** `holders.erase`（`:780-783`）；
  顺序仍"先 sink 后放槽"；注释说明"标志已置位，跳过 erase 会永久泄漏" ✅
- 文档：`seam.md:137` 峰值收紧 `kHardQueueLimit + 515·K` 并显式禁止 `1539 + 会话数×515`；
  `:202-221` 新增 §1.8「已知测试缺口：Win32 接线」列出 7 个未覆盖判定点 + CMake 证据链 ✅
### 执行方如实披露（值得记）
恢复变异时 `Copy-Item` 保留旧 mtime → MSBuild 跳过重编 → 测试仍红；touch 后转绿。
与既有记忆一致（变异测试必须 touch + 哈希双证）。
### 已派（并行）
- 审计 H `ses_e69a6bf2dffeFbfXYfLhYvCM97`：F-1 是否真闭合 + **同型缺陷全仓排查**（Stop/Close/scope guard/通道关闭/purge）
- 审计 I `ses_e69a6b007ffej3VD6pO5vTT2zt`：seam.md **全文与代码逐条对账**（行号失效/常量/P-1..P-12 状态过期/§4.4 变异表）
- 已令 H 与 I 直接互通（H 补 I 的文档核对、I 校正 H 的行号）
### 子代理
批 12 执行会话 `ses_e69c4df7` 已完成（待本轮结束后 delete）。
## 第822轮：双审 H/I 被平台中断（零输出）→ 已补发继续指令
- [BASH: get_goal] H / I 均 `idle`、`wrote=null`、无报告文件（`docs/spec/input-batch12-review-*.md` 不存在）
- 本轮均为"系统/平台中断（非用户停止）"，按任务调度条款经 `prompt` 直发原会话（附完整任务摘要），未新开替代
- 同步补发 H↔I 的互相对话 ID，保证磋商通道
- 本轮环境：再次出现 `Cannot connect to API` 宿主错误（子会话侧），累计已超 10 次；策略不变：压短提示词 + 原会话继续
## 第823轮：审计 H 完成（F-1 行为闭合，但同型 3 处可崩）→ 批 13 已派
### 审计 H（`docs/spec/input-batch12-review-H.md`）
- F-1：①erase 全路径执行 PASS ②顺序 PASS（变异 M2 红）③**catch 全静默 FAIL（低）** ④标志时机 PASS
- 同型排查（重点产出）：
  - **N-1** `win32.cpp:150-170` ReleaseSession append 抛 ⇒ erase/notify 跳过 + forgotten id 早退不 notify ⇒ worker 睡死
  - **N-2** `:513-530` Shutdown append 抛 ⇒ join 跳过 ⇒ thread 析构 terminate（由析构调用 ⇒ 杀进程）
  - **N-3** `:261-291` WorkerMain 无兜底 ⇒ terminate
  - N-4/N-5/N-6 `server.cpp:2461/2474`、`rdpsnd_server.cpp:47-49`、`rdpdr_server.cpp:39-52` 析构/Stop 无 catch
- 变异红证：M1 → `tests/test_server.cpp:3880`；M2 → `:3848`（`injects_during_release got 1 want 0`）
- 回归 63/63（84.81s）；`rtsc_server_tests` 3 次 `49 tests/0 failing`（checks 561/562/563 随 `tests:3852-3856` 循环调度浮动，非新用例）
- 文档：`batch10-review-F.md:340` 仍写"F-1 未修复"（过期）；`seam.md:137` 行号 `232-254/307-315` 应为 `236-258/311-319`
### 批 13 `ses_e69673c71ffeNPiDZ61bfvgTm9`
N-1/N-2/N-3/N-4/N-5/N-6 + `release_failures` 计数 + `input_release_failures=` 日志 + 两处文档修正 + 2 变异
### 子代理
审计 H 已 delete 解散；审计 I（seam 全文对账）仍在途。
## 第824轮：审计 I 完成（发现 P-6 行为缺陷：extended1 会切 NumLock）→ 批 14 已派
### 审计 I（`docs/spec/input-batch12-review-I.md`，seam.md 全文对账）
- **C1（最严重）P-6 未实现**：`extended1`（0xE1/PAUSE）已解码，但
  `desktop_input_map.cpp:31-49` 的 `kKey` 分支不看它、`desktop_input_map.h:132-147` `IsInjectable` 仍判可注入
  ⇒ 注入裸 Ctrl/NumLock ⇒ **PAUSE 会真的切换本机 NumLock**，违反 P-6④。T15/M6 无实现无测试。
- C2 §1.7 第 2 条成立：`desktop_input.h:31-34` 无 origin/virtual_desk，用协商几何（`server.cpp:1303-1308`），
  恒 `VIRTUALDESK`（`win32.cpp:413-421`），测试固化 64x48 ⇒ `--monitor N` 子矩形会错位
- C3 `map.cpp:21-27` `extent<=1` 1:1 透传（设计 T6 要求空+计数）；C4 `wheel_delta==0` 仍产出（T10 要求空）
- T4 中点期望 32767/32768 实为 32785；T12 前提过期；T13/T14/T15 未实现
- 状态列过期：P-1/P-2/P-3解码/P-4/P-5/P-9/P-10 已修（P-9 flags=0x013D 含 0x0020）
- §1.3/§1.4 接口名整体失效（实际 `DesktopInputSink`/`desktop_input.h`/`MakeWin32DesktopInputSink`/`Shutdown()`；
  文档无 `InputSink`/`CreatePlatformInputSink`/`ReleaseAll`）；文档内 `Inject` 返回值自相矛盾（§1.3 bool vs §1.6 void）
- §1.8 是全文**唯一**行号全对的小节（与审计 H 独立复核一致）
- 常量全部一致（256/1024、400/800/1000/2000、515/1539、kRefreshInterval=1000ms、kWheelStep=255、
  kWheelUnitsPerNotch=120、kMaxWheelChunksPerEvent=8、kInjectTag=0x52545343）；漂移只在行号/状态
- 约 75 条行号引用中约 48 条失效/过期；§2.5 诊断全未实现；`--input-share`/`--input-owner` 不存在（实际 `--max-input-sessions`）
- §4.4：M1/M4 有真实用例；M2/M3 部分（BuildNative 变异存活）；M5/M6 无覆盖，**M6 的"变异"当前就是实现**
### 批 14 `ses_e695daf83ffea99Y2dp6plWJZC`（仅 map.cpp/map.h/test_desktop_input.cpp，禁改 docs 以免与批 13 冲突）
C1 extended1 不注入（`TranslateInput` 返回空 + `IsInjectable` 排除）、C3 `width/height<=1` 不产出绝对移动、
C4 零滚轮不产出 + 3 变异
### 待办排期
批 15（文档全文重写：§0/§1.3/§1.4/§1.7/§4.1/§4.4 + 48 条失效行号 + 状态列）需在批 13/14 落地后单独立项，
避免与两个执行方同时改 seam.md
### 子代理
审计 I 已 delete 解散。在途：批 13（N-1..N-6）、批 14（P-6/C3/C4）。
## 第825轮：批 13 遭 `upstream_rejected` 终止（仅部分落盘）→ 已重派
- 现状核查：批 13 仅改 `include/rtsc/server/desktop_input.h`（`InputStats` 增 `release_failures` 字段 + 注释），
  `win32.cpp` 无任何 `release_failures`/`noexcept` 命中，`Shutdown`/`ReleaseSession` 未修 [BASH: Select-String]
- 处置：错误态会话已 `delete`；按任务调度经 `task` 新开 `ses_e69544b0effewGwtRR0Dimrtmo`，
  提示中明确"保留已有的 `release_failures` 字段并接通"，避免重复定义
- 并行状态：批 14 `ses_e695daf83ffea99Y2dp6plWJZC`（map.cpp/map.h/test_desktop_input.cpp）busy
- 文件隔离确认：批 13' 改 win32.cpp/desktop_input.h/server.cpp/rdpsnd/rdpdr/main.cpp + 两处文档；
  批 14 只改 map.cpp/map.h/test_desktop_input.cpp → 无重叠
- 环境：`upstream_rejected` 累计第 3 次（本会话宿主错误总数已超 12 次），仍未更换模型
## 第826轮：批 14 验收提交 `805428b`（P-6/几何/零滚轮）；批 13' 补发继续
### 主代理独立验收
- `cmake --build build --config Release` → exit=0 / warn=0 / err=0
- `rtsc_desktop_input_tests.exe` → `44 tests, 13741 checks, 0 failing`（原 41 → 44，新增 3 条）
- `ctest --test-dir build -C Release` **独占** → `0 tests failed out of 63`（70.43s）
### 逐行核对（W5）
- P-6 修复：`desktop_input_map.cpp:41-47` `if (ev.extended1) return out;`，注释明确"裸 scancode 会按到**另一个**物理键
  （裸 CTRL/NumLock）→ 切换本机键盘状态"；`desktop_input_map.h:139` `IsInjectable` 改为
  `ev.scancode != 0 && !ev.extended1`（与 TranslateInput 锁步）✅
- C3 几何：`map.cpp:78` 改为 `if (ev.is_move && g.width > 1 && g.height > 1)`，注释说明 1:1 透传会把指针放到错误位置 ✅
- C4 零滚轮：`map.cpp:105` `if (ev.wheel_delta == 0) return out;`，注释给出"滥发零滚轮可驱逐移动、饿死真实输入"的理由 ✅
- 新测试：`tests:85 extended1_is_not_injected`、`:260 zero_wheel_is_not_injected`、几何不可用用例（含 64x48 固化点的复核）
### 并行
批 13' `ses_e69544b0` 上一轮零输出（win32.cpp 无任何 `release_failures`/`noexcept`），已 `prompt` 补发完整任务摘要，
并提示"`InputStats.release_failures` 字段已存在，勿重复定义"
## 第827轮：批 13' 已落盘大量 teardown 修复（待其 relay 收尾）
### 现状（[BASH: Select-String win32.cpp]）
- `win32.cpp:176/184` `ReleaseSession` 两处 catch + `:185 release_failures_++`
- `:208-209` `Stats()` 接出 `release_failures`
- `:335` `WorkerMain() noexcept` + `:369/376` catch
- `:601-604` `Shutdown() noexcept` 注释"Teardown must be noexcept: it runs from the destructor" + `:615-648` 五处 catch
- `:682 std::atomic<uint64_t> release_failures_{0}`
- 同时改了 `rdpsnd_server.cpp`/`rdpdr_server.cpp`/`server.cpp`/`server.h`/`main.cpp`/`desktop_input_null.cpp`/CMakeLists
- 新增 `tests/desktop_input_win32_test_hooks.h`（把 Win32 层判定暴露给测试 —— 部分回应 F-2 覆盖缺口）
### 调度
- 批 14 会话 `ses_e695daf8` 任务已完成（其产物已于第826轮验收提交 `805428b`）→ 已 delete
- 批 13' `ses_e69544b0` 仍 busy（`wrote` 时间戳新），等其 relay 报告后统一验收
- 本主代理本轮不碰上述文件（避免与在写方冲突）
## 第828轮：批 13' 工作树中间态验证（未提交，等其收尾）
### 主代理实测（对当前工作树，非最终态）
- `cmake --build build --config Release` → exit=0 / warn=0 / err=0
- `rtsc_server_tests` → `49 tests, 563 checks, 0 failing`
- `rtsc_desktop_input_tests` → `46 tests, 13752 checks, 0 failing`（原 44 → 46，新增 2 条 = N-1/N-2 红证用例）
- `ctest --test-dir build -C Release` **独占** → `0 tests failed out of 63`（57.95s）
### 逐行核对（W5）
- N-1：`win32.cpp:174-196` `forget_sessions_.insert` 与 `AppendReleasesLocked` 各自 try/catch，
  `sessions_.erase(it)` 在 try 外**无条件**执行，`cv_.notify_one()` 在锁外无条件执行 ✅
- N-2：`win32.cpp:601-650` `Shutdown() noexcept`；注释"skipped join makes ~std::thread call std::terminate"；
  逐会话 append try/catch + `pressed` 清空 try/catch + `sessions_.clear()` try/catch；
  **notify_all + join 在锁外无条件**（`:640-641`）；`pending_moves_/last_move_sent_` 清理 try/catch ✅
- N-3：`win32.cpp:335 WorkerMain() noexcept` + `:369/376` catch ✅
- 计数：`:682 atomic<uint64_t> release_failures_`、`:208-209` Stats 接出 ✅
### 未提交原因
批 13' 会话仍 busy（`wrote` 时间戳新），文件仍可能变动；按"不与他人在写文件冲突"原则，
主代理本轮只做只读验证，不 `git add`。待其 relay 报告后统一提交。
## 第829轮：批 13' 验收提交 `6fc5614`；我自行发现 P-6 只修了一半
### 主代理验收（批 13'）
- 构建 exit=0 / warn=0 / err=0；`rtsc_server_tests 49/563/0`；`rtsc_desktop_input_tests 46/13752/0`；
  全量 ctest **63/63**（55.73s 执行方、57.95s 我复跑）
- 逐行核对：N-1 `win32.cpp:174-196`、N-2 `:604-653`（`noexcept` + 无条件 notify/join）、N-3 `:335-379`
  （`WorkerMain() noexcept` + `stopping_` 改原子）、N-4/N-5/N-6 三处析构/Stop catch、`release_failures` 三处接通
- 测试缝：`CMakeLists.txt:684-694` 仅 WIN32 + `RTSC_DESKTOP_TESTING` 下把 win32.cpp 编进测试并链 user32
- 已提交 `6fc5614`；批 13' 会话已 delete
### **我发现的未闭合缺陷（P-6 只修一半）**
`EncodePauseKey()`（`proto/input.cpp:90-102`）产生 `04 1D / 00 45 / 05 1D / 01 45`——**只有两个 CTRL 带 extended1**，
`0x45`(NUMLOCK) down/up 不带。批 14 只丢 extended1 ⇒ **NUMLOCK 仍被注入 ⇒ NumLock 仍被切换**。
已写入 `discover.md` 第 24 例；已把该追问下发给审计 K（`ses_e676f3ab6ffelV9lFbyt3lo9Ea`）独立确认。
### 已派双审
- 审计 J `ses_e676f4a60ffeJvOfQZOzd86Sb0`：teardown 复验 + **测试缝风险**（宏误定义/factory 编译掉/全局 hook 污染）
- 审计 K `ses_e676f3ab6ffelV9lFbyt3lo9Ea`：映射语义复验 + **PAUSE 全序列**追问（已明确要求实跑 4 事件序列并报告产出）
## 第830轮：审计 K 第 1 轮确认 P-6 FAIL(High)；批 16 已派
### 审计 K（`docs/spec/input-batch14-review-K.md`）
- **P-6 FAIL(High)**：4 事件产出 2 个 `0x45` 动作 → **NumLock 仍翻转**；"每次远程 Pause = 一次 NumLock 反转"
- 几何 PASS（按键/按钮保留正确；`NormalizeAxis extent<=1` 为不可达但有意保留的防御分支）
- 零滚轮 PASS（`IsInjectable` 同批已改 `!=0`，无矛盾）
- **测试覆盖 FAIL(Medium)**：变异 B（全局丢 0x45）**全绿存活** → 现有用例分不清"半修"与"NumLock 失效"
- 回归 PASS（`--clean-first` 零警告 + ctest 独占 63/63，两次）
- 修法：`PauseSequenceFilter` 平台中立状态机（照抄 K §1.4），在 `RdpSession` 中于 `InjectIfLeasable` **之前**过滤
  （PAUSE 不占租约、不入队、不耗令牌）；`ReleaseInput` 调 `Reset()`；`map.cpp:47`/`map.h:139` 的 E1 丢弃保留为第二道防线
- K 自跑红/绿：BASELINE（只丢 E1）→ `PAUSE actions got=2 want=0` 红；PROPOSED → 0 动作、单独 NumLock tap = 2、lone E1+2 taps = 2 全绿
### 批 16 `ses_e6743097dffe4H8z0Ie9fcxSqN`
`PauseSequenceFilter` + server 层过滤 + `Reset` + 2 条测试（desktop_input / server 端到端）+ 2 变异（回退半修 / 全局丢 0x45）
### 已令审计 K 收口
追加「批 16 验收判据」节、明确"4 事件是否同 PDU"的证据要求、给出 2 个变异的确切变异点，然后 relay parent 停止
### 在途
审计 J `ses_e676f4a60ffeJvOfQZOzd86Sb0`（teardown 复验 + 测试缝风险）+ 批 16
## 第831轮：批 16 验收提交 `c315ff8`（PAUSE 整体不注入）
### 主代理独立验收
- `cmake --build build --config Release` → exit=0 / warn=0 / err=0
- `rtsc_desktop_input_tests` → `47 tests, 13760 checks, 0 failing`
- `rtsc_server_tests` → `50 tests, 574 checks, 0 failing`
- `ctest --test-dir build -C Release` **独占** → `0 tests failed out of 63`（67.46s）
### 逐行核对（W5）
- `map.h:84-114` `PauseSequenceFilter::ShouldDrop`：非 kKey 不丢不动状态（注释说明"丢失的 PDU 不得吞掉后续 NumLock"）；
  `extended1` → arm 且丢（down/up 都置位，因 0x45 up 在 ctrl up 之后）；`ctrl_armed_ && 0x45 && !extended` → 丢，
  release 关窗；其它键关窗且不丢 → **上界：孤立 E1 最多吞一次 NumLock tap**，绝不吞光所有 0x45
- `server.cpp:836` 过滤点在 `input_sink_ == nullptr` 之后、**租约门之前**（`:837-840`）→ PAUSE 不占租约/不入队/不耗令牌 ✅
- `server.cpp:769-771` `ReleaseInput` 在 `input_released_` 置位后立即 `pause_filter_.Reset()`（早退路径也覆盖）✅
- 测试：`test_desktop_input.cpp:119`（四事件全丢/0 动作；tap=2；lone E1 只吞一次）、
  `test_server.cpp:1418`（PAUSE PDU → 注入 0 次 + 不抢租约；裸 NumLock → 恰好 2 次）✅
### 变异（执行方，%TEMP% 副本）
- M1 只丢 extended1（半修回退）→ `all_dropped`/`actions got 2 want 0`/`lone_actions got 4 want 2` 红
- M2 全局丢 0x45 → `tap_kept`/`tap_actions got 0 want 2` 红（证明确实能区分"误杀"）
### 未验证
真机 SendInput 下 NumLock 是否翻转（审计角色不动本机键鼠）→ 仍 UNVERIFIED，已列入真机清单
### 状态
批 16 会话已 delete；在途：审计 J（teardown + 测试缝）、审计 K（收口）
## 第832轮：审计 K 收口（批 16 盖章）+ 一条待办(kSync 不清 arm)
### 审计 K 复验（`docs/spec/input-batch14-review-K.md` §9/§10）
- 逐行复核全部 PASS：`map.h:84-114`、`server.cpp:836`（sink 空判后、租约门前）、`:771`（Reset 在
  `input_released_` 早退之后、`input_lease_held_` 早退之前）、`:2066` 每会话成员、
  `map.cpp:47`+`map.h:176` E1 兜底保留、**全仓唯一 `input_sink_->Inject` 出口 = `server.cpp:841`**（过滤器无法绕过）、
  `input_callback_` 独立调用（`:1916-1917`/`:2042-2043`）故诊断不被遮蔽
- 独立复跑：build exit=0 / 0 warn 0 err；ctest **63/63**（60.40s）；`47/13760/0` + `50/574/0`；四个文件 SHA256 与执行方逐字节一致
- **加固探针（10 断言，用仓库头文件实跑）**：per-event 漏 NumLock=2（复现 bug）、per-session 整序列=0、
  **拆成 4 个 PDU 仍=0**、独立 tap=2、lone E1+2 taps=2、`E1,A,tap`=2、`Reset()` 后 tap=2、
  **窗口内插入 mouse move 仍注入=1**、紧随的 NumLock=0、`SYNC` 时 armed 后 tap=0
- 变异 4 项（第16条）：M1 删 0x45 分支→红；M2a 全局丢 0x45→红；M2b map.cpp 全局丢→红；
  **M3 把过滤移到租约门之后→红**（证明"租约门前"是可测约束而非风格）；对照 ShouldDrop 恒 false→红；恢复全绿
### K 的 §10 验收判据 AC-1..AC-7（已全部满足）
AC-1 四事件全丢且动作 0；AC-2 独立 tap=2 且 `IsInjectable(0x45)=true`；AC-3 lone E1+2 taps=2（有上界）；
AC-4 `Reset()` 后 tap 可注入；AC-5 `ReleaseInput` 无条件 Reset；AC-6 PAUSE 不占租约/不进 sink/不耗令牌且 callback 仍收 4 事件；
AC-7 真机 NumLock 物理状态 → **UNVERIFIED**
### "4 事件是否同 PDU"的取证结论（K 给出，重要）
修复**不依赖**该假设（过滤器是会话级，探针已证拆 4 PDU 仍 0）。安全论证只需更弱性质，且已有仓库证据：
客户端同 PDU（`proto/input.cpp:90-102` + `client.cpp:357-360`，`tests/test_input.cpp:115-116` 断言 `0x10`=numEvents 4）；
`FastPathPdu::parse` 全有全无（`share.cpp:277-280`）；服务端不分片重组（`share.h:209-214` 仅枚举，全仓零使用点）
⇒ 截断的 PAUSE 整条丢弃。唯一 UNVERIFIED：第三方客户端是否也单 PDU（需真机抓包）。
### 待办（K 的两条非阻塞观察）
1) `rtsc_server_tests` 的 checks 数随 `WaitUntil` 轮次浮动（565/566/574）→ **验收只钉 `0 failing` + 用例名，禁止钉 checks 数**
2) `kSync` 不清 `ctrl_armed_`（`map.h:92` 只处理 kKey）→ "E1→SYNC→NumLock" 整组被吞；
   按 P-7 语义（kSync = 按键状态重置）应视作序列终止。一行修法：kSync 分支 `ctrl_armed_ = false; return false;`
### 子代理
审计 K 已 delete 解散。在途：审计 J（teardown + 测试缝风险）。
## 第833轮：批 17 已派（kSync 关窗 + seam.md 全文重写）
- 设计定案写入 `plan.md` 末尾「批 17 定案」（A 代码 1 行 + 1 测试；B 文档 11 项逐条重写）
- 执行会话 `ses_e670a548affer01q7CAdv99mRX`
- 关键约定：**文档中禁止保留失效行号**（无法确认的改写为符号名）；验收**只钉 `0 failing` + 用例名**（memory 第 74 条）
- 在途：审计 J `ses_e676f4a60ffeJvOfQZOzd86Sb0`（teardown + 测试缝风险，busy）
### 第833轮补充：W8 裁剪记录
- `process.md` 已含 833 轮逐轮记录，最长单节为 804-820 的注入批次；本轮不删（均在 30 天内且有溯源价值）
- `discover.md` 现有 25 例（第 1-24 例 + 早期归档），第 20-24 例为本轮输入注入主线新增
- `memory.md` 现有 75 条原则，第 72-75 条为本轮新增（豁免定界、幂等哨兵、值域追溯、验收钉用例名、序列缺陷）
- `plan.md` 含批 1-17 定案与历史归档
## 第834轮：审计 J 空输出且无报告 → 已唤醒补交
- [BASH: git status / Get-ChildItem] `docs/spec/input-batch13-review-J.md` **不存在**，J 平台状态 completed 但空输出
- 按第 11 条「completed 空输出且无写入产物禁止判完成，必须核验产物」→ 判为**未完成**
- 处置：经 `prompt` 直发原会话（附完整任务摘要），不新开替代
- 同时注意到批 17 正在改 `map.h`/`test_desktop_input.cpp`/`seam.md` —— 与 J 的只读审计不冲突
- 工作树现状（批 17 在写，勿提交）：`docs/spec/input-injection-seam.md`、`include/rtsc/server/desktop_input_map.h`、`tests/test_desktop_input.cpp` 均有未提交改动
## 第835轮：批 17 验收提交 `a141f58`（kSync 关窗 + seam 全文重写）
### 主代理独立验收
- `cmake --build build --config Release` → exit=0 / warn=0 / err=0
- `rtsc_desktop_input_tests` → `48 tests, 0 failing`；`rtsc_server_tests` → `50 tests, 0 failing`（**不钉 checks 数**）
- `ctest --test-dir build -C Release` **独占** → `0 tests failed out of 63`（65.08s）
### 逐行核对（W5）
- `map.h:88-96` kSync 分支在"非 kKey 早退"**之前**（这是关键：否则 kSync 落在 `:101` 早退里永远不会清 arm）；
  注释说明"SYNC 后丢失的 0xE1 半序列不得让陈旧 arm 吞掉下一次真实 NumLock 点击" ✅
- 文档自检（[BASH: 正则]）：`\.(cpp|h|md):\d` 命中 **0**（全篇零行号引用）、767 行、`U+FFFD`=0 ✅
- 文档 11 项已落地：§0 状态表、§1.3/§1.4 接口名（显式声明旧名不存在）、Inject 统一 void、
  §1.7#2 仍 OPEN + 三处错位实测、§1.8 改"部分闭合"（覆盖 vs 仅读码两张清单）、
  §2.3 held_release/`kGlobalBurst=2000` 理由/`release_failures`/两把锁、§3 P 分节 + P-12 汇总、
  §4.1 T4 中点改 32785/32798（复算）、T6/T10/T12/T13/T14/T15、§4.4 M1-M7 覆盖现状、§7 收敛记录（H/I/K/J）
- 执行方主动交底：`win32.cpp` 顶部注释仍是旧式 `sessions × 515` 峰值写法（本批"不改产品逻辑"未动），
  已在文档 §7.2 如实记录不一致 —— **记入待办**
### 待办
1) `desktop_input_win32.cpp` 顶部注释的峰值公式需同步为 `kHardQueueLimit + 515·K`（下一批）
2) 审计 J 补交后复核（在途）
### 子代理
批 17 已 delete 解散。
## 第836轮：批 18 提交 `d8badad`（峰值注释统一为 hard_limit + 515·K）
### 主代理直接执行（1 文件注释 + 文档回写，无逻辑改动）
- `src/server/desktop_input_win32.cpp:25-38`：删除"合成 up 作为额外项 `sessions × 515`"的重复计基线写法，
  统一为 `peak ≤ kHardQueueLimit + 515·K`（K=持租且 pressed 非空的会话数，默认 1 → 1539），
  并显式声明"合成 up 与 pressed 是**同一项**，非额外相加"、"PEAK 非瞬时不变式"
- `docs/spec/input-injection-seam.md` §7.2 补记：把"仍存在的不一致"改为"已于批 18 修复"
- 验证：`cmake --build` exit=0 / warn=0 / err=0；seam `U+FFFD`=0
### 剩余待办
- 审计 J 补交（在途，busy）
- 真机验证（用户环境）
## 第837轮：审计 J 完成（N-1/N-2/N-3 已闭合，4 个未闭合点）→ 批 19 已派
### 审计 J（`docs/spec/input-batch13-review-J.md`，241 行）
已闭合（带红证）：
- N-1 `win32.cpp:159-197`（`:191 erase`/`:196 notify` 在 try 外，M1 红 `test_desktop_input.cpp:1105`）
- N-2 `:604-650`（M2 回退 → **进程被杀** `0xE06D7363 EXIT=3`；M2b 只跳 join → 干净红 `:1136`）
- N-3 `:335-379`（`stopping_` 改原子无新缺陷，relaxed 足够）
- N-5/N-6 语义正确（rdpdr 逐项 catch）；测试缝三条风险中两条 PASS
未闭合（必修）：
- **J-1（High）** `server.cpp:2496-2508`：`sessions` 拷贝 / `unique_lock` / `cv.wait` 三个可抛点未隔离 →
  `~RdpServer:2210` 无 try → terminate。实证 `EXIT=3 0xE06D7363`
- **J-2（Medium）** `win32.cpp:708-710` `AsWin32` 裸 `static_cast`：喂 null sink 四种结局（含 AV/挂死）
- **J-3（Medium）** a) `worker_failures_` 只写不读（`:370/377/684`，无 Stats/无断言）；
  b) N-1 的 `drained` 断言**钉不住 notify**（删 notify 仍 30+20+100 次全绿，竞态）
- **J-4（Medium）** rdpdr 逐项 catch 无用例（`test_rdpdr_server_io.cpp:511-534` 只 1 个 IRP）
- **J-5（Low）** `seam.md` §1.8 仍称"任何变异都无法让 ctest 转红"（与 M1/M2b/M5 矛盾）+ 七处行号全部漂移；
  `review-F.md:340` 的 `776-787` 应为 `776-791`
计数语义：`RdpServer::input_release_failure_count()` 计"ReleaseSession 整体抛出"，出厂 sink 自己吞 append 异常
⇒ 该计数恒 0 时 ups 仍可能丢；真实可观测点是 `InputStats.release_failures`
### 批 19 `ses_e66c8ff12ffeQrlk0HjTcC5TBm`
J-1（三处 try + `~RdpServer` 兜底）、J-2（dynamic_cast 或 tag 检查）、J-3a（`worker_failures` 接线）、
J-3b（`worker_waiting_` hook + WaitUntil 确定性前置）、J-4（2 个 IRP 用例）、J-5（§1.8 改部分闭合 + 零行号）
+ 3 变异
### 子代理
审计 J 已 delete 解散。
## 第838轮：真机清单补 PAUSE 验收点（与批 19 文件不重叠）
- 批 19 正在改 `server.cpp`/`win32.cpp`/`main.cpp`/`desktop_input.h`/null/两个测试/`seam.md`/`review-F.md`
  → 主代理本轮只改 `docs/spec/input-injection-real-machine-checklist.md`（无冲突）
- 新增三条真机验收（原"Pause 可能无效"已过期，改为"整序列丢弃"）：
  1. 按 Pause 后**本机 NumLock 状态必须不变**（翻转即回归）
  2. Pause 之后再单独按 NumLock **必须正常切换**（抑制不误伤，上界=一次 tap）
  3. Pause 后紧接 `kSync`，随后 NumLock 仍生效（批 17 的窗口终止）
- 文件 92 行、`U+FFFD`=0
## 第839轮：批 19 验收提交 `5aa9fea`；审计 L 已派
### 主代理独立验收
- `cmake --build build --config Release` → exit=0 / warn=0 / err=0
- `rtsc_desktop_input_tests` 49/0；`rtsc_server_tests` 50/0；`rtsc_rdpdr_server_io_tests` 13/0（均 0 failing）
- `ctest --test-dir build -C Release` **独占** → `0 tests failed out of 63`（59.90s）
### 逐行核对（W5）
- J-1：`server.cpp:2210-2217` `~RdpServer` `try { Stop(); } catch (...)`；`:2508-2513` 快照 try；
  `:2524-2528` `unique_lock`+`cv.wait` try；注释说明"teardown 已完成，吞掉正确" ✅
- J-2：`win32.cpp:731-732` `dynamic_cast<Win32DesktopInputSink*>`；注释记录 static_cast 的四种 UB 结局 ✅
- J-3a：`desktop_input.h:54,65`、null `:44`、`main.cpp:620-621,633` 三端接通 ✅
- J-3b：`win32.cpp:369/375` `worker_waiting_` store(true/false) + `:684` atomic；hook `:240` ✅
- 执行方红证：J-1 变异→`unhandled-seh EXIT=3`；J-2 变异→`0xC0000409`；J-3b 删 notify→5/5 红；J-4 变异→`fires==2 got 1`
### 我提出的审计追问（已写入 L 的任务）
1) **J-1 快照失败 → sessions 空 → wait 仍等 `live==0`**：若会话线程永不退出，`Stop()` 会永久挂起（比 terminate 更隐蔽）
2) **J-1 wait 被吞异常后 `live != 0` 就返回**：`~RdpServer` 可能在会话线程仍访问 `impl_` 时销毁对象 → **use-after-free**（本项最危险）
3) J-2 `dynamic_cast` 依赖 RTTI，需确认无 target 设 `/GR-`
4) J-3b `store(true)` 与 `cv_.wait` 之间的 lost-wakeup 面
### 子代理
批 19 已 delete 解散。
## 第840轮：批 20（几何 origin/虚拟桌面）设计审计 M 已派
### 主代理取证（[BASH: Select-String / Get-Content]）
- `InjectGeometry`（`desktop_input.h:31-34`）只有 `width/height`，**无 origin、无虚拟桌面范围**
- 服务端填的是**协商并钳制后**的 framebuffer（`server.cpp:1324`），与捕获矩形无关联
- `BuildNative` 恒发 `MOUSEEVENTF_MOVE|ABSOLUTE|VIRTUALDESK`（`win32.cpp:518-522`）
- 捕获侧 `MakeGdiDesktopSource(monitor_index, x, y, width, height)`（`desktop_gdi.h:40-42`）支持单显示器 + 子矩形，并缩放到协商几何
⇒ `--monitor N` 或子矩形时，客户端坐标以"捕获矩形"为域、注入按"整个虚拟桌面"归一化 → **指针整体偏移/缩放错**
### 设计定案审计 `ses_e664d2035ffev3TAIwV4TuCE9J`
要求产出（`docs/spec/input-geometry-design-M.md`，不写代码）：
1) 完整映射公式（含取整）+ `MOUSEINPUT` 原文 + 至少一个成熟实现对照 + "分母是宽-1 还是宽"的判定
2) `InjectGeometry` 最小充分字段集与各字段来源
3) `DesktopSource` 取值方案三选一
4) ≥4 个变异点
5) 逐位数值例子（含 `--monitor -1` 默认是否已正确）
### 范围已写入 `plan.md`「批 20 范围」
- 先定案再实现；TDD 覆盖 1:1 / 2x / origin 非零 / 多屏虚拟桌面
- `--monitor N` 真机落点仍 UNVERIFIED
### 在途
审计 L `ses_e66978403ffeW2pFrvAxAFLkgp`（批 19 复验，重点 UAF）+ 设计审计 M

## 【归档压缩：841-859 轮（原 139 行）】

- **841** W8 裁剪（process 1010→836）+ 双审在途。
- **842** 审计 L 判 J-1 FAIL(High，挂起/UAF) → 批 21。
- **843** 派发 M 几何设计；N 为第二审计。
- **844** 批21 落盘核验（等 relay）；真机清单补 `input_release_failures`/`input_worker_failures` 与 `Stop()` 契约。
- **845** 主代理独立复算分母：`ceil(x*65536/w)` 全宽度零失配 vs `extent-1` 3/7/8/28。
- **846** 几何数值复核 + **自我纠错**：用"新旧实现互比"得 99.77% 是伪度量（discover 第 27 例）。
- **847** 批21 验收（构建 0/0、ctest 63/63）+ 三变异全红 + 提交 `d8b312a`；几何 §13 入库 `e9ef8ab`。
- **848-850** N 反驳 M（中心采样/混合式/DPI 位/M5 单点）；我独立 GDI 探针 7/7 组证实中心采样；
  我的端点锚定 oracle 作废（第 28 例）；N 的"纯 ceil 会打断既有断言"实测不成立（第 29 例）。
- **851** M/N 收敛；真实库复现跨屏 `(1601,512)` vs 应 `(2560,512)`。
- **852** M 文档三处修正 grep 验收；核验 `DesktopSource` 6 处实现 → 默认实现正确。
- **853** 批22 执行 AI `stream_interrupted` → 唤醒续做。
- **854** 批22 验收发现 High：`pixels_are_physical` 用虚拟桌面宽比对主屏口径（第 31 例）。
- **855** 批22 提交 `ad5891e`；裁决严格相等；第 32 例（运行时读源码测试）。
- **856-857** 审计 P 8 条核验；批23 派发。
- **858-859** 双审 P/Q 签字；我复现结构守卫可假绿/假红；追加 6 项；第 34 例（文本匹配测试三重失效）。

- **848-850** 几何交叉审计：N 反驳 M（中心采样/混合式分母/DPI 位/M5 单点）。主代理独立 GDI 探针 7/7 组
  证实中心采样 `floor((2x+1)*cap/(2*fb))` 零失配；DPI 虚拟化实测复现。**我第 846 轮的端点锚定 oracle 作废**
  （discover 第 28 例）。N 的"纯 ceil 会打断既有断言"经实测不成立（第 29 例）。
- **851** M/N 收敛；主代理用真实库复现跨屏缺陷 `n=(32793,32800)→(1601,512)` vs 应 `(2560,512)`。
- **852** M 文档三处修正经 grep 验收（U3 已确证 / U1U2 保留 UNVERIFIED / §3.3 标题 / §6.1 两基线）。
  核验 `DesktopSource` 6 处实现 → 默认实现正确。
- **853** 批22 执行 AI `stream_interrupted` 中断 → 唤醒续做（工作树 10 文件已落盘）。
- **854** 批22 验收：构建 0/0、ctest 63/63、映射值独立复算一致；**发现 High**：
  `pixels_are_physical` 用虚拟桌面宽比对 `DESKTOPHORZRES`（后者是主屏口径）→ 多屏恒 false（第 31 例）。
- **855** 批22 提交 `ad5891e`；我重做变异确认；裁决采纳严格相等（我的用例措辞错误）；
  discover 第 32 例（运行时读源码的测试，变异证据要求）。
- **856** 审计 P 报告 8 条逐条核验（6 成立）；批23 清单固化。
- **857** 批23 派发执行 AI。
### 双审结论（P/Q 一致，已多轮互审收敛）
**映射核心 PASS；批22 验收 CONDITIONAL**。生产代码（MapAxis/混合式/中心采样/fail-closed/GDI Geometry）**不改**；
缺的是验证资产与运维出口。
### 主代理独立复现的 High
结构守卫可假绿（注释伪装 → 0 failing）也可假红（正确代码+含 VIRTUALSCREEN 的注释 → 1 failing）。
已入 discover 第 34 例：禁止读源码文本验证行为，必须行为 seam。
### 裁决
- ① **同意**按"重写 H1 + 批23 清单"开启执行
- ② **同意**改判 `plan.md:721` 与 M §4.2:332 为 `SM_CXSCREEN/SM_CYSCREEN`（多屏正确）
- H3 热插拔复测承诺：**裁决删除该承诺**（非 const 复读引入 TOCTOU，且无测试覆盖）
### 已完成
- `plan.md` 追加 6 项（H1/H2/M5/M6/H3）提交 `9f00d9b`
- 追加指令已 relay 给在跑的批23执行 AI `ses_e64c0da68...`
- 审计 P `ses_e64fc340f...`、Q `ses_e64fbe978f...` 均 **delete 解散**（报告已入库）
### 在途
批 23 执行 AI（原 8 项 + 追加 6 项）
## 第860轮：批23 在途 + 主代理独立 oracle 入库
### 实质产出
- `docs/spec/input-geometry-probe-evidence.md` §9（提交 `165bbc6`）：
  - 稠密往返 oracle：w∈{1280,1920,3200,3840} 全像素**全 0 失配**
  - 缩放往返 oracle：fb/cap ∈ {640/1280, 1280/640, 1280/2560, 2560/1280} **全 0 失配**
  - **量化证明 1:1 用例不可能抓采样相位**：center vs window-start 在 cap==fb 时差异 0/1920、0/1280
  - **量化证明下采样只测 1 点**：fb=640/cap=1280 时 x=0 center=1/start=0（能区分），
    x=1 center=3/start=2（未测）⇒ Q 的 M6_interior_only 成立的算术原因
- W8 裁剪：process 741→615、discover 501→361
### 在途
批 23 执行 AI `ses_e64c0da68...`（原 8 项 + 追加 H1/H2/M5/M6/H3）
工作树已改 12 文件（含 test_desktop_gdi.cpp / test_server.cpp / main.cpp）
### 验收时使用
主代理将用 §9 的 oracle 独立核对执行 AI 的稠密表数值，不采信其报告数字
## 第861轮：批23 主代理验收 + 提交 12a9348
### 主代理亲测（不读报告）
| 项 | 证据 |
|---|---|
| 构建 | `cmake --build build --config Release` **exit=0**，六类诊断**全 0** |
| 全量 | `ctest --test-dir build -C Release -j1` **63/63, 0 failed**（58.16s） |
| H1 源码守卫已删 | `Select-String tests/test_desktop_gdi.cpp -Pattern 'RTSC_SOURCE_DIR\|PixelsArePhysical\(dpi_ok'` = **0** |
| H1 行为 seam | `:284-360` `FakeMetrics : MetricSource` 驱动 `PixelsArePhysicalFromMetrics`，7 条断言 |
| **H1 变异（我重做）** | 副本把 `SM_CXSCREEN→SM_CXVIRTUALSCREEN` → **FAIL :346/:349 两条行为断言，1 failing/2 failed checks，EXIT=1**（纯行为，非文本）；恢复+touch+hash 相同 → **0 failing** |
| dropped_unmapped 日志 | `main.cpp:622/623` 打印 + `:636` 变更检测（3 命中） |
| 稠密表 | `test_desktop_input.cpp:606-700` A(1:1 全像素×4宽4高) + B(cap=2×fb 中心采样) + 端点差异自证 |
### 提交
`12a9348` 批23（11 文件 +915/-90）
### 调度
- 执行 AI `ses_e64c0da68...` **delete 解散**（任务完成）
- 它 relay 两个已解散审计会话失败属**预期**（会话已删），无需代转
### 待办
新开双审复核批23
## 第862-863轮：双审 R/S 收口 + 批24 派发
### 审计 R（自顶向下，6 条，已逐条核验）
| # | 发现 | 主代理核验 |
|---|---|---|
| R1 | H1 工厂接线无测试保护 | **已复现**：工厂改 VIRTUALSCREEN → `10/57/0 failing, EXIT=0`（假绿） |
| R2 | M `:431` 端点公式未标否决，与 `:441` B0=1921 矛盾 | 成立 |
| R3 | `dropped_unmapped` 日志验收仍是 src.find（假测试） | 成立（`:1720,1723`）|
| R4 | M `:616` 两数字错（应 0/640 与 640/640） | **已复算**成立 |
| R5 | M 四处实现状态过期（`:254/:318-322/:332/:655`） | 成立 |
| R6 | H2 接线 y 轴不可见（capture.y=desktop.y=0） | 成立 |
### 审计 S（自底向上，20 个变异，5 条新发现）
- **S1 [Medium·回归]** `dropped_unmapped` 对非租约会话归零：`server.cpp:885` `IsInjectable(ev,g)==false` 直接 return，
  sink 计数永不执行；而 `desktop_input.h:83-87` 仍称"唯一可见信号" ⇒ **批23 引入的回归**
- S2 三处边界未钉死（right+1 / height>=65536 / capture.height<0，对照侧有 control 会红）
- S3 清理（`MakeWin32MetricSource` 无调用方、CMake `RTSC_SOURCE_DIR` 过期）
- S 独立算术穷举：outputs 全 ∈[0,65535]，int64 上界 4.3e9 无 UB
### 裁决与派发
- S1 采纳**方案 A**：`DesktopInputSink::NoteUnmappableMove(session_id)` 纯虚 + null 空实现 + win32 计数
- 批 24 共 9 项（R1-R6 + S1-S3）已固化 plan.md（`fb003af`、`4fa40f8`）
- 执行 AI `ses_e6475efa1ffe89jIpbNZLZldeO` 已派出（含 9 项 + 变异要求 + F 盘 temp 约束）
- 审计 R `ses_e648c3fb8...`、S `ses_e648bf021...` 均 **delete 解散**（报告已入库）
### discover 第 35 例（本轮教训）
修假测试时只验证"seam 内部能红"，没验证"装配点能红" ⇒ 工厂仍可假绿。
**修复必须对着缺陷成因验证，不是对着修复形式验证。**
## 第864轮：批24 主代理验收 + 提交 fa79fec
### 主代理亲测
| 项 | 证据 |
|---|---|
| 构建 | exit=0，六类诊断全 0 |
| 全量 | `ctest --test-dir build -C Release -j1` **63/63, 0 failed**（59.78s） |
| **R1 修复真有效（我重做变异）** | 复刻 seam 无关的最小编译（test_desktop_gdi.cpp + desktop_gdi.cpp + crash_guard.cpp，独立 cl 编译）<br>基线 `11 tests, 60 checks, 0 failing`；把决策改 `PixelsArePhysical(..., SM_CXVIRTUALSCREEN, ...)` → **FAIL :392 `source->Geometry().pixels_are_physical`，1 failing/1 check，EXIT=1**；恢复+touch → 0 failing，hash_same=True |
| 额外变异（我自选，R/S 未提） | `desktop.right` 改用 `SM_CYVIRTUALSCREEN` → **3 failing**（`:225/:271/:300`）⇒ desktop 矩形本身有运行时保护 |
| R3 装配 | `main.cpp:611` 调 `FormatInputStats`、`:616` 调 `InputStatsChanged` |
| S1 | `server.cpp:885-897` 未持租约且不可映射纯移动时调 `NoteUnmappableMove` |
### 提交
`fa79fec` 批24（12 文件，含新 TU `desktop_input_stats.cpp`）；`d2aa9d3` 真机清单 §10 两条
### 残余缺口（诚实登记，已入 plan.md 批25候选 R7）
host `main.cpp` 调用点无行为测试（`--once` 阻塞等待客户端，无法低成本自动化）
### 调度
执行 AI `ses_e6475efa1...` **delete 解散**
## 第865轮：批25 —— 闭合 R7（host 装配点行为测试）+ 启动安全闸首次覆盖
### 做了什么
新增 `tests/host_cli_check.cmake`（cmake -P + execute_process）+ CMakeLists 5 条 `host_cli_*`。
`--seconds 1` 让 host 自行到期退出，绕开 `--once` 等连接的阻塞，从而能观测
`main.cpp:611` 的装配点与启动安全闸。
### 验证
| 项 | 证据 |
|---|---|
| 配置 | exit 0；`CTestTestfile.cmake` 5 条 |
| 构建 | exit 0；六类诊断 0/0 |
| 全量 | **68/68, 0 failed**（72.55s）|
| 变异 A（`main.cpp:611` → `log.line(reason)`） | `host_cli_stats_line` 唯一红 ⇒ R7 真闭合 |
| 变异 B（拒绝路径 `return 2`→`0`） | 两个 `refuse_*` 红 |
| 变异 C（改计数键名） | `desktop_input` + `stats_line` 红 |
| 恢复 | hash 一致、MUTANT 残留 0、重编 68/68 |
### 新教训（discover 例 36）
`Copy-Item` 恢复会带回旧 mtime → MSBuild 不重编 → 二进制仍是变异体 → 下一个变异证据被污染。
恢复后必须 `touch`，且必须确认构建日志里出现该文件的重编行（BUILD_EXIT=0 在"什么都没编"时也成立）。
### 残留
R7 关闭；真机语义项（数字是否随注入变化）仍 UNVERIFIED。

## 【归档压缩：864-866 轮（原 33 行）】

- **864** 批24 验收 + 提交 `fa79fec`：`ctest` 63/63；R1 变异（决策改 VIRTUALSCREEN）→ `:392` 红；
  额外自选变异 `desktop.right` 改 `SM_CYVIRTUALSCREEN` → 3 红。真机清单补 `dropped_unmapped` 与未持租约计数 `d2aa9d3`。
  登记 R7（host 调用点无行为测试）。
- **865** 批25 提交 `dab111d`：新增 `tests/host_cli_check.cmake`（cmake -P + execute_process）5 个 CASE；
  `--port 0 --seconds 1` 让 host 自行退出。变异 `main.cpp:611`→`log.line(reason)` → 仅 `host_cli_stats_line` 红（R7 装配点闭合）。
  拒绝路径 `return 2`→`0` → 2 个 `refuse_*` 红。
- **866** 审计 T 报告（CONDITIONAL，5 条 Low）。我自行复现 T-1/T-2/T-5，**但 F2 的变异打偏**：
  `String.Replace` 同时改了生产入口与 seam，`:461` 变红不能证明生产入口（后由审计 U 推翻，见 867）。

## 第867轮：批26 双审收口（F2 返工 + U-1/U-2/U-3/U-4/U-7 + T 的 SKIP 缺口）
### 核心事件：我的变异证据被审计 U 推翻
我用 `String.Replace` 替换了一个在文件里出现 **2** 次的字符串（生产入口 `:404` + seam `:411`），
两处同时改掉，于是 `:461`（只受 seam 影响）变红被我误当成"生产入口已测"。U 实测 13/73 全绿。
单点重跑确认 **U 对、我错**。记入 discover 例 38（变异必须唯一定位 + 目标与断言层一致）。
### 返工
生产入口改为一行胶水 `MakeGdiDesktopSourceWithDpiProbe(&EnablePerMonitorDpiAwareness, ...)`，
新增可注入 probe seam + 用例（两方向 + 调用次数恰好 1 次）。
### 变异矩阵（全部实测）
| 变异 | 结果 |
|---|---|
| 装配忽略 probe | 红 :561/:571 |
| 生产入口传 nullptr | 红 :561 |
| `desktop.left = 0`（丢原点） | 红 :497 |
| `InputStatsChanged` `!=`→`<` | 红 7 处 + periodic 1 处 |
| `FormatInputStats` 整段换位 | 红 :1785 |
| 回退串 `"none"` | 红 :1794 |
| seam 恒 nullptr | 红 3 tests/4 checks（改前全绿） |
### 验证
构建 exit 0 / 六类诊断 0；`ctest -j1` **68/68**（77.76s）；desktop_input 68/13910；desktop_gdi 14/89；MUT- 残留 0。
### 残留
R7 的"宿主调用点"部分 **OPEN**（方案1 需生产面改动 + 安全评审；方案3 未实现）。

## 第868轮：批27 —— 用"修正产品行为"闭合 R7 宿主调用点（无测试后门）
### 第一性原理
原需求"只在计数变化时打印"导致**空闲宿主永远不打印任何 periodic 行**——这本身是运维缺口。
让**首次采样无条件打印基线**：既补上运维可见性，又让调用点可从 `--seconds 7` 观测。
不需要 env 门控 sink、不需要生产后可替换后端、不需要安全评审（这两点是审计 U 的方案1 的代价）。
### 改动
`PeriodicInputStatsLine(const InputStats* printed, ...)`（nullptr=无基线必打印）；
main 加 `printed_input_valid`；`host_cli_check.cmake` 加 `periodic_stats_line` CASE，
用纯子串计数断言 periodic 行**恰好 1 次**（"至少一次"会放过刷屏）；
加 `cmake_minimum_required(3.20)`（否则 `while(TRUE)` 的条件被当字符串，`hits=0`）。
### 变异矩阵
| 变异 | 结果 |
|---|---|
| 删 main 的调用（occ=1 已验证） | 仅 `host_cli_periodic_stats_line` 红 |
| lambda 整体 `return;` | 同上红 |
| `nullptr` 返空（无基线不打印） | `desktop_input` + `periodic_stats_line` 双红 |
### 验证
构建 exit 0 / 六类诊断 0；`ctest -j1` **69/69, 0 failed**（73.49s）；实测 host `--seconds 7` → periodic=1 final=1。
### 过程事故（自我记录）
恢复变异时用错时间戳备份名 → 变异体残留一轮，`ctest` 97% 假红；改用 `Get-ChildItem` 列出真实备份名后恢复。
**教训**：备份文件名应记录到变量并在恢复时引用，不能手抄时间戳。
### R7
**[x] 完全闭合**（函数内部 + 宿主调用点），无生产后门。