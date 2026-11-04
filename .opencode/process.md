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

## 【归档压缩：865-867 轮（原 33 行）】

- **865** 批25 `dab111d`：`tests/host_cli_check.cmake` 5 CASE；变异 `main:611`→`log.line(reason)` 仅 `host_cli_stats_line` 红；
  拒绝路径 `return 2`→`0` → 2 个 `refuse_*` 红。首次覆盖宿主启动安全闸。
- **866** 审计 T 报告（CONDITIONAL，5 条 Low）。我复现 T-1/T-2/T-5；**但 F2 变异打偏**
  （`String.Replace` 同时改生产入口与 seam，`:461` 变红不能证明生产入口）。
- **867** 审计 U 推翻我的 F2 结论（13/73 全绿），单点重跑确认 **U 对、我错**（discover 例 38）。
  批26 `2dfedac` 九项收口：F1 metrics 单一来源、F2 加 `MakeGdiDesktopSourceWithDpiProbe`、
  U-1 七字段双向、U-2 整行顺序、U-3 nullptr、U-4 FakeMetrics origin、U-7 seam.md 2→6 字段、
  T 的 SKIP→CHECK。`ctest` 68/68。
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


## 【归档压缩：868 轮（批27 / 27b，原 44 行）】

### 批 27（`2ebac6d`）—— R7 宿主调用点闭合
推导：原"只在计数变化时打印"使**空闲宿主永远不打印任何 periodic 行**（运维缺口）。
让首次采样无条件打印基线 ⇒ 调用点可从 `--seconds` 观测，**无需 env 门控 sink / 生产后可替换后端 / 安全评审**。
`PeriodicInputStatsLine(const InputStats*, ...)`：nullptr = 无基线必打印。
变异：删 main 调用 / lambda 整体 return / nullptr 返空 —— 全红。

### 批 27b（`db5f764`）—— 自审判据盲区（discover 例 40）
`--seconds 7` 而采样 5s ⇒ 窗口只有 1 次采样，"打印一次"与"每次打印"观测相同；
刷屏变异（删 `printed_input_valid = true`）下用例**仍绿**。
修：`--seconds 12`（覆盖 5s/10s）+ `execute_process TIMEOUT 10→25`（窗口变长必须同步放大）。
修后同一变异 → 红 `found 2`。**又踩例 36**：换源未重编，旧二进制误报 2 行。

### D1 [中] 基线行数值未断言（假测试）
我复现：`MUT-D1 = FormatInputStats("periodic", InputStats{})` → **68 tests/13912 checks 全绿**。
根因：用例的 `base` 全 0，"打印当前值"与"打印默认值"逐字节相同。
修复：`base.injected=7 + base.dropped_unmapped=5`（两个**不同**非零值），断言两个都出现在基线行。
同一变异 → **红 :1820/:1821（2 checks）**。
### D2 [低] checklist 把基线说成通用行为
实测 `--once` 只走 `log_input_stats("final")`，无 periodic。已在该条补注"仅 --seconds/无界模式"。
### D3/D4
D3（缺 `cmake_minimum_required` 会假红）本批已加，记作已闭合；
D4 跨平台 Linux 实跑 **UNVERIFIED**（被 server.cpp 既有 `-Werror=reorder` 阻断，非本批引入）。
### 验证
构建 0/0 六类诊断 0；`ctest -j1` **69/69, 0 failed**（87.98s）；`MUT-` 残留 0。


## 【归档压缩：870-871 轮（原 36 行）】

- **870** 审计 W 报 B1（change 分支值断言在批 28 被删除、无替代）。我复现：
  `MUT-B1`（change 分支打印旧快照）→ 修复前 **68/13912 全绿**；同一变异在 `db5f764` 下红
  ⇒ 批 28 引入的判据回归（discover 例 42）。修复后红 :1846/:1847/:1848。
  D1e：基线夹具改七字段互异非零（11..17）+ 整行相等 + 七条字面量。
- **871** 双审报 `verify.ps1` 机械门 5 条缺陷（D3 CWD 未锚定 / D4 漏 untracked /
  **D5 注释豁免放过"注释掉代码"** / D6 未校验退出码 / D7 范围）。D5 我复现：
  3 行变异夹具旧门只报 1 条，而 B2 残留正是纯注释行形态（discover 例 43）。
  修复：零豁免 + `git -C $root` + `--untracked` + 退出码检查 + 去掉注释里的变异名字面量。
  验证：干净树 passed / 3 行夹具 3 条全报 / 非仓库 128 报错退出；`ctest` 69/69。
  双审一致 PASS（提交级），两角色 `delete` 解散。

## 第872-874轮（合并）：Linux gate 三层缺陷 —— 从"跑不起来"到"跑起来也没证明"

### 三层（逐层加深，每层都是"绿但没证明"）
| 层 | 缺陷 | 证据 | 修复 |
|---|---|---|---|
| 1 | `.sh` 被 `core.autocrlf=true` 检出为 CRLF，bash 起不来 | `file` → CRLF；gate EXIT=2 | `.gitattributes` `*.sh eol=lf` |
| 2 | gate 用 `RTSC_TLS_OPENSSL` 默认 OFF ⇒ OpenSSL 后端未编译，P0 用例被 `#if` 守卫掉 | `server_security` `Passed 0.01 sec`，7/45 | gate 显式 `-DRTSC_TLS_OPENSSL=ON` |
| 3 | gate 只断言聚合结果 ⇒ 被守卫掉的用例照样 100% | M2 下 `REQUIRED_TESTS=present` 仍绿 | 两道身份断言 |

### 批32 `150a6ea`：5 个真实跨平台错误（此前只知"reorder"1 个）
`server.cpp:1400` 聚合初始化缺成员；`server.cpp:715` 初始化列表顺序；
测试 3 处 2 参聚合；`WaitUntil` 未使用；`main.cpp` switch 漏 `kMouseRel`；
`test_server_security.cpp` 守卫错（`!defined(_WIN32)` → `RTSC_TLS_OPENSSL`）。
### 批33 `22876f2`：Debug 构建下的性能预算
`#if defined(NDEBUG)` 围住判定，未优化构建打印 skipped。
### 批34 `36430c1` + 批35 `3bb033f`：见上表 1/2 层与第 3 层

### 可证伪性验证（两红两绿）
| 变异 | 结果 |
|---|---|
| M1 gate `ON`→`OFF` | EXIT=1，`required tests missing: tls_openssl` |
| M2 `test_server_security.cpp:444 #if`→`#if 0`（目标仍在） | EXIT=1，`P0 ... did not execute`，且 `REQUIRED_TESTS=present` |
| 恢复 | SHA256 `3AE7AFC7...9A8A` 一致；全仓 `MUT-` 0 |
| 绿证 | EXIT=0、`LINUX GATE PASS`、68/68、`P0_REGRESSION=executed` |
| 语法 | `bash -n` → `SYNTAX_OK` |

### 平台差异（精确比对，非笼统说法）
Linux 68 / Windows 69；Windows-only: `desktop_gdi`,`tls`；Linux-only: `tls_openssl`；
其余 67 项完全同名 ⇒ 平台后端替换，**不是用例丢失**。

### 教训（discover 例 44-46 合并）
UNVERIFIED 必须定期重试；"非本批引入"只影响归因不豁免修复；
**"绿"必须能被证明是"该绿的绿"**：凡可被条件编译移除的测试，聚合断言无效，必须断言身份。


## 第875轮：批36 —— verify.ps1 传播 gate 的两道身份断言
### 缺口（例 46 教训的同型复发）
批35 给 gate 加了两行身份输出，但 `verify.ps1:448-464` 这个**唯一消费方**
仍只校验四项（FAILED_COUNT / WINDOWS_H_COUNT / FACTORY_SYMBOL）。
断言存在 ≠ 断言被消费。
### 修复
`verify.ps1:458` needle 列表补 `REQUIRED_TESTS=present`、`P0_REGRESSION=executed`，
沿用 line-anchored 正则。
### 可证伪性
| 变异 | 结果 |
|---|---|
| gate 两条 echo → `true`（gate 仍 EXIT=0） | `verify.ps1` 断言块：`MISSING -> REQUIRED_TESTS=present`、`MISSING -> P0_REGRESSION=executed` |
| 恢复 | 全仓 `MUT-` 0 |
| 编码 | 首字节 `35`（无 BOM）、`CR=482` 均不变（字节级替换） |
| 语法 | PowerShell 5.1 Parser `PARSE_OK` |
### 本轮自身失误（已修正并记录）
首次用 `ReadAllText`+`WriteAllText` 改 `verify.ps1`，写入 BOM 且把 CRLF 改成 LF，
产生 `1 file changed, 2 insertions(+), 2 deletions(-)` 的伪 diff（首行注释被改）。
已 `git checkout` 回滚，改用字节级定位替换，diff 收敛为单行 `1 insertion(+), 1 deletion(-)`。
## 第876轮：批37 —— 两审计 CONDITIONAL 收口（四条同族缺陷）
### 审计结论
X：CONDITIONAL（D1 门可被 skip 短路、D3 Linux 无优化覆盖）
Y：CONDITIONAL（P1 gate 不判预算、P1 PartialGeometry 无守护、P1 relative-move 零守护、P2 三条）
双方交叉验证一致；对 `RTSC_TLS_OPENSSL` 传播链结论一致：**传播成功，P0 用例是被关掉的有效测试，批34 是真修复**。
### 修复（`44636b8`）
| # | 缺陷 | 修法 |
|---|---|---|
| D1 | gate 的 OK 行断言可被用例体 `printf("skipped:")+return` 短路 | OK 行 + 无 `skipped:` + `tests>=8 / checks>=67`（下限，采纳 X 的稳定性质疑） |
| D3 | gate 用 Debug ⇒ 七条预算断言永不执行 | gate 追加 `RelWithDebInfo` 只跑 `rtsc_view_tests`，要求 `VIEW_BUDGETS=executed` |
| 新 | `gui_send` 在 Linux 注册 0 用例却 exit 0（修 D1 时暴露） | `test_main.h` `ran_tests==0` → `exit 2`；`gui_send add_test` 加 `if(WIN32)` |
| P1 | `PartialGeometry` 的 mapped 语义无守护 | 两例从 `PhysicalGeometry(2,2)` 各坏一个信任位 + 按钮对照组 |
| P2 | `CONFIGURE_EXIT` 被我批34 删掉 | 恢复 |
### 可证伪性（每项均红→绿）
| 变异 | 结果 |
|---|---|
| P0 用例体 → `if(true){skipped;return;}` | `EXIT=1` `suite self-skipped` |
| 删 P0 体内 1 条 CHECK | `EXIT=1` `ran less than the full body (checks=66, want >=67)` |
| `CHECK(best < budget*1e-7)` | `VIEW_RELEASE_EXIT=1`，`:1473` 三条 FAIL |
| 删 `!g.mapped` | `:751/:905/:914` 红（2 failing） |
| 删 `!g.pixels_are_physical` | `:755/:908` 红（2 failing） |
| 拼错 `RTSC_TEST_FILTER` | exit 2（修前 exit 0） |
### 验证
- Linux gate：`LINUX GATE PASS`、67/67、`VIEW_BUDGETS=executed`（Release 7348 / Debug 7341）
- Windows：构建六类诊断全 0；ctest **69/69**
- 全仓 `MUT-` 残留 0；每个变异体恢复后 SHA256 与备份一致
### 未修（明确登记，不假装处理）
- P1-c `kind="relative-move"` 日志文本零守护：纯日志，造断言的代价高于收益；若审计坚持须给出断言形态。
- Windows `-Wswitch` 零守护（`cl /W4 /WX` 对漏枚举不报错，仅 `/w44062` 报 C4062）。
- `rtsc_server_tests` checks 655–657 漂移（与本次无关，未对其实施任何 checks 断言）。
- `scripts/real-server-test.ps1` 不调 ctest（独立线）。
### 本轮操作失误（记录）
用 `--clean-first` 只重建单个 target，把其它产物删了却不重建 → ctest 68/69 全崩。
教训：`--clean-first` 不能与 `--target` 组合用于增量验证；要么全量重建，要么不用 clean。
另：`Copy-Item` 恢复文件后 mtime 早于产物，MSBuild 不重编，导致"变异仍绿"的假象 —— 必须核对二进制 LastWriteTime（discover 例 36 复发）。
## 第877轮：批38 —— 堵 D3 的同形洞（审计X V8）
### 缺陷
批37 的 D3 只断言 `VIEW_RELEASE_EXIT==0` 与"无 `skipped: timing budgets` 字面量"，
把 checks 数只打印不断言。X 的 V8 红证：
`#if defined(NDEBUG)`→`#if 0` + 改 skip 文案 ⇒ `VIEW_RELEASE_EXIT=0`、
`7341 checks`（= Debug 数，预算一条没跑）、`VIEW_BUDGETS=executed`、`LINUX GATE PASS`。
**这是我刚修完 D1 就原地重犯的同一个错**（用"无某字符串"代理"执行了"）。
### 修复（`b9a633f`）
`VIEW_MIN_CHECKS=7348`，断言 `VIEW_CHECKS >= 7348`（下限）。差值 7 = 七条 bench CHECK。
### 可证伪性
| 变异 | 结果 |
|---|---|
| `#if defined(NDEBUG)`→`#if 0` + 改 skip 文案 | `EXIT=1` `view budget bodies did not run (checks=7341, want >=7348)`，且 `VIEW_RELEASE_EXIT=0` |
| 恢复 | SHA256 `775301AB...8866`；全仓 `MUT-` 0；`7348 checks`；`LINUX GATE PASS` |
### 验证
Linux `LINUX GATE PASS` + `VIEW_BUDGETS=executed`（7348）；Windows 构建六类诊断全 0；`bash -n` SYNTAX_OK。
### X 对批37 的复核结论
D1 两道断言各自可证伪 ✅；Release 7341/7348 delta=7 ✅；`gui_send` 两平台行为 ✅；
`exit 2` 不误伤正常路径（0/1/2 三态互不串）✅；`CONFIGURE_EXIT` 已恢复 ✅。
X 亦纠正我一处：删 1 条 CHECK=66、删 3 条=64，均红，数字差异来自变异强度而非判据。
### 教训（discover 例 49）
"能观测"≠"已断言"：凡 `printf`/`echo` 出来供人看的数字，必须问"它错了谁会失败"。
新原则必须立刻回扫本次改动本身（我在同一提交里立了原则又违反）。
可观测量的**差值**比绝对值更可靠（7348−7341=7 恰等于七条断言）。
## 第878轮：批39 —— 两审计 P1 收口（`cc1591e`）
### 1. 我的重复覆盖 + 事实错误（两审计独立否证）
- 批37 的 `:903-914` 是**重复覆盖**：旧用例 `:750-766`（自 `150a6ea^`）已逐位守两信任位；删新块后 `:751/:755` 仍红（T0/T1）。**已删**。
- 我的注释写"span 先拒 PartialGeometry"是**事实错误**：`PartialGeometry(1920,1080)` span 合法，先拒的是 `:80` trust、其次 `:82` 空 capture。**已按事实重写**。
### 2. 真正无人守护的是辅助函数自身输出
- `PartialGeometry` 三种变异全绿（68 tests/13922 checks）——因为调用点 `w/h∈{0,1}` 被 `:81` span 拦下，变异打的是下游规则。
- 新增 `desktop_input_partial_geometry_helper_contract` 断言辅助函数输出（width/height/mapped/pixels/capture/desktop/AbsoluteMoveMappable）。
- 三变异皆红：`PG+mapped=true` / `PG+pixels=true` / `PG+capture.width=1920`。
### 3. Y 的 P1-c：`InputEventKindToken`
- `main.cpp` 内联 switch → 纯函数放 `src/server/desktop_input_stats.cpp`（与 `FormatInputStats` 同范式）。switch 结构性消失（`cl /W4 /WX` 本就不报漏枚举，仅 `/w44062` 报 C4062）。
- 新增 `desktop_input_kind_token_covers_every_kind` 枚举 6 值；变异 `kMouseRel→"mouse"` → `:2186` 红（修前 `ctest -R host_cli` 6/6 全绿）。
### 4. 未采纳项（附理由）
Y 的"VIEW_MIN_CHECKS=7348 是魔数"：**暂不处理**。7348 是"7 条预算执行过"的唯一可观测证据，从运行结果推导即自证；已做下限比较 + 注释"增减 bench 须重新标定"。
### 验证
- Windows：构建六类诊断全 0；ctest **69/69**（75.22s）；`rtsc_desktop_input_tests` **70 tests / 13934 checks**，0 failing
- Linux：`LINUX GATE PASS` 67/67 + `P0_REGRESSION=executed` + `VIEW_BUDGETS=executed`(7348)
- 行尾：`git cat-file` 逐字节核对 HEAD blob，四文件纯 LF（`test_desktop_input.cpp` LF=2187/CR=0）
### 本轮自身失误
- 用 `for($i=866...)` 造出意外空文件 `=866`（PowerShell 解析问题），已删除。
- 多次遇到"`Copy-Item` 恢复后 mtime 早于产物 → MSBuild 不重编 → 变异仍绿"（例 36 复发），靠改 mtime + 核对二进制时间戳解决。
- 一次插入用例时留下重复的 `RTSC_TEST(...)` 行（C2267/C2601 75 个错误），已修正。
### 教训（discover 例 50）
"变异全绿"≠"规则无人守"，必须先枚举全部拒绝路径再判断变异打到哪一道；
"无人守护"必须给反证（删既有用例后是否仍红）；注释里的因果链是不可执行断言；
MSVC 默认不报漏枚举，必须把 switch 提成可单测的纯函数。
## 第879轮：批41 —— verify.ps1 主路径从未通过（`9e30a01`）
### 发现
后台跑 `verify.ps1 -LinuxBuild`（默认 Debug）→ `ui` 测试红：
`test_ui.cpp:252 new_us <= 0.6 * ref_us`，Debug ratio **0.77/0.79/0.77**（三次稳定），Release **0.39/0.41**。
相对倍率断言在 `-Od` 下确定性失败 ⇒ 自 `f77b90f` 起 `verify.ps1` 默认路径**每次都红**。
### 为什么长期没发现
我所有"全绿"都来自 Release 的 `build`；`verify.ps1` 用 Debug 的 `build\verify`。**两个构建目录，只盯了一个。**
且 `verify.ps1 -LinuxBuild` 被我连续多轮记为 UNVERIFIED 而未运行（例 44 形态）。
### 修复
1. `test_ui.cpp` `#if defined(NDEBUG)` 围住测量+断言，Debug 打印 skip
2. gate RelWithDebInfo 阶段增跑 `rtsc_ui_tests`，断言 `UI_RELEASE_EXIT=0` + 无 skip + `checks>=86`
   （**不重犯批33**：不是"改 skip 就完事"，而是把断言放回可观测构建执行）
3. `verify.ps1` needle 补 `UI_RATIO=executed`；124/137 拆成两种措辞（采纳审计X）
### UI_MIN_CHECKS=86 的来由
Linux 20 tests/86 checks；Windows 50/265（Win32-only 用例差额）。Linux Debug 84 / Release 86，差 2 = 两条计时断言。
### 可证伪性
| 变异 | 结果 |
|---|---|
| `RgbaToBgra` 每次迭代插 64 次 volatile 自旋 | Release ratio 11.31，`:253`/`:254` 双红 |
| `#if defined(NDEBUG)`→`#if 0` + 改 skip 文案 | `UI_RELEASE_EXIT=0` 但 `ui ratio body did not run (checks=84, want >=86)` |
### 验证
Windows Release 构建六类全 0 + ctest **69/69**；Windows Debug ctest **69/69**（修前 68/69）；
Linux `LINUX GATE PASS` 67/67 + `VIEW_BUDGETS=executed`(7348) + `UI_RATIO=executed`(86)。
### 本轮自身失误
1. 变异时 `$t2` 为 null 导致 `WriteAllText` 把 `src/ui/surface.cpp` 写成 0 字节；
   已从备份恢复并逐字节核对与 HEAD blob 相同（6889B）。**教训：写入前必须校验长度/索引**。
2. 恢复 `test_ui.cpp` 时用了旧备份，把刚加的 guard 一起回滚；已重新应用。
3. 陈旧二进制问题又出现两次（`Copy-Item` 保留旧 mtime），靠 `LastWriteTime=Get-Date` 强制重编解决。
### 教训（discover 例 51）
"全绿"必须指明构建类型与目录；默认配置才是主路径；UNVERIFIED 会累积成盲区；
修一类缺陷必须全仓扫描同型（本例 7 处计时断言中仅 2 处是相对倍率）。
## 第880轮：verify.ps1 -LinuxBuild 端到端首次真跑通过（关闭长期 UNVERIFIED）
### 背景
此前多轮把 `verify.ps1 -LinuxBuild` 记为 UNVERIFIED 而未实际运行（discover 例 44/51 形态）。
### 三次连跑
| 运行 | 结果 |
|---|---|
| 修前（后台启动） | Windows ctest **68/69**，`ui` Failed（`test_ui.cpp:252` ratio 0.77） |
| 修后（verify2.log） | Windows Debug **69/69** + `LINUX GATE PASS` + `linux build gate passed` |
| 修后（verify5） | `wrapper_exit=0`，**`verify_exit=0`** |
### 证据
- Windows Debug（`build\verify`）：`100% tests passed, 0 tests failed out of 69`
- Linux：`CTEST_EXIT=0` 67/67、`VIEW_BUDGETS=executed`(7348)、`UI_RATIO=executed`(86)
- 变异残留门 passed
- 该项自 2026-11-03 起 **UNVERIFIED → VERIFIED(exit 0)**
### 剩余 UNVERIFIED
真机 U1/U2/U4–U9、`--monitor N` 落点（需真实多显示器桌面）。
### 教训
"记成 UNVERIFIED" 不是中性状态，它会累积成盲区（例 44/51 连续两例都由此暴露）。
每轮应至少收敛一个 UNVERIFIED 项；能跑的必须跑，不能跑的必须写清阻塞条件。
## 第881轮：批42 —— checks 下限可被补足（审计X），改断言体内部标记行（`1b38b8c`）
### 缺陷（同族第三次复发）
批41 的 `UI_MIN_CHECKS=86` / `VIEW_MIN_CHECKS=7348` 是"产出量下限"，而 checks 计的是
"执行了多少次 CHECK" ⇒ **任何无关恒真 CHECK 都能补足**。
真 gate 实测：ratio 体 `#if 0` + 改文案 + 补 2 个 CHECK → `86 checks`、`UI_RATIO=executed`、
`LINUX GATE PASS`；view 侧 `#if 0` + 补 7 CHECK → `7348`、gate PASSES。
**非对抗路径也会打开**：X 的 GROW=2（正常加 2 个 CHECK）后 body 失效正好卡在下限。
### 修复
- view：`grep -c "\[bench\]" >= 7`（循环体内 printf 产出行）
- ui：`grep -q "rgba->bgra 1280x1024:"`（体内测量行）
- checks 下限降级为"套件规模异常"辅助检查
### 可证伪性（真 gate）
| 攻击 | 结果 |
|---|---|
| view `#if 0`+补7 CHECK+改文案 | `EXIT=1`，`bench lines=0, want 7` |
| ui `#if 0`+改文案+补2 CHECK | `EXIT=1`，`measurement line missing` |
| ui `#if 0`+改文案+补3 CHECK（GROW） | 同上 `EXIT=1` |
| 未改代码 | 全绿 |
### 顺带：注释第 3 版仍错，第 4 版修正（例 53）
- `:80` 是 `!mapped || !pixels_are_physical`（OR）：任一半翻转仍被拒，两半全 true 才通过
- `PartialGeometry` 即使两半全 true 仍被 `:82` 空 capture 拒（`InjectRect` 默认 0），**永远不会 mapping**
### 验证
Linux `LINUX GATE PASS` 67/67 + `VIEW_BUDGETS=executed`(7348) + `UI_RATIO=executed`(86)；
Windows Release 六类全 0 + **69/69**(74.33s)；Windows Debug **69/69**(75.82s)；全仓 `MUT-` 0。
### 接受审计 X 的结论更正
批 38 PASS → PASS-with-caveat（当时未验"补 CHECK"路径）。本批 view/ui 一并收口，该族结束。
### 教训（discover 例 52/53）
判断"某段代码执行了吗"的唯一可靠证据是该段代码**自己产生的副作用**；
写注释前必须逐行核对判定顺序、`&&`/`||` 方向与默认值，改三次仍错就改为做实验。
## 第882轮：批43 —— 用例52 的原则回头扫，发现 P0 同族洞（`f8c24e8`）
### 缺陷
批35 的 P0 断言（`tests>=8 && checks>=67`）与批41 的 view/ui 是同一个洞。
真 gate 实测：`CHECK(got_challenge)` → 两个 `CHECK(true)`，checks 67→68（仍≥67）
⇒ `EXIT=0` / `P0_REGRESSION=executed` / `LINUX GATE PASS`（drain 回归断言已消失）。
### 修复
- P0 成功路径打印 `  drain: challenge surfaced after coalesced record`（全仓唯一）
- gate 断言该行；缺失即 `body did not reach its success path (drain marker missing)`
### 可证伪性（真 gate）
| 变异 | 结果 |
|---|---|
| `CHECK(got_challenge)` → 两个 `CHECK(true)` | `EXIT=1`，`drain marker missing`；变异体 checks=68 仍高于 67 ⇒ 抓住它的是标记行 |
| 未改代码 | `P0_REGRESSION=executed`，8 tests/**67** checks，PASS |
### gate 断言分类自查（例52 的"问一句"）
- 身份类（不可补足）：`REQUIRED_TESTS`(ctest -N 名字) / `FACTORY_SYMBOL`(nm 符号) /
  `P0_REGRESSION`(体内标记行) / `VIEW_BUDGETS`([bench] 行数) / `UI_RATIO`(测量行)
- 零值类（不能假）：`FAILED_COUNT=0` / `WINDOWS_H_COUNT=0` / 各 `*_EXIT=0`
- 下限类（仅辅助）：`SEC/VIEW/UI_MIN_CHECKS`
⇒ **已无任何断言依赖"总数达到下限"来证明某段代码执行过**
### 本轮自身失误
提交信息写"修后 8 tests/68 checks"，实测仍 **67**（新增 printf 不产生 CHECK）。
凭推理写数字 = 未验证断言。已在记忆更正。
### 验证
Linux `LINUX GATE PASS` 67/67 + `P0_REGRESSION=executed` + `VIEW_BUDGETS=executed`(7348)
+ `UI_RATIO=executed`(86)；Windows Release 六类全 0 + **69/69**(73.93s)；全仓 `MUT-` 0。
## 第883轮：批44 —— 更正批43 的覆盖声明（`a9f69ca`）
### 审计 X 推翻我两处结论，我独立复现确认他全对
1. 批43 声称"攻击 B（`CHECK` → 两个 `CHECK(true)`）→ EXIT=1"。实测 **EXIT=0**。
   我那次变异把 **printf 与 CHECK 一起删了**，所以 marker 消失；只换 CHECK 时 marker 照常打印。
2. 攻击 C（只删 `CHECK(got_challenge)`、保留 printf）→ 同样 **EXIT=0** / `P0_REGRESSION=executed`。
3. 根因（原理性）：`CHECK` 只调 `report_failure`、不改控制流（`test_framework.h:47-53`），
   所以任何产出物断言只能证明"路径走到了"，不能证明"断言还在"。
4. 我的断言分类误判：`P0_REGRESSION` 不是身份类，是**路径类**。
### 处置
- 不加新机制（没有能检测"删断言"的机制），而是**把边界写进代码注释**：
  gate 新增 COVERAGE BOUNDARY 段；`test_server_security.cpp` 写 What it proves / What it does NOT prove。
- 三档分类更正：身份类（`REQUIRED_TESTS`/`FACTORY_SYMBOL`）/ 路径类（`P0_REGRESSION`/`VIEW_BUDGETS`/`UI_RATIO`）/ 计数类（`*_MIN_CHECKS`）。
### 验证
Linux `LINUX GATE PASS` + P0/VIEW/UI 三标记均 executed；Windows Release 六类全 0 + **69/69**(81.79s)；全仓 `MUT-` 0。
### 本轮额外探查（未改代码）
为确认 P0 是否守护 drain 实现，我对 `tls_schannel.cpp` / `tls_openssl.cpp` /
`security_layer.cpp` 的 drain 位置做了 4 次变异，**P0 均未变红**
（`M7`、`max_out>=1`、两处 `buffered_input` 循环、`pending_cipher_` 不 Receive）。
最后一种被其它用例抓到（3 failing tests），但 P0 不是那个守卫者。
⇒ 登记：**P0 用例的 drain 语义守护强度未验证**，不宣称它守住了 drain。
### 教训（discover 例 55）
变异必须唯一且先跑后写；"修复生效"的证据必须由脚本输出产生，不能口述；
产出物断言的覆盖上限是"路径"，不是"断言存在"。
## 第884轮：批45 —— 更正 P0 守护点（`261582c`）
### 我批44 第3节错了：4 个变异全部打错文件
X 指出并复现，我独立确认：
- `tls_schannel.cpp`（Windows 后端，Linux 不编译）
- `tls_openssl.cpp` 的 `max_out` 分支（`max_out=0` 走不到）
- `security_layer.cpp:244/:321`（**客户端 mirror**，注释自述服务端才是关键路径）
- P0 实际用 `ServerSecurityLayer`，drain 在 `src/security/server_security_layer.cpp:194`
- `tests/test_server_security.cpp:35` 注释**本身就写着** "which lives in ServerSecurityLayer::DriveCredssp"
### 更正后的结论
- 改 `:194` → P0 **红**（`test_server_security.cpp:611 got_challenge`，唯一失败用例）
  ⇒ P0 是 `:194` 的唯一守卫，批34 结论成立，**UNVERIFIED → VERIFIED**
- 改 `:292`（`ReceivePdu` 数据面 drain）→ 整棵 ctest **67/67 全绿**
  ⇒ **新登记（中）**：`:292` 无任何用例守护
### 处置
- `server_security_layer.cpp:292` 加 COVERAGE 注记（无覆盖 / 关掉全绿 / `:194` 在另一阶段不能替代 / 触达条件）
- `test_server_security.cpp:600-603` 补"守护点是 `:194`，本用例是它唯一守卫"
- gate COVERAGE BOUNDARY 同步；`LIB_BYTES` 标注 `output only, not asserted`（采纳 X 第4节）
### 本轮自身失误（例47 复发）
用 `WriteAllLines` 改 gate 时**又**写 CRLF → `bash -n` 报语法错。已改回显式 LF。**例47 记过一次，这次是复发。**
### 验证
Linux `LINUX GATE PASS` 67/67 + P0/VIEW/UI 三标记 + `FAILED_COUNT=0`；Windows Release 六类全 0 + **69/69**(87.04s)；`bash -n` SYNTAX_OK；全仓 `MUT-` 0。
### 教训（discover 例 56）
变异必须先定位"被测对象的实现文件"（从测试里的类名 grep 定义）；
"变异全绿"除了"无人守护"还有"打错位置"这一解释；
镜像/对称实现是最危险的误伤点，选点前必须确认哪一份被测试执行。
## 第885轮：批46 —— 给 :292 数据面 drain 补用例（`8739643`）
### 我的错误判断（审计X 反对并给出可行方案）
批45 我写 ":292 无法构造测试" 并只留边界注释。X 指出配方**就在同一测试文件**：
`server_security_layer_hybrid_without_ex_omits_euar`（:231-291）驱动到 `kDone`，
唯一缺的是 `ScriptedTls::buffered_input()` 硬编码 `return 0`。
**我把"我没找到配方"当成"不可能"。**
### 实现（照抄 X 的骨架，+24 / +72 行）
- `test_tls_scripted.h`：`buffered_input()` 返回 `buffered_`（默认 0）、`stage_for_test()`、`Receive(nullptr,0)` 吐出并清零
- `test_server_security.cpp` 新增 `server_security_layer_data_plane_drain_lifts_coalesced_record`
### 可证伪性（Linux RelWithDebInfo 真跑）
| 状态 | 结果 |
|---|---|
| 正常 | 9 tests / 79 checks, 0 failing |
| `:292` → `while(false)` | **9 tests / 78 checks, 1 failing**，`:361 frames.size()==1u (got 0, want 1)`，唯一失败者 |
| 恢复 | 全绿，`MUT-` 0 |
### 顺带
- `:292` 注释由 "no test exercises this branch" 改为 "Guarded by <用例名>"（消除会过期的断言与悬空的 plan.md 批号引用）
- gate 的 COVERAGE BOUNDARY 保留（它描述 P0 marker 的能力边界，与 `:292` 无关）
### 验证
Linux `LINUX GATE PASS` 67/67 + 三标记 + `FAILED_COUNT=0`；
Windows Release 六类诊断全 0 + 直接跑 8/72（含新用例）+ ctest **69/69**(85.94s)；全仓 `MUT-` 0。
### 教训（discover 例 57）
"没有现成用法" ≠ "无法构造"；宣布不可测前先问"进入该状态的最短路径"；
边界注释是会过期的断言，可验证的就不该只写边界。
## 第886轮：批47 —— C9 同型排查，客户端 3 处 drain 全部无守护（`abd1f3e`）
### 发现
批46 修 `:292` 时我按 C9 只看了记忆里记得的同型点。这次 `git grep -n buffered_input`
真扫全仓（6 实现 + 5 调用点）才发现 `src/security/security_layer.cpp` 还有 3 处 drain：
`:244`（DriveCredssp）、`:321`（DriveEuar）、`:409`（ReceivePdu）。
**逐个改 `while(false)` 后整棵 ctest 67/67 全绿 —— 三处都无任何用例守护。**
### 新增 3 个用例（tests/test_security_layer.cpp，+120 行）
复用已有配方（MakeConfig / ServerChallengeMessage / MakeServerEchoForTest）+
`ScriptedTls*` 裸指针 + `stage_for_test`：
- `security_layer_credssp_drain_lifts_coalesced_record`（:244）
- `security_layer_euar_drain_lifts_coalesced_record`（:321）
- `security_layer_receivepdu_drain_lifts_coalesced_record`（:409）
### 红证（Linux，逐个变异，各自唯一失败者）
| 变异 | 结果 |
|---|---|
| :244 → while(false) | 22/162, **1 failing**；`:368 r.want == kWrite`，`[ FAIL ] ...credssp_drain...` |
| :321 → while(false) | **1 failing**；`:406 r.want == kDone` + `:407 handshake_complete()` |
| :409 → while(false) | **1 failing**；`:449 frames.size() == 1` |
| 恢复 | 22/162, **0 failing**；`MUT-` 0 |
### 注释
三处改为 "Guarded by <用例名>"；原 :242 "The server half is the critical path;
this client mirror keeps the two symmetric." 已不成立（客户端也都有守护了），一并替换。
### 我这轮犯的两个错（discover 例 58）
1. **WriteAllLines 又把 LF 写成 CRLF**（例 47 复发）→ ReadAllText/Replace/WriteAllText 修正，校验 CRLF=0。
2. **行索引覆盖了 `while` 行本身**：想插注释却把 `while (tls_->buffered_input() > 0) {`
   覆盖掉，git diff 立刻暴露（少一行 while）。回滚重做，改用文本锚点替换。
   **教训：按行号写文件前必须校验目标行内容，不能只按索引。**
### 验证
Linux gate `LINUX GATE PASS` 67/67 + 五标记 + `FAILED_COUNT=0`；
Windows Release 六类诊断全 0 + `rtsc_security_tests` 22/162 + ctest **69/69**（78.95s）；
行尾：security_layer.cpp LF 454/CRLF 0、test_security_layer.cpp CRLF 1051/1051、无混合；
`bash -n` SYNTAX_OK；全仓 `MUT-` 0。
## 第887轮：批48 —— 修 TlsByteTransport::Read 死循环（`7bfb413`）
### 因果链（G2）
1. 定位：`src/net/gateway_transport.cpp:555`
2. 原因：后端持不完整 TLS 记录时 `Receive(nullptr,0)` 返回 `kNeedMoreInput` 且不消耗，
   `buffered_input()` 永远 > 0 → `continue` 永不退出
3. 原意图：优先取已缓冲的完整记录，避免先去读 socket
4. 错误假设：`buffered_input() > 0` ⇒ 本次 drain 有进展
5. 防再犯：以 `buffered_input()` 前后是否减少为进展判据；不减少就落到读 socket
### 测试先行
`ScriptedPartialRecordTls`（buffered 恒 3、Receive 恒 kNeedMoreInput、
`receive_calls > 100` 时返回 kProtocolError 防挂死）+ 新用例：
| 状态 | 结果 |
|---|---|
| 修复前 | `:3659 n == kReadTimeout (got -1, want -2)`；`:3660 receive_calls == 1 (got **101**, want 1)` |
| 修复后 | 120 tests / 1210 checks, 0 failing |
### C9 复扫
全仓 5 个 `buffered_input()` 循环，只有 `gateway_transport.cpp:555` 是 `continue` 无逃逸；
`security_layer.cpp:244/:321/:409`、`server_security_layer.cpp:194/:300` 都有
`if (status == kNeedMoreInput) break;`，安全。
### 验证
Linux gate `LINUX GATE PASS` 67/67 + 五标记 + `FAILED_COUNT=0`（首次跑因 bench 偶发红，重跑绿）；
Windows Release 六类诊断全 0 + `rtsc_gateway_tests` 120/1210 + ctest **69/69**(74.55s)；
行尾 CRLF 一致；全仓 `MUT-` 0。
### 教训（discover 例 59/60）
`X > 0` 用作"继续循环"条件时必须证明每轮有进展；"缓冲非空"≠"能产出"；
循环排查先问"每轮是否有状态单调推进"。gate 的 bench 偶发红要先看分布再判回归，禁止抬 budget 掩盖。
## 第888轮：批49 —— 修行号引用漂移 + 更正例58 的编造出处（`5300160`）
审计 X 复核批46/47 全部 PASS，提 2 条文档缺陷。我逐条自验，**两条都成立**。
### 缺陷 1：注释行号引用漂移（3/5 处已错）
批47 我在三处 drain 上方插注释 → 行号下移 → 注释里的引用没同步。
`test_security_layer.cpp:373` 写 `:321`（实际 `:323`）、`:411` 写 `:409`（实际 `:413`）、
`test_server_security.cpp:294` 写 `:292`（实际 `:300`）。
**修法（采纳 X 建议）：5 处全改符号引用** → `git grep` 行号引用归 0。
### 缺陷 2：例58 编造出处（W5 违规）
我写"例47 记的是改 .sh 禁止 WriteAllLines"——**编造**。全文 4 处 WriteAllLines
全在例58 自身；例47（`:724`）说的是 `ReadAllText`+`WriteAllText` 会加 BOM、CRLF→LF，
**方向相反**。
### 实测四种写法（PowerShell 5.1，`a\nb\nc\n`）
| 写法 | LF 源 | CRLF 源 |
|---|---|---|
| ReadAllText+WriteAllText(UTF8 no BOM) | LF 保持 | CRLF 保持 |
| ReadAllLines+WriteAllLines | **LF→CRLF**，多一尾部换行 6B→9B | CRLF 保持，多一尾部换行 |
| 连写两次 WriteAllLines | LF=4 CRLF=4（**非幂等**） | — |
**唯一规则**：只用 ReadAllText→Replace→WriteAllText（显式 UTF8 无 BOM），禁用 WriteAllLines，写完必查 CR/LF。
### 采纳 X 第三条
多处按索引插入必须**从后往前**（X 正向插 3 个插桩标记导致索引失效）。
### 验证
C0 六类诊断全 0；Linux ctest 67/67；Windows ctest 69/69（73.79s）；
Linux gate `LINUX GATE PASS` + `FAILED_COUNT=0`；行尾无混合；`MUT-` 0。
## 第889轮：批50 —— 修 orders_apply.h 的过期断言（`2d07aee`）
C9 扫描 `continue` 与"未实现"类注释时命中 `include/rtsc/render/orders_apply.h:50`：
原文称 "BS_HATCHED and BS_PATTERN are not implemented yet (TODO 3b3)"，
但 `src/render/orders_apply.cpp:337-342` 早已分发到 `ApplyPatternPatBlt`/`ApplyHatchedPatBlt`，
且 test_orders.cpp 有 9 个 pattern/hatch 用例。
**这是与例57 同族的"会过期的断言"**：描述旧状态，代码前进了注释没跟。
### 变异测试（第16条）
| 变异 | 结果 |
|---|---|
| `BS_PATTERN` 分发 → `false &&` | **5 failing / 224 failed checks**；`:1065`、`patblt_apply_pattern_and_hatch_supported` |
| `BS_HATCHED` 分发 → `false &&` | **5 failing / 1870 failed checks**；`:1088` 等 |
| 恢复 | 103/5793，**0 failing**；hash 一致；`MUT-` 0 |
### C9 同型复查
`capabilities.cpp:722`（MemBlt/Mem3Blt/SaveBitmap）准确；`orders_apply.cpp:347` 准确；
`gateway_transport.h:299` 明确写了 follow-up，准确；`cliprdr_client.h:94`/`file_list.h:5` 属 feature-gap（UNVERIFIED）。
### 验证
C0 六类诊断全 0；Linux 重建 0 错误 + `rtsc_orders_tests` 103/5793；
Windows ctest **69/69**（78.35s）；行尾一致；`MUT-` 0。
## 第890轮：批52 —— kClosed 明文丢失 + 陈旧构建守卫（`5349d77`）
### B. kClosed 携带明文被丢弃（真数据丢失，审计 X 报）
`gateway_transport.cpp` 两处 `&& status != kClosed` 过滤器把
"明文非空且同时报关闭"的情况丢弃。可达性：OpenSSL `:390-398` 先插明文再
ZERO_RETURN 且不清空；SChannel `:654-658` 注释明写 "keep the plaintext decoded so far"。
新增 `ScriptedClosingTls` + 2 个用例（drain 分支 / feed 分支），
红证 `n == 1 (got -2)` 与 `(got 0)`，修复后 123/1226 绿。
drain 分支再加 hardened EOF（交付两明文后 `kClosed` → 立即 `return 0`）。
变异（各自恢复 `&& kClosed`）→ 各只杀对应用例。
### C. 注释 nit
`orders_apply.h` "Only an unhandled style reports kUnsupported" → 补上
"handled style with out-of-range parameters (BS_HATCHED with BrushHatch > 0x05)"。
### 顺带：Write 期间明文入队无覆盖
`pending_.insert` 此前全仓 0 用例。新增 `ScriptedReadDuringWriteTls` +
`tls_byte_transport_keeps_plaintext_that_arrives_during_write`；
变异（抑制 insert）→ `:3958 n == 1 (got -2)` 唯一失败。
### 更正自己的误判
`:655` 的 `e.status` 是我自己的变异残留，HEAD 本就是 `if (!plaintext.empty())`，无此缺陷。
### verify.ps1 陈旧构建守卫（批51 版抓不到真正失败模式，本批重做）
dry-run 判据在 mtime 回退时也是空的。改为内容+size+mtime 指纹：
不一致就删 build 目录; build+ctest 全成功才写指纹。
红证：mtime 回退 30 天 → 打印 "stale build directory ... rebuilding from scratch"。
还修了自身缺陷：`$ErrorActionPreference="Stop"` 下 git stderr 警告会变成终止错误。
### 验证
C0 六类诊断全 0；rtsc_gateway_tests **124/1234**；Linux ctest 67/67；
Windows ctest **69/69**(83.61s)；`verify.ps1` EXIT=0；`verify.ps1 -LinuxBuild` EXIT=0 + LINUX GATE PASS；`MUT-` 0。
### 教训（discover 例 62/63/64）
陈旧产物会让测试结果与工作树脱钩（守卫要抓根因不抓症状）；
"某量==0"零信息量，断言要能区分两个世界；注释数量词必须数一遍。
## 第891轮：批53 —— 指纹改内容哈希 + M3/M5 覆盖（`9389bd8`）
### verify.ps1 指纹的 4 个洞（审计 X 攻击，我逐条实测确认）
| 攻击 | 旧指纹 | 新指纹 |
|---|---|---|
| A assume-unchanged + 等长改写 + mtime 回填 | fp 相同 | 抓到 |
| B 未跟踪头文件改写 + mtime 回填 | fp 相同 | 抓到 |
| C showUntrackedFiles=no + 新增源文件 | fp 相同 | 抓到 |
| D git 不可用 | fp = SHA256("") fail-open | 非空且随内容变 |
| E 对照：普通改写 | 抓到 | 抓到 |
**修法**：`Get-ChildItem -Recurse -File -Force` 枚举 src/include/tests/tools + CMakeLists.txt，
逐文件 SHA-256；枚举为空 `exit 1`。顺带解决成本问题：改 `.opencode/`、`docs/` 不再触发重建（实测）。
### M3 hardened EOF 零覆盖
删 `gateway_transport.cpp:565` 全套绿。补二次 Read 断言（`n2==0`、`read_calls==0`）；
红证 `:3931 n2 == 0 (got -2)` + `:3932 read_calls == 0 (got 1)`，唯一失败。
### M5 Write 侧 kClosed
X 的 `&& e.status` 变异是**等价变异**（e 恒 kOk，不可杀）；真正风险是 `&& r.status`。
给 `ScriptedReadDuringWriteTls` 加 `close_with_data`，新增用例；红证 `:4007 n == 1 (got -2)`。
### 注释更正
`ScriptedClosingTls` 的 "real backend answers kNeedMoreInput" 只对 SChannel 成立；
OpenSSL 返回 kOk + 空明文（`:404`）。已分别注明。
### 验证
C0 六类诊断全 0；gateway **125/1243**；Linux ctest 67/67；Windows ctest **69/69**(72.12s)；
Linux gate **LINUX GATE PASS** + 五标记；verify.ps1 EXIT=0 且改 docs 不触发重建；`MUT-` 0。
### 教训（discover 例 65/66）
守卫判据要直接观测被测事实，不能依赖 git 状态等间接元信息；"查不到"≠"没变化"；
变异报绿时先问该变异是否真改变了行为（等价变异不可杀）。
## 第892轮：批54 —— 指纹补 reparse fail-closed（`40d2d47`）
审计 X 复核批53：A/B/C/D 全堵、M3/M5 闭合、端到端 `-Clean -LinuxBuild` 通过（69/69 + LINUX GATE PASS）。
**残留 1 洞**：reparse point 不被 `Get-ChildItem -Recurse -File` 遍历。

我自己复现确认：接合点 `tree\src\inc` 下的 `value.h` 完全不在 `-Recurse -File` 结果里，且不报错。
后果：接合点内头文件是盲区 + mtime 回填 → Ninja 不重编 → "树变了但 verify 报绿"。

修法：遍历前扫 reparse，有则 `exit 1`（fail-closed）。
红证（直接抽取 verify.ps1 的真实代码块跑最小工程）：干净树 exit=0；加接合点 → 
`fingerprint refuses to run: 1 reparse point(s) ... cannot be hashed` exit=1。
当前四树 reparse=0，`verify.ps1` 与 `-LinuxBuild` 均 EXIT=0。

采纳 X 的表述更正：n2 断言在 `:3934/:3935`、Write-kClosed 在 `:4010`；
"MUT- 0" 精确为"构建输入 0"（记忆与 backups 里有该字样，但门只扫构建输入）。
### 教训（discover 例 67）
递归遍历不保证遍历到全部（链接/接合点会被静默跳过）；静默跳过比报错更危险；
判据覆盖性要问"有没有一类输入能让判据看不见变化"；自证 + 他证缺一不可。
## 第893轮：批55 —— 只拒绝目录型 reparse + 显式 -ErrorAction Stop（`5993d24`）
### 加固 1：权限拒绝盲区
X 指出两处 `Get-ChildItem` 无 `-ErrorAction Stop`。实测（从 verify.ps1 逐字抽取代码块，
icacls deny 一个子目录）：
| 条件 | 结果 |
|---|---|
| 无 `-ErrorAction Stop` + EAP=Continue + deny | exit=0，fp=`A2CAFE20...` |
| 文件完全不存在（参照） | fp=`A2CAFE20...` ← **逐字节相同** |
| 有 `-ErrorAction Stop` + deny | exit=1（fail-closed） |
已给两处加 `-ErrorAction Stop`。
### 加固 2：OneDrive 误伤
实测 OneDrive：`-Recurse -File` 枚举 400 个文件，其中 **392 个是 reparse**（可读、可哈希）；
`-Recurse -Force` 另有 582 个目录型 reparse。⇒ 文件型不是盲区，只有目录型是。
改为只拒绝 `PSIsContainer -and ReparsePoint`。
### 红证（抽取真实代码块）
干净树 exit=0；文件符号链接 exit=0 且改目标内容 fp 变化；目录接合点 exit=1 refused；
恢复后 fp 逐字节回到原值。
### 验证
`verify.ps1` EXIT=0；`-LinuxBuild` EXIT=0 → LINUX GATE PASS（中途一次 view bench 偶发红，
重跑即绿，例60 同族）；构建输入 MUT- 0；verify.ps1 CRLF 600/600。
### 教训（discover 例 68/69）
fail-closed 粒度要对准真正的危险（只有目录型 reparse 是盲区）；判据若在正常环境无法通过
就是障碍不是守卫；全局 EAP 是隐式契约，"必须失败"的操作要显式 `-ErrorAction Stop`。
## 第894轮：批56/57 —— bench 预算重设 + flood witness 确定性化（`d4f341a` / `f68eeb9`）
### 批56：view bench（`d4f341a`）
测量三个数后重设预算：空闲 0.11-0.16ms / 噪声峰值 0.89ms（并行构建）/ 真实回归
1.47-1.53ms（CopyExact 换成逐像素+除法）。
- 每用例新增 `iters` 使样本 ≥10ms（小用例对负载 7.4x、大用例 2.1x 的差异被抹平）
- 预算改为约 4x 空闲值：1:1 1.2、letterbox 1.1、2x 20、0.8x 80、0.5x4K 60、1.33x 12、0.4x4K 140
- 有界单次重试（打印 `retrying:`）
- Rule 16：逐像素+除法 → 11 用例红；float 加权混合 → 1:1 达 22ms、6 用例红；恢复全绿
- X 独立复测：同负载 HEAD 2/8 失败 vs 本改动 0/8，且变异仍被抓
### 批57：flood witness（`f68eeb9`）
X 报 `server_flood_vs_stop_race_converges` 负载下 flaky。**我 14 次全绿、checks 恒定，未复现**。
但读代码找到真因：launcher 在 accept 循环里**同步**调用（`server.cpp:2491`），旧实现让每个
launcher 固定睡 40ms 赌测试线程先置 `stop_began`；负载下测试线程可被挂起 >40ms → witness 恒 0。
修法：入口计数识别最后一个 launcher，有界等待 `stop_began` 后再启动（结构保证）。
Rule 16：`if (snapshot_taken && false)`（跳过所有 session->Stop()）→ `RED_TIMEOUT live=8` +
`FAIL stop_cleared`，不变量仍 load-bearing。
### 环境发现（例 70）
WSL 被另一个项目 `/mnt/f/tctp` 的交叉编译占满（load 8.7），另有 sqlservr/beam.smp。
这解释了之前三次 bench 偶发红。"重跑就绿"是逃避，不是证据。
### 验证
C0 六类诊断全 0；server 55/641；view 60/7348；Linux ctest 67/67；Windows ctest **69/69**(76.04s)；
Linux gate **LINUX GATE PASS**；构建输入 MUT- 0。
### 教训（discover 例 70/71）
时间断言必须先量空闲值/噪声峰值/回归值；witness 与不变量要分开，witness 依赖时序要改同步；
没复现不等于不存在，但必须标注"未复现，基于结构分析"。

## 第895轮：批58 —— flood 测试的注册等待预算随 launcher 暂停缩放（`9beeab0`）
### 怎么发现的
批57 后按"分支完备"逐个跑 `RTSC_TEST_LAUNCH_DELAY_MS`，发现 **`delay_ms=200` 时测试自己红**：
```
flood_vs_stop: launches=6 registered=-1 live=0 total=6 sockets=8 delay_ms=200
1 failing tests, 2 failed checks
```
`{0,1,5,40}` 全绿。服务器代码一字未改 ⇒ 红在测试自身。
### 根因
launcher 在 accept 循环里同步执行 ⇒ 非最后一个 launcher 的 `delay_ms` 睡眠串行化后续注册
（8 个连接要 `7 × delay_ms`）；而用例的注册等待是**固定 1 s**。`delay_ms=200` 需 ~1400 ms
→ `all_registered=false` → 只注册 6 个就发起 Stop()。失效阈值约 140 ms。
### 修法
`register_budget_ms = min(2000 + 4 × delay_ms × kConnect, 60000)`，并把耦合与实测阈值写进注释。
### 验证（分支空间）
delay ∈ {0,1,5,40,200,1000} × 2 次 = **12/12 绿**，`started_after_stop=1` 恒定；
delay=1000 实际耗时 ~7s（预算 34s）。
### Rule 16
变异缩放预算 → 固定 1000：`{0,1,5,40}` 仍绿，**只有 `delay_ms=200` 红**
（`launches=6 registered=-1`、2 failed checks）⇒ 缩放正好且仅在该生效处 load-bearing。
恢复：hash 一致、MUT- 0、确实重编、12/12 再绿。
### 验证（C0）
Windows Release 六类诊断全 0；Linux 全量重建 0 错误 + ctest **67/67**(84.84s)；
Windows ctest **69/69**(74.37s)；Linux gate **LINUX GATE PASS** + `FAILED_COUNT=0`；
test_server.cpp CRLF 4583/4583；构建输入 MUT- 0。
### 教训（discover 例 72 / memory 规则 76）
测试装置自己的参数空间也是分支；任何"可调大"的旋钮，其最大有用值必须被测试自身的等待预算覆盖；
判据是问"把这个旋钮调到 10 倍会怎样"。
## 第896轮：批59 —— 修我自己在批56 引入的 gate 断言退化（`ca0aad1`）
### 缺陷
批56 的 bench 重试行用 `[bench]` 标记，而 gate 断言 `grep -c "\[bench\]" >= 7`。
重试行被算成结果行 ⇒ "1 个用例被编译掉 + 1 个用例重试" 计数仍为 7 ⇒ gate 假绿。
### 红证（sed 抽取 gate 真实断言块）
| 场景 | 修前 | 修后 |
|---|---|---|
| 健康 7 条结果行 | 0 | 0 |
| 6 条结果 + 1 条 retry | **0（假绿）** | 1 |
| 7 条但缺 `0.5x 4K`、`0.4x 4K` 重复 | — | 1（身份断言抓） |
### 修法
1. 重试行改 `[bench-retry]` ⇒ 计数只含结果行。
2. 加逐用例身份断言（7 条正则，标签后必须紧跟数字串，避免 `1:1` 匹配 `1:1 letterbox`）。
### Rule 16
改回 `[bench]` ⇒ B 复现假绿；删身份循环 ⇒ D 变绿。两层各自 load-bearing。
### 验证
Linux gate PASS + 67/67 + VIEW_BUDGETS=executed；真实 RelWithDebInfo `bench_lines=7 retry_lines=0`
60/7348，负载下 0.8x 55.78/80、0.5x4K 42.09/60、0.4x4K 97.38/140（~1.43x 余量）；
Windows 六类诊断全 0 + ctest 69/69(82.47s)；bash -n OK；MUT- 0。
### 教训（discover 例 73）
给测试加输出时必须 grep 该标记在 gate 里的全部消费者；计数断言升级为身份断言；
修完要给两层红证；**"我自己刚改的代码"最该怀疑**——Rule 16 变异只测抓回归能力，不测门禁是否变弱。
## 第897轮：批60 —— bench 注释事实错误 + iters 让"样本>=11ms"成立（`bb6d371`）
### 缺陷（批56 我写错的注释）
"Every budget is about 4x the idle measurement" 实际是 **3.3x–10.9x**（注释自带表可算）；
"roughly 1.5x to 2x headroom" 实测是 **1.43x/1.43x/1.44x**；
"every sample is at least ~10 ms" 不成立（2x 9.6ms、1.33x 7.2ms）。
### 修法
按实测重写注释（3.3x–10.9x，说明小用例给大倍数是因 1ms 抖动地板）；iters 2x 2→3、1.33x 4→6，
七例空闲样本 15/16/14.4/22.9/16.9/10.8/43 ms 全部 ≥10.8ms。
### Rule 16
`CopyExact` 的 memcpy → 逐像素+取模（唯一变异）：1:1 **9.22 vs 1.20 红**、letterbox **9.59 vs 1.10 红**，
其余 5 例绿 ⇒ 60/7348，1 failing/2 failed，EXIT=1。红态下 `bench_lines=7`（重试行走 `[bench-retry]`）。
恢复 hash 一致、MUT- 0、确实重编。
### 验证
RelWithDebInfo 绿态 `bench_lines=7 retry_lines=0` 60/7348，实测 0.15/0.16/6.48/18.41/17.89/3.06/37.74；
Linux gate PASS 67/67；Windows 六类诊断全 0 + 69/69(81.16s)；MUT- 0。
### 教训（discover 例 74）
注释里每个数字都要从表里算一遍（"表在、结论错"最该避免）；余量要给实测值不给区间；
注释描述实现，不能让实现迁就注释。
## 第898轮：批61 —— 采纳 X 的 flood 防御性洞 + deadline，bench 注释去逐值（`7c54e1a`）
### 未复现声明（W5）
X 报 "Windows Debug + 全量 + 40 burner" 下 OLD(d687048) 1-2/6 红。我同条件实测
**OLD 0/8 红、NEW 0/6 红**（本机 32 核，burner 配比不等价）。**未复现**，但两条修复
是独立逻辑缺陷，不依赖复现。
### 1. flood 用注册数而非 launcher 调用数（X §2 问题2）
`index == kConnect` 假设"launcher 调用序 == 注册序"，但 `server.cpp:2509` 的
`if (!started) { release(); continue; }` 会回滚注册而该次 launcher 已计入 ⇒ 洞。
改为 `session_count() >= kConnect` + `gate_claimed` CAS 保证恰好一个 park，
新增 `gate_waited`/`gate_expired` 并**断言**（让"从未 park"和"park 超时"显式失败）。
### 2. 有界等待改真实 deadline（X §6）
实测 `sleep_for(1ms)` = **15.50ms**（100 次=1550ms），5000 次 ≈ **78s** 而非 5s。
改 `steady_clock` 10s deadline + `gate_expired`。
### 3. bench 注释去逐值（X §4）
X 实测 13.3/11.0/5.2/6.0/5.4/7.5/5.2x；我实测 10.9/10.0/4.4/5.4/5.0/6.3/4.6x
⇒ 比值随机器漂移近 2x，逐值表必然过期。改为陈述不变量（绝对余量 ~1.4x），
并把"前两版注释都错了"写进注释。
### Rule 16
删 `gate_waited.store` ⇒ 6 值全红；`>= kConnect` → `+1`（永不 park）⇒ 全红且 delay=1 时
witness 归零。恢复后 10/10 绿、`gate_wait=1 gate_expired=0` 恒定。
### 验证
Linux gate PASS 67/67；Windows Release 六类诊断全 0 + 55/642 + ctest 69/69(73.46s)；
**Windows Debug `verify.ps1` 69/69**(150s)；负载下 NEW 0/6 红；CRLF 4619/4619、1535/1535；MUT- 0。
### 教训（discover 例 75/76）
"迭代 N 次"不是时间上界（Windows sleep_for(1ms)=15.5ms）；跨机器测量值不能写进注释
（同一注释数字本轮连错三次）。
### 任务收尾：
补充发现（C9 同型排查，见 discover 例 77）：全仓 18 处 `sleep_for(1ms)` 已分类——
2 处 deadline（正确）、1 处批61 已改、2 处是原子信号同步点（非上界）、其余为带 CHECK 的短轮询。
`sleep_for(10ms)xN` 的 80 余处在 Windows 上会拉长失败等待但不动判定，**登记不改**（风险大于收益）。
## 第900轮：批62 —— gate 从"计数"升级为"身份+实际工作量"（`8a35947`）
### 五条缺陷（4 条来自 Y2 独立审计，1 条来自 X 的 Q3）
1. **bench 门禁测不出"体没跑"（中）**：`measure()` → `return 0.01;` 仍 PASS。
   修：测试打印 `[bench-calls] label calls=N want=M`，gate 断言 7 条且 `calls>=want`。
   红证：7 failed checks（calls=0）。
2. **第 8 个用例不强制改 gate（低）**：`-lt 7` → `-ne 7`。
3. **FACTORY_SYMBOL 可被 U 符号满足（低）**：加 `nm --defined-only`（真实 archive 复现假阳）。
4. **SEC_TESTS 下限可补足（低）**：`-ne 9` + `checks>=79`。
5. **gate_waited 不够抗改（中，X 做出假绿）**：改为 `gate_claimed`/`gate_entered`/`gate_parked`
   三点断言。红证：复现 X 攻击 → 全红且 `gate_claim=0`。
### 反驳 Y2 一条
Y2 建议把 1:1 预算收到 4x；批56 实测噪声峰值 0.89ms > 4x 空闲 0.44ms ⇒ 必假红，不采纳。
改为在 commit 措辞上限定"≥5x 结构回归"。
### 顺带闭合批50 的 UNVERIFIED
`file_list.h:5` / `cliprdr_client.h:94` 声称 direction-B 未实现，实际 `DropFileList` 已实现
且有 tests/test_drop_files.cpp。变异 `offset > size` → `false &&` ⇒ `test_drop_files.cpp:419` 红。
### 验证
Linux gate PASS 67/67 + VIEW_BUDGETS/UI_RATIO；RelWithDebInfo `calls==want` 60/7355；
Windows Release 69/69(88.13s)；Windows Debug verify.ps1 69/69(143s)；delay 5 值 ×2 全绿；MUT- 0。
### 教训（discover 例 78/79）
三层断言若读同一个量则等于一层；下限在可增可减集合上必 fail-open；
单一"我执行过"标志会被位置改变架空，必须入门+出口+认领三点断言。
## 第901轮：批63 —— marker 限定 case 区块 + 预算按负载重标定（`4d50ae2`）
### 采纳 X 的五条
1. P0/UI marker 整日志 grep 可被别的用例同串骗过（真实二进制红证：suite 9/79 全绿、
   旧检查 PASS、新区块检查 FAIL）。
2. **我第一版 awk 正则多一个空格** ⇒ `[ RUN  ]`/`[  OK  ]` 全不匹配 ⇒ honest 日志被拒
   ⇒ `LINUX GATE PASS` 不可能打印（`bash -n` 仍 OK）。
3. **gawk 内置名 `case` 不能当变量** ⇒ 脚本 fatal 不工作（`bash -n` 仍 OK）。改名 `want`。
4. C/D 空白边界（尾随空格、CRLF）⇒ 改按用例名 + 剥前后空白。
5. `:180` 的 `OK .* <case>$` 未锚定 ⇒ `^\[  OK  \] <case>$`。
### 预算重标定（X 的发现）
X 实测负载下 0.8x/0.5x4K/0.4x4K 三个全超、1:1 从未接近。本机 40 burner 复现
0.4x 4K **138.07/140(99%)**。新预算约 2x 负载峰值：2x 30 / 0.8x 150 / 0.5x4K 115 /
1.33x 18 / 0.4x4K 280。验证 4/4 轮绿、零重试、最坏余量 61%。
### 诚实登记的残余缺陷
0.4x 4K（倍率 2.5，非整数）走 generic tap walk；三种变异都只变 1.02-1.05x
⇒ 该用例的 ms 预算**无法表达 2x 算法回归**，只能抓 ≥8x。已在注释写明判别力上限，
精细守护交给 0.5x 4K（uniform 路径，变异到 3.1x）。
### 验证
Linux gate PASS 67/67 + 三标记；Linux ctest 67/67(79.76s)；Windows Release 69/69(76.09s)；
Windows Debug verify.ps1 69/69(129s)；MUT- 0；CRLF 1564/1564、427/427；gate LF 430。
### 教训（discover 例 80/81）
`bash -n` 只验语法不验语义；awk 变量名要避开内置名；块正则必须对真实 harness 输出验证；
性能预算的"假红率"与"检出率"必须分开测，预算宽可能是"该用例测的不是算法"。
## 第902轮：批64 —— [bench-calls] 解析器畸形行 fail-closed（`8711c9a`）
### 缺陷（Y2 §2 硬化建议）
`sed` 对不匹配行原样输出 ⇒ awk 看到 ("[bench-calls]", <label>)；当前标签恰好触发检查，
但**以 0 或非数字开头的标签会静默通过**。
修法：`NF != 2` + 两个字段都必须纯数字 + 数值比较，三条件任一不满足即 bad。
### 五场景红/绿证（提取 gate 真实块，358-367 含 if/fi）
healthy 通过；缺 `want=` / `calls=0` / 数字开头畸形 / `calls=999` 全部 FAIL。5/5 符合。
### 本轮我自己的三次验证脚本失误（见 discover 例 82）
片段提取不完整、多行引号被二次解析、`if` 退出码语义写反 —— 三轮结果全错。
教训：**验证脚本必须先跑一个已知答案的场景自检**。
### 验证
Linux gate PASS + FAILED_COUNT=0 + 67/67 + 三标记；bash -n OK；MUT- 0；gate LF 438。
## 第903轮：批65 —— 更正分支守护归属 + gate 提取器自检（`0f4fcfa`）
### X 的两处更正（我独立复现，X 对、我错）
分别只把一个分支的行循环跑两遍：
| 变异 | 0.5x 4K | 0.8x | 0.4x 4K |
|---|---|---|---|
| uniform ×2 | 13.92→**24.89 (1.79x)** | 14.70（无） | 29.44（无） |
| generic ×2 | 14.51（无） | 20.50→**39.18 (1.91x)** | 40.57→**75.35 (1.86x)** |
⇒ 0.5x 4K 护 uniform，0.8x 护 generic（判别力最强），0.4x 4K 是非整数倍率的存活性守护。
批63 注释"精细守护交给 0.5x 4K"是错的，已改。
### gate 提取器自检（采纳 X 建议）
`selftest_p0_block_has_marker()`：用内联已知健康日志先跑一遍，失败即
`extractor itself is broken`。Rule 16：重新注入"多一个空格的正则"与 `-v case=`
两个历史错误，自检均 REJECTED（后者报 gawk builtin fatal）。
### X 的 Q2 G 场景
X 用 gate 原文函数实测 G = rejected（正确）；我上报的表写 accepted，**是我的表错了**
（跑的是更早的整行比较版本）。G 不改。
### 验证
Linux gate PASS 67/67；RelWithDebInfo 60/7355；Windows Release 69/69(76.98s)；
Windows Debug verify.ps1 69/69(134s)；MUT- 0；gate LF 461；test_view.cpp 1577/1577。
### 教训（discover 例 83）
多路径函数必须按路径分别变异；写"X 守护 Y"必须证明"Y 坏时 X 红"；
不能因免疫某变异就删用例（形状覆盖另算）；我的表与审计冲突时默认我错。
## 第904轮：批66 —— 四处边界闭合 + 双向自检 + 数字可推导化（`53fde63`）
### Y2 的真缺陷：块不闭合
`inb = (name == want)` 在 OK/FAIL 行仍为 1，块等下一个 RUN 才关。实测
marker-after-OK / marker-after-FAIL 均 **accept（应为 reject）**。修法：先剥 tag,
`tag=="RUN" && name==want`。修后 5/5 正确。P0 与 UI 都有此洞。
### X 的 fail-OPEN
HEAD 版自检只钉"接受"：`return 0` 时自检 ACCEPT + 真实检查 ACCEPT ⇒ marker 门已死
而 gate 仍 PASS。实测三变体证实。改共享 helper `selftest_marker_extractor`，
钉四边界（健康接受 / 他人marker拒 / OK后拒 / FAIL后拒），P0+UI 各调一次。
Rule 16：BASELINE 绿，ALWAYS_ACCEPT/ALWAYS_REJECT/NO_SCOPE/NO_CLOSURE/BAD_REGEX/
CASE_BUILTIN 六变异 P0+UI **全部 caught**。
### UI_CASE 未接线（Y2）
`-v want` 仍硬编码字符串，改 `UI_CASE` 不影响真检查 → 改 `-v want="${UI_CASE}"`。
### 数字纠正（Y2 + X）
- "only catches >=8x" 无推导 → 改 budget/base：5.5x-12.1x（本机实测算得）。
  并写明 **2x 结构性回归不可见**（MUT-STRUCT 2.0x → suite rc=0）。
- "per-pixel division is 10x" 只在**整条快路径被替换**时成立；只加除法是 2.3x 仍绿。
- 跨机数字：X 定量一致（0.8x 是 generic 最佳探针）但量级差大；'unmoved' 不精确
  （0.4x 4K 在无关变异下稳定快 10%）→ 改区间 + 双机标注 + 写明 <1.0 是缓存效应。
### 验证
Linux gate PASS 67/67；Windows Release 69/69(86.21s)；Windows Debug 69/69(127s)；
MUT- 0；resample.cpp 未改（18104 bytes BOM 完整）。
### 教训（例 84/85/86）
自检必须钉双向（只钉接受会放行 `return 0`）；区间提取必须定义开启+关闭；
注释数字必须可推导（公式/区间/多机），不能抄一次测量。
## 第905轮：批67 —— eval 注入面 + 大小写 tag + 撇号撕引号（`7a6d268`）
### X 的 1.1 eval 注入（实测可达）
`eval "$logvar=..."` 传 `EVIL; echo INJECTED` 真的执行了 echo。改用 `printf -v`（写）
+ `${!logvar:-}`（读），修后报 "invalid variable name" 而非执行。两处调用点今天传字面量，
但参数化 helper 不该留活注入面。
### X 的 1.2/1.4
`mktemp` 失败加准确报错；helper 收尾 `unset -f reset restore expect_accept expect_reject`
（实测 declare -F 计数 0，原泄漏在 set -u 下顶层误调会致命）。
### Y2 的大小写 tag（真残留）
`[ ok ] <P0>` 不闭合块 ⇒ 其后 marker accept（应 reject）。改大小写白名单，修后 4/4。
### Y2 的自我纠正（我也独立证实）
`^\[[^]]*\]`（任意方括号行当边界）会把块内的 `[rtsc-server] WARNING:` /
`[GCC] static channels:` 当成边界 ⇒ **假红**。已写进注释禁止该写法。
### 我自己引入的新错误：撇号撕开 awk 程序（discover 例 87）
在 awk 单引号程序内写 `'ok'` 使 shell 引号被闭合，awk 程序被切成 shell 词、
`#` 变 shell 注释。**全文件 `bash -n` 仍 rc=0**（引号总量平衡），但提取器变成永远 accept。
检测：片段级 `bash -n`（rc=2）+ 场景矩阵（4/6 翻转）。
### 自检扩到六边界
新增 `[ ok ]` 小写关闭（须 reject）与「块内含 `[rtsc-server]`/`[GCC]` 行」（须 accept）。
Rule 16：BASELINE 绿；UPPER-ONLY / ANY-BRACKET 两回归均 caught；撇号变体语法错 fail-closed。
### Y2 的 Q3 措辞修正（discover 例 88）
`budget/base` 是**阈值倍数**不是最小可检测回归；改说 "trips at Nx wall-clock"，
并标 idle 口径（8.3x）与负载口径（≈4.9x）。
### X 的 3.2
三机区间 6.4x-11.5x / 7.1x-12.8x / 本机 → 合并写 5.5x-12.8x，"do not quote a single number"。
### 验证
Linux gate PASS 67/67；Win Release 69/69(85.14s)；Win Debug 69/69(126s)；MUT- 0；
片段级 bash -n rc=0。
## 第906轮：批68 —— 七边界 + RUN 大小写 + 删除死守卫（`546edab`）
### Y2 的四个宽松 fail-open（全复现，全修）
六边界只钉"是否在块内"，不钉"marker 精确"与"用例名相等"：
MARKER_LOOSE / MARKER_PREFIX / NAME_PREFIX / NAME_PREFIX2 全部 rc=0 漏。
加两条边界：截断 marker（`${marker%??????}` 去尾部，不是追加后缀）、前缀用例名。
### Y2 的 RUN 大小写（我修时踩了两层）
先改 `tolower(tag)=="run"` **无效**（8 拼写仍 reject）。逐字段打印发现真正根因是
名字剥离正则 `[A-Z]+` 只吃大写 ⇒ `[ Run  ] case` 时 name 保留整行。
改 `[A-Za-z]+` 后 8/8 accept，真实 harness 仍 accept。
### 我批67 的死守卫（自己发现，已删）
"awk 程序内撇号静态守卫"从未生效：守卫自身 `awk -v q="'"` 带两个撇号。
重新注入原错误，守卫沉默。已删除，注释写明"不要试图静态检测"，
语义闸是七边界自检（Y2 也独立指出片段级 bash -n 不是语义闸）。
### 我另发现的 fail-OPEN（logvar 撞名）
`logvar=rc` 时 reset 写 helper 自己的 rc、restore 写回入口值 0 ⇒ `return "$rc"` 恒 0，
**永久损坏的提取器也 rc=0**。已加：合法标识符校验 + helper 局部名黑名单 + readonly 检测
+ printf -v 失败准确报错。修后 logvar=rc 在完好/损坏提取器上均 rc=1。
### Rule 16
八变体：MARKER_LOOSE/MARKER_PREFIX/NAME_PREFIX/NAME_PREFIX2/ALWAYS_ACCEPT/NO_SCOPE/
NO_CLOSURE 全 caught；BASELINE 绿。RUN 大小写矩阵 8/8。
### 验证
Linux gate PASS 67/67；Win Release 69/69(73.22s)；Win Debug 69/69(83s)；MUT- 0；
产品代码未改（只改 gate 脚本）。
### 教训（例89/90/91）
边界测试要覆盖"匹配多严"这个独立维度；守卫本身必须做 Rule 16（死守卫比没守卫更糟）；
同一语义在多处实现时逐一检查，靠逐字段打印而非猜测定位。
## 第907轮：批69 —— 十四边界（TAIL/MID/大小写）+ 数组与短 marker 守卫（`18ac6d3`）
### Y2 的 Q4：三条，两条真漏一条归类错误
```
MARKER_TAIL    (/record/)           七边界 ACCEPT 漏 -> 九边界 REJECT caught
MARKER_MID     (/coalesced record/) 七边界 ACCEPT 漏 -> 九边界 REJECT caught
MARKER_TOLOWER (tolower($0) ~)      九边界 REJECT caught
MARKER_CASE_INS([Dd]rain)/           归类错误：无 marker 三场景全 reject => 只是拼写宽容
```
- tail 截断改比例 `${marker:0:${#marker}*2/3}`（Y2 指出 `%??????` 在 len==6 塌空串、
  len<6 原样返回）。
- 加 head 截断 `${marker#??????}`（同时覆盖 MID）+ 全大写探针 + 交替大小写探针。
### X 的数组发现：实测不是 fail-open
`declare -A` + 健康提取器 rc=0，但 + 损坏提取器 rc=1 => **vacuous pass 不是 false green**。
仍按 `logvar=rc` 同等标准拒绝（`*a*|*A*` 分支）。九种 declare 组合实测通过。
### X 的 marker 长度下限
`[ "${#marker}" -le 12 ]` return 1。
### 验证
Linux gate PASS 67/67；Win Release 69/69(75.43s)；Win Debug 69/69(83s)；MUT- 0。
### 教训（例92/93）
"放宽"不等于 fail-open：要证明 fail-open 必须给出一个输入使它 accept 而正确实现 reject；
截断探针有四个方向（头/尾/中/大小写），只截尾部只能证明"不是只匹配前半段"。

## 第908轮：批70 —— 更正数组注释事实错误 + 整数变量拒绝 + 探针独立性（`672b684`）
### X 更正我的数组判定（X 对，我和 X 上一轮都错）
我批69 注释写 "printf -v writes element [0] and leaves $logvar empty, so every probe
runs against an empty path... vacuous-pass"。实测：
```
declare -A V=([k]=orig); printf -v V '%s' "/tmp/probe"
  scalar=[/tmp/probe]  elem0=[/tmp/probe]  wc -l < "${V}" -> 3
```
**读写同址到 [0]，数据路径完好，自检完全正常。** 注释已整体重写；
仍拒绝数组，但理由改成"让数据路径显式可见，不依赖标量/元素别名"。
唯一真实副作用：restore 在关联数组里新建空 [0]（gate 无影响）。
### X 的 `declare -i`
原行为已 fail-closed（printf -v 当算术表达式报错 → reset 的 || return 1），
但报错文本误导。已加显式 `*i*` 分支，四种组合实测 rc=1 且报错正确。
### X 的探针独立性（我实测证实两条）
```
variant                  P01  P02  P03  P04  P09  P10  P10b
ONLY_FAIL_CLOSE_BROKEN   acc  rej  rej  acc  rej  rej  rej   <- P04 绿，P03 红
CLASS_REGEX_[Dd]         acc  rej  rej  rej  rej  rej  acc   <- P10b 绿，P09 红
```
⇒ P03/P04 独立；P09/P10 也不等价。
**但更正 X 一处**：X 说 "P10 能抓 [Dd]"，实测 P10（`DrAiN`）也抓不到 ——
`[Dd]rain` 只接受 `Drain`/`drain`。登记为已知盲区（非 fail-open）。
### X 的 2/3 vs 1/2
维持 2/3：两个探针是互补方向，改 1/2 是同轴移动不增维度。
### 我自己的失误：旧变异脚本静默失效
`rule16_b68.py` 的 NO_CLOSURE/BAD_REGEX 替换串针对旧版 `tag == "RUN"`，
源码改成 `tolower` 后替换不匹配 ⇒ 变异根本没应用，但输出显示 "MISSED"。
换 `rule16_final.py` 后 11/11 全 caught。记入 discover 例 95。
### 验证
Linux gate PASS 67/67；Win Release 69/69(78.21s)；Win Debug 69/69(95s)；MUT- 0。
### 教训（例94/95/96）
注释里的"为什么"必须与"做什么"同等验证；变异测试第一步是断言变异已应用；
"接受更多拼写"不等于 fail-open（要给出"该拒却受"的输入）。

## 第909轮：批71 —— 更正大小写探针注释 + 拒绝 nameref + 14 形状矩阵（`f354a1c`）
### X 的 Q1 两处"错误"：一条作废、一条成立
- **错误 A 作废**：X 用 Python `i=0` 起枚举得 `dRaIn`，但 gate 真实构造是 awk 1 基
  （`i=1 -> i%2=1 -> toupper`）⇒ 首字母大写 `D`，实测产出 `DrAiN: cHaLl...`。
  原注释正确。X 在续报里主动撤回，并总结"审计别人构造的字符串必须复用同一构造函数"。
- **错误 B 成立**：`DrAiN` 不匹配 `/[Dd]rain/`，原注释"交替探针能抓逐字符类"自相矛盾。
  已重写为 KNOWN GAP 段（含三场景非 fail-open 的实测依据）。
### X 的 nameref（Q3 + §4）
`declare -n` 的 flag 串只有 `-n`，三个既有分支全不匹配：
- nameref→数组：写穿 `REAL[0]`，**数组守卫完全绕过**（最强理由）
- nameref→readonly：目标自身拦住 rc=1
- nameref 链：写穿到末端
- nameref→未设置：printf -v 创建新全局变量
已加 `*n*` 分支。
### X 的 flag 顺序（Q2）
`*i*` 放 `*a*` 之后正确，不调整：`-ai` 被 `*a*` 先吃 ⇒ 报"是数组"（更准确）。
### 14 种变量形状矩阵（我独立实测）
plain/export = 0/1（正常）；其余 12 种（readonly / readonly数组 / readonly+int /
readonly+export / 索引数组 / 关联数组 / 整数元素数组 / 关联整数数组 / 整数 /
nameref三种）= 1/1 全部拒绝。
### X 的 §5 建议
"仓库加 `extract_fn` helper、所有审计/变异脚本统一用它提取真实函数体并断言唯一性" ——
**采纳为方法学规则写入 memory**，不加进 gate（gate 不需要提取自己的函数）。
### 验证
Linux gate PASS 67/67；Win Release 69/69(74.55s)；Win Debug 69/69(86s)；MUT- 0。
### 教训（例97/98）
审计构造的输入必须复用真实构造函数；按 flag 串判断变量形态的守卫对 nameref 一律失明。
