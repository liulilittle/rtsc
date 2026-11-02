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
## 第841轮：W8 裁剪（process.md 1010→836 行）+ 双审在途
### 裁剪（字节级操作，遵循 discover 第 21 例）
- 把 806-820 轮（192 行逐轮细节）压缩为 8 行归档摘要（保留：所有提交号、失败判定、
  关键教训指针、被驳回的疑点）
- 方法：`ReadAllText(UTF8)` → 行切片 → `WriteAllText(UTF8)`（**全程字符串级，无 latin1 中转**）
- 校验三件事：①字节数方向 91585→73829（变小 ✅）②`U+FFFD`=0 ✅ ③标题结构完好（42 个 `## `，
  821-840 逐轮保留）✅
- 备份：`.opencode/backups/process.md.pre841`
### 四文件现状
`discover.md` 797 行/65.2KB、`memory.md` 764 行/159.8KB、`plan.md` 696 行/57.4KB、`process.md` 836 行/72.1KB
### 在途
审计 L `ses_e66978403ffeW2pFrvAxAFLkgp`（批 19 复验：UAF/挂起/RTTI/lost-wakeup）、
设计审计 M `ses_e664d2035ffev3TAIwV4TuCE9J`（几何定案）
## 第842轮：审计 L 判 J-1 FAIL(High，挂起 + UAF) → 批 21 已派
### 审计 L（`docs/spec/input-batch19-review-L.md`）
- **J-1 FAIL(High，两项)**：
  ① 快照分配失败被吞 ⇒ `sessions` 空 ⇒ 一次 `s->Stop()` 都不发；`RdpSession::Stop()`（`server.cpp:756-759`）
     才是置 `stop_requested_` 的唯一入口，`listener->Close()` 不影响已 accept 的 transport ⇒ 会话线程不退出 ⇒
     `live` 永不为 0 ⇒ `cv.wait` **永久挂死**（实测 20s）
  ② `cv.wait` catch 吞掉后立即返回（实测 `live=1`），违反 `server.h:293-295/304-310/317-324` 的
     "借用指针 must outlive the server (including Stop())" ⇒ **UAF**
  - 我写的两处"安全论证"注释（`:2504-2507`、`:2520-2523`）**都被代码证伪**
- J-2 PASS（`dynamic_cast` 在 `:731-733`；全仓零 `/GR-`；6 个 hook 全 nullptr 早退；还原 static_cast 后新用例挂死 30s）
- J-3a PASS + Low（三个断言全是 `==0`，删 `fetch_add` 仍绿 ⇒ "能涨"侧无回归保护）
- J-3b PASS（`store(true)` 在 `mu_` 内且 wait 前，notify 方持同一 `mu_` ⇒ 无 lost-wakeup）
- J-4 PASS（双 IRP；逐项 `break` 与整圈 catch 两种变异均红）
- J-5 PASS + Low（`review-F.md:340` 括注 `a59a594` 与行号 `776-791`（属 `6fc5614`）不匹配）
- 回归：build 零错零警告、ctest 63/63、三套件 0 failing
- 如实披露：08:09 一次 `server` 失败 13 次重跑不复现（在报告上未归因）；一次探针误写入共享工作树已按同一 blob 恢复
### 批 21 `ses_e66140044ffeWtCbsIG4OB7yES`
新增两条不变式并要求写进注释：
- **I1 不得静默成功**：任何"没能确认全部会话已停止"的路径必须留可诊断输出
- **I2 不得 UAF**：仍有会话线程可能访问借用指针时 `Stop()` 不得返回；超时不得当成功
修法：①快照失败时改为**锁内直接遍历 `registry->sessions` 调 `s->Stop()`**（无分配）②等待改 `wait_for` 循环 + 周期告警
+ ③删改两处错误注释 + ④`server.h` Stop 契约补"会阻塞到全部退出"
测试：`server_stop_delivers_stop_when_snapshot_allocation_fails`、`server_stop_does_not_return_while_session_thread_alive`
+ J-3a 补"能涨"断言 + J-5 括注修正；变异 2 个
### 教训
`discover.md` 第 26 例：**`catch(...)` 不是安全，它把失败转移给调用者的假设**；注释里的"安全论证"必须能被代码证伪。
## 第843轮：设计审计 M 交付（几何定案草案）→ 已派第二名审计 N 交叉
### M 的核心定案（`docs/spec/input-geometry-design-M.md`，653 行）
1) 四步公式：`fx=clamp(wx,0,fbw-1)` → `lx=round(fx*(cw-1)/(fbw-1))`（端点锚定）→ `px=cx+lx` →
   `rel=clamp(px-dx,0,dw-1)` → `nx=min(65535,ceil(rel*65536/dw))`；flag 恒 `MOVE|ABSOLUTE|VIRTUALDESK`
2) **分母裁决（争议）**：用 `65536/width`（解码侧 `n*w>>16` 的互逆），判现有 `extent-1` **为错**；
   代价是改一条已绿断言 `tests/test_desktop_input.cpp:272-279`（`(1920,1080)→65535` 改 `65502`）
3) `InjectGeometry` 最小集：`width/height + capture{4} + desktop{4} + bool mapped`；**不加 DPI、不加 `use_virtual_desk`**
4) `DesktopSource` 推荐**方案④** `virtual DesktopGeometry Geometry() const { return {}; }`（非纯虚带默认，老实现零改动）
5) 变异 9 项；**诚实披露**：M5（分母）在**稀疏落点级 0 命中**、M6（采样相位）只有 B0 一个稀疏点能抓
6) 可达性数值例：monitor1(1920,0) 1280x1024、桌面 3200x1024、fb 1280x1024、客户端(640,512)
   → 应落 **(2560,512)**，现实现落 **(1601,512)**（偏 −959 px 且跨屏）；`--monitor -1` 方向正确但 49.18% 偏 1 px
- 自检：落点表 21 行、变异表 9 行、§6.1 全像素 1310720、§6.5 分母枚举 5 组 → 全部 0 不符；文档 lint 通过
- UNVERIFIED 9 项（U1-U9）；§11 冲突登记含 `input-injection-evidence.md:139,144` 分母与 `tests:272-279` 端点
### 第二名审计 N `ses_e66????????`（已派）
必答四项：①分母裁决（自取证 `MOUSEINPUT` 原文 + 解码源码，自己枚举 5 个宽度全像素算失配）
②采样相位（端点 vs 中心 vs 起点，找 GDI `StretchBlt` 真实证据）
③M5 稀疏 0 命中是否意味着**无法被测住**，给出能抓住它的最小断言
④字段集是否会丢信息（混合 DPI / `VIRTUALDESK` 恒开）
### 状态
审计 M 待 N 的交叉回执后再收口；批 21（J-1 挂起/UAF）仍在途，与 N 只读审计无冲突
## 第844轮：批 21 落盘已核（等 relay）；真机清单补计数与 Stop 契约
### 批 21 工作树核验（只读，未提交）
- `server.cpp:2548-2562` 已写入不变式 **I1/I2** 注释（含"listener close alone does NOT unblock an accepted session"
  与"a timeout is not success and must never end the wait"）
- `:2565-2613` 快照失败 → 打印诊断 + **锁内直接遍历 `registry->sessions` 调 `Stop()`**；成功则锁外遍历
- `:2615-2665` 等待改为 `wait_for(2s)` 循环，每轮超时打印 `[rtsc-server] stop: N session(s) still live after Xs`，
  `wait_failed` 时额外打印并 `sleep_for(100ms)` 退避；**只有 `live==0` 才 return**
- 新测试：`tests/test_server.cpp:3458 server_stop_delivers_stop_when_snapshot_allocation_fails`、
  `:3534 server_stop_does_not_return_while_session_thread_alive`
- J-3a 已补"能涨"：`tests/test_desktop_input.cpp:1296 desktop_input_worker_failures_counts_a_failed_dispatch`
  + hook（`test_hooks.h:34-35`）；`win32.cpp:388/395` 两处 `fetch_add`
- 环境注入开关 `StopFailureInjection`（`server.cpp:117-145`，env-gated，仅测试用）
### 本轮独立产出（与批 21 不冲突）
`docs/spec/input-injection-real-machine-checklist.md` 补 §10 两条计数（`input_release_failures` 应恒 0、
`input_worker_failures` 应恒 0）+ 新增 §11「停止与退出（`Stop()` 契约）」三条真机项
（有限时间返回、关闭后销毁宿主对象不崩、无输入会话应立即返回）→ 文件 102 行、`U+FFFD`=0
### 在途
批 21（等 relay 报告）、审计 N（几何定案交叉）
## 第845轮：主代理独立复算分母裁决（审计 M 的核心争议）
### 方法
纯整数探针（PowerShell int64，非编译代码），对 w∈{1280,1920,2560,3840,8192} 枚举**全像素** x∈[0,w-1]，
三类编码各自与解码 `dec(n) = (n*w) >> 16`（floor）做往返，统计失配数：
- A = 现行 `round(x*65535/(w-1))`（extent-1）
- B = 审计 M 主张 `ceil(x*65536/w)`
- C = `round(x*65536/w)`
### 结果（[BASH] 实测）
| w | A (extent-1) | B (ceil 65536) | C (round 65536) |
|---|---|---|---|
| 1280 | 3 | **0** | 512 |
| 1920 | 7 | **0** | 896 |
| 2560 | 8 | **0** | 1024 |
| 3840 | 28 | **0** | 1792 |
| 8192 | 0 | **0** | 0 |
### 结论
- **B 在全部测试宽度上往返零失配**，A 在 4/5 宽度上失配（3/7/8/28），C 大面积失配 ⇒ **审计 M 的方向正确**
- 与 M 报告的差异：M 称 2560 为 20，我实测 **8**（其余 3/7/28 一致）。差异不影响结论（A≠0、B=0），但记录在案：
  **引用他人数值前必须自己复算**（与 memory 第 20 例同源）
- 注：8192 时 A 恰好 0（整除），说明"整除比例掩盖取整差异"（memory 已有该教训）
## 第846轮：几何数值复核（含一次自纠）
### 修正后的正确度量（oracle = 端点锚定意图 `truth=round(x*(cw-1)/(fbw-1))`）
- 现实现 `round(x*65535/(fbw-1))` + `dec=n*dw>>16`：相对 truth **mean=0.332px, max=1px**
- 审计 M 的新公式（capture 映射 + `ceil(px*65536/dw)`）：**mean=0, max=0**
⇒ M 的"最大 1px、约 49% 像素偏 1px"量级与我一致；M 的修法在端点锚定定义下精确
### M 的必答数值例已独立复现
- monitor1 起点 (1920,0)、捕获 1280x1024、桌面 3200x1024、fb 1280x1024、客户端 (640,512)：
  - 现实现：`n=32793 → land x=1601`（第一块屏，M 说 1601 ✅）
  - 新公式：`lx=640 → px=2560 → n=52429 → land x=2560`（第二块屏，M 说 2560 ✅）
### 我的自纠（已入 discover 第 27 例）
我先用"新旧实现 decode 结果互比"得到 99.77%，那是**伪度量**（衡量两实现差异而非对真值误差）。
**误差必须对 oracle 测量，禁止 A/B 互比。**
### 待办
审计 N 仍在途（分母裁决/采样相位/M5 可测性/字段集）；批 21 仍在途。
## 第847轮：批21 主代理独立验收+三变异全红+提交 d8b312a
### 验收证据（主代理亲测，非子代理引用）
- 构建：`cmake --build build --config Release` **exit=0**，日志 warning C / error C / error LNK / warning LNK / error MSB / warning MSB **全 0**
- 全量：`ctest --test-dir build -C Release` **63/63 passed, 0 failed**（65.34s）
- 生产库隔离：`build\rtsc_server.vcxproj` 的 4 个配置 PreprocessorDefinitions **无** RTSC_SERVER_TESTING；
  `build\rtsc_server_testing.vcxproj` **有** ⇒ 宏不会污染生产二进制
- 错误论断清除：'each one notices the closed transport' grep=0、'Teardown is already done at this point' grep=0
- Stop() 契约（server.h:331-343）：明确"提前返回即 use-after-free"
### 变异测试（%TEMP%\opencode\Lexec2，独立 build，工作树未触碰）
| # | 变异 | 结果 |
|---|---|---|
| A | 删 server.cpp 快照失败回退里的 `session->Stop()` | **FAIL** server_stop_delivers_stop_when_snapshot_allocation_fails |
| B | wait 失败 `catch` 直接 `return`（旧行为） | **FAIL** server_stop_does_not_return_while_session_thread_alive |
| C | 删 desktop_input_win32.cpp:388 `worker_failures_.fetch_add` | **FAIL** desktop_input_worker_failures_counts_a_failed_dispatch |
三变异恢复后：server 52 tests/586 checks/**0 failing**、desktop 50 tests/13784 checks/**0 failing**
### 变异过程中的两个坑（已复现，非推测）
1) 变异 A 首次写法 `/* comment */;` 触发 **C4189 未引用局部变量**，`/WX` 下直接编译失败 ⇒
   变异体必须先能编译，否则"红了"可能只是编译失败。改用 `(void)session;` 才测到断言。
2) `Copy-Item` 恢复后 **保留源 mtime** → MSBuild 判定免重编 → 两个套件"恢复后仍红"（假红）。
   `touch` 更新时间戳后重编才转绿。⇒ **恢复后必须 touch + 重编，否则绿证无效**
### 提交
`d8b312a` 批21（8 文件）；`e9ef8ab` 几何设计 §13 实证探针章节
### 调度
- 执行子代理 ses_e66140044... 已完成 → **delete 解散**（非 abort）
- 审计 M ses_e664d2035... 以"只回收口报告"的短提示唤醒（title=审计M几何设计收口）
- 审计 N ses_e65f23c5d... 前两次被 provider upstream_rejected → 改**极短提示**（≤20 行、禁止再读库）
## 第848-850轮：几何定案交叉审计（N 反驳 M，主代理独立复现）
### 主代理独立探针（证据入库 `docs/spec/input-geometry-probe-evidence.md`，提交 9dd9783）
1) **GDI 采样相位**（`%TEMP%\opencode\gdi_probe.ps1`，DIB→DIB，COLORONCOLOR）：
   `center=floor(((2x+1)*cap)/(2*fb))` 在 7/7 组 **0 失配**（含 2560→1280、3200→1280）；
   端点锚定 2560→1280 错 640/1280、3200→1280 错 428/1280；左端点 100% 错。
   ⇒ **N 的 3a 成立**；我第 846 轮的 oracle（端点锚定）在下采样路径上错误（discover 第 28 例）。
2) **DPI 语境**：未声明感知时 `SM_CXVIRTUALSCREEN=2048x1152`，`DESKTOPHORZRES=2560x1440`；
   `SetProcessDpiAwarenessContext(PMv2)` 后 `SM_*=2560x1440`。`desktop_gdi.cpp:63-65` 丢弃返回值
   ⇒ **N 的第 3 条成立**（`pixels_are_physical` 有真实失败路径）。
3) **解码公式**：本会话 `SendInput` 返回 1 但光标不动（非交互桌面）⇒ N 的"真机确证
   `floor(n*extent/65536)`"**我侧 UNVERIFIED**，仅 N 单方证据。排查中我自己踩过
   `INPUT` 结构多写 `long pad`（sizeof=48，应 40）导致 err=87，已记录。
4) **编码三方案全像素往返**（纯算术）：纯 ceil 与混合式在 w∈{1280,1920,2048,2560,3200,3840}
   全部 **0 失配**；现行 `round(x*65535/(w-1))` 为 3/7/0/8/20/28。
### 对 N 第 1 条论证的纠正（重要）
N 称"纯 ceil 会打断 `tests/test_desktop_input.cpp:272-279` 的既有断言"。**实测不成立**：
该用例是 `ev.x=1920`、几何 `1920x1080`（value==extent，超出末像素），而现行 `NormalizeAxis`
有前置夹取 `if (value >= extent-1) return 65535`（`desktop_input_map.cpp:25`），
三种编码方案对该用例**都返回 65535**。混合式的真正价值是"末像素 wire 值回到 65535
（对齐 MS 文档端点语义）+ 零往返失配"，不是"避免改断言"。
### 定案（待 M 回应后由主代理盖章）
- 分母：**混合式**（内部 `ceil(rel*65536/w)`，`rel>=w-1` 时 65535）
- 采样：**中心采样** `floor(((2x+1)*cap)/(2*fb))`（捕获路径）
- 字段：`InjectGeometry{width,height,capture{x,y,w,h},desktop{x,y,w,h},mapped,pixels_are_physical}`
- `pixels_are_physical=false` → `mapped=false` fail-closed
### 在途
审计 M 正回应 N 的 4 条反驳（ses_e664d2035...，busy）；审计 N 已 idle（报告已入库）。
## 第851轮：M/N 收敛 + 主代理真实库复现 + 退回 M 修文档
### 收敛结果（M 采纳 N 全部 4 条）
- 采样：中心采样 `floor(((2x+1)*cw)/(2*fbw))`（M 撤回端点锚定）
- 分母：混合式（内部 ceil，`rel>=w-1`→65535），断言零改动
- 字段：`InjectGeometry{width,height,capture,desktop,mapped,pixels_are_physical}`
- M5：`w=1280,rel=1` 单点可杀（ceil 52→1 vs extent-1 51→0）
### 主代理独立证据（新增，提交 ea80c9f）
- **真实库复现跨屏**：`probe_real.cpp` 链接 `build/Release/rtsc_server_desktop_input_map.lib`，
  `TranslateInput(ev(640,512), InjectGeometry{1280,1024})` → `wire n=(32793,32800)`，
  按 `floor(n*3200/65536)` 落 `(1601,512)`，应 `(2560,512)`，偏 959px。与 M §13.1 一致。
- 编译坑：`InputEvent` 在 `server.h`，只含 `desktop_input_map.h` 报 C2065。
### 退回 M 的三处文档问题（报告≠产物）
1. §8 U1/U2/U3 仍 UNVERIFIED，但 M 报告称"已改已确证"（grep '已确证'=0）
   → 裁决：U3 改已确证（三方实测）；U1/U2 保持 UNVERIFIED（仅 N 单方，我无法复现）
2. §3.3「不加 DPI 字段」与 §4.1 `pixels_are_physical` 冲突 → 改为"不加 DPI 数值字段"
3. §6.1 同时存在 49.18% 与 50.23% → 统一为"端点基线/中心基线"
### 调度
- 审计 N 已 delete（报告入库 9dd9783，任务完成）
- 审计 M 收到修正指令（title=审计M修正文档三处）
## 第852轮：M 文档修正已验收（grep 产物）
### 核验（主代理亲测，非读报告）
- `:551` U3 = **已确证（中心采样）**，列三方实测（M phaseM、N 21 组、主代理 7 组）
- `:549` U1 = **UNVERIFIED**（仅 N 单方 4179/685 点；主代理会话 SendInput 无效）
- `:550` U2 = 编码侧已证（ceil 0 失配）/ **OS 解码侧 UNVERIFIED**
- `:265` §3.3 标题 = "为什么不加 DPI **数值**字段（但保留 pixels_are_physical 有效性位）"
- `:389`/`:657` 统一为"端点基线 49.18% / 中心基线 50.23%"，无孤立 49.18
- `pixels_are_physical` 出现 4 处（:20/:265/:311/:332）
### 处置
- 提交 `21815ca`；审计 M **delete 解散**（任务完成）
- M 自述本次虚报根因："只改了 §2.5/§3.2，没改 §8 表格" → 与 discover 第 30 例一致
### 在途
执行 AI `ses_e6561baf4...` 批 22（busy，尚未写工作树）
## 第853轮：批22 执行 AI 被 stream_interrupted 中断 → 唤醒续做
### 断点状态（主代理只读核验）
工作树 10 文件已改（+583/-42）：
- `desktop_input.h`：`InjectRect`、`InjectGeometry{width,height,capture,desktop,mapped,pixels_are_physical}`、`InputStats::dropped_unmapped`
- `server.h`：`DesktopGeometry`（全默认值）+ `virtual DesktopGeometry Geometry() const { return {}; }`（默认实现，6 处实现零改动）
- `desktop_input_map.h`：`AbsoluteMoveMappable(g)` 内联谓词（mapped && physical && 各 span>1）
- `desktop_input_map.cpp`：`Clamp` + `MapAxis`（步骤0 clamp → 步骤1 中心采样 `((2f+1)*cap)/(2*fb)` → 步骤2 +capture origin → 步骤3 `relative>=desk-1?65535:ceil(rel*65536/desk)`）
- 其余：desktop_gdi.cpp / null / win32 / server.cpp / 两个测试文件
### 处置
- 子代理 idle（非终结）→ 经 `manage_subagent prompt` 唤醒续做（附断点清单 + 剩余 5 步）
- 明确要求：独占 ctest、只认 0 failing、三变异 + touch 重编 + Get-FileHash
### 待办
构建/测试/变异由执行 AI 完成 → 主代理验收 → 双审
## 第854轮：批22 主代理验收（构建/测试过，发现 1 个 High 缺陷）
### 主代理亲测（非引用报告）
- `cmake --build build --config Release` **exit=0**，warning C/error C/error LNK/warning LNK/error MSB/warning MSB **全 0**
- `ctest --test-dir build -C Release` **63/63 passed, 0 failed**（79.20s，独占）
- 独立复算（PowerShell 重写 MapAxis）与验收值**逐条一致**：
  cross-monitor `n=(52429,32768)`→decode 2560；`rel=1→52`；末像素→65535；1:1 恒等（0/100/639/640/1279 全部 land==wire）
### 发现的 High 缺陷（第 31 例，已入 discover）
`desktop_gdi.cpp:321-324` 用 **虚拟桌面宽** 比对 `DESKTOPHORZRES`（桌面 DC 返回**主显示器**能力）
⇒ 多显示器下 `pixels_are_physical` 恒 false ⇒ 绝对移动全丢 ⇒ `--monitor N` 完全不可用。
单屏两者相等，故测试全绿、缺陷不可见。测试还把该错误判据写成断言（保护缺陷）。
### 处置
- 退回执行 AI 修（title=批22修多屏判据）：判据改 `SM_CXSCREEN/SM_CYSCREEN` 比对；
  抽纯函数 `PixelsArePhysical` 加多屏单测（虚拟桌面更宽仍 true）；变异验证
- 双审：原 M/N 组已解散，执行 AI 无法直连 → 修完后**新开两个审计 AI**
### 已确认正确
映射实现（MapAxis/中心采样/混合式/末像素/fail-closed）经主代理独立复算与 ctest 双重确认
## 第855轮：批22 提交 ad5891e + 双审派出（P/Q 新组）
### 主代理独立验收（全部亲测）
| 项 | 证据 |
|---|---|
| 构建 | `cmake --build build --config Release` exit=0，六类诊断计数全 0 |
| 全量 | `ctest --test-dir build -C Release` **63/63, 0 failed**（58.79s，独占） |
| 映射值 | PowerShell 独立重写 MapAxis：cross-monitor `(52429,32768)`→2560；`rel=1→52`；末像素→65535；1:1 恒等 |
| 多屏判据 | 旧判据残留 grep=**0**；调用点 `PixelsArePhysical(dpi_ok, Metric(SM_CXSCREEN), Metric(SM_CYSCREEN), ...)` |
| 变异（我重做） | 副本改 `SM_CXSCREEN→SM_CXVIRTUALSCREEN` → **1 failing/4 failed checks, EXIT=1**；恢复+touch+hash 相同 → **0 failing, EXIT=0** |
### 裁决：执行 AI 的反驳成立（我的用例有错）
我原给 `(true,3200,1080,1920,1080) → true`，但该签名第 2 参是 `primary_w`；
主屏 3200 与物理 1920 不一致**本就应 false**。`>=` 语义会让变异不转红（假绿）。
⇒ **采纳严格相等**；多屏场景由 `(true,1920,1080,1920,1080)=true` + 调用点结构守卫覆盖。
### 新发现（discover 第 32 例）
结构守卫在**运行时读源码文本**，所以同一 exe 在"源码已恢复"后再跑会变绿。
⇒ 变异证据必须"改源码→重编→跑→恢复→重编→跑"，且记录当时 hash。
### 提交
`ad5891e` 批22（12 文件 +670/-45）
### 调度
- 执行 AI **delete 解散**（任务完成）
- 双审**新开两会话**（原 M/N 组已解散）：P 自顶向下 `ses_e64fc340fffefiPwHITCUqaaW9`、
  Q 自底向上 `ses_e64fbe978ffeAmiKOui8vVn22l`；已双向补发对方 ID
## 第856轮：审计 P（自顶向下）报告 + 主代理核验
### P 结论：CONDITIONAL（映射核心正确，可观测/接线/覆盖有缺口）
### 主代理逐条核验（只读）
| # | P 的发现 | 我的核验 | 判定 |
|---|---|---|---|
| 1 | `dropped_unmapped` 未接入运维日志 | `[BASH] Select-String tools/rtsc_server/main.cpp -Pattern dropped_unmapped` = **0**；`:611-620` 只打印 injected/dropped_queue/send/release/worker | **成立 Medium** |
| 2 | 服务端→sink 几何接线无测试 | `[READ:tests/test_server.cpp:544-550]` `RecordingInputSink::SetGeometry` 只存 width/height | **成立 Medium** |
| 3 | 判据字面与实现不一致（SM_*VS vs SM_CXSCREEN） | 我已裁决采纳 SM_CXSCREEN（多屏正确）；M §4.2 文本未同步 | **成立 Medium（文档）** |
| 4 | desktop origin 平移零覆盖 | `[BASH]` 测试里 `desktop = InjectRect{0,0,...}` 全部原点 0 | **成立 Medium** |
| 5 | `AbsoluteMoveMappable` 不校验 capture⊂desktop、desk<=65536 | `[READ:desktop_input_map.h]` 谓词只查 span>1 | **成立 Low** |
| 6 | `requires_usable_geometry` 注释与实测理由不符 | 待复核 | 待定 |
| 7 | M 设计 §10/§12 残留已否决公式 | 待复核 | 待定 |
| 8 | `IsInjectable` 不含几何门槛（纯移动仍抢租约） | `[READ:desktop_input_map.h:200-201]` `kMouse: return ev.is_move || ev.button != 0` | **成立 Low（前批遗留）** |
### P 确认正确的部分（与我一致）
MapAxis 逐字符合 §3.2；1:1 稠密 34303 点 0 失配；通用不变量 5926 点 0 失配；
验收#1 `(52429,32768)→2560`；溢出上界 3.5e13 << 9.2e18；fail-closed 只丢移动且计数不重复。
### 在途
审计 Q（自底向上）尚未回报；P 已把报告 relay 给 Q 做互审。