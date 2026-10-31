# 批 4 独立审计报告 A：afb2a69 服务器侧桌面输入注入骨架

- 被审提交：`afb2a69`（`feat(server): desktop input injection skeleton, default off`）
- 审计角色：独立审计 AI（甲2）；前两个审计会话因宿主 TLS 证书错误不可用，本报告独立完成
- 审计范围：仅任务指定的 7 项；仓库 `src/ include/ tests/ tools/ CMakeLists.txt` 全程只读。
  本报告是本次唯一写入仓库的文件（`docs/spec/input-injection-review-A.md`）。
- 审计环境：Windows / MSVC 19.44.35229 / CMake（VS2022 Enterprise 自带）；
  `git rev-parse HEAD` = `afb2a696a362b600ada6fa47ecd1ba0dd297cd5b`，`git status --short` 为空。
- 安全约束：**未对真实桌面调用 `SendInput`**。映射层用纯函数单测；Win32 `INPUT`
  构造用源码 + 官方文档逐字段核对；宿主用 `--seconds 1` 实跑但无客户端连接，
  因此不会产生注入。

## 结论总表

| # | 审计项 | 结论 | 一句话 |
|---|--------|------|--------|
| 1 | 映射正确性（键盘/鼠标/按钮/滚轮/不注入） | **PASS** | 与 `KEYBDINPUT`/`MOUSEINPUT`/`SendInput` 文档一致；纯映射 14 项单测全绿 |
| 2 | 安全门禁（默认关 / 危险组合 / 逃生门） | **PASS** | 默认 `input=off`；两种危险组合均 EXIT=2；逃生门有显著警告且 EXIT=0 |
| 3 | 门控与生命周期 | **PASS** | 四处接缝均受 `enable_desktop_input && input_sink_` 门控；`ReleaseInput` 幂等；live 计数前释放；借用指针不释放 |
| 4 | 线程 / 队列（Win32 sink） | **PASS** | 单工作线程、256 软上限、满队先丢移动、键/按钮不丢、250 Hz、补 UP、失败计数+5 s 限流、自有 tag |
| 5 | 独立变异 1 个 | **PASS** | 干净归档重建；`wheel*120` 变异 4 项转红（原始失败行已贴），还原转绿 |
| 6 | 健壮性（未知 kind / unicode 0 / scancode 0 / geometry 0 / 多显示器） | **PASS（含 UNVERIFIED 与建议）** | 无崩溃/除零；scancode 0 未过滤；多显示器原点缺失标 UNVERIFIED |
| 7 | 总结论 | **通过（无阻断性 FAIL）** | 骨架可合入（默认关）；残余风险见文末 |

---

## 1. 映射正确性（官方文档原文 + 源码逐条核对）

官方文档（本次实取原文，Microsoft Learn）：

- `KEYBDINPUT`（winuser.h）
  - `wVk`：“If the **dwFlags** member specifies **KEYEVENTF_UNICODE**, **wVk** must be 0.”
  - `wScan`：“A hardware scan code for the key. If **dwFlags** specifies **KEYEVENTF_UNICODE**, **wScan** specifies a Unicode character which is to be sent to the foreground application.”
  - `KEYEVENTF_EXTENDEDKEY`：“If specified, the **wScan** scan code consists of a sequence of two bytes, where the first byte has a value of 0xE0.”
  - `KEYEVENTF_KEYUP`：“If specified, the key is being released.”
  - `KEYEVENTF_SCANCODE`：“If specified, **wScan** identifies the key and **wVk** is ignored.”
  - `KEYEVENTF_UNICODE`：“The **wVk** parameter must be zero. This flag can only be combined with the **KEYEVENTF_KEYUP** flag.”
- `MOUSEINPUT`（winuser.h）
  - `mouseData`（WHEEL）：“A positive value indicates that the wheel was rotated forward ... a negative value ... backward. One wheel click is defined as **WHEEL_DELTA**, which is 120.”
  - `mouseData`（HWHEEL）：“A positive value indicates that the wheel was rotated to the right; a negative value ... left. One wheel click is defined as **WHEEL_DELTA**, which is 120.”
  - X 按钮：“**XBUTTON1** 0x0001 ... **XBUTTON2** 0x0002.”
  - `MOUSEEVENTF_VIRTUALDESK`：“Maps coordinates to the entire desktop. Must be used with **MOUSEEVENTF_ABSOLUTE**.”
  - `MOUSEEVENTF_ABSOLUTE`：“**dx** and **dy** contain normalized absolute coordinates between 0 and 65,535 ... In a multimonitor system, the coordinates map to the primary monitor.”
  - Remarks：“If **MOUSEEVENTF_VIRTUALDESK** is specified, the coordinates map to the entire virtual desktop.”
- `SendInput`
  - 返回值：“The function returns the number of events that it successfully inserted ... If the function returns zero, the input was already blocked by another thread.”
  - Remarks：“This function is subject to UIPI. Applications are permitted to inject input only into applications that are at an equal or lesser integrity level.”
  - Remarks：“This function does not reset the keyboard's current state. Any keys that are already pressed when the function is called might interfere ...”

### 1.1 键盘 scancode / extended —— PASS

- `src/server/desktop_input_map.cpp:34` `case InputEvent::Kind::kKey:` 直接复制
  `key.scancode = ev.scancode;`，并把 `ev.extended` / `ev.release` 原样带出
  （`desktop_input_map.cpp:39-41`）。**没有**任何 `+0x100` / `+0xE0` 运算
  （`Select-String ... "0x100|0xE0"` 在映射层只命中注释 `desktop_input_map.cpp:35-36`）。
- `src/server/desktop_input_win32.cpp:301` `native.ki.wScan = input.scancode;`
  `:302` `dwFlags = KEYEVENTF_SCANCODE`，`:303-305` 按 `input.extended`
  追加 `KEYEVENTF_EXTENDEDKEY`，`:306` 按 `input.release` 追加
  `KEYEVENTF_KEYUP`。这正是文档“wScan 是 0xE0 之后的那一字节、扩展性是独立标志”的用法。
- 单测 `desktop_input_extended_key_keeps_scancode`（`tests/test_desktop_input.cpp:57-68`）
  断言 `scancode == 0x1D` 且 `extended == true`。实跑通过（见 §5 绿跑输出）。

### 1.2 鼠标绝对移动 —— PASS（多显示器语义见 §6）

- `src/server/desktop_input_map.cpp:20` `NormalizeAxis(uint16_t value, uint16_t extent)`
  把像素坐标归一化到 0..65535，`:21` 对 `extent<=1` 回退为直通，`:23`
  对 `value >= extent-1` 夹到 65535，`:24-25` 用 `value*65535 + last/2` / `last` 四舍五入。
- `desktop_input_map.cpp:59-65` 仅在 `ev.is_move` 时产生 `kMouseMove`，x/y 分别归一化。
- `src/server/desktop_input_win32.cpp:313-315` 构造：
  ```cpp
  native.mi.dwFlags = static_cast<DWORD>(
      MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK);
  ```
  与文档要求的三标志组合一致；`dx/dy` 为 0..65535 的 `LONG`（`:311-312`）。
- 单测 `desktop_input_absolute_move_full_range`（`tests/test_desktop_input.cpp:84-105`）
  覆盖 (0,0)→(0,0) 与 (1920,1080)→(65535,65535)。

### 1.3 按钮 1..5 与释放身份 —— PASS

- 映射层 `desktop_input_map.cpp:68-74`：只要 `ev.button != 0` 就产生
  `kMouseButton`，并把 `button` 与 `button_down` 原样带出；释放事件（`is_move=false`、
  `button != 0`、`button_down=false`）同样保留按钮身份。
- 后端 `desktop_input_win32.cpp:323-352`：
  1→LEFTDOWN/LEFTUP，2→RIGHTDOWN/RIGHTUP，3→MIDDLEDOWN/MIDDLEUP，
  4→XDOWN/XUP + `XBUTTON1`，5→XDOWN/XUP + `XBUTTON2`；`mouseData` 只对 X 按钮置位。
- 单测 `desktop_input_button_left_up_keeps_identity`（`tests/test_desktop_input.cpp:121-134`）
  覆盖释放身份。实跑通过。

### 1.4 滚轮（wire 单位直通，禁止再乘 120） —— PASS

- 映射层 `desktop_input_map.cpp:77-88`：`wheel.wheel = ev.wheel_delta;`
  （`InputEvent::wheel_delta` 注释明确“wire units: WHEEL_DELTA (120) per notch”，
  `include/rtsc/server/server.h:247`）；x/y 被忽略（`:78-81` 注释 + 不赋值）。
- 后端 `desktop_input_win32.cpp:363-367`：
  ```cpp
  native.mi.dwFlags = ... input.horizontal ? MOUSEEVENTF_HWHEEL : MOUSEEVENTF_WHEEL;
  native.mi.mouseData = static_cast<DWORD>(input.wheel);
  ```
  **没有**任何 `*120`/`14400`；负值按 `DWORD` 二补码写入（`-120 → 0xFFFFFF88`），
  与文档“负值表示反向、120 为一格”一致。
- 单测 `desktop_input_wheel_positive_is_wire_units`、`..._negative_...`、
  `desktop_input_horizontal_wheel`、`desktop_input_wheel_ignores_xy`
  （`tests/test_desktop_input.cpp:137-208`）覆盖正/负/水平/忽略 x/y。
- 独立变异 `*120` 精确打红这四个用例（见 §5），证明该约束有测试牙齿。

### 1.5 `kMouseRel` / `kSync` 不注入 —— PASS

- `src/server/desktop_input_map.cpp:95-99`：
  ```cpp
  case InputEvent::Kind::kMouseRel:
  case InputEvent::Kind::kSync:
      return out;   // 空
  ```
- 单测 `desktop_input_mouse_relative_not_injected`（`tests/test_desktop_input.cpp:176-183`）
  与 `desktop_input_sync_not_injected`（`:185-191`）断言 empty。实跑通过。
- 说明：`kMouseRel` 的相对位移受系统鼠标加速/阈值影响（官方 `MOUSEINPUT` Remarks：
  “Relative mouse motion is subject to the effects of the mouse speed and the two-mouse
  threshold values ... up to four times”），v1 不注入是正确取舍。

**§1 结论：PASS。**

---

## 2. 安全门禁（本机实跑 `build\Release\rtsc_server_host.exe`）

宿主二进制来自当前工作树（`--help` 已包含 `--allow-input` / `--allow-input-unverified`），
且 `git status --short` 为空。默认值：`Options::enhanced = true`（`tools/rtsc_server/main.cpp:99`）、
`allow_any_credentials = false`（`:104`）、`allow_input = false`（`:120`）、
`allow_input_unverified = false`（`:123`）；`ServerConfig::enable_desktop_input = false`
（`include/rtsc/server/server.h:144`）。

门禁逻辑：`tools/rtsc_server/main.cpp:329-347`
```cpp
const bool weakened_credentials = !opt.enhanced || opt.allow_any_credentials;
const bool unsafe_input = opt.allow_input && weakened_credentials;
if (unsafe_input && !opt.allow_input_unverified) { ... return 2; }
```
`cfg.enable_desktop_input = opt.allow_input;`（`:362`）；
sink 只在 `--allow-input` 时创建（`:425-428`），并 `server.SetInputSink(input_sink.get())`（`:539`）。

### 2.1 默认关（不传 `--allow-input`）

```
$ & build\Release\rtsc_server_host.exe --test-pattern --seconds 1 --port 49996
port=49996 enhanced=true credssp=6 account=rtsc@NTDEV desktop=1280x1024 source=test-pattern clipboard=enabled audio=off input=off
EXIT=0
```
`input=off`，且无任何 `--allow-input` WARNING；sink 未创建（`:426` 条件不成立）。
**PASS（默认关）。**

### 2.2 `--allow-input` + `--no-enhanced` → 拒绝启动

```
$ & build\Release\rtsc_server_host.exe --allow-input --no-enhanced --test-pattern --seconds 1 --port 49997
refusing to start: --allow-input requires verified credentials.
  conflicting option --no-enhanced: no password check at all.
  Remove those options, or pass --allow-input-unverified to accept unauthenticated remote control.
EXIT=2
```
**PASS（EXIT=2）。**

### 2.3 `--allow-input` + `--allow-any-credentials` → 拒绝启动

```
$ & build\Release\rtsc_server_host.exe --allow-input --allow-any-credentials --test-pattern --seconds 1 --port 49998
refusing to start: --allow-input requires verified credentials.
  conflicting option --allow-any-credentials: every account is accepted.
  Remove those options, or pass --allow-input-unverified to accept unauthenticated remote control.
EXIT=2
```
**PASS（EXIT=2）。**

### 2.4 逃生门 `--allow-input-unverified` → 启动且显著警告

```
$ & build\Release\rtsc_server_host.exe --allow-input --no-enhanced --allow-input-unverified --test-pattern --seconds 1 --port 49999
... input=on
WARNING: desktop input injection is ENABLED (--allow-input): the remote client can move the pointer, type into the foreground window and operate this machine. Every session shares the same physical desktop.
**********************************************************************
WARNING: --allow-input-unverified is in effect.
This server combines desktop input injection with a weakened credential policy
(--no-enhanced and/or --allow-any-credentials). Any client that reaches the port
can take control of this machine's interactive desktop. Use this only on an
isolated network with no untrusted peers.
**********************************************************************
listening on 0.0.0.0:49999
run window elapsed; stopping
EXIT=0
```
警告同时出现在 stdout 与 `SessionLog`（`main.cpp:455-470`）。**PASS。**

> 边界说明：门禁在 CLI 宿主层；库层允许嵌入者程序化设置
> `enable_desktop_input=true` 且 `accept_any_credentials=true`，库不二次拒绝。
> 这符合“配置由嵌入者负责”的既有 API 设计，但若今后把库直接暴露给不可信调用方，
> 需要把配对校验下沉。此处不判 FAIL。

**§2 结论：PASS。**

---

## 3. 门控与生命周期

### 3.1 注入点门控 —— PASS

所有接缝调用都带同一守卫 `config_.enable_desktop_input && input_sink_ != nullptr`：

| 调用 | 位置 |
|------|------|
| `ReleaseSession` | `src/server/server.cpp:698-699` |
| `SetGeometry` | `src/server/server.cpp:1172-1176` |
| `Inject`（慢路径） | `src/server/server.cpp:1719-1720` |
| `Inject`（快路径） | `src/server/server.cpp:1847-1848` |

`input_sink_` 与 `input_session_id_` 成员见 `server.cpp:1863-1865`。
未安装 sink 或配置为 false 时，四条路径全部短路；默认配置零注入。

### 3.2 `ReleaseInput` 幂等 —— PASS

`src/server/server.cpp:695-701`
```cpp
void ReleaseInput() {
    if (input_released_) return;
    input_released_ = true;
    if (config_.enable_desktop_input && input_sink_ != nullptr) {
        input_sink_->ReleaseSession(input_session_id_);
    }
}
```
`input_released_` 声明在 `server.cpp:1865`。同一 session 的 `ReleaseInput` 只由
session 线程/`ServeOne` 调用一次，`input_released_` 是二重防御。

### 3.3 teardown 在 live 计数释放之前 —— PASS

线程路径（生产路径）`src/server/server.cpp:2162-2174`：
```cpp
try { session->Stop(); } catch (...) {}
try { session->ScrubCredentials(); } catch (...) {}
try { session->ReleaseInput(); } catch (...) {}
release();                                   // live.fetch_sub 在此才发生
```
`release` 的 `registry->live.fetch_sub(1, ...)` 在 `server.cpp:2136/2140`，
即 **ReleaseInput 先于 live 减 1**；`RdpServer::Stop()` 的等待谓词正是 live 计数，
所以 `Stop()` 返回时注入侧补 UP 已完成。

单会话路径 `RdpServer::ServeOne()`：`server.cpp:2238` `session.ReleaseInput();`
在返回前调用（该路径没有 live 计数）。

> 备注（低危）：`ServeOne` 中 `session.Stop()` 未像线程路径那样包 try/catch
> （`Transport::Close()` 不是 `noexcept`，`include/rtsc/net/transport.h:66`）。
> 若 `Close()` 抛异常，`ReleaseInput` 会被跳过。生产宿主默认走线程路径，
> 仅 `--once`/嵌入者使用 ServeOne。建议后续把 `Stop()` 也包起来或先释放输入。

### 3.4 sink 借用指针不被 server 释放 —— PASS

- `RdpServer` 只保存裸指针 `DesktopInputSink* input_sink_`（`server.h:367`），
  `SetInputSink` 仅赋值（`server.cpp:2011`），`~RdpServer(){ Stop(); }`（`server.cpp:1999`），
  未见 `delete input_sink_` / `unique_ptr` 接管。
- 宿主生命周期：`input_sink` 在 `server` 之前声明
  （`tools/rtsc_server/main.cpp:425` vs `:510` 的 `RdpServer server(cfg);`），
  因此先析构 `server`（其析构 `Stop()` 等 live 归零）再析构 sink，满足
  “sink 必须活过 Stop()”的借用契约。

### 3.5 注入 session id 单调且与 wire id 独立 —— PASS

- 分配：`impl_->next_input_session_id.fetch_add(1, ...) + 1`
  （线程路径 `server.cpp:2098-2099`，单会话路径 `:2225`），计数器起始 0
  （`server.cpp:1975`），故首个 id=1，单调递增。
- `share_id_ = session_id_ * 0x01000000u + 0x12345678u`（`server.cpp:1317`），
  `session_id_` 始终传 0（`server.cpp:2097/2224` 的构造实参），注入 id 不参与 wire
  shareId；成员注释明确“never feeds the wire shareId”（`server.cpp:1861-1864`）。
- 4.29e9 次会话后 `uint32_t` 回绕仅理论风险，可忽略；如需绝对不回绕可改 64 位。

**§3 结论：PASS（含两条低危备注）。**

---

## 4. 线程 / 队列（Win32 sink，静态审计）

源码：`src/server/desktop_input_win32.cpp`。

| 要求 | 实现 | 证据 |
|------|------|------|
| 单工作线程 | 构造时 `worker_ = std::thread(WorkerMain)`，析构 `Shutdown()` join | `:84-85`、`:88`、`:409-419` |
| 队列 256 | `kMaxQueue = 256` | `:54` |
| 满队先丢移动 | 满队时 `find_if` 找最老 `kMouseMove` 并 `erase`；若无移动且来者是移动则丢弃来者 | `:154-171` |
| 键/按钮绝不丢 | 满队且无移动可丢时，键/按钮仍 `push_back`（队列临时增长） | `:164-171` |
| 移动合并 250 Hz | 相邻同会话移动合并（`:147-152`）；`pending_moves_` 每会话只留最新，`kMoveInterval = 4ms` 限速（`:55`、`:227`、`:267-275`、`:289-301`） |
| `ReleaseSession` 补 UP | 对 `pressed_keys`/`pressed_buttons` 逐项追加 release 事件 | `:114-122`、`:174-187` |
| `SendInput` 失败计数 + 5 s 限流 | `injected_failed_` 原子计数；`LogFailure` 首失败即打，之后 `kFailureLogInterval=5s` 内抑制 | `:56`、`:374-404`、`:436` |
| `dwExtraInfo` 自有 tag | `kInjectTag = 0x52545343`（"RTSC"），非 mstsc 的 `0x4321DCBA` | `:59`、`:288/316/356/367` |

补充核对：

- `Inject` 只在 session 线程做 `TranslateInput` + 入队（`:98-112`）；
  `SendInput` 只在 worker 的 `Emit` 中调用（`:374-387`），会话线程不会阻塞在 `SendInput`。
- 键/按钮/wheel 出队时先 `FlushSessionMove(session_id)`（`:278`），保证点击落在
  客户端发送时的最后指针位置；`ReleaseSession` 的 UP 也会先冲刷同会话待发移动。
- worker 等待用 `cv_.wait_until` 到最近的移动截止时间（`:196-215`、`:231-246`），
  不会忙轮询。
- `pending_moves_` / `last_move_sent_` 只由 worker 访问；`sessions_` / `queue_` 由
  `mu_` 保护；`Emit` 在锁外调用 `SendInput`。
- `Shutdown` 在 join 前把剩余会话的按下键/按钮补 UP 并清空（`:409-419`）。

### 4.1 低危残余

1. **队列对键/按钮是软上限**：持续键/按钮洪泛时 `queue_` 可无界增长（这是
   “键/按钮绝不丢”的直接取舍；恶意已认证客户端可做内存 DoS）。建议加
   “每会话/全局硬上限 → 超限断开会话”或至少限制 `pressed_keys` 集合大小。
2. **`last_move_sent_` 不清理**：`ReleaseSession` 只删 `sessions_`，不 `erase`
   `last_move_sent_`（worker-only map）。每个会话留一个 `uint32_t→time_point`，
   长跑多会话时缓慢增长。建议在 `Dispatch`/`ReleaseSession` 的 worker 侧清理。
3. `Shutdown()` 若被重复调用会在 `stopping_` 早退而不 join（`:410-412`），
   当前只有析构调用一次，不可达；若将来公开 `Shutdown` 需修。

**§4 结论：PASS（按任务要求的行为全部满足；上述为残余风险）。**

---

## 5. 独立变异（1 个）：`kWheel * 120`

### 5.1 干净归档 + 独立构建目录

```powershell
$src = "$env:TEMP\rtsc-src-a7"
git archive --format=zip -o "$env:TEMP\rtsc-a7.zip" afb2a69
tar -xf "$env:TEMP\rtsc-a7.zip" -C $src
$bld = "C:\Users\liulilte\rtsc-mutbuild-a7"
& cmake -S $src -B $bld -G "Visual Studio 17 2022" -A x64
& cmake --build $bld --config Release --target rtsc_desktop_input_tests
```
配置/构建均成功（`Configuring done` / `Generating done`，`Build files written`）。
（说明：最初 `git archive | tar -x` 经 PowerShell 管道出现 `Damaged tar archive
(bad header checksum)`；改用文件归档后正常，故以文件归档方式复现。）

### 5.2 变异前绿跑（原始用例）

```
$ & C:\Users\liulilte\rtsc-mutbuild-a7\Release\rtsc_desktop_input_tests.exe
...
14 tests, 57 checks, 0 failing tests, 0 failed checks
EXIT=0
```

### 5.3 应用变异

`$src\src\server\desktop_input_map.cpp` 原 `:84`：
```cpp
wheel.wheel = ev.wheel_delta;
```
改为：
```cpp
wheel.wheel = ev.wheel_delta * 120;
```
增量重建（同一构建目录，MSB8029 规避有效），构建 `EXIT=0`，测试转红：

```
  FAIL C:\Users\liulilte\AppData\Local\Temp\rtsc-src-a7\tests\test_desktop_input.cpp:147  out[0].wheel == 120 (got 14400, want 120)
[ FAIL ] desktop_input_wheel_positive_is_wire_units
  FAIL C:\Users\liulilte\AppData\Local\Temp\rtsc-src-a7\tests\test_desktop_input.cpp:159  out[0].wheel == -120 (got -14400, want -120)
[ FAIL ] desktop_input_wheel_negative_is_wire_units
  FAIL C:\Users\liulilte\AppData\Local\Temp\rtsc-src-a7\tests\test_desktop_input.cpp:172  out[0].wheel == 120 (got 14400, want 120)
[ FAIL ] desktop_input_horizontal_wheel
  FAIL C:\Users\liulilte\AppData\Local\Temp\rtsc-src-a7\tests\test_desktop_input.cpp:207  out[0].wheel == 120 (got 14400, want 120)
[ FAIL ] desktop_input_wheel_ignores_xy
14 tests, 57 checks, 4 failing tests, 4 failed checks
TEST_EXIT=1
```
（`:147/:159/:172/:207` 即 afb2a69 原始测试文件行号，未被任何改动偏移。）

### 5.4 还原 + 转绿

```
14 tests, 57 checks, 0 failing tests, 0 failed checks
TEST_EXIT=0
```

### 5.5 干净归档全链路编译（C0 旁证）

```
& cmake --build $bld --config Release --target rtsc_server_desktop_input
  desktop_input_win32.cpp
  rtsc_server_desktop_input.vcxproj -> ...\rtsc_server_desktop_input.lib
EXIT=0

& cmake --build $bld --config Release --target rtsc_server_host
  ...
  main.cpp
  rtsc_server_host.vcxproj -> ...\rtsc_server_host.exe
EXIT=0
```
`/W4 /WX`（`CMakeLists.txt:869-871`）下干净编译零警告零错误。

**§5 结论：PASS。**

---

## 6. 健壮性（`TranslateInput` 边界 + geometry）

为避免影响真实桌面，本节用**测试副本**（`%TEMP%\rtsc-src-a7\tests\test_desktop_input.cpp`
追加 6 个 probe；**不属于 afb2a69 提交**）在独立构建目录实跑，未调用 `SendInput`。

### 6.1 未知 kind —— PASS（实践层面）

`desktop_input_map.cpp:33-99` 的 `switch` 覆盖 `InputEvent::Kind` 的全部 6 个枚举值；
越界值不命中任何 case，落到 switch 之后的 `return out;`（`:101`），返回空。
`InputEvent.kind` 在快/慢路径中始终被显式赋值，服务端不会传入越界 kind。
（严格说读取越界枚举值是 UB；如需绝对安全可加 `default: return out;`，但
`/W4 /WX` 当前不报错。）

### 6.2 `unicode == 0` —— PASS

`desktop_input_map.cpp:45-53`：`if (ev.unicode_code == 0) return out;`。
probe `probe_unicode_zero_is_empty` 通过。

### 6.3 `scancode == 0` —— 未过滤（低危，建议）

`desktop_input_map.cpp:34-43` 无条件复制 scancode，包括 0。probe 实测：
```
[ RUN  ] probe_scancode_zero_is_not_filtered
PROBE scancode0 size=1 scancode=0
```
后端会构造 `wScan=0` + `KEYEVENTF_SCANCODE` 的键盘事件。影响：
- 服务端正常解码路径不会产生默认 `InputEvent`（QoE 时间戳在
  `server.cpp:1825-1830` `continue`；未知 eventCode `return`；慢路径 `kUnused`
  `continue`），所以只有显式 wire `keyCode=0` 才会触发；
- 该事件不会造成安全后果；按下状态集合会记录 `KeyId{0,...}`，`ReleaseSession`
  会补发一个 scancode 0 的 UP（同样无副作用）。
- 建议：在映射层丢弃 `scancode==0`（或 wire 解码层拒绝），与 `unicode==0` 对齐。

### 6.4 `geometry == 0` / `geometry == 1` —— PASS（无崩溃，1:1 直通）

`NormalizeAxis`（`desktop_input_map.cpp:21-24`）：`extent <= 1` 直接返回原值，
不做除法。probe：
```
PROBE geom0 size=1 x=1920 y=1080
```
即 (1920,1080) 原样输出，没有除零/溢出（`value` 是 `uint16_t`，最大 65535，仍在
`LONG` 范围）。`geometry==1` 同样直通（probe 通过）。

真实流程中 geometry 不会为 0：客户端 Connect Initial 的 CS_CORE 尺寸在
`server.cpp:1045-1053` 读入，`ClampDesktopSize` 在 `:1164-1167` 夹紧，
`SetGeometry` 在 `:1172-1176` 写入；输入只在 `ActiveLoop()`（`server.cpp:1473` 起）
处理，而 `ActiveLoop` 在 `DoFinalization()` 之后（`server.cpp:668-679`）。
因此 0/1 分支只是防御性代码。

### 6.5 中间归一化与“移动+按钮”顺序 —— PASS

probe 实测：
```
PROBE mid x=32785 y=32798
```
与公式 `(v*65535 + (extent-1)/2)/(extent-1)` 一致（1920x1080 的 960,540）。
`probe_combined_move_and_button_keeps_order` 验证同一 `kMouse` 事件中
`kMouseMove` 在前、`kMouseButton` 在后（`desktop_input_map.cpp:62-73` 的顺序），
点击落在新位置。

### 6.6 多显示器：`InjectGeometry` 只有 w/h → **UNVERIFIED**

- `InjectGeometry` 只有 `width/height`（`include/rtsc/server/desktop_input.h:30-33`）。
- Win32 侧使用 `MOUSEEVENTF_VIRTUALDESK`（`desktop_input_win32.cpp:314`）。
  官方文档：`VIRTUALDESK` 把坐标映射到**整个虚拟桌面**；普通 `ABSOLUTE`
  才映射到主显示器。当前几何是**客户端协商的 framebuffer 尺寸**（单矩形），
  不是虚拟桌面的 `(origin_x, origin_y, width, height)`。
- 因此在单显示器、且虚拟桌面与 framebuffer 同尺寸时正确；在多显示器、或
  framebuffer 只是某个显示器/虚拟桌面一部分时，0..65535 会被铺到整个虚拟桌面，
  **指针位置会偏移/缩放**。本机未做多显示器实机验证，标 **UNVERIFIED**。
- 建议（二选一）：
  1. 把注入几何扩展为 `{origin_x, origin_y, width, height}`（虚拟桌面矩形），
     归一化仍按该矩形做 `VIRTUALDESK`；
  2. 或明确 v1 只支持“framebuffer == 整个虚拟桌面”，并在 `--allow-input` 启动日志/
     文档中写死该前提；多显示器时拒绝启用或降级为主显示器 `ABSOLUTE`。

### 6.7 其他边界

- 按钮值 >5：映射层原样带出（`static_cast<uint8_t>`），后端 `default: return false`
  （`desktop_input_win32.cpp:350-351`）→ `Emit` 计入 `dropped_unsupported_`；
  不会误触其他按钮。按下状态集合可能记录未知按钮，`ReleaseSession` 的 UP 也会被
  后端丢弃，不会卡住真实按钮。可接受。
- `kWheel` 的 `wheel_delta` 不是 120 的倍数（wire 可带 ±60/±240）：后端原样透传；
  Windows 部分应用只接受 120 的倍数，兼容性需实测（本批要求就是“直通 wire 单位”，
  故不判 FAIL）。
- UIPI：`SendInput` 被 UIPI 阻止时返回 0，且官方文档明确“neither GetLastError nor
  the return value will indicate the failure was caused by UIPI blocking”；当前
  `LogFailure` 只打印 `GetLastError()`，措辞为“event was dropped and the session is
  kept”，不误报为协议错误，可接受。

**§6 结论：PASS（无崩溃/无除零；scancode 0 建议过滤；多显示器标 UNVERIFIED）。**

---

## 7. 总结论

| # | 项 | 结论 |
|---|----|------|
| 1 | 映射正确性 | **PASS** |
| 2 | 安全门禁 | **PASS** |
| 3 | 门控与生命周期 | **PASS** |
| 4 | 线程/队列 | **PASS** |
| 5 | 独立变异 | **PASS** |
| 6 | 健壮性 | **PASS（含 UNVERIFIED/建议）** |
| 7 | 总结论 | **通过，无阻断性 FAIL** |

afb2a69 的骨架在默认关、双重门控、映射单位、生命周期与线程模型上均符合任务要求；
独立变异证明滚轮单位约束有测试牙齿。合入前建议处理（均非阻断）：

1. 多显示器几何（§6.6）——在 `--allow-input` 的文档/启动日志中写死前提，或补
   `origin+size`；否则多显示器下点击会偏。
2. `scancode==0` 过滤（§6.3）。
3. 键/按钮队列的硬上限与 `last_move_sent_` 清理（§4.1）。
4. sink/服务器层集成测试缺失（见 §8 O2）。

---

## 8. 范围外观察（不影响本批 PASS/FAIL，但建议跟进）

- **O1 `max_input_sessions` 未实现**：设计文档要求 `enable_desktop_input=true` 时
  默认 `max_input_sessions = 1`（`docs/spec/input-injection-evidence.md:267-268`、
  `:334`；`docs/spec/input-injection-seam.md` 的 D4 行 `:553`）。当前 `ServerConfig`
  没有该字段，多个会话会同时向同一物理桌面注入（last-writer-wins）。宿主启动日志
  有“Every session shares the same physical desktop”警告，但没有硬门控。
- **O2 缺少 sink/服务器集成测试**：提交只有 14 个纯映射测试；设计文档中的
  T17（移动合并）、T18（队列不丢按钮）、T19（ReleaseSession 补 UP）、
  T20（限流）、I8（session_id 非 0 且两会话不同）没有对应自动化用例
  （`docs/spec/input-injection-seam.md:529-532`、`:544`）。
  本次用代码审计 + 宿主实跑覆盖，但回归保护不足。
- **O3 运行时 `SetInputSink(nullptr)`**：头文件写“nullptr clears it”
  （`include/rtsc/server/server.h:292-298`），但 `input_sink_` 是无同步裸指针；
  若在会话运行中清除，存在数据竞争，且已注入的键/按钮不会收到 `ReleaseSession`
  → 本机卡键。生产宿主只在 Start 前设置一次，不触发；建议在头文件明确
  “只在 Start 前设置”，或加锁并在清除前补释放。
- **O4 跨会话释放**：`ReleaseSession` 补 UP 会作用于共享物理桌面；若 A、B 同时按住
  同一键，A 退出时的 UP 会提前释放 B 的键。这是共享桌面语义的已知限制
  （设计文档 D4 明确 v1 不做租约），文档化即可。
- **O5 `ServeOne` 的 `Stop()` 未包异常**（§3.3 备注）。
- **O6 `last_move_sent_` 每会话小泄漏**（§4.1）。
- **O7 队列对键/按钮无硬上限**（§4.1；安全上可被已认证客户端做内存 DoS）。

---

## 附录 A：证据命令与原始输出

### A.1 仓库状态

```
$ git rev-parse HEAD
afb2a696a362b600ada6fa47ecd1ba0dd297cd5b
$ git status --short
(空)
$ git show --stat afb2a69
 ... 13 files changed, 1260 insertions(+), 9 deletions(-)
```

### A.2 现有构建的映射单测

```
$ & build\Release\rtsc_desktop_input_tests.exe
...
14 tests, 57 checks, 0 failing tests, 0 failed checks
EXIT=0
```

### A.3 受影响的服务器测试（现有构建）

```
$ & build\Release\rtsc_server_tests.exe
40 tests, 433 checks, 0 failing tests, 0 failed checks
EXIT=0

$ & build\Release\rtsc_server_multisession_tests.exe
7 tests, 184 checks, 0 failing tests, 0 failed checks
EXIT=0
```
（说明：本次未复跑全量 ctest 63 项；按影响范围选了映射单测、服务器单测、
多会话单测、干净构建与宿主实跑。全量 63/63 是提交信息中的自述，未独立复核。）

### A.4 宿主门禁实跑

见 §2.1-§2.4 的原始输出与 EXIT 码（0 / 2 / 2 / 0）。

### A.5 变异构建

```
配置：cmake -S %TEMP%\rtsc-src-a7 -B C:\Users\liulilte\rtsc-mutbuild-a7
      -G "Visual Studio 17 2022" -A x64          -> EXIT=0
构建：cmake --build ... --target rtsc_desktop_input_tests
                                                -> EXIT=0
绿跑：14 tests, 57 checks, 0 failing             -> EXIT=0
变异：wheel.wheel = ev.wheel_delta * 120;
红跑：14 tests, 57 checks, 4 failing tests       -> EXIT=1
      FAIL test_desktop_input.cpp:147 (got 14400, want 120)
      FAIL test_desktop_input.cpp:159 (got -14400, want -120)
      FAIL test_desktop_input.cpp:172 (got 14400, want 120)
      FAIL test_desktop_input.cpp:207 (got 14400, want 120)
还原：14 tests, 57 checks, 0 failing             -> EXIT=0
```

### A.6 干净归档全链路编译

```
cmake --build ... --target rtsc_server_desktop_input -> EXIT=0
cmake --build ... --target rtsc_server_host         -> EXIT=0
```

### A.7 健壮性 probe（测试副本追加，非提交内容）

```
PROBE scancode0 size=1 scancode=0
PROBE geom0 size=1 x=1920 y=1080
PROBE mid x=32785 y=32798
20 tests, 72 checks, 0 failing tests, 0 failed checks
EXIT=0
```

### A.8 关键证据行索引

| 断言 | 证据 |
|------|------|
| scancode 直通、不 +0x100 | `src/server/desktop_input_map.cpp:34-43`；`src/server/desktop_input_win32.cpp:298-308` |
| 绝对移动三标志 | `src/server/desktop_input_win32.cpp:312-316` |
| 0..65535 归一化 | `src/server/desktop_input_map.cpp:20-29`、`:60-70` |
| 按钮 1..5 | `src/server/desktop_input_win32.cpp:323-352` |
| wheel 直通 | `src/server/desktop_input_map.cpp:77-88`；`src/server/desktop_input_win32.cpp:363-367` |
| kMouseRel/kSync 空 | `src/server/desktop_input_map.cpp:95-99` |
| 门禁默认值 | `tools/rtsc_server/main.cpp:99/104/120/123`；`include/rtsc/server/server.h:144` |
| 危险组合拒绝 | `tools/rtsc_server/main.cpp:329-347` |
| 注入四处门控 | `src/server/server.cpp:698/1172/1719/1847` |
| ReleaseInput 幂等 | `src/server/server.cpp:695-701` |
| live 前释放 | `src/server/server.cpp:2171` vs `:2136/2140` |
| 借用指针 | `include/rtsc/server/server.h:367`；`src/server/server.cpp:2011` |
| id 单调独立 | `src/server/server.cpp:1975/2098/2225`；`:1317` |
| 队列/线程/tag | `src/server/desktop_input_win32.cpp:54-59`、`:147-215`、`:284-419` |
| CMake 接线 | `CMakeLists.txt:673-685`、`:694`、`:766`、`:869-871` |