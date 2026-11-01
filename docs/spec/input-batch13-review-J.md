# 批 13 审计 J：teardown 异常安全是否闭合 + Win32 测试缝是否损害生产语义

- 对象：提交 `6fc5614`（父 `805428b`，`git show --stat` 14 文件 / +452 −53）
- 审计角色：只读审计（除本文件外未改 src/include/tests/tools/CMakeLists）
- 环境：Windows / MSVC 14.44（`Visual Studio 17 2022`，`/W4 /WX /permissive- /utf-8`，`/EHsc`）
- 独立性：实验全部在 `%TEMP%\opencode\{mutJ,mutJ2,mutJ3,mutJ4,mutJ5,jprobe}` 的**独立副本**上做；每份副本用 `git hash-object` 与 `git rev-parse 6fc5614:<path>` 逐文件比对，见 §5 表头（全部 `prist=True`）。
- 证据约定：`[READ:path:line]` 指 `6fc5614` 的 blob（工作树中 `server.cpp` / `desktop_input_map.h` / `tests/*` 已被批 16/17 继续修改，`desktop_input_win32.cpp` 自 `6fc5614` 起**未变**，我已核 `rev-parse` 两侧相等）。

## 0. 结论（一句话）

N-1 / N-2 / N-3 的**"关键清理无条件执行"在异常路径上确实成立**（有 3 条独立红证），`stopping_` 改 `std::atomic<bool>` 后**没有**新的可见性/顺序缺陷；
但有 **4 个未闭合点**：

| ID | 严重度 | 一句话 |
|---|---|---|
| **J-1** | **High** | N-4 只包了两个虚调用，`Stop()` 里的 `sessions = registry->sessions`（会分配）与 `cv.wait` 仍可直接抛出并 `terminate`；探针实测进程被杀 |
| **J-2** | **Medium** | 测试缝的 hook 全部 `static_cast<Win32DesktopInputSink*>`，无类型校验；同一 target 的 `MakeWin32DesktopInputSink()` 返回 null sink，误用即 `0xC0000005`；探针实测崩 |
| **J-3** | **Medium** | `worker_failures_` **只写不读**（全仓 0 个读取点），N-3 的失败不可观测；且 N-1 的 `drained` 断言**钉不住 notify**（删掉 notify 后 150 次全绿） |
| **J-4** | **Medium** | rdpdr 的"catch 后继续"**没有测试**：改成"只失败第一个 pending"后 13/379 全绿 |
| **J-5** | Low | `docs/spec/input-injection-seam.md`（`6fc5614` 版）§1.8 仍断言"该文件不在任何测试 target 闭包内、任何变异都无法让 ctest 转红"，与本提交直接矛盾；同节 7 处行号全部漂移；而 §1 第 137 行的 `292-315` / `389-410` **是准确的** |

## 1. N-1 / N-2 / N-3 逐项

### 1.1 N-1 `ReleaseSession`（`[READ:src/server/desktop_input_win32.cpp:159-197]`） —— **PASS**

路径枚举（`holders`/`forget_sessions_` 唯一插入点分别在 `:175` 与 `AcquireInputLease` 的 `:854`）：

| 路径 | 是否执行 `sessions_.erase` | 是否执行 `cv_.notify_one` |
|---|---|---|
| 无 session 状态（`:180` 为 `end`） | 无需 | **是**（`:196`） |
| `forget_sessions_.insert` 抛（`:174-179` catch） | 会话状态照擦 | **是** |
| `AppendReleasesLocked` 抛（`:182-187` catch + `release_failures_++`） | **是**（`:191` 在 try 外） | **是** |
| 全正常 | **是** | **是** |

`:191` 与 `:196` 都在 try 之外，`:197` 是函数唯一的右花括号 —— 结构上不存在"跳过清理"的分支。**红证 M1**（把 `sessions_.erase(it)` 移进 try）实测转红：

```text
[ RUN  ] desktop_input_release_session_clears_state_when_append_throws
  FAIL ...\tests\test_desktop_input.cpp:1105  ...SessionCount(sink.get()) == static_cast<size_t>(0) (got 1, want 0)
1 tests, 5 checks, 1 failing tests, 1 failed checks      EXIT=1
```

（恢复后 `1 tests, 5 checks, 0 failing`，`EXIT=0`。）**语义**：ups 丢失（键可能卡住）与"会话/id 不可复用"两个后果被分开了 —— 前者计数，后者绝不发生。这是本批最关键的取舍，判正确。

### 1.2 N-2 `Shutdown() noexcept`（`[READ:src/server/desktop_input_win32.cpp:604-650]`） —— **PASS（附 1 条 Low 注记）**

- `stopping_` 只在锁内写（`:611`），append pass 只在 `!stopping_` 时跑（`:610`），重复调用不重复补 up；
- 每个会话的 append（`:613-618`）、`pressed = PressedInputs{}`（`:619-624`）、`sessions_.clear()`（`:626-629`）各自 try/catch；
- 锁段整体还有一层 catch（`:605` / `:631-634`），注释明写"mutex misuse 不可恢复，但 worker 仍须唤醒并 join"；
- `cv_.notify_all()`（`:640`）与 `if (worker_.joinable()) worker_.join()`（`:641`）**在 try 之外、无条件**；`pending_moves_/last_move_sent_` 再包一层 catch（`:645-649`）。

**红证 M2**（恢复"非 noexcept + `if (stopping_) return;` 早退 + 不逐项 catch"）实测**不是 FAIL 而是进程被杀**：

```text
[ RUN  ] desktop_input_shutdown_joins_worker_when_append_throws
[rtsc-server] ... unhandled-seh   exception_code=0xE06D7363
text: ...\crashes\rtsc_desktop_input_tests-...txt   EXIT=3
```

崩溃转储栈含 `CxxThrowException` → 正是"异常穿过 noexcept/析构 ⇒ terminate"，与 H §2.1 对 N-2 的后果预测完全一致。**红证 M2b**（只把 `join` 去掉）则干净转红：

```text
FAIL ...\tests\test_desktop_input.cpp:1136  !rtsc::server::DesktopInputTestWorkerJoinable(sink.get())
1 tests, 4 checks, 1 failing tests, 1 failed checks      EXIT=1
```

**Low 注记（不阻塞）**：`:641` 的 `worker_.join()` 本身在 `noexcept` 函数里、无内层 catch；`join()` 抛 `std::system_error`（`EDEADLK`/`EINVAL`）时仍会 terminate。worker 线程从不调用 `Shutdown`，故 `EDEADLK` 不可达；但 `:601` 的注释声称"every step is isolated"，与 `:641` 存在措辞不一致。建议把 `join` 也包一层 `try{...}catch(...){}`（保持"绝不外抛"的口径统一）。

### 1.3 N-3 `WorkerMain() noexcept`（`[READ:src/server/desktop_input_win32.cpp:335-379]`） —— **PASS（附 J-3 观测盲区）**

- 循环体整段在 try 内（`:343-372`），`ForgetReleasedSessionsLocked`（`:346`）与 `Dispatch`（`:368`）都在保护范围内；
- 异常路径 `worker_failures_++` 并按 `stopping_` 决定是否退出（`:369-372`）；
- 退出前的 `FlushMoves()` 单独 try（`:374-378`）。

`stopping_` 由 `bool` → `std::atomic<bool>` 后的可见性：worker 在锁内读（`:350`），在**锁外**只在异常路径读（`:371`）。后者只用于"是否退出循环"这一**单调建议**，不保护任何被 mutex 拥有的数据（`queue_`/`sessions_`/`forget_sessions_` 的读取都在 `:345` 的 `unique_lock` 下），因此 `relaxed` 足够；**不构成**新缺陷。反向检查：`stopping_` 无任何 `bool` 残留读取（`:663` 是唯一声明）。

**但**：`worker_failures_` 只在 `:370` / `:377` 被 `fetch_add`，**全仓零读取点**（见 §4.2），所以"worker 丢了一条"外部完全不可见 —— 记 J-3。

## 2. N-4 / N-5 / N-6

### 2.1 N-4 `RdpServer::Stop()`（`[READ:src/server/server.cpp:2457-2501]`） —— **FAIL（High）**

已做的两处隔离确实有效（`:2473-2478` listener、`:2491-2496` 每会话），这一段 PASS。**但同一个函数里还有 3 个可抛点没有隔离**：

| 位置 | 语句 | 抛出后果 |
|---|---|---|
| `:2487-2490` | `{ lock_guard; sessions = registry->sessions; }` —— **vector 拷贝会分配** | 逃出 `Stop()` → 被 `~RdpServer`（`:2200`，**直接调用、无 try**）带出 → `terminate` |
| `:2497` | `std::unique_lock<std::mutex> lock(registry->mu);` | 同上 |
| `:2498` | `registry->cv.wait(...)`（可抛 `std::system_error`） | 同上 |

**红证（探针，非读码推演）**：在副本里给该拷贝加一个受环境变量控制的 `throw std::bad_alloc()`，跑 `server_releases_session_when_the_client_disconnects`：

```text
noenv        EXIT=0   1 tests, 7 checks, 0 failing tests
withthrow    EXIT=3   [crash] rtsc_server_tests: unhandled-seh
                      exception_code=0xE06D7363 (= C++ 异常)
```

未注入时同一二进制全绿，注入后进程直接死 → 归因明确是"`Stop()` 内的分配失败"。这正是 N-4 立项要消灭的那一类后果（"teardown 期间把进程带走"），H §2.1 的修法只覆盖了虚调用，漏掉了快照拷贝。

**最小修法**（约 6 行，不动语义）：

```cpp
std::vector<std::shared_ptr<RdpSession>> sessions;
try {
    std::lock_guard<std::mutex> lock(registry->mu);
    sessions = registry->sessions;
} catch (...) {
    // 快照失败：至少让 listener 已关、running 已置 false；
    // 下面仍要 wait，只是没有主动 Stop 的对象（会话会因断流自行退出）。
}
```

并把 `unique_lock` + `cv.wait` 包进 `try{...}catch(...){}`；`Stop()` 自身保持不抛（`~RdpServer` 无 try，这是唯一正确口径）。

### 2.2 N-5 `~RdpsndServer`（`[READ:src/channel/rdpsnd_server.cpp:47-54]`） —— **PASS**

`try{ if (source_ && started_) source_->Stop(); } catch (...) {}`，`source_` 是 `AudioCaptureSource`（外部注入，`include/rtsc/audio/audio_source.h:33` 的 `virtual void Stop() = 0` **未标 noexcept**）⇒ 必须 catch，宽度正确。

### 2.3 N-6 `~RdpdrServer`（`[READ:src/channel/rdpdr_server.cpp:39-58]`） —— **PASS（语义正确）/ 测试未钉（J-4）**

- `pending` 先 move 到局部（`:45-46`），回调重入不会失效容器 —— 正确；
- 逐 entry try/catch（`:52-55`）⇒ **单个回调抛不会跳过其余 pending**，正是"H 报告建议的语义"；如果整圈包一层，第一个抛就丢光了剩下的，所以**逐项**才是对的，判 PASS。

**但**：现有唯一覆盖它的用例 `rdpdr_server_io_destructor_fails_outstanding`（`[READ:tests/test_rdpdr_server_io.cpp:511-534]`）**只放 1 个 outstanding IRP**，所以"继续处理剩余"和"break 掉"在测试上**无法区分**。红证（变异：只失败第一个 pending）：

```text
[  OK  ] rdpdr_server_io_destructor_fails_outstanding
13 tests, 379 checks, 0 failing tests, 0 failed checks      EXIT=0
```

变异存活 ⇒ 记 **J-4**。最小修法：同一个用例里发 2 个 `CreateFile`（`outstanding_count()==2`），用两个计数器断言 `fires==2 && status1==status2==kStatusUnsuccessful`。

### 2.4 `catch (...)` 是否过宽 —— **保留，宽度正确**

与 H §4.1 同口径：`/EHsc` 下 `catch(...)` **不捕 SEH/AV**（不会掩盖内存破坏）；`DesktopInputSink` / `AudioCaptureSource` / `IrpCallback` 都是对外扩展点，规范未约束第三方实现的异常类型，收窄成 `catch(const std::bad_alloc&)` 会让抛 `std::runtime_error` 的 embedder 重新把槽/进程搞坏。真正的缺陷是**静默**（J-3）与**漏点**（J-1），不是宽度。

## 3. 测试缝风险（重点）

### 3.1 ① 宏会不会误入生产构建 —— **PASS**

`RTSC_DESKTOP_INPUT_TESTING` 全仓只有 3 处来源：`CMakeLists.txt:691-692`（`target_compile_definitions(... PRIVATE)`）、`tests/desktop_input_win32_test_hooks.h:15`（`#if`）、以及源码中的 `#if` 守卫。全仓无 `add_compile_definitions` / 全局 `/D`（`[BASH: Select-String CMakeLists.txt -Pattern 'add_compile_definitions|add_definitions'` 零命中）。

生产库的实际宏集合已落盘核对：

```text
[BASH: Select-String build\rtsc_server_desktop_input.vcxproj -Pattern PreprocessorDefinitions]
  %(PreprocessorDefinitions);WIN32;_WINDOWS;NDEBUG;CMAKE_INTDIR="Release"      ← 无 RTSC_DESKTOP_INPUT_TESTING
[BASH: Select-String build\rtsc_desktop_input_tests.vcxproj -Pattern PreprocessorDefinitions]
  ...;WIN32;_WINDOWS;NDEBUG;RTSC_DESKTOP_INPUT_TESTING;RTSC_SOURCE_DIR="F:/rtsc";...
```

⇒ 生产 target 拿不到宏；`MakeWin32DesktopInputSink()` 在生产走 `:748` 的真实现。① PASS。

### 3.2 ② 测试里"生产 factory 被编掉、null sink 顶名"是否造成"测试绿而生产链接坏" —— **PASS（有条件）**

机理确认：测试二进制里 `desktop_input_win32.cpp` 走 `#if defined(RTSC_DESKTOP_INPUT_TESTING)` 分支（`:693-744`）只导出 `...ForTest` + 6 个测试入口，`:748` 的 `MakeWin32DesktopInputSink()` 被**编译掉**；名字由 `desktop_input_null.cpp:52` 提供。因此测试二进制里**根本没有生产 factory**。

**红证（M3b）**：把生产 factory 的返回改成不存在的符号，然后分别构建两个 target：

```text
[BASH: cmake --build ... --target rtsc_desktop_input_tests]  TESTBUILD_EXIT=0     ← 测试照绿
[BASH: cmake --build ... --target rtsc_server_host]          HOSTBUILD_EXIT=1
  error C3861: "ThisSymbolDoesNotExist_ProductionOnly": 找不到标识符
  [...\rtsc_server_desktop_input.vcxproj]
```

⇒ **结论**：单跑 `ctest` 无法发现生产 factory 的编译/链接断裂；但全量构建（`ctest` 前置的 `cmake --build`）会通过 `rtsc_server_desktop_input` / `rtsc_server_host` 抓到。所以**不构成"假绿"**，但存在一个必须写进流程的守卫：**"只跑 ctest 不足以验证该文件的生产分支"**。这不是代码缺陷，是验收口径；判 PASS（有条件）。

### 3.3 ③ hook 的全局可变状态 / 测试间污染 / 并行 ctest —— **PASS（隔离成立）**，**FAIL（类型安全，J-2）**

**污染面**：`g_append_failure_hook`（`[READ:src/server/desktop_input_win32.cpp:87]`）是**进程级** `std::atomic<DesktopInputAppendFailureHook>`；两个用它的用例都成对 `Set(hook)` → `Set(nullptr)`（`:1199-1202`、`:1232-1235`）。`RunAll` 是**单线程顺序**执行（`tests/test_main.h:56-68`），`ctest` 每个测试是**独立进程**（`add_test(NAME desktop_input COMMAND rtsc_desktop_input_tests)`，`CMakeLists.txt:787`）⇒ **不存在跨用例/跨进程污染**。CHECK 失败不中止（`test_framework.h:47-53`），所以"断言红了就漏掉 clear"也不成立。判 PASS。

**但类型安全是真缺陷**（J-2）。所有 hook 都是"拿 `DesktopInputSink*`，直接 `static_cast` 成 `Win32DesktopInputSink*`"：

```cpp
[READ:src/server/desktop_input_win32.cpp:705-707]
Win32DesktopInputSink* AsWin32(DesktopInputSink* sink) {
    return static_cast<Win32DesktopInputSink*>(sink);
}
```

而**同一个测试 target** 的 `MakeWin32DesktopInputSink()` 返回的是 `NullDesktopInputSink`（`desktop_input_null.cpp:17,52`）。探针（`%TEMP%\opencode\jprobe\hook_probe.cpp`，用测试 target 的同一组宏/头，`MakeWin32DesktopInputSink()` 的返回值直接喂 hook）连跑 5 次：

```text
[BASH: probe_hook.exe ×5]
  run0 EXIT=-1073741819   null sink=... (dynamic type = NullDesktopInputSink)
                          DesktopInputTestSessionCount(null_sink)=0 (survived)   ← 读到垃圾，返回 0
                          （SeedPressedKey 处 → 0xC0000005 access violation）
  run1 EXIT=-1073741819   （同上）
  run2 EXIT=-1073740791   （0xC0000409 fail-fast，SeedPressedKey 写越界踩到 CRT 检查）
  run3/run4               挂住不返回，需外部 kill（shell 超时 180 s）
```

即三种结局：**静默返回错值**（统计类 hook 读到垃圾）、**AV / fail-fast**、**挂死**。**当前用例没触发**（都走 `...ForTest()`），属潜伏缺陷：任何人把 `MakeWin32DesktopInputSink()` 的返回值传进 hook（最自然的写法）就必崩/必挂，且崩在测试进程里、表现为 flaky 而不是断言红，`static_cast` 的 UB 性质决定结果还不可预期。

**最小修法（二选一）**：
- A（推荐，最省）：`MakeWin32DesktopInputSinkForTest()` 直接返回 `Win32DesktopInputSink*`（或加一个 `struct Win32DesktopInputSinkHandle`），hook 只接受具体类型 ⇒ 编译期就拒绝 null sink；
- B（改动更小）：`AsWin32` 改 `dynamic_cast`（`/GR` 默认开，`rtsc_desktop_input_tests.vcxproj` 未关 RTTI），`nullptr` 时返回失败/0，并给 `SeedPressedKey` 加"无法下转即不写"的早退。

## 4. 计数连通性

### 4.1 `release_failures` 三处语义 —— **PASS，但两个计数器是"不同事件"（须写清）**

| 位置 | 计数条件 | 值域 |
|---|---|---|
| win32 sink（`[READ:...:185-186]`、`:616-617`） | **合成 up 入队失败**（append 抛） | 每会话/每次 Shutdown 一项 |
| null sink（`[READ:src/server/desktop_input_null.cpp:40-42]`） | 恒 0（无队列，显式赋值） | 0 |
| server（`[READ:src/server/server.cpp:784-785]`） | **`ReleaseSession()` 整体抛出** | 每次 teardown 至多 1 |

关键事实：修复后的 Win32 `ReleaseSession` **自己吞掉 append 异常**（`:184-187`），所以对**出厂 sink** 而言 `server` 那个计数器**恒为 0** —— 即使 ups 真的丢了。也就是说 `RdpServer::input_release_failure_count()` 与 `InputStats::release_failures` **不是同一信号的两个出口，而是两个不相交的事件**。

可观测性并未断裂，因为 host 打的是 `InputStats`：

```text
[READ:tools/rtsc_server/main.cpp:618-619]   " input_release_failures=" + std::to_string(stats.release_failures)
[READ:tools/rtsc_server/main.cpp:630]       stats.release_failures != printed_input.release_failures  → 触发打印
```

⇒ 判 PASS，但建议在 `server.h:395-398` 的注释里补一句"该计数只覆盖 sink 实现自身抛出的情形；Win32 backend 的合成 up 丢失在 `DesktopInputSink::Stats().release_failures`"，否则运维会误以为 server 计数为 0 = 没丢键。

### 4.2 `worker_failures_` 未暴露 —— **FAIL（Medium，J-3）**

```text
[BASH: Select-String src/server desktop_input_win32.cpp -Pattern worker_failures_]
  370: worker_failures_.fetch_add(1, std::memory_order_relaxed);
  377: worker_failures_.fetch_add(1, std::memory_order_relaxed);
  684: std::atomic<uint64_t> worker_failures_{0};
[BASH: Select-String 全仓 (src/include/tests/tools) -Pattern worker_failures]
  → 仅上述 3 行；无 Stats()、无访问器、无 hook、无断言
```

即 N-3 新引入的"worker 吞掉一次异常并丢弃该项"**对任何读者都不可见**：既不进 `InputStats`，也没有测试。这是"为了不 terminate 而静默丢输入"的典型盲区（一条被丢的 `kKey` = 一次按键丢失）。

**最小修法**：`InputStats` 增加 `size_t worker_failures = 0;`（与 `release_failures` 同款），`Stats()` 里 `stats.worker_failures = worker_failures_.load(relaxed)`，null sink 显式 0；顺带给 hook 加 `DesktopInputTestWorkerFailureCount`，在 N-3 的用例里断言"注入一次 Dispatch 抛异常后该值 +1 且过程不崩"。

## 5. 测试真实性（先红后绿，全部在 `%TEMP%` 副本实跑）

副本基线（全部与 `6fc5614` 同 blob）：

```text
[BASH: git hash-object <copy> vs git rev-parse 6fc5614:<path>]
  src/server/server.cpp                  prist=True
  src/server/desktop_input_win32.cpp     prist=True
  tests/test_server.cpp                  prist=True
  tests/test_desktop_input.cpp           prist=True
  CMakeLists.txt                         prist=True
  src/channel/rdpdr_server.cpp           prist=True
  src/channel/rdpsnd_server.cpp          prist=True
[BASH: cmake --build ... --clean-first]   BUILD_EXIT=0   DIAG(error C|error LNK|warning C)=0
[BASH: ctest --test-dir <copy>\build -C Release]
  100% tests passed, 0 tests failed out of 63      (78.42 s)
```

| 变异 | 改坏点 | 实测 | 行号 |
|---|---|---|---|
| **M1 = 回退 N-1** | `sessions_.erase(it)` 移入 `AppendReleasesLocked` 的 try | **红** | `tests/test_desktop_input.cpp:1105`（`SessionCount == 0`，got 1） |
| **M2 = 回退 N-2** | `Shutdown` 去掉 noexcept / 加 `if(stopping_) return;` / 去掉逐项 catch | **进程被杀**（0xE06D7363，unhandled-seh，EXIT=3） | — |
| **M2b = 只跳 join** | `if (worker_.joinable() && false) worker_.join();` | **红** | `tests/test_desktop_input.cpp:1136`（`!WorkerJoinable`） |
| **M3 = server 计数** | 删 `input_lease_->release_failures->fetch_add` | **红** | `tests/test_server.cpp:3899`（got 0 want 1） |
| **M5 = sink 计数** | 删 `ReleaseSession` 内的 `release_failures_.fetch_add` | **红** | `tests/test_desktop_input.cpp:1107`（got 0 want 1） |
| **M4 = 删无条件 notify** | `ReleaseSession` 末尾的 `cv_.notify_one()` 改为空语句 | **存活（假测试）** | 见下 |

**M4 是本次最重要的负面结论**：删掉 `:196` 的 `cv_.notify_one()` 后，N-1 用例

```text
M4 runs=30 fails=0    (另一份副本 runs=20 fails=0, 又一份 runs=100 fails=0)
```

原因是**竞态**：worker 启动后要跑完第一轮才进 `cv_.wait()`；若测试线程在 worker 尚未 park 时完成 `ReleaseSession`，worker 的**首轮** `ForgetReleasedSessionsLocked()`（`:346`）自己就把 forget 抽干了，notify 有没有都绿。只有当 worker 已 park 时缺 notify 才暴露：

```text
[BASH: 在副本的用例里 ReleaseSession 之前插入 sleep_for(200ms)]
  M4(no notify) + settle  EXIT=1
  FAIL tests/test_desktop_input.cpp:1119  drained
  healthy     + settle  runs=5 fails=0
```

独立探针（不经测试框架，直接调 hook）把这条机理压实：

```text
[BASH: probe_M4.exe  ×5]   after_release sessions=0 pending_forget=1 release_failures=1
                           drained=0 final_pending=1        EXIT=1（5/5）
[BASH: probe_P.exe  ×3]    drained=1 after_ms=0/10/10  final_pending=0   EXIT=0（3/3）
```

⇒ `[READ:tests/test_desktop_input.cpp:1108-1118]` 的 `drained` **不能可靠钉住"worker 被唤醒"**，只能偶然钉住。这个断言要保留，必须消除竞态。

**最小修法**：在用例里让"worker 已 park"成为确定前置 —— 在 `SetDesktopInputAppendFailureHook` 之前加一次"等待 worker 进入等待态"的探测（hook 暴露 `std::atomic<bool> worker_waiting_`，worker 在 `cv_.wait` 前 set、唤醒后 clear；测试 `WaitUntil(worker_waiting)`），或退而求其次 `sleep_for(200ms)`（经验实测 100% 命中，但仍是时间依赖，不如前者）。用确定性探测更好，因为 N-1 的整个价值就在"worker 必须被唤醒"。

### 5.1 N-2 用例的一个额外正面结论

`[READ:tests/test_desktop_input.cpp:1140-1145]` 在 `WorkerJoinable` 仍为真时 `sink.release()` 泄漏对象以避免 terminate，这个防御是**对的**（否则失败会被 `std::terminate` 吞成"进程挂"而不是"用例红"）。M2b 实测走不到这条分支（崩溃前已 join 失败），但它保护的是"M2 类变异在断言阶段就炸"的场景，保留。

## 6. 回归

**独占**（跑前确认无其他 `rtsc_*`/`ctest` 进程）：

```text
[BASH: ctest --test-dir build -C Release --output-on-failure]（工作树）
  100% tests passed, 0 tests failed out of 63      Total Test time (real) = 61.42 s
[BASH: 同上，第二次]
  100% tests passed, 0 tests failed out of 63      Total Test time (real) = 61.04 s
[BASH: ctest --test-dir <6fc5614 纯净副本>\build -C Release]
  100% tests passed, 0 tests failed out of 63      (78.42 s)
```

| 套件 | 结果（3 次） |
|---|---|
| `rtsc_desktop_input_tests` | `46 tests, 13752 checks, 0 failing` ×3（无抖动） |
| `rtsc_server_tests` | `49 tests, 0 failing` ×3；checks 在 563 / 564 间浮动（`server_release_session_precedes_lease_handoff` 的交接循环按调度放 CHECK，见 H §5） |
| `rtsc_rdpdr_server_io_tests` / `rtsc_rdpsnd_server_tests` | `13/379/0`、`14/401/0` |

判 **PASS**（63/63、0 failing 均实测；按要求不把 checks 总数当判据）。

## 7. 文档行号（`docs/spec/input-injection-seam.md` @ `6fc5614`）

### 7.1 题目点名的第 137 行两处 —— **PASS**

```text
[READ:docs/spec/input-injection-seam.md:137]  ... `AppendReleasesLocked` ...（`desktop_input_win32.cpp:292-315` ...）...
                                              且 purge 明确保留 `synthetic` 项（`:389-410` ...）
[READ:src/server/desktop_input_win32.cpp:292-315]   void AppendReleasesLocked(...) { ... }
[READ:src/server/desktop_input_win32.cpp:389-410]   void ForgetReleasedSessionsLocked() { ... forget_sessions_.clear(); }
```

与实际代码**完全一致**（含"批 12-H 时为 236-258 / 311-319，N-1/N-2 修改后整体下移"的说明）。

### 7.2 §1.8（同文件 `:204-221`）—— **FAIL（Low，J-5）**

1. **结论性断言已失效**：`:204` 仍写"`src/server/desktop_input_win32.cpp` **不在任何测试 target 的编译/链接闭包内**"，`:209` 仍写"因此对该文件的任何变异都无法让 ctest 转红"。`6fc5614` 的 `CMakeLists.txt:684-694` 恰好把这个文件编进了 `rtsc_desktop_input_tests`，且本报告 §5 的 M1/M2b/M5 都是在 ctest target 上转红的 —— 与本句**直接矛盾**。
2. **`:206-208` 的 CMake 行号已漂移**：`CMakeLists.txt:676-682` 仍含 `add_executable` + null sink（部分正确），但 `:691` 现在指向 `target_compile_definitions`（`RTSC_DESKTOP_INPUT_TESTING`），生产库已移到 `:702`；`:704`（host 链接）现在是 `:713-715`。`:608-609`（`rtsc_server_tests` 链接 `rtsc_server`）**仍准确**。
3. **`:212-218` 七处代码行号全部漂移**（`6fc5614` 实际值）：

| 文档写 | 实际（`6fc5614`） |
|---|---|
| `:197-203` 移动合并 | `249-255` |
| `:204-209` `oldest_move` | `256-261` |
| `:221-228` `kEvictMove`/`kDrop` | `274-283` |
| `:236-258` `AppendReleasesLocked` | `292-315` |
| `:301-322` purge | `389-410` |
| `:368-384` `Dispatch` | `456-473` |
| `:388-476` `BuildNative` | `476-564` |

**最小修法**：把 §1.8 改成"**部分闭合**"：已由测试钉住（ReleaseSession/Shutdown 的 append 抛异常、`release_failures`、forget 抽干、无条件 notify/join —— 但 notify 一条见 §5 M4，实际未钉死）；仍只靠读码（移动合并、`kEvictMove`/`kDrop`、`AppendReleasesLocked` 的键位、purge、`Dispatch` 顺序、`BuildNative`）。并把 7 处行号改为上表值（或干脆改成 `文件:符号`，避免再漂）。

### 7.3 `docs/spec/input-batch10-review-F.md:340` —— **PASS（轻微偏短）**

写"`server.cpp:776-787`"；实际修复块是 `776-791`（`holders.erase` 在 `788-791`）。关于"`holders.erase` 已移出可抛调用"的论断正确，只是行号少算了 4 行。建议改 `776-791`。

## 8. FAIL 汇总 + 最小修法

| ID | 判定 | 位置 | 最小修法 | 影响面 |
|---|---|---|---|---|
| **J-1** | **FAIL High** | `server.cpp:2486-2498` | 快照拷贝 + `unique_lock` + `cv.wait` 各包 `try{...}catch(...){}`，`Stop()` 全程不抛 | 需新增 1 个用例：注入"快照分配失败仍不 terminate"（本报告探针可直接复用：env-gated throw） |
| **J-2** | **FAIL Medium** | `desktop_input_win32.cpp:705-743`、`desktop_input_win32_test_hooks.h:25-50` | `MakeWin32DesktopInputSinkForTest()` 返回具体类型 `Win32DesktopInputSink*`（或 hook 用 `dynamic_cast` 并失败早退） | 只动测试缝 + 1 处用例取用点；生产 target 不编这段 |
| **J-3** | **FAIL Medium** | `desktop_input_win32.cpp:370/377/684`、`tests/test_desktop_input.cpp:1108-1118` | ① `InputStats.worker_failures` + `Stats()` + host 打印；② `drained` 改为确定性前置（hook 暴露 `worker_waiting_` + `WaitUntil`），否则保持时间依赖 | `desktop_input.h`、`desktop_input_null.cpp`、`main.cpp`、两个测试文件 |
| **J-4** | **FAIL Medium** | `tests/test_rdpdr_server_io.cpp:511-534` | 用例内放 2 个 outstanding IRP，断言两个都收到 `kStatusUnsuccessful` | 只改测试 |
| **J-5** | **FAIL Low** | `docs/spec/input-injection-seam.md:204-221` | §1.8 改"部分闭合" + 7 处行号按 §7.2 表更新 | 只改文档 |
| **N-2 注记** | Low | `desktop_input_win32.cpp:641` | `join` 包一层 catch，与 `:601` 注释口径统一 | 1 行 |

**判"已闭合"的三项**：N-1（行为）、N-2（行为）、N-3（行为）—— 均有红证，且状态机正确。

## 9. 影响范围（若按本报告修）

- 代码：`src/server/server.cpp`（J-1）、`src/server/desktop_input_win32.cpp`（J-2/J-3/N-2 注记）、`include/rtsc/server/desktop_input.h` + `src/server/desktop_input_null.cpp` + `tools/rtsc_server/main.cpp`（J-3 计数）。
- 测试：`tests/test_desktop_input.cpp`（J-2/J-3）、`tests/test_rdpdr_server_io.cpp`（J-4）。
- 文档：`docs/spec/input-injection-seam.md` §1.8、`docs/spec/input-batch10-review-F.md:340`。
- 受影响套件（按影响范围跑，非全量）：`rtsc_server_tests`（J-1）、`rtsc_desktop_input_tests`（J-2/J-3）、`rtsc_rdpdr_server_io_tests`（J-4）、`rtsc_rdpsnd_server_tests`（回归确认 N-5 未受影响）；C0 需覆盖 `rtsc_server_desktop_input` 与 `rtsc_server_host` 的编译（`/W4 /WX`），因为 J-2 动的是那条分支。

## 10. 未验证（W5）

1. **真实 `bad_alloc`** 的端到端复现：J-1 与 N-2 的红证都用"受控注入异常"代替真内存耗尽；两者的前置条件（可抛调用在清理之前）相同，红绿结论一致，但真实分配失败的时机分布未测。
2. **`cv_.wait` 抛 `std::system_error`** 的路径：J-1 的探针只覆盖了快照拷贝（`bad_alloc`），没单独构造 `system_error`。
3. **真机 `SendInput`**：本报告全部在"不注入真实输入"的测试缝下完成，pressed/合成 up 的物理效果仍 UNVERIFIED-真机。
4. **J-2 的 AV 是否 100%**：探针连续 1 次命中 `0xC0000005`（`SeedPressedKey` 写 `sessions_[id]` 必然越界），未做 100 次重复；`static_cast` 的 UB 性质决定了结果依赖对象布局，理论上也可能"写进别的字段不崩"。
5. **批 16/17 的 `PauseSequenceFilter`** 不在本审计对象内（`6fc5614` 无此类），仅在核对 `desktop_input_map.h` 行号时看到；其正确性由 K 审计负责，本报告不背书。
