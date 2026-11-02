# 批 19 审计 L：J-1..J-5 修复是否闭合 + 新异常安全/测试真实性缺陷

- 对象：提交 `5aa9fea`（父 `31a4937`，`git show --stat` 11 文件 / +184 −33）
- 审计角色：只读审计（除本文件外未改 src/include/tests/tools/CMakeLists）
- 环境：Windows 11 / MSVC 14.44.35207（`/W4 /WX /permissive- /utf-8`，`/EHsc`，VS 17 2022 Release x64，32 逻辑核）
- 独立性：全部变异实验在 `%TEMP%\opencode\Laudit`（`git archive 5aa9fea` 全量副本）上做；
  基线用 `git hash-object vs git rev-parse 5aa9fea:<path>` 逐文件比对（`prist=True`，见 §0.2）。
- 证据约定：`[READ:path:line]` 指 `5aa9fea` 的 blob；变异实验用 `[BASH:...]` 给命令与实测输出。

## 0. 结论（一句话）

**J-2 / J-3a / J-3b / J-4 / J-5 五项闭合成立**（J-3b、J-4 有红证；J-2 有红证——变异后用例直接挂死）。
**J-1 只闭合了一半，且新引入一个 High 级 use-after-free 前提**：

| ID | 判定 | 一句话 |
|---|---|---|
| **J-1①** | **FAIL High** | 快照拷贝失败 ⇒ `sessions` 为空 ⇒ **没有任何 `s->Stop()`** ⇒ `live` 永不为 0 ⇒ `cv.wait` **永久挂住**（实测 20 s 无返回）。修法把"漏掉的 3 个可抛点"换成了"只捕获不发信号"，teardown 从"崩"变成"挂"，仍是不可接受的失败模式。 |
| **J-1②** | **FAIL High（新缺陷）** | `cv.wait` 抛 `std::system_error` 被 `catch(...){}` 吞掉后，`Stop()` **立即返回**而 `live != 0`。实测：`Stop()` 返回 `live=1`，随后**会话线程仍在调用宿主对象**（`DesktopSource::Capture` 被 CountingSource 记到 1 次）。这正是 `~RdpServer` 提前完成、宿主按文档销毁借用对象 ⇒ **UAF**。`~RdpServer` 的 try 只防止 `terminate`，不防止"提前返回"。 |
| **J-2** | **PASS** | `dynamic_cast` 已就位（`[READ:...:732]`），全仓 **零 `/GR-` / 零 `-fno-rtti`**，各 target 的 `.vcxproj` 也 **零 `RuntimeTypeInfo`**（= MSVC 默认 `/GR` 开启）。6 个 hook 全部 `nullptr → 0/false/early-return`（`:739-775`），无"调用方继续用 null"。变异红证：`static_cast` 恢复后新用例 `desktop_input_test_hooks_reject_foreign_sink` **挂死**（30 s 超时，与被修缺陷同型）。 |
| **J-3a** | **PASS** | 三端接通：`InputStats::worker_failures`（`desktop_input.h:65`）→ win32 `Stats()`（`win32.cpp:213-214`）→ null 显式 0（`desktop_input_null.cpp:44`）→ host 打印+变更判定（`main.cpp:620-621`、`:633`）。语义与 `release_failures` 一致（同为"某动作被丢弃且只有计数器可见"的单调累计；`[READ:desktop_input.h:50-59]` 两段注释口径相同）。**但见 §5.1 的"只写不验"注记**。 |
| **J-3b** | **PASS（红证）** | `worker_waiting_` 在 `mu_` 内 `store(true)` 后立刻 `cv_.wait`（`win32.cpp:369-374`），醒来 `store(false)`（`:375`）；无 lost-wakeup 窗口（`wait` 前持锁，notify 方持同一 `mu_`，故 notify 只会落在 store 之后或 wait 唤醒之后）。实测删 `cv_.notify_one()`（`win32.cpp:199`）后，新用例 **5/5 红**（`test_desktop_input.cpp:1234`）。 |
| **J-4** | **PASS（红证）** | 双 IRP + 首个回调抛（`test_rdpdr_server_io.cpp:515-549`）。两种写坏的变异都转红：①`catch(...){break;}`（逐项内 break）→ `fires==1 (want 2)`、`status2==0`；②整圈单 `catch` 包住循环 → 同样红。 |
| **J-5** | **PASS（附 1 条 Low）** | §1.8 已改"**部分闭合**"并先写结论（`seam.md:236-240`）；全文 `文件:行号` 引用 **0 处**（含 `:数字` 形态 0 处）。`review-F.md:340` 已为 `776-791`，但**目标提交号写的是 `a59a594`**——那处的 `holders.erase` 在 `782`，`776-791` 落在 `a59a594` 行号上属"块边界近似"，若按 `6fc5614` 才精确为 `776-791`。见 §6.2。 |

**新引入风险（本批最危险）**：`~RdpServer` 的 `try{Stop();}catch(...){}` + `Stop()` 内 wait 的 `catch(...){}` **组合出
"析构提前完成而会话线程仍活"**——这是 J-1 修法自身的副产品，不是原有缺陷。J-2 的 `nullptr` 路径**未引入**新风险（各 hook 都早退，见 §3.2）。

---

## 1. J-1 `src/server/server.cpp`（FAIL High ×2）

已做的三处隔离确实存在：

```text
[READ:src/server/server.cpp:2210-2217]  RdpServer::~RdpServer() { try { Stop(); } catch (...) {} }
[READ:src/server/server.cpp:2509-2513]  try { lock_guard; sessions = registry->sessions; } catch (...) {}
[READ:src/server/server.cpp:2524-2528]  try { unique_lock; cv.wait(..., live == 0); } catch (...) {}
```

### 1.1 追问①：快照失败 ⇒ `sessions` 空 ⇒ 等待永不返回 —— **确证，High**

结构上的因果链（`[READ:src/server/server.cpp:2508-2528]`）：

1. `sessions` 为空 ⇒ `for (const auto& s : sessions)` 的循环体 **一次都不执行** ⇒ 没有一次 `s->Stop()`；
2. 会话线程只在 `session->Run()` 返回/抛之后才走到 teardown（`[READ:src/server/server.cpp:2371]` 的
   `body` lambda），而 `Run()` 在 `ActiveLoop` 里靠 `ReadFrame` 的 `kReadTimeout` 轮询
   `stop_requested_`（`[READ:src/server/server.cpp:929-930]`）；`stop_requested_` **只有 `RdpSession::Stop()` 会置位**
   （`[READ:src/server/server.cpp:756-759]`）；
3. 于是会话线程永远不会主动退出，`live` 永远 ≥ 1，`cv.wait(pred)` 永不满足 ⇒ `Stop()` 永久挂住。

注释 `[READ:src/server/server.cpp:2504-2507]` 断言"each one notices the closed transport and tears itself down"——**这条断言在本仓不成立**：
`Stop()` 对 listener 调的是 `listener->Close()`（`:2490-2494`），**不影响已 accept 的 `Transport`**；
会话的 `transport_` 只能由 `RdpSession::Stop()` 关闭。快照失败正好跳过了那一步。

**红证 R1（实测挂死）**：副本里在快照拷贝前插入 env 门控 `throw std::bad_alloc()`（模拟分配失败），
用例把会话驱动到 active 并**保持客户端连接**，然后 `Stop()`：

```text
[BASH: Laudit\build\Release\rtsc_server_tests.exe, RTSC_TEST_FILTER=probe_L_j1_snapshot_throw]
  PROBE before Stop
  (20 s 内无任何输出，进程需外部 kill)  → TIMEOUT after 20s -> Stop() HUNG
```

**对照（证明挂死是"没发 Stop 信号"，不是别的原因）**：同一二进制、同一注入，只把客户端 transport 先关掉再 `Stop()`：

```text
[BASH: 同上 + PROBE_L_CLOSE_CLIENT=1]
  PROBE closing client transport first
  PROBE client closed, session_count=0
  PROBE before Stop
  PROBE after Stop session_count=0
  PROBE joined
  1 tests, 2 checks, 0 failing      EXIT=0
```

⇒ 归因明确：**只有"快照失败 + 会话仍在跑"这一组合会永久挂住**。这正是 J-1 立项要消灭的
"teardown 把进程带走"的另一半（从 terminate 变成 hang）。生产里 `main.cpp:725` 的 `server.Stop()`
之后紧跟 `runner.join()`，挂住就是进程收不了尾（`--seconds` 到期也不退出）。

**最小修法（仍不动语义，约 4 行）**：

```cpp
std::vector<std::shared_ptr<RdpSession>> sessions;
bool snapshot_ok = false;
try {
    std::lock_guard<std::mutex> lock(registry->mu);
    sessions = registry->sessions;
    snapshot_ok = true;
} catch (...) {
}
if (!snapshot_ok) {
    // No snapshot: we cannot address the sessions, so we must not block on a
    // count only they can clear. Set the stop flag and return; the detached
    // threads finish when their transports fail (a hang here is worse than a
    // prompt return, and ~RdpServer must not stall the process).
    return;
}
```

注意 `running=false` 已在 `:2485` 置位、listener 已关（`:2490-2494`），所以提前 return 不会漏掉
"不再接受新连接"这一语义；丢掉的是"等旧会话结束"。可选更稳妥的写法：把 `live` 的等待改成
`cv.wait_until(deadline)`（例如 5 s）——**两者择一即可，但"无限期等一个没人会清零的计数"必须去掉**。

### 1.2 追问②：wait 吞异常后早退 ⇒ use-after-free —— **确证，High（本项最危险点）**

`catch (...)` 吞掉 `cv.wait` 的 `std::system_error` 之后，`Stop()` **直接返回**（`:2527-2528`），
不再检查 `live`。此时：

- `~RdpServer`（`:2210-2217`）返回 ⇒ **`RdpServer` / `Impl` 被销毁**；
- 但会话线程还在跑，`body` lambda 捕获了 `registry`（shared_ptr，安全） **以及 `session`**，
  而 `session` 内保存的是**裸指针** `source_` / `input_sink_` / `clipboard_` / `file_list_provider_`
  （`[READ:src/server/server.cpp:2049]（`DesktopSource* source_`）、[READ:src/server/server.cpp:2056]（`DesktopInputSink* input_sink_`）` 构造参数逐个存裸指针；`source_` 在
  `[READ:src/server/server.cpp:1563]` 被 `Capture()` 调用）；
- 文档明确允许宿主在 `Stop()` 之后销毁这些对象：`[READ:include/rtsc/server/server.h:293-295]`
  "The pointer must outlive the server"、`[READ:include/rtsc/server/server.h:307-310]` 与
  `[READ:include/rtsc/server/server.h:319-323]` 的 sink/clipboard 都写 "must outlive the server (including Stop())"。

⇒ `Stop()` 返回即 `RdpServer` 析构完成 ⇒ 宿主销毁 sink/source/clipboard ⇒ 会话线程继续调用它们 ⇒ **UAF**。
`~RdpServer` 的 `try` 只防止异常逃逸，**完全不检查"是否真的等到了"**，所以它对这个新缺陷零保护。

**红证 R2（实测：Stop 返回 live=1，之后会话线程仍调用宿主对象）**：
副本里给 wait 加 env 门控 `throw`，宿主对象用 `CountingSource`（`Capture` 内计数），
用例在 `Stop()` 返回后**置标志**，然后开闸让会话线程继续：

```text
[BASH: Laudit\build\Release\rtsc_server_tests.exe, RTSC_TEST_FILTER=probe_L_j1_touch_after_stop]
  PROBE session inside Capture=1
  PROBE Stop returned with live=1
  PROBE Capture calls AFTER Stop() returned=1        ← 宿主对象（server 已析构）仍被会话线程调用
  PROBE second Stop: live=0
  1 tests, 2 checks, 0 failing
```

其中"Capture calls AFTER Stop() returned" 的判定是：`Capture` 入口检查
`g_stop_returned`（由测试线程在 `Stop()` 返回后置 true），命中即计数。
**这条计数只依赖"Stop 返回后仍进入 Capture"，不依赖任何内存被真的释放**，所以它比"跑起来崩不崩"更可靠——
UB 是否立刻崩取决于堆复用时机，计数不会骗人。

补充：`Stop()` 的注释 `[READ:src/server/server.cpp:2520-2523]` 自述"Teardown is already done at this point, so
swallowing it is correct"——**这句是错的**：`cv.wait` 正是"等待会话线程结束"这一步本身，
吞掉它等于放弃 server.h 承诺的 "then joins their threads"（`[READ:include/rtsc/server/server.h:332-334]`）。

**最小修法**：

```cpp
    // A failed wait must not silently look like a completed teardown: the
    // destructor's contract is "the session threads are finished". Retry the
    // predicate once via a bounded wait; if that also fails, at least keep the
    // process alive without pretending the wait succeeded.
    for (int attempt = 0; attempt < 2; ++attempt) {
        try {
            std::unique_lock<std::mutex> lock(registry->mu);
            if (registry->cv.wait_for(lock, std::chrono::seconds(5),
                                      [&] { return registry->live == 0; })) {
                return;
            }
        } catch (...) {
        }
    }
```

即：**① 不能无限等一个可能没人清零的计数（见 1.1）；② 也不能把"等失败"当成"等成功"**。
两者结合的正确形态是"有界等待 + 失败时不假装完成"（例如 `main.cpp` 侧在 `Stop()` 后自行确认 `session_count()==0`
再销毁借用对象，或把 `Stop()` 改成返回 `bool` 表示"是否确认所有会话线程已结束"）。
若不想改签名，最小可接受修法是**在 `catch` 后再读一次 `live`**，若 `live != 0` 至少
`std::fprintf(stderr, ...)` 报错（让挂/早退可诊断），但**报错不能替代正确性**。

严重度：**High**。触发条件是 `cv.wait` 抛（`std::system_error`，通常是 mutex misuse/资源耗尽），
概率低但后果是静默 UAF；且 `~RdpServer` 的 try 让人误以为"已经安全"。

---

## 2. J-2 `AsWin32` → `dynamic_cast`（PASS）

### 2.1 ① RTTI 是否真的开 —— **PASS**

```text
[READ:src/server/desktop_input_win32.cpp:731-733]  AsWin32 → dynamic_cast<Win32DesktopInputSink*>(sink)
[BASH: git grep -n -i "fno-rtti|/GR-" 5aa9fea -- .]   → 命中 0（全仓无任何关闭 RTTI 的开关）
[BASH: Select-String build\*.vcxproj -Pattern "RuntimeTypeInfo|/GR-"] → 0（所有 target 都用 MSVC 默认 /GR）
[BASH: CMAKE 侧] add_compile_options 只有 /W4 /WX /permissive- /Zc:__cplusplus /utf-8（无 /GR-）
```

`dynamic_cast` 只在 `#if defined(RTSC_DESKTOP_INPUT_TESTING)` 分支里（`[READ:...:714]` 起），
生产 target `<PreprocessorDefinitions>` 无该宏（`build\rtsc_server_desktop_input.vcxproj:136`
=`WIN32;_WINDOWS;NDEBUG`），因此生产二进制**不含**这段代码 ⇒ 即便将来有人给生产 target 关 RTTI 也不会编译失败；
测试 target 的 `.vcxproj:154` 有 `RTSC_DESKTOP_INPUT_TESTING` 且无 `RuntimeTypeInfo=false`。

### 2.2 ② nullptr 后各 hook 的行为 —— **PASS（静默返回，不是继续用 null）**

`[READ:src/server/desktop_input_win32.cpp:737-776]` 六个 hook 全部显式判空：

| hook | nullptr 行为 | 行 |
|---|---|---|
| `DesktopInputTestSeedPressedKey` | `return;`（不写对象） | `:740` |
| `DesktopInputTestSessionCount` | `return 0` | `:746` |
| `DesktopInputTestPendingForgetCount` | `return 0` | `:752` |
| `DesktopInputTestShutdown` | `return;`（不调 Shutdown） | `:758` |
| `DesktopInputTestWorkerJoinable` | `return false` | `:768` |
| `DesktopInputTestWorkerWaiting` | `return false` | `:774` |

`DesktopInputTestWorkerFinished` 走 `!Joinable`（`:762-764`）⇒ 外来 sink 返回 `true`（"未在运行"），
语义上正确（不是 Win32 sink 就没有 worker 在跑）。**没有"调用方继续用 null"的路径。**

**红证 R3（变异 → 新用例挂死）**：副本里把 `dynamic_cast` 还原为 `static_cast` 后
跑新用例 `desktop_input_test_hooks_reject_foreign_sink`：

```text
[BASH: Laudit\build\Release\rtsc_desktop_input_tests.exe, RTSC_TEST_FILTER=desktop_input_test_hooks_reject_foreign_sink]
  [ RUN  ] desktop_input_test_hooks_reject_foreign_sink
  (30 s 无输出，需外部 kill)  → TIMEOUT/挂死
```

与被修缺陷的表现（批 13-J 记录的 AV / fail-fast / 挂死）同型 ⇒ **新用例确实钉住了这个变异**。

### 2.3 Low 注记（不阻塞）

`desktop_input_test_hooks_reject_foreign_sink`（`[READ:tests/test_desktop_input.cpp:1237-1266]`）只覆盖
`nullptr` 与 null sink 两种外来类型，**没有覆盖"另一个真实子类"**（例如测试里临时定义一个
`class OtherSink : public DesktopInputSink`）。`dynamic_cast` 对任意外来类型都返回 `nullptr`，
所以语义上已经覆盖；此注记只是提示"用例覆盖面略窄于实现保证面"。

---

## 3. J-3a `worker_failures` 三端接通（PASS）

### 3.1 语义与 `release_failures` 是否一致 —— **PASS**

| 位置 | `release_failures` | `worker_failures` |
|---|---|---|
| 结构体字段 | `[READ:include/rtsc/server/desktop_input.h:64]` | `[READ:include/rtsc/server/desktop_input.h:65]` |
| 注释口径 | "teardown attempts whose synthetic ups could not be queued … counter is the only way an operator can observe a release that was lost" | "platform actions dropped because one worker iteration threw … the counter is the only visible signal" |
| win32 计数点 | `[READ:...:188]`（ReleaseSession）、`[READ:...:632]`（Shutdown） | `[READ:...:386]`（循环体 catch）、`[READ:...:393]`（FlushMoves catch） |
| win32 `Stats()` | `[READ:...:211-212]` | `[READ:...:213-214]` |
| null 显式 0 | `[READ:src/server/desktop_input_null.cpp:42]` | `[READ:src/server/desktop_input_null.cpp:44]` |
| host 打印 | `[READ:tools/rtsc_server/main.cpp:618-619]` | `[READ:tools/rtsc_server/main.cpp:620-621]` |
| host 变更判定 | `[READ:tools/rtsc_server/main.cpp:632]` | `[READ:tools/rtsc_server/main.cpp:633]` |
| 测试断言 | `[READ:tests/test_desktop_input.cpp:1228]`、`:1285` | `[READ:tests/test_desktop_input.cpp:1194]`、`:1286`、`:1160` |

两者都是 **monotonic、relaxed load/store、null 显式 0**，语义一致。

### 3.2 注记（Low，不阻塞）：`worker_failures` 仍缺"能涨"的用例

`[BASH: git grep -n worker_failures 5aa9fea -- tests]` 只有三个断言，且**全部断言它 == 0**：

```text
tests/test_desktop_input.cpp:1194  CHECK_EQ(sink->Stats().worker_failures, 0)   // null sink
tests/test_desktop_input.cpp:1286  CHECK_EQ(sink->Stats().worker_failures, 0)   // shutdown 用例
tests/test_desktop_input.cpp:1160  CHECK(src.find("input_worker_failures=") ...) // host 源码里有这个串
```

**实际复现**：副本里把 `[READ:...:386]` 的 `worker_failures_.fetch_add(1, ...)` 删掉（模拟"计数点写坏"），
`rtsc_desktop_input_tests` 仍然 **49 tests / 0 failing**：

```text
[BASH: Laudit 副本，删除 win32.cpp:386 的 fetch_add 后重建并全跑]
  49 tests, 13778 checks, 0 failing tests, 0 failed checks      EXIT=0
```

⇒ J-3a 的"可观测性"**代码层接通了，但测试层只钉住了 0**，即"计数点存在且恒 0"与"计数点被删掉"无法区分。
这与 J-3b 之前的问题同型（"能观测"≠"被验证"）。**最小修法**：给 win32 sink 加一个
`DesktopInputTestWorkerFailureCount`（或复用 `Stats()`），再用 hook 让一次 `Dispatch` 抛（例如给
`Emit` 注入一个抛异常的 `SendInput` 替身——目前 `Emit` 直连 Win32 API，所以更现实的做法是
在 `AppendReleaseLocked` 类 hook 之外加一个 `g_dispatch_failure_hook`），断言"注入一次后 `worker_failures` +1 且进程不崩"。
严重度 **Low**：计数确实可被运维读到，缺的只是"涨"这一侧的回归保护。

---

## 4. J-3b `worker_waiting_`（PASS，红证）

### 4.1 置位/清位是否在 `mu_` 内、有无 lost-wakeup —— **无窗口**

```text
[READ:src/server/desktop_input_win32.cpp:353-376]
    std::unique_lock<std::mutex> lock(mu_);      // 持锁
    ... ForgetReleasedSessionsLocked(); ...
    if (!queue_.empty()) {...} else if (stopping_) {...} else {
        const auto deadline = NextMoveDeadline();
        worker_waiting_.store(true, release);    // :369  仍在持锁
        if (deadline) cv_.wait_until(lock, *deadline); else cv_.wait(lock);  // :370-374 释放锁并 park
        worker_waiting_.store(false, release);   // :375  已被唤醒并重新持锁
    }
```

lost-wakeup 面分析：

- `notify_one` 的调用方（`Inject` `[READ:...:159]`、`ReleaseSession` `[READ:...:199]`）都必须先取 `mu_`
  （`:164`）才能改 `queue_`/`forget_sessions_`，而 worker 在**置位之后、释放锁之前**都持有 `mu_`。
  于是两种交错：
  1. notify 方先拿到锁 ⇒ 它改了队列并 notify 的时刻 worker 还没 park（`worker_waiting_` 尚为 false）⇒
     worker 随后取锁会看到 `queue_` 非空 / `forget_sessions_` 非空（谓词成立）⇒ **不会 park**；
  2. worker 先拿到锁 ⇒ park 期间 notify 方取锁、改状态、`notify_one` ⇒ 唤醒 worker。
  不存在"notify 落在 store(true) 之后、wait 之前且状态未变"的窗口，因为**状态变更与 notify 同锁**。
- `store(false)` 在唤醒后、仍持锁（`unique_lock` 到 `:377` 才析构）⇒ 读者看到 `false` 时
  worker 要么在跑、要么即将重新取锁；读者看到 `true` 时 worker **一定**已释放 `mu_` 进入等待
  （或即将进入，`wait` 的归还语义保证不会在持锁状态下返回）。
  **注释 `[READ:...:363-368]` 的说法（"a reader that observes true can only take mu_ once the worker is
  actually parked"）在 `wait_until` 的虚假唤醒面下略强**：`wait_until` 可能超时/虚假唤醒后立刻
  `store(false)`，此时读者可能看到 `true` 而 worker 已在返回路上；但用例只把 `true` 当"worker 曾经 park 过"
  的前置条件（随后才 `ReleaseSession`），**不要求它一直为真**，因此不影响判定。判 PASS。

### 4.2 确定性复现"删 notify 必红" —— **实测 5/5 红**

变异：把 `[READ:src/server/desktop_input_win32.cpp:199]` 的 `cv_.notify_one();` 改为空语句，
重建 `rtsc_desktop_input_tests` 后单跑用例 5 次：

```text
[BASH: Laudit\build\Release\rtsc_desktop_input_tests.exe, RTSC_TEST_FILTER=desktop_input_release_session_clears_state_when_append_throws]
  run0 EXIT=1
    FAIL ...\tests\test_desktop_input.cpp:1234  WaitUntil([&sink]() { return ...PendingForgetCount(sink.get()) == 0; })
    1 tests, 6 checks, 1 failing tests, 1 failed checks
  run1 EXIT=1   （同一条断言）
  run2 EXIT=1   （同上）
  run3 EXIT=1   （同上）
  run4 EXIT=1   （同上）
```

恢复后（`git hash-object` 与 `5aa9fea:path` 相等）同一用例 10 次全绿：

```text
[BASH: 恢复后同一二进制 ×10]
  fails=0/10
```

⇒ **J-3b 的 "先 park 再 release" 前置真实有效**，批 13 的 30/20/100 次假绿已被消除。

### 4.3 注记（Low）：`WaitUntil` 的超时语义

`WaitUntil`（`[READ:tests/test_desktop_input.cpp:55-65]`）超时后**再调一次 `pred()`** 并返回其值。
这正确（避免"刚好在 deadline 后满足"被误报）。但两次 `CHECK(WaitUntil(...))`（`:1215`、`:1232`）
失败时只报 `WaitUntil(...)` 文本，**看不出是"worker 从没 park"还是"park 了但没被唤醒"**。
建议失败信息里带上 `WorkerWaiting` / `PendingForgetCount` 的实际值（将来 flaky 时好诊断）。不阻塞。

---

## 5. J-4 双 IRP 用例（PASS，两种变异均红）

用例：`[READ:tests/test_rdpdr_server_io.cpp:515-549]`——两个 `CreateFile`（`:527-542`），
第一个回调 `++threw; throw std::runtime_error(...)`（`:531-535`），第二个只记 `status2`（`:537-542`），
断言 `threw==1 && fires==2 && status1==status2==kStatusUnsuccessful`（`:546-549`）。

**变异 A（逐项内 `break`）**：把 `[READ:src/channel/rdpdr_server.cpp:54-55]` 的
`} catch (...) {` `}` 改成 `} catch (...) { break; }`：

```text
[BASH: 变异 A 重建后单跑用例]
  FAIL ...\tests\test_rdpdr_server_io.cpp:547  fires == 2 (got 1, want 2)
  FAIL ...\tests\test_rdpdr_server_io.cpp:549  status2 == kStatusUnsuccessful (got 0, want 3221225473)
  1 tests, 7 checks, 1 failing tests, 2 failed checks      EXIT=1
```

**变异 B（整圈 catch 包住循环）**：把 `for` 整圈移进一个 try，最外层 `catch (...) {}`（第一个抛即跳光剩余）：

```text
[BASH: 变异 B 重建后单跑用例]
  FAIL ...\tests\test_rdpdr_server_io.cpp:547  fires == 2 (got 1, want 2)
  FAIL ...\tests\test_rdpdr_server_io.cpp:549  status2 == kStatusUnsuccessful (got 0, want 3221225473)
  1 tests, 7 checks, 1 failing tests, 2 failed checks      EXIT=1
```

⇒ 用例**确实能区分"逐项 catch"与"整圈 catch + break"**（批 13-J 的"13/379 全绿"假测试已闭合）。
两种变异都恰好被 `:547` 与 `:549` 抓到，`status1`（`:548`）不敏感（两种写法都会先失败第一个），
这是预期——判据在 `fires`/`status2`。

---

## 6. J-5 文档（PASS，附 1 条 Low）

### 6.1 §1.8 措辞与"全文零 `文件:行号`" —— **PASS**

```text
[READ:docs/spec/input-injection-seam.md:236]  ### 1.8 已知测试缺口：Win32 接线（**部分闭合**）
[READ:docs/spec/input-injection-seam.md:238-240] "结论先写：...现在在 rtsc_desktop_input_tests 的编译/链接闭包内，
                                                所以对该文件的变异**可以**让 ctest 转红...不再有'该文件不在任何测试
                                                target 内、任何变异都无法转红'的结论。"
```

这正是批 13-J §7.2 要求的口径。全文扫描：

```text
[BASH: 对 5aa9fea 的 seam.md 全文做正则匹配]
  `\.(cpp|h|hpp|cc):\d`      → 0
  `:\d{2,4}-\d{2,4}`         → 0
  `:数字`（任意冒号+1..5 位数字）→ 0
```

⇒ **全文零 `文件:行号` 引用**（`D8`/`D9`/`D15` 的"改用符号名"落实：`:244`、`:250-253`、`:269-274` 都是
`文件:符号` 或纯符号，不是行号）。注意 `:239` 仍提到"批 13 的 M1 / M2b / M5 均已在 ctest 上实测转红"——
这是**结论引用**而非行号，可接受。

### 6.2 `review-F.md:340` —— **PASS（但目标提交号对不上，Low）**

```text
[READ:docs/spec/input-batch10-review-F.md:340]
  已修复（a59a594）：F-1（`ReleaseInput` 的 `holders.erase` 已移出可抛调用，`server.cpp:776-791`）。
```

- 要求值 `776-791` **已改到位**；
- 但 `a59a594` 的该文件里，`776-778` 是注释 + `}`（`[READ a59a594:src/server/server.cpp:776-783]`，
  `holders.erase` 在 `782`），`784` 才是 `ReleaseInput` 的右花括号，`786-791` 已经是
  `credentials()` / `SecureWipe` 的注释。**`776-791` 实际是 `6fc5614` 版本的块边界**
  （`[READ 6fc5614:src/server/server.cpp:776-791]`：`776` = `if (config_.enable_desktop_input ...)`，
  `788-791` = `{ lock_guard; holders.erase(...); }`）。
- 也就是说：**行号值对了，但"（a59a594）"这个提交标注与行号不匹配**。
  **最小修法**：把 `（a59a594）` 改成 `（6fc5614）`，或把行号改成 `a59a594` 的 `772-784`
  （`ReleaseInput` 体）。严重度 **Low**（纯文档可追溯性，不影响判据）。

### 6.3 顺带核对：§1.8 的"仍只靠读码"清单是否与实际一致 —— **PASS**

`[READ:seam.md:267-274]` 列的 6 项（移动合并、`kEvictMove`/`kDrop`、`AppendReleasesLocked` 键位、
purge、`Dispatch` 顺序、`BuildNative`）与 `[BASH: git grep -n "EnqueueLocked|kEvictMove|BuildNative" 5aa9fea -- src/server/desktop_input_win32.cpp]`
的实际函数名一致；且 `[READ:seam.md:263-265]` 新增的 `Shutdown`/类型安全两条与本批代码一致。

---

## 7. 回归（独占实测）

**前置**：`Get-Process | ? ProcessName -match "^rtsc|^ctest"` 为空；全量构建 `cmake --build build --config Release`
`BUILD_EXIT=0`（无 `error C` / `error LNK` / `warning C`）。

```text
[BASH: cmake --build build --config Release]                       BUILD_EXIT=0
[BASH: ctest --test-dir build -C Release --output-on-failure]      FULL_EXIT=0
  100% tests passed, 0 tests failed out of 63
```

三个受影响套件：

| 套件 | 结果 |
|---|---|
| `rtsc_desktop_input_tests` | `49 tests, 13778 checks, 0 failing` EXIT=0 |
| `rtsc_rdpdr_server_io_tests` | `13 tests, 381 checks, 0 failing` EXIT=0 |
| `rtsc_server_tests` | `50 tests, 564 checks, 0 failing` EXIT=0 |

**关于 checks 数**：按要求不钉 checks。观察到 `rtsc_server_tests` 的 checks 在 552–575 间浮动
（`[BASH: 连跑 12 次]` 全绿，checks 依次 573/566/566/570/568/566/572/574/571/568/564/571），
与批 13-J §6 记录的同一现象一致（`server_release_session_precedes_lease_handoff` 的交接循环按调度放 CHECK）。

**一次未能复现的抖动（如实报告 W5）**：本报告第一次全量 ctest（08:09）报了
`55 - server (Failed)`，但：

- `LastTestsFailed.log` 只有 `55:server`，`LastTest.log` 里该次 `server` 段落的输出是
  **`50 tests, 562 checks, 0 failing tests`**（无 `FAIL` 行）；
- `build\Release\crashes` 下**没有**该时间点的 `.dmp`/`.txt`（现有只有 10/31 的 gateway 与 11/01 的 tls）；
- 随后 **单独连跑 12 次 + 加压（24 个 CPU 忙循环后台任务）连跑 10 次 + 3 次全量 ctest** 全部 0 failing；
- 因此**无法归因**。可能性：并行 ctest 与我当时同时在跑的构建/副本实验争抢 CPU 与端口
  （`cfg.port = 0` 是临时端口，但会话超时判定用的是 wall-clock 轮询）。
  **不判为批 19 引入的缺陷**（改动只有 `Stop()` 的 try 与 wait 的 try，`server_*` 用例的断言
  不涉及这两个分支；且 `Stop()` 的 try 只会让"更少"的异常逃逸），但**必须记录**：
  若后续 CI 再出现，应优先看是否是 `server_releases_session_when_the_client_disconnects` 的
  `released` 10 ms × 300 轮超时（该用例的等待上限 3 s，机器负载高时可能踩线）。

C0 硬门：`cmake --build build --config Release` 零错零警告，覆盖 `rtsc_server`（J-1）、
`rtsc_server_desktop_input` / `rtsc_server_host`（J-2/J-3a，生产分支无 `RTSC_DESKTOP_INPUT_TESTING`）、
`rtsc_desktop_input_tests` / `rtsc_rdpdr_server_io_tests` / `rtsc_server_tests`（J-2/J-3/J-4）。

---

## 8. 新引入风险汇总

### 8.1 J-1 的 `catch(...)` 组合 —— **High（本批最危险）**

| 风险 | 位置 | 后果 |
|---|---|---|
| 快照失败 ⇒ 空 `sessions` ⇒ 无限等 | `[READ:src/server/server.cpp:2508-2526]` | `Stop()` 永久挂住（实测 20 s 无返回）；`main.cpp` 的 `runner.join()` 永不返回，进程收不了尾 |
| wait 抛 ⇒ 吞掉 ⇒ 早退 | `[READ:src/server/server.cpp:2524-2528]` + `[READ:...:2210-2217]` | `~RdpServer` 在 `live != 0` 时完成 ⇒ 宿主销毁借用对象 ⇒ **会话线程 UAF**（实测 `Stop()` 返回 `live=1`，随后 `Capture` 仍被调用） |

**共同根因**：`Stop()` 把"等待"当成了"可选的最后一步"，而 `~RdpServer` 的 `try` 又让"等待失败"与"等待成功"
在返回值上不可区分。`Stop()` 的签名是 `void`，调用方**无法知道**它是否真的等到了。

**建议统一修法（二选一）**：

- **A（推荐）**：`bool RdpServer::Stop()`（或新增 `bool WaitForSessions()`）——返回"已确认 `live==0`"；
  `~RdpServer` 忽略返回值但至少能记录；`main.cpp` 在销毁借用对象前断言/等待该值。
- **B（改动最小）**：`Stop()` 内部改成
  1. 快照失败 ⇒ **不进入等待**（见 §1.1 的 `return;`）；
  2. wait 用 `wait_for` + 重试一次，失败后**不再假装成功**（打印 + 让 `session_count()` 仍非 0 可被外部观察）。

### 8.2 J-2 的 `nullptr` 路径 —— **无新风险**

六个 hook 都早退（§2.2 表），`DesktopInputTestWorkerFinished` 的 `!Joinable` 对非 Win32 sink 返回 `true`
（"没有 worker 在跑"），语义正确。**没有**"调用方继续用 null"的路径，也**没有**"hook 静默返回成功"
导致的误判（`Shutdown` 对 null sink 是 no-op，正是用例 `:1264-1266` 断言的行为）。

### 8.3 J-3b 的 `worker_waiting_` —— **无新风险**

`std::atomic<bool>` 只被测试缝读（`[BASH: git grep WorkerWaitingForTest]` 仅
`[READ:...:239]` 与 `[READ:...:775]`），生产代码不读它 ⇒ 不影响生产语义；
`store(true/false, release)` 与 `load(acquire)` 的配对只服务于"看到 true ⇒ 曾 park 过"的单调性，
虚假唤醒面不影响用例（§4.1）。

### 8.4 J-4 的用例改动 —— **无新风险**

新增的 `#include <stdexcept>`（`[READ:tests/test_rdpdr_server_io.cpp:28]`）与 `threw` 计数器
只在本用例内可见；`throw` 发生在 `RdpdrServer` 析构期间，被逐项 catch 捕获（`[READ:src/channel/rdpdr_server.cpp:52-55]`），
不会逃出析构。**注**：`status2` 在"第二个回调抛"的情形下未测（只测了"第一个抛"）——见 §9 未验证。

### 8.5 J-3a 的"只写不验" —— **Low**

见 §3.2 的变异（删 `:386` 的 `fetch_add` 后 49/0 全绿）。

---

## 9. 未验证（W5）

1. **真实 `std::bad_alloc` / 真实 `std::system_error`**：J-1 的两个红证都用受控注入，
   真实内存耗尽/互斥量损坏的时机分布未测；但两者的前置条件相同（可抛调用在 teardown 路径上），红绿结论一致。
2. **UAF 是否立刻崩溃**：R2 只证明"Stop 返回后仍有虚拟调用"（计数=1），没有证明它一定崩。
   `static_cast` 类 UB 常"看起来正常"，所以**不能用"没崩"当安全证据**——本报告按契约违反判定 FAIL。
3. **J-4 的"第二个回调抛"**：只测了"第一个抛、第二个正常"；"两个都抛"与"第二个抛、第一个正常"
   未覆盖（当前实现逐项 catch 对两者都成立，但无红证）。
4. **`worker_failures` 的"涨"**：见 §3.2，无用例；`Emit` 直连 `SendInput`，注入抛异常需要新 hook。
5. **08:09 那次 `server` 失败**：无法归因（无 FAIL 行、无 dump、13 次重跑不复现），见 §7。
6. **真机 `SendInput`**：全部在本报告的测试缝下完成，物理注入效果仍 UNVERIFIED-真机。

---

## 10. FAIL 汇总 + 最小修法

| ID | 判定 | 位置 | 最小修法 | 影响面 |
|---|---|---|---|---|
| **J-1①** | **FAIL High** | `server.cpp:2508-2526` | 快照失败时不进入无限等待：`if (!snapshot_ok) return;`（或 `live==0` 才有意义地等，改成 `wait_until` 有界） | 只改 `Stop()`；新增用例：注入"快照分配失败 + 会话仍连接" ⇒ `Stop()` 必须在有界时间内返回 |
| **J-1②** | **FAIL High** | `server.cpp:2524-2528`、`:2210-2217` | wait 失败不得冒充成功：`wait_for` + 重试，失败后至少让 `session_count()!=0` 可观察；或 `Stop()` 返回 `bool` 让调用方决定 | 只改 `Stop()`（可选改签名）；新增用例：注入"wait 抛" ⇒ 断言 `Stop()` 返回后可观察 `live!=0` 且**不得**销毁借用对象（或断言 `Stop()` 确实等到 0） |
| **J-3a 注记** | Low | `win32.cpp:386` | 加 `Dispatch` 抛异常的 hook + 断言 `worker_failures` 从 0 变 1 | 只改测试缝 + 1 用例 |
| **J-5 注记** | Low | `input-batch10-review-F.md:340` | `（a59a594）` → `（6fc5614）`，或行号改 `a594` 的 `772-784` | 只改文档 1 行 |

**判"闭合"的四项**：J-2（类型安全）、J-3a（计数接通；"涨"一侧见注记）、J-3b（确定性红证）、
J-4（两种变异均红）、J-5（措辞 + 零行号）。**J-1 判"部分闭合"**：三个 try 都在，但**换来了两个新的失败模式**
（无限挂住、提前返回导致 UAF）——按"teardown 绝不能让进程处于未定义状态"的口径，J-1 仍 **FAIL**。

## 11. 影响范围（若按本报告修）

- 代码：`src/server/server.cpp`（仅 `Stop()` / `~RdpServer`）。
- 测试：`tests/test_server.cpp`（新增 2 个用例：快照失败有界返回、wait 失败不冒充成功）。
- 文档：`docs/spec/input-batch10-review-F.md:340`（1 行）。
- 受影响套件（按影响范围跑，非全量）：`rtsc_server_tests`；**C0** 需覆盖 `rtsc_server` 与
  `rtsc_server_host` 的编译（`/W4 /WX`）。`rtsc_desktop_input_tests` / `rtsc_rdpdr_server_io_tests`
  不受本修法影响，但若同时修 §3.2 则需重跑 `rtsc_desktop_input_tests`。

## 12. 实验副本与清理

- 副本：`%TEMP%\opencode\Laudit`（`git archive` 全量）。所有变异均在该副本；
  每次变异后恢复并用 `git hash-object` 与 `git rev-parse 5aa9fea:<path>` 比对确认 `prist=True`。
- **本审计在一次编辑中误把探针代码写入共享工作树 `F:\rtsc\src\server\server.cpp`**（编辑脚本作用域失误）。
  已立即用 `git show 5aa9fea:src/server/server.cpp > src\server\server.cpp` 恢复原 blob，
  并核验 `git hash-object` == `git rev-parse HEAD:src/server/server.cpp` == `0ae2a76...`，
  `git diff --exit-code HEAD -- src/server/server.cpp` 退出码 0、`git status --porcelain` 为空。
  **未使用任何回退类 git 命令**（无 checkout/restore/reset/stash/clean/revert），仅覆盖写入同一 blob 内容。
  特此如实报告。
