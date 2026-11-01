# 批 12 审计 H：teardown 的异常安全性（F-1 闭合复核 + 同型排查）

- 对象：提交 `a59a594`（父 `b6fcaac`，`git show --stat` 5 文件 / +552 −4）
- 审计角色：只读审计（除本文件外未改任何文件）
- 环境：Windows / MSVC（CMake 生成器 `Visual Studio 17 2022`），`/W4 /WX /permissive-`，`/EHsc`（`build/rtsc_server.vcxproj`：`<ExceptionHandling>Sync</ExceptionHandling>`）
- 证据约定：文中的 `path:line` 均为本机 `[READ:path:line]` 读取结果；命令输出以 fenced block 原样粘贴（`[BASH:...]`）。

## 0. 结论（一句话）

F-1 的**行为缺陷已闭合**（`holders.erase` 在 `ReleaseSession` 抛异常时仍执行，且顺序仍是"先 sink 后放槽"），变异可红可绿；
但 `catch (...)` **完全静默**（无计数、无日志），且委托实现（Win32 sink）里仍有 **3 处同型残留**（`ReleaseSession` / `Shutdown` / `WorkerMain`），服务端 `RdpServer::Stop()` 与两个通道析构也有 3 处低危同型点。F-1 建议判"行为闭合、可观测性未闭合（低）"。

## 1. F-1 修复逐项（`src/server/server.cpp:762-784`）

修复后的实现（HEAD）：

```cpp
762  void ReleaseInput() {
763      if (input_released_) return;
764      input_released_ = true;
765      if (!input_lease_held_) return;
766      input_lease_held_ = false;
...
772      if (config_.enable_desktop_input && input_sink_ != nullptr) {
773          try {
774              input_sink_->ReleaseSession(input_session_id_);
775          } catch (...) {
776              // Teardown must still free the slot below: the flags above are
777              // already set, so a skipped erase would leak it permanently.
778          }
779      }
780      {
781          std::lock_guard<std::mutex> lock(input_lease_->mu);
782          input_lease_->holders.erase(input_session_id_);
783      }
784  }
```

`[READ:src/server/server.cpp:762-784]`、`[READ:src/server/server.cpp:651-660]`（`InputLease`）、`[READ:src/server/server.cpp:835-861]`（`AcquireInputLease`：唯一 `holders.insert` 点，`:846`）。

### ① `holders.erase` 在所有路径都执行 —— **PASS**

逐条路径枚举（`holders` 只可能由 `AcquireInputLease` 在 `:846` 插入）：

| 路径 | 行为 | 是否执行 erase |
|---|---|---|
| `input_released_` 已 true（`:763`） | 直接 return | 已释放过，无需再擦（幂等） |
| 从未持租（`:765`） | return | 未插入过，无需擦 |
| `sink == null` 或注入关闭（`:772` 为假） | 跳过 sink | **是**（`:780-783`） |
| `ReleaseSession` 正常返回 | — | **是** |
| `ReleaseSession` 抛 `bad_alloc`/任意异常 | catch 落空后继续 | **是**（`try` 在 `:773-779` 内结束，erase 在 `:780`） |
| `holders.erase` 本身 | `std::set<uint32_t>::erase(key)` + `std::less<uint32_t>` | 无分配、无比较器抛点（实际 no-throw） |

补充：`lock_guard` 构造（`:781`）理论上可抛 `std::system_error`，但那是"互斥量误用"级错误，且本仓在 `server.cpp:2328-2335` 专门为同一风险写了兜底——这里是**仓库内不一致**（见 §2.2 S-7），非可达缺陷。

### ② 顺序仍是"先 sink 后放槽"（F3 不回退） —— **PASS（附降级说明）**

`ReleaseSession` 在 `:774`，`holders.erase` 在 `:782`，槽在整个 sink 调用期间仍被占用；`ReleaseOrderingSink` 用例仍在（`tests/test_server.cpp:3788-3861`，检查点 `:3848`）。变异 M2（把 erase 提前到 sink 之前）实测转红：`FAIL tests/test_server.cpp:3848 sink.injects_during_release() == 0 (got 1)`（见 §3）。

**降级说明（不构成 FAIL）**：异常路径下"sink 已排队合成 up"这一前提不再成立（例如 `ReleaseSession` 在 `forget_sessions_.insert` 就抛），此后再放槽，新会话可能先按键。但合成 up 本身已经丢了，键本来就卡住；这是 F 报告建议的修法（catch 后无条件擦）的固有取舍，无法再改进顺序。

### ③ `catch (...)` 是否吞掉了应上报的信息 —— **FAIL（低）**

`:775-778` 的 catch 体只有注释：**没有计数、没有日志、没有 sink 侧失败计数透出**。后果：

- `ReleaseInput` 只调用一次（`input_released_` 在 `:764` 已置 true），失败后**永不重试**；丢失的合成 up 直接变成"本地键/按钮卡住"（`include/rtsc/server/desktop_input.h:75-81` 明说这是用户可见后果）；
- 运维侧没有任何观测点：`RdpServer` 只有 `input_lease_denied_count()`（`server.cpp:2500-2502`），没有 release 失败计数；
- 反向证据：Win32 sink 自己为 `SendInput` 失败实现了"5 s 限流日志"（`desktop_input_win32.cpp:493-511`），teardown 失败却完全静默，标准不一致。

最小修法见 §4.2（在 `InputLease` 加 `release_failures` 共享原子 + 公共访问器，或至少限流 stderr）。

### ④ 两个标志的置位时机是否因异常语义不一致 —— **PASS**

- `input_released_ = true`（`:764`）与 `input_lease_held_ = false`（`:766`）都在可抛调用**之前**，语义是"租约已放弃、teardown 不再重入"，在 catch 路径下依旧成立（erase 随后补上）；
- `input_lease_held_` 只在 `ReleaseInput:766` 清、只在 `AcquireInputLease:854` 置，两个函数都只在会话线程执行；
- `InjectIfLeasable`（`:819-826`）在 `input_lease_held_ == false` 后不会再取租/注入，teardown 后没有"复活"路径；
- 释放后 `input_released_` 永不复位，`ReleaseInput` 二次调用是 no-op，不会重复擦（`holders.erase` 对不存在 key 也是 no-op）。

唯一残余：若 `AcquireInputLease` 内 `input_sink_->SetGeometry`（`:858`）抛异常，槽已插入（`:846`）且 `input_lease_held_` 已 true（`:854`），异常穿到会话线程后被 `body`/`ServeOne` 的 teardown 捕获 → `ReleaseInput` 仍会擦槽，**不泄漏**，判 PASS。

## 2. 同型排查："先置标志/改状态，再执行可抛调用"

搜索面：`src/server/{server,desktop_input_win32,desktop_input_null}.cpp`、`src/channel/*.cpp` 全部析构、`src/net/*.cpp` 全部 `Close()`、`src/audio/*`、`src/ui/*` 析构；`scope guard` 类在本仓**不存在**（`grep ScopedExit|ScopeGuard|scope_exit` 零命中）。

### 2.1 需要修（按优先级）

| ID | 位置 | 同型点 | 后果 | 最小修法 |
|---|---|---|---|---|
| **N-1** | `desktop_input_win32.cpp:150-170` `ReleaseSession` | `forget_sessions_.insert`（`:160`）→ `AppendReleasesLocked`（`:166`，内部 `queue_.push_back` `:249/:256` 可 `bad_alloc`）→ `sessions_.erase`（`:167`）→ `cv_.notify_one`（`:169`） | ① append 抛 → `sessions_.erase` 与 `notify` 都被跳过：会话条目+`pressed` 永久残留；② 更隐蔽：`forget_sessions_` 留着但 worker **永远不会被唤醒**（worker 空队列时 `cv_.wait` 无超时，`:274-280`；`Inject` 对被 forget 的 id 在 `:128-131` 直接 return，**不 notify**）⇒ 同一进程内重启 RdpServer 后 id 从 1 重来（`desktop_input.h:78-80`），新会话 1 的所有输入会被 `:128` 永久丢弃，直到别的会话注入或有待发移动到期唤醒 worker | 先摘状态再补 up，notify 无条件：`try { lock; forget_sessions_.insert(id); it=sessions_.find(id); if(it!=end){ SessionInputState s=std::move(it->second); sessions_.erase(it); try{AppendReleasesLocked(id,s);}catch(...){/*计数*/} } } catch(...){} cv_.notify_one();` |
| **N-2** | `desktop_input_win32.cpp:513-530` `Shutdown` | `stopping_=true`（`:517`）→ `AppendReleasesLocked`（`:519`，可抛）→ `entry.second.pressed = {}`（`:520`，可抛）→ `worker_.join()`（`:524`） | append 抛 → `join` 跳过 → `std::thread` 析构遇 joinable ⇒ `std::terminate`；而 `Shutdown` 由 `~Win32DesktopInputSink`（`:114`）调用，析构里抛出同样 terminate ⇒ **进程被 teardown 杀死** | 把 `:518-521` 整段包 `try{...}catch(...){}`，随后无条件 `sessions_.clear(); cv_.notify_all(); join();`（join 也可再加一层 catch） |
| **N-3** | `desktop_input_win32.cpp:261-291` `WorkerMain` | 无任何异常兜底；`Dispatch:376 pending_moves_[id] = item.input`、`EmitDueMoves:344 last_move_sent_[id] = ...` 都分配内存 | worker 线程里 `bad_alloc` ⇒ 逃出线程函数 ⇒ `std::terminate`；与 N-2 同属"teardown/后台路径把进程杀掉" | 循环体 `try{ EmitDueMoves(); if(item) Dispatch(...); } catch(...){ /*计数; 丢弃该项*/ }`；`ForgetReleasedSessionsLocked`（`:301-322`）本身只做容器 erase/clear + 原子加，**无可抛点，已安全**；但 `:267` 的 drain 调用位于建议的 try 之外，需一并纳入 |

### 2.2 已安全（附理由）

| ID | 位置 | 判定理由 |
|---|---|---|
| S-1 | `server.cpp:2346-2369` 线程 teardown | `Stop`/`ScrubCredentials`/`ReleaseInput` 三步各自 `try/catch`，前一步抛不会跳过后一步；`body` 标 `noexcept` + 内层 catch，异常不出线程 |
| S-2 | `server.cpp:2427-2446` `ServeOne` teardown | 与 S-1 同形逐段隔离；F-1 修复前的最大隐患（跳 `ReleaseInput`）已消除 |
| S-3 | `server.cpp:2310-2340` registry `release` | 注释与实现一致：可抛的 `sessions.erase` 单独包 try，live 计数在锁外 `fetch_sub`，lock 失败还有 fallback（`:2328-2335`）——本仓"标志/计数必须先落地"的正例 |
| S-4 | `server.cpp:752-755` `RdpSession::Stop()` | `stop_requested_` 是"停止请求"不是资源槽，先置后 `transport_->Close()` 正确：Close 抛了请求也已发布；会话侧唯一实现 `WinsockTransport::Close`（`winsock_transport.cpp:64-69`）只调 `::closesocket`，不抛 |
| S-5 | `desktop_input_win32.cpp:301-322` purge | 函数体只有 `map::erase`、`deque::erase`、`atomic::fetch_add`、`set::clear`（`QueuedInput` 平凡可移动），无分配点，实际 no-throw；`!it->synthetic` 保留语义在 `:312` |
| S-6 | `desktop_input_win32.cpp:119-122/172-182` `SetGeometry`/`Stats` | 无 teardown 语义；`SetGeometry` 抛了也只影响本次 Acquire，槽由 teardown 擦（见 1④） |
| S-7 | `server.cpp:780-783` erase 段 | 见 §1① 末段：`set::erase(uint32)` 无抛点；`lock_guard` 失败属不可恢复的程序员错误（与 `:2328` 的防御口径不一致，建议在注释里点名即可） |
| S-8 | `src/net/{winsock,posix}_transport.cpp` 析构 | 析构即 `Close()`，实现只有 `closesocket`/`close(fd)`，无抛点 |
| S-9 | `src/audio/sine_source.cpp:33` `Stop()` | `running_ = false`，无抛点 |
| S-10 | `src/audio/audio_win32.cpp:44-57` `~WaveOutPlayer` | `stopping_.store(true)` 后 `join` + `waveOutClose`/`CloseHandle`，无失败语义；只有互斥量误用级异常，非本类缺陷 |
| S-11 | `src/ui/window_{win32,x11,wayland}.cpp` 析构 | 只调平台 `DestroyWindow`/`XDestroyWindow`/`wl_*` 破坏 API，无 C++ 抛点 |
| S-12 | `cliprdr_server.cpp:67`、`cliprdr_client.cpp:130`、`drdynvc_client.cpp:102`、`rail_client.cpp:55`、`rdpdr_client.cpp:125`、`rdpsnd_client.cpp:23` | 全部 `= default`，无 teardown 逻辑 |
| S-13 | `src/net/gateway_transport.cpp:115-119/420-424/642-648/1323-1328` | 全仓 `= true;` 紧跟 `Close()/Release/erase` 的扫描只多出这 4 处：`closed_ = true` **本身就是终态**（不是待清理的资源槽），随后的 `Close()` 都是自有实现/系统调用，无抛点；`src/client/client.cpp` 只有 `has_input_pending_/has_rtt_` 两个纯数据标志，无 teardown 语义 |

### 2.3 建议修（低，非本批门槛）

| ID | 位置 | 同型点 | 后果 | 最小修法 |
|---|---|---|---|---|
| N-4 | `server.cpp:2449-2479` `RdpServer::Stop` | `listener->Close()`（`:2461`）与 `for(sessions) s->Stop()`（`:2474`）都是**虚接口、未标 noexcept**（`include/rtsc/net/transport.h:66,85`），且 `~RdpServer` 直接调 `Stop()`（`:2192`） | 任一个抛：其余会话收不到 stop 请求、`:2476` 的 `live==0` 等待被跳过；析构路径抛出 ⇒ terminate | `if(listener){try{listener->Close();}catch(...){}}`；循环体 `try{s->Stop();}catch(...){}`（`body:2356` 已有同样防御，这里是缺口） |
| N-5 | `src/channel/rdpsnd_server.cpp:47-49` `~RdpsndServer` | 析构里调**外部注入**的 `source_->Stop()`（`config.audio_source_factory` 产品），无 catch | 嵌入式实现抛异常 ⇒ 析构抛出 ⇒ terminate | `try{ if(source_&&started_) source_->Stop(); }catch(...){}` |
| N-6 | `src/channel/rdpdr_server.cpp:39-52` `~RdpdrServer` | 析构里遍历 `pending` 调外部 `entry.callback(...)`，无 catch；状态已先 move 出来（这部分对） | 回调抛 ⇒ 析构抛出 ⇒ terminate | 每个 callback 包 try/catch（或整个循环包一层） |

> 说明：N-4/N-5/N-6 都不会泄漏"租约槽"这类不可恢复状态，只是"teardown 期间把进程带走/少停会话"，故列低危；N-1/N-2/N-3 与 F-1 同源（状态/资源在可抛调用之后才清理），应优先。

## 3. 测试真实性（变异，先红后绿）

副本：`%TEMP%\opencode\auditH`（`git archive a59a594` 解包），独立 `cmake -G "Visual Studio 17 2022"` 构建 `rtsc_server_tests`（`/W4 /WX`，`BUILD_EXIT=0`）。
用例：`RTSC_TEST(server_release_input_frees_lease_slot_when_release_throws)`（`tests/test_server.cpp:3863-3881`），探针 `RunLeaseHandoffProbe`（`:759-818`），抛异常 sink `ReleaseThrowingSink`（`:679-722`，`:697-703` 先记 release 再 `throw std::bad_alloc()`）。

**基线（未变异）**：`49 tests, 562 checks, 0 failing`；过滤 `server_release` 三用例 `3 tests, 53 checks, 0 failing`。

**M1＝把 `holders.erase` 移回 try 内（F-1 原缺陷）**：

```cpp
// 变异后 ReleaseInput 尾部
try {
    if (config_.enable_desktop_input && input_sink_ != nullptr) {
        input_sink_->ReleaseSession(input_session_id_);   // <-- 抛 bad_alloc
    }
    { std::lock_guard<std::mutex> lock(input_lease_->mu);
      input_lease_->holders.erase(input_session_id_); }   // <-- 被跳过
} catch (...) {}
```

```text
[ RUN  ] server_release_input_frees_lease_slot_when_release_throws
  FAIL ...\auditH\tests\test_server.cpp:3880  handed_off
[ FAIL ] server_release_input_frees_lease_slot_when_release_throws
1 tests, 6 checks, 1 failing tests, 1 failed checks
```

**红证行号 `tests/test_server.cpp:3880`**；同用例的 `:3879 CHECK(released)` 仍为绿，证明 `ReleaseSession` 确实被调用、失败点正是"槽没放"。

**M2＝把 erase 提前到 sink 之前（F3 回退）**：

```text
[ RUN  ] server_release_session_precedes_lease_handoff
  FAIL ...\auditH\tests\test_server.cpp:3848  sink.injects_during_release() == static_cast<size_t>(0) (got 1, want 0)
[ FAIL ] server_release_session_precedes_lease_handoff
1 tests, 12 checks, 1 failing tests, 1 failed checks
```

**恢复原文件后**：

```text
filter: server_release
[  OK  ] server_releases_session_when_the_client_disconnects
[  OK  ] server_release_session_precedes_lease_handoff
[  OK  ] server_release_input_frees_lease_slot_when_release_throws
3 tests, 53 checks, 0 failing tests, 0 failed checks
```

判定：新用例**不是假测试**，M1/M2 都能转红、恢复转绿；F-1 修复与 F3 顺序各有一个独立红证。

**变异注记（W5）**：M1/M2 都是"改坏实现"的变异（第 16 条），不是对测试本身造假；`ReleaseThrowingSink` 的抛点在"记录之后"，比真实 `bad_alloc`（可能一条 up 都没排）更宽松，但两种情形的前置条件（`input_released_=true` 已置）相同，红绿结论一致。

## 4. `catch (...)` 是否过宽 / 是否应加计数

### 4.1 宽度评估 —— **保留 `catch (...)`，宽度本身正确**

- 编译为 `/EHsc`（`<ExceptionHandling>Sync</ExceptionHandling>`），`catch (...)` **不捕获 SEH/AV**，不会掩盖内存破坏；
- 会捕获 `std::logic_error` 等 sink 自身 bug。但 `DesktopInputSink` 是对外扩展点（`include/rtsc/server/desktop_input.h:62-86`，借出指针、任意实现者可抛任意类型），teardown 的正确性不应依赖第三方实现的异常规格；若收窄成 `catch (const std::bad_alloc&)`，一个抛 `std::runtime_error` 的 sink 就会重新把槽漏掉——**不能收窄**；
- 真正的问题是**静默**（§1③），而不是宽度。

### 4.2 最小修法（二选一，建议都做）

A. 计数（与 `denied` 同款，改动最小且可测）：

```cpp
// server.cpp:651-660 InputLease
std::shared_ptr<std::atomic<size_t>> denied;
std::shared_ptr<std::atomic<size_t>> release_failures;   // 新增
// ctor 初始化 make_shared<atomic<size_t>>(0)

// server.cpp:775-778
} catch (...) {
    input_lease_->release_failures->fetch_add(1, std::memory_order_relaxed);
}

// 公共访问器（照 :2500-2502 的形状）
size_t RdpServer::input_release_failure_count() const {
    return impl_->input_lease->release_failures->load(std::memory_order_relaxed);
}
```

B. 限流日志（与 sink 的 `LogFailure` 同款，5 s 一次，`desktop_input_win32.cpp:493-511`）：

```cpp
} catch (...) {
    // 5 s 限流：teardown 的合成 up 丢失 = 本地键可能卡住
    std::fprintf(stderr, "[rtsc-server] desktop input release failed; keys may be stuck\n");
}
```

只做 A 不引入日志也能让测试断言；只做 B 不改 API。两者都做最符合现有风格（server 用计数、sink 用限流日志）。

## 5. 回归（独占运行）

- 增量构建：`cmake --build build --config Release --parallel 8` → `EXIT=0`（C0：`/W4 /WX` 零诊断，无编译器 warning）
- `ctest --test-dir build -C Release --output-on-failure`：

```text
63/63 Test #63: gateway ..........................   Passed    1.31 sec
100% tests passed, 0 tests failed out of 63
Total Test time (real) =  84.81 sec        EXIT=0
```

- `rtsc_server_tests.exe`：连跑 3 次 `49 tests, 0 failing`，**checks 数在 561/562/563 间浮动**（期望值 562）。原因不是新增用例：`server_release_session_precedes_lease_handoff` 在 `tests/test_server.cpp:3852-3856` 的交接循环里放了 `CHECK(SendTestInput(second))`，迭代次数由调度决定，所以 checks 总数天然抖动；**失败数恒为 0**。
- `rtsc_desktop_input_tests.exe`（本提交同时改了该套件）：`41 tests, 13713 checks, 0 failing`。

## 6. 文档漂移（跨审计提示，供审计 I 复核）

1. `docs/spec/input-batch10-review-F.md:340` 在 `a59a594` 中仍写 **"未修复：F-1（`server.cpp` 未改）"**，与同提交的 `server.cpp:773-778` 直接矛盾；该文 `:249` 的缺陷行与 §2.4（`:147-198`）的代码引用仍是修复前 `762-778` 的口径。建议把 §3/§6 改成"F-1 已由 a59a594 闭合（行为），余留观测性（见批 12-H）"。
2. `docs/spec/input-injection-seam.md:137` 的两处行号 **已漂移**：`desktop_input_win32.cpp:232-254` 实际为 **236-258**（`AppendReleasesLocked`），`:307-315` 实际为 **311-319**（purge，`!it->synthetic` 在 **312**）。该文件自 `b6fcaac` 起未改，属存量漂移（`git show b6fcaac:...` 同为 236/312）。
3. `seam.md` §1.8 的行号（`:197-203`、`:204-209`、`:221-228`、`:236-258`、`:301-322`、`:368-384`、`:388-476`）与 `CMakeLists.txt:676-682/691/704/608-609` 经核对**全部准确**；与本次 `server.cpp:762-784`、`win32.cpp:301-322` 无冲突。

## 7. 未验证（W5）

- N-1 的"worker 永不唤醒 ⇒ 重启后 id 复用全拒"是读码推演（`Inject:128-131` 早退不 notify + `WorkerMain:274-280` 无超时），**未**构造真实 `bad_alloc` + 重启的端到端复现；
- M1/M2 用手工变异验证，未做随机化调度压测；新用例在 2 s 内完成交接，慢机上余量未测（`WaitUntil` 5 s / 循环 200×10 ms）；
- `ReleaseInput` 中 `lock_guard` 抛 `system_error` 的路径未测（列为不可达/程序员错误）；
- 真实 `bad_alloc` 在 teardown 的出现率未做内存压力注入（与 F 报告 §7 同口径）。

## 8. 影响范围（若按本报告修）

- 代码：`src/server/desktop_input_win32.cpp`（N-1/N-2/N-3，优先）；`src/server/server.cpp`（§4.2 计数/日志，可选 N-4）；`src/channel/rdpsnd_server.cpp`/`rdpdr_server.cpp`（N-5/N-6，低）。
- 测试：N-1/N-2/N-3 位于 Win32 接线，**不在任何 ctest target 的编译闭包**（`CMakeLists.txt:676-688` 只编 null sink；`rtsc_server_desktop_input` 只被 host 链接 `:691/:704`），修了也无法被 ctest 钉住——必须按 F-2 的测试缝（或注入 `SendInput` 函数指针）才可回归；server 侧计数（§4.2）可直接在 `rtsc_server_tests` 断言。
- 受影响套件：`rtsc_server_tests`（ReleaseInput 路径）、`rtsc_desktop_input_tests`（若动 `desktop_input_map` 无关，可不跑）、`rtsc_server_desktop_input` 编译（C0 不可豁免）。按影响面跑 `server` + 编译门即可，不需要全量。
