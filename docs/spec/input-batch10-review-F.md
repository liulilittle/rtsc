# 输入注入批 10 审计 F：队列 / 记账 / 生命周期侧（D-A/DB/DC + E2/E3/E4/E8）

- 对象提交：`63e3cc6`（父 `e6f57fd`）。
- 只读：本会话在仓库内唯一写入是本文件（工作树中 `seam.md`/`desktop_input.h`/`desktop_input_win32.cpp`/`tests/test_desktop_input.cpp` 的改动来自并发执行代理，非本审计；见 §6）。
- 红证环境：`%TEMP%\opencode\auditF\`。`git archive 63e3cc6` 纯净副本 `clean/`，每个变异各一份副本（`mutM1`..`mutM8`、`mutC`），`restored/` 为重新解包的原样副本。
- 编译：MSVC 19.44，`/std:c++20 /EHsc /W4 /WX /utf-8`；Win32 后端另跑 `/c /permissive- /W4 /WX`。
- 方法：①读码；②**用被审代码本体**（真实 `desktop_input_map.cpp`、真实 `desktop_input_win32.cpp`，仅把 `SendInput` 换成记录器，`#define SendInput ProbeSendInput`）写探针，验证队列/生命周期/记账的真实行为；③变异红/绿；④与审计 G（`docs/spec/input-batch10-review-G.md`）交叉质证。

基线（纯净副本）：

```
[BASH: restored.exe]  40 tests, 9602 checks, 0 failing tests, 0 failed checks   exit=0
[BASH: buildsrv\rtsc_server_tests.exe]  48 tests, 556 checks, 0 failing tests, 0 failed checks exit=0
[BASH: cl /c /W4 /WX /permissive- desktop_input_win32.cpp]  exit=0（零错误零警告）
```

> 工作树现状（非本审计对象，仅记录）：`git status` 显示 `docs/spec/input-injection-seam.md`、`include/rtsc/server/desktop_input.h`、`src/server/desktop_input_win32.cpp`（E7-a/b/c/d）以及随后的 `tests/test_desktop_input.cpp`（E1-T）已被并发代理改动。本报告全部判定针对 `63e3cc6`；§6 另行复核了工作树补丁。

## 进展清单

- [x] D-C 纯函数化：`AdmitAndTrack` 顺序、单一 `TrackInput`、平台层残留逻辑清单
- [x] E2：被限流 press 不入 `pressed`；held up 拒绝不改状态（纯函数 + 真实 sink 双证）
- [x] E3：`forget_sessions_` 生命周期、purge/synthetic、待发移动
- [x] E4：`ServeOne` 三段 try/catch 与 `ReleaseInput` 幂等/异常安全（**发现租约槽泄漏，红证**）
- [x] E8：M1/M2/M3/M4 逐条转红、恢复转绿；另测 M5/M6/M7/M8
- [x] 回归：`Dispatch` 不再限流；合成 up 上界公式
- [x] 与 G 的 6 点交叉质证（§5）
- [x] relay parent

## 1. 结论总表

| # | 要点 | 判定 | 一句话依据 |
|---|---|---|---|
| 1 | D-C 纯函数化（`AdmitAndTrack`） | **PASS**（附覆盖缺口） | `map.h:226-237` 闸先于记账；`win32.cpp:211-215` 唯一接线；桩内无 `TrackInput`（`grep` 只有注释命中） |
| 1b | 平台层残留判定 | **FAIL（低，覆盖）** | 合成 up / purge / 待发移动全在 `win32.cpp`，而该文件**不在任何测试 target**（`CMakeLists:676-682,691,704`）；M6/M7/M8 全绿存活，探针证明三者都是真 bug |
| 2 | E2 记账修正 | **PASS** | 真实 sink：限流拒绝的 0x1F 按下 `downs=0 ups=0`；held up 不花令牌且清键；拒绝不改 `pressed`（`tests:571-582`，M5 转红） |
| 3 | E3 生命周期 | **PASS**（2 条低危保留） | `forget_sessions_` 每轮 worker 清空（`win32.cpp:263,317`），不永久增长；purge 保留 synthetic、清 `pending_moves_`/`last_move_sent_`/桶（`:297-318`）；probe_sink3 证待发移动被丢弃。保留：purge 计入 `dropped_queue_full`；forget 窗口过后迟到的 `Inject` 会复活会话（**红证**） |
| 4 | E4 teardown | **FAIL（低）** | 三段 try/catch 与 `ReleaseInput` 幂等成立；但 `ReleaseSession` 抛异常时 `holders.erase`（`server.cpp:775-778`）被跳过且 `input_released_` 已置真 ⇒ **租约槽永久泄漏**（红证：`second_injects=0` vs 对照 `1`） |
| 5 | E8 变异真实性 | **PASS** | M1/M2/M3/M4 逐个转红并给出测试名+行号，restored 转绿；额外 M5 也转红 |
| 6 | 回归风险 | **PASS** | `Dispatch`（`win32.cpp:364-381`）无 `Allow`；合成 up 上界 = 每次 `ReleaseSession` ≤515、队列峰 ≤ `hard + 515·K` |

## 2. 逐项

### 2.1 要点 1：D-C 纯函数化 — PASS（行为）/ FAIL（低，覆盖）

**结构**：`include/rtsc/server/desktop_input_map.h:204-211` 定义 `AdmitOutcome{action, held_release, rate_limited}`；`:226-237` `AdmitAndTrack`：

```cpp
outcome.held_release = IsHeldRelease(input, pressed);   // 230
if (!rate_gate(outcome.held_release)) { ... return; }   // 231-234
outcome.action = AdmitInput(state, pressed, input, outcome.held_release); // 235
```

接线：`src/server/desktop_input_win32.cpp:211-215` 唯一的 `AdmitAndTrack(...)`，`rate_gate` 是 `rate_limiter_.Allow(session_id, held_release, now)`。

**追问 1：限流闸是否所有路径都先于记账？** 是。

| 路径 | 位置 | 闸→记账 |
|---|---|---|
| 合并移动快路径 | `win32.cpp:193-199` | 只调 `Allow`（`:196`），**不记账**（移动从不 `TrackInput`）⇒ 无顺序问题 |
| 一般路径 | `win32.cpp:211-216` | `AdmitAndTrack` 内闸先于 `AdmitInput`；`outcome.rate_limited` 直接 `return false`（`:216`），先于 `push_back`（`:228`） |
| 合成 up | `win32.cpp:232-254` | 有意绕过闸与队列策略；此时状态正在被丢弃，不需要记账 |

**追问 2：`EnqueueLocked` 是否还有第二处 `TrackInput`？** 没有。`grep TrackInput src/server/desktop_input_win32.cpp` 只命中注释（`:138`），生产代码唯一的 `TrackInput` 在 `map.cpp:170`（`AdmitInput` 内）。第二处**闸**确有一处（`:196` 合并移动），但它不记账，且 `held_release=false` 对移动恒正确。

**追问 3：平台层仍有哪些关键判定未被纯函数覆盖？**

| 仍在 `win32.cpp` 的判定 | 位置 | 风险 | 覆盖 |
|---|---|---|---|
| 合并移动（队尾同会话 move） | `:193-199` | 只覆盖"不增长"，若未来改成跨会话合并会破坏 FIFO | 无测试 |
| 驱逐受害者 `oldest_move` 的选择 | `:200-205` | 迭代器在 `AdmitAndTrack` 前取得；当前无队列变更故安全，未来若是"边判边改"即成悬垂 | 无测试 |
| `kEvictMove`/`kDrop` 计数与 `erase` | `:218-224` | 计数语义（计被驱逐的旧移动）易回归 | 无测试 |
| 合成 up 追加（无上限 `push_back`） | `:232-254` | 绕过 `DecideEnqueue`，是峰值超 1539 的唯一来源 | 无测试（M7 存活） |
| forget 清理（桶/移动/非合成积压） | `:297-318` | 漏一项即"断开后仍动指针"或"桶泄漏" | 无测试（M8 存活） |
| `Dispatch` 先 flush 移动再发键 | `:379-380` | 顺序错则点击落点错 | 无测试 |
| `BuildNative`（0xE0/UNICODE/按钮号） | `:384-472` | 平台语义 | 无测试 |

**为什么"无测试"是硬事实**：`CMakeLists.txt:676-682` 的 `rtsc_desktop_input_tests` 只编 `tests/test_desktop_input.cpp` + `desktop_input_null.cpp`，链接 `rtsc_server_desktop_input_map`；`desktop_input_win32.cpp` 只进 `rtsc_server_desktop_input`（`:691`），后者只被 `rtsc_server_host` 链接（`:703-704`）；`rtsc_server_tests` 链接 `rtsc_server`（`:608-609`），闭包内无该库。⇒ **对 `win32.cpp` 的任何变异都不可能让测试转红**。

实测（M6/M7/M8 都是合法可编译的 `/W4 /WX` 代码，测试全绿，探针全红）：

```
[BASH: mutM6.exe] 40 tests, 9602 checks, 0 failing   <-- 存活
[BASH: mutM7.exe] 40 tests, 9602 checks, 0 failing   <-- 存活
[BASH: mutM8.exe] 40 tests, 9602 checks, 0 failing   <-- 存活
```

判定：**D-C 本身 PASS**（判定逻辑确实移入纯函数、顺序正确、单一接线）；**覆盖缺口 FAIL（低）**：`D-C` 只把"决策"变可测，`EnqueueLocked`/`ForgetReleasedSessionsLocked`/`Dispatch` 的执行仍零覆盖，且我实测这三个变异都是真缺陷（§2.5）。

### 2.2 要点 2：E2 记账修正 — PASS

纯函数层：

- 被限流 press 不入 `pressed`：`AdmitAndTrack` 在 `rate_gate` 拒绝时直接返回（`map.h:231-234`），`AdmitInput` 未调用 ⇒ 无 `TrackInput`。测试 `tests:546-569` 钉住；我的 M5（把闸挪到 `AdmitInput` 之后）使该用例转红（`tests:556,558,567-569,582`）。
- 被限流的 up 不改状态：`tests:571-582` 用 `deny` 闸断言 `held.keys.size()==1`；M5 使其在 `:582` 转红（got 0）。
- 注：真实限流器对 held release 恒放行（`map.cpp:195`），所以"被限流的 held up"只可能来自自定义闸/未来闸；契约由上述用例钉住。

真实 sink 层（`SendInput` 打桩，走 `Inject()`→队列→worker 全链路）：

```
[BASH: probe_sink2.exe (63e3cc6)]
burn=802 rate_limited=1
refused 0x1F press: rate_limited=2 (want 2)
held 0x02 up: rate_limited=2 (want unchanged: exempt)
downs(0x1F)=0 (want 0: refused press never injected)
ups(0x1F)=0 (want 0: refused press never tracked)
ups(0x02)=1 (want 1: the held up, teardown must not add one)
ups(0x03)=1 (want 1: still held at teardown)
```

⇒ 被限流的 0x1F 按下既不注入（`downs=0`）也不进 `pressed`（teardown 无 `0x1F` up）；held up 不花令牌（`rate_limited` 不变）且正确清键（teardown 不再补一条）。**PASS**。

（观察，非本批缺陷）记账发生在**入队**（`map.cpp:170`），不是 `SendInput` 成功之后：若 up 的 `SendInput` 失败（`win32.cpp:485`），键已从 `pressed` 移除，teardown 不会再补 up ⇒ 该键可能卡到会话结束之后。与"注入失败不断连"的既有裁决同源，建议另批处理。

### 2.3 要点 3：E3 生命周期 — PASS（2 条低危保留）

**`forget_sessions_` 何时 erase / 是否永久增长**：

- 插入：`ReleaseSession`（`win32.cpp:156`），持 `mu_`；随后 `notify_one`（`:159/:165`）。
- 擦除：`ForgetReleasedSessionsLocked` 末尾 `forget_sessions_.clear()`（`:317`），该函数在 worker **每次循环开头**调用（`:263`），持 `mu_`。
- ⇒ 运行期存活窗口 = "一次 worker 迭代"，集合大小受两次迭代之间的 `ReleaseSession` 次数量级约束，**不会永久增长**。
- 边界：`Shutdown()`（`:509-526`）置 `stopping_` 并 join，之后若再调 `ReleaseSession`，插入的 id 不会被清（无人消费）。这是析构期路径，且 `Shutdown` 本身不 `clear()` 该集合；量级为"关闭后到期的 id 数"，不构成现实泄漏。记为观察。

**purge 语义**（`:297-318`）：清 `pending_moves_`（`:299`）、`last_move_sent_`（`:300`）、限流桶（`:301`）、该会话**非合成**排队项（`:307-315`），保留 `synthetic`。探针：

```
[BASH: probe_sink3.exe (63e3cc6)]  moves_before=1 moves_after=1   // 待发移动在 release 后被丢弃
[BASH: probe_sink3.exe (mutM8)]    moves_before=1 moves_after=2   // 删掉 :299 后指针在 release 后仍动 —— 真 bug，测试不红
```

**synthetic 会被后续 `Inject` 误当普通事件吗**：不会。`synthetic` 只存在于 `QueuedInput`（`:90-97`），只在 `AppendReleasesLocked` 置真（`:245,:252`）；`Inject` 的 `push_back({session_id, input})`（`:228`）恒为 false；全代码唯一的读者是 purge 过滤器（`:308`）。FIFO 与 `mu_` 保证"旧持有者合成 up 先于新持有者按下"（`server.cpp:762-778` 的注释 + `tests/test_server.cpp:3672` F3 用例）。

**保留 (a)：purge 计入 `dropped_queue_full`（`:310`）**。这些动作并未"被队列满拒绝"，而是"会话结束被丢弃"。`desktop_input.h:41-43` 的定义没涵盖该来源 ⇒ 文档漂移（与 G 的 E7-b 同判）。

**保留 (b)：`forget_sessions_` 只是一次性窗口，不是永久屏障**。`win32.cpp:122-124` 的注释声称"已释放的会话不得用迟到事件复活其状态（或限流桶）"——实测在 worker 清空 `forget_sessions_` 之后再 `Inject`，会话被复活并真实注入：

```
[BASH: probe_sink.exe (63e3cc6)]
after press: emitted=1 first=key1Edown injected=1
after release: emitted=2 last=key1Eup injected=2
late inject after drain: emitted_delta=1 last=key1Fdown injected=3 rate_limited=0 queue_full=0
sequence: key1Edown key1Eup key1Fdown key1Fup
```

⇒ 注释/不变式表述过强（仅"worker 排空前"成立）。生产路径不可达（`ReleaseInput` 是会话线程最后一次调用，且 `input_lease_held_` 已置 false ⇒ `InjectIfLeasable` 不再注入），故定级**低（防御性/文档）**。注意不能改用"水位线"修法：`desktop_input.h:76-78` 明说重开服务器时 id 从 1 重来，水位线会误杀新会话；最小修法是修正注释（或保留一个有上限的 `released_ids_`）。

### 2.4 要点 4：E4 — FAIL（低）：`ReleaseInput` 不是异常安全的

**成立的部分**：

- 幂等：`server.cpp:762-764` `if (input_released_) return; input_released_ = true;`。
- 三段 try/catch 都在：`server.cpp:2429-2440`（`Stop` / `ScrubCredentials` / `ReleaseInput`），线程路径 `:2351-2362` 同形。前一步抛异常不会跳过 `ReleaseInput`。

**缺陷**：`ReleaseInput` 自身是"先置标志、再做两步"，第二步抛异常时第三步被跳过：

```cpp
762  void ReleaseInput() {
763      if (input_released_) return;
764      input_released_ = true;
765      if (!input_lease_held_) return;
766      input_lease_held_ = false;
772      if (config_.enable_desktop_input && input_sink_ != nullptr) {
773          input_sink_->ReleaseSession(input_session_id_);   // <-- 可能抛
774      }
775      { std::lock_guard<std::mutex> lock(input_lease_->mu);
776        input_lease_->holders.erase(input_session_id_); }  // <-- 被跳过
```

`ReleaseSession` 可抛：`AppendReleasesLocked` 的 `queue_.push_back`（`win32.cpp:245,252`）/`forget_sessions_.insert`（`:156`）都会在 `bad_alloc` 下抛出。抛了以后 `input_released_` 已为真 ⇒ 不会重试；`holders` 永久保留该 id ⇒ **租约槽泄漏，后续会话全被拒**。

**红证**（`tests/test_server.cpp` 临时追加两个探针用例，副本内；未进仓库）：sink 的 `ReleaseSession` 先记录再 `throw std::bad_alloc()`。

```
[BASH: probe_release_throw_leaks_lease_slot]
  probe(throw): releases=1 denied=101 second_injects=0
  FAIL tests/test_server.cpp:3923  injected > 0
[ FAIL ] probe_release_throw_leaks_lease_slot
[BASH: probe_release_without_throw_frees_lease_slot]
  probe(nothrow): releases=1 denied=1 second_injects=1
[ OK ] probe_release_without_throw_frees_lease_slot
50 tests, 576 checks, 1 failing tests, 1 failed checks
```

对照（不抛）第二个会话 1 次就被放行；抛异常时重试 100 次全部被拒（`denied` 从 1 涨到 101）且从未注入。**这正是 `server.cpp:2417-2421` 新注释宣称要防的泄漏，只是发生在 `ReleaseInput` 内部。**

**最小修法**（保持 F3 的顺序：先 sink 后放槽）：

```cpp
772  if (config_.enable_desktop_input && input_sink_ != nullptr) {
773      try {
774          input_sink_->ReleaseSession(input_session_id_);
775      } catch (...) {
776          // teardown must still free the lease slot
777      }
778  }
```

**建议用例**（先红后绿）：在 `tests/test_server.cpp` 加一个 `ReleaseSession` 抛 `std::bad_alloc` 的 sink，断言断连后第二个会话能取得租约（即上面的对照断言）。现有 `rtsc_server_tests` 48/556/0 全绿也说明该路径零覆盖。

### 2.5 要点 5：E8 变异真实性 — PASS（M1-M4 全红），附 M5-M8

副本结构：`mutM1`..`mutM8` 各自 `git archive 63e3cc6` 后只打一处补丁；`build.bat` 编 `test_desktop_input.cpp + map.cpp + null.cpp + crash_guard.cpp`（`/W4 /WX`，全部 exit=0）。

| 变异 | 补丁 | 结果 | 失败用例（行号） |
|---|---|---|---|
| **M1** track 提前 | `map.cpp:165-170`：`TrackInput` 移到 `DecideEnqueue` 前 | **红** | `desktop_input_queue_dropped_press_is_not_tracked`（`tests:485,488,490`），`1 failing / 3 checks` |
| **M2** 退回 `IsReleaseInput` | `map.cpp:164` `state.incoming_is_held_release = IsReleaseInput(input)` | **红** | `queue_unheld_release_is_dropped_at_hard_limit`（`:354,363`）、`queue_held_release_is_accepted_and_untracked`（`:384`）、`queue_held_button_release_is_exempt`（`:449`）、`queue_unicode_release_is_not_exempt`（`:471`）、`queue_dropped_press_is_not_tracked`（`:490`）、`queue_rate_gate_gets_held_release_flag`（`:532`）、`queue_rate_limited_input_is_not_tracked`（`:569`），`7 failing / 8 checks` |
| **M3** 忽略 extended | `map.cpp:149` `KeyId{input.scancode, false}` | **红** | `desktop_input_queue_extended_identity_is_not_confused`（`:399,411`），`1 failing / 2 checks` |
| **M4** evict 不 track | `map.cpp:170` `if (action == kAccept)` | **红** | `desktop_input_queue_evict_move_still_tracks_press`（`:424,425`），`1 failing / 2 checks` |
| **M5**（追加）闸后置 | `map.h:230-236` 把 `AdmitInput` 放到 `rate_gate` 之前 | **红** | `desktop_input_queue_rate_limited_input_is_not_tracked`（`:556,558,567,568,569,582`），`1 failing / 6 checks` |
| **M6**（追加）sink 闸后置 | `win32.cpp:214` 恒 true，`:216` 后补 `Allow(...,false)` | **存活** `40/9602/0` | 探针红：`ups(0x1F)=1`（幽灵 held）、`ups(0x02)=0`（held up 被限流 ⇒ 物理键卡住） |
| **M7**（追加）purge 连 synthetic 一起删 | `win32.cpp:308` 去掉 `!it->synthetic` | **存活** `40/9602/0` | 探针红：`sequence: key1Edown key1Fdown`（teardown up 全丢） |
| **M8**（追加）forget 不清待发移动 | `win32.cpp:299` 置空 | **存活** `40/9602/0` | 探针红：`moves_after=2`（release 后仍动指针） |

恢复绿（重新解包 `63e3cc6` 构造）：

```
[BASH: restored.exe] 40 tests, 9602 checks, 0 failing tests, 0 failed checks  exit=0
```

**判定**：任务指定的 M1-M4 **全部转红**，`E8` 的"假测试"缺陷已闭合 ⇒ **PASS**。M3 的旧恒真断言（在空 `pressed` 上查 `IsHeldRelease`）已被 `tests:387-412` 用非空集合重写，M3 现在转红，可信。
**但**：M6/M7/M8（`win32.cpp` 层）全绿存活，因为它们根本不在测试闭包内（§2.1）。这与审计 D 的 D-B 同源，属覆盖缺口而非"测试假绿"。

### 2.6 要点 6：回归风险 — PASS

- **`Dispatch` 已完全不调用 `Allow`**：`win32.cpp:364-381`（注释 `:365-368` + move/`FlushSessionMove`/`Emit`），`grep Allow src/server/desktop_input_win32.cpp` 只命中 `:196`（合并移动）与 `:214`（`AdmitAndTrack` 回调）。限流前移后没有遗留的"出队再判"。
- **合成 up 绕过限流有界**：
  - 每次 `ReleaseSession`：≤ `|pressed|` = ≤510 键 + 5 按钮 = **515** 个平台动作（`win32.cpp:239-253`）；
  - 每个会话对"超过硬限的增量"总贡献 ≤515：越限的 held release 每接受一条就 `erase` 一个 `pressed` 项（`map.cpp:170`→`TrackInput`），而合成 up 补发的是"剩下的 `pressed`"——两者共用同一 515 配额；
  - 队列峰值：`peak ≤ kHardQueueLimit + 515·K`，`K` = 同时持租（能进入 `pressed`）的会话数。默认 `max_input_sessions=1` 时 `K=1` ⇒ **1539 成立**；`--input-share`/unlimited/`max_input_sessions≥2` 时才可能更高；
  - 注入速率：合成 up **完全不受限流**，所以一次断连最多瞬时注入 515 个动作；累计上界 = 515 ×（曾持租的会话数），由连接建立速率而非输入速率决定。
  - 探针（真实 `AppendReleasesLocked`，`SendInput` 打桩，把满载积压直接填到 `queue_` 建模）：

```
[BASH: probe_peak.exe]
before: queue=1024 (hard=1024)
after one release: queue=1539
after two releases: queue=2054 (predicted 1024+515*2=2054)
exceeds_doc_peak=1 (doc peak 1024+515=1539)
lemma: before=256 (soft=256, contains_move=1) after=257 size_above_soft_with_move=1
```

  说明：`queue=1024` 的积压是直接填充建模（真实路径可达，D 已用探针测到峰值 1539）；合成 up 的追加与算术是**真实代码路径**。

## 3. 缺陷与最小修法

| ID | 级别 | 位置 | 红证 | 最小修法 |
|---|---|---|---|---|
| **F-1** | **低（正确性）** | `src/server/server.cpp:762-778` | `probe_release_throw_leaks_lease_slot`：`denied=101 second_injects=0`；对照 `denied=1 second_injects=1` | 用 try/catch 包住 `ReleaseSession`，**无条件**执行 `holders.erase`（保持"先 sink 后放槽"顺序）；补一个抛异常 sink 的用例 |
| **F-2** | 低（覆盖） | `desktop_input_win32.cpp` 全文件 | M6/M7/M8 全绿存活，探针证明三者都是真 bug | 把 `QueuedInput` + 入队/驱逐/purge/`Dispatch` 顺序抽成平台中立单元（编进 `rtsc_desktop_input_tests`），`win32.cpp` 只留 `BuildNative`/`Emit`；退一步的最小缝：给 `Emit` 一个可注入的 `SendInput` 函数指针，让测试编译 real sink |
| **F-3** | 低（文档/防御） | `win32.cpp:122-124` 注释 | `probe_sink`：drain 后 `Inject` 仍被注入（`emitted_delta=1`） | 注释限定为"worker 排空 forget 请求之前"；或维护有上限的 `released_ids_`（**不要**用 id 水位线：重开服务器 id 从 1 重来） |
| **F-4** | 低（文档） | `desktop_input.h:41-43` | `win32.cpp:310` purge 计入 `dropped_queue_full` | 定义补"or discarded when their session is released" |
| **F-5** | 低（测试缺口） | `tests/test_desktop_input.cpp` | mutC 存活（`40/9602/0`）；`probe_token`：clean `kept_token_spendable=1` / mutC `=0` | 补"held up 不耗令牌"用例（见 §5-Q1） |

### 交叉：与审计 G 的既有 FAIL 对照

G 的 E7-a/b/c/d 我全部复核成立（§5-Q2/Q5/Q6）；G 未覆盖的 F-1（`ReleaseInput` 异常安全）是本审计新增的**唯一行为性缺陷**。

## 4. 复现方法

1. 副本：`git archive 63e3cc6 | Expand-Archive` 到 `%TEMP%\opencode\auditF\clean`（`restored` 为第二份原样副本）。
2. 测试构建（`build.bat <root> <out>`，先 `call vcvars64.bat`）：
   ```
   cl /nologo /std:c++20 /EHsc /W4 /WX /utf-8 /I<root>\include /I<root>\tests
      /DRTSC_SOURCE_DIR=\"<root 正斜杠>\"
      <root>\tests\test_desktop_input.cpp <root>\src\server\desktop_input_map.cpp
      <root>\src\server\desktop_input_null.cpp <root>\src\util\crash_guard.cpp
      /Fe:<root>\bin\<out>.exe /link dbghelp.lib
   ```
3. 服务端套件（E4 探针）：`cmake -G Ninja -DCMAKE_BUILD_TYPE=Release` + `cmake --build --target rtsc_server_tests`；探针用例临时追加到副本的 `tests/test_server.cpp` 末尾（未进仓库）。
4. sink 探针（`SendInput` 打桩）：`probe_sink.cpp`（合成 up / 迟到 Inject）、`probe_sink2.cpp`（限流 vs held 记账）、`probe_sink3.cpp`（待发移动）、`probe_peak.cpp`（峰值/引理，`#define private public` 仅用于该临时 TU）。
5. 变异：`mutM1`..`mutM8`、`mutC`（`map.h/map.cpp/win32.cpp` 各一处）。

## 5. 交叉定案（审计 F × 审计 G）

### Q1 mutC 是否真存活？——**是，独立复现**

```
[BASH: mutC.exe] 40 tests, 9602 checks, 0 failing tests, 0 failed checks      <-- 存活
[BASH: probe_token.exe (clean)] presses=799 held_ups=100 dropped=1 kept_token_spendable=1 second_extra_press=0
[BASH: probe_token.exe (mutC)]  presses=799 held_ups=100 dropped=2 kept_token_spendable=0 second_extra_press=0
```

根因同 G：`tests:639`/`:671` 只在**空桶**下断言 held up 放行（`:631-635` 先把 800 个令牌花光），空桶扣不扣都放行。更刺眼的是 `tests:626` 的注释直接写 "Releases also consume no token"，而断言无法检出这句话是假的。**同意 E1-T（低）**。
补用例建议（比 G 的更强，同时钉住两个桶）：799 press 花掉会话桶 → 10 万 held up → 断言 `Allow(1,false)` 仍真；再断言"全局只剩 1 令牌时，held up 之后新会话仍能花"（G 的 probe11 行为用例化）。

### Q2 峰值 1539 的完整性——**G 的 E7-a 成立，但公式要改写**

- `AppendReleasesLocked`（`win32.cpp:232-254`）确实无上限 `push_back`，purge 又保留 `synthetic`（`:307-315`）⇒ 1539 不是全局上界。我用真实代码路径给出比读码更强的证据：`queue=1024 → 1539 → 2054`，并同时证伪饱和引理（`256 + 1 = 257 > soft` 且队列内仍有移动）。
- **但 G 的"`≤1539 + 会话数×515`"多算了一份基线**。准确写法：`peak ≤ kHardQueueLimit + 515·K`，`K` = 同时持租（`pressed` 非空）的会话数。理由：越限 held release 每接受一条就擦掉一个 `pressed` 项，合成 up 补发"剩余 `pressed`"——**同一会话对超过硬限的增量总贡献 ≤515**，二者共用同一配额。
- **并且**：默认 `max_input_sessions=1`（租约只有一个持有者）时 `K=1`，`1539` 作为全局上界**仍然成立**；只有 `--input-share`/unlimited/`max_input_sessions≥2` 才被突破。文档改写应带这个条件，而不是无条件否定 1539。
- 工作树补丁（`win32.cpp:23-31`、`seam.md:137-138`）已写出"对端可入队 1539 + 合成 up ≤ 会话数×515"，结论方向对，但建议按上式收紧（避免读者把两个 1539 与 515·N 相加成 `1539+515N` 的重复计数）。

### Q3 final Stats 时点——**同意低危保留，但两条路径都要说明**

- `--once`：`main.cpp:640` 在 `server.Stop()`（`:642`）**之前**取数；`ServeOne` 已跑完 `ReleaseInput`（`server.cpp:2437-2440`），合成 up 已入队而 worker 可能未发 ⇒ 少计 ≤515。
- 常规：`main.cpp:719-721` 在 `Stop()+join` 之后，但 sink worker 直到 `input_sink` 析构（`main` 返回）才 `Shutdown`（`win32.cpp:509-526`）⇒ 同样可能少计。
- 最小修法：文档写明"final 不含未排空的 teardown up"；要彻底则给 `DesktopInputSink` 加 `WaitIdle()`（改接口，属可选增强，不建议在本批扩范围）。

### Q4 无界模式 Ctrl+C——**G 成立**

`grep SIGINT|SIGBREAK|SetConsoleCtrlHandler|signal\(` 在 `tools/rtsc_server/main.cpp` + `src/util/crash_guard.cpp` 只有 `crash_guard.cpp:257` 的 `signal(SIGABRT, AbortHandler)`；`main.cpp:713` 只在 `bounded && now >= deadline` 时跳出。⇒ 默认无界模式 Ctrl+C 不打印 final。**最小**修法是文档限定"正常退出"；补 SIGINT 是可选（会动主机生命周期，建议另批）。

### Q5 双计路径——**同意无重复计数**（我复核三条增量点）

| 计数 | 唯一/全部增量点 | 结论 |
|---|---|---|
| `dropped_rate_limited` | 仅 `map.cpp:204`（`Allow` 内部） | 每个被拒动作恰好 +1；caller 不再计（`win32.cpp:216`、`:196` 都是纯 `return false`） |
| `injected` / `send_failures` | 仅 `win32.cpp:482`/`:485`（`Emit`） | 与 dropped 互斥 |
| `dropped_queue_full` | `:220`（evict 旧移动）、`:223`（`kDrop` 入队动作）、`:310`（会话结束 purge） | 三者互斥：同一动作要么被 evict（是**另一条**旧动作被计）、要么 kDrop、要么随后被 purge；`kEvictMove` 的入队动作本身不计数 |

挑战点：`kEvictMove` 计的是**被驱逐的旧移动**，不是触发它的新动作 ⇒ "事件数 ≠ 计数"，但"一个平台动作只进一个计数器"成立。purge 也不双计（这些动作此前只被放行，没有计过任何 dropped）。**另一种可能出现双计的路径不存在**（`Emit` 的 `BuildNative` 失败计入 `dropped_unsupported`，与上述四者分离）。
补充：`dropped_unsupported` 有 3 处自增（`:125` 迟到事件、`:132` 空翻译、`:477` `BuildNative` 失败）且**完全不进 `InputStats`**（`desktop_input.h:36-54` 只有四字段）；`seam.md:160-161` 已明写"内部计数但当前未接出结构体" ⇒ 不是漂移。

### Q6 其他文档漂移——**同意 a-d，另加 1 条**

| # | 位置 | 判定 | 说明 |
|---|---|---|---|
| a | `seam.md:137`/`:138`、`win32.cpp:26-27` | 成立 | 需限定"对端可入队事件"，并补合成 up 项（公式按 Q2 收紧） |
| b | `desktop_input.h:41-43` | 成立 | 定义漏 purge 来源（`win32.cpp:310`） |
| c | `seam.md:168` | 成立 | "退出前"未限定正常退出（无 SIGINT） |
| d | `seam.md:170` | 成立 | `Inject` 是 `void`（`desktop_input.h:71`；`server.cpp:820` 不取返回值） |
| **e（新增）** | `seam.md:266` | **成立（G 漏算）** | "全局 1000 = 4 × 400 的约 1/3"算术不成立：4×400/3≈533≠1000。按 8×400 读才≈1067（G 的算法），但正文写的是 4。建议改为"约 2.5 × 单会话速率"或"8 × 400 的约 1/3" |

另外复核：`seam.md:273-275` "同一个动作只会被其中一个计数器记一次" 成立（Q5）；`:280-281` 合成 up 绕过 Inject ⇒ 不受限流/队列策略，成立（`win32.cpp:232-254`）。

## 6. 工作树补丁复核（非审计对象，供执行批参考）

工作树（未提交）已改 3 个文件，我逐行核对：

| 文件 | 改动 | 复核 |
|---|---|---|
| `src/server/desktop_input_win32.cpp:23-31` | 峰值注释改为"对端可入队 1539 + 合成 up 每会话 515" | 方向正确，建议按 §5-Q2 收紧为 `1024 + 515·K`（K=同时持租会话数） |
| `docs/spec/input-injection-seam.md:137-138` | 同上 + 引理限定 | 同上；`:138` 末句"合成 up 不参与驱逐"与代码一致 |
| `docs/spec/input-injection-seam.md:165-170` | final 限定正常退出、`Inject` 无返回值 | 与 `main.cpp:637-644,713-721`、`desktop_input.h:71` 一致 |
| `include/rtsc/server/desktop_input.h:41-44` | `dropped_queue_full` 补 purge 来源 | 与 `win32.cpp:310` 一致 |
| `tests/test_desktop_input.cpp`（随后被并发改动） | 新增 `desktop_input_rate_limit_held_release_keeps_token`（`:681-744`） | **我复核有效**：pristine `41 tests, 11611 checks, 0 failing`；同一用例在 mutC 上 `FAIL tests:724` ⇒ E1-T 已闭合（会话桶） |
| 同上的**残留**（低） | 新用例只钉住**会话桶** | **mutC2**（held up 只扣**全局**桶）仍 `41/11611/0` **存活** ⇒ 全局桶未被钉住。最小补法：在用例末尾耗尽全局（s1 800 + s2 800 + s3 399，全局剩 1），做 100 条 held up，再 `CHECK(Allow(4,false))`（保留的 1 令牌可花）+ `CHECK(!Allow(4,false))` |

**未修复**：F-1（`server.cpp` 未改）、F-2/F-3（`win32.cpp` 只改注释，行为未变）。⇒ 本批仍不能盖章，F-1 必须先红后绿修掉。

### 6.1 批 11 执行报告复核（执行 AI `ses_e69f47a99ffe7vXb014jKHPhZp`）

| 执行报告项 | 我的复核 | 证据 |
|---|---|---|
| 峰值两段式（`seam.md:137-138`、`win32.cpp:25-32`） | **成立但偏保守** | `read` 逐字核对；`≤1539 + 会话数×515` 是合法上界，但重复计了基线；更紧的写法是 `kHardQueueLimit + 515·K`（K=同时持租会话数，见 §5-Q2） |
| `seam.md:169` final 限定正常退出 | 成立 | 与 `main.cpp:713-721`、无 SIGINT（`crash_guard.cpp:257` 只有 SIGABRT）一致 |
| `seam.md:171` `Inject` 无返回值 | 成立 | `desktop_input.h:71` |
| `desktop_input.h:41-44` 补 purge 来源 | 成立 | 与 `win32.cpp:310` 一致 |
| 新用例 `:681-744` + mutC 红点 `:724` | **独立复现** | pristine `41/11611/0`；mutC `FAIL :724`；恢复 `41/11611/0` |
| C0（comment-only 改动） | 复核通过 | `cl /c /W4 /WX /permissive- /EHsc` on 工作树 `desktop_input_win32.cpp` → exit=0 |
| "mutC 只扣会话桶" 的完备性 | **不成立（低）** | 新 mutant **mutC2**（held up 只扣全局桶）`41/11611/0` 存活；补法见上表 |

（工作树为多代理共享，本节快照于本报告写入时；`tests/` 的并发改动不改变 §1-§5 针对 `63e3cc6` 的判定。）

## 7. 未验证项（W5）

- F-1 的触发概率：只证"`ReleaseSession` 抛异常 ⇒ 槽泄漏"；未测真实 `bad_alloc` 在生产中的出现率（需注入内存压力）。
- `probe_peak` 的 `queue=1024` 积压直接填充建模；未端到端构造"真实对端使 worker 积压 1024 条"（D 已用另一路径测到 1539，本报告不重复）。
- 合成 up 的真实 `SendInput` 吞吐（515 条一次断连的耗时）未实测。
- `a` 项 `seam.md:265` 的"交互式 <20 动作/s / 拖拽 <300 动作/s"是设计估计，未实测。
- `--input-share` 多租约场景下 `K>1` 的峰值未做端到端攻击复现（只做了两会话直接构造 `pressed` 的探针）。

## 8. 影响范围（供执行 AI，按本报告修法）

- 代码：`src/server/server.cpp`（F-1，唯一行为改动，最小 4 行）；可选 `src/server/desktop_input_win32.cpp`（F-2 测试缝 / F-3 注释）。
- 测试：`tests/test_server.cpp` 新增"`ReleaseSession` 抛异常后租约仍可交接"用例（**必须先红**：当前实现 `second_injects=0`）；`tests/test_desktop_input.cpp` 新增 held-up 不耗令牌用例（先红，mutC 存活）。
- 文档：`seam.md:137-138,168,170,266`；`desktop_input.h:41-44`；`win32.cpp:26-31`。
- 影响套件：`rtsc_server_tests`（新增用例 + `ReleaseInput` 路径）、`rtsc_desktop_input_tests`（纯函数用例）、`rtsc_server_desktop_input` 编译（C0 不可豁免）。**不需要**全量测试。
