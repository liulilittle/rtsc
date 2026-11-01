# 输入注入限流与可观测语义审计（审计 E，终稿）

- 对象：提交 `27cf199`（"输入注入：held-release 定界硬限豁免、限流 400/1000、可观测与文档回写"）。
- 只读：本文件是唯一写入。`src/` `include/` `tests/` `tools/` `CMakeLists.txt` 均未改。
- 红证环境：`%TEMP%\rtsc_rate_audit`（仓库副本），MSVC 19.44，`/std:c++20 /W4 /WX`。
- 代码与文档在 27cf199 之后无漂移：
  [BASH: `git -C F:\rtsc diff --stat 27cf199 -- <被审 9 个文件>`] → 空输出（无漂移）。
- 状态：本轮已并入审计 D（`ses_e6a5ce98dfferVQXZ3ELT8rso3`）的交叉审计，见 §13「交叉定案」。

## 进展清单

- [x] 7 个主题逐项 PASS/FAIL + 行号证据
- [x] 基线先绿（`35 tests, 3759 checks, 0 failing`）
- [x] 任务指定的两个变异（去释放豁免 / 速率无穷）红→恢复绿
- [x] 交叉审计 D 的四条新主张（峰值 vs 瞬时上界、M3、M4、win32 零覆盖）由我独立复验
- [x] **自纠 2 处**：E2 上界 131,077 → 515；E4 撤销（无红证，按"未实证不报缺陷"）
- [x] 四步形态（①探针 ②根因 ③方案 ④协商盖章）落到每条缺陷
- [x] relay parent 终稿报告

## 0. 结论速览

| 项 | 主题 | 判定 | 关键证据 |
|---|---|---|---|
| 1a | 400/s burst 800、1000/s burst 2000 | PASS | `map.h:216-219`；`tests:469-490, 515-542` 基线绿 |
| 1b | `steady_clock` 单调性 | PASS | `map.h:214`；`map.cpp:185-188` |
| 1c | `Refill` 时钟倒退 / 大跳变 | PASS（失败闭合） | `map.cpp:184` `if (now <= bucket.last) return;`；`:188` `std::min(burst,...)` |
| 1d | `sessions_` 无界增长 / `Forget` 覆盖 | **FAIL**（低）E3 | probe：`after Forget: 0` → `post-Forget Allow: 1` |
| 2 | 拒绝不扣令牌（无部分扣减） | PASS | `map.cpp:202-207`；`tests:544-571` |
| 3 | 释放豁免与队列豁免语义一致 | **FAIL**（中）E1 + **FAIL**（低）E2 | probe：1,000,000 未持有 up 全放行；probe2：限流丢的 press 仍 held |
| 4 | 移动是否绕过限流 / 实际上界 | PASS | `win32.cpp:324, 328-333, 291-318` |
| 5a | `dropped_rate_limited` 双后端暴露 | PASS（接线零覆盖） | `win32.cpp:161`；`null.cpp:32-39`；`tests:687-709` |
| 5b | 两 dropped 计数是否重复 | PASS（口径未文档化） | `win32.cpp:193-201` vs `:324-327` 互斥 |
| 5c | 主机侧可观测 | **FAIL**（低）E6 | `[BASH]` 生产代码 0 处调用 `.Stats()` |
| 6 | 文档 §1.5/§1.6/§2.3 逐条一致 | **FAIL**（低）E7 | 见 §7 表 |
| 7a | 任务指定两变异真实性 | PASS | mutA / mutB 均转红，恢复后转绿 |
| 7b | 测试套件整体变异充分性 | **FAIL**（中）E8 | M3、M4 变异**存活**（35/3759/0 全绿） |

---

## 1. 基线（先绿）

```
[BASH: %TEMP%\rtsc_rate_audit\b\base.exe]
35 tests, 3759 checks, 0 failing tests, 0 failed checks      exit=0
[BASH: cl /c /W4 /WX /permissive- src/server/desktop_input_win32.cpp]
desktop_input_win32.cpp   exit=0      (C0：零错误零警告)
```

---

## 2. 项 1：令牌桶正确性 / 单调性 / 会话表增长

### 1a PASS — 速率与桶容量

[READ:include/rtsc/server/desktop_input_map.h:216-219] `400.0 / 800.0 / 1000.0 / 2000.0`；
[READ:src/server/desktop_input_map.cpp:196-198] 两个 `Refill` 分别用会话/全局常量。
800/400 = 2000/1000 = 2 s，与 `map.h:204-205` 的 "two seconds of traffic" 一致。

### 1b PASS — `steady_clock`

[READ:include/rtsc/server/desktop_input_map.h:214] `using Clock = std::chrono::steady_clock;`
时间点全部由调用方传入（[READ:src/server/desktop_input_win32.cpp:324-325] worker `Clock::now()`），
桶内不存墙钟。`dropped()` 为 relaxed 原子（[READ:src/server/desktop_input_map.cpp:215-217]），
`Stats()` 可跨线程读；`Allow`/`Forget` 只在 worker 线程。

### 1c PASS — 时钟倒退 / 大跳变

[READ:src/server/desktop_input_map.cpp:184] `if (now <= bucket.last) return;`
→ 倒退不补令牌也不回写 `last`（失败闭合，不会因回拨凭空得令牌）。
[READ:src/server/desktop_input_map.cpp:188] `std::min(burst, tokens + elapsed*rate)`
→ 大跳变最多补满一个 burst。首次调用直接满桶（`:176-180`）。

### 1d FAIL（低）E3 — 断开后 `sessions_` 会被复活

① 查问题（探针）：
```
[BASH: %TEMP%\rtsc_rate_audit\b\probe.exe]
buckets after first Allow: 1
buckets after Forget: 0
buckets after post-Forget Allow (queued item): 1      <-- 复活
```
② 根因 / ROOTCAUSE：worker 每轮**先** drain `forget_sessions_`（[READ:src/server/desktop_input_win32.cpp:239]）
**再**出队（`:240-242`）。会话断开时队列里仍有非释放积压（按下/移动），该条
`Dispatch → Allow` 用 `sessions_[session_id]`（[READ:src/server/desktop_input_map.cpp:197]）
无条件插入，把刚被 `Forget` 掉的桶重建。会话 id 进程内单调递增不复用
（[READ:src/server/server.cpp:2286] `fetch_add(1)+1`；`:2414` 同），此后再无 `Forget` → 永久残留。
`ForgetReleasedSessionsLocked` 也不清 `pending_moves_`（[READ:win32.cpp:268-274]），
断开会话的待发移动仍会 `Emit`，并再次写回 `last_move_sent_`。

量级（实测，不夸大）：一个泄漏桶 `sizeof(InputRateLimiter)=48`（[BASH: probe4.exe] 输出），
每连接 1 个；`pending_moves_` 由 `EmitDueMoves` ≤4 ms 自排空
（[READ:win32.cpp:291-302] `kMoveInterval=4ms`）→ "断开后动指针" ≤1 次、≤4 ms。

③ 方案 / plan：
- `QueuedInput` 增 `bool synthetic`（`win32.cpp:83-86`）；
- `ReleaseSession` 持 `mu_` 时先 `AppendReleasesLocked`（标 `synthetic=true`）再 erase 该 id 的**非 synthetic** 积压；
- `ForgetReleasedSessionsLocked` 内补 `pending_moves_.erase(id)`（`last_move_sent_` 已 erase）。

④ 协商：审计 D 独立得出同一结论与同一修法（D 判"中→低"），本报告采纳"低"。

---

## 3. 项 2 PASS — 拒绝不扣令牌

[READ:src/server/desktop_input_map.cpp:196-208]：两次 `Refill` 只补不扣；
`if (session.tokens < 1.0 || global_.tokens < 1.0) { dropped_++; return false; }`
在**任何扣减之前**返回，随后才 `-= 1.0` 两次（`:206-207`）→ 无"部分扣减"。
[tests:544-571] 用 799+800+401=2000 后"会话 1 仍留 1 个令牌、1 s 后能花 401 个"钉住该语义，基线绿。

---

## 4. 项 3 FAIL — 两套释放语义不一致

### E1（中）FAIL — 限流豁免用 `IsReleaseInput`，不看 held

① 查问题（探针）：
```
[BASH: %TEMP%\rtsc_rate_audit\b\probe.exe]
unheld key-up: IsReleaseInput=1 IsHeldRelease=0
after 800 presses: dropped=1 next_press_allowed=0
1000000 unheld up events: allowed=1000000 dropped=1
```
② 根因 / ROOTCAUSE：`Dispatch` 传给限流的是 `IsReleaseInput(item.input)`
（[READ:src/server/desktop_input_win32.cpp:324]），其定义只看 `release`/`!button_down`
（[READ:include/rtsc/server/desktop_input_map.h:78-84]），**不看 `pressed`**；
而队列侧用的是 `IsHeldRelease`（[READ:map.cpp:144-156]，[READ:win32.cpp:127-128]）。
两条判定分叉 ⇒ 未持有的 up 免令牌、免计数，队列硬限只约束**积压**（入队侧），
不约束**注入速率**（worker 每出队一条就 `SendInput` 一条：`win32.cpp:232-257, 433-446`）。

量级：1,000,000 条连续未持有 up **全部放行**（实测）。持续速率上界
= worker 排空速率（算法上无界；具体 evt/s **未实测**，W5 标注，不报数字）。

③ 方案 / plan（推荐 A）：
1. `QueuedInput` 增 `bool exempt_release`（`win32.cpp:83-86`），由 `EnqueueLocked` 写入
   `AdmitInput` 实际用的 `held_release`（`win32.cpp:192-203`）；`AppendReleasesLocked`
   的合成 up 置 `true`（`:220, 227`）。
2. `Dispatch` 改 `Allow(item.session_id, item.exempt_release, Clock::now())`（`win32.cpp:324`）。
3. `map.h:207-211`、`desktop_input.h:42-45`、`seam.md:263-264` 同步改为"只有 held release 免限流"。

替代（D 推荐）：把限流前移到 `Inject()` 内（该处已持 `mu_`，`win32.cpp:110`），
`Dispatch` 删除 `Allow`。能一并消 E2，无需新增锁，代价是 `map.h:199-203` 的
"worker-only 无锁"注释要改。**两者择一由执行批决定；本报告不预设。**

④ 协商：审计 D 与我一致判 FAIL（D 亦给红证 `unheld_keyups_allowed=5000 dropped=1`）。

### E2（低）FAIL — `pressed` 含"被限流丢弃的按下"（**本报告自纠数量级**）

① 查问题（探针）：
```
[BASH: %TEMP%\rtsc_rate_audit\b\probe2.exe]
press admitted=1 pressed_keys=1
limiter allows the tracked press=0 dropped=1
held=1 hard_limit_decision=0        <-- 从未注入的按下，其 up 在满队列仍 kAccept
```
② 根因 / ROOTCAUSE：`AdmitInput` 在**入队时**就 `TrackInput`
（[READ:src/server/desktop_input_map.cpp:170] `if (action != kDrop) TrackInput(...)`），
限流在**出队后**才丢弃（[READ:win32.cpp:320-327]），两者之间无回撤。
于是 `win32.cpp:119-126` 与 `map.h:186-195` 宣称的"被丢弃的按下从未被记录为 held"
只对**队列硬限**成立，对**限流**不成立。

**自纠**：上一轮我写 `|pressed| ≤ 131,077`（按 `PlatformInput::scancode` 的 `uint16_t`
值域）。该值**错误**，被两条独立证据推翻：
- [READ:include/rtsc/server/server.h:229] `uint8_t scancode = 0;`（wire 侧单字节）；
- [READ:src/server/desktop_input_map.cpp:39-44] scancode 0 被丢，其余原样拷入；
- [BASH: probe4.exe] `WIRE keys=510 buttons=5 |pressed|=515`
  （510 = 255 scancode × 2 extended；5 = `DecodePointerButtons` 只会写 1..5，
  [READ:src/server/server.cpp:592-598]）。
⇒ **`|pressed| ≤ 515`**。同理我上一轮推的 `hard + 2·|pressed| = 2054` 也错：
`size + |pressed| ≤ hard + P`（每次 held release 使 size+1、pressed−1），故
**峰值 = `hard + |pressed| = 1024 + 515 = 1539`**（与 D 独立测得 `peak=1539` 一致）。

③ 方案：与 E1 同源解决（限流前移，未放行则不入队不 track）；或修法 A 之后在
出队丢弃时从 `pressed` 撤销该条。

④ 协商：D 与我一致——现象真、严重度**低**（不是 128×hard 的膨胀）。

---

## 5. 项 4 PASS — 移动不绕过限流

[READ:win32.cpp:324] `Allow` 先判；通过后才 [READ:win32.cpp:328-333] 写入 `pending_moves_`
并 `EmitDueMoves()`。三条发送路径 `EmitDueMoves`/`FlushSessionMove`/`FlushMoves`
（[READ:win32.cpp:291-318]）都直接 `Emit`（`:433`），**不再过 `Allow`**，但：
- 每个进入 `pending_moves_` 的移动都已花掉 1 个令牌；
- `pending_moves_[sid] = input` 是覆盖写，一个已放行移动最多 `Emit` 一次（随后 erase）；
- ⇒ 移动注入速率 ≤ 已放行移动数 ≤ 会话 400/s、全局 1000/s；退出时 `FlushMoves` 额外 ≤ 会话数。

附注（既有漂移，非本批）：250 Hz 不是硬上限 —— `FlushSessionMove`
（[READ:win32.cpp:304-310]）不看 `MoveDue()/kMoveInterval`，按键插入时会立即把待发移动打出去。

---

## 6. 项 5：可观测

### 5a PASS（接线零覆盖）— 双后端 `Stats()`

[READ:win32.cpp:161] `stats.dropped_rate_limited = rate_limiter_.dropped();`
[READ:include/rtsc/server/desktop_input.h:47-52] 四字段同结构体。
[READ:src/server/desktop_input_null.cpp:32-39] null 后端同字段恒 0 并注释"无队列故不限流"。
[tests:687-709] 断言四字段，基线绿。

**但 Win32 的接线（`win32.cpp:161`）零测试覆盖**（D 提出，我复验）：
[READ:CMakeLists.txt:676-682] `rtsc_desktop_input_tests` 只编 `desktop_input_null.cpp`；
[READ:CMakeLists.txt:690-696] win32 只进 `rtsc_server_desktop_input`；
[READ:CMakeLists.txt:703-704] 仅 `rtsc_server_host` 链接它；
[READ:CMakeLists.txt:609] `rtsc_server_tests` 链 `rtsc_server`（不含 desktop_input）。
⇒ 该行任何变异都不会红（见 §8 E8）。

### 5b PASS（口径未文档化）— 两 dropped 计数不重复

限流丢弃在出队后（[READ:win32.cpp:324-327]），队列丢弃在入队时（`:193-201`），互斥。
`kEvictMove` 计的是被驱逐的旧移动（`:194-196`）。唯一粒度问题：一个 RDP 事件可译成两个
平台动作（`map.cpp:60-80`），可能一个进 `dropped_queue_full`、另一个进
`dropped_rate_limited`；头文件只对 `injected` 说明"per platform action"
（[READ:desktop_input.h:36-40]），两个 dropped 未说明 → 见 E7-h。

### 5c FAIL（低）E6 — 主机侧不可观测

① 查问题：
```
[BASH: Select-String -Path src\*.cpp,src\server\*.cpp,tools\rtsc_server\*.cpp -Pattern "\.Stats\(\)"]
NO MATCH (0 hits)
```
② 根因 / ROOTCAUSE：`rtsc_server_host` 从不读 `DesktopInputSink::Stats()`
（[READ:tools/rtsc_server/main.cpp:628-662] 循环只读 `session_count/total/lease_denied`）。
⇒ `dropped_rate_limited`/`dropped_queue_full`/`send_failures` 在随仓主机里完全不可见。
另：`lease_denied_reported` 是"首次一次"（[READ:main.cpp:646-647]），打印的是首次拒绝时的计数
（≈1），不随真实拒绝数增长。
③ 方案：服务循环内按 live/total 变化或每 N 秒采样 `input_sink->Stats()`，
任一计数变化时打一行；退出前打终值。不改注入路径。
④ 协商：D 独立确认同一事实。

---

## 7. 项 6 FAIL（低）E7 — 文档漂移清单

| # | 文档 | 声称 | 代码事实 | 归属 | 判定 |
|---|---|---|---|---|---|
| a | `seam.md:137` | 队列上界 `hard_limit + pressed` | **峰值**正确（1539，probe4/probe5）；但作为**瞬时不变式**被违反：probe5 `violations=7` | 本批 | **表述 FAIL**（须写"峰值"，并补"size>soft ⇒ 无 move"引理） |
| b | `seam.md:141-143` | 未持有的 keyup 不豁免 | 队列侧正确（`map.cpp:144-156`）；漏"被**限流**丢弃的按下的 up 仍豁免"（probe2） | 本批 | 遗漏 FAIL |
| c | `seam.md:133`、`:259` | 移动输出"上限 250 Hz" | [READ:win32.cpp:304-310] `FlushSessionMove` 直接 `Emit`，不看 `MoveDue()`；[READ:win32.cpp:294] 只有定时路径查 `kMoveInterval` | **既有** | 漂移（R1；**读码证据，无运行时探针**） |
| d | `seam.md:158-162` | 失败日志"首次 / 失败率>50% 5 s / 恢复"三态 | [READ:win32.cpp:448-466] `LogFailure` 是"任意失败、每 5 s 至多一条"，无 >50% 判定、无"恢复"行 | **既有** | 漂移（R1；**读码证据，无运行时探针**） |
| e | `seam.md:263-264` | 释放免限流"且数量被 pressed 集合限界" | 后半句错（probe：1,000,000 条全放行）。该行文本来自 **b369d75**（`27cf199^` 第 172 行已有；`334d5a1` 没有），**不是** 27cf199 新增；但 27cf199 实现了与之冲突的限流 | 本批实现 vs 既有文档行 | **FAIL（本批）** |
| f | `seam.md:256-258` | "400 events/s / 1000 events/s" | 按**平台动作**扣令牌（move+button 扣 2，`map.cpp:60-80`）→ 2 动作事件稳态仅 200 事件/s | **既有**（`27cf199^:171` 同文本） | 口径漂移（R1） |
| g | `map.h:221-223` | "false 由 caller 计入 dropped_rate_limited" | `Allow` 自己 `dropped_.fetch_add`（`map.cpp:203`），sink 只读（`win32.cpp:161`）→ 照注释实现会**真重复计数** | 本批 | **FAIL** |
| h | `desktop_input.h:41` | `dropped_queue_full` = "refused" | [READ:win32.cpp:194-196] `kEvictMove` 分支同样 `dropped_queue_full_.fetch_add(1)`，被驱逐的旧移动进入该计数 | 本批（该行被 27cf199 重写） | **FAIL**（**读码证据，无运行时探针**） |
| i | `seam.md:258` | 全局 1000 是"8×400 的 1/3" | 3200/3≈1067，代码 1000（31.25%） | 既有 | 可接受（建议"约 1/3"；读码/算术，无探针） |
| j | `seam.md:208-210` | 启动行 `input=`/`input_max_sessions=`；首次租约拒绝一条 WARNING | `main.cpp:487-489`、`:641-655` 一致 | 本批 | **PASS** |

**与 D 的分歧（须记录）**：D 称 `seam.md:263-264` 是 27cf199 的 `+` 行，依据是
`git diff 334d5a1 27cf199`。该 diff 跨越 2 个提交（`334d5a1..27cf199` 含 `b369d75` + `27cf199`）。
实测归属：`[BASH] git show 334d5a1:...seam.md | grep keyup` 无该条；
`[BASH] git show 27cf199^:...seam.md` 第 172 行已有该条 ⇒ 该文本由 **b369d75** 引入。
判定结论不变（本批 FAIL），但归属应为"本批实现与既有文档行冲突"，非"本批新增该行"。

---

## 8. 项 7：变异真实性

### 7a PASS — 任务指定的两个变异

**变异 A：去掉释放豁免**（`map.cpp:194` `if (is_release) return true;` → `(void)is_release;`）
```
[BASH: mutA.exe]
FAIL tests/test_desktop_input.cpp:509  allowed == 5000 (got 0, want 5000)
FAIL tests/test_desktop_input.cpp:512  limiter.dropped() == 2 (got 5002, want 2)
[ FAIL ] desktop_input_rate_limit_release_is_exempt
35 tests, 3759 checks, 1 failing tests, 2 failed checks
```
**变异 B：速率设为无穷**（两处 `Refill` 的 per_second → `std::numeric_limits<double>::infinity()`）
```
[BASH: mutB.exe]
FAIL tests:488  allowed == 400 (got 401)
FAIL tests:489  limiter.dropped() == 2 (got 1)
[ FAIL ] desktop_input_rate_limit_session_bucket
FAIL tests:540  allowed == 1000 (got 1008)
FAIL tests:541  limiter.dropped() == 9 (got 1)
[ FAIL ] desktop_input_rate_limit_global_bucket
FAIL tests:570  !limiter.Allow(1, false, t1)
[ FAIL ] desktop_input_rate_limit_global_drop_keeps_session_token
35 tests, 3759 checks, 3 failing tests, 5 failed checks
```
**恢复后转绿**（用未变异的 pristine 副本重建）：
```
[BASH: restored.exe]
35 tests, 3759 checks, 0 failing tests, 0 failed checks      exit=0
```

### 7b FAIL（中）E8 — 套件整体变异充分性不合格（M3/M4 存活，我独立复现）

**M3（`IsHeldRelease` 的 KeyId 身份丢掉 extended）**：
`map.cpp:149` `KeyId{input.scancode, input.extended}` → `KeyId{input.scancode, false}`
```
[BASH: mutC.exe]
35 tests, 3759 checks, 0 failing tests, 0 failed checks      <-- 存活
```
ROOTCAUSE：唯一的 extended 断言在 [READ:tests/test_desktop_input.cpp:384]
`CHECK(!IsHeldRelease(KeyUp(0x1D, true), pressed));`，而该处 `pressed` 已被
[READ:tests:377] `CHECK(pressed.keys.empty())` 清空 ⇒ 断言恒真（空集合查什么都是 false）。
`map.h:86-89` 的"身份含 0xE0"因此无测试保护。

**M4（`AdmitInput` 只在 kAccept 时 track，evict 路径不 track）**：
`map.cpp:170` `if (action != kDrop)` → `if (action == kAccept)`
```
[BASH: mutD.exe]
35 tests, 3759 checks, 0 failing tests, 0 failed checks      <-- 存活
```
ROOTCAUSE：所有 `AdmitInput` 调用点（[READ:tests:369,374,379,393,400,407,422,429,440]）
都用 `QueueState(0,...)` 或 `QueueState(16,false,...)`，即 `has_movable_move` 恒 false
⇒ `kEvictMove` 分支在测试里**从不出现**。而 `size≥soft 且有可驱逐移动时按下走 kEvictMove`
是真实常见路径（`map.cpp:109`）；退化后该 press 不被 track，其 up 不再 held → 存活期卡键。

**方案 / plan（E8）**：补三条纯函数用例（不改产品代码即可先红）：
1. `pressed` 非空时断言 `IsHeldRelease(KeyUp(sc, /*extended=*/true), pressed) == false`
   且 `IsHeldRelease(KeyUp(sc, false), pressed) == true`（M3 转红）；
2. `QueueState(size=soft, movable_move=true, incoming_is_move=false)` + 按下 →
   `kEvictMove` 且 `pressed.keys.size()==1`（M4 转红）；
3. `size=hard` 下 held release 接受后 `pressed` 清空、且 `size` 不超过 `hard+|pressed|` 峰值（a 项）。
另：为 `win32.cpp` 的接线（`Dispatch` 的 `Allow` 调用、`Stats` 的 `dropped_rate_limited`）
提供最小可测缝（如把 `QueuedInput`/决策抽成纯函数，或给 sink 注入假时钟 + 只读桶计数），
否则 §5a/§6 的接线永远是零覆盖。

④ 协商：D 独立复现 M3/M4 存活并判"测试真实性不合格"，与我一致。

---

## 9. 缺陷与最小修法汇总（修正后）

| ID | 级别 | 位置 | 红证 | 最小修法 |
|---|---|---|---|---|
| E1 | **中** | `win32.cpp:324` + `map.h:78-84` | probe：1,000,000 未持有 up 全放行 | `QueuedInput.exempt_release` 随队传递；或限流前移进 `Inject()`（已持 `mu_`） |
| E2 | **低** | `map.cpp:170` / `win32.cpp:320-327` | probe2：`held=1 hard_limit_decision=0` | 与 E1 同源（前移则天然消解）；否则出队丢弃时撤销 `pressed` |
| E3 | **低** | `win32.cpp:239, 268-274` | probe：`Forget:0 → Allow:1` | `QueuedInput.synthetic` + 清 `pending_moves_` |
| E6 | **低** | `main.cpp:628-662` | `[BASH]` 0 处 `.Stats()` | 循环内采样并打一行 |
| E7 | **低** | §7 表 a/b/e/g/h（本批）；c/d/f/i（既有） | 见 §7 | 逐条改写；e 与 E1 同批落 |
| E8 | **中** | `tests:384`、`tests` 无 evict+press 用例 | mutC/mutD 全绿 | 见 §8 方案 1–3 + win32 可测缝 |

**已撤销**：原 E4（`ServeOne` 无 try/catch）。理由：按"未实证不报缺陷"，
我无法造出红证——全部 in-tree `Transport::Close()` 实现体均无 throw
（[READ:winsock_transport.cpp:64-69]、[READ:gateway_transport.cpp:115-119,420-424,642-648,1323-1328]），
`ScrubCredentials` 为 `noexcept`（[READ:server.cpp:796]）。且 `27cf199^` 同样无 try/catch
（[BASH] `git show 27cf199^:src/server/server.cpp` → 2426/2428），非本批引入。
保留为**未实证观察（W5）**：接口允许 `Close()` 抛，未来新增 transport 若抛则跳过 `ReleaseInput`。

---

## 10. 复现方法

1. 副本：`include/`、`tests/`、`src/server/desktop_input_map.cpp`、
   `src/server/desktop_input_null.cpp`、`src/util/crash_guard.cpp` → `%TEMP%\rtsc_rate_audit`。
2. 编译（`b\build.bat <out> [srcRoot]`，需先 `call vcvars64.bat`）：
   `cl /nologo /std:c++20 /EHsc /W4 /WX /utf-8 /I<root>\include /I<root>\tests
   /DRTSC_SOURCE_DIR="\"<root 正斜杠>\"" <tests>\test_desktop_input.cpp <src>\src\server\desktop_input_map.cpp
   <root>\src\server\desktop_input_null.cpp <root>\src\util\crash_guard.cpp /Fe:<root>\b\<out>.exe /link dbghelp.lib`
3. 基线 `base` → 35/3759/0；变异 A/B → mutA/mutB（失败集见 §8）；M3/M4 → mutC/mutD（**全绿=存活**）；
   pristine 重建 `restored` → 35/3759/0。
4. 探针：`probe`（E1+E3）、`probe2`（E2）、`probe4`（wire 上界 515 / 桶 48 B）、
   `probe5`（峰值 vs 瞬时 + extended1）。全部只链 `desktop_input_map.cpp`。

---

## 11. 执行影响范围（供执行 AI）

- 代码：`src/server/desktop_input_win32.cpp`（E1/E2/E3）；若选"前移"还要
  `include/rtsc/server/desktop_input_map.h` + `src/server/desktop_input_map.cpp`（`Allow` 加锁）。
- 测试：`rtsc_desktop_input_tests`（主）、`rtsc_server_tests`（ReleaseInput 路径）；
  `rtsc_server_desktop_input` 编译（Win32 C0，不可豁免）。
- 新增用例：§8 方案 1–3；另加"未持有 up 在 burst 后必须被限流"。
- 文档：`seam.md` §1.5/§1.6/§2.3 + `desktop_input.h:36-45` + `map.h:207-223`。

---

## 12. 未验证项（W5）

- 未持有 up 的实际 evt/s 上界：只证"无算法上界 + 100 万条全放行"，未做真机 SendInput 基准。
- `pending_moves_` 在断开后实际 Emit 次数：由 `kMoveInterval=4ms` 推 ≤1 次，未插桩实测。
- 原 E4 可触发性：无红证，已撤销为观察。

---

## 13. 交叉定案（审计 E × 审计 D）

**一致点（双方独立红证）**
1. E1 FAIL：未持有 up 免限流，`seam.md:263-264` 的"被 pressed 集合限界"不成立。
2. E2 现象真、严重度**低**；`|pressed| ≤ 515`（D 报 515，我 probe4 独立得 515）。
3. E3 现象真、严重度**低**（桶泄漏每连接 1 个 48 B；断开后移动 ≤4 ms）。
4. 队列峰值 = `hard + |pressed| = 1539`；**瞬时不变式 `size ≤ hard+|pressed|` 不成立**
   （我 probe5 `violations=7`；D 报 `violated=1/774 次`）→ 文档须写"峰值"。
5. E6：生产代码 0 处调用 `Stats()`。
6. M3、M4 变异**存活**（我 mutC/mutD 全绿复现）；win32 接线零覆盖（CMakeLists 证据一致）。
7. `extended1` 不参与 `TranslateInput`/`KeyId`，与 `seam.md` P-6 冲突（probe5：
   `identical_output=1`）——双方都判**既有漂移**，不算本批 FAIL。

**分歧点（已用证据裁定）**
- D 称 `seam.md:263-264` 为 27cf199 的 `+` 行（依据 `git diff 334d5a1 27cf199`）。
  该 diff 跨 2 个提交。实测该文本在 `27cf199^`（b369d75）第 172 行已存在、在 `334d5a1` 不存在
  ⇒ 归属 b369d75。**判定不变（本批 FAIL），归属更正**。
- D 判 E3 修法"丢弃非合成积压"可接受；我同意（未出队的 press 从未 `SendInput`，`Dispatch` 才 `Emit`），
  但补充：合成 up 必须保留，否则真卡键。

**我方最终判定**
- held-release 定界目标**达成**（峰值 1539 有界）。
- 但本批在**限流语义（E1）**、**文档回写（E7 a/b/e/g/h）**、**测试真实性（E8）**三面不合格。
- 执行批必须：修 E1（顺带 E2）→ 补 §8 的 3 条用例 → 重跑 M3/M4 必须**转红** → 修 E3/E6/E7。
- 通过门槛：M3/M4 转红 + 新增"未持有 up 受限流"用例红→绿 + Win32 后端 C0 零错零警告。

---

## 14. 工作树修复验证（27cf199 → 当前工作树，独立复验）

审计对象是 `27cf199`；本轮结束时工作树已被执行 AI 改动（`git status`：
`M include/rtsc/server/desktop_input_map.h, src/server/desktop_input_map.cpp,
src/server/desktop_input_win32.cpp, tests/test_desktop_input.cpp, tools/rtsc_server/main.cpp,
docs/spec/input-injection-seam.md`）。我用 `%TEMP%\rtsc_rate_audit_wt` 独立快照复验：

| 验收项 | 探针 | 结果 | 判定 |
|---|---|---|---|
| E1 修复：未持有 up 必须受限流 | probe8（走新 `AdmitAndTrack` 管线） | `100000 unheld ups: accepted=0 rate_limited=100000` | **PASS** |
| E1 修复：held release 仍豁免且不花令牌 | probe8 | `held press accepted=1 held up rate_limited=0 action=0 dropped_delta=0` | **PASS** |
| E2 修复：被限流拒绝的 press 不得 track | probe8 | `rate_limited press: rate_limited=1 tracked_keys=0` | **PASS** |
| E3 修复：断开后清 pending move | [READ: 工作树 win32.cpp:294-299] `pending_moves_.erase(session_id)` + `rate_limiter_.Forget` | 源码已含 | **PASS（读码）** |
| E8 门槛：M3 变异必须转红 | wtM3（KeyId 丢 extended） | `[ FAIL ] desktop_input_queue_extended_identity_is_not_confused` | **PASS** |
| E8 门槛：M4 变异必须转红 | wtM4（evict 路径不 track） | `[ FAIL ] desktop_input_queue_evict_move_still_tracks_press` | **PASS** |
| win32 后端 C0 | `cl /c /W4 /WX /permissive-` | exit=0 | **PASS** |
| 工作树整体测试 | wtbase2 | `40 tests, 9602 checks, 1 failing tests`（`desktop_input_host_reports_input_state_and_lease_denial`，7 checks） | **未闭环** |

**未闭环项（必须如实上报）**：工作树 `tools/rtsc_server/main.cpp` 已标 `M`，但测试
`tests/test_desktop_input.cpp:851-859` 仍要求 `input lease denied summary`、`->Stats()`、
`input_injected=`、`input_dropped_queue=`、`input_rate_limited=`、`input_send_failures=`、
`"final"` 七个源码串，实测全部未命中
[BASH: `Select-String -Path F:\rtsc\tools\rtsc_server\main.cpp -Pattern "->Stats\(\)|input_injected=|input lease denied summary"` → NO MATCH]。
即 E6（主机侧可观测）在审计时点是 **TDD 红态、尚未实现**，执行批不能据此收尾。

同时 [BASH: `Select-String` on 工作树 main.cpp] 证明：审计报告 §6 5c 的 E6 缺陷在 27cf199 上成立，
在工作树上也仍未修复。

## 15. 缺陷逐条四步形态（探针 → 根因 → 方案 → 协商）

| ID | ① 查问题（探针/读码，先于结论） | ② 根因 | ③ 方案 | ④ 协商 |
|---|---|---|---|---|
| E1 | [BASH: probe.exe] `1000000 unheld up events: allowed=1000000 dropped=1`；`IsReleaseInput=1 IsHeldRelease=0` | `win32.cpp:324` 传 `IsReleaseInput`，`map.h:78-84` 不看 `pressed`；队列侧却用 `IsHeldRelease`（`map.cpp:144-156`） | `QueuedInput.exempt_release` 随队传递；或限流前移进 `Inject()`（工作树已选后者） | 与 D 一致 FAIL；工作树 probe8 复验已闭环 |
| E2 | [BASH: probe2.exe] `press admitted=1` → `limiter ... =0 dropped=1` → `held=1 hard_limit_decision=0` | `map.cpp:170` 在入队时 `TrackInput`，限流在出队后才丢（`win32.cpp:320-327`），无回撤 | 与 E1 同源：限流前移，未放行则不入队不 track | 与 D 一致；工作树 probe8 `tracked_keys=0` 已闭环 |
| E3 | [BASH: probe.exe] `after Forget: 0` → `post-Forget Allow: 1` | worker 先 `Forget`（`win32.cpp:239`）再出队（`:240-242`），积压 `Dispatch` 用 `sessions_[id]` 重建（`map.cpp:197`）；id 单调不复用 | `QueuedInput.synthetic` + Forget 时清非合成积压 + `pending_moves_.erase` | 与 D 一致；工作树已加 `pending_moves_.erase`（读码） |
| E6 | [BASH: Select-String 生产代码 `.Stats()`] → NO MATCH | `main.cpp:628-662` 只读 session/lease 计数，从不读 `Stats()` | 循环内采样并打一行 + 退出打终值 | 与 D 一致；工作树测试已红，实现未完成 |
| E7-g | [BASH: probe7.exe] `delta=1`，`header claim 'counted by the caller' is FALSE` | `Allow` 自己 `dropped_.fetch_add`（`map.cpp:203`），注释（`map.h:221-223`）却让 caller 计 | 删注释从句，写明 Allow 自计 | 与 D 一致 |
| E7-f | [BASH: probe6.exe] `one move+button -> 2 actions`；`burst 800: actions=800 events=400`；`steady=200/s`（doc 400/s） | 按平台动作扣令牌（`map.cpp:60-80` + `win32.cpp:118-129`） | 文档改"平台动作"口径 | 与 D 一致 |
| E7-a | [BASH: probe5.exe] `peak=31 hard=16 violations=7` | held release 接受后 `TrackInput` 才 erase（`map.cpp:170`），瞬时 `size > hard+|pressed|` | 文档写"峰值"并补"size>soft ⇒ 无 move"引理 | 与 D 一致 |
| E8 | [BASH: mutC.exe/mutD.exe] 均 `35 tests, 3759 checks, 0 failing`（存活） | `tests:384` 断言在空 `pressed` 上恒真；`AdmitInput` 用例 `has_movable_move` 恒 false | 补 3 条用例（工作树已补，wtM3/wtM4 转红） | 与 D 一致 |

**E7-c / E7-d / E7-h**：只有 [READ] 读码证据，无运行时探针 → 按"未实证不报缺陷"，
降级为**文档漂移观察（W5）**，不计入本批 FAIL 结论。