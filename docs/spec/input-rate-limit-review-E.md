# 输入注入限流与可观测语义审计（审计 E）

- 对象：提交 `27cf199`（"输入注入：held-release 定界硬限豁免、限流 400/1000、可观测与文档回写"）。
- 只读范围：`include/rtsc/server/desktop_input_map.h`、`src/server/desktop_input_map.cpp`、
  `src/server/desktop_input_win32.cpp`、`src/server/desktop_input_null.cpp`、
  `include/rtsc/server/desktop_input.h`、`src/server/server.cpp`、`tools/rtsc_server/main.cpp`、
  `tests/test_desktop_input.cpp`、`docs/spec/input-injection-seam.md`。
- 工作树未改动（唯一写入：本文件）。审计时 HEAD 已因其他代理的记忆提交前进到 `4a3de27`；
  `git diff --stat 27cf199 -- <上述文件>` 为空，被审代码与文档在 27cf199 后无漂移。
- 红证环境：`%TEMP%\rtsc_rate_audit`（仓库副本，不触碰工作树），MSVC 19.44，`/std:c++20 /W4 /WX`。

## 0. 结论速览

| 项 | 主题 | 判定 |
|---|---|---|
| 1a | 400/s burst 800、1000/s burst 2000 | PASS |
| 1b | `steady_clock` 单调性 | PASS |
| 1c | `Refill` 时钟倒退 / 大跳变 | PASS（失败闭合，不超发） |
| 1d | `sessions_` 无界增长 / `Forget` 覆盖所有断开路径 | **FAIL**（见 E3、E4） |
| 2 | 拒绝不扣令牌（无部分扣减） | PASS |
| 3 | 释放豁免与队列豁免的语义一致性 | **FAIL**（见 E1、E2） |
| 4 | `pending_moves_` / `Emit` 是否绕过限流 | PASS（有精度漂移，见 E7-c） |
| 5a | `dropped_rate_limited` 在 `Stats()` 双后端一致暴露 | PASS |
| 5b | `dropped_queue_full` 与 `dropped_rate_limited` 重复计数 | PASS（有粒度说明，见 E7-d） |
| 5c | 生产主机对限流丢弃的可观测性 | **FAIL**（见 E6） |
| 6 | 文档 §1.5 / §1.6 / §2.3 与代码逐条一致 | **FAIL**（见 E7） |
| 7 | 变异真实性（去豁免 / 速率无穷） | PASS |

## 1. 基线（先绿）

```
$ %TEMP%\rtsc_rate_audit\b\base.exe      # 27cf199 的 desktop_input 测试目标
35 tests, 3759 checks, 0 failing tests, 0 failed checks
$ cl /c /W4 /WX /permissive- ... src/server/desktop_input_win32.cpp
exit=0                                    # Win32 后端在 C0 门（零警告零错误）下编译通过
```

## 2. 项 1：令牌桶正确性 / 单调性 / 会话表增长

### 1a PASS — 速率与桶容量

`desktop_input_map.h:216-219`：400/800、1000/2000；`desktop_input_map.cpp:196-198` 分别补充。
800/400 = 2 s、2000/1000 = 2 s，与注释"two seconds of traffic"一致。
`tests/test_desktop_input.cpp:469-490` 精确钉住 800 后第 801 个被拒、1 s 后恰好 400 个；
`tests:515-542` 钉住全局 2000 / 1000。基线运行全绿，说明数值没有偏差。

### 1b PASS — `steady_clock`

`InputRateLimiter::Clock = std::chrono::steady_clock`（`desktop_input_map.h:214`），
time point 全部由调用方（worker 的 `Clock::now()`，`desktop_input_win32.cpp:324-325`）传入，
桶内不存墙钟；`Refill` 只做 `now - bucket.last` 与 `duration<double>` 换算（`map.cpp:185-188`）。
`steady_clock` 的 `is_steady == true` 是标准要求（C++ [time.clock.steady]），无回拨来源。
无数据竞争：`Allow`/`Forget` 只在 worker（`Dispatch` / `ForgetReleasedSessionsLocked`）；
`dropped()` 是 relaxed 原子（`map.cpp:215-217`），`Stats()` 可从任意线程读。

### 1c PASS — 时钟倒退 / 大跳变

`map.cpp:184`：`if (now <= bucket.last) return;` —— 倒退或同刻不补令牌、也不回写 `last`
（失败闭合：不会因回拨而凭空得令牌；等真实时间越过旧 `last` 后才按实际间隔补）。
大跳变由 `map.cpp:188` 的 `std::min(burst, ...)` 封顶，最多补满一个 burst，不会一次给 10^9 个令牌。
`bucket.started` 首次调用直接满桶（`map.cpp:176-180`），因此 `Clock::time_point{}` 起点的测试也正确。

### 1d FAIL — `sessions_` 可在"断开后仍有积压"时被复活并永久留存

`Allow` 用 `sessions_[session_id]` 无条件插入（`map.cpp:197`）。正常路径的 `Forget` 覆盖是齐的：

- 正常断开 / 异常断开：`server.cpp:2341-2364`（detached 路径，`Run()` 与 `ReleaseInput()` 各自 try/catch）、
  `server.cpp:2419-2428`（`ServeOne`）都会调用 `ReleaseInput()`；
  `ReleaseInput` 在持租约时调用 `input_sink_->ReleaseSession()`（`server.cpp:762-774`）。
- `ReleaseSession` 把 id 放进 `forget_sessions_`（`desktop_input_win32.cpp:143`），
  worker 在每轮循环开头 drain 并 `Forget`（`win32.cpp:239, 268-274`）。
- `Shutdown()` 不 `Forget`，但桶随 sink 对象销毁，进程生命周期内不增长（`win32.cpp:468-480`）。

但存在一条**复活**路径，用探针实测：

```
unheld key-up: IsReleaseInput=1 IsHeldRelease=0
...
buckets after first Allow: 1
buckets after Forget: 0
buckets after post-Forget Allow (queued item): 1        <-- 复活
```

机制：worker 先 `ForgetReleasedSessionsLocked()` 再出队（`win32.cpp:239-242`）。
若该会话断开时队列里还有**非释放**积压（按下/移动），该条 `Dispatch → Allow` 会重新
`sessions_[id]` 插入；而 id 在进程内单调递增（`server.cpp:2286, 2414`）且不会再被 `Forget`，
于是桶永久残留。`last_move_sent_` 同理会因 `EmitDueMoves/FlushSessionMove` 被重新写回
（`win32.cpp:296, 308, 315`）。高负载 + 频繁断连（恰是队列积压最容易发生的情形）时按会话数无界增长。
另外 `ForgetReleasedSessionsLocked` 不清 `pending_moves_`，断开会话的待发移动仍会被注入
（语义上"ReleaseSession 之后该会话不再动指针"被破坏），并再次复活 `last_move_sent_`。

红证：`%TEMP%\rtsc_rate_audit\b\probe.exe` 第 3 段（见上）。

## 3. 项 2 PASS — 拒绝不扣令牌

`map.cpp:196-208`：两个 `Refill` 只补不扣；`if (session.tokens < 1.0 || global_.tokens < 1.0)`
在**任何扣减之前**返回 false，随后才 `-= 1.0` 两次。因此全局拒绝不会花掉会话令牌，反之亦然。
`tests:544-571` 用"799+800+401=2000 后会话 1 仍有 1 个令牌，1 s 后能花 401 个"钉住该语义，基线绿。

## 4. 项 3 FAIL — 两套释放语义不一致，且互相放大

### 事实

- 队列：`IsHeldRelease(input, pressed)`（`map.cpp:144-156`），只豁免"当前确实按住"的 up；
  未持有的 up 在硬限处被 `kDrop`（`map.cpp:117`、测试 `tests:341-362`）。
- 限流：`Dispatch` 传的是 `IsReleaseInput(item.input)`（`win32.cpp:324`），
  定义见 `desktop_input_map.h:78-84` —— **不看 held**。因此**任意** key-up / 按钮 up /
  unicode up 都永久免令牌、免计数。

### 红证（探针）

```
unheld key-up: IsReleaseInput=1 IsHeldRelease=0
after 800 presses: dropped=1 next_press_allowed=0
1000000 unheld up events: allowed=1000000 dropped=1     <-- 100 万个未持有 up 全部放行
```

结论：任务书问的"未持有的 up 不受限流但仍受队列硬限"**成立**，但队列硬限只是**积压**上限，
不是速率上限：worker 每轮出队一条就 `SendInput` 一条（`win32.cpp:232-257, 433-446`），
队列被刷满时丢弃发生在**入队**侧，实际注入速率 = worker 排空速率。

### 放大分析（数量级）

1. 受限类（key-down / button-down / wheel / move）：会话 400/s、全局 1000/s
   是代码可证的硬上限。
2. 释放类：代码层面**无任何速率上限**。持续速率 = 1/(worker 循环 + `SendInput` 往返)，
   量级估计 10^4–10^5 evt/s（**估算，未实测**：不向本机桌面注入 10 万条事件做基准）。
   即相对 1000/s 全局上限至少放大 1–2 个数量级，算法上无界。
3. 队列是**所有会话共享**的（`win32.cpp:484`）。一个会话的 up 洪水会填满 1024 硬限，
   先驱逐其它会话的移动、再丢弃其它会话的按下（`map.cpp:107-118`），
   而全局桶从未对该会话收费 —— 全局公平性上限对释放类完全失效。默认
   `max_input_sessions=1`（`main.cpp:126`）时这是单会话把本机输入流刷爆；
   `--max-input-sessions 0` 时变成跨会话饿死。

### 二次放大：`pressed` 可被"限流丢弃的按下"污染

队列在**入队时**就 `TrackInput`（`map.cpp:170`），限流在**出队后**才丢（`win32.cpp:320-327`），
两者之间没有任何回撤。探针实测：

```
press admitted=1 pressed_keys=1
limiter allows the tracked press=0 dropped=1
held=1 hard_limit_decision=0        <-- 从未注入的按下，其 up 在满队列仍被 kAccept
```

后果：`win32.cpp:119-126` 与 `map.h:186-195` 宣称的"被丢弃的按下从未被记录为 held"只对
**队列硬限**成立，对**限流**不成立。攻击者可以只靠 400 次/s 的入队按下（其中大部分被限流丢弃）
把 `pressed` 填到 `KeyId` 值域上限：`scancode uint16 × extended bool` = 131 072 个键 + 5 个按钮
（`map.h:90-98`），即 131 077 个"held"条目（≈128 × 1024 硬限）。之后这些 up 全部
免队列硬限、免限流；`ReleaseSession` 又按 `pressed` 再追加同数量的合成 up
（`win32.cpp:207-229`），队列最坏上界是 `hard_limit + 2·|pressed|` 而不是文档写的
`hard_limit + |pressed|`（§1.5:137）。仍有限（≈13 万条），但与"只有当前按住的键才豁免"的设计不符，
比文档上界大两个数量级。

### 最小修法（推荐 A）

**A（语义正确，推荐）**：把"是否豁免"在入队时一次性定死并随队传递，限流只看这个标志：

1. `QueuedInput` 增加 `bool exempt_release`（`win32.cpp:83-86`）；`EnqueueLocked` 把
   `AdmitInput` 实际使用的 `held_release` 写进该字段（`win32.cpp:192-203`），
   `AppendReleasesLocked` 的合成 up 置 `true`（`win32.cpp:220, 227`）。
2. `Dispatch` 改为 `rate_limiter_.Allow(item.session_id, item.exempt_release, Clock::now())`
   （`win32.cpp:324`）。
3. `IsReleaseInput` 仍保留给"队列侧识别释放"，但不再是限流豁免的依据；`map.h:207-211`、
   `desktop_input.h:42-45`、doc §2.3:263-264 同步改为"只有 held release 免限流"。

代价：未持有的 up 也会被 400/1000 限流（这正是文档的承诺）；一次 up 洪水再也无法越过限流点。
合成 up（真实清物理状态）仍 `exempt_release=true`，不会因限流而卡键。

**B（最小改动、只改文档）**：保留 `IsReleaseInput`，把 §2.3:263-264 与
`desktop_input.h:42-45` 改成"所有 up 都不限流；队列硬限对未持有的 up 仍生效（只是积压上限）"，
并明确写出"单会话 up 速率无上界"。**不推荐**：§2.3 的限流目的就是"防单会话刷爆输入流"，
B 等于放弃该目标，且 131 077 的 `pressed` 上界与 `hard_limit + |pressed|` 的论证仍然误导。

## 5. 项 4 PASS — 移动是否绕过限流，实际上界

`Dispatch` 先 `Allow`（`win32.cpp:324`），通过后才把移动放进 `pending_moves_[sid]`
（`win32.cpp:328-333`），随后 `EmitDueMoves()`。三条发送路径
`EmitDueMoves` / `FlushSessionMove` / `FlushMoves`（`win32.cpp:291-318`）都直接 `Emit`
（`win32.cpp:433`），**不再经过 `Allow`**。但：

- 每个进入 `pending_moves_` 的移动都已在 `Allow` 花掉一个令牌；
- `pending_moves_[sid] = input` 是覆盖写，一个已放行的移动最多被 `Emit` 一次
  （`EmitDueMoves` 或 `FlushSessionMove` 之一，之后 erase）；
- 因此移动的注入速率 ≤ 已放行的移动数 ≤ 会话 400/s、全局 1000/s；worker 退出时
  `FlushMoves` 额外 ≤ `pending_moves_.size()`（≤ 会话数）。

**但 250 Hz 不是硬上限**：`FlushSessionMove`（`win32.cpp:304-310`）不看
`MoveDue()/kMoveInterval`，按键/按钮/滚轮（以及释放）插入时会立刻把待发移动打出去。
构造：t=0 放行移动 M1（`last_move_sent_` 为空 ⇒ 立即 Emit），t=1 ms 放行一个按键 ⇒
`FlushSessionMove` 再次 Emit 移动，瞬时 1000 Hz。定时路径确实 ≤250 Hz，但"输出上限 250 Hz"
（§1.5:133、§2.3:259）与代码不符（E7-c）。

## 6. 项 5：可观测

### 5a PASS — 双后端 `Stats()` 一致暴露

- Win32：`stats.dropped_rate_limited = rate_limiter_.dropped()`（`win32.cpp:161`），
  与 `injected/dropped_queue_full/send_failures` 同结构体（`desktop_input.h:47-52`）。
- Null：结构体同字段，恒 0 且注释说明"无队列故不限流"（`desktop_input_null.cpp:32-39`）；
  测试 `tests:687-709` 断言四个字段，基线绿。
- 该字段**只有** `tests:687-709` 的 null 路径被测；Win32 的接线
  （`win32.cpp:161`）没有测试覆盖（测试目标只链接 null 后端，`CMakeLists.txt:676-689`）。
  建议执行 AI 加一个"可注入假时钟/假 worker"的最小测试或至少编译期断言。

### 5b PASS — 不重复计数（按平台动作口径）

同一个平台动作只会计入其中一个：限流丢弃发生在出队之后（`win32.cpp:324-327`），
队列丢弃发生在入队时（`win32.cpp:193-201`），二者互斥。`kEvictMove` 计入被驱逐的旧移动，
与进入的新事件无关（`win32.cpp:194-196`）。**但**一次 RDP `InputEvent` 可翻译成两个平台动作
（`map.cpp:60-80`，移动+按钮）：移动被驱逐 → `dropped_queue_full++`，同事件的按钮被限流 →
`dropped_rate_limited++`，同一 RDP 事件在两个计数器里各出现一次。头文件只对 `injected`
说明了"per platform action"（`desktop_input.h:36-40`），两个 dropped 计数器没有说明口径
（E7-d）。

### 5c FAIL — 主机侧不可观测

`main.cpp:487-489` 打印 `input=on|off` 与 `input_max_sessions=N`，与 §2.1:208 一致（PASS）；
`main.cpp:641-655` 首次租约拒绝打一条 WARNING，与 §2.1:209-210 一致（PASS）。
但**全仓没有任何生产代码调用 `DesktopInputSink::Stats()`**：

```
PS> Select-String -Path src\*.cpp,src\server\*.cpp,tools\rtsc_server\*.cpp -Pattern "\.Stats\(\)"
（无命中；全仓唯一命中是 tests/test_desktop_input.cpp:702-705 的 null 后端断言）
```

因此 `dropped_rate_limited`（以及 `dropped_queue_full`、`send_failures`）在随仓发布的
`rtsc_server_host` 里**完全不可见**：不周期打印、不随会话数变化打印、退出也不打印。
§1.6:158-160 只承诺"以 `InputStats` 暴露"（API 层面成立），但本提交标题的"可观测"对运维面不成立。
另外 `lease_denied_reported` 是"首次一次"（`main.cpp:646-647`），打印的是首次拒绝时的计数
（几乎恒为 1），不会随真实拒绝数增长；`.opencode/plan.md:615` 写的"运行期每秒最多一条 lease-denied 汇总"
与代码不符（该文件不在本提交 diff 内，属计划漂移）。

最小修法：在 `main.cpp` 的服务循环里按"live/total 变化"或每 N 秒采样一次
`input_sink->Stats()`，仅在任一计数变化时 `log.line` 一条
`sessions: ... input_injected=... input_dropped_queue=... input_rate_limited=... input_send_failures=...`；
退出前再打一条终值。不改任何注入路径。

## 7. 项 6 FAIL — 文档回写漂移清单

逐条对照（行号为当前文件）：

| # | 文档 | 声称 | 代码事实 | 判定 |
|---|---|---|---|---|
| a | §1.5:136-137 | 只豁免 held release；队列上界 `hard_limit + pressed` | 队列判定与代码一致（`map.cpp:116-118`）；但 `pressed` 可含被**限流**丢弃的按下（探针 2），`AppendReleasesLocked` 再加 `|pressed|`（`win32.cpp:207-229`），真实上界 `hard_limit + 2·|pressed|`，`|pressed| ≤ 131 077` | 数字漂移 |
| b | §1.5:141-143 | "未持有的 keyup（重复 up，或被硬限丢弃的按下的 up）也不豁免" | 正确（`map.cpp:144-156`）；但漏掉"被**限流**丢弃的按下的 up 仍豁免" | 遗漏 |
| c | §1.5:133、§2.3:259 | 纯移动输出"上限 250 Hz" | `FlushSessionMove` 绕过 `kMoveInterval`，可瞬时 >250 Hz；受限类真实上限是 400/s（会话）/1000/s（全局） | 数字漂移（本提交前已存在，本提交未修正） |
| d | §1.6:158-162 | `InputStats` 暴露四计数；失败日志只在"首次/失败率>50% 持续 5 s/恢复"三态变化时输出 | 四计数成立；但 `LogFailure` 是"任意失败、每 5 s 至多一条"，没有 >50% 判定也没有"恢复"行（`win32.cpp:448-466`） | 漂移（本提交前已存在） |
| e | §2.3:263-264 | 释放不受限流，"且释放数量被该会话按住的键/按钮集合限界" | 前半句对；**后半句错**：`Dispatch` 用 `IsReleaseInput`，未持有 up 也免（100 万条实测全放行，`dropped` 不变） | **漂移（本提交引入的限流实现与既有文档冲突）** |
| f | §2.3:256-258 | "400 events/s / 1000 events/s"（"事件"口径） | 代码按**平台动作**扣令牌：一个 `kMouse` 移动+按钮事件扣 2 个令牌（`map.cpp:60-80` + `win32.cpp:118-129`），因此 2 动作事件的稳态速率只有 200/s | 口径漂移 |
| g | `desktop_input_map.h:221-223` | "a false result is expected to be counted by the caller（sink 加到 dropped_rate_limited）" | 实际 `Allow` 自己 `dropped_.fetch_add`（`map.cpp:203`），sink 只读 `dropped()`（`win32.cpp:161`）；照着注释实现会**真的**重复计数 | 注释漂移，应删 |
| h | `desktop_input.h:41` | `dropped_queue_full` 计数"events refused by the bounded injection queue" | 也包含被驱逐的旧移动（`win32.cpp:194-196`），且驱逐时进入的事件是接受的 | 措辞漂移 |
| i | §2.3:258 | 全局 1000 是"8 × 400 的 1/3" | 3200/3 ≈ 1067，代码 1000（31.25%），只是近似表述 | 可接受，建议写"约 1/3"或"3200 的 31%" |
| j | §2.1:208-210 | 启动行 `input=`/`input_max_sessions=`；首次租约拒绝一条 WARNING | 与 `main.cpp:487-489, 641-655` 一致 | PASS |

## 8. 项 7 PASS — 变异真实性（只在 %TEMP% 副本）

基线：`35 tests, 3759 checks, 0 failing`。

**变异 A：去掉释放豁免**（`Allow` 首行改为 `(void)is_release;`，其余不动）

```
FAIL tests/test_desktop_input.cpp:509  allowed == 5000 (got 0, want 5000)
FAIL tests/test_desktop_input.cpp:512  limiter.dropped() == 2 (got 5002, want 2)
[ FAIL ] desktop_input_rate_limit_release_is_exempt
35 tests, 3759 checks, 1 failing tests, 2 failed checks
```

**变异 B：速率设为无穷**（`Refill(global_, inf, ...)`、`Refill(session, inf, ...)`）

```
FAIL tests/test_desktop_input.cpp:488  allowed == 400 (got 401, want 400)
FAIL tests/test_desktop_input.cpp:489  limiter.dropped() == 2 (got 1, want 2)
[ FAIL ] desktop_input_rate_limit_session_bucket
FAIL tests/test_desktop_input.cpp:540  allowed == 1000 (got 1008, want 1000)
FAIL tests/test_desktop_input.cpp:541  limiter.dropped() == 9 (got 1, want 9)
[ FAIL ] desktop_input_rate_limit_global_bucket
FAIL tests/test_desktop_input.cpp:570  !limiter.Allow(1, false, t1)
[ FAIL ] desktop_input_rate_limit_global_drop_keeps_session_token
35 tests, 3759 checks, 3 failing tests, 5 failed checks
```

两个变异都按预期转红，且失败断言正是被变异的语义（不是超时/崩溃）。
**覆盖缺口**：变异 A 只打死直接传 `is_release=true` 的类级测试；
`Dispatch` 把 `IsReleaseInput` 接进 `Allow` 的那一行（`win32.cpp:324`）没有测试，
即"未持有 up 也被豁免"这个真实缺陷不会被任何现有测试发现（探针才是红证）。

## 9. 缺陷与最小修法汇总（按严重度）

| ID | 级别 | 位置 | 问题 | 最小修法 |
|---|---|---|---|---|
| E1 | 中高 | `win32.cpp:324` + `map.cpp:193-194` | 释放豁免用 `IsReleaseInput`，未持有 up 无速率上界；400/1000 硬上限对 up 类失效；文档 §2.3:263-264 的定界理由不成立 | 见 §4 修法 A（`QueuedInput.exempt_release` + `Allow` 读该标志）；同步改 §2.3 与两处头注释 |
| E2 | 中 | `map.cpp:170` / `win32.cpp:320-327` | 队列入队即 `TrackInput`，限流随后丢弃按下但不回撤，`pressed` 可被未注入的按下填到 131 077；held 豁免与"仅队列放行"不变式冲突；队列真实上界 `hard+2|pressed|` | 与 E1 同一处解决：E1 修法 A 之后，被限流拒绝的按下应在出队丢弃时从 `pressed` 撤掉，或（更稳）把限流判定前移到入队（`EnqueueLocked` 内、持 `mu_`），使"未放行就不入队、不 track"；若选后者，§2.3:252-254 的"出队后判定"要改，`InputRateLimiter` 需线程安全（加内部 mutex） |
| E3 | 中 | `win32.cpp:239, 268-274` | `Forget` 后同会话队列积压的 `Dispatch` 复活 `sessions_`；`pending_moves_` 不清；`last_move_sent_` 复活 ⇒ 长期运行下按断连次数无界增长 + 断开后仍动指针 | `QueuedInput` 增 `bool synthetic_release`；`ForgetReleasedSessionsLocked` 在锁内删除该 id 的**非合成**积压、`pending_moves_`、`last_move_sent_`，再 `Forget`（合成的 up 必须保留，否则卡键） |
| E4 | 低 | `server.cpp:2426-2428` | `ServeOne` 的 `Stop()`/`ScrubCredentials()` 不在 try/catch 内，`Close()` 非 noexcept（`include/rtsc/net/transport.h:66`），抛异常会跳过 `ReleaseInput()` ⇒ 租约槽 + 桶泄漏 | 与 `server.cpp:2351-2362` 相同：三步各自 try/catch（或 scope guard） |
| E5 | 低 | `desktop_input_map.h:221-223` | 注释说由 caller 计数，实际 `Allow` 自计 | 删除该从句，写明 "Allow 自己累加 dropped()" |
| E6 | 低 | `tools/rtsc_server/main.cpp:628-662` | 生产主机从不读 `Stats()`，限流/队列/发送失败在运维面不可见；租约 WARNING 的 count 是首次值 | 见 §6 5c |
| E7 | 低 | 文档 §1.5/§1.6/§2.3 等 | 见 §7 表（a–i） | 逐条改写；其中 e、f 必须与 E1/E2 的代码修法一起落 |

## 10. 复现方法（执行 AI / 复审可直接照做）

审计实际做法（可照抄；全部在 `%TEMP%` 内，工作树只读）：

1. 最小文件集复制：`include/`、`tests/`、`src/server/desktop_input_map.cpp`、
   `src/server/desktop_input_null.cpp`、`src/util/crash_guard.cpp`、`tools/rtsc_server/main.cpp`。
2. `build.bat`（放在副本的 `b\` 下；`%1`=输出名，`%2`=可选 map.cpp 所在副本根目录）：

```bat
@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul
set ROOT=%TEMP%\rtsc_rate_audit
set OUT=%1
set SRC=%2
if "%SRC%"=="" set SRC=%ROOT%
cl /nologo /std:c++20 /EHsc /W4 /WX /utf-8 /I"%ROOT%\include" /I"%ROOT%\tests" ^
   /DRTSC_SOURCE_DIR="\"%ROOT:\=/%\"" ^
   "%ROOT%\tests\test_desktop_input.cpp" "%SRC%\src\server\desktop_input_map.cpp" ^
   "%ROOT%\src\server\desktop_input_null.cpp" "%ROOT%\src\util\crash_guard.cpp" ^
   /Fe:"%ROOT%\b\%OUT%.exe" /Fd:"%ROOT%\b\%OUT%.pdb" /link dbghelp.lib
exit /b %ERRORLEVEL%
```

3. 基线：`build.bat base` → `base.exe` → `35 tests, 3759 checks, 0 failing tests`。
4. 变异 A：副本里 `Allow` 首行 `if (is_release) return true;` 改为 `(void)is_release;`。
   变异 B：两处 `Refill(..., kSessionEventsPerSecond/kGlobalEventsPerSecond, ...)`
   改为 `std::numeric_limits<double>::infinity()`（补 `#include <limits>`）。
   分别 `build.bat mutA <副本>` / `build.bat mutB <副本>`，失败集见 §8。
5. 探针：`probe.cpp` 用 `#define private public` 读 `sessions_.size()` 并跑 100 万次 up；
   `probe2.cpp` 串起 `AdmitInput` 与 `Allow` 证明"队列已 track、限流再丢"。
   两者只链接 `desktop_input_map.cpp`，不链接 sink。

## 11. 执行影响范围（供执行 AI，按 C0/影响范围测试）

- 代码：`src/server/desktop_input_win32.cpp`（E1/E2/E3：`QueuedInput`、`EnqueueLocked`、
  `AppendReleasesLocked`、`Dispatch`、`ForgetReleasedSessionsLocked`）；
  若选"限流前移到入队"，还要动 `include/rtsc/server/desktop_input_map.h` +
  `src/server/desktop_input_map.cpp`（`Allow` 线程安全化）；E4 只动 `src/server/server.cpp`。
- 测试：
  - `rtsc_desktop_input_tests`（主套件，已有 6 个限流/队列用例）；
  - `rtsc_server_tests`（`ReleaseInput`/租约/异常断开路径，E4）；
  - `rtsc_server_desktop_input` 编译（Win32 后端 C0；不能豁免）。
  - 新增用例建议：①未持有 up 在 burst 后必须被限流；②held up 仍豁免且不花令牌；
  ③被限流拒绝的按下不得让其 up 免队列硬限（若限流前移，则断言 `pressed` 不含它）；
  ④`Forget` 后派发同 id 积压不重建桶（需要一个只读的桶计数钩子，如
  `tracked_sessions()`，或测试内 `#define private public`）；⑤`ServeOne` 在 `Close()` 抛异常时
  仍调用 `ReleaseSession`（用已有 fake transport）。
- 文档：`docs/spec/input-injection-seam.md` §1.5/§1.6/§2.3 + `desktop_input.h:39-45` +
  `desktop_input_map.h:207-211, 221-223`。

## 12. 待互审判定点（审计 E → 审计 X）

1. E1 选"修法 A（held 标志随队传递）"还是"把限流前移到入队 + 限流器加锁"？
   前者不改 §2.3 的判定时机、改动更小；后者能同时消掉 E2，但把每事件一次
   `mu_` 竞争放回会话线程（8 会话量级，需评估）。
2. E2 的 `pressed` 上界 131 077 是否应作为设计值写进 §1.5，还是应把 `pressed` 限制为
   "Win32 实际能按下的键集"（例如只接受被映射过的 scancode）？
3. E3 的修法里"丢弃断开会话的非合成积压"是否改变既有语义边界（我认为应丢：
   输入是实时语义，且可避免断开后动指针；风险在合成 up 的保留）。
4. E7-c/e 是否算本提交的"文档回写"失败（e 是本提交实现与既有文档冲突，我判 FAIL；
   c/d 是既有漂移，我判"本提交未修正、需一并回写"）。