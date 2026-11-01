# 输入注入批 10：限流 / 可观测 / 文档侧审计（审计 G，独立稿）

- 对象提交：`63e3cc6`（"输入注入：限流前移与held语义、AdmitAndTrack纯函数、生命周期清理、Stats可观测、文档峰值口径"），父 `e6f57fd`。
- 只读：本文件是唯一写入。审计开始时 `git status --porcelain` 为空；审计收尾时工作树出现**批 11 执行中**的未提交改动（`docs/spec/input-injection-seam.md`、`include/rtsc/server/desktop_input.h`、`src/server/desktop_input_win32.cpp`、`tests/test_desktop_input.cpp`），非本审计所改，本审计未触碰（也不回退，遵守共享工作树禁令）。
- 红证环境：`%TEMP%\rtsc_b10_G`（仓库副本），MSVC 19.44，`/std:c++20 /EHsc /W4 /WX /permissive- /utf-8`。
- 基线：`40 tests, 9602 checks, 0 failing tests, 0 failed checks`（`base.exe` / `restored.exe`，exit=0）。
- C0：`desktop_input_win32.cpp` 与 `tools/rtsc_server/main.cpp` 各自 `cl /c /W4 /WX /permissive-` → exit=0（零错误零警告）。

## 进展清单

- [x] E1 四个分项用探针给出数值证据（未持有 up / held up / unicode up / 全局拒绝不扣会话令牌）
- [x] E5 重复计数路径逐条排查（`Allow` 自计数、`dropped_queue_full` 三个来源、`kEvictMove`）
- [x] E6 三个追问（`--once` 终值、刷屏频率上界、lease summary 去重）逐条读码 + 运行时终值
- [x] E7 六条逐条比对实现，列出残余漂移
- [x] 变异：去 held 豁免（限流侧 / 队列侧）与速率无穷均转红；恢复后转绿
- [x] 额外变异 mutC 暴露一处测试缺口（held up "不耗令牌" 未被任何用例钉住）
- [x] 批 11 验收判据 + mutC 确切变异点（新用例在 pristine 绿、在 mutC 红，见 §10）
- [ ] 与对端审计（`ses_e6a12ff22ffeOCGAtI9LBFGDR6`）交叉验证（对端审计 F 在途，父会话指示不再等待，按批 11 定案收口）

## 0. 结论速览

| 项 | 主题 | 判定 | 关键证据 |
|---|---|---|---|
| 1 | E1 限流前移与 held 语义 | **PASS** | probe9 [1]-[4] / probe11；`map.cpp:195`；`win32.cpp:211-215` |
| 2 | E5 计数口径（无重复计数） | **PASS** | probe10；`win32.cpp:193-227`；`map.cpp:203-205` |
| 3 | E6 可观测（三追问） | **PASS**（2 条低危保留项） | `main.cpp:608,620,640,660-665,698-708,709-712,721`；host 实跑终值 |
| 4 | E7 文档一致性 | **FAIL（低）** | 峰值口径未计合成 up；`dropped_queue_full` 定义漏 purge；"退出前终值"未限定正常退出；`Inject` 返回值口径过期（`:170`） |
| 5 | 变异真实性（指定两变异） | **PASS** | mutA / mutB 转红，restored 转绿；另 mutA2 转红 |
| 5+ | 额外：held up "不耗令牌" 测试缺口 | **FAIL（低）** | mutC（held up 仍豁免但扣令牌）`40/9602/0` **存活** |

---

## 1. E1：限流前移与 held 语义 — PASS

### 1.1 代码位置

- 声明：[READ:`include/rtsc/server/desktop_input_map.h:264-268`] `bool Allow(uint32_t session_id, bool held_release, Clock::time_point now);`，注释明确 `held_release` 必须是 `IsHeldRelease(input, pressed)`，不是 `IsReleaseInput(input)`。
- 实现：[READ:`src/server/desktop_input_map.cpp:191-195`] `Allow(..., bool held_release, ...)`，**唯一**早退是 `if (held_release) return true;`（`:195`）；其余 up 与按下同路径。
- 前移接线：[READ:`src/server/desktop_input_win32.cpp:211-215`] `AdmitAndTrack(state, session.pressed, input, [&](bool held_release){ return rate_limiter_.Allow(session_id, held_release, now); })`；`Inject()` 全程持 `mu_`（[READ:`win32.cpp:120-121`]），`Allow` 与队列共用同一临界区。
- 队列侧与限流侧使用同一 held 判定：[READ:`map.cpp:230`] `outcome.held_release = IsHeldRelease(input, pressed);` 先于 `AdmitInput`；[READ:`map.cpp:144-156`] `IsHeldRelease` 含 scancode+extended 身份与按钮集合。

### 1.2 数值证据（`%TEMP%\rtsc_b10_G\probe9.cpp` / `probe11.cpp`）

```
[BASH: probe9.exe]
[1] drain: allowed=800 extra_press=0 dropped=1 | 5000 unheld ups: IsHeldRelease=0 allowed=0 dropped=5001
[2] presses=799 held_ups_allowed=100000 dropped_delta=0 | press_after_100k_held_ups=1 second_press=0
[3] unicode up: IsHeldRelease=0 Allow=0 dropped=1
[4] global_denied=1 dropped=1 | next second session1 allowed=401 (401 = kept token, 400 = token was stolen)
[BASH: probe11.exe]
held_ups_allowed=100000 | fresh session press with 1 global token left=1 dropped=0
```

| 分项 | 结论 | 证据 |
|---|---|---|
| ① 未持有 up 被限流 | 5000 条全部拒绝（allowed=0），`dropped` 从 1 增至 5001 | probe9 [1] |
| ② held up 豁免且**不耗令牌** | 10 万条 held up 全放行、`dropped_delta=0`；会话仅剩的 1 个令牌仍可花（press=1，再 press=0）；全局仅剩 1 个令牌时新会话仍可花 | probe9 [2]、probe11 |
| ③ unicode up 受限 | `IsHeldRelease=0`、`Allow=0` | probe9 [3] |
| ④ 全局拒绝不扣会话令牌 | 全局耗尽后拒绝 1 条；1 s 后会话 1 仍能花 401 条（400 补充 + 保留的 1） | probe9 [4] |

**判定：PASS。** 行为与头文件/文档声称一致。

### 1.3 附：一处测试缺口（不计入 E1 行为判定，单列于 §5+）

`Allow` 的 held 早退若改为"仍豁免但扣令牌"，当前 40 个用例全绿（mutC 存活）。即"held up 不耗令牌"只有探针证明，**没有测试钉住**。最小修法见 §6.4。

---

## 2. E5：计数口径 — PASS

### 2.1 `Allow` 自计数、caller 不重复计数

- [READ:`src/server/desktop_input_map.cpp:203-205`] 拒绝分支唯一自增：`dropped_.fetch_add(1, ...)`，随后 `return false`。
- [READ:`include/rtsc/server/desktop_input_map.h:264-267`] "A refusal is counted here (`InputStats::dropped_rate_limited` reads `dropped()`); the caller must not count it again."
- [READ:`include/rtsc/server/desktop_input.h:41-48`] `dropped_rate_limited` 只描述"被限流器拒绝的平台动作"。
- 全仓调用点：`Allow(` 仅出现在 `win32.cpp:196`（合并移动快路径）、`win32.cpp:214`（`AdmitAndTrack` 回调）与测试；生产代码无第二处 `dropped_` 自增（[BASH: `Select-String src/**/*.cpp -Pattern "dropped_rate_limited|\.dropped\(\)|dropped_\.fetch_add"`] → 仅 `map.cpp:204`、`win32.cpp:174` 读）。
- 探针：10 条被限流的移动 → `dropped_delta=10`（每条恰好一次，无 caller 侧二次计数）。

```
[BASH: probe10.exe]
10 rate-limited moves: rate_limited=10 dropped_delta=10 (must be 1 per refusal, no caller-side second count)
evict decision: action=1 rate_limited=0 tracked_keys=1 dropped=0
```

### 2.2 两 dropped 计数是否对同一平台动作双计（含 `kEvictMove`）

`EnqueueLocked` 的控制流（[READ:`win32.cpp:187-230`]）是互斥的：

| 路径 | 代码 | 计数 |
|---|---|---|
| 合并移动且限流拒绝 | `:196` `if (!Allow(...)) return false;` | 只 `dropped_rate_limited`（`Allow` 内） |
| `AdmitAndTrack` 限流拒绝 | `:216` `if (outcome.rate_limited) return false;` | 只 `dropped_rate_limited`（`Allow` 内） |
| `kEvictMove` | `:218-221` 驱逐**旧移动** + `dropped_queue_full_++` | 旧移动记 `dropped_queue_full`；**入队的新动作**已由 `Allow` 放行（不记 rate） |
| `kDrop` | `:222-224` `dropped_queue_full_++` | 只 `dropped_queue_full`（该动作已过 `Allow`） |
| `kAccept` | `:225-226` | 不记丢弃 |

⇒ 同一个平台动作**不会**同时进入两个 dropped 计数；`kEvictMove` 计的是被驱逐的另一条旧移动，不是入队动作。**PASS。**

### 2.3 第三来源（不是双计，但定义未文档化）

[READ:`win32.cpp:307-315`] `ForgetReleasedSessionsLocked` 会清除会话的非合成积压，并对每条 `dropped_queue_full_++`。这些动作此前已过 `Allow`（花过令牌），只在这里记一次，不构成双计；但 `desktop_input.h:41-43` 的定义（"refused by the bounded injection queue / evicted"）没有涵盖"会话结束时被丢弃"这一来源 → 归入 E7 文档漂移（§4.7）。

---

## 3. E6：可观测 — PASS（含 2 条低危保留项）

### 3.1 代码位置

| 行 | 内容 |
|---|---|
| `main.cpp:607-619` | `log_input_stats(reason)`：读 `input_sink->Stats()`，打印 `input_injected= input_dropped_queue= input_rate_limited= input_send_failures=`，并更新 `printed_input` |
| `main.cpp:620-628` | `input_stats_changed()`：四计数任一变化才返回 true |
| `main.cpp:640` | `--once` 路径 `log_input_stats("final")` |
| `main.cpp:660-665` | `kInputStatsInterval=5s`、`kLeaseSummaryInterval=1s` |
| `main.cpp:698-708` | lease denied summary：`now >= next_lease_summary`（每 ≥1 s 至多一次）且 `lease_denied != reported_lease_denied` 才打印 |
| `main.cpp:709-712` | 周期 stats：每 ≥5 s 且计数变化才打印 |
| `main.cpp:721` | 正常退出前 `log_input_stats("final")` |

运行时证据（`build\Release\rtsc_server_host.exe` 已含本轮字符串）：

```
[BASH: rtsc_server_host.exe --allow-input --port 34567 --seconds 2 --test-pattern]
input=on input_max_sessions=1
run window elapsed; stopping
input stats (final): input_injected=0 input_dropped_queue=0 input_rate_limited=0 input_send_failures=0
exit=0
```

### 3.2 三追问

1. **`--once` 是否打印终值？** 是，`main.cpp:640`。但它在 `server.Stop()`（`:642`）**之前**取数；`ServeOne()` 已调用 `ReleaseInput()`（[READ:`src/server/server.cpp:2437-2440`]），合成 up 已入队而 worker 可能尚未发出 ⇒ 该"final"可能少计 ≤|pressed| 条（≤515）。周期路径的 `:721` 在 `Stop()+join()` 之后，但 sink worker 仍是异步的，同样存在这个有界滞后。
2. **高频会话下是否刷屏？频率上界？** 不会。stats ≤1 行/5 s（`:660,709-712`）；lease summary ≤1 行/s（`:661,698-708`）；`sessions:` 行只在 live/total 变化时打印（`:673-678`），与输入速率无关。上界 = 0.2 行/s + 1 行/s（lease）+ 会话抖动。
3. **lease summary 是否只在计数变化时打印、是否与首次 WARNING 重复？** 是只在 `lease_denied != reported_lease_denied` 时打印；首次 WARNING（`:686-697`）先把 `reported_lease_denied = lease_denied`（`:688`），同一轮或下一轮 summary 都不会重复同一计数；summary 文案前缀不同（`input lease denied summary:`），不是重复行。

### 3.3 保留项（低危，不改变 PASS）

- **(i) "final" 不是严格终值**：两条退出路径都在 sink worker 异步排空期间读 `Stats()`，可能少计 teardown 合成 up（有界 ≤|pressed|）。最小修法：给 `DesktopInputSink` 加 `WaitIdle()`/`Drain()`（Win32 在 `mu_` 下等 `queue_` 空且 `pending_moves_` 空；null 空实现），在 final 前调用；或明确文档"final 不含未排空的 teardown up"。
- **(ii) 无界模式 Ctrl+C 不打印 final**：`main.cpp` 只在 `bounded && now >= deadline`（`:713`）时跳出循环；全仓无 `SIGINT`/`SetConsoleCtrlHandler`（[BASH: `Select-String tools/rtsc_server/*.cpp src/util/crash_guard.cpp -Pattern "SIGINT|SetConsoleCtrlHandler|signal\("`] → 只有 `crash_guard.cpp:257` 的 `SIGABRT`）。默认无 `--seconds` 时用 Ctrl+C 终止 ⇒ 不打印 final。最小修法：装 `SIGINT`/`SIGBREAK` 置停止标志，让主循环跳出并走 `:719-721`；同时把 `seam.md:168` 的"退出前"限定为"正常退出（`--seconds` 到期或 `--once`）"。

---

## 4. E7：文档一致性 — FAIL（低）

逐条比对 `docs/spec/input-injection-seam.md` 与 `63e3cc6` 实现。先说明一个流程事实：**`63e3cc6` 本身没有改文档**——[BASH: `git diff --name-only e6f57fd 63e3cc6`] 只列 7 个代码/测试文件；`git diff --stat e6f57fd 63e3cc6 -- docs/` 为空。文档峰值口径的更新实际落在 `e6f57fd`（"记忆"提交）。提交信息"文档峰值口径"与提交内容不符（低危流程项，不影响代码）。

### 4.1 ① `seam.md:137` 峰值口径 `1024+515=1539`

| 声称 | 代码事实 | 判定 |
|---|---|---|
| `hard_limit = 1024` | [READ:`win32.cpp:78`] `kMaxQueue = 256`；[READ:`win32.cpp:83`] `kHardQueueLimit = 4 * kMaxQueue` = 1024 | PASS |
| `pressed` 上界 510 键 = 255×0xE0 | [READ:`server.h:229`] wire `uint8_t scancode`；[READ:`map.cpp:39`] 零码丢弃；[READ:`map.cpp:127`] `KeyId{scancode, extended}` ⇒ 255×2=510 | PASS（文档已写明推导） |
| `+ 5 按钮` | [READ:`server.cpp:589-598`] `DecodePointerButtons` 只写 1..5；[READ:`map.cpp:135-141`] 按 `button` 记账 ⇒ 5 | PASS |
| `peak(queue) ≤ 1024+515 = 1539` | **对端可入队事件**成立（饱和引理 `:138`）；但 `AppendReleasesLocked` 把合成 up **直接 push**、不过 `DecideEnqueue`（[READ:`win32.cpp:232-254`]），且 purge 明确保留 `synthetic`（[READ:`win32.cpp:307-315`]）⇒ 队列可超过 1539（每次 `ReleaseSession` 追加 ≤515，最多"会话数×515"条可叠加） | **FAIL（低）**：数值/推导正确，但作为 `peak(queue)` 的全局上界不成立 |

**最小修法（文档）**：把 `seam.md:137` 改为"对端可入队事件的峰值 ≤ 1024+515=1539；`ReleaseSession`/`Shutdown` 补发的合成 up 绕过队列策略，额外 ≤ 会话数×515，故总队列峰值 = 1539 + 合成 up"；`win32.cpp:26-27` 的同类注释同步限定。

同一根因还影响 `seam.md:138` 的**饱和引理**：`size > soft_limit ⇒ 队列内无纯移动` 在合成 up 存在时不成立——队列在 size=256 且含纯移动时，`ReleaseSession` 追加 ≤515 条 synthetic up 即可让 `size>soft` 同时仍有移动（[READ:`win32.cpp:232-254,307-315`]）。硬限结论（`kDrop` 不会被 evict 绕过）仍成立（下一批按下会先吃掉那条移动、size 不变，随后按 hard 增长到 1024 后 drop），但引理表述需加"对端可入队事件"限定。

> 证据等级：读码 + 算术（`AppendReleasesLocked` 无上限 push 是确定的）；未做运行时探针，因为实例化 Win32 sink 会向本机真实注入输入。归入 W5 的"读码证据"。

### 4.2 ② `seam.md:133` 移动速率表述 — PASS

[READ:`seam.md:133`] 定时路径每 4 ms（250 Hz）、同会话按键/按钮/滚轮立即 flush、瞬时可高于 250 Hz、移动同样受 §2.3 限流。
实现：[READ:`win32.cpp:84`] `kMoveInterval=4ms`；[READ:`win32.cpp:348-354`] `FlushSessionMove` 不看 `MoveDue()`，直接 `Emit`；[READ:`win32.cpp:193-199`] 合并移动也过 `Allow`。一致。

### 4.3 ③ `seam.md:143-144` 未持有 up 受限 — PASS

[READ:`seam.md:143-144`] "未持有的 keyup 也不豁免队列硬限（重复 up，或被硬限/限流丢弃的按下的 up）…这些 up 同时也**不免限流**"。
实现：[READ:`map.cpp:111-118`] 仅 `incoming_is_held_release` 越硬限；[READ:`map.cpp:230-234`] 限流先于 `AdmitInput`，被限流的按下不 track（`map.cpp:170` 只在 `action != kDrop` 时 track）⇒ 其 up 不是 held，限流与硬限都适用。probe9 [1]/[3] 数值一致。

### 4.4 ④ `seam.md:164-168` 失败日志 — PASS

[READ:`seam.md:163-164`] "任意一次失败后，若距上一条失败日志已满 5 s 就打印一行；没有'失败率 >50% 持续 5 s'的判定，也没有'恢复'行"。
实现：[READ:`win32.cpp:489-507`] `LogFailure`：首次立即打印，之后 `now - last_failure_log_ >= kFailureLogInterval`（[READ:`win32.cpp:85`] 5 s）才打印；无失败率判定、无恢复行。一致。

### 4.5 ⑤ `seam.md:259-282` §2.3 全节 — PASS

| 文档行 | 声称 | 代码 |
|---|---|---|
| `:259-262` | 在 `Inject()` 内、与队列同一临界区、`steady_clock`、入队前判定 | [READ:`win32.cpp:120-121,187-215`]；[READ:`map.cpp:174-189`] |
| `:264-265` | 400 动作/s、burst 800 | [READ:`map.h:259-260`] |
| `:266-267` | 全局 1000 动作/s、burst 2000、"约 1/3" | [READ:`map.h:261-262`]；3200/3≈1067，1000=31.25%，"约"可接受 |
| `:268-269` | 平台动作口径，move+button 扣 2、稳态 200/s | [READ:`map.cpp:64-79`] 一次 kMouse 可产 2 个动作 |
| `:270-272` | 移动 250 Hz + 立即 flush | 同 §4.2 |
| `:273-275` | 超限丢弃 + 计数、不排队、不断连、不逐事件打日志、同一动作只记一个计数器 | [READ:`win32.cpp:216-227`]；[READ:`map.cpp:203-205`] |
| `:276-279` | 仅 held release 免限流且不耗令牌；未持有 up 不免 | [READ:`map.cpp:195`]；probe9 [2][3][4]、probe11 |
| `:280-281` | 合成 up 绕过 `Inject()`，不受队列策略/限流 | [READ:`win32.cpp:232-254`]（直接 push） |
| `:282` | 全局拒绝不扣会话令牌 | [READ:`map.cpp:200-208`]；probe9 [4] |
| `:283-285` | 只有一把锁；`Allow`/`Forget` 在锁内；`Stats()` 只读原子 | [READ:`win32.cpp:545-547`]；[READ:`win32.cpp:262-263,297-301`]；[READ:`map.cpp:216-218`] |

### 4.6 ⑥ `Allow` 自计数口径 — PASS

[READ:`map.h:264-267`] 与 [READ:`desktop_input.h:41-48`] 均写明"拒绝由 `Allow` 计数、caller 不再计"；实现 `map.cpp:203-205` 一致；probe10 每条拒绝恰好 +1。

### 4.7 残余漂移清单（FAIL 项）

| # | 位置 | 漂移 | 最小修法 |
|---|---|---|---|
| a | `seam.md:137` / `:138` / `win32.cpp:26-27` | 峰值 `1539` 与饱和引理 `size>soft ⇒ 无纯移动` 都未计合成 up；`AppendReleasesLocked` 无上限 push 且 purge 保留 synthetic ⇒ 可超过/可同时有移动 | 限定为"对端可入队事件"，并补"合成 up 额外 ≤ 会话数×515" |
| b | `desktop_input.h:41-43` | `dropped_queue_full` 定义只写"queue 拒绝/驱逐旧移动"，漏了 `ForgetReleasedSessionsLocked` 的会话结束 purge（[READ:`win32.cpp:307-315`]） | 定义追加 "or discarded when their session is released"；`seam.md` §1.5/§2.3 可补一句 |
| c | `seam.md:168` | "退出前再打印一条 (final) 终值"未限定；无界模式 Ctrl+C 无 final（§3.3-ii） | 改为"正常退出（`--seconds` 到期或 `--once`）前"；或补 SIGINT 处理 |
| d | `seam.md:170` | "`Inject` 返回 false"过期：`Inject` 是 `void`（[READ:`desktop_input.h:71`]；[READ:`server.cpp:820`] 忽略返回值；`win32.cpp:120` / `null.cpp:24` 均 `void`） | 改为"`Inject` 无返回值；丢弃只经计数可见，会话不做重传" |

注：`seam.md:21`/`:52`/`:75`/`:99` 的 `bool Inject` 位于明确标注"设计草案，不落入产品代码"的 §1.3（`:54`）或历史裁决段，**不计**为本批漂移；只有 §1.6 的实现描述 `:170` 是可执行漂移。

---

## 5. 变异真实性 — PASS（指定两变异）

副本：`%TEMP%\rtsc_b10_G\{mutA,mutA2,mutB,mutC}`；构建命令 `build.bat <out> <srcRoot>`（含 `/W4 /WX`，均 exit=0）。

### 5.1 变异 A：去掉限流侧 held 豁免

`mutA`：`map.cpp:195` `if (held_release) return true;` → `(void)held_release;`

```
[BASH: mutA.exe]
FAIL tests/test_desktop_input.cpp:641  allowed == 5000 (got 0, want 5000)
FAIL tests/test_desktop_input.cpp:644  limiter.dropped() == 2 (got 5002, want 2)
[ FAIL ] desktop_input_rate_limit_release_is_exempt
FAIL tests/test_desktop_input.cpp:671  limiter.Allow(1, IsHeldRelease(KeyUp(0x1D), pressed), t0)
[ FAIL ] desktop_input_rate_limit_unheld_release_is_limited
40 tests, 9602 checks, 2 failing tests, 3 failed checks
```

### 5.2 变异 A2：去掉队列侧 held 豁免（补充，非任务指定）

`mutA2`：`map.cpp:116` `if (state.incoming_is_held_release) return kAccept;` → `(void)...;`

```
[BASH: mutA2.exe]
FAIL tests:335/337  desktop_input_queue_accepts_held_release_at_hard_limit
FAIL tests:379/380  desktop_input_queue_held_release_is_accepted_and_untracked
FAIL tests:442/443  desktop_input_queue_held_button_release_is_exempt
FAIL tests:521/524  desktop_input_queue_rate_gate_gets_held_release_flag
40 tests, 9602 checks, 4 failing tests, 8 failed checks
```

### 5.3 变异 B：速率设无穷

`mutB`：`map.cpp:197,199` 两处 `Refill` 的 per_second → `std::numeric_limits<double>::infinity()`。

```
[BASH: mutB.exe]
FAIL tests:620/621  desktop_input_rate_limit_session_bucket (401/1, want 400/2)
FAIL tests:706/707  desktop_input_rate_limit_global_bucket (1008/1, want 1000/9)
FAIL tests:736      desktop_input_rate_limit_global_drop_keeps_session_token
40 tests, 9602 checks, 3 failing tests, 5 failed checks
```

### 5.4 恢复绿

```
[BASH: restored.exe]  40 tests, 9602 checks, 0 failing tests, 0 failed checks   exit=0
```

**判定：PASS。** 两个指定变异均使目标用例转红；恢复 pristine 后转绿。

### 5+ 额外变异 C：held up 仍豁免但**扣令牌**（测试缺口）

`mutC`：`map.cpp:195` → 先 `Refill` 两个桶、各 `-= 1.0`、再 `return true;`

```
[BASH: mutC.exe]  40 tests, 9602 checks, 0 failing tests, 0 failed checks   <-- 存活
[BASH: probe9c.exe]（probe9 链到 mutC 的 desktop_input_map.cpp）
[2] presses=799 held_ups_allowed=100000 dropped_delta=0 | press_after_100k_held_ups=0 second_press=0
    （pristine 同一探针 press_after_100k_held_ups=1）
```

**根因**：现有用例只验证"held up 在**空桶**下仍放行"（`tests:639`、`tests:671`），空桶扣不扣令牌都放行；没有用例验证"桶里还有令牌时，held up 不得把令牌花掉"。**最小修法（测试）**：在 `tests/test_desktop_input.cpp` 增一条（或扩展 `desktop_input_rate_limit_release_is_exempt`）：

```
// 799 presses -> session bucket has exactly 1 token left
for (int i = 0; i < 799; ++i) CHECK(limiter.Allow(1, false, t0));
for (int i = 0; i < 100; ++i) CHECK(limiter.Allow(1, true, t0));  // held ups
CHECK(limiter.Allow(1, false, t0));   // the kept token is still spendable
CHECK(!limiter.Allow(1, false, t0));  // and only one token was left
```

该用例在 mutC 下第二/第三条必红，在 pristine 下绿。

---

## 6. 缺陷与最小修法汇总

| ID | 级别 | 位置 | 红证 | 最小修法 |
|---|---|---|---|---|
| E7-a | 低 | `seam.md:137`、`:138`、`win32.cpp:26-27` | 读码：`win32.cpp:232-254` 无上限 push；`307-315` 保留 synthetic | 限定"对端可入队事件峰值/饱和引理"，补合成 up 项 |
| E7-b | 低 | `desktop_input.h:41-43` | 读码：`win32.cpp:310` purge 计入 `dropped_queue_full` | 定义补"会话结束时丢弃" |
| E7-c | 低 | `seam.md:168`、`main.cpp:713-722` | 无 SIGINT 处理；Ctrl+C 不打印 final | 限定"正常退出"或补 SIGINT |
| E7-d | 低 | `seam.md:170` | `Inject` 是 `void`（`desktop_input.h:71`；`server.cpp:820` 忽略返回值），文档称"返回 false" | 改为"`Inject` 无返回值；丢弃只经计数可见，会话不做重传" |
| E6-i | 低 | `main.cpp:640,721` | 读码：sink worker 异步，final 可能少计 teardown up | 加 `WaitIdle()` 或在文档说明 |
| E1-T | 低 | `tests/test_desktop_input.cpp` | mutC `40/9602/0` 存活 | 补"held up 不耗令牌"用例（§5+） |

**不构成本批 FAIL 的观察（W5）**：
- `seam.md:265` "交互式打字 < 20 动作/s、快速拖拽 + 移动合并后 < 300 动作/s" 是设计估计，代码不约束；未实测。
- `desktop_input_map.h:81-87` 的 `IsReleaseInput` 已不再被生产代码使用（仅测试引用），属可清理的死代码；不影响语义。
- `seam.md:137` 的"探针 774 次违反瞬时公式"沿用上一轮探针结论，本轮未重跑。

---

## 7. 复现方法

1. 副本：`include/`、`tests/`、`src/server/desktop_input_map.cpp`、`src/server/desktop_input_null.cpp`、`src/util/crash_guard.cpp`、`tools/rtsc_server/main.cpp` → `%TEMP%\rtsc_b10_G`。
2. 构建（先 `call vcvars64.bat`）：
   ```
   cl /nologo /std:c++20 /EHsc /W4 /WX /utf-8 /I<root>\include /I<root>\tests
      /DRTSC_SOURCE_DIR="<root 正斜杠>"
      <root>\tests\test_desktop_input.cpp <src>\src\server\desktop_input_map.cpp
      <root>\src\server\desktop_input_null.cpp <root>\src\util\crash_guard.cpp
      /Fe:<root>\b\<out>.exe /link dbghelp.lib
   ```
3. 探针：`probe9`（E1 四项）、`probe10`（E5 计数）、`probe11`（held up 不耗全局令牌）。
4. 变异：`mutA`（限流侧 held 豁免）、`mutA2`（队列侧）、`mutB`（速率无穷）、`mutC`（held up 扣令牌，存活）。
5. C0：`cl /c /W4 /WX /permissive- /EHsc` 分别编译 `desktop_input_win32.cpp`、`main.cpp` → exit=0。
6. 主机终值：`rtsc_server_host.exe --allow-input --port 34567 --seconds 2 --test-pattern`。

---

## 8. 待与对端审计交叉验证的问题

1. **mutC 存活**：`held up 仍豁免但扣令牌` 在当前 40 用例下全绿。请独立复现；若同意，这是"不耗令牌"语义的测试缺口（E1-T）。
2. **峰值 1539 的完整性**：`AppendReleasesLocked`（`win32.cpp:232-254`）绕过 `DecideEnqueue`，purge 又保留 synthetic（`307-315`）⇒ `peak(queue) ≤ 1539` 作为全局上界不成立。请指出我是否漏了某处对合成 up 的数量/时机约束；若没有，E7-a 成立。
3. **`--once` final 的时点**：`main.cpp:640` 在 `server.Stop()` 之前取数，且 sink worker 异步；两条退出路径的 final 都可能少计 teardown up。请复核是否接受为低危保留项，还是要求加 `WaitIdle()`。
4. **无界模式 Ctrl+C 无 final**：全仓无 SIGINT 处理；`seam.md:168` "退出前"是否应限定为正常退出。
5. **重复计数**：我判定 `dropped_queue_full` 与 `dropped_rate_limited` 对同一动作互斥（含 `kEvictMove` 与 purge）。请用不同路径挑战该结论。
6. **E7 其他漂移**：`seam.md` §1.5/§1.6/§2.3 是否还有我漏掉的表述（尤其 `dropped_queue_full` 的 purge 来源、`dropped_unsupported` 的覆盖范围）。

---

## 9. 最终判定（本稿）

- **E1 PASS**（行为正确，probe 数值完整）；附测试缺口 E1-T（低）。
- **E5 PASS**（无重复计数；purge 来源只影响文档定义）。
- **E6 PASS**（三个追问均满足；2 条低危保留项：final 时点、Ctrl+C 无 final）。
- **E7 FAIL（低）**：峰值口径未计合成 up；`dropped_queue_full` 定义漏 purge；"退出前终值"未限定；`seam.md:170` 的 `Inject` 返回值口径过期。
- **变异真实性 PASS**（mutA/mutA2/mutB 转红，restored 转绿）。

通过门槛建议：E7-a/b/c/d 为纯文档/注释改动（最小）；E1-T 为一条测试；E6-i 可选。上述修完后本批限流/可观测/文档侧可盖章。

---

## 10. 批 11 验收判据（供执行 AI / 复核审计直接勾选）

> 范围与 `.opencode/plan.md:624-651`「批 11 定案」一致：仅文档/注释 + 1 条测试，**不动产品逻辑**。每条均为"给定-当-则"，复核时逐条勾选；未勾选即未收口。

### 10.1 文档 / 注释

- [ ] **E7-a1（峰值两段式）** 给定 `docs/spec/input-injection-seam.md:137` 与 `src/server/desktop_input_win32.cpp:26-27`；当按批 11 改写；则文本**同时**含：
  - (i) `peak(queue) ≤ kHardQueueLimit + |pressed|@饱和 = 1024 + 515 = 1539`，并限定为"**对端可入队事件**"；
  - (ii) `+ Σ_会话 |pressed| ≤ 会话数 × 515`（合成 up：`AppendReleasesLocked` 直推、不受队列上限；purge 保留 `synthetic`）；
  - (iii) 明确"不得读作瞬时不变式"（释放后 queue=1534 / pressed=0 的探针事实）。
- [ ] **E7-a2（饱和引理限定）** 给定 `seam.md:138`；当加"对端可入队事件"限定；则不再无条件声称 `size > soft_limit ⇒ 队列内无纯移动`（合成 up 可使其不成立），但保留"硬限 `kDrop` 不会被 `kEvictMove` 绕过"的结论。
- [ ] **E7-b（purge 计入）** 给定 `include/rtsc/server/desktop_input.h:41-43`；当补 `dropped_queue_full` 定义；则文本明确含"会话结束时 purge 的排队项"（`win32.cpp:310` 路径），不再只写"queue 拒绝 / 驱逐旧移动"。
- [ ] **E7-c（final 限定）** 给定 `seam.md:168`；当改写；则写明仅"正常退出（`--seconds` 到期或 `--once`）"打印 `(final)`，且写明无界模式 Ctrl+C 不打印（`main.cpp:713-722` 无 SIGINT 处理）。
- [ ] **E7-d（删返回值口径）** 给定 `seam.md:170`；当删除"`Inject` 返回 false"；则全段不再声称 `Inject` 有返回值（`desktop_input.h:71` 为 `void`；`server.cpp:820` 忽略返回值）。

### 10.2 测试（E1-T）

- [ ] **新用例存在** 给定 `tests/test_desktop_input.cpp`；当新增 `RTSC_TEST(desktop_input_rate_limit_held_release_keeps_token)`；则用例体与 §10.3 等价（799 presses → 100 held ups → 保留令牌仍可花）。
- [ ] **新用例在 pristine 绿** 给定未变异实现；当运行该用例；则 `desktop_input_rate_limit_held_release_keeps_token` 为 OK，且整套 `0 failing`。
- [ ] **新用例在 mutC 红** 给定 §10.4 的 mutC 变异；当运行该用例；则必须在"保留令牌仍可花"的 `CHECK(limiter.Allow(1, false, t0))` 处 **FAIL**。
- [ ] **恢复绿 + 双证** 给定撤回 mutC、恢复原式；当重跑；则同一用例 OK、整套 `0 failing`；并按 plan 用 `Get-FileHash` 给出恢复前后双证。

### 10.3 新用例参考实现（已在本轮 `%TEMP%` 副本实测）

```cpp
RTSC_TEST(desktop_input_rate_limit_held_release_keeps_token) {
    // A held release is exempt AND spends no token: the one token a session
    // kept must still be spendable after a burst of held ups. Without this
    // check a limiter that exempts held ups but still charges them is
    // indistinguishable from the correct one (mutation mutC survives).
    InputRateLimiter limiter;
    const RateClock::time_point t0 = RateTime(8000);  // 8000 未被其它用例占用
    for (int i = 0; i < 799; ++i) {
        CHECK(limiter.Allow(1, false, t0));  // burst 800 -> exactly 1 left
    }
    PressedInputs pressed;
    pressed.keys.insert(KeyId{0x1D, false});
    const size_t dropped_before = limiter.dropped();
    for (int i = 0; i < 100; ++i) {
        CHECK(limiter.Allow(1, IsHeldRelease(KeyUp(0x1D), pressed), t0));
    }
    CHECK_EQ(limiter.dropped(), dropped_before);  // nothing was refused
    CHECK(limiter.Allow(1, false, t0));           // the kept token survived
    CHECK(!limiter.Allow(1, false, t0));          // and it was only one token
}
```

实测（`%TEMP%\rtsc_b10_G`，MSVC 19.44，`/W4 /WX`）：

```
[BASH: newtest.exe]   (pristine + 新用例)
[ RUN  ] desktop_input_rate_limit_held_release_keeps_token
[  OK  ] desktop_input_rate_limit_held_release_keeps_token
41 tests, 10504 checks, 0 failing tests, 0 failed checks      exit=0

[BASH: newtestC.exe]  (mutC + 新用例)
[ RUN  ] desktop_input_rate_limit_held_release_keeps_token
  FAIL ...\tests\test_desktop_input.cpp:664  limiter.Allow(1, false, t0)
[ FAIL ] desktop_input_rate_limit_held_release_keeps_token
41 tests, 10504 checks, 1 failing tests, 1 failed checks
```

> 行号 664 是**本轮副本**插入位置的行号；执行 AI 请按用例名与"kept token survived"注释定位，不要按固定行号。

### 10.4 mutC 确切变异点（执行 AI 复现用）

- 文件：`src/server/desktop_input_map.cpp`
- 函数：`InputRateLimiter::Allow`（`:191-210`）
- 行：`:195`
- 原式：

```cpp
    if (held_release) return true;
```

- 新式（语义：仍不被限流拒绝，但**两桶各扣 1 令牌**）：

```cpp
    if (held_release) {
        Refill(global_, kGlobalEventsPerSecond, kGlobalBurst, now);
        Bucket& held_session = sessions_[session_id];
        Refill(held_session, kSessionEventsPerSecond, kSessionBurst, now);
        held_session.tokens -= 1.0;
        global_.tokens -= 1.0;
        return true;
    }
```

注意：临时变量命名用 `held_session`，不要复用后面的 `session`（`map.cpp:198`），否则在 `/W4 /WX` 下可能触发变量遮蔽告警/错误。

- 预期：`desktop_input_rate_limit_held_release_keeps_token` 在"the kept token survived"处红；`desktop_input_rate_limit_unheld_release_is_limited` 等旧用例**仍绿**（mutC 在全套旧 40 用例下 `40/9602/0` 存活，已验证）。
- 恢复原式后：新用例绿、全套 `41/10504/0`（已验证）。

### 10.5 收口门（与 plan 一致）

- [ ] `cmake --build build --config Release` → 0 error / 0 warning。
- [ ] `ctest --test-dir build -C Release` → 63/63。
- [ ] mutC 红 → 恢复绿（含 `Get-FileHash` 双证）。
- [ ] 文档与代码逐条对照，无"文档说 X、代码是 Y"的句子。

**本稿任务到此完成**：E1/E5/E6 PASS，E7 FAIL（低，4 处文档/注释）+ E1-T（低，1 条测试）；无产品逻辑改动建议。对端审计 F 在途，按父会话指示不再等待，批 11 以本节判据收口。
