# 输入注入审计 D：held-release 是否真正定界队列硬上限（commit `27cf199`）

## 0. 范围、基线与方法

| 项 | 值 |
|---|---|
| 被审提交 | `27cf1998a8e78f5b280ffccf2970e3fa5350ffaf`（父 `334d5a1`） |
| 审计对象 | 上一轮 F1 复验：`queue_` 硬上限是否被 held-release 豁免定界 |
| 工作树 | 只读。仓库内唯一写入是本文件（`docs/spec/input-lease-review-D.md`）。另见审计 E 的 `docs/spec/input-rate-limit-review-E.md`（未提交，他人产物） |
| 构建/变异环境 | `%TEMP%\opencode\auditD_lease\`：`git archive 27cf199` 纯净副本 `build_clean`（VS 17 2022 / x64 / Release / `/W4 /WX /permissive-`）；变异只改副本，禁止改工作树 |
| 方法 | ①逐行读实现与所有 `push_back` 点；②用**被审代码本体**（`src/server/desktop_input_map.cpp` + 真实 `AdmitInput/DecideEnqueue/IsHeldRelease/TrackInput`）写探针复现 sink 的 `EnqueueLocked` 决策，测峰值；③变异红/绿；④与审计 E 交叉质证 |

基线（纯净副本，`27cf199` 原样）：

```
[BASH: %TEMP%\opencode\auditD_lease\build_clean\Release\rtsc_desktop_input_tests.exe]
35 tests, 3759 checks, 0 failing tests, 0 failed checks   exit=0
```

## 1. 结论总表

| 要点 | 结论 | 一句话依据 |
|---|---|---|
| 1. 上界证明（所有 `push_back` 有界） | **PASS（有界）/ 公式需改写** | 真实不变式是**峰值** `queue_ ≤ hard_limit + 515`；任务给的字面公式 `queue_ ≤ hard + |pressed| + pending_moves` 作为**瞬时**不变式被探针证伪 774 次（释放后 `queue=1534, pressed=0`）。文档 `input-injection-seam.md:137` 的表述同病 → D-A（文档 FAIL） |
| 2. `pressed` 是否可能无界 | **PASS（有界 515）** | `InputEvent::scancode` 是 `uint8_t`（`server.h:229`），快路径 1 字节（`server.cpp:1925`）、慢路径只取低字节（`server.cpp:1826`）→ `KeyId` 值域 = 255×2 = 510，按钮 wire 上只产 1..5（`server.cpp:589-599`）→ 上限 **510+5=515**。探针 `wire_reachable_presses=510 pressed_keys=510`。**恶意对端无法伪造 65536 个 scancode** |
| 3. `IsHeldRelease` 与 `TrackInput` 键身份互逆 | **PASS** | 两者都用 `KeyId{input.scancode, input.extended}`，且都对 `unicode != 0` 早退；插入/擦除对称（`desktop_input_map.cpp:121-142` vs `:144-156`）。附 `extended1` 不参与身份（既有漂移，D-E） |
| 4. 其它丢弃点是否吞掉 held release | **PASS** | 仓库无 `IntegrityCheck` 符号；真实过滤点是 `IsInjectable`（`server.cpp:814-821`）与未知 eventCode 中止（`:2007-2019`）。前者不可能拦 held up（held up 的 press 曾被接受⇒会话必已持租）；后者会吞同 PDU 后续 up，但不永久卡键（teardown `AppendReleasesLocked` 兜底） |
| 5. 变异真实性 | **目标测试 PASS / 覆盖缺口 FAIL** | "track 提前"变异下 `desktop_input_queue_dropped_press_is_not_tracked` 必红（3 checks），恢复即绿；但 **M3（extended 身份）与 M4（evict 路径 track）变异全绿**，且 **`desktop_input_win32.cpp` 不在任何测试 target 内**（CMake `:676-682,691,704`）→ 本提交的核心接线零测试覆盖 |
| 交叉：审计 E 的 E1（限流豁免不看 held） | **我确认 FAIL（中）** | 探针：空 `pressed` 的 key-up `IsReleaseInput=1`，耗尽 burst 后 5000 条未持有 up 全部放行、`dropped` 不变；`input-injection-seam.md:263-264` 的"释放数量被 pressed 限界"是假陈述 |
| 交叉：审计 E 的 E2（限流丢 press 不回撤 `pressed`） | **FAIL 成立但严重度降为低** | 现象真实；但 E 报的 131,077 上界**不成立**，实际 515，队列峰值上界仍为 1539（见 §7 Q2） |
| 交叉：审计 E 的 E3（断连桶/移动泄漏） | **FAIL 成立，严重度低** | `pending_moves_` 由 `EmitDueMoves` 在 ≤4 ms 内自排空（`desktop_input_win32.cpp:291-302`），"断开后仍会动指针"≤1 次；桶泄漏 = 每连接 1 个 `Bucket` |

## 2. 要点 1：严格上界证明

### 2.1 决策函数与 `push_back` 全表

`DecideEnqueue`（`src/server/desktop_input_map.cpp:107-119`）的优先级：

```
107 size < soft                      -> kAccept          // 唯一"无条件增长"分支
109 has_movable_move                 -> kEvictMove       // 增长 0
110 incoming_is_move                 -> kDrop
116 incoming_is_held_release         -> kAccept          // 唯一"越过硬限"分支
117 size >= hard_limit               -> kDrop
118                                  -> kAccept
```

`queue_` 的全部增长点（`src/server/desktop_input_win32.cpp`）：

| 位置 | 调用 | 是否受 `DecideEnqueue` 约束 | 上界 |
|---|---|---|---|
| `:203` `queue_.push_back` | `EnqueueLocked`（`kAccept` / `kEvictMove` 之后） | 是 | §2.2 定理 |
| `:220` `queue_.push_back` | `AppendReleasesLocked`（键 up，teardown 专用） | **否**（有意绕过） | 每次 `ReleaseSession`/`Shutdown` ≤ `|pressed.keys|` ≤ 510 |
| `:227` `queue_.push_back` | `AppendReleasesLocked`（按钮 up） | 否 | ≤ `|pressed.buttons|` ≤ 5 |
| `:331` `pending_moves_[id] = input` | `Dispatch`（move 状态量） | 否（map 覆盖写） | 每会话 1 项；`EmitDueMoves` 4 ms 内排空 |
| `:175-180` 合并 | `EnqueueLocked` move 合并 | 不增长（覆盖队尾） | — |

`AppendReleasesLocked` 的**可达性**受限：`ReleaseInput` 只在 `input_lease_held_` 时调 `ReleaseSession`（`server.cpp:765-773`），而 `pressed` 只有注入过的会话才非空 ⇒ 调用次数 ≤ 持租会话数，且每会话一次。

### 2.2 定理与证明

**引理 1（饱和无 move）**：若 `queue_.size() > soft_limit`，则队列中不含 `kMouseMove`。
证明：`size < soft` 时 move 被接受（增长）；`size ≥ soft` 且有 move 时任何事件走 `kEvictMove`（`:109`，先于 `:116/:117`），只替换不增长，且每来一个 press 就吃掉一个 move。故 move 数不能把 `size` 推过 `soft`：一旦 `size ≥ soft`，move 只会被逐个驱逐，直到为 0；此后再来 move 走 `:110 kDrop`（`incoming_is_move`），无法重新进入。∎

**引理 2（饱和后不再新建 held 项）**：`size ≥ hard_limit` 时，press 走 `:117 kDrop`（引理 1 ⇒ `has_movable_move=false`，`kEvictMove` 不可达）⇒ `TrackInput` 不执行（`AdmitInput:170` 只在非 `kDrop` 时 track）⇒ `pressed` 只减不增。∎

**定理（峰值上界）**：
```
peak(queue_) ≤ hard_limit + (|pressed.keys| + |pressed.buttons|)_饱和时刻
             ≤ 1024 + 515 = 1539
```
证明：越限接受只可能来自 `:116`（引理 1 排除 `kEvictMove` 越限），每次越限接受同时 `erase` 一个 `pressed` 项（`AdmitInput:170` → `TrackInput:128-130`），且引理 2 保证饱和期不再新增 ⇒ 越限增量 ≤ 饱和时刻的 `|pressed|` ≤ 515。饱和后只能收缩（`:117` 拦住所有非 held 事件），故上界不可被重新突破。∎

**探针（被审代码本体，非模型）**：

```
[BASH: probe_bound.exe]   // 510 键身份填满 -> 撞硬限 -> 全部释放 -> 新 press/unheld up
at_hard_limit queue=1024 pressed=510
after_releases queue=1534 exempt_accepted=510 pressed=0
literal_bound(hard+|pressed|+pending_moves)=1024 queue=1534 violated=1
peak_bound(hard+510)=1534 peak=1534 within=1
extra_press=kDrop extra_unheld_up=kDrop queue=1534

[BASH: probe_bound2.exe]  // 3 轮：2000 move 洪泛 + 510 键 + 5 按钮 + 2000 未持有 up
cycle0 saturated queue=1024 pressed=515 move_at_saturation=0
cycle0 after_release_flood queue=1539 pressed=0 peak=1539
cycle1 ... peak=1539 ; cycle2 ... peak=1539
SUMMARY peak=1539 hard+515=1539 within_peak_bound=1 literal_violations=774
        accepts=4617 evicts=3 drops=6003
```

`move_at_saturation=0` 直接验证引理 1；`literal_violations=774` 说明**任务给的字面公式不成立**（它把 `pressed` 当成"队列中未消费豁免的计数"，实际每次豁免接受就已 `erase`）。

### 2.3 结论

- 硬上限**确实被 held-release 定界**：上界 `1539`（不是无界，也不是 C 报告里的 `5,000,000`）。上一轮 F1 的无界缺陷已闭合。
- 但**上界的正确表述是"峰值"**，不是瞬时 `hard + |pressed|`；`docs/spec/input-injection-seam.md:137` 写"队列上界 = `hard_limit` + pressed 集合大小"会让读者按瞬时口径复算而得出矛盾结论 → **D-A（文档 FAIL，低）**。
- `pending_moves_` 不属于 `queue_`，不应写进 `queue_` 的公式；总注入内存 = `queue_(≤1539) + 每会话 1 项 pending_move + 每会话 pressed(≤515)`。

## 3. 要点 2：`pressed` 是否有界（恶意对端能否灌满 65536 个 scancode）

**结论：PASS，上限 515。任务设想的"65536 个不同 scancode 全按下"在 wire 上不可达。**

证据链：

1. `KeyId.scancode` 是 `uint16_t`（`include/rtsc/server/desktop_input_map.h:91`），但**唯一写入源**是 `InputEvent::scancode`，其类型是 `uint8_t`（`include/rtsc/server/server.h:229`）；`TranslateInput` 原样拷贝（`desktop_input_map.cpp:44`）。
2. 线上解码：快路径 `ev.scancode = p[pos++]`（`server.cpp:1925`，单字节）；慢路径 `static_cast<uint8_t>(key_code & 0xFF)`（`server.cpp:1826`，只取低字节）。
3. `scancode == 0` 在翻译层被丢弃（`desktop_input_map.cpp:39`）⇒ 可表示身份 = 255 × 2（extended 位）= **510**。
4. 按钮：`DecodePointerButtons` 只产 1..5（`server.cpp:589-599`），`pressed.buttons` 是 `std::set<uint8_t>` ⇒ ≤ **5**。
5. `pressed` 以会话为粒度（`SessionInputState::pressed`，`desktop_input_win32.cpp:88-91`），`ReleaseSession`/`Shutdown` 清空（`:150`、`:475`）。

```
[BASH: probe_scancode.exe]
sizeof(InputEvent::scancode)=1
wire_reachable_presses=510 pressed_keys=510
0x1234 truncates to 0x34
```

**与审计 E 的冲突**：E 报告 E2 用"`KeyId`=uint16×bool ⇒ 131,077 项、可把上界抬到 ~132k"论证。该论证**不成立**（`scancode` 的 16 位宽度是死宽度，见上）。E2 的现象仍真实（见 §7 Q2），但其上界应为 515，队列峰值 1539。

## 4. 要点 3：`IsHeldRelease` / `TrackInput` 键身份是否严格互逆

| 事件 | `TrackInput`（`desktop_input_map.cpp:121-142`） | `IsHeldRelease`（`:144-156`） | 互逆 |
|---|---|---|---|
| 扫描码按下 `{sc, ext}` | `keys.insert(KeyId{sc,ext})` | `release==false` → false | ✓ |
| 扫描码抬起 `{sc, ext}` | `keys.erase(KeyId{sc,ext})` | `count(KeyId{sc,ext}) != 0` | ✓ 同一键 |
| unicode 按下 | `unicode != 0` → 直接 return（不 track） | `unicode != 0` → false | ✓ 对称 |
| unicode 抬起 | 同上（不 erase） | 同上 → false | ✓ 对称（不会误豁免） |
| 按钮按下 `b` | `buttons.insert(b)` | `button_down==true` → false | ✓ |
| 按钮抬起 `b` | `buttons.erase(b)` | `count(b) != 0` | ✓ |

不会出现"永不豁免"或"错误豁免"的错位：
- 0xE0 键与其非扩展同码键是**两个** `KeyId`（`operator<` 先比 `scancode` 再比 `extended`，`:94-97`）；按下 `E0 1D` 抬起 `1D` 不会被豁免（正确），且真键在 teardown 仍会被 `AppendReleasesLocked` 用按下时的身份补 up（`:214-221`）⇒ **错位最多造成"会话存活期间该键卡住"，不会永久卡键**。
- 重复按下（自动重复）`insert` 幂等；重复抬起在 `pressed` 为空时不再豁免（`DecideEnqueue:117` 丢弃）——正确。

**附（既有漂移，D-E）**：`extended1`（0xE1 / PAUSE）不参与 `KeyId`，且 `TranslateInput` 完全不看它 ⇒ 0xE1 的 CTRL 与普通 CTRL 是同一条 `KeyId`，会按普通 CTRL 注入。而 `docs/spec/input-injection-seam.md:420-421` 的 P-6 裁决写"`extended1` 事件**不注入**，计入 `dropped_unsupported`"。代码与文档冲突（`git grep extended1 -- src` 只有解码，无注入侧判定）。这是 `334d5a1` 之前就存在的漂移，非本提交引入，但对"PAUSE 序列会注入真 CTRL"这一副作用应在文档中纠正。

## 5. 要点 4：其它丢弃点是否会吞掉 held release

| 丢弃点 | 位置 | 能否吞 held up | 依据 |
|---|---|---|---|
| `IntegrityCheck` | **不存在** | — | `git grep -n "IntegrityCheck"` 空输出；全仓只有 UIPI 完整性级别的文字（`docs/spec/input-injection-evidence.md:45`） |
| `IsInjectable` 租约前置门 | `server.cpp:814-821` | 不能 | held up 的 press 曾被接受 ⇒ 该会话必已 `AcquireInputLease` 成功；`input_lease_held_` 为真时**不再调用** `IsInjectable`（`:816-819`），事件一律转发 |
| `scancode == 0` | `desktop_input_map.cpp:39` | 不能 | `scancode==0` 的 press 从未入队/从未 track，没有对应 held 项 |
| `unicode_code == 0` | `:52` | 不能 | unicode 从不 track |
| `button == 0`（kMouse） | `:73` | 不能（只影响畸形流） | 合规释放携带按钮位（`server.cpp:585-588` 注释 + `DecodePointerButtons:589-599` 在 `DOWN` 之外解码）；无按钮位的"释放"本就不携带身份，无可清状态 |
| 未知 eventCode 中止本 PDU | `server.cpp:2007-2019` | **会**（同 PDU 内后续 up） | `return` 放弃剩余 body。但不永久卡键：`pressed` 仍持有该键，teardown `AppendReleasesLocked` 补 up。且这是 `[MS-RDPBCGR] SHOULD 断连`的宽松偏离，攻击者只能自伤 |
| `inputs.empty()` → `dropped_unsupported_` | `desktop_input_win32.cpp:114-117` | 不能 | 空翻译只发生在上面已排除的组合 |
| 队列 `kDrop` | `:197-199` | 不能 | `DecideEnqueue:116` 先于 `:117`；held up 不会被这条拦住 |
| 限流 `Allow` 拒绝 | `:324` | **不会丢**（反向问题：全放行） | `IsReleaseInput` 对所有 up 返回 true（`:78-84`）⇒ up 从不被限流 → 见 §7 E1 |

## 6. 要点 5：变异真实性

### 6.1 目标测试确实"先红后绿"

变异 M1 = 把 `AdmitInput` 的 `TrackInput` 移到 `DecideEnqueue` **之前**（即 `desktop_input_map.cpp:165-170` 换序），其余不动：

```
[BASH: cmake --build ... --target rtsc_desktop_input_tests; rtsc_desktop_input_tests.exe]
  FAIL tests/test_desktop_input.cpp:444  pressed.keys.empty()
  FAIL tests/test_desktop_input.cpp:447  !IsHeldRelease(up, pressed)
  FAIL tests/test_desktop_input.cpp:449  AdmitInput(full, pressed, up, ...) == kDrop
[ FAIL ] desktop_input_queue_dropped_press_is_not_tracked
35 tests, 3759 checks, 1 failing tests, 3 failed checks   exit=1
```

恢复原序后 `35 tests, 3759 checks, 0 failing`（exit=0）。**`tests/test_desktop_input.cpp:433` 是真测试，不是假测试。**

补充变异 M2 = `AdmitInput` 退回旧策略 `incoming_is_held_release = IsReleaseInput(input)`（即 `334d5a1` 的行为）：

```
[ FAIL ] desktop_input_queue_unheld_release_is_dropped_at_hard_limit   (:351, :360 got 5000)
[ FAIL ] desktop_input_queue_held_release_is_accepted_and_untracked    (:381)
[ FAIL ] desktop_input_queue_held_button_release_is_exempt             (:408)
[ FAIL ] desktop_input_queue_unicode_release_is_not_exempt             (:430)
[ FAIL ] desktop_input_queue_dropped_press_is_not_tracked              (:449)
35 tests, 3759 checks, 5 failing tests, 6 failed checks   exit=1
```

⇒ 本提交的核心语义（只有 held release 豁免）被 5 条测试钉住，**该层回归保护有效**。

### 6.2 但有两个变异存活（覆盖缺口，D-B）

| 变异 | 内容 | 结果 | 说明 |
|---|---|---|---|
| **M3** | `IsHeldRelease` 用 `KeyId{input.scancode, false}`（忽略 0xE0 标志） | **全绿** `35/3759/0` | `tests/test_desktop_input.cpp:384` 的"extended 身份"断言此时 `pressed` 为空 ⇒ **恒真**，测不到。`map.h:86-89` 与 `:382-384` 注释声称的身份互逆**无测试保护** |
| **M4** | `AdmitInput` 改为 `if (action == kAccept) TrackInput(...)`（`kEvictMove` 路径不 track） | **全绿** `35/3759/0` | 真实可达路径（`size ≥ soft` 且有 move 时 press → `kEvictMove`）**零覆盖**；一旦退化，被 evict 接受的 press 不进 `pressed`，其 up 在硬限被丢 ⇒ 会话存活期卡键 |

### 6.3 更根本的缺口：Win32 sink 接线零覆盖（D-C）

`CMakeLists.txt:676-682`：`rtsc_desktop_input_tests` 只编译 `tests/test_desktop_input.cpp` + **`src/server/desktop_input_null.cpp`**，只链接 `rtsc_server_desktop_input_map`。`src/server/desktop_input_win32.cpp` 只进 `rtsc_server_desktop_input`（`:691`），后者只被 host 链接（`:704`）；`rtsc_server_tests` 链接的是 `rtsc_server`（`:609`），**不含**该库。

⇒ 本提交最关键的三行接线（`desktop_input_win32.cpp:127-128` 求 `held_release`、`:192` 传给 `AdmitInput`、`:170`/`:203` 的 track-then-push 顺序）**不在任何测试 target 的源码或链接闭包内**，任何变异都不会变红。这与上一轮 C 报告 §2.4 的结论一致（当时是 `TrackPressedLocked` 位置无覆盖，现在是同一处仍未解决）。审计 E 的"两个变异均红"只覆盖 `InputRateLimiter`（纯函数、在 map 层），**不覆盖 sink 接线**。

## 7. 与审计 E 的交叉质证

### Q1（E）：修 E1 选"held 标志随队传递"还是"限流前移到 EnqueueLocked"？

**我的选择：限流前移到 `Inject()` 内（等价于 `EnqueueLocked` 之前），但不要给限流器新增锁 —— `Inject()` 已持 `mu_`。**
理由与代价：

1. 前移能**同时消掉 E1 与 E2**：E1 的根因是 `Dispatch` 只能看到 `IsReleaseInput`（`win32.cpp:324`）；E2 的根因是"入队即 track、出队才丢、不回撤"（`map.cpp:170`）。前移后，被限流的 press 既不进队列也不进 `pressed` ⇒ 两条同时成立。
2. 前移**不需要新增竞争**：`Inject()` 在 `mu_` 内（`win32.cpp:110`），把 `InputRateLimiter` 改成 `mu_` 保护即可；`Dispatch`（worker）删掉 `Allow` 调用，反而少一次跨线程可见的原子读。代价是限流器从"worker 独占无锁"变成"受 `mu_` 保护"，需同步改 `map.h:199-203` 的注释（当前写"runs on the sink's single worker thread, so it takes no lock"，照做前移而不改注释就是文档缺陷）。
3. 不选"只随队传递 held 标志"的原因：它只修 E1，E2 仍在（`pressed` 可被限流丢弃的 press 填满），而 E2 会让 §2.2 引理 2 的前提"饱和后不再新建 held 项"多一个例外（限流造成的"假 held"），上界虽不变但论证变复杂。
4. 若主代理要求最小 diff，退路是"随队传递"：`QueuedInput` 加 `bool exempt_release`（入队时 `held_release` 的值），`Dispatch` 用 `rate_limiter_.Allow(id, item.exempt_release, now)`。但这需要 `QueuedInput` 增加字段并同步 `AppendReleasesLocked`（合成 up 应传 `true`）。

### Q2（E）：E2 的 131,077 上界是否有更小实际值？

**有：515（510 键 + 5 按钮），且这是硬结构上界。** 131,077 不成立，因为 `KeyId.scancode` 的 16 位宽度是死宽度 —— 唯一写入源 `InputEvent::scancode` 是 `uint8_t`（`server.h:229`），线上快路径单字节（`server.cpp:1925`）、慢路径取低字节（`:1826`）。证据：`probe_scancode.exe` → `sizeof(InputEvent::scancode)=1`、`wire_reachable_presses=510`。

因此：E2 的"真实队列上界 = hard_limit + 2·|pressed|"应为 `hard_limit + |pressed| ≤ 1539`（探针 `peak=1539`）；E2 的严重度从"中"降为"低"（不是 128× 硬限的膨胀，只是把 `pressed` 从"实际按住"扩到"曾入队但被限流丢弃"，上限仍 515）。E2 的实际危害是：①文档/注释"被丢弃的 press 从未 held"（`map.h:101-102,192-195`、`win32.cpp:19-21`）对限流路径**不成立**；②被限流的 press 之后会收到一条无对应按下的豁免 up（对桌面无害）；③多占豁免额度（有界）。

### Q3（E）：E3 修法里"丢弃断开会话的非合成积压"是否可接受？

**可以，且必须保留合成 up。** 论证：未出队的 press 从未 `SendInput`（`Dispatch` 才 `Emit`，`win32.cpp:339`）⇒ 丢弃它不会卡键；合成 up 是 `AppendReleasesLocked` 为"已注入且仍按住"的键补发的（`:207-229`），丢了才会卡键。最小实现：

```cpp
struct QueuedInput { uint32_t session_id; PlatformInput input; bool synthetic = false; };
// ReleaseSession（持 mu_）：先 AppendReleasesLocked（合成 up, synthetic=true），
// 然后 queue_ 中该 id 的非 synthetic 项全部 erase；forget_sessions_ 仍记录。
// ForgetReleasedSessionsLocked（worker）：pending_moves_.erase(id); last_move_sent_.erase(id);
//   rate_limiter_.Forget(id);
```
这样也一并消掉 E3 的"断开后仍动指针"（`pending_moves_` 清空）与"Dispatch 重建桶"（积压已删，`Allow` 不会再为该 id 建桶）。

### Q4（E）：c/d 属既有漂移，是否算本批"文档回写"FAIL？

**分两类，我的判定：**

| 漂移 | 是否本提交引入 | 判定 |
|---|---|---|
| `input-injection-seam.md:137` "上界 = hard + pressed"（瞬时口径错误） | **是**（本提交新增该行） | **FAIL（D-A）**，必须改 |
| `input-injection-seam.md:263-264` "释放数量被 pressed 限界" | **是**（`git diff 334d5a1 27cf199 -- docs/spec/input-injection-seam.md` 中该条为 `+` 行） | **FAIL（E1 的文档面）** |
| `desktop_input_map.h:221-223` "a false result is expected to be counted by the caller" | **是**（本提交新增） | **FAIL（D-F）**：`Allow` 自己 `dropped_.fetch_add`（`map.cpp:203`），`Dispatch` 未再加；照注释实现会**真重复计数** |
| `desktop_input.h:41-46` "refused by the bounded injection queue" 未含 evict | **是** | 低（`dropped_queue_full` 同时计 evict，`win32.cpp:195`），建议一并写清 |
| `seam.md:133` 250 Hz"上限" | 否（既有） | **不算本批 FAIL**，记 R1：`FlushSessionMove`（`win32.cpp:304-310,338`）绕过 `kMoveInterval`，瞬时可达 1000 Hz；250 Hz 只是"稳态 move 节流" |
| `seam.md:256` "events" 实为平台动作 | 否（既有，本提交只重排了列表） | 不算本批 FAIL，记 R1：move+button 一条事件扣 2 令牌 ⇒ 稳态 200 事件/s |
| `seam.md:161-162` 三态失败率日志 | 否（既有；**本提交重写了这两行却保留了该不实陈述**） | 不算本批 FAIL，记 R1：`LogFailure` 每 5 s 至多一条（`win32.cpp:448-466`），无"失败率>50%/恢复"三态。既然本批做"文档回写"，建议顺手改掉 |
| `seam.md:420-421` `extended1` 不注入 | 否（既有） | 不算本批 FAIL，记 R2（D-E）：代码按普通 CTRL 注入 |
| `E4` `ServeOne` 无 try/catch | 否（`334d5a1:src/server/server.cpp` 同形，`git show` 已核） | 不算本批 FAIL，记 R3 |
| `E6` 生产代码无 `Stats()` 调用方 | 否（`334d5a1` 也没有） | 部分算：本提交提交信息宣称"可观测"，但 `dropped_rate_limited` 在 host 中不可见（`git grep "Stats()" -- src tools` 只命中 null/win32 实现）→ 记为 **D-G（低，文档/可观测缺口）** |

## 8. FAIL 与最小修法

### D-A（低，文档，必修）：上界公式改为峰值口径
`docs/spec/input-injection-seam.md:137`：
```
| 队列上界 | 峰值 `hard_limit + 515`（held release 越限接受的条数 ≤ 饱和时刻的
| pressed 集合大小 ≤ 510 键 + 5 按钮）；饱和后不再新建 pressed 项，故上界不可被重新突破 |
```
并在同表补一条引理：`size > soft_limit ⇒ 队列内无纯移动`（§2.2 引理 1），它是"饱和时无 move 可驱逐"的依据。

### D-B（中，测试，必修）：补 3 条用例消除 M3/M4 存活
1. `desktop_input_queue_extended_identity_is_not_confused`：先按下 `{0x1D, extended=false}`（`pressed` 非空），断言 `!IsHeldRelease(KeyUp(0x1D, true), pressed)` 且 `IsHeldRelease(KeyUp(0x1D,false), pressed)`；反向再来一次。⇒ M3 转红。
2. `desktop_input_queue_evict_move_still_tracks_press`：`QueueState(size=soft, has_movable_move=true)` 下 press 必须 `kEvictMove` **且** `pressed.keys.size()==1`。⇒ M4 转红。
3. （D-C）把 `held_release` 的求值抽成 `map` 层纯函数（例如 `bool IsHeldRelease(const PlatformInput&, const PressedInputs&)` 已具备，另加一个 `AdmitForSession(EnqueueState, PressedInputs&, const PlatformInput&)` 由 sink 调用），并在测试里驱动它，从而让"求值时机在入队前"这件事有测试锚点；否则 sink 接线只能靠 review。

### D-C（中，测试，必修）：Win32 sink 接线零覆盖
最小可行：把 `EnqueueLocked` 的"决策 + 记账"整段抽成 `map` 层的纯函数 `AdmitForSession(state, pressed, input)`（内部 `held = IsHeldRelease(...)`，再 `AdmitInput(...)`），sink 只保留容器操作。这样 M1/M3/M4 全部落在被测试的 TU 内。**禁止**为了让测试能链接 win32 而引入平台分支到测试 target（会破坏 `desktop_input_null` 的可移植性）。

### E1（中，必修，跨报告一致）：限流豁免改用 held 语义
见 §7 Q1：限流前移到 `Inject()`（`mu_` 内），豁免参数用 `IsHeldRelease(input, session.pressed)`；同步改 `map.h:199-203`、`seam.md:263-264` 的"释放数量被 pressed 限界"表述为"**held** release 才豁免"。

### E2（低，可选同批）：`pressed` 与限流的一致性
若采纳 E1 的前移方案，E2 自动消失（被限流的 press 不入队不 track）。若只做"随队传递"，需在 `Dispatch` 丢弃 press 时回撤 `pressed`（worker 需持 `mu_`，或用"待回撤集合"由 `Inject` 侧消费）——**不推荐**，复杂度高于前移。

### D-G（低）：把 `dropped_rate_limited` 接到 host 日志
`tools/rtsc_server/main.cpp:641-655` 已有"首次 lease-denied 打印一次"的巡检；在同一处（或停止时）打印一次 `input_stats`（`injected/dropped_queue_full/dropped_rate_limited/send_failures`），否则本提交新增的计数在 `rtsc_server_host` 中不可见。需在 `RdpServer` 暴露 `input_stats()` 访问器（`input_lease_denied_count()` 已有先例，`server.cpp` 侧照抄）。

## 9. 复现

```text
# 纯净副本
git archive --format=tar 27cf199 -o %TEMP%\opencode\auditD_lease\src.tar
tar -xf src.tar -C %TEMP%\opencode\auditD_lease
cmake -S ... -B ...\build_clean -G "Visual Studio 17 2022" -A x64
cmake --build ...\build_clean --config Release --target rtsc_desktop_input_tests
...\build_clean\Release\rtsc_desktop_input_tests.exe
  -> 35 tests, 3759 checks, 0 failing (exit 0)          # 基线

# 探针（cl /std:c++20 /W4，直接编译被审的 map.cpp）
cl /nologo /std:c++20 /EHsc /W4 /I include probe_bound.cpp  src\server\desktop_input_map.cpp
cl /nologo /std:c++20 /EHsc /W4 /I include probe_bound2.cpp src\server\desktop_input_map.cpp
cl /nologo /std:c++20 /EHsc /W4 /I include probe_scancode.cpp src\server\desktop_input_map.cpp
cl /nologo /std:c++20 /EHsc /W4 /I include probe_rate.cpp  src\server\desktop_input_map.cpp
  -> peak=1539=hard+515 ; literal_violations=774 ; move_at_saturation=0
  -> sizeof(scancode)=1 ; wire_reachable_presses=510
  -> unheld_keyups_allowed=5000 dropped=1

# 变异（只改副本，恢复后哈希/逐行比对一致）
M1 track-before-decide  -> 1 test / 3 checks 红，恢复 35/3759/0 绿
M2 旧 IsReleaseInput 策略 -> 5 tests / 6 checks 红
M3 IsHeldRelease 忽略 extended -> 全绿（存活，D-B）
M4 只在 kAccept 时 track   -> 全绿（存活，D-B）
```

## 10. 放行意见

- **held-release 定界目标：达成。** `queue_` 峰值严格 ≤ `hard_limit + 515 = 1539`（探针 3 轮复现），上一轮 F1 的"释放恒接受 ⇒ 无界"已闭合；`pressed` 有界 515，键身份互逆，无其它丢弃点吞掉 held up。要点 1/2/3/4 判 **PASS**（要点 1 的字面公式与文档表述需按 D-A 改写）。
- **不放行的部分（均非"定界失效"，而是文档/测试/限流语义）**：
  - D-A 文档上界公式（低，必修）；
  - D-B + D-C 测试缺口（中：M3/M4 存活、win32 接线零覆盖，第 16 条"假测试必须重写"意义上不合格）；
  - E1 限流豁免不看 held（中，跨报告一致 FAIL）；
  - E2（低）、D-G（低）。
- 建议顺序：先修 D-B/D-C（补测试，先红后绿），再修 E1（限流前移，随测试），最后回写 D-A/D-G 文档；修完重跑 `rtsc_desktop_input_tests` + `rtsc_server_tests`，并对 M1–M4 重做变异红/绿。
