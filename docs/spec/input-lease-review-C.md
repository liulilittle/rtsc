# 输入注入修复审计 C（commit `334d5a1`）

## 0. 审计范围与基线

| 项 | 值 |
|---|---|
| 被审提交 | `334d5a1cfeee28e0509eda7fc920c1155f5b7b0c`（父 `3f30939`） |
| 审计时 HEAD | `0994da9`（`git diff --stat 334d5a1 0994da9 -- src include tests tools CMakeLists.txt` 输出为空：**代码与 334d5a1 完全一致**，HEAD 只多文档/记忆提交） |
| 工作树 | 审计期间出现**未提交的批次 9 改动**（`git status --porcelain` 列出 `CMakeLists.txt`、`include/rtsc/server/desktop_input.h`、`include/rtsc/server/desktop_input_map.h`、`src/server/desktop_input_map.cpp`、`src/server/desktop_input_win32.cpp`、`tests/test_desktop_input.cpp`）。本报告**只审 `334d5a1` 的 blob**，行号一律取 `git show 334d5a1:<file>`；工作树脏改动只在 §8 做前瞻提示。 |
| 环境 | Windows 11 / MSVC 14.44 / `cmake -G "Visual Studio 17 2022" -A x64` / Release |

**方法/纪律**：源码只读；变异、构建、探针全部在 `%TEMP%\opencode\audit_c\` 下的 `git archive HEAD` 纯净副本（`clean/`）与变异副本（`base/`）中进行；仓库内唯一写入是本文件。`F:\rtsc\build` 只在审计开始时对当时仍是干净的 `334d5a1` 源码做过一次既有目录编译（未改任何源码），复现代码见 §7。

## 1. 结论总表

| 要点 | 结论 | 一句话依据 |
|---|---|---|
| 1. F1 永久卡键 | **FAIL（部分修复）** | 两处目标修复都到位且能防住"丢 up → 永久卡键"；但 `incoming_is_release → kAccept` 使**队列彻底失去硬上限**（`DecideEnqueue(size=5,000,000, release) == kAccept`），一条 32 KB fast-path PDU 即可把队列推过 1024；且 sink 级 `TrackPressedLocked` 位置**没有任何测试覆盖**（变异存活）。 |
| 2. F4 幻影输入 | **PASS** | 未知 `pdu_type2` 分支确实 `handled=true` + 计数 + 不回落（`server.cpp:1718-1724`）；`IsKnownShareDataPduType` 对 `ShareDataPduType` 的 24/24 枚举值全覆盖（脚本比对 `missing= extra=`）。附一个测试断言顺序竞态（§2.4，非产品缺陷）。 |
| 3. F3 租约交接顺序 | **PASS** | `ReleaseSession`（`server.cpp:773`）先于 `holders.erase`（`:777`）；`input_released_` 幂等守卫、单次调用路径、无锁嵌套、无双重释放均有据；变异回退可稳定复红。 |
| 4. F4-甲3 不可注入事件占租 | **PASS** | `IsInjectable` 与 `TranslateInput` 对 6 个 kind 的全部字段组合穷举，**0 失配**；`InjectIfLeasable` 仅在未持租时用该谓词（`server.cpp:814-821`）。附 3 条语义备注。 |
| 5. 回归风险 | **PASS（附残余风险 R1/R2）** | `IsInjectable` 内联不引入链接依赖（`rtsc_server` 未链接 `rtsc_server_desktop_input_map`，纯净副本整链通过）；被删测试留下"fast-path 撞 share 头"场景不再覆盖，但新策略已批准且该碰撞需要保留位 0x10，真实客户端不会产生。 |

## 2. 要点 1：F1 永久卡键（FAIL，部分修复）

### 2.1 目标缺陷确实被修复（PASS 部分）

`3f30939` 的根因是 `Inject` 先 `TrackPressedLocked` 后入队，而硬限会丢 keyup（旧 `desktop_input_win32.cpp:118-119`），于是：
keyup 被丢 → `pressed_keys` 已被 erase → teardown 无 up 可补 → **永久卡键**。

`334d5a1` 的两处改动都正确落地：

1. `src/server/desktop_input_win32.cpp:110-129`
   ```cpp
   for (const PlatformInput& input : inputs) {
       if (EnqueueLocked(session_id, input)) {   // :124-126
           TrackPressedLocked(session, input);
       }
   }
   ```
   `EnqueueLocked` 只有"已入队/已并入队尾"才返回 true，因此**被丢弃的 press 不会被记成 held**，teardown 不会错误补 up。
2. `src/server/desktop_input_map.cpp:106-117`
   ```cpp
   if (state.incoming_is_release) return EnqueueAction::kAccept;  // :114
   if (state.size >= state.hard_limit) return EnqueueAction::kDrop; // :115
   ```
   `IsRelease` 覆盖 `kKey`（含 unicode）的 `release==true` 与 `kMouseButton` 的 `!button_down`（`desktop_input_win32.cpp:168-174`），即 `TranslateInput` 能产出的**所有**释放形态都排在硬限丢弃之前。

推导核验：press 入队并 tracked；硬限到达；release 仍被接受并入队、tracked 时 erase；worker 按 FIFO 先发 press 再发 release；会话中途断开时 `AppendReleasesLocked`（`:234-256`）仍能补上未释放的键。**F1 的"永久卡键"目标缺陷已修复。**

### 2.2 但释放恒接受使硬上限失效（FAIL 的核心）

`DecideEnqueue` 的 `:114` 无条件优先于 `:115`，且**不检查释放对应的键是否真的被本会话按住**。`EnqueueLocked` 对 `kAccept` 一律 `queue_.push_back(...)`（`desktop_input_win32.cpp:230`），`queue_` 是无限 `std::deque`，没有第二个上限。于是释放流可无界增长。

**红证（直接执行被审代码，不是模型）**：用 `334d5a1` 的 `desktop_input_map.cpp` 编译探针，构造 `hard_limit=1024`：

```
[BASH: probe_clean.exe]
is_injectable_mismatches=0
size=1024 release=0 press=2
size=1025 release=0 press=2
size=100000 release=0 press=2
size=1000000 release=0 press=2
release_at_5M=ACCEPT
```
（`0=kAccept, 2=kDrop`）

即：**队列已有 5,000,000 个元素时，一个释放仍被接受**。`pressed_` 集合的有界性并不能救这一点：

- `pressed_keys` 是 `std::set<KeyId>`，`KeyId{uint16 scancode, bool extended}`（`desktop_input_win32.cpp:73-81`），唯一写入源 `TrackPressedLocked`（`:176-194`）拿到的 `input.scancode` 来自 `InputEvent::scancode`（`uint8_t`，`server.h` 中 `InputEvent` 定义），故每会话 ≤ 256×2=512 项；`pressed_buttons` ≤ 256 项。**集合本身有界，但队列不是集合**：一条"从未按下过的键"的 keyup、或"已释放键"的重复 keyup，都会 `erase` 空操作后照样入队。
- 甚至"只接受 held 键的释放"也需额外实现；当前代码连这个检查都没有（`DecideEnqueue` 拿不到 session 状态）。

**可达性（不是理论）**：fast-path 长度上限 `FastPathLength::kMax = 32767`（`include/rtsc/proto/share.h:224`），scancode 事件固定 2 字节（`src/proto/share.cpp:286`），`ParseInputEvents` 只要 `pos < n` 就一直解（`server.cpp:1916`，且**不校验 `count_or_reserved` 与实际事件数**），所以**一条 32 KB 的 fast-path input PDU 可在一次 `Inject` 循环里产生 ~16,382 个 keyup**，每个都走 `:114 → kAccept → push_back`。单条 PDU 就把 1024 硬限推过 16 倍；对端还能连续发送。默认 `max_input_sessions=1` 也不能缓解——攻击者自己就是持租者。队列是**全 server 共享**的，worker 串行 `SendInput`，消费端跟不上时内存按"事件数 × ~40-48 B"增长，直到 OOM。

**二次放大**：`EnqueueLocked` 每个事件都 `std::find_if(queue_.begin(), queue_.end(), is-move)`（`desktop_input_win32.cpp:205-210`）。队列被释放灌到 N 后，每个新事件都要全表扫 N 次（无 move 可驱逐），复杂度 **O(N²)**，阻塞持租会话自己的输入线程。

**与文档/设计的关系**：`.opencode/plan.md:612,619-620` 的批次 9 定案确实写了"释放类事件永不被队列上限丢弃"，`:1.5` 同时写"硬上限 1024（无可驱逐时丢**非释放**事件）"。但代码注释给出的理由——"releases are bounded by the set of keys/buttons the session holds down"（`desktop_input_map.cpp:110-113`、`desktop_input_win32.cpp:20-23`）——**前提不成立**：接受的是"释放事件流"，不是"held 集合"。实现忠实于批准方案，但该方案的"有界"论证是错误的；按项目"硬上限 1024 = 内存保护"的设计意图，这仍是必须修的安全回归，故判 FAIL。

### 2.3 追问逐条回答

| 追问 | 结论 | 证据 |
|---|---|---|
| release 恒接受是否无界增长？ | **是** | 探针 `release_at_5M=ACCEPT`；`queue_.push_back` 无第二上限（`:230`）；`queue_` 为 `std::deque`（`:502`），无容量限制 |
| `pressed_` 是否有界？ | **有界但救不了队列** | `KeyId` 域 ≤512 / 按钮 ≤256（`:73-92`、`:176-194`）；释放不要求"键在集合中"，重复/未按下的 up 照样入队 |
| 250 Hz move 合并会丢 release 吗？ | **不会** | 合并仅在 `input.kind==kMouseMove && queue_.back().input.kind==kMouseMove`（`:199-204`）；worker 侧 `pending_moves_` 只保存 move（`:344-357`），key/button 先 `FlushSessionMove` 再按序 `Emit`，不经过 move 节流 |
| `EnqueueLocked` 是否还有第二条丢弃分支绕过 bool？ | **没有** | 全函数唯一 `return false` 在 `:226`（kDrop）；`:211-213` 的 coalesce 返回 true 且不增长队列；`AppendReleasesLocked`（`:234-256`）是 teardown 专用直推，绕过策略但量 ≤ held 集合（≤517/会话）；worker `BuildNative` 的 `return false`（`:427/:447`）发生在出队之后，不是"入队丢弃" |

### 2.4 测试真实性：策略级绿，sink 级裸奔

- **绿**：纯净副本 `rtsc_desktop_input_tests` 23 tests / 97 checks / 0 fail，`rtsc_server_tests` 48 tests / 555 checks / 0 fail。
- **红（F1 策略部分）**：把 `desktop_input_map.cpp:114` 的 release 分支删掉，`desktop_input_queue_accepts_release_at_hard_limit`（`tests/test_desktop_input.cpp:304`）会红。该测试确实钉住了策略。
- **覆盖缺口（重要）**：把 `desktop_input_win32.cpp:124-126` 变异回旧写法 `TrackPressedLocked(...); EnqueueLocked(...);`（即 F1 第二修回退），**`rtsc_desktop_input_tests` 仍然 23/97 全绿**。原因：策略层已保证 release 不被丢，旧顺序在新策略下也不会触发原缺陷；而 `EnqueueLocked/TrackPressedLocked` 在匿名命名空间 + Win32 文件里，**没有任何测试能触达**。也就是说"只入队才 track"这一修**没有回归保护**，未来若有人恢复"硬限丢 release"或改动顺序，测试不会报警。见 §6 最小修法中的测试缝建议。
- 新测试把 `DecideEnqueue(16/17, release=true)==kAccept` 固化为期望（`tests/test_desktop_input.cpp:304-318`）。若按 §6 修复，须同步改为"held release 才 kAccept；非 held release 在硬限 kDrop"，否则该测试会**把缺陷固化**。

### 2.5 最小修法（F1）

**改动点只有 sink 的判定输入，`DecideEnqueue` 本身不变**（仍用 `incoming_is_release`，语义收紧为"held release"）：

```cpp
// Inject() 内，EnqueueLocked 之前：
const bool held_release =
    input.kind == PlatformInput::Kind::kKey
        ? (input.release && input.unicode == 0 &&
           session.pressed_keys.count(KeyId{input.scancode, input.extended}) != 0)
        : (input.kind == PlatformInput::Kind::kMouseButton &&
           !input.button_down &&
           session.pressed_buttons.count(input.button) != 0);
EnqueueLocked(session_id, input, held_release);
```

`EnqueueLocked(..., bool held_release)` 里 `state.incoming_is_release = held_release;`。

性质：
- 被按住键/按钮的 up **永远不被硬限丢**（原 F1 保证保留）；
- 未按下/重复 up 在硬限时按普通事件 `kDrop`（没有物理键可卡，安全）；
- 每条 up 消耗一个 held 项，held 项由已接受的 press 创建，因此**越过硬限的 up 数 ≤ held 集合上限（≤517/会话）**，队列上界恢复为 `hard_limit + 517`；O(N²) 扫描也随之消失。
- unicode 键本来就不进 `pressed_keys`（`TrackPressedLocked` 只处理 `unicode==0`），其 up 在硬限会被丢；`KEYEVENTF_UNICODE` 不建立物理键状态，可接受（若要求更严，可把 unicode code 也纳入 held 集合，域 ≤65536，仍有限）。
- 测试：`QueueState(16,false,false,true)` 仍表示 held release（保持绿）；新增 `QueueState(16,false,false,false) → kDrop` 用例；sink 的 `held_release` 计算建议抽成纯函数（输入 `SessionInputState` + `PlatformInput`）或提供 `#ifdef` 测试钩子，补一条"硬限丢 press 后 `pressed_` 不含该键"的用例，填补 §2.4 的覆盖缺口。

## 3. 要点 2：F4 幻影输入（PASS）

### 3.1 分支行为（PASS）

`src/server/server.cpp:1701-1724`：

- `payload.size() < 18` 或 `ShareDataHeader::parse != Ok` → `return true` 且 `handled` 保持 false（`:1706-1710`），合法 fast-path 仍交给 `HandleInputPdu`（`:1674`）。
- 解析成功但 `!IsKnownShareDataPduType(hdr.pdu_type2)`（`:1718`）→ `malformed_input_pdus_ +1`（`:1719-1721`）、`*handled=true`（`:1722`）、`return true`（`:1723`）。**不再回落 fast-path**，会话继续。

红证（变异回旧回退）：

```
[FAIL] server_undefined_share_data_type_is_not_reinterpreted
  test_server.cpp:2173  events.empty()                      // 幻影事件确实产生
  test_server.cpp:2175  malformed_input_pdus == before+1    // got 0, want 1
```
说明该测试对"禁止回落 + 计数"是真实的红绿测试。

### 3.2 白名单完整性（PASS，24/24）

脚本直接比对 `ShareDataPduType` 枚举与 `IsKnownShareDataPduType` 的 case：

```
[BASH: enum/case 比对]
enum_count=24 case_count=24 missing= extra=
```

逐项覆盖：`kUpdate/kControl/kPointer/kInput/kSynchronize/kRefreshRect/kPlaySound/kSuppressOutput/kShutdownRequest/kShutdownDenied/kSaveSessionInfo/kFontList/kFontMap/kSetKeyboardIndicators/kPersistentKeyList/kBitmapCacheError/kSetKeyboardImeStatus/kOffscreenCacheError/kSetErrorInfo/kDrawNineGridError/kDrawGdiPlusError/kArcStatus/kStatusInfo/kMonitorLayout`（`server.cpp:552-581`，枚举 `include/rtsc/proto/share.h:28-53`）。

追问中点名的 `kRefreshRect(0x21)`、`kSuppressOutput(0x23)`、`kFontList(0x27)`、`kSaveSessionInfo(0x26)` 全部在列；MS-RDPBCGR 2.2.8.1.1.2 定义的 24 个 sharedPDUType 无遗漏（0x2A/0x33..0x35 未定义，不需要）。**不会把合法 PDU 当 malformed 丢掉。**

### 3.3 副作用/边界

- 未知 share 类型现在计入 `malformed_input_pdu_count()`。该计数器原语义是"输入 PDU 帧错误"；`include/rtsc/server/server.h:374-388` 已把文档改成"malformed input-carrying PDUs（含未定义 share 类型）"，**文档与实现一致**，可接受。
- 隐藏的取舍：一个"同时能解析成 share 头、且 `pduType2` 未定义"的**合法 fast-path PDU**会被当 malformed 丢弃。见 §5.2。

### 3.4 测试竞态（轻微，建议修）

`tests/test_server.cpp:2168-2175`：

```cpp
std::this_thread::sleep_for(200ms);
{ lock; CHECK(events.empty()); }          // :2173
CHECK_EQ(malformed_count, before + 1);    // :2175
```

若会话线程恰好在 `:2173` 与 `:2175` 之间处理完该 PDU：幻影事件已 push 但不再被检查，而计数恰好 +1，**测试会以"绿"放过幻影输入**。窗口很小但方向错误。最小修法：先轮询 `malformed_input_pdu_count()==before+1`（带超时），**再**断言 `events.empty()`（可再加 50 ms 静默复核）。

## 4. 要点 3：租约交接顺序（PASS）

### 4.1 顺序与守卫

`src/server/server.cpp:762-779`：

```
762 void ReleaseInput() {
763     if (input_released_) return;      // 幂等：重复调用直接返回
764     input_released_ = true;
765     if (!input_lease_held_) return;   // 从未持租：没有 up 要补，不碰 sink
766     input_lease_held_ = false;        // 本地先置 false（失败关闭）
772-774 if (enable && sink) sink->ReleaseSession(id);   // 先补 up（槽位仍在 holders）
775-778 { lock(lease.mu); holders.erase(id); }          // 后释放槽位
779 }
```

- **无双重释放**：`input_released_` 守卫 + 调用点唯一（线程路径 `:2360`、`ServeOne` 路径 `:2428`，各自只经过一次）；`holders.erase` 对不存在的 id 是 no-op。
- **先 sink 后槽位**：A 的合成 up 在 `holders.erase` 之前进入 `queue_`；默认 `max_input_sessions=1` 下 B 只能在 erase 之后取得槽位并 `Inject`，其 keydown 必然排在 A 的 up 之后，FIFO worker 不会抬掉 B 的新键。`ReleaseSession` 内部只取 sink `mu_`，`erase` 只取 lease `mu`，**从不嵌套**，worker 也不取 lease 锁，无死锁/无锁序反转（与 A 报告 §3 一致）。
- `input_lease_held_=false` 在 `ReleaseSession` 之前：同一线程不可能再进 `InjectIfLeasable`；若极端重入，`AcquireInputLease` 会因槽位仍被自己占着而拒绝（fail-closed），不会在 teardown 中注入。
- 代价：交接窗口内 B 的事件会被计为 denied（`AcquireInputLease` 返回 false）。这是预期行为，不是泄漏。

### 4.2 红证

变异回旧顺序（先 erase 后 `ReleaseSession`）后：

```
[FAIL] server_release_session_precedes_lease_handoff
  test_server.cpp:3724  sink.injects_during_release() == 0  (got 1, want 0)
```
`ReleaseOrderingSink` 在 `ReleaseSession` 内阻塞 500 ms，B 的持续输入在该窗口内抢到槽位并 `Inject`，稳定复红；修复版 48/555 全绿。测试是真实有效的。

## 5. 要点 4：F4-甲3 `IsInjectable` 与 `TranslateInput` 锁步（PASS）

### 5.1 逐 kind 对照

| kind | `IsInjectable`（`desktop_input_map.h:79-94`） | `TranslateInput`（`desktop_input_map.cpp:30-104`） | 一致 |
|---|---|---|---|
| kKey | `scancode != 0`（:82） | `scancode==0 → empty`（:38），否则 1 个 kKey | ✅ |
| kUnicode | `unicode_code != 0`（:84） | `unicode_code==0 → empty`（:51），否则 1 个 kKey | ✅ |
| kMouse | `is_move \|\| button != 0`（:86） | `is_move` 产 move（:63）；`button != 0` 产 button（:72）；两者皆无 → empty | ✅ |
| kWheel | `true`（:88） | 恒产 1 个 kWheel（:86-90） | ✅ |
| kMouseRel / kSync | `false`（:91） | empty（:99-101） | ✅ |

穷举探针（6 kinds × scancode{0,1,0x1E,0xFF,0xFFFF} × unicode{0,1,0x6F22,0xFFFF} × release/extended/is_move/button{0,1,3,5,6,255}/button_down）：

```
[BASH: probe_clean.exe]  is_injectable_mismatches=0
```

**不存在** `IsInjectable=true` 而 `TranslateInput` 空，也不存在反向组合。`server.cpp:814-821` 只在未持租时用该谓词；持租者仍转发（保留 unsupported 统计），与注释一致；`server_non_injectable_input_does_not_hold_lease` 变异回旧 `AcquireInputLease()` 后红（`:3777/:3778/:3790`，denied 0→1），是真测试。

### 5.2 三条语义备注（不判 FAIL）

1. **零增量滚轮**：`kWheel` 恒 `IsInjectable=true`，`TranslateInput` 也恒非空，二者锁步；但 `wheel_delta==0` 实际是无操作，却可让会话取得/持有租约。它属于"可注入事件"，不是 F4-甲3 的"不可注入"，按定义 PASS；若担心租约滥用，可在 server 侧把零增量 wheel 当 no-op 但仍可持租（设计取舍）。
2. **button > 5**：`IsInjectable=true` 且 `TranslateInput` 非空（`static_cast<uint8_t>(ev.button)`），但 `BuildNative` 对 6..255 返回 false（`desktop_input_win32.cpp:395-428`，default 分支 `:426-427`）→ 落到 `dropped_unsupported`。线上解码 `DecodePointerButtons` 只产出 1..5（`server.cpp:589-599`），**wire 上不可达**，故非缺陷；若未来新增按钮，应同步 `IsInjectable`/`BuildNative`。
3. **持租者转发 kSync**：持租者发 kSync 仍会进 sink 并计入 `dropped_unsupported`（`server.cpp:814-820` 注释明说），不是"占用租约"（租约已持有）。

## 6. 要点 5：回归风险（PASS，附残余风险）

### 6.1 链接依赖（PASS）

`IsInjectable` 是 header 内 `inline`（`desktop_input_map.h:79`），只 switch 字段，不调用 `TranslateInput/DecideEnqueue`。`rtsc_server` 的链接列表（`CMakeLists.txt:595-606`）**不包含** `rtsc_server_desktop_input_map`；`server.cpp` 新增的 `#include "rtsc/server/desktop_input_map.h"`（`:59`）只取内联函数。纯净副本中 `rtsc_server`、`rtsc_server_tests`（不链接 map 库）整链成功、48/555 全绿——**无新增链接依赖**。Linux 侧头文件也不含平台头（`desktop_input_map.h` 只依赖 `desktop_input.h`/`server.h`），不引入 Win32 依赖。

### 6.2 被替换测试留下的覆盖（PASS + R1）

`3f30939:tests/test_server.cpp:2039` 的 `server_fastpath_pdu_resembling_share_header_is_not_swallowed` 断言的正是"fast-path PDU 字节巧合通过 `ShareDataHeader::parse` 时仍要解出按键"。`334d5a1` 用 `server_undefined_share_data_type_is_not_reinterpreted`（`tests/test_server.cpp:2118`）**反转**了该策略：同一族 payload 现在按 malformed 丢弃。

该碰撞的精确条件（可复算）：`ShareControlHeader::parse` 要求 `pdu_type = byte2 | byte3<<8` 的 `type=(pdu_type&0xF)==7` 且 `version=(pdu_type>>4)&0xFFF==1`（`src/proto/share.cpp:50-72`），解出 **byte2=0x17、byte3=0x00**；在 fast-path 流里 byte2 是事件头（code=0 scancode，flags=0x17），byte3 是 keyCode=0。仓库只定义键盘 flags `0x01/0x02/0x04`（`include/rtsc/proto/input.h:20-22`），**0x10 是保留位**；因此合规客户端不会产生 byte2=0x17（保留位被置 + keyCode=0）的 fast-path 事件。结论：新策略不会丢弃"合规客户端的合法输入"，但确实**不再覆盖**"解析器可接受的碰撞 PDU 到达 fast-path"这一场景；这是已批准的策略取舍（`plan.md:488`），列为残余风险 R1，不判 FAIL。新测试仍验证了"会话存活 + 随后的合法 fast-path 键 0x2C 可解码"（`test_server.cpp:2177-2190`），正常快路径未失覆盖。

另：**已知 share 类型**与 fast-path 的碰撞（byte16 恰好是 0x02/0x1C 等）在本提交前后都会被当 share 吞掉，属既有问题，非本提交引入，未在本次范围内修。

## 7. 复现与证据

```text
# 代码同一性
[BASH] git diff --stat 334d5a1 0994da9 -- src include tests tools CMakeLists.txt
       (空)

# 纯净副本（334d5a1 代码）+ 构建 + 绿
[BASH] git archive --format=tar HEAD -o %TEMP%\opencode\audit_c\head.tar
       tar -xf head.tar -C %TEMP%\opencode\audit_c\clean
       cmake -S clean -B clean\build -G "Visual Studio 17 2022" -A x64
       cmake --build clean\build --config Release --target rtsc_desktop_input_tests rtsc_server_tests
       clean\build\Release\rtsc_desktop_input_tests.exe   -> 23 tests, 97 checks, 0 failing (exit 0)
       clean\build\Release\rtsc_server_tests.exe          -> 48 tests, 555 checks, 0 failing (exit 0)

# 策略探针（编译 clean 的 map.cpp，非模型）
[BASH] cl /std:c++20 /I clean\include probe_map.cpp clean\src\server\desktop_input_map.cpp
       probe.exe -> is_injectable_mismatches=0
                    size=1024 release=0 press=2
                    size=1000000 release=0 press=2
                    release_at_5M=ACCEPT

# 变异红（base = 334d5a1 + 4 处回退；同一构建）
[回退 F3 顺序 + F4 回落 + F4-甲3 无谓词 + F1 track 位置]
       rtsc_server_tests.exe -> 48 tests, 527 checks, 3 failing tests, 6 failed checks (exit 1)
         [FAIL] server_undefined_share_data_type_is_not_reinterpreted
                :2173 events.empty() / :2175 malformed count 0 vs 1
         [FAIL] server_release_session_precedes_lease_handoff
                :3724 injects_during_release 1 vs 0
         [FAIL] server_non_injectable_input_does_not_hold_lease
                :3777 inject_ids empty / :3778 geometry_ids empty / :3790 denied 1 vs 0
       rtsc_desktop_input_tests.exe -> 23 tests, 97 checks, 0 failing
         （F1 track 位置回退**未被任何测试发现** = 覆盖缺口）
```

## 8. 残余风险与前瞻提示（非本次提交）

- **R1（策略取舍）**：§6.2 的 fast-path/share 头碰撞现在按 malformed 丢弃。合规客户端不可达（保留位 0x10），但解析器不强制保留位；建议在 `HandleSlowPathPdu` 的注释/测试里明确"该碰撞 payload 依赖未定义 flag 0x10"，并保留一条"紧随其后的合法 fast-path 键仍可解码"的回归（现有）。
- **R2（F1 的队列无界）**：见 §2.2/§2.5，须修。
- **可观测性**：`InputStats`（`include/rtsc/server/desktop_input.h:43-47@334d5a1`）没有队列深度/丢弃分类（释放被接受、press 被丢），释放灌队列时 `dropped_queue_full` 可能长期为 0，运维不可见。建议加 `queue_depth`（或对 held-release 越限单独计数），否则 R2 无法被监控发现。
- **工作树批次 9 提示（未审）**：审计结束时工作树有未提交的限流改动（`git status` 6 文件）。其中 `InputRateLimiter::Allow` 在 worker `Dispatch` 里、`queue_.pop_front()` **之后**才执行（`git diff -- src/server/desktop_input_win32.cpp` 的 `rate_limiter_.Allow(item.session_id, IsRelease(item.input), ...)`），且释放仍豁免；它**不能**修复 R2——队列在 worker 取出之前就已无界增长。若批次 9 的"5000 releases 全允许"用例（工作树 `tests/test_desktop_input.cpp` 的 `desktop_input_rate_limit_release_is_exempt`）被固化，请同步与 §2.5 的 held-release 收紧对齐，否则该缺陷会被两层测试同时固化。

## 9. 放行意见

- **F4（要点 2）、F3（要点 3）、F4-甲3（要点 4）、回归（要点 5）**：可放行（附 R1 与 §3.4 测试顺序小修）。
- **F1（要点 1）**：**不放行**。目标"永久卡键"已修，但释放恒接受使 `kHardQueueLimit=1024` 形同虚设，构成"单个持租会话即可无界增长注入队列 + O(N²) 扫描"的 DoS；必须按 §2.5 把 `incoming_is_release` 收紧为"held release"，并补 sink 级测试，之后重跑 `rtsc_desktop_input_tests` + `rtsc_server_tests`。