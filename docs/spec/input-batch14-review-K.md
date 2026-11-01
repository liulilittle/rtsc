# 批 14 审计 K：映射语义修复（P-6 / 几何 / 零滚轮）复核 —— 对象 `805428b` + `6fc5614` 终态

状态：2026-11-02。审计 K（只读）。唯一写入：本文件（`docs/spec/input-batch14-review-K.md`）。
范围：`src/server/desktop_input_map.cpp`、`include/rtsc/server/desktop_input_map.h`、`tests/test_desktop_input.cpp`（批 14 新增用例）、
以及批 14 修复必然会走到的注入链路（`src/server/server.cpp` `InjectIfLeasable`、`src/server/desktop_input_win32.cpp` `Inject`、`src/proto/input.cpp` `EncodePauseKey`）。

终态确认：`[BASH: git diff 805428b -- src/server/desktop_input_map.cpp include/rtsc/server/desktop_input_map.h]` → **无输出**；
`6fc5614` 未改 `desktop_input_map.*`（只把 win32 后端纳入测试闭包）。故映射层终态 = `805428b`。

证据口径：`[READ:文件:行]` 为当前工作树行号；`[BASH:...]` 为本次实际执行。

---

## 0. 结论摘要

| # | 主题 | 判定 |
|---|---|---|
| 1 | P-6 / extended1 | **FAIL（High）**：只丢了带 0x04 的两个 CTRL，**PAUSE 的 NUMLOCK(0x45) down/up 仍被注入 → 每次远端按 Pause 仍切换本机 NumLock**。批 14 修了一半，缺陷未闭合。 |
| 1b | `IsInjectable` 与 `TranslateInput` 锁步 | PASS（可用几何下逐 kind 一致，交叉测试覆盖 extended1/零滚轮）；**注释口径偏强**（几何退化时 kMouse 会不一致，已在测试注释中承认）。 |
| 2 | 几何 | PASS（几何不足只抑制 MOVE、保留按键/按钮是正确取舍）；`NormalizeAxis` 的 `extent<=1` 分支**已无调用者（死分支）**，属有意防御，可保留。 |
| 3 | 零滚轮 | PASS（`IsInjectable(kWheel)` 已同步改为 `wheel_delta != 0`，**不再存在"可注入但不产出"的矛盾**；持租约者收到的零滚轮只计 `dropped_unsupported`，不占令牌/队列位）。 |
| 4 | 新测试覆盖面 | **FAIL（Medium）**：只测单事件；**没有任何用例把 PAUSE 四事件序列喂给注入路径**（server 侧 `test_server.cpp:1343` 只断言解码，且自己注明"注入 UNVERIFIED"）。这正是半修能通过测试的原因。 |
| 5 | 回归 | PASS：`ctest` **独占全量 63/63**（`--clean-first` 全量重编后复跑），C0 编译零错零警告。 |

一句话：**几何与零滚轮两处修对了；P-6 修错了一半，必须回到执行环。**

---

## 1. P-6 / extended1（FAIL，High）

### 1.1 代码事实

- `[READ:src/server/desktop_input_map.cpp:47]` `if (ev.extended1) return out;`（在 kKey 分支内，`40` 的零 scancode 之后）。
- `[READ:include/rtsc/server/desktop_input_map.h:139]` `return ev.scancode != 0 && !ev.extended1;`
- 解码侧把 0x04 忠实送进结构：`[READ:src/server/server.cpp:1946]`（fast-path）、`[READ:src/server/server.cpp:1842]`（slow-path）。
- `[READ:src/proto/input.cpp:90-102]` `EncodePauseKey()`：只有两个 CTRL 事件带 `extended1=true`，`kScancodePause = 0x45`（`[READ:include/rtsc/proto/input.h:96]`，注释即"shares the NumLock scancode"）的 down/up **不带** 0x04。
- 注入路径：`[READ:src/server/server.cpp:827-834]` `InjectIfLeasable` → `[READ:src/server/desktop_input_win32.cpp:142-147]` `TranslateInput` → 空则 `dropped_unsupported_++`；非空逐个入队。`[READ:src/server/desktop_input_win32.cpp:492-498]` 用 `KEYEVENTF_SCANCODE` + `wScan=0x45`（不带 `KEYEVENTF_EXTENDEDKEY`）发出。

### 1.2 红证（实跑，不改仓库）

探针：用 `rtsc::proto::EncodePauseKey()` 的真实字节，按 `ParseInputEvents` 同样的位解码构造 `InputEvent`，喂 `TranslateInput`（几何 1920×1080）。源码 `C:\Users\liulilte\AppData\Local\Temp\opencode\kprobe\pause_probe.cpp`。

```
[BASH: cl /I F:\rtsc\include pause_probe.cpp F:\rtsc\src\server\desktop_input_map.cpp F:\rtsc\build\Release\rtsc_proto.lib]
[BASH: pause_probe.exe]
EncodePauseKey() -> 4 events
wire 04 1D -> sc=1D e0=0 e1=1 rel=0 | n=0 | IsInjectable=0
wire 00 45 -> sc=45 e0=0 e1=0 rel=0 | n=1 | IsInjectable=1
    ACTION kind=0 sc=45 release=0
wire 05 1D -> sc=1D e0=0 e1=1 rel=1 | n=0 | IsInjectable=0
wire 01 45 -> sc=45 e0=0 e1=0 rel=1 | n=1 | IsInjectable=1
    ACTION kind=0 sc=45 release=1
TOTAL platform actions from PAUSE = 2 (NumLock 0x45 actions = 2)
VERDICT: FAIL (NumLock down/up still injected -> toggles local NumLock)
```

**4 事件序列逐项产出**：

| 线上字节 | 解码 | `TranslateInput` | `IsInjectable` |
|---|---|---|---|
| `04 1D` | sc=0x1D, rel=0, e0=0, **e1=1** | **0 个**（批 14 丢弃） | false |
| `00 45` | sc=0x45, rel=0, e0=0, e1=0 | **1 个 kKey down sc=0x45** | **true** |
| `05 1D` | sc=0x1D, rel=1, e0=0, **e1=1** | **0 个** | false |
| `01 45` | sc=0x45, rel=1, e0=0, e1=0 | **1 个 kKey up sc=0x45** | **true** |

即：**CTRL 被丢，NUMLOCK 照旧按下并抬起**。Windows 上 `SendInput` 的 `wScan=0x45`（非 E0 扩展）就是 NumLock，一次 down+up 必定翻转本机 NumLock 状态。这与 `docs/spec/input-injection-seam.md:452-464`（P-6 裁决④"绝不允许当作裸 CTRL/NumLock 注入"）以及本批审计 I 的 C1 完全一致——**批 14 只闭合了 C1 的一半，P-6 仍未闭合**。

### 1.3 附带后果（不只是 NumLock）

- **租约被 PAUSE 抢走**：`[READ:src/server/server.cpp:830]` 对 `00 45` 返回 `IsInjectable=true`，于是第一个非 E1 事件就会 `AcquireInputLease()`（`[READ:src/server/server.cpp:843-868]`）并 `SetGeometry`。PAUSE 序列本应"不可注入"，现在却能占用唯一租约槽位——与 `IsInjectable` 注释（`[READ:include/rtsc/server/desktop_input_map.h:128-132]`）的意图相悖。
- **键位簿记被污染**：`00 45` 被接受后进入 `pressed`（`[READ:src/server/desktop_input_map.cpp:140-161]`），若 `01 45` 被限流/硬限丢弃，本机就留下一个物理 NumLock 按下态，直到 `AppendReleasesLocked` 补 up。

### 1.4 最小修法（推荐：会话级序列状态机 + 保留现有 E1 兜底）

**不能只按 `scancode == 0x45` 判**——那会吃掉用户真正按的 NumLock。必须带状态：0xE1 envelope 打开后，紧随的 `0x45` down/up 属于同一 PAUSE 序列。

1. `include/rtsc/server/desktop_input_map.h` 增一个平台中立的纯状态机（可单测、不碰 SendInput）：

```cpp
// Per-session PAUSE (0xE1) envelope. Only the two CTRL halves carry 0x04 on the
// wire; the NUMLOCK(0x45) halves belong to the same sequence but are unflagged,
// so dropping only the flagged events would still inject a bare NumLock pair and
// toggle the local NumLock. Expects the 4 wire events in order:
//   04 1D / 00 45 / 05 1D / 01 45
class PauseSequenceFilter {
 public:
    // true = this event is part of an unrepresentable PAUSE sequence; drop it.
    bool ShouldDrop(const InputEvent& ev) {
        if (ev.kind != InputEvent::Kind::kKey) return false;  // do not close the window on mouse/wheel
        if (ev.extended1) { ctrl_armed_ = true; return true; }  // arm on down AND up (up precedes 0x45 up)
        if (ctrl_armed_ && ev.scancode == 0x45 && !ev.extended) {
            if (ev.release) ctrl_armed_ = false;                // window closes on the NumLock up
            return true;
        }
        ctrl_armed_ = false;                                    // any other key closes a stale window
        return false;
    }
    void Reset() { ctrl_armed_ = false; }
 private:
    bool ctrl_armed_ = false;
};
```

2. `src/server/server.cpp` `RdpSession` 加成员 `PauseSequenceFilter pause_filter_;`，并在 `InjectIfLeasable` **最前面**（`[READ:src/server/server.cpp:828]` 之后、租约门之前）加：

```cpp
if (pause_filter_.ShouldDrop(ev)) return;   // whole PAUSE sequence: unrepresentable
```

  放在租约门之前是关键：这样 PAUSE 既不会被注入，也不会抢租约。副作用：这 4 个事件不再进入 sink，`dropped_unsupported` 也就不会加 4。若需要可观测性，在 `RdpSession` 上加一个 `pause_suppressed_` 计数并经 `RdpServer` 的输入统计接出（可选，别为计数把事件重新放回注入路径）。

   注意 `[READ:src/server/server.cpp:59]` 已 `#include "rtsc/server/desktop_input_map.h"`，状态机放在该头文件内联即可，**不需要新增链接依赖**（`server.cpp` 属于 `rtsc_server`，`[READ:CMakeLists.txt:595-598]`；`desktop_input_map` 是纯头/纯映射库，不引 `<windows.h>`）。

   **若 J 坚持放 sink 层**：技术上可行（`sink` 已有 `SessionInputState`（`[READ:src/server/desktop_input_win32.cpp:112-115]`），把状态机挂在 `sets_` 里即可，`TranslateInput` 仍保持纯函数），但**必须同时解决租约**——因为 `IsInjectable` 是按单事件无状态判定的（`[READ:src/server/server.cpp:829-832]`），sink 过滤发生时租约已经被拿走。两条都不做而只在 sink 过滤 = 仍然"PAUSE 抢租约"，只能算部分修。故推荐 server 层。

3. 保留 `map.cpp:47` 与 `map.h:139` 的 E1 检查作为第二道防线（sink 若被其它调用方直接驱动仍不会注入 E1 半）。

   覆盖范围：过滤器吃 `InputEvent`，因此**快路径与慢路径同时覆盖**——慢路径 `[READ:src/server/server.cpp:1842]` 也从 `keyboardFlags & 0x0200` 解出 `extended1`，两条路径最终都走 `InjectIfLeasable`（`[READ:src/server/server.cpp:1908,2034]`）。

4. **新测试（先红后绿）**：
   - `tests/test_desktop_input.cpp`：新增用例驱动 `PauseSequenceFilter` 走完整 `04 1D / 00 45 / 05 1D / 01 45`，断言**每个** `ShouldDrop==true`、且总平台动作 **0**；对照组 1：独立 NumLock、tap（`00 45`/`01 45`）必须 `ShouldDrop==false` 且产出 2 个动作；对照组 2（对抗）：孤立 `04 1D` 后连续两次 NumLock tap，只允许吞掉第一次（下界封顶，不产生无限吞键）。
   - `tests/test_server.cpp`：`cfg.enable_desktop_input=true` + `RecordingInputSink`（`[READ:tests/test_server.cpp:542]`），发一条 `EncodeFastPathInputPdu(EncodePauseKey())`，断言 `sink.inject_ids().empty()`；再发独立 NumLock 事件断言 2 次 inject。**现有 `server_input_extended_flags_are_prefixes`（`[READ:tests/test_server.cpp:1343-1416]`）只断言解码（且显式写明注入 UNVERIFIED），修完仍应保持绿。**

**先红后绿（同一断言集，只切换过滤实现）**：`redgreen.cpp`，`/DBASELINE` 编译 = 出厂行为（只有 E1 被 `TranslateInput` 丢），默认编译 = 上述 `PauseSequenceFilter`。

```
[BASH: rg_red.exe]   filter = BASELINE (shipped: only 0xE1 dropped)
[FAIL] PAUSE 04 1D / 00 45 / 05 1D / 01 45 -> actions       got=2 want=0
[ OK ] standalone NumLock tap -> actions                    got=2 want=2
[FAIL] lone E1 + 2 NumLock taps -> actions                  got=4 want=2
RED (2 failing assertions)      exit=1

[BASH: rg_green.exe] filter = PROPOSED PauseSequenceFilter (whole sequence)
[ OK ] PAUSE 04 1D / 00 45 / 05 1D / 01 45 -> actions       got=0 want=0
[ OK ] standalone NumLock tap -> actions                    got=2 want=2
[ OK ] lone E1 + 2 NumLock taps -> actions                  got=2 want=2
GREEN (0 failing assertions)    exit=0
```

即：**修法是"PAUSE 3 条断言先红、加状态机后全绿"，不是纸面推导**。

设计性质（修完应保持）：
- 过滤点只在 `InjectIfLeasable`，**`input_callback_`（`[READ:src/server/server.cpp:2035/1909]`）仍收到全部 4 个事件**，诊断/日志观测不受影响。
- `IsInjectable(0x45)==true` **保持不变**（真实 NumLock 必须可注入），因此 §1b 的逐 kind 锁步不被破坏——过滤是"序列状态"而非"scancode 单点"，两者不冲突。
- 状态机在 `ReleaseSession` 后必须 `Reset()`（会话对象销毁即自然重置；若同一 `RdpSession` 跨租约复用，可在 `ReleaseInput` 处补一行）。

**备选修法（更简单但有代价，不推荐单独使用）**：在 `map.cpp` 对 `scancode==0x45` 一律丢弃。代价：真实 NumLock 键彻底不可用（客户端常用的 NumLock 开关全废），且仍会残留"PAUSE 抢租约"问题（需同时改 `IsInjectable` 才能在租约门前生效）。故推荐上面的状态机方案。

**严重度 High**：每次远端 Pause = 本机 NumLock 翻转（会改变本机键盘状态，属 P-6 裁决④明令禁止的副作用），且可被利用抢占输入租约。

---

## 1b. `IsInjectable` 与 `TranslateInput` 锁步（PASS，附注释口径问题）

`[READ:include/rtsc/server/desktop_input_map.h:136-151]` 逐 kind：

| kind | `IsInjectable` | `TranslateInput`（可用几何） | 一致 |
|---|---|---|---|
| kKey | `scancode!=0 && !extended1` | `40` 零码丢弃、`47` E1 丢弃，否则 1 个 | ✅ |
| kUnicode | `unicode_code!=0` | `60` 零码丢弃，否则 1 个 | ✅ |
| kMouse | `is_move || button!=0` | 几何可用时 move 1 个 + 可选 button 1 个；全 0 为空 | ✅（**仅可用几何**） |
| kWheel | `wheel_delta!=0` | `105` 零值丢弃，否则 1 个 | ✅ |
| kMouseRel / kSync | false | 空 | ✅ |

交叉测试 `[READ:tests/test_desktop_input.cpp:940-1009]` 已覆盖 extended1 半、零滚轮、零 scancode、零 unicode、bare mouse、kMouseRel、kSync，并在 `996` 用 `{1920,1080}` 几何做等价断言，`992-995` 明确把"退化几何"排除在等价关系之外。

**结论 PASS**，但两点提示（非缺陷）：
- `map.h:128` 的注释"True when TranslateInput would produce at least one platform action"在退化几何（0/1）下不成立（kMouse move-only：`true` vs 空）。建议在该注释补一句"geometry-dependent: 退化几何下 absolute move 不产出"，与测试注释同源。
- 可达性：生产几何来自 `ClampDesktopSize`（`[READ:src/server/server.cpp:150-173,1306-1317]`），配置 0 被 `ValidateDesktopSize` 拒绝（`[READ:src/server/server.cpp:175-182]`），因此只有"配置成 1×1"这一类退化配置能触发不一致；此时租约会被只有 move 的会话占用但不动指针。**Low**，可选修法：`InjectIfLeasable` 在已知几何下对 `kMouse && is_move && button==0 && (w<=1||h<=1)` 提前 return。

---

## 2. 几何（PASS）

代码：`[READ:src/server/desktop_input_map.cpp:78]` `if (ev.is_move && g.width > 1 && g.height > 1)`；按钮分支在 `87-93` **独立于**几何判定。

- **"几何不足时按下/释放仍注入"是否正确？→ 正确。** 依据：`[READ:src/server/desktop_input_map.cpp:85-93]` 按钮事件不携带坐标（`PlatformInput` 的 button 分支只写 `button/button_down`），抑制它只会丢点击，并让随后的 release 变成"释放一个从未按下的键"，本机反而更脆弱；测试 `[READ:tests/test_desktop_input.cpp:195-207]` 已把该取舍钉死（`{0,0}` 几何下 `kMouseButton` 仍产出 1 个动作）。
- **`NormalizeAxis` 的 `extent<=1` 分支是否死代码？→ 是（无调用者），但属有意防御。**
  - `NormalizeAxis` 在匿名命名空间（`[READ:src/server/desktop_input_map.cpp:10-30]`），全仓唯一调用点是 `81-82`（`[BASH: grep NormalizeAxis]` 仅命中 `22/81/82`），而 `81-82` 被 `g.width>1 && g.height>1` 守卫，故 `extent<=1` 分支**不可达**。
  - `22-27` 的注释已如实说明"Callers reject …; the guard here only keeps a future caller from dividing by zero"。判定 **PASS（无需改码）**；若想消除死分支，可改为 `assert(extent > 1)`，但会失去防除零兜底，**建议保留现状**。
- 附带核对（非本批引入）：几何仍取**协商后钳制的 framebuffer**（`[READ:src/server/server.cpp:1306-1317]`）、注入恒 `VIRTUALDESK`（`[READ:src/server/desktop_input_win32.cpp:505-507]`）。即审计 I 的 C2（`--monitor N` 子矩形原点偏移）**本批未处理，仍未闭合**，但不在本批范围内，此处仅记录。

---

## 3. 零滚轮（PASS）

代码：`[READ:src/server/desktop_input_map.cpp:96-111]`，零值在 `105` 提前 `return out;`；`IsInjectable` 同步改为 `[READ:include/rtsc/server/desktop_input_map.h:145]` `return ev.wheel_delta != 0;`。

**"`wheel_delta==0` 与 `IsInjectable(kWheel)==true` 是否矛盾？"→ 现在不矛盾（已在同一次提交中成对修改）。**

- 新目标（未持租约）：零滚轮 `IsInjectable=false` → `[READ:src/server/server.cpp:829-832]` 直接 return，**不取租约**。
- 已持租约：`[READ:src/server/server.cpp:833]` 仍转发给 sink（为了不让 `dropped_unsupported` 漏计），`[READ:src/server/desktop_input_win32.cpp:142-147]` 翻译为空 → `dropped_unsupported_++` 后 return。**不占队列位、不耗限流令牌、不启动 worker 唤醒后的实际动作**（`cv_.notify_one()` 在 `:156` 仍会执行，但队列为空，worker 空转一次即回睡——可忽略）。
- 交叉测试 `[READ:tests/test_desktop_input.cpp:978-981,1008]` 覆盖零滚轮不取租约；单事件语义测试 `266-285`。

结论：审计 I 的 C4 已闭合，**无"占租约/耗令牌/入队"的残留**。

---

## 4. 新测试覆盖面（FAIL，Medium）

批 14 新增的三条用例均为**单事件**（行号口径：题目给的 `85/260` 是 `805428b` 提交内的位置；当前终态 `6fc5614` 因前面插入了 `IsInjectable` 引用与 win32 用例，已后移为 `91/266`）：

- `[READ:tests/test_desktop_input.cpp:91-116]` `desktop_input_extended1_is_not_injected`（提交内 `85`）：只断言"带 E1 的单事件 → 空"，并顺手断言 `<0x1D>` 与 `<0x1D,e0>` 两个对照。**没有任何一行构造 `0x45` 事件。**
- `[READ:tests/test_desktop_input.cpp:172-208]` 几何：覆盖 `{0,0}`/`{1,1}`/`{2,1}`/`{1,2}`/`{2,2}` 与 button 语义，覆盖良好。
- `[READ:tests/test_desktop_input.cpp:266-285]` 零滚轮（提交内 `260`）：覆盖垂直/水平零值与 ±120，覆盖良好。
- `[READ:tests/test_desktop_input.cpp:940-1009]` 交叉一致性：只放 `0x1D(E1)` 与零滚轮单事件。

唯一涉及完整 PAUSE 的地方是 **server 解码**测试 `[READ:tests/test_server.cpp:1343-1416]`：它把 `EncodePauseKey()` 的 4 事件 + 一个 End 键送入服务器，断言 `got.size()==5` 并逐字段核对 `extended1`。它**不安装 sink**、不断言注入结果，注释 `1349-1350` 自述"Pause injection itself stays UNVERIFIED"。因此：

- **测试套件无法发现"NUMLOCK 仍被注入"**——这是第 1 点缺陷存活的直接原因，属"变异 M6 存活"的同类问题（审计 I §4.4 已预警，本批只补了半条单事件断言）。
- 判定 **FAIL（Medium：不是运行期缺陷，但正是让 High 缺陷漏网的门）**。修法见 §1.4 第 4 步（序列级用例 + server 级 sink 断言 + 对抗用例）。

### 4.1 变异实测（把 `test_desktop_input.cpp` + 改坏的 `desktop_input_map.cpp` 单独编到临时目录，仓库不动）

| 变异 | 改法 | 结果 |
|---|---|---|
| A：删掉 `extended1` 丢弃 | `map.cpp:47` 删除 | **红**（`desktop_input_extended1_is_not_injected` + 交叉一致性，2 tests / 3 checks） |
| C：删掉零滚轮丢弃 | `map.cpp:105` 删除 | **红**（`desktop_input_zero_wheel_is_not_injected` + 交叉一致性，2 tests / 3 checks） |
| D：删掉几何守卫 | `map.cpp:78` 条件退回 `if (ev.is_move)` | **红**（`..._requires_usable_geometry`，5 checks；含 `{1,2}` 与"退化几何下 click 变 2 个动作"） |
| **B：全局丢弃 `scancode==0x45`**（错误的"快速修法"） | `map.cpp` 加 `if (ev.scancode == 0x45) return out;` | **全绿：46 tests / 13752 checks / 0 failing** |

B 存活是决定性证据：**现有测试无法区分"PAUSE 被完整抑制"与"NumLock 键彻底失效"**，也无法区分"PAUSE 半修"。K2 的两条新用例（序列 0 动作 + 独立 NumLock 2 动作）恰好把 B 与 K1 同时变成红，属最小且必要的补测。

---

## 5. 回归（PASS）

C0（编译/类型）：全量重新配置编译，**exit=0，零 error、零 warning**（`/W4 /WX` 已对该 target 生效，`[READ:CMakeLists.txt:890-892]`）。

```
[BASH: cmake --build build --config Release --clean-first]   exit=0
[BASH: findstr warning|error build.log]                      （无命中）
```

测试（独占运行，两次）：

```
[BASH: build\Release\rtsc_desktop_input_tests.exe]
46 tests, 13752 checks, 0 failing tests, 0 failed checks        exit=0
[BASH: build\Release\rtsc_server_tests.exe]
49 tests, 564 checks, 0 failing tests, 0 failed checks          exit=0
[BASH: ctest --test-dir build -C Release]  （旧二进制）
100% tests passed, 0 tests failed out of 63                     (56.54 s)
[BASH: ctest --test-dir build -C Release]  （--clean-first 全量重编后）
100% tests passed, 0 tests failed out of 63                     (76.49 s)
```

判定 **PASS**：批 14 的改动没有让任何既有用例变红（46 + 49 + 63 全绿）；但注意——**全绿不等于 P-6 正确**，第 1 点的缺陷正是"在绿树下存在"。

---

## 6. FAIL 清单与最小修法

| # | 严重度 | FAIL | 证据 | 最小修法 | 验证 |
|---|---|---|---|---|---|
| K1 | **High** | PAUSE 的 NUMLOCK(0x45) down/up 仍被注入，每次远端 Pause 翻转本机 NumLock；且 PAUSE 会抢输入租约 | `map.cpp:47` 仅丢 extended1；`proto/input.cpp:98,100` 的 0x45 不带 0x04；红证 4 事件产出 2 个 0x45 动作 | 见 §1.4：`PauseSequenceFilter`（纯状态机）+ `RdpSession` 成员，`InjectIfLeasable` **租约门前**过滤；保留 `map.cpp:47`/`map.h:139` 兜底 | 序列级单测（0 动作）+ 独立 NumLock 对照（2 动作）+ 对抗用例；server 级 sink 断言 0 次 inject |
| K2 | Medium | 无 PAUSE 全序列注入测试，半修可通过全部 46+49 用例 | `test_desktop_input.cpp:91-116` 只测单事件；`test_server.cpp:1343-1416` 只断言解码 | 随 K1 补两组用例（见 §1.4 步骤 4） | 先红（当前实现红）后绿 |
| K3 | Low | `map.h:128` 的锁步注释在退化几何下不成立（kMouse move-only） | `map.h:136-151` vs `map.cpp:78` | 注释补"geometry-dependent"；可选在 `InjectIfLeasable` 提前跳过退化几何下的 move-only 事件 | 注释 + 可选 server 用例 |
| K4 | 记录 | 审计 I 的 C2（`--monitor N` 子矩形原点偏移）本批未处理 | `server.cpp:1306-1317`、`desktop_input_win32.cpp:505-507` | 不在本批范围，按 C2 原方案另行裁决 | 真机 UNVERIFIED |

**优先级**：K1 = K2（同一次改动一起做）> K3 > K4。

---

## 7. 与审计 J 的互审（待回执）

本报告把以下三条作为待交叉验证项发给 J（`ses_e676f4a60ffeJvOfQZOzd86Sb0`）：

1. **PAUSE 红证**：4 事件产出 `NUM down/up` 两个动作（附件输出如上）。请独立复跑（或用你自己的探针）确认，避免"我一个人的探针错"。
2. **修法形态**：K1 建议放 **server 会话层**（`InjectIfLeasable` 租约门前），而非 sink 内部——理由是"不能抢租约"。若 J 认为必须在 sink 层（防其它调用方），需同时解决 `IsInjectable` 无几何/无状态导致的租约问题，请给出理由。
3. **K3 是否值得修**：我判 Low（仅配置 1×1 可触发）；若 J 认为 `ClampDesktopSize` 其它路径也能产出 1，请指出具体输入。

J 的 teardown/测试缝结论不影响本报告的代码证据（均为本工作树读码 + 本地探针）。

---

## 8. 未验证与限制

1. 本角色只读，未改 `src/include/tests/tools/CMakeLists`；探针全部编译在 `C:\Users\liulilte\AppData\Local\Temp\opencode\kprobe\` 下，独立于仓库。
2. **未做真机 SendInput**：`NumLock` 翻转是"`wScan=0x45` + `KEYEVENTF_SCANCODE` 即 NumLock"的确定性推理（Win32 文档与仓库 `[READ:include/rtsc/proto/input.h:96]` 的注释），未在本机实际按键复现（审计角色不动本机键鼠状态）。标 **【UNVERIFIED-真机】**，但线上字节与翻译层的两个动作是**已实测**的。
3. 未验证 `PauseSequenceFilter` 在 `ReleaseSession` 中途被打断的边界（建议 `ReleaseSession` 或 `kSync` 时 `Reset()`，实现时补一行即可）。
4. 未重跑 J 负责的 teardown/测试缝主题。
