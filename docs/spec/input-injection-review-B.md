# 输入注入相关提交独立复核（审计乙）

- 审计角色：独立审计 AI 乙（接替因宿主 TLS 证书错误终止的前一会话）。
- 审计范围：只读复核 `10b3b20`（慢路径输入解码 / 能力位 / 滚轮切块）、`e6c4ad7`（切块上限可观测）、以及主代理追加的 `afb2a69`（desktop input injection skeleton）。
- 独立性声明：本报告未读取 `docs/spec/input-wheel-review-A.md`，未采用任何其他审计的结论；规范值全部由本人 webfetch 原文核对。
- 只读声明：未修改 `src/`、`include/`、`tests/`、`tools/`、`CMakeLists.txt`；所有变异均在 `%TEMP%` 的 `git archive` 副本中进行。本报告文件是唯一写产物。
- 环境：Windows / MSVC 19.44.35229.0 / CMake（VS 2022 内置） / 生成器 `Visual Studio 17 2022` x64。
- 代码行号均指对应提交的已提交内容（`git show <commit>:<path>`），不是工作树。

---

## 0. 构建与基线（对照用，不作为被审对象的证据）

两个隔离构建目录（按要求放在 `%TEMP%` 之外，避免 MSB8029 破坏增量）：

| 用途 | 源（git archive） | 构建目录 |
|---|---|---|
| 慢路径/客户端 | `e6c4ad7` → `%TEMP%\rtsc-mut-src-b6` | `C:\Users\liulilte\rtsc-mutbuild-b6` |
| 注入骨架 | `afb2a69` → `%TEMP%\rtsc-mut-src-b7` | `C:\Users\liulilte\rtsc-mutbuild-b7` |

本人实测基线（原始未变异）：

```
[BASH] rtsc_server_tests.exe  → 40 tests, 433 checks, 0 failing tests, 0 failed checks (EXIT=0)
[BASH] rtsc_client_tests.exe  → 25 tests, 139 checks, 0 failing tests, 0 failed checks (EXIT=0)
[BASH] rtsc_desktop_input_tests.exe → 14 tests, 57 checks, 0 failing tests, 0 failed checks (EXIT=0)
```

`rtsc_client_tests` 的 25/139/0 与任务给出的已知基线一致。

---

## 1. 规范原文逐值核对（本人 webfetch）

### 1.1 `[MS-RDPBCGR] 2.2.7.1.6 TS_INPUT_CAPABILITYSET` — inputFlags

原文：<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b3bc76ae-9ee5-454f-b197-ede845ca69cc>（2026-11-01 抓取）

| 规范原文 Flag | 值 |
|---|---|
| INPUT_FLAG_SCANCODES | 0x0001（"At a minimum ... MUST be set"） |
| INPUT_FLAG_MOUSEX | 0x0004 |
| INPUT_FLAG_FASTPATH_INPUT | 0x0008 |
| INPUT_FLAG_UNICODE | 0x0010 |
| INPUT_FLAG_FASTPATH_INPUT2 | 0x0020 |
| INPUT_FLAG_UNUSED1 | 0x0040 |
| INPUT_FLAG_MOUSE_RELATIVE | 0x0080 |
| TS_INPUT_FLAG_MOUSE_HWHEEL | 0x0100 |
| TS_INPUT_FLAG_QOE_TIMESTAMPS | 0x0200 |

规范表中**没有 0x0002**。

代码值：[READ:include/rtsc/proto/capabilities.h:235-264]

```cpp
uint16_t input_flags = kInputFlagScancodes | kInputFlagFastPathInput |
                       kInputFlagFastPathInput2 | kInputFlagMouseX |
                       kInputFlagUnicode | kInputFlagMouseHWheel;
```

按位计算（本人命令输出）：

```
[BASH] "0x{0:X4}" -f (0x0001 -bor 0x0004 -bor 0x0008 -bor 0x0010 -bor 0x0020 -bor 0x0100)
0x013D
```

结论：**一致**。默认值恰为 0x013D；必需的 0x0001 已置；历史常量 `kInputFlagMouse = 0x0002` 保留但不参与默认值（`capabilities.h:236-240`），因此没有广告规范中不存在的位。0x0080 MOUSE_RELATIVE 未广告——这是与"注入层不注入相对鼠标"一致的保守选择（见 §2/§5.1），不是漏必需位。

补充：`server_advertises_fastpath_input_capability` 从真实 Demand Active 线上字节读取并断言 0x0001/0x0008/0x0020/0x0100/0x0010 置位、0x0002 清零（[READ:tests/test_server.cpp:641-646]）。

### 1.2 `[MS-RDPBCGR] 2.2.8.1.1.3.1.1 TS_INPUT_EVENT` — messageType 与事件体长度

原文：<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a9a26b3d-84a2-495f-83fc-9edd6601f33b>

结构：`eventTime (4 bytes) + messageType (2 bytes) + slowPathInputData (variable)`。

| 规范原文 messageType | 值 | 事件体 | 事件体长度 |
|---|---|---|---|
| INPUT_EVENT_SYNC | 0x0000 | TS_SYNC_EVENT | pad2Octets(2)+toggleFlags(4)=6 |
| INPUT_EVENT_UNUSED | 0x0002 | TS_UNUSED_EVENT | pad4Octets(4)+pad2Octets(2)=6 |
| INPUT_EVENT_SCANCODE | 0x0004 | TS_KEYBOARD_EVENT | keyboardFlags(2)+keyCode(2)+pad2Octets(2)=6 |
| INPUT_EVENT_UNICODE | 0x0005 | TS_UNICODE_KEYBOARD_EVENT | keyboardFlags(2)+unicodeCode(2)+pad2Octets(2)=6 |
| INPUT_EVENT_MOUSE | 0x8001 | TS_POINTER_EVENT | pointerFlags(2)+xPos(2)+yPos(2)=6 |
| INPUT_EVENT_MOUSEX | 0x8002 | TS_POINTERX_EVENT | 同 TS_POINTER_EVENT=6 |
| INPUT_EVENT_MOUSEREL | 0x8004 | TS_RELPOINTER_EVENT | pointerFlags(2)+xDelta(2)+yDelta(2)=6 |

各结构原文分别见：2.2.8.1.1.3.1.1.1 `7acaec9f-c8a6-4ee9-87d6-d9b89cf56489`、`.2` `551b9903-8fb9-4d00-b3ac-a187431efb86`、`.3` `2c1ced34-340a-46cd-be6e-fc8cab7c3b17`、`.4` `2ef7632f-2f2a-4de7-ab58-2585cedcdf48`、`.5` `6c5d0ef9-4653-4d69-9ba9-09ba3acd660f`、`.6` `afbdb159-89cf-4e96-890b-ea955b723701`、`.7` `9af47964-8bfc-4f43-8a15-4339a89833fa`。

代码值：[READ:include/rtsc/proto/share.h:175-190]

```cpp
enum class SlowPathInputEventType : uint16_t {
    kSync = 0x0000, kUnused = 0x0002, kScancode = 0x0004,
    kUnicode = 0x0005, kMouse = 0x8001, kMouseX = 0x8002, kMouseRel = 0x8004,
};
constexpr size_t kSlowPathInputEventHeaderSize = 6;
constexpr size_t kSlowPathInputEventSize = 12;
```

解码器按 `eventTime(4)+messageType(2)+body(6)` 的 12 字节步长走查，body 取 6 字节（[READ:src/server/server.cpp:1616-1698]）。

结论：**一致**。7 个 messageType 值全部相同；每个已定义事件的 body 都是 6 字节，因此固定 12 字节步长成立。`TS_UNUSED_EVENT` 页面把 pad2Octets 文字误写成 "32-bit"，但字段图明确是 2 字节；代码按 6 字节处理是正确的。

### 1.3 `[MS-RDPBCGR] 2.2.8.1.1.3.1.1.7 TS_RELPOINTER_EVENT` — pointerFlags 与 X1/X2

原文：<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9af47964-8bfc-4f43-8a15-4339a89833fa>

| 规范原文 Flag | 值 | 含义 |
|---|---|---|
| PTRFLAGS_MOVE | 0x0800 | 按 xDelta/yDelta 移动 |
| PTRFLAGS_DOWN | 0x8000 | 按下事件 |
| PTRFLAGS_BUTTON1 | 0x1000 | 左键（button 1） |
| PTRFLAGS_BUTTON2 | 0x2000 | 右键（button 2） |
| PTRFLAGS_BUTTON3 | 0x4000 | 中键（button 3） |
| PTRXFLAGS_BUTTON1 | 0x0001 | 扩展键 1（button 4） |
| PTRXFLAGS_BUTTON2 | 0x0002 | 扩展键 2（button 5） |

`xDelta/yDelta` 为 **16-bit signed**。`TS_FP_RELPOINTER_EVENT`（2.2.8.1.2.2.7）原文明确 "The possible flags are identical to those found in the pointerFlags field of the TS_RELPOINTER_EVENT structure."

代码值：[READ:src/server/server.cpp:1766-1797]（fast-path MOUSEREL）

```cpp
ev.kind = InputEvent::Kind::kMouseRel;
ev.rel_x = static_cast<int16_t>(...);
ev.rel_y = static_cast<int16_t>(...);
DecodePointerButtons(pf, false, ev);           // PTRFLAGS_BUTTON1/2/3 + PTRFLAGS_DOWN
if (ev.button == 0) {
    if ((pf & proto::kPtrXButton2) != 0) ev.button = 5;
    else if ((pf & proto::kPtrXButton1) != 0) ev.button = 4;
}
```

常量定义：[READ:include/rtsc/proto/input.h:35-58]（0x8000/0x4000/0x2000/0x1000/0x0800/0x0400/0x0200/0x01FF，X1=0x0001、X2=0x0002）。

结论：**一致**。X1/X2 在 TS_RELPOINTER_EVENT 中合法；代码既解普通 1/2/3（0x1000/0x2000/0x4000）也解 X1/X2（0x0001/0x0002），且 deltas 按有符号 i16 处理。

---

## 2. 慢路径与 fast-path 的语义一致性

关键语义由同一函数 `DecodePointerEvent` / `DecodePointerButtons` 承担（[READ:src/server/server.cpp:549-598]）：

- 慢路径 `kMouse`/`kMouseX` → `DecodePointerEvent(...)`（[READ:src/server/server.cpp:1662-1674]）
- fast-path `kMouse`/`kMouseX` → `DecodePointerEvent(...)`（[READ:src/server/server.cpp:1745-1760]）

因此以下四项**完全共用**，不存在两份实现：

| 语义 | 共用点 | 结果 |
|---|---|---|
| wheel 9 位二补码符号扩展 | `DecodePointerEvent` 内 `raw & 0x01FF`，`(raw & 0x0100) ? raw - 0x0200 : raw` | 一致 |
| `is_move` | `ev.is_move = (pf & kPtrMove) != 0` | 一致 |
| `horizontal` | `ev.horizontal = !(pf & kPtrWheel)` | 一致 |
| 按钮身份（含 X1/X2 命名空间选择） | `DecodePointerButtons(pf, mouse_x, ev)` | 一致 |

键盘/Unicode/Sync 是两段独立填充（慢路径 [READ:src/server/server.cpp:1630-1661]；fast-path [READ:src/server/server.cpp:1722-1765]），逐字段核对后等价：

- 键盘：慢路径 `KBDFLAGS_RELEASE 0x8000 / EXTENDED 0x0100 / EXTENDED1 0x0200` → `release/extended/extended1`；fast-path `0x01/0x02/0x04` → 同三字段。scancode 均取低 8 位。
- Unicode：两路都只映射 `release`；`unicode_code` 布局相同。
- Sync：慢路径 `toggleFlags` 低字节 `& 0x1F`；fast-path `eventFlags` 已是 5 位 `& 0x1F`。两者都保留规范未定义的 0x10 位，行为一致（见发现 F-3）。

**分叉（唯一）**：`INPUT_EVENT_MOUSEREL`（0x8004）在 fast-path 分支被解码为 `kMouseRel`，但慢路径分支只计数后 `continue`，不产生事件：

- 慢路径：[READ:src/server/server.cpp:1677-1686] "belongs to the dedicated kMouseRel workstream; count it rather than create a second semantic here"
- fast-path：[READ:src/server/server.cpp:1766-1797]

结论：**PASS（指针语义零分叉）**，但发现 F-1：提交说明声称慢路径解码含 MOUSEREL，实际未解码；且服务器未广告 0x0080 MOUSE_RELATIVE，故合规客户端不会发送相对鼠标，功能上可接受，但提交信息与实现不符，需在文档/提交说明中纠正。

---

## 3. 健壮性

### 3.1 慢路径 `ParseSlowPathInput`（[READ:src/server/server.cpp:1616-1698]）

| 攻击面 | 代码处理 | 结论 |
|---|---|---|
| `n < 4`（没有 numEvents/pad） | `if (n < 4) return;` | 安全 |
| 读 messageType 前越界 | 先 `pos + 6 > n` 返回，再读 `p[pos+4..5]` | 安全 |
| 事件体截断 | `pos + 12 > n` 返回（读完 header 后、读 body 前） | 安全 |
| `numEvents` 与载荷不符 | 每次循环用 `pos` 与 `n` 做边界检查；不足即返回，多余载荷忽略 | 安全，不越界 |
| `remaining` 下溢 | 实现中不存在递减的 `remaining`；只用 `pos += 12`，`pos <= n` | 不适用，无下溢 |
| `numberEvents = 0xFFFF` | `for (uint16_t i=0; i<count; ++i)` 最多 65535 次；每次推进 12 且越界返回；4 字节载荷第一次迭代即返回 | 安全，无死循环/无溢出 |
| 未知 messageType | 计数 `unknown_input_events_` 后 `return`（放弃本 PDU） | 安全（长度未知无法重同步） |
| 整数提升 | `p[0] | (p[1] << 8)` 的 `uint8_t` 提升为 `int`，无符号/有符号扩展问题 | 安全 |

边界测试由 `server_slowpath_malformed_input_is_survivable` 覆盖：截断（count=2 只给 1 个事件）、`0xFFFF` + 4 字节载荷、未知 0x0007 计数，且每次畸形 PDU 之后仍能继续解快路径按键（[READ:tests/test_server.cpp:1735-1817]）。基线实测该夹具通过（§0）。

### 3.2 客户端滚轮切块（[READ:src/client/client.cpp:20-40,247-307]）

- 单位：`kWheelUnitsPerNotch = 120`，`units = int64(wheel_delta) * 120`（[src/client/client.cpp:278-280]）——`int16 * 120` 在 int64 中计算，INT16_MIN 也不溢出。
- 单块上限：`kWheelStep = 255`；每块 `rotation & 0x01FF`，即 |rotation| ≤ 255，落在 9 位二补码可表示区间（-256..255）内，且不使用 -256 这个单一码点（注释已说明）。
- 总量守恒：`chunks = ceil(magnitude/255)`，块数 ≤ 8 时逐块 `part = min(remaining,255)`，和恰为 `magnitude`。本人算例与测试一致：
  - 3 格 = 360 → 2 块 255+105=360（[READ:tests/test_client.cpp:229-263]）
  - 17 格 = 2040 → 8 块×255=2040，丢弃 0（[READ:tests/test_client.cpp:309-318]）
  - 18 格 = 2160 → 封顶 8 块，发送 2040，丢弃 120（[READ:tests/test_client.cpp:321-332]）
  - 120 格 = 14400 → 发送 2040，丢弃 12360（[READ:tests/test_client.cpp:337-359]）
- 上限丢弃可观测：`dropped_wheel_units_count()` 公开、单调、按"单位"累计（[READ:include/rtsc/client/client.h:155-163,191-192]；[READ:src/client/client.cpp:301-306]）。e6c4ad7 把"静默截断"改成"计数"，并有 3/17/18/120 四组测试。
- 水平滚轮门控：服务器未广告 0x0100 时丢弃并 `dropped_hwheel_count_` 计数（[READ:src/client/client.cpp:247-258]），符合 2.2.8.1.1.3.1.1.1 的 MUST NOT。

结论：**PASS**。上限丢弃不可避免地损失旋转量（设计如此），但已可观测且文档/测试一致。

### 3.3 慢/快路径分派的一个残余观察（F-2，低危）

`HandleSlowPathPdu` 先尝试把任意载荷解析为 `ShareDataHeader`，只有 `pduType=7 且 pduVersion=1` 才标记为已处理（[READ:src/proto/share.cpp:86-108]，[READ:src/server/server.cpp:1549-1560]）。合法的 fast-path 输入 PDU 极难与之撞车：需要 `bytes[2..3] == 0x17,0x00`，即首个事件头 0x17（scancode、eventFlags 含未定义的 0x10 位）且 keyCode=0。这只会出现在**非合规**客户端上，后果是该事件被吞掉，不是内存安全问题。记录为观察项，不构成 FAIL。

---

## 4. 独立变异测试（红证）

### 4.1 变异 A：慢路径 MOUSE messageType 0x8001 → 0x8003

- 源：`git archive e6c4ad7` → `%TEMP%\rtsc-mut-src-b6`
- 构建目录：`C:\Users\liulilte\rtsc-mutbuild-b6`
- 变异点：`include/rtsc/proto/share.h` 的 `SlowPathInputEventType::kMouse`（解码器 switch 的匹配常量）
- 基线：`rtsc_server_tests` = 40 tests / 433 checks / 0 failing

**过程诚实记录（重要）**：第一次增量构建后测试仍全绿，但 `rtsc_server_tests.exe` 时间戳（04:29:23）早于被改头文件的时间戳（04:32:44），说明 MSBuild 未重新编译 `server.cpp`，绿色是**陈旧二进制假象**。强制 touch `server.cpp` 触发重编后（exe 04:37:16）才得到真实结果。这也反证该测试不是"假测试"。

变异后原始失败行：

```
[ FAIL ] server_decodes_slowpath_mouse_wheel
  FAIL C:\Users\liulilte\AppData\Local\Temp\rtsc-mut-src-b6\tests\test_server.cpp:1612  got.size() == static_cast<size_t>(2) (got 0, want 2)
40 tests, 425 checks, 1 failing tests, 1 failed checks
TEST_EXIT=1
```

恢复后：

```
40 tests, 433 checks, 0 failing tests, 0 failed checks
TEST_EXIT=0
```

`Get-FileHash -Algorithm SHA256` 双证：

```
原始 share.h      : 961EFA08657D28B1306FEEBF0EA7CAA2AB7A87ED1F1A5C75B3B377DB86F93BAB
变异 share.h      : ECA01EFC887872D032DDB29569680E9913FF28468B3BE7B243EDF22481C06232
恢复 share.h      : 961EFA08657D28B1306FEEBF0EA7CAA2AB7A87ED1F1A5C75B3B377DB86F93BAB
```

结论：**PASS**（先绿→变异红→恢复绿，哈希证明恢复原样）。

### 4.2 变异 B：TranslateInput wheel 乘 120

- 源：`git archive afb2a69` → `%TEMP%\rtsc-mut-src-b7`
- 构建目录：`C:\Users\liulilte\rtsc-mutbuild-b7`
- 变异点：`src/server/desktop_input_map.cpp:84` `wheel.wheel = ev.wheel_delta;` → `ev.wheel_delta * 120;`
- 基线：`rtsc_desktop_input_tests` = 14 tests / 57 checks / 0 failing

变异后原始失败行：

```
[ FAIL ] desktop_input_wheel_positive_is_wire_units
  FAIL ...\tests\test_desktop_input.cpp:147  out[0].wheel == 120 (got 14400, want 120)
[ FAIL ] desktop_input_wheel_negative_is_wire_units
  FAIL ...\tests\test_desktop_input.cpp:159  out[0].wheel == -120 (got -14400, want -120)
[ FAIL ] desktop_input_horizontal_wheel
  FAIL ...\tests\test_desktop_input.cpp:172  out[0].wheel == 120 (got 14400, want 120)
[ FAIL ] desktop_input_wheel_ignores_xy
  FAIL ...\tests\test_desktop_input.cpp:207  out[0].wheel == 120 (got 14400, want 120)
14 tests, 57 checks, 4 failing tests, 4 failed checks
TEST_EXIT=1
```

恢复后：

```
14 tests, 57 checks, 0 failing tests, 0 failed checks
TEST_EXIT=0
```

哈希双证：

```
原始 desktop_input_map.cpp : 03F06D3A0B7F37C37B22C5ACF3485F8045AEC22BFEC2DE35E95245669AD71E71
变异 desktop_input_map.cpp : FA45CBBA451784F5D114DA7C97245B6BECAD6DC77CDCA7D27E65D044893B5446
恢复 desktop_input_map.cpp : 03F06D3A0B7F37C37B22C5ACF3485F8045AEC22BFEC2DE35E95245669AD71E71
```

结论：**PASS**。

---

## 5. 追加复核 `afb2a69`（desktop input injection skeleton）

### 5.1 `TranslateInput`（[READ:src/server/desktop_input_map.cpp:30-100]）

| 要求 | 代码 | 结论 |
|---|---|---|
| wheel 不得再乘 120 | `wheel.wheel = ev.wheel_delta;`（:84），注释明确 "must not multiply it by 120 again" | PASS |
| `kMouseRel` 返回空 | `case kMouseRel: case kSync: return out;`（:95-97） | PASS |
| `kSync` 返回空 | 同上 | PASS |
| `!is_move && button==0` 返回空 | kMouse 分支只在 `is_move` 时 push move、只在 `button != 0` 时 push button（:59-74），两者皆无则返回空 vector | PASS |
| 附：绝对坐标归一化 | `NormalizeAxis` 把 `extent-1` 映射到 65535，`extent<=1` 直通（:20-26） | PASS |
| 附：键盘 scancode 不偏移 0x100 | 直接拷贝 `ev.scancode`；extended 作为独立标志（:34-44） | PASS |

测试覆盖：14 个映射用例，包括 `desktop_input_mouse_relative_not_injected`、`desktop_input_sync_not_injected`、`desktop_input_mouse_without_move_or_button_is_empty`、正/负/水平滚轮按 120 单位（[READ:tests/test_desktop_input.cpp:137-219]）。

### 5.2 Win32 sink（[READ:src/server/desktop_input_win32.cpp]）

| 要求 | 代码 | 结论 |
|---|---|---|
| 队列 256 上限 | `constexpr size_t kMaxQueue = 256;`（:54）；`if (queue_.size() >= kMaxQueue)`（:154） | PASS |
| 满队先丢移动 | 满队时 `find_if` 找最旧 `kMouseMove` 并 `erase`（:155-163）；若无可丢移动且入队项本身是移动则丢弃（:164-169） | PASS |
| 键/按钮不丢 | 无可丢移动且入队项是键/按钮时仍 `push_back`（:171），队列临时增长而不丢 up 事件 | PASS（见发现 F-4） |
| `ReleaseSession` 补 up | `AppendReleasesLocked` 遍历 `pressed_keys`/`pressed_buttons` 生成 release 入队（:174-193），然后 erase 会话状态（:114-123） | PASS |
| SendInput 失败计数 + 限流 | `injected_failed_` 自增，`LogFailure` 用 5 秒窗口限流（:56, :374-407） | PASS（计数无公开访问器，见 F-5） |
| `dwExtraInfo` 自有 tag | `kInjectTag = 0x52545343`（"RTSC"），键盘/移动/按钮/滚轮四类均写入（:59, :288, :316, :356, :367） | PASS |
| 单 worker 串行化 | 构造启动 `worker_`，`Inject` 只加锁入队并 `notify_one`（:84-111, :196-222） | PASS |
| 移动合并/限速 | `pending_moves_` 按会话保留最新位置，`kMoveInterval=4ms`（250Hz），键/按钮前先 flush 同会话移动（:55, :239-281） | PASS |

### 5.3 安全门（实测）

- `--allow-input` 默认关：`bool allow_input = false;`（[READ:tools/rtsc_server/main.cpp:120]）；`cfg.enable_desktop_input = opt.allow_input;`（:362）。
- 默认启动行实测：

```
[BASH] rtsc_server_host --test-pattern --seconds 1 --port 0
port=0 enhanced=true credssp=6 account=rtsc@NTDEV desktop=1280x1024 source=test-pattern clipboard=enabled audio=off input=off
EXIT=0
```

- 危险组合必须 EXIT=2（实测）：

```
[BASH] rtsc_server_host --allow-input --no-enhanced
refusing to start: --allow-input requires verified credentials.
  conflicting option --no-enhanced: no password check at all.
EXIT1=2
[BASH] rtsc_server_host --allow-input --allow-any-credentials
refusing to start: --allow-input requires verified credentials.
  conflicting option --allow-any-credentials: every account is accepted.
EXIT2=2
```

- `--allow-input-unverified` 逃生门有显著警告（实测星号横幅 + 多行警告）：

```
[BASH] rtsc_server_host --allow-input --no-enhanced --allow-input-unverified --test-pattern --seconds 1 --port 0
port=0 enhanced=false ... input=on
WARNING: desktop input injection is ENABLED (--allow-input): ...
**********************************************************************
WARNING: --allow-input-unverified is in effect.
This server combines desktop input injection with a weakened credential policy
...
**********************************************************************
EXIT=0
```

代码位置：[READ:tools/rtsc_server/main.cpp:330-350]（拒绝逻辑）、`:455-480`（警告横幅）、`:362`（配置映射）。

### 5.4 生命周期

- `SetInputSink` 只保存裸指针，不释放：`input_sink_ = sink;`，成员为 `DesktopInputSink*`（[READ:include/rtsc/server/server.h:298,367]）。所有权文档与 `SetClipboard` 相同（借用、须比 server 活得久）。
- 注入点双重门控：`config_.enable_desktop_input && input_sink_ != nullptr`（慢路径 :1719-1720；fast-path :1847-1848）。
- teardown 在 live 计数释放前调 `ReleaseSession`：会话体先 `session->ReleaseInput();` 再 `release();`（[READ:src/server/server.cpp:2166-2174]）；`ServeOne` 在 `Stop/ScrubCredentials` 后调用 `ReleaseInput()`（:2235-2238）；`ReleaseInput` 有 `input_released_` 幂等守卫（:695-700）。
- 声明顺序保证 sink 晚于 server 析构：`input_sink` 在 `RdpServer server(cfg)` 之前声明（[READ:tools/rtsc_server/main.cpp:425-428,510]），C++ 逆序析构，server 先停并 join 会话线程，sink 后销毁。

结论：**PASS**。

### 5.5 变异（已在 §4.2 完成）

`kWheel` 乘 120 → 4 个滚轮映射用例转红；恢复后转绿并有 SHA256 双证。**PASS**。

### 5.6 C0

`afb2a69` 的 `rtsc_server_host` 目标在隔离目录构建（相关目标均带 `/W4 /WX`）：

```
[BASH] cmake --build C:\Users\liulilte\rtsc-mutbuild-b7 --config Release --target rtsc_server_host
rtsc_server_desktop_input_map.vcxproj -> ...lib
rtsc_server_desktop_input.vcxproj -> ...lib
rtsc_server_host.vcxproj -> ...exe
BUILD_EXIT=0
```

无 error / warning 输出，满足 C0。`rtsc_desktop_input_tests` 同样 0 error / 0 warning。

---

## 6. 结论汇总

### 6.1 PASS/FAIL

| 编号 | 项目 | 结论 |
|---|---|---|
| 1.1 | inputFlags 规范核对（默认 0x013D） | **PASS** |
| 1.2 | TS_INPUT_EVENT messageType/长度 | **PASS** |
| 1.3 | TS_RELPOINTER_EVENT X1/X2 合法性 | **PASS** |
| 2 | 慢/fast-path 语义一致性 | **PASS**（指针语义零分叉；MOUSEREL 见 F-1） |
| 3 | 健壮性（计数不符/下溢/越界/未知类型/0xFFFF） | **PASS** |
| 4 | 独立变异（慢路径 0x8001→0x8003） | **PASS**（红→绿，哈希双证） |
| 5 | 已知基线对照 | **PASS**（client 25/139/0；server 40/433/0 实测一致） |
| A1 | afb2a69 TranslateInput | **PASS** |
| A2 | afb2a69 Win32 sink | **PASS**（F-4/F-5 为残余风险，非阻断） |
| A3 | afb2a69 安全门 | **PASS**（EXIT=2 实测；默认 input=off 实测） |
| A4 | afb2a69 生命周期 | **PASS** |
| A5 | afb2a69 变异（wheel×120） | **PASS** |

**本报告无 FAIL。** 未发现规范值错误、越界/崩溃路径、注入绕过或默认开启注入。

### 6.2 发现清单（均非阻断，建议后续处理）

- **F-1（文档/提交信息，低）**：`10b3b20` 提交说明把 `MOUSEREL 0x8004` 列为慢路径已解码，但 `ParseSlowPathInput` 实际只计数后跳过（[READ:src/server/server.cpp:1677-1686]）。服务器也未广告 0x0080 MOUSE_RELATIVE，合规客户端不会发相对鼠标，故功能可接受；但应修正提交说明/注释，或明确"慢路径相对鼠标不在本里程碑"。
- **F-2（分派歧义，低）**：只有非合规 fast-path 事件（eventFlags 含未定义 0x10、keyCode=0）才可能被 `ShareDataHeader::parse` 误判为慢路径并吞掉（见 §3.3）。可选加固：`HandleSlowPathPdu` 额外校验 `total_length` 与载荷长度一致，或要求 `pdu_source/stream_id` 合理。
- **F-3（规范外位，极低）**：慢/快路径的 `sync_flags` 都保留未定义的 0x10 位（慢 `body[2] & 0x1F`，快 `flags & 0x1F`）。由于注入层直接丢弃 `kSync`，当前无影响；若未来消费该字段，应按规范只保留 0x0F。
- **F-4（健壮性，低-中）**：`Win32DesktopInputSink` 为保证"键/按钮不丢"，在队列满且无移动可驱逐时允许队列**无限增长**（[READ:src/server/desktop_input_win32.cpp:147-172]）。恶意/异常客户端持续发键事件可造成内存增长。建议加硬上限（例如 4×kMaxQueue 后拒绝该会话或断开），同时保留"up 事件不丢"语义。
- **F-5（可观测性，低）**：`injected_ok_/injected_failed_/dropped_queue_full_/dropped_unsupported_` 都是私有原子计数，无访问器；SendInput 失败只有 5 秒限流日志可见。建议暴露只读统计或周期性汇总。
- **F-6（资源增长，极低）**：`last_move_sent_` 在 `ReleaseSession` 中未擦除，长跑多会话时每会话残留一个 map 项（[READ:src/server/desktop_input_win32.cpp:224-237,114-123]）。建议在 `ReleaseSession` 一并 `last_move_sent_.erase(session_id)`（注意需在锁内/worker 协调）。
- **F-7（文档，低）**：`SetInputSink` 未说明"应在 Start() 前调用"；裸指针由会话线程直接读取，运行中替换存在数据竞争风险。与 `SetClipboard` 同样属调用约定，建议在头文件注明。

### 6.3 未验证项（W5）

- 未在真实 Windows 桌面（非测试机）上验证 SendInput 的 UIPI/锁屏行为；仅做代码路径与编译验证。
- 未复跑全量 `ctest`（任务给定 62/62 与 63/63 基线；本人只跑了受影响的 server/client/desktop_input 三个套件）。
- 未读取另一审计的 `input-wheel-review-A.md`（按任务要求保持独立性），因此本报告不复核双方结论差异。