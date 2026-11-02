# 输入注入接缝 / 安全默认值 / 协议完整性

状态：2026-11-02（第 833 轮，批 17 全文对账重写）。原作者：审计乙（第 793 轮）。
范围：设计裁决 + 当前实现事实。代码目录的现状以本文件 §0 的状态表为准。

**本版写法约定（批 17 起强制）**

1. 仓库位置一律用 **符号名**（`文件:符号`），**不再引用行号**。行号会随每次改动漂移；
   `input-batch12-review-I.md` 的 48 条失效引用全部由这一条消除。
2. 无法用仓库证据确认的论断标 **【UNVERIFIED】**，并写清"怎么才能验证"。禁止以"应该/大概率"代替证据。
3. 官方文档引用保留可核验 URL；本文件**未重新抓取**官方页面，引文沿用原文与
   `docs/spec/share-data.md` 的本地记录，标 **【未复验】** 的地方以本地记录为准。
4. 文档与代码冲突时以代码 + 测试为准，并回写本文件（批 10/11 的定案方式）。

---

## 0. 结论摘要（当前实现）

1. **注入层已实现并默认关闭**。`DesktopInputSink`（`include/rtsc/server/desktop_input.h`）是借用指针接口，
   默认 `ServerConfig::enable_desktop_input = false`，且宿主只有 `--allow-input` 才创建 sink；
   未启用时 `SetInputCallback` 的观测语义完全不变（`tools/rtsc_server/main.cpp` 安装的是只写日志的回调）。
2. **规范是硬要求，不是增强项**：`[MS-RDPBCGR]` 2.2.8.1.2 "Processing Fast-Path Input Event PDU" 原文
   > "Once this PDU has been processed, the server **MUST inject the input event into the user's session**."

   （https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/178aef78-2606-4e44-a94a-6ee6f6dc5cc6，
   本轮未重新抓取 **【未复验】**）。默认 off 是"安全默认值"裁决（§2.1），不是不实现。
3. **协议前置缺陷均已闭合或按裁决落地**（逐条见 §3）：
   - `INPUT_FLAG_FASTPATH_INPUT2 (0x0020)` 已广告（默认 `input_flags = 0x013D`）；
   - 慢路径输入 PDU（`pduType2 = 0x1C`）已解码，快/慢两条通道产出同一个 `InputEvent`；
   - 未知 `eventCode` / 未知慢路径 `messageType` 只计数不断连（有意偏离 SHOULD），畸形 PDU 另有计数。
4. **P-6（PAUSE/0xE1）已完整闭合**：`PauseSequenceFilter` 在服务端租约门**之前**把整条 PAUSE 序列丢弃，
   平台层 `TranslateInput` 另有一道 `extended1` 兜底。E1-CTRL 与 NUMLOCK(0x45) 两半都不再注入，
   不会再切换本机 NumLock。真机物理状态仍 **【UNVERIFIED】**（§4.3）。
5. **仍 OPEN 的一条是几何来源**（§1.7 第 2 条）：`InjectGeometry` 只有 `width/height`，
   服务端填协商 framebuffer，后端恒发 `MOUSEEVENTF_VIRTUALDESK` ⇒ 默认 `--monitor -1` 正确，
   `--monitor N`（子矩形）会整体错位。

### 0.1 P-1…P-12 状态总表（当前实现）

| ID | 主题 | 状态 |
|---|---|---|
| P-1 | 横向滚轮 `kPtrHwheel` | **已修**（解码 + `horizontal` + `MOUSEEVENTF_HWHEEL`） |
| P-2 | 滚轮符号/单位 | **已修**（9 位二补码；单位 = WHEEL_DELTA，注入不再乘 120） |
| P-3 | `kMouseRel` 被吞 | **解码已修**；注入按裁决不做（相对位移受加速污染） |
| P-4 | QoE / 相对移动产生伪 `kKey` | **已修**（`continue`，不落回调） |
| P-5 | move / release 不可区分 | **已修**（`is_move` + 按钮身份在 down 之外解码） |
| P-6 | E1 / PAUSE 不忠实 | **已修**（整序列过滤 + 平台层兜底）；真机 UNVERIFIED |
| P-7 | `kSync` 盲注入会反相 | **部分**：不注入 + 序列终止已落地；"期望状态决策函数"未实现 |
| P-8 | `kUnicode` | **通过**（两条硬约束已在后端实现） |
| P-9 | 未广告 `FASTPATH_INPUT2` | **已修**（默认含 0x0020，有 Demand Active 用例） |
| P-10 | 慢路径输入被静默丢弃 | **已修**（0x1C 解码，含 SYNC/SCANCODE/UNICODE/POINTER/POINTERX/MOUSEREL） |
| P-11 | 未知事件 / 长度校验 | **部分**：未知 code 与畸形 PDU 已计数、不断连；快路径截断仍直接 return 且不计数 |
| P-12 | 汇总 | 见上 |

---

## 1. 接缝设计

### 1.1 现状（硬证据，符号锚点）

| 事实 | 证据 |
|---|---|
| 默认宿主只观测不注入 | `tools/rtsc_server/main.cpp:main`：`if (opt.allow_input) input_sink = MakeWin32DesktopInputSink();`，否则 `SetInputSink` 不调用 |
| 观测回调保留、签名不变 | `include/rtsc/server/server.h:InputCallback` = `std::function<void(const InputEvent&)>` |
| 回调在会话线程执行，且不得长时间阻塞 | `server.h:InputEvent` 前置注释（"Callbacks run on the session thread … must not block"） |
| 每个会话有非零、互异的输入会话 id | `src/server/server.cpp:Impl::next_input_session_id` 原子递增，两条会话构造路径均 `fetch_add(1) + 1`；`0` 保留为未分配 |
| 解码后统一走"注入 → 回调" | `server.cpp:RdpSession::InjectIfLeasable` 之后调用 `input_callback_`（两处解析路径都如此） |
| 库不决定几何来源 | `server.h:ServerConfig::desktop_width/height` 是协商值；`desktop_gdi.h:MakeGdiDesktopSource` 把捕获矩形**缩放**到协商几何 |
| 借用指针范式 | `RdpServer::SetDesktopSource` / `SetClipboard` / `SetInputSink` 三者同一契约（调用方持有，必须活过 `Stop()`） |

### 1.2 三个候选方案与裁决（不变）

| 方案 | 优点 | 否决/采纳理由 |
|---|---|---|
| A. 沿用 `InputCallback` 做注入 | 零库改动 | **否决**：①回调拿不到会话 id，多会话无法归属/仲裁；②返回 `void`，无法表达拒绝；③生命周期靠调用方自觉，`Stop()` 后会话线程仍可能调用 |
| B. 派生 `RdpSession` / 虚函数 | 语义最强 | **否决**：`RdpSession` 是 `server.cpp` 匿名命名空间内的实现细节，提升为公有基类等于公开内部状态机 |
| C. 新增借用指针 `DesktopInputSink`（**采纳**） | 加法式、不动既有回调签名、带 session id、生命周期与 clipboard 一致 | 采纳；`SetInputCallback` 保留为观测/日志/测试用 |

### 1.3 接口（**实际实现**，不再是设计草案）

```cpp
// include/rtsc/server/desktop_input.h
namespace rtsc::server {

// 虚拟屏幕物理像素坐标里的矩形；原点可为负（主屏左/上方的显示器）。
struct InjectRect {
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;
};

// 注入坐标所在的几何。`width`/`height` 是协商后的 framebuffer（客户端坐标系）；
// `capture` 是 framebuffer 取自物理虚拟屏幕的哪块；`desktop` 是
// MOUSEEVENTF_VIRTUALDESK 归一化所用的虚拟桌面外接框。
// `mapped` 为 false 表示 capture/desktop 未知（合成源或尚未协商）；
// `pixels_are_physical` 为 false 表示进程 DPI 上下文未证实为物理像素。
// 两者任一为 false 都让绝对移动 fail-closed，但按钮/滚轮/键盘不受影响。
// （§1.7 第 2 条描述的"没有 origin"是历史草案，已由本结构取代。）
struct InjectGeometry {
    uint16_t width = 0;
    uint16_t height = 0;
    InjectRect capture;
    InjectRect desktop;
    bool mapped = false;
    bool pixels_are_physical = false;
};

struct InputStats {
    size_t injected = 0;            // 成功的平台动作
    size_t dropped_queue_full = 0;  // 队列上限拒绝 / 驱逐 / 会话结束 purge
    size_t dropped_rate_limited = 0;
    size_t send_failures = 0;       // SendInput 未成功发出 1 个事件
    size_t release_failures = 0;    // teardown 合成 up 无法入队
    size_t worker_failures = 0;     // worker 线程吞掉的异常动作
    size_t dropped_unmapped = 0;    // 几何不可信的纯移动（fail-closed）
};

class DesktopInputSink {
 public:
    virtual ~DesktopInputSink() = default;
    virtual void SetGeometry(uint32_t session_id, const InjectGeometry& g) = 0;
    // 返回值是 void：丢弃只经 InputStats 可见（§1.6）。
    virtual void Inject(uint32_t session_id, const InputEvent& ev) = 0;
    virtual void ReleaseSession(uint32_t session_id) = 0;
    // 未持租约的会话也必须报：否则几何不可信时 dropped_unmapped 恒为 0。
    virtual void NoteUnmappableMove(uint32_t session_id) = 0;
    virtual InputStats Stats() const = 0;
};

// 宿主 `input stats` 行的唯一构造点，抽成纯函数以便直接断言每个字段。
std::string FormatInputStats(const char* reason, const InputStats& stats);
// 宿主只在计数变化时打印；逐字段比较，漏掉一个字段该计数就永远不打印。
bool InputStatsChanged(const InputStats& prev, const InputStats& cur);

std::unique_ptr<DesktopInputSink> MakeWin32DesktopInputSink();

}  // namespace rtsc::server
```

`RdpServer` 侧：

```cpp
void SetInputSink(DesktopInputSink* sink);  // nullptr 关闭注入；指针必须活过 Stop()
```

**调用顺序**：`RdpSession::InjectIfLeasable` 先做 PAUSE 过滤，再取租约，再 `input_sink_->Inject(...)`；
随后无条件调用 `input_callback_`（观测不被遮蔽）。

### 1.4 注入器实现位置与生命周期

| 文件 | 角色 |
|---|---|
| `include/rtsc/server/desktop_input.h` | 接口 + `InjectGeometry` + `InputStats` + 工厂声明 |
| `include/rtsc/server/desktop_input_map.h` | 平台中立：`PlatformInput`、`TranslateInput`、`PauseSequenceFilter`、`PressedInputs`/`TrackInput`/`IsHeldRelease`、`DecideEnqueue`/`AdmitInput`/`AdmitAndTrack`、`InputRateLimiter` |
| `src/server/desktop_input_map.cpp` | 上述纯函数的实现（含 `NormalizeAxis`） |
| `src/server/desktop_input_win32.cpp` | Win32 后端：单 worker 线程、队列、限流、`BuildNative`+`SendInput`、`ReleaseSession`/`Shutdown` |
| `src/server/desktop_input_null.cpp` | 非 Windows 的计数 no-op（与 `NullClipboard` 同角色），工厂同名 |

- **生命周期**：宿主必须在 `RdpServer server(cfg);` **之前**声明 sink（`main.cpp` 即如此）。
  sink 必须活过 `server.Stop()`；`Stop()` join 会话线程后 sink 才可析构。
- **关闭顺序**：`RdpServer::Stop()` → sink 析构 → `Win32DesktopInputSink::Shutdown()`（补发 synthetic up、
  `notify_all` + `join` worker）。`Shutdown()` 是 `noexcept`：它从析构函数运行，漏 join 会让
  `~std::thread` 调 `std::terminate`。

### 1.5 线程模型：会话线程**禁止**直接 `SendInput`

裁决不变：会话线程只做"翻译 + 入队"，`SendInput` 只在 sink 自有的一条 worker 线程里执行。

理由（不变）：`server.h` 明确要求回调不长时间阻塞；会话的 `ActiveLoop` 是单线程串行循环，
阻塞会同时停摆 `rdpsnd_->Poll`、`rdpdr_->Poll` 与帧刷新。`SendInput` 的返回值语义
（https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput **【未复验】**）
也要求调用点单点可计量；多线程并发调用会让跨会话交错不可复现。

队列策略（`desktop_input_win32.cpp` 的 worker + `desktop_input_map.h` 的纯策略）：

| 事件类 | 策略 |
|---|---|
| `kKey` / `kUnicode` / 按钮按下抬起 | FIFO，不与移动合并 |
| `kMouse` 纯移动（无按钮位） | **合并**：同会话队尾移动只更新坐标；定时路径每 4 ms（250 Hz）发一次；同会话按键/按钮/滚轮会立即 flush 待发移动，瞬时输出可高于 250 Hz |
| `kWheel` | FIFO，不与移动合并（离散动作） |
| 软上限 `kMaxQueue = 256` | 先驱逐**最旧的一条纯移动**（计 `dropped_queue_full`）；无可驱逐的移动时，移动本身被丢弃 |
| 硬上限 `kHardQueueLimit = 4 * kMaxQueue = 1024` | 只豁免 **held release**（该会话确实按住的 key/按钮的 up）；其余一律 `kDrop` 计数 |
| 队列峰值（**峰值**口径，不是瞬时不变式） | ① 对端可入队事件：`peak ≤ kHardQueueLimit + \|pressed\|@饱和 = 1024 + 515 = 1539`。`pressed` 的结构上界来自线上取值域：RDP `keyCode` 是 1 字节，非零值 255 个 × 0xE0 两位 = 510 键（`KeyId.scancode` 声明为 `uint16_t`，但线上只有 8 位能到达），加 5 个按钮号 = 515。② 合成 up 由 `AppendReleasesLocked` 按 `pressed` 直推、不过 `DecideEnqueue`，且 purge 明确保留 `synthetic` 项，故每会话增量 `≤ 515`，全局 `≤ kHardQueueLimit + 515·K`（K = 同时持租且 pressed 非空的会话数）。默认 `max_input_sessions = 1` ⇒ **1539**。不得写成 `1539 + 会话数 × 515`（重复计基线），也不得读作瞬时不变式：释放后队列可仍为 1534 而 `pressed` 已为 0 |
| 饱和引理（仅对端可入队事件） | `size > soft_limit ⇒ 队列内无纯移动`：`size ≥ soft` 时任何事件先走 `kEvictMove`（只替换不增长），移动被驱逐光后新移动走 `kDrop`，故硬限 `kDrop` 不会被 evict 绕过。合成 up 不参与驱逐，本引理不覆盖它们 |
| `kSync` | 不注入（无 Win32 "设置 toggle 状态"事件）；且它**终止** PAUSE 窗口（§3 P-7） |
| `kMouseRel` | **已上送**（`Kind::kMouseRel`，带符号 `rel_x/rel_y`）；v1 不注入（相对位移受系统加速污染） |
| `kMouseRel` / `kSync` 的 `IsInjectable` | 均为 `false` ⇒ 未持租约时**不会**取租约、也到不了 sink；已持租约的会话仍把它们转给 sink，由 sink 计 `dropped_unsupported` 并丢弃 |

`unicode` 释放不豁免：`KEYEVENTF_UNICODE`（`wVk = 0`）不按下物理键，不进 `pressed`。
**未持有的 keyup 也不豁免**队列硬限与限流——否则单条大 PDU 的数千个 keyup 就能让队列无限增长。

### 1.6 失败传播：计数 + 限流日志，**不断连**

裁决不变：注入失败**不**断开 RDP 连接，只计数并限流告警（每 5 s 至多一行）。理由：主因是服务器本机状态
（UIPI、锁屏、桌面切换），不是对端违约；断了等于把本机问题变成对端连接问题，还能被普通用户开高完整性
窗口当成 DoS。协议层惩罚只用于协议违约（未知事件类型 SHOULD 断连，与本议题是两件事）。

对外可观测面 = `InputStats` **七个**计数器（`include/rtsc/server/desktop_input.h`）：

| 字段 | 含义 |
|---|---|
| `injected` | 成功的平台动作（Win32：`SendInput` 成功发出一个 `INPUT`；null sink：接受的 `Inject` 次数） |
| `dropped_queue_full` | 硬/软上限拒绝、被驱逐的旧移动、**会话结束 purge 的排队项**（`ForgetReleasedSessionsLocked`）——不只是硬限丢弃 |
| `dropped_rate_limited` | 限流拒绝（§2.3） |
| `send_failures` | `SendInput` 返回值 != 1 |
| `release_failures` | teardown 的合成 up 无法入队（`AppendReleasesLocked` 抛异常），键/按钮可能仍按下 |
| `worker_failures` | worker 线程吞掉的异常动作（非 0 表示有注入被静默丢弃） |
| `dropped_unmapped` | 几何不可信而被 fail-closed 丢弃的纯移动；含**未持租约**的会话（`NoteUnmappableMove`） |

`sink` 内部另有 `dropped_unsupported`（已释放会话的迟到事件、翻译为空的事件），**未接出**结构体。
`SendInput` 失败日志行为：任意一次失败后，若距上一条失败日志已满 5 s 就打印一行（`kFailureLogInterval`），
不带失败率判定，也没有"恢复"行。限流丢弃**不打日志**（只经 `dropped_rate_limited` 可见）。

宿主 `main.cpp` 每 5 s 采样一次 `Stats()`，仅在任一计数变化时（`InputStatsChanged`）打印
`input stats (periodic|final): input_injected=… input_dropped_queue=… input_rate_limited=… input_send_failures=… input_release_failures=… input_worker_failures=… input_dropped_unmapped=…`；
行文本由纯函数 `FormatInputStats` 构造。`(final)` **只**在正常退出路径（`--once`、`--seconds` 到期）打印。
无界模式没有 `SetConsoleCtrlHandler`，Ctrl+C 直接终止进程，**不打印 final**。

**回压**：`Inject` 是 `void`（与 §1.3 一致，历史文档的 `bool` 说法已废弃）；丢弃只经计数可见，会话不重传
（输入是实时语义，重传旧键位比丢掉更糟）。全仓唯一注入出口是 `RdpSession::InjectIfLeasable` 里的
`input_sink_->Inject(...)`，过滤器与租约都在这条路径上，无法绕过。

### 1.7 两条"接口余量"

**第 1 条（会话归属）——已闭合。** `Inject(session_id, ev)`；`next_input_session_id` 原子递增，
两条会话构造路径各自 `fetch_add(1) + 1`，`0` 保留为未分配。`RdpSession::ReleaseInput` 先
`pause_filter_.Reset()`，若该会话**持过**租约则先 `input_sink_->ReleaseSession(input_session_id_)`
（此时槽位仍占着），然后才 `holders.erase`；从未持租的会话不调用 sink（它从未注入过）。
用例 `server_input_lease_one_session_then_handoff` 断言两个 id 非零且互异。
**残留可观测性缺口（低）**：宿主的 `"session active: … event forwarded"` 日志行仍不带 `session_id`。

**第 2 条（几何来源）——仍 OPEN。** 实测错位点（三处，全部可在代码上核验）：

1. `InjectGeometry` **没有 `origin_x/origin_y`**（`desktop_input.h` 只有 `width/height`），
   而 `desktop_gdi.h:MakeGdiDesktopSource` 支持把捕获矩形（`x,y,width,height`）缩放后输出；
   `--monitor N` 抓的是子矩形，原点与尺寸都没进注入层。
2. 服务端把**协商并钳制后的 framebuffer** 填进几何：`RdpSession` 在 Demand Active 处
   `inject_geometry_ = InjectGeometry{desktop_width_, desktop_height_}`。
3. 后端**恒**发 `MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`
   （`desktop_input_win32.cpp:BuildNative`），即坐标恒映射到整个虚拟桌面。归一化只在协商尺寸上做，
   所以只有"捕获源 = 整虚拟桌面"时才自洽；`--monitor N` 时整幅指针偏移都会被放大。

后果与现状：默认 `--monitor -1`（整虚拟桌面）可工作；`--monitor N` 下坐标整体错位，属已知缺陷。
测试把 64×48 的协商几何固化为期望（`tests/test_server.cpp` 租约用例），只是固定了"几何 = 协商值"，
**不**证明子矩形正确。修法（未实施，二选一）：

- ① 给 `InjectGeometry` 加 `origin_x/origin_y/virtual_desktop`，由 `DesktopSource` 暴露捕获矩形（GDI 源已有 `rect_`）；
- ② 短期不扩展，则在 `--monitor N` 时拒绝/告警注入，并把本文件改成"仅支持整虚拟桌面"。

真机/多屏表现 **【UNVERIFIED】**（§4.3 第 6 条）。换算公式与边界：越界值（RDP 侧 `u16` 可到 65535）
必须**钳制**而不是回绕（`NormalizeAxis` 对 `value >= extent-1` 返回 65535）；
`width/height <= 1` 视为几何不可用，**绝对移动不产出**（`TranslateInput` 的 `kMouse` 分支要求
`g.width > 1 && g.height > 1`），但按钮事件照旧产出（否则点击丢失、后续释放会卡键）。

归一化的目标区间与 `VIRTUALDESK` 语义依据（https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-mouseinput **【未复验】**）：
> "If MOUSEEVENTF_ABSOLUTE value is specified, dx and dy contain normalized absolute coordinates between
> 0 and 65,535. …"
> "If MOUSEEVENTF_VIRTUALDESK is specified, the coordinates map to the entire virtual desktop."

注意**第二条引文正是 §1.7#2 缺口的根源**：后端恒开 `VIRTUALDESK`，归一化却按协商 framebuffer 做，
于是"归一化分母"与"映射目标"不是同一个矩形。

### 1.8 已知测试缺口：Win32 接线（**部分闭合**）

**结论先写**：`src/server/desktop_input_win32.cpp` 现在**在 `rtsc_desktop_input_tests` 的编译/链接闭包内**，
所以对该文件的变异**可以**让 ctest 转红（批 13 的 M1 / M2b / M5 均已在 ctest 上实测转红）。不再有
"该文件不在任何测试 target 内、任何变异都无法转红"的结论。

`src/server/desktop_input_win32.cpp` 现在**同时**存在于两处构建：

- 生产：`rtsc_server_desktop_input`（编**不带** `RTSC_DESKTOP_INPUT_TESTING` 的同一文件，
  且只被 `rtsc_server_host` 链接）。该库不受测试宏影响，工厂正常提供。
- 测试：`CMakeLists.txt` 的 `WIN32` 分支把同一文件编进 `rtsc_desktop_input_tests` 并定义
  `RTSC_DESKTOP_INPUT_TESTING`，同时链 `user32`。该宏下：

  - 生产工厂 `MakeWin32DesktopInputSink` **编译掉**，改由 null sink 提供（避免测试触碰真实桌面）；
  - 暴露 `MakeWin32DesktopInputSinkForTest()` 与 `tests/desktop_input_win32_test_hooks.h` 的只读视图 /
    注入钩子（`SetDesktopInputAppendFailureHook`、`DesktopInputTestSeedPressedKey`、
    `DesktopInputTestSessionCount/PendingForgetCount/WorkerFinished/WorkerJoinable/WorkerWaiting`、
    `DesktopInputTestShutdown`）。

**已由测试缝覆盖的点（用例 `desktop_input_release_session_clears_state_when_append_throws` /
`desktop_input_shutdown_joins_worker_when_append_throws` / `desktop_input_test_hooks_reject_foreign_sink`）**：

- `ReleaseSession` 的合成 up 追加抛异常时，`sessions_.erase` 仍无条件执行、`forget_sessions_` 请求仍被 worker 抽干、
  `cv_.notify_one()` 无条件执行，且 `release_failures` +1；
  - notify 一条是**确定性**钉住的：用例先用 `DesktopInputTestWorkerWaiting` 等到 worker 已 park
    （`worker_waiting_` 在 `cv_.wait` 前置位、醒来清位），再触发 `ReleaseSession`，所以删掉
    `cv_.notify_one()` 必红（批 13 之前是竞态假绿：worker 首轮自己抽干 forget）。
- `Shutdown()`（`noexcept`）在追加抛异常时仍 `notify_all` + `join`，不遗留 joinable 线程；
- 测试缝的类型安全：`AsWin32` 用 `dynamic_cast`，把 null / 外来 sink 传给任何 hook 都返回 0/false 且不写对象
  （原 `static_cast` 是未定义行为，实测 AV / fail-fast / 挂死）。

**仍只靠读码审查的点**（`BuildNative` 与 `Dispatch`/`Emit` 未由用例驱动，`Emit` 会真的调 `SendInput`）：

- 移动合并与 oldest move 的取得时机（`EnqueueLocked`）；
- `kEvictMove`/`kDrop` 的计数与 `erase`；
- `AppendReleasesLocked` 的遍历与 `synthetic` 标记（用例只证明"被调用 + 可抛"，不校验键位与方向）；
- `ForgetReleasedSessionsLocked` 的 purge（桶 / 待发移动 / 非合成积压）；
- `Dispatch` 顺序：先 flush 同会话待发移动再发出队项；
- `BuildNative`：`0xE0` / `UNICODE` / 按钮号（含 XBUTTON1/2）/ 滚轮的 `mouseData` 单位。

要真正覆盖这些点，需要给 `Emit` 一个可注入的 `SendInput` 函数指针（或把 `BuildNative` 判定的
`INPUT` 字段抽成平台中立纯函数再断言）。本批不做。

---

## 2. 安全设计（默认值裁决）

### 2.1 默认 off，显式 `--allow-input`（已实现）

- 默认值：`ServerConfig::enable_desktop_input = false`；宿主 `cfg.enable_desktop_input = opt.allow_input`；
  只有 `--allow-input` 才 `MakeWin32DesktopInputSink()`，否则不调用 `SetInputSink`。
  `enable_desktop_input` 为 false 时即使装了 sink 也不注入（`AcquireInputLease` 直接返回 false）。
- 启动行含 `input=on|off` 与 `input_max_sessions=N`（与 `audio=` 并列）。
- 运行期：首次租约拒绝打印一次 `WARNING: input lease denied (input_lease_denied_count=N)`，
  之后按"计数变化且距上一条汇总 ≥1 s"打印 `WARNING: input lease denied summary: …`，**不按事件打印**。
- 现状对照：音频**默认 off**（`AudioSource::kOff`，注释写明隐私理由）；USB 重定向服务器侧未实现。
  注意**反例**：剪贴板**默认 on**（无条件 `CreatePlatformClipboard()`）。因此准确的表述是
  "本仓既有策略 = 会外泄本机数据/扩大攻击面的能力默认 off"，注入不泄数据但**授予控制权**，风险更高 ⇒ off。
- 为什么不是"默认 on 但可关"：RDP 输入是**单向权限跃迁**（从"看屏幕"到"操作整个交互会话"），
  且本机用户很难察觉（只会看到鼠标自己动）。默认值必须在安全的那一侧。

### 2.2 组合门禁：`--allow-input` + 弱化凭据 → **拒绝启动**（已实现）

| 组合 | 实际含义 | 证据 |
|---|---|---|
| `--allow-input --no-enhanced` | **完全不做密码校验** | `main.cpp` 门禁注释原文："--no-enhanced performs no password check at all"；`server.h:ServerConfig` 注释同结论（Standard Security 路径上 authenticator 只看到账号名） |
| `--allow-input --allow-any-credentials` | 口令是字面量默认值 `"password"`，账号名任意 | `main.cpp:Options::password = "password"`；`credential_lookup` 只比对 user/domain |
| 两者叠加 | 任何可达端口者 = 桌面完全控制 | 上两行 |

裁决：默认**拒绝启动**，退出码 2（与 `ParseOptions` 失败一致），文案点名冲突选项，并给出
`--allow-input-unverified` 逃生门。逃生门在启动日志里打印 **7 行** banner（上下各一行星号 + 5 行正文，
`main.cpp:main` 的 `unsafe_input && opt.allow_input_unverified` 分支），位置在启动行与凭证行**之后**，
不是日志首行。

论证（为什么不只警告）：本仓已有先例证明警告不足（`--allow-any-credentials` 只是一行 `log.line`，
`Start()` 也只 WARNING）；日志会被重定向/截断；失败模式是"静默提权"，事后审计成本极高。
这是默认值裁决，不是删功能：显式逃生门保留全部能力。

### 2.3 多会话共享桌面（限流、租约、可观测）

事实：所有会话捕获**同一个**桌面、注入落到**同一个**输入桌面 ⇒ 两会话同时发绝对移动会互相抢占，
同时打字会串字。

租约（`InputLease`，`server.h:ServerConfig::max_input_sessions` 默认 1）：

- 第一个**可注入**事件持有一个槽位；`max_input_sessions == 0` 显式表示不限；
- 槽位满时该事件被拒并计 `input_lease_denied_count()`，**没有等待队列**——被拒会话在下一个可注入事件重试，
  持有点断连走 `ReleaseInput` 释放槽位后即可接管；
- 不可注入事件（`kSync`、`kMouseRel`、零码、无 move/button 的 `kMouse`）在未持租约时**不会**取租约
  （用例 `server_non_injectable_input_does_not_hold_lease`）；
- PAUSE 序列在租约门**之前**被过滤，所以既不占租约也不进 sink（用例 `server_pause_sequence_is_not_injected`）。

限流（`InputRateLimiter`，在 `Inject()` 内、与队列共用 `mu_`；按 `steady_clock` 单调时间补令牌，
**入队前**判定，因此被限流的动作既不进队列也不进 held 记账）：

| 桶 | 稳态 | 容量 | 理由 |
|---|---|---|---|
| 会话 | 400 动作/s（`kSessionEventsPerSecond`） | 800（`kSessionBurst`）= 2 s 突发 | 交互式打字 < 20 动作/s；快速拖拽 + 移动合并后 < 300 动作/s |
| 全局 | 1000 动作/s（`kGlobalEventsPerSecond`） | 2000（`kGlobalBurst`） | 与"2 s 突发"口径一致（1000 × 2 s）。**为什么是 2 倍稳态而不是别的值**：① 单会话打满自己的 800 突发后全局仍余 1200，第二个会话的合法突发不会被第一个会话的瞬时峰值挤掉；② 全局桶是"令牌数"（动作），与队列长度（事件数，1024/1539）不是同一口径，把 2000 对齐队列上界没有意义；③ 2 s 是足以吸收一次拖拽/连击峰值、又不会让长时洪泛通过的最短窗口（4 s 会让 1000/s 的洪泛能持续 4 s 才被削） |

- 口径是**平台动作**而不是 RDP 事件：一个 `kMouse` 移动+按钮事件翻译成两个动作、扣两个令牌，
  因此这类事件的稳态上限是 200/s。
- **`held_release` 语义**：只有"该会话确实按住的 key/按钮的 up"（`IsHeldRelease`，匹配
  `scancode + 0xE0 标志` 或按钮号）**不受限流、不消耗令牌、也不受队列硬限**。理由：丢这种释放比丢按下危险
  （本机卡键），且数量被 `pressed` 集合限界（≤ 510 键 + 5 按钮）。
  **未持有的 up**（重复 up、被限流/硬限丢弃的按下的 up、unicode up）与按下同权：受限流、受队列硬限。
- 顺序是"先算 held → 再问限流 → 再判队列 → 只在接受时记账"（`AdmitAndTrack`）。顺序是关键：
  被限流拒绝的按下永不进 `pressed`，其后续 up 就不会被当成 held 而获得豁免。
- 全局桶拒绝时**不扣**会话桶令牌（`Allow` 先判后扣，两个桶都不动）；否则一个忙碌会话会静默抽干其他会话的配额。
- 超限：丢弃该动作 + `dropped_rate_limited++`；不排队、不断连、不逐事件打日志。
- 清理用合成 up（`ReleaseSession`/`Shutdown`）绕过 `Inject()`，因此既不受队列策略也不受限流；
  若它们无法入队，`release_failures++`（本机可能卡键，这是唯一可观测点）。
- **锁**：两个锁——队列互斥量 `mu_`（同时保护限流桶、`forget_sessions_`、计数写入）与
  日志互斥量 `log_mu_`（只保护"是否该打印失败行"）。**不**引入"每会话一把 SendInput 锁"：
  那会把跨会话交错变成随机顺序，比单队列合并更差。
- **触发释放的只有两个事件**：会话结束（`RdpSession::ReleaseInput`）与进程/服务器关闭
  （sink 析构的 `Shutdown()`）。旧文档列的"租约被撤销"不存在——槽位只在会话结束时释放，
  没有独立的撤租事件。

### 2.4 输入回显 / 隐私

1. 指针会真的移动，键会落到**当前前台窗口**（`SendInput` 注入系统输入流，不是某个进程）。
2. 本机用户能看到光标自己动、窗口自己切换；**没有任何 API 能让注入的输入对本机用户不可见**。
   唯一可区分点是 `dwExtraInfo`：
   > "dwExtraInfo … An additional value associated with the keystroke. Use the GetMessageExtraInfo function
   > to obtain this information."（https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-keybdinput **【未复验】**）

   **已实现**：本仓用自有常量 `kInjectTag = 0x52545343`（ASCII "RTSC"）打在键盘/鼠标/滚轮事件上，
   不复用 mstsc 的 `0x4321DCBA`（`docs/spec/input-evidence.md` 记录该常量，原文标注未验证）。便于本地排障与
   "注入 vs 真人"取证区分。
3. 反过来，远程端看到的桌面就是本机屏幕（GDI 捕获），本机的一切可见内容对远程端也可见——
   这是已存在的只读风险，注入把它升级为双向。
4. 因此 `--allow-input` 的语义必须描述为"把本机交互桌面交给远端操作"。
   **现状**：`main.cpp` 顶部的使用说明注释已完整写出该危险；但 `usage()`（`--help` 打印的东西）
   **只列旗标名**，不显示危险说明。这属已知文档/UX 缺口（`input-batch12-review-I.md` C6），未修。

### 2.5 UIPI / 完整性级别：**静默失败**如何暴露

规范行为（`SendInput` 文档同页，**【未复验】**）：
> "This function is subject to UIPI. Applications are permitted to inject input only into applications that
> are at an equal or lesser integrity level."
> "This function fails when it is blocked by UIPI. Note that **neither GetLastError nor the return value will
> indicate the failure was caused by UIPI blocking**."

暴露手段与**实现现状**：

| # | 手段 | 状态 |
|---|---|---|
| 1 | `SendInput` 返回值 != 1 → `send_failures++`，记 `GetLastError()` 进限流日志，**不重试** | **已实现** |
| 2 | 启动打印自身完整性级别与进程会话 ID（`GetTokenInformation(TokenIntegrityLevel)` / `ProcessIdToSessionId`） | **未实现**（全仓无调用） |
| 3 | 只读诊断：`GetForegroundWindow()` → 目标完整性级别，高于自身则一次性告警 | **未实现**（全仓无 `GetForegroundWindow`），且该诊断本身 **【UNVERIFIED】** |
| 4 | SAS：`SendSAS` 需服务或 `uiAccess`，本仓普通用户态进程两者都不满足 ⇒ v1 不做，fast-path 的 Ctrl/Alt/Del 按普通按键注入（锁屏/安全桌面上无效） | **按裁决未实现**（全仓无 `SendSAS`） |

`proto::EncodeCtrlAltDel()` 的注释已声明"SAS 由 winlogon 在会话内提出"是产品假设而非 mstsc 证据；
注入侧必须把它当 best effort。

### 2.6 卡键（stuck key）

`SendInput` 文档同页：
> "This function does not reset the keyboard's current state. Any keys that are already pressed when the
> function is called might interfere with the events that this function generates." **【未复验】**

若不处理：远程按住 Ctrl/Shift/Alt/Win 时断网 ⇒ 本机永久卡住修饰键（一次断连即可造成本地桌面不可用）。

裁决（已实现）：按会话跟踪"仍按下的键/按钮"（`PressedInputs`，只存 `KeyId{scancode, extended}` 与按钮号，
不存时间戳与内容），`ReleaseSession(session_id)` 补发 `KEYEVENTF_KEYUP` / `MOUSEEVENTF_*UP`。
跟踪只在事件**通过两道门（限流 + 队列）之后**发生，因此"被拒绝的按下"永远不会被当成 held。

---

## 3. 协议完整性缺陷清单

约定：P-n 编号沿用。状态列：**已修** / **部分** / **按裁决** / **未实现**。

### P-1 横向滚轮 `kPtrHwheel` —— **已修**

- 解码（`server.cpp:DecodePointerEvent`）：`wheel = (pf & kPtrWheel) || (pf & kPtrHwheel)`，**WHEEL 优先**；
  `InputEvent::horizontal = !vertical`。
- 广告：默认 `input_flags` 含 `kInputFlagMouseHWheel = 0x0100`。
- 注入：`MOUSEEVENTF_HWHEEL`，`mouseData = wheel`（单位），正值 = 向右。
- 测试：`desktop_input_horizontal_wheel`、`server_decodes_wheel_rotation_in_wire_units`。

### P-2 滚轮符号/单位 —— **已修**

契约：`ui(格) → client encode 格×120 = 单位 → wire(9 位二补码) → server decode = 单位 → 注入 mouseData = 单位（不再缩放）`。
线上单事件只能表达 9 位二补码（`-256..+255`），所以客户端把一个 UI 事件**分块**成每块 ≤ 255 单位、同一 PDU 内按同符号
依次发出（`kMaxWheelChunksPerEvent = 8` 封顶，超出部分丢弃并计 `dropped_wheel_units_count_`）。
锚点（客户端 `InputEvent.wheel_delta` 的单位是**格**，服务端是**120 单位/格**的单位；一"格" = 120 单位）：
- 客户端编码：`-1 格 → 0x0388`（= -120 单位）、`+1 格 → 0x0278`（= +120 单位）、`+2 格 → 0x02F0`（= 240）、
  `-3 格 → 分两块 0x0301(-255) / 0x0397(-105)`（`tests/test_client.cpp` 的 `client_encodes_*` /
  `client_splits_three_notch_wheel_without_losing_rotation`）；
- 服务端解码：`0x0388 → -120`、`0x0478 → 横向 +120`、`0x0301 → -255`、`0x02FF → +255`、`0x0600 → 垂直优先 0`
  （`tests/test_server.cpp` 的 `server_decodes_wheel_rotation_in_wire_units`）。

- 解码：`DecodePointerEvent` 对 `kPtrWheelRotationMask` 做 9 位二补码展开（`0x0100` 是符号位，不是独立标志）。
- 注入：`BuildNative` 的 `kWheel` 分支 `mouseData = input.wheel`，**不乘 120**；滚轮事件不带 `MOUSEEVENTF_MOVE`，
  且 `InputEvent.x/y` 在滚轮分支被清零（xPos/yPos 必须忽略）。
- 测试：`desktop_input_wheel_positive_is_wire_units`、`..._negative_...`、`desktop_input_wheel_ignores_xy`。

### P-3 相对移动 `kMouseRel`（0x5）—— **解码已修；注入按裁决不做**

- 解码：`InputEvent::Kind::kMouseRel` + 有符号 `rel_x/rel_y`；`is_move` 保持 false；X1/X2 走 PTRXFLAGS 回退。
  快路径与慢路径产出同一个事件。
- 注入裁决：**不注入**。`MOUSEINPUT` 文档（**【未复验】**）说明相对模式受鼠标速度与两个阈值影响
  （最多放大 4 倍），注入位移 ≠ 客户端位移。如要支持，必须"读 `SystemParametersInfo` 反算"或
  "相对转绝对（积分 + 钳制）"，两者都属新风险，需单独裁决。
- 测试：`desktop_input_mouse_relative_not_injected`、`server_input_relative_mouse_keeps_signed_deltas`、
  `server_decodes_slowpath_mouse_relative`。

### P-4 QoE 时间戳与伪 `kKey` —— **已修**

- 机制（历史）：消费事件后 `break` 落到回调，`ev` 是默认构造的 `InputEvent`（默认 `kind = kKey, scancode = 0`）——
  于是回调收到"幽灵按键"。
- 修复：`kQoeTimestamp` 分支 `pos += 4; continue;`（不回调），`kMouseRel` 明确为 `Kind::kMouseRel`。
- 测试：`server_input_qoe_timestamp_is_not_an_input_event`、`server_input_relative_qoe_pointer_sequence_keeps_order`。

### P-5 move / release 不可区分 —— **已修**

- 解码：按钮身份在 `kPtrDown` **之外**解析（快路径/慢路径共用 `DecodePointerButtons`）；
  `InputEvent::is_move = (pf & kPtrMove) != 0`。
- 注入侧防御：`TranslateInput` 只在 `is_move && 几何可用` 时产 `kMouseMove`；按钮身份存在时单独产 `kMouseButton`；
  两者可同事件产出（移动+按下 = 两个动作，扣两个令牌）。
- 测试：`desktop_input_button_left_up_keeps_identity`、`server_input_pointer_move_and_release_are_distinguishable`。
- 遗留：`down=false && button==0 && !move` 的"未知释放"没有独立计数器（见 §4.1 T13）。

### P-6 E1（`kKbdExtended1` 0x04）/ PAUSE —— **已修（整序列不注入）**

- 线上序列：`04 1D / 00 45 / 05 1D / 01 45`——**只有两个 CTRL 事件带 0x04**，NUMLOCK(0x45) 两半不带。
- 平台硬边界：`KEYEVENTF_EXTENDEDKEY` 只能表达 **0xE0** 前缀，不能表达 **0xE1**：
  > "KEYEVENTF_EXTENDEDKEY 0x0001 | If specified, the wScan scan code consists of a sequence of two bytes,
  > where the first byte has a value of **0xE0**."（https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-keybdinput **【未复验】**）
- 修复（两层）：
  1. `PauseSequenceFilter`（平台中立）在 `RdpSession::InjectIfLeasable` 里、**租约门之前**过滤：
     `extended1` → arm 且丢（down/up 都 arm，因为 0x45 up 在 CTRL up 之后）；`armed && 0x45 && !extended` → 丢，
     0x45 的 up 关窗；其它键关窗且注入；`kSync` 关窗且注入（见 P-7）。上界：孤立 0xE1 最多吞一次 NumLock tap。
  2. `TranslateInput` 的 `kKey` 分支 `if (ev.extended1) return out;` 作为兜底；`IsInjectable` 同判。
- `RdpSession::ReleaseInput` 调 `pause_filter_.Reset()`。
- 用例：`desktop_input_pause_sequence_is_fully_suppressed`、`desktop_input_extended1_is_not_injected`、
  `server_pause_sequence_is_not_injected`（PAUSE PDU → 注入 0 次且不抢租约；随后独立 NumLock tap → 恰好 2 次）。
- 真机"NumLock 物理状态不变"仍 **【UNVERIFIED】**。
- 安全性论证不依赖"4 事件在同一 PDU"：过滤器是**会话级**，拆成 4 个 PDU 仍为 0 动作；
  仓库客户端确实同一 PDU（`EncodePauseKey()` + `EncodeFastPathInputPdu()`，wire 头 `0x10` = 4 事件），
  `FastPathPdu::parse` 是整 PDU 全有全无，服务端不做 fast-path 分片重组 ⇒ 截断的 PAUSE 整条丢弃。
  第三方客户端是否也单 PDU **【UNVERIFIED】**。

### P-7 `kSync`（0x3）—— **部分**

- 字段：`InputEvent::sync_flags`；位定义 `FastPathSyncFlag`（ScrollLock 0x01 / NumLock 0x02 / CapsLock 0x04 / KanaLock 0x08）。
- 语义：状态声明 + 按键状态重置为"全部抬起"。
- 已实现：**不注入**（`TranslateInput` 返回空，`IsInjectable` 为 false，不抢租约）；
  **序列终止**：`PauseSequenceFilter::ShouldDrop` 在 `kSync` 分支 `ctrl_armed_ = false; return false;`
  ——否则"E1 → SYNC → NumLock tap"会被整组吞掉（用例 `desktop_input_pause_window_closed_by_sync`）。
- 未实现：注入器的"期望状态决策函数"（记录期望 + `GetKeyState(VK_NUMLOCK/CAPITAL/SCROLL)` 实测 →
  `相等则 0 次、不等则 1 次按键`）。KanaLock 在 Win32 无对应 toggle 键位，忽略。
  真机同步一致性 **【UNVERIFIED】**。

### P-8 `kUnicode`（0x4）—— **通过**

- 解码：`InputEvent::unicode_code`（u16）+ `release`；快/慢路径都解。
- 约束 1：`KEYEVENTF_UNICODE` 要求 `wVk = 0`，且只能与 `KEYEVENTF_KEYUP` 组合——`BuildNative` 即此形态。
- 约束 2：BMP 外字符以**代理对**（两个 `kUnicode` 事件）到达；注入端逐个直译，不折叠。
- 边界：`unicode_code == 0` 丢弃（`TranslateInput` + `IsInjectable` 双判）。
- 测试：`desktop_input_unicode`、`server_decodes_slowpath_unicode`。

### P-9 广告 `FASTPATH_INPUT2` —— **已修**

`InputCapabilitySet` 默认 `input_flags = kInputFlagScancodes | kInputFlagFastPathInput(0x0008) |
kInputFlagFastPathInput2(0x0020) | kInputFlagMouseX(0x0004) | kInputFlagUnicode(0x0010) |
kInputFlagMouseHWheel(0x0100)` = **0x013D**。规范原文（**【未复验】**）：
> "INPUT_FLAG_FASTPATH_INPUT2 0x0020 | Advertised by **all RDP servers**, except for RDP 4.0, 5.0, and 5.1
> servers, to indicate support for fast-path input. …"
（https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b3bc76ae-9ee5-454f-b197-ede845ca69cc）

用例：`server_advertises_fastpath_input_capability` 断言 Demand Active 的 `input_flags & 0x0020 != 0`。
真机 mstsc 行为（不广告时是否改发慢路径）**不再阻塞**：慢路径已实现。

### P-10 慢路径输入 `PDUTYPE2_INPUT (0x1C)` —— **已修**

- `HandleSlowPathPdu` 把 0x1C 交给 `ParseSlowPathInput`：`numEvents(2) + pad2Octets(2)` + N×
  `TS_INPUT_EVENT`（`eventTime(4) + messageType(2) + 6 字节体`）。
- `messageType` 是规范的离散值：`0x0000 SYNC / 0x0002 UNUSED / 0x0004 SCANCODE / 0x0005 UNICODE /
  0x8001 MOUSE / 0x8002 MOUSEX / 0x8004 MOUSEREL`（https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a9a26b3d-84a2-495f-83fc-9edd6601f33b **【未复验】**）。
- 两条通道共用 `DecodePointerEvent` / `DecodePointerButtons` / `InjectIfLeasable`，语义不重复。
- 用例：`server_decodes_slowpath_scancode_input`、`server_decodes_slowpath_mouse_wheel`、
  `server_decodes_slowpath_mousex`、`server_decodes_slowpath_mouse_relative`、`server_decodes_slowpath_unicode`、
  `server_slowpath_malformed_input_is_survivable`、`server_slowpath_event_count_mismatch_is_counted`、
  `server_undefined_share_data_type_is_not_reinterpreted`。

### P-11 未知 `eventCode` / 长度校验 —— **部分**

- 已实现：快路径未知 `eventCode` 与慢路径未知 `messageType` → 计 `unknown_input_event_count()` 并放弃该 PDU 剩余部分
  （长度未知，无法重同步），**不断连**——有意偏离规范的 SHOULD，理由：便于抓包定位客户端版本差异（SHOULD 非 MUST）。
- 已实现：慢路径 `numberEvents` 与载荷不符（短头 / 截断事件体 / 计数越界）→ `malformed_input_pdu_count()`；
  share-data 头可解析但 `pduType2` 未定义 → 同样计 `malformed_input_pdu_count()` 并丢弃该载荷
  （不再回退成 fast-path 解析，历史缺陷见 `docs/spec/discover.md`）。
- **仍缺**：快路径事件体截断（`pos + need > n`）直接 `return`，**不计**畸形；PDU 结束后也没有
  `pos == n` 的强校验（`[MS-RDPBCGR]` 遍历不变量）。

### P-12 汇总表

| ID | 缺陷 | 状态 | 是否阻塞"真实客户端可操作" |
|---|---|---|---|
| P-1 | `kPtrHwheel` 未解码 | **已修** | 否 |
| P-2 | 滚轮符号/单位双重计数 | **已修** | 否 |
| P-3 | `kMouseRel` 被吞 | **解码已修 / 注入按裁决不做** | 否（相对鼠标模式不支持，已声明） |
| P-4 | `kMouseRel`/QoE 触发伪 `kKey` | **已修** | 否 |
| P-5 | move / release 不可区分 | **已修** | 否 |
| P-6 | E1/Pause 不忠实 | **已修**（真机 UNVERIFIED） | 否 |
| P-7 | `kSync` 盲注入会反相 | **部分**（不注入 + 序列终止；决策函数未做） | 否 |
| P-8 | `kUnicode` 字段足够 | **通过** | 否 |
| P-9 | 未广告 `FASTPATH_INPUT2` | **已修** | 否 |
| P-10 | 慢路径输入被静默丢弃 | **已修** | 否 |
| P-11 | 未知 eventCode / 严格长度校验 | **部分**（计数已做；快路径截断未计数、无 `pos == n` 强校验） | 否 |

---

## 4. 测试计划

### 4.1 纯映射函数（`rtsc_desktop_input_tests`，每个平台都跑）

两段式设计不变：

```
InputEvent + InjectGeometry + SessionInputState  --TranslateInput()-->  std::vector<PlatformInput>   // 纯函数
std::vector<PlatformInput>                       --BuildNative()+Emit()-->  SendInput(...)          // Win32 后端
```

`PlatformInput` 是自有 POD（`kind, scancode, extended, release, unicode, x, y, button, button_down, wheel, horizontal`），
**不引用** `windows.h`。

| 用例 | 断言（当前实现） | 现有用例 |
|---|---|---|
| T1 scancode down/up | `scancode` 原样、`release` 透传 | `desktop_input_key_a_down`、`..._key_release` |
| T2 extended | `extended=true` 不偏移 scancode（≠ 0x100） | `desktop_input_extended_key_keeps_scancode` |
| T3 unicode | `unicode_code != 0` → 一个 `kKey`（`unicode` 置位），零码 → 空 | `desktop_input_unicode`；零码由 `desktop_input_is_injectable_matches_translation` 的 `zero_unicode` 交叉断言覆盖 |
| T4 绝对指针 | `x=0 → 0`；`x=w → 65535`；**中点 = 32785**（1920 宽）/ 32798（1080 高），不是 32767/32768 | `desktop_input_absolute_move_full_range`（端点）；中点由公式 `floor((x*65535 + (extent-1)/2)/(extent-1))` 决定，**无独立用例** |
| T5 几何偏移 | **不适用**：`InjectGeometry` 无 origin（§1.7#2 OPEN） | 无（设计未实现） |
| T6 几何不可用 | `{0,0}`/`{1,1}`/`{2,1}`/`{1,2}` → 绝对移动**不产出**；按钮仍产出 | `desktop_input_absolute_move_requires_usable_geometry`。**已知不一致（K3，Low）**：`IsInjectable` 不带几何入参，`kMouse{is_move}` 在退化几何下仍返回 true（会取租约但产 0 动作），该交叉一致性用例本身也明确注明"T6 是 geometry-dependent、由 T6 用例单独钉住" |
| T7 越界钳制 | `x=65535, width=1280 → 65535`；`x >= width-1` 一律钳到 65535 | 实现于 `NormalizeAxis`；无 65535 入参用例 |
| T8 滚轮纵向 | `wheel_delta=-120 → wheel=-120`，无 `kMouseMove`；`mouseData` 由后端直写（不乘 120） | `desktop_input_wheel_negative_is_wire_units`；后端 `mouseData` 无测试（§1.8） |
| T9 滚轮横向 | `horizontal=true → kWheel.horizontal`，后端 `MOUSEEVENTF_HWHEEL` | `desktop_input_horizontal_wheel`；后端标志无测试 |
| T10 滚轮零值 | `wheel_delta == 0` → **不产出**（不占队列位、不耗令牌） | `desktop_input_zero_wheel_is_not_injected`、`desktop_input_is_injectable_matches_translation` |
| T11 按钮按下 | 1/2/3/4/5 身份透传；后端 1→LEFT、2→RIGHT、3→MIDDLE、4/5→XDOWN+XBUTTON1/2 | 翻译层：`desktop_input_button_left_down`；X1/X2 身份解码：`server_decodes_mousex_buttons_with_ptrxflags`；**后端的 XBUTTON 标志映射无测试**（§1.8） |
| T12 按钮释放重建 | 释放事件带 button 身份 → `kMouseButton(button_down=false)`（不靠"猜 button=1"） | `desktop_input_button_left_up_keeps_identity` |
| T13 未知释放 | 无历史按下 + `button==0 && !move` → 不产出（`TranslateInput` 的 `kMouse` 分支两条件皆假） | `desktop_input_mouse_without_move_or_button_is_empty`；**无 `unknown_release` 计数器** |
| T14 sync 决策 | 只有"不注入"；**决策函数未实现** | `desktop_input_sync_not_injected` |
| T15 Pause/E1 | 整条序列 0 个动作；单独 NumLock tap = 2；孤 E1 最多吞一次 tap；`kSync` 终止窗口 | `desktop_input_pause_sequence_is_fully_suppressed`、`desktop_input_pause_window_closed_by_sync`、`..._extended1_is_not_injected` |
| T16 kMouseRel | 0 个 `PlatformInput`（且不抢租约） | `desktop_input_mouse_relative_not_injected` |
| T17 队列合并 | 同会话队尾纯移动只更新坐标（后继移动仍过限流门） | 纯策略侧覆盖于队列用例；后端合并本身读码审查 |
| T18 队列不丢键 | 满软限驱逐最旧移动；硬限丢键而非移动；held release 例外 | `desktop_input_queue_evicts_move_when_available`、`..._hard_limit_drops_key`、`..._accepts_held_release_at_hard_limit` |
| T19 ReleaseSession | 补发 `CTRLUP`+`LEFTUP`；异常时仍擦状态并计 `release_failures` | `desktop_input_release_session_clears_state_when_append_throws`（只证明 append 被调用与异常路径，不校验键位） |
| T20 限流 | 会话 400/800、全局 1000/2000、held release 免限不耗令牌、未持有 up 同权、全局拒绝不扣会话令牌 | `desktop_input_rate_limit_session_bucket`、`..._global_bucket`、`..._release_is_exempt`、`..._unheld_release_is_limited`、`..._held_release_keeps_token`、`..._global_drop_keeps_session_token`、`..._is_per_session`、`..._forget_resets_session` |

### 4.2 集成测试（脚本化 peer，无需真机）—— **全部已有用例**

| ID | 断言 | 用例 |
|---|---|---|
| I1 | QoE 时间戳不回调 | `server_input_qoe_timestamp_is_not_an_input_event` |
| I2 | 相对移动有符号 delta 且不伪装成 kKey | `server_input_relative_mouse_keeps_signed_deltas`、`server_input_relative_qoe_pointer_sequence_keeps_order` |
| I3 | `0x1000`（释放）→ `button==1 && button_down==false` | `server_input_pointer_move_and_release_are_distinguishable` |
| I4 | `0x0800`（移动）→ `is_move == true` | 同上 |
| I5 | HWHEEL → `kWheel && horizontal && wheel_delta==120` | `server_decodes_wheel_rotation_in_wire_units` |
| I6 | Demand Active `input_flags & 0x0020` | `server_advertises_fastpath_input_capability` |
| I7 | 慢路径 0x1C 解码；畸形可存活并计数；未知 code 计数 | `server_decodes_slowpath_*`、`server_slowpath_malformed_input_is_survivable`、`server_input_unknown_event_code_is_counted` |
| I8 | 两会话 id 非零且互异；槽位交接；0 = 不限；release 先于交接；无不可注入事件占租；PAUSE 不占租 | `server_input_lease_one_session_then_handoff`、`server_input_lease_zero_means_unlimited`、`server_release_session_precedes_lease_handoff`、`server_non_injectable_input_does_not_hold_lease`、`server_pause_sequence_is_not_injected` |

### 4.3 必须真机验证（**【UNVERIFIED】** 清单，不得写成"已验证"）

1. `SendInput` 注入到高完整性前台窗口是否被静默丢弃，以及 `GetLastError` 实际取值。
2. 安全桌面 / UAC 提示 / 锁屏时注入的落点。
3. `SendSAS` 在本仓部署形态（非服务、无 uiAccess 清单）下的失败形态（预期失败）。
4. Pause 用 `VK_PAUSE` 注入是否被目标应用识别（当前实现是"整条不注入"，此项只在将来改语义时需要）。
5. `kSync` 的 toggle 同步与物理指示灯一致性（决策函数未实现，先验"不注入"是否正确）。
6. 多显示器 / 高 DPI 下绝对坐标映射（`MOUSEEVENTF_VIRTUALDESK` + 无 origin 的 §1.7#2 缺口）。
7. 多会话同时注入的实际干扰与限流阈值（租约是否真的避免"抢鼠标"）。
8. 注入输入对本机用户是否可见（预期完全可见；`dwExtraInfo` 是否可被本机钩子读到）。
9. 与 mstsc 的滚轮方向/幅度一致性。
10. PAUSE 注入后本机 NumLock 物理状态不变（AC-7）。
11. 第三方客户端是否也把 PAUSE 的 4 事件放在同一 PDU。

### 4.4 变异测试（第 16 条要求）

| 变异体 | 期望 | 覆盖现状 |
|---|---|---|
| M1 `dx = x`（不做 65535 归一化） | T4 端点用例转红 | **有真实用例**（`desktop_input_absolute_move_full_range`） |
| M2 `mouseData = wheel_delta * 120` | T8 转红 | **部分**：改 `TranslateInput` 会被 `desktop_input_wheel_*` 抓住；改 `BuildNative`（真正的危险点）**无用例**（§1.8） |
| M3 释放分支改为"猜 button=1" | 身份用例转红 | **有真实用例**：`desktop_input_button_left_up_keeps_identity`（翻译层）；`server_decodes_mousex_buttons_with_ptrxflags`（解码层 X1/X2 释放仍带身份） |
| M4 满队列丢**键**而不是丢移动 | T18 转红 | **有真实用例**（`desktop_input_queue_evicts_move_when_available`） |
| M5 `ReleaseSession` 不补 keyup | T19 转红 | **部分**：`desktop_input_release_session_clears_state_when_append_throws` 依赖 `release_failures == 1`，若完全不追加则计数为 0 → 红；但键位/方向未校验 |
| M6 `extended1` 当普通 CTRL 注入 | T15 转红 | **有真实用例**：`desktop_input_extended1_is_not_injected`、`..._pause_sequence_is_fully_suppressed`、`server_pause_sequence_is_not_injected` |
| M7（新）`PauseSequenceFilter` 不对 `kSync` 清 window | T15 的 `kSync` 用例转红 | **有真实用例**（`desktop_input_pause_window_closed_by_sync`，批 17 落地） |

任一条"改坏仍全绿" = 假测试，必须重写用例（不允许以"实现正确所以没必要"解释）。
当前无覆盖/半覆盖的两项是 M2（后端）与 M5（键位校验），已记入 §1.8。

---

## 5. 与甲（Win32 取证）的磋商（历史，已收敛）

初始立场与依赖点保留于本文件历史版本；结论均已体现在 §1/§2。与甲的 D1–D6 结论：

| # | 问题 | 采用结论 |
|---|---|---|
| D1 | `SendInput` vs `keybd_event` | `SendInput`（可批量、可返回条数） |
| D2 | 注入落点 | 系统输入流（前台窗口） |
| D3 | `dwExtraInfo` | 自有常量 `0x52545343`，不复用 mstsc 常量 |
| D4 | 多会话抢鼠标 | 单队列串行 + 租约（默认 1 槽），无等待队列 |
| D5 | UIPI 可否从错误码区分 | 不可；只计数 + 诊断（诊断未实现） |
| D6 | Session 0 / 服务态 | v1 不支持，只支持交互式会话进程 |

---

## 6. 最小改动清单（状态）

| 步骤 | 内容 | 状态 |
|---|---|---|
| 1 | 解码诚实性（P-4/P-5 + `horizontal`/`extended1`/`is_move`/`rel_x/rel_y`） | **完成**（`has_payload` 未加，改用逐 case `continue`） |
| 2 | 能力广告 0x0020 | **完成** |
| 3 | 接缝 `DesktopInputSink` + 真 session id | **完成** |
| 4 | 纯翻译层 + 单测 | **完成** |
| 5 | Win32 后端 + worker + 限流 + 计数 + `ReleaseSession` | **完成**（M2/M5 覆盖缺口见 §4.4） |
| 6 | CLI / 默认值 / 门禁 | **完成**：`--allow-input`、`--allow-input-unverified`、`--max-input-sessions`；**不存在** `--input-share` / `--input-owner` |
| 7 | 变异测试 M1–M6 | M1/M3/M4/M6 有真实用例；M2/M5 部分（§4.4） |
| 8 | 几何来源（origin / VIRTUALDESK / `--monitor N`） | **未做**（§1.7#2 OPEN） |
| 9 | `--help` 危险说明 | **未做**（§2.4） |
| 10 | UIPI 启动诊断 / 前台窗口只读诊断 | **未做**（§2.5） |
| 11 | 快路径截断计数 + `pos == n` 强校验 | **未做**（§3 P-11） |

---

## 7. 收敛记录（H / I / K / J）

### 7.1 审计 H（`docs/spec/input-batch12-review-H.md`，teardown 异常安全）

- 结论：F-1 的**行为缺陷闭合**（`ReleaseInput` 里 `holders.erase` 在 `ReleaseSession` 抛异常时仍执行，
  顺序仍是"先 sink 后放槽"），但 `catch (...)` 当时完全静默、Win32 sink 内仍有同型残留（低危）。
- 处置：批 13' 已修 — `ReleaseSession` / `Shutdown` / `WorkerMain` 全部异常隔离 + `release_failures` 计数，
  `Shutdown` 改 `noexcept` 并保证 `notify_all` + `join` 无条件执行；`InputStats::release_failures` 接出到宿主日志。
  复核见本文件 §1.8 / §2.3 / §4.4。
- 未闭合（可观测性）：服务端侧 `input_release_failure_count()` 只有计数，无周期日志（与 sink 计数不同源，
  sink 的 `release_failures` 已由宿主打印）。

### 7.2 审计 I（`docs/spec/input-batch12-review-I.md`，全文对账 48 条失效引用）

逐项处置：

| I 的编号 | 内容 | 处置 |
|---|---|---|
| C1 | P-6 extended1 当裸键注入 | 批 14（平台层）+ 批 16（会话级过滤器）**已闭合** |
| C2 / D2 | §1.7#2 几何来源错误 | **仍 OPEN**，本文件 §1.7#2 按实测错位点重写（不再声称有 origin） |
| C3 | T6 几何不可用未拒绝 | **已修**：`TranslateInput` 要求 `width>1 && height>1` 才产绝对移动 |
| C4 | T10 零滚轮 | **已修**：`wheel_delta == 0` 返回空，`IsInjectable` 同步 |
| C5 | §2.5 诊断未实现 | **仍未实现**，本文件 §2.5 逐条标"未实现" |
| C6 / D12 | `--help` 不描述危险 | **仍未修**，§2.4 记录现状 |
| C7 / D13 | CLI 幻觉 `--input-share`/`--input-owner` | 本文件 §6 已改为实际旗标 |
| C8 | 快路径长度强校验 | **仍未做**（§3 P-11） |
| C9 | M5/M6 变异存活 | M6 已转红（P-6 修复 + 用例）；M5 部分覆盖（§4.4） |
| D1 | §1.3/§1.4 接口名整体失效 | **本版重写**：只保留 `DesktopInputSink` / `desktop_input_map.*` / `MakeWin32DesktopInputSink` / `Shutdown`；删除 `InputSink`/`input_inject*`/`CreatePlatformInputSink`/`ReleaseAll` |
| D3 | §3 状态列过期 | **本版按 §0.1 重写** |
| D4 | §0 结论过期 | **本版重写** |
| D5b | T4/T12/T13/T14/T15 | 本版 §4.1：T4 中点改为 32785/32798、T12 改新解码形态、T13/T14 标未实现、T15 改"整序列不注入" |
| D6 | §4.2 I1–I8 待做口径 | 本版换成当前用例名 |
| D7 | §4.4 M1–M6 | 本版加"覆盖现状"列 + 新增 M7 |
| D8 | `AppendReleasesLocked` / `ForgetReleasedSessionsLocked` 的旧行号引用 | 本版删除全部旧行号，全部改用符号名（`desktop_input_win32.cpp:AppendReleasesLocked` / `desktop_input_win32.cpp:ForgetReleasedSessionsLocked`） |
| D9/D15 | 全部行号 | 本版**不写行号** |
| D10 | "只有一个锁"/"等待者"/`--input-share` | 本版 §2.3 改为 `mu_` + `log_mu_` 两把锁、无等待队列、`--max-input-sessions` |
| D11 | "5 行 banner + 日志首行" | 本版 §2.2 改为 7 行 banner，位于启动/凭证行之后 |
| D14 | §7 未收敛 | 本版 §7 追加收敛记录 |

补记：I 指出的常量漂移**不存在**（256/1024、400/800/1000/2000、515/1539、4 ms、1 s、±255、120、
`0x52545343` 均与代码一致）；漂移只在行号与状态描述，本版已按符号名 + 当前状态重写。
I 还指出 `desktop_input_win32.cpp` 顶部注释的峰值公式与 seam 不一致——**已于批 18 修复**：
代码注释原先写 "hard_limit + |pressed| … + sessions × 515"（把合成 up 当作额外项重复计基线），
现与 §1.5 统一为同一事实的单一式子：`peak ≤ kHardQueueLimit + 515·K`，`K` = 持租且 `pressed` 非空的会话数
（默认 `max_input_sessions = 1` → 1539）。合成 up 与之是**同一项**（由 `AppendReleasesLocked` 直推、
purge 保留 `synthetic`），不是额外相加。

### 7.3 审计 K（`docs/spec/input-batch14-review-K.md`）

- 第 1 轮：P-6 **FAIL(High)**（4 事件 → 2 个 0x45 动作 = NumLock 仍翻转）、测试覆盖 **FAIL(Medium)**
  （"全局丢 0x45"变异全绿存活）、几何/零滚轮 PASS、回归 PASS。
- 处置：批 16 实现 `PauseSequenceFilter`（会话级、租约门前）+ `ReleaseInput` 的 `Reset()`，补两条序列级用例；
  批 16 复验（K §9）全绿，M1/M2a/M2b/M3 + 无过滤器对照全部转红。
- K §9.3 的两条观察：
  1. `rtsc_server_tests` 的 checks 总数随 `WaitUntil` 轮次浮动 ⇒ **验收只钉 `0 failing` 与用例名**（已写入流程记忆）；
  2. `kSync` 不清 `ctrl_armed_` ⇒ **批 17 已修**（§3 P-7，用例 `desktop_input_pause_window_closed_by_sync`，
     变异 M7 转红）。
- K 的"4 事件是否同 PDU"结论：修复不依赖该假设；仓库证据（客户端单 PDU、整 PDU 全有全无、无分片重组）
  支持"截断的 PAUSE 整条丢弃"；第三方客户端 **【UNVERIFIED】**。

### 7.4 审计 J（teardown 复验 + 测试缝风险）

- 范围：teardown 异常安全的独立复验 + `RTSC_DESKTOP_INPUT_TESTING` 测试缝的风险（宏误定义 / 工厂被编译掉 /
  全局 hook 污染）。
- 现状与处置：
  - 测试缝只存在于 `rtsc_desktop_input_tests`（`WIN32` + 该宏）；生产库 `rtsc_server_desktop_input`
    不带该宏，工厂正常提供；
  - 测试构建里生产工厂被 `#if defined(RTSC_DESKTOP_INPUT_TESTING)` **编译掉**，改由 null sink 提供
    `MakeWin32DesktopInputSink`，所以 `desktop_input_null_sink_stats_count_injections` 的计数语义不受影响；
  - 全局 `g_append_failure_hook` 是 `std::atomic` 函数指针，用例用完即置 `nullptr`，且同一个可执行文件内
    只影响 `AppendReleaseLocked`；
  - `WorkerJoinable` / `WorkerFinished` / `SessionCount` / `PendingForgetCount` 都是只读取值。
- 判定口径：J 的结论**不阻塞**映射层/服务端证据；若 J 提出新的缝风险，按"补用例或收缩宏范围"处理，
  并在本节追加。截至第 833 轮，J 的复验结论尚未回执（`process.md` 第 833 轮记为在途），本节不代其盖章。
  上述三条是"谁有权改这个宏、宏泄漏到生产的路径"的现状事实，不依赖 J 的结论。

---

## 附录 A：证据索引（仅符号名，不含行号）

- `include/rtsc/server/desktop_input.h`：`InjectGeometry`、`InputStats`、`DesktopInputSink`、`MakeWin32DesktopInputSink`
- `include/rtsc/server/desktop_input_map.h`：`PlatformInput`、`TranslateInput`、`PauseSequenceFilter`、
  `IsInjectable`、`IsReleaseInput`、`KeyId`、`PressedInputs`、`TrackInput`、`IsHeldRelease`、`EnqueueAction`、
  `EnqueueState`、`DecideEnqueue`、`AdmitInput`、`AdmitOutcome`、`AdmitAndTrack`、`InputRateLimiter`
- `src/server/desktop_input_map.cpp`：`NormalizeAxis`、`TranslateInput`、`DecideEnqueue`、`TrackInput`、
  `IsHeldRelease`、`AdmitInput`、`InputRateLimiter::Allow/Refill/Forget/dropped`
- `src/server/desktop_input_win32.cpp`：`Win32DesktopInputSink`（`SetGeometry`/`Inject`/`ReleaseSession`/
  `Stats`/`EnqueueLocked`/`AppendReleasesLocked`/`ForgetReleasedSessionsLocked`/`EmitDueMoves`/`Dispatch`/
  `BuildNative`/`Emit`/`LogFailure`/`Shutdown`/`WorkerMain`）、常量 `kMaxQueue`/`kHardQueueLimit`/
  `kMoveInterval`/`kFailureLogInterval`/`kInjectTag`
- `src/server/desktop_input_null.cpp`：`NullDesktopInputSink`
- `tests/desktop_input_win32_test_hooks.h`：`SetDesktopInputAppendFailureHook`、`MakeWin32DesktopInputSinkForTest`、
  `DesktopInputTest*`
- `include/rtsc/server/server.h`：`ServerConfig`（`desktop_width/height`、`enable_desktop_input`、
  `max_input_sessions`、`accept_any_credentials`）、`InputEvent`、`InputCallback`、`RdpServer::SetInputSink`、
  `unknown_input_event_count`、`malformed_input_pdu_count`、`input_lease_denied_count`、
  `input_release_failure_count`、`kMaxDesktopWidth/Height`、`kMaxFramebufferBytes`
- `src/server/server.cpp`：`ClampDesktopSize`、`DecodePointerButtons`、`DecodePointerEvent`、`InputLease`、
  `RdpSession::InjectIfLeasable`、`RdpSession::AcquireInputLease`、`RdpSession::ReleaseInput`、
  `RdpSession::ParseInputEvents`、`RdpSession::ParseSlowPathInput`、`RdpSession::HandleSlowPathPdu`、
  `Impl::next_input_session_id`、`kRefreshInterval`
- `tools/rtsc_server/main.cpp`：`usage`、`ParseOptions`、`main` 里的门禁段 / sink 创建 / 启动行 /
  `log_input_stats` / 租约拒绝告警 / `--seconds` 循环
- `include/rtsc/proto/input.h`：`FastPathKbdFlag`、`FastPathSyncFlag`、`PointerFlag`、`PointerXFlag`、
  各 `Encode*`、`kScancodePause`、`EncodeCtrlAltDel`、`EncodePauseKey`
- `include/rtsc/proto/capabilities.h`：`kInputFlag*`、`InputCapabilitySet::input_flags`
- `include/rtsc/server/desktop_gdi.h`：`MakeGdiDesktopSource(monitor_index, x, y, width, height, error)`
- `src/client/client.cpp` / `src/proto/input.cpp`：滚轮编码与 PAUSE 序列
- `tests/test_desktop_input.cpp` / `tests/test_server.cpp` / `tests/test_input.cpp`：见 §4.1 / §4.2 的用例名
- 官方文档（本轮**未重新抓取**，引文沿用原文/本地记录）：`SendInput`（nf-winuser-sendinput）、
  `KEYBDINPUT`（ns-winuser-keybdinput）、`MOUSEINPUT`（ns-winuser-mouseinput）、`SendSAS`（nf-sas-sendsas）、
  [MS-RDPBCGR] Processing Fast-Path Input Event PDU（178aef78-…）、Input Capability Set（b3bc76ae-…）、
  Fast-Path Input Event（76c4dd59-…）、Slow-Path Input Event（a9a26b3d-…）
