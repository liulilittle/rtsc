# 输入注入接缝 / 安全默认值 / 协议完整性 —— 审计乙设计

状态：2026-10-31（第 793 轮，W11 批次）。作者：审计乙（`ses_e6db6db1dffeJJge2MFgISFFyj`）。
范围：**只读审计产物**。本文件不包含任何产品代码改动；`src/`、`include/`、`tests/` 本轮由执行 AI
（`ses_e6db7292effeP7r4WX0a48hO8C`）改动滚轮编码/解码，本审计对上述目录只读。

证据口径：每条论断给出 `文件:行` 或官方文档 URL 原文。无法验证的给出 **【UNVERIFIED】** 标签，
并写清"怎么才能验证"。禁止以"应该/大概率"代替证据。

---

## 0. 结论摘要

1. **P0 缺口不在协议解析层**：`InputEvent` 接缝已存在（`include/rtsc/server/server.h:191-224`），
   缺的是"把 `InputEvent` 变成 Win32 `INPUT` 并注入"这一层，以及它的默认关闸、失败可观测、会话归属。
2. **规范是硬要求，不是增强项**：`[MS-RDPBCGR]` 2.2.8.1.2 "Processing Fast-Path Input Event PDU" 原文
   > "Once this PDU has been processed, the server **MUST inject the input event into the user's session**."
   （https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/178aef78-2606-4e44-a94a-6ee6f6dc5cc6）
   今天这一条完全没有实现（`tools/rtsc_server/main.cpp:453-463` 只写日志）。
3. **接缝裁决**：保留 `InputCallback`（4 处测试依赖其签名），**新增**借用指针式
   `InputSink`（`bool Inject(uint32_t session_id, const InputEvent&)`）+ `RdpServer::SetInputSink`，
   与仓内既有的 `SetDesktopSource`/`SetClipboard` 借用指针范式一致（`server.h:240`、`server.h:256`）。
   理由是现有回调**拿不到会话 ID**（`server.h:224`），而 8 会话共享一个物理桌面必须能归属事件。
4. **安全默认值裁决：默认 off + `--allow-input`；且叠加密钥弱化组合时"拒绝启动"而非"打印警告"**。
   仅警告已被本仓证明无效（`--allow-any-credentials` 今天只有一行日志，`main.cpp:383-387`）。
5. **协议侧还有 3 个用户清单外的前置缺陷**：服务器不广告 `INPUT_FLAG_FASTPATH_INPUT2 (0x0020)`
   却只实现 fast-path；慢路径输入 PDU（`pduType2 = 0x1C`）被静默丢弃；未知 `eventCode` 只 return
   而规范要求 SHOULD 断连。这三条不修，"接上注入器"对真实 mstsc 仍可能是"注入了 0 个事件"。

---

## 1. 接缝设计

### 1.1 现状（硬证据）

| 事实 | 证据 |
|---|---|
| 唯一生产调用只写日志 | `tools/rtsc_server/main.cpp:453-463`（`log.line("session active: " + kind + " event forwarded")`） |
| 回调签名无会话 ID、无返回值 | `include/rtsc/server/server.h:224` `using InputCallback = std::function<void(const InputEvent&)>;` |
| 回调在会话线程执行，且**不得长时间阻塞** | `server.h:193-194` "Callbacks run on the session thread, so an implementation must not block the session for long." |
| 每个会话有 `session_id_`，但构造时两条路径都传 0 | `src/server/server.cpp:1623`、`src/server/server.cpp:1843`、`src/server/server.cpp:1962` |
| 解码后统一回调（无 kind 过滤） | `src/server/server.cpp:1614` `if (input_callback_) input_callback_(ev);` |
| 库不知道桌面几何给谁用 | `server.h:57-59`（`desktop_width/height`）、`desktop_gdi.h:38-39`（捕获矩形被**缩放**到协商几何） |
| 现有借用指针范式（可照抄） | `server.h:240` `SetDesktopSource(DesktopSource*)`；`server.h:249-256` `SetClipboard`（"must outlive the server (including Stop())"） |

### 1.2 三个候选方案与裁决

| 方案 | 优点 | 否决/采纳理由 |
|---|---|---|
| A. 沿用 `InputCallback`（生产 lambda 里做注入） | 零库改动 | **不可采纳**：①拿不到会话 ID（`server.h:224`），8 会话无法归属/仲裁；②返回 `void`，注入失败无法向上传播（`server.h:224`）；③生命周期靠调用方自觉，`Stop()` 后回调仍可能被会话线程调用（`server.h:253-255` 的 clipboard 契约正说明该风险真实存在） |
| B. 派生 `RdpSession` / 虚函数 | 语义最强 | **不可采纳**：`RdpSession` 是 `server.cpp` 匿名命名空间内的实现细节（`server.cpp:546` 起，`namespace {` 在 `server.cpp` 内），把它提升为公有基类等于公开内部协议状态机，爆炸半径远超本 P0 |
| C. 新增 `InputSink` 借用指针接口（**采纳**） | 加法式、不破坏现有测试签名、可携带 session_id 与失败返回、生命周期契约与 clipboard 一致 | 采纳。`SetInputCallback` 保留原语义（观测/日志/测试），`SetInputSink` 负责执行 |

### 1.3 接口（设计草案，**不落入产品代码**）

```cpp
// include/rtsc/server/input_sink.h （新增，平台中立）
namespace rtsc::server {

// 注入目标桌面几何：注入器把 RDP 坐标换算成平台坐标需要它。
// 与 DesktopSource 的捕获矩形同源（desktop_gdi.h:27-42），不是协商几何的想当然。
struct InjectGeometry {
    int32_t origin_x = 0;   // 相对虚拟桌面左上角
    int32_t origin_y = 0;
    int32_t width = 0;      // 物理像素宽（>0 才可注入）
    int32_t height = 0;
    bool virtual_desktop = false;  // true → MOUSEEVENTF_VIRTUALDESK
};

class InputSink {
 public:
  virtual ~InputSink() = default;
  // 在会话线程被调用；实现必须立即返回（内部入队），不得在此做阻塞 I/O。
  // 返回 false = 该事件被拒绝/丢弃（已计数），调用方不做任何协议层惩罚。
  virtual bool Inject(uint32_t session_id, const InputEvent& ev) = 0;
  // 会话结束 / Stop()：释放该会话仍按下的键与按钮，避免系统级卡键。
  virtual void ReleaseSession(uint32_t session_id) = 0;
  virtual void SetGeometry(const InjectGeometry& geom) = 0;
};

}  // namespace rtsc::server
```

`RdpServer` 侧（与 clipboard 同样的借用指针 + 生命周期文字）：

```cpp
void SetInputSink(InputSink* sink);   // nullptr 关闭注入；指针必须活过 Stop()
```

调用顺序：`RdpSession::ParseInputEvents` 在 `server.cpp:1614` 先调 `input_sink_->Inject(session_id_, ev)`，
再调现有 `input_callback_`（保持测试/日志语义不变）。**两者都保留**，`SetInputSink` 不改变
`SetInputCallback` 的任何既有行为（4 处测试因此不需要修改：`tests/test_server.cpp:615`、`:655`、`:2017`，
`tests/test_gui_send.cpp:200`）。

### 1.4 注入器实现位置与生命周期

- 文件：`include/rtsc/server/input_inject.h`（平台中立接口 + 纯翻译函数）、
  `src/server/input_inject_win32.cpp`（Win32 `SendInput` 后端）、
  `src/server/input_inject_null.cpp`（非 Windows：`Inject` 恒返回 false 并计数，等价于
  `NullClipboard` 的角色，`main.cpp:363-366`）。
- 工厂：`std::unique_ptr<InputSink> CreatePlatformInputSink(std::string* error)`（照
  `CreatePlatformClipboard()` / `MakeGdiDesktopSource()` 的形状，`desktop_gdi.h:40-42`）。
- 生命周期：**`main.cpp` 里必须在 `RdpServer server(cfg);` 之前声明**，与 clipboard 同因
  （`main.cpp:358-361` 注释："the clipboard must outlive the server object, because the session threads
  touch it until Stop() joins them"）。`Stop()` 返回后注入器方可析构。
- 关闭顺序：`RdpServer::Stop()`（`server.h:264-266`，join 会话线程）→ 注入器 `ReleaseAll()` →
  注入器析构。若反过来，会话线程可能对已析构的 sink 写队列。

### 1.5 线程模型：会话线程**禁止**直接 `SendInput`

裁决：会话线程只做"翻译 + 入队"，真正的 `SendInput` 在**注入器自有的一条工作线程**里执行。

依据与理由：

1. `server.h:193-194` 明确要求回调不得长时间阻塞；`ActiveLoop` 是单线程串行循环
   （`server.cpp:1415-1470`），一旦阻塞，同一循环里的 `rdpsnd_->Poll`（`:1419-1421`）、
   `rdpdr_->Poll`（`:1430-1432`）与帧刷新（`ReadFrame`，`:1433`）全部停摆 → 8 会话各自卡住。
2. `SendInput` 的返回语义要求调用点是**单点且可计量**：
   > "The function returns the number of events that it successfully inserted into the keyboard or mouse
   > input stream. If the function returns zero, the input was already blocked by another thread."
   （https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput）
   多线程各自调用时"成功/被阻塞"的归属无法判定，计数也就没有意义。
3. 共享桌面需要**串行化**：8 条会话线程并发调用 `SendInput` 会让事件流交错不可复现
   （文档同页："inserts the events … serially into the keyboard or mouse input stream. These events are not
   interspersed with other keyboard or mouse input events" —— 单次调用内部有序，**跨调用不保证**）。
   单工作线程 + 单队列即把"跨会话交错"收敛成一个确定的合并顺序。

队列策略（工作线程内）：

| 事件类 | 策略 |
|---|---|
| `kKey` / `kUnicode` / 按钮按下抬起 | FIFO，不与移动合并 |
| `kMouse` 纯移动（无按钮位） | **合并**：同会话只保留最新位置（移动是状态量，不是平台动作量）。定时发送路径每 4 ms（250 Hz）一次；同会话的按键/按钮/滚轮会**立即 flush** 待发移动，因此瞬时输出可以高于 250 Hz。移动还和所有平台动作一样受 §2.3 的 400/1000 限流 |
| `kWheel` | FIFO，不与移动合并（离散平台动作） |
| 队列达到软上限 256 | 先驱逐**最旧的一条纯移动**并计数（`dropped_queue_full++`） |
| 队列达到硬上限 1024 且无可驱逐的移动 | 只豁免 **held release**：该 key/按钮仍在会话 `pressed` 集合中（口径 = scancode + 0xE0 标志 / 按钮号）；其余平台动作（按下、移动、**未持有的释放**）一律 `kDrop` 并计数 |
| 队列上界（**峰值**口径） | `peak(queue) ≤ hard_limit + 饱和时刻的 pressed 集合大小 = 1024 + 515 = 1539`。pressed 的结构上限是 510 键（`scancode` 是 `uint8_t`，255 × 0xE0 两位）+ 5 按钮。**不要**把它读成瞬时不变式：每次越限接受同时擦除一个 pressed 项，释放后队列仍可能是 1534 而 pressed 已为 0（探针 774 次违反瞬时公式） |
| 饱和引理 | `size > soft_limit ⇒ 队列内无纯移动`：`size ≥ soft` 时任何事件都先走 `kEvictMove`（只替换不增长），每来一个按下就吃掉一条移动；移动被驱逐光后新移动走 `kDrop`。因此饱和时无移动可驱逐，硬限的 `kDrop` 不会被 evict 绕过 |
| `kSync` | 不注入（v1 无"设置 toggle 状态"的注入形式；见 §3 P-7） |
| `kMouseRel` | **已上送**（`InputEvent::Kind::kMouseRel`，带符号 `rel_x/rel_y`）；v1 不注入（相对位移受系统鼠标加速度污染），按 `dropped_unsupported` 计数 |

`unicode` 释放不豁免：`KEYEVENTF_UNICODE`（`wVk = 0`）只输入字符、不按下物理键，不进入 pressed 集合，
因此也没有可清的物理状态。**未持有的 keyup 也不豁免队列硬限**（重复 up，或被硬限/限流丢弃的按下的 up）——
否则单条 32 KiB 输入 PDU 的数千个 keyup 就能让队列无限增长；这些 up 同时也**不免限流**（见 §2.3）。

### 1.6 失败传播：计数 + 限流日志，**不断连**

裁决：注入失败**不**断开 RDP 连接，只计数并限流告警（每 5 s 至多一行）。理由：

1. 注入失败的主因是**服务器本机状态**（UIPI、会话锁屏、桌面切换），不是对端违约；断连等于把本机
   状态问题变成对端的连接问题，语义错位。
2. 可被利用为 DoS：本机普通用户开一个高完整性窗口（任务管理器）即可让所有远程会话被判"注入失败"
   而被踢掉（UIPI 阻挡的静默性见 §2.5 引文）。
3. 协议层惩罚应当只用于协议违约。规范给的违约惩罚是"未知事件类型 SHOULD 断连"
   （https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/178aef78-2606-4e44-a94a-6ee6f6dc5cc6
   原文："If a Fast-Path Input Event structure is received that does not match one of the known types, the
   server SHOULD drop the connection."），与"注入被系统拒绝"是两件事。

对外可观测面：实现以 `InputStats`（`include/rtsc/server/desktop_input.h`）暴露
`injected`、`dropped_queue_full`、`dropped_rate_limited`、`send_failures`；`dropped_unsupported`
（含 `kMouseRel`、零码事件与已释放会话的迟到事件）在注入器内部计数但当前未接出结构体。
`last_error` 只进 5 s 限流日志，结构体不存 Win32 错误码，也不存按键内容。
`SendInput` 失败日志的**实际**行为是：任意一次失败后，若距上一条失败日志已满 5 s 就打印一行
（`desktop_input_win32.cpp` 的 `LogFailure`）；没有"失败率 >50% 持续 5 s"的判定，也没有"恢复"行。
限流丢弃不打印日志（只经 `dropped_rate_limited` 可见）。主机（`tools/rtsc_server/main.cpp`）
每 5 s 采样一次 `Stats()`，仅在任一计数变化时打印
`input stats (periodic): input_injected=… input_dropped_queue=… input_rate_limited=… input_send_failures=…`，
退出前再打印一条 `(final)` 终值。

**回压**：`Inject` 返回 false 仅表示"已丢弃"，会话不做重传（输入是实时语义，重传旧键位比丢掉更糟）。

### 1.7 会话归属与几何：两个必须先补的"接口余量"

1. **会话归属**：`Inject(session_id, ev)`。今天 `server.cpp:1843` / `:1962` 两处会话构造都传
   `session_id = 0`，所以 `session_id` 目前在库内恒为 0 → 多会话仲裁形同虚设。
   修复建议：`RdpServer::Impl` 用原子递增计数器给每个会话分配 ID（与 `total_session_count()`
   `server.h:288-295` 同一处记账，避免两套计数），并把 `session_id` 一并放入日志行
   （`main.cpp:462` 现在是 `"session active: key event forwarded"`，无归属）。
2. **几何来源**：`InjectGeometry` 必须来自**捕获源的真实矩形**，而不是 `ServerConfig::desktop_width/height`
   （`server.h:57-59`）。因为 GDI 源把"捕获矩形**缩放**到协商几何"（`desktop_gdi.h:38-39`），
   而协商几何会被客户端请求 + 上限钳制改变（`server.h:142-159`：8192×8192 / 32 MiB 上限、
   `server.cpp` 内 `desktop_width_`/`desktop_height_` 记录钳制结果）。
   若把 1280×1024 的协商坐标直接当物理坐标，1080p 屏上指针只会落在左上角 2/3 区域。

绝对坐标换算（纯函数，见 §4）：

```
dx = round((x - geom.origin_x) * 65535 / (geom.width  - 1))   // 0..65535
dy = round((y - geom.origin_y) * 65535 / (geom.height - 1))
flags |= MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | (geom.virtual_desktop ? MOUSEEVENTF_VIRTUALDESK : 0)
```

依据（https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-mouseinput）：
> "If MOUSEEVENTF_ABSOLUTE value is specified, dx and dy contain normalized absolute coordinates between
> 0 and 65,535. … In a multimonitor system, the coordinates map to the primary monitor."
> "If MOUSEEVENTF_VIRTUALDESK is specified, the coordinates map to the entire virtual desktop."

边界：`x/y` 越界（客户端可发 0..65535 的 `u16`，`server.cpp:1567-1568`）必须**钳制**而不是回绕；
`width/height <= 1` 视为几何不可用 → 拒绝注入并计数（避免除零）。

---

## 2. 安全设计（默认值裁决）

### 2.1 默认 off，显式 `--allow-input`（裁决：采纳）

- 现状对照：音频**默认 off** 且注释写明隐私理由（`main.cpp:105` `AudioSource audio = AudioSource::kOff; // default: no capture (privacy)`；
  `main.cpp:342-345`）；USB 重定向服务器侧未实现（`docs/spec/server-mode.md:42`）。
  注意**反例**：剪贴板是**默认 on**（`main.cpp:352-366` 无条件创建 `CreatePlatformClipboard()`）。
  所以"与既有策略一致"要写准确：本仓的既有策略是**"会外泄本机数据/会扩大攻击面的能力默认 off"**
  （音频外泄声音 → off）。输入注入不泄数据，但**授予控制权**，风险等级更高 → 必须 off。
  （顺带记录的观察，非本批范围：剪贴板默认 on 与该策略不自洽，建议后续单独裁决。）
- 默认 off 的具体形态：不加 `--allow-input` 时 `SetInputSink(nullptr)`，`main.cpp:453-463` 的日志回调
  原样保留（会话可观测性不丢）。启动行增加 `input=off|on` 与 `input_max_sessions=N` 字段，与现有
  `audio=` 字段并列（`tools/rtsc_server/main.cpp` 的启动日志）；运行期首次租约拒绝时打印一次
  `WARNING: input lease denied (input_lease_denied_count=N)`，此后按"计数变化且距上一条汇总 ≥1 s"
  打印 `WARNING: input lease denied summary: input_lease_denied_count=N`，不按事件打印。
- 为什么不是"默认 on 但可关"：RDP 输入是**单向权限跃迁**——从"看屏幕"到"操作整个交互会话"
  （文件、浏览器、UAC 之后的提权面、Ctrl+Alt+Del 面）。默认 on 等于每个部署点默认把桌面交出去，
  且用户很难察觉（本机用户只会看到鼠标自己动）。默认值必须是**安全的那一侧**。

### 2.2 组合门禁：`--allow-input` + 弱化凭据 → **拒绝启动**（裁决：拒绝，不是警告）

本仓的三档真实风险（都有代码证据）：

| 组合 | 实际含义 | 证据 |
|---|---|---|
| `--allow-input --no-enhanced` | **完全不做密码校验** | `main.cpp:428-432` 原文："With --no-enhanced there is no password check at all."；`server.h:66-76` 同样声明"on the Standard RDP Security path an installed authenticator only sees the account name - the Client Info password field is NOT verified" |
| `--allow-input --allow-any-credentials` | 口令是**字面量默认值** `"password"`，且账号名任意 | `main.cpp:90` `std::string password = "password";`；`main.cpp:331-340` lookup 只比对 `user/domain`，命中即返回 `accepted_password` |
| 两者叠加 | 任何可达端口者 = 桌面完全控制（无需知道任何秘密） | 上两行合并 |

裁决：**默认拒绝启动**（退出码 2，与 `ParseOptions` 失败一致，`main.cpp:295-298`），报错文案直接点名
"输入注入需要经过验证的凭据；请去掉 --no-enhanced / --allow-any-credentials，或显式加
`--allow-input-unverified` 承担风险"。给 `--allow-input-unverified` 逃生门（并打印 5 行醒目 banner +
写进日志首行），是为了不把高级用户的合法自测场景彻底堵死，同时让"我知道我在干什么"成为一次显式动作。

论证（为什么不是"打印显著警告"）：

1. 本仓已有先例证明警告不足：`--allow-any-credentials` 的警告只是一行 `log.line`
   （`main.cpp:383-387`），`server.h:73-75` 也把它写成"Start() emits a WARNING"。日志会被重定向、
   被截断、被 `--log` 写进没人看的文件；默认值 + 启动失败是唯一无法被忽略的信号。
2. 失败模式是"静默提权"：攻击者拿到的是本机交互桌面，操作痕迹与本人操作同源（见 §2.4），
   事后审计成本极高。对这种后果，配置期强制优于运行期提示。
3. 这是**默认值裁决**，不是删除功能：显式逃生门保留全部能力，符合"默认安全、显式危险"原则。

### 2.3 多会话共享桌面（8 会话，`docs/spec/server-mode.md:24-27`；`server-mode.md:37` 7 tests/184 checks）

事实：8 个会话捕获**同一个**桌面（`main.cpp:393-395` 注释："The server serves the same source to every
session"），注入也落在**同一个**输入桌面 → 两个会话同时发绝对移动，指针会互相抢占；同时打字会串字。

裁决（默认 + 逃生门）：

| 模式 | 行为 | 默认 |
|---|---|---|
| `first`（**默认**） | 第一个发起输入的会话取得"控制租约"；其他会话的输入被丢弃并计数 + 告警（首次一条 + 之后按周期汇总）；租约在持有点断连时释放给下一个等待者（先到先得）。键盘/按钮状态按租约持有者单独跟踪 | ✅ |
| `all` | 所有会话都注入（"共享白板"语义），靠队列串行 + 限流降低破坏 | 仅 `--input-share` 时 |
| `none` | 只观测不注入（今天的等价物） | `--allow-input` 未给时 |

限流（与模式无关的硬上限，防单会话饿死其他会话/刷爆输入流）。实现在注入器的 `Inject()` 内、
与队列共用同一临界区（`include/rtsc/server/desktop_input_map.h` 的 `InputRateLimiter` 自身无锁），
按 `std::chrono::steady_clock` 单调时间补充令牌，**事件入队前**判定（因此被限流的平台动作
既不进队列，也不进 held 记账）：

- 单会话：`kSessionEventsPerSecond = 400` 平台动作/s，桶容量 `kSessionBurst = 800`（2 s 突发；
  交互式打字 < 20 动作/s，快速拖拽 + 移动合并后 < 300 动作/s）。
- 全局：`kGlobalEventsPerSecond = 1000` 平台动作/s，桶容量 `kGlobalBurst = 2000`（8 × 400 的约 1/3，
  确保队列不会长期打满）。
- 口径是**平台动作**而不是 RDP 事件：一个 `kMouse` 移动+按钮事件翻译成两个动作、扣两个令牌，
  因此这类事件的稳态上限是 200/s。
- 纯移动输出频率：合并后的定时路径每 4 ms 一次（250 Hz）；同会话的按键/按钮/滚轮会立即 flush
  待发移动，瞬时可以高于 250 Hz。它与 `kRefreshInterval`（约 1 s 桌面刷新，`server.cpp:1410-1412`）
  无关——注入频率不必与刷新率绑定。
- 超限：丢弃该平台动作 + `InputStats::dropped_rate_limited++`；不排队、不断连、**不逐事件打日志**
  （限流只经计数可见；`SendInput` 失败才走 §1.6 的 5 s 限流日志）。限流先于队列判定，
  同一个动作只会被其中一个计数器记一次。
- 例外：只有 **held release（该会话确实按住的 key/按钮的 up）不受限流，也不消耗令牌**——
  丢这种释放比丢按下危险，且其数量被 pressed 集合限界（最多 510 键 + 5 按钮）。
  **未持有的 up（重复 up、被限流或硬限丢弃的按下的 up、unicode up）不免限流**，
  它们和按下一样消耗令牌；队列硬限对它们同样生效。
- 清理用合成 up（`ReleaseSession`/`Shutdown` 补发的键/按钮 up）绕过 `Inject()`，
  因此既不受队列策略也不受限流。
- 全局桶拒绝时不扣会话桶的令牌，否则一个忙碌会话会静默抽干其他会话的配额。
- **锁**：只有一个锁——注入器内部队列的互斥量；`Allow`/`Forget` 都在该锁内，
  `Stats()` 只读 relaxed 原子的丢弃计数。不引入"每会话一把 SendInput 锁"（那会把跨会话
  交错变成随机顺序，比单队列合并更差）。

### 2.4 输入回显 / 隐私

结论（对运维必须写进文档）：**注入的输入就是本机会话的真实输入**，会出现在服务器本机：

1. 指针会真的移动，键会真的落到**当前前台窗口**（`SendInput` 注入的是系统输入流，不是某个进程）。
   因此远程用户可以把内容打进本机用户正在编辑的文档、终端、浏览器。
2. 本机用户能看到光标自己动、窗口自己切换；**没有任何 API 能让注入的输入对本机用户不可见**。
   唯一可区分点是 `dwExtraInfo`：
   > "dwExtraInfo … An additional value associated with the keystroke. Use the GetMessageExtraInfo function
   > to obtain this information."（https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-keybdinput）
   即本机的低级钩子**可以**识别 AI/远程注入（mstsc 自己就用常量 `0x4321DCBA` 打标，
   `docs/spec/input-evidence.md:45`）。建议本仓用**自己的**常量（如 `0x52545343`，"RTSC"），
   便于本地排障与"注入 vs 真人"取证区分。
3. 反过来，远程端看到的桌面就是本机屏幕（GDI 捕获，`server-mode.md:14`），本机用户的一切可见内容
   对远程端也是可见的——这是今天**已经存在**的只读风险，注入把它升级为双向。
4. 因此：`--allow-input` 的语义必须描述为"把本机交互桌面交给远端操作"，而不是"支持远程输入"。
   文档与 `--help` 都要这么写（`main.cpp:15-55` 的 usage 块）。

### 2.5 UIPI / 完整性级别：**静默失败**如何暴露

规范行为（原文，`SendInput` 文档同页）：
> "This function is subject to UIPI. Applications are permitted to inject input only into applications that
> are at an equal or lesser integrity level."
> "This function fails when it is blocked by UIPI. Note that **neither GetLastError nor the return value will
> indicate the failure was caused by UIPI blocking**."

即：管理员窗口、UAC 提权后的进程、部分受保护进程收不到注入，而**返回值/错误码不会告诉你原因**。
暴露手段（不注入探测，避免"探测即操作"）：

1. `SendInput` 返回值 != 输入条数 → `injected_failed++`，记 `GetLastError()`（哪怕它不说 UIPI），
   **不做**"再试一次"（重试只会放大副作用）。
2. 启动时打印自身完整性级别与进程会话 ID（`GetTokenInformation(TokenIntegrityLevel)` /
   `ProcessIdToSessionId`），并打印一句能力边界：低/中完整性进程无法操作高完整性窗口。
3. 运行期诊断（只读、不注入）：对 `GetForegroundWindow()` 取 PID → 取目标完整性级别，
   若 > 自身级别，则一次性告警"前台窗口完整性更高，注入将被系统静默丢弃"。这是"解释失败"而不是
   "预测失败"，必须标注 **【UNVERIFIED】**：`GetForegroundWindow` 在 UIPI 下可能返回 NULL 或
   高完整性窗口句柄不可读，具体行为需真机验证。
4. Ctrl+Alt+Del / 安全桌面：`SendInput` **不能**产生 SAS；这是 Windows 的设计边界，正解是 `SendSAS`：
   > "To successfully call the SendSAS function, an application must either be running as a service or have
   > the uiAccess attribute … set to 'true' … The local security policy of a computer must be configured to
   > allow services and applications to simulate a SAS."（https://learn.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas）
   裁决：v1 **不**实现 SAS（普通用户态进程两条路都不满足），fast-path scancode 里的 Ctrl/Alt/Del
   序列按普通按键注入（在锁屏/安全桌面上无效），并在文档标注 **【UNVERIFIED】** 与已知限制。
   `proto::EncodeCtrlAltDel()`（`include/rtsc/proto/input.h:97-104`）的注释本身已声明"SAS 由
   winlogon 在会话内提出"是产品假设而非 mstsc 证据 —— 注入侧必须把这条假设降级为"best effort"。

### 2.6 卡键（stuck key）——安全与可用性都要处理

`SendInput` 文档同页：
> "This function does not reset the keyboard's current state. Any keys that are already pressed when the
> function is called might interfere with the events that this function generates."

若不处理：远程端在按住 Ctrl/Shift/Alt/Win 时断网 → 本机永久卡住修饰键，本机用户无法正常操作
（安全事件：远程可用一次断连造成本地桌面不可用）。

裁决：注入器**按会话**跟踪"仍按下的键/按钮"，在 `ReleaseSession(session_id)`（会话结束、`Stop()`、
租约被撤销）时补发对应 `KEYEVENTF_KEYUP` / `MOUSEEVENTF_*UP`。跟踪表只存 scancode/button id 集合，
不存时间戳与内容，避免把按键内容写进日志（隐私）。

---

## 3. 协议完整性缺陷清单（注入功能的前置条件）

约定：P-n 编号供与甲对账使用。**状态列**：`OPEN` 待修 / `EXEC` 执行 AI 本批在改（我方只读）/
`BLOCKER` 不修则注入对真实客户端无效。

### P-1 横向滚轮 `kPtrHwheel` 未解码（`EXEC`，本批由执行 AI 修）

- 证据：解码只判 `(pf & proto::kPtrWheel)`（`src/server/server.cpp:1571`），全仓 `src/` 无 `kPtrHwheel`
  使用（`[BASH: Select-String -Path src\server\server.cpp -Pattern "Hwheel|PtrMove|extended1" ]` → 0 命中）；
  常量存在（`include/rtsc/proto/input.h:41`）；服务器**广告**了该能力（`capabilities.h:225-234` 默认
  `input_flags` 含 `kInputFlagMouseHWheel`，由 `server.cpp:438-439` 原样发出）→ 能力广告与解码能力不一致，
  客户端据此合法发送却被丢。旧审计已记（`docs/spec/input-evidence.md:147`）。
- 修复：`if (pf & kPtrWheel) 纵向 else if (pf & kPtrHwheel) 横向`（WHEEL 优先，`docs/spec/share-data.md:745`）；
  `InputEvent` 增加 `bool horizontal`（执行 AI 本批改动，`process.md:297`）。
- 注入侧契约：`MOUSEEVENTF_HWHEEL`（0x1000），`mouseData = wheel_delta`（单位），正值 = 向右
  （`MOUSEINPUT` 文档："A positive value indicates that the wheel was rotated to the right"）。

### P-2 滚轮符号/单位（`EXEC`，本批由执行 AI 修；注入侧必须按新契约实现）

- 现状缺陷：`server.cpp:1573-1578` 先取 `pf & 0x01FF` 再按 `kPtrWheelNegative` 取负 → **双重计数**；
  编码侧 `src/client/client.cpp:231-238` 按幅值 + 独立负号位，且把**格数**直接当单位上线。
  探针实测（`docs/spec/discover` 即 `.opencode/discover.md:600-616`）：`-1` → `0x0301` → 解出 `-257`。
- 本批已定契约（`process.md:261-284`，主代理 + 甲共同定案，乙无异议）：
  `ui(格) → client encode 格×120 = 单位 → wire(9 位二补码) → server decode = 单位 → 注入 mouseData = 单位（不再缩放）`；
  clamp 在**单位域** ±255；锚点 `encode(-1)=0x0388`、`encode(+1)=0x0278`、`encode(-120)=0x0301`、
  `encode(+120)=0x02FF`、`hwheel(+1)=0x0478`；`decode(0x0301) = -255`、`decode(0x02FF) = +255`、
  `0x0600` 垂直优先。
- **注入侧硬约束**：`mouseData = ev.wheel_delta`（**不再乘 120**）。若注入侧再乘 `WHEEL_DELTA`，
  等于单位被二次放大（120 倍）——这是"自洽往返掩盖单位错误"的同型陷阱（`discover.md` 第 788 轮记录的
  第 12 例）。验收断言：`decode(0x0301) → mouseData == -255`（不是 -255×120，也不是 -2 格）。
- 另一条：滚轮事件**不得**带 `MOUSEEVENTF_MOVE`。xPos/yPos 在滚轮事件里应被忽略
  （`docs/spec/share-data.md:729`），若顺手注入绝对移动会导致指针跳到滚轮发生点。

### P-3 相对移动 `kMouseRel`（0x5）被吞掉，无法注入（`BLOCKER` 针对相对鼠标客户端）

- 证据：`server.cpp:1603-1606` 只 `pos += 6` 后 `break`；`InputEvent` 没有 `dx/dy` 字段
  （`server.h:195-221`）。线上语义：`xDelta/yDelta` 是**有符号 i16**（`docs/spec/share-data.md:796-807`），
  与绝对事件的 `u16` 不同（混用会把"向左"变成"大幅向右"）。
- 影响：mstsc 在相对鼠标模式（部分远程游戏/远程程序场景）下只发 `kMouseRel` → 注入层收到 0 个事件。
- 修复建议（分两步）：①解码补 `dx/dy`（新增 `int16_t dx, dy`，kind 增设 `kMouseRel` 或加 `bool relative`），
  不注入也先做到"可观测 + 计数"；②注入侧用 `MOUSEEVENTF_MOVE`（相对模式，不加 `ABSOLUTE`）。
  但**注意**：相对模式"is subject to the effects of the mouse speed and the two-mouse threshold values …
  it is thus possible for the system to multiply specified relative mouse movement … by up to four times"
  （`MOUSEINPUT` 文档）→ 相对注入的位移不等于客户端位移。裁决：v1 **不注入**相对移动（计数 +
  `dropped_unsupported`），并在文档标注原因；如需支持必须做"用 `SystemParametersInfo` 读阈值后反算"
  或"相对转绝对（积分 + 钳制）"，两者都属**新风险**，需单独裁决。

### P-4 QoE 时间戳（0x6）与 `kMouseRel` 一样触发**伪 `kKey` 回调**（`BLOCKER` 级隐患，因为默认值会注入 scancode 0）

- 机制（这是对 `discover.md:622-623` 的**机制修正**，结论一致）：`server.cpp:1607-1610` 消费 4 字节后
  `break`，控制流落到 `server.cpp:1614` 的 `input_callback_(ev)`；此时 `ev` 是 `server.cpp:1543`
  默认构造的 `InputEvent`，而 `Kind kind = Kind::kKey`（`server.h:204`）——
  **所以回调收到的是 `kind=kKey, scancode=0, release=false`**。`kMouseRel` 同理。
  不是"落到 default 分支"，而是"break 后仍回调默认构造值"；两种描述指向同一个 bug，但修复点不同
  （要修 1614 的回调条件，而不是只修 default）。
- 后果：一旦接上注入器，`scancode 0` 会被翻译成一条 Win32 键盘事件（`KEYEVENTF_SCANCODE` + `wScan=0`）
  注入本机 → 至少是无效事件刷屏，最坏触发未定义行为。这是"先修解码再注入"的硬理由。
- 修复建议：`kMouseRel` / `kQoeTimestamp` 分支不得落回调；最小改法是每个 case 里 `continue`
  （而不是 `break`），或把 `input_callback_` 调用移进各 case；同时 `InputEvent` 增加
  `bool has_payload`/改用 `std::optional<InputEvent>` 之类显式标记。并补回归用例：
  "发 1 个 `kQoeTimestamp` → 回调 0 次"、"发 1 个 `kMouseRel` → 回调 0 次（或 kind 明确为相对移动）"。

### P-5 `kPtrMove` 与按钮释放不可区分（`BLOCKER`：释放丢失 = 卡键/拖拽失败）

- 证据：按钮位只在 `if ((pf & proto::kPtrDown) != 0)` 内解析（`server.cpp:1580-1596`）→ 释放事件
  （客户端发 `0x1000` / `0x0001` 而**不带** `0x8000`，见 `src/client/client.cpp:208-223` 与
  测试 `tests/test_server.cpp:669-675`）解出 `button = 0, button_down = false`；
  纯移动 `PTRFLAGS_MOVE (0x0800)`（`share-data.md:739`）同样 `button = 0, button_down = false`，
  且 `InputEvent` 无"是否移动"字段（`server.h:195-221`）。
  测试已经把该缺陷固化为"预期"：`tests/test_server.cpp:695-703`（`else { ++seen.nondown_mouse; }`，
  只数个数，不看按钮）。旧审计的 P3 也已记录（`docs/spec/input-evidence.md:144`）。
- 后果：注入器收到"释放"时不知道该释放哪个键 → 要么丢弃（卡键），要么猜（误释放）。
- 修复建议：①按钮位在 `kPtrDown` 之外也解析（`ev.button` 独立于 `ev.button_down`）；
  ②加 `bool move` 显式位（或 `Kind::kMouseMove`）；③补语义用例：`0x1000` → `button=1, down=false`；
  `0x0800` → `button=0, down=false, move=true`；`0x9000` → `button=1, down=true`。
  ④注入侧状态机（防御式，即使解码修好也要）：`down=false && button==0` 且**没有** move 位 = 未知释放 →
  计数丢弃；`down=false && button!=0` → 释放该键。

### P-6 E1（`FASTPATH_INPUT_KBDFLAGS_EXTENDED1`，0x04）/ Pause 不忠实（`OPEN`，且是平台硬边界）

- 解码证据：`server.cpp:1549-1550` 只读 `kKbdRelease`(0x01) 与 `kKbdExtended`(0x02)，
  `kKbdExtended1`(0x04)（`input.h:22`）**没有**进入 `InputEvent`（`server.h:206-210` 无该字段）。
- 线上证据：Pause 的四事件序列是 `04 1D / 00 45 / 05 1D / 01 45`，两个 CTRL 事件带 `0x04`
  （`src/proto/input.cpp:90-102` 编码；`docs/spec/share-data.md:704-708` 规范原文）。
  被我们解码后变成：CTRL down、NUMLOCK down、CTRL up、NUMLOCK up（`extended=false`）。
  注入结果是"按了一下 Ctrl + 按了一下 NumLock"——NumLock **被真的切换**，与 Pause 毫无关系。
- 平台硬边界：`KEYEVENTF_EXTENDEDKEY` 只能表达 **0xE0** 前缀，不能表达 **0xE1**：
  > "KEYEVENTF_EXTENDEDKEY 0x0001 | If specified, the wScan scan code consists of a sequence of two bytes,
  > where the first byte has a value of **0xE0**."（https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-keybdinput）
  → 用 `SendInput` 无法合成 E1 序列。
- 裁决：①`InputEvent` 增加 `bool extended1`（忠实反映线上，供日志/诊断与未来实现）；②注入侧对
  `extended1` 事件**不注入**，计入 `dropped_unsupported` 并一次性说明"Pause 不可注入（0xE1 无法用
  SendInput 表达）"；③若确实需要 Pause，正解是 `wVk = VK_PAUSE (0x13)` 的按键事件——
  这属于**新语义**（不是 scancode 直译），标注 **【UNVERIFIED】**，需真机验证 Pause 是否被目标进程正确识别；
  ④绝不允许"当作裸 CTRL/NumLock 注入"（会切换 NumLock，是**副作用**）。

### P-7 `kSync`（0x3）：字段够用，但**不能盲注入**

- 字段证据：`server.h:219-220` `uint8_t sync_flags`；解码 `server.cpp:1599-1602` 直接透传 5 位 flags；
  位定义见 `input.h:26-31`（ScrollLock 0x01 / NumLock 0x02 / CapsLock 0x04 / KanaLock 0x08）。
- 语义证据：该事件是**状态声明**（指示灯应亮），并把按键状态重置为"全部抬起"
  （`docs/spec/share-data.md:770-783`）。
- 裁决：`kSync` **不注入**。若"按 shift 状态"去注入一次 NumLock 按键，等于**切换**（toggle），
  会把状态改成相反的一半概率。正确做法：注入器记录每会话期望状态，需要时用
  `GetKeyState(VK_NUMLOCK/VK_CAPITAL/VK_SCROLL)` 读实际状态，**仅在不等时**注入一次按键（这仍有 toggle 语义，
  但方向可控）；该"决策函数"可做纯单测（期望状态 + 实测状态 → 0/1 次按键），
  真机验证标注 **【UNVERIFIED】**。
- 另：KanaLock（0x08）在 Win32 无对应 toggle 键位，忽略并计数。

### P-8 `kUnicode`（0x4）：字段够用于注入，但有两条硬约束

- 字段证据：`semver` 不适用——`server.h:208` `uint16_t unicode_code`、`release`；解码 `server.cpp:1553-1561`。
  线上 3 字节（`docs/spec/share-data.md:710-718`），且**前提是服务器广告了 Unicode**
  （`capabilities.h:230-234` 默认含 `kInputFlagUnicode`，由 `server.cpp:438-439` 发出）→ 前提成立。
- 约束 1：`KEYEVENTF_UNICODE` 要求 `wVk = 0`，且"this flag can only be combined with the
  KEYEVENTF_KEYUP flag"（`KEYBDINPUT` 文档）→ 注入形态固定为
  `{wVk=0, wScan=char, dwFlags=KEYEVENTF_UNICODE | (release?KEYEVENTF_KEYUP:0)}`。
- 约束 2：`unicodeCode` 是 **u16**，BMP 外字符只能以**代理对**两个事件到达（同一 `kUnicode` 类型）。
  注入端逐个事件直译即可（系统会组合），不做代理对折叠——折叠反而会破坏顺序。
- 边界：`unicode_code == 0` 是非法（`wScan=0` + UNICODE 无意义）→ 丢弃并计数。
- Tahoma/输入法路径：Unicode 事件正是 IME 注入路径（`input-evidence.md:100-103` 的 `VK_PACKET (0xE7)` 分支），
  与 scancode 路径并列实现即可，无需额外字段。

### P-9 服务器**只实现 fast-path，却不广告 fast-path 输入能力**（`BLOCKER` 疑点，本审计新增）

- 证据：`server.cpp:438-439` 用 `InputCapabilitySet` 默认值 → `input_flags = 0x0001|0x0002|0x0004|0x0010|0x0100 = 0x0117`
  （`capabilities.h:220-234`），**缺** `0x0008 (FASTPATH_INPUT)` 与 `0x0020 (FASTPATH_INPUT2)`。
- 规范原文（https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b3bc76ae-9ee5-454f-b197-ede845ca69cc）：
  > "INPUT_FLAG_FASTPATH_INPUT2 0x0020 | Advertised by **all RDP servers**, except for RDP 4.0, 5.0, and 5.1
  > servers, to indicate support for fast-path input. Clients that do not support this flag will not be able to
  > use fast-path input when connecting to RDP 5.2, 6.0, …"
- 风险：我们只解 fast-path 输入（`server.cpp:1523-1531` 只处理 `action==0` 的 fast-path 头），却不声明支持。
  真实 mstsc 是否因此改发慢路径输入 → 慢路径输入被丢弃（P-10）→ "接上注入器仍然零事件"。
  **【UNVERIFIED】**：mstsc 10.0.26100.8875 在本服务器不广告 0x0020 时的实际行为未实测
  （需要 mstsc 抓包或真机联调；本审计禁止运行真实注入程序，也不具备 mstsc 反向互通环境）。
- 修复建议：`InputCapabilitySet` 默认加 `kInputFlagFastPathInput2 = 0x0020`（并可保留 0x0008 不加，
  因为它只对 RDP 5.0/5.1 语义），同时补用例断言服务器 Demand Active 里 `input_flags & 0x0020 != 0`。
  这一条**不阻塞**注入器实现，但阻塞"真实客户端可用"的验收。

### P-10 慢路径输入 PDU（`PDUTYPE2_INPUT 0x1C`）被静默丢弃（`BLOCKER` 疑点，本审计新增）

- 证据：`HandleSlowPathPdu` 只处理 `kRefreshRect` 与 `kSuppressOutput`
  （`server.cpp:1488-1519`），其余 pdu_type2 直接 `return true`（`:1520`）；
  而 `PDUTYPE2_INPUT = 0x1C` 是 C→S 的合法输入通道（`share-data.md:309`；
  `docs/spec/capabilities.md:312` 同值）。慢路径事件结构 `TS_INPUT_EVENT`
  = `eventTime(4)` + `messageType(2)` + data，`messageType` 取值 0x0000 SYNC / 0x0004 SCANCODE /
  0x0005 UNICODE / 0x8001 MOUSE / 0x8002 MOUSEX / 0x8004 MOUSEREL
  （https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a9a26b3d-84a2-495f-83fc-9edd6601f33b）。
- 规范还要求：非 fast-path 的 PDU 必须按慢路径处理
  > "If it is not set to this value the PDU is not a Fast-Path Input Event PDU and MUST be processed as a
  > slow-path PDU (section 3.3.5.2)."（同 178aef78 页）
- 修复建议：无输入注入之前，至少**计数 + 一次性告警**（"收到慢路径输入，未实现"），避免再出现"客户端发了、
  服务器静默丢了、没人知道"的第三例（前两例：HWHEEL、kMouseRel）。完整实现作为 P1 排期（映射到同一
  `InputEvent` 即可，两种通道共用注入队列）。

### P-11 未知 `eventCode` 的处理与规范不一致（`OPEN`，低危）

- 证据：`server.cpp:1611-1612` `default: return;`（丢弃整包、不断连）；规范要求
  > "If a Fast-Path Input Event structure is received that does not match one of the known types, the server
  > SHOULD drop the connection."（178aef78 页）
  本地规范笔记同结论：`docs/spec/share-data.md:683`（`ERRINFO_INVALIDINPUTPDUTYPE 0x000010CF`）。
- 裁决：**保持不断连**，但必须 `unknown_event_code++` 计数 + 限流日志，并在文档说明"我们选择比规范更宽松
  的 SHOULD"（这是有意偏离，需写明理由：便于抓包定位客户端版本差异；SHOULD 非 MUST）。
- 附带缺陷：遍历没有做 `remaining == 0` 强校验（`share-data.md:821-833` 的不变量）→ 长度字段与实际内容
  矛盾时不会报错。建议加严格校验 + 计数（低危）。

### P-12 汇总表（供主代理定案排序）

| ID | 缺陷 | 状态 | 是否阻塞"真实客户端可操作" |
|---|---|---|---|
| P-1 | `kPtrHwheel` 未解码 | EXEC（执行 AI） | 是（横滚无效） |
| P-2 | 滚轮符号/单位双重计数、格当单位 | EXEC（执行 AI） | 是（纵滚错向/错幅） |
| P-3 | `kMouseRel` 被吞 | OPEN | 是（相对鼠标模式全失效） |
| P-4 | `kMouseRel`/QoE 触发伪 `kKey`（scancode 0） | OPEN | 是（会注入垃圾键） |
| P-5 | move / release 不可区分，释放丢按钮 | OPEN | 是（卡键、拖拽失败） |
| P-6 | E1/Pause 不忠实（且 SendInput 无法表达 E1） | OPEN（平台边界） | 否（可降级为不支持） |
| P-7 | `kSync` 盲注入会反相 | OPEN | 否（不注入即可） |
| P-8 | `kUnicode` 字段足够 | 通过 | — （只需注入侧两条约束） |
| P-9 | 未广告 `FASTPATH_INPUT2` | OPEN | 是（疑点，UNVERIFIED） |
| P-10 | 慢路径输入被静默丢弃 | OPEN | 是（疑点） |
| P-11 | 未知 eventCode 不断连、无严格长度校验 | OPEN（有意偏离） | 否 |

---

## 4. 测试计划

### 4.1 纯映射函数（可跨平台跑，`ctest` 常态覆盖）

设计成"两段式"才能纯测（Win32 的 `INPUT` 结构不能进 Linux 构建）：

```
InputEvent + InjectGeometry + SessionInputState  --Translate()-->  std::vector<PlatformInput>   // 纯函数
std::vector<PlatformInput>                       --Emit()-->       SendInput(...)               // 只有 3 行 Win32
```

`PlatformInput` 是自有 POD（`kind, code, flags, data, dx, dy, extra_info`），**不引用** `windows.h`。
（仓内既有同型做法：协议编码器纯函数 + 平台后端薄封装，`src/proto/input.cpp` 与 `src/ui/window_win32.cpp` 分工。）

| 用例 | 断言 | 依据 |
|---|---|---|
| T1 scancode down/up | `{wScan=0x1E, flags=KEYEVENTF_SCANCODE}` / `|KEYEVENTF_KEYUP` | `KEYBDINPUT` 文档 |
| T2 extended | `extended=true` → `flags |= KEYEVENTF_EXTENDEDKEY (0x0001)` | 同上（E0 前缀） |
| T3 unicode | `wVk=0, wScan=char, flags=KEYEVENTF_UNICODE(0x0004) | (up?0x0002:0)` | 同上（`wVk` 必须 0） |
| T4 绝对指针 | `x=0 → dx=0`；`x=w-1 → dx=65535`；`x=w/2` 落在 32767/32768 | `MOUSEINPUT` 文档（0..65535） |
| T5 几何偏移 | `origin_x=1920,width=1920,x=1920 → dx=0` | `desktop_gdi.h:27-42` |
| T6 几何不可用 | `width<=1` → 返回空 + `unsupported++`（不除零） | 防御 |
| T7 越界钳制 | `x=65535, width=1280` → `dx=65535`（钳制，不回绕） | `server.cpp:1567-1568` 的 u16 输入域 |
| T8 滚轮纵向 | `wheel_delta=-120` → `mouseData = (DWORD)-120`，`flags=WHEEL`，**无 MOVE** | §P-2 契约 + `share-data.md:729` |
| T9 滚轮横向 | `horizontal, +120` → `flags=HWHEEL`，`mouseData=120` | `MOUSEINPUT` 文档 |
| T10 滚轮零值 | `wheel_delta==0` → 不产生任何 `PlatformInput` | 防御（避免空滚轮刷队列） |
| T11 按钮按下 | `button=1,down=true` → `LEFTDOWN`；2→RIGHTDOWN；3→MIDDLEDOWN；4/5→`XDOWN`+`XBUTTON1/2` | `MOUSEINPUT` 文档（XBUTTON1 0x0001 / XBULLON2 0x0002） |
| T12 按钮释放重建 | 先 `down(button=1)` 再 `down=false,button=0`（现解码形态）→ 产出 `LEFTUP` 且仅一次 | §P-5 状态机 |
| T13 未知释放 | 无历史按下 + `down=false,button=0` → 丢弃并 `unknown_release++`，不产生 `PlatformInput` | 防御（不猜） |
| T14 sync 决策 | 期望 NumLock=on & 实测 off → 1 次按键；相等 → 0 次 | §P-7（纯决策函数） |
| T15 Pause/E1 | `extended1=true` → 0 个 `PlatformInput`，`unsupported++` | §P-6 |
| T16 kMouseRel | 若解码上送相对移动 → 0 个 `PlatformInput`，`unsupported++` | §P-3 裁决 |
| T17 队列合并 | 3 次纯移动 → 1 次输出（保留最新坐标） | §1.5 |
| T18 队列不丢键 | 满队列下压入按键 → 键仍在，且被丢的是最旧移动 | §1.5 |
| T19 ReleaseSession | 按下 Ctrl+左键后 `ReleaseSession` → 产出 `CTRLUP` + `LEFTUP` | §2.6（SendInput 不重置键盘状态） |
| T20 限流 | 单会话 > 400 平台动作/s → 超出部分被计数丢弃；held release 不受限流，未持有的 up 受限流 | §2.3 |

### 4.2 仓库内可做的集成测试（脚本化 peer，无需真机）

- I1：`kQoeTimestamp` 单独成包 → `SetInputCallback` 回调**0** 次（P-4 回归）。
- I2：`kMouseRel` 单独成包 → 回调 0 次（或 kind 明确为相对移动），且计数递增（P-4/P-3）。
- I3：`0x1000`（释放）→ `button==1 && button_down==false`（P-5 回归，现有 `tests/test_server.cpp:695-703` 的
  "只数个数"必须改成语义断言——该测试目前是把缺陷固化成预期）。
- I4：`0x0800`（移动）→ `move==true`（或 `kind==kMouseMove`）。
- I5：`kPtrHwheel 0x0400|120` → `kind==kWheel && horizontal==true && wheel_delta==120`（依赖执行 AI 的本批改动）。
- I6：Demand Active 的 `input_flags & 0x0020`（P-9）。
- I7：慢路径 `PDUTYPE2_INPUT(0x1C)` 包 → 计数递增且不断连（P-10 的可观测化）。
- I8：`SetInputSink(mock)` → 断言 `session_id` 非 0 且两会话的 id 不同（§1.7）。

### 4.3 必须真机验证（**【UNVERIFIED】** 清单，不得写成"已验证"）

1. `SendInput` 注入到**高完整性**前台窗口是否被静默丢弃，以及 `GetLastError` 实际取值（文档说"不会指示"）。
2. 安全桌面 / UAC 提示 / 锁屏时注入的落点（是否落到 Default 桌面被丢弃）。
3. `SendSAS` 在本仓部署形态（非服务、无 uiAccess 清单）下是否可用（预期失败，需实测确认失败形态）。
4. Pause 键用 `VK_PAUSE` 注入是否被目标应用识别为 Pause（§P-6 备选方案）。
5. `kSync` 的 toggle 同步在真机上是否与物理指示灯一致（§P-7）。
6. 多显示器 / 高 DPI 下绝对坐标映射是否覆盖全部物理像素（`MOUSEEVENTF_VIRTUALDESK` 行为）。
7. 8 会话同时对同一桌面注入时的实际干扰程度与限流阈值是否够（`first` 租约是否真的避免"抢鼠标"）。
8. 注入的输入对本机用户是否**可见**（预期：完全可见；`dwExtraInfo` 是否可被本机钩子读到）。
9. 与 mstsc 的滚轮方向/幅度是否与本地屏幕一致（`process.md:272` 已列为待验项）。
10. mstsc 在不广告 `0x0020` 时是否改发慢路径输入（P-9 的核心疑点）。

### 4.4 变异测试（第 16 条要求，交付执行 AI 时逐条落）

| 变异体（故意改坏） | 期望 |
|---|---|
| M1 `dx = x` 而不做 65535 归一化 | T4/T5 必须转红 |
| M2 `mouseData = wheel_delta * 120` | T8 必须转红（这是本批最危险的"看起来合理"的变异） |
| M3 释放分支沿用"猜 button=1" | T12/T13 必须转红 |
| M4 队列满时丢**键**而不是丢移动 | T18 必须转红 |
| M5 `ReleaseSession` 不补 keyup | T19 必须转红 |
| M6 `extended1` 当成普通 CTRL 注入 | T15 必须转红 |

任一条"改坏仍全绿"= 假测试，必须重写用例（不允许以"实现正确所以没必要"解释）。

---

## 5. 与甲（`ses_e6db711e9ffeie9GVIfm6NDNL6`）的磋商（初始立场 + 待收敛项）

本文件先落我方立场；收敛结果见 §7 追加节（relay 往返后补写）。

我方对甲分工（Win32 取证：`SendInput` 语义 / `SCANCODE` / `EXTENDEDKEY` / `UNICODE` / `ABSOLUTE` 归一化 /
`WHEEL_DELTA` / UIPI / Session 0 / `SendSAS`）的**依赖点**（需要甲给出可引用原文或反编译地址）：

| # | 我需要甲的结论 | 我方当前取值 | 若不成立的影响 |
|---|---|---|---|
| D1 | `SendInput` 的 `keybd_event` vs `SendInput` 选择 | 用 `SendInput`（批量、可返回条数） | T1/T11 断言形态 |
| D2 | 注入到"本机前台窗口"还是"某个固定窗口" | 系统输入流（前台） | 多会话干扰判定 |
| D3 | `dwExtraInfo` 常量的取舍 | 自用常量，不复用 mstsc `0x4321DCBA`（`input-evidence.md:45`） | 取证可区分性 |
| D4 | 8 会话抢鼠标的真实表现（是否有"输入所有权"机制） | 单队列串行 + `first` 租约 | §2.3 默认值 |
| D5 | UIPI 失败是否可从 `GetLastError` 区分 | 不可（`SendInput` 文档明确） | §2.5 只做计数+诊断 |
| D6 | Session 0 / 服务态注入是否可行 | v1 不支持，只支持交互式会话进程 | 部署形态 |

我方认为**甲可能漏掉**的项（请甲对账）：
- **P-9 能力广告**（不广告 `FASTPATH_INPUT2`）——纯协议侧，甲的 Win32 视角容易漏，但它决定"客户端到底发不发 fast-path"。
- **P-10 慢路径输入 PDU 被静默丢弃**——同上。
- **P-4 的机制**（伪 `kKey` 来自 `server.h:204` 的默认 `kind`，而非 default 分支）——影响修复点。
- **`InputCallback` 无 session_id**（`server.h:224`）——这是接缝层问题，不是 Win32 语义问题。

我方**可能漏掉**、请甲补的项：
- 注入路径是否需要 `SetCursorPos`（mstsc 有 7 处，`input-evidence.md:64`）而不是纯 `MOUSEEVENTF_ABSOLUTE`
  的差异（含 `MOUSEEVENTF_MOVE_NOCOALESCE` 0x2000 对拖拽平滑度的影响）。
- 用户态进程能否读取前台窗口完整性级别（§2.5 第 3 点的可行性）。
- `SendInput` 在"目标线程忙/挂起"时是否会阻塞以及最长阻塞时间（决定 §1.5 是否需要超时看门狗）。

---

## 6. 交付给执行 AI 的最小改动清单（本审计不实施，只给验收口径）

按依赖顺序（每一步可独立验证）：

1. **解码诚实性**（P-4/P-5）：`kMouseRel`/`kQoeTimestamp` 不落回调；`kPtrMove` 与释放可见；
   `InputEvent` 增 `move`、`horizontal`、`extended1`、`dx/dy`（若做相对）、`has_payload`。
2. **能力广告**（P-9）：`input_flags |= 0x0020`，并补 Demand Active 断言。
3. **接缝**（§1.3）：`InputSink` + `SetInputSink` + 真 `session_id`。
4. **纯翻译层 + 单测**（§4.1），Linux/Windows 双跑。
5. **Win32 后端 + 单工作线程队列 + 限流 + 计数 + `ReleaseSession`**。
6. **CLI/默认值/门禁**（§2.1/§2.2）：`--allow-input`、`--input-share`、`--input-owner`、
   `--allow-input-unverified`、启动行 `input=` 字段、拒绝启动矩阵。
7. **变异测试**（§4.4）逐条红/绿。

---

## 7. 与甲的收敛记录

（本节在 relay 往返后追加；当前状态：**已向甲发出对账请求（P-1…P-12 + D1…D6），尚未收到回执 → 未收敛**。）

---

## 附录 A：证据索引（本文件引用的每个仓库位置）

- `tools/rtsc_server/main.cpp`：15-55 usage；90 默认口令字面量；105 音频默认 off；295-298 退出码 2；
  300-312 配置装配；331-340 credential_lookup；342-350 音频 opt-in；352-366 剪贴板默认 on；
  368-391 启动日志 + accept-all 警告；393-395 同源桌面；421-448 authenticator 边界；453-463 仅日志回调。
- `include/rtsc/server/server.h`：57-59 协商几何；66-76 accept-all 与认证边界；142-159 几何上限；
  191-224 `InputEvent`/`InputCallback`（204 默认 kind、224 签名）；240/249-256 借用指针范式；
  264-266 Stop 语义；288-295 会话计数。
- `src/server/server.cpp`：438-439 能力广告；546-602 会话构造；1410-1412 刷新节拍；1415-1470 ActiveLoop；
  1479-1521 慢路径丢弃；1523-1531 fast-path 门；1534-1616 解码（1543 默认构造、1549-1550 E1 丢失、
  1571-1578 滚轮、1580-1596 按钮、1603-1610 吞事件、1611-1612 未知类型、1614 无条件回调）；
  1622-1623 成员；1755-1756 setter；1843/1962 会话构造传 0。
- `include/rtsc/proto/input.h`：19-31 flags；35-53 pointer flags；61-81 编码器；88-95 scancode；97-110 SAS/Pause。
- `src/proto/input.cpp`：90-102 Pause 序列。
- `src/client/client.cpp`：200-246 `EncodeInput`（231-238 旧滚轮编码）。
- `include/rtsc/proto/capabilities.h`：218-241 InputCapabilitySet。
- `include/rtsc/server/desktop_gdi.h`：27-42 捕获矩形/缩放。
- `docs/spec/share-data.md`：309 `0x1C`；652-683 事件表 + 未知类型；704-708 Pause；710-718 Unicode；
  720-745 指针 flags；770-783 SYNC；785-794 QoE；796-807 相对指针；809-833 尺寸/遍历不变量。
- `docs/spec/capabilities.md`：312 `0x1C`；1732-1748 inputFlags。
- `docs/spec/input-evidence.md`：45 `dwExtraInfo`；64 `SetCursorPos` 7 处；100-103 `VK_PACKET`；
  144/147 遗留 P3。
- `docs/spec/server-mode.md`：14 GDI 捕获；24-27 多会话；35 输入"完成"的**不实**声明；37 多会话压测；42 USB 未做。
- `tests/test_server.cpp`：602-640 只计数；642-707 释放只数个数（固化缺陷）；2017 另一回调用例。
- 官方文档：`SendInput`（nf-winuser-sendinput）、`KEYBDINPUT`（ns-winuser-keybdinput）、
  `MOUSEINPUT`（ns-winuser-mouseinput）、`SendSAS`（api/sas/nf-sas-sendsas）、
  [MS-RDPBCGR] Input Capability Set（b3bc76ae-…）、Processing Fast-Path Input Event PDU（178aef78-…）、
  Fast-Path Input Event（76c4dd59-…）、Slow-Path Input Event（a9a26b3d-…）。
