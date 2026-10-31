# 服务器侧 Win32 输入注入：语义证据与实现方案

- 状态：审计证据文档（甲）；**未改任何产品/测试代码**；本文件与 `evidence/input-inject-*` 之外无改动。
- 仓库基线：`git rev-parse --short HEAD` = **453fb94**；工作树为多代理共享未提交态（`git status --short` 显示
  `include/rtsc/server/server.h`、`src/client/client.cpp`、`src/server/server.cpp`、`tests/*` 等被在途修改）。
  **行号随在途改动漂移**；引用一律带符号名，漂移时按符号名复核。
- 目标缺口（父代理已取证）：服务器侧 Win32 注入 API 调用数 = 0（`[READ:.opencode/process.md:272-297]`）。

## 0. 复现方式（全部只读，不注入真实键鼠）

```
[BASH: evidence\input-inject-probe-build.bat]        # cl /W4 /WX，0 error 0 warning
[BASH: evidence\input-inject-mapping-probe.exe]      # 只调 MapVirtualKeyW/GetSystemMetrics/OpenInputDesktop
[BASH: evidence\input-inject-mapping-harness.exe]    # 纯函数映射断言（只构造 INPUT，不调 SendInput）
[BASH: evidence\input-inject-mapping-harness.exe --mutate=1..7]   # 变异测试，每个都必须转红
```

产物：`evidence/input-inject-mapping-probe.txt`（真实 API 读数）、
`evidence/input-inject-mapping-harness.txt`（**42 断言基线全绿 + 7 个变异体各自转红**）。

**两个程序都不含 `SendInput`/`keybd_event`/`mouse_event`/`SetCursorPos` 调用**（复核：
`Select-String -Pattern 'SendInput|keybd_event|mouse_event|SetCursorPos' evidence/input-inject-*.cpp` → 命中 0）。

探针实测环境（`evidence/input-inject-mapping-probe.txt` §3/§6）：

```
virtual screen: origin=(0,0) size=2048x1152 ; monitors=1
current process session id = 1 ; WTSGetActiveConsoleSessionId = 0x00000001
window station = WinSta0 ; thread desktop = Default ; input desktop = Default
```

---

## 1. SendInput 语义清单（官方原文 + 实测）

### 1.1 契约、返回值、失败路径

来源：<https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput>

| 项 | 原文 |
|---|---|
| 作用 | "Synthesizes keystrokes, mouse motions, and button clicks." |
| 返回值 | "The function returns the number of events that it successfully inserted into the keyboard or mouse input stream. **If the function returns zero, the input was already blocked by another thread.** To get extended error information, call `GetLastError`." |
| UIPI 不可检测 | "This function fails when it is blocked by UIPI. **Note that neither `GetLastError` nor the return value will indicate the failure was caused by UIPI blocking.**" |
| 完整性等级 | "Applications are permitted to inject input only into applications that are at an equal or lesser integrity level." |
| 原子性 | "inserts the events in the INPUT structures serially into the keyboard or mouse input stream. **These events are not interspersed with other keyboard or mouse input events inserted either by the user** ... or by ... other calls to `SendInput`." |
| 不清键盘状态 | "This function does not reset the keyboard's current state. Any keys that are already pressed when the function is called might interfere with the events that this function generates." |
| `cbSize` | "If cbSize is not the size of an INPUT structure, the function fails." |

**设计含义**：失败只能用「返回计数 < 请求计数」判定；UIPI 拒绝与成功**无法从返回值/`GetLastError` 区分**（§2.3）。

### 1.2 KEYBDINPUT 与四个 flag

来源：<https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-keybdinput>

| flag | 值 | 原文 |
|---|---|---|
| `KEYEVENTF_EXTENDEDKEY` | 0x0001 | "If specified, the **wScan scan code consists of a sequence of two bytes, where the first byte has a value of 0xE0**." |
| `KEYEVENTF_KEYUP` | 0x0002 | "If specified, the key is being released." |
| `KEYEVENTF_UNICODE` | 0x0004 | "the system synthesizes a VK_PACKET keystroke. **The wVk parameter must be zero.** This flag can only be combined with the KEYEVENTF_KEYUP flag." |
| `KEYEVENTF_SCANCODE` | 0x0008 | "If specified, **wScan identifies the key and wVk is ignored**." |

同页 Remarks："Set the KEYEVENTF_SCANCODE flag to define keyboard input in terms of the scan code ... The virtual key
value of a key can change depending on the current keyboard layout ..., but the scan code will always be the same."

### 1.3 扫描码来源：直接用 RDP `keyCode`，**不要** ±0x100

RDP 侧：fast-path 键盘事件 `keyCode` 是 1 字节，扩展键的 `0xE0` 前缀不是独立字节，由
`FASTPATH_INPUT_KBDFLAGS_EXTENDED` 表示——`[READ:include/rtsc/proto/input.h:84-95]`（"The RDP keyCode is the low byte
of the 8042 set-1 scancode. For the extended keys the 0xE0 prefix is NOT a separate byte: it is implied by
kKbdExtended"）。

Win32 侧：`KEYEVENTF_EXTENDEDKEY` 的语义**正是**「让 wScan 成为 0xE0 前缀的两字节序列」（§1.2 原文）。故：

```
wScan = ev.scancode                       // RDP keyCode 原样，不加 0x100
dwFlags |= KEYEVENTF_SCANCODE
dwFlags |= ev.extended ? KEYEVENTF_EXTENDEDKEY : 0
dwFlags |= ev.release ? KEYEVENTF_KEYUP : 0
```

实测交叉验证（`evidence/input-inject-mapping-probe.txt` §1/§2）：`MapVirtualKeyW(VK_RCONTROL, MAPVK_VK_TO_VSC_EX)`
= `0xE01D`、`VK_RMENU` = `0xE038`、`VK_LWIN` = `0xE05B`——**高字节 0xE0、低字节 = `MAPVK_VK_TO_VSC` 的低字节**；
反向 `MapVirtualKeyW(0xE01D, MAPVK_VSC_TO_VK_EX)` = `0xA3`(VK_RCONTROL)、`0x001D` = `0xA2`(VK_LCONTROL)。
即扩展位是**标志**，不是扫描码数值的一部分；`+0x100` 是 X11/evdev 约定，Win32 无此约定。

> 结论：**注入路径不需要 `MapVirtualKeyW`**（RDP 已给 set-1 扫描码）。只有「只有 VK、需要反查扫描码」的场景才需要。

### 1.4 扩展位 0xE0 / 0xE1（PAUSE 特例 / NumLock 官方样例）

来源：<https://learn.microsoft.com/en-us/windows/win32/inputdev/about-keyboard-input>

- "Extended-Key Flag"：扩展键集合 = 右侧 Alt/Ctrl；Insert/Delete/Home/End/PgUp/PgDn/方向键；Break(Ctrl+Pause)；
  Print Screen；小键盘 `/` 与 Enter；Windows/Application 键。
- "If specified, the scan code consists of a sequence of two bytes, where the first byte has a value of 0xE0."
- "Note that the Num Lock key has a separate scan code from the Pause key (which uses the same scan code **without** the
  extended-key flag)"；"The right-hand Shift key is not considered an extended key either; it has a separate scan code
  (0x36) instead."
- 该页 "Scan 1 Make" 表把扩展键写成 `0xE0xx` 两字节、PAUSE 写成 `0xE11D45`（E1 前缀）。

实测：`MapVirtualKeyW(VK_PAUSE, MAPVK_VK_TO_VSC_EX)` = `0xE11D`（探针 §1），`MAPVK_VK_TO_VSC` = 0。

**PAUSE 结论**：`KEYEVENTF_*` 只表达 0xE0，**无 0xE1 语义**，`MapVirtualKeyW` 也只回 `0xE11D`（丢 `0x45`）→
**PAUSE 不能用「单键+flag」注入**；只能展开为文档化的 Ctrl/NumLock 两键序列（仓库客户端侧已有 `EncodePauseKey`，
`[READ:include/rtsc/proto/input.h:106-110]`）。服务端当前**丢弃 E1 标志**（见 §3.2 G3），PAUSE 会退化成 NumLock 按下。

**NumLock 冲突（重要，官方样例 vs RDP 语义）**：`keybd_event` 官方页的 NumLock 样例是
`keybd_event(VK_NUMLOCK, 0x45, KEYEVENTF_EXTENDEDKEY, 0)`（来源：
<https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-keybd_event>）——即 **NumLock 注入带扩展位**；
而 RDP 的 NumLock 是 `keyCode 0x45, extended=false`（`[READ:include/rtsc/proto/input.h:91]` "shares the NumLock
scancode"）。两者冲突 → 需要**真机定论**（§6 U5），必要时加 quirk 表 `{0x45, extended=false} → 注入时带 EXTENDEDKEY`。
注意 `MapVirtualKeyW(0xE045, MAPVK_VSC_TO_VK_EX)` 实测 = `0x00`（探针 §2），与「NumLock 必须带扩展位」的说法**不一致**，
故此项**不得**在无真机证据前写进定案。

### 1.5 鼠标：绝对坐标归一化 / VIRTUALDESK / 多显示器

来源：<https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-mouseinput>

| flag | 值 | 原文 |
|---|---|---|
| `MOUSEEVENTF_MOVE` | 0x0001 | "Movement occurred." |
| `MOUSEEVENTF_ABSOLUTE` | 0x8000 | "dx and dy members contain normalized absolute coordinates." |
| `MOUSEEVENTF_VIRTUALDESK` | 0x4000 | "Maps coordinates to the entire desktop. **Must be used with MOUSEEVENTF_ABSOLUTE.**" |
| `MOUSEEVENTF_MOVE_NOCOALESCE` | 0x2000 | "The WM_MOUSEMOVE messages will not be coalesced." |

归一化原文："dx and dy contain **normalized absolute coordinates between 0 and 65,535**. ... coordinate (0,0) maps onto
the upper-left corner of the display surface; coordinate (65535,65535) maps onto the lower-right corner. **In a
multimonitor system, the coordinates map to the primary monitor.** If MOUSEEVENTF_VIRTUALDESK is specified, the
coordinates map to the entire virtual desktop."

相对移动的坑："Relative mouse motion is subject to the effects of the mouse speed and the two-mouse threshold values ...
it is thus possible for the system to multiply specified relative mouse movement ... by up to four times." → **注入必须用
绝对坐标**。

投影公式（§4.3 落地）：

```
phys  = capture.left + round(ev.x * capture.width  / negotiated.width)
norm  = round((phys - virtual.left) * 65535 / (virtual.width - 1))
dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
```

实测（探针 §4，2048x1152 原点 (0,0)）：`(0,0)→(0,0)`、`(w-1,h-1)→(65535,65535)`、往返误差 0 px。
分母用 `extent-1` 还是 `extent` 官方未规定 → §6 U2（变异体 M3 证明断言对该选择敏感）。

抓取侧坐标必须与注入侧同源：`[READ:include/rtsc/server/desktop_gdi.h:44-58]`、
`[READ:src/server/desktop_gdi.cpp:79-141]`（`EnumDisplayMonitors`/`GetMonitorInfo` 取 `rcMonitor`；虚拟桌面用
`SM_XVIRTUALSCREEN/SM_YVIRTUALSCREEN/SM_CXVIRTUALSCREEN/SM_CYVIRTUALSCREEN`）、
`[READ:src/server/desktop_gdi.cpp:200-208]`（同尺寸 BitBlt，否则 StretchBlt 缩放到谈判几何）。

### 1.6 滚轮：单位 WHEEL_DELTA(120) 与符号

- `MOUSEEVENTF_WHEEL` 0x0800；`MOUSEEVENTF_HWHEEL` 0x1000（Vista+）。
- 垂直："A **positive value indicates ... forward, away from the user**; a negative value ... backward, toward the user.
  **One wheel click is defined as WHEEL_DELTA, which is 120.**"
- 水平："a **positive value indicates ... to the right**; a negative value ... to the left."
- 约束："**You cannot specify both the MOUSEEVENTF_WHEEL flag and either MOUSEEVENTF_XDOWN or MOUSEEVENTF_XUP flags
  simultaneously**, because they both require use of the mouseData field."

RDP 侧（<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2c1ced34-340a-46cd-be6e-fc8cab7c3b17>）：
`PTRFLAGS_WHEEL_NEGATIVE` 0x0100 "is negative and **MUST be sign-extended before injection at the server**"；
`WheelRotationMask` 0x01FF = "number of **rotation units**"；`PTRFLAGS_HWHEEL` 0x0400 横向；两 flag 同给时 WHEEL 优先。

**单位裁决（与乙 P-2 对齐）**：RDP rotation 字段与 Win32 同刻度（120/notch）；仓库 seam 已把值定义为
「wire units: WHEEL_DELTA (120) per notch」（`[READ:include/rtsc/server/server.h:217]`，在途改动）→
**注入侧直接搬运 `mouseData = wheel_delta`，绝不再乘 120**。若 seam 单位哪天改成 notch，则必须乘 120；两处必须
`static_assert`/单测锁死（harness A9 即锁：`+1 notch → mouseData==120`）。

实测（探针 §5）：`+1 → 120 (0x78)`、`-1 → -120 (0xFFFFFF88)`、`±255 → ±30600`。
`mouseData` 是 DWORD，**负值必须二补码写入**（`(DWORD)(int)v`），Win32 无「负方向 flag」（与 RDP 的
`PTRFLAGS_WHEEL_NEGATIVE` 不同构）。

### 1.7 按钮映射（RDP 1..5 → MOUSEEVENTF_*）

| flag | 值 |  | flag | 值 |
|---|---|---|---|---|
| `LEFTDOWN`/`LEFTUP` | 0x0002/0x0004 |  | `XDOWN`/`XUP` | 0x0080/0x0100 |
| `RIGHTDOWN`/`RIGHTUP` | 0x0008/0x0010 |  | `XBUTTON1`/`XBUTTON2` | 0x0001/0x0002（写 `mouseData`） |
| `MIDDLEDOWN`/`MIDDLEUP` | 0x0020/0x0040 |  | | |

原文："If dwFlags contains MOUSEEVENTF_XDOWN or MOUSEEVENTF_XUP, then mouseData specifies which X buttons were pressed
or released."；"The bit flags ... indicate **changes in status, not ongoing conditions**."

RDP 侧：`PTRFLAGS_DOWN` 0x8000；`PTRFLAGS_BUTTON1/2/3` = 0x1000/0x2000/0x4000，原文 "**If the PTRFLAGS_DOWN flag is
set, then the button was pressed, otherwise it was released**"；扩展按钮在 `TS_POINTERX_EVENT`
（<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2ef7632f-2f2a-4de7-ab58-2585cedcdf48>）
`PTRXFLAGS_BUTTON1/2` = 0x0001/0x0002 = 按钮 4/5。

映射：`1→LEFT`、`2→RIGHT`、`3→MIDDLE`、`4→X+XBUTTON1`、`5→X+XBUTTON2`；`button_down` 选 DOWN/UP。
**UP 事件也必须知道按钮身份**（原文：按钮位在 release 事件里同样存在）→ §3.2 G4。

---

## 2. 注入目标与安全边界

### 2.1 线程所在桌面 = 注入目标；`OpenInputDesktop`/`SetThreadDesktop`

- 桌面语义（<https://learn.microsoft.com/en-us/windows/win32/winstation/desktops>）："only one of these desktops at a
  time is active. This active desktop, also known as the **input desktop**, is the one ... that receives user input."；
  "By default, there are three desktops in the interactive window station: Default, ScreenSaver, and Winlogon."；
  "the system switches to the Winlogon desktop when the user presses the CTRL+ALT+DEL key sequence, or when the UAC
  dialog box is open."；"The Winlogon desktop's security descriptor allows access to a very restricted set of accounts
  ... Applications generally do not carry any of these accounts' SIDs ... therefore **cannot access the Winlogon
  desktop**."
- 线程桌面归属（<https://learn.microsoft.com/en-us/windows/win32/winstation/thread-connection-to-a-desktop>）："If the
  thread has called the SetThreadDesktop function, it connects to the specified desktop. If ... not ..., it connects to
  the desktop **inherited from the parent process**."
- `OpenInputDesktop`："Opens the desktop that receives user input."；"The window station associated with the calling
  process must be **capable of receiving input**."；断开会话返回「恢复时激活」的桌面；失败返回 NULL + `GetLastError`。
- `SetThreadDesktop`："Assigns the specified desktop to the calling thread."；"This desktop must be associated with the
  current window station."；"**will fail if the calling thread has any windows or hooks on its current desktop**".
- **最直接官方依据**（`SetCursorPos`，<https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setcursorpos>）：
  "**The input desktop must be the current desktop when you call SetCursorPos.** Call OpenInputDesktop ... If it is not,
  call SetThreadDesktop with the HDESK returned by OpenInputDesktop to switch to that desktop."
  → 同族 USER32 输入 API 都要求线程连到 input desktop；`SendInput` 页未单列此句 → §6 U1。

**实测（探针 §6）**：`thread desktop = Default`、`input desktop = Default`，但两**句柄不相等** →
**判定必须比较桌面名（`GetUserObjectInformation(UOI_NAME)`），不能比较句柄**。

### 2.2 Session 0 隔离

- <https://learn.microsoft.com/en-us/windows/win32/services/interactive-services>："**Services cannot directly
  interact with a user as of Windows Vista.**"；"**All services run in Terminal Services session 0.**"；"By default,
  services use a noninteractive window station and cannot interact with the user."
- <https://learn.microsoft.com/en-us/windows/win32/winstation/window-station-and-desktop-creation>：无
  `SERVICE_INTERACTIVE_PROCESS` 的服务用 `Service-0x0-3e7$\default`，"**This window station is not interactive**"。

**结论**：以服务方式启动的 `rtsc_server` 在非交互 winsta，拿不到交互桌面（`desktop_gdi.cpp` 同类失败分支
`[READ:src/server/desktop_gdi.cpp:111-114]`）。**部署前提：运行于目标用户交互会话**（登录计划任务 / Run 键 /
手动启动）。探针实测本机 session id = 1（交互），符合前提。

### 2.3 UIPI：低完整性不能注入高完整性窗口，且失败不可检测

- §1.1 原文两条（只能注入等/低完整性；失败不体现在返回值/`GetLastError`）。
- `ChangeWindowMessageFilterEx`（<https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-changewindowmessagefilterex>）：
  "Modifies the User Interface Privilege Isolation (UIPI) **message filter** for a specified window."；MSGFLT_ALLOW 让
  消息「regardless of the source ... even it comes from a lower privileged process」。
- **结论**：该 API 只放宽**窗口消息**投递，**没有任何机制可放宽 `SendInput` 的完整性检查**；普通用户（medium IL）
  的 `rtsc_server` 无法向提升窗口注入，且**无法检测**。属产品级限制。（阴性论断 → §6 U7）

### 2.4 Ctrl+Alt+Del：`SendInput` 不能合成，需 `SendSAS` 且需策略/服务权限

来源：<https://learn.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas>

- "must either be **running as a service** or have the **uiAccess attribute** ... set to "true""；非服务时须"running as
  either the current user or the LocalSystem account"，且"**UAC must be turned on**"。
- "Applications with the uiAccess attribute set to "true" **must be signed by using Authenticode**" + 必须位于
  "**\Program Files\**" 或 "**\windows\system32\**"。
- 本机策略须放行：**Computer Configuration | Administrative Templates | Windows Components | Windows Logon Options |
  Disable or enable software Secure Attention Sequence**。
- 服务可模拟令牌，"simulates a SAS **on the session associated with the impersonated token**"。

**结论**：`SendInput` 合成 SAS **不可能**（SAS 由 Winlogon 桌面处理，普通进程无权访问，§2.1）。要支持需满足
「签名 + uiAccess + 受保护安装目录 + 组策略放行」或「服务 + 令牌模拟」，与当前形态冲突。注入侧应**显式返回不支持**，
不得静默丢弃（仓库已标为 product requirement：`[READ:include/rtsc/proto/input.h:97-104]`）。

### 2.5 多会话共享同一物理桌面（本仓 8 会话并发）

- `[READ:.opencode/plan.md:492]` "服务器模式：**8 会话并发压力测试通过**（`server_multisession` 7 tests/184 checks）"；
  `[READ:.opencode/process.md:217]` "8 会话并发（已通过）在无输入时只是 8 个只读镜像"。
- 同型共享语义先例：`[READ:include/rtsc/server/server.h:249-256]` 剪贴板 "shared-desktop / last-writer-wins"。
- 注入目标只有一个：本进程所在会话的**唯一物理桌面**（§2.1）。

**结论（硬限制）**：8 会话是**同进程、同会话、同桌面**的 8 个线程 → 共享同一个光标与键盘焦点：
光标 last-writer-wins；按键进当前前台窗口；客户端 A 按住、B 点击会造成粘键/粘按钮。

**必须的两条防护**：① 按会话跟踪按下状态，`ReleaseSession` 补发所有 UP（§4.6）；② 文档化共享语义，且
`enable_desktop_input=true` 时默认 `max_input_sessions = 1`，启动打印 WARNING。

### 2.6 安全桌面（UAC/锁屏/屏保）期间注入会失败

§2.1：UAC/CTRL+ALT+DEL → Winlogon 桌面；屏保 → ScreenSaver 桌面；普通进程无权访问 Winlogon。
`OpenInputDesktop` 在断开会话上返回「恢复时激活」的桌面。
**结论**：注入前/失败后重新 `OpenInputDesktop` 并比对名字；非本线程桌面时**跳过 + 计数**，不得报错刷屏。

---

## 3. 与仓库既有接缝的对接（现状审计）

### 3.1 现状

| 事实 | 证据 |
|---|---|
| `InputEvent` 字段：kind/scancode/unicode_code/release/extended/x/y/button/button_down/wheel_delta/horizontal/sync_flags | `[READ:include/rtsc/server/server.h:195-224]` |
| `InputCallback = std::function<void(const InputEvent&)>`，**无会话身份** | `[READ:include/rtsc/server/server.h:226-227]` |
| 回调契约：跑在会话线程，"must not block the session for long" | `[READ:include/rtsc/server/server.h:191-194]` |
| `SetInputCallback` 是**服务器级**（所有会话共用一个回调） | `[READ:include/rtsc/server/server.h:250]`、`[READ:src/server/server.cpp:1755-1756]` |
| 会话构造传 `session_id = 0`（所有会话同 id） | `[READ:src/server/server.cpp:1968-1969]`、`[READ:src/server/server.cpp:558]` |
| 生产端唯一调用只写日志 | `[READ:tools/rtsc_server/main.cpp:450-463]` |
| 服务端 Win32 注入 API 调用 = 0 | `[BASH: Select-String -Path src,include,tools -Include *.cpp,*.h -Pattern 'SendInput\|keybd_event\|mouse_event\|SetCursorPos\|OpenInputDesktop\|SetThreadDesktop\|SendSAS']` → 仅 4 处客户端/GUI：`src/client/client.cpp:267`、`include/rtsc/client/client.h:95`、`tools/rtsc_gui/main.cpp:1186/1190` |
| 每会话谈判几何 `desktop_width_/desktop_height_` | `[READ:src/server/server.cpp:1090-1094,1650-1651]` |
| 能力集用默认 `InputCapabilitySet`（0x0117，缺 0x0008/0x0020） | `[READ:src/server/server.cpp:438-439]`、`[READ:include/rtsc/proto/capabilities.h:221-234]` |
| 慢路径 PDU 只处理 RefreshRect/SuppressOutput | `[READ:src/server/server.cpp:1479-1521]` |

### 3.2 缺口清单（注入前必须补；G2/G9/G10 为与乙对账后补入）

| # | 缺口 | 证据 | 影响 |
|---|---|---|---|
| **G1** | `horizontal` 已声明但**解析器从不赋值**，`kPtrHwheel`(0x0400) 无分支 | `[READ:include/rtsc/server/server.h:218-220]` vs `[READ:src/server/server.cpp:1571]` | 横向滚轮被当成「无按钮 kMouse」→ 若注入器把无按钮 kMouse 当移动，光标**跳到陈旧坐标**；而能力集**已广告 HWHEEL**（`[READ:include/rtsc/proto/capabilities.h:221-234]`）→ 合法客户端必然触发 |
| **G2** | `kMouseRel` **不是**被丢弃，而是 `break` 后**仍触发回调**，`ev` 是默认构造 → `kind=kKey, scancode=0` **幻影按键** | `[READ:src/server/server.cpp:1543]`（默认构造）、`[READ:src/server/server.cpp:1610-1613]`、`[READ:src/server/server.cpp:1621]` | 注入 scancode 0 的 key-down（无效键且永不释放）；同一路径也命中 `kQoeTimestamp`（1614-1617） |
| **G3** | E1 标志（PAUSE）未传播 | `[READ:src/server/server.cpp:1549-1550]`（只读 release/extended） | PAUSE 退化为 NumLock 按下（§1.4） |
| **G4** | release 事件丢失按钮身份：`ev.button` 只在 `kPtrDown` 分支内赋值 | `[READ:src/server/server.cpp:1580-1596]` | 无法生成 `LEFTUP/...` → **按钮永久按下** |
| **G5** | 回调无会话身份、`session_id` 恒 0 | `[READ:include/rtsc/server/server.h:226-227]`、`[READ:src/server/server.cpp:1969,558]` | 无法按会话跟踪按下状态/断线清理（§2.5 必需） |
| **G6** | 回调不携带该会话谈判几何 | `InputEvent` 无 width/height | 绝对坐标无法换算（§1.5） |
| **G7** | `kSync` 无 Win32 等价物 | `[READ:include/rtsc/server/server.h:222-223]` | 盲注入按键会**反向**翻转 toggle 状态 |
| **G8** | 无 move 位：纯 `PTRFLAGS_MOVE` 与 button-up 都解成 `button=0,button_down=false` | `[READ:src/server/server.cpp:1580-1596]` | 无法区分「移动」与「释放」（见 G4/P-5） |
| **G9** | 能力集未广告 `INPUT_FLAG_FASTPATH_INPUT 0x0008` / `FASTPATH_INPUT2 0x0020`，却只实现 fast-path | `[READ:src/server/server.cpp:438-439]`、`[READ:include/rtsc/proto/capabilities.h:221-234]` | 真实 mstsc 可能退回慢路径 → 触发 G10（UNVERIFIED，§6 U10） |
| **G10** | 慢路径输入（`pduType2 = 0x1C`）被静默丢弃 | `[READ:src/server/server.cpp:1479-1521]`（仅两种 pduType2，其余 `return true`） | 走慢路径的客户端**一个输入事件都到不了**回调 |

### 3.3 接缝改动（最小侵入，采纳乙的 `InputSink` 形态）

保留 `SetInputCallback`（日志/遥测/既有测试不动：`tests/test_server.cpp:615/655/2017`、`tests/test_gui_send.cpp:200`），
**新增**带会话身份的注入接缝：

```cpp
// include/rtsc/server/server.h（新增；既有 InputEvent/InputCallback 不改）
class InputSink {                      // 平台中立；Linux/测试可替身
 public:
    virtual ~InputSink() = default;
    // 每事件一次：只入队，绝不阻塞会话线程。false = 丢弃（队列满/不支持）。
    virtual bool Inject(uint32_t session_id, const InputEvent& ev) = 0;
    // 会话 active 时调用；重协商（Desktop Size）时再次调用覆盖。幂等。
    virtual void SetGeometry(uint32_t session_id, uint16_t width, uint16_t height) = 0;
    // 会话结束/断线：补发该会话所有未释放的 key-up / button-up。
    virtual void ReleaseSession(uint32_t session_id) = 0;
};
void RdpServer::SetInputSink(InputSink* sink);   // 借用指针，nullptr = 关闭（默认）
```

`ServerConfig` 新增（**默认 false**，动态可配）：

```cpp
bool enable_desktop_input = false;   // 默认关闭：默认配置零行为变化
uint32_t max_input_sessions = 1;     // 0 = 不限制（不推荐，§2.5）
```

动态渠道：`ServerConfig` 字段 + CLI `--enable-input` + 环境变量 `RTSC_SERVER_ENABLE_DESKTOP_INPUT=1`
（CLI > env > 默认）；运行时 `SetInputSink(nullptr)` 关闭。
会话 id：accept 处用 `total_session_count` 分配单调 id（`[READ:src/server/server.cpp:1949]`），**只给注入用**，
不改 `share_id_`（`[READ:src/server/server.cpp:1235]`）。

---

## 4. 实现方案（文件级）

### 4.1 新增文件

| 文件 | 内容 |
|---|---|
| `include/rtsc/server/desktop_input.h` | `InputSink` 的 Win32 工厂 + `Options`；只导出工厂，不泄漏 Win32 类型（同 `desktop_gdi.h:14-21` 风格） |
| `src/server/desktop_input_win32.cpp` | 映射纯函数 + 注入线程 + 桌面/几何/卡键管理 |
| `src/server/desktop_input_null.cpp` | 非 Windows 空实现（`Inject` 返回 false，`Status()` 说明不支持） |
| `tests/test_desktop_input.cpp` | 纯函数断言（不调 `SendInput`），见 §5.1 |
| `evidence/input-inject-mapping-harness.cpp` | 已存在：设计期断言 + 变异体（§5.2） |

CMake（照抄 `desktop_gdi` 模式 `[READ:CMakeLists.txt:659-667]`）：新增 `rtsc_server_input_win32`（链 `user32`）、
`rtsc_desktop_input_tests` + `add_test(NAME desktop_input ...)`；`rtsc_server_host` 链该库（同
`[READ:CMakeLists.txt:673-677]`），并加 `/W4 /WX`（同 `[READ:CMakeLists.txt:844-847]`）。

### 4.2 纯函数映射

```cpp
struct InjectTarget {                 // 与 desktop_gdi 的 CaptureRect 同源
    int left, top, width, height;     // 抓取矩形（虚拟屏坐标）
    int vleft, vtop, vwidth, vheight; // 虚拟桌面矩形
};
// 只构造 INPUT；不调任何注入 API。失败给 reason（PAUSE/E1、未知按钮、scancode 0）。
bool BuildInputs(const InputEvent& ev, uint16_t negotiated_w, uint16_t negotiated_h,
                 const InjectTarget& t, std::vector<INPUT>& out, std::string& reason);
```

### 4.3 映射规则（逐 kind）

| kind | 输出 |
|---|---|
| `kKey` | 1 个 `INPUT_KEYBOARD`：`wVk=0`，`wScan=scancode`，`dwFlags=SCANCODE\|(extended?EXTENDEDKEY:0)\|(release?KEYUP:0)`，`dwExtraInfo=kRtscInjectTag`。**不加 0x100**；`scancode==0` **拒绝**（防 G2 幻影） |
| `kUnicode` | `wVk=0`，`wScan=unicode_code`，`dwFlags=UNICODE\|(release?KEYUP:0)`；非 BMP 由调用方拆代理对 |
| `kMouse` | 1~2 个 `INPUT_MOUSE`：先 `MOVE\|ABSOLUTE\|VIRTUALDESK`（归一化），再（若有 button）`*DOWN/*UP \| ABSOLUTE \| VIRTUALDESK`，X 按钮 `mouseData=XBUTTON1/2`；**同一次 SendInput 调用**（原子，§1.1） |
| `kWheel` | 1 个 `INPUT_MOUSE`：`dx=dy=0`，`mouseData=(DWORD)(int)wheel_delta`，`dwFlags = horizontal ? HWHEEL : WHEEL`；**绝不与 XDOWN/XUP 合并**（§1.6） |
| `kSync` | 空数组（no-op）+ 计数（§3.2 G7） |
| `kMouseRel`（若补 G2 后再支持） | `MOUSEEVENTF_MOVE` 相对；受鼠标加速影响（§1.5）→ v1 不注入 |
| E1/PAUSE | 返回 false + reason；可选增强：展开 Ctrl/NumLock 4 事件 |

### 4.4 线程模型

- 契约不允许占用会话线程（`[READ:include/rtsc/server/server.h:191-194]`）；`SendInput` 在安全桌面切换/输入队列
  拥塞时可能长时间不返回（§2.6）；8 会话共享桌面需串行化 + 会话归属（§2.5）。
- **进程内单个注入线程**（非每会话一个）：有界队列（容量 **256**，见 §8 (e)）+ 每会话 `PressedState`；
  `Inject()` 只加锁入队（微秒级），满则丢弃并计数（**优先丢 move，绝不丢 up**）；
  循环：出队 → `EnsureInputDesktop()` → `BuildInputs()` → 一次 `SendInput` → 校验 `sent != n`。
- 单线程的理由：系统只保证**单次调用内**不被插入（§1.1），跨线程的「移动+按下」仍可能交错。

### 4.5 失败路径

```cpp
const UINT sent = ::SendInput((UINT)inputs.size(), inputs.data(), sizeof(INPUT));
if (sent != inputs.size()) {
    const DWORD err = ::GetLastError();      // UIPI 拒绝时可能仍 sent==n，不可检测（§1.1）
    ++stats_.failed;
    if (err == ERROR_ACCESS_DENIED) ++stats_.access_denied;
    // 连续失败 N 次（默认 5）→ degraded，只打印一次，避免 8 会话刷屏
}
```

`EnsureInputDesktop()` 失败（锁屏/UAC/session 0）→ 丢弃 + 计数，恢复后自动继续；
`BuildInputs()` 失败 → 计数 + 同 reason 只打一次日志；`Status()` 暴露
`{injected, dropped, failed, access_denied, desktop, degraded}`。

### 4.6 卡键/粘键清理

`SetGeometry` 建槽；down 记入集合，up 移除；`ReleaseSession(id)` 对集合内每项补发 UP（键盘同 scancode+extended；
鼠标用最后坐标 + 对应 `*UP`），一次 `SendInput` 数组发出。注入线程析构时对所有会话执行同样清理。

### 4.7 安全/默认值

`enable_desktop_input` 默认 false（与 `enable_rdpdr_handshake`/`enable_rdpsnd` 的既有约定一致，
`[READ:include/rtsc/server/server.h:117-132]`）；开启时 `Start()` 打 WARNING（已认证客户端获得完整桌面控制权 +
多会话共享桌面），同 `WarnIfAcceptAll()`（`[READ:src/server/server.cpp:1958]`）风格；不落盘、不记录按键内容。

---

## 5. 测试计划

### 5.1 纯函数层（不碰真实桌面）

`tests/test_desktop_input.cpp` 断言 `BuildInputs` 的 INPUT 数组字段（A1–A12，同 harness）：

| 断言 | 期望 |
|---|---|
| A1 `'A'` down（0x1E） | 1 个 KEYBOARD；`wVk==0`；`wScan==0x1E`；`dwFlags==SCANCODE` |
| A2 右 Ctrl down（0x1D, extended） | `wScan==0x1D`；含 `EXTENDEDKEY`；**无 0x100 偏置** |
| A3 右 Ctrl up | `SCANCODE\|EXTENDEDKEY\|KEYUP` |
| A4 unicode U+6F22 | `wVk==0`；`wScan==0x6F22`；`KEYEVENTF_UNICODE` |
| A5 端点 | `(0,0)→(0,0)`；`(w-1,h-1)→(65535,65535)`；恒含 `ABSOLUTE\|VIRTUALDESK` |
| A5b 往返 | 采样点像素误差 ≤1 |
| A6 左键点击 (100,50) | 2 个 INPUT：先 MOVE 后 LEFTDOWN，同数组 |
| A7 右键 up | `RIGHTUP` |
| A8 X1/X2 down | `XDOWN` + `mouseData==XBUTTON1/XBUTTON2` |
| A9 滚轮 ±1 notch | `mouseData==120 / (DWORD)-120`；`WHEEL`；水平 `HWHEEL` 同号 |
| A10 kSync | 空数组 |
| A11 E1/PAUSE | false + reason |
| A12 scancode 0 | false + reason（防 G2 幻影） |
| A13 清理 | `ReleaseSession` 补发的 UP 与 down 一一对应 |

### 5.2 变异测试（第 16 条，已实测）

`--mutate=N` 逐个破坏关键判定，**每个变异体都必须转红**（`evidence/input-inject-mapping-harness.txt`）：

| 变异 | 破坏点 | 结果 |
|---|---|---|
| M1 | 丢弃 `KEYEVENTF_EXTENDEDKEY` | FAIL A2, A3 |
| M2 | 滚轮符号取反 | FAIL A9 ×3 |
| M3 | 归一化分母用 `extent` 而非 `extent-1` | FAIL A5 角点 |
| M4 | 丢弃 `KEYEVENTF_KEYUP` | FAIL A3 |
| M5 | X1 写成 `XBUTTON2` | FAIL A8 |
| M6 | 去掉 `ABSOLUTE\|VIRTUALDESK` | FAIL A5, A6 |
| M7 | 放过 scancode 0 | FAIL A12 |

基线：`42 checks, 0 failure(s)`；7 个变异体全部 exit=1 → 断言表对每个关键判定敏感（非假测试）。

### 5.3 集成层（不注入真实桌面）

用替身 `InputSink` 挂 `SetInputSink`，跑既有 `DriveToActive(..., send_input=true)`（`[READ:tests/test_server.cpp:611-628]`），
断言：事件到达替身、`SetGeometry/Inject/ReleaseSession` 顺序、断线触发 UP 补发。

### 5.4 必须真机验证

见 §6（U1–U10）。

---

## 6. UNVERIFIED 清单（汇总，禁止当结论用）

| # | 未验证项 | 建议验证方式 |
|---|---|---|
| U1 | `SendInput` 是否要求线程连到 input desktop（官方只在 `SetCursorPos` 明写） | 锁屏后调用，看返回值/`GetLastError` |
| U2 | 归一化分母 `extent-1` vs `extent` 与系统取整 | 注入端点后读 `GetCursorPos` |
| U3 | UIPI 静默失败（`sent==n` 但无效果） | 向以管理员运行的窗口注入 |
| U4 | 多显示器负坐标 + 每屏 DPI 的往返误差 | 双屏负原点布局 |
| U5 | NumLock/Pause 注入的扩展位要求（官方样例与 `MapVirtualKeyW(0xE045)`=0 矛盾） | 注入 0x45（带/不带扩展位）观察 toggle |
| U6 | `SCANCODE` + 右 Ctrl 是否被识别为 `VK_RCONTROL` | 注入后读 `GetAsyncKeyState(VK_RCONTROL)` |
| U7 | `ChangeWindowMessageFilterEx` 对注入无作用（阴性论断） | 对 high-IL 窗口先调该 API 再注入 |
| U8 | 8 会话共享桌面下「移动+点击」是否被其他会话插入 | 两客户端并发点击观察落点 |
| U9 | 探针环境为单屏 2048x1152、session 1 | 目标机重跑探针 |
| U10 | 真实 mstsc 是否因缺 `0x0020`/`0x0008` 改发慢路径 | 抓包 pduType2=0x1C 是否出现 |

---

## 7. 参考（全部为本文引用来源）

1. SendInput — <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput>
2. KEYBDINPUT — <https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-keybdinput>
3. MOUSEINPUT — <https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-mouseinput>
4. Keyboard Input Overview（Extended-Key Flag / Scan 1 Make 表）— <https://learn.microsoft.com/en-us/windows/win32/inputdev/about-keyboard-input>
5. MapVirtualKeyW — <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-mapvirtualkeyw>
6. keybd_event（**superseded** + NumLock 样例）— <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-keybd_event>
7. OpenInputDesktop — <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-openinputdesktop>
8. SetThreadDesktop — <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setthreaddesktop>
9. SetCursorPos（input desktop 要求）— <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setcursorpos>
10. Desktops（input desktop / Winlogon 桌面）— <https://learn.microsoft.com/en-us/windows/win32/winstation/desktops>
11. Thread Connection to a Desktop — <https://learn.microsoft.com/en-us/windows/win32/winstation/thread-connection-to-a-desktop>
12. Window Station and Desktop Creation — <https://learn.microsoft.com/en-us/windows/win32/winstation/window-station-and-desktop-creation>
13. Interactive Services（services 不能直接交互；服务都在 session 0）— <https://learn.microsoft.com/en-us/windows/win32/services/interactive-services>
14. ChangeWindowMessageFilterEx — <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-changewindowmessagefilterex>
15. SendSAS — <https://learn.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas>
16. [MS-RDPBCGR] TS_POINTER_EVENT — <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2c1ced34-340a-46cd-be6e-fc8cab7c3b17>
17. [MS-RDPBCGR] TS_FP_POINTER_EVENT — <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/16a96ded-b3d3-4468-b993-9c7a51297510>
18. [MS-RDPBCGR] TS_POINTERX_EVENT — <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2ef7632f-2f2a-4de7-ab58-2585cedcdf48>
19. [MS-RDPBCGR] TS_RELPOINTER_EVENT — <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9af47964-8bfc-4f43-8a15-4339a89833fa>
20. GetTokenInformation（TokenIntegrityLevel，§8 完整性预检）— <https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation>

仓库证据：`include/rtsc/server/server.h:191-256,307`、`include/rtsc/proto/input.h:18-23,84-110`、
`include/rtsc/proto/capabilities.h:219-243`、`include/rtsc/server/desktop_gdi.h:14-58`、
`src/server/server.cpp:438-439,548-558,1090-1094,1479-1521,1534-1623,1650-1651,1755-1756,1949,1968-1969`、
`src/server/desktop_gdi.cpp:6-21,44-141,200-208,246-273`、`src/client/client.cpp:193-246`、
`tools/rtsc_server/main.cpp:450-463`、`CMakeLists.txt:595-611,659-677,844-847`、
`docs/spec/server-mode.md:37`、`.opencode/plan.md:492,563-566`、`.opencode/process.md:217,272-297`。

自产证据：`evidence/input-inject-mapping-probe.cpp/.txt/.exe`、`evidence/input-inject-mapping-harness.cpp/.txt/.exe`、
`evidence/input-inject-probe-build.bat`。

---

## 8. 对账答复（与审计乙 ses_e6db6db1dffeJJge2MFgISFFyj 收敛记录）

> 行号说明：`src/server/server.cpp` 在本轮被在途修改，`input_callback_` 调用点由 1614 漂移到 **1621**；
> 本文 §3.2 G2 引用的是漂移后行号（1610-1613 + 1621）。以符号 `ParseInputEvents` 为准。

### 8.1 对乙 P-1..P-12 的裁定

| 编号 | 裁定 | 依据 / 补充 |
|---|---|---|
| P-1 Hwheel 未解码 | **对** | 与本文 G1 同一缺陷；补充更强证据：`horizontal` **已声明但从未赋值**（`server.h:218-220` vs `server.cpp:1571`），是「声明与实现不一致」，比「未解码」更易误导实现者 |
| P-2 滚轮双重取负 | **对**（注入侧不乘 120） | `server.cpp:1571-1578`：`rot=(pf&0x01FF)` → `(int16)rot` → 再按 0x0100 取负；`-1 notch`(0x03FF) 得 -511。注入侧 `mouseData = wheel_delta` 恒等搬运（§1.6），**不乘 120**——与乙一致；前提是 seam 单位=120/notch（`server.h:217`），harness A9 锁死该契约 |
| P-3 `kMouseRel` 被吞 | **对，但需修正机制** | 见 P-4：不是「丢弃」，而是**发出幻影 kKey**。v1 不注入相对移动的裁决**同意**（`MOUSEINPUT` 加速 1~4 倍原文，§1.5） |
| P-4 幻影 `kKey` | **对，我漏了，采纳** | 行号链：`server.cpp:1543`（`InputEvent ev;` 默认 `kind=kKey, scancode=0`）→ `1610-1613`（`kMouseRel` 仅 `pos+=6` 后 `break`）→ `1614-1617`（`kQoeTimestamp` 同）→ `1621` 无条件 `input_callback_(ev)`。**修复点裁决：在 1621 前加「本事件是否产出 payload」判定**（新增 `bool has_payload` 或让两分支 `continue`），**不改 `default:`**——`default` 是「未知 eventCode → 终止解析」，语义不同（P-11） |
| P-5 测试固化缺陷 | **对** | `tests/test_server.cpp:695-703` 只累加 `nondown_mouse >= 2`，注释自承"the two X releases arrive as plain mouse ups"；未断言释放事件的 `button` 身份 → 把 G4 固化成预期。修法：断言语义改为「release 事件 `button` 与 down 相同」 |
| P-6 E1/Pause | **对**，另加官方证据 | `keybd_event` 官方页 NumLock 样例用 `KEYEVENTF_EXTENDEDKEY`，与 RDP NumLock（extended=false）冲突 → 升级为 §6 U5 真机项；v1 不注入并计数 |
| P-7 kSync | **对，但 v1 裁决更保守** | 本文 G7：v1 **no-op + 计数**；「`GetKeyState` 不等才按一次」会翻转物理 toggle 且 8 会话共享，列为 v2 + UNVERIFIED |
| P-8 kUnicode | **对** | `wVk` 必须 0；`UNICODE` 只能与 `KEYUP` 组合；代理对不折叠 |
| P-9 未广告 0x0008/0x0020 | **对，我漏了，采纳** | `server.cpp:438-439` 用默认 `input_flags=0x0117`（`capabilities.h:232-234`）。服务端**只实现 fast-path**，不广告 0x0008/0x0020 与实现自相矛盾。**真实 mstsc 是否因此改发慢路径 = UNVERIFIED（U10）**，需抓包；但「广告与实现一致」本身是硬要求 |
| P-10 慢路径 0x1C 被丢 | **确认** | `server.cpp:1479-1521` 只处理 `kRefreshRect`/`kSuppressOutput`，其余 `return true`（1520）→ `pduType2=0x1C` 静默忽略。与 P-9 组成完整故障链：不广告 fast-path → 客户端走慢路径 → 事件全丢 |
| P-11 未知 eventCode | **对（弱化处理）** | 规范 SHOULD 断连；仓库风格宽容。裁决：**保持宽松但必须计数 + 单次日志**，并补 `remaining==0` 校验（防止把长度当事件数） |
| P-12 接缝无 session_id | **对，采纳你的形态** | 见 §3.3：`InputSink` 三方法 + `SetInputSink`（借用指针，同 `SetClipboard` 契约 `server.h:249-256`）；`InputCallback` 签名**不动**（4 处用例签名不变：`test_server.cpp:615/655/2017`、`test_gui_send.cpp:200`）。**主张改回调签名的方案一律否决** |

### 8.2 D1–D6 答复

| # | 答复 | 证据 |
|---|---|---|
| **D1** | **`SendInput`**。`keybd_event` 官方页首句："**Note This function has been superseded. Use SendInput instead.**" 且 `keybd_event` 返回 `VOID`（无法判定失败）；`SendInput` 单次调用原子（不被用户/其他注入插入） | 参考 1、6 |
| **D2** | **前台窗口**（系统输入流），**不能指定窗口**。原文：事件被插入 "into the keyboard or mouse input stream"；UNICODE 路径明确投给 "the **foreground thread's** message queue"。定向投递只能用 `PostMessage/SendMessage`（不产生真实输入状态、同样受 UIPI、多数应用不认）→ 不采用 | 参考 1、2 |
| **D3** | **不复用 `0x4321DCBA`**；用自有常量（harness: `kInjectTag = 0x52545343` 'RTSC'）。`0x4321DCBA` 是 mstsc **自身**注入标记（`input-evidence.md:45` 观测），复用会与 mstsc/第三方过滤逻辑混淆；复用收益 = UNVERIFIED | `docs/spec/input-evidence.md:45` |
| **D4** | 真实表现：**单光标、单焦点、last-writer-wins**；v1 **不做租约**，改为**门控**：`max_input_sessions=1`（默认）+ 按会话 `ReleaseSession` 清理。租约只能仲裁鼠标，解决不了键盘焦点（同一前台窗口）→ 列 v2 | §2.5 |
| **D5** | **不能区分**。原文："neither `GetLastError` nor the return value will indicate the failure was caused by UIPI blocking." 可加**预检**（非检测）：`GetForegroundWindow` → `GetWindowThreadProcessId` → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → `GetTokenInformation(TokenIntegrityLevel)`；失败按「更高完整性」处理并跳过。仍有 TOCTOU → UNVERIFIED | 参考 1、20 |
| **D6** | **v1 只支持交互式会话进程**（与你一致）。服务态在 session 0 非交互 winsta（参考 12/13），`SendInput`/`OpenInputDesktop` 落不到用户桌面；服务路线需 `CreateProcessAsUser` 到用户会话 → v2 | 参考 12、13 |

### 8.3 父代理点名的 5 项

**a) P-4 机制** — **同意**。链条：`server.cpp:1543` 默认构造（`kind=kKey, scancode=0`）→ `1610-1613`/`1614-1617`
仅 `pos+=N; break;` → `1621` 无条件回调。**修复点：1621 前跳过回调**（加 `has_payload` 标记或两分支 `continue`），
**不要改 `default:`**（default 承担「未知码 → 停止解析」，是 P-11 的落点；合并会让未知码也能继续解析）。
防御：映射层额外拒绝 `scancode==0`（harness A12 / 变异体 M7 已证）。

**b) P-5 测试固化** — **同意**。`tests/test_server.cpp:681` 注释 "the two X releases arrive as plain mouse ups" 即
自证把 G4 当预期；`695-703` 只数个数。属「测试固化缺陷」同型家族（`.opencode/discover.md` 已多次记录）。修法：改为
断言 release 的 `button` 与 down 相同（并保留 down 的 X1/X2 断言）。

**c) P-9** — **采纳（我文档原先缺此条）**。`server.cpp:438-439` 用默认 `0x0117`，缺 `0x0008`/`0x0020`；
服务端只实现 fast-path，故**应广告 0x0008|0x0020**。真实 mstsc 是否因此改发慢路径 **UNVERIFIED（U10）**——需抓包
观察 `pduType2=0x1C`。注意顺序：**先修 P-4/G2 再广告**，否则一旦客户端真的走 fast-path，幻影事件面更大。

**d) P-10** — **确认**。`server.cpp:1479-1521` 仅 `kRefreshRect`/`kSuppressOutput`，其余 `return true`（1520）；
慢路径输入 `pduType2=0x1C` 静默丢弃，回调一次都不会触发。

**e) 队列容量与接口形态** — 最终裁决：

- **队列 256（采纳乙）**。理由：单条约 40B → 8 会话上限 ~80KB；注入线程单次 `SendInput` <10µs，吞吐远高于人类
  输入速率（键盘自动重复 ~30/s、鼠标峰值数百/s）；1024 只会在阻塞时**增加延迟**（积压更久）而无吞吐收益。
  另加一条硬规则：**队列满时优先丢 move，绝不丢 up**（丢 up = 粘键）。
- **`SetGeometry` 采纳（否掉我的 `SessionBegin` 一次性快照）**。理由：几何可在会话中途重协商
  （`[READ:src/server/server.cpp:977-978,1090-1094]` 接收并按客户端请求重算），一次性快照会过期。
  最终三方法：`Inject(session_id, ev)` / `SetGeometry(session_id, w, h)`（幂等，可重复调用）/ `ReleaseSession(session_id)`；
  session 槽懒创建（`Inject`/`SetGeometry` 首次触达即建）。

### 8.4 乙问的反向自查四项

| 项 | 答复 |
|---|---|
| `SetCursorPos` vs 纯 `MOUSEEVENTF_ABSOLUTE` | `SetCursorPos` 用**屏幕绝对坐标**、须 `WINSTA_WRITEATTRIBUTES` + input desktop（官方原文，参考 9），且受 `ClipCursor` 自动裁剪（"the system automatically adjusts the coordinates"）；纯 `ABSOLUTE` 走输入流、产生真实输入事件、支持 `VIRTUALDESK` 归一化。**裁决：只用 `ABSOLUTE\|VIRTUALDESK`，不混用 `SetCursorPos`** |
| `MOUSEEVENTF_MOVE_NOCOALESCE`(0x2000) 对拖拽 | 只影响 `WM_MOUSEMOVE` 合并（原文 "will not be coalesced"）；不改变注入正确性，只增加消息量。**裁决：默认不设**，做成 `Options.no_coalesce_move`（默认 false），仅在目标应用拖拽丢点时启用；`SendInput` 的原子性只保证调用内不被插入，不保证每条 move 都成为独立消息 |
| 用户态能否读前台窗口完整性 | **可以**：`GetForegroundWindow` → `GetWindowThreadProcessId` → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → `GetTokenInformation(TokenIntegrityLevel)`（参考 20）。注意 protected process 可能 `OpenProcess` 失败 → 按「更高」处理；**本仓未实测 = UNVERIFIED** |
| `SendInput` 在目标线程挂起时是否阻塞及上限 | **官方未规定（UNVERIFIED）**。语义是「插入输入流」，不等待目标线程消费；因此**不设同步看门狗**，只做「队列深度 + 单次调用耗时」计数；若真机见 >1s 阻塞再加 degraded 阈值 |

### 8.5 收敛结论

- 与乙**无实质分歧**：P-1 至 P-12 **全部同意**（P-2 的「注入侧不乘 120」双方一致；P-4/P-9/P-10 采纳乙的补充）。
- 双方一致的四条硬结论：① 只用 `SendInput` + 扫描码（不加 0x100，扩展位用 flag）；② 绝对坐标
  `ABSOLUTE|VIRTUALDESK`；③ 注入默认关闭 + 单会话门控 + `ReleaseSession` 补 UP；④ `SendInput` 不能合成 SAS、
  UIPI 失败不可检测、session 0 不可注入。
- 剩余**必须真机**才能定案的只有 §6 的 U1–U10（尤其 U2/U5/U10）。