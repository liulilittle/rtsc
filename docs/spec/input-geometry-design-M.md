# `--monitor N` 注入坐标错位：设计定案（批 20）

状态：**设计定案（待双审签字）**。本文不含实现代码；执行 AI 按本文落地，审计按 §7 变异表验收。
角色：审计 AI-M（只读）。唯一写入文件：本文件。
所有数值均由 §10 的整数模型跑出，可独立复算。
行号口径：以 `ed4e45a 计划: 批20 范围（几何 origin/虚拟桌面）` 为基线；工作树中他代理的在途改动
不影响引用语义（若行号漂移，按符号名定位）。

---

## 0. 结论速览

| 项 | 定案 |
|---|---|
| 客户端坐标域 | **协商并钳制后的 framebuffer**（Demand Active 公告的 `desktop_width_/desktop_height_`）[READ:src/server/server.cpp:1309-1325] |
| 映射步骤 | **四步**：framebuffer 像素 → 捕获矩形内像素（含 capture origin）→ 虚拟屏物理像素 → 归一化 0..65535（含 desktop origin/尺寸） |
| 第一步取整 | **端点锚定**：`lx = round(x*(cw-1) / (fbw-1))`（`cw==fbw` 时恒等；两端角点精确；与最近邻采样差 ≤1 px） |
| 归一化分母 | **`65536 / 桌面宽`，向上取整**；现有 `extent-1` 约定**判错**（可证明不自洽，见 §2.4） |
| `VIRTUALDESK` | **恒发**（`MOVE|ABSOLUTE|VIRTUALDESK` 不变）；但归一化域必须设成虚拟桌面包围盒，缺 origin 时恒发正是错位根因 |
| `InjectGeometry` | 加 `capture{x,y,w,h}` + `desktop{x,y,w,h}` + `mapped`；**不加 DPI、不加 `use_virtual_desk`** |
| `DesktopSource` 接口 | **方案 ④**：新增 `virtual DesktopGeometry Geometry() const`（**带默认实现**，老实现零改动） |
| 默认 `--monitor -1` | 现在**方向正确**，但 `fb != 桌面尺寸` 时约 49% 像素有 1 px 取整误差；新公式 **0 px** |
| `--monitor N` / 子矩形 | **同机理**（小的当大的）、**不同数值**（缩放比不同）；`--monitor N` 会整体跨屏偏移，子矩形是裁剪区偏移+缩放 |
| 真机未验证 | Windows 解码的取整方向、GDI 采样相位、`dx=0` 传闻、混合 DPI → §8 |

---

## 1. 事实复核（只读证据）

| # | 事实 | 证据 |
|---|---|---|
| F1 | `InjectGeometry` 只有 `uint16_t width, height`，无 origin、无虚拟桌面范围 | [READ:include/rtsc/server/desktop_input.h:28-34] |
| F2 | 服务端把“协商并钳制后的 framebuffer”当成注入几何 | [READ:src/server/server.cpp:1309-1325] |
| F3 | 几何只在**拿到输入租约时**推给 sink；非租约会话不入账 | [READ:src/server/server.cpp:851-877] |
| F4 | `BuildNative` 对 `kMouseMove` 恒发 `MOVE｜ABSOLUTE｜VIRTUALDESK` | [READ:src/server/desktop_input_win32.cpp:517-526] |
| F5 | `NormalizeAxis` 用 `extent-1` 作分母，`value>=last → 65535` | [READ:src/server/desktop_input_map.cpp:13-28] |
| F6 | 只有 `is_move && g.width>1 && g.height>1` 才产出移动 | [READ:src/server/desktop_input_map.cpp:78-84] |
| F7 | 捕获支持“单显示器 + 子矩形”，最终矩形经**虚拟桌面钳制**后才生效（可能被缩小） | [READ:src/server/desktop_gdi.cpp:79-142] |
| F8 | 索引 0 被重排为主屏，其余是 `stable_sort` 后的枚举顺序，**不是** `EnumDisplayMonitors` 原始顺序 | [READ:src/server/desktop_gdi.cpp:95-105] |
| F9 | 捕获矩形**只存在**于 `GdiDesktopSourceImpl::rect_`，对外不可见 | [READ:src/server/desktop_gdi.cpp:146-148,241-244] |
| F10 | 同尺寸走 `BitBlt`，否则 `StretchBlt(COLORONCOLOR)` 缩放到协商几何 | [READ:src/server/desktop_gdi.cpp:197-209] |
| F11 | `DesktopSource` 只有 `Capture()` 一个纯虚函数 | [READ:include/rtsc/server/server.h:185-190] |
| F12 | 工厂参数语义：monitor -1=虚拟桌面，>=0=该索引；x,y 相对所选显示左上角；w,h<=0 表示整屏 | [READ:include/rtsc/server/desktop_gdi.h:25-42] |
| F13 | 捕获工厂内已 `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)`（**进程级**，全有或全无） | [READ:src/server/desktop_gdi.cpp:59-65,250] |
| F14 | 线上 `xPos/yPos` 是“相对**服务器桌面**左上角”的坐标 | [MS-RDPBCGR 2.2.8.1.1.3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2c1ced34-340a-46cd-be6e-fc8cab7c3b17) |
| F15 | 客户端先把窗口坐标换算到**协商桌面**坐标再上线（`x = x*dw/ww`） | [FreeRDP `client/Windows/wf_event.c` `wf_scale_mouse_pos`](https://raw.githubusercontent.com/FreeRDP/FreeRDP/master/client/Windows/wf_event.c) |
| F16 | 现有单测钉死 `(0,0)→(0,0)`、`(fbw,fbh)→(65535,65535)`，依赖 `extent-1` 语义 | [READ:tests/test_desktop_input.cpp:259-280] |
| F17 | 集成测试断言 `geometry_width/height == 协商值`（64x48），不涉及 origin | [READ:tests/test_server.cpp:544-550,3765-3772] |
| F18 | `tools/rtsc_server` 里捕获源与注入 sink 在**同一进程**（同一 DPI 语境） | [READ:tools/rtsc_server/main.cpp:469,541,585-587] |

由此可得一个关键前提：**客户端坐标域恒为 `[0, fbw) × [0, fbh)`**（F14+F15），
它是否等于物理像素取决于捕获侧是否 1:1（F10），**不能假设**。

---

## 2. 规范依据

### 2.1 `MOUSEINPUT` 原文（Microsoft Learn，逐字抓取）

来源：<https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-mouseinput>

- `MOUSEEVENTF_ABSOLUTE 0x8000`：*“The **dx** and **dy** members contain normalized absolute
  coordinates.”*
- `MOUSEEVENTF_VIRTUALDESK 0x4000`：*“Maps coordinates to the entire desktop. **Must be used with
  MOUSEEVENTF_ABSOLUTE.**”*
- Remarks：*“If **MOUSEEVENTF_ABSOLUTE** value is specified, **dx** and **dy** contain normalized
  absolute coordinates between 0 and 65,535. … Coordinate (0,0) maps onto the upper-left corner of
  the display surface; coordinate (65535,65535) maps onto the lower-right corner. In a multimonitor
  system, the coordinates map to the primary monitor.”*
- *“If **MOUSEEVENTF_VIRTUALDESK** is specified, the coordinates map to the entire virtual
  desktop.”*

三条推论：

1. `0..65535` 是**闭区间两端点**，不是“16.16 定点”（虽然在 `>>16` 实现下等价）。
2. 不带 `VIRTUALDESK` 时域是**主显示器矩形**（`SM_*SCREEN`），**不是**含负原点的虚拟桌面。
3. 带 `VIRTUALDESK` 时域是**虚拟桌面包围盒**（`SM_X/Y/CX/CYVIRTUALSCREEN`）。文档没说虚拟桌面
   原点为 0，所以负原点布局下**必须**先减 `SM_XVIRTUALSCREEN`。

现有代码恒发 `VIRTUALDESK`（F4）却按“framebuffer 尺寸、无 origin”归一化（F2/F5），
等价于把“客户端图像矩形”当成“整个虚拟桌面”；两者只在 `capture == desktop` 时重合。

### 2.2 解码方向：分母判定的真正依据

文档不规定除法/取整细节，故看**系统如何反解**。两套独立的 reimplementation 一致：

**Wine** `dlls/win32u/input.c` `update_mouse_coords()`：

```c
if (input->mi.dwFlags & MOUSEEVENTF_VIRTUALDESK)
    rc = get_virtual_screen_rect( no_dpi, MDT_DEFAULT );
else
    rc = get_primary_monitor_rect( no_dpi );
input->mi.dx = rc.left + ((input->mi.dx * (rc.right - rc.left)) >> 16);
```

⇒ `phys = origin + floor(n * extent / 65536)`，域按 flag 选择，**与 §2.1 完全一致**。

**ReactOS** `win32ss/user/ntuser/mouse.c` `UserSendMouseInput()`：

```c
else if (pmi->dwFlags & MOUSEEVENTF_VIRTUALDESK)
{
    ptCursor.x = pmi->dx * UserGetSystemMetrics(SM_CXVIRTUALSCREEN) >> 16;
    ptCursor.y = pmi->dy * UserGetSystemMetrics(SM_CYVIRTUALSCREEN) >> 16;
}
```

同型 `n*extent >> 16`（该历史版本**漏加负原点**，2009 年 ReactOS 邮件列表已作为 bug 讨论：
<https://reactos.org/pipermail/ros-dev/2009-July/011887.html> —— 这正是“漏 origin”的活标本）。

一致性校验：`n = 65535` 时 `floor(65535*w/65536) = w-1`（`w ≤ 65536`），
恰好落在最后一像素，与文档“`(65535,65535)` → 右下角”**吻合**。

**推断（证据强度：中）**：Windows 反解为 `phys = origin + floor(n*extent/65536)`，
分母是 **extent**，取整**向下**。文档未明写 → 真机待验（§8 U1/U2）。

### 2.3 成熟实现对照

| 实现 | 正向公式 | 归一化域 | 取整 | 与本文定案的关系 |
|---|---|---|---|---|
| **Wine**（解码） | — | `VIRTUALDESK`→虚拟桌面；否则主屏 | floor | **本文的反解模型** |
| **ReactOS**（解码） | — | 同上 | floor | 同型（历史漏 origin） |
| **Chromium** `ui/base/win/event_creation_utils.cc` | `max(1, ceil((p-left) * 65536 / width))` | `SM_*VIRTUALSCREEN` 矩形，但**不发 VIRTUALDESK** | ceil | **正向与本文逐字一致**；缺 flag 是它的缺陷（负原点时按主屏解） |
| **Chromium remoting** `remoting/host/input_injector_win.cc` | `x*65535/(width-1)`，`x` 用 `clamp(x, 0, width)` | 虚拟桌面（发 `MOVE|ABSOLUTE|VIRTUALDESK`） | 截断 | 与 Wine/ReactOS 反解**不互逆**（§2.4）；`clamp` 上界写成 `width`（差一） |
| **FreeRDP server** `server/Windows/wf_input.c` | `(x + servscreen_xoffset) * (65535/SM_CXSCREEN)` | **主屏**（不发 `VIRTUALDESK`） | 截断（float） | 有“手工加 origin”这一步（正是我们缺的），但域固定主屏 → 多屏会钳到主屏 |
| **rdev** `src/windows/simulate.rs` | `(x+1)*65535/width` | 虚拟桌面（发 `MOVE|ABSOLUTE|VIRTUALDESK`） | 截断 | 与本文 `ceil(x*65536/width)` **落点等价**（实测 `w ∈ [2,300] ∪ {640,1280,1920,2560,3200,3840,8192,65535}` 的 `floor(n*w/65536)` 完全一致）；它只是把 `ceil` 写成 `+1` 的整数技巧 |
| **cua PR #1980** | `(p-vd_origin)*65535/(vd_size-1)` | 虚拟桌面 | 四舍五入 | 其声称的“Windows 反解”`n*(vw-1)/65535` 与 Wine/ReactOS 源码**矛盾**，属接缝经验修正 |
| **mstsc 反汇编** | — | — | — | **未取证**（§8 U1） |

本仓唯一实测：单屏 2048x1152、原点 (0,0) 时 `(2047,1151) → (65535,65535)` 往返 0 px
[READ:evidence/input-inject-mapping-probe.txt:38-44]——但该探针的“反解”是**用同一条公式自证**，
因此**不能**作为分母判据。

### 2.4 分母裁决：`extent-1` 还是 `extent`？

**裁决：用 `extent`（`n = ceil(rel*65536/extent)`），现有 `NormalizeAxis` 的 `extent-1` 判错。**

判据是**正解 ∘ 反解 = 恒等**（反解取 §2.2 的 `floor(n*extent/65536)`）：

1. **取 `n = ceil(rel*65536/w)`**：`n ≥ rel*65536/w` ⇒ `n*w/65536 ≥ rel`；又
   `n < rel*65536/w + 1` ⇒ `n*w/65536 < rel + w/65536 ≤ rel + 1`（`w ≤ 65536`）
   ⇒ `floor(n*w/65536) == rel`，**逐像素精确**。
   实测：`w ∈ {1280,1920,3200,3840,8192}` 全部 **0 失配**（§10 输出）。
2. **取 `n = round(rel*65535/(w-1))`（现有）**：`w=1280` 有 **3** 个像素反解回退 1 px，
   `1920→7`、`3200→20`、`3840→28`、`7680→110`。误差小，但**可证明不自洽**。
3. **取 `n = round(rel*65536/w)`（四舍五入版）**：`w=1280` 有 **512** 个像素反解偏差 1 px
   ⇒ **取整方向必须是 ceil，不能是 round**（Chromium `ui/base` 同样是 `ceil`）。
4. 端点承诺两者都满足：`w=1920` 时 `n=65502` 与 `n=65535` 都落到最后一像素（1919）。
   即“65535→右下角”**不需要** `extent-1`；那个分母只是把最后一格硬撑满 0..65535 的错觉。
5. **前提**：`w ≤ 65536` 时上面第 1 条的 1 px 界成立。若虚拟桌面宽 > 65536（极多/极宽显示器），
   一次 `n` 增量覆盖 >1 px，往返必然丢像素 —— 这是 65536 档位的**物理上限**，不是本公式的缺陷；
   实际 `--monitor N` 场景下 `desktop_w` 是包围盒宽度，请按 §8 U9 记录真实上限。

**代价（必须明确）**：`tests/test_desktop_input.cpp:272-279` 钉死了 `(1920,1080)→65535`，
新语义下该值是 `65502`。**必须改这条断言并重算期望，禁止放宽容差**（否则就是假测试）。
建议改法：**主断言改为“落点像素”**（`decode(n) == 期望物理像素`），再补“精确 n”断言锁公式。
关键限制（见 §7）：**稀疏落点断言抓不到分母错误**（21 个稀疏用例的落点全部不变），
必须靠**稠密往返表**（`w ∈ {1280,1920,3200,3840}`、`rel` 取全部像素）或**精确 n 断言**。

> **需双审签字的关键裁决**：改动一条已通过的钉死断言（T4 曾以“边界值错”判 FAIL；
> [READ:docs/spec/input-injection-evidence.md:143-144] 亦承认分母“官方未规定”）。
> 这是**一致性 vs 兼容性**的取舍：收益是“往返 0 误差”可写成 0 容差断言（可当强红证），
> 代价是改一条已通过的期望值；**像素级可见收益很小**（3/1280 像素各差 1 px）。
> 退路：保持 `65535/(w-1)`，把往返断言降级为“≤1 px”，但放弃 0 容差红证。

### 2.5 第一步（framebuffer → 捕获像素）的语义

候选有三条（都是“把 `fbw` 个像素摊到 `cw` 个像素”的整数解），必须显式选一条：

| 候选 | 公式 | `fb=640,cap=1280` 端点 | 评价 |
|---|---|---|---|
| **A 端点锚定（采用）** | `lx = round(x*(cw-1) / (fw-1))` | `0→0`,`639→1279` | 两端**恰好**是捕获矩形首末像素；`cw==fw` 时恒等；放大时每个捕获像素都可被寻址 |
| B 窗口中心 | `lx = floor(((2x+1)*cw)/(2fw))` | `0→1`,`639→1279` | 放大时 **捕获像素 0 永远不可达**（`x=0` 就跳到 1）；`fw=640,cap=1920` 时末像素也只到 1918 |
| C 窗口起点 | `lx = x*cw/fw` | `0→0`,`639→1278` | 末端**提前一格**（捕获末像素不可达），整体向左上偏 |

差异量级（§10 实测，`cw != fw` 时**不是个别点**）：

| `fw` → `cap` | A 与 B 不同的源像素 | A 与 C 不同的源像素 |
|---|---|---|
| 640 → 1280 | 320 / 640 | 320 / 640 |
| 640 → 1920 | 320 / 640 | 480 / 640 |
| 800 → 1920 | 288 / 800 | 696 / 800 |
| 1280 → 3200 | 428 / 1280 | 1066 / 1280 |
| 1920 → 3840 | 960 / 1920 | 960 / 1920 |

**采用 A**，理由：

1. **两角精确**：`fb(0,0)` 恰是 `capture(cx,cy)`，`fb(fw-1,fh-1)` 恰是 `capture(cx+cw-1, cy+ch-1)`。
   客户端看到的“图像左上像素”就是捕获矩形的左上像素；这是用户唯一能验证的语义。
2. **`cw==fw` 恒等**（F10 的 `BitBlt` 分支零取整），与既有 1:1 路径完全一致
   [READ:src/server/desktop_gdi.cpp:200-203]。
3. 候选 B 在放大时把捕获的**首像素**排除在可达集合外（`0→1`），属可观察缺陷；候选 C 末端提前一格。
4. A 与真实 GDI 最近邻采样的相位可能差 1 px（属 §8 U3），但 A 的**可达集合与单调性**是三者中最正确，
   且 `cw==fw` 时无差异。

> 注意：A 与 B 在 `cw==fw` 时**完全相同**（都恒等），所以 1:1 用例无法区分；必须用 `cw != fw` 的用例。
> 端点断言本身也无法区分 A 与 B/C 的中间点，故 §7 要求**稠密逐像素**比较。

---

## 3. 定案公式

### 3.1 记号

| 符号 | 含义 | 来源 |
|---|---|---|
| `fbw, fbh` | 协商并钳制后的 framebuffer 尺寸 | `desktop_width_/desktop_height_` [READ:src/server/server.cpp:1314-1318] |
| `cx, cy, cw, ch` | 捕获矩形（虚拟屏**物理**像素，已含钳制后的最终值） | `DesktopGeometry::capture`（新） |
| `dx, dy, dw, dh` | 归一化域 = 虚拟桌面包围盒（物理像素，`dx/dy` 可为负） | `DesktopGeometry::desktop`（新） |
| `wx, wy` | 线上 `xPos/yPos`（`uint16`，可能越界） | `InputEvent::x/y` |

### 3.2 完整映射（逐轴独立）

```
步骤 0（钳制到客户端域；防越界/防溢出，不改变合法值）
    fx = clamp(wx, 0, fbw - 1)        // int64 参与后续乘法
    fy = clamp(wy, 0, fbh - 1)

步骤 1（framebuffer 像素 → 捕获矩形内像素；端点锚定，四舍五入）
    if fbw <= 1 or cw <= 0: lx = 0
    else:
        den = 2*(fbw - 1)
        lx  = min(cw - 1, (fx*(cw - 1)*2 + (fbw - 1)) / den)   // round(fx*(cw-1)/(fbw-1))
    （y 轴同式，用 fy/fbh/ch）
    两端精确：fx=0 → 0，fx=fbw-1 → cw-1。

步骤 2（捕获内像素 → 虚拟屏物理像素）
    px = cx + lx
    py = cy + ly

步骤 3（物理像素 → Win32 归一化；与 floor(n*extent/65536) 严格互逆）
    rx = clamp(px - dx, 0, dw - 1)
    ry = clamp(py - dy, 0, dh - 1)
    nx = min(65535, ceil(rx * 65536 / dw))     // ceil(a/b) = (a + b - 1) / b，a>=0,b>0
    ny = min(65535, ceil(ry * 65536 / dh))

输出: MOUSEINPUT{ dx = nx, dy = ny,
                  dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK }
```

取整规则：步骤 1 **四舍五入（half-up）**；步骤 3 **向上取整**；步骤 0 与步骤 3 的 `clamp` 是**闭区间**。

**步骤 3 是“与系统解码互逆”的那一步，其形式必须跟随 §8 U2 的真机结论**：

| 若真机解码是 | 步骤 3 应写成 | 说明 |
|---|---|---|
| `floor(n*w/65536)`（Wine/ReactOS，**本定案假设**） | `ceil(rel*65536/w)` | 往返 0 误差（§2.4 证明） |
| `round(n*(w-1)/65535)`（cua 的说法） | `round(rel*65535/(w-1))` | 与本文现有 `NormalizeAxis` 同形，仅需补 `rel = phys - dx` |

两者的**其它步骤（0/1/2）与 `InjectGeometry`/`DesktopSource` 结构完全不受影响**；
若 U2 翻转，只需把步骤 3 换成下表右列并把 §6.4 的“新 n”列重算（落点列基本不变）。
这正是把“域/原点”与“取整约定”分开定案的价值：**缺陷修复不依赖 U2，只有最后 1 px 精度依赖它**。

数值范围（防溢出）：`cw, ch ≤ 32767`（`SM_CXVIRTUALSCREEN` 是 `int`）、`fbw, fbh ≤ 8192`
（`kMaxDesktopWidth/Height`）⇒ 步骤 1 分子 `fx*(cw-1)*2 ≈ 8191*32766*2 ≈ 5.37e8`，
步骤 3 最大 `32766*65536 ≈ 2.147e9`（略低于 `INT32_MAX`）。**仍要求用 `int64_t`**：余量只剩 1e-4，
且未来放宽上限必然溢出。

退化规则（沿用既有 fail-closed 语义 [READ:src/server/desktop_input_map.cpp:78]）：

- `fbw <= 1 || fbh <= 1` → 不产出 `kMouseMove`（保持现状 + F16 的退化用例）。
- `!mapped` → 不产出 `kMouseMove`；**按钮/滚轮/键盘照常**（否则会留下卡住的按钮，
  与 `desktop_input_absolute_move_requires_usable_geometry` 的按钮分支一致 [READ:tests/test_desktop_input.cpp:305-317]）。
- `cw <= 0 || ch <= 0 || dw <= 1 || dh <= 1` → 视为 `!mapped`。

### 3.3 为什么**不加** DPI 字段

1. 两个矩形都取**物理像素**：捕获侧把进程设为 `PER_MONITOR_AWARE_V2`（F13，进程级），
   `GetSystemMetrics(SM_*VIRTUALSCREEN)` 与 `GetMonitorInfo/rcMonitor` 在该进程态下就是物理像素；
   `MOUSEINPUT` 的绝对空间在**注入进程**的 DPI 语境下同样是物理虚拟屏坐标。
   捕获与注入在**同一进程**（F18），不存在跨进程 DPI 失配。
2. 加 DPI 字段会引入“用哪个 DPI 缩放”的第二套语义，而 Win32 没有“按 DPI 归一化”的注入入口。
3. 已知陷阱是**不要在注入线程里再调 `GetSystemMetrics`**（线程 DPI 语境不可保证），
   而应把矩形作为**快照**经 `SetGeometry` 传过去——这正是 §4 的设计。
4. 混合缩放（不同 DPI）下 `VIRTUALDESK` 的绝对空间仍是**未缩放的物理虚拟屏坐标**
   （Wine/ReactOS 都直接取 `SM_*VIRTUALSCREEN`）；DPI 只影响“矩形怎么量”，由捕获侧统一量好即可。
   → 真机差异列入 §8 U4。

---

## 4. `InjectGeometry` 目标结构

### 4.1 最小充分集

```cpp
// include/rtsc/server/desktop_input.h
struct InjectRect {              // 一律 int32：虚拟屏坐标可为负
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;
};

struct InjectGeometry {
    // 协商并钳制后的 framebuffer：客户端坐标域（语义不变，放最前以保持聚合初始化兼容）。
    uint16_t width = 0;
    uint16_t height = 0;

    // 捕获矩形（虚拟屏物理像素）。width/height<=0 表示不可知。
    InjectRect capture;

    // 归一化域：恒发 VIRTUALDESK 时应为虚拟桌面包围盒。
    InjectRect desktop;

    // capture/desktop 是否可信。false ⇒ 绝对移动一律丢弃。
    bool mapped = false;
};
```

`InjectGeometry{desktop_width_, desktop_height_}` 这种两参数聚合初始化**继续可用**
（新增成员有默认值），可把改动面压到最小。

被丢弃的绝对移动计入 sink 的**内部** `dropped_unsupported_`
[READ:src/server/desktop_input_win32.cpp:141,700]；该计数**目前不在 `InputStats` 里**
[READ:include/rtsc/server/desktop_input.h:59-66]，因此“几何不可信导致的丢弃”对运维**不可见**。
建议顺带把它提升为 `InputStats` 的一个字段（属可观测性增强，非本缺陷必需；若加，需同步
`desktop_input_null.cpp` 与 `InputStats` 的既有断言）。

### 4.2 字段来源与生命周期

| 字段 | 来源 | 填入时机 |
|---|---|---|
| `width/height` | `desktop_width_/desktop_height_` | 与现在相同：`DoConnectResponse` [READ:src/server/server.cpp:1324] |
| `capture` | `DesktopSource::Geometry()`（GDI 实现返回其 `rect_`，即**钳制后**最终矩形） | 同上；另在 `AcquireInputLease` 前复测一次 |
| `desktop` | 同一工厂内一次性取 `SM_X/Y/CX/CYVIRTUALSCREEN` 快照 | 同上 |
| `mapped` | `capture.width>0 && capture.height>0 && desktop.width>1 && desktop.height>1` | 同上 |

**禁止**在 sink / 映射层调用 `GetSystemMetrics`：`desktop_input_map.cpp` 必须保持平台中立
[READ:include/rtsc/server/desktop_input_map.h:1-12]，且注入线程 DPI 语境不可保证。

### 4.3 关于 `use_virtual_desk` 字段：不加

- 恒发 `VIRTUALDESK` + “域 = `desktop` 矩形”在**所有**布局下自洽：单屏时
  `SM_*VIRTUALSCREEN == SM_*SCREEN`，多屏时域正好是包围盒。
- 唯一表达不了的是“只投到主屏”，仓库内无此需求（`--monitor N` 是**捕获**选择，不是注入域选择：
  注入永远落在真实光标空间）。
- “恒发/不发 VIRTUALDESK”仍可作变异点测（§7 M7）。
- 若双审坚持要主屏模式，再加 `bool use_virtual_desk`，`desktop` 填主屏矩形，公式不变。

---

## 5. `DesktopSource` 接口方案

现状：只有 `Capture()`（F11），矩形锁死在 `GdiDesktopSourceImpl::rect_`（F9）。

| 方案 | 内容 | 优点 | 致命缺点 | 结论 |
|---|---|---|---|---|
| ① | 新增 `virtual bool CaptureRect(int32_t*, …×8)` | 改动集中 | 纯虚会**打断所有嵌入方**编译；8 个出参易错序；`bool` 无法区分“未知”与“全零” | 否 |
| ② | 工厂返回结构体 `{source, geometry, error}` | 不动抽象 | 改返回类型 → `main.cpp:541`、`test_desktop_gdi.cpp:73/88/105/128/160` 全改；服务端需第二条入口（`SetDesktopGeometry`）与 `SetDesktopSource` 可失配；构造期快照无法复测 | 次优 |
| ③ | 调用方按 `--monitor/--width` 自己算 | 零接口改动 | **必然错**：`ResolveCaptureRect` 会重排索引（F8）、把 x,y 相对所选显示器平移（F12）、再钳制缩小（F7）；调用方算不出实际矩形 | 否决 |
| **④** | `virtual DesktopGeometry Geometry() const`（**非纯虚、默认 `{}`**） | 单入口、可复测、老实现零改动、字段可扩展不破签名 | 是**快照**：热插拔不自动刷新（用“取租约时复测”覆盖常见场景） | **推荐** |

```cpp
// include/rtsc/server/server.h
struct DesktopGeometry {
    bool capture_known = false;
    int32_t capture_x = 0, capture_y = 0, capture_width = 0, capture_height = 0;
    int32_t desktop_x = 0, desktop_y = 0, desktop_width = 0, desktop_height = 0;
};

class DesktopSource {
 public:
    virtual ~DesktopSource() = default;
    virtual bool Capture(uint16_t width, uint16_t height, std::vector<uint8_t>& rgba) = 0;
    // 新增：默认“未知”。老实现不改一行即编译通过。
    virtual DesktopGeometry Geometry() const { return {}; }
};
```

- `GdiDesktopSourceImpl` 覆写：返回 `rect_` + 工厂期取好的 `SM_*VIRTUALSCREEN` 快照。
- `TestPatternSource` 保持默认（`capture_known=false`）→ `mapped=false` → 合成图上的绝对移动被丢弃
  （本来也无物理意义），但 `width/height` 仍按协商值下发，[READ:tests/test_server.cpp:3771-3772] 不受影响。

---

## 6. 可达性与数值例

### 6.1 `--monitor -1`（默认）现在是否正确？

- `capture == 虚拟桌面`（F12）⇒ 步骤 2 的 origin 为 0，步骤 3 的 `(cx-dx)=0`。
- 现有实现**方向正确**，残余只有取整不一致：
  `fb=1280x1024`、桌面 `1920x1080` 全像素枚举 ⇒ **max_err = 1 px**，
  `644675 / 1310720`（**49.18%**）的像素落在 ±1（0.5 px 量级）。
- `fb == 桌面` 时误差 0（走 1:1 `BitBlt` 且归一化域重合）。
- 新公式同例：**max_err = 0 px，0 个像素偏离**（`decode(map(x)) == step1(x)` 逐像素成立）。

结论：**默认路径“可用但不精确”**；本设计不改默认语义方向，只把误差从 1 px 消到 0。
（换采样相位只改“参照的理想像素”，不改“是否精确”：端点/中心/起点三种候选的往返失配都是 0，
差异体现在**与真实 GDI 采样是否对齐**，即 §8 U3。）

### 6.2 `--monitor N` 与“子矩形”是两种不同的错位

| 场景 | capture vs desktop | 错位性质 | 是否随位置变化 |
|---|---|---|---|
| `--monitor N`（多屏，副屏） | 尺寸可能相同但 **origin 非零** | **纯平移**（`−cx`），可能与预期整屏偏移 | 是（越靠右/下越偏；理论上右边界仍对） |
| `--monitor N`（副屏尺寸 ≠ 桌面） | 尺寸不同 + origin 非零 | **平移 + 缩放** | 是 |
| 子矩形（x/y/w/h） | 尺寸必然不同、origin 可能非零 | **平移 + 缩放**；缩放比 = 捕获/桌面 | 是 |
| `--monitor N`（单屏，capture==desktop） | 完全相同 | **无错位** | 否 |
| 默认 `-1` | 完全相同 | **正确**（≤1 px 取整） | 否 |

判定口诀：**错位是否存在，只看 `capture` 是否等于 `desktop`**。只要不等，`--monitor N` 与子矩形
走**同一条错误路径**（把小的当成大的），数值表现不同（缩放比/偏移量不同），**机理相同**。

### 6.3 必答数值例：monitor 1 起点 (1920,0)、1280x1024，客户端 (640,512)

桌面 = 双屏并排 `3200x1024`（屏0 在 x∈[0,1920)，屏1 在 x∈[1920,3200)），`fb = 1280x1024`（1:1）。

| 项 | 计算 | 结果 |
|---|---|---|
| 客户端坐标 | `(wx,wy)=(640,512)` | — |
| 步骤 0 | `640 ≤ 1279`、`512 ≤ 1023` | `(640,512)` |
| 步骤 1 | `round(640*1279/1279)=640`；`round(512*1023/1023)=512`（`cw==fw`，恒等） | `(640,512)` |
| 步骤 2 | `1920+640=2560`；`0+512=512` | **`(2560,512)`** |
| 步骤 3 | `ceil(2560*65536/3200)=ceil(52428.8)=52429`；`ceil(512*65536/1024)=32768` | `n=(52429,32768)` |
| 系统反解 | `floor(52429*3200/65536)=2560`；`floor(32768*1024/65536)=512` | **`(2560,512)` ✅ 0 px** |
| **现有实现** | `round(640*65535/1279)=32793`；`round(512*65535/1023)=32800` | `n=(32793,32800)` |
| **现有落点** | `floor(32793*3200/65536)=1601`；512 | **`(1601,512)` ❌ 偏 −959 px** |

即 **应落在第二块屏 (2560,512)，现实现落在第一块屏 (1601,512)**——偏 959 px，且**跨到了错误的显示器**
（`x=1601 < 1920` 全在屏0）。这正是“没有 origin 却恒发 VIRTUALDESK”的直接后果。

### 6.4 落点表（可逐行抄进单测）

列说明：`fb` = 协商几何；`捕获` = `(cx,cy,cw,ch)`；`桌面` = `(dx,dy,dw,dh)`；
`新 n / 新落点` = §3 公式；`规范落点` = `cx + round(fx*(cw-1)/(fbw-1))`（端点锚定下“应该”指向的物理像素，
也是 §3 公式输出的真实落点，二者逐行相等是本表的自检）；
`现有 n / 现有落点` = `round(fx*65535/(fbw-1))` 经 `floor(n*dw/65536)+dx`。

| 用例 | fb | 捕获 | 桌面 | 客户端 | 新 n | 新落点 | 规范落点 | 现有 n | 现有落点 | 现有误差 |
|---|---|---|---|---|---|---|---|---|---|---|
| A1 | 1280x1024 | (1920,0,1280,1024) | (0,0,3200,1024) | (0,0) | (39322,0) | (1920,0) | (1920,0) | (0,0) | (0,0) | **−1920,0** |
| A2 | 1280x1024 | 同上 | 同上 | (640,512) | (52429,32768) | (2560,512) | (2560,512) | (32793,32800) | (1601,512) | **−959,0** |
| A3 | 1280x1024 | 同上 | 同上 | (1279,1023) | (65516,65472) | (3199,1023) | (3199,1023) | (65535,65535) | (3199,1023) | 0,0 |
| A4 | 1280x1024 | 同上 | 同上 | (3000,5) 越界 | (65516,320) | (3199,5) | (3199,5) | (65535,320) | (3199,5) | 0,0 |
| B0 | 640x512 | 同上 | 同上 | (0,0) | (39322,0) | (1920,0) | (1920,0) | (0,0) | (0,0) | **−1920,0** |
| B1 | 640x512 | 同上 | 同上 | (320,256) | (52450,32832) | (2561,513) | (2561,513) | (32819,32832) | (1602,513) | **−959,0** |
| B2 | 640x512 | 同上 | 同上 | (639,511) | (65516,65472) | (3199,1023) | (3199,1023) | (65535,65535) | (3199,1023) | 0,0 |
| C1 | 800x600 | (100,50,800,600) | (0,0,1920,1080) | (400,300) | (17067,21239) | (500,350) | (500,350) | (32809,32822) | (961,540) | **+461,+190** |
| C2 | 800x600 | 同上 | 同上 | (0,0) | (3414,3035) | (100,50) | (100,50) | (0,0) | (0,0) | **−100,−50** |
| C3 | 800x600 | 同上 | 同上 | (799,599) | (30686,39383) | (899,649) | (899,649) | (65535,65535) | (1919,1079) | **+1020,+430** |
| D1 | 1280x1024 | (−1280,0,1280,1024) | (−1280,0,3200,1024) | (0,0) | (0,0) | (−1280,0) | (−1280,0) | (0,0) | (−1280,0) | 0,0 |
| D2 | 1280x1024 | 同上 | 同上 | (640,512) | (13108,32768) | (−640,512) | (−640,512) | (32793,32800) | (321,512) | **+961,0** |
| D3 | 1280x1024 | 同上 | 同上 | (1279,1023) | (26194,65472) | (−1,1023) | (−1,1023) | (65535,65535) | (1919,1023) | **+1920,0** |
| E1 | 1280x1024 | (0,0,1920,1080) | (0,0,1920,1080) | (0,0) | (0,0) | (0,0) | (0,0) | (0,0) | (0,0) | 0,0 |
| E2 | 1280x1024 | 同上 | 同上 | (639,511) | (32734,32708) | (959,539) | (959,539) | (32742,32735) | (959,539) | 0,0 |
| E3 | 1280x1024 | 同上 | 同上 | (1279,1023) | (65502,65476) | (1919,1079) | (1919,1079) | (65535,65535) | (1919,1079) | 0,0 |
| F1 | 1920x1080 | (0,0,1920,1080) | (0,0,3840,1080) | (0,0) | (0,0) | (0,0) | (0,0) | (0,0) | (0,0) | 0,0 |
| F2 | 1920x1080 | 同上 | 同上 | (960,540) | (16384,32768) | (960,540) | (960,540) | (32785,32798) | (1920,540) | **+960,0** |
| F3 | 1920x1080 | 同上 | 同上 | (1919,1079) | (32751,65476) | (1919,1079) | (1919,1079) | (65535,65535) | (3839,1079) | **+1920,0** |
| G1 | 4x4 | (0,0,4,4) | (0,0,4,4) | (3,3) | (49152,49152) | (3,3) | (3,3) | (65535,65535) | (3,3) | 0,0 |
| G2 | 4x4 | (0,0,4,4) | (0,0,4,4) | (1,1) | (16384,16384) | (1,1) | (1,1) | (21845,21845) | (1,1) | 0,0 |

读法要点：

- **现有落点恰好正确的用例**：A3、A4、B2、D1、E1、E2、E3、F1、G1、G2。它们要么都撞在边界上
  （`x=0` 且 origin=0，或 `x=fw-1` 使 `n=65535` 解码成桌面右下角），要么桌面与捕获 1:1 且 origin=0。
  ⇒ **只测角点的测试抓不到现有缺陷**，必须加中间点（A2/B1/C1/D2/F2）。
- **F2/F3 是 `--monitor 0`（主屏、origin=0）仍然错位的反例**：捕获是主屏 1920x1080、桌面 3840x1080，
  客户端 x=960 应落在 960，现实现按**整个虚拟桌面**归一化 ⇒ 落到 1920（跑到**第二块屏**）；
  x=1919 现实现落到 3839。这说明缺陷**不只**是 origin 缺失，还有“归一化域被当成虚拟桌面”。
- **A1/B0/C2 的现有落点是 (0,0)**：`n=0` 一律解码成桌面**原点**；捕获矩形 origin ≠ 0 时必然错。
- **B0 是 `--monitor N` 的最强红证**：客户端 (0,0) 应落在副屏左上角 (1920,0)，现实现落在 (0,0)。
- **B0 是 `--monitor N` 的最强红证**：客户端 (0,0) 应落在副屏左上角 (1920,0)，现实现落在 (0,0)。

可复现方式：把 §10 附录的 `map_axis` / `decode`（纯整数、8 行）原样拷进测试仓库作为**独立 oracle**，
由上表参数生成期望值；禁止让被测实现自己算期望。本文表格全部由该 oracle 生成并逐行人工核对。

### 6.5 分母判决的枚举数据（§2.4 用）

| `desktop_w` | `ceil(rel*65536/w)` 失配 | `round(rel*65536/w)` 失配 | `round(rel*65535/(w-1))` 失配 |
|---|---|---|---|
| 1280 | **0** | 512 | 3 |
| 1920 | **0** | 896 | 7 |
| 3200 | **0** | 1536 | 20 |
| 3840 | **0** | 1792 | 28 |
| 8192 | **0** | 0 | 0 |

（“失配” = `floor(n*w/65536) != rel`，即一次注入后再用 `GetCursorPos` 读回会偏 1 px 的像素数。）

---

## 7. 变异清单

前提：

1. 期望值必须来自 §10 的**独立模型**，不得由被测函数自证（否则是假测试）。
2. **两级断言都要有**：`n` 的精确值（锁公式，抓 M5/M5b/M6/M6s）与落点 `decode(n)`（锁可见语义，抓 M1–M4/M8）。
   只写落点会漏掉分母/采样相位类变异（见下文“必须用稠密表”）。
3. **已排除的假变异**（诚实登记，禁止当成“必红”写进验收）：
   - “去掉线上坐标钳制（步骤 0）”——由于步骤 1 的结果被 `cw-1` 界住，
     实测**不改变任何输出**；它只是防溢出/防负值的保险，**不能**作为变异点。
     （若要用它，必须先去掉 `cw-1` 界，但那会引入溢出，属另一种实现错误。）
   - “把闭区间钳制改成半开区间”——同样被 `cw-1` 界吸收，**不改变输出**。

| # | 变异（改坏点） | 必须转红的用例 | n 级命中 | 落点级命中 | 实测落点差（示例） |
|---|---|---|---|---|---|
| **M1** | 忽略捕获 origin（`cx=cy=0`） | A1,A2,A3,A4,B0,B1,B2,C1,C2,C3,D1,D2,D3 | 13 | **13** | A1→`(0,0)`、A2→`(640,512)`、B1→`(641,513)`、C1→`(400,300)` |
| **M2** | 忽略捕获 extent（令 `cw=fw,ch=fh`） | B1,B2,E2,E3 | 4 | **4** | B1→`(2240,256)`、E2→`(639,511)`（默认路径也红） |
| **M3** | 忽略虚拟桌面 origin（`dx=dy=0`） | D2,D3 | 2 | **2** | D2→`(−1280,512)`、D3→`(−1280,1023)` |
| **M4** | 归一化域用**捕获矩形**而非虚拟桌面 | A1,A2,A3,A4,B0,B1,B2,C1,C2,C3,D2,D3,F2,F3 | 14 | **14** | A2→`(1600,512)`、C1→`(960,540)`、F2→`(1920,540)`（跨屏）、F3→`(3838,1079)` |
| **M5** | 桌面分母用 `65535/(dw-1)`（现有约定） | A1,A2,A3,A4,B0,B1,B2,C1,C2,C3,D2,D3,E2,E3,F2,F3,G1,G2 | **18** | **0** | 见下方“必须用 n 级断言” |
| **M5b** | 桌面分母保持 `65536/dw` 但改 **round** | B1,C2,C3,D2,E2,E3,F3 | 7 | **7** | B1→`(2560,513)`、E2→`(959,538)`、F3→`(1919,1078)` |
| **M6** | 步骤 1 改成**窗口中心采样** | B0 + **稠密逐像素**（`fw=640,cap=1280` 全 `x∈[0,640)`） | 1 | **1** | B0→`(1921,1)`；稠密：`fw=640,cap=1280` 有 **320/640**、`fw=1280,cap=3200` 有 **428/1280** 个不同 |
| **M6s** | 步骤 1 改成**窗口起点** `x*cw/fw` | B1,B2,E2,E3 + 稠密 | 4 | **4** | B1→`(2560,512)`、B2→`(3198,1022)`、E2→`(958,538)` |
| **M7** | `dwFlags` 去掉 `MOUSEEVENTF_VIRTUALDESK`（或 `ABSOLUTE`） | 对 `INPUT.dwFlags` 的断言 | — | — | flag 断言红（像素级不受影响，但语义失效） |
| **M8** | 捕获 origin **符号取反**（`cx=-cx`） | A1,A2,A3,A4,B0,B1,B2,C1,C2,C3,D1,D2,D3 | 13 | **13** | A2→`(0,512)`、D2→`(1919,512)` |
| **M9** | `mapped` 恒 `true`（来源未知几何也当可信） | `TestPatternSource` 会话 + 绝对移动 | — | — | 应“丢弃并计数”，实际发出未归一化坐标 |

**必须用“稠密往返表”或“精确 n”才能抓到的变异（重要，否则是假测试）**：

- **M5（分母 `extent` vs `extent-1`）在 21 个稀疏用例的落点级 0 命中**。原因是像素是量化的：
  例如桌面宽 3200、`rel=2560` 时 `n=52429` 与 `n=52444` 都解码成 2560。
  ⇒ **只断言稀疏落点的测试无法发现分母错误**。两条可用断言：
  (a) 断言**精确 `n`**（§6.4 的“新 n”列就是为此给出）；
  (b) **稠密往返表**：`desk_w ∈ {1280,1920,3200,3840}`、`rel` 取全部像素，`decode(map(rel)) == rel`。
      实测失配数：`3 / 7 / 20 / 28`（`extent-1` 版） vs `0 / 0 / 0 / 0`（本方案）。
- **M6（中心采样）在稀疏落点级只命中 B0 一个点**，必须配稠密逐像素比较
  （`fw=640,cap=1280` 有 **320/640** 个不同；`fw=1280,cap=3200` 有 **428/1280** 个）。
- 反之，**M1/M2/M3/M4/M8** 在落点级就能命中 2–14 个用例，稀疏落点断言足够。

> **诚实说明（供双审取舍）**：本方案相对现有 `extent-1` 的**像素级收益很小**
> （全表 21 例落点不变；只在稠密表里 3/1280 ≈ 0.23% 的像素上少 1 px 误差）。
> 它的价值是**可证明的互逆性**（能写成 0 容差断言），而不是肉眼可见的改善。
> 如果双审判定“不值得改已有通过的断言”，退路见 §2.4 末尾——但那样必须放弃“往返 0 误差”这条强断言。

完整性自检（第 16 条）：基线绿 → **逐个**变异红（每个变异至少命中一行用例）→ 恢复绿；
基线检查数不得减少；每个变异体必须写命中的**用例名**，禁止只写“某处失败”。
§10 的模型可直接生成“基线值 + 每个变异的期望值”，供测试做对照表。

> 建议的断言组合（能同时覆盖两级）：
> 1. 每个用例断言 `n` 的**精确值**（覆盖 M5/M5b/M6/M6s 的细微差异）；
> 2. 每个用例断言 `decode(n)` 的**落点**（覆盖 M1/M2/M3/M4/M8 的可见错位）；
> 3. `fw=640,cap=1280` 与 `fw=1280,cap=3200` 两组**稠密逐像素**表（覆盖 M6/M6s）；
> 4. `dw ∈ {1280,1920,3200,3840}` 的**稠密往返表**（覆盖 M5/M5b）。

---

## 8. UNVERIFIED 清单（禁止当结论用）

| # | 未验证项 | 为什么重要 | 建议验证方式 |
|---|---|---|---|
| U1 | Windows 真实解码是否 `floor(n*extent/65536)` | 决定 ceil/round（M5b 的方向） | 注入 10 个已知 `n` 后读 `GetCursorPos` 逐点比对（单屏即可） |
| U2 | 反解分母是 `extent` 还是 `extent-1` | 若真是 `extent-1`，§2.4 裁决要反过来 | 同一探针在**中间点**采样（端点两者一致，§6.4 已证） |
| U3 | GDI `StretchBlt(COLORONCOLOR)` 的采样相位（中心 vs 起点） | 步骤 1 可能差 1 px（§2.5：1280→3200 时 428 个像素不同） | 捕获源输出棋盘格，按已知缩放比读回像素反推相位 |
| U4 | 混合 DPI 多屏下 `SM_*VIRTUALSCREEN` 与 `MOUSEINPUT` 绝对空间是否一致 | 决定要不要 DPI 字段 | 2 屏不同缩放，注入 `desktop` 四角并读回 |
| U5 | 显示器热插拔后不重启是否可接受 | 快照几何会过期 | 运行中插拔观察落点；本设计只保证“取租约时复测” |
| U6 | “`dx=0` 在 Win10 FCU 后不生效”的传闻（Chromium 注释 `max(1.0, …)`） | 若成立，左上角 1 px 不可达 | 真机注入 `(0,0)` 读回 `GetCursorPos`；**未证实前禁止加 `max(1,·)`**（会破坏 §2.4 的精确性） |
| U7 | `--monitor N` 的索引稳定性（F8：0=主屏，其余是枚举顺序） | 重启后同一 N 可能指向另一块屏 | 文档化“索引不保证跨重启稳定”；正确性不依赖它（公式用实际矩形） |
| U8 | 多屏**非矩形**布局（L 形/上下错位）时包围盒内的空洞 | 空洞区仍可被点到（物理上有效） | 真机观察；本设计不需要特殊处理（不裁剪到屏幕） |
| U9 | 虚拟桌面宽/高是否可能 > 65536 | 超过后 65536 档位本身无法逐像素寻址（§2.4 第 5 条） | 真机读 `SM_CXVIRTUALSCREEN`；若可达，需在文档中标注“像素级精度上限”，不改公式 |

---

## 9. 落地影响面（排期用，非代码）

| 文件 | 改动性质 |
|---|---|
| `include/rtsc/server/desktop_input.h` | `InjectRect` + `InjectGeometry` 扩字段（`width/height` 保持在前，两参数聚合初始化不变） |
| `include/rtsc/server/server.h` | 新增 `DesktopGeometry` + `virtual DesktopGeometry Geometry() const`（**带默认实现**） |
| `src/server/desktop_gdi.cpp` | `GdiDesktopSourceImpl` 保存并返回 `rect_` + 工厂期 `SM_*VIRTUALSCREEN` 快照 |
| `src/server/server.cpp` | `DoConnectResponse`(1324) 与 `AcquireInputLease`(873) 组装几何；**不改公告尺寸** |
| `src/server/desktop_input_map.cpp` | 用 §3 公式替换 `NormalizeAxis`；`mapped` 门槛；`int64` 中间量 |
| `src/server/desktop_input_win32.cpp` | flag 不变；`SetGeometry` 存全结构 |
| `src/server/desktop_input_null.cpp` | 签名不变（结构体变大） |
| `tests/test_desktop_input.cpp` | 新增 A/B/C/D/E/F/G 用例；**改** `desktop_input_absolute_move_full_range` 期望（§2.4）；新增 `mapped=false`；加 `dwFlags` 断言 |
| `tests/test_server.cpp` | `RecordingInputSink` 记录 `capture/desktop/mapped`；补“租约时复测”用例 |
| `tests/test_desktop_gdi.cpp` | 断言 `Geometry()` 与 `GetMonitorInfo`/`SM_*` 一致；子矩形钳制后的值 |
| `docs/spec/input-injection-evidence.md` | §1.5 公式与 U2 结论同步修订（分母裁决） |
| `CMakeLists.txt` | **无改动**（`desktop_input_map` 已在纯函数库里） |

必须跑的套件（影响面，**不做全量**）：`desktop_input`、`desktop_gdi`、`server`
（含 sink/lease 子集）；构建 **0 error 0 warning**（`/W4 /WX` 已在该库开启
[READ:CMakeLists.txt:890-892]）。真机项按 §8 另列清单。

---

## 10. 附录：可复现的独立模型

```python
def ceil_div(a, b):                 # a >= 0, b > 0
    return -((-a) // b)

def round_div(a, b):                # a >= 0, b > 0, half-up
    return (2 * a + b) // (2 * b)

def map_axis(wire, fb, cap, cap0, desk0, desk_n):
    """wire -> Win32 normalized; exact inverse of floor(n*desk_n/65536)."""
    f = max(0, min(wire, fb - 1))                       # step 0
    local = 0 if fb <= 1 else min(cap - 1, round_div(f * (cap - 1), fb - 1))  # step 1
    phys = cap0 + local                                 # step 2
    rel = max(0, min(phys - desk0, desk_n - 1))         # step 3
    return min(65535, ceil_div(rel * 65536, desk_n))

def decode(n, desk0, desk_n):                            # what the OS does
    return desk0 + (n * desk_n) // 65536
```

自检（实现完成后必须成立）：

- **落点恒等**：对全部 `p ∈ [0, fb)`，
  `decode(map_axis(p, fb, cap, cap0, desk0, desk_n), desk0, desk_n) == cap0 + step1(p)`，
  其中 `step1(p) = round_div(p*(cap-1), fb-1)`（§3 公式本身）。实测 `fb=1280,cap=1920,desk=1920`：
  `0/1310720` 像素失配（§10 实测行）。
- **端点**：`step1(0) == 0`、`step1(fb-1) == cap-1`（捕获矩形两端可达）。
- **1:1 恒等**：`cap == fb` 时 `step1(p) == p`（`BitBlt` 路径零取整）。
- **桌面段**：对 `desk_n ∈ {1280,1920,2560,3200,3840,8192}` 与全部 `p`，
  `decode(map_axis(p, desk_n, desk_n, 0, 0, desk_n), 0, desk_n) == p`（0 失配）。
- **可区分性**：`fb=640, cap=1280` 时 `step1` 与“中心采样”在 **320/640** 个 `p` 上不同，
  与“窗口起点”也在 **320/640** 个 `p` 上不同 ⇒ 稠密用例能把三者分开（§7 M6/M6s）。

本次实测（§6.5）：`ceil` 版 0 失配；`round` 版 512/896/1536/1792/0；`extent-1` 版 3/7/20/28/0。

**本文所有数值的自检记录**（审计期为只读角色，校验脚本未入库；执行 AI 应按下面几项复刻断言）：

| 板块 | 校验方式 | 结果 |
|---|---|---|
| §6.4 落点表（21 行） | 由 `map_axis`/`decode` 重算 `新 n`、`新落点`、`规范落点`、`现有落点`，逐格比对 | 21 行 **0 处不符** |
| §7 变异表 | 重算每个变异的命中用例集合与 n 级/落点级命中数 | 9 行 **全部相符**（含 M5 的“n 级命中 18、落点级 0”） |
| §7 落点示例 | 重算每处 `用例→(x,y)` | 19 处 **0 处不符** |
| §2.5 采样相位差异 | 端点 vs 中心 / vs 起点逐像素统计 | 5 组 **全部相符** |
| §6.5 分母枚举 | 三种分母的往返失配数 | 5 组 **全部相符** |
| §6.1 默认路径 | `fb=1280x1024`、桌面 `1920x1080` 全 1310720 像素 | 旧 max 1 px / 644675 偏离；新 **0 / 0** |

---

## 11. 与既有文档/裁决的冲突登记

| 冲突点 | 既有文本 | 本文裁决 |
|---|---|---|
| 分母 | `input-injection-evidence.md:139,144` 用 `(virtual.width-1)`，称“官方未规定” | 改判为 `65536/width` + `ceil`（依据 Wine/ReactOS 解码源码 + 往返 0 误差） |
| 端点断言 | `tests/test_desktop_input.cpp:272-279` 钉 `(1920,1080)→65535` | 期望改为最后一像素的精确值（`n=65502`），或改断言为“落点 == 1919”；**禁止放宽容差** |
| `InjectTarget` 草案 | `input-injection-evidence.md:363-369` 的 `InjectTarget{left,top,width,height,vleft,vtop,vwidth,vheight}` | 本定案与之一致（字段一一对应）；明确“不加 `use_virtual_desk`、不加 DPI” |
| 接口注记 | `input-injection-seam.md:87-89` 的 `InjectGeometry` 注释明写“没有 origin、没有 virtual_desktop 标志，见 §1.7 第 2 条” | 本文即为该注记的定案答案：`InjectGeometry` 扩为 §4.1，`DesktopSource` 扩为 §5 |
| `--monitor N` 状态 | `input-batch12-review-I.md` C2、`input-batch14-review-K.md` K4 标 OPEN | 本文关闭**设计**部分；真机落点仍为 §8 U1/U2 |
| 探针自证 | `evidence/input-inject-mapping-probe.txt:38-44` 的“往返 0 误差” | 该探针用同一条公式正反算，**不构成**分母证据（§2.3） |

---

## 12. 问题 → 答案索引（对任务清单逐条）

| 任务问题 | 答案位置 | 一句话结论 |
|---|---|---|
| 1a 正确映射公式（含取整） | §3.2、§2.5 | 步骤 0 钳制 → 步骤 1 `round(x*(cw-1)/(fw-1))` → 步骤 2 `+capture_origin` → 步骤 3 `ceil(rel*65536/desk_w)` |
| 1b `MOUSEINPUT` 原文 | §2.1 | `ABSOLUTE` 归一化 0..65535，两端点对应域两角；`VIRTUALDESK` 把域改成整个虚拟桌面 |
| 1c 成熟实现对照 | §2.3 | Wine/ReactOS 反解 `floor(n*w/65536)`；Chromium `ui/base` 正向 `ceil(p*65536/w)` 与本文一致；FreeRDP 手工加 origin 但域固定主屏；rdev 落点等价 |
| 1d 分母是 `宽-1` 还是 `宽` | §2.4、§6.5 | **用 `宽`（`65536/宽`，向上取整）**；`宽-1` 与解码不互逆（1280 宽有 3 个像素偏 1） |
| 2 `InjectGeometry` 目标结构 | §4.1、§4.2 | `width/height` + `capture{4}` + `desktop{4}` + `mapped`；不加 DPI、不加 `use_virtual_desk` |
| 3 `DesktopSource` 接口扩展 | §5 | 选方案 ④：`virtual DesktopGeometry Geometry() const` 带默认实现 |
| 4 变异清单（≥4） | §7 | M1 忽略 capture origin、M2 忽略 capture extent、M3 忽略 desktop origin、M4 归一化域用捕获矩形、M5/M5b 分母、M6/M6s 采样相位、M7 flag、M8 origin 符号、M9 `mapped` 恒真 |
| 5a `--monitor -1` 现在是否正确 | §6.1 | 方向正确，`fb != 桌面` 时 49.18% 像素有 1 px 误差 |
| 5b `--monitor N` 与子矩形错位是否不同 | §6.2 | 机理相同（小的当大的）；数值不同（纯平移 vs 平移+缩放） |
| 5c 数值例 monitor1(1920,0) 1280x1024 客户端 (640,512) | §6.3 | 应落 `(2560,512)`；现有实现落 `(1601,512)`，偏 −959 px 且**跨屏** |

---

## 13. 实证探针（红证 → 绿证，可复跑）

本节回应“未实证不报缺陷”：缺陷结论来自**对可执行产物跑探针**，不是阅读推断。
探针未入库（审计角色只写本文件），但源码、编译命令与输出全部在下面，可逐字复现。

### 13.1 红证：对 shipped lib 实测

探针链接仓库已有的 `build/Release/rtsc_server_desktop_input_map.lib`
（SHA256 `096C1270790BB07A6BC4E67F4923F8193AB9E7984E5FA6E3E302F45D0CEB0067`，2026/11/2 10:23:01 构建），
用**当前服务端真实传入的** `InjectGeometry{fbw, fbh}`
（[READ:src/server/server.cpp:1368] 只填宽高）调用 `TranslateInput`，
再按 Wine/ReactOS 的解码语义 `origin + floor(n*extent/65536)` 还原落点。

```text
A2 wire n=(32793,32800) actual landing=(1601,512) expected n=(52429,32768) expected landing=(2560,512)
[RED] A2 lands on monitor 2: actual=(1601,512) expected=(2560,512) delta=(-959,0)
[RED] A2 x within 1px of reference: actual=(1601,512) expected=(2560,512) delta=(-959,0)
A1 wire n=(0,0) landing=(0,0) expected=(1920,0)
[RED] A1 lands on selected monitor origin: actual x=0 expected 1920

3 failing probe(s)          (exit=1)
```

**结论（红证成立）**：`--monitor 1` 下客户端点 (640,512) 实际落到 **第一块屏 (1601,512)**，
应在 **第二块屏 (2560,512)**，偏 **−959 px**；点 (0,0) 落到 (0,0) 而非选中屏原点 (1920,0)。
这不是“差 1 px”，是**跨屏**。

### 13.2 绿证：同一探针跑设计实现

把 §3.2 / §4.1 的实现写成独立副本
（`geom_green/map_fixed.cpp`，含 `InjectRect capture/desktop` + `mapped`），
同一组 21 个用例 + 稠密往返：

```text
[GREEN] A1 wire n=(39322,0) landing=(1920,0) expected=(1920,0)
[GREEN] A2 wire n=(52429,32768) landing=(2560,512) expected=(2560,512)
[GREEN] A3 ... [GREEN] G2   (21/21 全绿)
[GREEN] dense round trip 1280/1920/3200/3840: 0 mismatch(es)

0 failing green-probe check(s)      (exit=0)
```

同时验证了 §2.4：E3（fb 1280x1024、捕获 1920x1080、点 (1279,1023)）得到 `n=65502`，
解码回 1919 —— 即 `extent-1` 的 65535 约定会把最后一个像素“钉”在 65535 而牺牲互逆性。

### 13.3 探针位置与复跑方式

| 用途 | 路径（临时目录，未入库） |
|---|---|
| 红证探针源 | `%TEMP%\opencode\probe_input_geom.cpp` |
| 红证日志 | `%TEMP%\opencode\probe_red.log` |
| 绿证实现 | `%TEMP%\opencode\geom_green\map_fixed.cpp` |
| 绿证探针源 | `%TEMP%\opencode\geom_green\probe_green.cpp` |
| 绿证日志 | `%TEMP%\opencode\probe_green.log` |

复跑（红）：

```text
cl /nologo /std:c++20 /EHsc /MD /W4 /I F:\rtsc\include probe_input_geom.cpp ^
   /Fe:probe_input_geom.exe F:\rtsc\build\Release\rtsc_server_desktop_input_map.lib
```

复跑（绿）：

```text
cl /nologo /std:c++20 /EHsc /MD /W4 /I geom_green\include ^
   probe_green.cpp geom_green\map_fixed.cpp /Fe:probe_green.exe
```

执行 AI 落地后，应把 §7 变异表转成 `tests/test_desktop_input.cpp` 的断言；
红证对应的回归断言建议直接写成本节的 A1/A2 两条（跨屏是最强的可观测判据）。
