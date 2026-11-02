# `--monitor N` 注入坐标错位：第二审计（N）交叉验证报告

角色：审计 AI-N（只读）。唯一写入文件：本文件。
基线：`docs/spec/input-geometry-design-M.md`（653 行）。本报告**不采信** M 的结论，全部数值由 N 自建探针独立跑出。
探针位置：`%TEMP%\opencode\probe_n\`（工作树零写入）。真机环境：Windows 10 Pro 25H2 (build 26200)，单屏物理 2560x1440、系统 DPI 120、默认 2048x1152。

---

## 0. 四项裁决

| 项 | 裁决 | 一句话 |
|---|---|---|
| 1 分母 | **CONDITIONAL（接受 65536+ceil，但必须改成"末像素保留 65535"的混合式）** | 纯 `ceil` 会打断钉子断言；混合式两全 |
| 2 采样相位 | **FAIL（M 选端点锚定，与 GDI 实测不符）** | GDI 实测是**中心采样**，全部 21 组比例 0 失配 |
| 3 M5 可测性 | **PASS（可测，M 的"落点级 0 命中"是稀疏用例选的不好，不是原理性不可测）** | 单点 `w=1280, rel=1` 即可杀 M5 |
| 4 字段集 | **CONDITIONAL（字段够用，但缺少"DPI 语境可信"这一位）** | `SM_*` 在 DPI 语境不可信时会静默给出缩放值 |

---

## 1. 分母裁决（最关键）

### 1.1 官方原文（逐字）

[MOUSEINPUT 文档](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-mouseinput) Remarks：

> "If **MOUSEEVENTF_ABSOLUTE** value is specified, **dx** and **dy** contain normalized absolute
> coordinates between 0 and 65,535. … Coordinate (0,0) maps onto the upper-left corner of the
> display surface; coordinate (65535,65535) maps onto the lower-right corner."
> "If **MOUSEEVENTF_VIRTUALDESK** is specified, the coordinates map to the entire virtual desktop."

结论：文档只承诺**两个端点的落点**，**没有**规定"65535 个格如何摊到 w 个像素"。因此"归一化到 65535"
（`/(w-1)`）与"按 65536 等分"（`/w`）在文档层面**都合法**，唯一判据是**解码是否逐像素互逆**。

### 1.2 解码公式：真机实测（不是源码推测）

Wine `dlls/win32u/input.c::update_mouse_coords()`：

```c
input->mi.dx = rc.left + ((input->mi.dx * (rc.right - rc.left)) >> 16);
```

ReactOS `win32ss/user/ntuser/mouse.c::UserSendMouseInput()`（实际抓取 `raw.githubusercontent.com/reactos/reactos/master`）：

```c
ptCursor.x = pmi->dx * UserGetSystemMetrics(SM_CXVIRTUALSCREEN) >> 16;
ptCursor.y = pmi->dy * UserGetSystemMetrics(SM_CYVIRTUALSCREEN) >> 16;
```

两处都漏看负原点（ReactOS 更明显），但**都确实是 `>>16`、分母是 extent**。

**N 的真机红证**（`probe.exe`，`SendInput(MOVE|ABSOLUTE|VIRTUALDESK)` → `GetCursorPos`）：

```
SM_VIRTUALSCREEN=(0,0,2560,1440)   dpi=120
x 轴 4179 个采样点（n∈[0,4096) ∪ 64×1024 步长 ∪ 近端点 16×256 步长）:
  floor(n*w/65536)         mismatch=0
  round(n*w/65536)         mismatch=2051
  ceil(n*w/65536)          mismatch=4067
  floor(n*(w-1)/65535)     mismatch=217
  round(n*(w-1)/65535)     mismatch=1955
y 轴 685 个采样点（extent=1440）:
  floor(n*h/65536)         mismatch=0
  round(n*h/65536)         mismatch=343
  ceil(n*h/65536)          mismatch=684
  floor(n*(h-1)/65535)     mismatch=332
  round(n*(h-1)/65535)     mismatch=167
```

⇒ Windows 解码确定为 **`phys = origin + floor(n * extent / 65536)`**。这是**真机证据**，
不是 M §2.2 的"证据强度：中"推断；M 的 U1/U2 可以关闭。

### 1.3 正向公式：M 的 `ceil` 对，但**不能直接落地**

`ceil(rel*65536/w)` 与解码互逆的证明（M §2.4 第 1 条）**N 复算成立**，全像素 0 失配：

```
w=1280 ceil 0 | w=1920 ceil 0 | w=2560 ceil 0 | w=3200 ceil 0 | w=3840 ceil 0 | w=8192 ceil 0
w=1280 old 3  | w=1920 old 7  | w=2560 old 8  | w=3200 old 20 | w=3840 old 28
```

M 声称的 `3/7/20/28` **可复现**（N 独立跑出同一组数；`8192` 是 0，M 也这么写）。
但 M 的表格**漏了 2560**（=8），而 2560 是本机实际宽度，应在表里。

**N 发现的 M 遗漏（关键）**：`ceil` 在**末像素**给出 `ceil((w-1)*65536/w) = 65536 - ceil(65536/w)`，
对 `w=1920` 是 `65502`，**不是 65535**。M 接受这一点并主张改钉子断言。

N 的**混合式**同时满足两件事：

```
on-wire(rel, w):
    if rel >= w-1: return 65535            // 末像素保留文档承诺的右下角
    return ceil(rel * 65536 / w)           // 内部像素与 floor(n*w/65536) 严格互逆
```

**N 的 C++ 红绿证**（`redgreen.cpp` + 仓库**真实** `desktop_input_map.cpp`，`/W4 /WX` 零警告）：

| 变体 | 断言 A `wire(1,1),w=1280 → 落点 1` | 断言 B 钉子 `wire(w,w) → 65535` | 稠密 `w=1280` 全像素往返 |
|---|---|---|---|
| 仓库现状（extent-1） | **RED**（n=51 → 落点 0） | GREEN | **RED**（3 失配） |
| M 的纯 ceil | GREEN（n=52 → 1） | **RED**（n=65485，M 自己说是 65502；实测同域） | GREEN |
| **N 的混合式** | GREEN | **GREEN（65535）** | **GREEN（0 失配）** |

```
A: wire(1,1) fb=1280 -> n=51 land=0        [FAIL]   <- 现状
B: wire(1280,1280) fb=1280 -> n=65535 land=1279  [ OK ]
C: dense w=1280 mismatches=3                     [FAIL]
RED: 2 failures
--- 换成混合式 ---
A: wire(1,1) fb=1280 -> n=52 land=1        [ OK ]
B: wire(1280,1280) fb=1280 -> n=65535 land=1279  [ OK ]
C: dense w=1280 mismatches=0                     [ OK ]
GREEN: 0 failures
--- 换成 M 的纯 ceil ---
B: wire(1280,1280) fb=1280 -> n=65485 land=1279  [FAIL]
RED: 1 failures
```

**裁决**：接受"分母用 65536、编码用 ceil"的**实质**（与解码互逆、0 容差可写成强红证），
但**采纳混合式**（内部 ceil + 末像素 65535）。理由：

1. 收益不变：内部像素仍是 0 失配；N 实测默认路径 `fb=1280x1024 → 2560x1440`
   现状 **650/1280 像素偏（max 2px）**，混合式 **0/1280**。
2. **不必改钉子断言** `tests/test_desktop_input.cpp:272-279`：`(1920,1080)→65535` 继续成立。
   这消除了 M §2.4 "改一条已绿断言"的全部风险，并且**避免实现反推期望** ——
   65535 来自文档原文（"65535 → 右下角"），不是从代码反推。
3. 混合式在 `w ∈ {2,3,4,5,7,10,640,800,1000,1024,1080,1152,1280,1440,1920,2048,2560,3200,3840,4096,8192,16384,65535,65536}`
   全部往返 0 失配，且 24 个宽度全部单调（`geo_probe.exe` 实测 `ALL GREEN (0 failures)`）。
4. 仅"末像素"退化为文档的端点承诺，代价是：末像素与次末像素之间的一格不可达
   （`rel=w-2` 的 n 与 `rel=w-1` 的 65535 都是最后一像素的候选）。
   但对 1:1 捕获（BitBlt 分支、最常见的 `--monitor N` 且 fb==捕获）**完全无影响**：
   此时 `fb==cap`，像素级恒等。

### 1.4 是否值得动这条已绿断言

**不值得动。** M 自己承认"像素级可见收益仅 3/1280"。N 的结论：

- 若采纳纯 ceil：收益 3/1280 像素的 1px，代价是**改一条已通过、且由官方文档原文直接支撑的断言**，
  并且新期望 65502 **只能由实现反推**（规范没有给出这个数），属于"期望来自实现"的反模式。
- 若采纳混合式：**同样的 0 失配收益，零断言改动，期望仍来自规范原文**。
  这才是"改动最小、证据最强"的落法。

---

## 2. 采样相位（M 步骤 1）

### 2.1 M 的判断是错的

M §2.5 选 `lx = round(x*(cw-1)/(fw-1))`（端点锚定），并在 §8 U3 承认"与 GDI 可能差 1px"。
**N 实测：不是"可能差 1px"，是根本不成立。**

`StretchBlt(COLORONCOLOR)` 真机实测（`g2d.exe` / `phase3.exe` / `near1.exe`，
DIB→DIB 与 **屏幕 DC→DIB** 两条路径都跑，结果一致）：

```
src=1280x1024 dst=640x512    A=245760  B=0    C=327680   of 327680
src=1280x1024 dst=800x600    A=148672  B=0    C=465920   of 480000
src=3200x2560 dst=1280x1024  A=729656  B=0    C=1310720  of 1310720
src=1920x1080 dst=1280x1024  A=20480   B=0    C=998400   of 1310720
src=1280x1024 dst=1920x1080  A=364800  B=0    C=1346560  of 2073600
src=1920x1080 dst=2560x1440  A=0       B=0    C=1612800  of 3686400
src=3840x2160 dst=1920x1080  A=1555200 B=0    C=2073600  of 2073600
（A=端点锚定, B=中心采样 floor(((2x+1)*cap)/(2*fb)), C=窗口起点 x*cap/fb）
```

**B（中心采样）在每一个比例上都是 0 失配**，包括 2x 精确缩放、1:1、缩小、放大、非整数比、
`1920→1919` 这类差 1px 的近似。点采样证据更直观（`small.exe`，7→3）：

```
sw=7 dw=3 mode=3 map=1,3,5     <- 中心采样 (1,3,5)；端点锚定会给出 (0,3,6)
```

**像素级实证**（`dbg.exe`，源码像素值=x）：
```
src 1280x1024 -> dst 640x512, dst row0 = 4097,4099,4101,4103
=> (gx,gy) = (1,1),(3,1),(5,1),(7,1)   —— 源像素 (1,1) 而非 (0,0)
```

### 2.2 结论

| 候选 | 与 GDI 实测一致？ | 证据 |
|---|---|---|
| **B 中心采样** `floor(((2x+1)*cap)/(2*fb))` | **是（21 组比例全部 0 失配）** | 上表 + 屏幕 DC 路径 |
| A 端点锚定（M 选的） | **否**（缩小/2x 场景 50% 像素全错） | `A=245760/327680` |
| C 窗口起点 | 否（几乎 100% 错） | `C=327680/327680` |

⇒ **M 步骤 1 必须改成中心采样**（`floor`，不是 round；实测就是 floor）。
M 把它标成 UNVERIFIED 是不够的 —— 这不是"未验证"，是**已验证与所选公式相反**。
这一条**必须在实现前修正**，否则 `--monitor N` 会稳定偏 1px（默认路径 `fb=1280 cap=2560` 时
端点锚定 640/1280 像素错，中心采样 0）。

对照 M 的自我表述："A 与 B 在 cw==fw 时完全相同"——**正确，但这正是它无法被 1:1 用例发现的原因**；
而仓库默认 `--monitor -1` 在 `fb != 桌面` 时**恰好不是 1:1**，所以这条错误会直接暴露在默认路径上。

---

## 3. M5 落点级 0 命中 ⇒ 可否被测住

### 3.1 裁决：**可以测住**，M 的"只能靠稠密表"是**用例选择问题**

M §7 说 M5 在 21 个稀疏用例上落点级 0 命中。N 复算成立（`mut2.py`）：

```
M5 denom extent-1   n_hits=18   land_hits=0
```

原因是 M 的 21 个用例的 `rel` 恰好都落在"extent-1 与 ceil 解码相同"的位置
（多为 0、末像素、或量化后同格）。**换一个 rel 就能杀它**：

```
w=1280, rel=1:
   ceil   n=52  -> 落点 1     ✓
   extent-1 n=51 -> 落点 0     ✗（偏 1px）
   round  n=51  -> 落点 0     ✗
w=1920, rel=1: ceil 35->1 | extent-1 34->0 ✗   (round 同 ✗)
w=3200, rel=1: ceil 21->1 | extent-1 20->0 ✗
w=3840, rel=1: ceil 18->1 | extent-1 17->0 ✗
```

### 3.2 最小断言（给定/当/则）

> **给定** 1:1 捕获几何（capture == desktop，`fb = desktop = 1280×1024`），客户端坐标域为 `[0,1280)`；
> **当** 注入 `kMouseMove` 于 `(x,y) = (1,1)`；
> **则** `TranslateInput` 产出的 `PlatformInput.x == 52 && .y == 52`（精确 n），
> 且 `decode(n, 1280) == 1`（落点 == 1，**禁止放宽容差**）。

这一条同时杀 M5（extent-1 → 51）与 M5b（round → 51），**不需要稠密表**。
再加两条可覆盖全轴：

- 稠密表：`w ∈ {1280,1920,2560,3200,3840}`，`rel` 取全部像素，`decode(map(rel)) == rel`。
- `(0,0) → 0`、`(w-1,w-1) → 65535`（末像素保留，混合式下成立）。

**已在 C++ 层验证该断言红/绿**（`redgreen.cpp`，见 §1.3）：现状 RED、混合式 GREEN。
所以这条断言不是"纸面设计"，是**可执行的红证**。

---

## 4. `InjectGeometry` 字段集

### 4.1 最小集：同意 M 的 4+4+1，但要补一个 DPI 可信位

```cpp
struct InjectRect { int32_t x=0, y=0, width=0, height=0; };
struct InjectGeometry {
    uint16_t width=0, height=0;   // 协商并钳制后的 framebuffer（客户端域）
    InjectRect capture;           // 捕获矩形，虚拟屏物理像素
    InjectRect desktop;           // 归一化域 = SM_*VIRTUALSCREEN 包围盒
    bool mapped=false;            // capture/desktop 是否可信
    // N 新增：几何快照的 DPI 语境是否可信（见 4.3）
    bool pixels_are_physical=false;
};
```

**不加 DPI 数值**（同意 M：Win32 没有"按 DPI 归一化"的注入入口，加数值只会造第二套语义）。
**不加 `use_virtual_desk`**（同意 M：恒发 `VIRTUALDESK` + 域填包围盒在所有布局下自洽；
仓库内没有"只投主屏"的需求）。

### 4.2 混合 DPI 是否会丢信息：**不会**（已实测）

`SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` 是**进程级**，且**对既有线程生效**：

```
main before: awareness=0 SM_VS=2048x1152 DESKTOPHORZRES=2560x1440
set PMv2 prev=1 err=0
main after:  awareness=2 SM_VS=2560x1440 DESKTOPHORZRES=2560x1440
worker(before-change, after main set): awareness=2 SM_VS=2560x1440   <- 老线程也升级
  worker inject n=1000 -> y=21  (1440-space=21, 1152-space=17)
```

⇒ 注入 worker 与捕获在同一 DPI 语境，`SM_*` 与绝对空间同源。M §3.3 的推理**成立**。

### 4.3 N 的独立发现：M 把 F13 当成保证，实测是"best effort"

`desktop_gdi.cpp:63-65`：

```cpp
void EnablePerMonitorDpiAwareness() {
    (void)::SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
}
```

返回值被丢弃。N 实测**失败路径真实存在**：

```
set PMv2 again -> prev=0 err=5 (ERROR_ACCESS_DENIED)
after SYSTEM attempt: awareness=2 SM_VS=2560x1440   （进程已固定，改不了）
默认（未设置时）: awareness=0 SM_VS=2048x1152  DESKTOPHORZRES=2560x1440
```

即：**若进程 DPI 语境不是 PMv2**（manifest 已固定 / 宿主提前设过 / 调用被拒），
`SM_CXVIRTUALSCREEN` 返回 **2048×1152**，而真实物理桌面是 **2560×1440** —— 相差 512×288。

后果：`desktop` 字段会是错的包围盒，`capture` 也会是错的（`ResolveCaptureRect` 用同一批 `SM_*`）。
而 `MOUSEINPUT` 的绝对空间按**注入进程的 DPI 语境**解释；只要注入侧也是 unaware，
两者"自洽地错" —— 但**一旦捕获侧与注入侧语境不同**（例如嵌入方在 `SetProcessDpiAwarenessContext`
之后再创建捕获源、或另一模块改过语境），就会整体错位。

⇒ **必须**把"这批 SM_* 是否物理像素"记进几何（`pixels_are_physical`），
并在 `false` 时 fail-closed（`mapped=false`，丢弃绝对移动）或改用
`GetDeviceCaps(DESKTOPHORZRES/DESKTOPVERTRES)` 校正。M 的 §3.3 第 4 条把它列入 U4，但
**没有把它做成字段**，这是信息丢失（不可观测、不可 fail-closed）。

顺带：同一次实测里 `DESKTOPHORZRES=2560x1440` 在 unaware 语境下**仍然是物理值**，
所以 `GetDeviceCaps` 是该场景下唯一可信的来源——这条应写进方案。

---

## 5. 其余复核（与 M 一致 / 不一致）

| M 的断言 | N 复核 | 证据 |
|---|---|---|
| §6.4 21 行落点表 | **数值全对** | `mut2.py` 逐行重算，21/21 相符 |
| §7 M1/M2/M3/M4/M8 落点级 13/4/2/14/13 | 相符（M2 N 算 5，M 写 4） | `mut2.py`（M2 漏了 B0） |
| §7 M5b round 落点级 7 | 相符（N 算 8，多 B0） | 同上 |
| §7 M6 中心采样只命中 B0 | 相符 | 同上 |
| §6.1 默认路径 644675/1310720 = 49.18% | **可复现**（N 独立算出 644675/1310720） | `extra.py` |
| §6.3 `(2560,512)` / 现有 `(1601,512)` | 相符 | `table.py` |
| §2.4 ceil 往返 0 失配 | 相符 | `final.py` / `geo_probe.exe` |
| §2.5 A vs B/C 差异数（320/640 等） | 相符 | `extra.py` |

**需要注意的 M 自身不一致**：§6.1 说"新公式同例 max_err=0" 用的是端点锚定 oracle；
N 用**GDI 真值**（中心采样）重算：M 的设计在 `fb=1280x1024→2560x1440` 上仍有 **640/1280 像素偏 1px**
（= 50%），因为端点锚定本身错了。所谓"0 误差"是**对错误 oracle 的 0 误差**。

---

## 6. 变异清单复核（第 16 条）

N 用独立模型复算了 M §7 全部变异（`mut2.py`）：

| 变异 | M 声称 n/落点 | N 实测 n/落点 | 判定 |
|---|---|---|---|
| M1 忽略 capture origin | 13 / 13 | 13 / 13 | 相符 |
| M2 忽略 capture extent | 4 / 4 | **5 / 5**（含 B0） | M 少算 1 |
| M3 忽略 desktop origin | 2 / 2 | 2 / 2 | 相符 |
| M4 域用捕获矩形 | 14 / 14 | 14 / 14 | 相符 |
| M5 extent-1 分母 | 18 / **0** | 18 / **0** | 相符（见 §3：换 rel=1 即可命中） |
| M5b round 分母 | 7 / 7 | **8 / 8**（含 B0） | M 少算 1 |
| M6 中心采样 | 1 / 1 | 1 / 1 | 相符 |
| M6s 窗口起点 | 4 / 4 | **5 / 5**（含 B0） | M 少算 1 |
| M8 origin 取反 | 13 / 13 | 13 / 13 | 相符 |

**M5 的关键补强**：只要把用例里的 `(0,0)` / `(w-1,h-1)` 换成 `(1,1)`（或任何 `rel < w` 的
小值），M5 就从"落点级 0 命中"变成"落点级命中"。M 的"必须靠稠密表"是**用例没选好**，
不是原理性不可测（§3 已给最小断言，并在 C++ 层验证红/绿）。

---

## 7. 最终建议

**是否可进入实现：CONDITIONAL — 需先修正 3 处，否则不可进入。**

必须先改的 3 处：

1. **步骤 1 换成中心采样** `floor(((2*x+1)*cap)/(2*fb))`，不是端点锚定。
   M 把它当 UNVERIFIED；N 已实测**验证为相反**（21/21 组 0 失配 vs 端点锚定的 50% 错）。
2. **步骤 3 用混合式**（内部 ceil(`rel*65536/w`)，末像素 `65535`）。
   这样钉子断言 `test_desktop_input.cpp:272-279` **不必改**，期望来自文档原文而非实现反推。
3. **`InjectGeometry` 加 `pixels_are_physical`**（或等效的 `dpi_ok`），
   `false` ⇒ `mapped=false` + fail-closed。`EnablePerMonitorDpiAwareness` 的返回值必须检查
   （实测可直接 `err=5` 失败，`SM_*` 给出 2048×1152 而真实 2560×1440）。

可以保持 M 的其余结构：`InjectRect`/`DesktopGeometry` 方案④（`virtual` + 默认实现）、
`mapped` 门槛、恒发 `VIRTUALDESK`、不加 DPI 数值、不加 `use_virtual_desk`、`int64_t` 中间量、
按钮/滚轮/键盘不受几何影响。

**必须补进验收的新断言**（N 已在 C++ 层验证红/绿）：

- `wire(1,1)` @ `fb=desk=1280` ⇒ `n==52` 且 `decode==1`（杀 M5/M5b；现状 RED）
- `wire(w-1,w-1)` ⇒ 落点 `w-1`（中心采样下 `(639,639)` @ 640 也成立，覆盖放大/缩小）
- `(1280x1024) → (2560x1440)` 稠密往返 == 中心采样真值（杀端点锚定；现状 50% 偏）
- `dwFlags` 含 `VIRTUALDESK`（M7）
- `pixels_are_physical=false` ⇒ 绝对移动被丢弃并计数

**未验证项（诚实登记）**：

- `dx=0` 在 Win10 FCU 后不生效的传闻（M §8 U6）：N 实测 `n=0 → 落点 0` **正常工作**，
  本机不支持该传闻；但 Chromium `ui/base` 仍保留 `max(1.0,…)`，故**不建议**加 `max(1,·)`。
- 多显示器负原点布局：本机单屏，无法实测。Wine/ReactOS 源码显示会加 origin
  （Wine 加、ReactOS 历史版漏），**需真机双屏验证**后才能关闭 M §8 U8/U4。
- `--monitor N` 的注入侧尚无活跃真机用例（本报告的真机数据来自独立探针，不是本仓进程）。
