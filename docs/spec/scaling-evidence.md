# mstsc 缩放/插值行为：二进制取证 + GDI 实测 + 对齐契约

目标：`C:\Windows\System32\mstscax.dll`（9,166,848 B；SHA-256 前缀 `d73c76d65721043c`；PDB `mstscax.pdb`）。
工具：REA 6.7 + Ghidra 12.1.4（PE x86-64）；Win32 GDI 实测探针（本机，`%TEMP%\opencode\`）。

> 本文档是「缩放对齐」批次的**唯一契约**。旧版 §2/§3/§4 中「整数倍也要平滑」「2x 块复制=不一致」等结论已被第 5 节实测推翻，已合并删除，勿再引用历史版本。

## 1. 二进制观察（反编译原文，未加解释）

### E1 主绘制路径 `mstscax.dll!FUN_18003444c`（0x18003444c，24,062 字节）

```c
SetStretchBltMode(hdc, 4);
SetBrushOrgEx(hdc, 0, 0, (LPPOINT)0x0);
...
if ((local_108 == 100) &&
    ((local_e0 == 0 ||
      (iVar10 = FUN_180036ba0(*(undefined8 *)(param_1 + 0xe0),
                              *(undefined4 *)(param_1 + 200),
                              *(undefined4 *)(param_1 + 0xcc)), iVar10 != 0)))) {
    ...
    if ((param_7 == 1.0) && (param_8 == 1.0)) {
        BVar9 = BitBlt(hdc, LVar20, LVar22, iVar10 - LVar20, iVar18 - LVar22,
                       param_2, LVar20, LVar22, 0xcc0020);
    } else {
        fVar23 = ceilf(((float)LVar20 - (float)param_5) / param_7);
        fVar24 = ceilf(((float)LVar22 - (float)param_6) / param_8);
        fVar25 = floorf((float)(iVar18 - LVar22) / param_8);
        fVar26 = floorf((float)(iVar10 - LVar20) / param_7);
        BVar9 = StretchBlt(local_c8, LVar20, local_a8.top, iVar10 - LVar20,
                           iVar18 - LVar22, local_d0, (int)fVar23 + param_5,
                           (int)fVar24 + param_6, (int)fVar26, (int)fVar25,
                           0xcc0020);
    }
```

属性来源：`(*pcVar3)(..., "EnableSmartSizing", &local_e0)`、`(*pcVar3)(..., "ZoomLevel", &local_108)`，且 `local_108` 与 **100** 比较。

### E2 常量语义（Windows SDK `um/wingdi.h`，独立确证）

```c
#define BLACKONWHITE  1
#define WHITEONBLACK  2
#define COLORONCOLOR  3
#define HALFTONE      4
#define STRETCH_HALFTONE  HALFTONE
```
即 `SetStretchBltMode(hdc, 4)` = **HALFTONE**。

### E3 交叉佐证

- `FUN_180191d30`（worker DC）：`GetDC` 后同样 `SetStretchBltMode(hdc, 4)` + `SetBrushOrgEx(hdc, 0, 0, NULL)`。
- `FUN_1804cfb98`：尺寸相同时不改模式；不同时 `mode = SetStretchBltMode(param_2, 4)`，结束 `SetStretchBltMode(param_2, mode)` 恢复。
- `StretchBlt` 共 8 个引用点，分布在 0x18003444c(2)、0x180068828(2)、0x180191d30(2)、0x1804cfb98(1)，另 1 处不在函数体内。

### E5 1:1 判定器 `FUN_180036ba0`（0x180036ba0）

```c
if ((((*(int *)(param_1 + 0x68) - *(int *)(param_1 + 0x60) == param_2) &&
     (uVar2 = uVar1, *(int *)(param_1 + 0x6c) - *(int *)(param_1 + 100) == param_3)) &&
    (*(int *)(param_1 + 0x50) == 0)) &&
   (((*(int *)(param_1 + 0x58) == param_2 && (*(int *)(param_1 + 0x54) == 0)) &&
    (*(int *)(param_1 + 0x5c) == param_3)))) { uVar2 = 1; }
```
→ 1:1 判据是**桌面宽高与目标宽高相等 + 四个偏移/尺寸字段为 0**，外层再与 `ZoomLevel == 100` 相与。是**整数尺寸相等**判定。

### E6 相关属性字符串

`ZoomLevel`(0x1806adfe0)、`EnableSmartSizing`(0x1806adff0)、`DesktopScaleFactor`(0x1806b9928)、`DeviceScaleFactor`(0x1806b9978)、`"SetZoomLevel failed!"`(0x1807a39c0)。

### E7 GDI HALFTONE 实测（本机探针，父代理与两位审计各自独立复跑）

`%TEMP%\opencode\arb\arb.exe`（DIB→DIB，`SetStretchBltMode(HALFTONE)` + `SetBrushOrgEx(0,0)`）：

```
16x1 alt{0,255} -> 8x1 (0.5x)     R: 127 127 127 127 127 127 127 127
4x4 1px checker -> 2x2            R: 128 128 128 128
32x32 1px checker -> 4x4          R: 128 (16 个)
16x1 ramp(3x+1) -> 8x1            R: 1 8 14 20 26 32 38 46
8x1 alt -> 16x1 (2x)              R: 0 0 255 255 0 0 255 255 ...   (块复制)
1080p 1px vstripes -> 4K (2x)     distinct = 2                     (块复制)
1080p step edge -> 5760x3240 (3x) distinct = 2                     (块复制)
1080p step edge -> 1.37x          distinct = 2                     (块复制)
1080p ramp -> 1536x864 (0.8x)     distinct = 256                   (平均)
```

另经审计独立验证（`probe_gdi9`）：GDI **完全不处理 alpha**（0.5x alpha 硬边输出全 0）。
`probe_gdi13`：1px **二维**棋盘在 2x 时 GDI 压平为 128，但该行为**随图像尺寸翻转**（8x8→distinct=1、64x64→distinct=2、256x256→distinct=1）→ 属 HALFTONE 抖动伪影，**不稳定，不可作为契约**。

## 2. 契约（观察级结论，可引用）

| 情形 | mstsc 实际行为 | 依据 |
|---|---|---|
| scale == 1.0（两轴尺寸相等 + 零偏移） | `BitBlt(SRCCOPY)`，逐像素精确、无插值 | E1 / E5 |
| scale > 1（含 2x/3x 与 1.37x/1.5x 等非整数） | **最近邻族**：每个目标像素是某个源像素的精确副本；不产生新颜色 | E7（distinct=2、blended=0） |
| scale < 1（含整数比 0.5x/0.25x） | **近似面积平均**（GDI 的结果与精确 box 有 ±4/255 量级偏差） | E7 + 两位审计独立实测 |
| alpha | GDI 完全不处理（保持源值/0） | probe_gdi9 |

## 3. 与当前实现的差距（`src/client/view.cpp`，sha256 1615c8f8…）

| 项 | 现状 | 契约 | 判定 |
|---|---|---|---|
| 1:1（零偏移） | `:93-101` 逐行 `memcpy` | `BitBlt` SRCCOPY | 一致 |
| 1:1（居中/letterbox，vt.x/y≠0） | 落到 `k==1` 块路径，1.92ms | 应仍为精确拷贝 | 结果正确但慢 10x |
| 整数倍放大 2x/3x | `:107-142` 块复制 | 最近邻族 | **一致** |
| 非整数放大 1.37x/1.5x | `:144-218` **双线性** | 最近邻族 | **不一致** |
| 降采样 0.5x/0.8x | `:153-190` **抽点**（`uu=i*sw/dw` 取左上角，0.5x 恒偶数） | 面积平均 | **不一致（缺陷）** |
| alpha | `:216` `d[3]=p00[3]` 只取左上角 | GDI 不处理；本项目**有意改进**为同权 | 有意偏离 |
| 注释 | `:146-148`「Bilinear … is what mstsc does」 | 反证 | 必须删改 |

## 4. 对齐决策（父代理裁决）

1. **scale == 1.0** → 精确拷贝（保留 memcpy；居中 1:1 也应走精确路径）。
2. **scale > 1** → 最近邻（整数倍保留 k×k 专用内层循环以满足性能；非整数改为最近邻）。**与 mstsc 一致**。
3. **scale < 1** → **精确面积平均**（覆盖加权 + 半像素中心）。**有意改进**：GDI 用近似 box（实测偏差 ±4/255 量级），我们用精确 box。
4. **alpha** → 四通道同权重。**有意改进**：GDI 不处理 alpha。

### 有意偏离清单（必须在文档与代码注释中如实标注，禁止声称「与 mstsc 一致」）

| 编号 | 偏离项 | mstsc 行为 | 本项目 | 理由 |
|---|---|---|---|---|
| D-1 | 降采样精度 | 近似 box（±4/255 偏差） | 精确 box | 可手算、可测、无抖动 |
| D-2 | alpha 重采样 | 不处理 | 四通道同权 | Present 会把 alpha 写入 DIB，未来合成需要正确值 |
| D-3 | 1px 二维棋盘 2x | 压平为 128（不稳定，随尺寸翻转） | 保留块复制（0/255） | 复刻抖动伪影会毁掉文字/线条清晰度，且行为不可移植 |

## 5. 验收要求（先红后绿；期望值禁止取自生产输出）

期望值来源仅限：手算整数面积公式、独立参考实现（不得调用被测代码）、本文件 E7 实测值。

- 降采样：0.5x 1px 条纹 → `127/128`；0.5x alpha 硬边 → `0 128 255 255`；0.5x 白底 1px 黑线（奇数列）→ 该列 ∈[96,160] 且**不得 255**；0.8x ramp 5→4 → `10 71 133 194`；7x5→3x2 → `26 108 190`。
- 升采样：2x/3x 必须与独立 nearest 参考 `memcmp==0`（回归守卫，防止被"修"成模糊）；1.37x/1.33x 输出必须 ⊆ 源像素集合（不产生新颜色）。
- 1:1：`memcmp==0`（含居中 letterbox）。
- 边界：1x1→NxN 全等；1x200→1x333 单调；奇数尺寸无越界。
- 性能（Release，中位 ≥9 次）：1:1 <1ms、1:1 letterbox <0.6ms、2x <8ms、0.8x(1080p→1536x864) ≤22ms、0.5x(4K→1080p) ≤25ms、1.33x(1080p→2560x1440) ≤10ms。
- 变异反证：降采样改回抽点 → 降采样用例全红；升采样改回双线性 → nearest 守卫红。
### E8 升采样/降采样的**精确索引公式**（GDI 实测，执行 AI 发现、父代理独立验算）

`probe_gdi16.exe`（DIB→DIB，HALFTONE + SetBrushOrgEx，源像素值=源索引，256 色内唯一）测得的 x-map：

```
1.5x   4x4 -> 6x6 : 0 0 1 2 2 3
1.5x   2x2 -> 3x3 : 0 0 1
2.5x   2x2 -> 5x5 : 0 0 0 1 1
1.667x 3x3 -> 5x5 : 0 0 1 2 2
1.625x 8x1 -> 13x1: 0 0 1 2 2 3 3 4 5 5 6 7 7
2x     4x4 -> 8x8 : 0 0 1 1 2 2 3 3
```

三种候选公式对照（父代理独立复算，逐组失配数）：

| 公式 | 4→6 | 2→3 | 2→5 | 3→5 | 8→13 | 4→8 | 结论 |
|---|---|---|---|---|---|---|---|
| A `floor(d*S/D)` | 0 | 0 | 0 | **9/25** | **3/13** | 0 | 错 |
| B `floor((2d+1)*S/(2D))` | 20/36 | — | — | 9/25 | 1/13 | — | 错 |
| **C `((2d+1)*S - 1) / (2*D)`** | **0** | **0** | **0** | **0** | **0** | **0** | **正确** |

C 的语义：**半像素中心 + 整数除法向下取整（平局向下）**。平局验证：`4→6` 的 `d=1`（源坐标恰 1.0）GDI=0；`8→13` 的 `d=6`（恰 4.0）GDI=3 —— 均为平局向下，与 C 一致。

→ **实现必须用 C**，不得用 `floor(d*S/D)`（在 3→5、8→13、1.37x 生产量级上会产生整列偏移）。

### E9 降采样的舍入约定（GDI 与精确 box 的差异）

- GDI：`(0+255)/2 = 127.5` → 输出 **127**（截断）。
- 精确 box + 舍入 `(acc+den/2)/den` → **128**。
- 属**舍入约定差异**，非行为分歧。本项目采用**四舍五入**（更对称），在偏离清单中记为 D-1 的一部分；相应测试期望写 128（不接受 127/128 双值，避免测试变松）。

### E10 GDI HALFTONE 在**二维高频内容**上会产生源中不存在的新值（抖动）

审计甲实测（`probe_dither.exe`，自然纹理图）：

```
natural 1920x1080 -> 3840x1080 : mean|d|=0.6771 max|d|=35  not-in-source = 302940/4147200 (7.305%)
natural 1920x1080 -> 2400x1080 : mean|d|=0.7548 max|d|=42  not-in-source = 300240/2592000 (11.583%)
natural 640x480   -> 1280x480   : mean|d|=0.7473 max|d|=35  not-in-source =  44880/614400  (7.305%)
低频 ramp 1920->2400/2560/2880/3840 : mismatch=0  max|d|=0
```

→ **低频内容（渐变/条纹/台阶/1px 线）GDI = 纯最近邻（max|d|=0）；二维高频内容 HALFTONE 会抖动，7.3–11.6% 像素出现源中不存在的值。** 这与「1px 二维棋盘 2x → 128」同一机制。

**对验收的影响（重要）**：
- 升采样断言**只能**用 E8 公式推出的源索引作为黄金标准，且**只在低频内容上**验证；
- **不得**用 GDI 实际输出作为测试期望（否则会被抖动污染）；
- **不得**对二维高频内容（如 1px 棋盘）设断言——GDI 自身行为不稳定且我们有意不复刻；
- 措辞禁止写「与 GDI 逐字节一致」，只能写「相位与 E8 公式一致」。

### E11 降采样舍入：GDI 的 127/128 取决于**是否双轴缩放**

审计甲实测（`probe_verify2.exe`）：

```
单轴 16xH -> 8xH    : GDI = 127 x8   (H=8/16/32/64 六组全 127)
双轴 16xH -> 8xH/2  : GDI = 128 x8   (H=2/4/8/16/32/64 六组全 128)
```

→ 不是"高度阈值"导致的差异，而是**单轴/双轴**路径不同。本项目统一用 `(acc+den/2)/den`（round-half-up）得 **128**，属确定性选择；`scaling-evidence.md` 不得表述为「128 与 mstsc 一致」。
