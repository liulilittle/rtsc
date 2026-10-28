# mstsc 缩放/插值行为：二进制取证与对齐要求

目标：`C:\Windows\System32\mstscax.dll`（9,166,848 B；SHA-256 前缀 `d73c76d65721043c`；PDB `mstscax.pdb`）。
工具：REA 6.7 + Ghidra 12.1.4（PE x86-64，默认自动分析完成）。

## 1. 证据

### E1 主绘制路径 `mstscax.dll!FUN_18003444c`（0x18003444c，反编译 24,062 字节）

缩放分支之前的固定设置：

```c
SetStretchBltMode(hdc, 4);
SetBrushOrgEx(hdc, 0, 0, (LPPOINT)0x0);
```

随后的分派（`param_7`/`param_8` 为 x/y 比例）：

```c
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
                       (int)fVar24 + param_6, (int)fVar26, (int)fVar25, 0xcc0020);
}
```

同函数还从属性取状态：

```c
(*pcVar3)(*(longlong **)(param_1 + 0xa0), "EnableSmartSizing", &local_e0);
(*pcVar3)(*(longlong **)(param_1 + 0xa0), "ZoomLevel", &local_108);
...
if (local_108 == 100) { /* 1:1 相关分支 */ }
```

### E2 常量语义独立确证（Windows SDK `um/wingdi.h`）

```c
#define BLACKONWHITE        1
#define WHITEONBLACK        2
#define COLORONCOLOR        3
#define HALFTONE            4
#define STRETCH_HALFTONE    HALFTONE
```

即 `SetStretchBltMode(hdc, 4)` = **HALFTONE**。

### E3 交叉佐证（另两个函数）

- `mstscax.dll!FUN_180191d30`（worker DC）：`GetDC` 后同样 `SetStretchBltMode(hdc, 4)` + `SetBrushOrgEx(hdc, 0, 0, NULL)`，再 `StretchBlt(...)`。
- `mstscax.dll!FUN_1804cfb98`（保存/恢复模式）：

```c
if ((wSrc == iVar4 - iVar5) && (hSrc == iVar1 - iVar2)) {
    mode = 0;
    bVar3 = true;              /* 尺寸相同：不改模式 */
} else {
    bVar3 = false;
    mode = SetStretchBltMode(param_2, 4);   /* 需要缩放：HALFTONE */
}
...
if (!bVar3) SetStretchBltMode(param_2, mode);   /* 恢复 */
```

### E4 调用点分布

`StretchBlt` 共 8 个引用点，归属：0x18003444c（2）、0x180068828（2）、0x180191d30（2）、0x1804cfb98（1），另 1 处不落在任何函数体内。

## 2. 结论（对齐契约）

1. **scale == 1.0（x 与 y 同时为 1.0f）** → `BitBlt(SRCCOPY)`，逐像素精确、无插值。
2. **scale != 1.0（含 2x/3x 整数倍）** → `StretchBlt(SRCCOPY)`，且 stretch 模式为 **HALFTONE**（面积平均式采样），并设置 `SetBrushOrgEx(0,0)`。
3. 判断依据是**实际比例是否为 1.0**，不是"是否整数倍"。整数倍不是快速路径。

## 3. 当前实现差距（`src/client/view.cpp`）

| 项 | 现状 | 二进制契约 | 判定 |
|---|---|---|---|
| 1:1 | `ScaleSurface` Fast path 1 逐行 `memcpy` | `BitBlt` SRCCOPY | 一致 |
| 整数倍 2x/3x | Fast path 2 最近邻块复制 | `StretchBlt` + HALFTONE 平滑 | **不一致** |
| 非整数倍 | 双线性插值 | `StretchBlt` + HALFTONE | **不一致**（GDI HALFTONE 非双线性） |
| 注释 | `view.cpp:144-148`「Bilinear ... is what mstsc does」 | 无证据，与二进制相反 | **必须删除/改写** |
| 属性 | 无 `EnableSmartSizing`/`ZoomLevel` 语义 | 二属性驱动 | 待评估 |

## 4. 验收要求

- 新期望值必须来自本文件 E1/E2（HALFTONE 语义 + 1.0 边界），**禁止**用生产实现输出当期望。
- 必须覆盖：1:1 逐字节相等；2x 输出**不得**为块复制（相邻像素不得成块相等）；0.5x 体现面积平均；1.5x 平滑；alpha 一并处理；1px/奇数边界。
- 变异反证：把实现改回块复制/双线性时，新用例必须转红。
### E5 1:1 守卫判定器 `FUN_180036ba0`（0x180036ba0）

```c
undefined4 FUN_180036ba0(longlong param_1, int param_2, int param_3) {
    ...
    uVar1 = 0; uVar2 = 0;
    if ((((*(int *)(param_1 + 0x68) - *(int *)(param_1 + 0x60) == param_2) &&
         (uVar2 = uVar1, *(int *)(param_1 + 0x6c) - *(int *)(param_1 + 100) == param_3)) &&
        (*(int *)(param_1 + 0x50) == 0)) &&
       (((*(int *)(param_1 + 0x58) == param_2 && (*(int *)(param_1 + 0x54) == 0)) &&
        (*(int *)(param_1 + 0x5c) == param_3)))) {
        uVar2 = 1;
    }
    ...
    return uVar2;
}
```

语义（观察 + 推断标注）：**当前桌面宽高必须等于目标宽高**（两个差值为 0），且四个偏移/尺寸字段全为 0，才返回 1。E1 中该返回值决定走 `BitBlt` 还是 `StretchBlt`（`if ((local_108 == 100) && (local_e0 == 0 || FUN_180036ba0(...) != 0))`）。→ **1:1 是严格相等判定，不是"接近 1"**。

### E6 相关属性字符串（只读证据）

`ZoomLevel`(0x1806adfe0)、`EnableSmartSizing`(0x1806adff0)、`DesktopScaleFactor`(0x1806b9928)、`DeviceScaleFactor`(0x1806b9978)、`puDesktopScaleFactor`/`puDeviceScaleFactor`(0x1806c4d68/0x1806c4d80)、`"SetZoomLevel failed!"`(0x1807a39c0)。

→ `DesktopScaleFactor` / `DeviceScaleFactor` 在 mstsc 中是**独立于 ZoomLevel 的 DPI 缩放维度**；本仓目前只有单一 zoom 标量。**待评估是否需要建模**（先取证其用途，再决定）。

## 5. 修正记录（2026-10-28，实测推翻推断）

**第 2 节结论「scale!=1.0 → HALFTONE 面积平均」是推断，已被实测推翻。**

### E7 GDI HALFTONE 实测（本机 Win32 GDI 探针，`%TEMP%\opencode\viewprobe\probe_gdi12/14`）

```
[1080p 1px vstripes -> 4K, HALFTONE ok=1] row0 R[0..31] =
   0   0 255 255   0   0 255 255   0   0 255 255   0   0 255 255  ...
   distinct R values in the whole frame (block => 2): 2

1080p step edge -> 4K (2x)          distinct=  2   (块复制)
1080p step edge -> 5760x3240 (3x)   distinct=  2   (块复制)
1080p step edge -> 2630x1480 (1.37x) distinct=  2   (块复制)
1080p ramp -> 1536x864 (0.8x)       distinct=256   (平均/平滑)
```

父代理本地复跑 `probe_gdi12.exe` / `probe_gdi14.exe` 得到同一结果。

### 修正后的契约（观察级，可引用）

| 情形 | GDI HALFTONE 实测行为 | 依据 |
|---|---|---|
| scale == 1.0 | 调用方根本不进 StretchBlt（走 `BitBlt` SRCCOPY） | E1 / E5 |
| scale > 1（含 2x/3x/1.37x） | **最近邻块复制**（非平滑） | E7 |
| scale < 1（非整数比） | 覆盖加权平均（平滑） | E7 |
| scale < 1（整数比，如 0.5x/0.25x） | 实测退化为块复制（非平均） | 审计甲 probe_gdi |
| alpha | GDI **完全不处理**（0.5x 硬边输出全 0） | 审计甲 probe_gdi9 |

### 因此待裁决的两点（记录给决策，不预设结论）

- **P1**：升采样是否对齐 GDI 的最近邻？若改为平滑，属**有意偏离 mstsc**，必须在文档中单列说明，不得声称「与 mstsc 一致」。
- **P2**：降采样是否无条件面积平均（更正确）？GDI 在整数比降采样会退化为块复制，对齐它意味着保留混叠。

> 教训：`SetStretchBltMode(hdc, 4)` 只证明「用了 HALFTONE 模式」，**不能**推出「HALFTONE 在升采样时做面积平均」。模式名与各方向的实际行为必须分别实测。
