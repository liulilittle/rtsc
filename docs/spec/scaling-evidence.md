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