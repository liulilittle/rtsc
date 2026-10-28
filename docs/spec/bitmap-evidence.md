# 位图/编解码路径：mstsc 取证清单与本仓差距（A3 批次，取证先行）

目标：`C:\Windows\System32\mstscax.dll`（SHA-256 前缀 `d73c76d65721043c`），REA 6.7 + Ghidra 12.1.4。
状态：**仅取证，未改实现**。本文档只记录「mstsc 暴露了哪些编解码路径」与「本仓实现了哪些」，不对未取证的线格式下结论。

## 1. mstsc 侧观察（字符串表，109 条命中，以下为可归类的部分）

| 字符串 | 地址 | 推断含义（标注置信度） |
|---|---|---|
| `NSCODEC (%d)` | 0x1806c8bb0 | NSCodec 路径存在（**观察**） |
| `PLANAR (%d)` | 0x1806c8c90 | RDP6 planar 路径存在（**观察**） |
| `PROGRESSIVE V1(%d%%)` / `V1(100%%)` | 0x1806c8bd0 / 0x1806c8c00 | Progressive V1 路径存在（**观察**） |
| `PROGRESSIVE V2(%d%%)` / `V2(100%%)` | 0x1806c8d88 / 0x1806c8db8 | Progressive V2 路径存在（**观察**） |
| `Planar=%d, ` | 0x1806c9548 | 同上的统计输出（观察） |
| `CaDecProgressiveRectContext` / `ProgressiveCachedCompressor` | 0x1806b06f0 / 0x1806b09a0 | 渐进式解码上下文与缓存压缩器（观察） |
| `kAoPlanarCachedCompressor` | 0x1806b09cd | 平面缓存压缩器（观察） |
| `CTSGraphicsSurfaceBase::FastBltPlanar failed!` / `Failed in FastBltPlanar` | 0x1806b51d0 / 0x18078c498 | 平面快速 blit 路径（观察） |
| `GfxClearCodec`（性能计数器名 0x18078dc80，错误串 0x18078da18） | — | **ClearCodec 路径存在**（观察） |
| `NsCodecRatioScrData` / `NsCodecRatioOrders` | 0x1806c0830 / 0x180796560 | NSCodec 用于屏幕与 orders（观察） |
| `Failed to initialize the progressive output` | 0x18078bf50 | 渐进式输出初始化（观察） |

**尚未取证（不得当结论）**：各 codec 的 `bitmapCodecId`/GUID 到实现的**分派表**、Progressive V1/V2 的启用条件、ClearCodec 的 GUID 与线格式、RemoteFX（本批字符串未直接命中，但 `CaDec*` 前缀疑相关，**未验证**）。

## 2. 本仓已实现（`src/proto/`）

| 路径 | 位置 | 覆盖 |
|---|---|---|
| 未压缩位图 | `bitmap.cpp:101 DecodeRawBitmap` | 8 / 15 / 16 / 24 / 32 bpp，自底向上 + 4 字节行对齐 |
| Interleaved RLE | `bitmap.cpp:164 DecodeRleBitmap` | 全部压缩序；`REGULAR_BG_RUN`/`FG_RUN`/`FGBG_IMAGE`/`COLOR_RUN`/`COLOR_IMAGE` 等（`bitmap.cpp:346-380`） |
| RDP6 planar | `rdp6.cpp:161 DecodeRdp6Bitmap` | 32bpp 压缩（已按 FreeRDP `planar.c` 对齐，且按真机向量与 E7/E8 修正行序与重采样无关部分） |
| NSCodec | `nsc.cpp:86 NscDecodeBitmap` | 结构层 + RLE 解码（未经真机验证，**未验证**） |
| 路由 | `graphics.cpp:259-283` | 32bpp 压缩 → RDP6；否则 raw/RLE（`graphics.cpp:263/274/283`） |

## 3. 差距（仅列出，未定优先级）

1. **ClearCodec**：mstsc 有（`GfxClearCodec` 计数器），本仓无。它通常配合 RemoteFX/EGFX 出现。
2. **Progressive V1/V2**：mstsc 有两条渐进式路径，本仓无。
3. **RemoteFX**：字符串未直接命中，**未验证** mstsc 是否在该 DLL 内实现；`CaDecProgressiveRectContext` 的 `Ca` 前缀可能指 ClearCodec/RemoteFX 家族（**推断**）。
4. **Bitmap Cache Rev1/Rev2 的持久化**：本仓有 Rev2 绘制序（`orders.cpp`）但无跨会话持久缓存。
5. **NSCodec 未经真机验证**：仅自造流测试。

## 4. 下一步取证（按价值排序）

1. **解码分派表**：定位按 `bitmapCodecId`（或 codec GUID）选择解码器的函数，确认 mstsc 接受的全部 codec 与选择条件（这决定我们是否需要实现 ClearCodec/Progressive）。
2. **Progressive 启用条件**：mstsc 何时协商/使用 Progressive（caps 中的 `TS_BITMAPCODEC`/`TS_GRAPHICS_CAPABILITY`）。
3. **真机抓包补充**：连 192.168.1.7 的 32bpp 会话当前只出现 planar；如需验证其它 codec 需改变会话配置（带宽/画质档位）。

> 纪律提醒：本文件中的「推断」全部标注；未取证的线格式不得写入实现。
## 5. A3 取证结论（2026-10-28，父代理）

**已定位**：`mstscax.dll!FUN_1802e513c`（13,057 字节）是 **planar 解压器本体**：

```c
if (param_5 == 0) {
    iVar4 = FUN_180025b90(param_1, param_1 + size, 8, L"Decompress reads off end of buffer");
    if (iVar4 == 0) return -0x60f3bb94;
    uVar6 = *(ushort *)(param_1 + 2);                       // 头内长度字段
    iVar4 = FUN_180025b90(param_1, param_1 + size, uVar6 + 8, L"Decompress reads off end of buffer");
    ...
    uVar17 = ((param_6 + 3 >> 2) * (uint)param_8 * 4 + 0x1f >> 5) << 2;  // 平面尺寸（按 bpp 与高度）
    if (uVar10 != uVar17) { /* 尺寸不符 → 记录 0x1c 日志 */ }
```

7 个调用者：`FUN_18001f464`、`FUN_1800276ac`、`FUN_1800aced0`、`FUN_1800fde50`、`FUN_180151e8c`、`FUN_18058f500`（另 1 处不在函数内）。抽查 `FUN_1800fde50`/`FUN_1800276ac` 的伪代码**未见按小常量（codec id）的 switch/case**。

**推断（标注）**：这些调用者是**按 bpp/flags 而非按 codec GUID** 直接调用对应解压器（`FastBltPlanar` 一类的直接路径），codec 选择可能在更上层（caps 协商/`TS_BITMAPCODEC` 分派），**未验证**。

**A3 决策（父代理，理由充分可改）**：
- **暂不实现 ClearCodec / Progressive V1/V2**。理由：①当前验收路径（192.168.1.7 局域网、32bpp）实测只出现 planar（真机向量 513B/1320B 均为 planar）；②本仓无任何能产生这些 codec 的服务器/抓包，实现后**无法验证**，违反"禁止无法验证的实现入库"；③它们的启用取决于远端策略（带宽/GPU/EGFX），需先取到实际会话样本。
- **列为需真机样本的候选**：若将来在真实会话中观察到 ClearCodec/Progressive（通过 `bitmapCodecId`/EGFX 通道判别），再按本文件流程取证实现。
- **NSCodec 仍需一次真机/回环验证**（本仓仅有自造流测试）——这是当前唯一"已实现但未验证"的解码路径。
