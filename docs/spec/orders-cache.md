# 绘制订单：secondary 头与 brush 缓存（证据文档）

来源：`[MS-RDPEGDI]` 2.2.2.2.1.2.x（`.tmp/MS-RDPEGDI-240423.docx`，2024-04-23 版）。
本文件只记录**从规范原文提取的事实**，不含实现决策。

## 1. SECONDARY_DRAWING_ORDER_HEADER（2.2.2.2.1.2.1）

官方 annotated dump（Cache Bitmap Rev3 样例）：

```
00000000 03 37 00 30 0c 08 ff 7f ...
03    -> controlFlags = 0x03 = 0x2 | 0x1 = TS_SECONDARY | TS_STANDARD
37 00 -> orderLength = 0x37 + 13 = 68 bytes
30 0c -> extraFlags = 0x0c30
        cacheId      = (extraFlags >> 6) & 0x7  = 0
        bitsPerPixel = (extraFlags >> 3) & 0x7  = 0x6 (32 bpp)
        flags        = extraFlags & 0x7         = 0x0  (样例：CBR3_DO_NOT_CACHE 0x10 | CBR3_IGNORABLE 0x08)
08    -> orderType = 0x08 = TS_CACHE_BITMAP_COMPRESSED_REV3 (?)
```

布局：`controlFlags(1B)` + `orderLength(2B LE, signed)` + `extraFlags(2B LE)` + `orderType(1B)` + `orderData`。

**`orderLength` 语义（规范原文，已确认）**：
> A 16-bit, signed integer. The encoded length in bytes of the secondary drawing order, **including the size of the header**.
> When constructing the order, the value in the orderLength field MUST be **13 bytes less than the actual order length**.
> Hence, when decoding the order, the orderLength field MUST be **adjusted by adding 13 bytes**. These adjustments are for historical reasons.

→ **实际长度 = `orderLength + 13`**。因此 secondary order 可被安全跳过（primary order 长度不可知，不可跳过）。

`controlFlags` 三类判定（规范原文）：
- `TS_STANDARD (0x01)` 置位 → primary；
- `TS_STANDARD | TS_SECONDARY (0x01|0x02)` → secondary；
- **仅 `TS_SECONDARY (0x02)`** → alternate secondary（头结构不同，见 `ALTSEC_DRAWING_ORDER_HEADER`）。

`orderType` 取值：`TS_CACHE_BITMAP_UNCOMPRESSED 0x00` / `TS_CACHE_COLOR_TABLE 0x01` / `TS_CACHE_BITMAP_COMPRESSED 0x02` /
`TS_CACHE_GLYPH 0x03` / `TS_CACHE_BITMAP_UNCOMPRESSED_REV2 0x04` / `TS_CACHE_BITMAP_COMPRESSED_REV2 0x05` /
**`TS_CACHE_BRUSH 0x07`** / `TS_CACHE_BITMAP_COMPRESSED_REV3 0x08`。

## 2. CACHE_BRUSH_ORDER（2.2.2.2.1.2.7）

官方 annotated dump：

```
TS_CACHE_BRUSH
00    -> cacheEntry    = 0
01    -> iBitmapFormat = TS_BMF_1BPP (0x01)
08    -> cx            = 8
08    -> cy            = 8
81    -> Style         = 0x81
08    -> iBytes        = 8 bytes
aa 55 aa 55 aa 55 aa 55 -> brushData
```

布局：`cacheEntry(1B)` + `iBitmapFormat(1B)` + `cx(1B)` + `cy(1B)` + `Style(1B)` + `iBytes(1B)` + `brushData(iBytes)`。

## 3. COMPRESSED_COLOR_BRUSH（2.2.2.2.1.2.7.1）

四色 8×8 画笔的压缩形式：`P1..P64`（每像素 **2 bit**，`0..3` 索引翻译表）+ `color1..color4`（变长，按色深）。
> 四色以上的画笔：数据按相应色深**不压缩直接**放入 `brushData`。

## 4. 与 PatBlt 的 TS_CACHED_BRUSH 的关系

PatBlt 的 `BrushStyle` 最高位 `TS_CACHED_BRUSH (0x80)` 置位时：
- `BrushHatch` = **brush 缓存索引**；
- `BrushStyle` **低半字节** = 缓存画笔的色深：`BMF_1BPP 0x1` / `BMF_8BPP 0x3` / `BMF_16BPP 0x4` / `BMF_24BPP 0x5` / `BMF_32BPP 0x6`。

规范在该处措辞为「previously cached using the **Cache Bitmap Secondary Order**」，但画笔缓存的实际订单是
`CACHE_BRUSH_ORDER`（2.2.2.2.1.2.7）。**两者措辞不一致，实现前需以真实流量确认服务器发的是哪一种。**

## 5. 未验证项

- `orderLength` 的精确基准（+13 的来源）仅由单个 dump 归纳，**未验证**；需多个真实样例。
- `TS_CACHED_BRUSH` 究竟引用 `CACHE_BRUSH_ORDER` 还是 Cache Bitmap 缓存条目，**未验证**。
- 以上均需在真机联调抓包时确认。
